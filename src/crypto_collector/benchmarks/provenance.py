from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import tarfile
import tempfile
import time
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Annotated, Any, Literal, Protocol, TypeVar, cast
from urllib.parse import urlsplit

import zstandard
from pydantic import BaseModel, StringConstraints, ValidationError, model_validator

from crypto_collector.benchmarks.contracts import (
    GateAcceptanceReceiptV1,
    GateArchiveAttestationV1,
    GateBuildProvenanceV1,
    GateCandidateReportV1,
    GateEvidenceDisclosureV1,
    GateFileInventoryV1,
    GateProvenanceReceiptV1,
    GateRunIndexV1,
    GateRuntimeIndexV1,
    GateRuntimeReceiptV1,
    GitCommitSha,
    ImageId,
    NonEmptyString,
    NonNegativeInt,
)
from crypto_collector.domain.envelope import FrozenStrictModel
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.storage.models import Sha256

_MAX_DOCUMENT_BYTES = 32 * 1024 * 1024
_MAX_COMMAND_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_TAR_TRAILING_ZERO_BYTES = tarfile.RECORDSIZE
_PROVENANCE_RECEIPT_NAME = "provenance-receipt.json"
_ACCEPTANCE_RECEIPT_NAME = "acceptance-receipt.json"
_BUILD_PROVENANCE_MODE = "0444"
_RUNTIME_USER = "65532:65532"
_WRITER_CONTAINER_MEMORY_LIMIT_BYTES = 4 * 1024**3
_FORBIDDEN_DISTRIBUTIONS = frozenset({"boto3", "oss2", "pyarrow"})
_BUILD_INPUT_PATHS = (
    ".dockerignore",
    "Dockerfile",
    "README.md",
    "pyproject.toml",
    "requirements",
    "benchmarks",
    "src",
    "scripts",
)
_LOCK_REQUIREMENT = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)==(?P<version>[^=\s]+)\Z"
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)
LiteralMode0444 = Literal["0444"]
LiteralRuntimeUser = Literal["65532:65532"]
LiteralLinuxAmd64 = Literal["linux/amd64"]
AnnotatedContainerId = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9a-f]{64}$"),
]


class ProvenanceValidationError(ValueError):
    pass


def _normalize_distribution_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value.casefold())


class GitPort(Protocol):
    def inspect_source(self, source_commit: str) -> object: ...


class DockerPort(Protocol):
    def reproduce(
        self,
        *,
        source_commit: str,
        source_date_epoch: int,
    ) -> object: ...

    def inspect_container(self, name: str) -> object: ...


class ArchiveProviderPort(Protocol):
    def verify_and_download(
        self,
        *,
        provider: str,
        archive_locator: str,
        object_version: str,
        destination: Path,
    ) -> object: ...


class _GitSourceFacts(FrozenStrictModel):
    source_commit: GitCommitSha
    source_date_epoch: NonNegativeInt
    checkout_clean: bool
    source_archive_sha256s: tuple[Sha256, Sha256]
    untracked_build_inputs: tuple[NonEmptyString, ...]
    ignored_build_inputs: tuple[NonEmptyString, ...]


class _BuildFacts(FrozenStrictModel):
    source_context_sha256: Sha256
    collector_wheel_sha256: Sha256
    image_id: ImageId
    labels: dict[str, str]
    build_provenance: GateBuildProvenanceV1
    build_provenance_content_sha256: Sha256
    build_provenance_mode: LiteralMode0444
    workload_sha256: Sha256
    runtime_user: LiteralRuntimeUser
    installed_distributions: tuple[NonEmptyString, ...]

    @model_validator(mode="after")
    def validate_distributions(self) -> _BuildFacts:
        if self.installed_distributions != tuple(
            sorted(set(self.installed_distributions))
        ):
            raise ValueError("installed distributions must be sorted and unique")
        if any(
            _LOCK_REQUIREMENT.fullmatch(item) is None
            for item in self.installed_distributions
        ):
            raise ValueError("installed distributions must use exact versions")
        names = {
            _normalize_distribution_name(item.partition("==")[0])
            for item in self.installed_distributions
        }
        if names.intersection(_FORBIDDEN_DISTRIBUTIONS):
            raise ValueError("collector image contains forbidden dependency SDKs")
        return self


class _ReproductionFacts(FrozenStrictModel):
    source_commit: GitCommitSha
    source_date_epoch: NonNegativeInt
    platform: LiteralLinuxAmd64
    base_image_digest: ImageId
    docker_engine_version: NonEmptyString
    docker_buildx_version: NonEmptyString
    buildkit_version: NonEmptyString
    dockerfile_frontend: NonEmptyString
    provenance_enabled: bool
    sbom_enabled: bool
    requirements_lock_sha256: Sha256
    build_requirements_lock_sha256: Sha256
    dockerfile_sha256: Sha256
    workload_sha256: Sha256
    runtime_lock_requirements: tuple[NonEmptyString, ...]
    build_lock_requirements: tuple[NonEmptyString, ...]
    builds: tuple[_BuildFacts, _BuildFacts]

    @model_validator(mode="after")
    def validate_build_lock(self) -> _ReproductionFacts:
        for name, requirements in (
            ("runtime", self.runtime_lock_requirements),
            ("build", self.build_lock_requirements),
        ):
            if not requirements or requirements != tuple(sorted(set(requirements))):
                raise ValueError(
                    f"{name} lock requirements must be nonempty, sorted, and unique"
                )
            if any(_LOCK_REQUIREMENT.fullmatch(item) is None for item in requirements):
                raise ValueError(f"{name} lock contains an unversioned requirement")
            names = {
                _normalize_distribution_name(item.partition("==")[0])
                for item in requirements
            }
            if names.intersection(_FORBIDDEN_DISTRIBUTIONS):
                raise ValueError(f"{name} lock contains a forbidden dependency SDK")
        requirements = self.build_lock_requirements
        names = {
            _normalize_distribution_name(item.partition("==")[0])
            for item in requirements
        }
        if "hatchling" not in names:
            raise ValueError("complete build lock must contain Hatchling")
        return self


class _ContainerFacts(FrozenStrictModel):
    container_id: AnnotatedContainerId
    name: NonEmptyString
    exists: bool
    removed: bool
    status: NonEmptyString
    running: bool
    paused: bool
    restarting: bool
    oom_killed: bool
    dead: bool
    pid: NonNegativeInt
    exit_code: int
    error: str
    image_id: ImageId
    memory_limit_bytes: NonNegativeInt
    memory_swap_limit_bytes: NonNegativeInt


class _ArchiveProviderFacts(FrozenStrictModel):
    provider: Literal["s3_object_lock", "oss_worm"]
    archive_locator: NonEmptyString
    object_version: NonEmptyString
    retention_mode: Literal["compliance", "worm"]
    retention_until_unix_ns: NonNegativeInt
    observed_at_unix_ns: NonNegativeInt
    content_size_bytes: NonNegativeInt


def _self_hashed(model_type: type[_ModelT], unsigned: dict[str, object]) -> _ModelT:
    digest = hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest()
    return model_type.model_validate(
        {**unsigned, "sha256": digest},
        strict=True,
    )


def _open_regular_nofollow(path: Path) -> tuple[int, os.stat_result]:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ProvenanceValidationError("evidence file path must be absolute")
    if path.parent.resolve(strict=True) != path.parent:
        raise ProvenanceValidationError("evidence file parent may not be a symlink")
    flags = os.O_RDONLY
    for name in ("O_NONBLOCK", "O_NOFOLLOW", "O_CLOEXEC"):
        value = getattr(os, name, None)
        if type(value) is not int or value == 0:
            raise ProvenanceValidationError(f"required open flag {name} is unavailable")
        flags |= value
    try:
        fd = os.open(path, flags)
    except OSError as error:
        raise ProvenanceValidationError(
            f"cannot open evidence file {path.name}"
        ) from error
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ProvenanceValidationError("evidence file must be a regular file")
    except BaseException:
        os.close(fd)
        raise
    return fd, before


def _stable_file_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_bounded_nofollow(path: Path, *, allow_empty: bool = False) -> bytes:
    fd, before = _open_regular_nofollow(path)
    try:
        if (
            (before.st_size == 0 and not allow_empty)
            or before.st_size < 0
            or before.st_size > _MAX_DOCUMENT_BYTES
        ):
            raise ProvenanceValidationError("evidence document size is invalid")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise ProvenanceValidationError("evidence document was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise ProvenanceValidationError("evidence document grew while reading")
        after = os.fstat(fd)
        if _stable_file_identity(before) != _stable_file_identity(after):
            raise ProvenanceValidationError("evidence document changed while reading")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _hash_regular_file_nofollow(
    path: Path,
) -> tuple[int, str, tuple[int, int, int, int, int]]:
    fd, before = _open_regular_nofollow(path)
    digest = hashlib.sha256()
    total = 0
    try:
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(fd)
        identity = _stable_file_identity(before)
        if total != before.st_size or identity != _stable_file_identity(after):
            raise ProvenanceValidationError("evidence file changed while hashing")
        return total, digest.hexdigest(), identity
    finally:
        os.close(fd)


def _load_canonical(path: Path, model_type: type[_ModelT]) -> tuple[_ModelT, bytes]:
    source = _read_bounded_nofollow(path)
    try:
        model = model_type.model_validate_json(source, strict=True)
    except (TypeError, ValueError, ValidationError) as error:
        raise ProvenanceValidationError(
            f"{path.name} does not match {model_type.__name__}"
        ) from error
    canonical = cast(Any, model).canonical_bytes()
    if canonical != source:
        raise ProvenanceValidationError(f"{path.name} is not canonical JSON")
    return model, source


def _resolve_ref(root: Path, relative_path: str) -> Path:
    path = root.joinpath(*relative_path.split("/"))
    if not path.is_relative_to(root):
        raise ProvenanceValidationError("evidence reference escaped its root")
    return path


def _load_ref(
    root: Path,
    ref: Any,
    model_type: type[_ModelT],
) -> tuple[_ModelT, bytes]:
    path = _resolve_ref(root, ref.relative_path)
    model, source = _load_canonical(path, model_type)
    if len(source) != ref.content_size_bytes:
        raise ProvenanceValidationError(
            "evidence document size disagrees with its reference"
        )
    if hashlib.sha256(source).hexdigest() != ref.content_sha256:
        raise ProvenanceValidationError(
            "evidence document hash disagrees with its reference"
        )
    return model, source


def _scan_inventory_root(
    root_name: str,
    root: Path,
) -> tuple[GateFileInventoryV1, ...]:
    if not root.is_absolute() or root.resolve(strict=True) != root or not root.is_dir():
        raise ProvenanceValidationError(f"archive {root_name} root is invalid")
    rows: list[GateFileInventoryV1] = []

    def reject_walk_error(error: OSError) -> None:
        raise ProvenanceValidationError("cannot walk archive inventory") from error

    for directory, directory_names, file_names in os.walk(
        root,
        followlinks=False,
        onerror=reject_walk_error,
    ):
        directory_path = Path(directory)
        for name in tuple(directory_names):
            candidate = directory_path / name
            if candidate.is_symlink():
                raise ProvenanceValidationError(
                    "archive inventory rejects symbolic links"
                )
        for name in file_names:
            path = directory_path / name
            if path.is_symlink():
                raise ProvenanceValidationError(
                    "archive inventory rejects symbolic links"
                )
            content_size, content_sha256, _ = _hash_regular_file_nofollow(path)
            rows.append(
                GateFileInventoryV1(
                    root=cast(Any, root_name),
                    relative_path=path.relative_to(root).as_posix(),
                    content_size_bytes=content_size,
                    content_sha256=content_sha256,
                )
            )
    return tuple(sorted(rows, key=lambda item: item.relative_path))


def _validate_archive_inventory(
    attestation: GateArchiveAttestationV1,
    *,
    evidence_root: Path,
    data_root: Path,
    state_root: Path,
) -> None:
    observed = (
        *_scan_inventory_root("evidence", evidence_root),
        *_scan_inventory_root("data", data_root),
        *_scan_inventory_root("state", state_root),
    )
    if attestation.files != observed:
        raise ProvenanceValidationError(
            "archive inventory does not match local evidence"
        )


def _expected_archive_directories(
    files: tuple[GateFileInventoryV1, ...],
) -> frozenset[str]:
    directories: set[str] = set()
    for item in files:
        current: str = item.root
        directories.add(current)
        for part in item.relative_path.split("/")[:-1]:
            current = f"{current}/{part}"
            directories.add(current)
    return frozenset(directories)


def _normalize_archive_directory_name(name: str) -> str:
    normalized = name.removesuffix("/")
    if (
        not normalized
        or "\x00" in normalized
        or "\\" in normalized
        or normalized.startswith("/")
        or any(part in {"", ".", ".."} for part in normalized.split("/"))
    ):
        raise ProvenanceValidationError(
            "remote archive directory path is not normalized"
        )
    return normalized


def _scan_archive_readback(
    path: Path,
    *,
    expected_identity: tuple[int, int, int, int, int],
    expected_files: tuple[GateFileInventoryV1, ...],
) -> tuple[GateFileInventoryV1, ...]:
    rows: list[GateFileInventoryV1] = []
    seen: set[tuple[str, str]] = set()
    seen_directories: set[str] = set()
    expected_directories = _expected_archive_directories(expected_files)
    maximum_files = len(expected_files)
    maximum_content_bytes = sum(item.content_size_bytes for item in expected_files)
    root_order = {"evidence": 0, "data": 1, "state": 2}
    total_content_bytes = 0
    fd, before = _open_regular_nofollow(path)
    if _stable_file_identity(before) != expected_identity:
        os.close(fd)
        raise ProvenanceValidationError("remote archive changed before inspection")
    try:
        with (
            os.fdopen(os.dup(fd), "rb") as compressed,
            zstandard.ZstdDecompressor().stream_reader(
                compressed,
                read_across_frames=True,
            ) as decoded,
            tarfile.open(fileobj=decoded, mode="r|") as archive,
        ):
            for member in archive:
                if member.isdir():
                    if member.size != 0:
                        raise ProvenanceValidationError(
                            "remote archive directory size must be zero"
                        )
                    directory = _normalize_archive_directory_name(member.name)
                    if directory not in expected_directories:
                        raise ProvenanceValidationError(
                            "remote archive contains an unexpected directory"
                        )
                    if directory in seen_directories:
                        raise ProvenanceValidationError(
                            "remote archive contains a duplicate directory"
                        )
                    seen_directories.add(directory)
                    continue
                if not member.isfile():
                    raise ProvenanceValidationError(
                        "remote archive contains a non-regular member"
                    )
                if len(rows) >= maximum_files:
                    raise ProvenanceValidationError(
                        "remote archive contains excess members"
                    )
                root_name, separator, relative_path = member.name.partition("/")
                if not separator or root_name not in root_order:
                    raise ProvenanceValidationError(
                        "remote archive member is outside declared roots"
                    )
                if member.size < 0 or (
                    total_content_bytes + member.size > maximum_content_bytes
                ):
                    raise ProvenanceValidationError(
                        "remote archive content exceeds attestation"
                    )
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ProvenanceValidationError(
                        "remote archive member cannot be read"
                    )
                digest = hashlib.sha256()
                member_size = 0
                while True:
                    chunk = extracted.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    member_size += len(chunk)
                if member_size != member.size:
                    raise ProvenanceValidationError(
                        "remote archive member was truncated"
                    )
                identity = (root_name, relative_path)
                if identity in seen:
                    raise ProvenanceValidationError(
                        "remote archive contains duplicate members"
                    )
                seen.add(identity)
                total_content_bytes += member_size
                rows.append(
                    GateFileInventoryV1(
                        root=cast(Any, root_name),
                        relative_path=relative_path,
                        content_size_bytes=member_size,
                        content_sha256=digest.hexdigest(),
                    )
                )
            trailing_size = 0
            if archive.fileobj is None:
                raise ProvenanceValidationError("remote archive stream is unavailable")
            while True:
                trailing = archive.fileobj.read(1024 * 1024)
                if not trailing:
                    break
                trailing_size += len(trailing)
                if trailing_size > _MAX_TAR_TRAILING_ZERO_BYTES or any(trailing):
                    raise ProvenanceValidationError(
                        "remote archive contains trailing content"
                    )
        if _stable_file_identity(os.fstat(fd)) != expected_identity:
            raise ProvenanceValidationError("remote archive changed while inspecting")
    except zstandard.ZstdError as error:
        raise ProvenanceValidationError("remote archive is not valid zstd") from error
    except (OSError, tarfile.TarError, ValidationError) as error:
        raise ProvenanceValidationError("remote archive is invalid") from error
    finally:
        os.close(fd)
    return tuple(
        sorted(rows, key=lambda item: (root_order[item.root], item.relative_path))
    )


def _validate_archive_provider(
    attestation: GateArchiveAttestationV1,
    provider: ArchiveProviderPort,
) -> _ArchiveProviderFacts:
    if attestation.provider == "webdav" or attestation.object_version is None:
        raise ProvenanceValidationError(
            "archive is not immutable qualification evidence"
        )
    with tempfile.TemporaryDirectory(prefix="writer-archive-readback-") as directory:
        destination = Path(directory).resolve(strict=True) / "archive.tar.zst"
        try:
            value = provider.verify_and_download(
                provider=attestation.provider,
                archive_locator=attestation.archive_locator,
                object_version=attestation.object_version,
                destination=destination,
            )
            facts = _ArchiveProviderFacts.model_validate(value, strict=True)
        except (OSError, ValidationError) as error:
            raise ProvenanceValidationError(
                "archive provider verification failed"
            ) from error
        if facts.provider != attestation.provider:
            raise ProvenanceValidationError("archive provider identity disagrees")
        if facts.archive_locator != attestation.archive_locator:
            raise ProvenanceValidationError("archive provider locator disagrees")
        if facts.object_version != attestation.object_version:
            raise ProvenanceValidationError("archive provider object version disagrees")
        if facts.retention_mode != attestation.retention_mode:
            raise ProvenanceValidationError("archive provider retention mode disagrees")
        if facts.retention_until_unix_ns != attestation.retention_until_unix_ns:
            raise ProvenanceValidationError(
                "archive provider retention deadline disagrees"
            )
        if facts.observed_at_unix_ns < attestation.verified_at_unix_ns:
            raise ProvenanceValidationError(
                "archive provider observation predates attestation"
            )
        archive_size, archive_sha256, archive_identity = _hash_regular_file_nofollow(
            destination
        )
        if (
            facts.content_size_bytes != archive_size
            or attestation.archive_size_bytes != archive_size
        ):
            raise ProvenanceValidationError("archive provider object size disagrees")
        if archive_sha256 != attestation.archive_sha256:
            raise ProvenanceValidationError("archive provider readback hash disagrees")
        if (
            _scan_archive_readback(
                destination,
                expected_identity=archive_identity,
                expected_files=attestation.files,
            )
            != attestation.files
        ):
            raise ProvenanceValidationError(
                "remote archive inventory does not match attestation"
            )
    return facts


def _validate_git_facts(value: object, source_commit: str) -> _GitSourceFacts:
    try:
        facts = _GitSourceFacts.model_validate(value, strict=True)
    except ValidationError as error:
        raise ProvenanceValidationError(
            "Git returned malformed source facts"
        ) from error
    if facts.source_commit != source_commit:
        raise ProvenanceValidationError("Git resolved a different source commit")
    if not facts.checkout_clean:
        raise ProvenanceValidationError("source checkout must be clean")
    if facts.untracked_build_inputs or facts.ignored_build_inputs:
        raise ProvenanceValidationError(
            "source contains untracked or ignored build inputs"
        )
    if facts.source_archive_sha256s[0] != facts.source_archive_sha256s[1]:
        raise ProvenanceValidationError("two source archive contexts differ")
    return facts


def _expected_labels(provenance: GateBuildProvenanceV1) -> dict[str, str]:
    content_sha256 = hashlib.sha256(provenance.canonical_bytes()).hexdigest()
    return {
        "org.opencontainers.image.revision": provenance.implementation_source_commit,
        "org.opencontainers.image.base.digest": provenance.base_image_digest,
        "io.crypto-collector.source-date-epoch": str(provenance.source_date_epoch),
        "io.crypto-collector.collector-wheel-sha256": provenance.collector_wheel_sha256,
        "io.crypto-collector.requirements-lock-sha256": provenance.requirements_lock_sha256,
        "io.crypto-collector.build-requirements-lock-sha256": provenance.build_requirements_lock_sha256,
        "io.crypto-collector.dockerfile-sha256": provenance.dockerfile_sha256,
        "io.crypto-collector.workload-sha256": provenance.workload_sha256,
        "io.crypto-collector.build-provenance-sha256": content_sha256,
        "io.crypto-collector.platform": provenance.platform,
        "io.crypto-collector.docker-engine-version": provenance.docker_engine_version,
        "io.crypto-collector.docker-buildx-version": provenance.docker_buildx_version,
        "io.crypto-collector.buildkit-version": provenance.buildkit_version,
        "io.crypto-collector.dockerfile-frontend": provenance.dockerfile_frontend,
        "io.crypto-collector.provenance": "false",
        "io.crypto-collector.sbom": "false",
        "io.crypto-collector.runtime-user": provenance.runtime_user,
    }


def _requirements_by_distribution(
    requirements: tuple[str, ...],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for requirement in requirements:
        match = _LOCK_REQUIREMENT.fullmatch(requirement)
        if match is None:
            raise ProvenanceValidationError(
                "runtime dependency is not exactly versioned"
            )
        name = _normalize_distribution_name(match.group("name"))
        if name in result:
            raise ProvenanceValidationError("runtime dependency names are not unique")
        result[name] = match.group("version")
    return result


def _validate_runtime_dependency_boundary(facts: _ReproductionFacts) -> None:
    locked = _requirements_by_distribution(facts.runtime_lock_requirements)
    for build in facts.builds:
        installed = _requirements_by_distribution(build.installed_distributions)
        collector_version = installed.pop("crypto-market-data-collector", None)
        if collector_version is None or installed != locked:
            raise ProvenanceValidationError(
                "image runtime dependency boundary differs from collector.lock"
            )


def _validate_reproduction(
    value: object,
    *,
    git_facts: _GitSourceFacts,
    run_index: GateRunIndexV1,
) -> _ReproductionFacts:
    try:
        facts = _ReproductionFacts.model_validate_json(
            encode_json(value),
            strict=True,
        )
    except (TypeError, ValueError, ValidationError) as error:
        raise ProvenanceValidationError(
            "Docker returned malformed reproduction facts"
        ) from error
    _validate_runtime_dependency_boundary(facts)
    if facts.source_commit != git_facts.source_commit:
        raise ProvenanceValidationError("reproduction source commit differs from Git")
    if facts.source_date_epoch != git_facts.source_date_epoch:
        raise ProvenanceValidationError(
            "reproduction SOURCE_DATE_EPOCH differs from Git"
        )
    if facts.provenance_enabled or facts.sbom_enabled:
        raise ProvenanceValidationError("ambient provenance and SBOM must be disabled")
    expected_outer = (
        run_index.requirements_lock_sha256,
        run_index.dockerfile_sha256,
        run_index.workload_sha256,
    )
    if (
        facts.requirements_lock_sha256,
        facts.dockerfile_sha256,
        facts.workload_sha256,
    ) != expected_outer:
        raise ProvenanceValidationError(
            "reproduced build inputs disagree with run index"
        )

    first, second = facts.builds
    if tuple(build.source_context_sha256 for build in facts.builds) != (
        git_facts.source_archive_sha256s
    ):
        raise ProvenanceValidationError(
            "build source contexts differ from Git archives"
        )
    if first.collector_wheel_sha256 != second.collector_wheel_sha256:
        raise ProvenanceValidationError("reproduced wheel hashes differ")
    if first.image_id != second.image_id:
        raise ProvenanceValidationError("reproduced image IDs differ")
    if first.build_provenance != second.build_provenance:
        raise ProvenanceValidationError("build provenance documents differ")
    if run_index.collector_wheel_sha256 != first.collector_wheel_sha256:
        raise ProvenanceValidationError("reproduced wheel differs from run index")
    if (
        run_index.expected_image_id != first.image_id
        or run_index.runtime_image_id != first.image_id
    ):
        raise ProvenanceValidationError("reproduced image differs from runtime claims")

    for build in facts.builds:
        provenance = build.build_provenance
        expected_provenance = (
            git_facts.source_commit,
            git_facts.source_date_epoch,
            facts.platform,
            facts.base_image_digest,
            facts.docker_engine_version,
            facts.docker_buildx_version,
            facts.buildkit_version,
            facts.dockerfile_frontend,
            build.collector_wheel_sha256,
            facts.requirements_lock_sha256,
            facts.build_requirements_lock_sha256,
            facts.dockerfile_sha256,
            facts.workload_sha256,
            False,
            False,
            _RUNTIME_USER,
        )
        observed_provenance = (
            provenance.implementation_source_commit,
            provenance.source_date_epoch,
            provenance.platform,
            provenance.base_image_digest,
            provenance.docker_engine_version,
            provenance.docker_buildx_version,
            provenance.buildkit_version,
            provenance.dockerfile_frontend,
            provenance.collector_wheel_sha256,
            provenance.requirements_lock_sha256,
            provenance.build_requirements_lock_sha256,
            provenance.dockerfile_sha256,
            provenance.workload_sha256,
            provenance.provenance_enabled,
            provenance.sbom_enabled,
            provenance.runtime_user,
        )
        if observed_provenance != expected_provenance:
            raise ProvenanceValidationError("image build provenance facts disagree")
        if build.labels != _expected_labels(provenance):
            raise ProvenanceValidationError("OCI image labels do not match provenance")
        if (
            build.build_provenance_content_sha256
            != hashlib.sha256(provenance.canonical_bytes()).hexdigest()
        ):
            raise ProvenanceValidationError("build provenance file hash disagrees")
        if build.build_provenance_mode != _BUILD_PROVENANCE_MODE:
            raise ProvenanceValidationError("build provenance file is not read-only")
        if build.workload_sha256 != facts.workload_sha256:
            raise ProvenanceValidationError("image workload copy hash disagrees")
        if build.runtime_user != _RUNTIME_USER:
            raise ProvenanceValidationError("image runtime user is not 65532:65532")
    return facts


def _validate_container(
    value: object,
    *,
    name: str,
    image_id: str,
    expected_memory_limit_bytes: int | None = None,
) -> _ContainerFacts:
    try:
        facts = _ContainerFacts.model_validate(value, strict=True)
    except ValidationError as error:
        raise ProvenanceValidationError(
            "Docker returned malformed container facts"
        ) from error
    if facts.name != name:
        raise ProvenanceValidationError("container name resolution changed")
    if not facts.exists or facts.removed:
        raise ProvenanceValidationError("gate container was not retained")
    if facts.status != "exited" or any(
        (facts.running, facts.paused, facts.restarting, facts.oom_killed, facts.dead)
    ):
        raise ProvenanceValidationError("gate container did not exit successfully")
    if facts.pid != 0 or facts.exit_code != 0 or facts.error:
        raise ProvenanceValidationError("gate container state is not successful")
    if facts.image_id != image_id:
        raise ProvenanceValidationError(
            "container .Image differs from reproduced image"
        )
    if expected_memory_limit_bytes is not None and (
        facts.memory_limit_bytes != expected_memory_limit_bytes
        or facts.memory_swap_limit_bytes != expected_memory_limit_bytes
    ):
        raise ProvenanceValidationError(
            "writer container memory limit or zero-swap contract changed"
        )
    return facts


def _publish_no_replace(path: Path, source: bytes) -> None:
    if path.exists():
        if _read_bounded_nofollow(path) == source:
            parent_fd = os.open(
                path.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            return
        raise ProvenanceValidationError(f"existing {path.name} conflicts with receipt")
    parent = path.parent
    parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    partial = parent / f".{path.name}.{os.getpid()}.{time.time_ns()}.partial"
    fd = -1
    primary: BaseException | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        for name in ("O_NOFOLLOW", "O_CLOEXEC"):
            flags |= cast(int, getattr(os, name))
        fd = os.open(partial, flags, 0o600)
        view = memoryview(source)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise ProvenanceValidationError(
                    f"zero-progress write while publishing {path.name}"
                )
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.link(partial, path)
        os.fsync(parent_fd)
    except BaseException as error:
        primary = error
        if isinstance(error, ProvenanceValidationError):
            raise
        raise ProvenanceValidationError(f"cannot publish {path.name}") from error
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                if primary is None:
                    raise
        try:
            partial.unlink(missing_ok=True)
        finally:
            os.close(parent_fd)


def validate_provenance(
    *,
    source_commit: str,
    runtime_index: Path,
    archive_attestation: Path,
    writer_container: str,
    verifier_container: str,
    docker: DockerPort,
    git: GitPort,
    archive_provider: ArchiveProviderPort,
) -> GateAcceptanceReceiptV1:
    validation_started_at = time.time_ns()
    try:
        runtime, runtime_source = _load_canonical(runtime_index, GateRuntimeIndexV1)
        evidence_root = runtime_index.parent
        run_index, run_source = _load_ref(
            evidence_root,
            runtime.run_index,
            GateRunIndexV1,
        )
        runtime_receipt, runtime_receipt_source = _load_ref(
            evidence_root,
            runtime.runtime_receipt,
            GateRuntimeReceiptV1,
        )
        candidate, _ = _load_ref(
            evidence_root,
            run_index.candidate_report,
            GateCandidateReportV1,
        )
        archive, _ = _load_canonical(
            archive_attestation,
            GateArchiveAttestationV1,
        )
    except (OSError, ValidationError) as error:
        raise ProvenanceValidationError(
            "provenance predecessor loading failed"
        ) from error

    if runtime.mode != "qualification" or run_index.mode != "qualification":
        raise ProvenanceValidationError(
            "functional mode cannot be provenance-qualified"
        )
    if runtime_receipt.mode != "qualification" or candidate.mode != "qualification":
        raise ProvenanceValidationError("functional predecessor cannot be qualified")
    if runtime_receipt.verified_at_unix_ns > validation_started_at:
        raise ProvenanceValidationError("runtime receipt timestamp is in the future")
    if runtime_receipt.verified_at_unix_ns > archive.verified_at_unix_ns:
        raise ProvenanceValidationError(
            "runtime receipt timestamp follows archive attestation"
        )
    if archive.verified_at_unix_ns > validation_started_at:
        raise ProvenanceValidationError(
            "archive attestation timestamp is in the future"
        )
    if not (
        runtime.run_id
        == run_index.run_id
        == runtime_receipt.run_id
        == candidate.run_id
        == archive.run_id
    ):
        raise ProvenanceValidationError("predecessor run IDs disagree")
    if runtime_receipt.run_index_sha256 != run_index.sha256:
        raise ProvenanceValidationError(
            "runtime receipt does not bind run-index self-hash"
        )
    if (
        runtime_receipt.run_index_content_sha256
        != hashlib.sha256(run_source).hexdigest()
    ):
        raise ProvenanceValidationError("runtime receipt does not bind run-index bytes")
    if (
        runtime.runtime_receipt.content_sha256
        != hashlib.sha256(runtime_receipt_source).hexdigest()
    ):
        raise ProvenanceValidationError(
            "runtime index does not bind runtime receipt bytes"
        )
    if archive.runtime_index_sha256 != runtime.sha256:
        raise ProvenanceValidationError("archive does not bind runtime-index self-hash")
    if not archive.immutable or archive.provider == "webdav":
        raise ProvenanceValidationError(
            "archive is not immutable qualification evidence"
        )
    if not runtime_receipt.qualification_runtime_accepted:
        raise ProvenanceValidationError("runtime receipt did not accept qualification")
    if run_index.implementation_source_commit != source_commit:
        raise ProvenanceValidationError("caller source commit differs from run index")
    if candidate.runtime_summary != runtime_receipt.recomputed_summary:
        raise ProvenanceValidationError(
            "candidate and runtime receipt summaries disagree"
        )
    _validate_archive_inventory(
        archive,
        evidence_root=evidence_root,
        data_root=Path(run_index.data_root),
        state_root=Path(run_index.state_root),
    )
    archive_provider_facts = _validate_archive_provider(archive, archive_provider)

    git_facts = _validate_git_facts(git.inspect_source(source_commit), source_commit)
    reproduction = _validate_reproduction(
        docker.reproduce(
            source_commit=source_commit,
            source_date_epoch=git_facts.source_date_epoch,
        ),
        git_facts=git_facts,
        run_index=run_index,
    )
    image_id = reproduction.builds[0].image_id
    writer = _validate_container(
        docker.inspect_container(writer_container),
        name=writer_container,
        image_id=image_id,
        expected_memory_limit_bytes=_WRITER_CONTAINER_MEMORY_LIMIT_BYTES,
    )
    verifier = _validate_container(
        docker.inspect_container(verifier_container),
        name=verifier_container,
        image_id=image_id,
    )
    if writer.container_id == verifier.container_id:
        raise ProvenanceValidationError(
            "writer and verifier must be distinct containers"
        )

    validation_time = time.time_ns()
    retention_until = archive.retention_until_unix_ns
    if (
        retention_until is None
        or archive_provider_facts.observed_at_unix_ns > validation_time
        or retention_until <= validation_time
    ):
        raise ProvenanceValidationError(
            "archive retention proof is not currently immutable"
        )

    summary = runtime_receipt.recomputed_summary
    if summary is None or summary.final_worker_aggregate.durability_lag_max_ns is None:
        raise ProvenanceValidationError(
            "accepted runtime receipt lacks safe result facts"
        )
    if run_index.expected_target_id is None:
        raise ProvenanceValidationError("qualification run lacks expected target ID")

    provenance_path = archive_attestation.parent / _PROVENANCE_RECEIPT_NAME
    acceptance_path = archive_attestation.parent / _ACCEPTANCE_RECEIPT_NAME
    receipt_time = validation_time
    existing_provenance_source: bytes | None = None
    if provenance_path.exists():
        existing_provenance, existing_provenance_source = _load_canonical(
            provenance_path,
            GateProvenanceReceiptV1,
        )
        existing_receipt_time = existing_provenance.verified_at_unix_ns
        if not (
            archive.verified_at_unix_ns <= existing_receipt_time <= validation_time
        ):
            raise ProvenanceValidationError(
                "existing provenance receipt timestamp is invalid"
            )
        receipt_time = existing_receipt_time

    provenance_unsigned: dict[str, object] = {
        "schema_version": 1,
        "record_type": "gate_provenance_receipt_v1",
        "verifier_version": "gate-provenance-verifier-v1",
        "verified_at_unix_ns": receipt_time,
        "run_id": run_index.run_id,
        "mode": run_index.mode,
        "runtime_index_sha256": runtime.sha256,
        "runtime_receipt_sha256": runtime_receipt.sha256,
        "archive_attestation_sha256": archive.sha256,
        "archive_sha256": archive.archive_sha256,
        "opaque_locator_sha256": archive.opaque_locator_sha256,
        "implementation_source_commit": source_commit,
        "source_date_epoch": git_facts.source_date_epoch,
        "source_archive_sha256": git_facts.source_archive_sha256s[0],
        "collector_wheel_sha256": reproduction.builds[0].collector_wheel_sha256,
        "requirements_lock_sha256": reproduction.requirements_lock_sha256,
        "build_requirements_lock_sha256": reproduction.build_requirements_lock_sha256,
        "dockerfile_sha256": reproduction.dockerfile_sha256,
        "workload_sha256": reproduction.workload_sha256,
        "image_id": image_id,
        "platform": reproduction.platform,
        "base_image_digest": reproduction.base_image_digest,
        "docker_engine_version": reproduction.docker_engine_version,
        "docker_buildx_version": reproduction.docker_buildx_version,
        "buildkit_version": reproduction.buildkit_version,
        "dockerfile_frontend": reproduction.dockerfile_frontend,
        "source_reproduction_valid": True,
        "image_reproduction_valid": True,
        "image_contract_valid": True,
        "container_binding_valid": True,
        "archive_immutable": True,
        "provenance_valid": True,
    }
    provenance = _self_hashed(GateProvenanceReceiptV1, provenance_unsigned)
    acceptance_time = receipt_time
    existing_acceptance_source: bytes | None = None
    if acceptance_path.exists():
        existing_acceptance, existing_acceptance_source = _load_canonical(
            acceptance_path,
            GateAcceptanceReceiptV1,
        )
        existing_acceptance_time = existing_acceptance.accepted_at_unix_ns
        if existing_acceptance_time != receipt_time:
            raise ProvenanceValidationError(
                "existing acceptance receipt timestamp is invalid"
            )
        acceptance_time = existing_acceptance_time
    acceptance_unsigned: dict[str, object] = {
        "schema_version": 1,
        "record_type": "gate_acceptance_receipt_v1",
        "accepted_at_unix_ns": acceptance_time,
        "run_id": run_index.run_id,
        "mode": run_index.mode,
        "runtime_receipt_sha256": runtime_receipt.sha256,
        "runtime_index_sha256": runtime.sha256,
        "archive_attestation_sha256": archive.sha256,
        "provenance_receipt_sha256": provenance.sha256,
        "expected_target_id": run_index.expected_target_id,
        "workload_sha256": run_index.workload_sha256,
        "workload_plan_sha256": run_index.workload_plan_sha256,
        "multiplier": candidate.multiplier,
        "duration_ns": candidate.duration_ns,
        "expected_record_count": summary.expected_record_count,
        "accepted_record_count": summary.accepted_record_count,
        "durable_record_count": summary.durable_record_count,
        "durability_lag_max_ns": summary.final_worker_aggregate.durability_lag_max_ns,
        "implementation_source_commit": source_commit,
        "collector_wheel_sha256": reproduction.builds[0].collector_wheel_sha256,
        "requirements_lock_sha256": reproduction.requirements_lock_sha256,
        "dockerfile_sha256": reproduction.dockerfile_sha256,
        "image_id": image_id,
        "archive_provider": archive.provider,
        "opaque_locator_sha256": archive.opaque_locator_sha256,
        "runtime_accepted": True,
        "provenance_valid": True,
        "archive_immutable": True,
        "qualification_accepted": True,
    }
    acceptance = _self_hashed(GateAcceptanceReceiptV1, acceptance_unsigned)
    provenance_source = provenance.canonical_bytes()
    acceptance_source = acceptance.canonical_bytes()
    if (
        existing_provenance_source is not None
        and existing_provenance_source != provenance_source
    ):
        raise ProvenanceValidationError(
            f"existing {provenance_path.name} conflicts with receipt"
        )
    if (
        existing_acceptance_source is not None
        and existing_acceptance_source != acceptance_source
    ):
        raise ProvenanceValidationError(
            f"existing {acceptance_path.name} conflicts with receipt"
        )
    _publish_no_replace(provenance_path, provenance_source)
    _publish_no_replace(acceptance_path, acceptance_source)
    del runtime_source
    return acceptance


def build_disclosure(
    acceptance: GateAcceptanceReceiptV1,
) -> GateEvidenceDisclosureV1:
    if not isinstance(acceptance, GateAcceptanceReceiptV1):
        raise TypeError("acceptance must be GateAcceptanceReceiptV1")
    unsigned: dict[str, object] = {
        "schema_version": 1,
        "record_type": "gate_evidence_disclosure_v1",
        "run_id": acceptance.run_id,
        "mode": acceptance.mode,
        "acceptance_receipt_sha256": acceptance.sha256,
        "runtime_index_sha256": acceptance.runtime_index_sha256,
        "provenance_receipt_sha256": acceptance.provenance_receipt_sha256,
        "archive_attestation_sha256": acceptance.archive_attestation_sha256,
        "workload_sha256": acceptance.workload_sha256,
        "workload_plan_sha256": acceptance.workload_plan_sha256,
        "multiplier": acceptance.multiplier,
        "duration_ns": acceptance.duration_ns,
        "expected_record_count": acceptance.expected_record_count,
        "accepted_record_count": acceptance.accepted_record_count,
        "durable_record_count": acceptance.durable_record_count,
        "durability_lag_max_ns": acceptance.durability_lag_max_ns,
        "implementation_source_commit": acceptance.implementation_source_commit,
        "collector_wheel_sha256": acceptance.collector_wheel_sha256,
        "requirements_lock_sha256": acceptance.requirements_lock_sha256,
        "dockerfile_sha256": acceptance.dockerfile_sha256,
        "image_id": acceptance.image_id,
        "archive_provider": acceptance.archive_provider,
        "opaque_locator_sha256": acceptance.opaque_locator_sha256,
        "qualification_accepted": acceptance.qualification_accepted,
    }
    return _self_hashed(GateEvidenceDisclosureV1, unsigned)


def load_build_provenance(path: Path) -> GateBuildProvenanceV1:
    provenance, _ = _load_canonical(path, GateBuildProvenanceV1)
    return provenance


def load_acceptance_receipt(path: Path) -> GateAcceptanceReceiptV1:
    acceptance, _ = _load_canonical(path, GateAcceptanceReceiptV1)
    return acceptance


def publish_disclosure(path: Path, disclosure: GateEvidenceDisclosureV1) -> None:
    if not isinstance(disclosure, GateEvidenceDisclosureV1):
        raise TypeError("disclosure must be GateEvidenceDisclosureV1")
    _publish_no_replace(path, disclosure.canonical_bytes())


class SubprocessGitPort:
    def __init__(self, repository: Path) -> None:
        self._repository = repository

    def _run(self, *arguments: str) -> bytes:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=self._repository,
            check=False,
            capture_output=True,
            timeout=120,
        )
        if (
            completed.returncode != 0
            or len(completed.stdout) > _MAX_COMMAND_OUTPUT_BYTES
        ):
            raise ProvenanceValidationError("Git command failed")
        return completed.stdout

    @staticmethod
    def _paths(source: bytes) -> tuple[str, ...]:
        if source and not source.endswith(b"\0"):
            raise ProvenanceValidationError("Git path output is not NUL terminated")
        try:
            paths = tuple(
                item.decode("utf-8", errors="strict")
                for item in source.split(b"\0")[:-1]
            )
        except UnicodeDecodeError as error:
            raise ProvenanceValidationError("Git path output is not UTF-8") from error
        if any(not path or "\x00" in path for path in paths) or len(set(paths)) != len(
            paths
        ):
            raise ProvenanceValidationError("Git path output is invalid")
        return tuple(sorted(paths))

    def _is_inert_python_bytecode(self, path: str) -> bool:
        relative = PurePosixPath(path)
        parts = relative.parts
        if (
            relative.is_absolute()
            or len(parts) < 2
            or "." in parts
            or ".." in parts
            or relative.suffix != ".pyc"
            or parts[-2] != "__pycache__"
        ):
            return False
        try:
            mode = self._repository.joinpath(*parts).lstat().st_mode
        except OSError:
            return False
        return stat.S_ISREG(mode)

    def inspect_source(self, source_commit: str) -> object:
        resolved = self._run(
            "rev-parse", "--verify", f"{source_commit}^{{commit}}"
        ).strip()
        head = self._run("rev-parse", "--verify", "HEAD").strip()
        if head != resolved:
            raise ProvenanceValidationError(
                "checkout HEAD differs from the source commit"
            )
        epoch = self._run("show", "-s", "--format=%ct", source_commit).strip()
        status = self._run(
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
        )
        untracked = self._paths(
            self._run(
                "ls-files",
                "--others",
                "--exclude-standard",
                "-z",
                "--",
                *_BUILD_INPUT_PATHS,
            )
        )
        ignored_paths = self._paths(
            self._run(
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
                "-z",
                "--",
                *_BUILD_INPUT_PATHS,
            )
        )
        ignored = tuple(
            path for path in ignored_paths if not self._is_inert_python_bytecode(path)
        )
        with tempfile.TemporaryDirectory(prefix="writer-git-archive-") as directory:
            archives: list[str] = []
            for ordinal in range(2):
                destination = Path(directory) / f"source-{ordinal}.tar"
                completed = subprocess.run(
                    (
                        "git",
                        "archive",
                        "--format=tar",
                        "-o",
                        destination,
                        source_commit,
                    ),
                    cwd=self._repository,
                    check=False,
                    capture_output=True,
                    timeout=120,
                )
                if completed.returncode != 0:
                    raise ProvenanceValidationError("git archive failed")
                _, archive_sha256, _ = _hash_regular_file_nofollow(
                    destination.resolve(strict=True)
                )
                archives.append(archive_sha256)
        return {
            "source_commit": resolved.decode("ascii"),
            "source_date_epoch": int(epoch.decode("ascii")),
            "checkout_clean": not status and not untracked,
            "source_archive_sha256s": tuple(archives),
            "untracked_build_inputs": untracked,
            "ignored_build_inputs": ignored,
        }


class SubprocessArchiveProviderPort:
    def __init__(self, repository: Path) -> None:
        self._repository = repository

    def _run_json(self, command: tuple[str, ...]) -> Mapping[str, Any]:
        completed = subprocess.run(
            command,
            cwd=self._repository,
            check=False,
            capture_output=True,
            timeout=300,
        )
        if (
            completed.returncode != 0
            or not completed.stdout
            or len(completed.stdout) > _MAX_COMMAND_OUTPUT_BYTES
            or len(completed.stderr) > _MAX_COMMAND_OUTPUT_BYTES
        ):
            raise ProvenanceValidationError("archive provider CLI command failed")
        try:
            decoded = decode_json(completed.stdout)
        except (TypeError, ValueError) as error:
            raise ProvenanceValidationError(
                "archive provider CLI returned invalid JSON"
            ) from error
        if not isinstance(decoded, dict):
            raise ProvenanceValidationError(
                "archive provider CLI returned an invalid object"
            )
        return cast(Mapping[str, Any], decoded)

    def _run_download(self, command: tuple[str, ...], destination: Path) -> None:
        if (
            not destination.is_absolute()
            or destination.exists()
            or destination.parent.resolve(strict=True) != destination.parent
        ):
            raise ProvenanceValidationError(
                "archive readback destination is not a new safe path"
            )
        completed = subprocess.run(
            command,
            cwd=self._repository,
            check=False,
            capture_output=True,
            timeout=3600,
        )
        if (
            completed.returncode != 0
            or len(completed.stdout) > _MAX_COMMAND_OUTPUT_BYTES
            or len(completed.stderr) > _MAX_COMMAND_OUTPUT_BYTES
            or not destination.exists()
        ):
            raise ProvenanceValidationError("archive provider readback failed")

    @staticmethod
    def _locator(locator: str, expected_scheme: str) -> tuple[str, str]:
        parsed = urlsplit(locator)
        if (
            parsed.scheme != expected_scheme
            or not parsed.netloc
            or "@" in parsed.netloc
            or ":" in parsed.netloc
            or parsed.query
            or parsed.fragment
            or not parsed.path.startswith("/")
            or parsed.path == "/"
            or "\x00" in locator
            or any(character.isspace() for character in parsed.netloc)
        ):
            raise ProvenanceValidationError("archive provider locator is invalid")
        return parsed.netloc, parsed.path[1:]

    @staticmethod
    def _field(value: Mapping[str, Any], *names: str) -> object:
        normalized_names = {re.sub(r"[^a-z0-9]", "", name.casefold()) for name in names}
        matches: list[object] = []
        for candidate in (value, value.get("Headers"), value.get("headers")):
            if not isinstance(candidate, Mapping):
                continue
            for key, item in candidate.items():
                if (
                    isinstance(key, str)
                    and re.sub(r"[^a-z0-9]", "", key.casefold()) in normalized_names
                ):
                    matches.append(item)
        if not matches or any(item != matches[0] for item in matches[1:]):
            raise ProvenanceValidationError(
                "archive provider response field is missing or ambiguous"
            )
        return matches[0]

    @staticmethod
    def _timestamp_ns(value: object) -> int:
        if type(value) is not str or not value:
            raise ProvenanceValidationError("archive retention timestamp is invalid")
        try:
            parsed = datetime.fromisoformat(value)
        except ValueError as error:
            raise ProvenanceValidationError(
                "archive retention timestamp is invalid"
            ) from error
        if parsed.tzinfo is None:
            raise ProvenanceValidationError(
                "archive retention timestamp lacks a timezone"
            )
        utc = parsed.astimezone(UTC)
        return int(utc.timestamp()) * 1_000_000_000 + utc.microsecond * 1_000

    def _verify_s3(
        self,
        *,
        locator: str,
        object_version: str,
        destination: Path,
    ) -> dict[str, object]:
        bucket, key = self._locator(locator, "s3")
        identity = (
            "--bucket",
            bucket,
            "--key",
            key,
            "--version-id",
            object_version,
        )
        head = self._run_json(
            ("aws", "s3api", "head-object", *identity, "--output", "json")
        )
        version = self._field(head, "VersionId")
        content_size = self._field(head, "ContentLength")
        mode = self._field(head, "ObjectLockMode")
        retention_until = self._field(head, "ObjectLockRetainUntilDate")
        if version != object_version or mode != "COMPLIANCE":
            raise ProvenanceValidationError(
                "S3 object version or Object Lock mode is invalid"
            )
        if type(content_size) is not int or content_size < 0:
            raise ProvenanceValidationError("S3 object size is invalid")
        get_command = (
            "aws",
            "s3api",
            "get-object",
            *identity,
            "--output",
            "json",
            destination.as_posix(),
        )
        self._run_download(get_command, destination)
        return {
            "provider": "s3_object_lock",
            "archive_locator": locator,
            "object_version": object_version,
            "retention_mode": "compliance",
            "retention_until_unix_ns": self._timestamp_ns(retention_until),
            "observed_at_unix_ns": time.time_ns(),
            "content_size_bytes": content_size,
        }

    def _verify_oss(
        self,
        *,
        locator: str,
        object_version: str,
        destination: Path,
    ) -> dict[str, object]:
        bucket, key = self._locator(locator, "oss")
        identity = (
            "--bucket",
            bucket,
            "--key",
            key,
            "--version-id",
            object_version,
        )
        head = self._run_json(
            (
                "ossutil",
                "api",
                "head-object",
                *identity,
                "--output-format",
                "json",
            )
        )
        retention = self._run_json(
            (
                "ossutil",
                "api",
                "get-object-retention",
                *identity,
                "--output-format",
                "json",
            )
        )
        version = self._field(head, "VersionId", "x-oss-version-id")
        content_size = self._field(head, "ContentLength", "content-length")
        retention_value = retention.get("Retention")
        if not isinstance(retention_value, Mapping):
            raise ProvenanceValidationError("OSS retention response is invalid")
        mode = self._field(retention_value, "Mode")
        retention_until = self._field(retention_value, "RetainUntilDate")
        if version != object_version or mode != "COMPLIANCE":
            raise ProvenanceValidationError(
                "OSS object version or WORM mode is invalid"
            )
        if type(content_size) is not int or content_size < 0:
            raise ProvenanceValidationError("OSS object size is invalid")
        self._run_download(
            (
                "ossutil",
                "cp",
                locator,
                destination.as_posix(),
                "--version-id",
                object_version,
                "--force",
                "--no-progress",
            ),
            destination,
        )
        return {
            "provider": "oss_worm",
            "archive_locator": locator,
            "object_version": object_version,
            "retention_mode": "worm",
            "retention_until_unix_ns": self._timestamp_ns(retention_until),
            "observed_at_unix_ns": time.time_ns(),
            "content_size_bytes": content_size,
        }

    def verify_and_download(
        self,
        *,
        provider: str,
        archive_locator: str,
        object_version: str,
        destination: Path,
    ) -> object:
        if provider == "s3_object_lock":
            return self._verify_s3(
                locator=archive_locator,
                object_version=object_version,
                destination=destination,
            )
        if provider == "oss_worm":
            return self._verify_oss(
                locator=archive_locator,
                object_version=object_version,
                destination=destination,
            )
        if provider == "webdav":
            raise ProvenanceValidationError(
                "WebDAV cannot provide immutable qualification evidence"
            )
        raise ProvenanceValidationError("archive provider is unsupported")


class SubprocessDockerPort:
    def __init__(self, repository: Path) -> None:
        self._repository = repository

    def reproduce(self, *, source_commit: str, source_date_epoch: int) -> object:
        script = subprocess.run(
            (
                "git",
                "show",
                f"{source_commit}:scripts/reproduce-writer-image.sh",
            ),
            cwd=self._repository,
            check=False,
            capture_output=True,
            timeout=120,
        )
        if (
            script.returncode != 0
            or not script.stdout
            or len(script.stdout) > _MAX_COMMAND_OUTPUT_BYTES
            or len(script.stderr) > _MAX_COMMAND_OUTPUT_BYTES
        ):
            raise ProvenanceValidationError(
                "committed image reproduction script cannot be loaded"
            )
        completed = subprocess.run(
            (
                "bash",
                "-s",
                "--",
                "--source-commit",
                source_commit,
                "--source-date-epoch",
                str(source_date_epoch),
            ),
            cwd=self._repository,
            check=False,
            input=script.stdout,
            stdout=subprocess.PIPE,
            timeout=3600,
        )
        if (
            completed.returncode != 0
            or not completed.stdout
            or len(completed.stdout) > _MAX_COMMAND_OUTPUT_BYTES
        ):
            raise ProvenanceValidationError("image reproduction script failed")
        try:
            return decode_json(completed.stdout)
        except (TypeError, ValueError) as error:
            raise ProvenanceValidationError(
                "reproduction transcript is invalid"
            ) from error

    def _inspect(self, identifier: str) -> Mapping[str, Any]:
        completed = subprocess.run(
            ("docker", "container", "inspect", identifier),
            cwd=self._repository,
            check=False,
            capture_output=True,
            timeout=120,
        )
        if (
            completed.returncode != 0
            or len(completed.stdout) > _MAX_COMMAND_OUTPUT_BYTES
        ):
            raise ProvenanceValidationError("docker container inspect failed")
        decoded = decode_json(completed.stdout)
        if (
            not isinstance(decoded, list)
            or len(decoded) != 1
            or not isinstance(decoded[0], dict)
        ):
            raise ProvenanceValidationError("docker container inspect shape is invalid")
        return cast(Mapping[str, Any], decoded[0])

    def inspect_container(self, name: str) -> object:
        first = self._inspect(name)
        container_id = first.get("Id")
        if (
            type(container_id) is not str
            or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
        ):
            raise ProvenanceValidationError("container inspect lacks immutable ID")
        inspected = self._inspect(container_id)
        if inspected.get("Id") != container_id:
            raise ProvenanceValidationError(
                "container identity changed during immutable-ID inspect"
            )
        state = inspected.get("State")
        if not isinstance(state, dict):
            raise ProvenanceValidationError("container inspect lacks state")
        host_config = inspected.get("HostConfig")
        if not isinstance(host_config, dict):
            raise ProvenanceValidationError("container inspect lacks host config")
        return {
            "container_id": inspected.get("Id"),
            "name": str(inspected.get("Name", "")).removeprefix("/"),
            "exists": True,
            "removed": False,
            "status": state.get("Status"),
            "running": state.get("Running"),
            "paused": state.get("Paused"),
            "restarting": state.get("Restarting"),
            "oom_killed": state.get("OOMKilled"),
            "dead": state.get("Dead"),
            "pid": state.get("Pid"),
            "exit_code": state.get("ExitCode"),
            "error": state.get("Error"),
            "image_id": inspected.get("Image"),
            "memory_limit_bytes": host_config.get("Memory"),
            "memory_swap_limit_bytes": host_config.get("MemorySwap"),
        }


__all__ = [
    "ArchiveProviderPort",
    "DockerPort",
    "GitPort",
    "ProvenanceValidationError",
    "SubprocessArchiveProviderPort",
    "SubprocessDockerPort",
    "SubprocessGitPort",
    "build_disclosure",
    "load_acceptance_receipt",
    "load_build_provenance",
    "publish_disclosure",
    "validate_provenance",
]
