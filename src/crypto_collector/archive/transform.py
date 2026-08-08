from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import re
import stat
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from enum import StrEnum
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import IO, Self, cast

import zstandard

from crypto_collector.archive.keys import data_key, uses_encoded_data
from crypto_collector.archive.models import (
    ArchiveJobKey,
    ArchivePolicyV1,
    FrozenArchiveTargetV1,
    FrozenCompressionPolicyV1,
    SourceArtifact,
    canonical_json_bytes,
)
from crypto_collector.storage.errors import PublicationConflict
from crypto_collector.storage.raw_writer import (
    open_readonly_nofollow,
    size_and_sha256_fd,
)

_MAX_SIGNED_INT64 = 2**63 - 1
_IO_CHUNK_BYTES = 1024 * 1024
_ZSTANDARD_RUNTIME_VERSION = distribution_version("zstandard")
_POLICY_DIRECTORY = re.compile(r"^policy=[0-9a-f]{64}$")
_TARGET_DIRECTORY = re.compile(r"^target=[a-z0-9][a-z0-9._-]{0,63}$")
_MANIFEST_DIRECTORY = re.compile(r"^[0-9a-f]{64}$")
_STORED_FILE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\.[0-9a-f]{64}\.zst$")
_PARTIAL_FILE = re.compile(
    r"^\.[a-z0-9][a-z0-9._-]{0,63}\.[0-9a-f]{64}\.zst"
    r"\.partial\.[a-z0-9][a-z0-9_-]{0,63}$"
)
_OWNER_REGISTRY_LOCK = threading.Lock()
_OWNED_STAGING_ROOTS: set[tuple[int, int]] = set()


class TransformError(RuntimeError):
    pass


class SourceIdentityMismatch(TransformError):
    pass


class StagingCapacityExceeded(TransformError):
    pass


class StagingSpaceExhausted(TransformError):
    pass


class StagingConflictError(TransformError):
    pass


class StagingOwnershipError(TransformError):
    pass


class StagingReconciliationError(TransformError):
    pass


class TransformPlanMismatch(TransformError):
    pass


class TransformRuntimeMismatch(TransformError):
    pass


class TransformKind(StrEnum):
    PASSTHROUGH = "passthrough"
    ZSTD_V1 = "zstd-v1"


@dataclass(frozen=True, slots=True)
class TransformPlan:
    job_key: ArchiveJobKey
    artifact: SourceArtifact
    policy: ArchivePolicyV1
    target: FrozenArchiveTargetV1
    data_root: Path
    source_path: Path
    kind: TransformKind
    stored_key: str


@dataclass(frozen=True, slots=True)
class StoredArtifact:
    job_key: ArchiveJobKey
    source_relative_path: str
    source_path: Path
    source_size_bytes: int
    source_sha256: str
    path: Path
    size_bytes: int
    sha256: str
    transform_kind: TransformKind
    codec: str
    codec_level: int | None
    codec_policy_version: int | None
    codec_tool: str | None
    codec_version: str | None
    transform_profile: str | None
    transform_implementation_sha256: str | None


@dataclass(frozen=True, slots=True)
class _StagingReservation:
    requested_bytes: int
    partial_path: Path | None


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise OSError(errno.ENOTSUP, f"required open flag {name} is unavailable")
    return value


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
    )


def _normalized_absolute(value: Path, *, field_name: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"{field_name} must be Path")
    if not value.is_absolute() or any(
        part in {"", ".", ".."} for part in value.parts[1:]
    ):
        raise ValueError(f"{field_name} must be a normalized absolute path")
    return value


def _close_quietly(fd: int) -> None:
    with suppress(OSError):
        os.close(fd)


def _open_or_create_directory(path: Path) -> int:
    directory = _normalized_absolute(path, field_name="staging directory")
    current_fd = os.open(directory.anchor, _directory_flags())
    try:
        for segment in directory.parts[1:]:
            try:
                child_fd = os.open(segment, _directory_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(segment, mode=0o750, dir_fd=current_fd)
                except FileExistsError:
                    pass
                else:
                    os.fsync(current_fd)
                child_fd = os.open(segment, _directory_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        _close_quietly(current_fd)
        raise


def _open_existing_directory(path: Path) -> int:
    directory = _normalized_absolute(path, field_name="staging directory")
    current_fd = os.open(directory.anchor, _directory_flags())
    try:
        for segment in directory.parts[1:]:
            child_fd = os.open(segment, _directory_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        _close_quietly(current_fd)
        raise


def _open_relative_directory(
    root_fd: int,
    parts: tuple[str, ...],
    *,
    create: bool,
) -> int:
    current_fd = os.open(".", _directory_flags(), dir_fd=root_fd)
    try:
        for segment in parts:
            try:
                child_fd = os.open(segment, _directory_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(segment, mode=0o750, dir_fd=current_fd)
                except FileExistsError:
                    pass
                else:
                    os.fsync(current_fd)
                child_fd = os.open(segment, _directory_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        _close_quietly(current_fd)
        raise


def _validated_job_key(key: ArchiveJobKey) -> ArchiveJobKey:
    if type(key) is not ArchiveJobKey:
        raise TypeError("key must be ArchiveJobKey")
    try:
        validated = ArchiveJobKey.model_validate(key.model_dump(mode="python"))
    except ValueError as error:
        raise StagingReconciliationError("staging job key is invalid") from error
    if validated != key:
        raise StagingReconciliationError("staging job key is not canonical")
    return validated


def _staging_job_parts(key: ArchiveJobKey) -> tuple[str, str, str]:
    validated = _validated_job_key(key)
    return (
        f"policy={validated.policy_sha256}",
        f"target={validated.target_id}",
        validated.source_manifest_sha256,
    )


def _unlink_scanned_regular(
    directory_fd: int,
    name: str,
    observed: os.stat_result,
) -> None:
    flags = (
        os.O_RDONLY
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NONBLOCK")
    )
    file_fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (
            observed.st_dev,
            observed.st_ino,
        ):
            raise StagingReconciliationError(
                "staging partial changed during reconciliation"
            )
        os.unlink(name, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(file_fd)


def _scan_directory_bytes(
    directory_fd: int,
    *,
    relative_parts: tuple[str, ...] = (),
    excluded_partials: frozenset[tuple[str, ...]] = frozenset(),
    reconcile_orphans: bool = False,
) -> int:
    total = 0
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            observed = entry.stat(follow_symlinks=False)
            relative = (*relative_parts, entry.name)
            depth = len(relative_parts)
            if stat.S_ISLNK(observed.st_mode):
                if depth == 3 and _STORED_FILE.fullmatch(entry.name) is not None:
                    raise StagingConflictError(
                        "immutable staging destination is not a regular file"
                    )
                raise StagingReconciliationError("staging tree contains a symlink")
            if stat.S_ISREG(observed.st_mode):
                if depth != 3:
                    raise StagingReconciliationError(
                        "staging tree contains an unbound regular file"
                    )
                if _PARTIAL_FILE.fullmatch(entry.name) is not None:
                    if relative in excluded_partials:
                        continue
                    if reconcile_orphans:
                        _unlink_scanned_regular(directory_fd, entry.name, observed)
                        continue
                    raise StagingReconciliationError(
                        "staging tree contains an inactive partial"
                    )
                if _STORED_FILE.fullmatch(entry.name) is None:
                    raise StagingReconciliationError(
                        "staging tree contains an unbound regular file"
                    )
                total += observed.st_size
                if total > _MAX_SIGNED_INT64:
                    raise StagingCapacityExceeded("staging byte usage exceeds int64")
                continue
            if stat.S_ISDIR(observed.st_mode):
                valid_directory = (
                    (depth == 0 and _POLICY_DIRECTORY.fullmatch(entry.name) is not None)
                    or (
                        depth == 1
                        and _TARGET_DIRECTORY.fullmatch(entry.name) is not None
                    )
                    or (
                        depth == 2
                        and _MANIFEST_DIRECTORY.fullmatch(entry.name) is not None
                    )
                )
                if not valid_directory:
                    if depth == 3 and _STORED_FILE.fullmatch(entry.name) is not None:
                        raise StagingConflictError(
                            "immutable staging destination is not a regular file"
                        )
                    raise StagingReconciliationError(
                        "staging tree contains an unbound directory"
                    )
                child_fd = os.open(entry.name, _directory_flags(), dir_fd=directory_fd)
                try:
                    total += _scan_directory_bytes(
                        child_fd,
                        relative_parts=relative,
                        excluded_partials=excluded_partials,
                        reconcile_orphans=reconcile_orphans,
                    )
                finally:
                    os.close(child_fd)
                if total > _MAX_SIGNED_INT64:
                    raise StagingCapacityExceeded("staging byte usage exceeds int64")
                continue
            if depth == 3 and _STORED_FILE.fullmatch(entry.name) is not None:
                raise StagingConflictError(
                    "immutable staging destination is not a regular file"
                )
            raise StagingReconciliationError(
                "staging tree contains a non-file filesystem object"
            )
    return total


def _acquire_staging_owner(root: Path) -> tuple[int, tuple[int, int]]:
    root_fd = _open_or_create_directory(root)
    try:
        os.fsync(root_fd)
        root_stat = os.fstat(root_fd)
        root_identity = (root_stat.st_dev, root_stat.st_ino)
        with _OWNER_REGISTRY_LOCK:
            if root_identity in _OWNED_STAGING_ROOTS:
                raise StagingOwnershipError(
                    "staging root already has an owner in this process"
                )
            try:
                fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno not in {errno.EACCES, errno.EAGAIN}:
                    raise
                raise StagingOwnershipError(
                    "staging root already has an active process owner"
                ) from error
            _OWNED_STAGING_ROOTS.add(root_identity)
        return root_fd, root_identity
    except BaseException:
        _close_quietly(root_fd)
        raise


def _release_staging_owner(
    owner_fd: int,
    root_identity: tuple[int, int],
) -> None:
    try:
        fcntl.flock(owner_fd, fcntl.LOCK_UN)
    finally:
        _close_quietly(owner_fd)
        with _OWNER_REGISTRY_LOCK:
            _OWNED_STAGING_ROOTS.discard(root_identity)


class StagingBudget:
    __slots__ = (
        "_active",
        "_closed",
        "_lock",
        "_max_bytes",
        "_max_concurrency",
        "_owner_fd",
        "_root",
        "_root_identity",
    )

    def __init__(
        self,
        root: Path,
        *,
        max_bytes: int,
        max_concurrency: int,
    ) -> None:
        self._root = _normalized_absolute(root, field_name="staging root")
        if type(max_bytes) is not int or not 0 < max_bytes <= _MAX_SIGNED_INT64:
            raise ValueError("max_bytes must be a positive signed int64")
        if (
            type(max_concurrency) is not int
            or not 0 < max_concurrency <= _MAX_SIGNED_INT64
        ):
            raise ValueError("max_concurrency must be a positive signed int64")
        self._max_bytes = max_bytes
        self._max_concurrency = max_concurrency
        self._active: dict[str, _StagingReservation] = {}
        self._lock = threading.Lock()
        self._closed = True
        self._owner_fd, self._root_identity = _acquire_staging_owner(self._root)
        self._closed = False
        try:
            if self._used_bytes(reconcile_orphans=True) > self._max_bytes:
                raise StagingCapacityExceeded(
                    "existing staging bytes exceed the configured limit"
                )
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(self, *ignored: object) -> None:
        del ignored
        self.close()

    def __del__(self) -> None:
        if not getattr(self, "_closed", True):
            with suppress(BaseException):
                self.close()

    def _require_open(self) -> None:
        if self._closed:
            raise StagingOwnershipError("staging budget is closed")
        try:
            observed_fd = _open_existing_directory(self._root)
        except OSError as error:
            raise StagingOwnershipError(
                "staging root no longer resolves to its owned directory"
            ) from error
        try:
            observed = os.fstat(observed_fd)
        finally:
            os.close(observed_fd)
        if (observed.st_dev, observed.st_ino) != self._root_identity:
            raise StagingOwnershipError(
                "staging root was replaced while the budget was active"
            )

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            if self._active:
                raise StagingOwnershipError(
                    "staging budget cannot close with active reservations"
                )
            self._closed = True
            owner_fd = self._owner_fd
            self._owner_fd = -1
        _release_staging_owner(owner_fd, self._root_identity)

    @property
    def root(self) -> Path:
        return self._root

    @property
    def active_reservations(self) -> int:
        with self._lock:
            self._require_open()
            return len(self._active)

    def _active_partial_paths(self) -> frozenset[tuple[str, ...]]:
        result: set[tuple[str, ...]] = set()
        for reservation in self._active.values():
            partial = reservation.partial_path
            if partial is None:
                continue
            try:
                result.add(partial.relative_to(self._root).parts)
            except ValueError as error:
                raise StagingReconciliationError(
                    "active staging partial escaped its root"
                ) from error
        return frozenset(result)

    def _used_bytes(self, *, reconcile_orphans: bool) -> int:
        self._require_open()
        root_fd = os.open(".", _directory_flags(), dir_fd=self._owner_fd)
        try:
            return _scan_directory_bytes(
                root_fd,
                excluded_partials=self._active_partial_paths(),
                reconcile_orphans=reconcile_orphans,
            )
        finally:
            os.close(root_fd)

    def _begin_reservation(
        self,
        token: str,
        requested_bytes: int,
        *,
        partial_path: Path | None,
    ) -> None:
        self._require_open()
        if len(self._active) >= self._max_concurrency:
            raise StagingCapacityExceeded("staging concurrency limit is exhausted")
        used = self._used_bytes(reconcile_orphans=True)
        reserved = sum(item.requested_bytes for item in self._active.values())
        if used + reserved + requested_bytes > self._max_bytes:
            raise StagingCapacityExceeded("staging bytes limit is exhausted")
        self._active[token] = _StagingReservation(
            requested_bytes=requested_bytes,
            partial_path=partial_path,
        )

    @staticmethod
    def _validate_requested_bytes(requested_bytes: int) -> None:
        if (
            type(requested_bytes) is not int
            or not 0 < requested_bytes <= _MAX_SIGNED_INT64
        ):
            raise ValueError("requested_bytes must be a positive signed int64")

    @contextmanager
    def reserve(self, requested_bytes: int) -> Iterator[None]:
        self._validate_requested_bytes(requested_bytes)
        token = uuid.uuid4().hex
        with self._lock:
            self._begin_reservation(token, requested_bytes, partial_path=None)
        try:
            yield
        finally:
            with self._lock:
                self._active.pop(token, None)

    @contextmanager
    def reserve_existing_transform(self) -> Iterator[None]:
        token = uuid.uuid4().hex
        with self._lock:
            self._begin_reservation(token, 0, partial_path=None)
        try:
            yield
        finally:
            with self._lock:
                self._active.pop(token, None)

    @contextmanager
    def reserve_transform(
        self,
        key: ArchiveJobKey,
        requested_bytes: int,
    ) -> Iterator[Path]:
        self._validate_requested_bytes(requested_bytes)
        destination = self.path_for(key)
        partial = destination.with_name(
            f".{destination.name}.partial.{uuid.uuid4().hex}"
        )
        token = uuid.uuid4().hex
        with self._lock:
            self._begin_reservation(
                token,
                requested_bytes,
                partial_path=partial,
            )
        try:
            yield partial
        finally:
            with self._lock:
                self._active.pop(token, None)

    def path_for(self, key: ArchiveJobKey) -> Path:
        self._require_open()
        validated = _validated_job_key(key)
        return (
            self._root
            / f"policy={validated.policy_sha256}"
            / f"target={validated.target_id}"
            / validated.source_manifest_sha256
            / f"{validated.artifact_role}.{validated.artifact_sha256}.zst"
        )

    def _open_job_parent(self, key: ArchiveJobKey, *, create: bool) -> int:
        self._require_open()
        return _open_relative_directory(
            self._owner_fd,
            _staging_job_parts(key),
            create=create,
        )

    def _require_job_destination(
        self,
        key: ArchiveJobKey,
        parent_fd: int,
        destination: Path,
        *,
        expected_size_bytes: int,
        expected_sha256: str,
        expected_file_fd: int | None = None,
    ) -> None:
        self._require_open()
        try:
            observed_parent_fd = self._open_job_parent(key, create=False)
        except OSError as error:
            raise StagingOwnershipError(
                "staging job parent no longer exists under its owned root"
            ) from error
        try:
            expected_parent = os.fstat(parent_fd)
            observed_parent = os.fstat(observed_parent_fd)
            if (expected_parent.st_dev, expected_parent.st_ino) != (
                observed_parent.st_dev,
                observed_parent.st_ino,
            ):
                raise StagingOwnershipError(
                    "staging job parent moved outside its owned root"
                )
            try:
                observed_file_fd = _open_regular_at(
                    observed_parent_fd,
                    destination.name,
                )
            except OSError as error:
                raise StagingConflictError(
                    "staging destination is missing after publication"
                ) from error
            try:
                if expected_file_fd is not None and not _same_inode(
                    expected_file_fd,
                    os.fstat(observed_file_fd),
                ):
                    raise StagingConflictError(
                        "staging destination inode changed after publication"
                    )
                if size_and_sha256_fd(observed_file_fd) != (
                    expected_size_bytes,
                    expected_sha256,
                ):
                    raise StagingConflictError(
                        "staging destination identity changed after publication"
                    )
                _require_name_is_open_inode(
                    observed_parent_fd,
                    destination.name,
                    observed_file_fd,
                )
            finally:
                os.close(observed_file_fd)
        finally:
            os.close(observed_parent_fd)
        self._require_open()

    def release(self, path: Path) -> None:
        self._require_open()
        candidate = _normalized_absolute(path, field_name="staging artifact")
        try:
            relative = candidate.relative_to(self._root)
        except ValueError as error:
            raise ValueError("staging artifact is outside the staging root") from error
        if (
            len(relative.parts) != 4
            or _POLICY_DIRECTORY.fullmatch(relative.parts[0]) is None
            or _TARGET_DIRECTORY.fullmatch(relative.parts[1]) is None
            or _MANIFEST_DIRECTORY.fullmatch(relative.parts[2]) is None
            or _STORED_FILE.fullmatch(relative.parts[3]) is None
        ):
            raise ValueError("staging artifact path is not deterministic")
        with self._lock:
            self._require_open()
            parent_fd = _open_relative_directory(
                self._owner_fd,
                cast(tuple[str, ...], relative.parts[:3]),
                create=False,
            )
            try:
                self._require_open()
                flags = (
                    os.O_RDONLY
                    | _required_flag("O_NOFOLLOW")
                    | _required_flag("O_CLOEXEC")
                    | _required_flag("O_NONBLOCK")
                )
                file_fd = os.open(candidate.name, flags, dir_fd=parent_fd)
                try:
                    if not stat.S_ISREG(os.fstat(file_fd).st_mode):
                        raise OSError(errno.EINVAL, "staging artifact is not regular")
                    current = os.stat(
                        candidate.name, dir_fd=parent_fd, follow_symlinks=False
                    )
                    opened = os.fstat(file_fd)
                    if (current.st_dev, current.st_ino) != (
                        opened.st_dev,
                        opened.st_ino,
                    ):
                        raise OSError(
                            errno.EBUSY, "staging artifact changed before release"
                        )
                    os.unlink(candidate.name, dir_fd=parent_fd)
                    os.fsync(parent_fd)
                    self._require_open()
                finally:
                    os.close(file_fd)
            finally:
                os.close(parent_fd)


def _source_identity(path: Path) -> tuple[int, str]:
    fd = open_readonly_nofollow(path)
    try:
        return size_and_sha256_fd(fd)
    finally:
        os.close(fd)


def _validate_source_fd(fd: int, artifact: SourceArtifact) -> None:
    if size_and_sha256_fd(fd) != (artifact.size_bytes, artifact.sha256):
        raise SourceIdentityMismatch("archive source identity does not match manifest")


def plan_transform(
    data_root: Path,
    artifact: SourceArtifact,
    *,
    source_manifest_sha256: str,
    policy: ArchivePolicyV1,
    target_id: str,
) -> TransformPlan:
    root = _normalized_absolute(data_root, field_name="data root")
    if type(artifact) is not SourceArtifact:
        raise TypeError("artifact must be SourceArtifact")
    if type(policy) is not ArchivePolicyV1:
        raise TypeError("policy must be ArchivePolicyV1")
    try:
        artifact = SourceArtifact.model_validate(artifact.model_dump(mode="python"))
        policy = ArchivePolicyV1.model_validate(policy.model_dump(mode="python"))
    except ValueError as error:
        raise TransformPlanMismatch(
            "transform inputs do not match validated archive facts"
        ) from error
    try:
        target = policy.target(target_id)
    except KeyError as error:
        raise ValueError("target is not present in the frozen policy") from error
    source_path = root / artifact.relative_path
    observed = _source_identity(source_path)
    if observed != (artifact.size_bytes, artifact.sha256):
        raise SourceIdentityMismatch("archive source identity does not match manifest")
    key = ArchiveJobKey(
        source_manifest_sha256=source_manifest_sha256,
        artifact_role=artifact.artifact_role,
        artifact_sha256=artifact.sha256,
        target_id=target.target_id,
        policy_sha256=policy.policy_sha256,
    )
    kind = (
        TransformKind.ZSTD_V1
        if uses_encoded_data(artifact, target)
        else TransformKind.PASSTHROUGH
    )
    return TransformPlan(
        job_key=key,
        artifact=artifact,
        policy=policy,
        target=target,
        data_root=root,
        source_path=source_path,
        kind=kind,
        stored_key=data_key(artifact, policy, target_id=target.target_id),
    )


def _validate_plan(plan: TransformPlan) -> None:
    if (
        type(plan.job_key) is not ArchiveJobKey
        or type(plan.artifact) is not SourceArtifact
        or type(plan.policy) is not ArchivePolicyV1
        or type(plan.target) is not FrozenArchiveTargetV1
        or not isinstance(plan.data_root, Path)
        or not isinstance(plan.source_path, Path)
        or type(plan.kind) is not TransformKind
        or type(plan.stored_key) is not str
    ):
        raise TransformPlanMismatch("transform plan contains an invalid field type")
    try:
        expected_key_input = ArchiveJobKey.model_validate(
            plan.job_key.model_dump(mode="python")
        )
        expected_artifact = SourceArtifact.model_validate(
            plan.artifact.model_dump(mode="python")
        )
        expected_policy = ArchivePolicyV1.model_validate(
            plan.policy.model_dump(mode="python")
        )
        root = _normalized_absolute(plan.data_root, field_name="data root")
        source_path = _normalized_absolute(plan.source_path, field_name="source path")
        expected_target = expected_policy.target(expected_key_input.target_id)
    except (KeyError, TypeError, ValueError) as error:
        raise TransformPlanMismatch("transform plan is not policy bound") from error
    expected_key = ArchiveJobKey(
        source_manifest_sha256=expected_key_input.source_manifest_sha256,
        artifact_role=expected_artifact.artifact_role,
        artifact_sha256=expected_artifact.sha256,
        target_id=expected_target.target_id,
        policy_sha256=expected_policy.policy_sha256,
    )
    expected_kind = (
        TransformKind.ZSTD_V1
        if uses_encoded_data(expected_artifact, expected_target)
        else TransformKind.PASSTHROUGH
    )
    expected_stored_key = data_key(
        expected_artifact,
        expected_policy,
        target_id=expected_target.target_id,
    )
    if (
        plan.job_key != expected_key
        or plan.artifact != expected_artifact
        or plan.policy != expected_policy
        or plan.target != expected_target
        or source_path != root / expected_artifact.relative_path
        or plan.kind is not expected_kind
        or plan.stored_key != expected_stored_key
    ):
        raise TransformPlanMismatch("transform plan does not match frozen policy facts")


def _validate_transform_runtime(plan: TransformPlan) -> None:
    if plan.kind is TransformKind.PASSTHROUGH:
        return
    compression = plan.target.compression
    runtime_identity = {
        "codec": compression.codec,
        "codec_policy_version": compression.codec_policy_version,
        "transform_profile": compression.transform_profile,
        "codec_tool": compression.codec_tool,
        "codec_tool_version": _ZSTANDARD_RUNTIME_VERSION,
    }
    runtime_implementation = hashlib.sha256(
        canonical_json_bytes(runtime_identity)
    ).hexdigest()
    if (
        compression.codec_tool_version != _ZSTANDARD_RUNTIME_VERSION
        or compression.transform_implementation_sha256 != runtime_implementation
    ):
        raise TransformRuntimeMismatch(
            "frozen transform identity does not match the zstandard runtime"
        )


def _compress_bound(source_size: int) -> int:
    small_adjustment = (
        ((128 * 1024) - source_size) >> 11 if source_size < 128 * 1024 else 0
    )
    bound = source_size + (source_size >> 8) + small_adjustment + 64
    if bound > _MAX_SIGNED_INT64:
        raise StagingCapacityExceeded("zstd output bound exceeds signed int64")
    return bound


def _write_all(fd: int, data: bytes | memoryview) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError(errno.EIO, "staging write made no progress")
        view = view[written:]


class _BoundedFdWriter:
    __slots__ = ("_fd", "_limit", "_written")

    def __init__(self, fd: int, limit: int) -> None:
        self._fd = fd
        self._limit = limit
        self._written = 0

    def write(self, data: bytes | memoryview) -> int:
        size = len(data)
        if self._written + size > self._limit:
            raise StagingCapacityExceeded(
                "zstd output exceeded its staging reservation"
            )
        _write_all(self._fd, data)
        self._written += size
        return size

    def flush(self) -> None:
        return


class _ExistingOutputComparator:
    __slots__ = ("_digest", "_fd", "_limit", "_offset")

    def __init__(self, fd: int, limit: int) -> None:
        self._fd = fd
        self._limit = limit
        self._offset = 0
        self._digest = hashlib.sha256()

    def write(self, data: bytes | memoryview) -> int:
        view = memoryview(data)
        size = len(view)
        if self._offset + size > self._limit:
            raise StagingCapacityExceeded(
                "zstd output exceeded its staging reservation"
            )
        expected = bytearray()
        while len(expected) < size:
            try:
                chunk = os.pread(
                    self._fd,
                    size - len(expected),
                    self._offset + len(expected),
                )
            except InterruptedError:
                continue
            if not chunk:
                raise StagingConflictError(
                    "immutable staging destination is not the canonical transform"
                )
            expected.extend(chunk)
        if view.tobytes() != expected:
            raise StagingConflictError(
                "immutable staging destination is not the canonical transform"
            )
        self._digest.update(view)
        self._offset += size
        return size

    def flush(self) -> None:
        return

    def finish(self) -> tuple[int, str]:
        while True:
            try:
                remainder = os.pread(self._fd, 1, self._offset)
            except InterruptedError:
                continue
            break
        if remainder:
            raise StagingConflictError(
                "immutable staging destination is not the canonical transform"
            )
        return self._offset, self._digest.hexdigest()


def _stream_zstd_to_sink(
    source_fd: int,
    sink: IO[bytes],
    *,
    source_size: int,
    source_sha256: str,
    compression: FrozenCompressionPolicyV1,
) -> None:
    compressor = zstandard.ZstdCompressor(
        level=compression.level,
        write_checksum=True,
        write_content_size=True,
        threads=0,
    )
    writer = compressor.stream_writer(
        cast(IO[bytes], sink),
        size=source_size,
        closefd=False,
    )
    primary_error: BaseException | None = None
    streamed_size = 0
    streamed_sha256 = hashlib.sha256()
    try:
        while True:
            try:
                chunk = os.read(source_fd, _IO_CHUNK_BYTES)
            except InterruptedError:
                continue
            if not chunk:
                break
            accepted = writer.write(chunk)
            if accepted != len(chunk):
                raise OSError(errno.EIO, "zstd writer accepted a partial source chunk")
            streamed_size += len(chunk)
            streamed_sha256.update(chunk)
        if streamed_size != source_size or streamed_sha256.hexdigest() != source_sha256:
            raise SourceIdentityMismatch(
                "streamed archive source identity does not match manifest"
            )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            writer.close()
        except BaseException as close_error:
            if primary_error is None:
                raise
            primary_error.add_note(f"zstd close also failed: {close_error!r}")


def _stream_zstd(
    source_fd: int,
    destination_fd: int,
    *,
    source_size: int,
    source_sha256: str,
    compression: FrozenCompressionPolicyV1,
    output_limit: int,
) -> None:
    sink = _BoundedFdWriter(destination_fd, output_limit)
    _stream_zstd_to_sink(
        source_fd,
        cast(IO[bytes], sink),
        source_size=source_size,
        source_sha256=source_sha256,
        compression=compression,
    )


def _same_inode(first_fd: int, second: os.stat_result) -> bool:
    first = os.fstat(first_fd)
    return (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)


def _open_regular_at(parent_fd: int, name: str) -> int:
    flags = (
        os.O_RDONLY
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
        | _required_flag("O_NONBLOCK")
    )
    file_fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        if not stat.S_ISREG(os.fstat(file_fd).st_mode):
            raise OSError(errno.EINVAL, "staging object is not a regular file")
        return file_fd
    except BaseException:
        _close_quietly(file_fd)
        raise


def _require_name_is_open_inode(parent_fd: int, name: str, file_fd: int) -> None:
    observed = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(observed.st_mode) or not _same_inode(file_fd, observed):
        raise StagingConflictError("staging object path changed during validation")


def _open_existing_destination(parent_fd: int, destination: Path) -> int | None:
    try:
        return _open_regular_at(parent_fd, destination.name)
    except FileNotFoundError:
        return None
    except OSError as error:
        if error.errno in {errno.EINVAL, errno.EISDIR, errno.ELOOP, errno.ENOTDIR}:
            raise StagingConflictError(
                "immutable staging destination is not a regular file"
            ) from error
        raise


def _publish_no_replace_at(
    parent_fd: int,
    partial: Path,
    destination: Path,
    verification_fd: int,
) -> None:
    try:
        os.link(
            partial.name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileExistsError as error:
        raise PublicationConflict(
            partial,
            destination,
            "immutable staging destination already exists",
        ) from error
    destination_fd = -1
    try:
        destination_fd = _open_regular_at(parent_fd, destination.name)
        if not _same_inode(verification_fd, os.fstat(destination_fd)):
            raise StagingConflictError(
                "published staging destination is not the verified partial"
            )
        os.fsync(parent_fd)
        os.unlink(partial.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        _require_name_is_open_inode(
            parent_fd,
            destination.name,
            destination_fd,
        )
    finally:
        if destination_fd >= 0:
            os.close(destination_fd)


def _reuse_existing(
    plan: TransformPlan,
    *,
    source_fd: int,
    parent_fd: int,
    destination: Path,
    output_bound: int,
) -> StoredArtifact | None:
    existing_fd = _open_existing_destination(parent_fd, destination)
    if existing_fd is None:
        return None
    try:
        comparator = _ExistingOutputComparator(existing_fd, output_bound)
        _stream_zstd_to_sink(
            source_fd,
            cast(IO[bytes], comparator),
            source_size=plan.artifact.size_bytes,
            source_sha256=plan.artifact.sha256,
            compression=plan.target.compression,
        )
        _validate_source_fd(source_fd, plan.artifact)
        generated_identity = comparator.finish()
        observed_identity = size_and_sha256_fd(existing_fd)
        if generated_identity != observed_identity:
            raise StagingConflictError(
                "immutable staging destination changed during validation"
            )
        _require_name_is_open_inode(parent_fd, destination.name, existing_fd)
        os.fsync(existing_fd)
        os.fsync(parent_fd)
        _require_name_is_open_inode(parent_fd, destination.name, existing_fd)
        return _stored_artifact(
            plan,
            path=destination,
            size_bytes=observed_identity[0],
            sha256=observed_identity[1],
        )
    finally:
        os.close(existing_fd)


def _unlink_matching_partial(
    parent_fd: int,
    partial: Path,
    verification_fd: int,
) -> None:
    current = os.stat(partial.name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(current.st_mode) or not _same_inode(verification_fd, current):
        raise StagingConflictError("staging partial changed before idempotent reuse")
    os.unlink(partial.name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _discard_failed_partial(
    parent_fd: int,
    partial: Path,
    partial_fd: int,
    primary_error: BaseException,
) -> None:
    try:
        _unlink_matching_partial(parent_fd, partial, partial_fd)
    except FileNotFoundError:
        return
    except (OSError, StagingConflictError) as cleanup_error:
        primary_error.add_note(
            f"staging partial cleanup also failed: {cleanup_error!r}"
        )


def _stored_artifact(
    plan: TransformPlan,
    *,
    path: Path,
    size_bytes: int,
    sha256: str,
) -> StoredArtifact:
    compression = plan.target.compression
    if plan.kind is TransformKind.PASSTHROUGH:
        codec = "passthrough"
        level = None
        policy_version = None
        tool = None
        tool_version = None
        profile = None
        implementation = None
    else:
        codec = compression.codec
        level = compression.level
        policy_version = compression.codec_policy_version
        tool = compression.codec_tool
        tool_version = compression.codec_tool_version
        profile = compression.transform_profile
        implementation = compression.transform_implementation_sha256
    return StoredArtifact(
        job_key=plan.job_key,
        source_relative_path=plan.artifact.relative_path,
        source_path=plan.source_path,
        source_size_bytes=plan.artifact.size_bytes,
        source_sha256=plan.artifact.sha256,
        path=path,
        size_bytes=size_bytes,
        sha256=sha256,
        transform_kind=plan.kind,
        codec=codec,
        codec_level=level,
        codec_policy_version=policy_version,
        codec_tool=tool,
        codec_version=tool_version,
        transform_profile=profile,
        transform_implementation_sha256=implementation,
    )


def execute_transform(
    plan: TransformPlan,
    *,
    budget: StagingBudget,
) -> StoredArtifact:
    if type(plan) is not TransformPlan:
        raise TypeError("plan must be TransformPlan")
    if type(budget) is not StagingBudget:
        raise TypeError("budget must be StagingBudget")
    _validate_plan(plan)
    _validate_transform_runtime(plan)
    source_fd = open_readonly_nofollow(plan.source_path)
    try:
        _validate_source_fd(source_fd, plan.artifact)
        if plan.kind is TransformKind.PASSTHROUGH:
            return _stored_artifact(
                plan,
                path=plan.source_path,
                size_bytes=plan.artifact.size_bytes,
                sha256=plan.artifact.sha256,
            )

        output_bound = _compress_bound(plan.artifact.size_bytes)
        destination = budget.path_for(plan.job_key)
        parent_fd = -1
        try:
            reused: StoredArtifact | None = None
            with budget.reserve_existing_transform():
                try:
                    parent_fd = budget._open_job_parent(plan.job_key, create=False)
                except FileNotFoundError:
                    pass
                if parent_fd >= 0:
                    reused = _reuse_existing(
                        plan,
                        source_fd=source_fd,
                        parent_fd=parent_fd,
                        destination=destination,
                        output_bound=output_bound,
                    )
                if reused is not None:
                    budget._require_job_destination(
                        plan.job_key,
                        parent_fd,
                        destination,
                        expected_size_bytes=reused.size_bytes,
                        expected_sha256=reused.sha256,
                    )
                else:
                    budget._require_open()
            if reused is not None:
                return reused
            with budget.reserve_transform(plan.job_key, output_bound) as partial:
                if parent_fd < 0:
                    parent_fd = budget._open_job_parent(plan.job_key, create=True)
                partial_fd = -1
                verification_fd = -1
                try:
                    flags = (
                        os.O_WRONLY
                        | os.O_CREAT
                        | os.O_EXCL
                        | _required_flag("O_NOFOLLOW")
                        | _required_flag("O_CLOEXEC")
                    )
                    partial_fd = os.open(
                        partial.name,
                        flags,
                        0o640,
                        dir_fd=parent_fd,
                    )
                    os.fsync(parent_fd)
                    _stream_zstd(
                        source_fd,
                        partial_fd,
                        source_size=plan.artifact.size_bytes,
                        source_sha256=plan.artifact.sha256,
                        compression=plan.target.compression,
                        output_limit=output_bound,
                    )
                    os.fsync(partial_fd)
                    _validate_source_fd(source_fd, plan.artifact)
                    verification_fd = _open_regular_at(parent_fd, partial.name)
                    if not _same_inode(partial_fd, os.fstat(verification_fd)):
                        raise StagingConflictError(
                            "staging partial changed before readonly validation"
                        )
                    stored_size, stored_sha256 = size_and_sha256_fd(verification_fd)
                    if not 0 < stored_size <= output_bound:
                        raise StagingCapacityExceeded(
                            "zstd output is outside its staging reservation"
                        )
                    published_own_inode = True
                    try:
                        _publish_no_replace_at(
                            parent_fd,
                            partial,
                            destination,
                            verification_fd,
                        )
                    except PublicationConflict as error:
                        published_own_inode = False
                        existing_fd = _open_existing_destination(
                            parent_fd,
                            destination,
                        )
                        if existing_fd is None:
                            raise StagingConflictError(
                                "immutable staging destination changed during publication"
                            ) from error
                        try:
                            existing_identity = size_and_sha256_fd(existing_fd)
                            if existing_identity != (stored_size, stored_sha256):
                                raise StagingConflictError(
                                    "immutable staging destination already contains "
                                    "different bytes"
                                ) from error
                            _require_name_is_open_inode(
                                parent_fd,
                                destination.name,
                                existing_fd,
                            )
                            os.fsync(existing_fd)
                            os.fsync(parent_fd)
                            _unlink_matching_partial(
                                parent_fd,
                                partial,
                                verification_fd,
                            )
                            _require_name_is_open_inode(
                                parent_fd,
                                destination.name,
                                existing_fd,
                            )
                        finally:
                            os.close(existing_fd)
                    except OSError as error:
                        if error.errno in {
                            errno.EINVAL,
                            errno.EISDIR,
                            errno.ELOOP,
                            errno.ENOTDIR,
                        }:
                            raise StagingConflictError(
                                "immutable staging destination is not a regular file"
                            ) from error
                        raise
                    budget._require_job_destination(
                        plan.job_key,
                        parent_fd,
                        destination,
                        expected_size_bytes=stored_size,
                        expected_sha256=stored_sha256,
                        expected_file_fd=(
                            verification_fd if published_own_inode else None
                        ),
                    )
                    return _stored_artifact(
                        plan,
                        path=destination,
                        size_bytes=stored_size,
                        sha256=stored_sha256,
                    )
                except BaseException as error:
                    if partial_fd >= 0:
                        _discard_failed_partial(
                            parent_fd,
                            partial,
                            partial_fd,
                            error,
                        )
                    raise
                finally:
                    if verification_fd >= 0:
                        os.close(verification_fd)
                    if partial_fd >= 0:
                        os.close(partial_fd)
        except OSError as error:
            if error.errno in {
                errno.ENOSPC,
                getattr(errno, "EDQUOT", -1),
            }:
                raise StagingSpaceExhausted(
                    "staging filesystem has insufficient space"
                ) from error
            raise
        finally:
            if parent_fd >= 0:
                os.close(parent_fd)
    finally:
        os.close(source_fd)


__all__ = [
    "SourceIdentityMismatch",
    "StagingBudget",
    "StagingCapacityExceeded",
    "StagingConflictError",
    "StagingOwnershipError",
    "StagingReconciliationError",
    "StagingSpaceExhausted",
    "StoredArtifact",
    "TransformError",
    "TransformKind",
    "TransformPlan",
    "TransformPlanMismatch",
    "TransformRuntimeMismatch",
    "execute_transform",
    "plan_transform",
]
