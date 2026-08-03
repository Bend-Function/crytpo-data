from __future__ import annotations

import hashlib
import io
import os
import socket
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import zstandard
from pydantic import BaseModel, ValidationError
from typer.testing import CliRunner

from crypto_collector.benchmarks import provenance as provenance_module
from crypto_collector.benchmarks import writer
from crypto_collector.benchmarks.contracts import (
    GateAcceptanceReceiptV1,
    GateArchiveAttestationV1,
    GateBuildProvenanceV1,
    GateEvidenceDisclosureV1,
    GateEvidenceDocumentRefV1,
    GateFileInventoryV1,
    GateProvenanceReceiptV1,
    GateRuntimeIndexV1,
)
from crypto_collector.benchmarks.provenance import (
    ProvenanceValidationError,
    SubprocessDockerPort,
    build_disclosure,
    validate_provenance,
)
from crypto_collector.benchmarks.runner import RunnerPreflightError
from crypto_collector.domain.json_codec import encode_json
from tests.unit.benchmarks.test_runtime_verifier import (
    _candidate as base_candidate_report,
)
from tests.unit.benchmarks.test_runtime_verifier import (
    _receipt as base_runtime_receipt,
)
from tests.unit.benchmarks.test_runtime_verifier import _run_index as base_run_index

_SHA_A = "a" * 64
_SHA_B = "b" * 64
_RUN_ID = "00000000-0000-4000-8000-000000000001"
_IMAGE_ID = f"sha256:{_SHA_A}"
_RUNTIME_LOCK_REQUIREMENTS = ("pydantic==2.13.4", "zstandard==0.25.0")


_EXPECTED_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    GateFileInventoryV1: (
        "schema_version",
        "record_type",
        "root",
        "relative_path",
        "content_size_bytes",
        "content_sha256",
    ),
    GateArchiveAttestationV1: (
        "schema_version",
        "record_type",
        "run_id",
        "runtime_index_sha256",
        "provider",
        "archive_locator",
        "opaque_locator_sha256",
        "object_version",
        "retention_mode",
        "retention_until_unix_ns",
        "verified_at_unix_ns",
        "archive_size_bytes",
        "archive_sha256",
        "files",
        "file_count",
        "content_size_bytes",
        "inventory_sha256",
        "immutable",
        "webdav_backup_verified",
        "sha256",
    ),
    GateBuildProvenanceV1: (
        "schema_version",
        "record_type",
        "implementation_source_commit",
        "source_date_epoch",
        "platform",
        "base_image_digest",
        "docker_engine_version",
        "docker_buildx_version",
        "buildkit_version",
        "dockerfile_frontend",
        "collector_wheel_sha256",
        "requirements_lock_sha256",
        "build_requirements_lock_sha256",
        "dockerfile_sha256",
        "workload_sha256",
        "provenance_enabled",
        "sbom_enabled",
        "runtime_user",
        "sha256",
    ),
    GateProvenanceReceiptV1: (
        "schema_version",
        "record_type",
        "verifier_version",
        "verified_at_unix_ns",
        "run_id",
        "mode",
        "runtime_index_sha256",
        "runtime_receipt_sha256",
        "archive_attestation_sha256",
        "archive_sha256",
        "opaque_locator_sha256",
        "implementation_source_commit",
        "source_date_epoch",
        "source_archive_sha256",
        "collector_wheel_sha256",
        "requirements_lock_sha256",
        "build_requirements_lock_sha256",
        "dockerfile_sha256",
        "workload_sha256",
        "image_id",
        "platform",
        "base_image_digest",
        "docker_engine_version",
        "docker_buildx_version",
        "buildkit_version",
        "dockerfile_frontend",
        "source_reproduction_valid",
        "image_reproduction_valid",
        "image_contract_valid",
        "container_binding_valid",
        "archive_immutable",
        "provenance_valid",
        "sha256",
    ),
    GateAcceptanceReceiptV1: (
        "schema_version",
        "record_type",
        "accepted_at_unix_ns",
        "run_id",
        "mode",
        "runtime_receipt_sha256",
        "runtime_index_sha256",
        "archive_attestation_sha256",
        "provenance_receipt_sha256",
        "expected_target_id",
        "workload_sha256",
        "workload_plan_sha256",
        "multiplier",
        "duration_ns",
        "expected_record_count",
        "accepted_record_count",
        "durable_record_count",
        "durability_lag_max_ns",
        "implementation_source_commit",
        "collector_wheel_sha256",
        "requirements_lock_sha256",
        "dockerfile_sha256",
        "image_id",
        "archive_provider",
        "opaque_locator_sha256",
        "runtime_accepted",
        "provenance_valid",
        "archive_immutable",
        "qualification_accepted",
        "sha256",
    ),
    GateEvidenceDisclosureV1: (
        "schema_version",
        "record_type",
        "run_id",
        "mode",
        "acceptance_receipt_sha256",
        "runtime_index_sha256",
        "provenance_receipt_sha256",
        "archive_attestation_sha256",
        "workload_sha256",
        "workload_plan_sha256",
        "multiplier",
        "duration_ns",
        "expected_record_count",
        "accepted_record_count",
        "durable_record_count",
        "durability_lag_max_ns",
        "implementation_source_commit",
        "collector_wheel_sha256",
        "requirements_lock_sha256",
        "dockerfile_sha256",
        "image_id",
        "archive_provider",
        "opaque_locator_sha256",
        "qualification_accepted",
        "sha256",
    ),
}


def _hash(unsigned: dict[str, Any]) -> str:
    return hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest()


def _self_hashed(model_type: type[Any], unsigned: dict[str, Any]) -> Any:
    return model_type.model_validate_json(
        encode_json({**unsigned, "sha256": _hash(unsigned)})
    )


def test_task8_contract_field_order_is_frozen() -> None:
    for model_type, fields in _EXPECTED_FIELDS.items():
        assert tuple(model_type.model_fields) == fields


def test_file_inventory_rejects_unsafe_paths() -> None:
    for path in ("/absolute", "../escape", "x\\y", "a//b", "."):
        with pytest.raises(ValidationError):
            GateFileInventoryV1(
                root="evidence",
                relative_path=path,
                content_size_bytes=1,
                content_sha256=_SHA_A,
            )


def test_file_inventory_requires_the_empty_digest_for_an_empty_file() -> None:
    with pytest.raises(ValidationError, match="empty"):
        GateFileInventoryV1(
            root="state",
            relative_path="empty.marker",
            content_size_bytes=0,
            content_sha256=_SHA_A,
        )


def test_build_provenance_is_self_hashing_and_disables_ambient_metadata() -> None:
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_build_provenance_v1",
        "implementation_source_commit": "c" * 40,
        "source_date_epoch": 1_800_000_000,
        "platform": "linux/amd64",
        "base_image_digest": f"sha256:{_SHA_B}",
        "docker_engine_version": "28.3.3",
        "docker_buildx_version": "v0.25.0",
        "buildkit_version": "v0.24.0",
        "dockerfile_frontend": f"docker/dockerfile:1.18@sha256:{_SHA_B}",
        "collector_wheel_sha256": _SHA_A,
        "requirements_lock_sha256": _SHA_A,
        "build_requirements_lock_sha256": _SHA_B,
        "dockerfile_sha256": _SHA_A,
        "workload_sha256": _SHA_B,
        "provenance_enabled": False,
        "sbom_enabled": False,
        "runtime_user": "65532:65532",
    }
    provenance = _self_hashed(GateBuildProvenanceV1, unsigned)

    assert provenance.canonical_bytes().endswith(b"\n")
    with pytest.raises(ValidationError, match="provenance"):
        _self_hashed(
            GateBuildProvenanceV1,
            {**unsigned, "provenance_enabled": True},
        )
    with pytest.raises(ValidationError, match="SHA-256"):
        GateBuildProvenanceV1.model_validate(
            {**provenance.model_dump(mode="python"), "workload_sha256": _SHA_A}
        )


def _document_ref(root: Path, path: Path) -> GateEvidenceDocumentRefV1:
    source = path.read_bytes()
    return GateEvidenceDocumentRefV1(
        relative_path=path.relative_to(root).as_posix(),
        content_size_bytes=len(source),
        content_sha256=hashlib.sha256(source).hexdigest(),
    )


def _inventory(root_name: str, root: Path) -> tuple[GateFileInventoryV1, ...]:
    return tuple(
        GateFileInventoryV1(
            root=root_name,
            relative_path=path.relative_to(root).as_posix(),
            content_size_bytes=path.stat().st_size,
            content_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


def _build_provenance(
    *,
    source_commit: str,
    wheel_sha256: str,
    requirements_lock_sha256: str,
    dockerfile_sha256: str,
    workload_sha256: str,
) -> GateBuildProvenanceV1:
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_build_provenance_v1",
        "implementation_source_commit": source_commit,
        "source_date_epoch": 1_800_000_000,
        "platform": "linux/amd64",
        "base_image_digest": f"sha256:{_SHA_B}",
        "docker_engine_version": "28.3.3",
        "docker_buildx_version": "v0.25.0",
        "buildkit_version": "v0.24.0",
        "dockerfile_frontend": f"docker/dockerfile:1.18@sha256:{_SHA_B}",
        "collector_wheel_sha256": wheel_sha256,
        "requirements_lock_sha256": requirements_lock_sha256,
        "build_requirements_lock_sha256": _SHA_B,
        "dockerfile_sha256": dockerfile_sha256,
        "workload_sha256": workload_sha256,
        "provenance_enabled": False,
        "sbom_enabled": False,
        "runtime_user": "65532:65532",
    }
    return _self_hashed(GateBuildProvenanceV1, unsigned)


def _labels(provenance: GateBuildProvenanceV1) -> dict[str, str]:
    content_sha256 = hashlib.sha256(provenance.canonical_bytes()).hexdigest()
    return {
        "org.opencontainers.image.revision": (provenance.implementation_source_commit),
        "org.opencontainers.image.base.digest": provenance.base_image_digest,
        "io.crypto-collector.source-date-epoch": str(provenance.source_date_epoch),
        "io.crypto-collector.collector-wheel-sha256": (
            provenance.collector_wheel_sha256
        ),
        "io.crypto-collector.requirements-lock-sha256": (
            provenance.requirements_lock_sha256
        ),
        "io.crypto-collector.build-requirements-lock-sha256": (
            provenance.build_requirements_lock_sha256
        ),
        "io.crypto-collector.dockerfile-sha256": provenance.dockerfile_sha256,
        "io.crypto-collector.workload-sha256": provenance.workload_sha256,
        "io.crypto-collector.build-provenance-sha256": content_sha256,
        "io.crypto-collector.platform": provenance.platform,
        "io.crypto-collector.docker-engine-version": (provenance.docker_engine_version),
        "io.crypto-collector.docker-buildx-version": (provenance.docker_buildx_version),
        "io.crypto-collector.buildkit-version": provenance.buildkit_version,
        "io.crypto-collector.dockerfile-frontend": (provenance.dockerfile_frontend),
        "io.crypto-collector.provenance": "false",
        "io.crypto-collector.sbom": "false",
        "io.crypto-collector.runtime-user": provenance.runtime_user,
    }


@dataclass
class FakeGit:
    facts: dict[str, Any]

    def inspect_source(self, source_commit: str) -> object:
        assert source_commit == self.facts["source_commit"]
        return self.facts


@dataclass
class FakeDocker:
    reproduction: dict[str, Any]
    containers: dict[str, dict[str, Any]]

    def reproduce(
        self,
        *,
        source_commit: str,
        source_date_epoch: int,
    ) -> object:
        assert source_commit == self.reproduction["source_commit"]
        assert source_date_epoch == self.reproduction["source_date_epoch"]
        return self.reproduction

    def inspect_container(self, name: str) -> object:
        return self.containers[name]


@dataclass
class FakeArchiveProvider:
    facts: dict[str, Any]
    archive_source: bytes
    requests: list[tuple[str, str, str, Path]]

    def verify_and_download(
        self,
        *,
        provider: str,
        archive_locator: str,
        object_version: str,
        destination: Path,
    ) -> object:
        self.requests.append((provider, archive_locator, object_version, destination))
        destination.write_bytes(self.archive_source)
        return self.facts


@dataclass(frozen=True)
class ProvenanceFixture:
    source_commit: str
    evidence_root: Path
    data_root: Path
    state_root: Path
    runtime_index_path: Path
    archive_attestation_path: Path
    git: FakeGit
    docker: FakeDocker
    archive_provider: FakeArchiveProvider


def _tar_source(
    roots: tuple[tuple[str, Path], ...],
    *,
    directories: tuple[tuple[str, bytes], ...] = (),
) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in directories:
            member = tarfile.TarInfo(name)
            member.type = tarfile.DIRTYPE
            member.size = len(payload)
            member.mtime = 0
            member.mode = 0o500
            member.uid = 0
            member.gid = 0
            archive.addfile(member, io.BytesIO(payload))
        for root_name, root in roots:
            for path in sorted(root.rglob("*")):
                if not path.is_file():
                    continue
                source = path.read_bytes()
                member = tarfile.TarInfo(
                    f"{root_name}/{path.relative_to(root).as_posix()}"
                )
                member.size = len(source)
                member.mtime = 0
                member.mode = 0o400
                member.uid = 0
                member.gid = 0
                archive.addfile(member, io.BytesIO(source))
    return raw.getvalue()


def _archive_source(
    roots: tuple[tuple[str, Path], ...],
    *,
    directories: tuple[tuple[str, bytes], ...] = (),
) -> bytes:
    return zstandard.ZstdCompressor(level=1).compress(
        _tar_source(roots, directories=directories)
    )


def _write_fixture(
    tmp_path: Path,
    *,
    mode: str = "qualification",
    include_empty_file: bool = False,
    extra_files: tuple[tuple[str, str, bytes], ...] = (),
    runtime_verified_at_unix_ns: int = 1,
    archive_verified_at_unix_ns: int = 2,
    provider_observed_at_unix_ns: int = 3,
) -> ProvenanceFixture:
    evidence_root = tmp_path / "evidence"
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    operator_root = tmp_path / "operator"
    for root in (evidence_root, data_root, state_root, operator_root):
        root.mkdir()
    if include_empty_file:
        (state_root / "empty.marker").write_bytes(b"")
    roots_by_name = {
        "evidence": evidence_root,
        "data": data_root,
        "state": state_root,
    }
    for root_name, relative_path, content in extra_files:
        path = roots_by_name[root_name].joinpath(*relative_path.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    qualification = mode == "qualification"
    source_commit = "c" * 40
    runtime_receipt = base_runtime_receipt(mode=mode)
    receipt_unsigned = runtime_receipt.model_dump(mode="json", exclude={"sha256"})
    receipt_unsigned["verified_at_unix_ns"] = runtime_verified_at_unix_ns
    runtime_receipt = _self_hashed(type(runtime_receipt), receipt_unsigned)
    candidate = base_candidate_report(mode=mode)
    candidate_unsigned = candidate.model_dump(mode="json", exclude={"sha256"})
    candidate_unsigned["runtime_summary"] = (
        runtime_receipt.recomputed_summary.model_dump(mode="json")
        if runtime_receipt.recomputed_summary is not None
        else None
    )
    candidate = _self_hashed(type(candidate), candidate_unsigned)
    candidate_path = evidence_root / "candidate-report.json"
    candidate_path.write_bytes(candidate.canonical_bytes())

    run_index = base_run_index(mode=mode)
    run_unsigned = run_index.model_dump(mode="json", exclude={"sha256"})
    run_unsigned.update(
        {
            "data_root": data_root.as_posix(),
            "state_root": state_root.as_posix(),
            "implementation_source_commit": source_commit if qualification else None,
            "candidate_report": _document_ref(evidence_root, candidate_path).model_dump(
                mode="json"
            ),
        }
    )
    run_index = _self_hashed(type(run_index), run_unsigned)
    run_index_path = evidence_root / "run-index.json"
    run_index_path.write_bytes(run_index.canonical_bytes())

    receipt_unsigned = runtime_receipt.model_dump(mode="json", exclude={"sha256"})
    receipt_unsigned.update(
        {
            "run_index_sha256": run_index.sha256,
            "run_index_content_sha256": hashlib.sha256(
                run_index.canonical_bytes()
            ).hexdigest(),
        }
    )
    runtime_receipt = _self_hashed(type(runtime_receipt), receipt_unsigned)
    runtime_receipt_path = evidence_root / "runtime-receipt.json"
    runtime_receipt_path.write_bytes(runtime_receipt.canonical_bytes())

    runtime_unsigned = {
        "schema_version": 1,
        "record_type": "gate_runtime_index_v1",
        "run_id": run_index.run_id,
        "status": "complete",
        "mode": mode,
        "run_index": _document_ref(evidence_root, run_index_path).model_dump(
            mode="json"
        ),
        "runtime_receipt": _document_ref(
            evidence_root, runtime_receipt_path
        ).model_dump(mode="json"),
    }
    runtime_index = _self_hashed(GateRuntimeIndexV1, runtime_unsigned)
    runtime_index_path = evidence_root / "runtime-index.json"
    runtime_index_path.write_bytes(runtime_index.canonical_bytes())

    files = (
        *_inventory("evidence", evidence_root),
        *_inventory("data", data_root),
        *_inventory("state", state_root),
    )
    inventory_sha256 = hashlib.sha256(
        b"".join(item.canonical_bytes() for item in files)
    ).hexdigest()
    archived_source = _archive_source(
        (
            ("evidence", evidence_root),
            ("data", data_root),
            ("state", state_root),
        )
    )
    archive_unsigned = {
        "schema_version": 1,
        "record_type": "gate_archive_attestation_v1",
        "run_id": run_index.run_id,
        "runtime_index_sha256": runtime_index.sha256,
        "provider": "s3_object_lock",
        "archive_locator": "s3://private-evidence/gate.tar.zst",
        "opaque_locator_sha256": hashlib.sha256(
            b"s3://private-evidence/gate.tar.zst"
        ).hexdigest(),
        "object_version": "version-1",
        "retention_mode": "compliance",
        "retention_until_unix_ns": 2**63 - 1,
        "verified_at_unix_ns": archive_verified_at_unix_ns,
        "archive_size_bytes": len(archived_source),
        "archive_sha256": hashlib.sha256(archived_source).hexdigest(),
        "files": [item.model_dump(mode="json") for item in files],
        "file_count": len(files),
        "content_size_bytes": sum(item.content_size_bytes for item in files),
        "inventory_sha256": inventory_sha256,
        "immutable": True,
        "webdav_backup_verified": False,
    }
    archive = _self_hashed(GateArchiveAttestationV1, archive_unsigned)
    archive_path = operator_root / "archive-attestation.json"
    archive_path.write_bytes(archive.canonical_bytes())
    archive_provider = FakeArchiveProvider(
        facts={
            "provider": "s3_object_lock",
            "archive_locator": archive.archive_locator,
            "object_version": "version-1",
            "retention_mode": "compliance",
            "retention_until_unix_ns": 2**63 - 1,
            "observed_at_unix_ns": provider_observed_at_unix_ns,
            "content_size_bytes": len(archived_source),
        },
        archive_source=archived_source,
        requests=[],
    )

    wheel_sha256 = run_index.collector_wheel_sha256 or _SHA_A
    requirements_lock_sha256 = run_index.requirements_lock_sha256 or _SHA_A
    dockerfile_sha256 = run_index.dockerfile_sha256 or _SHA_A
    provenance = _build_provenance(
        source_commit=source_commit,
        wheel_sha256=wheel_sha256,
        requirements_lock_sha256=requirements_lock_sha256,
        dockerfile_sha256=dockerfile_sha256,
        workload_sha256=run_index.workload_sha256,
    )
    source_archive_sha256 = "d" * 64
    git = FakeGit(
        {
            "source_commit": source_commit,
            "source_date_epoch": provenance.source_date_epoch,
            "checkout_clean": True,
            "source_archive_sha256s": (
                source_archive_sha256,
                source_archive_sha256,
            ),
            "untracked_build_inputs": (),
            "ignored_build_inputs": (),
        }
    )
    build = {
        "source_context_sha256": source_archive_sha256,
        "collector_wheel_sha256": provenance.collector_wheel_sha256,
        "image_id": _IMAGE_ID,
        "labels": _labels(provenance),
        "build_provenance": provenance.model_dump(mode="json"),
        "build_provenance_content_sha256": hashlib.sha256(
            provenance.canonical_bytes()
        ).hexdigest(),
        "build_provenance_mode": "0444",
        "workload_sha256": provenance.workload_sha256,
        "runtime_user": "65532:65532",
        "installed_distributions": (
            "crypto-market-data-collector==0.1.0",
            *_RUNTIME_LOCK_REQUIREMENTS,
        ),
    }
    reproduction = {
        "source_commit": source_commit,
        "source_date_epoch": provenance.source_date_epoch,
        "platform": provenance.platform,
        "base_image_digest": provenance.base_image_digest,
        "docker_engine_version": provenance.docker_engine_version,
        "docker_buildx_version": provenance.docker_buildx_version,
        "buildkit_version": provenance.buildkit_version,
        "dockerfile_frontend": provenance.dockerfile_frontend,
        "provenance_enabled": False,
        "sbom_enabled": False,
        "requirements_lock_sha256": provenance.requirements_lock_sha256,
        "build_requirements_lock_sha256": (provenance.build_requirements_lock_sha256),
        "dockerfile_sha256": provenance.dockerfile_sha256,
        "workload_sha256": provenance.workload_sha256,
        "runtime_lock_requirements": _RUNTIME_LOCK_REQUIREMENTS,
        "build_lock_requirements": (
            "hatchling==1.27.0",
            "packaging==25.0",
            "pathspec==0.12.1",
            "pluggy==1.6.0",
            "trove-classifiers==2025.5.9.12",
        ),
        "builds": (build.copy(), build.copy()),
    }
    containers = {
        name: {
            "container_id": ("1" if name == "writer-gate" else "2") * 64,
            "name": name,
            "exists": True,
            "removed": False,
            "status": "exited",
            "running": False,
            "paused": False,
            "restarting": False,
            "oom_killed": False,
            "dead": False,
            "pid": 0,
            "exit_code": 0,
            "error": "",
            "image_id": _IMAGE_ID,
            "memory_limit_bytes": (4 * 1024**3 if name == "writer-gate" else 0),
            "memory_swap_limit_bytes": (4 * 1024**3 if name == "writer-gate" else 0),
        }
        for name in ("writer-gate", "writer-gate-verifier")
    }
    return ProvenanceFixture(
        source_commit=source_commit,
        evidence_root=evidence_root,
        data_root=data_root,
        state_root=state_root,
        runtime_index_path=runtime_index_path,
        archive_attestation_path=archive_path,
        git=git,
        docker=FakeDocker(reproduction, containers),
        archive_provider=archive_provider,
    )


def _validate(fixture: ProvenanceFixture) -> GateAcceptanceReceiptV1:
    return validate_provenance(
        source_commit=fixture.source_commit,
        runtime_index=fixture.runtime_index_path,
        archive_attestation=fixture.archive_attestation_path,
        writer_container="writer-gate",
        verifier_container="writer-gate-verifier",
        docker=fixture.docker,
        git=fixture.git,
        archive_provider=fixture.archive_provider,
    )


def _replace_remote_archive(
    fixture: ProvenanceFixture,
    remote_source: bytes,
) -> GateArchiveAttestationV1:
    fixture.archive_provider.archive_source = remote_source
    fixture.archive_provider.facts["content_size_bytes"] = len(remote_source)
    archive = GateArchiveAttestationV1.model_validate_json(
        fixture.archive_attestation_path.read_bytes(), strict=True
    )
    unsigned = archive.model_dump(mode="json", exclude={"sha256"})
    unsigned.update(
        {
            "archive_size_bytes": len(remote_source),
            "archive_sha256": hashlib.sha256(remote_source).hexdigest(),
        }
    )
    rebound = _self_hashed(GateArchiveAttestationV1, unsigned)
    fixture.archive_attestation_path.write_bytes(rebound.canonical_bytes())
    return rebound


def test_validate_provenance_publishes_complete_one_way_dag(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)

    acceptance = _validate(fixture)
    operator_root = fixture.archive_attestation_path.parent
    provenance = GateProvenanceReceiptV1.model_validate_json(
        (operator_root / "provenance-receipt.json").read_bytes(),
        strict=True,
    )
    disclosure = build_disclosure(acceptance)
    run_index = base_run_index(mode="qualification")
    runtime_receipt_source = (
        fixture.evidence_root / "runtime-receipt.json"
    ).read_bytes()
    runtime_index = GateRuntimeIndexV1.model_validate_json(
        fixture.runtime_index_path.read_bytes(), strict=True
    )

    assert (
        runtime_index.runtime_receipt.content_sha256
        == hashlib.sha256(runtime_receipt_source).hexdigest()
    )
    assert provenance.runtime_index_sha256 == runtime_index.sha256
    assert acceptance.provenance_receipt_sha256 == provenance.sha256
    assert disclosure.acceptance_receipt_sha256 == acceptance.sha256
    assert acceptance.qualification_accepted is True
    assert (operator_root / "acceptance-receipt.json").read_bytes() == (
        acceptance.canonical_bytes()
    )
    assert run_index.mode == "qualification"


def test_validate_provenance_rejects_functional_mode(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path, mode="functional")

    with pytest.raises(ProvenanceValidationError, match="functional"):
        _validate(fixture)


def test_validate_provenance_rejects_inventory_drift(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)
    (fixture.data_root / "late-file").write_bytes(b"not archived")

    with pytest.raises(ProvenanceValidationError, match="inventory"):
        _validate(fixture)


def test_validate_provenance_inventories_empty_regular_files(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path, include_empty_file=True)

    assert _validate(fixture).qualification_accepted is True


def test_validate_provenance_rejects_self_reported_archive_version(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(tmp_path)
    archive = GateArchiveAttestationV1.model_validate_json(
        fixture.archive_attestation_path.read_bytes(), strict=True
    )
    unsigned = archive.model_dump(mode="json", exclude={"sha256"})
    unsigned["object_version"] = "self-forged-version"
    fixture.archive_attestation_path.write_bytes(
        _self_hashed(GateArchiveAttestationV1, unsigned).canonical_bytes()
    )

    with pytest.raises(ProvenanceValidationError, match="provider.*version"):
        _validate(fixture)


def test_validate_provenance_binds_remote_archive_inventory_bytes(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(tmp_path)
    archive = GateArchiveAttestationV1.model_validate_json(
        fixture.archive_attestation_path.read_bytes(), strict=True
    )
    (fixture.data_root / "remote-only").write_bytes(b"not in attested inventory")
    remote_source = _archive_source(
        (
            ("evidence", fixture.evidence_root),
            ("data", fixture.data_root),
            ("state", fixture.state_root),
        )
    )
    (fixture.data_root / "remote-only").unlink()
    fixture.archive_provider.archive_source = remote_source
    fixture.archive_provider.facts["content_size_bytes"] = len(remote_source)
    unsigned = archive.model_dump(mode="json", exclude={"sha256"})
    unsigned.update(
        {
            "archive_size_bytes": len(remote_source),
            "archive_sha256": hashlib.sha256(remote_source).hexdigest(),
        }
    )
    fixture.archive_attestation_path.write_bytes(
        _self_hashed(GateArchiveAttestationV1, unsigned).canonical_bytes()
    )

    with pytest.raises(ProvenanceValidationError, match="remote archive"):
        _validate(fixture)


def test_validate_provenance_accepts_required_zero_size_archive_directories(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(
        tmp_path,
        extra_files=(("data", "nested/deeper/sample.bin", b"sample"),),
    )
    remote_source = _archive_source(
        (
            ("evidence", fixture.evidence_root),
            ("data", fixture.data_root),
            ("state", fixture.state_root),
        ),
        directories=(
            ("evidence/", b""),
            ("data/", b""),
            ("data/nested/", b""),
            ("data/nested/deeper", b""),
        ),
    )
    _replace_remote_archive(fixture, remote_source)

    assert _validate(fixture).qualification_accepted is True


def test_validate_provenance_rejects_archive_directory_payload(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(tmp_path)
    remote_source = _archive_source(
        (
            ("evidence", fixture.evidence_root),
            ("data", fixture.data_root),
            ("state", fixture.state_root),
        ),
        directories=(("evidence/", b"SECRET"),),
    )
    _replace_remote_archive(fixture, remote_source)

    with pytest.raises(ProvenanceValidationError, match="directory.*size"):
        _validate(fixture)


def test_validate_provenance_rejects_unneeded_archive_directory(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(tmp_path)
    remote_source = _archive_source(
        (
            ("evidence", fixture.evidence_root),
            ("data", fixture.data_root),
            ("state", fixture.state_root),
        ),
        directories=(("data/unneeded/", b""),),
    )
    _replace_remote_archive(fixture, remote_source)

    with pytest.raises(ProvenanceValidationError, match="unexpected directory"):
        _validate(fixture)


def test_validate_provenance_rejects_non_normalized_archive_directory(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(tmp_path)
    remote_source = _archive_source(
        (
            ("evidence", fixture.evidence_root),
            ("data", fixture.data_root),
            ("state", fixture.state_root),
        ),
        directories=(("evidence/./", b""),),
    )
    _replace_remote_archive(fixture, remote_source)

    with pytest.raises(ProvenanceValidationError, match="directory.*normalized"):
        _validate(fixture)


def test_validate_provenance_rejects_duplicate_archive_directory(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(tmp_path)
    remote_source = _archive_source(
        (
            ("evidence", fixture.evidence_root),
            ("data", fixture.data_root),
            ("state", fixture.state_root),
        ),
        directories=(("evidence/", b""), ("evidence", b"")),
    )
    _replace_remote_archive(fixture, remote_source)

    with pytest.raises(ProvenanceValidationError, match="duplicate director"):
        _validate(fixture)


@pytest.mark.parametrize("concatenation", ["tar", "zstd"])
def test_validate_provenance_rejects_hidden_archive_after_tar_eof(
    tmp_path: Path,
    concatenation: str,
) -> None:
    fixture = _write_fixture(tmp_path)
    hidden_root = tmp_path / "hidden"
    hidden_root.mkdir()
    (hidden_root / "undeclared.jsonl.zst").write_bytes(b"hidden")
    hidden_tar = _tar_source((("data", hidden_root),))
    if concatenation == "tar":
        declared_tar = zstandard.ZstdDecompressor().decompress(
            fixture.archive_provider.archive_source
        )
        remote_source = zstandard.ZstdCompressor(level=1).compress(
            declared_tar + hidden_tar
        )
    else:
        remote_source = fixture.archive_provider.archive_source + (
            zstandard.ZstdCompressor(level=1).compress(hidden_tar)
        )
    fixture.archive_provider.archive_source = remote_source
    fixture.archive_provider.facts["content_size_bytes"] = len(remote_source)
    archive = GateArchiveAttestationV1.model_validate_json(
        fixture.archive_attestation_path.read_bytes(), strict=True
    )
    unsigned = archive.model_dump(mode="json", exclude={"sha256"})
    unsigned.update(
        {
            "archive_size_bytes": len(remote_source),
            "archive_sha256": hashlib.sha256(remote_source).hexdigest(),
        }
    )
    fixture.archive_attestation_path.write_bytes(
        _self_hashed(GateArchiveAttestationV1, unsigned).canonical_bytes()
    )

    with pytest.raises(ProvenanceValidationError, match="trailing|remote archive"):
        _validate(fixture)


def test_raw_inventory_streams_files_larger_than_document_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = tmp_path.resolve() / "raw"
    raw.mkdir()
    source = b"raw-payload-larger-than-a-document"
    (raw / "large.jsonl.zst").write_bytes(source)
    monkeypatch.setattr(provenance_module, "_MAX_DOCUMENT_BYTES", 8)

    rows = provenance_module._scan_inventory_root("data", raw)

    assert rows[0].content_size_bytes == len(source)
    assert rows[0].content_sha256 == hashlib.sha256(source).hexdigest()


def test_archive_readback_streams_beyond_document_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _write_fixture(tmp_path)
    archive = GateArchiveAttestationV1.model_validate_json(
        fixture.archive_attestation_path.read_bytes(), strict=True
    )
    monkeypatch.setattr(provenance_module, "_MAX_DOCUMENT_BYTES", 8)

    facts = provenance_module._validate_archive_provider(
        archive, fixture.archive_provider
    )

    assert facts.object_version == archive.object_version


def test_safe_reader_uses_nonblocking_nofollow_cloexec_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path.resolve() / "document.json"
    path.write_bytes(b"{}\n")
    observed_flags: list[int] = []
    real_open = provenance_module.os.open

    def recording_open(path: object, flags: int, *args: object) -> int:
        observed_flags.append(flags)
        return real_open(path, flags, *args)

    monkeypatch.setattr(provenance_module.os, "open", recording_open)

    assert provenance_module._read_bounded_nofollow(path) == b"{}\n"
    required = os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
    assert observed_flags[0] & required == required


def test_safe_reader_rejects_fifo_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path.resolve() / "evidence.fifo"
    os.mkfifo(fifo)
    script = """
import sys
from pathlib import Path
from crypto_collector.benchmarks.provenance import (
    ProvenanceValidationError,
    _read_bounded_nofollow,
)
try:
    _read_bounded_nofollow(Path(sys.argv[1]))
except ProvenanceValidationError:
    raise SystemExit(0)
raise SystemExit(2)
"""

    completed = subprocess.run(
        (sys.executable, "-c", script, fifo.as_posix()),
        check=False,
        capture_output=True,
        timeout=1,
    )

    assert completed.returncode == 0, completed.stderr.decode("utf-8")


def test_safe_reader_rejects_socket_and_device() -> None:
    with tempfile.TemporaryDirectory(
        prefix="prov-socket-", dir="/private/tmp"
    ) as directory:
        socket_path = Path(directory).resolve() / "evidence.socket"
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(socket_path.as_posix())
            with pytest.raises(ProvenanceValidationError, match="regular file|open"):
                provenance_module._read_bounded_nofollow(socket_path)
    with pytest.raises(ProvenanceValidationError, match="regular file"):
        provenance_module._read_bounded_nofollow(Path("/dev/null"))


def test_validate_provenance_rejects_runtime_receipt_after_archive(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(
        tmp_path,
        runtime_verified_at_unix_ns=3,
        archive_verified_at_unix_ns=2,
        provider_observed_at_unix_ns=4,
    )

    with pytest.raises(ProvenanceValidationError, match="runtime receipt.*archive"):
        _validate(fixture)


def test_validate_provenance_rejects_future_runtime_receipt(
    tmp_path: Path,
) -> None:
    future = 2**62
    fixture = _write_fixture(
        tmp_path,
        runtime_verified_at_unix_ns=future,
        archive_verified_at_unix_ns=future + 1,
        provider_observed_at_unix_ns=future + 2,
    )

    with pytest.raises(ProvenanceValidationError, match="runtime receipt.*future"):
        _validate(fixture)


@pytest.mark.parametrize(
    ("verified_at_unix_ns", "retention_until_unix_ns", "match"),
    (
        (1, 2, "currently immutable"),
        (2**63 - 1, 2**63, "archive attestation.*future"),
    ),
)
def test_validate_provenance_rejects_stale_or_future_archive_proof(
    tmp_path: Path,
    verified_at_unix_ns: int,
    retention_until_unix_ns: int,
    match: str,
) -> None:
    fixture = _write_fixture(tmp_path)
    archive = GateArchiveAttestationV1.model_validate_json(
        fixture.archive_attestation_path.read_bytes(), strict=True
    )
    unsigned = archive.model_dump(mode="json", exclude={"sha256"})
    unsigned.update(
        {
            "verified_at_unix_ns": verified_at_unix_ns,
            "retention_until_unix_ns": retention_until_unix_ns,
        }
    )
    fixture.archive_attestation_path.write_bytes(
        _self_hashed(GateArchiveAttestationV1, unsigned).canonical_bytes()
    )
    fixture.archive_provider.facts["retention_until_unix_ns"] = retention_until_unix_ns

    with pytest.raises(ProvenanceValidationError, match=match):
        _validate(fixture)


def test_archive_inventory_rejects_future_dag_nodes(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)
    archive = GateArchiveAttestationV1.model_validate_json(
        fixture.archive_attestation_path.read_bytes(), strict=True
    )
    future = GateFileInventoryV1(
        root="evidence",
        relative_path="provenance-receipt.json",
        content_size_bytes=1,
        content_sha256=_SHA_A,
    )
    files = tuple(sorted((*archive.files, future), key=lambda item: item.relative_path))
    unsigned = archive.model_dump(mode="json", exclude={"sha256"})
    unsigned.update(
        {
            "files": [item.model_dump(mode="json") for item in files],
            "file_count": len(files),
            "content_size_bytes": sum(item.content_size_bytes for item in files),
            "inventory_sha256": hashlib.sha256(
                b"".join(item.canonical_bytes() for item in files)
            ).hexdigest(),
        }
    )

    with pytest.raises(ValidationError, match="future"):
        _self_hashed(GateArchiveAttestationV1, unsigned)


@pytest.mark.parametrize(
    ("mutation", "match"),
    [
        ("dirty", "clean"),
        ("different_archives", "source archive"),
        ("different_images", "image"),
        ("removed_container", "retained"),
        ("failed_container", "successful"),
        ("created_container", "successful"),
        ("unbounded_writer_memory", "memory"),
        ("writer_swap_enabled", "memory"),
    ],
)
def test_validate_provenance_rejects_untrusted_host_claims(
    tmp_path: Path,
    mutation: str,
    match: str,
) -> None:
    fixture = _write_fixture(tmp_path)
    if mutation == "dirty":
        fixture.git.facts["checkout_clean"] = False
    elif mutation == "different_archives":
        fixture.git.facts["source_archive_sha256s"] = ("d" * 64, "e" * 64)
    elif mutation == "different_images":
        fixture.docker.reproduction["builds"][1]["image_id"] = f"sha256:{'e' * 64}"
    elif mutation == "removed_container":
        fixture.docker.containers["writer-gate"]["removed"] = True
        fixture.docker.containers["writer-gate"]["exists"] = False
    elif mutation == "created_container":
        fixture.docker.containers["writer-gate-verifier"]["status"] = "created"
    elif mutation == "unbounded_writer_memory":
        fixture.docker.containers["writer-gate"]["memory_limit_bytes"] = 0
    elif mutation == "writer_swap_enabled":
        fixture.docker.containers["writer-gate"]["memory_swap_limit_bytes"] = (
            8 * 1024**3
        )
    else:
        fixture.docker.containers["writer-gate-verifier"]["exit_code"] = 1

    with pytest.raises(ProvenanceValidationError, match=match):
        _validate(fixture)


@pytest.mark.parametrize("mutation", ["missing", "extra", "version"])
def test_validate_provenance_requires_exact_runtime_lock_distributions(
    tmp_path: Path,
    mutation: str,
) -> None:
    fixture = _write_fixture(tmp_path)
    distributions = list(
        fixture.docker.reproduction["builds"][0]["installed_distributions"]
    )
    if mutation == "missing":
        distributions.remove("pydantic==2.13.4")
    elif mutation == "extra":
        distributions.append("unexpected-runtime==1.0")
    else:
        distributions[distributions.index("zstandard==0.25.0")] = "zstandard==0.24.0"
    fixture.docker.reproduction["builds"][0]["installed_distributions"] = tuple(
        sorted(distributions)
    )

    with pytest.raises(ProvenanceValidationError, match="runtime dependency"):
        _validate(fixture)


def test_runtime_dependency_names_use_pep503_normalization() -> None:
    assert provenance_module._requirements_by_distribution(
        ("Ruamel.YAML_clib==0.2.15",)
    ) == {"ruamel-yaml-clib": "0.2.15"}


def test_disclosure_contains_no_private_paths_or_locator(tmp_path: Path) -> None:
    fixture = _write_fixture(tmp_path)
    acceptance = _validate(fixture)

    disclosure = build_disclosure(acceptance)
    source = disclosure.canonical_bytes()

    assert fixture.evidence_root.as_posix().encode() not in source
    assert fixture.data_root.as_posix().encode() not in source
    assert fixture.state_root.as_posix().encode() not in source
    assert b"s3://private-evidence" not in source
    assert disclosure.opaque_locator_sha256 == acceptance.opaque_locator_sha256


def test_writer_rejects_noncanonical_or_extended_build_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provenance = _build_provenance(
        source_commit="c" * 40,
        wheel_sha256=_SHA_A,
        requirements_lock_sha256=_SHA_A,
        dockerfile_sha256=_SHA_A,
        workload_sha256=_SHA_B,
    )
    path = tmp_path / "build-provenance-v1.json"
    path.write_bytes(
        encode_json(
            {
                **provenance.model_dump(mode="json"),
                "unexpected_private_claim": "/host/path",
            }
        )
        + b"\n"
    )
    monkeypatch.setenv("COLLECTOR_RUNTIME_IMAGE_ID", _IMAGE_ID)

    with pytest.raises(RunnerPreflightError, match="provenance"):
        writer._build_claims(
            functional_only=False,
            target_declaration=tmp_path / "target.json",
            expected_target_id="target-a",
            expected_image_id=_IMAGE_ID,
            build_provenance=path,
        )


def test_writer_cli_registers_provenance_and_disclosure_commands() -> None:
    result = CliRunner().invoke(writer.app, ["--help"])

    assert result.exit_code == 0
    assert "validate-provenance" in result.stdout
    assert "build-disclosure" in result.stdout


def test_writer_cli_injects_the_external_archive_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}
    archive_port = object()

    class Receipt:
        @staticmethod
        def canonical_bytes() -> bytes:
            return b"{}\n"

    def validate(**kwargs: object) -> Receipt:
        observed.update(kwargs)
        return Receipt()

    monkeypatch.setattr(writer, "validate_provenance", validate)
    monkeypatch.setattr(
        writer,
        "SubprocessArchiveProviderPort",
        lambda repository: archive_port,
        raising=False,
    )

    result = CliRunner().invoke(
        writer.app,
        [
            "validate-provenance",
            "--source-commit",
            "c" * 40,
            "--runtime-index",
            (tmp_path / "runtime-index.json").as_posix(),
            "--archive-attestation",
            (tmp_path / "archive-attestation.json").as_posix(),
            "--writer-container",
            "writer-gate",
            "--verifier-container",
            "writer-gate-verifier",
            "--repository",
            tmp_path.as_posix(),
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed["archive_provider"] is archive_port


def test_reproduction_script_freezes_clean_two_build_protocol() -> None:
    script_path = Path("scripts/reproduce-writer-image.sh")
    assert script_path.is_file()
    script = script_path.read_text(encoding="utf-8")

    assert script.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
    assert "mktemp -d" in script
    assert "trap cleanup" in script
    assert "git rev-parse --verify HEAD" in script
    assert "git archive" in script
    assert "for ordinal in 1 2" in script
    assert "moby/buildkit:v0.24.0@sha256:" in script
    assert "docker buildx create" in script
    assert "--driver docker-container" in script
    assert "docker buildx inspect" in script
    assert "docker version --format" in script
    assert "docker buildx version" in script
    assert 'buildkit_version="v0.24.0"' not in script
    assert '--builder "$builder_name"' in script
    assert "--platform linux/amd64" in script
    assert "--no-cache" in script
    assert "--provenance=false" in script
    assert "--sbom=false" in script
    assert "SOURCE_DATE_EPOCH" in script
    assert "COLLECTOR_WHEEL_SHA256" in script
    assert "BUILD_PROVENANCE_SHA256" in script
    assert "runtime_lock_requirements" in script
    assert "context-1/requirements/collector.lock" in script
    assert "docker image inspect" in script
    assert "docker container inspect" in script
    assert "docker container export" in script
    assert 'image.get("Os")' in script
    assert 'image.get("Architecture")' in script
    assert 'config.get("User")' in script
    assert 'config.get("Entrypoint")' in script
    assert 'config.get("Cmd")' in script
    assert 'separators=(",", ":")' in script
    assert "acceptance-receipt" not in script


def test_subprocess_docker_port_invokes_bash_reproducer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_commit = "a" * 40
    committed_script = b"#!/usr/bin/env bash\nexit 0\n"
    observed: list[tuple[str, ...]] = []

    class Completed:
        returncode = 0

        def __init__(self, stdout: bytes) -> None:
            self.stdout = stdout
            self.stderr = b""

    def run(command: tuple[str, ...], **kwargs: object) -> Completed:
        observed.append(command)
        if command[:2] == ("git", "show"):
            assert "input" not in kwargs
            return Completed(committed_script)
        assert kwargs["input"] == committed_script
        return Completed(b"{}\n")

    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    result = SubprocessDockerPort(Path.cwd()).reproduce(
        source_commit=source_commit,
        source_date_epoch=1,
    )

    assert result == {}
    assert observed == [
        ("git", "show", f"{source_commit}:scripts/reproduce-writer-image.sh"),
        (
            "bash",
            "-s",
            "--",
            "--source-commit",
            source_commit,
            "--source-date-epoch",
            "1",
        ),
    ]


def test_subprocess_docker_transcript_uses_strict_json_collection_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _write_fixture(tmp_path)

    class Completed:
        returncode = 0
        stdout = encode_json(fixture.docker.reproduction) + b"\n"
        stderr = b""

    monkeypatch.setattr(
        provenance_module.subprocess,
        "run",
        lambda *args, **kwargs: Completed(),
    )
    transcript = SubprocessDockerPort(tmp_path).reproduce(
        source_commit=fixture.source_commit,
        source_date_epoch=1_800_000_000,
    )
    runtime, _ = provenance_module._load_canonical(
        fixture.runtime_index_path,
        GateRuntimeIndexV1,
    )
    run_index, _ = provenance_module._load_ref(
        fixture.evidence_root,
        runtime.run_index,
        type(base_run_index(mode="qualification")),
    )
    git_facts = provenance_module._validate_git_facts(
        fixture.git.facts,
        fixture.source_commit,
    )

    reproduction = provenance_module._validate_reproduction(
        transcript,
        git_facts=git_facts,
        run_index=run_index,
    )

    assert reproduction.runtime_lock_requirements == _RUNTIME_LOCK_REQUIREMENTS


def test_subprocess_git_port_enumerates_untracked_and_ignored_build_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port = provenance_module.SubprocessGitPort(tmp_path)
    commands: list[tuple[str, ...]] = []
    bytecode = tmp_path / "src/collector/__pycache__/module.cpython-311.pyc"
    bytecode.parent.mkdir(parents=True)
    bytecode.write_bytes(b"inert interpreter cache")
    adjacent_bytecode = tmp_path / "src/cache.pyc"
    adjacent_bytecode.write_bytes(b"not inside __pycache__")
    wrong_suffix = bytecode.parent / "payload.txt"
    wrong_suffix.write_bytes(b"not bytecode")
    nested_bytecode = bytecode.parent / "nested/payload.pyc"
    nested_bytecode.parent.mkdir()
    nested_bytecode.write_bytes(b"not an immediate cache child")
    bytecode_link = bytecode.parent / "link.pyc"
    bytecode_link.symlink_to(bytecode.name)

    def git_output(*arguments: str) -> bytes:
        commands.append(arguments)
        if arguments[0] == "rev-parse":
            return ("c" * 40 + "\n").encode("ascii")
        if arguments[0] == "show":
            return b"1800000000\n"
        if arguments[0] == "status":
            return b""
        if "--ignored" in arguments:
            return (
                b"src/cache.pyc\0"
                b"src/collector/__pycache__/link.pyc\0"
                b"src/collector/__pycache__/module.cpython-311.pyc\0"
                b"src/collector/__pycache__/nested/payload.pyc\0"
                b"src/collector/__pycache__/payload.txt\0"
                b"src/ignored-input\0"
            )
        return b"Dockerfile.local\0"

    class Completed:
        returncode = 0
        stdout = b""
        stderr = b""

    def archive(command: tuple[object, ...], **kwargs: object) -> Completed:
        del kwargs
        destination = Path(command[command.index("-o") + 1])
        destination.write_bytes(b"deterministic archive")
        return Completed()

    monkeypatch.setattr(port, "_run", git_output)
    monkeypatch.setattr(provenance_module.subprocess, "run", archive)

    facts = port.inspect_source("c" * 40)

    assert isinstance(facts, dict)
    assert facts["untracked_build_inputs"] == ("Dockerfile.local",)
    assert facts["ignored_build_inputs"] == (
        "src/cache.pyc",
        "src/collector/__pycache__/link.pyc",
        "src/collector/__pycache__/nested/payload.pyc",
        "src/collector/__pycache__/payload.txt",
        "src/ignored-input",
    )
    assert any("--others" in command for command in commands)
    assert any("--ignored" in command for command in commands)


def test_subprocess_git_port_rejects_checkout_head_different_from_source_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port = provenance_module.SubprocessGitPort(tmp_path)

    def git_output(*arguments: str) -> bytes:
        if arguments == ("rev-parse", "--verify", "HEAD"):
            return ("d" * 40 + "\n").encode("ascii")
        if arguments[0] == "rev-parse":
            return ("c" * 40 + "\n").encode("ascii")
        raise AssertionError("checkout mismatch must fail before other Git commands")

    monkeypatch.setattr(port, "_run", git_output)

    with pytest.raises(ProvenanceValidationError, match="checkout HEAD"):
        port.inspect_source("c" * 40)


@pytest.mark.parametrize(
    ("provider", "locator", "expected_commands", "retention_mode"),
    [
        (
            "s3_object_lock",
            "s3://private-evidence/path/gate.tar.zst",
            ("head-object", "get-object"),
            "compliance",
        ),
        (
            "oss_worm",
            "oss://private-evidence/path/gate.tar.zst",
            ("head-object", "get-object-retention", "cp"),
            "worm",
        ),
    ],
)
def test_subprocess_archive_provider_queries_head_retention_and_versioned_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    provider: str,
    locator: str,
    expected_commands: tuple[str, ...],
    retention_mode: str,
) -> None:
    observed: list[tuple[str, ...]] = []
    destination = tmp_path.resolve() / "readback.tar.zst"
    source = b"remote archive bytes"

    class Completed:
        returncode = 0

        def __init__(self, stdout: bytes = b"") -> None:
            self.stdout = stdout
            self.stderr = b""

    def run(command: tuple[str, ...], **kwargs: object) -> Completed:
        del kwargs
        observed.append(command)
        if "head-object" in command:
            return Completed(
                encode_json(
                    {
                        "VersionId": "version-1",
                        "ContentLength": len(source),
                        "ObjectLockMode": "COMPLIANCE",
                        "ObjectLockRetainUntilDate": "2099-01-01T00:00:00Z",
                    }
                )
            )
        if "get-object-retention" in command:
            return Completed(
                encode_json(
                    {
                        "Retention": {
                            "Mode": "COMPLIANCE",
                            "RetainUntilDate": "2099-01-01T00:00:00Z",
                        }
                    }
                )
            )
        destination.write_bytes(source)
        return Completed(encode_json({"VersionId": "version-1"}))

    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    facts = provenance_module.SubprocessArchiveProviderPort(
        Path.cwd()
    ).verify_and_download(
        provider=provider,
        archive_locator=locator,
        object_version="version-1",
        destination=destination,
    )

    assert isinstance(facts, dict)
    assert facts["provider"] == provider
    assert facts["object_version"] == "version-1"
    assert facts["retention_mode"] == retention_mode
    assert facts["content_size_bytes"] == len(source)
    assert destination.read_bytes() == source
    flattened = tuple(argument for command in observed for argument in command)
    assert all(command in flattened for command in expected_commands)
    assert all("version-1" in command for command in observed)


def test_subprocess_archive_provider_rejects_webdav_without_command(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise AssertionError("WebDAV must not invoke a qualification provider")

    monkeypatch.setattr(provenance_module.subprocess, "run", run)

    with pytest.raises(ProvenanceValidationError, match="WebDAV"):
        provenance_module.SubprocessArchiveProviderPort(Path.cwd()).verify_and_download(
            provider="webdav",
            archive_locator="https://backup.invalid/gate.tar.zst",
            object_version="version-1",
            destination=tmp_path.resolve() / "readback.tar.zst",
        )


def test_archive_inventory_walk_errors_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def walk(
        root: Path,
        *,
        followlinks: bool,
        onerror: object,
    ) -> tuple[()]:
        del root, followlinks
        assert callable(onerror)
        onerror(PermissionError("denied"))
        return ()

    monkeypatch.setattr(provenance_module.os, "walk", walk)

    with pytest.raises(ProvenanceValidationError, match="walk archive inventory"):
        provenance_module._scan_inventory_root("evidence", tmp_path.resolve())


def test_provenance_publication_resumes_after_acceptance_crash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _write_fixture(tmp_path)
    publish = provenance_module._publish_no_replace
    crashed = False

    def crash_before_acceptance(path: Path, source: bytes) -> None:
        nonlocal crashed
        if path.name == "acceptance-receipt.json" and not crashed:
            crashed = True
            raise ProvenanceValidationError("injected acceptance publication crash")
        publish(path, source)

    monkeypatch.setattr(
        provenance_module,
        "_publish_no_replace",
        crash_before_acceptance,
    )
    with pytest.raises(ProvenanceValidationError, match="injected"):
        _validate(fixture)
    operator_root = fixture.archive_attestation_path.parent
    assert (operator_root / "provenance-receipt.json").is_file()
    assert not (operator_root / "acceptance-receipt.json").exists()

    first_provenance = GateProvenanceReceiptV1.model_validate_json(
        (operator_root / "provenance-receipt.json").read_bytes(),
        strict=True,
    )
    fixture.archive_provider.facts["observed_at_unix_ns"] = (
        first_provenance.verified_at_unix_ns + 1
    )

    monkeypatch.setattr(provenance_module, "_publish_no_replace", publish)
    resumed = _validate(fixture)
    repeated = _validate(fixture)

    assert resumed == repeated
    assert resumed.qualification_accepted is True


def test_provenance_resume_rejects_future_existing_receipt_time(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(tmp_path)
    _validate(fixture)
    operator_root = fixture.archive_attestation_path.parent
    provenance_path = operator_root / "provenance-receipt.json"
    acceptance_path = operator_root / "acceptance-receipt.json"
    provenance = GateProvenanceReceiptV1.model_validate_json(
        provenance_path.read_bytes(),
        strict=True,
    )
    unsigned = provenance.model_dump(mode="json", exclude={"sha256"})
    unsigned["verified_at_unix_ns"] = 2**63 - 1
    provenance_path.write_bytes(
        _self_hashed(GateProvenanceReceiptV1, unsigned).canonical_bytes()
    )
    acceptance_path.unlink()

    with pytest.raises(ProvenanceValidationError, match="receipt timestamp"):
        _validate(fixture)


def test_provenance_resume_rejects_acceptance_time_different_from_provenance(
    tmp_path: Path,
) -> None:
    fixture = _write_fixture(tmp_path)
    _validate(fixture)
    operator_root = fixture.archive_attestation_path.parent
    acceptance_path = operator_root / "acceptance-receipt.json"
    acceptance = GateAcceptanceReceiptV1.model_validate_json(
        acceptance_path.read_bytes(),
        strict=True,
    )
    unsigned = acceptance.model_dump(mode="json", exclude={"sha256"})
    unsigned["accepted_at_unix_ns"] = acceptance.accepted_at_unix_ns + 1
    acceptance_path.write_bytes(
        _self_hashed(GateAcceptanceReceiptV1, unsigned).canonical_bytes()
    )

    with pytest.raises(ProvenanceValidationError, match="receipt timestamp"):
        _validate(fixture)


def test_no_replace_publication_rejects_zero_progress_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def zero_then_fail(fd: int, source: object) -> int:
        del fd, source
        nonlocal calls
        calls += 1
        if calls == 1:
            return 0
        raise AssertionError("zero-progress write was retried")

    monkeypatch.setattr(provenance_module.os, "write", zero_then_fail)

    with pytest.raises(ProvenanceValidationError, match="zero-progress"):
        provenance_module._publish_no_replace(tmp_path / "receipt.json", b"{}\n")


def test_no_replace_identical_retry_fsyncs_parent_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "receipt.json"
    path.write_bytes(b"{}\n")
    fsynced: list[int] = []
    monkeypatch.setattr(provenance_module.os, "fsync", fsynced.append)

    provenance_module._publish_no_replace(path, b"{}\n")

    assert len(fsynced) == 1


def test_build_provenance_rejects_malformed_frontend_digest() -> None:
    provenance = _build_provenance(
        source_commit="c" * 40,
        wheel_sha256=_SHA_A,
        requirements_lock_sha256=_SHA_A,
        dockerfile_sha256=_SHA_A,
        workload_sha256=_SHA_B,
    )
    unsigned = provenance.model_dump(mode="json", exclude={"sha256"})
    unsigned["dockerfile_frontend"] = "docker/dockerfile:1.18@sha256:"

    with pytest.raises(ValidationError, match="frontend"):
        _self_hashed(GateBuildProvenanceV1, unsigned)


def test_subprocess_docker_port_rejects_second_inspect_identity_change(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port = SubprocessDockerPort(Path.cwd())
    responses = iter(
        (
            {"Id": "1" * 64},
            {
                "Id": "2" * 64,
                "Name": "/writer-gate",
                "Image": _IMAGE_ID,
                "State": {
                    "Status": "exited",
                    "Running": False,
                    "Paused": False,
                    "Restarting": False,
                    "OOMKilled": False,
                    "Dead": False,
                    "Pid": 0,
                    "ExitCode": 0,
                    "Error": "",
                },
            },
        )
    )
    monkeypatch.setattr(port, "_inspect", lambda identifier: next(responses))

    with pytest.raises(ProvenanceValidationError, match="identity"):
        port.inspect_container("writer-gate")


def test_subprocess_docker_port_binds_retained_memory_limits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port = SubprocessDockerPort(Path.cwd())
    container_id = "1" * 64
    inspected = {
        "Id": container_id,
        "Name": "/writer-gate",
        "Image": _IMAGE_ID,
        "State": {
            "Status": "exited",
            "Running": False,
            "Paused": False,
            "Restarting": False,
            "OOMKilled": False,
            "Dead": False,
            "Pid": 0,
            "ExitCode": 0,
            "Error": "",
        },
        "HostConfig": {
            "Memory": 4 * 1024**3,
            "MemorySwap": 4 * 1024**3,
        },
    }
    responses = iter(({"Id": container_id}, inspected))
    monkeypatch.setattr(port, "_inspect", lambda identifier: next(responses))

    facts = port.inspect_container("writer-gate")

    assert isinstance(facts, dict)
    assert facts["memory_limit_bytes"] == 4 * 1024**3
    assert facts["memory_swap_limit_bytes"] == 4 * 1024**3
