from __future__ import annotations

import hashlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from crypto_collector.benchmarks import runner
from crypto_collector.benchmarks.contracts import GateRootProbeV1, GateTargetV1
from crypto_collector.benchmarks.runner import (
    PreparedRun,
    QualificationClaims,
    RunnerPreflightError,
    RunRequest,
    WriterGateRunError,
    prepare_run,
)
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.storage.raw_writer import NoReplaceCapability

_NOW_UTC_NS = 1_786_850_400_000_000_000
_WORKLOAD_PATH = Path("benchmarks/workloads/research-default-v1.yaml").resolve()


class _ArtifactStub:
    def __init__(self, label: str = "artifact") -> None:
        self.label = label

    def canonical_bytes(self) -> bytes:
        return encode_json({"label": self.label}) + b"\n"

    def model_dump(self, *, mode: str) -> dict[str, object]:
        assert mode == "json"
        return {"label": self.label}


class _PlanStub:
    workload_plan_sha256 = "a" * 64


@pytest.fixture(autouse=True)
def _stub_workload_planner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        runner, "build_workload_plan", lambda *_args, **_kwargs: _PlanStub()
    )


def _functional_request(tmp_path: Path, **overrides: object) -> RunRequest:
    values: dict[str, object] = {
        "workload_path": _WORKLOAD_PATH,
        "multiplier": 2,
        "duration_ns": 10_000_000_000,
        "evidence_root": tmp_path / "evidence",
        "report_path": tmp_path / "writer-short.json",
        "functional_only": True,
    }
    values.update(overrides)
    return RunRequest(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("evidence_relative", "data_relative", "state_relative", "report_relative"),
    (
        ("evidence", None, None, "evidence/report.json"),
        ("report/evidence", None, None, "report"),
        ("evidence", "data", "state", "data/report.json"),
        ("evidence", "report/data", "state", "report"),
        ("evidence", "data", "state", "state/report.json"),
        ("evidence", "data", "report/state", "report"),
        ("evidence", "data", "state", "data/raw/report.json"),
        ("evidence", "data", "state", "data/raw"),
    ),
    ids=(
        "report-inside-evidence",
        "report-ancestor-of-evidence",
        "report-inside-data",
        "report-ancestor-of-data",
        "report-inside-state",
        "report-ancestor-of-state",
        "report-inside-raw",
        "report-is-raw-root",
    ),
)
def test_preflight_rejects_report_paths_that_overlap_writer_roots(
    tmp_path: Path,
    evidence_relative: str,
    data_relative: str | None,
    state_relative: str | None,
    report_relative: str,
) -> None:
    overrides: dict[str, object] = {
        "evidence_root": tmp_path / evidence_relative,
        "report_path": tmp_path / report_relative,
    }
    if data_relative is not None:
        assert state_relative is not None
        overrides.update(
            data_root=tmp_path / data_relative,
            state_root=tmp_path / state_relative,
        )

    with pytest.raises(RunnerPreflightError):
        prepare_run(
            _functional_request(tmp_path, **overrides),
            now_utc_ns=_NOW_UTC_NS,
        )


def _prepare_publication(tmp_path: Path) -> tuple[PreparedRun, Path]:
    prepared = prepare_run(
        _functional_request(tmp_path),
        now_utc_ns=_NOW_UTC_NS,
    )
    prepared.evidence_root.mkdir()
    workload_document = prepared.evidence_root / "workload.yaml"
    workload_document.write_bytes(b"workload\n")
    return prepared, workload_document


def _invoke_publication(
    prepared: PreparedRun,
    workload_document: Path,
) -> object:
    artifact: Any = _ArtifactStub()
    return runner._publish_candidate_dag(  # type: ignore[attr-defined]
        prepared=prepared,
        workload_document_path=workload_document,
        run_started_monotonic_ns=1,
        admission_started_monotonic_ns=2,
        admission_started_utc_ns=_NOW_UTC_NS,
        admission_ended_monotonic_ns=2 + prepared.request.duration_ns,
        trace_set=artifact,
        bucket_ref=artifact,
        worker_ref=artifact,
        resource_ref=artifact,
        health_ref=artifact,
        raw_inventory=artifact,
        manifest_inventory=artifact,
        summary=artifact,
    )


def _replace_models_with_stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    def build_stub(model_type: type[object], _unsigned: dict[str, object]) -> object:
        return _ArtifactStub(model_type.__name__)

    monkeypatch.setattr(runner, "_self_hashed", build_stub)
    monkeypatch.setattr(
        runner,
        "evaluate_runtime_candidate",
        lambda **_kwargs: SimpleNamespace(runtime_evidence_valid=True),
    )


def test_report_publication_failure_does_not_publish_run_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, workload_document = _prepare_publication(tmp_path)
    _replace_models_with_stubs(monkeypatch)

    def publish(path: Path, data: bytes) -> None:
        if path == prepared.report_path:
            raise OSError("injected report publication failure")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    monkeypatch.setattr(runner, "_publish_bytes_no_replace", publish)

    with pytest.raises(OSError, match="injected report publication failure"):
        _invoke_publication(prepared, workload_document)

    assert not (prepared.evidence_root / "run-index.json").exists()


def test_run_index_is_the_last_fallible_publication_action(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, workload_document = _prepare_publication(tmp_path)
    _replace_models_with_stubs(monkeypatch)
    published: list[Path] = []

    def publish(path: Path, data: bytes) -> None:
        published.append(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    monkeypatch.setattr(runner, "_publish_bytes_no_replace", publish)

    _invoke_publication(prepared, workload_document)

    assert published[-1] == prepared.evidence_root / "run-index.json"
    assert published.count(prepared.evidence_root / "run-index.json") == 1


def test_precommit_verifier_failure_forbids_all_candidate_leaf_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, workload_document = _prepare_publication(tmp_path)
    _replace_models_with_stubs(monkeypatch)
    monkeypatch.setattr(
        runner,
        "evaluate_runtime_candidate",
        lambda **_kwargs: SimpleNamespace(
            runtime_evidence_valid=False,
            failure_codes=("evidence_integrity_invalid",),
        ),
    )

    with pytest.raises(WriterGateRunError, match="precommit runtime verifier"):
        _invoke_publication(prepared, workload_document)

    assert not (prepared.evidence_root / "candidate-report.json").exists()
    assert not prepared.report_path.exists()
    assert not (prepared.evidence_root / "run-index.json").exists()
    assert not (prepared.evidence_root / "runtime-receipt.json").exists()
    assert not (prepared.evidence_root / "runtime-index.json").exists()


def _root_probe(root: Path) -> GateRootProbeV1:
    return GateRootProbeV1(
        root=root.as_posix(),
        storage_device="1:1",
        filesystem="ext4",
        mount_point=root.as_posix(),
        mount_options=("mount:rw", "super:rw"),
        minimum_available_bytes=107_374_182_400,
        observed_available_bytes=322_122_547_200,
        no_replace_capability=NoReplaceCapability.HARDLINK,
        same_parent_publication_only=True,
        file_sync_supported=True,
        directory_sync_supported=True,
    )


def _target_document(
    data_root: Path,
    state_root: Path,
    *,
    created_at_unix_ns: int,
) -> GateTargetV1:
    data_probe = _root_probe(data_root)
    state_probe = _root_probe(state_root)
    unsigned: dict[str, object] = {
        "schema_version": 1,
        "record_type": "gate_target_v1",
        "target_id": "gate-target-a",
        "data_root": data_probe.model_dump(mode="json"),
        "state_root": state_probe.model_dump(mode="json"),
        "deployment_purpose": "raw-writer-gate-b",
        "created_at_unix_ns": created_at_unix_ns,
    }
    return GateTargetV1(
        target_id="gate-target-a",
        data_root=data_probe,
        state_root=state_probe,
        created_at_unix_ns=created_at_unix_ns,
        sha256=hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest(),
    )


def _qualification_claims(target_path: Path) -> QualificationClaims:
    return QualificationClaims(
        target_declaration_path=target_path,
        expected_target_id="gate-target-a",
        expected_image_id="sha256:" + "1" * 64,
        runtime_image_id="sha256:" + "1" * 64,
        implementation_source_commit="2" * 40,
        collector_wheel_sha256="3" * 64,
        requirements_lock_sha256="4" * 64,
        dockerfile_sha256="5" * 64,
    )


def test_qualification_target_mutation_after_preflight_blocks_index_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    target_path = tmp_path / "target.json"
    original = _target_document(
        data_root,
        state_root,
        created_at_unix_ns=1_800_000_000_000_000_000,
    )
    target_path.write_bytes(original.canonical_bytes())
    monkeypatch.setattr(runner.sys, "platform", "linux")
    prepared = prepare_run(
        RunRequest(
            workload_path=_WORKLOAD_PATH,
            multiplier=2,
            duration_ns=600_000_000_000,
            evidence_root=tmp_path / "evidence",
            report_path=tmp_path / "writer-report.json",
            functional_only=False,
            data_root=data_root,
            state_root=state_root,
            qualification=_qualification_claims(target_path),
        ),
        now_utc_ns=_NOW_UTC_NS,
    )
    prepared.evidence_root.mkdir()
    workload_document = prepared.evidence_root / "workload.yaml"
    workload_document.write_bytes(b"workload\n")

    changed = _target_document(
        data_root,
        state_root,
        created_at_unix_ns=original.created_at_unix_ns + 1,
    )
    target_path.write_bytes(changed.canonical_bytes())
    _replace_models_with_stubs(monkeypatch)

    def publish(path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    monkeypatch.setattr(runner, "_publish_bytes_no_replace", publish)

    with pytest.raises((RunnerPreflightError, WriterGateRunError)):
        _invoke_publication(prepared, workload_document)

    assert not (prepared.evidence_root / "run-index.json").exists()
