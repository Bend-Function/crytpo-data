from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Any, NoReturn

import pytest

from crypto_collector.benchmarks import runtime_verifier
from crypto_collector.benchmarks.contracts import (
    GateRuntimeIndexV1,
    GateRuntimeReceiptV1,
)
from crypto_collector.storage.raw_writer import PublicationConflict
from tests.support.writer_gate_crash_child import CRASH_RETURN_CODE
from tests.support.writer_gate_evidence import write_passing_micro_evidence


class _SimulatedInterruption(BaseException):
    pass


def _final_paths(evidence_root: Path) -> tuple[Path, Path]:
    return (
        evidence_root / "runtime-receipt.json",
        evidence_root / "runtime-index.json",
    )


def _stat_identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)


def _run_crash_child(
    run_index_path: Path, phase: str
) -> subprocess.CompletedProcess[str]:
    repository_root = Path(__file__).resolve().parents[3]
    return subprocess.run(
        (
            sys.executable,
            "-m",
            "tests.support.writer_gate_crash_child",
            run_index_path.as_posix(),
            phase,
        ),
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def _load_runtime_pair(
    receipt_path: Path,
    runtime_index_path: Path,
) -> tuple[GateRuntimeReceiptV1, GateRuntimeIndexV1]:
    receipt_source = receipt_path.read_bytes()
    index_source = runtime_index_path.read_bytes()
    receipt = GateRuntimeReceiptV1.model_validate_json(receipt_source, strict=True)
    runtime_index = GateRuntimeIndexV1.model_validate_json(index_source, strict=True)
    assert receipt.canonical_bytes() == receipt_source
    assert runtime_index.canonical_bytes() == index_source
    return receipt, runtime_index


@pytest.mark.parametrize(
    "phase",
    (
        "after_primary_documents",
        "mid_trace",
        "after_trace",
        "after_bucket",
        "mid_worker_samples",
        "after_worker_samples",
        "after_resource_samples",
        "after_health_samples",
        "after_samples",
        "after_first_manifest",
        "after_first_raw_part",
        "mid_raw",
        "after_raw",
        "after_partial_sync",
        "after_receipt",
        "after_index_partial_sync",
        "after_index",
    ),
)
def test_fresh_process_recovers_after_sigkill_at_each_boundary(
    tmp_path: Path,
    phase: str,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)

    interrupted = _run_crash_child(evidence.run_index_path, phase)

    assert interrupted.returncode == CRASH_RETURN_CODE, (
        interrupted.stdout,
        interrupted.stderr,
    )
    stale_scratch = tuple(evidence.state_root.glob(".gate-runtime-*.sqlite.partial"))
    assert stale_scratch
    publication_phases = {
        "after_partial_sync",
        "after_receipt",
        "after_index_partial_sync",
        "after_index",
    }
    if phase not in publication_phases:
        assert any(Path(f"{path}-wal").is_file() for path in stale_scratch)
    if phase == "after_index":
        assert runtime_index_path.is_file()
        runtime_index_source = runtime_index_path.read_bytes()
        runtime_index_identity = _stat_identity(runtime_index_path)
    else:
        assert not runtime_index_path.exists()
        runtime_index_source = None
        runtime_index_identity = None
    if phase in {"after_receipt", "after_index_partial_sync", "after_index"}:
        assert receipt_path.is_file()
        receipt_source = receipt_path.read_bytes()
        receipt_identity = _stat_identity(receipt_path)
    else:
        assert not receipt_path.exists()
        receipt_source = None
        receipt_identity = None
    if phase == "after_partial_sync":
        assert tuple(evidence.root.glob(".runtime-receipt.json.partial.*"))
    if phase == "after_index_partial_sync":
        assert tuple(evidence.root.glob(".runtime-index.json.partial.*"))

    recovered = _run_crash_child(evidence.run_index_path, "none")

    assert recovered.returncode == 0, (recovered.stdout, recovered.stderr)
    receipt, runtime_index = _load_runtime_pair(receipt_path, runtime_index_path)
    assert receipt.runtime_evidence_valid is True
    assert runtime_index.run_id == receipt.run_id == evidence.run_index.run_id
    if receipt_source is not None:
        assert receipt_path.read_bytes() == receipt_source
        assert _stat_identity(receipt_path) == receipt_identity
    if runtime_index_source is not None:
        assert runtime_index_path.read_bytes() == runtime_index_source
        assert _stat_identity(runtime_index_path) == runtime_index_identity
    assert all(path.exists() for path in stale_scratch)


def test_interruption_before_receipt_publication_leaves_no_final_documents(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)

    def interrupt_before_receipt(*args: object, **kwargs: object) -> NoReturn:
        raise _SimulatedInterruption

    monkeypatch.setattr(
        runtime_verifier,
        "_publish_runtime_receipt",
        interrupt_before_receipt,
    )

    with pytest.raises(_SimulatedInterruption):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert not receipt_path.exists()
    assert not runtime_index_path.exists()


@pytest.mark.parametrize(
    "boundary",
    (
        "_load_primary_documents",
        "_validate_trace",
        "_validate_bucket_artifact",
        "_validate_sample_artifacts",
        "_validate_raw_evidence",
    ),
)
def test_restart_after_each_evidence_boundary_ignores_partial_attempt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    boundary: str,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)
    original = getattr(runtime_verifier, boundary)

    def interrupt_after_boundary(*args: object, **kwargs: object) -> NoReturn:
        original(*args, **kwargs)
        raise _SimulatedInterruption

    monkeypatch.setattr(runtime_verifier, boundary, interrupt_after_boundary)

    with pytest.raises(_SimulatedInterruption):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    stale_scratch = tuple(evidence.state_root.glob(".gate-runtime-*.sqlite.partial*"))
    assert stale_scratch
    assert not receipt_path.exists()
    assert not runtime_index_path.exists()

    monkeypatch.undo()
    receipt = runtime_verifier.validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )

    assert receipt.runtime_evidence_valid is True
    assert receipt_path.is_file()
    assert runtime_index_path.is_file()
    assert all(path.exists() for path in stale_scratch)


def test_restart_reuses_published_receipt_and_only_adds_runtime_index(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)
    publish_runtime_index = runtime_verifier._publish_runtime_index
    atomic_publish = runtime_verifier.atomic_write_and_sync_json_exclusive

    def interrupt_before_index(*args: object, **kwargs: object) -> NoReturn:
        raise _SimulatedInterruption

    monkeypatch.setattr(
        runtime_verifier,
        "_publish_runtime_index",
        interrupt_before_index,
    )

    with pytest.raises(_SimulatedInterruption):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert receipt_path.is_file()
    assert not runtime_index_path.exists()
    original_receipt = receipt_path.read_bytes()
    original_receipt_identity = _stat_identity(receipt_path)

    def forbid_receipt_republication(*args: object, **kwargs: object) -> NoReturn:
        pytest.fail("a fresh verifier must reuse the published receipt")

    published_paths: list[Path] = []

    def record_atomic_publication(
        path: Path,
        data: bytes,
        **kwargs: Any,
    ) -> None:
        published_paths.append(path)
        atomic_publish(path, data, **kwargs)

    monkeypatch.setattr(
        runtime_verifier,
        "_publish_runtime_index",
        publish_runtime_index,
    )
    monkeypatch.setattr(
        runtime_verifier,
        "_publish_runtime_receipt",
        forbid_receipt_republication,
    )
    monkeypatch.setattr(
        runtime_verifier,
        "atomic_write_and_sync_json_exclusive",
        record_atomic_publication,
    )

    receipt = runtime_verifier.validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )

    assert len(published_paths) == 1
    assert published_paths[0].parent == evidence.root
    assert published_paths[0].name.startswith(".runtime-index.json.partial.")
    assert receipt.canonical_bytes() == original_receipt
    assert receipt_path.read_bytes() == original_receipt
    assert _stat_identity(receipt_path) == original_receipt_identity
    assert runtime_index_path.is_file()


def test_complete_receipt_and_index_pair_replays_without_republication(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)
    first = runtime_verifier.validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )
    receipt_identity = _stat_identity(receipt_path)
    index_identity = _stat_identity(runtime_index_path)

    second = runtime_verifier.validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )

    assert second == first
    assert _stat_identity(receipt_path) == receipt_identity
    assert _stat_identity(runtime_index_path) == index_identity


def test_runtime_index_without_receipt_is_rejected_without_overwrite(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)
    sentinel = b"orphan runtime index\n"
    runtime_index_path.write_bytes(sentinel)

    with pytest.raises(
        runtime_verifier.RuntimeEvidenceValidationError,
        match="without its receipt",
    ):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert not receipt_path.exists()
    assert runtime_index_path.read_bytes() == sentinel


def test_malformed_existing_receipt_is_rejected_without_index(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)
    sentinel = b"{}\n"
    receipt_path.write_bytes(sentinel)

    with pytest.raises(
        runtime_verifier.RuntimeEvidenceValidationError,
        match="runtime-receipt.json is invalid",
    ):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert receipt_path.read_bytes() == sentinel
    assert not runtime_index_path.exists()


def test_foreign_existing_receipt_is_rejected_without_index(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    foreign = write_passing_micro_evidence(tmp_path / "foreign")
    runtime_verifier.validate_runtime_evidence(
        foreign.run_index_path,
        target_probe=None,
    )
    receipt_path, runtime_index_path = _final_paths(evidence.root)
    foreign_receipt = (foreign.root / "runtime-receipt.json").read_bytes()
    receipt_path.write_bytes(foreign_receipt)

    with pytest.raises(
        runtime_verifier.RuntimeEvidenceValidationError,
        match="binds a different run",
    ):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert receipt_path.read_bytes() == foreign_receipt
    assert not runtime_index_path.exists()


@pytest.mark.parametrize("replacement", (b"{}\n", b"foreign"))
def test_conflicting_existing_runtime_index_is_rejected_without_overwrite(
    tmp_path: Path,
    replacement: bytes,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)
    runtime_verifier.validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )
    if replacement == b"foreign":
        foreign = write_passing_micro_evidence(tmp_path / "foreign")
        runtime_verifier.validate_runtime_evidence(
            foreign.run_index_path,
            target_probe=None,
        )
        replacement = (foreign.root / "runtime-index.json").read_bytes()
    runtime_index_path.write_bytes(replacement)
    receipt_source = receipt_path.read_bytes()

    with pytest.raises(runtime_verifier.RuntimeEvidenceValidationError):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert receipt_path.read_bytes() == receipt_source
    assert runtime_index_path.read_bytes() == replacement


def test_restart_recomputes_predecessors_before_reusing_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)

    def interrupt_before_index(*args: object, **kwargs: object) -> NoReturn:
        raise _SimulatedInterruption

    monkeypatch.setattr(
        runtime_verifier,
        "_publish_runtime_index",
        interrupt_before_index,
    )
    with pytest.raises(_SimulatedInterruption):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )
    original_receipt = receipt_path.read_bytes()
    candidate_path = evidence.root / evidence.run_index.candidate_report.relative_path
    candidate_path.write_bytes(b"{}\n")
    monkeypatch.undo()

    with pytest.raises(
        runtime_verifier.RuntimeEvidenceValidationError,
        match="fresh recomputation",
    ):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert receipt_path.read_bytes() == original_receipt
    assert not runtime_index_path.exists()


@pytest.mark.parametrize(
    "final_name",
    ("runtime-receipt.json", "runtime-index.json"),
)
def test_publication_never_overwrites_a_concurrently_created_final_node(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    final_name: str,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    target = evidence.root / final_name
    sentinel = b"pre-existing final node\n"
    publish_no_replace = runtime_verifier.publish_no_replace

    def occupy_target_before_publish(
        source: Path,
        destination: Path,
        **kwargs: Any,
    ) -> None:
        if destination == target:
            target.write_bytes(sentinel)
        publish_no_replace(source, destination, **kwargs)

    monkeypatch.setattr(
        runtime_verifier,
        "publish_no_replace",
        occupy_target_before_publish,
    )

    with pytest.raises(PublicationConflict):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert target.is_file()
    assert target.read_bytes() == sentinel


def test_partial_documents_and_stale_scratch_are_not_treated_as_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    receipt_path, runtime_index_path = _final_paths(evidence.root)
    receipt_partial = evidence.root / ".runtime-receipt.json.partial.stale-attempt"
    index_partial = evidence.root / ".runtime-index.json.partial.stale-attempt"
    atomic_publish = runtime_verifier.atomic_write_and_sync_json_exclusive

    def leave_partial_documents(
        path: Path,
        data: bytes,
        **kwargs: Any,
    ) -> NoReturn:
        assert path.parent == evidence.root
        assert path.name.startswith(".runtime-receipt.json.partial.")
        receipt_partial.write_bytes(data)
        index_partial.write_bytes(b"incomplete runtime index\n")
        raise _SimulatedInterruption

    monkeypatch.setattr(
        runtime_verifier,
        "atomic_write_and_sync_json_exclusive",
        leave_partial_documents,
    )

    with pytest.raises(_SimulatedInterruption):
        runtime_verifier.validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    stale_scratch = tuple(evidence.state_root.glob(".gate-runtime-*.sqlite.partial*"))
    assert receipt_partial.is_file()
    assert index_partial.is_file()
    assert stale_scratch
    assert not receipt_path.exists()
    assert not runtime_index_path.exists()

    published_paths: list[Path] = []

    def record_atomic_publication(
        path: Path,
        data: bytes,
        **kwargs: Any,
    ) -> None:
        published_paths.append(path)
        atomic_publish(path, data, **kwargs)

    monkeypatch.setattr(
        runtime_verifier,
        "atomic_write_and_sync_json_exclusive",
        record_atomic_publication,
    )

    receipt = runtime_verifier.validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )

    assert len(published_paths) == 2
    assert published_paths[0].name.startswith(".runtime-receipt.json.partial.")
    assert published_paths[1].name.startswith(".runtime-index.json.partial.")
    assert receipt.runtime_evidence_valid is True
    assert receipt_path.is_file()
    assert runtime_index_path.is_file()
    assert receipt_partial.is_file()
    assert index_partial.is_file()
    assert all(path.exists() for path in stale_scratch)
