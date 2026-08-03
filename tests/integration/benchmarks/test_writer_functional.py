from __future__ import annotations

from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from crypto_collector.benchmarks import runner, writer
from crypto_collector.benchmarks.artifacts import iter_merged_trace_partitions
from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    GateRuntimeReceiptV1,
)
from crypto_collector.benchmarks.runner import RunRequest, run_writer_gate
from tests.support.writer_gate_evidence import _micro_workload_bytes


def test_real_spawn_micro_workload_produces_independently_valid_evidence(
    tmp_path: Path,
) -> None:
    workload = tmp_path / "workload.json"
    workload.write_bytes(_micro_workload_bytes())
    result = run_writer_gate(
        RunRequest(
            workload_path=workload,
            multiplier=1,
            duration_ns=10_000_000_000,
            evidence_root=tmp_path / "evidence",
            report_path=tmp_path / "writer-short.json",
            functional_only=True,
        )
    )

    assert result.child_process_count == len(CANONICAL_EXCHANGES)
    assert result.candidate_report.candidate_runtime_passed is True
    assert result.candidate_report.runtime_summary.expected_record_count == 17
    assert result.candidate_report.runtime_summary.accepted_record_count == 17
    assert result.candidate_report.runtime_summary.durable_record_count == 17
    assert (
        result.candidate_report.runtime_summary.raw_file_count
        == result.candidate_report.runtime_summary.expected_touched_file_identity_count
    )
    assert result.run_index_path.name == "run-index.json"
    assert result.report_path.read_bytes() == result.candidate_report.canonical_bytes()
    trace_rows = iter_merged_trace_partitions(
        result.run_index_path.parent,
        result.run_index.admission_trace_set.partitions,
        max_rows=result.candidate_report.runtime_summary.expected_record_count,
        max_content_bytes=(
            result.run_index.admission_trace_set.merged_content_size_bytes
        ),
        max_line_bytes=64 * 1024,
    )
    assert result.candidate_report.admission_ended_monotonic_ns == max(
        result.candidate_report.admission_scheduled_end_monotonic_ns,
        *(row.admission_completed_monotonic_ns for row in trace_rows),
    )

    writer._launch_fresh_runtime_verifier(  # type: ignore[attr-defined]
        result.run_index_path,
        expected_target_id=None,
    )
    receipt_source = (
        result.run_index_path.parent / "runtime-receipt.json"
    ).read_bytes()
    receipt = GateRuntimeReceiptV1.model_validate_json(receipt_source, strict=True)
    assert receipt.canonical_bytes() == receipt_source

    assert receipt.runtime_evidence_valid is True
    assert receipt.qualification_runtime_accepted is False


def _micro_request(tmp_path: Path) -> RunRequest:
    workload = tmp_path / "workload.json"
    workload.write_bytes(_micro_workload_bytes())
    return RunRequest(
        workload_path=workload,
        multiplier=1,
        duration_ns=10_000_000_000,
        evidence_root=tmp_path / "evidence",
        report_path=tmp_path / "writer-short.json",
        functional_only=True,
    )


def _assert_failed_run_has_only_partial_health(request: RunRequest) -> None:
    assert not (request.evidence_root / "candidate-report.json").exists()
    assert not (request.evidence_root / "run-index.json").exists()
    assert not request.report_path.exists()
    health = request.evidence_root / "diagnostics/storage-health-partial.jsonl.zst"
    assert health.is_file() or Path(f"{health}.partial").is_file()
    workers = request.evidence_root / "diagnostics/workers-partial.jsonl.zst"
    assert workers.is_file() or Path(f"{workers}.partial").is_file()


def test_periodic_statvfs_failure_retains_health_and_forbids_candidate(
    tmp_path: Path,
) -> None:
    request = _micro_request(tmp_path)
    with (
        patch.object(
            runner,
            "_available_bytes",
            side_effect=OSError("injected statvfs failure"),
        ),
        pytest.raises(runner.WriterGateRunError, match="statvfs"),
    ):
        run_writer_gate(request)

    _assert_failed_run_has_only_partial_health(request)


def test_worker_health_sampling_failure_retains_health_and_forbids_candidate(
    tmp_path: Path,
) -> None:
    request = _micro_request(tmp_path)
    original = runner._store_child_message

    def fail_first_sample(message: object, **kwargs: Any) -> None:
        original(message, **kwargs)
        if isinstance(message, dict) and message.get("kind") == "sample":
            raise runner.WriterGateRunError("injected worker-health sampling failure")

    with (
        patch.object(
            runner,
            "_store_child_message",
            fail_first_sample,
        ),
        pytest.raises(runner.WriterGateRunError, match="worker-health"),
    ):
        run_writer_gate(request)

    _assert_failed_run_has_only_partial_health(request)
