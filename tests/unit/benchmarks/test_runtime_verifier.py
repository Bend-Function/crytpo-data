from __future__ import annotations

import hashlib
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
import zstandard
from pydantic import BaseModel, ValidationError

from crypto_collector.benchmarks import runtime_verifier
from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    FinalWorkerAggregateV1,
    GateAdmissionTraceSetV1,
    GateArtifactRefV1,
    GateCandidateReportV1,
    GateEvidenceDocumentRefV1,
    GateExchangeArtifactPartitionV1,
    GateManifestInventoryEntryV1,
    GateManifestInventoryV1,
    GateRawInventoryV1,
    GateResourceSummaryV1,
    GateRootProbeV1,
    GateRunIndexV1,
    GateRuntimeIndexV1,
    GateRuntimeReceiptV1,
    GateRuntimeSummaryV1,
    GateStorageHealthSummaryV1,
    GateStreamRuntimeSummaryV1,
    GateTargetReprobeV1,
    GateTargetV1,
    StreamGroup,
)
from crypto_collector.benchmarks.runtime_verifier import (
    RuntimeEvidenceValidationError,
    TargetProbePort,
    evaluate_runtime_candidate,
    validate_runtime_evidence,
)
from crypto_collector.benchmarks.target import GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES
from crypto_collector.benchmarks.workload import load_workload
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.storage.manifest import RawManifestV1, load_raw_manifest
from crypto_collector.storage.raw_writer import NoReplaceCapability
from crypto_collector.storage.stats import DURABILITY_BUCKET_UPPER_BOUNDS_NS
from tests.support.writer_gate_evidence import write_passing_micro_evidence

_SHA_A = "a" * 64
_SHA_B = "b" * 64
_RUN_ID = "00000000-0000-4000-8000-000000000001"
_STREAMS: tuple[StreamGroup, ...] = (
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "derivative",
    "candle_1m",
    "book_deep_snapshot",
    "control",
)


def test_precommit_evaluation_matches_fresh_verifier_without_publication(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    candidate_source = evidence.candidate_report.canonical_bytes()
    candidate_path = evidence.root / "candidate-report.json"
    candidate_path.unlink()
    evidence.run_index_path.unlink()

    evaluation = evaluate_runtime_candidate(
        evidence_root=evidence.root,
        run_index=evidence.run_index,
        candidate_source=candidate_source,
        target_probe=None,
    )

    assert evaluation.runtime_evidence_valid is True
    assert evaluation.recomputed_summary == evidence.candidate_report.runtime_summary
    assert evaluation.failure_codes == ()
    assert not candidate_path.exists()
    assert not evidence.run_index_path.exists()
    assert not (evidence.root / "runtime-receipt.json").exists()
    assert not (evidence.root / "runtime-index.json").exists()

    candidate_path.write_bytes(candidate_source)
    evidence.run_index_path.write_bytes(evidence.run_index.canonical_bytes())
    receipt = validate_runtime_evidence(evidence.run_index_path, target_probe=None)

    assert receipt.runtime_evidence_valid == evaluation.runtime_evidence_valid
    assert receipt.recomputed_summary == evaluation.recomputed_summary
    assert receipt.failure_codes == evaluation.failure_codes
    assert receipt.evidence_integrity_valid == evaluation.evidence_integrity_valid
    assert receipt.candidate_summary_matches == evaluation.candidate_summary_matches
    assert receipt.runtime_predicates_passed == evaluation.runtime_predicates_passed


def test_precommit_evaluation_rejects_candidate_ref_mismatch_without_publication(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    candidate_path = evidence.root / "candidate-report.json"
    candidate_path.unlink()
    evidence.run_index_path.unlink()

    evaluation = evaluate_runtime_candidate(
        evidence_root=evidence.root,
        run_index=evidence.run_index,
        candidate_source=evidence.candidate_report.canonical_bytes() + b" ",
        target_probe=None,
    )

    assert evaluation.runtime_evidence_valid is False
    assert evaluation.failure_codes == ("evidence_integrity_invalid",)
    assert not candidate_path.exists()
    assert not evidence.run_index_path.exists()
    assert not (evidence.root / "runtime-receipt.json").exists()
    assert not (evidence.root / "runtime-index.json").exists()


_EXPECTED_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    GateEvidenceDocumentRefV1: (
        "schema_version",
        "record_type",
        "relative_path",
        "content_size_bytes",
        "content_sha256",
    ),
    GateManifestInventoryEntryV1: (
        "ordinal",
        "manifest",
        "data",
        "manifest_record_count",
    ),
    GateRawInventoryV1: (
        "schema_version",
        "record_type",
        "raw_files",
        "file_count",
        "record_count",
        "content_size_bytes",
        "compressed_size_bytes",
        "sha256",
    ),
    GateManifestInventoryV1: (
        "schema_version",
        "record_type",
        "manifests",
        "file_count",
        "record_count",
        "manifest_content_size_bytes",
        "sha256",
    ),
    GateStreamRuntimeSummaryV1: (
        "stream_group",
        "expected_record_count",
        "expected_payload_bytes",
        "scheduled_record_count",
        "scheduled_payload_bytes",
        "attempted_record_count",
        "attempted_payload_bytes",
        "accepted_record_count",
        "accepted_payload_bytes",
        "early_count",
        "late_count",
        "out_of_window_count",
        "required_burst_count",
        "scheduled_burst_count",
        "burst_second",
        "burst_scheduled_count",
        "burst_attempted_count",
        "burst_accepted_count",
        "burst_admitted_in_actual_second_count",
        "planned_values_match",
        "admission_values_match",
        "burst_valid",
    ),
    GateRuntimeSummaryV1: (
        "expected_record_count",
        "expected_payload_bytes",
        "scheduled_record_count",
        "scheduled_payload_bytes",
        "attempted_record_count",
        "attempted_payload_bytes",
        "accepted_record_count",
        "accepted_payload_bytes",
        "durable_record_count",
        "durable_payload_bytes",
        "durability_sample_count",
        "manifest_record_count",
        "raw_file_count",
        "manifest_file_count",
        "declared_file_identity_count",
        "expected_touched_file_identity_count",
        "observed_touched_file_identity_count",
        "accepted_identity_count",
        "unique_accepted_identity_count",
        "early_count",
        "late_count",
        "out_of_window_count",
        "received_utc_hours",
        "stream_summaries",
        "final_worker_aggregate",
        "resource_summary",
        "storage_health_summary",
    ),
    GateCandidateReportV1: (
        "schema_version",
        "record_type",
        "run_id",
        "mode",
        "workload_sha256",
        "workload_plan_sha256",
        "multiplier",
        "duration_ns",
        "run_started_monotonic_ns",
        "admission_started_monotonic_ns",
        "admission_scheduled_end_monotonic_ns",
        "admission_ended_monotonic_ns",
        "run_ended_monotonic_ns",
        "admission_started_utc_ns",
        "admission_ended_utc_ns",
        "declared_admission_utc_hour",
        "expected_target_id",
        "target_declaration_sha256",
        "expected_image_id",
        "runtime_image_id",
        "runtime_summary",
        "runtime_failure_codes",
        "candidate_runtime_passed",
        "sha256",
    ),
    GateRunIndexV1: (
        "schema_version",
        "record_type",
        "run_id",
        "status",
        "mode",
        "artifact_schema_version",
        "identity_algorithm",
        "event_algorithm",
        "payload_algorithm",
        "schedule_algorithm",
        "data_root",
        "state_root",
        "workload_document",
        "workload_sha256",
        "workload_plan_sha256",
        "admission_trace_set",
        "second_bucket_artifact",
        "worker_sampling_artifact",
        "resource_sampling_artifact",
        "storage_health_artifact",
        "raw_inventory",
        "manifest_inventory",
        "candidate_report",
        "expected_target_id",
        "target_declaration",
        "implementation_source_commit",
        "collector_wheel_sha256",
        "requirements_lock_sha256",
        "dockerfile_sha256",
        "expected_image_id",
        "runtime_image_id",
        "sha256",
    ),
    GateRuntimeReceiptV1: (
        "schema_version",
        "record_type",
        "verifier_version",
        "verified_at_unix_ns",
        "run_id",
        "mode",
        "run_index_sha256",
        "run_index_content_sha256",
        "expected_target_id",
        "recomputed_summary",
        "target_reprobe",
        "failure_codes",
        "evidence_integrity_valid",
        "candidate_summary_matches",
        "runtime_predicates_passed",
        "runtime_evidence_valid",
        "qualification_runtime_accepted",
        "sha256",
    ),
    GateRuntimeIndexV1: (
        "schema_version",
        "record_type",
        "run_id",
        "status",
        "mode",
        "run_index",
        "runtime_receipt",
        "sha256",
    ),
}


def _hash(unsigned: dict[str, Any]) -> str:
    return hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest()


def _self_hashed(model_type: type[Any], unsigned: dict[str, Any]) -> Any:
    return model_type.model_validate_json(
        encode_json({**unsigned, "sha256": _hash(unsigned)})
    )


def _rehash(model_type: type[Any], model: Any, **updates: Any) -> Any:
    unsigned = model.model_dump(mode="json", exclude={"sha256"})
    unsigned.update(updates)
    return _self_hashed(model_type, unsigned)


def test_runtime_verifier_rejects_noncanonical_entrypoint(tmp_path: Path) -> None:
    wrong_path = tmp_path / "other-index.json"
    wrong_path.write_bytes(b"{}\n")
    probe: TargetProbePort | None = None

    with pytest.raises(RuntimeEvidenceValidationError, match="run-index.json"):
        validate_runtime_evidence(wrong_path, target_probe=probe)

    assert not (tmp_path / "runtime-receipt.json").exists()
    assert not (tmp_path / "runtime-index.json").exists()


def test_raw_frame_scanner_accepts_multiple_independent_frames(
    tmp_path: Path,
) -> None:
    compressor = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    )
    path = tmp_path / "multi-frame.jsonl.zst"
    path.write_bytes(
        compressor.compress(b'{"row":1}\n') + compressor.compress(b'{"row":2}\n')
    )

    runtime_verifier._validate_raw_zstd_frames(
        path,
        max_plain_frame_bytes=64,
    )


@pytest.mark.parametrize(
    "mutation",
    (
        "checksum_corrupt",
        "truncated",
        "trailing_garbage",
        "invalid_second_frame",
        "missing_frame_newline",
    ),
)
def test_raw_frame_scanner_rejects_physical_corruption(
    tmp_path: Path,
    mutation: str,
) -> None:
    compressor = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    )
    first = compressor.compress(b'{"row":1}\n')
    if mutation == "checksum_corrupt":
        changed = bytearray(first)
        changed[-1] ^= 1
        source = bytes(changed)
    elif mutation == "truncated":
        source = first[:-1]
    elif mutation == "trailing_garbage":
        source = first + b"not-a-zstd-frame"
    elif mutation == "invalid_second_frame":
        source = first + zstandard.ZstdCompressor(
            level=3,
            write_checksum=False,
            write_content_size=True,
        ).compress(b'{"row":2}\n')
    else:
        assert mutation == "missing_frame_newline"
        source = compressor.compress(b'{"row":1}')
    path = tmp_path / f"{mutation}.jsonl.zst"
    path.write_bytes(source)

    with pytest.raises(RuntimeEvidenceValidationError):
        runtime_verifier._validate_raw_zstd_frames(
            path,
            max_plain_frame_bytes=64,
        )


def test_runtime_verifier_recomputes_functional_acceptance(tmp_path: Path) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")

    receipt = validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )

    assert receipt.runtime_evidence_valid is True
    assert receipt.qualification_runtime_accepted is False
    assert receipt.recomputed_summary == evidence.candidate_report.runtime_summary
    assert (evidence.root / "runtime-receipt.json").read_bytes() == (
        receipt.canonical_bytes()
    )
    runtime_index_path = evidence.root / "runtime-index.json"
    runtime_index_source = runtime_index_path.read_bytes()
    runtime_index = GateRuntimeIndexV1.model_validate_json(
        runtime_index_source,
        strict=True,
    )
    assert runtime_index.canonical_bytes() == runtime_index_source
    assert (runtime_index.run_id, runtime_index.mode) == (
        evidence.run_index.run_id,
        "functional",
    )
    for reference, path in (
        (runtime_index.run_index, evidence.run_index_path),
        (runtime_index.runtime_receipt, evidence.root / "runtime-receipt.json"),
    ):
        source = path.read_bytes()
        assert reference.content_size_bytes == len(source)
        assert reference.content_sha256 == hashlib.sha256(source).hexdigest()


def test_functional_runtime_allows_unavailable_post_warmup_trend(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(
        tmp_path / "evidence",
        warmup_seconds=120,
    )

    receipt = validate_runtime_evidence(evidence.run_index_path, target_probe=None)

    assert receipt.recomputed_summary is not None
    resource = receipt.recomputed_summary.resource_summary
    assert resource.resource_trend_valid is False
    assert resource.rss_slope_bytes_per_minute is None
    assert receipt.runtime_evidence_valid is True


def test_functional_runtime_predicate_accepts_complete_late_admission(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    summary = evidence.candidate_report.runtime_summary
    streams = list(summary.stream_summaries)
    stream = streams[0]
    streams[0] = type(stream).model_validate(
        {
            **stream.model_dump(mode="python"),
            "late_count": 1,
            "out_of_window_count": 1,
            "admission_values_match": False,
        }
    )
    late_summary = GateRuntimeSummaryV1.model_validate(
        {
            **summary.model_dump(mode="python"),
            "late_count": 1,
            "out_of_window_count": 1,
            "stream_summaries": tuple(streams),
        }
    )
    documents = SimpleNamespace(
        workload=SimpleNamespace(workload=evidence.workload),
        candidate=evidence.candidate_report,
    )

    assert runtime_verifier._runtime_predicates_pass(  # type: ignore[attr-defined,arg-type]
        evidence.run_index,
        documents,
        evidence.plan,
        late_summary,
        None,
    )


def test_functional_runtime_predicate_records_performance_breaches(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    summary = evidence.candidate_report.runtime_summary
    aggregate = summary.final_worker_aggregate
    resource = summary.resource_summary
    health = summary.storage_health_summary
    degraded = GateRuntimeSummaryV1.model_validate(
        {
            **summary.model_dump(mode="python"),
            "final_worker_aggregate": type(aggregate).model_validate(
                {
                    **aggregate.model_dump(mode="python"),
                    "slo_breach_count": 1,
                    "active_logical_generation_count_peak": 1,
                    "retiring_generation_count_peak": 1,
                }
            ),
            "resource_summary": type(resource).model_validate(
                {
                    **resource.model_dump(mode="python"),
                    "sample_max_gap_ns": resource.coverage_ns,
                    "rss_peak_bytes": 10**12,
                    "open_fds_peak": 10**6,
                }
            ),
            "storage_health_summary": type(health).model_validate(
                {
                    **health.model_dump(mode="python"),
                    "sample_max_gap_ns": health.coverage_ns,
                }
            ),
        }
    )
    documents = SimpleNamespace(
        workload=SimpleNamespace(workload=evidence.workload),
        candidate=evidence.candidate_report,
    )

    assert runtime_verifier._runtime_predicates_pass(  # type: ignore[attr-defined,arg-type]
        evidence.run_index,
        documents,
        evidence.plan,
        degraded,
        None,
    )


def test_functional_runtime_predicate_rejects_critical_worker_observation(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    summary = evidence.candidate_report.runtime_summary
    health = summary.storage_health_summary
    changed = GateRuntimeSummaryV1.model_validate(
        {
            **summary.model_dump(mode="python"),
            "storage_health_summary": type(health).model_validate(
                {
                    **health.model_dump(mode="python"),
                    "critical_worker_observation_count": 1,
                    "workers_healthy": False,
                }
            ),
        }
    )
    documents = SimpleNamespace(
        workload=SimpleNamespace(workload=evidence.workload),
        candidate=evidence.candidate_report,
    )

    assert not runtime_verifier._runtime_predicates_pass(  # type: ignore[attr-defined,arg-type]
        evidence.run_index,
        documents,
        evidence.plan,
        changed,
        None,
    )


def test_functional_runtime_predicate_rejects_extra_rotated_files(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    summary = evidence.candidate_report.runtime_summary
    changed = GateRuntimeSummaryV1.model_validate(
        {
            **summary.model_dump(mode="python"),
            "raw_file_count": summary.raw_file_count + 1,
            "manifest_file_count": summary.manifest_file_count + 1,
        }
    )
    documents = SimpleNamespace(
        workload=SimpleNamespace(workload=evidence.workload),
        candidate=evidence.candidate_report,
    )

    assert not runtime_verifier._runtime_predicates_pass(  # type: ignore[attr-defined,arg-type]
        evidence.run_index,
        documents,
        evidence.plan,
        changed,
        None,
    )


def test_functional_sample_validation_records_large_sampling_gaps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    delayed_ns = 100_000_000_000

    worker_rounds = list(evidence.worker_rounds)
    final_worker_round = worker_rounds[-1]
    delayed_worker_samples = tuple(
        type(sample).model_validate(
            {
                **sample.model_dump(mode="python"),
                "scheduled_monotonic_ns": delayed_ns,
                "request_started_monotonic_ns": delayed_ns,
                "request_completed_monotonic_ns": delayed_ns,
                "snapshot": type(sample.snapshot).model_validate(
                    {
                        **sample.snapshot.model_dump(mode="python"),
                        "observed_monotonic_ns": delayed_ns,
                    }
                ),
            }
        )
        for sample in final_worker_round.samples
    )
    worker_rounds[-1] = type(final_worker_round).model_validate(
        {
            **final_worker_round.model_dump(mode="python"),
            "scheduled_monotonic_ns": delayed_ns,
            "samples": delayed_worker_samples,
        }
    )

    resource_rounds = list(evidence.resource_rounds)
    final_resource_round = resource_rounds[-1]
    delayed_resource_samples = tuple(
        type(sample).model_validate(
            {
                **sample.model_dump(mode="python"),
                "scheduled_monotonic_ns": delayed_ns,
                "request_started_monotonic_ns": delayed_ns,
                "request_completed_monotonic_ns": delayed_ns,
            }
        )
        for sample in final_resource_round.samples
    )
    resource_rounds[-1] = type(final_resource_round).model_validate(
        {
            **final_resource_round.model_dump(mode="python"),
            "scheduled_monotonic_ns": delayed_ns,
            "samples": delayed_resource_samples,
        }
    )

    health_samples = list(evidence.health_samples)
    final_health_sample = health_samples[-1]
    health_samples[-1] = type(final_health_sample).model_validate(
        {
            **final_health_sample.model_dump(mode="python"),
            "scheduled_monotonic_ns": delayed_ns,
            "request_started_monotonic_ns": delayed_ns,
            "request_completed_monotonic_ns": delayed_ns,
        }
    )

    def artifact_rows(
        _root: Path,
        _reference: object,
        model_type: type[BaseModel],
        **_kwargs: object,
    ) -> tuple[BaseModel, ...]:
        if model_type is type(worker_rounds[0]):
            return tuple(worker_rounds)
        if model_type is type(resource_rounds[0]):
            return tuple(resource_rounds)
        if model_type is type(health_samples[0]):
            return tuple(health_samples)
        raise AssertionError(f"unexpected sample model: {model_type}")

    monkeypatch.setattr(runtime_verifier, "_artifact_rows", artifact_rows)
    documents = runtime_verifier._PrimaryDocuments(  # type: ignore[attr-defined]
        workload=load_workload(evidence.root / "workload.json"),
        candidate=evidence.candidate_report,
        raw_inventory=evidence.raw_inventory,
        manifest_inventory=evidence.manifest_inventory,
    )
    database = runtime_verifier._ScratchDatabase.open(  # type: ignore[attr-defined]
        evidence.state_root
    )
    try:
        runtime_verifier._validate_trace(  # type: ignore[attr-defined]
            evidence.root,
            evidence.run_index,
            evidence.candidate_report,
            evidence.plan,
            database,
        )
        samples = runtime_verifier._validate_sample_artifacts(  # type: ignore[attr-defined]
            evidence.root,
            evidence.run_index,
            documents,
            database,
        )
    finally:
        database.close()
        database.cleanup()

    assert samples.resource_summary.sample_max_gap_ns > 2_000_000_000
    assert samples.storage_health_summary.sample_max_gap_ns > 2_000_000_000


def test_functional_raw_validation_accepts_recorded_manifest_slo_breach(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    entry = evidence.manifest_inventory.manifests[0]
    manifest_path = evidence.data_root / entry.manifest.relative_path
    manifest = load_raw_manifest(manifest_path).manifest
    changed = RawManifestV1.model_validate(
        {
            **manifest.model_dump(mode="python"),
            "slo_breach_count": 1,
        }
    )
    source = changed.canonical_bytes()
    manifest_path.write_bytes(source)
    changed_entry = GateManifestInventoryEntryV1(
        ordinal=entry.ordinal,
        manifest=GateEvidenceDocumentRefV1(
            relative_path=entry.manifest.relative_path,
            content_size_bytes=len(source),
            content_sha256=hashlib.sha256(source).hexdigest(),
        ),
        data=entry.data,
        manifest_record_count=entry.manifest_record_count,
    )
    entries = list(evidence.manifest_inventory.manifests)
    entries[0] = changed_entry
    inventory_unsigned = evidence.manifest_inventory.model_dump(
        mode="json", exclude={"sha256"}
    )
    inventory_unsigned["manifests"] = [item.model_dump(mode="json") for item in entries]
    manifest_inventory = _self_hashed(
        GateManifestInventoryV1,
        inventory_unsigned,
    )
    documents = runtime_verifier._PrimaryDocuments(  # type: ignore[attr-defined]
        workload=load_workload(evidence.root / "workload.json"),
        candidate=evidence.candidate_report,
        raw_inventory=evidence.raw_inventory,
        manifest_inventory=manifest_inventory,
    )
    database = runtime_verifier._ScratchDatabase.open(  # type: ignore[attr-defined]
        evidence.state_root
    )
    try:
        runtime_verifier._validate_trace(  # type: ignore[attr-defined]
            evidence.root,
            evidence.run_index,
            evidence.candidate_report,
            evidence.plan,
            database,
        )
        validated = runtime_verifier._validate_raw_evidence(  # type: ignore[attr-defined]
            evidence.data_root,
            documents,
            database,
            evidence.plan,
        )
    finally:
        database.close()
        database.cleanup()

    assert validated.durable_record_count == evidence.plan.expected_record_count


def _artifact(path: str, *, rows: int = 1) -> GateArtifactRefV1:
    return GateArtifactRefV1(
        relative_path=path,
        row_count=rows,
        content_size_bytes=100 * rows,
        content_sha256=_SHA_A,
        compressed_size_bytes=50 * rows,
        compressed_sha256=_SHA_B,
    )


def _document(path: str, *, sha256: str = _SHA_A) -> GateEvidenceDocumentRefV1:
    return GateEvidenceDocumentRefV1(
        relative_path=path,
        content_size_bytes=100,
        content_sha256=sha256,
    )


def _raw_inventory() -> GateRawInventoryV1:
    raw = _artifact("raw/binance/spot/x/trade/2026/08/02/00/part-1-0.jsonl.zst")
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_raw_inventory_v1",
        "raw_files": [raw.model_dump(mode="json")],
        "file_count": 1,
        "record_count": 1,
        "content_size_bytes": 100,
        "compressed_size_bytes": 50,
    }
    return _self_hashed(GateRawInventoryV1, unsigned)


def _manifest_inventory() -> GateManifestInventoryV1:
    data = _artifact("raw/binance/spot/x/trade/2026/08/02/00/part-1-0.jsonl.zst")
    entry = GateManifestInventoryEntryV1(
        ordinal=0,
        manifest=_document(
            "raw/binance/spot/x/trade/2026/08/02/00/part-1-0.manifest.json"
        ),
        data=data,
        manifest_record_count=1,
    )
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_manifest_inventory_v1",
        "manifests": [entry.model_dump(mode="json")],
        "file_count": 1,
        "record_count": 1,
        "manifest_content_size_bytes": 100,
    }
    return _self_hashed(GateManifestInventoryV1, unsigned)


def _worker_aggregate(
    *, record_count: int = 8, active_generation_count_peak: int = 8
) -> FinalWorkerAggregateV1:
    buckets = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    buckets[0] = record_count
    return FinalWorkerAggregateV1(
        worker_count=5,
        sampling_round_count=2,
        final_round_index=1,
        accepted_record_count=record_count,
        durable_record_count=record_count,
        unpersisted_record_count=0,
        uncertain_record_count=0,
        enqueue_high_water_count=0,
        normal_overflow_count=0,
        control_overflow_count=0,
        not_accepting_count=0,
        durability_histogram_schema_version=1,
        durability_bucket_counts=tuple(buckets),
        durability_sample_count=record_count,
        durability_lag_p50_ns=DURABILITY_BUCKET_UPPER_BOUNDS_NS[0],
        durability_lag_p95_ns=DURABILITY_BUCKET_UPPER_BOUNDS_NS[0],
        durability_lag_p99_ns=DURABILITY_BUCKET_UPPER_BOUNDS_NS[0],
        durability_lag_max_ns=DURABILITY_BUCKET_UPPER_BOUNDS_NS[0],
        sync_count=5,
        sync_duration_total_ns=5,
        sync_duration_max_ns=1,
        slo_breach_count=0,
        write_failure_count=0,
        sync_failure_count=0,
        publication_failure_count=0,
        unpersisted_record_count_peak=0,
        queued_records_peak=0,
        queued_bytes_peak=0,
        buffered_records_peak=0,
        buffered_bytes_peak=0,
        in_flight_records_peak=0,
        in_flight_bytes_peak=0,
        resident_record_bytes_peak=0,
        resident_control_records_peak=0,
        resident_control_bytes_peak=0,
        oldest_unpersisted_age_max_ns=None,
        active_logical_generation_count_peak=active_generation_count_peak,
        retiring_generation_count_peak=0,
        open_file_descriptor_count_peak=8,
        sync_inflight_peak=1,
    )


def _resource_summary(*, qualification: bool = False) -> GateResourceSummaryV1:
    duration_ns = 600_000_000_000 if qualification else 10_000_000_000
    round_count = 601 if qualification else 2
    post_warmup_count = 481 if qualification else 2
    return GateResourceSummaryV1(
        process_count=6,
        round_count=round_count,
        post_warmup_round_count=post_warmup_count,
        warmup_ended_monotonic_ns=(121_000_000_000 if qualification else 1_000_000_000),
        resource_trend_valid=True,
        first_request_monotonic_ns=1_000_000_000,
        final_completion_monotonic_ns=1_000_000_000 + duration_ns,
        coverage_ns=duration_ns,
        sample_max_gap_ns=1_000_000_000,
        rss_peak_bytes=1024,
        rss_slope_bytes_per_minute=Decimal(0),
        open_fds_peak=12,
        first_open_fds_after_warmup=12,
        max_open_fds_after_warmup=12,
        final_open_fds_after_warmup=12,
        fd_growth_after_warmup=0,
    )


def _health_summary(*, qualification: bool = False) -> GateStorageHealthSummaryV1:
    duration_ns = 600_000_000_000 if qualification else 10_000_000_000
    sample_count = 599 if qualification else 9
    required_coverage_ns = duration_ns - 2_000_000_000
    return GateStorageHealthSummaryV1(
        duration_ns=duration_ns,
        interval_ns=1_000_000_000,
        sample_count=sample_count,
        expected_min_sample_count=sample_count,
        first_request_monotonic_ns=1_000_000_000,
        final_completion_monotonic_ns=1_000_000_000 + required_coverage_ns,
        coverage_ns=required_coverage_ns,
        required_coverage_ns=required_coverage_ns,
        sample_max_gap_ns=1_000_000_000,
        minimum_data_available_bytes=300 * 1024**3,
        minimum_state_available_bytes=300 * 1024**3,
        minimum_available_bytes_if_shared=300 * 1024**3,
        critical_worker_observation_count=0,
        sample_count_valid=True,
        coverage_valid=True,
        workers_healthy=True,
    )


def _stream_summary(name: StreamGroup) -> GateStreamRuntimeSummaryV1:
    return GateStreamRuntimeSummaryV1(
        stream_group=name,
        expected_record_count=1,
        expected_payload_bytes=100,
        scheduled_record_count=1,
        scheduled_payload_bytes=100,
        attempted_record_count=1,
        attempted_payload_bytes=100,
        accepted_record_count=1,
        accepted_payload_bytes=100,
        early_count=0,
        late_count=0,
        out_of_window_count=0,
        required_burst_count=2,
        scheduled_burst_count=1,
        burst_second=0,
        burst_scheduled_count=1,
        burst_attempted_count=1,
        burst_accepted_count=1,
        burst_admitted_in_actual_second_count=1,
        planned_values_match=True,
        admission_values_match=True,
        burst_valid=True,
    )


_QUALIFICATION_STREAM_FACTS: tuple[tuple[StreamGroup, int, int, int, int], ...] = (
    ("trade", 15_000_000, 20_106_023_944, 250_000, 86),
    ("book_live", 6_000_000, 191_396_044_800, 50_000, 217),
    ("ticker", 300_000, 625_200_128, 2_500, 81),
    ("bbo", 3_000_000, 2_716_712_456, 25_000, 268),
    ("derivative", 600_000, 1_722_086_680, 5_000, 223),
    ("candle_1m", 150_000, 240_781_744, 1_000, 488),
    ("book_deep_snapshot", 10_020, 2_356_805_632, 500, 596),
    ("control", 600, 987_600, 100, 225),
)


def _qualification_stream_summary(
    name: StreamGroup,
    record_count: int,
    payload_bytes: int,
    burst_count: int,
    burst_second: int,
) -> GateStreamRuntimeSummaryV1:
    return GateStreamRuntimeSummaryV1(
        stream_group=name,
        expected_record_count=record_count,
        expected_payload_bytes=payload_bytes,
        scheduled_record_count=record_count,
        scheduled_payload_bytes=payload_bytes,
        attempted_record_count=record_count,
        attempted_payload_bytes=payload_bytes,
        accepted_record_count=record_count,
        accepted_payload_bytes=payload_bytes,
        early_count=0,
        late_count=0,
        out_of_window_count=0,
        required_burst_count=burst_count,
        scheduled_burst_count=burst_count,
        burst_second=burst_second,
        burst_scheduled_count=burst_count,
        burst_attempted_count=burst_count,
        burst_accepted_count=burst_count,
        burst_admitted_in_actual_second_count=burst_count,
        planned_values_match=True,
        admission_values_match=True,
        burst_valid=True,
    )


def _runtime_summary() -> GateRuntimeSummaryV1:
    streams = tuple(_stream_summary(name) for name in _STREAMS)
    return GateRuntimeSummaryV1(
        expected_record_count=8,
        expected_payload_bytes=800,
        scheduled_record_count=8,
        scheduled_payload_bytes=800,
        attempted_record_count=8,
        attempted_payload_bytes=800,
        accepted_record_count=8,
        accepted_payload_bytes=800,
        durable_record_count=8,
        durable_payload_bytes=800,
        durability_sample_count=8,
        manifest_record_count=8,
        raw_file_count=8,
        manifest_file_count=8,
        declared_file_identity_count=8,
        expected_touched_file_identity_count=8,
        observed_touched_file_identity_count=8,
        accepted_identity_count=8,
        unique_accepted_identity_count=8,
        early_count=0,
        late_count=0,
        out_of_window_count=0,
        received_utc_hours=("2026/08/02/00",),
        stream_summaries=streams,
        final_worker_aggregate=_worker_aggregate(),
        resource_summary=_resource_summary(),
        storage_health_summary=_health_summary(),
    )


def _qualification_runtime_summary() -> GateRuntimeSummaryV1:
    streams = tuple(
        _qualification_stream_summary(*facts) for facts in _QUALIFICATION_STREAM_FACTS
    )
    record_count = 25_060_620
    payload_bytes = 219_164_642_984
    return GateRuntimeSummaryV1(
        expected_record_count=record_count,
        expected_payload_bytes=payload_bytes,
        scheduled_record_count=record_count,
        scheduled_payload_bytes=payload_bytes,
        attempted_record_count=record_count,
        attempted_payload_bytes=payload_bytes,
        accepted_record_count=record_count,
        accepted_payload_bytes=payload_bytes,
        durable_record_count=record_count,
        durable_payload_bytes=payload_bytes,
        durability_sample_count=record_count,
        manifest_record_count=record_count,
        raw_file_count=3_505,
        manifest_file_count=3_505,
        declared_file_identity_count=3_505,
        expected_touched_file_identity_count=3_505,
        observed_touched_file_identity_count=3_505,
        accepted_identity_count=record_count,
        unique_accepted_identity_count=record_count,
        early_count=0,
        late_count=0,
        out_of_window_count=0,
        received_utc_hours=("2027/01/15/08",),
        stream_summaries=streams,
        final_worker_aggregate=_worker_aggregate(
            record_count=record_count,
            active_generation_count_peak=3_505,
        ),
        resource_summary=_resource_summary(qualification=True),
        storage_health_summary=_health_summary(qualification=True),
    )


def _candidate(*, mode: str = "functional") -> GateCandidateReportV1:
    qualification = mode == "qualification"
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_candidate_report_v1",
        "run_id": _RUN_ID,
        "mode": mode,
        "workload_sha256": _SHA_A,
        "workload_plan_sha256": _SHA_B,
        "multiplier": 2 if qualification else 1,
        "duration_ns": 600_000_000_000 if qualification else 10_000_000_000,
        "run_started_monotonic_ns": 0,
        "admission_started_monotonic_ns": 1_000_000_000,
        "admission_scheduled_end_monotonic_ns": (
            601_000_000_000 if qualification else 11_000_000_000
        ),
        "admission_ended_monotonic_ns": (
            601_000_000_000 if qualification else 11_000_000_000
        ),
        "run_ended_monotonic_ns": (
            602_000_000_000 if qualification else 12_000_000_000
        ),
        "admission_started_utc_ns": 1_800_000_000_000_000_000,
        "admission_ended_utc_ns": (
            1_800_000_600_000_000_000 if qualification else 1_800_000_010_000_000_000
        ),
        "declared_admission_utc_hour": "2027/01/15/08",
        "expected_target_id": "target-a" if qualification else None,
        "target_declaration_sha256": _SHA_A if qualification else None,
        "expected_image_id": f"sha256:{_SHA_A}" if qualification else None,
        "runtime_image_id": f"sha256:{_SHA_A}" if qualification else None,
        "runtime_summary": _runtime_summary().model_dump(mode="json"),
        "runtime_failure_codes": [],
        "candidate_runtime_passed": True,
    }
    return _self_hashed(GateCandidateReportV1, unsigned)


def _trace_set() -> GateAdmissionTraceSetV1:
    partitions = tuple(
        GateExchangeArtifactPartitionV1(
            exchange=exchange,
            artifact=_artifact(f"trace/{exchange.value}.jsonl.zst"),
        )
        for exchange in CANONICAL_EXCHANGES
    )
    return GateAdmissionTraceSetV1(
        partitions=partitions,
        merged_row_count=5,
        merged_content_size_bytes=500,
        merged_content_sha256=_SHA_A,
    )


def _run_index(*, mode: str = "functional") -> GateRunIndexV1:
    qualification = mode == "qualification"
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_run_index_v1",
        "run_id": _RUN_ID,
        "status": "complete",
        "mode": mode,
        "artifact_schema_version": 1,
        "identity_algorithm": "gate-identity-v1",
        "event_algorithm": "gate-event-v1",
        "payload_algorithm": "gate-payload-v1",
        "schedule_algorithm": "gate-schedule-v2-full-second-burst",
        "data_root": "/var/lib/crypto-collector/data",
        "state_root": "/var/lib/crypto-collector/state",
        "workload_document": _document("workload.yaml").model_dump(mode="json"),
        "workload_sha256": _SHA_A,
        "workload_plan_sha256": _SHA_B,
        "admission_trace_set": _trace_set().model_dump(mode="json"),
        "second_bucket_artifact": _artifact("samples/buckets.jsonl.zst").model_dump(
            mode="json"
        ),
        "worker_sampling_artifact": _artifact("samples/workers.jsonl.zst").model_dump(
            mode="json"
        ),
        "resource_sampling_artifact": _artifact(
            "samples/resources.jsonl.zst"
        ).model_dump(mode="json"),
        "storage_health_artifact": _artifact("samples/health.jsonl.zst").model_dump(
            mode="json"
        ),
        "raw_inventory": _document("raw-inventory.json").model_dump(mode="json"),
        "manifest_inventory": _document("manifest-inventory.json").model_dump(
            mode="json"
        ),
        "candidate_report": _document("candidate-report.json").model_dump(mode="json"),
        "expected_target_id": "target-a" if qualification else None,
        "target_declaration": (
            _document("target-declaration.json").model_dump(mode="json")
            if qualification
            else None
        ),
        "implementation_source_commit": "c" * 40 if qualification else None,
        "collector_wheel_sha256": _SHA_A if qualification else None,
        "requirements_lock_sha256": _SHA_A if qualification else None,
        "dockerfile_sha256": _SHA_A if qualification else None,
        "expected_image_id": f"sha256:{_SHA_A}" if qualification else None,
        "runtime_image_id": f"sha256:{_SHA_A}" if qualification else None,
    }
    return _self_hashed(GateRunIndexV1, unsigned)


def _root_probe(*, root: str, device: str) -> GateRootProbeV1:
    return GateRootProbeV1(
        root=root,
        storage_device=device,
        filesystem="ext4",
        mount_point=root,
        mount_options=("mount:rw", "super:rw"),
        minimum_available_bytes=GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES,
        observed_available_bytes=300 * 1024**3,
        no_replace_capability=NoReplaceCapability.HARDLINK,
        same_parent_publication_only=True,
        file_sync_supported=True,
        directory_sync_supported=True,
    )


def _target_reprobe(*, valid: bool = True) -> GateTargetReprobeV1:
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_target_reprobe_v1",
        "target_id": "target-a" if valid else "target-b",
        "expected_target_id": "target-a",
        "declaration_sha256": _SHA_A,
        "probed_at_unix_ns": 1_800_000_000_000_000_000,
        "data_root": _root_probe(root="/data", device="1:1").model_dump(mode="json"),
        "state_root": _root_probe(root="/state", device="2:2").model_dump(mode="json"),
        "shared_mount": False,
        "shared_required_available_bytes": None,
        "shared_observed_available_bytes": None,
        "target_id_matches": valid,
        "declaration_facts_match": True,
        "available_space_valid": True,
        "reprobe_valid": valid,
    }
    return _self_hashed(GateTargetReprobeV1, unsigned)


def _receipt(*, mode: str = "functional", valid: bool = True) -> GateRuntimeReceiptV1:
    qualification = mode == "qualification"
    failure_codes = [] if valid else ["runtime_predicate_failed"]
    summary = _qualification_runtime_summary() if qualification else _runtime_summary()
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_runtime_receipt_v1",
        "verifier_version": "gate-runtime-verifier-v1",
        "verified_at_unix_ns": 1_800_000_000_000_000_000,
        "run_id": _RUN_ID,
        "mode": mode,
        "run_index_sha256": _SHA_A,
        "run_index_content_sha256": _SHA_B,
        "expected_target_id": "target-a" if qualification else None,
        "recomputed_summary": summary.model_dump(mode="json"),
        "target_reprobe": (
            _target_reprobe().model_dump(mode="json") if qualification else None
        ),
        "failure_codes": failure_codes,
        "evidence_integrity_valid": True,
        "candidate_summary_matches": True,
        "runtime_predicates_passed": valid,
        "runtime_evidence_valid": valid,
        "qualification_runtime_accepted": valid and qualification,
    }
    return _self_hashed(GateRuntimeReceiptV1, unsigned)


def test_task5_contract_field_order_is_frozen() -> None:
    for model_type, fields in _EXPECTED_FIELDS.items():
        assert tuple(model_type.model_fields) == fields


def test_document_and_inventory_contracts_are_canonical() -> None:
    raw = _raw_inventory()
    manifests = _manifest_inventory()

    assert raw.file_count == manifests.file_count == 1
    assert raw.record_count == manifests.record_count == 1
    assert raw.canonical_bytes().endswith(b"\n")
    assert manifests.canonical_bytes().endswith(b"\n")


@pytest.mark.parametrize(
    "path", ["/absolute.json", "../escape.json", "x.txt", "x\\y.json"]
)
def test_document_ref_rejects_unsafe_or_unsupported_path(path: str) -> None:
    with pytest.raises(ValidationError):
        _document(path)


def test_inventory_rejects_wrong_ordinal_sibling_and_totals() -> None:
    manifest = _manifest_inventory()
    values = manifest.model_dump(mode="python")
    entry = values["manifests"][0]

    with pytest.raises(ValidationError, match="ordinal"):
        _rehash(
            GateManifestInventoryV1,
            manifest,
            manifests=[{**entry, "ordinal": 1}],
        )
    with pytest.raises(ValidationError, match="sibling"):
        GateManifestInventoryEntryV1(
            ordinal=0,
            manifest=_document("raw/other.manifest.json"),
            data=entry["data"],
            manifest_record_count=1,
        )
    with pytest.raises(ValidationError, match="total|count"):
        _rehash(GateManifestInventoryV1, manifest, record_count=2)


def test_manifest_inventory_rejects_duplicate_hashes() -> None:
    manifest = _manifest_inventory()
    first = manifest.manifests[0]
    duplicate_hashes = GateManifestInventoryEntryV1(
        ordinal=1,
        manifest=first.manifest.model_copy(
            update={
                "relative_path": "raw/binance/spot/x/trade/2026/08/02/00/part-2-0.manifest.json"
            }
        ),
        data=first.data.model_copy(
            update={
                "relative_path": "raw/binance/spot/x/trade/2026/08/02/00/part-2-0.jsonl.zst"
            }
        ),
        manifest_record_count=1,
    )

    with pytest.raises(ValidationError, match="hashes.*unique"):
        _rehash(
            GateManifestInventoryV1,
            manifest,
            manifests=[
                first.model_dump(mode="json"),
                duplicate_hashes.model_dump(mode="json"),
            ],
            file_count=2,
            record_count=2,
            manifest_content_size_bytes=200,
        )


def test_runtime_summary_recomputes_all_derived_booleans_and_totals() -> None:
    stream = _stream_summary("trade")
    with pytest.raises(ValidationError, match="planned"):
        GateStreamRuntimeSummaryV1.model_validate(
            {**stream.model_dump(mode="python"), "planned_values_match": False}
        )
    summary = _runtime_summary()
    with pytest.raises(ValidationError, match="total|stream"):
        GateRuntimeSummaryV1.model_validate(
            {**summary.model_dump(mode="python"), "accepted_record_count": 7}
        )
    with pytest.raises(ValidationError, match="nonempty"):
        GateRuntimeSummaryV1.model_validate(
            {**summary.model_dump(mode="python"), "received_utc_hours": ()}
        )
    with pytest.raises(ValidationError, match="worker aggregate"):
        GateRuntimeSummaryV1.model_validate(
            {**summary.model_dump(mode="python"), "durable_record_count": 7}
        )


def test_candidate_mode_timing_and_verdict_are_derived() -> None:
    functional = _candidate()
    assert functional.candidate_runtime_passed is True
    with pytest.raises(ValidationError, match="functional"):
        _rehash(GateCandidateReportV1, functional, expected_target_id="target-a")
    with pytest.raises(ValidationError, match="candidate"):
        _rehash(GateCandidateReportV1, functional, candidate_runtime_passed=False)
    with pytest.raises(ValidationError, match="out of range"):
        _rehash(
            GateCandidateReportV1,
            functional,
            admission_started_utc_ns=10**30,
            admission_ended_utc_ns=10**30,
        )


def test_run_index_is_terminal_and_mode_claims_are_exact() -> None:
    functional = _run_index()
    assert functional.status == "complete"
    with pytest.raises(ValidationError):
        GateRunIndexV1.model_validate(
            {**functional.model_dump(mode="python"), "status": "failed"}
        )
    with pytest.raises(ValidationError, match="functional"):
        _rehash(
            GateRunIndexV1,
            functional,
            expected_image_id=f"sha256:{_SHA_A}",
        )
    assert _run_index(mode="qualification").expected_target_id == "target-a"


@pytest.mark.parametrize(
    ("field", "path"),
    [
        ("candidate_report", "run-index.json"),
        ("raw_inventory", "runtime-receipt.json"),
        ("manifest_inventory", "runtime-index.json"),
    ],
)
def test_run_index_rejects_reserved_dag_paths(field: str, path: str) -> None:
    run_index = _run_index()

    with pytest.raises(ValidationError, match="reserved"):
        _rehash(
            GateRunIndexV1,
            run_index,
            **{field: _document(path).model_dump(mode="json")},
        )


def test_receipt_truth_table_never_qualifies_functional_evidence() -> None:
    passing = _receipt()
    failing = _receipt(valid=False)

    assert passing.runtime_evidence_valid is True
    assert passing.qualification_runtime_accepted is False
    assert failing.runtime_evidence_valid is False
    with pytest.raises(ValidationError, match="runtime evidence"):
        _rehash(GateRuntimeReceiptV1, passing, runtime_evidence_valid=False)
    with pytest.raises(ValidationError, match="recomputation"):
        _rehash(
            GateRuntimeReceiptV1,
            passing,
            recomputed_summary=None,
            candidate_summary_matches=False,
            failure_codes=["runtime_recomputation_missing"],
            runtime_evidence_valid=False,
        )


def test_receipt_truth_table_accepts_only_valid_qualification_evidence() -> None:
    passing = _receipt(mode="qualification")
    failing = _receipt(mode="qualification", valid=False)

    assert passing.recomputed_summary is not None
    assert passing.recomputed_summary.expected_record_count == 25_060_620
    assert passing.recomputed_summary.expected_payload_bytes == 219_164_642_984
    assert passing.recomputed_summary.expected_touched_file_identity_count == 3_505
    assert (
        passing.recomputed_summary.storage_health_summary.duration_ns == 600_000_000_000
    )
    assert passing.runtime_evidence_valid is True
    assert passing.qualification_runtime_accepted is True
    assert failing.runtime_evidence_valid is False
    assert failing.qualification_runtime_accepted is False

    structural_rejection = _rehash(
        GateRuntimeReceiptV1,
        passing,
        recomputed_summary=None,
        target_reprobe=None,
        failure_codes=["target_evidence_invalid"],
        evidence_integrity_valid=False,
        candidate_summary_matches=False,
        runtime_predicates_passed=False,
        runtime_evidence_valid=False,
        qualification_runtime_accepted=False,
    )
    assert structural_rejection.target_reprobe is None
    assert structural_rejection.runtime_evidence_valid is False

    invalid_cases = (
        {"evidence_integrity_valid": False},
        {"candidate_summary_matches": False},
        {"runtime_predicates_passed": False},
        {"target_reprobe": _target_reprobe(valid=False).model_dump(mode="json")},
    )
    for updates in invalid_cases:
        rejected = _rehash(
            GateRuntimeReceiptV1,
            passing,
            **updates,
            failure_codes=["qualification_fact_invalid"],
            runtime_evidence_valid=False,
            qualification_runtime_accepted=False,
        )
        assert rejected.runtime_evidence_valid is False
        assert rejected.qualification_runtime_accepted is False


def test_runtime_index_binds_complete_document_refs() -> None:
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_runtime_index_v1",
        "run_id": _RUN_ID,
        "status": "complete",
        "mode": "functional",
        "run_index": _document("run-index.json").model_dump(mode="json"),
        "runtime_receipt": _document("runtime-receipt.json").model_dump(mode="json"),
    }
    index = _self_hashed(GateRuntimeIndexV1, unsigned)

    assert index.status == "complete"
    with pytest.raises(ValidationError, match="SHA-256"):
        GateRuntimeIndexV1.model_validate(
            {**index.model_dump(mode="python"), "mode": "qualification"}
        )


def _write_qualification_entrypoint(
    evidence: Any,
    *,
    declaration_target_id: str,
    expected_target_id: str,
) -> None:
    target_unsigned = {
        "schema_version": 1,
        "record_type": "gate_target_v1",
        "target_id": declaration_target_id,
        "data_root": _root_probe(
            root=evidence.data_root.as_posix(),
            device="1:1",
        ).model_dump(mode="json"),
        "state_root": _root_probe(
            root=evidence.state_root.as_posix(),
            device="2:2",
        ).model_dump(mode="json"),
        "deployment_purpose": "raw-writer-gate-b",
        "created_at_unix_ns": 1_800_000_000_000_000_000,
    }
    target = _self_hashed(GateTargetV1, target_unsigned)
    target_path = evidence.root / "target-declaration.json"
    target_path.write_bytes(target.canonical_bytes())
    target_source = target_path.read_bytes()
    target_ref = GateEvidenceDocumentRefV1(
        relative_path=target_path.name,
        content_size_bytes=len(target_source),
        content_sha256=hashlib.sha256(target_source).hexdigest(),
    )
    qualification = _rehash(
        GateRunIndexV1,
        evidence.run_index,
        mode="qualification",
        expected_target_id=expected_target_id,
        target_declaration=target_ref.model_dump(mode="json"),
        implementation_source_commit="c" * 40,
        collector_wheel_sha256=_SHA_A,
        requirements_lock_sha256=_SHA_A,
        dockerfile_sha256=_SHA_A,
        expected_image_id=f"sha256:{_SHA_A}",
        runtime_image_id=f"sha256:{_SHA_A}",
    )
    evidence.run_index_path.write_bytes(qualification.canonical_bytes())


def test_qualification_target_mismatch_publishes_structural_rejection(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    _write_qualification_entrypoint(
        evidence,
        declaration_target_id="declared-target",
        expected_target_id="different-target",
    )

    def probe_should_not_run(
        declaration: GateTargetV1,
        *,
        expected_target_id: str,
    ) -> GateTargetReprobeV1:
        pytest.fail("a mismatched declaration must fail before the live probe")

    receipt = validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=probe_should_not_run,
    )

    assert receipt.mode == "qualification"
    assert receipt.target_reprobe is None
    assert receipt.failure_codes == ("target_evidence_invalid",)
    assert receipt.runtime_evidence_valid is False
    assert receipt.qualification_runtime_accepted is False
    assert (evidence.root / "runtime-receipt.json").is_file()
    assert (evidence.root / "runtime-index.json").is_file()


def test_qualification_probe_wrong_type_publishes_structural_rejection(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    _write_qualification_entrypoint(
        evidence,
        declaration_target_id="declared-target",
        expected_target_id="declared-target",
    )

    def invalid_probe(
        declaration: GateTargetV1,
        *,
        expected_target_id: str,
    ) -> Any:
        return True

    receipt = validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=invalid_probe,
    )

    assert receipt.target_reprobe is None
    assert receipt.failure_codes == ("target_evidence_invalid",)
    assert receipt.runtime_evidence_valid is False


def test_qualification_probe_wrong_binding_publishes_structural_rejection(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    _write_qualification_entrypoint(
        evidence,
        declaration_target_id="declared-target",
        expected_target_id="declared-target",
    )

    def foreign_probe(
        declaration: GateTargetV1,
        *,
        expected_target_id: str,
    ) -> GateTargetReprobeV1:
        return _target_reprobe()

    receipt = validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=foreign_probe,
    )

    assert receipt.target_reprobe is None
    assert receipt.failure_codes == ("target_evidence_invalid",)
    assert receipt.runtime_evidence_valid is False
