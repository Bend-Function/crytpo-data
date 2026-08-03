from __future__ import annotations

import hashlib
import json
import os
import resource
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TypedDict, cast
from unittest.mock import patch

import pytest

from crypto_collector.benchmarks import runtime_verifier
from crypto_collector.benchmarks.artifacts import (
    build_admission_trace_set,
    write_jsonl_zstd,
)
from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    FinalWorkerAggregateV1,
    GateAcceptanceReceiptV1,
    GateAdmissionTraceSetV1,
    GateAdmissionTraceV1,
    GateArchiveAttestationV1,
    GateArtifactRefV1,
    GateBuildProvenanceV1,
    GateEvidenceDisclosureV1,
    GateExchangeArtifactPartitionV1,
    GateFileInventoryV1,
    GateProvenanceReceiptV1,
    GateResourceSummaryV1,
    GateRootProbeV1,
    GateStorageHealthSummaryV1,
    GateTargetReprobeV1,
    GateTargetV1,
)
from crypto_collector.benchmarks.oracle import PlannedEventV1, build_workload_plan
from crypto_collector.benchmarks.workload import load_workload
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.storage.models import AcceptedRecordIdentityV1, EnqueueStatus

WORKLOAD_PATH = Path("benchmarks/workloads/research-default-v1.yaml")
GOLDEN_PATH = Path("benchmarks/workloads/research-default-v1.golden.json")
TRACE_STREAM_SHORT_ROW_COUNT = 10_000
TRACE_STREAM_FULL_ROW_COUNT = 1_000_000
TRACE_STREAM_RSS_LIMIT_BYTES = 256 * 1024 * 1024
TRACE_STREAM_MAX_LINE_BYTES = 4_096
QUALIFICATION_RECORD_COUNT = 25_060_620
QUALIFICATION_SCRATCH_BUDGET_BYTES = 64 * 1024**3
QUALIFICATION_SCRATCH_HEADROOM_FACTOR = 4


class TraceStreamProbeResult(TypedDict):
    partition_count: int
    partition_row_counts: list[int]
    merged_row_count: int
    merged_content_size_bytes: int
    merged_content_sha256: str
    verifier_accepted_record_count: int
    verifier_durable_record_count: int
    scratch_database_bytes: int
    projected_qualification_scratch_bytes: int
    reserved_qualification_scratch_bytes: int
    peak_rss_bytes: int


def _synthetic_payload(
    *,
    planned_event_id: str,
    canonical_identity: str,
    local_sequence: int,
) -> bytes:
    payload: dict[str, object] = {
        "algorithm": "gate-payload-v1",
        "event_id": planned_event_id,
        "stream": "trade",
        "identity": canonical_identity,
        "local_sequence": local_sequence,
        "value": 0,
        "padding": "",
    }
    target_size = 512
    unpadded = encode_json(payload)
    padding_size = target_size - len(unpadded)
    if padding_size < 0:
        raise ValueError("synthetic payload target is too small")
    payload["padding"] = "x" * padding_size
    encoded = encode_json(payload)
    if len(encoded) != target_size:
        raise AssertionError("synthetic payload padding is not exact")
    return encoded


def _synthetic_event(
    global_ordinal: int,
) -> PlannedEventV1:
    exchange_index = global_ordinal % len(CANONICAL_EXCHANGES)
    exchange = CANONICAL_EXCHANGES[exchange_index]
    local_sequence = global_ordinal // len(CANONICAL_EXCHANGES)
    instrument = f"GATE-{exchange.value.upper()}-SPOT-L0000-S0000"
    identity = f"gate-identity-v1:{exchange.value}:spot:{instrument}:trade"
    planned_event_id = f"{global_ordinal + 1:064x}"
    payload = _synthetic_payload(
        planned_event_id=planned_event_id,
        canonical_identity=identity,
        local_sequence=local_sequence,
    )
    return PlannedEventV1(
        identity_algorithm="gate-identity-v1",
        event_algorithm="gate-event-v1",
        payload_algorithm="gate-payload-v1",
        schedule_algorithm="gate-schedule-v2-full-second-burst",
        planned_event_id=planned_event_id,
        stream_group="trade",
        logical_stream="trade",
        exchange=exchange,
        market=Market.SPOT,
        lane_index=0,
        symbol_index=0,
        instrument_key=instrument,
        canonical_identity=identity,
        identity_index=exchange_index,
        local_sequence=local_sequence,
        transport=Transport.WEBSOCKET,
        due_offset_ns=global_ordinal,
        deadline_offset_ns=global_ordinal + 1_000_000_000,
        payload_bytes=len(payload),
        payload_sha256=hashlib.sha256(payload).hexdigest(),
        payload_canonical_bytes=payload,
    )


def _synthetic_plan_events(row_count: int) -> Iterator[PlannedEventV1]:
    for global_ordinal in range(row_count):
        yield _synthetic_event(global_ordinal)


def _synthetic_trace_rows(
    exchange: Exchange,
    exchange_index: int,
    rows_per_partition: int,
) -> Iterator[GateAdmissionTraceV1]:
    instrument = f"GATE-{exchange.value.upper()}-SPOT-L0000-S0000"
    worker_instance_id = f"gate-worker-v1-{exchange.value}"
    exchange_count = len(CANONICAL_EXCHANGES)
    for local_sequence in range(rows_per_partition):
        global_ordinal = local_sequence * exchange_count + exchange_index
        event = _synthetic_event(global_ordinal)
        due_monotonic_ns = 1_000_000_000 + event.due_offset_ns
        yield GateAdmissionTraceV1(
            planned_event_id=event.planned_event_id,
            stream_group="trade",
            logical_stream="trade",
            exchange=exchange,
            market=Market.SPOT,
            instrument_key=instrument,
            canonical_identity=(
                f"gate-identity-v1:{exchange.value}:spot:{instrument}:trade"
            ),
            identity_index=event.identity_index,
            local_sequence=local_sequence,
            due_monotonic_ns=due_monotonic_ns,
            deadline_monotonic_ns=due_monotonic_ns + 1_000_000_000,
            attempt_started_monotonic_ns=due_monotonic_ns,
            admission_completed_monotonic_ns=due_monotonic_ns + 1,
            enqueue_status=EnqueueStatus.ACCEPTED,
            payload_bytes=event.payload_bytes,
            payload_sha256=event.payload_sha256,
            accepted_identity=AcceptedRecordIdentityV1(
                exchange=exchange,
                market=Market.SPOT,
                instrument_key=instrument,
                logical_stream="trade",
                worker_instance_id=worker_instance_id,
                writer_sequence=local_sequence,
                acceptance_ordinal=local_sequence,
                config_sha256="a" * 64,
                config_generation=0,
            ),
        )


def _peak_rss_bytes() -> int:
    peak_rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak_rss if sys.platform == "darwin" else peak_rss * 1_024


def _build_trace_streaming_probe(root: Path, row_count: int) -> TraceStreamProbeResult:
    exchange_count = len(CANONICAL_EXCHANGES)
    if row_count <= 0 or row_count % exchange_count != 0:
        raise ValueError("trace probe row count must be positive and divisible by five")
    rows_per_partition = row_count // exchange_count
    root.mkdir(parents=True)

    partitions = tuple(
        GateExchangeArtifactPartitionV1(
            exchange=exchange,
            artifact=write_jsonl_zstd(
                root,
                f"traces/{exchange.value}.jsonl.zst",
                _synthetic_trace_rows(exchange, exchange_index, rows_per_partition),
                zstd_level=3,
            ),
        )
        for exchange_index, exchange in enumerate(CANONICAL_EXCHANGES)
    )
    max_content_bytes = sum(
        partition.artifact.content_size_bytes for partition in partitions
    )
    trace_set = build_admission_trace_set(
        root,
        partitions,
        max_rows=row_count,
        max_content_bytes=max_content_bytes,
        max_line_bytes=TRACE_STREAM_MAX_LINE_BYTES,
    )
    state_root = root / "state"
    state_root.mkdir()
    database = runtime_verifier._ScratchDatabase.open(state_root)
    plan_sha256 = "b" * 64
    plan = SimpleNamespace(
        workload_plan_sha256=plan_sha256,
        expected_record_count=row_count,
        duration_seconds=10,
    )
    run_index = SimpleNamespace(
        workload_plan_sha256=plan_sha256,
        admission_trace_set=trace_set,
    )
    candidate = SimpleNamespace(
        admission_started_monotonic_ns=1_000_000_000,
        admission_scheduled_end_monotonic_ns=11_000_000_000,
        admission_ended_monotonic_ns=11_000_000_000,
        admission_started_utc_ns=1_800_000_000_000_000_000,
        admission_ended_utc_ns=1_800_000_010_000_000_000,
    )
    scratch_database_bytes = 0
    durable_record_count = 0
    try:
        with patch.object(
            runtime_verifier,
            "iter_plan_events",
            lambda _plan: _synthetic_plan_events(row_count),
        ):
            validation = runtime_verifier._validate_trace(
                root,
                cast(Any, run_index),
                cast(Any, candidate),
                cast(Any, plan),
                database,
            )
        database.connection.execute(
            """
            INSERT INTO durable
            SELECT route_id, acceptance_ordinal, route_id, writer_sequence
            FROM accepted
            """
        )
        database.connection.commit()
        durable_row = database.connection.execute(
            "SELECT COUNT(*) FROM durable"
        ).fetchone()
        assert durable_row is not None
        durable_record_count = int(durable_row[0])
        runtime_verifier._validate_complete_durable_set(
            database,
            expected_record_count=row_count,
        )
        runtime_verifier._finish_scratch_database(database)
        scratch_database_bytes = sum(
            path.stat().st_size
            for path in (
                database.path,
                Path(f"{database.path}-wal"),
                Path(f"{database.path}-shm"),
            )
            if path.exists()
        )
    except BaseException:
        database.close()
        raise
    finally:
        database.cleanup()
    projected_scratch_bytes = (
        scratch_database_bytes * QUALIFICATION_RECORD_COUNT + row_count - 1
    ) // row_count
    return TraceStreamProbeResult(
        partition_count=len(partitions),
        partition_row_counts=[partition.artifact.row_count for partition in partitions],
        merged_row_count=trace_set.merged_row_count,
        merged_content_size_bytes=trace_set.merged_content_size_bytes,
        merged_content_sha256=trace_set.merged_content_sha256,
        verifier_accepted_record_count=validation.accepted_record_count,
        verifier_durable_record_count=durable_record_count,
        scratch_database_bytes=scratch_database_bytes,
        projected_qualification_scratch_bytes=projected_scratch_bytes,
        reserved_qualification_scratch_bytes=(
            projected_scratch_bytes * QUALIFICATION_SCRATCH_HEADROOM_FACTOR
        ),
        peak_rss_bytes=_peak_rss_bytes(),
    )


def _run_trace_streaming_probe(root: Path, row_count: int) -> TraceStreamProbeResult:
    timeout_seconds = 900 if row_count == TRACE_STREAM_FULL_ROW_COUNT else 120
    completed = subprocess.run(
        (
            sys.executable,
            str(Path(__file__).resolve()),
            "--trace-stream-probe",
            str(root),
            str(row_count),
        ),
        check=False,
        capture_output=True,
        timeout=timeout_seconds,
    )
    if completed.returncode != 0:
        raise AssertionError(
            "trace streaming probe failed:\n"
            + completed.stderr.decode("utf-8", errors="replace")
        )
    decoded = decode_json(completed.stdout)
    if not isinstance(decoded, dict):
        raise TypeError("trace streaming probe did not return a JSON object")
    return cast(TraceStreamProbeResult, decoded)


def _trace_stream_probe_main(arguments: list[str]) -> int:
    if len(arguments) != 3 or arguments[0] != "--trace-stream-probe":
        raise ValueError("invalid trace streaming probe arguments")
    result = _build_trace_streaming_probe(Path(arguments[1]), int(arguments[2]))
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
    return 0


def test_writer_gate_foundational_artifact_surface_is_frozen() -> None:
    assert tuple(GateArtifactRefV1.model_fields)[:3] == (
        "schema_version",
        "record_type",
        "relative_path",
    )
    assert "planned_event_id" in GateAdmissionTraceV1.model_fields
    assert tuple(GateAdmissionTraceSetV1.model_fields)[-3:] == (
        "merged_row_count",
        "merged_content_size_bytes",
        "merged_content_sha256",
    )


def test_writer_gate_aggregation_surface_is_frozen() -> None:
    assert tuple(FinalWorkerAggregateV1.model_fields)[:5] == (
        "schema_version",
        "record_type",
        "worker_count",
        "sampling_round_count",
        "final_round_index",
    )


def test_writer_gate_target_surface_is_frozen() -> None:
    assert tuple(GateRootProbeV1.model_fields)[-5:] == (
        "observed_available_bytes",
        "no_replace_capability",
        "same_parent_publication_only",
        "file_sync_supported",
        "directory_sync_supported",
    )
    assert tuple(GateTargetV1.model_fields)[-2:] == (
        "created_at_unix_ns",
        "sha256",
    )
    assert tuple(GateTargetReprobeV1.model_fields)[-5:] == (
        "target_id_matches",
        "declaration_facts_match",
        "available_space_valid",
        "reprobe_valid",
        "sha256",
    )
    assert tuple(GateResourceSummaryV1.model_fields)[-4:] == (
        "first_open_fds_after_warmup",
        "max_open_fds_after_warmup",
        "final_open_fds_after_warmup",
        "fd_growth_after_warmup",
    )
    assert tuple(GateStorageHealthSummaryV1.model_fields)[-3:] == (
        "sample_count_valid",
        "coverage_valid",
        "workers_healthy",
    )


def test_writer_gate_provenance_surface_is_frozen() -> None:
    assert tuple(GateFileInventoryV1.model_fields)[:4] == (
        "schema_version",
        "record_type",
        "root",
        "relative_path",
    )
    assert tuple(GateArchiveAttestationV1.model_fields)[-3:] == (
        "immutable",
        "webdav_backup_verified",
        "sha256",
    )
    assert tuple(GateBuildProvenanceV1.model_fields)[-4:] == (
        "provenance_enabled",
        "sbom_enabled",
        "runtime_user",
        "sha256",
    )
    assert tuple(GateProvenanceReceiptV1.model_fields)[-2:] == (
        "provenance_valid",
        "sha256",
    )
    assert tuple(GateAcceptanceReceiptV1.model_fields)[-2:] == (
        "qualification_accepted",
        "sha256",
    )
    assert tuple(GateEvidenceDisclosureV1.model_fields)[-2:] == (
        "qualification_accepted",
        "sha256",
    )


def test_research_default_workload_has_exact_multiplier_two_cardinalities() -> None:
    workload = load_workload(WORKLOAD_PATH)
    functional = build_workload_plan(
        workload,
        multiplier=2,
        duration_ns=10_000_000_000,
    )
    qualification = build_workload_plan(
        workload,
        multiplier=2,
        duration_ns=600_000_000_000,
    )

    assert (
        functional.expected_record_count,
        functional.expected_touched_file_identity_count,
        functional.declared_file_identity_count,
    ) == (417_677, 3_172, 3_505)
    assert (
        qualification.expected_record_count,
        qualification.expected_touched_file_identity_count,
        qualification.declared_file_identity_count,
    ) == (25_060_620, 3_505, 3_505)


def _assert_trace_streaming_probe(
    result: TraceStreamProbeResult,
    *,
    expected_rows: int,
) -> None:
    assert result["partition_count"] == 5
    assert result["partition_row_counts"] == [expected_rows // 5] * 5
    assert result["merged_row_count"] == expected_rows
    assert result["merged_content_size_bytes"] > expected_rows
    assert len(result["merged_content_sha256"]) == 64
    assert result["verifier_accepted_record_count"] == expected_rows
    assert result["verifier_durable_record_count"] == expected_rows
    assert result["scratch_database_bytes"] > 0
    assert result["projected_qualification_scratch_bytes"] > 0
    assert (
        result["reserved_qualification_scratch_bytes"]
        <= QUALIFICATION_SCRATCH_BUDGET_BYTES
    )
    assert result["peak_rss_bytes"] <= TRACE_STREAM_RSS_LIMIT_BYTES


def test_five_trace_partitions_stream_short_fixture_within_rss_bound(
    tmp_path: Path,
) -> None:
    result = _run_trace_streaming_probe(
        tmp_path / "trace-stream-short",
        TRACE_STREAM_SHORT_ROW_COUNT,
    )

    _assert_trace_streaming_probe(result, expected_rows=TRACE_STREAM_SHORT_ROW_COUNT)


@pytest.mark.performance
def test_five_trace_partitions_stream_one_million_rows_within_rss_bound(
    tmp_path: Path,
) -> None:
    result = _run_trace_streaming_probe(
        tmp_path / "trace-stream-million",
        TRACE_STREAM_FULL_ROW_COUNT,
    )

    _assert_trace_streaming_probe(result, expected_rows=TRACE_STREAM_FULL_ROW_COUNT)


@pytest.mark.performance
@pytest.mark.skipif(
    os.environ.get("CRYPTO_COLLECTOR_FULL_GATE_ORACLE") != "1",
    reason="set CRYPTO_COLLECTOR_FULL_GATE_ORACLE=1 for the 10-minute plan hash",
)
def test_qualification_plan_matches_literal_golden_hash() -> None:
    decoded = decode_json(GOLDEN_PATH.read_bytes())
    assert isinstance(decoded, dict)
    golden = cast(dict[str, Any], decoded)["plans"]["qualification_10m_multiplier_2"]
    plan = build_workload_plan(
        load_workload(WORKLOAD_PATH),
        multiplier=2,
        duration_ns=600_000_000_000,
    )

    assert {
        "duration_ns": plan.duration_ns,
        "multiplier": plan.multiplier,
        "expected_record_count": plan.expected_record_count,
        "declared_file_identity_count": plan.declared_file_identity_count,
        "expected_touched_file_identity_count": (
            plan.expected_touched_file_identity_count
        ),
        "expected_payload_byte_count": plan.expected_payload_byte_count,
        "workload_plan_sha256": plan.workload_plan_sha256,
    } == {key: value for key, value in golden.items() if key != "streams"}
    assert {
        summary.stream_group: {
            "summary": {
                "expected_record_count": summary.expected_record_count,
                "identity_count": summary.identity_count,
                "expected_touched_file_identity_count": (
                    summary.expected_touched_file_identity_count
                ),
                "required_burst_count": summary.required_burst_count,
                "scheduled_burst_count": summary.scheduled_burst_count,
                "burst_second": summary.burst_second,
                "expected_payload_byte_count": (summary.expected_payload_byte_count),
            }
        }
        for summary in plan.streams
    } == golden["streams"]


if __name__ == "__main__":
    raise SystemExit(_trace_stream_probe_main(sys.argv[1:]))
