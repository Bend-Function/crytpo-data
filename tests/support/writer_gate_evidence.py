from __future__ import annotations

import hashlib
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

import zstandard

from crypto_collector.benchmarks.aggregation import (
    aggregate_final_worker_snapshots,
    summarize_resources,
    summarize_storage_health,
    validate_worker_rounds,
)
from crypto_collector.benchmarks.artifacts import (
    build_admission_trace_set,
    write_jsonl_zstd,
)
from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    GateAdmissionTraceV1,
    GateArtifactRefV1,
    GateCandidateReportV1,
    GateEvidenceDocumentRefV1,
    GateExchangeArtifactPartitionV1,
    GateManifestInventoryEntryV1,
    GateManifestInventoryV1,
    GateProcessKeyV1,
    GateProcessResourceSampleV1,
    GateRawInventoryV1,
    GateResourceSamplingRoundV1,
    GateRunIndexV1,
    GateRuntimeSummaryV1,
    GateSamplingRoundV1,
    GateSecondBucketV1,
    GateStorageHealthSampleV1,
    GateStreamRuntimeSummaryV1,
    GateWorkerHealthV1,
    GateWorkerKeyV1,
    GateWorkerSampleV1,
    StreamGroup,
)
from crypto_collector.benchmarks.oracle import (
    PlannedEventV1,
    WorkloadPlanV1,
    build_native_draft,
    build_workload_plan,
    iter_exchange_plan_events,
    iter_plan_events,
)
from crypto_collector.benchmarks.workload import GateWorkloadV1, load_workload
from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.domain.types import CloseReason, Exchange, Market
from crypto_collector.storage.layout import raw_partial_path
from crypto_collector.storage.manifest import (
    RawManifestV1,
    lease_path_for_data,
    manifest_path_for_data,
)
from crypto_collector.storage.models import (
    AcceptedRecordIdentityV1,
    AdmissionState,
    DurabilityHistogramSeriesV1,
    EnqueueStatus,
    PublicationState,
    WriterLifecycle,
    WriterMetricsSnapshotV1,
)
from crypto_collector.storage.serialize import encode_envelope
from crypto_collector.storage.stats import DURABILITY_BUCKET_UPPER_BOUNDS_NS

_REPO_ROOT = Path(__file__).resolve().parents[2]
_BASE_WORKLOAD = _REPO_ROOT / "benchmarks/workloads/research-default-v1.yaml"
_RUN_ID = "00000000-0000-4000-8000-000000000001"
_CONFIG_SHA256 = "c" * 64
_ADMISSION_STARTED_MONOTONIC_NS = 1_000_000_000
_DURATION_NS = 10_000_000_000
_ADMISSION_ENDED_MONOTONIC_NS = _ADMISSION_STARTED_MONOTONIC_NS + _DURATION_NS
_RUN_ENDED_MONOTONIC_NS = 12_000_000_000
_ADMISSION_STARTED_UTC_NS = 1_800_000_000_000_000_000
_ONE_SECOND_NS = 1_000_000_000
_STREAM_GROUPS: tuple[StreamGroup, ...] = (
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "derivative",
    "candle_1m",
    "book_deep_snapshot",
    "control",
)


@dataclass(frozen=True, slots=True)
class PassingMicroEvidence:
    root: Path
    data_root: Path
    state_root: Path
    run_index_path: Path
    workload: GateWorkloadV1
    plan: WorkloadPlanV1
    events: tuple[PlannedEventV1, ...]
    traces: tuple[GateAdmissionTraceV1, ...]
    buckets: tuple[GateSecondBucketV1, ...]
    worker_rounds: tuple[GateSamplingRoundV1, ...]
    resource_rounds: tuple[GateResourceSamplingRoundV1, ...]
    health_samples: tuple[GateStorageHealthSampleV1, ...]
    raw_inventory: GateRawInventoryV1
    manifest_inventory: GateManifestInventoryV1
    candidate_report: GateCandidateReportV1
    run_index: GateRunIndexV1


def _self_hashed(model_type: type[Any], unsigned: dict[str, Any]) -> Any:
    digest = hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest()
    return model_type.model_validate_json(
        encode_json({**unsigned, "sha256": digest}),
    )


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def _document_ref(root: Path, path: Path) -> GateEvidenceDocumentRefV1:
    data = path.read_bytes()
    return GateEvidenceDocumentRefV1(
        relative_path=path.relative_to(root).as_posix(),
        content_size_bytes=len(data),
        content_sha256=hashlib.sha256(data).hexdigest(),
    )


def _micro_workload_bytes(*, warmup_seconds: int = 9) -> bytes:
    baseline = load_workload(_BASE_WORKLOAD).workload.model_dump(mode="json")
    data = cast(dict[str, Any], deepcopy(baseline))
    data.update(
        {
            "name": "research-micro-v1",
            "symbols_per_market": 1,
            "fixed_scope_file_count": 5,
            "scalable_file_count": 70,
            "active_file_count": 75,
        }
    )
    streams = cast(dict[str, dict[str, Any]], data["streams"])
    for name, stream in streams.items():
        stream.update(
            {
                "mean_records_per_second": "0.001",
                "burst_records_in_1s": 1,
                "payload_p50_bytes": 320,
                "payload_p95_bytes": 384,
                "payload_max_bytes": 512,
            }
        )
        if name == "derivative":
            stream["instrument_instances"] = 5
            stream["file_instances"] = 10
        elif name == "control":
            stream["instances"] = 5
            stream["mean_records_per_second"] = "0.2"
            stream["burst_records_in_1s"] = 2
        else:
            stream["instances"] = 10
    qualification = cast(dict[str, Any], data["qualification"])
    qualification["warmup_seconds"] = warmup_seconds
    workload = GateWorkloadV1.model_validate(data)
    return encode_json(workload.model_dump(mode="json"))


def _accepted_identity(
    event: PlannedEventV1,
    *,
    writer_sequence: int,
) -> AcceptedRecordIdentityV1:
    return AcceptedRecordIdentityV1(
        exchange=event.exchange,
        market=event.market,
        instrument_key=event.instrument_key,
        logical_stream=event.logical_stream,
        worker_instance_id=f"gate-worker-v1-{event.exchange.value}",
        writer_sequence=writer_sequence,
        acceptance_ordinal=writer_sequence,
        config_sha256=_CONFIG_SHA256,
        config_generation=0,
    )


def _envelope(
    event: PlannedEventV1,
    identity: AcceptedRecordIdentityV1,
) -> RawEnvelope:
    draft, source, _ = build_native_draft(
        event,
        admission_started_utc_ns=_ADMISSION_STARTED_UTC_NS,
    )
    return RawEnvelope(
        **draft.model_dump(mode="python"),
        received_at_ns=(_ADMISSION_STARTED_UTC_NS + event.due_offset_ns + 1),
        monotonic_ns=(_ADMISSION_STARTED_MONOTONIC_NS + event.due_offset_ns + 1),
        worker_instance_id=identity.worker_instance_id,
        connection_id=source.connection_id,
        connection_generation=source.connection_generation,
        writer_sequence=identity.writer_sequence,
        egress_id=source.egress_id,
        config_sha256=_CONFIG_SHA256,
    )


def _trace(
    event: PlannedEventV1,
    identity: AcceptedRecordIdentityV1,
) -> GateAdmissionTraceV1:
    due = _ADMISSION_STARTED_MONOTONIC_NS + event.due_offset_ns
    return GateAdmissionTraceV1(
        planned_event_id=event.planned_event_id,
        stream_group=event.stream_group,
        logical_stream=event.logical_stream,
        exchange=event.exchange,
        market=event.market,
        instrument_key=event.instrument_key,
        canonical_identity=event.canonical_identity,
        identity_index=event.identity_index,
        local_sequence=event.local_sequence,
        due_monotonic_ns=due,
        deadline_monotonic_ns=(
            _ADMISSION_STARTED_MONOTONIC_NS + event.deadline_offset_ns
        ),
        attempt_started_monotonic_ns=due,
        admission_completed_monotonic_ns=due + 1,
        enqueue_status=EnqueueStatus.ACCEPTED,
        payload_bytes=event.payload_bytes,
        payload_sha256=event.payload_sha256,
        accepted_identity=identity,
    )


def _build_primary_rows(
    plan: WorkloadPlanV1,
) -> tuple[
    tuple[PlannedEventV1, ...],
    tuple[GateAdmissionTraceV1, ...],
    tuple[RawEnvelope, ...],
    dict[Exchange, tuple[GateAdmissionTraceV1, ...]],
]:
    traces_by_id: dict[str, GateAdmissionTraceV1] = {}
    envelopes_by_id: dict[str, RawEnvelope] = {}
    partitions: dict[Exchange, tuple[GateAdmissionTraceV1, ...]] = {}
    for exchange in CANONICAL_EXCHANGES:
        partition: list[GateAdmissionTraceV1] = []
        for writer_sequence, event in enumerate(
            iter_exchange_plan_events(plan, exchange)
        ):
            identity = _accepted_identity(
                event,
                writer_sequence=writer_sequence,
            )
            trace = _trace(event, identity)
            traces_by_id[event.planned_event_id] = trace
            envelopes_by_id[event.planned_event_id] = _envelope(event, identity)
            partition.append(trace)
        partitions[exchange] = tuple(partition)
    events = tuple(iter_plan_events(plan))
    traces = tuple(traces_by_id[event.planned_event_id] for event in events)
    envelopes = tuple(envelopes_by_id[event.planned_event_id] for event in events)
    return events, traces, envelopes, partitions


def _build_buckets(
    plan: WorkloadPlanV1,
    events: tuple[PlannedEventV1, ...],
) -> tuple[GateSecondBucketV1, ...]:
    by_key: dict[tuple[str, int], list[PlannedEventV1]] = defaultdict(list)
    for event in events:
        by_key[(event.stream_group, event.due_offset_ns // _ONE_SECOND_NS)].append(
            event
        )
    result: list[GateSecondBucketV1] = []
    for stream_group in _STREAM_GROUPS:
        for second_index in range(plan.duration_seconds):
            rows = by_key[(stream_group, second_index)]
            payload_bytes = sum(row.payload_bytes for row in rows)
            result.append(
                GateSecondBucketV1(
                    stream_group=stream_group,
                    second_index=second_index,
                    scheduled_count=len(rows),
                    attempted_count=len(rows),
                    accepted_count=len(rows),
                    admitted_in_actual_second_count=len(rows),
                    scheduled_payload_bytes=payload_bytes,
                    attempted_payload_bytes=payload_bytes,
                    accepted_payload_bytes=payload_bytes,
                    early_count=0,
                    late_count=0,
                    out_of_window_count=0,
                )
            )
    return tuple(result)


def _histogram_counts(count: int) -> tuple[int, ...]:
    return (count, *(0 for _ in DURABILITY_BUCKET_UPPER_BOUNDS_NS[1:]))


def _worker_snapshot(
    exchange: Exchange,
    traces: tuple[GateAdmissionTraceV1, ...],
    *,
    final: bool,
    observed_monotonic_ns: int,
) -> WriterMetricsSnapshotV1:
    exchange_rows = tuple(
        row
        for row in traces
        if row.exchange is exchange
        and row.admission_completed_monotonic_ns <= observed_monotonic_ns
    )
    series_counts: dict[tuple[str, str], int] = defaultdict(int)
    for row in exchange_rows:
        market = "" if row.market is None else row.market.value
        series_counts[(market, row.logical_stream)] += 1
    histogram_series = tuple(
        DurabilityHistogramSeriesV1(
            exchange=exchange,
            market=None if not market else Market(market),
            logical_stream=logical_stream,
            bucket_counts=_histogram_counts(count),
            sample_count=count,
            lag_p50_ns=0,
            lag_p95_ns=0,
            lag_p99_ns=0,
            lag_max_ns=0,
        )
        for (market, logical_stream), count in sorted(series_counts.items())
    )
    count = len(exchange_rows)
    touched = len({row.canonical_identity for row in exchange_rows})
    lag = None if count == 0 else 0
    return WriterMetricsSnapshotV1(
        observed_monotonic_ns=observed_monotonic_ns,
        exchange=exchange,
        worker_instance_id=f"gate-worker-v1-{exchange.value}",
        config_sha256=_CONFIG_SHA256,
        config_generation=0,
        lifecycle=(WriterLifecycle.CLOSED if final else WriterLifecycle.ACCEPTING),
        admission_state=(AdmissionState.CLOSED if final else AdmissionState.OPEN),
        publication_state=PublicationState.IDLE,
        critical_reason=None,
        acceptance_ordinal_high_water=None if count == 0 else count - 1,
        accepted_record_count=count,
        durable_record_count=count,
        unpersisted_record_count=0,
        uncertain_record_count=0,
        queued_records=0,
        queued_bytes=0,
        buffered_records=0,
        buffered_bytes=0,
        in_flight_records=0,
        in_flight_bytes=0,
        resident_record_bytes=0,
        resident_control_records=0,
        resident_control_bytes=0,
        oldest_unpersisted_age_ns=None,
        enqueue_high_water_count=0,
        normal_overflow_count=0,
        control_overflow_count=0,
        not_accepting_count=0,
        active_logical_generation_count=0 if final else touched,
        retiring_generation_count=0,
        open_file_descriptor_count=0 if final else touched,
        sync_inflight=0,
        durability_histogram_schema_version=1,
        durability_bucket_counts=_histogram_counts(count),
        durability_sample_count=count,
        durability_lag_p50_ns=lag,
        durability_lag_p95_ns=lag,
        durability_lag_p99_ns=lag,
        durability_lag_max_ns=lag,
        durability_histogram_series=histogram_series,
        sync_count=touched,
        sync_duration_total_ns=touched,
        sync_duration_max_ns=0 if touched == 0 else 1,
        slo_breach_count=0,
        write_failure_count=0,
        sync_failure_count=0,
        publication_failure_count=0,
    )


def _build_worker_rounds(
    traces: tuple[GateAdmissionTraceV1, ...],
) -> tuple[GateSamplingRoundV1, ...]:
    worker_keys = tuple(
        GateWorkerKeyV1(
            exchange=exchange,
            worker_instance_id=f"gate-worker-v1-{exchange.value}",
        )
        for exchange in CANONICAL_EXCHANGES
    )
    result: list[GateSamplingRoundV1] = []
    round_schedule = (
        *(
            ("periodic", _ADMISSION_STARTED_MONOTONIC_NS + second * _ONE_SECOND_NS)
            for second in range(1, 11)
        ),
        ("final", _RUN_ENDED_MONOTONIC_NS),
    )
    for round_index, (round_kind, scheduled) in enumerate(round_schedule):
        samples = tuple(
            GateWorkerSampleV1(
                round_index=round_index,
                round_kind=round_kind,
                scheduled_monotonic_ns=scheduled,
                request_started_monotonic_ns=scheduled,
                request_completed_monotonic_ns=scheduled,
                snapshot=_worker_snapshot(
                    exchange,
                    traces,
                    final=round_kind == "final",
                    observed_monotonic_ns=scheduled,
                ),
            )
            for exchange in CANONICAL_EXCHANGES
        )
        result.append(
            GateSamplingRoundV1(
                round_index=round_index,
                round_kind=round_kind,
                scheduled_monotonic_ns=scheduled,
                expected_worker_keys=worker_keys,
                samples=samples,
            )
        )
    return tuple(result)


def _process_keys() -> tuple[GateProcessKeyV1, ...]:
    return (
        GateProcessKeyV1(
            role="supervisor",
            exchange=None,
            worker_instance_id=None,
        ),
        *(
            GateProcessKeyV1(
                role="exchange_worker",
                exchange=exchange,
                worker_instance_id=f"gate-worker-v1-{exchange.value}",
            )
            for exchange in CANONICAL_EXCHANGES
        ),
    )


def _build_resource_rounds() -> tuple[GateResourceSamplingRoundV1, ...]:
    process_keys = _process_keys()
    result: list[GateResourceSamplingRoundV1] = []
    for round_index in range(11):
        scheduled = _ADMISSION_STARTED_MONOTONIC_NS + round_index * _ONE_SECOND_NS
        samples = tuple(
            GateProcessResourceSampleV1(
                round_index=round_index,
                scheduled_monotonic_ns=scheduled,
                request_started_monotonic_ns=scheduled,
                request_completed_monotonic_ns=scheduled,
                process_key=process_key,
                process_id=100 + process_index,
                rss_bytes=1024,
                open_fd_count=2,
            )
            for process_index, process_key in enumerate(process_keys)
        )
        result.append(
            GateResourceSamplingRoundV1(
                round_index=round_index,
                scheduled_monotonic_ns=scheduled,
                expected_process_keys=process_keys,
                samples=samples,
            )
        )
    return tuple(result)


def _build_health_samples() -> tuple[GateStorageHealthSampleV1, ...]:
    workers = tuple(
        GateWorkerHealthV1(
            exchange=exchange,
            worker_instance_id=f"gate-worker-v1-{exchange.value}",
            lifecycle=WriterLifecycle.ACCEPTING,
            critical_reason=None,
        )
        for exchange in CANONICAL_EXCHANGES
    )
    return tuple(
        GateStorageHealthSampleV1(
            round_index=round_index,
            scheduled_monotonic_ns=(
                _ADMISSION_STARTED_MONOTONIC_NS + (round_index + 1) * _ONE_SECOND_NS
            ),
            request_started_monotonic_ns=(
                _ADMISSION_STARTED_MONOTONIC_NS + (round_index + 1) * _ONE_SECOND_NS
            ),
            request_completed_monotonic_ns=(
                _ADMISSION_STARTED_MONOTONIC_NS + (round_index + 1) * _ONE_SECOND_NS
            ),
            data_available_bytes=300 * 1024**3,
            state_available_bytes=300 * 1024**3,
            workers=workers,
        )
        for round_index in range(9)
    )


def _write_raw_evidence(
    data_root: Path,
    envelopes: tuple[RawEnvelope, ...],
) -> tuple[GateRawInventoryV1, GateManifestInventoryV1]:
    grouped: dict[tuple[str, str, str, str], list[RawEnvelope]] = defaultdict(list)
    for envelope in envelopes:
        grouped[
            (
                envelope.exchange.value,
                "" if envelope.market is None else envelope.market.value,
                "" if envelope.instrument_key is None else envelope.instrument_key,
                envelope.logical_stream,
            )
        ].append(envelope)

    compressor = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    )
    pairs: list[tuple[GateEvidenceDocumentRefV1, GateArtifactRefV1, RawManifestV1]] = []
    for group in grouped.values():
        first = group[0]
        partial = raw_partial_path(
            data_root,
            first,
            (first.received_at_ns // (3_600 * _ONE_SECOND_NS))
            * (3_600 * _ONE_SECOND_NS),
            0,
        )
        data_path = Path(str(partial).removesuffix(".partial"))
        data_relative_path = data_path.relative_to(data_root).as_posix()
        plain = b"".join(encode_envelope(envelope) for envelope in group)
        compressed = compressor.compress(plain)
        _write_bytes(data_path, compressed)
        data_ref = _raw_artifact_ref(data_relative_path, plain, compressed, len(group))
        manifest_path = manifest_path_for_data(data_path)
        manifest_relative_path = manifest_path.relative_to(data_root).as_posix()
        event_times = tuple(
            envelope.event_time_ns
            for envelope in group
            if envelope.event_time_ns is not None
        )
        manifest = RawManifestV1(
            schema_version=1,
            exchange=first.exchange,
            market=first.market,
            instrument_key=first.instrument_key,
            logical_stream=first.logical_stream,
            wire_symbols=tuple(
                sorted(
                    {
                        envelope.wire_symbol
                        for envelope in group
                        if envelope.wire_symbol is not None
                    }
                )
            ),
            data_relative_path=data_relative_path,
            manifest_relative_path=manifest_relative_path,
            file_size_bytes=len(compressed),
            file_sha256=hashlib.sha256(compressed).hexdigest(),
            zstd_level=3,
            zstd_write_checksum=True,
            zstd_write_content_size=True,
            max_plain_frame_bytes=1_048_576,
            record_count=len(group),
            first_received_at_ns=group[0].received_at_ns,
            last_received_at_ns=group[-1].received_at_ns,
            first_event_time_ns=event_times[0] if event_times else None,
            last_event_time_ns=event_times[-1] if event_times else None,
            worker_instance_id=first.worker_instance_id,
            connection_generations=tuple(
                sorted(
                    {
                        envelope.connection_generation
                        for envelope in group
                        if envelope.connection_generation is not None
                    }
                )
            ),
            writer_sequence_first=group[0].writer_sequence,
            writer_sequence_last=group[-1].writer_sequence,
            config_sha256=_CONFIG_SHA256,
            egress_ids=tuple(
                sorted(
                    {
                        envelope.egress_id
                        for envelope in group
                        if envelope.egress_id is not None
                    }
                )
            ),
            requested_intervals_ns=(),
            effective_intervals_ns=(),
            gap_count=0,
            reconnect_count=0,
            parse_error_count=0,
            checksum_error_count=0,
            queue_overflow_count=0,
            control_event_ids=(),
            durability_measurement="measured",
            durability_sample_count=len(group),
            durability_lag_p50_ns=0,
            durability_lag_p95_ns=0,
            durability_lag_p99_ns=0,
            durability_lag_max_ns=0,
            sync_count=1,
            sync_duration_total_ns=1,
            sync_duration_max_ns=1,
            slo_breach_count=0,
            write_failure_count=0,
            sync_failure_count=0,
            close_reason=CloseReason.SHUTDOWN,
            created_at_ns=group[0].received_at_ns,
            closed_at_ns=group[-1].received_at_ns + 1,
            recovery_transaction_id=None,
            recovery_source_state=None,
            recovery_source_relative_path=None,
            recovery_source_bytes=None,
            recovery_source_sha256=None,
            recovery_control_event_id=None,
            recovered_frame_count=None,
            recovered_record_count=None,
            recovered_bytes=None,
            recovered_sha256=None,
            quarantined_suffix_relative_path=None,
            quarantined_suffix_bytes=None,
            quarantined_suffix_sha256=None,
            unavailable_fields=(),
        )
        _write_bytes(manifest_path, manifest.canonical_bytes())
        pairs.append((_document_ref(data_root, manifest_path), data_ref, manifest))

    pairs.sort(key=lambda item: item[0].relative_path)
    raw_files = tuple(
        sorted((item[1] for item in pairs), key=lambda item: item.relative_path)
    )
    raw_unsigned = {
        "schema_version": 1,
        "record_type": "gate_raw_inventory_v1",
        "raw_files": [item.model_dump(mode="json") for item in raw_files],
        "file_count": len(raw_files),
        "record_count": sum(item.row_count for item in raw_files),
        "content_size_bytes": sum(item.content_size_bytes for item in raw_files),
        "compressed_size_bytes": sum(item.compressed_size_bytes for item in raw_files),
    }
    raw_inventory = _self_hashed(GateRawInventoryV1, raw_unsigned)
    entries = tuple(
        GateManifestInventoryEntryV1(
            ordinal=ordinal,
            manifest=manifest_ref,
            data=data_ref,
            manifest_record_count=manifest.record_count,
        )
        for ordinal, (manifest_ref, data_ref, manifest) in enumerate(pairs)
    )
    manifest_unsigned = {
        "schema_version": 1,
        "record_type": "gate_manifest_inventory_v1",
        "manifests": [entry.model_dump(mode="json") for entry in entries],
        "file_count": len(entries),
        "record_count": sum(entry.manifest_record_count for entry in entries),
        "manifest_content_size_bytes": sum(
            entry.manifest.content_size_bytes for entry in entries
        ),
    }
    manifest_inventory = _self_hashed(
        GateManifestInventoryV1,
        manifest_unsigned,
    )
    return raw_inventory, manifest_inventory


def _raw_artifact_ref(
    relative_path: str,
    plain: bytes,
    compressed: bytes,
    rows: int,
) -> GateArtifactRefV1:
    return GateArtifactRefV1(
        relative_path=relative_path,
        row_count=rows,
        content_size_bytes=len(plain),
        content_sha256=hashlib.sha256(plain).hexdigest(),
        compressed_size_bytes=len(compressed),
        compressed_sha256=hashlib.sha256(compressed).hexdigest(),
    )


def _stream_runtime_summaries(
    plan: WorkloadPlanV1,
    buckets: tuple[GateSecondBucketV1, ...],
) -> tuple[GateStreamRuntimeSummaryV1, ...]:
    result: list[GateStreamRuntimeSummaryV1] = []
    for stream_plan in plan.streams:
        rows = tuple(
            bucket
            for bucket in buckets
            if bucket.stream_group == stream_plan.stream_group
        )
        burst = rows[stream_plan.burst_second]
        result.append(
            GateStreamRuntimeSummaryV1(
                stream_group=stream_plan.stream_group,
                expected_record_count=stream_plan.expected_record_count,
                expected_payload_bytes=stream_plan.expected_payload_byte_count,
                scheduled_record_count=sum(row.scheduled_count for row in rows),
                scheduled_payload_bytes=sum(
                    row.scheduled_payload_bytes for row in rows
                ),
                attempted_record_count=sum(row.attempted_count for row in rows),
                attempted_payload_bytes=sum(
                    row.attempted_payload_bytes for row in rows
                ),
                accepted_record_count=sum(row.accepted_count for row in rows),
                accepted_payload_bytes=sum(row.accepted_payload_bytes for row in rows),
                early_count=sum(row.early_count for row in rows),
                late_count=sum(row.late_count for row in rows),
                out_of_window_count=sum(row.out_of_window_count for row in rows),
                required_burst_count=stream_plan.required_burst_count,
                scheduled_burst_count=stream_plan.scheduled_burst_count,
                burst_second=stream_plan.burst_second,
                burst_scheduled_count=burst.scheduled_count,
                burst_attempted_count=burst.attempted_count,
                burst_accepted_count=burst.accepted_count,
                burst_admitted_in_actual_second_count=(
                    burst.admitted_in_actual_second_count
                ),
                planned_values_match=True,
                admission_values_match=True,
                burst_valid=True,
            )
        )
    return tuple(result)


def _runtime_summary(
    plan: WorkloadPlanV1,
    buckets: tuple[GateSecondBucketV1, ...],
    worker_rounds: tuple[GateSamplingRoundV1, ...],
    resource_rounds: tuple[GateResourceSamplingRoundV1, ...],
    health_samples: tuple[GateStorageHealthSampleV1, ...],
    raw_inventory: GateRawInventoryV1,
    manifest_inventory: GateManifestInventoryV1,
    *,
    warmup_seconds: int = 9,
) -> GateRuntimeSummaryV1:
    worker_keys = worker_rounds[0].expected_worker_keys
    worker_sequences = validate_worker_rounds(
        worker_rounds,
        expected_workers=worker_keys,
    )
    worker_aggregate = aggregate_final_worker_snapshots(worker_sequences)
    resource_summary = summarize_resources(
        resource_rounds,
        expected_processes=resource_rounds[0].expected_process_keys,
        warmup_ended_monotonic_ns=(
            _ADMISSION_STARTED_MONOTONIC_NS + warmup_seconds * _ONE_SECOND_NS
        ),
    )
    health_summary = summarize_storage_health(
        health_samples,
        duration_ns=_DURATION_NS,
        interval_ns=_ONE_SECOND_NS,
    )
    stream_summaries = _stream_runtime_summaries(plan, buckets)
    expected_payload_bytes = plan.expected_payload_byte_count
    return GateRuntimeSummaryV1(
        expected_record_count=plan.expected_record_count,
        expected_payload_bytes=expected_payload_bytes,
        scheduled_record_count=plan.expected_record_count,
        scheduled_payload_bytes=expected_payload_bytes,
        attempted_record_count=plan.expected_record_count,
        attempted_payload_bytes=expected_payload_bytes,
        accepted_record_count=plan.expected_record_count,
        accepted_payload_bytes=expected_payload_bytes,
        durable_record_count=raw_inventory.record_count,
        durable_payload_bytes=expected_payload_bytes,
        durability_sample_count=worker_aggregate.durability_sample_count,
        manifest_record_count=manifest_inventory.record_count,
        raw_file_count=raw_inventory.file_count,
        manifest_file_count=manifest_inventory.file_count,
        declared_file_identity_count=plan.declared_file_identity_count,
        expected_touched_file_identity_count=(
            plan.expected_touched_file_identity_count
        ),
        observed_touched_file_identity_count=raw_inventory.file_count,
        accepted_identity_count=plan.expected_record_count,
        unique_accepted_identity_count=plan.expected_record_count,
        early_count=0,
        late_count=0,
        out_of_window_count=0,
        received_utc_hours=(
            datetime.fromtimestamp(
                _ADMISSION_STARTED_UTC_NS // _ONE_SECOND_NS,
                tz=UTC,
            ).strftime("%Y/%m/%d/%H"),
        ),
        stream_summaries=stream_summaries,
        final_worker_aggregate=worker_aggregate,
        resource_summary=resource_summary,
        storage_health_summary=health_summary,
    )


def write_passing_micro_evidence(
    root: Path,
    *,
    warmup_seconds: int = 9,
) -> PassingMicroEvidence:
    if not isinstance(root, Path):
        raise TypeError("evidence root must be Path")
    if root.exists():
        resolved = root.resolve(strict=True)
        if resolved != root or not root.is_dir():
            raise ValueError("evidence root must be a normalized real directory")
        if next(root.iterdir(), None) is not None:
            raise ValueError("evidence root must be empty")
    else:
        root.mkdir(parents=True, exist_ok=False)
        resolved = root.resolve(strict=True)
        if resolved != root:
            raise ValueError("evidence root must be a normalized real directory")
    root = resolved
    data_root = root / "data"
    state_root = root / "state"
    data_root.mkdir()
    state_root.mkdir()

    workload_path = root / "workload.json"
    _write_bytes(
        workload_path,
        _micro_workload_bytes(warmup_seconds=warmup_seconds),
    )
    loaded = load_workload(workload_path)
    plan = build_workload_plan(
        loaded,
        multiplier=1,
        duration_ns=_DURATION_NS,
    )
    events, traces, envelopes, trace_partitions = _build_primary_rows(plan)

    partition_refs = tuple(
        GateExchangeArtifactPartitionV1(
            exchange=exchange,
            artifact=write_jsonl_zstd(
                root,
                f"primary/trace/{exchange.value}.jsonl.zst",
                trace_partitions[exchange],
                zstd_level=3,
            ),
        )
        for exchange in CANONICAL_EXCHANGES
    )
    trace_set = build_admission_trace_set(
        root,
        partition_refs,
        max_rows=17,
        max_content_bytes=1_000_000,
        max_line_bytes=64_000,
    )
    buckets = _build_buckets(plan, events)
    bucket_ref = write_jsonl_zstd(
        root,
        "primary/buckets.jsonl.zst",
        buckets,
        zstd_level=3,
    )
    worker_rounds = _build_worker_rounds(traces)
    worker_ref = write_jsonl_zstd(
        root,
        "primary/workers.jsonl.zst",
        worker_rounds,
        zstd_level=3,
    )
    resource_rounds = _build_resource_rounds()
    resource_ref = write_jsonl_zstd(
        root,
        "primary/resources.jsonl.zst",
        resource_rounds,
        zstd_level=3,
    )
    health_samples = _build_health_samples()
    health_ref = write_jsonl_zstd(
        root,
        "primary/health.jsonl.zst",
        health_samples,
        zstd_level=3,
    )

    raw_inventory, manifest_inventory = _write_raw_evidence(
        data_root,
        envelopes,
    )
    for exchange in CANONICAL_EXCHANGES:
        _write_bytes(
            data_root / "raw" / exchange.value / ".writer.lock",
            b"",
        )
    for data_ref in raw_inventory.raw_files:
        _write_bytes(
            lease_path_for_data(data_root / data_ref.relative_path),
            b"",
        )
    raw_inventory_path = root / "raw-inventory.json"
    manifest_inventory_path = root / "manifest-inventory.json"
    _write_bytes(raw_inventory_path, raw_inventory.canonical_bytes())
    _write_bytes(manifest_inventory_path, manifest_inventory.canonical_bytes())
    summary = _runtime_summary(
        plan,
        buckets,
        worker_rounds,
        resource_rounds,
        health_samples,
        raw_inventory,
        manifest_inventory,
        warmup_seconds=warmup_seconds,
    )
    candidate_unsigned = {
        "schema_version": 1,
        "record_type": "gate_candidate_report_v1",
        "run_id": _RUN_ID,
        "mode": "functional",
        "workload_sha256": loaded.sha256,
        "workload_plan_sha256": plan.workload_plan_sha256,
        "multiplier": 1,
        "duration_ns": _DURATION_NS,
        "run_started_monotonic_ns": 0,
        "admission_started_monotonic_ns": _ADMISSION_STARTED_MONOTONIC_NS,
        "admission_scheduled_end_monotonic_ns": _ADMISSION_ENDED_MONOTONIC_NS,
        "admission_ended_monotonic_ns": _ADMISSION_ENDED_MONOTONIC_NS,
        "run_ended_monotonic_ns": _RUN_ENDED_MONOTONIC_NS,
        "admission_started_utc_ns": _ADMISSION_STARTED_UTC_NS,
        "admission_ended_utc_ns": _ADMISSION_STARTED_UTC_NS + _DURATION_NS,
        "declared_admission_utc_hour": datetime.fromtimestamp(
            _ADMISSION_STARTED_UTC_NS // _ONE_SECOND_NS,
            tz=UTC,
        ).strftime("%Y/%m/%d/%H"),
        "expected_target_id": None,
        "target_declaration_sha256": None,
        "expected_image_id": None,
        "runtime_image_id": None,
        "runtime_summary": summary.model_dump(mode="json"),
        "runtime_failure_codes": [],
        "candidate_runtime_passed": True,
    }
    candidate = _self_hashed(GateCandidateReportV1, candidate_unsigned)
    candidate_path = root / "candidate-report.json"
    _write_bytes(candidate_path, candidate.canonical_bytes())

    run_unsigned = {
        "schema_version": 1,
        "record_type": "gate_run_index_v1",
        "run_id": _RUN_ID,
        "status": "complete",
        "mode": "functional",
        "artifact_schema_version": 1,
        "identity_algorithm": "gate-identity-v1",
        "event_algorithm": "gate-event-v1",
        "payload_algorithm": "gate-payload-v1",
        "schedule_algorithm": "gate-schedule-v2-full-second-burst",
        "data_root": data_root.as_posix(),
        "state_root": state_root.as_posix(),
        "workload_document": _document_ref(root, workload_path).model_dump(mode="json"),
        "workload_sha256": loaded.sha256,
        "workload_plan_sha256": plan.workload_plan_sha256,
        "admission_trace_set": trace_set.model_dump(mode="json"),
        "second_bucket_artifact": bucket_ref.model_dump(mode="json"),
        "worker_sampling_artifact": worker_ref.model_dump(mode="json"),
        "resource_sampling_artifact": resource_ref.model_dump(mode="json"),
        "storage_health_artifact": health_ref.model_dump(mode="json"),
        "raw_inventory": _document_ref(root, raw_inventory_path).model_dump(
            mode="json"
        ),
        "manifest_inventory": _document_ref(
            root,
            manifest_inventory_path,
        ).model_dump(mode="json"),
        "candidate_report": _document_ref(root, candidate_path).model_dump(mode="json"),
        "expected_target_id": None,
        "target_declaration": None,
        "implementation_source_commit": None,
        "collector_wheel_sha256": None,
        "requirements_lock_sha256": None,
        "dockerfile_sha256": None,
        "expected_image_id": None,
        "runtime_image_id": None,
    }
    run_index = _self_hashed(GateRunIndexV1, run_unsigned)
    run_index_path = root / "run-index.json"
    _write_bytes(run_index_path, run_index.canonical_bytes())
    return PassingMicroEvidence(
        root=root,
        data_root=data_root,
        state_root=state_root,
        run_index_path=run_index_path,
        workload=loaded.workload,
        plan=plan,
        events=events,
        traces=traces,
        buckets=buckets,
        worker_rounds=worker_rounds,
        resource_rounds=resource_rounds,
        health_samples=health_samples,
        raw_inventory=raw_inventory,
        manifest_inventory=manifest_inventory,
        candidate_report=candidate,
        run_index=run_index,
    )


__all__ = ["PassingMicroEvidence", "write_passing_micro_evidence"]
