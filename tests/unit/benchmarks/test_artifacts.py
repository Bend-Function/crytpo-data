from __future__ import annotations

import errno
import hashlib
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest
import zstandard
from pydantic import BaseModel, ValidationError

import crypto_collector.benchmarks.artifacts as artifacts_module
from crypto_collector.benchmarks.artifacts import (
    StreamingJsonlZstdWriter,
    build_admission_trace_set,
    iter_jsonl_zstd,
    iter_merged_trace_partitions,
    write_jsonl_zstd,
)
from crypto_collector.benchmarks.contracts import (
    GateAdmissionTraceSetV1,
    GateAdmissionTraceV1,
    GateArtifactRefV1,
    GateExchangeArtifactPartitionV1,
    GateProcessKeyV1,
    GateProcessResourceSampleV1,
    GateResourceSamplingRoundV1,
    GateSamplingRoundV1,
    GateSecondBucketV1,
    GateStorageHealthSampleV1,
    GateWorkerHealthV1,
    GateWorkerKeyV1,
    GateWorkerSampleV1,
)
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.domain.types import Exchange, Market
from crypto_collector.storage.errors import PublicationConflict
from crypto_collector.storage.models import (
    DURABILITY_BUCKET_UPPER_BOUNDS_NS,
    AcceptedRecordIdentityV1,
    AdmissionState,
    EnqueueStatus,
    PublicationState,
    WriterLifecycle,
    WriterMetricsSnapshotV1,
)
from crypto_collector.storage.raw_writer import NoReplaceCapability

CANONICAL_EXCHANGES = (
    Exchange.BINANCE,
    Exchange.OKX,
    Exchange.BYBIT,
    Exchange.BITGET,
    Exchange.KRAKEN,
)
EXPECTED_FIELDS = {
    GateArtifactRefV1: (
        "schema_version",
        "record_type",
        "relative_path",
        "row_count",
        "content_size_bytes",
        "content_sha256",
        "compressed_size_bytes",
        "compressed_sha256",
    ),
    GateExchangeArtifactPartitionV1: (
        "schema_version",
        "record_type",
        "exchange",
        "artifact",
    ),
    GateAdmissionTraceSetV1: (
        "schema_version",
        "record_type",
        "partitions",
        "merged_row_count",
        "merged_content_size_bytes",
        "merged_content_sha256",
    ),
    GateAdmissionTraceV1: (
        "schema_version",
        "record_type",
        "planned_event_id",
        "stream_group",
        "logical_stream",
        "exchange",
        "market",
        "instrument_key",
        "canonical_identity",
        "identity_index",
        "local_sequence",
        "due_monotonic_ns",
        "deadline_monotonic_ns",
        "attempt_started_monotonic_ns",
        "admission_completed_monotonic_ns",
        "enqueue_status",
        "payload_bytes",
        "payload_sha256",
        "accepted_identity",
    ),
    GateSecondBucketV1: (
        "schema_version",
        "record_type",
        "stream_group",
        "second_index",
        "scheduled_count",
        "attempted_count",
        "accepted_count",
        "admitted_in_actual_second_count",
        "scheduled_payload_bytes",
        "attempted_payload_bytes",
        "accepted_payload_bytes",
        "early_count",
        "late_count",
        "out_of_window_count",
    ),
    GateWorkerKeyV1: ("exchange", "worker_instance_id"),
    GateWorkerSampleV1: (
        "schema_version",
        "record_type",
        "round_index",
        "round_kind",
        "scheduled_monotonic_ns",
        "request_started_monotonic_ns",
        "request_completed_monotonic_ns",
        "snapshot",
    ),
    GateSamplingRoundV1: (
        "schema_version",
        "record_type",
        "round_index",
        "round_kind",
        "scheduled_monotonic_ns",
        "expected_worker_keys",
        "samples",
    ),
    GateProcessKeyV1: ("role", "exchange", "worker_instance_id"),
    GateProcessResourceSampleV1: (
        "schema_version",
        "record_type",
        "round_index",
        "scheduled_monotonic_ns",
        "request_started_monotonic_ns",
        "request_completed_monotonic_ns",
        "process_key",
        "process_id",
        "rss_bytes",
        "open_fd_count",
    ),
    GateResourceSamplingRoundV1: (
        "schema_version",
        "record_type",
        "round_index",
        "scheduled_monotonic_ns",
        "expected_process_keys",
        "samples",
    ),
    GateWorkerHealthV1: (
        "exchange",
        "worker_instance_id",
        "lifecycle",
        "critical_reason",
    ),
    GateStorageHealthSampleV1: (
        "schema_version",
        "record_type",
        "round_index",
        "scheduled_monotonic_ns",
        "request_started_monotonic_ns",
        "request_completed_monotonic_ns",
        "data_available_bytes",
        "state_available_bytes",
        "workers",
    ),
}


def _sha(value: str | bytes) -> str:
    source = value.encode("ascii") if isinstance(value, str) else value
    return hashlib.sha256(source).hexdigest()


def _worker_id(exchange: Exchange) -> str:
    return f"gate-worker-v1-{exchange.value}"


def _accepted_identity(exchange: Exchange) -> AcceptedRecordIdentityV1:
    instrument = f"GATE-{exchange.value.upper()}-SPOT-L0000-S0000"
    return AcceptedRecordIdentityV1(
        exchange=exchange,
        market=Market.SPOT,
        instrument_key=instrument,
        logical_stream="trade",
        worker_instance_id=_worker_id(exchange),
        writer_sequence=1,
        acceptance_ordinal=0,
        config_sha256="a" * 64,
        config_generation=0,
    )


def _trace(
    exchange: Exchange,
    sequence: int,
    *,
    due_monotonic_ns: int | None = None,
    planned_event_id: str | None = None,
) -> GateAdmissionTraceV1:
    due = (
        2_000_000_000 + sequence * 10 if due_monotonic_ns is None else due_monotonic_ns
    )
    instrument = f"GATE-{exchange.value.upper()}-SPOT-L0000-S0000"
    return GateAdmissionTraceV1(
        planned_event_id=(
            _sha(f"{exchange.value}:{sequence}")
            if planned_event_id is None
            else planned_event_id
        ),
        stream_group="trade",
        logical_stream="trade",
        exchange=exchange,
        market=Market.SPOT,
        instrument_key=instrument,
        canonical_identity=(
            f"gate-identity-v1:{exchange.value}:spot:{instrument}:trade"
        ),
        identity_index=sequence,
        local_sequence=0,
        due_monotonic_ns=due,
        deadline_monotonic_ns=due + 1_000_000_000,
        attempt_started_monotonic_ns=due,
        admission_completed_monotonic_ns=due + 1,
        enqueue_status=EnqueueStatus.ACCEPTED,
        payload_bytes=320,
        payload_sha256=_sha(f"payload:{exchange.value}:{sequence}"),
        accepted_identity=_accepted_identity(exchange),
    )


def _bucket(second_index: int = 0) -> GateSecondBucketV1:
    return GateSecondBucketV1(
        stream_group="trade",
        second_index=second_index,
        scheduled_count=1,
        attempted_count=1,
        accepted_count=1,
        admitted_in_actual_second_count=1,
        scheduled_payload_bytes=320,
        attempted_payload_bytes=320,
        accepted_payload_bytes=320,
        early_count=0,
        late_count=0,
        out_of_window_count=0,
    )


def _metrics_snapshot(
    exchange: Exchange,
    *,
    lifecycle: WriterLifecycle = WriterLifecycle.CLOSED,
) -> WriterMetricsSnapshotV1:
    empty_buckets = (0,) * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    return WriterMetricsSnapshotV1(
        observed_monotonic_ns=10,
        exchange=exchange,
        worker_instance_id=_worker_id(exchange),
        config_sha256="a" * 64,
        config_generation=0,
        lifecycle=lifecycle,
        admission_state=AdmissionState.CLOSED,
        publication_state=PublicationState.IDLE,
        critical_reason=None,
        acceptance_ordinal_high_water=None,
        accepted_record_count=0,
        durable_record_count=0,
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
        active_logical_generation_count=0,
        retiring_generation_count=0,
        open_file_descriptor_count=0,
        sync_inflight=0,
        durability_histogram_schema_version=1,
        durability_bucket_counts=empty_buckets,
        durability_sample_count=0,
        durability_lag_p50_ns=None,
        durability_lag_p95_ns=None,
        durability_lag_p99_ns=None,
        durability_lag_max_ns=None,
        durability_histogram_series=(),
        sync_count=0,
        sync_duration_total_ns=0,
        sync_duration_max_ns=0,
        slo_breach_count=0,
        write_failure_count=0,
        sync_failure_count=0,
        publication_failure_count=0,
    )


def _worker_keys() -> tuple[GateWorkerKeyV1, ...]:
    return tuple(
        GateWorkerKeyV1(exchange=exchange, worker_instance_id=_worker_id(exchange))
        for exchange in CANONICAL_EXCHANGES
    )


def _worker_samples(
    *, lifecycle: WriterLifecycle = WriterLifecycle.CLOSED
) -> tuple[GateWorkerSampleV1, ...]:
    return tuple(
        GateWorkerSampleV1(
            round_index=0,
            round_kind="final",
            scheduled_monotonic_ns=10,
            request_started_monotonic_ns=11,
            request_completed_monotonic_ns=12,
            snapshot=_metrics_snapshot(exchange, lifecycle=lifecycle),
        )
        for exchange in CANONICAL_EXCHANGES
    )


def _process_keys() -> tuple[GateProcessKeyV1, ...]:
    return (
        GateProcessKeyV1(role="supervisor", exchange=None, worker_instance_id=None),
        *(
            GateProcessKeyV1(
                role="exchange_worker",
                exchange=exchange,
                worker_instance_id=_worker_id(exchange),
            )
            for exchange in CANONICAL_EXCHANGES
        ),
    )


def _process_samples() -> tuple[GateProcessResourceSampleV1, ...]:
    return tuple(
        GateProcessResourceSampleV1(
            round_index=0,
            scheduled_monotonic_ns=10,
            request_started_monotonic_ns=11,
            request_completed_monotonic_ns=12,
            process_key=key,
            process_id=100 + index,
            rss_bytes=1_000 + index,
            open_fd_count=10 + index,
        )
        for index, key in enumerate(_process_keys())
    )


def _install_artifact(
    root: Path,
    relative_path: str,
    plain: bytes,
    *,
    compressed: bytes | None = None,
) -> GateArtifactRefV1:
    encoded = (
        zstandard.ZstdCompressor(level=3, write_checksum=True).compress(plain)
        if compressed is None
        else compressed
    )
    target = root / relative_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(encoded)
    return GateArtifactRefV1(
        relative_path=relative_path,
        row_count=(
            plain.count(b"\n") + (1 if plain and not plain.endswith(b"\n") else 0)
        ),
        content_size_bytes=len(plain),
        content_sha256=_sha(plain),
        compressed_size_bytes=len(encoded),
        compressed_sha256=_sha(encoded),
    )


def _trace_partitions(
    root: Path,
    *,
    overrides: dict[Exchange, tuple[GateAdmissionTraceV1, ...]] | None = None,
) -> tuple[
    tuple[GateExchangeArtifactPartitionV1, ...],
    tuple[GateAdmissionTraceV1, ...],
]:
    root.mkdir(parents=True, exist_ok=True)
    rows: list[GateAdmissionTraceV1] = []
    partitions: list[GateExchangeArtifactPartitionV1] = []
    for exchange_index, exchange in enumerate(CANONICAL_EXCHANGES):
        exchange_rows = (
            overrides[exchange]
            if overrides is not None and exchange in overrides
            else (
                _trace(
                    exchange, exchange_index * 2, due_monotonic_ns=100 + exchange_index
                ),
                _trace(
                    exchange,
                    exchange_index * 2 + 1,
                    due_monotonic_ns=200 + exchange_index,
                ),
            )
        )
        rows.extend(exchange_rows)
        artifact = write_jsonl_zstd(
            root,
            f"traces/{exchange.value}.jsonl.zst",
            exchange_rows,
            zstd_level=3,
        )
        partitions.append(
            GateExchangeArtifactPartitionV1(exchange=exchange, artifact=artifact)
        )
    return tuple(partitions), tuple(rows)


def test_foundational_contract_field_order_is_frozen() -> None:
    for model_type, expected_fields in EXPECTED_FIELDS.items():
        assert tuple(model_type.model_fields) == expected_fields


def test_trace_identity_status_and_timestamps_are_strict() -> None:
    accepted = _trace(Exchange.BINANCE, 0)
    values = accepted.model_dump()

    assert accepted.accepted_identity is not None
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate(
            {
                **values,
                "admission_completed_monotonic_ns": accepted.due_monotonic_ns - 1,
            }
        )
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate(
            {**values, "deadline_monotonic_ns": accepted.due_monotonic_ns}
        )
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate({**values, "identity_index": True})
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate({**values, "extra": "forbidden"})
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate({**values, "planned_event_id": "not-a-sha"})
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate(
            {
                **values,
                "enqueue_status": EnqueueStatus.OVERFLOW,
                "accepted_identity": accepted.accepted_identity,
            }
        )
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate({**values, "accepted_identity": None})
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate(
            {
                **values,
                "accepted_identity": accepted.accepted_identity.model_copy(
                    update={"exchange": Exchange.OKX}
                ),
            }
        )
    with pytest.raises(ValidationError, match="worker instance ID"):
        GateAdmissionTraceV1.model_validate(
            {
                **values,
                "accepted_identity": accepted.accepted_identity.model_copy(
                    update={"worker_instance_id": _worker_id(Exchange.OKX)}
                ),
            }
        )


def test_bucket_actual_second_count_is_independent_of_scheduled_second() -> None:
    drain_second = GateSecondBucketV1(
        stream_group="trade",
        second_index=9,
        scheduled_count=0,
        attempted_count=0,
        accepted_count=0,
        admitted_in_actual_second_count=3,
        scheduled_payload_bytes=0,
        attempted_payload_bytes=0,
        accepted_payload_bytes=0,
        early_count=0,
        late_count=0,
        out_of_window_count=0,
    )

    assert drain_second.admitted_in_actual_second_count == 3


@pytest.mark.parametrize(
    "relative_path",
    [
        "",
        "/absolute.jsonl.zst",
        "../escape.jsonl.zst",
        "trace/./part.jsonl.zst",
        "trace//part.jsonl.zst",
        "trace\\part.jsonl.zst",
        "trace/part.jsonl.zst\x00",
        "trace/part.json",
        "trace/part.jsonl.zst.partial",
    ],
)
def test_artifact_paths_are_normalized_completed_zstd_jsonl(
    relative_path: str,
) -> None:
    with pytest.raises(ValidationError):
        GateArtifactRefV1(
            relative_path=relative_path,
            row_count=1,
            content_size_bytes=2,
            content_sha256="a" * 64,
            compressed_size_bytes=3,
            compressed_sha256="b" * 64,
        )


def test_worker_and_process_rounds_are_complete_and_canonical() -> None:
    worker_round = GateSamplingRoundV1(
        round_index=0,
        round_kind="final",
        scheduled_monotonic_ns=10,
        expected_worker_keys=_worker_keys(),
        samples=_worker_samples(),
    )
    resource_round = GateResourceSamplingRoundV1(
        round_index=0,
        scheduled_monotonic_ns=10,
        expected_process_keys=_process_keys(),
        samples=_process_samples(),
    )

    assert len(worker_round.samples) == 5
    assert len(resource_round.samples) == 6
    with pytest.raises(ValidationError):
        GateSamplingRoundV1(
            round_index=0,
            round_kind="final",
            scheduled_monotonic_ns=10,
            expected_worker_keys=_worker_keys()[:-1],
            samples=_worker_samples()[:-1],
        )
    with pytest.raises(ValidationError):
        GateSamplingRoundV1(
            round_index=0,
            round_kind="final",
            scheduled_monotonic_ns=10,
            expected_worker_keys=_worker_keys(),
            samples=_worker_samples(lifecycle=WriterLifecycle.STARTING),
        )
    with pytest.raises(ValidationError):
        GateResourceSamplingRoundV1(
            round_index=0,
            scheduled_monotonic_ns=10,
            expected_process_keys=_process_keys(),
            samples=tuple(
                sample.model_copy(update={"process_id": 100})
                for sample in _process_samples()
            ),
        )
    with pytest.raises(ValidationError):
        GateResourceSamplingRoundV1(
            round_index=0,
            scheduled_monotonic_ns=10,
            expected_process_keys=tuple(reversed(_process_keys())),
            samples=tuple(reversed(_process_samples())),
        )


def test_storage_health_requires_five_canonical_workers() -> None:
    workers = tuple(
        GateWorkerHealthV1(
            exchange=exchange,
            worker_instance_id=_worker_id(exchange),
            lifecycle=WriterLifecycle.STARTING,
            critical_reason=None,
        )
        for exchange in CANONICAL_EXCHANGES
    )
    sample = GateStorageHealthSampleV1(
        round_index=0,
        scheduled_monotonic_ns=10,
        request_started_monotonic_ns=11,
        request_completed_monotonic_ns=12,
        data_available_bytes=1_000,
        state_available_bytes=2_000,
        workers=workers,
    )

    assert sample.workers == workers
    with pytest.raises(ValidationError):
        GateStorageHealthSampleV1.model_validate(
            {**sample.model_dump(), "workers": tuple(reversed(workers))}
        )


def test_jsonl_zstd_round_trip_and_semantic_hash_ignore_frame_variation(
    tmp_path: Path,
) -> None:
    rows = tuple(_bucket(index) for index in range(200))

    first = write_jsonl_zstd(tmp_path, "buckets/a.jsonl.zst", rows, zstd_level=3)
    second = write_jsonl_zstd(tmp_path, "buckets/b.jsonl.zst", rows, zstd_level=19)

    assert first.content_sha256 == second.content_sha256
    assert first.content_size_bytes == second.content_size_bytes
    assert first.compressed_sha256 != second.compressed_sha256
    assert (
        tuple(
            iter_jsonl_zstd(
                tmp_path,
                first,
                GateSecondBucketV1,
                max_rows=200,
                max_content_bytes=first.content_size_bytes,
                max_line_bytes=1_024,
            )
        )
        == rows
    )


def test_codec_rejects_permissive_rows_and_boolean_limits(tmp_path: Path) -> None:
    class PermissiveRow(BaseModel):
        value: int

        def canonical_bytes(self) -> bytes:
            return encode_json(self.model_dump(mode="json")) + b"\n"

    with pytest.raises(TypeError, match="frozen, strict, and extra-forbid"):
        write_jsonl_zstd(
            tmp_path,
            "invalid/permissive.jsonl.zst",
            (PermissiveRow(value=1),),
            zstd_level=3,
        )
    with pytest.raises(ValueError, match="positive integer"):
        write_jsonl_zstd(
            tmp_path,
            "invalid/level.jsonl.zst",
            (_bucket(),),
            zstd_level=cast(Any, True),
        )
    with pytest.raises(TypeError, match="one exact model type"):
        write_jsonl_zstd(
            tmp_path,
            "invalid/mixed.jsonl.zst",
            cast(Any, (_bucket(), _trace(Exchange.BINANCE, 0))),
            zstd_level=3,
        )

    artifact = write_jsonl_zstd(
        tmp_path, "valid/limits.jsonl.zst", (_bucket(),), zstd_level=3
    )
    with pytest.raises(ValueError, match="positive integer"):
        tuple(
            iter_jsonl_zstd(
                tmp_path,
                artifact,
                GateSecondBucketV1,
                max_rows=cast(Any, True),
                max_content_bytes=10_000,
                max_line_bytes=10_000,
            )
        )


def test_codec_rejects_symlink_roots_parents_and_files(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    linked_root = tmp_path / "linked-root"
    linked_root.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="non-symlink directory"):
        write_jsonl_zstd(linked_root, "trace.jsonl.zst", (_bucket(),), zstd_level=3)

    linked_parent = tmp_path / "linked-parent"
    linked_parent.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="real directories"):
        write_jsonl_zstd(
            tmp_path,
            "linked-parent/trace.jsonl.zst",
            (_bucket(),),
            zstd_level=3,
        )
    assert not (outside / "trace.jsonl.zst").exists()
    assert not (outside / "trace.jsonl.zst.partial").exists()

    artifact = write_jsonl_zstd(
        tmp_path, "real/trace.jsonl.zst", (_bucket(),), zstd_level=3
    )
    linked_file = tmp_path / "real/linked.jsonl.zst"
    linked_file.symlink_to(tmp_path / artifact.relative_path)
    linked_ref = artifact.model_copy(update={"relative_path": "real/linked.jsonl.zst"})
    with pytest.raises(OSError):
        tuple(
            iter_jsonl_zstd(
                tmp_path,
                linked_ref,
                GateSecondBucketV1,
                max_rows=1,
                max_content_bytes=10_000,
                max_line_bytes=10_000,
            )
        )


def test_jsonl_reader_enforces_all_bounds(tmp_path: Path) -> None:
    rows = (_bucket(0), _bucket(1))
    artifact = write_jsonl_zstd(
        tmp_path, "buckets/bounded.jsonl.zst", rows, zstd_level=3
    )
    common = (tmp_path, artifact, GateSecondBucketV1)

    with pytest.raises(ValueError, match="row bound"):
        tuple(
            iter_jsonl_zstd(
                *common,
                max_rows=1,
                max_content_bytes=artifact.content_size_bytes,
                max_line_bytes=1_024,
            )
        )
    with pytest.raises(ValueError, match="content byte bound"):
        tuple(
            iter_jsonl_zstd(
                *common,
                max_rows=2,
                max_content_bytes=artifact.content_size_bytes - 1,
                max_line_bytes=1_024,
            )
        )
    with pytest.raises(ValueError, match="line byte bound"):
        tuple(
            iter_jsonl_zstd(
                *common,
                max_rows=2,
                max_content_bytes=artifact.content_size_bytes,
                max_line_bytes=8,
            )
        )


@pytest.mark.parametrize(
    ("field_name", "replacement", "message"),
    [
        ("row_count", 2, "row count"),
        ("content_size_bytes", 10_000, "content size"),
        ("content_sha256", "f" * 64, "content SHA"),
    ],
)
def test_jsonl_reader_rejects_content_ref_disagreement(
    tmp_path: Path,
    field_name: str,
    replacement: object,
    message: str,
) -> None:
    artifact = write_jsonl_zstd(
        tmp_path, "buckets/ref.jsonl.zst", (_bucket(),), zstd_level=3
    )
    invalid = artifact.model_copy(update={field_name: replacement})

    with pytest.raises(ValueError, match=message):
        tuple(
            iter_jsonl_zstd(
                tmp_path,
                invalid,
                GateSecondBucketV1,
                max_rows=2,
                max_content_bytes=20_000,
                max_line_bytes=10_000,
            )
        )


def test_empty_artifact_round_trip_is_canonical(tmp_path: Path) -> None:
    artifact = write_jsonl_zstd(tmp_path, "empty/rows.jsonl.zst", (), zstd_level=3)

    assert artifact.row_count == 0
    assert artifact.content_size_bytes == 0
    assert artifact.content_sha256 == _sha(b"")
    assert (
        tuple(
            iter_jsonl_zstd(
                tmp_path,
                artifact,
                GateSecondBucketV1,
                max_rows=1,
                max_content_bytes=1,
                max_line_bytes=1,
            )
        )
        == ()
    )


def test_streaming_writer_publishes_on_successful_context_exit(
    tmp_path: Path,
) -> None:
    writer = StreamingJsonlZstdWriter(
        tmp_path,
        "streaming/buckets.jsonl.zst",
        zstd_level=3,
    )

    with writer:
        writer.write(_bucket())
        writer.write(_bucket(1))

    assert writer.artifact_ref.row_count == 2
    assert tuple(
        iter_jsonl_zstd(
            tmp_path,
            writer.artifact_ref,
            GateSecondBucketV1,
            max_rows=2,
            max_content_bytes=20_000,
            max_line_bytes=10_000,
        )
    ) == (_bucket(), _bucket(1))


def test_streaming_writer_accepts_guarded_trusted_chunks(tmp_path: Path) -> None:
    rows = (_bucket(), _bucket(1))
    chunk = b"".join(row.canonical_bytes() for row in rows)
    writer = StreamingJsonlZstdWriter(
        tmp_path,
        "streaming/trusted-chunk.jsonl.zst",
        zstd_level=3,
    )

    writer.write_trusted_lines(chunk, GateSecondBucketV1, row_count=2)
    artifact = writer.close()

    assert artifact.row_count == 2
    assert artifact.content_size_bytes == len(chunk)
    assert artifact.content_sha256 == _sha(chunk)
    assert (
        tuple(
            iter_jsonl_zstd(
                tmp_path,
                artifact,
                GateSecondBucketV1,
                max_rows=2,
                max_content_bytes=20_000,
                max_line_bytes=10_000,
            )
        )
        == rows
    )


def test_streaming_writer_rejects_untrusted_chunk_row_count(tmp_path: Path) -> None:
    writer = StreamingJsonlZstdWriter(
        tmp_path,
        "streaming/invalid-trusted-chunk.jsonl.zst",
        zstd_level=3,
    )
    chunk = _bucket().canonical_bytes() + _bucket(1).canonical_bytes()
    try:
        with pytest.raises(ValueError, match="row count"):
            writer.write_trusted_lines(chunk, GateSecondBucketV1, row_count=1)
    finally:
        writer.abort()


def test_streaming_writer_retains_partial_on_error(tmp_path: Path) -> None:
    destination = "streaming/error.jsonl.zst"

    with (
        pytest.raises(RuntimeError, match="injected"),
        StreamingJsonlZstdWriter(
            tmp_path,
            destination,
            zstd_level=3,
        ) as writer,
    ):
        writer.write(_bucket())
        raise RuntimeError("injected")

    assert not (tmp_path / destination).exists()
    assert (tmp_path / f"{destination}.partial").is_file()


def test_jsonl_reader_rejects_noncanonical_missing_newline_and_duplicate_key(
    tmp_path: Path,
) -> None:
    canonical = _bucket().canonical_bytes()
    reordered = (
        encode_json(dict(reversed(tuple(_bucket().model_dump(mode="json").items()))))
        + b"\n"
    )
    duplicate = b'{"schema_version":1,' + canonical[1:]

    for index, plain in enumerate((reordered, canonical[:-1], duplicate)):
        artifact = _install_artifact(tmp_path, f"invalid/{index}.jsonl.zst", plain)
        with pytest.raises(ValueError):
            tuple(
                iter_jsonl_zstd(
                    tmp_path,
                    artifact,
                    GateSecondBucketV1,
                    max_rows=2,
                    max_content_bytes=10_000,
                    max_line_bytes=10_000,
                )
            )


def test_jsonl_reader_rejects_malformed_and_trailing_zstd_bytes(
    tmp_path: Path,
) -> None:
    canonical = _bucket().canonical_bytes()
    frame = zstandard.ZstdCompressor(level=3, write_checksum=True).compress(canonical)
    cases = (b"not-zstd", frame + b"trailing")

    for index, compressed in enumerate(cases):
        artifact = _install_artifact(
            tmp_path,
            f"frames/{index}.jsonl.zst",
            canonical,
            compressed=compressed,
        )
        with pytest.raises(ValueError):
            tuple(
                iter_jsonl_zstd(
                    tmp_path,
                    artifact,
                    GateSecondBucketV1,
                    max_rows=1,
                    max_content_bytes=len(canonical),
                    max_line_bytes=len(canonical),
                )
            )


def test_writer_never_replaces_and_retains_failed_partial(tmp_path: Path) -> None:
    first = write_jsonl_zstd(
        tmp_path, "buckets/immutable.jsonl.zst", (_bucket(0),), zstd_level=3
    )
    final_path = tmp_path / first.relative_path
    original = final_path.read_bytes()

    with pytest.raises(PublicationConflict):
        write_jsonl_zstd(tmp_path, first.relative_path, (_bucket(1),), zstd_level=3)

    assert final_path.read_bytes() == original
    assert final_path.with_name(final_path.name + ".partial").is_file()

    def failing_rows() -> Iterator[GateSecondBucketV1]:
        yield _bucket(2)
        raise RuntimeError("injected row failure")

    failed_path = tmp_path / "buckets/failed.jsonl.zst"
    with pytest.raises(RuntimeError, match="injected row failure"):
        write_jsonl_zstd(
            tmp_path, "buckets/failed.jsonl.zst", failing_rows(), zstd_level=3
        )
    assert not failed_path.exists()
    assert failed_path.with_name(failed_path.name + ".partial").is_file()


def test_writer_fsyncs_file_then_uses_explicit_hardlink_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[tuple[str, object]] = []
    original_fsync = os.fsync
    original_publish = artifacts_module.publish_no_replace

    def recording_fsync(fd: int) -> None:
        events.append(("fsync", stat.S_IFMT(os.fstat(fd).st_mode)))
        original_fsync(fd)

    def recording_publish(
        source: Path,
        destination: Path,
        *,
        capability: NoReplaceCapability | None = None,
        expected_source_fd: int | None = None,
        phase_hook: object = None,
    ) -> None:
        assert expected_source_fd is not None
        assert os.fstat(expected_source_fd).st_size > 0
        with pytest.raises(OSError) as error:
            os.write(expected_source_fd, b"x")
        assert error.value.errno == errno.EBADF
        events.append(("publish", capability))
        original_publish(
            source,
            destination,
            capability=capability,
            expected_source_fd=expected_source_fd,
            phase_hook=cast(Any, phase_hook),
        )

    monkeypatch.setattr(os, "fsync", recording_fsync)
    monkeypatch.setattr(artifacts_module, "publish_no_replace", recording_publish)

    write_jsonl_zstd(tmp_path, "ordered/trace.jsonl.zst", (_bucket(),), zstd_level=3)

    publish_index = events.index(("publish", NoReplaceCapability.HARDLINK))
    assert any(event == ("fsync", stat.S_IFREG) for event in events[:publish_index])
    assert any(
        event == ("fsync", stat.S_IFDIR) for event in events[publish_index + 1 :]
    )


def test_five_trace_partitions_merge_to_exact_virtual_content(tmp_path: Path) -> None:
    partitions, unordered_rows = _trace_partitions(tmp_path)
    expected = tuple(
        sorted(
            unordered_rows,
            key=lambda row: (row.due_monotonic_ns, row.planned_event_id),
        )
    )
    expected_content = b"".join(row.canonical_bytes() for row in expected)

    trace_set = build_admission_trace_set(
        tmp_path,
        partitions,
        max_rows=len(expected),
        max_content_bytes=len(expected_content),
        max_line_bytes=max(len(row.canonical_bytes()) for row in expected),
    )

    assert trace_set.partitions == partitions
    assert trace_set.merged_row_count == len(expected)
    assert trace_set.merged_content_size_bytes == len(expected_content)
    assert trace_set.merged_content_sha256 == _sha(expected_content)
    assert (
        tuple(
            iter_merged_trace_partitions(
                tmp_path,
                partitions,
                max_rows=len(expected),
                max_content_bytes=len(expected_content),
                max_line_bytes=max(len(row.canonical_bytes()) for row in expected),
            )
        )
        == expected
    )
    assert len(tuple((tmp_path / "traces").glob("*.jsonl.zst"))) == 5


@pytest.mark.parametrize("mutation", ["missing", "duplicate", "reordered"])
def test_trace_partitions_require_exact_canonical_exchange_set(
    tmp_path: Path,
    mutation: str,
) -> None:
    partitions, rows = _trace_partitions(tmp_path)
    if mutation == "missing":
        candidate = partitions[:-1]
    elif mutation == "duplicate":
        candidate = (*partitions, partitions[-1])
    else:
        candidate = (partitions[1], partitions[0], *partitions[2:])

    with pytest.raises((TypeError, ValueError, ValidationError)):
        build_admission_trace_set(
            tmp_path,
            candidate,
            max_rows=len(rows),
            max_content_bytes=sum(len(row.canonical_bytes()) for row in rows),
            max_line_bytes=2_000,
        )


def test_trace_merge_rejects_cross_exchange_unsorted_and_id_collision(
    tmp_path: Path,
) -> None:
    cross_root = tmp_path / "cross"
    cross, cross_rows = _trace_partitions(
        cross_root,
        overrides={Exchange.BINANCE: (_trace(Exchange.OKX, 100),)},
    )
    with pytest.raises(ValueError, match="partition exchange"):
        tuple(
            iter_merged_trace_partitions(
                cross_root,
                cross,
                max_rows=len(cross_rows),
                max_content_bytes=100_000,
                max_line_bytes=2_000,
            )
        )

    unsorted_root = tmp_path / "unsorted"
    later = _trace(Exchange.BINANCE, 101, due_monotonic_ns=500)
    earlier = _trace(Exchange.BINANCE, 102, due_monotonic_ns=400)
    unsorted, unsorted_rows = _trace_partitions(
        unsorted_root,
        overrides={Exchange.BINANCE: (later, earlier)},
    )
    with pytest.raises(ValueError, match="internally sorted"):
        tuple(
            iter_merged_trace_partitions(
                unsorted_root,
                unsorted,
                max_rows=len(unsorted_rows),
                max_content_bytes=100_000,
                max_line_bytes=2_000,
            )
        )

    collision_root = tmp_path / "collision"
    collision_id = "f" * 64
    collision, collision_rows = _trace_partitions(
        collision_root,
        overrides={
            Exchange.BINANCE: (
                _trace(
                    Exchange.BINANCE,
                    201,
                    due_monotonic_ns=100,
                    planned_event_id=collision_id,
                ),
            ),
            Exchange.KRAKEN: (
                _trace(
                    Exchange.KRAKEN,
                    202,
                    due_monotonic_ns=900,
                    planned_event_id=collision_id,
                ),
            ),
        },
    )
    with pytest.raises(ValueError, match="planned event ID collision"):
        tuple(
            iter_merged_trace_partitions(
                collision_root,
                collision,
                max_rows=len(collision_rows),
                max_content_bytes=100_000,
                max_line_bytes=2_000,
            )
        )


def test_trace_set_rejects_merged_count_and_size_disagreement(tmp_path: Path) -> None:
    partitions, rows = _trace_partitions(tmp_path)
    trace_set = build_admission_trace_set(
        tmp_path,
        partitions,
        max_rows=len(rows),
        max_content_bytes=100_000,
        max_line_bytes=2_000,
    )

    with pytest.raises(ValidationError):
        GateAdmissionTraceSetV1.model_validate(
            {**trace_set.model_dump(), "merged_row_count": len(rows) - 1}
        )
    with pytest.raises(ValidationError):
        GateAdmissionTraceSetV1.model_validate(
            {
                **trace_set.model_dump(),
                "merged_content_size_bytes": trace_set.merged_content_size_bytes - 1,
            }
        )


def test_reader_validates_compressed_size_and_sha_before_decompression(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = write_jsonl_zstd(
        tmp_path, "buckets/hash-first.jsonl.zst", (_bucket(),), zstd_level=3
    )
    touched = False
    original = artifacts_module._iter_zstd_plain_chunks

    def recording_chunks(fd: int, compressed_size: int) -> Iterator[bytes]:
        nonlocal touched
        touched = True
        yield from original(fd, compressed_size)

    monkeypatch.setattr(artifacts_module, "_iter_zstd_plain_chunks", recording_chunks)
    invalid = artifact.model_copy(update={"compressed_sha256": "f" * 64})

    with pytest.raises(ValueError, match="compressed SHA"):
        tuple(
            iter_jsonl_zstd(
                tmp_path,
                invalid,
                GateSecondBucketV1,
                max_rows=1,
                max_content_bytes=10_000,
                max_line_bytes=10_000,
            )
        )
    assert not touched
