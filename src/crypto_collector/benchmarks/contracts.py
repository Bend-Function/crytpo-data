from __future__ import annotations

import re
from decimal import Decimal
from hashlib import sha256
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    StringConstraints,
    model_validator,
)

from crypto_collector.domain.envelope import FrozenStrictModel
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.domain.types import Exchange, Market
from crypto_collector.storage.durability import WriterCriticalReason
from crypto_collector.storage.models import (
    AcceptedRecordIdentityV1,
    EnqueueStatus,
    SchemaVersion1,
    Sha256,
    WriterLifecycle,
    WriterMetricsSnapshotV1,
    validate_normalized_data_relative_path,
)
from crypto_collector.storage.stats import DURABILITY_BUCKET_UPPER_BOUNDS_NS

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]
PositiveSignedInt64 = Annotated[int, Field(gt=0, le=2**63 - 1)]
StreamGroup = Literal[
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "derivative",
    "candle_1m",
    "book_deep_snapshot",
    "control",
]
LogicalStream = Literal[
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "funding",
    "open_interest",
    "candle_1m",
    "book_deep_snapshot",
    "_control",
]
ProcessRole = Literal["supervisor", "exchange_worker"]

CANONICAL_EXCHANGES = (
    Exchange.BINANCE,
    Exchange.OKX,
    Exchange.BYBIT,
    Exchange.BITGET,
    Exchange.KRAKEN,
)
EMPTY_SHA256 = sha256(b"").hexdigest()
_CANONICAL_NONNEGATIVE_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")


def _worker_instance_id(exchange: Exchange) -> str:
    return f"gate-worker-v1-{exchange.value}"


def _validate_artifact_relative_path(value: str) -> str:
    normalized = validate_normalized_data_relative_path(value)
    if not normalized.endswith(".jsonl.zst"):
        raise ValueError("artifact path must end with .jsonl.zst")
    return normalized


ArtifactRelativePath = Annotated[str, AfterValidator(_validate_artifact_relative_path)]


def _normalize_nonnegative_decimal(value: object) -> Decimal:
    if type(value) is str:
        if _CANONICAL_NONNEGATIVE_DECIMAL.fullmatch(value) is None:
            raise ValueError("value must be a canonical non-negative decimal string")
        return Decimal(value)
    if type(value) is not Decimal:
        raise ValueError("value must be a Decimal or canonical decimal string")
    if not value.is_finite() or value < 0:
        raise ValueError("value must be a finite non-negative Decimal")
    rendered = format(value, "f")
    if value == 0:
        rendered = "0"
    elif "." in rendered:
        rendered = rendered.rstrip("0").rstrip(".")
    if _CANONICAL_NONNEGATIVE_DECIMAL.fullmatch(rendered) is None:
        raise ValueError("value cannot be normalized as a canonical decimal")
    return Decimal(rendered)


CanonicalNonNegativeDecimal = Annotated[
    Decimal,
    BeforeValidator(_normalize_nonnegative_decimal),
]


class _GateContract(FrozenStrictModel):
    def canonical_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="json")) + b"\n"


class GateArtifactRefV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_artifact_ref_v1"] = "gate_artifact_ref_v1"
    relative_path: ArtifactRelativePath
    row_count: NonNegativeInt
    content_size_bytes: NonNegativeInt
    content_sha256: Sha256
    compressed_size_bytes: PositiveInt
    compressed_sha256: Sha256

    @model_validator(mode="after")
    def validate_content_facts(self) -> Self:
        if (self.row_count == 0) != (self.content_size_bytes == 0):
            raise ValueError("artifact row and content byte zero states must agree")
        if self.content_size_bytes == 0 and self.content_sha256 != EMPTY_SHA256:
            raise ValueError("empty artifact content must use the empty SHA-256")
        return self


class GateExchangeArtifactPartitionV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_exchange_artifact_partition_v1"] = (
        "gate_exchange_artifact_partition_v1"
    )
    exchange: Exchange
    artifact: GateArtifactRefV1


def _validate_canonical_partitions(
    partitions: tuple[GateExchangeArtifactPartitionV1, ...],
) -> None:
    exchanges = tuple(partition.exchange for partition in partitions)
    if exchanges != CANONICAL_EXCHANGES:
        raise ValueError("trace partitions must use all exchanges in canonical order")
    paths = tuple(partition.artifact.relative_path for partition in partitions)
    if len(set(paths)) != len(paths):
        raise ValueError("trace partition artifact paths must be unique")


class GateAdmissionTraceSetV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_admission_trace_set_v1"] = "gate_admission_trace_set_v1"
    partitions: tuple[GateExchangeArtifactPartitionV1, ...]
    merged_row_count: NonNegativeInt
    merged_content_size_bytes: NonNegativeInt
    merged_content_sha256: Sha256

    @model_validator(mode="after")
    def validate_merged_facts(self) -> Self:
        _validate_canonical_partitions(self.partitions)
        if self.merged_row_count != sum(
            partition.artifact.row_count for partition in self.partitions
        ):
            raise ValueError("merged trace row count must equal its partition sum")
        if self.merged_content_size_bytes != sum(
            partition.artifact.content_size_bytes for partition in self.partitions
        ):
            raise ValueError("merged trace content size must equal its partition sum")
        if (self.merged_row_count == 0) != (self.merged_content_size_bytes == 0):
            raise ValueError("merged trace row and byte zero states must agree")
        if (
            self.merged_content_size_bytes == 0
            and self.merged_content_sha256 != EMPTY_SHA256
        ):
            raise ValueError("empty merged trace must use the empty SHA-256")
        return self


class GateAdmissionTraceV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_admission_trace_v1"] = "gate_admission_trace_v1"
    planned_event_id: Sha256
    stream_group: StreamGroup
    logical_stream: LogicalStream
    exchange: Exchange
    market: Market | None
    instrument_key: NonEmptyString | None
    canonical_identity: NonEmptyString
    identity_index: NonNegativeInt
    local_sequence: NonNegativeInt
    due_monotonic_ns: NonNegativeInt
    deadline_monotonic_ns: PositiveInt
    attempt_started_monotonic_ns: NonNegativeInt
    admission_completed_monotonic_ns: NonNegativeInt
    enqueue_status: EnqueueStatus
    payload_bytes: PositiveInt
    payload_sha256: Sha256
    accepted_identity: AcceptedRecordIdentityV1 | None

    @model_validator(mode="after")
    def validate_trace(self) -> Self:
        if self.due_monotonic_ns >= self.deadline_monotonic_ns:
            raise ValueError("trace due time must precede its deadline")
        if self.attempt_started_monotonic_ns > self.admission_completed_monotonic_ns:
            raise ValueError("trace attempt start must not follow admission completion")
        if self.stream_group == "control":
            if (
                self.logical_stream != "_control"
                or self.market is not None
                or self.instrument_key is not None
            ):
                raise ValueError("control trace routing fields are invalid")
            expected_identity = f"gate-identity-v1:{self.exchange.value}:-:-:_control"
        else:
            if self.stream_group == "derivative":
                if self.logical_stream not in {"funding", "open_interest"}:
                    raise ValueError("derivative trace logical stream is invalid")
            elif self.logical_stream != self.stream_group:
                raise ValueError("trace stream group and logical stream must agree")
            if self.market is None or self.instrument_key is None:
                raise ValueError("non-control trace requires market and instrument")
            expected_identity = (
                f"gate-identity-v1:{self.exchange.value}:{self.market.value}:"
                f"{self.instrument_key}:{self.logical_stream}"
            )
        if self.canonical_identity != expected_identity:
            raise ValueError("trace canonical identity does not match routing fields")

        accepted = self.enqueue_status in {
            EnqueueStatus.ACCEPTED,
            EnqueueStatus.ACCEPTED_HIGH_WATER,
        }
        if accepted != (self.accepted_identity is not None):
            raise ValueError("trace enqueue status and accepted identity must agree")
        if self.accepted_identity is not None:
            identity = self.accepted_identity
            expected_route = (
                self.exchange,
                self.market,
                self.instrument_key,
                self.logical_stream,
            )
            observed_route = (
                identity.exchange,
                identity.market,
                identity.instrument_key,
                identity.logical_stream,
            )
            if observed_route != expected_route:
                raise ValueError("accepted identity routing must match the trace")
        return self


class GateSecondBucketV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_second_bucket_v1"] = "gate_second_bucket_v1"
    stream_group: StreamGroup
    second_index: NonNegativeInt
    scheduled_count: NonNegativeInt
    attempted_count: NonNegativeInt
    accepted_count: NonNegativeInt
    admitted_in_actual_second_count: NonNegativeInt
    scheduled_payload_bytes: NonNegativeInt
    attempted_payload_bytes: NonNegativeInt
    accepted_payload_bytes: NonNegativeInt
    early_count: NonNegativeInt
    late_count: NonNegativeInt
    out_of_window_count: NonNegativeInt

    @model_validator(mode="after")
    def validate_bucket(self) -> Self:
        if not self.accepted_count <= self.attempted_count <= self.scheduled_count:
            raise ValueError(
                "bucket record counts must satisfy accepted <= attempted <= scheduled"
            )
        if not (
            self.accepted_payload_bytes
            <= self.attempted_payload_bytes
            <= self.scheduled_payload_bytes
        ):
            raise ValueError("bucket payload bytes must follow record stage ordering")
        for count, byte_count, stage in (
            (self.scheduled_count, self.scheduled_payload_bytes, "scheduled"),
            (self.attempted_count, self.attempted_payload_bytes, "attempted"),
            (self.accepted_count, self.accepted_payload_bytes, "accepted"),
        ):
            if (count == 0) != (byte_count == 0):
                raise ValueError(
                    f"bucket {stage} count and byte zero states must agree"
                )
        if any(
            value > self.attempted_count
            for value in (self.early_count, self.late_count, self.out_of_window_count)
        ):
            raise ValueError("bucket timing failures cannot exceed attempted records")
        return self


class GateWorkerKeyV1(_GateContract):
    exchange: Exchange
    worker_instance_id: NonEmptyString

    @model_validator(mode="after")
    def validate_worker(self) -> Self:
        if self.worker_instance_id != _worker_instance_id(self.exchange):
            raise ValueError("worker instance ID does not match its exchange")
        return self


class GateWorkerSampleV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_worker_sample_v1"] = "gate_worker_sample_v1"
    round_index: NonNegativeInt
    round_kind: NonEmptyString
    scheduled_monotonic_ns: NonNegativeInt
    request_started_monotonic_ns: NonNegativeInt
    request_completed_monotonic_ns: NonNegativeInt
    snapshot: WriterMetricsSnapshotV1

    @model_validator(mode="after")
    def validate_sample(self) -> Self:
        if not (
            self.scheduled_monotonic_ns
            <= self.request_started_monotonic_ns
            <= self.request_completed_monotonic_ns
        ):
            raise ValueError("worker sample request timing is invalid")
        if self.snapshot.worker_instance_id != _worker_instance_id(
            self.snapshot.exchange
        ):
            raise ValueError("worker snapshot identity is not canonical")
        if (
            self.round_kind == "final"
            and self.snapshot.lifecycle is not WriterLifecycle.CLOSED
        ):
            raise ValueError("final worker sample requires a CLOSED snapshot")
        return self


def _canonical_worker_pairs() -> tuple[tuple[Exchange, str], ...]:
    return tuple(
        (exchange, _worker_instance_id(exchange)) for exchange in CANONICAL_EXCHANGES
    )


class GateSamplingRoundV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_sampling_round_v1"] = "gate_sampling_round_v1"
    round_index: NonNegativeInt
    round_kind: NonEmptyString
    scheduled_monotonic_ns: NonNegativeInt
    expected_worker_keys: tuple[GateWorkerKeyV1, ...]
    samples: tuple[GateWorkerSampleV1, ...]

    @model_validator(mode="after")
    def validate_round(self) -> Self:
        expected_pairs = tuple(
            (key.exchange, key.worker_instance_id) for key in self.expected_worker_keys
        )
        if expected_pairs != _canonical_worker_pairs():
            raise ValueError("sampling round must declare five canonical workers")
        observed_pairs = tuple(
            (sample.snapshot.exchange, sample.snapshot.worker_instance_id)
            for sample in self.samples
        )
        if observed_pairs != expected_pairs:
            raise ValueError(
                "sampling round must contain one ordered sample per worker"
            )
        if any(
            sample.round_index != self.round_index
            or sample.round_kind != self.round_kind
            or sample.scheduled_monotonic_ns != self.scheduled_monotonic_ns
            for sample in self.samples
        ):
            raise ValueError("worker sample parent fields do not match their round")
        return self


class GateProcessKeyV1(_GateContract):
    role: ProcessRole
    exchange: Exchange | None
    worker_instance_id: NonEmptyString | None

    @model_validator(mode="after")
    def validate_process(self) -> Self:
        if self.role == "supervisor":
            if self.exchange is not None or self.worker_instance_id is not None:
                raise ValueError("supervisor process key must be unscoped")
        elif self.exchange is None or self.worker_instance_id != _worker_instance_id(
            self.exchange
        ):
            raise ValueError("exchange worker process key is invalid")
        return self


class GateProcessResourceSampleV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_process_resource_sample_v1"] = (
        "gate_process_resource_sample_v1"
    )
    round_index: NonNegativeInt
    scheduled_monotonic_ns: NonNegativeInt
    request_started_monotonic_ns: NonNegativeInt
    request_completed_monotonic_ns: NonNegativeInt
    process_key: GateProcessKeyV1
    process_id: PositiveSignedInt64
    rss_bytes: NonNegativeInt
    open_fd_count: NonNegativeInt

    @model_validator(mode="after")
    def validate_sample(self) -> Self:
        if not (
            self.scheduled_monotonic_ns
            <= self.request_started_monotonic_ns
            <= self.request_completed_monotonic_ns
        ):
            raise ValueError("process sample request timing is invalid")
        return self


def _canonical_process_pairs() -> tuple[tuple[str, Exchange | None, str | None], ...]:
    return (
        ("supervisor", None, None),
        *(
            ("exchange_worker", exchange, _worker_instance_id(exchange))
            for exchange in CANONICAL_EXCHANGES
        ),
    )


class GateResourceSamplingRoundV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_resource_sampling_round_v1"] = (
        "gate_resource_sampling_round_v1"
    )
    round_index: NonNegativeInt
    scheduled_monotonic_ns: NonNegativeInt
    expected_process_keys: tuple[GateProcessKeyV1, ...]
    samples: tuple[GateProcessResourceSampleV1, ...]

    @model_validator(mode="after")
    def validate_round(self) -> Self:
        expected_pairs = tuple(
            (key.role, key.exchange, key.worker_instance_id)
            for key in self.expected_process_keys
        )
        if expected_pairs != _canonical_process_pairs():
            raise ValueError("resource round must declare six canonical processes")
        observed_pairs = tuple(
            (
                sample.process_key.role,
                sample.process_key.exchange,
                sample.process_key.worker_instance_id,
            )
            for sample in self.samples
        )
        if observed_pairs != expected_pairs:
            raise ValueError(
                "resource round must contain one ordered sample per process"
            )
        if any(
            sample.round_index != self.round_index
            or sample.scheduled_monotonic_ns != self.scheduled_monotonic_ns
            for sample in self.samples
        ):
            raise ValueError("process sample parent fields do not match their round")
        process_ids = tuple(sample.process_id for sample in self.samples)
        if len(process_ids) != len(set(process_ids)):
            raise ValueError("resource round process IDs must be unique")
        return self


class GateWorkerHealthV1(_GateContract):
    exchange: Exchange
    worker_instance_id: NonEmptyString
    lifecycle: WriterLifecycle
    critical_reason: WriterCriticalReason | None

    @model_validator(mode="after")
    def validate_health(self) -> Self:
        if self.worker_instance_id != _worker_instance_id(self.exchange):
            raise ValueError("worker health identity is not canonical")
        if (self.lifecycle is WriterLifecycle.CRITICAL) != (
            self.critical_reason is not None
        ):
            raise ValueError("worker health lifecycle and critical reason must agree")
        return self


class GateStorageHealthSampleV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_storage_health_sample_v1"] = (
        "gate_storage_health_sample_v1"
    )
    round_index: NonNegativeInt
    scheduled_monotonic_ns: NonNegativeInt
    request_started_monotonic_ns: NonNegativeInt
    request_completed_monotonic_ns: NonNegativeInt
    data_available_bytes: NonNegativeInt
    state_available_bytes: NonNegativeInt
    workers: tuple[GateWorkerHealthV1, ...]

    @model_validator(mode="after")
    def validate_sample(self) -> Self:
        if not (
            self.scheduled_monotonic_ns
            <= self.request_started_monotonic_ns
            <= self.request_completed_monotonic_ns
        ):
            raise ValueError("storage health request timing is invalid")
        observed_pairs = tuple(
            (worker.exchange, worker.worker_instance_id) for worker in self.workers
        )
        if observed_pairs != _canonical_worker_pairs():
            raise ValueError("storage health must contain five canonical workers")
        return self


def _summary_nearest_rank(
    bucket_counts: tuple[int, ...], *, sample_count: int, numerator: int
) -> int | None:
    if sample_count == 0:
        return None
    rank = max(1, (numerator * sample_count + 99) // 100)
    cumulative = 0
    for upper_bound, count in zip(
        DURABILITY_BUCKET_UPPER_BOUNDS_NS,
        bucket_counts,
        strict=True,
    ):
        cumulative += count
        if cumulative >= rank:
            return upper_bound
    raise ValueError("histogram buckets do not contain their declared samples")


def _validate_summary_histogram(
    *,
    bucket_counts: tuple[int, ...],
    sample_count: int,
    p50_ns: int | None,
    p95_ns: int | None,
    p99_ns: int | None,
    max_ns: int | None,
) -> None:
    if len(bucket_counts) != len(DURABILITY_BUCKET_UPPER_BOUNDS_NS):
        raise ValueError("summary histogram buckets do not match schema")
    if sum(bucket_counts) != sample_count:
        raise ValueError("summary histogram sample count does not match buckets")
    expected_quantiles = tuple(
        _summary_nearest_rank(
            bucket_counts,
            sample_count=sample_count,
            numerator=numerator,
        )
        for numerator in (50, 95, 99)
    )
    if (p50_ns, p95_ns, p99_ns) != expected_quantiles:
        raise ValueError("summary histogram quantiles do not match buckets")
    if sample_count == 0:
        if max_ns is not None:
            raise ValueError("empty summary histogram cannot have a maximum")
        return
    if max_ns is None:
        raise ValueError("nonempty summary histogram requires a maximum")
    highest_index = max(index for index, count in enumerate(bucket_counts) if count)
    lower_bound = (
        -1
        if highest_index == 0
        else DURABILITY_BUCKET_UPPER_BOUNDS_NS[highest_index - 1]
    )
    if not lower_bound < max_ns <= DURABILITY_BUCKET_UPPER_BOUNDS_NS[highest_index]:
        raise ValueError("summary histogram maximum does not match buckets")


class FinalWorkerAggregateV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["final_worker_aggregate_v1"] = "final_worker_aggregate_v1"
    worker_count: Literal[5]
    sampling_round_count: PositiveInt
    final_round_index: NonNegativeInt
    accepted_record_count: NonNegativeInt
    durable_record_count: NonNegativeInt
    unpersisted_record_count: NonNegativeInt
    uncertain_record_count: NonNegativeInt
    enqueue_high_water_count: NonNegativeInt
    normal_overflow_count: NonNegativeInt
    control_overflow_count: NonNegativeInt
    not_accepting_count: NonNegativeInt
    durability_histogram_schema_version: SchemaVersion1
    durability_bucket_counts: tuple[NonNegativeInt, ...]
    durability_sample_count: NonNegativeInt
    durability_lag_p50_ns: NonNegativeInt | None
    durability_lag_p95_ns: NonNegativeInt | None
    durability_lag_p99_ns: NonNegativeInt | None
    durability_lag_max_ns: NonNegativeInt | None
    sync_count: NonNegativeInt
    sync_duration_total_ns: NonNegativeInt
    sync_duration_max_ns: NonNegativeInt
    slo_breach_count: NonNegativeInt
    write_failure_count: NonNegativeInt
    sync_failure_count: NonNegativeInt
    publication_failure_count: NonNegativeInt
    unpersisted_record_count_peak: NonNegativeInt
    queued_records_peak: NonNegativeInt
    queued_bytes_peak: NonNegativeInt
    buffered_records_peak: NonNegativeInt
    buffered_bytes_peak: NonNegativeInt
    in_flight_records_peak: NonNegativeInt
    in_flight_bytes_peak: NonNegativeInt
    resident_record_bytes_peak: NonNegativeInt
    resident_control_records_peak: NonNegativeInt
    resident_control_bytes_peak: NonNegativeInt
    oldest_unpersisted_age_max_ns: NonNegativeInt | None
    active_logical_generation_count_peak: NonNegativeInt
    retiring_generation_count_peak: NonNegativeInt
    open_file_descriptor_count_peak: NonNegativeInt
    sync_inflight_peak: NonNegativeInt

    @model_validator(mode="after")
    def validate_aggregate(self) -> Self:
        if self.final_round_index != self.sampling_round_count - 1:
            raise ValueError("final round index must terminate the sampling rounds")
        if not (
            self.accepted_record_count
            == self.durable_record_count
            == self.durability_sample_count
        ):
            raise ValueError("final accepted, durable, and sampled counts must agree")
        if self.unpersisted_record_count != 0 or self.uncertain_record_count != 0:
            raise ValueError("final aggregate terminal counts must be zero")
        _validate_summary_histogram(
            bucket_counts=self.durability_bucket_counts,
            sample_count=self.durability_sample_count,
            p50_ns=self.durability_lag_p50_ns,
            p95_ns=self.durability_lag_p95_ns,
            p99_ns=self.durability_lag_p99_ns,
            max_ns=self.durability_lag_max_ns,
        )
        if (self.unpersisted_record_count_peak == 0) != (
            self.oldest_unpersisted_age_max_ns is None
        ):
            raise ValueError("unpersisted peak and oldest age zero states must agree")
        return self


class GateResourceSummaryV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_resource_summary_v1"] = "gate_resource_summary_v1"
    process_count: Literal[6]
    round_count: PositiveInt
    post_warmup_round_count: NonNegativeInt
    warmup_ended_monotonic_ns: NonNegativeInt
    resource_trend_valid: bool
    first_request_monotonic_ns: NonNegativeInt
    final_completion_monotonic_ns: NonNegativeInt
    coverage_ns: NonNegativeInt
    sample_max_gap_ns: NonNegativeInt
    rss_peak_bytes: NonNegativeInt
    rss_slope_bytes_per_minute: CanonicalNonNegativeDecimal | None
    open_fds_peak: NonNegativeInt
    first_open_fds_after_warmup: NonNegativeInt | None
    max_open_fds_after_warmup: NonNegativeInt | None
    final_open_fds_after_warmup: NonNegativeInt | None
    fd_growth_after_warmup: NonNegativeInt | None

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if self.post_warmup_round_count > self.round_count:
            raise ValueError("post-warmup round count exceeds all rounds")
        if self.final_completion_monotonic_ns < self.first_request_monotonic_ns:
            raise ValueError("resource completion precedes the first request")
        if self.coverage_ns != (
            self.final_completion_monotonic_ns - self.first_request_monotonic_ns
        ):
            raise ValueError("resource coverage does not match its boundaries")
        if (self.round_count == 1) != (self.sample_max_gap_ns == 0):
            raise ValueError("resource maximum gap does not match round cardinality")

        post_count = self.post_warmup_round_count
        fd_facts = (
            self.first_open_fds_after_warmup,
            self.max_open_fds_after_warmup,
            self.final_open_fds_after_warmup,
            self.fd_growth_after_warmup,
        )
        if self.resource_trend_valid != (post_count >= 2):
            raise ValueError("resource trend validity does not match sample count")
        if post_count == 0:
            if self.rss_slope_bytes_per_minute is not None or any(
                value is not None for value in fd_facts
            ):
                raise ValueError("zero post-warmup rounds require null trend facts")
            return self
        if any(value is None for value in fd_facts):
            raise ValueError("post-warmup rounds require complete FD trend facts")
        first_fd = self.first_open_fds_after_warmup
        maximum_fd = self.max_open_fds_after_warmup
        final_fd = self.final_open_fds_after_warmup
        growth = self.fd_growth_after_warmup
        assert first_fd is not None
        assert maximum_fd is not None
        assert final_fd is not None
        assert growth is not None
        if maximum_fd < max(first_fd, final_fd):
            raise ValueError("post-warmup FD maximum is inconsistent")
        if growth != max(0, maximum_fd - first_fd):
            raise ValueError("FD growth does not match baseline and maximum")
        if self.open_fds_peak < maximum_fd:
            raise ValueError("all-round FD peak is below the post-warmup maximum")
        if post_count == 1:
            if (
                self.rss_slope_bytes_per_minute is not None
                or first_fd != maximum_fd
                or first_fd != final_fd
                or growth != 0
            ):
                raise ValueError("one post-warmup round has invalid trend facts")
        elif self.rss_slope_bytes_per_minute is None:
            raise ValueError("valid resource trend requires an RSS slope")
        return self


class GateStorageHealthSummaryV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_storage_health_summary_v1"] = (
        "gate_storage_health_summary_v1"
    )
    duration_ns: PositiveInt
    interval_ns: PositiveInt
    sample_count: PositiveInt
    expected_min_sample_count: PositiveInt
    first_request_monotonic_ns: NonNegativeInt
    final_completion_monotonic_ns: NonNegativeInt
    coverage_ns: NonNegativeInt
    required_coverage_ns: NonNegativeInt
    sample_max_gap_ns: NonNegativeInt
    minimum_data_available_bytes: NonNegativeInt
    minimum_state_available_bytes: NonNegativeInt
    minimum_available_bytes_if_shared: NonNegativeInt
    critical_worker_observation_count: NonNegativeInt
    sample_count_valid: bool
    coverage_valid: bool
    workers_healthy: bool

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        expected_count = max(
            2,
            (self.duration_ns + self.interval_ns - 1) // self.interval_ns - 1,
        )
        if self.expected_min_sample_count != expected_count:
            raise ValueError("expected health sample count is inconsistent")
        if self.final_completion_monotonic_ns < self.first_request_monotonic_ns:
            raise ValueError("health completion precedes the first request")
        coverage = self.final_completion_monotonic_ns - self.first_request_monotonic_ns
        if self.coverage_ns != coverage:
            raise ValueError("health coverage does not match its boundaries")
        required_coverage = max(0, self.duration_ns - 2 * self.interval_ns)
        if self.required_coverage_ns != required_coverage:
            raise ValueError("required health coverage is inconsistent")
        if (self.sample_count == 1) != (self.sample_max_gap_ns == 0):
            raise ValueError("health maximum gap does not match sample cardinality")
        if self.minimum_available_bytes_if_shared != min(
            self.minimum_data_available_bytes,
            self.minimum_state_available_bytes,
        ):
            raise ValueError("conditional shared-root minimum is inconsistent")
        if self.sample_count_valid != (
            self.sample_count >= self.expected_min_sample_count
        ):
            raise ValueError("health sample-count validity is inconsistent")
        if self.coverage_valid != (self.coverage_ns >= self.required_coverage_ns):
            raise ValueError("health coverage validity is inconsistent")
        if self.workers_healthy != (self.critical_worker_observation_count == 0):
            raise ValueError("worker health validity is inconsistent")
        return self


__all__ = [
    "CANONICAL_EXCHANGES",
    "FinalWorkerAggregateV1",
    "GateAdmissionTraceSetV1",
    "GateAdmissionTraceV1",
    "GateArtifactRefV1",
    "GateExchangeArtifactPartitionV1",
    "GateProcessKeyV1",
    "GateProcessResourceSampleV1",
    "GateResourceSamplingRoundV1",
    "GateResourceSummaryV1",
    "GateSamplingRoundV1",
    "GateSecondBucketV1",
    "GateStorageHealthSampleV1",
    "GateStorageHealthSummaryV1",
    "GateWorkerHealthV1",
    "GateWorkerKeyV1",
    "GateWorkerSampleV1",
]
