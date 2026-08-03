from __future__ import annotations

import re
from datetime import UTC, datetime
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
from crypto_collector.storage.raw_writer import NoReplaceCapability
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
EvidenceMode = Literal["functional", "qualification"]
EvidenceInventoryRoot = Literal["evidence", "data", "state"]
ImmutableArchiveProvider = Literal["s3_object_lock", "oss_worm"]
ArchiveProvider = Literal["s3_object_lock", "oss_worm", "webdav"]
ArchiveRetentionMode = Literal["compliance", "worm"]

CANONICAL_EXCHANGES = (
    Exchange.BINANCE,
    Exchange.OKX,
    Exchange.BYBIT,
    Exchange.BITGET,
    Exchange.KRAKEN,
)
RAW_RECORD_FRAME_OVERHEAD_BYTES = 256 * 1024
RAW_RECORD_FRAME_MIN_BYTES = 1024**2
EMPTY_SHA256 = sha256(b"").hexdigest()
_CANONICAL_NONNEGATIVE_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?\Z")
_NORMALIZED_ABSOLUTE_POSIX_PATH = re.compile(r"/(?:[^/\x00]+(?:/[^/\x00]+)*)?\Z")
_PINNED_DOCKERFILE_FRONTEND = re.compile(
    r"docker/dockerfile:[A-Za-z0-9][A-Za-z0-9._-]*@sha256:[0-9a-f]{64}\Z"
)
_RUNTIME_DAG_RESERVED_PATHS = frozenset(
    {"run-index.json", "runtime-receipt.json", "runtime-index.json"}
)
_PROVENANCE_DAG_FUTURE_PATHS = frozenset(
    {
        "provenance-receipt.json",
        "acceptance-receipt.json",
        "evidence-disclosure.json",
    }
)


def _worker_instance_id(exchange: Exchange) -> str:
    return f"gate-worker-v1-{exchange.value}"


def _validate_artifact_relative_path(value: str) -> str:
    normalized = validate_normalized_data_relative_path(value)
    if not normalized.endswith(".jsonl.zst"):
        raise ValueError("artifact path must end with .jsonl.zst")
    return normalized


ArtifactRelativePath = Annotated[str, AfterValidator(_validate_artifact_relative_path)]


def _validate_document_relative_path(value: str) -> str:
    normalized = validate_normalized_data_relative_path(value)
    if not normalized.endswith((".json", ".yaml")):
        raise ValueError("evidence document path must end with .json or .yaml")
    return normalized


DocumentRelativePath = Annotated[
    str,
    AfterValidator(_validate_document_relative_path),
]


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
TargetId = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
CanonicalRunId = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    ),
]
GitCommitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
ImageId = Annotated[str, StringConstraints(pattern=r"^sha256:[0-9a-f]{64}$")]
FailureCode = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9]+(?:_[a-z0-9]+)*$",
    ),
]
UtcHour = Annotated[
    str,
    StringConstraints(pattern=r"^[0-9]{4}/[0-9]{2}/[0-9]{2}/[0-9]{2}$"),
]


def _normalize_absolute_posix_path(value: object) -> str:
    if type(value) is not str:
        raise ValueError("path must be an absolute POSIX string")
    if value == "/":
        return value
    if _NORMALIZED_ABSOLUTE_POSIX_PATH.fullmatch(value) is None or any(
        part in {"", ".", ".."} for part in value.split("/")[1:]
    ):
        raise ValueError("path must be lexically normalized absolute POSIX")
    return value


NormalizedAbsolutePosixPath = Annotated[
    str,
    BeforeValidator(_normalize_absolute_posix_path),
]


class _GateContract(FrozenStrictModel):
    def canonical_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="json")) + b"\n"


class _SelfHashingGateContract(_GateContract):
    @model_validator(mode="after")
    def validate_self_hash(self) -> Self:
        unsigned = self.model_dump(mode="json", exclude={"sha256"})
        expected = sha256(encode_json(unsigned) + b"\n").hexdigest()
        if getattr(self, "sha256", None) != expected:
            raise ValueError("document SHA-256 does not match its canonical fields")
        return self


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
            if identity.worker_instance_id != _worker_instance_id(self.exchange):
                raise ValueError(
                    "accepted identity worker instance ID does not match its exchange"
                )
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


class GateRootProbeV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_root_probe_v1"] = "gate_root_probe_v1"
    root: NormalizedAbsolutePosixPath
    storage_device: Annotated[
        str,
        StringConstraints(pattern=r"^(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)$"),
    ]
    filesystem: NonEmptyString
    mount_point: NormalizedAbsolutePosixPath
    mount_options: tuple[NonEmptyString, ...]
    minimum_available_bytes: Literal[107374182400]
    observed_available_bytes: NonNegativeInt
    no_replace_capability: Literal[NoReplaceCapability.HARDLINK]
    same_parent_publication_only: Literal[True]
    file_sync_supported: Literal[True]
    directory_sync_supported: Literal[True]

    @model_validator(mode="after")
    def validate_root_facts(self) -> Self:
        if self.root == "/":
            raise ValueError("gate root may not be the filesystem root")
        if not self.filesystem.strip() or self.filesystem != self.filesystem.strip():
            raise ValueError("filesystem must be a normalized nonempty value")
        if not self.mount_options:
            raise ValueError("mount options must be nonempty")
        if self.mount_options != tuple(sorted(set(self.mount_options))):
            raise ValueError("mount options must be sorted and unique")
        if any(
            not option.startswith(("mount:", "super:"))
            or option in {"mount:", "super:"}
            for option in self.mount_options
        ):
            raise ValueError("mount options must use mount: or super: prefixes")
        return self


class GateTargetV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_target_v1"] = "gate_target_v1"
    target_id: TargetId
    data_root: GateRootProbeV1
    state_root: GateRootProbeV1
    deployment_purpose: Literal["raw-writer-gate-b"] = "raw-writer-gate-b"
    created_at_unix_ns: NonNegativeInt
    sha256: Sha256

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.data_root.root == self.state_root.root:
            raise ValueError("data and state roots must be distinct")
        for root in (self.data_root, self.state_root):
            if root.observed_available_bytes < root.minimum_available_bytes:
                raise ValueError("target root available bytes are below its floor")
        if (
            self.data_root.storage_device == self.state_root.storage_device
            and self.data_root.mount_point == self.state_root.mount_point
            and min(
                self.data_root.observed_available_bytes,
                self.state_root.observed_available_bytes,
            )
            < (
                self.data_root.minimum_available_bytes
                + self.state_root.minimum_available_bytes
            )
        ):
            raise ValueError("shared target mount is below its combined floor")
        return self


class GateTargetReprobeV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_target_reprobe_v1"] = "gate_target_reprobe_v1"
    target_id: TargetId
    expected_target_id: TargetId
    declaration_sha256: Sha256
    probed_at_unix_ns: NonNegativeInt
    data_root: GateRootProbeV1
    state_root: GateRootProbeV1
    shared_mount: bool
    shared_required_available_bytes: NonNegativeInt | None
    shared_observed_available_bytes: NonNegativeInt | None
    target_id_matches: bool
    declaration_facts_match: bool
    available_space_valid: bool
    reprobe_valid: bool
    sha256: Sha256

    @model_validator(mode="after")
    def validate_reprobe(self) -> Self:
        if self.data_root.root == self.state_root.root:
            raise ValueError("re-probed data and state roots must be distinct")
        expected_shared = (
            self.data_root.storage_device == self.state_root.storage_device
            and self.data_root.mount_point == self.state_root.mount_point
        )
        if self.shared_mount != expected_shared:
            raise ValueError("shared mount flag does not match root facts")
        if expected_shared:
            expected_required = (
                self.data_root.minimum_available_bytes
                + self.state_root.minimum_available_bytes
            )
            expected_observed = min(
                self.data_root.observed_available_bytes,
                self.state_root.observed_available_bytes,
            )
            if (
                self.shared_required_available_bytes != expected_required
                or self.shared_observed_available_bytes != expected_observed
            ):
                raise ValueError("shared mount byte facts are inconsistent")
        elif (
            self.shared_required_available_bytes is not None
            or self.shared_observed_available_bytes is not None
        ):
            raise ValueError("distinct mounts require null shared byte facts")
        if self.target_id_matches != (self.target_id == self.expected_target_id):
            raise ValueError("target ID match flag is inconsistent")
        individual_space_valid = all(
            root.observed_available_bytes >= root.minimum_available_bytes
            for root in (self.data_root, self.state_root)
        )
        shared_space_valid = not expected_shared or (
            self.shared_observed_available_bytes is not None
            and self.shared_required_available_bytes is not None
            and self.shared_observed_available_bytes
            >= self.shared_required_available_bytes
        )
        if self.available_space_valid != (
            individual_space_valid and shared_space_valid
        ):
            raise ValueError("available-space validity is inconsistent")
        if self.reprobe_valid != (
            self.target_id_matches
            and self.declaration_facts_match
            and self.available_space_valid
        ):
            raise ValueError("target re-probe validity is inconsistent")
        return self


class GateEvidenceDocumentRefV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_evidence_document_ref_v1"] = (
        "gate_evidence_document_ref_v1"
    )
    relative_path: DocumentRelativePath
    content_size_bytes: PositiveInt
    content_sha256: Sha256


class GateManifestInventoryEntryV1(_GateContract):
    ordinal: NonNegativeInt
    manifest: GateEvidenceDocumentRefV1
    data: GateArtifactRefV1
    manifest_record_count: PositiveInt

    @model_validator(mode="after")
    def validate_entry(self) -> Self:
        expected_manifest_path = (
            self.data.relative_path.removesuffix(".jsonl.zst") + ".manifest.json"
        )
        if self.manifest.relative_path != expected_manifest_path:
            raise ValueError("manifest inventory paths must be exact siblings")
        if self.manifest_record_count != self.data.row_count:
            raise ValueError("manifest and data record counts must agree")
        return self


class GateRawInventoryV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_raw_inventory_v1"] = "gate_raw_inventory_v1"
    raw_files: tuple[GateArtifactRefV1, ...]
    file_count: PositiveInt
    record_count: PositiveInt
    content_size_bytes: PositiveInt
    compressed_size_bytes: PositiveInt
    sha256: Sha256

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        paths = tuple(item.relative_path for item in self.raw_files)
        if not paths or paths != tuple(sorted(set(paths))):
            raise ValueError("raw inventory paths must be nonempty, sorted, and unique")
        content_hashes = tuple(item.content_sha256 for item in self.raw_files)
        compressed_hashes = tuple(item.compressed_sha256 for item in self.raw_files)
        if len(set(content_hashes)) != len(content_hashes) or len(
            set(compressed_hashes)
        ) != len(compressed_hashes):
            raise ValueError("raw inventory content hashes must be unique")
        expected = (
            len(self.raw_files),
            sum(item.row_count for item in self.raw_files),
            sum(item.content_size_bytes for item in self.raw_files),
            sum(item.compressed_size_bytes for item in self.raw_files),
        )
        observed = (
            self.file_count,
            self.record_count,
            self.content_size_bytes,
            self.compressed_size_bytes,
        )
        if observed != expected:
            raise ValueError("raw inventory totals do not match its files")
        return self


class GateManifestInventoryV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_manifest_inventory_v1"] = "gate_manifest_inventory_v1"
    manifests: tuple[GateManifestInventoryEntryV1, ...]
    file_count: PositiveInt
    record_count: PositiveInt
    manifest_content_size_bytes: PositiveInt
    sha256: Sha256

    @model_validator(mode="after")
    def validate_inventory(self) -> Self:
        paths = tuple(item.manifest.relative_path for item in self.manifests)
        ordinals = tuple(item.ordinal for item in self.manifests)
        data_paths = tuple(item.data.relative_path for item in self.manifests)
        if not paths or paths != tuple(sorted(set(paths))):
            raise ValueError(
                "manifest inventory paths must be nonempty, sorted, and unique"
            )
        if ordinals != tuple(range(len(self.manifests))):
            raise ValueError(
                "manifest inventory ordinals must be zero-based consecutive"
            )
        if len(set(data_paths)) != len(data_paths):
            raise ValueError("manifest inventory data paths must be unique")
        hash_namespaces = (
            tuple(item.manifest.content_sha256 for item in self.manifests),
            tuple(item.data.content_sha256 for item in self.manifests),
            tuple(item.data.compressed_sha256 for item in self.manifests),
        )
        if any(len(set(values)) != len(values) for values in hash_namespaces):
            raise ValueError("manifest inventory hashes must be unique")
        expected = (
            len(self.manifests),
            sum(item.manifest_record_count for item in self.manifests),
            sum(item.manifest.content_size_bytes for item in self.manifests),
        )
        observed = (
            self.file_count,
            self.record_count,
            self.manifest_content_size_bytes,
        )
        if observed != expected:
            raise ValueError("manifest inventory totals do not match its entries")
        return self


class GateStreamRuntimeSummaryV1(_GateContract):
    stream_group: StreamGroup
    expected_record_count: PositiveInt
    expected_payload_bytes: PositiveInt
    scheduled_record_count: NonNegativeInt
    scheduled_payload_bytes: NonNegativeInt
    attempted_record_count: NonNegativeInt
    attempted_payload_bytes: NonNegativeInt
    accepted_record_count: NonNegativeInt
    accepted_payload_bytes: NonNegativeInt
    early_count: NonNegativeInt
    late_count: NonNegativeInt
    out_of_window_count: NonNegativeInt
    required_burst_count: PositiveInt
    scheduled_burst_count: PositiveInt
    burst_second: NonNegativeInt
    burst_scheduled_count: NonNegativeInt
    burst_attempted_count: NonNegativeInt
    burst_accepted_count: NonNegativeInt
    burst_admitted_in_actual_second_count: NonNegativeInt
    planned_values_match: bool
    admission_values_match: bool
    burst_valid: bool

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        if self.scheduled_burst_count != min(
            self.expected_record_count,
            self.required_burst_count,
        ):
            raise ValueError("scheduled burst count is inconsistent")
        expected_planned = (
            self.scheduled_record_count == self.expected_record_count
            and self.scheduled_payload_bytes == self.expected_payload_bytes
        )
        if self.planned_values_match != expected_planned:
            raise ValueError("planned-values match flag is inconsistent")
        expected_admission = (
            self.attempted_record_count
            == self.accepted_record_count
            == self.expected_record_count
            and self.attempted_payload_bytes
            == self.accepted_payload_bytes
            == self.expected_payload_bytes
            and self.early_count == 0
            and self.late_count == 0
            and self.out_of_window_count == 0
        )
        if self.admission_values_match != expected_admission:
            raise ValueError("admission-values match flag is inconsistent")
        expected_burst = all(
            value == self.scheduled_burst_count
            for value in (
                self.burst_scheduled_count,
                self.burst_attempted_count,
                self.burst_accepted_count,
                self.burst_admitted_in_actual_second_count,
            )
        )
        if self.burst_valid != expected_burst:
            raise ValueError("burst validity flag is inconsistent")
        return self


class GateRuntimeSummaryV1(_GateContract):
    expected_record_count: PositiveInt
    expected_payload_bytes: PositiveInt
    scheduled_record_count: NonNegativeInt
    scheduled_payload_bytes: NonNegativeInt
    attempted_record_count: NonNegativeInt
    attempted_payload_bytes: NonNegativeInt
    accepted_record_count: NonNegativeInt
    accepted_payload_bytes: NonNegativeInt
    durable_record_count: NonNegativeInt
    durable_payload_bytes: NonNegativeInt
    durability_sample_count: NonNegativeInt
    manifest_record_count: NonNegativeInt
    raw_file_count: PositiveInt
    manifest_file_count: PositiveInt
    declared_file_identity_count: PositiveInt
    expected_touched_file_identity_count: PositiveInt
    observed_touched_file_identity_count: PositiveInt
    accepted_identity_count: NonNegativeInt
    unique_accepted_identity_count: NonNegativeInt
    early_count: NonNegativeInt
    late_count: NonNegativeInt
    out_of_window_count: NonNegativeInt
    received_utc_hours: tuple[UtcHour, ...]
    stream_summaries: tuple[GateStreamRuntimeSummaryV1, ...]
    final_worker_aggregate: FinalWorkerAggregateV1
    resource_summary: GateResourceSummaryV1
    storage_health_summary: GateStorageHealthSummaryV1

    @model_validator(mode="after")
    def validate_summary(self) -> Self:
        observed_streams = tuple(item.stream_group for item in self.stream_summaries)
        expected_streams = (
            "trade",
            "book_live",
            "ticker",
            "bbo",
            "derivative",
            "candle_1m",
            "book_deep_snapshot",
            "control",
        )
        if observed_streams != expected_streams:
            raise ValueError("runtime stream summaries must use canonical order")
        field_pairs = (
            ("expected_record_count", "expected_record_count"),
            ("expected_payload_bytes", "expected_payload_bytes"),
            ("scheduled_record_count", "scheduled_record_count"),
            ("scheduled_payload_bytes", "scheduled_payload_bytes"),
            ("attempted_record_count", "attempted_record_count"),
            ("attempted_payload_bytes", "attempted_payload_bytes"),
            ("accepted_record_count", "accepted_record_count"),
            ("accepted_payload_bytes", "accepted_payload_bytes"),
            ("early_count", "early_count"),
            ("late_count", "late_count"),
            ("out_of_window_count", "out_of_window_count"),
        )
        for summary_field, stream_field in field_pairs:
            if getattr(self, summary_field) != sum(
                getattr(item, stream_field) for item in self.stream_summaries
            ):
                raise ValueError(f"runtime {summary_field} total is inconsistent")
        worker_facts = (
            self.final_worker_aggregate.accepted_record_count,
            self.final_worker_aggregate.durable_record_count,
            self.final_worker_aggregate.durability_sample_count,
        )
        summary_facts = (
            self.accepted_record_count,
            self.durable_record_count,
            self.durability_sample_count,
        )
        if summary_facts != worker_facts:
            raise ValueError("runtime worker aggregate facts are inconsistent")
        if self.accepted_identity_count != self.accepted_record_count:
            raise ValueError("accepted identity count must equal accepted records")
        if self.unique_accepted_identity_count > self.accepted_identity_count:
            raise ValueError(
                "unique accepted identities exceed all accepted identities"
            )
        if not self.received_utc_hours:
            raise ValueError("received UTC hours must be nonempty")
        if self.received_utc_hours != tuple(sorted(set(self.received_utc_hours))):
            raise ValueError("received UTC hours must be sorted and unique")
        for hour in self.received_utc_hours:
            try:
                parsed = datetime.strptime(hour, "%Y/%m/%d/%H").replace(tzinfo=UTC)
            except ValueError as error:
                raise ValueError("received UTC hour is not a real hour") from error
            if parsed.strftime("%Y/%m/%d/%H") != hour:
                raise ValueError("received UTC hour is not canonical")
        return self


class GateCandidateReportV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_candidate_report_v1"] = "gate_candidate_report_v1"
    run_id: CanonicalRunId
    mode: EvidenceMode
    workload_sha256: Sha256
    workload_plan_sha256: Sha256
    multiplier: PositiveInt
    duration_ns: PositiveInt
    run_started_monotonic_ns: NonNegativeInt
    admission_started_monotonic_ns: NonNegativeInt
    admission_scheduled_end_monotonic_ns: NonNegativeInt
    admission_ended_monotonic_ns: NonNegativeInt
    run_ended_monotonic_ns: NonNegativeInt
    admission_started_utc_ns: NonNegativeInt
    admission_ended_utc_ns: NonNegativeInt
    declared_admission_utc_hour: UtcHour
    expected_target_id: TargetId | None
    target_declaration_sha256: Sha256 | None
    expected_image_id: ImageId | None
    runtime_image_id: ImageId | None
    runtime_summary: GateRuntimeSummaryV1
    runtime_failure_codes: tuple[FailureCode, ...]
    candidate_runtime_passed: bool
    sha256: Sha256

    @model_validator(mode="after")
    def validate_report(self) -> Self:
        if not (
            self.run_started_monotonic_ns
            <= self.admission_started_monotonic_ns
            < self.admission_scheduled_end_monotonic_ns
            <= self.admission_ended_monotonic_ns
            <= self.run_ended_monotonic_ns
        ):
            raise ValueError("candidate monotonic boundaries are inconsistent")
        if self.admission_scheduled_end_monotonic_ns != (
            self.admission_started_monotonic_ns + self.duration_ns
        ):
            raise ValueError("candidate scheduled end does not match duration")
        if self.admission_started_utc_ns > self.admission_ended_utc_ns:
            raise ValueError("candidate UTC admission boundaries are reversed")
        try:
            expected_hour = datetime.fromtimestamp(
                self.admission_started_utc_ns // 1_000_000_000,
                tz=UTC,
            ).strftime("%Y/%m/%d/%H")
        except (OverflowError, OSError, ValueError) as error:
            raise ValueError("candidate UTC admission start is out of range") from error
        if self.declared_admission_utc_hour != expected_hour:
            raise ValueError("declared admission UTC hour is inconsistent")
        mode_claims = (
            self.expected_target_id,
            self.target_declaration_sha256,
            self.expected_image_id,
            self.runtime_image_id,
        )
        if self.mode == "functional":
            if any(value is not None for value in mode_claims):
                raise ValueError("functional candidate forbids target and image claims")
            if self.duration_ns != 10_000_000_000:
                raise ValueError("functional candidate duration must be ten seconds")
        else:
            if any(value is None for value in mode_claims):
                raise ValueError("qualification candidate requires target/image claims")
            if self.duration_ns < 600_000_000_000 or self.multiplier < 2:
                raise ValueError("qualification candidate is underdriven")
        if self.runtime_failure_codes != tuple(sorted(set(self.runtime_failure_codes))):
            raise ValueError("candidate failure codes must be sorted and unique")
        if self.candidate_runtime_passed != (not self.runtime_failure_codes):
            raise ValueError("candidate runtime verdict is inconsistent")
        return self


class GateRunIndexV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_run_index_v1"] = "gate_run_index_v1"
    run_id: CanonicalRunId
    status: Literal["complete"]
    mode: EvidenceMode
    artifact_schema_version: SchemaVersion1
    identity_algorithm: Literal["gate-identity-v1"]
    event_algorithm: Literal["gate-event-v1"]
    payload_algorithm: Literal["gate-payload-v1"]
    schedule_algorithm: Literal["gate-schedule-v2-full-second-burst"]
    data_root: NormalizedAbsolutePosixPath
    state_root: NormalizedAbsolutePosixPath
    workload_document: GateEvidenceDocumentRefV1
    workload_sha256: Sha256
    workload_plan_sha256: Sha256
    admission_trace_set: GateAdmissionTraceSetV1
    second_bucket_artifact: GateArtifactRefV1
    worker_sampling_artifact: GateArtifactRefV1
    resource_sampling_artifact: GateArtifactRefV1
    storage_health_artifact: GateArtifactRefV1
    raw_inventory: GateEvidenceDocumentRefV1
    manifest_inventory: GateEvidenceDocumentRefV1
    candidate_report: GateEvidenceDocumentRefV1
    expected_target_id: TargetId | None
    target_declaration: GateEvidenceDocumentRefV1 | None
    implementation_source_commit: GitCommitSha | None
    collector_wheel_sha256: Sha256 | None
    requirements_lock_sha256: Sha256 | None
    dockerfile_sha256: Sha256 | None
    expected_image_id: ImageId | None
    runtime_image_id: ImageId | None
    sha256: Sha256

    @model_validator(mode="after")
    def validate_index(self) -> Self:
        if self.data_root == "/" or self.state_root == "/":
            raise ValueError("run index roots may not be filesystem root")
        if self.data_root == self.state_root:
            raise ValueError("run index data and state roots must be distinct")
        if self.workload_document.content_sha256 != self.workload_sha256:
            raise ValueError("workload document SHA must equal workload SHA")
        document_paths = (
            self.workload_document.relative_path,
            self.raw_inventory.relative_path,
            self.manifest_inventory.relative_path,
            self.candidate_report.relative_path,
            *(
                ()
                if self.target_declaration is None
                else (self.target_declaration.relative_path,)
            ),
        )
        artifact_paths = (
            *(
                part.artifact.relative_path
                for part in self.admission_trace_set.partitions
            ),
            self.second_bucket_artifact.relative_path,
            self.worker_sampling_artifact.relative_path,
            self.resource_sampling_artifact.relative_path,
            self.storage_health_artifact.relative_path,
        )
        all_paths = (*document_paths, *artifact_paths)
        if len(set(all_paths)) != len(all_paths):
            raise ValueError("run index evidence paths must be unique")
        if _RUNTIME_DAG_RESERVED_PATHS.intersection(all_paths):
            raise ValueError("run index evidence may not use reserved DAG paths")
        mode_claims = (
            self.expected_target_id,
            self.target_declaration,
            self.implementation_source_commit,
            self.collector_wheel_sha256,
            self.requirements_lock_sha256,
            self.dockerfile_sha256,
            self.expected_image_id,
            self.runtime_image_id,
        )
        if self.mode == "functional":
            if any(value is not None for value in mode_claims):
                raise ValueError("functional run index forbids qualification claims")
        elif any(value is None for value in mode_claims):
            raise ValueError("qualification run index requires provenance claims")
        return self


class GateRuntimeReceiptV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_runtime_receipt_v1"] = "gate_runtime_receipt_v1"
    verifier_version: Literal["gate-runtime-verifier-v1"] = "gate-runtime-verifier-v1"
    verified_at_unix_ns: NonNegativeInt
    run_id: CanonicalRunId
    mode: EvidenceMode
    run_index_sha256: Sha256
    run_index_content_sha256: Sha256
    expected_target_id: TargetId | None
    recomputed_summary: GateRuntimeSummaryV1 | None
    target_reprobe: GateTargetReprobeV1 | None
    failure_codes: tuple[FailureCode, ...]
    evidence_integrity_valid: bool
    candidate_summary_matches: bool
    runtime_predicates_passed: bool
    runtime_evidence_valid: bool
    qualification_runtime_accepted: bool
    sha256: Sha256

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        if self.failure_codes != tuple(sorted(set(self.failure_codes))):
            raise ValueError("runtime failure codes must be sorted and unique")
        if self.recomputed_summary is None and (
            self.candidate_summary_matches or self.runtime_predicates_passed
        ):
            raise ValueError("absent recomputation cannot support runtime claims")
        target_valid = True
        if self.mode == "functional":
            if self.expected_target_id is not None or self.target_reprobe is not None:
                raise ValueError("functional runtime receipt forbids target evidence")
        else:
            if self.expected_target_id is None:
                raise ValueError(
                    "qualification runtime receipt requires an expected target ID"
                )
            if self.target_reprobe is None:
                if (
                    self.evidence_integrity_valid
                    or self.recomputed_summary is not None
                    or self.candidate_summary_matches
                    or self.runtime_predicates_passed
                ):
                    raise ValueError(
                        "missing qualification target evidence requires a structural rejection"
                    )
                target_valid = False
            else:
                if self.target_reprobe.expected_target_id != self.expected_target_id:
                    raise ValueError("target re-probe expected ID differs from receipt")
                target_valid = self.target_reprobe.reprobe_valid
        expected_runtime_valid = (
            self.evidence_integrity_valid
            and self.candidate_summary_matches
            and self.runtime_predicates_passed
            and self.recomputed_summary is not None
            and target_valid
        )
        if self.runtime_evidence_valid != expected_runtime_valid:
            raise ValueError("runtime evidence validity is inconsistent")
        expected_qualification = (
            self.mode == "qualification" and self.runtime_evidence_valid
        )
        if self.qualification_runtime_accepted != expected_qualification:
            raise ValueError("qualification runtime verdict is inconsistent")
        if (not self.failure_codes) != self.runtime_evidence_valid:
            raise ValueError("runtime failure codes and validity must agree")
        return self


class GateRuntimeIndexV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_runtime_index_v1"] = "gate_runtime_index_v1"
    run_id: CanonicalRunId
    status: Literal["complete"]
    mode: EvidenceMode
    run_index: GateEvidenceDocumentRefV1
    runtime_receipt: GateEvidenceDocumentRefV1
    sha256: Sha256

    @model_validator(mode="after")
    def validate_index(self) -> Self:
        if self.run_index.relative_path != "run-index.json":
            raise ValueError("runtime index must bind canonical run-index.json")
        if self.runtime_receipt.relative_path != "runtime-receipt.json":
            raise ValueError("runtime index must bind canonical runtime-receipt.json")
        if self.run_index.relative_path == self.runtime_receipt.relative_path:
            raise ValueError("runtime index document paths must be distinct")
        return self


class GateFileInventoryV1(_GateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_file_inventory_v1"] = "gate_file_inventory_v1"
    root: EvidenceInventoryRoot
    relative_path: Annotated[
        str,
        AfterValidator(validate_normalized_data_relative_path),
    ]
    content_size_bytes: NonNegativeInt
    content_sha256: Sha256

    @model_validator(mode="after")
    def validate_content_facts(self) -> Self:
        if self.content_size_bytes == 0 and self.content_sha256 != EMPTY_SHA256:
            raise ValueError("empty inventory file must use the empty SHA-256")
        return self


class GateArchiveAttestationV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_archive_attestation_v1"] = "gate_archive_attestation_v1"
    run_id: CanonicalRunId
    runtime_index_sha256: Sha256
    provider: ArchiveProvider
    archive_locator: NonEmptyString
    opaque_locator_sha256: Sha256
    object_version: NonEmptyString | None
    retention_mode: ArchiveRetentionMode | None
    retention_until_unix_ns: NonNegativeInt | None
    verified_at_unix_ns: NonNegativeInt
    archive_size_bytes: PositiveInt
    archive_sha256: Sha256
    files: tuple[GateFileInventoryV1, ...]
    file_count: PositiveInt
    content_size_bytes: NonNegativeInt
    inventory_sha256: Sha256
    immutable: bool
    webdav_backup_verified: bool
    sha256: Sha256

    @model_validator(mode="after")
    def validate_attestation(self) -> Self:
        locator_digest = sha256(self.archive_locator.encode("utf-8")).hexdigest()
        if self.opaque_locator_sha256 != locator_digest:
            raise ValueError("opaque locator SHA-256 is inconsistent")
        root_order = {"evidence": 0, "data": 1, "state": 2}
        observed_order = tuple(
            (root_order[item.root], item.relative_path) for item in self.files
        )
        if not self.files or observed_order != tuple(sorted(set(observed_order))):
            raise ValueError("archive inventory must be nonempty, sorted, and unique")
        if any(
            item.root == "evidence"
            and item.relative_path in _PROVENANCE_DAG_FUTURE_PATHS
            for item in self.files
        ):
            raise ValueError("archive inventory may not reference future DAG nodes")
        if self.file_count != len(self.files):
            raise ValueError("archive file count does not match inventory")
        if self.content_size_bytes != sum(
            item.content_size_bytes for item in self.files
        ):
            raise ValueError("archive content size does not match inventory")
        inventory_digest = sha256(
            b"".join(item.canonical_bytes() for item in self.files)
        ).hexdigest()
        if self.inventory_sha256 != inventory_digest:
            raise ValueError("archive inventory SHA-256 is inconsistent")

        if self.provider == "s3_object_lock":
            expected_immutable = (
                self.object_version is not None
                and self.retention_mode == "compliance"
                and self.retention_until_unix_ns is not None
                and self.retention_until_unix_ns > self.verified_at_unix_ns
            )
        elif self.provider == "oss_worm":
            expected_immutable = (
                self.object_version is not None
                and self.retention_mode == "worm"
                and self.retention_until_unix_ns is not None
                and self.retention_until_unix_ns > self.verified_at_unix_ns
            )
        else:
            if any(
                value is not None
                for value in (
                    self.object_version,
                    self.retention_mode,
                    self.retention_until_unix_ns,
                )
            ):
                raise ValueError("WebDAV may not claim immutable retention facts")
            expected_immutable = False
        if self.immutable != expected_immutable:
            raise ValueError("archive immutability verdict is inconsistent")
        return self


class GateBuildProvenanceV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_build_provenance_v1"] = "gate_build_provenance_v1"
    implementation_source_commit: GitCommitSha
    source_date_epoch: NonNegativeInt
    platform: Literal["linux/amd64"]
    base_image_digest: ImageId
    docker_engine_version: NonEmptyString
    docker_buildx_version: NonEmptyString
    buildkit_version: NonEmptyString
    dockerfile_frontend: NonEmptyString
    collector_wheel_sha256: Sha256
    requirements_lock_sha256: Sha256
    build_requirements_lock_sha256: Sha256
    dockerfile_sha256: Sha256
    workload_sha256: Sha256
    provenance_enabled: bool
    sbom_enabled: bool
    runtime_user: Literal["65532:65532"]
    sha256: Sha256

    @model_validator(mode="after")
    def validate_build_contract(self) -> Self:
        if self.provenance_enabled:
            raise ValueError("BuildKit ambient provenance must be disabled")
        if self.sbom_enabled:
            raise ValueError("BuildKit ambient SBOM must be disabled")
        for name, value in (
            ("Docker Engine", self.docker_engine_version),
            ("Docker Buildx", self.docker_buildx_version),
            ("BuildKit", self.buildkit_version),
        ):
            if value != value.strip() or any(
                character.isspace() for character in value
            ):
                raise ValueError(f"{name} version must be one normalized token")
        if _PINNED_DOCKERFILE_FRONTEND.fullmatch(self.dockerfile_frontend) is None:
            raise ValueError("Dockerfile frontend must be versioned and digest-pinned")
        return self


class GateProvenanceReceiptV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_provenance_receipt_v1"] = "gate_provenance_receipt_v1"
    verifier_version: Literal["gate-provenance-verifier-v1"] = (
        "gate-provenance-verifier-v1"
    )
    verified_at_unix_ns: NonNegativeInt
    run_id: CanonicalRunId
    mode: EvidenceMode
    runtime_index_sha256: Sha256
    runtime_receipt_sha256: Sha256
    archive_attestation_sha256: Sha256
    archive_sha256: Sha256
    opaque_locator_sha256: Sha256
    implementation_source_commit: GitCommitSha
    source_date_epoch: NonNegativeInt
    source_archive_sha256: Sha256
    collector_wheel_sha256: Sha256
    requirements_lock_sha256: Sha256
    build_requirements_lock_sha256: Sha256
    dockerfile_sha256: Sha256
    workload_sha256: Sha256
    image_id: ImageId
    platform: Literal["linux/amd64"]
    base_image_digest: ImageId
    docker_engine_version: NonEmptyString
    docker_buildx_version: NonEmptyString
    buildkit_version: NonEmptyString
    dockerfile_frontend: NonEmptyString
    source_reproduction_valid: bool
    image_reproduction_valid: bool
    image_contract_valid: bool
    container_binding_valid: bool
    archive_immutable: bool
    provenance_valid: bool
    sha256: Sha256

    @model_validator(mode="after")
    def validate_verdict(self) -> Self:
        expected = self.mode == "qualification" and all(
            (
                self.source_reproduction_valid,
                self.image_reproduction_valid,
                self.image_contract_valid,
                self.container_binding_valid,
                self.archive_immutable,
            )
        )
        if self.provenance_valid != expected:
            raise ValueError("provenance verdict is inconsistent")
        return self


class GateAcceptanceReceiptV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_acceptance_receipt_v1"] = "gate_acceptance_receipt_v1"
    accepted_at_unix_ns: NonNegativeInt
    run_id: CanonicalRunId
    mode: EvidenceMode
    runtime_receipt_sha256: Sha256
    runtime_index_sha256: Sha256
    archive_attestation_sha256: Sha256
    provenance_receipt_sha256: Sha256
    expected_target_id: TargetId | None
    workload_sha256: Sha256
    workload_plan_sha256: Sha256
    multiplier: PositiveInt
    duration_ns: PositiveInt
    expected_record_count: PositiveInt
    accepted_record_count: NonNegativeInt
    durable_record_count: NonNegativeInt
    durability_lag_max_ns: NonNegativeInt
    implementation_source_commit: GitCommitSha
    collector_wheel_sha256: Sha256
    requirements_lock_sha256: Sha256
    dockerfile_sha256: Sha256
    image_id: ImageId
    archive_provider: ImmutableArchiveProvider
    opaque_locator_sha256: Sha256
    runtime_accepted: bool
    provenance_valid: bool
    archive_immutable: bool
    qualification_accepted: bool
    sha256: Sha256

    @model_validator(mode="after")
    def validate_acceptance(self) -> Self:
        if self.mode == "functional" and self.expected_target_id is not None:
            raise ValueError("functional acceptance forbids a target ID")
        if self.mode == "qualification" and self.expected_target_id is None:
            raise ValueError("qualification acceptance requires a target ID")
        expected = self.mode == "qualification" and all(
            (
                self.runtime_accepted,
                self.provenance_valid,
                self.archive_immutable,
            )
        )
        if self.qualification_accepted != expected:
            raise ValueError("qualification acceptance verdict is inconsistent")
        return self


class GateEvidenceDisclosureV1(_SelfHashingGateContract):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["gate_evidence_disclosure_v1"] = "gate_evidence_disclosure_v1"
    run_id: CanonicalRunId
    mode: EvidenceMode
    acceptance_receipt_sha256: Sha256
    runtime_index_sha256: Sha256
    provenance_receipt_sha256: Sha256
    archive_attestation_sha256: Sha256
    workload_sha256: Sha256
    workload_plan_sha256: Sha256
    multiplier: PositiveInt
    duration_ns: PositiveInt
    expected_record_count: PositiveInt
    accepted_record_count: NonNegativeInt
    durable_record_count: NonNegativeInt
    durability_lag_max_ns: NonNegativeInt
    implementation_source_commit: GitCommitSha
    collector_wheel_sha256: Sha256
    requirements_lock_sha256: Sha256
    dockerfile_sha256: Sha256
    image_id: ImageId
    archive_provider: ImmutableArchiveProvider
    opaque_locator_sha256: Sha256
    qualification_accepted: bool
    sha256: Sha256


__all__ = [
    "CANONICAL_EXCHANGES",
    "RAW_RECORD_FRAME_MIN_BYTES",
    "RAW_RECORD_FRAME_OVERHEAD_BYTES",
    "FinalWorkerAggregateV1",
    "GateAcceptanceReceiptV1",
    "GateAdmissionTraceSetV1",
    "GateAdmissionTraceV1",
    "GateArchiveAttestationV1",
    "GateArtifactRefV1",
    "GateBuildProvenanceV1",
    "GateCandidateReportV1",
    "GateEvidenceDisclosureV1",
    "GateEvidenceDocumentRefV1",
    "GateExchangeArtifactPartitionV1",
    "GateFileInventoryV1",
    "GateManifestInventoryEntryV1",
    "GateManifestInventoryV1",
    "GateProcessKeyV1",
    "GateProcessResourceSampleV1",
    "GateProvenanceReceiptV1",
    "GateRawInventoryV1",
    "GateResourceSamplingRoundV1",
    "GateResourceSummaryV1",
    "GateRootProbeV1",
    "GateRunIndexV1",
    "GateRuntimeIndexV1",
    "GateRuntimeReceiptV1",
    "GateRuntimeSummaryV1",
    "GateSamplingRoundV1",
    "GateSecondBucketV1",
    "GateStorageHealthSampleV1",
    "GateStorageHealthSummaryV1",
    "GateStreamRuntimeSummaryV1",
    "GateTargetReprobeV1",
    "GateTargetV1",
    "GateWorkerHealthV1",
    "GateWorkerKeyV1",
    "GateWorkerSampleV1",
]
