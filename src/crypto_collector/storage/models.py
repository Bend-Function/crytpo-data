from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BeforeValidator,
    Field,
    StringConstraints,
    model_validator,
)

from crypto_collector.domain.envelope import (
    MARKET_SCOPED_STREAMS,
    FrozenStrictModel,
    NativeEventDraft,
    RawEnvelope,
)
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.storage.durability import WriterCriticalReason
from crypto_collector.storage.stats import DURABILITY_BUCKET_UPPER_BOUNDS_NS

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
NonNegativeInt = Annotated[int, Field(ge=0)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CanonicalUuid = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
    ),
]


def validate_schema_version_one(value: object) -> Literal[1]:
    if type(value) is not int or value != 1:
        raise ValueError("schema_version must be the integer 1")
    return 1


SchemaVersion1 = Annotated[
    Literal[1],
    BeforeValidator(validate_schema_version_one),
]


def validate_normalized_data_relative_path(value: str) -> str:
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("path must be normalized POSIX relative data path")
    return value


NormalizedDataRelativePath = Annotated[
    str,
    AfterValidator(validate_normalized_data_relative_path),
]
NormalizedStateRelativePath = Annotated[
    str,
    AfterValidator(validate_normalized_data_relative_path),
]


@dataclass(frozen=True, slots=True)
class AcceptedRecord:
    envelope: RawEnvelope
    encoded_jsonl: bytes

    def __post_init__(self) -> None:
        if type(self.envelope) is not RawEnvelope:
            raise TypeError("envelope must be RawEnvelope")
        if (
            type(self.encoded_jsonl) is not bytes
            or not self.encoded_jsonl
            or not self.encoded_jsonl.endswith(b"\n")
        ):
            raise ValueError("encoded_jsonl must be nonempty newline-terminated bytes")

    @property
    def accepted_monotonic_ns(self) -> int:
        return self.envelope.monotonic_ns


class EnqueueStatus(StrEnum):
    ACCEPTED = "accepted"
    ACCEPTED_HIGH_WATER = "accepted_high_water"
    OVERFLOW = "overflow"
    CONTROL_OVERFLOW = "control_overflow"
    NOT_ACCEPTING = "not_accepting"


class AcceptedRecordIdentityV1(FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    exchange: Exchange
    market: Market | None
    instrument_key: NonEmptyString | None
    logical_stream: NonEmptyString
    worker_instance_id: NonEmptyString
    writer_sequence: NonNegativeInt
    acceptance_ordinal: NonNegativeInt
    config_sha256: Sha256
    config_generation: NonNegativeInt


_TRUSTED_ACCEPTED_RECORD_IDENTITY_FIELDS = (
    "schema_version",
    "exchange",
    "market",
    "instrument_key",
    "logical_stream",
    "worker_instance_id",
    "writer_sequence",
    "acceptance_ordinal",
    "config_sha256",
    "config_generation",
)
if (
    tuple(AcceptedRecordIdentityV1.model_fields)
    != _TRUSTED_ACCEPTED_RECORD_IDENTITY_FIELDS
    or AcceptedRecordIdentityV1.__private_attributes__
    or AcceptedRecordIdentityV1.model_computed_fields
    or AcceptedRecordIdentityV1.model_config.get("extra") != "forbid"
    or AcceptedRecordIdentityV1.model_config.get("frozen") is not True
    or AcceptedRecordIdentityV1.model_config.get("strict") is not True
):
    raise RuntimeError("trusted accepted-record identity construction is stale")


def _construct_accepted_identity_from_validated_parts(
    *,
    exchange: Exchange,
    market: Market | None,
    instrument_key: str | None,
    logical_stream: str,
    worker_instance_id: str,
    writer_sequence: int,
    acceptance_ordinal: int,
    config_sha256: str,
    config_generation: int,
) -> AcceptedRecordIdentityV1:
    values = {
        "schema_version": 1,
        "exchange": exchange,
        "market": market,
        "instrument_key": instrument_key,
        "logical_stream": logical_stream,
        "worker_instance_id": worker_instance_id,
        "writer_sequence": writer_sequence,
        "acceptance_ordinal": acceptance_ordinal,
        "config_sha256": config_sha256,
        "config_generation": config_generation,
    }
    identity = AcceptedRecordIdentityV1.__new__(AcceptedRecordIdentityV1)
    object.__setattr__(identity, "__dict__", values)
    object.__setattr__(
        identity,
        "__pydantic_fields_set__",
        set(_TRUSTED_ACCEPTED_RECORD_IDENTITY_FIELDS),
    )
    object.__setattr__(identity, "__pydantic_extra__", None)
    object.__setattr__(identity, "__pydantic_private__", None)
    return identity


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    status: EnqueueStatus
    record: AcceptedRecord | None
    record_identity: AcceptedRecordIdentityV1 | None

    def __post_init__(self) -> None:
        status = self.status
        if type(status) is not EnqueueStatus:
            raise TypeError("status must be EnqueueStatus")
        if self.record is not None and type(self.record) is not AcceptedRecord:
            raise TypeError("record must be AcceptedRecord or None")
        if (
            self.record_identity is not None
            and type(self.record_identity) is not AcceptedRecordIdentityV1
        ):
            raise TypeError("record_identity must be AcceptedRecordIdentityV1 or None")
        accepted = (
            status is EnqueueStatus.ACCEPTED
            or status is EnqueueStatus.ACCEPTED_HIGH_WATER
        )
        if accepted and (self.record is None or self.record_identity is None):
            raise ValueError("accepted status requires record and identity")
        if not accepted and (
            self.record is not None or self.record_identity is not None
        ):
            raise ValueError("accepted status, record, and identity must agree")
        if self.record is not None and self.record_identity is not None:
            envelope = self.record.envelope
            identity = self.record_identity
            expected = (
                envelope.exchange,
                envelope.market,
                envelope.instrument_key,
                envelope.logical_stream,
                envelope.worker_instance_id,
                envelope.writer_sequence,
                envelope.config_sha256,
            )
            observed = (
                identity.exchange,
                identity.market,
                identity.instrument_key,
                identity.logical_stream,
                identity.worker_instance_id,
                identity.writer_sequence,
                identity.config_sha256,
            )
            if observed != expected:
                raise ValueError("record identity must match its accepted envelope")

    @property
    def accepted(self) -> bool:
        return (
            self.status is EnqueueStatus.ACCEPTED
            or self.status is EnqueueStatus.ACCEPTED_HIGH_WATER
        )


class WriterLifecycle(StrEnum):
    STARTING = "starting"
    ACCEPTING = "accepting"
    ROTATING = "rotating"
    CRITICAL = "critical"
    CLOSING = "closing"
    CLOSED = "closed"


class AdmissionState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class PublicationState(StrEnum):
    IDLE = "idle"
    SEALING = "sealing"
    FINAL_SYNC = "final_sync"
    PUBLISHING = "publishing"
    FAILED = "failed"


def _validate_lifecycle_admission(
    lifecycle: WriterLifecycle,
    admission_state: AdmissionState,
) -> None:
    if lifecycle is WriterLifecycle.ROTATING:
        return
    expected = (
        AdmissionState.OPEN
        if lifecycle is WriterLifecycle.ACCEPTING
        else AdmissionState.CLOSED
    )
    if admission_state is not expected:
        raise ValueError("lifecycle admission state invariant failed")


def _validate_record_byte_pair(*, records: int, bytes_: int, stage: str) -> None:
    if (records == 0) != (bytes_ == 0):
        raise ValueError(f"{stage} record/byte zero-state invariant failed")


def _validate_oldest_unpersisted_age(
    *,
    unpersisted_record_count: int,
    oldest_unpersisted_age_ns: int | None,
) -> None:
    if (unpersisted_record_count == 0) != (oldest_unpersisted_age_ns is None):
        raise ValueError(
            "oldest_unpersisted_age_ns must be None exactly when no records "
            "are unpersisted"
        )


def _validate_closed_terminal_state(
    *,
    lifecycle: WriterLifecycle,
    publication_state: PublicationState,
    terminal_gauges: tuple[int, ...],
    incomplete: bool = False,
) -> None:
    if lifecycle is WriterLifecycle.CLOSED and (
        publication_state is not PublicationState.IDLE
        or incomplete
        or any(terminal_gauges)
    ):
        raise ValueError("closed writer terminal state invariant failed")


@dataclass(frozen=True, slots=True)
class WriterStatus:
    lifecycle: WriterLifecycle
    admission_state: AdmissionState
    publication_state: PublicationState
    accepting: bool
    incomplete: bool
    incomplete_reason: str | None
    critical_reason: WriterCriticalReason | None
    queued_records: int
    queued_bytes: int
    buffered_records: int
    buffered_bytes: int
    in_flight_records: int
    in_flight_bytes: int
    active_logical_generation_count: int
    retiring_generation_count: int
    open_file_descriptor_count: int
    dirty_file_count: int
    sync_inflight: int
    oldest_unpersisted_age_ns: int | None
    accepted_record_count: int
    durable_record_count: int
    unpersisted_record_count: int
    uncertain_record_count: int

    def __post_init__(self) -> None:
        if type(self.lifecycle) is not WriterLifecycle:
            raise TypeError("lifecycle must be WriterLifecycle")
        if type(self.admission_state) is not AdmissionState:
            raise TypeError("admission_state must be AdmissionState")
        if type(self.publication_state) is not PublicationState:
            raise TypeError("publication_state must be PublicationState")
        if type(self.accepting) is not bool or type(self.incomplete) is not bool:
            raise TypeError("writer status flags must be booleans")
        if self.accepting != (self.admission_state is AdmissionState.OPEN):
            raise ValueError("accepting must agree with admission_state")
        _validate_lifecycle_admission(self.lifecycle, self.admission_state)
        if self.incomplete != (self.incomplete_reason is not None):
            raise ValueError("incomplete must agree with incomplete_reason")
        if self.incomplete_reason is not None and (
            type(self.incomplete_reason) is not str
            or not self.incomplete_reason
            or self.incomplete_reason != self.incomplete_reason.strip()
        ):
            raise ValueError("incomplete_reason must be a normalized nonempty string")
        if (
            self.critical_reason is not None
            and type(self.critical_reason) is not WriterCriticalReason
        ):
            raise TypeError("critical_reason must be WriterCriticalReason or None")
        if (self.lifecycle is WriterLifecycle.CRITICAL) != (
            self.critical_reason is not None
        ):
            raise ValueError("critical lifecycle must agree with critical_reason")
        count_fields = (
            "queued_records",
            "queued_bytes",
            "buffered_records",
            "buffered_bytes",
            "in_flight_records",
            "in_flight_bytes",
            "active_logical_generation_count",
            "retiring_generation_count",
            "open_file_descriptor_count",
            "dirty_file_count",
            "sync_inflight",
            "accepted_record_count",
            "durable_record_count",
            "unpersisted_record_count",
            "uncertain_record_count",
        )
        for field_name in count_fields:
            value = getattr(self, field_name)
            if type(value) is not int:
                raise TypeError(f"{field_name} must be an integer")
            if value < 0:
                raise ValueError(f"{field_name} must be non-negative")
        if self.oldest_unpersisted_age_ns is not None and (
            type(self.oldest_unpersisted_age_ns) is not int
            or self.oldest_unpersisted_age_ns < 0
        ):
            raise ValueError("oldest_unpersisted_age_ns must be non-negative or None")
        if self.accepted_record_count != (
            self.durable_record_count
            + self.unpersisted_record_count
            + self.uncertain_record_count
        ):
            raise ValueError("accepted record conservation invariant failed")
        if self.unpersisted_record_count != (
            self.queued_records + self.buffered_records + self.in_flight_records
        ):
            raise ValueError("unpersisted stage conservation invariant failed")
        for stage, records, bytes_ in (
            ("queued", self.queued_records, self.queued_bytes),
            ("buffered", self.buffered_records, self.buffered_bytes),
            ("in_flight", self.in_flight_records, self.in_flight_bytes),
        ):
            _validate_record_byte_pair(records=records, bytes_=bytes_, stage=stage)
        _validate_oldest_unpersisted_age(
            unpersisted_record_count=self.unpersisted_record_count,
            oldest_unpersisted_age_ns=self.oldest_unpersisted_age_ns,
        )
        _validate_closed_terminal_state(
            lifecycle=self.lifecycle,
            publication_state=self.publication_state,
            incomplete=self.incomplete,
            terminal_gauges=(
                self.queued_records,
                self.queued_bytes,
                self.buffered_records,
                self.buffered_bytes,
                self.in_flight_records,
                self.in_flight_bytes,
                self.active_logical_generation_count,
                self.retiring_generation_count,
                self.open_file_descriptor_count,
                self.dirty_file_count,
                self.sync_inflight,
                self.unpersisted_record_count,
                self.uncertain_record_count,
            ),
        )


def _nearest_rank(
    bucket_counts: tuple[int, ...],
    *,
    sample_count: int,
    percent: int,
) -> int | None:
    if sample_count == 0:
        return None
    rank = max(1, (percent * sample_count + 99) // 100)
    cumulative = 0
    for upper_bound, count in zip(
        DURABILITY_BUCKET_UPPER_BOUNDS_NS,
        bucket_counts,
        strict=True,
    ):
        cumulative += count
        if cumulative >= rank:
            return upper_bound
    raise ValueError("histogram buckets do not contain sample_count values")


def _validate_histogram_fields(
    *,
    bucket_counts: tuple[int, ...],
    sample_count: int,
    lag_p50_ns: int | None,
    lag_p95_ns: int | None,
    lag_p99_ns: int | None,
    lag_max_ns: int | None,
) -> None:
    if len(bucket_counts) != len(DURABILITY_BUCKET_UPPER_BOUNDS_NS):
        raise ValueError("bucket_counts must match the durability histogram schema")
    if sum(bucket_counts) != sample_count:
        raise ValueError("histogram sample count must equal the disjoint bucket sum")
    expected = tuple(
        _nearest_rank(bucket_counts, sample_count=sample_count, percent=percent)
        for percent in (50, 95, 99)
    )
    if (lag_p50_ns, lag_p95_ns, lag_p99_ns) != expected:
        raise ValueError("durability quantiles must match nearest-rank buckets")
    if sample_count == 0:
        if lag_max_ns is not None:
            raise ValueError("empty histogram cannot have a maximum")
        return
    if lag_max_ns is None:
        raise ValueError("nonempty histogram requires a maximum")
    highest_nonempty = max(index for index, count in enumerate(bucket_counts) if count)
    lower_bound = (
        -1
        if highest_nonempty == 0
        else DURABILITY_BUCKET_UPPER_BOUNDS_NS[highest_nonempty - 1]
    )
    upper_bound = DURABILITY_BUCKET_UPPER_BOUNDS_NS[highest_nonempty]
    if not lower_bound < lag_max_ns <= upper_bound:
        raise ValueError("histogram maximum must use its highest nonempty bucket")


class DurabilityHistogramSeriesV1(FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    exchange: Exchange
    market: Market | None
    logical_stream: NonEmptyString
    bucket_counts: tuple[NonNegativeInt, ...]
    sample_count: NonNegativeInt
    lag_p50_ns: NonNegativeInt | None
    lag_p95_ns: NonNegativeInt | None
    lag_p99_ns: NonNegativeInt | None
    lag_max_ns: NonNegativeInt | None

    @model_validator(mode="after")
    def validate_histogram(self) -> Self:
        _validate_histogram_fields(
            bucket_counts=self.bucket_counts,
            sample_count=self.sample_count,
            lag_p50_ns=self.lag_p50_ns,
            lag_p95_ns=self.lag_p95_ns,
            lag_p99_ns=self.lag_p99_ns,
            lag_max_ns=self.lag_max_ns,
        )
        return self


class WriterMetricsSnapshotV1(FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    observed_monotonic_ns: NonNegativeInt
    exchange: Exchange
    worker_instance_id: NonEmptyString
    config_sha256: Sha256
    config_generation: NonNegativeInt
    lifecycle: WriterLifecycle
    admission_state: AdmissionState
    publication_state: PublicationState
    critical_reason: WriterCriticalReason | None
    acceptance_ordinal_high_water: NonNegativeInt | None
    accepted_record_count: NonNegativeInt
    durable_record_count: NonNegativeInt
    unpersisted_record_count: NonNegativeInt
    uncertain_record_count: NonNegativeInt
    queued_records: NonNegativeInt
    queued_bytes: NonNegativeInt
    buffered_records: NonNegativeInt
    buffered_bytes: NonNegativeInt
    in_flight_records: NonNegativeInt
    in_flight_bytes: NonNegativeInt
    resident_record_bytes: NonNegativeInt
    resident_control_records: NonNegativeInt
    resident_control_bytes: NonNegativeInt
    oldest_unpersisted_age_ns: NonNegativeInt | None
    enqueue_high_water_count: NonNegativeInt
    normal_overflow_count: NonNegativeInt
    control_overflow_count: NonNegativeInt
    not_accepting_count: NonNegativeInt
    active_logical_generation_count: NonNegativeInt
    retiring_generation_count: NonNegativeInt
    open_file_descriptor_count: NonNegativeInt
    sync_inflight: NonNegativeInt
    durability_histogram_schema_version: SchemaVersion1
    durability_bucket_counts: tuple[NonNegativeInt, ...]
    durability_sample_count: NonNegativeInt
    durability_lag_p50_ns: NonNegativeInt | None
    durability_lag_p95_ns: NonNegativeInt | None
    durability_lag_p99_ns: NonNegativeInt | None
    durability_lag_max_ns: NonNegativeInt | None
    durability_histogram_series: tuple[DurabilityHistogramSeriesV1, ...]
    sync_count: NonNegativeInt
    sync_duration_total_ns: NonNegativeInt
    sync_duration_max_ns: NonNegativeInt
    slo_breach_count: NonNegativeInt
    write_failure_count: NonNegativeInt
    sync_failure_count: NonNegativeInt
    publication_failure_count: NonNegativeInt

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        _validate_lifecycle_admission(self.lifecycle, self.admission_state)
        if (self.lifecycle is WriterLifecycle.CRITICAL) != (
            self.critical_reason is not None
        ):
            raise ValueError("critical lifecycle must agree with critical_reason")
        expected_high_water = (
            None if self.accepted_record_count == 0 else self.accepted_record_count - 1
        )
        if self.acceptance_ordinal_high_water != expected_high_water:
            raise ValueError(
                "acceptance ordinal high-water must match accepted record count"
            )
        if self.accepted_record_count != (
            self.durable_record_count
            + self.unpersisted_record_count
            + self.uncertain_record_count
        ):
            raise ValueError("accepted record conservation invariant failed")
        if self.unpersisted_record_count != (
            self.queued_records + self.buffered_records + self.in_flight_records
        ):
            raise ValueError("unpersisted stage conservation invariant failed")
        if self.resident_record_bytes != (
            self.queued_bytes + self.buffered_bytes + self.in_flight_bytes
        ):
            raise ValueError("resident byte conservation invariant failed")
        if self.resident_control_bytes > self.resident_record_bytes:
            raise ValueError("resident control bytes exceed all resident bytes")
        if self.resident_control_records > self.unpersisted_record_count:
            raise ValueError("resident control records exceed unpersisted records")
        for stage, records, bytes_ in (
            ("queued", self.queued_records, self.queued_bytes),
            ("buffered", self.buffered_records, self.buffered_bytes),
            ("in_flight", self.in_flight_records, self.in_flight_bytes),
            (
                "resident control",
                self.resident_control_records,
                self.resident_control_bytes,
            ),
        ):
            _validate_record_byte_pair(records=records, bytes_=bytes_, stage=stage)
        _validate_oldest_unpersisted_age(
            unpersisted_record_count=self.unpersisted_record_count,
            oldest_unpersisted_age_ns=self.oldest_unpersisted_age_ns,
        )
        _validate_closed_terminal_state(
            lifecycle=self.lifecycle,
            publication_state=self.publication_state,
            terminal_gauges=(
                self.queued_records,
                self.queued_bytes,
                self.buffered_records,
                self.buffered_bytes,
                self.in_flight_records,
                self.in_flight_bytes,
                self.resident_record_bytes,
                self.resident_control_records,
                self.resident_control_bytes,
                self.active_logical_generation_count,
                self.retiring_generation_count,
                self.open_file_descriptor_count,
                self.sync_inflight,
                self.unpersisted_record_count,
                self.uncertain_record_count,
            ),
        )
        if self.durability_sample_count != self.durable_record_count:
            raise ValueError("durability sample count must equal durable record count")
        _validate_histogram_fields(
            bucket_counts=self.durability_bucket_counts,
            sample_count=self.durability_sample_count,
            lag_p50_ns=self.durability_lag_p50_ns,
            lag_p95_ns=self.durability_lag_p95_ns,
            lag_p99_ns=self.durability_lag_p99_ns,
            lag_max_ns=self.durability_lag_max_ns,
        )
        series_keys = tuple(
            (
                item.exchange.value,
                "" if item.market is None else item.market.value,
                item.logical_stream,
            )
            for item in self.durability_histogram_series
        )
        if series_keys != tuple(sorted(series_keys)) or len(series_keys) != len(
            set(series_keys)
        ):
            raise ValueError("durability histogram series must be sorted and unique")
        if any(
            item.exchange is not self.exchange
            for item in self.durability_histogram_series
        ):
            raise ValueError("durability histogram series exchange mismatch")
        if (
            sum(item.sample_count for item in self.durability_histogram_series)
            != self.durability_sample_count
        ):
            raise ValueError("durability series sample counts do not match aggregate")
        for index, aggregate_count in enumerate(self.durability_bucket_counts):
            if (
                sum(
                    item.bucket_counts[index]
                    for item in self.durability_histogram_series
                )
                != aggregate_count
            ):
                raise ValueError("durability series buckets do not match aggregate")
        series_maxima = tuple(
            item.lag_max_ns
            for item in self.durability_histogram_series
            if item.lag_max_ns is not None
        )
        if self.durability_lag_max_ns != (
            max(series_maxima) if series_maxima else None
        ):
            raise ValueError("durability series maxima do not match aggregate")
        return self

    def canonical_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="json")) + b"\n"


class StorageScopeError(ValueError):
    pass


class AdmissionContractError(ValueError):
    pass


class CapacityClass(StrEnum):
    NORMAL = "normal"
    CONTROL = "control"


class StorageLogicalTargetV1(FrozenStrictModel):
    market: Market | None
    instrument_key: NonEmptyString | None
    logical_stream: NonEmptyString

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if self.logical_stream == "_control":
            if self.market is not None or self.instrument_key is not None:
                raise ValueError("_control targets must be exchange scoped")
            return self
        if self.market is None:
            raise ValueError("non-control targets require a market")
        if self.logical_stream in MARKET_SCOPED_STREAMS:
            if self.instrument_key is not None:
                raise ValueError("market-scoped targets cannot name an instrument")
        elif self.instrument_key is None:
            raise ValueError("instrument-scoped targets require an instrument key")
        return self


class StorageControlRequestV1(FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    control_event_id: NonEmptyString
    affected_markets: tuple[Market, ...]
    target_logical_identities: tuple[StorageLogicalTargetV1, ...]

    @model_validator(mode="after")
    def validate_request(self) -> Self:
        if not self.target_logical_identities:
            raise ValueError("control request targets must be nonempty")
        affected_values = tuple(item.value for item in self.affected_markets)
        if affected_values != tuple(sorted(affected_values)) or len(
            affected_values
        ) != len(set(affected_values)):
            raise ValueError("affected markets must be sorted and unique")
        target_keys = tuple(
            (
                "" if item.market is None else item.market.value,
                "" if item.instrument_key is None else item.instrument_key,
                item.logical_stream,
            )
            for item in self.target_logical_identities
        )
        if target_keys != tuple(sorted(target_keys)) or len(target_keys) != len(
            set(target_keys)
        ):
            raise ValueError("control request targets must be sorted and unique")
        named_markets = {
            item.market
            for item in self.target_logical_identities
            if item.market is not None
        }
        if not named_markets.issubset(set(self.affected_markets)):
            raise ValueError("target markets must appear in affected_markets")
        if not self.affected_markets and named_markets:
            raise ValueError("market-scoped targets require affected_markets")
        return self


class StorageControlTargetV1(FrozenStrictModel):
    generation_id: NonEmptyString
    data_relative_path: NormalizedDataRelativePath

    @model_validator(mode="after")
    def validate_final_raw_data_path(self) -> Self:
        if not self.data_relative_path.startswith(
            "raw/"
        ) or not self.data_relative_path.endswith(".jsonl.zst"):
            raise ValueError("data_relative_path must identify a final raw data path")
        return self


class StorageControlAssociationV1(FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    control_kind: NonEmptyString
    control_event_id: NonEmptyString
    targets: tuple[StorageControlTargetV1, ...]
    acceptance_ordinal: NonNegativeInt
    config_generation: NonNegativeInt

    @model_validator(mode="after")
    def validate_targets(self) -> Self:
        if not self.targets:
            raise ValueError("control association targets must be nonempty")
        keys = tuple(
            (item.generation_id, item.data_relative_path) for item in self.targets
        )
        if keys != tuple(sorted(keys)):
            raise ValueError("control association targets must be sorted")
        generation_ids = tuple(item.generation_id for item in self.targets)
        paths = tuple(item.data_relative_path for item in self.targets)
        if len(set(generation_ids)) != len(generation_ids) or len(set(paths)) != len(
            paths
        ):
            raise ValueError("control association targets must be unique")
        return self

    def canonical_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="json")) + b"\n"


@dataclass(frozen=True, slots=True)
class ValidatedControlDraft:
    draft: NativeEventDraft
    control_kind: str
    association_request: StorageControlRequestV1 | None


def _parse_control_request(value: object) -> StorageControlRequestV1:
    if type(value) is not dict:
        raise StorageScopeError("storage_association must be an object")
    required_keys = {
        "schema_version",
        "control_event_id",
        "affected_markets",
        "target_logical_identities",
    }
    if set(value) != required_keys:
        raise StorageScopeError("storage_association has missing or extra fields")
    affected_raw = value["affected_markets"]
    targets_raw = value["target_logical_identities"]
    if type(affected_raw) is not list or type(targets_raw) is not list:
        raise StorageScopeError("storage_association arrays must be JSON arrays")
    try:
        affected = tuple(Market(item) for item in affected_raw)
        parsed_targets: list[StorageLogicalTargetV1] = []
        for item in targets_raw:
            if type(item) is not dict or set(item) != {
                "market",
                "instrument_key",
                "logical_stream",
            }:
                raise ValueError("target must have the exact logical identity fields")
            parsed_targets.append(
                StorageLogicalTargetV1(
                    market=(None if item["market"] is None else Market(item["market"])),
                    instrument_key=item["instrument_key"],
                    logical_stream=item["logical_stream"],
                )
            )
        targets = tuple(parsed_targets)
        return StorageControlRequestV1(
            schema_version=value["schema_version"],
            control_event_id=value["control_event_id"],
            affected_markets=affected,
            target_logical_identities=targets,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise StorageScopeError("invalid storage_association") from error


def validate_control_draft(draft: NativeEventDraft) -> ValidatedControlDraft:
    if type(draft) is not NativeEventDraft:
        raise TypeError("draft must be NativeEventDraft")
    if draft.logical_stream != "_control":
        raise StorageScopeError("control draft must use the _control stream")
    if (
        draft.market is not None
        or draft.instrument_key is not None
        or draft.wire_symbol is not None
        or draft.native_channel is not None
        or draft.transport is not Transport.INTERNAL
    ):
        raise StorageScopeError("control draft must use exchange-only internal scope")
    payload = draft.payload
    if type(payload) is not dict:
        raise StorageScopeError("control payload must be an object")
    kind = payload.get("kind")
    if type(kind) is not str or not kind or kind != kind.strip():
        raise StorageScopeError("control payload requires a normalized kind")
    request = (
        _parse_control_request(payload["storage_association"])
        if "storage_association" in payload
        else None
    )
    return ValidatedControlDraft(
        draft=draft,
        control_kind=kind,
        association_request=request,
    )


__all__ = [
    "AcceptedRecord",
    "AcceptedRecordIdentityV1",
    "AdmissionContractError",
    "AdmissionState",
    "CanonicalUuid",
    "CapacityClass",
    "DurabilityHistogramSeriesV1",
    "EnqueueResult",
    "EnqueueStatus",
    "NonEmptyString",
    "NormalizedDataRelativePath",
    "NormalizedStateRelativePath",
    "PublicationState",
    "SchemaVersion1",
    "Sha256",
    "StorageControlAssociationV1",
    "StorageControlRequestV1",
    "StorageControlTargetV1",
    "StorageLogicalTargetV1",
    "StorageScopeError",
    "ValidatedControlDraft",
    "WriterLifecycle",
    "WriterMetricsSnapshotV1",
    "WriterStatus",
    "validate_control_draft",
    "validate_normalized_data_relative_path",
    "validate_schema_version_one",
]
