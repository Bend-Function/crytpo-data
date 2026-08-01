from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self, TypeVar

from pydantic import BeforeValidator, Field, ValidationError, model_validator

from crypto_collector.domain.envelope import MARKET_SCOPED_STREAMS, FrozenStrictModel
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.domain.paths import encode_instrument_key
from crypto_collector.domain.types import CloseReason, Exchange, Market
from crypto_collector.storage.models import (
    CanonicalUuid,
    NonEmptyString,
    NormalizedDataRelativePath,
    Sha256,
)

NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]
ZstdLevel = Annotated[int, Field(ge=1, le=22)]
_PART_INTEGER = r"(?:0|[1-9][0-9]*)"
_PART_NAME = re.compile(rf"^part-{_PART_INTEGER}-{_PART_INTEGER}\.jsonl\.zst$")


class UnsupportedManifestSchema(RuntimeError):
    pass


def _manifest_schema_version(value: object) -> Literal[1]:
    if type(value) is not int or value != 1:
        raise UnsupportedManifestSchema("unsupported raw manifest schema version")
    return 1


def _literal_true(value: object) -> Literal[True]:
    if type(value) is not bool or value is not True:
        raise ValueError("zstd codec flags must be the boolean true")
    return True


ManifestSchemaVersion1 = Annotated[
    Literal[1],
    BeforeValidator(_manifest_schema_version),
]
LiteralTrue = Annotated[Literal[True], BeforeValidator(_literal_true)]


class RecoverySourceState(StrEnum):
    PARTIAL_COMPLETE = "partial_complete"
    PARTIAL_TRUNCATED = "partial_truncated"
    ORPHAN_CLOSED_DATA = "orphan_closed_data"
    OWNED_CONTROL_CARRIER = "owned_control_carrier"
    PUBLICATION_COEXISTENCE = "publication_coexistence"
    CLEANUP_INTENT = "cleanup_intent"
    CLEANUP_TOMBSTONE = "cleanup_tombstone"


RECOVERY_UNAVAILABLE_FIELDS = tuple(
    sorted(
        {
            "zstd_level",
            "max_plain_frame_bytes",
            "created_at_ns",
            "gap_count",
            "reconnect_count",
            "parse_error_count",
            "checksum_error_count",
            "queue_overflow_count",
            "control_event_ids",
            "durability_sample_count",
            "durability_lag_p50_ns",
            "durability_lag_p95_ns",
            "durability_lag_p99_ns",
            "durability_lag_max_ns",
            "sync_count",
            "sync_duration_total_ns",
            "sync_duration_max_ns",
            "slo_breach_count",
            "write_failure_count",
            "sync_failure_count",
        }
    )
)

_SortedValue = TypeVar("_SortedValue", str, int)


def _require_sorted_unique(
    values: tuple[_SortedValue, ...],
    *,
    field_name: str,
) -> None:
    if values != tuple(sorted(values)) or len(values) != len(set(values)):
        raise ValueError(f"{field_name} must be sorted and unique")


def _sibling_path(path: str | Path, *, suffix: str) -> Path:
    candidate = Path(path)
    data_suffix = ".jsonl.zst"
    if not candidate.name.endswith(data_suffix):
        raise ValueError("data path must name a complete .jsonl.zst file")
    stem = candidate.name.removesuffix(data_suffix)
    if not stem or stem in {".", ".."}:
        raise ValueError("data path must name a complete .jsonl.zst file")
    return candidate.with_name(stem + suffix)


def _utc_storage_hour(timestamp_ns: int) -> str:
    try:
        return datetime.fromtimestamp(
            timestamp_ns // 1_000_000_000,
            tz=UTC,
        ).strftime("%Y/%m/%d/%H")
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError("timestamp is outside the supported UTC range") from error


def manifest_path_for_data(path: str | Path) -> Path:
    return _sibling_path(path, suffix=".manifest.json")


def lease_path_for_data(path: str | Path) -> Path:
    return _sibling_path(path, suffix=".lease")


class RawManifestV1(FrozenStrictModel):
    schema_version: ManifestSchemaVersion1
    exchange: Exchange
    market: Market | None
    instrument_key: NonEmptyString | None
    logical_stream: NonEmptyString
    wire_symbols: tuple[NonEmptyString, ...]
    data_relative_path: NormalizedDataRelativePath
    manifest_relative_path: NormalizedDataRelativePath
    file_size_bytes: PositiveInt
    file_sha256: Sha256
    zstd_level: ZstdLevel | None
    zstd_write_checksum: LiteralTrue
    zstd_write_content_size: LiteralTrue
    max_plain_frame_bytes: PositiveInt | None
    record_count: PositiveInt
    first_received_at_ns: NonNegativeInt
    last_received_at_ns: NonNegativeInt
    first_event_time_ns: NonNegativeInt | None
    last_event_time_ns: NonNegativeInt | None
    worker_instance_id: NonEmptyString
    connection_generations: tuple[NonNegativeInt, ...]
    writer_sequence_first: NonNegativeInt
    writer_sequence_last: NonNegativeInt
    config_sha256: Sha256
    egress_ids: tuple[NonEmptyString, ...]
    requested_intervals_ns: tuple[PositiveInt, ...]
    effective_intervals_ns: tuple[PositiveInt, ...]
    gap_count: NonNegativeInt | None
    reconnect_count: NonNegativeInt | None
    parse_error_count: NonNegativeInt | None
    checksum_error_count: NonNegativeInt | None
    queue_overflow_count: NonNegativeInt | None
    control_event_ids: tuple[NonEmptyString, ...] | None
    durability_measurement: Literal["measured", "unavailable_after_crash"]
    durability_sample_count: NonNegativeInt | None
    durability_lag_p50_ns: NonNegativeInt | None
    durability_lag_p95_ns: NonNegativeInt | None
    durability_lag_p99_ns: NonNegativeInt | None
    durability_lag_max_ns: NonNegativeInt | None
    sync_count: NonNegativeInt | None
    sync_duration_total_ns: NonNegativeInt | None
    sync_duration_max_ns: NonNegativeInt | None
    slo_breach_count: NonNegativeInt | None
    write_failure_count: NonNegativeInt | None
    sync_failure_count: NonNegativeInt | None
    close_reason: CloseReason
    created_at_ns: NonNegativeInt | None
    closed_at_ns: NonNegativeInt
    recovery_transaction_id: CanonicalUuid | None
    recovery_source_state: RecoverySourceState | None
    recovery_source_relative_path: NormalizedDataRelativePath | None
    recovery_source_bytes: PositiveInt | None
    recovery_source_sha256: Sha256 | None
    recovery_control_event_id: NonEmptyString | None
    recovered_frame_count: PositiveInt | None
    recovered_record_count: PositiveInt | None
    recovered_bytes: PositiveInt | None
    recovered_sha256: Sha256 | None
    quarantined_suffix_relative_path: NormalizedDataRelativePath | None
    quarantined_suffix_bytes: PositiveInt | None
    quarantined_suffix_sha256: Sha256 | None
    unavailable_fields: tuple[NonEmptyString, ...]

    @model_validator(mode="after")
    def validate_manifest(self) -> Self:
        self._validate_sorted_facts()
        self._validate_row_facts()
        self._validate_layout()
        if self.close_reason is CloseReason.RECOVERY:
            self._validate_recovery_manifest()
        else:
            self._validate_normal_manifest()
        return self

    def _validate_sorted_facts(self) -> None:
        for field_name in (
            "wire_symbols",
            "connection_generations",
            "egress_ids",
            "requested_intervals_ns",
            "effective_intervals_ns",
            "unavailable_fields",
        ):
            _require_sorted_unique(getattr(self, field_name), field_name=field_name)
        if self.control_event_ids is not None:
            _require_sorted_unique(
                self.control_event_ids,
                field_name="control_event_ids",
            )

    def _validate_row_facts(self) -> None:
        if (self.first_event_time_ns is None) != (self.last_event_time_ns is None):
            raise ValueError("event-time bounds must be paired")
        if self.writer_sequence_last < self.writer_sequence_first:
            raise ValueError("writer sequence bounds are reversed")
        if self.instrument_key is None:
            if self.wire_symbols:
                raise ValueError("unscoped manifests cannot contain wire symbols")
        elif not self.wire_symbols:
            raise ValueError("instrument manifests require wire symbols")
        if (not self.requested_intervals_ns) != (not self.effective_intervals_ns):
            raise ValueError("requested and effective interval sets must be paired")

    def _validate_layout(self) -> None:
        if self.logical_stream == "_control":
            if self.market is not None or self.instrument_key is not None:
                raise ValueError("_control manifest scope is invalid")
            scope: tuple[str, ...] = ("raw", self.exchange.value, "_control")
        else:
            if self.market is None:
                raise ValueError("non-control manifests require a market")
            if self.logical_stream in MARKET_SCOPED_STREAMS:
                if self.instrument_key is not None:
                    raise ValueError(
                        "market-scoped manifests cannot name an instrument"
                    )
                identity_segment = "_market"
            else:
                if self.instrument_key is None:
                    raise ValueError(
                        "instrument-scoped manifests require an instrument"
                    )
                identity_segment = encode_instrument_key(self.instrument_key)
            scope = (
                "raw",
                self.exchange.value,
                self.market.value,
                identity_segment,
                self.logical_stream,
            )

        first_hour = _utc_storage_hour(self.first_received_at_ns)
        last_hour = _utc_storage_hour(self.last_received_at_ns)
        if first_hour != last_hour:
            raise ValueError("manifest rows cross a UTC storage hour")
        expected_prefix = (*scope, *first_hour.split("/"))
        data_parts = tuple(self.data_relative_path.split("/"))
        if data_parts[:-1] != expected_prefix or not _PART_NAME.fullmatch(
            data_parts[-1]
        ):
            raise ValueError("data path does not match manifest identity/layout/hour")
        expected_manifest = manifest_path_for_data(self.data_relative_path).as_posix()
        if self.manifest_relative_path != expected_manifest:
            raise ValueError("manifest path is not the exact data sibling")

    def _validate_normal_manifest(self) -> None:
        if self.created_at_ns is None:
            raise ValueError("normal manifests require created_at_ns")
        if self.zstd_level is None or self.max_plain_frame_bytes is None:
            raise ValueError("normal manifests require codec settings")
        control_values = (
            self.gap_count,
            self.reconnect_count,
            self.parse_error_count,
            self.checksum_error_count,
            self.queue_overflow_count,
            self.control_event_ids,
        )
        if any(value is None for value in control_values):
            raise ValueError("normal manifests require control summaries")
        durability_values = (
            self.durability_sample_count,
            self.durability_lag_p50_ns,
            self.durability_lag_p95_ns,
            self.durability_lag_p99_ns,
            self.durability_lag_max_ns,
            self.sync_count,
            self.sync_duration_total_ns,
            self.sync_duration_max_ns,
            self.slo_breach_count,
            self.write_failure_count,
            self.sync_failure_count,
        )
        if self.durability_measurement != "measured" or any(
            value is None for value in durability_values
        ):
            raise ValueError("normal manifests require measured durability summaries")
        if self.durability_sample_count != self.record_count:
            raise ValueError("durability sample count must match record_count")
        assert self.durability_lag_p50_ns is not None
        assert self.durability_lag_p95_ns is not None
        assert self.durability_lag_p99_ns is not None
        if not (
            self.durability_lag_p50_ns
            <= self.durability_lag_p95_ns
            <= self.durability_lag_p99_ns
        ):
            raise ValueError("durability quantiles must be non-decreasing")
        recovery_values = (
            self.recovery_transaction_id,
            self.recovery_source_state,
            self.recovery_source_relative_path,
            self.recovery_source_bytes,
            self.recovery_source_sha256,
            self.recovery_control_event_id,
            self.recovered_frame_count,
            self.recovered_record_count,
            self.recovered_bytes,
            self.recovered_sha256,
            self.quarantined_suffix_relative_path,
            self.quarantined_suffix_bytes,
            self.quarantined_suffix_sha256,
        )
        if any(value is not None for value in recovery_values):
            raise ValueError("normal manifests cannot contain recovery lineage")
        if self.unavailable_fields:
            raise ValueError("normal manifests cannot name unavailable fields")

    def _validate_recovery_manifest(self) -> None:
        if self.zstd_level is not None or self.max_plain_frame_bytes is not None:
            raise ValueError("recovery manifests cannot invent codec settings")
        unavailable_values = (
            self.gap_count,
            self.reconnect_count,
            self.parse_error_count,
            self.checksum_error_count,
            self.queue_overflow_count,
            self.control_event_ids,
            self.durability_sample_count,
            self.durability_lag_p50_ns,
            self.durability_lag_p95_ns,
            self.durability_lag_p99_ns,
            self.durability_lag_max_ns,
            self.sync_count,
            self.sync_duration_total_ns,
            self.sync_duration_max_ns,
            self.slo_breach_count,
            self.write_failure_count,
            self.sync_failure_count,
        )
        if self.durability_measurement != "unavailable_after_crash" or any(
            value is not None for value in unavailable_values
        ):
            raise ValueError("recovery summaries must be unavailable after crash")
        required_values = (
            self.recovery_transaction_id,
            self.recovery_source_state,
            self.recovery_source_relative_path,
            self.recovery_source_bytes,
            self.recovery_source_sha256,
            self.recovery_control_event_id,
            self.recovered_frame_count,
            self.recovered_record_count,
            self.recovered_bytes,
            self.recovered_sha256,
        )
        if any(value is None for value in required_values):
            raise ValueError("recovery manifests require complete lineage facts")
        if self.recovery_source_state in {
            RecoverySourceState.CLEANUP_INTENT,
            RecoverySourceState.CLEANUP_TOMBSTONE,
        }:
            raise ValueError("cleanup outcomes do not publish recovery manifests")
        if self.created_at_ns is not None:
            raise ValueError("recovery manifests cannot invent created_at_ns")
        if self.unavailable_fields != RECOVERY_UNAVAILABLE_FIELDS:
            raise ValueError("recovery unavailable_fields set is not canonical")
        assert self.recovery_transaction_id is not None
        expected_control_event_id = (
            "raw-recovery-lineage:v1:" + self.recovery_transaction_id
        )
        if self.recovery_control_event_id != expected_control_event_id:
            raise ValueError("recovery control event ID does not match its transaction")
        if self.recovered_record_count != self.record_count:
            raise ValueError("recovered record count must match record_count")
        if self.recovered_bytes != self.file_size_bytes:
            raise ValueError("recovered bytes must match the published file")
        if self.recovered_sha256 != self.file_sha256:
            raise ValueError("recovered hash must match the published file")
        suffix_values = (
            self.quarantined_suffix_relative_path,
            self.quarantined_suffix_bytes,
            self.quarantined_suffix_sha256,
        )
        suffix_present = tuple(value is not None for value in suffix_values)
        if len(set(suffix_present)) != 1:
            raise ValueError(
                "quarantined suffix facts must be all present or all absent"
            )
        assert self.recovery_source_bytes is not None
        assert self.recovery_source_relative_path is not None
        assert self.recovery_source_sha256 is not None
        assert self.recovered_frame_count is not None
        assert self.recovered_record_count is not None
        assert self.recovered_bytes is not None
        assert self.recovered_sha256 is not None
        if self.recovered_frame_count > self.recovered_record_count:
            raise ValueError("recovered frames cannot exceed recovered records")
        if suffix_present[0]:
            assert self.quarantined_suffix_bytes is not None
            if (
                self.recovered_bytes + self.quarantined_suffix_bytes
                != self.recovery_source_bytes
            ):
                raise ValueError(
                    "recovery prefix and suffix bytes must cover the source"
                )
        elif self.recovered_bytes != self.recovery_source_bytes:
            raise ValueError("complete recovery bytes must match the source")

        source_state = self.recovery_source_state
        assert source_state is not None
        source_is_partial = self.recovery_source_relative_path.endswith(
            ".jsonl.zst.partial"
        )
        source_matches_published = (
            self.recovery_source_bytes == self.file_size_bytes
            and self.recovery_source_sha256 == self.file_sha256
        )
        if source_state is RecoverySourceState.PARTIAL_COMPLETE:
            if (
                suffix_present[0]
                or not source_is_partial
                or not source_matches_published
            ):
                raise ValueError("complete partial recovery facts are inconsistent")
        elif source_state is RecoverySourceState.PARTIAL_TRUNCATED:
            if not suffix_present[0] or not source_is_partial:
                raise ValueError("truncated partial recovery requires a bad suffix")
        elif source_state is RecoverySourceState.ORPHAN_CLOSED_DATA:
            if (
                suffix_present[0]
                or self.recovery_source_relative_path != self.data_relative_path
                or not source_matches_published
            ):
                raise ValueError("retained closed orphan must preserve its source")
        elif source_state is RecoverySourceState.OWNED_CONTROL_CARRIER:
            if (
                suffix_present[0]
                or self.logical_stream != "_control"
                or self.record_count != 1
                or self.recovered_frame_count != 1
                or self.recovery_source_relative_path
                != self.data_relative_path + ".partial"
                or not source_matches_published
            ):
                raise ValueError("owned control carrier facts are inconsistent")
        elif source_state is RecoverySourceState.PUBLICATION_COEXISTENCE and (
            suffix_present[0] or not source_is_partial or not source_matches_published
        ):
            raise ValueError("publication coexistence facts are inconsistent")

    def canonical_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="json")) + b"\n"


class ManifestValidationError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class LoadedRawManifest:
    path: Path
    manifest: RawManifestV1
    canonical_bytes: bytes
    sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("loaded manifest path must be Path")
        if type(self.manifest) is not RawManifestV1:
            raise TypeError("loaded manifest must be RawManifestV1")
        if self.canonical_bytes != self.manifest.canonical_bytes():
            raise ValueError("loaded canonical bytes do not match the manifest")
        expected_sha256 = hashlib.sha256(self.canonical_bytes).hexdigest()
        if self.sha256 != expected_sha256:
            raise ValueError("loaded manifest SHA-256 does not match canonical bytes")


def load_raw_manifest(path: Path) -> LoadedRawManifest:
    if not isinstance(path, Path):
        raise TypeError("manifest path must be Path")
    source = path.read_bytes()
    try:
        manifest = RawManifestV1.model_validate_json(source)
    except UnsupportedManifestSchema:
        raise
    except (ValidationError, ValueError) as error:
        raise ManifestValidationError("raw manifest structure is invalid") from error
    canonical = manifest.canonical_bytes()
    if source != canonical:
        raise ManifestValidationError("raw manifest bytes are not canonical")
    return LoadedRawManifest(
        path=path,
        manifest=manifest,
        canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


__all__ = [
    "RECOVERY_UNAVAILABLE_FIELDS",
    "LoadedRawManifest",
    "ManifestValidationError",
    "RawManifestV1",
    "RecoverySourceState",
    "UnsupportedManifestSchema",
    "lease_path_for_data",
    "load_raw_manifest",
    "manifest_path_for_data",
]
