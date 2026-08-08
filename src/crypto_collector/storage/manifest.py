from __future__ import annotations

import hashlib
import io
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, BinaryIO, Literal, Protocol, Self, TypeVar, cast

import zstandard
from pydantic import BeforeValidator, Field, ValidationError, model_validator

from crypto_collector.domain.envelope import (
    MARKET_SCOPED_STREAMS,
    FrozenStrictModel,
    RawEnvelope,
)
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.domain.paths import encode_instrument_key
from crypto_collector.domain.types import CloseReason, Exchange, Market
from crypto_collector.storage.errors import SourceUnavailable
from crypto_collector.storage.lease import (
    SourceLease,
    _normalized_absolute_path,
    _open_regular_no_follow,
)
from crypto_collector.storage.models import (
    CanonicalUuid,
    NonEmptyString,
    NormalizedDataRelativePath,
    NormalizedStateRelativePath,
    Sha256,
)
from crypto_collector.storage.serialize import decode_envelope_jsonl

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


class SourceDisposition(StrEnum):
    PRESENT_VERIFIED = "present_verified"
    CLEANUP_INTENT = "cleanup_intent"
    CLEANUP_TOMBSTONE = "cleanup_tombstone"
    MISSING_UNEXPLAINED = "missing_unexplained"


class CleanupProofKind(StrEnum):
    DURABLE_INTENT = "durable_intent"
    FINAL_TOMBSTONE = "final_tombstone"


class CleanupProofEvidenceV1(FrozenStrictModel):
    schema_version: ManifestSchemaVersion1 = 1
    kind: CleanupProofKind
    proof_relative_path: NormalizedStateRelativePath
    proof_size_bytes: PositiveInt
    proof_sha256: Sha256
    source_manifest_relative_path: NormalizedDataRelativePath
    source_manifest_sha256: Sha256
    source_data_relative_path: NormalizedDataRelativePath
    source_data_size_bytes: PositiveInt
    source_data_sha256: Sha256


@dataclass(frozen=True, slots=True)
class LocalSourceValidation:
    disposition: SourceDisposition
    cleanup_proof: CleanupProofEvidenceV1 | None

    def __post_init__(self) -> None:
        if type(self.disposition) is not SourceDisposition:
            raise TypeError("source disposition must be SourceDisposition")
        proof_expected = self.disposition in {
            SourceDisposition.CLEANUP_INTENT,
            SourceDisposition.CLEANUP_TOMBSTONE,
        }
        if proof_expected != (self.cleanup_proof is not None):
            raise ValueError("cleanup proof presence does not match source disposition")


class SourceDispositionResolver(Protocol):
    def resolve_missing(
        self,
        *,
        loaded: LoadedRawManifest,
        data_path: Path,
        expected_data_sha256: str,
        expected_proof: CleanupProofEvidenceV1 | None = None,
    ) -> CleanupProofEvidenceV1 | None: ...


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


def _read_fd_bytes(fd: int) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    while True:
        try:
            chunk = os.read(fd, 1024 * 1024)
        except InterruptedError:
            continue
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


def _hash_fd(fd: int) -> tuple[int, str]:
    os.lseek(fd, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    size = 0
    while True:
        try:
            chunk = os.read(fd, 1024 * 1024)
        except InterruptedError:
            continue
        if not chunk:
            os.lseek(fd, 0, os.SEEK_SET)
            return size, digest.hexdigest()
        size += len(chunk)
        digest.update(chunk)


def load_raw_manifest(path: Path) -> LoadedRawManifest:
    if not isinstance(path, Path):
        raise TypeError("manifest path must be Path")
    fd, absolute = _open_regular_no_follow(path)
    try:
        source = _read_fd_bytes(fd)
    finally:
        os.close(fd)
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
        path=absolute,
        manifest=manifest,
        canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _expected_manifest_path(loaded: LoadedRawManifest, data_root: Path) -> Path:
    if not isinstance(data_root, Path):
        raise TypeError("data_root must be Path")
    root = _normalized_absolute_path(data_root / "root-sentinel").parent
    expected = root / loaded.manifest.manifest_relative_path
    if loaded.path != expected:
        raise ManifestValidationError(
            "loaded manifest path does not match manifest_relative_path"
        )
    return expected


def _validate_cleanup_evidence(
    evidence: CleanupProofEvidenceV1,
    *,
    loaded: LoadedRawManifest,
    expected_proof: CleanupProofEvidenceV1 | None,
) -> None:
    if type(evidence) is not CleanupProofEvidenceV1:
        raise ManifestValidationError("cleanup resolver returned invalid evidence")
    manifest = loaded.manifest
    observed_binding = (
        evidence.source_manifest_relative_path,
        evidence.source_manifest_sha256,
        evidence.source_data_relative_path,
        evidence.source_data_size_bytes,
        evidence.source_data_sha256,
    )
    expected_binding = (
        manifest.manifest_relative_path,
        loaded.sha256,
        manifest.data_relative_path,
        manifest.file_size_bytes,
        manifest.file_sha256,
    )
    if observed_binding != expected_binding:
        raise ManifestValidationError("cleanup proof does not bind the exact source")
    if expected_proof is not None and evidence != expected_proof:
        raise ManifestValidationError("cleanup proof differs from frozen evidence")


def validate_local_source(
    loaded: LoadedRawManifest,
    *,
    data_root: Path,
    resolver: SourceDispositionResolver,
    lease: SourceLease,
    expected_cleanup_proof: CleanupProofEvidenceV1 | None = None,
) -> LocalSourceValidation:
    if type(loaded) is not LoadedRawManifest:
        raise TypeError("loaded must be LoadedRawManifest")
    if not isinstance(lease, SourceLease):
        raise TypeError("lease must be SourceLease")
    _expected_manifest_path(loaded, data_root)
    root = _normalized_absolute_path(data_root / "root-sentinel").parent
    data_path = root / loaded.manifest.data_relative_path
    expected_lease_path = lease_path_for_data(data_path)
    try:
        lease._assert_held_for(expected_lease_path)
    except (RuntimeError, ValueError) as error:
        raise ManifestValidationError(
            "source lease does not bind this manifest"
        ) from error

    try:
        fd, _ = _open_regular_no_follow(data_path)
    except FileNotFoundError:
        evidence = resolver.resolve_missing(
            loaded=loaded,
            data_path=data_path,
            expected_data_sha256=loaded.manifest.file_sha256,
            expected_proof=expected_cleanup_proof,
        )
        if evidence is None:
            return LocalSourceValidation(
                disposition=SourceDisposition.MISSING_UNEXPLAINED,
                cleanup_proof=None,
            )
        _validate_cleanup_evidence(
            evidence,
            loaded=loaded,
            expected_proof=expected_cleanup_proof,
        )
        disposition = (
            SourceDisposition.CLEANUP_INTENT
            if evidence.kind is CleanupProofKind.DURABLE_INTENT
            else SourceDisposition.CLEANUP_TOMBSTONE
        )
        return LocalSourceValidation(
            disposition=disposition,
            cleanup_proof=evidence,
        )

    try:
        size, sha256 = _hash_fd(fd)
    finally:
        os.close(fd)
    if size != loaded.manifest.file_size_bytes:
        raise ManifestValidationError("local source size does not match its manifest")
    if sha256 != loaded.manifest.file_sha256:
        raise ManifestValidationError(
            "local source SHA-256 does not match its manifest"
        )
    return LocalSourceValidation(
        disposition=SourceDisposition.PRESENT_VERIFIED,
        cleanup_proof=None,
    )


class _NoCleanupProofResolver:
    def resolve_missing(
        self,
        *,
        loaded: LoadedRawManifest,
        data_path: Path,
        expected_data_sha256: str,
        expected_proof: CleanupProofEvidenceV1 | None = None,
    ) -> None:
        return None


class RawManifestReader:
    def __init__(
        self,
        manifest_path: Path,
        *,
        expected_manifest_sha256: str | None = None,
    ) -> None:
        if not isinstance(manifest_path, Path):
            raise TypeError("manifest_path must be Path")
        if expected_manifest_sha256 is not None and (
            type(expected_manifest_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_manifest_sha256) is None
        ):
            raise ValueError(
                "expected_manifest_sha256 must be a lowercase SHA-256 digest"
            )
        self.manifest_path = _normalized_absolute_path(manifest_path)
        self.expected_manifest_sha256 = expected_manifest_sha256
        self._loaded: LoadedRawManifest | None = None
        self._lease: SourceLease | None = None
        self._data_file: BinaryIO | None = None
        self._zstd_reader: BinaryIO | None = None
        self._reader: BinaryIO | None = None
        self._done = False
        self._rows: list[RawEnvelope] = []

    @staticmethod
    def _infer_data_root(loaded: LoadedRawManifest) -> Path:
        suffix = Path(loaded.manifest.manifest_relative_path).parts
        parts = loaded.path.parts
        if len(parts) <= len(suffix) or tuple(parts[-len(suffix) :]) != suffix:
            raise ManifestValidationError(
                "manifest path does not end with manifest_relative_path"
            )
        return Path(*parts[: -len(suffix)])

    def __enter__(self) -> Self:
        if self._lease is not None:
            raise RuntimeError("raw manifest reader is already entered")
        loaded = load_raw_manifest(self.manifest_path)
        if (
            self.expected_manifest_sha256 is not None
            and loaded.sha256 != self.expected_manifest_sha256
        ):
            raise ManifestValidationError(
                "raw manifest SHA-256 differs from the expected source identity"
            )
        data_root = self._infer_data_root(loaded)
        data_path = data_root / loaded.manifest.data_relative_path
        lease = SourceLease.shared(lease_path_for_data(data_path))
        fd: int | None = None
        data_file: BinaryIO | None = None
        zstd_reader: BinaryIO | None = None
        reader: BinaryIO | None = None
        try:
            validation = validate_local_source(
                loaded,
                data_root=data_root,
                resolver=_NoCleanupProofResolver(),
                lease=lease,
            )
            if validation.disposition is not SourceDisposition.PRESENT_VERIFIED:
                raise SourceUnavailable(
                    f"raw source is unavailable: {loaded.manifest.data_relative_path}"
                )
            fd, _ = _open_regular_no_follow(data_path)
            size, sha256 = _hash_fd(fd)
            if (
                size != loaded.manifest.file_size_bytes
                or sha256 != loaded.manifest.file_sha256
            ):
                raise ManifestValidationError(
                    "local source changed after manifest validation"
                )
            data_file = os.fdopen(fd, "rb", closefd=True)
            fd = None
            zstd_reader_impl = zstandard.ZstdDecompressor().stream_reader(
                data_file,
                read_across_frames=True,
            )
            zstd_reader = cast(BinaryIO, zstd_reader_impl)
            reader = io.BufferedReader(zstd_reader_impl)
        except BaseException as error:
            cleanup_errors: list[BaseException] = []
            for resource in (reader, zstd_reader, data_file):
                if resource is None:
                    continue
                try:
                    resource.close()
                except BaseException as cleanup_error:  # noqa: BLE001
                    cleanup_errors.append(cleanup_error)
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as cleanup_error:  # noqa: BLE001
                    cleanup_errors.append(cleanup_error)
            try:
                lease.release()
            except BaseException as cleanup_error:  # noqa: BLE001
                cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                error.add_note(
                    "reader cleanup also failed: "
                    + ", ".join(type(item).__name__ for item in cleanup_errors)
                )
            raise
        assert data_file is not None
        assert zstd_reader is not None
        assert reader is not None
        self._loaded = loaded
        self._lease = lease
        self._data_file = data_file
        self._zstd_reader = zstd_reader
        self._reader = reader
        self._done = False
        self._rows = []
        return self

    def __iter__(self) -> Iterator[RawEnvelope]:
        if self._reader is None:
            raise RuntimeError("raw manifest reader is not entered")
        return self

    def __next__(self) -> RawEnvelope:
        reader = self._reader
        loaded = self._loaded
        if reader is None or loaded is None:
            raise RuntimeError("raw manifest reader is not entered")
        if self._done:
            raise StopIteration
        try:
            line = reader.readline()
            if not line:
                self._validate_complete_rows(loaded.manifest)
                self._done = True
                raise StopIteration
            envelope = decode_envelope_jsonl(line)
            self._validate_row_identity(envelope, loaded.manifest)
        except StopIteration:
            raise
        except (OSError, ValueError, zstandard.ZstdError) as error:
            raise ManifestValidationError("raw source rows are invalid") from error
        self._rows.append(envelope)
        if len(self._rows) > loaded.manifest.record_count:
            raise ManifestValidationError("raw source has more rows than its manifest")
        return envelope

    def _validate_row_identity(
        self,
        envelope: RawEnvelope,
        manifest: RawManifestV1,
    ) -> None:
        expected = (
            manifest.exchange,
            manifest.market,
            manifest.instrument_key,
            manifest.logical_stream,
            manifest.worker_instance_id,
            manifest.config_sha256,
        )
        observed = (
            envelope.exchange,
            envelope.market,
            envelope.instrument_key,
            envelope.logical_stream,
            envelope.worker_instance_id,
            envelope.config_sha256,
        )
        if observed != expected:
            raise ManifestValidationError(
                "raw row identity does not match its manifest"
            )
        if self._rows and envelope.writer_sequence <= self._rows[-1].writer_sequence:
            raise ManifestValidationError("raw writer sequences are not increasing")

    def _validate_complete_rows(self, manifest: RawManifestV1) -> None:
        rows = self._rows
        if len(rows) != manifest.record_count:
            raise ManifestValidationError(
                "raw source row count does not match manifest"
            )
        if not rows:
            raise ManifestValidationError("raw source must contain at least one row")
        event_times = [
            row.event_time_ns for row in rows if row.event_time_ns is not None
        ]
        requested = {
            row.rest_metadata.requested_interval_ns
            for row in rows
            if row.rest_metadata is not None
            and row.rest_metadata.requested_interval_ns is not None
        }
        effective = {
            row.rest_metadata.effective_interval_ns
            for row in rows
            if row.rest_metadata is not None
            and row.rest_metadata.effective_interval_ns is not None
        }
        observed = (
            rows[0].received_at_ns,
            rows[-1].received_at_ns,
            event_times[0] if event_times else None,
            event_times[-1] if event_times else None,
            rows[0].writer_sequence,
            rows[-1].writer_sequence,
            tuple(
                sorted({row.wire_symbol for row in rows if row.wire_symbol is not None})
            ),
            tuple(
                sorted(
                    {
                        row.connection_generation
                        for row in rows
                        if row.connection_generation is not None
                    }
                )
            ),
            tuple(sorted({row.egress_id for row in rows if row.egress_id is not None})),
            tuple(sorted(requested)),
            tuple(sorted(effective)),
        )
        expected = (
            manifest.first_received_at_ns,
            manifest.last_received_at_ns,
            manifest.first_event_time_ns,
            manifest.last_event_time_ns,
            manifest.writer_sequence_first,
            manifest.writer_sequence_last,
            manifest.wire_symbols,
            manifest.connection_generations,
            manifest.egress_ids,
            manifest.requested_intervals_ns,
            manifest.effective_intervals_ns,
        )
        if observed != expected:
            raise ManifestValidationError("raw row facts do not match their manifest")

    def __exit__(self, *_exc: object) -> None:
        reader = self._reader
        zstd_reader = self._zstd_reader
        data_file = self._data_file
        lease = self._lease
        self._reader = None
        self._zstd_reader = None
        self._data_file = None
        self._lease = None
        self._loaded = None
        try:
            if reader is not None:
                reader.close()
            elif zstd_reader is not None:
                zstd_reader.close()
            if data_file is not None and not data_file.closed:
                data_file.close()
        finally:
            if lease is not None:
                lease.release()


__all__ = [
    "RECOVERY_UNAVAILABLE_FIELDS",
    "CleanupProofEvidenceV1",
    "CleanupProofKind",
    "LoadedRawManifest",
    "LocalSourceValidation",
    "ManifestValidationError",
    "RawManifestReader",
    "RawManifestV1",
    "RecoverySourceState",
    "SourceDisposition",
    "SourceDispositionResolver",
    "SourceUnavailable",
    "UnsupportedManifestSchema",
    "lease_path_for_data",
    "load_raw_manifest",
    "manifest_path_for_data",
    "validate_local_source",
]
