from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import uuid
from collections.abc import Iterable
from concurrent.futures import Executor
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, ClassVar, Literal, Protocol, Self, TypeVar, cast

import zstandard
from pydantic import Field, ValidationError, ValidationInfo, model_validator

from crypto_collector.domain.clock import Clock
from crypto_collector.domain.envelope import (
    MARKET_SCOPED_STREAMS,
    FrozenStrictModel,
    NativeEventDraft,
    RawEnvelope,
)
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.domain.paths import decode_instrument_key, encode_instrument_key
from crypto_collector.domain.types import CloseReason, Exchange, Market, Transport
from crypto_collector.storage.durability import (
    DurabilityTrigger,
    RecoveryAccountingMode,
    RecoveryDurabilityCoordinator,
    StorageIoLimiter,
)
from crypto_collector.storage.errors import PublicationConflict, RecoveryBlocked
from crypto_collector.storage.lease import (
    SourceLease,
    _open_parent_no_follow,
    _open_regular_no_follow,
)
from crypto_collector.storage.manifest import (
    RECOVERY_UNAVAILABLE_FIELDS,
    CleanupProofEvidenceV1,
    CleanupProofKind,
    RawManifestV1,
    RecoverySourceState,
    SourceDisposition,
    SourceDispositionResolver,
    lease_path_for_data,
    load_raw_manifest,
    manifest_path_for_data,
    validate_local_source,
)
from crypto_collector.storage.models import (
    AcceptedRecord,
    AcceptedRecordIdentityV1,
    CanonicalUuid,
    NonEmptyString,
    NormalizedDataRelativePath,
    NormalizedStateRelativePath,
    SchemaVersion1,
    Sha256,
    StorageControlAssociationV1,
    StorageControlTargetV1,
    validate_normalized_data_relative_path,
)
from crypto_collector.storage.raw_writer import (
    _open_bound_readonly_and_close,
    atomic_write_and_sync_json_exclusive,
    fsync_directory,
    publish_no_replace,
    run_storage,
    size_and_sha256_fd,
)
from crypto_collector.storage.serialize import decode_envelope_jsonl, encode_envelope
from crypto_collector.storage.stats import CumulativeDurabilityHistogram
from crypto_collector.storage.stream_file import StreamFile, write_all

NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]

RECOVERY_GENERATION_NAMESPACE = uuid.UUID("54c28b47-77d8-5f40-a39d-486f57a98f44")
_FINAL_PART_NAME = re.compile(
    r"^part-((?:0|[1-9][0-9]*))-((?:0|[1-9][0-9]*))\.jsonl\.zst$"
)
_RECOVERY_EVENT_PREFIX = "raw-recovery-lineage:v1:"
_CANONICAL_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _normalized_relative_path(value: str, *, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be str")
    try:
        return validate_normalized_data_relative_path(value)
    except ValueError as error:
        raise ValueError(f"{field_name} must be normalized") from error


def recovery_generation_id(data_relative_path: str) -> str:
    normalized = _normalized_relative_path(
        data_relative_path,
        field_name="data_relative_path",
    )
    if not _FINAL_PART_NAME.fullmatch(Path(normalized).name):
        raise ValueError("data_relative_path must name a canonical final raw part")
    _parse_source_path(normalized)
    return str(uuid.uuid5(RECOVERY_GENERATION_NAMESPACE, normalized))


def _quarantine_relative_path(source_relative_path: str, *, suffix: str) -> str:
    source = _normalized_relative_path(
        source_relative_path,
        field_name="source_relative_path",
    )
    if not source.endswith((".jsonl.zst", ".jsonl.zst.partial")):
        raise ValueError("source_relative_path must name raw data")
    return _normalized_relative_path(
        f"quarantine/{source}.{suffix}",
        field_name="quarantine_relative_path",
    )


def bad_tail_quarantine_relative_path(source_relative_path: str) -> str:
    return _quarantine_relative_path(source_relative_path, suffix="bad-tail")


def whole_source_quarantine_relative_path(source_relative_path: str) -> str:
    return _quarantine_relative_path(source_relative_path, suffix="whole")


@dataclass(frozen=True, slots=True)
class ValidatedRecoveryFrame:
    start_offset: int
    end_offset: int
    envelopes: tuple[RawEnvelope, ...]

    def __post_init__(self) -> None:
        if (
            type(self.start_offset) is not int
            or type(self.end_offset) is not int
            or self.start_offset < 0
            or self.end_offset <= self.start_offset
        ):
            raise ValueError("recovery frame offsets are invalid")
        if not self.envelopes or any(
            type(envelope) is not RawEnvelope for envelope in self.envelopes
        ):
            raise ValueError("recovery frame must contain validated envelopes")


@dataclass(frozen=True, slots=True)
class RecoveryFrameScan:
    source_size_bytes: int
    valid_prefix_size_bytes: int
    frames: tuple[ValidatedRecoveryFrame, ...]

    def __post_init__(self) -> None:
        if (
            type(self.source_size_bytes) is not int
            or type(self.valid_prefix_size_bytes) is not int
            or self.source_size_bytes < 0
            or not 0 <= self.valid_prefix_size_bytes <= self.source_size_bytes
        ):
            raise ValueError("recovery frame scan sizes are invalid")
        expected_start = 0
        for frame in self.frames:
            if frame.start_offset != expected_start:
                raise ValueError("recovery frames must form one contiguous prefix")
            expected_start = frame.end_offset
        if expected_start != self.valid_prefix_size_bytes:
            raise ValueError("recovery frame prefix size is inconsistent")

    @property
    def invalid_suffix_size_bytes(self) -> int:
        return self.source_size_bytes - self.valid_prefix_size_bytes

    @property
    def record_count(self) -> int:
        return sum(len(frame.envelopes) for frame in self.frames)


@dataclass(frozen=True, slots=True)
class RecoveryRowFacts:
    exchange: Exchange
    market: Market | None
    instrument_key: str | None
    logical_stream: str
    wire_symbols: tuple[str, ...]
    record_count: int
    first_received_at_ns: int
    last_received_at_ns: int
    first_event_time_ns: int | None
    last_event_time_ns: int | None
    worker_instance_id: str
    connection_generations: tuple[int, ...]
    writer_sequence_first: int
    writer_sequence_last: int
    config_sha256: str
    egress_ids: tuple[str, ...]
    requested_intervals_ns: tuple[int, ...]
    effective_intervals_ns: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class StreamingRecoveryScan:
    source_size_bytes: int
    source_sha256: str
    valid_prefix_size_bytes: int
    valid_prefix_sha256: str
    invalid_suffix_size_bytes: int
    invalid_suffix_sha256: str | None
    frame_count: int
    row_facts: RecoveryRowFacts | None

    def __post_init__(self) -> None:
        if (
            self.source_size_bytes
            != self.valid_prefix_size_bytes + self.invalid_suffix_size_bytes
        ):
            raise ValueError("streaming recovery scan byte counts are inconsistent")
        if (self.invalid_suffix_size_bytes == 0) != (
            self.invalid_suffix_sha256 is None
        ):
            raise ValueError("streaming recovery suffix hash is inconsistent")
        if (self.frame_count == 0) != (self.row_facts is None):
            raise ValueError("streaming recovery row facts are inconsistent")


class _RecoveryRowFactsBuilder:
    def __init__(self) -> None:
        self.rows: int = 0
        self.first: RawEnvelope | None = None
        self.last: RawEnvelope | None = None
        self.first_event_time_ns: int | None = None
        self.last_event_time_ns: int | None = None
        self.wire_symbols: set[str] = set()
        self.connection_generations: set[int] = set()
        self.egress_ids: set[str] = set()
        self.requested_intervals_ns: set[int] = set()
        self.effective_intervals_ns: set[int] = set()

    def extend(self, envelopes: tuple[RawEnvelope, ...]) -> None:
        for envelope in envelopes:
            if self.first is None:
                self.first = envelope
            self.last = envelope
            self.rows += 1
            if envelope.event_time_ns is not None:
                if self.first_event_time_ns is None:
                    self.first_event_time_ns = envelope.event_time_ns
                self.last_event_time_ns = envelope.event_time_ns
            if envelope.wire_symbol is not None:
                self.wire_symbols.add(envelope.wire_symbol)
            if envelope.connection_generation is not None:
                self.connection_generations.add(envelope.connection_generation)
            if envelope.egress_id is not None:
                self.egress_ids.add(envelope.egress_id)
            metadata = envelope.rest_metadata
            if metadata is not None and metadata.requested_interval_ns is not None:
                self.requested_intervals_ns.add(metadata.requested_interval_ns)
                assert metadata.effective_interval_ns is not None
                self.effective_intervals_ns.add(metadata.effective_interval_ns)

    def freeze(self) -> RecoveryRowFacts | None:
        first = self.first
        last = self.last
        if first is None or last is None:
            return None
        return RecoveryRowFacts(
            exchange=first.exchange,
            market=first.market,
            instrument_key=first.instrument_key,
            logical_stream=first.logical_stream,
            wire_symbols=tuple(sorted(self.wire_symbols)),
            record_count=self.rows,
            first_received_at_ns=first.received_at_ns,
            last_received_at_ns=last.received_at_ns,
            first_event_time_ns=self.first_event_time_ns,
            last_event_time_ns=self.last_event_time_ns,
            worker_instance_id=first.worker_instance_id,
            connection_generations=tuple(sorted(self.connection_generations)),
            writer_sequence_first=first.writer_sequence,
            writer_sequence_last=last.writer_sequence,
            config_sha256=first.config_sha256,
            egress_ids=tuple(sorted(self.egress_ids)),
            requested_intervals_ns=tuple(sorted(self.requested_intervals_ns)),
            effective_intervals_ns=tuple(sorted(self.effective_intervals_ns)),
        )


@dataclass(frozen=True, slots=True)
class _SourcePathIdentity:
    exchange: Exchange
    market: Market | None
    instrument_key: str | None
    logical_stream: str
    storage_hour: tuple[str, str, str, str]


def _parse_source_path(source_relative_path: str) -> _SourcePathIdentity:
    source = _normalized_relative_path(
        source_relative_path,
        field_name="source_relative_path",
    )
    parts = source.split("/")
    if parts[0] != "raw":
        raise ValueError("source path must be below raw")
    try:
        exchange = Exchange(parts[1])
    except (IndexError, ValueError) as error:
        raise ValueError("source path has an invalid exchange") from error
    if len(parts) == 8 and parts[2] == "_control":
        market = None
        instrument_key = None
        logical_stream = "_control"
        storage_hour = tuple(parts[3:7])
        filename = parts[7]
    elif len(parts) == 10:
        try:
            market = Market(parts[2])
        except ValueError as error:
            raise ValueError("source path has an invalid market") from error
        logical_stream = parts[4]
        identity_segment = parts[3]
        if identity_segment == "_market":
            instrument_key = None
            if logical_stream not in MARKET_SCOPED_STREAMS:
                raise ValueError("source path market scope does not match stream")
        else:
            instrument_key = decode_instrument_key(identity_segment)
            if encode_instrument_key(instrument_key) != identity_segment:
                raise ValueError("source path instrument encoding is not canonical")
            if logical_stream in MARKET_SCOPED_STREAMS:
                raise ValueError("market-scoped stream cannot use an instrument path")
        storage_hour = tuple(parts[5:9])
        filename = parts[9]
    else:
        raise ValueError("source path does not match a raw storage scope")
    if len(storage_hour) != 4:
        raise ValueError("source path storage hour is invalid")
    try:
        parsed_hour = datetime(
            int(storage_hour[0]),
            int(storage_hour[1]),
            int(storage_hour[2]),
            int(storage_hour[3]),
            tzinfo=UTC,
        )
    except (TypeError, ValueError) as error:
        raise ValueError("source path storage hour is invalid") from error
    canonical_hour = (
        f"{parsed_hour.year:04d}",
        f"{parsed_hour.month:02d}",
        f"{parsed_hour.day:02d}",
        f"{parsed_hour.hour:02d}",
    )
    if storage_hour != canonical_hour:
        raise ValueError("source path storage hour is not canonical")
    final_filename = filename.removesuffix(".partial")
    filename_match = _FINAL_PART_NAME.fullmatch(final_filename)
    if filename_match is None:
        raise ValueError("source path does not name a canonical raw part")
    expected_hour_start_ns = int(parsed_hour.timestamp()) * 1_000_000_000
    if int(filename_match.group(1)) != expected_hour_start_ns:
        raise ValueError("source part start does not match its storage hour")
    return _SourcePathIdentity(
        exchange=exchange,
        market=market,
        instrument_key=instrument_key,
        logical_stream=logical_stream,
        storage_hour=canonical_hour,
    )


def _decode_valid_frame_rows(
    plain: bytes,
    *,
    identity: _SourcePathIdentity,
    expected_worker_instance_id: str | None,
    expected_config_sha256: str | None,
    previous_writer_sequence: int | None,
) -> tuple[tuple[RawEnvelope, ...], str, str, int]:
    if not plain or not plain.endswith(b"\n"):
        raise ValueError("recovery frame is not complete JSONL")
    segments = plain.split(b"\n")
    if segments[-1] != b"" or any(not segment for segment in segments[:-1]):
        raise ValueError("recovery frame contains an empty or trailing row")
    envelopes = tuple(
        decode_envelope_jsonl(segment + b"\n") for segment in segments[:-1]
    )
    worker = expected_worker_instance_id
    config_sha256 = expected_config_sha256
    sequence = previous_writer_sequence
    for envelope in envelopes:
        observed_identity = (
            envelope.exchange,
            envelope.market,
            envelope.instrument_key,
            envelope.logical_stream,
        )
        expected_identity = (
            identity.exchange,
            identity.market,
            identity.instrument_key,
            identity.logical_stream,
        )
        if observed_identity != expected_identity:
            raise ValueError("recovery row does not match source path identity")
        try:
            received_hour = datetime.fromtimestamp(
                envelope.received_at_ns // 1_000_000_000,
                tz=UTC,
            ).strftime("%Y/%m/%d/%H")
        except (OverflowError, OSError, ValueError) as error:
            raise ValueError("recovery row received time is invalid") from error
        if tuple(received_hour.split("/")) != identity.storage_hour:
            raise ValueError("recovery row crosses the source storage hour")
        if worker is None:
            worker = envelope.worker_instance_id
            config_sha256 = envelope.config_sha256
        elif (
            envelope.worker_instance_id != worker
            or envelope.config_sha256 != config_sha256
        ):
            raise ValueError("recovery part mixes worker or config identities")
        if sequence is not None and envelope.writer_sequence <= sequence:
            raise ValueError("recovery writer sequences must be strictly increasing")
        sequence = envelope.writer_sequence
    assert worker is not None
    assert config_sha256 is not None
    assert sequence is not None
    return envelopes, worker, config_sha256, sequence


def scan_recovery_frames(
    source: bytes,
    source_relative_path: str,
) -> RecoveryFrameScan:
    if type(source) is not bytes:
        raise TypeError("recovery source must be bytes")
    identity = _parse_source_path(source_relative_path)
    offset = 0
    frames: list[ValidatedRecoveryFrame] = []
    worker_instance_id: str | None = None
    config_sha256: str | None = None
    writer_sequence: int | None = None
    source_view = memoryview(source)
    while offset < len(source):
        remaining = source_view[offset:]
        try:
            decompressor = zstandard.ZstdDecompressor().decompressobj()
            plain = decompressor.decompress(remaining)
            if not decompressor.eof:
                break
            consumed = len(remaining) - len(decompressor.unused_data)
            if consumed <= 0:
                break
            frame_bytes = remaining[:consumed]
            parameters = zstandard.get_frame_parameters(frame_bytes)
            if not parameters.has_checksum or parameters.content_size != len(plain):
                break
            envelopes, next_worker, next_config, next_sequence = (
                _decode_valid_frame_rows(
                    plain,
                    identity=identity,
                    expected_worker_instance_id=worker_instance_id,
                    expected_config_sha256=config_sha256,
                    previous_writer_sequence=writer_sequence,
                )
            )
        except (TypeError, ValueError, zstandard.ZstdError):
            break
        frames.append(
            ValidatedRecoveryFrame(
                start_offset=offset,
                end_offset=offset + consumed,
                envelopes=envelopes,
            )
        )
        offset += consumed
        worker_instance_id = next_worker
        config_sha256 = next_config
        writer_sequence = next_sequence
    return RecoveryFrameScan(
        source_size_bytes=len(source),
        valid_prefix_size_bytes=offset,
        frames=tuple(frames),
    )


def _scan_recovery_chunks(
    chunks: Iterable[bytes],
    source_relative_path: str,
) -> StreamingRecoveryScan:
    identity = _parse_source_path(source_relative_path)
    source_digest = hashlib.sha256()
    prefix_digest = hashlib.sha256()
    suffix_digest = hashlib.sha256()
    source_size = 0
    prefix_size = 0
    suffix_size = 0
    frame_count = 0
    invalid = False
    compressed = bytearray()
    plain = bytearray()
    decompressor = zstandard.ZstdDecompressor().decompressobj()
    worker_instance_id: str | None = None
    config_sha256: str | None = None
    writer_sequence: int | None = None
    row_facts = _RecoveryRowFactsBuilder()

    for chunk in chunks:
        if type(chunk) is not bytes:
            raise TypeError("recovery chunks must contain bytes")
        if not chunk:
            continue
        source_digest.update(chunk)
        source_size += len(chunk)
        if invalid:
            suffix_digest.update(chunk)
            suffix_size += len(chunk)
            continue
        pending: bytes | memoryview = memoryview(chunk)
        while pending:
            try:
                decoded = decompressor.decompress(pending)
            except zstandard.ZstdError:
                compressed.extend(pending)
                suffix_digest.update(compressed)
                suffix_size += len(compressed)
                compressed.clear()
                plain.clear()
                invalid = True
                break
            plain.extend(decoded)
            if not decompressor.eof:
                compressed.extend(pending)
                break
            unused = decompressor.unused_data
            consumed = len(pending) - len(unused)
            compressed.extend(pending[:consumed])
            frame_bytes = bytes(compressed)
            try:
                parameters = zstandard.get_frame_parameters(frame_bytes)
                if not parameters.has_checksum or parameters.content_size != len(plain):
                    raise ValueError("recovery frame codec facts are invalid")
                envelopes, next_worker, next_config, next_sequence = (
                    _decode_valid_frame_rows(
                        bytes(plain),
                        identity=identity,
                        expected_worker_instance_id=worker_instance_id,
                        expected_config_sha256=config_sha256,
                        previous_writer_sequence=writer_sequence,
                    )
                )
            except (TypeError, ValueError, zstandard.ZstdError):
                suffix_digest.update(frame_bytes)
                suffix_digest.update(unused)
                suffix_size += len(frame_bytes) + len(unused)
                invalid = True
                break
            prefix_digest.update(frame_bytes)
            prefix_size += len(frame_bytes)
            frame_count += 1
            row_facts.extend(envelopes)
            worker_instance_id = next_worker
            config_sha256 = next_config
            writer_sequence = next_sequence
            compressed.clear()
            plain.clear()
            decompressor = zstandard.ZstdDecompressor().decompressobj()
            pending = unused

    if not invalid and compressed:
        suffix_digest.update(compressed)
        suffix_size += len(compressed)
    return StreamingRecoveryScan(
        source_size_bytes=source_size,
        source_sha256=source_digest.hexdigest(),
        valid_prefix_size_bytes=prefix_size,
        valid_prefix_sha256=prefix_digest.hexdigest(),
        invalid_suffix_size_bytes=suffix_size,
        invalid_suffix_sha256=(suffix_digest.hexdigest() if suffix_size else None),
        frame_count=frame_count,
        row_facts=row_facts.freeze(),
    )


@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    intent: RecoveryIntentV1
    manifest: RawManifestV1 | None
    recovered_data_bytes: bytes | None
    quarantine_bytes: bytes | None

    def __post_init__(self) -> None:
        if type(self.intent) is not RecoveryIntentV1:
            raise TypeError("recovery plan intent must be RecoveryIntentV1")
        if self.manifest is not None and type(self.manifest) is not RawManifestV1:
            raise TypeError("recovery plan manifest must be RawManifestV1 or None")
        if (
            self.recovered_data_bytes is not None
            and type(self.recovered_data_bytes) is not bytes
        ):
            raise TypeError("recovered_data_bytes must be bytes or None")
        if (
            self.quarantine_bytes is not None
            and type(self.quarantine_bytes) is not bytes
        ):
            raise TypeError("quarantine_bytes must be bytes or None")
        if (self.manifest is None) != (
            self.intent.planned_manifest_relative_path is None
        ):
            raise ValueError("recovery plan manifest does not match its intent")
        if self.manifest is not None and (
            self.manifest.canonical_bytes() != self.manifest_bytes
            or self.intent.planned_manifest_size_bytes != len(self.manifest_bytes)
            or self.intent.planned_manifest_sha256
            != hashlib.sha256(self.manifest_bytes).hexdigest()
        ):
            raise ValueError("recovery plan manifest bytes do not match intent")
        if self.recovered_data_bytes is not None:
            if (
                self.intent.planned_data_size_bytes != len(self.recovered_data_bytes)
                or self.intent.planned_data_sha256
                != hashlib.sha256(self.recovered_data_bytes).hexdigest()
            ):
                raise ValueError("recovery plan recovered data does not match intent")
        elif (
            self.intent.planned_source_disposition is RecoverySourceDisposition.REMOVED
        ):
            raise ValueError("removed recovery plan requires recovered data bytes")
        if (
            self.recovered_data_bytes is not None
            and self.intent.planned_data_relative_path is None
        ):
            raise ValueError("recovery plan has unplanned recovered data")
        if (self.quarantine_bytes is None) != (
            self.intent.planned_quarantine_relative_path is None
        ):
            raise ValueError("recovery plan quarantine does not match its intent")
        if self.quarantine_bytes is not None and (
            self.intent.planned_quarantine_size_bytes != len(self.quarantine_bytes)
            or self.intent.planned_quarantine_sha256
            != hashlib.sha256(self.quarantine_bytes).hexdigest()
        ):
            raise ValueError("recovery plan quarantine bytes do not match intent")

    @property
    def manifest_bytes(self) -> bytes | None:
        return None if self.manifest is None else self.manifest.canonical_bytes()


def _recovery_manifest_from_facts(
    *,
    row_facts: RecoveryRowFacts,
    recovered_frame_count: int,
    source_size_bytes: int,
    source_sha256: str,
    source_relative_path: str,
    source_state: RecoverySourceState,
    transaction_id: str,
    created_at_ns: int,
    data_relative_path: str,
    data_size_bytes: int,
    data_sha256: str,
    quarantine_relative_path: str | None,
    quarantine_size_bytes: int | None,
    quarantine_sha256: str | None,
) -> RawManifestV1:
    return RawManifestV1(
        schema_version=1,
        exchange=row_facts.exchange,
        market=row_facts.market,
        instrument_key=row_facts.instrument_key,
        logical_stream=row_facts.logical_stream,
        wire_symbols=row_facts.wire_symbols,
        data_relative_path=data_relative_path,
        manifest_relative_path=manifest_path_for_data(data_relative_path).as_posix(),
        file_size_bytes=data_size_bytes,
        file_sha256=data_sha256,
        zstd_level=None,
        zstd_write_checksum=True,
        zstd_write_content_size=True,
        max_plain_frame_bytes=None,
        record_count=row_facts.record_count,
        first_received_at_ns=row_facts.first_received_at_ns,
        last_received_at_ns=row_facts.last_received_at_ns,
        first_event_time_ns=row_facts.first_event_time_ns,
        last_event_time_ns=row_facts.last_event_time_ns,
        worker_instance_id=row_facts.worker_instance_id,
        connection_generations=row_facts.connection_generations,
        writer_sequence_first=row_facts.writer_sequence_first,
        writer_sequence_last=row_facts.writer_sequence_last,
        config_sha256=row_facts.config_sha256,
        egress_ids=row_facts.egress_ids,
        requested_intervals_ns=row_facts.requested_intervals_ns,
        effective_intervals_ns=row_facts.effective_intervals_ns,
        gap_count=None,
        reconnect_count=None,
        parse_error_count=None,
        checksum_error_count=None,
        queue_overflow_count=None,
        control_event_ids=None,
        durability_measurement="unavailable_after_crash",
        durability_sample_count=None,
        durability_lag_p50_ns=None,
        durability_lag_p95_ns=None,
        durability_lag_p99_ns=None,
        durability_lag_max_ns=None,
        sync_count=None,
        sync_duration_total_ns=None,
        sync_duration_max_ns=None,
        slo_breach_count=None,
        write_failure_count=None,
        sync_failure_count=None,
        close_reason=CloseReason.RECOVERY,
        created_at_ns=None,
        closed_at_ns=created_at_ns,
        recovery_transaction_id=transaction_id,
        recovery_source_state=source_state,
        recovery_source_relative_path=source_relative_path,
        recovery_source_bytes=source_size_bytes,
        recovery_source_sha256=source_sha256,
        recovery_control_event_id=_RECOVERY_EVENT_PREFIX + transaction_id,
        recovered_frame_count=recovered_frame_count,
        recovered_record_count=row_facts.record_count,
        recovered_bytes=data_size_bytes,
        recovered_sha256=data_sha256,
        quarantined_suffix_relative_path=quarantine_relative_path,
        quarantined_suffix_bytes=quarantine_size_bytes,
        quarantined_suffix_sha256=quarantine_sha256,
        unavailable_fields=RECOVERY_UNAVAILABLE_FIELDS,
    )


def _recovery_manifest(
    *,
    scan: RecoveryFrameScan,
    source: bytes,
    source_relative_path: str,
    source_state: RecoverySourceState,
    transaction_id: str,
    created_at_ns: int,
    data_relative_path: str,
    data: bytes,
    quarantine_relative_path: str | None,
    quarantine: bytes | None,
) -> RawManifestV1:
    rows = tuple(envelope for frame in scan.frames for envelope in frame.envelopes)
    builder = _RecoveryRowFactsBuilder()
    builder.extend(rows)
    row_facts = builder.freeze()
    if row_facts is None:
        raise ValueError("recovery manifest requires validated rows")
    return _recovery_manifest_from_facts(
        row_facts=row_facts,
        recovered_frame_count=len(scan.frames),
        source_size_bytes=len(source),
        source_sha256=hashlib.sha256(source).hexdigest(),
        source_relative_path=source_relative_path,
        source_state=source_state,
        transaction_id=transaction_id,
        created_at_ns=created_at_ns,
        data_relative_path=data_relative_path,
        data_size_bytes=len(data),
        data_sha256=hashlib.sha256(data).hexdigest(),
        quarantine_relative_path=quarantine_relative_path,
        quarantine_size_bytes=None if quarantine is None else len(quarantine),
        quarantine_sha256=(
            None if quarantine is None else hashlib.sha256(quarantine).hexdigest()
        ),
    )


@dataclass(frozen=True, slots=True)
class RecoveryByteRange:
    start_offset: int
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        if type(self.start_offset) is not int or self.start_offset < 0:
            raise ValueError("recovery byte range start must be non-negative")
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("recovery byte range size must be non-negative")
        if (
            type(self.sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.sha256) is None
        ):
            raise ValueError("recovery byte range SHA-256 is invalid")


@dataclass(frozen=True, slots=True)
class StreamingRecoveryPlan:
    intent: RecoveryIntentV1
    manifest: RawManifestV1 | None
    recovered_range: RecoveryByteRange | None
    quarantine_range: RecoveryByteRange | None


def _plan_streaming_recovery_source(
    *,
    source_relative_path: str,
    scan: StreamingRecoveryScan,
    transaction_id: str,
    created_at_ns: int,
    next_part_sequence: int,
) -> StreamingRecoveryPlan:
    if type(scan) is not StreamingRecoveryScan:
        raise TypeError("scan must be StreamingRecoveryScan")
    is_partial = source_relative_path.endswith(".jsonl.zst.partial")
    if not is_partial and not source_relative_path.endswith(".jsonl.zst"):
        raise ValueError("recovery source must be partial or closed raw data")

    source_state: RecoverySourceState
    disposition: RecoverySourceDisposition
    data_relative_path: str | None = None
    manifest: RawManifestV1 | None = None
    recovered_range: RecoveryByteRange | None = None
    quarantine_range: RecoveryByteRange | None = None
    quarantine_relative_path: str | None = None
    if is_partial and scan.valid_prefix_size_bytes > 0:
        row_facts = scan.row_facts
        if row_facts is None:
            raise ValueError("valid recovery prefix requires row facts")
        data_relative_path = _next_recovery_relative_path(
            source_relative_path,
            next_part_sequence=next_part_sequence,
        )
        recovered_range = RecoveryByteRange(
            start_offset=0,
            size_bytes=scan.valid_prefix_size_bytes,
            sha256=scan.valid_prefix_sha256,
        )
        if scan.invalid_suffix_size_bytes:
            source_state = RecoverySourceState.PARTIAL_TRUNCATED
            quarantine_relative_path = bad_tail_quarantine_relative_path(
                source_relative_path
            )
            assert scan.invalid_suffix_sha256 is not None
            quarantine_range = RecoveryByteRange(
                start_offset=scan.valid_prefix_size_bytes,
                size_bytes=scan.invalid_suffix_size_bytes,
                sha256=scan.invalid_suffix_sha256,
            )
        else:
            source_state = RecoverySourceState.PARTIAL_COMPLETE
        disposition = RecoverySourceDisposition.REMOVED
        manifest = _recovery_manifest_from_facts(
            row_facts=row_facts,
            recovered_frame_count=scan.frame_count,
            source_size_bytes=scan.source_size_bytes,
            source_sha256=scan.source_sha256,
            source_relative_path=source_relative_path,
            source_state=source_state,
            transaction_id=transaction_id,
            created_at_ns=created_at_ns,
            data_relative_path=data_relative_path,
            data_size_bytes=recovered_range.size_bytes,
            data_sha256=recovered_range.sha256,
            quarantine_relative_path=quarantine_relative_path,
            quarantine_size_bytes=(
                None if quarantine_range is None else quarantine_range.size_bytes
            ),
            quarantine_sha256=(
                None if quarantine_range is None else quarantine_range.sha256
            ),
        )
    elif (
        not is_partial
        and scan.valid_prefix_size_bytes == scan.source_size_bytes
        and scan.valid_prefix_size_bytes > 0
    ):
        row_facts = scan.row_facts
        if row_facts is None:
            raise ValueError("valid closed recovery source requires row facts")
        source_state = RecoverySourceState.ORPHAN_CLOSED_DATA
        disposition = RecoverySourceDisposition.RETAINED
        data_relative_path = source_relative_path
        manifest = _recovery_manifest_from_facts(
            row_facts=row_facts,
            recovered_frame_count=scan.frame_count,
            source_size_bytes=scan.source_size_bytes,
            source_sha256=scan.source_sha256,
            source_relative_path=source_relative_path,
            source_state=source_state,
            transaction_id=transaction_id,
            created_at_ns=created_at_ns,
            data_relative_path=data_relative_path,
            data_size_bytes=scan.source_size_bytes,
            data_sha256=scan.source_sha256,
            quarantine_relative_path=None,
            quarantine_size_bytes=None,
            quarantine_sha256=None,
        )
    else:
        source_state = (
            RecoverySourceState.PARTIAL_TRUNCATED
            if is_partial
            else RecoverySourceState.ORPHAN_CLOSED_DATA
        )
        disposition = RecoverySourceDisposition.MOVED_TO_QUARANTINE
        quarantine_relative_path = whole_source_quarantine_relative_path(
            source_relative_path
        )
        quarantine_range = RecoveryByteRange(
            start_offset=0,
            size_bytes=scan.source_size_bytes,
            sha256=scan.source_sha256,
        )

    manifest_bytes = None if manifest is None else manifest.canonical_bytes()
    intent = RecoveryIntentV1.create(
        schema_version=1,
        fact_kind="intent",
        transaction_id=transaction_id,
        created_at_ns=created_at_ns,
        predecessor_sha256=None,
        source_state=source_state,
        source_relative_path=source_relative_path,
        source_size_bytes=scan.source_size_bytes,
        source_sha256=scan.source_sha256,
        planned_source_disposition=disposition,
        planned_data_generation_id=(
            None
            if data_relative_path is None
            else recovery_generation_id(data_relative_path)
        ),
        planned_data_relative_path=data_relative_path,
        planned_data_size_bytes=(
            None
            if data_relative_path is None
            else (
                scan.source_size_bytes
                if recovered_range is None
                else recovered_range.size_bytes
            )
        ),
        planned_data_sha256=(
            None
            if data_relative_path is None
            else scan.source_sha256
            if recovered_range is None
            else recovered_range.sha256
        ),
        planned_manifest_relative_path=(
            None if manifest is None else manifest.manifest_relative_path
        ),
        planned_manifest_size_bytes=(
            None if manifest_bytes is None else len(manifest_bytes)
        ),
        planned_manifest_sha256=(
            None
            if manifest_bytes is None
            else hashlib.sha256(manifest_bytes).hexdigest()
        ),
        planned_quarantine_relative_path=quarantine_relative_path,
        planned_quarantine_size_bytes=(
            None if quarantine_range is None else quarantine_range.size_bytes
        ),
        planned_quarantine_sha256=(
            None if quarantine_range is None else quarantine_range.sha256
        ),
        cleanup_proof_kind=None,
        cleanup_proof_relative_path=None,
        cleanup_proof_size_bytes=None,
        cleanup_proof_sha256=None,
        recovery_control_event_id=_RECOVERY_EVENT_PREFIX + transaction_id,
    )
    return StreamingRecoveryPlan(
        intent=intent,
        manifest=manifest,
        recovered_range=recovered_range,
        quarantine_range=quarantine_range,
    )


def _next_recovery_relative_path(
    source_relative_path: str,
    *,
    next_part_sequence: int,
) -> str:
    if type(next_part_sequence) is not int or next_part_sequence < 0:
        raise ValueError("next_part_sequence must be a non-negative integer")
    source = Path(source_relative_path)
    final_name = source.name.removesuffix(".partial")
    match = re.fullmatch(
        r"part-((?:0|[1-9][0-9]*))-(?:0|[1-9][0-9]*)\.jsonl\.zst",
        final_name,
    )
    if match is None:
        raise ValueError("partial source does not have a canonical part name")
    candidate = source.with_name(
        f"part-{match.group(1)}-{next_part_sequence}.jsonl.zst"
    ).as_posix()
    if candidate == source_relative_path.removesuffix(".partial"):
        raise ValueError("recovery sequence must allocate a distinct part path")
    return candidate


def plan_recovery_source(
    *,
    source_relative_path: str,
    source: bytes,
    transaction_id: str,
    created_at_ns: int,
    next_part_sequence: int,
) -> RecoveryPlan:
    if type(source) is not bytes:
        raise TypeError("recovery source must be bytes")
    if type(created_at_ns) is not int or created_at_ns < 0:
        raise ValueError("created_at_ns must be a non-negative integer")
    scan = scan_recovery_frames(source, source_relative_path)
    source_sha256 = hashlib.sha256(source).hexdigest()
    is_partial = source_relative_path.endswith(".jsonl.zst.partial")
    if not is_partial and not source_relative_path.endswith(".jsonl.zst"):
        raise ValueError("recovery source must be partial or closed raw data")

    recovered_data: bytes | None = None
    quarantine: bytes | None = None
    manifest: RawManifestV1 | None = None
    if is_partial and scan.frames:
        recovered_data = source[: scan.valid_prefix_size_bytes]
        suffix = source[scan.valid_prefix_size_bytes :]
        source_state = (
            RecoverySourceState.PARTIAL_COMPLETE
            if not suffix
            else RecoverySourceState.PARTIAL_TRUNCATED
        )
        disposition = RecoverySourceDisposition.REMOVED
        data_relative_path = _next_recovery_relative_path(
            source_relative_path,
            next_part_sequence=next_part_sequence,
        )
        quarantine = suffix or None
        quarantine_relative_path = (
            None
            if quarantine is None
            else bad_tail_quarantine_relative_path(source_relative_path)
        )
        manifest = _recovery_manifest(
            scan=scan,
            source=source,
            source_relative_path=source_relative_path,
            source_state=source_state,
            transaction_id=transaction_id,
            created_at_ns=created_at_ns,
            data_relative_path=data_relative_path,
            data=recovered_data,
            quarantine_relative_path=quarantine_relative_path,
            quarantine=quarantine,
        )
    elif not is_partial and scan.frames and scan.valid_prefix_size_bytes == len(source):
        source_state = RecoverySourceState.ORPHAN_CLOSED_DATA
        disposition = RecoverySourceDisposition.RETAINED
        data_relative_path = source_relative_path
        quarantine_relative_path = None
        manifest = _recovery_manifest(
            scan=scan,
            source=source,
            source_relative_path=source_relative_path,
            source_state=source_state,
            transaction_id=transaction_id,
            created_at_ns=created_at_ns,
            data_relative_path=data_relative_path,
            data=source,
            quarantine_relative_path=None,
            quarantine=None,
        )
    else:
        source_state = (
            RecoverySourceState.PARTIAL_TRUNCATED
            if is_partial
            else RecoverySourceState.ORPHAN_CLOSED_DATA
        )
        disposition = RecoverySourceDisposition.MOVED_TO_QUARANTINE
        data_relative_path = None
        quarantine_relative_path = whole_source_quarantine_relative_path(
            source_relative_path
        )
        quarantine = source

    manifest_bytes = None if manifest is None else manifest.canonical_bytes()
    intent = RecoveryIntentV1.create(
        schema_version=1,
        fact_kind="intent",
        transaction_id=transaction_id,
        created_at_ns=created_at_ns,
        predecessor_sha256=None,
        source_state=source_state,
        source_relative_path=source_relative_path,
        source_size_bytes=len(source),
        source_sha256=source_sha256,
        planned_source_disposition=disposition,
        planned_data_generation_id=(
            None
            if data_relative_path is None
            else recovery_generation_id(data_relative_path)
        ),
        planned_data_relative_path=data_relative_path,
        planned_data_size_bytes=(
            None
            if data_relative_path is None
            else (len(source) if recovered_data is None else len(recovered_data))
        ),
        planned_data_sha256=(
            None
            if data_relative_path is None
            else hashlib.sha256(
                source if recovered_data is None else recovered_data
            ).hexdigest()
        ),
        planned_manifest_relative_path=(
            None if manifest is None else manifest.manifest_relative_path
        ),
        planned_manifest_size_bytes=(
            None if manifest_bytes is None else len(manifest_bytes)
        ),
        planned_manifest_sha256=(
            None
            if manifest_bytes is None
            else hashlib.sha256(manifest_bytes).hexdigest()
        ),
        planned_quarantine_relative_path=quarantine_relative_path,
        planned_quarantine_size_bytes=(None if quarantine is None else len(quarantine)),
        planned_quarantine_sha256=(
            None if quarantine is None else hashlib.sha256(quarantine).hexdigest()
        ),
        cleanup_proof_kind=None,
        cleanup_proof_relative_path=None,
        cleanup_proof_size_bytes=None,
        cleanup_proof_sha256=None,
        recovery_control_event_id=_RECOVERY_EVENT_PREFIX + transaction_id,
    )
    return RecoveryPlan(
        intent=intent,
        manifest=manifest,
        recovered_data_bytes=recovered_data,
        quarantine_bytes=quarantine,
    )


def _group_presence(values: tuple[object | None, ...], *, field_name: str) -> bool:
    present = tuple(value is not None for value in values)
    if len(set(present)) != 1:
        raise ValueError(f"{field_name} fields must be all present or all null")
    return present[0]


class RecoverySourceDisposition(StrEnum):
    RETAINED = "retained"
    REMOVED = "removed"
    MOVED_TO_QUARANTINE = "moved_to_quarantine"
    LEGITIMATELY_MISSING = "legitimately_missing"


class _RecoveryFact(FrozenStrictModel):
    _filename: ClassVar[str]

    @classmethod
    def create(cls, **values: object) -> Self:
        if "fact_sha256" in values:
            raise ValueError("fact_sha256 is computed, not supplied")
        provisional = cls.model_validate(
            {**values, "fact_sha256": "0" * 64},
            context={"skip_fact_hash": True},
        )
        digest = hashlib.sha256(provisional.hash_payload_bytes()).hexdigest()
        return cls.model_validate(
            {
                **provisional.model_dump(
                    mode="python",
                    exclude={"fact_sha256"},
                ),
                "fact_sha256": digest,
            }
        )

    def hash_payload_bytes(self) -> bytes:
        return (
            encode_json(
                self.model_dump(
                    mode="python",
                    exclude={"fact_sha256"},
                )
            )
            + b"\n"
        )

    def canonical_fact_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="python")) + b"\n"

    @model_validator(mode="after")
    def _validate_fact_hash(self, info: ValidationInfo) -> Self:
        if info.context and info.context.get("skip_fact_hash") is True:
            return self
        expected = hashlib.sha256(self.hash_payload_bytes()).hexdigest()
        if getattr(self, "fact_sha256", None) != expected:
            raise ValueError("recovery fact SHA-256 is invalid")
        return self


class RecoveryIntentV1(_RecoveryFact):
    _filename = "intent.json"

    schema_version: SchemaVersion1 = 1
    fact_kind: Literal["intent"] = "intent"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: None = None
    source_state: RecoverySourceState
    source_relative_path: NormalizedDataRelativePath
    source_size_bytes: NonNegativeInt
    source_sha256: Sha256
    planned_source_disposition: RecoverySourceDisposition
    planned_data_generation_id: NonEmptyString | None
    planned_data_relative_path: NormalizedDataRelativePath | None
    planned_data_size_bytes: PositiveInt | None
    planned_data_sha256: Sha256 | None
    planned_manifest_relative_path: NormalizedDataRelativePath | None
    planned_manifest_size_bytes: PositiveInt | None
    planned_manifest_sha256: Sha256 | None
    planned_quarantine_relative_path: NormalizedDataRelativePath | None
    planned_quarantine_size_bytes: NonNegativeInt | None
    planned_quarantine_sha256: Sha256 | None
    cleanup_proof_kind: CleanupProofKind | None
    cleanup_proof_relative_path: NormalizedStateRelativePath | None
    cleanup_proof_size_bytes: PositiveInt | None
    cleanup_proof_sha256: Sha256 | None
    recovery_control_event_id: NonEmptyString
    fact_sha256: Sha256

    @model_validator(mode="after")
    def _validate_intent(self) -> Self:
        _parse_source_path(self.source_relative_path)
        source_is_partial = self.source_relative_path.endswith(".jsonl.zst.partial")
        partial_states = {
            RecoverySourceState.PARTIAL_COMPLETE,
            RecoverySourceState.PARTIAL_TRUNCATED,
            RecoverySourceState.PUBLICATION_COEXISTENCE,
        }
        if (self.source_state in partial_states) != source_is_partial:
            raise ValueError("recovery source state does not match its path")
        if (
            self.recovery_control_event_id
            != _RECOVERY_EVENT_PREFIX + self.transaction_id
        ):
            raise ValueError("recovery control event ID does not match transaction")
        data_present = _group_presence(
            (
                self.planned_data_generation_id,
                self.planned_data_relative_path,
                self.planned_data_size_bytes,
                self.planned_data_sha256,
            ),
            field_name="planned data",
        )
        manifest_present = _group_presence(
            (
                self.planned_manifest_relative_path,
                self.planned_manifest_size_bytes,
                self.planned_manifest_sha256,
            ),
            field_name="planned manifest",
        )
        quarantine_present = _group_presence(
            (
                self.planned_quarantine_relative_path,
                self.planned_quarantine_size_bytes,
                self.planned_quarantine_sha256,
            ),
            field_name="planned quarantine",
        )
        cleanup_present = _group_presence(
            (
                self.cleanup_proof_kind,
                self.cleanup_proof_relative_path,
                self.cleanup_proof_size_bytes,
                self.cleanup_proof_sha256,
            ),
            field_name="cleanup proof",
        )
        if data_present:
            assert self.planned_data_generation_id is not None
            assert self.planned_data_relative_path is not None
            if self.planned_data_generation_id != recovery_generation_id(
                self.planned_data_relative_path
            ):
                raise ValueError("planned generation does not match canonical path")
            if not manifest_present:
                raise ValueError("planned data requires a planned manifest")
            assert self.planned_manifest_relative_path is not None
            if (
                self.planned_manifest_relative_path
                != manifest_path_for_data(self.planned_data_relative_path).as_posix()
            ):
                raise ValueError("planned manifest is not the data sibling")

        disposition = self.planned_source_disposition
        if disposition is RecoverySourceDisposition.REMOVED:
            if self.source_state not in {
                RecoverySourceState.PARTIAL_COMPLETE,
                RecoverySourceState.PARTIAL_TRUNCATED,
                RecoverySourceState.PUBLICATION_COEXISTENCE,
            }:
                raise ValueError("removed disposition requires a partial source")
            if not self.source_relative_path.endswith(".jsonl.zst.partial"):
                raise ValueError("removed source must be a partial")
            if not data_present or cleanup_present:
                raise ValueError("removed source requires replacement artifacts only")
            if (
                self.planned_data_relative_path
                == self.source_relative_path.removesuffix(".partial")
                and self.source_state is not RecoverySourceState.PUBLICATION_COEXISTENCE
            ):
                raise ValueError("partial recovery must allocate a distinct generation")
            assert self.planned_data_relative_path is not None
            if (
                self.source_state is RecoverySourceState.PUBLICATION_COEXISTENCE
                and self.planned_data_relative_path
                != self.source_relative_path.removesuffix(".partial")
            ):
                raise ValueError(
                    "publication coexistence must preserve the final destination"
                )
            if (
                Path(self.planned_data_relative_path).parent
                != Path(self.source_relative_path).parent
            ):
                raise ValueError("partial recovery must remain in its source scope")
            if self.source_state is RecoverySourceState.PARTIAL_TRUNCATED:
                if not quarantine_present:
                    raise ValueError("truncated partial requires a bad-tail quarantine")
                assert self.planned_quarantine_relative_path is not None
                assert self.planned_quarantine_size_bytes is not None
                if (
                    self.planned_quarantine_relative_path
                    != (bad_tail_quarantine_relative_path(self.source_relative_path))
                    or self.planned_quarantine_size_bytes == 0
                ):
                    raise ValueError("truncated partial quarantine is invalid")
                assert self.planned_data_size_bytes is not None
                if (
                    self.planned_data_size_bytes + self.planned_quarantine_size_bytes
                    != self.source_size_bytes
                ):
                    raise ValueError(
                        "recovered prefix and bad tail must cover the source size"
                    )
            elif quarantine_present:
                raise ValueError("complete partial cannot have a bad tail")
            elif self.source_state in {
                RecoverySourceState.PARTIAL_COMPLETE,
                RecoverySourceState.PUBLICATION_COEXISTENCE,
            }:
                if (
                    self.planned_data_size_bytes != self.source_size_bytes
                    or self.planned_data_sha256 != self.source_sha256
                ):
                    raise ValueError(
                        "complete partial replacement must preserve the source"
                    )
        elif disposition is RecoverySourceDisposition.MOVED_TO_QUARANTINE:
            if (
                data_present
                or manifest_present
                or cleanup_present
                or not quarantine_present
            ):
                raise ValueError("whole quarantine cannot publish recovered artifacts")
            if self.source_state not in {
                RecoverySourceState.PARTIAL_TRUNCATED,
                RecoverySourceState.ORPHAN_CLOSED_DATA,
            }:
                raise ValueError("source state cannot be wholly quarantined")
            assert self.planned_quarantine_relative_path is not None
            assert self.planned_quarantine_size_bytes is not None
            assert self.planned_quarantine_sha256 is not None
            if (
                self.planned_quarantine_relative_path
                != whole_source_quarantine_relative_path(self.source_relative_path)
                or self.planned_quarantine_size_bytes != self.source_size_bytes
                or self.planned_quarantine_sha256 != self.source_sha256
            ):
                raise ValueError("whole quarantine must preserve the complete source")
        elif disposition is RecoverySourceDisposition.RETAINED:
            if (
                self.source_state is not RecoverySourceState.ORPHAN_CLOSED_DATA
                or not data_present
                or quarantine_present
                or cleanup_present
            ):
                raise ValueError("retained disposition requires a valid closed orphan")
            if (
                self.planned_data_relative_path != self.source_relative_path
                or self.planned_data_size_bytes != self.source_size_bytes
                or self.planned_data_sha256 != self.source_sha256
            ):
                raise ValueError("retained orphan must preserve the source identity")
        else:
            expected_kind = {
                RecoverySourceState.CLEANUP_INTENT: CleanupProofKind.DURABLE_INTENT,
                RecoverySourceState.CLEANUP_TOMBSTONE: CleanupProofKind.FINAL_TOMBSTONE,
            }.get(self.source_state)
            if (
                expected_kind is None
                or self.source_size_bytes == 0
                or data_present
                or quarantine_present
                or not manifest_present
                or not cleanup_present
                or self.cleanup_proof_kind is not expected_kind
            ):
                raise ValueError(
                    "legitimately missing source requires exact cleanup proof"
                )
            if not self.source_relative_path.endswith(".jsonl.zst"):
                raise ValueError("cleanup source must name final raw data")
            assert self.planned_manifest_relative_path is not None
            if (
                self.planned_manifest_relative_path
                != manifest_path_for_data(self.source_relative_path).as_posix()
            ):
                raise ValueError("cleanup manifest must be the source sibling")
        return self


class RecoveryArtifactsDurableV1(_RecoveryFact):
    _filename = "artifacts-durable.json"

    schema_version: SchemaVersion1 = 1
    fact_kind: Literal["artifacts_durable"] = "artifacts_durable"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    data_generation_id: NonEmptyString | None
    data_relative_path: NormalizedDataRelativePath | None
    data_size_bytes: PositiveInt | None
    data_sha256: Sha256 | None
    manifest_relative_path: NormalizedDataRelativePath | None
    manifest_size_bytes: PositiveInt | None
    manifest_sha256: Sha256 | None
    quarantine_relative_path: NormalizedDataRelativePath | None
    quarantine_size_bytes: NonNegativeInt | None
    quarantine_sha256: Sha256 | None
    fact_sha256: Sha256

    @model_validator(mode="after")
    def _validate_artifact_groups(self) -> Self:
        data = _group_presence(
            (
                self.data_generation_id,
                self.data_relative_path,
                self.data_size_bytes,
                self.data_sha256,
            ),
            field_name="durable data",
        )
        manifest = _group_presence(
            (
                self.manifest_relative_path,
                self.manifest_size_bytes,
                self.manifest_sha256,
            ),
            field_name="durable manifest",
        )
        _group_presence(
            (
                self.quarantine_relative_path,
                self.quarantine_size_bytes,
                self.quarantine_sha256,
            ),
            field_name="durable quarantine",
        )
        if data:
            assert self.data_relative_path is not None
            assert self.data_generation_id is not None
            if self.data_generation_id != recovery_generation_id(
                self.data_relative_path
            ):
                raise ValueError("durable generation does not match canonical path")
            if not manifest:
                raise ValueError("durable data requires a manifest")
        return self


class RecoverySourceSettledV1(_RecoveryFact):
    _filename = "source-settled.json"

    schema_version: SchemaVersion1 = 1
    fact_kind: Literal["source_settled"] = "source_settled"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    source_relative_path: NormalizedDataRelativePath
    source_disposition: RecoverySourceDisposition
    settled_relative_path: NormalizedDataRelativePath | None
    settled_size_bytes: NonNegativeInt | None
    settled_sha256: Sha256 | None
    fact_sha256: Sha256

    @model_validator(mode="after")
    def _validate_settlement(self) -> Self:
        settled = _group_presence(
            (
                self.settled_relative_path,
                self.settled_size_bytes,
                self.settled_sha256,
            ),
            field_name="settled source",
        )
        needs_settled = self.source_disposition in {
            RecoverySourceDisposition.RETAINED,
            RecoverySourceDisposition.MOVED_TO_QUARANTINE,
        }
        if settled != needs_settled:
            raise ValueError("settlement fields do not match source disposition")
        return self


class RecoveryControlOwnershipV1(_RecoveryFact):
    _filename = "control-ownership.json"

    schema_version: SchemaVersion1 = 1
    fact_kind: Literal["control_ownership"] = "control_ownership"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    recovery_control_event_id: NonEmptyString
    control_record_identity: AcceptedRecordIdentityV1
    control_envelope: RawEnvelope
    control_encoded_sha256: Sha256
    control_frame_base64: NonEmptyString
    control_frame_size_bytes: PositiveInt
    control_frame_sha256: Sha256
    control_recovery_manifest_base64: NonEmptyString
    control_recovery_manifest_size_bytes: PositiveInt
    control_recovery_manifest_sha256: Sha256
    control_generation_id: NonEmptyString
    control_data_relative_path: NormalizedDataRelativePath
    control_manifest_relative_path: NormalizedDataRelativePath
    control_association: StorageControlAssociationV1 | None
    zstd_level: Annotated[int, Field(ge=1, le=22)]
    max_plain_frame_bytes: PositiveInt
    fact_sha256: Sha256

    @model_validator(mode="after")
    def _validate_ownership_identity(self) -> Self:
        if (
            self.recovery_control_event_id
            != _RECOVERY_EVENT_PREFIX + self.transaction_id
        ):
            raise ValueError("ownership event ID does not match transaction")
        envelope = self.control_envelope
        identity = self.control_record_identity
        if (
            envelope.logical_stream != "_control"
            or envelope.transport is not Transport.INTERNAL
            or envelope.market is not None
            or envelope.instrument_key is not None
            or envelope.wire_symbol is not None
            or envelope.native_channel is not None
            or envelope.event_time_ns is not None
            or envelope.event_time_source is not None
            or envelope.integrity_mode is not None
            or envelope.coverage is not None
            or envelope.rest_metadata is not None
            or envelope.connection_id is not None
            or envelope.connection_generation is not None
            or envelope.egress_id is not None
        ):
            raise ValueError(
                "owned control envelope must use internal null source context"
            )
        if identity.logical_stream != "_control" or (
            identity.exchange,
            identity.market,
            identity.instrument_key,
            identity.worker_instance_id,
            identity.writer_sequence,
            identity.config_sha256,
        ) != (
            envelope.exchange,
            envelope.market,
            envelope.instrument_key,
            envelope.worker_instance_id,
            envelope.writer_sequence,
            envelope.config_sha256,
        ):
            raise ValueError("ownership identity does not match control envelope")
        if (
            self.control_manifest_relative_path
            != manifest_path_for_data(self.control_data_relative_path).as_posix()
        ):
            raise ValueError("owned control manifest is not the data sibling")
        encoded_envelope = encode_envelope(envelope)
        if hashlib.sha256(encoded_envelope).hexdigest() != self.control_encoded_sha256:
            raise ValueError("owned control encoded hash is invalid")
        try:
            frame = base64.b64decode(self.control_frame_base64, validate=True)
            manifest_bytes = base64.b64decode(
                self.control_recovery_manifest_base64,
                validate=True,
            )
        except (binascii.Error, ValueError) as error:
            raise ValueError("owned control base64 is invalid") from error
        if (
            base64.b64encode(frame).decode("ascii") != self.control_frame_base64
            or base64.b64encode(manifest_bytes).decode("ascii")
            != self.control_recovery_manifest_base64
        ):
            raise ValueError("owned control base64 is not canonical")
        if (
            len(frame) != self.control_frame_size_bytes
            or hashlib.sha256(frame).hexdigest() != self.control_frame_sha256
        ):
            raise ValueError("owned control frame facts are invalid")
        source_relative_path = self.control_data_relative_path + ".partial"
        scan = scan_recovery_frames(frame, source_relative_path)
        if (
            scan.valid_prefix_size_bytes != len(frame)
            or len(scan.frames) != 1
            or scan.frames[0].envelopes != (envelope,)
        ):
            raise ValueError("owned control frame is not the exact envelope")
        expected_manifest = _recovery_manifest(
            scan=scan,
            source=frame,
            source_relative_path=source_relative_path,
            source_state=RecoverySourceState.OWNED_CONTROL_CARRIER,
            transaction_id=self.transaction_id,
            created_at_ns=self.created_at_ns,
            data_relative_path=self.control_data_relative_path,
            data=frame,
            quarantine_relative_path=None,
            quarantine=None,
        ).canonical_bytes()
        if (
            manifest_bytes != expected_manifest
            or len(manifest_bytes) != self.control_recovery_manifest_size_bytes
            or hashlib.sha256(manifest_bytes).hexdigest()
            != self.control_recovery_manifest_sha256
        ):
            raise ValueError("owned control recovery manifest facts are invalid")
        return self


class RecoveryControlDurableV1(_RecoveryFact):
    _filename = "control-durable.json"

    schema_version: SchemaVersion1 = 1
    fact_kind: Literal["control_durable"] = "control_durable"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    recovery_control_event_id: NonEmptyString
    control_record_identity: AcceptedRecordIdentityV1
    control_generation_id: NonEmptyString
    control_data_relative_path: NormalizedDataRelativePath
    control_encoded_sha256: Sha256
    durable_at_monotonic_ns: NonNegativeInt
    fact_sha256: Sha256


class RecoveryCompleteV1(_RecoveryFact):
    _filename = "complete.json"

    schema_version: SchemaVersion1 = 1
    fact_kind: Literal["complete"] = "complete"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    recovery_control_event_id: NonEmptyString
    source_state: RecoverySourceState
    source_disposition: RecoverySourceDisposition
    outcome_sha256: Sha256
    fact_sha256: Sha256


class RecoveryControlPayloadV1(FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    kind: Literal["recovery_reconciled"] = "recovery_reconciled"
    recovery_control_event_id: NonEmptyString
    transaction_id: CanonicalUuid
    source_state: RecoverySourceState
    source_disposition: RecoverySourceDisposition
    source_market: Market | None
    source_instrument_key: NonEmptyString | None
    source_logical_stream: NonEmptyString
    source_relative_path: NormalizedDataRelativePath
    source_sha256: Sha256
    recovered_generation_id: NonEmptyString | None
    recovered_relative_path: NormalizedDataRelativePath | None
    recovered_sha256: Sha256 | None
    quarantined_relative_path: NormalizedDataRelativePath | None
    quarantined_sha256: Sha256 | None
    informational_only: bool
    affected_markets: tuple[Market, ...]

    @model_validator(mode="after")
    def _validate_payload(self) -> Self:
        recovered = _group_presence(
            (
                self.recovered_generation_id,
                self.recovered_relative_path,
                self.recovered_sha256,
            ),
            field_name="recovered payload",
        )
        quarantined = _group_presence(
            (self.quarantined_relative_path, self.quarantined_sha256),
            field_name="quarantine payload",
        )
        if (
            self.recovery_control_event_id
            != _RECOVERY_EVENT_PREFIX + self.transaction_id
        ):
            raise ValueError("payload event ID does not match transaction")
        if recovered:
            assert self.recovered_relative_path is not None
            assert self.recovered_generation_id is not None
            if self.recovered_generation_id != recovery_generation_id(
                self.recovered_relative_path
            ):
                raise ValueError("payload generation does not match recovered path")
        expected_informational = (
            self.source_disposition is RecoverySourceDisposition.LEGITIMATELY_MISSING
        )
        if self.informational_only is not expected_informational:
            raise ValueError("informational_only does not match source disposition")
        if self.source_logical_stream == "_control":
            if (
                self.source_market is not None
                or self.source_instrument_key is not None
                or self.affected_markets
            ):
                raise ValueError("control source context must be exchange scoped")
        else:
            if self.source_market is None or self.affected_markets != (
                self.source_market,
            ):
                raise ValueError("affected markets must exactly match source market")
            needs_instrument = self.source_logical_stream not in MARKET_SCOPED_STREAMS
            if needs_instrument != (self.source_instrument_key is not None):
                raise ValueError("source instrument does not match stream scope")
        disposition = self.source_disposition
        if disposition is RecoverySourceDisposition.REMOVED:
            if not recovered:
                raise ValueError("removed source requires recovered payload")
            if quarantined and self.quarantined_relative_path != (
                bad_tail_quarantine_relative_path(self.source_relative_path)
            ):
                raise ValueError("removed source quarantine must be its bad tail")
        elif disposition is RecoverySourceDisposition.RETAINED:
            if (
                not recovered
                or quarantined
                or self.recovered_relative_path != self.source_relative_path
            ):
                raise ValueError("retained payload must preserve source identity")
        elif disposition is RecoverySourceDisposition.MOVED_TO_QUARANTINE:
            if (
                recovered
                or not quarantined
                or self.quarantined_relative_path
                != (whole_source_quarantine_relative_path(self.source_relative_path))
            ):
                raise ValueError("whole-quarantine payload is invalid")
        elif recovered or quarantined:
            raise ValueError("informational cleanup payload cannot name artifacts")
        return self


RecoveryFact = (
    RecoveryIntentV1
    | RecoveryArtifactsDurableV1
    | RecoverySourceSettledV1
    | RecoveryControlOwnershipV1
    | RecoveryControlDurableV1
    | RecoveryCompleteV1
)
_FactT = TypeVar("_FactT", bound=_RecoveryFact)
_FACT_TYPES: tuple[type[_RecoveryFact], ...] = (
    RecoveryIntentV1,
    RecoveryArtifactsDurableV1,
    RecoverySourceSettledV1,
    RecoveryControlOwnershipV1,
    RecoveryControlDurableV1,
    RecoveryCompleteV1,
)
_FACT_TYPE_BY_FILENAME = {fact_type._filename: fact_type for fact_type in _FACT_TYPES}


def _convert_enum(
    container: dict[str, Any],
    field: str,
    enum_type: type[StrEnum],
) -> None:
    if container.get(field) is not None:
        container[field] = enum_type(container[field])


def _convert_fact_enums(wire: dict[str, Any]) -> None:
    _convert_enum(wire, "source_state", RecoverySourceState)
    _convert_enum(
        wire,
        "planned_source_disposition",
        RecoverySourceDisposition,
    )
    _convert_enum(wire, "source_disposition", RecoverySourceDisposition)
    _convert_enum(wire, "cleanup_proof_kind", CleanupProofKind)
    identity = wire.get("control_record_identity")
    if type(identity) is dict:
        _convert_enum(identity, "exchange", Exchange)
        _convert_enum(identity, "market", Market)
    envelope = wire.get("control_envelope")
    if type(envelope) is dict:
        from crypto_collector.domain.types import (
            CoverageMode,
            IntegrityMode,
            Transport,
        )

        _convert_enum(envelope, "exchange", Exchange)
        _convert_enum(envelope, "market", Market)
        _convert_enum(envelope, "transport", Transport)
        _convert_enum(envelope, "integrity_mode", IntegrityMode)
        _convert_enum(envelope, "coverage", CoverageMode)
    association = wire.get("control_association")
    if type(association) is dict and type(association.get("targets")) is list:
        association["targets"] = tuple(association["targets"])


def _read_regular_bytes(path: Path) -> bytes:
    fd, _ = _open_regular_no_follow(path)
    try:
        chunks: list[bytes] = []
        while True:
            try:
                chunk = os.read(fd, 1024 * 1024)
            except InterruptedError:
                continue
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def load_recovery_fact(path: Path, fact_type: type[_FactT]) -> _FactT:
    if not isinstance(path, Path):
        raise TypeError("recovery fact path must be Path")
    if fact_type not in _FACT_TYPES:
        raise TypeError("fact_type must be a recovery fact model")
    if path.name != fact_type._filename:
        raise RecoveryBlocked("recovery fact filename does not match its kind")
    try:
        source = _read_regular_bytes(path)
        wire = decode_json(source)
        if type(wire) is not dict:
            raise ValueError("recovery fact must be a JSON object")
        _convert_fact_enums(wire)
        fact = fact_type.model_validate(wire)
        if source != fact.canonical_fact_bytes():
            raise ValueError("recovery fact bytes are not canonical")
        return fact
    except RecoveryBlocked:
        raise
    except (OSError, TypeError, ValueError, ValidationError) as error:
        raise RecoveryBlocked("recovery fact is invalid or noncanonical") from error


def _validate_recovery_chain_bindings(chain: tuple[RecoveryFact, ...]) -> None:
    intent = cast(RecoveryIntentV1, chain[0])
    if len(chain) >= 2:
        artifacts = cast(RecoveryArtifactsDurableV1, chain[1])
        expected_artifacts = (
            intent.planned_data_generation_id,
            intent.planned_data_relative_path,
            intent.planned_data_size_bytes,
            intent.planned_data_sha256,
            intent.planned_manifest_relative_path,
            intent.planned_manifest_size_bytes,
            intent.planned_manifest_sha256,
            intent.planned_quarantine_relative_path,
            intent.planned_quarantine_size_bytes,
            intent.planned_quarantine_sha256,
        )
        observed_artifacts = (
            artifacts.data_generation_id,
            artifacts.data_relative_path,
            artifacts.data_size_bytes,
            artifacts.data_sha256,
            artifacts.manifest_relative_path,
            artifacts.manifest_size_bytes,
            artifacts.manifest_sha256,
            artifacts.quarantine_relative_path,
            artifacts.quarantine_size_bytes,
            artifacts.quarantine_sha256,
        )
        if observed_artifacts != expected_artifacts:
            raise RecoveryBlocked("durable artifacts disagree with recovery intent")
    if len(chain) >= 3:
        settled = cast(RecoverySourceSettledV1, chain[2])
        if (
            settled.source_relative_path != intent.source_relative_path
            or settled.source_disposition is not intent.planned_source_disposition
        ):
            raise RecoveryBlocked("source settlement disagrees with recovery intent")
        expected_settled: tuple[str | None, int | None, str | None]
        if settled.source_disposition is RecoverySourceDisposition.RETAINED:
            expected_settled = (
                intent.source_relative_path,
                intent.source_size_bytes,
                intent.source_sha256,
            )
        elif (
            settled.source_disposition is RecoverySourceDisposition.MOVED_TO_QUARANTINE
        ):
            expected_settled = (
                intent.planned_quarantine_relative_path,
                intent.planned_quarantine_size_bytes,
                intent.planned_quarantine_sha256,
            )
        else:
            expected_settled = (None, None, None)
        if (
            settled.settled_relative_path,
            settled.settled_size_bytes,
            settled.settled_sha256,
        ) != expected_settled:
            raise RecoveryBlocked("source settlement facts disagree with intent")
    if len(chain) >= 4:
        ownership = cast(RecoveryControlOwnershipV1, chain[3])
        identity = ownership.control_record_identity
        if ownership.recovery_control_event_id != intent.recovery_control_event_id:
            raise RecoveryBlocked("control ownership event disagrees with intent")
        expected_association: StorageControlAssociationV1 | None = None
        if intent.planned_data_generation_id is not None:
            assert intent.planned_data_relative_path is not None
            expected_association = StorageControlAssociationV1(
                schema_version=1,
                control_kind="recovery_reconciled",
                control_event_id=intent.recovery_control_event_id,
                targets=(
                    StorageControlTargetV1(
                        generation_id=intent.planned_data_generation_id,
                        data_relative_path=intent.planned_data_relative_path,
                    ),
                ),
                acceptance_ordinal=identity.acceptance_ordinal,
                config_generation=identity.config_generation,
            )
        if ownership.control_association != expected_association:
            raise RecoveryBlocked("control ownership association disagrees with intent")
        expected_payload = _control_payload_from_intent(intent).model_dump(mode="json")
        if ownership.control_envelope.payload != expected_payload:
            raise RecoveryBlocked("control ownership payload disagrees with intent")
    if len(chain) >= 5:
        ownership = cast(RecoveryControlOwnershipV1, chain[3])
        durable = cast(RecoveryControlDurableV1, chain[4])
        if (
            durable.recovery_control_event_id,
            durable.control_record_identity,
            durable.control_generation_id,
            durable.control_data_relative_path,
            durable.control_encoded_sha256,
        ) != (
            ownership.recovery_control_event_id,
            ownership.control_record_identity,
            ownership.control_generation_id,
            ownership.control_data_relative_path,
            ownership.control_encoded_sha256,
        ):
            raise RecoveryBlocked("durable control disagrees with ownership")
    if len(chain) >= 6:
        complete = cast(RecoveryCompleteV1, chain[5])
        outcome = _outcome_from_intent(intent)
        if (
            complete.recovery_control_event_id != intent.recovery_control_event_id
            or complete.source_state is not intent.source_state
            or complete.source_disposition is not intent.planned_source_disposition
            or complete.outcome_sha256 != _outcome_sha256(outcome)
        ):
            raise RecoveryBlocked("completion fact disagrees with recovery outcome")


def load_recovery_chain(transaction_root: Path) -> tuple[RecoveryFact, ...]:
    if not isinstance(transaction_root, Path):
        raise TypeError("transaction_root must be Path")
    try:
        directory_fd, _sentinel, _absolute = _open_parent_no_follow(
            transaction_root / ".chain-sentinel"
        )
        try:
            names = set(os.listdir(directory_fd))
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise RecoveryBlocked("recovery transaction directory is invalid") from error

    known = set(_FACT_TYPE_BY_FILENAME)
    unknown = names - known
    if unknown:
        raise RecoveryBlocked("recovery transaction has unknown entries")
    loaded: list[RecoveryFact] = []
    missing_seen = False
    previous_sha256: str | None = None
    transaction_id: str | None = None
    for fact_type in _FACT_TYPES:
        filename = fact_type._filename
        if filename not in names:
            missing_seen = True
            continue
        if missing_seen:
            raise RecoveryBlocked("recovery fact has a missing predecessor")
        fact = cast(
            RecoveryFact,
            load_recovery_fact(transaction_root / filename, fact_type),
        )
        if transaction_id is None:
            transaction_id = fact.transaction_id
            if transaction_root.name != transaction_id:
                raise RecoveryBlocked(
                    "transaction directory name does not match intent"
                )
        elif fact.transaction_id != transaction_id:
            raise RecoveryBlocked("recovery chain transaction IDs disagree")
        if fact.predecessor_sha256 != previous_sha256:
            raise RecoveryBlocked("recovery fact predecessor hash is invalid")
        previous_sha256 = fact.fact_sha256
        loaded.append(fact)
    if not loaded or type(loaded[0]) is not RecoveryIntentV1:
        raise RecoveryBlocked("recovery transaction has no valid intent")
    chain = tuple(loaded)
    _validate_recovery_chain_bindings(chain)
    return chain


def _recovery_directory_flags() -> int:
    flags = os.O_RDONLY
    for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        value = getattr(os, name, None)
        if type(value) is not int or value == 0:
            raise OSError(f"required open flag {name} is unavailable")
        flags |= value
    return flags


def _open_directory_path(path: Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.anchor or any(
        part in {"", ".", ".."} for part in absolute.parts[1:]
    ):
        raise ValueError("recovery directory path must be normalized and absolute")
    current_fd = os.open(absolute.anchor, _recovery_directory_flags())
    try:
        for segment in absolute.parts[1:]:
            next_fd = os.open(segment, _recovery_directory_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _create_child_directories(root: Path, segments: tuple[str, ...]) -> None:
    current_fd = _open_directory_path(root)
    try:
        for segment in segments:
            if not segment or segment in {".", ".."} or "/" in segment:
                raise ValueError("recovery directory segment is invalid")
            try:
                next_fd = os.open(
                    segment,
                    _recovery_directory_flags(),
                    dir_fd=current_fd,
                )
            except FileNotFoundError:
                os.mkdir(segment, 0o750, dir_fd=current_fd)
                os.fsync(current_fd)
                next_fd = os.open(
                    segment,
                    _recovery_directory_flags(),
                    dir_fd=current_fd,
                )
            else:
                os.fsync(current_fd)
            os.close(current_fd)
            current_fd = next_fd
    finally:
        os.close(current_fd)


class _RecoveryJournal:
    """Crash-safe publisher for one exchange's immutable recovery facts."""

    def __init__(self, *, state_root: Path, exchange: Exchange) -> None:
        if not isinstance(state_root, Path):
            raise TypeError("state_root must be Path")
        if type(exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        self._state_root = Path(os.path.abspath(os.fspath(state_root)))
        self._exchange = exchange

    @staticmethod
    def _transaction_id(value: str) -> str:
        if type(value) is not str or _CANONICAL_UUID.fullmatch(value) is None:
            raise ValueError("transaction_id must be a canonical UUID")
        return value

    @property
    def exchange_root(self) -> Path:
        return self._state_root / "raw-recovery" / self._exchange.value

    def transaction_root(self, transaction_id: str) -> Path:
        return self.exchange_root / self._transaction_id(transaction_id)

    def ensure_exchange(self) -> Path:
        try:
            _create_child_directories(
                self._state_root,
                ("raw-recovery", self._exchange.value),
            )
        except (OSError, TypeError, ValueError) as error:
            raise RecoveryBlocked("recovery journal directory is unsafe") from error
        return self.exchange_root

    def ensure_transaction(self, transaction_id: str) -> Path:
        normalized = self._transaction_id(transaction_id)
        try:
            _create_child_directories(
                self._state_root,
                ("raw-recovery", self._exchange.value, normalized),
            )
        except (OSError, TypeError, ValueError) as error:
            raise RecoveryBlocked("recovery journal directory is unsafe") from error
        return self.transaction_root(normalized)

    def transaction_ids(self) -> tuple[str, ...]:
        exchange_root = self.ensure_exchange()
        try:
            directory_fd = _open_directory_path(exchange_root)
            try:
                names = tuple(sorted(os.listdir(directory_fd)))
                if any(_CANONICAL_UUID.fullmatch(name) is None for name in names):
                    raise RecoveryBlocked(
                        "recovery exchange journal has an unknown entry"
                    )
                retained: list[str] = []
                for transaction_id in names:
                    transaction_root = self.transaction_root(transaction_id)
                    entries = self._prepare_transaction(transaction_root)
                    if entries:
                        retained.append(transaction_id)
                        continue
                    os.rmdir(transaction_id, dir_fd=directory_fd)
                    os.fsync(directory_fd)
                return tuple(retained)
            finally:
                os.close(directory_fd)
        except RecoveryBlocked:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise RecoveryBlocked("recovery exchange journal is invalid") from error

    @staticmethod
    def _temporary_name(fact_type: type[_RecoveryFact], transaction_id: str) -> str:
        return f".{fact_type._filename}.tmp-{transaction_id}"

    def _prepare_transaction(self, transaction_root: Path) -> set[str]:
        try:
            directory_fd = _open_directory_path(transaction_root)
            try:
                names = set(os.listdir(directory_fd))
                known_finals = set(_FACT_TYPE_BY_FILENAME)
                known_temps = {
                    self._temporary_name(fact_type, transaction_root.name): fact_type
                    for fact_type in _FACT_TYPES
                }
                unknown = names - known_finals - set(known_temps)
                if unknown:
                    raise RecoveryBlocked("recovery transaction has unknown entries")
                for temporary_name, fact_type in known_temps.items():
                    if temporary_name not in names:
                        continue
                    try:
                        temporary_fd = os.open(
                            temporary_name,
                            os.O_RDONLY
                            | os.O_NOFOLLOW
                            | os.O_CLOEXEC
                            | getattr(os, "O_NONBLOCK", 0),
                            dir_fd=directory_fd,
                        )
                    except OSError as error:
                        raise RecoveryBlocked(
                            "recovery fact temporary is unsafe"
                        ) from error
                    try:
                        temporary_stat = os.fstat(temporary_fd)
                        if not stat.S_ISREG(temporary_stat.st_mode):
                            raise RecoveryBlocked(
                                "recovery fact temporary is not regular"
                            )
                        if fact_type._filename in names:
                            final_fd = os.open(
                                fact_type._filename,
                                os.O_RDONLY
                                | os.O_NOFOLLOW
                                | os.O_CLOEXEC
                                | getattr(os, "O_NONBLOCK", 0),
                                dir_fd=directory_fd,
                            )
                            try:
                                final_stat = os.fstat(final_fd)
                                if (
                                    temporary_stat.st_dev,
                                    temporary_stat.st_ino,
                                ) != (final_stat.st_dev, final_stat.st_ino):
                                    raise RecoveryBlocked(
                                        "recovery fact temporary conflicts with final"
                                    )
                            finally:
                                os.close(final_fd)
                        os.unlink(temporary_name, dir_fd=directory_fd)
                        os.fsync(directory_fd)
                        names.remove(temporary_name)
                    finally:
                        os.close(temporary_fd)
                return names
            finally:
                os.close(directory_fd)
        except RecoveryBlocked:
            raise
        except (OSError, TypeError, ValueError) as error:
            raise RecoveryBlocked(
                "recovery transaction directory is invalid"
            ) from error

    def load_chain(self, transaction_id: str) -> tuple[RecoveryFact, ...]:
        transaction_root = self.transaction_root(transaction_id)
        self._prepare_transaction(transaction_root)
        chain = load_recovery_chain(transaction_root)
        source_identity = _parse_source_path(
            cast(RecoveryIntentV1, chain[0]).source_relative_path
        )
        if source_identity.exchange is not self._exchange:
            raise RecoveryBlocked("recovery intent is in the wrong exchange journal")
        fsync_directory(transaction_root)
        return chain

    def publish(self, fact: RecoveryFact) -> RecoveryFact:
        if not isinstance(fact, _FACT_TYPES):
            raise TypeError("fact must be a recovery fact")
        if type(fact) is RecoveryIntentV1 and (
            _parse_source_path(fact.source_relative_path).exchange is not self._exchange
        ):
            raise RecoveryBlocked("recovery intent exchange conflicts with journal")
        transaction_root = self.ensure_transaction(fact.transaction_id)
        names = self._prepare_transaction(transaction_root)
        final_names = names & set(_FACT_TYPE_BY_FILENAME)
        chain: tuple[RecoveryFact, ...]
        if final_names:
            chain = load_recovery_chain(transaction_root)
        else:
            chain = ()
        fact_index = _FACT_TYPES.index(type(fact))
        if fact_index < len(chain):
            existing = chain[fact_index]
            if existing != fact:
                raise RecoveryBlocked("recovery fact conflicts with durable fact")
            fsync_directory(transaction_root)
            return existing
        if fact_index != len(chain):
            raise RecoveryBlocked("recovery fact does not extend the durable chain")
        if fact_index > 0 and fact.predecessor_sha256 != chain[-1].fact_sha256:
            raise RecoveryBlocked("recovery fact predecessor conflicts with chain")
        _validate_recovery_chain_bindings((*chain, fact))

        fact_type = type(fact)
        temporary = transaction_root / self._temporary_name(
            fact_type,
            fact.transaction_id,
        )
        final = transaction_root / fact_type._filename
        try:
            atomic_write_and_sync_json_exclusive(
                temporary,
                fact.canonical_fact_bytes(),
            )
            publish_no_replace(temporary, final)
            observed = load_recovery_fact(final, fact_type)
            if observed != fact:
                raise RecoveryBlocked("published recovery fact does not match intent")
            fsync_directory(transaction_root)
        except RecoveryBlocked:
            raise
        except (OSError, PublicationConflict, TypeError, ValueError) as error:
            raise RecoveryBlocked("recovery fact publication conflict") from error
        return fact


def _strict_nonempty(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be str")
    if not value:
        raise ValueError(f"{field_name} must be nonempty")
    return value


def _strict_sha256(value: object, *, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be 64 lowercase hexadecimal characters")
    return value


def _strict_integer(
    value: object,
    *,
    field_name: str,
    minimum: int,
) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be int")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field_name} must be {qualifier}")
    return value


def _validate_transaction_event(
    transaction_id: object,
    recovery_control_event_id: object,
) -> None:
    if (
        type(transaction_id) is not str
        or _CANONICAL_UUID.fullmatch(transaction_id) is None
    ):
        raise ValueError("transaction_id must be a canonical UUID")
    event_id = _strict_nonempty(
        recovery_control_event_id,
        field_name="recovery_control_event_id",
    )
    if event_id != _RECOVERY_EVENT_PREFIX + transaction_id:
        raise ValueError("recovery control event ID does not match transaction")


def _validate_source_outcome_state(
    source_state: RecoverySourceState,
    source_disposition: RecoverySourceDisposition,
    source_relative_path: str,
) -> None:
    partial_states = {
        RecoverySourceState.PARTIAL_COMPLETE,
        RecoverySourceState.PARTIAL_TRUNCATED,
        RecoverySourceState.PUBLICATION_COEXISTENCE,
    }
    is_partial = source_relative_path.endswith(".jsonl.zst.partial")
    if (source_state in partial_states) != is_partial:
        raise ValueError("recovery source state does not match its path")
    allowed_states = {
        RecoverySourceDisposition.REMOVED: partial_states,
        RecoverySourceDisposition.MOVED_TO_QUARANTINE: {
            RecoverySourceState.PARTIAL_TRUNCATED,
            RecoverySourceState.ORPHAN_CLOSED_DATA,
        },
        RecoverySourceDisposition.RETAINED: {
            RecoverySourceState.ORPHAN_CLOSED_DATA,
        },
        RecoverySourceDisposition.LEGITIMATELY_MISSING: {
            RecoverySourceState.CLEANUP_INTENT,
            RecoverySourceState.CLEANUP_TOMBSTONE,
        },
    }
    if source_state not in allowed_states[source_disposition]:
        raise ValueError("recovery source state does not match its disposition")


def _payload_from_control_record(
    record: NativeEventDraft | RawEnvelope,
) -> RecoveryControlPayloadV1:
    if type(record) not in {NativeEventDraft, RawEnvelope}:
        raise TypeError("control record must be NativeEventDraft or RawEnvelope")
    if (
        record.logical_stream != "_control"
        or record.transport is not Transport.INTERNAL
    ):
        raise ValueError("recovery control record must use the internal _control scope")
    try:
        payload = RecoveryControlPayloadV1.model_validate_json(
            encode_json(record.payload)
        )
    except (TypeError, ValueError) as error:
        raise ValueError("recovery control payload is invalid") from error
    source_identity = _parse_source_path(payload.source_relative_path)
    _validate_source_outcome_state(
        payload.source_state,
        payload.source_disposition,
        payload.source_relative_path,
    )
    if (
        source_identity.exchange is not record.exchange
        or source_identity.market is not payload.source_market
        or source_identity.instrument_key != payload.source_instrument_key
        or source_identity.logical_stream != payload.source_logical_stream
    ):
        raise ValueError("recovery control payload does not match source path")
    return payload


def _target_from_payload(
    payload: RecoveryControlPayloadV1,
) -> StorageControlTargetV1 | None:
    if payload.recovered_generation_id is None:
        return None
    assert payload.recovered_relative_path is not None
    return StorageControlTargetV1(
        generation_id=payload.recovered_generation_id,
        data_relative_path=payload.recovered_relative_path,
    )


def _validate_control_identity(identity: AcceptedRecordIdentityV1) -> None:
    if type(identity) is not AcceptedRecordIdentityV1:
        raise TypeError("control_record_identity must be AcceptedRecordIdentityV1")
    if (
        identity.market is not None
        or identity.instrument_key is not None
        or identity.logical_stream != "_control"
    ):
        raise ValueError("control record identity must use exchange _control scope")


def _validate_control_carrier_path(
    path: object,
    *,
    exchange: Exchange,
) -> str:
    if type(exchange) is not Exchange:
        raise TypeError("control carrier exchange must be Exchange")
    normalized = _normalized_relative_path(
        cast(str, path),
        field_name="control_data_relative_path",
    )
    if normalized.endswith(".partial"):
        raise ValueError("control data path must be final")
    identity = _parse_source_path(normalized)
    if (
        identity.exchange is not exchange
        or identity.market is not None
        or identity.instrument_key is not None
        or identity.logical_stream != "_control"
    ):
        raise ValueError("control data path must match exchange _control scope")
    return normalized


@dataclass(frozen=True, slots=True)
class RecoveryOutcome:
    transaction_id: CanonicalUuid
    recovery_control_event_id: NonEmptyString
    source_state: RecoverySourceState
    source_disposition: RecoverySourceDisposition
    source_relative_path: NormalizedDataRelativePath
    source_sha256: Sha256
    recovered_generation_id: NonEmptyString | None
    recovered_relative_path: NormalizedDataRelativePath | None
    recovered_sha256: Sha256 | None
    quarantined_relative_path: NormalizedDataRelativePath | None
    quarantined_sha256: Sha256 | None
    informational_only: bool

    def __post_init__(self) -> None:
        _validate_transaction_event(
            self.transaction_id,
            self.recovery_control_event_id,
        )
        if type(self.source_state) is not RecoverySourceState:
            raise TypeError("source_state must be RecoverySourceState")
        if type(self.source_disposition) is not RecoverySourceDisposition:
            raise TypeError("source_disposition must be RecoverySourceDisposition")
        source_identity = _parse_source_path(self.source_relative_path)
        _validate_source_outcome_state(
            self.source_state,
            self.source_disposition,
            self.source_relative_path,
        )
        RecoveryControlPayloadV1(
            schema_version=1,
            recovery_control_event_id=self.recovery_control_event_id,
            transaction_id=self.transaction_id,
            source_state=self.source_state,
            source_disposition=self.source_disposition,
            source_market=source_identity.market,
            source_instrument_key=source_identity.instrument_key,
            source_logical_stream=source_identity.logical_stream,
            source_relative_path=self.source_relative_path,
            source_sha256=self.source_sha256,
            recovered_generation_id=self.recovered_generation_id,
            recovered_relative_path=self.recovered_relative_path,
            recovered_sha256=self.recovered_sha256,
            quarantined_relative_path=self.quarantined_relative_path,
            quarantined_sha256=self.quarantined_sha256,
            informational_only=self.informational_only,
            affected_markets=(
                () if source_identity.market is None else (source_identity.market,)
            ),
        )


def _control_payload_from_intent(
    intent: RecoveryIntentV1,
) -> RecoveryControlPayloadV1:
    identity = _parse_source_path(intent.source_relative_path)
    affected_markets = () if identity.market is None else (identity.market,)
    return RecoveryControlPayloadV1(
        schema_version=1,
        recovery_control_event_id=intent.recovery_control_event_id,
        transaction_id=intent.transaction_id,
        source_state=intent.source_state,
        source_disposition=intent.planned_source_disposition,
        source_market=identity.market,
        source_instrument_key=identity.instrument_key,
        source_logical_stream=identity.logical_stream,
        source_relative_path=intent.source_relative_path,
        source_sha256=intent.source_sha256,
        recovered_generation_id=intent.planned_data_generation_id,
        recovered_relative_path=intent.planned_data_relative_path,
        recovered_sha256=intent.planned_data_sha256,
        quarantined_relative_path=intent.planned_quarantine_relative_path,
        quarantined_sha256=intent.planned_quarantine_sha256,
        informational_only=(
            intent.planned_source_disposition
            is RecoverySourceDisposition.LEGITIMATELY_MISSING
        ),
        affected_markets=affected_markets,
    )


def _outcome_from_intent(intent: RecoveryIntentV1) -> RecoveryOutcome:
    return RecoveryOutcome(
        transaction_id=intent.transaction_id,
        recovery_control_event_id=intent.recovery_control_event_id,
        source_state=intent.source_state,
        source_disposition=intent.planned_source_disposition,
        source_relative_path=intent.source_relative_path,
        source_sha256=intent.source_sha256,
        recovered_generation_id=intent.planned_data_generation_id,
        recovered_relative_path=intent.planned_data_relative_path,
        recovered_sha256=intent.planned_data_sha256,
        quarantined_relative_path=intent.planned_quarantine_relative_path,
        quarantined_sha256=intent.planned_quarantine_sha256,
        informational_only=(
            intent.planned_source_disposition
            is RecoverySourceDisposition.LEGITIMATELY_MISSING
        ),
    )


def _outcome_sha256(outcome: RecoveryOutcome) -> str:
    return hashlib.sha256(encode_json(asdict(outcome)) + b"\n").hexdigest()


@dataclass(frozen=True, slots=True)
class PendingRecoveryControl:
    transaction_id: CanonicalUuid
    recovery_control_event_id: NonEmptyString
    source_state: RecoverySourceState
    source_disposition: RecoverySourceDisposition
    draft: NativeEventDraft
    target: StorageControlTargetV1 | None

    def __post_init__(self) -> None:
        _validate_transaction_event(
            self.transaction_id,
            self.recovery_control_event_id,
        )
        if type(self.source_state) is not RecoverySourceState:
            raise TypeError("source_state must be RecoverySourceState")
        if type(self.source_disposition) is not RecoverySourceDisposition:
            raise TypeError("source_disposition must be RecoverySourceDisposition")
        if type(self.draft) is not NativeEventDraft:
            raise TypeError("draft must be NativeEventDraft")
        if self.target is not None and type(self.target) is not StorageControlTargetV1:
            raise TypeError("target must be StorageControlTargetV1 or None")
        payload = _payload_from_control_record(self.draft)
        if (
            payload.transaction_id != self.transaction_id
            or payload.recovery_control_event_id != self.recovery_control_event_id
            or payload.source_state is not self.source_state
            or payload.source_disposition is not self.source_disposition
        ):
            raise ValueError("pending recovery fields do not match its draft")
        if self.target != _target_from_payload(payload):
            raise ValueError("pending recovery target does not match its draft")


@dataclass(frozen=True, slots=True)
class RecoveryControlAdmission:
    transaction_id: CanonicalUuid
    recovery_control_event_id: NonEmptyString
    control_record: AcceptedRecord
    control_record_identity: AcceptedRecordIdentityV1
    control_generation_id: NonEmptyString
    control_data_relative_path: NormalizedDataRelativePath
    control_manifest_relative_path: NormalizedDataRelativePath
    association: StorageControlAssociationV1 | None
    control_frame_bytes: bytes
    zstd_level: int
    max_plain_frame_bytes: PositiveInt

    def __post_init__(self) -> None:
        _validate_transaction_event(
            self.transaction_id,
            self.recovery_control_event_id,
        )
        if type(self.control_record) is not AcceptedRecord:
            raise TypeError("control_record must be AcceptedRecord")
        _validate_control_identity(self.control_record_identity)
        _strict_nonempty(
            self.control_generation_id,
            field_name="control_generation_id",
        )
        data_path = _validate_control_carrier_path(
            self.control_data_relative_path,
            exchange=self.control_record_identity.exchange,
        )
        manifest_path = _normalized_relative_path(
            self.control_manifest_relative_path,
            field_name="control_manifest_relative_path",
        )
        if manifest_path != manifest_path_for_data(data_path).as_posix():
            raise ValueError("control manifest path must be the data sibling")
        if (
            self.association is not None
            and type(self.association) is not StorageControlAssociationV1
        ):
            raise TypeError("association must be StorageControlAssociationV1 or None")
        if type(self.control_frame_bytes) is not bytes:
            raise TypeError("control_frame_bytes must be bytes")
        if not self.control_frame_bytes:
            raise ValueError("control_frame_bytes must be nonempty")
        zstd_level = _strict_integer(
            self.zstd_level,
            field_name="zstd_level",
            minimum=1,
        )
        if zstd_level > 22:
            raise ValueError("zstd_level must not exceed 22")
        _strict_integer(
            self.max_plain_frame_bytes,
            field_name="max_plain_frame_bytes",
            minimum=1,
        )

        record = self.control_record
        envelope = record.envelope
        identity = self.control_record_identity
        if record.encoded_jsonl != encode_envelope(envelope):
            raise ValueError("control record bytes do not match its envelope")
        expected_identity = (
            envelope.exchange,
            envelope.market,
            envelope.instrument_key,
            envelope.logical_stream,
            envelope.worker_instance_id,
            envelope.writer_sequence,
            envelope.config_sha256,
        )
        observed_identity = (
            identity.exchange,
            identity.market,
            identity.instrument_key,
            identity.logical_stream,
            identity.worker_instance_id,
            identity.writer_sequence,
            identity.config_sha256,
        )
        if observed_identity != expected_identity:
            raise ValueError("control record identity does not match its envelope")
        payload = _payload_from_control_record(envelope)
        if (
            payload.transaction_id != self.transaction_id
            or payload.recovery_control_event_id != self.recovery_control_event_id
        ):
            raise ValueError("control admission does not match recovery payload")
        expected_target = _target_from_payload(payload)
        expected_association = (
            None
            if expected_target is None
            else StorageControlAssociationV1(
                schema_version=1,
                control_kind=payload.kind,
                control_event_id=payload.recovery_control_event_id,
                targets=(expected_target,),
                acceptance_ordinal=identity.acceptance_ordinal,
                config_generation=identity.config_generation,
            )
        )
        if self.association != expected_association:
            raise ValueError("control association does not match recovery payload")
        scan = scan_recovery_frames(
            self.control_frame_bytes,
            data_path + ".partial",
        )
        if (
            scan.valid_prefix_size_bytes != len(self.control_frame_bytes)
            or len(scan.frames) != 1
            or scan.frames[0].envelopes != (envelope,)
        ):
            raise ValueError("control frame must contain exactly the accepted envelope")


@dataclass(frozen=True, slots=True)
class RecoveryControlReceipt:
    transaction_id: CanonicalUuid
    recovery_control_event_id: NonEmptyString
    control_record_identity: AcceptedRecordIdentityV1
    control_generation_id: NonEmptyString
    control_data_relative_path: NormalizedDataRelativePath
    control_encoded_sha256: Sha256
    durable_at_monotonic_ns: NonNegativeInt

    def __post_init__(self) -> None:
        _validate_transaction_event(
            self.transaction_id,
            self.recovery_control_event_id,
        )
        _validate_control_identity(self.control_record_identity)
        _strict_nonempty(
            self.control_generation_id,
            field_name="control_generation_id",
        )
        _validate_control_carrier_path(
            self.control_data_relative_path,
            exchange=self.control_record_identity.exchange,
        )
        _strict_sha256(
            self.control_encoded_sha256,
            field_name="control_encoded_sha256",
        )
        _strict_integer(
            self.durable_at_monotonic_ns,
            field_name="durable_at_monotonic_ns",
            minimum=0,
        )


@dataclass(frozen=True, slots=True)
class RecoveryReconciliation:
    completed_outcomes: tuple[RecoveryOutcome, ...]
    pending_controls: tuple[PendingRecoveryControl, ...]

    def __post_init__(self) -> None:
        if type(self.completed_outcomes) is not tuple:
            raise TypeError("completed_outcomes must be a tuple")
        if any(type(item) is not RecoveryOutcome for item in self.completed_outcomes):
            raise TypeError("completed_outcomes must contain RecoveryOutcome values")
        if type(self.pending_controls) is not tuple:
            raise TypeError("pending_controls must be a tuple")
        if any(
            type(item) is not PendingRecoveryControl for item in self.pending_controls
        ):
            raise TypeError(
                "pending_controls must contain PendingRecoveryControl values"
            )
        completed_ids = tuple(
            outcome.transaction_id for outcome in self.completed_outcomes
        )
        pending_ids = tuple(pending.transaction_id for pending in self.pending_controls)
        if completed_ids != tuple(sorted(completed_ids)):
            raise ValueError("completed outcomes must be in transaction-ID order")
        if pending_ids != tuple(sorted(pending_ids)):
            raise ValueError("pending controls must be in transaction-ID order")
        if len(set(completed_ids)) != len(completed_ids):
            raise ValueError("completed transaction IDs must be unique")
        if len(set(pending_ids)) != len(pending_ids):
            raise ValueError("pending transaction IDs must be unique")
        if set(completed_ids) & set(pending_ids):
            raise ValueError("completed and pending transactions must be disjoint")


@dataclass(frozen=True, slots=True)
class RecoveryContext:
    data_root: Path
    state_root: Path
    exchange: Exchange
    worker_instance_id: str
    config_sha256: str
    config_generation: int
    clock: Clock
    io_limiter: StorageIoLimiter
    recovery_coordinator: RecoveryDurabilityCoordinator
    storage_executor: Executor
    source_disposition_resolver: SourceDispositionResolver

    def __post_init__(self) -> None:
        if not isinstance(self.data_root, Path):
            raise TypeError("data_root must be Path")
        if not isinstance(self.state_root, Path):
            raise TypeError("state_root must be Path")
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        _strict_nonempty(
            self.worker_instance_id,
            field_name="worker_instance_id",
        )
        _strict_sha256(self.config_sha256, field_name="config_sha256")
        _strict_integer(
            self.config_generation,
            field_name="config_generation",
            minimum=0,
        )
        if not callable(getattr(self.clock, "time_ns", None)) or not callable(
            getattr(self.clock, "monotonic_ns", None)
        ):
            raise TypeError("clock must implement time_ns and monotonic_ns")
        if type(self.io_limiter) is not StorageIoLimiter:
            raise TypeError("io_limiter must be StorageIoLimiter")
        if type(self.recovery_coordinator) is not RecoveryDurabilityCoordinator:
            raise TypeError(
                "recovery_coordinator must be RecoveryDurabilityCoordinator"
            )
        if (
            self.recovery_coordinator.accounting_mode
            is not RecoveryAccountingMode.UNMEASURED
        ):
            raise ValueError("recovery coordinator must use unmeasured accounting")
        if not callable(getattr(self.storage_executor, "submit", None)):
            raise TypeError("storage_executor must implement Executor.submit")
        if not callable(
            getattr(self.source_disposition_resolver, "resolve_missing", None)
        ):
            raise TypeError(
                "source_disposition_resolver must implement resolve_missing"
            )


class RecoveryBackend(Protocol):
    async def reconcile(self, context: RecoveryContext) -> RecoveryReconciliation: ...

    async def bind_control_ownership(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        admission: RecoveryControlAdmission,
    ) -> None: ...

    async def acknowledge_control_durable(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        receipt: RecoveryControlReceipt,
    ) -> RecoveryOutcome: ...


def _pending_from_intent(intent: RecoveryIntentV1) -> PendingRecoveryControl:
    payload = _control_payload_from_intent(intent)
    source_identity = _parse_source_path(intent.source_relative_path)
    target = _target_from_payload(payload)
    return PendingRecoveryControl(
        transaction_id=intent.transaction_id,
        recovery_control_event_id=intent.recovery_control_event_id,
        source_state=intent.source_state,
        source_disposition=intent.planned_source_disposition,
        draft=NativeEventDraft(
            exchange=source_identity.exchange,
            market=None,
            instrument_key=None,
            wire_symbol=None,
            logical_stream="_control",
            native_channel=None,
            transport=Transport.INTERNAL,
            event_time_ns=None,
            event_time_source=None,
            payload=payload.model_dump(mode="json"),
        ),
        target=target,
    )


def _verify_recovery_artifact(
    data_root: Path,
    relative_path: str,
    expected_size: int,
    expected_sha256: str,
) -> None:
    path = data_root / validate_normalized_data_relative_path(relative_path)
    try:
        fd, _ = _open_regular_no_follow(path)
        try:
            observed = size_and_sha256_fd(fd)
        finally:
            os.close(fd)
    except OSError as error:
        raise RecoveryBlocked(
            f"recovery artifact is missing or unsafe: {relative_path}"
        ) from error
    if observed != (expected_size, expected_sha256):
        raise RecoveryBlocked(
            f"recovery artifact disagrees with intent: {relative_path}"
        )


def _cleanup_proof_from_intent(
    intent: RecoveryIntentV1,
) -> CleanupProofEvidenceV1:
    assert intent.cleanup_proof_kind is not None
    assert intent.cleanup_proof_relative_path is not None
    assert intent.cleanup_proof_size_bytes is not None
    assert intent.cleanup_proof_sha256 is not None
    assert intent.planned_manifest_relative_path is not None
    assert intent.planned_manifest_sha256 is not None
    return CleanupProofEvidenceV1(
        schema_version=1,
        kind=intent.cleanup_proof_kind,
        proof_relative_path=intent.cleanup_proof_relative_path,
        proof_size_bytes=intent.cleanup_proof_size_bytes,
        proof_sha256=intent.cleanup_proof_sha256,
        source_manifest_relative_path=intent.planned_manifest_relative_path,
        source_manifest_sha256=intent.planned_manifest_sha256,
        source_data_relative_path=intent.source_relative_path,
        source_data_size_bytes=intent.source_size_bytes,
        source_data_sha256=intent.source_sha256,
    )


def _verify_cleanup_source(
    *,
    data_root: Path,
    intent: RecoveryIntentV1,
    resolver: SourceDispositionResolver,
    lease: SourceLease | None = None,
) -> None:
    assert intent.planned_manifest_relative_path is not None
    assert intent.planned_manifest_size_bytes is not None
    assert intent.planned_manifest_sha256 is not None
    expected_proof = _cleanup_proof_from_intent(intent)
    manifest_path = data_root / intent.planned_manifest_relative_path
    owned_lease = lease
    acquired = False
    try:
        loaded = load_raw_manifest(manifest_path)
        if (
            len(loaded.canonical_bytes) != intent.planned_manifest_size_bytes
            or loaded.sha256 != intent.planned_manifest_sha256
            or loaded.manifest.data_relative_path != intent.source_relative_path
            or loaded.manifest.file_size_bytes != intent.source_size_bytes
            or loaded.manifest.file_sha256 != intent.source_sha256
        ):
            raise RecoveryBlocked("cleanup source manifest disagrees with intent")
        if owned_lease is None:
            owned_lease = SourceLease.exclusive(
                lease_path_for_data(data_root / intent.source_relative_path)
            )
            acquired = True
        validation = validate_local_source(
            loaded,
            data_root=data_root,
            resolver=resolver,
            lease=owned_lease,
            expected_cleanup_proof=expected_proof,
        )
    except RecoveryBlocked:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise RecoveryBlocked("cleanup source proof could not be verified") from error
    finally:
        if acquired:
            assert owned_lease is not None
            owned_lease.release()
    expected_disposition = (
        SourceDisposition.CLEANUP_INTENT
        if intent.source_state is RecoverySourceState.CLEANUP_INTENT
        else SourceDisposition.CLEANUP_TOMBSTONE
    )
    if (
        validation.disposition is not expected_disposition
        or validation.cleanup_proof != expected_proof
    ):
        raise RecoveryBlocked("cleanup source proof disagrees with intent")


def _verify_settled_data_artifact(
    *,
    data_root: Path,
    artifacts: RecoveryArtifactsDurableV1,
    resolver: SourceDispositionResolver,
) -> None:
    relative_path = artifacts.data_relative_path
    if relative_path is None:
        return
    assert artifacts.data_size_bytes is not None
    assert artifacts.data_sha256 is not None
    try:
        data_fd, _ = _open_regular_no_follow(data_root / relative_path)
    except FileNotFoundError:
        data_fd = None
    except OSError as error:
        raise RecoveryBlocked("recovered data path is unsafe") from error
    if data_fd is not None:
        try:
            observed = size_and_sha256_fd(data_fd)
        finally:
            os.close(data_fd)
        if observed != (
            artifacts.data_size_bytes,
            artifacts.data_sha256,
        ):
            raise RecoveryBlocked("recovered data disagrees with durable artifacts")
        fsync_directory((data_root / relative_path).parent)
        return

    assert artifacts.manifest_relative_path is not None
    assert artifacts.manifest_size_bytes is not None
    assert artifacts.manifest_sha256 is not None
    try:
        loaded = load_raw_manifest(data_root / artifacts.manifest_relative_path)
        if (
            len(loaded.canonical_bytes) != artifacts.manifest_size_bytes
            or loaded.sha256 != artifacts.manifest_sha256
            or loaded.manifest.data_relative_path != relative_path
            or loaded.manifest.file_size_bytes != artifacts.data_size_bytes
            or loaded.manifest.file_sha256 != artifacts.data_sha256
        ):
            raise RecoveryBlocked("recovered cleanup manifest disagrees with artifacts")
        lease = SourceLease.exclusive(lease_path_for_data(data_root / relative_path))
        try:
            validation = validate_local_source(
                loaded,
                data_root=data_root,
                resolver=resolver,
                lease=lease,
            )
        finally:
            lease.release()
    except RecoveryBlocked:
        raise
    except (OSError, TypeError, ValueError) as error:
        raise RecoveryBlocked("recovered data cleanup proof is invalid") from error
    if (
        validation.disposition
        not in {
            SourceDisposition.CLEANUP_INTENT,
            SourceDisposition.CLEANUP_TOMBSTONE,
        }
        or validation.cleanup_proof is None
    ):
        raise RecoveryBlocked("recovered data loss is unexplained")


def _verify_settled_chain_artifacts(
    data_root: Path,
    chain: tuple[RecoveryFact, ...],
    resolver: SourceDispositionResolver,
) -> None:
    if len(chain) < 3:
        raise RecoveryBlocked("recovery transaction has not settled its source")
    intent = cast(RecoveryIntentV1, chain[0])
    artifacts = cast(RecoveryArtifactsDurableV1, chain[1])
    for relative_path, size, sha256 in (
        (
            artifacts.manifest_relative_path,
            artifacts.manifest_size_bytes,
            artifacts.manifest_sha256,
        ),
        (
            artifacts.quarantine_relative_path,
            artifacts.quarantine_size_bytes,
            artifacts.quarantine_sha256,
        ),
    ):
        if relative_path is None:
            continue
        assert size is not None
        assert sha256 is not None
        _verify_recovery_artifact(data_root, relative_path, size, sha256)
        fsync_directory((data_root / relative_path).parent)
    _verify_settled_data_artifact(
        data_root=data_root,
        artifacts=artifacts,
        resolver=resolver,
    )
    if (
        intent.planned_source_disposition
        is RecoverySourceDisposition.LEGITIMATELY_MISSING
    ):
        _verify_cleanup_source(
            data_root=data_root,
            intent=intent,
            resolver=resolver,
        )
        return
    if intent.planned_source_disposition in {
        RecoverySourceDisposition.REMOVED,
        RecoverySourceDisposition.MOVED_TO_QUARANTINE,
    }:
        source_path = data_root / intent.source_relative_path
        try:
            fd, _ = _open_regular_no_follow(source_path)
        except FileNotFoundError:
            return
        except OSError as error:
            raise RecoveryBlocked("settled recovery source path is unsafe") from error
        else:
            os.close(fd)
            raise RecoveryBlocked("settled recovery source still exists")


def _assert_control_carrier_unallocated(
    data_root: Path,
    admission: RecoveryControlAdmission,
) -> None:
    for relative_path in (
        admission.control_data_relative_path + ".partial",
        admission.control_data_relative_path,
        admission.control_manifest_relative_path,
    ):
        try:
            fd, _ = _open_regular_no_follow(data_root / relative_path)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise RecoveryBlocked("reserved control carrier path is unsafe") from error
        else:
            os.close(fd)
            raise RecoveryBlocked("reserved control carrier path already exists")


def _ownership_from_admission(
    *,
    settled: RecoverySourceSettledV1,
    admission: RecoveryControlAdmission,
    created_at_ns: int,
) -> RecoveryControlOwnershipV1:
    frame = admission.control_frame_bytes
    source_relative_path = admission.control_data_relative_path + ".partial"
    scan = scan_recovery_frames(frame, source_relative_path)
    manifest = _recovery_manifest(
        scan=scan,
        source=frame,
        source_relative_path=source_relative_path,
        source_state=RecoverySourceState.OWNED_CONTROL_CARRIER,
        transaction_id=admission.transaction_id,
        created_at_ns=created_at_ns,
        data_relative_path=admission.control_data_relative_path,
        data=frame,
        quarantine_relative_path=None,
        quarantine=None,
    )
    manifest_bytes = manifest.canonical_bytes()
    return RecoveryControlOwnershipV1.create(
        schema_version=1,
        fact_kind="control_ownership",
        transaction_id=admission.transaction_id,
        created_at_ns=created_at_ns,
        predecessor_sha256=settled.fact_sha256,
        recovery_control_event_id=admission.recovery_control_event_id,
        control_record_identity=admission.control_record_identity,
        control_envelope=admission.control_record.envelope,
        control_encoded_sha256=hashlib.sha256(
            admission.control_record.encoded_jsonl
        ).hexdigest(),
        control_frame_base64=base64.b64encode(frame).decode("ascii"),
        control_frame_size_bytes=len(frame),
        control_frame_sha256=hashlib.sha256(frame).hexdigest(),
        control_recovery_manifest_base64=base64.b64encode(manifest_bytes).decode(
            "ascii"
        ),
        control_recovery_manifest_size_bytes=len(manifest_bytes),
        control_recovery_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        control_generation_id=admission.control_generation_id,
        control_data_relative_path=admission.control_data_relative_path,
        control_manifest_relative_path=admission.control_manifest_relative_path,
        control_association=admission.association,
        zstd_level=admission.zstd_level,
        max_plain_frame_bytes=admission.max_plain_frame_bytes,
    )


def _verify_owned_control_carrier(
    data_root: Path,
    ownership: RecoveryControlOwnershipV1,
) -> None:
    frame = base64.b64decode(ownership.control_frame_base64, validate=True)
    _verify_recovery_artifact(
        data_root,
        ownership.control_data_relative_path,
        ownership.control_frame_size_bytes,
        ownership.control_frame_sha256,
    )
    partial_path = data_root / (ownership.control_data_relative_path + ".partial")
    try:
        partial_fd, _ = _open_regular_no_follow(partial_path)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise RecoveryBlocked("owned control partial path is unsafe") from error
    else:
        os.close(partial_fd)
        raise RecoveryBlocked("owned control partial remains after publication")
    expected_manifest = base64.b64decode(
        ownership.control_recovery_manifest_base64,
        validate=True,
    )
    manifest_path = data_root / ownership.control_manifest_relative_path
    try:
        observed_manifest = _read_regular_bytes(manifest_path)
    except OSError as error:
        raise RecoveryBlocked("owned control manifest is missing or unsafe") from error
    if observed_manifest != expected_manifest:
        _validate_normal_owned_control_manifest(observed_manifest, ownership)
    scanned = scan_recovery_frames(
        frame,
        ownership.control_data_relative_path + ".partial",
    )
    if (
        scanned.valid_prefix_size_bytes != len(frame)
        or len(scanned.frames) != 1
        or scanned.frames[0].envelopes != (ownership.control_envelope,)
    ):
        raise RecoveryBlocked("owned control carrier does not contain its exact row")


def _validate_normal_owned_control_manifest(
    source: bytes,
    ownership: RecoveryControlOwnershipV1,
) -> None:
    try:
        manifest = RawManifestV1.model_validate_json(source)
    except (TypeError, ValueError, ValidationError) as error:
        raise RecoveryBlocked("owned control normal manifest is invalid") from error
    if manifest.canonical_bytes() != source:
        raise RecoveryBlocked("owned control normal manifest is noncanonical")
    envelope = ownership.control_envelope
    metadata = envelope.rest_metadata
    requested_intervals = (
        ()
        if metadata is None or metadata.requested_interval_ns is None
        else (metadata.requested_interval_ns,)
    )
    effective_intervals = (
        ()
        if metadata is None or metadata.effective_interval_ns is None
        else (metadata.effective_interval_ns,)
    )
    expected_identity_and_rows = (
        envelope.exchange,
        None,
        None,
        "_control",
        (),
        ownership.control_data_relative_path,
        ownership.control_manifest_relative_path,
        ownership.control_frame_size_bytes,
        ownership.control_frame_sha256,
        ownership.zstd_level,
        True,
        True,
        ownership.max_plain_frame_bytes,
        1,
        envelope.received_at_ns,
        envelope.received_at_ns,
        envelope.event_time_ns,
        envelope.event_time_ns,
        envelope.worker_instance_id,
        (
            ()
            if envelope.connection_generation is None
            else (envelope.connection_generation,)
        ),
        envelope.writer_sequence,
        envelope.writer_sequence,
        envelope.config_sha256,
        () if envelope.egress_id is None else (envelope.egress_id,),
        requested_intervals,
        effective_intervals,
    )
    observed_identity_and_rows = (
        manifest.exchange,
        manifest.market,
        manifest.instrument_key,
        manifest.logical_stream,
        manifest.wire_symbols,
        manifest.data_relative_path,
        manifest.manifest_relative_path,
        manifest.file_size_bytes,
        manifest.file_sha256,
        manifest.zstd_level,
        manifest.zstd_write_checksum,
        manifest.zstd_write_content_size,
        manifest.max_plain_frame_bytes,
        manifest.record_count,
        manifest.first_received_at_ns,
        manifest.last_received_at_ns,
        manifest.first_event_time_ns,
        manifest.last_event_time_ns,
        manifest.worker_instance_id,
        manifest.connection_generations,
        manifest.writer_sequence_first,
        manifest.writer_sequence_last,
        manifest.config_sha256,
        manifest.egress_ids,
        manifest.requested_intervals_ns,
        manifest.effective_intervals_ns,
    )
    if observed_identity_and_rows != expected_identity_and_rows:
        raise RecoveryBlocked("owned control normal manifest disagrees with row")
    if (
        manifest.gap_count,
        manifest.reconnect_count,
        manifest.parse_error_count,
        manifest.checksum_error_count,
        manifest.queue_overflow_count,
        manifest.control_event_ids,
    ) != (0, 0, 0, 0, 0, ()):
        raise RecoveryBlocked("owned control normal summaries are invalid")
    lag_values = (
        manifest.durability_lag_p50_ns,
        manifest.durability_lag_p95_ns,
        manifest.durability_lag_p99_ns,
        manifest.durability_lag_max_ns,
    )
    expected_lag_values: tuple[int | None, ...] | None = None
    if manifest.durability_lag_max_ns is not None:
        expected_histogram = CumulativeDurabilityHistogram()
        expected_histogram.add(manifest.durability_lag_max_ns)
        expected_snapshot = expected_histogram.snapshot()
        expected_lag_values = (
            expected_snapshot.lag_p50_ns,
            expected_snapshot.lag_p95_ns,
            expected_snapshot.lag_p99_ns,
            expected_snapshot.lag_max_ns,
        )
    if (
        manifest.close_reason is not CloseReason.RECOVERY_CONTROL
        or manifest.durability_measurement != "measured"
        or manifest.durability_sample_count != 1
        or lag_values != expected_lag_values
        or manifest.sync_count is None
        or manifest.sync_count < 1
        or manifest.sync_duration_total_ns is None
        or manifest.sync_duration_max_ns is None
        or manifest.sync_duration_total_ns < manifest.sync_duration_max_ns
        or manifest.slo_breach_count not in {0, 1}
        or manifest.write_failure_count != 0
        or manifest.sync_failure_count != 0
        or manifest.created_at_ns is None
        or manifest.created_at_ns < ownership.created_at_ns
        or manifest.closed_at_ns < manifest.created_at_ns
    ):
        raise RecoveryBlocked("owned control measured durability facts are invalid")


def _discover_unbound_raw_sources(
    data_root: Path,
    exchange: Exchange,
    reserved_relative_paths: frozenset[str],
) -> tuple[str, ...]:
    exchange_root = data_root / "raw" / exchange.value
    try:
        root_fd = _open_directory_path(exchange_root)
    except FileNotFoundError:
        return ()
    except OSError as error:
        raise RecoveryBlocked("raw exchange directory is unsafe") from error
    else:
        os.close(root_fd)

    discovered: list[str] = []

    def walk(directory: Path) -> None:
        try:
            entries = tuple(os.scandir(directory))
        except OSError as error:
            raise RecoveryBlocked("raw recovery discovery failed") from error
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink():
                raise RecoveryBlocked("raw recovery discovery found a symlink")
            if entry.is_dir(follow_symlinks=False):
                walk(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise RecoveryBlocked(
                    "raw recovery discovery found a non-regular entry"
                )
            name = entry.name
            if not name.endswith((".jsonl.zst.partial", ".jsonl.zst")):
                continue
            relative = path.relative_to(data_root).as_posix()
            try:
                identity = _parse_source_path(relative)
            except ValueError as error:
                raise RecoveryBlocked("raw recovery source path is invalid") from error
            if identity.exchange is not exchange:
                raise RecoveryBlocked("raw recovery source exchange is inconsistent")
            if relative in reserved_relative_paths:
                continue
            if name.endswith(".jsonl.zst"):
                manifest_path = data_root / manifest_path_for_data(relative)
                try:
                    manifest_stat = os.lstat(manifest_path)
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise RecoveryBlocked("raw manifest discovery failed") from error
                else:
                    if not stat.S_ISREG(manifest_stat.st_mode):
                        raise RecoveryBlocked("raw manifest path is unsafe")
                    continue
            discovered.append(relative)

    walk(exchange_root)
    discovered_set = set(discovered)
    for partial_relative_path in tuple(discovered_set):
        if not partial_relative_path.endswith(".partial"):
            continue
        final_relative_path = partial_relative_path.removesuffix(".partial")
        final_path = data_root / final_relative_path
        try:
            partial_fd, _ = _open_regular_no_follow(data_root / partial_relative_path)
            try:
                final_fd, _ = _open_regular_no_follow(final_path)
            except FileNotFoundError:
                os.close(partial_fd)
                continue
            except BaseException:
                os.close(partial_fd)
                raise
        except OSError as error:
            raise RecoveryBlocked("publication coexistence paths are unsafe") from error
        try:
            partial_stat = os.fstat(partial_fd)
            final_stat = os.fstat(final_fd)
            if (partial_stat.st_dev, partial_stat.st_ino) != (
                final_stat.st_dev,
                final_stat.st_ino,
            ):
                raise RecoveryBlocked(
                    "partial and final publication identities conflict"
                )
        finally:
            os.close(partial_fd)
            os.close(final_fd)
        if final_relative_path in reserved_relative_paths:
            raise RecoveryBlocked("publication coexistence overlaps a recovery owner")
        discovered_set.discard(final_relative_path)
    return tuple(sorted(discovered_set))


def _discover_manifest_only_sources(
    data_root: Path,
    exchange: Exchange,
    reserved_relative_paths: frozenset[str],
) -> tuple[str, ...]:
    exchange_root = data_root / "raw" / exchange.value
    try:
        root_fd = _open_directory_path(exchange_root)
    except FileNotFoundError:
        return ()
    except OSError as error:
        raise RecoveryBlocked("raw manifest directory is unsafe") from error
    else:
        os.close(root_fd)

    discovered: list[str] = []

    def walk(directory: Path) -> None:
        try:
            entries = tuple(os.scandir(directory))
        except OSError as error:
            raise RecoveryBlocked("raw manifest discovery failed") from error
        for entry in entries:
            path = Path(entry.path)
            if entry.is_symlink():
                raise RecoveryBlocked("raw manifest discovery found a symlink")
            if entry.is_dir(follow_symlinks=False):
                walk(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                raise RecoveryBlocked(
                    "raw manifest discovery found a non-regular entry"
                )
            if not entry.name.endswith(".manifest.json"):
                continue
            manifest_relative_path = path.relative_to(data_root).as_posix()
            try:
                loaded = load_raw_manifest(path)
            except (OSError, TypeError, ValueError) as error:
                raise RecoveryBlocked(
                    "raw manifest discovery found invalid bytes"
                ) from error
            manifest = loaded.manifest
            if manifest.exchange is not exchange:
                raise RecoveryBlocked("raw manifest belongs to another exchange")
            if (
                manifest_relative_path in reserved_relative_paths
                or manifest.data_relative_path in reserved_relative_paths
            ):
                continue
            data_path = data_root / manifest.data_relative_path
            try:
                data_fd, _ = _open_regular_no_follow(data_path)
            except FileNotFoundError:
                discovered.append(manifest_relative_path)
            except OSError as error:
                raise RecoveryBlocked("manifest-bound data path is unsafe") from error
            else:
                os.close(data_fd)

    walk(exchange_root)
    return tuple(sorted(discovered))


def _scan_recovery_path(
    source_path: Path,
    source_relative_path: str,
) -> StreamingRecoveryScan:
    try:
        fd, _ = _open_regular_no_follow(source_path)
        try:
            initial = os.fstat(fd)

            def chunks() -> Iterable[bytes]:
                offset = 0
                while offset < initial.st_size:
                    try:
                        chunk = os.pread(
                            fd,
                            min(1024 * 1024, initial.st_size - offset),
                            offset,
                        )
                    except InterruptedError:
                        continue
                    if not chunk:
                        raise OSError("recovery source truncated during scan")
                    offset += len(chunk)
                    yield chunk

            scanned = _scan_recovery_chunks(chunks(), source_relative_path)
            final = os.fstat(fd)
        finally:
            os.close(fd)
    except (OSError, TypeError, ValueError) as error:
        raise RecoveryBlocked("recovery source could not be scanned safely") from error
    if (initial.st_dev, initial.st_ino, initial.st_size) != (
        final.st_dev,
        final.st_ino,
        final.st_size,
    ) or scanned.source_size_bytes != initial.st_size:
        raise RecoveryBlocked("recovery source changed during scan")
    return scanned


def _plan_publication_coexistence(
    *,
    data_root: Path,
    source_relative_path: str,
    scan: StreamingRecoveryScan,
    transaction_id: str,
    created_at_ns: int,
    resolver: SourceDispositionResolver,
    lease: SourceLease,
) -> StreamingRecoveryPlan | None:
    if not source_relative_path.endswith(".partial"):
        return None
    source_path = data_root / source_relative_path
    final_relative_path = source_relative_path.removesuffix(".partial")
    final_path = data_root / final_relative_path
    try:
        source_fd, _ = _open_regular_no_follow(source_path)
        try:
            final_fd, _ = _open_regular_no_follow(final_path)
        except FileNotFoundError:
            os.close(source_fd)
            return None
        except BaseException:
            os.close(source_fd)
            raise
    except OSError as error:
        raise RecoveryBlocked("publication coexistence paths are unsafe") from error
    try:
        source_stat = os.fstat(source_fd)
        final_stat = os.fstat(final_fd)
        if (source_stat.st_dev, source_stat.st_ino) != (
            final_stat.st_dev,
            final_stat.st_ino,
        ):
            raise RecoveryBlocked("publication coexistence has different inodes")
    finally:
        os.close(source_fd)
        os.close(final_fd)
    if (
        scan.source_size_bytes == 0
        or scan.valid_prefix_size_bytes != scan.source_size_bytes
        or scan.invalid_suffix_size_bytes != 0
        or scan.row_facts is None
    ):
        raise RecoveryBlocked("publication coexistence data is not fully valid")

    manifest_relative_path = manifest_path_for_data(final_relative_path).as_posix()
    manifest_path = data_root / manifest_relative_path
    manifest: RawManifestV1 | None
    try:
        loaded = load_raw_manifest(manifest_path)
    except FileNotFoundError:
        loaded = None
    except (OSError, TypeError, ValueError) as error:
        raise RecoveryBlocked("publication coexistence manifest is invalid") from error
    if loaded is None:
        manifest = _recovery_manifest_from_facts(
            row_facts=scan.row_facts,
            recovered_frame_count=scan.frame_count,
            source_size_bytes=scan.source_size_bytes,
            source_sha256=scan.source_sha256,
            source_relative_path=source_relative_path,
            source_state=RecoverySourceState.PUBLICATION_COEXISTENCE,
            transaction_id=transaction_id,
            created_at_ns=created_at_ns,
            data_relative_path=final_relative_path,
            data_size_bytes=scan.source_size_bytes,
            data_sha256=scan.source_sha256,
            quarantine_relative_path=None,
            quarantine_size_bytes=None,
            quarantine_sha256=None,
        )
        manifest_bytes = manifest.canonical_bytes()
    else:
        validation = validate_local_source(
            loaded,
            data_root=data_root,
            resolver=resolver,
            lease=lease,
        )
        if (
            validation.disposition is not SourceDisposition.PRESENT_VERIFIED
            or loaded.manifest.data_relative_path != final_relative_path
            or loaded.manifest.file_size_bytes != scan.source_size_bytes
            or loaded.manifest.file_sha256 != scan.source_sha256
        ):
            raise RecoveryBlocked("publication coexistence manifest disagrees")
        manifest = None
        manifest_bytes = loaded.canonical_bytes

    intent = RecoveryIntentV1.create(
        schema_version=1,
        fact_kind="intent",
        transaction_id=transaction_id,
        created_at_ns=created_at_ns,
        predecessor_sha256=None,
        source_state=RecoverySourceState.PUBLICATION_COEXISTENCE,
        source_relative_path=source_relative_path,
        source_size_bytes=scan.source_size_bytes,
        source_sha256=scan.source_sha256,
        planned_source_disposition=RecoverySourceDisposition.REMOVED,
        planned_data_generation_id=recovery_generation_id(final_relative_path),
        planned_data_relative_path=final_relative_path,
        planned_data_size_bytes=scan.source_size_bytes,
        planned_data_sha256=scan.source_sha256,
        planned_manifest_relative_path=manifest_relative_path,
        planned_manifest_size_bytes=len(manifest_bytes),
        planned_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        planned_quarantine_relative_path=None,
        planned_quarantine_size_bytes=None,
        planned_quarantine_sha256=None,
        cleanup_proof_kind=None,
        cleanup_proof_relative_path=None,
        cleanup_proof_size_bytes=None,
        cleanup_proof_sha256=None,
        recovery_control_event_id=_RECOVERY_EVENT_PREFIX + transaction_id,
    )
    return StreamingRecoveryPlan(
        intent=intent,
        manifest=manifest,
        recovered_range=None,
        quarantine_range=None,
    )


def _next_recovery_sequence(source_path: Path) -> int:
    try:
        names = os.listdir(source_path.parent)
    except OSError as error:
        raise RecoveryBlocked(
            "recovery source directory cannot be enumerated"
        ) from error
    sequences: list[int] = []
    for name in names:
        if name.endswith(".lease"):
            candidate = name.removesuffix(".lease") + ".jsonl.zst"
        elif name.endswith(".manifest.json"):
            candidate = name.removesuffix(".manifest.json") + ".jsonl.zst"
        else:
            candidate = name.removesuffix(".partial")
        match = _FINAL_PART_NAME.fullmatch(candidate)
        if match is not None:
            sequences.append(int(match.group(2)))
    return max(sequences, default=-1) + 1


def _ensure_data_parent(data_root: Path, relative_path: str) -> Path:
    normalized = validate_normalized_data_relative_path(relative_path)
    parent_segments = tuple(Path(normalized).parent.parts)
    try:
        _create_child_directories(data_root, parent_segments)
    except (OSError, TypeError, ValueError) as error:
        raise RecoveryBlocked("recovery artifact parent is unsafe") from error
    return data_root / normalized


def _remove_known_temporary(path: Path) -> None:
    try:
        fd, _ = _open_regular_no_follow(path)
    except FileNotFoundError:
        return
    except OSError as error:
        raise RecoveryBlocked("recovery artifact temporary is unsafe") from error
    else:
        os.close(fd)
    try:
        parent_fd, name, _ = _open_parent_no_follow(path)
        try:
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    except OSError as error:
        raise RecoveryBlocked("recovery artifact temporary cleanup failed") from error


def _accept_exact_publication(
    *,
    destination: Path,
    temporary: Path | None,
    expected_size: int,
    expected_sha256: str,
) -> bool:
    try:
        destination_fd, _ = _open_regular_no_follow(destination)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RecoveryBlocked("recovery artifact destination is unsafe") from error
    try:
        if size_and_sha256_fd(destination_fd) != (
            expected_size,
            expected_sha256,
        ):
            raise RecoveryBlocked("recovery artifact destination has conflicting bytes")
        destination_stat = os.fstat(destination_fd)
    finally:
        os.close(destination_fd)

    parent_fd, _destination_name, _ = _open_parent_no_follow(destination)
    try:
        if temporary is not None:
            if temporary.parent != destination.parent:
                raise RecoveryBlocked("recovery publication names are not siblings")
            try:
                temporary_fd = os.open(
                    temporary.name,
                    os.O_RDONLY
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC
                    | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=parent_fd,
                )
            except FileNotFoundError:
                temporary_fd = None
            except OSError as error:
                raise RecoveryBlocked(
                    "recovery artifact temporary is unsafe"
                ) from error
            if temporary_fd is not None:
                try:
                    temporary_stat = os.fstat(temporary_fd)
                    if not stat.S_ISREG(temporary_stat.st_mode) or (
                        temporary_stat.st_dev,
                        temporary_stat.st_ino,
                    ) != (destination_stat.st_dev, destination_stat.st_ino):
                        raise RecoveryBlocked(
                            "recovery artifact temporary conflicts with final"
                        )
                    current = os.stat(
                        temporary.name,
                        dir_fd=parent_fd,
                        follow_symlinks=False,
                    )
                    if (current.st_dev, current.st_ino) != (
                        temporary_stat.st_dev,
                        temporary_stat.st_ino,
                    ):
                        raise RecoveryBlocked(
                            "recovery artifact temporary identity changed"
                        )
                    os.unlink(temporary.name, dir_fd=parent_fd)
                finally:
                    os.close(temporary_fd)
        os.fsync(parent_fd)
    except RecoveryBlocked:
        raise
    except OSError as error:
        raise RecoveryBlocked("recovery artifact parent sync failed") from error
    finally:
        os.close(parent_fd)
    return True


def _publish_exact_bytes(
    *,
    data_root: Path,
    relative_path: str,
    payload: bytes,
    transaction_id: str,
) -> None:
    destination = _ensure_data_parent(data_root, relative_path)
    expected = (len(payload), hashlib.sha256(payload).hexdigest())
    temporary = destination.with_name(f".{destination.name}.tmp-{transaction_id}")
    if _accept_exact_publication(
        destination=destination,
        temporary=temporary,
        expected_size=expected[0],
        expected_sha256=expected[1],
    ):
        return
    _remove_known_temporary(temporary)
    if not payload:
        try:
            parent_fd, name, _ = _open_parent_no_follow(temporary)
            try:
                fd = os.open(
                    name,
                    os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o640,
                    dir_fd=parent_fd,
                )
                os.fsync(parent_fd)
                os.fsync(fd)
                os.close(fd)
            finally:
                os.close(parent_fd)
        except OSError as error:
            raise RecoveryBlocked("empty recovery artifact creation failed") from error
    else:
        try:
            atomic_write_and_sync_json_exclusive(temporary, payload)
        except (OSError, TypeError, ValueError) as error:
            raise RecoveryBlocked("recovery artifact write failed") from error
    try:
        publish_no_replace(temporary, destination)
    except (OSError, PublicationConflict) as error:
        raise RecoveryBlocked("recovery artifact publication conflict") from error
    _verify_recovery_artifact(data_root, relative_path, *expected)


def _publish_source_range(
    *,
    data_root: Path,
    source_path: Path,
    byte_range: RecoveryByteRange,
    relative_path: str,
    transaction_id: str,
) -> None:
    destination = _ensure_data_parent(data_root, relative_path)
    temporary = destination.with_name(f".{destination.name}.tmp-{transaction_id}")
    if _accept_exact_publication(
        destination=destination,
        temporary=temporary,
        expected_size=byte_range.size_bytes,
        expected_sha256=byte_range.sha256,
    ):
        return
    _remove_known_temporary(temporary)
    try:
        source_fd, _ = _open_regular_no_follow(source_path)
        parent_fd, temporary_name, _ = _open_parent_no_follow(temporary)
        output_fd: int | None = None
        try:
            output_fd = os.open(
                temporary_name,
                os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o640,
                dir_fd=parent_fd,
            )
            os.fsync(parent_fd)
            offset = byte_range.start_offset
            remaining = byte_range.size_bytes
            while remaining:
                try:
                    chunk = os.pread(source_fd, min(1024 * 1024, remaining), offset)
                except InterruptedError:
                    continue
                if not chunk:
                    raise OSError("recovery source range ended early")
                write_all(output_fd, chunk)
                offset += len(chunk)
                remaining -= len(chunk)
            os.fsync(output_fd)
            if size_and_sha256_fd(output_fd) != (
                byte_range.size_bytes,
                byte_range.sha256,
            ):
                raise RecoveryBlocked("recovery source range hash changed")
        finally:
            if output_fd is not None:
                os.close(output_fd)
            os.close(parent_fd)
            os.close(source_fd)
        publish_no_replace(temporary, destination)
    except RecoveryBlocked:
        raise
    except (OSError, PublicationConflict) as error:
        raise RecoveryBlocked("recovery source range publication failed") from error
    _verify_recovery_artifact(
        data_root,
        relative_path,
        byte_range.size_bytes,
        byte_range.sha256,
    )


def _artifact_exists_exactly(
    data_root: Path,
    relative_path: str,
    expected_size: int,
    expected_sha256: str,
) -> bool:
    try:
        fd, _ = _open_regular_no_follow(data_root / relative_path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise RecoveryBlocked("recovery artifact path is unsafe") from error
    try:
        observed = size_and_sha256_fd(fd)
    finally:
        os.close(fd)
    if observed != (expected_size, expected_sha256):
        raise RecoveryBlocked("recovery artifact destination has conflicting bytes")
    return True


def _prepare_recovered_stream(
    *,
    data_root: Path,
    source_path: Path,
    byte_range: RecoveryByteRange,
    data_relative_path: str,
    generation_id: str,
) -> StreamFile:
    destination = _ensure_data_parent(data_root, data_relative_path)
    partial = destination.with_name(destination.name + ".partial")
    stream: StreamFile | None = None
    source_fd: int | None = None
    partial_fd: int | None = None
    parent_fd: int | None = None
    try:
        source_fd, _ = _open_regular_no_follow(source_path)
        parent_fd, partial_name, _ = _open_parent_no_follow(partial)
        try:
            partial_fd = os.open(
                partial_name,
                os.O_RDWR
                | os.O_APPEND
                | os.O_NOFOLLOW
                | os.O_CLOEXEC
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            os.close(parent_fd)
            parent_fd = None
            stream = StreamFile.allocate(
                partial,
                zstd_level=1,
                max_plain_frame_bytes=1,
                generation_id=generation_id,
            )
            existing_size = 0
        else:
            observed = os.fstat(partial_fd)
            if (
                not stat.S_ISREG(observed.st_mode)
                or observed.st_size > byte_range.size_bytes
            ):
                raise RecoveryBlocked("recovered partial is not an exact prefix")
            os.fsync(parent_fd)
            stream = StreamFile(
                path=partial,
                generation_id=generation_id,
                fd=partial_fd,
                zstd_level=1,
                max_plain_frame_bytes=1,
                compressor=zstandard.ZstdCompressor(
                    level=1,
                    write_checksum=True,
                    write_content_size=True,
                ),
            )
            partial_fd = None
            existing_size = observed.st_size

        digest = hashlib.sha256()
        offset = 0
        while offset < existing_size:
            read_size = min(1024 * 1024, existing_size - offset)
            try:
                existing = os.pread(stream.fileno(), read_size, offset)
                expected = os.pread(
                    source_fd,
                    read_size,
                    byte_range.start_offset + offset,
                )
            except InterruptedError:
                continue
            if not existing or existing != expected:
                raise RecoveryBlocked("recovered partial is not an exact prefix")
            digest.update(existing)
            offset += len(existing)

        remaining = byte_range.size_bytes - existing_size
        source_offset = byte_range.start_offset + existing_size
        while remaining:
            try:
                chunk = os.pread(
                    source_fd,
                    min(1024 * 1024, remaining),
                    source_offset,
                )
            except InterruptedError:
                continue
            if not chunk:
                raise OSError("recovery prefix ended early")
            write_all(stream.fileno(), chunk)
            digest.update(chunk)
            stream.compressed_size += len(chunk)
            source_offset += len(chunk)
            remaining -= len(chunk)
        stream.compressed_size = byte_range.size_bytes
    except BaseException:
        if stream is not None:
            stream.close_fd()
        elif partial_fd is not None:
            os.close(partial_fd)
        raise
    finally:
        if parent_fd is not None:
            os.close(parent_fd)
        if source_fd is not None:
            os.close(source_fd)
    assert stream is not None
    if digest.hexdigest() != byte_range.sha256:
        stream.close_fd()
        raise RecoveryBlocked("recovery prefix hash changed while copying")
    return stream


def _publish_recovered_stream(
    *,
    stream: StreamFile,
    destination: Path,
    expected: RecoveryByteRange,
) -> None:
    verification_fd = _open_bound_readonly_and_close(stream)
    try:
        if size_and_sha256_fd(verification_fd) != (
            expected.size_bytes,
            expected.sha256,
        ):
            raise RecoveryBlocked("synced recovery prefix has unexpected bytes")
        publish_no_replace(
            stream.path,
            destination,
            expected_source_fd=verification_fd,
        )
    except (OSError, PublicationConflict) as error:
        raise RecoveryBlocked("recovered data publication failed") from error
    finally:
        os.close(verification_fd)


async def _publish_recovered_range(
    context: RecoveryContext,
    *,
    source_path: Path,
    byte_range: RecoveryByteRange,
    data_relative_path: str,
    generation_id: str,
) -> None:
    destination = context.data_root / data_relative_path
    exists = await run_storage(
        context.io_limiter,
        context.storage_executor,
        _accept_exact_publication,
        destination=destination,
        temporary=destination.with_name(destination.name + ".partial"),
        expected_size=byte_range.size_bytes,
        expected_sha256=byte_range.sha256,
    )
    if exists:
        return
    stream = await run_storage(
        context.io_limiter,
        context.storage_executor,
        _prepare_recovered_stream,
        data_root=context.data_root,
        source_path=source_path,
        byte_range=byte_range,
        data_relative_path=data_relative_path,
        generation_id=generation_id,
    )
    try:
        work = stream.seal_for_sync(force_sync=True)
        assert work is not None
        await context.recovery_coordinator.sync_batch(
            (work,),
            trigger=DurabilityTrigger.RECOVERY,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _publish_recovered_stream,
            stream=stream,
            destination=context.data_root / data_relative_path,
            expected=byte_range,
        )
    except BaseException:
        if not stream.closed:
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                stream.close_fd,
            )
        raise


def _artifacts_fact_from_intent(
    intent: RecoveryIntentV1,
    *,
    created_at_ns: int,
) -> RecoveryArtifactsDurableV1:
    return RecoveryArtifactsDurableV1.create(
        schema_version=1,
        fact_kind="artifacts_durable",
        transaction_id=intent.transaction_id,
        created_at_ns=created_at_ns,
        predecessor_sha256=intent.fact_sha256,
        data_generation_id=intent.planned_data_generation_id,
        data_relative_path=intent.planned_data_relative_path,
        data_size_bytes=intent.planned_data_size_bytes,
        data_sha256=intent.planned_data_sha256,
        manifest_relative_path=intent.planned_manifest_relative_path,
        manifest_size_bytes=intent.planned_manifest_size_bytes,
        manifest_sha256=intent.planned_manifest_sha256,
        quarantine_relative_path=intent.planned_quarantine_relative_path,
        quarantine_size_bytes=intent.planned_quarantine_size_bytes,
        quarantine_sha256=intent.planned_quarantine_sha256,
    )


def _verify_artifacts_durable(
    data_root: Path,
    artifacts: RecoveryArtifactsDurableV1,
) -> None:
    for relative_path, size, sha256 in (
        (
            artifacts.data_relative_path,
            artifacts.data_size_bytes,
            artifacts.data_sha256,
        ),
        (
            artifacts.manifest_relative_path,
            artifacts.manifest_size_bytes,
            artifacts.manifest_sha256,
        ),
        (
            artifacts.quarantine_relative_path,
            artifacts.quarantine_size_bytes,
            artifacts.quarantine_sha256,
        ),
    ):
        if relative_path is None:
            continue
        assert size is not None
        assert sha256 is not None
        _verify_recovery_artifact(
            data_root,
            relative_path,
            size,
            sha256,
        )
        fsync_directory((data_root / relative_path).parent)


def _settled_fact_from_intent(
    intent: RecoveryIntentV1,
    artifacts: RecoveryArtifactsDurableV1,
    *,
    created_at_ns: int,
) -> RecoverySourceSettledV1:
    settled: tuple[str | None, int | None, str | None]
    if intent.planned_source_disposition is RecoverySourceDisposition.RETAINED:
        settled = (
            intent.source_relative_path,
            intent.source_size_bytes,
            intent.source_sha256,
        )
    elif (
        intent.planned_source_disposition
        is RecoverySourceDisposition.MOVED_TO_QUARANTINE
    ):
        settled = (
            intent.planned_quarantine_relative_path,
            intent.planned_quarantine_size_bytes,
            intent.planned_quarantine_sha256,
        )
    else:
        settled = (None, None, None)
    return RecoverySourceSettledV1.create(
        schema_version=1,
        fact_kind="source_settled",
        transaction_id=intent.transaction_id,
        created_at_ns=created_at_ns,
        predecessor_sha256=artifacts.fact_sha256,
        source_relative_path=intent.source_relative_path,
        source_disposition=intent.planned_source_disposition,
        settled_relative_path=settled[0],
        settled_size_bytes=settled[1],
        settled_sha256=settled[2],
    )


async def _publish_streaming_plan_artifacts(
    context: RecoveryContext,
    *,
    source_path: Path,
    plan: StreamingRecoveryPlan,
) -> None:
    intent = plan.intent
    if plan.recovered_range is not None:
        assert intent.planned_data_relative_path is not None
        assert intent.planned_data_generation_id is not None
        await _publish_recovered_range(
            context,
            source_path=source_path,
            byte_range=plan.recovered_range,
            data_relative_path=intent.planned_data_relative_path,
            generation_id=intent.planned_data_generation_id,
        )
    elif intent.planned_source_disposition is RecoverySourceDisposition.RETAINED or (
        intent.source_state is RecoverySourceState.PUBLICATION_COEXISTENCE
    ):
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            fsync_directory,
            source_path.parent,
        )
    if plan.manifest is not None:
        assert intent.planned_manifest_relative_path is not None
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _publish_exact_bytes,
            data_root=context.data_root,
            relative_path=intent.planned_manifest_relative_path,
            payload=plan.manifest.canonical_bytes(),
            transaction_id=intent.transaction_id,
        )
    if plan.quarantine_range is not None:
        assert intent.planned_quarantine_relative_path is not None
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _publish_source_range,
            data_root=context.data_root,
            source_path=source_path,
            byte_range=plan.quarantine_range,
            relative_path=intent.planned_quarantine_relative_path,
            transaction_id=intent.transaction_id,
        )


def _settle_discovered_source(
    *,
    data_root: Path,
    intent: RecoveryIntentV1,
) -> None:
    if intent.planned_source_disposition is RecoverySourceDisposition.RETAINED:
        _verify_recovery_artifact(
            data_root,
            intent.source_relative_path,
            intent.source_size_bytes,
            intent.source_sha256,
        )
        fsync_directory((data_root / intent.source_relative_path).parent)
        return
    source_path = data_root / intent.source_relative_path
    try:
        source_fd, _ = _open_regular_no_follow(source_path)
    except FileNotFoundError:
        try:
            parent_fd, name, _ = _open_parent_no_follow(source_path)
            try:
                try:
                    os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    os.fsync(parent_fd)
                    return
                raise RecoveryBlocked("recovery source reappeared during settlement")
            finally:
                os.close(parent_fd)
        except RecoveryBlocked:
            raise
        except OSError as error:
            raise RecoveryBlocked(
                "recovery source absence could not be made durable"
            ) from error
    except OSError as error:
        raise RecoveryBlocked("recovery source settlement path is unsafe") from error
    try:
        if size_and_sha256_fd(source_fd) != (
            intent.source_size_bytes,
            intent.source_sha256,
        ):
            raise RecoveryBlocked("recovery source changed before settlement")
        parent_fd, name, _ = _open_parent_no_follow(source_path)
        try:
            current_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            source_stat = os.fstat(source_fd)
            if (current_stat.st_dev, current_stat.st_ino) != (
                source_stat.st_dev,
                source_stat.st_ino,
            ):
                raise RecoveryBlocked("recovery source inode changed before settlement")
            os.unlink(name, dir_fd=parent_fd)
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        os.close(source_fd)


async def _reconcile_discovered_source(
    context: RecoveryContext,
    journal: _RecoveryJournal,
    source_relative_path: str,
) -> PendingRecoveryControl:
    source_path = context.data_root / source_relative_path
    final_source_path = (
        source_path.with_name(source_path.name.removesuffix(".partial"))
        if source_relative_path.endswith(".partial")
        else source_path
    )
    lease = await run_storage(
        context.io_limiter,
        context.storage_executor,
        SourceLease.exclusive,
        lease_path_for_data(final_source_path),
    )
    destination_lease: SourceLease | None = None
    try:
        scan = await run_storage(
            context.io_limiter,
            context.storage_executor,
            _scan_recovery_path,
            source_path,
            source_relative_path,
        )
        transaction_id = str(uuid.uuid4())
        created_at_ns = context.clock.time_ns()
        plan = await run_storage(
            context.io_limiter,
            context.storage_executor,
            _plan_publication_coexistence,
            data_root=context.data_root,
            source_relative_path=source_relative_path,
            scan=scan,
            transaction_id=transaction_id,
            created_at_ns=created_at_ns,
            resolver=context.source_disposition_resolver,
            lease=lease,
        )
        if plan is None:
            next_sequence = await run_storage(
                context.io_limiter,
                context.storage_executor,
                _next_recovery_sequence,
                source_path,
            )
            plan = _plan_streaming_recovery_source(
                source_relative_path=source_relative_path,
                scan=scan,
                transaction_id=transaction_id,
                created_at_ns=created_at_ns,
                next_part_sequence=next_sequence,
            )
        leased_data_relative_path = (
            source_relative_path.removesuffix(".partial")
            if source_relative_path.endswith(".partial")
            else source_relative_path
        )
        if (
            plan.intent.planned_data_relative_path is not None
            and plan.intent.planned_data_relative_path != leased_data_relative_path
        ):
            destination_lease = await run_storage(
                context.io_limiter,
                context.storage_executor,
                SourceLease.exclusive,
                lease_path_for_data(
                    context.data_root / plan.intent.planned_data_relative_path
                ),
            )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.publish,
            plan.intent,
        )
        await _publish_streaming_plan_artifacts(
            context,
            source_path=source_path,
            plan=plan,
        )
        artifacts = _artifacts_fact_from_intent(
            plan.intent,
            created_at_ns=context.clock.time_ns(),
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _verify_artifacts_durable,
            context.data_root,
            artifacts,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.publish,
            artifacts,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _verify_artifacts_durable,
            context.data_root,
            artifacts,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _settle_discovered_source,
            data_root=context.data_root,
            intent=plan.intent,
        )
        settled = _settled_fact_from_intent(
            plan.intent,
            artifacts,
            created_at_ns=context.clock.time_ns(),
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.publish,
            settled,
        )
        return _pending_from_intent(plan.intent)
    finally:
        if destination_lease is not None:
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                destination_lease.release,
            )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            lease.release,
        )


async def _reconcile_manifest_only_source(
    context: RecoveryContext,
    journal: _RecoveryJournal,
    manifest_relative_path: str,
) -> PendingRecoveryControl:
    loaded = await run_storage(
        context.io_limiter,
        context.storage_executor,
        load_raw_manifest,
        context.data_root / manifest_relative_path,
    )
    manifest = loaded.manifest
    source_path = context.data_root / manifest.data_relative_path
    lease = await run_storage(
        context.io_limiter,
        context.storage_executor,
        SourceLease.exclusive,
        lease_path_for_data(source_path),
    )
    try:
        try:
            validation = await run_storage(
                context.io_limiter,
                context.storage_executor,
                validate_local_source,
                loaded,
                data_root=context.data_root,
                resolver=context.source_disposition_resolver,
                lease=lease,
            )
        except (OSError, TypeError, ValueError) as error:
            raise RecoveryBlocked("manifest-only source proof is invalid") from error
        evidence = validation.cleanup_proof
        if (
            validation.disposition
            not in {
                SourceDisposition.CLEANUP_INTENT,
                SourceDisposition.CLEANUP_TOMBSTONE,
            }
            or evidence is None
        ):
            raise RecoveryBlocked("manifest-only source loss is unexplained")
        source_state = (
            RecoverySourceState.CLEANUP_INTENT
            if validation.disposition is SourceDisposition.CLEANUP_INTENT
            else RecoverySourceState.CLEANUP_TOMBSTONE
        )
        transaction_id = str(uuid.uuid4())
        intent = RecoveryIntentV1.create(
            schema_version=1,
            fact_kind="intent",
            transaction_id=transaction_id,
            created_at_ns=context.clock.time_ns(),
            predecessor_sha256=None,
            source_state=source_state,
            source_relative_path=manifest.data_relative_path,
            source_size_bytes=manifest.file_size_bytes,
            source_sha256=manifest.file_sha256,
            planned_source_disposition=(RecoverySourceDisposition.LEGITIMATELY_MISSING),
            planned_data_generation_id=None,
            planned_data_relative_path=None,
            planned_data_size_bytes=None,
            planned_data_sha256=None,
            planned_manifest_relative_path=manifest.manifest_relative_path,
            planned_manifest_size_bytes=len(loaded.canonical_bytes),
            planned_manifest_sha256=loaded.sha256,
            planned_quarantine_relative_path=None,
            planned_quarantine_size_bytes=None,
            planned_quarantine_sha256=None,
            cleanup_proof_kind=evidence.kind,
            cleanup_proof_relative_path=evidence.proof_relative_path,
            cleanup_proof_size_bytes=evidence.proof_size_bytes,
            cleanup_proof_sha256=evidence.proof_sha256,
            recovery_control_event_id=_RECOVERY_EVENT_PREFIX + transaction_id,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.publish,
            intent,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _verify_cleanup_source,
            data_root=context.data_root,
            intent=intent,
            resolver=context.source_disposition_resolver,
            lease=lease,
        )
        artifacts = _artifacts_fact_from_intent(
            intent,
            created_at_ns=context.clock.time_ns(),
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _verify_artifacts_durable,
            context.data_root,
            artifacts,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.publish,
            artifacts,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _verify_artifacts_durable,
            context.data_root,
            artifacts,
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _settle_discovered_source,
            data_root=context.data_root,
            intent=intent,
        )
        settled = _settled_fact_from_intent(
            intent,
            artifacts,
            created_at_ns=context.clock.time_ns(),
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.publish,
            settled,
        )
        return _pending_from_intent(intent)
    finally:
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            lease.release,
        )


def _frozen_recovery_sequence(intent: RecoveryIntentV1) -> int:
    if not intent.source_relative_path.endswith(".partial"):
        return 0
    data_relative_path = intent.planned_data_relative_path
    if data_relative_path is None:
        return 0
    match = _FINAL_PART_NAME.fullmatch(Path(data_relative_path).name)
    if match is None:
        raise RecoveryBlocked("recovery intent has an invalid planned data path")
    return int(match.group(2))


async def _resume_incomplete_source_transaction(
    context: RecoveryContext,
    journal: _RecoveryJournal,
    chain: tuple[RecoveryFact, ...],
) -> tuple[RecoveryFact, ...]:
    if len(chain) not in {1, 2}:
        raise RecoveryBlocked("recovery transaction is not resumable at source phase")
    intent = cast(RecoveryIntentV1, chain[0])
    is_cleanup = intent.source_state in {
        RecoverySourceState.CLEANUP_INTENT,
        RecoverySourceState.CLEANUP_TOMBSTONE,
    }
    source_path = context.data_root / intent.source_relative_path
    final_source_path = (
        source_path.with_name(source_path.name.removesuffix(".partial"))
        if intent.source_relative_path.endswith(".partial")
        else source_path
    )
    lease = await run_storage(
        context.io_limiter,
        context.storage_executor,
        SourceLease.exclusive,
        lease_path_for_data(final_source_path),
    )
    destination_lease: SourceLease | None = None
    try:
        leased_data_relative_path = (
            intent.source_relative_path.removesuffix(".partial")
            if intent.source_relative_path.endswith(".partial")
            else intent.source_relative_path
        )
        if (
            intent.planned_data_relative_path is not None
            and intent.planned_data_relative_path != leased_data_relative_path
        ):
            destination_lease = await run_storage(
                context.io_limiter,
                context.storage_executor,
                SourceLease.exclusive,
                lease_path_for_data(
                    context.data_root / intent.planned_data_relative_path
                ),
            )
        if len(chain) == 1:
            if is_cleanup:
                await run_storage(
                    context.io_limiter,
                    context.storage_executor,
                    _verify_cleanup_source,
                    data_root=context.data_root,
                    intent=intent,
                    resolver=context.source_disposition_resolver,
                    lease=lease,
                )
            elif intent.source_state is RecoverySourceState.PUBLICATION_COEXISTENCE:
                scan = await run_storage(
                    context.io_limiter,
                    context.storage_executor,
                    _scan_recovery_path,
                    source_path,
                    intent.source_relative_path,
                )
                plan = await run_storage(
                    context.io_limiter,
                    context.storage_executor,
                    _plan_publication_coexistence,
                    data_root=context.data_root,
                    source_relative_path=intent.source_relative_path,
                    scan=scan,
                    transaction_id=intent.transaction_id,
                    created_at_ns=intent.created_at_ns,
                    resolver=context.source_disposition_resolver,
                    lease=lease,
                )
                if plan is None or plan.intent != intent:
                    raise RecoveryBlocked(
                        "publication coexistence disagrees with durable intent"
                    )
                await _publish_streaming_plan_artifacts(
                    context,
                    source_path=source_path,
                    plan=plan,
                )
            else:
                scan = await run_storage(
                    context.io_limiter,
                    context.storage_executor,
                    _scan_recovery_path,
                    source_path,
                    intent.source_relative_path,
                )
                plan = _plan_streaming_recovery_source(
                    source_relative_path=intent.source_relative_path,
                    scan=scan,
                    transaction_id=intent.transaction_id,
                    created_at_ns=intent.created_at_ns,
                    next_part_sequence=_frozen_recovery_sequence(intent),
                )
                if plan.intent != intent:
                    raise RecoveryBlocked(
                        "recovery source disagrees with durable intent"
                    )
                await _publish_streaming_plan_artifacts(
                    context,
                    source_path=source_path,
                    plan=plan,
                )
            artifacts = _artifacts_fact_from_intent(
                intent,
                created_at_ns=context.clock.time_ns(),
            )
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                _verify_artifacts_durable,
                context.data_root,
                artifacts,
            )
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                journal.publish,
                artifacts,
            )
        else:
            artifacts = cast(RecoveryArtifactsDurableV1, chain[1])
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _verify_artifacts_durable,
            context.data_root,
            artifacts,
        )
        if is_cleanup:
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                _verify_cleanup_source,
                data_root=context.data_root,
                intent=intent,
                resolver=context.source_disposition_resolver,
                lease=lease,
            )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _settle_discovered_source,
            data_root=context.data_root,
            intent=intent,
        )
        settled = _settled_fact_from_intent(
            intent,
            artifacts,
            created_at_ns=context.clock.time_ns(),
        )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.publish,
            settled,
        )
        return (intent, artifacts, settled)
    finally:
        if destination_lease is not None:
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                destination_lease.release,
            )
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            lease.release,
        )


def _prepare_owned_control_stream(
    *,
    data_root: Path,
    ownership: RecoveryControlOwnershipV1,
) -> StreamFile:
    frame = base64.b64decode(ownership.control_frame_base64, validate=True)
    destination = _ensure_data_parent(
        data_root,
        ownership.control_data_relative_path,
    )
    partial = destination.with_name(destination.name + ".partial")
    parent_fd, partial_name, _ = _open_parent_no_follow(partial)
    fd: int | None = None
    try:
        try:
            fd = os.open(
                partial_name,
                os.O_RDWR
                | os.O_APPEND
                | os.O_NOFOLLOW
                | os.O_CLOEXEC
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
        except FileNotFoundError:
            os.close(parent_fd)
            parent_fd = -1
            stream = StreamFile.allocate(
                partial,
                zstd_level=ownership.zstd_level,
                max_plain_frame_bytes=ownership.max_plain_frame_bytes,
                generation_id=ownership.control_generation_id,
            )
            prefix_size = 0
        else:
            observed = os.fstat(fd)
            if not stat.S_ISREG(observed.st_mode):
                raise RecoveryBlocked("owned control partial is not regular")
            if observed.st_size > len(frame):
                raise RecoveryBlocked("owned control carrier is not an exact prefix")
            prefix = bytearray()
            offset = 0
            while offset < observed.st_size:
                try:
                    chunk = os.pread(fd, observed.st_size - offset, offset)
                except InterruptedError:
                    continue
                if not chunk:
                    raise RecoveryBlocked("owned control partial ended early")
                prefix.extend(chunk)
                offset += len(chunk)
            if bytes(prefix) != frame[: observed.st_size]:
                raise RecoveryBlocked("owned control carrier is not an exact prefix")
            stream = StreamFile(
                path=partial,
                generation_id=ownership.control_generation_id,
                fd=fd,
                zstd_level=ownership.zstd_level,
                max_plain_frame_bytes=ownership.max_plain_frame_bytes,
                compressor=zstandard.ZstdCompressor(
                    level=ownership.zstd_level,
                    write_checksum=True,
                    write_content_size=True,
                ),
            )
            fd = None
            prefix_size = observed.st_size
    except BaseException:
        if fd is not None:
            os.close(fd)
        raise
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)
    try:
        if prefix_size < len(frame):
            write_all(stream.fileno(), frame[prefix_size:])
        stream.compressed_size = len(frame)
        return stream
    except BaseException:
        stream.close_fd()
        raise


def _publish_owned_control_stream(
    *,
    stream: StreamFile,
    destination: Path,
    ownership: RecoveryControlOwnershipV1,
) -> None:
    verification_fd = _open_bound_readonly_and_close(stream)
    try:
        if size_and_sha256_fd(verification_fd) != (
            ownership.control_frame_size_bytes,
            ownership.control_frame_sha256,
        ):
            raise RecoveryBlocked("owned control carrier has unexpected bytes")
        publish_no_replace(
            stream.path,
            destination,
            expected_source_fd=verification_fd,
        )
    except RecoveryBlocked:
        raise
    except (OSError, PublicationConflict) as error:
        raise RecoveryBlocked("owned control carrier publication failed") from error
    finally:
        os.close(verification_fd)


async def _restore_owned_control_carrier(
    context: RecoveryContext,
    ownership: RecoveryControlOwnershipV1,
) -> None:
    final_path = context.data_root / ownership.control_data_relative_path
    partial_path = final_path.with_name(final_path.name + ".partial")
    manifest_path = context.data_root / ownership.control_manifest_relative_path
    try:
        manifest_bytes = await run_storage(
            context.io_limiter,
            context.storage_executor,
            _read_regular_bytes,
            manifest_path,
        )
    except FileNotFoundError:
        manifest_bytes = None
    except OSError as error:
        raise RecoveryBlocked("owned control manifest path is unsafe") from error

    final_exists = await run_storage(
        context.io_limiter,
        context.storage_executor,
        _artifact_exists_exactly,
        context.data_root,
        ownership.control_data_relative_path,
        ownership.control_frame_size_bytes,
        ownership.control_frame_sha256,
    )
    try:
        partial_fd, _ = await run_storage(
            context.io_limiter,
            context.storage_executor,
            _open_regular_no_follow,
            partial_path,
        )
    except FileNotFoundError:
        partial_exists = False
    except OSError as error:
        raise RecoveryBlocked("owned control partial path is unsafe") from error
    else:
        os.close(partial_fd)
        partial_exists = True
    if final_exists and partial_exists:
        raise RecoveryBlocked("owned control partial and final coexist")

    expected_manifest = base64.b64decode(
        ownership.control_recovery_manifest_base64,
        validate=True,
    )
    if manifest_bytes is not None:
        if not final_exists or partial_exists:
            raise RecoveryBlocked("owned control manifest lacks its exact carrier")
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            _verify_owned_control_carrier,
            context.data_root,
            ownership,
        )
        return

    if not final_exists:
        stream = await run_storage(
            context.io_limiter,
            context.storage_executor,
            _prepare_owned_control_stream,
            data_root=context.data_root,
            ownership=ownership,
        )
        try:
            work = stream.seal_for_sync(force_sync=True)
            assert work is not None
            await context.recovery_coordinator.sync_batch(
                (work,),
                trigger=DurabilityTrigger.RECOVERY,
            )
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                _publish_owned_control_stream,
                stream=stream,
                destination=final_path,
                ownership=ownership,
            )
        except BaseException:
            if not stream.closed:
                await run_storage(
                    context.io_limiter,
                    context.storage_executor,
                    stream.close_fd,
                )
            raise
    await run_storage(
        context.io_limiter,
        context.storage_executor,
        _publish_exact_bytes,
        data_root=context.data_root,
        relative_path=ownership.control_manifest_relative_path,
        payload=expected_manifest,
        transaction_id=ownership.transaction_id,
    )
    await run_storage(
        context.io_limiter,
        context.storage_executor,
        _verify_owned_control_carrier,
        context.data_root,
        ownership,
    )


async def _replay_owned_control_transaction(
    context: RecoveryContext,
    journal: _RecoveryJournal,
    chain: tuple[RecoveryFact, ...],
) -> tuple[RecoveryFact, ...]:
    if len(chain) != 4:
        raise RecoveryBlocked("owned control replay requires an ownership fact")
    intent = cast(RecoveryIntentV1, chain[0])
    ownership = cast(RecoveryControlOwnershipV1, chain[3])
    await _restore_owned_control_carrier(context, ownership)
    durable = RecoveryControlDurableV1.create(
        schema_version=1,
        fact_kind="control_durable",
        transaction_id=ownership.transaction_id,
        created_at_ns=context.clock.time_ns(),
        predecessor_sha256=ownership.fact_sha256,
        recovery_control_event_id=ownership.recovery_control_event_id,
        control_record_identity=ownership.control_record_identity,
        control_generation_id=ownership.control_generation_id,
        control_data_relative_path=ownership.control_data_relative_path,
        control_encoded_sha256=ownership.control_encoded_sha256,
        durable_at_monotonic_ns=context.clock.monotonic_ns(),
    )
    await run_storage(
        context.io_limiter,
        context.storage_executor,
        journal.publish,
        durable,
    )
    complete = RecoveryCompleteV1.create(
        schema_version=1,
        fact_kind="complete",
        transaction_id=intent.transaction_id,
        created_at_ns=context.clock.time_ns(),
        predecessor_sha256=durable.fact_sha256,
        recovery_control_event_id=intent.recovery_control_event_id,
        source_state=intent.source_state,
        source_disposition=intent.planned_source_disposition,
        outcome_sha256=_outcome_sha256(_outcome_from_intent(intent)),
    )
    await run_storage(
        context.io_limiter,
        context.storage_executor,
        journal.publish,
        complete,
    )
    return (*chain, durable, complete)


def _preflight_recovery_ownership(
    chains: tuple[tuple[RecoveryFact, ...], ...],
) -> frozenset[str]:
    owner_by_path: dict[str, str] = {}

    def claim(relative_path: str | None, transaction_id: str) -> None:
        if relative_path is None:
            return
        existing = owner_by_path.get(relative_path)
        if existing is not None and existing != transaction_id:
            raise RecoveryBlocked("recovery filesystem identity has overlapping owners")
        owner_by_path[relative_path] = transaction_id

    for chain in chains:
        if not chain:
            raise RecoveryBlocked("recovery transaction has no intent")
        intent = cast(RecoveryIntentV1, chain[0])
        transaction_id = intent.transaction_id
        claim(intent.source_relative_path, transaction_id)
        claim(intent.planned_data_relative_path, transaction_id)
        if intent.planned_data_relative_path is not None:
            claim(intent.planned_data_relative_path + ".partial", transaction_id)
        claim(intent.planned_manifest_relative_path, transaction_id)
        claim(intent.planned_quarantine_relative_path, transaction_id)
        if len(chain) >= 4:
            ownership = cast(RecoveryControlOwnershipV1, chain[3])
            claim(ownership.control_data_relative_path, transaction_id)
            claim(ownership.control_data_relative_path + ".partial", transaction_id)
            claim(ownership.control_manifest_relative_path, transaction_id)
    return frozenset(owner_by_path)


class PosixRecoveryBackend:
    async def reconcile(self, context: RecoveryContext) -> RecoveryReconciliation:
        if type(context) is not RecoveryContext:
            raise TypeError("context must be RecoveryContext")
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        transaction_ids = await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.transaction_ids,
        )
        loaded_chains: list[tuple[RecoveryFact, ...]] = []
        for transaction_id in transaction_ids:
            loaded_chains.append(
                await run_storage(
                    context.io_limiter,
                    context.storage_executor,
                    journal.load_chain,
                    transaction_id,
                )
            )
        reserved = set(
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                _preflight_recovery_ownership,
                tuple(loaded_chains),
            )
        )
        completed: list[RecoveryOutcome] = []
        pending: list[PendingRecoveryControl] = []
        for chain in loaded_chains:
            if len(chain) < 3:
                chain = await _resume_incomplete_source_transaction(
                    context,
                    journal,
                    chain,
                )
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                _verify_settled_chain_artifacts,
                context.data_root,
                chain,
                context.source_disposition_resolver,
            )
            intent = cast(RecoveryIntentV1, chain[0])
            if len(chain) == 3:
                pending.append(_pending_from_intent(intent))
            elif len(chain) == 4:
                chain = await _replay_owned_control_transaction(
                    context,
                    journal,
                    chain,
                )
                completed.append(_outcome_from_intent(intent))
            elif len(chain) == 5:
                ownership = cast(RecoveryControlOwnershipV1, chain[3])
                await run_storage(
                    context.io_limiter,
                    context.storage_executor,
                    _verify_owned_control_carrier,
                    context.data_root,
                    ownership,
                )
                complete = RecoveryCompleteV1.create(
                    schema_version=1,
                    fact_kind="complete",
                    transaction_id=intent.transaction_id,
                    created_at_ns=context.clock.time_ns(),
                    predecessor_sha256=chain[-1].fact_sha256,
                    recovery_control_event_id=intent.recovery_control_event_id,
                    source_state=intent.source_state,
                    source_disposition=intent.planned_source_disposition,
                    outcome_sha256=_outcome_sha256(_outcome_from_intent(intent)),
                )
                await run_storage(
                    context.io_limiter,
                    context.storage_executor,
                    journal.publish,
                    complete,
                )
                completed.append(_outcome_from_intent(intent))
            else:
                completed.append(_outcome_from_intent(intent))
        manifest_only_sources = await run_storage(
            context.io_limiter,
            context.storage_executor,
            _discover_manifest_only_sources,
            context.data_root,
            context.exchange,
            frozenset(reserved),
        )
        for manifest_relative_path in manifest_only_sources:
            recovered_pending = await _reconcile_manifest_only_source(
                context,
                journal,
                manifest_relative_path,
            )
            pending.append(recovered_pending)
            source_relative_path = _payload_from_control_record(
                recovered_pending.draft
            ).source_relative_path
            reserved.update({source_relative_path, manifest_relative_path})
        discovered = await run_storage(
            context.io_limiter,
            context.storage_executor,
            _discover_unbound_raw_sources,
            context.data_root,
            context.exchange,
            frozenset(reserved),
        )
        for source_relative_path in discovered:
            pending.append(
                await _reconcile_discovered_source(
                    context,
                    journal,
                    source_relative_path,
                )
            )
        return RecoveryReconciliation(
            completed_outcomes=tuple(
                sorted(completed, key=lambda item: item.transaction_id)
            ),
            pending_controls=tuple(
                sorted(pending, key=lambda item: item.transaction_id)
            ),
        )

    async def bind_control_ownership(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        admission: RecoveryControlAdmission,
    ) -> None:
        if type(context) is not RecoveryContext:
            raise TypeError("context must be RecoveryContext")
        if type(pending) is not PendingRecoveryControl:
            raise TypeError("pending must be PendingRecoveryControl")
        if type(admission) is not RecoveryControlAdmission:
            raise TypeError("admission must be RecoveryControlAdmission")
        if admission.control_record_identity.exchange is not context.exchange:
            raise RecoveryBlocked("control admission exchange disagrees with context")
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        chain = await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.load_chain,
            pending.transaction_id,
        )
        if len(chain) < 3:
            raise RecoveryBlocked("control ownership requires a source-settled chain")
        intent = cast(RecoveryIntentV1, chain[0])
        settled = cast(RecoverySourceSettledV1, chain[2])
        if pending != _pending_from_intent(intent):
            raise RecoveryBlocked("pending control disagrees with recovery chain")
        if (
            admission.transaction_id != pending.transaction_id
            or admission.recovery_control_event_id != pending.recovery_control_event_id
            or admission.control_record.envelope.payload != pending.draft.payload
        ):
            raise RecoveryBlocked("control admission disagrees with pending control")
        if len(chain) == 3:
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                _assert_control_carrier_unallocated,
                context.data_root,
                admission,
            )
            created_at_ns = context.clock.time_ns()
        elif len(chain) == 4:
            existing = cast(RecoveryControlOwnershipV1, chain[3])
            created_at_ns = existing.created_at_ns
        else:
            raise RecoveryBlocked("control ownership is already past its bind phase")
        expected = _ownership_from_admission(
            settled=settled,
            admission=admission,
            created_at_ns=created_at_ns,
        )
        if len(chain) == 4:
            if existing != expected:
                raise RecoveryBlocked("control ownership conflicts with durable fact")
            return
        await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.publish,
            expected,
        )

    async def acknowledge_control_durable(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        receipt: RecoveryControlReceipt,
    ) -> RecoveryOutcome:
        if type(context) is not RecoveryContext:
            raise TypeError("context must be RecoveryContext")
        if type(pending) is not PendingRecoveryControl:
            raise TypeError("pending must be PendingRecoveryControl")
        if type(receipt) is not RecoveryControlReceipt:
            raise TypeError("receipt must be RecoveryControlReceipt")
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        chain = await run_storage(
            context.io_limiter,
            context.storage_executor,
            journal.load_chain,
            pending.transaction_id,
        )
        if len(chain) < 4:
            raise RecoveryBlocked("durable receipt requires control ownership")
        intent = cast(RecoveryIntentV1, chain[0])
        ownership = cast(RecoveryControlOwnershipV1, chain[3])
        if pending != _pending_from_intent(intent):
            raise RecoveryBlocked("pending control disagrees with recovery chain")
        if (
            receipt.transaction_id,
            receipt.recovery_control_event_id,
            receipt.control_record_identity,
            receipt.control_generation_id,
            receipt.control_data_relative_path,
            receipt.control_encoded_sha256,
        ) != (
            ownership.transaction_id,
            ownership.recovery_control_event_id,
            ownership.control_record_identity,
            ownership.control_generation_id,
            ownership.control_data_relative_path,
            ownership.control_encoded_sha256,
        ):
            raise RecoveryBlocked("durable receipt disagrees with control ownership")
        if len(chain) >= 5:
            existing_durable = cast(RecoveryControlDurableV1, chain[4])
            durable_created_at_ns = existing_durable.created_at_ns
        else:
            durable_created_at_ns = context.clock.time_ns()
        expected_durable = RecoveryControlDurableV1.create(
            schema_version=1,
            fact_kind="control_durable",
            transaction_id=receipt.transaction_id,
            created_at_ns=durable_created_at_ns,
            predecessor_sha256=ownership.fact_sha256,
            recovery_control_event_id=receipt.recovery_control_event_id,
            control_record_identity=receipt.control_record_identity,
            control_generation_id=receipt.control_generation_id,
            control_data_relative_path=receipt.control_data_relative_path,
            control_encoded_sha256=receipt.control_encoded_sha256,
            durable_at_monotonic_ns=receipt.durable_at_monotonic_ns,
        )
        if len(chain) >= 5 and existing_durable != expected_durable:
            raise RecoveryBlocked("durable receipt conflicts with durable fact")
        if len(chain) < 6:
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                _verify_settled_chain_artifacts,
                context.data_root,
                chain,
                context.source_disposition_resolver,
            )
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                _verify_owned_control_carrier,
                context.data_root,
                ownership,
            )
        if len(chain) == 4:
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                journal.publish,
                expected_durable,
            )
        outcome = _outcome_from_intent(intent)
        if len(chain) < 6:
            complete = RecoveryCompleteV1.create(
                schema_version=1,
                fact_kind="complete",
                transaction_id=intent.transaction_id,
                created_at_ns=context.clock.time_ns(),
                predecessor_sha256=expected_durable.fact_sha256,
                recovery_control_event_id=intent.recovery_control_event_id,
                source_state=intent.source_state,
                source_disposition=intent.planned_source_disposition,
                outcome_sha256=_outcome_sha256(outcome),
            )
            await run_storage(
                context.io_limiter,
                context.storage_executor,
                journal.publish,
                complete,
            )
        return outcome


__all__ = [
    "RECOVERY_GENERATION_NAMESPACE",
    "PendingRecoveryControl",
    "PosixRecoveryBackend",
    "RecoveryArtifactsDurableV1",
    "RecoveryBackend",
    "RecoveryCompleteV1",
    "RecoveryContext",
    "RecoveryControlAdmission",
    "RecoveryControlDurableV1",
    "RecoveryControlOwnershipV1",
    "RecoveryControlPayloadV1",
    "RecoveryControlReceipt",
    "RecoveryIntentV1",
    "RecoveryOutcome",
    "RecoveryReconciliation",
    "RecoverySourceDisposition",
    "RecoverySourceSettledV1",
    "bad_tail_quarantine_relative_path",
    "load_recovery_chain",
    "load_recovery_fact",
    "recovery_generation_id",
    "whole_source_quarantine_relative_path",
]
