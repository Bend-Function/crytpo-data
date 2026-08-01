from __future__ import annotations

import asyncio
import ctypes
import errno
import hashlib
import os
import stat
import sys
import uuid
from collections.abc import Callable, Sequence
from concurrent.futures import Executor
from dataclasses import dataclass, field
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import ParamSpec, Protocol, TypeVar

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.types import CloseReason, Exchange, Market
from crypto_collector.storage.durability import (
    DurabilityBatch,
    DurabilityTrigger,
    FileDurabilityResult,
    FilePersistenceError,
    FileSyncCompleted,
    FileSyncFailed,
    StorageIoLimiter,
    WriterCriticalError,
    WriterCriticalReason,
)
from crypto_collector.storage.layout import raw_partial_path
from crypto_collector.storage.manifest import RawManifestV1, manifest_path_for_data
from crypto_collector.storage.models import (
    AcceptedRecord,
    AcceptedRecordIdentityV1,
    StorageControlAssociationV1,
)
from crypto_collector.storage.stats import CumulativeDurabilityHistogram
from crypto_collector.storage.stream_file import (
    SealedFileWork,
    StreamFile,
    write_all,
)

_P = ParamSpec("_P")
_T = TypeVar("_T")
_RENAME_NOREPLACE = 1
_HASH_CHUNK_BYTES = 1024 * 1024


class PublicationConflict(RuntimeError):
    def __init__(self, source: Path, destination: Path, message: str) -> None:
        self.source = source
        self.destination = destination
        super().__init__(message)


class NoReplaceCapability(StrEnum):
    RENAMEAT2_NOREPLACE = "renameat2_noreplace"
    HARDLINK = "hardlink"


class _Renameat2Unavailable(OSError):
    pass


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise OSError(errno.ENOTSUP, f"required open flag {name} is unavailable")
    return value


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_DIRECTORY")
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )


def _readonly_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
        | _required_open_flag("O_NONBLOCK")
    )


def _normalized_absolute_path(value: Path, *, field_name: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"{field_name} must be Path")
    if not value.is_absolute() or any(
        part in {"", ".", ".."} for part in value.parts[1:]
    ):
        raise ValueError(f"{field_name} must be a normalized absolute path")
    if not value.name or value.name in {".", ".."}:
        raise ValueError(f"{field_name} must include a normalized basename")
    return value


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except BaseException:  # noqa: BLE001 - retain the primary storage failure
        return


def _open_directory_no_symlinks(path: Path) -> int:
    directory = _normalized_absolute_path(path, field_name="directory path")
    current_fd = os.open(directory.anchor, _directory_flags())
    try:
        for part_name in directory.parts[1:]:
            child_fd = os.open(part_name, _directory_flags(), dir_fd=current_fd)
            try:
                os.close(current_fd)
            except BaseException:
                _close_quietly(child_fd)
                raise
            current_fd = child_fd
        return current_fd
    except BaseException:
        _close_quietly(current_fd)
        raise


def _close_all_after(
    descriptors: tuple[int, ...],
    primary_error: BaseException | None,
) -> None:
    close_errors: list[BaseException] = []
    for descriptor in descriptors:
        try:
            os.close(descriptor)
        except BaseException as error:  # noqa: BLE001 - close every descriptor
            close_errors.append(error)
    if primary_error is None and close_errors:
        raise close_errors[0]


def fsync_directory(path: Path) -> None:
    directory_fd = _open_directory_no_symlinks(path)
    primary_error: BaseException | None = None
    try:
        os.fsync(directory_fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _close_all_after((directory_fd,), primary_error)


def _require_regular_fd(fd: int, *, description: str) -> os.stat_result:
    if type(fd) is not int or fd < 0:
        raise TypeError(f"{description} fd must be a non-negative integer")
    result = os.fstat(fd)
    if not stat.S_ISREG(result.st_mode):
        raise OSError(errno.EINVAL, f"{description} must be a regular file")
    return result


def _open_regular_at(parent_fd: int, name: str) -> int:
    fd = os.open(name, _readonly_flags(), dir_fd=parent_fd)
    try:
        _require_regular_fd(fd, description="publication path")
    except BaseException:
        _close_quietly(fd)
        raise
    return fd


def open_readonly_nofollow(path: Path) -> int:
    candidate = _normalized_absolute_path(path, field_name="file path")
    parent_fd = _open_directory_no_symlinks(candidate.parent)
    try:
        file_fd = _open_regular_at(parent_fd, candidate.name)
    except BaseException as error:
        _close_all_after((parent_fd,), error)
        raise
    try:
        _close_all_after((parent_fd,), None)
    except BaseException as error:
        _close_all_after((file_fd,), error)
        raise
    return file_fd


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev, left.st_ino) == (right.st_dev, right.st_ino)


def require_path_is_open_inode(path: Path, fd: int) -> None:
    expected = _require_regular_fd(fd, description="verification")
    observed_fd = open_readonly_nofollow(path)
    primary_error: BaseException | None = None
    try:
        observed = _require_regular_fd(observed_fd, description="published path")
        if not _same_inode(expected, observed):
            raise PublicationConflict(path, path, "published path inode changed")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _close_all_after((observed_fd,), primary_error)


def _open_bound_readonly_and_close(stream_file: StreamFile) -> int:
    if type(stream_file) is not StreamFile:
        raise TypeError("stream_file must be StreamFile")
    writable_stat = _require_regular_fd(
        stream_file.fileno(),
        description="writable partial",
    )
    verification_fd = open_readonly_nofollow(stream_file.path)
    try:
        verification_stat = _require_regular_fd(
            verification_fd,
            description="readonly partial",
        )
        if not _same_inode(writable_stat, verification_stat):
            raise PublicationConflict(
                stream_file.path,
                stream_file.path,
                "partial path inode changed before close",
            )
    except BaseException as error:
        try:
            stream_file.close_fd()
        except BaseException as close_error:
            _close_all_after((verification_fd,), close_error)
            raise
        _close_all_after((verification_fd,), error)
        raise
    try:
        stream_file.close_fd()
    except BaseException as error:
        _close_all_after((verification_fd,), error)
        raise
    return verification_fd


def size_and_sha256_fd(fd: int) -> tuple[int, str]:
    initial = _require_regular_fd(fd, description="hash source")
    digest = hashlib.sha256()
    offset = 0
    while offset < initial.st_size:
        try:
            chunk = os.pread(
                fd, min(_HASH_CHUNK_BYTES, initial.st_size - offset), offset
            )
        except InterruptedError:
            continue
        if not chunk:
            raise OSError(errno.EIO, "hash source truncated during scan")
        digest.update(chunk)
        offset += len(chunk)
    final = _require_regular_fd(fd, description="hash source")
    if not _same_inode(initial, final) or final.st_size != initial.st_size:
        raise OSError(errno.EBUSY, "hash source changed during scan")
    return initial.st_size, digest.hexdigest()


def _renameat2_noreplace(source: Path, destination: Path, *, dir_fd: int) -> None:
    if not sys.platform.startswith("linux"):
        raise _Renameat2Unavailable(errno.ENOTSUP, "renameat2 is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise _Renameat2Unavailable(
            errno.ENOTSUP, "renameat2 is unavailable"
        ) from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        dir_fd,
        os.fsencode(source.name),
        dir_fd,
        os.fsencode(destination.name),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {
        errno.ENOSYS,
        errno.EINVAL,
        errno.EOPNOTSUPP,
        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
    }:
        raise _Renameat2Unavailable(error_number, "renameat2 is unsupported")
    raise OSError(error_number, os.strerror(error_number), destination)


def _open_matching_destination(
    parent_fd: int,
    source_fd: int,
    source: Path,
    destination: Path,
) -> int:
    try:
        destination_fd = _open_regular_at(parent_fd, destination.name)
    except OSError as error:
        raise PublicationConflict(
            source,
            destination,
            "immutable publication destination is not a regular source inode",
        ) from error
    try:
        if not _same_inode(os.fstat(source_fd), os.fstat(destination_fd)):
            raise PublicationConflict(
                source,
                destination,
                "immutable publication destination already exists",
            )
    except BaseException:
        _close_quietly(destination_fd)
        raise
    return destination_fd


def _finish_hardlink_publication(
    *,
    parent_fd: int,
    source: Path,
    destination: Path,
    source_fd: int,
) -> None:
    destination_fd = _open_matching_destination(
        parent_fd,
        source_fd,
        source,
        destination,
    )
    _close_all_after((destination_fd,), None)
    os.fsync(parent_fd)
    os.unlink(source.name, dir_fd=parent_fd)
    os.fsync(parent_fd)


def _publish_hardlink(
    parent_fd: int,
    source: Path,
    destination: Path,
    source_fd: int,
) -> None:
    try:
        os.link(
            source.name,
            destination.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
            follow_symlinks=False,
        )
    except FileExistsError:
        pass
    _finish_hardlink_publication(
        parent_fd=parent_fd,
        source=source,
        destination=destination,
        source_fd=source_fd,
    )


def _publish_renameat2(
    parent_fd: int,
    source: Path,
    destination: Path,
    source_fd: int,
) -> None:
    try:
        _renameat2_noreplace(source, destination, dir_fd=parent_fd)
    except FileExistsError:
        destination_fd = _open_matching_destination(
            parent_fd,
            source_fd,
            source,
            destination,
        )
        _close_all_after((destination_fd,), None)
        os.fsync(parent_fd)
        os.unlink(source.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
        return
    destination_fd = _open_matching_destination(
        parent_fd,
        source_fd,
        source,
        destination,
    )
    _close_all_after((destination_fd,), None)
    os.fsync(parent_fd)


def publish_no_replace(
    source: Path,
    destination: Path,
    *,
    capability: NoReplaceCapability | None = None,
    expected_source_fd: int | None = None,
) -> None:
    source_path = _normalized_absolute_path(source, field_name="source")
    destination_path = _normalized_absolute_path(destination, field_name="destination")
    if source_path.parent != destination_path.parent:
        raise ValueError("publication source and destination must have the same parent")
    if source_path.name == destination_path.name:
        raise ValueError("publication requires distinct basenames")
    if capability is not None and type(capability) is not NoReplaceCapability:
        raise TypeError("capability must be NoReplaceCapability or None")
    expected_source_stat: os.stat_result | None = None
    if expected_source_fd is not None:
        expected_source_stat = _require_regular_fd(
            expected_source_fd,
            description="expected publication source",
        )

    parent_fd = _open_directory_no_symlinks(source_path.parent)
    source_fd: int | None = None
    primary_error: BaseException | None = None
    try:
        source_fd = _open_regular_at(parent_fd, source_path.name)
        if expected_source_stat is not None and not _same_inode(
            expected_source_stat,
            os.fstat(source_fd),
        ):
            raise PublicationConflict(
                source_path,
                destination_path,
                "publication source inode changed",
            )
        publication_source_fd = (
            source_fd if expected_source_fd is None else expected_source_fd
        )
        assert publication_source_fd is not None
        selected = capability
        if selected is None:
            selected = (
                NoReplaceCapability.RENAMEAT2_NOREPLACE
                if sys.platform.startswith("linux")
                else NoReplaceCapability.HARDLINK
            )
        if selected is NoReplaceCapability.RENAMEAT2_NOREPLACE:
            try:
                _publish_renameat2(
                    parent_fd,
                    source_path,
                    destination_path,
                    publication_source_fd,
                )
            except _Renameat2Unavailable:
                if capability is not None:
                    raise
                _publish_hardlink(
                    parent_fd,
                    source_path,
                    destination_path,
                    publication_source_fd,
                )
        else:
            _publish_hardlink(
                parent_fd,
                source_path,
                destination_path,
                publication_source_fd,
            )
    except FileExistsError as error:
        primary_error = error
        raise PublicationConflict(
            source_path,
            destination_path,
            "immutable publication destination already exists",
        ) from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        descriptors = (parent_fd,) if source_fd is None else (source_fd, parent_fd)
        _close_all_after(descriptors, primary_error)


def _atomic_write_and_sync_json_exclusive_open(path: Path, data: bytes) -> int:
    candidate = _normalized_absolute_path(path, field_name="manifest temporary path")
    if type(data) is not bytes or not data:
        raise ValueError("manifest bytes must be nonempty bytes")
    parent_fd = _open_directory_no_symlinks(candidate.parent)
    file_fd: int | None = None
    try:
        flags = (
            os.O_CREAT
            | os.O_EXCL
            | os.O_RDWR
            | _required_open_flag("O_NOFOLLOW")
            | _required_open_flag("O_CLOEXEC")
        )
        file_fd = os.open(candidate.name, flags, 0o640, dir_fd=parent_fd)
        os.fsync(parent_fd)
        write_all(file_fd, data)
        os.fsync(file_fd)
    except BaseException as error:
        descriptors = (parent_fd,) if file_fd is None else (file_fd, parent_fd)
        _close_all_after(descriptors, error)
        raise
    assert file_fd is not None
    try:
        _close_all_after((parent_fd,), None)
    except BaseException as error:
        _close_all_after((file_fd,), error)
        raise
    return file_fd


def atomic_write_and_sync_json_exclusive(path: Path, data: bytes) -> None:
    file_fd = _atomic_write_and_sync_json_exclusive_open(path, data)
    _close_all_after((file_fd,), None)


async def run_storage(
    io_limiter: StorageIoLimiter,
    storage_executor: Executor,
    function: Callable[_P, _T],
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _T:
    if type(io_limiter) is not StorageIoLimiter:
        raise TypeError("io_limiter must be StorageIoLimiter")
    if not callable(getattr(storage_executor, "submit", None)):
        raise TypeError("storage_executor must implement Executor.submit")
    if not callable(function):
        raise TypeError("function must be callable")
    loop = asyncio.get_running_loop()
    call = partial(function, *args, **kwargs)
    async with io_limiter.slot():
        return await loop.run_in_executor(storage_executor, call)


_HOUR_NS = 3_600_000_000_000
_CLOSE_TRIGGER = {
    CloseReason.ROTATE_TIME: DurabilityTrigger.HOUR,
    CloseReason.ROTATE_SIZE: DurabilityTrigger.SIZE,
    CloseReason.CONFIG_RELOAD: DurabilityTrigger.CONFIG,
    CloseReason.SHUTDOWN: DurabilityTrigger.SHUTDOWN,
    CloseReason.RECOVERY: DurabilityTrigger.RECOVERY,
}
_CONTROL_KIND_COUNTER = {
    "gap_detected": "gap_count",
    "reconnect": "reconnect_count",
    "parse_error": "parse_error_count",
    "checksum_error": "checksum_error_count",
    "queue_overflow": "queue_overflow_count",
}


def _nonempty(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a normalized nonempty string")
    return value


def _nonnegative(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    return value


def _sha256(value: object, *, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True)
class _RecordClaim:
    identity: AcceptedRecordIdentityV1
    accepted_monotonic_ns: int


@dataclass(frozen=True, slots=True)
class _ClaimedSealedWork:
    claim_id: int
    work: SealedFileWork
    claims: tuple[_RecordClaim, ...]


@dataclass(frozen=True, slots=True)
class _PartSummary:
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
    gap_count: int
    reconnect_count: int
    parse_error_count: int
    checksum_error_count: int
    queue_overflow_count: int
    control_event_ids: tuple[str, ...]
    durability_sample_count: int
    durability_lag_p50_ns: int
    durability_lag_p95_ns: int
    durability_lag_p99_ns: int
    durability_lag_max_ns: int
    sync_count: int
    sync_duration_total_ns: int
    sync_duration_max_ns: int
    slo_breach_count: int
    write_failure_count: int
    sync_failure_count: int


class _PartAccumulator:
    def __init__(
        self,
        first_record: AcceptedRecord,
        first_identity: AcceptedRecordIdentityV1,
        *,
        durability_slo_ns: int,
    ) -> None:
        self._validate_pair(first_record, first_identity)
        envelope = first_record.envelope
        self._exchange = envelope.exchange
        self._market = envelope.market
        self._instrument_key = envelope.instrument_key
        self._logical_stream = envelope.logical_stream
        self._worker_instance_id = envelope.worker_instance_id
        self._config_sha256 = envelope.config_sha256
        self._config_generation = first_identity.config_generation
        self._durability_slo_ns = _nonnegative(
            durability_slo_ns,
            field_name="durability_slo_ns",
        )
        if self._durability_slo_ns == 0:
            raise ValueError("durability_slo_ns must be positive")
        self._wire_symbols: set[str] = set()
        self._connection_generations: set[int] = set()
        self._egress_ids: set[str] = set()
        self._requested_intervals_ns: set[int] = set()
        self._effective_intervals_ns: set[int] = set()
        self._record_count = 0
        self._first_received_at_ns: int | None = None
        self._last_received_at_ns: int | None = None
        self._first_event_time_ns: int | None = None
        self._last_event_time_ns: int | None = None
        self._writer_sequence_first: int | None = None
        self._writer_sequence_last: int | None = None
        self._histogram = CumulativeDurabilityHistogram()
        self._sync_count = 0
        self._sync_duration_total_ns = 0
        self._sync_duration_max_ns = 0
        self._slo_breach_count = 0
        self._write_failure_count = 0
        self._sync_failure_count = 0
        self._gap_count = 0
        self._reconnect_count = 0
        self._parse_error_count = 0
        self._checksum_error_count = 0
        self._queue_overflow_count = 0
        self._control_event_ids: set[str] = set()
        self._frozen = False

    @staticmethod
    def _validate_pair(
        record: AcceptedRecord,
        identity: AcceptedRecordIdentityV1,
    ) -> None:
        if type(record) is not AcceptedRecord:
            raise TypeError("record must be AcceptedRecord")
        if type(identity) is not AcceptedRecordIdentityV1:
            raise TypeError("identity must be AcceptedRecordIdentityV1")
        envelope = record.envelope
        observed = (
            identity.exchange,
            identity.market,
            identity.instrument_key,
            identity.logical_stream,
            identity.worker_instance_id,
            identity.writer_sequence,
            identity.config_sha256,
        )
        expected = (
            envelope.exchange,
            envelope.market,
            envelope.instrument_key,
            envelope.logical_stream,
            envelope.worker_instance_id,
            envelope.writer_sequence,
            envelope.config_sha256,
        )
        if observed != expected:
            raise ValueError("accepted identity does not match its record")

    def validate_record(
        self,
        record: AcceptedRecord,
        identity: AcceptedRecordIdentityV1,
    ) -> None:
        if self._frozen:
            raise ValueError("part accumulator is frozen")
        self._validate_pair(record, identity)
        envelope = record.envelope
        expected = (
            self._exchange,
            self._market,
            self._instrument_key,
            self._logical_stream,
            self._worker_instance_id,
            self._config_sha256,
            self._config_generation,
        )
        observed = (
            envelope.exchange,
            envelope.market,
            envelope.instrument_key,
            envelope.logical_stream,
            envelope.worker_instance_id,
            envelope.config_sha256,
            identity.config_generation,
        )
        if observed != expected:
            raise ValueError("record does not belong to this raw part")
        if (
            self._writer_sequence_last is not None
            and envelope.writer_sequence <= self._writer_sequence_last
        ):
            raise ValueError("part writer sequences must be strictly increasing")

    def append_validated(self, record: AcceptedRecord) -> None:
        envelope = record.envelope
        if envelope.wire_symbol is not None:
            self._wire_symbols.add(envelope.wire_symbol)
        if envelope.connection_generation is not None:
            self._connection_generations.add(envelope.connection_generation)
        if envelope.egress_id is not None:
            self._egress_ids.add(envelope.egress_id)
        metadata = envelope.rest_metadata
        if metadata is not None and metadata.requested_interval_ns is not None:
            assert metadata.effective_interval_ns is not None
            self._requested_intervals_ns.add(metadata.requested_interval_ns)
            self._effective_intervals_ns.add(metadata.effective_interval_ns)
        if self._record_count == 0:
            self._first_received_at_ns = envelope.received_at_ns
            self._writer_sequence_first = envelope.writer_sequence
        self._last_received_at_ns = envelope.received_at_ns
        self._writer_sequence_last = envelope.writer_sequence
        if envelope.event_time_ns is not None:
            if self._first_event_time_ns is None:
                self._first_event_time_ns = envelope.event_time_ns
            self._last_event_time_ns = envelope.event_time_ns
        self._record_count += 1

    @property
    def record_count(self) -> int:
        return self._record_count

    @property
    def durability_sample_count(self) -> int:
        return self._histogram.snapshot().sample_count

    @property
    def logical_stream(self) -> str:
        return self._logical_stream

    def apply_completion(
        self,
        result: FileDurabilityResult,
        claims: tuple[_RecordClaim, ...],
    ) -> None:
        if self._frozen:
            raise ValueError("part accumulator is frozen")
        if result.record_count != len(claims) or result.was_dirty != bool(claims):
            raise ValueError("completion record count does not match its claims")
        completed_ns = result.sync_completed_monotonic_ns
        if completed_ns is None:
            raise ValueError("final sync completion requires a completion time")
        batch_histogram = CumulativeDurabilityHistogram()
        lags: list[int] = []
        for claim in claims:
            if completed_ns < claim.accepted_monotonic_ns:
                raise ValueError("sync completion precedes record acceptance")
            lag_ns = completed_ns - claim.accepted_monotonic_ns
            batch_histogram.add(lag_ns)
            lags.append(lag_ns)
        batch = batch_histogram.snapshot()
        observed = (
            result.lag_p50_ns,
            result.lag_p95_ns,
            result.lag_p99_ns,
            result.lag_max_ns,
        )
        expected = (
            batch.lag_p50_ns,
            batch.lag_p95_ns,
            batch.lag_p99_ns,
            batch.lag_max_ns,
        )
        if observed != expected:
            raise ValueError("completion durability statistics do not match claims")
        for lag_ns in lags:
            self._histogram.add(lag_ns)
            if lag_ns > self._durability_slo_ns:
                self._slo_breach_count += 1
        self._sync_count += 1
        self._sync_duration_total_ns += result.sync_duration_ns
        self._sync_duration_max_ns = max(
            self._sync_duration_max_ns,
            result.sync_duration_ns,
        )

    def apply_failure(self, error: BaseException) -> None:
        if isinstance(error, FilePersistenceError):
            if error.reason is WriterCriticalReason.WRITE_FAILED:
                self._write_failure_count += 1
            else:
                self._sync_failure_count += 1
        else:
            self._sync_failure_count += 1

    def validate_durable_control(
        self,
        association: StorageControlAssociationV1,
        *,
        generation_id: str,
        data_relative_path: str,
    ) -> None:
        if self._frozen:
            raise ValueError("part accumulator is frozen")
        if type(association) is not StorageControlAssociationV1:
            raise TypeError("association must be StorageControlAssociationV1")
        expected_target = (generation_id, data_relative_path)
        matching_targets = tuple(
            target
            for target in association.targets
            if (target.generation_id, target.data_relative_path) == expected_target
        )
        if len(matching_targets) != 1:
            raise ValueError("durable control does not target this exact raw part")
        if association.control_event_id in self._control_event_ids:
            raise ValueError("durable control association was already folded")

    def fold_durable_control(
        self,
        association: StorageControlAssociationV1,
        *,
        generation_id: str,
        data_relative_path: str,
    ) -> None:
        self.validate_durable_control(
            association,
            generation_id=generation_id,
            data_relative_path=data_relative_path,
        )
        counter_name = _CONTROL_KIND_COUNTER.get(association.control_kind)
        if counter_name is not None:
            setattr(self, f"_{counter_name}", getattr(self, f"_{counter_name}") + 1)
        self._control_event_ids.add(association.control_event_id)

    def freeze(self) -> _PartSummary:
        if self._frozen:
            raise ValueError("part accumulator is already frozen")
        if self._record_count == 0:
            raise ValueError("empty raw parts cannot be frozen")
        durability = self._histogram.snapshot()
        if durability.sample_count != self._record_count:
            raise ValueError("not every raw record is durable")
        if self._write_failure_count or self._sync_failure_count:
            raise ValueError("failed raw parts cannot publish normal manifests")
        assert self._first_received_at_ns is not None
        assert self._last_received_at_ns is not None
        assert self._writer_sequence_first is not None
        assert self._writer_sequence_last is not None
        assert durability.lag_p50_ns is not None
        assert durability.lag_p95_ns is not None
        assert durability.lag_p99_ns is not None
        assert durability.lag_max_ns is not None
        self._frozen = True
        return _PartSummary(
            exchange=self._exchange,
            market=self._market,
            instrument_key=self._instrument_key,
            logical_stream=self._logical_stream,
            wire_symbols=tuple(sorted(self._wire_symbols)),
            record_count=self._record_count,
            first_received_at_ns=self._first_received_at_ns,
            last_received_at_ns=self._last_received_at_ns,
            first_event_time_ns=self._first_event_time_ns,
            last_event_time_ns=self._last_event_time_ns,
            worker_instance_id=self._worker_instance_id,
            connection_generations=tuple(sorted(self._connection_generations)),
            writer_sequence_first=self._writer_sequence_first,
            writer_sequence_last=self._writer_sequence_last,
            config_sha256=self._config_sha256,
            egress_ids=tuple(sorted(self._egress_ids)),
            requested_intervals_ns=tuple(sorted(self._requested_intervals_ns)),
            effective_intervals_ns=tuple(sorted(self._effective_intervals_ns)),
            gap_count=self._gap_count,
            reconnect_count=self._reconnect_count,
            parse_error_count=self._parse_error_count,
            checksum_error_count=self._checksum_error_count,
            queue_overflow_count=self._queue_overflow_count,
            control_event_ids=tuple(sorted(self._control_event_ids)),
            durability_sample_count=durability.sample_count,
            durability_lag_p50_ns=durability.lag_p50_ns,
            durability_lag_p95_ns=durability.lag_p95_ns,
            durability_lag_p99_ns=durability.lag_p99_ns,
            durability_lag_max_ns=durability.lag_max_ns,
            sync_count=self._sync_count,
            sync_duration_total_ns=self._sync_duration_total_ns,
            sync_duration_max_ns=self._sync_duration_max_ns,
            slo_breach_count=self._slo_breach_count,
            write_failure_count=self._write_failure_count,
            sync_failure_count=self._sync_failure_count,
        )


class _ActivePart:
    def __init__(
        self,
        *,
        data_root: Path,
        stream_file: StreamFile,
        first_record: AcceptedRecord,
        first_identity: AcceptedRecordIdentityV1,
        part_start_ns: int,
        part_sequence: int,
        durability_slo_ns: int,
    ) -> None:
        self.data_root = data_root
        self.stream_file = stream_file
        self.partial_path = stream_file.path
        self.closed_data_path = Path(str(self.partial_path).removesuffix(".partial"))
        self.closed_manifest_path = manifest_path_for_data(self.closed_data_path)
        self.manifest_partial_path = Path(str(self.closed_manifest_path) + ".partial")
        self.data_relative_path = self.closed_data_path.relative_to(
            data_root
        ).as_posix()
        self.manifest_relative_path = self.closed_manifest_path.relative_to(
            data_root
        ).as_posix()
        self.part_start_ns = part_start_ns
        self.part_sequence = part_sequence
        self.created_at_ns = first_record.envelope.received_at_ns
        self.received_hour = first_record.envelope.received_at_ns // _HOUR_NS
        self.config_sha256 = first_record.envelope.config_sha256
        self.config_generation = first_identity.config_generation
        self._accumulator = _PartAccumulator(
            first_record,
            first_identity,
            durability_slo_ns=durability_slo_ns,
        )
        self._pending_claims: list[_RecordClaim] = []
        self._claimed: dict[int, _ClaimedSealedWork] = {}
        self._batch_task_by_claim_id: dict[
            int,
            asyncio.Task[DurabilityBatch],
        ] = {}
        self._next_claim_id = 0
        self.close_reason: CloseReason | None = None
        self.closed_at_ns: int | None = None

    @classmethod
    def allocate(
        cls,
        *,
        data_root: Path,
        first_record: AcceptedRecord,
        first_identity: AcceptedRecordIdentityV1,
        generation_id: str,
        part_start_ns: int,
        part_sequence: int,
        zstd_level: int,
        max_plain_frame_bytes: int,
        durability_slo_ns: int,
    ) -> _ActivePart:
        root = Path(os.path.abspath(os.fspath(data_root)))
        generation = _nonempty(generation_id, field_name="generation_id")
        path = raw_partial_path(
            root,
            first_record.envelope,
            part_start_ns=part_start_ns,
            sequence=part_sequence,
        )
        stream = StreamFile.allocate(
            path,
            generation_id=generation,
            zstd_level=zstd_level,
            max_plain_frame_bytes=max_plain_frame_bytes,
        )
        try:
            return cls(
                data_root=root,
                stream_file=stream,
                first_record=first_record,
                first_identity=first_identity,
                part_start_ns=part_start_ns,
                part_sequence=part_sequence,
                durability_slo_ns=durability_slo_ns,
            )
        except BaseException:
            stream.close_fd()
            raise

    @property
    def generation_id(self) -> str:
        return self.stream_file.generation_id

    @property
    def record_count(self) -> int:
        return self._accumulator.record_count

    @property
    def durability_sample_count(self) -> int:
        return self._accumulator.durability_sample_count

    @property
    def logical_stream(self) -> str:
        return self._accumulator.logical_stream

    def append_accepted(
        self,
        record: AcceptedRecord,
        identity: AcceptedRecordIdentityV1,
    ) -> None:
        if self.close_reason is not None:
            raise ValueError("retired raw parts cannot accept records")
        self._accumulator.validate_record(record, identity)
        self.stream_file.append(
            record.encoded_jsonl,
            accepted_monotonic_ns=record.accepted_monotonic_ns,
        )
        self._accumulator.append_validated(record)
        self._pending_claims.append(
            _RecordClaim(identity, record.accepted_monotonic_ns)
        )

    def seal_for_sync(self, *, force_sync: bool = False) -> _ClaimedSealedWork | None:
        if self._claimed:
            raise ValueError("raw part already has sync work in flight")
        work = self.stream_file.seal_for_sync(force_sync=force_sync)
        if work is None:
            return None
        claims = tuple(self._pending_claims)
        pending_count = 0 if work.pending is None else len(work.pending.rows)
        if pending_count != len(claims):
            raise AssertionError("sealed rows and durability claims diverged")
        self._pending_claims.clear()
        claim_id = self._next_claim_id
        self._next_claim_id += 1
        claimed = _ClaimedSealedWork(claim_id, work, claims)
        self._claimed[claim_id] = claimed
        return claimed

    def _require_owned_claim(self, claimed: _ClaimedSealedWork) -> None:
        if type(claimed) is not _ClaimedSealedWork:
            raise TypeError("claimed work must be _ClaimedSealedWork")
        if self._claimed.get(claimed.claim_id) is not claimed:
            raise ValueError("claimed work is not owned by this raw part")

    def apply_completion(
        self,
        claimed: _ClaimedSealedWork,
        result: FileDurabilityResult,
    ) -> None:
        self._require_owned_claim(claimed)
        if result.generation_id != self.generation_id:
            raise ValueError("completion generation does not match raw part")
        self._accumulator.apply_completion(result, claimed.claims)
        del self._claimed[claimed.claim_id]
        self._batch_task_by_claim_id.pop(claimed.claim_id, None)

    def apply_failure(
        self,
        claimed: _ClaimedSealedWork,
        error: BaseException,
    ) -> None:
        self._require_owned_claim(claimed)
        self._accumulator.apply_failure(error)
        del self._claimed[claimed.claim_id]
        self._batch_task_by_claim_id.pop(claimed.claim_id, None)

    def validate_retirement(
        self,
        reason: CloseReason,
        *,
        closed_at_ns: int,
    ) -> int:
        if type(reason) is not CloseReason or reason is CloseReason.RECOVERY:
            raise ValueError("active parts require a normal close reason")
        closed = _nonnegative(closed_at_ns, field_name="closed_at_ns")
        if self.close_reason is not None and (
            self.close_reason is not reason or self.closed_at_ns != closed
        ):
            raise ValueError("raw part was already retired with different facts")
        return closed

    def validate_final_barrier(
        self,
        reason: CloseReason,
        *,
        closed_at_ns: int,
    ) -> None:
        self.validate_retirement(
            reason,
            closed_at_ns=(
                closed_at_ns if self.closed_at_ns is None else self.closed_at_ns
            ),
        )
        if self.close_reason is not None and self.close_reason is not reason:
            raise ValueError("retired raw part close reason does not match the barrier")
        if self.stream_file.closed:
            raise ValueError("closed raw files cannot enter a final barrier")
        if self.record_count == 0:
            raise ValueError("empty raw parts cannot enter a final barrier")

    def retire(self, reason: CloseReason, *, closed_at_ns: int) -> None:
        closed = self.validate_retirement(reason, closed_at_ns=closed_at_ns)
        if self.close_reason is not None:
            return
        self.close_reason = reason
        self.closed_at_ns = closed

    def freeze_summary(self) -> _PartSummary:
        if self._pending_claims or self._claimed:
            raise ValueError("raw part still owns unsettled durability claims")
        return self._accumulator.freeze()

    def in_flight_claim(self) -> _ClaimedSealedWork | None:
        if len(self._claimed) > 1:
            raise AssertionError("raw part owns more than one in-flight claim")
        return next(iter(self._claimed.values()), None)

    def bind_claim_batch_task(
        self,
        claimed: _ClaimedSealedWork,
        batch_task: asyncio.Task[DurabilityBatch],
    ) -> None:
        self._require_owned_claim(claimed)
        if not isinstance(batch_task, asyncio.Task):
            raise TypeError("claim batch task must be asyncio.Task")
        if claimed.claim_id in self._batch_task_by_claim_id:
            raise ValueError("claimed work already has a batch settlement task")
        self._batch_task_by_claim_id[claimed.claim_id] = batch_task

    def claim_batch_task(
        self,
        claimed: _ClaimedSealedWork,
    ) -> asyncio.Task[DurabilityBatch] | None:
        self._require_owned_claim(claimed)
        return self._batch_task_by_claim_id.get(claimed.claim_id)

    def locate_control_identity(
        self,
        identity: AcceptedRecordIdentityV1,
    ) -> _ClaimedSealedWork | None:
        if type(identity) is not AcceptedRecordIdentityV1:
            raise TypeError("control identity must be AcceptedRecordIdentityV1")
        if self.logical_stream != "_control" or identity.logical_stream != "_control":
            raise ValueError("control dependencies require _control identities")
        pending_matches = tuple(
            claim for claim in self._pending_claims if claim.identity == identity
        )
        claimed_matches = tuple(
            claimed
            for claimed in self._claimed.values()
            if any(claim.identity == identity for claim in claimed.claims)
        )
        if len(pending_matches) + len(claimed_matches) != 1:
            raise ValueError(
                "control dependency identity must be exactly one owned claim"
            )
        if claimed_matches:
            return claimed_matches[0]
        return None

    def validate_pending_control_identity(
        self,
        identity: AcceptedRecordIdentityV1,
    ) -> None:
        if self.locate_control_identity(identity) is not None or self._claimed:
            raise ValueError("pending control work is blocked by an in-flight claim")

    def validate_durable_control(
        self,
        association: StorageControlAssociationV1,
    ) -> None:
        self._accumulator.validate_durable_control(
            association,
            generation_id=self.generation_id,
            data_relative_path=self.data_relative_path,
        )

    def fold_durable_control(
        self,
        association: StorageControlAssociationV1,
    ) -> None:
        self._accumulator.fold_durable_control(
            association,
            generation_id=self.generation_id,
            data_relative_path=self.data_relative_path,
        )

    def build_manifest(
        self,
        summary: _PartSummary,
        *,
        file_size_bytes: int,
        file_sha256: str,
    ) -> RawManifestV1:
        if self.close_reason is None or self.closed_at_ns is None:
            raise ValueError("raw part must be retired before manifest construction")
        return RawManifestV1(
            schema_version=1,
            exchange=summary.exchange,
            market=summary.market,
            instrument_key=summary.instrument_key,
            logical_stream=summary.logical_stream,
            wire_symbols=summary.wire_symbols,
            data_relative_path=self.data_relative_path,
            manifest_relative_path=self.manifest_relative_path,
            file_size_bytes=file_size_bytes,
            file_sha256=file_sha256,
            zstd_level=self.stream_file.zstd_level,
            zstd_write_checksum=True,
            zstd_write_content_size=True,
            max_plain_frame_bytes=self.stream_file.max_plain_frame_bytes,
            record_count=summary.record_count,
            first_received_at_ns=summary.first_received_at_ns,
            last_received_at_ns=summary.last_received_at_ns,
            first_event_time_ns=summary.first_event_time_ns,
            last_event_time_ns=summary.last_event_time_ns,
            worker_instance_id=summary.worker_instance_id,
            connection_generations=summary.connection_generations,
            writer_sequence_first=summary.writer_sequence_first,
            writer_sequence_last=summary.writer_sequence_last,
            config_sha256=summary.config_sha256,
            egress_ids=summary.egress_ids,
            requested_intervals_ns=summary.requested_intervals_ns,
            effective_intervals_ns=summary.effective_intervals_ns,
            gap_count=summary.gap_count,
            reconnect_count=summary.reconnect_count,
            parse_error_count=summary.parse_error_count,
            checksum_error_count=summary.checksum_error_count,
            queue_overflow_count=summary.queue_overflow_count,
            control_event_ids=summary.control_event_ids,
            durability_measurement="measured",
            durability_sample_count=summary.durability_sample_count,
            durability_lag_p50_ns=summary.durability_lag_p50_ns,
            durability_lag_p95_ns=summary.durability_lag_p95_ns,
            durability_lag_p99_ns=summary.durability_lag_p99_ns,
            durability_lag_max_ns=summary.durability_lag_max_ns,
            sync_count=summary.sync_count,
            sync_duration_total_ns=summary.sync_duration_total_ns,
            sync_duration_max_ns=summary.sync_duration_max_ns,
            slo_breach_count=summary.slo_breach_count,
            write_failure_count=summary.write_failure_count,
            sync_failure_count=summary.sync_failure_count,
            close_reason=self.close_reason,
            created_at_ns=self.created_at_ns,
            closed_at_ns=self.closed_at_ns,
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

    def close_fd_for_test(self) -> None:
        self.stream_file.close_fd()


_LogicalPartKey = tuple[Market | None, str | None, str]


class _ActivePartSet:
    def __init__(
        self,
        *,
        data_root: Path,
        exchange: Exchange,
        config_sha256: str,
        config_generation: int,
        zstd_level: int,
        max_plain_frame_bytes: int,
        max_compressed_size_bytes: int,
        rotate_interval_ns: int,
        durability_slo_ns: int,
    ) -> None:
        if type(exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        self._data_root = Path(os.path.abspath(os.fspath(data_root)))
        self._exchange = exchange
        self._config_sha256 = _sha256(config_sha256, field_name="config_sha256")
        self._config_generation = _nonnegative(
            config_generation,
            field_name="config_generation",
        )
        self._zstd_level = _nonnegative(zstd_level, field_name="zstd_level")
        self._max_plain_frame_bytes = _nonnegative(
            max_plain_frame_bytes,
            field_name="max_plain_frame_bytes",
        )
        self._max_compressed_size_bytes = _nonnegative(
            max_compressed_size_bytes,
            field_name="max_compressed_size_bytes",
        )
        self._rotate_interval_ns = _nonnegative(
            rotate_interval_ns,
            field_name="rotate_interval_ns",
        )
        self._durability_slo_ns = _nonnegative(
            durability_slo_ns,
            field_name="durability_slo_ns",
        )
        if any(
            value == 0
            for value in (
                self._zstd_level,
                self._max_plain_frame_bytes,
                self._max_compressed_size_bytes,
                self._rotate_interval_ns,
                self._durability_slo_ns,
            )
        ):
            raise ValueError("raw part limits must be positive")
        self._active: dict[_LogicalPartKey, _ActivePart] = {}
        self._next_part_sequence = 0

    @staticmethod
    def _key(envelope: RawEnvelope) -> _LogicalPartKey:
        return envelope.market, envelope.instrument_key, envelope.logical_stream

    def _allocate(
        self,
        record: AcceptedRecord,
        identity: AcceptedRecordIdentityV1,
    ) -> _ActivePart:
        sequence = self._next_part_sequence
        self._next_part_sequence += 1
        received_hour_start = (record.envelope.received_at_ns // _HOUR_NS) * _HOUR_NS
        return _ActivePart.allocate(
            data_root=self._data_root,
            first_record=record,
            first_identity=identity,
            generation_id=str(uuid.uuid4()),
            part_start_ns=received_hour_start,
            part_sequence=sequence,
            zstd_level=self._zstd_level,
            max_plain_frame_bytes=self._max_plain_frame_bytes,
            durability_slo_ns=self._durability_slo_ns,
        )

    def _validate_current_config(
        self,
        record: AcceptedRecord,
        identity: AcceptedRecordIdentityV1,
    ) -> None:
        if record.envelope.exchange is not self._exchange:
            raise ValueError("record exchange does not match active part set")
        if (
            record.envelope.config_sha256 != self._config_sha256
            or identity.config_sha256 != self._config_sha256
            or identity.config_generation != self._config_generation
        ):
            raise ValueError("record config does not match active part set")

    def append_accepted(
        self,
        record: AcceptedRecord,
        identity: AcceptedRecordIdentityV1,
    ) -> tuple[_ActivePart, ...]:
        self._validate_current_config(record, identity)
        key = self._key(record.envelope)
        part = self._active.get(key)
        retired: tuple[_ActivePart, ...] = ()
        received_hour = record.envelope.received_at_ns // _HOUR_NS
        if part is not None and part.received_hour != received_hour:
            part.validate_retirement(
                CloseReason.ROTATE_TIME,
                closed_at_ns=record.envelope.received_at_ns,
            )
            replacement = self._allocate(record, identity)
            try:
                replacement.append_accepted(record, identity)
            except BaseException:
                replacement.close_fd_for_test()
                raise
            part.retire(
                CloseReason.ROTATE_TIME,
                closed_at_ns=record.envelope.received_at_ns,
            )
            retired = (part,)
            self._active[key] = replacement
            return retired
        if part is None:
            part = self._allocate(record, identity)
            self._active[key] = part
        part.append_accepted(record, identity)
        return retired

    def detach_all(
        self,
        reason: CloseReason,
        *,
        closed_at_ns: int,
    ) -> tuple[_ActivePart, ...]:
        closed = _nonnegative(closed_at_ns, field_name="closed_at_ns")
        parts = tuple(
            sorted(self._active.values(), key=lambda item: item.data_relative_path)
        )
        for part in parts:
            part.validate_retirement(reason, closed_at_ns=closed)
        for part in parts:
            part.retire(reason, closed_at_ns=closed)
        self._active.clear()
        return parts

    def rotate_for_config(
        self,
        config_sha256: str,
        *,
        config_generation: int,
        closed_at_ns: int,
    ) -> tuple[_ActivePart, ...]:
        next_sha256 = _sha256(config_sha256, field_name="config_sha256")
        next_generation = _nonnegative(
            config_generation,
            field_name="config_generation",
        )
        if next_generation <= self._config_generation:
            raise ValueError("config_generation must be strictly greater")
        retired = self.detach_all(
            CloseReason.CONFIG_RELOAD,
            closed_at_ns=closed_at_ns,
        )
        self._config_sha256 = next_sha256
        self._config_generation = next_generation
        return retired

    def detach_size_due(self, *, closed_at_ns: int) -> tuple[_ActivePart, ...]:
        closed = _nonnegative(closed_at_ns, field_name="closed_at_ns")
        due_keys = tuple(
            key
            for key, part in self._active.items()
            if part.stream_file.compressed_size >= self._max_compressed_size_bytes
        )
        due = [self._active[key] for key in due_keys]
        for part in due:
            part.validate_retirement(CloseReason.ROTATE_SIZE, closed_at_ns=closed)
        for part in due:
            part.retire(CloseReason.ROTATE_SIZE, closed_at_ns=closed)
        for key in due_keys:
            del self._active[key]
        return tuple(sorted(due, key=lambda item: item.data_relative_path))

    def detach_interval_due(self, *, now_ns: int) -> tuple[_ActivePart, ...]:
        now = _nonnegative(now_ns, field_name="now_ns")
        due_keys = tuple(
            key
            for key, part in self._active.items()
            if now - part.created_at_ns >= self._rotate_interval_ns
        )
        due = [self._active[key] for key in due_keys]
        for part in due:
            part.validate_retirement(CloseReason.ROTATE_TIME, closed_at_ns=now)
        for part in due:
            part.retire(CloseReason.ROTATE_TIME, closed_at_ns=now)
        for key in due_keys:
            del self._active[key]
        return tuple(sorted(due, key=lambda item: item.data_relative_path))


class _DurabilityCoordinator(Protocol):
    async def sync_batch(
        self,
        work_items: Sequence[SealedFileWork],
        *,
        trigger: DurabilityTrigger,
    ) -> DurabilityBatch: ...


class _PublishNoReplace(Protocol):
    def __call__(
        self,
        source: Path,
        destination: Path,
        *,
        capability: NoReplaceCapability | None = None,
        expected_source_fd: int | None = None,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class _FinalBarrierBatchSettled:
    command_id: str
    batch: DurabilityBatch | None
    error: BaseException | None

    def __post_init__(self) -> None:
        _nonempty(self.command_id, field_name="command_id")
        if (self.batch is None) == (self.error is None):
            raise ValueError("batch settlement requires exactly one outcome")
        if self.batch is not None and type(self.batch) is not DurabilityBatch:
            raise TypeError("batch settlement batch must be DurabilityBatch")
        if self.error is not None and not isinstance(self.error, BaseException):
            raise TypeError("batch settlement error must be BaseException")


@dataclass(frozen=True, slots=True)
class _FinalBarrierPrerequisiteBatchSettled:
    command_id: str
    batch_task: asyncio.Task[DurabilityBatch]
    batch: DurabilityBatch | None
    error: BaseException | None

    def __post_init__(self) -> None:
        _nonempty(self.command_id, field_name="command_id")
        if not isinstance(self.batch_task, asyncio.Task):
            raise TypeError("prerequisite batch task must be asyncio.Task")
        if (self.batch is None) == (self.error is None):
            raise ValueError(
                "prerequisite batch settlement requires exactly one outcome"
            )
        if self.batch is not None and type(self.batch) is not DurabilityBatch:
            raise TypeError("prerequisite batch must be DurabilityBatch")
        if self.error is not None and not isinstance(self.error, BaseException):
            raise TypeError("prerequisite batch error must be BaseException")


@dataclass(frozen=True, slots=True)
class _FinalBarrierPublicationSettled:
    command_id: str
    manifests: tuple[RawManifestV1, ...] | None
    error: BaseException | None

    def __post_init__(self) -> None:
        _nonempty(self.command_id, field_name="command_id")
        if (self.manifests is None) == (self.error is None):
            raise ValueError("publication settlement requires exactly one outcome")
        if self.manifests is not None and any(
            type(item) is not RawManifestV1 for item in self.manifests
        ):
            raise TypeError("publication manifests must contain RawManifestV1 values")
        if self.error is not None and not isinstance(self.error, BaseException):
            raise TypeError("publication error must be BaseException")


@dataclass(frozen=True, slots=True)
class _FinalBarrierControlDependency:
    control_part: _ActivePart
    control_identity: AcceptedRecordIdentityV1
    association: StorageControlAssociationV1
    targets: tuple[_ActivePart, ...]

    def __post_init__(self) -> None:
        if type(self.control_part) is not _ActivePart:
            raise TypeError("control_part must be _ActivePart")
        if type(self.control_identity) is not AcceptedRecordIdentityV1:
            raise TypeError("control_identity must be AcceptedRecordIdentityV1")
        if type(self.association) is not StorageControlAssociationV1:
            raise TypeError("association must be StorageControlAssociationV1")
        if type(self.targets) is not tuple or not self.targets:
            raise ValueError("control dependency targets must be a nonempty tuple")
        if any(type(target) is not _ActivePart for target in self.targets):
            raise TypeError(
                "control dependency targets must contain _ActivePart values"
            )
        identity = self.control_identity
        if (
            identity.logical_stream != "_control"
            or identity.market is not None
            or identity.instrument_key is not None
        ):
            raise ValueError("control dependency identity must be exchange-scoped")
        if (
            self.association.acceptance_ordinal != identity.acceptance_ordinal
            or self.association.config_generation != identity.config_generation
        ):
            raise ValueError("control association does not match its accepted identity")
        expected_targets = tuple(
            (target.generation_id, target.data_relative_path) for target in self.targets
        )
        association_targets = tuple(
            (target.generation_id, target.data_relative_path)
            for target in self.association.targets
        )
        if association_targets != expected_targets:
            raise ValueError("control dependency targets must match the association")


@dataclass(slots=True)
class _FinalBarrierCommandState:
    command_id: str
    parts: tuple[_ActivePart, ...]
    work_parts: tuple[_ActivePart, ...]
    trigger: DurabilityTrigger
    claims_by_generation: dict[str, tuple[_ActivePart, _ClaimedSealedWork]]
    batch_generation_ids: tuple[str, ...]
    control_dependencies_by_generation: dict[
        str,
        tuple[_FinalBarrierControlDependency, ...],
    ]
    control_generation_ids: tuple[str, ...]
    remaining_generation_ids: set[str]
    result_future: asyncio.Future[tuple[RawManifestV1, ...]]
    prerequisite_claims_by_generation: dict[
        str,
        tuple[_ActivePart, _ClaimedSealedWork],
    ] = field(default_factory=dict)
    prerequisite_generations_by_batch_task: dict[
        asyncio.Task[DurabilityBatch],
        tuple[str, ...],
    ] = field(default_factory=dict)
    remaining_prerequisite_generation_ids: set[str] = field(default_factory=set)
    batch_task: asyncio.Task[DurabilityBatch] | None = None
    batch_settled: bool = False
    batch: DurabilityBatch | None = None
    batch_error: BaseException | None = None
    file_errors: dict[str, BaseException] = field(default_factory=dict)
    publication_task: asyncio.Task[tuple[RawManifestV1, ...]] | None = None


class _FinalBarrierController:
    def __init__(
        self,
        *,
        durability_coordinator: _DurabilityCoordinator,
        completion_queue: asyncio.Queue[object],
        io_limiter: StorageIoLimiter,
        storage_executor: Executor,
        no_replace_capability: NoReplaceCapability,
        publication_function: _PublishNoReplace = publish_no_replace,
    ) -> None:
        if not callable(getattr(durability_coordinator, "sync_batch", None)):
            raise TypeError("durability_coordinator must implement sync_batch")
        if type(completion_queue) is not asyncio.Queue:
            raise TypeError("completion_queue must be asyncio.Queue")
        if completion_queue.maxsize > 0:
            raise ValueError("completion_queue must be unbounded and non-raising")
        if type(io_limiter) is not StorageIoLimiter:
            raise TypeError("io_limiter must be StorageIoLimiter")
        if not callable(getattr(storage_executor, "submit", None)):
            raise TypeError("storage_executor must implement Executor.submit")
        if type(no_replace_capability) is not NoReplaceCapability:
            raise TypeError("no_replace_capability must be NoReplaceCapability")
        if not callable(publication_function):
            raise TypeError("publication_function must be callable")
        self._coordinator = durability_coordinator
        self._io_limiter = io_limiter
        self._storage_executor = storage_executor
        self._no_replace_capability = no_replace_capability
        self._publication_function = publication_function
        self._message_sink = completion_queue.put_nowait
        self._commands: dict[str, _FinalBarrierCommandState] = {}
        self._command_by_generation: dict[str, str] = {}
        self._detached_futures: set[asyncio.Future[tuple[RawManifestV1, ...]]] = set()

    async def _publish_one(
        self,
        part: _ActivePart,
        summary: _PartSummary,
    ) -> RawManifestV1:
        verification_fd = await run_storage(
            self._io_limiter,
            self._storage_executor,
            _open_bound_readonly_and_close,
            part.stream_file,
        )
        manifest_primary_error: BaseException | None = None
        try:
            await run_storage(
                self._io_limiter,
                self._storage_executor,
                self._publication_function,
                part.partial_path,
                part.closed_data_path,
                capability=self._no_replace_capability,
                expected_source_fd=verification_fd,
            )
            await run_storage(
                self._io_limiter,
                self._storage_executor,
                require_path_is_open_inode,
                part.closed_data_path,
                verification_fd,
            )
            file_size, file_sha256 = await run_storage(
                self._io_limiter,
                self._storage_executor,
                size_and_sha256_fd,
                verification_fd,
            )
        except BaseException as error:
            manifest_primary_error = error
            raise
        finally:
            try:
                await run_storage(
                    self._io_limiter,
                    self._storage_executor,
                    os.close,
                    verification_fd,
                )
            except BaseException:
                if manifest_primary_error is None:
                    raise
        manifest = part.build_manifest(
            summary,
            file_size_bytes=file_size,
            file_sha256=file_sha256,
        )
        manifest_fd = await run_storage(
            self._io_limiter,
            self._storage_executor,
            _atomic_write_and_sync_json_exclusive_open,
            part.manifest_partial_path,
            manifest.canonical_bytes(),
        )
        primary_error: BaseException | None = None
        try:
            await run_storage(
                self._io_limiter,
                self._storage_executor,
                self._publication_function,
                part.manifest_partial_path,
                part.closed_manifest_path,
                capability=self._no_replace_capability,
                expected_source_fd=manifest_fd,
            )
        except BaseException as error:
            primary_error = error
            raise
        finally:
            try:
                await run_storage(
                    self._io_limiter,
                    self._storage_executor,
                    os.close,
                    manifest_fd,
                )
            except BaseException:
                if primary_error is None:
                    raise
        return manifest

    async def _publish_group(
        self,
        parts: tuple[_ActivePart, ...],
        summaries: tuple[_PartSummary, ...],
    ) -> tuple[RawManifestV1, ...]:
        manifests: list[RawManifestV1] = []
        for index, (part, summary) in enumerate(zip(parts, summaries, strict=True)):
            try:
                manifests.append(await self._publish_one(part, summary))
            except BaseException as error:
                try:
                    await self._close_parts(parts[index:])
                except BaseException as cleanup_error:
                    raise WriterCriticalError(
                        reason=WriterCriticalReason.PUBLICATION_FAILED,
                        affected_generation_ids=tuple(
                            item.generation_id for item in parts[index:]
                        ),
                        completed_batches=(),
                        message="raw publication failure cleanup failed",
                    ) from cleanup_error
                raise WriterCriticalError(
                    reason=WriterCriticalReason.PUBLICATION_FAILED,
                    affected_generation_ids=tuple(
                        item.generation_id for item in parts[index:]
                    ),
                    completed_batches=(),
                    message="raw immutable publication failed",
                ) from error
        return tuple(manifests)

    async def _close_parts(self, parts: tuple[_ActivePart, ...]) -> None:
        first_error: BaseException | None = None
        for part in parts:
            if part.stream_file.closed:
                continue
            try:
                await run_storage(
                    self._io_limiter,
                    self._storage_executor,
                    part.stream_file.close_fd,
                )
            except BaseException as error:  # noqa: BLE001 - close every owned FD
                if first_error is None:
                    first_error = error
        if first_error is not None:
            raise first_error

    async def _close_then_raise(
        self,
        parts: tuple[_ActivePart, ...],
        terminal_error: BaseException,
    ) -> tuple[RawManifestV1, ...]:
        try:
            await self._close_parts(parts)
        except BaseException as cleanup_error:
            terminal_error.add_note("raw failed-barrier descriptor cleanup also failed")
            raise terminal_error from cleanup_error
        raise terminal_error

    def _start_failure_cleanup(
        self,
        command: _FinalBarrierCommandState,
        error: BaseException,
    ) -> None:
        coroutine = self._close_then_raise(command.parts, error)
        try:
            cleanup_task = asyncio.create_task(coroutine)
        except BaseException:
            coroutine.close()
            raise
        command.publication_task = cleanup_task
        cleanup_task.add_done_callback(
            partial(self._post_publication_settled, command.command_id)
        )

    def _post_batch_settled(
        self,
        command_id: str,
        task: asyncio.Task[DurabilityBatch],
    ) -> None:
        try:
            message = _FinalBarrierBatchSettled(
                command_id=command_id,
                batch=task.result(),
                error=None,
            )
        except BaseException as error:  # noqa: BLE001 - task cancellation is terminal
            message = _FinalBarrierBatchSettled(
                command_id=command_id,
                batch=None,
                error=error,
            )
        self._message_sink(message)

    def _post_prerequisite_batch_settled(
        self,
        command_id: str,
        task: asyncio.Task[DurabilityBatch],
    ) -> None:
        try:
            message = _FinalBarrierPrerequisiteBatchSettled(
                command_id=command_id,
                batch_task=task,
                batch=task.result(),
                error=None,
            )
        except BaseException as error:  # noqa: BLE001 - task cancellation is terminal
            message = _FinalBarrierPrerequisiteBatchSettled(
                command_id=command_id,
                batch_task=task,
                batch=None,
                error=error,
            )
        self._message_sink(message)

    def _post_publication_settled(
        self,
        command_id: str,
        task: asyncio.Task[tuple[RawManifestV1, ...]],
    ) -> None:
        try:
            message = _FinalBarrierPublicationSettled(
                command_id=command_id,
                manifests=task.result(),
                error=None,
            )
        except BaseException as error:  # noqa: BLE001 - task cancellation is terminal
            message = _FinalBarrierPublicationSettled(
                command_id=command_id,
                manifests=None,
                error=error,
            )
        self._message_sink(message)

    def _critical_from_command(
        self,
        command: _FinalBarrierCommandState,
    ) -> WriterCriticalError:
        failed_control_ids = tuple(
            generation_id
            for generation_id in command.control_generation_ids
            if generation_id in command.file_errors
        )
        if not failed_control_ids and isinstance(
            command.batch_error, WriterCriticalError
        ):
            failed_control_ids = tuple(
                generation_id
                for generation_id in command.control_generation_ids
                if generation_id in command.batch_error.affected_generation_ids
            )
        if failed_control_ids:
            return WriterCriticalError(
                reason=WriterCriticalReason.CONTROL_DURABILITY_FAILED,
                affected_generation_ids=failed_control_ids,
                completed_batches=(),
                message="associated raw control durability failed",
            )
        if isinstance(command.batch_error, WriterCriticalError):
            return command.batch_error
        failed_ids = tuple(
            part.generation_id
            for part in command.work_parts
            if part.generation_id in command.file_errors
        )
        if not failed_ids:
            failed_ids = tuple(part.generation_id for part in command.work_parts)
        reason = (
            WriterCriticalReason.WRITE_FAILED
            if any(
                isinstance(error, FilePersistenceError)
                and error.reason is WriterCriticalReason.WRITE_FAILED
                for error in command.file_errors.values()
            )
            else WriterCriticalReason.SYNC_FAILED
        )
        return WriterCriticalError(
            reason=reason,
            affected_generation_ids=failed_ids,
            completed_batches=(),
            message="raw final durability barrier failed",
        )

    def _cleanup_command(self, command: _FinalBarrierCommandState) -> None:
        for part in command.work_parts:
            generation_id = part.generation_id
            if self._command_by_generation.get(generation_id) == command.command_id:
                raise RuntimeError("final barrier generation index was not settled")
        removed = self._commands.pop(command.command_id, None)
        if removed is not command:
            raise RuntimeError("final barrier command index is inconsistent")

    def _release_generation(
        self,
        command: _FinalBarrierCommandState,
        generation_id: str,
    ) -> None:
        observed = self._command_by_generation.pop(generation_id, None)
        if observed != command.command_id:
            raise RuntimeError("final barrier generation index is inconsistent")

    def _release_command_reservations(
        self,
        command: _FinalBarrierCommandState,
    ) -> None:
        for part in command.work_parts:
            if (
                self._command_by_generation.get(part.generation_id)
                == command.command_id
            ):
                del self._command_by_generation[part.generation_id]

    def _finish_command(
        self,
        command: _FinalBarrierCommandState,
        *,
        manifests: tuple[RawManifestV1, ...] | None = None,
        error: BaseException | None = None,
    ) -> None:
        if (manifests is None) == (error is None):
            raise ValueError("final barrier requires exactly one terminal outcome")
        self._cleanup_command(command)
        if error is not None:
            command.result_future.set_exception(error)
        else:
            assert manifests is not None
            command.result_future.set_result(manifests)

    def _try_finish_final_barrier(
        self,
        command: _FinalBarrierCommandState,
    ) -> None:
        if command.remaining_generation_ids or not command.batch_settled:
            return
        if command.publication_task is not None:
            return
        if command.file_errors or command.batch_error is not None:
            self._start_failure_cleanup(
                command,
                self._critical_from_command(command),
            )
            return
        batch = command.batch
        if batch is None:
            self._start_failure_cleanup(
                command,
                WriterCriticalError(
                    reason=WriterCriticalReason.SYNC_FAILED,
                    affected_generation_ids=tuple(
                        part.generation_id for part in command.parts
                    ),
                    completed_batches=(),
                    message="raw final durability batch had no result",
                ),
            )
            return
        if (
            batch.trigger is not command.trigger
            or tuple(result.generation_id for result in batch.files)
            != command.batch_generation_ids
        ):
            self._start_failure_cleanup(
                command,
                WriterCriticalError(
                    reason=WriterCriticalReason.SYNC_FAILED,
                    affected_generation_ids=tuple(
                        part.generation_id for part in command.work_parts
                    ),
                    completed_batches=(),
                    message="raw final durability batch did not match its command",
                ),
            )
            return
        try:
            summaries = tuple(part.freeze_summary() for part in command.parts)
            publication_coroutine = self._publish_group(command.parts, summaries)
            try:
                publication_task = asyncio.create_task(publication_coroutine)
            except BaseException:
                publication_coroutine.close()
                raise
        except BaseException as error:  # noqa: BLE001 - terminalize state corruption
            self._start_failure_cleanup(command, error)
            return
        command.publication_task = publication_task
        publication_task.add_done_callback(
            partial(self._post_publication_settled, command.command_id)
        )

    @staticmethod
    def _fold_dependencies(
        dependencies: tuple[_FinalBarrierControlDependency, ...],
    ) -> None:
        for dependency in dependencies:
            for target in dependency.targets:
                target.validate_durable_control(dependency.association)
        for dependency in dependencies:
            for target in dependency.targets:
                target.fold_durable_control(dependency.association)

    def _settle_claim_message(
        self,
        command: _FinalBarrierCommandState,
        *,
        generation_id: str,
        part: _ActivePart,
        claimed: _ClaimedSealedWork,
        message: FileSyncCompleted | FileSyncFailed,
        dependencies: tuple[_FinalBarrierControlDependency, ...],
    ) -> bool:
        if type(message) is FileSyncCompleted:
            try:
                part.apply_completion(claimed, message.result)
                self._fold_dependencies(dependencies)
                return True
            except BaseException as error:  # noqa: BLE001 - never strand a command
                if part._claimed.get(claimed.claim_id) is claimed:
                    try:
                        part.apply_failure(
                            claimed,
                            FilePersistenceError(
                                reason=WriterCriticalReason.SYNC_FAILED,
                                original=error,
                            ),
                        )
                    except BaseException as claim_error:  # noqa: BLE001 - terminal state
                        error = claim_error
                command.file_errors[generation_id] = error
                return False
        assert type(message) is FileSyncFailed
        try:
            part.apply_failure(claimed, message.error)
            command.file_errors[generation_id] = message.error
        except BaseException as error:  # noqa: BLE001 - never strand a command
            command.file_errors[generation_id] = error
        return False

    def _fail_missing_batch_completions(
        self,
        command: _FinalBarrierCommandState,
    ) -> None:
        missing = tuple(
            generation_id
            for generation_id in command.batch_generation_ids
            if generation_id in command.remaining_generation_ids
        )
        for generation_id in missing:
            self._release_generation(command, generation_id)
            part, claimed = command.claims_by_generation[generation_id]
            error = FilePersistenceError(
                reason=WriterCriticalReason.SYNC_FAILED,
                original=RuntimeError(
                    "final barrier file completion was not delivered"
                ),
            )
            try:
                part.apply_failure(claimed, error)
            except BaseException as claim_error:  # noqa: BLE001 - terminal state
                error = FilePersistenceError(
                    reason=WriterCriticalReason.SYNC_FAILED,
                    original=claim_error,
                )
            command.file_errors[generation_id] = error
            command.remaining_generation_ids.remove(generation_id)

    def _fail_missing_prerequisite_completions(
        self,
        command: _FinalBarrierCommandState,
        generation_ids: tuple[str, ...],
        settlement_error: BaseException | None,
    ) -> None:
        for generation_id in generation_ids:
            if generation_id not in command.remaining_prerequisite_generation_ids:
                continue
            part, claimed = command.prerequisite_claims_by_generation[generation_id]
            reason = WriterCriticalReason.SYNC_FAILED
            if (
                isinstance(settlement_error, WriterCriticalError)
                and generation_id in settlement_error.affected_generation_ids
                and settlement_error.reason
                in {
                    WriterCriticalReason.WRITE_FAILED,
                    WriterCriticalReason.SYNC_FAILED,
                }
            ):
                reason = settlement_error.reason
            error = FilePersistenceError(
                reason=reason,
                original=(
                    settlement_error
                    if settlement_error is not None
                    else RuntimeError("prerequisite file completion was not delivered")
                ),
            )
            self._settle_claim_message(
                command,
                generation_id=generation_id,
                part=part,
                claimed=claimed,
                message=FileSyncFailed(generation_id, error),
                dependencies=(),
            )
            command.remaining_prerequisite_generation_ids.remove(generation_id)

    def _try_advance_prerequisites(
        self,
        command: _FinalBarrierCommandState,
    ) -> None:
        if command.remaining_prerequisite_generation_ids:
            return
        if (
            command.batch_task is not None
            or command.batch_settled
            or command.publication_task is not None
        ):
            return
        if command.file_errors:
            self._release_command_reservations(command)
            self._start_failure_cleanup(
                command,
                self._critical_from_command(command),
            )
            return
        try:
            self._submit_final_batch(command)
        except BaseException as error:  # noqa: BLE001 - terminalize owned close work
            command.batch_error = error
            self._release_command_reservations(command)
            self._start_failure_cleanup(
                command,
                self._critical_from_command(command),
            )

    def _submit_final_batch(self, command: _FinalBarrierCommandState) -> None:
        if command.remaining_prerequisite_generation_ids:
            raise RuntimeError("final batch cannot precede prerequisite completion")
        if command.batch_task is not None or command.batch_settled:
            raise RuntimeError("final durability batch was already submitted")

        remaining_control_ids = set(command.control_dependencies_by_generation)
        closing_ids = {part.generation_id for part in command.parts}
        batch_parts = command.parts + tuple(
            part
            for part in command.work_parts
            if part.generation_id not in closing_ids
            and part.generation_id in remaining_control_ids
        )
        batch_generation_ids = tuple(part.generation_id for part in batch_parts)
        if len(set(batch_generation_ids)) != len(batch_generation_ids):
            raise ValueError("final barrier batch generation IDs must be unique")
        for (
            generation_id,
            dependencies,
        ) in command.control_dependencies_by_generation.items():
            control_part = next(
                part
                for part in command.work_parts
                if part.generation_id == generation_id
            )
            for dependency in dependencies:
                control_part.validate_pending_control_identity(
                    dependency.control_identity
                )
        for part in batch_parts:
            if part.in_flight_claim() is not None:
                raise RuntimeError("final batch part still has work in flight")
            owner = self._command_by_generation.get(part.generation_id)
            if owner != command.command_id:
                raise ValueError("raw part already belongs to a final barrier")

        claims_by_generation: dict[
            str,
            tuple[_ActivePart, _ClaimedSealedWork],
        ] = {}
        works: list[SealedFileWork] = []
        for part in batch_parts:
            claimed = part.seal_for_sync(force_sync=True)
            assert claimed is not None
            claims_by_generation[part.generation_id] = (part, claimed)
            works.append(claimed.work)
        for (
            generation_id,
            dependencies,
        ) in command.control_dependencies_by_generation.items():
            _part, claimed = claims_by_generation[generation_id]
            claimed_identities = tuple(claim.identity for claim in claimed.claims)
            for dependency in dependencies:
                if claimed_identities.count(dependency.control_identity) != 1:
                    raise AssertionError(
                        "control identity was not sealed into its final barrier work"
                    )

        command.claims_by_generation = claims_by_generation
        command.batch_generation_ids = batch_generation_ids
        command.remaining_generation_ids = set(batch_generation_ids)
        batch_coroutine = self._coordinator.sync_batch(
            tuple(works),
            trigger=command.trigger,
        )
        try:
            batch_task = asyncio.create_task(batch_coroutine)
        except BaseException as error:  # noqa: BLE001 - rollback every sealed claim
            batch_coroutine.close()
            persistence_error = FilePersistenceError(
                reason=WriterCriticalReason.SYNC_FAILED,
                original=error,
            )
            for generation_id, (part, claimed) in claims_by_generation.items():
                part.apply_failure(claimed, persistence_error)
                command.file_errors[generation_id] = persistence_error
                self._release_generation(command, generation_id)
            command.remaining_generation_ids.clear()
            command.batch_settled = True
            command.batch_error = error
            self._try_finish_final_barrier(command)
            return
        command.batch_task = batch_task
        batch_task.add_done_callback(
            partial(self._post_batch_settled, command.command_id)
        )

    def _handle_prerequisite_completion(
        self,
        command: _FinalBarrierCommandState,
        *,
        generation_id: str,
        message: FileSyncCompleted | FileSyncFailed,
    ) -> None:
        part, claimed = command.prerequisite_claims_by_generation[generation_id]
        claimed_identities = {claim.identity for claim in claimed.claims}
        all_dependencies = command.control_dependencies_by_generation.get(
            generation_id,
            (),
        )
        durable_dependencies = tuple(
            dependency
            for dependency in all_dependencies
            if dependency.control_identity in claimed_identities
        )
        succeeded = self._settle_claim_message(
            command,
            generation_id=generation_id,
            part=part,
            claimed=claimed,
            message=message,
            dependencies=durable_dependencies,
        )
        if succeeded and durable_dependencies:
            pending_dependencies = tuple(
                dependency
                for dependency in all_dependencies
                if dependency not in durable_dependencies
            )
            if pending_dependencies:
                command.control_dependencies_by_generation[generation_id] = (
                    pending_dependencies
                )
            else:
                command.control_dependencies_by_generation.pop(generation_id, None)
        command.remaining_prerequisite_generation_ids.remove(generation_id)
        closing_generation_ids = {part.generation_id for part in command.parts}
        requires_final_batch = (
            generation_id in closing_generation_ids
            or generation_id in command.control_dependencies_by_generation
        )
        if succeeded and not requires_final_batch:
            self._release_generation(command, generation_id)
        self._try_advance_prerequisites(command)

    def handle_message(self, message: object) -> bool:
        if type(message) is FileSyncCompleted:
            generation_id = message.result.generation_id
        elif type(message) is FileSyncFailed:
            generation_id = message.generation_id
        elif type(message) is _FinalBarrierPrerequisiteBatchSettled:
            command = self._commands.get(message.command_id)
            if command is None:
                return True
            generation_ids = command.prerequisite_generations_by_batch_task.pop(
                message.batch_task,
                None,
            )
            if generation_ids is None:
                raise ValueError("unknown final barrier prerequisite batch settlement")
            self._fail_missing_prerequisite_completions(
                command,
                generation_ids,
                message.error,
            )
            self._try_advance_prerequisites(command)
            return True
        elif type(message) is _FinalBarrierBatchSettled:
            command = self._commands.get(message.command_id)
            if command is None:
                raise ValueError("unknown final barrier batch settlement")
            if command.batch_settled:
                raise ValueError("final barrier batch settled more than once")
            command.batch_settled = True
            command.batch = message.batch
            command.batch_error = message.error
            self._fail_missing_batch_completions(command)
            self._try_finish_final_barrier(command)
            return True
        elif type(message) is _FinalBarrierPublicationSettled:
            command = self._commands.get(message.command_id)
            if command is None or command.publication_task is None:
                raise ValueError("unknown final barrier publication settlement")
            self._finish_command(
                command,
                manifests=message.manifests,
                error=message.error,
            )
            return True
        else:
            return False

        command_id = self._command_by_generation.get(generation_id)
        if command_id is None:
            return False
        command = self._commands[command_id]
        if generation_id in command.remaining_prerequisite_generation_ids:
            self._handle_prerequisite_completion(
                command,
                generation_id=generation_id,
                message=message,
            )
            return True
        if generation_id not in command.remaining_generation_ids:
            raise RuntimeError("final barrier generation index is inconsistent")
        self._release_generation(command, generation_id)
        part, claimed = command.claims_by_generation[generation_id]
        dependencies = command.control_dependencies_by_generation.get(
            generation_id,
            (),
        )
        self._settle_claim_message(
            command,
            generation_id=generation_id,
            part=part,
            claimed=claimed,
            message=message,
            dependencies=dependencies,
        )
        command.remaining_generation_ids.remove(generation_id)
        self._try_finish_final_barrier(command)
        return True

    def _start_close_group(
        self,
        parts: tuple[_ActivePart, ...],
        *,
        reason: CloseReason,
        closed_at_ns: int,
        control_dependencies: tuple[_FinalBarrierControlDependency, ...],
    ) -> asyncio.Future[tuple[RawManifestV1, ...]]:
        closed = _nonnegative(closed_at_ns, field_name="closed_at_ns")
        generation_ids = tuple(part.generation_id for part in parts)
        if len(set(generation_ids)) != len(generation_ids):
            raise ValueError("final barrier generation IDs must be unique")
        for part in parts:
            part.validate_final_barrier(reason, closed_at_ns=closed)

        closing_generation_ids = set(generation_ids)
        closing_parts_by_generation = {part.generation_id: part for part in parts}
        control_parts_by_generation: dict[str, _ActivePart] = {}
        dependencies_by_generation: dict[
            str,
            list[_FinalBarrierControlDependency],
        ] = {}
        fold_keys: set[tuple[str, str]] = set()
        dependency_identity_keys: set[tuple[str, int, int, int]] = set()
        for dependency in control_dependencies:
            control_part = dependency.control_part
            control_part.locate_control_identity(dependency.control_identity)
            closing_part = closing_parts_by_generation.get(control_part.generation_id)
            if closing_part is not None and closing_part is not control_part:
                raise ValueError(
                    "control generation identifies a different closing part"
                )
            if not any(
                target.generation_id in closing_generation_ids
                for target in dependency.targets
            ):
                raise ValueError(
                    "control dependency must target a closing raw generation"
                )
            existing = control_parts_by_generation.setdefault(
                control_part.generation_id,
                control_part,
            )
            if existing is not control_part:
                raise ValueError("control generation identifies different raw parts")
            identity_key = (
                control_part.generation_id,
                dependency.control_identity.config_generation,
                dependency.control_identity.acceptance_ordinal,
                dependency.control_identity.writer_sequence,
            )
            if identity_key in dependency_identity_keys:
                raise ValueError(
                    "control dependency identity was supplied more than once"
                )
            dependency_identity_keys.add(identity_key)
            for target in dependency.targets:
                target.validate_durable_control(dependency.association)
                fold_key = (
                    target.generation_id,
                    dependency.association.control_event_id,
                )
                if fold_key in fold_keys:
                    raise ValueError(
                        "control event would be folded into a target twice"
                    )
                fold_keys.add(fold_key)
            dependencies_by_generation.setdefault(
                control_part.generation_id,
                [],
            ).append(dependency)

        work_parts = parts + tuple(
            part
            for generation_id, part in control_parts_by_generation.items()
            if generation_id not in closing_generation_ids
        )
        work_generation_ids = tuple(part.generation_id for part in work_parts)
        if len(set(work_generation_ids)) != len(work_generation_ids):
            raise ValueError("final barrier work generation IDs must be unique")
        for work_part in work_parts:
            if work_part.generation_id in self._command_by_generation:
                raise ValueError("raw part already belongs to a final barrier")

        prerequisite_claims: dict[
            str,
            tuple[_ActivePart, _ClaimedSealedWork],
        ] = {}
        prerequisite_generations_by_batch_task: dict[
            asyncio.Task[DurabilityBatch],
            list[str],
        ] = {}
        for work_part in work_parts:
            claimed = work_part.in_flight_claim()
            if claimed is not None:
                batch_task = work_part.claim_batch_task(claimed)
                if batch_task is None:
                    raise ValueError(
                        "in-flight raw claim requires a batch settlement task"
                    )
                prerequisite_claims[work_part.generation_id] = (work_part, claimed)
                prerequisite_generations_by_batch_task.setdefault(
                    batch_task,
                    [],
                ).append(work_part.generation_id)
        for part in parts:
            if part.close_reason is None:
                part.retire(reason, closed_at_ns=closed)

        loop = asyncio.get_running_loop()
        command_id = str(uuid.uuid4())
        result_future: asyncio.Future[tuple[RawManifestV1, ...]] = loop.create_future()
        command = _FinalBarrierCommandState(
            command_id=command_id,
            parts=parts,
            work_parts=work_parts,
            trigger=_CLOSE_TRIGGER[reason],
            claims_by_generation={},
            batch_generation_ids=(),
            control_dependencies_by_generation={
                generation_id: tuple(dependencies)
                for generation_id, dependencies in dependencies_by_generation.items()
            },
            control_generation_ids=tuple(
                part.generation_id
                for part in work_parts
                if part.logical_stream == "_control"
            ),
            remaining_generation_ids=set(),
            result_future=result_future,
            prerequisite_claims_by_generation=prerequisite_claims,
            prerequisite_generations_by_batch_task={
                task: tuple(generation_ids)
                for task, generation_ids in (
                    prerequisite_generations_by_batch_task.items()
                )
            },
            remaining_prerequisite_generation_ids=set(prerequisite_claims),
        )
        self._commands[command_id] = command
        for generation_id in work_generation_ids:
            self._command_by_generation[generation_id] = command_id
        for batch_task in command.prerequisite_generations_by_batch_task:
            batch_task.add_done_callback(
                partial(self._post_prerequisite_batch_settled, command_id)
            )
        if not prerequisite_claims:
            self._submit_final_batch(command)
        return result_future

    async def close_group(
        self,
        parts: Sequence[_ActivePart],
        *,
        reason: CloseReason,
        closed_at_ns: int,
        control_dependencies: Sequence[_FinalBarrierControlDependency] = (),
    ) -> tuple[RawManifestV1, ...]:
        if type(reason) is not CloseReason or reason is CloseReason.RECOVERY:
            raise ValueError("normal final barriers require a normal close reason")
        owned_parts = tuple(parts)
        owned_dependencies = tuple(control_dependencies)
        if any(
            type(dependency) is not _FinalBarrierControlDependency
            for dependency in owned_dependencies
        ):
            raise TypeError(
                "control_dependencies must contain "
                "_FinalBarrierControlDependency values"
            )
        if not owned_parts:
            if owned_dependencies:
                raise ValueError("control dependencies require a nonempty close group")
            return ()
        if any(type(part) is not _ActivePart for part in owned_parts):
            raise TypeError("parts must contain _ActivePart values")
        result_future = self._start_close_group(
            owned_parts,
            reason=reason,
            closed_at_ns=closed_at_ns,
            control_dependencies=owned_dependencies,
        )
        try:
            return await asyncio.shield(result_future)
        except asyncio.CancelledError:
            self._detached_futures.add(result_future)
            raise

    async def wait_for_detached(self) -> tuple[object, ...]:
        futures = tuple(self._detached_futures)
        if not futures:
            return ()
        outcomes = await asyncio.gather(
            *(asyncio.shield(future) for future in futures),
            return_exceptions=True,
        )
        self._detached_futures.difference_update(
            future for future in futures if future.done()
        )
        return tuple(outcomes)


__all__ = [
    "NoReplaceCapability",
    "PublicationConflict",
    "atomic_write_and_sync_json_exclusive",
    "fsync_directory",
    "open_readonly_nofollow",
    "publish_no_replace",
    "require_path_is_open_inode",
    "run_storage",
    "size_and_sha256_fd",
]
