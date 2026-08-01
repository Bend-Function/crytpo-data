from __future__ import annotations

import asyncio
import os
from collections.abc import AsyncIterator, Sequence
from concurrent.futures import Executor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol, TypeAlias, cast

from crypto_collector.domain.clock import Clock
from crypto_collector.storage.stats import CumulativeDurabilityHistogram
from crypto_collector.storage.stream_file import SealedFileWork

_MAX_SIGNED_INT64 = 2**63 - 1


def _integer(value: object, *, field_name: str, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field_name} must be {qualifier}")
    if value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must fit a signed 64-bit integer")
    return value


def _nonempty(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a non-empty normalized string")
    return value


class DurabilityTrigger(StrEnum):
    PERIODIC = "periodic"
    SIZE = "size"
    HOUR = "hour"
    CONFIG = "config"
    RECOVERY = "recovery"
    SHUTDOWN = "shutdown"
    BARRIER = "barrier"


class RecoveryAccountingMode(StrEnum):
    UNMEASURED = "unmeasured"


@dataclass(frozen=True, slots=True)
class FileDurabilityResult:
    generation_id: str
    was_dirty: bool
    record_count: int
    sync_completed_monotonic_ns: int | None
    sync_duration_ns: int
    lag_p50_ns: int | None
    lag_p95_ns: int | None
    lag_p99_ns: int | None
    lag_max_ns: int | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "generation_id",
            _nonempty(self.generation_id, field_name="generation_id"),
        )
        if type(self.was_dirty) is not bool:
            raise TypeError("was_dirty must be a boolean")
        count = _integer(self.record_count, field_name="record_count")
        if self.was_dirty != (count > 0):
            raise ValueError("was_dirty must agree with record_count")
        if self.sync_completed_monotonic_ns is not None:
            object.__setattr__(
                self,
                "sync_completed_monotonic_ns",
                _integer(
                    self.sync_completed_monotonic_ns,
                    field_name="sync_completed_monotonic_ns",
                ),
            )
        if self.was_dirty and self.sync_completed_monotonic_ns is None:
            raise ValueError("dirty durability results require a completion time")
        object.__setattr__(
            self,
            "sync_duration_ns",
            _integer(self.sync_duration_ns, field_name="sync_duration_ns"),
        )
        quantiles = (self.lag_p50_ns, self.lag_p95_ns, self.lag_p99_ns)
        values = (*quantiles, self.lag_max_ns)
        if any(value is None for value in values):
            if any(value is not None for value in values):
                raise ValueError("lag statistics must be all present or all absent")
        else:
            normalized = tuple(
                _integer(value, field_name="lag statistic") for value in values
            )
            if normalized[0] > normalized[1] or normalized[1] > normalized[2]:
                raise ValueError("lag quantiles must be non-decreasing")
        if not self.was_dirty and any(value is not None for value in values):
            raise ValueError("clean durability results cannot contain lag statistics")


@dataclass(frozen=True, slots=True)
class FileSyncCompleted:
    result: FileDurabilityResult

    def __post_init__(self) -> None:
        if type(self.result) is not FileDurabilityResult:
            raise TypeError("result must be FileDurabilityResult")


@dataclass(frozen=True, slots=True)
class FileSyncFailed:
    generation_id: str
    error: BaseException

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "generation_id",
            _nonempty(self.generation_id, field_name="generation_id"),
        )
        if not isinstance(self.error, BaseException):
            raise TypeError("error must be a BaseException")


FileSyncCompletion: TypeAlias = FileSyncCompleted | FileSyncFailed


class FileSyncCompletionSink(Protocol):
    def __call__(self, completion: FileSyncCompletion) -> None: ...


def discard_file_sync_completion(_completion: FileSyncCompletion) -> None:
    pass


@dataclass(frozen=True, slots=True)
class DurabilityBatch:
    batch_sequence: int
    trigger: DurabilityTrigger
    started_monotonic_ns: int
    completed_monotonic_ns: int
    files: tuple[FileDurabilityResult, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "batch_sequence",
            _integer(self.batch_sequence, field_name="batch_sequence"),
        )
        if type(self.trigger) is not DurabilityTrigger:
            raise TypeError("trigger must be DurabilityTrigger")
        started = _integer(
            self.started_monotonic_ns,
            field_name="started_monotonic_ns",
        )
        completed = _integer(
            self.completed_monotonic_ns,
            field_name="completed_monotonic_ns",
        )
        if completed < started:
            raise ValueError("batch completion cannot precede its start")
        if type(self.files) is not tuple or not self.files:
            raise ValueError("files must be a nonempty tuple")
        if any(type(item) is not FileDurabilityResult for item in self.files):
            raise TypeError("files must contain FileDurabilityResult values")
        generation_ids = tuple(item.generation_id for item in self.files)
        if len(set(generation_ids)) != len(generation_ids):
            raise ValueError("batch file generations must be unique")

    @property
    def record_count(self) -> int:
        return sum(item.record_count for item in self.files)


class WriterCriticalReason(StrEnum):
    OLDEST_UNPERSISTED_AGE = "oldest_unpersisted_age"
    WRITE_FAILED = "write_failed"
    SYNC_FAILED = "sync_failed"
    PUBLICATION_FAILED = "publication_failed"
    CONTROL_DURABILITY_FAILED = "control_durability_failed"
    SLO_TRANSITION_CALLBACK_FAILED = "slo_transition_callback_failed"
    CLOSE_DEADLINE = "close_deadline"
    MARKED_INCOMPLETE = "marked_incomplete"


class WriterAffinityError(RuntimeError):
    """A public writer API was called outside its owning thread or event loop."""


class WriterCriticalError(RuntimeError):
    def __init__(
        self,
        *,
        reason: WriterCriticalReason,
        affected_generation_ids: tuple[str, ...],
        completed_batches: tuple[DurabilityBatch, ...],
        message: str,
    ) -> None:
        if type(reason) is not WriterCriticalReason:
            raise TypeError("reason must be WriterCriticalReason")
        if type(affected_generation_ids) is not tuple:
            raise TypeError("affected_generation_ids must be a tuple")
        normalized_ids = tuple(
            _nonempty(item, field_name="affected_generation_id")
            for item in affected_generation_ids
        )
        if len(set(normalized_ids)) != len(normalized_ids):
            raise ValueError("affected generation IDs must be unique")
        if type(completed_batches) is not tuple or any(
            type(item) is not DurabilityBatch for item in completed_batches
        ):
            raise TypeError("completed_batches must contain DurabilityBatch values")
        normalized_message = _nonempty(message, field_name="message")
        self.reason = reason
        self.affected_generation_ids = normalized_ids
        self.completed_batches = completed_batches
        super().__init__(normalized_message)


class DuplicateFileGeneration(ValueError):
    def __init__(self, generation_id: str) -> None:
        self.generation_id = _nonempty(
            generation_id,
            field_name="generation_id",
        )
        super().__init__(
            f"file generation already has durability work in flight: {generation_id}"
        )


class SyncBackend(Protocol):
    def sync(self, fd: int) -> None: ...


class PosixSyncBackend:
    def sync(self, fd: int) -> None:
        normalized_fd = _integer(fd, field_name="fd")
        sync = getattr(os, "fdatasync", os.fsync)
        sync(normalized_fd)


class StorageIoLimiter:
    def __init__(self, max_concurrency: int) -> None:
        self._max_concurrency = _integer(
            max_concurrency,
            field_name="max_concurrency",
            minimum=1,
        )
        self._slots = asyncio.Semaphore(self._max_concurrency)

    @property
    def max_concurrency(self) -> int:
        return self._max_concurrency

    @asynccontextmanager
    async def slot(self) -> AsyncIterator[None]:
        await self._slots.acquire()
        try:
            yield
        finally:
            self._slots.release()


class FilePersistenceError(RuntimeError):
    def __init__(
        self,
        *,
        reason: WriterCriticalReason,
        original: Exception,
    ) -> None:
        if reason not in {
            WriterCriticalReason.WRITE_FAILED,
            WriterCriticalReason.SYNC_FAILED,
        }:
            raise ValueError("file persistence reason must be write or sync failure")
        if not isinstance(original, Exception):
            raise TypeError("original must be an Exception")
        self.reason = reason
        self.original = original
        message = (
            "raw frame write failed"
            if reason is WriterCriticalReason.WRITE_FAILED
            else "raw file synchronization failed"
        )
        super().__init__(message)


class DurabilityCoordinator:
    def __init__(
        self,
        *,
        clock: Clock,
        sync_backend: SyncBackend,
        io_limiter: StorageIoLimiter,
        storage_executor: Executor,
        durability_slo_ns: int,
        durability_critical_ns: int,
        completion_sink: FileSyncCompletionSink,
    ) -> None:
        self._initialize(
            clock=clock,
            sync_backend=sync_backend,
            io_limiter=io_limiter,
            storage_executor=storage_executor,
            durability_slo_ns=durability_slo_ns,
            durability_critical_ns=durability_critical_ns,
            completion_sink=completion_sink,
            measure_lag=True,
        )

    def _initialize(
        self,
        *,
        clock: Clock,
        sync_backend: SyncBackend,
        io_limiter: StorageIoLimiter,
        storage_executor: Executor,
        durability_slo_ns: int,
        durability_critical_ns: int,
        completion_sink: FileSyncCompletionSink,
        measure_lag: bool,
    ) -> None:
        _integer(
            durability_slo_ns,
            field_name="durability_slo_ns",
            minimum=1,
        )
        _integer(
            durability_critical_ns,
            field_name="durability_critical_ns",
            minimum=1,
        )
        if type(io_limiter) is not StorageIoLimiter:
            raise TypeError("io_limiter must be StorageIoLimiter")
        if not callable(getattr(sync_backend, "sync", None)):
            raise TypeError("sync_backend must implement sync(fd)")
        if not callable(getattr(storage_executor, "submit", None)):
            raise TypeError("storage_executor must implement Executor.submit")
        if not callable(completion_sink):
            raise TypeError("completion_sink must be callable")
        if type(measure_lag) is not bool:
            raise TypeError("measure_lag must be a boolean")
        self._clock = clock
        self._sync_backend = sync_backend
        self._io_limiter = io_limiter
        self._storage_executor = storage_executor
        self._completion_sink = completion_sink
        self._measure_lag = measure_lag
        self._inflight_generations: set[str] = set()
        self._owned_batches: set[asyncio.Task[DurabilityBatch]] = set()
        self._next_batch_sequence = 0

    def _clock_ns(self, *, field_name: str) -> int:
        return _integer(self._clock.monotonic_ns(), field_name=field_name)

    def _persist_blocking(self, work: SealedFileWork) -> FileDurabilityResult:
        started_ns = self._clock_ns(field_name="sync_started_monotonic_ns")
        pending = work.pending
        if pending is not None:
            try:
                written = work.stream_file.write_frame(pending)
            except Exception as error:  # noqa: BLE001 - every write failure is terminal
                failure = FilePersistenceError(
                    reason=WriterCriticalReason.WRITE_FAILED,
                    original=error,
                )
                raise failure from None
            if written.record_count != len(pending.rows):
                mismatch = RuntimeError("written frame record count mismatch")
                failure = FilePersistenceError(
                    reason=WriterCriticalReason.WRITE_FAILED,
                    original=mismatch,
                )
                raise failure from None
        try:
            self._sync_backend.sync(work.stream_file.fileno())
            completed_ns = self._clock_ns(
                field_name="sync_completed_monotonic_ns",
            )
            if completed_ns < started_ns:
                raise RuntimeError("monotonic clock moved backward during sync")
        except Exception as error:
            if isinstance(error, FilePersistenceError):
                raise
            failure = FilePersistenceError(
                reason=WriterCriticalReason.SYNC_FAILED,
                original=error,
            )
            raise failure from None

        if pending is None:
            snapshot = None
            record_count = 0
        else:
            record_count = len(pending.rows)
            if self._measure_lag:
                histogram = CumulativeDurabilityHistogram()
                for row in pending.rows:
                    if completed_ns < row.accepted_monotonic_ns:
                        clock_error = RuntimeError(
                            "sync completion precedes record acceptance"
                        )
                        failure = FilePersistenceError(
                            reason=WriterCriticalReason.SYNC_FAILED,
                            original=clock_error,
                        )
                        raise failure from None
                    histogram.add(completed_ns - row.accepted_monotonic_ns)
                snapshot = histogram.snapshot()
            else:
                snapshot = None
        return FileDurabilityResult(
            generation_id=work.generation_id,
            was_dirty=pending is not None,
            record_count=record_count,
            sync_completed_monotonic_ns=completed_ns,
            sync_duration_ns=completed_ns - started_ns,
            lag_p50_ns=None if snapshot is None else snapshot.lag_p50_ns,
            lag_p95_ns=None if snapshot is None else snapshot.lag_p95_ns,
            lag_p99_ns=None if snapshot is None else snapshot.lag_p99_ns,
            lag_max_ns=None if snapshot is None else snapshot.lag_max_ns,
        )

    async def _persist_one(self, work: SealedFileWork) -> FileDurabilityResult:
        try:
            async with self._io_limiter.slot():
                result = await asyncio.get_running_loop().run_in_executor(
                    self._storage_executor,
                    self._persist_blocking,
                    work,
                )
        except Exception as error:
            self._completion_sink(FileSyncFailed(work.generation_id, error))
            raise
        else:
            self._completion_sink(FileSyncCompleted(result))
            return result
        finally:
            self._inflight_generations.remove(work.generation_id)

    def _register_work(
        self,
        work_items: Sequence[SealedFileWork],
    ) -> tuple[tuple[SealedFileWork, ...], int, int]:
        if isinstance(work_items, (str, bytes, bytearray)) or not isinstance(
            work_items,
            Sequence,
        ):
            raise TypeError("work_items must be a sequence of SealedFileWork")
        owned = tuple(work_items)
        if not owned:
            raise ValueError("work_items must be nonempty")
        if any(type(item) is not SealedFileWork for item in owned):
            raise TypeError("work_items must contain SealedFileWork values")
        generation_ids = tuple(item.generation_id for item in owned)
        seen: set[str] = set()
        for generation_id in generation_ids:
            if generation_id in seen or generation_id in self._inflight_generations:
                raise DuplicateFileGeneration(generation_id)
            seen.add(generation_id)
        started_ns = self._clock_ns(field_name="batch_started_monotonic_ns")
        batch_sequence = self._next_batch_sequence
        self._next_batch_sequence += 1
        self._inflight_generations.update(generation_ids)
        return owned, batch_sequence, started_ns

    async def _run_owned_batch(
        self,
        work_items: tuple[SealedFileWork, ...],
        *,
        batch_sequence: int,
        trigger: DurabilityTrigger,
        started_ns: int,
    ) -> DurabilityBatch:
        outcomes = await asyncio.gather(
            *(self._persist_one(item) for item in work_items),
            return_exceptions=True,
        )
        failures = tuple(
            (work, outcome)
            for work, outcome in zip(work_items, outcomes, strict=True)
            if isinstance(outcome, BaseException)
        )
        if failures:
            persistence_failures = tuple(
                outcome
                for _work, outcome in failures
                if isinstance(outcome, FilePersistenceError)
            )
            reason = (
                WriterCriticalReason.WRITE_FAILED
                if any(
                    item.reason is WriterCriticalReason.WRITE_FAILED
                    for item in persistence_failures
                )
                else WriterCriticalReason.SYNC_FAILED
            )
            critical = WriterCriticalError(
                reason=reason,
                affected_generation_ids=tuple(
                    work.generation_id for work, _outcome in failures
                ),
                completed_batches=(),
                message=(
                    "raw durability write failed"
                    if reason is WriterCriticalReason.WRITE_FAILED
                    else "raw durability sync failed"
                ),
            )
            cause = next(
                (
                    outcome
                    for _work, outcome in failures
                    if isinstance(outcome, FilePersistenceError)
                    and outcome.reason is reason
                ),
                failures[0][1],
            )
            raise critical from cause
        if any(type(item) is not FileDurabilityResult for item in outcomes):
            raise AssertionError("durability batch produced an invalid result")
        results = tuple(cast(FileDurabilityResult, item) for item in outcomes)
        completed_ns = max(
            started_ns,
            self._clock_ns(field_name="batch_completed_monotonic_ns"),
        )
        return DurabilityBatch(
            batch_sequence=batch_sequence,
            trigger=trigger,
            started_monotonic_ns=started_ns,
            completed_monotonic_ns=completed_ns,
            files=results,
        )

    async def sync_batch(
        self,
        work_items: Sequence[SealedFileWork],
        *,
        trigger: DurabilityTrigger,
    ) -> DurabilityBatch:
        if type(trigger) is not DurabilityTrigger:
            raise TypeError("trigger must be DurabilityTrigger")
        owned, batch_sequence, started_ns = self._register_work(work_items)
        batch_coroutine = self._run_owned_batch(
            owned,
            batch_sequence=batch_sequence,
            trigger=trigger,
            started_ns=started_ns,
        )
        try:
            internal = asyncio.create_task(batch_coroutine)
        except BaseException:
            batch_coroutine.close()
            for item in owned:
                self._inflight_generations.discard(item.generation_id)
            if self._next_batch_sequence == batch_sequence + 1:
                self._next_batch_sequence = batch_sequence
            raise
        self._owned_batches.add(internal)
        internal.add_done_callback(self._owned_batches.discard)

        cancellation: asyncio.CancelledError | None = None
        while not internal.done():
            try:
                await asyncio.shield(internal)
            except asyncio.CancelledError as error:
                if cancellation is None:
                    cancellation = error
            except WriterCriticalError:
                pass

        try:
            batch = internal.result()
        except WriterCriticalError as critical:
            if cancellation is not None:
                raise critical from cancellation
            raise
        if cancellation is not None:
            raise cancellation
        return batch


class RecoveryDurabilityCoordinator(DurabilityCoordinator):
    def __init__(
        self,
        *,
        accounting_mode: RecoveryAccountingMode,
        clock: Clock,
        sync_backend: SyncBackend,
        io_limiter: StorageIoLimiter,
        storage_executor: Executor,
        completion_sink: FileSyncCompletionSink,
    ) -> None:
        if accounting_mode is not RecoveryAccountingMode.UNMEASURED:
            raise ValueError("recovery durability accounting must be unmeasured")
        self._accounting_mode = accounting_mode
        self._initialize(
            clock=clock,
            sync_backend=sync_backend,
            io_limiter=io_limiter,
            storage_executor=storage_executor,
            durability_slo_ns=1,
            durability_critical_ns=1,
            completion_sink=completion_sink,
            measure_lag=False,
        )

    @property
    def accounting_mode(self) -> Literal[RecoveryAccountingMode.UNMEASURED]:
        return RecoveryAccountingMode.UNMEASURED

    async def sync_batch(
        self,
        work_items: Sequence[SealedFileWork],
        *,
        trigger: DurabilityTrigger,
    ) -> DurabilityBatch:
        if trigger is not DurabilityTrigger.RECOVERY:
            raise ValueError("recovery coordinator requires the recovery trigger")
        return await super().sync_batch(work_items, trigger=trigger)


__all__ = [
    "DuplicateFileGeneration",
    "DurabilityBatch",
    "DurabilityCoordinator",
    "DurabilityTrigger",
    "FileDurabilityResult",
    "FilePersistenceError",
    "FileSyncCompleted",
    "FileSyncCompletion",
    "FileSyncCompletionSink",
    "FileSyncFailed",
    "PosixSyncBackend",
    "RecoveryAccountingMode",
    "RecoveryDurabilityCoordinator",
    "StorageIoLimiter",
    "SyncBackend",
    "WriterAffinityError",
    "WriterCriticalError",
    "WriterCriticalReason",
    "discard_file_sync_completion",
]
