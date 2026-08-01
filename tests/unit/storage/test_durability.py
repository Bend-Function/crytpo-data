from __future__ import annotations

import asyncio
import errno
import inspect
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

import crypto_collector.storage as storage_package
import crypto_collector.storage.durability as durability_module
from crypto_collector.storage.durability import (
    DuplicateFileGeneration,
    DurabilityCoordinator,
    DurabilityTrigger,
    FilePersistenceError,
    FileSyncCompleted,
    FileSyncFailed,
    PosixSyncBackend,
    RecoveryAccountingMode,
    RecoveryDurabilityCoordinator,
    StorageIoLimiter,
    WriterCriticalError,
    WriterCriticalReason,
)
from crypto_collector.storage.stats import (
    DURABILITY_BUCKET_UPPER_BOUNDS_NS,
    CumulativeDurabilityHistogram,
    DurabilityHistogramSnapshot,
    DurabilityLedger,
    DurabilityStage,
    RollingDurabilityHistogram,
)
from crypto_collector.storage.stream_file import SealedFileWork, StreamFile


class FakeClock:
    def __init__(self, now_ns: int = 0) -> None:
        self._now_ns = now_ns
        self._lock = threading.Lock()

    def time_ns(self) -> int:
        return self.monotonic_ns()

    def monotonic_ns(self) -> int:
        with self._lock:
            return self._now_ns

    def advance_ns(self, delta_ns: int) -> None:
        with self._lock:
            self._now_ns += delta_ns

    def set_ns(self, value_ns: int) -> None:
        with self._lock:
            self._now_ns = value_ns


class NoopSync:
    def sync(self, _fd: int) -> None:
        pass


class AdvancingSync:
    def __init__(self, clock: FakeClock, advance_ns: int) -> None:
        self._clock = clock
        self._advance_ns = advance_ns

    def sync(self, _fd: int) -> None:
        self._clock.advance_ns(self._advance_ns)


class FailingSync:
    def __init__(self, error: OSError) -> None:
        self._error = error

    def sync(self, _fd: int) -> None:
        raise self._error


class BlockingSync:
    def __init__(
        self,
        loop: asyncio.AbstractEventLoop,
        *,
        expected_starts: int,
        fail_fds: frozenset[int] = frozenset(),
    ) -> None:
        self._loop = loop
        self._expected_starts = expected_starts
        self._fail_fds = fail_fds
        self._release = threading.Event()
        self._started_event = asyncio.Event()
        self._lock = threading.Lock()
        self.active = 0
        self.max_active = 0
        self.started = 0

    def sync(self, fd: int) -> None:
        with self._lock:
            self.active += 1
            self.started += 1
            self.max_active = max(self.max_active, self.active)
            if self.started >= self._expected_starts:
                self._loop.call_soon_threadsafe(self._started_event.set)
        try:
            if fd in self._fail_fds:
                raise OSError(errno.EIO, "injected sync failure")
            if not self._release.wait(timeout=5):
                raise TimeoutError("test sync backend was not released")
        finally:
            with self._lock:
                self.active -= 1

    async def wait_until_started(self) -> None:
        await asyncio.wait_for(self._started_event.wait(), timeout=2)

    def release_all(self) -> None:
        self._release.set()


def make_work(
    tmp_path: Path,
    name: str,
    *,
    accepted_monotonic_ns: tuple[int, ...] = (1,),
    force_sync: bool = False,
) -> tuple[StreamFile, SealedFileWork]:
    stream = StreamFile.allocate(
        tmp_path / f"{name}.jsonl.zst.partial",
        generation_id=name,
        zstd_level=3,
        max_plain_frame_bytes=4096,
    )
    for index, accepted_ns in enumerate(accepted_monotonic_ns):
        stream.append(
            f'{{"row":{index}}}\n'.encode(),
            accepted_monotonic_ns=accepted_ns,
        )
    work = stream.seal_for_sync(force_sync=force_sync)
    assert work is not None
    return stream, work


def make_coordinator(
    *,
    clock: FakeClock,
    sync_backend: object,
    executor: ThreadPoolExecutor,
    io_limiter: StorageIoLimiter | None = None,
    completion_sink=None,  # type: ignore[no-untyped-def]
) -> DurabilityCoordinator:
    return DurabilityCoordinator(
        clock=clock,
        sync_backend=sync_backend,  # type: ignore[arg-type]
        io_limiter=io_limiter or StorageIoLimiter(max_concurrency=2),
        storage_executor=executor,
        durability_slo_ns=1_000_000_000,
        durability_critical_ns=5_000_000_000,
        completion_sink=completion_sink or (lambda _completion: None),
    )


def test_live_coordinator_does_not_expose_an_unmeasured_override() -> None:
    parameters = inspect.signature(DurabilityCoordinator).parameters

    assert "_measure_lag" not in parameters


def test_task3_public_types_are_reexported_from_storage_package() -> None:
    assert storage_package.DurabilityCoordinator is DurabilityCoordinator
    assert storage_package.FilePersistenceError is FilePersistenceError
    assert storage_package.WriterCriticalError is WriterCriticalError


def test_file_persistence_error_accepts_only_file_io_reasons() -> None:
    with pytest.raises(ValueError, match="write or sync"):
        FilePersistenceError(
            reason=WriterCriticalReason.PUBLICATION_FAILED,
            original=RuntimeError("publication"),
        )
    with pytest.raises(TypeError, match="Exception"):
        FilePersistenceError(
            reason=WriterCriticalReason.WRITE_FAILED,
            original=object(),  # type: ignore[arg-type]
        )
    sanitized = FilePersistenceError(
        reason=WriterCriticalReason.WRITE_FAILED,
        original=RuntimeError("must not be retained"),
    )
    assert not hasattr(sanitized, "original")


def test_histogram_uses_disjoint_versioned_buckets_and_exact_max() -> None:
    histogram = CumulativeDurabilityHistogram()
    for lag_ns in (0, 100_000, 100_001, 2**63 - 1):
        histogram.add(lag_ns)

    snapshot = histogram.snapshot()

    assert len(snapshot.bucket_counts) == len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    assert snapshot.bucket_counts[0] == 1
    assert snapshot.bucket_counts[1] == 1
    assert snapshot.bucket_counts[2] == 1
    assert snapshot.bucket_counts[-1] == 1
    assert sum(snapshot.bucket_counts) == snapshot.sample_count == 4
    assert snapshot.lag_total_ns == 2**63 - 1 + 200_001
    assert snapshot.lag_max_ns == 2**63 - 1


@given(
    st.lists(
        st.integers(min_value=0, max_value=2**63 - 1),
        max_size=100,
    )
)
def test_histogram_snapshot_matches_independent_nearest_rank_oracle(
    lag_values: list[int],
) -> None:
    histogram = CumulativeDurabilityHistogram()
    for lag_ns in lag_values:
        histogram.add(lag_ns)

    snapshot = histogram.snapshot()
    expected_counts = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    for lag_ns in lag_values:
        bucket_index = next(
            index
            for index, upper_bound in enumerate(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
            if lag_ns <= upper_bound
        )
        expected_counts[bucket_index] += 1

    def expected_quantile(percent: int) -> int | None:
        if not lag_values:
            return None
        rank = max(1, (percent * len(lag_values) + 99) // 100)
        cumulative = 0
        for upper_bound, count in zip(
            DURABILITY_BUCKET_UPPER_BOUNDS_NS,
            expected_counts,
            strict=True,
        ):
            cumulative += count
            if cumulative >= rank:
                return upper_bound
        raise AssertionError("oracle did not find a quantile bucket")

    assert snapshot.bucket_counts == tuple(expected_counts)
    assert snapshot.sample_count == len(lag_values)
    assert snapshot.lag_total_ns == sum(lag_values)
    assert snapshot.lag_max_ns == (max(lag_values) if lag_values else None)
    assert snapshot.lag_p50_ns == expected_quantile(50)
    assert snapshot.lag_p95_ns == expected_quantile(95)
    assert snapshot.lag_p99_ns == expected_quantile(99)


@pytest.mark.parametrize("lag_ns", [-1, True, 2**63])
def test_histogram_rejects_invalid_lag_without_mutation(lag_ns: object) -> None:
    histogram = CumulativeDurabilityHistogram()

    with pytest.raises((TypeError, ValueError)):
        histogram.add(lag_ns)  # type: ignore[arg-type]

    assert histogram.snapshot().sample_count == 0


def test_cumulative_quantile_may_decrease_without_counter_reset() -> None:
    histogram = CumulativeDurabilityHistogram()
    histogram.add(1_500_000_000)
    before = histogram.snapshot()
    for _ in range(100):
        histogram.add(100_000)

    after = histogram.snapshot()

    assert after.sample_count > before.sample_count
    assert all(
        after_count >= before_count
        for before_count, after_count in zip(
            before.bucket_counts,
            after.bucket_counts,
            strict=True,
        )
    )
    assert before.lag_p50_ns == 1_500_000_000
    assert after.lag_p50_ns == 100_000


def test_rolling_ring_uses_exactly_sixty_monotonic_second_slots() -> None:
    ring = RollingDurabilityHistogram()
    ring.add(lag_ns=900_000_000, sync_completed_monotonic_ns=10_999_999_999)

    included = ring.snapshot(now_monotonic_ns=69_999_999_999)
    expired = ring.snapshot(now_monotonic_ns=70_000_000_000)

    assert included.sample_count == 1
    assert included.lag_max_ns == 900_000_000
    assert expired.sample_count == 0
    assert expired.lag_p99_ns is expired.lag_max_ns is None
    ring.add(lag_ns=1, sync_completed_monotonic_ns=130_000_000_000)
    assert ring.allocated_slot_count == 60
    assert ring.snapshot(now_monotonic_ns=130_000_000_000).sample_count == 1


def test_rolling_ring_resets_colliding_slot_after_large_jump() -> None:
    ring = RollingDurabilityHistogram()
    ring.add(lag_ns=10, sync_completed_monotonic_ns=1_000_000_000)
    ring.add(lag_ns=20, sync_completed_monotonic_ns=61_000_000_000)

    snapshot = ring.snapshot(now_monotonic_ns=61_000_000_000)

    assert snapshot.sample_count == 1
    assert snapshot.lag_max_ns == 20
    assert ring.active_slot_count == 1


def test_rolling_snapshot_physically_expires_all_stale_slots() -> None:
    ring = RollingDurabilityHistogram()
    for second in range(60):
        ring.add(
            lag_ns=second,
            sync_completed_monotonic_ns=second * 1_000_000_000,
        )
    assert ring.active_slot_count == 60

    snapshot = ring.snapshot(now_monotonic_ns=120_000_000_000)

    assert snapshot.sample_count == 0
    assert snapshot.lag_total_ns == 0
    assert ring.active_slot_count == 0


def test_histogram_snapshot_rejects_max_in_the_wrong_bucket() -> None:
    counts = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    counts[2] = 1

    with pytest.raises(ValueError, match="maximum"):
        DurabilityHistogramSnapshot(
            bucket_counts=tuple(counts),
            sample_count=1,
            lag_total_ns=1,
            lag_p50_ns=250_000,
            lag_p95_ns=250_000,
            lag_p99_ns=250_000,
            lag_max_ns=1,
        )


def test_critical_age_includes_accepted_but_unclaimed_rows() -> None:
    clock = FakeClock(now_ns=100)
    ledger = DurabilityLedger(clock=clock)
    ledger.register_accepted(record_id="queued", accepted_monotonic_ns=100)
    clock.advance_ns(5_001)

    critical = ledger.classify_critical_age(durability_critical_ns=5_000)

    assert critical is not None
    assert critical.reason == "oldest_unpersisted_age"
    assert critical.record_id == "queued"
    assert critical.record_stage is DurabilityStage.QUEUED
    assert critical.age_ns == 5_001


def test_critical_age_threshold_is_strict_and_terminal_rows_are_removed() -> None:
    clock = FakeClock(now_ns=100)
    ledger = DurabilityLedger(clock=clock)
    ledger.register_accepted(record_id="record", accepted_monotonic_ns=100)
    assert ledger.stage_count(DurabilityStage.QUEUED) == 1
    assert (
        sum(
            ledger.stage_count(stage)
            for stage in (
                DurabilityStage.QUEUED,
                DurabilityStage.BUFFERED,
                DurabilityStage.IN_FLIGHT,
            )
        )
        == ledger.unpersisted_count
    )
    ledger.mark_buffered("record")
    assert ledger.stage_count(DurabilityStage.QUEUED) == 0
    assert ledger.stage_count(DurabilityStage.BUFFERED) == 1
    ledger.mark_in_flight("record")
    assert ledger.stage_count(DurabilityStage.BUFFERED) == 0
    assert ledger.stage_count(DurabilityStage.IN_FLIGHT) == 1
    assert (
        sum(
            ledger.stage_count(stage)
            for stage in (
                DurabilityStage.QUEUED,
                DurabilityStage.BUFFERED,
                DurabilityStage.IN_FLIGHT,
            )
        )
        == ledger.unpersisted_count
    )
    clock.advance_ns(5_000)
    assert ledger.oldest_unpersisted_age_ns() == 5_000
    assert ledger.classify_critical_age(durability_critical_ns=5_000) is None

    ledger.mark_durable("record")

    assert ledger.unpersisted_count == 0
    assert ledger.stage_count(DurabilityStage.IN_FLIGHT) == 0
    assert ledger.stage_count(DurabilityStage.DURABLE) == 1
    assert ledger.oldest_unpersisted_age_ns() is None
    assert ledger.classify_critical_age(durability_critical_ns=0) is None


def test_critical_age_does_not_shrink_when_injected_clock_rolls_back() -> None:
    clock = FakeClock(now_ns=1_000)
    ledger = DurabilityLedger(clock=clock)
    ledger.register_accepted(record_id="record", accepted_monotonic_ns=0)
    before = ledger.classify_critical_age(durability_critical_ns=900)
    assert before is not None

    clock.set_ns(500)
    after = ledger.classify_critical_age(durability_critical_ns=900)

    assert after is not None
    assert after.observed_monotonic_ns == before.observed_monotonic_ns
    assert after.age_ns == before.age_ns


def test_ledger_rejects_duplicate_and_backward_transitions() -> None:
    ledger = DurabilityLedger(clock=FakeClock(now_ns=10))
    ledger.register_accepted(record_id="record", accepted_monotonic_ns=10)
    with pytest.raises(ValueError, match="duplicate"):
        ledger.register_accepted(record_id="record", accepted_monotonic_ns=10)
    ledger.mark_buffered("record")
    with pytest.raises(ValueError, match="transition"):
        ledger.mark_buffered("record")


def test_ledger_heap_stays_bounded_behind_one_old_unpersisted_record() -> None:
    ledger = DurabilityLedger(clock=FakeClock(now_ns=10_000))
    ledger.register_accepted(record_id="oldest", accepted_monotonic_ns=0)
    for index in range(1_000):
        record_id = f"later-{index}"
        ledger.register_accepted(
            record_id=record_id,
            accepted_monotonic_ns=index + 1,
        )
        ledger.mark_uncertain(record_id)

    assert ledger.unpersisted_count == 1
    assert ledger.heap_entry_count <= 65


@pytest.mark.asyncio
async def test_lag_is_bucketed_at_sync_completion(tmp_path: Path) -> None:
    clock = FakeClock(now_ns=200)
    stream, work = make_work(
        tmp_path,
        "lagged",
        accepted_monotonic_ns=(100, 200),
    )
    executor = ThreadPoolExecutor(max_workers=2)
    try:
        coordinator = make_coordinator(
            clock=clock,
            sync_backend=AdvancingSync(clock, advance_ns=400),
            executor=executor,
        )

        batch = await coordinator.sync_batch(
            [work],
            trigger=DurabilityTrigger.PERIODIC,
        )
    finally:
        executor.shutdown(wait=True)
        stream.close_fd()

    result = batch.files[0]
    assert batch.trigger is DurabilityTrigger.PERIODIC
    assert result.sync_completed_monotonic_ns == 600
    assert result.sync_duration_ns == 400
    assert result.record_count == 2
    assert result.lag_p50_ns == 100_000
    assert result.lag_p95_ns == 100_000
    assert result.lag_p99_ns == 100_000
    assert result.lag_max_ns == 500


@pytest.mark.asyncio
async def test_clean_force_sync_has_an_explicit_result(tmp_path: Path) -> None:
    clock = FakeClock(now_ns=10)
    stream, work = make_work(
        tmp_path,
        "clean",
        accepted_monotonic_ns=(),
        force_sync=True,
    )
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        coordinator = make_coordinator(
            clock=clock,
            sync_backend=NoopSync(),
            executor=executor,
        )
        batch = await coordinator.sync_batch([work], trigger=DurabilityTrigger.BARRIER)
    finally:
        executor.shutdown(wait=True)
        stream.close_fd()

    result = batch.files[0]
    assert result.was_dirty is False
    assert result.record_count == 0
    assert result.lag_p50_ns is result.lag_max_ns is None


@pytest.mark.asyncio
async def test_recovery_coordinator_is_unmeasured_and_shares_limiter(
    tmp_path: Path,
) -> None:
    loop = asyncio.get_running_loop()
    clock = FakeClock(now_ns=100)
    streams_and_work = [
        make_work(tmp_path, f"recovery-{index}", accepted_monotonic_ns=(1,))
        for index in range(4)
    ]
    executor = ThreadPoolExecutor(max_workers=4)
    limiter = StorageIoLimiter(max_concurrency=2)
    sync = BlockingSync(loop, expected_starts=2)
    live = make_coordinator(
        clock=clock,
        sync_backend=sync,
        executor=executor,
        io_limiter=limiter,
    )
    recovery = RecoveryDurabilityCoordinator(
        accounting_mode=RecoveryAccountingMode.UNMEASURED,
        clock=clock,
        sync_backend=sync,
        io_limiter=limiter,
        storage_executor=executor,
        completion_sink=lambda _completion: None,
    )
    live_task = asyncio.create_task(
        live.sync_batch(
            [streams_and_work[0][1], streams_and_work[1][1]],
            trigger=DurabilityTrigger.PERIODIC,
        )
    )
    recovery_task = asyncio.create_task(
        recovery.sync_batch(
            [streams_and_work[2][1], streams_and_work[3][1]],
            trigger=DurabilityTrigger.RECOVERY,
        )
    )
    try:
        await sync.wait_until_started()
        await asyncio.wait_for(
            loop.run_in_executor(executor, lambda: None),
            timeout=2,
        )
        assert sync.max_active == sync.active == 2
        sync.release_all()
        live_batch, recovery_batch = await asyncio.gather(live_task, recovery_task)
    finally:
        sync.release_all()
        await asyncio.gather(live_task, recovery_task, return_exceptions=True)
        executor.shutdown(wait=True)
        for stream, _work in streams_and_work:
            stream.close_fd()

    assert live_batch.record_count == recovery_batch.record_count == 2
    assert all(item.lag_p50_ns is None for item in recovery_batch.files)


@pytest.mark.asyncio
async def test_sync_concurrency_is_global_across_overlapping_batches(
    tmp_path: Path,
) -> None:
    loop = asyncio.get_running_loop()
    clock = FakeClock(now_ns=100)
    streams_and_work = [make_work(tmp_path, f"bounded-{index}") for index in range(4)]
    executor = ThreadPoolExecutor(max_workers=4)
    sync = BlockingSync(loop, expected_starts=2)
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=sync,
        executor=executor,
        io_limiter=StorageIoLimiter(max_concurrency=2),
    )
    first = asyncio.create_task(
        coordinator.sync_batch(
            [streams_and_work[0][1], streams_and_work[1][1]],
            trigger=DurabilityTrigger.PERIODIC,
        )
    )
    second = asyncio.create_task(
        coordinator.sync_batch(
            [streams_and_work[2][1], streams_and_work[3][1]],
            trigger=DurabilityTrigger.SIZE,
        )
    )
    try:
        await sync.wait_until_started()
        await asyncio.wait_for(
            loop.run_in_executor(executor, lambda: None),
            timeout=2,
        )
        assert sync.max_active == sync.active == 2
        sync.release_all()
        await asyncio.gather(first, second)
    finally:
        sync.release_all()
        await asyncio.gather(first, second, return_exceptions=True)
        executor.shutdown(wait=True)
        for stream, _work in streams_and_work:
            stream.close_fd()


@pytest.mark.asyncio
async def test_overlapping_batches_reject_same_generation(tmp_path: Path) -> None:
    loop = asyncio.get_running_loop()
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "duplicate")
    executor = ThreadPoolExecutor(max_workers=2)
    sync = BlockingSync(loop, expected_starts=1)
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=sync,
        executor=executor,
    )
    first = asyncio.create_task(
        coordinator.sync_batch([work], trigger=DurabilityTrigger.PERIODIC)
    )
    try:
        await sync.wait_until_started()
        with pytest.raises(DuplicateFileGeneration):
            await coordinator.sync_batch([work], trigger=DurabilityTrigger.BARRIER)
        sync.release_all()
        await first
    finally:
        sync.release_all()
        await asyncio.gather(first, return_exceptions=True)
        executor.shutdown(wait=True)
        stream.close_fd()


@pytest.mark.asyncio
async def test_sequential_batches_allow_the_same_open_generation(
    tmp_path: Path,
) -> None:
    clock = FakeClock(now_ns=100)
    stream, first_work = make_work(tmp_path, "sequential")
    executor = ThreadPoolExecutor(max_workers=1)
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=NoopSync(),
        executor=executor,
    )
    try:
        first = await coordinator.sync_batch(
            [first_work],
            trigger=DurabilityTrigger.PERIODIC,
        )
        stream.append(b'{"row":2}\n', accepted_monotonic_ns=2)
        second_work = stream.seal_for_sync()
        assert second_work is not None
        second = await coordinator.sync_batch(
            [second_work],
            trigger=DurabilityTrigger.PERIODIC,
        )
    finally:
        executor.shutdown(wait=True)
        stream.close_fd()

    assert first.files[0].generation_id == second.files[0].generation_id
    assert second.batch_sequence == first.batch_sequence + 1


@pytest.mark.asyncio
async def test_batch_rejects_empty_and_internal_duplicates(tmp_path: Path) -> None:
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "same-batch")
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        coordinator = make_coordinator(
            clock=clock,
            sync_backend=NoopSync(),
            executor=executor,
        )
        with pytest.raises(ValueError, match="nonempty"):
            await coordinator.sync_batch([], trigger=DurabilityTrigger.PERIODIC)
        with pytest.raises(DuplicateFileGeneration):
            await coordinator.sync_batch(
                [work, work],
                trigger=DurabilityTrigger.PERIODIC,
            )
    finally:
        executor.shutdown(wait=True)
        stream.close_fd()


@pytest.mark.asyncio
async def test_task_creation_failure_rolls_back_generation_registration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "task-create-failure")
    executor = ThreadPoolExecutor(max_workers=1)
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=NoopSync(),
        executor=executor,
    )
    real_create_task = durability_module.asyncio.create_task

    def fail_create_task(coroutine):  # type: ignore[no-untyped-def]
        coroutine.close()
        raise RuntimeError("injected task creation failure")

    monkeypatch.setattr(durability_module.asyncio, "create_task", fail_create_task)
    try:
        with pytest.raises(RuntimeError, match="task creation"):
            await coordinator.sync_batch([work], trigger=DurabilityTrigger.PERIODIC)
        monkeypatch.setattr(
            durability_module.asyncio,
            "create_task",
            real_create_task,
        )
        batch = await coordinator.sync_batch(
            [work],
            trigger=DurabilityTrigger.PERIODIC,
        )
    finally:
        executor.shutdown(wait=True)
        stream.close_fd()

    assert batch.record_count == 1


@pytest.mark.asyncio
async def test_internal_batch_cancellation_keeps_thread_and_generation_owned(
    tmp_path: Path,
) -> None:
    loop = asyncio.get_running_loop()
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "owned-after-internal-cancel")
    executor = ThreadPoolExecutor(max_workers=1)
    sync = BlockingSync(loop, expected_starts=1)
    completions: list[object] = []
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=sync,
        executor=executor,
        completion_sink=completions.append,
    )
    public = asyncio.create_task(
        coordinator.sync_batch([work], trigger=DurabilityTrigger.PERIODIC)
    )
    try:
        await sync.wait_until_started()
        internal = next(iter(coordinator._owned_batches))
        internal.cancel("supervisor requested cancellation")
        await asyncio.sleep(0)
        internal.cancel("supervisor repeated cancellation")
        await asyncio.sleep(0)

        assert not public.done()
        assert sync.active == 1
        assert completions == []
        with pytest.raises(DuplicateFileGeneration):
            await coordinator.sync_batch(
                [work],
                trigger=DurabilityTrigger.BARRIER,
            )

        sync.release_all()
        batch = await public
    finally:
        sync.release_all()
        await asyncio.gather(public, return_exceptions=True)
        executor.shutdown(wait=True)
        stream.close_fd()

    assert batch.record_count == 1
    assert len(completions) == 1
    assert isinstance(completions[0], FileSyncCompleted)


@pytest.mark.asyncio
async def test_internal_batch_cancellation_before_start_accounts_and_releases(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "cancelled-before-start")
    executor = ThreadPoolExecutor(max_workers=1)
    completions: list[object] = []
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=NoopSync(),
        executor=executor,
        completion_sink=completions.append,
    )
    real_create_task = durability_module.asyncio.create_task
    cancelled_once = False

    def create_cancelled_task(coroutine):  # type: ignore[no-untyped-def]
        nonlocal cancelled_once
        task = real_create_task(coroutine)
        if not cancelled_once:
            cancelled_once = True
            task.cancel("cancel before first coroutine step")
        return task

    monkeypatch.setattr(
        durability_module.asyncio,
        "create_task",
        create_cancelled_task,
    )
    try:
        with pytest.raises(WriterCriticalError) as captured:
            await coordinator.sync_batch(
                [work],
                trigger=DurabilityTrigger.PERIODIC,
            )
        monkeypatch.setattr(
            durability_module.asyncio,
            "create_task",
            real_create_task,
        )
        retry = await coordinator.sync_batch(
            [work],
            trigger=DurabilityTrigger.PERIODIC,
        )
    finally:
        executor.shutdown(wait=True)
        stream.close_fd()

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert retry.record_count == 1
    assert len(completions) == 2
    assert isinstance(completions[0], FileSyncFailed)
    assert isinstance(completions[1], FileSyncCompleted)


@pytest.mark.asyncio
async def test_partial_file_task_creation_failure_accounts_every_claim(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clock = FakeClock(now_ns=100)
    first_stream, first_work = make_work(tmp_path, "task-created")
    second_stream, second_work = make_work(tmp_path, "task-not-created")
    executor = ThreadPoolExecutor(max_workers=2)
    completions: list[object] = []
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=NoopSync(),
        executor=executor,
        completion_sink=completions.append,
    )
    real_create_task = durability_module.asyncio.create_task
    call_count = 0

    def fail_second_file_task(coroutine):  # type: ignore[no-untyped-def]
        nonlocal call_count
        call_count += 1
        if call_count == 3:
            raise RuntimeError("injected partial task creation failure")
        return real_create_task(coroutine)

    monkeypatch.setattr(
        durability_module.asyncio,
        "create_task",
        fail_second_file_task,
    )
    try:
        with pytest.raises(WriterCriticalError) as captured:
            await coordinator.sync_batch(
                [first_work, second_work],
                trigger=DurabilityTrigger.PERIODIC,
            )
    finally:
        executor.shutdown(wait=True)
        first_stream.close_fd()
        second_stream.close_fd()

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert captured.value.affected_generation_ids == (second_work.generation_id,)
    assert len(completions) == 2
    assert sum(isinstance(item, FileSyncCompleted) for item in completions) == 1
    assert sum(isinstance(item, FileSyncFailed) for item in completions) == 1
    assert coordinator._inflight_generations == set()


@pytest.mark.asyncio
async def test_cancelled_queued_executor_future_emits_failure_and_releases_claim(
    tmp_path: Path,
) -> None:
    class TrackingExecutor(ThreadPoolExecutor):
        def __init__(self) -> None:
            super().__init__(max_workers=1)
            self.submission_count = 0
            self.second_submission = asyncio.Event()

        def submit(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            future = super().submit(*args, **kwargs)
            self.submission_count += 1
            if self.submission_count == 2:
                self.second_submission.set()
            return future

    blocker_release = threading.Event()
    blocker_started = threading.Event()

    def occupy_worker() -> None:
        blocker_started.set()
        if not blocker_release.wait(timeout=5):
            raise TimeoutError("executor blocker was not released")

    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "cancelled-executor-future")
    executor = TrackingExecutor()
    blocker = executor.submit(occupy_worker)
    assert blocker_started.wait(timeout=2)
    completions: list[object] = []
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=NoopSync(),
        executor=executor,
        completion_sink=completions.append,
    )
    task = asyncio.create_task(
        coordinator.sync_batch([work], trigger=DurabilityTrigger.PERIODIC)
    )
    try:
        await asyncio.wait_for(executor.second_submission.wait(), timeout=2)
        executor.shutdown(wait=False, cancel_futures=True)
        with pytest.raises(WriterCriticalError) as captured:
            await task
    finally:
        blocker_release.set()
        await asyncio.gather(task, return_exceptions=True)
        await asyncio.wrap_future(blocker)
        executor.shutdown(wait=True)
        stream.close_fd()

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert len(completions) == 1
    assert isinstance(completions[0], FileSyncFailed)
    assert coordinator._inflight_generations == set()


@pytest.mark.asyncio
async def test_fast_completion_is_emitted_before_unrelated_file_finishes(
    tmp_path: Path,
) -> None:
    loop = asyncio.get_running_loop()
    clock = FakeClock(now_ns=100)
    fast_stream, fast_work = make_work(tmp_path, "fast")
    blocked_stream, blocked_work = make_work(tmp_path, "blocked")
    executor = ThreadPoolExecutor(max_workers=2)
    sync = BlockingSync(loop, expected_starts=2)
    completions: asyncio.Queue[object] = asyncio.Queue()

    class OneFastSync:
        def sync(self, fd: int) -> None:
            if fd == fast_stream.fileno():
                return
            sync.sync(fd)

    coordinator = make_coordinator(
        clock=clock,
        sync_backend=OneFastSync(),
        executor=executor,
        completion_sink=completions.put_nowait,
    )
    task = asyncio.create_task(
        coordinator.sync_batch(
            [blocked_work, fast_work],
            trigger=DurabilityTrigger.PERIODIC,
        )
    )
    try:
        completion = await asyncio.wait_for(completions.get(), timeout=2)
        assert isinstance(completion, FileSyncCompleted)
        assert completion.result.generation_id == fast_stream.generation_id
        assert not task.done()
        sync.release_all()
        batch = await task
    finally:
        sync.release_all()
        await asyncio.gather(task, return_exceptions=True)
        executor.shutdown(wait=True)
        fast_stream.close_fd()
        blocked_stream.close_fd()

    assert tuple(item.generation_id for item in batch.files) == (
        blocked_stream.generation_id,
        fast_stream.generation_id,
    )


@pytest.mark.asyncio
async def test_one_sync_failure_waits_for_other_inflight_job(
    tmp_path: Path,
) -> None:
    loop = asyncio.get_running_loop()
    clock = FakeClock(now_ns=100)
    failed_stream, failed_work = make_work(tmp_path, "failed")
    blocked_stream, blocked_work = make_work(tmp_path, "still-running")
    executor = ThreadPoolExecutor(max_workers=2)
    blocker = BlockingSync(loop, expected_starts=1)
    failure_observed = asyncio.Event()

    class FailOneSync:
        def sync(self, fd: int) -> None:
            if fd == failed_stream.fileno():
                loop.call_soon_threadsafe(failure_observed.set)
                raise OSError(errno.EIO, "injected sync failure")
            blocker.sync(fd)

    completions: list[object] = []
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=FailOneSync(),
        executor=executor,
        completion_sink=completions.append,
    )
    task = asyncio.create_task(
        coordinator.sync_batch(
            [failed_work, blocked_work],
            trigger=DurabilityTrigger.PERIODIC,
        )
    )
    try:
        await asyncio.wait_for(failure_observed.wait(), timeout=2)
        assert not task.done()
        blocker.release_all()
        with pytest.raises(WriterCriticalError) as captured:
            await task
    finally:
        blocker.release_all()
        await asyncio.gather(task, return_exceptions=True)
        executor.shutdown(wait=True)
        failed_stream.close_fd()
        blocked_stream.close_fd()

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert len(completions) == 2
    assert sum(isinstance(item, FileSyncCompleted) for item in completions) == 1
    assert sum(isinstance(item, FileSyncFailed) for item in completions) == 1


@pytest.mark.asyncio
async def test_write_error_is_classified_before_sync(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "write-failure")
    executor = ThreadPoolExecutor(max_workers=1)
    sync_called = False
    completions: list[object] = []

    class TrackingSync:
        def sync(self, _fd: int) -> None:
            nonlocal sync_called
            sync_called = True

    def fail_write(_self: StreamFile, _pending: object) -> None:
        raise OSError(errno.ENOSPC, "injected write failure")

    monkeypatch.setattr(StreamFile, "write_frame", fail_write)
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=TrackingSync(),
        executor=executor,
        completion_sink=completions.append,
    )
    try:
        with pytest.raises(WriterCriticalError) as captured:
            await coordinator.sync_batch([work], trigger=DurabilityTrigger.PERIODIC)
    finally:
        executor.shutdown(wait=True)
        stream.close_fd()

    assert captured.value.reason is WriterCriticalReason.WRITE_FAILED
    assert sync_called is False
    assert len(completions) == 1
    assert isinstance(completions[0], FileSyncFailed)
    public_failure = completions[0].error
    assert isinstance(public_failure, FilePersistenceError)
    assert captured.value.__cause__ is public_failure
    assert public_failure.__cause__ is None
    assert public_failure.__context__ is None
    assert public_failure.__traceback__ is None
    assert not hasattr(public_failure, "original")
    assert "injected" not in str(public_failure)


@pytest.mark.asyncio
async def test_cancellation_waits_for_inflight_sync_before_propagating(
    tmp_path: Path,
) -> None:
    loop = asyncio.get_running_loop()
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "cancel")
    executor = ThreadPoolExecutor(max_workers=1)
    sync = BlockingSync(loop, expected_starts=1)
    completions: list[object] = []
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=sync,
        executor=executor,
        completion_sink=completions.append,
    )
    task = asyncio.create_task(
        coordinator.sync_batch([work], trigger=DurabilityTrigger.PERIODIC)
    )
    try:
        await sync.wait_until_started()
        task.cancel("caller stopped waiting")
        await asyncio.sleep(0)
        assert not task.done()
        assert stream.closed is False
        sync.release_all()
        with pytest.raises(asyncio.CancelledError, match="caller stopped waiting"):
            await task
    finally:
        sync.release_all()
        await asyncio.gather(task, return_exceptions=True)
        executor.shutdown(wait=True)
        stream.close_fd()

    assert len(completions) == 1
    assert isinstance(completions[0], FileSyncCompleted)


@pytest.mark.asyncio
async def test_sync_error_wins_over_repeated_cancellation_after_accounting(
    tmp_path: Path,
) -> None:
    loop = asyncio.get_running_loop()
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "cancel-and-fail")
    executor = ThreadPoolExecutor(max_workers=1)
    sync = BlockingSync(
        loop,
        expected_starts=1,
        fail_fds=frozenset({stream.fileno()}),
    )
    completions: list[object] = []
    coordinator = make_coordinator(
        clock=clock,
        sync_backend=sync,
        executor=executor,
        completion_sink=completions.append,
    )
    task = asyncio.create_task(
        coordinator.sync_batch([work], trigger=DurabilityTrigger.PERIODIC)
    )
    try:
        await sync.wait_until_started()
        task.cancel("first cancellation")
        await asyncio.sleep(0)
        task.cancel("second cancellation")
        with pytest.raises(WriterCriticalError) as captured:
            await task
    finally:
        sync.release_all()
        await asyncio.gather(task, return_exceptions=True)
        executor.shutdown(wait=True)
        stream.close_fd()

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert isinstance(captured.value.__cause__, asyncio.CancelledError)
    assert captured.value.__cause__.args == ("first cancellation",)
    assert len(completions) == 1
    assert isinstance(completions[0], FileSyncFailed)


@pytest.mark.asyncio
async def test_success_sink_failure_is_not_reemitted_as_file_failure(
    tmp_path: Path,
) -> None:
    clock = FakeClock(now_ns=100)
    stream, work = make_work(tmp_path, "sink-failure")
    executor = ThreadPoolExecutor(max_workers=1)
    emitted: list[object] = []

    def failing_sink(completion: object) -> None:
        emitted.append(completion)
        raise RuntimeError("sink violated its non-raising contract")

    coordinator = make_coordinator(
        clock=clock,
        sync_backend=NoopSync(),
        executor=executor,
        completion_sink=failing_sink,
    )
    try:
        with pytest.raises(WriterCriticalError):
            await coordinator.sync_batch([work], trigger=DurabilityTrigger.PERIODIC)
    finally:
        executor.shutdown(wait=True)
        stream.close_fd()

    assert len(emitted) == 1
    assert isinstance(emitted[0], FileSyncCompleted)


def test_portable_sync_prefers_fdatasync_and_falls_back_to_fsync(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[int] = []
    monkeypatch.delattr(durability_module.os, "fdatasync", raising=False)
    monkeypatch.setattr(durability_module.os, "fsync", called.append)

    PosixSyncBackend().sync(7)

    assert called == [7]


def test_portable_sync_prefers_fdatasync(monkeypatch: pytest.MonkeyPatch) -> None:
    fdatasync_calls: list[int] = []
    fsync_calls: list[int] = []
    monkeypatch.setattr(
        durability_module.os,
        "fdatasync",
        fdatasync_calls.append,
        raising=False,
    )
    monkeypatch.setattr(durability_module.os, "fsync", fsync_calls.append)

    PosixSyncBackend().sync(9)

    assert fdatasync_calls == [9]
    assert fsync_calls == []
