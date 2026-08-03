from __future__ import annotations

import asyncio
import gc
import hashlib
import re
import threading
import weakref
from collections.abc import Iterator
from dataclasses import replace
from itertools import groupby
from pathlib import Path
from typing import cast

import pytest

from crypto_collector.benchmarks import runner
from crypto_collector.benchmarks.artifacts import StreamingJsonlZstdWriter
from crypto_collector.benchmarks.contracts import GateAdmissionTraceV1
from crypto_collector.benchmarks.oracle import (
    PlannedEventV1,
    WorkloadPlanV1,
    build_workload_plan,
    iter_exchange_plan_events,
)
from crypto_collector.benchmarks.workload import load_workload
from crypto_collector.domain.clock import SystemClock
from crypto_collector.domain.envelope import NativeEventDraft, RestMetadata
from crypto_collector.domain.types import Exchange, Market
from crypto_collector.storage.models import (
    AcceptedRecordIdentityV1,
    EnqueueResult,
    EnqueueStatus,
)
from crypto_collector.storage.service import RawWriterService
from tests.support.writer_gate_evidence import _micro_workload_bytes

_PreparedChunk = runner._AdmissionChunk  # type: ignore[attr-defined]
_PreparedSecondChunks = tuple[_PreparedChunk, ...]
_TraceBatch = tuple[runner._AdmissionTraceSeed, ...]  # type: ignore[attr-defined]


class _AbortEvent:
    def __init__(self) -> None:
        self.requested = False

    def is_set(self) -> bool:
        return self.requested

    def set(self) -> None:
        self.requested = True


def test_admission_replay_has_bounded_chunk_and_spool_lookahead() -> None:
    assert runner._ADMISSION_QUEUE_MAX_CHUNKS == 2  # type: ignore[attr-defined]
    assert runner._SPOOL_LOOKAHEAD_SECONDS == 3  # type: ignore[attr-defined]
    assert runner._ADMISSION_CHUNK_MAX_ROWS == 1024  # type: ignore[attr-defined]
    assert runner._ADMISSION_CHUNK_MAX_PAYLOAD_BYTES == 8 * 1024 * 1024  # type: ignore[attr-defined]
    assert runner._ADMISSION_YIELD_BYTES == 1024 * 1024  # type: ignore[attr-defined]


@pytest.mark.asyncio
async def test_sleep_until_returns_its_boundary_observation_without_resampling() -> (
    None
):
    class _CountingClock:
        def __init__(self) -> None:
            self.calls = 0

        def monotonic_ns(self) -> int:
            self.calls += 1
            return 123

    clock = _CountingClock()

    observed = await runner._sleep_until(  # type: ignore[attr-defined]
        cast(SystemClock, clock),
        100,
    )

    assert observed == 123
    assert clock.calls == 1


class _FixedClock:
    def __init__(self, monotonic_ns: int) -> None:
        self._monotonic_ns = monotonic_ns

    def monotonic_ns(self) -> int:
        return self._monotonic_ns

    def time_ns(self) -> int:
        return 1_800_000_000_000_000_000


class _OverflowService:
    def __init__(self) -> None:
        self.calls = 0

    def try_accept(self, *_args: object, **_kwargs: object) -> EnqueueResult:
        self.calls += 1
        return EnqueueResult(
            status=EnqueueStatus.OVERFLOW,
            record=None,
            record_identity=None,
        )


class _AbortingService(_OverflowService):
    def __init__(self, abort_event: _AbortEvent) -> None:
        super().__init__()
        self._abort_event = abort_event

    def try_accept(self, *args: object, **kwargs: object) -> EnqueueResult:
        result = super().try_accept(*args, **kwargs)
        if self.calls == 1:
            self._abort_event.set()
        return result


class _ReleaseObservingService(_OverflowService):
    def __init__(self, first_template: weakref.ReferenceType[NativeEventDraft]) -> None:
        super().__init__()
        self._first_template = first_template
        self.first_template_released = False

    def try_accept(self, *args: object, **kwargs: object) -> EnqueueResult:
        if self.calls == 1:
            self.first_template_released = self._first_template() is None
        return super().try_accept(*args, **kwargs)


class _TraceWriterSpy:
    def __init__(self, *, write_error: BaseException | None = None) -> None:
        self.write_error = write_error
        self.rows: list[object] = []
        self.trusted_lines: list[tuple[bytes, type[object]]] = []
        self.trusted_chunks: list[tuple[bytes, type[object], int]] = []
        self.abort_errors: list[BaseException | None] = []
        self.close_called = False

    def write(self, row: object) -> None:
        if self.write_error is not None:
            raise self.write_error
        self.rows.append(row)

    def write_trusted_line(self, line: bytes, model_type: type[object]) -> None:
        if self.write_error is not None:
            raise self.write_error
        self.trusted_lines.append((line, model_type))

    def write_trusted_lines(
        self,
        chunk: bytes,
        model_type: type[object],
        *,
        row_count: int,
    ) -> None:
        if self.write_error is not None:
            raise self.write_error
        self.trusted_chunks.append((chunk, model_type, row_count))

    def abort(self, error: BaseException | None = None) -> None:
        self.abort_errors.append(error)

    def close(self) -> object:
        self.close_called = True
        return object()


def _micro_plan(tmp_path: Path) -> WorkloadPlanV1:
    workload_path = tmp_path / "micro-workload.json"
    workload_path.write_bytes(_micro_workload_bytes())
    return build_workload_plan(
        load_workload(workload_path),
        multiplier=1,
        duration_ns=10_000_000_000,
    )


def test_draft_rebase_avoids_generic_model_construction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _micro_plan(tmp_path)
    events = tuple(iter_exchange_plan_events(plan, Exchange.BINANCE))
    websocket = next(event for event in events if event.transport.value == "websocket")
    rest = next(event for event in events if event.transport.value == "rest")
    anchor = 1_800_000_000_000_000_000

    def unexpected(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("draft rebase used generic Pydantic construction")

    monkeypatch.setattr(NativeEventDraft, "model_construct", unexpected)
    monkeypatch.setattr(RestMetadata, "model_construct", unexpected)

    for event in (websocket, rest):
        prepared = runner._prepared_admission(event)  # type: ignore[attr-defined]
        rebased = runner._rebase_draft_template(  # type: ignore[attr-defined]
            prepared.draft,
            due_offset_ns=prepared.due_offset_ns,
            admission_started_utc_ns=anchor,
        )
        assert rebased.event_time_ns == anchor + event.due_offset_ns
        assert (
            NativeEventDraft.model_validate(rebased.model_dump(mode="python"))
            == rebased
        )


def _prepared_seconds(
    tmp_path: Path,
    *,
    second_count: int,
) -> tuple[
    runner._ExchangeAdmissionSpool,  # type: ignore[attr-defined]
    tuple[_PreparedSecondChunks, ...],
]:
    plan = _micro_plan(tmp_path)
    spool = runner._prepare_exchange_spool(  # type: ignore[attr-defined]
        plan,
        Exchange.BINANCE,
        tmp_path / "spool",
    )
    seconds = tuple(
        tuple(
            spool.iter_partition_chunks(  # type: ignore[attr-defined]
                spool.partitions[second_index],
                admission_started_utc_ns=0,
            )
        )
        for second_index in range(second_count)
    )
    return spool, seconds


def test_spool_partition_replay_bounds_live_rows_to_chunk_plus_lookahead(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _micro_plan(tmp_path)
    expected = next(
        tuple(events)
        for second_index, events in groupby(
            iter_exchange_plan_events(plan, Exchange.BINANCE),
            key=lambda event: event.due_offset_ns // 1_000_000_000,
        )
        if second_index == 4
    )
    spool = runner._prepare_exchange_spool(  # type: ignore[attr-defined]
        plan,
        Exchange.BINANCE,
        tmp_path / "spool-live-bound",
    )
    partition = spool.partitions[4]
    original_rebase = runner._rebase_prepared_admission  # type: ignore[attr-defined]
    live_count = 0
    peak_live_count = 0

    def tracked_rebase(
        wire: runner._PreparedAdmissionWireV1,  # type: ignore[attr-defined]
        *,
        admission_started_utc_ns: int,
    ) -> runner._PreparedAdmission:  # type: ignore[attr-defined]
        nonlocal live_count, peak_live_count
        prepared = original_rebase(
            wire,
            admission_started_utc_ns=admission_started_utc_ns,
        )
        live_count += 1
        peak_live_count = max(peak_live_count, live_count)

        def released() -> None:
            nonlocal live_count
            live_count -= 1

        weakref.finalize(prepared.draft, released)
        return prepared

    monkeypatch.setattr(runner, "_rebase_prepared_admission", tracked_rebase)
    monkeypatch.setattr(runner, "_ADMISSION_CHUNK_MAX_ROWS", 2)
    monkeypatch.setattr(runner, "_ADMISSION_CHUNK_MAX_PAYLOAD_BYTES", 10_000)
    observed_ids: list[str] = []
    observed_chunks: list[tuple[int, int, bool]] = []
    try:
        chunks = spool.iter_partition_chunks(  # type: ignore[attr-defined]
            partition,
            admission_started_utc_ns=0,
        )
        for chunk in chunks:
            observed_chunks.append(
                (chunk.chunk_index, len(chunk.rows), chunk.last_for_second)
            )
            observed_ids.extend(row.planned_event_id for row in chunk.rows)
            assert live_count <= 3
            del chunk
            gc.collect()
        del chunks
        gc.collect()
    finally:
        spool.cleanup()

    assert observed_chunks == [(0, 2, False), (1, 2, False), (2, 1, True)]
    assert observed_ids == [event.planned_event_id for event in expected]
    assert peak_live_count <= 3
    assert live_count == 0


def test_spool_partition_validates_content_digest_before_final_chunk(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _micro_plan(tmp_path)
    spool = runner._prepare_exchange_spool(  # type: ignore[attr-defined]
        plan,
        Exchange.BINANCE,
        tmp_path / "spool-final-integrity",
    )
    partition = spool.partitions[4]
    tampered_partition = replace(partition, content_sha256="0" * 64)
    tampered_spool = runner._ExchangeAdmissionSpool(  # type: ignore[attr-defined]
        root=spool.root,
        exchange=spool.exchange,
        partitions=(tampered_partition,),
        row_count=tampered_partition.row_count,
    )
    monkeypatch.setattr(runner, "_ADMISSION_CHUNK_MAX_ROWS", 2)
    monkeypatch.setattr(runner, "_ADMISSION_CHUNK_MAX_PAYLOAD_BYTES", 10_000)
    chunks = tampered_spool.iter_partition_chunks(
        tampered_partition,
        admission_started_utc_ns=0,
    )
    observed: list[runner._AdmissionChunk] = []  # type: ignore[attr-defined]
    try:
        with pytest.raises(runner.WriterGateRunError, match="content facts"):
            while True:
                observed.append(next(chunks))
    finally:
        chunks.close()
        spool.cleanup()

    assert [chunk.last_for_second for chunk in observed] == [False, False]
    assert sum(len(chunk.rows) for chunk in observed) == partition.row_count - 1


def _second_rows(
    chunks: _PreparedSecondChunks,
) -> tuple[runner._PreparedAdmission, ...]:  # type: ignore[attr-defined]
    return tuple(row for chunk in chunks for row in chunk.rows)


def _chunks_for_rows(
    second_index: int,
    rows: tuple[runner._PreparedAdmission, ...],  # type: ignore[attr-defined]
    *,
    pause_cyclic_gc: bool | None = None,
) -> _PreparedSecondChunks:
    grouped_rows: list[tuple[runner._PreparedAdmission, ...]] = []  # type: ignore[attr-defined]
    pending: list[runner._PreparedAdmission] = []  # type: ignore[attr-defined]
    pending_payload_bytes = 0
    for prepared in rows:
        if pending and (
            len(pending) >= runner._ADMISSION_CHUNK_MAX_ROWS  # type: ignore[attr-defined]
            or pending_payload_bytes + prepared.payload_bytes
            > runner._ADMISSION_CHUNK_MAX_PAYLOAD_BYTES  # type: ignore[attr-defined]
        ):
            grouped_rows.append(tuple(pending))
            pending = []
            pending_payload_bytes = 0
        pending.append(prepared)
        pending_payload_bytes += prepared.payload_bytes
    if pending or not grouped_rows:
        grouped_rows.append(tuple(pending))
    pause = (
        len(rows) >= runner._ADMISSION_GC_PAUSE_MIN_RECORDS  # type: ignore[attr-defined]
        if pause_cyclic_gc is None
        else pause_cyclic_gc
    )
    return tuple(
        runner._AdmissionChunk(  # type: ignore[attr-defined]
            second_index=second_index,
            chunk_index=chunk_index,
            rows=chunk_rows,
            payload_bytes=sum(row.payload_bytes for row in chunk_rows),
            last_for_second=chunk_index == len(grouped_rows) - 1,
            pause_cyclic_gc=pause,
        )
        for chunk_index, chunk_rows in enumerate(grouped_rows)
    )


def _ordered_burst_rows(
    template: runner._PreparedAdmission,  # type: ignore[attr-defined]
    row_count: int,
) -> tuple[runner._PreparedAdmission, ...]:  # type: ignore[attr-defined]
    return tuple(
        replace(template, planned_event_id=f"{ordinal:064x}")
        for ordinal in range(row_count)
    )


async def _completed_producer(row_count: int) -> int:
    return row_count


@pytest.mark.asyncio
async def test_child_runtime_failure_cancels_and_settles_its_sibling() -> None:
    sibling_started = asyncio.Event()
    sibling_cancelled = asyncio.Event()
    release_cleanup = asyncio.Event()
    abort_event = _AbortEvent()

    async def failing_admission() -> int:
        await sibling_started.wait()
        raise RuntimeError("injected admission failure")

    async def sampling_with_cleanup() -> None:
        sibling_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            sibling_cancelled.set()
            await release_cleanup.wait()
            raise

    admission_task = asyncio.create_task(failing_admission())
    sampling_task = asyncio.create_task(sampling_with_cleanup())
    runtime: asyncio.Task[int] | None = None
    try:
        runtime = asyncio.create_task(
            runner._gather_child_runtime_tasks(  # type: ignore[attr-defined]
                admission_task,
                sampling_task,
                abort_event=abort_event,
            )
        )
        await asyncio.wait_for(sibling_cancelled.wait(), timeout=0.5)
        assert abort_event.is_set()
        assert runtime.done() is False
        assert sampling_task.done() is False

        runtime.cancel()
        for _ in range(3):
            await asyncio.sleep(0)
        assert runtime.done() is False

        release_cleanup.set()
        with pytest.raises(RuntimeError, match="injected admission failure"):
            await runtime
    finally:
        release_cleanup.set()
        tasks = tuple(
            task
            for task in (runtime, admission_task, sampling_task)
            if task is not None
        )
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)

    assert sampling_task.cancelled()


async def _no_sleep(*args: object, **_kwargs: object) -> int:
    clock = cast(SystemClock, args[0])
    return clock.monotonic_ns()


def _trace_seed(
    *,
    accepted: bool = False,
) -> runner._AdmissionTraceSeed:  # type: ignore[attr-defined]
    identity = (
        AcceptedRecordIdentityV1(
            exchange=Exchange.BINANCE,
            market=Market.SPOT,
            instrument_key="BTC-USDT",
            logical_stream="trade",
            worker_instance_id="gate-worker-v1-binance",
            writer_sequence=0,
            acceptance_ordinal=0,
            config_sha256="3" * 64,
            config_generation=0,
        )
        if accepted
        else None
    )
    return runner._AdmissionTraceSeed(  # type: ignore[attr-defined]
        planned_event_id="1" * 64,
        stream_group="trade",
        logical_stream="trade",
        exchange=Exchange.BINANCE,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        canonical_identity="gate-identity-v1:binance:spot:BTC-USDT:trade",
        identity_index=0,
        local_sequence=0,
        due_monotonic_ns=1_000_000_000,
        deadline_monotonic_ns=2_000_000_000,
        attempt_started_monotonic_ns=1_000_000_000,
        admission_completed_monotonic_ns=1_000_000_001,
        enqueue_status=(EnqueueStatus.ACCEPTED if accepted else EnqueueStatus.OVERFLOW),
        payload_bytes=320,
        payload_sha256="2" * 64,
        accepted_identity=identity,
    )


def test_trace_seed_fast_encoder_is_exact_without_generic_model_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seeds = (_trace_seed(), _trace_seed(accepted=True))
    expected = tuple(seed.to_trace().canonical_bytes() for seed in seeds)

    def unexpected(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("trace fast encoder used the generic model path")

    monkeypatch.setattr(runner._AdmissionTraceSeed, "to_trace", unexpected)  # type: ignore[attr-defined]

    observed = tuple(
        runner._trace_seed_canonical_line(seed)  # type: ignore[attr-defined]
        for seed in seeds
    )

    assert observed == expected
    for line in observed:
        GateAdmissionTraceV1.model_validate_json(line[:-1], strict=True)


async def _invoke_admission(
    *,
    service: _OverflowService,
    prefetched: asyncio.Queue[_PreparedChunk | None],
    producer: asyncio.Task[int],
    trace_batches: asyncio.Queue[_TraceBatch | None],
    duration_seconds: int,
    expected_row_count: int,
    admission_started_monotonic_ns: int = 0,
    duration_ns: int | None = None,
    enforce_hard_schedule: bool = True,
    clock: _FixedClock | None = None,
    abort_event: _AbortEvent | None = None,
) -> int:
    return await runner._child_admit_events(  # type: ignore[attr-defined]
        service=cast(RawWriterService, service),
        exchange=Exchange.BINANCE,
        prefetched=prefetched,
        producer=producer,
        trace_batches=trace_batches,
        duration_seconds=duration_seconds,
        expected_row_count=expected_row_count,
        admission_started_monotonic_ns=admission_started_monotonic_ns,
        admission_started_utc_ns=1_800_000_000_000_000_000,
        duration_ns=(
            duration_seconds * 1_000_000_000 if duration_ns is None else duration_ns
        ),
        enforce_hard_schedule=enforce_hard_schedule,
        clock=cast(SystemClock, _FixedClock(0) if clock is None else clock),
        abort_event=_AbortEvent() if abort_event is None else abort_event,
    )


@pytest.mark.asyncio
async def test_admission_replay_waits_for_chunk_queue_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _micro_plan(tmp_path)
    first_event = next(iter_exchange_plan_events(plan, Exchange.BINANCE))
    generation_started = threading.Event()

    def observed_events(
        _plan: WorkloadPlanV1,
        _exchange: Exchange,
    ) -> Iterator[PlannedEventV1]:
        generation_started.set()
        yield first_event

    monkeypatch.setattr(runner, "iter_exchange_plan_events", observed_events)
    spool_root = (tmp_path / "producer-capacity-spool").resolve()
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue(maxsize=1)
    sentinel = _chunks_for_rows(0, ())[0]
    prefetched.put_nowait(sentinel)
    abort_event = _AbortEvent()

    task = asyncio.create_task(
        runner._produce_admission_chunks(  # type: ignore[attr-defined]
            plan,
            Exchange.BINANCE,
            prefetched,
            0,
            abort_event,
            spool_root=spool_root,
        )
    )
    try:
        assert await asyncio.to_thread(generation_started.wait, 0.5) is True
        for _ in range(3):
            await asyncio.sleep(0)
        assert task.done() is False
        assert prefetched.get_nowait() is sentinel
        prefetched.task_done()

        first_produced = await asyncio.wait_for(prefetched.get(), timeout=0.5)
        assert first_produced is not None
        assert first_produced.second_index == 0
        assert first_produced.chunk_index == 0
        prefetched.task_done()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    assert abort_event.is_set()
    assert not spool_root.exists()


@pytest.mark.asyncio
async def test_cancelled_spool_write_finishes_before_private_root_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _micro_plan(tmp_path)
    spool_root = (tmp_path / "cancelled-write-spool").resolve()
    write_started = threading.Event()
    release_write = threading.Event()
    write_finished = threading.Event()
    original_write = runner._write_spool_partition  # type: ignore[attr-defined]

    def blocked_write(
        root: Path,
        second_index: int,
        events: Iterator[PlannedEventV1],
    ) -> runner._AdmissionSpoolPartition:  # type: ignore[attr-defined]
        write_started.set()
        if not release_write.wait(timeout=2):
            raise AssertionError("test did not release the blocked spool write")
        try:
            return original_write(root, second_index, events)
        finally:
            write_finished.set()

    monkeypatch.setattr(runner, "_write_spool_partition", blocked_write)
    abort_event = _AbortEvent()
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue(
        maxsize=runner._ADMISSION_QUEUE_MAX_CHUNKS  # type: ignore[attr-defined]
    )
    producer = asyncio.create_task(
        runner._produce_admission_chunks(  # type: ignore[attr-defined]
            plan,
            Exchange.BINANCE,
            prefetched,
            0,
            abort_event,
            spool_root=spool_root,
        )
    )
    try:
        assert await asyncio.to_thread(write_started.wait, 0.5) is True
        producer.cancel()
        for _ in range(3):
            await asyncio.sleep(0)
        assert producer.done() is False
        assert spool_root.is_dir()

        producer.cancel()
        for _ in range(3):
            await asyncio.sleep(0)
        assert producer.done() is False
        assert spool_root.is_dir()

        release_write.set()
        with pytest.raises(asyncio.CancelledError):
            await producer
    finally:
        release_write.set()
        if not producer.done():
            producer.cancel()
        await asyncio.gather(producer, return_exceptions=True)

    assert write_finished.is_set()
    assert abort_event.is_set()
    assert not spool_root.exists()


@pytest.mark.asyncio
async def test_spool_open_error_does_not_leave_a_private_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _micro_plan(tmp_path)
    spool_root = (tmp_path / "open-error-spool").resolve()

    def broken_events(
        _plan: WorkloadPlanV1,
        _exchange: Exchange,
    ) -> Iterator[PlannedEventV1]:
        raise RuntimeError("injected plan iteration failure")
        yield

    monkeypatch.setattr(runner, "iter_exchange_plan_events", broken_events)

    with pytest.raises(RuntimeError, match="injected plan iteration failure"):
        await runner._produce_admission_chunks(  # type: ignore[attr-defined]
            plan,
            Exchange.BINANCE,
            asyncio.Queue(maxsize=1),
            0,
            _AbortEvent(),
            spool_root=spool_root,
        )

    assert not spool_root.exists()


@pytest.mark.parametrize(
    ("max_rows", "max_payload_bytes"),
    ((2, 10_000), (100, 700)),
)
@pytest.mark.asyncio
async def test_admission_producer_chunks_a_large_second_without_changing_schedule(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    max_rows: int,
    max_payload_bytes: int,
) -> None:
    plan = _micro_plan(tmp_path)
    original = tuple(iter_exchange_plan_events(plan, Exchange.BINANCE))
    shifted = tuple(
        sorted(
            (
                event.model_copy(
                    update={
                        "due_offset_ns": 0,
                        "deadline_offset_ns": 1_000_000_000,
                    }
                )
                for event in original
            ),
            key=lambda event: (event.due_offset_ns, event.planned_event_id),
        )
    )

    def one_large_second(
        _plan: WorkloadPlanV1,
        _exchange: Exchange,
    ) -> Iterator[PlannedEventV1]:
        yield from shifted

    monkeypatch.setattr(runner, "iter_exchange_plan_events", one_large_second)
    monkeypatch.setattr(runner, "_ADMISSION_CHUNK_MAX_ROWS", max_rows, raising=False)
    monkeypatch.setattr(
        runner,
        "_ADMISSION_CHUNK_MAX_PAYLOAD_BYTES",
        max_payload_bytes,
        raising=False,
    )
    spool_root = (tmp_path / f"producer-chunk-spool-{max_rows}").resolve()
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue(maxsize=1)
    producer = asyncio.create_task(
        runner._produce_admission_chunks(  # type: ignore[attr-defined]
            plan,
            Exchange.BINANCE,
            prefetched,
            0,
            _AbortEvent(),
            spool_root=spool_root,
        )
    )
    chunks: list[_PreparedChunk] = []
    while True:
        item = await prefetched.get()
        prefetched.task_done()
        if item is None:
            break
        chunks.append(item)
    produced_count = await producer

    second_zero = [chunk for chunk in chunks if chunk.second_index == 0]
    assert len(second_zero) > 1
    assert tuple(chunk.second_index for chunk in chunks) == tuple(
        sorted(chunk.second_index for chunk in chunks)
    )
    for second_index in range(plan.duration_seconds):
        second_chunks = [
            chunk for chunk in chunks if chunk.second_index == second_index
        ]
        assert second_chunks
        assert tuple(chunk.last_for_second for chunk in second_chunks) == (
            (False,) * (len(second_chunks) - 1) + (True,)
        )
        assert tuple(chunk.chunk_index for chunk in second_chunks) == tuple(
            range(len(second_chunks))
        )
        for chunk in second_chunks:
            rows = chunk.rows
            assert len(rows) <= max_rows
            assert sum(row.payload_bytes for row in rows) <= max_payload_bytes
            assert chunk.payload_bytes == sum(row.payload_bytes for row in rows)
            assert all(
                row.due_offset_ns // 1_000_000_000 == second_index for row in rows
            )
    flattened = tuple(row.planned_event_id for chunk in chunks for row in chunk.rows)
    assert flattened == tuple(event.planned_event_id for event in shifted)
    assert produced_count == len(shifted)
    assert not spool_root.exists()


@pytest.mark.asyncio
async def test_child_admission_returns_count_and_releases_prior_second_seeds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool, seconds = _prepared_seconds(tmp_path, second_count=5)
    event_seconds = {
        row.planned_event_id: chunk.second_index
        for chunks in seconds
        for chunk in chunks
        for row in chunk.rows
    }
    live_by_second: dict[int, int] = {}
    retained_prior_seed = False
    seed_fields = tuple(runner._AdmissionTraceSeed.__dataclass_fields__)  # type: ignore[attr-defined]

    class _TrackedSeed:
        def __init__(self, *ordered_values: object) -> None:
            nonlocal retained_prior_seed
            values = dict(zip(seed_fields, ordered_values, strict=True))
            self.__dict__.update(values)
            second_index = event_seconds[str(values["planned_event_id"])]
            if any(
                live_count and prior_second < second_index
                for prior_second, live_count in live_by_second.items()
            ):
                retained_prior_seed = True
            live_by_second[second_index] = live_by_second.get(second_index, 0) + 1
            self._second_index = second_index

        def __del__(self) -> None:
            second_index = self._second_index
            live_by_second[second_index] -= 1

    monkeypatch.setattr(runner, "_AdmissionTraceSeed", _TrackedSeed)
    monkeypatch.setattr(runner, "_sleep_until", _no_sleep)
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue()
    for chunks in seconds:
        for chunk in chunks:
            prefetched.put_nowait(chunk)
    prefetched.put_nowait(None)
    expected_count = sum(len(chunk.rows) for chunks in seconds for chunk in chunks)
    producer = asyncio.create_task(_completed_producer(expected_count))
    trace_batches: asyncio.Queue[_TraceBatch | None] = asyncio.Queue(maxsize=1)

    async def drain_trace_batches() -> None:
        while True:
            batch = await trace_batches.get()
            trace_batches.task_done()
            if batch is None:
                return
            del batch
            await asyncio.sleep(0)

    drain = asyncio.create_task(drain_trace_batches())
    try:
        attempted, _ = await asyncio.gather(
            _invoke_admission(
                service=_OverflowService(),
                prefetched=prefetched,
                producer=producer,
                trace_batches=trace_batches,
                duration_seconds=len(seconds),
                expected_row_count=expected_count,
            ),
            drain,
        )
    finally:
        spool.cleanup()

    assert retained_prior_seed is False
    assert type(attempted) is int
    assert attempted == expected_count


@pytest.mark.asyncio
async def test_child_admission_releases_each_prepared_template_after_rebase(
    tmp_path: Path,
) -> None:
    spool, seconds = _prepared_seconds(tmp_path, second_count=5)
    rows = tuple(
        sorted(
            (
                replace(
                    prepared,
                    due_offset_ns=0,
                    deadline_offset_ns=1_000_000_000,
                )
                for prepared in _second_rows(seconds[4])[:2]
            ),
            key=lambda prepared: prepared.planned_event_id,
        )
    )
    chunks = _chunks_for_rows(0, rows)
    first_template = weakref.ref(chunks[0].rows[0].draft)
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue()
    for chunk in chunks:
        prefetched.put_nowait(chunk)
    prefetched.put_nowait(None)
    producer = asyncio.create_task(_completed_producer(2))
    service = _ReleaseObservingService(first_template)
    del chunk, chunks, seconds, rows

    try:
        attempted = await _invoke_admission(
            service=service,
            prefetched=prefetched,
            producer=producer,
            trace_batches=asyncio.Queue(maxsize=2),
            duration_seconds=1,
            expected_row_count=2,
            duration_ns=10_000_000_000,
            clock=_FixedClock(9_999_999_999),
        )
    finally:
        spool.cleanup()

    assert attempted == 2
    assert service.first_template_released is True


@pytest.mark.asyncio
async def test_child_admission_emits_compact_per_second_trace_batches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool, seconds = _prepared_seconds(tmp_path, second_count=5)
    monkeypatch.setattr(runner, "_sleep_until", _no_sleep)
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue()
    for chunks in seconds:
        for chunk in chunks:
            prefetched.put_nowait(chunk)
    prefetched.put_nowait(None)
    expected_count = sum(len(chunk.rows) for chunks in seconds for chunk in chunks)
    producer = asyncio.create_task(_completed_producer(expected_count))
    trace_batches: asyncio.Queue[_TraceBatch | None] = asyncio.Queue(maxsize=8)
    try:
        attempted = await _invoke_admission(
            service=_OverflowService(),
            prefetched=prefetched,
            producer=producer,
            trace_batches=trace_batches,
            duration_seconds=len(seconds),
            expected_row_count=expected_count,
        )
    finally:
        spool.cleanup()

    batches: list[_TraceBatch] = []
    while not trace_batches.empty():
        batch = trace_batches.get_nowait()
        trace_batches.task_done()
        if batch is not None:
            batches.append(batch)
    nonempty_batches = tuple(batch for batch in batches if batch)

    assert type(attempted) is int and attempted == expected_count
    assert sum(len(batch) for batch in nonempty_batches) == expected_count
    assert len(nonempty_batches) == 2
    for batch in nonempty_batches:
        assert len({seed.due_monotonic_ns // 1_000_000_000 for seed in batch}) == 1
        for seed in batch:
            assert not hasattr(seed, "draft")
            assert not hasattr(seed, "source")
            assert not hasattr(seed, "payload")


@pytest.mark.asyncio
async def test_chunked_admission_trace_preserves_canonical_sha_and_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _micro_plan(tmp_path)
    original = tuple(iter_exchange_plan_events(plan, Exchange.BINANCE))
    shifted = tuple(
        sorted(
            (
                event.model_copy(
                    update={
                        "due_offset_ns": 0,
                        "deadline_offset_ns": 1_000_000_000,
                    }
                )
                for event in original
            ),
            key=lambda event: (event.due_offset_ns, event.planned_event_id),
        )
    )

    def one_large_second(
        _plan: WorkloadPlanV1,
        _exchange: Exchange,
    ) -> Iterator[PlannedEventV1]:
        yield from shifted

    monkeypatch.setattr(runner, "iter_exchange_plan_events", one_large_second)
    monkeypatch.setattr(runner, "_ADMISSION_CHUNK_MAX_ROWS", 2, raising=False)
    monkeypatch.setattr(
        runner,
        "_ADMISSION_CHUNK_MAX_PAYLOAD_BYTES",
        10_000,
        raising=False,
    )
    monkeypatch.setattr(runner, "_sleep_until", _no_sleep)
    spool_root = (tmp_path / "trace-chunk-spool").resolve()
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue(maxsize=1)
    trace_batches: asyncio.Queue[_TraceBatch | None] = asyncio.Queue(maxsize=1)
    producer = asyncio.create_task(
        runner._produce_admission_chunks(  # type: ignore[attr-defined]
            plan,
            Exchange.BINANCE,
            prefetched,
            0,
            _AbortEvent(),
            spool_root=spool_root,
        )
    )
    observed_batches: list[_TraceBatch] = []

    async def drain_trace_batches() -> None:
        while True:
            batch = await trace_batches.get()
            trace_batches.task_done()
            if batch is None:
                return
            observed_batches.append(batch)

    attempted, _ = await asyncio.gather(
        _invoke_admission(
            service=_OverflowService(),
            prefetched=prefetched,
            producer=producer,
            trace_batches=trace_batches,
            duration_seconds=plan.duration_seconds,
            expected_row_count=len(shifted),
        ),
        drain_trace_batches(),
    )

    observed = tuple(seed for batch in observed_batches for seed in batch)
    expected = tuple(
        runner._AdmissionTraceSeed(  # type: ignore[attr-defined]
            prepared.planned_event_id,
            prepared.stream_group,
            prepared.logical_stream,
            prepared.exchange,
            prepared.market,
            prepared.instrument_key,
            prepared.canonical_identity,
            prepared.identity_index,
            prepared.local_sequence,
            prepared.due_offset_ns,
            prepared.deadline_offset_ns,
            prepared.due_offset_ns,
            prepared.due_offset_ns,
            EnqueueStatus.OVERFLOW,
            prepared.payload_bytes,
            prepared.payload_sha256,
            None,
        )
        for prepared in (
            runner._prepared_admission(event)
            for event in shifted  # type: ignore[attr-defined]
        )
    )
    observed_bytes = b"".join(
        runner._trace_seed_canonical_line(seed)
        for seed in observed  # type: ignore[attr-defined]
    )
    expected_bytes = b"".join(
        runner._trace_seed_canonical_line(seed)
        for seed in expected  # type: ignore[attr-defined]
    )

    assert attempted == len(observed) == len(expected) == len(shifted)
    assert (
        hashlib.sha256(observed_bytes).hexdigest()
        == hashlib.sha256(expected_bytes).hexdigest()
    )
    assert observed_bytes == expected_bytes
    nonempty = tuple(batch for batch in observed_batches if batch)
    assert len(nonempty) > 1
    assert all(len(batch) <= 2 for batch in nonempty)
    assert all(
        sum(seed.payload_bytes for seed in batch) <= 10_000 for batch in nonempty
    )
    assert not spool_root.exists()


@pytest.mark.asyncio
async def test_due_admission_bypasses_async_wait_and_bounds_abort_polling(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool, seconds = _prepared_seconds(tmp_path, second_count=1)
    prepared = _second_rows(seconds[0])[0]
    row_count = runner._ADMISSION_GC_PAUSE_MIN_RECORDS + 1  # type: ignore[attr-defined]
    chunks = _chunks_for_rows(0, _ordered_burst_rows(prepared, row_count))
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue()
    for chunk in chunks:
        prefetched.put_nowait(chunk)
    producer = asyncio.create_task(_completed_producer(row_count))
    abort_event = _AbortEvent()
    service = _AbortingService(abort_event)
    gc_calls: list[str] = []

    async def unexpected_wait(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("already-due admission entered the async wait path")

    monkeypatch.setattr(runner, "_sleep_until", unexpected_wait)
    monkeypatch.setattr(runner.gc, "isenabled", lambda: True)  # type: ignore[attr-defined]
    monkeypatch.setattr(runner.gc, "disable", lambda: gc_calls.append("disable"))  # type: ignore[attr-defined]
    monkeypatch.setattr(runner.gc, "enable", lambda: gc_calls.append("enable"))  # type: ignore[attr-defined]
    try:
        with pytest.raises(runner.WriterGateRunError, match="globally aborted"):
            await _invoke_admission(
                service=service,
                prefetched=prefetched,
                producer=producer,
                trace_batches=asyncio.Queue(maxsize=2),
                duration_seconds=1,
                expected_row_count=row_count,
                clock=_FixedClock(999_999_999),
                abort_event=abort_event,
            )
    finally:
        spool.cleanup()

    assert service.calls == runner._ADMISSION_ABORT_CHECK_RECORDS  # type: ignore[attr-defined]
    assert gc_calls == ["disable", "enable"]


@pytest.mark.asyncio
async def test_equal_due_burst_restores_gc_after_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool, seconds = _prepared_seconds(tmp_path, second_count=1)
    prepared = _second_rows(seconds[0])[0]
    row_count = runner._ADMISSION_GC_PAUSE_MIN_RECORDS  # type: ignore[attr-defined]
    chunks = _chunks_for_rows(0, _ordered_burst_rows(prepared, row_count))
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue()
    for chunk in chunks:
        prefetched.put_nowait(chunk)
    prefetched.put_nowait(None)
    producer = asyncio.create_task(_completed_producer(row_count))
    gc_calls: list[str] = []
    monkeypatch.setattr(runner.gc, "isenabled", lambda: True)  # type: ignore[attr-defined]
    monkeypatch.setattr(runner.gc, "disable", lambda: gc_calls.append("disable"))  # type: ignore[attr-defined]
    monkeypatch.setattr(runner.gc, "enable", lambda: gc_calls.append("enable"))  # type: ignore[attr-defined]

    try:
        attempted = await _invoke_admission(
            service=_OverflowService(),
            prefetched=prefetched,
            producer=producer,
            trace_batches=asyncio.Queue(),
            duration_seconds=1,
            expected_row_count=row_count,
            clock=_FixedClock(999_999_999),
        )
    finally:
        spool.cleanup()

    assert attempted == row_count
    assert gc_calls == ["disable", "enable"]


@pytest.mark.asyncio
async def test_equal_due_burst_restores_gc_after_cancellation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool, seconds = _prepared_seconds(tmp_path, second_count=1)
    prepared = _second_rows(seconds[0])[0]
    row_count = runner._ADMISSION_GC_PAUSE_MIN_RECORDS  # type: ignore[attr-defined]
    chunks = _chunks_for_rows(0, _ordered_burst_rows(prepared, row_count))
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue()
    for chunk in chunks:
        prefetched.put_nowait(chunk)
    producer = asyncio.create_task(_completed_producer(row_count))
    wait_started = asyncio.Event()
    gc_calls: list[str] = []

    async def blocked_wait(*_args: object, **_kwargs: object) -> int:
        wait_started.set()
        await asyncio.Event().wait()
        raise AssertionError("cancelled wait resumed")

    monkeypatch.setattr(runner, "_sleep_until", blocked_wait)
    monkeypatch.setattr(runner.gc, "isenabled", lambda: True)  # type: ignore[attr-defined]
    monkeypatch.setattr(runner.gc, "disable", lambda: gc_calls.append("disable"))  # type: ignore[attr-defined]
    monkeypatch.setattr(runner.gc, "enable", lambda: gc_calls.append("enable"))  # type: ignore[attr-defined]
    admission = asyncio.create_task(
        _invoke_admission(
            service=_OverflowService(),
            prefetched=prefetched,
            producer=producer,
            trace_batches=asyncio.Queue(maxsize=2),
            duration_seconds=1,
            expected_row_count=row_count,
            admission_started_monotonic_ns=1,
            clock=_FixedClock(0),
        )
    )
    try:
        await wait_started.wait()
        admission.cancel()
        with pytest.raises(asyncio.CancelledError):
            await admission
    finally:
        spool.cleanup()

    assert gc_calls == ["disable", "enable"]


@pytest.mark.asyncio
async def test_trace_batch_writer_keeps_successful_trace_partial_until_caller_publish() -> (
    None
):
    batches: asyncio.Queue[_TraceBatch | None] = asyncio.Queue(maxsize=2)
    batches.put_nowait((_trace_seed(),))
    batches.put_nowait(None)
    writer = _TraceWriterSpy()

    written = await runner._write_trace_batches(  # type: ignore[attr-defined]
        cast(StreamingJsonlZstdWriter, writer),
        batches,
        _AbortEvent(),
    )

    assert written == 1
    assert writer.rows == []
    assert writer.trusted_lines == []
    assert writer.trusted_chunks == [
        (
            _trace_seed().to_trace().canonical_bytes(),
            GateAdmissionTraceV1,
            1,
        )
    ]
    assert writer.abort_errors == []
    assert writer.close_called is False


@pytest.mark.asyncio
async def test_trace_batch_writer_failure_aborts_without_final_publication() -> None:
    injected = RuntimeError("injected trace write failure")
    batches: asyncio.Queue[_TraceBatch | None] = asyncio.Queue(maxsize=2)
    batches.put_nowait((_trace_seed(),))
    batches.put_nowait(None)
    writer = _TraceWriterSpy(write_error=injected)

    with pytest.raises(RuntimeError, match="injected trace write failure"):
        await runner._write_trace_batches(  # type: ignore[attr-defined]
            cast(StreamingJsonlZstdWriter, writer),
            batches,
            _AbortEvent(),
        )

    assert writer.abort_errors == [injected]
    assert writer.close_called is False


@pytest.mark.asyncio
async def test_trace_batch_writer_releases_batch_while_waiting_for_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _TrackedSeed:
        pass

    def observed_write(
        _writer: object,
        batch: tuple[object, ...],
        _abort_event: object,
    ) -> int:
        return len(batch)

    monkeypatch.setattr(runner, "_write_trace_seed_batch", observed_write)
    tracked = _TrackedSeed()
    tracked_ref = weakref.ref(tracked)
    batch = cast(_TraceBatch, (tracked,))
    batches: asyncio.Queue[_TraceBatch | None] = asyncio.Queue(maxsize=1)
    batches.put_nowait(batch)
    del batch, tracked
    writer_task = asyncio.create_task(
        runner._write_trace_batches(  # type: ignore[attr-defined]
            cast(StreamingJsonlZstdWriter, _TraceWriterSpy()),
            batches,
            _AbortEvent(),
        )
    )
    try:
        await batches.join()
        gc.collect()
        assert tracked_ref() is None
        batches.put_nowait(None)
        assert await writer_task == 1
    finally:
        if not writer_task.done():
            writer_task.cancel()
        await asyncio.gather(writer_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_admission_boundary_error_contains_actionable_coordinates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool, seconds = _prepared_seconds(tmp_path, second_count=1)
    monkeypatch.setattr(runner, "_sleep_until", _no_sleep)
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue()
    for chunk in seconds[0]:
        prefetched.put_nowait(chunk)
    prefetched.put_nowait(None)
    expected_count = sum(len(chunk.rows) for chunk in seconds[0])
    producer = asyncio.create_task(_completed_producer(expected_count))
    service = _OverflowService()
    start = 123
    duration_ns = 1_000_000_000

    try:
        with pytest.raises(runner.WriterGateRunError) as captured:
            await _invoke_admission(
                service=service,
                prefetched=prefetched,
                producer=producer,
                trace_batches=asyncio.Queue(maxsize=2),
                duration_seconds=1,
                expected_row_count=expected_count,
                admission_started_monotonic_ns=start,
                duration_ns=duration_ns,
                enforce_hard_schedule=True,
                clock=_FixedClock(start + duration_ns + 7),
            )
    finally:
        spool.cleanup()

    message = str(captured.value)
    assert "binance" in message
    assert re.search(r"second(?:_index)?\s*[=:]\s*0", message)
    assert re.search(r"attempted\s*[=:]\s*0", message)
    assert "overrun" in message and "7" in message
    assert service.calls == 0


@pytest.mark.asyncio
async def test_functional_admission_finishes_complete_plan_after_scheduled_end(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spool, seconds = _prepared_seconds(tmp_path, second_count=1)
    monkeypatch.setattr(runner, "_sleep_until", _no_sleep)
    prefetched: asyncio.Queue[_PreparedChunk | None] = asyncio.Queue()
    for chunk in seconds[0]:
        prefetched.put_nowait(chunk)
    prefetched.put_nowait(None)
    expected_count = sum(len(chunk.rows) for chunk in seconds[0])
    producer = asyncio.create_task(_completed_producer(expected_count))
    trace_batches: asyncio.Queue[_TraceBatch | None] = asyncio.Queue()
    service = _OverflowService()
    start = 123
    duration_ns = 1_000_000_000
    observed = start + duration_ns + 7

    try:
        attempted = await _invoke_admission(
            service=service,
            prefetched=prefetched,
            producer=producer,
            trace_batches=trace_batches,
            duration_seconds=1,
            expected_row_count=expected_count,
            admission_started_monotonic_ns=start,
            duration_ns=duration_ns,
            enforce_hard_schedule=False,
            clock=_FixedClock(observed),
        )
    finally:
        spool.cleanup()

    seeds: list[runner._AdmissionTraceSeed] = []  # type: ignore[attr-defined]
    saw_terminal = False
    while not trace_batches.empty():
        batch = trace_batches.get_nowait()
        trace_batches.task_done()
        if batch is None:
            saw_terminal = True
        else:
            seeds.extend(batch)

    assert attempted == expected_count == service.calls == len(seeds)
    assert saw_terminal is True
    assert all(seed.attempt_started_monotonic_ns == observed for seed in seeds)
    assert all(seed.admission_completed_monotonic_ns == observed for seed in seeds)
