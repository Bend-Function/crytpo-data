from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable
from typing import Any, Protocol, cast

from crypto_collector.domain import (
    CloseReason,
    CoverageMode,
    Exchange,
    Market,
    NativeEventDraft,
    SourceContext,
    Transport,
)
from crypto_collector.domain.clock import Clock, SystemClock
from crypto_collector.domain.json_codec import JsonPayload
from crypto_collector.exchanges import (
    AdapterPlan,
    CollectionRequest,
    ExchangeContractError,
    StreamExpectation,
)
from crypto_collector.runtime.messages import FatalWriterSignal, WorkerStatus
from crypto_collector.runtime.state import WorkerState
from crypto_collector.storage import (
    AsyncioSleeper,
    AsyncSleeper,
    EnqueueResult,
    EnqueueStatus,
)
from crypto_collector.storage.durability import WriterCriticalError
from crypto_collector.storage.errors import RecoveryBlocked

logger = logging.getLogger(__name__)

_UTC_HOUR_NS = 3_600_000_000_000


class WriterPort(Protocol):
    def try_accept(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> EnqueueResult: ...

    async def mark_incomplete(self, reason: str) -> None: ...

    async def close_all(
        self,
        reason: CloseReason,
        deadline_ns: int,
    ) -> tuple[object, ...]: ...


class WorkerAdapter(Protocol):
    exchange: Exchange

    def plan(self, request: CollectionRequest) -> AdapterPlan: ...

    async def run(
        self,
        plan: AdapterPlan,
        runtime: Any,
        sink: PlanBoundEventSink,
    ) -> None: ...


class WorkerStopToken:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    def is_set(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()

    def set(self) -> None:
        self._event.set()


def _expectation_key(
    expectation: StreamExpectation,
) -> tuple[Market | None, str | None, str, str]:
    return expectation.key


class PlanBoundEventSink:
    def __init__(
        self,
        plan: AdapterPlan,
        *,
        writer: WriterPort,
        on_fatal: Callable[[str], None],
    ) -> None:
        if type(plan) is not AdapterPlan:
            raise TypeError("plan must be AdapterPlan")
        if not callable(getattr(writer, "try_accept", None)):
            raise TypeError("writer must provide try_accept()")
        if not callable(on_fatal):
            raise TypeError("on_fatal must be callable")
        self._exchange = plan.exchange
        self._writer = writer
        self._on_fatal = on_fatal
        self._expectations = {
            _expectation_key(expectation): expectation
            for expectation in plan.expectations
        }
        self._gap_count = 0
        self._stopped_reason: str | None = None

    @property
    def gap_count(self) -> int:
        return self._gap_count

    @property
    def stopped_reason(self) -> str | None:
        return self._stopped_reason

    def stop_accepting(self, reason: str) -> None:
        if type(reason) is not str or not reason:
            raise ValueError("stop reason must be a non-empty string")
        if self._stopped_reason is None:
            self._stopped_reason = reason

    def _fail(self, reason: str) -> None:
        first_failure = self._stopped_reason is None
        self.stop_accepting(reason)
        if first_failure:
            self._on_fatal(reason)

    @staticmethod
    def _not_accepting() -> EnqueueResult:
        return EnqueueResult(
            status=EnqueueStatus.NOT_ACCEPTING,
            record=None,
            record_identity=None,
        )

    def try_emit(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> EnqueueResult:
        if type(draft) is not NativeEventDraft:
            raise TypeError("draft must be NativeEventDraft")
        if draft.exchange is not self._exchange:
            raise ExchangeContractError("event exchange does not match adapter plan")
        if self._stopped_reason is not None:
            return self._not_accepting()
        key = (draft.market, draft.instrument_key, draft.logical_stream, shard)
        expectation = self._expectations.get(key)
        if expectation is None:
            raise ExchangeContractError(
                "emitted event has no matching stream expectation and shard"
            )
        actual_coverage = draft.coverage or CoverageMode.COMPLETE
        if actual_coverage is not expectation.coverage:
            raise ExchangeContractError("event coverage does not match expectation")

        try:
            result = self._writer.try_accept(draft, source=source, shard=shard)
        except WriterCriticalError:
            self._fail("writer_critical")
            raise
        if result.status is EnqueueStatus.OVERFLOW:
            self._gap_count += 1
            self._record_queue_overflow(draft, source)
        elif result.status is EnqueueStatus.CONTROL_OVERFLOW:
            self._fail("control_overflow")
        elif result.status is EnqueueStatus.NOT_ACCEPTING:
            self._fail("writer_not_accepting")
        return result

    def _record_queue_overflow(
        self,
        draft: NativeEventDraft,
        source: SourceContext,
    ) -> None:
        control_key = (None, None, "_control", "_control")
        if control_key not in self._expectations:
            self._fail("control_expectation_missing")
            return
        control = NativeEventDraft(
            exchange=self._exchange,
            market=None,
            instrument_key=None,
            wire_symbol=None,
            logical_stream="_control",
            native_channel=None,
            transport=Transport.INTERNAL,
            event_time_ns=None,
            event_time_source=None,
            payload={
                "kind": "queue_overflow",
                "market": None if draft.market is None else draft.market.value,
                "instrument_key": draft.instrument_key,
                "logical_stream": draft.logical_stream,
                "connection_id": source.connection_id,
                "connection_generation": source.connection_generation,
                "egress_id": source.egress_id,
            },
        )
        try:
            control_result = self._writer.try_accept(
                control,
                source=SourceContext.internal(),
                shard="_control",
            )
        except WriterCriticalError:
            self._fail("writer_critical")
            raise
        if control_result.status in {
            EnqueueStatus.OVERFLOW,
            EnqueueStatus.CONTROL_OVERFLOW,
        }:
            self._fail("control_overflow")
        elif control_result.status is EnqueueStatus.NOT_ACCEPTING:
            self._fail("writer_not_accepting")


WriterFactory = Callable[..., Awaitable[WriterPort]]
RuntimeFactory = Callable[[WorkerStopToken], Any | Awaitable[Any]]


class ExchangeWorker:
    def __init__(
        self,
        *,
        exchange: Exchange,
        worker_instance_id: str,
        request: CollectionRequest,
        adapter: WorkerAdapter,
        writer_factory: WriterFactory,
        runtime_factory: RuntimeFactory,
        clock: Clock | None = None,
        checkpoint_sleeper: AsyncSleeper | None = None,
    ) -> None:
        if type(exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        if type(worker_instance_id) is not str or not worker_instance_id:
            raise ValueError("worker_instance_id must be a non-empty string")
        if type(request) is not CollectionRequest or request.exchange is not exchange:
            raise ValueError("collection request must match worker exchange")
        if getattr(adapter, "exchange", None) is not exchange:
            raise ValueError("adapter must match worker exchange")
        if not callable(writer_factory) or not callable(runtime_factory):
            raise TypeError("worker factories must be callable")
        selected_clock = SystemClock() if clock is None else clock
        if not callable(getattr(selected_clock, "time_ns", None)) or not callable(
            getattr(selected_clock, "monotonic_ns", None)
        ):
            raise TypeError("clock must implement time_ns() and monotonic_ns()")
        selected_sleeper = (
            AsyncioSleeper() if checkpoint_sleeper is None else checkpoint_sleeper
        )
        if not callable(getattr(selected_sleeper, "sleep_ns", None)):
            raise TypeError("checkpoint_sleeper must implement sleep_ns()")

        self.exchange = exchange
        self.worker_instance_id = worker_instance_id
        self._request = request
        self.adapter = adapter
        self._writer_factory = writer_factory
        self._runtime_factory = runtime_factory
        self.clock = selected_clock
        self._checkpoint_sleeper = selected_sleeper
        self._state = WorkerState.STARTING
        self._state_changed = asyncio.Condition()
        self._lifecycle_lock = asyncio.Lock()
        self._stop_requested = False
        self._last_failure: str | None = None
        self._exit_code: int | None = None
        self._writer_terminal = False
        self._incomplete_marked = False
        self._expectation_start_ns: int | None = None
        self._writer: WriterPort | None = None
        self._runtime: Any = None
        self._plan: AdapterPlan | None = None
        self._sink: PlanBoundEventSink | None = None
        self._stop = WorkerStopToken()
        self._fatal_queue: asyncio.Queue[FatalWriterSignal] = asyncio.Queue()
        self._fatal_pending = False
        self._adapter_task: asyncio.Task[None] | None = None
        self._adapter_watch_task: asyncio.Task[None] | None = None
        self._fatal_task: asyncio.Task[None] | None = None
        self._checkpoint_task: asyncio.Task[None] | None = None
        self._closed_manifests: tuple[object, ...] | None = None

    @property
    def state(self) -> WorkerState:
        return self._state

    @property
    def exit_code(self) -> int | None:
        return self._exit_code

    @property
    def plan(self) -> AdapterPlan | None:
        return self._plan

    def status(self) -> WorkerStatus:
        return WorkerStatus(
            exchange=self.exchange,
            worker_instance_id=self.worker_instance_id,
            state=self._state,
            config_sha256=self._request.config_sha256,
            gap_count=0 if self._sink is None else self._sink.gap_count,
            last_failure=self._last_failure,
            exit_code=self._exit_code,
        )

    async def _transition(self, state: WorkerState) -> None:
        async with self._state_changed:
            self._state = state
            self._state_changed.notify_all()

    def _signal_fatal(self, reason: str) -> None:
        if self._fatal_pending or self._state in {
            WorkerState.STOPPING,
            WorkerState.STOPPED,
        }:
            return
        self._fatal_pending = True
        self._fatal_queue.put_nowait(FatalWriterSignal(reason))

    def _on_writer_critical(self, error: BaseException) -> None:
        del error
        self._writer_terminal = True
        if self._sink is not None:
            self._sink.stop_accepting("writer_critical")
        if not self._incomplete_marked:
            self._signal_fatal("writer_critical")

    async def start(self) -> None:
        async with self._lifecycle_lock:
            await self._start_locked()

    async def _start_locked(self) -> None:
        if self._state is not WorkerState.STARTING:
            raise RuntimeError("worker may be started exactly once")
        try:
            writer = await self._writer_factory(on_critical=self._on_writer_critical)
        except RecoveryBlocked:
            self._last_failure = "storage_recovery_blocked"
            await self._transition(WorkerState.PAUSED_WRITER)
            return
        except Exception:  # noqa: BLE001 - storage open is a process boundary.
            self._last_failure = "storage_open_failed"
            await self._transition(WorkerState.PAUSED_WRITER)
            return
        self._writer = writer
        if self._stop_requested:
            return

        try:
            runtime_candidate = self._runtime_factory(self._stop)
            self._runtime = (
                await cast(Awaitable[Any], runtime_candidate)
                if inspect.isawaitable(runtime_candidate)
                else runtime_candidate
            )
            if getattr(self._runtime, "stop", None) is not self._stop:
                raise ValueError("runtime must use the worker stop token")
        except Exception:  # noqa: BLE001 - network setup is an isolation boundary.
            await self._fail_prepare("runtime_prepare_failed")
            return
        if self._stop_requested:
            return
        try:
            plan = self.adapter.plan(self._request)
        except Exception:  # noqa: BLE001 - adapter planning is an isolation boundary.
            await self._fail_prepare("adapter_plan_failed")
            return
        if type(plan) is not AdapterPlan or plan.exchange is not self.exchange:
            await self._fail_prepare("adapter_plan_invalid")
            return
        control_expectation = next(
            (
                expectation
                for expectation in plan.expectations
                if expectation.key == (None, None, "_control", "_control")
            ),
            None,
        )
        if control_expectation is None:
            await self._fail_prepare("control_expectation_missing")
            return
        if control_expectation.coverage is not CoverageMode.COMPLETE:
            await self._fail_prepare("control_expectation_invalid")
            return
        self._plan = plan
        sink = PlanBoundEventSink(
            plan,
            writer=writer,
            on_fatal=self._signal_fatal,
        )
        self._sink = sink
        checkpoint_start_ns = self.clock.time_ns()
        try:
            checkpoint = sink.try_emit(
                self._expectation_checkpoint(
                    plan,
                    effective_start_ns=checkpoint_start_ns,
                ),
                source=SourceContext.internal(),
                shard="_control",
            )
        except WriterCriticalError:
            await self._pause_writer_locked("writer_critical")
            return
        except Exception:  # noqa: BLE001 - checkpoint is a prepare boundary.
            await self._pause_writer_locked("expectation_checkpoint_failed")
            return
        if not checkpoint.accepted:
            reason = (
                "writer_not_accepting"
                if checkpoint.status is EnqueueStatus.NOT_ACCEPTING
                else "control_overflow"
            )
            await self._pause_writer_locked(reason)
            return
        self._expectation_start_ns = checkpoint_start_ns
        if self._stop_requested:
            return

        self._fatal_task = asyncio.create_task(self._watch_fatal())
        try:
            self._adapter_task = asyncio.create_task(
                self.adapter.run(plan, self._runtime, sink)
            )
        except Exception:  # noqa: BLE001 - invalid adapter run contract.
            await self._fail_prepare("adapter_run_invalid")
            return
        await self._transition(WorkerState.RUNNING)
        if self._stop_requested:
            return
        self._adapter_watch_task = asyncio.create_task(self._watch_adapter())
        self._checkpoint_task = asyncio.create_task(self._run_hourly_checkpoints())

    def _expectation_checkpoint(
        self,
        plan: AdapterPlan,
        *,
        effective_start_ns: int | None = None,
        effective_end_ns: int | None = None,
    ) -> NativeEventDraft:
        expectations: list[dict[str, JsonPayload]] = [
            {
                "market": None if item.market is None else item.market.value,
                "instrument_key": item.instrument_key,
                "logical_stream": item.logical_stream,
                "shard_id": item.shard_id,
                "coverage": item.coverage.value,
            }
            for item in sorted(
                plan.expectations,
                key=lambda item: (
                    "" if item.market is None else item.market.value,
                    item.instrument_key or "",
                    item.logical_stream,
                    item.shard_id,
                ),
            )
        ]
        payload: dict[str, JsonPayload] = {
            "kind": "subscription_expectation",
            "effective_start_ns": (
                self.clock.time_ns()
                if effective_start_ns is None
                else effective_start_ns
            ),
            "config_sha256": self._request.config_sha256,
            "expectations": cast(JsonPayload, expectations),
        }
        if effective_end_ns is not None:
            payload["effective_end_ns"] = effective_end_ns
        return NativeEventDraft(
            exchange=self.exchange,
            market=None,
            instrument_key=None,
            wire_symbol=None,
            logical_stream="_control",
            native_channel=None,
            transport=Transport.INTERNAL,
            event_time_ns=None,
            event_time_source=None,
            payload=payload,
        )

    async def _fail_prepare(self, reason: str) -> None:
        self._last_failure = reason
        self._stop_requested = True
        self._stop.set()
        if self._sink is not None:
            self._sink.stop_accepting(reason)
        await self._stop_checkpoint_loop()
        await self._join_adapter(cancel_now=True)
        await self._close_runtime()
        await self._mark_writer_incomplete(reason)
        await self._transition(WorkerState.PAUSED_WRITER)

    async def _mark_writer_incomplete(self, reason: str) -> None:
        if self._incomplete_marked:
            return
        self._incomplete_marked = True
        self._writer_terminal = True
        writer = self._writer
        if writer is not None:
            try:
                await writer.mark_incomplete(reason)
            except Exception:  # noqa: BLE001 - prepare is already terminal.
                logger.error("writer mark-incomplete failed")

    async def _watch_adapter(self) -> None:
        task = self._adapter_task
        assert task is not None
        reason: str
        try:
            await task
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001 - adapter details are an isolation boundary.
            reason = "adapter_failed"
        else:
            reason = "adapter_stopped"
        if self._fatal_pending:
            return
        await self._handle_adapter_exit(reason)

    async def _handle_adapter_exit(self, reason: str) -> None:
        async with self._lifecycle_lock:
            if (
                self._state is not WorkerState.RUNNING
                or self._stop_requested
                or self._fatal_pending
            ):
                return
            terminal_control_written = self._emit_adapter_terminal_control(reason)
            expectation_closed = self._emit_expectation_end()
            sink_failure = None if self._sink is None else self._sink.stopped_reason
            if sink_failure is not None:
                await self._pause_writer_locked(sink_failure)
                return
            if not terminal_control_written:
                await self._pause_writer_locked("adapter_terminal_control_failed")
                return
            if not expectation_closed:
                await self._pause_writer_locked("expectation_close_failed")
                return
            self._last_failure = reason
            self._exit_code = 1
            self._stop_requested = True
            self._stop.set()
            if self._sink is not None:
                self._sink.stop_accepting(reason)
            await self._stop_checkpoint_loop()
            await self._close_runtime()
            await self._mark_writer_incomplete(reason)
            await self._transition(WorkerState.DEGRADED)

    def _emit_adapter_terminal_control(self, reason: str) -> bool:
        sink = self._sink
        if sink is None or sink.stopped_reason is not None:
            return False
        try:
            result = sink.try_emit(
                NativeEventDraft(
                    exchange=self.exchange,
                    market=None,
                    instrument_key=None,
                    wire_symbol=None,
                    logical_stream="_control",
                    native_channel=None,
                    transport=Transport.INTERNAL,
                    event_time_ns=None,
                    event_time_source=None,
                    payload={"kind": reason},
                ),
                source=SourceContext.internal(),
                shard="_control",
            )
        except Exception:  # noqa: BLE001 - terminalization continues.
            logger.error("adapter terminal control event failed")
            return False
        return result.accepted

    async def _run_hourly_checkpoints(self) -> None:
        plan = self._plan
        sink = self._sink
        assert plan is not None and sink is not None
        next_boundary_ns = (self.clock.time_ns() // _UTC_HOUR_NS + 1) * _UTC_HOUR_NS
        try:
            while not self._stop.is_set():
                now_ns = self.clock.time_ns()
                await self._checkpoint_sleeper.sleep_ns(
                    max(0, next_boundary_ns - now_ns)
                )
                if self._stop.is_set():
                    return
                now_ns = self.clock.time_ns()
                if now_ns < next_boundary_ns:
                    continue
                while next_boundary_ns <= now_ns and not self._stop.is_set():
                    result = sink.try_emit(
                        self._expectation_checkpoint(
                            plan,
                            effective_start_ns=next_boundary_ns,
                        ),
                        source=SourceContext.internal(),
                        shard="_control",
                    )
                    if not result.accepted:
                        return
                    self._expectation_start_ns = next_boundary_ns
                    next_boundary_ns += _UTC_HOUR_NS
        except asyncio.CancelledError:
            return
        except Exception:  # noqa: BLE001 - fatal watcher owns terminalization.
            self._signal_fatal("expectation_checkpoint_failed")

    def _emit_expectation_end(self) -> bool:
        plan = self._plan
        sink = self._sink
        start_ns = self._expectation_start_ns
        if (
            plan is None
            or sink is None
            or start_ns is None
            or sink.stopped_reason is not None
        ):
            return True
        try:
            result = sink.try_emit(
                self._expectation_checkpoint(
                    plan,
                    effective_start_ns=start_ns,
                    effective_end_ns=self.clock.time_ns(),
                ),
                source=SourceContext.internal(),
                shard="_control",
            )
        except Exception:  # noqa: BLE001 - shutdown must still quiesce inputs.
            return False
        return result.accepted

    async def _watch_fatal(self) -> None:
        signal = await self._fatal_queue.get()
        await self._pause_writer(signal.reason)

    async def _pause_writer(self, reason: str) -> None:
        async with self._lifecycle_lock:
            await self._pause_writer_locked(reason)

    async def _pause_writer_locked(self, reason: str) -> None:
        if self._state in {
            WorkerState.DEGRADED,
            WorkerState.PAUSED_WRITER,
            WorkerState.STOPPING,
            WorkerState.STOPPED,
        }:
            return
        self._last_failure = reason
        self._stop_requested = True
        if self._sink is not None:
            self._sink.stop_accepting(reason)
        self._stop.set()
        await self._stop_checkpoint_loop()
        await self._join_adapter(cancel_now=True)
        await self._close_runtime()
        await self._mark_writer_incomplete(reason)
        await self._transition(WorkerState.PAUSED_WRITER)

    async def _stop_checkpoint_loop(self) -> None:
        task = self._checkpoint_task
        self._checkpoint_task = None
        if task is None or task is asyncio.current_task():
            return
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001 - worker is already terminalizing.
            logger.error("expectation checkpoint task failed during shutdown")

    async def _join_adapter(
        self,
        *,
        cancel_now: bool,
        deadline_ns: int | None = None,
    ) -> None:
        task = self._adapter_task
        if task is None:
            return
        if not task.done() and not cancel_now and deadline_ns is not None:
            remaining_ns = max(0, deadline_ns - self.clock.monotonic_ns())
            if remaining_ns:
                await asyncio.wait(
                    {task},
                    timeout=remaining_ns / 1_000_000_000,
                )
        if not task.done():
            task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001 - status is handled by the watcher.
            logger.debug("adapter task already failed before shutdown")

    async def wait_until_state(
        self,
        state: WorkerState,
        *,
        timeout: float | None = None,
    ) -> None:
        async def wait() -> None:
            async with self._state_changed:
                await self._state_changed.wait_for(lambda: self._state is state)

        if self._state is state:
            return
        await asyncio.wait_for(wait(), timeout)

    async def yield_once(self) -> None:
        await asyncio.sleep(0)

    async def stop(self, *, deadline_ns: int) -> tuple[object, ...]:
        if type(deadline_ns) is not int or deadline_ns < 0:
            raise ValueError("deadline_ns must be a non-negative integer")
        self._stop_requested = True
        expectation_closed = self._emit_expectation_end()
        if self._sink is not None:
            self._sink.stop_accepting("shutdown")
        self._stop.set()
        cleanup_task = asyncio.create_task(
            self._stop_locked(
                deadline_ns=deadline_ns,
                expectation_closed=expectation_closed,
            )
        )
        try:
            return await asyncio.shield(cleanup_task)
        except asyncio.CancelledError:
            await cleanup_task
            raise

    async def _stop_locked(
        self,
        *,
        deadline_ns: int,
        expectation_closed: bool,
    ) -> tuple[object, ...]:
        async with self._lifecycle_lock:
            if self._state is WorkerState.STOPPED:
                return self._closed_manifests or ()
            await self._transition(WorkerState.STOPPING)
            await self._stop_checkpoint_loop()
            await self._join_adapter(cancel_now=False, deadline_ns=deadline_ns)
            await self._close_runtime()
            if not expectation_closed and not self._writer_terminal:
                self._last_failure = "expectation_close_failed"
                await self._mark_writer_incomplete("expectation_close_failed")
            manifests: tuple[object, ...] = ()
            writer = self._writer
            if writer is not None and not self._writer_terminal:
                try:
                    manifests = await writer.close_all(
                        CloseReason.SHUTDOWN,
                        deadline_ns,
                    )
                except Exception:  # noqa: BLE001 - terminal status remains inspectable.
                    if self._last_failure is None:
                        self._last_failure = "writer_close_failed"
            await self._cancel_watchers()
            await self._transition(WorkerState.STOPPED)
            self._closed_manifests = manifests
            return manifests

    async def _cancel_watchers(self) -> None:
        current = asyncio.current_task()
        tasks = tuple(
            task
            for task in (self._fatal_task, self._adapter_watch_task)
            if task is not None and task is not current
        )
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _close_runtime(self) -> None:
        runtime = self._runtime
        self._runtime = None
        if runtime is None:
            return
        close = getattr(runtime, "aclose", None)
        if callable(close):
            try:
                result = close()
                if inspect.isawaitable(result):
                    await result
            except Exception:  # noqa: BLE001 - continue bounded shutdown.
                logger.error("runtime close failed")
