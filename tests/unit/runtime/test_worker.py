from __future__ import annotations

import asyncio
from dataclasses import dataclass

import pytest

from crypto_collector.domain import (
    CoverageMode,
    Exchange,
    Market,
    NativeEventDraft,
    SourceContext,
    Transport,
)
from crypto_collector.exchanges import (
    AdapterPlan,
    CollectionRequest,
    ExchangeContractError,
    StreamExpectation,
    WebSocketSubscription,
)
from crypto_collector.runtime.state import WorkerState
from crypto_collector.runtime.worker import ExchangeWorker, PlanBoundEventSink
from crypto_collector.scheduler import IntervalPlan
from crypto_collector.storage import EnqueueStatus
from crypto_collector.storage.durability import (
    WriterCriticalError,
    WriterCriticalReason,
)
from crypto_collector.storage.errors import RecoveryBlocked


@dataclass(frozen=True, slots=True)
class Result:
    status: EnqueueStatus

    @property
    def accepted(self) -> bool:
        return self.status in {
            EnqueueStatus.ACCEPTED,
            EnqueueStatus.ACCEPTED_HIGH_WATER,
        }


class ScriptedWriter:
    def __init__(self, *statuses: EnqueueStatus) -> None:
        self._statuses = list(statuses)
        self.calls: list[tuple[NativeEventDraft, SourceContext, str]] = []
        self.incomplete_reasons: list[str] = []
        self.closed = False
        self.close_calls = 0

    def try_accept(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> Result:
        self.calls.append((draft, source, shard))
        status = self._statuses.pop(0) if self._statuses else EnqueueStatus.ACCEPTED
        return Result(status)

    async def mark_incomplete(self, reason: str) -> None:
        self.incomplete_reasons.append(reason)

    async def close_all(self, reason: object, deadline_ns: int) -> tuple[object, ...]:
        del reason, deadline_ns
        self.close_calls += 1
        self.closed = True
        return ()


def plan() -> AdapterPlan:
    return AdapterPlan(
        exchange=Exchange.OKX,
        ws=(
            WebSocketSubscription(
                id="okx:spot:btc:trades",
                market=Market.SPOT,
                instrument_key="BTC-USDT",
                wire_symbol="BTC-USDT",
                channel="trades",
                endpoint="wss://ws.okx.test/ws/v5/public",
                egress_id="direct-primary",
                shard_id="spot-0",
                logical_stream="trade",
            ),
        ),
        rest=(),
        expectations=(
            StreamExpectation(
                market=None,
                instrument_key=None,
                logical_stream="_control",
                shard_id="_control",
            ),
            StreamExpectation(
                market=Market.SPOT,
                instrument_key="BTC-USDT",
                logical_stream="trade",
                shard_id="spot-0",
            ),
        ),
        disabled_optional_features=(),
    )


def trade_draft() -> NativeEventDraft:
    return NativeEventDraft(
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="trade",
        native_channel="trades",
        transport=Transport.WEBSOCKET,
        event_time_ns=1,
        event_time_source="ts",
        payload={"tradeId": "1", "px": "100", "sz": "1"},
    )


def request() -> CollectionRequest:
    return CollectionRequest.model_validate(
        {
            "exchange": Exchange.OKX,
            "selected": {Market.SPOT: ()},
            "enabled_streams": {Market.SPOT: frozenset({"trade"})},
            "interval_plans": {"book_deep_snapshot": IntervalPlan(30, 30, None)},
            "config_sha256": "a" * 64,
        }
    )


def test_bound_sink_rejects_wrong_shard_before_writer() -> None:
    writer = ScriptedWriter()
    sink = PlanBoundEventSink(plan(), writer=writer, on_fatal=lambda reason: None)

    with pytest.raises(ExchangeContractError, match="expectation"):
        sink.try_emit(
            trade_draft(),
            source=SourceContext(
                connection_id="ws-1",
                connection_generation=1,
                egress_id="direct-primary",
            ),
            shard="spot-1",
        )
    assert writer.calls == []


def test_market_overflow_emits_reserved_control_record() -> None:
    writer = ScriptedWriter(EnqueueStatus.OVERFLOW, EnqueueStatus.ACCEPTED)
    fatal: list[str] = []
    sink = PlanBoundEventSink(plan(), writer=writer, on_fatal=fatal.append)

    result = sink.try_emit(
        trade_draft(),
        source=SourceContext(
            connection_id="ws-1",
            connection_generation=1,
            egress_id="direct-primary",
        ),
        shard="spot-0",
    )

    assert result.status is EnqueueStatus.OVERFLOW
    assert [call[0].logical_stream for call in writer.calls] == ["trade", "_control"]
    assert writer.calls[1][0].payload["kind"] == "queue_overflow"
    assert writer.calls[1][2] == "_control"
    assert sink.gap_count == 1
    assert fatal == []


def test_control_overflow_signals_fatal_writer_state() -> None:
    writer = ScriptedWriter(EnqueueStatus.CONTROL_OVERFLOW)
    fatal: list[str] = []
    sink = PlanBoundEventSink(plan(), writer=writer, on_fatal=fatal.append)

    sink.try_emit(
        NativeEventDraft(
            exchange=Exchange.OKX,
            market=None,
            instrument_key=None,
            wire_symbol=None,
            logical_stream="_control",
            native_channel=None,
            transport=Transport.INTERNAL,
            event_time_ns=None,
            event_time_source=None,
            payload={"kind": "test_control"},
        ),
        source=SourceContext.internal(),
        shard="_control",
    )

    assert fatal == ["control_overflow"]

    rejected = sink.try_emit(
        trade_draft(),
        source=SourceContext(
            connection_id="ws-1",
            connection_generation=1,
            egress_id="direct-primary",
        ),
        shard="spot-0",
    )
    assert rejected.status is EnqueueStatus.NOT_ACCEPTING
    assert len(writer.calls) == 1


def test_queue_overflow_control_write_failure_is_fatal_and_latches_sink() -> None:
    fatal: list[str] = []

    class Writer(ScriptedWriter):
        def try_accept(
            self,
            draft: NativeEventDraft,
            *,
            source: SourceContext,
            shard: str,
        ) -> Result:
            if self.calls:
                raise WriterCriticalError(
                    reason=WriterCriticalReason.WRITE_FAILED,
                    affected_generation_ids=(),
                    completed_batches=(),
                    message="injected control failure",
                )
            return super().try_accept(draft, source=source, shard=shard)

    writer = Writer(EnqueueStatus.OVERFLOW)
    sink = PlanBoundEventSink(plan(), writer=writer, on_fatal=fatal.append)

    with pytest.raises(WriterCriticalError, match="injected control failure"):
        sink.try_emit(
            trade_draft(),
            source=SourceContext(
                connection_id="ws-1",
                connection_generation=4,
                egress_id="direct-primary",
            ),
            shard="spot-0",
        )

    assert fatal == ["writer_critical"]
    assert sink.stopped_reason == "writer_critical"
    assert sink.gap_count == 1
    rejected = sink.try_emit(
        trade_draft(),
        source=SourceContext(
            connection_id="ws-1",
            connection_generation=4,
            egress_id="direct-primary",
        ),
        shard="spot-0",
    )
    assert rejected.status is EnqueueStatus.NOT_ACCEPTING
    assert len(writer.calls) == 1


@pytest.mark.asyncio
async def test_recovery_failure_precedes_runtime_or_adapter_action() -> None:
    actions: list[str] = []

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            actions.append("plan")
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, runtime, sink
            actions.append("run")

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        del on_critical
        raise RecoveryBlocked("injected")

    async def runtime_factory(stop: object) -> object:
        del stop
        actions.append("runtime")
        return object()

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    await worker.start()

    assert worker.state is WorkerState.PAUSED_WRITER
    assert worker.status().last_failure == "storage_recovery_blocked"
    assert actions == []
    assert await worker.stop(deadline_ns=1_000_000_000) == ()


@pytest.mark.asyncio
async def test_writer_fatal_stops_adapter_without_crashing_process() -> None:
    writer = ScriptedWriter()
    entered = asyncio.Event()
    exited = asyncio.Event()
    critical_callback: object | None = None

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, sink
            entered.set()
            try:
                await runtime.stop.wait()
            finally:
                exited.set()

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        nonlocal critical_callback
        critical_callback = on_critical
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop

    async def runtime_factory(stop: object) -> Runtime:
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    await worker.start()
    await asyncio.wait_for(entered.wait(), 1)
    assert callable(critical_callback)

    critical_callback(RuntimeError("sensitive detail"))  # type: ignore[operator]
    await worker.wait_until_state(WorkerState.PAUSED_WRITER, timeout=1)

    assert await asyncio.wait_for(exited.wait(), 1) is True
    assert worker.exit_code is None
    assert writer.incomplete_reasons == ["writer_critical"]
    await worker.stop(deadline_ns=1_000_000_000)


@pytest.mark.asyncio
async def test_writer_fatal_waits_for_adapter_cleanup_before_pausing() -> None:
    writer = ScriptedWriter()
    adapter_entered = asyncio.Event()
    cleanup_entered = asyncio.Event()
    release_cleanup = asyncio.Event()
    critical_callback: object | None = None

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, runtime, sink
            adapter_entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleanup_entered.set()
                await release_cleanup.wait()

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        nonlocal critical_callback
        critical_callback = on_critical
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop

    async def runtime_factory(stop: object) -> Runtime:
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    await worker.start()
    await adapter_entered.wait()
    assert callable(critical_callback)

    critical_callback(RuntimeError("sensitive detail"))  # type: ignore[operator]
    await cleanup_entered.wait()
    assert worker.state is WorkerState.RUNNING
    assert writer.incomplete_reasons == []

    release_cleanup.set()
    await worker.wait_until_state(WorkerState.PAUSED_WRITER, timeout=1)
    assert writer.incomplete_reasons == ["writer_critical"]
    await worker.stop(deadline_ns=worker.clock.monotonic_ns())


@pytest.mark.asyncio
async def test_market_overflow_invalidates_only_emitting_generation() -> None:
    writer = ScriptedWriter(
        EnqueueStatus.ACCEPTED,
        EnqueueStatus.OVERFLOW,
        EnqueueStatus.ACCEPTED,
    )
    closed_generations: set[int] = set()
    overflow_seen = asyncio.Event()

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan
            result = sink.try_emit(
                trade_draft(),
                source=SourceContext(
                    connection_id="ws-1",
                    connection_generation=7,
                    egress_id="direct-primary",
                ),
                shard="spot-0",
            )
            if result.status is EnqueueStatus.OVERFLOW:
                closed_generations.add(7)
                overflow_seen.set()
            await runtime.stop.wait()

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        del on_critical
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True

    runtime: Runtime | None = None

    async def runtime_factory(stop: object) -> Runtime:
        nonlocal runtime
        runtime = Runtime(stop)
        return runtime

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    await worker.start()
    await asyncio.wait_for(overflow_seen.wait(), 1)

    assert worker.state is WorkerState.RUNNING
    assert worker.status().gap_count == 1
    assert closed_generations == {7}
    await worker.stop(deadline_ns=worker.clock.monotonic_ns() + 1_000_000_000)
    assert runtime is not None and runtime.closed


@pytest.mark.asyncio
async def test_startup_control_overflow_pauses_before_adapter_run() -> None:
    writer = ScriptedWriter(EnqueueStatus.CONTROL_OVERFLOW)
    run_called = False

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, runtime, sink
            nonlocal run_called
            run_called = True

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        del on_critical
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True

    runtime: Runtime | None = None

    async def runtime_factory(stop: object) -> Runtime:
        nonlocal runtime
        runtime = Runtime(stop)
        return runtime

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    await worker.start()

    assert worker.state is WorkerState.PAUSED_WRITER
    assert worker.status().last_failure == "control_overflow"
    assert writer.incomplete_reasons == ["control_overflow"]
    assert runtime is not None and runtime.closed
    assert not run_called
    await worker.stop(deadline_ns=1_000_000_000)


@pytest.mark.asyncio
async def test_stop_during_writer_open_cannot_revive_worker() -> None:
    writer = ScriptedWriter()
    writer_factory_entered = asyncio.Event()
    release_writer_factory = asyncio.Event()
    runtime_calls = 0

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, runtime, sink

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        del on_critical
        writer_factory_entered.set()
        await release_writer_factory.wait()
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop

    async def runtime_factory(stop: object) -> Runtime:
        nonlocal runtime_calls
        runtime_calls += 1
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    start_task = asyncio.create_task(worker.start())
    await writer_factory_entered.wait()
    stop_task = asyncio.create_task(
        worker.stop(deadline_ns=worker.clock.monotonic_ns() + 1_000_000_000)
    )
    await asyncio.sleep(0)
    assert not stop_task.done()

    release_writer_factory.set()
    await start_task
    await stop_task

    assert worker.state is WorkerState.STOPPED
    assert runtime_calls == 0
    assert writer.close_calls == 1


@pytest.mark.asyncio
async def test_invalid_control_coverage_fails_prepare_and_closes_runtime() -> None:
    writer = ScriptedWriter()
    runtime_closed = False

    invalid_plan = AdapterPlan(
        exchange=Exchange.OKX,
        ws=(),
        rest=(),
        expectations=(
            StreamExpectation(
                market=None,
                instrument_key=None,
                logical_stream="_control",
                shard_id="_control",
                coverage=CoverageMode.LOSSY_WINDOW,
            ),
        ),
        disabled_optional_features=(),
    )

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return invalid_plan

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, runtime, sink
            raise AssertionError("adapter must not run")

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        del on_critical
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop

        async def aclose(self) -> None:
            nonlocal runtime_closed
            runtime_closed = True

    async def runtime_factory(stop: object) -> Runtime:
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    await worker.start()

    assert worker.state is WorkerState.PAUSED_WRITER
    assert worker.status().last_failure == "control_expectation_invalid"
    assert writer.incomplete_reasons == ["control_expectation_invalid"]
    assert runtime_closed
    await worker.stop(deadline_ns=worker.clock.monotonic_ns())
    assert writer.close_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("raise_error", "expected_reason"),
    ((True, "adapter_failed"), (False, "adapter_stopped")),
)
async def test_adapter_terminal_exit_marks_data_incomplete_and_requests_restart(
    raise_error: bool,
    expected_reason: str,
) -> None:
    writer = ScriptedWriter()
    runtime_closed = False

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, runtime, sink
            if raise_error:
                raise RuntimeError("sensitive adapter detail")

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        del on_critical
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop

        async def aclose(self) -> None:
            nonlocal runtime_closed
            runtime_closed = True

    async def runtime_factory(stop: object) -> Runtime:
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    await worker.start()
    await worker.wait_until_state(WorkerState.DEGRADED, timeout=1)

    assert worker.status().last_failure == expected_reason
    assert worker.exit_code == 1
    assert writer.incomplete_reasons == [expected_reason]
    assert [call[0].payload["kind"] for call in writer.calls] == [
        "subscription_expectation",
        expected_reason,
        "subscription_expectation",
    ]
    assert "effective_end_ns" in writer.calls[-1][0].payload
    assert runtime_closed
    await worker.stop(deadline_ns=worker.clock.monotonic_ns())
    assert writer.close_calls == 0


@pytest.mark.asyncio
async def test_hour_boundary_repeats_expectation_and_shutdown_closes_interval() -> None:
    hour_ns = 3_600_000_000_000
    writer = ScriptedWriter()
    first_sleep_entered = asyncio.Event()
    release_first_sleep = asyncio.Event()
    block_later_sleeps = asyncio.Event()

    class Clock:
        wall_ns = hour_ns - 5
        monotonic = 1_000

        def time_ns(self) -> int:
            return self.wall_ns

        def monotonic_ns(self) -> int:
            return self.monotonic

    clock = Clock()

    class Sleeper:
        calls = 0
        first_delay_ns: int | None = None

        async def sleep_ns(self, delay_ns: int) -> None:
            self.calls += 1
            if self.calls == 1:
                self.first_delay_ns = delay_ns
                first_sleep_entered.set()
                await release_first_sleep.wait()
                return
            await block_later_sleeps.wait()

    sleeper = Sleeper()

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, sink
            await runtime.stop.wait()

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        del on_critical
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop

    async def runtime_factory(stop: object) -> Runtime:
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
        clock=clock,
        checkpoint_sleeper=sleeper,
    )
    await worker.start()
    await first_sleep_entered.wait()
    assert sleeper.first_delay_ns == 5

    clock.wall_ns = hour_ns
    release_first_sleep.set()
    for _ in range(20):
        if len(writer.calls) >= 2:
            break
        await asyncio.sleep(0)
    assert [call[0].payload["effective_start_ns"] for call in writer.calls] == [
        hour_ns - 5,
        hour_ns,
    ]

    await worker.stop(deadline_ns=clock.monotonic_ns() + 1_000_000_000)
    assert [call[0].payload["kind"] for call in writer.calls] == [
        "subscription_expectation",
        "subscription_expectation",
        "subscription_expectation",
    ]
    assert writer.calls[-1][0].payload["effective_start_ns"] == hour_ns
    assert writer.calls[-1][0].payload["effective_end_ns"] == hour_ns


@pytest.mark.asyncio
async def test_stop_waits_for_adapter_cancellation_cleanup_before_closing() -> None:
    writer = ScriptedWriter()
    adapter_entered = asyncio.Event()
    cleanup_entered = asyncio.Event()
    release_cleanup = asyncio.Event()

    class Adapter:
        exchange = Exchange.OKX

        def plan(self, collection_request: CollectionRequest) -> AdapterPlan:
            del collection_request
            return plan()

        async def run(
            self, adapter_plan: object, runtime: object, sink: object
        ) -> None:
            del adapter_plan, runtime, sink
            adapter_entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                cleanup_entered.set()
                await release_cleanup.wait()

    async def writer_factory(*, on_critical: object) -> ScriptedWriter:
        del on_critical
        return writer

    class Runtime:
        def __init__(self, stop: object) -> None:
            self.stop = stop
            self.closed = False

        async def aclose(self) -> None:
            self.closed = True

    runtime: Runtime | None = None

    async def runtime_factory(stop: object) -> Runtime:
        nonlocal runtime
        runtime = Runtime(stop)
        return runtime

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=Adapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
    )
    await worker.start()
    await adapter_entered.wait()
    stop_task = asyncio.create_task(
        worker.stop(deadline_ns=worker.clock.monotonic_ns())
    )
    await cleanup_entered.wait()

    assert worker.state is WorkerState.STOPPING
    assert not stop_task.done()
    assert not writer.closed
    assert runtime is not None and not runtime.closed

    release_cleanup.set()
    await stop_task
    assert worker.state is WorkerState.STOPPED
    assert writer.closed
    assert runtime.closed
