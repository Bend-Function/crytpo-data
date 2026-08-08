from __future__ import annotations

import asyncio
import json
import random
import traceback
from base64 import b64decode
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Self, cast

import httpx
import pytest

from crypto_collector.domain import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    NativeEventDraft,
    SourceContext,
    Transport,
)
from crypto_collector.domain.clock import SystemClock
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges import (
    AdapterRuntime,
    CollectionRequest,
    EgressTransport,
    NetworkAdmissionExpired,
    NetworkAdmissionLease,
    NetworkAdmissionPort,
    NetworkAdmissionReleaseDisposition,
    NetworkAdmissionReleaseError,
)
from crypto_collector.exchanges.okx import OkxAdapter, OkxEndpoints, OkxPlanRoute
from crypto_collector.exchanges.okx import execution as okx_execution
from crypto_collector.network import BudgetRegistry, RetryDecision
from crypto_collector.network.state_store import EgressStateStore
from crypto_collector.scheduler import (
    IntervalPlan,
    RestDispatch,
    RestJob,
    RestScheduler,
    StableCadence,
    SubmitResult,
)
from crypto_collector.selection import InstrumentRecord, LifecyclePhase
from crypto_collector.storage import EnqueueResult, EnqueueStatus
from tests.support.okx_session import (
    AutoAckWebSocketConnection,
    RouteScriptedHttpTransport,
    RouteScriptedWebSocketTransport,
    okx_response,
)

REST_ENDPOINT = "https://okx.test"
WS_PUBLIC_ENDPOINT = "wss://okx.test/ws/v5/public"
WS_BUSINESS_ENDPOINT = "wss://okx.test/ws/v5/business"
SECOND_NS = 1_000_000_000
_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "okx"


class StopToken:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    def is_set(self) -> bool:
        return self._event.is_set()

    async def wait(self) -> None:
        await self._event.wait()

    def set(self) -> None:
        self._event.set()


@dataclass(frozen=True, slots=True)
class _SinkResult:
    status: EnqueueStatus

    @property
    def accepted(self) -> bool:
        return self.status in {
            EnqueueStatus.ACCEPTED,
            EnqueueStatus.ACCEPTED_HIGH_WATER,
        }


class RecordingSink:
    def __init__(
        self,
        *,
        stop: StopToken | None = None,
        stop_when: Callable[[NativeEventDraft], bool] | None = None,
        status_for: Callable[[NativeEventDraft], EnqueueStatus] | None = None,
    ) -> None:
        self.stop = stop
        self.stop_when = stop_when
        self.status_for = status_for
        self.rows: list[tuple[NativeEventDraft, SourceContext, str]] = []

    def try_emit(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> EnqueueResult:
        self.rows.append((draft, source, shard))
        status = (
            EnqueueStatus.ACCEPTED
            if self.status_for is None
            else self.status_for(draft)
        )
        if (
            self.stop is not None
            and self.stop_when is not None
            and self.stop_when(draft)
        ):
            self.stop.set()
        return cast(EnqueueResult, _SinkResult(status))


class RecordingRetryEffects:
    def __init__(self) -> None:
        self.calls: list[tuple[RestDispatch, RetryDecision]] = []

    def apply(self, dispatch: RestDispatch, decision: RetryDecision) -> None:
        self.calls.append((dispatch, decision))


class RecordingNetworkAdmission:
    def __init__(self) -> None:
        self.calls: list[tuple[Exchange, Transport, str, str, int | None]] = []
        self.releases: list[tuple[Exchange, Transport, str, str]] = []
        self.release_dispositions: list[NetworkAdmissionReleaseDisposition] = []

    async def acquire(
        self,
        *,
        exchange: Exchange,
        transport: Transport,
        egress_id: str,
        quota_group: str,
        deadline_monotonic_ns: int | None,
    ) -> NetworkAdmissionLease:
        self.calls.append(
            (
                exchange,
                transport,
                egress_id,
                quota_group,
                deadline_monotonic_ns,
            )
        )

        async def release(disposition: NetworkAdmissionReleaseDisposition) -> None:
            self.releases.append((exchange, transport, egress_id, quota_group))
            self.release_dispositions.append(disposition)

        return NetworkAdmissionLease(
            exchange=exchange,
            transport=transport,
            egress_id=egress_id,
            quota_group=quota_group,
            _release=release,
        )


def _instrument(
    market: Market,
    instrument_key: str,
    *,
    phase: LifecyclePhase = LifecyclePhase.TRADABLE,
) -> InstrumentRecord:
    perpetual = market is Market.PERPETUAL
    family = instrument_key.removesuffix("-SWAP")
    return InstrumentRecord(
        exchange=Exchange.OKX,
        market=market,
        instrument_key=instrument_key,
        canonical_pair="BTC/USDT",
        wire_symbols={
            "rest": instrument_key,
            "websocket": instrument_key,
            **({"index": family, "instrument_family": family} if perpetual else {}),
        },
        base_asset="BTC",
        quote_asset="USDT",
        settlement_asset="USDT" if perpetual else None,
        status="preopen" if phase is LifecyclePhase.PREOPEN else "live",
        lifecycle_phase=phase,
        tradable=phase is LifecyclePhase.TRADABLE,
        lifecycle={"state": phase.value},
        tradable_at_ns=None,
        tradable_at_source=None,
        turnover=None,
        raw_catalog_reference=f"fixture://okx/{instrument_key}",
    )


def _request(
    selected: Mapping[Market, tuple[InstrumentRecord, ...]],
    streams: Mapping[Market, frozenset[str]],
    *,
    intervals: Mapping[str, IntervalPlan] | None = None,
) -> CollectionRequest:
    return CollectionRequest.model_validate(
        {
            "exchange": Exchange.OKX,
            "selected": selected,
            "enabled_streams": streams,
            "interval_plans": {} if intervals is None else intervals,
            "config_sha256": "a" * 64,
        }
    )


def _adapter(
    *,
    routes: Mapping[tuple[Market, str | None], OkxPlanRoute],
    rest_routes: Mapping[Market, tuple[OkxPlanRoute, ...]] | None = None,
) -> OkxAdapter:
    return OkxAdapter(
        endpoints=OkxEndpoints(
            rest=REST_ENDPOINT,
            websocket_public=WS_PUBLIC_ENDPOINT,
            websocket_business=WS_BUSINESS_ENDPOINT,
        ),
        routes=routes,
        rest_routes=rest_routes,
    )


def _runtime(
    *,
    stop: StopToken,
    transports: Mapping[str, EgressTransport],
    budget_keys: tuple[tuple[str, str, str], ...] = (),
    network_admission: NetworkAdmissionPort | None = None,
    include_retry_effects: bool = True,
) -> AdapterRuntime:
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    for key in budget_keys:
        budgets.add(key, capacity=100, refill_per_second=100)
    return AdapterRuntime(
        transports=transports,
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        network_admission=(
            RecordingNetworkAdmission()
            if network_admission is None
            else network_admission
        ),
        retry_effects=RecordingRetryEffects() if include_retry_effects else None,
    )


async def _wait_until(predicate: Callable[[], bool]) -> None:
    async def wait() -> None:
        while not predicate():
            await asyncio.sleep(0)

    await asyncio.wait_for(wait(), timeout=3)


def _data_frame(channel: str, marker: str, *, inst_id: str | None = None) -> str:
    argument: dict[str, str] = {"channel": channel}
    row: dict[str, JsonPayload] = {"ts": "1800000000123", "marker": marker}
    if inst_id is not None:
        argument["instId"] = inst_id
        row["instId"] = inst_id
    return json.dumps(
        {"arg": argument, "data": [row]},
        separators=(",", ":"),
    )


def _book_frame(
    *,
    action: str,
    sequence: int,
    previous: int,
    bid: str = "100",
    ask: str = "101",
) -> str:
    return json.dumps(
        {
            "arg": {"channel": "books", "instId": "BTC-USDT"},
            "action": action,
            "data": [
                {
                    "bids": [[bid, "1", "0", "1"]],
                    "asks": [[ask, "1", "0", "1"]],
                    "ts": str(1_800_000_000_000 + sequence),
                    "checksum": 0,
                    "prevSeqId": previous,
                    "seqId": sequence,
                }
            ],
        },
        separators=(",", ":"),
    )


@pytest.mark.asyncio
async def test_same_route_status_uses_one_real_session_per_market_without_copying() -> (
    None
):
    spot = _instrument(Market.SPOT, "BTC-USDT")
    swap = _instrument(Market.PERPETUAL, "BTC-USDT-SWAP")
    route = OkxPlanRoute("shared", "shared-nat", "shared-0")
    adapter = _adapter(
        routes={(Market.SPOT, None): route, (Market.PERPETUAL, None): route}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,), Market.PERPETUAL: (swap,)},
            {
                Market.SPOT: frozenset({"status"}),
                Market.PERPETUAL: frozenset({"status"}),
            },
        )
    )
    websocket = RouteScriptedWebSocketTransport()
    perpetual_connection = AutoAckWebSocketConnection(
        "perpetual-status",
        _data_frame("status", "perpetual"),
    )
    spot_connection = AutoAckWebSocketConnection(
        "spot-status",
        _data_frame("status", "spot"),
    )
    websocket.add(WS_PUBLIC_ENDPOINT, perpetual_connection, spot_connection)
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            sum(row.logical_stream == "status" for row, _source, _shard in sink.rows)
            == 2
        ),
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "shared": EgressTransport("shared", RouteScriptedHttpTransport(), websocket)
        },
    )

    await adapter.run(plan, runtime, sink)

    status = [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "status"
    ]
    assert len(status) == 2
    by_marker = {
        cast(dict[str, object], draft.payload)["data"][0]["marker"]: draft
        for draft in status
    }  # type: ignore[index]
    assert by_marker["perpetual"].market is Market.PERPETUAL
    assert by_marker["spot"].market is Market.SPOT
    assert {draft.coverage for draft in status} == {CoverageMode.UNKNOWN}
    assert websocket.uris == [WS_PUBLIC_ENDPOINT, WS_PUBLIC_ENDPOINT]


@pytest.mark.asyncio
async def test_same_egress_websocket_groups_await_sequential_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    aaa = _instrument(Market.SPOT, "AAA-USDT")
    zzz = _instrument(Market.SPOT, "ZZZ-USDT")
    adapter = _adapter(
        routes={
            (Market.SPOT, aaa.instrument_key): OkxPlanRoute(
                "shared", "shared-nat", "shard-a"
            ),
            (Market.SPOT, zzz.instrument_key): OkxPlanRoute(
                "shared", "shared-nat", "shard-z"
            ),
        }
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (zzz, aaa)},
            {Market.SPOT: frozenset({"ticker"})},
        )
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("group-a"),
        AutoAckWebSocketConnection("group-z"),
    )

    class SequentialAdmission(RecordingNetworkAdmission):
        def __init__(self) -> None:
            super().__init__()
            self.lock = asyncio.Lock()
            self.entered = (asyncio.Event(), asyncio.Event())
            self.release = (asyncio.Event(), asyncio.Event())

        async def acquire(
            self,
            *,
            exchange: Exchange,
            transport: Transport,
            egress_id: str,
            quota_group: str,
            deadline_monotonic_ns: int | None,
        ) -> NetworkAdmissionLease:
            async with self.lock:
                index = len(self.calls)
                lease = await super().acquire(
                    exchange=exchange,
                    transport=transport,
                    egress_id=egress_id,
                    quota_group=quota_group,
                    deadline_monotonic_ns=deadline_monotonic_ns,
                )
                self.entered[index].set()
                await self.release[index].wait()
                return lease

    admission = SequentialAdmission()
    original_seed = okx_execution._stable_seed
    seed_parts: list[tuple[str, ...]] = []

    def record_seed(*parts: str) -> int:
        seed_parts.append(parts)
        return original_seed(*parts)

    monkeypatch.setattr(okx_execution, "_stable_seed", record_seed)
    stop = StopToken()
    runtime = _runtime(
        stop=stop,
        transports={
            "shared": EgressTransport("shared", RouteScriptedHttpTransport(), websocket)
        },
        network_admission=admission,
    )
    run_task = asyncio.create_task(adapter.run(plan, runtime, RecordingSink()))

    await asyncio.wait_for(admission.entered[0].wait(), timeout=1)
    await asyncio.sleep(0)
    assert not admission.entered[1].is_set()
    assert websocket.uris == []
    admission.release[0].set()
    await asyncio.wait_for(admission.entered[1].wait(), timeout=1)
    await _wait_until(lambda: len(websocket.uris) == 1)
    admission.release[1].set()
    await _wait_until(lambda: len(websocket.uris) == 2)
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)

    assert admission.calls == [
        (Exchange.OKX, Transport.WEBSOCKET, "shared", "shared-nat", None),
        (Exchange.OKX, Transport.WEBSOCKET, "shared", "shared-nat", None),
    ]
    assert {parts for parts in seed_parts if parts and parts[0] == "ws"} == {
        ("ws", "spot", WS_PUBLIC_ENDPOINT, "shared", "shard-a"),
        ("ws", "spot", WS_PUBLIC_ENDPOINT, "shared", "shard-z"),
    }


@pytest.mark.asyncio
async def test_websocket_reconnect_requires_fresh_admission_each_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )

    class NoDelayPolicy:
        def __init__(self, *, base_ns: int, cap_ns: int) -> None:
            del base_ns, cap_ns

        def delay_ns(self, attempt: int, *, rng: object) -> int:
            del attempt, rng
            return 0

    monkeypatch.setattr(okx_execution, "OkxWsReconnectPolicy", NoDelayPolicy)
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("generation-1", OSError("route down")),
        AutoAckWebSocketConnection(
            "generation-2",
            _data_frame("tickers", "second", inst_id="BTC-USDT"),
        ),
    )
    stop = StopToken()
    admission = RecordingNetworkAdmission()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "ticker",
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        network_admission=admission,
    )

    await adapter.run(plan, runtime, sink)

    assert admission.calls == [
        (Exchange.OKX, Transport.WEBSOCKET, "direct", "nat", None),
        (Exchange.OKX, Transport.WEBSOCKET, "direct", "nat", None),
    ]
    assert websocket.uris == [WS_PUBLIC_ENDPOINT, WS_PUBLIC_ENDPOINT]


@pytest.mark.asyncio
async def test_stop_cancels_pending_websocket_admission_before_connect() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )

    class BlockingAdmission(RecordingNetworkAdmission):
        def __init__(self) -> None:
            super().__init__()
            self.entered = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def acquire(
            self,
            *,
            exchange: Exchange,
            transport: Transport,
            egress_id: str,
            quota_group: str,
            deadline_monotonic_ns: int | None,
        ) -> NetworkAdmissionLease:
            lease = await super().acquire(
                exchange=exchange,
                transport=transport,
                egress_id=egress_id,
                quota_group=quota_group,
                deadline_monotonic_ns=deadline_monotonic_ns,
            )
            self.entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled.set()
            return lease

    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, AutoAckWebSocketConnection("must-not-connect"))
    stop = StopToken()
    admission = BlockingAdmission()
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        network_admission=admission,
    )
    run_task = asyncio.create_task(adapter.run(plan, runtime, RecordingSink()))

    await asyncio.wait_for(admission.entered.wait(), timeout=1)
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)

    assert admission.cancelled.is_set()
    assert websocket.uris == []


@pytest.mark.asyncio
async def test_planned_websocket_work_without_admission_port_fails_before_connect() -> (
    None
):
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection(
            "must-not-connect",
            _data_frame("tickers", "unexpected", inst_id="BTC-USDT"),
        ),
    )
    stop = StopToken()
    clock = SystemClock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=stop,
    )

    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "ticker",
    )
    with pytest.raises(RuntimeError, match="network admission"):
        await adapter.run(plan, runtime, sink)
    assert websocket.uris == []


@pytest.mark.asyncio
async def test_catalog_work_without_admission_port_fails_before_http() -> None:
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/public/instruments",
        httpx.Response(200, content=(_FIXTURES / "instruments-spot.json").read_bytes()),
    )
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(("okx", "nat", "instruments"), capacity=1, refill_per_second=1)
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
    )

    with pytest.raises(RuntimeError, match="network admission"):
        await adapter.fetch_catalog(runtime, Market.SPOT)
    assert http.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("close_method", "expected_disposition"),
    [
        ("aclose", NetworkAdmissionReleaseDisposition.NORMAL),
        ("fail_closed", NetworkAdmissionReleaseDisposition.FAIL_CLOSED),
    ],
)
async def test_admission_lease_release_is_exact_once_and_double_cancel_safe(
    close_method: str,
    expected_disposition: NetworkAdmissionReleaseDisposition,
) -> None:
    release_started = asyncio.Event()
    release_allowed = asyncio.Event()
    release_count = 0

    async def release(disposition: NetworkAdmissionReleaseDisposition) -> None:
        nonlocal release_count
        assert disposition is expected_disposition
        release_count += 1
        release_started.set()
        await release_allowed.wait()

    lease = NetworkAdmissionLease(
        exchange=Exchange.OKX,
        transport=Transport.REST,
        egress_id="direct",
        quota_group="nat",
        _release=release,
    )
    close = cast(Callable[[], object], getattr(lease, close_method))
    first = asyncio.create_task(close())  # type: ignore[arg-type]
    second = asyncio.create_task(close())  # type: ignore[arg-type]
    await asyncio.wait_for(release_started.wait(), timeout=1)
    first.cancel()
    await asyncio.sleep(0)
    first.cancel()
    await asyncio.sleep(0)
    assert not first.done()
    release_allowed.set()
    with pytest.raises(asyncio.CancelledError):
        await first
    await second
    await close()  # type: ignore[misc]
    assert release_count == 1
    assert lease.release_disposition is expected_disposition


@pytest.mark.asyncio
@pytest.mark.parametrize("release_behavior", ["sync_raise", "non_awaitable"])
async def test_admission_lease_caches_malformed_release_result_exact_once(
    release_behavior: str,
) -> None:
    calls = 0

    def release(disposition: NetworkAdmissionReleaseDisposition) -> object:
        nonlocal calls
        assert disposition is NetworkAdmissionReleaseDisposition.NORMAL
        calls += 1
        if release_behavior == "sync_raise":
            raise RuntimeError("release failed")
        return None

    lease = NetworkAdmissionLease(
        exchange=Exchange.OKX,
        transport=Transport.REST,
        egress_id="direct",
        quota_group="nat",
        _release=release,  # type: ignore[arg-type]
    )
    with pytest.raises(NetworkAdmissionReleaseError):
        await lease.aclose()
    with pytest.raises(NetworkAdmissionReleaseError):
        await lease.aclose()
    assert calls == 1


@pytest.mark.asyncio
async def test_cancel_during_acquire_releases_a_same_tick_lease() -> None:
    entered = asyncio.Event()
    cancelled = asyncio.Event()
    allow_return = asyncio.Event()
    released = asyncio.Event()

    class CancellationReturningAdmission:
        async def acquire(
            self,
            *,
            exchange: Exchange,
            transport: Transport,
            egress_id: str,
            quota_group: str,
            deadline_monotonic_ns: int | None,
        ) -> NetworkAdmissionLease:
            del deadline_monotonic_ns
            entered.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                cancelled.set()
                await allow_return.wait()

                async def release(
                    disposition: NetworkAdmissionReleaseDisposition,
                ) -> None:
                    assert disposition is NetworkAdmissionReleaseDisposition.NORMAL
                    released.set()

                return NetworkAdmissionLease(
                    exchange=exchange,
                    transport=transport,
                    egress_id=egress_id,
                    quota_group=quota_group,
                    _release=release,
                )
            raise AssertionError("acquire gate unexpectedly resumed")

    stop = StopToken()
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        network_admission=CancellationReturningAdmission(),
    )
    task = asyncio.create_task(
        okx_execution._acquire_network_lease(
            runtime=runtime,
            exchange=Exchange.OKX,
            transport=Transport.WEBSOCKET,
            egress_id="direct",
            quota_group="nat",
            deadline_ns=None,
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=1)
    task.cancel()
    await asyncio.wait_for(cancelled.wait(), timeout=1)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    allow_return.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert released.is_set()


@pytest.mark.asyncio
async def test_post_admission_clock_failure_closes_the_harvested_lease() -> None:
    class ThrowingSecondClock:
        def __init__(self) -> None:
            self.calls = 0

        def monotonic_ns(self) -> int:
            self.calls += 1
            if self.calls == 2:
                raise RuntimeError("post-admission clock failed")
            return 1

        def time_ns(self) -> int:
            return 1

    admission = RecordingNetworkAdmission()
    clock = ThrowingSecondClock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=RestScheduler(BudgetRegistry(SystemClock())),
        clock=clock,
        stop=StopToken(),
        network_admission=admission,
    )

    with pytest.raises(RuntimeError, match="post-admission clock failed"):
        await okx_execution._acquire_network_lease(
            runtime=runtime,
            exchange=Exchange.OKX,
            transport=Transport.REST,
            egress_id="direct",
            quota_group="nat",
            deadline_ns=10,
        )
    assert admission.releases == [(Exchange.OKX, Transport.REST, "direct", "nat")]
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    ]


@pytest.mark.asyncio
async def test_expired_admission_remains_primary_when_normal_release_fails() -> None:
    canary = "https://user:token-canary@proxy.invalid"
    releases: list[NetworkAdmissionReleaseDisposition] = []

    class Clock:
        def __init__(self) -> None:
            self.now = 0

        def monotonic_ns(self) -> int:
            return self.now

        def time_ns(self) -> int:
            return 0

    class Admission:
        async def acquire(self, **kwargs: object) -> NetworkAdmissionLease:
            clock.now = SECOND_NS + 1

            async def release(
                disposition: NetworkAdmissionReleaseDisposition,
            ) -> None:
                releases.append(disposition)
                raise RuntimeError(canary)

            return NetworkAdmissionLease(
                exchange=cast(Exchange, kwargs["exchange"]),
                transport=cast(Transport, kwargs["transport"]),
                egress_id=cast(str, kwargs["egress_id"]),
                quota_group=cast(str, kwargs["quota_group"]),
                _release=release,
            )

    clock = Clock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=StopToken(),
        network_admission=Admission(),
    )

    with pytest.raises(NetworkAdmissionExpired) as caught:
        await okx_execution._acquire_network_lease(
            runtime=runtime,
            exchange=Exchange.OKX,
            transport=Transport.REST,
            egress_id="direct",
            quota_group="nat",
            deadline_ns=SECOND_NS,
        )
    rendered = " ".join(
        [repr(caught.value), str(caught.value), *getattr(caught.value, "__notes__", ())]
    )
    assert canary not in rendered
    assert releases == [NetworkAdmissionReleaseDisposition.NORMAL]


@pytest.mark.asyncio
async def test_admission_lease_subclass_is_rejected_only_after_release() -> None:
    class DerivedLease(NetworkAdmissionLease):
        async def aclose(self) -> None:
            raise AssertionError("subclass release override must not run")

    releases: list[NetworkAdmissionReleaseDisposition] = []

    class DerivedAdmission:
        async def acquire(self, **kwargs: object) -> NetworkAdmissionLease:
            async def release(
                disposition: NetworkAdmissionReleaseDisposition,
            ) -> None:
                releases.append(disposition)

            return DerivedLease(
                exchange=cast(Exchange, kwargs["exchange"]),
                transport=cast(Transport, kwargs["transport"]),
                egress_id=cast(str, kwargs["egress_id"]),
                quota_group=cast(str, kwargs["quota_group"]),
                _release=release,
            )

    runtime = _runtime(
        stop=StopToken(),
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        network_admission=DerivedAdmission(),
    )

    with pytest.raises(TypeError, match="must return NetworkAdmissionLease"):
        await okx_execution._acquire_network_lease(
            runtime=runtime,
            exchange=Exchange.OKX,
            transport=Transport.REST,
            egress_id="direct",
            quota_group="nat",
            deadline_ns=None,
        )
    assert releases == [NetworkAdmissionReleaseDisposition.FAIL_CLOSED]


@pytest.mark.asyncio
async def test_stop_wait_failure_releases_a_same_tick_admission_lease() -> None:
    class FailingStop:
        def is_set(self) -> bool:
            return False

        async def wait(self) -> None:
            raise RuntimeError("stop wait failed")

    admission = RecordingNetworkAdmission()
    clock = SystemClock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=FailingStop(),
        network_admission=admission,
    )

    with pytest.raises(RuntimeError, match="stop wait failed"):
        await okx_execution._acquire_network_lease(
            runtime=runtime,
            exchange=Exchange.OKX,
            transport=Transport.REST,
            egress_id="direct",
            quota_group="nat",
            deadline_ns=None,
        )
    assert admission.releases == [(Exchange.OKX, Transport.REST, "direct", "nat")]


@pytest.mark.asyncio
async def test_same_tick_stop_does_not_hide_admission_failure() -> None:
    class SameTickStop:
        def __init__(self) -> None:
            self.stopped = False

        def is_set(self) -> bool:
            return self.stopped

        async def wait(self) -> None:
            self.stopped = True

    class FailingAdmission:
        async def acquire(self, **kwargs: object) -> NetworkAdmissionLease:
            del kwargs
            raise RuntimeError("admission failed")

    clock = SystemClock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=SameTickStop(),
        network_admission=FailingAdmission(),
    )

    with pytest.raises(RuntimeError, match="admission failed"):
        await okx_execution._acquire_network_lease(
            runtime=runtime,
            exchange=Exchange.OKX,
            transport=Transport.REST,
            egress_id="direct",
            quota_group="nat",
            deadline_ns=None,
        )


@pytest.mark.asyncio
async def test_admission_timeout_closes_a_lease_returned_during_cancellation() -> None:
    released: list[NetworkAdmissionReleaseDisposition] = []

    class ZeroClock:
        def monotonic_ns(self) -> int:
            return 0

        def time_ns(self) -> int:
            return 0

    class LateAdmission:
        async def acquire(
            self,
            *,
            exchange: Exchange,
            transport: Transport,
            egress_id: str,
            quota_group: str,
            deadline_monotonic_ns: int | None,
        ) -> NetworkAdmissionLease:
            del deadline_monotonic_ns
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:

                async def release(
                    disposition: NetworkAdmissionReleaseDisposition,
                ) -> None:
                    released.append(disposition)

                return NetworkAdmissionLease(
                    exchange=exchange,
                    transport=transport,
                    egress_id=egress_id,
                    quota_group=quota_group,
                    _release=release,
                )
            raise AssertionError("late admission unexpectedly resumed")

    clock = ZeroClock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=StopToken(),
        network_admission=LateAdmission(),
    )

    with pytest.raises(NetworkAdmissionExpired):
        await okx_execution._acquire_network_lease(
            runtime=runtime,
            exchange=Exchange.OKX,
            transport=Transport.REST,
            egress_id="direct",
            quota_group="nat",
            deadline_ns=0,
        )
    assert released == [NetworkAdmissionReleaseDisposition.NORMAL]


@pytest.mark.asyncio
async def test_rest_admission_deadline_only_bounds_io_start() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    item = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    ).rest[0]

    class Clock:
        def __init__(self, monotonic_ns: int) -> None:
            self.now = monotonic_ns

        def time_ns(self) -> int:
            return 1_800_000_000_000_000_000 + self.now

        def monotonic_ns(self) -> int:
            return self.now

    class AdvancingHttp(RouteScriptedHttpTransport):
        def __init__(self, clock: Clock) -> None:
            super().__init__()
            self._clock = clock

        async def get(self, *args: object, **kwargs: object) -> httpx.Response:
            response = await super().get(*args, **kwargs)  # type: ignore[arg-type]
            self._clock.now = 11
            return response

    payload = {
        "code": "0",
        "msg": "",
        "data": [{"asks": [], "bids": [], "ts": "1800000000123"}],
    }
    on_time_clock = Clock(10)
    on_time_http = AdvancingHttp(on_time_clock)
    on_time_http.add("/api/v5/market/books-full", okx_response(payload))
    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct", on_time_http, RouteScriptedWebSocketTransport()
            )
        },
        scheduler=RestScheduler(BudgetRegistry(on_time_clock), clock=on_time_clock),
        clock=on_time_clock,
        stop=StopToken(),
        network_admission=admission,
    )
    job = item.materialize(
        ready_monotonic_ns=1,
        scheduled_ns=1,
        attempt=1,
        deadline_ns=10,
    )
    attempt = await okx_execution._capture_rest_attempt(
        item=item,
        dispatch=RestDispatch(job, job.routes[0], 10),
        runtime=runtime,
    )
    await attempt.lease.aclose()
    assert attempt.capture is not None
    assert len(on_time_http.requests) == 1

    late_clock = Clock(10)
    late_http = RouteScriptedHttpTransport()

    class LateAdmission(RecordingNetworkAdmission):
        async def acquire(self, **kwargs: object) -> NetworkAdmissionLease:
            late_clock.now = 11
            return await super().acquire(**kwargs)  # type: ignore[arg-type]

    late_admission = LateAdmission()
    late_runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct", late_http, RouteScriptedWebSocketTransport()
            )
        },
        scheduler=RestScheduler(BudgetRegistry(late_clock), clock=late_clock),
        clock=late_clock,
        stop=StopToken(),
        network_admission=late_admission,
    )
    with pytest.raises(NetworkAdmissionExpired):
        await okx_execution._capture_rest_attempt(
            item=item,
            dispatch=RestDispatch(job, job.routes[0], 10),
            runtime=late_runtime,
        )
    assert late_http.requests == []
    assert len(late_admission.releases) == 1


@pytest.mark.asyncio
async def test_wall_clock_evidence_cannot_push_http_start_past_deadline() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    item = (
        _adapter(routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")})
        .plan(
            _request(
                {Market.SPOT: (spot,)},
                {Market.SPOT: frozenset({"book_deep_snapshot"})},
            )
        )
        .rest[0]
    )

    class AdvancingWallClock:
        def __init__(self) -> None:
            self.now = 10

        def monotonic_ns(self) -> int:
            return self.now

        def time_ns(self) -> int:
            self.now = 11
            return 1_800_000_000_000_000_000

    clock = AdvancingWallClock()
    http = RouteScriptedHttpTransport()
    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=StopToken(),
        network_admission=admission,
    )
    job = item.materialize(
        ready_monotonic_ns=1,
        scheduled_ns=1,
        deadline_ns=10,
    )

    with pytest.raises(NetworkAdmissionExpired, match="before HTTP started"):
        await okx_execution._capture_rest_attempt(
            item=item,
            dispatch=RestDispatch(job, job.routes[0], 10),
            runtime=runtime,
        )
    assert http.requests == []
    assert admission.release_dispositions == [NetworkAdmissionReleaseDisposition.NORMAL]


@pytest.mark.asyncio
async def test_scheduler_wait_clock_failure_does_not_leave_a_second_consumer() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    item = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    ).rest[0]
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(item.routes[0].budget_key, capacity=1, refill_per_second=1)
    scheduler = RestScheduler(budgets, clock=clock)
    now_ns = clock.monotonic_ns()
    job = item.materialize(
        ready_monotonic_ns=now_ns,
        scheduled_ns=now_ns,
        deadline_ns=now_ns + 10 * SECOND_NS,
    )
    assert await scheduler.submit(job) is SubmitResult.ENQUEUED

    class ThrowingClock:
        def monotonic_ns(self) -> int:
            raise RuntimeError("scheduler wait clock failed")

        def time_ns(self) -> int:
            return 0

    stop = StopToken()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=scheduler,
        clock=ThrowingClock(),
        stop=stop,
    )
    with pytest.raises(RuntimeError, match="scheduler wait clock failed"):
        await okx_execution._await_or_stop_until(
            scheduler.next_ready(),
            runtime,
            deadline_ns=now_ns + SECOND_NS,
        )

    dispatch = await asyncio.wait_for(
        okx_execution._await_or_stop_until(
            scheduler.next_ready(),
            replace(runtime, clock=clock),
            deadline_ns=now_ns + SECOND_NS,
        ),
        timeout=1,
    )
    assert dispatch is not None
    assert dispatch.job.id == job.id


@pytest.mark.asyncio
async def test_malformed_stop_wait_cannot_orphan_the_scheduler_consumer() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    item = (
        _adapter(routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")})
        .plan(
            _request(
                {Market.SPOT: (spot,)},
                {Market.SPOT: frozenset({"book_deep_snapshot"})},
            )
        )
        .rest[0]
    )
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(item.routes[0].budget_key, capacity=1, refill_per_second=1)
    scheduler = RestScheduler(budgets, clock=clock)
    now_ns = clock.monotonic_ns()
    job = item.materialize(
        ready_monotonic_ns=now_ns,
        scheduled_ns=now_ns,
        deadline_ns=now_ns + 10 * SECOND_NS,
    )
    assert await scheduler.submit(job) is SubmitResult.ENQUEUED

    class MalformedStop:
        def is_set(self) -> bool:
            return False

        def wait(self) -> None:
            return None

    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=scheduler,
        clock=clock,
        stop=MalformedStop(),
    )
    with pytest.raises(TypeError):
        await okx_execution._next_rest_dispatch(runtime, ())

    dispatch = await asyncio.wait_for(scheduler.next_ready(), timeout=1)
    assert dispatch.job.id == job.id


@pytest.mark.asyncio
async def test_same_tick_stop_does_not_hide_scheduler_failure() -> None:
    class FailingScheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            del job
            return SubmitResult.ENQUEUED

        async def next_ready(self) -> RestDispatch:
            raise RuntimeError("scheduler failed")

    class SameTickStop:
        def __init__(self) -> None:
            self.stopped = False

        def is_set(self) -> bool:
            return self.stopped

        async def wait(self) -> None:
            self.stopped = True

    clock = SystemClock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=FailingScheduler(),
        clock=clock,
        stop=SameTickStop(),
    )

    with pytest.raises(RuntimeError, match="scheduler failed"):
        await okx_execution._next_rest_dispatch(
            runtime,
            (),
            states={},
            catalog_controller=None,
        )


@pytest.mark.asyncio
async def test_harvested_stop_waiter_must_finish_at_a_true_level() -> None:
    started = asyncio.Event()

    class FalseStop:
        def is_set(self) -> bool:
            return False

        async def wait(self) -> None:
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                return

    async def operation() -> int:
        await started.wait()
        return 1

    runtime = _runtime(
        stop=FalseStop(),
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
    )

    with pytest.raises(RuntimeError, match="stop wait returned"):
        await okx_execution._await_or_stop(operation(), runtime)


@pytest.mark.asyncio
async def test_combined_stop_validates_an_external_waiter_cancelled_by_internal_stop() -> (
    None
):
    started = asyncio.Event()

    class FalseStop:
        def is_set(self) -> bool:
            return False

        async def wait(self) -> None:
            started.set()
            try:
                await asyncio.Event().wait()
            except asyncio.CancelledError:
                return

    internal = asyncio.Event()
    combined = okx_execution._CombinedStopToken(FalseStop(), internal)
    waiter = asyncio.create_task(combined.wait())
    await started.wait()
    internal.set()

    with pytest.raises(RuntimeError, match="stop wait returned"):
        await waiter


@pytest.mark.asyncio
async def test_preflight_rejects_missing_dynamic_fallback_before_connect() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={
            (Market.SPOT, None): OkxPlanRoute("primary", "nat-a", "spot-0"),
            (Market.SPOT, "ETH-USDT"): OkxPlanRoute("fallback", "nat-b", "unused"),
        }
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, AutoAckWebSocketConnection("unused"))
    stop = StopToken()
    runtime = _runtime(
        stop=stop,
        transports={
            "primary": EgressTransport(
                "primary", RouteScriptedHttpTransport(), websocket
            )
        },
    )

    with pytest.raises(LookupError, match="fallback"):
        await adapter.run(plan, runtime, RecordingSink())
    assert websocket.uris == []


@pytest.mark.asyncio
async def test_preflight_validates_every_ws_group_before_any_connect() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"ticker", "trade"})},
        )
    )
    public = next(item for item in plan.ws if item.endpoint == WS_PUBLIC_ENDPOINT)
    invalid = replace(public, endpoint="wss://okx.test/ws/v5/private")
    invalid_plan = replace(
        plan,
        ws=tuple(invalid if item is public else item for item in plan.ws),
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("invalid-and-unused"),
    )
    websocket.add(
        WS_BUSINESS_ENDPOINT,
        AutoAckWebSocketConnection("valid-but-unused"),
    )
    stop = StopToken()
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    with pytest.raises(ValueError, match="evidenced OKX anonymous WebSocket path"):
        await adapter.run(invalid_plan, runtime, RecordingSink())
    assert websocket.uris == []


@pytest.mark.asyncio
async def test_preflight_rejects_missing_retry_effects_before_ws_or_http() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"ticker", "book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )
    http = RouteScriptedHttpTransport()
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, AutoAckWebSocketConnection("unused"))
    runtime = _runtime(
        stop=StopToken(),
        transports={"direct": EgressTransport("direct", http, websocket)},
        include_retry_effects=False,
    )

    with pytest.raises(RuntimeError, match="OKX REST work requires retry effects"):
        await adapter.run(plan, runtime, RecordingSink())
    assert websocket.uris == []
    assert http.requests == []


@pytest.mark.asyncio
async def test_pre_set_stop_starts_no_network_operation() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"ticker", "book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )
    stop = StopToken()
    stop.set()
    http = RouteScriptedHttpTransport()
    websocket = RouteScriptedWebSocketTransport()
    admission = RecordingNetworkAdmission()
    runtime = _runtime(
        stop=stop,
        transports={"direct": EgressTransport("direct", http, websocket)},
        budget_keys=tuple(route.budget_key for route in plan.rest[0].routes),
        network_admission=admission,
    )

    await adapter.run(plan, runtime, RecordingSink())

    assert admission.calls == []
    assert http.requests == []
    assert websocket.uris == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "ws_stream_channel",
        "ws_wire_symbol",
        "rest_path",
        "catalog_path",
        "coverage",
        "ws_derivative_spot",
        "premium_spot",
        "insurance_fund_spot",
        "disabled_books_rpi",
        "duplicate_book_live",
        "extra_expectation",
        "wire_alias_collision",
        "catalog_without_ws",
        "ws_without_catalog",
    ],
)
async def test_preflight_rejects_cross_field_plan_identity_before_network(
    mutation: str,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    selected: tuple[InstrumentRecord, ...] = (spot,)
    routes: Mapping[tuple[Market, str | None], OkxPlanRoute] = {
        (Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")
    }
    if mutation == "wire_alias_collision":
        other = replace(
            _instrument(Market.SPOT, "ETH-USDT"),
            wire_symbols={"rest": "BTC-USDT", "websocket": "BTC-USDT"},
        )
        selected = (spot, other)
        routes = {
            (Market.SPOT, "BTC-USDT"): OkxPlanRoute("route-a", "nat", "spot-a"),
            (Market.SPOT, "ETH-USDT"): OkxPlanRoute("route-b", "nat", "spot-b"),
        }
    adapter = _adapter(routes=routes)
    streams = (
        frozenset({"instrument"})
        if mutation in {"catalog_path", "catalog_without_ws", "ws_without_catalog"}
        else frozenset({"book_deep_snapshot"})
        if mutation in {"rest_path", "premium_spot", "insurance_fund_spot"}
        else frozenset({"book_live"})
        if mutation in {"disabled_books_rpi", "duplicate_book_live"}
        else frozenset({"ticker"})
    )
    plan = adapter.plan(_request({Market.SPOT: selected}, {Market.SPOT: streams}))
    if mutation == "ws_stream_channel":
        item = plan.ws[0]
        plan = replace(
            plan,
            ws=(
                replace(
                    item,
                    channel="trades-all",
                    endpoint=WS_BUSINESS_ENDPOINT,
                ),
            ),
        )
    elif mutation == "ws_wire_symbol":
        plan = replace(plan, ws=(replace(plan.ws[0], wire_symbol="ETH-USDT"),))
    elif mutation == "rest_path":
        plan = replace(
            plan,
            rest=(
                replace(
                    plan.rest[0],
                    path="/api/v5/market/candles",
                    params={"instId": "ETH-USDT", "bar": "1m", "limit": 2},
                ),
            ),
        )
    elif mutation == "catalog_path":
        plan = replace(
            plan,
            catalog=(
                replace(
                    plan.catalog[0],
                    path="/api/v5/market/tickers",
                    params={"instType": "SPOT"},
                ),
            ),
        )
    elif mutation == "catalog_without_ws":
        plan = replace(
            plan,
            ws=tuple(item for item in plan.ws if item.logical_stream != "instrument"),
        )
    elif mutation == "ws_without_catalog":
        plan = replace(plan, catalog=())
    elif mutation == "ws_derivative_spot":
        item = plan.ws[0]
        plan = replace(
            plan,
            ws=(replace(item, logical_stream="mark_price", channel="mark-price"),),
            expectations=tuple(
                replace(expectation, logical_stream="mark_price")
                if expectation.logical_stream == "ticker"
                else expectation
                for expectation in plan.expectations
            ),
        )
    elif mutation in {"premium_spot", "insurance_fund_spot"}:
        stream = mutation.removesuffix("_spot")
        path = (
            "/api/v5/public/premium-history"
            if stream == "premium"
            else "/api/v5/public/insurance-fund"
        )
        params = (
            {"instId": "BTC-USDT"}
            if stream == "premium"
            else {"instType": "SWAP", "instFamily": "BTC-USDT"}
        )
        logical_endpoint = path.rsplit("/", 1)[-1]
        route = plan.rest[0].routes[0]
        plan = replace(
            plan,
            rest=(
                replace(
                    plan.rest[0],
                    logical_stream=stream,
                    path=path,
                    params=params,
                    logical_endpoint=logical_endpoint,
                    routes=(
                        replace(
                            route,
                            budget_key=("okx", "nat", logical_endpoint),
                        ),
                    ),
                ),
            ),
            expectations=tuple(
                replace(expectation, logical_stream=stream)
                if expectation.logical_stream == "book_deep_snapshot"
                else expectation
                for expectation in plan.expectations
            ),
        )
    elif mutation == "disabled_books_rpi":
        plan = replace(
            plan,
            ws=(replace(plan.ws[0], channel="books-rpi"),),
            disabled_optional_features=("books_rpi",),
        )
    elif mutation == "duplicate_book_live":
        original = plan.ws[0]
        plan = replace(
            plan,
            ws=(
                original,
                replace(
                    original,
                    id=f"{original.id}:rpi",
                    channel="books-rpi",
                ),
            ),
        )
    elif mutation == "extra_expectation":
        expectation = next(
            item for item in plan.expectations if item.logical_stream == "ticker"
        )
        plan = replace(
            plan,
            expectations=(
                *plan.expectations,
                replace(expectation, logical_stream="bbo"),
            ),
        )
    else:
        expectation = next(
            item for item in plan.expectations if item.logical_stream == "ticker"
        )
        plan = replace(
            plan,
            expectations=tuple(
                replace(item, coverage=CoverageMode.LOSSY_WINDOW)
                if item is expectation
                else item
                for item in plan.expectations
            ),
        )
    http = RouteScriptedHttpTransport()
    websocket = RouteScriptedWebSocketTransport()
    admission = RecordingNetworkAdmission()
    runtime = _runtime(
        stop=StopToken(),
        transports={"direct": EgressTransport("direct", http, websocket)},
        network_admission=admission,
    )

    with pytest.raises(ValueError):
        await adapter.run(plan, runtime, RecordingSink())
    assert websocket.uris == []
    assert http.requests == []
    assert admission.calls == []


@pytest.mark.asyncio
async def test_preflight_rejects_market_mismatched_inst_type_before_connect() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    invalid_ws = tuple(
        replace(item, params={"instType": "SWAP"})
        if item.channel == "instruments"
        else item
        for item in plan.ws
    )
    invalid_plan = replace(plan, ws=invalid_ws)
    http = RouteScriptedHttpTransport()
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, AutoAckWebSocketConnection("unused"))
    runtime = _runtime(
        stop=StopToken(),
        transports={"direct": EgressTransport("direct", http, websocket)},
    )

    with pytest.raises(ValueError, match="must match spot market"):
        await adapter.run(invalid_plan, runtime, RecordingSink())
    assert websocket.uris == []
    assert http.requests == []


@pytest.mark.asyncio
async def test_child_failure_latches_internal_stop_and_closes_other_group() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"ticker", "trade"})},
        )
    )

    class SameTickSend(AutoAckWebSocketConnection):
        def __init__(self) -> None:
            super().__init__("public")
            self.cancel_swallowed = asyncio.Event()
            self.owner: asyncio.Task[object] | None = None
            self.observed_cancelling: list[int] = []

        async def __aenter__(self) -> Self:
            owner = asyncio.current_task()
            assert owner is not None
            self.owner = cast(asyncio.Task[object], owner)
            return await super().__aenter__()

        async def send(self, message: str) -> None:
            await super().send(message)
            assert self.owner is not None
            asyncio.get_running_loop().call_soon(self.owner.cancel)

        async def recv(self) -> str | bytes:
            assert self.owner is not None
            self.observed_cancelling.append(self.owner.cancelling())
            assert self.owner.cancelling() == 1
            self.cancel_swallowed.set()
            return await super().recv()

    class FailingSend(AutoAckWebSocketConnection):
        def __init__(self, first: SameTickSend) -> None:
            super().__init__("business")
            self._first = first

        async def send(self, message: str) -> None:
            del message
            await self._first.cancel_swallowed.wait()
            raise ValueError("injected business connect failure")

    public = SameTickSend()
    business = FailingSend(public)
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, public)
    websocket.add(WS_BUSINESS_ENDPOINT, business)
    stop = StopToken()
    admission = RecordingNetworkAdmission()
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        network_admission=admission,
    )

    with pytest.raises(ValueError, match="injected business connect failure"):
        await asyncio.wait_for(
            adapter.run(plan, runtime, RecordingSink()),
            timeout=1,
        )
    assert public.closed
    assert business.closed
    assert public.observed_cancelling == [1]
    assert len(admission.releases) == 2


@pytest.mark.asyncio
async def test_double_cancel_waits_for_websocket_context_and_lease_cleanup() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )

    class BlockingSend(AutoAckWebSocketConnection):
        def __init__(self) -> None:
            super().__init__("blocking-send")
            self.entered = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def send(self, message: str) -> None:
            del message
            self.entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled.set()

    connection = BlockingSend()
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    admission = RecordingNetworkAdmission()
    runtime = _runtime(
        stop=StopToken(),
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        network_admission=admission,
    )
    run_task = asyncio.create_task(adapter.run(plan, runtime, RecordingSink()))
    await asyncio.wait_for(connection.entered.wait(), timeout=1)

    run_task.cancel()
    asyncio.get_running_loop().call_soon(run_task.cancel)
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(run_task, timeout=1)

    assert connection.cancelled.is_set()
    assert connection.closed
    assert admission.releases == [(Exchange.OKX, Transport.WEBSOCKET, "direct", "nat")]
    assert admission.release_dispositions == [NetworkAdmissionReleaseDisposition.NORMAL]


@pytest.mark.asyncio
async def test_stop_during_admitted_http_cancels_transport_and_releases_lease() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )

    class BlockingHttp(RouteScriptedHttpTransport):
        def __init__(self) -> None:
            super().__init__()
            self.entered = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def get(self, *args: object, **kwargs: object) -> httpx.Response:
            del args, kwargs
            self.entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled.set()
            raise AssertionError("unreachable")

    http = BlockingHttp()
    stop = StopToken()
    admission = RecordingNetworkAdmission()
    item = plan.rest[0]
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        budget_keys=(item.routes[0].budget_key,),
        network_admission=admission,
    )
    run_task = asyncio.create_task(adapter.run(plan, runtime, RecordingSink()))
    await asyncio.wait_for(http.entered.wait(), timeout=2)
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)
    assert http.cancelled.is_set()
    assert admission.releases == [(Exchange.OKX, Transport.REST, "direct", "nat")]


@pytest.mark.asyncio
async def test_slow_rest_attempt_crosses_deadline_without_false_expiry() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    interval_ns = 10_000_000
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={
                "book_deep_snapshot": IntervalPlan(
                    interval_ns,
                    interval_ns,
                    None,
                )
            },
        )
    )

    class SlowFirstHttp(RouteScriptedHttpTransport):
        def __init__(self) -> None:
            super().__init__()
            self.calls = 0
            self.first_started = asyncio.Event()
            self.release_first = asyncio.Event()

        async def get(self, *args: object, **kwargs: object) -> httpx.Response:
            del args, kwargs
            self.calls += 1
            if self.calls == 1:
                self.first_started.set()
                await self.release_first.wait()
            return okx_response(
                {
                    "code": "0",
                    "msg": "",
                    "data": [
                        {
                            "asks": [["101", "1", "1"]],
                            "bids": [["100", "1", "1"]],
                            "ts": "1800000000123",
                        }
                    ],
                }
            )

    http = SlowFirstHttp()
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            sum(
                row.logical_stream == "book_deep_snapshot"
                for row, _source, _shard in sink.rows
            )
            == 2
        ),
    )
    item = plan.rest[0]
    admission = RecordingNetworkAdmission()
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        budget_keys=(item.routes[0].budget_key,),
        network_admission=admission,
    )
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await asyncio.wait_for(http.first_started.wait(), timeout=1)
    await asyncio.sleep(0.05)
    before_release_controls = [
        cast(dict[str, object], draft.payload)
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "_control" and isinstance(draft.payload, dict)
    ]
    assert any(
        payload.get("kind") == "rest_cadence_skipped"
        and payload.get("reason") == "in_flight"
        for payload in before_release_controls
    )
    skipped = [
        payload
        for payload in before_release_controls
        if payload.get("kind") == "rest_cadence_skipped"
        and payload.get("reason") == "in_flight"
    ]
    skipped_scheduled = [
        cast(int, payload["scheduled_monotonic_ns"]) for payload in skipped
    ]
    assert len(skipped_scheduled) >= 2
    assert skipped_scheduled == sorted(set(skipped_scheduled))
    blocked_by = {
        cast(int, payload["blocked_by_scheduled_monotonic_ns"]) for payload in skipped
    }
    assert len(blocked_by) == 1
    assert next(iter(blocked_by)) < skipped_scheduled[0]
    assert not any(
        payload.get("kind") == "rest_occurrence_expired"
        for payload in before_release_controls
    )
    http.release_first.set()
    await asyncio.wait_for(run_task, timeout=2)
    assert http.calls >= 2
    assert (
        sum(
            draft.logical_stream == "book_deep_snapshot"
            for draft, _source, _shard in sink.rows
        )
        == 2
    )
    assert not any(
        isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "rest_occurrence_expired"
        for draft, _source, _shard in sink.rows
    )
    assert len(admission.releases) >= 2


@pytest.mark.asyncio
async def test_local_connection_ids_are_unique_per_endpoint_before_server_ack() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"ticker", "trade"})},
        )
    )

    class NoAckConnection(AutoAckWebSocketConnection):
        async def send(self, message: str) -> None:
            self.sent.append(message)

    public = NoAckConnection("unused-public-id", "pong")
    business = NoAckConnection("unused-business-id", "pong")
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, public)
    websocket.add(WS_BUSINESS_ENDPOINT, business)
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            sum(
                isinstance(row.payload, dict) and row.payload.get("kind") == "ws_pong"
                for row, _source, _shard in sink.rows
            )
            == 2
        ),
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                websocket,
            )
        },
    )

    await adapter.run(plan, runtime, sink)

    pongs = [
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict) and draft.payload.get("kind") == "ws_pong"
    ]
    assert len(pongs) == 2
    connection_ids = {cast(str, payload["connection_id"]) for payload in pongs}
    assert len(connection_ids) == 2
    assert all(
        identifier.startswith("okx-spot-spot-0-") for identifier in connection_ids
    )
    assert public.closed and business.closed


@pytest.mark.asyncio
async def test_server_ack_never_changes_local_connection_identity_across_generation() -> (
    None
):
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection(
            "server-connection-one",
            "pong",
            _data_frame("tickers", "first", inst_id="BTC-USDT"),
        ),
        AutoAckWebSocketConnection(
            "server-connection-two",
            _data_frame("tickers", "second", inst_id="BTC-USDT"),
        ),
    )

    async def collect_once() -> tuple[str, RecordingSink]:
        stop = StopToken()
        sink = RecordingSink(
            stop=stop,
            stop_when=lambda draft: draft.logical_stream == "ticker",
        )
        runtime = _runtime(
            stop=stop,
            transports={
                "direct": EgressTransport(
                    "direct", RouteScriptedHttpTransport(), websocket
                )
            },
        )
        await adapter.run(plan, runtime, sink)
        data_source = next(
            source
            for draft, source, _shard in sink.rows
            if draft.logical_stream == "ticker"
        )
        return cast(str, data_source.connection_id), sink

    first_connection_id, first_sink = await collect_once()
    second_connection_id, _second_sink = await collect_once()
    controls = [
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in first_sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") in {"ws_subscribe_ack", "ws_pong"}
    ]
    assert {cast(str, payload["connection_id"]) for payload in controls} == {
        first_connection_id
    }
    ack = next(payload for payload in controls if payload["kind"] == "ws_subscribe_ack")
    assert ack["server_connection_id"] == "server-connection-one"
    assert all(payload["origin_transport"] == "websocket" for payload in controls)
    assert first_connection_id != "server-connection-one"
    assert first_connection_id != second_connection_id


@pytest.mark.asyncio
async def test_invalid_binary_websocket_frame_is_preserved_as_base64_control() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    connection = AutoAckWebSocketConnection("binary", b"\xff")
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "ws_reconnect"
        ),
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    await adapter.run(plan, runtime, sink)

    control = next(
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "ws_reconnect"
    )
    assert control["reason"] == "protocol_error"
    assert control["error_type"] == "OkxWsProtocolError"
    assert control["frame_encoding"] == "base64"
    assert control["frame_base64"] == "/w=="
    assert control["frame_byte_length"] == 1
    assert "frame" not in control
    assert connection.closed


@pytest.mark.asyncio
async def test_liquidation_preserves_one_multi_instrument_frame_with_unknown_time() -> (
    None
):
    swap = _instrument(Market.PERPETUAL, "BTC-USDT-SWAP")
    route = OkxPlanRoute("direct", "direct", "perpetual-0")
    adapter = _adapter(routes={(Market.PERPETUAL, None): route})
    plan = adapter.plan(
        _request(
            {Market.PERPETUAL: (swap,)},
            {Market.PERPETUAL: frozenset({"liquidation"})},
        )
    )
    payload = {
        "arg": {"channel": "liquidation-orders", "instType": "SWAP"},
        "data": [
            {"instId": "BTC-USDT-SWAP", "details": [{"ts": "2"}]},
            {"instId": "ETH-USDT-SWAP", "details": [{"ts": "1"}]},
        ],
        "future": {"kept": True},
    }
    connection = AutoAckWebSocketConnection(
        "liquidation-1",
        json.dumps(payload, separators=(",", ":")),
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "liquidation",
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    await adapter.run(plan, runtime, sink)

    rows = [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "liquidation"
    ]
    assert len(rows) == 1
    assert rows[0].payload == payload
    assert rows[0].event_time_ns is None
    assert rows[0].instrument_key is None
    assert rows[0].coverage is CoverageMode.LOSSY_WINDOW


@pytest.mark.asyncio
async def test_wrong_symbol_is_controlled_and_never_written_to_planned_stream() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    wrong = json.dumps(
        {
            "arg": {"channel": "tickers", "instId": "BTC-USDT"},
            "data": [{"instId": "ETH-USDT", "ts": "1800000000123"}],
        },
        separators=(",", ":"),
    )
    connection = AutoAckWebSocketConnection("wrong-symbol", wrong)
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            draft.logical_stream == "_control"
            and isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "ws_reconnect"
        ),
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    await adapter.run(plan, runtime, sink)

    assert not [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "ticker"
    ]
    reconnect = [
        draft
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "ws_reconnect"
    ]
    assert len(reconnect) == 1
    assert reconnect[0].payload["frame"] == json.loads(wrong)  # type: ignore[index]


@pytest.mark.asyncio
async def test_protocol_error_control_preserves_raw_frame_and_egress() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("socks-a", "shared-nat", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    connection = AutoAckWebSocketConnection("protocol-error", "not-json")
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            draft.logical_stream == "_control"
            and isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "ws_reconnect"
        ),
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "socks-a": EgressTransport(
                "socks-a",
                RouteScriptedHttpTransport(),
                websocket,
            )
        },
    )

    await adapter.run(plan, runtime, sink)

    reconnect = next(
        draft
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "ws_reconnect"
    )
    payload = cast(dict[str, JsonPayload], reconnect.payload)
    assert payload["frame"] == "not-json"
    assert payload["egress_id"] == "socks-a"
    assert payload["reason"] == "protocol_error"


@pytest.mark.asyncio
async def test_market_overflow_reconnects_only_that_websocket_generation() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    first = AutoAckWebSocketConnection(
        "generation-1",
        _data_frame("tickers", "first", inst_id="BTC-USDT"),
    )
    second = AutoAckWebSocketConnection(
        "generation-2",
        _data_frame("tickers", "second", inst_id="BTC-USDT"),
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, first, second)
    stop = StopToken()
    ticker_count = 0

    def status_for(draft: NativeEventDraft) -> EnqueueStatus:
        nonlocal ticker_count
        if draft.logical_stream == "ticker":
            ticker_count += 1
            if ticker_count == 1:
                return EnqueueStatus.OVERFLOW
        return EnqueueStatus.ACCEPTED

    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "ticker" and ticker_count == 2,
        status_for=status_for,
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    await adapter.run(plan, runtime, sink)

    assert websocket.uris == [WS_PUBLIC_ENDPOINT, WS_PUBLIC_ENDPOINT]
    assert first.closed and second.closed
    sources = [
        source
        for draft, source, _shard in sink.rows
        if draft.logical_stream == "ticker"
    ]
    assert [source.connection_generation for source in sources] == [1, 2]


@pytest.mark.asyncio
async def test_control_rejection_propagates_instead_of_reconnect_loop() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    connection = AutoAckWebSocketConnection("rejected")
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    sink = RecordingSink(
        status_for=lambda draft: (
            EnqueueStatus.NOT_ACCEPTING
            if draft.logical_stream == "_control"
            else EnqueueStatus.ACCEPTED
        )
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    with pytest.raises(RuntimeError, match="event sink rejected"):
        await adapter.run(plan, runtime, sink)

    assert websocket.uris == [WS_PUBLIC_ENDPOINT]


@pytest.mark.asyncio
async def test_maintenance_sequence_reset_is_informational_and_keeps_generation() -> (
    None
):
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"book_live"})})
    )
    connection = AutoAckWebSocketConnection(
        "maintenance",
        _book_frame(action="snapshot", sequence=100, previous=-1),
        _book_frame(action="update", sequence=50, previous=100),
        _book_frame(action="update", sequence=51, previous=50),
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            sum(row.logical_stream == "book_live" for row, _source, _shard in sink.rows)
            == 3
        ),
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    await adapter.run(plan, runtime, sink)

    books = [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "book_live"
    ]
    assert len(books) == 3
    assert {draft.integrity_mode for draft in books} == {
        IntegrityMode.SEQUENCE_VERIFIED
    }
    kinds = [
        draft.payload.get("kind")
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "_control" and isinstance(draft.payload, dict)
    ]
    assert kinds.count("book_sequence_reset") == 1
    assert "book_gap" not in kinds
    assert websocket.uris == [WS_PUBLIC_ENDPOINT]


@pytest.mark.asyncio
async def test_preopen_crossed_snapshot_is_valid_without_reconnect() -> None:
    spot = _instrument(
        Market.SPOT,
        "BTC-USDT",
        phase=LifecyclePhase.PREOPEN,
    )
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"book_live"})})
    )
    connection = AutoAckWebSocketConnection(
        "preopen",
        _book_frame(
            action="snapshot",
            sequence=1,
            previous=-1,
            bid="102",
            ask="101",
        ),
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "book_live",
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    await adapter.run(plan, runtime, sink)

    books = [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "book_live"
    ]
    assert [draft.integrity_mode for draft in books] == [
        IntegrityMode.SEQUENCE_VERIFIED
    ]
    assert not [
        draft
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict) and draft.payload.get("kind") == "book_gap"
    ]


@pytest.mark.asyncio
async def test_rest_candidate_is_selected_per_occurrence_but_retry_stays_on_egress() -> (
    None
):
    spot = _instrument(Market.SPOT, "BTC-USDT")
    primary = OkxPlanRoute("primary", "nat-primary", "spot-0")
    secondary = OkxPlanRoute("secondary", "nat-secondary", "ignored-shard")
    adapter = _adapter(
        routes={(Market.SPOT, None): primary},
        rest_routes={Market.SPOT: (secondary,)},
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={
                "book_deep_snapshot": IntervalPlan(
                    SECOND_NS,
                    SECOND_NS,
                    None,
                )
            },
        )
    )
    item = plan.rest[0]
    routes = item.routes
    primary_http = RouteScriptedHttpTransport()
    secondary_http = RouteScriptedHttpTransport()
    secondary_http.add(
        "/api/v5/market/books-full",
        okx_response(
            {"code": "50011", "msg": "limited", "data": []},
            headers={"retry-after": "0"},
        ),
        okx_response(
            {
                "code": "0",
                "msg": "",
                "data": [
                    {
                        "asks": [["101", "1", "1"]],
                        "bids": [["100", "1", "1"]],
                        "ts": "1800000000123",
                    }
                ],
            }
        ),
    )
    stop = StopToken()
    sink = RecordingSink()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    primary_bucket = budgets.add(
        routes[0].budget_key,
        capacity=1,
        refill_per_second=1,
    )
    budgets.add(routes[1].budget_key, capacity=100, refill_per_second=100)
    assert primary_bucket.try_acquire(1)
    scheduler = RestScheduler(budgets, clock=clock)

    class RecordingScheduler:
        def __init__(self) -> None:
            self.jobs: list[RestJob] = []

        async def submit(self, job: RestJob) -> SubmitResult:
            self.jobs.append(job)
            result = await scheduler.submit(job)
            if len(self.jobs) == 3:
                stop.set()
            if job.attempt == 2:
                assert result is SubmitResult.ENQUEUED
                return SubmitResult.EVICTED_AND_ENQUEUED
            return result

        async def next_ready(self) -> RestDispatch:
            return await scheduler.next_ready()

    recording_scheduler = RecordingScheduler()
    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={
            "primary": EgressTransport(
                "primary", primary_http, RouteScriptedWebSocketTransport()
            ),
            "secondary": EgressTransport(
                "secondary", secondary_http, RouteScriptedWebSocketTransport()
            ),
        },
        scheduler=recording_scheduler,
        clock=clock,
        stop=stop,
        retry_effects=(retry_effects := RecordingRetryEffects()),
        network_admission=admission,
    )

    await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=3)

    assert primary_http.requests == []
    assert len(secondary_http.requests) == 2
    deep = [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "book_deep_snapshot"
    ]
    assert len(deep) == 1
    assert deep[0].rest_metadata is not None
    assert deep[0].rest_metadata.attempt == 2
    control = next(
        draft
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict) and draft.payload.get("kind") == "rest_retry"
    )
    payload = cast(dict[str, JsonPayload], control.payload)
    assert payload["origin_transport"] == "rest"
    assert payload["egress_id"] == "secondary"
    assert payload["attempt"] == 1
    assert payload["status"] == 200
    assert payload["response"] == {"code": "50011", "msg": "limited", "data": []}
    assert len(retry_effects.calls) == 1
    assert retry_effects.calls[0][0].route == routes[1]
    initial, retry, next_occurrence = recording_scheduler.jobs
    assert initial.routes == routes
    assert retry.routes == (routes[1],)
    assert retry.scheduled_ns == initial.scheduled_ns
    assert retry.deadline_ns == initial.deadline_ns
    assert retry.attempt == 2
    assert next_occurrence.routes == routes
    assert next_occurrence.scheduled_ns > initial.scheduled_ns
    assert next_occurrence.attempt == 1
    assert admission.calls == [
        (
            Exchange.OKX,
            Transport.REST,
            "secondary",
            "nat-secondary",
            initial.deadline_ns,
        ),
        (
            Exchange.OKX,
            Transport.REST,
            "secondary",
            "nat-secondary",
            retry.deadline_ns,
        ),
    ]


@pytest.mark.asyncio
async def test_invalid_json_runtime_control_preserves_exact_binary_body() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )
    http = RouteScriptedHttpTransport()
    http.add("/api/v5/market/books-full", httpx.Response(200, content=b"\xff"))
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "rest_terminal"
        ),
    )
    item = plan.rest[0]
    admission = RecordingNetworkAdmission()
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        budget_keys=(item.routes[0].budget_key,),
        network_admission=admission,
    )

    await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=2)

    control = next(
        draft
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "rest_terminal"
    )
    response = cast(dict[str, JsonPayload], control.payload)["response"]
    evidence = cast(dict[str, JsonPayload], response)
    assert evidence == {
        "body_encoding": "base64",
        "body_base64": "/w==",
        "body_byte_length": 1,
    }
    assert b64decode(cast(str, evidence["body_base64"]), validate=True) == b"\xff"
    assert len(admission.releases) == 1


@pytest.mark.asyncio
async def test_retry_effect_is_applied_before_rest_lease_releases_same_quota() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"ticker", "book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )
    order: list[str] = []
    effect_applied = asyncio.Event()

    class SerialAdmission:
        def __init__(self) -> None:
            self.lock = asyncio.Lock()
            self.rest_waiting = asyncio.Event()
            self.ws_acquired = False

        async def acquire(
            self,
            *,
            exchange: Exchange,
            transport: Transport,
            egress_id: str,
            quota_group: str,
            deadline_monotonic_ns: int | None,
        ) -> NetworkAdmissionLease:
            del deadline_monotonic_ns
            if transport is Transport.WEBSOCKET:
                await self.rest_waiting.wait()
                await effect_applied.wait()
            await self.lock.acquire()
            order.append(f"acquire-{transport.value}")
            if transport is Transport.REST:
                self.rest_waiting.set()
            else:
                self.ws_acquired = True

            async def release(
                disposition: NetworkAdmissionReleaseDisposition,
            ) -> None:
                assert disposition is NetworkAdmissionReleaseDisposition.NORMAL
                order.append(f"release-{transport.value}")
                self.lock.release()

            return NetworkAdmissionLease(
                exchange=exchange,
                transport=transport,
                egress_id=egress_id,
                quota_group=quota_group,
                _release=release,
            )

    admission = SerialAdmission()

    class Effects:
        def apply(self, dispatch: RestDispatch, decision: RetryDecision) -> None:
            del dispatch, decision
            assert not admission.ws_acquired
            assert admission.lock.locked()
            order.append("effect")
            effect_applied.set()

    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/market/books-full",
        okx_response(
            {"code": "50011", "msg": "limited", "data": []},
            headers={"retry-after": "0"},
        ),
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection(
            "same-quota",
            _data_frame("tickers", "ready", inst_id="BTC-USDT"),
        ),
    )
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "ticker",
    )
    item = plan.rest[0]
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(item.routes[0].budget_key, capacity=100, refill_per_second=100)
    runtime = AdapterRuntime(
        transports={"direct": EgressTransport("direct", http, websocket)},
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        retry_effects=Effects(),
        network_admission=admission,
    )
    await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=2)

    assert effect_applied.is_set()
    assert order.index("effect") < order.index("release-rest")
    assert order.index("release-rest") < order.index("acquire-websocket")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_point",
    ["classification", "clock", "decision", "effect"],
)
async def test_retry_transaction_failure_releases_fail_closed(
    failure_point: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    item = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    ).rest[0]
    admission = RecordingNetworkAdmission()
    runtime = _runtime(
        stop=StopToken(),
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        network_admission=admission,
    )
    now_ns = runtime.clock.monotonic_ns()
    job = item.materialize(
        ready_monotonic_ns=now_ns,
        scheduled_ns=now_ns,
        deadline_ns=now_ns + SECOND_NS,
    )
    dispatch = RestDispatch(job, job.routes[0], now_ns)
    lease = await admission.acquire(
        exchange=Exchange.OKX,
        transport=Transport.REST,
        egress_id="direct",
        quota_group="nat",
        deadline_monotonic_ns=job.deadline_ns,
    )
    attempt = okx_execution._RestAttemptResult(
        capture=None,
        response_error=okx_execution.OkxResponseError(
            http_status=200,
            exchange_code="50011",
            exchange_message="limited",
            retry_action=okx_execution.RetryAction.THROTTLE,
            retry_after="0",
            raw_payload={"code": "50011"},
        ),
        transport_error=None,
        request_started_at_ns=1,
        request_ended_at_ns=2,
        lease=lease,
    )
    policy = okx_execution.retry_policy(
        clock=runtime.clock,
        rng=random.Random(1),
        max_attempts=2,
        base_ns=1,
        cap_ns=1,
    )
    if failure_point == "classification":

        def fail_classification(error: object) -> object:
            del error
            raise RuntimeError("retry transaction failed")

        monkeypatch.setattr(okx_execution, "_retry_classification", fail_classification)
    elif failure_point == "clock":

        class ThrowingClock:
            def monotonic_ns(self) -> int:
                raise RuntimeError("retry transaction failed")

            def time_ns(self) -> int:
                return 0

        runtime = replace(runtime, clock=ThrowingClock())
    elif failure_point == "decision":

        class ThrowingPolicy:
            def decide(self, **kwargs: object) -> RetryDecision:
                del kwargs
                raise RuntimeError("retry transaction failed")

        policy = cast(okx_execution.RetryPolicy, ThrowingPolicy())
    else:

        class ThrowingEffects:
            def apply(self, dispatch: RestDispatch, decision: RetryDecision) -> None:
                del dispatch, decision
                raise RuntimeError("retry transaction failed")

        runtime = replace(runtime, retry_effects=ThrowingEffects())

    with pytest.raises(RuntimeError, match="retry transaction failed"):
        await okx_execution._classify_rest_retry_and_release(
            attempt_result=attempt,
            policy=policy,
            dispatch=dispatch,
            runtime=runtime,
            deadline_ns=cast(int, job.deadline_ns),
        )
    assert admission.releases == [(Exchange.OKX, Transport.REST, "direct", "nat")]
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    ]


@pytest.mark.asyncio
async def test_fail_closed_release_error_note_never_contains_secret_material() -> None:
    canary = "socks5://user:token-canary@127.0.0.1:1080"
    release_calls: list[NetworkAdmissionReleaseDisposition] = []

    async def release(disposition: NetworkAdmissionReleaseDisposition) -> None:
        release_calls.append(disposition)
        raise RuntimeError(canary)

    lease = NetworkAdmissionLease(
        exchange=Exchange.OKX,
        transport=Transport.REST,
        egress_id="direct",
        quota_group="nat",
        _release=release,
    )
    spot = _instrument(Market.SPOT, "BTC-USDT")
    item = (
        _adapter(routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")})
        .plan(
            _request(
                {Market.SPOT: (spot,)},
                {Market.SPOT: frozenset({"book_deep_snapshot"})},
            )
        )
        .rest[0]
    )
    clock = SystemClock()
    now_ns = clock.monotonic_ns()
    job = item.materialize(
        ready_monotonic_ns=now_ns,
        scheduled_ns=now_ns,
        deadline_ns=now_ns + SECOND_NS,
    )
    dispatch = RestDispatch(job, job.routes[0], now_ns)

    class ThrowingEffects:
        def apply(self, dispatch: RestDispatch, decision: RetryDecision) -> None:
            del dispatch, decision
            raise RuntimeError("effect persistence failed")

    runtime = replace(
        _runtime(
            stop=StopToken(),
            transports={
                "direct": EgressTransport(
                    "direct",
                    RouteScriptedHttpTransport(),
                    RouteScriptedWebSocketTransport(),
                )
            },
            network_admission=RecordingNetworkAdmission(),
        ),
        retry_effects=ThrowingEffects(),
    )
    attempt = okx_execution._RestAttemptResult(
        capture=None,
        response_error=okx_execution.OkxResponseError(
            http_status=200,
            exchange_code="50011",
            exchange_message="limited",
            retry_action=okx_execution.RetryAction.THROTTLE,
            retry_after="0",
            raw_payload={"code": "50011"},
        ),
        transport_error=None,
        request_started_at_ns=1,
        request_ended_at_ns=2,
        lease=lease,
    )
    policy = okx_execution.retry_policy(
        clock=clock,
        rng=random.Random(1),
        max_attempts=2,
        base_ns=1,
        cap_ns=1,
    )

    with pytest.raises(RuntimeError, match="effect persistence failed") as caught:
        await okx_execution._classify_rest_retry_and_release(
            attempt_result=attempt,
            policy=policy,
            dispatch=dispatch,
            runtime=runtime,
            deadline_ns=cast(int, job.deadline_ns),
        )
    rendered = " ".join(
        [repr(caught.value), str(caught.value), *getattr(caught.value, "__notes__", ())]
    )
    assert canary not in rendered
    assert release_calls == [NetworkAdmissionReleaseDisposition.FAIL_CLOSED]


@pytest.mark.parametrize("retry_submission", ["expired", "capacity"])
@pytest.mark.asyncio
async def test_routine_retry_submission_terminal_never_claims_actual_egress(
    retry_submission: str,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    primary = OkxPlanRoute("primary", "nat-primary", "spot-0")
    secondary = OkxPlanRoute("secondary", "nat-secondary", "unused")
    adapter = _adapter(
        routes={(Market.SPOT, None): primary},
        rest_routes={Market.SPOT: (secondary,)},
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )
    item = plan.rest[0]
    primary_http = RouteScriptedHttpTransport()
    secondary_http = RouteScriptedHttpTransport()
    secondary_http.add(
        "/api/v5/market/books-full",
        okx_response(
            {"code": "50011", "msg": "limited", "data": []},
            headers={"retry-after": "0"},
        ),
    )
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "rest_terminal"
        ),
    )
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    primary_bucket = budgets.add(
        item.routes[0].budget_key,
        capacity=1,
        refill_per_second=1,
    )
    assert primary_bucket.try_acquire(1)
    budgets.add(item.routes[1].budget_key, capacity=100, refill_per_second=100)
    scheduler = RestScheduler(budgets, clock=clock)

    class RejectingRetryScheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            if job.attempt == 2:
                if retry_submission == "capacity":
                    raise okx_execution.CapacityError("full")
                return SubmitResult.EXPIRED
            return await scheduler.submit(job)

        async def next_ready(self) -> RestDispatch:
            return await scheduler.next_ready()

    runtime = AdapterRuntime(
        transports={
            "primary": EgressTransport(
                "primary", primary_http, RouteScriptedWebSocketTransport()
            ),
            "secondary": EgressTransport(
                "secondary", secondary_http, RouteScriptedWebSocketTransport()
            ),
        },
        scheduler=RejectingRetryScheduler(),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=2)
    controls = [
        cast(dict[str, object], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") in {"rest_retry", "rest_terminal"}
    ]
    assert [payload["kind"] for payload in controls] == [
        "rest_retry",
        "rest_terminal",
    ]
    terminal = controls[1]
    assert terminal["egress_id"] is None
    assert terminal["dispatched"] is False
    assert terminal["planned_egress_id"] == "secondary"
    assert terminal["sticky_egress_id"] == "secondary"
    assert terminal["candidate_egress_ids"] == ["primary", "secondary"]
    assert primary_http.requests == []
    assert len(secondary_http.requests) == 1


def test_initial_schedule_rejection_has_candidates_but_no_actual_egress() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("primary", "nat-a", "spot-0")},
        rest_routes={Market.SPOT: (OkxPlanRoute("secondary", "nat-b", "unused"),)},
    )
    item = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    ).rest[0]
    draft, _source = okx_execution._rest_control(
        kind="rest_schedule_rejected",
        item=item,
        attempt=1,
        reason="capacity_exhausted",
        scheduled_ns=100,
        deadline_ns=200,
    )
    payload = cast(dict[str, object], draft.payload)
    assert payload["egress_id"] is None
    assert payload["dispatched"] is False
    assert payload["candidate_egress_ids"] == ["primary", "secondary"]
    assert payload["planned_egress_id"] is None


@pytest.mark.asyncio
async def test_malformed_rest_success_is_terminal_with_complete_evidence() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"candle_1m"})},
            intervals={
                "candle_1m": IntervalPlan(SECOND_NS, SECOND_NS, None),
            },
        )
    )
    malformed = {
        "code": "0",
        "msg": "",
        "data": [["1800000000123", "too-short"]],
        "future": {"preserved": True},
    }
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/market/candles",
        okx_response(
            malformed,
            headers={"x-ratelimit-remaining": "9"},
        ),
    )
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            draft.logical_stream == "_control"
            and isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "rest_terminal"
        ),
    )
    item = plan.rest[0]
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport(
                "direct",
                http,
                RouteScriptedWebSocketTransport(),
            )
        },
        budget_keys=(item.routes[0].budget_key,),
    )

    await adapter.run(plan, runtime, sink)

    assert len(http.requests) == 1
    assert not [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "candle_1m"
    ]
    terminal = next(
        draft
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "rest_terminal"
    )
    payload = cast(dict[str, JsonPayload], terminal.payload)
    assert terminal.market is None
    assert payload["origin_transport"] == "rest"
    assert payload["response"] == malformed
    assert payload["egress_id"] == "direct"
    assert payload["method"] == "GET"
    assert payload["path"] == "/api/v5/market/candles"
    assert payload["params"] == {
        "instId": "BTC-USDT",
        "bar": "1m",
        "limit": 2,
    }
    assert payload["status"] == 200
    assert payload["attempt"] == 1
    assert payload["rate_limit_headers"] == {"x-ratelimit-remaining": "9"}
    assert isinstance(payload["request_started_at_ns"], int)
    assert isinstance(payload["request_ended_at_ns"], int)
    assert isinstance(payload["rest_metadata"], dict)


@pytest.mark.asyncio
async def test_recoverable_parse_failure_releases_next_cadence_occurrence() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"candle_1m"})},
            intervals={
                "candle_1m": IntervalPlan(100_000_000, 100_000_000, None),
            },
        )
    )
    malformed = {
        "code": "0",
        "msg": "",
        "data": [["1800000000123", "too-short"]],
    }
    valid = {
        "code": "0",
        "msg": "",
        "data": [
            [
                "1800000001123",
                "1",
                "2",
                "0.5",
                "1.5",
                "10",
                "15",
                "20",
                "1",
            ]
        ],
    }
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/market/candles",
        okx_response(malformed),
        okx_response(valid),
    )
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "candle_1m",
    )
    item = plan.rest[0]
    admission = RecordingNetworkAdmission()
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport(
                "direct",
                http,
                RouteScriptedWebSocketTransport(),
            )
        },
        budget_keys=(item.routes[0].budget_key,),
        network_admission=admission,
    )

    await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=2)

    assert len(http.requests) == 2
    assert len(admission.releases) == 2
    assert (
        sum(draft.logical_stream == "candle_1m" for draft, _source, _shard in sink.rows)
        == 1
    )
    assert any(
        isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "rest_terminal"
        and draft.payload.get("response") == malformed
        for draft, _source, _shard in sink.rows
    )


@pytest.mark.asyncio
async def test_rest_transport_failure_control_has_complete_no_response_evidence() -> (
    None
):
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )
    http = RouteScriptedHttpTransport()
    http.add("/api/v5/market/books-full", OSError("connection refused"))
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "rest_retry"
        ),
    )
    item = plan.rest[0]

    class Health:
        def __init__(self) -> None:
            self.failures: list[tuple[Transport, str, str]] = []

        def choose_websocket_egress(
            self,
            *,
            exchange: Exchange,
            market: Market,
            endpoint: str,
            preferred_egress_id: str,
            previous_egress_id: str | None,
        ) -> str:
            del exchange, market, endpoint, previous_egress_id
            return preferred_egress_id

        def is_egress_available(
            self,
            *,
            exchange: Exchange,
            egress_id: str,
        ) -> bool:
            del exchange, egress_id
            return True

        def record_transport_failure(
            self,
            *,
            exchange: Exchange,
            transport: Transport,
            egress_id: str,
            reason: str,
        ) -> None:
            del exchange
            self.failures.append((transport, egress_id, reason))

    health = Health()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(item.routes[0].budget_key, capacity=100, refill_per_second=100)
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                http,
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        transport_health=health,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )

    await adapter.run(plan, runtime, sink)

    control = next(
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict) and draft.payload.get("kind") == "rest_retry"
    )
    assert control["origin_transport"] == "rest"
    assert control["egress_id"] == "direct"
    assert control["attempt"] == 1
    assert control["method"] == "GET"
    assert control["path"] == "/api/v5/market/books-full"
    assert control["params"] == {"instId": "BTC-USDT", "sz": 5000}
    assert isinstance(control["request_started_at_ns"], int)
    assert isinstance(control["request_ended_at_ns"], int)
    assert cast(int, control["request_ended_at_ns"]) >= cast(
        int, control["request_started_at_ns"]
    )
    assert control["status"] is None
    assert control["rate_limit_headers"] == {}
    assert control["response"] is None
    assert control["requested_interval_ns"] == SECOND_NS
    assert control["effective_interval_ns"] == SECOND_NS
    assert control["rest_metadata"] is None
    assert "connection refused" not in json.dumps(control, sort_keys=True)
    assert health.failures == [(Transport.REST, "direct", "OSError")]


@pytest.mark.asyncio
async def test_throwing_rest_health_recorder_still_releases_attempt_lease() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    item = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    ).rest[0]
    http = RouteScriptedHttpTransport()
    http.add("/api/v5/market/books-full", OSError("route down"))

    class ThrowingHealth:
        def __init__(self) -> None:
            self.calls = 0

        def is_egress_available(self, *, exchange: Exchange, egress_id: str) -> bool:
            del exchange, egress_id
            return True

        def choose_websocket_egress(
            self,
            *,
            exchange: Exchange,
            market: Market,
            endpoint: str,
            preferred_egress_id: str,
            previous_egress_id: str | None,
        ) -> str:
            del exchange, market, endpoint, previous_egress_id
            return preferred_egress_id

        def record_transport_failure(self, **kwargs: object) -> None:
            del kwargs
            raise RuntimeError("health persistence failed")

    clock = SystemClock()
    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=StopToken(),
        transport_health=ThrowingHealth(),
        network_admission=admission,
    )
    now_ns = clock.monotonic_ns()
    job = item.materialize(
        ready_monotonic_ns=now_ns,
        scheduled_ns=now_ns,
        attempt=1,
        deadline_ns=now_ns + SECOND_NS,
    )
    with pytest.raises(RuntimeError, match="health persistence failed"):
        await okx_execution._capture_rest_attempt(
            item=item,
            dispatch=RestDispatch(job, job.routes[0], now_ns),
            runtime=runtime,
        )
    assert admission.releases == [(Exchange.OKX, Transport.REST, "direct", "nat")]


@pytest.mark.asyncio
async def test_transport_failure_end_clock_error_fail_closes_attempt_lease() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    item = (
        _adapter(routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")})
        .plan(
            _request(
                {Market.SPOT: (spot,)},
                {Market.SPOT: frozenset({"book_deep_snapshot"})},
            )
        )
        .rest[0]
    )
    http = RouteScriptedHttpTransport()
    http.add("/api/v5/market/books-full", OSError("route down"))

    class Clock:
        def __init__(self) -> None:
            self.time_calls = 0

        def monotonic_ns(self) -> int:
            return 1

        def time_ns(self) -> int:
            self.time_calls += 1
            if self.time_calls == 2:
                raise RuntimeError("end clock failed")
            return 1

    clock = Clock()
    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=StopToken(),
        network_admission=admission,
    )
    job = item.materialize(
        ready_monotonic_ns=1,
        scheduled_ns=1,
        deadline_ns=SECOND_NS,
    )

    with pytest.raises(RuntimeError, match="end clock failed"):
        await okx_execution._capture_rest_attempt(
            item=item,
            dispatch=RestDispatch(job, job.routes[0], 1),
            runtime=runtime,
        )
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    ]


@pytest.mark.asyncio
async def test_response_end_clock_failure_records_exact_evidence_before_fail_closed() -> (
    None
):
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )

    class Clock:
        def __init__(self) -> None:
            self.time_calls = 0
            self.system = SystemClock()

        def monotonic_ns(self) -> int:
            return self.system.monotonic_ns()

        def time_ns(self) -> int:
            self.time_calls += 1
            if self.time_calls == 2:
                raise RuntimeError("response end clock failed")
            return 100

    order: list[str] = []

    class Admission(RecordingNetworkAdmission):
        async def acquire(self, **kwargs: object) -> NetworkAdmissionLease:
            lease = await super().acquire(**cast(dict[str, object], kwargs))
            original_release = lease._release

            async def release(
                disposition: NetworkAdmissionReleaseDisposition,
            ) -> None:
                order.append("release")
                await original_release(disposition)

            return replace(lease, _release=release)

    class Sink(RecordingSink):
        def try_emit(
            self,
            draft: NativeEventDraft,
            *,
            source: SourceContext,
            shard: str,
        ) -> EnqueueResult:
            if (
                isinstance(draft.payload, dict)
                and draft.payload.get("reason") == "response_end_evidence_failed"
            ):
                order.append("control")
            return super().try_emit(draft, source=source, shard=shard)

    clock = Clock()
    item = plan.rest[0]
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/market/books-full",
        httpx.Response(
            429,
            content=b"\xff",
            headers={
                "retry-after": "7",
                "x-ratelimit-remaining": "0",
                "authorization": "must-not-be-recorded",
            },
        ),
    )
    budgets = BudgetRegistry(clock)
    budgets.add(item.routes[0].budget_key, capacity=10, refill_per_second=10)
    admission = Admission()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=StopToken(),
        retry_effects=RecordingRetryEffects(),
        network_admission=admission,
    )
    sink = Sink()

    with pytest.raises(RuntimeError, match="response end clock failed"):
        await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=2)

    control = next(
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("reason") == "response_end_evidence_failed"
    )
    assert control["evidence_complete"] is False
    assert control["failure_type"] == "RuntimeError"
    assert control["request_started_at_ns"] == 100
    assert control["request_ended_at_ns"] is None
    assert control["status"] == 429
    assert control["response"] == {
        "body_encoding": "base64",
        "body_base64": "/w==",
        "body_byte_length": 1,
    }
    assert control["rate_limit_headers"] == {
        "retry-after": "7",
        "x-ratelimit-remaining": "0",
    }
    assert control["egress_id"] == "direct"
    assert control["planned_egress_id"] == "direct"
    assert len(http.requests) == 1
    assert order == ["control", "release"]
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    ]


@pytest.mark.asyncio
async def test_retry_effect_failure_records_response_before_fail_closed() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )
    order: list[str] = []

    class Admission(RecordingNetworkAdmission):
        async def acquire(self, **kwargs: object) -> NetworkAdmissionLease:
            lease = await super().acquire(**cast(dict[str, object], kwargs))
            original_release = lease._release

            async def release(
                disposition: NetworkAdmissionReleaseDisposition,
            ) -> None:
                order.append("release")
                await original_release(disposition)

            return replace(lease, _release=release)

    class Effects:
        def apply(self, dispatch: RestDispatch, decision: RetryDecision) -> None:
            del dispatch, decision
            raise RuntimeError("retry effect persistence failed")

    class Sink(RecordingSink):
        def try_emit(
            self,
            draft: NativeEventDraft,
            *,
            source: SourceContext,
            shard: str,
        ) -> EnqueueResult:
            if (
                isinstance(draft.payload, dict)
                and draft.payload.get("reason") == "retry_transaction_failed"
            ):
                order.append("control")
            return super().try_emit(draft, source=source, shard=shard)

    item = plan.rest[0]
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/market/books-full",
        okx_response(
            {"code": "50011", "msg": "limited", "data": []},
            headers={"retry-after": "3", "x-ratelimit-remaining": "0"},
        ),
    )
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(item.routes[0].budget_key, capacity=10, refill_per_second=10)
    admission = Admission()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=StopToken(),
        retry_effects=Effects(),
        network_admission=admission,
    )
    sink = Sink()

    with pytest.raises(RuntimeError, match="retry effect persistence failed"):
        await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=2)

    control = next(
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("reason") == "retry_transaction_failed"
    )
    assert control["evidence_complete"] is False
    assert control["failure_type"] == "RuntimeError"
    assert control["request_started_at_ns"] is not None
    assert control["request_ended_at_ns"] is None
    assert control["status"] == 200
    assert control["response"] == {
        "code": "50011",
        "msg": "limited",
        "data": [],
    }
    assert control["rate_limit_headers"] == {
        "retry-after": "3",
        "x-ratelimit-remaining": "0",
    }
    assert control["rest_metadata"] is None
    assert order == ["control", "release"]
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    ]


@pytest.mark.asyncio
async def test_unread_http_response_is_a_fail_closed_port_contract_error() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    item = (
        _adapter(routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")})
        .plan(
            _request(
                {Market.SPOT: (spot,)},
                {Market.SPOT: frozenset({"book_deep_snapshot"})},
            )
        )
        .rest[0]
    )
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/market/books-full",
        httpx.Response(
            200,
            headers={
                "x-ratelimit-remaining": "4",
                "authorization": "must-not-be-recorded",
            },
            stream=httpx.ByteStream(b'{"code":"0","data":[]}'),
        ),
    )
    clock = SystemClock()
    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=StopToken(),
        network_admission=admission,
    )
    now_ns = clock.monotonic_ns()
    job = item.materialize(
        ready_monotonic_ns=now_ns,
        scheduled_ns=now_ns,
        attempt=1,
        deadline_ns=now_ns + SECOND_NS,
    )
    sink = RecordingSink()

    with pytest.raises(
        okx_execution.OkxExecutionError,
        match="unreadable response evidence",
    ):
        await okx_execution._capture_rest_attempt(
            item=item,
            dispatch=RestDispatch(job, job.routes[0], now_ns),
            runtime=runtime,
            sink=sink,
        )

    control = next(
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("reason") == "response_contract_failed"
    )
    assert control["evidence_complete"] is False
    assert control["request_started_at_ns"] is not None
    assert control["request_ended_at_ns"] is None
    assert control["status"] == 200
    assert control["rate_limit_headers"] == {"x-ratelimit-remaining": "4"}
    assert control["response"] is None
    assert control["body_unavailable"] is True
    assert control["rest_metadata"] is None
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("status_mode", ["false", "low", "high", "repr", "getter"])
async def test_invalid_http_status_is_sanitized_and_fail_closed(
    status_mode: str,
) -> None:
    canary = "STATUS_PRIVATE_CANARY"
    spot = _instrument(Market.SPOT, "BTC-USDT")
    item = (
        _adapter(routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")})
        .plan(
            _request(
                {Market.SPOT: (spot,)},
                {Market.SPOT: frozenset({"book_deep_snapshot"})},
            )
        )
        .rest[0]
    )

    class SecretStatus:
        def __repr__(self) -> str:
            return canary

    class InvalidResponse:
        @property
        def status_code(self) -> object:
            if status_mode == "getter":
                raise RuntimeError(canary)
            return {
                "false": False,
                "low": 99,
                "high": 600,
                "repr": SecretStatus(),
            }[status_mode]

        @property
        def headers(self) -> Mapping[str, str]:
            return {
                "x-ratelimit-remaining": "4",
                "authorization": canary,
            }

        @property
        def content(self) -> bytes:
            return b'{"code":"0","data":[]}'

        def __repr__(self) -> str:
            return canary

    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/market/books-full",
        cast(httpx.Response, InvalidResponse()),
    )
    clock = SystemClock()
    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=StopToken(),
        network_admission=admission,
    )
    now_ns = clock.monotonic_ns()
    job = item.materialize(
        ready_monotonic_ns=now_ns,
        scheduled_ns=now_ns,
        attempt=1,
        deadline_ns=now_ns + SECOND_NS,
    )
    sink = RecordingSink()

    with pytest.raises(okx_execution.OkxExecutionError) as caught:
        await okx_execution._capture_rest_attempt(
            item=item,
            dispatch=RestDispatch(job, job.routes[0], now_ns),
            runtime=runtime,
            sink=sink,
        )

    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    rendered = "".join(
        traceback.StackSummary.extract(
            (
                (frame, line)
                for frame, line in traceback.walk_tb(caught.value.__traceback__)
                if "/src/crypto_collector/" in frame.f_code.co_filename
            ),
            capture_locals=True,
        ).format()
    )
    assert canary not in rendered
    control = next(
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("reason") == "response_contract_failed"
    )
    assert control["status"] is None
    assert control["response"] == {"code": "0", "data": []}
    assert control["evidence_complete"] is False
    assert control["request_ended_at_ns"] is None
    assert control["rest_metadata"] is None
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    ]


@pytest.mark.asyncio
async def test_rest_transport_health_filters_only_the_next_occurrence_after_restart(
    tmp_path: Path,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    primary = OkxPlanRoute("primary", "nat-shared", "spot-0")
    secondary = OkxPlanRoute("secondary", "nat-shared", "ignored-shard")
    adapter = _adapter(
        routes={(Market.SPOT, None): primary},
        rest_routes={Market.SPOT: (secondary,)},
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )
    item = plan.rest[0]

    class PersistentHealth:
        def __init__(self, store: EgressStateStore) -> None:
            self._store = store

        def is_egress_available(
            self,
            *,
            exchange: Exchange,
            egress_id: str,
        ) -> bool:
            return not self._store.load_egress(
                exchange.value,
                egress_id,
            ).requires_probe

        def choose_websocket_egress(
            self,
            *,
            exchange: Exchange,
            market: Market,
            endpoint: str,
            preferred_egress_id: str,
            previous_egress_id: str | None,
        ) -> str:
            del exchange, market, endpoint, previous_egress_id
            return preferred_egress_id

        def record_transport_failure(
            self,
            *,
            exchange: Exchange,
            transport: Transport,
            egress_id: str,
            reason: str,
        ) -> None:
            del transport
            self._store.record_transport_failure(
                exchange=exchange.value,
                egress_id=egress_id,
                reason=reason,
            )

    class RecordingScheduler:
        def __init__(self) -> None:
            self.jobs: list[RestJob] = []

        async def submit(self, job: RestJob) -> SubmitResult:
            self.jobs.append(job)
            return SubmitResult.ENQUEUED

        async def next_ready(self) -> RestDispatch:
            raise AssertionError("route materialization test does not dispatch")

    primary_http = RouteScriptedHttpTransport()
    primary_http.add("/api/v5/market/books-full", OSError("route down"))
    transports = {
        "primary": EgressTransport(
            "primary", primary_http, RouteScriptedWebSocketTransport()
        ),
        "secondary": EgressTransport(
            "secondary",
            RouteScriptedHttpTransport(),
            RouteScriptedWebSocketTransport(),
        ),
    }
    clock = SystemClock()
    stop = StopToken()
    scheduled_ns = clock.monotonic_ns()
    deadline_ns = scheduled_ns + SECOND_NS
    state_path = tmp_path / "egress-health.sqlite"
    with EgressStateStore.open(state_path) as first_store:
        first_scheduler = RecordingScheduler()
        first_runtime = AdapterRuntime(
            transports=transports,
            scheduler=first_scheduler,
            clock=clock,
            stop=stop,
            transport_health=PersistentHealth(first_store),
            network_admission=RecordingNetworkAdmission(),
        )
        first_job = item.materialize(
            ready_monotonic_ns=scheduled_ns,
            scheduled_ns=scheduled_ns,
            attempt=1,
            deadline_ns=deadline_ns,
        )
        attempt = await okx_execution._capture_rest_attempt(
            item=item,
            dispatch=RestDispatch(first_job, item.routes[0], scheduled_ns),
            runtime=first_runtime,
        )
        assert isinstance(attempt.transport_error, OSError)
        assert first_store.load_egress("okx", "primary").requires_probe
        assert not first_store.load_egress("okx", "secondary").requires_probe
        assert not first_store.load_quota("okx", "nat-shared").requires_probe

        await okx_execution._submit_rest_occurrence(
            item=item,
            runtime=first_runtime,
            scheduled_ns=scheduled_ns,
            ready_ns=scheduled_ns,
            deadline_ns=deadline_ns,
            attempt=2,
            sticky_route=item.routes[0],
        )
        assert first_scheduler.jobs[0].routes == (item.routes[0],)

    # A new runtime reads the same durable health state. A new occurrence can
    # fail over, while its shard and plan identity remain owned by the primary.
    with EgressStateStore.open(state_path) as restarted_store:
        restarted_scheduler = RecordingScheduler()
        restarted_health = PersistentHealth(restarted_store)
        restarted_runtime = AdapterRuntime(
            transports=transports,
            scheduler=restarted_scheduler,
            clock=clock,
            stop=stop,
            transport_health=restarted_health,
        )
        await okx_execution._submit_rest_occurrence(
            item=item,
            runtime=restarted_runtime,
            scheduled_ns=scheduled_ns + SECOND_NS,
            ready_ns=scheduled_ns + SECOND_NS,
            deadline_ns=deadline_ns + SECOND_NS,
            attempt=1,
        )
        assert restarted_scheduler.jobs[0].routes == (item.routes[1],)
        assert item.shard_id == "spot-0"
        assert not restarted_health.is_egress_available(
            exchange=Exchange.OKX,
            egress_id="primary",
        )
        assert restarted_health.is_egress_available(
            exchange=Exchange.OKX,
            egress_id="secondary",
        )
        assert not restarted_store.load_quota("okx", "nat-shared").requires_probe

        # The egress circuit is shared by both transports; the failure does not
        # create a transport-specific health partition.
        restarted_health.record_transport_failure(
            exchange=Exchange.OKX,
            transport=Transport.WEBSOCKET,
            egress_id="secondary",
            reason="transport_error",
        )
        assert not restarted_health.is_egress_available(
            exchange=Exchange.OKX,
            egress_id="secondary",
        )


@pytest.mark.asyncio
async def test_catalog_bootstrap_selects_available_secondary_route() -> None:
    primary = OkxPlanRoute("primary", "nat-primary", "spot-primary")
    secondary = OkxPlanRoute("secondary", "nat-secondary", "ignored-secondary")
    adapter = _adapter(
        routes={(Market.SPOT, None): primary},
        rest_routes={Market.SPOT: (secondary,)},
    )
    fixture_bytes = (_FIXTURES / "instruments-spot.json").read_bytes()
    primary_http = RouteScriptedHttpTransport()
    secondary_http = RouteScriptedHttpTransport()
    secondary_http.add(
        "/api/v5/public/instruments",
        httpx.Response(200, content=fixture_bytes),
    )
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    primary_bucket = budgets.add(
        ("okx", "nat-primary", "instruments"),
        capacity=1,
        refill_per_second=1,
    )
    assert primary_bucket.try_acquire(1)
    budgets.add(
        ("okx", "nat-secondary", "instruments"),
        capacity=100,
        refill_per_second=100,
    )
    scheduler = RestScheduler(budgets, clock=clock)

    class BootstrapEvictingScheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            result = await scheduler.submit(job)
            assert result is SubmitResult.ENQUEUED
            return SubmitResult.EVICTED_AND_ENQUEUED

        async def next_ready(self) -> RestDispatch:
            return await scheduler.next_ready()

    runtime = AdapterRuntime(
        transports={
            "primary": EgressTransport(
                "primary",
                primary_http,
                RouteScriptedWebSocketTransport(),
            ),
            "secondary": EgressTransport(
                "secondary",
                secondary_http,
                RouteScriptedWebSocketTransport(),
            ),
        },
        scheduler=BootstrapEvictingScheduler(),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )

    snapshot = await adapter.fetch_catalog(runtime, Market.SPOT)

    assert snapshot.instruments
    assert primary_http.requests == []
    assert len(secondary_http.requests) == 1


@pytest.mark.asyncio
async def test_fetch_catalog_bootstrap_and_active_refresh_share_one_consumer() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    http = RouteScriptedHttpTransport()
    fixture_bytes = (_FIXTURES / "instruments-spot.json").read_bytes()
    payload = decode_json(fixture_bytes)
    assert isinstance(payload, dict)
    http.add(
        "/api/v5/public/instruments",
        httpx.Response(200, content=fixture_bytes),
        httpx.Response(200, content=fixture_bytes),
    )
    websocket = RouteScriptedWebSocketTransport()
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(("okx", "direct", "instruments"), capacity=100, refill_per_second=100)
    scheduler = RestScheduler(budgets, clock=clock)

    class SingleConsumerScheduler:
        def __init__(self) -> None:
            self.active_consumers = 0
            self.max_consumers = 0

        async def submit(self, job: RestJob) -> SubmitResult:
            return await scheduler.submit(job)

        async def next_ready(self) -> RestDispatch:
            self.active_consumers += 1
            self.max_consumers = max(self.max_consumers, self.active_consumers)
            try:
                return await scheduler.next_ready()
            finally:
                self.active_consumers -= 1

    tracked = SingleConsumerScheduler()
    runtime = AdapterRuntime(
        transports={"direct": EgressTransport("direct", http, websocket)},
        scheduler=tracked,
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )

    catalog = await adapter.fetch_catalog(runtime, Market.SPOT)

    assert {item.instrument_key for item in catalog.instruments} == {
        "BTC-USDT",
        "NEW-USDT",
    }
    assert [request.path for request in http.requests] == ["/api/v5/public/instruments"]

    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    blocking = AutoAckWebSocketConnection("blocking")
    websocket.add(WS_PUBLIC_ENDPOINT, blocking)
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await _wait_until(lambda: blocking.drained.is_set())
    refreshed = await asyncio.wait_for(
        adapter.fetch_catalog(runtime, Market.SPOT),
        timeout=2,
    )

    assert {item.instrument_key for item in refreshed.instruments} == {
        "BTC-USDT",
        "NEW-USDT",
    }
    assert tracked.max_consumers == 1
    raw = [
        (draft, source, shard)
        for draft, source, shard in sink.rows
        if draft.logical_stream == "instrument" and draft.transport is Transport.REST
    ]
    assert len(raw) == 1
    assert raw[0][0].payload == payload
    assert raw[0][1].egress_id == "direct"
    assert raw[0][2] == "spot-0"
    stop.set()
    await run_task
    assert len(http.requests) == 2


@pytest.mark.asyncio
async def test_active_catalog_uses_same_configured_market_route_as_market_stream() -> (
    None
):
    selected = _instrument(Market.SPOT, "ZZZ-USDT")
    shard_a = OkxPlanRoute("egress-a", "nat-a", "shard-a")
    shard_z = OkxPlanRoute("egress-z", "nat-z", "shard-z")
    adapter = _adapter(
        routes={
            (Market.SPOT, "AAA-USDT"): shard_a,
            (Market.SPOT, "ZZZ-USDT"): shard_z,
        }
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (selected,)},
            {Market.SPOT: frozenset({"instrument"})},
        )
    )
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/public/instruments",
        httpx.Response(200, content=(_FIXTURES / "instruments-spot.json").read_bytes()),
    )
    websocket = RouteScriptedWebSocketTransport()
    blocking = AutoAckWebSocketConnection("market-route")
    websocket.add(WS_PUBLIC_ENDPOINT, blocking)
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(("okx", "nat-z", "instruments"), capacity=1, refill_per_second=1)
    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={
            "egress-a": EgressTransport(
                "egress-a",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            ),
            "egress-z": EgressTransport("egress-z", http, websocket),
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        network_admission=admission,
        retry_effects=RecordingRetryEffects(),
    )
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await _wait_until(lambda: blocking.drained.is_set())

    snapshot = await asyncio.wait_for(
        adapter.fetch_catalog(runtime, Market.SPOT),
        timeout=1,
    )
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)

    assert snapshot.instruments
    raw = [
        (draft, source, shard)
        for draft, source, shard in sink.rows
        if draft.logical_stream == "instrument" and draft.transport is Transport.REST
    ]
    assert len(raw) == 1
    assert raw[0][1].egress_id == "egress-z"
    assert raw[0][2] == "shard-z"
    assert admission.calls[0] == (
        Exchange.OKX,
        Transport.WEBSOCKET,
        "egress-z",
        "nat-z",
        None,
    )
    assert admission.calls[1][:4] == (
        Exchange.OKX,
        Transport.REST,
        "egress-z",
        "nat-z",
    )
    assert admission.calls[1][4] is not None


@pytest.mark.asyncio
async def test_active_catalog_eviction_does_not_permanently_stop_rest_cadence() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    interval_ns = 20_000_000
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"instrument", "book_deep_snapshot"})},
            intervals={
                "book_deep_snapshot": IntervalPlan(
                    interval_ns,
                    interval_ns,
                    None,
                )
            },
        )
    )
    http = RouteScriptedHttpTransport()
    fixture_bytes = (_FIXTURES / "instruments-spot.json").read_bytes()
    http.add(
        "/api/v5/public/instruments",
        httpx.Response(200, content=fixture_bytes),
    )
    http.add(
        "/api/v5/market/books-full",
        okx_response(
            {
                "code": "0",
                "msg": "",
                "data": [
                    {
                        "asks": [["101", "1", "1"]],
                        "bids": [["100", "1", "1"]],
                        "ts": "1800000000123",
                    }
                ],
            }
        ),
    )
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "book_deep_snapshot",
    )
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    for item in plan.rest:
        for candidate in item.routes:
            budgets.add(candidate.budget_key, capacity=100, refill_per_second=100)
    budgets.add(("okx", "direct", "instruments"), capacity=100, refill_per_second=100)
    scheduler = RestScheduler(budgets, clock=clock, max_pending=1)

    class GatedScheduler:
        def __init__(self) -> None:
            self.routine_submitted = asyncio.Event()
            self.catalog_submitted = asyncio.Event()
            self.allow_dispatch = asyncio.Event()
            self.active_consumers = 0
            self.max_consumers = 0
            self.catalog_result: SubmitResult | None = None

        async def submit(self, job: RestJob) -> SubmitResult:
            result = await scheduler.submit(job)
            plan_item_id = job.control_context.get("plan_item_id")
            if type(plan_item_id) is str and plan_item_id.endswith(":catalog"):
                self.catalog_result = result
                self.catalog_submitted.set()
                self.allow_dispatch.set()
            else:
                self.routine_submitted.set()
            return result

        async def next_ready(self) -> RestDispatch:
            self.active_consumers += 1
            self.max_consumers = max(self.max_consumers, self.active_consumers)
            try:
                await self.allow_dispatch.wait()
                return await scheduler.next_ready()
            finally:
                self.active_consumers -= 1

    gated = GatedScheduler()
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("catalog-eviction"),
    )
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                http,
                websocket,
            )
        },
        scheduler=gated,
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )

    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await asyncio.wait_for(gated.routine_submitted.wait(), timeout=1)
    refreshed = await asyncio.wait_for(
        adapter.fetch_catalog(runtime, Market.SPOT),
        timeout=1,
    )
    await asyncio.wait_for(run_task, timeout=1)

    assert refreshed.instruments
    assert gated.catalog_result is SubmitResult.EVICTED_AND_ENQUEUED
    assert len(scheduler.evicted_ids()) == 1
    assert gated.max_consumers == 1
    assert [request.path for request in http.requests] == [
        "/api/v5/public/instruments",
        "/api/v5/market/books-full",
    ]
    kinds = [
        draft.payload.get("kind")
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "_control" and isinstance(draft.payload, dict)
    ]
    assert "rest_occurrence_expired" in kinds


@pytest.mark.asyncio
async def test_catalog_bootstrap_deadline_bounds_silent_scheduler_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(okx_execution, "_CATALOG_DEADLINE_NS", 1_000_000)
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    stop = StopToken()

    class Clock:
        def time_ns(self) -> int:
            return 1_800_000_000_000_000_000

        def monotonic_ns(self) -> int:
            return 100

    clock = Clock()
    budgets = BudgetRegistry(clock)
    bucket = budgets.add(
        ("okx", "direct", "instruments"),
        capacity=1,
        refill_per_second=1,
    )
    assert bucket.try_acquire(1)
    http = RouteScriptedHttpTransport()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                http,
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )

    with pytest.raises(TimeoutError, match="deadline"):
        await asyncio.wait_for(
            adapter.fetch_catalog(runtime, Market.SPOT),
            timeout=0.2,
        )
    assert http.requests == []


@pytest.mark.asyncio
async def test_active_catalog_schema_failure_preserves_raw_and_settles_future() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    malformed = {
        "code": "0",
        "msg": "",
        "data": [{"instType": "SPOT", "future": {"preserved": True}}],
    }
    http = RouteScriptedHttpTransport()
    http.add("/api/v5/public/instruments", okx_response(malformed))
    websocket = RouteScriptedWebSocketTransport()
    blocking = AutoAckWebSocketConnection("catalog-schema")
    websocket.add(WS_PUBLIC_ENDPOINT, blocking)
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(("okx", "direct", "instruments"), capacity=100, refill_per_second=100)
    runtime = AdapterRuntime(
        transports={"direct": EgressTransport("direct", http, websocket)},
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await _wait_until(lambda: blocking.drained.is_set())

    with pytest.raises(okx_execution.OkxPayloadError):
        await asyncio.wait_for(
            adapter.fetch_catalog(runtime, Market.SPOT),
            timeout=1,
        )
    raw = [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "instrument" and draft.transport is Transport.REST
    ]
    assert len(raw) == 1
    assert raw[0].payload == malformed
    assert any(
        isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "rest_terminal"
        and draft.payload.get("response") == malformed
        for draft, _source, _shard in sink.rows
    )
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)


@pytest.mark.asyncio
async def test_queued_catalog_deadline_emits_one_terminal_before_settling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(okx_execution, "_CATALOG_DEADLINE_NS", 1_000_000)
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    bucket = budgets.add(
        ("okx", "direct", "instruments"),
        capacity=1,
        refill_per_second=1,
    )
    assert bucket.try_acquire(1)
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("queued-catalog")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await asyncio.wait_for(connection.drained.wait(), timeout=1)
    with pytest.raises(TimeoutError, match="deadline"):
        await asyncio.wait_for(
            adapter.fetch_catalog(runtime, Market.SPOT),
            timeout=1,
        )
    terminals = [
        cast(dict[str, object], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "rest_terminal"
        and draft.payload.get("reason") == "catalog_queue_deadline_expired"
    ]
    assert len(terminals) == 1
    assert terminals[0]["egress_id"] is None
    assert terminals[0]["dispatched"] is False
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)


@pytest.mark.asyncio
async def test_watchdog_owned_submission_cancel_remains_a_queue_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(okx_execution, "_CATALOG_DEADLINE_NS", 1_000_000)
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    stop = StopToken()
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("watchdog-owned-cancel")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    item = plan.catalog[0]
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        budget_keys=(item.routes[0].budget_key,),
    )
    submission_cancelled = asyncio.Event()

    async def committed_after_watchdog_cancel(**kwargs: object) -> object:
        del kwargs
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError as cancellation:
            submission_cancelled.set()
            return okx_execution._SubmitOutcome(
                SubmitResult.ENQUEUED,
                cancellation,
            )
        raise AssertionError("unreachable")

    monkeypatch.setattr(
        okx_execution,
        "_submit_rest_occurrence",
        committed_after_watchdog_cancel,
    )
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await asyncio.wait_for(connection.drained.wait(), timeout=1)

    with pytest.raises(TimeoutError, match="deadline"):
        await asyncio.wait_for(
            adapter.fetch_catalog(runtime, Market.SPOT),
            timeout=1,
        )
    assert submission_cancelled.is_set()
    assert not run_task.done()
    terminals = [
        draft
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("reason") == "catalog_queue_deadline_expired"
    ]
    assert len(terminals) == 1
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)


@pytest.mark.asyncio
async def test_catalog_watchdog_sink_failure_settles_request_and_stops_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(okx_execution, "_CATALOG_DEADLINE_NS", 1_000_000)
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    bucket = budgets.add(
        ("okx", "direct", "instruments"),
        capacity=1,
        refill_per_second=1,
    )
    assert bucket.try_acquire(1)
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("catalog-fatal")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )

    def status_for(draft: NativeEventDraft) -> EnqueueStatus:
        if (
            isinstance(draft.payload, dict)
            and draft.payload.get("reason") == "catalog_queue_deadline_expired"
        ):
            return EnqueueStatus.NOT_ACCEPTING
        return EnqueueStatus.ACCEPTED

    sink = RecordingSink(status_for=status_for)
    controller = okx_execution.OkxCatalogController(
        plan=plan,
        runtime=runtime,
        sink=sink,
    )
    run_task = asyncio.create_task(
        okx_execution.run_okx_plan(
            plan,
            runtime,
            sink,
            catalog_controller=controller,
        )
    )
    await asyncio.wait_for(connection.drained.wait(), timeout=1)
    request_task = asyncio.create_task(controller.request(Market.SPOT))

    with pytest.raises(okx_execution.OkxExecutionError, match="sink rejected"):
        await asyncio.wait_for(request_task, timeout=1)
    with pytest.raises(okx_execution.OkxExecutionError, match="sink rejected"):
        await asyncio.wait_for(run_task, timeout=1)
    assert controller.pending(plan.catalog[0].id) is None
    assert connection.closed


@pytest.mark.asyncio
async def test_catalog_watchdog_fatal_cancels_an_in_flight_routine_http(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(okx_execution, "_CATALOG_DEADLINE_NS", 1_000_000)
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"instrument", "book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None)},
        )
    )

    class BlockingHttp(RouteScriptedHttpTransport):
        def __init__(self) -> None:
            super().__init__()
            self.started = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def get(self, *args: object, **kwargs: object) -> httpx.Response:
            del args, kwargs
            self.started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled.set()
            raise AssertionError("unreachable")

    http = BlockingHttp()
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("catalog-fatal-slow-http")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()

    class WatchdogClock:
        def __init__(self) -> None:
            self.system = SystemClock()
            self.frozen_monotonic_ns: int | None = None

        def time_ns(self) -> int:
            return self.system.time_ns()

        def monotonic_ns(self) -> int:
            if self.frozen_monotonic_ns is not None:
                return self.frozen_monotonic_ns
            return self.system.monotonic_ns()

        def freeze(self) -> None:
            self.frozen_monotonic_ns = self.system.monotonic_ns()

        def advance(self, delta_ns: int) -> None:
            assert self.frozen_monotonic_ns is not None
            self.frozen_monotonic_ns += delta_ns

    clock = WatchdogClock()
    budgets = BudgetRegistry(clock)
    deep_item = plan.rest[0]
    for route in deep_item.routes:
        budgets.add(route.budget_key, capacity=100, refill_per_second=100)
    catalog_key = plan.catalog[0].routes[0].budget_key
    catalog_bucket = budgets.add(catalog_key, capacity=1, refill_per_second=1)
    scheduler = RestScheduler(budgets, clock=clock)
    catalog_submitted = asyncio.Event()

    class CatalogSubmissionScheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            result = await scheduler.submit(job)
            if job.control_context.get("plan_item_id") == plan.catalog[0].id:
                catalog_submitted.set()
            return result

        async def next_ready(self) -> RestDispatch:
            return await scheduler.next_ready()

    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={"direct": EgressTransport("direct", http, websocket)},
        scheduler=CatalogSubmissionScheduler(),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=admission,
    )

    def status_for(draft: NativeEventDraft) -> EnqueueStatus:
        if (
            isinstance(draft.payload, dict)
            and draft.payload.get("reason") == "catalog_queue_deadline_expired"
        ):
            return EnqueueStatus.NOT_ACCEPTING
        return EnqueueStatus.ACCEPTED

    sink = RecordingSink(status_for=status_for)
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await asyncio.wait_for(http.started.wait(), timeout=2)
    clock.freeze()
    assert catalog_bucket.try_acquire(1)
    request_task = asyncio.create_task(adapter.fetch_catalog(runtime, Market.SPOT))
    await asyncio.wait_for(catalog_submitted.wait(), timeout=1)
    clock.advance(1_000_001)

    with pytest.raises(okx_execution.OkxExecutionError, match="sink rejected"):
        await asyncio.wait_for(request_task, timeout=1)
    with pytest.raises(okx_execution.OkxExecutionError, match="sink rejected"):
        await asyncio.wait_for(run_task, timeout=1)
    assert http.cancelled.is_set()
    assert connection.closed
    assert (
        admission.release_dispositions.count(NetworkAdmissionReleaseDisposition.NORMAL)
        >= 2
    )


@pytest.mark.asyncio
async def test_initial_catalog_capacity_error_is_durable_before_raise() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )

    class CapacityScheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            del job
            raise okx_execution.CapacityError("full")

        async def next_ready(self) -> RestDispatch:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    stop = StopToken()
    clock = SystemClock()
    sink = RecordingSink()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=CapacityScheduler(),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    controller = okx_execution.OkxCatalogController(
        plan=plan,
        runtime=runtime,
        sink=sink,
    )
    with pytest.raises(okx_execution.CapacityError):
        await controller.request(Market.SPOT)
    terminals = [
        cast(dict[str, object], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "rest_terminal"
    ]
    assert len(terminals) == 1
    assert terminals[0]["reason"] == "catalog_submission_CapacityError"
    assert terminals[0]["egress_id"] is None
    await controller.close()


@pytest.mark.asyncio
async def test_run_stop_cancels_controller_owned_catalog_submission() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )

    class BlockingScheduler:
        def __init__(self) -> None:
            self.submit_started = asyncio.Event()
            self.submit_cancelled = asyncio.Event()

        async def submit(self, job: RestJob) -> SubmitResult:
            del job
            self.submit_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.submit_cancelled.set()
            raise AssertionError("unreachable")

        async def next_ready(self) -> RestDispatch:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")

    scheduler = BlockingScheduler()
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("blocking-submit")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    clock = SystemClock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        scheduler=scheduler,
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    run_task = asyncio.create_task(adapter.run(plan, runtime, RecordingSink()))
    await asyncio.wait_for(connection.drained.wait(), timeout=1)
    request_task = asyncio.create_task(adapter.fetch_catalog(runtime, Market.SPOT))
    await asyncio.wait_for(scheduler.submit_started.wait(), timeout=1)

    stop.set()
    await asyncio.wait_for(run_task, timeout=1)
    with pytest.raises(asyncio.CancelledError):
        await request_task
    assert scheduler.submit_cancelled.is_set()
    assert connection.closed


@pytest.mark.asyncio
async def test_catalog_retry_silent_expiry_preserves_attempt_and_sticky_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(okx_execution, "_CATALOG_DEADLINE_NS", 50_000_000)
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/public/instruments",
        okx_response(
            {"code": "50011", "msg": "limited", "data": []},
            headers={"retry-after": "0"},
        ),
    )
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("retry-expiry")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(("okx", "direct", "instruments"), capacity=100, refill_per_second=100)
    scheduler = RestScheduler(budgets, clock=clock)

    class SilentRetryScheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            if job.attempt == 2:
                return SubmitResult.ENQUEUED
            return await scheduler.submit(job)

        async def next_ready(self) -> RestDispatch:
            return await scheduler.next_ready()

    runtime = AdapterRuntime(
        transports={"direct": EgressTransport("direct", http, websocket)},
        scheduler=SilentRetryScheduler(),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await asyncio.wait_for(connection.drained.wait(), timeout=1)
    with pytest.raises(TimeoutError, match="deadline"):
        await asyncio.wait_for(
            adapter.fetch_catalog(runtime, Market.SPOT),
            timeout=1,
        )
    terminal = next(
        cast(dict[str, object], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("reason") == "catalog_queue_deadline_expired"
    )
    assert terminal["attempt"] == 2
    assert terminal["egress_id"] is None
    assert terminal["planned_egress_id"] == "direct"
    assert terminal["sticky_egress_id"] == "direct"
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)


@pytest.mark.asyncio
async def test_active_catalog_retry_rejection_orders_retry_before_terminal() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    primary = OkxPlanRoute("primary", "nat-primary", "spot-0")
    secondary = OkxPlanRoute("secondary", "nat-secondary", "unused")
    adapter = _adapter(
        routes={(Market.SPOT, None): primary},
        rest_routes={Market.SPOT: (secondary,)},
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    primary_ws = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("catalog-retry-rejected")
    primary_ws.add(WS_PUBLIC_ENDPOINT, connection)
    primary_http = RouteScriptedHttpTransport()
    secondary_http = RouteScriptedHttpTransport()
    secondary_http.add(
        "/api/v5/public/instruments",
        okx_response(
            {"code": "50011", "msg": "limited", "data": []},
            headers={"retry-after": "0"},
        ),
    )
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    primary_bucket = budgets.add(
        ("okx", "nat-primary", "instruments"),
        capacity=1,
        refill_per_second=1,
    )
    assert primary_bucket.try_acquire(1)
    budgets.add(
        ("okx", "nat-secondary", "instruments"),
        capacity=100,
        refill_per_second=100,
    )
    scheduler = RestScheduler(budgets, clock=clock)

    class RejectingRetryScheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            if job.attempt == 2:
                return SubmitResult.EXPIRED
            return await scheduler.submit(job)

        async def next_ready(self) -> RestDispatch:
            return await scheduler.next_ready()

    runtime = AdapterRuntime(
        transports={
            "primary": EgressTransport("primary", primary_http, primary_ws),
            "secondary": EgressTransport(
                "secondary",
                secondary_http,
                RouteScriptedWebSocketTransport(),
            ),
        },
        scheduler=RejectingRetryScheduler(),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await asyncio.wait_for(connection.drained.wait(), timeout=1)
    with pytest.raises(TimeoutError, match="expired"):
        await asyncio.wait_for(
            adapter.fetch_catalog(runtime, Market.SPOT),
            timeout=1,
        )
    controls = [
        cast(dict[str, object], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") in {"rest_retry", "rest_terminal"}
    ]
    assert [payload["kind"] for payload in controls] == [
        "rest_retry",
        "rest_terminal",
    ]
    terminal = controls[1]
    assert terminal["attempt"] == 2
    assert terminal["egress_id"] is None
    assert terminal["dispatched"] is False
    assert terminal["planned_egress_id"] == "secondary"
    assert terminal["sticky_egress_id"] == "secondary"
    assert terminal["candidate_egress_ids"] == ["primary", "secondary"]
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)


@pytest.mark.asyncio
async def test_in_flight_catalog_can_finish_after_scheduler_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(okx_execution, "_CATALOG_DEADLINE_NS", 50_000_000)
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )

    class SlowCatalogHttp(RouteScriptedHttpTransport):
        def __init__(self) -> None:
            super().__init__()
            self.entered = asyncio.Event()
            self.release = asyncio.Event()

        async def get(self, *args: object, **kwargs: object) -> httpx.Response:
            del args, kwargs
            self.entered.set()
            await self.release.wait()
            return httpx.Response(
                200,
                content=(_FIXTURES / "instruments-spot.json").read_bytes(),
            )

    http = SlowCatalogHttp()
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("slow-catalog")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(("okx", "direct", "instruments"), capacity=100, refill_per_second=100)
    runtime = AdapterRuntime(
        transports={"direct": EgressTransport("direct", http, websocket)},
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await asyncio.wait_for(connection.drained.wait(), timeout=1)
    fetch_task = asyncio.create_task(adapter.fetch_catalog(runtime, Market.SPOT))
    await asyncio.wait_for(http.entered.wait(), timeout=1)
    await asyncio.sleep(0.08)
    http.release.set()
    snapshot = await asyncio.wait_for(fetch_task, timeout=1)
    assert snapshot.instruments
    assert not any(
        isinstance(draft.payload, dict)
        and draft.payload.get("reason") == "catalog_queue_deadline_expired"
        for draft, _source, _shard in sink.rows
    )
    assert (
        sum(
            draft.logical_stream == "instrument" for draft, _source, _shard in sink.rows
        )
        == 1
    )
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)


@pytest.mark.asyncio
async def test_active_catalog_50011_retry_keeps_occurrence_and_egress() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    fixture_bytes = (_FIXTURES / "instruments-spot.json").read_bytes()
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/public/instruments",
        okx_response(
            {"code": "50011", "msg": "limited", "data": []},
            headers={"retry-after": "0"},
        ),
        httpx.Response(200, content=fixture_bytes),
    )
    websocket = RouteScriptedWebSocketTransport()
    blocking = AutoAckWebSocketConnection("catalog-retry")
    websocket.add(WS_PUBLIC_ENDPOINT, blocking)
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    budgets.add(("okx", "direct", "instruments"), capacity=100, refill_per_second=100)
    effects = RecordingRetryEffects()
    scheduler = RestScheduler(budgets, clock=clock)

    class RetryEvictingScheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            result = await scheduler.submit(job)
            if job.attempt == 2:
                assert result is SubmitResult.ENQUEUED
                return SubmitResult.EVICTED_AND_ENQUEUED
            return result

        async def next_ready(self) -> RestDispatch:
            return await scheduler.next_ready()

    admission = RecordingNetworkAdmission()
    runtime = AdapterRuntime(
        transports={"direct": EgressTransport("direct", http, websocket)},
        scheduler=RetryEvictingScheduler(),
        clock=clock,
        stop=stop,
        retry_effects=effects,
        network_admission=admission,
    )
    sink = RecordingSink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    await _wait_until(lambda: blocking.drained.is_set())

    snapshot = await asyncio.wait_for(
        adapter.fetch_catalog(runtime, Market.SPOT),
        timeout=1,
    )
    stop.set()
    await asyncio.wait_for(run_task, timeout=1)

    assert snapshot.instruments
    assert len(http.requests) == 2
    assert len(effects.calls) == 1
    retry_dispatch = effects.calls[0][0]
    assert retry_dispatch.job.attempt == 1
    retry_control = next(
        draft
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict) and draft.payload.get("kind") == "rest_retry"
    )
    assert retry_control.payload["egress_id"] == "direct"  # type: ignore[index]
    raw = [
        draft
        for draft, _source, _shard in sink.rows
        if draft.logical_stream == "instrument" and draft.transport is Transport.REST
    ]
    assert len(raw) == 1
    assert raw[0].rest_metadata is not None
    assert raw[0].rest_metadata.attempt == 2
    assert admission.calls[0] == (
        Exchange.OKX,
        Transport.WEBSOCKET,
        "direct",
        "direct",
        None,
    )
    assert [call[:4] for call in admission.calls[1:]] == [
        (Exchange.OKX, Transport.REST, "direct", "direct"),
        (Exchange.OKX, Transport.REST, "direct", "direct"),
    ]
    assert admission.calls[1][4] == admission.calls[2][4]
    assert admission.calls[1][4] is not None


@pytest.mark.asyncio
async def test_rest_first_occurrences_use_stable_per_item_phase() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    interval_ns = 10 * SECOND_NS
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={
                "book_deep_snapshot": IntervalPlan(
                    interval_ns,
                    interval_ns,
                    None,
                )
            },
        )
    )
    stop = StopToken()

    class Clock:
        def time_ns(self) -> int:
            return 1_800_000_000_000_000_000

        def monotonic_ns(self) -> int:
            return 100

    class Scheduler:
        def __init__(self) -> None:
            self.jobs: list[RestJob] = []

        async def submit(self, job: RestJob) -> SubmitResult:
            self.jobs.append(job)
            stop.set()
            return SubmitResult.ENQUEUED

        async def next_ready(self) -> RestDispatch:
            raise AssertionError("stopped initial scheduling must not dispatch")

    scheduler = Scheduler()
    clock = Clock()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=scheduler,
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )

    await adapter.run(plan, runtime, RecordingSink())

    assert len(scheduler.jobs) == 1
    item = plan.rest[0]
    cadence = StableCadence(100, interval_ns, item.id)
    assert scheduler.jobs[0].scheduled_ns == 100 + cadence.phase_ns
    assert scheduler.jobs[0].ready_monotonic_ns == 100 + cadence.phase_ns


@pytest.mark.asyncio
async def test_initial_submission_barrier_surfaces_fatal_before_blocked_sibling() -> (
    None
):
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "direct", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot", "candle_1m"})},
            intervals={
                "book_deep_snapshot": IntervalPlan(SECOND_NS, SECOND_NS, None),
                "candle_1m": IntervalPlan(SECOND_NS, SECOND_NS, None),
            },
        )
    )
    fatal_item = next(
        item for item in plan.rest if item.logical_stream == "book_deep_snapshot"
    )
    blocked_started = asyncio.Event()
    blocked_cancelled = asyncio.Event()
    sentinel = RuntimeError("initial cadence submission failed")

    class Scheduler:
        async def submit(self, job: RestJob) -> SubmitResult:
            if job.control_context["plan_item_id"] == fatal_item.id:
                await blocked_started.wait()
                raise sentinel
            blocked_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                blocked_cancelled.set()
            raise AssertionError("unreachable")

        async def next_ready(self) -> RestDispatch:
            raise AssertionError("startup failure must precede REST consumption")

    class Clock:
        def time_ns(self) -> int:
            return 1_800_000_000_000_000_000

        def monotonic_ns(self) -> int:
            return 100

    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=Scheduler(),
        clock=Clock(),
        stop=StopToken(),
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )

    with pytest.raises(RuntimeError) as caught:
        await asyncio.wait_for(
            okx_execution._run_rest(
                plan,
                runtime,
                RecordingSink(),
                catalog_controller=None,
            ),
            timeout=1,
        )
    assert caught.value is sentinel
    assert blocked_cancelled.is_set()
    assert "OKX REST producer cleanup also failed" not in getattr(
        sentinel,
        "__notes__",
        (),
    )


@pytest.mark.asyncio
async def test_silent_expiry_is_rearmed_by_independent_cadence_producer() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={
                "book_deep_snapshot": IntervalPlan(100, 100, None),
            },
        )
    )
    item = plan.rest[0]
    stop = StopToken()

    class Clock:
        def __init__(self) -> None:
            self.now_ns = 100

        def time_ns(self) -> int:
            return 1_800_000_000_000_000_000

        def monotonic_ns(self) -> int:
            return self.now_ns

    clock = Clock()

    class Scheduler:
        def __init__(self) -> None:
            self.jobs: list[RestJob] = []

        async def submit(self, job: RestJob) -> SubmitResult:
            self.jobs.append(job)
            if len(self.jobs) == 1:
                assert job.deadline_ns is not None
                clock.now_ns = job.deadline_ns + 1
            else:
                stop.set()
            return SubmitResult.ENQUEUED

        async def next_ready(self) -> RestDispatch:
            raise AssertionError("cadence producer test does not consume dispatches")

    scheduler = Scheduler()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=scheduler,
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    cadence = StableCadence(100, 100, item.id)
    state = okx_execution._RoutineRestState(item=item, cadence=cadence)
    sink = RecordingSink()

    await okx_execution._run_rest_cadence(
        state=state,
        runtime=runtime,
        sink=sink,
    )

    assert len(scheduler.jobs) == 2
    assert scheduler.jobs[1].scheduled_ns > scheduler.jobs[0].scheduled_ns
    assert scheduler.jobs[1].attempt == 1
    assert any(
        isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "rest_occurrence_expired"
        for draft, _source, _shard in sink.rows
    )


@pytest.mark.asyncio
async def test_active_retry_is_not_replaced_at_the_next_cadence() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={
                "book_deep_snapshot": IntervalPlan(100, 100, None),
            },
        )
    )
    item = plan.rest[0]
    cadence = StableCadence(100, 100, item.id)
    first_scheduled_ns = cadence.anchor_monotonic_ns + cadence.phase_ns
    first_deadline_ns = first_scheduled_ns + cadence.interval_ns
    stop = StopToken()

    class Clock:
        def time_ns(self) -> int:
            return 1_800_000_000_000_000_000

        def monotonic_ns(self) -> int:
            return first_deadline_ns

    class Scheduler:
        def __init__(self) -> None:
            self.jobs: list[RestJob] = []

        async def submit(self, job: RestJob) -> SubmitResult:
            self.jobs.append(job)
            return SubmitResult.ENQUEUED

        async def next_ready(self) -> RestDispatch:
            raise AssertionError("cadence producer test does not consume dispatches")

    scheduler = Scheduler()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=scheduler,
        clock=Clock(),
        stop=stop,
    )
    state = okx_execution._RoutineRestState(item=item, cadence=cadence)
    state.activate(
        scheduled_ns=first_scheduled_ns,
        deadline_ns=first_deadline_ns,
        attempt=2,
    )
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "rest_cadence_skipped"
        ),
    )

    await okx_execution._run_rest_cadence(
        state=state,
        runtime=runtime,
        sink=sink,
    )

    assert scheduler.jobs == []
    assert state.active_attempt == 2


def test_mixed_missing_native_timestamps_do_not_claim_an_event_time() -> None:
    message = okx_execution.OkxWsMessage(
        kind=okx_execution.OkxWsMessageKind.DATA,
        raw_text="fixture",
        payload={
            "arg": {"channel": "tickers", "instId": "BTC-USDT"},
            "data": [
                {"instId": "BTC-USDT", "ts": "1800000000123"},
                {"instId": "BTC-USDT"},
            ],
        },
        argument={"channel": "tickers", "instId": "BTC-USDT"},
        request_id=None,
        connection_id=None,
        code=None,
    )

    assert okx_execution._message_timestamp(message) is None


@pytest.mark.asyncio
async def test_websocket_failure_is_recorded_before_generation_lease_release() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )

    class Health:
        def __init__(self) -> None:
            self.failures: list[str] = []

        def is_egress_available(self, *, exchange: Exchange, egress_id: str) -> bool:
            del exchange, egress_id
            return True

        def choose_websocket_egress(self, **kwargs: object) -> str:
            return cast(str, kwargs["preferred_egress_id"])

        def record_transport_failure(self, **kwargs: object) -> None:
            assert any(
                isinstance(draft.payload, dict)
                and draft.payload.get("kind") == "ws_reconnect"
                for draft, _source, _shard in sink.rows
            )
            self.failures.append(cast(str, kwargs["reason"]))

    health = Health()

    class OrderedAdmission(RecordingNetworkAdmission):
        async def acquire(self, **kwargs: object) -> NetworkAdmissionLease:
            lease = await super().acquire(**kwargs)  # type: ignore[arg-type]

            async def release(
                disposition: NetworkAdmissionReleaseDisposition,
            ) -> None:
                assert disposition is NetworkAdmissionReleaseDisposition.NORMAL
                assert health.failures == ["OSError"]
                await lease.aclose()

            return NetworkAdmissionLease(
                exchange=lease.exchange,
                transport=lease.transport,
                egress_id=lease.egress_id,
                quota_group=lease.quota_group,
                _release=release,
            )

    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("failure-order", OSError("down")),
    )
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "ws_reconnect"
        ),
    )
    admission = OrderedAdmission()
    runtime = replace(
        _runtime(
            stop=stop,
            transports={
                "direct": EgressTransport(
                    "direct", RouteScriptedHttpTransport(), websocket
                )
            },
            network_admission=admission,
        ),
        transport_health=health,
    )
    await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=1)
    assert len(admission.releases) == 1


@pytest.mark.asyncio
async def test_websocket_body_error_survives_generation_lease_release_failure() -> None:
    canary = "socks5://user:token-canary@127.0.0.1:1080"
    releases: list[NetworkAdmissionReleaseDisposition] = []

    async def release(disposition: NetworkAdmissionReleaseDisposition) -> None:
        releases.append(disposition)
        raise RuntimeError(canary)

    lease = NetworkAdmissionLease(
        exchange=Exchange.OKX,
        transport=Transport.WEBSOCKET,
        egress_id="direct",
        quota_group="nat",
        _release=release,
    )

    class FailingSession:
        async def __aenter__(self) -> Self:
            raise ValueError("session body failed")

        async def __aexit__(self, *args: object) -> None:
            del args

    runtime = _runtime(
        stop=StopToken(),
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
    )

    with pytest.raises(ValueError, match="session body failed") as caught:
        async with okx_execution._leased_ws_session(
            cast(okx_execution.OkxWsSession, FailingSession()),
            lease,
            runtime=runtime,
            egress_id="direct",
        ):
            raise AssertionError("unreachable")
    rendered = " ".join(
        [repr(caught.value), str(caught.value), *getattr(caught.value, "__notes__", ())]
    )
    assert canary not in rendered
    assert releases == [NetworkAdmissionReleaseDisposition.NORMAL]


@pytest.mark.asyncio
async def test_throwing_websocket_health_recorder_releases_generation_lease() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )

    class ThrowingHealth:
        def __init__(self) -> None:
            self.calls = 0

        def is_egress_available(self, *, exchange: Exchange, egress_id: str) -> bool:
            del exchange, egress_id
            return True

        def choose_websocket_egress(self, **kwargs: object) -> str:
            return cast(str, kwargs["preferred_egress_id"])

        def record_transport_failure(self, **kwargs: object) -> None:
            del kwargs
            self.calls += 1
            raise OSError("ws health persistence failed")

    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("throwing-health", OSError("down")),
    )
    stop = StopToken()
    admission = RecordingNetworkAdmission()
    health = ThrowingHealth()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        scheduler=RestScheduler(BudgetRegistry(SystemClock())),
        clock=SystemClock(),
        stop=stop,
        transport_health=health,
        network_admission=admission,
    )
    with pytest.raises(OSError, match="ws health persistence failed"):
        await asyncio.wait_for(adapter.run(plan, runtime, RecordingSink()), timeout=1)
    assert admission.releases == [(Exchange.OKX, Transport.WEBSOCKET, "direct", "nat")]
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    ]
    assert health.calls == 1


@pytest.mark.asyncio
async def test_websocket_transport_failure_reselects_egress_for_new_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("primary", "primary", "spot-0")
    fallback = OkxPlanRoute("secondary", "secondary", "unused-shard")
    adapter = _adapter(
        routes={
            (Market.SPOT, None): route,
            (Market.SPOT, "ETH-USDT"): fallback,
        }
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )

    class Policy:
        def __init__(self, *, base_ns: int, cap_ns: int) -> None:
            assert base_ns == 250_000_000
            assert cap_ns == 60_000_000_000

        def delay_ns(self, attempt: int, *, rng: object) -> int:
            del attempt, rng
            return 0

    monkeypatch.setattr(okx_execution, "OkxWsReconnectPolicy", Policy)
    primary_ws = RouteScriptedWebSocketTransport()
    primary_ws.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("primary-1", OSError("route down")),
    )
    secondary_ws = RouteScriptedWebSocketTransport()
    secondary_ws.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection(
            "secondary-1",
            _data_frame("tickers", "secondary", inst_id="BTC-USDT"),
        ),
    )

    class Health:
        def __init__(self) -> None:
            self.choices: list[tuple[str, str | None]] = []
            self.failures: list[tuple[Transport, str, str]] = []

        def choose_websocket_egress(
            self,
            *,
            exchange: Exchange,
            market: Market,
            endpoint: str,
            preferred_egress_id: str,
            previous_egress_id: str | None,
        ) -> str:
            del exchange, market, endpoint
            self.choices.append((preferred_egress_id, previous_egress_id))
            return "primary" if previous_egress_id is None else "secondary"

        def is_egress_available(
            self,
            *,
            exchange: Exchange,
            egress_id: str,
        ) -> bool:
            del exchange, egress_id
            return True

        def record_transport_failure(
            self,
            *,
            exchange: Exchange,
            transport: Transport,
            egress_id: str,
            reason: str,
        ) -> None:
            del exchange
            self.failures.append((transport, egress_id, reason))

    health = Health()
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "ticker",
    )
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    runtime = AdapterRuntime(
        transports={
            "primary": EgressTransport(
                "primary",
                RouteScriptedHttpTransport(),
                primary_ws,
            ),
            "secondary": EgressTransport(
                "secondary",
                RouteScriptedHttpTransport(),
                secondary_ws,
            ),
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        transport_health=health,
        network_admission=RecordingNetworkAdmission(),
    )

    await adapter.run(plan, runtime, sink)

    ticker = next(
        (draft, source)
        for draft, source, _shard in sink.rows
        if draft.logical_stream == "ticker"
    )
    assert ticker[1].egress_id == "secondary"
    assert health.choices == [("primary", None), ("primary", "primary")]
    assert health.failures == [(Transport.WEBSOCKET, "primary", "OSError")]
    reconnect = next(
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "ws_reconnect"
    )
    assert reconnect["reason"] == "transport_error"
    assert reconnect["error_type"] == "OSError"


@pytest.mark.parametrize(
    ("timeout_kind", "expected_reason"),
    [
        ("subscription", "SUBSCRIPTION_TIMEOUT"),
        ("pong", "PONG_TIMEOUT"),
    ],
)
@pytest.mark.asyncio
async def test_websocket_liveness_timeout_records_health_before_failover(
    monkeypatch: pytest.MonkeyPatch,
    timeout_kind: str,
    expected_reason: str,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={
            (Market.SPOT, None): OkxPlanRoute("primary", "primary", "spot-0"),
            (Market.SPOT, "ETH-USDT"): OkxPlanRoute("secondary", "secondary", "unused"),
        }
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    original_session = okx_execution.OkxWsSession

    class FastSession(original_session):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(
                *args,  # type: ignore[arg-type]
                **kwargs,  # type: ignore[arg-type]
                idle_timeout_seconds=0.001 if timeout_kind == "pong" else 0.1,
                pong_timeout_seconds=0.001,
                subscription_timeout_seconds=(
                    0.001 if timeout_kind == "subscription" else 0.1
                ),
            )

    class ZeroReconnect:
        def __init__(self, *, base_ns: int, cap_ns: int) -> None:
            del base_ns, cap_ns

        def delay_ns(self, attempt: int, *, rng: object) -> int:
            del attempt, rng
            return 0

    class NoAckConnection(AutoAckWebSocketConnection):
        async def send(self, message: str) -> None:
            self.sent.append(message)

    first = (
        NoAckConnection("no-ack")
        if timeout_kind == "subscription"
        else AutoAckWebSocketConnection("no-pong")
    )
    primary_ws = RouteScriptedWebSocketTransport()
    primary_ws.add(WS_PUBLIC_ENDPOINT, first)
    secondary_ws = RouteScriptedWebSocketTransport()
    secondary_ws.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection(
            "secondary",
            _data_frame("tickers", "secondary", inst_id="BTC-USDT"),
        ),
    )

    class Health:
        def __init__(self) -> None:
            self.previous: list[str | None] = []
            self.failures: list[tuple[str, str]] = []

        def choose_websocket_egress(self, **kwargs: object) -> str:
            previous = cast(str | None, kwargs["previous_egress_id"])
            self.previous.append(previous)
            return "primary" if previous is None else "secondary"

        def is_egress_available(self, **kwargs: object) -> bool:
            del kwargs
            return True

        def record_transport_failure(self, **kwargs: object) -> None:
            self.failures.append(
                (cast(str, kwargs["egress_id"]), cast(str, kwargs["reason"]))
            )

    monkeypatch.setattr(okx_execution, "OkxWsSession", FastSession)
    monkeypatch.setattr(okx_execution, "OkxWsReconnectPolicy", ZeroReconnect)
    health = Health()
    admission = RecordingNetworkAdmission()
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: draft.logical_stream == "ticker",
    )
    clock = SystemClock()
    runtime = AdapterRuntime(
        transports={
            "primary": EgressTransport(
                "primary", RouteScriptedHttpTransport(), primary_ws
            ),
            "secondary": EgressTransport(
                "secondary", RouteScriptedHttpTransport(), secondary_ws
            ),
        },
        scheduler=RestScheduler(BudgetRegistry(clock), clock=clock),
        clock=clock,
        stop=stop,
        transport_health=health,
        network_admission=admission,
    )

    await asyncio.wait_for(adapter.run(plan, runtime, sink), timeout=1)

    assert health.previous == [None, "primary"]
    assert health.failures == [("primary", expected_reason)]
    reconnect = next(
        cast(dict[str, JsonPayload], draft.payload)
        for draft, _source, _shard in sink.rows
        if isinstance(draft.payload, dict)
        and draft.payload.get("kind") == "ws_reconnect"
    )
    assert reconnect["reason"] == expected_reason.lower()
    assert reconnect["error_type"] == expected_reason
    assert admission.release_dispositions == [
        NetworkAdmissionReleaseDisposition.NORMAL,
        NetworkAdmissionReleaseDisposition.NORMAL,
    ]


@pytest.mark.asyncio
async def test_ack_only_disconnects_increase_reconnect_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    attempts: list[int] = []

    class Policy:
        def __init__(self, *, base_ns: int, cap_ns: int) -> None:
            assert base_ns == 250_000_000
            assert cap_ns == 60_000_000_000

        def delay_ns(self, attempt: int, *, rng: object) -> int:
            del rng
            attempts.append(attempt)
            return 0

    monkeypatch.setattr(okx_execution, "OkxWsReconnectPolicy", Policy)
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("ack-1", OSError("closed")),
        AutoAckWebSocketConnection("ack-2", OSError("closed")),
        AutoAckWebSocketConnection("ack-3"),
    )
    stop = StopToken()
    sink = RecordingSink(
        stop=stop,
        stop_when=lambda draft: (
            sum(
                isinstance(row.payload, dict)
                and row.payload.get("kind") == "ws_subscribe_ack"
                for row, _source, _shard in sink.rows
            )
            == 3
        ),
    )
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
    )

    await adapter.run(plan, runtime, sink)

    assert attempts == [0, 1]


@pytest.mark.asyncio
async def test_stop_race_does_not_hide_child_sink_failure() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"ticker"})})
    )
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("sink-race")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    stop = StopToken()

    def status_for(draft: NativeEventDraft) -> EnqueueStatus:
        if (
            draft.logical_stream == "_control"
            and isinstance(draft.payload, dict)
            and draft.payload.get("kind") == "ws_subscribe_ack"
        ):
            stop.set()
            return EnqueueStatus.NOT_ACCEPTING
        return EnqueueStatus.ACCEPTED

    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                websocket,
            )
        },
    )

    with pytest.raises(okx_execution.OkxExecutionError, match="sink rejected"):
        await okx_execution.run_okx_plan(
            plan,
            runtime,
            RecordingSink(status_for=status_for),
        )
    assert connection.closed


@pytest.mark.asyncio
async def test_stop_cancels_pending_active_catalog_future() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    stop = StopToken()
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    bucket = budgets.add(
        ("okx", "direct", "instruments"),
        capacity=1,
        refill_per_second=1,
    )
    assert bucket.try_acquire(1)
    scheduler = RestScheduler(budgets, clock=clock)
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        AutoAckWebSocketConnection("pending-catalog"),
    )
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                websocket,
            )
        },
        scheduler=scheduler,
        clock=clock,
        stop=stop,
        retry_effects=RecordingRetryEffects(),
        network_admission=RecordingNetworkAdmission(),
    )
    run_task = asyncio.create_task(adapter.run(plan, runtime, RecordingSink()))
    await asyncio.sleep(0)
    fetch_task = asyncio.create_task(adapter.fetch_catalog(runtime, Market.SPOT))
    await _wait_until(lambda: bool(scheduler.pending_ids()))
    with pytest.raises(RuntimeError, match="already pending"):
        await adapter.fetch_catalog(runtime, Market.SPOT)

    stop.set()
    await asyncio.wait_for(run_task, timeout=1)
    with pytest.raises(asyncio.CancelledError):
        await fetch_task


def test_late_throttle_decision_still_applies_quota_effect() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    )
    item = plan.rest[0]
    job = item.materialize(
        ready_monotonic_ns=1,
        scheduled_ns=1,
        attempt=1,
        deadline_ns=SECOND_NS,
    )
    dispatch = RestDispatch(job, job.routes[0], 1)
    clock = SystemClock()
    policy = okx_execution.retry_policy(
        clock=clock,
        rng=random.Random(1),
        max_attempts=5,
        base_ns=1,
        cap_ns=1,
    )
    decision = okx_execution._bounded_retry_decision(
        policy,
        attempt=1,
        now_ns=SECOND_NS + 1,
        deadline_ns=SECOND_NS,
        classification=okx_execution.RetryClassification(
            okx_execution.RetryAction.THROTTLE,
            "0",
            "okx_50011",
        ),
    )
    stop = StopToken()
    effects = RecordingRetryEffects()
    budgets = BudgetRegistry(clock)
    budgets.add(job.routes[0].budget_key, capacity=100, refill_per_second=100)
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        scheduler=RestScheduler(budgets, clock=clock),
        clock=clock,
        stop=stop,
        retry_effects=effects,
    )

    assert decision.action is okx_execution.RetryAction.THROTTLE
    assert not decision.retry
    assert decision.reason == "deadline_exceeded"
    okx_execution._apply_retry_effect(runtime, dispatch=dispatch, decision=decision)
    assert effects.calls == [(dispatch, decision)]


def test_throttle_or_ban_without_retry_effects_fails_fast() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("direct", "direct", "spot-0")
    adapter = _adapter(routes={(Market.SPOT, None): route})
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    )
    item = plan.rest[0]
    job = item.materialize(
        ready_monotonic_ns=1,
        scheduled_ns=1,
        attempt=1,
        deadline_ns=SECOND_NS,
    )
    dispatch = RestDispatch(job, job.routes[0], 1)
    stop = StopToken()
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport(
                "direct",
                RouteScriptedHttpTransport(),
                RouteScriptedWebSocketTransport(),
            )
        },
        budget_keys=(job.routes[0].budget_key,),
        include_retry_effects=False,
    )
    decision = RetryDecision(
        retry=True,
        delay_ns=1,
        action=okx_execution.RetryAction.THROTTLE,
        cause="okx_50011",
        reason="okx_50011",
    )

    with pytest.raises(RuntimeError, match="requires retry effects"):
        okx_execution._apply_retry_effect(
            runtime,
            dispatch=dispatch,
            decision=decision,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("accessor", ["accepted", "status"])
async def test_sink_result_accessor_failure_wins_same_tick_run_cancel(
    accessor: str,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request(
            {Market.SPOT: (spot,)},
            {Market.SPOT: frozenset({"book_deep_snapshot"})},
            intervals={"book_deep_snapshot": IntervalPlan(1_000_000, 1_000_000, None)},
        )
    )
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/market/books-full",
        okx_response(
            {
                "code": "0",
                "msg": "",
                "data": [{"asks": [], "bids": [], "ts": "1800000000123"}],
            }
        ),
    )
    stop = StopToken()
    admission = RecordingNetworkAdmission()
    item = plan.rest[0]

    class FirstOccurrenceClock:
        def __init__(self) -> None:
            self.armed = False
            self.calls = 0
            self.system = SystemClock()

        def arm(self) -> None:
            self.armed = True
            self.calls = 0

        def time_ns(self) -> int:
            return self.system.time_ns()

        def monotonic_ns(self) -> int:
            if not self.armed:
                return 0
            self.calls += 1
            return 0 if self.calls == 1 else 1_000_000

    clock = FirstOccurrenceClock()
    budgets = BudgetRegistry(clock)
    budgets.add(item.routes[0].budget_key, capacity=100, refill_per_second=100)
    scheduler = RestScheduler(budgets, clock=clock)

    class FirstOccurrenceScheduler:
        def __init__(self) -> None:
            self.submit_calls = 0

        async def submit(self, job: RestJob) -> SubmitResult:
            self.submit_calls += 1
            if self.submit_calls > 1:
                await stop.wait()
                raise asyncio.CancelledError
            return await scheduler.submit(job)

        async def next_ready(self) -> RestDispatch:
            return await scheduler.next_ready()

    gated_scheduler = FirstOccurrenceScheduler()
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        scheduler=gated_scheduler,
        clock=clock,
        stop=stop,
        network_admission=admission,
        retry_effects=RecordingRetryEffects(),
    )
    clock.arm()

    class WriterPortError(RuntimeError):
        pass

    sentinel = WriterPortError(f"{accessor} getter failed")

    class BadResult:
        @property
        def accepted(self) -> bool:
            if accessor == "accepted":
                raise sentinel
            return False

        @property
        def status(self) -> EnqueueStatus:
            raise sentinel

    class Sink(RecordingSink):
        run_task: asyncio.Task[None] | None = None

        def try_emit(
            self,
            draft: NativeEventDraft,
            *,
            source: SourceContext,
            shard: str,
        ) -> EnqueueResult:
            accepted = super().try_emit(draft, source=source, shard=shard)
            if draft.logical_stream == "book_deep_snapshot":
                assert self.run_task is not None
                stop.set()
                self.run_task.cancel("caller-cancel")
                return cast(EnqueueResult, BadResult())
            return accepted

    sink = Sink()
    run_task = asyncio.create_task(adapter.run(plan, runtime, sink))
    sink.run_task = run_task
    with pytest.raises(WriterPortError) as caught:
        await asyncio.wait_for(run_task, timeout=1)
    assert caught.value is sentinel
    assert "OKX event sink failure" in getattr(sentinel, "__notes__", ())
    assert admission.release_dispositions == [NetworkAdmissionReleaseDisposition.NORMAL]
    assert gated_scheduler.submit_calls >= 1


@pytest.mark.asyncio
async def test_committed_catalog_setup_failure_survives_normal_stop_close(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )
    stop = StopToken()
    websocket = RouteScriptedWebSocketTransport()
    connection = AutoAckWebSocketConnection("catalog-close-race")
    websocket.add(WS_PUBLIC_ENDPOINT, connection)
    catalog_item = plan.catalog[0]
    runtime = _runtime(
        stop=stop,
        transports={
            "direct": EgressTransport("direct", RouteScriptedHttpTransport(), websocket)
        },
        budget_keys=(catalog_item.routes[0].budget_key,),
    )

    class SetupFatal(RuntimeError):
        pass

    sentinel = SetupFatal("catalog post-commit setup failed")
    submit_started = asyncio.Event()

    async def committed_after_cancel(**kwargs: object) -> object:
        del kwargs
        submit_started.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            return okx_execution._SubmitOutcome(SubmitResult.ENQUEUED, sentinel)
        raise AssertionError("unreachable")

    monkeypatch.setattr(
        okx_execution,
        "_submit_rest_occurrence",
        committed_after_cancel,
    )
    run_task = asyncio.create_task(adapter.run(plan, runtime, RecordingSink()))
    await asyncio.wait_for(connection.drained.wait(), timeout=1)
    fetch_task = asyncio.create_task(adapter.fetch_catalog(runtime, Market.SPOT))
    await asyncio.wait_for(submit_started.wait(), timeout=1)
    stop.set()

    with pytest.raises(SetupFatal) as fetch_caught:
        await asyncio.wait_for(fetch_task, timeout=1)
    with pytest.raises(SetupFatal) as run_caught:
        await asyncio.wait_for(run_task, timeout=1)
    assert fetch_caught.value is sentinel
    assert run_caught.value is sentinel


@pytest.mark.asyncio
async def test_cancelled_bootstrap_is_settled_before_runtime_is_poisoned() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    adapter = _adapter(
        routes={(Market.SPOT, None): OkxPlanRoute("direct", "nat", "spot-0")}
    )
    plan = adapter.plan(
        _request({Market.SPOT: (spot,)}, {Market.SPOT: frozenset({"instrument"})})
    )

    class BlockingHttp(RouteScriptedHttpTransport):
        def __init__(self) -> None:
            super().__init__()
            self.entered = asyncio.Event()
            self.cancelled = asyncio.Event()

        async def get(self, *args: object, **kwargs: object) -> httpx.Response:
            del args, kwargs
            self.entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.cancelled.set()
            raise AssertionError("unreachable")

    http = BlockingHttp()
    admission = RecordingNetworkAdmission()
    item = plan.catalog[0]
    runtime = _runtime(
        stop=StopToken(),
        transports={
            "direct": EgressTransport("direct", http, RouteScriptedWebSocketTransport())
        },
        budget_keys=(item.routes[0].budget_key,),
        network_admission=admission,
    )
    fetch_task = asyncio.create_task(adapter.fetch_catalog(runtime, Market.SPOT))
    await asyncio.wait_for(http.entered.wait(), timeout=1)
    fetch_task.cancel("first-cancel")
    asyncio.get_running_loop().call_soon(fetch_task.cancel, "second-cancel")
    with pytest.raises(asyncio.CancelledError) as caught:
        await fetch_task
    assert caught.value.args == ("first-cancel",)
    assert http.cancelled.is_set()
    assert len(admission.releases) == 1
    assert adapter._bootstrap_task is None
    with pytest.raises(RuntimeError, match="poisoned"):
        runtime.ensure_run_not_claimed()
    with pytest.raises(RuntimeError, match="poisoned"):
        await adapter.fetch_catalog(runtime, Market.SPOT)
    with pytest.raises(RuntimeError, match="single-use"):
        runtime.claim_run()


@pytest.mark.asyncio
@pytest.mark.parametrize("release_fails", [False, True])
async def test_parse_cleanup_cancellation_is_detached_and_preserved(
    release_fails: bool,
) -> None:
    release_started = asyncio.Event()
    release_gate = asyncio.Event()
    canary = "socks5://user:secret@127.0.0.1:1080"

    async def release(disposition: NetworkAdmissionReleaseDisposition) -> None:
        assert disposition is NetworkAdmissionReleaseDisposition.NORMAL
        release_started.set()
        await release_gate.wait()
        if release_fails:
            raise RuntimeError(canary)

    lease = NetworkAdmissionLease(
        exchange=Exchange.OKX,
        transport=Transport.REST,
        egress_id="direct",
        quota_group="nat",
        _release=release,
    )
    primary = ValueError("recoverable parse failure")
    cleanup_task = asyncio.create_task(okx_execution._close_preserving(lease, primary))
    await release_started.wait()
    cleanup_task.cancel("cleanup-cancel")
    release_gate.set()
    outcome = await cleanup_task
    cancellation = outcome.cancellation
    assert cancellation is not None
    assert cancellation.args == ("cleanup-cancel",)
    assert cancellation.__cause__ is None
    assert cancellation.__context__ is None
    assert cancellation.__traceback__ is None
    notes = getattr(cancellation, "__notes__", ())
    assert ("network admission release also failed" in notes) is release_fails
    assert canary not in " ".join((*notes, *getattr(primary, "__notes__", ())))
