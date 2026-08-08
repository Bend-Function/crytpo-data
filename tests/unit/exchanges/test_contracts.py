from __future__ import annotations

import asyncio
import traceback
from decimal import Decimal
from functools import partial
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from crypto_collector.domain.envelope import SourceContext
from crypto_collector.domain.types import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    Transport,
)
from crypto_collector.exchanges.contracts import (
    AdapterPlan,
    AdapterRetrySettings,
    AdapterRuntime,
    BookIntegrity,
    CollectionRequest,
    ConnectionGeneration,
    EgressTransport,
    Instrument,
    NetworkAdmissionLease,
    NetworkAdmissionReleaseDisposition,
    NetworkAdmissionReleaseError,
    RestPlanItem,
    StreamExpectation,
    WebSocketSubscription,
)
from crypto_collector.exchanges.registry import AdapterRegistry
from crypto_collector.scheduler import (
    IntervalPlan,
    RestBudgetRoute,
    RestJob,
    RestPriority,
)
from crypto_collector.selection import (
    CatalogScope,
    CompleteCatalogSnapshot,
    InstrumentRecord,
    SnapshotPage,
)
from tests.support.scripted_transport import (
    ScriptedHttpTransport,
    ScriptedWebSocketTransport,
)


def _instrument(
    *,
    exchange: Exchange = Exchange.KRAKEN,
    market: Market = Market.SPOT,
    instrument_key: str = "BTC/USDT",
) -> Instrument:
    return Instrument(
        exchange=exchange,
        market=market,
        instrument_key=instrument_key,
        canonical_pair="BTC/USDT",
        wire_symbols={"rest": "XBTUSDT", "ws_v2": "BTC/USDT"},
        base_asset="BTC",
        quote_asset="USDT",
        settlement_asset=None,
        status="online",
        tradable=True,
        lifecycle={"state": "online"},
        tradable_at_ns=None,
        tradable_at_source=None,
        turnover=None,
        raw_catalog_reference="raw/catalog/page-1",
    )


def test_adapter_retry_settings_match_network_defaults_and_validate_bounds() -> None:
    settings = AdapterRetrySettings()

    assert settings.rest_max_attempts == 5
    assert settings.base_backoff_ns == 250_000_000
    assert settings.max_backoff_ns == 30_000_000_000
    assert settings.ws_reconnect_max_backoff_ns == 60_000_000_000

    with pytest.raises(ValueError, match="positive integer"):
        AdapterRetrySettings(rest_max_attempts=0)
    with pytest.raises(ValueError, match="max_backoff_ns"):
        AdapterRetrySettings(base_backoff_ns=2, max_backoff_ns=1)
    with pytest.raises(ValueError, match="ws_reconnect_max_backoff_ns"):
        AdapterRetrySettings(
            base_backoff_ns=2,
            ws_reconnect_max_backoff_ns=1,
        )


def _rest_plan_item(
    *,
    exchange: Exchange = Exchange.OKX,
    path: str = "/api/v5/market/books",
    params: object | None = None,
    priority: RestPriority = RestPriority.DEEP_SNAPSHOT,
    requires_generation: bool = False,
    replaceable: bool = True,
    routes: tuple[RestBudgetRoute, ...] = (),
) -> RestPlanItem:
    return RestPlanItem(
        id="okx:spot:btc:book",
        exchange=exchange,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        endpoint="https://www.okx.test",
        path=path,
        params={} if params is None else params,  # type: ignore[arg-type]
        egress_id="direct-primary",
        shard_id="spot-0",
        logical_stream="book_deep_snapshot",
        quota_group="direct",
        logical_endpoint="books",
        priority=priority,
        endpoint_cost=Decimal(1),
        interval_plan=None if requires_generation else IntervalPlan(30, 30, None),
        requires_generation=requires_generation,
        replaceable=replaceable,
        routes=routes,
    )


def test_one_instrument_can_have_distinct_wire_symbols() -> None:
    instrument = _instrument()

    assert instrument.wire_symbol("rest") == "XBTUSDT"
    assert instrument.wire_symbol("ws_v2") == "BTC/USDT"
    assert isinstance(instrument.wire_symbols, MappingProxyType)
    with pytest.raises(KeyError, match="wire symbol"):
        instrument.wire_symbol("missing")


def test_integrity_levels_are_explicit() -> None:
    assert BookIntegrity is IntegrityMode
    assert BookIntegrity.SEQUENCE_VERIFIED.is_research_valid
    assert BookIntegrity.CHECKSUM_VERIFIED.is_research_valid
    assert BookIntegrity.BEST_EFFORT.is_research_valid
    assert not BookIntegrity.INVALID.is_research_valid


def test_connection_generation_builds_exact_source_context() -> None:
    generation = ConnectionGeneration("okx-public-0", 3, "socks-primary")

    assert generation.source_context() == SourceContext(
        connection_id="okx-public-0",
        connection_generation=3,
        egress_id="socks-primary",
    )


@pytest.mark.parametrize("generation", [-1, True])
def test_connection_generation_rejects_invalid_generation(generation: object) -> None:
    with pytest.raises(ValueError, match="generation"):
        ConnectionGeneration("okx-public-0", generation, "direct-primary")  # type: ignore[arg-type]


def test_collection_request_cannot_carry_credentials_or_private_channels() -> None:
    instrument = _instrument(exchange=Exchange.OKX, instrument_key="BTC-USDT")
    body = {
        "exchange": Exchange.OKX,
        "selected": {Market.SPOT: (instrument,)},
        "enabled_streams": {Market.SPOT: frozenset({"trade"})},
        "interval_plans": {
            "book_deep_snapshot": IntervalPlan(30, 30, None),
        },
        "config_sha256": "a" * 64,
        "headers": {"Authorization": "Bearer secret"},
    }

    with pytest.raises(ValidationError, match="extra_forbidden"):
        CollectionRequest.model_validate(body)


def test_collection_request_rejects_cross_exchange_instrument() -> None:
    with pytest.raises(ValidationError, match="selected instrument scope"):
        CollectionRequest.model_validate(
            {
                "exchange": Exchange.OKX,
                "selected": {Market.SPOT: (_instrument(),)},
                "enabled_streams": {Market.SPOT: frozenset({"trade"})},
                "interval_plans": {},
                "config_sha256": "a" * 64,
            }
        )


def test_collection_request_freezes_inputs_and_validates_intervals() -> None:
    selected = {
        Market.SPOT: (_instrument(exchange=Exchange.OKX, instrument_key="BTC-USDT"),)
    }
    streams = {Market.SPOT: frozenset({"trade"})}
    intervals = {"book_deep_snapshot": IntervalPlan(30, 30, None)}
    request = CollectionRequest.model_validate(
        {
            "exchange": Exchange.OKX,
            "selected": selected,
            "enabled_streams": streams,
            "interval_plans": intervals,
            "config_sha256": "a" * 64,
        }
    )

    selected.clear()
    streams.clear()
    intervals.clear()
    assert tuple(request.selected) == (Market.SPOT,)
    assert tuple(request.enabled_streams) == (Market.SPOT,)
    assert tuple(request.interval_plans) == ("book_deep_snapshot",)
    with pytest.raises(TypeError):
        request.selected[Market.PERPETUAL] = ()  # type: ignore[index]

    with pytest.raises(ValidationError, match="valid positive intervals"):
        CollectionRequest.model_validate(
            {
                "exchange": Exchange.OKX,
                "selected": {Market.SPOT: request.selected[Market.SPOT]},
                "enabled_streams": {Market.SPOT: frozenset({"trade"})},
                "interval_plans": {"book_deep_snapshot": IntervalPlan(0, 30, None)},
                "config_sha256": "a" * 64,
            }
        )
    with pytest.raises(ValidationError, match="matching warning evidence"):
        CollectionRequest.model_validate(
            {
                "exchange": Exchange.OKX,
                "selected": {Market.SPOT: request.selected[Market.SPOT]},
                "enabled_streams": {Market.SPOT: frozenset({"trade"})},
                "interval_plans": {"book_deep_snapshot": IntervalPlan(30, 60, None)},
                "config_sha256": "a" * 64,
            }
        )


def test_adapter_plan_requires_an_expectation_for_every_planned_stream() -> None:
    subscription = WebSocketSubscription(
        id="okx:spot:btc:trades",
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        channel="trades",
        endpoint="wss://ws.okx.test/ws/v5/public",
        egress_id="direct-primary",
        quota_group="direct",
        shard_id="spot-0",
        logical_stream="trade",
    )

    with pytest.raises(ValueError, match="missing stream expectation"):
        AdapterPlan(
            exchange=Exchange.OKX,
            ws=(subscription,),
            rest=(),
            expectations=(),
            disabled_optional_features=(),
            egress_quota_groups={"direct-primary": "direct"},
        )

    expectation = StreamExpectation(
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        logical_stream="trade",
        shard_id="spot-0",
    )
    plan = AdapterPlan(
        exchange=Exchange.OKX,
        ws=(subscription,),
        rest=(),
        expectations=(expectation,),
        disabled_optional_features=(),
        instruments=(_instrument(exchange=Exchange.OKX, instrument_key="BTC-USDT"),),
        egress_quota_groups={"direct-primary": "direct"},
    )
    assert plan.expected_logical_streams() == frozenset({"trade"})


def test_market_plan_item_requires_an_exact_market_expectation() -> None:
    subscription = WebSocketSubscription(
        id="okx:spot:_market:status",
        market=Market.SPOT,
        instrument_key=None,
        wire_symbol=None,
        channel="status",
        endpoint="wss://ws.okx.test/ws/v5/public",
        egress_id="direct-primary",
        quota_group="direct",
        shard_id="spot-0",
        logical_stream="status",
    )

    with pytest.raises(ValueError, match="missing stream expectation"):
        AdapterPlan(
            exchange=Exchange.OKX,
            ws=(subscription,),
            rest=(),
            expectations=(
                StreamExpectation(
                    market=Market.SPOT,
                    instrument_key="BTC-USDT",
                    logical_stream="status",
                    shard_id="spot-0",
                ),
            ),
            disabled_optional_features=(),
            instruments=(
                _instrument(exchange=Exchange.OKX, instrument_key="BTC-USDT"),
            ),
            egress_quota_groups={"direct-primary": "direct"},
        )


def test_rest_plan_item_requires_matching_expectation() -> None:
    rest = _rest_plan_item(params={"instId": "BTC-USDT", "sz": "400"})

    with pytest.raises(ValueError, match="missing stream expectation"):
        AdapterPlan(
            exchange=Exchange.OKX,
            ws=(),
            rest=(rest,),
            expectations=(),
            disabled_optional_features=(),
            instruments=(
                _instrument(exchange=Exchange.OKX, instrument_key="BTC-USDT"),
            ),
            egress_quota_groups={"direct-primary": "direct"},
        )


def test_rest_plan_item_freezes_params_and_materializes_one_exact_route() -> None:
    sizes = ["100", "400"]
    item = _rest_plan_item(params={"sz": sizes})
    job = item.materialize(
        ready_monotonic_ns=10,
        scheduled_ns=20,
    )
    sizes.append("1000")
    assert item.params["sz"] == ("100", "400")
    assert item.routes == (
        RestBudgetRoute(
            egress_id="direct-primary",
            budget_key=("okx", "direct", "books"),
        ),
    )
    assert job.eligible_egress_ids == ("direct-primary",)
    assert job.routes[0].budget_key == ("okx", "direct", "books")
    assert job.generation_source is None
    with pytest.raises(TypeError):
        item.params["sz"] = ("1",)  # type: ignore[index]
    with pytest.raises(ValueError, match="cannot bind"):
        item.materialize(
            ready_monotonic_ns=10,
            scheduled_ns=20,
            generation=ConnectionGeneration("okx-public-0", 1, "direct-primary"),
        )


def test_independent_rest_plan_item_materializes_ordered_candidate_routes() -> None:
    routes = (
        RestBudgetRoute(
            egress_id="direct-primary",
            budget_key=("okx", "direct", "books"),
        ),
        RestBudgetRoute(
            egress_id="socks-secondary",
            budget_key=("okx", "proxy-secondary", "books"),
        ),
    )
    item = _rest_plan_item(routes=routes)

    job = item.materialize(ready_monotonic_ns=10, scheduled_ns=20)

    assert item.routes == routes
    assert job.routes == routes
    assert job.eligible_egress_ids == ("direct-primary", "socks-secondary")


@pytest.mark.parametrize(
    ("routes", "message"),
    [
        (
            (
                RestBudgetRoute(
                    "another-primary",
                    ("okx", "direct", "books"),
                ),
            ),
            "routes\\[0\\] must match",
        ),
        (
            (
                RestBudgetRoute(
                    "direct-primary",
                    ("okx", "another-quota", "books"),
                ),
            ),
            "routes\\[0\\] must match",
        ),
        (
            (
                RestBudgetRoute("direct-primary", ("okx", "direct", "books")),
                RestBudgetRoute("direct-primary", ("okx", "proxy", "books")),
            ),
            "must not repeat an egress_id",
        ),
        (
            (
                RestBudgetRoute("direct-primary", ("okx", "direct", "books")),
                RestBudgetRoute("socks-secondary", ("okx", "proxy", "candles")),
            ),
            "exchange and logical_endpoint",
        ),
        (
            (
                RestBudgetRoute("direct-primary", ("okx", "direct", "books")),
                RestBudgetRoute("socks-secondary", ("binance", "proxy", "books")),
            ),
            "exchange and logical_endpoint",
        ),
    ],
)
def test_rest_plan_item_rejects_invalid_candidate_routes(
    routes: tuple[RestBudgetRoute, ...],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        _rest_plan_item(routes=routes)


def test_rest_bootstrap_materializes_only_after_generation_exists() -> None:
    item = _rest_plan_item(
        priority=RestPriority.LIVE_BOOTSTRAP,
        requires_generation=True,
        replaceable=False,
    )
    with pytest.raises(ValueError, match="requires a connection generation"):
        item.materialize(ready_monotonic_ns=10, scheduled_ns=20)
    with pytest.raises(ValueError, match="planned egress"):
        item.materialize(
            ready_monotonic_ns=10,
            scheduled_ns=20,
            generation=ConnectionGeneration("okx-public-0", 1, "socks-secondary"),
        )

    generation = ConnectionGeneration("okx-public-0", 1, "direct-primary")
    job = item.materialize(
        ready_monotonic_ns=10,
        scheduled_ns=20,
        generation=generation,
    )
    assert job.generation_source == generation.source_context()
    assert job.routes == (
        RestBudgetRoute(
            egress_id="direct-primary",
            budget_key=("okx", "direct", "books"),
        ),
    )
    assert job.priority is RestPriority.LIVE_BOOTSTRAP


def test_rest_bootstrap_rejects_candidate_failover_routes() -> None:
    routes = (
        RestBudgetRoute("direct-primary", ("okx", "direct", "books")),
        RestBudgetRoute("socks-secondary", ("okx", "proxy", "books")),
    )

    with pytest.raises(ValueError, match="require exactly one route"):
        _rest_plan_item(
            priority=RestPriority.LIVE_BOOTSTRAP,
            requires_generation=True,
            replaceable=False,
            routes=routes,
        )


def test_adapter_plan_rejects_cross_exchange_rest_budget() -> None:
    rest = _rest_plan_item(exchange=Exchange.BINANCE)
    expectation = StreamExpectation(
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        logical_stream="book_deep_snapshot",
        shard_id="spot-0",
    )
    with pytest.raises(ValueError, match="item exchange"):
        AdapterPlan(
            exchange=Exchange.OKX,
            ws=(),
            rest=(rest,),
            expectations=(expectation,),
            disabled_optional_features=(),
            egress_quota_groups={"direct-primary": "direct"},
        )


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("//private.test/orders", {}),
        ("/api/v5/market/books?token=secret", {}),
        ("/api/v5/market/books", {"signature": "secret"}),
        ("/api/v5/market/books", {"sz": ["400", object()]}),
    ],
)
def test_rest_plan_item_rejects_unsafe_request_parts(
    path: str,
    params: object,
) -> None:
    with pytest.raises((TypeError, ValueError), match="path|query"):
        _rest_plan_item(path=path, params=params)


def test_public_endpoints_reject_credentials_and_query_strings() -> None:
    common = {
        "id": "okx:spot:btc:trades",
        "market": Market.SPOT,
        "instrument_key": "BTC-USDT",
        "wire_symbol": "BTC-USDT",
        "channel": "trades",
        "egress_id": "direct-primary",
        "quota_group": "direct",
        "shard_id": "spot-0",
        "logical_stream": "trade",
    }
    with pytest.raises(ValueError, match="anonymous public URI"):
        WebSocketSubscription(
            **common,
            endpoint="wss://token:secret@ws.okx.test/ws/v5/public",
        )
    with pytest.raises(ValueError, match="anonymous public URI"):
        WebSocketSubscription(
            **common,
            endpoint="wss://ws.okx.test/ws/v5/public?token=secret",
        )


@pytest.mark.parametrize(
    "endpoint",
    [
        "wss://ws.okx.test/ws?",
        "wss://ws.okx.test/ws#",
        "wss://ws.okx.test\\path",
        "wss://%65xample.com/ws",
        "wss://ws.okx.test/ws\x7f",
    ],
)
def test_public_endpoints_reject_ambiguous_uris(endpoint: str) -> None:
    with pytest.raises(ValueError, match="anonymous public URI"):
        WebSocketSubscription(
            id="okx:spot:btc:trades",
            market=Market.SPOT,
            instrument_key="BTC-USDT",
            wire_symbol="BTC-USDT",
            channel="trades",
            endpoint=endpoint,
            egress_id="direct-primary",
            quota_group="direct",
            shard_id="spot-0",
            logical_stream="trade",
        )


def test_market_wide_liquidation_subscription_keeps_one_market_expectation() -> None:
    params = {"instType": "SWAP"}
    subscription = WebSocketSubscription(
        id="okx:swap:liquidations",
        market=Market.PERPETUAL,
        instrument_key=None,
        wire_symbol=None,
        channel="liquidation-orders",
        endpoint="wss://ws.okx.test/ws/v5/public",
        egress_id="direct-primary",
        quota_group="direct",
        shard_id="swap-0",
        logical_stream="liquidation",
        params=params,
    )
    params["instType"] = "SPOT"
    plan = AdapterPlan(
        exchange=Exchange.OKX,
        ws=(subscription,),
        rest=(),
        expectations=(
            StreamExpectation(
                market=Market.PERPETUAL,
                instrument_key=None,
                logical_stream="liquidation",
                shard_id="swap-0",
                coverage=CoverageMode.LOSSY_WINDOW,
            ),
        ),
        disabled_optional_features=(),
        egress_quota_groups={"direct-primary": "direct"},
    )
    assert subscription.params["instType"] == "SWAP"
    assert plan.expected_logical_streams() == frozenset({"liquidation"})


@pytest.mark.asyncio
async def test_adapter_runtime_freezes_egress_lookup_and_closes_http() -> None:
    class Scheduler:
        async def submit(self, job: RestJob) -> object:
            del job
            return object()

        async def next_ready(self) -> object:
            return object()

    class Clock:
        def time_ns(self) -> int:
            return 1

        def monotonic_ns(self) -> int:
            return 1

    class Stop:
        def is_set(self) -> bool:
            return False

        async def wait(self) -> None:
            return None

    http = ScriptedHttpTransport()
    transport = EgressTransport(
        egress_id="direct-primary",
        http=http,
        websocket=ScriptedWebSocketTransport(),
    )
    transports = {"direct-primary": transport}
    runtime = AdapterRuntime(
        transports=transports,
        scheduler=Scheduler(),  # type: ignore[arg-type]
        clock=Clock(),
        stop=Stop(),
    )
    transports.clear()

    runtime.ensure_run_not_claimed()
    runtime.ensure_run_not_claimed()
    assert runtime.transport_for("direct-primary") is transport
    with pytest.raises(LookupError, match="not available"):
        runtime.transport_for("missing")
    with pytest.raises(ValueError, match="mapping key"):
        AdapterRuntime(
            transports={"wrong": transport},
            scheduler=Scheduler(),  # type: ignore[arg-type]
            clock=Clock(),
            stop=Stop(),
        )
    runtime.poison()
    with pytest.raises(RuntimeError, match="poisoned"):
        runtime.ensure_run_not_claimed()
    with pytest.raises(RuntimeError, match="single-use"):
        runtime.claim_run()
    await runtime.aclose()
    assert http.closed


@pytest.mark.asyncio
async def test_network_admission_release_failure_is_sanitized_and_memoized() -> None:
    canary = "socks5://user:secret@127.0.0.1:1080"
    calls: list[NetworkAdmissionReleaseDisposition] = []

    async def release(
        secret: str,
        disposition: NetworkAdmissionReleaseDisposition,
    ) -> None:
        calls.append(disposition)
        raise RuntimeError(secret)

    lease = NetworkAdmissionLease(
        exchange=Exchange.OKX,
        transport=Transport.REST,
        egress_id="direct-primary",
        quota_group="direct",
        _release=partial(release, canary),
    )

    with pytest.raises(NetworkAdmissionReleaseError) as first:
        await lease.fail_closed()
    with pytest.raises(NetworkAdmissionReleaseError) as second:
        await lease.aclose()

    assert calls == [NetworkAdmissionReleaseDisposition.FAIL_CLOSED]
    assert lease.release_disposition is NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    for error in (first.value, second.value):
        assert error.__cause__ is None
        assert error.__context__ is None
        rendered = "".join(
            traceback.StackSummary.extract(
                (
                    (frame, line)
                    for frame, line in traceback.walk_tb(error.__traceback__)
                    if "/src/crypto_collector/" in frame.f_code.co_filename
                ),
                capture_locals=True,
            ).format()
        )
        assert canary not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize("release_fails", [False, True])
async def test_network_admission_release_preserves_external_cancel(
    release_fails: bool,
) -> None:
    canary = "release-provider-private"
    started = asyncio.Event()
    gate = asyncio.Event()
    observed: list[asyncio.CancelledError] = []

    async def release(disposition: NetworkAdmissionReleaseDisposition) -> None:
        assert disposition is NetworkAdmissionReleaseDisposition.FAIL_CLOSED
        started.set()
        await gate.wait()
        if release_fails:
            raise RuntimeError(canary)

    lease = NetworkAdmissionLease(
        exchange=Exchange.OKX,
        transport=Transport.REST,
        egress_id="direct-primary",
        quota_group="direct",
        _release=release,
    )

    async def close() -> None:
        try:
            await lease.fail_closed()
        except asyncio.CancelledError as cancellation:
            observed.append(cancellation)
            raise

    task = asyncio.create_task(close())
    await started.wait()
    task.cancel("caller-cancel-first")
    asyncio.get_running_loop().call_soon(task.cancel, "caller-cancel-second")
    gate.set()
    with pytest.raises(asyncio.CancelledError) as caught:
        await task

    assert observed == [caught.value]
    assert caught.value.args == ("caller-cancel-first",)
    notes = getattr(caught.value, "__notes__", ())
    assert ("network admission release also failed" in notes) is release_fails
    assert canary not in " ".join(notes)
    assert lease.release_disposition is NetworkAdmissionReleaseDisposition.FAIL_CLOSED


@pytest.mark.asyncio
async def test_network_admission_release_factory_failure_is_memoized() -> None:
    canary = "release-task-factory-private"
    calls: list[NetworkAdmissionReleaseDisposition] = []

    async def release(disposition: NetworkAdmissionReleaseDisposition) -> None:
        calls.append(disposition)

    lease = NetworkAdmissionLease(
        exchange=Exchange.OKX,
        transport=Transport.REST,
        egress_id="direct-primary",
        quota_group="direct",
        _release=release,
    )
    loop = asyncio.get_running_loop()
    original_factory = loop.get_task_factory()

    def reject_task(
        _loop: asyncio.AbstractEventLoop,
        _coroutine: object,
        **_kwargs: object,
    ) -> asyncio.Task[object]:
        raise RuntimeError(canary)

    loop.set_task_factory(reject_task)
    try:
        with pytest.raises(NetworkAdmissionReleaseError) as first:
            await lease.fail_closed()
    finally:
        loop.set_task_factory(original_factory)

    with pytest.raises(NetworkAdmissionReleaseError) as second:
        await lease.aclose()
    assert calls == []
    assert lease.release_disposition is NetworkAdmissionReleaseDisposition.FAIL_CLOSED
    for error in (first.value, second.value):
        assert error.__cause__ is None
        assert error.__context__ is None
        assert canary not in str(error)


@pytest.mark.asyncio
async def test_adapter_runtime_closes_all_unique_http_clients_after_failure() -> None:
    class Scheduler:
        async def submit(self, job: RestJob) -> object:
            del job
            return object()

        async def next_ready(self) -> object:
            return object()

    class Clock:
        def time_ns(self) -> int:
            return 1

        def monotonic_ns(self) -> int:
            return 1

    class Stop:
        def is_set(self) -> bool:
            return False

        async def wait(self) -> None:
            return None

    class FailingHttp(ScriptedHttpTransport):
        async def aclose(self) -> None:
            self.closed = True
            raise RuntimeError("injected close failure")

    failing = FailingHttp()
    healthy = ScriptedHttpTransport()
    runtime = AdapterRuntime(
        transports={
            "one": EgressTransport(
                egress_id="one",
                http=failing,
                websocket=ScriptedWebSocketTransport(),
            ),
            "two": EgressTransport(
                egress_id="two",
                http=healthy,
                websocket=ScriptedWebSocketTransport(),
            ),
        },
        scheduler=Scheduler(),
        clock=Clock(),
        stop=Stop(),
    )

    with pytest.raises(RuntimeError, match="injected close failure"):
        await runtime.aclose()
    assert failing.closed
    assert healthy.closed


def test_stream_expectation_distinguishes_control_market_and_instrument_scope() -> None:
    control = StreamExpectation(
        market=None,
        instrument_key=None,
        logical_stream="_control",
        shard_id="_control",
    )
    market = StreamExpectation(
        market=Market.SPOT,
        instrument_key=None,
        logical_stream="instrument",
        shard_id="spot-market",
        coverage=CoverageMode.COMPLETE,
    )
    assert control.market is None
    assert market.instrument_key is None

    with pytest.raises(ValueError, match="exchange-scoped"):
        StreamExpectation(
            market=Market.SPOT,
            instrument_key=None,
            logical_stream="_control",
            shard_id="_control",
        )
    with pytest.raises(ValueError, match="requires an instrument"):
        StreamExpectation(
            market=Market.SPOT,
            instrument_key=None,
            logical_stream="trade",
            shard_id="spot-0",
        )
    with pytest.raises(ValueError, match="cannot use"):
        StreamExpectation(
            market=Market.SPOT,
            instrument_key="BTC-USDT",
            logical_stream="trade",
            shard_id="_control",
        )


def test_registry_rejects_duplicate_exchange_and_unknown_lookup() -> None:
    class Adapter:
        exchange = Exchange.OKX

        async def fetch_catalog(self, runtime, market):  # type: ignore[no-untyped-def]
            raise AssertionError("not called")

        def plan(self, request):  # type: ignore[no-untyped-def]
            raise AssertionError("not called")

        async def run(self, plan, runtime, sink):  # type: ignore[no-untyped-def]
            raise AssertionError("not called")

    registry = AdapterRegistry()
    registry.register(Adapter())

    with pytest.raises(ValueError, match="already registered"):
        registry.register(Adapter())
    with pytest.raises(LookupError, match="not registered"):
        registry.for_exchange(Exchange.BINANCE)
    with pytest.raises(TypeError):
        registry.snapshot()[Exchange.BINANCE] = Adapter()  # type: ignore[index]


def test_instrument_catalog_raw_event_must_match_scope() -> None:
    from crypto_collector.exchanges.contracts import InstrumentCatalog

    assert InstrumentCatalog is CompleteCatalogSnapshot
    with pytest.raises(ValueError, match="instrument scope"):
        InstrumentCatalog(
            scope=CatalogScope(Exchange.OKX, Market.SPOT),
            observed_at_ns=2,
            snapshot_id="okx-spot-2",
            pages=(SnapshotPage("raw/catalog/page-1", None, None),),
            reported_total_count=1,
            authoritative_empty=False,
            instruments=(_instrument(),),
        )


def test_instrument_contract_has_one_canonical_owner() -> None:
    assert Instrument is InstrumentRecord
