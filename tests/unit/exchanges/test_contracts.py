from __future__ import annotations

from decimal import Decimal
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from crypto_collector.domain.envelope import SourceContext
from crypto_collector.domain.types import CoverageMode, Exchange, IntegrityMode, Market
from crypto_collector.exchanges.contracts import (
    AdapterPlan,
    AdapterRuntime,
    BookIntegrity,
    CollectionRequest,
    ConnectionGeneration,
    EgressTransport,
    Instrument,
    RestPlanItem,
    StreamExpectation,
    WebSocketSubscription,
)
from crypto_collector.exchanges.registry import AdapterRegistry
from crypto_collector.scheduler import (
    IntervalPlan,
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


def _rest_plan_item(
    *,
    exchange: Exchange = Exchange.OKX,
    path: str = "/api/v5/market/books",
    params: object | None = None,
    priority: RestPriority = RestPriority.DEEP_SNAPSHOT,
    requires_generation: bool = False,
    replaceable: bool = True,
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
    )
    assert plan.expected_logical_streams() == frozenset({"trade"})


def test_rest_plan_item_requires_matching_expectation() -> None:
    rest = _rest_plan_item(params={"instId": "BTC-USDT", "sz": "400"})

    with pytest.raises(ValueError, match="missing stream expectation"):
        AdapterPlan(
            exchange=Exchange.OKX,
            ws=(),
            rest=(rest,),
            expectations=(),
            disabled_optional_features=(),
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


def test_rest_bootstrap_materializes_only_after_generation_exists() -> None:
    item = _rest_plan_item(
        priority=RestPriority.LIVE_BOOTSTRAP,
        requires_generation=True,
        replaceable=False,
    )
    with pytest.raises(ValueError, match="requires a connection generation"):
        item.materialize(ready_monotonic_ns=10, scheduled_ns=20)

    generation = ConnectionGeneration("okx-public-0", 1, "direct-primary")
    job = item.materialize(
        ready_monotonic_ns=10,
        scheduled_ns=20,
        generation=generation,
    )
    assert job.generation_source == generation.source_context()
    assert job.priority is RestPriority.LIVE_BOOTSTRAP


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
            shard_id="spot-0",
            logical_stream="trade",
        )


def test_market_wide_subscription_can_cover_instrument_expectations() -> None:
    params = {"instType": "SWAP"}
    subscription = WebSocketSubscription(
        id="okx:swap:liquidations",
        market=Market.PERPETUAL,
        instrument_key=None,
        wire_symbol=None,
        channel="liquidation-orders",
        endpoint="wss://ws.okx.test/ws/v5/business",
        egress_id="direct-primary",
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
                instrument_key="BTC-USDT-SWAP",
                logical_stream="liquidation",
                shard_id="swap-0",
                coverage=CoverageMode.LOSSY_WINDOW,
            ),
            StreamExpectation(
                market=Market.PERPETUAL,
                instrument_key="ETH-USDT-SWAP",
                logical_stream="liquidation",
                shard_id="swap-0",
                coverage=CoverageMode.LOSSY_WINDOW,
            ),
        ),
        disabled_optional_features=(),
    )
    assert subscription.params["instType"] == "SWAP"
    assert plan.expected_logical_streams() == frozenset({"liquidation"})


@pytest.mark.asyncio
async def test_adapter_runtime_freezes_egress_lookup_and_closes_http() -> None:
    class Scheduler:
        async def submit(self, job: RestJob) -> object:
            del job
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
    await runtime.aclose()
    assert http.closed


@pytest.mark.asyncio
async def test_adapter_runtime_closes_all_unique_http_clients_after_failure() -> None:
    class Scheduler:
        async def submit(self, job: RestJob) -> object:
            del job
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
