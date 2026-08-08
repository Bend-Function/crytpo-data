from __future__ import annotations

from decimal import Decimal

import pytest

from crypto_collector.capabilities import CapabilityRegistry
from crypto_collector.domain import CoverageMode, Exchange, Market
from crypto_collector.exchanges.contracts import CollectionRequest
from crypto_collector.exchanges.okx import (
    OKX_COMMON_RESEARCH_STREAMS,
    OKX_PERPETUAL_RESEARCH_STREAMS,
    OKX_RESEARCH_DEFAULT_STREAMS,
    OkxAdapter,
    OkxEndpoints,
    OkxPlanRoute,
)
from crypto_collector.scheduler import IntervalPlan, RestBudgetRoute, RestPriority
from crypto_collector.selection import InstrumentRecord


def _instrument(market: Market, instrument_key: str) -> InstrumentRecord:
    perpetual = market is Market.PERPETUAL
    return InstrumentRecord(
        exchange=Exchange.OKX,
        market=market,
        instrument_key=instrument_key,
        canonical_pair="BTC/USDT" if instrument_key.startswith("BTC") else "ETH/USDT",
        wire_symbols={
            "rest": instrument_key,
            "websocket": instrument_key,
            **(
                {
                    "index": instrument_key.removesuffix("-SWAP"),
                    "instrument_family": instrument_key.removesuffix("-SWAP"),
                }
                if perpetual
                else {}
            ),
        },
        base_asset="BTC" if instrument_key.startswith("BTC") else "ETH",
        quote_asset="USDT",
        settlement_asset="USDT" if perpetual else None,
        status="live",
        tradable=True,
        lifecycle={"state": "live"},
        tradable_at_ns=None,
        tradable_at_source=None,
        turnover=None,
        raw_catalog_reference=f"raw/{market.value}/{instrument_key}",
    )


def _request(
    *,
    selected: dict[Market, tuple[InstrumentRecord, ...]],
    streams: dict[Market, frozenset[str]],
    intervals: dict[str, IntervalPlan] | None = None,
) -> CollectionRequest:
    return CollectionRequest.model_validate(
        {
            "exchange": Exchange.OKX,
            "selected": selected,
            "enabled_streams": streams,
            "interval_plans": intervals or {},
            "config_sha256": "a" * 64,
        }
    )


def _one(items: object, *, stream: str) -> object:
    selected = [item for item in items if item.logical_stream == stream]  # type: ignore[attr-defined]
    assert len(selected) == 1
    return selected[0]


def test_research_default_plan_declares_every_okx_stream() -> None:
    spot = _instrument(Market.SPOT, "BTC-USDT")
    swap = _instrument(Market.PERPETUAL, "BTC-USDT-SWAP")
    request = _request(
        selected={Market.PERPETUAL: (swap,), Market.SPOT: (spot,)},
        streams={
            Market.PERPETUAL: OKX_COMMON_RESEARCH_STREAMS
            | OKX_PERPETUAL_RESEARCH_STREAMS,
            Market.SPOT: OKX_COMMON_RESEARCH_STREAMS,
        },
    )

    plan = OkxAdapter().plan(request)

    assert plan.expected_logical_streams() == OKX_RESEARCH_DEFAULT_STREAMS | {
        "_control"
    }
    assert len({item.id for item in (*plan.ws, *plan.rest)}) == len(
        (*plan.ws, *plan.rest)
    )
    assert [(item.market, item.instrument_key) for item in plan.instruments] == [
        (Market.PERPETUAL, "BTC-USDT-SWAP"),
        (Market.SPOT, "BTC-USDT"),
    ]
    assert plan.disabled_optional_features == ()


def test_live_book_and_deep_snapshot_are_independent_products() -> None:
    instrument = _instrument(Market.SPOT, "BTC-USDT")
    interval = IntervalPlan(30_000_000_000, 30_000_000_000, None)
    request = _request(
        selected={Market.SPOT: (instrument,)},
        streams={Market.SPOT: frozenset({"book_live", "book_deep_snapshot"})},
        intervals={"spot/BTC-USDT/book_deep_snapshot": interval},
    )

    plan = OkxAdapter().plan(request)
    live = _one(plan.ws, stream="book_live")
    deep = _one(plan.rest, stream="book_deep_snapshot")

    assert live.channel == "books"  # type: ignore[attr-defined]
    assert deep.path == "/api/v5/market/books-full"  # type: ignore[attr-defined]
    assert deep.params == {"instId": "BTC-USDT", "sz": 5000}  # type: ignore[attr-defined]
    assert deep.priority is RestPriority.DEEP_SNAPSHOT  # type: ignore[attr-defined]
    assert deep.interval_plan == interval  # type: ignore[attr-defined]
    assert deep.requires_generation is False  # type: ignore[attr-defined]
    assert deep.replaceable is True  # type: ignore[attr-defined]


def test_configured_deep_depth_is_not_silently_promoted_to_capability_max() -> None:
    instrument = _instrument(Market.SPOT, "BTC-USDT")
    plan = OkxAdapter(
        deep_depths={(Market.SPOT, instrument.instrument_key): 1_000}
    ).plan(
        _request(
            selected={Market.SPOT: (instrument,)},
            streams={Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    )

    deep = _one(plan.rest, stream="book_deep_snapshot")
    assert deep.params == {"instId": "BTC-USDT", "sz": 1_000}  # type: ignore[attr-defined]


def test_market_deep_depth_default_applies_to_each_selected_instrument() -> None:
    btc = _instrument(Market.SPOT, "BTC-USDT")
    eth = _instrument(Market.SPOT, "ETH-USDT")
    plan = OkxAdapter(deep_depths={(Market.SPOT, None): 400}).plan(
        _request(
            selected={Market.SPOT: (btc, eth)},
            streams={Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    )

    assert {item.params["sz"] for item in plan.rest} == {400}


def test_deep_depth_rejects_values_above_the_okx_capability() -> None:
    with pytest.raises(ValueError, match="5000-level capability"):
        OkxAdapter(deep_depths={(Market.SPOT, None): 5_001})


def test_routes_bind_every_instrument_item_to_injected_egress_and_shard() -> None:
    instrument = _instrument(Market.PERPETUAL, "BTC-USDT-SWAP")
    route = OkxPlanRoute("socks-nz-1", "nat-nz", "perpetual-nz-3")
    adapter = OkxAdapter(routes={(Market.PERPETUAL, instrument.instrument_key): route})
    request = _request(
        selected={Market.PERPETUAL: (instrument,)},
        streams={
            Market.PERPETUAL: frozenset(
                {"book_live", "book_deep_snapshot", "index_ticker", "premium"}
            )
        },
    )

    plan = adapter.plan(request)

    assert {item.egress_id for item in (*plan.ws, *plan.rest)} == {"socks-nz-1"}
    assert {item.shard_id for item in (*plan.ws, *plan.rest)} == {"perpetual-nz-3"}
    assert {item.quota_group for item in plan.ws} == {"nat-nz"}
    assert {item.quota_group for item in plan.rest} == {"nat-nz"}
    assert plan.egress_quota_groups == {"socks-nz-1": "nat-nz"}
    index = _one(plan.ws, stream="index_ticker")
    assert index.instrument_key == "BTC-USDT-SWAP"  # type: ignore[attr-defined]
    assert index.wire_symbol == "BTC-USDT"  # type: ignore[attr-defined]
    deep = _one(plan.rest, stream="book_deep_snapshot")
    job = deep.materialize(ready_monotonic_ns=1, scheduled_ns=2)  # type: ignore[attr-defined]
    assert job.routes[0].budget_key == ("okx", "nat-nz", "books-full")


def test_rest_routes_append_frozen_market_candidates_without_changing_primary() -> None:
    instrument = _instrument(Market.SPOT, "BTC-USDT")
    primary = OkxPlanRoute("primary", "nat-primary", "spot-primary")
    secondary = OkxPlanRoute("secondary", "nat-secondary", "ignored-secondary")
    candidates = {Market.SPOT: (primary, secondary, secondary)}
    adapter = OkxAdapter(
        routes={(Market.SPOT, instrument.instrument_key): primary},
        rest_routes=candidates,
    )
    candidates[Market.SPOT] = ()

    plan = adapter.plan(
        _request(
            selected={Market.SPOT: (instrument,)},
            streams={Market.SPOT: frozenset({"book_deep_snapshot"})},
        )
    )

    deep = _one(plan.rest, stream="book_deep_snapshot")
    assert deep.egress_id == "primary"  # type: ignore[attr-defined]
    assert deep.quota_group == "nat-primary"  # type: ignore[attr-defined]
    assert deep.shard_id == "spot-primary"  # type: ignore[attr-defined]
    assert deep.routes == (  # type: ignore[attr-defined]
        RestBudgetRoute("primary", ("okx", "nat-primary", "books-full")),
        RestBudgetRoute("secondary", ("okx", "nat-secondary", "books-full")),
    )
    catalog = adapter._catalog_item(Market.SPOT)
    assert catalog.routes == (
        RestBudgetRoute("primary", ("okx", "nat-primary", "instruments")),
        RestBudgetRoute("secondary", ("okx", "nat-secondary", "instruments")),
    )
    assert not catalog.requires_generation
    expectation = next(
        item
        for item in plan.expectations
        if item.logical_stream == "book_deep_snapshot"
    )
    assert expectation.shard_id == "spot-primary"


def test_market_stream_and_frozen_catalog_use_current_selected_route() -> None:
    selected = _instrument(Market.SPOT, "ZZZ-USDT")
    shard_a = OkxPlanRoute("egress-a", "nat-a", "shard-a")
    shard_z = OkxPlanRoute("egress-z", "nat-z", "shard-z")
    adapter = OkxAdapter(
        routes={
            (Market.SPOT, "AAA-USDT"): shard_a,
            (Market.SPOT, "ZZZ-USDT"): shard_z,
        }
    )

    plan = adapter.plan(
        _request(
            selected={Market.SPOT: (selected,)},
            streams={Market.SPOT: frozenset({"instrument"})},
        )
    )

    market_ws = _one(plan.ws, stream="instrument")
    catalog = _one(plan.catalog, stream="instrument")
    expectation = _one(plan.expectations, stream="instrument")
    assert (market_ws.egress_id, market_ws.quota_group, market_ws.shard_id) == (  # type: ignore[attr-defined]
        "egress-z",
        "nat-z",
        "shard-z",
    )
    assert (catalog.egress_id, catalog.quota_group, catalog.shard_id) == (
        "egress-z",
        "nat-z",
        "shard-z",
    )
    assert expectation.shard_id == "shard-z"  # type: ignore[attr-defined]


def test_adapter_rejects_conflicting_quota_groups_for_one_egress_globally() -> None:
    with pytest.raises(ValueError, match="egress.*quota group"):
        OkxAdapter(
            routes={
                (Market.SPOT, None): OkxPlanRoute("shared", "nat-a", "spot-a"),
                (Market.PERPETUAL, None): OkxPlanRoute(
                    "shared", "nat-b", "perpetual-b"
                ),
            }
        )

    with pytest.raises(ValueError, match="egress.*quota group"):
        OkxAdapter(
            routes={(Market.SPOT, None): OkxPlanRoute("shared", "nat-a", "spot-a")},
            rest_routes={
                Market.PERPETUAL: (OkxPlanRoute("shared", "nat-b", "perpetual-b"),)
            },
        )


@pytest.mark.parametrize(
    ("rest_routes", "error"),
    [
        ({"spot": ()}, "Market"),
        ({Market.SPOT: []}, "tuple"),
        ({Market.SPOT: (object(),)}, "OkxPlanRoute"),
        (
            {
                Market.SPOT: (
                    OkxPlanRoute("same", "nat-a", "a"),
                    OkxPlanRoute("same", "nat-b", "b"),
                )
            },
            "conflicting",
        ),
    ],
)
def test_rest_routes_reject_invalid_or_ambiguous_candidates(
    rest_routes: object,
    error: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=error):
        OkxAdapter(rest_routes=rest_routes)  # type: ignore[arg-type]


def test_market_route_can_cover_market_and_instrument_items() -> None:
    instrument = _instrument(Market.SPOT, "BTC-USDT")
    route = OkxPlanRoute("proxy-a", "proxy-a-nat", "spot-a-0")
    plan = OkxAdapter(routes={(Market.SPOT, None): route}).plan(
        _request(
            selected={Market.SPOT: (instrument,)},
            streams={
                Market.SPOT: frozenset(
                    {"instrument", "status", "trade", "book_deep_snapshot"}
                )
            },
        )
    )

    assert {item.egress_id for item in (*plan.ws, *plan.rest)} == {"proxy-a"}
    instrument_item = _one(plan.ws, stream="instrument")
    assert instrument_item.instrument_key is None  # type: ignore[attr-defined]
    assert instrument_item.params == {"instType": "SPOT"}  # type: ignore[attr-defined]
    status = _one(plan.ws, stream="status")
    assert status.instrument_key is None  # type: ignore[attr-defined]


def test_explicit_routes_never_silently_fall_back_to_direct() -> None:
    instrument = _instrument(Market.SPOT, "BTC-USDT")
    adapter = OkxAdapter(
        routes={
            (Market.SPOT, "ETH-USDT"): OkxPlanRoute(
                "proxy-a", "proxy-a-nat", "spot-a-0"
            )
        }
    )

    with pytest.raises(ValueError, match="route is missing"):
        adapter.plan(
            _request(
                selected={Market.SPOT: (instrument,)},
                streams={Market.SPOT: frozenset({"trade"})},
            )
        )


def test_liquidation_preserves_one_market_frame_and_is_explicitly_lossy() -> None:
    btc = _instrument(Market.PERPETUAL, "BTC-USDT-SWAP")
    eth = _instrument(Market.PERPETUAL, "ETH-USDT-SWAP")
    plan = OkxAdapter().plan(
        _request(
            selected={Market.PERPETUAL: (eth, btc)},
            streams={Market.PERPETUAL: frozenset({"liquidation"})},
        )
    )

    subscription = _one(plan.ws, stream="liquidation")
    assert subscription.instrument_key is None  # type: ignore[attr-defined]
    assert subscription.wire_symbol is None  # type: ignore[attr-defined]
    assert subscription.channel == "liquidation-orders"  # type: ignore[attr-defined]
    assert subscription.params == {"instType": "SWAP"}  # type: ignore[attr-defined]
    expectations = [
        item for item in plan.expectations if item.logical_stream == "liquidation"
    ]
    assert len(expectations) == 1
    assert expectations[0].instrument_key is None
    assert {item.coverage for item in expectations} == {CoverageMode.LOSSY_WINDOW}


def test_derivative_reference_routes_preserve_instrument_identity() -> None:
    instrument = _instrument(Market.PERPETUAL, "BTC-USDT-SWAP")
    plan = OkxAdapter().plan(
        _request(
            selected={Market.PERPETUAL: (instrument,)},
            streams={
                Market.PERPETUAL: frozenset({"premium", "insurance_fund", "candle_1m"})
            },
        )
    )

    premium = _one(plan.rest, stream="premium")
    insurance = _one(plan.rest, stream="insurance_fund")
    candle = _one(plan.rest, stream="candle_1m")
    assert premium.params == {"instId": "BTC-USDT-SWAP"}  # type: ignore[attr-defined]
    assert insurance.instrument_key == "BTC-USDT-SWAP"  # type: ignore[attr-defined]
    assert insurance.params == {  # type: ignore[attr-defined]
        "instType": "SWAP",
        "instFamily": "BTC-USDT",
    }
    assert candle.params == {  # type: ignore[attr-defined]
        "instId": "BTC-USDT-SWAP",
        "bar": "1m",
        "limit": 2,
    }
    assert {item.priority for item in (premium, insurance, candle)} == {  # type: ignore[attr-defined]
        RestPriority.REFERENCE_DATA
    }
    assert premium.interval_plan == IntervalPlan(  # type: ignore[attr-defined]
        300_000_000_000, 300_000_000_000, None
    )
    assert candle.interval_plan == IntervalPlan(  # type: ignore[attr-defined]
        60_000_000_000, 60_000_000_000, None
    )


def test_spot_rejects_derivative_and_unknown_streams() -> None:
    instrument = _instrument(Market.SPOT, "BTC-USDT")
    for stream in ("funding_rate", "private_orders"):
        with pytest.raises(ValueError, match="unsupported OKX spot stream"):
            OkxAdapter().plan(
                _request(
                    selected={Market.SPOT: (instrument,)},
                    streams={Market.SPOT: frozenset({stream})},
                )
            )


def test_endpoints_default_to_capability_manifest_and_can_be_overridden() -> None:
    instrument = _instrument(Market.SPOT, "BTC-USDT")
    request = _request(
        selected={Market.SPOT: (instrument,)},
        streams={Market.SPOT: frozenset({"trade", "book_deep_snapshot"})},
    )
    capability = CapabilityRegistry.load_builtin().for_market(Exchange.OKX, Market.SPOT)
    default = OkxAdapter().plan(request)
    custom = OkxAdapter(
        endpoints=OkxEndpoints(
            rest="https://okx.test",
            websocket_public="wss://okx.test/ws/v5/public",
            websocket_business="wss://okx.test/ws/v5/business",
        )
    ).plan(request)

    assert {item.endpoint for item in default.rest} == {capability.rest_base_urls[0]}
    assert {item.endpoint for item in default.ws} == {
        "wss://ws.okx.com:8443/ws/v5/business"
    }
    assert {item.endpoint for item in custom.rest} == {"https://okx.test"}
    assert {item.endpoint for item in custom.ws} == {"wss://okx.test/ws/v5/business"}
    trade = _one(custom.ws, stream="trade")
    assert trade.channel == "trades-all"  # type: ignore[attr-defined]


def test_endpoint_overrides_reject_credentials_and_wrong_okx_ws_paths() -> None:
    with pytest.raises(ValueError, match="anonymous public"):
        OkxEndpoints(
            rest="https://token@okx.test",
            websocket_public="wss://okx.test/ws/v5/public",
            websocket_business="wss://okx.test/ws/v5/business",
        )
    with pytest.raises(ValueError, match="OKX /ws/v5/public path"):
        OkxEndpoints(
            rest="https://okx.test",
            websocket_public="wss://okx.test/ws/v5/private",
            websocket_business="wss://okx.test/ws/v5/business",
        )


def test_plan_is_stable_for_input_mapping_and_instrument_order() -> None:
    btc = _instrument(Market.SPOT, "BTC-USDT")
    eth = _instrument(Market.SPOT, "ETH-USDT")
    streams = frozenset({"trade", "ticker", "book_deep_snapshot"})
    first = OkxAdapter().plan(
        _request(
            selected={Market.SPOT: (eth, btc)},
            streams={Market.SPOT: streams},
        )
    )
    second = OkxAdapter().plan(
        _request(
            selected={Market.SPOT: (btc, eth)},
            streams={Market.SPOT: streams},
        )
    )

    assert first == second
    assert all(item.endpoint_cost == Decimal(1) for item in first.rest)
