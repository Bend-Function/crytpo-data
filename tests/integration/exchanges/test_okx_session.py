from __future__ import annotations

import asyncio
import json
from collections import Counter
from collections.abc import Awaitable, Callable, Mapping
from pathlib import Path
from typing import cast

import httpx
import pytest

from crypto_collector.config.models import IngressConfig, WriterConfig
from crypto_collector.domain import (
    CloseReason,
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    RawEnvelope,
    Transport,
)
from crypto_collector.domain.clock import SystemClock
from crypto_collector.exchanges import (
    AdapterPlan,
    AdapterRuntime,
    CollectionRequest,
    EgressTransport,
)
from crypto_collector.exchanges.okx import (
    OKX_COMMON_RESEARCH_STREAMS,
    OKX_PERPETUAL_RESEARCH_STREAMS,
    OKX_RESEARCH_DEFAULT_STREAMS,
    OkxAdapter,
    OkxEndpoints,
    OkxPlanRoute,
)
from crypto_collector.network import BudgetRegistry, EgressStateStore, RestRetryEffects
from crypto_collector.runtime import ExchangeWorker, WorkerState
from crypto_collector.runtime.worker import WorkerAdapter
from crypto_collector.scheduler import IntervalPlan, RestScheduler
from crypto_collector.selection import CompleteCatalogSnapshot, InstrumentRecord
from crypto_collector.storage import RawManifestV1, RawWriterService
from tests.support.okx_session import (
    AllowAllNetworkAdmission,
    AutoAckWebSocketConnection,
    RouteScriptedHttpTransport,
    RouteScriptedWebSocketTransport,
    okx_response,
    read_raw_rows,
)

REST_ENDPOINT = "https://okx.test"
WS_PUBLIC_ENDPOINT = "wss://okx.test/ws/v5/public"
WS_BUSINESS_ENDPOINT = "wss://okx.test/ws/v5/business"
DEEP_BOOK_PATH = "/api/v5/market/books-full"
CANDLE_PATH = "/api/v5/market/candles"
PREMIUM_PATH = "/api/v5/public/premium-history"
INSURANCE_FUND_PATH = "/api/v5/public/insurance-fund"
CONFIG_SHA256 = "a" * 64
SECOND_NS = 1_000_000_000
REST_INTERVAL = IntervalPlan(SECOND_NS, SECOND_NS, None)


def _instrument(market: Market) -> InstrumentRecord:
    if market is Market.SPOT:
        instrument_key = "BTC-USDT"
        wire_symbols = {"rest": instrument_key, "websocket": instrument_key}
        canonical_pair = "BTC/USDT"
        settlement_asset = None
    else:
        instrument_key = "BTC-USDT-SWAP"
        wire_symbols = {
            "rest": instrument_key,
            "websocket": instrument_key,
            "index": "BTC-USDT",
            "instrument_family": "BTC-USDT",
        }
        canonical_pair = "BTC/USDT:USDT"
        settlement_asset = "USDT"
    return InstrumentRecord(
        exchange=Exchange.OKX,
        market=market,
        instrument_key=instrument_key,
        canonical_pair=canonical_pair,
        wire_symbols=wire_symbols,
        base_asset="BTC",
        quote_asset="USDT",
        settlement_asset=settlement_asset,
        status="live",
        tradable=True,
        lifecycle={"state": "live"},
        tradable_at_ns=None,
        tradable_at_source=None,
        turnover=None,
        raw_catalog_reference=f"fixture://okx/{instrument_key}",
    )


def _request(
    selected: Mapping[Market, tuple[InstrumentRecord, ...]],
    enabled_streams: Mapping[Market, frozenset[str]],
) -> CollectionRequest:
    return CollectionRequest.model_validate(
        {
            "exchange": Exchange.OKX,
            "selected": selected,
            "enabled_streams": enabled_streams,
            "interval_plans": {
                "book_deep_snapshot": REST_INTERVAL,
                "candle_1m": REST_INTERVAL,
                "premium": REST_INTERVAL,
                "insurance_fund": REST_INTERVAL,
            },
            "config_sha256": CONFIG_SHA256,
        }
    )


def _adapter(*, dual_market: bool) -> OkxAdapter:
    routes: dict[tuple[Market, str | None], OkxPlanRoute] = {
        (Market.SPOT, "BTC-USDT"): OkxPlanRoute(
            egress_id="direct-primary",
            quota_group="direct-nat",
            shard_id="spot-0",
        )
    }
    if dual_market:
        routes[(Market.PERPETUAL, "BTC-USDT-SWAP")] = OkxPlanRoute(
            egress_id="socks-secondary",
            quota_group="proxy-nat",
            shard_id="perpetual-0",
        )
    return OkxAdapter(
        endpoints=OkxEndpoints(
            rest=REST_ENDPOINT,
            websocket_public=WS_PUBLIC_ENDPOINT,
            websocket_business=WS_BUSINESS_ENDPOINT,
        ),
        routes=routes,
    )


def _data_message(
    *,
    channel: str,
    marker: str,
    wire_symbol: str | None = None,
    argument: Mapping[str, str] | None = None,
    fields: Mapping[str, object] | None = None,
) -> str:
    arg: dict[str, object] = {"channel": channel}
    if wire_symbol is not None:
        arg["instId"] = wire_symbol
    if argument is not None:
        arg.update(argument)
    row: dict[str, object] = {
        "ts": "1760000000123",
        "fixtureMarker": marker,
    }
    if wire_symbol is not None:
        row["instId"] = wire_symbol
    if fields is not None:
        row.update(fields)
    return json.dumps(
        {
            "arg": arg,
            "data": [row],
            "futureTopLevel": {"marker": marker},
        },
        separators=(",", ":"),
    )


def _book_message(
    *,
    wire_symbol: str,
    action: str,
    sequence: int,
    previous: int,
    future_marker: str,
    empty: bool = False,
) -> str:
    asks: list[list[str]] = []
    bids: list[list[str]] = []
    if not empty:
        asks = [["100001.00000001", "0.20000000", "0", "2"]]
        bids = [["100000.99999999", "0.30000000", "0", "3"]]
    return json.dumps(
        {
            "arg": {"channel": "books", "instId": wire_symbol},
            "action": action,
            "data": [
                {
                    "asks": asks,
                    "bids": bids,
                    "ts": str(1_760_000_000_000 + sequence),
                    "checksum": 0,
                    "prevSeqId": previous,
                    "seqId": sequence,
                    "futureBookField": {"marker": future_marker},
                }
            ],
            "futureTopLevel": [future_marker],
        },
        separators=(",", ":"),
    )


def _success(data: list[object], *, marker: str) -> httpx.Response:
    return okx_response(
        {
            "code": "0",
            "msg": "",
            "data": data,
            "futureEnvelopeField": {"marker": marker},
        }
    )


def _deep_success(marker: str) -> httpx.Response:
    return _success(
        [
            {
                "asks": [["100001.00000001", "0.20000000", "2"]],
                "bids": [["100000.99999999", "0.30000000", "3"]],
                "ts": "1760000000123",
                "futureDeepField": {"marker": marker},
            }
        ],
        marker=marker,
    )


def _candle_success(marker: str) -> httpx.Response:
    return _success(
        [
            [
                "1760000000123",
                "100000",
                "100100",
                "99900",
                "100050",
                "10",
                "1000000",
                "5",
                "1",
                {"futureCandleField": marker},
            ]
        ],
        marker=marker,
    )


async def _wait_until(
    predicate: Callable[[], bool],
    *,
    timeout_seconds: float = 8.0,
) -> None:
    async def wait() -> None:
        while not predicate():
            await asyncio.sleep(0.001)

    await asyncio.wait_for(wait(), timeout_seconds)


def _mapping(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return value


def _data_row(envelope: RawEnvelope) -> Mapping[str, object]:
    payload = _mapping(envelope.payload)
    data = payload["data"]
    assert isinstance(data, list) and len(data) == 1
    return _mapping(data[0])


def _arguments(*values: Mapping[str, object]) -> set[str]:
    return {json.dumps(dict(value), sort_keys=True) for value in values}


def _actual_arguments(connection: AutoAckWebSocketConnection) -> set[str]:
    return _arguments(*connection.subscribe_arguments)


async def _run_session(
    *,
    tmp_path: Path,
    worker_id: str,
    adapter: OkxAdapter,
    request: CollectionRequest,
    transports: Mapping[str, EgressTransport],
    ready: Callable[[], bool],
    active_action: Callable[[AdapterRuntime], Awaitable[None]] | None = None,
    extra_budget_keys: tuple[tuple[str, str, str], ...] = (),
) -> tuple[AdapterPlan, ExchangeWorker, tuple[RawManifestV1, ...], BudgetRegistry]:
    plan = adapter.plan(request)
    clock = SystemClock()
    budgets = BudgetRegistry(clock)
    registered_budgets: set[tuple[str, str, str]] = set()
    for item in plan.rest:
        for route in item.routes:
            if route.budget_key in registered_budgets:
                continue
            budgets.add(route.budget_key, capacity=100, refill_per_second=100)
            registered_budgets.add(route.budget_key)
    for budget_key in extra_budget_keys:
        if budget_key in registered_budgets:
            continue
        budgets.add(budget_key, capacity=100, refill_per_second=100)
        registered_budgets.add(budget_key)
    scheduler = RestScheduler(budgets, clock=clock)
    egress_state = EgressStateStore.open(
        tmp_path / "state" / f"{worker_id}-egress.sqlite"
    )
    retry_effects = RestRetryEffects(
        budgets=budgets,
        state_store=egress_state,
        clock=clock,
    )
    writer: RawWriterService | None = None
    active_runtime: AdapterRuntime | None = None

    async def writer_factory(*, on_critical: object) -> RawWriterService:
        nonlocal writer
        writer = await RawWriterService.open(
            data_root=tmp_path / "data",
            state_root=tmp_path / "state",
            exchange=Exchange.OKX,
            worker_instance_id=worker_id,
            config_sha256=CONFIG_SHA256,
            config_generation=0,
            writer_config=WriterConfig.model_validate({}),
            ingress_config=IngressConfig.model_validate({}),
            metric_stream_allowlist=tuple(sorted(plan.expected_logical_streams())),
            clock=clock,
            on_critical=on_critical,  # type: ignore[arg-type]
        )
        return writer

    async def runtime_factory(stop: object) -> AdapterRuntime:
        nonlocal active_runtime
        active_runtime = AdapterRuntime(
            transports=transports,
            scheduler=scheduler,
            clock=clock,
            stop=stop,  # type: ignore[arg-type]
            retry_effects=retry_effects,
            network_admission=AllowAllNetworkAdmission(),
        )
        return active_runtime

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id=worker_id,
        request=request,
        adapter=cast(WorkerAdapter, adapter),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
        clock=clock,
    )
    manifests: tuple[object, ...] = ()
    try:
        await worker.start()
        if active_action is not None:
            assert active_runtime is not None
            await active_action(active_runtime)
        await _wait_until(ready)
        assert writer is not None
        await writer.sync_now()
    finally:
        try:
            manifests = await worker.stop(
                deadline_ns=clock.monotonic_ns() + 5 * SECOND_NS
            )
        finally:
            egress_state.close()
    typed = tuple(item for item in manifests if type(item) is RawManifestV1)
    assert worker.state is WorkerState.STOPPED
    assert worker.status().last_failure is None, worker.status()
    assert all(item.close_reason is CloseReason.SHUTDOWN for item in typed)
    return plan, worker, typed, budgets


@pytest.mark.asyncio
async def test_active_catalog_refresh_shares_rest_dispatcher_and_persists_raw(
    tmp_path: Path,
) -> None:
    spot = _instrument(Market.SPOT)
    request = _request(
        {Market.SPOT: (spot,)},
        {Market.SPOT: frozenset({"instrument", "book_deep_snapshot"})},
    )
    adapter = _adapter(dual_market=False)
    public = AutoAckWebSocketConnection(
        "spot-catalog-refresh",
        _data_message(
            channel="instruments",
            argument={"instType": "SPOT"},
            marker="ws-instrument",
            fields={"instId": spot.instrument_key, "instType": "SPOT"},
        ),
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(WS_PUBLIC_ENDPOINT, public)
    catalog_bytes = (
        Path(__file__).resolve().parents[2]
        / "fixtures"
        / "exchanges"
        / "okx"
        / "instruments-spot.json"
    ).read_bytes()
    http = RouteScriptedHttpTransport()
    http.add(
        "/api/v5/public/instruments",
        httpx.Response(200, content=catalog_bytes),
    )
    http.add(DEEP_BOOK_PATH, _deep_success("deep-alongside-catalog"))
    catalog_snapshot: CompleteCatalogSnapshot | None = None

    async def refresh(runtime: AdapterRuntime) -> None:
        nonlocal catalog_snapshot
        await _wait_until(public.drained.is_set)
        catalog_snapshot = await adapter.fetch_catalog(runtime, Market.SPOT)

    plan, worker, manifests, _budgets = await _run_session(
        tmp_path=tmp_path,
        worker_id="okx-active-catalog",
        adapter=adapter,
        request=request,
        transports={
            "direct-primary": EgressTransport(
                egress_id="direct-primary",
                http=http,
                websocket=websocket,
            )
        },
        active_action=refresh,
        extra_budget_keys=(("okx", "direct-nat", "instruments"),),
        ready=lambda: len(http.requests) == 2,
    )

    assert worker.state is WorkerState.STOPPED
    assert catalog_snapshot is not None
    assert {item.instrument_key for item in catalog_snapshot.instruments} == {
        "BTC-USDT",
        "NEW-USDT",
    }
    assert Counter(request.path for request in http.requests) == Counter(
        {"/api/v5/public/instruments": 1, DEEP_BOOK_PATH: 1}
    )
    rows = read_raw_rows(tmp_path / "data", manifests)
    instrument_rows = rows["instrument"]
    assert len(instrument_rows) == 2
    rest_rows = [row for row in instrument_rows if row.transport is Transport.REST]
    assert len(rest_rows) == 1
    assert _mapping(rest_rows[0].payload)["code"] == "0"
    assert len(rows["book_deep_snapshot"]) == 1
    assert plan.expected_logical_streams() == {
        "_control",
        "instrument",
        "book_deep_snapshot",
    }


@pytest.mark.asyncio
async def test_scripted_okx_dual_market_captures_all_17_streams_and_isolates_status(
    tmp_path: Path,
) -> None:
    """The complete slice is in-memory: pytest socket blocking remains enabled."""

    spot = _instrument(Market.SPOT)
    perpetual = _instrument(Market.PERPETUAL)
    request = _request(
        {Market.SPOT: (spot,), Market.PERPETUAL: (perpetual,)},
        {
            Market.SPOT: OKX_COMMON_RESEARCH_STREAMS,
            Market.PERPETUAL: (
                OKX_COMMON_RESEARCH_STREAMS | OKX_PERPETUAL_RESEARCH_STREAMS
            ),
        },
    )
    adapter = _adapter(dual_market=True)

    spot_public = AutoAckWebSocketConnection(
        "spot-public-1",
        "pong",
        _data_message(
            channel="instruments",
            argument={"instType": "SPOT"},
            marker="spot-instrument",
            fields={"instId": spot.instrument_key, "instType": "SPOT"},
        ),
        _data_message(channel="status", marker="spot-status"),
        _data_message(
            channel="tickers",
            wire_symbol=spot.instrument_key,
            marker="spot-ticker",
        ),
        _data_message(
            channel="bbo-tbt",
            wire_symbol=spot.instrument_key,
            marker="spot-bbo",
        ),
        _book_message(
            wire_symbol=spot.instrument_key,
            action="snapshot",
            sequence=100,
            previous=-1,
            future_marker="spot-book",
        ),
    )
    spot_business = AutoAckWebSocketConnection(
        "spot-business-1",
        _data_message(
            channel="trades-all",
            wire_symbol=spot.instrument_key,
            marker="spot-trade",
        ),
    )
    spot_ws = RouteScriptedWebSocketTransport()
    spot_ws.add(WS_PUBLIC_ENDPOINT, spot_public)
    spot_ws.add(WS_BUSINESS_ENDPOINT, spot_business)
    spot_http = RouteScriptedHttpTransport()
    spot_http.add(DEEP_BOOK_PATH, _deep_success("spot-deep"))
    spot_http.add(CANDLE_PATH, _candle_success("spot-candle"))

    perpetual_public = AutoAckWebSocketConnection(
        "perpetual-public-1",
        _data_message(
            channel="instruments",
            argument={"instType": "SWAP"},
            marker="perpetual-instrument",
            fields={"instId": perpetual.instrument_key, "instType": "SWAP"},
        ),
        _data_message(channel="status", marker="perpetual-status"),
        _data_message(
            channel="liquidation-orders",
            argument={"instType": "SWAP"},
            marker="perpetual-liquidation",
            fields={"instType": "SWAP", "details": [{"side": "sell"}]},
        ),
        _data_message(
            channel="tickers",
            wire_symbol=perpetual.instrument_key,
            marker="perpetual-ticker",
        ),
        _data_message(
            channel="bbo-tbt",
            wire_symbol=perpetual.instrument_key,
            marker="perpetual-bbo",
        ),
        _book_message(
            wire_symbol=perpetual.instrument_key,
            action="snapshot",
            sequence=300,
            previous=-1,
            future_marker="perpetual-book",
        ),
        _data_message(
            channel="mark-price",
            wire_symbol=perpetual.instrument_key,
            marker="perpetual-mark",
        ),
        _data_message(
            channel="index-tickers",
            wire_symbol="BTC-USDT",
            marker="perpetual-index",
        ),
        _data_message(
            channel="funding-rate",
            wire_symbol=perpetual.instrument_key,
            marker="perpetual-funding",
        ),
        _data_message(
            channel="open-interest",
            wire_symbol=perpetual.instrument_key,
            marker="perpetual-open-interest",
        ),
        _data_message(
            channel="price-limit",
            wire_symbol=perpetual.instrument_key,
            marker="perpetual-price-limit",
        ),
    )
    perpetual_business = AutoAckWebSocketConnection(
        "perpetual-business-1",
        _data_message(
            channel="trades-all",
            wire_symbol=perpetual.instrument_key,
            marker="perpetual-trade",
        ),
    )
    perpetual_ws = RouteScriptedWebSocketTransport()
    perpetual_ws.add(WS_PUBLIC_ENDPOINT, perpetual_public)
    perpetual_ws.add(WS_BUSINESS_ENDPOINT, perpetual_business)
    perpetual_http = RouteScriptedHttpTransport()
    perpetual_http.add(DEEP_BOOK_PATH, _deep_success("perpetual-deep"))
    perpetual_http.add(CANDLE_PATH, _candle_success("perpetual-candle"))
    perpetual_http.add(
        PREMIUM_PATH,
        _success(
            [
                {
                    "instId": perpetual.instrument_key,
                    "premium": "0.0001",
                    "ts": "1760000000123",
                    "futurePremiumField": "preserved",
                }
            ],
            marker="perpetual-premium",
        ),
    )
    perpetual_http.add(
        INSURANCE_FUND_PATH,
        _success(
            [
                {
                    "instFamily": "BTC-USDT",
                    "details": [{"balance": "1000"}],
                    "futureInsuranceField": "preserved",
                }
            ],
            marker="perpetual-insurance",
        ),
    )

    transports = {
        "direct-primary": EgressTransport(
            egress_id="direct-primary",
            http=spot_http,
            websocket=spot_ws,
        ),
        "socks-secondary": EgressTransport(
            egress_id="socks-secondary",
            http=perpetual_http,
            websocket=perpetual_ws,
        ),
    }
    plan, _, manifests, _ = await _run_session(
        tmp_path=tmp_path,
        worker_id="okx-dual-market",
        adapter=adapter,
        request=request,
        transports=transports,
        ready=lambda: (
            spot_public.drained.is_set()
            and spot_business.drained.is_set()
            and perpetual_public.drained.is_set()
            and perpetual_business.drained.is_set()
            and len(spot_http.requests) == 2
            and len(perpetual_http.requests) == 4
        ),
    )

    expected_streams = OKX_RESEARCH_DEFAULT_STREAMS | {"_control"}
    assert len(expected_streams) == 17
    assert plan.expected_logical_streams() == expected_streams
    assert {manifest.logical_stream for manifest in manifests} == expected_streams
    rows = read_raw_rows(tmp_path / "data", manifests)
    assert set(rows) == expected_streams
    assert all(rows[stream] for stream in expected_streams)
    for stream in OKX_COMMON_RESEARCH_STREAMS:
        assert len(rows[stream]) == 2
        assert {row.market for row in rows[stream]} == {
            Market.SPOT,
            Market.PERPETUAL,
        }
    for stream in OKX_PERPETUAL_RESEARCH_STREAMS:
        assert len(rows[stream]) == 1
        assert rows[stream][0].market is Market.PERPETUAL

    status = rows["status"]
    assert len(status) == 2
    assert {row.market for row in status} == {Market.SPOT, Market.PERPETUAL}
    assert all(row.coverage is CoverageMode.UNKNOWN for row in status)
    assert {
        cast(Market, row.market): _data_row(row)["fixtureMarker"] for row in status
    } == {
        Market.SPOT: "spot-status",
        Market.PERPETUAL: "perpetual-status",
    }
    liquidation = rows["liquidation"]
    assert len(liquidation) == 1
    assert liquidation[0].market is Market.PERPETUAL
    assert liquidation[0].instrument_key is None
    assert liquidation[0].coverage is CoverageMode.LOSSY_WINDOW
    assert liquidation[0].event_time_ns is None

    assert {row.egress_id for row in rows["book_deep_snapshot"]} == {
        "direct-primary",
        "socks-secondary",
    }
    assert {row.egress_id for row in rows["book_live"]} == {
        "direct-primary",
        "socks-secondary",
    }
    assert _mapping(rows["premium"][0].payload)["futureEnvelopeField"] == {
        "marker": "perpetual-premium"
    }
    insurance = rows["insurance_fund"]
    assert len(insurance) == 1
    assert insurance[0].instrument_key == perpetual.instrument_key
    assert insurance[0].wire_symbol == perpetual.instrument_key
    assert _data_row(insurance[0])["futureInsuranceField"] == "preserved"
    insurance_requests = [
        item for item in perpetual_http.requests if item.path == INSURANCE_FUND_PATH
    ]
    assert len(insurance_requests) == 1
    assert insurance_requests[0].params == {
        "instType": "SWAP",
        "instFamily": "BTC-USDT",
    }

    control_payloads = [_mapping(row.payload) for row in rows["_control"]]
    assert (
        sum(payload.get("kind") == "ws_subscribe_ack" for payload in control_payloads)
        == 18
    )
    assert sum(payload.get("kind") == "ws_pong" for payload in control_payloads) == 1
    ack_egresses = {
        cast(str, payload["egress_id"])
        for payload in control_payloads
        if payload.get("kind") == "ws_subscribe_ack"
    }
    assert ack_egresses == {"direct-primary", "socks-secondary"}

    assert _actual_arguments(spot_public) == _arguments(
        {"channel": "instruments", "instType": "SPOT"},
        {"channel": "status"},
        {"channel": "tickers", "instId": spot.instrument_key},
        {"channel": "bbo-tbt", "instId": spot.instrument_key},
        {"channel": "books", "instId": spot.instrument_key},
    )
    assert _actual_arguments(spot_business) == _arguments(
        {"channel": "trades-all", "instId": spot.instrument_key}
    )
    assert _actual_arguments(perpetual_public) == _arguments(
        {"channel": "instruments", "instType": "SWAP"},
        {"channel": "status"},
        {"channel": "liquidation-orders", "instType": "SWAP"},
        {"channel": "tickers", "instId": perpetual.instrument_key},
        {"channel": "bbo-tbt", "instId": perpetual.instrument_key},
        {"channel": "books", "instId": perpetual.instrument_key},
        {"channel": "mark-price", "instId": perpetual.instrument_key},
        {"channel": "index-tickers", "instId": "BTC-USDT"},
        {"channel": "funding-rate", "instId": perpetual.instrument_key},
        {"channel": "open-interest", "instId": perpetual.instrument_key},
        {"channel": "price-limit", "instId": perpetual.instrument_key},
    )
    assert _actual_arguments(perpetual_business) == _arguments(
        {"channel": "trades-all", "instId": perpetual.instrument_key}
    )
    assert spot_ws.uris == [WS_BUSINESS_ENDPOINT, WS_PUBLIC_ENDPOINT]
    assert perpetual_ws.uris == [WS_BUSINESS_ENDPOINT, WS_PUBLIC_ENDPOINT]
    assert all(
        connection.closed
        for connection in (
            spot_public,
            spot_business,
            perpetual_public,
            perpetual_business,
        )
    )
    assert spot_http.closed and perpetual_http.closed


@pytest.mark.asyncio
async def test_scripted_okx_book_heartbeat_reset_gap_and_disconnect_change_generation(
    tmp_path: Path,
) -> None:
    spot = _instrument(Market.SPOT)
    request = _request(
        {Market.SPOT: (spot,)},
        {Market.SPOT: frozenset({"book_live"})},
    )
    adapter = _adapter(dual_market=False)
    generation_one = AutoAckWebSocketConnection(
        "spot-book-1",
        _book_message(
            wire_symbol=spot.instrument_key,
            action="snapshot",
            sequence=100,
            previous=-1,
            future_marker="snapshot-1",
        ),
        _book_message(
            wire_symbol=spot.instrument_key,
            action="update",
            sequence=100,
            previous=100,
            future_marker="heartbeat",
            empty=True,
        ),
        _book_message(
            wire_symbol=spot.instrument_key,
            action="update",
            sequence=101,
            previous=100,
            future_marker="linked-update",
        ),
        _book_message(
            wire_symbol=spot.instrument_key,
            action="update",
            sequence=1,
            previous=101,
            future_marker="maintenance-reset",
        ),
        _book_message(
            wire_symbol=spot.instrument_key,
            action="update",
            sequence=2,
            previous=1,
            future_marker="linked-after-reset",
        ),
        _book_message(
            wire_symbol=spot.instrument_key,
            action="update",
            sequence=3,
            previous=0,
            future_marker="sequence-gap",
        ),
    )
    generation_two = AutoAckWebSocketConnection(
        "spot-book-2",
        _book_message(
            wire_symbol=spot.instrument_key,
            action="snapshot",
            sequence=200,
            previous=-1,
            future_marker="snapshot-2",
        ),
        OSError("scripted disconnect"),
    )
    generation_three = AutoAckWebSocketConnection(
        "spot-book-3",
        _book_message(
            wire_symbol=spot.instrument_key,
            action="snapshot",
            sequence=300,
            previous=-1,
            future_marker="snapshot-3",
        ),
    )
    websocket = RouteScriptedWebSocketTransport()
    websocket.add(
        WS_PUBLIC_ENDPOINT,
        generation_one,
        generation_two,
        generation_three,
    )
    http = RouteScriptedHttpTransport()
    plan, _, manifests, _ = await _run_session(
        tmp_path=tmp_path,
        worker_id="okx-book-lifecycle",
        adapter=adapter,
        request=request,
        transports={
            "direct-primary": EgressTransport(
                egress_id="direct-primary",
                http=http,
                websocket=websocket,
            )
        },
        ready=lambda: generation_three.drained.is_set(),
    )

    assert plan.expected_logical_streams() == {"_control", "book_live"}
    rows = read_raw_rows(tmp_path / "data", manifests)
    live = rows["book_live"]
    assert len(live) == 8
    assert [row.connection_generation for row in live] == [1, 1, 1, 1, 1, 1, 2, 3]
    assert all(row.connection_id.startswith("okx-spot-spot-0-") for row in live)
    assert len({row.connection_id for row in live}) == 3
    assert [row.integrity_mode for row in live] == [
        IntegrityMode.SEQUENCE_VERIFIED,
        IntegrityMode.SEQUENCE_VERIFIED,
        IntegrityMode.SEQUENCE_VERIFIED,
        IntegrityMode.SEQUENCE_VERIFIED,
        IntegrityMode.SEQUENCE_VERIFIED,
        IntegrityMode.INVALID,
        IntegrityMode.SEQUENCE_VERIFIED,
        IntegrityMode.SEQUENCE_VERIFIED,
    ]
    markers = [_data_row(row)["futureBookField"] for row in live]
    assert markers.count({"marker": "heartbeat"}) == 1
    assert markers[3:5] == [
        {"marker": "maintenance-reset"},
        {"marker": "linked-after-reset"},
    ]
    assert markers[5] == {"marker": "sequence-gap"}

    controls = [_mapping(row.payload) for row in rows["_control"]]
    resets = [item for item in controls if item.get("kind") == "book_sequence_reset"]
    gaps = [item for item in controls if item.get("kind") == "book_gap"]
    reconnects = [item for item in controls if item.get("kind") == "ws_reconnect"]
    assert len(resets) == 1
    assert resets[0]["reason"] == "maintenance_sequence_reset"
    assert resets[0]["connection_generation"] == 1
    assert len(gaps) == 1
    assert gaps[0]["reason"] == "book_sequence_gap"
    assert gaps[0]["connection_generation"] == 1
    assert any(
        item.get("reason") == "transport_error"
        and item.get("error_type") == "OSError"
        and item.get("connection_generation") == 2
        for item in reconnects
    )
    acknowledgements = [
        item for item in controls if item.get("kind") == "ws_subscribe_ack"
    ]
    assert [item.get("server_connection_id") for item in acknowledgements] == [
        "spot-book-1",
        "spot-book-2",
        "spot-book-3",
    ]
    assert websocket.uris == [WS_PUBLIC_ENDPOINT] * 3
    assert all(
        connection.closed
        for connection in (generation_one, generation_two, generation_three)
    )
    assert http.closed


@pytest.mark.asyncio
async def test_scripted_okx_rest_50011_retry_and_schema_terminal_keep_exact_evidence(
    tmp_path: Path,
) -> None:
    perpetual = _instrument(Market.PERPETUAL)
    request = _request(
        {Market.PERPETUAL: (perpetual,)},
        {Market.PERPETUAL: frozenset({"book_deep_snapshot", "candle_1m"})},
    )
    adapter = OkxAdapter(
        endpoints=OkxEndpoints(
            rest=REST_ENDPOINT,
            websocket_public=WS_PUBLIC_ENDPOINT,
            websocket_business=WS_BUSINESS_ENDPOINT,
        ),
        routes={
            (Market.PERPETUAL, perpetual.instrument_key): OkxPlanRoute(
                egress_id="socks-secondary",
                quota_group="proxy-nat",
                shard_id="perpetual-0",
            )
        },
    )
    http = RouteScriptedHttpTransport()
    rate_limited_payload = {
        "code": "50011",
        "msg": "Rate limit reached",
        "data": [],
        "futureRateLimitField": {"exact": True},
    }
    http.add(
        DEEP_BOOK_PATH,
        okx_response(
            rate_limited_payload,
            headers={"retry-after": "0", "x-ratelimit-remaining": "0"},
        ),
        _deep_success("retry-success"),
    )
    malformed_candle_payload = {
        "code": "0",
        "msg": "",
        "data": [["1760000000123", "too-short"]],
        "futureSchemaField": {"exact": [1, 2, 3]},
    }
    http.add(CANDLE_PATH, okx_response(malformed_candle_payload))
    websocket = RouteScriptedWebSocketTransport()
    plan, _, manifests, budgets = await _run_session(
        tmp_path=tmp_path,
        worker_id="okx-rest-failures",
        adapter=adapter,
        request=request,
        transports={
            "socks-secondary": EgressTransport(
                egress_id="socks-secondary",
                http=http,
                websocket=websocket,
            )
        },
        ready=lambda: len(http.requests) == 3,
    )

    assert plan.expected_logical_streams() == {
        "_control",
        "book_deep_snapshot",
        "candle_1m",
    }
    assert Counter(request.path for request in http.requests) == Counter(
        {DEEP_BOOK_PATH: 2, CANDLE_PATH: 1}
    )
    assert budgets.bucket(("okx", "proxy-nat", "books-full")).refill_per_second == 50
    rows = read_raw_rows(tmp_path / "data", manifests)
    deep = rows["book_deep_snapshot"]
    assert len(deep) == 1
    assert deep[0].egress_id == "socks-secondary"
    assert deep[0].rest_metadata is not None
    assert deep[0].rest_metadata.attempt == 2
    assert _mapping(deep[0].payload)["futureEnvelopeField"] == {
        "marker": "retry-success"
    }
    assert "candle_1m" not in rows

    controls = [_mapping(row.payload) for row in rows["_control"]]
    retry = next(item for item in controls if item.get("kind") == "rest_retry")
    assert retry["origin_transport"] == "rest"
    assert retry["logical_stream"] == "book_deep_snapshot"
    assert retry["attempt"] == 1
    assert retry["reason"] == "okx_50011"
    assert retry["egress_id"] == "socks-secondary"
    assert retry["method"] == "GET"
    assert retry["path"] == DEEP_BOOK_PATH
    assert retry["response"] == rate_limited_payload
    assert retry["rate_limit_headers"] == {
        "retry-after": "0",
        "x-ratelimit-remaining": "0",
    }
    assert isinstance(retry["request_started_at_ns"], int)
    assert isinstance(retry["request_ended_at_ns"], int)
    assert retry["request_ended_at_ns"] >= retry["request_started_at_ns"]
    assert retry["requested_interval_ns"] == SECOND_NS
    assert retry["effective_interval_ns"] == SECOND_NS

    terminal = next(
        item
        for item in controls
        if item.get("kind") == "rest_terminal"
        and item.get("logical_stream") == "candle_1m"
    )
    assert terminal["reason"] == "OkxPayloadError"
    assert terminal["attempt"] == 1
    assert terminal["egress_id"] == "socks-secondary"
    assert terminal["path"] == CANDLE_PATH
    assert terminal["response"] == malformed_candle_payload
    assert isinstance(terminal["request_started_at_ns"], int)
    assert isinstance(terminal["request_ended_at_ns"], int)
    assert terminal["request_ended_at_ns"] >= terminal["request_started_at_ns"]
    assert http.closed
