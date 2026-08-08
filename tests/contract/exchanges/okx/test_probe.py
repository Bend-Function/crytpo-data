from __future__ import annotations

import asyncio
import json
from collections import deque
from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx
import pytest

from crypto_collector.config.probe_contracts import (
    DateGateRequest,
    ProbeRequest,
)
from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.exchanges.contracts import (
    AdapterRuntime,
    CollectionRequest,
    EgressTransport,
    PublicQueryValue,
)
from crypto_collector.exchanges.okx.adapter import (
    OKX_COMMON_RESEARCH_STREAMS,
    OKX_PERPETUAL_RESEARCH_STREAMS,
    OkxAdapter,
    OkxPlanRoute,
)
from crypto_collector.exchanges.okx.probe import (
    OKX_BOOKS_FULL_TOKENS_PER_SECOND,
    OKX_CANDLES_TOKENS_PER_SECOND,
    OKX_INSTRUMENTS_TOKENS_PER_SECOND,
    OKX_INSURANCE_FUND_TOKENS_PER_SECOND,
    OKX_PREMIUM_HISTORY_TOKENS_PER_SECOND,
    OkxProbeError,
    OkxProbeProvider,
)
from crypto_collector.network import BudgetRegistry
from crypto_collector.scheduler import RestScheduler
from crypto_collector.selection import CatalogScope, ListingState

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "okx"
_HOUR_NS = 3_600_000_000_000
_DEFAULT_LOOKBACK_NS = 72 * _HOUR_NS
_NOW_NS = 1_800_000_000_000_000_000
_TIME_PAYLOAD = {
    "code": "0",
    "msg": "",
    "data": [{"ts": "1800000000123"}],
}
_SPOT_TICKERS = {
    "code": "0",
    "msg": "",
    "data": [
        {
            "instType": "SPOT",
            "instId": "BTC-USDT",
            "last": "100000",
            "vol24h": "2.5",
            "volCcy24h": "250000.00000001",
            "ts": "1800000000123",
        },
        {
            "instType": "SPOT",
            "instId": "NEW-USDT",
            "last": "",
            "vol24h": "0",
            "volCcy24h": "",
            "ts": "1800000000123",
        },
    ],
}
_BOOKS_RPI = {
    "code": "0",
    "msg": "",
    "data": [{"asks": [], "bids": [], "ts": "1800000000123"}],
}


class FixedClock:
    def __init__(self, now_ns: int = _NOW_NS) -> None:
        self._now_ns = now_ns

    def time_ns(self) -> int:
        return self._now_ns

    def monotonic_ns(self) -> int:
        return 1


class NeverStop:
    def __init__(self) -> None:
        self._event = asyncio.Event()

    def is_set(self) -> bool:
        return False

    async def wait(self) -> None:
        await self._event.wait()


class ScriptedTransport:
    def __init__(
        self,
        *,
        fail_time: bool = False,
        catalog_business_error: bool = False,
        fail_rpi_for_swap: bool = False,
    ) -> None:
        self.fail_time = fail_time
        self.catalog_business_error = catalog_business_error
        self.fail_rpi_for_swap = fail_rpi_for_swap
        self.calls: list[tuple[str, dict[str, PublicQueryValue], float | None]] = []

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, PublicQueryValue] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        path = httpx.URL(url).path
        normalized = {} if params is None else dict(params)
        self.calls.append((path, normalized, timeout))
        if path == "/api/v5/public/time" and self.fail_time:
            raise httpx.ConnectError("socks5://user:secret@127.0.0.1:1080 failed")
        if path == "/api/v5/public/time":
            payload: Any = _TIME_PAYLOAD
        elif path == "/api/v5/public/instruments":
            if self.catalog_business_error:
                payload = {"code": "50011", "msg": "too many requests", "data": []}
            else:
                filename = (
                    "instruments-spot.json"
                    if normalized["instType"] == "SPOT"
                    else "instruments-swap.json"
                )
                payload = decode_json((_FIXTURES / filename).read_bytes())
        elif path == "/api/v5/market/tickers":
            payload = (
                _SPOT_TICKERS
                if normalized["instType"] == "SPOT"
                else decode_json((_FIXTURES / "tickers.json").read_bytes())
            )
        elif path == "/api/v5/market/books-rpi":
            payload = (
                {"code": "50013", "msg": "unavailable", "data": []}
                if self.fail_rpi_for_swap
                and str(normalized["instId"]).endswith("-SWAP")
                else _BOOKS_RPI
            )
        else:  # pragma: no cover - makes unexpected probe expansion obvious.
            raise AssertionError(f"unexpected OKX probe path: {path}")
        return httpx.Response(200, content=encode_json(payload))


class ProbeWebSocketConnection:
    def __init__(
        self,
        *,
        connection_id: str,
        mismatch_ack: bool = False,
        silent: bool = False,
        omit_book_snapshot: bool = False,
    ) -> None:
        self.connection_id = connection_id
        self.mismatch_ack = mismatch_ack
        self.silent = silent
        self.omit_book_snapshot = omit_book_snapshot
        self.frames: deque[str] = deque()
        self.sent: list[str] = []
        self.closed = False
        self._blocked = asyncio.Event()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self.closed = True

    async def send(self, message: str) -> None:
        self.sent.append(message)
        if self.silent:
            return
        payload = json.loads(message)
        if payload.get("op") != "subscribe":
            return
        request_id = payload["id"]
        for argument in payload["args"]:
            acknowledged = dict(argument)
            if self.mismatch_ack:
                acknowledged["instId"] = "MISMATCH-USDT"
            self.frames.append(
                json.dumps(
                    {
                        "id": request_id,
                        "event": "subscribe",
                        "arg": acknowledged,
                        "connId": self.connection_id,
                    },
                    separators=(",", ":"),
                )
            )
            if argument["channel"] == "books" and not self.omit_book_snapshot:
                self.frames.append(
                    json.dumps(
                        {
                            "arg": argument,
                            "action": "snapshot",
                            "data": [
                                {
                                    "asks": [["2", "1", "0", "1"]],
                                    "bids": [["1", "1", "0", "1"]],
                                    "ts": "1800000000123",
                                    "seqId": 1,
                                    "prevSeqId": -1,
                                }
                            ],
                        },
                        separators=(",", ":"),
                    )
                )

    async def recv(self) -> str:
        if self.frames:
            return self.frames.popleft()
        await self._blocked.wait()
        raise AssertionError("unreachable WebSocket wake")


class ProbeWebSocketTransport:
    def __init__(
        self,
        *,
        mismatch_role: str | None = None,
        silent_role: str | None = None,
        omit_snapshot_role: str | None = None,
    ) -> None:
        self.mismatch_role = mismatch_role
        self.silent_role = silent_role
        self.omit_snapshot_role = omit_snapshot_role
        self.uris: list[str] = []
        self.connections: list[ProbeWebSocketConnection] = []

    def connect(self, uri: str) -> ProbeWebSocketConnection:
        self.uris.append(uri)
        role = "business" if uri.endswith("/business") else "public"
        connection = ProbeWebSocketConnection(
            connection_id=f"probe-{role}-{len(self.connections) + 1}",
            mismatch_ack=self.mismatch_role == role,
            silent=self.silent_role == role,
            omit_book_snapshot=self.omit_snapshot_role == role,
        )
        self.connections.append(connection)
        return connection


def _websocket_transports(
    *egress_ids: str,
) -> dict[str, ProbeWebSocketTransport]:
    return {egress_id: ProbeWebSocketTransport() for egress_id in egress_ids}


def _request(
    *,
    egress_ids: tuple[str, ...] = ("direct-a",),
    markets: tuple[Market, ...] = (Market.SPOT,),
    date_gates: tuple[DateGateRequest, ...] = (),
    observed_at_ns: int = _NOW_NS,
    initial_lookback_ns: Mapping[tuple[Market, str | None], int] | None = None,
) -> ProbeRequest:
    return ProbeRequest(
        exchange=Exchange.OKX,
        markets=tuple(CatalogScope(Exchange.OKX, market) for market in markets),
        egress_ids=egress_ids,
        initial_lookback_ns=(
            {(market, None): _DEFAULT_LOOKBACK_NS for market in markets}
            if initial_lookback_ns is None
            else initial_lookback_ns
        ),
        config_sha256="a" * 64,
        observed_at_ns=observed_at_ns,
        date_gates=date_gates,
    )


@pytest.mark.asyncio
async def test_probe_builds_complete_ephemeral_catalog_and_quota_evidence(
    tmp_path: Path,
) -> None:
    direct = ScriptedTransport()
    socks = ScriptedTransport()
    websocket_transports = _websocket_transports("socks-b", "direct-a")
    provider = OkxProbeProvider(
        transports={"socks-b": socks, "direct-a": direct},
        websocket_transports=websocket_transports,
        quota_groups={"socks-b": "shared-public-ip", "direct-a": "shared-public-ip"},
        clock=FixedClock(),
        rest_base_url="http://127.0.0.1:8080",
    )
    request = _request(
        egress_ids=("socks-b", "direct-a"),
        markets=(Market.SPOT, Market.PERPETUAL),
        date_gates=(
            DateGateRequest(
                feature_id="books_rpi",
                markets=(Market.PERPETUAL, Market.SPOT),
                required=False,
                available_from="2026-07-28",
                requires_live_probe=True,
            ),
        ),
    )
    before = tuple(tmp_path.rglob("*"))

    evidence = await provider.probe(request)

    assert tuple(tmp_path.rglob("*")) == before == ()
    assert evidence.exchange is Exchange.OKX
    assert evidence.public_time.exchange_time_ns == 1_800_000_000_123_000_000
    assert [(item.egress_id, item.reachable) for item in evidence.egresses] == [
        ("direct-a", True),
        ("socks-b", True),
    ]
    assert all(
        [
            (item.transport, item.endpoint_role, item.reachable)
            for item in egress.transports
        ]
        == [
            ("http", "public_rest", True),
            ("websocket", "business", True),
            ("websocket", "public", True),
        ]
        for egress in evidence.egresses
    )
    assert all(
        transport.uris
        == [
            "wss://ws.okx.com:8443/ws/v5/public",
            "wss://ws.okx.com:8443/ws/v5/business",
        ]
        for transport in websocket_transports.values()
    )
    assert all(
        connection.closed
        for transport in websocket_transports.values()
        for connection in transport.connections
    )
    assert [item.scope.market for item in evidence.markets] == [
        Market.PERPETUAL,
        Market.SPOT,
    ]

    markets = {item.scope.market: item for item in evidence.markets}
    spot = markets[Market.SPOT]
    perpetual = markets[Market.PERPETUAL]
    assert spot.subscriptions_per_connection == 98
    assert spot.subscriptions_per_instrument == 4
    assert perpetual.subscriptions_per_connection == 97
    assert perpetual.subscriptions_per_instrument == 9
    assert spot.endpoint_work[0].logical_endpoint == "books-full"
    assert spot.endpoint_work[0].depth == "max_supported"
    assert {(item.logical_endpoint, item.kind) for item in spot.endpoint_work} == {
        ("books-full", "deep_snapshot"),
        ("candles", "periodic_reference"),
        ("instruments", "periodic_reference"),
    }
    assert {(item.logical_endpoint, item.kind) for item in perpetual.endpoint_work} == {
        ("books-full", "deep_snapshot"),
        ("candles", "periodic_reference"),
        ("instruments", "periodic_reference"),
        ("insurance-fund", "periodic_reference"),
        ("premium-history", "periodic_reference"),
    }

    spot_instruments = {item.instrument_key: item for item in spot.catalog.instruments}
    assert spot_instruments["BTC-USDT"].turnover is not None
    assert spot_instruments["BTC-USDT"].turnover.value == Decimal("250000.00000001")
    assert spot_instruments["BTC-USDT"].listing_state is ListingState.BASELINE
    assert spot_instruments["NEW-USDT"].listing_state is ListingState.PENDING
    assert spot.catalog.catalog_revision == 1
    assert spot.catalog.turnover_revision == 1
    assert len(spot.catalog.catalog_digest_sha256 or "") == 64

    perpetual_instruments = {
        item.instrument_key: item for item in perpetual.catalog.instruments
    }
    assert set(perpetual_instruments) == {"BTC-USDT-SWAP", "NEW-USDT-SWAP"}
    assert perpetual_instruments["BTC-USDT-SWAP"].turnover is not None
    assert perpetual_instruments["BTC-USDT-SWAP"].turnover.value == Decimal(
        "1234567.8900000"
    )

    assert [
        (
            item.quota_group,
            item.logical_endpoint,
            item.available_tokens_per_second,
        )
        for item in evidence.endpoint_budgets
    ] == [
        ("shared-public-ip", "books-full", OKX_BOOKS_FULL_TOKENS_PER_SECOND),
        ("shared-public-ip", "candles", OKX_CANDLES_TOKENS_PER_SECOND),
        (
            "shared-public-ip",
            "instruments",
            OKX_INSTRUMENTS_TOKENS_PER_SECOND,
        ),
        (
            "shared-public-ip",
            "insurance-fund",
            OKX_INSURANCE_FUND_TOKENS_PER_SECOND,
        ),
        (
            "shared-public-ip",
            "premium-history",
            OKX_PREMIUM_HISTORY_TOKENS_PER_SECOND,
        ),
    ]
    assert [(item.feature_id, item.available) for item in evidence.date_gates] == [
        ("books_rpi", True)
    ]
    assert all(call[2] == 10.0 for call in socks.calls + direct.calls)


@pytest.mark.asyncio
async def test_probe_72h_initial_window_only_marks_recent_official_listing() -> None:
    listed_at_ns = 1_700_000_000_123_000_000
    observed_at_ns = listed_at_ns + 71 * _HOUR_NS
    provider = OkxProbeProvider(
        transports={"direct-a": ScriptedTransport()},
        websocket_transports=_websocket_transports("direct-a"),
        quota_groups={"direct-a": "direct-a"},
        clock=FixedClock(observed_at_ns),
        rest_base_url="http://127.0.0.1:8080",
    )

    evidence = await provider.probe(_request(observed_at_ns=observed_at_ns))

    records = {
        item.instrument_key: item for item in evidence.markets[0].catalog.instruments
    }
    assert records["BTC-USDT"].listing_state is ListingState.ACTIVE_NEW
    assert records["BTC-USDT"].new_listing_started_at_ns == listed_at_ns
    assert records["NEW-USDT"].listing_state is ListingState.PENDING


@pytest.mark.asyncio
async def test_probe_symbol_lookback_overrides_market_fallback() -> None:
    provider = OkxProbeProvider(
        transports={"direct-a": ScriptedTransport()},
        websocket_transports=_websocket_transports("direct-a"),
        quota_groups={"direct-a": "direct-a"},
        clock=FixedClock(),
        rest_base_url="http://127.0.0.1:8080",
    )
    listed_at_ns = 1_700_000_000_123_000_000

    evidence = await provider.probe(
        _request(
            initial_lookback_ns={
                (Market.SPOT, None): 0,
                (Market.SPOT, "BTC-USDT"): _NOW_NS - listed_at_ns,
            }
        )
    )

    records = {
        item.instrument_key: item for item in evidence.markets[0].catalog.instruments
    }
    assert records["BTC-USDT"].listing_state is ListingState.ACTIVE_NEW
    assert records["NEW-USDT"].listing_state is ListingState.PENDING


@pytest.mark.asyncio
async def test_probe_budgets_cover_every_rest_endpoint_in_full_adapter_plan() -> None:
    provider = OkxProbeProvider(
        transports={"direct": ScriptedTransport()},
        websocket_transports=_websocket_transports("direct"),
        quota_groups={"direct": "direct"},
        clock=FixedClock(),
        rest_base_url="http://127.0.0.1:8080",
    )
    evidence = await provider.probe(
        _request(
            egress_ids=("direct",),
            markets=(Market.SPOT, Market.PERPETUAL),
        )
    )
    markets = {item.scope.market: item for item in evidence.markets}
    selected = {
        market: (market_evidence.catalog.instruments[0],)
        for market, market_evidence in markets.items()
    }
    plan = OkxAdapter().plan(
        CollectionRequest.model_validate(
            {
                "exchange": Exchange.OKX,
                "selected": selected,
                "enabled_streams": {
                    Market.SPOT: frozenset({"book_deep_snapshot", "candle_1m"}),
                    Market.PERPETUAL: frozenset(
                        {
                            "book_deep_snapshot",
                            "candle_1m",
                            "premium",
                            "insurance_fund",
                        }
                    ),
                },
                "interval_plans": {},
                "config_sha256": "a" * 64,
            }
        )
    )
    budgets = BudgetRegistry(FixedClock())
    for item in evidence.endpoint_budgets:
        budgets.add(
            (Exchange.OKX.value, item.quota_group, item.logical_endpoint),
            capacity=item.available_tokens_per_second,
            refill_per_second=item.available_tokens_per_second,
        )

    for item in plan.rest:
        assert budgets.bucket(
            (item.exchange.value, item.quota_group, item.logical_endpoint)
        )


@pytest.mark.asyncio
async def test_probe_budget_registry_covers_adapter_catalog_fetch() -> None:
    http = ScriptedTransport()
    websocket = ProbeWebSocketTransport()
    provider = OkxProbeProvider(
        transports={"direct": http},
        websocket_transports={"direct": websocket},
        quota_groups={"direct": "direct"},
        clock=FixedClock(),
    )
    evidence = await provider.probe(_request(egress_ids=("direct",)))
    runtime_clock = FixedClock()
    budgets = BudgetRegistry(runtime_clock)
    for item in evidence.endpoint_budgets:
        budgets.add(
            (Exchange.OKX.value, item.quota_group, item.logical_endpoint),
            capacity=item.available_tokens_per_second,
            refill_per_second=item.available_tokens_per_second,
        )
    runtime = AdapterRuntime(
        transports={
            "direct": EgressTransport(
                egress_id="direct",
                http=http,
                websocket=websocket,
            )
        },
        scheduler=RestScheduler(budgets, clock=runtime_clock),
        clock=runtime_clock,
        stop=NeverStop(),
    )
    adapter = OkxAdapter(
        routes={
            (Market.SPOT, None): OkxPlanRoute(
                egress_id="direct",
                quota_group="direct",
                shard_id="probe-catalog",
            )
        }
    )

    catalog = await adapter.fetch_catalog(runtime, Market.SPOT)

    assert catalog.scope == CatalogScope(Exchange.OKX, Market.SPOT)
    assert [item.instrument_key for item in catalog.instruments] == [
        "BTC-USDT",
        "NEW-USDT",
    ]


@pytest.mark.asyncio
async def test_probe_isolates_failed_egress_and_does_not_leak_transport_error() -> None:
    failed = ScriptedTransport(fail_time=True)
    healthy = ScriptedTransport()
    provider = OkxProbeProvider(
        transports={"failed": failed, "healthy": healthy},
        websocket_transports=_websocket_transports("failed", "healthy"),
        quota_groups={"failed": "failed-ip", "healthy": "healthy-ip"},
        clock=FixedClock(),
    )

    evidence = await provider.probe(_request(egress_ids=("failed", "healthy")))

    egresses = {item.egress_id: item for item in evidence.egresses}
    assert egresses["failed"].reachable is False
    assert "secret" not in egresses["failed"].raw_reference
    assert egresses["healthy"].reachable is True
    assert {item.quota_group for item in evidence.endpoint_budgets} == {"healthy-ip"}
    assert len(evidence.endpoint_budgets) == 5
    assert all(call[0] == "/api/v5/public/time" for call in failed.calls)


@pytest.mark.asyncio
async def test_http_success_with_websocket_ack_mismatch_is_not_ws_healthy() -> None:
    healthy = ProbeWebSocketTransport()
    mismatch = ProbeWebSocketTransport(mismatch_role="business")
    provider = OkxProbeProvider(
        transports={"healthy": ScriptedTransport(), "mismatch": ScriptedTransport()},
        websocket_transports={"healthy": healthy, "mismatch": mismatch},
        quota_groups={"healthy": "healthy-ip", "mismatch": "mismatch-ip"},
        clock=FixedClock(),
        timeout_seconds=0.05,
    )

    evidence = await provider.probe(_request(egress_ids=("mismatch", "healthy")))

    egresses = {item.egress_id: item for item in evidence.egresses}
    failed = egresses["mismatch"]
    assert failed.reachable is False
    assert failed.http_reachable is True
    assert failed.websocket_reachable is False
    by_role = {item.endpoint_role: item for item in failed.transports}
    assert by_role["public"].reachable is True
    assert by_role["business"].reachable is False
    assert "MISMATCH-USDT" not in by_role["business"].raw_reference
    assert {item.quota_group for item in evidence.endpoint_budgets} == {
        "healthy-ip",
        "mismatch-ip",
    }
    assert all(connection.closed for connection in mismatch.connections)


@pytest.mark.asyncio
async def test_websocket_ack_timeout_is_bounded_and_closes_every_session() -> None:
    websocket = ProbeWebSocketTransport(silent_role="business")
    provider = OkxProbeProvider(
        transports={"direct": ScriptedTransport()},
        websocket_transports={"direct": websocket},
        quota_groups={"direct": "direct"},
        clock=FixedClock(),
        timeout_seconds=0.01,
    )

    evidence = await provider.probe(_request(egress_ids=("direct",)))

    egress = evidence.egresses[0]
    assert egress.http_reachable is True
    assert egress.websocket_reachable is False
    assert {item.endpoint_role: item.reachable for item in egress.transports} == {
        "public_rest": True,
        "business": False,
        "public": True,
    }
    assert len(websocket.connections) == 2
    assert all(connection.closed for connection in websocket.connections)


@pytest.mark.asyncio
async def test_public_book_probe_requires_first_snapshot_after_ack() -> None:
    websocket = ProbeWebSocketTransport(omit_snapshot_role="public")
    provider = OkxProbeProvider(
        transports={"direct": ScriptedTransport()},
        websocket_transports={"direct": websocket},
        quota_groups={"direct": "direct"},
        clock=FixedClock(),
        timeout_seconds=0.01,
    )

    evidence = await provider.probe(_request(egress_ids=("direct",)))

    egress = evidence.egresses[0]
    by_role = {item.endpoint_role: item for item in egress.transports}
    assert by_role["public"].reachable is False
    assert by_role["business"].reachable is True
    assert all(connection.closed for connection in websocket.connections)


@pytest.mark.asyncio
async def test_probe_all_egress_failure_has_stable_sanitized_error() -> None:
    provider = OkxProbeProvider(
        transports={"direct": ScriptedTransport(fail_time=True)},
        websocket_transports=_websocket_transports("direct"),
        quota_groups={"direct": "direct"},
        clock=FixedClock(),
    )

    with pytest.raises(
        OkxProbeError,
        match="^OKX public-time probe failed on every requested egress$",
    ) as captured:
        await provider.probe(_request(egress_ids=("direct",)))

    assert "secret" not in str(captured.value)


@pytest.mark.asyncio
async def test_required_catalog_failure_is_deterministic() -> None:
    provider = OkxProbeProvider(
        transports={"direct-a": ScriptedTransport(catalog_business_error=True)},
        websocket_transports=_websocket_transports("direct-a"),
        quota_groups={"direct-a": "direct-a"},
        clock=FixedClock(),
    )

    with pytest.raises(
        OkxProbeError,
        match="^OKX spot-catalog probe failed on every reachable egress$",
    ):
        await provider.probe(_request())


@pytest.mark.asyncio
async def test_unknown_live_date_gate_is_reported_unavailable() -> None:
    provider = OkxProbeProvider(
        transports={"direct-a": ScriptedTransport()},
        websocket_transports=_websocket_transports("direct-a"),
        quota_groups={"direct-a": "direct-a"},
        clock=FixedClock(),
    )
    request = _request(
        date_gates=(
            DateGateRequest(
                feature_id="future_feature",
                markets=(Market.SPOT,),
                required=False,
                available_from=None,
                requires_live_probe=True,
            ),
        )
    )

    evidence = await provider.probe(request)

    assert [(item.feature_id, item.available) for item in evidence.date_gates] == [
        ("future_feature", False)
    ]


@pytest.mark.asyncio
async def test_books_rpi_gate_requires_every_requested_market_to_pass() -> None:
    transport = ScriptedTransport(fail_rpi_for_swap=True)
    provider = OkxProbeProvider(
        transports={"direct-a": transport},
        websocket_transports=_websocket_transports("direct-a"),
        quota_groups={"direct-a": "direct-a"},
        clock=FixedClock(),
    )
    request = _request(
        markets=(Market.SPOT, Market.PERPETUAL),
        date_gates=(
            DateGateRequest(
                feature_id="books_rpi",
                markets=(Market.PERPETUAL, Market.SPOT),
                required=False,
                available_from="2026-07-28",
                requires_live_probe=True,
            ),
        ),
    )

    evidence = await provider.probe(request)

    assert [(item.feature_id, item.available) for item in evidence.date_gates] == [
        ("books_rpi", False)
    ]
    rpi_symbols = [
        str(params["instId"])
        for path, params, _timeout in transport.calls
        if path == "/api/v5/market/books-rpi"
    ]
    assert rpi_symbols == ["BTC-USDT-SWAP"]


@pytest.mark.asyncio
async def test_subscription_capacity_matches_adapter_instrument_ws_surface() -> None:
    transport = ScriptedTransport()
    provider = OkxProbeProvider(
        transports={"direct-a": transport},
        websocket_transports=_websocket_transports("direct-a"),
        quota_groups={"direct-a": "direct-a"},
        clock=FixedClock(),
    )
    evidence = await provider.probe(_request(markets=(Market.SPOT, Market.PERPETUAL)))
    markets = {item.scope.market: item for item in evidence.markets}
    selected = {
        market: (market_evidence.catalog.instruments[0],)
        for market, market_evidence in markets.items()
    }
    plan = OkxAdapter().plan(
        CollectionRequest.model_validate(
            {
                "exchange": Exchange.OKX,
                "selected": selected,
                "enabled_streams": {
                    Market.SPOT: OKX_COMMON_RESEARCH_STREAMS,
                    Market.PERPETUAL: (
                        OKX_COMMON_RESEARCH_STREAMS | OKX_PERPETUAL_RESEARCH_STREAMS
                    ),
                },
                "interval_plans": {},
                "config_sha256": "a" * 64,
            }
        )
    )

    for market, market_evidence in markets.items():
        instrument_ws_count = sum(
            item.market is market and item.instrument_key is not None
            for item in plan.ws
        )
        assert instrument_ws_count == market_evidence.subscriptions_per_instrument
    liquidation = [item for item in plan.ws if item.logical_stream == "liquidation"]
    assert len(liquidation) == 1
    assert liquidation[0].instrument_key is None


def test_provider_requires_exact_quota_group_coverage_and_safe_base_url() -> None:
    transport = ScriptedTransport()
    with pytest.raises(ValueError, match="exactly cover"):
        OkxProbeProvider(
            transports={"direct": transport},
            websocket_transports=_websocket_transports("direct"),
            quota_groups={},
            clock=FixedClock(),
        )
    with pytest.raises(ValueError, match="must use HTTPS"):
        OkxProbeProvider(
            transports={"direct": transport},
            websocket_transports=_websocket_transports("direct"),
            quota_groups={"direct": "direct"},
            clock=FixedClock(),
            rest_base_url="http://api.example.test",
        )
    with pytest.raises(ValueError, match="credentials"):
        OkxProbeProvider(
            transports={"direct": transport},
            websocket_transports=_websocket_transports("direct"),
            quota_groups={"direct": "direct"},
            clock=FixedClock(),
            rest_base_url="https://user:secret@api.example.test",
        )
    with pytest.raises(ValueError, match="websocket_transports must exactly cover"):
        OkxProbeProvider(
            transports={"direct": transport},
            websocket_transports={},
            quota_groups={"direct": "direct"},
            clock=FixedClock(),
        )
    with pytest.raises(ValueError, match="credentials"):
        OkxProbeProvider(
            transports={"direct": transport},
            websocket_transports=_websocket_transports("direct"),
            quota_groups={"direct": "direct"},
            clock=FixedClock(),
            websocket_public_url=(
                "wss://probe-user:probe-secret@ws.example.test/ws/v5/public"
            ),
        )
