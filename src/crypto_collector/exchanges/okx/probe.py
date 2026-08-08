from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, replace
from decimal import Decimal
from hashlib import sha256
from math import isfinite
from types import MappingProxyType
from typing import cast
from urllib.parse import urlsplit

import httpx

from crypto_collector.config.probe_contracts import (
    DateGateProbe,
    DateGateRequest,
    EgressReachabilityProbe,
    EndpointBudgetProbe,
    EndpointWork,
    ExchangeProbeEvidence,
    MarketProbeEvidence,
    ProbeRequest,
    PublicTimeProbe,
    TransportReachabilityProbe,
)
from crypto_collector.domain import Exchange, Market, RestMetadata, SourceContext
from crypto_collector.domain.clock import Clock
from crypto_collector.domain.json_codec import (
    JsonPayload,
    ValidatedJsonPayload,
    encode_json,
)
from crypto_collector.exchanges.contracts import (
    PublicHttpTransport,
    PublicQueryValue,
    PublicWebSocketTransport,
    WebSocketSubscription,
)
from crypto_collector.exchanges.okx.catalog import parse_instruments, parse_tickers
from crypto_collector.exchanges.okx.errors import require_okx_success
from crypto_collector.exchanges.okx.rest import (
    OkxRestCapture,
    OkxRestRequest,
    instruments_request,
    parse_public_time_ns,
    public_time_request,
    tickers_request,
)
from crypto_collector.exchanges.okx.ws import (
    OkxWsMessageKind,
    OkxWsSession,
    OkxWsSessionAction,
)
from crypto_collector.selection import (
    CatalogInstrument,
    CatalogView,
    CompleteCatalogSnapshot,
    CompleteTurnoverSnapshot,
    InstrumentRecord,
    Turnover,
    materialize_initial_catalog_instrument,
)

DEFAULT_OKX_REST_BASE_URL = "https://openapi.okx.com"
DEFAULT_OKX_WEBSOCKET_PUBLIC_URL = "wss://ws.okx.com:8443/ws/v5/public"
DEFAULT_OKX_WEBSOCKET_BUSINESS_URL = "wss://ws.okx.com:8443/ws/v5/business"
OKX_BOOKS_FULL_TOKENS_PER_SECOND = Decimal(5)
OKX_INSTRUMENTS_TOKENS_PER_SECOND = Decimal(10)
OKX_CANDLES_TOKENS_PER_SECOND = Decimal(20)
OKX_PREMIUM_HISTORY_TOKENS_PER_SECOND = Decimal(10)
OKX_INSURANCE_FUND_TOKENS_PER_SECOND = Decimal(5)
# OKX documents operation and payload limits, but no public concurrent-subscription
# ceiling. This is an operator-overridable project admission cap, not a venue limit.
OKX_CONSERVATIVE_SUBSCRIPTIONS_PER_CONNECTION = 100

_BOOKS_FULL_LOGICAL_ENDPOINT = "books-full"
_CATALOG_REFRESH_INTERVAL_NS = 5 * 60 * 1_000_000_000
_CANDLE_INTERVAL_NS = 60 * 1_000_000_000
_REFERENCE_INTERVAL_NS = 5 * 60 * 1_000_000_000
_ENDPOINT_TOKENS_PER_SECOND = MappingProxyType(
    {
        _BOOKS_FULL_LOGICAL_ENDPOINT: OKX_BOOKS_FULL_TOKENS_PER_SECOND,
        "instruments": OKX_INSTRUMENTS_TOKENS_PER_SECOND,
        "candles": OKX_CANDLES_TOKENS_PER_SECOND,
        "premium-history": OKX_PREMIUM_HISTORY_TOKENS_PER_SECOND,
        "insurance-fund": OKX_INSURANCE_FUND_TOKENS_PER_SECOND,
    }
)
_BOOKS_RPI_FEATURE = "books_rpi"
_BOOKS_RPI_PATH = "/api/v5/market/books-rpi"
_MARKET_SUBSCRIPTIONS_PER_INSTRUMENT = {
    Market.SPOT: 4,
    Market.PERPETUAL: 9,
}
_MARKET_FIXED_SUBSCRIPTIONS = {
    Market.SPOT: 2,
    Market.PERPETUAL: 3,
}
_RATE_LIMIT_REFERENCE = "docs/exchanges/okx/README.md#anonymous-rest-coverage"
_CAPABILITY_REFERENCE = "docs/exchanges/okx/README.md#anonymous-websocket-channels"


class OkxProbeError(RuntimeError):
    """A bounded OKX probe could not produce complete startup evidence."""


@dataclass(frozen=True, slots=True)
class _FetchedPayload:
    payload: Mapping[str, JsonPayload]
    started_at_ns: int
    observed_at_ns: int
    raw_reference: str
    status: int


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _base_url(value: object) -> str:
    if type(value) is not str or not value:
        raise ValueError("rest_base_url must be a non-empty string")
    try:
        parsed = httpx.URL(value)
    except (TypeError, ValueError) as error:
        raise ValueError(
            "rest_base_url must be an anonymous public HTTP URL"
        ) from error
    if parsed.scheme not in {"http", "https"} or parsed.host is None:
        raise ValueError("rest_base_url must be an anonymous public HTTP URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            "rest_base_url must not contain credentials, query, or fragment"
        )
    if parsed.scheme == "http" and parsed.host not in {"127.0.0.1", "::1", "localhost"}:
        raise ValueError("non-loopback rest_base_url must use HTTPS")
    path = parsed.path.rstrip("/")
    if path:
        raise ValueError("rest_base_url must not contain a path")
    return str(parsed.copy_with(path="")).rstrip("/")


def _websocket_url(value: object, *, endpoint_role: str, path: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{endpoint_role} must be a non-empty string")
    try:
        parsed = urlsplit(value)
    except ValueError as error:
        raise ValueError(
            f"{endpoint_role} must be an anonymous public WebSocket URL"
        ) from error
    if parsed.scheme not in {"ws", "wss"} or not parsed.hostname:
        raise ValueError(f"{endpoint_role} must be an anonymous public WebSocket URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(
            f"{endpoint_role} must not contain credentials, query, or fragment"
        )
    if parsed.scheme == "ws" and parsed.hostname not in {
        "127.0.0.1",
        "::1",
        "localhost",
    }:
        raise ValueError(f"non-loopback {endpoint_role} must use WSS")
    if parsed.path.rstrip("/") != path:
        raise ValueError(f"{endpoint_role} must end at the OKX {path} path")
    return value.rstrip("/")


def _payload_reference(kind: str, payload: object) -> str:
    digest = sha256(encode_json(payload)).hexdigest()
    return f"okx:probe:{kind}:sha256:{digest}"


def _failure_reference(kind: str, error: BaseException | None = None) -> str:
    error_type = "unavailable" if error is None else type(error).__qualname__
    digest = sha256(f"{kind}\0{error_type}".encode()).hexdigest()
    return f"okx:probe:{kind}:failure:sha256:{digest}"


def _snapshot_digest(snapshot_id: str, references: tuple[str, ...]) -> str:
    payload = {"snapshot_id": snapshot_id, "raw_references": list(references)}
    return sha256(encode_json(payload)).hexdigest()


def _rpi_response_is_compatible(
    payload: Mapping[str, JsonPayload],
    *,
    wire_symbol: str,
) -> bool:
    data = payload.get("data")
    if not isinstance(data, (list, tuple)):
        return False
    for row in data:
        if not isinstance(row, Mapping):
            return False
        returned_symbol = row.get("instId")
        if returned_symbol is not None and returned_symbol != wire_symbol:
            return False
    return True


def _catalog_view(
    catalog: CompleteCatalogSnapshot,
    turnover: CompleteTurnoverSnapshot,
    *,
    request: ProbeRequest,
) -> CatalogView:
    if catalog.scope != turnover.scope or turnover.catalog_revision != 1:
        raise OkxProbeError("OKX turnover evidence is not bound to its catalog")
    observations = {item.instrument_key: item for item in turnover.observations}
    materialized: list[CatalogInstrument] = []
    for record in catalog.instruments:
        observation = observations.get(record.instrument_key)
        value = (
            None
            if observation is None
            else Turnover(
                observation.value,
                observation.method,
                observation.currency,
                observed_at_ns=turnover.observed_at_ns,
                raw_reference=observation.raw_reference,
            )
        )
        item = materialize_initial_catalog_instrument(
            record,
            observed_at_ns=catalog.observed_at_ns,
            initial_lookback_ns=request.initial_lookback_for(
                catalog.scope.market,
                record.instrument_key,
            ),
        )
        materialized.append(replace(item, turnover=value))
    catalog_references = catalog.page_raw_references
    turnover_references = turnover.page_raw_references
    return CatalogView(
        scope=catalog.scope,
        catalog_observed_at_ns=catalog.observed_at_ns,
        catalog_revision=1,
        catalog_digest_sha256=_snapshot_digest(
            catalog.snapshot_id,
            catalog_references,
        ),
        catalog_snapshot_id=catalog.snapshot_id,
        catalog_page_raw_references=catalog_references,
        turnover_observed_at_ns=turnover.observed_at_ns,
        turnover_revision=1,
        turnover_digest_sha256=_snapshot_digest(
            turnover.snapshot_id,
            turnover_references,
        ),
        turnover_catalog_revision=1,
        turnover_snapshot_id=turnover.snapshot_id,
        turnover_page_raw_references=turnover_references,
        turnover_covered_instrument_keys=turnover.covered_instrument_keys,
        instruments=tuple(materialized),
    )


class OkxProbeProvider:
    """Collect ephemeral startup evidence over caller-owned anonymous clients."""

    exchange = Exchange.OKX

    def __init__(
        self,
        *,
        transports: Mapping[str, PublicHttpTransport],
        websocket_transports: Mapping[str, PublicWebSocketTransport],
        quota_groups: Mapping[str, str],
        clock: Clock,
        rest_base_url: str = DEFAULT_OKX_REST_BASE_URL,
        websocket_public_url: str = DEFAULT_OKX_WEBSOCKET_PUBLIC_URL,
        websocket_business_url: str = DEFAULT_OKX_WEBSOCKET_BUSINESS_URL,
        timeout_seconds: float = 10.0,
        subscriptions_per_connection: int = (
            OKX_CONSERVATIVE_SUBSCRIPTIONS_PER_CONNECTION
        ),
    ) -> None:
        if not isinstance(transports, Mapping) or not transports:
            raise ValueError("transports must be a non-empty mapping")
        normalized_transports: dict[str, PublicHttpTransport] = {}
        for egress_id, http_transport in transports.items():
            key = _nonempty(egress_id, field="transport egress ID")
            if not callable(getattr(http_transport, "get", None)):
                raise TypeError("each transport must provide get()")
            normalized_transports[key] = http_transport
        if not isinstance(quota_groups, Mapping):
            raise TypeError("quota_groups must be a mapping")
        if not isinstance(websocket_transports, Mapping):
            raise TypeError("websocket_transports must be a mapping")
        normalized_websocket_transports: dict[str, PublicWebSocketTransport] = {}
        for egress_id, websocket_transport in websocket_transports.items():
            key = _nonempty(egress_id, field="WebSocket transport egress ID")
            if not callable(getattr(websocket_transport, "connect", None)):
                raise TypeError("each WebSocket transport must provide connect()")
            normalized_websocket_transports[key] = websocket_transport
        normalized_quota_groups = {
            _nonempty(egress_id, field="quota egress ID"): _nonempty(
                quota_group,
                field="quota group",
            )
            for egress_id, quota_group in quota_groups.items()
        }
        if set(normalized_quota_groups) != set(normalized_transports):
            raise ValueError("quota_groups must exactly cover transport egress IDs")
        if set(normalized_websocket_transports) != set(normalized_transports):
            raise ValueError(
                "websocket_transports must exactly cover HTTP transport egress IDs"
            )
        if not callable(getattr(clock, "time_ns", None)):
            raise TypeError("clock must provide time_ns()")
        if (
            type(timeout_seconds) not in {int, float}
            or not isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be finite and positive")
        if (
            type(subscriptions_per_connection) is not int
            or subscriptions_per_connection <= 0
        ):
            raise ValueError("subscriptions_per_connection must be a positive integer")
        self._transports = MappingProxyType(normalized_transports)
        self._websocket_transports = MappingProxyType(normalized_websocket_transports)
        self._quota_groups = MappingProxyType(normalized_quota_groups)
        self._clock = clock
        self._rest_base_url = _base_url(rest_base_url)
        self._websocket_public_url = _websocket_url(
            websocket_public_url,
            endpoint_role="websocket_public_url",
            path="/ws/v5/public",
        )
        self._websocket_business_url = _websocket_url(
            websocket_business_url,
            endpoint_role="websocket_business_url",
            path="/ws/v5/business",
        )
        self._timeout_seconds = float(timeout_seconds)
        self._websocket_timeout_seconds = min(float(timeout_seconds), 25.0)
        self._subscriptions_per_connection = subscriptions_per_connection

    def _now(self, request: ProbeRequest) -> int:
        now = self._clock.time_ns()
        if type(now) is not int or now < request.observed_at_ns or now > 2**63 - 1:
            raise OkxProbeError("probe clock is outside the request observation window")
        return now

    async def _fetch(
        self,
        request: ProbeRequest,
        *,
        egress_id: str,
        path: str,
        params: Mapping[str, PublicQueryValue],
        kind: str,
    ) -> _FetchedPayload:
        started_at_ns = self._now(request)
        response = await self._transports[egress_id].get(
            f"{self._rest_base_url}{path}",
            params=params,
            timeout=self._timeout_seconds,
        )
        observed_at_ns = self._now(request)
        payload = require_okx_success(response)
        return _FetchedPayload(
            payload=payload,
            started_at_ns=started_at_ns,
            observed_at_ns=observed_at_ns,
            raw_reference=_payload_reference(kind, payload),
            status=response.status_code,
        )

    async def _fetch_request(
        self,
        request: ProbeRequest,
        *,
        egress_id: str,
        rest_request: OkxRestRequest,
        kind: str,
    ) -> tuple[_FetchedPayload, OkxRestCapture]:
        fetched = await self._fetch(
            request,
            egress_id=egress_id,
            path=rest_request.path,
            params=rest_request.params,
            kind=kind,
        )
        capture = OkxRestCapture(
            payload=fetched.payload,
            rest_metadata=RestMetadata(
                request_started_at_ns=fetched.started_at_ns,
                request_ended_at_ns=fetched.observed_at_ns,
                method="GET",
                path=rest_request.path,
                params=cast(
                    dict[str, ValidatedJsonPayload],
                    dict(rest_request.params),
                ),
                status=fetched.status,
                attempt=1,
                rate_limit_headers={},
            ),
            source=SourceContext(
                connection_id=None,
                connection_generation=None,
                egress_id=egress_id,
            ),
            request=rest_request,
        )
        return fetched, capture

    async def _reachability(
        self,
        request: ProbeRequest,
        egress_id: str,
    ) -> tuple[TransportReachabilityProbe, int | None]:
        try:
            fetched, capture = await self._fetch_request(
                request,
                egress_id=egress_id,
                rest_request=public_time_request(),
                kind="public-time",
            )
            exchange_time_ns = parse_public_time_ns(capture)
        except Exception as error:  # noqa: BLE001 - one route must not hide others.
            return (
                TransportReachabilityProbe(
                    transport="http",
                    endpoint_role="public_rest",
                    reachable=False,
                    observed_at_ns=self._now(request),
                    raw_reference=_failure_reference("egress-reachability", error),
                ),
                None,
            )
        return (
            TransportReachabilityProbe(
                transport="http",
                endpoint_role="public_rest",
                reachable=True,
                observed_at_ns=fetched.observed_at_ns,
                raw_reference=fetched.raw_reference,
            ),
            exchange_time_ns,
        )

    async def _first_success(
        self,
        request: ProbeRequest,
        *,
        egress_ids: tuple[str, ...],
        rest_request: OkxRestRequest,
        kind: str,
    ) -> _FetchedPayload:
        for egress_id in egress_ids:
            try:
                fetched, _capture = await self._fetch_request(
                    request,
                    egress_id=egress_id,
                    rest_request=rest_request,
                    kind=kind,
                )
            except Exception:  # noqa: BLE001, S112 - bounded route failover.
                continue
            return fetched
        raise OkxProbeError(f"OKX {kind} probe failed on every reachable egress")

    async def _market_evidence(
        self,
        request: ProbeRequest,
        *,
        market: Market,
        egress_ids: tuple[str, ...],
    ) -> tuple[MarketProbeEvidence, CompleteCatalogSnapshot]:
        catalog_response = await self._first_success(
            request,
            egress_ids=egress_ids,
            rest_request=instruments_request(market),
            kind=f"{market.value}-catalog",
        )
        try:
            catalog = parse_instruments(
                catalog_response.payload,
                market,
                observed_at_ns=catalog_response.observed_at_ns,
            )
        except Exception as error:
            raise OkxProbeError(
                f"OKX {market.value} catalog response is invalid"
            ) from error
        ticker_response = await self._first_success(
            request,
            egress_ids=egress_ids,
            rest_request=tickers_request(market),
            kind=f"{market.value}-turnover",
        )
        try:
            turnover = parse_tickers(
                ticker_response.payload,
                market=market,
                catalog=catalog,
                catalog_revision=1,
                observed_at_ns=ticker_response.observed_at_ns,
            )
            view = _catalog_view(catalog, turnover, request=request)
        except Exception as error:
            raise OkxProbeError(
                f"OKX {market.value} turnover response is invalid"
            ) from error
        observed_at_ns = self._now(request)
        available_instrument_subscriptions = (
            self._subscriptions_per_connection - _MARKET_FIXED_SUBSCRIPTIONS[market]
        )
        if available_instrument_subscriptions <= 0:
            raise OkxProbeError(
                "OKX project subscription cap cannot fit market-level channels"
            )
        endpoint_work = [
            EndpointWork(
                _BOOKS_FULL_LOGICAL_ENDPOINT,
                Decimal(1),
                jobs_per_instrument=1,
                depth="max_supported",
                observed_at_ns=observed_at_ns,
                raw_reference=_RATE_LIMIT_REFERENCE,
            ),
            EndpointWork(
                "instruments",
                Decimal(1),
                kind="periodic_reference",
                jobs_per_instrument=0,
                jobs_per_market=1,
                requested_interval_ns=_CATALOG_REFRESH_INTERVAL_NS,
                observed_at_ns=observed_at_ns,
                raw_reference=_RATE_LIMIT_REFERENCE,
            ),
            EndpointWork(
                "candles",
                Decimal(1),
                kind="periodic_reference",
                jobs_per_instrument=1,
                requested_interval_ns=_CANDLE_INTERVAL_NS,
                observed_at_ns=observed_at_ns,
                raw_reference=_RATE_LIMIT_REFERENCE,
            ),
        ]
        if market is Market.PERPETUAL:
            endpoint_work.extend(
                (
                    EndpointWork(
                        "premium-history",
                        Decimal(1),
                        kind="periodic_reference",
                        jobs_per_instrument=1,
                        requested_interval_ns=_REFERENCE_INTERVAL_NS,
                        observed_at_ns=observed_at_ns,
                        raw_reference=_RATE_LIMIT_REFERENCE,
                    ),
                    EndpointWork(
                        "insurance-fund",
                        Decimal(1),
                        kind="periodic_reference",
                        jobs_per_instrument=1,
                        requested_interval_ns=_REFERENCE_INTERVAL_NS,
                        observed_at_ns=observed_at_ns,
                        raw_reference=_RATE_LIMIT_REFERENCE,
                    ),
                )
            )
        return (
            MarketProbeEvidence(
                catalog=view,
                subscriptions_per_connection=available_instrument_subscriptions,
                subscriptions_per_instrument=(
                    _MARKET_SUBSCRIPTIONS_PER_INSTRUMENT[market]
                ),
                endpoint_work=tuple(endpoint_work),
            ),
            catalog,
        )

    @staticmethod
    def _representative_instruments(
        catalogs: Mapping[Market, CompleteCatalogSnapshot],
    ) -> tuple[tuple[Market, InstrumentRecord], ...]:
        representatives: list[tuple[Market, InstrumentRecord]] = []
        for market, catalog in sorted(
            catalogs.items(),
            key=lambda item: item[0].value,
        ):
            instrument = min(
                (item for item in catalog.instruments if item.tradable),
                key=lambda item: item.instrument_key,
                default=None,
            )
            if instrument is None:
                raise OkxProbeError(
                    f"OKX {market.value} catalog has no tradable WebSocket probe symbol"
                )
            representatives.append((market, instrument))
        return tuple(representatives)

    def _ws_subscriptions(
        self,
        *,
        endpoint_role: str,
        egress_id: str,
        representatives: tuple[tuple[Market, InstrumentRecord], ...],
    ) -> tuple[WebSocketSubscription, ...]:
        if endpoint_role == "public":
            endpoint = self._websocket_public_url
            channel = "books"
            logical_stream = "book_live"
        elif endpoint_role == "business":
            endpoint = self._websocket_business_url
            channel = "trades-all"
            logical_stream = "trade"
        else:  # pragma: no cover - only internal constant callers exist.
            raise ValueError("unsupported OKX WebSocket endpoint role")
        return tuple(
            WebSocketSubscription(
                id=f"okx:probe:{endpoint_role}:{market.value}:{instrument.instrument_key}",
                market=market,
                instrument_key=instrument.instrument_key,
                wire_symbol=instrument.wire_symbol("websocket"),
                channel=channel,
                endpoint=endpoint,
                egress_id=egress_id,
                shard_id=f"probe-{endpoint_role}",
                logical_stream=logical_stream,
            )
            for market, instrument in representatives
        )

    async def _websocket_reachability(
        self,
        request: ProbeRequest,
        *,
        egress_id: str,
        endpoint_role: str,
        representatives: tuple[tuple[Market, InstrumentRecord], ...],
    ) -> TransportReachabilityProbe:
        subscriptions = self._ws_subscriptions(
            endpoint_role=endpoint_role,
            egress_id=egress_id,
            representatives=representatives,
        )
        expected_books = {
            (item.market, item.wire_symbol)
            for item in subscriptions
            if item.channel == "books"
        }
        observed_books: set[tuple[Market, str | None]] = set()
        references: list[str] = []
        session = OkxWsSession(
            self._websocket_transports[egress_id],
            subscriptions,
            request_id="probe1" if endpoint_role == "public" else "probe2",
            idle_timeout_seconds=self._websocket_timeout_seconds,
            pong_timeout_seconds=min(self._websocket_timeout_seconds, 5.0),
            subscription_timeout_seconds=self._websocket_timeout_seconds,
        )
        try:
            async with asyncio.timeout(self._websocket_timeout_seconds):
                async with session:
                    while True:
                        event = await session.receive()
                        if event.action is not OkxWsSessionAction.MESSAGE:
                            reason = (
                                "unknown"
                                if event.reconnect_reason is None
                                else event.reconnect_reason.value
                            )
                            raise OkxProbeError(
                                f"OKX {endpoint_role} WebSocket probe requires reconnect: "
                                f"{reason}"
                            )
                        message = event.message
                        if message is None:  # pragma: no cover - session validates.
                            raise OkxProbeError(
                                "OKX WebSocket probe event lacks a message"
                            )
                        if message.kind in {
                            OkxWsMessageKind.SUBSCRIBE_ACK,
                            OkxWsMessageKind.DATA,
                        }:
                            references.append(
                                _payload_reference(
                                    f"websocket-{endpoint_role}-frame",
                                    message.payload,
                                )
                            )
                        if (
                            message.kind is OkxWsMessageKind.DATA
                            and message.channel == "books"
                            and message.payload is not None
                            and message.payload.get("action") == "snapshot"
                            and isinstance(message.payload.get("data"), list)
                            and bool(message.payload["data"])
                        ):
                            matching = next(
                                (
                                    item
                                    for item in subscriptions
                                    if item.channel == "books"
                                    and item.wire_symbol == message.wire_symbol
                                ),
                                None,
                            )
                            if matching is not None:
                                observed_books.add(
                                    (matching.market, matching.wire_symbol)
                                )
                        if session.pending_subscription_count == 0 and (
                            not expected_books or observed_books == expected_books
                        ):
                            observed_at_ns = self._now(request)
                            return TransportReachabilityProbe(
                                transport="websocket",
                                endpoint_role=endpoint_role,
                                reachable=True,
                                observed_at_ns=observed_at_ns,
                                raw_reference=(
                                    f"okx:probe:websocket-{endpoint_role}:sha256:"
                                    + _snapshot_digest(
                                        f"websocket-{endpoint_role}",
                                        tuple(sorted(references)),
                                    )
                                ),
                            )
        except TimeoutError as error:
            raise OkxProbeError(
                f"OKX {endpoint_role} WebSocket probe timed out"
            ) from error

    def _failed_websocket_reachability(
        self,
        request: ProbeRequest,
        *,
        endpoint_role: str,
        kind: str,
        error: BaseException | None = None,
    ) -> TransportReachabilityProbe:
        return TransportReachabilityProbe(
            transport="websocket",
            endpoint_role=endpoint_role,
            reachable=False,
            observed_at_ns=self._now(request),
            raw_reference=_failure_reference(kind, error),
        )

    async def _date_gate(
        self,
        request: ProbeRequest,
        *,
        gate: DateGateRequest,
        catalogs: Mapping[Market, CompleteCatalogSnapshot],
        egress_ids: tuple[str, ...],
    ) -> DateGateProbe:
        feature_id = gate.feature_id
        if feature_id != _BOOKS_RPI_FEATURE:
            return DateGateProbe(
                feature_id=feature_id,
                available=False,
                observed_at_ns=self._now(request),
                raw_reference=_failure_reference(f"feature-{feature_id}"),
            )
        references: list[str] = []
        for market in gate.markets:
            catalog = catalogs.get(market)
            instrument = (
                None
                if catalog is None
                else next(
                    (item for item in catalog.instruments if item.tradable),
                    None,
                )
            )
            if instrument is None:
                return DateGateProbe(
                    feature_id=feature_id,
                    available=False,
                    observed_at_ns=self._now(request),
                    raw_reference=_failure_reference(
                        f"feature-books-rpi-{market.value}-no-tradable-instrument"
                    ),
                )
            wire_symbol = instrument.wire_symbol("rest")
            last_error: Exception | None = None
            for egress_id in egress_ids:
                try:
                    fetched = await self._fetch(
                        request,
                        egress_id=egress_id,
                        path=_BOOKS_RPI_PATH,
                        params={"instId": wire_symbol, "sz": 1},
                        kind=f"feature-books-rpi-{market.value}",
                    )
                    if not _rpi_response_is_compatible(
                        fetched.payload,
                        wire_symbol=wire_symbol,
                    ):
                        raise OkxProbeError(
                            "OKX books-rpi response identity is invalid"
                        )
                except Exception as error:  # noqa: BLE001 - optional route failover.
                    last_error = error
                    continue
                references.append(fetched.raw_reference)
                break
            else:
                return DateGateProbe(
                    feature_id=feature_id,
                    available=False,
                    observed_at_ns=self._now(request),
                    raw_reference=(
                        _failure_reference(
                            f"feature-books-rpi-{market.value}",
                            last_error,
                        )
                        if last_error is not None
                        else _CAPABILITY_REFERENCE
                    ),
                )
        return DateGateProbe(
            feature_id=feature_id,
            available=True,
            observed_at_ns=self._now(request),
            raw_reference=(
                "okx:probe:feature-books-rpi:sha256:"
                + _snapshot_digest(feature_id, tuple(references))
            ),
        )

    async def probe(self, request: ProbeRequest) -> ExchangeProbeEvidence:
        if type(request) is not ProbeRequest:
            raise TypeError("request must be ProbeRequest")
        if request.exchange is not Exchange.OKX:
            raise ValueError("probe request must target OKX")
        if not request.egress_ids:
            raise OkxProbeError("OKX probe requires at least one egress")
        missing = tuple(
            egress_id
            for egress_id in request.egress_ids
            if egress_id not in self._transports
        )
        if missing:
            raise OkxProbeError(
                "OKX probe has no transport for egress IDs: " + ", ".join(missing)
            )

        http_reachability: dict[str, TransportReachabilityProbe] = {}
        exchange_times: list[tuple[str, int]] = []
        for egress_id in request.egress_ids:
            reachability_evidence, exchange_time_ns = await self._reachability(
                request, egress_id
            )
            http_reachability[egress_id] = reachability_evidence
            if exchange_time_ns is not None:
                exchange_times.append((egress_id, exchange_time_ns))
        if not exchange_times:
            raise OkxProbeError(
                "OKX public-time probe failed on every requested egress"
            )
        reachable_ids = tuple(egress_id for egress_id, _time in exchange_times)
        public_egress, exchange_time_ns = exchange_times[0]
        public_time_evidence = http_reachability[public_egress]

        markets: list[MarketProbeEvidence] = []
        catalogs: dict[Market, CompleteCatalogSnapshot] = {}
        for scope in request.markets:
            market_evidence, catalog = await self._market_evidence(
                request,
                market=scope.market,
                egress_ids=reachable_ids,
            )
            markets.append(market_evidence)
            catalogs[scope.market] = catalog

        representatives = self._representative_instruments(catalogs)
        reachability: list[EgressReachabilityProbe] = []
        for egress_id in request.egress_ids:
            http_probe = http_reachability[egress_id]
            websocket_probes: list[TransportReachabilityProbe] = []
            for endpoint_role in ("public", "business"):
                if not http_probe.reachable:
                    websocket_probes.append(
                        self._failed_websocket_reachability(
                            request,
                            endpoint_role=endpoint_role,
                            kind=f"websocket-{endpoint_role}-http-unreachable",
                        )
                    )
                    continue
                try:
                    websocket_probe = await self._websocket_reachability(
                        request,
                        egress_id=egress_id,
                        endpoint_role=endpoint_role,
                        representatives=representatives,
                    )
                except Exception as error:  # noqa: BLE001 - isolate each WS route.
                    websocket_probe = self._failed_websocket_reachability(
                        request,
                        endpoint_role=endpoint_role,
                        kind=f"websocket-{endpoint_role}",
                        error=error,
                    )
                websocket_probes.append(websocket_probe)
            transport_probes = (http_probe, *websocket_probes)
            observed_at_ns = max(item.observed_at_ns for item in transport_probes)
            reachable = all(item.reachable for item in transport_probes)
            reachability.append(
                EgressReachabilityProbe(
                    egress_id=egress_id,
                    reachable=reachable,
                    observed_at_ns=observed_at_ns,
                    raw_reference=(
                        "okx:probe:egress-reachability:sha256:"
                        + _snapshot_digest(
                            egress_id,
                            tuple(item.raw_reference for item in transport_probes),
                        )
                    ),
                    transports=transport_probes,
                )
            )

        reachable_groups = tuple(
            sorted({self._quota_groups[egress_id] for egress_id in reachable_ids})
        )
        budget_observed_at_ns = self._now(request)
        endpoint_budgets = tuple(
            EndpointBudgetProbe(
                quota_group,
                logical_endpoint,
                available_tokens_per_second,
                observed_at_ns=budget_observed_at_ns,
                raw_reference=_RATE_LIMIT_REFERENCE,
            )
            for quota_group in reachable_groups
            for logical_endpoint, available_tokens_per_second in (
                _ENDPOINT_TOKENS_PER_SECOND.items()
            )
        )
        date_gates = tuple(
            [
                await self._date_gate(
                    request,
                    gate=gate,
                    catalogs=catalogs,
                    egress_ids=reachable_ids,
                )
                for gate in request.date_gates
                if gate.requires_live_probe
            ]
        )
        return ExchangeProbeEvidence(
            exchange=Exchange.OKX,
            public_time=PublicTimeProbe(
                exchange_time_ns=exchange_time_ns,
                observed_at_ns=public_time_evidence.observed_at_ns,
                raw_reference=public_time_evidence.raw_reference,
            ),
            egresses=tuple(reachability),
            markets=tuple(markets),
            endpoint_budgets=endpoint_budgets,
            date_gates=date_gates,
        )


__all__ = [
    "DEFAULT_OKX_REST_BASE_URL",
    "DEFAULT_OKX_WEBSOCKET_BUSINESS_URL",
    "DEFAULT_OKX_WEBSOCKET_PUBLIC_URL",
    "OKX_BOOKS_FULL_TOKENS_PER_SECOND",
    "OKX_CANDLES_TOKENS_PER_SECOND",
    "OKX_CONSERVATIVE_SUBSCRIPTIONS_PER_CONNECTION",
    "OKX_INSTRUMENTS_TOKENS_PER_SECOND",
    "OKX_INSURANCE_FUND_TOKENS_PER_SECOND",
    "OKX_PREMIUM_HISTORY_TOKENS_PER_SECOND",
    "OkxProbeError",
    "OkxProbeProvider",
]
