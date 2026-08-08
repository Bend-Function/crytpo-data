from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from urllib.parse import urlsplit

from crypto_collector.capabilities import CapabilityRegistry
from crypto_collector.domain import CoverageMode, Exchange, Market
from crypto_collector.exchanges.contracts import (
    AdapterPlan,
    AdapterRuntime,
    CollectionRequest,
    EventSink,
    RestPlanItem,
    StreamExpectation,
    WebSocketSubscription,
)
from crypto_collector.exchanges.okx.execution import (
    OkxCatalogController,
    fetch_okx_catalog,
    run_okx_plan,
)
from crypto_collector.exchanges.okx.rest import (
    candles_request,
    deep_book_request,
    derivative_reference_request,
    instruments_request,
)
from crypto_collector.scheduler import IntervalPlan, RestBudgetRoute, RestPriority
from crypto_collector.selection import CompleteCatalogSnapshot, InstrumentRecord

_NANOSECONDS_PER_SECOND = 1_000_000_000
_NETWORK_ADMISSION_RELEASE_FAILURE_NOTE = "network admission release also failed"


async def _await_owned_cleanup(
    task: asyncio.Task[None],
) -> asyncio.CancelledError | None:
    cancellation: asyncio.CancelledError | None = None
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as error:
            if cancellation is None:
                cancellation = error
    task.result()
    return cancellation


async def _cancel_and_settle_bootstrap(
    task: asyncio.Task[CompleteCatalogSnapshot],
    cancellation: asyncio.CancelledError,
) -> BaseException | None:
    task.cancel()
    while not task.done():
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError:
            continue
        except BaseException:  # noqa: BLE001 - harvest the owned bootstrap task.
            break
    try:
        await task
    except asyncio.CancelledError as task_cancellation:
        if _NETWORK_ADMISSION_RELEASE_FAILURE_NOTE in getattr(
            task_cancellation, "__notes__", ()
        ):
            cancellation.add_note(_NETWORK_ADMISSION_RELEASE_FAILURE_NOTE)
        return None
    except BaseException as error:  # noqa: BLE001 - preserve the owned outcome.
        error.add_note("OKX catalog bootstrap cancellation also observed")
        return error
    return None


_DEFAULT_DEEP_INTERVAL_NS = 30 * _NANOSECONDS_PER_SECOND
_DEFAULT_CANDLE_INTERVAL_NS = 60 * _NANOSECONDS_PER_SECOND
_DEFAULT_REFERENCE_INTERVAL_NS = 5 * 60 * _NANOSECONDS_PER_SECOND
_DEFAULT_ENDPOINT_COST = Decimal(1)

OKX_COMMON_RESEARCH_STREAMS = frozenset(
    {
        "instrument",
        "status",
        "trade",
        "ticker",
        "bbo",
        "book_live",
        "book_deep_snapshot",
        "candle_1m",
    }
)
OKX_PERPETUAL_RESEARCH_STREAMS = frozenset(
    {
        "mark_price",
        "index_ticker",
        "premium",
        "funding_rate",
        "open_interest",
        "price_limit",
        "insurance_fund",
        "liquidation",
    }
)
OKX_RESEARCH_DEFAULT_STREAMS = (
    OKX_COMMON_RESEARCH_STREAMS | OKX_PERPETUAL_RESEARCH_STREAMS
)

_INSTRUMENT_WS_CHANNELS = MappingProxyType(
    {
        "trade": "trades-all",
        "ticker": "tickers",
        "bbo": "bbo-tbt",
        "mark_price": "mark-price",
        "index_ticker": "index-tickers",
        "funding_rate": "funding-rate",
        "open_interest": "open-interest",
        "price_limit": "price-limit",
    }
)


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _public_endpoint(value: object, *, field: str, scheme: str) -> str:
    endpoint = _nonempty(value, field=field)
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise ValueError(f"{field} must be a valid public endpoint") from error
    if (
        parsed.scheme != scheme
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or "\\" in endpoint
        or "%" in parsed.hostname
        or parsed.netloc.endswith(":")
        or (port is not None and not 1 <= port <= 65_535)
        or any(
            character.isspace()
            or ord(character) < 0x20
            or 0x7F <= ord(character) <= 0x9F
            for character in endpoint
        )
    ):
        raise ValueError(f"{field} must be an anonymous public {scheme} endpoint")
    return endpoint


@dataclass(frozen=True, slots=True)
class OkxPlanRoute:
    egress_id: str
    quota_group: str
    shard_id: str

    def __post_init__(self) -> None:
        for field in ("egress_id", "quota_group", "shard_id"):
            object.__setattr__(
                self,
                field,
                _nonempty(getattr(self, field), field=field),
            )


@dataclass(frozen=True, slots=True)
class OkxEndpoints:
    rest: str
    websocket_public: str
    websocket_business: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "rest",
            _public_endpoint(self.rest, field="rest", scheme="https"),
        )
        for field, path in (
            ("websocket_public", "/ws/v5/public"),
            ("websocket_business", "/ws/v5/business"),
        ):
            endpoint = _public_endpoint(getattr(self, field), field=field, scheme="wss")
            if urlsplit(endpoint).path != path:
                raise ValueError(f"{field} must end at the OKX {path} path")
            object.__setattr__(self, field, endpoint)


RouteKey = tuple[Market, str | None]


class OkxAdapter:
    exchange = Exchange.OKX

    def __init__(
        self,
        *,
        endpoints: OkxEndpoints | None = None,
        routes: Mapping[RouteKey, OkxPlanRoute] | None = None,
        rest_routes: Mapping[Market, tuple[OkxPlanRoute, ...]] | None = None,
        deep_depths: Mapping[RouteKey, int] | None = None,
        capabilities: CapabilityRegistry | None = None,
        disabled_optional_features: tuple[str, ...] = (),
    ) -> None:
        registry = capabilities or CapabilityRegistry.load_builtin()
        self._capabilities = registry
        self._endpoints = endpoints or self._default_endpoints(registry)
        self._uses_default_routes = routes is None
        self._routes = self._normalize_routes(routes)
        self._rest_routes = self._normalize_rest_routes(rest_routes)
        self._egress_quota_groups = self._normalize_egress_quota_groups(
            self._routes,
            self._rest_routes,
            uses_default_routes=self._uses_default_routes,
        )
        self._deep_depths = self._normalize_deep_depths(deep_depths, registry)
        if type(disabled_optional_features) is not tuple or any(
            type(item) is not str or not item for item in disabled_optional_features
        ):
            raise TypeError("disabled_optional_features must be a tuple of strings")
        if len(set(disabled_optional_features)) != len(disabled_optional_features):
            raise ValueError("disabled_optional_features must be unique")
        self._disabled_optional_features = tuple(sorted(disabled_optional_features))
        self._state_lock = asyncio.Lock()
        self._bootstrap_task: asyncio.Task[CompleteCatalogSnapshot] | None = None
        self._active_controller: OkxCatalogController | None = None

    @staticmethod
    def _default_endpoints(registry: CapabilityRegistry) -> OkxEndpoints:
        spot = registry.for_market(Exchange.OKX, Market.SPOT)
        public = next(
            (
                endpoint
                for endpoint in spot.websocket_base_urls
                if endpoint.endswith("/ws/v5/public")
            ),
            None,
        )
        business = next(
            (
                endpoint
                for endpoint in spot.websocket_base_urls
                if endpoint.endswith("/ws/v5/business")
            ),
            None,
        )
        if public is None or business is None:
            raise ValueError("OKX capability record lacks public WebSocket endpoints")
        return OkxEndpoints(
            rest=spot.rest_base_urls[0],
            websocket_public=public,
            websocket_business=business,
        )

    @staticmethod
    def _normalize_routes(
        routes: Mapping[RouteKey, OkxPlanRoute] | None,
    ) -> Mapping[RouteKey, OkxPlanRoute]:
        if routes is None:
            return MappingProxyType({})
        if not isinstance(routes, Mapping):
            raise TypeError("routes must be a mapping")
        normalized: dict[RouteKey, OkxPlanRoute] = {}
        for key, route in routes.items():
            if (
                type(key) is not tuple
                or len(key) != 2
                or type(key[0]) is not Market
                or (key[1] is not None and (type(key[1]) is not str or not key[1]))
            ):
                raise TypeError(
                    "route keys must be (Market, instrument_key | None) tuples"
                )
            if type(route) is not OkxPlanRoute:
                raise TypeError("routes must contain OkxPlanRoute values")
            normalized[key] = route
        return MappingProxyType(normalized)

    @staticmethod
    def _normalize_rest_routes(
        routes: Mapping[Market, tuple[OkxPlanRoute, ...]] | None,
    ) -> Mapping[Market, tuple[OkxPlanRoute, ...]]:
        if routes is None:
            return MappingProxyType({})
        if not isinstance(routes, Mapping):
            raise TypeError("rest_routes must be a mapping")
        normalized: dict[Market, tuple[OkxPlanRoute, ...]] = {}
        for market, candidates in routes.items():
            if type(market) is not Market:
                raise TypeError("rest route keys must be Market values")
            if type(candidates) is not tuple:
                raise TypeError("rest route candidates must be tuples")
            if any(type(candidate) is not OkxPlanRoute for candidate in candidates):
                raise TypeError(
                    "rest route candidates must contain OkxPlanRoute values"
                )
            by_egress: dict[str, OkxPlanRoute] = {}
            for candidate in candidates:
                existing = by_egress.get(candidate.egress_id)
                if (
                    existing is not None
                    and existing.quota_group != candidate.quota_group
                ):
                    raise ValueError(
                        "rest routes contain conflicting candidates for one egress"
                    )
                by_egress.setdefault(candidate.egress_id, candidate)
            normalized[market] = tuple(by_egress.values())
        return MappingProxyType(normalized)

    @staticmethod
    def _normalize_egress_quota_groups(
        routes: Mapping[RouteKey, OkxPlanRoute],
        rest_routes: Mapping[Market, tuple[OkxPlanRoute, ...]],
        *,
        uses_default_routes: bool,
    ) -> Mapping[str, str]:
        configured = [
            *routes.values(),
            *(route for candidates in rest_routes.values() for route in candidates),
        ]
        if uses_default_routes:
            configured.append(OkxAdapter._default_route(Market.SPOT))
        normalized: dict[str, str] = {}
        for route in configured:
            existing = normalized.get(route.egress_id)
            if existing is not None and existing != route.quota_group:
                raise ValueError(
                    f"egress {route.egress_id!r} has conflicting quota groups"
                )
            normalized[route.egress_id] = route.quota_group
        return MappingProxyType(dict(sorted(normalized.items())))

    def _rest_budget_routes(
        self,
        *,
        market: Market,
        primary: OkxPlanRoute,
        logical_endpoint: str,
    ) -> tuple[RestBudgetRoute, ...]:
        ordered: list[OkxPlanRoute] = []
        by_egress: dict[str, OkxPlanRoute] = {}
        for candidate in (primary, *self._rest_routes.get(market, ())):
            existing = by_egress.get(candidate.egress_id)
            if existing is not None:
                if existing.quota_group != candidate.quota_group:
                    raise ValueError(
                        "REST primary and candidate routes conflict for one egress"
                    )
                continue
            by_egress[candidate.egress_id] = candidate
            ordered.append(candidate)
        return tuple(
            RestBudgetRoute(
                candidate.egress_id,
                (Exchange.OKX.value, candidate.quota_group, logical_endpoint),
            )
            for candidate in ordered
        )

    @staticmethod
    def _normalize_deep_depths(
        depths: Mapping[RouteKey, int] | None,
        registry: CapabilityRegistry,
    ) -> Mapping[RouteKey, int]:
        if depths is None:
            return MappingProxyType({})
        if not isinstance(depths, Mapping):
            raise TypeError("deep_depths must be a mapping")
        normalized: dict[RouteKey, int] = {}
        for key, depth in depths.items():
            if (
                type(key) is not tuple
                or len(key) != 2
                or type(key[0]) is not Market
                or (key[1] is not None and (type(key[1]) is not str or not key[1]))
            ):
                raise TypeError(
                    "deep depth keys must be (Market, instrument_key | None) tuples"
                )
            capability_depth = registry.for_market(
                Exchange.OKX, key[0]
            ).live_book.max_rest_depth
            if type(capability_depth) is not int:
                raise ValueError("OKX deep snapshot capability must have finite depth")
            if type(depth) is not int or not 1 <= depth <= capability_depth:
                raise ValueError(
                    "OKX deep depth must be a positive integer no greater than "
                    f"the {capability_depth}-level capability"
                )
            normalized[key] = depth
        return MappingProxyType(normalized)

    def _deep_depth(self, market: Market, instrument_key: str) -> int:
        configured = self._deep_depths.get(
            (market, instrument_key)
        ) or self._deep_depths.get((market, None))
        if configured is not None:
            return configured
        capability_depth = self._capabilities.for_market(
            Exchange.OKX, market
        ).live_book.max_rest_depth
        if type(capability_depth) is not int:
            raise ValueError("OKX deep snapshot capability must have finite depth")
        return capability_depth

    @staticmethod
    def _default_route(market: Market) -> OkxPlanRoute:
        return OkxPlanRoute(
            egress_id="direct",
            quota_group="direct",
            shard_id=f"{market.value}-0",
        )

    def _catalog_route(self, market: Market) -> OkxPlanRoute:
        market_route = self._routes.get((market, None))
        if market_route is not None:
            return market_route
        candidates = tuple(
            sorted(
                (
                    (instrument_key, route)
                    for (route_market, instrument_key), route in self._routes.items()
                    if route_market is market and instrument_key is not None
                ),
                key=lambda item: item[0],
            )
        )
        if candidates:
            return candidates[0][1]
        if self._uses_default_routes:
            return self._default_route(market)
        raise ValueError(f"OKX catalog route is missing for {market.value}")

    def _instrument_route(
        self,
        market: Market,
        instrument_key: str,
    ) -> OkxPlanRoute:
        route = self._routes.get((market, instrument_key)) or self._routes.get(
            (market, None)
        )
        if route is not None:
            return route
        if self._uses_default_routes:
            return self._default_route(market)
        raise ValueError(f"OKX route is missing for {market.value}/{instrument_key}")

    def _market_route(
        self,
        market: Market,
        instruments: tuple[InstrumentRecord, ...],
    ) -> OkxPlanRoute:
        route = self._routes.get((market, None))
        if route is not None:
            return route
        if instruments:
            return self._instrument_route(market, instruments[0].instrument_key)
        if self._uses_default_routes:
            return self._default_route(market)
        raise ValueError(f"OKX market route is missing for {market.value}")

    @staticmethod
    def _interval_plan(
        request: CollectionRequest,
        *,
        market: Market,
        instrument_key: str,
        logical_stream: str,
        logical_endpoint: str,
        default_ns: int,
    ) -> IntervalPlan:
        keys = (
            f"{market.value}/{instrument_key}/{logical_stream}",
            f"{market.value}/{logical_stream}",
            logical_stream,
            logical_endpoint,
        )
        for key in keys:
            interval = request.interval_plans.get(key)
            if interval is not None:
                return interval
        return IntervalPlan(default_ns, default_ns, None)

    def _ws_item(
        self,
        *,
        market: Market,
        instrument: InstrumentRecord,
        route: OkxPlanRoute,
        logical_stream: str,
        channel: str,
        wire_symbol: str | None = None,
    ) -> WebSocketSubscription:
        endpoint = (
            self._endpoints.websocket_business
            if channel == "trades-all"
            else self._endpoints.websocket_public
        )
        return WebSocketSubscription(
            id=(f"okx:{market.value}:{instrument.instrument_key}:{logical_stream}:ws"),
            market=market,
            instrument_key=instrument.instrument_key,
            wire_symbol=wire_symbol or instrument.wire_symbol("websocket"),
            channel=channel,
            endpoint=endpoint,
            egress_id=route.egress_id,
            quota_group=route.quota_group,
            shard_id=route.shard_id,
            logical_stream=logical_stream,
        )

    def _rest_item(
        self,
        *,
        request: CollectionRequest,
        market: Market,
        instrument: InstrumentRecord,
        route: OkxPlanRoute,
        logical_stream: str,
    ) -> RestPlanItem:
        if logical_stream == "book_deep_snapshot":
            depth = self._deep_depth(market, instrument.instrument_key)
            native = deep_book_request(instrument, depth=depth)
            logical_endpoint = "books-full"
            priority = RestPriority.DEEP_SNAPSHOT
            default_interval_ns = _DEFAULT_DEEP_INTERVAL_NS
        elif logical_stream == "candle_1m":
            native = candles_request(instrument, bar="1m", limit=2)
            logical_endpoint = "candles"
            priority = RestPriority.REFERENCE_DATA
            default_interval_ns = _DEFAULT_CANDLE_INTERVAL_NS
        elif logical_stream in {"premium", "insurance_fund"}:
            native = derivative_reference_request(logical_stream, instrument)
            logical_endpoint = native.path.rsplit("/", 1)[-1]
            priority = RestPriority.REFERENCE_DATA
            default_interval_ns = _DEFAULT_REFERENCE_INTERVAL_NS
        else:  # pragma: no cover - guarded by the planner's static dispatch.
            raise ValueError(f"unsupported OKX REST stream: {logical_stream}")
        interval = self._interval_plan(
            request,
            market=market,
            instrument_key=instrument.instrument_key,
            logical_stream=logical_stream,
            logical_endpoint=logical_endpoint,
            default_ns=default_interval_ns,
        )
        routes = self._rest_budget_routes(
            market=market,
            primary=route,
            logical_endpoint=logical_endpoint,
        )
        return RestPlanItem(
            id=(
                f"okx:{market.value}:{instrument.instrument_key}:{logical_stream}:rest"
            ),
            exchange=Exchange.OKX,
            market=market,
            instrument_key=instrument.instrument_key,
            wire_symbol=instrument.wire_symbol("rest"),
            endpoint=self._endpoints.rest,
            path=native.path,
            params=native.params,
            egress_id=route.egress_id,
            shard_id=route.shard_id,
            logical_stream=logical_stream,
            quota_group=route.quota_group,
            logical_endpoint=logical_endpoint,
            priority=priority,
            endpoint_cost=_DEFAULT_ENDPOINT_COST,
            interval_plan=interval,
            requires_generation=False,
            replaceable=True,
            routes=routes,
        )

    @staticmethod
    def _expectation(
        *,
        market: Market,
        instrument_key: str | None,
        logical_stream: str,
        shard_id: str,
    ) -> StreamExpectation:
        coverage = (
            CoverageMode.LOSSY_WINDOW
            if logical_stream == "liquidation"
            else CoverageMode.UNKNOWN
            if logical_stream == "status"
            else CoverageMode.COMPLETE
        )
        return StreamExpectation(
            market=market,
            instrument_key=instrument_key,
            logical_stream=logical_stream,
            shard_id=shard_id,
            coverage=coverage,
        )

    def plan(self, request: CollectionRequest) -> AdapterPlan:
        if type(request) is not CollectionRequest:
            raise TypeError("request must be CollectionRequest")
        if request.exchange is not Exchange.OKX:
            raise ValueError("OKX adapter requires an OKX collection request")

        plan_instruments = tuple(
            instrument
            for market in sorted(request.selected, key=lambda item: item.value)
            for instrument in sorted(
                request.selected[market],
                key=lambda item: item.instrument_key,
            )
        )
        ws: list[WebSocketSubscription] = []
        rest: list[RestPlanItem] = []
        catalog: list[RestPlanItem] = []
        expectations: list[StreamExpectation] = [
            StreamExpectation(
                market=None,
                instrument_key=None,
                logical_stream="_control",
                shard_id="_control",
            )
        ]
        for market in sorted(request.enabled_streams, key=lambda item: item.value):
            streams = request.enabled_streams[market]
            allowed = OKX_COMMON_RESEARCH_STREAMS
            if market is Market.PERPETUAL:
                allowed = allowed | OKX_PERPETUAL_RESEARCH_STREAMS
            unsupported = sorted(streams - allowed)
            if unsupported:
                detail = ", ".join(unsupported)
                raise ValueError(f"unsupported OKX {market.value} stream(s): {detail}")
            if not streams:
                continue
            instruments = tuple(
                sorted(
                    request.selected[market],
                    key=lambda item: item.instrument_key,
                )
            )
            market_route = self._market_route(market, instruments)
            if "instrument" in streams:
                catalog.append(self._catalog_item(market, route=market_route))
            inst_type = "SPOT" if market is Market.SPOT else "SWAP"
            market_subscriptions = [
                ("instrument", "instruments", {"instType": inst_type}),
                ("status", "status", {}),
            ]
            if market is Market.PERPETUAL:
                market_subscriptions.append(
                    ("liquidation", "liquidation-orders", {"instType": "SWAP"})
                )
            market_stream_ids = {
                logical_stream for logical_stream, _, _ in market_subscriptions
            }
            for logical_stream, channel, params in market_subscriptions:
                if logical_stream not in streams:
                    continue
                ws.append(
                    WebSocketSubscription(
                        id=f"okx:{market.value}:_market:{logical_stream}:ws",
                        market=market,
                        instrument_key=None,
                        wire_symbol=None,
                        channel=channel,
                        endpoint=self._endpoints.websocket_public,
                        egress_id=market_route.egress_id,
                        quota_group=market_route.quota_group,
                        shard_id=market_route.shard_id,
                        logical_stream=logical_stream,
                        params=params,
                    )
                )
                expectations.append(
                    self._expectation(
                        market=market,
                        instrument_key=None,
                        logical_stream=logical_stream,
                        shard_id=market_route.shard_id,
                    )
                )

            capability = self._capabilities.for_market(Exchange.OKX, market)
            for instrument in instruments:
                route = self._instrument_route(market, instrument.instrument_key)
                for logical_stream in sorted(streams - market_stream_ids):
                    if logical_stream in {
                        "book_deep_snapshot",
                        "candle_1m",
                        "premium",
                        "insurance_fund",
                    }:
                        rest.append(
                            self._rest_item(
                                request=request,
                                market=market,
                                instrument=instrument,
                                route=route,
                                logical_stream=logical_stream,
                            )
                        )
                    else:
                        channel = (
                            capability.live_book.channel
                            if logical_stream == "book_live"
                            else _INSTRUMENT_WS_CHANNELS[logical_stream]
                        )
                        wire_symbol = (
                            instrument.wire_symbol("index")
                            if logical_stream == "index_ticker"
                            else None
                        )
                        ws.append(
                            self._ws_item(
                                market=market,
                                instrument=instrument,
                                route=route,
                                logical_stream=logical_stream,
                                channel=channel,
                                wire_symbol=wire_symbol,
                            )
                        )
                    expectations.append(
                        self._expectation(
                            market=market,
                            instrument_key=instrument.instrument_key,
                            logical_stream=logical_stream,
                            shard_id=route.shard_id,
                        )
                    )

        return AdapterPlan(
            exchange=Exchange.OKX,
            ws=tuple(ws),
            rest=tuple(rest),
            expectations=tuple(expectations),
            disabled_optional_features=self._disabled_optional_features,
            catalog=tuple(catalog),
            instruments=plan_instruments,
            egress_quota_groups=self._egress_quota_groups,
        )

    async def fetch_catalog(
        self,
        runtime: AdapterRuntime,
        market: Market,
    ) -> CompleteCatalogSnapshot:
        if type(market) is not Market:
            raise TypeError("market must be Market")
        async with self._state_lock:
            controller = self._active_controller
            if controller is not None:
                if not controller.owns_runtime(runtime):
                    raise RuntimeError(
                        "active OKX catalog refresh requires the run runtime"
                    )
                bootstrap = None
            else:
                if self._bootstrap_task is not None:
                    raise RuntimeError("OKX catalog bootstrap is already active")
                runtime.ensure_run_not_claimed()
                item = self._catalog_item(market)
                bootstrap_coroutine = fetch_okx_catalog(
                    runtime=runtime,
                    market=market,
                    item=item,
                )
                try:
                    bootstrap = asyncio.create_task(bootstrap_coroutine)
                except BaseException:
                    bootstrap_coroutine.close()
                    raise
                self._bootstrap_task = bootstrap
        if controller is not None:
            return await controller.request(market)
        assert bootstrap is not None
        result: CompleteCatalogSnapshot | None = None
        body_error: BaseException | None = None
        try:
            result = await asyncio.shield(bootstrap)
        except BaseException as error:  # noqa: BLE001 - preserve bootstrap outcome.
            body_error = error
            runtime.poison()
            if isinstance(error, asyncio.CancelledError) and not bootstrap.done():
                cleanup_error = await _cancel_and_settle_bootstrap(bootstrap, error)
                if cleanup_error is not None:
                    body_error = cleanup_error
        finally:
            if bootstrap.done():
                if self._bootstrap_task is bootstrap:
                    self._bootstrap_task = None
            else:
                bootstrap.add_done_callback(self._bootstrap_finished)
        if body_error is not None:
            if isinstance(body_error, asyncio.CancelledError):
                body_error.__cause__ = None
                body_error.__context__ = None
                body_error.__suppress_context__ = True
                body_error.__traceback__ = None
            raise body_error
        assert result is not None
        return result

    def _bootstrap_finished(
        self,
        task: asyncio.Task[CompleteCatalogSnapshot],
    ) -> None:
        try:
            task.exception()
        except asyncio.CancelledError:
            pass

        if self._bootstrap_task is task:
            self._bootstrap_task = None

    def _catalog_item(
        self,
        market: Market,
        *,
        route: OkxPlanRoute | None = None,
    ) -> RestPlanItem:
        route = self._catalog_route(market) if route is None else route
        native = instruments_request(market)
        routes = self._rest_budget_routes(
            market=market,
            primary=route,
            logical_endpoint="instruments",
        )
        return RestPlanItem(
            id=f"okx:{market.value}:_market:instrument:catalog",
            exchange=Exchange.OKX,
            market=market,
            instrument_key=None,
            wire_symbol=None,
            endpoint=self._endpoints.rest,
            path=native.path,
            params=native.params,
            egress_id=route.egress_id,
            shard_id=route.shard_id,
            logical_stream="instrument",
            quota_group=route.quota_group,
            logical_endpoint="instruments",
            priority=RestPriority.CATALOG_STATUS_TIME,
            endpoint_cost=_DEFAULT_ENDPOINT_COST,
            interval_plan=None,
            requires_generation=False,
            replaceable=False,
            routes=routes,
        )

    async def run(
        self,
        plan: AdapterPlan,
        runtime: AdapterRuntime,
        sink: EventSink,
    ) -> None:
        controller = OkxCatalogController(plan=plan, runtime=runtime, sink=sink)
        async with self._state_lock:
            if self._bootstrap_task is not None:
                raise RuntimeError("OKX catalog bootstrap is already active")
            if self._active_controller is not None:
                raise RuntimeError("OKX adapter execution is already active")
            runtime.claim_run()
            self._active_controller = controller
        try:
            await run_okx_plan(
                plan,
                runtime,
                sink,
                catalog_controller=controller,
            )
        finally:
            try:
                await controller.close()
            finally:
                if self._active_controller is controller:
                    self._active_controller = None


__all__ = [
    "OKX_COMMON_RESEARCH_STREAMS",
    "OKX_PERPETUAL_RESEARCH_STREAMS",
    "OKX_RESEARCH_DEFAULT_STREAMS",
    "OkxAdapter",
    "OkxEndpoints",
    "OkxPlanRoute",
]
