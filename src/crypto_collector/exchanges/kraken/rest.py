from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import cast

import httpx

from crypto_collector.domain import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    NativeEventDraft,
    RestMetadata,
    SourceContext,
    Transport,
)
from crypto_collector.domain.json_codec import JsonPayload, ValidatedJsonPayload
from crypto_collector.exchanges.contracts import PublicQueryValue
from crypto_collector.exchanges.kraken.errors import (
    KrakenApi,
    KrakenPayloadError,
    inspect_kraken_response,
)
from crypto_collector.observability.redaction import SENSITIVE_QUERY_NAMES
from crypto_collector.scheduler import RestDispatch
from crypto_collector.selection import InstrumentRecord

SPOT_PAIRS_PATH = "/0/public/AssetPairs"
SPOT_TICKER_PATH = "/0/public/Ticker"
SPOT_TRADES_PATH = "/0/public/Trades"
SPOT_OHLC_PATH = "/0/public/OHLC"
SPOT_DEPTH_PATH = "/0/public/Depth"
SPOT_STATUS_PATH = "/0/public/SystemStatus"

FUTURES_INSTRUMENTS_PATH = "/derivatives/api/v3/instruments"
FUTURES_STATUS_PATH = "/derivatives/api/v3/instruments/status"
FUTURES_TICKERS_PATH = "/derivatives/api/v3/tickers"
FUTURES_HISTORY_PATH = "/derivatives/api/v3/history"
FUTURES_ORDERBOOK_PATH = "/derivatives/api/v3/orderbook"
FUTURES_FUNDING_PATH = "/derivatives/api/v3/historical-funding-rates"

_RATE_HEADER_NAMES = frozenset(
    {"retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"}
)
_SYMBOL = re.compile(r"^[A-Za-z0-9_./:-]+$")
_CHARTS_CANDLE = re.compile(
    r"^/api/charts/v1/(spot|mark|trade)/([A-Z0-9_]+)/"
    r"(1m|5m|15m|30m|1h|4h|12h|1d|1w)$"
)
_CHARTS_ANALYTICS = re.compile(r"^/api/charts/v1/analytics/([A-Z0-9_]+)/([a-z-]+)$")
_ANALYTICS_TYPES = frozenset(
    {
        "open-interest",
        "aggressor-differential",
        "trade-volume",
        "trade-count",
        "liquidation-volume",
        "rolling-volatility",
        "long-short-ratio",
        "long-short-info",
        "cvd",
        "top-traders",
        "orderbook",
        "spreads",
        "liquidity",
        "slippage",
        "future-basis",
        "funding",
    }
)
_CHART_INTERVALS = frozenset({60, 300, 900, 1800, 3600, 14400, 43200, 86400, 604800})
_SPOT_OHLC_INTERVALS = frozenset({1, 5, 15, 30, 60, 240, 1440, 10080, 21600})
_EXACT_SCHEMAS: Mapping[
    tuple[KrakenApi, str],
    tuple[frozenset[str], frozenset[str]],
] = MappingProxyType(
    {
        (KrakenApi.SPOT, SPOT_PAIRS_PATH): (frozenset(), frozenset()),
        (KrakenApi.SPOT, SPOT_TICKER_PATH): (frozenset(), frozenset({"pair"})),
        (KrakenApi.SPOT, SPOT_TRADES_PATH): (
            frozenset({"pair"}),
            frozenset({"pair", "since", "count"}),
        ),
        (KrakenApi.SPOT, SPOT_OHLC_PATH): (
            frozenset({"pair"}),
            frozenset({"pair", "interval", "since"}),
        ),
        (KrakenApi.SPOT, SPOT_DEPTH_PATH): (
            frozenset({"pair"}),
            frozenset({"pair", "count"}),
        ),
        (KrakenApi.SPOT, SPOT_STATUS_PATH): (frozenset(), frozenset()),
        (KrakenApi.FUTURES, FUTURES_INSTRUMENTS_PATH): (frozenset(), frozenset()),
        (KrakenApi.FUTURES, FUTURES_STATUS_PATH): (frozenset(), frozenset()),
        (KrakenApi.FUTURES, FUTURES_TICKERS_PATH): (frozenset(), frozenset({"symbol"})),
        (KrakenApi.FUTURES, FUTURES_HISTORY_PATH): (
            frozenset({"symbol"}),
            frozenset({"symbol", "lastTime"}),
        ),
        (KrakenApi.FUTURES, FUTURES_ORDERBOOK_PATH): (
            frozenset({"symbol"}),
            frozenset({"symbol"}),
        ),
        (KrakenApi.FUTURES, FUTURES_FUNDING_PATH): (
            frozenset({"symbol"}),
            frozenset({"symbol"}),
        ),
    }
)


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _params(value: Mapping[str, PublicQueryValue]) -> Mapping[str, PublicQueryValue]:
    normalized: dict[str, PublicQueryValue] = {}
    for key, item in value.items():
        name = _nonempty(key, field="query parameter name")
        if name.casefold() in SENSITIVE_QUERY_NAMES:
            raise ValueError("sensitive query parameters are not permitted")
        if type(item) not in {str, int, bool} and item is not None:
            raise TypeError(
                "Kraken public query parameters must be exact scalar values"
            )
        normalized[name] = item
    return MappingProxyType(normalized)


def _string_param(params: Mapping[str, PublicQueryValue], name: str) -> str:
    value = _nonempty(params[name], field=f"{name} query parameter")
    if not _SYMBOL.fullmatch(value):
        raise ValueError(f"unsupported characters in Kraken {name} query parameter")
    return value


def _integer_param(
    params: Mapping[str, PublicQueryValue],
    name: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    value = params[name]
    if type(value) is int:
        parsed = value
    elif type(value) is str and value.isascii() and value.isdigit():
        parsed = int(value)
    else:
        raise ValueError(f"Kraken {name} must be a decimal integer")
    if parsed < minimum or (maximum is not None and parsed > maximum):
        raise ValueError(f"Kraken {name} is outside its evidenced range")
    return parsed


def _validate_request(
    api: KrakenApi,
    path: str,
    params: Mapping[str, PublicQueryValue],
) -> None:
    schema = _EXACT_SCHEMAS.get((api, path))
    if schema is None:
        candle_match = _CHARTS_CANDLE.fullmatch(path)
        analytics_match = _CHARTS_ANALYTICS.fullmatch(path)
        if api is not KrakenApi.CHARTS or (
            candle_match is None and analytics_match is None
        ):
            raise ValueError("path is not an evidenced Kraken anonymous REST endpoint")
        if candle_match is not None:
            if set(params) - {"from", "to"}:
                raise ValueError("unsupported Kraken Charts candle parameter")
            for name in params:
                _integer_param(params, name, minimum=0)
            return
        assert analytics_match is not None
        if analytics_match.group(2) not in _ANALYTICS_TYPES:
            raise ValueError("unsupported Kraken analytics type")
        if not {"since", "interval"}.issubset(params) or set(params) - {
            "since",
            "interval",
            "to",
        }:
            raise ValueError("Kraken analytics requires since and interval only")
        _integer_param(params, "since", minimum=0)
        if _integer_param(params, "interval", minimum=1) not in _CHART_INTERVALS:
            raise ValueError("unsupported Kraken analytics interval")
        if "to" in params:
            _integer_param(params, "to", minimum=0)
        return
    required, allowed = schema
    names = frozenset(params)
    if names - allowed:
        raise ValueError("unsupported Kraken query parameter")
    if required - names:
        raise ValueError("missing required Kraken query parameter")
    for name in {"pair", "symbol", "lastTime"} & names:
        _string_param(params, name)
    if path == SPOT_DEPTH_PATH and "count" in params:
        _integer_param(params, "count", minimum=1, maximum=500)
    if path == SPOT_TRADES_PATH:
        if "count" in params:
            _integer_param(params, "count", minimum=1, maximum=1000)
        if "since" in params:
            _integer_param(params, "since", minimum=0)
    if path == SPOT_OHLC_PATH:
        interval = (
            _integer_param(params, "interval", minimum=1) if "interval" in params else 1
        )
        if interval not in _SPOT_OHLC_INTERVALS:
            raise ValueError("unsupported Kraken Spot OHLC interval")
        if "since" in params:
            _integer_param(params, "since", minimum=0)


def _expected_logical_stream(
    api: KrakenApi,
    path: str,
    params: Mapping[str, PublicQueryValue],
) -> str:
    fixed = {
        (KrakenApi.SPOT, SPOT_PAIRS_PATH): "instrument",
        (KrakenApi.SPOT, SPOT_TICKER_PATH): "ticker",
        (KrakenApi.SPOT, SPOT_TRADES_PATH): "trade",
        (KrakenApi.SPOT, SPOT_DEPTH_PATH): "book_deep_snapshot",
        (KrakenApi.SPOT, SPOT_STATUS_PATH): "status",
        (KrakenApi.FUTURES, FUTURES_INSTRUMENTS_PATH): "instrument",
        (KrakenApi.FUTURES, FUTURES_STATUS_PATH): "status",
        (KrakenApi.FUTURES, FUTURES_TICKERS_PATH): "ticker",
        (KrakenApi.FUTURES, FUTURES_HISTORY_PATH): "trade",
        (KrakenApi.FUTURES, FUTURES_ORDERBOOK_PATH): "book_deep_snapshot",
        (KrakenApi.FUTURES, FUTURES_FUNDING_PATH): "funding_rate_history",
    }.get((api, path))
    if fixed is not None:
        return fixed
    if api is KrakenApi.SPOT and path == SPOT_OHLC_PATH:
        return f"candle_{params.get('interval', 1)}m"
    candle_match = _CHARTS_CANDLE.fullmatch(path)
    if api is KrakenApi.CHARTS and candle_match is not None:
        return f"candle_{candle_match.group(1)}_{candle_match.group(3)}"
    analytics_match = _CHARTS_ANALYTICS.fullmatch(path)
    if api is KrakenApi.CHARTS and analytics_match is not None:
        return f"analytics_{analytics_match.group(2).replace('-', '_')}"
    raise ValueError("Kraken request has no logical stream mapping")


def _scoped_wire_symbol(
    api: KrakenApi,
    path: str,
    params: Mapping[str, PublicQueryValue],
) -> str | None:
    if api is KrakenApi.SPOT and path in {
        SPOT_TICKER_PATH,
        SPOT_TRADES_PATH,
        SPOT_OHLC_PATH,
        SPOT_DEPTH_PATH,
    }:
        value = params.get("pair")
        return value if type(value) is str else None
    if api is KrakenApi.FUTURES and path in {
        FUTURES_TICKERS_PATH,
        FUTURES_HISTORY_PATH,
        FUTURES_ORDERBOOK_PATH,
        FUTURES_FUNDING_PATH,
    }:
        value = params.get("symbol")
        return value if type(value) is str else None
    candle_match = _CHARTS_CANDLE.fullmatch(path)
    if api is KrakenApi.CHARTS and candle_match is not None:
        return candle_match.group(2)
    analytics_match = _CHARTS_ANALYTICS.fullmatch(path)
    if api is KrakenApi.CHARTS and analytics_match is not None:
        return analytics_match.group(1)
    return None


@dataclass(frozen=True, slots=True)
class KrakenRestRequest:
    api: KrakenApi
    path: str
    params: Mapping[str, PublicQueryValue]
    logical_stream: str
    instrument_key: str | None = None

    def __post_init__(self) -> None:
        if type(self.api) is not KrakenApi:
            raise TypeError("api must be KrakenApi")
        path = _nonempty(self.path, field="path")
        params = _params(self.params)
        _validate_request(self.api, path, params)
        logical_stream = _nonempty(self.logical_stream, field="logical_stream")
        if logical_stream != _expected_logical_stream(self.api, path, params):
            raise ValueError("logical_stream does not match Kraken request path")
        wire_symbol = _scoped_wire_symbol(self.api, path, params)
        if wire_symbol is None:
            if self.instrument_key is not None:
                raise ValueError("market-wide Kraken request cannot bind an instrument")
        else:
            instrument_key = _nonempty(self.instrument_key, field="instrument_key")
            expected_wire = (
                instrument_key.replace("/", "")
                if self.api is KrakenApi.SPOT
                else instrument_key
            )
            if wire_symbol != expected_wire:
                raise ValueError(
                    "Kraken request wire symbol does not match instrument_key"
                )
        object.__setattr__(self, "params", params)
        object.__setattr__(self, "logical_stream", logical_stream)


@dataclass(frozen=True, slots=True)
class KrakenRestCapture:
    payload: Mapping[str, JsonPayload]
    rest_metadata: RestMetadata
    source: SourceContext
    request: KrakenRestRequest

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping) or any(
            type(key) is not str for key in self.payload
        ):
            raise TypeError("payload must be a string-keyed mapping")
        if type(self.rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(self.source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if type(self.request) is not KrakenRestRequest:
            raise TypeError("request must be KrakenRestRequest")
        if (
            self.rest_metadata.method != "GET"
            or not 200 <= self.rest_metadata.status < 300
        ):
            raise ValueError("Kraken public success capture requires GET and HTTP 2xx")
        if (
            self.rest_metadata.path != self.request.path
            or self.rest_metadata.params != dict(self.request.params)
        ):
            raise ValueError("REST metadata does not match the Kraken request")
        self.source.validate_for(
            transport=Transport.REST, logical_stream=self.request.logical_stream
        )
        if self.request.api is KrakenApi.SPOT and (
            self.payload.get("error") != [] or "result" not in self.payload
        ):
            raise ValueError(
                "Kraken Spot capture requires a successful business envelope"
            )
        if (
            self.request.api is KrakenApi.FUTURES
            and self.payload.get("result") != "success"
        ):
            raise ValueError(
                "Kraken Futures capture requires a successful business envelope"
            )
        if self.request.api is KrakenApi.CHARTS:
            errors = self.payload.get("errors")
            singular = self.payload.get("error")
            if (
                (errors is not None and errors != [])
                or (type(singular) is str and bool(singular))
                or self.payload.get("result") == "error"
            ):
                raise ValueError(
                    "Kraken Charts capture requires a successful business envelope"
                )
            candle_match = _CHARTS_CANDLE.fullmatch(self.request.path)
            analytics_match = _CHARTS_ANALYTICS.fullmatch(self.request.path)
            if candle_match is not None:
                _array(self.payload.get("candles"), field="Kraken Charts candles")
                if type(self.payload.get("more_candles")) is not bool:
                    raise KrakenPayloadError(
                        "Kraken Charts candles require more_candles boolean"
                    )
            elif analytics_match is not None:
                if errors != []:
                    raise KrakenPayloadError(
                        "Kraken Charts analytics success requires an empty errors array"
                    )
                result = _mapping(
                    self.payload.get("result"),
                    field="Kraken Charts analytics result",
                )
                _array(result.get("timestamp"), field="analytics timestamp")
                data = result.get("data")
                if not isinstance(data, Mapping):
                    _array(data, field="analytics data")
                if type(result.get("more")) is not bool:
                    raise KrakenPayloadError(
                        "Kraken Charts analytics result requires more boolean"
                    )
            else:  # pragma: no cover - KrakenRestRequest already validates this.
                raise ValueError("Kraken Charts capture has an unsupported path")


def _kraken_instrument(
    instrument: InstrumentRecord, *, market: Market | None = None
) -> None:
    if not isinstance(instrument, InstrumentRecord):
        raise TypeError("instrument must be InstrumentRecord")
    if instrument.exchange is not Exchange.KRAKEN:
        raise ValueError("instrument must belong to Kraken")
    if market is not None and instrument.market is not market:
        raise ValueError("instrument does not belong to required Kraken market")


def spot_pairs_request() -> KrakenRestRequest:
    return KrakenRestRequest(KrakenApi.SPOT, SPOT_PAIRS_PATH, {}, "instrument")


def spot_tickers_request(
    instrument: InstrumentRecord | None = None,
) -> KrakenRestRequest:
    if instrument is None:
        params: Mapping[str, PublicQueryValue] = {}
    else:
        _kraken_instrument(instrument, market=Market.SPOT)
        params = {"pair": instrument.wire_symbol("rest_query")}
    return KrakenRestRequest(
        KrakenApi.SPOT,
        SPOT_TICKER_PATH,
        params,
        "ticker",
        None if instrument is None else instrument.instrument_key,
    )


def spot_trades_request(
    instrument: InstrumentRecord,
    *,
    since: int | None = None,
    count: int | None = None,
) -> KrakenRestRequest:
    _kraken_instrument(instrument, market=Market.SPOT)
    params: dict[str, PublicQueryValue] = {"pair": instrument.wire_symbol("rest_query")}
    if since is not None:
        params["since"] = since
    if count is not None:
        params["count"] = count
    return KrakenRestRequest(
        KrakenApi.SPOT,
        SPOT_TRADES_PATH,
        params,
        "trade",
        instrument.instrument_key,
    )


def spot_ohlc_request(
    instrument: InstrumentRecord,
    *,
    interval: int = 1,
    since: int | None = None,
) -> KrakenRestRequest:
    _kraken_instrument(instrument, market=Market.SPOT)
    params: dict[str, PublicQueryValue] = {
        "pair": instrument.wire_symbol("rest_query"),
        "interval": interval,
    }
    if since is not None:
        params["since"] = since
    return KrakenRestRequest(
        KrakenApi.SPOT,
        SPOT_OHLC_PATH,
        params,
        f"candle_{interval}m",
        instrument.instrument_key,
    )


def spot_depth_request(
    instrument: InstrumentRecord, *, count: int = 500
) -> KrakenRestRequest:
    _kraken_instrument(instrument, market=Market.SPOT)
    return KrakenRestRequest(
        KrakenApi.SPOT,
        SPOT_DEPTH_PATH,
        {"pair": instrument.wire_symbol("rest_query"), "count": count},
        "book_deep_snapshot",
        instrument.instrument_key,
    )


def spot_status_request() -> KrakenRestRequest:
    return KrakenRestRequest(KrakenApi.SPOT, SPOT_STATUS_PATH, {}, "status")


def futures_instruments_request() -> KrakenRestRequest:
    return KrakenRestRequest(
        KrakenApi.FUTURES, FUTURES_INSTRUMENTS_PATH, {}, "instrument"
    )


def futures_status_request() -> KrakenRestRequest:
    return KrakenRestRequest(
        KrakenApi.FUTURES,
        FUTURES_STATUS_PATH,
        {},
        "status",
    )


def futures_tickers_request(
    instrument: InstrumentRecord | None = None,
) -> KrakenRestRequest:
    if instrument is None:
        params: Mapping[str, PublicQueryValue] = {}
    else:
        _kraken_instrument(instrument, market=Market.PERPETUAL)
        params = {"symbol": instrument.wire_symbol("rest")}
    return KrakenRestRequest(
        KrakenApi.FUTURES,
        FUTURES_TICKERS_PATH,
        params,
        "ticker",
        None if instrument is None else instrument.instrument_key,
    )


def futures_history_request(
    instrument: InstrumentRecord,
    *,
    last_time: str | None = None,
) -> KrakenRestRequest:
    _kraken_instrument(instrument, market=Market.PERPETUAL)
    params: dict[str, PublicQueryValue] = {"symbol": instrument.wire_symbol("rest")}
    if last_time is not None:
        params["lastTime"] = last_time
    return KrakenRestRequest(
        KrakenApi.FUTURES,
        FUTURES_HISTORY_PATH,
        params,
        "trade",
        instrument.instrument_key,
    )


def futures_orderbook_request(instrument: InstrumentRecord) -> KrakenRestRequest:
    _kraken_instrument(instrument, market=Market.PERPETUAL)
    return KrakenRestRequest(
        KrakenApi.FUTURES,
        FUTURES_ORDERBOOK_PATH,
        {"symbol": instrument.wire_symbol("rest")},
        "book_deep_snapshot",
        instrument.instrument_key,
    )


def futures_funding_request(instrument: InstrumentRecord) -> KrakenRestRequest:
    _kraken_instrument(instrument, market=Market.PERPETUAL)
    return KrakenRestRequest(
        KrakenApi.FUTURES,
        FUTURES_FUNDING_PATH,
        {"symbol": instrument.wire_symbol("rest")},
        "funding_rate_history",
        instrument.instrument_key,
    )


def futures_candles_request(
    instrument: InstrumentRecord,
    *,
    tick_type: str = "trade",
    resolution: str = "1m",
    from_time: int | None = None,
    to_time: int | None = None,
) -> KrakenRestRequest:
    _kraken_instrument(instrument, market=Market.PERPETUAL)
    symbol = instrument.wire_symbol("charts")
    path = f"/api/charts/v1/{tick_type}/{symbol}/{resolution}"
    params: dict[str, PublicQueryValue] = {}
    if from_time is not None:
        params["from"] = from_time
    if to_time is not None:
        params["to"] = to_time
    return KrakenRestRequest(
        KrakenApi.CHARTS,
        path,
        params,
        f"candle_{tick_type}_{resolution}",
        instrument.instrument_key,
    )


def futures_analytics_request(
    instrument: InstrumentRecord,
    *,
    analytics_type: str,
    since: int,
    interval: int,
    to_time: int | None = None,
) -> KrakenRestRequest:
    _kraken_instrument(instrument, market=Market.PERPETUAL)
    path = (
        f"/api/charts/v1/analytics/{instrument.wire_symbol('charts')}/{analytics_type}"
    )
    params: dict[str, PublicQueryValue] = {"since": since, "interval": interval}
    if to_time is not None:
        params["to"] = to_time
    return KrakenRestRequest(
        KrakenApi.CHARTS,
        path,
        params,
        f"analytics_{analytics_type.replace('-', '_')}",
        instrument.instrument_key,
    )


def _rate_limit_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.casefold() in _RATE_HEADER_NAMES
        or name.casefold().startswith("x-ratelimit-")
    }


def capture_kraken_response(
    response: httpx.Response,
    *,
    dispatch: RestDispatch,
    request: KrakenRestRequest,
    request_started_at_ns: int,
    request_ended_at_ns: int,
) -> KrakenRestCapture:
    if type(dispatch) is not RestDispatch:
        raise TypeError("dispatch must be RestDispatch")
    if type(request) is not KrakenRestRequest:
        raise TypeError("request must be KrakenRestRequest")
    market = Market.SPOT if request.api is KrakenApi.SPOT else Market.PERPETUAL
    expected_logical_key = (
        Exchange.KRAKEN.value,
        market.value,
        request.instrument_key or "_market",
        request.logical_stream,
    )
    if dispatch.job.logical_key != expected_logical_key:
        raise ValueError("dispatch logical identity does not match Kraken request")
    metadata = dispatch.build_rest_metadata(
        request_started_at_ns=request_started_at_ns,
        request_ended_at_ns=request_ended_at_ns,
        method="GET",
        path=request.path,
        params=cast(Mapping[str, ValidatedJsonPayload], request.params),
        status=response.status_code,
        rate_limit_headers=_rate_limit_headers(response.headers),
    )
    inspection = inspect_kraken_response(response, api=request.api)
    if inspection.error is not None:
        raise inspection.error.attach_request_evidence(
            rest_metadata=metadata, source=dispatch.source_context
        )
    if inspection.payload is None:  # pragma: no cover
        raise KrakenPayloadError("Kraken success response has no payload")
    return KrakenRestCapture(
        inspection.payload, metadata, dispatch.source_context, request
    )


def _result_mapping(capture: KrakenRestCapture) -> Mapping[str, JsonPayload]:
    return _mapping(capture.payload.get("result"), field="Kraken Spot result")


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise KrakenPayloadError(f"{field} must be an object")
    return cast(Mapping[str, JsonPayload], value)


def _array(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise KrakenPayloadError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _instrument_event(
    capture: KrakenRestCapture,
    *,
    instrument: InstrumentRecord,
    coverage: CoverageMode | None = None,
    integrity: IntegrityMode | None = None,
) -> NativeEventDraft:
    _kraken_instrument(instrument)
    wire_protocol = "rest_query" if instrument.market is Market.SPOT else "rest"
    return NativeEventDraft(
        exchange=Exchange.KRAKEN,
        market=instrument.market,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol(wire_protocol),
        logical_stream=capture.request.logical_stream,
        native_channel=capture.request.path,
        transport=Transport.REST,
        event_time_ns=None,
        event_time_source=None,
        integrity_mode=integrity,
        coverage=coverage,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


def parse_spot_deep_book(
    capture: KrakenRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    _kraken_instrument(instrument, market=Market.SPOT)
    if (
        capture.request.api is not KrakenApi.SPOT
        or capture.request.path != SPOT_DEPTH_PATH
    ):
        raise ValueError("capture is not Kraken Spot Depth")
    if capture.request.params.get("pair") != instrument.wire_symbol("rest_query"):
        raise ValueError("Spot Depth request symbol does not match instrument")
    result = _result_mapping(capture)
    result_key = instrument.wire_symbol("rest_result")
    if set(result) != {result_key}:
        raise KrakenPayloadError(
            "Kraken Spot Depth response must contain only the requested pair"
        )
    row = _mapping(result.get(result_key), field="Spot Depth pair")
    for side in ("asks", "bids"):
        for level in _array(row.get(side), field=f"Depth {side}"):
            fields = _array(level, field=f"Depth {side} level")
            if (
                len(fields) < 3
                or type(fields[0]) is not str
                or type(fields[1]) is not str
            ):
                raise KrakenPayloadError(
                    "Spot Depth levels require price, quantity, timestamp"
                )
    return _instrument_event(
        capture,
        instrument=instrument,
        coverage=CoverageMode.LOSSY_WINDOW,
        integrity=IntegrityMode.SNAPSHOT_CHAIN,
    )


def parse_futures_deep_book(
    capture: KrakenRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    _kraken_instrument(instrument, market=Market.PERPETUAL)
    if (
        capture.request.api is not KrakenApi.FUTURES
        or capture.request.path != FUTURES_ORDERBOOK_PATH
    ):
        raise ValueError("capture is not Kraken Futures orderbook")
    if capture.request.params.get("symbol") != instrument.wire_symbol("rest"):
        raise ValueError("Futures orderbook request symbol does not match instrument")
    row = _mapping(capture.payload.get("orderBook"), field="Futures orderBook")
    for side in ("bids", "asks"):
        for level in _array(row.get(side), field=f"orderBook {side}"):
            fields = _array(level, field=f"orderBook {side} level")
            if len(fields) != 2:
                raise KrakenPayloadError(
                    "Futures orderbook level requires exactly price and size"
                )
            for index, value in enumerate(fields):
                if type(value) is int:
                    parsed = Decimal(value)
                elif type(value) is Decimal:
                    parsed = value
                else:
                    raise KrakenPayloadError(
                        "Futures orderbook price and size must not pass through float"
                    )
                if not parsed.is_finite() or parsed < 0 or (index == 0 and parsed == 0):
                    raise KrakenPayloadError(
                        "Futures orderbook requires positive price and non-negative size"
                    )
    return _instrument_event(
        capture,
        instrument=instrument,
        coverage=CoverageMode.COMPLETE,
        integrity=IntegrityMode.SNAPSHOT_CHAIN,
    )


def parse_spot_market_event(
    capture: KrakenRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    _kraken_instrument(instrument, market=Market.SPOT)
    allowed = {SPOT_TICKER_PATH, SPOT_TRADES_PATH, SPOT_OHLC_PATH}
    if capture.request.api is not KrakenApi.SPOT or capture.request.path not in allowed:
        raise ValueError("capture is not a supported Kraken Spot market event")
    if capture.request.params.get("pair") != instrument.wire_symbol("rest_query"):
        raise ValueError("Spot request symbol does not match instrument")
    result = _result_mapping(capture)
    result_key = instrument.wire_symbol("rest_result")
    expected_keys = (
        {result_key, "last"}
        if capture.request.path in {SPOT_TRADES_PATH, SPOT_OHLC_PATH}
        else {result_key}
    )
    if set(result) != expected_keys:
        raise KrakenPayloadError(
            "Kraken Spot response scope does not match the requested pair"
        )
    if capture.request.path != SPOT_TICKER_PATH:
        _array(result.get(result_key), field="Spot rows")
    else:
        _mapping(result.get(result_key), field="Spot ticker")
    coverage = (
        CoverageMode.LOSSY_WINDOW
        if capture.request.path in {SPOT_TRADES_PATH, SPOT_OHLC_PATH}
        else CoverageMode.UNKNOWN
    )
    return _instrument_event(capture, instrument=instrument, coverage=coverage)


def parse_futures_market_event(
    capture: KrakenRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    _kraken_instrument(instrument, market=Market.PERPETUAL)
    allowed = {FUTURES_TICKERS_PATH, FUTURES_HISTORY_PATH, FUTURES_FUNDING_PATH}
    is_charts = capture.request.api is KrakenApi.CHARTS
    if not is_charts and (
        capture.request.api is not KrakenApi.FUTURES
        or capture.request.path not in allowed
    ):
        raise ValueError("capture is not a supported Kraken Futures market event")
    expected = instrument.wire_symbol("charts" if is_charts else "rest")
    if is_charts:
        candle_match = _CHARTS_CANDLE.fullmatch(capture.request.path)
        analytics_match = _CHARTS_ANALYTICS.fullmatch(capture.request.path)
        actual = (
            candle_match.group(2)
            if candle_match is not None
            else analytics_match.group(1)
            if analytics_match is not None
            else None
        )
        if actual != expected:
            raise ValueError("Futures Charts request symbol does not match instrument")
    elif capture.request.params.get("symbol") != expected:
        raise ValueError("Futures request symbol does not match instrument")
    if capture.request.path == FUTURES_TICKERS_PATH:
        rows = _array(capture.payload.get("tickers"), field="Futures tickers")
        if len(rows) != 1:
            raise KrakenPayloadError(
                "Futures ticker response must contain only the requested symbol"
            )
        ticker = _mapping(rows[0], field="Futures ticker")
        if ticker.get("symbol") != expected:
            raise KrakenPayloadError("Futures ticker response lacks requested symbol")
        coverage = CoverageMode.UNKNOWN
    elif capture.request.path == FUTURES_HISTORY_PATH:
        _array(capture.payload.get("history"), field="Futures history")
        coverage = CoverageMode.LOSSY_WINDOW
    elif capture.request.path == FUTURES_FUNDING_PATH:
        _array(capture.payload.get("rates"), field="Futures funding rates")
        coverage = CoverageMode.LOSSY_WINDOW
    else:
        coverage = CoverageMode.LOSSY_WINDOW
    return _instrument_event(capture, instrument=instrument, coverage=coverage)


def parse_status(
    capture: KrakenRestCapture,
    *,
    market: Market,
    instrument: InstrumentRecord | None = None,
) -> NativeEventDraft:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    if market is Market.SPOT:
        if instrument is not None:
            raise ValueError("Kraken Spot status is market-wide")
        expected = SPOT_STATUS_PATH
    else:
        if instrument is not None:
            raise ValueError("Kraken Futures status is market-wide")
        expected = FUTURES_STATUS_PATH
    expected_api = KrakenApi.SPOT if market is Market.SPOT else KrakenApi.FUTURES
    if (
        capture.request.api is not expected_api
        or capture.request.path != expected
        or capture.request.logical_stream != "status"
    ):
        raise ValueError("capture is not matching Kraken status")
    if market is Market.SPOT:
        result = _result_mapping(capture)
        status = result.get("status")
        if type(status) is not str or not status:
            raise KrakenPayloadError("Kraken Spot status requires status string")
    else:
        rows = _array(
            capture.payload.get("instrumentStatus"),
            field="Kraken Futures instrumentStatus",
        )
        symbols: set[str] = set()
        for index, value in enumerate(rows):
            row = _mapping(value, field=f"instrumentStatus[{index}]")
            symbol = row.get("tradeable")
            if type(symbol) is not str or not symbol:
                raise KrakenPayloadError(
                    "Kraken Futures instrumentStatus requires tradeable symbol"
                )
            dislocation = row.get("experiencingDislocation")
            if type(dislocation) is not bool:
                raise KrakenPayloadError(
                    "Kraken Futures instrumentStatus requires boolean dislocation"
                )
            direction = row.get("priceDislocationDirection")
            if direction not in {
                None,
                "ABOVE_UPPER_BOUND",
                "BELOW_LOWER_BOUND",
            }:
                raise KrakenPayloadError(
                    "Kraken Futures instrumentStatus has invalid dislocation direction"
                )
            volatility = row.get("experiencingExtremeVolatility")
            if type(volatility) is not bool:
                raise KrakenPayloadError(
                    "Kraken Futures instrumentStatus requires boolean volatility"
                )
            multiplier = row.get("extremeVolatilityInitialMarginMultiplier")
            if type(multiplier) is not int:
                raise KrakenPayloadError(
                    "Kraken Futures instrumentStatus requires integer margin multiplier"
                )
            if symbol in symbols:
                raise KrakenPayloadError(
                    "Kraken Futures instrumentStatus symbols must be unique"
                )
            symbols.add(symbol)
    return NativeEventDraft(
        exchange=Exchange.KRAKEN,
        market=market,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="status",
        native_channel=expected,
        transport=Transport.REST,
        event_time_ns=None,
        event_time_source=None,
        integrity_mode=None,
        coverage=CoverageMode.UNKNOWN,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


__all__ = [
    "FUTURES_FUNDING_PATH",
    "FUTURES_HISTORY_PATH",
    "FUTURES_INSTRUMENTS_PATH",
    "FUTURES_ORDERBOOK_PATH",
    "FUTURES_STATUS_PATH",
    "FUTURES_TICKERS_PATH",
    "SPOT_DEPTH_PATH",
    "SPOT_OHLC_PATH",
    "SPOT_PAIRS_PATH",
    "SPOT_STATUS_PATH",
    "SPOT_TICKER_PATH",
    "SPOT_TRADES_PATH",
    "KrakenRestCapture",
    "KrakenRestRequest",
    "capture_kraken_response",
    "futures_analytics_request",
    "futures_candles_request",
    "futures_funding_request",
    "futures_history_request",
    "futures_instruments_request",
    "futures_orderbook_request",
    "futures_status_request",
    "futures_tickers_request",
    "parse_futures_deep_book",
    "parse_futures_market_event",
    "parse_spot_deep_book",
    "parse_spot_market_event",
    "parse_status",
    "spot_depth_request",
    "spot_ohlc_request",
    "spot_pairs_request",
    "spot_status_request",
    "spot_tickers_request",
    "spot_trades_request",
]
