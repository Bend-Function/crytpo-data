from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
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
from crypto_collector.exchanges.bitget.errors import (
    BitgetPayloadError,
    inspect_bitget_response,
)
from crypto_collector.exchanges.contracts import PublicQueryValue
from crypto_collector.observability.redaction import SENSITIVE_QUERY_NAMES
from crypto_collector.scheduler import RestDispatch
from crypto_collector.selection import InstrumentRecord


class BitgetEndpoints:
    """Evidenced anonymous UTA v3 REST paths."""

    INSTRUMENTS = "/api/v3/market/instruments"
    TICKERS = "/api/v3/market/tickers"
    ORDERBOOK = "/api/v3/market/orderbook"
    FILLS = "/api/v3/market/fills"
    CANDLES = "/api/v3/market/candles"
    HISTORY_CANDLES = "/api/v3/market/history-candles"
    OPEN_INTEREST = "/api/v3/market/open-interest"
    CURRENT_FUNDING_RATE = "/api/v3/market/current-fund-rate"
    FUNDING_RATE_HISTORY = "/api/v3/market/history-fund-rate"
    INDEX_COMPONENTS = "/api/v3/market/index-components"
    LIQUIDATIONS = "/api/v3/market/liquidations"


INSTRUMENTS_PATH = BitgetEndpoints.INSTRUMENTS
TICKERS_PATH = BitgetEndpoints.TICKERS
ORDERBOOK_PATH = BitgetEndpoints.ORDERBOOK
FILLS_PATH = BitgetEndpoints.FILLS
CANDLES_PATH = BitgetEndpoints.CANDLES
HISTORY_CANDLES_PATH = BitgetEndpoints.HISTORY_CANDLES
OPEN_INTEREST_PATH = BitgetEndpoints.OPEN_INTEREST
CURRENT_FUNDING_RATE_PATH = BitgetEndpoints.CURRENT_FUNDING_RATE
FUNDING_RATE_HISTORY_PATH = BitgetEndpoints.FUNDING_RATE_HISTORY
INDEX_COMPONENTS_PATH = BitgetEndpoints.INDEX_COMPONENTS
LIQUIDATIONS_PATH = BitgetEndpoints.LIQUIDATIONS

_SPOT_AND_USDT = frozenset({"SPOT", "USDT-FUTURES"})
_USDT_FUTURES = frozenset({"USDT-FUTURES"})
_CANDLE_INTERVALS = frozenset(
    {"1m", "3m", "5m", "15m", "30m", "1H", "4H", "6H", "12H", "1D"}
)
_SPOT_CANDLE_TYPES = frozenset({"market", "index"})
_FUTURES_CANDLE_TYPES = frozenset({"market", "mark", "index", "premium"})
_RATE_HEADER_NAMES = frozenset(
    {
        "retry-after",
        "x-bg-request-accept-time",
        "x-bg-response-complete-time",
        "x-mbx-used-remain-limit",
    }
)
_MILLISECONDS_TO_NANOSECONDS = 1_000_000
_MAX_SIGNED_64 = 2**63 - 1
_NINETY_DAYS_MS = 90 * 24 * 60 * 60 * 1_000


@dataclass(frozen=True, slots=True)
class _RequestSchema:
    required: frozenset[str]
    allowed: frozenset[str]
    categories: frozenset[str] | None = None


_REQUEST_SCHEMAS = MappingProxyType(
    {
        INSTRUMENTS_PATH: _RequestSchema(
            frozenset({"category"}),
            frozenset({"category"}),
            _SPOT_AND_USDT,
        ),
        TICKERS_PATH: _RequestSchema(
            frozenset({"category"}),
            frozenset({"category", "symbol"}),
            _SPOT_AND_USDT,
        ),
        ORDERBOOK_PATH: _RequestSchema(
            frozenset({"category", "symbol"}),
            frozenset({"category", "symbol", "limit"}),
            _SPOT_AND_USDT,
        ),
        FILLS_PATH: _RequestSchema(
            frozenset({"category", "symbol"}),
            frozenset({"category", "symbol", "limit"}),
            _SPOT_AND_USDT,
        ),
        CANDLES_PATH: _RequestSchema(
            frozenset({"category", "symbol", "interval"}),
            frozenset(
                {
                    "category",
                    "symbol",
                    "interval",
                    "startTime",
                    "endTime",
                    "type",
                    "limit",
                }
            ),
            _SPOT_AND_USDT,
        ),
        HISTORY_CANDLES_PATH: _RequestSchema(
            frozenset({"category", "symbol", "interval"}),
            frozenset(
                {
                    "category",
                    "symbol",
                    "interval",
                    "startTime",
                    "endTime",
                    "type",
                    "limit",
                }
            ),
            _SPOT_AND_USDT,
        ),
        OPEN_INTEREST_PATH: _RequestSchema(
            frozenset({"category"}),
            frozenset({"category", "symbol"}),
            _USDT_FUTURES,
        ),
        CURRENT_FUNDING_RATE_PATH: _RequestSchema(
            frozenset({"category"}),
            frozenset({"category", "symbol"}),
            _USDT_FUTURES,
        ),
        FUNDING_RATE_HISTORY_PATH: _RequestSchema(
            frozenset({"category", "symbol"}),
            frozenset({"category", "symbol", "cursor", "limit"}),
            _USDT_FUTURES,
        ),
        INDEX_COMPONENTS_PATH: _RequestSchema(
            frozenset({"symbol"}),
            frozenset({"symbol"}),
        ),
        LIQUIDATIONS_PATH: _RequestSchema(
            frozenset({"category"}),
            frozenset({"category", "symbol", "limit", "cursor"}),
            _USDT_FUTURES,
        ),
    }
)
_ALLOWED_PATHS = frozenset(_REQUEST_SCHEMAS)
_FIXED_STREAM_BY_PATH = MappingProxyType(
    {
        INSTRUMENTS_PATH: "instrument_catalog",
        ORDERBOOK_PATH: "book_deep_snapshot",
        FILLS_PATH: "trade",
        OPEN_INTEREST_PATH: "open_interest",
        CURRENT_FUNDING_RATE_PATH: "funding",
        FUNDING_RATE_HISTORY_PATH: "funding_history",
        INDEX_COMPONENTS_PATH: "index_components",
        LIQUIDATIONS_PATH: "liquidation",
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
            raise TypeError("Bitget query parameters must be scalar public values")
        normalized[name] = item
    return MappingProxyType(normalized)


def _string_param(params: Mapping[str, PublicQueryValue], name: str) -> str:
    return _nonempty(params[name], field=f"{name} query parameter")


def _enum_param(
    params: Mapping[str, PublicQueryValue],
    name: str,
    allowed: frozenset[str],
) -> str:
    value = _string_param(params, name)
    if value not in allowed:
        raise ValueError(f"unsupported Bitget {name} query parameter")
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
        raise ValueError(f"Bitget {name} query parameter must be a decimal integer")
    if parsed < minimum or (maximum is not None and parsed > maximum):
        bound = (
            f"at least {minimum}"
            if maximum is None
            else f"between {minimum} and {maximum}"
        )
        raise ValueError(f"Bitget {name} query parameter must be {bound}")
    return parsed


def _validate_request_params(
    path: str,
    params: Mapping[str, PublicQueryValue],
) -> None:
    schema = _REQUEST_SCHEMAS[path]
    names = frozenset(params)
    unknown = names - schema.allowed
    if unknown:
        rendered = ", ".join(sorted(unknown))
        raise ValueError(
            f"unsupported Bitget query parameter(s) for {path}: {rendered}"
        )
    missing = schema.required - names
    if missing:
        rendered = ", ".join(sorted(missing))
        raise ValueError(
            f"missing required Bitget query parameter(s) for {path}: {rendered}"
        )
    if "category" in params:
        if schema.categories is None:
            raise ValueError(f"Bitget category is not applicable to {path}")
        _enum_param(params, "category", schema.categories)
    if "symbol" in params:
        _string_param(params, "symbol")
    if path == ORDERBOOK_PATH and "limit" in params:
        _integer_param(params, "limit", minimum=1, maximum=1_000)
    if path == FILLS_PATH and "limit" in params:
        _integer_param(params, "limit", minimum=1, maximum=100)
    if path in {CANDLES_PATH, HISTORY_CANDLES_PATH}:
        _enum_param(params, "interval", _CANDLE_INTERVALS)
        if "type" in params:
            category = _string_param(params, "category")
            allowed_types = (
                _SPOT_CANDLE_TYPES if category == "SPOT" else _FUTURES_CANDLE_TYPES
            )
            _enum_param(params, "type", allowed_types)
        for name in ("startTime", "endTime"):
            if name in params:
                _integer_param(params, name, minimum=0)
        if "limit" in params:
            maximum = 1_000 if path == CANDLES_PATH else 100
            _integer_param(params, "limit", minimum=1, maximum=maximum)
        if "startTime" in params and "endTime" in params:
            start = _integer_param(params, "startTime", minimum=0)
            end = _integer_param(params, "endTime", minimum=0)
            if end < start:
                raise ValueError("Bitget endTime cannot precede startTime")
            if path == HISTORY_CANDLES_PATH and end - start > _NINETY_DAYS_MS:
                raise ValueError("Bitget history candle range cannot exceed 90 days")
    if path == FUNDING_RATE_HISTORY_PATH:
        if "cursor" in params:
            _integer_param(params, "cursor", minimum=1, maximum=100)
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=100)
    if path == LIQUIDATIONS_PATH:
        if "cursor" in params:
            _string_param(params, "cursor")
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=100)


@dataclass(frozen=True, slots=True)
class BitgetRestRequest:
    path: str
    params: Mapping[str, PublicQueryValue]
    logical_stream: str

    def __post_init__(self) -> None:
        if self.path not in _ALLOWED_PATHS:
            raise ValueError(
                "path is not an evidenced Bitget anonymous UTA v3 REST endpoint"
            )
        params = _params(self.params)
        _validate_request_params(self.path, params)
        object.__setattr__(self, "params", params)
        object.__setattr__(
            self,
            "logical_stream",
            _nonempty(self.logical_stream, field="logical_stream"),
        )
        _validate_request_scope(self.path, params, self.logical_stream)


def _validate_request_scope(
    path: str,
    params: Mapping[str, PublicQueryValue],
    logical_stream: str,
) -> None:
    if path == TICKERS_PATH:
        expected_stream = "ticker" if "symbol" in params else "ticker_catalog"
    elif path in {CANDLES_PATH, HISTORY_CANDLES_PATH}:
        expected_stream = f"candle_{params['interval']}"
    else:
        expected_stream = _FIXED_STREAM_BY_PATH[path]
    if logical_stream != expected_stream:
        raise ValueError(
            "Bitget request scope does not match logical stream for its path"
        )


@dataclass(frozen=True, slots=True)
class BitgetRestCapture:
    payload: Mapping[str, JsonPayload]
    rest_metadata: RestMetadata
    source: SourceContext
    request: BitgetRestRequest

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping) or any(
            type(key) is not str for key in self.payload
        ):
            raise TypeError("payload must be a string-keyed mapping")
        if type(self.rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(self.source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if type(self.request) is not BitgetRestRequest:
            raise TypeError("request must be BitgetRestRequest")
        if self.payload.get("code") != "00000":
            raise ValueError(
                "Bitget capture payload must contain string success code '00000'"
            )
        if self.rest_metadata.method != "GET":
            raise ValueError("Bitget public capture must use GET")
        if not 200 <= self.rest_metadata.status < 300:
            raise ValueError("Bitget success capture requires a 2xx HTTP status")
        if self.rest_metadata.path != self.request.path:
            raise ValueError("REST metadata path does not match the request")
        if self.rest_metadata.params != dict(self.request.params):
            raise ValueError("REST metadata params do not match the request")
        self.source.validate_for(
            transport=Transport.REST,
            logical_stream=self.request.logical_stream,
        )


def request_category(market: Market) -> str:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    return "SPOT" if market is Market.SPOT else "USDT-FUTURES"


def instruments_request(
    market: Market,
) -> BitgetRestRequest:
    return BitgetRestRequest(
        INSTRUMENTS_PATH,
        {"category": request_category(market)},
        "instrument_catalog",
    )


def tickers_request(
    market: Market,
) -> BitgetRestRequest:
    return BitgetRestRequest(
        TICKERS_PATH,
        {"category": request_category(market)},
        "ticker_catalog",
    )


def _bitget_instrument(
    instrument: InstrumentRecord,
    *,
    market: Market | None = None,
) -> None:
    if not isinstance(instrument, InstrumentRecord):
        raise TypeError("instrument must be InstrumentRecord")
    if instrument.exchange is not Exchange.BITGET:
        raise ValueError("instrument must belong to Bitget")
    if market is not None and instrument.market is not market:
        raise ValueError("instrument does not belong to the required market")


def _instrument_params(instrument: InstrumentRecord) -> dict[str, PublicQueryValue]:
    _bitget_instrument(instrument)
    return {
        "category": request_category(instrument.market),
        "symbol": instrument.wire_symbol("rest"),
    }


def ticker_request(instrument: InstrumentRecord) -> BitgetRestRequest:
    return BitgetRestRequest(TICKERS_PATH, _instrument_params(instrument), "ticker")


def deep_book_request(
    instrument: InstrumentRecord,
    *,
    depth: int = 1_000,
) -> BitgetRestRequest:
    if type(depth) is not int or not 1 <= depth <= 1_000:
        raise ValueError("Bitget REST order-book depth must be between 1 and 1000")
    params = _instrument_params(instrument)
    params["limit"] = depth
    return BitgetRestRequest(ORDERBOOK_PATH, params, "book_deep_snapshot")


def fills_request(
    instrument: InstrumentRecord,
    *,
    limit: int = 100,
) -> BitgetRestRequest:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Bitget fills limit must be between 1 and 100")
    params = _instrument_params(instrument)
    params["limit"] = limit
    return BitgetRestRequest(FILLS_PATH, params, "trade")


def _candles_request(
    instrument: InstrumentRecord,
    *,
    path: str,
    interval: str,
    candle_type: str,
    limit: int,
    start_time_ms: int | None,
    end_time_ms: int | None,
) -> BitgetRestRequest:
    if interval not in _CANDLE_INTERVALS:
        raise ValueError("unsupported Bitget candle interval")
    allowed_types = (
        _SPOT_CANDLE_TYPES
        if instrument.market is Market.SPOT
        else _FUTURES_CANDLE_TYPES
    )
    if candle_type not in allowed_types:
        raise ValueError("unsupported Bitget candle type")
    maximum = 1_000 if path == CANDLES_PATH else 100
    if type(limit) is not int or not 1 <= limit <= maximum:
        raise ValueError(f"Bitget candle limit must be between 1 and {maximum}")
    params = _instrument_params(instrument)
    params.update({"interval": interval, "type": candle_type, "limit": limit})
    if start_time_ms is not None:
        params["startTime"] = start_time_ms
    if end_time_ms is not None:
        params["endTime"] = end_time_ms
    return BitgetRestRequest(path, params, f"candle_{interval}")


def candles_request(
    instrument: InstrumentRecord,
    *,
    interval: str = "1m",
    candle_type: str = "market",
    limit: int = 100,
    start_time_ms: int | None = None,
    end_time_ms: int | None = None,
) -> BitgetRestRequest:
    return _candles_request(
        instrument,
        path=CANDLES_PATH,
        interval=interval,
        candle_type=candle_type,
        limit=limit,
        start_time_ms=start_time_ms,
        end_time_ms=end_time_ms,
    )


def history_candles_request(
    instrument: InstrumentRecord,
    *,
    interval: str = "1m",
    candle_type: str = "market",
    limit: int = 100,
    start_time_ms: int | None = None,
    end_time_ms: int | None = None,
) -> BitgetRestRequest:
    return _candles_request(
        instrument,
        path=HISTORY_CANDLES_PATH,
        interval=interval,
        candle_type=candle_type,
        limit=limit,
        start_time_ms=start_time_ms,
        end_time_ms=end_time_ms,
    )


def open_interest_request(instrument: InstrumentRecord) -> BitgetRestRequest:
    _bitget_instrument(instrument, market=Market.PERPETUAL)
    return BitgetRestRequest(
        OPEN_INTEREST_PATH,
        _instrument_params(instrument),
        "open_interest",
    )


def current_funding_rate_request(instrument: InstrumentRecord) -> BitgetRestRequest:
    _bitget_instrument(instrument, market=Market.PERPETUAL)
    return BitgetRestRequest(
        CURRENT_FUNDING_RATE_PATH,
        _instrument_params(instrument),
        "funding",
    )


def funding_rate_history_request(
    instrument: InstrumentRecord,
    *,
    cursor: int = 1,
    limit: int = 100,
) -> BitgetRestRequest:
    _bitget_instrument(instrument, market=Market.PERPETUAL)
    if type(cursor) is not int or not 1 <= cursor <= 100:
        raise ValueError("Bitget funding-history cursor must be between 1 and 100")
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Bitget funding-history limit must be between 1 and 100")
    params = _instrument_params(instrument)
    params.update({"cursor": cursor, "limit": limit})
    return BitgetRestRequest(
        FUNDING_RATE_HISTORY_PATH,
        params,
        "funding_history",
    )


def index_components_request(instrument: InstrumentRecord) -> BitgetRestRequest:
    _bitget_instrument(instrument, market=Market.PERPETUAL)
    return BitgetRestRequest(
        INDEX_COMPONENTS_PATH,
        {"symbol": instrument.wire_symbol("rest")},
        "index_components",
    )


def liquidations_request(
    instrument: InstrumentRecord | None = None,
    *,
    limit: int = 100,
    cursor: str | None = None,
) -> BitgetRestRequest:
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Bitget liquidations limit must be between 1 and 100")
    params: dict[str, PublicQueryValue] = {
        "category": request_category(Market.PERPETUAL),
        "limit": limit,
    }
    if instrument is not None:
        _bitget_instrument(instrument, market=Market.PERPETUAL)
        params["symbol"] = instrument.wire_symbol("rest")
    if cursor is not None:
        params["cursor"] = _nonempty(cursor, field="cursor")
    return BitgetRestRequest(LIQUIDATIONS_PATH, params, "liquidation")


def derivative_reference_request(
    logical_stream: str,
    instrument: InstrumentRecord,
) -> BitgetRestRequest:
    """Build a current derivative reference request by canonical stream name."""

    if logical_stream == "open_interest":
        return open_interest_request(instrument)
    if logical_stream == "funding":
        return current_funding_rate_request(instrument)
    if logical_stream == "index_components":
        return index_components_request(instrument)
    raise ValueError("unsupported Bitget derivative reference stream")


def _rate_limit_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.casefold() in _RATE_HEADER_NAMES
        or name.casefold().startswith("x-ratelimit-")
    }


def _request_logical_key(request: BitgetRestRequest) -> tuple[str, str, str, str]:
    category = request.params.get("category")
    if category == "SPOT":
        market = Market.SPOT
    elif category == "USDT-FUTURES" or request.path == INDEX_COMPONENTS_PATH:
        market = Market.PERPETUAL
    else:  # pragma: no cover - request schemas guard every supported path.
        raise ValueError("Bitget request does not identify a supported market")
    symbol = request.params.get("symbol")
    instrument_key = symbol if type(symbol) is str else "_market"
    return (
        Exchange.BITGET.value,
        market.value,
        instrument_key,
        request.logical_stream,
    )


def capture_bitget_response(
    response: httpx.Response,
    *,
    dispatch: RestDispatch,
    request: BitgetRestRequest,
    request_started_at_ns: int,
    request_ended_at_ns: int,
) -> BitgetRestCapture:
    """Attach scheduler evidence and reject UTA business errors at HTTP 200."""

    if type(dispatch) is not RestDispatch:
        raise TypeError("dispatch must be RestDispatch")
    if type(request) is not BitgetRestRequest:
        raise TypeError("request must be BitgetRestRequest")
    expected_logical_key = _request_logical_key(request)
    if dispatch.job.logical_key != expected_logical_key:
        raise ValueError("dispatch logical key does not match the Bitget request")
    metadata = dispatch.build_rest_metadata(
        request_started_at_ns=request_started_at_ns,
        request_ended_at_ns=request_ended_at_ns,
        method="GET",
        path=request.path,
        params=cast(Mapping[str, ValidatedJsonPayload], request.params),
        status=response.status_code,
        rate_limit_headers=_rate_limit_headers(response.headers),
    )
    inspection = inspect_bitget_response(response)
    if inspection.error is not None:
        raise inspection.error.attach_request_evidence(
            rest_metadata=metadata,
            source=dispatch.source_context,
        )
    if inspection.payload is None:  # pragma: no cover - guarded by inspection.
        raise BitgetPayloadError("Bitget success response has no payload")
    return BitgetRestCapture(
        payload=inspection.payload,
        rest_metadata=metadata,
        source=dispatch.source_context,
        request=request,
    )


def _mapping_row(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BitgetPayloadError(f"{field} must be an object")
    return cast(Mapping[str, JsonPayload], value)


def _response_array(capture: BitgetRestCapture) -> tuple[object, ...]:
    data = capture.payload.get("data")
    if not isinstance(data, (list, tuple)):
        raise BitgetPayloadError("Bitget response data must be an array")
    return tuple(data)


def _response_object(capture: BitgetRestCapture) -> Mapping[str, JsonPayload]:
    return _mapping_row(capture.payload.get("data"), field="Bitget response data")


def _timestamp_ns(value: object) -> int | None:
    if value is None or value == "":
        return None
    if type(value) is not str or not value.isascii() or not value.isdigit():
        return None
    normalized = value.lstrip("0") or "0"
    maximum_ms = _MAX_SIGNED_64 // _MILLISECONDS_TO_NANOSECONDS
    maximum_text = str(maximum_ms)
    if len(normalized) > len(maximum_text) or (
        len(normalized) == len(maximum_text) and normalized > maximum_text
    ):
        return None
    timestamp = int(normalized) * _MILLISECONDS_TO_NANOSECONDS
    return timestamp if timestamp <= _MAX_SIGNED_64 else None


def _required_timestamp_ns(value: object, *, field: str) -> int:
    timestamp = _timestamp_ns(value)
    if timestamp is None:
        raise BitgetPayloadError(f"Bitget response requires a valid {field} timestamp")
    return timestamp


def _uniform_timestamp_ns(values: tuple[object, ...], *, field: str) -> int | None:
    if not values:
        return None
    timestamps = tuple(_required_timestamp_ns(value, field=field) for value in values)
    first = timestamps[0]
    return first if all(timestamp == first for timestamp in timestamps[1:]) else None


def _validate_request_identity(
    capture: BitgetRestCapture,
    instrument: InstrumentRecord,
) -> None:
    _bitget_instrument(instrument)
    if capture.request.params.get("category") not in {
        None,
        request_category(instrument.market),
    }:
        raise ValueError("Bitget request category does not match the instrument")
    if capture.request.params.get("symbol") != instrument.wire_symbol("rest"):
        raise ValueError("Bitget request symbol does not match the instrument")


def _instrument_event(
    capture: BitgetRestCapture,
    *,
    instrument: InstrumentRecord,
    logical_stream: str,
    event_time_ns: int | None,
    event_time_source: str | None,
    integrity_mode: IntegrityMode | None = None,
    coverage: CoverageMode | None = None,
) -> NativeEventDraft:
    _bitget_instrument(instrument)
    if event_time_ns is not None and event_time_source is None:
        raise ValueError("event_time_source is required with event_time_ns")
    return NativeEventDraft(
        exchange=Exchange.BITGET,
        market=instrument.market,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        logical_stream=logical_stream,
        native_channel=capture.request.path,
        transport=Transport.REST,
        event_time_ns=event_time_ns,
        event_time_source=None if event_time_ns is None else event_time_source,
        integrity_mode=integrity_mode,
        coverage=coverage,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


def parse_deep_book(
    capture: BitgetRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    if (
        capture.request.path != ORDERBOOK_PATH
        or capture.request.logical_stream != "book_deep_snapshot"
    ):
        raise ValueError("capture is not a Bitget REST order-book response")
    _validate_request_identity(capture, instrument)
    data = _response_object(capture)
    for side in ("a", "b"):
        levels = data.get(side)
        if not isinstance(levels, (list, tuple)):
            raise BitgetPayloadError(f"Bitget order-book data requires a {side} array")
        for level in levels:
            if not isinstance(level, (list, tuple)) or len(level) != 2:
                raise BitgetPayloadError(
                    "Bitget REST order-book levels must be [price, quantity]"
                )
            for index, value in enumerate(level):
                if type(value) is int:
                    parsed = Decimal(value)
                elif type(value) is Decimal:
                    parsed = value
                elif type(value) is str:
                    try:
                        parsed = Decimal(value)
                    except InvalidOperation:
                        parsed = Decimal("NaN")
                else:
                    parsed = Decimal("NaN")
                valid = parsed.is_finite() and (
                    parsed > 0 if index == 0 else parsed >= 0
                )
                if not valid:
                    raise BitgetPayloadError(
                        "Bitget REST order-book price must be positive and quantity "
                        "must be non-negative"
                    )
    event_time_ns = _required_timestamp_ns(data.get("ts"), field="data.ts")
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream="book_deep_snapshot",
        event_time_ns=event_time_ns,
        event_time_source="bitget.data.ts",
        integrity_mode=IntegrityMode.SNAPSHOT_CHAIN,
        coverage=CoverageMode.COMPLETE,
    )


def parse_ticker_snapshot(
    capture: BitgetRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    if (
        capture.request.path != TICKERS_PATH
        or capture.request.logical_stream != "ticker"
    ):
        raise ValueError("capture is not a Bitget ticker response")
    _validate_request_identity(capture, instrument)
    rows = tuple(
        _mapping_row(row, field="Bitget ticker row") for row in _response_array(capture)
    )
    if len(rows) != 1:
        raise BitgetPayloadError(
            "Bitget symbol ticker response must contain exactly one row"
        )
    row = rows[0]
    if row.get("category") != request_category(instrument.market):
        raise BitgetPayloadError("Bitget ticker category does not match the request")
    if row.get("symbol") != instrument.wire_symbol("rest"):
        raise BitgetPayloadError("Bitget ticker symbol does not match the request")
    event_time_ns = _required_timestamp_ns(row.get("ts"), field="data[0].ts")
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream="ticker",
        event_time_ns=event_time_ns,
        event_time_source="bitget.data[0].ts",
    )


def parse_fills(
    capture: BitgetRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    if capture.request.path != FILLS_PATH or capture.request.logical_stream != "trade":
        raise ValueError("capture is not a Bitget public fills response")
    _validate_request_identity(capture, instrument)
    timestamps: list[object] = []
    for row_value in _response_array(capture):
        row = _mapping_row(row_value, field="Bitget public fill row")
        for field in ("execId", "price", "size", "side"):
            value = row.get(field)
            if type(value) is not str or not value:
                raise BitgetPayloadError(
                    f"Bitget public fill row requires string {field}"
                )
        if row.get("side") not in {"buy", "sell"}:
            raise BitgetPayloadError("Bitget public fill side must be buy or sell")
        timestamps.append(row.get("ts"))
    event_time_ns = _uniform_timestamp_ns(tuple(timestamps), field="data[].ts")
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream="trade",
        event_time_ns=event_time_ns,
        event_time_source="bitget.data[0].ts" if event_time_ns is not None else None,
        coverage=CoverageMode.LOSSY_WINDOW,
    )


def parse_candles(
    capture: BitgetRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    if capture.request.path not in {CANDLES_PATH, HISTORY_CANDLES_PATH}:
        raise ValueError("capture is not a Bitget candle response")
    _validate_request_identity(capture, instrument)
    interval = capture.request.params.get("interval")
    if (
        type(interval) is not str
        or capture.request.logical_stream != f"candle_{interval}"
    ):
        raise ValueError("Bitget candle interval does not match its logical stream")
    timestamps: list[object] = []
    for row in _response_array(capture):
        if not isinstance(row, (list, tuple)) or len(row) < 7:
            raise BitgetPayloadError("Bitget candle row must contain at least 7 fields")
        if any(type(value) is not str for value in row[:7]):
            raise BitgetPayloadError("Bitget candle core fields must be strings")
        timestamps.append(row[0])
    event_time_ns = _uniform_timestamp_ns(tuple(timestamps), field="data[][0]")
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream=capture.request.logical_stream,
        event_time_ns=event_time_ns,
        event_time_source="bitget.data[0][0]" if event_time_ns is not None else None,
    )


_REFERENCE_PATHS = MappingProxyType(
    {
        "open_interest": OPEN_INTEREST_PATH,
        "funding": CURRENT_FUNDING_RATE_PATH,
        "funding_history": FUNDING_RATE_HISTORY_PATH,
        "index_components": INDEX_COMPONENTS_PATH,
    }
)


def parse_derivative_reference(
    capture: BitgetRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _bitget_instrument(instrument, market=Market.PERPETUAL)
    logical_stream = capture.request.logical_stream
    if _REFERENCE_PATHS.get(logical_stream) != capture.request.path:
        raise ValueError("capture is not a Bitget derivative reference response")
    _validate_request_identity(capture, instrument)
    identity = instrument.wire_symbol("rest")
    event_time_ns: int | None = None
    event_time_source: str | None = None
    if logical_stream == "open_interest":
        data = _response_object(capture)
        rows_value = data.get("list")
        if not isinstance(rows_value, (list, tuple)):
            raise BitgetPayloadError("Bitget open-interest data.list must be an array")
        rows = tuple(
            _mapping_row(row, field="Bitget open-interest row") for row in rows_value
        )
        event_time_ns = _required_timestamp_ns(data.get("ts"), field="data.ts")
        event_time_source = "bitget.data.ts"
    elif logical_stream == "funding":
        rows = tuple(
            _mapping_row(row, field="Bitget funding row")
            for row in _response_array(capture)
        )
    elif logical_stream == "funding_history":
        data = _response_object(capture)
        rows_value = data.get("resultList")
        if not isinstance(rows_value, (list, tuple)):
            raise BitgetPayloadError(
                "Bitget funding-history data.resultList must be an array"
            )
        rows = tuple(
            _mapping_row(row, field="Bitget funding-history row") for row in rows_value
        )
        event_time_ns = _uniform_timestamp_ns(
            tuple(row.get("fundingRateTimestamp") for row in rows),
            field="data.resultList[].fundingRateTimestamp",
        )
        if event_time_ns is not None:
            event_time_source = "bitget.data.resultList[0].fundingRateTimestamp"
    else:
        data = _response_object(capture)
        if data.get("symbol") != identity:
            raise BitgetPayloadError(
                "Bitget index-components symbol does not match the request"
            )
        components = data.get("componentList")
        if not isinstance(components, (list, tuple)):
            raise BitgetPayloadError(
                "Bitget index-components data.componentList must be an array"
            )
        for component_value in components:
            _mapping_row(component_value, field="Bitget index component row")
        rows = ()
    for reference_row in rows:
        if reference_row.get("symbol") != identity:
            raise BitgetPayloadError(
                "Bitget derivative response symbol does not match the request"
            )
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream=logical_stream,
        event_time_ns=event_time_ns,
        event_time_source=event_time_source,
    )


def parse_liquidations(
    capture: BitgetRestCapture,
    *,
    instrument: InstrumentRecord | None = None,
) -> NativeEventDraft:
    if (
        capture.request.path != LIQUIDATIONS_PATH
        or capture.request.logical_stream != "liquidation"
    ):
        raise ValueError("capture is not a Bitget liquidation response")
    data = _response_object(capture)
    rows_value = data.get("list")
    if not isinstance(rows_value, (list, tuple)):
        raise BitgetPayloadError("Bitget liquidation data.list must be an array")
    rows = tuple(
        _mapping_row(row, field="Bitget liquidation row") for row in rows_value
    )
    timestamps = tuple(row.get("ts") for row in rows)
    event_time_ns = _uniform_timestamp_ns(timestamps, field="data.list[].ts")
    if instrument is not None:
        _bitget_instrument(instrument, market=Market.PERPETUAL)
        _validate_request_identity(capture, instrument)
        identity = instrument.wire_symbol("rest")
        for row in rows:
            if row.get("symbol") != identity:
                raise BitgetPayloadError(
                    "Bitget liquidation symbol does not match the request"
                )
        instrument_key: str | None = instrument.instrument_key
        wire_symbol: str | None = identity
    else:
        if "symbol" in capture.request.params:
            raise ValueError("symbol-scoped liquidation capture requires an instrument")
        instrument_key = None
        wire_symbol = None
    return NativeEventDraft(
        exchange=Exchange.BITGET,
        market=Market.PERPETUAL,
        instrument_key=instrument_key,
        wire_symbol=wire_symbol,
        logical_stream="liquidation",
        native_channel=LIQUIDATIONS_PATH,
        transport=Transport.REST,
        event_time_ns=event_time_ns,
        event_time_source=(
            "bitget.data.list[0].ts" if event_time_ns is not None else None
        ),
        coverage=CoverageMode.LOSSY_WINDOW,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


__all__ = [
    "CANDLES_PATH",
    "CURRENT_FUNDING_RATE_PATH",
    "FILLS_PATH",
    "FUNDING_RATE_HISTORY_PATH",
    "HISTORY_CANDLES_PATH",
    "INDEX_COMPONENTS_PATH",
    "INSTRUMENTS_PATH",
    "LIQUIDATIONS_PATH",
    "OPEN_INTEREST_PATH",
    "ORDERBOOK_PATH",
    "TICKERS_PATH",
    "BitgetEndpoints",
    "BitgetRestCapture",
    "BitgetRestRequest",
    "candles_request",
    "capture_bitget_response",
    "current_funding_rate_request",
    "deep_book_request",
    "derivative_reference_request",
    "fills_request",
    "funding_rate_history_request",
    "history_candles_request",
    "index_components_request",
    "instruments_request",
    "liquidations_request",
    "open_interest_request",
    "parse_candles",
    "parse_deep_book",
    "parse_derivative_reference",
    "parse_fills",
    "parse_liquidations",
    "parse_ticker_snapshot",
    "request_category",
    "ticker_request",
    "tickers_request",
]
