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
from crypto_collector.exchanges.bybit.errors import (
    BybitPayloadError,
    bybit_rate_limit_headers,
    inspect_bybit_response,
)
from crypto_collector.exchanges.contracts import PublicQueryValue
from crypto_collector.observability.redaction import SENSITIVE_QUERY_NAMES
from crypto_collector.scheduler import RestDispatch
from crypto_collector.selection import InstrumentRecord


class BybitEndpoints:
    INSTRUMENTS = "/v5/market/instruments-info"
    TICKERS = "/v5/market/tickers"
    RECENT_TRADES = "/v5/market/recent-trade"
    KLINE = "/v5/market/kline"
    MARK_PRICE_KLINE = "/v5/market/mark-price-kline"
    INDEX_PRICE_KLINE = "/v5/market/index-price-kline"
    PREMIUM_INDEX_KLINE = "/v5/market/premium-index-price-kline"
    FUNDING_HISTORY = "/v5/market/funding/history"
    OPEN_INTEREST = "/v5/market/open-interest"
    ACCOUNT_RATIO = "/v5/market/account-ratio"
    ORDERBOOK = "/v5/market/orderbook"
    RPI_ORDERBOOK = "/v5/market/rpi_orderbook"
    FULL_ORDERBOOK = "/v5/market/full_orderbook"
    INSURANCE = "/v5/market/insurance"
    RISK_LIMIT = "/v5/market/risk-limit"
    INDEX_COMPONENTS = "/v5/market/index-price-components"
    PRICE_LIMIT = "/v5/market/price-limit"
    ADL_ALERT = "/v5/market/adlAlert"
    SYSTEM_STATUS = "/v5/system/status"
    SERVER_TIME = "/v5/market/time"
    ANNOUNCEMENTS = "/v5/announcements/index"


INSTRUMENTS_PATH = BybitEndpoints.INSTRUMENTS
TICKERS_PATH = BybitEndpoints.TICKERS
DEEP_BOOK_PATH = BybitEndpoints.ORDERBOOK
RPI_BOOK_PATH = BybitEndpoints.RPI_ORDERBOOK
FULL_BOOK_PATH = BybitEndpoints.FULL_ORDERBOOK
PUBLIC_TIME_PATH = BybitEndpoints.SERVER_TIME
STATUS_PATH = BybitEndpoints.SYSTEM_STATUS
CANDLES_PATH = BybitEndpoints.KLINE

_MAX_SIGNED_64 = 2**63 - 1
_MILLISECONDS_TO_NANOSECONDS = 1_000_000
_CATEGORY_BY_MARKET = {
    Market.SPOT: "spot",
    Market.PERPETUAL: "linear",
}
_CANDLE_INTERVALS = frozenset(
    {"1", "3", "5", "15", "30", "60", "120", "240", "360", "720", "D", "W", "M"}
)
_ANALYTICS_INTERVALS = frozenset({"5min", "15min", "30min", "1h", "4h", "1d"})
_RATIO_PERIODS = frozenset({"5min", "15min", "30min", "1h", "4h", "1d"})
_SYSTEM_STATES = frozenset({"scheduled", "ongoing", "completed", "canceled"})


@dataclass(frozen=True, slots=True)
class _RequestSchema:
    required: frozenset[str]
    allowed: frozenset[str]


_REQUEST_SCHEMAS = MappingProxyType(
    {
        BybitEndpoints.INSTRUMENTS: _RequestSchema(
            frozenset({"category"}),
            frozenset(
                {
                    "category",
                    "symbol",
                    "symbolType",
                    "status",
                    "baseCoin",
                    "limit",
                    "cursor",
                }
            ),
        ),
        BybitEndpoints.TICKERS: _RequestSchema(
            frozenset({"category"}),
            frozenset({"category", "symbol"}),
        ),
        BybitEndpoints.RECENT_TRADES: _RequestSchema(
            frozenset({"category", "symbol"}),
            frozenset({"category", "symbol", "limit"}),
        ),
        BybitEndpoints.KLINE: _RequestSchema(
            frozenset({"category", "symbol", "interval"}),
            frozenset({"category", "symbol", "interval", "start", "end", "limit"}),
        ),
        BybitEndpoints.MARK_PRICE_KLINE: _RequestSchema(
            frozenset({"category", "symbol", "interval"}),
            frozenset({"category", "symbol", "interval", "start", "end", "limit"}),
        ),
        BybitEndpoints.INDEX_PRICE_KLINE: _RequestSchema(
            frozenset({"category", "symbol", "interval"}),
            frozenset({"category", "symbol", "interval", "start", "end", "limit"}),
        ),
        BybitEndpoints.PREMIUM_INDEX_KLINE: _RequestSchema(
            frozenset({"category", "symbol", "interval"}),
            frozenset({"category", "symbol", "interval", "start", "end", "limit"}),
        ),
        BybitEndpoints.FUNDING_HISTORY: _RequestSchema(
            frozenset({"category", "symbol"}),
            frozenset({"category", "symbol", "startTime", "endTime", "limit"}),
        ),
        BybitEndpoints.OPEN_INTEREST: _RequestSchema(
            frozenset({"category", "symbol", "intervalTime"}),
            frozenset(
                {
                    "category",
                    "symbol",
                    "intervalTime",
                    "startTime",
                    "endTime",
                    "limit",
                    "cursor",
                }
            ),
        ),
        BybitEndpoints.ACCOUNT_RATIO: _RequestSchema(
            frozenset({"category", "symbol", "period"}),
            frozenset(
                {
                    "category",
                    "symbol",
                    "period",
                    "startTime",
                    "endTime",
                    "limit",
                    "cursor",
                }
            ),
        ),
        BybitEndpoints.ORDERBOOK: _RequestSchema(
            frozenset({"category", "symbol"}),
            frozenset({"category", "symbol", "limit"}),
        ),
        BybitEndpoints.RPI_ORDERBOOK: _RequestSchema(
            frozenset({"category", "symbol", "limit"}),
            frozenset({"category", "symbol", "limit"}),
        ),
        BybitEndpoints.FULL_ORDERBOOK: _RequestSchema(
            frozenset({"category", "symbol"}),
            frozenset({"category", "symbol"}),
        ),
        BybitEndpoints.INSURANCE: _RequestSchema(
            frozenset(),
            frozenset({"coin"}),
        ),
        BybitEndpoints.RISK_LIMIT: _RequestSchema(
            frozenset({"category"}),
            frozenset({"category", "symbol", "cursor"}),
        ),
        BybitEndpoints.INDEX_COMPONENTS: _RequestSchema(
            frozenset({"indexName"}),
            frozenset({"indexName"}),
        ),
        BybitEndpoints.PRICE_LIMIT: _RequestSchema(
            frozenset({"category", "symbol"}),
            frozenset({"category", "symbol"}),
        ),
        BybitEndpoints.ADL_ALERT: _RequestSchema(
            frozenset(),
            frozenset({"symbol"}),
        ),
        BybitEndpoints.SYSTEM_STATUS: _RequestSchema(
            frozenset(),
            frozenset({"id", "state"}),
        ),
        BybitEndpoints.SERVER_TIME: _RequestSchema(frozenset(), frozenset()),
        BybitEndpoints.ANNOUNCEMENTS: _RequestSchema(
            frozenset({"locale"}),
            frozenset({"locale", "type", "tag", "page", "limit"}),
        ),
    }
)
_ALLOWED_PATHS = frozenset(_REQUEST_SCHEMAS)


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
        if type(item) not in {str, int}:
            raise TypeError("Bybit query parameters must be public strings or integers")
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
        raise ValueError(f"unsupported Bybit {name}: {value!r}")
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
        raise ValueError(f"Bybit {name} must be a decimal integer")
    if parsed < minimum or (maximum is not None and parsed > maximum):
        suffix = f" and {maximum}" if maximum is not None else ""
        raise ValueError(f"Bybit {name} must be between {minimum}{suffix}")
    return parsed


def _symbol_param(params: Mapping[str, PublicQueryValue], name: str = "symbol") -> str:
    symbol = _string_param(params, name)
    if (
        not symbol.isascii()
        or symbol != symbol.upper()
        or any(character.isspace() for character in symbol)
    ):
        raise ValueError(f"Bybit {name} must be an uppercase ASCII identifier")
    return symbol


def _category(
    params: Mapping[str, PublicQueryValue],
    *,
    required: bool,
) -> str:
    if "category" not in params:
        if required:
            raise ValueError("Bybit request requires category")
        return "linear"
    return _enum_param(params, "category", frozenset({"spot", "linear"}))


def _validate_request_params(
    path: str,
    params: Mapping[str, PublicQueryValue],
) -> None:
    schema = _REQUEST_SCHEMAS[path]
    names = frozenset(params)
    missing = schema.required - names
    if missing:
        raise ValueError(f"Bybit {path} request requires {', '.join(sorted(missing))}")
    unsupported = names - schema.allowed
    if unsupported:
        raise ValueError(
            f"Bybit {path} request has unsupported parameters: {', '.join(sorted(unsupported))}"
        )

    if "symbol" in params:
        _symbol_param(params)
    for name in ("baseCoin", "coin", "indexName"):
        if name in params:
            _symbol_param(params, name)
    for name in ("cursor", "symbolType", "id", "type", "tag", "locale"):
        if name in params:
            _string_param(params, name)

    if path == BybitEndpoints.INSTRUMENTS:
        category = _category(params, required=True)
        if "status" in params:
            allowed = (
                frozenset({"Trading"})
                if category == "spot"
                else frozenset({"Trading", "PreLaunch"})
            )
            _enum_param(params, "status", allowed)
        if category == "spot" and {
            "baseCoin",
            "limit",
            "cursor",
            "status",
        }.intersection(params):
            raise ValueError(
                "Bybit Spot instruments do not support status, pagination, or baseCoin"
            )
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=1_000)
    elif path in {BybitEndpoints.TICKERS, BybitEndpoints.RECENT_TRADES}:
        category = _category(params, required=True)
        if path == BybitEndpoints.RECENT_TRADES and "limit" in params:
            _integer_param(
                params,
                "limit",
                minimum=1,
                maximum=60 if category == "spot" else 1_000,
            )
    elif path in {
        BybitEndpoints.KLINE,
        BybitEndpoints.MARK_PRICE_KLINE,
        BybitEndpoints.INDEX_PRICE_KLINE,
        BybitEndpoints.PREMIUM_INDEX_KLINE,
    }:
        category = _category(params, required=True)
        if path != BybitEndpoints.KLINE and category != "linear":
            raise ValueError("Bybit reference-price klines require linear category")
        _enum_param(params, "interval", _CANDLE_INTERVALS)
        for name in ("start", "end"):
            if name in params:
                _integer_param(params, name, minimum=0)
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=1_000)
    elif path == BybitEndpoints.FUNDING_HISTORY:
        if _category(params, required=True) != "linear":
            raise ValueError("Bybit funding history requires linear category")
        for name in ("startTime", "endTime"):
            if name in params:
                _integer_param(params, name, minimum=0)
        if "startTime" in params and "endTime" not in params:
            raise ValueError("Bybit funding history startTime requires endTime")
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=200)
    elif path in {BybitEndpoints.OPEN_INTEREST, BybitEndpoints.ACCOUNT_RATIO}:
        if _category(params, required=True) != "linear":
            raise ValueError("Bybit derivative analytics require linear category")
        interval_name = (
            "intervalTime" if path == BybitEndpoints.OPEN_INTEREST else "period"
        )
        _enum_param(
            params,
            interval_name,
            _ANALYTICS_INTERVALS
            if path == BybitEndpoints.OPEN_INTEREST
            else _RATIO_PERIODS,
        )
        for name in ("startTime", "endTime"):
            if name in params:
                _integer_param(params, name, minimum=0)
        if "limit" in params:
            _integer_param(
                params,
                "limit",
                minimum=1,
                maximum=200 if path == BybitEndpoints.OPEN_INTEREST else 500,
            )
    elif path == BybitEndpoints.ORDERBOOK:
        _category(params, required=True)
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=1_000)
    elif path == BybitEndpoints.RPI_ORDERBOOK:
        _category(params, required=True)
        _integer_param(params, "limit", minimum=1, maximum=50)
    elif path == BybitEndpoints.FULL_ORDERBOOK:
        _category(params, required=True)
    elif path == BybitEndpoints.RISK_LIMIT:
        if _category(params, required=True) != "linear":
            raise ValueError("Bybit risk limit requires linear category")
    elif path == BybitEndpoints.PRICE_LIMIT:
        if _category(params, required=True) != "linear":
            raise ValueError("Bybit price limit requires linear category")
    elif path == BybitEndpoints.SYSTEM_STATUS and "state" in params:
        _enum_param(params, "state", _SYSTEM_STATES)
    elif path == BybitEndpoints.ANNOUNCEMENTS:
        for name in ("page", "limit"):
            if name in params:
                _integer_param(
                    params,
                    name,
                    minimum=1,
                    maximum=50 if name == "limit" else None,
                )


@dataclass(frozen=True, slots=True)
class BybitRestRequest:
    path: str
    params: Mapping[str, PublicQueryValue]
    logical_stream: str

    def __post_init__(self) -> None:
        if self.path not in _ALLOWED_PATHS:
            raise ValueError("path is not an evidenced Bybit anonymous REST endpoint")
        params = _params(self.params)
        _validate_request_params(self.path, params)
        object.__setattr__(self, "params", params)
        object.__setattr__(
            self,
            "logical_stream",
            _nonempty(self.logical_stream, field="logical_stream"),
        )


@dataclass(frozen=True, slots=True)
class BybitRestCapture:
    payload: Mapping[str, JsonPayload]
    rest_metadata: RestMetadata
    source: SourceContext
    request: BybitRestRequest

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping) or any(
            type(key) is not str for key in self.payload
        ):
            raise TypeError("payload must be a string-keyed mapping")
        if type(self.rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(self.source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if type(self.request) is not BybitRestRequest:
            raise TypeError("request must be BybitRestRequest")
        if (
            type(self.payload.get("retCode")) is not int
            or self.payload.get("retCode") != 0
        ):
            raise ValueError("Bybit capture payload must contain integer retCode=0")
        if type(self.payload.get("retMsg")) is not str:
            raise ValueError("Bybit capture payload must contain a string retMsg")
        _mapping(self.payload.get("result"), field="Bybit response result")
        if self.rest_metadata.method != "GET":
            raise ValueError("Bybit public capture must use GET")
        if not 200 <= self.rest_metadata.status < 300:
            raise ValueError("Bybit success capture requires a 2xx HTTP status")
        if self.rest_metadata.path != self.request.path:
            raise ValueError("REST metadata path does not match the request")
        if self.rest_metadata.params != dict(self.request.params):
            raise ValueError("REST metadata params do not match the request")
        self.source.validate_for(
            transport=Transport.REST,
            logical_stream=self.request.logical_stream,
        )


def _market_category(market: Market) -> str:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    return _CATEGORY_BY_MARKET[market]


def _bybit_instrument(
    instrument: InstrumentRecord,
    *,
    market: Market | None = None,
) -> None:
    if not isinstance(instrument, InstrumentRecord):
        raise TypeError("instrument must be InstrumentRecord")
    if instrument.exchange is not Exchange.BYBIT:
        raise ValueError("instrument must belong to Bybit")
    if market is not None and instrument.market is not market:
        raise ValueError("instrument does not belong to the required market")


def instruments_request(
    market: Market,
    *,
    cursor: str | None = None,
    status: str | None = None,
    limit: int | None = None,
) -> BybitRestRequest:
    category = _market_category(market)
    params: dict[str, PublicQueryValue] = {"category": category}
    if market is Market.PERPETUAL:
        if status is None:
            raise ValueError(
                "Bybit Linear catalog request requires Trading or PreLaunch status"
            )
        params["status"] = status
        params["limit"] = 1_000 if limit is None else limit
        if cursor is not None:
            params["cursor"] = cursor
    elif cursor is not None or status is not None or limit is not None:
        raise ValueError(
            "Bybit Spot instruments do not support status or pagination parameters"
        )
    return BybitRestRequest(
        path=BybitEndpoints.INSTRUMENTS,
        params=params,
        logical_stream="instrument",
    )


def tickers_request(
    market: Market,
    *,
    symbol: str | None = None,
) -> BybitRestRequest:
    params: dict[str, PublicQueryValue] = {"category": _market_category(market)}
    if symbol is not None:
        params["symbol"] = symbol
    return BybitRestRequest(
        path=BybitEndpoints.TICKERS,
        params=params,
        logical_stream="ticker",
    )


def recent_trades_request(
    instrument: InstrumentRecord,
    *,
    limit: int | None = None,
) -> BybitRestRequest:
    _bybit_instrument(instrument)
    resolved_limit = 60 if instrument.market is Market.SPOT else 1_000
    return BybitRestRequest(
        path=BybitEndpoints.RECENT_TRADES,
        params={
            "category": _market_category(instrument.market),
            "symbol": instrument.wire_symbol("rest"),
            "limit": resolved_limit if limit is None else limit,
        },
        logical_stream="trade",
    )


def candles_request(
    instrument: InstrumentRecord,
    *,
    interval: str = "1",
    limit: int = 200,
) -> BybitRestRequest:
    _bybit_instrument(instrument)
    return BybitRestRequest(
        path=BybitEndpoints.KLINE,
        params={
            "category": _market_category(instrument.market),
            "symbol": instrument.wire_symbol("rest"),
            "interval": interval,
            "limit": limit,
        },
        logical_stream=f"candle_{interval}",
    )


def reference_candles_request(
    logical_stream: str,
    instrument: InstrumentRecord,
    *,
    interval: str = "1",
    limit: int = 200,
) -> BybitRestRequest:
    _bybit_instrument(instrument, market=Market.PERPETUAL)
    paths = {
        "mark_price": BybitEndpoints.MARK_PRICE_KLINE,
        "index_price": BybitEndpoints.INDEX_PRICE_KLINE,
        "premium": BybitEndpoints.PREMIUM_INDEX_KLINE,
    }
    try:
        path = paths[logical_stream]
    except KeyError:
        raise ValueError("unsupported Bybit reference candle stream") from None
    return BybitRestRequest(
        path=path,
        params={
            "category": "linear",
            "symbol": instrument.wire_symbol("rest"),
            "interval": interval,
            "limit": limit,
        },
        logical_stream=f"{logical_stream}_candle_{interval}",
    )


def deep_book_request(
    instrument: InstrumentRecord,
    *,
    depth: int = 1_000,
) -> BybitRestRequest:
    _bybit_instrument(instrument)
    return BybitRestRequest(
        path=BybitEndpoints.ORDERBOOK,
        params={
            "category": _market_category(instrument.market),
            "symbol": instrument.wire_symbol("rest"),
            "limit": depth,
        },
        logical_stream="book_deep_snapshot",
    )


def rpi_book_request(
    instrument: InstrumentRecord,
    *,
    depth: int = 50,
) -> BybitRestRequest:
    _bybit_instrument(instrument)
    return BybitRestRequest(
        path=BybitEndpoints.RPI_ORDERBOOK,
        params={
            "category": _market_category(instrument.market),
            "symbol": instrument.wire_symbol("rest"),
            "limit": depth,
        },
        logical_stream="book_deep_snapshot",
    )


def full_book_request(
    instrument: InstrumentRecord,
    *,
    logical_stream: str = "book_live_bootstrap",
) -> BybitRestRequest:
    _bybit_instrument(instrument)
    if logical_stream not in {"book_live_bootstrap", "book_deep_snapshot"}:
        raise ValueError("Bybit full order book has an invalid logical stream")
    return BybitRestRequest(
        path=BybitEndpoints.FULL_ORDERBOOK,
        params={
            "category": _market_category(instrument.market),
            "symbol": instrument.wire_symbol("rest"),
        },
        logical_stream=logical_stream,
    )


def derivative_reference_request(
    logical_stream: str,
    instrument: InstrumentRecord,
) -> BybitRestRequest:
    _bybit_instrument(instrument, market=Market.PERPETUAL)
    symbol = instrument.wire_symbol("rest")
    settlement = instrument.settlement_asset
    if settlement is None:
        raise ValueError("Bybit perpetual instrument requires a settlement asset")
    requests: dict[str, tuple[str, dict[str, PublicQueryValue]]] = {
        "funding_rate": (
            BybitEndpoints.FUNDING_HISTORY,
            {"category": "linear", "symbol": symbol, "limit": 200},
        ),
        "open_interest": (
            BybitEndpoints.OPEN_INTEREST,
            {
                "category": "linear",
                "symbol": symbol,
                "intervalTime": "5min",
                "limit": 200,
            },
        ),
        "account_ratio": (
            BybitEndpoints.ACCOUNT_RATIO,
            {"category": "linear", "symbol": symbol, "period": "5min", "limit": 500},
        ),
        "price_limit": (
            BybitEndpoints.PRICE_LIMIT,
            {"category": "linear", "symbol": symbol},
        ),
        "adl_alert": (BybitEndpoints.ADL_ALERT, {"symbol": symbol}),
        "insurance_fund": (BybitEndpoints.INSURANCE, {"coin": settlement}),
        "risk_limit": (
            BybitEndpoints.RISK_LIMIT,
            {"category": "linear", "symbol": symbol},
        ),
        "index_components": (
            BybitEndpoints.INDEX_COMPONENTS,
            {"indexName": instrument.wire_symbol("index")},
        ),
    }
    try:
        path, params = requests[logical_stream]
    except KeyError:
        raise ValueError("unsupported Bybit derivative reference stream") from None
    return BybitRestRequest(path=path, params=params, logical_stream=logical_stream)


def public_time_request() -> BybitRestRequest:
    return BybitRestRequest(
        path=BybitEndpoints.SERVER_TIME,
        params={},
        logical_stream="_control",
    )


def status_request(*, state: str | None = None) -> BybitRestRequest:
    return BybitRestRequest(
        path=BybitEndpoints.SYSTEM_STATUS,
        params={} if state is None else {"state": state},
        logical_stream="status",
    )


def announcements_request(
    *,
    locale: str = "en-US",
    page: int = 1,
    limit: int = 20,
) -> BybitRestRequest:
    return BybitRestRequest(
        path=BybitEndpoints.ANNOUNCEMENTS,
        params={"locale": locale, "page": page, "limit": limit},
        logical_stream="instrument",
    )


def capture_bybit_response(
    response: httpx.Response,
    *,
    dispatch: RestDispatch,
    request: BybitRestRequest,
    request_started_at_ns: int,
    request_ended_at_ns: int,
) -> BybitRestCapture:
    if type(dispatch) is not RestDispatch:
        raise TypeError("dispatch must be RestDispatch")
    if type(request) is not BybitRestRequest:
        raise TypeError("request must be BybitRestRequest")
    logical_key = dispatch.job.logical_key
    if logical_key is not None and logical_key[-1] != request.logical_stream:
        raise ValueError("dispatch logical stream does not match the Bybit request")
    metadata = dispatch.build_rest_metadata(
        request_started_at_ns=request_started_at_ns,
        request_ended_at_ns=request_ended_at_ns,
        method="GET",
        path=request.path,
        params=cast(Mapping[str, ValidatedJsonPayload], request.params),
        status=response.status_code,
        rate_limit_headers=bybit_rate_limit_headers(response.headers),
    )
    inspection = inspect_bybit_response(response)
    if inspection.error is not None:
        raise inspection.error.attach_request_evidence(
            rest_metadata=metadata,
            source=dispatch.source_context,
        )
    if inspection.payload is None:  # pragma: no cover - guarded by inspection.
        raise BybitPayloadError("Bybit success response has no payload")
    return BybitRestCapture(
        payload=inspection.payload,
        rest_metadata=metadata,
        source=dispatch.source_context,
        request=request,
    )


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BybitPayloadError(f"{field} must be a JSON object")
    return cast(Mapping[str, JsonPayload], value)


def _result(capture: BybitRestCapture) -> Mapping[str, JsonPayload]:
    return _mapping(capture.payload.get("result"), field="Bybit response result")


def _rows(result: Mapping[str, JsonPayload]) -> tuple[Mapping[str, JsonPayload], ...]:
    rows = result.get("list")
    if not isinstance(rows, (list, tuple)):
        raise BybitPayloadError("Bybit response result.list must be an array")
    return tuple(
        _mapping(value, field=f"Bybit response result.list[{index}]")
        for index, value in enumerate(rows)
    )


def _required_string(row: Mapping[str, JsonPayload], field: str) -> str:
    value = row.get(field)
    if type(value) is not str or not value:
        raise BybitPayloadError(f"Bybit {field} must be a non-empty string")
    return value


def _optional_string(row: Mapping[str, JsonPayload], field: str) -> str | None:
    value = row.get(field)
    if value is None:
        return None
    if type(value) is not str:
        raise BybitPayloadError(f"Bybit {field} must be a string when present")
    return value


def _decimal_string(
    row: Mapping[str, JsonPayload],
    field: str,
    *,
    allow_empty: bool = False,
) -> str:
    value = row.get(field)
    if type(value) is not str or (not value and not allow_empty):
        raise BybitPayloadError(f"Bybit {field} must be a decimal string")
    if value == "" and allow_empty:
        return value
    _validate_decimal_text(value, field=field)
    return value


def _validate_decimal_text(value: object, *, field: str) -> None:
    if type(value) is not str or not value:
        raise BybitPayloadError(f"Bybit {field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise BybitPayloadError(f"Bybit {field} must be a decimal string") from error
    if not parsed.is_finite():
        raise BybitPayloadError(f"Bybit {field} must be a finite decimal string")


def _timestamp_ns(value: object, *, field: str, integer_allowed: bool = False) -> int:
    if type(value) is int and integer_allowed:
        milliseconds = value
    elif type(value) is str and value.isascii() and value.isdigit():
        milliseconds = int(value)
    else:
        raise BybitPayloadError(f"Bybit {field} must be a millisecond timestamp")
    timestamp = milliseconds * _MILLISECONDS_TO_NANOSECONDS
    if milliseconds < 0 or timestamp > _MAX_SIGNED_64:
        raise BybitPayloadError(f"Bybit {field} does not fit signed 64-bit nanoseconds")
    return timestamp


def _uniform_timestamp(
    values: tuple[object, ...],
    *,
    field: str,
    integer_allowed: bool = False,
) -> int | None:
    if not values:
        return None
    timestamps = tuple(
        _timestamp_ns(value, field=field, integer_allowed=integer_allowed)
        for value in values
    )
    first = timestamps[0]
    return first if all(value == first for value in timestamps[1:]) else None


def _validate_category(
    result: Mapping[str, JsonPayload],
    instrument: InstrumentRecord,
) -> None:
    if result.get("category") != _market_category(instrument.market):
        raise BybitPayloadError("Bybit result category does not match the instrument")


def _validate_symbol(
    result: Mapping[str, JsonPayload],
    instrument: InstrumentRecord,
    *,
    field: str = "symbol",
) -> None:
    if result.get(field) != instrument.wire_symbol("rest"):
        raise BybitPayloadError("Bybit result symbol does not match the instrument")


def _instrument_event(
    capture: BybitRestCapture,
    *,
    instrument: InstrumentRecord,
    event_time_ns: int | None,
    event_time_source: str | None,
    integrity_mode: IntegrityMode | None = None,
    coverage: CoverageMode | None = None,
) -> NativeEventDraft:
    _bybit_instrument(instrument)
    return NativeEventDraft(
        exchange=Exchange.BYBIT,
        market=instrument.market,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        logical_stream=capture.request.logical_stream,
        native_channel=capture.request.path,
        transport=Transport.REST,
        event_time_ns=event_time_ns,
        event_time_source=None if event_time_ns is None else event_time_source,
        integrity_mode=integrity_mode,
        coverage=coverage,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


def parse_ticker(
    capture: BybitRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _bybit_instrument(instrument)
    if (
        capture.request.path != BybitEndpoints.TICKERS
        or capture.request.logical_stream != "ticker"
    ):
        raise ValueError("capture is not a Bybit ticker response")
    result = _result(capture)
    _validate_category(result, instrument)
    rows = _rows(result)
    expected = instrument.wire_symbol("rest")
    matches = [row for row in rows if _required_string(row, "symbol") == expected]
    if len(matches) != 1:
        raise BybitPayloadError(
            "Bybit ticker response must contain the requested symbol once"
        )
    known_sparse_strings = (
        "lastPrice",
        "indexPrice",
        "markPrice",
        "prevPrice24h",
        "price24hPcnt",
        "highPrice24h",
        "lowPrice24h",
        "prevPrice1h",
        "openInterest",
        "openInterestValue",
        "turnover24h",
        "volume24h",
        "fundingRate",
        "nextFundingTime",
        "bid1Price",
        "bid1Size",
        "ask1Price",
        "ask1Size",
    )
    for field in known_sparse_strings:
        value = _optional_string(matches[0], field)
        if value in {None, ""}:
            continue
        if field == "nextFundingTime":
            _timestamp_ns(value, field="result.list[].nextFundingTime")
        else:
            _decimal_string(matches[0], field)
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=None,
        event_time_source=None,
    )


def parse_recent_trades(
    capture: BybitRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _bybit_instrument(instrument)
    if (
        capture.request.path != BybitEndpoints.RECENT_TRADES
        or capture.request.logical_stream != "trade"
    ):
        raise ValueError("capture is not a Bybit recent-trade response")
    result = _result(capture)
    _validate_category(result, instrument)
    times: list[object] = []
    symbol = instrument.wire_symbol("rest")
    for row in _rows(result):
        if _required_string(row, "symbol") != symbol:
            raise BybitPayloadError("Bybit recent trade symbol does not match request")
        for field in ("execId", "price", "size", "side", "time"):
            _required_string(row, field)
        for field in ("price", "size"):
            _decimal_string(row, field)
        for field in ("isBlockTrade", "isRPITrade"):
            value = row.get(field)
            if value is not None and type(value) is not bool:
                raise BybitPayloadError(f"Bybit {field} must be a boolean")
        times.append(row["time"])
    event_time = _uniform_timestamp(tuple(times), field="result.list[].time")
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source="bybit.result.list[0].time"
        if event_time is not None
        else None,
    )


def _parse_candle_rows(
    result: Mapping[str, JsonPayload],
    *,
    minimum_fields: int,
) -> int | None:
    values = result.get("list")
    if not isinstance(values, (list, tuple)):
        raise BybitPayloadError("Bybit candle result.list must be an array")
    timestamps: list[object] = []
    for row in values:
        if not isinstance(row, (list, tuple)) or len(row) < minimum_fields:
            raise BybitPayloadError(
                f"Bybit candle row must contain at least {minimum_fields} fields"
            )
        if any(type(value) is not str or not value for value in row[:minimum_fields]):
            raise BybitPayloadError("Bybit candle fields must be non-empty strings")
        for index, value in enumerate(row[1:minimum_fields], start=1):
            _validate_decimal_text(value, field=f"result.list[][{index}]")
        timestamps.append(row[0])
    return _uniform_timestamp(tuple(timestamps), field="result.list[][0]")


def parse_candles(
    capture: BybitRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _bybit_instrument(instrument)
    if capture.request.path != BybitEndpoints.KLINE:
        raise ValueError("capture is not a Bybit kline response")
    result = _result(capture)
    _validate_category(result, instrument)
    _validate_symbol(result, instrument)
    interval = capture.request.params.get("interval")
    if (
        type(interval) is not str
        or capture.request.logical_stream != f"candle_{interval}"
    ):
        raise ValueError("Bybit candle interval does not match logical stream")
    event_time = _parse_candle_rows(result, minimum_fields=7)
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source="bybit.result.list[0][0]" if event_time is not None else None,
    )


def parse_reference_candles(
    capture: BybitRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _bybit_instrument(instrument, market=Market.PERPETUAL)
    expected_prefix = {
        BybitEndpoints.MARK_PRICE_KLINE: "mark_price",
        BybitEndpoints.INDEX_PRICE_KLINE: "index_price",
        BybitEndpoints.PREMIUM_INDEX_KLINE: "premium",
    }.get(capture.request.path)
    if expected_prefix is None:
        raise ValueError("capture is not a Bybit reference-price kline response")
    result = _result(capture)
    _validate_category(result, instrument)
    _validate_symbol(result, instrument)
    interval = capture.request.params.get("interval")
    if capture.request.logical_stream != f"{expected_prefix}_candle_{interval}":
        raise ValueError("Bybit reference candle path does not match logical stream")
    event_time = _parse_candle_rows(result, minimum_fields=5)
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source="bybit.result.list[0][0]" if event_time is not None else None,
    )


def parse_book(
    capture: BybitRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _bybit_instrument(instrument)
    expected_path = capture.request.path
    if expected_path not in {
        BybitEndpoints.ORDERBOOK,
        BybitEndpoints.RPI_ORDERBOOK,
        BybitEndpoints.FULL_ORDERBOOK,
    }:
        raise ValueError("capture is not a Bybit order-book response")
    if capture.request.params.get("category") != _market_category(instrument.market):
        raise BybitPayloadError(
            "Bybit order-book request category does not match the instrument"
        )
    result = _result(capture)
    symbol = instrument.wire_symbol("rest")
    if result.get("s") != symbol or capture.request.params.get("symbol") != symbol:
        raise BybitPayloadError("Bybit order-book symbol does not match request")
    fields_per_level = 3 if expected_path == BybitEndpoints.RPI_ORDERBOOK else 2
    if expected_path == BybitEndpoints.FULL_ORDERBOOK:
        maximum_depth = 10_000
    elif "limit" not in capture.request.params:
        maximum_depth = 1_000
    else:
        maximum_depth = _integer_param(
            capture.request.params,
            "limit",
            minimum=1,
            maximum=50 if expected_path == BybitEndpoints.RPI_ORDERBOOK else 1_000,
        )
    for side in ("b", "a"):
        levels = result.get(side)
        if not isinstance(levels, (list, tuple)):
            raise BybitPayloadError(f"Bybit order book requires a {side} array")
        if len(levels) > maximum_depth:
            raise BybitPayloadError(
                f"Bybit order book exceeds the evidenced {maximum_depth}-level bound"
            )
        for level in levels:
            if (
                not isinstance(level, (list, tuple))
                or len(level) != fields_per_level
                or any(type(value) is not str or not value for value in level)
            ):
                raise BybitPayloadError(
                    f"Bybit order-book levels must contain {fields_per_level} decimal strings"
                )
            for position, value in enumerate(level):
                text_value = cast(str, value)
                try:
                    decimal = Decimal(text_value)
                except InvalidOperation as error:
                    raise BybitPayloadError(
                        "Bybit order-book level is not decimal"
                    ) from error
                if not decimal.is_finite() or (
                    decimal <= 0 if position == 0 else decimal < 0
                ):
                    raise BybitPayloadError(
                        "Bybit order-book price must be positive and quantities non-negative"
                    )
    for field in ("u", "seq"):
        value = result.get(field)
        if type(value) is not int or value <= 0:
            raise BybitPayloadError(
                f"Bybit order-book {field} must be a positive integer"
            )
    for field in ("ts", "cts"):
        if type(result.get(field)) is not int:
            raise BybitPayloadError(
                f"Bybit order-book {field} must be an integer millisecond timestamp"
            )
    event_time = _timestamp_ns(result["ts"], field="result.ts", integer_allowed=True)
    _timestamp_ns(result["cts"], field="result.cts", integer_allowed=True)
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source="bybit.result.ts",
        integrity_mode=IntegrityMode.SNAPSHOT_CHAIN,
        coverage=CoverageMode.UNKNOWN,
    )


def _reference_rows(
    capture: BybitRestCapture,
    instrument: InstrumentRecord,
) -> tuple[Mapping[str, JsonPayload], ...]:
    result = _result(capture)
    symbol = instrument.wire_symbol("rest")
    path = capture.request.path
    if path in {
        BybitEndpoints.FUNDING_HISTORY,
        BybitEndpoints.OPEN_INTEREST,
        BybitEndpoints.ACCOUNT_RATIO,
        BybitEndpoints.RISK_LIMIT,
    }:
        if path != BybitEndpoints.ACCOUNT_RATIO:
            _validate_category(result, instrument)
        if path == BybitEndpoints.OPEN_INTEREST:
            _validate_symbol(result, instrument)
        rows = _rows(result)
        for row in rows:
            returned = row.get("symbol")
            if returned is not None and returned != symbol:
                raise BybitPayloadError(
                    "Bybit reference row symbol does not match request"
                )
        cursor = result.get("nextPageCursor")
        if cursor is not None and type(cursor) is not str:
            raise BybitPayloadError("Bybit nextPageCursor must be a string")
        return rows
    if path in {BybitEndpoints.INSURANCE, BybitEndpoints.ADL_ALERT}:
        return _rows(result)
    return ()


def parse_derivative_reference(
    capture: BybitRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _bybit_instrument(instrument, market=Market.PERPETUAL)
    expected_paths = {
        "funding_rate": BybitEndpoints.FUNDING_HISTORY,
        "open_interest": BybitEndpoints.OPEN_INTEREST,
        "account_ratio": BybitEndpoints.ACCOUNT_RATIO,
        "price_limit": BybitEndpoints.PRICE_LIMIT,
        "adl_alert": BybitEndpoints.ADL_ALERT,
        "insurance_fund": BybitEndpoints.INSURANCE,
        "risk_limit": BybitEndpoints.RISK_LIMIT,
        "index_components": BybitEndpoints.INDEX_COMPONENTS,
    }
    logical_stream = capture.request.logical_stream
    if expected_paths.get(logical_stream) != capture.request.path:
        raise ValueError(
            "capture is not a configured Bybit derivative reference response"
        )
    result = _result(capture)
    rows = _reference_rows(capture, instrument)
    timestamps: tuple[object, ...] = ()
    timestamp_field: str | None = None
    if logical_stream == "funding_rate":
        for row in rows:
            _decimal_string(row, "fundingRate")
            _required_string(row, "fundingRateTimestamp")
        timestamps = tuple(row["fundingRateTimestamp"] for row in rows)
        timestamp_field = "result.list[].fundingRateTimestamp"
    elif logical_stream == "open_interest":
        for row in rows:
            _decimal_string(row, "openInterest")
            _decimal_string(row, "singleOpenInterest")
            _required_string(row, "timestamp")
        timestamps = tuple(row["timestamp"] for row in rows)
        timestamp_field = "result.list[].timestamp"
    elif logical_stream == "account_ratio":
        for row in rows:
            _required_string(row, "symbol")
            _decimal_string(row, "buyRatio")
            _decimal_string(row, "sellRatio")
            _required_string(row, "timestamp")
        timestamps = tuple(row["timestamp"] for row in rows)
        timestamp_field = "result.list[].timestamp"
    elif logical_stream == "price_limit":
        _validate_symbol(result, instrument)
        _decimal_string(result, "buyLmt")
        _decimal_string(result, "sellLmt")
        _required_string(result, "ts")
        timestamps = (result["ts"],)
        timestamp_field = "result.ts"
    elif logical_stream == "adl_alert":
        _required_string(result, "updatedTime")
        expected = instrument.wire_symbol("rest")
        if capture.request.params.get("symbol") != expected:
            raise BybitPayloadError(
                "Bybit ADL request symbol does not match the instrument"
            )
        for row in rows:
            if _required_string(row, "symbol") != expected:
                raise BybitPayloadError(
                    "Bybit exact-symbol ADL response contains a different symbol"
                )
            for field in (
                "balance",
                "maxBalance",
                "insurancePnlRatio",
                "pnlRatio",
                "adlTriggerThreshold",
                "adlStopRatio",
            ):
                _decimal_string(row, field, allow_empty=field == "maxBalance")
        timestamps = (result["updatedTime"],)
        timestamp_field = "result.updatedTime"
    elif logical_stream == "insurance_fund":
        _required_string(result, "updatedTime")
        requested_coin = capture.request.params.get("coin")
        if requested_coin != instrument.settlement_asset:
            raise BybitPayloadError(
                "Bybit insurance request coin does not match the instrument settlement asset"
            )
        for row in rows:
            if _required_string(row, "coin") != requested_coin:
                raise BybitPayloadError(
                    "Bybit insurance response coin does not match the request"
                )
            _required_string(row, "symbols")
            _decimal_string(row, "balance")
            _decimal_string(row, "value")
        timestamps = (result["updatedTime"],)
        timestamp_field = "result.updatedTime"
    elif logical_stream == "risk_limit":
        for row in rows:
            if type(row.get("id")) is not int:
                raise BybitPayloadError("Bybit risk-limit id must be an integer")
            for field in (
                "riskLimitValue",
                "maintenanceMargin",
                "initialMargin",
                "maxLeverage",
                "mmDeduction",
            ):
                _decimal_string(row, field, allow_empty=field == "mmDeduction")
            lowest = row.get("isLowestRisk")
            if type(lowest) is not int or lowest not in {0, 1}:
                raise BybitPayloadError("Bybit risk-limit isLowestRisk must be 0 or 1")
    elif logical_stream == "index_components":
        if result.get("indexName") != instrument.wire_symbol("index"):
            raise BybitPayloadError("Bybit index name does not match the instrument")
        _decimal_string(result, "lastPrice")
        _required_string(result, "updateTime")
        components = result.get("components")
        if not isinstance(components, (list, tuple)):
            raise BybitPayloadError("Bybit index components must be an array")
        for component_value in components:
            component = _mapping(component_value, field="Bybit index component")
            for field in ("exchange", "spotPair"):
                _required_string(component, field)
            for field in ("equivalentPrice", "multiplier", "price", "weight"):
                _decimal_string(component, field)
        timestamps = (result["updateTime"],)
        timestamp_field = "result.updateTime"
    event_time = (
        None
        if timestamp_field is None
        else _uniform_timestamp(timestamps, field=timestamp_field)
    )
    event_time_source = (
        None
        if event_time is None or timestamp_field is None
        else f"bybit.{timestamp_field.replace('[]', '[0]')}"
    )
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source=event_time_source,
    )


def parse_status(
    capture: BybitRestCapture,
    *,
    market: Market,
) -> NativeEventDraft:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    if (
        capture.request.path != BybitEndpoints.SYSTEM_STATUS
        or capture.request.logical_stream != "status"
    ):
        raise ValueError("capture is not a Bybit system-status response")
    result = _result(capture)
    for row in _rows(result):
        for field in ("id", "title", "state", "begin", "end", "href"):
            value = row.get(field)
            if field == "href":
                if type(value) is not str:
                    raise BybitPayloadError("Bybit status href must be a string")
            else:
                _required_string(row, field)
        _timestamp_ns(row["begin"], field="result.list[].begin")
        _timestamp_ns(row["end"], field="result.list[].end")
        for field in ("serviceTypes", "product", "uidSuffix"):
            values = row.get(field)
            if not isinstance(values, (list, tuple)) or any(
                type(value) is not int for value in values
            ):
                raise BybitPayloadError(
                    f"Bybit status {field} must be an integer array"
                )
        for field in ("maintainType", "env"):
            value = row.get(field)
            if type(value) is int:
                continue
            if type(value) is str and value:
                continue
            raise BybitPayloadError(
                f"Bybit status {field} must be a non-empty string or integer"
            )
    return NativeEventDraft(
        exchange=Exchange.BYBIT,
        market=market,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="status",
        native_channel=BybitEndpoints.SYSTEM_STATUS,
        transport=Transport.REST,
        event_time_ns=None,
        event_time_source=None,
        coverage=CoverageMode.UNKNOWN,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


def parse_public_time_ns(capture: BybitRestCapture) -> int:
    if (
        capture.request.path != BybitEndpoints.SERVER_TIME
        or capture.request.logical_stream != "_control"
    ):
        raise ValueError("capture is not a Bybit server-time response")
    result = _result(capture)
    seconds_text = _required_string(result, "timeSecond")
    nanoseconds_text = _required_string(result, "timeNano")
    if not seconds_text.isascii() or not seconds_text.isdigit():
        raise BybitPayloadError("Bybit timeSecond must be Unix seconds")
    if not nanoseconds_text.isascii() or not nanoseconds_text.isdigit():
        raise BybitPayloadError("Bybit timeNano must be Unix nanoseconds")
    nanoseconds = int(nanoseconds_text)
    if nanoseconds > _MAX_SIGNED_64 or nanoseconds // 1_000_000_000 != int(
        seconds_text
    ):
        raise BybitPayloadError(
            "Bybit timeSecond and timeNano must describe the same second"
        )
    return nanoseconds


def parse_announcements(
    capture: BybitRestCapture,
    *,
    market: Market,
) -> NativeEventDraft:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    if (
        capture.request.path != BybitEndpoints.ANNOUNCEMENTS
        or capture.request.logical_stream != "instrument"
    ):
        raise ValueError("capture is not a Bybit announcement response")
    result = _result(capture)
    if type(result.get("total")) is not int or cast(int, result["total"]) < 0:
        raise BybitPayloadError("Bybit announcement total must be non-negative integer")
    publish_times: list[object] = []
    publish_fields: set[str] = set()
    rows = _rows(result)
    every_row_has_publish_time = bool(rows)
    for row in rows:
        for field in ("title", "description", "url"):
            _optional_string(row, field)
        type_value = row.get("type")
        if type_value is not None:
            type_info = _mapping(type_value, field="Bybit announcement type")
            _optional_string(type_info, "title")
            _optional_string(type_info, "key")
        tags = row.get("tags")
        if tags is not None and (
            not isinstance(tags, (list, tuple))
            or any(type(tag) is not str for tag in tags)
        ):
            raise BybitPayloadError("Bybit announcement tags must be a string array")
        for field in (
            "dateTimestamp",
            "startDateTimestamp",
            "startDataTimestamp",
            "endDateTimestamp",
            "endDataTimestamp",
            "publishTime",
        ):
            value = row.get(field)
            if value is not None:
                _timestamp_ns(
                    value, field=f"result.list[].{field}", integer_allowed=True
                )
        publish_field = (
            "publishTime" if row.get("publishTime") is not None else "dateTimestamp"
        )
        publish = row.get(publish_field)
        if publish is None:
            every_row_has_publish_time = False
            continue
        publish_times.append(publish)
        publish_fields.add(publish_field)
    event_time = (
        _uniform_timestamp(
            tuple(publish_times),
            field=f"result.list[].{next(iter(publish_fields))}",
            integer_allowed=True,
        )
        if every_row_has_publish_time and len(publish_fields) == 1
        else None
    )
    event_source = (
        None
        if event_time is None
        else f"bybit.result.list[0].{next(iter(publish_fields))}"
    )
    return NativeEventDraft(
        exchange=Exchange.BYBIT,
        market=market,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="instrument",
        native_channel=BybitEndpoints.ANNOUNCEMENTS,
        transport=Transport.REST,
        event_time_ns=event_time,
        event_time_source=event_source,
        coverage=CoverageMode.UNKNOWN,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


__all__ = [
    "CANDLES_PATH",
    "DEEP_BOOK_PATH",
    "FULL_BOOK_PATH",
    "INSTRUMENTS_PATH",
    "PUBLIC_TIME_PATH",
    "RPI_BOOK_PATH",
    "STATUS_PATH",
    "TICKERS_PATH",
    "BybitEndpoints",
    "BybitRestCapture",
    "BybitRestRequest",
    "announcements_request",
    "candles_request",
    "capture_bybit_response",
    "deep_book_request",
    "derivative_reference_request",
    "full_book_request",
    "instruments_request",
    "parse_announcements",
    "parse_book",
    "parse_candles",
    "parse_derivative_reference",
    "parse_public_time_ns",
    "parse_recent_trades",
    "parse_reference_candles",
    "parse_status",
    "parse_ticker",
    "public_time_request",
    "recent_trades_request",
    "reference_candles_request",
    "rpi_book_request",
    "status_request",
    "tickers_request",
]
