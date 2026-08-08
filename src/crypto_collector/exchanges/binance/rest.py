from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import cast

import httpx

from crypto_collector.domain import (
    CoverageMode,
    IntegrityMode,
    Market,
    NativeEventDraft,
    RestMetadata,
    SourceContext,
    Transport,
)
from crypto_collector.domain.json_codec import (
    JsonPayload,
    ValidatedJsonPayload,
    decode_json,
    encode_json,
    validate_json_payload,
)
from crypto_collector.exchanges.binance.book import parse_book_snapshot
from crypto_collector.exchanges.binance.errors import (
    BinancePayloadError,
    inspect_binance_response,
)
from crypto_collector.exchanges.contracts import PublicQueryParams, PublicQueryValue
from crypto_collector.observability.redaction import SENSITIVE_QUERY_NAMES
from crypto_collector.scheduler import RestDispatch
from crypto_collector.selection import InstrumentRecord

SPOT_EXCHANGE_INFO_PATH = "/api/v3/exchangeInfo"
SPOT_DEPTH_PATH = "/api/v3/depth"
SPOT_TRADES_PATH = "/api/v3/trades"
SPOT_AGG_TRADES_PATH = "/api/v3/aggTrades"
SPOT_KLINES_PATH = "/api/v3/klines"
SPOT_TICKER_PATH = "/api/v3/ticker/24hr"
SPOT_PRICE_PATH = "/api/v3/ticker/price"
SPOT_BOOK_TICKER_PATH = "/api/v3/ticker/bookTicker"
SPOT_AVERAGE_PRICE_PATH = "/api/v3/avgPrice"
SPOT_REFERENCE_PRICE_PATH = "/api/v3/referencePrice"
SPOT_REFERENCE_CALCULATION_PATH = "/api/v3/referencePrice/calculation"
SPOT_EXECUTION_RULES_PATH = "/api/v3/executionRules"

FUTURES_EXCHANGE_INFO_PATH = "/fapi/v1/exchangeInfo"
FUTURES_DEPTH_PATH = "/fapi/v1/depth"
FUTURES_TRADES_PATH = "/fapi/v1/trades"
FUTURES_AGG_TRADES_PATH = "/fapi/v1/aggTrades"
FUTURES_KLINES_PATH = "/fapi/v1/klines"
FUTURES_INDEX_KLINES_PATH = "/fapi/v1/indexPriceKlines"
FUTURES_MARK_KLINES_PATH = "/fapi/v1/markPriceKlines"
FUTURES_PREMIUM_KLINES_PATH = "/fapi/v1/premiumIndexKlines"
FUTURES_TICKER_PATH = "/fapi/v1/ticker/24hr"
FUTURES_PRICE_PATH = "/fapi/v2/ticker/price"
FUTURES_BOOK_TICKER_PATH = "/fapi/v1/ticker/bookTicker"
FUTURES_PREMIUM_INDEX_PATH = "/fapi/v1/premiumIndex"
FUTURES_FUNDING_RATE_PATH = "/fapi/v1/fundingRate"
FUTURES_FUNDING_INFO_PATH = "/fapi/v1/fundingInfo"
FUTURES_OPEN_INTEREST_PATH = "/fapi/v1/openInterest"
FUTURES_OPEN_INTEREST_HISTORY_PATH = "/futures/data/openInterestHist"
FUTURES_INDEX_INFO_PATH = "/fapi/v1/indexInfo"
FUTURES_CONSTITUENTS_PATH = "/fapi/v1/constituents"
FUTURES_INSURANCE_PATH = "/fapi/v1/insuranceBalance"
FUTURES_ASSET_INDEX_PATH = "/fapi/v1/assetIndex"
FUTURES_ADL_RISK_PATH = "/fapi/v1/symbolAdlRisk"
FUTURES_TRADING_SCHEDULE_PATH = "/fapi/v1/tradingSchedule"

_SPOT_PATHS = frozenset(
    {
        SPOT_EXCHANGE_INFO_PATH,
        SPOT_DEPTH_PATH,
        SPOT_TRADES_PATH,
        SPOT_AGG_TRADES_PATH,
        SPOT_KLINES_PATH,
        SPOT_TICKER_PATH,
        SPOT_PRICE_PATH,
        SPOT_BOOK_TICKER_PATH,
        SPOT_AVERAGE_PRICE_PATH,
        SPOT_REFERENCE_PRICE_PATH,
        SPOT_REFERENCE_CALCULATION_PATH,
        SPOT_EXECUTION_RULES_PATH,
    }
)
_FUTURES_PATHS = frozenset(
    {
        FUTURES_EXCHANGE_INFO_PATH,
        FUTURES_DEPTH_PATH,
        FUTURES_TRADES_PATH,
        FUTURES_AGG_TRADES_PATH,
        FUTURES_KLINES_PATH,
        FUTURES_INDEX_KLINES_PATH,
        FUTURES_MARK_KLINES_PATH,
        FUTURES_PREMIUM_KLINES_PATH,
        FUTURES_TICKER_PATH,
        FUTURES_PRICE_PATH,
        FUTURES_BOOK_TICKER_PATH,
        FUTURES_PREMIUM_INDEX_PATH,
        FUTURES_FUNDING_RATE_PATH,
        FUTURES_FUNDING_INFO_PATH,
        FUTURES_OPEN_INTEREST_PATH,
        FUTURES_OPEN_INTEREST_HISTORY_PATH,
        FUTURES_INDEX_INFO_PATH,
        FUTURES_CONSTITUENTS_PATH,
        FUTURES_INSURANCE_PATH,
        FUTURES_ASSET_INDEX_PATH,
        FUTURES_ADL_RISK_PATH,
        FUTURES_TRADING_SCHEDULE_PATH,
    }
)
_KLINE_PATHS = frozenset(
    {
        SPOT_KLINES_PATH,
        FUTURES_KLINES_PATH,
        FUTURES_INDEX_KLINES_PATH,
        FUTURES_MARK_KLINES_PATH,
        FUTURES_PREMIUM_KLINES_PATH,
    }
)
_FUTURES_KLINE_PATHS = _KLINE_PATHS - {SPOT_KLINES_PATH}
_KLINE_INTERVALS = frozenset(
    {
        "1s",
        "1m",
        "3m",
        "5m",
        "15m",
        "30m",
        "1h",
        "2h",
        "4h",
        "6h",
        "8h",
        "12h",
        "1d",
        "3d",
        "1w",
        "1M",
    }
)
_OI_PERIODS = frozenset({"5m", "15m", "30m", "1h", "2h", "4h", "6h", "12h", "1d"})
_RATE_HEADER_PREFIXES = ("x-mbx-used-weight", "x-mbx-order-count")
_MAX_SIGNED_64 = 2**63 - 1
_TIME_ZONE = re.compile(r"(?P<sign>[+-]?)(?P<hours>\d{1,2})(?::(?P<minutes>\d{2}))?\Z")


@dataclass(frozen=True, slots=True)
class BinanceSpecialQuota:
    group: str
    limit: int
    window_seconds: int
    cost: int = 1

    def __post_init__(self) -> None:
        if type(self.group) is not str or not self.group:
            raise ValueError("special quota group must be non-empty")
        for name in ("limit", "window_seconds", "cost"):
            value = getattr(self, name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"special quota {name} must be positive")


@dataclass(frozen=True, slots=True)
class _RequestSchema:
    required: frozenset[str]
    allowed: frozenset[str]


_SCHEMAS = MappingProxyType(
    {
        SPOT_EXCHANGE_INFO_PATH: _RequestSchema(
            frozenset(),
            frozenset(
                {
                    "symbol",
                    "symbols",
                    "permissions",
                    "showPermissionSets",
                    "symbolStatus",
                }
            ),
        ),
        SPOT_DEPTH_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol", "limit", "symbolStatus"})
        ),
        SPOT_TRADES_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol", "limit"})
        ),
        SPOT_AGG_TRADES_PATH: _RequestSchema(
            frozenset({"symbol"}),
            frozenset({"symbol", "fromId", "startTime", "endTime", "limit"}),
        ),
        SPOT_KLINES_PATH: _RequestSchema(
            frozenset({"symbol", "interval"}),
            frozenset(
                {"symbol", "interval", "startTime", "endTime", "timeZone", "limit"}
            ),
        ),
        SPOT_TICKER_PATH: _RequestSchema(
            frozenset(), frozenset({"symbol", "symbols", "type", "symbolStatus"})
        ),
        SPOT_PRICE_PATH: _RequestSchema(
            frozenset(), frozenset({"symbol", "symbols", "symbolStatus"})
        ),
        SPOT_BOOK_TICKER_PATH: _RequestSchema(
            frozenset(), frozenset({"symbol", "symbols", "symbolStatus"})
        ),
        SPOT_AVERAGE_PRICE_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol"})
        ),
        SPOT_REFERENCE_PRICE_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol"})
        ),
        SPOT_REFERENCE_CALCULATION_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol", "symbolStatus"})
        ),
        SPOT_EXECUTION_RULES_PATH: _RequestSchema(
            frozenset(), frozenset({"symbol", "symbols", "symbolStatus"})
        ),
        FUTURES_EXCHANGE_INFO_PATH: _RequestSchema(frozenset(), frozenset()),
        FUTURES_DEPTH_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol", "limit"})
        ),
        FUTURES_TRADES_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol", "limit"})
        ),
        FUTURES_AGG_TRADES_PATH: _RequestSchema(
            frozenset({"symbol"}),
            frozenset({"symbol", "fromId", "startTime", "endTime", "limit"}),
        ),
        FUTURES_KLINES_PATH: _RequestSchema(
            frozenset({"symbol", "interval"}),
            frozenset({"symbol", "interval", "startTime", "endTime", "limit"}),
        ),
        FUTURES_INDEX_KLINES_PATH: _RequestSchema(
            frozenset({"pair", "interval"}),
            frozenset({"pair", "interval", "startTime", "endTime", "limit"}),
        ),
        FUTURES_MARK_KLINES_PATH: _RequestSchema(
            frozenset({"symbol", "interval"}),
            frozenset({"symbol", "interval", "startTime", "endTime", "limit"}),
        ),
        FUTURES_PREMIUM_KLINES_PATH: _RequestSchema(
            frozenset({"symbol", "interval"}),
            frozenset({"symbol", "interval", "startTime", "endTime", "limit"}),
        ),
        FUTURES_TICKER_PATH: _RequestSchema(frozenset(), frozenset({"symbol"})),
        FUTURES_PRICE_PATH: _RequestSchema(frozenset(), frozenset({"symbol"})),
        FUTURES_BOOK_TICKER_PATH: _RequestSchema(frozenset(), frozenset({"symbol"})),
        FUTURES_PREMIUM_INDEX_PATH: _RequestSchema(frozenset(), frozenset({"symbol"})),
        FUTURES_FUNDING_RATE_PATH: _RequestSchema(
            frozenset(), frozenset({"symbol", "startTime", "endTime", "limit"})
        ),
        FUTURES_FUNDING_INFO_PATH: _RequestSchema(frozenset(), frozenset()),
        FUTURES_OPEN_INTEREST_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol"})
        ),
        FUTURES_OPEN_INTEREST_HISTORY_PATH: _RequestSchema(
            frozenset({"symbol", "period"}),
            frozenset({"symbol", "period", "limit", "startTime", "endTime"}),
        ),
        FUTURES_INDEX_INFO_PATH: _RequestSchema(frozenset(), frozenset({"symbol"})),
        FUTURES_CONSTITUENTS_PATH: _RequestSchema(
            frozenset({"symbol"}), frozenset({"symbol"})
        ),
        FUTURES_INSURANCE_PATH: _RequestSchema(frozenset(), frozenset({"symbol"})),
        FUTURES_ASSET_INDEX_PATH: _RequestSchema(frozenset(), frozenset({"symbol"})),
        FUTURES_ADL_RISK_PATH: _RequestSchema(frozenset(), frozenset({"symbol"})),
        FUTURES_TRADING_SCHEDULE_PATH: _RequestSchema(frozenset(), frozenset()),
    }
)


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _normalize_params(value: PublicQueryParams) -> PublicQueryParams:
    if not isinstance(value, Mapping):
        raise TypeError("params must be a mapping")
    normalized: dict[str, PublicQueryValue | Sequence[PublicQueryValue]] = {}
    for key, item in value.items():
        name = _nonempty(key, field="query parameter name")
        if name.casefold() in SENSITIVE_QUERY_NAMES:
            raise ValueError("sensitive query parameters are not permitted")
        if isinstance(item, (list, tuple)):
            if name not in {"symbols", "permissions"}:
                raise TypeError(f"Binance {name} must be a scalar public query value")
            parts: list[PublicQueryValue] = []
            for part in item:
                if part is None or type(part) in {bool, int, str}:
                    parts.append(part)
                else:
                    raise TypeError("Binance query arrays must contain public scalars")
            normalized[name] = encode_json(parts).decode("utf-8")
        elif item is None or type(item) in {bool, int, str}:
            normalized[name] = cast(PublicQueryValue, item)
        else:
            raise TypeError("Binance query parameters must be public scalars")
    return MappingProxyType(normalized)


def _integer(
    params: PublicQueryParams, name: str, *, minimum: int, maximum: int
) -> int:
    value = params[name]
    if type(value) is not int:
        raise ValueError(f"Binance {name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"Binance {name} must be between {minimum} and {maximum}")
    return value


def _optional_time(params: PublicQueryParams, name: str) -> int | None:
    if name not in params:
        return None
    return _integer(params, name, minimum=0, maximum=_MAX_SIGNED_64)


def _string(params: PublicQueryParams, name: str) -> str:
    value = params[name]
    return _nonempty(value, field=f"Binance {name}")


def _symbols(params: PublicQueryParams) -> tuple[str, ...] | None:
    value = params.get("symbols")
    if value is None:
        return None
    if type(value) is not str:
        raise ValueError("Binance symbols must be a JSON array query value")
    try:
        decoded = decode_json(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Binance symbols must be a JSON array query value") from error
    if not isinstance(decoded, list) or not decoded:
        raise ValueError("Binance symbols must be a non-empty array")
    normalized: list[str] = []
    for item in decoded:
        normalized.append(_nonempty(item, field="Binance symbols entry"))
    return tuple(normalized)


def _permissions(params: PublicQueryParams) -> tuple[str, ...] | None:
    value = params.get("permissions")
    if value is None:
        return None
    if type(value) is not str or not value:
        raise ValueError("Binance permissions must be a non-empty enum or JSON array")
    if not value.startswith("["):
        return (value,)
    try:
        decoded = decode_json(value)
    except (TypeError, ValueError) as error:
        raise ValueError("Binance permissions must be a JSON string array") from error
    if not isinstance(decoded, list) or not decoded:
        raise ValueError("Binance permissions must be a non-empty array")
    return tuple(_nonempty(item, field="Binance permissions entry") for item in decoded)


def _time_zone(params: PublicQueryParams) -> None:
    value = _string(params, "timeZone")
    matched = _TIME_ZONE.fullmatch(value)
    if matched is None:
        raise ValueError("unsupported Binance timeZone")
    hours = int(matched.group("hours"))
    minutes = int(matched.group("minutes") or "0")
    if minutes > 59:
        raise ValueError("unsupported Binance timeZone")
    offset = hours * 60 + minutes
    if matched.group("sign") == "-":
        offset = -offset
    if not -12 * 60 <= offset <= 14 * 60:
        raise ValueError("unsupported Binance timeZone")


def _validate_params(path: str, params: PublicQueryParams) -> None:
    schema = _SCHEMAS[path]
    names = frozenset(params)
    unknown = names - schema.allowed
    if unknown:
        raise ValueError(
            f"unsupported Binance query parameter(s) for {path}: "
            + ", ".join(sorted(unknown))
        )
    missing = schema.required - names
    if missing:
        raise ValueError(
            f"missing required Binance query parameter(s) for {path}: "
            + ", ".join(sorted(missing))
        )
    for name in ("symbol", "pair"):
        if name in params:
            _string(params, name)
    for name in ("fromId", "startTime", "endTime"):
        if name in params:
            _optional_time(params, name)
    if "symbol" in params and "symbols" in params:
        raise ValueError("Binance symbol and symbols are mutually exclusive")
    symbols = _symbols(params)
    if symbols is not None and len(set(symbols)) != len(symbols):
        raise ValueError("Binance symbols must be unique")
    if path == SPOT_EXCHANGE_INFO_PATH:
        selector_count = sum(
            name in params for name in ("symbol", "symbols", "permissions")
        )
        if selector_count > 1:
            raise ValueError("Binance exchangeInfo selectors are mutually exclusive")
        if "symbolStatus" in params and selector_count:
            raise ValueError("Binance symbolStatus cannot accompany a symbol selector")
        if (
            "showPermissionSets" in params
            and type(params["showPermissionSets"]) is not bool
        ):
            raise TypeError("Binance showPermissionSets must be a boolean")
        permissions = _permissions(params)
        if permissions is not None and len(set(permissions)) != len(permissions):
            raise ValueError("Binance permissions must be unique")
    if path == SPOT_EXECUTION_RULES_PATH:
        selectors = sum(
            name in params for name in ("symbol", "symbols", "symbolStatus")
        )
        if selectors > 1:
            raise ValueError("Binance executionRules selectors are mutually exclusive")
    if "symbolStatus" in params:
        status = _string(params, "symbolStatus")
        if status not in {"TRADING", "HALT", "BREAK"}:
            raise ValueError("unsupported Binance symbolStatus")
    if (
        path in {SPOT_DEPTH_PATH, SPOT_TRADES_PATH, SPOT_AGG_TRADES_PATH}
        and "limit" in params
    ):
        maximum = 5_000 if path == SPOT_DEPTH_PATH else 1_000
        _integer(params, "limit", minimum=1, maximum=maximum)
    if path == FUTURES_DEPTH_PATH and "limit" in params:
        limit = _integer(params, "limit", minimum=5, maximum=1_000)
        if limit not in {5, 10, 20, 50, 100, 500, 1_000}:
            raise ValueError("unsupported Binance Futures depth limit")
    if (
        path
        in {FUTURES_TRADES_PATH, FUTURES_AGG_TRADES_PATH, FUTURES_FUNDING_RATE_PATH}
        and "limit" in params
    ):
        _integer(params, "limit", minimum=1, maximum=1_000)
    if path in _KLINE_PATHS:
        interval = _string(params, "interval")
        if interval not in _KLINE_INTERVALS or (
            path != SPOT_KLINES_PATH and interval == "1s"
        ):
            raise ValueError("unsupported Binance kline interval")
        if "limit" in params:
            _integer(
                params,
                "limit",
                minimum=1,
                maximum=1_000 if path == SPOT_KLINES_PATH else 1_500,
            )
    if path == SPOT_KLINES_PATH and "timeZone" in params:
        _time_zone(params)
    if (
        path == SPOT_TICKER_PATH
        and "type" in params
        and _string(params, "type") not in {"FULL", "MINI"}
    ):
        raise ValueError("unsupported Binance ticker type")
    if path == FUTURES_OPEN_INTEREST_HISTORY_PATH:
        if _string(params, "period") not in _OI_PERIODS:
            raise ValueError("unsupported Binance open-interest period")
        if "limit" in params:
            _integer(params, "limit", minimum=1, maximum=500)
    if path == FUTURES_AGG_TRADES_PATH:
        if "fromId" in params and ({"startTime", "endTime"} & set(params)):
            raise ValueError("Binance Futures fromId cannot accompany a time range")
        start = _optional_time(params, "startTime")
        end = _optional_time(params, "endTime")
        if (
            start is not None
            and end is not None
            and (end < start or end - start >= 3_600_000)
        ):
            raise ValueError(
                "Binance Futures aggregate-trade window must be under one hour"
            )


def _spot_depth_weight(limit: int) -> int:
    if limit <= 100:
        return 5
    if limit <= 500:
        return 25
    if limit <= 1_000:
        return 50
    return 250


def _futures_kline_weight(limit: int) -> int:
    if limit < 100:
        return 1
    if limit < 500:
        return 2
    if limit <= 1_000:
        return 5
    return 10


def _request_weight(market: Market, path: str, params: PublicQueryParams) -> int:
    if market is Market.SPOT:
        if path == SPOT_EXCHANGE_INFO_PATH:
            return 20
        if path == SPOT_DEPTH_PATH:
            return _spot_depth_weight(cast(int, params.get("limit", 100)))
        if path == SPOT_TRADES_PATH:
            return 25
        if path == SPOT_AGG_TRADES_PATH:
            return 4
        if path == SPOT_KLINES_PATH:
            return 2
        if path == SPOT_EXECUTION_RULES_PATH:
            symbols = _symbols(params)
            if "symbol" in params:
                return 2
            if symbols is not None:
                return min(40, len(symbols) * 2)
            return 40
        if path == SPOT_TICKER_PATH:
            symbols = _symbols(params)
            if "symbol" in params or (symbols is not None and len(symbols) <= 20):
                return 2
            if symbols is not None and len(symbols) <= 100:
                return 40
            return 80
        return 2 if "symbol" in params else 4
    if path == FUTURES_EXCHANGE_INFO_PATH:
        return 1
    if path == FUTURES_DEPTH_PATH:
        limit = cast(int, params.get("limit", 500))
        return 2 if limit <= 50 else 5 if limit == 100 else 10 if limit == 500 else 20
    if path == FUTURES_TRADES_PATH:
        return 5
    if path == FUTURES_AGG_TRADES_PATH:
        return 20
    if path in _FUTURES_KLINE_PATHS:
        return _futures_kline_weight(cast(int, params.get("limit", 500)))
    if path == FUTURES_TICKER_PATH:
        return 1 if "symbol" in params else 40
    if path == FUTURES_PRICE_PATH:
        return 1 if "symbol" in params else 2
    if path == FUTURES_BOOK_TICKER_PATH:
        return 2 if "symbol" in params else 5
    if path in {FUTURES_PREMIUM_INDEX_PATH, FUTURES_ASSET_INDEX_PATH}:
        return 1 if "symbol" in params else 10
    if path == FUTURES_CONSTITUENTS_PATH:
        return 2
    if path == FUTURES_TRADING_SCHEDULE_PATH:
        return 5
    if path in {FUTURES_FUNDING_INFO_PATH, FUTURES_OPEN_INTEREST_HISTORY_PATH}:
        return 0
    return 1


def _special_quota(path: str) -> BinanceSpecialQuota | None:
    if path in {FUTURES_FUNDING_RATE_PATH, FUTURES_FUNDING_INFO_PATH}:
        return BinanceSpecialQuota("funding-history", 500, 300)
    if path == FUTURES_OPEN_INTEREST_HISTORY_PATH:
        return BinanceSpecialQuota("open-interest-history", 1_000, 300)
    return None


@dataclass(frozen=True, slots=True)
class BinanceRestRequest:
    market: Market
    path: str
    params: PublicQueryParams
    logical_stream: str
    request_weight: int = field(init=False)
    special_quota: BinanceSpecialQuota | None = field(init=False)

    def __post_init__(self) -> None:
        if type(self.market) is not Market:
            raise TypeError("market must be Market")
        allowed = _SPOT_PATHS if self.market is Market.SPOT else _FUTURES_PATHS
        if self.path not in allowed:
            raise ValueError("path is not an evidenced Binance anonymous endpoint")
        params = _normalize_params(self.params)
        _validate_params(self.path, params)
        object.__setattr__(self, "params", params)
        object.__setattr__(
            self,
            "logical_stream",
            _nonempty(self.logical_stream, field="logical_stream"),
        )
        object.__setattr__(
            self, "request_weight", _request_weight(self.market, self.path, params)
        )
        object.__setattr__(self, "special_quota", _special_quota(self.path))


@dataclass(frozen=True, slots=True)
class BinanceRestCapture:
    payload: JsonPayload
    rest_metadata: RestMetadata
    source: SourceContext
    request: BinanceRestRequest

    def __post_init__(self) -> None:
        if type(self.rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(self.source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if type(self.request) is not BinanceRestRequest:
            raise TypeError("request must be BinanceRestRequest")
        if (
            self.rest_metadata.method != "GET"
            or not 200 <= self.rest_metadata.status < 300
        ):
            raise ValueError("Binance success capture requires GET and HTTP 2xx")
        if self.rest_metadata.path != self.request.path:
            raise ValueError("REST metadata path does not match request")
        if self.rest_metadata.params != _metadata_params(self.request):
            raise ValueError("REST metadata params do not match request")
        self.source.validate_for(
            transport=Transport.REST, logical_stream=self.request.logical_stream
        )


@dataclass(frozen=True, slots=True)
class BinanceMarketRestPayload:
    capture: BinanceRestCapture
    identities: tuple[str, ...]
    event_time_ns: int | None
    event_time_source: str | None

    def __post_init__(self) -> None:
        if type(self.capture) is not BinanceRestCapture:
            raise TypeError("capture must be BinanceRestCapture")
        if self.capture.request.market is not Market.PERPETUAL:
            raise ValueError("market REST payload must belong to Binance Futures")
        if type(self.identities) is not tuple or any(
            type(value) is not str or not value for value in self.identities
        ):
            raise TypeError("identities must be a tuple of non-empty strings")
        if len(set(self.identities)) != len(self.identities):
            raise ValueError("market REST identities must be unique")
        if (self.event_time_ns is None) != (self.event_time_source is None):
            raise ValueError("event time and source must be paired")
        if self.event_time_ns is not None:
            if type(self.event_time_ns) is not int:
                raise TypeError("event_time_ns must be an integer or None")
            if not 0 <= self.event_time_ns <= _MAX_SIGNED_64:
                raise ValueError("event_time_ns must fit signed 64-bit nanoseconds")
        if self.event_time_source is not None and (
            type(self.event_time_source) is not str or not self.event_time_source
        ):
            raise TypeError("event_time_source must be a non-empty string or None")

    @property
    def payload(self) -> JsonPayload:
        return self.capture.payload


def _binance_instrument(
    instrument: InstrumentRecord, *, market: Market | None = None
) -> None:
    if not isinstance(instrument, InstrumentRecord):
        raise TypeError("instrument must be InstrumentRecord")
    if instrument.exchange.value != "binance":
        raise ValueError("instrument must belong to Binance")
    if market is not None and instrument.market is not market:
        raise ValueError("instrument does not belong to the required market")


def exchange_info_request(market: Market) -> BinanceRestRequest:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    return BinanceRestRequest(
        market,
        SPOT_EXCHANGE_INFO_PATH
        if market is Market.SPOT
        else FUTURES_EXCHANGE_INFO_PATH,
        {},
        "instrument",
    )


def book_request(
    instrument: InstrumentRecord,
    *,
    depth: int,
    logical_stream: str = "book_deep_snapshot",
) -> BinanceRestRequest:
    _binance_instrument(instrument)
    if logical_stream not in {"book_deep_snapshot", "book_live_bootstrap"}:
        raise ValueError("unsupported Binance book REST logical stream")
    return BinanceRestRequest(
        instrument.market,
        SPOT_DEPTH_PATH if instrument.market is Market.SPOT else FUTURES_DEPTH_PATH,
        {"symbol": instrument.wire_symbol("rest"), "limit": depth},
        logical_stream,
    )


def ticker_request(
    instrument: InstrumentRecord | None, *, market: Market
) -> BinanceRestRequest:
    if instrument is not None:
        _binance_instrument(instrument, market=market)
    return BinanceRestRequest(
        market,
        SPOT_TICKER_PATH if market is Market.SPOT else FUTURES_TICKER_PATH,
        {} if instrument is None else {"symbol": instrument.wire_symbol("rest")},
        "ticker",
    )


def bbo_request(instrument: InstrumentRecord) -> BinanceRestRequest:
    _binance_instrument(instrument)
    return BinanceRestRequest(
        instrument.market,
        SPOT_BOOK_TICKER_PATH
        if instrument.market is Market.SPOT
        else FUTURES_BOOK_TICKER_PATH,
        {"symbol": instrument.wire_symbol("rest")},
        "bbo",
    )


def price_request(instrument: InstrumentRecord) -> BinanceRestRequest:
    _binance_instrument(instrument)
    return BinanceRestRequest(
        instrument.market,
        SPOT_PRICE_PATH if instrument.market is Market.SPOT else FUTURES_PRICE_PATH,
        {"symbol": instrument.wire_symbol("rest")},
        "price",
    )


def trades_request(
    instrument: InstrumentRecord, *, aggregate: bool = False, limit: int = 1_000
) -> BinanceRestRequest:
    _binance_instrument(instrument)
    path = (
        SPOT_AGG_TRADES_PATH
        if instrument.market is Market.SPOT and aggregate
        else SPOT_TRADES_PATH
        if instrument.market is Market.SPOT
        else FUTURES_AGG_TRADES_PATH
        if aggregate
        else FUTURES_TRADES_PATH
    )
    return BinanceRestRequest(
        instrument.market,
        path,
        {"symbol": instrument.wire_symbol("rest"), "limit": limit},
        "trade",
    )


def candles_request(
    instrument: InstrumentRecord,
    *,
    interval: str = "1m",
    limit: int = 500,
) -> BinanceRestRequest:
    _binance_instrument(instrument)
    return BinanceRestRequest(
        instrument.market,
        SPOT_KLINES_PATH if instrument.market is Market.SPOT else FUTURES_KLINES_PATH,
        {
            "symbol": instrument.wire_symbol("rest"),
            "interval": interval,
            "limit": limit,
        },
        f"candle_{interval}",
    )


_DERIVATIVE_KLINE_PATHS = MappingProxyType(
    {
        "index_candle": FUTURES_INDEX_KLINES_PATH,
        "mark_price_candle": FUTURES_MARK_KLINES_PATH,
        "premium_candle": FUTURES_PREMIUM_KLINES_PATH,
    }
)


def derivative_kline_request(
    logical_stream: str,
    instrument: InstrumentRecord,
    *,
    interval: str = "1m",
    limit: int = 500,
) -> BinanceRestRequest:
    _binance_instrument(instrument, market=Market.PERPETUAL)
    try:
        path = _DERIVATIVE_KLINE_PATHS[logical_stream]
    except KeyError:
        raise ValueError("unsupported Binance derivative kline stream") from None
    identity_name = "pair" if path == FUTURES_INDEX_KLINES_PATH else "symbol"
    identity = (
        instrument.wire_symbol("pair")
        if identity_name == "pair"
        else instrument.wire_symbol("rest")
    )
    return BinanceRestRequest(
        Market.PERPETUAL,
        path,
        {identity_name: identity, "interval": interval, "limit": limit},
        f"{logical_stream}_{interval}",
    )


_SPOT_REFERENCE_PATHS = MappingProxyType(
    {
        "average_price": SPOT_AVERAGE_PRICE_PATH,
        "reference_price": SPOT_REFERENCE_PRICE_PATH,
        "reference_price_calculation": SPOT_REFERENCE_CALCULATION_PATH,
        "execution_rules": SPOT_EXECUTION_RULES_PATH,
    }
)


def spot_reference_request(
    logical_stream: str,
    instrument: InstrumentRecord,
) -> BinanceRestRequest:
    _binance_instrument(instrument, market=Market.SPOT)
    try:
        path = _SPOT_REFERENCE_PATHS[logical_stream]
    except KeyError:
        raise ValueError("unsupported Binance Spot reference stream") from None
    return BinanceRestRequest(
        Market.SPOT,
        path,
        {"symbol": instrument.wire_symbol("rest")},
        logical_stream,
    )


_REFERENCE_PATHS = MappingProxyType(
    {
        "mark_price": FUTURES_PREMIUM_INDEX_PATH,
        "premium": FUTURES_PREMIUM_INDEX_PATH,
        "funding_rate": FUTURES_FUNDING_RATE_PATH,
        "funding_info": FUTURES_FUNDING_INFO_PATH,
        "open_interest": FUTURES_OPEN_INTEREST_PATH,
        "open_interest_history": FUTURES_OPEN_INTEREST_HISTORY_PATH,
        "index_info": FUTURES_INDEX_INFO_PATH,
        "index_constituents": FUTURES_CONSTITUENTS_PATH,
        "insurance_fund": FUTURES_INSURANCE_PATH,
        "asset_index": FUTURES_ASSET_INDEX_PATH,
        "adl_risk": FUTURES_ADL_RISK_PATH,
        "trading_schedule": FUTURES_TRADING_SCHEDULE_PATH,
    }
)


def derivative_reference_request(
    logical_stream: str,
    instrument: InstrumentRecord | None = None,
    *,
    asset_pair: str | None = None,
    index_symbol: str | None = None,
) -> BinanceRestRequest:
    try:
        path = _REFERENCE_PATHS[logical_stream]
    except KeyError:
        raise ValueError("unsupported Binance derivative reference stream") from None
    if instrument is not None:
        _binance_instrument(instrument, market=Market.PERPETUAL)
    if path == FUTURES_ASSET_INDEX_PATH:
        if instrument is not None:
            raise ValueError("asset_index uses an asset pair, not a contract symbol")
        if index_symbol is not None:
            raise ValueError("index_symbol is valid only for Binance index_info")
        asset_params: dict[str, PublicQueryValue] = (
            {}
            if asset_pair is None
            else {"symbol": _nonempty(asset_pair, field="asset_pair")}
        )
        return BinanceRestRequest(Market.PERPETUAL, path, asset_params, logical_stream)
    if path == FUTURES_INDEX_INFO_PATH:
        if instrument is not None:
            raise ValueError("index_info uses an index symbol, not a contract symbol")
        if asset_pair is not None:
            raise ValueError("asset_pair is valid only for Binance asset_index")
        index_params: dict[str, PublicQueryValue] = (
            {}
            if index_symbol is None
            else {"symbol": _nonempty(index_symbol, field="index_symbol")}
        )
        return BinanceRestRequest(Market.PERPETUAL, path, index_params, logical_stream)
    if asset_pair is not None:
        raise ValueError("asset_pair is valid only for Binance asset_index")
    if index_symbol is not None:
        raise ValueError("index_symbol is valid only for Binance index_info")
    requires_instrument = path in {
        FUTURES_OPEN_INTEREST_PATH,
        FUTURES_OPEN_INTEREST_HISTORY_PATH,
        FUTURES_CONSTITUENTS_PATH,
    }
    if requires_instrument and instrument is None:
        raise ValueError(f"{logical_stream} requires an instrument")
    params: dict[str, PublicQueryValue] = {}
    if instrument is not None:
        params["symbol"] = instrument.wire_symbol("rest")
    if path == FUTURES_OPEN_INTEREST_HISTORY_PATH:
        params["period"] = "5m"
        params["limit"] = 500
    return BinanceRestRequest(Market.PERPETUAL, path, params, logical_stream)


def _rate_limit_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.casefold() == "retry-after"
        or name.casefold().startswith(_RATE_HEADER_PREFIXES)
    }


def _metadata_params(request: BinanceRestRequest) -> dict[str, ValidatedJsonPayload]:
    return {
        name: validate_json_payload(list(value) if isinstance(value, tuple) else value)
        for name, value in request.params.items()
    }


def capture_binance_response(
    response: httpx.Response,
    *,
    dispatch: RestDispatch,
    request: BinanceRestRequest,
    request_started_at_ns: int,
    request_ended_at_ns: int,
) -> BinanceRestCapture:
    if type(dispatch) is not RestDispatch:
        raise TypeError("dispatch must be RestDispatch")
    if type(request) is not BinanceRestRequest:
        raise TypeError("request must be BinanceRestRequest")
    logical_key = dispatch.job.logical_key
    if logical_key is not None and logical_key[-1] != request.logical_stream:
        raise ValueError("dispatch logical stream does not match Binance request")
    metadata_params = _metadata_params(request)
    metadata = dispatch.build_rest_metadata(
        request_started_at_ns=request_started_at_ns,
        request_ended_at_ns=request_ended_at_ns,
        method="GET",
        path=request.path,
        params=metadata_params,
        status=response.status_code,
        rate_limit_headers=_rate_limit_headers(response.headers),
    )
    inspection = inspect_binance_response(response)
    if inspection.error is not None:
        raise inspection.error.attach_request_evidence(
            rest_metadata=metadata, source=dispatch.source_context
        )
    if inspection.payload is None:  # pragma: no cover - guarded by inspection.
        raise BinancePayloadError("Binance success response has no payload")
    return BinanceRestCapture(
        payload=inspection.payload,
        rest_metadata=metadata,
        source=dispatch.source_context,
        request=request,
    )


def _capture_rows(capture: BinanceRestCapture) -> tuple[Mapping[str, JsonPayload], ...]:
    if type(capture) is not BinanceRestCapture:
        raise TypeError("capture must be BinanceRestCapture")
    payload = capture.payload
    if isinstance(payload, Mapping):
        values: Sequence[object] = (payload,)
    elif isinstance(payload, list):
        values = payload
    else:
        raise BinancePayloadError("Binance response must be an object or array")
    rows: list[Mapping[str, JsonPayload]] = []
    for index, value in enumerate(values):
        if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
            raise BinancePayloadError(f"Binance response row {index} must be an object")
        rows.append(cast(Mapping[str, JsonPayload], value))
    return tuple(rows)


def _single_row(capture: BinanceRestCapture) -> Mapping[str, JsonPayload]:
    rows = _capture_rows(capture)
    if len(rows) != 1:
        raise BinancePayloadError("Binance response must contain exactly one row")
    return rows[0]


def _response_string(row: Mapping[str, JsonPayload], name: str) -> str:
    value = row.get(name)
    if type(value) is not str or not value:
        raise BinancePayloadError(f"Binance response {name} must be a non-empty string")
    return value


def _response_int(row: Mapping[str, JsonPayload], name: str) -> int:
    value = row.get(name)
    if type(value) is not int or value < 0:
        raise BinancePayloadError(
            f"Binance response {name} must be non-negative integer"
        )
    return value


def _response_bool(row: Mapping[str, JsonPayload], name: str) -> bool:
    value = row.get(name)
    if type(value) is not bool:
        raise BinancePayloadError(f"Binance response {name} must be a boolean")
    return value


def _response_decimal(
    row: Mapping[str, JsonPayload],
    name: str,
    *,
    nullable: bool = False,
    non_negative: bool = False,
) -> Decimal | None:
    value = row.get(name)
    if value is None and nullable:
        return None
    if type(value) is not str or not value:
        raise BinancePayloadError(f"Binance response {name} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise BinancePayloadError(
            f"Binance response {name} must be a decimal string"
        ) from error
    if not parsed.is_finite():
        raise BinancePayloadError(f"Binance response {name} must be finite")
    if non_negative and parsed < 0:
        raise BinancePayloadError(f"Binance response {name} must be non-negative")
    return parsed


def _timestamp_ns(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise BinancePayloadError(f"Binance response {field} must be Unix milliseconds")
    timestamp = value * 1_000_000
    if timestamp > _MAX_SIGNED_64:
        raise BinancePayloadError(f"Binance response {field} overflows nanoseconds")
    return timestamp


def _uniform_timestamp(
    rows: Sequence[Mapping[str, JsonPayload]], *, field: str
) -> int | None:
    if not rows:
        return None
    values = tuple(_timestamp_ns(row.get(field), field=field) for row in rows)
    return values[0] if all(value == values[0] for value in values[1:]) else None


def _validate_request_instrument(
    capture: BinanceRestCapture,
    instrument: InstrumentRecord,
    *,
    identity_field: str = "symbol",
) -> None:
    _binance_instrument(instrument)
    if capture.request.market is not instrument.market:
        raise ValueError("Binance response market does not match instrument")
    protocol = "pair" if identity_field == "pair" else "rest"
    if capture.request.params.get(identity_field) != instrument.wire_symbol(protocol):
        raise ValueError("Binance request identity does not match instrument")


def _validate_response_symbol(
    row: Mapping[str, JsonPayload], instrument: InstrumentRecord
) -> None:
    if _response_string(row, "symbol") != instrument.wire_symbol("rest"):
        raise BinancePayloadError("Binance response symbol does not match request")
    if instrument.market is Market.PERPETUAL and "st" in row:
        indicator = row["st"]
        if type(indicator) is not int or indicator != 1:
            raise BinancePayloadError("Binance response is not proven USD-M")


def _instrument_event(
    capture: BinanceRestCapture,
    *,
    instrument: InstrumentRecord,
    event_time_ns: int | None,
    event_time_source: str | None,
    integrity_mode: IntegrityMode | None = None,
    coverage: CoverageMode | None = None,
) -> NativeEventDraft:
    if (event_time_ns is None) != (event_time_source is None):
        raise ValueError("event time and source must be paired")
    return NativeEventDraft(
        exchange=instrument.exchange,
        market=instrument.market,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        logical_stream=capture.request.logical_stream,
        native_channel=capture.request.path,
        transport=Transport.REST,
        event_time_ns=event_time_ns,
        event_time_source=event_time_source,
        integrity_mode=integrity_mode,
        coverage=coverage,
        rest_metadata=capture.rest_metadata,
        payload=capture.payload,
    )


def parse_deep_book(
    capture: BinanceRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    expected_path = (
        SPOT_DEPTH_PATH if instrument.market is Market.SPOT else FUTURES_DEPTH_PATH
    )
    if capture.request.path != expected_path or capture.request.logical_stream not in {
        "book_deep_snapshot",
        "book_live_bootstrap",
    }:
        raise ValueError("capture is not a Binance depth snapshot")
    _validate_request_instrument(capture, instrument)
    snapshot = parse_book_snapshot(capture.payload, instrument.market)
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=snapshot.event_time_ns,
        event_time_source=(
            "binance.payload.E" if snapshot.event_time_ns is not None else None
        ),
        integrity_mode=IntegrityMode.SNAPSHOT_CHAIN,
        coverage=CoverageMode.COMPLETE,
    )


def parse_ticker(
    capture: BinanceRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    expected_path = (
        SPOT_TICKER_PATH if instrument.market is Market.SPOT else FUTURES_TICKER_PATH
    )
    if (
        capture.request.path != expected_path
        or capture.request.logical_stream != "ticker"
    ):
        raise ValueError("capture is not a Binance instrument ticker")
    _validate_request_instrument(capture, instrument)
    row = _single_row(capture)
    _validate_response_symbol(row, instrument)
    for field_name in ("lastPrice", "volume", "quoteVolume"):
        _response_decimal(row, field_name, non_negative=True)
    _response_int(row, "openTime")
    event_time = _timestamp_ns(row.get("closeTime"), field="closeTime")
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source="binance.payload.closeTime",
    )


def parse_price(
    capture: BinanceRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    expected_path = (
        SPOT_PRICE_PATH if instrument.market is Market.SPOT else FUTURES_PRICE_PATH
    )
    if (
        capture.request.path != expected_path
        or capture.request.logical_stream != "price"
    ):
        raise ValueError("capture is not a Binance instrument price")
    _validate_request_instrument(capture, instrument)
    row = _single_row(capture)
    _validate_response_symbol(row, instrument)
    _response_decimal(row, "price", non_negative=True)
    event_time = (
        None
        if instrument.market is Market.SPOT
        else _timestamp_ns(row.get("time"), field="time")
    )
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source=(None if event_time is None else "binance.payload.time"),
    )


def parse_bbo(
    capture: BinanceRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    expected_path = (
        SPOT_BOOK_TICKER_PATH
        if instrument.market is Market.SPOT
        else FUTURES_BOOK_TICKER_PATH
    )
    if capture.request.path != expected_path or capture.request.logical_stream != "bbo":
        raise ValueError("capture is not a Binance instrument BBO")
    _validate_request_instrument(capture, instrument)
    row = _single_row(capture)
    _validate_response_symbol(row, instrument)
    for field_name in ("bidPrice", "bidQty", "askPrice", "askQty"):
        _response_decimal(row, field_name, non_negative=True)
    event_time = (
        None
        if instrument.market is Market.SPOT
        else _timestamp_ns(row.get("time"), field="time")
    )
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source=(None if event_time is None else "binance.payload.time"),
    )


def parse_trades(
    capture: BinanceRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    expected_paths = (
        {SPOT_TRADES_PATH, SPOT_AGG_TRADES_PATH}
        if instrument.market is Market.SPOT
        else {FUTURES_TRADES_PATH, FUTURES_AGG_TRADES_PATH}
    )
    if (
        capture.request.path not in expected_paths
        or capture.request.logical_stream != "trade"
    ):
        raise ValueError("capture is not a Binance trades response")
    _validate_request_instrument(capture, instrument)
    if not isinstance(capture.payload, list):
        raise BinancePayloadError("Binance trades response must be an array")
    rows = _capture_rows(capture)
    aggregate = capture.request.path in {SPOT_AGG_TRADES_PATH, FUTURES_AGG_TRADES_PATH}
    timestamp_field = "T" if aggregate else "time"
    for row in rows:
        if aggregate:
            for field_name in ("a", "f", "l"):
                _response_int(row, field_name)
            for field_name in ("p", "q"):
                _response_decimal(row, field_name, non_negative=True)
            _response_bool(row, "m")
        else:
            _response_int(row, "id")
            for field_name in ("price", "qty", "quoteQty"):
                _response_decimal(row, field_name, non_negative=True)
            _response_bool(row, "isBuyerMaker")
        _timestamp_ns(row.get(timestamp_field), field=timestamp_field)
    event_time = _uniform_timestamp(rows, field=timestamp_field)
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source=(
            None if event_time is None else f"binance.payload[].{timestamp_field}"
        ),
    )


def parse_candles(
    capture: BinanceRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    if capture.request.path not in _KLINE_PATHS:
        raise ValueError("capture is not a Binance kline response")
    identity_field = (
        "pair" if capture.request.path == FUTURES_INDEX_KLINES_PATH else "symbol"
    )
    _validate_request_instrument(capture, instrument, identity_field=identity_field)
    interval = capture.request.params.get("interval")
    prefixes = {
        SPOT_KLINES_PATH: "candle_",
        FUTURES_KLINES_PATH: "candle_",
        FUTURES_INDEX_KLINES_PATH: "index_candle_",
        FUTURES_MARK_KLINES_PATH: "mark_price_candle_",
        FUTURES_PREMIUM_KLINES_PATH: "premium_candle_",
    }
    if (
        type(interval) is not str
        or capture.request.logical_stream != prefixes[capture.request.path] + interval
    ):
        raise ValueError("Binance kline interval does not match logical stream")
    if not isinstance(capture.payload, list):
        raise BinancePayloadError("Binance kline response must be an array")
    timestamps: list[int] = []
    for index, value in enumerate(capture.payload):
        if not isinstance(value, list) or len(value) < 12:
            raise BinancePayloadError(
                f"Binance kline row {index} must contain at least 12 fields"
            )
        timestamps.append(_timestamp_ns(value[0], field=f"[{index}][0]"))
        for field_index in (1, 2, 3, 4, 5, 7, 9, 10):
            pseudo = {"value": value[field_index]}
            signed_premium = (
                capture.request.path == FUTURES_PREMIUM_KLINES_PATH
                and field_index in {1, 2, 3, 4}
            )
            _response_decimal(
                pseudo,
                "value",
                non_negative=not signed_premium,
            )
        _timestamp_ns(value[6], field=f"[{index}][6]")
        if type(value[8]) is not int or value[8] < 0:
            raise BinancePayloadError("Binance kline trade count must be non-negative")
    event_time = (
        timestamps[0]
        if timestamps and all(item == timestamps[0] for item in timestamps[1:])
        else None
    )
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source=(None if event_time is None else "binance.payload[][0]"),
    )


def parse_spot_reference(
    capture: BinanceRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    _binance_instrument(instrument, market=Market.SPOT)
    logical_stream = capture.request.logical_stream
    if _SPOT_REFERENCE_PATHS.get(logical_stream) != capture.request.path:
        raise ValueError("capture is not a configured Binance Spot reference response")
    _validate_request_instrument(capture, instrument)
    row = _single_row(capture)
    event_time: int | None = None
    source: str | None = None
    if logical_stream == "average_price":
        _response_int(row, "mins")
        _response_decimal(row, "price", non_negative=True)
        event_time = _timestamp_ns(row.get("closeTime"), field="closeTime")
        source = "binance.payload.closeTime"
    elif logical_stream == "reference_price":
        _validate_response_symbol(row, instrument)
        _response_decimal(row, "referencePrice", nullable=True, non_negative=True)
        event_time = _timestamp_ns(row.get("timestamp"), field="timestamp")
        source = "binance.payload.timestamp"
    elif logical_stream == "reference_price_calculation":
        _validate_response_symbol(row, instrument)
        _response_string(row, "calculationType")
    else:
        rules = row.get("symbolRules")
        if not isinstance(rules, list):
            raise BinancePayloadError(
                "Binance executionRules requires symbolRules array"
            )
        for value in rules:
            if not isinstance(value, Mapping):
                raise BinancePayloadError("Binance symbolRules entries must be objects")
            mapped = cast(Mapping[str, JsonPayload], value)
            _validate_response_symbol(mapped, instrument)
            if not isinstance(mapped.get("rules"), list):
                raise BinancePayloadError("Binance symbolRules requires rules array")
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source=source,
    )


_DERIVATIVE_REFERENCE_EVENT_FIELDS = MappingProxyType(
    {
        "mark_price": "time",
        "premium": "time",
        "funding_rate": "fundingTime",
        "open_interest": "time",
        "open_interest_history": "timestamp",
        "index_constituents": "time",
        "adl_risk": "updateTime",
    }
)


def parse_insurance_fund(capture: BinanceRestCapture) -> BinanceMarketRestPayload:
    if (
        capture.request.path != FUTURES_INSURANCE_PATH
        or capture.request.logical_stream != "insurance_fund"
    ):
        raise ValueError("capture is not a Binance insurance-fund response")
    groups = _capture_rows(capture)
    identities: list[str] = []
    asset_rows: list[Mapping[str, JsonPayload]] = []
    for row in groups:
        symbols = row.get("symbols")
        if not isinstance(symbols, list) or not symbols:
            raise BinancePayloadError(
                "Binance insurance response requires non-empty symbols array"
            )
        for value in symbols:
            if type(value) is not str or not value:
                raise BinancePayloadError(
                    "Binance insurance symbols must be non-empty strings"
                )
            identity = value
            if identity in identities:
                raise BinancePayloadError(
                    "Binance insurance response contains duplicate symbols"
                )
            identities.append(identity)
        assets = row.get("assets")
        if not isinstance(assets, list) or not assets:
            raise BinancePayloadError(
                "Binance insurance response requires non-empty assets array"
            )
        for value in assets:
            if not isinstance(value, Mapping):
                raise BinancePayloadError("Binance insurance assets must be objects")
            asset = cast(Mapping[str, JsonPayload], value)
            _response_string(asset, "asset")
            _response_decimal(asset, "marginBalance", non_negative=True)
            _timestamp_ns(asset.get("updateTime"), field="assets[].updateTime")
            asset_rows.append(asset)
    requested = capture.request.params.get("symbol")
    if requested is not None and requested not in identities:
        raise BinancePayloadError(
            "Binance insurance response symbols do not include request"
        )
    event_time = _uniform_timestamp(asset_rows, field="updateTime")
    return BinanceMarketRestPayload(
        capture,
        tuple(identities),
        event_time,
        None if event_time is None else "binance.payload[].assets[].updateTime",
    )


def parse_funding_info(capture: BinanceRestCapture) -> BinanceMarketRestPayload:
    if (
        capture.request.path != FUTURES_FUNDING_INFO_PATH
        or capture.request.logical_stream != "funding_info"
        or capture.request.params
    ):
        raise ValueError("capture is not a Binance funding-info batch")
    if not isinstance(capture.payload, list):
        raise BinancePayloadError("Binance fundingInfo response must be an array")
    rows = _capture_rows(capture)
    identities: list[str] = []
    for row in rows:
        identities.append(_response_string(row, "symbol"))
        for field_name in ("adjustedFundingRateCap", "adjustedFundingRateFloor"):
            _response_decimal(row, field_name)
        interval = _response_int(row, "fundingIntervalHours")
        if interval == 0:
            raise BinancePayloadError("Binance fundingIntervalHours must be positive")
        _response_bool(row, "disclaimer")
        _timestamp_ns(row.get("updateTime"), field="updateTime")
    event_time = _uniform_timestamp(rows, field="updateTime")
    return BinanceMarketRestPayload(
        capture,
        tuple(identities),
        event_time,
        None if event_time is None else "binance.payload[].updateTime",
    )


def parse_asset_index(capture: BinanceRestCapture) -> BinanceMarketRestPayload:
    if (
        capture.request.path != FUTURES_ASSET_INDEX_PATH
        or capture.request.logical_stream != "asset_index"
    ):
        raise ValueError("capture is not a Binance asset-index response")
    rows = _capture_rows(capture)
    identities: list[str] = []
    requested = capture.request.params.get("symbol")
    for row in rows:
        identity = _response_string(row, "symbol")
        if requested is not None and identity != requested:
            raise BinancePayloadError(
                "Binance asset-index symbol does not match request"
            )
        identities.append(identity)
        _timestamp_ns(row.get("time"), field="time")
        for field_name in (
            "index",
            "bidBuffer",
            "askBuffer",
            "bidRate",
            "askRate",
            "autoExchangeBidBuffer",
            "autoExchangeAskBuffer",
            "autoExchangeBidRate",
            "autoExchangeAskRate",
        ):
            _response_decimal(row, field_name, non_negative=True)
    event_time = _uniform_timestamp(rows, field="time")
    return BinanceMarketRestPayload(
        capture,
        tuple(identities),
        event_time,
        None if event_time is None else "binance.payload[].time",
    )


def parse_index_info(capture: BinanceRestCapture) -> BinanceMarketRestPayload:
    if (
        capture.request.path != FUTURES_INDEX_INFO_PATH
        or capture.request.logical_stream != "index_info"
    ):
        raise ValueError("capture is not a Binance index-info response")
    rows = _capture_rows(capture)
    identities: list[str] = []
    requested = capture.request.params.get("symbol")
    for row in rows:
        identity = _response_string(row, "symbol")
        if requested is not None and identity != requested:
            raise BinancePayloadError(
                "Binance index-info symbol does not match request"
            )
        identities.append(identity)
        _timestamp_ns(row.get("time"), field="time")
        _response_string(row, "component")
        components = row.get("baseAssetList")
        if not isinstance(components, list):
            raise BinancePayloadError("Binance indexInfo requires baseAssetList array")
        for component in components:
            if not isinstance(component, Mapping):
                raise BinancePayloadError(
                    "Binance indexInfo base assets must be objects"
                )
            mapped = cast(Mapping[str, JsonPayload], component)
            for field_name in ("baseAsset", "quoteAsset"):
                _response_string(mapped, field_name)
            for field_name in ("weightInQuantity", "weightInPercentage"):
                _response_decimal(mapped, field_name, non_negative=True)
    event_time = _uniform_timestamp(rows, field="time")
    return BinanceMarketRestPayload(
        capture,
        tuple(identities),
        event_time,
        None if event_time is None else "binance.payload[].time",
    )


def parse_trading_schedule(
    capture: BinanceRestCapture,
) -> BinanceMarketRestPayload:
    if (
        capture.request.path != FUTURES_TRADING_SCHEDULE_PATH
        or capture.request.logical_stream != "trading_schedule"
        or capture.request.params
    ):
        raise ValueError("capture is not a Binance trading-schedule response")
    row = _single_row(capture)
    event_time = _timestamp_ns(row.get("updateTime"), field="updateTime")
    schedules = row.get("marketSchedules")
    if not isinstance(schedules, Mapping) or not schedules:
        raise BinancePayloadError(
            "Binance tradingSchedule requires non-empty marketSchedules object"
        )
    for category, category_value in schedules.items():
        if type(category) is not str or not category:
            raise BinancePayloadError(
                "Binance tradingSchedule category must be non-empty"
            )
        if not isinstance(category_value, Mapping):
            raise BinancePayloadError(
                "Binance tradingSchedule category must be an object"
            )
        sessions = category_value.get("sessions")
        if not isinstance(sessions, list):
            raise BinancePayloadError(
                "Binance tradingSchedule category requires sessions array"
            )
        previous_end: int | None = None
        for session in sessions:
            if not isinstance(session, Mapping):
                raise BinancePayloadError(
                    "Binance tradingSchedule session must be an object"
                )
            start = _timestamp_ns(session.get("startTime"), field="startTime")
            end = _timestamp_ns(session.get("endTime"), field="endTime")
            _response_string(cast(Mapping[str, JsonPayload], session), "type")
            if end <= start:
                raise BinancePayloadError(
                    "Binance tradingSchedule session endTime must follow startTime"
                )
            if previous_end is not None and start < previous_end:
                raise BinancePayloadError(
                    "Binance tradingSchedule sessions must be chronological"
                )
            previous_end = end
    return BinanceMarketRestPayload(
        capture,
        (),
        event_time,
        "binance.payload.updateTime",
    )


_DERIVATIVE_REFERENCE_REQUIRED_DECIMALS = MappingProxyType(
    {
        "mark_price": ("markPrice", "indexPrice"),
        "premium": ("markPrice", "indexPrice"),
        "funding_rate": ("fundingRate",),
        "open_interest": ("openInterest",),
        "open_interest_history": ("sumOpenInterest", "sumOpenInterestValue"),
    }
)
_INSTRUMENT_REFERENCE_STREAMS = frozenset(
    {
        "mark_price",
        "premium",
        "funding_rate",
        "open_interest",
        "open_interest_history",
        "index_constituents",
        "adl_risk",
    }
)


def parse_derivative_reference(
    capture: BinanceRestCapture, *, instrument: InstrumentRecord
) -> NativeEventDraft:
    _binance_instrument(instrument, market=Market.PERPETUAL)
    logical_stream = capture.request.logical_stream
    if (
        logical_stream not in _INSTRUMENT_REFERENCE_STREAMS
        or _REFERENCE_PATHS.get(logical_stream) != capture.request.path
    ):
        raise ValueError("capture is not an instrument-scoped derivative reference")
    _validate_request_instrument(capture, instrument)
    rows = _capture_rows(capture)
    for row in rows:
        _validate_response_symbol(row, instrument)
        for field_name in _DERIVATIVE_REFERENCE_REQUIRED_DECIMALS.get(
            logical_stream, ()
        ):
            _response_decimal(
                row,
                field_name,
                non_negative=logical_stream != "funding_rate",
            )
        if logical_stream == "index_constituents":
            constituents = row.get("constituents")
            if not isinstance(constituents, list):
                raise BinancePayloadError(
                    "Binance constituents response requires constituents array"
                )
            for constituent in constituents:
                if not isinstance(constituent, Mapping):
                    raise BinancePayloadError(
                        "Binance constituents entries must be objects"
                    )
                mapped = cast(Mapping[str, JsonPayload], constituent)
                for field_name in ("exchange", "symbol"):
                    _response_string(mapped, field_name)
                for field_name in ("price", "weight"):
                    _response_decimal(mapped, field_name, non_negative=True)
        elif logical_stream == "adl_risk":
            _response_string(row, "adlRisk")
    timestamp_field = _DERIVATIVE_REFERENCE_EVENT_FIELDS.get(logical_stream)
    event_time = (
        None
        if timestamp_field is None
        else _uniform_timestamp(rows, field=timestamp_field)
    )
    return _instrument_event(
        capture,
        instrument=instrument,
        event_time_ns=event_time,
        event_time_source=(
            None
            if event_time is None or timestamp_field is None
            else f"binance.payload[].{timestamp_field}"
        ),
    )


__all__ = [
    "FUTURES_DEPTH_PATH",
    "FUTURES_EXCHANGE_INFO_PATH",
    "FUTURES_PRICE_PATH",
    "SPOT_DEPTH_PATH",
    "SPOT_EXCHANGE_INFO_PATH",
    "BinanceMarketRestPayload",
    "BinanceRestCapture",
    "BinanceRestRequest",
    "BinanceSpecialQuota",
    "bbo_request",
    "book_request",
    "candles_request",
    "capture_binance_response",
    "derivative_kline_request",
    "derivative_reference_request",
    "exchange_info_request",
    "parse_asset_index",
    "parse_bbo",
    "parse_candles",
    "parse_deep_book",
    "parse_derivative_reference",
    "parse_funding_info",
    "parse_index_info",
    "parse_insurance_fund",
    "parse_price",
    "parse_spot_reference",
    "parse_ticker",
    "parse_trades",
    "parse_trading_schedule",
    "price_request",
    "spot_reference_request",
    "ticker_request",
    "trades_request",
]
