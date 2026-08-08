from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import cast
from urllib.parse import quote, urlsplit, urlunsplit

from crypto_collector.domain import CoverageMode, Market
from crypto_collector.domain.json_codec import JsonPayload, decode_json, encode_json
from crypto_collector.exchanges.binance.errors import BinancePayloadError

MAX_CONNECTION_LIFETIME_NS = 86_400_000_000_000
DEFAULT_ROTATION_LEAD_NS = 300_000_000_000
MAX_STREAMS_PER_CONNECTION = 1_024
_STREAM_DELIMITERS = frozenset("/%?#&=\\")
_MAX_SIGNED_64 = 2**63 - 1
_MILLISECONDS_TO_NANOSECONDS = 1_000_000
_SPOT_KLINE_INTERVALS = frozenset(
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
_FUTURES_KLINE_INTERVALS = _SPOT_KLINE_INTERVALS - {"1s"}
_FUTURES_ST_REQUIRED_STREAMS = frozenset(
    {"book_live", "trade", "ticker", "bbo", "mark_price", "instrument"}
)


class BinanceWsProtocolError(BinancePayloadError):
    def __init__(self, message: str, *, raw_text: str | None = None) -> None:
        self.raw_text = raw_text
        super().__init__(message)


class BinanceWsScopeError(BinanceWsProtocolError):
    """A merged Futures payload is proven to belong outside USD-M."""


class BinanceWsRoute(StrEnum):
    SPOT = "spot"
    PUBLIC = "public"
    MARKET = "market"


class BinanceWsMessageKind(StrEnum):
    SUBSCRIBE_ACK = "subscribe_ack"
    ERROR = "error"
    DATA = "data"
    SERVER_SHUTDOWN = "server_shutdown"


def _valid_stream_token(value: object) -> bool:
    return (
        type(value) is str
        and bool(value)
        and all(
            character.isprintable()
            and not character.isspace()
            and character not in _STREAM_DELIMITERS
            for character in value
        )
    )


@dataclass(frozen=True, slots=True)
class BinanceStreamSpec:
    market: Market
    logical_stream: str
    stream_name: str
    route: BinanceWsRoute
    instrument_key: str | None
    wire_symbol: str | None
    coverage: CoverageMode | None = None
    index_symbol: str | None = None

    def __post_init__(self) -> None:
        if type(self.market) is not Market:
            raise TypeError("market must be Market")
        if type(self.logical_stream) is not str or not self.logical_stream:
            raise ValueError("logical_stream must be non-empty")
        if type(self.route) is not BinanceWsRoute:
            raise TypeError("route must be BinanceWsRoute")
        if not _valid_stream_token(self.stream_name):
            raise ValueError("stream_name contains unsupported URL characters")
        if self.logical_stream == "index_info":
            if self.market is not Market.PERPETUAL:
                raise ValueError("index_info is available only for Binance Futures")
            if self.instrument_key is not None or self.wire_symbol is not None:
                raise ValueError("index_info must bind an explicit index symbol")
            if (
                type(self.index_symbol) is not str
                or not _valid_stream_token(self.index_symbol)
                or any(marker in self.index_symbol for marker in "@!")
            ):
                raise ValueError("index_symbol contains unsupported stream delimiters")
            expected_stream = f"{self.index_symbol.lower()}@compositeIndex"
            if self.stream_name != expected_stream:
                raise ValueError("index_info must use its exact composite-index stream")
        else:
            if self.index_symbol is not None:
                raise ValueError("index_symbol is valid only for index_info")
            if self.stream_name.endswith("@compositeIndex"):
                raise ValueError("composite-index streams are reserved for index_info")
            if (self.instrument_key is None) != (self.wire_symbol is None):
                raise ValueError("instrument_key and wire_symbol must be paired")
        if self.instrument_key is not None and (
            type(self.instrument_key) is not str or not self.instrument_key
        ):
            raise ValueError("instrument_key must be non-empty")
        if self.wire_symbol is not None:
            wire_symbol = self.wire_symbol
            if (
                type(wire_symbol) is not str
                or not _valid_stream_token(wire_symbol)
                or any(marker in wire_symbol for marker in "@!")
            ):
                raise ValueError("wire_symbol contains unsupported stream delimiters")
            if not self.stream_name.startswith(wire_symbol.lower() + "@"):
                raise ValueError("stream_name must use the lowercase wire symbol")
        if self.market is Market.SPOT and self.route is not BinanceWsRoute.SPOT:
            raise ValueError("Spot streams must use the Spot route")
        if self.market is Market.PERPETUAL and self.route is BinanceWsRoute.SPOT:
            raise ValueError(
                "Futures streams require an explicit public or market route"
            )
        expected_route = _route_for_stream(self.market, self.stream_name)
        if self.route is not expected_route:
            raise ValueError("stream is assigned to the wrong Binance route")
        if self.logical_stream == "liquidation":
            if self.coverage is not CoverageMode.LOSSY_WINDOW:
                raise ValueError(
                    "Binance liquidation must declare lossy-window coverage"
                )
        elif self.coverage is not None:
            raise ValueError("coverage is defined only for Binance liquidation streams")

    @property
    def identity_symbol(self) -> str | None:
        return self.index_symbol if self.index_symbol is not None else self.wire_symbol


@dataclass(frozen=True, slots=True)
class BinanceWsMessage:
    kind: BinanceWsMessageKind
    raw_text: str
    payload: Mapping[str, JsonPayload]
    stream_name: str | None
    data: JsonPayload | None
    request_id: int | str | None = None
    code: int | None = None
    message: str | None = None

    @property
    def requests_reconnect(self) -> bool:
        return self.kind is BinanceWsMessageKind.SERVER_SHUTDOWN


def _route_for_stream(market: Market, stream_name: str) -> BinanceWsRoute:
    if market is Market.SPOT:
        return BinanceWsRoute.SPOT
    suffix = stream_name.split("@", 1)[1] if "@" in stream_name else stream_name
    if (
        suffix.startswith("depth")
        or suffix == "bookTicker"
        or stream_name == "!bookTicker"
    ):
        return BinanceWsRoute.PUBLIC
    if (
        suffix in {"aggTrade", "miniTicker", "ticker", "forceOrder", "compositeIndex"}
        or suffix.startswith(("kline_", "markPrice"))
        or stream_name in {"!forceOrder@arr", "!contractInfo"}
    ):
        return BinanceWsRoute.MARKET
    raise ValueError("unsupported Binance Futures stream")


def stream_spec(
    market: Market,
    logical_stream: str,
    *,
    instrument_key: str | None = None,
    wire_symbol: str | None = None,
    index_symbol: str | None = None,
    update_speed_ms: int | None = None,
    all_market: bool = False,
) -> BinanceStreamSpec:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    if type(logical_stream) is not str or not logical_stream:
        raise ValueError("logical_stream must be non-empty")
    if type(all_market) is not bool:
        raise TypeError("all_market must be a boolean")
    if index_symbol is not None and logical_stream != "index_info":
        raise ValueError("index_symbol is valid only for index_info")
    symbol = None if wire_symbol is None else wire_symbol.lower()
    coverage: CoverageMode | None = None
    if logical_stream == "instrument" and market is Market.PERPETUAL:
        if instrument_key is not None or wire_symbol is not None or not all_market:
            raise ValueError("Binance contractInfo is a market-scoped stream")
        name = "!contractInfo"
    elif logical_stream == "liquidation" and market is Market.PERPETUAL:
        coverage = CoverageMode.LOSSY_WINDOW
        if all_market:
            if instrument_key is not None or wire_symbol is not None:
                raise ValueError("all-market liquidation cannot bind an instrument")
            name = "!forceOrder@arr"
        else:
            if symbol is None:
                raise ValueError("symbol liquidation requires a wire symbol")
            name = f"{symbol}@forceOrder"
    elif logical_stream == "index_info":
        if market is not Market.PERPETUAL:
            raise ValueError("index_info is available only for Binance Futures")
        if instrument_key is not None or wire_symbol is not None or all_market:
            raise ValueError("index_info requires an explicit index symbol")
        if (
            type(index_symbol) is not str
            or not _valid_stream_token(index_symbol)
            or "@" in index_symbol
            or "!" in index_symbol
        ):
            raise ValueError("index_symbol contains unsupported stream delimiters")
        name = f"{index_symbol.lower()}@compositeIndex"
    else:
        if all_market:
            raise ValueError("all_market is unsupported for this logical stream")
        if instrument_key is None or symbol is None:
            raise ValueError("instrument stream requires instrument identity")
        if logical_stream == "book_live":
            speed = 100 if update_speed_ms is None else update_speed_ms
            if market is Market.SPOT:
                if speed not in {100, 1_000}:
                    raise ValueError("Spot depth speed must be 100 or 1000ms")
                suffix = "depth@100ms" if speed == 100 else "depth"
            else:
                if speed not in {100, 250, 500}:
                    raise ValueError("Futures depth speed must be 100, 250, or 500ms")
                suffix = "depth" if speed == 250 else f"depth@{speed}ms"
            name = f"{symbol}@{suffix}"
        elif logical_stream == "trade":
            name = f"{symbol}@{'trade' if market is Market.SPOT else 'aggTrade'}"
        elif logical_stream == "ticker":
            name = f"{symbol}@ticker"
        elif logical_stream == "bbo":
            name = f"{symbol}@bookTicker"
        elif logical_stream.startswith("candle_"):
            interval = logical_stream.removeprefix("candle_")
            supported = (
                _SPOT_KLINE_INTERVALS
                if market is Market.SPOT
                else _FUTURES_KLINE_INTERVALS
            )
            if interval not in supported:
                raise ValueError("unsupported Binance candle interval")
            name = f"{symbol}@kline_{interval}"
        elif logical_stream == "mark_price" and market is Market.PERPETUAL:
            speed = 1_000 if update_speed_ms is None else update_speed_ms
            if speed not in {1_000, 3_000}:
                raise ValueError("mark-price speed must be 1000 or 3000ms")
            name = f"{symbol}@markPrice" + ("@1s" if speed == 1_000 else "")
        else:
            raise ValueError("unsupported Binance logical WebSocket stream")
    route = _route_for_stream(market, name)
    return BinanceStreamSpec(
        market=market,
        logical_stream=logical_stream,
        stream_name=name,
        route=route,
        instrument_key=instrument_key,
        wire_symbol=wire_symbol,
        index_symbol=index_symbol,
        coverage=coverage,
    )


def _request_id(value: object, market: Market) -> int | str | None:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    if market is Market.PERPETUAL:
        if type(value) is not int or value < 0:
            raise ValueError("Binance Futures request id must be an unsigned integer")
        return value
    if value is None:
        return None
    if type(value) is int:
        if not -(2**63) <= value <= _MAX_SIGNED_64:
            raise ValueError("Binance request id must fit signed 64-bit")
        return value
    if (
        type(value) is str
        and 0 < len(value) <= 36
        and value.isascii()
        and value.isalnum()
    ):
        return value
    raise ValueError("Binance request id must be int64 or <=36 ASCII alphanumerics")


def _normalized_specs(
    specs: Sequence[BinanceStreamSpec],
) -> tuple[BinanceStreamSpec, ...]:
    if not isinstance(specs, (list, tuple)) or not specs:
        raise ValueError("at least one Binance stream is required")
    if len(specs) > MAX_STREAMS_PER_CONNECTION:
        raise ValueError("Binance connection exceeds 1024 streams")
    values = tuple(specs)
    if any(type(item) is not BinanceStreamSpec for item in values):
        raise TypeError("specs must contain BinanceStreamSpec values")
    if len({item.stream_name for item in values}) != len(values):
        raise ValueError("Binance stream names must be unique")
    first = values[0]
    if any(
        item.market is not first.market or item.route is not first.route
        for item in values
    ):
        raise ValueError(
            "one Binance connection cannot mix markets or routed endpoints"
        )
    return values


def build_subscribe_message(
    specs: Sequence[BinanceStreamSpec], *, request_id: int | str | None
) -> str:
    values = _normalized_specs(specs)
    payload = {
        "method": "SUBSCRIBE",
        "params": [item.stream_name for item in values],
        "id": _request_id(request_id, values[0].market),
    }
    return encode_json(payload).decode("utf-8")


def combined_stream_url(base_url: str, specs: Sequence[BinanceStreamSpec]) -> str:
    values = _normalized_specs(specs)
    if type(base_url) is not str or not base_url:
        raise ValueError("base_url must be non-empty")
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise ValueError("invalid Binance WebSocket base URL") from error
    if (
        parsed.scheme not in {"ws", "wss"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65_535)
    ):
        raise ValueError("Binance WebSocket base URL must be anonymous")
    route = values[0].route
    path = parsed.path.rstrip("/")
    if route is BinanceWsRoute.SPOT:
        if path:
            raise ValueError("Spot base URL must not include a routed path")
        target_path = "/stream"
    else:
        expected = f"/{route.value}"
        if path not in {"", expected}:
            raise ValueError("Futures base URL route does not match stream family")
        target_path = f"{expected}/stream"
    query = "streams=" + "/".join(
        quote(item.stream_name, safe="!@_-") for item in values
    )
    return urlunsplit((parsed.scheme, parsed.netloc, target_path, query, ""))


def _text_frame(raw: object) -> str:
    if type(raw) is str:
        return raw
    if type(raw) is bytes:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise BinanceWsProtocolError(
                "Binance binary frame is not UTF-8", raw_text=None
            ) from error
    raise BinanceWsProtocolError("Binance frame must be text or UTF-8 bytes")


def _mapping(value: object, *, raw_text: str, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BinanceWsProtocolError(f"{field} must be an object", raw_text=raw_text)
    return cast(Mapping[str, JsonPayload], value)


def _data_rows(
    data: JsonPayload, *, raw_text: str
) -> tuple[Mapping[str, JsonPayload], ...]:
    if isinstance(data, Mapping):
        return (_mapping(data, raw_text=raw_text, field="Binance stream data"),)
    if isinstance(data, list):
        return tuple(
            _mapping(item, raw_text=raw_text, field=f"Binance stream data[{index}]")
            for index, item in enumerate(data)
        )
    raise BinanceWsProtocolError(
        "Binance stream data must be object/array", raw_text=raw_text
    )


def _validate_usd_m(
    data: JsonPayload, spec: BinanceStreamSpec, *, raw_text: str
) -> None:
    requires_indicator = spec.logical_stream in _FUTURES_ST_REQUIRED_STREAMS or (
        spec.instrument_key is None and spec.logical_stream != "index_info"
    )
    for row in _data_rows(data, raw_text=raw_text):
        indicator = row.get("st")
        if indicator is None:
            if requires_indicator:
                raise BinanceWsScopeError(
                    "Futures payload lacks required st market indicator",
                    raw_text=raw_text,
                )
            continue
        if type(indicator) is not int or indicator not in {1, 2}:
            raise BinanceWsScopeError(
                "invalid Futures st market indicator", raw_text=raw_text
            )
        if indicator == 2:
            raise BinanceWsScopeError(
                "COIN-M payload rejected from USD-M stream", raw_text=raw_text
            )


def _required_keys(
    row: Mapping[str, JsonPayload], keys: frozenset[str], *, raw_text: str
) -> None:
    missing = keys - row.keys()
    if missing:
        raise BinanceWsProtocolError(
            "Binance stream data lacks " + ", ".join(sorted(missing)),
            raw_text=raw_text,
        )


def _validate_shape(
    data: JsonPayload, spec: BinanceStreamSpec, *, raw_text: str
) -> None:
    rows = _data_rows(data, raw_text=raw_text)
    if not rows and spec.logical_stream not in {"ticker", "mark_price"}:
        raise BinanceWsProtocolError(
            "Binance stream data must not be empty", raw_text=raw_text
        )
    for row in rows:
        if spec.logical_stream == "book_live":
            _required_keys(
                row, frozenset({"e", "E", "s", "U", "u", "b", "a"}), raw_text=raw_text
            )
            if row.get("e") != "depthUpdate":
                raise BinanceWsProtocolError(
                    "book stream requires depthUpdate", raw_text=raw_text
                )
            if spec.market is Market.PERPETUAL:
                _required_keys(row, frozenset({"pu"}), raw_text=raw_text)
        elif spec.logical_stream == "trade":
            _required_keys(
                row, frozenset({"e", "E", "s", "p", "q", "T"}), raw_text=raw_text
            )
            expected = "trade" if spec.market is Market.SPOT else "aggTrade"
            if row.get("e") != expected:
                raise BinanceWsProtocolError(
                    "trade event type mismatch", raw_text=raw_text
                )
        elif spec.logical_stream == "bbo":
            if spec.market is Market.SPOT:
                _required_keys(
                    row,
                    frozenset({"u", "s", "b", "B", "a", "A"}),
                    raw_text=raw_text,
                )
            else:
                _required_keys(
                    row,
                    frozenset({"e", "E", "T", "s", "b", "B", "a", "A"}),
                    raw_text=raw_text,
                )
                if row.get("e") != "bookTicker":
                    raise BinanceWsProtocolError(
                        "BBO event type mismatch", raw_text=raw_text
                    )
        elif spec.logical_stream == "ticker":
            _required_keys(row, frozenset({"e", "E", "s"}), raw_text=raw_text)
            if row.get("e") != "24hrTicker":
                raise BinanceWsProtocolError(
                    "ticker event type mismatch", raw_text=raw_text
                )
        elif spec.logical_stream.startswith("candle_"):
            _required_keys(row, frozenset({"e", "E", "s", "k"}), raw_text=raw_text)
            kline = row.get("k")
            if row.get("e") != "kline" or not isinstance(kline, Mapping):
                raise BinanceWsProtocolError(
                    "candle stream requires kline object", raw_text=raw_text
                )
            nested = cast(Mapping[str, JsonPayload], kline)
            interval = spec.logical_stream.removeprefix("candle_")
            if nested.get("s") != row.get("s") or nested.get("i") != interval:
                raise BinanceWsProtocolError(
                    "candle payload identity or interval mismatch", raw_text=raw_text
                )
        elif spec.logical_stream == "mark_price":
            _required_keys(
                row, frozenset({"e", "E", "s", "p", "i", "r", "T"}), raw_text=raw_text
            )
            if row.get("e") != "markPriceUpdate":
                raise BinanceWsProtocolError(
                    "mark-price event type mismatch", raw_text=raw_text
                )
        elif spec.logical_stream == "liquidation":
            _required_keys(row, frozenset({"e", "E", "o"}), raw_text=raw_text)
            if row.get("e") != "forceOrder" or not isinstance(row.get("o"), Mapping):
                raise BinanceWsProtocolError(
                    "liquidation requires forceOrder object", raw_text=raw_text
                )
        elif spec.logical_stream == "instrument":
            _required_keys(row, frozenset({"e", "E"}), raw_text=raw_text)
            if row.get("e") != "contractInfo":
                raise BinanceWsProtocolError(
                    "instrument stream requires contractInfo", raw_text=raw_text
                )
        elif spec.logical_stream == "index_info":
            _required_keys(row, frozenset({"e", "E", "s"}), raw_text=raw_text)
            if row.get("e") != "compositeIndex":
                raise BinanceWsProtocolError(
                    "index-info event type mismatch", raw_text=raw_text
                )
        else:  # pragma: no cover - specs reject unsupported logical streams.
            raise BinanceWsProtocolError(
                "unsupported Binance stream shape", raw_text=raw_text
            )
        expected_symbol = spec.identity_symbol
        if expected_symbol is not None:
            symbol = row.get("s")
            if symbol is None and isinstance(row.get("o"), Mapping):
                symbol = cast(Mapping[str, JsonPayload], row["o"]).get("s")
            if (
                type(symbol) is not str
                or symbol.casefold() != expected_symbol.casefold()
            ):
                raise BinanceWsProtocolError(
                    "payload symbol does not match subscription", raw_text=raw_text
                )


def parse_ws_message(
    raw: object,
    *,
    expected: BinanceStreamSpec | None = None,
    market: Market | None = None,
) -> BinanceWsMessage:
    if market is not None and type(market) is not Market:
        raise TypeError("market must be Market or None")
    if expected is not None and type(expected) is not BinanceStreamSpec:
        raise TypeError("expected must be BinanceStreamSpec or None")
    if expected is not None and market is not None and expected.market is not market:
        raise ValueError("expected stream and message market do not match")
    message_market = expected.market if expected is not None else market
    raw_text = _text_frame(raw)
    try:
        decoded = decode_json(raw_text)
    except (TypeError, ValueError) as error:
        raise BinanceWsProtocolError(
            "Binance frame is not strict JSON", raw_text=raw_text
        ) from error
    payload = _mapping(decoded, raw_text=raw_text, field="Binance frame")
    if "result" in payload:
        if payload.get("result") is not None or "id" not in payload:
            raise BinanceWsProtocolError(
                "malformed Binance subscription ack", raw_text=raw_text
            )
        if message_market is None:
            raise BinanceWsProtocolError(
                "Binance control frame requires market context", raw_text=raw_text
            )
        request_id = _request_id(payload["id"], message_market)
        return BinanceWsMessage(
            BinanceWsMessageKind.SUBSCRIBE_ACK,
            raw_text,
            payload,
            None,
            None,
            request_id=request_id,
        )
    if "code" in payload or "msg" in payload:
        code = payload.get("code")
        message = payload.get("msg")
        if type(code) is not int or type(message) is not str or not message:
            raise BinanceWsProtocolError(
                "malformed Binance error frame", raw_text=raw_text
            )
        if message_market is None:
            raise BinanceWsProtocolError(
                "Binance control frame requires market context", raw_text=raw_text
            )
        request_value = payload.get("id")
        error_request_id: int | str | None = (
            None
            if request_value is None
            else _request_id(request_value, message_market)
        )
        return BinanceWsMessage(
            BinanceWsMessageKind.ERROR,
            raw_text,
            payload,
            None,
            None,
            request_id=error_request_id,
            code=code,
            message=message,
        )
    stream_name: str | None = None
    data: JsonPayload = cast(JsonPayload, payload)
    if "stream" in payload:
        stream = payload.get("stream")
        if type(stream) is not str or not stream or "data" not in payload:
            raise BinanceWsProtocolError(
                "malformed Binance combined frame", raw_text=raw_text
            )
        stream_name = stream
        data = cast(JsonPayload, payload["data"])
    rows = _data_rows(data, raw_text=raw_text)
    is_shutdown = any(row.get("e") == "serverShutdown" for row in rows)
    if is_shutdown:
        if len(rows) != 1 or rows[0].get("e") != "serverShutdown":
            raise BinanceWsProtocolError(
                "serverShutdown must be a single event", raw_text=raw_text
            )
        if message_market is not None and message_market is not Market.SPOT:
            raise BinanceWsProtocolError(
                "serverShutdown is a Spot event", raw_text=raw_text
            )
        if stream_name is not None and stream_name != "!serverShutdown":
            raise BinanceWsProtocolError(
                "combined serverShutdown stream name mismatch", raw_text=raw_text
            )
        timestamp = rows[0].get("E")
        if type(timestamp) is not int or timestamp < 0:
            raise BinanceWsProtocolError(
                "serverShutdown E must be Unix milliseconds", raw_text=raw_text
            )
        if timestamp * _MILLISECONDS_TO_NANOSECONDS > _MAX_SIGNED_64:
            raise BinanceWsProtocolError(
                "serverShutdown E overflows nanoseconds", raw_text=raw_text
            )
        return BinanceWsMessage(
            BinanceWsMessageKind.SERVER_SHUTDOWN,
            raw_text,
            payload,
            stream_name,
            data,
        )
    if expected is None:
        raise BinanceWsProtocolError(
            "Binance data frame requires an expected stream", raw_text=raw_text
        )
    else:
        if stream_name is not None and stream_name != expected.stream_name:
            raise BinanceWsProtocolError(
                "combined stream name mismatch", raw_text=raw_text
            )
        if expected.market is Market.PERPETUAL:
            _validate_usd_m(data, expected, raw_text=raw_text)
        _validate_shape(data, expected, raw_text=raw_text)
    return BinanceWsMessage(
        BinanceWsMessageKind.DATA,
        raw_text,
        payload,
        stream_name,
        data,
    )


def event_time_ns(message: BinanceWsMessage) -> int | None:
    if type(message) is not BinanceWsMessage:
        raise TypeError("message must be BinanceWsMessage")
    if message.data is None:
        return None
    rows = _data_rows(message.data, raw_text=message.raw_text)
    values: set[int] = set()
    for row in rows:
        value = row.get("E")
        if value is None:
            continue
        if type(value) is not int or value < 0:
            raise BinanceWsProtocolError(
                "Binance E must be Unix milliseconds", raw_text=message.raw_text
            )
        nanoseconds = value * _MILLISECONDS_TO_NANOSECONDS
        if nanoseconds > _MAX_SIGNED_64:
            raise BinanceWsProtocolError(
                "Binance E overflows nanoseconds", raw_text=message.raw_text
            )
        values.add(nanoseconds)
    return values.pop() if len(values) == 1 else None


def planned_rotation_at_ns(
    opened_monotonic_ns: int, *, lead_ns: int = DEFAULT_ROTATION_LEAD_NS
) -> int:
    if type(opened_monotonic_ns) is not int or opened_monotonic_ns < 0:
        raise ValueError("opened_monotonic_ns must be non-negative")
    if type(lead_ns) is not int or not 0 < lead_ns < MAX_CONNECTION_LIFETIME_NS:
        raise ValueError("lead_ns must be positive and below 24 hours")
    return opened_monotonic_ns + MAX_CONNECTION_LIFETIME_NS - lead_ns


def rotation_due(
    *,
    opened_monotonic_ns: int,
    now_monotonic_ns: int,
    lead_ns: int = DEFAULT_ROTATION_LEAD_NS,
) -> bool:
    if type(now_monotonic_ns) is not int or now_monotonic_ns < 0:
        raise ValueError("now_monotonic_ns must be non-negative")
    return now_monotonic_ns >= planned_rotation_at_ns(
        opened_monotonic_ns, lead_ns=lead_ns
    )


def pong_payload(ping_payload: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(ping_payload, (bytes, bytearray, memoryview)):
        raise TypeError("protocol ping payload must be bytes-like")
    payload = bytes(ping_payload)
    if len(payload) > 125:
        raise ValueError("WebSocket control payload cannot exceed 125 bytes")
    return payload


__all__ = [
    "DEFAULT_ROTATION_LEAD_NS",
    "MAX_CONNECTION_LIFETIME_NS",
    "MAX_STREAMS_PER_CONNECTION",
    "BinanceStreamSpec",
    "BinanceWsMessage",
    "BinanceWsMessageKind",
    "BinanceWsProtocolError",
    "BinanceWsRoute",
    "BinanceWsScopeError",
    "build_subscribe_message",
    "combined_stream_url",
    "event_time_ns",
    "parse_ws_message",
    "planned_rotation_at_ns",
    "pong_payload",
    "rotation_due",
    "stream_spec",
]
