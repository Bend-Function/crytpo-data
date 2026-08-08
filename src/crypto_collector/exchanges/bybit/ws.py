from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from enum import StrEnum
from typing import cast
from urllib.parse import urlsplit

from crypto_collector.capabilities import CapabilityError
from crypto_collector.domain import Market
from crypto_collector.domain.json_codec import (
    JsonPayload,
    decode_json,
    encode_json,
    validate_json_payload,
)
from crypto_collector.exchanges.contracts import WebSocketSubscription

BYBIT_WS_SPOT_URL = "wss://stream.bybit.com/v5/public/spot"
BYBIT_WS_LINEAR_URL = "wss://stream.bybit.com/v5/public/linear"
BYBIT_WS_STATUS_URL = "wss://stream.bybit.com/v5/public/misc/status"
BYBIT_WS_ARGS_CHARACTER_LIMIT = 21_000
BYBIT_WS_SPOT_ARGS_PER_REQUEST = 10
BYBIT_WS_HEARTBEAT_INTERVAL_SECONDS = 20
BYBIT_WS_CONNECTION_ATTEMPT_LIMIT = 500
BYBIT_WS_CONNECTION_ATTEMPT_WINDOW_SECONDS = 300
BYBIT_WS_MARKET_CONNECTION_LIMIT_PER_IP = 1_000
BYBIT_STANDARD_BOOK_DEPTHS = frozenset({1, 50, 200, 1000})
BYBIT_DEFAULT_BOOK_DEPTH = 200
BYBIT_SPOT_FULL_BOOK_AVAILABLE_FROM = date(2026, 7, 16)
BYBIT_PERPETUAL_FULL_BOOK_AVAILABLE_FROM = date(2026, 8, 11)

_SPOT_PATH = "/v5/public/spot"
_LINEAR_PATH = "/v5/public/linear"
_STATUS_PATH = "/v5/public/misc/status"
_REQUEST_ID = re.compile(r"[\x21-\x7e]{1,64}\Z")
_WIRE_SYMBOL = re.compile(r"[A-Z0-9]+\Z")
_KLINE_INTERVALS = frozenset(
    {"1", "3", "5", "15", "30", "60", "120", "240", "360", "720", "D", "W", "M"}
)
_POOL_FILTERS = frozenset({"USDT", "USDC", "inverse"})
_KNOWN_TICKER_STRING_FIELDS = frozenset(
    {
        "ask1Price",
        "ask1Size",
        "basis",
        "basisRate",
        "basisRateYear",
        "bid1Price",
        "bid1Size",
        "curPreListingPhase",
        "deliveryFeeRate",
        "deliveryTime",
        "fundingCap",
        "fundingIntervalHour",
        "fundingRate",
        "highPrice24h",
        "indexPrice",
        "lastPrice",
        "lowPrice24h",
        "markPrice",
        "nextFundingTime",
        "openInterest",
        "openInterestValue",
        "preOpenPrice",
        "preQty",
        "predictedDeliveryPrice",
        "prevPrice1h",
        "prevPrice24h",
        "price24hPcnt",
        "singleOpenInterest",
        "singleOpenInterestValue",
        "tickDirection",
        "turnover24h",
        "usdIndexPrice",
        "volume24h",
    }
)
_SPOT_TICKER_SNAPSHOT_FIELDS = frozenset(
    {
        "highPrice24h",
        "lastPrice",
        "lowPrice24h",
        "prevPrice24h",
        "price24hPcnt",
        "turnover24h",
        "usdIndexPrice",
        "volume24h",
    }
)
_LINEAR_TICKER_SNAPSHOT_FIELDS = frozenset(
    {
        "ask1Price",
        "ask1Size",
        "bid1Price",
        "bid1Size",
        "fundingCap",
        "fundingIntervalHour",
        "fundingRate",
        "highPrice24h",
        "indexPrice",
        "lastPrice",
        "lowPrice24h",
        "markPrice",
        "nextFundingTime",
        "openInterest",
        "openInterestValue",
        "prevPrice1h",
        "prevPrice24h",
        "price24hPcnt",
        "tickDirection",
        "turnover24h",
        "volume24h",
    }
)


class BybitWsProtocolError(ValueError):
    def __init__(self, message: str, *, raw_text: str | None = None) -> None:
        super().__init__(message)
        self.raw_text = raw_text


class BybitWsMessageKind(StrEnum):
    PONG = "pong"
    SUBSCRIBE_ACK = "subscribe_ack"
    UNSUBSCRIBE_ACK = "unsubscribe_ack"
    ERROR = "error"
    DATA = "data"


class BybitWsTopicKind(StrEnum):
    ORDERBOOK = "orderbook"
    RPI_ORDERBOOK = "rpi_orderbook"
    FULL_ORDERBOOK = "full_orderbook"
    TRADE = "trade"
    TICKER = "ticker"
    KLINE = "kline"
    ALL_LIQUIDATION = "all_liquidation"
    INSURANCE = "insurance"
    PRICE_LIMIT = "price_limit"
    ADL_ALERT = "adl_alert"
    SYSTEM_STATUS = "system_status"


@dataclass(frozen=True, slots=True)
class BybitWsTopic:
    raw: str
    kind: BybitWsTopicKind
    wire_symbol: str | None
    parameter: str | int | None = None


@dataclass(frozen=True, slots=True)
class BybitWsMessage:
    kind: BybitWsMessageKind
    raw_text: str
    payload: dict[str, JsonPayload]
    topic: BybitWsTopic | None
    request_id: str | None
    connection_id: str | None
    error_message: str | None

    @property
    def wire_symbol(self) -> str | None:
        return None if self.topic is None else self.topic.wire_symbol

    @property
    def data(self) -> JsonPayload | None:
        return self.payload.get("data")

    def acknowledges(self, *, operation: str, request_id: str) -> bool:
        if operation not in {"subscribe", "unsubscribe"}:
            raise ValueError("operation must be subscribe or unsubscribe")
        if type(request_id) is not str or not request_id:
            raise ValueError("request_id must be a non-empty string")
        expected_kind = (
            BybitWsMessageKind.SUBSCRIBE_ACK
            if operation == "subscribe"
            else BybitWsMessageKind.UNSUBSCRIBE_ACK
        )
        return (
            self.kind is expected_kind
            and self.request_id == request_id
            and self.payload.get("op") == operation
        )


class BybitFullBookDisabledReason(StrEnum):
    DATE_GATE_NOT_REACHED = "date_gate_not_reached"
    LIVE_PROBE_FAILED = "live_probe_failed"


@dataclass(frozen=True, slots=True)
class BybitCapabilityControlEvidence:
    code: str
    feature_id: str
    market: Market
    reason: BybitFullBookDisabledReason
    available_from: date
    as_of: date

    def __post_init__(self) -> None:
        if self.code != "optional_capability_disabled":
            raise ValueError("control evidence code is not the frozen Bybit code")
        if type(self.market) is not Market:
            raise TypeError("control evidence market must be Market")
        if type(self.reason) is not BybitFullBookDisabledReason:
            raise TypeError(
                "control evidence reason must be BybitFullBookDisabledReason"
            )
        if type(self.available_from) is not date or type(self.as_of) is not date:
            raise TypeError("control evidence dates must be date values")


@dataclass(frozen=True, slots=True)
class BybitFullBookCapability:
    market: Market
    feature_id: str
    available_from: date
    as_of: date
    required: bool
    date_gate_passed: bool
    live_probe_succeeded: bool | None
    enabled: bool
    requires_rest_bootstrap: bool
    disabled_reason: BybitFullBookDisabledReason | None
    control_evidence: BybitCapabilityControlEvidence | None

    def __post_init__(self) -> None:
        if type(self.market) is not Market or self.market not in {
            Market.SPOT,
            Market.PERPETUAL,
        }:
            raise TypeError("full-book capability market is unsupported")
        expected_feature, expected_date = (
            ("spot_full_order_book", BYBIT_SPOT_FULL_BOOK_AVAILABLE_FROM)
            if self.market is Market.SPOT
            else (
                "perpetual_full_order_book",
                BYBIT_PERPETUAL_FULL_BOOK_AVAILABLE_FROM,
            )
        )
        if self.feature_id != expected_feature or self.available_from != expected_date:
            raise ValueError("full-book capability identity does not match market")
        if type(self.as_of) is not date:
            raise TypeError("full-book capability as_of must be a date")
        if type(self.required) is not bool:
            raise TypeError("full-book capability required must be a boolean")
        if type(self.date_gate_passed) is not bool:
            raise TypeError("full-book date_gate_passed must be a boolean")
        if (
            self.live_probe_succeeded is not None
            and type(self.live_probe_succeeded) is not bool
        ):
            raise TypeError("full-book live probe evidence must be boolean or None")
        if (
            type(self.enabled) is not bool
            or type(self.requires_rest_bootstrap) is not bool
        ):
            raise TypeError("full-book enabled/bootstrap flags must be booleans")
        expected_date_gate = self.as_of >= self.available_from
        if self.date_gate_passed != expected_date_gate:
            raise ValueError("full-book date gate evidence is inconsistent")
        expected_enabled = expected_date_gate and self.live_probe_succeeded is True
        if self.enabled != expected_enabled:
            raise ValueError(
                "full-book enabled state is inconsistent with gate evidence"
            )
        if self.requires_rest_bootstrap != self.enabled:
            raise ValueError("enabled full book must require REST bootstrap")
        if self.enabled:
            if self.disabled_reason is not None or self.control_evidence is not None:
                raise ValueError("enabled full book must not carry disabled evidence")
            return
        if self.required:
            raise ValueError(
                "an unavailable required full-book capability cannot exist"
            )
        expected_reason = (
            BybitFullBookDisabledReason.DATE_GATE_NOT_REACHED
            if not expected_date_gate
            else BybitFullBookDisabledReason.LIVE_PROBE_FAILED
        )
        expected_probe = None if not expected_date_gate else False
        if (
            self.live_probe_succeeded is not expected_probe
            or self.disabled_reason is not expected_reason
            or self.control_evidence
            != BybitCapabilityControlEvidence(
                code="optional_capability_disabled",
                feature_id=self.feature_id,
                market=self.market,
                reason=expected_reason,
                available_from=self.available_from,
                as_of=self.as_of,
            )
        ):
            raise ValueError("disabled full-book evidence is inconsistent")


@dataclass(frozen=True, slots=True)
class BybitFullBookProbeEvidence:
    feature_id: str
    endpoint_identity: str
    market: Market
    wire_symbol: str
    egress_id: str
    succeeded: bool
    observed_at: date

    def __post_init__(self) -> None:
        if type(self.market) is not Market or self.market not in {
            Market.SPOT,
            Market.PERPETUAL,
        }:
            raise TypeError("full-book probe market is unsupported")
        expected_feature = (
            "spot_full_order_book"
            if self.market is Market.SPOT
            else "perpetual_full_order_book"
        )
        if self.feature_id != expected_feature:
            raise ValueError("full-book probe feature does not match market")
        if type(self.endpoint_identity) is not str or not self.endpoint_identity:
            raise ValueError("full-book probe endpoint identity must be non-empty")
        endpoint = urlsplit(self.endpoint_identity)
        expected_path = _SPOT_PATH if self.market is Market.SPOT else _LINEAR_PATH
        if (
            endpoint.scheme not in {"ws", "wss"}
            or endpoint.hostname is None
            or endpoint.username is not None
            or endpoint.password is not None
            or endpoint.path != expected_path
            or endpoint.query
            or endpoint.fragment
        ):
            raise ValueError(
                "full-book probe endpoint identity is not an exact public route"
            )
        if (
            type(self.wire_symbol) is not str
            or _WIRE_SYMBOL.fullmatch(self.wire_symbol) is None
        ):
            raise ValueError("full-book probe symbol is invalid")
        if type(self.egress_id) is not str or not self.egress_id:
            raise ValueError("full-book probe egress_id must be non-empty")
        if type(self.succeeded) is not bool:
            raise TypeError("full-book probe succeeded must be a boolean")
        if type(self.observed_at) is not date:
            raise TypeError("full-book probe observed_at must be a date")


def resolve_full_book_capability(
    market: Market,
    *,
    as_of: date,
    live_probe_succeeded: bool,
    required: bool = False,
) -> BybitFullBookCapability:
    if type(market) is not Market or market not in {Market.SPOT, Market.PERPETUAL}:
        raise TypeError("market must be Market.SPOT or Market.PERPETUAL")
    if type(as_of) is not date:
        raise TypeError("as_of must be a date")
    if type(live_probe_succeeded) is not bool:
        raise TypeError("live_probe_succeeded must be a boolean")
    if type(required) is not bool:
        raise TypeError("required must be a boolean")
    if market is Market.SPOT:
        feature_id = "spot_full_order_book"
        available_from = BYBIT_SPOT_FULL_BOOK_AVAILABLE_FROM
    else:
        feature_id = "perpetual_full_order_book"
        available_from = BYBIT_PERPETUAL_FULL_BOOK_AVAILABLE_FROM

    date_gate_passed = as_of >= available_from
    if not date_gate_passed:
        reason = BybitFullBookDisabledReason.DATE_GATE_NOT_REACHED
        probe_evidence: bool | None = None
    elif not live_probe_succeeded:
        reason = BybitFullBookDisabledReason.LIVE_PROBE_FAILED
        probe_evidence = False
    else:
        return BybitFullBookCapability(
            market=market,
            feature_id=feature_id,
            available_from=available_from,
            as_of=as_of,
            required=required,
            date_gate_passed=True,
            live_probe_succeeded=True,
            enabled=True,
            requires_rest_bootstrap=True,
            disabled_reason=None,
            control_evidence=None,
        )

    if required:
        raise CapabilityError(
            f"required Bybit {feature_id} unavailable: {reason.value}"
        )
    evidence = BybitCapabilityControlEvidence(
        code="optional_capability_disabled",
        feature_id=feature_id,
        market=market,
        reason=reason,
        available_from=available_from,
        as_of=as_of,
    )
    return BybitFullBookCapability(
        market=market,
        feature_id=feature_id,
        available_from=available_from,
        as_of=as_of,
        required=False,
        date_gate_passed=date_gate_passed,
        live_probe_succeeded=probe_evidence,
        enabled=False,
        requires_rest_bootstrap=False,
        disabled_reason=reason,
        control_evidence=evidence,
    )


def _text_frame(raw: object) -> str:
    if type(raw) is str:
        return raw
    if type(raw) is bytes:
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise BybitWsProtocolError("WebSocket bytes must be UTF-8 text") from error
    raise BybitWsProtocolError("WebSocket frame must be text or UTF-8 bytes")


def _required_text(
    value: object,
    *,
    field: str,
    raw_text: str,
    allow_empty: bool = False,
) -> str:
    if type(value) is not str or (not allow_empty and not value):
        qualifier = "a string" if allow_empty else "a non-empty string"
        raise BybitWsProtocolError(
            f"{field} must be {qualifier}",
            raw_text=raw_text,
        )
    return value


def _required_int(value: object, *, field: str, raw_text: str) -> int:
    if type(value) is not int:
        raise BybitWsProtocolError(f"{field} must be an integer", raw_text=raw_text)
    return value


def _required_bool(value: object, *, field: str, raw_text: str) -> bool:
    if type(value) is not bool:
        raise BybitWsProtocolError(f"{field} must be a boolean", raw_text=raw_text)
    return value


def _required_object(
    value: object,
    *,
    field: str,
    raw_text: str,
) -> dict[str, JsonPayload]:
    if not isinstance(value, dict):
        raise BybitWsProtocolError(f"{field} must be an object", raw_text=raw_text)
    return cast(dict[str, JsonPayload], value)


def _required_array(
    value: object,
    *,
    field: str,
    raw_text: str,
) -> list[JsonPayload]:
    if not isinstance(value, list):
        raise BybitWsProtocolError(f"{field} must be an array", raw_text=raw_text)
    return cast(list[JsonPayload], value)


def _required_numeric(value: object, *, field: str, raw_text: str) -> None:
    if type(value) not in {int, str} and not isinstance(value, Decimal):
        raise BybitWsProtocolError(
            f"{field} must be a number or numeric string",
            raw_text=raw_text,
        )


def _optional_request_id(
    payload: Mapping[str, JsonPayload], raw_text: str
) -> str | None:
    if "req_id" not in payload:
        return None
    return _required_text(
        payload["req_id"],
        field="req_id",
        raw_text=raw_text,
        allow_empty=True,
    )


def _optional_connection_id(
    payload: Mapping[str, JsonPayload], raw_text: str
) -> str | None:
    if "conn_id" not in payload:
        return None
    return _required_text(payload["conn_id"], field="conn_id", raw_text=raw_text)


def _symbol(value: object, *, field: str, raw_text: str) -> str:
    symbol = _required_text(value, field=field, raw_text=raw_text)
    if _WIRE_SYMBOL.fullmatch(symbol) is None:
        raise BybitWsProtocolError(
            f"{field} must be an uppercase Spot/Linear symbol",
            raw_text=raw_text,
        )
    return symbol


def parse_topic(value: object) -> BybitWsTopic:
    if type(value) is not str or not value:
        raise ValueError("topic must be a non-empty string")
    parts = value.split(".")
    if len(parts) == 3 and parts[0] == "orderbook":
        symbol = parts[2]
        if _WIRE_SYMBOL.fullmatch(symbol) is None:
            raise ValueError("orderbook topic has an invalid symbol")
        if parts[1] == "rpi":
            return BybitWsTopic(value, BybitWsTopicKind.RPI_ORDERBOOK, symbol, 50)
        if parts[1] == "full":
            return BybitWsTopic(value, BybitWsTopicKind.FULL_ORDERBOOK, symbol)
        try:
            depth = int(parts[1])
        except ValueError as error:
            raise ValueError("orderbook topic has an invalid depth") from error
        if str(depth) != parts[1] or depth not in BYBIT_STANDARD_BOOK_DEPTHS:
            raise ValueError("orderbook topic depth is not supported")
        return BybitWsTopic(value, BybitWsTopicKind.ORDERBOOK, symbol, depth)
    if len(parts) == 2:
        prefix, suffix = parts
        if prefix in {"insurance", "adlAlert"}:
            if suffix not in _POOL_FILTERS:
                raise ValueError(f"{prefix} topic has an unsupported pool filter")
            scoped_kind = (
                BybitWsTopicKind.INSURANCE
                if prefix == "insurance"
                else BybitWsTopicKind.ADL_ALERT
            )
            return BybitWsTopic(value, scoped_kind, None, suffix)
        if value == "system.status":
            return BybitWsTopic(value, BybitWsTopicKind.SYSTEM_STATUS, None)
        if _WIRE_SYMBOL.fullmatch(suffix) is None:
            raise ValueError("topic has an invalid symbol")
        kinds = {
            "publicTrade": BybitWsTopicKind.TRADE,
            "tickers": BybitWsTopicKind.TICKER,
            "allLiquidation": BybitWsTopicKind.ALL_LIQUIDATION,
            "priceLimit": BybitWsTopicKind.PRICE_LIMIT,
        }
        symbol_kind = kinds.get(prefix)
        if symbol_kind is None:
            raise ValueError("unsupported Bybit public topic")
        return BybitWsTopic(value, symbol_kind, suffix)
    if len(parts) == 3 and parts[0] == "kline":
        interval, symbol = parts[1:]
        if interval not in _KLINE_INTERVALS:
            raise ValueError("kline topic has an unsupported interval")
        if _WIRE_SYMBOL.fullmatch(symbol) is None:
            raise ValueError("kline topic has an invalid symbol")
        return BybitWsTopic(value, BybitWsTopicKind.KLINE, symbol, interval)
    raise ValueError("unsupported Bybit public topic")


def _require_type(
    payload: Mapping[str, JsonPayload],
    *,
    allowed: frozenset[str],
    raw_text: str,
) -> str:
    message_type = _required_text(payload.get("type"), field="type", raw_text=raw_text)
    if message_type not in allowed:
        raise BybitWsProtocolError(
            "type is not allowed for this topic",
            raw_text=raw_text,
        )
    return message_type


def _validate_levels(
    value: object,
    *,
    field: str,
    width: int,
    raw_text: str,
) -> None:
    levels = _required_array(value, field=field, raw_text=raw_text)
    for index, level in enumerate(levels):
        if not isinstance(level, list) or len(level) != width:
            raise BybitWsProtocolError(
                f"{field}[{index}] must contain exactly {width} strings",
                raw_text=raw_text,
            )
        for part_index, part in enumerate(level):
            _required_text(
                part,
                field=f"{field}[{index}][{part_index}]",
                raw_text=raw_text,
            )


def _validate_book(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    raw_text: str,
) -> None:
    allowed = (
        frozenset({"delta"})
        if topic.kind is BybitWsTopicKind.FULL_ORDERBOOK
        else (
            frozenset({"snapshot"})
            if topic.kind is BybitWsTopicKind.ORDERBOOK and topic.parameter == 1
            else frozenset({"snapshot", "delta"})
        )
    )
    message_type = _require_type(payload, allowed=allowed, raw_text=raw_text)
    data = _required_object(payload.get("data"), field="data", raw_text=raw_text)
    symbol = _symbol(data.get("s"), field="data.s", raw_text=raw_text)
    if symbol != topic.wire_symbol:
        raise BybitWsProtocolError("data.s does not match topic", raw_text=raw_text)
    width = 3 if topic.kind is BybitWsTopicKind.RPI_ORDERBOOK else 2
    _validate_levels(data.get("b"), field="data.b", width=width, raw_text=raw_text)
    _validate_levels(data.get("a"), field="data.a", width=width, raw_text=raw_text)
    update_id = _required_int(data.get("u"), field="data.u", raw_text=raw_text)
    if (
        topic.kind in {BybitWsTopicKind.ORDERBOOK, BybitWsTopicKind.RPI_ORDERBOOK}
        and update_id == 1
        and message_type != "snapshot"
    ):
        raise BybitWsProtocolError(
            "standard/RPI u=1 must be a snapshot",
            raw_text=raw_text,
        )
    _required_int(data.get("seq"), field="data.seq", raw_text=raw_text)
    _required_int(payload.get("cts"), field="cts", raw_text=raw_text)


def _object_rows(
    value: object, *, field: str, raw_text: str
) -> list[dict[str, JsonPayload]]:
    rows = _required_array(value, field=field, raw_text=raw_text)
    parsed: list[dict[str, JsonPayload]] = []
    for index, row in enumerate(rows):
        parsed.append(
            _required_object(row, field=f"{field}[{index}]", raw_text=raw_text)
        )
    return parsed


def _validate_trade(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    market: Market | None,
    raw_text: str,
) -> None:
    _require_type(payload, allowed=frozenset({"snapshot"}), raw_text=raw_text)
    for index, row in enumerate(
        _object_rows(payload.get("data"), field="data", raw_text=raw_text)
    ):
        prefix = f"data[{index}]"
        _required_int(row.get("T"), field=f"{prefix}.T", raw_text=raw_text)
        if (
            _symbol(row.get("s"), field=f"{prefix}.s", raw_text=raw_text)
            != topic.wire_symbol
        ):
            raise BybitWsProtocolError(
                "trade symbol does not match topic", raw_text=raw_text
            )
        side = _required_text(row.get("S"), field=f"{prefix}.S", raw_text=raw_text)
        if side not in {"Buy", "Sell"}:
            raise BybitWsProtocolError(
                "trade side must be Buy or Sell", raw_text=raw_text
            )
        for field in ("v", "p", "i"):
            _required_text(row.get(field), field=f"{prefix}.{field}", raw_text=raw_text)
        _required_bool(row.get("BT"), field=f"{prefix}.BT", raw_text=raw_text)
        _required_int(row.get("seq"), field=f"{prefix}.seq", raw_text=raw_text)
        if market is Market.PERPETUAL:
            _required_text(row.get("L"), field=f"{prefix}.L", raw_text=raw_text)
        elif "L" in row:
            _required_text(row["L"], field=f"{prefix}.L", raw_text=raw_text)
        if "RPI" in row:
            _required_bool(row["RPI"], field=f"{prefix}.RPI", raw_text=raw_text)


def _validate_ticker(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    market: Market | None,
    raw_text: str,
) -> None:
    allowed = (
        frozenset({"snapshot"})
        if market is Market.SPOT
        else frozenset({"snapshot", "delta"})
    )
    message_type = _require_type(payload, allowed=allowed, raw_text=raw_text)
    _required_int(payload.get("cs"), field="cs", raw_text=raw_text)
    data = _required_object(payload.get("data"), field="data", raw_text=raw_text)
    if (
        _symbol(data.get("symbol"), field="data.symbol", raw_text=raw_text)
        != topic.wire_symbol
    ):
        raise BybitWsProtocolError(
            "ticker symbol does not match topic", raw_text=raw_text
        )
    # All other derivatives ticker fields are sparse delta or future fields.
    for field in _KNOWN_TICKER_STRING_FIELDS.intersection(data):
        _required_text(
            data[field],
            field=f"data.{field}",
            raw_text=raw_text,
            allow_empty=True,
        )
    if message_type == "snapshot":
        required = (
            _SPOT_TICKER_SNAPSHOT_FIELDS
            if market is Market.SPOT
            else _LINEAR_TICKER_SNAPSHOT_FIELDS
        )
        missing = sorted(required - data.keys())
        if missing:
            raise BybitWsProtocolError(
                "ticker snapshot is missing required fields: " + ", ".join(missing),
                raw_text=raw_text,
            )
    elif len(data) < 2:
        raise BybitWsProtocolError(
            "ticker delta must contain at least one update field",
            raw_text=raw_text,
        )


def _validate_kline(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    raw_text: str,
) -> None:
    _require_type(payload, allowed=frozenset({"snapshot"}), raw_text=raw_text)
    for index, row in enumerate(
        _object_rows(payload.get("data"), field="data", raw_text=raw_text)
    ):
        prefix = f"data[{index}]"
        for field in ("start", "end", "timestamp"):
            _required_int(row.get(field), field=f"{prefix}.{field}", raw_text=raw_text)
        interval = _required_text(
            row.get("interval"), field=f"{prefix}.interval", raw_text=raw_text
        )
        if interval != topic.parameter:
            raise BybitWsProtocolError(
                "kline interval does not match topic", raw_text=raw_text
            )
        for field in ("open", "close", "high", "low", "volume", "turnover"):
            _required_text(row.get(field), field=f"{prefix}.{field}", raw_text=raw_text)
        _required_bool(row.get("confirm"), field=f"{prefix}.confirm", raw_text=raw_text)


def _validate_liquidation(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    raw_text: str,
) -> None:
    _require_type(payload, allowed=frozenset({"snapshot"}), raw_text=raw_text)
    for index, row in enumerate(
        _object_rows(payload.get("data"), field="data", raw_text=raw_text)
    ):
        prefix = f"data[{index}]"
        _required_int(row.get("T"), field=f"{prefix}.T", raw_text=raw_text)
        if (
            _symbol(row.get("s"), field=f"{prefix}.s", raw_text=raw_text)
            != topic.wire_symbol
        ):
            raise BybitWsProtocolError(
                "liquidation symbol does not match topic", raw_text=raw_text
            )
        side = _required_text(row.get("S"), field=f"{prefix}.S", raw_text=raw_text)
        if side not in {"Buy", "Sell"}:
            raise BybitWsProtocolError(
                "liquidation side must be Buy or Sell", raw_text=raw_text
            )
        _required_text(row.get("v"), field=f"{prefix}.v", raw_text=raw_text)
        _required_text(row.get("p"), field=f"{prefix}.p", raw_text=raw_text)


def _validate_insurance(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    raw_text: str,
) -> None:
    _require_type(payload, allowed=frozenset({"snapshot", "delta"}), raw_text=raw_text)
    for index, row in enumerate(
        _object_rows(payload.get("data"), field="data", raw_text=raw_text)
    ):
        coin = _required_text(
            row.get("coin"), field=f"data[{index}].coin", raw_text=raw_text
        )
        if topic.parameter != "inverse" and coin != topic.parameter:
            raise BybitWsProtocolError(
                "insurance coin does not match topic",
                raw_text=raw_text,
            )
        for field in ("symbols", "balance", "updateTime"):
            _required_text(
                row.get(field), field=f"data[{index}].{field}", raw_text=raw_text
            )


def _validate_price_limit(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    raw_text: str,
) -> None:
    data = _required_object(payload.get("data"), field="data", raw_text=raw_text)
    if (
        _symbol(data.get("symbol"), field="data.symbol", raw_text=raw_text)
        != topic.wire_symbol
    ):
        raise BybitWsProtocolError(
            "price-limit symbol does not match topic", raw_text=raw_text
        )
    _required_text(data.get("buyLmt"), field="data.buyLmt", raw_text=raw_text)
    _required_text(data.get("sellLmt"), field="data.sellLmt", raw_text=raw_text)


def _validate_adl(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    raw_text: str,
) -> None:
    _require_type(payload, allowed=frozenset({"snapshot"}), raw_text=raw_text)
    for index, row in enumerate(
        _object_rows(payload.get("data"), field="data", raw_text=raw_text)
    ):
        prefix = f"data[{index}]"
        coin = _required_text(row.get("c"), field=f"{prefix}.c", raw_text=raw_text)
        if topic.parameter != "inverse" and coin != topic.parameter:
            raise BybitWsProtocolError(
                "ADL coin does not match topic",
                raw_text=raw_text,
            )
        _symbol(row.get("s"), field=f"{prefix}.s", raw_text=raw_text)
        for field in ("b", "mb", "i_pr", "pr", "adl_tt", "adl_sr"):
            _required_numeric(
                row.get(field), field=f"{prefix}.{field}", raw_text=raw_text
            )


def _validate_status(payload: Mapping[str, JsonPayload], *, raw_text: str) -> None:
    for index, row in enumerate(
        _object_rows(payload.get("data"), field="data", raw_text=raw_text)
    ):
        prefix = f"data[{index}]"
        for field in ("id", "title", "state", "begin", "end", "href"):
            _required_text(
                row.get(field),
                field=f"{prefix}.{field}",
                raw_text=raw_text,
                allow_empty=field == "href",
            )
        for field in ("serviceTypes", "product", "uidSuffix"):
            values = _required_array(
                row.get(field), field=f"{prefix}.{field}", raw_text=raw_text
            )
            for value_index, value in enumerate(values):
                _required_int(
                    value,
                    field=f"{prefix}.{field}[{value_index}]",
                    raw_text=raw_text,
                )
        for field in ("maintainType", "env"):
            value = row.get(field)
            if type(value) is int:
                continue
            _required_text(value, field=f"{prefix}.{field}", raw_text=raw_text)


def _validate_data_message(
    payload: Mapping[str, JsonPayload],
    topic: BybitWsTopic,
    *,
    market: Market | None,
    raw_text: str,
) -> None:
    _required_int(payload.get("ts"), field="ts", raw_text=raw_text)
    if topic.kind is not BybitWsTopicKind.SYSTEM_STATUS and market is None:
        raise BybitWsProtocolError(
            "market is required for market-data frames",
            raw_text=raw_text,
        )
    if market is Market.SPOT and topic.kind in {
        BybitWsTopicKind.ALL_LIQUIDATION,
        BybitWsTopicKind.INSURANCE,
        BybitWsTopicKind.PRICE_LIMIT,
        BybitWsTopicKind.ADL_ALERT,
    }:
        raise BybitWsProtocolError(
            "topic is not available for Spot",
            raw_text=raw_text,
        )
    if topic.kind in {
        BybitWsTopicKind.ORDERBOOK,
        BybitWsTopicKind.RPI_ORDERBOOK,
        BybitWsTopicKind.FULL_ORDERBOOK,
    }:
        _validate_book(payload, topic, raw_text=raw_text)
    elif topic.kind is BybitWsTopicKind.TRADE:
        _validate_trade(payload, topic, market=market, raw_text=raw_text)
    elif topic.kind is BybitWsTopicKind.TICKER:
        _validate_ticker(payload, topic, market=market, raw_text=raw_text)
    elif topic.kind is BybitWsTopicKind.KLINE:
        _validate_kline(payload, topic, raw_text=raw_text)
    elif topic.kind is BybitWsTopicKind.ALL_LIQUIDATION:
        _validate_liquidation(payload, topic, raw_text=raw_text)
    elif topic.kind is BybitWsTopicKind.INSURANCE:
        _validate_insurance(payload, topic, raw_text=raw_text)
    elif topic.kind is BybitWsTopicKind.PRICE_LIMIT:
        _validate_price_limit(payload, topic, raw_text=raw_text)
    elif topic.kind is BybitWsTopicKind.ADL_ALERT:
        _validate_adl(payload, topic, raw_text=raw_text)
    else:
        _validate_status(payload, raw_text=raw_text)


def parse_ws_message(raw: object, *, market: Market | None = None) -> BybitWsMessage:
    if market is not None and type(market) is not Market:
        raise TypeError("market must be Market or None")
    raw_text = _text_frame(raw)
    try:
        decoded = validate_json_payload(decode_json(raw_text))
    except (TypeError, ValueError) as error:
        raise BybitWsProtocolError(
            "WebSocket frame must contain strict JSON",
            raw_text=raw_text,
        ) from error
    if not isinstance(decoded, dict):
        raise BybitWsProtocolError(
            "WebSocket JSON frame must be an object",
            raw_text=raw_text,
        )
    payload = cast(dict[str, JsonPayload], decoded)
    request_id = _optional_request_id(payload, raw_text)
    connection_id = _optional_connection_id(payload, raw_text)
    operation = payload.get("op")
    if operation is not None:
        op = _required_text(operation, field="op", raw_text=raw_text)
        if op not in {"ping", "subscribe", "unsubscribe"}:
            raise BybitWsProtocolError(
                "unsupported Bybit public WebSocket operation",
                raw_text=raw_text,
            )
        success = _required_bool(
            payload.get("success"), field="success", raw_text=raw_text
        )
        message = _required_text(
            payload.get("ret_msg"),
            field="ret_msg",
            raw_text=raw_text,
            allow_empty=True,
        )
        if connection_id is None:
            raise BybitWsProtocolError("conn_id is required", raw_text=raw_text)
        if not success:
            kind = BybitWsMessageKind.ERROR
        elif op == "ping":
            if message != "pong":
                raise BybitWsProtocolError(
                    "successful ping response must contain pong",
                    raw_text=raw_text,
                )
            kind = BybitWsMessageKind.PONG
        elif op == "subscribe":
            if message not in {"", "subscribe"}:
                raise BybitWsProtocolError(
                    "successful subscribe ACK has an unsupported ret_msg",
                    raw_text=raw_text,
                )
            kind = BybitWsMessageKind.SUBSCRIBE_ACK
        else:
            if message not in {"", "unsubscribe"}:
                raise BybitWsProtocolError(
                    "successful unsubscribe ACK has an unsupported ret_msg",
                    raw_text=raw_text,
                )
            kind = BybitWsMessageKind.UNSUBSCRIBE_ACK
        return BybitWsMessage(
            kind=kind,
            raw_text=raw_text,
            payload=payload,
            topic=None,
            request_id=request_id,
            connection_id=connection_id,
            error_message=message if kind is BybitWsMessageKind.ERROR else None,
        )

    try:
        topic = parse_topic(payload.get("topic"))
    except ValueError as error:
        raise BybitWsProtocolError(str(error), raw_text=raw_text) from error
    _validate_data_message(payload, topic, market=market, raw_text=raw_text)
    return BybitWsMessage(
        kind=BybitWsMessageKind.DATA,
        raw_text=raw_text,
        payload=payload,
        topic=topic,
        request_id=request_id,
        connection_id=connection_id,
        error_message=None,
    )


def _endpoint_path(subscription: WebSocketSubscription) -> str:
    path = urlsplit(subscription.endpoint).path
    if path not in {_SPOT_PATH, _LINEAR_PATH, _STATUS_PATH}:
        raise ValueError("endpoint is not an evidenced Bybit anonymous WebSocket path")
    if path == _SPOT_PATH and subscription.market is not Market.SPOT:
        raise ValueError("Bybit Spot subscriptions require the Spot endpoint")
    if path == _LINEAR_PATH and subscription.market is not Market.PERPETUAL:
        raise ValueError("Bybit perpetual subscriptions require the Linear endpoint")
    return path


def _no_params(subscription: WebSocketSubscription) -> None:
    if subscription.params:
        raise ValueError(f"{subscription.channel} does not accept subscription params")


def _require_symbol(subscription: WebSocketSubscription) -> str:
    if subscription.wire_symbol is None:
        raise ValueError(f"{subscription.channel} requires a wire symbol")
    if _WIRE_SYMBOL.fullmatch(subscription.wire_symbol) is None:
        raise ValueError("wire symbol must be an uppercase Spot/Linear symbol")
    return subscription.wire_symbol


def _require_market_scope(subscription: WebSocketSubscription) -> None:
    if subscription.wire_symbol is not None:
        raise ValueError(f"{subscription.channel} must be market scoped")


def subscription_topic(
    subscription: WebSocketSubscription,
    *,
    full_book_capability: BybitFullBookCapability | None = None,
    full_book_probe_evidence: BybitFullBookProbeEvidence | None = None,
) -> str:
    if type(subscription) is not WebSocketSubscription:
        raise TypeError("subscription must be WebSocketSubscription")
    path = _endpoint_path(subscription)
    channel = subscription.channel
    if channel == "system.status":
        if path != _STATUS_PATH:
            raise ValueError("system.status requires the misc/status endpoint")
        _require_market_scope(subscription)
        _no_params(subscription)
        return channel
    if path == _STATUS_PATH:
        raise ValueError("misc/status endpoint accepts only system.status")

    if channel == "orderbook":
        symbol = _require_symbol(subscription)
        if set(subscription.params) != {"depth"}:
            raise ValueError("orderbook requires only depth")
        depth = subscription.params["depth"]
        if type(depth) is not int or depth not in BYBIT_STANDARD_BOOK_DEPTHS:
            raise ValueError("orderbook depth must be one of 1, 50, 200, 1000")
        return f"orderbook.{depth}.{symbol}"
    if channel == "orderbook.rpi":
        symbol = _require_symbol(subscription)
        _no_params(subscription)
        return f"orderbook.rpi.{symbol}"
    if channel == "orderbook.full":
        symbol = _require_symbol(subscription)
        _no_params(subscription)
        if (
            full_book_capability is None
            or type(full_book_capability) is not BybitFullBookCapability
            or not full_book_capability.enabled
            or full_book_capability.market is not subscription.market
            or not full_book_capability.requires_rest_bootstrap
            or full_book_probe_evidence is None
            or type(full_book_probe_evidence) is not BybitFullBookProbeEvidence
            or not full_book_probe_evidence.succeeded
            or full_book_probe_evidence.feature_id != full_book_capability.feature_id
            or full_book_probe_evidence.market is not subscription.market
            or full_book_probe_evidence.endpoint_identity != subscription.endpoint
            or full_book_probe_evidence.wire_symbol != symbol
            or full_book_probe_evidence.egress_id != subscription.egress_id
            or full_book_probe_evidence.observed_at != full_book_capability.as_of
        ):
            raise CapabilityError(
                "Bybit full orderbook requires exact enabled capability/probe evidence"
            )
        return f"orderbook.full.{symbol}"
    if channel == "kline":
        symbol = _require_symbol(subscription)
        if set(subscription.params) != {"interval"}:
            raise ValueError("kline requires only interval")
        interval = subscription.params["interval"]
        if type(interval) is not str or interval not in _KLINE_INTERVALS:
            raise ValueError("kline interval is unsupported")
        return f"kline.{interval}.{symbol}"
    if channel in {"insurance", "adlAlert"}:
        if subscription.market is not Market.PERPETUAL:
            raise ValueError(f"{channel} is available only on the Linear endpoint")
        _require_market_scope(subscription)
        if set(subscription.params) != {"coin"}:
            raise ValueError(f"{channel} requires only coin")
        coin = subscription.params["coin"]
        if coin != "USDT":
            raise ValueError(f"{channel} supports only USDT in the Linear scope")
        return f"{channel}.{coin}"
    symbol_channels = {
        "publicTrade",
        "tickers",
        "priceLimit",
        "allLiquidation",
    }
    if channel not in symbol_channels:
        raise ValueError("unsupported Bybit public channel")
    if channel == "allLiquidation" and subscription.market is not Market.PERPETUAL:
        raise ValueError("allLiquidation is available only on the Linear endpoint")
    if channel == "priceLimit" and subscription.market is not Market.PERPETUAL:
        raise ValueError("priceLimit is available only on the Linear endpoint")
    symbol = _require_symbol(subscription)
    _no_params(subscription)
    return f"{channel}.{symbol}"


def _normalized_subscriptions(
    subscriptions: Sequence[WebSocketSubscription],
) -> tuple[WebSocketSubscription, ...]:
    if isinstance(subscriptions, (str, bytes, bytearray)):
        raise TypeError("subscriptions must be a sequence of WebSocketSubscription")
    normalized = tuple(subscriptions)
    if not normalized:
        raise ValueError("at least one WebSocket subscription is required")
    if any(type(item) is not WebSocketSubscription for item in normalized):
        raise TypeError("subscriptions must contain WebSocketSubscription values")
    first = normalized[0]
    for item in normalized[1:]:
        if item.endpoint != first.endpoint:
            raise ValueError("one WebSocket request cannot mix endpoints")
        if item.egress_id != first.egress_id:
            raise ValueError("one WebSocket request cannot mix egress routes")
        if item.shard_id != first.shard_id:
            raise ValueError("one WebSocket request cannot mix storage shards")
    return normalized


def validate_connection_topic_limit(topics: Sequence[str]) -> int:
    if isinstance(topics, (str, bytes, bytearray)):
        raise TypeError("topics must be a sequence of strings")
    normalized = tuple(topics)
    if any(type(topic) is not str or not topic for topic in normalized):
        raise ValueError("topics must contain non-empty strings")
    characters = len(encode_json(list(normalized)).decode("utf-8"))
    if characters > BYBIT_WS_ARGS_CHARACTER_LIMIT:
        raise ValueError("Bybit WebSocket args exceed 21,000 characters")
    return characters


def _validated_operation_request_id(
    request_id: str | None,
    *,
    required: bool,
) -> str | None:
    if required and request_id is None:
        raise ValueError("tracked Bybit WebSocket operations require request_id")
    if request_id is not None and (
        type(request_id) is not str or _REQUEST_ID.fullmatch(request_id) is None
    ):
        raise ValueError("request_id must be 1-64 printable ASCII characters")
    return request_id


def _operation_topics(
    subscriptions: Sequence[WebSocketSubscription],
    *,
    full_book_capability: BybitFullBookCapability | None,
    full_book_probe_evidence: BybitFullBookProbeEvidence | None,
) -> tuple[tuple[WebSocketSubscription, ...], tuple[str, ...]]:
    normalized = _normalized_subscriptions(subscriptions)
    topics = tuple(
        subscription_topic(
            item,
            full_book_capability=full_book_capability,
            full_book_probe_evidence=full_book_probe_evidence,
        )
        for item in normalized
    )
    if len(set(topics)) != len(topics):
        raise ValueError("Bybit WebSocket subscription topics must be unique")
    path = _endpoint_path(normalized[0])
    if path == _SPOT_PATH and len(topics) > BYBIT_WS_SPOT_ARGS_PER_REQUEST:
        raise ValueError("Bybit Spot permits at most 10 args per subscription request")
    validate_connection_topic_limit(topics)
    return normalized, topics


def _operation_message(
    operation: str,
    topics: tuple[str, ...],
    *,
    request_id: str | None,
) -> str:
    payload: dict[str, JsonPayload] = {"op": operation, "args": list(topics)}
    if request_id is not None:
        payload = {"req_id": request_id, **payload}
    return encode_json(payload).decode("utf-8")


def build_subscribe_message(
    subscriptions: Sequence[WebSocketSubscription],
    *,
    request_id: str | None = None,
    full_book_capability: BybitFullBookCapability | None = None,
    full_book_probe_evidence: BybitFullBookProbeEvidence | None = None,
    connection_topics: Sequence[str] = (),
) -> str:
    request_id = _validated_operation_request_id(request_id, required=False)
    _, topics = _operation_topics(
        subscriptions,
        full_book_capability=full_book_capability,
        full_book_probe_evidence=full_book_probe_evidence,
    )
    if isinstance(connection_topics, (str, bytes, bytearray)):
        raise TypeError("connection_topics must be a sequence of strings")
    existing_topics = tuple(connection_topics)
    if len(set(existing_topics)) != len(existing_topics):
        raise ValueError("existing Bybit WebSocket connection topics must be unique")
    if set(existing_topics).intersection(topics):
        raise ValueError("Bybit WebSocket connection topics must be unique")
    validate_connection_topic_limit((*existing_topics, *topics))
    return _operation_message("subscribe", topics, request_id=request_id)


def build_unsubscribe_message(
    subscriptions: Sequence[WebSocketSubscription],
    *,
    request_id: str | None = None,
    full_book_capability: BybitFullBookCapability | None = None,
    full_book_probe_evidence: BybitFullBookProbeEvidence | None = None,
) -> str:
    request_id = _validated_operation_request_id(request_id, required=False)
    _, topics = _operation_topics(
        subscriptions,
        full_book_capability=full_book_capability,
        full_book_probe_evidence=full_book_probe_evidence,
    )
    return _operation_message("unsubscribe", topics, request_id=request_id)


@dataclass(frozen=True, slots=True)
class BybitWsPendingTopicOperation:
    request_id: str
    operation: str
    topics: tuple[str, ...]

    def __post_init__(self) -> None:
        _validated_operation_request_id(self.request_id, required=True)
        if self.operation not in {"subscribe", "unsubscribe"}:
            raise ValueError("pending operation must be subscribe or unsubscribe")
        if (
            type(self.topics) is not tuple
            or not self.topics
            or any(type(topic) is not str or not topic for topic in self.topics)
        ):
            raise ValueError("pending operation topics must be non-empty strings")
        if len(set(self.topics)) != len(self.topics):
            raise ValueError("pending operation topics must be unique")


class BybitWsConnectionTopicBudgetTracker:
    """Track one connection's accepted, data-confirmed, and pending topics."""

    __slots__ = (
        "_accepted_topics",
        "_confirmed_topics",
        "_connection_scope",
        "_pending",
    )

    def __init__(self) -> None:
        self._accepted_topics: set[str] = set()
        self._confirmed_topics: set[str] = set()
        self._pending: dict[str, BybitWsPendingTopicOperation] = {}
        self._connection_scope: tuple[str, str, str] | None = None

    @property
    def accepted_topics(self) -> tuple[str, ...]:
        return tuple(sorted(self._accepted_topics))

    @property
    def confirmed_topics(self) -> tuple[str, ...]:
        return tuple(sorted(self._confirmed_topics))

    @property
    def pending_operations(self) -> tuple[BybitWsPendingTopicOperation, ...]:
        return tuple(self._pending[key] for key in sorted(self._pending))

    @property
    def pending_subscribe_topics(self) -> tuple[str, ...]:
        topics = {
            topic
            for operation in self._pending.values()
            if operation.operation == "subscribe"
            for topic in operation.topics
        }
        return tuple(sorted(topics))

    @property
    def budget_topics(self) -> tuple[str, ...]:
        return tuple(sorted(self._accepted_topics | set(self.pending_subscribe_topics)))

    @property
    def budget_characters(self) -> int:
        return validate_connection_topic_limit(self.budget_topics)

    @property
    def connection_scope(self) -> tuple[str, str, str] | None:
        return self._connection_scope

    def _scope_for(
        self,
        subscriptions: tuple[WebSocketSubscription, ...],
    ) -> tuple[str, str, str]:
        first = subscriptions[0]
        scope = (first.endpoint, first.egress_id, first.shard_id)
        if self._connection_scope is not None and scope != self._connection_scope:
            raise ValueError("tracked subscriptions do not belong to this connection")
        return scope

    def _require_new_request_id(self, request_id: str) -> None:
        if request_id in self._pending:
            raise ValueError("Bybit WebSocket request_id is already pending")

    def prepare_subscribe(
        self,
        subscriptions: Sequence[WebSocketSubscription],
        *,
        request_id: str,
        full_book_capability: BybitFullBookCapability | None = None,
        full_book_probe_evidence: BybitFullBookProbeEvidence | None = None,
    ) -> str:
        validated_request_id = cast(
            str,
            _validated_operation_request_id(request_id, required=True),
        )
        normalized, topics = _operation_topics(
            subscriptions,
            full_book_capability=full_book_capability,
            full_book_probe_evidence=full_book_probe_evidence,
        )
        scope = self._scope_for(normalized)
        self._require_new_request_id(validated_request_id)
        tracked_topics = {
            topic for operation in self._pending.values() for topic in operation.topics
        }
        if set(topics).intersection(self._accepted_topics | tracked_topics):
            raise ValueError("Bybit WebSocket connection topics must be unique")
        validate_connection_topic_limit((*self.budget_topics, *topics))
        message = _operation_message(
            "subscribe",
            topics,
            request_id=validated_request_id,
        )
        self._connection_scope = scope
        self._pending[validated_request_id] = BybitWsPendingTopicOperation(
            request_id=validated_request_id,
            operation="subscribe",
            topics=topics,
        )
        return message

    def prepare_unsubscribe(
        self,
        subscriptions: Sequence[WebSocketSubscription],
        *,
        request_id: str,
        full_book_capability: BybitFullBookCapability | None = None,
        full_book_probe_evidence: BybitFullBookProbeEvidence | None = None,
    ) -> str:
        validated_request_id = cast(
            str,
            _validated_operation_request_id(request_id, required=True),
        )
        normalized, topics = _operation_topics(
            subscriptions,
            full_book_capability=full_book_capability,
            full_book_probe_evidence=full_book_probe_evidence,
        )
        scope = self._scope_for(normalized)
        self._require_new_request_id(validated_request_id)
        topic_set = set(topics)
        if not topic_set.issubset(self._accepted_topics):
            raise ValueError("cannot unsubscribe a topic that is not accepted")
        pending_topics = {
            topic for operation in self._pending.values() for topic in operation.topics
        }
        if topic_set.intersection(pending_topics):
            raise ValueError("Bybit WebSocket topic already has a pending operation")
        message = _operation_message(
            "unsubscribe",
            topics,
            request_id=validated_request_id,
        )
        self._connection_scope = scope
        self._pending[validated_request_id] = BybitWsPendingTopicOperation(
            request_id=validated_request_id,
            operation="unsubscribe",
            topics=topics,
        )
        return message

    def expects_data(self, message: BybitWsMessage) -> bool:
        if type(message) is not BybitWsMessage:
            raise TypeError("message must be BybitWsMessage")
        return (
            message.kind is BybitWsMessageKind.DATA
            and message.topic is not None
            and message.topic.raw
            in (self._accepted_topics | set(self.pending_subscribe_topics))
        )

    def observe(self, message: BybitWsMessage) -> None:
        if type(message) is not BybitWsMessage:
            raise TypeError("message must be BybitWsMessage")
        if message.kind is BybitWsMessageKind.DATA:
            if not self.expects_data(message):
                raise BybitWsProtocolError(
                    "data topic is not active or awaiting subscribe ACK",
                    raw_text=message.raw_text,
                )
            assert message.topic is not None
            self._confirmed_topics.add(message.topic.raw)
            return
        if message.kind is BybitWsMessageKind.PONG:
            return
        request_id = message.request_id
        if request_id is None or request_id not in self._pending:
            raise BybitWsProtocolError(
                "WebSocket control response does not match a pending request_id",
                raw_text=message.raw_text,
            )
        pending = self._pending[request_id]
        if message.payload.get("op") != pending.operation:
            raise BybitWsProtocolError(
                "WebSocket control response operation does not match request_id",
                raw_text=message.raw_text,
            )
        if message.kind is BybitWsMessageKind.ERROR:
            if pending.operation == "subscribe" and set(pending.topics).intersection(
                self._confirmed_topics
            ):
                raise BybitWsProtocolError(
                    "subscribe failure conflicts with already confirmed topic data",
                    raw_text=message.raw_text,
                )
            del self._pending[request_id]
            return
        if not message.acknowledges(
            operation=pending.operation,
            request_id=request_id,
        ):
            raise BybitWsProtocolError(
                "WebSocket ACK does not match its pending operation",
                raw_text=message.raw_text,
            )
        del self._pending[request_id]
        if pending.operation == "subscribe":
            self._accepted_topics.update(pending.topics)
        else:
            self._accepted_topics.difference_update(pending.topics)
            self._confirmed_topics.difference_update(pending.topics)

    def cancel_pending(self, request_id: str) -> BybitWsPendingTopicOperation:
        validated_request_id = cast(
            str,
            _validated_operation_request_id(request_id, required=True),
        )
        try:
            pending = self._pending[validated_request_id]
        except KeyError as error:
            raise ValueError("Bybit WebSocket request_id is not pending") from error
        if pending.operation == "subscribe" and set(pending.topics).intersection(
            self._confirmed_topics
        ):
            raise ValueError(
                "cannot cancel a subscribe request after topic data was confirmed"
            )
        return self._pending.pop(validated_request_id)


def build_ping_message() -> str:
    return encode_json({"op": "ping"}).decode("utf-8")


__all__ = [
    "BYBIT_DEFAULT_BOOK_DEPTH",
    "BYBIT_PERPETUAL_FULL_BOOK_AVAILABLE_FROM",
    "BYBIT_SPOT_FULL_BOOK_AVAILABLE_FROM",
    "BYBIT_STANDARD_BOOK_DEPTHS",
    "BYBIT_WS_ARGS_CHARACTER_LIMIT",
    "BYBIT_WS_CONNECTION_ATTEMPT_LIMIT",
    "BYBIT_WS_CONNECTION_ATTEMPT_WINDOW_SECONDS",
    "BYBIT_WS_HEARTBEAT_INTERVAL_SECONDS",
    "BYBIT_WS_LINEAR_URL",
    "BYBIT_WS_MARKET_CONNECTION_LIMIT_PER_IP",
    "BYBIT_WS_SPOT_ARGS_PER_REQUEST",
    "BYBIT_WS_SPOT_URL",
    "BYBIT_WS_STATUS_URL",
    "BybitCapabilityControlEvidence",
    "BybitFullBookCapability",
    "BybitFullBookDisabledReason",
    "BybitFullBookProbeEvidence",
    "BybitWsConnectionTopicBudgetTracker",
    "BybitWsMessage",
    "BybitWsMessageKind",
    "BybitWsPendingTopicOperation",
    "BybitWsProtocolError",
    "BybitWsTopic",
    "BybitWsTopicKind",
    "build_ping_message",
    "build_subscribe_message",
    "build_unsubscribe_message",
    "parse_topic",
    "parse_ws_message",
    "resolve_full_book_capability",
    "subscription_topic",
    "validate_connection_topic_limit",
]
