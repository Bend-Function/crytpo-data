from __future__ import annotations

import asyncio
import math
import random
import re
from base64 import b64decode, b64encode
from binascii import Error as Base64Error
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import TracebackType
from typing import Protocol, Self, cast
from urllib.parse import urlsplit

from crypto_collector.domain import Market
from crypto_collector.domain.json_codec import (
    JsonPayload,
    decode_json,
    encode_json,
    validate_json_payload,
)
from crypto_collector.exchanges.contracts import (
    PublicWebSocketTransport,
    WebSocketSubscription,
)
from crypto_collector.exchanges.okx.book import OkxBookFrame, parse_book_message
from crypto_collector.network import full_jitter_ns

OKX_WS_ARGUMENT_LIMIT_BYTES = 64 * 1024
OKX_WS_SILENCE_LIMIT_SECONDS = 30.0
OKX_WS_OPERATION_LIMIT_PER_HOUR = 480

_PUBLIC_PATH = "/ws/v5/public"
_BUSINESS_PATH = "/ws/v5/business"
_PUBLIC_SYMBOL_CHANNELS = frozenset(
    {
        "bbo-tbt",
        "books",
        "books-rpi",
        "books5",
        "funding-rate",
        "index-tickers",
        "mark-price",
        "open-interest",
        "price-limit",
        "tickers",
        "trades",
    }
)
_PUBLIC_MARKET_CHANNELS = frozenset(
    {"adl-warning", "instruments", "liquidation-orders", "status"}
)
_PUBLIC_CHANNELS = _PUBLIC_SYMBOL_CHANNELS | _PUBLIC_MARKET_CHANNELS
_COMMON_CANDLE_BARS = frozenset(
    {
        "3M",
        "1M",
        "1W",
        "1D",
        "2D",
        "3D",
        "5D",
        "12H",
        "6H",
        "4H",
        "2H",
        "1H",
        "30m",
        "15m",
        "5m",
        "3m",
        "1m",
    }
)
_UTC_CANDLE_BARS = frozenset(
    {
        "3Mutc",
        "1Mutc",
        "1Wutc",
        "1Dutc",
        "2Dutc",
        "3Dutc",
        "5Dutc",
        "12Hutc",
        "6Hutc",
    }
)
_BUSINESS_CANDLE_CHANNELS = frozenset(
    {
        *(f"candle{bar}" for bar in _COMMON_CANDLE_BARS | _UTC_CANDLE_BARS),
        "candle1s",
        *(f"index-candle{bar}" for bar in _COMMON_CANDLE_BARS | _UTC_CANDLE_BARS),
        *(f"mark-price-candle{bar}" for bar in _COMMON_CANDLE_BARS | _UTC_CANDLE_BARS),
        "mark-price-candle1Yutc",
    }
)
_BUSINESS_CHANNELS = _BUSINESS_CANDLE_CHANNELS | frozenset({"trades-all"})
_REQUEST_ID = re.compile(r"[A-Za-z0-9]{1,32}\Z")
_RESERVED_ARGUMENT_FIELDS = frozenset({"channel", "instId"})
_INCREMENTAL_BOOK_CHANNELS = frozenset({"books", "books-rpi"})
_SUPPORTED_INSTRUMENT_TYPES = frozenset({"SPOT", "SWAP"})


class OkxWsProtocolError(ValueError):
    def __init__(
        self,
        message: str,
        *,
        raw_text: str | None = None,
        raw_binary_base64: str | None = None,
        raw_binary_length: int | None = None,
    ) -> None:
        super().__init__(message)
        self.raw_text = raw_text
        self.raw_binary_base64 = raw_binary_base64
        self.raw_binary_length = raw_binary_length


class OkxWsMessageKind(StrEnum):
    PONG = "pong"
    SUBSCRIBE_ACK = "subscribe_ack"
    UNSUBSCRIBE_ACK = "unsubscribe_ack"
    ERROR = "error"
    NOTICE = "notice"
    DATA = "data"


@dataclass(frozen=True, slots=True)
class OkxWsMessage:
    kind: OkxWsMessageKind
    raw_text: str
    payload: dict[str, JsonPayload] | None
    argument: dict[str, JsonPayload] | None
    request_id: str | None
    connection_id: str | None
    code: str | None

    @property
    def channel(self) -> str | None:
        if self.argument is None:
            return None
        channel = self.argument.get("channel")
        return channel if type(channel) is str else None

    @property
    def wire_symbol(self) -> str | None:
        if self.argument is None:
            return None
        instrument = self.argument.get("instId")
        return instrument if type(instrument) is str else None

    @property
    def requests_service_upgrade(self) -> bool:
        return self.kind is OkxWsMessageKind.NOTICE and self.code == "64008"


class OkxWsSessionAction(StrEnum):
    MESSAGE = "message"
    PING_SENT = "ping_sent"
    RECONNECT = "reconnect"


class OkxWsReconnectReason(StrEnum):
    PONG_TIMEOUT = "pong_timeout"
    SUBSCRIPTION_TIMEOUT = "subscription_timeout"
    SERVICE_UPGRADE = "service_upgrade"
    SERVER_ERROR = "server_error"
    SUBSCRIPTION_MISMATCH = "subscription_mismatch"
    PROTOCOL_ERROR = "protocol_error"
    TRANSPORT_ERROR = "transport_error"


@dataclass(frozen=True, slots=True)
class OkxWsSessionEvent:
    action: OkxWsSessionAction
    message: OkxWsMessage | None = None
    reconnect_reason: OkxWsReconnectReason | None = None
    raw_text: str | None = None
    raw_binary_base64: str | None = None
    raw_binary_length: int | None = None
    error_type: str | None = None

    def __post_init__(self) -> None:
        if type(self.action) is not OkxWsSessionAction:
            raise TypeError("action must be OkxWsSessionAction")
        if self.action is OkxWsSessionAction.MESSAGE:
            if self.message is None or any(
                value is not None
                for value in (
                    self.reconnect_reason,
                    self.raw_text,
                    self.raw_binary_base64,
                    self.raw_binary_length,
                    self.error_type,
                )
            ):
                raise ValueError("message events require only a parsed message")
        elif self.action is OkxWsSessionAction.PING_SENT:
            if any(
                value is not None
                for value in (
                    self.message,
                    self.reconnect_reason,
                    self.raw_text,
                    self.raw_binary_base64,
                    self.raw_binary_length,
                    self.error_type,
                )
            ):
                raise ValueError("ping events must not contain message or error state")
        elif self.reconnect_reason is None:
            raise ValueError("reconnect events require a reconnect reason")
        binary_values = (self.raw_binary_base64, self.raw_binary_length)
        if (binary_values[0] is None) != (binary_values[1] is None):
            raise ValueError("binary frame evidence must contain base64 and length")
        if self.raw_binary_base64 is not None:
            if self.message is not None or self.raw_text is not None:
                raise ValueError(
                    "binary frame evidence cannot conflict with frame text"
                )
            if (
                type(self.raw_binary_base64) is not str
                or not self.raw_binary_base64.isascii()
                or type(self.raw_binary_length) is not int
                or self.raw_binary_length < 0
            ):
                raise ValueError("binary frame evidence is invalid")
            try:
                decoded = b64decode(self.raw_binary_base64, validate=True)
            except (Base64Error, ValueError) as error:
                raise ValueError(
                    "binary frame evidence is not strict base64"
                ) from error
            if len(decoded) != self.raw_binary_length:
                raise ValueError("binary frame evidence length does not match")
        elif self.message is not None and self.raw_text is not None:
            raise ValueError("parsed and raw reconnect frames cannot conflict")


@dataclass(frozen=True, slots=True)
class OkxWsReconnectPolicy:
    base_ns: int = 1_000_000_000
    cap_ns: int = 60_000_000_000

    def __post_init__(self) -> None:
        if type(self.base_ns) is not int or self.base_ns <= 0:
            raise ValueError("base_ns must be a positive integer")
        if type(self.cap_ns) is not int or self.cap_ns <= 0:
            raise ValueError("cap_ns must be a positive integer")
        if self.base_ns > self.cap_ns:
            raise ValueError("base_ns must not exceed cap_ns")

    def delay_ns(self, attempt: int, *, rng: random.Random) -> int:
        return full_jitter_ns(
            attempt,
            base_ns=self.base_ns,
            cap_ns=self.cap_ns,
            rng=rng,
        )


class _WebSocketConnection(Protocol):
    async def send(self, message: str) -> object: ...

    async def recv(self) -> str | bytes: ...


class _WebSocketContext(Protocol):
    async def __aenter__(self) -> _WebSocketConnection: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> object: ...


def _nonempty_text(
    value: object,
    *,
    field: str,
    raw_text: str | None = None,
) -> str:
    if type(value) is not str or not value:
        raise OkxWsProtocolError(
            f"{field} must be a non-empty string",
            raw_text=raw_text,
        )
    return value


def _optional_text(
    payload: Mapping[str, JsonPayload],
    field: str,
    *,
    raw_text: str,
) -> str | None:
    value = payload.get(field)
    if value is None:
        return None
    return _nonempty_text(value, field=field, raw_text=raw_text)


def _argument(
    payload: Mapping[str, JsonPayload],
    *,
    required: bool,
    raw_text: str,
) -> dict[str, JsonPayload] | None:
    value = payload.get("arg")
    if value is None and not required:
        return None
    if not isinstance(value, dict):
        raise OkxWsProtocolError("arg must be an object", raw_text=raw_text)
    _nonempty_text(value.get("channel"), field="arg.channel", raw_text=raw_text)
    return value


def _text_frame(raw: object) -> str:
    if type(raw) is str:
        return raw
    if type(raw) is bytes:
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise OkxWsProtocolError(
                "WebSocket bytes must be UTF-8 text",
                raw_binary_base64=b64encode(raw).decode("ascii"),
                raw_binary_length=len(raw),
            ) from error
    raise OkxWsProtocolError("WebSocket frame must be text or UTF-8 bytes")


def parse_ws_message(raw: object) -> OkxWsMessage:
    raw_text = _text_frame(raw)
    if raw_text == "pong":
        return OkxWsMessage(
            kind=OkxWsMessageKind.PONG,
            raw_text=raw_text,
            payload=None,
            argument=None,
            request_id=None,
            connection_id=None,
            code=None,
        )
    try:
        decoded = validate_json_payload(decode_json(raw_text))
    except (TypeError, ValueError) as error:
        raise OkxWsProtocolError(
            "WebSocket frame must contain strict JSON",
            raw_text=raw_text,
        ) from error
    if not isinstance(decoded, dict):
        raise OkxWsProtocolError(
            "WebSocket JSON frame must be an object",
            raw_text=raw_text,
        )
    payload = cast(dict[str, JsonPayload], decoded)
    request_id = _optional_text(payload, "id", raw_text=raw_text)
    connection_id = _optional_text(payload, "connId", raw_text=raw_text)
    code = _optional_text(payload, "code", raw_text=raw_text)
    event = payload.get("event")

    if event == "subscribe":
        kind = OkxWsMessageKind.SUBSCRIBE_ACK
        argument = _argument(payload, required=True, raw_text=raw_text)
    elif event == "unsubscribe":
        kind = OkxWsMessageKind.UNSUBSCRIBE_ACK
        argument = _argument(payload, required=True, raw_text=raw_text)
    elif event == "error":
        kind = OkxWsMessageKind.ERROR
        argument = _argument(payload, required=False, raw_text=raw_text)
        if code is None:
            raise OkxWsProtocolError(
                "error event must contain code",
                raw_text=raw_text,
            )
    elif event == "notice":
        kind = OkxWsMessageKind.NOTICE
        argument = _argument(payload, required=False, raw_text=raw_text)
        if code is None:
            raise OkxWsProtocolError(
                "notice event must contain code",
                raw_text=raw_text,
            )
    elif event is not None:
        raise OkxWsProtocolError(
            "unsupported OKX WebSocket event",
            raw_text=raw_text,
        )
    else:
        argument = _argument(payload, required=True, raw_text=raw_text)
        data = payload.get("data")
        if not isinstance(data, list):
            raise OkxWsProtocolError("data must be an array", raw_text=raw_text)
        action = payload.get("action")
        if action is not None:
            _nonempty_text(action, field="action", raw_text=raw_text)
        kind = OkxWsMessageKind.DATA

    return OkxWsMessage(
        kind=kind,
        raw_text=raw_text,
        payload=payload,
        argument=argument,
        request_id=request_id,
        connection_id=connection_id,
        code=code,
    )


def parse_incremental_book_frames(
    message: OkxWsMessage,
) -> tuple[OkxBookFrame, ...]:
    if type(message) is not OkxWsMessage:
        raise TypeError("message must be OkxWsMessage")
    if (
        message.kind is not OkxWsMessageKind.DATA
        or message.channel not in _INCREMENTAL_BOOK_CHANNELS
        or message.payload is None
    ):
        raise ValueError("message is not an OKX incremental book data frame")
    return parse_book_message(message.payload)


def _endpoint_path(subscription: WebSocketSubscription) -> str:
    path = urlsplit(subscription.endpoint).path
    if path not in {_PUBLIC_PATH, _BUSINESS_PATH}:
        raise ValueError("endpoint is not an evidenced OKX anonymous WebSocket path")
    return path


def _validate_channel(subscription: WebSocketSubscription) -> None:
    path = _endpoint_path(subscription)
    channel = subscription.channel
    if path == _PUBLIC_PATH:
        if channel not in _PUBLIC_CHANNELS:
            raise ValueError("channel is not allowed on the OKX public endpoint")
    elif channel not in _BUSINESS_CHANNELS:
        raise ValueError("channel is not allowed on the OKX business endpoint")


def _reject_reserved_params(subscription: WebSocketSubscription) -> None:
    for key in subscription.params:
        if key in _RESERVED_ARGUMENT_FIELDS:
            raise ValueError(f"subscription params must not replace {key}")


def _require_no_params(subscription: WebSocketSubscription) -> None:
    if subscription.params:
        raise ValueError(f"{subscription.channel} does not accept subscription params")


def _require_market_scope(subscription: WebSocketSubscription) -> None:
    if subscription.wire_symbol is not None:
        raise ValueError(f"{subscription.channel} must not contain instId")


def _inst_type_argument(
    subscription: WebSocketSubscription,
    *,
    allowed: frozenset[str],
) -> dict[str, JsonPayload]:
    _require_market_scope(subscription)
    if set(subscription.params) != {"instType"}:
        raise ValueError(f"{subscription.channel} requires only instType")
    inst_type = subscription.params["instType"]
    if type(inst_type) is not str:
        raise TypeError(f"{subscription.channel} instType must be a string")
    if inst_type not in allowed:
        expected = " or ".join(sorted(allowed))
        raise ValueError(f"{subscription.channel} instType must be {expected}")
    expected_for_market = "SPOT" if subscription.market is Market.SPOT else "SWAP"
    if inst_type != expected_for_market:
        raise ValueError(
            f"{subscription.channel} instType must match "
            f"{subscription.market.value} market"
        )
    return {"channel": subscription.channel, "instType": inst_type}


def _adl_warning_argument(
    subscription: WebSocketSubscription,
) -> dict[str, JsonPayload]:
    _require_market_scope(subscription)
    keys = set(subscription.params)
    if "instType" not in keys or not keys <= {"instType", "instFamily"}:
        raise ValueError("adl-warning requires instType and optional instFamily")
    inst_type = subscription.params["instType"]
    if type(inst_type) is not str:
        raise TypeError("adl-warning instType must be a string")
    if subscription.market is not Market.PERPETUAL or inst_type != "SWAP":
        raise ValueError("adl-warning requires perpetual market and SWAP instType")
    argument: dict[str, JsonPayload] = {
        "channel": subscription.channel,
        "instType": inst_type,
    }
    if "instFamily" in subscription.params:
        family = subscription.params["instFamily"]
        if type(family) is not str:
            raise TypeError("adl-warning instFamily must be a string")
        if not family:
            raise ValueError("adl-warning instFamily must be non-empty")
        argument["instFamily"] = family
    return argument


def subscription_argument(
    subscription: WebSocketSubscription,
) -> dict[str, JsonPayload]:
    if type(subscription) is not WebSocketSubscription:
        raise TypeError("subscription must be WebSocketSubscription")
    _validate_channel(subscription)
    _reject_reserved_params(subscription)
    if subscription.channel == "instruments":
        return _inst_type_argument(
            subscription,
            allowed=_SUPPORTED_INSTRUMENT_TYPES,
        )
    if subscription.channel == "liquidation-orders":
        return _inst_type_argument(subscription, allowed=frozenset({"SWAP"}))
    if subscription.channel == "adl-warning":
        return _adl_warning_argument(subscription)
    if subscription.channel == "status":
        _require_market_scope(subscription)
        _require_no_params(subscription)
        return {"channel": subscription.channel}

    if subscription.wire_symbol is None:
        raise ValueError(f"{subscription.channel} requires instId")
    _require_no_params(subscription)
    return {
        "channel": subscription.channel,
        "instId": subscription.wire_symbol,
    }


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
            raise ValueError("one WebSocket session cannot mix endpoints")
        if item.egress_id != first.egress_id:
            raise ValueError("one WebSocket session cannot mix egress routes")
        if item.shard_id != first.shard_id:
            raise ValueError("one WebSocket session cannot mix storage shards")
    return normalized


def _subscribe_parts(
    subscriptions: Sequence[WebSocketSubscription],
    *,
    request_id: str | None,
) -> tuple[tuple[WebSocketSubscription, ...], tuple[dict[str, JsonPayload], ...]]:
    normalized = _normalized_subscriptions(subscriptions)
    if request_id is not None and (
        type(request_id) is not str or _REQUEST_ID.fullmatch(request_id) is None
    ):
        raise ValueError("request_id must be 1-32 ASCII alphanumeric characters")
    arguments = tuple(subscription_argument(item) for item in normalized)
    keys = tuple(encode_json(argument) for argument in arguments)
    if len(set(keys)) != len(keys):
        raise ValueError("WebSocket subscription arguments must be unique")
    if len(encode_json(list(arguments))) > OKX_WS_ARGUMENT_LIMIT_BYTES:
        raise ValueError("OKX WebSocket subscription arguments exceed 64 KiB")
    return normalized, arguments


def build_subscribe_message(
    subscriptions: Sequence[WebSocketSubscription],
    *,
    request_id: str | None = None,
) -> str:
    _, arguments = _subscribe_parts(subscriptions, request_id=request_id)
    payload: dict[str, JsonPayload] = {
        "op": "subscribe",
        "args": list(arguments),
    }
    if request_id is not None:
        payload = {"id": request_id, **payload}
    return encode_json(payload).decode("utf-8")


def _argument_matches(
    expected: Mapping[str, JsonPayload],
    actual: Mapping[str, JsonPayload],
) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def _positive_timeout(value: float, *, field: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{field} must be a finite positive number")
    parsed = float(value)
    if parsed >= OKX_WS_SILENCE_LIMIT_SECONDS:
        raise ValueError(f"{field} must be less than 30 seconds")
    return parsed


class OkxWsSession:
    def __init__(
        self,
        transport: PublicWebSocketTransport,
        subscriptions: Sequence[WebSocketSubscription],
        *,
        request_id: str,
        idle_timeout_seconds: float = 25.0,
        pong_timeout_seconds: float = 5.0,
        subscription_timeout_seconds: float = 10.0,
    ) -> None:
        if not callable(getattr(transport, "connect", None)):
            raise TypeError("transport must provide connect()")
        normalized, arguments = _subscribe_parts(
            subscriptions,
            request_id=request_id,
        )
        self._transport = transport
        self._subscriptions = normalized
        self._arguments = arguments
        self._request_id = request_id
        self._subscribe_message = build_subscribe_message(
            normalized,
            request_id=request_id,
        )
        self._idle_timeout = _positive_timeout(
            idle_timeout_seconds,
            field="idle_timeout_seconds",
        )
        self._pong_timeout = _positive_timeout(
            pong_timeout_seconds,
            field="pong_timeout_seconds",
        )
        self._subscription_timeout = _positive_timeout(
            subscription_timeout_seconds,
            field="subscription_timeout_seconds",
        )
        self._context: _WebSocketContext | None = None
        self._connection: _WebSocketConnection | None = None
        self._idle_deadline: float | None = None
        self._pong_deadline: float | None = None
        self._subscription_deadline: float | None = None
        self._acked: set[int] = set()
        self._server_connection_id: str | None = None
        self._terminal = False
        self._used = False

    @property
    def endpoint(self) -> str:
        return self._subscriptions[0].endpoint

    @property
    def subscribe_message(self) -> str:
        return self._subscribe_message

    @property
    def pending_subscription_count(self) -> int:
        return len(self._arguments) - len(self._acked)

    @property
    def server_connection_id(self) -> str | None:
        return self._server_connection_id

    async def __aenter__(self) -> Self:
        if self._used:
            raise RuntimeError("OKX WebSocket sessions are one-shot")
        self._used = True
        context = cast(_WebSocketContext, self._transport.connect(self.endpoint))
        connection = await context.__aenter__()
        if not callable(getattr(connection, "send", None)) or not callable(
            getattr(connection, "recv", None)
        ):
            error = TypeError("WebSocket connection must provide send() and recv()")
            try:
                await context.__aexit__(type(error), error, error.__traceback__)
            except BaseException:  # noqa: BLE001 - preserve validation cause.
                error.add_note("websocket context cleanup also failed")
            raise error
        self._context = context
        self._connection = connection
        try:
            await asyncio.wait_for(
                connection.send(self._subscribe_message),
                timeout=self._subscription_timeout,
            )
        except BaseException as error:
            self._connection = None
            self._context = None
            try:
                await context.__aexit__(type(error), error, error.__traceback__)
            except BaseException:  # noqa: BLE001 - preserve subscribe failure.
                error.add_note("websocket context cleanup also failed")
            raise
        now = asyncio.get_running_loop().time()
        self._idle_deadline = now + self._idle_timeout
        self._subscription_deadline = now + self._subscription_timeout
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        context = self._context
        self._context = None
        self._connection = None
        self._terminal = True
        if context is not None:
            try:
                await context.__aexit__(exc_type, exc, traceback)
            except BaseException:
                if exc is None:
                    raise
                exc.add_note("websocket context cleanup also failed")

    def _reconnect(
        self,
        reason: OkxWsReconnectReason,
        *,
        message: OkxWsMessage | None = None,
        raw_text: str | None = None,
        raw_binary_base64: str | None = None,
        raw_binary_length: int | None = None,
        error_type: str | None = None,
    ) -> OkxWsSessionEvent:
        self._terminal = True
        return OkxWsSessionEvent(
            action=OkxWsSessionAction.RECONNECT,
            message=message,
            reconnect_reason=reason,
            raw_text=raw_text,
            raw_binary_base64=raw_binary_base64,
            raw_binary_length=raw_binary_length,
            error_type=error_type,
        )

    def _match_argument(self, argument: Mapping[str, JsonPayload]) -> int | None:
        candidates = [
            (index, len(expected))
            for index, expected in enumerate(self._arguments)
            if _argument_matches(expected, argument)
        ]
        if not candidates:
            return None
        maximum = max(size for _, size in candidates)
        most_specific = [index for index, size in candidates if size == maximum]
        return most_specific[0] if len(most_specific) == 1 else None

    def _route_message(self, message: OkxWsMessage) -> OkxWsSessionEvent:
        if message.kind is OkxWsMessageKind.SUBSCRIBE_ACK:
            argument = message.argument
            matched = None if argument is None else self._match_argument(argument)
            if (
                message.request_id != self._request_id
                or message.connection_id is None
                or (
                    self._server_connection_id is not None
                    and message.connection_id != self._server_connection_id
                )
                or matched is None
                or matched in self._acked
            ):
                return self._reconnect(
                    OkxWsReconnectReason.SUBSCRIPTION_MISMATCH,
                    message=message,
                )
            self._server_connection_id = message.connection_id
            self._acked.add(matched)
            if len(self._acked) == len(self._arguments):
                self._subscription_deadline = None
        elif message.kind is OkxWsMessageKind.UNSUBSCRIBE_ACK:
            return self._reconnect(
                OkxWsReconnectReason.SUBSCRIPTION_MISMATCH,
                message=message,
            )
        elif message.kind is OkxWsMessageKind.DATA:
            argument = message.argument
            if argument is None or self._match_argument(argument) is None:
                return self._reconnect(
                    OkxWsReconnectReason.SUBSCRIPTION_MISMATCH,
                    message=message,
                )
        elif message.kind is OkxWsMessageKind.ERROR:
            return self._reconnect(
                OkxWsReconnectReason.SERVER_ERROR,
                message=message,
            )
        elif message.requests_service_upgrade:
            return self._reconnect(
                OkxWsReconnectReason.SERVICE_UPGRADE,
                message=message,
            )
        return OkxWsSessionEvent(
            action=OkxWsSessionAction.MESSAGE,
            message=message,
        )

    async def receive(self) -> OkxWsSessionEvent:
        connection = self._connection
        if connection is None:
            raise RuntimeError("OKX WebSocket session is not open")
        if self._terminal:
            raise RuntimeError("OKX WebSocket session already requires reconnect")
        loop = asyncio.get_running_loop()
        liveness_deadline = self._pong_deadline or self._idle_deadline
        if liveness_deadline is None:
            raise RuntimeError("OKX WebSocket session has no liveness deadline")
        deadlines = [liveness_deadline]
        if self._subscription_deadline is not None:
            deadlines.append(self._subscription_deadline)
        deadline = min(deadlines)
        timeout = max(0.0, deadline - loop.time())
        try:
            raw = await asyncio.wait_for(connection.recv(), timeout=timeout)
        except TimeoutError:
            if (
                self._subscription_deadline is not None
                and self._subscription_deadline <= liveness_deadline
            ):
                return self._reconnect(OkxWsReconnectReason.SUBSCRIPTION_TIMEOUT)
            if self._pong_deadline is not None:
                return self._reconnect(OkxWsReconnectReason.PONG_TIMEOUT)
            # Transport implementations expose different concrete I/O errors.
            try:
                await asyncio.wait_for(
                    connection.send("ping"),
                    timeout=self._pong_timeout,
                )
            except Exception as error:  # noqa: BLE001
                return self._reconnect(
                    OkxWsReconnectReason.TRANSPORT_ERROR,
                    error_type=type(error).__name__,
                )
            self._pong_deadline = loop.time() + self._pong_timeout
            return OkxWsSessionEvent(action=OkxWsSessionAction.PING_SENT)
        except Exception as error:  # noqa: BLE001
            return self._reconnect(
                OkxWsReconnectReason.TRANSPORT_ERROR,
                error_type=type(error).__name__,
            )

        self._idle_deadline = loop.time() + self._idle_timeout
        try:
            message = parse_ws_message(raw)
        except OkxWsProtocolError as error:
            return self._reconnect(
                OkxWsReconnectReason.PROTOCOL_ERROR,
                raw_text=error.raw_text,
                raw_binary_base64=error.raw_binary_base64,
                raw_binary_length=error.raw_binary_length,
                error_type=type(error).__name__,
            )
        if message.kind is OkxWsMessageKind.PONG:
            self._pong_deadline = None
        return self._route_message(message)


__all__ = [
    "OKX_WS_ARGUMENT_LIMIT_BYTES",
    "OKX_WS_OPERATION_LIMIT_PER_HOUR",
    "OKX_WS_SILENCE_LIMIT_SECONDS",
    "OkxWsMessage",
    "OkxWsMessageKind",
    "OkxWsProtocolError",
    "OkxWsReconnectPolicy",
    "OkxWsReconnectReason",
    "OkxWsSession",
    "OkxWsSessionAction",
    "OkxWsSessionEvent",
    "build_subscribe_message",
    "parse_incremental_book_frames",
    "parse_ws_message",
    "subscription_argument",
]
