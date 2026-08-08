from __future__ import annotations

import asyncio
import math
import random
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import TracebackType
from typing import Protocol, Self, cast
from urllib.parse import urlsplit

from crypto_collector.domain import CoverageMode, Market
from crypto_collector.domain.json_codec import (
    JsonPayload,
    decode_json,
    encode_json,
    validate_json_payload,
)
from crypto_collector.exchanges.bitget.book import (
    BitgetBookFrame,
    parse_book_message,
)
from crypto_collector.exchanges.contracts import (
    PublicWebSocketTransport,
    WebSocketSubscription,
)
from crypto_collector.network import full_jitter_ns

BITGET_WS_CHANNEL_LIMIT = 1_000
BITGET_WS_RECOMMENDED_CHANNEL_LIMIT = 49
BITGET_WS_SILENCE_LIMIT_SECONDS = 30.0

_PUBLIC_PATH = "/v3/ws/public"
_SYMBOL_TOPICS = frozenset(
    {"ticker", "publicTrade", "kline", "books1", "books5", "books50", "books"}
)
_TOPICS = _SYMBOL_TOPICS | frozenset({"liquidation"})
_INTERVALS = frozenset({"1m", "3m", "5m", "15m", "30m", "1H", "4H", "6H", "12H", "1D"})
_INST_TYPE_BY_MARKET = {
    Market.SPOT: "spot",
    Market.PERPETUAL: "usdt-futures",
}
_RESERVED_ARGUMENT_FIELDS = frozenset({"topic", "symbol"})
_MAX_SIGNED_64 = 2**63 - 1


class BitgetWsProtocolError(ValueError):
    def __init__(self, message: str, *, raw_text: str | None = None) -> None:
        super().__init__(message)
        self.raw_text = raw_text


class BitgetWsMessageKind(StrEnum):
    PONG = "pong"
    SUBSCRIBE_ACK = "subscribe_ack"
    UNSUBSCRIBE_ACK = "unsubscribe_ack"
    ERROR = "error"
    DATA = "data"


@dataclass(frozen=True, slots=True)
class BitgetWsMessage:
    kind: BitgetWsMessageKind
    raw_text: str
    payload: dict[str, JsonPayload] | None
    argument: dict[str, JsonPayload] | None
    connection_id: str | None
    code: str | None

    @property
    def topic(self) -> str | None:
        if self.argument is None:
            return None
        topic = self.argument.get("topic")
        return topic if type(topic) is str else None

    @property
    def wire_symbol(self) -> str | None:
        if self.argument is None:
            return None
        symbol = self.argument.get("symbol")
        return symbol if type(symbol) is str else None

    @property
    def action(self) -> str | None:
        if self.payload is None:
            return None
        action = self.payload.get("action")
        return action if type(action) is str else None

    @property
    def coverage(self) -> CoverageMode | None:
        if self.kind is not BitgetWsMessageKind.DATA:
            return None
        return topic_coverage(self.topic)


class BitgetWsSessionAction(StrEnum):
    MESSAGE = "message"
    PING_SENT = "ping_sent"
    RECONNECT = "reconnect"


class BitgetWsReconnectReason(StrEnum):
    PONG_TIMEOUT = "pong_timeout"
    SUBSCRIPTION_TIMEOUT = "subscription_timeout"
    SERVER_ERROR = "server_error"
    SUBSCRIPTION_MISMATCH = "subscription_mismatch"
    PROTOCOL_ERROR = "protocol_error"
    TRANSPORT_ERROR = "transport_error"


@dataclass(frozen=True, slots=True)
class BitgetWsSessionEvent:
    action: BitgetWsSessionAction
    message: BitgetWsMessage | None = None
    reconnect_reason: BitgetWsReconnectReason | None = None
    raw_text: str | None = None
    error_type: str | None = None

    def __post_init__(self) -> None:
        if type(self.action) is not BitgetWsSessionAction:
            raise TypeError("action must be BitgetWsSessionAction")
        if self.action is BitgetWsSessionAction.MESSAGE:
            if self.message is None or self.reconnect_reason is not None:
                raise ValueError("message events require only a parsed message")
        elif self.action is BitgetWsSessionAction.PING_SENT:
            if any(
                value is not None
                for value in (
                    self.message,
                    self.reconnect_reason,
                    self.raw_text,
                    self.error_type,
                )
            ):
                raise ValueError("ping events must not contain message or error state")
        elif self.reconnect_reason is None:
            raise ValueError("reconnect events require a reconnect reason")


@dataclass(frozen=True, slots=True)
class BitgetWsReconnectPolicy:
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
        raise BitgetWsProtocolError(
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


def _text_frame(raw: object) -> str:
    if type(raw) is str:
        return raw
    if type(raw) is bytes:
        try:
            return raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise BitgetWsProtocolError("WebSocket bytes must be UTF-8 text") from error
    raise BitgetWsProtocolError("WebSocket frame must be text or UTF-8 bytes")


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
        raise BitgetWsProtocolError("arg must be an object", raw_text=raw_text)
    inst_type = _nonempty_text(
        value.get("instType"),
        field="arg.instType",
        raw_text=raw_text,
    )
    if inst_type not in _INST_TYPE_BY_MARKET.values():
        raise BitgetWsProtocolError(
            "arg.instType is outside the supported UTA v3 scope",
            raw_text=raw_text,
        )
    topic = _nonempty_text(
        value.get("topic"),
        field="arg.topic",
        raw_text=raw_text,
    )
    if topic not in _TOPICS:
        raise BitgetWsProtocolError(
            "arg.topic is outside the supported UTA v3 scope",
            raw_text=raw_text,
        )
    symbol = value.get("symbol")
    if topic == "liquidation":
        if inst_type != "usdt-futures" or symbol is not None:
            raise BitgetWsProtocolError(
                "liquidation arg must be market-scoped usdt-futures",
                raw_text=raw_text,
            )
    else:
        _nonempty_text(symbol, field="arg.symbol", raw_text=raw_text)
    interval = value.get("interval")
    if topic == "kline":
        if type(interval) is not str or interval not in _INTERVALS:
            raise BitgetWsProtocolError(
                "arg.interval is not a documented UTA v3 interval",
                raw_text=raw_text,
            )
    elif interval is not None:
        raise BitgetWsProtocolError(
            "arg.interval is valid only for kline",
            raw_text=raw_text,
        )
    return value


def _error_argument(
    payload: Mapping[str, JsonPayload],
    *,
    raw_text: str,
) -> dict[str, JsonPayload] | None:
    value = payload.get("arg")
    if value is None:
        return None
    if not isinstance(value, dict):
        raise BitgetWsProtocolError("arg must be an object", raw_text=raw_text)
    return value


def _timestamp(value: object, *, field: str, raw_text: str) -> int:
    if type(value) is int:
        parsed = value
    elif type(value) is str and value and value.isascii() and value.isdigit():
        normalized = value.lstrip("0") or "0"
        maximum = str(_MAX_SIGNED_64)
        if len(normalized) > len(maximum) or (
            len(normalized) == len(maximum) and normalized > maximum
        ):
            raise BitgetWsProtocolError(
                f"{field} must fit a signed 64-bit integer",
                raw_text=raw_text,
            )
        parsed = int(normalized)
    else:
        raise BitgetWsProtocolError(
            f"{field} must be a non-negative decimal integer",
            raw_text=raw_text,
        )
    if not 0 <= parsed <= _MAX_SIGNED_64:
        raise BitgetWsProtocolError(
            f"{field} must fit a signed 64-bit integer",
            raw_text=raw_text,
        )
    return parsed


def parse_ws_message(raw: object) -> BitgetWsMessage:
    raw_text = _text_frame(raw)
    if raw_text == "pong":
        return BitgetWsMessage(
            kind=BitgetWsMessageKind.PONG,
            raw_text=raw_text,
            payload=None,
            argument=None,
            connection_id=None,
            code=None,
        )
    try:
        decoded = validate_json_payload(decode_json(raw_text))
    except (TypeError, ValueError) as error:
        raise BitgetWsProtocolError(
            "WebSocket frame must contain strict JSON",
            raw_text=raw_text,
        ) from error
    if not isinstance(decoded, dict):
        raise BitgetWsProtocolError(
            "WebSocket JSON frame must be an object",
            raw_text=raw_text,
        )
    payload = cast(dict[str, JsonPayload], decoded)
    connection_id = _optional_text(payload, "connId", raw_text=raw_text)
    code = _optional_text(payload, "code", raw_text=raw_text)
    event = payload.get("event")

    if event == "subscribe":
        kind = BitgetWsMessageKind.SUBSCRIBE_ACK
        argument = _argument(payload, required=True, raw_text=raw_text)
        if connection_id is None:
            raise BitgetWsProtocolError(
                "subscribe event must contain connId",
                raw_text=raw_text,
            )
    elif event == "unsubscribe":
        kind = BitgetWsMessageKind.UNSUBSCRIBE_ACK
        argument = _argument(payload, required=True, raw_text=raw_text)
    elif event == "error":
        kind = BitgetWsMessageKind.ERROR
        # Preserve the server's rejected argument even when it is outside our scope.
        argument = _error_argument(payload, raw_text=raw_text)
        if code is None:
            raise BitgetWsProtocolError(
                "error event must contain code",
                raw_text=raw_text,
            )
    elif event is not None:
        raise BitgetWsProtocolError(
            "unsupported Bitget WebSocket event",
            raw_text=raw_text,
        )
    else:
        argument = _argument(payload, required=True, raw_text=raw_text)
        data = payload.get("data")
        if not isinstance(data, list):
            raise BitgetWsProtocolError("data must be an array", raw_text=raw_text)
        action = payload.get("action")
        if type(action) is not str or action not in {"snapshot", "update"}:
            raise BitgetWsProtocolError(
                "data action must be snapshot or update",
                raw_text=raw_text,
            )
        _timestamp(payload.get("ts"), field="data ts", raw_text=raw_text)
        kind = BitgetWsMessageKind.DATA

    return BitgetWsMessage(
        kind=kind,
        raw_text=raw_text,
        payload=payload,
        argument=argument,
        connection_id=connection_id,
        code=code,
    )


def parse_incremental_book_frames(
    message: BitgetWsMessage,
) -> tuple[BitgetBookFrame, ...]:
    if type(message) is not BitgetWsMessage:
        raise TypeError("message must be BitgetWsMessage")
    if (
        message.kind is not BitgetWsMessageKind.DATA
        or message.topic != "books"
        or message.payload is None
    ):
        raise ValueError("message is not a Bitget incremental books frame")
    return parse_book_message(message.payload)


def topic_coverage(topic: str | None) -> CoverageMode | None:
    """Return the only UTA v3 stream-level incompleteness proved by the docs."""

    if topic is None:
        return None
    if topic not in _TOPICS:
        raise ValueError("topic is outside the supported Bitget UTA v3 scope")
    return CoverageMode.LOSSY_WINDOW if topic == "liquidation" else None


def _endpoint_path(subscription: WebSocketSubscription) -> str:
    path = urlsplit(subscription.endpoint).path
    if path != _PUBLIC_PATH:
        raise ValueError("endpoint is not the Bitget UTA v3 public WebSocket path")
    return path


def subscription_argument(
    subscription: WebSocketSubscription,
) -> dict[str, JsonPayload]:
    if type(subscription) is not WebSocketSubscription:
        raise TypeError("subscription must be WebSocketSubscription")
    _endpoint_path(subscription)
    topic = subscription.channel
    if topic not in _TOPICS:
        raise ValueError("topic is outside the supported Bitget UTA v3 scope")
    if any(key in _RESERVED_ARGUMENT_FIELDS for key in subscription.params):
        raise ValueError("subscription params must not replace topic or symbol")

    expected_inst_type = _INST_TYPE_BY_MARKET[subscription.market]
    expected_params = {"instType", "interval"} if topic == "kline" else {"instType"}
    if set(subscription.params) != expected_params:
        expected = "instType and interval" if topic == "kline" else "only instType"
        raise ValueError(f"{topic} requires {expected}")
    inst_type = subscription.params["instType"]
    if type(inst_type) is not str:
        raise TypeError("instType must be a string")
    if inst_type != expected_inst_type:
        raise ValueError("instType must match the subscription market")

    argument: dict[str, JsonPayload] = {
        "instType": inst_type,
        "topic": topic,
    }
    if topic == "liquidation":
        if subscription.market is not Market.PERPETUAL:
            raise ValueError("liquidation is available only for USDT futures")
        if subscription.wire_symbol is not None:
            raise ValueError("liquidation must not contain symbol")
    else:
        if subscription.wire_symbol is None:
            raise ValueError(f"{topic} requires symbol")
        argument["symbol"] = subscription.wire_symbol
    if topic == "kline":
        interval = subscription.params["interval"]
        if type(interval) is not str:
            raise TypeError("kline interval must be a string")
        if interval not in _INTERVALS:
            raise ValueError("kline interval is not documented for UTA v3")
        argument["interval"] = interval
    return argument


def _normalized_subscriptions(
    subscriptions: Sequence[WebSocketSubscription],
) -> tuple[WebSocketSubscription, ...]:
    if isinstance(subscriptions, (str, bytes, bytearray)):
        raise TypeError("subscriptions must be a sequence of WebSocketSubscription")
    normalized = tuple(subscriptions)
    if not normalized:
        raise ValueError("at least one WebSocket subscription is required")
    if len(normalized) > BITGET_WS_CHANNEL_LIMIT:
        raise ValueError("Bitget permits at most 1000 channels per connection")
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
) -> tuple[tuple[WebSocketSubscription, ...], tuple[dict[str, JsonPayload], ...]]:
    normalized = _normalized_subscriptions(subscriptions)
    arguments = tuple(subscription_argument(item) for item in normalized)
    keys = tuple(encode_json(argument) for argument in arguments)
    if len(set(keys)) != len(keys):
        raise ValueError("WebSocket subscription arguments must be unique")
    return normalized, arguments


def build_subscribe_message(
    subscriptions: Sequence[WebSocketSubscription],
) -> str:
    _, arguments = _subscribe_parts(subscriptions)
    return encode_json({"op": "subscribe", "args": list(arguments)}).decode("utf-8")


def _argument_matches(
    expected: Mapping[str, JsonPayload],
    actual: Mapping[str, JsonPayload],
) -> bool:
    return all(actual.get(key) == value for key, value in expected.items())


def _positive_timeout(value: float, *, field: str) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{field} must be a finite positive number")
    parsed = float(value)
    if parsed >= BITGET_WS_SILENCE_LIMIT_SECONDS:
        raise ValueError(f"{field} must be less than 30 seconds")
    return parsed


class BitgetConnection:
    """Small heartbeat primitive for an already-open public connection."""

    def __init__(self, connection: _WebSocketConnection) -> None:
        if not callable(getattr(connection, "send", None)) or not callable(
            getattr(connection, "recv", None)
        ):
            raise TypeError("connection must provide send() and recv()")
        self._connection = connection

    async def send_heartbeat(self) -> None:
        await self._connection.send("ping")

    async def wait_for_pong(self, *, timeout: float) -> bool:
        deadline = _positive_timeout(timeout, field="timeout")
        try:
            raw = await asyncio.wait_for(self._connection.recv(), timeout=deadline)
        except TimeoutError:
            return False
        return parse_ws_message(raw).kind is BitgetWsMessageKind.PONG


class BitgetWsSession:
    def __init__(
        self,
        transport: PublicWebSocketTransport,
        subscriptions: Sequence[WebSocketSubscription],
        *,
        idle_timeout_seconds: float = 25.0,
        pong_timeout_seconds: float = 5.0,
        subscription_timeout_seconds: float = 10.0,
    ) -> None:
        if not callable(getattr(transport, "connect", None)):
            raise TypeError("transport must provide connect()")
        normalized, arguments = _subscribe_parts(subscriptions)
        self._transport = transport
        self._subscriptions = normalized
        self._arguments = arguments
        self._subscribe_message = build_subscribe_message(normalized)
        self._ping_interval = _positive_timeout(
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
        self._next_ping_deadline: float | None = None
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
            raise RuntimeError("Bitget WebSocket sessions are one-shot")
        self._used = True
        context = cast(_WebSocketContext, self._transport.connect(self.endpoint))
        connection = await context.__aenter__()
        if not callable(getattr(connection, "send", None)) or not callable(
            getattr(connection, "recv", None)
        ):
            await context.__aexit__(None, None, None)
            raise TypeError("WebSocket connection must provide send() and recv()")
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
            await context.__aexit__(type(error), error, error.__traceback__)
            raise
        now = asyncio.get_running_loop().time()
        self._next_ping_deadline = now + self._ping_interval
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
            await context.__aexit__(exc_type, exc, traceback)

    def _reconnect(
        self,
        reason: BitgetWsReconnectReason,
        *,
        message: BitgetWsMessage | None = None,
        raw_text: str | None = None,
        error_type: str | None = None,
    ) -> BitgetWsSessionEvent:
        self._terminal = True
        return BitgetWsSessionEvent(
            action=BitgetWsSessionAction.RECONNECT,
            message=message,
            reconnect_reason=reason,
            raw_text=raw_text,
            error_type=error_type,
        )

    def _match_argument(self, argument: Mapping[str, JsonPayload]) -> int | None:
        matches = [
            index
            for index, expected in enumerate(self._arguments)
            if _argument_matches(expected, argument)
        ]
        return matches[0] if len(matches) == 1 else None

    def _route_message(self, message: BitgetWsMessage) -> BitgetWsSessionEvent:
        if message.kind is BitgetWsMessageKind.SUBSCRIBE_ACK:
            argument = message.argument
            matched = None if argument is None else self._match_argument(argument)
            if (
                message.connection_id is None
                or (
                    self._server_connection_id is not None
                    and message.connection_id != self._server_connection_id
                )
                or matched is None
                or matched in self._acked
            ):
                return self._reconnect(
                    BitgetWsReconnectReason.SUBSCRIPTION_MISMATCH,
                    message=message,
                )
            self._server_connection_id = message.connection_id
            self._acked.add(matched)
            if len(self._acked) == len(self._arguments):
                self._subscription_deadline = None
        elif message.kind is BitgetWsMessageKind.UNSUBSCRIBE_ACK:
            return self._reconnect(
                BitgetWsReconnectReason.SUBSCRIPTION_MISMATCH,
                message=message,
            )
        elif message.kind is BitgetWsMessageKind.DATA:
            argument = message.argument
            if argument is None or self._match_argument(argument) is None:
                return self._reconnect(
                    BitgetWsReconnectReason.SUBSCRIPTION_MISMATCH,
                    message=message,
                )
        elif message.kind is BitgetWsMessageKind.ERROR:
            return self._reconnect(
                BitgetWsReconnectReason.SERVER_ERROR,
                message=message,
            )
        return BitgetWsSessionEvent(
            action=BitgetWsSessionAction.MESSAGE,
            message=message,
        )

    async def receive(self) -> BitgetWsSessionEvent:
        connection = self._connection
        if connection is None:
            raise RuntimeError("Bitget WebSocket session is not open")
        if self._terminal:
            raise RuntimeError("Bitget WebSocket session already requires reconnect")
        loop = asyncio.get_running_loop()
        heartbeat_deadline = self._pong_deadline or self._next_ping_deadline
        if heartbeat_deadline is None:
            raise RuntimeError("Bitget WebSocket session has no heartbeat deadline")
        deadlines = [heartbeat_deadline]
        if self._subscription_deadline is not None:
            deadlines.append(self._subscription_deadline)
        timeout = max(0.0, min(deadlines) - loop.time())
        try:
            raw = await asyncio.wait_for(connection.recv(), timeout=timeout)
        except TimeoutError:
            if (
                self._subscription_deadline is not None
                and self._subscription_deadline <= heartbeat_deadline
            ):
                return self._reconnect(BitgetWsReconnectReason.SUBSCRIPTION_TIMEOUT)
            if self._pong_deadline is not None:
                return self._reconnect(BitgetWsReconnectReason.PONG_TIMEOUT)
            try:
                await asyncio.wait_for(
                    connection.send("ping"),
                    timeout=self._pong_timeout,
                )
            except Exception as error:  # noqa: BLE001
                return self._reconnect(
                    BitgetWsReconnectReason.TRANSPORT_ERROR,
                    error_type=type(error).__name__,
                )
            now = loop.time()
            self._pong_deadline = now + self._pong_timeout
            self._next_ping_deadline = now + self._ping_interval
            return BitgetWsSessionEvent(action=BitgetWsSessionAction.PING_SENT)
        except Exception as error:  # noqa: BLE001
            return self._reconnect(
                BitgetWsReconnectReason.TRANSPORT_ERROR,
                error_type=type(error).__name__,
            )

        try:
            message = parse_ws_message(raw)
        except BitgetWsProtocolError as error:
            return self._reconnect(
                BitgetWsReconnectReason.PROTOCOL_ERROR,
                raw_text=error.raw_text,
                error_type=type(error).__name__,
            )
        if message.kind is BitgetWsMessageKind.PONG:
            self._pong_deadline = None
        return self._route_message(message)


__all__ = [
    "BITGET_WS_CHANNEL_LIMIT",
    "BITGET_WS_RECOMMENDED_CHANNEL_LIMIT",
    "BITGET_WS_SILENCE_LIMIT_SECONDS",
    "BitgetConnection",
    "BitgetWsMessage",
    "BitgetWsMessageKind",
    "BitgetWsProtocolError",
    "BitgetWsReconnectPolicy",
    "BitgetWsReconnectReason",
    "BitgetWsSession",
    "BitgetWsSessionAction",
    "BitgetWsSessionEvent",
    "build_subscribe_message",
    "parse_incremental_book_frames",
    "parse_ws_message",
    "subscription_argument",
    "topic_coverage",
]
