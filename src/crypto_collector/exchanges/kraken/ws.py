from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import cast
from urllib.parse import urlsplit

from crypto_collector.domain import Market
from crypto_collector.domain.json_codec import JsonPayload, decode_json, encode_json
from crypto_collector.exchanges.contracts import WebSocketSubscription
from crypto_collector.exchanges.kraken.book import (
    KrakenFuturesBookFrame,
    KrakenSpotBookFrame,
    parse_futures_book_message,
    parse_spot_book_message,
)
from crypto_collector.exchanges.kraken.errors import KrakenProtocolError

SPOT_WS_SILENCE_LIMIT_SECONDS = 60
SPOT_WS_CONNECT_ATTEMPTS_PER_TEN_MINUTES = 150
FUTURES_WS_CONNECTION_LIMIT = 100
FUTURES_WS_REQUEST_BUDGET = 100
FUTURES_WS_REQUEST_REFILL_SECONDS = 1

_SPOT_SYMBOL_CHANNELS = frozenset({"book", "ticker", "trade", "ohlc"})
_SPOT_DATA_CHANNELS = frozenset({"book", "ticker", "trade", "ohlc", "instrument"})
_FUTURES_PRODUCT_FEEDS = frozenset({"book", "ticker", "trade"})
_FUTURES_DATA_FEEDS = frozenset(
    {"book_snapshot", "book", "ticker", "trade_snapshot", "trade"}
)
_SPOT_DEPTHS = frozenset({10, 25, 100, 500, 1000})
_SPOT_OHLC_INTERVALS = frozenset({1, 5, 15, 30, 60, 240, 1440, 10080, 21600})
_SPOT_WS_HOST = "ws.kraken.com"
_FUTURES_WS_HOST = "futures.kraken.com"


class KrakenWsMessageKind(StrEnum):
    ACK = "ack"
    DATA = "data"
    HEARTBEAT = "heartbeat"
    STATUS = "status"
    ERROR = "error"
    SYSTEM = "system"


@dataclass(frozen=True, slots=True)
class KrakenWsMessage:
    kind: KrakenWsMessageKind
    payload: Mapping[str, JsonPayload]
    raw_text: str
    channel: str | None
    error: str | None


def _text(raw: str | bytes) -> str:
    if type(raw) is str:
        return raw
    if type(raw) is bytes:
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise KrakenProtocolError(
                "Kraken WebSocket frame must be UTF-8",
                raw_text=None,
            ) from error
    raise TypeError("WebSocket frame must be str or bytes")


def _payload(raw: str | bytes) -> tuple[str, Mapping[str, JsonPayload]]:
    raw_text = _text(raw)
    try:
        value = decode_json(raw_text)
    except (TypeError, ValueError) as error:
        raise KrakenProtocolError(
            "Kraken WebSocket frame must be strict finite JSON",
            raw_text=raw_text,
        ) from error
    if not isinstance(value, dict) or any(type(key) is not str for key in value):
        raise KrakenProtocolError(
            "Kraken WebSocket frame must be an object",
            raw_text=raw_text,
        )
    return raw_text, cast(Mapping[str, JsonPayload], value)


def _array(value: object, *, field: str, raw_text: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise KrakenProtocolError(f"{field} must be an array", raw_text=raw_text)
    return cast(Sequence[object], value)


def _mapping(
    value: object,
    *,
    field: str,
    raw_text: str,
) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise KrakenProtocolError(f"{field} must be an object", raw_text=raw_text)
    return cast(Mapping[str, JsonPayload], value)


def _futures_ack_product_ids(
    payload: Mapping[str, JsonPayload],
    *,
    feed: str,
    raw_text: str,
) -> None:
    if feed not in _FUTURES_PRODUCT_FEEDS:
        return
    values = _array(
        payload.get("product_ids"),
        field="Kraken Futures acknowledgement product_ids",
        raw_text=raw_text,
    )
    if (
        not values
        or any(type(value) is not str or not value for value in values)
        or len(set(cast(Sequence[str], values))) != len(values)
    ):
        raise KrakenProtocolError(
            "Kraken Futures acknowledgement requires unique product_ids",
            raw_text=raw_text,
        )


def parse_spot_ws_message(raw: str | bytes) -> KrakenWsMessage:
    raw_text, payload = _payload(raw)
    method = payload.get("method")
    if method is not None:
        if method not in {"subscribe", "unsubscribe"}:
            raise KrakenProtocolError(
                "unsupported Kraken Spot WebSocket method",
                raw_text=raw_text,
            )
        success = payload.get("success")
        if type(success) is not bool:
            raise KrakenProtocolError(
                "Kraken Spot acknowledgement requires success",
                raw_text=raw_text,
            )
        error = payload.get("error")
        if not success and (type(error) is not str or not error):
            raise KrakenProtocolError(
                "failed Kraken Spot acknowledgement requires error",
                raw_text=raw_text,
            )
        acknowledgement_channel: str | None = None
        if success:
            result = payload.get("result")
            if not isinstance(result, Mapping):
                raise KrakenProtocolError(
                    "successful Kraken Spot acknowledgement requires result",
                    raw_text=raw_text,
                )
            channel = result.get("channel")
            if channel not in _SPOT_DATA_CHANNELS:
                raise KrakenProtocolError(
                    "Kraken Spot acknowledgement confirms unsupported channel",
                    raw_text=raw_text,
                )
            if channel in _SPOT_SYMBOL_CHANNELS:
                symbol = result.get("symbol")
                if type(symbol) is not str or not symbol:
                    raise KrakenProtocolError(
                        "Kraken Spot symbol acknowledgement requires symbol",
                        raw_text=raw_text,
                    )
            acknowledgement_channel = cast(str, channel)
        return KrakenWsMessage(
            kind=KrakenWsMessageKind.ACK if success else KrakenWsMessageKind.ERROR,
            payload=payload,
            raw_text=raw_text,
            channel=acknowledgement_channel,
            error=error if type(error) is str else None,
        )
    channel = payload.get("channel")
    if channel == "heartbeat":
        return KrakenWsMessage(
            KrakenWsMessageKind.HEARTBEAT,
            payload,
            raw_text,
            "heartbeat",
            None,
        )
    if channel == "status":
        _array(payload.get("data"), field="Spot status data", raw_text=raw_text)
        return KrakenWsMessage(
            KrakenWsMessageKind.STATUS,
            payload,
            raw_text,
            "status",
            None,
        )
    if channel not in _SPOT_DATA_CHANNELS:
        raise KrakenProtocolError(
            "unsupported or private Kraken Spot channel",
            raw_text=raw_text,
        )
    parsed_channel = cast(str, channel)
    message_type = payload.get("type")
    if message_type not in {"snapshot", "update"}:
        raise KrakenProtocolError(
            "Kraken Spot data requires snapshot or update type",
            raw_text=raw_text,
        )
    data = payload.get("data")
    if channel == "instrument":
        if not isinstance(data, (dict, list)):
            raise KrakenProtocolError(
                "Spot instrument data must be an object or array",
                raw_text=raw_text,
            )
    else:
        rows = _array(data, field="Spot channel data", raw_text=raw_text)
        if not rows and not (channel == "trade" and message_type == "snapshot"):
            raise KrakenProtocolError(
                "Spot channel data must not be empty",
                raw_text=raw_text,
            )
        if channel != "book":
            for index, value in enumerate(rows):
                row = _mapping(
                    value,
                    field=f"Spot {channel} data[{index}]",
                    raw_text=raw_text,
                )
                symbol = row.get("symbol")
                if type(symbol) is not str or not symbol:
                    raise KrakenProtocolError(
                        f"Spot {channel} data[{index}] requires symbol",
                        raw_text=raw_text,
                    )
    if channel == "book":
        try:
            parse_spot_book_message(payload)
        except ValueError as error:
            raise KrakenProtocolError(str(error), raw_text=raw_text) from error
    return KrakenWsMessage(
        KrakenWsMessageKind.DATA,
        payload,
        raw_text,
        parsed_channel,
        None,
    )


def parse_futures_ws_message(raw: str | bytes) -> KrakenWsMessage:
    raw_text, payload = _payload(raw)
    event = payload.get("event")
    if event is not None:
        if event in {"subscribed", "unsubscribed"}:
            feed = payload.get("feed")
            if feed not in _FUTURES_PRODUCT_FEEDS | {"heartbeat"}:
                raise KrakenProtocolError(
                    "Kraken Futures acknowledgement confirms unsupported feed",
                    raw_text=raw_text,
                )
            parsed_feed = cast(str, feed)
            _futures_ack_product_ids(
                payload,
                feed=parsed_feed,
                raw_text=raw_text,
            )
            return KrakenWsMessage(
                KrakenWsMessageKind.ACK,
                payload,
                raw_text,
                parsed_feed,
                None,
            )
        if event in {"subscribed_failed", "unsubscribed_failed"}:
            feed = payload.get("feed")
            if feed not in _FUTURES_PRODUCT_FEEDS | {"heartbeat"}:
                raise KrakenProtocolError(
                    "Kraken Futures failed acknowledgement requires public feed",
                    raw_text=raw_text,
                )
            parsed_feed = cast(str, feed)
            _futures_ack_product_ids(
                payload,
                feed=parsed_feed,
                raw_text=raw_text,
            )
            message = payload.get("message")
            if message is not None and (type(message) is not str or not message):
                raise KrakenProtocolError(
                    "Kraken Futures failed acknowledgement message must be non-empty",
                    raw_text=raw_text,
                )
            return KrakenWsMessage(
                KrakenWsMessageKind.ERROR,
                payload,
                raw_text,
                parsed_feed,
                message if type(message) is str else cast(str, event),
            )
        if event in {"error", "alert"}:
            message = payload.get("message")
            if type(message) is not str or not message:
                raise KrakenProtocolError(
                    "Kraken Futures error requires message",
                    raw_text=raw_text,
                )
            feed = payload.get("feed")
            return KrakenWsMessage(
                KrakenWsMessageKind.ERROR,
                payload,
                raw_text,
                feed if type(feed) is str else None,
                message,
            )
        if event in {"info", "pong"}:
            return KrakenWsMessage(
                KrakenWsMessageKind.SYSTEM,
                payload,
                raw_text,
                None,
                None,
            )
        raise KrakenProtocolError(
            "unsupported Kraken Futures event",
            raw_text=raw_text,
        )
    feed = payload.get("feed")
    if feed == "heartbeat":
        return KrakenWsMessage(
            KrakenWsMessageKind.HEARTBEAT,
            payload,
            raw_text,
            "heartbeat",
            None,
        )
    if feed not in _FUTURES_DATA_FEEDS:
        raise KrakenProtocolError(
            "unsupported or private Kraken Futures feed",
            raw_text=raw_text,
        )
    parsed_feed = cast(str, feed)
    if feed in {"book_snapshot", "book"}:
        try:
            parse_futures_book_message(payload)
        except ValueError as error:
            raise KrakenProtocolError(str(error), raw_text=raw_text) from error
    elif type(payload.get("product_id")) is not str or not payload.get("product_id"):
        raise KrakenProtocolError(
            "Kraken Futures data requires non-empty product_id",
            raw_text=raw_text,
        )
    return KrakenWsMessage(
        KrakenWsMessageKind.DATA,
        payload,
        raw_text,
        parsed_feed,
        None,
    )


def parse_spot_book_frames(message: KrakenWsMessage) -> tuple[KrakenSpotBookFrame, ...]:
    if type(message) is not KrakenWsMessage:
        raise TypeError("message must be KrakenWsMessage")
    if message.kind is not KrakenWsMessageKind.DATA or message.channel != "book":
        raise ValueError("message is not Kraken Spot book data")
    return parse_spot_book_message(message.payload)


def parse_futures_book_frame(message: KrakenWsMessage) -> KrakenFuturesBookFrame:
    if type(message) is not KrakenWsMessage:
        raise TypeError("message must be KrakenWsMessage")
    if message.kind is not KrakenWsMessageKind.DATA or message.channel not in {
        "book_snapshot",
        "book",
    }:
        raise ValueError("message is not Kraken Futures book data")
    return parse_futures_book_message(message.payload)


def _endpoint_value(
    endpoint: object,
    *,
    host: str,
    path: str,
) -> None:
    if type(endpoint) is not str or not endpoint:
        raise ValueError("invalid Kraken WebSocket endpoint")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid Kraken WebSocket endpoint") from error
    if (
        parsed.scheme != "wss"
        or parsed.hostname != host
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.path != path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("subscription uses the wrong Kraken WebSocket endpoint")


def _endpoint(
    subscription: WebSocketSubscription,
    *,
    host: str,
    path: str,
) -> None:
    _endpoint_value(subscription.endpoint, host=host, path=path)


def _bool_param(
    params: Mapping[str, object],
    name: str,
    *,
    default: bool,
) -> bool:
    value = params.get(name, default)
    if type(value) is not bool:
        raise TypeError(f"{name} subscription parameter must be bool")
    return value


def _require_subscription_identity(
    subscription: WebSocketSubscription,
    *,
    logical_stream: str,
) -> None:
    if subscription.logical_stream != logical_stream:
        raise ValueError("logical_stream does not match Kraken subscription channel")
    if (
        subscription.instrument_key is not None
        and subscription.instrument_key != subscription.wire_symbol
    ):
        raise ValueError(
            "Kraken subscription wire_symbol does not match instrument_key"
        )


def spot_subscription_params(
    subscription: WebSocketSubscription,
) -> dict[str, JsonPayload]:
    if type(subscription) is not WebSocketSubscription:
        raise TypeError("subscription must be WebSocketSubscription")
    if subscription.market is not Market.SPOT:
        raise ValueError("Kraken Spot subscription requires spot market")
    _endpoint(subscription, host=_SPOT_WS_HOST, path="/v2")
    channel = subscription.channel
    params = cast(Mapping[str, object], subscription.params)
    if channel == "instrument":
        if subscription.wire_symbol is not None:
            raise ValueError("instrument subscription is market-wide")
        allowed = {"snapshot", "include_tokenized_assets", "execution_venue"}
        if set(params) - allowed:
            raise ValueError("unsupported Spot instrument subscription parameter")
        include_tokenized = _bool_param(
            params,
            "include_tokenized_assets",
            default=False,
        )
        if include_tokenized:
            raise ValueError("tokenized assets are outside the anonymous crypto scope")
        _require_subscription_identity(subscription, logical_stream="instrument")
        result: dict[str, JsonPayload] = {
            "channel": "instrument",
            "snapshot": _bool_param(params, "snapshot", default=True),
            "include_tokenized_assets": False,
        }
        venue = params.get("execution_venue")
        if venue is not None:
            if venue != "international":
                raise ValueError("unsupported Spot execution venue")
            result["execution_venue"] = "international"
        return result
    if channel not in _SPOT_SYMBOL_CHANNELS:
        raise ValueError("unsupported or private Kraken Spot subscription channel")
    if type(subscription.wire_symbol) is not str or not subscription.wire_symbol:
        raise ValueError("Spot symbol channel requires wire_symbol")
    result = {"channel": channel, "symbol": [subscription.wire_symbol]}
    if channel == "book":
        if set(params) - {"depth", "snapshot"}:
            raise ValueError("unsupported Spot book subscription parameter")
        depth = params.get("depth", 10)
        if type(depth) is not int or depth not in _SPOT_DEPTHS:
            raise ValueError("Spot book depth must be 10, 25, 100, 500, or 1000")
        result["depth"] = depth
        snapshot = _bool_param(params, "snapshot", default=True)
        if not snapshot:
            raise ValueError("Spot book subscription requires snapshot=true")
        result["snapshot"] = True
        _require_subscription_identity(subscription, logical_stream="book_live")
    elif channel == "ticker":
        if set(params) - {"event_trigger", "snapshot"}:
            raise ValueError("unsupported Spot ticker subscription parameter")
        trigger = params.get("event_trigger", "trades")
        if trigger not in {"trades", "bbo"}:
            raise ValueError("Spot ticker event_trigger must be trades or bbo")
        result["event_trigger"] = trigger
        result["snapshot"] = _bool_param(params, "snapshot", default=True)
        _require_subscription_identity(
            subscription,
            logical_stream="bbo" if trigger == "bbo" else "ticker",
        )
    elif channel == "trade":
        if set(params) - {"snapshot"}:
            raise ValueError("unsupported Spot trade subscription parameter")
        snapshot = _bool_param(params, "snapshot", default=False)
        if snapshot:
            raise ValueError(
                "Spot trade snapshot=true cannot preserve empty-frame identity"
            )
        result["snapshot"] = False
        _require_subscription_identity(subscription, logical_stream="trade")
    else:
        if set(params) - {"interval", "snapshot"}:
            raise ValueError("unsupported Spot OHLC subscription parameter")
        interval = params.get("interval", 1)
        if type(interval) is not int or interval not in _SPOT_OHLC_INTERVALS:
            raise ValueError("unsupported Spot OHLC interval")
        result["interval"] = interval
        result["snapshot"] = _bool_param(params, "snapshot", default=True)
        _require_subscription_identity(
            subscription,
            logical_stream=f"candle_{interval}m",
        )
    return result


def build_spot_subscribe_message(
    subscriptions: tuple[WebSocketSubscription, ...],
    *,
    request_id: int | None = None,
) -> str:
    subscriptions = _normalized_subscriptions(subscriptions)
    arguments = [
        spot_subscription_params(subscription) for subscription in subscriptions
    ]
    first = arguments[0]
    if any(
        {key: value for key, value in argument.items() if key != "symbol"}
        != {key: value for key, value in first.items() if key != "symbol"}
        for argument in arguments[1:]
    ):
        raise ValueError(
            "one Kraken Spot request can group only identical channel parameters"
        )
    params = dict(first)
    if "symbol" in first:
        symbols = [
            cast(list[JsonPayload], argument["symbol"])[0] for argument in arguments
        ]
        if len(set(cast(list[str], symbols))) != len(symbols):
            raise ValueError("Kraken Spot subscription symbols must be unique")
        params["symbol"] = symbols
    elif len(arguments) != 1:
        raise ValueError("market-wide Spot subscription cannot be duplicated")
    payload: dict[str, JsonPayload] = {"method": "subscribe", "params": params}
    if request_id is not None:
        if type(request_id) is not int or request_id < 0:
            raise ValueError("request_id must be a non-negative integer")
        payload["req_id"] = request_id
    return encode_json(payload).decode()


def futures_subscription_request(
    subscriptions: tuple[WebSocketSubscription, ...],
) -> str:
    subscriptions = _normalized_subscriptions(subscriptions)
    first = subscriptions[0]
    if any(subscription.channel != first.channel for subscription in subscriptions):
        raise ValueError("one Futures request can subscribe to only one feed")
    for subscription in subscriptions:
        if subscription.market is not Market.PERPETUAL:
            raise ValueError("Kraken Futures subscription requires perpetual market")
        _endpoint(subscription, host=_FUTURES_WS_HOST, path="/ws/v1")
        if subscription.params:
            raise ValueError("Kraken Futures public feeds take no extra parameters")
    feed = first.channel
    if feed not in _FUTURES_PRODUCT_FEEDS:
        raise ValueError("unsupported or private Kraken Futures feed")
    product_ids: list[JsonPayload] = []
    for subscription in subscriptions:
        if type(subscription.wire_symbol) is not str or not subscription.wire_symbol:
            raise ValueError("Futures product feed requires wire_symbol")
        _require_subscription_identity(
            subscription,
            logical_stream="book_live" if feed == "book" else feed,
        )
        product_ids.append(subscription.wire_symbol)
    if len(set(cast(list[str], product_ids))) != len(product_ids):
        raise ValueError("Kraken Futures product_ids must be unique")
    payload: dict[str, JsonPayload] = {
        "event": "subscribe",
        "feed": feed,
        "product_ids": product_ids,
    }
    return encode_json(payload).decode()


def futures_heartbeat_request(*, endpoint: str) -> str:
    _endpoint_value(endpoint, host=_FUTURES_WS_HOST, path="/ws/v1")
    return encode_json({"event": "subscribe", "feed": "heartbeat"}).decode()


def _normalized_subscriptions(
    subscriptions: tuple[WebSocketSubscription, ...],
) -> tuple[WebSocketSubscription, ...]:
    if type(subscriptions) is not tuple or not subscriptions:
        raise ValueError("subscriptions must be a non-empty tuple")
    if any(type(item) is not WebSocketSubscription for item in subscriptions):
        raise TypeError("subscriptions must contain WebSocketSubscription values")
    first = subscriptions[0]
    for item in subscriptions[1:]:
        if item.endpoint != first.endpoint:
            raise ValueError("one WebSocket session cannot mix endpoints")
        if item.egress_id != first.egress_id:
            raise ValueError("one WebSocket session cannot mix egress routes")
        if item.shard_id != first.shard_id:
            raise ValueError("one WebSocket session cannot mix storage shards")
    return subscriptions


__all__ = [
    "FUTURES_WS_CONNECTION_LIMIT",
    "FUTURES_WS_REQUEST_BUDGET",
    "FUTURES_WS_REQUEST_REFILL_SECONDS",
    "SPOT_WS_CONNECT_ATTEMPTS_PER_TEN_MINUTES",
    "SPOT_WS_SILENCE_LIMIT_SECONDS",
    "KrakenWsMessage",
    "KrakenWsMessageKind",
    "build_spot_subscribe_message",
    "futures_heartbeat_request",
    "futures_subscription_request",
    "parse_futures_book_frame",
    "parse_futures_ws_message",
    "parse_spot_book_frames",
    "parse_spot_ws_message",
    "spot_subscription_params",
]
