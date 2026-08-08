from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from crypto_collector.domain import Market
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.exchanges.contracts import WebSocketSubscription
from crypto_collector.exchanges.kraken import (
    KrakenProtocolError,
    KrakenWsMessageKind,
    build_spot_subscribe_message,
    futures_heartbeat_request,
    futures_subscription_request,
    parse_futures_book_frame,
    parse_futures_ws_message,
    parse_spot_book_frames,
    parse_spot_ws_message,
    spot_subscription_params,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "kraken"


def _spot_subscription(
    *,
    channel: str = "book",
    wire_symbol: str | None = "BTC/USDT",
    params: dict[str, object] | None = None,
    egress_id: str = "direct",
    shard_id: str = "spot-0",
) -> WebSocketSubscription:
    resolved_params = {} if params is None else params
    interval = resolved_params.get("interval", 1)
    trigger = resolved_params.get("event_trigger", "trades")
    logical_stream = (
        "instrument"
        if channel == "instrument"
        else "book_live"
        if channel == "book"
        else "bbo"
        if channel == "ticker" and trigger == "bbo"
        else "ticker"
        if channel == "ticker"
        else f"candle_{interval}m"
        if channel == "ohlc"
        else channel
    )
    return WebSocketSubscription(
        id=f"kraken:spot:{channel}",
        market=Market.SPOT,
        instrument_key=None if wire_symbol is None else "BTC/USDT",
        wire_symbol=wire_symbol,
        channel=channel,
        endpoint="wss://ws.kraken.com/v2",
        egress_id=egress_id,
        shard_id=shard_id,
        logical_stream=logical_stream,
        params=resolved_params,  # type: ignore[arg-type]
    )


def _futures_subscription(
    *,
    channel: str = "book",
    wire_symbol: str | None = "PF_XBTUSD",
    egress_id: str = "direct",
    shard_id: str = "futures-0",
) -> WebSocketSubscription:
    return WebSocketSubscription(
        id=f"kraken:futures:{channel}",
        market=Market.PERPETUAL,
        instrument_key=None if wire_symbol is None else "PF_XBTUSD",
        wire_symbol=wire_symbol,
        channel=channel,
        endpoint="wss://futures.kraken.com/ws/v1",
        egress_id=egress_id,
        shard_id=shard_id,
        logical_stream=(
            "_control"
            if channel == "heartbeat"
            else "book_live"
            if channel == "book"
            else channel
        ),
    )


def test_spot_subscription_is_exact_v2_anonymous_json() -> None:
    raw = build_spot_subscribe_message(
        (
            _spot_subscription(params={"depth": 100}),
            WebSocketSubscription(
                id="kraken:spot:book:eth",
                market=Market.SPOT,
                instrument_key="ETH/USDT",
                wire_symbol="ETH/USDT",
                channel="book",
                endpoint="wss://ws.kraken.com/v2",
                egress_id="direct",
                shard_id="spot-0",
                logical_stream="book_live",
                params={"depth": 100},
            ),
        ),
        request_id=7,
    )

    assert decode_json(raw) == {
        "method": "subscribe",
        "params": {
            "channel": "book",
            "symbol": ["BTC/USDT", "ETH/USDT"],
            "depth": 100,
            "snapshot": True,
        },
        "req_id": 7,
    }
    assert "token" not in raw.casefold()


def test_spot_instrument_subscription_forces_tokenized_assets_off() -> None:
    subscription = _spot_subscription(
        channel="instrument",
        wire_symbol=None,
        params={"snapshot": True, "include_tokenized_assets": False},
    )

    assert spot_subscription_params(subscription) == {
        "channel": "instrument",
        "snapshot": True,
        "include_tokenized_assets": False,
    }

    enabled = _spot_subscription(
        channel="instrument",
        wire_symbol=None,
        params={"include_tokenized_assets": True},
    )
    with pytest.raises(ValueError, match="tokenized"):
        spot_subscription_params(enabled)


def test_spot_trade_subscription_defaults_snapshot_off() -> None:
    params = spot_subscription_params(_spot_subscription(channel="trade"))

    assert params == {
        "channel": "trade",
        "symbol": ["BTC/USDT"],
        "snapshot": False,
    }

    with pytest.raises(ValueError, match="empty-frame identity"):
        spot_subscription_params(
            _spot_subscription(channel="trade", params={"snapshot": True})
        )


def test_spot_book_subscription_cannot_disable_required_snapshot() -> None:
    with pytest.raises(ValueError, match="snapshot=true"):
        spot_subscription_params(
            _spot_subscription(channel="book", params={"snapshot": False})
        )


def test_spot_level3_and_wrong_endpoint_are_rejected() -> None:
    with pytest.raises(ValueError, match="private"):
        spot_subscription_params(_spot_subscription(channel="level3"))

    wrong = WebSocketSubscription(
        id="kraken:spot:book",
        market=Market.SPOT,
        instrument_key="BTC/USDT",
        wire_symbol="BTC/USDT",
        channel="book",
        endpoint="wss://ws.kraken.com/v1",
        egress_id="direct",
        shard_id="spot-0",
        logical_stream="book_live",
    )
    with pytest.raises(ValueError, match="endpoint"):
        spot_subscription_params(wrong)

    authenticated = WebSocketSubscription(
        id="kraken:spot:book:auth",
        market=Market.SPOT,
        instrument_key="BTC/USDT",
        wire_symbol="BTC/USDT",
        channel="book",
        endpoint="wss://ws-auth.kraken.com/v2",
        egress_id="direct",
        shard_id="spot-0",
        logical_stream="book_live",
    )
    with pytest.raises(ValueError, match="endpoint"):
        spot_subscription_params(authenticated)

    wrong_port = WebSocketSubscription(
        id="kraken:spot:book:port",
        market=Market.SPOT,
        instrument_key="BTC/USDT",
        wire_symbol="BTC/USDT",
        channel="book",
        endpoint="wss://ws.kraken.com:444/v2",
        egress_id="direct",
        shard_id="spot-0",
        logical_stream="book_live",
    )
    with pytest.raises(ValueError, match="endpoint"):
        spot_subscription_params(wrong_port)


def test_futures_subscription_uses_native_v1_feed_shape_without_auth() -> None:
    raw = futures_subscription_request(
        (
            _futures_subscription(),
            WebSocketSubscription(
                id="kraken:futures:book:eth",
                market=Market.PERPETUAL,
                instrument_key="PF_ETHUSD",
                wire_symbol="PF_ETHUSD",
                channel="book",
                endpoint="wss://futures.kraken.com/ws/v1",
                egress_id="direct",
                shard_id="futures-0",
                logical_stream="book_live",
            ),
        )
    )

    assert decode_json(raw) == {
        "event": "subscribe",
        "feed": "book",
        "product_ids": ["PF_XBTUSD", "PF_ETHUSD"],
    }
    assert "challenge" not in raw
    assert "api_key" not in raw


def test_market_wide_futures_heartbeat_is_a_distinct_public_feed() -> None:
    raw = futures_heartbeat_request(
        endpoint="wss://futures.kraken.com/ws/v1",
    )

    assert decode_json(raw) == {"event": "subscribe", "feed": "heartbeat"}
    with pytest.raises(ValueError, match="unsupported"):
        futures_subscription_request(
            (_futures_subscription(channel="heartbeat", wire_symbol=None),)
        )


@pytest.mark.parametrize(
    "builder", [build_spot_subscribe_message, futures_subscription_request]
)
@pytest.mark.parametrize(
    "field",
    ["egress", "shard"],
)
def test_grouped_subscriptions_cannot_mix_connection_ownership(
    builder, field: str
) -> None:
    factory = (
        _spot_subscription
        if builder is build_spot_subscribe_message
        else _futures_subscription
    )
    second = (
        factory(egress_id="proxy") if field == "egress" else factory(shard_id="other")
    )

    expected = "mix egress" if field == "egress" else "mix storage shards"
    with pytest.raises(ValueError, match=expected):
        builder((factory(), second))


def test_spot_parser_preserves_batched_trades_and_native_raw_text() -> None:
    raw = (
        '{"channel":"trade","type":"update","data":['
        '{"symbol":"BTC/USDT","price":100.1,"qty":0.1,"side":"buy"},'
        '{"symbol":"BTC/USDT","price":100.2,"qty":0.2,"side":"sell"}'
        '],"futureField":{"kept":true}}'
    )

    message = parse_spot_ws_message(raw)

    assert message.kind is KrakenWsMessageKind.DATA
    assert message.raw_text == raw
    assert message.payload["futureField"] == {"kept": True}
    data = message.payload["data"]
    assert isinstance(data, list)
    assert len(data) == 2
    first = data[0]
    assert isinstance(first, dict)
    assert first["price"] == Decimal("100.1")


def test_spot_trade_snapshot_may_be_empty_for_new_instrument() -> None:
    raw = '{"channel":"trade","type":"snapshot","data":[]}'

    message = parse_spot_ws_message(raw)

    assert message.kind is KrakenWsMessageKind.DATA
    assert message.channel == "trade"
    assert message.payload["data"] == []


def test_spot_status_heartbeat_and_official_book_are_distinct() -> None:
    status = parse_spot_ws_message(
        '{"channel":"status","type":"update","data":[{"system":"online"}]}'
    )
    heartbeat = parse_spot_ws_message('{"channel":"heartbeat"}')
    raw_book = (_FIXTURES / "spot-book.json").read_text()
    book = parse_spot_ws_message(raw_book)

    assert status.kind is KrakenWsMessageKind.STATUS
    assert heartbeat.kind is KrakenWsMessageKind.HEARTBEAT
    assert parse_spot_book_frames(book)[0].checksum == 3310070434


def test_futures_parser_preserves_mixed_casing_and_trade_type() -> None:
    ticker = parse_futures_ws_message(
        '{"feed":"ticker","product_id":"PF_XBTUSD",'
        '"funding_rate":0.0001,"markPrice":100.1,"openInterest":42}'
    )
    liquidation = parse_futures_ws_message(
        '{"feed":"trade","product_id":"PF_XBTUSD","uid":"x",'
        '"side":"sell","type":"liquidation","seq":2,"time":3,'
        '"qty":4,"price":5}'
    )

    assert ticker.kind is KrakenWsMessageKind.DATA
    assert set(ticker.payload) >= {"funding_rate", "markPrice", "openInterest"}
    assert liquidation.payload["type"] == "liquidation"


def test_futures_live_alert_is_preserved_as_subscription_error() -> None:
    raw = (
        '{"event":"alert","message":'
        '"Couldn\'t subscribe to invalid product `NOT_REAL`"}'
    )

    message = parse_futures_ws_message(raw)

    assert message.kind is KrakenWsMessageKind.ERROR
    assert message.error == "Couldn't subscribe to invalid product `NOT_REAL`"
    assert message.raw_text == raw


@pytest.mark.parametrize(
    "raw",
    [
        ('{"event":"subscribed_failed","feed":"book","product_ids":["PF_XBTUSD"]}'),
        '{"event":"unsubscribed_failed","feed":"heartbeat"}',
    ],
)
def test_futures_official_failed_ack_does_not_require_message(raw: str) -> None:
    message = parse_futures_ws_message(raw)

    assert message.kind is KrakenWsMessageKind.ERROR
    assert message.error in {"subscribed_failed", "unsubscribed_failed"}


@pytest.mark.parametrize(
    "raw",
    [
        '{"event":"subscribed_failed","feed":"book"}',
        '{"event":"subscribed_failed","feed":"open_orders"}',
    ],
)
def test_futures_failed_ack_still_requires_public_native_identity(raw: str) -> None:
    with pytest.raises(KrakenProtocolError):
        parse_futures_ws_message(raw)


def test_futures_official_book_fixture_decodes_numbers_as_decimal_not_float() -> None:
    message = parse_futures_ws_message((_FIXTURES / "futures-book.json").read_text())
    frame = parse_futures_book_frame(message)

    assert frame.bids[0].price == Decimal("34892.5")
    assert type(frame.bids[0].price) is Decimal
    assert frame.sequence_id == 326072249


@pytest.mark.parametrize(
    ("parser", "raw"),
    [
        (parse_spot_ws_message, '{"channel":"level3","type":"update","data":[]}'),
        (parse_spot_ws_message, "[]"),
        (parse_spot_ws_message, '{"channel":"ticker","type":"update","data":[{}]}'),
        (
            parse_spot_ws_message,
            '{"channel":"trade","type":"update","data":[{"symbol":""}]}',
        ),
        (
            parse_spot_ws_message,
            '{"channel":"ohlc","type":"update","data":[{"symbol":7}]}',
        ),
        (parse_futures_ws_message, '{"feed":"open_orders","product_id":"x"}'),
        (parse_futures_ws_message, '{"feed":"ticker","product_id":""}'),
        (parse_futures_ws_message, '{"feed":"trade","product_id":""}'),
        (parse_futures_ws_message, '{"feed":"trade_snapshot","product_id":""}'),
        (parse_futures_ws_message, '{"event":"error"}'),
    ],
)
def test_private_or_malformed_frames_are_protocol_errors(parser, raw: str) -> None:
    with pytest.raises(KrakenProtocolError) as captured:
        parser(raw)
    assert captured.value.raw_text == raw


@pytest.mark.parametrize(
    ("parser", "raw"),
    [
        (
            parse_spot_ws_message,
            ('{"method":"subscribe","success":true,"result":{"channel":"level3"}}'),
        ),
        (
            parse_futures_ws_message,
            '{"event":"subscribed","feed":"open_orders"}',
        ),
    ],
)
def test_private_acknowledgements_are_rejected(parser, raw: str) -> None:
    with pytest.raises(KrakenProtocolError, match="unsupported"):
        parser(raw)


def test_spot_symbol_acknowledgement_requires_native_symbol_identity() -> None:
    raw = '{"method":"subscribe","success":true,"result":{"channel":"book"}}'

    with pytest.raises(KrakenProtocolError, match="requires symbol"):
        parse_spot_ws_message(raw)

    message = parse_spot_ws_message(
        '{"method":"subscribe","success":true,'
        '"result":{"channel":"book","symbol":"BTC/USDT"}}'
    )
    assert message.kind is KrakenWsMessageKind.ACK
    assert message.channel == "book"


def test_futures_product_acknowledgement_requires_native_product_identity() -> None:
    for raw in (
        '{"event":"subscribed","feed":"book"}',
        '{"event":"subscribed","feed":"book","product_ids":[]}',
        (
            '{"event":"subscribed","feed":"book",'
            '"product_ids":["PF_XBTUSD","PF_XBTUSD"]}'
        ),
    ):
        with pytest.raises(KrakenProtocolError, match="product_ids"):
            parse_futures_ws_message(raw)

    message = parse_futures_ws_message(
        '{"event":"subscribed","feed":"book","product_ids":["PF_XBTUSD"]}'
    )
    assert message.kind is KrakenWsMessageKind.ACK


@pytest.mark.parametrize("market", [Market.SPOT, Market.PERPETUAL])
def test_subscription_metadata_must_match_native_routing_identity(
    market: Market,
) -> None:
    valid = _spot_subscription() if market is Market.SPOT else _futures_subscription()
    mismatched_symbol = WebSocketSubscription(
        id=valid.id,
        market=valid.market,
        instrument_key="ETH/USDT" if market is Market.SPOT else "PF_ETHUSD",
        wire_symbol=valid.wire_symbol,
        channel=valid.channel,
        endpoint=valid.endpoint,
        egress_id=valid.egress_id,
        shard_id=valid.shard_id,
        logical_stream=valid.logical_stream,
        params=valid.params,
    )
    mismatched_stream = WebSocketSubscription(
        id=valid.id,
        market=valid.market,
        instrument_key=valid.instrument_key,
        wire_symbol=valid.wire_symbol,
        channel=valid.channel,
        endpoint=valid.endpoint,
        egress_id=valid.egress_id,
        shard_id=valid.shard_id,
        logical_stream="trade",
        params=valid.params,
    )
    builder = (
        build_spot_subscribe_message
        if market is Market.SPOT
        else futures_subscription_request
    )

    with pytest.raises(ValueError, match="wire_symbol"):
        builder((mismatched_symbol,))
    with pytest.raises(ValueError, match="logical_stream"):
        builder((mismatched_stream,))
