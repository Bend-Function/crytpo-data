from __future__ import annotations

from dataclasses import replace
from datetime import date
from pathlib import Path

import pytest

from crypto_collector.capabilities import CapabilityError
from crypto_collector.domain import Market
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.exchanges.bybit.ws import (
    BYBIT_DEFAULT_BOOK_DEPTH,
    BYBIT_PERPETUAL_FULL_BOOK_AVAILABLE_FROM,
    BYBIT_STANDARD_BOOK_DEPTHS,
    BYBIT_WS_ARGS_CHARACTER_LIMIT,
    BYBIT_WS_CONNECTION_ATTEMPT_LIMIT,
    BYBIT_WS_CONNECTION_ATTEMPT_WINDOW_SECONDS,
    BYBIT_WS_HEARTBEAT_INTERVAL_SECONDS,
    BYBIT_WS_LINEAR_URL,
    BYBIT_WS_MARKET_CONNECTION_LIMIT_PER_IP,
    BYBIT_WS_SPOT_ARGS_PER_REQUEST,
    BYBIT_WS_SPOT_URL,
    BYBIT_WS_STATUS_URL,
    BybitFullBookDisabledReason,
    BybitFullBookProbeEvidence,
    BybitWsConnectionTopicBudgetTracker,
    BybitWsMessageKind,
    BybitWsProtocolError,
    BybitWsTopicKind,
    build_ping_message,
    build_subscribe_message,
    build_unsubscribe_message,
    parse_topic,
    parse_ws_message,
    resolve_full_book_capability,
    subscription_topic,
    validate_connection_topic_limit,
)
from crypto_collector.exchanges.contracts import WebSocketSubscription

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "bybit"


def _subscription(
    *,
    channel: str = "orderbook",
    market: Market = Market.SPOT,
    wire_symbol: str | None = "BTCUSDT",
    params: dict[str, object] | None = None,
    endpoint: str | None = None,
    ordinal: int = 0,
) -> WebSocketSubscription:
    selected_endpoint = endpoint
    if selected_endpoint is None:
        selected_endpoint = (
            "wss://stream.bybit.test/v5/public/spot"
            if market is Market.SPOT
            else "wss://stream.bybit.test/v5/public/linear"
        )
    return WebSocketSubscription(
        id=f"bybit:{market.value}:{channel}:{ordinal}",
        market=market,
        instrument_key=None if wire_symbol is None else wire_symbol,
        wire_symbol=wire_symbol,
        channel=channel,
        endpoint=selected_endpoint,
        egress_id="direct",
        shard_id="ws-0",
        logical_stream="book_live",
        params={} if params is None else params,
    )


def _frame(payload: object) -> str:
    return encode_json(payload).decode("utf-8")


def test_mainnet_urls_and_standard_depth_contract_are_frozen() -> None:
    assert BYBIT_WS_SPOT_URL == "wss://stream.bybit.com/v5/public/spot"
    assert BYBIT_WS_LINEAR_URL == "wss://stream.bybit.com/v5/public/linear"
    assert BYBIT_WS_STATUS_URL == "wss://stream.bybit.com/v5/public/misc/status"
    assert BYBIT_STANDARD_BOOK_DEPTHS == {1, 50, 200, 1000}
    assert BYBIT_DEFAULT_BOOK_DEPTH == 200
    assert BYBIT_WS_SPOT_ARGS_PER_REQUEST == 10
    assert BYBIT_WS_ARGS_CHARACTER_LIMIT == 21_000
    assert BYBIT_WS_HEARTBEAT_INTERVAL_SECONDS == 20
    assert BYBIT_WS_CONNECTION_ATTEMPT_LIMIT == 500
    assert BYBIT_WS_CONNECTION_ATTEMPT_WINDOW_SECONDS == 300
    assert BYBIT_WS_MARKET_CONNECTION_LIMIT_PER_IP == 1_000


@pytest.mark.parametrize(
    ("topic", "kind", "symbol", "parameter"),
    [
        ("orderbook.200.BTCUSDT", BybitWsTopicKind.ORDERBOOK, "BTCUSDT", 200),
        ("orderbook.rpi.BTCUSDT", BybitWsTopicKind.RPI_ORDERBOOK, "BTCUSDT", 50),
        ("orderbook.full.BTCUSDT", BybitWsTopicKind.FULL_ORDERBOOK, "BTCUSDT", None),
        ("publicTrade.BTCUSDT", BybitWsTopicKind.TRADE, "BTCUSDT", None),
        ("tickers.BTCUSDT", BybitWsTopicKind.TICKER, "BTCUSDT", None),
        ("kline.1.BTCUSDT", BybitWsTopicKind.KLINE, "BTCUSDT", "1"),
        ("allLiquidation.BTCUSDT", BybitWsTopicKind.ALL_LIQUIDATION, "BTCUSDT", None),
        ("insurance.USDT", BybitWsTopicKind.INSURANCE, None, "USDT"),
        ("priceLimit.BTCUSDT", BybitWsTopicKind.PRICE_LIMIT, "BTCUSDT", None),
        ("adlAlert.USDT", BybitWsTopicKind.ADL_ALERT, None, "USDT"),
        ("system.status", BybitWsTopicKind.SYSTEM_STATUS, None, None),
    ],
)
def test_exact_public_topics(
    topic: str, kind: BybitWsTopicKind, symbol: str | None, parameter: str | int | None
) -> None:
    parsed = parse_topic(topic)

    assert (parsed.raw, parsed.kind, parsed.wire_symbol, parsed.parameter) == (
        topic,
        kind,
        symbol,
        parameter,
    )


@pytest.mark.parametrize(
    "topic",
    [
        "liquidation.BTCUSDT",
        "orderbook.500.BTCUSDT",
        "orderbook.0200.BTCUSDT",
        "kline.2.BTCUSDT",
        "insurance.BTC",
        "orders.BTCUSDT",
        "publicTrade.btcusdt",
    ],
)
def test_unsupported_deprecated_or_ambiguous_topics_are_rejected(topic: str) -> None:
    with pytest.raises(ValueError):
        parse_topic(topic)


def test_subscription_messages_are_exact_and_application_ping_is_json() -> None:
    subscriptions = (
        _subscription(params={"depth": 200}),
        _subscription(channel="tickers", ordinal=1),
    )
    raw = build_subscribe_message(
        subscriptions,
        request_id="request-1",
    )

    assert decode_json(raw) == {
        "req_id": "request-1",
        "op": "subscribe",
        "args": ["orderbook.200.BTCUSDT", "tickers.BTCUSDT"],
    }
    assert decode_json(
        build_unsubscribe_message(subscriptions, request_id="request-2")
    ) == {
        "req_id": "request-2",
        "op": "unsubscribe",
        "args": ["orderbook.200.BTCUSDT", "tickers.BTCUSDT"],
    }
    assert build_ping_message() == '{"op":"ping"}'


@pytest.mark.parametrize(
    ("subscription", "expected"),
    [
        (_subscription(params={"depth": 200}), "orderbook.200.BTCUSDT"),
        (_subscription(channel="orderbook.rpi"), "orderbook.rpi.BTCUSDT"),
        (_subscription(channel="publicTrade"), "publicTrade.BTCUSDT"),
        (_subscription(channel="tickers"), "tickers.BTCUSDT"),
        (_subscription(channel="kline", params={"interval": "1"}), "kline.1.BTCUSDT"),
        (
            _subscription(channel="priceLimit", market=Market.PERPETUAL),
            "priceLimit.BTCUSDT",
        ),
        (
            _subscription(channel="allLiquidation", market=Market.PERPETUAL),
            "allLiquidation.BTCUSDT",
        ),
        (
            _subscription(
                channel="insurance",
                market=Market.PERPETUAL,
                wire_symbol=None,
                params={"coin": "USDT"},
            ),
            "insurance.USDT",
        ),
        (
            _subscription(
                channel="adlAlert",
                market=Market.PERPETUAL,
                wire_symbol=None,
                params={"coin": "USDT"},
            ),
            "adlAlert.USDT",
        ),
        (
            _subscription(
                channel="system.status",
                wire_symbol=None,
                endpoint="wss://stream.bybit.test/v5/public/misc/status",
            ),
            "system.status",
        ),
    ],
)
def test_subscription_builder_emits_every_exact_research_topic(
    subscription: WebSocketSubscription,
    expected: str,
) -> None:
    assert subscription_topic(subscription) == expected


def test_endpoint_routes_are_exact_and_private_or_cross_market_routes_fail() -> None:
    assert (
        subscription_topic(_subscription(channel="publicTrade"))
        == "publicTrade.BTCUSDT"
    )
    assert (
        subscription_topic(
            _subscription(channel="publicTrade", market=Market.PERPETUAL)
        )
        == "publicTrade.BTCUSDT"
    )
    status = _subscription(
        channel="system.status",
        wire_symbol=None,
        endpoint="wss://stream.bybit.test/v5/public/misc/status",
    )
    assert subscription_topic(status) == "system.status"

    with pytest.raises(ValueError, match="anonymous"):
        subscription_topic(
            _subscription(
                channel="publicTrade",
                endpoint="wss://stream.bybit.test/v5/private",
            )
        )
    with pytest.raises(ValueError, match="Spot endpoint"):
        subscription_topic(
            _subscription(
                channel="publicTrade",
                market=Market.PERPETUAL,
                endpoint="wss://stream.bybit.test/v5/public/spot",
            )
        )
    with pytest.raises(ValueError, match="misc/status"):
        subscription_topic(_subscription(channel="system.status", wire_symbol=None))
    with pytest.raises(ValueError, match="Linear"):
        subscription_topic(_subscription(channel="priceLimit"))
    with pytest.raises(ValueError, match="only USDT"):
        subscription_topic(
            _subscription(
                channel="insurance",
                market=Market.PERPETUAL,
                wire_symbol=None,
                params={"coin": "USDC"},
            )
        )


def test_spot_batch_limit_and_connection_character_limit_are_independent() -> None:
    ten = tuple(
        _subscription(
            channel="publicTrade",
            wire_symbol=f"TOKEN{index}USDT",
            ordinal=index,
        )
        for index in range(10)
    )
    build_subscribe_message(ten)
    with pytest.raises(ValueError, match="at most 10"):
        build_subscribe_message(
            (
                *ten,
                _subscription(
                    channel="publicTrade", wire_symbol="EXTRAUSDT", ordinal=10
                ),
            )
        )

    exact = "X" * (BYBIT_WS_ARGS_CHARACTER_LIMIT - 4)
    assert validate_connection_topic_limit((exact,)) == BYBIT_WS_ARGS_CHARACTER_LIMIT
    with pytest.raises(ValueError, match="21,000"):
        validate_connection_topic_limit((exact + "X",))

    existing = "X" * 10_500
    new_symbol = "Y" * 10_500
    new_subscription = _subscription(
        channel="publicTrade",
        market=Market.PERPETUAL,
        wire_symbol=new_symbol,
    )
    with pytest.raises(ValueError, match="21,000"):
        build_subscribe_message(
            (new_subscription,),
            connection_topics=(existing,),
        )


def test_connection_budget_tracks_21000_21001_and_unsubscribe_recovery() -> None:
    base_characters = validate_connection_topic_limit(("publicTrade.",))
    exact_symbol = "X" * (BYBIT_WS_ARGS_CHARACTER_LIMIT - base_characters)
    exact = _subscription(
        channel="publicTrade",
        market=Market.PERPETUAL,
        wire_symbol=exact_symbol,
    )
    tracker = BybitWsConnectionTopicBudgetTracker()

    tracker.prepare_subscribe((exact,), request_id="subscribe-exact")

    assert tracker.budget_characters == 21_000
    assert tracker.accepted_topics == ()
    assert tracker.confirmed_topics == ()
    subscribe_ack = parse_ws_message(
        _frame(
            {
                "success": True,
                "ret_msg": "subscribe",
                "conn_id": "connection-1",
                "req_id": "subscribe-exact",
                "op": "subscribe",
            }
        )
    )
    tracker.observe(subscribe_ack)
    assert tracker.accepted_topics == (f"publicTrade.{exact_symbol}",)
    assert tracker.confirmed_topics == ()

    small = _subscription(
        channel="tickers",
        market=Market.PERPETUAL,
        wire_symbol="BTCUSDT",
    )
    with pytest.raises(ValueError, match="21,000"):
        tracker.prepare_subscribe((small,), request_id="over-active-budget")

    tracker.prepare_unsubscribe((exact,), request_id="unsubscribe-exact")
    assert tracker.budget_characters == 21_000
    unsubscribe_ack = parse_ws_message(
        _frame(
            {
                "success": True,
                "ret_msg": "unsubscribe",
                "conn_id": "connection-1",
                "req_id": "unsubscribe-exact",
                "op": "unsubscribe",
            }
        )
    )
    tracker.observe(unsubscribe_ack)
    assert tracker.accepted_topics == ()
    assert tracker.confirmed_topics == ()
    assert tracker.budget_topics == ()
    tracker.prepare_subscribe((small,), request_id="reclaimed-budget")

    over = _subscription(
        channel="publicTrade",
        market=Market.PERPETUAL,
        wire_symbol=f"{exact_symbol}X",
    )
    with pytest.raises(ValueError, match="21,000"):
        BybitWsConnectionTopicBudgetTracker().prepare_subscribe(
            (over,),
            request_id="one-character-over",
        )


def test_connection_budget_allows_data_before_correlated_subscribe_ack() -> None:
    tracker = BybitWsConnectionTopicBudgetTracker()
    subscription = _subscription(channel="tickers", market=Market.PERPETUAL)
    tracker.prepare_subscribe((subscription,), request_id="subscribe-1")
    data = parse_ws_message(
        _frame(
            {
                "topic": "tickers.BTCUSDT",
                "type": "delta",
                "ts": 1_700_000_000_000,
                "cs": 1,
                "data": {"symbol": "BTCUSDT", "lastPrice": "100000"},
            }
        ),
        market=Market.PERPETUAL,
    )

    assert tracker.expects_data(data)
    tracker.observe(data)
    assert tracker.accepted_topics == ()
    assert tracker.confirmed_topics == ("tickers.BTCUSDT",)
    assert tracker.pending_subscribe_topics == ("tickers.BTCUSDT",)

    wrong_ack = parse_ws_message(
        _frame(
            {
                "success": True,
                "ret_msg": "subscribe",
                "conn_id": "connection-1",
                "req_id": "wrong-request",
                "op": "subscribe",
            }
        )
    )
    with pytest.raises(BybitWsProtocolError, match="pending request_id"):
        tracker.observe(wrong_ack)
    assert tracker.accepted_topics == ()
    assert tracker.confirmed_topics == ("tickers.BTCUSDT",)

    ack = parse_ws_message(
        _frame(
            {
                "success": True,
                "ret_msg": "subscribe",
                "conn_id": "connection-1",
                "req_id": "subscribe-1",
                "op": "subscribe",
            }
        )
    )
    tracker.observe(ack)
    assert tracker.accepted_topics == ("tickers.BTCUSDT",)
    assert tracker.confirmed_topics == ("tickers.BTCUSDT",)
    assert tracker.pending_operations == ()

    tracker.prepare_unsubscribe((subscription,), request_id="unsubscribe-1")
    unsubscribe_ack = parse_ws_message(
        _frame(
            {
                "success": True,
                "ret_msg": "unsubscribe",
                "conn_id": "connection-1",
                "req_id": "unsubscribe-1",
                "op": "unsubscribe",
            }
        )
    )
    tracker.observe(unsubscribe_ack)
    assert tracker.accepted_topics == ()
    assert tracker.confirmed_topics == ()


def test_connection_budget_error_releases_pending_without_false_activation() -> None:
    tracker = BybitWsConnectionTopicBudgetTracker()
    subscription = _subscription(channel="publicTrade")
    tracker.prepare_subscribe((subscription,), request_id="subscribe-error")
    error = parse_ws_message(
        _frame(
            {
                "success": False,
                "ret_msg": "invalid topic",
                "conn_id": "connection-1",
                "req_id": "subscribe-error",
                "op": "subscribe",
            }
        )
    )

    tracker.observe(error)

    assert tracker.accepted_topics == ()
    assert tracker.confirmed_topics == ()
    assert tracker.pending_operations == ()
    assert tracker.budget_topics == ()


def test_subscribe_error_after_data_is_a_fail_closed_protocol_conflict() -> None:
    tracker = BybitWsConnectionTopicBudgetTracker()
    subscription = _subscription(channel="tickers", market=Market.PERPETUAL)
    tracker.prepare_subscribe((subscription,), request_id="subscribe-conflict")
    data = parse_ws_message(
        _frame(
            {
                "topic": "tickers.BTCUSDT",
                "type": "delta",
                "ts": 1_700_000_000_000,
                "cs": 1,
                "data": {"symbol": "BTCUSDT", "lastPrice": "100000"},
            }
        ),
        market=Market.PERPETUAL,
    )
    tracker.observe(data)
    error = parse_ws_message(
        _frame(
            {
                "success": False,
                "ret_msg": "invalid topic",
                "conn_id": "connection-1",
                "req_id": "subscribe-conflict",
                "op": "subscribe",
            }
        )
    )

    with pytest.raises(BybitWsProtocolError, match="already confirmed"):
        tracker.observe(error)

    assert tracker.accepted_topics == ()
    assert tracker.confirmed_topics == ("tickers.BTCUSDT",)
    assert tracker.pending_subscribe_topics == ("tickers.BTCUSDT",)


def test_duplicate_topics_and_mixed_routes_are_rejected() -> None:
    first = _subscription(channel="tickers")
    with pytest.raises(ValueError, match="unique"):
        build_subscribe_message((first, first))
    with pytest.raises(ValueError, match="mix endpoints"):
        build_subscribe_message(
            (first, _subscription(channel="tickers", market=Market.PERPETUAL))
        )


def test_subscription_ack_pong_error_and_future_fields_are_preserved() -> None:
    ack_raw = _frame(
        {
            "success": True,
            "ret_msg": "subscribe",
            "conn_id": "conn-1",
            "req_id": "request-1",
            "op": "subscribe",
            "futureAckField": {"kept": True},
        }
    )
    pong_raw = _frame(
        {
            "success": True,
            "ret_msg": "pong",
            "conn_id": "conn-1",
            "op": "ping",
        }
    )
    error_raw = _frame(
        {
            "success": False,
            "ret_msg": "invalid topic",
            "conn_id": "conn-1",
            "op": "subscribe",
            "futureErrorCode": 999,
        }
    )

    ack = parse_ws_message(ack_raw)
    pong = parse_ws_message(pong_raw)
    error = parse_ws_message(error_raw)

    assert ack.kind is BybitWsMessageKind.SUBSCRIBE_ACK
    assert ack.request_id == "request-1"
    assert ack.acknowledges(operation="subscribe", request_id="request-1")
    assert not ack.acknowledges(operation="subscribe", request_id="wrong")
    assert ack.payload["futureAckField"] == {"kept": True}
    assert pong.kind is BybitWsMessageKind.PONG
    assert error.kind is BybitWsMessageKind.ERROR
    assert error.error_message == "invalid topic"
    assert error.payload["futureErrorCode"] == 999
    assert all(
        item.raw_text == raw
        for item, raw in ((ack, ack_raw), (pong, pong_raw), (error, error_raw))
    )

    invalid_ack = _frame(
        {
            "success": True,
            "ret_msg": "accepted-maybe",
            "conn_id": "conn-1",
            "req_id": "request-1",
            "op": "subscribe",
        }
    )
    with pytest.raises(BybitWsProtocolError, match="subscribe ACK"):
        parse_ws_message(invalid_ack)


def test_exact_ws_session_jsonl_fixture_preserves_every_wire_frame() -> None:
    frames = (_FIXTURES / "ws-session.jsonl").read_text(encoding="utf-8").splitlines()
    markets = (None, Market.SPOT, None, Market.PERPETUAL, None)
    messages = tuple(
        parse_ws_message(frame, market=market)
        for frame, market in zip(frames, markets, strict=True)
    )

    assert tuple(message.kind for message in messages) == (
        BybitWsMessageKind.SUBSCRIBE_ACK,
        BybitWsMessageKind.DATA,
        BybitWsMessageKind.SUBSCRIBE_ACK,
        BybitWsMessageKind.DATA,
        BybitWsMessageKind.PONG,
    )
    assert all(message.raw_text == frame for message, frame in zip(messages, frames))
    assert messages[0].payload["futureAck"] == {"kept": True}
    assert messages[1].data["futureBook"] == {"kept": True}
    assert messages[3].data["futureTicker"] == {"kept": True}


def test_standard_book_frame_is_strict_and_preserves_future_fields() -> None:
    raw = _frame(
        {
            "topic": "orderbook.200.BTCUSDT",
            "type": "snapshot",
            "ts": 1_700_000_000_000,
            "data": {
                "s": "BTCUSDT",
                "b": [["100", "2"]],
                "a": [["101", "3"]],
                "u": 1,
                "seq": 10,
                "futureBookField": [1, 2],
            },
            "cts": 1_699_999_999_999,
            "futureTopLevel": {"kept": "exactly"},
        }
    )

    message = parse_ws_message(raw, market=Market.SPOT)

    assert message.kind is BybitWsMessageKind.DATA
    assert message.topic is not None
    assert message.topic.kind is BybitWsTopicKind.ORDERBOOK
    assert message.wire_symbol == "BTCUSDT"
    assert message.payload["futureTopLevel"] == {"kept": "exactly"}
    assert message.data["futureBookField"] == [1, 2]


@pytest.mark.parametrize(
    ("topic", "message_type", "levels", "kind"),
    [
        (
            "orderbook.rpi.BTCUSDT",
            "delta",
            [["100", "2", "1"]],
            BybitWsTopicKind.RPI_ORDERBOOK,
        ),
        (
            "orderbook.full.BTCUSDT",
            "delta",
            [["100", "2"]],
            BybitWsTopicKind.FULL_ORDERBOOK,
        ),
    ],
)
def test_rpi_and_full_book_frames_keep_their_distinct_wire_shapes(
    topic: str,
    message_type: str,
    levels: list[list[str]],
    kind: BybitWsTopicKind,
) -> None:
    message = parse_ws_message(
        _frame(
            {
                "topic": topic,
                "type": message_type,
                "ts": 10,
                "data": {
                    "s": "BTCUSDT",
                    "b": levels,
                    "a": [],
                    "u": 2,
                    "seq": 11,
                },
                "cts": 9,
            }
        ),
        market=Market.SPOT,
    )

    assert message.topic is not None
    assert message.topic.kind is kind


def test_full_book_rejects_an_initial_snapshot_claim() -> None:
    raw = _frame(
        {
            "topic": "orderbook.full.BTCUSDT",
            "type": "snapshot",
            "ts": 10,
            "data": {"s": "BTCUSDT", "b": [], "a": [], "u": 1, "seq": 1},
            "cts": 9,
        }
    )
    with pytest.raises(BybitWsProtocolError, match="type"):
        parse_ws_message(raw, market=Market.SPOT)


def test_l1_is_snapshot_only_and_standard_or_rpi_u_one_cannot_be_delta() -> None:
    for topic in (
        "orderbook.1.BTCUSDT",
        "orderbook.200.BTCUSDT",
        "orderbook.rpi.BTCUSDT",
    ):
        width = 3 if ".rpi." in topic else 2
        raw = _frame(
            {
                "topic": topic,
                "type": "delta",
                "ts": 10,
                "data": {
                    "s": "BTCUSDT",
                    "b": [["1"] * width],
                    "a": [],
                    "u": 1,
                    "seq": 1,
                },
                "cts": 9,
            }
        )
        with pytest.raises(BybitWsProtocolError, match="type|u=1"):
            parse_ws_message(raw, market=Market.SPOT)


def test_sparse_derivatives_ticker_does_not_fill_absent_fields() -> None:
    raw = _frame(
        {
            "topic": "tickers.BTCUSDT",
            "type": "delta",
            "ts": 1_700_000_000_000,
            "cs": 10,
            "data": {
                "symbol": "BTCUSDT",
                "lastPrice": "1",
                "future": {"nested": [1, 2, 3]},
            },
        }
    )

    message = parse_ws_message(raw, market=Market.PERPETUAL)
    data = message.data

    assert isinstance(data, dict)
    assert data == {
        "symbol": "BTCUSDT",
        "lastPrice": "1",
        "future": {"nested": [1, 2, 3]},
    }
    assert "openInterest" not in data
    assert "fundingRate" not in data

    invalid_known = _frame(
        {
            "topic": "tickers.BTCUSDT",
            "type": "delta",
            "ts": 1,
            "cs": 2,
            "data": {"symbol": "BTCUSDT", "openInterest": 0},
        }
    )
    with pytest.raises(BybitWsProtocolError, match="openInterest"):
        parse_ws_message(invalid_known, market=Market.PERPETUAL)

    no_update = _frame(
        {
            "topic": "tickers.BTCUSDT",
            "type": "delta",
            "ts": 1,
            "cs": 2,
            "data": {"symbol": "BTCUSDT"},
        }
    )
    with pytest.raises(BybitWsProtocolError, match="one update"):
        parse_ws_message(no_update, market=Market.PERPETUAL)


def _ticker_snapshot(market: Market) -> dict[str, object]:
    if market is Market.SPOT:
        data = {
            "symbol": "BTCUSDT",
            "lastPrice": "1",
            "highPrice24h": "2",
            "lowPrice24h": "0.5",
            "prevPrice24h": "0.9",
            "volume24h": "10",
            "turnover24h": "11",
            "price24hPcnt": "0.1",
            "usdIndexPrice": "1",
        }
    else:
        data = {
            "symbol": "BTCUSDT",
            "tickDirection": "PlusTick",
            "price24hPcnt": "0.1",
            "lastPrice": "1",
            "prevPrice24h": "0.9",
            "highPrice24h": "2",
            "lowPrice24h": "0.5",
            "prevPrice1h": "1",
            "markPrice": "1",
            "indexPrice": "1",
            "openInterest": "10",
            "openInterestValue": "10",
            "turnover24h": "11",
            "volume24h": "10",
            "nextFundingTime": "1786248000000",
            "fundingRate": "0.001",
            "bid1Price": "0.9",
            "bid1Size": "2",
            "ask1Price": "1.1",
            "ask1Size": "3",
            "fundingIntervalHour": "8",
            "fundingCap": "0.005",
        }
    return {
        "topic": "tickers.BTCUSDT",
        "type": "snapshot",
        "ts": 1,
        "cs": 2,
        "data": data,
    }


@pytest.mark.parametrize("market", [Market.SPOT, Market.PERPETUAL])
def test_ticker_snapshot_requires_complete_stable_market_schema(market: Market) -> None:
    complete = _ticker_snapshot(market)
    assert (
        parse_ws_message(_frame(complete), market=market).kind
        is BybitWsMessageKind.DATA
    )

    data = dict(complete["data"])
    data.pop("lastPrice")
    missing = {**complete, "data": data}
    with pytest.raises(BybitWsProtocolError, match="missing required.*lastPrice"):
        parse_ws_message(_frame(missing), market=market)


def test_spot_ticker_rejects_delta_type() -> None:
    raw = _frame(
        {
            "topic": "tickers.BTCUSDT",
            "type": "delta",
            "ts": 1,
            "cs": 2,
            "data": {"symbol": "BTCUSDT"},
        }
    )
    with pytest.raises(BybitWsProtocolError, match="type"):
        parse_ws_message(raw, market=Market.SPOT)


@pytest.mark.parametrize(
    ("market", "payload"),
    [
        (
            Market.PERPETUAL,
            {
                "topic": "publicTrade.BTCUSDT",
                "type": "snapshot",
                "ts": 10,
                "data": [
                    {
                        "T": 9,
                        "s": "BTCUSDT",
                        "S": "Buy",
                        "v": "1",
                        "p": "100",
                        "L": "PlusTick",
                        "i": "trade-1",
                        "BT": False,
                        "RPI": True,
                        "seq": 7,
                    }
                ],
            },
        ),
        (
            Market.SPOT,
            {
                "topic": "kline.1.BTCUSDT",
                "type": "snapshot",
                "ts": 10,
                "data": [
                    {
                        "start": 0,
                        "end": 59_999,
                        "interval": "1",
                        "open": "1",
                        "close": "2",
                        "high": "3",
                        "low": "0.5",
                        "volume": "4",
                        "turnover": "5",
                        "confirm": False,
                        "timestamp": 9,
                    }
                ],
            },
        ),
        (
            Market.PERPETUAL,
            {
                "topic": "allLiquidation.BTCUSDT",
                "type": "snapshot",
                "ts": 10,
                "data": [{"T": 9, "s": "BTCUSDT", "S": "Sell", "v": "1", "p": "2"}],
            },
        ),
        (
            Market.PERPETUAL,
            {
                "topic": "insurance.USDT",
                "type": "delta",
                "ts": 10,
                "data": [
                    {
                        "coin": "USDT",
                        "symbols": "BTCUSDT",
                        "balance": "1",
                        "updateTime": "9",
                    }
                ],
            },
        ),
        (
            Market.PERPETUAL,
            {
                "topic": "priceLimit.BTCUSDT",
                "ts": 10,
                "data": {"symbol": "BTCUSDT", "buyLmt": "3", "sellLmt": "1"},
            },
        ),
        (
            Market.PERPETUAL,
            {
                "topic": "adlAlert.USDT",
                "type": "snapshot",
                "ts": 10,
                "data": [
                    {
                        "c": "USDT",
                        "s": "BTCUSDT",
                        "b": 1,
                        "mb": "",
                        "i_pr": "-0.3",
                        "pr": 0,
                        "adl_tt": 10000,
                        "adl_sr": "-0.25",
                    }
                ],
            },
        ),
        (
            None,
            {
                "topic": "system.status",
                "ts": 10,
                "data": [
                    {
                        "id": "id",
                        "title": "maintenance",
                        "state": "completed",
                        "begin": "1",
                        "end": "2",
                        "href": "",
                        "serviceTypes": [1, 2],
                        "product": [1],
                        "uidSuffix": [],
                        "maintainType": 1,
                        "env": 1,
                    }
                ],
            },
        ),
    ],
)
def test_every_research_topic_validates_its_known_required_schema(
    market: Market | None,
    payload: dict[str, object],
) -> None:
    message = parse_ws_message(_frame(payload), market=market)
    assert message.kind is BybitWsMessageKind.DATA


def test_status_accepts_documented_strings_and_example_integers() -> None:
    base = {
        "id": "id",
        "title": "maintenance",
        "state": "completed",
        "begin": "1",
        "end": "2",
        "href": "",
        "serviceTypes": [1],
        "product": [1],
        "uidSuffix": [],
    }
    for maintain_type, environment in ((1, 1), ("1", "1")):
        parse_ws_message(
            _frame(
                {
                    "topic": "system.status",
                    "ts": 10,
                    "data": [
                        {
                            **base,
                            "maintainType": maintain_type,
                            "env": environment,
                        }
                    ],
                }
            )
        )


def test_market_data_requires_explicit_market_but_status_and_control_do_not() -> None:
    ticker = _frame(
        {
            "topic": "tickers.BTCUSDT",
            "type": "delta",
            "ts": 1,
            "cs": 2,
            "data": {"symbol": "BTCUSDT", "lastPrice": "1"},
        }
    )
    with pytest.raises(BybitWsProtocolError, match="market is required"):
        parse_ws_message(ticker)

    assert (
        parse_ws_message(
            _frame(
                {
                    "success": True,
                    "ret_msg": "pong",
                    "conn_id": "conn",
                    "op": "ping",
                }
            )
        ).kind
        is BybitWsMessageKind.PONG
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"topic": "tickers.BTCUSDT", "type": "snapshot", "ts": 1, "cs": 2, "data": {}},
        {
            "topic": "allLiquidation.BTCUSDT",
            "type": "snapshot",
            "ts": 1,
            "data": [{"s": "BTCUSDT"}],
        },
        {
            "topic": "priceLimit.BTCUSDT",
            "ts": 1,
            "data": {"symbol": "ETHUSDT", "buyLmt": "2", "sellLmt": "1"},
        },
        {"success": True, "ret_msg": "not-pong", "conn_id": "c", "op": "ping"},
        {"success": "true", "ret_msg": "subscribe", "conn_id": "c", "op": "subscribe"},
    ],
)
def test_missing_wrong_or_cross_symbol_required_fields_are_protocol_errors(
    payload: dict[str, object],
) -> None:
    raw = _frame(payload)
    with pytest.raises(BybitWsProtocolError) as raised:
        parse_ws_message(raw, market=Market.PERPETUAL)
    assert raised.value.raw_text == raw


def test_binary_and_non_object_frames_fail_without_losing_available_raw_text() -> None:
    with pytest.raises(BybitWsProtocolError) as invalid_utf8:
        parse_ws_message(b"\xff")
    assert invalid_utf8.value.raw_text is None

    with pytest.raises(BybitWsProtocolError) as array:
        parse_ws_message("[]")
    assert array.value.raw_text == "[]"


def test_full_book_capability_is_date_then_live_probe_gated() -> None:
    before = resolve_full_book_capability(
        Market.PERPETUAL,
        as_of=date(2026, 8, 10),
        live_probe_succeeded=True,
    )
    assert not before.enabled
    assert before.disabled_reason is BybitFullBookDisabledReason.DATE_GATE_NOT_REACHED
    assert before.live_probe_succeeded is None
    assert before.control_evidence is not None
    assert before.control_evidence.code == "optional_capability_disabled"
    assert before.available_from == BYBIT_PERPETUAL_FULL_BOOK_AVAILABLE_FROM

    after_failed_probe = resolve_full_book_capability(
        Market.PERPETUAL,
        as_of=date(2026, 8, 11),
        live_probe_succeeded=False,
    )
    assert not after_failed_probe.enabled
    assert (
        after_failed_probe.disabled_reason
        is BybitFullBookDisabledReason.LIVE_PROBE_FAILED
    )

    enabled = resolve_full_book_capability(
        Market.SPOT,
        as_of=date(2026, 8, 9),
        live_probe_succeeded=True,
    )
    assert enabled.enabled
    assert enabled.requires_rest_bootstrap
    assert enabled.control_evidence is None

    with pytest.raises(ValueError, match="enabled state"):
        replace(before, enabled=True)
    with pytest.raises(ValueError, match="REST bootstrap"):
        replace(enabled, requires_rest_bootstrap=False)


@pytest.mark.parametrize(
    ("as_of", "probe", "reason"),
    [
        (date(2026, 8, 10), True, "date_gate_not_reached"),
        (date(2026, 8, 11), False, "live_probe_failed"),
    ],
)
def test_required_full_book_failure_raises_actionable_capability_error(
    as_of: date,
    probe: bool,
    reason: str,
) -> None:
    with pytest.raises(CapabilityError, match=reason):
        resolve_full_book_capability(
            Market.PERPETUAL,
            as_of=as_of,
            live_probe_succeeded=probe,
            required=True,
        )


def test_full_book_topic_requires_enabled_matching_bootstrap_capability() -> None:
    subscription = _subscription(channel="orderbook.full")
    with pytest.raises(CapabilityError):
        subscription_topic(subscription)
    with pytest.raises(CapabilityError):
        build_subscribe_message((subscription,), request_id="full-subscribe")
    with pytest.raises(CapabilityError):
        build_unsubscribe_message((subscription,), request_id="full-unsubscribe")
    with pytest.raises(CapabilityError):
        BybitWsConnectionTopicBudgetTracker().prepare_subscribe(
            (subscription,),
            request_id="full-tracked-subscribe",
        )

    enabled = resolve_full_book_capability(
        Market.SPOT,
        as_of=date(2026, 8, 9),
        live_probe_succeeded=True,
    )
    evidence = BybitFullBookProbeEvidence(
        feature_id="spot_full_order_book",
        endpoint_identity=subscription.endpoint,
        market=Market.SPOT,
        wire_symbol="BTCUSDT",
        egress_id="direct",
        succeeded=True,
        observed_at=date(2026, 8, 9),
    )
    with pytest.raises(CapabilityError):
        subscription_topic(subscription, full_book_capability=enabled)
    assert (
        subscription_topic(
            subscription,
            full_book_capability=enabled,
            full_book_probe_evidence=evidence,
        )
        == "orderbook.full.BTCUSDT"
    )

    for mismatch in (
        replace(evidence, wire_symbol="ETHUSDT"),
        replace(
            evidence,
            endpoint_identity="wss://stream-testnet.bybit.test/v5/public/spot",
        ),
        replace(evidence, egress_id="socks-a"),
        replace(evidence, succeeded=False),
        replace(evidence, observed_at=date(2026, 8, 8)),
    ):
        with pytest.raises(CapabilityError):
            subscription_topic(
                subscription,
                full_book_capability=enabled,
                full_book_probe_evidence=mismatch,
            )
