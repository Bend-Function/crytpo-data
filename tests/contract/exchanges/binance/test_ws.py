from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast
from urllib.parse import quote

import pytest

from crypto_collector.domain import CoverageMode, Market
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.exchanges.binance.catalog import (
    instrument_by_key,
    parse_exchange_info,
)
from crypto_collector.exchanges.binance.ws import (
    DEFAULT_ROTATION_LEAD_NS,
    MAX_CONNECTION_LIFETIME_NS,
    BinanceWsMessageKind,
    BinanceWsProtocolError,
    BinanceWsRoute,
    BinanceWsScopeError,
    build_subscribe_message,
    combined_stream_url,
    event_time_ns,
    parse_ws_message,
    planned_rotation_at_ns,
    pong_payload,
    rotation_due,
    stream_spec,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "binance"


def _frames() -> Mapping[str, str]:
    value = decode_json((_FIXTURES / "ws-session.json").read_bytes())
    assert isinstance(value, Mapping)
    assert all(type(key) is str and type(item) is str for key, item in value.items())
    return cast(Mapping[str, str], value)


def _book(market: Market, *, symbol: str = "BTCUSDT"):
    return stream_spec(
        market,
        "book_live",
        instrument_key=symbol,
        wire_symbol=symbol,
        update_speed_ms=100,
    )


def test_futures_stream_routes_are_explicit_and_never_inferred_from_host() -> None:
    book = _book(Market.PERPETUAL)
    trade = stream_spec(
        Market.PERPETUAL,
        "trade",
        instrument_key="BTCUSDT",
        wire_symbol="BTCUSDT",
    )

    assert book.route is BinanceWsRoute.PUBLIC
    assert trade.route is BinanceWsRoute.MARKET
    assert combined_stream_url("wss://fstream.binance.com", [book]).startswith(
        "wss://fstream.binance.com/public/stream?"
    )
    assert combined_stream_url("wss://fstream.binance.com/market", [trade]).startswith(
        "wss://fstream.binance.com/market/stream?"
    )
    with pytest.raises(ValueError, match="mix"):
        combined_stream_url("wss://fstream.binance.com", [book, trade])
    with pytest.raises(ValueError, match="does not match"):
        combined_stream_url("wss://fstream.binance.com/market", [book])


def test_spot_stream_url_and_subscription_message_are_exact() -> None:
    book = _book(Market.SPOT)
    trade = stream_spec(
        Market.SPOT,
        "trade",
        instrument_key="BTCUSDT",
        wire_symbol="BTCUSDT",
    )

    url = combined_stream_url("wss://stream.binance.com:9443", [book, trade])
    raw = build_subscribe_message([book, trade], request_id="req1")

    assert url == (
        "wss://stream.binance.com:9443/stream?streams=btcusdt@depth@100ms/btcusdt@trade"
    )
    assert decode_json(raw) == {
        "method": "SUBSCRIBE",
        "params": ["btcusdt@depth@100ms", "btcusdt@trade"],
        "id": "req1",
    }
    assert decode_json(build_subscribe_message([book], request_id=None))["id"] is None


def test_unicode_new_coin_flows_from_catalog_to_encoded_stream_and_binding() -> None:
    payload = decode_json((_FIXTURES / "futures-exchange-info.json").read_bytes())
    catalog = parse_exchange_info(
        payload,
        Market.PERPETUAL,
        observed_at_ns=1_770_000_000_000_000_000,
    )
    instrument = instrument_by_key(catalog, "币安人生USDT")
    spec = stream_spec(
        Market.PERPETUAL,
        "book_live",
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        update_speed_ms=100,
    )

    url = combined_stream_url("wss://fstream.binance.com", [spec])
    subscription = decode_json(build_subscribe_message([spec], request_id=1))
    frame = encode_json(
        {
            "stream": spec.stream_name,
            "data": {
                "e": "depthUpdate",
                "E": 1,
                "s": "币安人生USDT",
                "U": 1,
                "u": 2,
                "pu": 0,
                "b": [],
                "a": [],
                "st": 1,
            },
        }
    )

    assert url.endswith(
        "/public/stream?streams=" + quote(spec.stream_name, safe="!@_-")
    )
    assert "币安人生" not in url
    assert cast(Mapping[str, object], subscription)["params"] == [spec.stream_name]
    assert parse_ws_message(frame, expected=spec).kind is BinanceWsMessageKind.DATA


def test_fixture_frames_preserve_raw_payloads_and_unknown_fields() -> None:
    frames = _frames()
    spot = parse_ws_message(frames["spot_depth"], expected=_book(Market.SPOT))
    futures = parse_ws_message(
        frames["futures_depth"], expected=_book(Market.PERPETUAL)
    )
    ack = parse_ws_message(frames["spot_ack"], market=Market.SPOT)

    assert spot.kind is BinanceWsMessageKind.DATA
    assert spot.raw_text == frames["spot_depth"]
    assert spot.data is not None
    assert cast(Mapping[str, object], spot.data)["futureDepthField"] == {"kept": True}
    assert futures.kind is BinanceWsMessageKind.DATA
    assert event_time_ns(futures) == 1_672_515_782_136_000_000
    assert ack.kind is BinanceWsMessageKind.SUBSCRIBE_ACK
    assert ack.request_id == "spot1"
    assert ack.payload["futureAckField"] == {"kept": True}


def test_coin_m_payload_is_rejected_from_usd_m_generation() -> None:
    frames = _frames()
    spec = _book(Market.PERPETUAL, symbol="BTCUSD_PERP")

    with pytest.raises(BinanceWsScopeError, match="COIN-M"):
        parse_ws_message(frames["coin_m_depth"], expected=spec)


def test_liquidation_declares_lossy_window_and_contract_info_is_market_scoped() -> None:
    frames = _frames()
    liquidation = stream_spec(
        Market.PERPETUAL,
        "liquidation",
        instrument_key="BTCUSDT",
        wire_symbol="BTCUSDT",
    )
    contract_info = stream_spec(
        Market.PERPETUAL,
        "instrument",
        all_market=True,
    )

    liquidation_message = parse_ws_message(frames["liquidation"], expected=liquidation)
    contract_message = parse_ws_message(frames["contract_info"], expected=contract_info)

    assert liquidation.coverage is CoverageMode.LOSSY_WINDOW
    assert liquidation.route is BinanceWsRoute.MARKET
    assert liquidation_message.kind is BinanceWsMessageKind.DATA
    assert contract_info.instrument_key is None
    assert contract_info.stream_name == "!contractInfo"
    assert contract_message.kind is BinanceWsMessageKind.DATA


def test_server_shutdown_and_subscription_error_are_not_data() -> None:
    frames = _frames()

    shutdown = parse_ws_message(frames["server_shutdown"])
    error = parse_ws_message(frames["subscription_error"], market=Market.SPOT)

    assert shutdown.kind is BinanceWsMessageKind.SERVER_SHUTDOWN
    assert shutdown.requests_reconnect
    assert event_time_ns(shutdown) == 1_770_123_456_789_000_000
    assert error.kind is BinanceWsMessageKind.ERROR
    assert error.code == 2
    assert error.message == "Invalid request"
    assert error.payload["futureErrorField"] is True

    with pytest.raises(BinanceWsProtocolError, match="Spot event"):
        parse_ws_message(frames["server_shutdown"], market=Market.PERPETUAL)


@pytest.mark.parametrize(
    "raw",
    [
        '{"e":"serverShutdown"}',
        '{"stream":"wrong","data":{"e":"serverShutdown","E":1}}',
        (
            '{"stream":"!serverShutdown","data":['
            '{"e":"serverShutdown","E":1},{"e":"other","E":1}]}'
        ),
    ],
)
def test_server_shutdown_shape_and_combined_identity_fail_closed(raw: str) -> None:
    with pytest.raises(BinanceWsProtocolError, match="serverShutdown"):
        parse_ws_message(raw, market=Market.SPOT)


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        "not-json",
        '{"result":"not-null","id":1}',
        '{"code":2}',
        '{"stream":"btcusdt@depth@100ms"}',
        '{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":1,"u":2,"b":[],"a":[]}',
    ],
)
def test_malformed_or_unbound_raw_frames_fail_closed(raw: str) -> None:
    with pytest.raises(BinanceWsProtocolError) as raised:
        parse_ws_message(raw)
    assert raised.value.raw_text == raw


def test_payload_symbol_must_match_subscription_identity() -> None:
    frames = _frames()
    wrong = _book(Market.SPOT, symbol="ETHUSDT")

    with pytest.raises(BinanceWsProtocolError, match="stream name mismatch"):
        parse_ws_message(frames["spot_depth"], expected=wrong)


@pytest.mark.parametrize(
    "nested",
    [
        {"s": "ETHUSDT", "i": "1m"},
        {"s": "BTCUSDT", "i": "5m"},
    ],
)
def test_candle_nested_identity_and_interval_must_match_subscription(
    nested: dict[str, str],
) -> None:
    spec = stream_spec(
        Market.SPOT,
        "candle_1m",
        instrument_key="BTCUSDT",
        wire_symbol="BTCUSDT",
    )
    raw = (
        '{"e":"kline","E":1,"s":"BTCUSDT","k":'
        + '{"s":"'
        + nested["s"]
        + '","i":"'
        + nested["i"]
        + '"}}'
    )

    with pytest.raises(BinanceWsProtocolError, match="identity or interval"):
        parse_ws_message(raw, expected=spec)


def test_index_info_binds_independent_reference_identity_and_event_type() -> None:
    spec = stream_spec(
        Market.PERPETUAL,
        "index_info",
        index_symbol="SMALLUSDT",
    )

    assert spec.instrument_key is None
    assert spec.wire_symbol == "SMALLUSDT"
    assert spec.stream_name == "smallusdt@compositeIndex"
    with pytest.raises(BinanceWsProtocolError, match="event type mismatch"):
        parse_ws_message('{"e":"wrong","E":1,"s":"SMALLUSDT","st":1}', expected=spec)
    with pytest.raises(BinanceWsProtocolError, match="symbol does not match"):
        parse_ws_message(
            '{"e":"compositeIndex","E":1,"s":"BTCUSDT","st":1}', expected=spec
        )


def test_index_info_rejects_contract_identity_and_other_streams_reject_index_symbol() -> (
    None
):
    with pytest.raises(ValueError, match="explicit index symbol"):
        stream_spec(
            Market.PERPETUAL,
            "index_info",
            instrument_key="BTCUSDT",
            wire_symbol="BTCUSDT",
        )
    with pytest.raises(ValueError, match="only for index_info"):
        stream_spec(
            Market.PERPETUAL,
            "ticker",
            instrument_key="BTCUSDT",
            wire_symbol="BTCUSDT",
            index_symbol="SMALLUSDT",
        )


def test_ticker_and_market_specific_bbo_shapes_fail_closed() -> None:
    ticker = stream_spec(
        Market.SPOT,
        "ticker",
        instrument_key="BTCUSDT",
        wire_symbol="BTCUSDT",
    )
    futures_bbo = stream_spec(
        Market.PERPETUAL,
        "bbo",
        instrument_key="BTCUSDT",
        wire_symbol="BTCUSDT",
    )

    with pytest.raises(BinanceWsProtocolError, match="ticker event type"):
        parse_ws_message('{"e":"miniTicker","E":1,"s":"BTCUSDT"}', expected=ticker)
    with pytest.raises(BinanceWsProtocolError, match="lacks E, T, e"):
        parse_ws_message(
            '{"s":"BTCUSDT","b":"1","B":"1","a":"2","A":"1","st":1}',
            expected=futures_bbo,
        )


def test_connection_rotation_is_planned_before_documented_24_hour_limit() -> None:
    opened = 10_000
    planned = planned_rotation_at_ns(opened)

    assert planned == opened + MAX_CONNECTION_LIFETIME_NS - DEFAULT_ROTATION_LEAD_NS
    assert planned < opened + MAX_CONNECTION_LIFETIME_NS
    assert not rotation_due(opened_monotonic_ns=opened, now_monotonic_ns=planned - 1)
    assert rotation_due(opened_monotonic_ns=opened, now_monotonic_ns=planned)


def test_protocol_ping_payload_is_copied_exactly_into_pong() -> None:
    payload = b"binance-ping\x00"

    assert pong_payload(payload) == payload
    assert pong_payload(bytearray(payload)) == payload
    with pytest.raises(ValueError, match="125"):
        pong_payload(b"x" * 126)


@pytest.mark.parametrize("request_id", [-1, "request", None])
def test_futures_subscription_requires_unsigned_integer_id(request_id: object) -> None:
    with pytest.raises(ValueError, match="unsigned integer"):
        build_subscribe_message(
            [_book(Market.PERPETUAL)], request_id=cast(int | str | None, request_id)
        )


def test_futures_control_ack_requires_market_and_unsigned_integer_id() -> None:
    with pytest.raises(BinanceWsProtocolError, match="market context"):
        parse_ws_message('{"result":null,"id":1}')
    with pytest.raises(ValueError, match="unsigned integer"):
        parse_ws_message('{"result":null,"id":"bad"}', market=Market.PERPETUAL)

    parsed = parse_ws_message('{"result":null,"id":0}', market=Market.PERPETUAL)

    assert parsed.request_id == 0


@pytest.mark.parametrize(
    ("market", "logical_stream"),
    [
        (Market.SPOT, "candle_2m"),
        (Market.PERPETUAL, "candle_1s"),
        (Market.PERPETUAL, "candle_2m"),
    ],
)
def test_websocket_kline_intervals_fail_closed(
    market: Market, logical_stream: str
) -> None:
    with pytest.raises(ValueError, match="candle interval"):
        stream_spec(
            market,
            logical_stream,
            instrument_key="BTCUSDT",
            wire_symbol="BTCUSDT",
        )


def test_documented_futures_stream_rejects_missing_st_indicator() -> None:
    raw = (
        '{"stream":"btcusdt@depth@100ms","data":'
        '{"e":"depthUpdate","E":1,"s":"BTCUSDT","U":1,"u":2,'
        '"pu":0,"b":[],"a":[]}}'
    )

    with pytest.raises(BinanceWsScopeError, match="lacks required st"):
        parse_ws_message(raw, expected=_book(Market.PERPETUAL))


def test_combined_data_frame_requires_expected_stream_binding() -> None:
    with pytest.raises(BinanceWsProtocolError, match="expected stream"):
        parse_ws_message('{"stream":"future@unknown","data":{"future":true}}')
