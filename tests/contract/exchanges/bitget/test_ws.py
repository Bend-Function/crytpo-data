from __future__ import annotations

import asyncio
import random
from collections import deque
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Self, cast

import pytest

from crypto_collector.domain import CoverageMode, IntegrityMode, Market
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges.bitget.book import BitgetBook, BookAction
from crypto_collector.exchanges.bitget.ws import (
    BITGET_WS_CHANNEL_LIMIT,
    BITGET_WS_RECOMMENDED_CHANNEL_LIMIT,
    BitgetConnection,
    BitgetWsMessageKind,
    BitgetWsProtocolError,
    BitgetWsReconnectPolicy,
    BitgetWsReconnectReason,
    BitgetWsSession,
    BitgetWsSessionAction,
    build_subscribe_message,
    parse_incremental_book_frames,
    parse_ws_message,
    subscription_argument,
    topic_coverage,
)
from crypto_collector.exchanges.contracts import PublicQueryValue, WebSocketSubscription
from tests.support.scripted_transport import ScriptedWebSocketTransport

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "bitget"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_FIXTURE = _FIXTURES / "ws-session.jsonl"
_BLOCK = object()


def _object(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def _array(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _fixture_frames() -> dict[str, str]:
    frames: dict[str, str] = {}
    for line in _FIXTURE.read_bytes().splitlines():
        record = decode_json(line)
        assert isinstance(record, dict)
        name = record.get("name")
        wire = record.get("wire")
        assert type(name) is str
        assert type(wire) is str
        frames[name] = wire
    return frames


def _subscription(
    *,
    topic: str = "books",
    market: Market = Market.PERPETUAL,
    wire_symbol: str | None = "BTCUSDT",
    endpoint: str = "wss://ws.bitget.test/v3/ws/public",
    params: Mapping[str, PublicQueryValue] | None = None,
    shard_id: str = "perpetual-live-0",
) -> WebSocketSubscription:
    logical_stream = (
        "book_live"
        if topic == "books"
        else "liquidation"
        if topic == "liquidation"
        else "trade"
    )
    return WebSocketSubscription(
        id=f"bitget:{market.value}:{topic}",
        market=market,
        instrument_key=None if wire_symbol is None else wire_symbol,
        wire_symbol=wire_symbol,
        channel=topic,
        endpoint=endpoint,
        egress_id="direct-primary",
        shard_id=shard_id,
        logical_stream=logical_stream,
        params=(
            {"instType": "spot" if market is Market.SPOT else "usdt-futures"}
            if params is None
            else params
        ),
    )


class _ScriptedConnection:
    def __init__(self, *received: object) -> None:
        self.received = deque(received)
        self.sent: list[str] = []
        self.closed = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        del exc_type, exc, traceback
        self.closed = True

    async def send(self, message: str) -> None:
        self.sent.append(message)

    async def recv(self) -> str | bytes:
        if not self.received:
            raise AssertionError("scripted connection has no receive frame")
        item = self.received.popleft()
        if item is _BLOCK:
            await asyncio.Event().wait()
            raise AssertionError("unreachable")
        if isinstance(item, Exception):
            raise item
        assert type(item) in {str, bytes}
        return cast(str | bytes, item)


class _ContinuousDataConnection(_ScriptedConnection):
    def __init__(self, acknowledgement: str, data: str) -> None:
        super().__init__()
        self._acknowledgement = acknowledgement
        self._data = data
        self._first = True

    async def recv(self) -> str:
        await asyncio.sleep(0.002)
        if self._first:
            self._first = False
            return self._acknowledgement
        return self._data


def test_fixture_manifest_pins_each_fixture_and_archived_source() -> None:
    manifest = _object(decode_json((_FIXTURES / "manifest.json").read_bytes()))
    entries = _array(manifest["entries"])

    assert {str(_object(entry)["file"]) for entry in entries} == {
        "book-first-update.json",
        "book-snapshot.json",
        "book-update.json",
        "futures-instruments.json",
        "spot-instruments.json",
        "ws-session.jsonl",
    }
    for value in entries:
        entry = _object(value)
        fixture = _FIXTURES / str(entry["file"])
        source = _REPOSITORY_ROOT / str(entry["source_document"])
        assert sha256(fixture.read_bytes()).hexdigest() == entry["sha256"]
        assert (
            sha256(source.read_bytes()).hexdigest() == entry["source_document_sha256"]
        )
        anchor = str(entry["source_anchor"])
        assert anchor.startswith("#")
        assert f'id="{anchor[1:]}"'.encode() in source.read_bytes()
        secondary = entry.get("secondary_sources", [])
        assert isinstance(secondary, list)
        for secondary_value in secondary:
            secondary_entry = _object(secondary_value)
            secondary_source = _REPOSITORY_ROOT / str(
                secondary_entry["source_document"]
            )
            assert (
                sha256(secondary_source.read_bytes()).hexdigest()
                == secondary_entry["source_document_sha256"]
            )
            secondary_anchor = str(secondary_entry["source_anchor"])
            assert (
                f'id="{secondary_anchor[1:]}"'.encode() in secondary_source.read_bytes()
            )


def test_fixture_parser_classifies_and_preserves_raw_frames() -> None:
    frames = _fixture_frames()
    expected = {
        "subscribe_ack": BitgetWsMessageKind.SUBSCRIBE_ACK,
        "book_snapshot": BitgetWsMessageKind.DATA,
        "book_first_update": BitgetWsMessageKind.DATA,
        "pong": BitgetWsMessageKind.PONG,
        "subscription_error": BitgetWsMessageKind.ERROR,
    }

    messages = {name: parse_ws_message(wire) for name, wire in frames.items()}

    assert {name: message.kind for name, message in messages.items()} == expected
    assert all(message.raw_text == frames[name] for name, message in messages.items())
    ack = messages["subscribe_ack"]
    assert ack.connection_id == "bitget-conn-1"
    assert ack.payload is not None
    assert ack.payload["futureAckField"] == {"kept": True}
    snapshot = messages["book_snapshot"]
    assert snapshot.payload is not None
    assert snapshot.payload["futureTopLevel"] == [1, 2, 3]


def test_raw_book_payload_remains_available_before_chain_validation() -> None:
    frames = _fixture_frames()
    snapshot_message = parse_ws_message(frames["book_snapshot"])
    update_message = parse_ws_message(frames["book_first_update"])
    assert snapshot_message.payload is not None
    row = cast(list[dict[str, JsonPayload]], snapshot_message.payload["data"])[0]
    assert row["futureBookField"] == {"kept": "raw"}

    state = BitgetBook()
    snapshot = state.apply(parse_incremental_book_frames(snapshot_message)[0])
    update = state.apply(parse_incremental_book_frames(update_message)[0])

    assert snapshot.action is BookAction.SNAPSHOT
    assert snapshot.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert update.action is BookAction.APPLY
    assert update.integrity is IntegrityMode.SEQUENCE_VERIFIED


def test_only_literal_unquoted_pong_is_the_application_heartbeat() -> None:
    assert parse_ws_message(b"pong").kind is BitgetWsMessageKind.PONG
    with pytest.raises(BitgetWsProtocolError, match="must be an object"):
        parse_ws_message('"pong"')
    with pytest.raises(BitgetWsProtocolError, match="strict JSON"):
        parse_ws_message("ping")


def test_error_frame_preserves_the_rejected_argument_without_accepting_its_schema() -> (
    None
):
    raw = (
        '{"event":"error","code":"30001","msg":"bad argument",'
        '"arg":{"instType":"SPOT","topic":"privateThing"}}'
    )

    message = parse_ws_message(raw)

    assert message.kind is BitgetWsMessageKind.ERROR
    assert message.argument == {"instType": "SPOT", "topic": "privateThing"}
    assert message.raw_text == raw
    assert message.coverage is None


def test_oversized_digit_timestamp_is_a_typed_protocol_error() -> None:
    raw = (
        '{"arg":{"instType":"spot","topic":"ticker","symbol":"BTCUSDT"},'
        '"action":"snapshot","data":[],"ts":"' + "9" * 5_000 + '"}'
    )

    with pytest.raises(BitgetWsProtocolError, match="signed 64-bit") as captured:
        parse_ws_message(raw)
    assert captured.value.raw_text == raw


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        '{"event":"login","code":"00000"}',
        '{"event":"error","msg":"missing code"}',
        '{"event":"subscribe","arg":{"instType":"spot","topic":"ticker","symbol":"BTCUSDT"}}',
        '{"arg":{"instType":"spot","topic":"ticker","symbol":"BTCUSDT"},"action":"snapshot","data":{}}',
        '{"arg":{"instType":"SPOT","topic":"ticker","symbol":"BTCUSDT"},"action":"snapshot","data":[],"ts":1}',
        '{"arg":{"instType":"spot","topic":"unknown","symbol":"BTCUSDT"},"action":"snapshot","data":[],"ts":1}',
        '{"arg":{"instType":"spot","topic":"ticker","symbol":"BTCUSDT"},"action":"delta","data":[],"ts":1}',
        '{"arg":{"instType":"spot","topic":"ticker","symbol":"BTCUSDT"},"action":[],"data":[],"ts":1}',
        '{"arg":{"instType":"spot","topic":"kline","symbol":"BTCUSDT","interval":[]},"action":"snapshot","data":[],"ts":1}',
        '{"arg":{"instType":"spot","topic":"ticker","symbol":"BTCUSDT"},"action":"snapshot","data":[],"ts":"not-a-time"}',
    ],
)
def test_malformed_or_out_of_scope_frames_preserve_protocol_evidence(raw: str) -> None:
    with pytest.raises(BitgetWsProtocolError) as captured:
        parse_ws_message(raw)
    assert captured.value.raw_text == raw


def test_binary_non_utf8_frame_is_rejected_without_fabricated_text() -> None:
    with pytest.raises(BitgetWsProtocolError) as captured:
        parse_ws_message(b"\xff\xfe")
    assert captured.value.raw_text is None


def test_uta_v3_subscription_message_has_exact_casing_and_no_request_id() -> None:
    raw = build_subscribe_message(
        (
            _subscription(topic="ticker", market=Market.SPOT),
            _subscription(topic="books"),
        )
    )

    assert decode_json(raw) == {
        "op": "subscribe",
        "args": [
            {"instType": "spot", "topic": "ticker", "symbol": "BTCUSDT"},
            {
                "instType": "usdt-futures",
                "topic": "books",
                "symbol": "BTCUSDT",
            },
        ],
    }
    assert "id" not in _object(decode_json(raw))


@pytest.mark.parametrize(
    "topic",
    ["ticker", "publicTrade", "books1", "books5", "books50", "books"],
)
def test_symbol_topics_require_exact_inst_type_topic_and_symbol(topic: str) -> None:
    assert subscription_argument(_subscription(topic=topic)) == {
        "instType": "usdt-futures",
        "topic": topic,
        "symbol": "BTCUSDT",
    }


def test_kline_requires_documented_interval_as_a_separate_argument() -> None:
    subscription = _subscription(
        topic="kline",
        market=Market.SPOT,
        params={"instType": "spot", "interval": "1m"},
    )

    assert subscription_argument(subscription) == {
        "instType": "spot",
        "topic": "kline",
        "symbol": "BTCUSDT",
        "interval": "1m",
    }


def test_liquidation_is_usdt_futures_market_scoped_and_has_no_symbol() -> None:
    subscription = _subscription(topic="liquidation", wire_symbol=None)

    assert subscription_argument(subscription) == {
        "instType": "usdt-futures",
        "topic": "liquidation",
    }
    message = parse_ws_message(
        '{"data":[{"symbol":"BTCUSDT","side":"buy","price":"1",'
        '"amount":"2","ts":"3"}],"arg":{"instType":"usdt-futures",'
        '"topic":"liquidation"},"action":"update","ts":3}'
    )
    assert message.coverage is CoverageMode.LOSSY_WINDOW
    acknowledgement = parse_ws_message(
        '{"event":"subscribe","arg":{"instType":"usdt-futures",'
        '"topic":"liquidation"},"connId":"connection-1"}'
    )
    assert acknowledgement.coverage is None
    assert topic_coverage("liquidation") is CoverageMode.LOSSY_WINDOW
    assert topic_coverage("ticker") is None


@pytest.mark.parametrize(
    "subscription",
    [
        _subscription(topic="orders"),
        _subscription(endpoint="wss://ws.bitget.test/v2/ws/public"),
        _subscription(endpoint="wss://ws.bitget.test/v3/ws/private"),
        _subscription(topic="books", wire_symbol=None),
        _subscription(topic="liquidation", market=Market.SPOT, wire_symbol=None),
        _subscription(
            topic="books",
            params={"instType": "USDT-FUTURES"},
        ),
        _subscription(
            topic="kline",
            params={"instType": "usdt-futures", "interval": "2m"},
        ),
        _subscription(
            topic="ticker",
            params={"instType": "usdt-futures", "symbol": "ETHUSDT"},
        ),
    ],
)
def test_builder_rejects_classic_private_or_wrong_topic_schema(
    subscription: WebSocketSubscription,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        subscription_argument(subscription)


def test_builder_rejects_duplicates_mixed_routes_and_channel_overflow() -> None:
    first = _subscription()
    with pytest.raises(ValueError, match="unique"):
        build_subscribe_message((first, first))
    with pytest.raises(ValueError, match="mix storage shards"):
        build_subscribe_message(
            (first, _subscription(topic="ticker", shard_id="other"))
        )
    with pytest.raises(ValueError, match="1000"):
        build_subscribe_message((first,) * (BITGET_WS_CHANNEL_LIMIT + 1))
    assert BITGET_WS_RECOMMENDED_CHANNEL_LIMIT == 49


@pytest.mark.asyncio
async def test_connection_sends_and_accepts_only_literal_heartbeat_text() -> None:
    scripted = _ScriptedConnection("pong")
    connection = BitgetConnection(scripted)

    await connection.send_heartbeat()

    assert scripted.sent == ["ping"]
    assert await connection.wait_for_pong(timeout=0.1)


@pytest.mark.asyncio
async def test_session_subscribes_routes_data_and_tracks_connection_id() -> None:
    frames = _fixture_frames()
    connection = _ScriptedConnection(
        frames["subscribe_ack"],
        frames["book_snapshot"],
    )
    transport = ScriptedWebSocketTransport(connection)
    session = BitgetWsSession(transport, (_subscription(),))

    async with session:
        assert connection.sent == [session.subscribe_message]
        ack = await session.receive()
        assert ack.action is BitgetWsSessionAction.MESSAGE
        assert session.pending_subscription_count == 0
        assert session.server_connection_id == "bitget-conn-1"
        data = await session.receive()
        assert data.action is BitgetWsSessionAction.MESSAGE
        assert data.message is not None
        assert data.message.raw_text == frames["book_snapshot"]

    assert transport.uris == ["wss://ws.bitget.test/v3/ws/public"]
    assert connection.closed


@pytest.mark.asyncio
async def test_idle_session_sends_literal_ping_and_requires_literal_pong() -> None:
    connection = _ScriptedConnection(_BLOCK, "pong")
    session = BitgetWsSession(
        ScriptedWebSocketTransport(connection),
        (_subscription(),),
        idle_timeout_seconds=0.01,
        pong_timeout_seconds=0.05,
    )

    async with session:
        ping = await session.receive()
        assert ping.action is BitgetWsSessionAction.PING_SENT
        assert connection.sent[-1] == "ping"
        pong = await session.receive()
        assert pong.message is not None
        assert pong.message.kind is BitgetWsMessageKind.PONG


@pytest.mark.asyncio
async def test_continuous_market_data_does_not_starve_periodic_ping() -> None:
    frames = _fixture_frames()
    connection = _ContinuousDataConnection(
        frames["subscribe_ack"],
        frames["book_snapshot"],
    )
    session = BitgetWsSession(
        ScriptedWebSocketTransport(connection),
        (_subscription(),),
        idle_timeout_seconds=0.01,
        pong_timeout_seconds=0.05,
    )

    async with session:
        events = []
        for _ in range(20):
            event = await session.receive()
            events.append(event)
            if event.action is BitgetWsSessionAction.PING_SENT:
                break

    assert any(event.action is BitgetWsSessionAction.MESSAGE for event in events)
    assert events[-1].action is BitgetWsSessionAction.PING_SENT
    assert connection.sent[-1] == "ping"


@pytest.mark.asyncio
async def test_missing_pong_and_server_error_are_typed_reconnects() -> None:
    no_pong = _ScriptedConnection(_BLOCK, _BLOCK)
    session = BitgetWsSession(
        ScriptedWebSocketTransport(no_pong),
        (_subscription(),),
        idle_timeout_seconds=0.01,
        pong_timeout_seconds=0.01,
    )
    async with session:
        assert (await session.receive()).action is BitgetWsSessionAction.PING_SENT
        timeout = await session.receive()
        assert timeout.reconnect_reason is BitgetWsReconnectReason.PONG_TIMEOUT

    frames = _fixture_frames()
    errored = BitgetWsSession(
        ScriptedWebSocketTransport(_ScriptedConnection(frames["subscription_error"])),
        (_subscription(),),
    )
    async with errored:
        event = await errored.receive()
        assert event.reconnect_reason is BitgetWsReconnectReason.SERVER_ERROR
        assert event.message is not None
        assert event.message.raw_text == frames["subscription_error"]


def test_reconnect_policy_is_bounded_full_jitter() -> None:
    policy = BitgetWsReconnectPolicy(base_ns=100, cap_ns=1_000)
    first_rng = random.Random(7)
    second_rng = random.Random(7)
    first = [policy.delay_ns(attempt, rng=first_rng) for attempt in range(8)]
    second = [policy.delay_ns(attempt, rng=second_rng) for attempt in range(8)]

    assert first == second
    assert all(0 <= delay <= 1_000 for delay in first)
    with pytest.raises(ValueError, match="must not exceed"):
        BitgetWsReconnectPolicy(base_ns=2, cap_ns=1)
