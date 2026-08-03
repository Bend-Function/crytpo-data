from __future__ import annotations

import asyncio
import random
from collections import deque
from collections.abc import Mapping
from hashlib import sha256
from pathlib import Path
from typing import Self, cast

import pytest

from crypto_collector.domain import IntegrityMode, Market
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges.contracts import WebSocketSubscription
from crypto_collector.exchanges.okx.book import BookAction, OkxBookState
from crypto_collector.exchanges.okx.ws import (
    OKX_WS_ARGUMENT_LIMIT_BYTES,
    OkxWsMessageKind,
    OkxWsProtocolError,
    OkxWsReconnectPolicy,
    OkxWsReconnectReason,
    OkxWsSession,
    OkxWsSessionAction,
    build_subscribe_message,
    parse_incremental_book_frames,
    parse_ws_message,
    subscription_argument,
)
from tests.support.scripted_transport import ScriptedWebSocketTransport

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "okx"
_FIXTURE = _FIXTURES / "ws-session.jsonl"
_BLOCK = object()


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


def test_ws_fixture_is_pinned_by_the_shared_provenance_manifest() -> None:
    manifest = decode_json((_FIXTURES / "manifest.json").read_bytes())
    assert isinstance(manifest, dict)
    entries = manifest.get("entries")
    assert isinstance(entries, list)
    ws_entry = next(
        entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("file") == _FIXTURE.name
    )
    assert ws_entry["sha256"] == sha256(_FIXTURE.read_bytes()).hexdigest()
    assert ws_entry["source_anchor"] == "#websocket"


def _subscription(
    *,
    channel: str = "books",
    endpoint: str = "wss://ws.okx.test/ws/v5/public",
    wire_symbol: str | None = "BTC-USDT",
    params: Mapping[str, object] | None = None,
    shard_id: str = "spot-live-0",
) -> WebSocketSubscription:
    return WebSocketSubscription(
        id=f"okx:spot:{channel}",
        market=Market.SPOT,
        instrument_key=None if wire_symbol is None else "BTC-USDT",
        wire_symbol=wire_symbol,
        channel=channel,
        endpoint=endpoint,
        egress_id="direct-primary",
        shard_id=shard_id,
        logical_stream="book_live" if channel == "books" else "trade",
        params={} if params is None else params,  # type: ignore[arg-type]
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


def test_fixture_parser_classifies_and_preserves_every_raw_frame() -> None:
    frames = _fixture_frames()
    expected = {
        "subscribe_ack": OkxWsMessageKind.SUBSCRIBE_ACK,
        "book_snapshot": OkxWsMessageKind.DATA,
        "book_update": OkxWsMessageKind.DATA,
        "book_heartbeat": OkxWsMessageKind.DATA,
        "pong": OkxWsMessageKind.PONG,
        "service_upgrade": OkxWsMessageKind.NOTICE,
        "subscription_error": OkxWsMessageKind.ERROR,
    }

    messages = {name: parse_ws_message(wire) for name, wire in frames.items()}

    assert {name: message.kind for name, message in messages.items()} == expected
    assert all(message.raw_text == frames[name] for name, message in messages.items())
    ack_payload = messages["subscribe_ack"].payload
    assert ack_payload is not None
    assert ack_payload["futureAckField"] == {"kept": True}
    snapshot_payload = messages["book_snapshot"].payload
    assert snapshot_payload is not None
    assert snapshot_payload["futureTopLevel"] == [1, 2, 3]
    assert messages["service_upgrade"].requests_service_upgrade
    assert messages["service_upgrade"].connection_id == "okx-conn-1"
    assert messages["subscription_error"].code == "60012"


def test_raw_book_message_is_available_before_sequence_state_is_applied() -> None:
    frames = _fixture_frames()
    snapshot_message = parse_ws_message(frames["book_snapshot"])
    update_message = parse_ws_message(frames["book_update"])
    heartbeat_message = parse_ws_message(frames["book_heartbeat"])
    state = OkxBookState()

    assert snapshot_message.raw_text == frames["book_snapshot"]
    snapshot_payload = snapshot_message.payload
    assert snapshot_payload is not None
    row = cast(list[dict[str, JsonPayload]], snapshot_payload["data"])[0]
    assert row["futureBookField"] == {"kept": "exactly"}

    snapshot = state.apply(parse_incremental_book_frames(snapshot_message)[0])
    update = state.apply(parse_incremental_book_frames(update_message)[0])
    heartbeat = state.apply(parse_incremental_book_frames(heartbeat_message)[0])

    assert snapshot.action is BookAction.SNAPSHOT
    assert update.action is BookAction.APPLY
    assert update.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert heartbeat.action is BookAction.HEARTBEAT
    assert not heartbeat.count_as_book_update
    assert state.sequence_id == 101


def test_only_literal_unquoted_pong_is_the_application_heartbeat() -> None:
    assert parse_ws_message(b"pong").kind is OkxWsMessageKind.PONG
    with pytest.raises(OkxWsProtocolError, match="must be an object"):
        parse_ws_message('"pong"')
    with pytest.raises(OkxWsProtocolError, match="strict JSON"):
        parse_ws_message("ping")


@pytest.mark.parametrize(
    "raw",
    [
        "[]",
        '{"event":"login","code":"0"}',
        '{"event":"error","msg":"missing code"}',
        '{"event":"notice","msg":"missing code"}',
        '{"arg":{"channel":"tickers"},"data":{}}',
        '{"arg":{},"data":[]}',
    ],
)
def test_malformed_or_out_of_scope_frames_are_protocol_errors(raw: str) -> None:
    with pytest.raises(OkxWsProtocolError) as captured:
        parse_ws_message(raw)
    assert captured.value.raw_text == raw


def test_binary_non_utf8_frame_is_rejected_without_inventing_raw_text() -> None:
    with pytest.raises(OkxWsProtocolError) as captured:
        parse_ws_message(b"\xff\xfe")
    assert captured.value.raw_text is None


def test_public_subscription_message_is_exact_and_anonymous() -> None:
    subscriptions = (
        _subscription(channel="books"),
        _subscription(channel="tickers"),
    )

    raw = build_subscribe_message(subscriptions, request_id="req1")
    payload = decode_json(raw)

    assert payload == {
        "id": "req1",
        "op": "subscribe",
        "args": [
            {"channel": "books", "instId": "BTC-USDT"},
            {"channel": "tickers", "instId": "BTC-USDT"},
        ],
    }
    assert len(raw.encode()) < OKX_WS_ARGUMENT_LIMIT_BYTES


def test_business_anonymous_channels_and_market_wide_params_are_supported() -> None:
    trades = _subscription(
        channel="trades-all",
        endpoint="wss://ws.okx.test/ws/v5/business",
    )
    instruments = _subscription(
        channel="instruments",
        wire_symbol=None,
        params={"instType": "SPOT"},
    )

    assert subscription_argument(trades) == {
        "channel": "trades-all",
        "instId": "BTC-USDT",
    }
    assert subscription_argument(instruments) == {
        "channel": "instruments",
        "instType": "SPOT",
    }


@pytest.mark.parametrize(
    "subscription",
    [
        _subscription(channel="orders"),
        _subscription(
            channel="books",
            endpoint="wss://ws.okx.test/ws/v5/private",
        ),
        _subscription(
            channel="books",
            endpoint="wss://ws.okx.test/ws/v5/business",
        ),
        _subscription(
            channel="trades-all",
            endpoint="wss://ws.okx.test/ws/v5/public",
        ),
    ],
)
def test_channel_and_endpoint_allowlists_reject_private_or_misrouted_topics(
    subscription: WebSocketSubscription,
) -> None:
    with pytest.raises(ValueError, match="endpoint|channel"):
        subscription_argument(subscription)


def test_subscription_builder_rejects_ambiguous_or_oversized_batches() -> None:
    first = _subscription(channel="books")
    with pytest.raises(ValueError, match="unique"):
        build_subscribe_message((first, first), request_id="req1")
    with pytest.raises(ValueError, match="mix endpoints"):
        build_subscribe_message(
            (
                first,
                _subscription(
                    channel="trades-all",
                    endpoint="wss://ws.okx.test/ws/v5/business",
                ),
            ),
            request_id="req1",
        )
    with pytest.raises(ValueError, match="mix storage shards"):
        build_subscribe_message(
            (first, _subscription(channel="tickers", shard_id="other")),
            request_id="req1",
        )
    with pytest.raises(ValueError, match="1-32"):
        build_subscribe_message((first,), request_id="contains-hyphen")
    with pytest.raises(ValueError, match="1-32"):
        build_subscribe_message((first,), request_id=1)  # type: ignore[arg-type]
    huge = _subscription(
        channel="instruments",
        wire_symbol=None,
        params={"instType": "S" * OKX_WS_ARGUMENT_LIMIT_BYTES},
    )
    with pytest.raises(ValueError, match="64 KiB"):
        build_subscribe_message((huge,), request_id="req1")


def test_subscription_params_cannot_override_routing_or_use_arrays() -> None:
    with pytest.raises(ValueError, match="must not replace"):
        subscription_argument(
            _subscription(channel="books", params={"instId": "ETH-USDT"})
        )
    with pytest.raises(TypeError, match="scalar"):
        subscription_argument(
            _subscription(
                channel="instruments",
                wire_symbol=None,
                params={"instType": ["SPOT", "SWAP"]},
            )
        )


@pytest.mark.asyncio
async def test_session_subscribes_routes_data_and_requests_upgrade_reconnect() -> None:
    frames = _fixture_frames()
    connection = _ScriptedConnection(
        frames["subscribe_ack"],
        frames["book_snapshot"],
        frames["service_upgrade"],
    )
    transport = ScriptedWebSocketTransport(connection)
    session = OkxWsSession(transport, (_subscription(),), request_id="req1")

    async with session:
        assert connection.sent == [session.subscribe_message]
        ack = await session.receive()
        assert ack.action is OkxWsSessionAction.MESSAGE
        assert ack.message is not None
        assert ack.message.kind is OkxWsMessageKind.SUBSCRIBE_ACK
        assert session.pending_subscription_count == 0
        assert session.server_connection_id == "okx-conn-1"

        data = await session.receive()
        assert data.action is OkxWsSessionAction.MESSAGE
        assert data.message is not None
        assert data.message.raw_text == frames["book_snapshot"]

        notice = await session.receive()
        assert notice.action is OkxWsSessionAction.RECONNECT
        assert notice.reconnect_reason is OkxWsReconnectReason.SERVICE_UPGRADE
        assert notice.message is not None
        assert notice.message.raw_text == frames["service_upgrade"]
        with pytest.raises(RuntimeError, match="already requires reconnect"):
            await session.receive()

    assert transport.uris == ["wss://ws.okx.test/ws/v5/public"]
    assert connection.closed


@pytest.mark.asyncio
async def test_idle_session_sends_literal_ping_and_requires_literal_pong() -> None:
    connection = _ScriptedConnection(_BLOCK, "pong")
    session = OkxWsSession(
        ScriptedWebSocketTransport(connection),
        (_subscription(),),
        request_id="req1",
        idle_timeout_seconds=0.01,
        pong_timeout_seconds=0.05,
    )

    async with session:
        ping = await session.receive()
        assert ping.action is OkxWsSessionAction.PING_SENT
        assert connection.sent[-1] == "ping"

        pong = await session.receive()
        assert pong.action is OkxWsSessionAction.MESSAGE
        assert pong.message is not None
        assert pong.message.kind is OkxWsMessageKind.PONG


@pytest.mark.asyncio
async def test_missing_pong_and_transport_loss_return_typed_reconnect_signals() -> None:
    no_pong = _ScriptedConnection(_BLOCK, _BLOCK)
    session = OkxWsSession(
        ScriptedWebSocketTransport(no_pong),
        (_subscription(),),
        request_id="req1",
        idle_timeout_seconds=0.01,
        pong_timeout_seconds=0.01,
    )
    async with session:
        assert (await session.receive()).action is OkxWsSessionAction.PING_SENT
        timeout = await session.receive()
        assert timeout.action is OkxWsSessionAction.RECONNECT
        assert timeout.reconnect_reason is OkxWsReconnectReason.PONG_TIMEOUT

    lost = _ScriptedConnection(ConnectionError("injected transport close"))
    session = OkxWsSession(
        ScriptedWebSocketTransport(lost),
        (_subscription(),),
        request_id="req1",
    )
    async with session:
        closed = await session.receive()
        assert closed.reconnect_reason is OkxWsReconnectReason.TRANSPORT_ERROR
        assert closed.error_type == "ConnectionError"


@pytest.mark.asyncio
async def test_missing_subscription_ack_has_an_independent_deadline() -> None:
    connection = _ScriptedConnection("pong", _BLOCK)
    session = OkxWsSession(
        ScriptedWebSocketTransport(connection),
        (_subscription(),),
        request_id="req1",
        idle_timeout_seconds=0.05,
        pong_timeout_seconds=0.02,
        subscription_timeout_seconds=0.01,
    )
    async with session:
        pong = await session.receive()
        assert pong.action is OkxWsSessionAction.MESSAGE
        assert pong.message is not None
        assert pong.message.kind is OkxWsMessageKind.PONG

        timeout = await session.receive()
        assert timeout.action is OkxWsSessionAction.RECONNECT
        assert timeout.reconnect_reason is OkxWsReconnectReason.SUBSCRIPTION_TIMEOUT


@pytest.mark.asyncio
async def test_non_pong_data_does_not_extend_an_outstanding_pong_deadline() -> None:
    frames = _fixture_frames()
    connection = _ScriptedConnection(_BLOCK, frames["book_snapshot"], _BLOCK)
    session = OkxWsSession(
        ScriptedWebSocketTransport(connection),
        (_subscription(),),
        request_id="req1",
        idle_timeout_seconds=0.01,
        pong_timeout_seconds=0.03,
    )
    async with session:
        assert (await session.receive()).action is OkxWsSessionAction.PING_SENT
        assert (await session.receive()).action is OkxWsSessionAction.MESSAGE
        await asyncio.sleep(0.035)
        timeout = await session.receive()
        assert timeout.reconnect_reason is OkxWsReconnectReason.PONG_TIMEOUT


@pytest.mark.asyncio
async def test_ack_mismatch_server_error_and_malformed_frame_preserve_evidence() -> (
    None
):
    frames = _fixture_frames()
    wrong_ack = frames["subscribe_ack"].replace('"req1"', '"wrong"', 1)
    connection = _ScriptedConnection(wrong_ack)
    session = OkxWsSession(
        ScriptedWebSocketTransport(connection),
        (_subscription(),),
        request_id="req1",
    )
    async with session:
        mismatch = await session.receive()
        assert mismatch.reconnect_reason is OkxWsReconnectReason.SUBSCRIPTION_MISMATCH
        assert mismatch.message is not None
        assert mismatch.message.raw_text == wrong_ack

    connection = _ScriptedConnection(frames["subscription_error"])
    session = OkxWsSession(
        ScriptedWebSocketTransport(connection),
        (_subscription(),),
        request_id="req1",
    )
    async with session:
        server_error = await session.receive()
        assert server_error.reconnect_reason is OkxWsReconnectReason.SERVER_ERROR
        assert server_error.message is not None
        assert server_error.message.payload is not None
        assert server_error.message.payload["futureErrorField"] == 42

    malformed_raw = "{not-json"
    connection = _ScriptedConnection(malformed_raw)
    session = OkxWsSession(
        ScriptedWebSocketTransport(connection),
        (_subscription(),),
        request_id="req1",
    )
    async with session:
        malformed = await session.receive()
        assert malformed.reconnect_reason is OkxWsReconnectReason.PROTOCOL_ERROR
        assert malformed.raw_text == malformed_raw
        assert malformed.error_type == "OkxWsProtocolError"


def test_reconnect_policy_is_bounded_full_jitter() -> None:
    policy = OkxWsReconnectPolicy(base_ns=100, cap_ns=1_000)
    first_rng = random.Random(7)
    second_rng = random.Random(7)
    first = [policy.delay_ns(attempt, rng=first_rng) for attempt in range(8)]
    second = [policy.delay_ns(attempt, rng=second_rng) for attempt in range(8)]

    assert first == second
    assert all(0 <= delay <= 1_000 for delay in first)
    with pytest.raises(ValueError, match="must not exceed"):
        OkxWsReconnectPolicy(base_ns=2, cap_ns=1)
