"""Live smoke tests for Bybit V5 anonymous public market data."""

from __future__ import annotations

import asyncio
import json
import os

import httpx
import pytest
import websockets

RUN_LIVE = os.getenv("RUN_LIVE_API_TESTS") == "1"
REST_URL = "https://api.bybit.com/v5/market/orderbook"
SPOT_WS_URL = "wss://stream.bybit.com/v5/public/spot"
SYMBOL = "BTCUSDT"

pytestmark = pytest.mark.skipif(
    not RUN_LIVE,
    reason="set RUN_LIVE_API_TESTS=1 to call Bybit's public API",
)


def test_spot_orderbook_rest_is_public() -> None:
    with httpx.Client(timeout=10.0) as client:
        response = client.get(
            REST_URL,
            params={"category": "spot", "symbol": SYMBOL, "limit": 1},
        )

    response.raise_for_status()
    payload = response.json()
    assert payload["retCode"] == 0
    assert payload["result"]["s"] == SYMBOL
    assert len(payload["result"]["b"]) == 1
    assert len(payload["result"]["a"]) == 1
    assert int(payload["result"]["u"]) > 0
    assert int(payload["result"]["seq"]) > 0


def test_spot_level_one_orderbook_websocket_is_public() -> None:
    asyncio.run(_receive_spot_orderbook_snapshot())


async def _receive_spot_orderbook_snapshot() -> None:
    topic = f"orderbook.1.{SYMBOL}"

    async with websockets.connect(
        SPOT_WS_URL,
        open_timeout=10,
        close_timeout=5,
        ping_interval=None,
    ) as websocket:
        await websocket.send(json.dumps({"op": "subscribe", "args": [topic]}))

        for _ in range(10):
            raw_message = await asyncio.wait_for(websocket.recv(), timeout=10)
            if isinstance(raw_message, bytes):
                raw_message = raw_message.decode("utf-8")
            message = json.loads(raw_message)

            if message.get("topic") != topic:
                continue

            assert message["type"] == "snapshot"
            assert message["data"]["s"] == SYMBOL
            assert message["data"]["b"]
            assert message["data"]["a"]
            assert int(message["data"]["u"]) > 0
            assert int(message["data"]["seq"]) > 0
            return

    pytest.fail(f"did not receive {topic} data within 10 messages")
