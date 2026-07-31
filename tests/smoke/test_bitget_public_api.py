"""Live, anonymous Bitget UTA v3 public API smoke tests.

Run explicitly with::

    RUN_LIVE_API_TESTS=1 .venv/bin/pytest -q tests/smoke/test_bitget_public_api.py
"""

from __future__ import annotations

import asyncio
import json
import os

import httpx
import pytest
from websockets.asyncio.client import connect

pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_API_TESTS") != "1",
    reason="set RUN_LIVE_API_TESTS=1 to call Bitget's public API",
)

REST_BASE_URL = "https://api.bitget.com"
PUBLIC_WS_URL = "wss://ws.bitget.com/v3/ws/public"


@pytest.mark.parametrize("category", ["SPOT", "USDT-FUTURES"])
def test_v3_instruments_endpoint_is_public_for_btcusdt(category: str) -> None:
    response = httpx.get(
        f"{REST_BASE_URL}/api/v3/market/instruments",
        params={"category": category, "symbol": "BTCUSDT"},
        timeout=10.0,
    )

    response.raise_for_status()
    payload = response.json()
    assert payload["code"] == "00000", payload
    assert any(
        instrument["symbol"] == "BTCUSDT" and instrument["category"] == category
        for instrument in payload["data"]
    ), payload


def test_v3_spot_ticker_websocket_is_public() -> None:
    async def receive_ticker() -> None:
        subscription = {
            "op": "subscribe",
            "args": [
                {
                    "instType": "spot",
                    "topic": "ticker",
                    "symbol": "BTCUSDT",
                }
            ],
        }

        async with connect(
            PUBLIC_WS_URL,
            open_timeout=10,
            close_timeout=5,
            ping_interval=None,
            max_size=1_048_576,
        ) as websocket:
            await websocket.send(json.dumps(subscription))
            saw_ack = False

            for _ in range(8):
                raw_message = await asyncio.wait_for(websocket.recv(), timeout=10)
                if raw_message == "pong":
                    continue

                message = json.loads(raw_message)
                if message.get("event") == "error":
                    pytest.fail(f"Bitget rejected public subscription: {message}")
                if message.get("event") == "subscribe":
                    saw_ack = True
                    continue

                argument = message.get("arg", {})
                if argument.get("topic") != "ticker" or not message.get("data"):
                    continue

                assert saw_ack, message
                assert argument["instType"] == "spot"
                assert argument["symbol"] == "BTCUSDT"
                assert all(item.get("lastPrice") for item in message["data"]), message
                return

            pytest.fail("Bitget did not send a BTCUSDT ticker event")

    asyncio.run(receive_ticker())
