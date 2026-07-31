"""Live, anonymous Kraken Spot and Derivatives public API smoke tests.

Run explicitly with::

    RUN_LIVE_API_TESTS=1 .venv/bin/pytest -q tests/smoke/test_kraken_public_api.py
"""

from __future__ import annotations

import asyncio
import json
import os
import time

import httpx
import pytest
from websockets.asyncio.client import connect


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_LIVE_API_TESTS") != "1",
    reason="set RUN_LIVE_API_TESTS=1 to call Kraken's public APIs",
)

SPOT_REST_BASE_URL = "https://api.kraken.com/0"
SPOT_WS_URL = "wss://ws.kraken.com/v2"
FUTURES_REST_BASE_URL = "https://futures.kraken.com/derivatives/api/v3"
FUTURES_WS_URL = "wss://futures.kraken.com/ws/v1"
SPOT_REST_SYMBOL = "BTCUSDT"
SPOT_WS_SYMBOL = "BTC/USDT"
FUTURES_SYMBOL = "PF_XBTUSD"


def test_spot_asset_pair_discovery_is_public() -> None:
    response = httpx.get(
        f"{SPOT_REST_BASE_URL}/public/AssetPairs",
        params={"pair": SPOT_REST_SYMBOL},
        timeout=10.0,
    )

    response.raise_for_status()
    payload = response.json()
    assert payload["error"] == [], payload
    pair = payload["result"]["XBTUSDT"]
    assert pair["quote"] == "USDT"
    assert pair["status"] == "online"
    assert float(pair["tick_size"]) > 0


def test_futures_instrument_discovery_is_public() -> None:
    response = httpx.get(
        f"{FUTURES_REST_BASE_URL}/instruments",
        params={"contractType": "flexible_futures"},
        timeout=10.0,
    )

    response.raise_for_status()
    payload = response.json()
    assert payload["result"] == "success", payload
    instrument = next(
        item for item in payload["instruments"] if item["symbol"] == FUTURES_SYMBOL
    )
    assert instrument["tradeable"] is True
    assert instrument["base"] in {"BTC", "XBT"}
    assert instrument["quote"] == "USD"
    assert float(instrument["tickSize"]) > 0


def test_futures_open_interest_analytics_is_public() -> None:
    response = httpx.get(
        "https://futures.kraken.com/api/charts/v1/analytics/"
        f"{FUTURES_SYMBOL}/open-interest",
        params={"since": int(time.time()) - 3600, "interval": 300},
        timeout=10.0,
    )

    response.raise_for_status()
    payload = response.json()
    assert payload["errors"] == [], payload
    assert payload["result"]["timestamp"], payload
    assert payload["result"]["data"], payload


def test_spot_level_two_book_websocket_is_public() -> None:
    asyncio.run(_receive_spot_book_snapshot())


async def _receive_spot_book_snapshot() -> None:
    request = {
        "method": "subscribe",
        "params": {
            "channel": "book",
            "symbol": [SPOT_WS_SYMBOL],
            "depth": 10,
            "snapshot": True,
        },
    }

    async with connect(
        SPOT_WS_URL,
        open_timeout=10,
        close_timeout=5,
        ping_interval=None,
        max_size=1_048_576,
    ) as websocket:
        await websocket.send(json.dumps(request))
        saw_ack = False

        async with asyncio.timeout(15):
            while True:
                raw_message = await websocket.recv()
                if isinstance(raw_message, bytes):
                    raw_message = raw_message.decode("utf-8")
                message = json.loads(raw_message)

                if message.get("method") == "subscribe":
                    assert message["success"] is True, message
                    saw_ack = True
                    continue
                if message.get("channel") != "book":
                    continue

                assert saw_ack, message
                assert message["type"] == "snapshot"
                book = message["data"][0]
                assert book["symbol"] == SPOT_WS_SYMBOL
                assert book["bids"]
                assert book["asks"]
                assert int(book["checksum"]) >= 0
                return


def test_futures_ticker_websocket_is_public() -> None:
    asyncio.run(_receive_futures_ticker())


async def _receive_futures_ticker() -> None:
    request = {
        "event": "subscribe",
        "feed": "ticker",
        "product_ids": [FUTURES_SYMBOL],
    }

    async with connect(
        FUTURES_WS_URL,
        open_timeout=10,
        close_timeout=5,
        ping_interval=None,
        max_size=1_048_576,
    ) as websocket:
        await websocket.send(json.dumps(request))
        saw_ack = False

        async with asyncio.timeout(15):
            while True:
                raw_message = await websocket.recv()
                if isinstance(raw_message, bytes):
                    raw_message = raw_message.decode("utf-8")
                message = json.loads(raw_message)

                if message.get("event") == "error":
                    pytest.fail(f"Kraken Futures rejected public subscription: {message}")
                if message.get("event") == "subscribed":
                    saw_ack = True
                    continue
                if (
                    message.get("feed") != "ticker"
                    or message.get("product_id") != FUTURES_SYMBOL
                ):
                    continue

                assert saw_ack, message
                assert float(message["bid"]) > 0
                assert float(message["ask"]) > 0
                assert float(message["markPrice"]) > 0
                assert float(message["index"]) > 0
                assert float(message["openInterest"]) >= 0
                return
