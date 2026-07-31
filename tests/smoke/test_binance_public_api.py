"""Opt-in live smoke tests for Binance public market data.

These tests never authenticate or place orders. Enable them explicitly with
RUN_LIVE_API_TESTS=1.
"""

from __future__ import annotations

import asyncio
import json
import os
from decimal import Decimal
from typing import Any

import httpx
import pytest
import websockets

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_LIVE_API_TESTS") != "1",
    reason="set RUN_LIVE_API_TESTS=1 to call Binance public APIs",
)

HTTP_TIMEOUT = httpx.Timeout(8.0, connect=5.0)
WS_OPERATION_TIMEOUT_SECONDS = 12


def _get_json(url: str, params: dict[str, str]) -> Any:
    with httpx.Client(
        timeout=HTTP_TIMEOUT,
        headers={"User-Agent": "crypto-data-binance-live-smoke/1.0"},
    ) as client:
        response = client.get(url, params=params)
        response.raise_for_status()
        return response.json()


async def _receive_one_json(url: str) -> dict[str, Any]:
    async with asyncio.timeout(WS_OPERATION_TIMEOUT_SECONDS):
        async with websockets.connect(
            url,
            open_timeout=5,
            close_timeout=2,
            ping_timeout=5,
            max_size=1_048_576,
        ) as websocket:
            message = await websocket.recv()

    assert isinstance(message, str)
    payload = json.loads(message)
    assert isinstance(payload, dict)
    return payload


def _assert_positive_decimal(value: Any) -> None:
    number = Decimal(str(value))
    assert number.is_finite()
    assert number > 0


def test_spot_rest_ticker_is_public_and_live() -> None:
    payload = _get_json(
        "https://data-api.binance.vision/api/v3/ticker/price",
        {"symbol": "BTCUSDT"},
    )

    assert payload["symbol"] == "BTCUSDT"
    _assert_positive_decimal(payload["price"])


def test_usds_m_perpetual_rest_mark_price_is_public_and_live() -> None:
    payload = _get_json(
        "https://fapi.binance.com/fapi/v1/premiumIndex",
        {"symbol": "BTCUSDT"},
    )

    assert payload["symbol"] == "BTCUSDT"
    assert isinstance(payload["time"], int)
    assert payload["time"] > 0
    _assert_positive_decimal(payload["markPrice"])
    _assert_positive_decimal(payload["indexPrice"])


def test_spot_websocket_trade_stream_emits_data() -> None:
    payload = asyncio.run(
        _receive_one_json("wss://data-stream.binance.vision:443/ws/btcusdt@trade")
    )

    assert payload["e"] == "trade"
    assert payload["s"] == "BTCUSDT"
    assert isinstance(payload["t"], int)
    assert isinstance(payload["E"], int)
    assert isinstance(payload["T"], int)
    _assert_positive_decimal(payload["p"])
    _assert_positive_decimal(payload["q"])


def test_usds_m_perpetual_websocket_aggregate_trade_stream_emits_data() -> None:
    payload = asyncio.run(
        _receive_one_json("wss://fstream.binance.com/market/ws/btcusdt@aggTrade")
    )

    assert payload["e"] == "aggTrade"
    assert payload["s"] == "BTCUSDT"
    assert isinstance(payload["a"], int)
    assert isinstance(payload["E"], int)
    assert isinstance(payload["T"], int)
    _assert_positive_decimal(payload["p"])
    _assert_positive_decimal(payload["q"])
