"""Opt-in live smoke tests for anonymous OKX V5 market data."""

from __future__ import annotations

import asyncio
import json
import os
import time

import httpx
import pytest
import websockets


REST_BASE_URL = os.getenv("OKX_REST_BASE_URL", "https://openapi.okx.com").rstrip("/")
WS_PUBLIC_URL = os.getenv(
    "OKX_WS_PUBLIC_URL", "wss://ws.okx.com:8443/ws/v5/public"
)
INSTRUMENTS = (("SPOT", "BTC-USDT"), ("SWAP", "BTC-USDT-SWAP"))

pytestmark = pytest.mark.skipif(
    os.getenv("RUN_LIVE_API_TESTS") != "1",
    reason="set RUN_LIVE_API_TESTS=1 to contact OKX public APIs",
)


def _okx_data(response: httpx.Response) -> list[dict[str, object]]:
    response.raise_for_status()
    payload = response.json()
    assert payload["code"] == "0", payload
    assert payload["msg"] == "", payload
    assert isinstance(payload["data"], list) and payload["data"], payload
    return payload["data"]


@pytest.mark.parametrize(("instrument_type", "instrument_id"), INSTRUMENTS)
def test_public_rest_instrument_and_ticker(
    instrument_type: str, instrument_id: str
) -> None:
    with httpx.Client(
        base_url=REST_BASE_URL,
        timeout=httpx.Timeout(15.0),
        headers={"User-Agent": "crypto-data-okx-smoke/1"},
        follow_redirects=False,
    ) as client:
        instruments = _okx_data(
            client.get(
                "/api/v5/public/instruments",
                params={"instType": instrument_type, "instId": instrument_id},
            )
        )
        tickers = _okx_data(
            client.get("/api/v5/market/ticker", params={"instId": instrument_id})
        )

    instrument = instruments[0]
    assert instrument["instId"] == instrument_id
    assert instrument["instType"] == instrument_type
    assert instrument["state"] in {"live", "preopen", "post_only", "suspend"}
    assert str(instrument["listTime"]).isdigit()

    if instrument_type == "SPOT":
        assert instrument["baseCcy"] == "BTC"
        assert instrument["quoteCcy"] == "USDT"
    else:
        assert instrument["ctType"] == "linear"
        assert instrument["settleCcy"] == "USDT"
        assert instrument["ctVal"]

    ticker = tickers[0]
    assert ticker["instId"] == instrument_id
    assert float(str(ticker["last"])) > 0
    assert float(str(ticker["bidPx"])) > 0
    assert float(str(ticker["askPx"])) > 0
    assert float(str(ticker["vol24h"])) >= 0
    assert str(ticker["ts"]).isdigit()


async def _receive_public_tickers() -> None:
    requested = {instrument_id for _, instrument_id in INSTRUMENTS}
    received: set[str] = set()
    deadline = time.monotonic() + 20.0

    async with websockets.connect(
        WS_PUBLIC_URL,
        open_timeout=15.0,
        close_timeout=5.0,
        ping_interval=None,
        max_size=1_048_576,
    ) as websocket:
        await websocket.send(
            json.dumps(
                {
                    "id": "okxpublicsmoke",
                    "op": "subscribe",
                    "args": [
                        {"channel": "tickers", "instId": instrument_id}
                        for instrument_id in sorted(requested)
                    ],
                },
                separators=(",", ":"),
            )
        )

        while received != requested:
            remaining = deadline - time.monotonic()
            assert remaining > 0, f"timed out waiting for ticker data: {received=}"
            raw = await asyncio.wait_for(websocket.recv(), timeout=remaining)
            if isinstance(raw, bytes):
                raw = raw.decode("utf-8")
            if raw == "pong":
                continue

            message = json.loads(raw)
            if message.get("event") == "error":
                pytest.fail(f"OKX WebSocket error: {message}")
            if message.get("arg", {}).get("channel") != "tickers":
                continue

            instrument_id = message["arg"].get("instId")
            if instrument_id not in requested or not message.get("data"):
                continue
            row = message["data"][0]
            assert row["instId"] == instrument_id
            assert float(row["last"]) > 0
            assert str(row["ts"]).isdigit()
            received.add(instrument_id)


def test_public_websocket_tickers_for_spot_and_swap() -> None:
    asyncio.run(_receive_public_tickers())
