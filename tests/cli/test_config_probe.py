from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from collections import deque
from collections.abc import Mapping
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import httpx
from typer.testing import CliRunner

from crypto_collector.cli import app
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.exchanges.contracts import PublicQueryValue

_OKX_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "exchanges" / "okx"
_PUBLIC_TIME = {
    "code": "0",
    "msg": "",
    "data": [{"ts": "1800000000123"}],
}
_SPOT_TICKERS = {
    "code": "0",
    "msg": "",
    "data": [
        {
            "instType": "SPOT",
            "instId": "BTC-USDT",
            "last": "100000",
            "vol24h": "2.5",
            "volCcy24h": "250000.00000001",
            "ts": "1800000000123",
        },
        {
            "instType": "SPOT",
            "instId": "NEW-USDT",
            "last": "",
            "vol24h": "0",
            "volCcy24h": "",
            "ts": "1800000000123",
        },
    ],
}


class _ScriptedHttp:
    def __init__(self) -> None:
        self.urls: list[str] = []

    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, PublicQueryValue] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        del timeout
        self.urls.append(url)
        path = httpx.URL(url).path
        normalized = {} if params is None else dict(params)
        if path == "/api/v5/public/time":
            payload: Any = _PUBLIC_TIME
        elif path == "/api/v5/public/instruments":
            assert normalized == {"instType": "SPOT"}
            payload = decode_json(
                (_OKX_FIXTURES / "instruments-spot.json").read_bytes()
            )
        elif path == "/api/v5/market/tickers":
            assert normalized == {"instType": "SPOT"}
            payload = _SPOT_TICKERS
        else:  # pragma: no cover - unexpected probe expansion must be explicit.
            raise AssertionError(f"unexpected OKX probe path: {path}")
        return httpx.Response(200, content=encode_json(payload))


class _FailingHttp:
    async def get(
        self,
        url: str,
        *,
        params: Mapping[str, PublicQueryValue] | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        del url, params, timeout
        raise OSError("socks5h://probe-user:probe-secret@127.0.0.1:1080")


class _ScriptedWebSocketConnection:
    def __init__(self, connection_id: str, *, mismatch_ack: bool = False) -> None:
        self.connection_id = connection_id
        self.mismatch_ack = mismatch_ack
        self.frames: deque[str] = deque()
        self.closed = False
        self._blocked = asyncio.Event()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self.closed = True

    async def send(self, message: str) -> None:
        payload = json.loads(message)
        for argument in payload["args"]:
            acknowledged = dict(argument)
            if self.mismatch_ack:
                acknowledged["instId"] = "MISMATCH-USDT"
            self.frames.append(
                json.dumps(
                    {
                        "id": payload["id"],
                        "event": "subscribe",
                        "arg": acknowledged,
                        "connId": self.connection_id,
                    }
                )
            )
            if argument["channel"] == "books":
                self.frames.append(
                    json.dumps(
                        {
                            "arg": argument,
                            "action": "snapshot",
                            "data": [{"asks": [], "bids": [], "ts": "1"}],
                        }
                    )
                )

    async def recv(self) -> str:
        if self.frames:
            return self.frames.popleft()
        await self._blocked.wait()
        raise AssertionError("unreachable WebSocket wake")


class _ScriptedWebSocket:
    def __init__(self, *, mismatch_ack: bool = False) -> None:
        self.mismatch_ack = mismatch_ack
        self.uris: list[str] = []
        self.connections: list[_ScriptedWebSocketConnection] = []

    def connect(self, uri: str) -> _ScriptedWebSocketConnection:
        self.uris.append(uri)
        connection = _ScriptedWebSocketConnection(
            f"cli-probe-{len(self.connections) + 1}",
            mismatch_ack=self.mismatch_ack,
        )
        self.connections.append(connection)
        return connection


class _ScriptedClients:
    def __init__(
        self,
        http: _ScriptedHttp | _FailingHttp | None = None,
        websocket: _ScriptedWebSocket | None = None,
    ) -> None:
        self.http = _ScriptedHttp() if http is None else http
        self.websocket = _ScriptedWebSocket() if websocket is None else websocket
        self.closed = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        del args
        self.closed = True


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _unregistered_exchange_config(tmp_path: Path) -> Path:
    _write(
        tmp_path / "config.yaml",
        """\
data_root: ./data
state_root: ./state
exchanges:
  binance:
    markets:
      spot: {}
""",
    )
    return tmp_path


def test_config_probe_reports_enabled_unregistered_provider_and_writes_no_roots(
    tmp_path: Path,
) -> None:
    config_tree = _unregistered_exchange_config(tmp_path)

    result = CliRunner().invoke(
        app,
        ["config", "probe", str(config_tree), "--json"],
    )

    assert result.exit_code == 1, result.output
    body = json.loads(result.stdout)
    assert body["success"] is False
    assert body["observed_at_ns"] > 0
    assert body["exchanges"] == {}
    assert body["failures"] == [
        {
            "code": "provider_unavailable",
            "exchange": "binance",
            "feature_id": None,
            "market": None,
            "message": "no probe provider is registered",
        }
    ]
    assert not (config_tree / "data").exists()
    assert not (config_tree / "state").exists()


def test_config_probe_text_reports_failure_without_creating_roots(
    tmp_path: Path,
) -> None:
    config_tree = _unregistered_exchange_config(tmp_path)

    result = CliRunner().invoke(app, ["config", "probe", str(config_tree)])

    assert result.exit_code == 1, result.output
    assert "Configuration probe failed" in result.stdout
    assert "binance/provider_unavailable" in result.stdout
    assert not (config_tree / "data").exists()
    assert not (config_tree / "state").exists()


def test_config_probe_uses_okx_provider_closes_clients_and_writes_no_roots(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write(
        tmp_path / "config.yaml",
        """\
data_root: ./data
state_root: ./state
selection:
  fixed_pairs: [BTC/USDT]
  top_n: 1
exchanges:
  okx:
    endpoints:
      rest: http://127.0.0.1:8080
    markets:
      spot: {}
""",
    )
    _write(
        tmp_path / "config" / "network.yaml",
        """\
egress_pool:
  - id: direct
    type: direct
  - id: socks
    type: socks5h
    quota_group: proxy-nat
    url: env:SOCKS_URL
""",
    )
    proxy_secret = "socks5h://probe-user:probe-secret@127.0.0.1:1080"
    monkeypatch.setenv("SOCKS_URL", proxy_secret)
    clients: list[_ScriptedClients] = []
    secret_snapshots: list[object] = []

    def build_scripted_clients(*args: object, **kwargs: object) -> _ScriptedClients:
        assert args
        secret_snapshots.append(kwargs["secrets"])
        client = _ScriptedClients()
        clients.append(client)
        return client

    monkeypatch.setattr(
        "crypto_collector.network.build_clients",
        build_scripted_clients,
    )

    result = CliRunner().invoke(
        app,
        ["config", "probe", str(tmp_path), "--json"],
    )

    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["success"] is True
    exchange = body["exchanges"]["okx"]
    assert exchange["public_time"]["exchange_time_ns"] == 1_800_000_000_123_000_000
    assert [
        (item["egress_id"], item["reachable"]) for item in exchange["egresses"]
    ] == [("direct", True), ("socks", True)]
    assert {item["quota_group"] for item in exchange["endpoint_budgets"]} == {
        "direct",
        "proxy-nat",
    }
    market = exchange["markets"]["spot"]
    assert market["fixed"]["instrument_keys"] == ["BTC-USDT"]
    assert set(market["selection"]["entries"]) == {"BTC-USDT"}
    assert set(market["selection"]["entries"]["BTC-USDT"]["reasons"]) == {
        "fixed",
        "top_n",
    }
    assert market["shards"][0]["quota_group"] in {"direct", "proxy-nat"}
    assert market["intervals"]["books-full"] == {
        "effective_ns": 30_000_000_000,
        "requested_ns": 30_000_000_000,
        "warning": None,
    }
    assert market["intervals"]["candles"]["effective_ns"] == 60_000_000_000
    assert market["intervals"]["instruments"]["effective_ns"] == 300_000_000_000
    assert len(clients) == 2 and all(client.closed for client in clients)
    assert all(
        connection.closed
        for client in clients
        for connection in client.websocket.connections
    )
    assert len({id(snapshot) for snapshot in secret_snapshots}) == 1
    assert all(
        url.startswith("http://127.0.0.1:8080/")
        for client in clients
        for url in client.http.urls
    )
    assert proxy_secret not in result.stdout
    assert "probe-secret" not in result.stdout
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "state").exists()


def test_config_probe_http_success_ws_failure_isolated_and_writes_no_roots(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write(
        tmp_path / "config.yaml",
        """\
data_root: ./data
state_root: ./state
exchanges:
  okx:
    endpoints:
      rest: http://127.0.0.1:8080
    markets:
      spot: {}
""",
    )
    client = _ScriptedClients(
        websocket=_ScriptedWebSocket(mismatch_ack=True),
    )
    monkeypatch.setattr(
        "crypto_collector.network.build_clients",
        lambda *args, **kwargs: client,
    )

    result = CliRunner().invoke(
        app,
        ["config", "probe", str(tmp_path), "--json"],
    )

    assert result.exit_code == 1, result.output
    body = json.loads(result.stdout)
    egress = body["exchanges"]["okx"]["egresses"][0]
    assert egress["reachable"] is False
    assert [
        (item["transport"], item["endpoint_role"], item["reachable"])
        for item in egress["transports"]
    ] == [
        ("http", "public_rest", True),
        ("websocket", "business", False),
        ("websocket", "public", False),
    ]
    assert {
        item["quota_group"] for item in body["exchanges"]["okx"]["endpoint_budgets"]
    } == {"direct"}
    assert [(item["market"], item["code"]) for item in body["failures"]] == [
        (None, "websocket_unavailable")
    ]
    assert client.closed
    assert all(connection.closed for connection in client.websocket.connections)
    assert "MISMATCH-USDT" not in result.stdout
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "state").exists()


def test_config_probe_sanitizes_provider_failure_and_closes_client(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write(
        tmp_path / "config.yaml",
        """\
data_root: ./data
state_root: ./state
exchanges:
  okx:
    markets:
      spot: {}
""",
    )
    client = _ScriptedClients(_FailingHttp())
    monkeypatch.setattr(
        "crypto_collector.network.build_clients",
        lambda *args, **kwargs: client,
    )

    result = CliRunner().invoke(
        app,
        ["config", "probe", str(tmp_path), "--json"],
    )

    assert result.exit_code == 1, result.output
    body = json.loads(result.stdout)
    assert [
        (item["exchange"], item["code"], item["message"]) for item in body["failures"]
    ] == [("okx", "provider_error", "provider probe failed")]
    assert client.closed
    assert "probe-secret" not in result.stdout
    assert "socks5h://" not in result.stdout
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "state").exists()


def test_config_probe_runtime_setup_error_is_exit_one_and_sanitized(
    tmp_path: Path,
    monkeypatch,
) -> None:
    _write(
        tmp_path / "config.yaml",
        """\
data_root: ./data
state_root: ./state
exchanges:
  okx:
    markets:
      spot: {}
""",
    )

    def fail_client_setup(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("socks5h://probe-user:probe-secret@127.0.0.1:1080")

    monkeypatch.setattr("crypto_collector.network.build_clients", fail_client_setup)

    result = CliRunner().invoke(app, ["config", "probe", str(tmp_path)])

    assert result.exit_code == 1, result.output
    assert result.stdout.strip() == (
        "Configuration probe failed: runtime setup or cleanup failed"
    )
    assert "Invalid configuration" not in result.stdout
    assert "probe-secret" not in result.stdout
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "state").exists()


def test_config_probe_without_collector_dependencies_has_actionable_error(
    tmp_path: Path,
) -> None:
    config_tree = _unregistered_exchange_config(tmp_path)
    source_root = Path(__file__).resolve().parents[2] / "src"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(source_root)
    script = """
import json
import sys

class BlockCollectorDependencies:
    def find_spec(self, fullname, path=None, target=None):
        del path, target
        if fullname.split('.')[0] in {
            'httpcore', 'httpx', 'python_socks', 'websockets'
        }:
            raise ModuleNotFoundError('blocked collector dependency')
        return None

sys.meta_path.insert(0, BlockCollectorDependencies())
from typer.testing import CliRunner
from crypto_collector.cli import app

result = CliRunner().invoke(app, ['config', 'probe', sys.argv[1], '--json'])
print(json.dumps({'exit_code': result.exit_code, 'output': result.stdout}))
"""

    completed = subprocess.run(
        [sys.executable, "-c", script, str(config_tree)],
        check=True,
        capture_output=True,
        env=environment,
        text=True,
    )

    outcome = json.loads(completed.stdout)
    assert outcome == {
        "exit_code": 1,
        "output": (
            "Configuration probe unavailable: install the collector role dependencies\n"
        ),
    }
    assert not (config_tree / "data").exists()
    assert not (config_tree / "state").exists()
