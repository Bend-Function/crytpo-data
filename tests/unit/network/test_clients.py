from __future__ import annotations

import asyncio
import socket
import ssl
import traceback
import warnings
from collections.abc import Coroutine, Iterator
from typing import Any

import httpcore
import httpx
import pytest
import websockets
from python_socks.async_.asyncio import Proxy

import crypto_collector.network.clients as clients_module
from crypto_collector.config import SecretRef, SecretSnapshot
from crypto_collector.network.clients import (
    _AsyncioSocketStream,
    _CoreResponseStream,
    _ProxyEndpoint,
    _ProxyWebSocketConnection,
    _SocksNetworkBackend,
    build_clients,
    build_http_client_spec,
    build_websocket_connect_spec,
)
from crypto_collector.network.models import Egress, WebSocketConnectSpec


def direct_egress() -> Egress:
    return Egress.model_validate({"id": "direct", "type": "direct"})


def test_direct_http_client_ignores_host_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://unexpected.invalid:8080")

    spec = build_http_client_spec(direct_egress(), secrets=SecretSnapshot.empty())

    assert spec.trust_env is False
    assert spec.proxy is None


def test_http_client_limits_follow_egress_concurrency() -> None:
    egress = Egress.model_validate(
        {"id": "direct", "type": "direct", "max_http_concurrency": 3}
    )

    spec = build_http_client_spec(egress, secrets=SecretSnapshot.empty())

    assert spec.max_connections == 3
    assert spec.max_keepalive_connections == 3


def test_direct_websocket_disables_auto_proxy_detection() -> None:
    spec = build_websocket_connect_spec(
        direct_egress(),
        "wss://example.test/ws",
        secrets=SecretSnapshot.empty(),
    )

    assert spec.proxy is None


def test_websocket_spec_repr_redacts_uri_credentials() -> None:
    spec = build_websocket_connect_spec(
        direct_egress(),
        "wss://user:password@example.test/ws?token=secret-token",
        secrets=SecretSnapshot.empty(),
    )

    assert "password" not in repr(spec)
    assert "secret-token" not in repr(spec)


def test_socks5h_resolves_proxy_reference_only_from_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:password@127.0.0.1:1080")
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.resolve_all([reference])

    spec = build_http_client_spec(egress, secrets=secrets)
    websocket_spec = build_websocket_connect_spec(
        egress,
        "wss://example.test/ws",
        secrets=secrets,
    )

    assert spec.proxy is not None
    assert spec.proxy.reveal().startswith("socks5h://")
    assert "password" not in repr(spec)
    assert "password" not in repr(websocket_spec)


def test_builder_never_resolves_a_secret_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values(
        {reference: "socks5h://user:password@127.0.0.1:1080"}
    )
    monkeypatch.setattr(
        SecretRef,
        "_resolve_once",
        lambda _self: pytest.fail("builder attempted secret resolution"),
    )

    build_http_client_spec(egress, secrets=secrets)
    build_websocket_connect_spec(
        egress,
        "wss://example.test/ws",
        secrets=secrets,
    )


@pytest.mark.parametrize(
    "proxy_url",
    [
        "socks5h://user:password@127.0.0.1:not-a-port",
        "socks5h://user:password@127.0.0.1:0",
        "http://user:password@127.0.0.1:1080",
        "socks5h://user:password@127.0.0.1:1080/path",
        "socks5h://user:password@exa mple:1080",
        "socks5h://user:password@example\\host:1080",
        "socks5h://user:password@127.0.0.1:1080?",
        "socks5h://user:password@127.0.0.1:1080#",
        "socks5h://user:password@127.0.0.1:1080/\u0080",
        "socks5h://user:password@%0Aproxy.invalid:1080",
    ],
)
def test_invalid_proxy_secret_is_rejected_without_disclosure(proxy_url: str) -> None:
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values({reference: proxy_url})

    with pytest.raises(ValueError, match="invalid proxy URL") as captured:
        build_clients(egress, secrets=secrets)

    assert "password" not in str(captured.value)
    assert proxy_url not in str(captured.value)


def test_invalid_proxy_exception_chain_does_not_disclose_secret() -> None:
    proxy_url = "socks5h://user:password\uff20proxy.invalid:1080"
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values({reference: proxy_url})

    with pytest.raises(ValueError, match="invalid proxy URL") as captured:
        build_clients(egress, secrets=secrets)

    diagnostic = "".join(
        traceback.format_exception(captured.type, captured.value, captured.tb)
    )
    assert "password" not in diagnostic
    assert proxy_url not in diagnostic


def test_invalid_proxy_traceback_locals_do_not_retain_plaintext() -> None:
    canary = "traceback-local-secret"
    proxy_url = f"socks5h://user:{canary}\uff20proxy.invalid:1080"
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values({reference: proxy_url})

    with pytest.raises(ValueError, match="invalid proxy URL") as captured:
        build_clients(egress, secrets=secrets)

    traceback_with_locals = traceback.TracebackException(
        captured.type,
        captured.value,
        captured.tb,
        capture_locals=True,
    )
    collector_frames = "\n".join(
        repr(frame.locals or {})
        for frame in traceback_with_locals.stack
        if frame.filename.endswith("crypto_collector/network/clients.py")
    )
    assert canary not in collector_frames
    assert proxy_url not in collector_frames


def _exception_graph(error: BaseException) -> Iterator[BaseException]:
    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        yield current
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)


def _non_test_traceback_locals(error: BaseException) -> str:
    frames: list[str] = []
    for item in _exception_graph(error):
        traceback_with_locals = traceback.TracebackException(
            type(item),
            item,
            item.__traceback__,
            capture_locals=True,
        )
        frames.extend(
            repr(frame.locals or {})
            for frame in traceback_with_locals.stack
            if not frame.name.startswith("test_")
        )
    return "\n".join(frames)


def test_invalid_proxy_exception_object_graph_does_not_disclose_secret() -> None:
    proxy_url = "socks5h://user:object-graph-secret＠proxy.invalid:1080"
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values({reference: proxy_url})

    with pytest.raises(ValueError, match="invalid proxy URL") as captured:
        build_clients(egress, secrets=secrets)

    diagnostics = "\n".join(
        repr(item.args) for item in _exception_graph(captured.value)
    )
    assert "object-graph-secret" not in diagnostics
    assert proxy_url not in diagnostics


@pytest.mark.parametrize(
    "userinfo",
    [
        ":password",
        "user:",
        "%C3%A4:password",
        "%FF:password",
        "%GG:password",
        f"{'u' * 256}:password",
        f"user:{'p' * 256}",
    ],
)
def test_invalid_socks_credentials_are_rejected_before_connect(
    userinfo: str,
) -> None:
    proxy_url = f"socks5h://{userinfo}@127.0.0.1:1080"
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values({reference: proxy_url})

    with pytest.raises(ValueError, match="invalid proxy URL") as captured:
        build_clients(egress, secrets=secrets)

    diagnostics = "\n".join(
        repr(item.args) for item in _exception_graph(captured.value)
    )
    assert userinfo not in diagnostics
    assert proxy_url not in diagnostics


@pytest.mark.asyncio
async def test_proxy_url_accepts_equivalent_trailing_slash() -> None:
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values(
        {reference: "socks5h://user:password@127.0.0.1:1080/"}
    )

    clients = build_clients(egress, secrets=secrets)
    await clients.aclose()


@pytest.mark.parametrize(
    ("uri", "secret"),
    [
        (
            "wss://user:target-secret@example.test/ws?token=query-secret",
            "target-secret",
        ),
        ("wss://exa mple/ws", None),
        ("wss://example\\host/ws", None),
        ("wss://example.test/ws#", None),
        ("wss://example.test/ws\u0080", None),
        ("wss://%0Aexample.test/ws", None),
    ],
)
def test_invalid_websocket_target_uri_is_rejected_before_dependency_boundary(
    uri: str,
    secret: str | None,
) -> None:
    clients = build_clients(direct_egress(), secrets=SecretSnapshot.empty())

    with pytest.raises(ValueError, match="invalid WebSocket URI") as captured:
        clients.websocket.connect(uri)

    diagnostics = "\n".join(
        repr(item.args) for item in _exception_graph(captured.value)
    )
    if secret is not None:
        assert secret not in diagnostics
        assert "query-secret" not in diagnostics
        traceback_with_locals = traceback.TracebackException(
            captured.type,
            captured.value,
            captured.tb,
            capture_locals=True,
        )
        collector_frames = "\n".join(
            repr(frame.locals or {})
            for frame in traceback_with_locals.stack
            if frame.filename.endswith("crypto_collector/network/clients.py")
        )
        assert secret not in collector_frames
        assert "query-secret" not in collector_frames


@pytest.mark.asyncio
async def test_socks_transport_ignores_host_ca_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SSL_CERT_FILE", "/definitely/missing/collector-ca.pem")
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values(
        {reference: "socks5://user:password@127.0.0.1:1080"}
    )

    clients = build_clients(egress, secrets=secrets)
    await clients.aclose()


class _FailingCoreStream:
    def __aiter__(self) -> _FailingCoreStream:
        return self

    async def __anext__(self) -> bytes:
        raise httpcore.ReadTimeout("core read timed out")

    async def aclose(self) -> None:
        raise httpcore.ReadError("core close failed")


@pytest.mark.asyncio
async def test_response_stream_maps_httpcore_errors_after_headers() -> None:
    stream = _CoreResponseStream(_FailingCoreStream())

    with pytest.raises(httpx.ReadTimeout) as read_error:
        await anext(stream.__aiter__())
    with pytest.raises(httpx.ReadError) as close_error:
        await stream.aclose()

    for error in (read_error.value, close_error.value):
        diagnostics = "\n".join(repr(item.args) for item in _exception_graph(error))
        assert "core read timed out" not in diagnostics
        assert "core close failed" not in diagnostics


@pytest.mark.asyncio
async def test_none_http_connect_timeout_is_not_replaced_by_proxy_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, int, object, object]] = []
    sock = _CloseTrackingSocket()

    async def return_plain_socket(*args, **kwargs):
        del args, kwargs
        return sock

    async def fail_public_connect(self, *args, **kwargs):
        del self, args, kwargs
        pytest.fail("collector delegated timeout=None to Proxy.connect default")

    async def fail_connect(
        self,
        destination_host,
        destination_port,
        *,
        _socket,
        local_addr,
    ):
        del self
        observed.append((destination_host, destination_port, _socket, local_addr))
        raise OSError("unreachable")

    monkeypatch.setattr(clients_module, "_open_proxy_tcp_socket", return_plain_socket)
    monkeypatch.setattr(Proxy, "connect", fail_public_connect)
    monkeypatch.setattr(Proxy, "_connect", fail_connect)
    backend = _SocksNetworkBackend(
        endpoint=_ProxyEndpoint("socks5h", "proxy.invalid", 1080, None, None)
    )

    with pytest.raises(httpcore.ConnectError):
        await backend.connect_tcp("venue.invalid", 443, timeout=None)

    assert observed == [("venue.invalid", 443, sock, None)]


class _CloseTrackingSocket:
    def __init__(
        self,
        *,
        socket_option_error: Exception | None = None,
        close_error: Exception | None = None,
    ) -> None:
        self.closed = False
        self.close_attempted = False
        self.socket_option_error = socket_option_error
        self.close_error = close_error

    def close(self) -> None:
        self.close_attempted = True
        if self.close_error is not None:
            raise self.close_error
        self.closed = True

    def setsockopt(self, *args) -> None:
        del args
        if self.socket_option_error is not None:
            raise self.socket_option_error

    def setblocking(self, flag: bool) -> None:
        del flag

    def bind(self, address) -> None:
        del address


@pytest.mark.parametrize("client_kind", ["http", "websocket"])
@pytest.mark.asyncio
async def test_proxy_tcp_cancellation_closes_new_socket(
    monkeypatch: pytest.MonkeyPatch,
    client_kind: str,
) -> None:
    sock = _CloseTrackingSocket()
    cancelled = asyncio.CancelledError("proxy TCP connect cancelled")
    loop = asyncio.get_running_loop()

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: sock)

    async def cancel_connect(sock, address) -> None:
        del sock, address
        raise cancelled

    monkeypatch.setattr(loop, "sock_connect", cancel_connect)
    endpoint = _ProxyEndpoint("socks5h", "127.0.0.1", 1080, None, None)

    with pytest.raises(asyncio.CancelledError) as captured:
        if client_kind == "http":
            await _SocksNetworkBackend(endpoint=endpoint).connect_tcp(
                "venue.invalid", 443
            )
        else:
            connection = _ProxyWebSocketConnection(
                spec=WebSocketConnectSpec(
                    uri="ws://venue.invalid/ws",
                    proxy=None,
                    open_timeout=10,
                ),
                endpoint=endpoint,
                ssl_context=None,
            )
            await connection._connect_once()

    assert captured.value is cancelled
    assert sock.closed


@pytest.mark.parametrize("client_kind", ["http", "websocket"])
@pytest.mark.asyncio
async def test_proxy_tcp_timeout_closes_new_socket(
    monkeypatch: pytest.MonkeyPatch,
    client_kind: str,
) -> None:
    sock = _CloseTrackingSocket()
    loop = asyncio.get_running_loop()
    never_connected = asyncio.Event()

    monkeypatch.setattr(socket, "socket", lambda *args, **kwargs: sock)

    async def block_connect(sock, address) -> None:
        del sock, address
        await never_connected.wait()

    monkeypatch.setattr(loop, "sock_connect", block_connect)
    endpoint = _ProxyEndpoint("socks5h", "127.0.0.1", 1080, None, None)

    operation: Coroutine[Any, Any, Any]
    if client_kind == "http":
        expected_error: type[BaseException] = httpcore.ConnectTimeout
        operation = _SocksNetworkBackend(endpoint=endpoint).connect_tcp(
            "venue.invalid", 443, timeout=0.001
        )
    else:
        expected_error = TimeoutError
        connection = _ProxyWebSocketConnection(
            spec=WebSocketConnectSpec(
                uri="ws://venue.invalid/ws",
                proxy=None,
                open_timeout=0.001,
            ),
            endpoint=endpoint,
            ssl_context=None,
        )
        operation = connection._connect_once()

    with pytest.raises(expected_error):
        await operation

    assert sock.closed


@pytest.mark.asyncio
async def test_proxy_handshake_does_not_suppress_concurrent_warnings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sock = _CloseTrackingSocket()
    handshake_started = asyncio.Event()
    release_handshake = asyncio.Event()

    async def return_plain_socket(*args, **kwargs):
        del args, kwargs
        return sock

    async def block_handshake(self, *args, **kwargs):
        del self, args, kwargs
        handshake_started.set()
        await release_handshake.wait()
        return sock

    monkeypatch.setattr(
        clients_module,
        "_open_proxy_tcp_socket",
        return_plain_socket,
    )
    monkeypatch.setattr(Proxy, "_connect", block_handshake)
    endpoint = _ProxyEndpoint("socks5h", "127.0.0.1", 1080, None, None)

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        connecting = asyncio.create_task(
            clients_module._connect_via_proxy(
                endpoint,
                destination_host="venue.invalid",
                destination_port=443,
                timeout=10,
            )
        )
        await handshake_started.wait()
        warnings.warn("concurrent warning remains visible", DeprecationWarning)
        release_handshake.set()
        assert await connecting is sock

    assert any(
        str(item.message) == "concurrent warning remains visible" for item in captured
    )


@pytest.mark.parametrize("client_kind", ["http", "websocket"])
@pytest.mark.asyncio
async def test_proxy_auth_cancellation_does_not_retain_credentials(
    monkeypatch: pytest.MonkeyPatch,
    client_kind: str,
) -> None:
    canary = "cancelled-auth-secret"
    endpoint_canary = "PROXY_HOST_CANARY.invalid"
    sock = _CloseTrackingSocket()
    auth_started = asyncio.Event()
    never_authenticated = asyncio.Event()

    async def return_plain_socket(*args, **kwargs):
        del args, kwargs
        return sock

    async def stall_auth(self, *args, **kwargs):
        del self, args, kwargs
        auth_request = {"username": canary, "password": canary}
        auth_started.set()
        await never_authenticated.wait()
        pytest.fail(f"unexpected auth completion: {auth_request!r}")

    monkeypatch.setattr(
        clients_module,
        "_open_proxy_tcp_socket",
        return_plain_socket,
    )
    monkeypatch.setattr(Proxy, "_connect", stall_auth)
    endpoint = _ProxyEndpoint("socks5h", endpoint_canary, 1080, "user", canary)
    operation: Coroutine[Any, Any, Any]
    if client_kind == "http":
        operation = _SocksNetworkBackend(endpoint=endpoint).connect_tcp(
            "venue.invalid",
            443,
        )
    else:
        operation = _ProxyWebSocketConnection(
            spec=WebSocketConnectSpec(
                uri="ws://venue.invalid/ws",
                proxy=None,
                open_timeout=10,
            ),
            endpoint=endpoint,
            ssl_context=None,
        )._connect_once()
    task = asyncio.create_task(operation)
    await auth_started.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError) as captured:
        await task

    traceback_locals = _non_test_traceback_locals(captured.value)
    assert canary not in traceback_locals
    assert endpoint_canary not in traceback_locals
    assert sock.close_attempted


@pytest.mark.asyncio
async def test_websocket_proxy_auth_timeout_discards_cancelled_secret_chain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "timeout-auth-secret"
    sock = _CloseTrackingSocket()
    never_authenticated = asyncio.Event()

    async def return_plain_socket(*args, **kwargs):
        del args, kwargs
        return sock

    async def stall_auth(self, *args, **kwargs):
        del self, args, kwargs
        auth_request = {"username": canary, "password": canary}
        await never_authenticated.wait()
        pytest.fail(f"unexpected auth completion: {auth_request!r}")

    monkeypatch.setattr(
        clients_module,
        "_open_proxy_tcp_socket",
        return_plain_socket,
    )
    monkeypatch.setattr(Proxy, "_connect", stall_auth)
    connection = _ProxyWebSocketConnection(
        spec=WebSocketConnectSpec(
            uri="ws://venue.invalid/ws",
            proxy=None,
            open_timeout=0.001,
        ),
        endpoint=_ProxyEndpoint(
            "socks5h",
            "127.0.0.1",
            1080,
            "user",
            canary,
        ),
        ssl_context=None,
    )

    with pytest.raises(TimeoutError) as captured:
        await connection._connect_once()

    assert canary not in _non_test_traceback_locals(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None
    assert sock.close_attempted


@pytest.mark.asyncio
async def test_tls_cancellation_closes_transferred_plain_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sock = _CloseTrackingSocket()

    async def cancel_open_connection(**kwargs):
        del kwargs
        raise asyncio.CancelledError

    monkeypatch.setattr(asyncio, "open_connection", cancel_open_connection)
    stream = _AsyncioSocketStream(sock=sock)  # type: ignore[arg-type]

    with pytest.raises(asyncio.CancelledError):
        await stream.start_tls(ssl.create_default_context())

    assert sock.closed


@pytest.mark.asyncio
async def test_socket_option_failure_closes_proxy_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sock = _CloseTrackingSocket(socket_option_error=OSError("socket option failed"))

    async def return_socket(*args, **kwargs):
        del args, kwargs
        return sock

    monkeypatch.setattr(clients_module, "_connect_via_proxy", return_socket)
    backend = _SocksNetworkBackend(
        endpoint=_ProxyEndpoint("socks5h", "proxy.invalid", 1080, None, None)
    )

    with pytest.raises(httpcore.ConnectError) as captured:
        await backend.connect_tcp(
            "venue.invalid",
            443,
            socket_options=[(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)],
        )

    assert sock.closed
    diagnostics = "\n".join(
        repr(item.args) for item in _exception_graph(captured.value)
    )
    assert "socket option failed" not in diagnostics


@pytest.mark.asyncio
async def test_tls_cancellation_survives_socket_close_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancelled = asyncio.CancelledError("TLS startup cancelled")
    sock = _CloseTrackingSocket(close_error=OSError("close failed"))

    async def cancel_open_connection(**kwargs):
        del kwargs
        raise cancelled

    monkeypatch.setattr(asyncio, "open_connection", cancel_open_connection)
    stream = _AsyncioSocketStream(sock=sock)  # type: ignore[arg-type]

    with pytest.raises(asyncio.CancelledError) as captured:
        await stream.start_tls(ssl.create_default_context())

    assert captured.value is cancelled
    assert sock.close_attempted


@pytest.mark.parametrize("error_type", [TypeError, ValueError])
@pytest.mark.asyncio
async def test_socket_option_failure_survives_socket_close_failure(
    monkeypatch: pytest.MonkeyPatch,
    error_type: type[Exception],
) -> None:
    option_error = error_type("socket option failed")
    sock = _CloseTrackingSocket(
        socket_option_error=option_error,
        close_error=OSError("close failed"),
    )

    async def return_socket(*args, **kwargs):
        del args, kwargs
        return sock

    monkeypatch.setattr(clients_module, "_connect_via_proxy", return_socket)
    backend = _SocksNetworkBackend(
        endpoint=_ProxyEndpoint("socks5h", "proxy.invalid", 1080, None, None)
    )

    with pytest.raises(error_type) as captured:
        await backend.connect_tcp(
            "venue.invalid",
            443,
            socket_options=[(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)],
        )

    assert captured.value is option_error
    assert sock.close_attempted


@pytest.mark.asyncio
async def test_final_transport_validates_after_late_request_hook() -> None:
    canary = "late-hook-secret"
    delegate_called = False

    async def delegate(_request: httpx.Request) -> httpx.Response:
        nonlocal delegate_called
        delegate_called = True
        return httpx.Response(200)

    async def add_invalid_header(request: httpx.Request) -> None:
        request.headers["Authorization"] = f"Bearer {canary}\n"

    transport = clients_module._ValidatedTransport(httpx.MockTransport(delegate))
    async with httpx.AsyncClient(
        transport=transport,
        event_hooks={"request": [add_invalid_header]},
    ) as client:
        with pytest.raises(httpx.LocalProtocolError) as captured:
            await client.get("https://venue.invalid/catalog")

    assert not delegate_called
    assert captured.value.request.headers["Authorization"] == "***"
    diagnostics = "\n".join(
        repr(item.args) for item in _exception_graph(captured.value)
    )
    assert canary not in diagnostics
    traceback_with_locals = traceback.TracebackException(
        captured.type,
        captured.value,
        captured.tb,
        capture_locals=True,
    )
    collector_frames = "\n".join(
        repr(frame.locals or {})
        for frame in traceback_with_locals.stack
        if frame.filename.endswith("crypto_collector/network/clients.py")
    )
    assert canary not in collector_frames


@pytest.mark.asyncio
async def test_proxy_endpoint_is_parsed_once_and_shared_with_websocket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = SecretRef.parse("env:SOCKS_URL")
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )
    secrets = SecretSnapshot.from_test_values(
        {reference: "socks5h://user:password@127.0.0.1:1080"}
    )
    parse_endpoint = clients_module._parse_proxy_endpoint
    parsed: list[_ProxyEndpoint] = []

    def count_parse(egress: Egress, plaintext: str) -> _ProxyEndpoint:
        endpoint = parse_endpoint(egress, plaintext)
        parsed.append(endpoint)
        return endpoint

    monkeypatch.setattr(clients_module, "_parse_proxy_endpoint", count_parse)

    clients = build_clients(egress, secrets=secrets)
    clients.websocket.connect("wss://venue.invalid/ws")
    await clients.aclose()

    assert len(parsed) == 1


@pytest.mark.asyncio
async def test_websocket_proxy_tcp_error_does_not_disclose_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canary = "proxy-endpoint-secret.invalid"
    endpoint = _ProxyEndpoint("socks5h", canary, 1080, None, None)

    async def fail_open(*args, **kwargs):
        del args, kwargs
        raise OSError(f"cannot connect to {canary}:1080")

    monkeypatch.setattr(clients_module, "_open_proxy_tcp_socket", fail_open)
    connection = _ProxyWebSocketConnection(
        spec=WebSocketConnectSpec(
            uri="ws://venue.invalid/ws?token=ws-query-secret",
            proxy=None,
            open_timeout=10,
        ),
        endpoint=endpoint,
        ssl_context=None,
    )

    with pytest.raises(OSError, match="SOCKS proxy connection failed") as captured:
        await connection._connect_once()

    diagnostics = "\n".join(
        repr(item.args) for item in _exception_graph(captured.value)
    )
    assert canary not in diagnostics
    traceback_with_locals = traceback.TracebackException(
        captured.type,
        captured.value,
        captured.tb,
        capture_locals=True,
    )
    collector_frames = "\n".join(
        repr(frame.locals or {})
        for frame in traceback_with_locals.stack
        if frame.filename.endswith("crypto_collector/network/clients.py")
    )
    assert canary not in collector_frames
    assert "ws-query-secret" not in collector_frames


@pytest.mark.asyncio
async def test_websocket_cleanup_failure_does_not_replace_cancellation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cancelled = asyncio.CancelledError("WebSocket handshake cancelled")
    sock = _CloseTrackingSocket(close_error=OSError("close failed"))

    async def return_socket(*args, **kwargs):
        del args, kwargs
        return sock

    async def cancel_websocket_connect(*args, **kwargs):
        del args, kwargs
        raise cancelled

    monkeypatch.setattr(clients_module, "_connect_via_proxy", return_socket)
    monkeypatch.setattr(websockets, "connect", cancel_websocket_connect)
    connection = _ProxyWebSocketConnection(
        spec=WebSocketConnectSpec(
            uri="ws://venue.invalid/ws",
            proxy=None,
            open_timeout=10,
        ),
        endpoint=_ProxyEndpoint("socks5h", "127.0.0.1", 1080, None, None),
        ssl_context=None,
    )

    with pytest.raises(asyncio.CancelledError) as captured:
        await connection._connect_once()

    assert captured.value is cancelled
    assert sock.close_attempted
