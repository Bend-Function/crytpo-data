from __future__ import annotations

import asyncio
import contextlib
import select
import socket
import ssl
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self
from urllib.parse import unquote, urlsplit

import httpcore
import httpx
import websockets
from python_socks import ProxyError, ProxyTimeoutError, ProxyType
from python_socks.async_.asyncio import Proxy
from websockets.asyncio.client import (
    ClientConnection,
)
from websockets.asyncio.client import (
    connect as WebSocketConnection,
)
from websockets.exceptions import ProxyError as WebSocketProxyError
from websockets.uri import parse_uri

from crypto_collector.config.primitives import SecretSnapshot, SecretValue
from crypto_collector.network.models import (
    Egress,
    HttpClientSpec,
    WebSocketConnectSpec,
)


def _proxy_for(egress: Egress, secrets: SecretSnapshot) -> SecretValue | None:
    if egress.type == "direct":
        return None
    if egress.url is None:
        raise ValueError(f"{egress.type} egress requires a proxy secret reference")
    return secrets.value_for(egress.url)


@dataclass(frozen=True, slots=True, repr=False)
class _ProxyEndpoint:
    scheme: str
    host: str
    port: int
    username: str | None
    password: str | None

    @property
    def remote_dns(self) -> bool:
        return self.scheme == "socks5h"

    def new_proxy(self) -> Proxy:
        return Proxy(
            ProxyType.SOCKS5,
            self.host,
            self.port,
            self.username,
            self.password,
            self.remote_dns,
        )

    def __repr__(self) -> str:
        return (
            f"_ProxyEndpoint(scheme={self.scheme!r}, host={self.host!r}, "
            f"port={self.port!r}, credentials={'configured' if self.username else None!r})"
        )


def _parse_proxy_endpoint(egress: Egress, plaintext: str) -> _ProxyEndpoint:
    try:
        parsed = urlsplit(plaintext)
        port = parsed.port
        host = parsed.hostname
        if host is not None:
            host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        raise ValueError(f"invalid proxy URL for egress {egress.id!r}") from None
    has_paired_credentials = (parsed.username is None) == (parsed.password is None)
    if (
        parsed.scheme != egress.type
        or host is None
        or port is None
        or not 1 <= port <= 65_535
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not has_paired_credentials
    ):
        raise ValueError(f"invalid proxy URL for egress {egress.id!r}")
    return _ProxyEndpoint(
        scheme=parsed.scheme,
        host=host,
        port=port,
        username=None if parsed.username is None else unquote(parsed.username),
        password=None if parsed.password is None else unquote(parsed.password),
    )


@contextlib.contextmanager
def _map_httpcore_exceptions() -> Iterator[None]:
    mappings: tuple[tuple[type[Exception], type[httpx.HTTPError]], ...] = (
        (httpcore.ConnectTimeout, httpx.ConnectTimeout),
        (httpcore.ReadTimeout, httpx.ReadTimeout),
        (httpcore.WriteTimeout, httpx.WriteTimeout),
        (httpcore.PoolTimeout, httpx.PoolTimeout),
        (httpcore.ConnectError, httpx.ConnectError),
        (httpcore.ReadError, httpx.ReadError),
        (httpcore.WriteError, httpx.WriteError),
        (httpcore.ProxyError, httpx.ProxyError),
        (httpcore.UnsupportedProtocol, httpx.UnsupportedProtocol),
        (httpcore.LocalProtocolError, httpx.LocalProtocolError),
        (httpcore.RemoteProtocolError, httpx.RemoteProtocolError),
        (httpcore.ProtocolError, httpx.ProtocolError),
        (httpcore.NetworkError, httpx.NetworkError),
        (httpcore.TimeoutException, httpx.TimeoutException),
    )
    try:
        yield
    except Exception as error:
        for source, target in mappings:
            if isinstance(error, source):
                raise target(str(error)) from error
        raise


class _AsyncioSocketStream(httpcore.AsyncNetworkStream):
    def __init__(
        self,
        *,
        sock: socket.socket | None = None,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
    ) -> None:
        self._socket = sock
        self._reader = reader
        self._writer = writer

    async def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        try:
            if self._reader is not None:
                return await asyncio.wait_for(self._reader.read(max_bytes), timeout)
            if self._socket is None:
                return b""
            return await asyncio.wait_for(
                asyncio.get_running_loop().sock_recv(self._socket, max_bytes),
                timeout,
            )
        except TimeoutError as error:
            raise httpcore.ReadTimeout from error
        except OSError as error:
            raise httpcore.ReadError from error

    async def write(self, buffer: bytes, timeout: float | None = None) -> None:
        if not buffer:
            return
        try:
            if self._writer is not None:
                self._writer.write(buffer)
                await asyncio.wait_for(self._writer.drain(), timeout)
                return
            if self._socket is None:
                raise OSError("network stream is closed")
            await asyncio.wait_for(
                asyncio.get_running_loop().sock_sendall(self._socket, buffer),
                timeout,
            )
        except TimeoutError as error:
            raise httpcore.WriteTimeout from error
        except OSError as error:
            raise httpcore.WriteError from error

    async def aclose(self) -> None:
        if self._writer is not None:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except (ConnectionError, OSError):
                pass
            self._writer = None
            self._reader = None
        if self._socket is not None:
            self._socket.close()
            self._socket = None

    async def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if self._socket is None or self._writer is not None:
            raise httpcore.ConnectError("network stream cannot start TLS")
        sock = self._socket
        self._socket = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    sock=sock,
                    ssl=ssl_context,
                    server_hostname=server_hostname,
                ),
                timeout,
            )
        except TimeoutError as error:
            sock.close()
            raise httpcore.ConnectTimeout from error
        except (OSError, ssl.SSLError) as error:
            sock.close()
            raise httpcore.ConnectError from error
        return _AsyncioSocketStream(reader=reader, writer=writer)

    def get_extra_info(self, info: str) -> Any:
        if self._writer is not None:
            if info == "client_addr":
                return self._writer.get_extra_info("sockname")
            if info == "server_addr":
                return self._writer.get_extra_info("peername")
            if info == "socket":
                return self._writer.get_extra_info("socket")
            if info == "ssl_object":
                return self._writer.get_extra_info("ssl_object")
        elif self._socket is not None:
            if info == "client_addr":
                return self._socket.getsockname()
            if info == "server_addr":
                return self._socket.getpeername()
            if info == "socket":
                return self._socket
        if info == "is_readable":
            sock = self.get_extra_info("socket")
            if sock is None:
                return True
            try:
                readable, _, _ = select.select([sock], [], [], 0)
            except (OSError, ValueError):
                return True
            return bool(readable)
        return None


class _SocksNetworkBackend(httpcore.AsyncNetworkBackend):
    def __init__(
        self,
        *,
        endpoint: _ProxyEndpoint,
    ) -> None:
        self._endpoint = endpoint

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        proxy = self._endpoint.new_proxy()
        try:
            sock = await proxy.connect(
                dest_host=host,
                dest_port=port,
                timeout=timeout,
                local_addr=None if local_address is None else (local_address, 0),
            )
        except ProxyTimeoutError as error:
            raise httpcore.ConnectTimeout("SOCKS proxy connection timed out") from error
        except (ProxyError, OSError) as error:
            raise httpcore.ConnectError("SOCKS proxy connection failed") from error
        for option in socket_options or ():
            sock.setsockopt(*option)
        return _AsyncioSocketStream(sock=sock)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Any = None,
    ) -> httpcore.AsyncNetworkStream:
        del path, timeout, socket_options
        raise httpcore.ConnectError("SOCKS transport does not support Unix sockets")

    async def sleep(self, seconds: float) -> None:
        await asyncio.sleep(seconds)


class _CoreResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream: Any) -> None:
        self._stream = stream

    async def __aiter__(self) -> AsyncIterator[bytes]:
        async for part in self._stream:
            yield part

    async def aclose(self) -> None:
        await self._stream.aclose()


class _SocksTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        *,
        endpoint: _ProxyEndpoint,
        limits: httpx.Limits,
        ssl_context: ssl.SSLContext,
    ) -> None:
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            network_backend=_SocksNetworkBackend(
                endpoint=endpoint,
            ),
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with _map_httpcore_exceptions():
            response = await self._pool.handle_async_request(core_request)
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_CoreResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


def build_http_client_spec(
    egress: Egress, *, secrets: SecretSnapshot
) -> HttpClientSpec:
    return HttpClientSpec(proxy=_proxy_for(egress, secrets), trust_env=False)


def build_websocket_connect_spec(
    egress: Egress,
    uri: str,
    *,
    secrets: SecretSnapshot,
) -> WebSocketConnectSpec:
    return WebSocketConnectSpec(uri=uri, proxy=_proxy_for(egress, secrets))


class WebSocketClientFactory:
    __slots__ = ("_egress", "_secrets", "_ssl_context")

    def __init__(
        self,
        egress: Egress,
        secrets: SecretSnapshot,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        self._egress = egress
        self._secrets = secrets
        self._ssl_context = ssl_context

    def connect(self, uri: str) -> WebSocketConnection | _ProxyWebSocketConnection:
        spec = build_websocket_connect_spec(
            self._egress,
            uri,
            secrets=self._secrets,
        )
        endpoint = (
            None
            if spec.proxy is None
            else _parse_proxy_endpoint(self._egress, spec.proxy.reveal())
        )
        if endpoint is not None:
            return _ProxyWebSocketConnection(
                spec=spec,
                endpoint=endpoint,
                ssl_context=self._ssl_context,
            )
        tls_options: dict[str, Any] = {}
        if self._ssl_context is not None and spec.uri.casefold().startswith("wss://"):
            tls_options["ssl"] = self._ssl_context
        return websockets.connect(
            spec.uri,
            proxy=None,
            open_timeout=spec.open_timeout,
            close_timeout=spec.close_timeout,
            max_queue=spec.max_queue,
            **tls_options,
        )

    def __repr__(self) -> str:
        return f"WebSocketClientFactory(egress_id={self._egress.id!r})"


class _ProxyWebSocketConnection:
    __slots__ = ("_connection", "_endpoint", "_spec", "_ssl_context")

    def __init__(
        self,
        *,
        spec: WebSocketConnectSpec,
        endpoint: _ProxyEndpoint,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        self._spec = spec
        self._endpoint = endpoint
        self._ssl_context = ssl_context
        self._connection: ClientConnection | None = None

    async def _open(self) -> ClientConnection:
        if self._connection is not None:
            return self._connection
        websocket_uri = parse_uri(self._spec.uri)
        sock: socket.socket | None = None
        try:
            async with asyncio.timeout(self._spec.open_timeout):
                sock = await self._endpoint.new_proxy().connect(
                    websocket_uri.host,
                    websocket_uri.port,
                    timeout=None,
                )
                tls_options: dict[str, Any] = {}
                if self._ssl_context is not None and websocket_uri.secure:
                    tls_options["ssl"] = self._ssl_context
                connection = await websockets.connect(
                    self._spec.uri,
                    proxy=None,
                    sock=sock,
                    open_timeout=None,
                    close_timeout=self._spec.close_timeout,
                    max_queue=self._spec.max_queue,
                    **tls_options,
                )
                sock = None
        except ProxyError:
            raise WebSocketProxyError("failed to connect to SOCKS proxy") from None
        finally:
            if sock is not None:
                sock.close()
        self._connection = connection
        return connection

    def __await__(self) -> Any:
        return self._open().__await__()

    async def __aenter__(self) -> ClientConnection:
        return await self._open()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        if self._connection is not None:
            await self._connection.close()

    def __repr__(self) -> str:
        return "_ProxyWebSocketConnection(proxy='configured')"


class NetworkClients:
    __slots__ = ("_egress_id", "http", "websocket")

    def __init__(
        self,
        *,
        http: httpx.AsyncClient,
        websocket: WebSocketClientFactory,
        egress_id: str,
    ) -> None:
        self.http = http
        self.websocket = websocket
        self._egress_id = egress_id

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        await self.aclose()

    async def aclose(self) -> None:
        await self.http.aclose()

    def __repr__(self) -> str:
        return f"NetworkClients(egress_id={self._egress_id!r})"


def build_clients(
    egress: Egress,
    *,
    secrets: SecretSnapshot,
    ssl_context: ssl.SSLContext | None = None,
) -> NetworkClients:
    spec = build_http_client_spec(egress, secrets=secrets)
    endpoint = (
        None
        if spec.proxy is None
        else _parse_proxy_endpoint(egress, spec.proxy.reveal())
    )
    timeout = httpx.Timeout(spec.timeout_seconds)
    limits = httpx.Limits(
        max_connections=spec.max_connections,
        max_keepalive_connections=spec.max_keepalive_connections,
    )
    verify = httpx.create_ssl_context(
        verify=True if ssl_context is None else ssl_context,
        trust_env=False,
    )
    transport = (
        _SocksTransport(
            endpoint=endpoint,
            limits=limits,
            ssl_context=verify,
        )
        if endpoint is not None
        else None
    )
    http = httpx.AsyncClient(
        proxy=None,
        transport=transport,
        trust_env=spec.trust_env,
        timeout=timeout,
        limits=limits,
        verify=verify,
        follow_redirects=False,
    )
    return NetworkClients(
        http=http,
        websocket=WebSocketClientFactory(egress, secrets, verify),
        egress_id=egress.id,
    )
