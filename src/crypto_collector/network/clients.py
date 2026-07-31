from __future__ import annotations

import asyncio
import select
import socket
import ssl
from collections.abc import AsyncIterator, Awaitable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy
from ipaddress import ip_address
from types import TracebackType
from typing import Any, Generic, Self, TypeAlias, TypeVar
from urllib.parse import SplitResult, parse_qsl, unquote_to_bytes, urlsplit
from urllib.request import Request as UrllibRequest

import httpcore
import httpx
import websockets
from python_socks import ProxyError, ProxyType
from python_socks.async_.asyncio import Proxy
from websockets.asyncio.client import (
    ClientConnection,
)
from websockets.asyncio.client import (
    connect as WebSocketConnection,
)
from websockets.exceptions import InvalidURI
from websockets.exceptions import ProxyError as WebSocketProxyError
from websockets.uri import parse_uri

from crypto_collector.config.primitives import SecretSnapshot, SecretValue
from crypto_collector.network.models import (
    Egress,
    HttpClientSpec,
    WebSocketConnectSpec,
)
from crypto_collector.observability.redaction import (
    SENSITIVE_HEADER_NAMES,
    SENSITIVE_QUERY_NAMES,
    install_dependency_log_redaction,
)

_SENSITIVE_REQUEST_HEADERS = frozenset(
    name.encode("ascii") for name in SENSITIVE_HEADER_NAMES
) | {b"cookie"}


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
            "_ProxyEndpoint(endpoint='configured', "
            f"credentials={'configured' if self.username else None!r})"
        )


def _parse_proxy_endpoint(egress: Egress, plaintext: str) -> _ProxyEndpoint:
    endpoint = _try_parse_proxy_endpoint(egress, plaintext)
    if endpoint is None:
        plaintext = ""
        raise ValueError(f"invalid proxy URL for egress {egress.id!r}")
    return endpoint


def _try_urlsplit(value: str) -> SplitResult | None:
    try:
        return urlsplit(value)
    except (UnicodeError, ValueError):
        return None


def _has_unsafe_url_character(value: str) -> bool:
    return "\\" in value or any(
        character.isspace() or ord(character) < 0x20 or 0x7F <= ord(character) <= 0x9F
        for character in value
    )


def _decode_socks_credential(value: str | None) -> str | None:
    if value is None:
        return None
    index = 0
    while index < len(value):
        if value[index] == "%":
            escape = value[index + 1 : index + 3]
            if len(escape) != 2 or any(
                character not in "0123456789abcdefABCDEF" for character in escape
            ):
                return None
            index += 3
            continue
        if value[index] == "@":
            return None
        index += 1
    try:
        raw = unquote_to_bytes(value)
        decoded = raw.decode("ascii")
    except UnicodeError:
        return None
    if not 1 <= len(raw) <= 255:
        return None
    return decoded


def _try_parse_proxy_endpoint(egress: Egress, plaintext: str) -> _ProxyEndpoint | None:
    if _has_unsafe_url_character(plaintext) or "?" in plaintext or "#" in plaintext:
        return None
    parsed = _try_urlsplit(plaintext)
    if parsed is None:
        return None
    try:
        port = parsed.port
        host = parsed.hostname
        if host is not None:
            host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return None
    has_paired_credentials = (parsed.username is None) == (parsed.password is None)
    username = _decode_socks_credential(parsed.username)
    password = _decode_socks_credential(parsed.password)
    if (
        parsed.scheme != egress.type
        or host is None
        or "%" in host
        or port is None
        or not 1 <= port <= 65_535
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or not has_paired_credentials
        or (parsed.username is not None and username is None)
        or (parsed.password is not None and password is None)
    ):
        return None
    return _ProxyEndpoint(
        scheme=parsed.scheme,
        host=host,
        port=port,
        username=username,
        password=password,
    )


def _websocket_target_is_valid(uri: str) -> bool:
    if _has_unsafe_url_character(uri) or "#" in uri:
        return False
    parsed = _try_urlsplit(uri)
    if parsed is None:
        return False
    try:
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        return False
    if (
        parsed.scheme.casefold() not in {"ws", "wss"}
        or host is None
        or "%" in host
        or parsed.netloc.endswith(":")
        or (port is not None and not 1 <= port <= 65_535)
        or "@" in parsed.netloc
        or parsed.fragment
        or ("?" in uri and not parsed.query)
        or any(
            name.casefold() in SENSITIVE_QUERY_NAMES
            for name, _value in parse_qsl(parsed.query, keep_blank_values=True)
        )
    ):
        return False
    return _dependency_accepts_websocket_uri(uri)


def _dependency_accepts_websocket_uri(uri: str) -> bool:
    try:
        parse_uri(uri)
    except (InvalidURI, UnicodeError, ValueError):
        return False
    return True


def _mapped_httpcore_exception(error: Exception) -> httpx.HTTPError | None:
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
    for source, target in mappings:
        if isinstance(error, source):
            return target("SOCKS HTTP transport failed")
    return None


_CoreResult = TypeVar("_CoreResult")


@dataclass(frozen=True, slots=True)
class _CapturedCoreCall(Generic[_CoreResult]):
    value: _CoreResult | None = None
    error: httpx.HTTPError | None = None


async def _capture_core_call(
    awaitable: Awaitable[_CoreResult],
) -> _CapturedCoreCall[_CoreResult]:
    try:
        return _CapturedCoreCall(value=await awaitable)
    except Exception as error:
        mapped = _mapped_httpcore_exception(error)
        if mapped is None:
            raise
        return _CapturedCoreCall(error=mapped)


def _sensitive_header_names(
    headers: list[tuple[bytes, bytes]],
) -> set[str]:
    return {
        name.decode("ascii")
        for name, _value in headers
        if name.lower() in _SENSITIVE_REQUEST_HEADERS
    }


def _sanitize_sensitive_query(request: httpx.Request) -> bool:
    items = request.url.params.multi_items()
    if not any(name.casefold() in SENSITIVE_QUERY_NAMES for name, _value in items):
        return False
    request.url = request.url.copy_with(
        query=str(
            httpx.QueryParams(
                [
                    (
                        name,
                        "***" if name.casefold() in SENSITIVE_QUERY_NAMES else value,
                    )
                    for name, value in items
                ]
            )
        ).encode("ascii")
    )
    return True


def _validate_anonymous_request(request: httpx.Request) -> None:
    sensitive_names = _sensitive_header_names(request.headers.raw)
    has_sensitive_query = _sanitize_sensitive_query(request)
    has_userinfo = bool(request.url.userinfo)
    if has_userinfo:
        request.url = request.url.copy_with(username=None, password=None)
    has_fragment = "#" in str(request.url)
    if has_fragment:
        request.url = request.url.copy_with(fragment=None)
    for name in sensitive_names:
        request.headers[name] = "***"
    if sensitive_names or has_sensitive_query or has_userinfo:
        raise httpx.LocalProtocolError(
            "credentials are not permitted on anonymous market-data requests",
            request=request,
        )
    method = request.method
    if type(method) is not str or str.__eq__(method, "GET") is not True:
        request.method = "INVALID"
        raise httpx.LocalProtocolError(
            "anonymous market-data requests must use GET",
            request=request,
        )
    if (
        request.url.scheme.casefold() not in {"http", "https"}
        or not request.url.host
        or has_fragment
    ):
        raise httpx.LocalProtocolError(
            "anonymous market-data requests require an absolute HTTP(S) URL "
            "without a fragment",
            request=request,
        )


async def _validate_sensitive_request(request: httpx.Request) -> None:
    _validate_anonymous_request(request)


def _close_socket(sock: socket.socket) -> None:
    try:
        sock.close()
    except OSError:
        pass


class _ProxyTcpFailure(OSError):
    pass


class _ProxyNegotiationFailure(Exception):
    pass


class _ProxyDeadlineFailure(TimeoutError):
    pass


async def _open_proxy_tcp_socket(
    endpoint: _ProxyEndpoint,
    *,
    local_address: str | None,
) -> socket.socket:
    loop = asyncio.get_running_loop()
    try:
        literal_address = ip_address(endpoint.host)
    except ValueError:
        addresses = await loop.getaddrinfo(
            endpoint.host,
            endpoint.port,
            type=socket.SOCK_STREAM,
        )
    else:
        if literal_address.version == 4:
            addresses = [
                (
                    socket.AF_INET,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    (endpoint.host, endpoint.port),
                )
            ]
        else:
            addresses = [
                (
                    socket.AF_INET6,
                    socket.SOCK_STREAM,
                    0,
                    "",
                    (endpoint.host, endpoint.port, 0, 0),
                )
            ]
    last_error: OSError | None = None
    for family, sock_type, protocol, _canonical_name, address in addresses:
        candidate: socket.socket | None = None
        try:
            candidate = socket.socket(family, sock_type, protocol)
            candidate.setblocking(False)
            if local_address is not None:
                candidate.bind((local_address, 0))
            await loop.sock_connect(candidate, address)
            return candidate
        except OSError as error:
            last_error = error
            if candidate is not None:
                _close_socket(candidate)
        except BaseException:
            if candidate is not None:
                _close_socket(candidate)
            raise
    if last_error is not None:
        raise last_error
    raise OSError("proxy endpoint resolved to no TCP addresses")


async def _connect_via_proxy(
    endpoint: _ProxyEndpoint,
    *,
    destination_host: str,
    destination_port: int,
    timeout: float | None,
    local_address: str | None = None,
) -> socket.socket:
    sock: socket.socket | None = None
    failure: Exception | None = None
    control_failure: BaseException | None = None
    try:
        async with asyncio.timeout(timeout):
            sock = await _open_proxy_tcp_socket(
                endpoint,
                local_address=local_address,
            )
            connected = await endpoint.new_proxy()._connect(
                destination_host,
                destination_port,
                _socket=sock,
                local_addr=None,
            )
            if connected is not sock:
                _close_socket(sock)
            sock = None
            return connected
    except asyncio.CancelledError as error:
        if sock is not None:
            _close_socket(sock)
            sock = None
        error.__traceback__ = None
        error.__cause__ = None
        error.__context__ = None
        control_failure = error
    except TimeoutError:
        failure = _ProxyDeadlineFailure("SOCKS proxy connection timed out")
    except ProxyError:
        failure = _ProxyNegotiationFailure("SOCKS proxy negotiation failed")
    except OSError:
        failure = _ProxyTcpFailure("SOCKS proxy connection failed")
    except Exception:  # noqa: BLE001 - dependency failures must lose secret context
        failure = _ProxyNegotiationFailure("SOCKS proxy negotiation failed")
    finally:
        if sock is not None:
            _close_socket(sock)
            sock = None
    if control_failure is not None:
        raise control_failure
    assert failure is not None
    raise failure


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
        except asyncio.CancelledError:
            _close_socket(sock)
            raise
        except TimeoutError as error:
            _close_socket(sock)
            raise httpcore.ConnectTimeout from error
        except (OSError, ssl.SSLError) as error:
            _close_socket(sock)
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
        failure: (
            httpcore.ConnectTimeout | httpcore.ProxyError | httpcore.ConnectError | None
        ) = None
        try:
            sock = await _connect_via_proxy(
                self._endpoint,
                destination_host=host,
                destination_port=port,
                timeout=timeout,
                local_address=local_address,
            )
        except _ProxyDeadlineFailure:
            failure = httpcore.ConnectTimeout("SOCKS proxy connection timed out")
        except _ProxyNegotiationFailure:
            failure = httpcore.ProxyError("SOCKS proxy negotiation failed")
        except _ProxyTcpFailure:
            failure = httpcore.ConnectError("SOCKS proxy connection failed")
        if failure is not None:
            raise failure
        socket_option_failure: httpcore.ConnectError | None = None
        try:
            for option in socket_options or ():
                sock.setsockopt(*option)
        except OSError:
            _close_socket(sock)
            socket_option_failure = httpcore.ConnectError(
                "SOCKS socket option setup failed"
            )
        except (TypeError, ValueError):
            _close_socket(sock)
            raise
        if socket_option_failure is not None:
            raise socket_option_failure
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
        iterator = self._stream.__aiter__()
        while True:
            try:
                captured = await _capture_core_call(anext(iterator))
            except StopAsyncIteration:
                return
            if captured.error is not None:
                raise captured.error
            assert captured.value is not None
            yield captured.value

    async def aclose(self) -> None:
        captured = await _capture_core_call(self._stream.aclose())
        if captured.error is not None:
            raise captured.error


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
        _validate_anonymous_request(request)
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
        captured = await _capture_core_call(
            self._pool.handle_async_request(core_request)
        )
        if captured.error is not None:
            raise captured.error
        response = captured.value
        assert response is not None
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=_CoreResponseStream(response.stream),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()


class _ValidatedTransport(httpx.AsyncBaseTransport):
    def __init__(self, delegate: httpx.AsyncBaseTransport) -> None:
        self._delegate = delegate

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        _validate_anonymous_request(request)
        return await self._delegate.handle_async_request(request)

    async def aclose(self) -> None:
        await self._delegate.aclose()


@dataclass(frozen=True, slots=True)
class _PreparedAnonymousGet:
    request: httpx.Request
    rejected: bool


_QueryPrimitive: TypeAlias = str | int | float | bool | None
_PublicQueryParams: TypeAlias = (
    httpx.QueryParams
    | Mapping[str, _QueryPrimitive | Sequence[_QueryPrimitive]]
    | list[tuple[str, _QueryPrimitive]]
    | tuple[tuple[str, _QueryPrimitive], ...]
)
_TimeoutTuple: TypeAlias = tuple[
    float | None,
    float | None,
    float | None,
    float | None,
]
_PublicTimeout: TypeAlias = float | _TimeoutTuple | httpx.Timeout | None


class _UseConfiguredTimeout:
    __slots__ = ()

    def __repr__(self) -> str:
        return "USE_CONFIGURED_TIMEOUT"


_USE_CONFIGURED_TIMEOUT = _UseConfiguredTimeout()


class _RejectAllCookiePolicy(DefaultCookiePolicy):
    def set_ok(self, cookie: Cookie, request: UrllibRequest) -> bool:
        del cookie, request
        return False

    def return_ok(self, cookie: Cookie, request: UrllibRequest) -> bool:
        del cookie, request
        return False


def _prepare_anonymous_get(
    client: httpx.AsyncClient,
    url: str | httpx.URL,
    *,
    params: _PublicQueryParams | None,
    timeout: _PublicTimeout | _UseConfiguredTimeout,
) -> _PreparedAnonymousGet:
    try:
        if isinstance(timeout, _UseConfiguredTimeout):
            request = client.build_request("GET", url, params=params)
        else:
            request = client.build_request(
                "GET",
                url,
                params=params,
                timeout=timeout,
            )
    except Exception:  # noqa: BLE001 - raw invalid input must not escape in a traceback
        return _PreparedAnonymousGet(
            request=httpx.Request("GET", "https://invalid.invalid/"),
            rejected=True,
        )

    try:
        _validate_anonymous_request(request)
    except httpx.LocalProtocolError:
        return _PreparedAnonymousGet(request=request, rejected=True)
    return _PreparedAnonymousGet(request=request, rejected=False)


class _AnonymousHttpClient:
    __slots__ = ("__client",)

    def __init__(self, client: httpx.AsyncClient) -> None:
        client.cookies = CookieJar(policy=_RejectAllCookiePolicy())
        self.__client = client

    @property
    def is_closed(self) -> bool:
        return self.__client.is_closed

    @property
    def timeout(self) -> httpx.Timeout:
        return self.__client.timeout

    @timeout.setter
    def timeout(self, value: _PublicTimeout) -> None:
        self.__client.timeout = value

    def get(
        self,
        url: str | httpx.URL,
        *,
        params: _PublicQueryParams | None = None,
        timeout: _PublicTimeout | _UseConfiguredTimeout = _USE_CONFIGURED_TIMEOUT,
    ) -> Coroutine[Any, Any, httpx.Response]:
        prepared = _prepare_anonymous_get(
            self.__client,
            url,
            params=params,
            timeout=timeout,
        )
        del url, params, timeout
        if prepared.rejected:
            raise httpx.LocalProtocolError(
                "anonymous market-data request rejected",
                request=prepared.request,
            ) from None
        return self.__client.send(
            prepared.request,
            auth=None,
            follow_redirects=False,
        )

    async def aclose(self) -> None:
        await self.__client.aclose()


def build_http_client_spec(
    egress: Egress, *, secrets: SecretSnapshot
) -> HttpClientSpec:
    return HttpClientSpec(
        proxy=_proxy_for(egress, secrets),
        trust_env=False,
        max_connections=egress.max_http_concurrency,
        max_keepalive_connections=min(20, egress.max_http_concurrency),
    )


def build_websocket_connect_spec(
    egress: Egress,
    uri: str,
    *,
    secrets: SecretSnapshot,
) -> WebSocketConnectSpec:
    return WebSocketConnectSpec(uri=uri, proxy=_proxy_for(egress, secrets))


class WebSocketClientFactory:
    __slots__ = ("_egress_id", "_endpoint", "_ssl_context")

    def __init__(
        self,
        egress_id: str,
        endpoint: _ProxyEndpoint | None,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        self._egress_id = egress_id
        self._endpoint = endpoint
        self._ssl_context = ssl_context

    def connect(self, uri: str) -> _OneShotWebSocketConnection:
        if not _websocket_target_is_valid(uri):
            uri = ""
            raise ValueError("invalid WebSocket URI")
        spec = WebSocketConnectSpec(uri=uri, proxy=None)
        if self._endpoint is not None:
            return _ProxyWebSocketConnection(
                spec=spec,
                endpoint=self._endpoint,
                ssl_context=self._ssl_context,
            )
        tls_options: dict[str, Any] = {}
        if self._ssl_context is not None and spec.uri.casefold().startswith("wss://"):
            tls_options["ssl"] = self._ssl_context
        return _DirectWebSocketConnection(
            websockets.connect(
                spec.uri,
                proxy=None,
                open_timeout=spec.open_timeout,
                close_timeout=spec.close_timeout,
                max_queue=spec.max_queue,
                **tls_options,
            )
        )

    def __repr__(self) -> str:
        return f"WebSocketClientFactory(egress_id={self._egress_id!r})"


class _OneShotWebSocketConnection:
    __slots__ = ("_connection", "_used")

    def __init__(self) -> None:
        self._connection: ClientConnection | None = None
        self._used = False

    async def _connect_once(self) -> ClientConnection:
        raise NotImplementedError

    async def _open(self) -> ClientConnection:
        if self._used:
            raise RuntimeError("WebSocket connection handles are one-shot")
        self._used = True
        connection = await self._connect_once()
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
        connection = self._connection
        self._connection = None
        if connection is not None:
            await connection.close()


class _DirectWebSocketConnection(_OneShotWebSocketConnection):
    __slots__ = ("_delegate",)

    def __init__(self, delegate: WebSocketConnection) -> None:
        super().__init__()
        self._delegate = delegate

    async def _connect_once(self) -> ClientConnection:
        return await self._delegate

    def __repr__(self) -> str:
        return "_DirectWebSocketConnection()"


class _ProxyWebSocketConnection(_OneShotWebSocketConnection):
    __slots__ = ("_endpoint", "_spec", "_ssl_context")

    def __init__(
        self,
        *,
        spec: WebSocketConnectSpec,
        endpoint: _ProxyEndpoint,
        ssl_context: ssl.SSLContext | None,
    ) -> None:
        super().__init__()
        self._spec = spec
        self._endpoint = endpoint
        self._ssl_context = ssl_context

    async def _connect_once(self) -> ClientConnection:
        websocket_uri = parse_uri(self._spec.uri)
        sock: socket.socket | None = None
        proxy_failed = False
        timeout_failed = False
        failure: OSError | None = None
        connection: ClientConnection | None = None
        try:
            async with asyncio.timeout(self._spec.open_timeout):
                sock = await _connect_via_proxy(
                    self._endpoint,
                    destination_host=websocket_uri.host,
                    destination_port=websocket_uri.port,
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
        except _ProxyNegotiationFailure:
            proxy_failed = True
        except _ProxyTcpFailure:
            failure = OSError("SOCKS proxy connection failed")
        except TimeoutError:
            timeout_failed = True
        except BaseException:
            del websocket_uri
            raise
        finally:
            if sock is not None:
                _close_socket(sock)
        del websocket_uri
        if timeout_failed:
            raise TimeoutError("WebSocket connection timed out")
        if proxy_failed:
            raise WebSocketProxyError("failed to connect to SOCKS proxy")
        if failure is not None:
            raise failure
        if connection is None:
            raise RuntimeError("WebSocket connection did not initialize")
        return connection

    def __repr__(self) -> str:
        return "_ProxyWebSocketConnection(proxy='configured')"


class NetworkClients:
    __slots__ = ("_egress_id", "http", "websocket")

    def __init__(
        self,
        *,
        http: _AnonymousHttpClient,
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
    install_dependency_log_redaction()
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
    base_transport: httpx.AsyncBaseTransport = (
        _SocksTransport(
            endpoint=endpoint,
            limits=limits,
            ssl_context=verify,
        )
        if endpoint is not None
        else httpx.AsyncHTTPTransport(
            verify=verify,
            trust_env=False,
            limits=limits,
        )
    )
    transport = _ValidatedTransport(base_transport)
    http = _AnonymousHttpClient(
        httpx.AsyncClient(
            proxy=None,
            transport=transport,
            trust_env=spec.trust_env,
            timeout=timeout,
            follow_redirects=False,
            event_hooks={"request": [_validate_sensitive_request]},
        )
    )
    return NetworkClients(
        http=http,
        websocket=WebSocketClientFactory(egress.id, endpoint, verify),
        egress_id=egress.id,
    )
