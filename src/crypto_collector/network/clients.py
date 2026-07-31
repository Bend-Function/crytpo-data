from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from types import TracebackType
from typing import Any, Self
from urllib.parse import urlsplit

import httpx
import websockets
from websockets.asyncio.client import connect as WebSocketConnection

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


def _validated_proxy_url(egress: Egress, plaintext: str) -> str:
    try:
        parsed = urlsplit(plaintext)
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"invalid proxy URL for egress {egress.id!r}") from error
    has_paired_credentials = (parsed.username is None) == (parsed.password is None)
    if (
        parsed.scheme != egress.type
        or parsed.hostname is None
        or port is None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not has_paired_credentials
    ):
        raise ValueError(f"invalid proxy URL for egress {egress.id!r}")
    return plaintext


class _LocalDnsSocksTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        *,
        proxy: str,
        limits: httpx.Limits,
        verify: bool | ssl.SSLContext,
    ) -> None:
        self._transport = httpx.AsyncHTTPTransport(
            proxy=proxy,
            limits=limits,
            verify=verify,
        )

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        host = request.url.host
        try:
            ipaddress.ip_address(host)
            resolved_host = host
        except ValueError:
            addresses = await asyncio.get_running_loop().getaddrinfo(
                host,
                request.url.port,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            if not addresses:
                raise OSError(f"could not resolve proxy target: {host}")
            resolved_host = str(addresses[0][4][0])

        extensions = dict(request.extensions)
        extensions["sni_hostname"] = host
        proxied_request = httpx.Request(
            method=request.method,
            url=request.url.copy_with(host=resolved_host),
            headers=request.headers,
            stream=request.stream,
            extensions=extensions,
        )
        return await self._transport.handle_async_request(proxied_request)

    async def aclose(self) -> None:
        await self._transport.aclose()


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

    def connect(self, uri: str) -> WebSocketConnection:
        spec = build_websocket_connect_spec(
            self._egress,
            uri,
            secrets=self._secrets,
        )
        proxy = (
            None
            if spec.proxy is None
            else _validated_proxy_url(self._egress, spec.proxy.reveal())
        )
        tls_options: dict[str, Any] = {}
        if self._ssl_context is not None and spec.uri.casefold().startswith("wss://"):
            tls_options["ssl"] = self._ssl_context
        return websockets.connect(
            spec.uri,
            proxy=proxy,
            open_timeout=spec.open_timeout,
            close_timeout=spec.close_timeout,
            max_queue=spec.max_queue,
            **tls_options,
        )

    def __repr__(self) -> str:
        return f"WebSocketClientFactory(egress_id={self._egress.id!r})"


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
    proxy = (
        None
        if spec.proxy is None
        else _validated_proxy_url(egress, spec.proxy.reveal())
    )
    timeout = httpx.Timeout(spec.timeout_seconds)
    limits = httpx.Limits(
        max_connections=spec.max_connections,
        max_keepalive_connections=spec.max_keepalive_connections,
    )
    verify: bool | ssl.SSLContext = True if ssl_context is None else ssl_context
    transport = (
        _LocalDnsSocksTransport(proxy=proxy, limits=limits, verify=verify)
        if egress.type == "socks5" and proxy is not None
        else None
    )
    http = httpx.AsyncClient(
        proxy=proxy if transport is None else None,
        transport=transport,
        trust_env=spec.trust_env,
        timeout=timeout,
        limits=limits,
        verify=verify,
        follow_redirects=False,
    )
    return NetworkClients(
        http=http,
        websocket=WebSocketClientFactory(egress, secrets, ssl_context),
        egress_id=egress.id,
    )
