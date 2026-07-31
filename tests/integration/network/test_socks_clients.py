from __future__ import annotations

import socket
import time
from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio

from crypto_collector.config import SecretRef, SecretSnapshot
from crypto_collector.network.clients import build_clients
from crypto_collector.network.models import Egress
from tests.support.socks5_server import (
    LoopbackApps,
    LoopbackSocks5Server,
    TlsContexts,
    create_test_tls_contexts,
)


@pytest.fixture
def tls_contexts(tmp_path) -> TlsContexts:
    return create_test_tls_contexts(tmp_path)


@pytest_asyncio.fixture
async def loopback_apps(tls_contexts: TlsContexts) -> AsyncIterator[LoopbackApps]:
    apps = await LoopbackApps.start(server_ssl=tls_contexts.server)
    try:
        yield apps
    finally:
        await apps.close()


@pytest_asyncio.fixture
async def loopback_socks5(
    loopback_apps: LoopbackApps,
) -> AsyncIterator[LoopbackSocks5Server]:
    proxy = await LoopbackSocks5Server.start(
        destinations={
            ("venue.invalid", loopback_apps.http_port): (
                "127.0.0.1",
                loopback_apps.http_port,
            ),
            ("venue.invalid", loopback_apps.websocket_port): (
                "127.0.0.1",
                loopback_apps.websocket_port,
            ),
            ("venue.invalid", loopback_apps.https_port): (
                "127.0.0.1",
                loopback_apps.https_port,
            ),
            ("venue.invalid", loopback_apps.secure_websocket_port): (
                "127.0.0.1",
                loopback_apps.secure_websocket_port,
            ),
            ("127.0.0.1", loopback_apps.http_port): (
                "127.0.0.1",
                loopback_apps.http_port,
            ),
            ("::1", loopback_apps.http_port): (
                "127.0.0.1",
                loopback_apps.http_port,
            ),
            ("127.0.0.1", loopback_apps.https_port): (
                "127.0.0.1",
                loopback_apps.https_port,
            ),
            ("::1", loopback_apps.https_port): (
                "127.0.0.1",
                loopback_apps.https_port,
            ),
        }
    )
    try:
        yield proxy
    finally:
        await proxy.close()


@pytest.mark.network
@pytest.mark.asyncio
async def test_socks5h_http_and_websocket_delegate_dns_to_proxy(
    loopback_socks5: LoopbackSocks5Server,
    loopback_apps: LoopbackApps,
) -> None:
    reference = SecretRef.parse("env:SOCKS_URL")
    secrets = SecretSnapshot.from_test_values(
        {reference: loopback_socks5.url(credentials=("u", "secret"))}
    )
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )

    async with build_clients(egress, secrets=secrets) as clients:
        response = await clients.http.get(loopback_apps.proxied_http_url)
        assert response.status_code == 200
        async with clients.websocket.connect(
            loopback_apps.proxied_websocket_url
        ) as websocket:
            assert await websocket.recv() == "ready"

        assert loopback_socks5.requested_domains == [
            "venue.invalid",
            "venue.invalid",
        ]
        assert "secret" not in repr(clients)
        assert "secret" not in " ".join(loopback_socks5.redacted_logs)


@pytest.mark.network
@pytest.mark.asyncio
async def test_direct_clients_ignore_host_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
    loopback_apps: LoopbackApps,
) -> None:
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.setenv(name, "socks5h://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    direct = Egress.model_validate({"id": "direct", "type": "direct"})

    async with build_clients(direct, secrets=SecretSnapshot.empty()) as clients:
        response = await clients.http.get(loopback_apps.http_url)
        assert response.status_code == 200
        async with clients.websocket.connect(loopback_apps.websocket_url) as websocket:
            assert await websocket.recv() == "ready"

    assert clients.http.is_closed


@pytest.mark.network
@pytest.mark.asyncio
async def test_socks5_resolves_target_name_locally(
    loopback_socks5: LoopbackSocks5Server,
    loopback_apps: LoopbackApps,
) -> None:
    reference = SecretRef.parse("env:SOCKS_URL")
    secrets = SecretSnapshot.from_test_values(
        {
            reference: loopback_socks5.url(
                scheme="socks5",
                credentials=("u", "secret"),
            )
        }
    )
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5", "url": reference}
    )

    async with build_clients(egress, secrets=secrets) as clients:
        response = await clients.http.get(
            f"http://localhost:{loopback_apps.http_port}/catalog"
        )

    assert response.status_code == 200
    assert loopback_socks5.requested_domains == []


@pytest.mark.network
@pytest.mark.asyncio
async def test_socks5h_tunnels_verified_https_and_websocket_tls(
    loopback_socks5: LoopbackSocks5Server,
    loopback_apps: LoopbackApps,
    tls_contexts: TlsContexts,
) -> None:
    reference = SecretRef.parse("env:SOCKS_URL")
    secrets = SecretSnapshot.from_test_values(
        {reference: loopback_socks5.url(credentials=("u", "secret"))}
    )
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5h", "url": reference}
    )

    async with build_clients(
        egress,
        secrets=secrets,
        ssl_context=tls_contexts.client,
    ) as clients:
        response = await clients.http.get(loopback_apps.proxied_https_url)
        assert response.status_code == 200
        async with clients.websocket.connect(
            loopback_apps.proxied_secure_websocket_url
        ) as websocket:
            assert await websocket.recv() == "ready"

    assert loopback_socks5.requested_domains == [
        "venue.invalid",
        "venue.invalid",
    ]


@pytest.mark.network
@pytest.mark.asyncio
async def test_socks5_local_dns_does_not_reuse_tls_across_logical_hosts(
    monkeypatch: pytest.MonkeyPatch,
    loopback_socks5: LoopbackSocks5Server,
    loopback_apps: LoopbackApps,
    tls_contexts: TlsContexts,
) -> None:
    original_getaddrinfo = socket.getaddrinfo

    def resolve_test_hosts(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        if host in {"venue.invalid", "wrong.invalid"}:
            host = "127.0.0.1"
        return original_getaddrinfo(host, port, family, type, proto, flags)

    monkeypatch.setattr(socket, "getaddrinfo", resolve_test_hosts)
    reference = SecretRef.parse("env:SOCKS_URL")
    secrets = SecretSnapshot.from_test_values(
        {
            reference: loopback_socks5.url(
                scheme="socks5",
                credentials=("u", "secret"),
            )
        }
    )
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5", "url": reference}
    )

    async with build_clients(
        egress,
        secrets=secrets,
        ssl_context=tls_contexts.client,
    ) as clients:
        valid = await clients.http.get(loopback_apps.proxied_https_url)
        assert valid.status_code == 200
        with pytest.raises(httpx.ConnectError):
            await clients.http.get(
                f"https://wrong.invalid:{loopback_apps.https_port}/catalog"
            )

    assert loopback_apps.https_hosts == [f"venue.invalid:{loopback_apps.https_port}"]


@pytest.mark.network
@pytest.mark.asyncio
async def test_percent_encoded_proxy_credentials_match_for_http_and_websocket(
    caplog: pytest.LogCaptureFixture,
    loopback_apps: LoopbackApps,
) -> None:
    caplog.set_level("DEBUG")
    proxy = await LoopbackSocks5Server.start(
        username="user",
        password="p@ss/word",
        destinations={
            ("venue.invalid", loopback_apps.http_port): (
                "127.0.0.1",
                loopback_apps.http_port,
            ),
            ("venue.invalid", loopback_apps.websocket_port): (
                "127.0.0.1",
                loopback_apps.websocket_port,
            ),
        },
    )
    try:
        reference = SecretRef.parse("env:SOCKS_URL")
        secrets = SecretSnapshot.from_test_values(
            {
                reference: proxy.url(
                    credentials=("user", "p%40ss%2Fword"),
                )
            }
        )
        egress = Egress.model_validate(
            {"id": "socks-1", "type": "socks5h", "url": reference}
        )

        async with build_clients(egress, secrets=secrets) as clients:
            response = await clients.http.get(loopback_apps.proxied_http_url)
            assert response.status_code == 200
            async with clients.websocket.connect(
                loopback_apps.proxied_websocket_url
            ) as websocket:
                assert await websocket.recv() == "ready"
    finally:
        await proxy.close()

    assert "p@ss/word" not in caplog.text
    assert "p%40ss%2Fword" not in caplog.text


@pytest.mark.network
@pytest.mark.asyncio
async def test_socks5_local_dns_obeys_http_connect_timeout(
    monkeypatch: pytest.MonkeyPatch,
    loopback_socks5: LoopbackSocks5Server,
    loopback_apps: LoopbackApps,
) -> None:
    original_getaddrinfo = socket.getaddrinfo

    def slow_test_dns(
        host: str,
        port: int,
        family: int = 0,
        type: int = 0,
        proto: int = 0,
        flags: int = 0,
    ) -> list[tuple[int, int, int, str, tuple[str, int]]]:
        if host == "slow.invalid":
            time.sleep(0.1)
            host = "127.0.0.1"
        return original_getaddrinfo(host, port, family, type, proto, flags)

    monkeypatch.setattr(socket, "getaddrinfo", slow_test_dns)
    reference = SecretRef.parse("env:SOCKS_URL")
    secrets = SecretSnapshot.from_test_values(
        {
            reference: loopback_socks5.url(
                scheme="socks5",
                credentials=("u", "secret"),
            )
        }
    )
    egress = Egress.model_validate(
        {"id": "socks-1", "type": "socks5", "url": reference}
    )

    async with build_clients(egress, secrets=secrets) as clients:
        clients.http.timeout = httpx.Timeout(0.01)
        with pytest.raises(httpx.ConnectTimeout):
            await clients.http.get(
                f"http://slow.invalid:{loopback_apps.http_port}/catalog"
            )
