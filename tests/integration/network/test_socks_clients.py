from __future__ import annotations

from collections.abc import AsyncIterator

import pytest
import pytest_asyncio

from crypto_collector.config import SecretRef, SecretSnapshot
from crypto_collector.network.clients import build_clients
from crypto_collector.network.models import Egress
from tests.support.socks5_server import LoopbackApps, LoopbackSocks5Server


@pytest_asyncio.fixture
async def loopback_apps() -> AsyncIterator[LoopbackApps]:
    apps = await LoopbackApps.start()
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
            ("127.0.0.1", loopback_apps.http_port): (
                "127.0.0.1",
                loopback_apps.http_port,
            ),
            ("::1", loopback_apps.http_port): (
                "127.0.0.1",
                loopback_apps.http_port,
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
