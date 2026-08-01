from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio
from websockets.exceptions import ProxyError

from crypto_collector.config import SecretRef, SecretSnapshot
from crypto_collector.network.assignment import choose_egress
from crypto_collector.network.clients import build_clients
from crypto_collector.network.models import Egress
from crypto_collector.network.state_store import EgressStateStore
from tests.support.socks5_server import (
    LoopbackApps,
    LoopbackSocks5Server,
    TlsContexts,
    create_test_tls_contexts,
)


@pytest.fixture
def tls_contexts(tmp_path: Path) -> TlsContexts:
    return create_test_tls_contexts(tmp_path)


@pytest_asyncio.fixture
async def loopback_apps(tls_contexts: TlsContexts) -> AsyncIterator[LoopbackApps]:
    apps = await LoopbackApps.start(server_ssl=tls_contexts.server)
    try:
        yield apps
    finally:
        await apps.close()


@pytest_asyncio.fixture
async def failover_socks_pair(
    loopback_apps: LoopbackApps,
) -> AsyncIterator[tuple[LoopbackSocks5Server, LoopbackSocks5Server]]:
    destinations = {
        ("venue.invalid", loopback_apps.http_port): (
            "127.0.0.1",
            loopback_apps.http_port,
        ),
        ("venue.invalid", loopback_apps.websocket_port): (
            "127.0.0.1",
            loopback_apps.websocket_port,
        ),
    }
    first = await LoopbackSocks5Server.start(destinations=destinations)
    second = await LoopbackSocks5Server.start(destinations=destinations)
    try:
        yield first, second
    finally:
        await first.close()
        await second.close()


def proxy_egress(egress_id: str, reference: SecretRef) -> Egress:
    return Egress.model_validate(
        {
            "id": egress_id,
            "type": "socks5h",
            "url": reference,
            "quota_group": egress_id,
        }
    )


@pytest.mark.network
@pytest.mark.asyncio
async def test_failed_proxy_moves_only_the_new_connection_generation(
    failover_socks_pair: tuple[LoopbackSocks5Server, LoopbackSocks5Server],
    loopback_apps: LoopbackApps,
    tmp_path,
) -> None:
    first_proxy, second_proxy = failover_socks_pair
    first_ref = SecretRef.parse("env:SOCKS_A")
    second_ref = SecretRef.parse("env:SOCKS_B")
    egresses = [proxy_egress("a", first_ref), proxy_egress("b", second_ref)]
    secrets = SecretSnapshot.from_test_values(
        {first_ref: first_proxy.url(), second_ref: second_proxy.url()}
    )
    assignment_key = next(
        f"okx/spot/PAIR-{index}/books"
        for index in range(1_000)
        if choose_egress(f"okx/spot/PAIR-{index}/books", egresses).id == "a"
    )
    first_assignment = choose_egress(assignment_key, egresses)

    async with build_clients(first_assignment, secrets=secrets) as first_generation:
        response = await first_generation.http.get(loopback_apps.proxied_http_url)
        assert response.status_code == 200

    await first_proxy.close()
    with pytest.raises((ProxyError, OSError, httpx.TransportError)):
        async with build_clients(first_assignment, secrets=secrets) as failed:
            async with failed.websocket.connect(loopback_apps.proxied_websocket_url):
                pass

    store = EgressStateStore.open(tmp_path / "okx-network.sqlite")
    try:
        store.record_transport_failure(
            exchange="okx", egress_id=first_assignment.id, reason="connect_error"
        )
        health = store.admit_health(
            exchange="okx",
            egresses=egresses,
            now_unix_ns=1,
            now_monotonic_ns=1,
        ).snapshot(now_monotonic_ns=1)
        second_assignment = choose_egress(assignment_key, egresses, health=health)

        assert first_assignment.id == "a"
        assert second_assignment.id == "b"
        async with build_clients(
            second_assignment, secrets=secrets
        ) as second_generation:
            response = await second_generation.http.get(loopback_apps.proxied_http_url)
            assert response.status_code == 200
            async with second_generation.websocket.connect(
                loopback_apps.proxied_websocket_url
            ) as websocket:
                assert await websocket.recv() == "ready"
    finally:
        store.close()
