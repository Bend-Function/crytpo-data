from __future__ import annotations

import traceback

import pytest

from crypto_collector.config import SecretRef, SecretSnapshot
from crypto_collector.network.clients import (
    build_clients,
    build_http_client_spec,
    build_websocket_connect_spec,
)
from crypto_collector.network.models import Egress


def direct_egress() -> Egress:
    return Egress.model_validate({"id": "direct", "type": "direct"})


def test_direct_http_client_ignores_host_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://unexpected.invalid:8080")

    spec = build_http_client_spec(direct_egress(), secrets=SecretSnapshot.empty())

    assert spec.trust_env is False
    assert spec.proxy is None


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
