from __future__ import annotations

from crypto_collector.domain import Exchange


def assert_adapter_identity(adapter: object, exchange: Exchange) -> None:
    assert getattr(adapter, "exchange", None) is exchange
    for method in ("fetch_catalog", "plan", "run"):
        assert callable(getattr(adapter, method, None)), method


def assert_probe_provider_identity(provider: object, exchange: Exchange) -> None:
    assert getattr(provider, "exchange", None) is exchange
    assert callable(getattr(provider, "probe", None)), "probe"
