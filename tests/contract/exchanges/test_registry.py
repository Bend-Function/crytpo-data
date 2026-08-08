from __future__ import annotations

import pytest

from crypto_collector.domain import Exchange
from crypto_collector.exchanges.registry import AdapterRegistry


class _Provider:
    exchange = Exchange.OKX

    async def probe(self, request):  # type: ignore[no-untyped-def]
        raise AssertionError("not called")


class _Adapter:
    exchange = Exchange.OKX

    async def fetch_catalog(self, runtime, market):  # type: ignore[no-untyped-def]
        raise AssertionError("not called")

    def plan(self, request):  # type: ignore[no-untyped-def]
        raise AssertionError("not called")

    async def run(self, plan, runtime, sink):  # type: ignore[no-untyped-def]
        raise AssertionError("not called")


def test_registry_exposes_probe_providers_by_exchange_id_read_only() -> None:
    provider = _Provider()
    registry = AdapterRegistry()

    registry.register_probe_provider(provider)

    snapshot = registry.probe_providers()
    assert snapshot == {"okx": provider}
    with pytest.raises(TypeError):
        snapshot["binance"] = provider  # type: ignore[index]


def test_registry_rejects_duplicate_and_malformed_probe_providers() -> None:
    registry = AdapterRegistry()
    provider = _Provider()
    registry.register_probe_provider(provider)

    with pytest.raises(ValueError, match="already registered"):
        registry.register_probe_provider(_Provider())
    with pytest.raises(ValueError, match="already registered"):
        registry.register_probe_provider(provider)

    class MissingProbe:
        exchange = Exchange.BINANCE

    with pytest.raises(TypeError, match=r"provide probe\(\)"):
        registry.register_probe_provider(MissingProbe())  # type: ignore[arg-type]


def test_adapter_and_probe_provider_namespaces_are_independent() -> None:
    provider = _Provider()
    adapter = _Adapter()
    registry = AdapterRegistry()

    registry.register(adapter)
    registry.register_probe_provider(provider)

    assert registry.snapshot() == {Exchange.OKX: adapter}
    assert registry.probe_providers() == {"okx": provider}


def test_registry_rejects_incomplete_adapter_without_mutation() -> None:
    registry = AdapterRegistry()

    with pytest.raises(TypeError, match=r"fetch_catalog\(\).+plan\(\).+run\(\)"):
        registry.register(_Provider())  # type: ignore[arg-type]

    assert registry.snapshot() == {}
