from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import TYPE_CHECKING

from crypto_collector.domain import Exchange
from crypto_collector.exchanges.errors import AdapterNotRegisteredError

if TYPE_CHECKING:
    from crypto_collector.config.probe_contracts import ProbeProvider
    from crypto_collector.exchanges.contracts import ExchangeAdapter

_ADAPTER_METHODS = ("fetch_catalog", "plan", "run")


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[Exchange, ExchangeAdapter] = {}
        self._probe_providers: dict[Exchange, ProbeProvider] = {}

    def register(self, adapter: ExchangeAdapter) -> None:
        exchange = getattr(adapter, "exchange", None)
        if type(exchange) is not Exchange:
            raise TypeError("adapter.exchange must be Exchange")
        missing = tuple(
            method
            for method in _ADAPTER_METHODS
            if not callable(getattr(adapter, method, None))
        )
        if missing:
            raise TypeError(
                "adapter must provide " + ", ".join(f"{method}()" for method in missing)
            )
        if exchange in self._adapters:
            raise ValueError(f"adapter for {exchange.value!r} is already registered")
        self._adapters[exchange] = adapter

    def register_probe_provider(self, provider: ProbeProvider) -> None:
        exchange = getattr(provider, "exchange", None)
        if type(exchange) is not Exchange:
            raise TypeError("probe_provider.exchange must be Exchange")
        if not callable(getattr(provider, "probe", None)):
            raise TypeError("probe provider must provide probe()")
        self._register_probe_provider(exchange, provider)

    def _register_probe_provider(
        self,
        exchange: Exchange,
        provider: ProbeProvider,
    ) -> None:
        existing = self._probe_providers.get(exchange)
        if existing is not None:
            raise ValueError(
                f"probe provider for {exchange.value!r} is already registered"
            )
        self._probe_providers[exchange] = provider

    def for_exchange(self, exchange: Exchange) -> ExchangeAdapter:
        if type(exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        try:
            return self._adapters[exchange]
        except KeyError:
            raise AdapterNotRegisteredError(
                f"adapter for {exchange.value!r} is not registered"
            ) from None

    def snapshot(self) -> Mapping[Exchange, ExchangeAdapter]:
        return MappingProxyType(dict(self._adapters))

    def probe_providers(self) -> Mapping[str, ProbeProvider]:
        return MappingProxyType(
            {
                exchange.value: provider
                for exchange, provider in sorted(
                    self._probe_providers.items(), key=lambda item: item[0].value
                )
            }
        )
