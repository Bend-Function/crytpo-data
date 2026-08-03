from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from crypto_collector.domain import Exchange
from crypto_collector.exchanges.contracts import ExchangeAdapter
from crypto_collector.exchanges.errors import AdapterNotRegisteredError


class AdapterRegistry:
    def __init__(self) -> None:
        self._adapters: dict[Exchange, ExchangeAdapter] = {}

    def register(self, adapter: ExchangeAdapter) -> None:
        exchange = getattr(adapter, "exchange", None)
        if type(exchange) is not Exchange:
            raise TypeError("adapter.exchange must be Exchange")
        if exchange in self._adapters:
            raise ValueError(f"adapter for {exchange.value!r} is already registered")
        self._adapters[exchange] = adapter

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
