from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from crypto_collector.config.models import (
    BooksConfig,
    BooksOverride,
    CollectorConfig,
    DeepSnapshotConfig,
    DeepSnapshotOverride,
    NewListingsConfig,
    NewListingsOverride,
    SelectionConfig,
    SelectionOverride,
)


@dataclass(frozen=True, slots=True)
class EffectiveScopeConfig:
    exchange: str
    market: str
    symbol: str | None
    enabled: bool
    endpoints: Mapping[str, str]
    selection: SelectionConfig
    books: BooksConfig


def _overlay_new_listings(
    base: NewListingsConfig, override: NewListingsOverride | None
) -> NewListingsConfig:
    if override is None:
        return base
    updates: dict[str, object] = {}
    if override.enabled is not None:
        updates["enabled"] = override.enabled
    if override.capture_duration_ns is not None:
        updates["capture_duration_ns"] = override.capture_duration_ns
    if override.initial_lookback_ns is not None:
        updates["initial_lookback_ns"] = override.initial_lookback_ns
    return base.model_copy(update=updates)


def _overlay_selection(
    base: SelectionConfig, override: SelectionOverride
) -> SelectionConfig:
    updates: dict[str, object] = {}
    for name in (
        "quote_assets",
        "fixed_pairs",
        "top_n",
        "refresh_interval_ns",
        "exit_grace_ns",
        "capacity_policy",
    ):
        value = getattr(override, name)
        if value is not None:
            updates[name] = value
    if override.new_listings is not None:
        updates["new_listings"] = _overlay_new_listings(
            base.new_listings, override.new_listings
        )
    return base.model_copy(update=updates)


def _overlay_deep_snapshot(
    base: DeepSnapshotConfig, override: DeepSnapshotOverride
) -> DeepSnapshotConfig:
    updates: dict[str, object] = {}
    for name in ("enabled", "requested_interval_ns", "depth", "overload_policy"):
        value = getattr(override, name)
        if value is not None:
            updates[name] = value
    return base.model_copy(update=updates)


def _overlay_books(base: BooksConfig, override: BooksOverride) -> BooksConfig:
    updates: dict[str, object] = {}
    if override.live is not None:
        updates["live"] = override.live
    if override.deep_snapshot is not None:
        updates["deep_snapshot"] = _overlay_deep_snapshot(
            base.deep_snapshot, override.deep_snapshot
        )
    return base.model_copy(update=updates)


def effective_scope(
    config: CollectorConfig,
    exchange_id: str,
    market_id: str,
    symbol: str | None = None,
) -> EffectiveScopeConfig:
    try:
        exchange = config.exchanges[exchange_id]
    except KeyError as error:
        raise KeyError(f"exchange {exchange_id!r} is not configured") from error

    enabled = exchange.enabled
    selection = _overlay_selection(config.selection, exchange.selection)
    books = _overlay_books(config.books, exchange.books)

    market = exchange.markets.get(market_id)
    if market is not None:
        enabled = enabled and market.enabled
        selection = _overlay_selection(selection, market.selection)
        books = _overlay_books(books, market.books)

        if symbol is not None:
            symbol_override = market.symbols.get(symbol)
            if symbol_override is not None:
                enabled = enabled and symbol_override.enabled
                selection = _overlay_selection(selection, symbol_override.selection)
                books = _overlay_books(books, symbol_override.books)

    return EffectiveScopeConfig(
        exchange=exchange_id,
        market=market_id,
        symbol=symbol,
        enabled=enabled,
        endpoints=MappingProxyType(dict(exchange.endpoints)),
        selection=selection,
        books=books,
    )


__all__ = ["EffectiveScopeConfig", "effective_scope"]
