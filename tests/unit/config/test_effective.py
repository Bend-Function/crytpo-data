from __future__ import annotations

from copy import deepcopy

import pytest

from crypto_collector.config.effective import effective_scope
from crypto_collector.config.models import CollectorConfig
from tests.unit.config.test_models import BASE


def _config() -> CollectorConfig:
    source = deepcopy(BASE)
    source["selection"] = {
        "quote_assets": ["USDT"],
        "fixed_pairs": ["BTC/USDT"],
        "top_n": 20,
        "refresh_interval": "5m",
    }
    source["exchanges"] = {
        "binance": {
            "endpoints": {"rest": "https://example.invalid"},
            "selection": {
                "fixed_pairs": ["ETH/USDT"],
                "top_n": 5,
            },
            "books": {
                "deep_snapshot": {"requested_interval": "1m"},
            },
            "markets": {
                "spot": {
                    "selection": {"quote_assets": ["USD"], "top_n": 2},
                    "symbols": {
                        "BTCUSDT": {
                            "selection": {"top_n": 1},
                            "books": {"deep_snapshot": {"depth": 1000}},
                        }
                    },
                },
                "perpetual": {"enabled": False},
            },
        }
    }
    return CollectorConfig.model_validate(source)


def test_effective_scope_merges_only_explicit_overrides() -> None:
    resolved = effective_scope(_config(), "binance", "spot", "BTCUSDT")

    assert resolved.enabled is True
    assert resolved.selection.top_n == 1
    assert resolved.selection.quote_assets == ("USD",)
    assert resolved.selection.fixed_pairs == ("ETH/USDT",)
    assert resolved.selection.refresh_interval_ns == 300_000_000_000
    assert resolved.books.deep_snapshot.requested_interval_ns == 60_000_000_000
    assert resolved.books.deep_snapshot.depth == 1000


def test_unconfigured_symbol_inherits_market_scope() -> None:
    resolved = effective_scope(_config(), "binance", "spot", "NEWUSDT")

    assert resolved.enabled is True
    assert resolved.selection.top_n == 2
    assert resolved.books.deep_snapshot.depth == "max_supported"


def test_disabled_parent_scope_cannot_be_reenabled_by_child() -> None:
    resolved = effective_scope(_config(), "binance", "perpetual", "PF_XBTUSD")

    assert resolved.enabled is False


def test_effective_scope_requires_configured_exchange() -> None:
    with pytest.raises(KeyError, match="not configured"):
        effective_scope(_config(), "okx", "spot")


def test_effective_endpoints_are_immutable() -> None:
    resolved = effective_scope(_config(), "binance", "spot")

    with pytest.raises(TypeError):
        resolved.endpoints["rest"] = "https://changed.invalid"  # type: ignore[index]
