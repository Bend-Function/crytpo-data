from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import cast

import pytest

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.exchanges.okx import (
    OkxPayloadError,
    instrument_by_key,
    parse_instruments,
    parse_tickers,
)
from crypto_collector.selection import (
    LifecyclePhase,
    TradableAtSource,
    TurnoverMethod,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "okx"
_CATALOG_OBSERVED_NS = 1_750_000_000_000_000_000
_TURNOVER_OBSERVED_NS = 1_760_000_001_000_000_000


def _json(name: str) -> object:
    return decode_json((_FIXTURES / name).read_bytes())


def _object(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def _array(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def test_okx_catalog_maps_spot_identity_time_and_unknown_payload() -> None:
    catalog = parse_instruments(
        _json("instruments-spot.json"),
        Market.SPOT,
        observed_at_ns=_CATALOG_OBSERVED_NS,
    )

    assert catalog.scope.exchange is Exchange.OKX
    assert catalog.scope.market is Market.SPOT
    assert catalog.observed_at_ns == _CATALOG_OBSERVED_NS
    assert catalog.reported_total_count is None
    assert catalog.authoritative_empty is False
    assert tuple(item.instrument_key for item in catalog.instruments) == (
        "BTC-USDT",
        "NEW-USDT",
    )

    btc = instrument_by_key(catalog, "BTC-USDT")
    assert btc.canonical_pair == "BTC/USDT"
    assert btc.wire_symbol("rest") == "BTC-USDT"
    assert btc.wire_symbol("websocket") == "BTC-USDT"
    assert btc.settlement_asset is None
    assert btc.lifecycle_phase is LifecyclePhase.TRADABLE
    assert btc.tradable
    assert btc.tradable_at_ns == 1_700_000_000_123_000_000
    assert btc.tradable_at_source is TradableAtSource.EXCHANGE_LAUNCH
    assert isinstance(btc.lifecycle, MappingProxyType)
    lifecycle = _object(btc.lifecycle)
    future = _object(lifecycle["futureSchemaField"])
    assert future["mode"] == "preserve-me"
    assert future["ratio"] == Decimal("0.1234567890123456789")

    new = instrument_by_key(catalog, "NEW-USDT")
    assert new.lifecycle_phase is LifecyclePhase.PREOPEN
    assert not new.tradable
    assert new.tradable_at_ns == 1_760_003_600_000_000_000
    assert new.tradable_at_source is TradableAtSource.EXCHANGE_CONTINUOUS


def test_okx_catalog_keeps_only_linear_swap_for_selected_settlement() -> None:
    catalog = parse_instruments(
        _json("instruments-swap.json"),
        Market.PERPETUAL,
        observed_at_ns=_CATALOG_OBSERVED_NS,
    )

    assert tuple(item.instrument_key for item in catalog.instruments) == (
        "BTC-USDT-SWAP",
        "NEW-USDT-SWAP",
    )
    btc = instrument_by_key(catalog, "BTC-USDT-SWAP")
    assert btc.canonical_pair == "BTC/USDT"
    assert btc.base_asset == "BTC"
    assert btc.quote_asset == "USDT"
    assert btc.settlement_asset == "USDT"
    lifecycle = _object(btc.lifecycle)
    assert lifecycle["ctVal"] == "0.01"
    assert lifecycle["schemaAddedLater"] == "kept"

    new = instrument_by_key(catalog, "NEW-USDT-SWAP")
    assert new.lifecycle_phase is LifecyclePhase.PREOPEN
    assert new.tradable_at_ns == 1_761_003_600_000_000_000
    assert new.tradable_at_source is TradableAtSource.EXCHANGE_CONTINUOUS


def test_catalog_rejects_response_row_for_another_requested_type() -> None:
    payload = _json("instruments-spot.json")
    assert isinstance(payload, dict)
    first = _object(_array(payload["data"])[0])
    assert isinstance(first, dict)
    first["instType"] = "SWAP"

    with pytest.raises(OkxPayloadError, match="requested SPOT"):
        parse_instruments(
            payload,
            Market.SPOT,
            observed_at_ns=_CATALOG_OBSERVED_NS,
        )


def test_swap_turnover_uses_base_volume_times_price_not_contract_count() -> None:
    catalog = parse_instruments(
        _json("instruments-swap.json"),
        Market.PERPETUAL,
        observed_at_ns=_CATALOG_OBSERVED_NS,
    )

    snapshot = parse_tickers(
        _json("tickers.json"),
        market=Market.PERPETUAL,
        catalog=catalog,
        catalog_revision=7,
        observed_at_ns=_TURNOVER_OBSERVED_NS,
    )

    assert snapshot.catalog_revision == 7
    assert snapshot.observed_at_ns == _TURNOVER_OBSERVED_NS
    assert snapshot.reported_total_count is None
    assert snapshot.covered_instrument_keys == (
        "BTC-USDT-SWAP",
        "NEW-USDT-SWAP",
    )
    assert len(snapshot.observations) == 1
    btc = snapshot.observations[0]
    assert btc.instrument_key == "BTC-USDT-SWAP"
    assert btc.value == Decimal("1234567.89")
    assert btc.method is TurnoverMethod.BASE_VOLUME_X_REFERENCE_PRICE
    assert btc.currency == "USDT"


def test_spot_turnover_uses_exchange_quote_volume_without_price_conversion() -> None:
    catalog = parse_instruments(
        _json("instruments-spot.json"),
        Market.SPOT,
        observed_at_ns=_CATALOG_OBSERVED_NS,
    )
    payload = {
        "code": "0",
        "msg": "",
        "data": [
            {
                "instType": "SPOT",
                "instId": "BTC-USDT",
                "last": "2",
                "vol24h": "617283.945",
                "volCcy24h": "1234567.89000001",
                "ts": "1760000000123",
            }
        ],
    }

    snapshot = parse_tickers(
        payload,
        market=Market.SPOT,
        catalog=catalog,
        catalog_revision=8,
        observed_at_ns=_TURNOVER_OBSERVED_NS,
    )

    assert snapshot.covered_instrument_keys == ("BTC-USDT", "NEW-USDT")
    assert len(snapshot.observations) == 1
    assert snapshot.observations[0].value == Decimal("1234567.89000001")
    assert snapshot.observations[0].method is TurnoverMethod.EXCHANGE_QUOTE_TURNOVER


def test_turnover_observation_cannot_precede_bound_catalog() -> None:
    catalog = parse_instruments(
        _json("instruments-swap.json"),
        Market.PERPETUAL,
        observed_at_ns=_CATALOG_OBSERVED_NS,
    )

    with pytest.raises(ValueError, match="cannot precede"):
        parse_tickers(
            _json("tickers.json"),
            market=Market.PERPETUAL,
            catalog=catalog,
            catalog_revision=1,
            observed_at_ns=_CATALOG_OBSERVED_NS - 1,
        )
