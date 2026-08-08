from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType
from typing import cast

import pytest

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.exchanges.binance.catalog import (
    instrument_by_key,
    parse_exchange_info,
    parse_rate_limits,
    parse_ticker_turnover,
)
from crypto_collector.exchanges.binance.errors import BinancePayloadError
from crypto_collector.selection import (
    LifecyclePhase,
    TradableAtSource,
    TurnoverMethod,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "binance"
_OBSERVED_NS = 1_770_000_000_000_000_000


def _json(name: str) -> object:
    return decode_json((_FIXTURES / name).read_bytes())


def _object(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def _array(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def test_spot_catalog_preserves_unknown_status_and_filters_non_spot_rows() -> None:
    catalog = parse_exchange_info(
        _json("spot-exchange-info.json"),
        Market.SPOT,
        observed_at_ns=_OBSERVED_NS,
    )

    assert catalog.scope.exchange is Exchange.BINANCE
    assert catalog.scope.market is Market.SPOT
    assert tuple(item.instrument_key for item in catalog.instruments) == (
        "BTCUSDT",
        "NEWUSDT",
    )
    btc = instrument_by_key(catalog, "BTCUSDT")
    assert btc.canonical_pair == "BTC/USDT"
    assert btc.wire_symbol("rest") == "BTCUSDT"
    assert btc.wire_symbol("websocket") == "btcusdt"
    assert btc.settlement_asset is None
    assert btc.lifecycle_phase is LifecyclePhase.TRADABLE
    assert btc.tradable
    assert isinstance(btc.lifecycle, MappingProxyType)
    future = _object(_object(btc.lifecycle)["futureSchemaField"])
    assert future["ratio"] == Decimal("0.1234567890123456789")

    new = instrument_by_key(catalog, "NEWUSDT")
    assert new.status == "FUTURE_UNKNOWN_STATUS"
    assert new.lifecycle_phase is LifecyclePhase.UNKNOWN
    assert not new.tradable


def test_usd_m_catalog_uses_top_level_scope_contract_and_settlement() -> None:
    catalog = parse_exchange_info(
        _json("futures-exchange-info.json"),
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )

    assert tuple(item.instrument_key for item in catalog.instruments) == (
        "BTCUSDT",
        "NEWUSDT",
        "UNKNOWNUSDT",
        "币安人生USDT",
    )
    btc = instrument_by_key(catalog, "BTCUSDT")
    assert btc.canonical_pair == "BTC/USDT"
    assert btc.settlement_asset == "USDT"
    assert btc.wire_symbol("pair") == "BTCUSDT"
    assert btc.tradable_at_ns == 1_569_398_400_000_000_000
    assert btc.tradable_at_source is TradableAtSource.EXCHANGE_LAUNCH
    assert "st" not in _object(btc.lifecycle)

    pending = instrument_by_key(catalog, "NEWUSDT")
    assert pending.lifecycle_phase is LifecyclePhase.PREOPEN
    assert not pending.tradable
    unknown = instrument_by_key(catalog, "UNKNOWNUSDT")
    assert unknown.lifecycle_phase is LifecyclePhase.UNKNOWN


@pytest.mark.parametrize("indicator", [2, 3, "1"])
def test_present_unknown_or_coin_m_row_indicator_is_rejected(
    indicator: object,
) -> None:
    payload = _json("futures-exchange-info.json")
    rows = _array(_object(payload)["symbols"])
    first = _object(rows[0])
    assert isinstance(first, dict)
    first["st"] = indicator

    catalog = parse_exchange_info(
        payload,
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )

    assert "BTCUSDT" not in {item.instrument_key for item in catalog.instruments}


def test_optional_um_row_indicator_is_accepted_when_top_level_scope_is_usd_m() -> None:
    payload = _json("futures-exchange-info.json")
    rows = _array(_object(payload)["symbols"])
    first = _object(rows[0])
    assert isinstance(first, dict)
    first["st"] = 1

    catalog = parse_exchange_info(
        payload,
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )

    assert "BTCUSDT" in {item.instrument_key for item in catalog.instruments}


def test_boolean_onboard_date_is_rejected_instead_of_treated_as_zero() -> None:
    payload = _json("futures-exchange-info.json")
    first = _object(_array(_object(payload)["symbols"])[0])
    assert isinstance(first, dict)
    first["onboardDate"] = False

    with pytest.raises(BinancePayloadError, match="onboardDate"):
        parse_exchange_info(
            payload,
            Market.PERPETUAL,
            observed_at_ns=_OBSERVED_NS,
        )


@pytest.mark.parametrize("futures_type", [None, "C_MARGINED", 1])
def test_missing_wrong_or_malformed_top_level_futures_scope_fails_closed(
    futures_type: object,
) -> None:
    payload = _json("futures-exchange-info.json")
    envelope = _object(payload)
    assert isinstance(envelope, dict)
    if futures_type is None:
        envelope.pop("futuresType")
    else:
        envelope["futuresType"] = futures_type

    with pytest.raises(BinancePayloadError, match="futuresType|U_MARGINED"):
        parse_exchange_info(
            payload,
            Market.PERPETUAL,
            observed_at_ns=_OBSERVED_NS,
        )


def test_rate_limits_are_parsed_from_each_live_exchange_info_snapshot() -> None:
    spot = parse_rate_limits(_json("spot-exchange-info.json"))
    futures = parse_rate_limits(_json("futures-exchange-info.json"))

    assert spot[0].rate_limit_type == "REQUEST_WEIGHT"
    assert spot[0].limit == 6000
    assert futures[0].limit == 2400


@pytest.mark.parametrize(
    ("mutator", "message"),
    [
        (lambda row: row.pop("status"), "status"),
        (lambda row: row.__setitem__("isSpotTradingAllowed", "true"), "boolean"),
        (lambda row: row.__setitem__("permissionSets", [[1]]), "non-empty strings"),
    ],
)
def test_spot_identity_or_permission_type_drift_fails_closed(
    mutator, message: str
) -> None:
    payload = _json("spot-exchange-info.json")
    first = _object(_array(_object(payload)["symbols"])[0])
    assert isinstance(first, dict)
    mutator(first)

    with pytest.raises(BinancePayloadError, match=message):
        parse_exchange_info(payload, Market.SPOT, observed_at_ns=_OBSERVED_NS)


def test_ticker_turnover_uses_exact_quote_volume_without_binary_float() -> None:
    catalog = parse_exchange_info(
        _json("spot-exchange-info.json"),
        Market.SPOT,
        observed_at_ns=_OBSERVED_NS,
    )
    payload = [
        {
            "symbol": "BTCUSDT",
            "lastPrice": "60000.1",
            "volume": "1.5",
            "quoteVolume": "90000.150000000000000001",
            "futureTickerField": {"kept": True},
        },
        {
            "symbol": "NEWUSDT",
            "lastPrice": "0.1",
            "volume": "2",
            "quoteVolume": "0.2",
        },
    ]

    turnover = parse_ticker_turnover(
        payload,
        market=Market.SPOT,
        catalog=catalog,
        catalog_revision=7,
        observed_at_ns=_OBSERVED_NS + 1,
    )

    btc = next(
        item for item in turnover.observations if item.instrument_key == "BTCUSDT"
    )
    assert btc.value == Decimal("90000.150000000000000001")
    assert type(btc.value) is Decimal
    assert btc.method is TurnoverMethod.EXCHANGE_QUOTE_TURNOVER
    assert turnover.covered_instrument_keys == ("BTCUSDT", "NEWUSDT")


def test_single_symbol_ticker_covers_only_the_returned_catalog_instrument() -> None:
    catalog = parse_exchange_info(
        _json("spot-exchange-info.json"),
        Market.SPOT,
        observed_at_ns=_OBSERVED_NS,
    )

    turnover = parse_ticker_turnover(
        {"symbol": "BTCUSDT", "quoteVolume": "10.5"},
        market=Market.SPOT,
        catalog=catalog,
        catalog_revision=7,
        observed_at_ns=_OBSERVED_NS + 1,
    )

    assert turnover.covered_instrument_keys == ("BTCUSDT",)
    assert tuple(item.instrument_key for item in turnover.observations) == ("BTCUSDT",)


def test_ticker_decimal_type_drift_fails_closed() -> None:
    catalog = parse_exchange_info(
        _json("futures-exchange-info.json"),
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )

    with pytest.raises(BinancePayloadError, match="decimal string"):
        parse_ticker_turnover(
            [{"symbol": "BTCUSDT", "quoteVolume": Decimal("1.1")}],
            market=Market.PERPETUAL,
            catalog=catalog,
            catalog_revision=1,
            observed_at_ns=_OBSERVED_NS,
        )
