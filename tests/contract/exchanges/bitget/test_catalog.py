from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from types import MappingProxyType
from typing import cast

import pytest

from crypto_collector.domain import Exchange, Market
from crypto_collector.exchanges.bitget.catalog import (
    instrument_by_key,
    parse_instruments,
    parse_tickers,
)
from crypto_collector.exchanges.bitget.errors import BitgetPayloadError
from crypto_collector.exchanges.bitget.rest import (
    instruments_request,
    ticker_request,
    tickers_request,
)
from crypto_collector.selection import (
    LifecyclePhase,
    TradableAtSource,
    TurnoverMethod,
)

_CATALOG_NS = 1_770_531_248_742_000_000
_TURNOVER_NS = _CATALOG_NS + 1_000_000_000


def _spot_payload() -> dict[str, object]:
    return {
        "code": "00000",
        "msg": "success",
        "requestTime": 1_770_531_248_742,
        "futureEnvelope": {"kept": True},
        "data": [
            {
                "symbol": "BTCUSDT",
                "category": "SPOT",
                "symbolType": "crypto",
                "isReality": "no",
                "baseCoin": "BTC",
                "quoteCoin": "USDT",
                "status": "online",
                "launchTime": "1532454360000",
                "futureInstrumentField": "preserve-me",
                "futureSchema": {
                    "ratio": Decimal("0.123456789012345678901"),
                },
            },
            {
                "symbol": "NEWUSDT",
                "category": "SPOT",
                "symbolType": "crypto",
                "isReality": "no",
                "baseCoin": "NEW",
                "quoteCoin": "USDT",
                "status": "listed",
                "launchTime": None,
            },
        ],
    }


def _perpetual_payload() -> dict[str, object]:
    return {
        "code": "00000",
        "msg": "success",
        "requestTime": 1_770_531_054_230,
        "data": [
            {
                "symbol": "BTCUSDT",
                "category": "USDT-FUTURES",
                "symbolType": "crypto",
                "baseCoin": "BTC",
                "quoteCoin": "USDT",
                "type": "perpetual",
                "status": "online",
                "launchTime": "0",
                "offTime": "-1",
                "futureInstrumentField": "preserve-me-too",
            },
            {
                "symbol": "ETHUSDT_260925",
                "category": "USDT-FUTURES",
                "symbolType": "crypto",
                "baseCoin": "ETH",
                "quoteCoin": "USDT",
                "type": "delivery",
                "status": "online",
                "launchTime": "1700000000000",
            },
            {
                "symbol": "PAUSEDUSDT",
                "category": "USDT-FUTURES",
                "symbolType": "crypto",
                "baseCoin": "PAUSED",
                "quoteCoin": "USDT",
                "type": "perpetual",
                "status": "limit_open",
                "launchTime": "1760000000123",
            },
        ],
    }


def _object(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def test_spot_catalog_preserves_identity_lifecycle_and_unknown_fields() -> None:
    catalog = parse_instruments(
        _spot_payload(),
        Market.SPOT,
        request=instruments_request(Market.SPOT),
        observed_at_ns=_CATALOG_NS,
    )

    assert catalog.scope.exchange is Exchange.BITGET
    assert catalog.scope.market is Market.SPOT
    assert tuple(item.instrument_key for item in catalog.instruments) == (
        "BTCUSDT",
        "NEWUSDT",
    )
    btc = instrument_by_key(catalog, "BTCUSDT")
    assert btc.canonical_pair == "BTC/USDT"
    assert btc.wire_symbol("rest") == "BTCUSDT"
    assert btc.wire_symbol("websocket") == "BTCUSDT"
    assert btc.settlement_asset is None
    assert btc.lifecycle_phase is LifecyclePhase.TRADABLE
    assert btc.tradable
    assert btc.tradable_at_ns == 1_532_454_360_000_000_000
    assert btc.tradable_at_source is TradableAtSource.EXCHANGE_LAUNCH
    assert isinstance(btc.lifecycle, MappingProxyType)
    lifecycle = _object(btc.lifecycle)
    assert lifecycle["futureInstrumentField"] == "preserve-me"
    assert _object(lifecycle["futureSchema"])["ratio"] == Decimal(
        "0.123456789012345678901"
    )

    listed = instrument_by_key(catalog, "NEWUSDT")
    assert listed.lifecycle_phase is LifecyclePhase.PREOPEN
    assert not listed.tradable
    assert listed.tradable_at_ns is None
    assert listed.tradable_at_source is None


def test_usdt_futures_catalog_keeps_only_perpetual_and_zero_launch_is_unknown() -> None:
    catalog = parse_instruments(
        _perpetual_payload(),
        Market.PERPETUAL,
        request=instruments_request(Market.PERPETUAL),
        observed_at_ns=_CATALOG_NS,
    )

    assert tuple(item.instrument_key for item in catalog.instruments) == (
        "BTCUSDT",
        "PAUSEDUSDT",
    )
    btc = instrument_by_key(catalog, "BTCUSDT")
    assert btc.settlement_asset == "USDT"
    assert btc.tradable_at_ns is None
    assert "isReality" not in _object(btc.lifecycle)
    paused = instrument_by_key(catalog, "PAUSEDUSDT")
    assert paused.lifecycle_phase is LifecyclePhase.PAUSED
    assert not paused.tradable


@pytest.mark.parametrize(
    ("status", "phase"),
    [
        ("listed", LifecyclePhase.PREOPEN),
        ("online", LifecyclePhase.TRADABLE),
        ("limit_open", LifecyclePhase.PAUSED),
        ("limit_close", LifecyclePhase.PAUSED),
        ("offline", LifecyclePhase.UNKNOWN),
        ("restrictedAPI", LifecyclePhase.PAUSED),
        ("future_status", LifecyclePhase.UNKNOWN),
    ],
)
def test_documented_statuses_have_conservative_lifecycle_mapping(
    status: str,
    phase: LifecyclePhase,
) -> None:
    payload = _spot_payload()
    data = cast(list[dict[str, object]], payload["data"])
    data[:] = [data[0]]
    data[0]["status"] = status

    instrument = parse_instruments(
        payload,
        Market.SPOT,
        request=instruments_request(Market.SPOT),
        observed_at_ns=_CATALOG_NS,
    ).instruments[0]

    assert instrument.lifecycle_phase is phase
    assert instrument.tradable is (status == "online")


def test_catalog_requires_exact_category_and_string_success_code() -> None:
    wrong_category = _spot_payload()
    cast(list[dict[str, object]], wrong_category["data"])[0]["category"] = "spot"
    numeric_success = _spot_payload()
    numeric_success["code"] = 0

    with pytest.raises(BitgetPayloadError, match="requested SPOT"):
        parse_instruments(
            wrong_category,
            Market.SPOT,
            request=instruments_request(Market.SPOT),
            observed_at_ns=_CATALOG_NS,
        )
    with pytest.raises(BitgetPayloadError, match="string code='00000'"):
        parse_instruments(
            numeric_success,
            Market.SPOT,
            request=instruments_request(Market.SPOT),
            observed_at_ns=_CATALOG_NS,
        )


def test_catalog_rejects_oversized_launch_time_as_typed_payload_error() -> None:
    payload = _spot_payload()
    rows = cast(list[dict[str, object]], payload["data"])
    rows[:] = [rows[0]]
    rows[0]["launchTime"] = "9" * 5_000

    with pytest.raises(BitgetPayloadError, match="signed 64-bit"):
        parse_instruments(
            payload,
            Market.SPOT,
            request=instruments_request(Market.SPOT),
            observed_at_ns=_CATALOG_NS,
        )


@pytest.mark.parametrize("market", [Market.SPOT, Market.PERPETUAL])
def test_catalog_excludes_known_non_crypto_and_reality_rows(
    market: Market,
) -> None:
    payload = _spot_payload() if market is Market.SPOT else _perpetual_payload()
    rows = cast(list[dict[str, object]], payload["data"])
    template = dict(rows[0])
    for symbol, symbol_type, reality in (
        ("STOCKUSDT", "stock", "yes" if market is Market.SPOT else None),
        ("METALUSDT", "metal", "no" if market is Market.SPOT else None),
        ("REALITYUSDT", "crypto", "yes"),
    ):
        row = dict(template)
        row.update(
            {
                "symbol": symbol,
                "baseCoin": symbol.removesuffix("USDT"),
                "symbolType": symbol_type,
                "isReality": reality,
            }
        )
        rows.append(row)

    catalog = parse_instruments(
        payload,
        market,
        request=instruments_request(market),
        observed_at_ns=_CATALOG_NS,
    )

    assert all(
        item.instrument_key
        not in {
            "STOCKUSDT",
            "METALUSDT",
            "REALITYUSDT",
        }
        for item in catalog.instruments
    )


@pytest.mark.parametrize(
    ("market", "field", "value"),
    [
        (Market.SPOT, "symbolType", None),
        (Market.SPOT, "symbolType", "future_asset_class"),
        (Market.SPOT, "isReality", None),
        (Market.SPOT, "isReality", "future_reality_state"),
        (Market.PERPETUAL, "symbolType", None),
        (Market.PERPETUAL, "symbolType", "future_asset_class"),
        (Market.PERPETUAL, "type", None),
        (Market.PERPETUAL, "type", "future_contract_type"),
    ],
)
def test_complete_catalog_rejects_missing_or_unknown_scope_discriminator(
    market: Market,
    field: str,
    value: object,
) -> None:
    payload = _spot_payload() if market is Market.SPOT else _perpetual_payload()
    rows = cast(list[dict[str, object]], payload["data"])
    rows[:] = [rows[0]]
    if value is None:
        rows[0].pop(field, None)
    else:
        rows[0][field] = value

    with pytest.raises(BitgetPayloadError, match=field):
        parse_instruments(
            payload,
            market,
            request=instruments_request(market),
            observed_at_ns=_CATALOG_NS,
        )


def test_complete_catalog_parsers_reject_symbol_scoped_request_evidence() -> None:
    catalog = parse_instruments(
        _spot_payload(),
        Market.SPOT,
        request=instruments_request(Market.SPOT),
        observed_at_ns=_CATALOG_NS,
    )
    scoped_request = ticker_request(catalog.instruments[0])

    with pytest.raises(ValueError, match="unscoped category request"):
        parse_instruments(
            _spot_payload(),
            Market.SPOT,
            request=scoped_request,
            observed_at_ns=_CATALOG_NS,
        )
    with pytest.raises(ValueError, match="unscoped category request"):
        parse_tickers(
            {"code": "00000", "msg": "success", "data": []},
            market=Market.SPOT,
            request=scoped_request,
            catalog=catalog,
            catalog_revision=1,
            observed_at_ns=_TURNOVER_NS,
        )


@pytest.mark.parametrize("market", [Market.SPOT, Market.PERPETUAL])
def test_turnover_uses_direct_quote_turnover_for_both_markets(market: Market) -> None:
    instruments = _spot_payload() if market is Market.SPOT else _perpetual_payload()
    catalog = parse_instruments(
        instruments,
        market,
        request=instruments_request(market),
        observed_at_ns=_CATALOG_NS,
    )
    payload = {
        "code": "00000",
        "msg": "success",
        "requestTime": 1_765_444_397_411,
        "data": [
            {
                "category": "SPOT" if market is Market.SPOT else "USDT-FUTURES",
                "symbol": "BTCUSDT",
                "lastPrice": "90253.5",
                "volume24h": "7386.014738",
                "turnover24h": "677732572.225658000000000001",
                "futureTickerField": "preserved-in-raw-reference",
                "ts": "1765444395778",
            },
            {
                "category": "SPOT" if market is Market.SPOT else "USDT-FUTURES",
                "symbol": "UNKNOWNUSDT",
                "turnover24h": "999",
                "ts": "1765444395778",
            },
        ],
    }

    snapshot = parse_tickers(
        payload,
        market=market,
        request=tickers_request(market),
        catalog=catalog,
        catalog_revision=3,
        observed_at_ns=_TURNOVER_NS,
    )

    assert snapshot.covered_instrument_keys == tuple(
        sorted(item.instrument_key for item in catalog.instruments)
    )
    assert len(snapshot.observations) == 1
    observation = snapshot.observations[0]
    assert observation.instrument_key == "BTCUSDT"
    assert observation.value == Decimal("677732572.225658000000000001")
    assert observation.method is TurnoverMethod.EXCHANGE_QUOTE_TURNOVER
    assert observation.currency == "USDT"


def test_ticker_category_mismatch_and_observation_before_catalog_are_rejected() -> None:
    catalog = parse_instruments(
        _spot_payload(),
        Market.SPOT,
        request=instruments_request(Market.SPOT),
        observed_at_ns=_CATALOG_NS,
    )
    payload = {
        "code": "00000",
        "msg": "success",
        "data": [
            {
                "category": "USDT-FUTURES",
                "symbol": "BTCUSDT",
                "turnover24h": "1",
            }
        ],
    }

    with pytest.raises(BitgetPayloadError, match="wrong category"):
        parse_tickers(
            payload,
            market=Market.SPOT,
            request=tickers_request(Market.SPOT),
            catalog=catalog,
            catalog_revision=1,
            observed_at_ns=_TURNOVER_NS,
        )
    with pytest.raises(ValueError, match="cannot precede"):
        parse_tickers(
            {"code": "00000", "msg": "success", "data": []},
            market=Market.SPOT,
            request=tickers_request(Market.SPOT),
            catalog=catalog,
            catalog_revision=1,
            observed_at_ns=_CATALOG_NS - 1,
        )


def test_complete_ticker_response_rejects_duplicate_symbols() -> None:
    catalog = parse_instruments(
        _spot_payload(),
        Market.SPOT,
        request=instruments_request(Market.SPOT),
        observed_at_ns=_CATALOG_NS,
    )
    row = {
        "category": "SPOT",
        "symbol": "BTCUSDT",
        "turnover24h": "1",
    }

    with pytest.raises(BitgetPayloadError, match="repeats a symbol"):
        parse_tickers(
            {"code": "00000", "msg": "success", "data": [row, dict(row)]},
            market=Market.SPOT,
            request=tickers_request(Market.SPOT),
            catalog=catalog,
            catalog_revision=1,
            observed_at_ns=_TURNOVER_NS,
        )
