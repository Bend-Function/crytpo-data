from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.exchanges.kraken import (
    KrakenPayloadError,
    instrument_by_key,
    parse_futures_instruments,
    parse_futures_tickers,
    parse_spot_pairs,
    parse_spot_tickers,
)
from crypto_collector.selection import LifecyclePhase, TradableAtSource, TurnoverMethod

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "kraken"
_ROOT = Path(__file__).resolve().parents[4]
_OBSERVED = 1_786_200_000_000_000_000


def _json(name: str) -> object:
    return decode_json((_FIXTURES / name).read_bytes())


def _object(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def _native_futures_instrument(value: object) -> Mapping[str, object]:
    return _object(_object(value)["native_instrument"])


def test_fixture_manifest_pins_every_exact_example_and_official_source() -> None:
    manifest = _object(_json("manifest.json"))
    entries = manifest["entries"]
    assert isinstance(entries, list)
    assert {str(_object(entry)["file"]) for entry in entries} == {
        "spot-pairs.json",
        "spot-book.json",
        "futures-instruments.json",
        "futures-status.json",
        "futures-ticker.json",
        "futures-tickers.json",
        "futures-book.json",
    }
    for value in entries:
        entry = _object(value)
        fixture = _FIXTURES / str(entry["file"])
        source = _ROOT / str(entry["source_document"])
        assert sha256(fixture.read_bytes()).hexdigest() == entry["sha256"]
        assert (
            sha256(source.read_bytes()).hexdigest() == entry["source_document_sha256"]
        )
        if str(entry["adaptation"]).startswith("Byte-for-byte"):
            assert entry["source_anchor"] == "$"
            assert fixture.read_bytes() == source.read_bytes()


def test_spot_catalog_maps_all_native_aliases_without_string_replacement() -> None:
    catalog = parse_spot_pairs(_json("spot-pairs.json"), observed_at_ns=_OBSERVED)

    assert catalog.scope.exchange is Exchange.KRAKEN
    assert catalog.scope.market is Market.SPOT
    instrument = instrument_by_key(catalog, "BTC/USDT")
    assert instrument.canonical_pair == "BTC/USDT"
    assert instrument.wire_symbol("rest_query") == "BTCUSDT"
    assert instrument.wire_symbol("rest_result") == "XBTUSDT"
    assert instrument.wire_symbol("ws_v1") == "XBT/USDT"
    assert instrument.wire_symbol("ws_v2") == "BTC/USDT"
    assert instrument.base_asset == "BTC"
    assert instrument.quote_asset == "USDT"
    assert instrument.status == "online"
    assert instrument.lifecycle_phase is LifecyclePhase.TRADABLE
    assert instrument.tradable
    assert instrument.tradable_at_ns is None
    assert instrument.tradable_at_source is None
    assert _object(instrument.lifecycle)["tick_size"] == "0.1"


def test_spot_catalog_preserves_distinct_result_key_and_altname() -> None:
    catalog = parse_spot_pairs(
        _json("spot-pairs.json"),
        observed_at_ns=_OBSERVED,
    )
    instrument = instrument_by_key(catalog, "BTC/USD")

    assert instrument.wire_symbol("rest_query") == "BTCUSD"
    assert instrument.wire_symbol("rest_result") == "XXBTZUSD"
    assert instrument.wire_symbol("rest_altname") == "XBTUSD"


def test_spot_reduce_only_remains_a_market_data_tradable_phase() -> None:
    catalog = parse_spot_pairs(
        {
            "error": [],
            "result": {
                "XXBTZUSD": {
                    "wsname": "XBT/USD",
                    "altname": "XBTUSD",
                    "status": "reduce_only",
                }
            },
        },
        observed_at_ns=_OBSERVED,
    )

    instrument = instrument_by_key(catalog, "BTC/USD")
    assert instrument.lifecycle_phase is LifecyclePhase.TRADABLE
    assert instrument.tradable


def test_futures_catalog_includes_only_native_perpetual_prefixes() -> None:
    catalog = parse_futures_instruments(
        _json("futures-instruments.json"),
        tickers_payload=_json("futures-tickers.json"),
        observed_at_ns=_OBSERVED,
    )

    keys = tuple(item.instrument_key for item in catalog.instruments)
    assert "PF_XBTUSD" in keys
    assert "PI_XBTUSD" in keys
    assert not any(key.startswith(("FF_", "FI_")) for key in keys)
    assert "PF_EURUSD" not in keys
    assert "PF_TSLAXUSD" not in keys
    assert "PF_XAUUSD" not in keys
    assert "PF_XAUTUSD" in keys
    assert all(
        _native_futures_instrument(item.lifecycle)["tradfi"] is False
        for item in catalog.instruments
    )
    assert not {
        str(_native_futures_instrument(item.lifecycle)["category"])
        for item in catalog.instruments
    } & {"Commodities", "Forex", "Pre-IPO", "xStocks"}
    instrument = instrument_by_key(catalog, "PF_XBTUSD")
    assert instrument.canonical_pair == "BTC/USD"
    assert instrument.wire_symbol("rest") == "PF_XBTUSD"
    assert instrument.wire_symbol("websocket") == "PF_XBTUSD"
    assert instrument.wire_symbol("charts") == "PF_XBTUSD"
    assert instrument.settlement_asset is None
    assert instrument.tradable_at_ns == 1_647_954_936_000_000_000


def test_futures_official_opening_time_and_lifecycle_are_preserved() -> None:
    catalog = parse_futures_instruments(
        _json("futures-instruments.json"),
        tickers_payload=_json("futures-tickers.json"),
        observed_at_ns=_OBSERVED,
    )
    instrument = instrument_by_key(catalog, "PF_XBTUSD")

    assert instrument.tradable_at_ns == 1_647_954_936_000_000_000
    assert instrument.tradable_at_source is TradableAtSource.EXCHANGE_LAUNCH
    lifecycle = _native_futures_instrument(instrument.lifecycle)
    assert lifecycle["pair"] == "BTC:USD"
    assert lifecycle["fundingRateCoefficient"] == 8
    evidence = _object(_object(instrument.lifecycle)["collector_evidence"])
    assert str(evidence["instruments"]).startswith("kraken:futures-instruments:sha256:")
    assert str(evidence["tickers"]).startswith("kraken:futures-tickers:sha256:")
    assert len(catalog.pages) == 1
    assert "instruments-sha256=" in catalog.pages[0].raw_reference
    assert "tickers-sha256=" in catalog.pages[0].raw_reference


def test_futures_future_opening_stays_preopen_until_exchange_launch() -> None:
    payload = {
        "result": "success",
        "instruments": [
            {
                "symbol": "PF_NEWUSD",
                "base": "NEW",
                "quote": "USD",
                "pair": "NEW:USD",
                "tradfi": False,
                "category": "Linear Multi-Collateral Perpetual",
                "tradeable": True,
                "isExpired": False,
                "postOnly": False,
                "openingDate": "2026-08-09T00:00:00Z",
            }
        ],
    }
    launch_ns = 1_786_233_600_000_000_000
    no_ticker = {"result": "success", "tickers": []}
    online_ticker = {
        "result": "success",
        "tickers": [
            {
                "symbol": "PF_NEWUSD",
                "suspended": False,
                "postOnly": False,
            }
        ],
    }

    before = instrument_by_key(
        parse_futures_instruments(
            payload,
            tickers_payload=no_ticker,
            observed_at_ns=launch_ns - 1,
        ),
        "PF_NEWUSD",
    )
    at_launch = instrument_by_key(
        parse_futures_instruments(
            payload,
            tickers_payload=online_ticker,
            observed_at_ns=launch_ns,
        ),
        "PF_NEWUSD",
    )

    assert before.status == "preopen"
    assert before.lifecycle_phase is LifecyclePhase.PREOPEN
    assert not before.tradable
    assert before.tradable_at_ns == launch_ns
    assert before.tradable_at_source is TradableAtSource.EXCHANGE_LAUNCH
    assert at_launch.status == "online"
    assert at_launch.lifecycle_phase is LifecyclePhase.TRADABLE
    assert at_launch.tradable


def test_futures_current_ticker_status_controls_catalog_tradability() -> None:
    payload = {
        "result": "success",
        "instruments": [
            {
                "symbol": "PF_NEWUSD",
                "base": "NEW",
                "quote": "USD",
                "tradfi": False,
                "category": "Linear Multi-Collateral Perpetual",
                "tradeable": True,
                "isExpired": False,
                "postOnly": False,
                "openingDate": "2026-08-08T00:00:00Z",
            }
        ],
    }
    tickers = {
        "result": "success",
        "tickers": [
            {
                "symbol": "PF_NEWUSD",
                "suspended": True,
                "postOnly": False,
            }
        ],
    }

    instrument = instrument_by_key(
        parse_futures_instruments(
            payload,
            tickers_payload=tickers,
            observed_at_ns=_OBSERVED,
        ),
        "PF_NEWUSD",
    )

    assert instrument.status == "suspended"
    assert instrument.lifecycle_phase is LifecyclePhase.PAUSED
    assert not instrument.tradable
    assert _object(instrument.lifecycle)["native_ticker_status"] == {
        "suspended": True,
        "postOnly": False,
    }


def test_futures_opened_catalog_requires_current_ticker_status() -> None:
    payload = {
        "result": "success",
        "instruments": [
            {
                "symbol": "PF_NEWUSD",
                "base": "NEW",
                "quote": "USD",
                "tradfi": False,
                "category": "Linear Multi-Collateral Perpetual",
                "tradeable": True,
                "isExpired": False,
                "openingDate": "2026-08-08T00:00:00Z",
            }
        ],
    }

    with pytest.raises(KrakenPayloadError, match="opened catalog instrument"):
        parse_futures_instruments(
            payload,
            tickers_payload={
                "result": "success",
                "tickers": [{"symbol": "IN_XBTUSD"}],
            },
            observed_at_ns=_OBSERVED,
        )


def test_futures_preopen_catalog_allows_ticker_coverage_to_be_empty() -> None:
    payload = {
        "result": "success",
        "instruments": [
            {
                "symbol": "PF_NEWUSD",
                "base": "NEW",
                "quote": "USD",
                "tradfi": False,
                "category": "Linear Multi-Collateral Perpetual",
                "tradeable": True,
                "isExpired": False,
                "openingDate": "2026-08-09T00:00:00Z",
            }
        ],
    }
    tickers = {"result": "success", "tickers": []}
    catalog = parse_futures_instruments(
        payload,
        tickers_payload=tickers,
        observed_at_ns=_OBSERVED,
    )

    turnover = parse_futures_tickers(
        tickers,
        catalog=catalog,
        catalog_revision=1,
        observed_at_ns=_OBSERVED,
    )

    assert turnover.authoritative_empty
    assert turnover.covered_instrument_keys == ()


def test_spot_turnover_uses_base_volume_times_vwap() -> None:
    catalog = parse_spot_pairs(_json("spot-pairs.json"), observed_at_ns=_OBSERVED)
    payload = {
        "error": [],
        "result": {
            instrument.wire_symbol("rest_result"): {
                "v": [
                    "0",
                    "3.00000000" if instrument.instrument_key == "BTC/USDT" else "0",
                ],
                "p": [
                    "0",
                    "100.12340000" if instrument.instrument_key == "BTC/USDT" else "0",
                ],
            }
            for instrument in catalog.instruments
        },
    }

    turnover = parse_spot_tickers(
        payload,
        catalog=catalog,
        catalog_revision=3,
        observed_at_ns=_OBSERVED + 1,
    )

    observation = next(
        item for item in turnover.observations if item.instrument_key == "BTC/USDT"
    )
    assert observation.value == Decimal("300.3702000000000000")
    assert observation.method is TurnoverMethod.BASE_VOLUME_X_REFERENCE_PRICE
    assert observation.currency == "USDT"


def test_futures_turnover_uses_mixed_case_volume_quote_field() -> None:
    catalog = parse_futures_instruments(
        _json("futures-instruments.json"),
        tickers_payload=_json("futures-tickers.json"),
        observed_at_ns=_OBSERVED,
    )
    payload = {
        "result": "success",
        "serverTime": "2026-08-08T00:00:00Z",
        "tickers": [
            {
                "symbol": instrument.instrument_key,
                "volumeQuote": (
                    Decimal("1234567.890123")
                    if instrument.instrument_key == "PF_XBTUSD"
                    else Decimal(0)
                ),
                "openInterest": Decimal("123.4"),
                "markPrice": Decimal("100.1"),
                "suspended": False,
                "postOnly": False,
            }
            for instrument in catalog.instruments
        ],
    }

    turnover = parse_futures_tickers(
        payload,
        catalog=catalog,
        catalog_revision=4,
        observed_at_ns=_OBSERVED + 2,
    )

    observation = next(
        item for item in turnover.observations if item.instrument_key == "PF_XBTUSD"
    )
    assert observation.value == Decimal("1234567.890123")
    assert observation.method is TurnoverMethod.EXCHANGE_QUOTE_TURNOVER


def test_complete_turnover_parsers_reject_symbol_scoped_payloads() -> None:
    spot = parse_spot_pairs(_json("spot-pairs.json"), observed_at_ns=_OBSERVED)
    futures = parse_futures_instruments(
        _json("futures-instruments.json"),
        tickers_payload=_json("futures-tickers.json"),
        observed_at_ns=_OBSERVED,
    )

    with pytest.raises(KrakenPayloadError, match="complete ticker"):
        parse_spot_tickers(
            {"error": [], "result": {}},
            catalog=spot,
            catalog_revision=1,
            observed_at_ns=_OBSERVED + 1,
        )
    with pytest.raises(KrakenPayloadError, match="complete ticker"):
        parse_futures_tickers(
            {
                "result": "success",
                "tickers": [
                    {
                        "symbol": "PF_XBTUSD",
                        "volumeQuote": Decimal(1),
                        "suspended": False,
                        "postOnly": False,
                    }
                ],
            },
            catalog=futures,
            catalog_revision=1,
            observed_at_ns=_OBSERVED + 1,
        )


def test_turnover_rejects_binary_float_input() -> None:
    catalog = parse_spot_pairs(_json("spot-pairs.json"), observed_at_ns=_OBSERVED)
    payload = {
        "error": [],
        "result": {"XBTUSDT": {"v": ["1", 1.1], "p": ["1", "2"]}},
    }

    with pytest.raises(KrakenPayloadError, match="float"):
        parse_spot_tickers(
            payload,
            catalog=catalog,
            catalog_revision=1,
            observed_at_ns=_OBSERVED + 1,
        )
