from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from crypto_collector.domain import Market
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.exchanges.bybit.catalog import (
    BybitCatalogChain,
    BybitCatalogPage,
    BybitCatalogRaceError,
    instrument_by_key,
    parse_instrument_chains,
    parse_instrument_pages,
    parse_tickers,
)
from crypto_collector.exchanges.bybit.errors import BybitPayloadError
from crypto_collector.selection import (
    LifecyclePhase,
    TradableAtSource,
    TurnoverMethod,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "bybit"
_OBSERVED_NS = 1_786_248_010_000_000_000


def _json(name: str) -> object:
    return decode_json((_FIXTURES / name).read_bytes())


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _array(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _spot_payload() -> dict[str, object]:
    return _object(deepcopy(_json("spot-instruments.json")))


def _linear_chains(*, reversed_order: bool = False) -> tuple[BybitCatalogChain, ...]:
    trading = BybitCatalogChain(
        "Trading",
        (
            BybitCatalogPage(_json("linear-trading-page-1.json")),
            BybitCatalogPage(
                _json("linear-trading-page-2.json"),
                request_cursor="trading-page-2",
            ),
        ),
    )
    prelaunch = BybitCatalogChain(
        "PreLaunch",
        (BybitCatalogPage(_json("linear-prelaunch.json")),),
    )
    return (prelaunch, trading) if reversed_order else (trading, prelaunch)


def _linear_result():
    return parse_instrument_chains(
        _linear_chains(),
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )


def test_spot_catalog_accepts_real_response_without_cursor_and_preserves_raw() -> None:
    snapshot = parse_instrument_pages(
        (BybitCatalogPage(_json("spot-instruments.json")),),
        Market.SPOT,
        observed_at_ns=_OBSERVED_NS,
    )

    btc = instrument_by_key(snapshot, "BTCUSDT")
    assert btc.canonical_pair == "BTC/USDT"
    assert btc.tradable
    assert btc.lifecycle_phase is LifecyclePhase.TRADABLE
    assert btc.tradable_at_ns is None
    assert btc.tradable_at_source is None
    future = cast(dict[str, object], btc.lifecycle["futureSpotField"])
    assert future["preserve"] == Decimal("0.1234567890123456789")
    assert snapshot.page_count == 1
    assert snapshot.page_raw_references[0].startswith("bybit:catalog-manifest:sha256:")


def test_spot_accepts_empty_cursor_but_rejects_nonempty_or_multiple_pages() -> None:
    empty = _spot_payload()
    _object(empty["result"])["nextPageCursor"] = ""
    parse_instrument_pages(
        (BybitCatalogPage(empty),),
        Market.SPOT,
        observed_at_ns=_OBSERVED_NS,
    )

    nonempty = _spot_payload()
    _object(nonempty["result"])["nextPageCursor"] = "unexpected"
    with pytest.raises(BybitPayloadError, match="must not paginate"):
        parse_instrument_pages(
            (BybitCatalogPage(nonempty),),
            Market.SPOT,
            observed_at_ns=_OBSERVED_NS,
        )
    with pytest.raises(BybitPayloadError, match="exactly one page"):
        parse_instrument_pages(
            (
                BybitCatalogPage(_spot_payload()),
                BybitCatalogPage(_spot_payload()),
            ),
            Market.SPOT,
            observed_at_ns=_OBSERVED_NS,
        )


def test_linear_requires_two_terminal_status_chains_and_canonicalizes_order() -> None:
    first = _linear_result()
    reversed_result = parse_instrument_chains(
        _linear_chains(reversed_order=True),
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )

    assert tuple(chain.status for chain in first.chains) == ("Trading", "PreLaunch")
    assert first.manifest_bytes == reversed_result.manifest_bytes
    assert first.manifest_sha256 == sha256(first.manifest_bytes).hexdigest()
    assert first.manifest_reference == (
        f"bybit:catalog-manifest:sha256:{first.manifest_sha256}"
    )
    assert first.snapshot.snapshot_id == reversed_result.snapshot.snapshot_id
    manifest = first.manifest_payload
    assert manifest["merge_policy"] == "reject_cross_chain_transition"
    manifest_chains = cast(list[object], manifest["chains"])
    assert [_object(item)["status"] for item in manifest_chains] == [
        "Trading",
        "PreLaunch",
    ]
    trading_pages = cast(list[object], _object(manifest_chains[0])["pages"])
    assert [
        (
            _object(page)["request_cursor"],
            _object(page)["next_cursor"],
        )
        for page in trading_pages
    ] == [(None, "trading-page-2"), ("trading-page-2", None)]


def test_linear_filters_scope_and_keeps_each_instrument_real_page_reference() -> None:
    parsed = _linear_result()

    assert [item.instrument_key for item in parsed.snapshot.instruments] == [
        "BTCUSDT",
        "LIVEUSDT",
        "NEWUSDT",
        "ONLYUSDT",
    ]
    assert "ETHUSDC" not in {
        item.instrument_key for item in parsed.snapshot.instruments
    }
    assert "BTCUSDH26" not in {
        item.instrument_key for item in parsed.snapshot.instruments
    }
    new = instrument_by_key(parsed.snapshot, "NEWUSDT")
    live = instrument_by_key(parsed.snapshot, "LIVEUSDT")
    only = instrument_by_key(parsed.snapshot, "ONLYUSDT")
    assert live.status == "Trading"
    assert live.tradable
    assert live.tradable_at_source is TradableAtSource.EXCHANGE_LAUNCH
    assert new.status == "PreLaunch"
    assert not new.tradable
    assert new.tradable_at_source is TradableAtSource.EXCHANGE_CONTINUOUS
    assert only.status == "PreLaunch"
    assert not only.tradable
    assert only.lifecycle_phase is LifecyclePhase.PREOPEN
    assert only.tradable_at_ns == 1_786_250_300_000_000_000
    assert only.tradable_at_source is TradableAtSource.EXCHANGE_CONTINUOUS
    assert parsed.transitions == ()
    assert live.raw_catalog_reference.startswith(
        "bybit:instruments-perpetual-trading-page-2:sha256:"
    )
    assert only.raw_catalog_reference in {
        page.raw_reference for page in parsed.chains[1].pages
    }


def test_cross_chain_transition_is_a_typed_retryable_catalog_race() -> None:
    prelaunch_payload = _object(deepcopy(_json("linear-prelaunch.json")))
    row = _object(_array(_object(prelaunch_payload["result"])["list"])[0])
    row["symbol"] = "LIVEUSDT"
    row["baseCoin"] = "LIVE"
    prelaunch = BybitCatalogChain(
        "PreLaunch",
        (BybitCatalogPage(prelaunch_payload),),
    )

    with pytest.raises(BybitCatalogRaceError) as raised:
        parse_instrument_chains(
            (_linear_chains()[0], prelaunch),
            Market.PERPETUAL,
            observed_at_ns=_OBSERVED_NS,
        )

    assert len(raised.value.transitions) == 1
    evidence = raised.value.transitions[0]
    assert evidence.instrument_key == "LIVEUSDT"
    assert evidence.prelaunch_raw_reference.startswith(
        "bybit:instruments-perpetual-prelaunch-page-1:sha256:"
    )
    assert evidence.trading_raw_reference.startswith(
        "bybit:instruments-perpetual-trading-page-2:sha256:"
    )


def test_linear_rejects_missing_status_chain_and_chain_local_duplicates() -> None:
    with pytest.raises(BybitPayloadError, match="Trading and PreLaunch"):
        parse_instrument_chains(
            (_linear_chains()[0],),
            Market.PERPETUAL,
            observed_at_ns=_OBSERVED_NS,
        )

    duplicate = _object(deepcopy(_json("linear-trading-page-1.json")))
    result = _object(duplicate["result"])
    rows = _array(result["list"])
    rows.append(deepcopy(rows[0]))
    result["nextPageCursor"] = ""
    trading = BybitCatalogChain("Trading", (BybitCatalogPage(duplicate),))
    with pytest.raises(BybitPayloadError, match="duplicate instrument"):
        parse_instrument_chains(
            (trading, _linear_chains()[1]),
            Market.PERPETUAL,
            observed_at_ns=_OBSERVED_NS,
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("wrong_request", "not contiguous"),
        ("early_terminal", "continue after a terminal"),
        ("unterminated", "incomplete"),
        ("loop", "does not advance"),
        ("wrong_category", "category"),
    ],
)
def test_linear_cursor_and_category_evidence_fails_closed(
    mutation: str,
    message: str,
) -> None:
    first = _object(deepcopy(_json("linear-trading-page-1.json")))
    second = _object(deepcopy(_json("linear-trading-page-2.json")))
    request_cursor = "trading-page-2"
    if mutation == "wrong_request":
        request_cursor = "wrong"
    elif mutation == "early_terminal":
        _object(first["result"])["nextPageCursor"] = ""
    elif mutation == "unterminated":
        _object(second["result"])["nextPageCursor"] = "page-3"
    elif mutation == "loop":
        _object(second["result"])["nextPageCursor"] = "trading-page-2"
    elif mutation == "wrong_category":
        _object(first["result"])["category"] = "spot"
    trading = BybitCatalogChain(
        "Trading",
        (
            BybitCatalogPage(first),
            BybitCatalogPage(second, request_cursor=request_cursor),
        ),
    )
    with pytest.raises(BybitPayloadError, match=message):
        parse_instrument_chains(
            (trading, _linear_chains()[1]),
            Market.PERPETUAL,
            observed_at_ns=_OBSERVED_NS,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("launchTime", None, "launchTime"),
        ("launchTime", 1786248000000, "launchTime"),
        ("isPreListing", None, "isPreListing"),
        ("isPreListing", "false", "isPreListing"),
        ("preListingInfo", {"phases": []}, "must be null"),
    ],
)
def test_selected_linear_known_lifecycle_schema_is_strict(
    field: str,
    value: object,
    message: str,
) -> None:
    payload = _object(deepcopy(_json("linear-trading-page-2.json")))
    row = _object(_array(_object(payload["result"])["list"])[0])
    if value is None:
        row.pop(field)
    else:
        row[field] = value
    trading = BybitCatalogChain("Trading", (BybitCatalogPage(payload),))
    with pytest.raises(BybitPayloadError, match=message):
        parse_instrument_chains(
            (trading, _linear_chains()[1]),
            Market.PERPETUAL,
            observed_at_ns=_OBSERVED_NS,
        )


def test_prelisting_true_requires_non_null_info_and_unknown_status_is_preserved() -> (
    None
):
    malformed = _object(deepcopy(_json("linear-prelaunch.json")))
    row = _object(_array(_object(malformed["result"])["list"])[0])
    row["preListingInfo"] = None
    with pytest.raises(BybitPayloadError, match="must be an object"):
        parse_instrument_chains(
            (
                _linear_chains()[0],
                BybitCatalogChain("PreLaunch", (BybitCatalogPage(malformed),)),
            ),
            Market.PERPETUAL,
            observed_at_ns=_OBSERVED_NS,
        )

    future = _object(deepcopy(_json("linear-trading-page-2.json")))
    future_row = _object(_array(_object(future["result"])["list"])[0])
    future_row["symbol"] = "FUTUREUSDT"
    future_row["baseCoin"] = "FUTURE"
    future_row["status"] = "FutureLifecycleState"
    parsed = parse_instrument_chains(
        (
            BybitCatalogChain("Trading", (BybitCatalogPage(future),)),
            BybitCatalogChain(
                "PreLaunch",
                (
                    BybitCatalogPage(
                        {
                            "retCode": 0,
                            "retMsg": "OK",
                            "result": {
                                "category": "linear",
                                "list": [],
                                "nextPageCursor": "",
                            },
                        }
                    ),
                ),
            ),
        ),
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )
    future_instrument = instrument_by_key(parsed.snapshot, "FUTUREUSDT")
    assert future_instrument.lifecycle_phase is LifecyclePhase.UNKNOWN
    assert not future_instrument.tradable


def test_prelaunch_skipped_or_historical_phase_falls_back_to_future_launch() -> None:
    payload = _object(deepcopy(_json("linear-prelaunch.json")))
    rows = _array(_object(payload["result"])["list"])
    del rows[1:]
    row = _object(rows[0])
    row["symbol"] = "SKIPUSDT"
    row["baseCoin"] = "SKIP"
    row["launchTime"] = "1786251000000"
    info = _object(row["preListingInfo"])
    info["skipCallAuction"] = True
    phases = _array(info["phases"])
    _object(phases[-1])["startTime"] = "946684800000"
    parsed = parse_instrument_chains(
        (
            _linear_chains()[0],
            BybitCatalogChain("PreLaunch", (BybitCatalogPage(payload),)),
        ),
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )
    instrument = instrument_by_key(parsed.snapshot, "SKIPUSDT")
    assert instrument.tradable_at_ns == 1_786_251_000_000_000_000
    assert instrument.tradable_at_source is TradableAtSource.EXCHANGE_LAUNCH

    past_launch = _object(deepcopy(payload))
    past_row = _object(_array(_object(past_launch["result"])["list"])[0])
    past_row["launchTime"] = "946684900000"
    no_time = parse_instrument_chains(
        (
            _linear_chains()[0],
            BybitCatalogChain("PreLaunch", (BybitCatalogPage(past_launch),)),
        ),
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    )
    no_time_instrument = instrument_by_key(no_time.snapshot, "SKIPUSDT")
    assert no_time_instrument.tradable_at_ns is None
    assert no_time_instrument.tradable_at_source is None


@pytest.mark.parametrize("ret_code", ["0", Decimal(0), False, None])
def test_catalog_requires_strict_integer_success_envelope(ret_code: object) -> None:
    payload = _spot_payload()
    payload["retCode"] = ret_code
    with pytest.raises(BybitPayloadError, match="integer retCode=0"):
        parse_instrument_pages(
            (BybitCatalogPage(payload),),
            Market.SPOT,
            observed_at_ns=_OBSERVED_NS,
        )


def test_ticker_turnover_keeps_decimal_precision_and_rejects_numeric_float() -> None:
    catalog = parse_instrument_pages(
        (BybitCatalogPage(_json("spot-instruments.json")),),
        Market.SPOT,
        observed_at_ns=_OBSERVED_NS,
    )
    turnover = parse_tickers(
        _json("ticker-sparse.json"),
        market=Market.SPOT,
        catalog=catalog,
        catalog_revision=1,
        observed_at_ns=_OBSERVED_NS + 1,
    )

    assert len(turnover.observations) == 1
    observation = turnover.observations[0]
    assert observation.value == Decimal("123456789.987654321012345678")
    assert observation.method is TurnoverMethod.EXCHANGE_QUOTE_TURNOVER
    assert observation.currency == "USDT"

    malformed = _object(deepcopy(_json("ticker-sparse.json")))
    ticker = _object(_array(_object(malformed["result"])["list"])[0])
    ticker["turnover24h"] = Decimal("1.25")
    with pytest.raises(BybitPayloadError, match="decimal string"):
        parse_tickers(
            malformed,
            market=Market.SPOT,
            catalog=catalog,
            catalog_revision=1,
            observed_at_ns=_OBSERVED_NS + 1,
        )


def test_catalog_known_precision_fields_reject_json_numbers() -> None:
    payload = _object(deepcopy(_json("spot-instruments.json")))
    row = _object(_array(_object(payload["result"])["list"])[0])
    lot_size = _object(row["lotSizeFilter"])
    lot_size["basePrecision"] = Decimal("0.000001")

    with pytest.raises(BybitPayloadError, match="decimal string"):
        parse_instrument_pages(
            (BybitCatalogPage(payload),),
            Market.SPOT,
            observed_at_ns=_OBSERVED_NS,
        )
