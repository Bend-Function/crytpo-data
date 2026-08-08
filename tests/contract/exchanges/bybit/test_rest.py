from __future__ import annotations

from copy import deepcopy
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from crypto_collector.domain import (
    CoverageMode,
    IntegrityMode,
    Market,
    RestMetadata,
    SourceContext,
)
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges.bybit.catalog import (
    BybitCatalogChain,
    BybitCatalogPage,
    instrument_by_key,
    parse_instrument_chains,
    parse_instrument_pages,
)
from crypto_collector.exchanges.bybit.errors import BybitPayloadError
from crypto_collector.exchanges.bybit.rest import (
    BybitEndpoints,
    BybitRestCapture,
    BybitRestRequest,
    announcements_request,
    candles_request,
    deep_book_request,
    derivative_reference_request,
    full_book_request,
    instruments_request,
    parse_announcements,
    parse_book,
    parse_candles,
    parse_derivative_reference,
    parse_public_time_ns,
    parse_recent_trades,
    parse_reference_candles,
    parse_status,
    parse_ticker,
    public_time_request,
    recent_trades_request,
    reference_candles_request,
    rpi_book_request,
    status_request,
    tickers_request,
)
from crypto_collector.selection import InstrumentRecord

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "bybit"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_OBSERVED_NS = 1_786_248_010_000_000_000


def _fixture_bytes(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


def _json(name: str) -> object:
    return decode_json(_fixture_bytes(name))


def _object(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _array(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _spot_instrument() -> InstrumentRecord:
    catalog = parse_instrument_pages(
        (BybitCatalogPage(_json("spot-instruments.json")),),
        Market.SPOT,
        observed_at_ns=_OBSERVED_NS,
    )
    return instrument_by_key(catalog, "BTCUSDT")


def _linear_instrument() -> InstrumentRecord:
    catalog = parse_instrument_chains(
        (
            BybitCatalogChain(
                "Trading",
                (
                    BybitCatalogPage(_json("linear-trading-page-1.json")),
                    BybitCatalogPage(
                        _json("linear-trading-page-2.json"),
                        request_cursor="trading-page-2",
                    ),
                ),
            ),
            BybitCatalogChain(
                "PreLaunch",
                (BybitCatalogPage(_json("linear-prelaunch.json")),),
            ),
        ),
        Market.PERPETUAL,
        observed_at_ns=_OBSERVED_NS,
    ).snapshot
    return instrument_by_key(catalog, "BTCUSDT")


def _capture(
    request: BybitRestRequest,
    payload: object,
    *,
    source: SourceContext | None = None,
) -> BybitRestCapture:
    assert isinstance(payload, dict)
    return BybitRestCapture(
        payload=cast(dict[str, JsonPayload], payload),
        rest_metadata=RestMetadata(
            request_started_at_ns=100,
            request_ended_at_ns=200,
            method="GET",
            path=request.path,
            params=cast(dict[str, JsonPayload], dict(request.params)),
            status=200,
            attempt=1,
            rate_limit_headers={},
        ),
        source=source
        or SourceContext(
            connection_id=None,
            connection_generation=None,
            egress_id="direct",
        ),
        request=request,
    )


def _success(result: object, *, time: int = 1_786_248_010_000) -> dict[str, object]:
    return {
        "retCode": 0,
        "retMsg": "OK",
        "result": result,
        "retExtInfo": {},
        "time": time,
        "futureEnvelopeField": "preserved",
    }


def test_fixture_manifest_pins_each_example_to_its_refreshed_source() -> None:
    manifest = _object(_json("manifest.json"))
    entries = _array(manifest["entries"])
    actual = {path.name for path in _FIXTURES.iterdir() if path.name != "manifest.json"}
    manifested = {str(_object(entry)["file"]) for entry in entries}
    assert len(entries) == len(manifested)
    assert actual == manifested
    for value in entries:
        entry = _object(value)
        fixture = _FIXTURES / str(entry["file"])
        source = _REPOSITORY_ROOT / str(entry["source_document"])
        assert sha256(fixture.read_bytes()).hexdigest() == entry["sha256"]
        assert (
            sha256(source.read_bytes()).hexdigest() == entry["source_document_sha256"]
        )


def test_current_public_paths_are_case_sensitive_and_complete() -> None:
    assert BybitEndpoints.PRICE_LIMIT == "/v5/market/price-limit"
    assert BybitEndpoints.ADL_ALERT == "/v5/market/adlAlert"
    requests = (
        BybitRestRequest(
            BybitEndpoints.INSTRUMENTS, {"category": "spot"}, "instrument"
        ),
        BybitRestRequest(
            BybitEndpoints.INSTRUMENTS,
            {
                "category": "linear",
                "status": "Trading",
                "limit": 1_000,
                "cursor": "next",
            },
            "instrument",
        ),
        BybitRestRequest(BybitEndpoints.TICKERS, {"category": "spot"}, "ticker"),
        BybitRestRequest(
            BybitEndpoints.RECENT_TRADES,
            {"category": "spot", "symbol": "BTCUSDT", "limit": 60},
            "trade",
        ),
        BybitRestRequest(
            BybitEndpoints.KLINE,
            {"category": "spot", "symbol": "BTCUSDT", "interval": "1", "limit": 1_000},
            "candle_1",
        ),
        BybitRestRequest(
            BybitEndpoints.MARK_PRICE_KLINE,
            {"category": "linear", "symbol": "BTCUSDT", "interval": "D"},
            "mark_price_candle_D",
        ),
        BybitRestRequest(
            BybitEndpoints.INDEX_PRICE_KLINE,
            {"category": "linear", "symbol": "BTCUSDT", "interval": "W"},
            "index_price_candle_W",
        ),
        BybitRestRequest(
            BybitEndpoints.PREMIUM_INDEX_KLINE,
            {"category": "linear", "symbol": "BTCUSDT", "interval": "M"},
            "premium_candle_M",
        ),
        BybitRestRequest(
            BybitEndpoints.FUNDING_HISTORY,
            {"category": "linear", "symbol": "BTCUSDT", "limit": 200},
            "funding_rate",
        ),
        BybitRestRequest(
            BybitEndpoints.OPEN_INTEREST,
            {
                "category": "linear",
                "symbol": "BTCUSDT",
                "intervalTime": "1d",
                "limit": 200,
                "cursor": "next",
            },
            "open_interest",
        ),
        BybitRestRequest(
            BybitEndpoints.ACCOUNT_RATIO,
            {
                "category": "linear",
                "symbol": "BTCUSDT",
                "period": "4h",
                "limit": 500,
            },
            "account_ratio",
        ),
        BybitRestRequest(
            BybitEndpoints.ORDERBOOK,
            {"category": "linear", "symbol": "BTCUSDT", "limit": 1_000},
            "book_deep_snapshot",
        ),
        BybitRestRequest(
            BybitEndpoints.RPI_ORDERBOOK,
            {"category": "spot", "symbol": "BTCUSDT", "limit": 50},
            "book_deep_snapshot",
        ),
        BybitRestRequest(
            BybitEndpoints.FULL_ORDERBOOK,
            {"category": "spot", "symbol": "BTCUSDT"},
            "book_live_bootstrap",
        ),
        BybitRestRequest(BybitEndpoints.INSURANCE, {"coin": "USDT"}, "insurance_fund"),
        BybitRestRequest(
            BybitEndpoints.RISK_LIMIT,
            {"category": "linear", "symbol": "BTCUSDT"},
            "risk_limit",
        ),
        BybitRestRequest(
            BybitEndpoints.INDEX_COMPONENTS,
            {"indexName": "BTCUSDT"},
            "index_components",
        ),
        BybitRestRequest(
            BybitEndpoints.PRICE_LIMIT,
            {"category": "linear", "symbol": "BTCUSDT"},
            "price_limit",
        ),
        BybitRestRequest(BybitEndpoints.ADL_ALERT, {"symbol": "BTCUSDT"}, "adl_alert"),
        BybitRestRequest(BybitEndpoints.SYSTEM_STATUS, {"state": "ongoing"}, "status"),
        BybitRestRequest(BybitEndpoints.SERVER_TIME, {}, "_control"),
        BybitRestRequest(
            BybitEndpoints.ANNOUNCEMENTS,
            {"locale": "en-US", "page": 1, "limit": 20},
            "instrument",
        ),
    )
    assert {request.path for request in requests} == {
        value
        for name, value in vars(BybitEndpoints).items()
        if name.isupper() and type(value) is str
    }
    with pytest.raises(ValueError, match="not an evidenced"):
        BybitRestRequest("/v5/market/adl-alert", {}, "adl_alert")


@pytest.mark.parametrize(
    ("path", "params", "message"),
    [
        (BybitEndpoints.SERVER_TIME, {"unknown": "x"}, "unsupported"),
        (BybitEndpoints.TICKERS, {"category": "inverse"}, "unsupported Bybit category"),
        (
            BybitEndpoints.INSTRUMENTS,
            {"category": "spot", "status": "Trading"},
            "Spot instruments do not support",
        ),
        (
            BybitEndpoints.INSTRUMENTS,
            {"category": "spot", "limit": 1},
            "Spot instruments do not support",
        ),
        (
            BybitEndpoints.RECENT_TRADES,
            {"category": "spot", "symbol": "BTCUSDT", "limit": 61},
            "between 1 and 60",
        ),
        (
            BybitEndpoints.KLINE,
            {"category": "spot", "symbol": "BTCUSDT", "interval": "2"},
            "unsupported Bybit interval",
        ),
        (
            BybitEndpoints.OPEN_INTEREST,
            {"category": "linear", "symbol": "BTCUSDT", "intervalTime": "2h"},
            "unsupported Bybit intervalTime",
        ),
        (
            BybitEndpoints.ORDERBOOK,
            {"category": "spot", "symbol": "BTCUSDT", "limit": 1_001},
            "between 1 and 1000",
        ),
        (
            BybitEndpoints.RPI_ORDERBOOK,
            {"category": "spot", "symbol": "BTCUSDT", "limit": 51},
            "between 1 and 50",
        ),
        (
            BybitEndpoints.FULL_ORDERBOOK,
            {"category": "spot", "symbol": "BTCUSDT", "limit": 10_000},
            "unsupported",
        ),
        (
            BybitEndpoints.PRICE_LIMIT,
            {"category": "linear", "symbol": "btcusdt"},
            "uppercase ASCII",
        ),
        (
            BybitEndpoints.TICKERS,
            {"category": "spot", "api_key": "secret"},
            "sensitive",
        ),
        (
            BybitEndpoints.ANNOUNCEMENTS,
            {"locale": "en-US", "page": 0},
            "between 1",
        ),
        (
            BybitEndpoints.ANNOUNCEMENTS,
            {"locale": "en-US", "limit": 51},
            "between 1 and 50",
        ),
    ],
)
def test_request_schema_rejects_wrong_paths_params_and_bounds(
    path: str,
    params: dict[str, object],
    message: str,
) -> None:
    with pytest.raises((TypeError, ValueError), match=message):
        BybitRestRequest(path, cast(dict, params), "test")


@pytest.mark.parametrize(
    ("path", "params"),
    [
        (BybitEndpoints.KLINE, {"symbol": "BTCUSDT", "interval": "1"}),
        (BybitEndpoints.MARK_PRICE_KLINE, {"symbol": "BTCUSDT", "interval": "1"}),
        (BybitEndpoints.INDEX_PRICE_KLINE, {"symbol": "BTCUSDT", "interval": "1"}),
        (
            BybitEndpoints.PREMIUM_INDEX_KLINE,
            {"symbol": "BTCUSDT", "interval": "1"},
        ),
        (BybitEndpoints.RPI_ORDERBOOK, {"symbol": "BTCUSDT", "limit": 50}),
        (BybitEndpoints.PRICE_LIMIT, {"symbol": "BTCUSDT"}),
    ],
)
def test_every_category_aware_request_requires_explicit_category(
    path: str,
    params: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="requires category"):
        BybitRestRequest(path, cast(dict, params), "test")


def test_funding_time_window_rejects_start_only_but_accepts_documented_forms() -> None:
    base: dict[str, object] = {"category": "linear", "symbol": "BTCUSDT"}
    with pytest.raises(ValueError, match="startTime requires endTime"):
        BybitRestRequest(
            BybitEndpoints.FUNDING_HISTORY,
            cast(dict, {**base, "startTime": 1}),
            "funding_rate",
        )

    for timestamps in ({"endTime": 2}, {"startTime": 1, "endTime": 2}):
        request = BybitRestRequest(
            BybitEndpoints.FUNDING_HISTORY,
            cast(dict, {**base, **timestamps}),
            "funding_rate",
        )
        assert request.params["endTime"] == 2


def test_price_limit_is_linear_only() -> None:
    with pytest.raises(ValueError, match="requires linear category"):
        BybitRestRequest(
            BybitEndpoints.PRICE_LIMIT,
            {"category": "spot", "symbol": "BTCUSDT"},
            "price_limit",
        )


def test_builders_keep_spot_single_page_and_linear_status_explicit() -> None:
    assert instruments_request(Market.SPOT).params == {"category": "spot"}
    with pytest.raises(ValueError, match="do not support status"):
        instruments_request(Market.SPOT, status="Trading")
    with pytest.raises(ValueError, match="requires Trading or PreLaunch"):
        instruments_request(Market.PERPETUAL)
    assert instruments_request(Market.PERPETUAL, status="Trading").params == {
        "category": "linear",
        "status": "Trading",
        "limit": 1_000,
    }
    assert instruments_request(
        Market.PERPETUAL,
        status="PreLaunch",
        cursor="next",
        limit=500,
    ).params == {
        "category": "linear",
        "status": "PreLaunch",
        "limit": 500,
        "cursor": "next",
    }


def test_instrument_builders_bind_exact_category_symbol_and_depths() -> None:
    spot = _spot_instrument()
    linear = _linear_instrument()
    assert tickers_request(Market.SPOT, symbol="BTCUSDT").params == {
        "category": "spot",
        "symbol": "BTCUSDT",
    }
    assert recent_trades_request(spot).params["limit"] == 60
    assert recent_trades_request(linear).params["limit"] == 1_000
    assert candles_request(spot, interval="D").logical_stream == "candle_D"
    assert deep_book_request(spot).params["limit"] == 1_000
    assert rpi_book_request(spot).params["limit"] == 50
    assert full_book_request(spot).logical_stream == "book_live_bootstrap"
    assert derivative_reference_request("price_limit", linear).path == (
        "/v5/market/price-limit"
    )
    assert derivative_reference_request("adl_alert", linear).path == (
        "/v5/market/adlAlert"
    )
    assert derivative_reference_request("insurance_fund", linear).params == {
        "coin": "USDT"
    }


def test_sparse_ticker_is_preserved_without_synthesizing_derivative_fields() -> None:
    instrument = _spot_instrument()
    request = tickers_request(Market.SPOT, symbol="BTCUSDT")
    draft = parse_ticker(
        _capture(request, _json("ticker-sparse.json")),
        instrument=instrument,
    )
    payload = _object(draft.payload)
    ticker = _object(_array(_object(payload["result"])["list"])[0])

    assert ticker["lastPrice"] == "100000.123456789012345678"
    assert "openInterest" not in ticker
    assert "fundingRate" not in ticker
    assert ticker["futureTickerField"] == {"keep": True}

    malformed = _object(deepcopy(_json("ticker-sparse.json")))
    row = _object(_array(_object(malformed["result"])["list"])[0])
    row["lastPrice"] = Decimal("1.25")
    with pytest.raises(BybitPayloadError, match="string when present"):
        parse_ticker(_capture(request, malformed), instrument=instrument)


@pytest.mark.parametrize(
    ("builder", "fixture", "fields_per_level"),
    [
        (lambda item: deep_book_request(item), "book-standard-rest.json", 2),
        (lambda item: rpi_book_request(item), "book-rpi-rest.json", 3),
        (
            lambda item: full_book_request(
                item,
                logical_stream="book_deep_snapshot",
            ),
            "book-full-rest.json",
            2,
        ),
    ],
)
def test_all_rest_book_shapes_are_exact_snapshots(
    builder,
    fixture: str,
    fields_per_level: int,
) -> None:
    instrument = _spot_instrument()
    request = builder(instrument)
    draft = parse_book(_capture(request, _json(fixture)), instrument=instrument)
    result = _object(_object(draft.payload)["result"])

    assert len(_array(result["b"])[0]) == fields_per_level
    assert draft.integrity_mode is IntegrityMode.SNAPSHOT_CHAIN
    assert draft.coverage is CoverageMode.UNKNOWN
    assert draft.event_time_source == "bybit.result.ts"

    malformed = _object(deepcopy(_json(fixture)))
    bad_result = _object(malformed["result"])
    _array(bad_result["b"])[0] = ["1", Decimal(2)]
    with pytest.raises(BybitPayloadError, match="decimal strings"):
        parse_book(_capture(request, malformed), instrument=instrument)


def test_book_request_category_must_match_instrument_before_payload_parsing() -> None:
    spot = _spot_instrument()
    linear_request = deep_book_request(_linear_instrument())
    malformed_payload = _success({})

    with pytest.raises(BybitPayloadError, match="category does not match"):
        parse_book(_capture(linear_request, malformed_payload), instrument=spot)


def test_book_string_limit_is_normalized_before_depth_comparison() -> None:
    instrument = _spot_instrument()
    request = BybitRestRequest(
        BybitEndpoints.ORDERBOOK,
        {"category": "spot", "symbol": "BTCUSDT", "limit": "1"},
        "book_deep_snapshot",
    )
    parse_book(
        _capture(request, _json("book-standard-rest.json")),
        instrument=instrument,
    )

    too_deep = _object(deepcopy(_json("book-standard-rest.json")))
    _object(too_deep["result"])["b"] = [["2", "1"], ["1", "1"]]
    with pytest.raises(BybitPayloadError, match="1-level bound"):
        parse_book(_capture(request, too_deep), instrument=instrument)


def test_book_prices_are_positive_quantities_allow_zero_and_ids_are_strict() -> None:
    instrument = _spot_instrument()
    request = deep_book_request(instrument)

    zero_quantity = _object(deepcopy(_json("book-standard-rest.json")))
    result = _object(zero_quantity["result"])
    _array(_array(result["b"])[0])[1] = "0"
    parse_book(_capture(request, zero_quantity), instrument=instrument)

    zero_price = _object(deepcopy(zero_quantity))
    _array(_array(_object(zero_price["result"])["b"])[0])[0] = "0"
    with pytest.raises(BybitPayloadError, match="price must be positive"):
        parse_book(_capture(request, zero_price), instrument=instrument)

    for field, value in (
        ("u", 0),
        ("seq", True),
        ("ts", "1786248011000"),
        ("cts", None),
    ):
        malformed = _object(deepcopy(_json("book-standard-rest.json")))
        _object(malformed["result"])[field] = value
        with pytest.raises(BybitPayloadError, match=field):
            parse_book(_capture(request, malformed), instrument=instrument)


def test_full_rest_book_enforces_evidenced_ten_thousand_level_ceiling() -> None:
    instrument = _spot_instrument()
    request = full_book_request(instrument, logical_stream="book_deep_snapshot")
    malformed = _object(deepcopy(_json("book-full-rest.json")))
    _object(malformed["result"])["b"] = [["1", "0"] for _ in range(10_001)]
    with pytest.raises(BybitPayloadError, match="10000-level bound"):
        parse_book(_capture(request, malformed), instrument=instrument)


def test_recent_trades_and_trade_kline_validate_known_rows_and_event_time() -> None:
    instrument = _spot_instrument()
    trades = parse_recent_trades(
        _capture(recent_trades_request(instrument), _json("recent-trades.json")),
        instrument=instrument,
    )
    candle = parse_candles(
        _capture(candles_request(instrument), _json("kline.json")),
        instrument=instrument,
    )

    assert trades.event_time_ns == 1_786_248_013_000_000_000
    assert trades.event_time_source == "bybit.result.list[0].time"
    assert candle.event_time_ns == 1_786_248_000_000_000_000
    assert candle.event_time_source == "bybit.result.list[0][0]"

    malformed = _object(deepcopy(_json("kline.json")))
    _array(_array(_object(malformed["result"])["list"])[0]).pop()
    with pytest.raises(BybitPayloadError, match="at least 7"):
        parse_candles(
            _capture(candles_request(instrument), malformed),
            instrument=instrument,
        )

    malformed_trade = _object(deepcopy(_json("recent-trades.json")))
    trade_row = _object(_array(_object(malformed_trade["result"])["list"])[0])
    trade_row["price"] = "not-a-decimal"
    with pytest.raises(BybitPayloadError, match="decimal string"):
        parse_recent_trades(
            _capture(recent_trades_request(instrument), malformed_trade),
            instrument=instrument,
        )


def test_reference_price_klines_use_path_specific_five_string_schema() -> None:
    instrument = _linear_instrument()
    for stream in ("mark_price", "index_price", "premium"):
        request = reference_candles_request(stream, instrument, interval="15")
        payload = _success(
            {
                "category": "linear",
                "symbol": "BTCUSDT",
                "list": [["1786248000000", "1", "2", "0.5", "1.5"]],
                "futureResultField": True,
            }
        )
        draft = parse_reference_candles(
            _capture(request, payload),
            instrument=instrument,
        )
        assert draft.event_time_ns == 1_786_248_000_000_000_000
        assert draft.logical_stream == f"{stream}_candle_15"


def _reference_payload(stream: str) -> dict[str, object]:
    if stream == "funding_rate":
        return _success(
            {
                "category": "linear",
                "list": [
                    {
                        "symbol": "BTCUSDT",
                        "fundingRate": "-0.0001",
                        "fundingRateTimestamp": "1786248000000",
                    }
                ],
            }
        )
    if stream == "open_interest":
        return _success(
            {
                "category": "linear",
                "symbol": "BTCUSDT",
                "list": [
                    {
                        "openInterest": "123.456789",
                        "singleOpenInterest": "61.7283945",
                        "timestamp": "1786248000000",
                    }
                ],
                "nextPageCursor": "next",
            }
        )
    if stream == "account_ratio":
        return _success(
            {
                "list": [
                    {
                        "symbol": "BTCUSDT",
                        "buyRatio": "0.49",
                        "sellRatio": "0.51",
                        "timestamp": "1786248000000",
                    }
                ],
                "nextPageCursor": "next",
            }
        )
    if stream == "price_limit":
        return _success(
            {
                "symbol": "BTCUSDT",
                "buyLmt": "101000.1",
                "sellLmt": "99000.9",
                "ts": "1786248000000",
            }
        )
    if stream == "adl_alert":
        return _success(
            {
                "updatedTime": "1786248000000",
                "list": [
                    {
                        "coin": "USDT",
                        "symbol": "BTCUSDT",
                        "balance": "1000000.1",
                        "maxBalance": "",
                        "insurancePnlRatio": "-0.3",
                        "pnlRatio": "-0.4",
                        "adlTriggerThreshold": "10000",
                        "adlStopRatio": "-0.25",
                    }
                ],
            }
        )
    if stream == "insurance_fund":
        return _success(
            {
                "updatedTime": "1786248000000",
                "list": [
                    {
                        "coin": "USDT",
                        "symbols": "BTCUSDT,ETHUSDT",
                        "balance": "1000000.123456789",
                        "value": "999999.987654321",
                    }
                ],
            }
        )
    if stream == "risk_limit":
        return _success(
            {
                "category": "linear",
                "list": [
                    {
                        "id": 1,
                        "symbol": "BTCUSDT",
                        "riskLimitValue": "2000000",
                        "maintenanceMargin": "0.005",
                        "initialMargin": "0.01",
                        "isLowestRisk": 1,
                        "maxLeverage": "100",
                        "mmDeduction": "",
                    }
                ],
                "nextPageCursor": "",
            }
        )
    if stream == "index_components":
        return _success(
            {
                "indexName": "BTCUSDT",
                "lastPrice": "100000.1",
                "updateTime": "1786248000000",
                "components": [
                    {
                        "exchange": "Bybit",
                        "spotPair": "BTCUSDT",
                        "equivalentPrice": "100000.1",
                        "multiplier": "1",
                        "price": "100000.1",
                        "weight": "0.5",
                    }
                ],
            }
        )
    raise AssertionError(stream)


@pytest.mark.parametrize(
    "stream",
    [
        "funding_rate",
        "open_interest",
        "account_ratio",
        "price_limit",
        "adl_alert",
        "insurance_fund",
        "risk_limit",
        "index_components",
    ],
)
def test_each_derivative_reference_parser_rejects_schema_drift_and_keeps_raw(
    stream: str,
) -> None:
    instrument = _linear_instrument()
    request = derivative_reference_request(stream, instrument)
    payload = _reference_payload(stream)
    draft = parse_derivative_reference(
        _capture(request, payload),
        instrument=instrument,
    )

    assert draft.logical_stream == stream
    assert _object(draft.payload)["futureEnvelopeField"] == "preserved"
    if stream not in {"risk_limit"}:
        assert draft.event_time_ns == 1_786_248_000_000_000_000
    else:
        assert draft.event_time_ns is None


def test_risk_limit_boolean_does_not_pass_as_integer_schema() -> None:
    instrument = _linear_instrument()
    payload = _reference_payload("risk_limit")
    row = _object(_array(_object(payload["result"])["list"])[0])
    row["isLowestRisk"] = True
    with pytest.raises(BybitPayloadError, match="must be 0 or 1"):
        parse_derivative_reference(
            _capture(derivative_reference_request("risk_limit", instrument), payload),
            instrument=instrument,
        )


def test_exact_symbol_adl_allows_empty_but_rejects_foreign_results() -> None:
    instrument = _linear_instrument()
    payload = _reference_payload("adl_alert")
    _object(payload["result"])["list"] = []
    parse_derivative_reference(
        _capture(derivative_reference_request("adl_alert", instrument), payload),
        instrument=instrument,
    )

    _object(payload["result"])["list"] = [{"symbol": "ETHUSDT"}]
    with pytest.raises(BybitPayloadError, match="different symbol"):
        parse_derivative_reference(
            _capture(derivative_reference_request("adl_alert", instrument), payload),
            instrument=instrument,
        )


def test_insurance_allows_empty_but_rejects_foreign_coin_results() -> None:
    instrument = _linear_instrument()
    payload = _reference_payload("insurance_fund")
    _object(payload["result"])["list"] = []
    parse_derivative_reference(
        _capture(
            derivative_reference_request("insurance_fund", instrument),
            payload,
        ),
        instrument=instrument,
    )

    _object(payload["result"])["list"] = [{"coin": "USDC"}]
    with pytest.raises(BybitPayloadError, match="insurance response"):
        parse_derivative_reference(
            _capture(
                derivative_reference_request("insurance_fund", instrument),
                payload,
            ),
            instrument=instrument,
        )


def test_insurance_request_coin_must_match_instrument_settlement_asset() -> None:
    instrument = _linear_instrument()
    request = BybitRestRequest(
        BybitEndpoints.INSURANCE,
        {"coin": "USDC"},
        "insurance_fund",
    )
    payload = _reference_payload("insurance_fund")
    row = _object(_array(_object(payload["result"])["list"])[0])
    row["coin"] = "USDC"

    with pytest.raises(BybitPayloadError, match="settlement asset"):
        parse_derivative_reference(
            _capture(request, payload),
            instrument=instrument,
        )


def test_status_time_and_announcements_have_independent_strict_schemas() -> None:
    status_payload = _success(
        {
            "list": [
                {
                    "id": "maintenance-1",
                    "title": "System maintenance",
                    "state": "completed",
                    "begin": "1786248000000",
                    "end": "1786248060000",
                    "href": "",
                    "serviceTypes": [1, 2],
                    "product": [1],
                    "uidSuffix": [],
                    "maintainType": 1,
                    "env": 1,
                }
            ]
        }
    )
    status = parse_status(
        _capture(status_request(), status_payload),
        market=Market.SPOT,
    )
    assert status.coverage is CoverageMode.UNKNOWN
    assert status.instrument_key is None

    time_payload = _success(
        {
            "timeSecond": "1786248000",
            "timeNano": "1786248000123456789",
        }
    )
    assert (
        parse_public_time_ns(_capture(public_time_request(), time_payload))
        == 1_786_248_000_123_456_789
    )

    announcement_payload = _success(
        {
            "total": 1,
            "list": [
                {
                    "title": "New listing",
                    "description": "A new market",
                    "type": {"title": "New Listings", "key": "new_crypto"},
                    "tags": ["Spot", "Spot Listings"],
                    "url": "https://announcements.bybit.com/example",
                    "dateTimestamp": 1786248000000,
                    "publishTime": 1786248000000,
                }
            ],
        }
    )
    announcement = parse_announcements(
        _capture(announcements_request(), announcement_payload),
        market=Market.SPOT,
    )
    assert announcement.logical_stream == "instrument"
    assert announcement.event_time_source == "bybit.result.list[0].publishTime"

    sparse_announcement = parse_announcements(
        _capture(
            announcements_request(),
            _success({"total": 1, "list": [{"futureField": "preserved"}]}),
        ),
        market=Market.SPOT,
    )
    assert sparse_announcement.event_time_ns is None
    sparse_row = _object(
        _array(_object(_object(sparse_announcement.payload)["result"])["list"])[0]
    )
    assert sparse_row["futureField"] == "preserved"

    string_status = _object(deepcopy(status_payload))
    string_status_row = _object(_array(_object(string_status["result"])["list"])[0])
    string_status_row["maintainType"] = "maintenance"
    string_status_row["env"] = "production"
    parse_status(_capture(status_request(), string_status), market=Market.SPOT)

    malformed_announcement = _object(deepcopy(announcement_payload))
    malformed_row = _object(
        _array(_object(malformed_announcement["result"])["list"])[0]
    )
    malformed_row["tags"] = "Spot"
    with pytest.raises(BybitPayloadError, match="tags must be a string array"):
        parse_announcements(
            _capture(announcements_request(), malformed_announcement),
            market=Market.SPOT,
        )

    malformed_time = _success(
        {"timeSecond": "1786248001", "timeNano": "1786248000123456789"}
    )
    with pytest.raises(BybitPayloadError, match="same second"):
        parse_public_time_ns(_capture(public_time_request(), malformed_time))
