from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import cast

import httpx
import pytest

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.exchanges.binance.catalog import (
    instrument_by_key,
    parse_exchange_info,
    parse_rate_limits,
)
from crypto_collector.exchanges.binance.errors import (
    BinancePayloadError,
    BinanceResponseError,
    classify_binance_response,
)
from crypto_collector.exchanges.binance.rest import (
    FUTURES_AGG_TRADES_PATH,
    FUTURES_DEPTH_PATH,
    FUTURES_FUNDING_INFO_PATH,
    FUTURES_FUNDING_RATE_PATH,
    FUTURES_KLINES_PATH,
    FUTURES_OPEN_INTEREST_HISTORY_PATH,
    FUTURES_PRICE_PATH,
    SPOT_DEPTH_PATH,
    BinanceMarketRestPayload,
    BinanceRestCapture,
    BinanceRestRequest,
    bbo_request,
    book_request,
    candles_request,
    capture_binance_response,
    derivative_kline_request,
    derivative_reference_request,
    exchange_info_request,
    parse_asset_index,
    parse_bbo,
    parse_candles,
    parse_deep_book,
    parse_derivative_reference,
    parse_funding_info,
    parse_index_info,
    parse_insurance_fund,
    parse_price,
    parse_spot_reference,
    parse_ticker,
    parse_trades,
    parse_trading_schedule,
    price_request,
    spot_reference_request,
    ticker_request,
    trades_request,
)
from crypto_collector.exchanges.contracts import RestPlanItem
from crypto_collector.network import RetryAction
from crypto_collector.scheduler import IntervalPlan, RestDispatch, RestPriority

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "binance"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_SECOND = 1_000_000_000


def _json(name: str) -> object:
    return decode_json((_FIXTURES / name).read_bytes())


def _object(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def _array(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _instrument(market: Market):
    catalog = parse_exchange_info(
        _json(
            "spot-exchange-info.json"
            if market is Market.SPOT
            else "futures-exchange-info.json"
        ),
        market,
        observed_at_ns=1_770_000_000_000_000_000,
    )
    return instrument_by_key(catalog, "BTCUSDT")


def _dispatch(request: BinanceRestRequest) -> RestDispatch:
    instrument = _instrument(request.market)
    interval = IntervalPlan(30 * _SECOND, 30 * _SECOND, None)
    item = RestPlanItem(
        id="binance:test:rest",
        exchange=Exchange.BINANCE,
        market=request.market,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        endpoint=(
            "https://data-api.binance.vision"
            if request.market is Market.SPOT
            else "https://fapi.binance.com"
        ),
        path=request.path,
        params=request.params,
        egress_id="socks-a",
        shard_id="rest-0",
        logical_stream=request.logical_stream,
        quota_group="proxy-a",
        logical_endpoint=request.path.rsplit("/", 1)[-1],
        priority=RestPriority.REFERENCE_DATA,
        endpoint_cost=Decimal(max(1, request.request_weight)),
        interval_plan=interval,
        requires_generation=False,
        replaceable=True,
    )
    job = item.materialize(
        ready_monotonic_ns=10,
        scheduled_ns=20,
        attempt=2,
    )
    return RestDispatch(job=job, route=job.routes[0], dispatched_monotonic_ns=15)


def _capture(request: BinanceRestRequest, payload: object) -> BinanceRestCapture:
    return capture_binance_response(
        httpx.Response(200, content=encode_json(payload)),
        dispatch=_dispatch(request),
        request=request,
        request_started_at_ns=100,
        request_ended_at_ns=200,
    )


def test_fixture_manifest_pins_every_example_and_refreshed_source_digest() -> None:
    manifest = _object(_json("manifest.json"))
    entries = _array(manifest["entries"])

    assert {str(_object(entry)["file"]) for entry in entries} == {
        "spot-exchange-info.json",
        "futures-exchange-info.json",
        "spot-depth.json",
        "futures-depth.json",
        "ws-session.json",
    }
    for value in entries:
        entry = _object(value)
        fixture = _FIXTURES / str(entry["file"])
        source = _REPOSITORY_ROOT / str(entry["source_document"])
        assert sha256(fixture.read_bytes()).hexdigest() == entry["sha256"]
        assert (
            sha256(source.read_bytes()).hexdigest() == entry["source_document_sha256"]
        )
        for additional_value in _array(entry.get("additional_sources", [])):
            additional = _object(additional_value)
            path = _REPOSITORY_ROOT / str(additional["path"])
            assert sha256(path.read_bytes()).hexdigest() == additional["sha256"]


@pytest.mark.parametrize(
    ("limit", "weight"),
    [(100, 5), (101, 25), (500, 25), (501, 50), (1000, 50), (1001, 250), (5000, 250)],
)
def test_spot_depth_weights_are_exact_at_every_boundary(
    limit: int, weight: int
) -> None:
    request = BinanceRestRequest(
        Market.SPOT,
        SPOT_DEPTH_PATH,
        {"symbol": "BTCUSDT", "limit": limit},
        "book_deep_snapshot",
    )

    assert request.request_weight == weight


def test_top_twenty_full_spot_depth_at_30s_exceeds_live_minute_budget() -> None:
    request = BinanceRestRequest(
        Market.SPOT,
        SPOT_DEPTH_PATH,
        {"symbol": "BTCUSDT", "limit": 5000},
        "book_deep_snapshot",
    )
    live_limit = next(
        item.limit
        for item in parse_rate_limits(_json("spot-exchange-info.json"))
        if item.rate_limit_type == "REQUEST_WEIGHT" and item.interval == "MINUTE"
    )

    assert 20 * request.request_weight * 2 == 10_000
    assert 20 * request.request_weight * 2 > live_limit


@pytest.mark.parametrize(
    ("limit", "weight"),
    [(5, 2), (50, 2), (100, 5), (500, 10), (1000, 20)],
)
def test_futures_depth_weights_and_allowed_limits_are_exact(
    limit: int, weight: int
) -> None:
    request = BinanceRestRequest(
        Market.PERPETUAL,
        FUTURES_DEPTH_PATH,
        {"symbol": "BTCUSDT", "limit": limit},
        "book_deep_snapshot",
    )

    assert request.request_weight == weight


@pytest.mark.parametrize("limit", [1, 99, 100, 499, 500, 1000, 1001, 1500])
def test_futures_kline_weight_is_derived_from_requested_limit(limit: int) -> None:
    request = BinanceRestRequest(
        Market.PERPETUAL,
        FUTURES_KLINES_PATH,
        {"symbol": "BTCUSDT", "interval": "1m", "limit": limit},
        "candle_1m",
    )
    expected = 1 if limit < 100 else 2 if limit < 500 else 5 if limit <= 1000 else 10

    assert request.request_weight == expected


def test_current_futures_price_path_is_v2_and_old_path_is_rejected() -> None:
    request = BinanceRestRequest(
        Market.PERPETUAL,
        FUTURES_PRICE_PATH,
        {"symbol": "BTCUSDT"},
        "price",
    )

    assert request.path == "/fapi/v2/ticker/price"
    with pytest.raises(ValueError, match="not an evidenced"):
        BinanceRestRequest(
            Market.PERPETUAL,
            "/fapi/v1/ticker/price",
            {"symbol": "BTCUSDT"},
            "price",
        )


def test_funding_and_historical_oi_keep_special_ip_quota_evidence() -> None:
    funding = BinanceRestRequest(
        Market.PERPETUAL,
        FUTURES_FUNDING_RATE_PATH,
        {"symbol": "BTCUSDT"},
        "funding_rate",
    )
    info = BinanceRestRequest(
        Market.PERPETUAL,
        FUTURES_FUNDING_INFO_PATH,
        {},
        "funding_info",
    )
    oi = BinanceRestRequest(
        Market.PERPETUAL,
        FUTURES_OPEN_INTEREST_HISTORY_PATH,
        {"symbol": "BTCUSDT", "period": "5m"},
        "open_interest_history",
    )

    assert funding.special_quota == info.special_quota
    assert funding.special_quota is not None
    assert funding.special_quota.limit == 500
    assert funding.special_quota.window_seconds == 300
    assert info.request_weight == 0
    assert oi.special_quota is not None
    assert oi.special_quota.limit == 1000
    assert oi.request_weight == 0


def test_public_request_factories_preserve_market_and_logical_scope() -> None:
    spot = _instrument(Market.SPOT)
    futures = _instrument(Market.PERPETUAL)

    assert exchange_info_request(Market.SPOT).path == "/api/v3/exchangeInfo"
    assert exchange_info_request(Market.PERPETUAL).path == "/fapi/v1/exchangeInfo"
    assert book_request(spot, depth=5000).request_weight == 250
    bootstrap = book_request(
        futures,
        depth=1000,
        logical_stream="book_live_bootstrap",
    )
    assert bootstrap.logical_stream == "book_live_bootstrap"
    assert ticker_request(None, market=Market.PERPETUAL).request_weight == 40
    assert bbo_request(futures).request_weight == 2
    assert price_request(futures).path == "/fapi/v2/ticker/price"
    assert spot_reference_request("average_price", spot).request_weight == 2
    assert (
        spot_reference_request("reference_price", spot).path == "/api/v3/referencePrice"
    )
    assert spot_reference_request("execution_rules", spot).request_weight == 2
    assert candles_request(spot, interval="1m", limit=1000).request_weight == 2
    assert derivative_kline_request("index_candle", futures).params["pair"] == "BTCUSDT"
    assert derivative_kline_request("premium_candle", futures).request_weight == 5
    assert (
        derivative_reference_request("open_interest", futures).path
        == "/fapi/v1/openInterest"
    )


def test_asset_index_factory_uses_explicit_asset_pair_not_contract_symbol() -> None:
    futures = _instrument(Market.PERPETUAL)

    request = derivative_reference_request("asset_index", asset_pair="BTCUSD")

    assert request.params == {"symbol": "BTCUSD"}
    with pytest.raises(ValueError, match="asset pair"):
        derivative_reference_request("asset_index", futures)


def test_index_info_factory_uses_reference_identity_not_contract_catalog() -> None:
    futures = _instrument(Market.PERPETUAL)

    request = derivative_reference_request("index_info", index_symbol="SMALLUSDT")

    assert request.params == {"symbol": "SMALLUSDT"}
    with pytest.raises(ValueError, match="index symbol"):
        derivative_reference_request("index_info", futures)


def test_deep_book_parser_validates_fixture_and_preserves_exact_payload() -> None:
    spot = _instrument(Market.SPOT)
    futures = _instrument(Market.PERPETUAL)
    spot_request = book_request(spot, depth=5000)
    futures_request = book_request(futures, depth=1000)

    spot_draft = parse_deep_book(
        _capture(spot_request, _json("spot-depth.json")), instrument=spot
    )
    futures_draft = parse_deep_book(
        _capture(futures_request, _json("futures-depth.json")), instrument=futures
    )

    assert spot_draft.event_time_ns is None
    assert spot_draft.event_time_source is None
    assert spot_draft.payload == _json("spot-depth.json")
    assert futures_draft.event_time_ns == 1_589_436_922_972_000_000
    assert futures_draft.event_time_source == "binance.payload.E"
    assert futures_draft.coverage is not None
    with pytest.raises(BinanceResponseError):
        _capture(spot_request, {"code": -1121, "msg": "Invalid symbol"})
    with pytest.raises(BinancePayloadError, match="lastUpdateId"):
        parse_deep_book(_capture(spot_request, {}), instrument=spot)


def test_ticker_price_and_bbo_parsers_bind_response_symbol_and_time() -> None:
    spot = _instrument(Market.SPOT)
    futures = _instrument(Market.PERPETUAL)
    ticker_payload = {
        "symbol": "BTCUSDT",
        "lastPrice": "60000.1",
        "volume": "12.5",
        "quoteVolume": "750001.25",
        "openTime": 1_760_000_000_000,
        "closeTime": 1_760_086_400_000,
        "future": {"kept": True},
    }

    ticker = parse_ticker(
        _capture(ticker_request(spot, market=Market.SPOT), ticker_payload),
        instrument=spot,
    )
    spot_price = parse_price(
        _capture(price_request(spot), {"symbol": "BTCUSDT", "price": "60000.1"}),
        instrument=spot,
    )
    futures_bbo = parse_bbo(
        _capture(
            bbo_request(futures),
            {
                "symbol": "BTCUSDT",
                "bidPrice": "60000",
                "bidQty": "1.25",
                "askPrice": "60001",
                "askQty": "2.5",
                "time": 1_760_086_400_123,
                "st": 1,
            },
        ),
        instrument=futures,
    )

    assert ticker.event_time_ns == 1_760_086_400_000_000_000
    assert ticker.payload == ticker_payload
    assert spot_price.event_time_ns is None
    assert futures_bbo.event_time_source == "binance.payload.time"

    wrong = dict(ticker_payload, symbol="ETHUSDT")
    with pytest.raises(BinancePayloadError, match="symbol does not match"):
        parse_ticker(
            _capture(ticker_request(spot, market=Market.SPOT), wrong),
            instrument=spot,
        )


def test_trade_and_candle_parsers_preserve_native_time_semantics() -> None:
    spot = _instrument(Market.SPOT)
    aggregate = trades_request(spot, aggregate=True)
    trades = [
        {
            "a": 1,
            "p": "60000.1",
            "q": "0.1",
            "f": 10,
            "l": 11,
            "T": 1_760_000_000_123,
            "m": True,
            "future": "kept",
        }
    ]
    candle_row = [
        1_760_000_000_000,
        "60000",
        "60100",
        "59900",
        "60050",
        "10.5",
        1_760_000_059_999,
        "630525",
        100,
        "5.1",
        "306255",
        "0",
    ]

    trade = parse_trades(_capture(aggregate, trades), instrument=spot)
    candle = parse_candles(
        _capture(candles_request(spot), [candle_row]), instrument=spot
    )

    assert trade.event_time_ns == 1_760_000_000_123_000_000
    assert trade.event_time_source == "binance.payload[].T"
    assert trade.payload == trades
    assert candle.event_time_ns == 1_760_000_000_000_000_000
    assert candle.event_time_source == "binance.payload[][0]"

    malformed = [list(candle_row[:11])]
    with pytest.raises(BinancePayloadError, match="12 fields"):
        parse_candles(_capture(candles_request(spot), malformed), instrument=spot)


def test_spot_and_derivative_reference_parsers_bind_identity_and_source_time() -> None:
    spot = _instrument(Market.SPOT)
    futures = _instrument(Market.PERPETUAL)
    average = parse_spot_reference(
        _capture(
            spot_reference_request("average_price", spot),
            {"mins": 5, "price": "60000.1", "closeTime": 1_760_000_000_123},
        ),
        instrument=spot,
    )
    reference = parse_spot_reference(
        _capture(
            spot_reference_request("reference_price", spot),
            {
                "symbol": "BTCUSDT",
                "referencePrice": None,
                "timestamp": 1_760_000_000_456,
            },
        ),
        instrument=spot,
    )
    mark = parse_derivative_reference(
        _capture(
            derivative_reference_request("mark_price", futures),
            {
                "symbol": "BTCUSDT",
                "markPrice": "60000.1",
                "indexPrice": "59999.9",
                "time": 1_760_000_000_789,
                "st": 1,
                "future": "kept",
            },
        ),
        instrument=futures,
    )
    open_interest = parse_derivative_reference(
        _capture(
            derivative_reference_request("open_interest", futures),
            {
                "symbol": "BTCUSDT",
                "openInterest": "123.456",
                "time": 1_760_000_001_000,
            },
        ),
        instrument=futures,
    )
    insurance = parse_insurance_fund(
        _capture(
            derivative_reference_request("insurance_fund", futures),
            {
                "symbols": ["BTCUSDT", "ETHUSDT"],
                "assets": [
                    {
                        "asset": "USDT",
                        "marginBalance": "123456.789",
                        "updateTime": 1_760_000_002_000,
                    }
                ],
                "future": "kept",
            },
        )
    )
    adl = parse_derivative_reference(
        _capture(
            derivative_reference_request("adl_risk", futures),
            {
                "symbol": "BTCUSDT",
                "adlRisk": "2",
                "updateTime": 1_760_000_004_000,
            },
        ),
        instrument=futures,
    )

    assert average.event_time_source == "binance.payload.closeTime"
    assert reference.event_time_source == "binance.payload.timestamp"
    assert mark.event_time_source == "binance.payload[].time"
    assert _object(mark.payload)["future"] == "kept"
    assert open_interest.event_time_ns == 1_760_000_001_000_000_000
    assert insurance.identities == ("BTCUSDT", "ETHUSDT")
    assert insurance.event_time_source == "binance.payload[].assets[].updateTime"
    assert adl.event_time_source == "binance.payload[].updateTime"

    wrong_insurance = {
        "symbols": ["ETHUSDT"],
        "assets": [
            {
                "asset": "USDT",
                "marginBalance": "1",
                "updateTime": 1_760_000_002_000,
            }
        ],
    }
    with pytest.raises(BinancePayloadError, match="do not include"):
        parse_insurance_fund(
            _capture(
                derivative_reference_request("insurance_fund", futures),
                wrong_insurance,
            )
        )
    with pytest.raises(ValueError, match="instrument-scoped"):
        parse_derivative_reference(
            _capture(
                derivative_reference_request("insurance_fund", futures),
                {
                    "symbols": ["BTCUSDT"],
                    "assets": [
                        {
                            "asset": "USDT",
                            "marginBalance": "1",
                            "updateTime": 1_760_000_002_000,
                        }
                    ],
                },
            ),
            instrument=futures,
        )


def _asset_index_row(symbol: str, time: int) -> dict[str, object]:
    return {
        "symbol": symbol,
        "time": time,
        "index": "1.01",
        "bidBuffer": "0.01",
        "askBuffer": "0.02",
        "bidRate": "0.99",
        "askRate": "1.01",
        "autoExchangeBidBuffer": "0.03",
        "autoExchangeAskBuffer": "0.04",
        "autoExchangeBidRate": "0.98",
        "autoExchangeAskRate": "1.02",
        "future": "kept",
    }


def test_market_reference_parsers_validate_batch_identity_shape_and_time() -> None:
    funding_payload = [
        {
            "symbol": "BTCUSDT",
            "adjustedFundingRateCap": "0.025",
            "adjustedFundingRateFloor": "-0.025",
            "fundingIntervalHours": 8,
            "disclaimer": False,
            "updateTime": 1_760_000_004_500,
            "future": "kept",
        }
    ]
    funding = parse_funding_info(
        _capture(derivative_reference_request("funding_info"), funding_payload)
    )
    asset = parse_asset_index(
        _capture(
            derivative_reference_request("asset_index", asset_pair="BTCUSD"),
            _asset_index_row("BTCUSD", 1_760_000_005_000),
        )
    )
    index_info = parse_index_info(
        _capture(
            derivative_reference_request("index_info", index_symbol="SMALLUSDT"),
            [
                {
                    "symbol": "SMALLUSDT",
                    "time": 1_760_000_005_500,
                    "component": "baseAsset",
                    "baseAssetList": [
                        {
                            "baseAsset": "我踏马来了",
                            "quoteAsset": "USDT",
                            "weightInQuantity": "0.98650673",
                            "weightInPercentage": "0.01000000",
                        }
                    ],
                    "future": "kept",
                }
            ],
        )
    )
    schedule_payload = {
        "updateTime": 1_760_000_006_000,
        "marketSchedules": {
            "EQUITY": {
                "sessions": [
                    {
                        "startTime": 1_760_000_006_000,
                        "endTime": 1_760_000_007_000,
                        "type": "REGULAR",
                    }
                ]
            }
        },
        "future": "kept",
    }
    schedule = parse_trading_schedule(
        _capture(derivative_reference_request("trading_schedule"), schedule_payload)
    )

    assert funding.identities == ("BTCUSDT",)
    assert funding.payload == funding_payload
    assert funding.event_time_source == "binance.payload[].updateTime"
    assert asset.identities == ("BTCUSD",)
    assert asset.event_time_source == "binance.payload[].time"
    assert _object(asset.payload)["future"] == "kept"
    assert index_info.identities == ("SMALLUSDT",)
    assert index_info.event_time_source == "binance.payload[].time"
    assert schedule.identities == ()
    assert schedule.event_time_ns == 1_760_000_006_000_000_000
    assert schedule.payload == schedule_payload


def test_market_reference_batch_uses_only_a_uniform_exchange_time() -> None:
    payload = [
        _asset_index_row("BTCUSD", 1_760_000_005_000),
        _asset_index_row("ETHUSD", 1_760_000_005_001),
    ]

    parsed = parse_asset_index(
        _capture(derivative_reference_request("asset_index"), payload)
    )

    assert parsed.identities == ("BTCUSD", "ETHUSD")
    assert parsed.event_time_ns is None
    assert parsed.event_time_source is None


def test_market_reference_parsers_fail_closed_on_identity_shape_and_time() -> None:
    with pytest.raises(BinancePayloadError, match="does not match"):
        parse_asset_index(
            _capture(
                derivative_reference_request("asset_index", asset_pair="BTCUSD"),
                _asset_index_row("ETHUSD", 1_760_000_005_000),
            )
        )
    with pytest.raises(BinancePayloadError, match="overflows"):
        parse_asset_index(
            _capture(
                derivative_reference_request("asset_index", asset_pair="BTCUSD"),
                _asset_index_row("BTCUSD", 9_223_372_036_855),
            )
        )
    with pytest.raises(BinancePayloadError, match="marketSchedules"):
        parse_trading_schedule(
            _capture(
                derivative_reference_request("trading_schedule"),
                {"updateTime": 1_760_000_006_000, "marketSchedules": []},
            )
        )
    with pytest.raises(BinancePayloadError, match="follow startTime"):
        parse_trading_schedule(
            _capture(
                derivative_reference_request("trading_schedule"),
                {
                    "updateTime": 1_760_000_006_000,
                    "marketSchedules": {
                        "FUTURE_CATEGORY": {
                            "sessions": [
                                {
                                    "startTime": 1_760_000_007_000,
                                    "endTime": 1_760_000_006_000,
                                    "type": "FUTURE_SESSION_TYPE",
                                }
                            ]
                        }
                    },
                },
            )
        )
    with pytest.raises(BinancePayloadError, match="decimal string"):
        parse_funding_info(
            _capture(
                derivative_reference_request("funding_info"),
                [
                    {
                        "symbol": "BTCUSDT",
                        "adjustedFundingRateCap": 1,
                        "adjustedFundingRateFloor": "-0.025",
                        "fundingIntervalHours": 8,
                        "disclaimer": False,
                        "updateTime": 1_760_000_004_500,
                    }
                ],
            )
        )
    with pytest.raises(BinancePayloadError, match="updateTime"):
        parse_funding_info(
            _capture(
                derivative_reference_request("funding_info"),
                [
                    {
                        "symbol": "BTCUSDT",
                        "adjustedFundingRateCap": "0.025",
                        "adjustedFundingRateFloor": "-0.025",
                        "fundingIntervalHours": 8,
                        "disclaimer": False,
                    }
                ],
            )
        )


def test_market_rest_payload_rejects_invalid_public_event_time_contract() -> None:
    capture = _capture(
        derivative_reference_request("asset_index", asset_pair="BTCUSD"),
        _asset_index_row("BTCUSD", 1_760_000_005_000),
    )

    with pytest.raises(TypeError, match="event_time_ns"):
        BinanceMarketRestPayload(capture, ("BTCUSD",), True, "payload.time")
    with pytest.raises(ValueError, match="signed 64-bit"):
        BinanceMarketRestPayload(capture, ("BTCUSD",), -1, "payload.time")
    with pytest.raises(TypeError, match="non-empty string"):
        BinanceMarketRestPayload(capture, ("BTCUSD",), 1, "")


@pytest.mark.parametrize(
    ("parser", "request_factory", "payload"),
    [
        (
            parse_ticker,
            lambda item: ticker_request(item, market=Market.SPOT),
            {"symbol": "BTCUSDT"},
        ),
        (
            parse_price,
            price_request,
            {"symbol": "BTCUSDT", "price": 1.25},
        ),
        (
            parse_bbo,
            bbo_request,
            {"symbol": "BTCUSDT", "bidPrice": "1"},
        ),
    ],
)
def test_instrument_response_parsers_fail_closed_on_shape_drift(
    parser, request_factory, payload: object
) -> None:
    instrument = _instrument(Market.SPOT)

    with pytest.raises(BinancePayloadError):
        parser(_capture(request_factory(instrument), payload), instrument=instrument)


@pytest.mark.parametrize(
    ("parser", "request_factory", "payload"),
    [
        (
            parse_ticker,
            lambda item: ticker_request(item, market=Market.SPOT),
            {
                "symbol": "BTCUSDT",
                "lastPrice": "1",
                "volume": "-1",
                "quoteVolume": "1",
                "openTime": 1,
                "closeTime": 2,
            },
        ),
        (
            parse_price,
            price_request,
            {"symbol": "BTCUSDT", "price": "-1"},
        ),
    ],
)
def test_price_and_volume_responses_reject_negative_values(
    parser, request_factory, payload: object
) -> None:
    instrument = _instrument(Market.SPOT)

    with pytest.raises(BinancePayloadError, match="non-negative"):
        parser(_capture(request_factory(instrument), payload), instrument=instrument)


def test_open_interest_rejects_negative_but_funding_rate_may_be_negative() -> None:
    futures = _instrument(Market.PERPETUAL)
    with pytest.raises(BinancePayloadError, match="non-negative"):
        parse_derivative_reference(
            _capture(
                derivative_reference_request("open_interest", futures),
                {
                    "symbol": "BTCUSDT",
                    "openInterest": "-1",
                    "time": 1_760_000_000_000,
                },
            ),
            instrument=futures,
        )

    funding = parse_derivative_reference(
        _capture(
            derivative_reference_request("funding_rate", futures),
            [
                {
                    "symbol": "BTCUSDT",
                    "fundingRate": "-0.0001",
                    "fundingTime": 1_760_000_000_000,
                }
            ],
        ),
        instrument=futures,
    )

    assert funding.event_time_source == "binance.payload[].fundingTime"


@pytest.mark.parametrize(
    ("path", "params", "message"),
    [
        (SPOT_DEPTH_PATH, {"symbol": "BTCUSDT", "limit": 5001}, "between 1 and 5000"),
        (FUTURES_DEPTH_PATH, {"symbol": "BTCUSDT", "limit": 200}, "unsupported"),
        (
            FUTURES_AGG_TRADES_PATH,
            {"symbol": "BTCUSDT", "fromId": 1, "startTime": 2},
            "cannot accompany",
        ),
        (
            FUTURES_AGG_TRADES_PATH,
            {"symbol": "BTCUSDT", "startTime": 1, "endTime": 3_600_001},
            "under one hour",
        ),
        (SPOT_DEPTH_PATH, {"symbol": "BTCUSDT", "signature": "secret"}, "sensitive"),
        (SPOT_DEPTH_PATH, {"symbol": ["BTCUSDT"]}, "scalar"),
    ],
)
def test_direct_requests_fail_closed_on_invalid_or_sensitive_params(
    path: str, params: dict[str, object], message: str
) -> None:
    market = Market.SPOT if path.startswith("/api/") else Market.PERPETUAL
    with pytest.raises((TypeError, ValueError), match=message):
        BinanceRestRequest(market, path, params, "test")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (418, {"code": -1003, "msg": "IP banned"}, RetryAction.BAN),
        (429, {"code": -1003, "msg": "Too many requests"}, RetryAction.THROTTLE),
        (503, {"code": -1008, "msg": "Server busy"}, RetryAction.BACKOFF),
        (200, {"code": -1008, "msg": "Server busy"}, RetryAction.BACKOFF),
        (400, {"code": -1121, "msg": "Invalid symbol"}, RetryAction.DO_NOT_RETRY),
    ],
)
def test_http_and_business_failures_have_explicit_retry_actions(
    status: int, payload: dict[str, object], expected: RetryAction
) -> None:
    response = httpx.Response(
        status,
        content=encode_json(payload),
        headers={"Retry-After": "2"},
    )

    error = classify_binance_response(response)

    assert error is not None
    assert error.retry_action is expected
    assert error.retry_after == "2"
    assert error.raw_payload == payload


def test_capture_preserves_live_weight_headers_and_attaches_dispatch_evidence() -> None:
    request = bbo_request(_instrument(Market.SPOT))
    dispatch = _dispatch(request)
    response = httpx.Response(
        200,
        content=encode_json({"symbol": "BTCUSDT", "bidPrice": "1", "askPrice": "2"}),
        headers={"X-MBX-USED-WEIGHT-1M": "123", "Future-Header": "ignored"},
    )

    capture = capture_binance_response(
        response,
        dispatch=dispatch,
        request=request,
        request_started_at_ns=100,
        request_ended_at_ns=200,
    )

    assert capture.rest_metadata.attempt == 2
    assert capture.rest_metadata.rate_limit_headers == {"x-mbx-used-weight-1m": "123"}
    assert capture.source.egress_id == "socks-a"


def test_capture_converts_batch_symbol_params_to_json_arrays() -> None:
    request = BinanceRestRequest(
        Market.SPOT,
        "/api/v3/ticker/24hr",
        {"symbols": ["BTCUSDT", "ETHUSDT"]},
        "ticker",
    )
    dispatch = _dispatch(request)

    capture = capture_binance_response(
        httpx.Response(200, content=encode_json([])),
        dispatch=dispatch,
        request=request,
        request_started_at_ns=100,
        request_ended_at_ns=200,
    )

    assert request.params["symbols"] == '["BTCUSDT","ETHUSDT"]'
    assert capture.rest_metadata.params["symbols"] == '["BTCUSDT","ETHUSDT"]'
    wire = httpx.Request(
        "GET",
        "https://data-api.binance.vision" + request.path,
        params=request.params,
    )
    assert wire.url.params["symbols"] == '["BTCUSDT","ETHUSDT"]'


def test_permission_arrays_are_one_json_query_scalar() -> None:
    request = BinanceRestRequest(
        Market.SPOT,
        "/api/v3/exchangeInfo",
        {"permissions": ["MARGIN", "LEVERAGED"]},
        "instrument",
    )

    wire = httpx.Request(
        "GET",
        "https://data-api.binance.vision" + request.path,
        params=request.params,
    )

    assert wire.url.params.multi_items() == [("permissions", '["MARGIN","LEVERAGED"]')]


@pytest.mark.parametrize("time_zone", ["-12:00", "0", "05:45", "+14:00"])
def test_spot_kline_accepts_evidenced_time_zone_range(time_zone: str) -> None:
    request = BinanceRestRequest(
        Market.SPOT,
        "/api/v3/klines",
        {"symbol": "BTCUSDT", "interval": "1m", "timeZone": time_zone},
        "candle_1m",
    )

    assert request.params["timeZone"] == time_zone


@pytest.mark.parametrize("time_zone", ["-12:01", "+14:01", "15", "1:60", "UTC"])
def test_spot_kline_rejects_unsupported_time_zone(time_zone: str) -> None:
    with pytest.raises(ValueError, match="timeZone"):
        BinanceRestRequest(
            Market.SPOT,
            "/api/v3/klines",
            {"symbol": "BTCUSDT", "interval": "1m", "timeZone": time_zone},
            "candle_1m",
        )


def test_futures_rest_kline_rejects_one_second_common_definition_conflict() -> None:
    with pytest.raises(ValueError, match="unsupported Binance kline interval"):
        BinanceRestRequest(
            Market.PERPETUAL,
            FUTURES_KLINES_PATH,
            {"symbol": "BTCUSDT", "interval": "1s"},
            "candle_1s",
        )


def test_capture_error_keeps_request_and_egress_evidence() -> None:
    request = bbo_request(_instrument(Market.PERPETUAL))
    dispatch = _dispatch(request)

    with pytest.raises(BinanceResponseError) as raised:
        capture_binance_response(
            httpx.Response(
                429,
                content=encode_json({"code": -1003, "msg": "slow down"}),
                headers={"Retry-After": "3"},
            ),
            dispatch=dispatch,
            request=request,
            request_started_at_ns=100,
            request_ended_at_ns=200,
        )

    assert raised.value.rest_metadata is not None
    assert raised.value.rest_metadata.attempt == 2
    assert raised.value.source is not None
    assert raised.value.source.egress_id == "socks-a"
