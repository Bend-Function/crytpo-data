from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import cast

import httpx
import pytest

from crypto_collector.domain import (
    CoverageMode,
    IntegrityMode,
    Market,
    RestMetadata,
    SourceContext,
)
from crypto_collector.domain.json_codec import (
    JsonPayload,
    ValidatedJsonPayload,
    decode_json,
    encode_json,
)
from crypto_collector.exchanges.kraken import (
    KrakenApi,
    KrakenPayloadError,
    KrakenRestCapture,
    KrakenRestRequest,
    capture_kraken_response,
    classify_kraken_response,
    futures_analytics_request,
    futures_candles_request,
    futures_orderbook_request,
    futures_status_request,
    futures_tickers_request,
    instrument_by_key,
    parse_futures_deep_book,
    parse_futures_instruments,
    parse_futures_market_event,
    parse_spot_deep_book,
    parse_spot_market_event,
    parse_spot_pairs,
    parse_status,
    spot_depth_request,
    spot_status_request,
    spot_trades_request,
)
from crypto_collector.network import RetryAction, parse_retry_after_ns
from crypto_collector.scheduler import (
    RestBudgetRoute,
    RestDispatch,
    RestJob,
    RestPriority,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "kraken"
_OBSERVED = 1_786_200_000_000_000_000


def _json(name: str) -> object:
    return decode_json((_FIXTURES / name).read_bytes())


def _spot_instrument():
    return instrument_by_key(
        parse_spot_pairs(_json("spot-pairs.json"), observed_at_ns=_OBSERVED),
        "BTC/USDT",
    )


def _futures_instrument():
    return instrument_by_key(
        parse_futures_instruments(
            _json("futures-instruments.json"),
            tickers_payload=_json("futures-tickers.json"),
            observed_at_ns=_OBSERVED,
        ),
        "PF_XBTUSD",
    )


def _capture(
    payload: Mapping[str, JsonPayload], request: KrakenRestRequest
) -> KrakenRestCapture:
    return KrakenRestCapture(
        payload=payload,
        rest_metadata=RestMetadata(
            request_started_at_ns=10,
            request_ended_at_ns=20,
            method="GET",
            path=request.path,
            params=cast(dict[str, ValidatedJsonPayload], dict(request.params)),
            status=200,
            attempt=1,
            rate_limit_headers={},
        ),
        source=SourceContext(
            connection_id=None,
            connection_generation=None,
            egress_id="direct",
        ),
        request=request,
    )


def _dispatch(*, logical_key: tuple[str, ...]) -> RestDispatch:
    route = RestBudgetRoute(
        egress_id="direct",
        budget_key=("kraken", "public", "trades"),
    )
    job = RestJob(
        id="kraken-rest",
        priority=RestPriority.REFERENCE_DATA,
        routes=(route,),
        endpoint_cost=Decimal(1),
        ready_monotonic_ns=0,
        deadline_ns=None,
        interval=None,
        generation_source=None,
        attempt=1,
        logical_key=logical_key,
        replaceable=False,
        scheduled_ns=0,
        control_context={},
    )
    return RestDispatch(job=job, route=route, dispatched_monotonic_ns=0)


@pytest.mark.parametrize(
    ("api", "payload", "expected"),
    [
        (
            KrakenApi.SPOT,
            {"error": ["EAPI:Rate limit exceeded"]},
            RetryAction.THROTTLE,
        ),
        (
            KrakenApi.SPOT,
            {"error": ["EService: Throttled: 1786200000"]},
            RetryAction.THROTTLE,
        ),
        (
            KrakenApi.SPOT,
            {"error": ["EService:Unavailable"]},
            RetryAction.BACKOFF,
        ),
        (
            KrakenApi.SPOT,
            {"error": ["EService:Busy"]},
            RetryAction.BACKOFF,
        ),
        (
            KrakenApi.SPOT,
            {"error": ["EGeneral:Internal error"]},
            RetryAction.BACKOFF,
        ),
        (
            KrakenApi.FUTURES,
            {"result": "error", "error": "apiLimitExceeded"},
            RetryAction.THROTTLE,
        ),
        (
            KrakenApi.FUTURES,
            {"result": "error", "error": "invalidArgument"},
            RetryAction.DO_NOT_RETRY,
        ),
        (
            KrakenApi.FUTURES,
            {"result": "error", "error": "Server Error"},
            RetryAction.BACKOFF,
        ),
        (
            KrakenApi.FUTURES,
            {"result": "error", "error": "Unavailable"},
            RetryAction.BACKOFF,
        ),
        (
            KrakenApi.CHARTS,
            {
                "result": None,
                "errors": [
                    {
                        "severity": "E",
                        "error_class": "General",
                        "type": "Invalid arguments",
                        "msg": None,
                        "value": None,
                        "field": "interval",
                    }
                ],
            },
            RetryAction.DO_NOT_RETRY,
        ),
    ],
)
def test_business_errors_are_classified_before_http_success(
    api: KrakenApi,
    payload: dict[str, object],
    expected: RetryAction,
) -> None:
    error = classify_kraken_response(
        httpx.Response(200, content=encode_json(payload)),
        api=api,
    )

    assert error is not None
    assert error.retry_action is expected
    assert error.raw_payload == payload


def test_spot_business_throttle_preserves_absolute_retry_deadline() -> None:
    error = classify_kraken_response(
        httpx.Response(
            200,
            content=b'{"error":["EService: Throttled: 1786200000"]}',
        ),
        api=KrakenApi.SPOT,
    )

    assert error is not None
    assert error.retry_action is RetryAction.THROTTLE
    assert error.retry_after is not None
    assert not error.retry_after.isdecimal()
    assert (
        parse_retry_after_ns(
            error.retry_after,
            now_unix_ns=1_786_199_990_000_000_000,
        )
        == 10_000_000_000
    )


def test_success_envelopes_are_protocol_specific() -> None:
    spot = classify_kraken_response(
        httpx.Response(200, content=b'{"error":[],"result":{}}'),
        api=KrakenApi.SPOT,
    )
    futures = classify_kraken_response(
        httpx.Response(200, content=b'{"result":"success","tickers":[]}'),
        api=KrakenApi.FUTURES,
    )
    charts = classify_kraken_response(
        httpx.Response(200, content=b'{"candles":[],"more_candles":false}'),
        api=KrakenApi.CHARTS,
    )

    assert spot is None
    assert futures is None
    assert charts is None


def test_capture_constructor_rejects_unsuccessful_business_envelopes() -> None:
    spot_request = spot_trades_request(_spot_instrument())
    futures_request = futures_orderbook_request(_futures_instrument())
    charts_request = futures_analytics_request(
        _futures_instrument(),
        analytics_type="open-interest",
        since=1,
        interval=300,
    )

    with pytest.raises(ValueError, match="Spot capture"):
        _capture({"error": ["EAPI:Rate limit exceeded"]}, spot_request)
    with pytest.raises(ValueError, match="Futures capture"):
        _capture({"result": "error", "error": "invalidArgument"}, futures_request)
    with pytest.raises(ValueError, match="Charts capture"):
        _capture(
            {
                "result": None,
                "errors": [
                    {
                        "severity": "E",
                        "error_class": "General",
                        "type": "Invalid arguments",
                        "msg": None,
                        "value": None,
                        "field": "interval",
                    }
                ],
            },
            charts_request,
        )


def test_charts_object_error_keeps_native_code_and_field() -> None:
    payload = {
        "result": None,
        "errors": [
            {
                "severity": "E",
                "error_class": "General",
                "type": "Invalid arguments",
                "msg": None,
                "value": None,
                "field": "interval",
            }
        ],
    }

    error = classify_kraken_response(
        httpx.Response(400, content=encode_json(payload)),
        api=KrakenApi.CHARTS,
    )

    assert error is not None
    assert error.exchange_code == "General:Invalid arguments"
    assert error.exchange_message == "Invalid arguments (field=interval)"
    assert error.raw_payload == payload


def test_invalid_json_and_http_failure_never_become_success() -> None:
    invalid = classify_kraken_response(
        httpx.Response(200, content=b"not-json"),
        api=KrakenApi.SPOT,
    )
    unavailable = classify_kraken_response(
        httpx.Response(503, content=b'{"result":"error","error":"serverError"}'),
        api=KrakenApi.FUTURES,
    )

    assert invalid is not None
    assert invalid.exchange_code == "invalid_json"
    assert invalid.retry_action is RetryAction.DO_NOT_RETRY
    assert unavailable is not None
    assert unavailable.retry_action is RetryAction.BACKOFF

    missing_result = classify_kraken_response(
        httpx.Response(200, content=b'{"error":[]}'),
        api=KrakenApi.SPOT,
    )
    assert missing_result is not None
    assert missing_result.exchange_code == "invalid_envelope"


def test_request_builders_keep_spot_and_futures_native_symbols_separate() -> None:
    spot = _spot_instrument()
    future = _futures_instrument()

    spot_book = spot_depth_request(spot, count=500)
    futures_book = futures_orderbook_request(future)
    candles = futures_candles_request(
        future,
        tick_type="mark",
        resolution="5m",
        from_time=1,
        to_time=2,
    )
    analytics = futures_analytics_request(
        future,
        analytics_type="open-interest",
        since=1,
        interval=300,
    )

    assert spot_book.params == {"pair": "BTCUSDT", "count": 500}
    assert futures_book.params == {"symbol": "PF_XBTUSD"}
    assert candles.path == "/api/charts/v1/mark/PF_XBTUSD/5m"
    assert analytics.path.endswith("/PF_XBTUSD/open-interest")


def test_spot_ohlc_request_accepts_official_default_interval() -> None:
    request = KrakenRestRequest(
        KrakenApi.SPOT,
        "/0/public/OHLC",
        {"pair": "BTCUSDT"},
        "candle_1m",
        "BTC/USDT",
    )

    assert request.params == {"pair": "BTCUSDT"}
    assert request.logical_stream == "candle_1m"


@pytest.mark.parametrize(
    "factory",
    [
        lambda: KrakenRestRequest(
            KrakenApi.SPOT,
            "/0/private/Balance",
            {},
            "balance",
        ),
        lambda: KrakenRestRequest(
            KrakenApi.SPOT,
            "/0/public/Depth",
            {"pair": "BTCUSDT", "api_key": "secret"},
            "book_deep_snapshot",
        ),
        lambda: KrakenRestRequest(
            KrakenApi.CHARTS,
            "/api/charts/v1/trade/PF_XBTUSD/30s",
            {},
            "candle_trade_30s",
        ),
        lambda: KrakenRestRequest(
            KrakenApi.SPOT,
            "/0/public/AssetPairs",
            {"pair": "BTCUSDT"},
            "instrument",
        ),
        lambda: KrakenRestRequest(
            KrakenApi.FUTURES,
            "/derivatives/api/v3/instruments",
            {"contractType": "flexible_futures"},
            "instrument",
        ),
        lambda: KrakenRestRequest(
            KrakenApi.SPOT,
            "/0/public/Ticker",
            {"pair": "BTCUSDT"},
            "trade",
        ),
        lambda: KrakenRestRequest(
            KrakenApi.SPOT,
            "/0/public/Ticker",
            {"aclass": "tokenized_asset"},
            "ticker",
        ),
    ],
)
def test_request_allowlist_rejects_private_secret_or_unsupported_contract(
    factory,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        factory()


def test_spot_depth_is_a_finite_window_and_preserves_native_result_identity() -> None:
    instrument = _spot_instrument()
    request = spot_depth_request(instrument, count=500)
    capture = _capture(
        {
            "error": [],
            "result": {
                "XBTUSDT": {
                    "asks": [["101.00000", "1.25000000", 1_786_200_000]],
                    "bids": [["100.00000", "2.50000000", 1_786_200_000]],
                    "futureField": {"kept": True},
                }
            },
        },
        request,
    )

    draft = parse_spot_deep_book(capture, instrument=instrument)

    assert draft.coverage is CoverageMode.LOSSY_WINDOW
    assert draft.integrity_mode is IntegrityMode.SNAPSHOT_CHAIN
    assert draft.wire_symbol == "BTCUSDT"
    assert cast(dict[str, object], draft.payload)["result"] is not None


def test_futures_orderbook_is_complete_per_native_endpoint_contract() -> None:
    instrument = _futures_instrument()
    request = futures_orderbook_request(instrument)
    capture = _capture(
        {
            "result": "success",
            "serverTime": "2026-08-08T00:00:00Z",
            "orderBook": {
                "bids": [[Decimal("100.0"), Decimal(2)]],
                "asks": [[Decimal("101.0"), Decimal(3)]],
            },
        },
        request,
    )

    draft = parse_futures_deep_book(capture, instrument=instrument)

    assert draft.coverage is CoverageMode.COMPLETE
    assert draft.integrity_mode is IntegrityMode.SNAPSHOT_CHAIN
    assert draft.wire_symbol == "PF_XBTUSD"


def test_futures_orderbook_rejects_invented_object_level_shape() -> None:
    instrument = _futures_instrument()
    request = futures_orderbook_request(instrument)
    capture = _capture(
        {
            "result": "success",
            "orderBook": {
                "bids": [{"price": Decimal("100.0"), "qty": Decimal(2)}],
                "asks": [[Decimal("101.0"), Decimal(3)]],
            },
        },
        request,
    )

    with pytest.raises(KrakenPayloadError, match="must be an array"):
        parse_futures_deep_book(capture, instrument=instrument)


def test_spot_rest_trade_batch_is_preserved_as_one_raw_event() -> None:
    instrument = _spot_instrument()
    request = spot_trades_request(instrument, count=2)
    payload: Mapping[str, JsonPayload] = {
        "error": [],
        "result": {
            "XBTUSDT": [
                ["100.0", "0.1", Decimal("1786200000.1"), "b", "m", ""],
                ["100.1", "0.2", Decimal("1786200000.2"), "s", "l", ""],
            ],
            "last": "1786200000200000000",
        },
    }

    draft = parse_spot_market_event(_capture(payload, request), instrument=instrument)

    result = cast(dict[str, object], draft.payload)["result"]
    assert isinstance(result, dict)
    assert len(result["XBTUSDT"]) == 2
    assert draft.coverage is CoverageMode.LOSSY_WINDOW


def test_futures_rest_ticker_keeps_exact_camel_case_fields() -> None:
    instrument = _futures_instrument()
    request = futures_tickers_request(instrument)
    payload = _json("futures-ticker.json")
    assert isinstance(payload, dict)

    draft = parse_futures_market_event(
        _capture(cast(Mapping[str, JsonPayload], payload), request),
        instrument=instrument,
    )

    ticker = cast(
        list[dict[str, object]], cast(dict[str, object], draft.payload)["tickers"]
    )[0]
    assert set(ticker) >= {
        "fundingRate",
        "fundingRatePrediction",
        "markPrice",
        "openInterest",
    }
    assert "funding_rate" not in ticker
    assert draft.coverage is CoverageMode.UNKNOWN


def test_instrument_scoped_rest_rejects_extra_native_symbols() -> None:
    spot = _spot_instrument()
    spot_request = spot_trades_request(spot)
    spot_payload: Mapping[str, JsonPayload] = {
        "error": [],
        "result": {
            "XBTUSDT": [["100", "1", Decimal(1), "b", "m", ""]],
            "ETHUSDT": [["10", "1", Decimal(1), "b", "m", ""]],
            "last": "1",
        },
    }
    future = _futures_instrument()
    futures_request = KrakenRestRequest(
        KrakenApi.FUTURES,
        "/derivatives/api/v3/tickers",
        {"symbol": "PF_XBTUSD"},
        "ticker",
        "PF_XBTUSD",
    )
    futures_payload: Mapping[str, JsonPayload] = {
        "result": "success",
        "tickers": [
            {"symbol": "PF_XBTUSD"},
            {"symbol": "PF_ETHUSD"},
        ],
    }

    with pytest.raises(KrakenPayloadError, match="scope"):
        parse_spot_market_event(_capture(spot_payload, spot_request), instrument=spot)
    with pytest.raises(KrakenPayloadError, match="only the requested"):
        parse_futures_market_event(
            _capture(futures_payload, futures_request),
            instrument=future,
        )


def test_capture_requires_full_scheduler_logical_identity() -> None:
    request = spot_trades_request(_spot_instrument(), count=1)
    response = httpx.Response(
        200,
        content=b'{"error":[],"result":{"XBTUSDT":[],"last":"1"}}',
    )

    with pytest.raises(ValueError, match="logical identity"):
        capture_kraken_response(
            response,
            dispatch=_dispatch(logical_key=("kraken", "spot", "ETH/USDT", "trade")),
            request=request,
            request_started_at_ns=1,
            request_ended_at_ns=2,
        )

    capture = capture_kraken_response(
        response,
        dispatch=_dispatch(logical_key=("kraken", "spot", "BTC/USDT", "trade")),
        request=request,
        request_started_at_ns=1,
        request_ended_at_ns=2,
    )
    assert capture.request.instrument_key == "BTC/USDT"


def test_charts_capture_requires_native_success_schema_and_exact_symbol() -> None:
    instrument = _futures_instrument()
    request = futures_analytics_request(
        instrument,
        analytics_type="open-interest",
        since=1,
        interval=300,
    )
    valid_payload: Mapping[str, JsonPayload] = {
        "result": {
            "timestamp": [1],
            "data": [Decimal("42.5")],
            "more": False,
        },
        "errors": [],
    }

    draft = parse_futures_market_event(
        _capture(valid_payload, request),
        instrument=instrument,
    )

    assert draft.coverage is CoverageMode.LOSSY_WINDOW
    with pytest.raises(KrakenPayloadError, match="analytics"):
        _capture({}, request)

    colliding = KrakenRestRequest(
        KrakenApi.CHARTS,
        "/api/charts/v1/analytics/PF_XBTUSD2/open-interest",
        {"since": 1, "interval": 300},
        "analytics_open_interest",
        "PF_XBTUSD2",
    )
    with pytest.raises(ValueError, match="symbol"):
        parse_futures_market_event(
            _capture(valid_payload, colliding),
            instrument=instrument,
        )


def test_charts_candle_capture_rejects_http_200_empty_object() -> None:
    request = futures_candles_request(_futures_instrument())

    with pytest.raises(KrakenPayloadError, match="candles"):
        _capture({}, request)


def test_rest_status_parsers_require_protocol_specific_payloads() -> None:
    spot_request = spot_status_request()
    futures_request = futures_status_request()

    spot = parse_status(
        _capture(
            {"error": [], "result": {"status": "online"}},
            spot_request,
        ),
        market=Market.SPOT,
    )
    futures = parse_status(
        _capture(
            cast(Mapping[str, JsonPayload], _json("futures-status.json")),
            futures_request,
        ),
        market=Market.PERPETUAL,
    )

    assert spot.logical_stream == futures.logical_stream == "status"
    with pytest.raises(KrakenPayloadError, match="status string"):
        parse_status(
            _capture({"error": [], "result": {}}, spot_request),
            market=Market.SPOT,
        )
    with pytest.raises(KrakenPayloadError, match="instrumentStatus"):
        parse_status(
            _capture({"result": "success"}, futures_request),
            market=Market.PERPETUAL,
        )

    with pytest.raises(ValueError, match="market-wide"):
        parse_status(
            _capture(
                {
                    "result": "success",
                    "instrumentStatus": [
                        {
                            "tradeable": "PF_XBTUSD",
                            "experiencingDislocation": False,
                            "priceDislocationDirection": None,
                            "experiencingExtremeVolatility": False,
                            "extremeVolatilityInitialMarginMultiplier": 1,
                        }
                    ],
                },
                futures_request,
            ),
            market=Market.PERPETUAL,
            instrument=_futures_instrument(),
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("experiencingDislocation", 0),
        ("priceDislocationDirection", "SIDEWAYS"),
        ("experiencingExtremeVolatility", None),
        ("extremeVolatilityInitialMarginMultiplier", Decimal(1)),
    ],
)
def test_futures_status_requires_exact_official_row_schema(
    field: str,
    value: JsonPayload,
) -> None:
    row: dict[str, JsonPayload] = {
        "tradeable": "PF_XBTUSD",
        "experiencingDislocation": False,
        "priceDislocationDirection": None,
        "experiencingExtremeVolatility": False,
        "extremeVolatilityInitialMarginMultiplier": 1,
    }
    row[field] = value

    with pytest.raises(KrakenPayloadError, match="instrumentStatus"):
        parse_status(
            _capture(
                {"result": "success", "instrumentStatus": [row]},
                futures_status_request(),
            ),
            market=Market.PERPETUAL,
        )
