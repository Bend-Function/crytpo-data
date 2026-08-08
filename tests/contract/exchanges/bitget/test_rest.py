from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from decimal import Decimal
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
from crypto_collector.domain.json_codec import JsonPayload, encode_json
from crypto_collector.exchanges.bitget.catalog import (
    instrument_by_key,
    parse_instruments,
)
from crypto_collector.exchanges.bitget.errors import (
    BitgetPayloadError,
    BitgetResponseError,
    classify_bitget_response,
)
from crypto_collector.exchanges.bitget.rest import (
    BitgetEndpoints,
    BitgetRestCapture,
    BitgetRestRequest,
    candles_request,
    capture_bitget_response,
    current_funding_rate_request,
    deep_book_request,
    fills_request,
    funding_rate_history_request,
    history_candles_request,
    index_components_request,
    instruments_request,
    liquidations_request,
    open_interest_request,
    parse_candles,
    parse_deep_book,
    parse_derivative_reference,
    parse_fills,
    parse_liquidations,
    parse_ticker_snapshot,
    request_category,
    ticker_request,
    tickers_request,
)
from crypto_collector.exchanges.contracts import RestPlanItem
from crypto_collector.network import RetryAction
from crypto_collector.scheduler import (
    IntervalPlan,
    IntervalWarning,
    RestDispatch,
    RestPriority,
)
from crypto_collector.selection import InstrumentRecord

_SECOND = 1_000_000_000


def _instrument(
    market: Market = Market.PERPETUAL,
    *,
    symbol: str = "BTCUSDT",
) -> InstrumentRecord:
    category = "SPOT" if market is Market.SPOT else "USDT-FUTURES"
    row: dict[str, object] = {
        "symbol": symbol,
        "category": category,
        "symbolType": "crypto",
        "baseCoin": symbol.removesuffix("USDT"),
        "quoteCoin": "USDT",
        "status": "online",
        "launchTime": "1532454360000",
    }
    if market is Market.SPOT:
        row["isReality"] = "no"
    if market is Market.PERPETUAL:
        row["type"] = "perpetual"
    catalog = parse_instruments(
        {"code": "00000", "msg": "success", "data": [row]},
        market,
        request=instruments_request(market),
        observed_at_ns=1_750_000_000_000_000_000,
    )
    return instrument_by_key(catalog, symbol)


def _capture(payload: object, request: BitgetRestRequest) -> BitgetRestCapture:
    assert isinstance(payload, Mapping)
    return BitgetRestCapture(
        payload=cast(Mapping[str, JsonPayload], payload),
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
        source=SourceContext(
            connection_id=None,
            connection_generation=None,
            egress_id="direct",
        ),
        request=request,
    )


def _dispatch(
    instrument: InstrumentRecord,
    request: BitgetRestRequest,
) -> RestDispatch:
    interval = IntervalPlan(
        30 * _SECOND,
        120 * _SECOND,
        IntervalWarning(30 * _SECOND, 120 * _SECOND, 1),
    )
    item = RestPlanItem(
        id="bitget:perpetual:btc:rest",
        exchange=instrument.exchange,
        market=instrument.market,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        endpoint="https://api.bitget.com",
        path=request.path,
        params=request.params,
        egress_id="socks-a",
        shard_id="perpetual-rest-0",
        logical_stream=request.logical_stream,
        quota_group="proxy-a",
        logical_endpoint="uta-v3-public",
        priority=RestPriority.DEEP_SNAPSHOT,
        endpoint_cost=Decimal(1),
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


def test_uta_v3_paths_and_category_casing_are_exact() -> None:
    assert BitgetEndpoints.INSTRUMENTS == "/api/v3/market/instruments"
    assert request_category(Market.SPOT) == "SPOT"
    assert request_category(Market.PERPETUAL) == "USDT-FUTURES"
    assert instruments_request(Market.SPOT).params == {"category": "SPOT"}
    assert tickers_request(Market.PERPETUAL).params == {"category": "USDT-FUTURES"}
    assert instruments_request(Market.SPOT).logical_stream == "instrument_catalog"
    assert tickers_request(Market.SPOT).logical_stream == "ticker_catalog"

    with pytest.raises(ValueError, match="not an evidenced"):
        BitgetRestRequest(
            "/api/v3/public/instruments",
            {"category": "SPOT"},
            "instrument",
        )
    with pytest.raises(ValueError, match="unsupported Bitget category"):
        BitgetRestRequest(
            BitgetEndpoints.INSTRUMENTS,
            {"category": "spot"},
            "instrument_catalog",
        )

    with pytest.raises(ValueError, match="unsupported Bitget query parameter"):
        BitgetRestRequest(
            BitgetEndpoints.INSTRUMENTS,
            {"category": "SPOT", "symbol": "BTCUSDT"},
            "instrument_catalog",
        )
    with pytest.raises(ValueError, match="scope does not match"):
        BitgetRestRequest(
            BitgetEndpoints.TICKERS,
            {"category": "SPOT", "symbol": "BTCUSDT"},
            "ticker_catalog",
        )
    with pytest.raises(ValueError, match="missing required"):
        BitgetRestRequest(
            BitgetEndpoints.CURRENT_FUNDING_RATE,
            {},
            "funding",
        )


def test_rest_depth_is_independent_of_catalog_ws_max_depth() -> None:
    instrument = _instrument()
    lifecycle = cast(Mapping[str, object], instrument.lifecycle)
    assert "maxDepth" not in lifecycle

    request = deep_book_request(instrument, depth=1_000)

    assert request.params["limit"] == 1_000
    with pytest.raises(ValueError, match="between 1 and 1000"):
        deep_book_request(instrument, depth=1_001)


def test_request_factories_cover_only_evidenced_uta_v3_market_paths() -> None:
    perpetual = _instrument()
    spot = _instrument(Market.SPOT)

    assert fills_request(spot).path == "/api/v3/market/fills"
    assert candles_request(spot, limit=1_000).params["limit"] == 1_000
    assert candles_request(spot, candle_type="index").params["type"] == "index"
    assert candles_request(perpetual, candle_type="premium").params["type"] == (
        "premium"
    )
    assert history_candles_request(perpetual).path.endswith("history-candles")
    assert open_interest_request(perpetual).params == {
        "category": "USDT-FUTURES",
        "symbol": "BTCUSDT",
    }
    assert current_funding_rate_request(perpetual).logical_stream == "funding"
    assert funding_rate_history_request(perpetual).params["cursor"] == 1
    assert index_components_request(perpetual).params == {"symbol": "BTCUSDT"}
    assert liquidations_request().params == {
        "category": "USDT-FUTURES",
        "limit": 100,
    }

    with pytest.raises(ValueError, match="required market"):
        open_interest_request(spot)
    with pytest.raises(ValueError, match="between 1 and 1000"):
        candles_request(spot, limit=1_001)
    with pytest.raises(ValueError, match="between 1 and 100"):
        history_candles_request(spot, limit=101)
    with pytest.raises(ValueError, match="candle type"):
        candles_request(spot, candle_type="mark")
    with pytest.raises(ValueError, match="candle type"):
        candles_request(spot, candle_type="premium")
    with pytest.raises(ValueError, match="cannot exceed 90 days"):
        history_candles_request(
            perpetual,
            start_time_ms=0,
            end_time_ms=90 * 24 * 60 * 60 * 1_000 + 1,
        )


def test_every_rest_path_rejects_a_mislabeled_logical_stream() -> None:
    perpetual = _instrument()
    spot = _instrument(Market.SPOT)
    requests = (
        instruments_request(Market.SPOT),
        tickers_request(Market.SPOT),
        ticker_request(spot),
        deep_book_request(spot),
        fills_request(spot),
        candles_request(spot),
        history_candles_request(spot),
        open_interest_request(perpetual),
        current_funding_rate_request(perpetual),
        funding_rate_history_request(perpetual),
        index_components_request(perpetual),
        liquidations_request(),
    )

    for request in requests:
        with pytest.raises(ValueError, match="scope does not match"):
            BitgetRestRequest(request.path, request.params, "wrong_stream")


def test_only_string_00000_is_success_and_raw_business_error_is_preserved() -> None:
    strict_success = classify_bitget_response(
        httpx.Response(
            200,
            content=encode_json(
                {"code": "00000", "msg": "success", "data": [], "new": 1}
            ),
        )
    )
    numeric_zero = classify_bitget_response(
        httpx.Response(
            200,
            content=encode_json({"code": 0, "msg": "success", "data": []}),
        )
    )
    maintenance = classify_bitget_response(
        httpx.Response(
            200,
            content=encode_json(
                {
                    "code": "40725",
                    "msg": "release window",
                    "data": [],
                    "futureErrorField": {"kept": True},
                }
            ),
        )
    )

    assert strict_success is None
    assert numeric_zero is not None
    assert numeric_zero.exchange_code == "invalid_code_type"
    assert numeric_zero.retry_action is RetryAction.DO_NOT_RETRY
    assert maintenance is not None
    assert maintenance.retry_action is RetryAction.BACKOFF
    raw = cast(Mapping[str, object], maintenance.raw_payload)
    assert raw["futureErrorField"] == {"kept": True}


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (418, RetryAction.BAN),
        (429, RetryAction.THROTTLE),
        (503, RetryAction.BACKOFF),
        (400, RetryAction.DO_NOT_RETRY),
    ],
)
def test_http_failures_use_shared_retry_classification(
    status: int,
    expected: RetryAction,
) -> None:
    error = classify_bitget_response(
        httpx.Response(
            status,
            content=encode_json({"code": "99999", "msg": "failed", "data": []}),
            headers={"Retry-After": "2"},
        )
    )

    assert error is not None
    assert error.retry_action is expected
    assert error.retry_after == "2"


def test_http_ban_and_throttle_take_precedence_over_maintenance_code() -> None:
    throttled = classify_bitget_response(
        httpx.Response(
            429,
            content=encode_json(
                {"code": "40725", "msg": "release and throttled", "data": []}
            ),
        )
    )
    banned = classify_bitget_response(
        httpx.Response(
            418,
            content=encode_json(
                {"code": "40725", "msg": "release and banned", "data": []}
            ),
        )
    )

    assert throttled is not None
    assert throttled.retry_action is RetryAction.THROTTLE
    assert banned is not None
    assert banned.retry_action is RetryAction.BAN


def test_capture_preserves_scheduler_and_rate_limit_evidence_on_failure() -> None:
    instrument = _instrument()
    request = deep_book_request(instrument)
    dispatch = _dispatch(instrument, request)
    response = httpx.Response(
        429,
        content=encode_json({"code": "99999", "msg": "too frequent", "data": []}),
        headers={
            "Retry-After": "3",
            "X-BG-REQUEST-ACCEPT-TIME": "100",
            "x-mbx-used-remain-limit": "0",
        },
    )

    with pytest.raises(BitgetResponseError) as raised:
        capture_bitget_response(
            response,
            dispatch=dispatch,
            request=request,
            request_started_at_ns=100,
            request_ended_at_ns=200,
        )

    error = raised.value
    assert error.retry_action is RetryAction.THROTTLE
    assert error.rest_metadata is not None
    assert error.rest_metadata.attempt == 2
    assert error.rest_metadata.rate_limit_headers == {
        "x-bg-request-accept-time": "100",
        "x-mbx-used-remain-limit": "0",
        "retry-after": "3",
    }
    assert error.source == dispatch.source_context


def test_capture_rejects_cross_instrument_dispatch_evidence() -> None:
    btc = _instrument()
    eth = _instrument(symbol="ETHUSDT")
    btc_request = deep_book_request(btc)
    eth_request = deep_book_request(eth)
    dispatch = _dispatch(btc, btc_request)
    response = httpx.Response(
        200,
        content=encode_json(
            {
                "code": "00000",
                "msg": "success",
                "data": {"a": [], "b": [], "ts": "1"},
            }
        ),
    )

    with pytest.raises(ValueError, match="logical key"):
        capture_bitget_response(
            response,
            dispatch=dispatch,
            request=eth_request,
            request_started_at_ns=100,
            request_ended_at_ns=200,
        )


@pytest.mark.parametrize(
    "logical_key",
    [
        None,
        ("okx", "perpetual", "BTCUSDT", "book_deep_snapshot"),
        ("bitget", "spot", "BTCUSDT", "book_deep_snapshot"),
        ("bitget", "perpetual", "ETHUSDT", "book_deep_snapshot"),
        ("bitget", "perpetual", "BTCUSDT", "trade"),
    ],
)
def test_capture_requires_complete_exact_dispatch_logical_key(
    logical_key: tuple[str, ...] | None,
) -> None:
    instrument = _instrument()
    request = deep_book_request(instrument)
    valid = _dispatch(instrument, request)
    job = replace(
        valid.job,
        logical_key=logical_key,
        replaceable=logical_key is not None,
    )
    dispatch = replace(valid, job=job)

    with pytest.raises(ValueError, match="logical key"):
        capture_bitget_response(
            httpx.Response(
                200,
                content=encode_json(
                    {
                        "code": "00000",
                        "msg": "success",
                        "data": {"a": [], "b": [], "ts": "1"},
                    }
                ),
            ),
            dispatch=dispatch,
            request=request,
            request_started_at_ns=100,
            request_ended_at_ns=200,
        )


def test_rest_order_book_is_complete_raw_snapshot_without_ws_linkage() -> None:
    instrument = _instrument()
    request = deep_book_request(instrument, depth=1_000)
    payload = {
        "code": "00000",
        "msg": "success",
        "requestTime": 1_730_969_017_897,
        "data": {
            "a": [[Decimal("73000.0"), Decimal("0.007")]],
            "b": [["71213.8", "1.836"]],
            "ts": "1730969017964",
            "futureBookField": {"kept": True},
        },
    }

    event = parse_deep_book(_capture(payload, request), instrument=instrument)

    assert event.logical_stream == "book_deep_snapshot"
    assert event.integrity_mode is IntegrityMode.SNAPSHOT_CHAIN
    assert event.coverage is CoverageMode.COMPLETE
    assert event.event_time_ns == 1_730_969_017_964_000_000
    assert event.event_time_source == "bitget.data.ts"
    raw = cast(Mapping[str, object], event.payload)
    assert raw == payload
    assert "seq" not in cast(Mapping[str, object], raw["data"])


def test_rest_order_book_rejects_zero_price_but_preserves_zero_quantity() -> None:
    instrument = _instrument()
    request = deep_book_request(instrument)
    base = {
        "code": "00000",
        "msg": "success",
        "data": {"a": [["11", "0"]], "b": [["10", "1"]], "ts": "1"},
    }

    accepted = parse_deep_book(_capture(base, request), instrument=instrument)
    assert accepted.payload == base

    zero_price = {
        "code": "00000",
        "msg": "success",
        "data": {"a": [["0", "1"]], "b": [], "ts": "1"},
    }
    with pytest.raises(BitgetPayloadError, match="price must be positive"):
        parse_deep_book(_capture(zero_price, request), instrument=instrument)

    oversized_timestamp = {
        "code": "00000",
        "msg": "success",
        "data": {"a": [], "b": [], "ts": "9" * 5_000},
    }
    with pytest.raises(BitgetPayloadError, match="valid data.ts timestamp"):
        parse_deep_book(
            _capture(oversized_timestamp, request),
            instrument=instrument,
        )


def test_symbol_ticker_validates_response_identity_and_preserves_payload() -> None:
    instrument = _instrument(Market.SPOT)
    request = ticker_request(instrument)
    payload = {
        "code": "00000",
        "msg": "success",
        "requestTime": 1_765_444_397_411,
        "data": [
            {
                "category": "SPOT",
                "symbol": "BTCUSDT",
                "turnover24h": "677732572.225658",
                "ts": "1765444395778",
                "newTickerField": "kept",
            }
        ],
    }

    event = parse_ticker_snapshot(_capture(payload, request), instrument=instrument)

    assert event.event_time_ns == 1_765_444_395_778_000_000
    assert event.payload == payload


def test_recent_fills_are_raw_bounded_window_and_mixed_times_have_no_batch_time() -> (
    None
):
    instrument = _instrument()
    request = fills_request(instrument)
    payload = {
        "code": "00000",
        "msg": "success",
        "data": [
            {
                "execId": "1",
                "execLinkId": "link-1",
                "price": "29990.5",
                "size": "0.0166",
                "side": "sell",
                "ts": "1627116776464",
                "isRPI": "no",
            },
            {
                "execId": "2",
                "execLinkId": "link-2",
                "price": "30007.0",
                "size": "0.0166",
                "side": "buy",
                "ts": "1627116600875",
                "isRPI": "yes",
            },
        ],
    }

    event = parse_fills(_capture(payload, request), instrument=instrument)

    assert event.logical_stream == "trade"
    assert event.coverage is CoverageMode.LOSSY_WINDOW
    assert event.event_time_ns is None
    assert event.payload == payload


@pytest.mark.parametrize("historical", [False, True])
def test_candle_rows_are_preserved_and_uniform_batch_time_is_exact(
    historical: bool,
) -> None:
    instrument = _instrument()
    request = (
        history_candles_request(instrument)
        if historical
        else candles_request(instrument)
    )
    payload = {
        "code": "00000",
        "msg": "success",
        "data": [
            [
                "1687708800000",
                "27176.93",
                "27177.43",
                "27166.93",
                "27177.43",
                "2990.08",
                "81246917.3294",
                "future-field",
            ]
        ],
    }

    event = parse_candles(_capture(payload, request), instrument=instrument)

    assert event.logical_stream == "candle_1m"
    assert event.event_time_ns == 1_687_708_800_000_000_000
    assert event.payload == payload


def test_derivative_reference_parsers_validate_native_shapes() -> None:
    instrument = _instrument()
    cases = [
        (
            open_interest_request(instrument),
            {
                "code": "00000",
                "msg": "success",
                "data": {
                    "list": [{"symbol": "BTCUSDT", "openInterest": "2243.019"}],
                    "ts": "1730969652411",
                    "future": "kept",
                },
            },
            1_730_969_652_411_000_000,
        ),
        (
            current_funding_rate_request(instrument),
            {
                "code": "00000",
                "msg": "success",
                "data": [
                    {
                        "symbol": "BTCUSDT",
                        "fundingRate": "0.000071",
                        "nextUpdate": "1743062400000",
                    }
                ],
            },
            None,
        ),
        (
            funding_rate_history_request(instrument),
            {
                "code": "00000",
                "msg": "success",
                "data": {
                    "resultList": [
                        {
                            "symbol": "BTCUSDT",
                            "fundingRate": "0.0001",
                            "fundingRateTimestamp": "1754899200000",
                        }
                    ]
                },
            },
            1_754_899_200_000_000_000,
        ),
        (
            index_components_request(instrument),
            {
                "code": "00000",
                "msg": "success",
                "data": {
                    "symbol": "BTCUSDT",
                    "componentList": [
                        {
                            "exchange": "BITGET",
                            "spotPair": "BTC/USDT",
                            "equivalentPrice": "88469.77",
                            "weight": "0.0768",
                        }
                    ],
                },
            },
            None,
        ),
    ]

    for request, payload, expected_time in cases:
        event = parse_derivative_reference(
            _capture(payload, request),
            instrument=instrument,
        )
        assert event.logical_stream == request.logical_stream
        assert event.event_time_ns == expected_time
        assert event.payload == payload


def test_liquidation_history_is_always_lossy_for_symbol_and_market_scope() -> None:
    instrument = _instrument()
    payload = {
        "code": "00000",
        "msg": "success",
        "data": {
            "list": [
                {
                    "symbol": "BTCUSDT",
                    "side": "buy",
                    "price": "29990.5",
                    "amount": "0.5",
                    "ts": "1690313813709",
                    "futureLiquidationField": "kept",
                }
            ],
            "cursor": "1690313813709",
        },
    }

    symbol_event = parse_liquidations(
        _capture(payload, liquidations_request(instrument)),
        instrument=instrument,
    )
    market_event = parse_liquidations(
        _capture(payload, liquidations_request()),
    )

    assert symbol_event.coverage is CoverageMode.LOSSY_WINDOW
    assert symbol_event.instrument_key == "BTCUSDT"
    assert symbol_event.event_time_ns == 1_690_313_813_709_000_000
    assert market_event.coverage is CoverageMode.LOSSY_WINDOW
    assert market_event.instrument_key is None
    assert market_event.wire_symbol is None
    assert market_event.payload == payload
