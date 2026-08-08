from __future__ import annotations

from base64 import b64decode
from collections.abc import Mapping
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import cast

import httpx
import pytest

from crypto_collector.domain import (
    CoverageMode,
    Exchange,
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
from crypto_collector.exchanges.contracts import RestPlanItem
from crypto_collector.exchanges.okx import (
    OkxPayloadError,
    OkxResponseError,
    OkxRestCapture,
    OkxRestRequest,
    candles_request,
    capture_okx_response,
    classify_okx_response,
    deep_book_request,
    derivative_reference_request,
    instrument_by_key,
    parse_candles,
    parse_deep_book,
    parse_derivative_reference,
    parse_instruments,
    parse_public_time_ns,
    parse_status,
    public_time_request,
    status_request,
)
from crypto_collector.network import RetryAction
from crypto_collector.scheduler import (
    IntervalPlan,
    IntervalWarning,
    RestDispatch,
    RestPriority,
)
from crypto_collector.selection import InstrumentRecord

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "okx"
_REPOSITORY_ROOT = Path(__file__).resolve().parents[4]
_SECOND = 1_000_000_000


def _fixture_bytes(name: str) -> bytes:
    return (_FIXTURES / name).read_bytes()


def _fixture_json(name: str) -> object:
    return decode_json(_fixture_bytes(name))


def _object(value: object) -> Mapping[str, object]:
    assert isinstance(value, Mapping)
    return cast(Mapping[str, object], value)


def _array(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _instrument() -> InstrumentRecord:
    catalog = parse_instruments(
        _fixture_json("instruments-swap.json"),
        Market.PERPETUAL,
        observed_at_ns=1_750_000_000_000_000_000,
    )
    return instrument_by_key(catalog, "BTC-USDT-SWAP")


def _candle_row(timestamp: str) -> list[str]:
    return [timestamp, "1", "2", "0.5", "1.5", "10", "15", "20", "1"]


def _deep_dispatch(
    instrument: InstrumentRecord,
    request: OkxRestRequest,
) -> RestDispatch:
    interval = IntervalPlan(
        30 * _SECOND,
        120 * _SECOND,
        IntervalWarning(30 * _SECOND, 120 * _SECOND, 1),
    )
    item = RestPlanItem(
        id="okx:perpetual:btc:deep",
        exchange=Exchange.OKX,
        market=Market.PERPETUAL,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        endpoint="https://openapi.okx.com",
        path=request.path,
        params=request.params,
        egress_id="socks-a",
        shard_id="perpetual-deep-0",
        logical_stream="book_deep_snapshot",
        quota_group="proxy-a",
        logical_endpoint="books-full",
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


def _manual_capture(
    payload: object,
    request: OkxRestRequest,
) -> OkxRestCapture:
    assert isinstance(payload, Mapping)
    return OkxRestCapture(
        payload=cast(Mapping[str, JsonPayload], payload),
        rest_metadata=RestMetadata(
            request_started_at_ns=100,
            request_ended_at_ns=200,
            method="GET",
            path=request.path,
            params=cast(
                dict[str, ValidatedJsonPayload],
                dict(request.params),
            ),
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


def test_http_200_business_limit_code_is_throttle_and_keeps_payload() -> None:
    response = httpx.Response(
        200,
        content=_fixture_bytes("error-50011.json"),
        headers={"Retry-After": "2"},
    )

    error = classify_okx_response(response)

    assert error is not None
    assert error.retry_action is RetryAction.THROTTLE
    assert error.exchange_code == "50011"
    assert error.retry_after == "2"
    assert _object(error.raw_payload)["futureErrorField"] == "preserved"


def test_fixture_manifest_pins_every_rest_example() -> None:
    manifest = _object(_fixture_json("manifest.json"))
    entries = _array(manifest["entries"])

    source = _REPOSITORY_ROOT / str(manifest["source_document"])
    assert sha256(source.read_bytes()).hexdigest() == manifest["source_document_sha256"]

    assert {
        "books-full.json",
        "error-50011.json",
        "index-ticker.json",
        "insurance-fund.json",
        "instruments-spot.json",
        "instruments-swap.json",
        "tickers.json",
    }.issubset({str(_object(entry)["file"]) for entry in entries})
    for value in entries:
        entry = _object(value)
        name = str(entry["file"])
        assert sha256(_fixture_bytes(name)).hexdigest() == entry["sha256"]


@pytest.mark.parametrize(
    ("status", "payload", "expected"),
    [
        (418, {"code": "missing_code", "msg": "blocked", "data": []}, RetryAction.BAN),
        (429, {"code": "50011", "msg": "slow", "data": []}, RetryAction.THROTTLE),
        (503, {"code": "0", "msg": "", "data": []}, RetryAction.BACKOFF),
        (200, {"code": "50013", "msg": "busy", "data": []}, RetryAction.BACKOFF),
        (
            200,
            {"code": "51000_sub_code", "msg": "bad", "data": []},
            RetryAction.DO_NOT_RETRY,
        ),
    ],
)
def test_business_and_http_failures_have_explicit_retry_actions(
    status: int,
    payload: dict[str, object],
    expected: RetryAction,
) -> None:
    error = classify_okx_response(httpx.Response(status, content=encode_json(payload)))

    assert error is not None
    assert error.retry_action is expected
    assert error.exchange_code == str(payload["code"])


def test_http_200_missing_code_and_invalid_json_are_not_success() -> None:
    missing = classify_okx_response(
        httpx.Response(200, content=encode_json({"msg": "", "data": []}))
    )
    invalid = classify_okx_response(httpx.Response(200, content=b"not-json"))

    assert missing is not None
    assert missing.exchange_code == "missing_code"
    assert missing.retry_action is RetryAction.DO_NOT_RETRY
    assert invalid is not None
    assert invalid.exchange_code == "invalid_json"


def test_invalid_json_preserves_exact_binary_body_as_base64() -> None:
    error = classify_okx_response(httpx.Response(200, content=b"\xff"))

    assert error is not None
    evidence = _object(error.raw_payload)
    assert evidence == {
        "body_encoding": "base64",
        "body_base64": "/w==",
        "body_byte_length": 1,
    }
    assert b64decode(cast(str, evidence["body_base64"]), validate=True) == b"\xff"


def test_numeric_zero_code_is_an_intentional_compatibility_success() -> None:
    response = httpx.Response(
        200,
        content=encode_json({"code": 0, "msg": "", "data": []}),
    )

    assert classify_okx_response(response) is None


@pytest.mark.parametrize(
    ("path", "params"),
    [
        ("/api/v5/public/time", {}),
        (
            "/api/v5/public/instruments",
            {"instType": "EVENTS", "seriesId": "BTC-ABOVE-DAILY"},
        ),
        (
            "/api/v5/market/tickers",
            {"instType": "OPTION", "instFamily": "BTC-USD"},
        ),
        (
            "/api/v5/market/books-full",
            {"instId": "BTC-USDT", "sz": "5000"},
        ),
        (
            "/api/v5/market/books-rpi",
            {"instId": "BTC-USDT", "sz": 400},
        ),
        ("/api/v5/system/status", {"state": "pre_open"}),
        (
            "/api/v5/market/candles",
            {
                "instId": "BTC-USDT",
                "bar": "1Dutc",
                "after": "1760000000000",
                "before": 1760000001000,
                "limit": "300",
                "adjust": "forward",
            },
        ),
        ("/api/v5/public/funding-rate", {"instId": "ANY"}),
        (
            "/api/v5/public/open-interest",
            {
                "instType": "OPTION",
                "instFamily": "BTC-USD",
                "instId": "BTC-USD-250101-100000-C",
            },
        ),
        (
            "/api/v5/public/mark-price",
            {"instType": "MARGIN", "instId": "BTC-USDT"},
        ),
        ("/api/v5/market/index-tickers", {"quoteCcy": "USDT"}),
        (
            "/api/v5/public/premium-history",
            {
                "instId": "BTC-USDT-SWAP",
                "after": "1760000000000",
                "before": 1760000001000,
                "limit": "100",
            },
        ),
        ("/api/v5/public/price-limit", {"instId": "BTC-USDT-SWAP"}),
        (
            "/api/v5/public/insurance-fund",
            {
                "instType": "MARGIN",
                "ccy": "USDT",
                "type": "bankruptcy_loss",
                "after": "1760000000000",
                "limit": 100,
            },
        ),
    ],
)
def test_direct_request_accepts_documented_path_specific_params(
    path: str,
    params: dict[str, str | int],
) -> None:
    request = OkxRestRequest(
        path=path,
        params=params,
        logical_stream="test_stream",
    )

    assert dict(request.params) == params


@pytest.mark.parametrize(
    ("path", "params", "message"),
    [
        ("/api/v5/public/time", {"unknown": "x"}, "unsupported"),
        ("/api/v5/public/instruments", {"instType": "EVENTS"}, "seriesId"),
        (
            "/api/v5/public/instruments",
            {"instType": "SPOT", "seriesId": "BTC-ABOVE-DAILY"},
            "only applicable",
        ),
        (
            "/api/v5/market/tickers",
            {"instType": "MARGIN"},
            "unsupported OKX instType",
        ),
        (
            "/api/v5/market/books-full",
            {"instId": "BTC-USDT", "sz": 5_001},
            "between 1 and 5000",
        ),
        (
            "/api/v5/market/books-rpi",
            {"instId": "BTC-USDT", "sz": "401"},
            "between 1 and 400",
        ),
        (
            "/api/v5/system/status",
            {"state": "unknown"},
            "unsupported OKX state",
        ),
        (
            "/api/v5/market/candles",
            {"instId": "BTC-USDT", "bar": "7m"},
            "unsupported OKX bar",
        ),
        (
            "/api/v5/market/candles",
            {"instId": "BTC-USDT", "limit": True},
            "decimal integer",
        ),
        (
            "/api/v5/public/open-interest",
            {"instType": "OPTION"},
            "requires instFamily",
        ),
        ("/api/v5/market/index-tickers", {}, "requires quoteCcy or instId"),
        (
            "/api/v5/public/premium-history",
            {"instId": "BTC-USDT-SWAP", "limit": 101},
            "between 1 and 100",
        ),
        (
            "/api/v5/public/insurance-fund",
            {"instType": "SWAP"},
            "requires instFamily",
        ),
        (
            "/api/v5/public/insurance-fund",
            {"instType": "MARGIN", "ccy": "USDT", "type": "unknown"},
            "unsupported OKX type",
        ),
    ],
)
def test_direct_request_rejects_invalid_path_specific_params(
    path: str,
    params: dict[str, str | int | bool],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        OkxRestRequest(
            path=path,
            params=params,
            logical_stream="test_stream",
        )


def test_capture_attaches_request_and_egress_evidence_to_business_error() -> None:
    instrument = _instrument()
    request = deep_book_request(instrument)
    dispatch = _deep_dispatch(instrument, request)

    with pytest.raises(OkxResponseError) as raised:
        capture_okx_response(
            httpx.Response(200, content=_fixture_bytes("error-50011.json")),
            dispatch=dispatch,
            request=request,
            request_started_at_ns=100,
            request_ended_at_ns=200,
        )

    assert raised.value.rest_metadata is not None
    assert raised.value.rest_metadata.attempt == 2
    assert raised.value.rest_metadata.path == request.path
    assert raised.value.source is not None
    assert raised.value.source.egress_id == "socks-a"


def test_deep_snapshot_keeps_exact_payload_and_complete_request_evidence() -> None:
    instrument = _instrument()
    request = deep_book_request(instrument, depth=5_000)
    dispatch = _deep_dispatch(instrument, request)
    response = httpx.Response(
        200,
        content=_fixture_bytes("books-full.json"),
        headers={
            "X-RateLimit-Remaining": "7",
            "Unrelated": "not-recorded",
        },
    )

    capture = capture_okx_response(
        response,
        dispatch=dispatch,
        request=request,
        request_started_at_ns=1_760_000_000_000_000_000,
        request_ended_at_ns=1_760_000_000_001_000_000,
    )
    draft = parse_deep_book(capture, instrument=instrument)

    assert capture.source.egress_id == "socks-a"
    assert draft.logical_stream == "book_deep_snapshot"
    assert draft.integrity_mode is IntegrityMode.SNAPSHOT_CHAIN
    assert draft.coverage is CoverageMode.COMPLETE
    assert draft.event_time_ns == 1_760_000_000_123_000_000
    assert draft.event_time_source == "okx.data[0].ts"
    assert draft.payload == _fixture_json("books-full.json")
    draft_payload = _object(draft.payload)
    first_row = _object(_array(draft_payload["data"])[0])
    assert first_row["futureBookField"] == {"sequenceHint": "not-routing-state"}
    metadata = draft.rest_metadata
    assert metadata is not None
    assert metadata.path == "/api/v5/market/books-full"
    assert metadata.params == {"instId": "BTC-USDT-SWAP", "sz": 5000}
    assert metadata.attempt == 2
    assert metadata.rate_limit_headers == {"x-ratelimit-remaining": "7"}
    assert metadata.requested_interval_ns == 30 * _SECOND
    assert metadata.effective_interval_ns == 120 * _SECOND
    draft.validate_source(capture.source)


def test_deep_snapshot_rejects_symbol_misrouting_and_noncanonical_rows() -> None:
    instrument = _instrument()
    wrong_request = OkxRestRequest(
        path="/api/v5/market/books-full",
        params={"instId": "ETH-USDT-SWAP", "sz": 5000},
        logical_stream="book_deep_snapshot",
    )
    wrong_capture = _manual_capture(
        _fixture_json("books-full.json"),
        wrong_request,
    )
    with pytest.raises(ValueError, match="does not match"):
        parse_deep_book(wrong_capture, instrument=instrument)

    request = deep_book_request(instrument)
    malformed = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [{"bids": [["1", "2", "0", "1"]], "asks": [], "ts": "1"}],
        },
        request,
    )
    with pytest.raises(OkxPayloadError, match="price, quantity, order_count"):
        parse_deep_book(malformed, instrument=instrument)


def test_parsers_honor_documented_query_defaults() -> None:
    instrument = _instrument()
    deep_request = OkxRestRequest(
        path="/api/v5/market/books-full",
        params={"instId": "BTC-USDT-SWAP"},
        logical_stream="book_deep_snapshot",
    )
    candle_request = OkxRestRequest(
        path="/api/v5/market/candles",
        params={"instId": "BTC-USDT-SWAP"},
        logical_stream="candle_1m",
    )

    deep = parse_deep_book(
        _manual_capture(_fixture_json("books-full.json"), deep_request),
        instrument=instrument,
    )
    candle = parse_candles(
        _manual_capture(
            {"code": "0", "msg": "", "data": [_candle_row("1760000000123")]},
            candle_request,
        ),
        instrument=instrument,
    )

    assert deep.event_time_ns == 1_760_000_000_123_000_000
    assert candle.logical_stream == "candle_1m"


@pytest.mark.parametrize("timestamp", [None, "", "not-a-timestamp"])
def test_deep_snapshot_requires_a_valid_native_timestamp(timestamp: object) -> None:
    instrument = _instrument()
    capture = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [{"bids": [], "asks": [], "ts": timestamp}],
        },
        deep_book_request(instrument),
    )

    with pytest.raises(OkxPayloadError, match="valid.*timestamp"):
        parse_deep_book(capture, instrument=instrument)


def test_candle_batch_uses_event_time_only_when_all_rows_agree() -> None:
    instrument = _instrument()
    request = candles_request(instrument)
    different = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [_candle_row("1760000000123"), _candle_row("1760000060123")],
        },
        request,
    )
    uniform = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [_candle_row("1760000000123"), _candle_row("1760000000123")],
        },
        request,
    )

    different_event = parse_candles(different, instrument=instrument)
    uniform_event = parse_candles(uniform, instrument=instrument)

    assert different_event.event_time_ns is None
    assert different_event.event_time_source is None
    assert uniform_event.event_time_ns == 1_760_000_000_123_000_000
    assert uniform_event.event_time_source == "okx.data[0][0]"


@pytest.mark.parametrize(
    "row",
    [
        ["1760000000123", "1", "2", "0.5", "1.5", "10", "15", "20"],
        _candle_row("invalid"),
    ],
)
def test_candle_rows_require_nine_fields_and_a_valid_timestamp(
    row: list[str],
) -> None:
    instrument = _instrument()
    capture = _manual_capture(
        {"code": "0", "msg": "", "data": [row]},
        candles_request(instrument),
    )

    with pytest.raises(OkxPayloadError):
        parse_candles(capture, instrument=instrument)


def test_documented_public_request_factories_and_reference_parsers() -> None:
    instrument = _instrument()
    assert public_time_request().path == "/api/v5/public/time"
    assert status_request(state="ongoing").params == {"state": "ongoing"}
    assert candles_request(instrument).path == "/api/v5/market/candles"
    assert derivative_reference_request("funding_rate", instrument).path == (
        "/api/v5/public/funding-rate"
    )
    assert derivative_reference_request("index_ticker", instrument).params == {
        "instId": "BTC-USDT"
    }
    assert derivative_reference_request("insurance_fund", instrument).params == {
        "instType": "SWAP",
        "instFamily": "BTC-USDT",
    }
    with pytest.raises(ValueError, match="between 1 and 5000"):
        deep_book_request(instrument, depth=5_001)
    with pytest.raises(ValueError, match="sensitive"):
        OkxRestRequest(
            path="/api/v5/public/time",
            params={"api_key": "must-not-enter-evidence"},
            logical_stream="_control",
        )

    time_capture = _manual_capture(
        {"code": "0", "msg": "", "data": [{"ts": "1760000000123"}]},
        public_time_request(),
    )
    assert parse_public_time_ns(time_capture) == 1_760_000_000_123_000_000

    candle_request = candles_request(instrument)
    candle_capture = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [
                [
                    "1760000000123",
                    "1",
                    "2",
                    "0.5",
                    "1.5",
                    "10",
                    "15",
                    "20",
                    "1",
                ]
            ],
        },
        candle_request,
    )
    candle = parse_candles(candle_capture, instrument=instrument)
    assert candle.logical_stream == "candle_1m"
    assert candle.event_time_ns == 1_760_000_000_123_000_000
    assert candle.event_time_source == "okx.data[0][0]"

    reference_request = derivative_reference_request("mark_price", instrument)
    reference_capture = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [
                {
                    "instType": "SWAP",
                    "instId": "BTC-USDT-SWAP",
                    "markPx": "100000.123456789",
                    "ts": "1760000000456",
                    "future": "kept",
                }
            ],
        },
        reference_request,
    )
    reference = parse_derivative_reference(
        reference_capture,
        instrument=instrument,
    )
    assert reference.logical_stream == "mark_price"
    assert reference.event_time_source == "okx.data[0].ts"
    reference_payload = _object(reference.payload)
    reference_row = _object(_array(reference_payload["data"])[0])
    assert reference_row["future"] == "kept"

    insurance_request = derivative_reference_request("insurance_fund", instrument)
    insurance_capture = _manual_capture(
        _fixture_json("insurance-fund.json"),
        insurance_request,
    )
    insurance = parse_derivative_reference(
        insurance_capture,
        instrument=instrument,
    )
    assert insurance.event_time_ns is None
    assert insurance.payload == insurance_capture.payload

    status_capture = _manual_capture(
        {"code": "0", "msg": "", "data": []},
        status_request(),
    )
    status = parse_status(status_capture, market=Market.PERPETUAL)
    assert status.market is Market.PERPETUAL
    assert status.instrument_key is None
    assert status.coverage is CoverageMode.UNKNOWN


def test_reference_batch_uses_event_time_only_when_all_rows_agree() -> None:
    instrument = _instrument()
    request = derivative_reference_request("premium", instrument)
    different = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [
                {"instId": "BTC-USDT-SWAP", "ts": "1760000000123"},
                {"instId": "BTC-USDT-SWAP", "ts": "1760000001123"},
            ],
        },
        request,
    )
    uniform = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [
                {"instId": "BTC-USDT-SWAP", "ts": "1760000000123"},
                {"instId": "BTC-USDT-SWAP", "ts": "1760000000123"},
            ],
        },
        request,
    )

    different_event = parse_derivative_reference(different, instrument=instrument)
    uniform_event = parse_derivative_reference(uniform, instrument=instrument)

    assert different_event.event_time_ns is None
    assert different_event.event_time_source is None
    assert uniform_event.event_time_ns == 1_760_000_000_123_000_000
    assert uniform_event.event_time_source == "okx.data[0].ts"


def test_reference_rows_require_valid_native_timestamps() -> None:
    instrument = _instrument()
    request = derivative_reference_request("premium", instrument)
    capture = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [{"instId": "BTC-USDT-SWAP"}],
        },
        request,
    )

    with pytest.raises(OkxPayloadError, match="valid.*timestamp"):
        parse_derivative_reference(capture, instrument=instrument)


@pytest.mark.parametrize(
    "rows",
    [[], [{"ts": "1760000000123"}, {"ts": "1760000000123"}], [{"ts": "bad"}]],
)
def test_public_time_requires_one_valid_timestamp_row(
    rows: list[dict[str, str]],
) -> None:
    capture = _manual_capture(
        {"code": "0", "msg": "", "data": rows},
        public_time_request(),
    )

    with pytest.raises(OkxPayloadError):
        parse_public_time_ns(capture)


def test_reference_routes_use_catalog_identities_instead_of_canonical_pair() -> None:
    payload = _fixture_json("instruments-swap.json")
    assert isinstance(payload, dict)
    first = _object(_array(payload["data"])[0])
    assert isinstance(first, dict)
    first["uly"] = "BTC-USD"
    first["instFamily"] = "BTC-USD_UM"
    catalog = parse_instruments(
        payload,
        Market.PERPETUAL,
        observed_at_ns=1_750_000_000_000_000_000,
    )
    instrument = instrument_by_key(catalog, "BTC-USDT-SWAP")

    index_request = derivative_reference_request("index_ticker", instrument)
    insurance_request = derivative_reference_request("insurance_fund", instrument)

    assert instrument.canonical_pair == "BTC/USDT"
    assert index_request.params == {"instId": "BTC-USD"}
    assert insurance_request.params == {
        "instType": "SWAP",
        "instFamily": "BTC-USD_UM",
    }


def test_reference_parsers_validate_official_index_identity() -> None:
    instrument = _instrument()
    request = derivative_reference_request("index_ticker", instrument)
    capture = _manual_capture(_fixture_json("index-ticker.json"), request)

    index = parse_derivative_reference(capture, instrument=instrument)

    assert index.event_time_ns == 1_649_419_644_492_000_000
    assert index.event_time_source == "okx.data[0].ts"
    assert index.payload == capture.payload

    mismatched = _manual_capture(
        {
            "code": "0",
            "msg": "",
            "data": [{"instId": "ETH-USDT", "ts": "1649419644492"}],
        },
        request,
    )
    with pytest.raises(OkxPayloadError, match="identity does not match"):
        parse_derivative_reference(mismatched, instrument=instrument)
