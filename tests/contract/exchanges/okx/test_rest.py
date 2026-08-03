from __future__ import annotations

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


def test_numeric_zero_code_is_an_intentional_compatibility_success() -> None:
    response = httpx.Response(
        200,
        content=encode_json({"code": 0, "msg": "", "data": []}),
    )

    assert classify_okx_response(response) is None


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
            "data": [["1760000000123", "1", "2", "0.5", "1.5", "10", "15"]],
        },
        candle_request,
    )
    candle = parse_candles(candle_capture, instrument=instrument)
    assert candle.logical_stream == "candle_1m"
    assert candle.event_time_ns == 1_760_000_000_123_000_000

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
    reference_payload = _object(reference.payload)
    reference_row = _object(_array(reference_payload["data"])[0])
    assert reference_row["future"] == "kept"

    status_capture = _manual_capture(
        {"code": "0", "msg": "", "data": []},
        status_request(),
    )
    status = parse_status(status_capture, market=Market.PERPETUAL)
    assert status.market is Market.PERPETUAL
    assert status.instrument_key is None
