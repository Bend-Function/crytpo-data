from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import cast

import httpx

from crypto_collector.domain import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    NativeEventDraft,
    RestMetadata,
    SourceContext,
    Transport,
)
from crypto_collector.domain.json_codec import JsonPayload, ValidatedJsonPayload
from crypto_collector.exchanges.contracts import PublicQueryValue
from crypto_collector.exchanges.okx.errors import (
    OkxPayloadError,
    inspect_okx_response,
)
from crypto_collector.observability.redaction import SENSITIVE_QUERY_NAMES
from crypto_collector.scheduler import RestDispatch
from crypto_collector.selection import InstrumentRecord

INSTRUMENTS_PATH = "/api/v5/public/instruments"
TICKERS_PATH = "/api/v5/market/tickers"
DEEP_BOOK_PATH = "/api/v5/market/books-full"
PUBLIC_TIME_PATH = "/api/v5/public/time"
STATUS_PATH = "/api/v5/system/status"
CANDLES_PATH = "/api/v5/market/candles"

_REFERENCE_PATHS = MappingProxyType(
    {
        "funding_rate": "/api/v5/public/funding-rate",
        "open_interest": "/api/v5/public/open-interest",
        "mark_price": "/api/v5/public/mark-price",
        "index_ticker": "/api/v5/market/index-tickers",
        "premium": "/api/v5/public/premium-history",
        "price_limit": "/api/v5/public/price-limit",
        "insurance_fund": "/api/v5/public/insurance-fund",
    }
)
_ALLOWED_PATHS = frozenset(
    {
        INSTRUMENTS_PATH,
        TICKERS_PATH,
        DEEP_BOOK_PATH,
        PUBLIC_TIME_PATH,
        STATUS_PATH,
        CANDLES_PATH,
        *_REFERENCE_PATHS.values(),
    }
)
_RATE_HEADER_NAMES = frozenset(
    {
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
    }
)
_REFERENCE_EVENT_TIME_FIELDS = {
    "funding_rate": "ts",
    "open_interest": "ts",
    "mark_price": "ts",
    "index_ticker": "ts",
    "premium": "ts",
    "price_limit": "ts",
    "insurance_fund": "ts",
}
_MILLISECONDS_TO_NANOSECONDS = 1_000_000
_MAX_SIGNED_64 = 2**63 - 1


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _params(
    value: Mapping[str, PublicQueryValue],
) -> Mapping[str, PublicQueryValue]:
    normalized: dict[str, PublicQueryValue] = {}
    for key, item in value.items():
        name = _nonempty(key, field="query parameter name")
        if name.casefold() in SENSITIVE_QUERY_NAMES:
            raise ValueError("sensitive query parameters are not permitted")
        if type(item) not in {str, int, bool} and item is not None:
            raise TypeError("OKX query parameters must be scalar public values")
        normalized[name] = item
    return MappingProxyType(normalized)


@dataclass(frozen=True, slots=True)
class OkxRestRequest:
    path: str
    params: Mapping[str, PublicQueryValue]
    logical_stream: str

    def __post_init__(self) -> None:
        if self.path not in _ALLOWED_PATHS:
            raise ValueError("path is not an evidenced OKX anonymous REST endpoint")
        object.__setattr__(self, "params", _params(self.params))
        object.__setattr__(
            self,
            "logical_stream",
            _nonempty(self.logical_stream, field="logical_stream"),
        )


@dataclass(frozen=True, slots=True)
class OkxRestCapture:
    payload: Mapping[str, JsonPayload]
    rest_metadata: RestMetadata
    source: SourceContext
    request: OkxRestRequest

    def __post_init__(self) -> None:
        if not isinstance(self.payload, Mapping) or any(
            type(key) is not str for key in self.payload
        ):
            raise TypeError("payload must be a string-keyed mapping")
        if type(self.rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(self.source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if type(self.request) is not OkxRestRequest:
            raise TypeError("request must be OkxRestRequest")
        code = self.payload.get("code")
        if code != "0" and code != 0:
            raise ValueError("OKX capture payload must contain a success code")
        if self.rest_metadata.method != "GET":
            raise ValueError("OKX public capture must use GET")
        if not 200 <= self.rest_metadata.status < 300:
            raise ValueError("OKX success capture requires a 2xx HTTP status")
        if self.rest_metadata.path != self.request.path:
            raise ValueError("REST metadata path does not match the request")
        if self.rest_metadata.params != dict(self.request.params):
            raise ValueError("REST metadata params do not match the request")
        self.source.validate_for(
            transport=Transport.REST,
            logical_stream=self.request.logical_stream,
        )


def instruments_request(market: Market) -> OkxRestRequest:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    return OkxRestRequest(
        path=INSTRUMENTS_PATH,
        params={"instType": "SPOT" if market is Market.SPOT else "SWAP"},
        logical_stream="instrument",
    )


def tickers_request(market: Market) -> OkxRestRequest:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    return OkxRestRequest(
        path=TICKERS_PATH,
        params={"instType": "SPOT" if market is Market.SPOT else "SWAP"},
        logical_stream="ticker",
    )


def deep_book_request(
    instrument: InstrumentRecord,
    *,
    depth: int = 5_000,
) -> OkxRestRequest:
    _okx_instrument(instrument)
    if type(depth) is not int or not 1 <= depth <= 5_000:
        raise ValueError("OKX books-full depth must be between 1 and 5000")
    return OkxRestRequest(
        path=DEEP_BOOK_PATH,
        params={"instId": instrument.wire_symbol("rest"), "sz": depth},
        logical_stream="book_deep_snapshot",
    )


def public_time_request() -> OkxRestRequest:
    return OkxRestRequest(
        path=PUBLIC_TIME_PATH,
        params={},
        logical_stream="_control",
    )


def status_request(*, state: str | None = None) -> OkxRestRequest:
    if state is not None and state not in {
        "scheduled",
        "ongoing",
        "pre_open",
        "completed",
        "canceled",
    }:
        raise ValueError("unsupported OKX maintenance state")
    return OkxRestRequest(
        path=STATUS_PATH,
        params={} if state is None else {"state": state},
        logical_stream="status",
    )


def candles_request(
    instrument: InstrumentRecord,
    *,
    bar: str = "1m",
    limit: int = 300,
) -> OkxRestRequest:
    _okx_instrument(instrument)
    _nonempty(bar, field="bar")
    if type(limit) is not int or not 1 <= limit <= 300:
        raise ValueError("OKX candle limit must be between 1 and 300")
    return OkxRestRequest(
        path=CANDLES_PATH,
        params={
            "instId": instrument.wire_symbol("rest"),
            "bar": bar,
            "limit": limit,
        },
        logical_stream=f"candle_{bar}",
    )


def derivative_reference_request(
    logical_stream: str,
    instrument: InstrumentRecord,
) -> OkxRestRequest:
    _okx_instrument(instrument, market=Market.PERPETUAL)
    try:
        path = _REFERENCE_PATHS[logical_stream]
    except KeyError:
        raise ValueError("unsupported OKX derivative reference stream") from None
    wire_symbol = instrument.wire_symbol("rest")
    if logical_stream == "index_ticker":
        params: Mapping[str, PublicQueryValue] = {
            "instId": instrument.canonical_pair.replace("/", "-")
        }
    elif logical_stream == "insurance_fund":
        params = {
            "instType": "SWAP",
            "instFamily": instrument.canonical_pair.replace("/", "-"),
        }
    elif logical_stream in {"open_interest", "mark_price"}:
        params = {"instType": "SWAP", "instId": wire_symbol}
    else:
        params = {"instId": wire_symbol}
    return OkxRestRequest(
        path=path,
        params=params,
        logical_stream=logical_stream,
    )


def _okx_instrument(
    instrument: InstrumentRecord,
    *,
    market: Market | None = None,
) -> None:
    if not isinstance(instrument, InstrumentRecord):
        raise TypeError("instrument must be InstrumentRecord")
    if instrument.exchange.value != "okx":
        raise ValueError("instrument must belong to OKX")
    if market is not None and instrument.market is not market:
        raise ValueError("instrument does not belong to the required market")


def _rate_limit_headers(headers: httpx.Headers) -> dict[str, str]:
    return {
        name: value
        for name, value in headers.items()
        if name.casefold() in _RATE_HEADER_NAMES
        or name.casefold().startswith("x-ratelimit-")
    }


def capture_okx_response(
    response: httpx.Response,
    *,
    dispatch: RestDispatch,
    request: OkxRestRequest,
    request_started_at_ns: int,
    request_ended_at_ns: int,
) -> OkxRestCapture:
    """Attach complete scheduler evidence and reject business errors at HTTP 200."""

    if type(dispatch) is not RestDispatch:
        raise TypeError("dispatch must be RestDispatch")
    if type(request) is not OkxRestRequest:
        raise TypeError("request must be OkxRestRequest")
    logical_key = dispatch.job.logical_key
    if logical_key is not None and logical_key[-1] != request.logical_stream:
        raise ValueError("dispatch logical stream does not match the OKX request")
    metadata = dispatch.build_rest_metadata(
        request_started_at_ns=request_started_at_ns,
        request_ended_at_ns=request_ended_at_ns,
        method="GET",
        path=request.path,
        params=cast(Mapping[str, ValidatedJsonPayload], request.params),
        status=response.status_code,
        rate_limit_headers=_rate_limit_headers(response.headers),
    )
    inspection = inspect_okx_response(response)
    if inspection.error is not None:
        raise inspection.error.attach_request_evidence(
            rest_metadata=metadata,
            source=dispatch.source_context,
        )
    if inspection.payload is None:  # pragma: no cover - guarded by inspection.
        raise OkxPayloadError("OKX success response has no payload")
    return OkxRestCapture(
        payload=inspection.payload,
        rest_metadata=metadata,
        source=dispatch.source_context,
        request=request,
    )


def _response_rows(capture: OkxRestCapture) -> tuple[object, ...]:
    data = capture.payload.get("data")
    if not isinstance(data, (list, tuple)):
        raise OkxPayloadError("OKX response data must be an array")
    return tuple(data)


def _mapping_row(value: object) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise OkxPayloadError("OKX response row must be an object")
    return cast(Mapping[str, JsonPayload], value)


def _timestamp_ns(value: object) -> int | None:
    if value is None or value == "":
        return None
    if type(value) is not str or not value.isascii() or not value.isdigit():
        return None
    timestamp = int(value) * _MILLISECONDS_TO_NANOSECONDS
    return timestamp if timestamp <= _MAX_SIGNED_64 else None


def _first_row_timestamp(
    capture: OkxRestCapture,
    *,
    field: str,
) -> int | None:
    rows = _response_rows(capture)
    if not rows:
        return None
    return _timestamp_ns(_mapping_row(rows[0]).get(field))


def _instrument_event(
    capture: OkxRestCapture,
    *,
    instrument: InstrumentRecord,
    logical_stream: str,
    event_time_ns: int | None,
    integrity_mode: IntegrityMode | None = None,
    coverage: CoverageMode | None = None,
) -> NativeEventDraft:
    _okx_instrument(instrument)
    return NativeEventDraft(
        exchange=instrument.exchange,
        market=instrument.market,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        logical_stream=logical_stream,
        native_channel=capture.request.path,
        transport=Transport.REST,
        event_time_ns=event_time_ns,
        event_time_source=None if event_time_ns is None else "okx.ts",
        integrity_mode=integrity_mode,
        coverage=coverage,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


def parse_deep_book(
    capture: OkxRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _okx_instrument(instrument)
    if (
        capture.request.path != DEEP_BOOK_PATH
        or capture.request.logical_stream != "book_deep_snapshot"
    ):
        raise ValueError("capture is not an OKX books-full response")
    rows = _response_rows(capture)
    if len(rows) != 1:
        raise OkxPayloadError("OKX books-full response must contain exactly one row")
    expected_symbol = instrument.wire_symbol("rest")
    if capture.request.params.get("instId") != expected_symbol:
        raise ValueError("books-full request symbol does not match the instrument")
    depth = capture.request.params.get("sz")
    if type(depth) is not int or not 1 <= depth <= 5_000:
        raise ValueError("books-full request lacks a valid requested depth")
    first = _mapping_row(rows[0])
    for side in ("bids", "asks"):
        levels = first.get(side)
        if not isinstance(levels, (list, tuple)):
            raise OkxPayloadError(f"OKX books-full row requires a {side} array")
        for level in levels:
            if (
                not isinstance(level, (list, tuple))
                or len(level) != 3
                or any(type(value) is not str for value in level)
            ):
                raise OkxPayloadError(
                    "OKX books-full levels must be [price, quantity, order_count]"
                )
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream="book_deep_snapshot",
        event_time_ns=_first_row_timestamp(capture, field="ts"),
        integrity_mode=IntegrityMode.SNAPSHOT_CHAIN,
        coverage=CoverageMode.COMPLETE,
    )


def parse_candles(
    capture: OkxRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _okx_instrument(instrument)
    if capture.request.path != CANDLES_PATH:
        raise ValueError("capture is not an OKX candles response")
    if capture.request.params.get("instId") != instrument.wire_symbol("rest"):
        raise ValueError("candles request symbol does not match the instrument")
    bar = capture.request.params.get("bar")
    if type(bar) is not str or capture.request.logical_stream != f"candle_{bar}":
        raise ValueError("candles request bar does not match its logical stream")
    rows = _response_rows(capture)
    event_time = None
    if rows:
        first = rows[0]
        if not isinstance(first, (list, tuple)) or not first:
            raise OkxPayloadError("OKX candle row must be a non-empty array")
        event_time = _timestamp_ns(first[0])
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream=capture.request.logical_stream,
        event_time_ns=event_time,
    )


def parse_derivative_reference(
    capture: OkxRestCapture,
    *,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    _okx_instrument(instrument, market=Market.PERPETUAL)
    logical_stream = capture.request.logical_stream
    if _REFERENCE_PATHS.get(logical_stream) != capture.request.path:
        raise ValueError("capture is not a configured derivative reference response")
    if logical_stream in {"index_ticker", "insurance_fund"}:
        identity = instrument.canonical_pair.replace("/", "-")
        field = "instId" if logical_stream == "index_ticker" else "instFamily"
    else:
        identity = instrument.wire_symbol("rest")
        field = "instId"
    if capture.request.params.get(field) != identity:
        raise ValueError("reference request identity does not match the instrument")
    for row in _response_rows(capture):
        mapped = _mapping_row(row)
        returned_identity = mapped.get(field)
        if (
            returned_identity is not None
            and returned_identity != ""
            and returned_identity != identity
        ):
            raise OkxPayloadError(
                "OKX reference response identity does not match the request"
            )
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream=logical_stream,
        event_time_ns=_first_row_timestamp(
            capture,
            field=_REFERENCE_EVENT_TIME_FIELDS[logical_stream],
        ),
    )


def parse_status(
    capture: OkxRestCapture,
    *,
    market: Market,
) -> NativeEventDraft:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    if (
        capture.request.path != STATUS_PATH
        or capture.request.logical_stream != "status"
    ):
        raise ValueError("capture is not an OKX status response")
    _response_rows(capture)
    return NativeEventDraft(
        exchange=Exchange.OKX,
        market=market,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="status",
        native_channel=STATUS_PATH,
        transport=Transport.REST,
        event_time_ns=None,
        event_time_source=None,
        integrity_mode=None,
        coverage=CoverageMode.COMPLETE,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


def parse_public_time_ns(capture: OkxRestCapture) -> int:
    if (
        capture.request.path != PUBLIC_TIME_PATH
        or capture.request.logical_stream != "_control"
    ):
        raise ValueError("capture is not an OKX public-time response")
    timestamp = _first_row_timestamp(capture, field="ts")
    if timestamp is None:
        raise OkxPayloadError("OKX public-time response lacks a valid ts")
    return timestamp


__all__ = [
    "CANDLES_PATH",
    "DEEP_BOOK_PATH",
    "INSTRUMENTS_PATH",
    "PUBLIC_TIME_PATH",
    "STATUS_PATH",
    "TICKERS_PATH",
    "OkxRestCapture",
    "OkxRestRequest",
    "candles_request",
    "capture_okx_response",
    "deep_book_request",
    "derivative_reference_request",
    "instruments_request",
    "parse_candles",
    "parse_deep_book",
    "parse_derivative_reference",
    "parse_public_time_ns",
    "parse_status",
    "public_time_request",
    "status_request",
    "tickers_request",
]
