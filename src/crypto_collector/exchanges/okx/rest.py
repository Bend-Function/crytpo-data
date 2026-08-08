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
RPI_BOOK_PATH = "/api/v5/market/books-rpi"
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
}
_MILLISECONDS_TO_NANOSECONDS = 1_000_000
_MAX_SIGNED_64 = 2**63 - 1
_DERIVATIVE_INSTRUMENT_TYPES = frozenset({"SWAP", "FUTURES", "OPTION"})
_INSTRUMENT_TYPES_BY_PATH = MappingProxyType(
    {
        INSTRUMENTS_PATH: frozenset(
            {"SPOT", "MARGIN", "SWAP", "FUTURES", "OPTION", "EVENTS"}
        ),
        TICKERS_PATH: frozenset({"SPOT", "SWAP", "FUTURES", "OPTION", "EVENTS"}),
        _REFERENCE_PATHS["open_interest"]: frozenset(
            {"SWAP", "FUTURES", "OPTION", "EVENTS"}
        ),
        _REFERENCE_PATHS["mark_price"]: frozenset(
            {"MARGIN", "SWAP", "FUTURES", "OPTION", "EVENTS"}
        ),
        _REFERENCE_PATHS["insurance_fund"]: frozenset(
            {"MARGIN", "SWAP", "FUTURES", "OPTION"}
        ),
    }
)
_CANDLE_BARS = frozenset(
    {
        "1m",
        "3m",
        "5m",
        "15m",
        "30m",
        "1H",
        "2H",
        "4H",
        "6H",
        "12H",
        "1D",
        "2D",
        "3D",
        "1W",
        "1M",
        "3M",
        "6Hutc",
        "12Hutc",
        "1Dutc",
        "2Dutc",
        "3Dutc",
        "1Wutc",
        "1Mutc",
        "3Mutc",
    }
)
_STATUS_STATES = frozenset(
    {"scheduled", "ongoing", "pre_open", "completed", "canceled"}
)
_INSURANCE_FUND_TYPES = frozenset(
    {
        "liquidation_balance_deposit",
        "bankruptcy_loss",
        # Still documented as accepted, but deprecated and returning empty data.
        "platform_revenue",
        "adl",
    }
)


@dataclass(frozen=True, slots=True)
class _RequestSchema:
    required: frozenset[str]
    allowed: frozenset[str]


_REQUEST_SCHEMAS = MappingProxyType(
    {
        PUBLIC_TIME_PATH: _RequestSchema(frozenset(), frozenset()),
        INSTRUMENTS_PATH: _RequestSchema(
            frozenset({"instType"}),
            frozenset({"instType", "seriesId", "instFamily", "instId"}),
        ),
        TICKERS_PATH: _RequestSchema(
            frozenset({"instType"}),
            frozenset({"instType", "instFamily"}),
        ),
        DEEP_BOOK_PATH: _RequestSchema(
            frozenset({"instId"}),
            frozenset({"instId", "sz"}),
        ),
        RPI_BOOK_PATH: _RequestSchema(
            frozenset({"instId"}),
            frozenset({"instId", "sz"}),
        ),
        STATUS_PATH: _RequestSchema(frozenset(), frozenset({"state"})),
        CANDLES_PATH: _RequestSchema(
            frozenset({"instId"}),
            frozenset({"instId", "bar", "after", "before", "limit", "adjust"}),
        ),
        _REFERENCE_PATHS["funding_rate"]: _RequestSchema(
            frozenset({"instId"}),
            frozenset({"instId"}),
        ),
        _REFERENCE_PATHS["open_interest"]: _RequestSchema(
            frozenset({"instType"}),
            frozenset({"instType", "instFamily", "instId"}),
        ),
        _REFERENCE_PATHS["mark_price"]: _RequestSchema(
            frozenset({"instType"}),
            frozenset({"instType", "instFamily", "instId"}),
        ),
        _REFERENCE_PATHS["index_ticker"]: _RequestSchema(
            frozenset(),
            frozenset({"quoteCcy", "instId"}),
        ),
        _REFERENCE_PATHS["premium"]: _RequestSchema(
            frozenset({"instId"}),
            frozenset({"instId", "after", "before", "limit"}),
        ),
        _REFERENCE_PATHS["price_limit"]: _RequestSchema(
            frozenset({"instId"}),
            frozenset({"instId"}),
        ),
        _REFERENCE_PATHS["insurance_fund"]: _RequestSchema(
            frozenset({"instType"}),
            frozenset(
                {"instType", "type", "instFamily", "ccy", "before", "after", "limit"}
            ),
        ),
    }
)
_ALLOWED_PATHS = frozenset(_REQUEST_SCHEMAS)


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


def _string_param(
    params: Mapping[str, PublicQueryValue],
    name: str,
) -> str:
    return _nonempty(params[name], field=f"{name} query parameter")


def _enum_param(
    params: Mapping[str, PublicQueryValue],
    name: str,
    allowed: frozenset[str],
) -> str:
    value = _string_param(params, name)
    if value not in allowed:
        raise ValueError(f"unsupported OKX {name} query parameter")
    return value


def _integer_param(
    params: Mapping[str, PublicQueryValue],
    name: str,
    *,
    minimum: int,
    maximum: int | None = None,
) -> int:
    value = params[name]
    if type(value) is int:
        parsed = value
    elif type(value) is str and value.isascii() and value.isdigit():
        parsed = int(value)
    else:
        raise ValueError(f"OKX {name} query parameter must be a decimal integer")
    if parsed < minimum or (maximum is not None and parsed > maximum):
        bound = (
            f"at least {minimum}"
            if maximum is None
            else f"between {minimum} and {maximum}"
        )
        raise ValueError(f"OKX {name} query parameter must be {bound}")
    return parsed


def _validate_request_params(
    path: str,
    params: Mapping[str, PublicQueryValue],
) -> None:
    schema = _REQUEST_SCHEMAS[path]
    names = frozenset(params)
    unknown = names - schema.allowed
    if unknown:
        rendered = ", ".join(sorted(unknown))
        raise ValueError(f"unsupported OKX query parameter(s) for {path}: {rendered}")
    missing = schema.required - names
    if missing:
        rendered = ", ".join(sorted(missing))
        raise ValueError(
            f"missing required OKX query parameter(s) for {path}: {rendered}"
        )

    for name in ("instId", "instFamily", "seriesId", "ccy"):
        if name in params:
            _string_param(params, name)

    if path in _INSTRUMENT_TYPES_BY_PATH:
        inst_type = _enum_param(
            params,
            "instType",
            _INSTRUMENT_TYPES_BY_PATH[path],
        )
        if path == INSTRUMENTS_PATH:
            if inst_type == "EVENTS" and "seriesId" not in params:
                raise ValueError("OKX EVENTS instruments query requires seriesId")
            if "seriesId" in params and inst_type != "EVENTS":
                raise ValueError(
                    "OKX seriesId is only applicable to EVENTS instruments"
                )
            if inst_type == "OPTION" and "instFamily" not in params:
                raise ValueError("OKX OPTION instruments query requires instFamily")
        if (
            path == _REFERENCE_PATHS["open_interest"]
            and inst_type == "OPTION"
            and "instFamily" not in params
        ):
            raise ValueError("OKX OPTION open-interest query requires instFamily")
        if "instFamily" in params and inst_type not in _DERIVATIVE_INSTRUMENT_TYPES:
            raise ValueError(
                f"OKX instFamily is not applicable to {inst_type} on {path}"
            )
        if path == _REFERENCE_PATHS["insurance_fund"]:
            if inst_type in _DERIVATIVE_INSTRUMENT_TYPES:
                if "instFamily" not in params:
                    raise ValueError(
                        "OKX derivative insurance-fund query requires instFamily"
                    )
                if "ccy" in params:
                    raise ValueError(
                        "OKX insurance-fund ccy is only applicable to MARGIN"
                    )
            elif "ccy" not in params:
                raise ValueError("OKX MARGIN insurance-fund query requires ccy")

    if path in {DEEP_BOOK_PATH, RPI_BOOK_PATH} and "sz" in params:
        _integer_param(
            params,
            "sz",
            minimum=1,
            maximum=5_000 if path == DEEP_BOOK_PATH else 400,
        )
    if path == STATUS_PATH and "state" in params:
        _enum_param(params, "state", _STATUS_STATES)
    if path == CANDLES_PATH:
        if "bar" in params:
            _enum_param(params, "bar", _CANDLE_BARS)
        for name in ("after", "before"):
            if name in params:
                _integer_param(params, name, minimum=0)
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=300)
        if "adjust" in params:
            _enum_param(params, "adjust", frozenset({"forward"}))
    if path == _REFERENCE_PATHS["index_ticker"]:
        if not {"quoteCcy", "instId"}.intersection(params):
            raise ValueError("OKX index-tickers query requires quoteCcy or instId")
        if "quoteCcy" in params:
            _enum_param(
                params,
                "quoteCcy",
                frozenset({"USD", "USDT", "BTC", "USDC"}),
            )
    if path == _REFERENCE_PATHS["premium"]:
        for name in ("after", "before"):
            if name in params:
                _integer_param(params, name, minimum=0)
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=100)
    if path == _REFERENCE_PATHS["insurance_fund"]:
        if "type" in params:
            _enum_param(params, "type", _INSURANCE_FUND_TYPES)
        for name in ("after", "before"):
            if name in params:
                _integer_param(params, name, minimum=0)
        if "limit" in params:
            _integer_param(params, "limit", minimum=1, maximum=100)


@dataclass(frozen=True, slots=True)
class OkxRestRequest:
    path: str
    params: Mapping[str, PublicQueryValue]
    logical_stream: str

    def __post_init__(self) -> None:
        if self.path not in _ALLOWED_PATHS:
            raise ValueError("path is not an evidenced OKX anonymous REST endpoint")
        params = _params(self.params)
        _validate_request_params(self.path, params)
        object.__setattr__(self, "params", params)
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
    if logical_stream == "index_ticker":
        params: Mapping[str, PublicQueryValue] = {
            "instId": instrument.wire_symbol("index")
        }
    elif logical_stream == "insurance_fund":
        params = {
            "instType": "SWAP",
            "instFamily": instrument.wire_symbol("instrument_family"),
        }
    elif logical_stream in {"open_interest", "mark_price"}:
        params = {
            "instType": "SWAP",
            "instId": instrument.wire_symbol("rest"),
        }
    else:
        params = {"instId": instrument.wire_symbol("rest")}
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


def okx_rate_limit_headers(headers: httpx.Headers) -> dict[str, str]:
    """Keep only public rate-limit evidence from an OKX response."""

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
        rate_limit_headers=okx_rate_limit_headers(response.headers),
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


def _required_timestamp_ns(value: object, *, field: str) -> int:
    timestamp = _timestamp_ns(value)
    if timestamp is None:
        raise OkxPayloadError(f"OKX response requires a valid {field} timestamp")
    return timestamp


def _uniform_timestamp_ns(
    values: tuple[object, ...],
    *,
    field: str,
) -> int | None:
    if not values:
        return None
    timestamps = tuple(_required_timestamp_ns(value, field=field) for value in values)
    first = timestamps[0]
    return first if all(timestamp == first for timestamp in timestamps[1:]) else None


def _instrument_event(
    capture: OkxRestCapture,
    *,
    instrument: InstrumentRecord,
    logical_stream: str,
    event_time_ns: int | None,
    event_time_source: str | None,
    integrity_mode: IntegrityMode | None = None,
    coverage: CoverageMode | None = None,
) -> NativeEventDraft:
    _okx_instrument(instrument)
    if event_time_ns is not None and event_time_source is None:
        raise ValueError("event_time_source is required with event_time_ns")
    return NativeEventDraft(
        exchange=instrument.exchange,
        market=instrument.market,
        instrument_key=instrument.instrument_key,
        wire_symbol=instrument.wire_symbol("rest"),
        logical_stream=logical_stream,
        native_channel=capture.request.path,
        transport=Transport.REST,
        event_time_ns=event_time_ns,
        event_time_source=None if event_time_ns is None else event_time_source,
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
    if "sz" in capture.request.params:
        _integer_param(
            capture.request.params,
            "sz",
            minimum=1,
            maximum=5_000,
        )
    first = _mapping_row(rows[0])
    event_time_ns = _required_timestamp_ns(
        first.get("ts"),
        field="data[0].ts",
    )
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
        event_time_ns=event_time_ns,
        event_time_source="okx.data[0].ts",
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
    bar = capture.request.params.get("bar", "1m")
    if type(bar) is not str or capture.request.logical_stream != f"candle_{bar}":
        raise ValueError("candles request bar does not match its logical stream")
    timestamps: list[object] = []
    for row in _response_rows(capture):
        if not isinstance(row, (list, tuple)) or len(row) < 9:
            raise OkxPayloadError("OKX candle row must contain at least 9 fields")
        timestamps.append(row[0])
    event_time = _uniform_timestamp_ns(
        tuple(timestamps),
        field="data[][0]",
    )
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream=capture.request.logical_stream,
        event_time_ns=event_time,
        event_time_source="okx.data[0][0]" if event_time is not None else None,
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
    if logical_stream == "index_ticker":
        identity = instrument.wire_symbol("index")
        field = "instId"
    elif logical_stream == "insurance_fund":
        identity = instrument.wire_symbol("instrument_family")
        field = "instFamily"
    else:
        identity = instrument.wire_symbol("rest")
        field = "instId"
    if capture.request.params.get(field) != identity:
        raise ValueError("reference request identity does not match the instrument")
    rows = tuple(_mapping_row(row) for row in _response_rows(capture))
    for mapped in rows:
        returned_identity = mapped.get(field)
        if (
            returned_identity is not None
            and returned_identity != ""
            and returned_identity != identity
        ):
            raise OkxPayloadError(
                "OKX reference response identity does not match the request"
            )
    event_time_ns = (
        None
        if logical_stream == "insurance_fund"
        else _uniform_timestamp_ns(
            tuple(
                row.get(_REFERENCE_EVENT_TIME_FIELDS[logical_stream]) for row in rows
            ),
            field=f"data[].{_REFERENCE_EVENT_TIME_FIELDS[logical_stream]}",
        )
    )
    return _instrument_event(
        capture,
        instrument=instrument,
        logical_stream=logical_stream,
        event_time_ns=event_time_ns,
        event_time_source="okx.data[0].ts" if event_time_ns is not None else None,
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
        coverage=CoverageMode.UNKNOWN,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


def parse_public_time_ns(capture: OkxRestCapture) -> int:
    if (
        capture.request.path != PUBLIC_TIME_PATH
        or capture.request.logical_stream != "_control"
    ):
        raise ValueError("capture is not an OKX public-time response")
    rows = _response_rows(capture)
    if len(rows) != 1:
        raise OkxPayloadError("OKX public-time response must contain exactly one row")
    return _required_timestamp_ns(
        _mapping_row(rows[0]).get("ts"),
        field="data[0].ts",
    )


__all__ = [
    "CANDLES_PATH",
    "DEEP_BOOK_PATH",
    "INSTRUMENTS_PATH",
    "PUBLIC_TIME_PATH",
    "RPI_BOOK_PATH",
    "STATUS_PATH",
    "TICKERS_PATH",
    "OkxRestCapture",
    "OkxRestRequest",
    "candles_request",
    "capture_okx_response",
    "deep_book_request",
    "derivative_reference_request",
    "instruments_request",
    "okx_rate_limit_headers",
    "parse_candles",
    "parse_deep_book",
    "parse_derivative_reference",
    "parse_public_time_ns",
    "parse_status",
    "public_time_request",
    "status_request",
    "tickers_request",
]
