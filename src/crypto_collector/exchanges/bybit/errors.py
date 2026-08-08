from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from crypto_collector.domain import RestMetadata, SourceContext
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges.errors import ExchangeContractError, ExchangeError
from crypto_collector.network import RetryAction, classify_http

BYBIT_ACCESS_TOO_FREQUENT_MINIMUM_DELAY_NS = 600_000_000_000

_ACCESS_TOO_FREQUENT = "access too frequent"
_BACKOFF_BUSINESS_CODES = frozenset({10000, 10016})
_THROTTLE_BUSINESS_CODES = frozenset({429, 10006})
_DO_NOT_RETRY_BUSINESS_CODES = frozenset({10001, 10017, 10029})
_RATE_LIMIT_HEADER_NAMES = frozenset(
    {
        "retry-after",
        "x-bapi-limit",
        "x-bapi-limit-status",
        "x-bapi-limit-reset-timestamp",
    }
)


class _ResponseLike(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def content(self) -> bytes: ...

    @property
    def headers(self) -> Any: ...


class BybitPayloadError(ExchangeContractError):
    """A Bybit payload cannot satisfy the anonymous public-data contract."""


class BybitResponseError(ExchangeError):
    """A classified HTTP or Bybit business failure with raw evidence attached."""

    def __init__(
        self,
        *,
        http_status: int,
        exchange_code: str,
        exchange_message: str,
        retry_action: RetryAction,
        retry_after: str | None,
        minimum_delay_ns: int,
        rate_limit_headers: Mapping[str, str],
        raw_payload: JsonPayload,
    ) -> None:
        self.http_status = http_status
        self.exchange_code = exchange_code
        self.exchange_message = exchange_message
        self.retry_action = retry_action
        self.retry_after = retry_after
        self.minimum_delay_ns = minimum_delay_ns
        self.rate_limit_headers = dict(rate_limit_headers)
        self.raw_payload = raw_payload
        self.rest_metadata: RestMetadata | None = None
        self.source: SourceContext | None = None
        detail = exchange_message or "no message"
        super().__init__(
            f"Bybit response failed with HTTP {http_status}, "
            f"code {exchange_code!r}: {detail}"
        )

    @property
    def retryable(self) -> bool:
        return self.retry_action is not RetryAction.DO_NOT_RETRY

    def attach_request_evidence(
        self,
        *,
        rest_metadata: RestMetadata,
        source: SourceContext,
    ) -> BybitResponseError:
        if type(rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if self.rest_metadata is not None or self.source is not None:
            raise ValueError("Bybit response error already has request evidence")
        self.rest_metadata = rest_metadata
        self.source = source
        return self


@dataclass(frozen=True, slots=True)
class BybitResponseInspection:
    payload: Mapping[str, JsonPayload] | None
    error: BybitResponseError | None


def _status(value: object) -> int:
    if type(value) is not int or not 100 <= value <= 599:
        raise ValueError("response status_code must be an HTTP status integer")
    return value


def bybit_rate_limit_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return the exact evidenced retry/quota response headers."""

    return {
        name: value
        for name, value in headers.items()
        if name.casefold() in _RATE_LIMIT_HEADER_NAMES
    }


def _header(headers: Mapping[str, str], expected: str) -> str | None:
    expected_folded = expected.casefold()
    for name, value in headers.items():
        if name.casefold() == expected_folded:
            return value
    return None


def _decode_payload(response: _ResponseLike) -> JsonPayload:
    try:
        decoded = decode_json(response.content)
    except (TypeError, ValueError) as error:
        raise BybitPayloadError(
            "Bybit response body is not finite valid JSON"
        ) from error
    if decoded is None or type(decoded) in {bool, int, str}:
        return cast(JsonPayload, decoded)
    if isinstance(decoded, (list, dict)):
        return cast(JsonPayload, decoded)
    raise BybitPayloadError("Bybit response body contains an unsupported JSON value")


def _ret_code(value: object) -> int | None:
    return value if type(value) is int else None


def _message(value: object) -> str:
    return value if type(value) is str else ""


def _body_text(response: _ResponseLike) -> str:
    return response.content.decode("utf-8", errors="replace")


def _is_access_too_frequent(response: _ResponseLike) -> bool:
    return (
        response.status_code == 403
        and _ACCESS_TOO_FREQUENT in _body_text(response).casefold()
    )


def _error(
    *,
    response: _ResponseLike,
    code: str,
    message: str,
    action: RetryAction,
    minimum_delay_ns: int,
    payload: JsonPayload,
) -> BybitResponseError:
    headers = bybit_rate_limit_headers(response.headers)
    return BybitResponseError(
        http_status=response.status_code,
        exchange_code=code,
        exchange_message=message,
        retry_action=action,
        retry_after=_header(response.headers, "retry-after"),
        minimum_delay_ns=minimum_delay_ns,
        rate_limit_headers=headers,
        raw_payload=payload,
    )


def inspect_bybit_response(response: _ResponseLike) -> BybitResponseInspection:
    """Decode once and classify Bybit JSON status even when HTTP is successful."""

    status = _status(response.status_code)
    access_too_frequent = _is_access_too_frequent(response)
    try:
        raw_payload = _decode_payload(response)
    except BybitPayloadError:
        raw_text = _body_text(response)
        if access_too_frequent:
            action = RetryAction.BAN
            minimum_delay_ns = BYBIT_ACCESS_TOO_FREQUENT_MINIMUM_DELAY_NS
        else:
            action = classify_http(
                status, _header(response.headers, "retry-after")
            ).action
            minimum_delay_ns = 0
        return BybitResponseInspection(
            payload=None,
            error=_error(
                response=response,
                code="invalid_json",
                message="response body is not finite valid JSON",
                action=action,
                minimum_delay_ns=minimum_delay_ns,
                payload=raw_text,
            ),
        )

    if not isinstance(raw_payload, dict):
        if access_too_frequent:
            action = RetryAction.BAN
            minimum_delay_ns = BYBIT_ACCESS_TOO_FREQUENT_MINIMUM_DELAY_NS
        else:
            action = classify_http(
                status, _header(response.headers, "retry-after")
            ).action
            minimum_delay_ns = 0
        return BybitResponseInspection(
            payload=None,
            error=_error(
                response=response,
                code="invalid_envelope",
                message="response body is not an object",
                action=action,
                minimum_delay_ns=minimum_delay_ns,
                payload=raw_payload,
            ),
        )

    payload = cast(dict[str, JsonPayload], raw_payload)
    code = _ret_code(payload.get("retCode"))
    message = _message(payload.get("retMsg"))
    if code == 0 and 200 <= status < 300:
        return BybitResponseInspection(payload=payload, error=None)

    if access_too_frequent:
        action = RetryAction.BAN
        minimum_delay_ns = BYBIT_ACCESS_TOO_FREQUENT_MINIMUM_DELAY_NS
    elif status == 403:
        # Generic 403 also represents regional access restrictions. Only the
        # evidenced phrase above is allowed to create a ten-minute IP ban.
        action = RetryAction.DO_NOT_RETRY
        minimum_delay_ns = 0
    elif status == 429:
        action = RetryAction.THROTTLE
        minimum_delay_ns = 0
    elif not 200 <= status < 300:
        action = classify_http(
            status,
            _header(response.headers, "retry-after"),
        ).action
        minimum_delay_ns = 0
    elif code in _THROTTLE_BUSINESS_CODES:
        action = RetryAction.THROTTLE
        minimum_delay_ns = 0
    elif code in _BACKOFF_BUSINESS_CODES:
        action = RetryAction.BACKOFF
        minimum_delay_ns = 0
    elif code in _DO_NOT_RETRY_BUSINESS_CODES:
        action = RetryAction.DO_NOT_RETRY
        minimum_delay_ns = 0
    else:
        action = RetryAction.DO_NOT_RETRY
        minimum_delay_ns = 0

    if code is None:
        exchange_code = "missing_or_invalid_ret_code"
        failure_message = message or "Bybit integer retCode is missing"
    else:
        exchange_code = str(code)
        failure_message = message or "Bybit success code is missing"
    return BybitResponseInspection(
        payload=payload,
        error=_error(
            response=response,
            code=exchange_code,
            message=failure_message,
            action=action,
            minimum_delay_ns=minimum_delay_ns,
            payload=payload,
        ),
    )


def classify_bybit_response(response: _ResponseLike) -> BybitResponseError | None:
    return inspect_bybit_response(response).error


def require_bybit_success(response: _ResponseLike) -> Mapping[str, JsonPayload]:
    inspection = inspect_bybit_response(response)
    if inspection.error is not None:
        raise inspection.error
    if inspection.payload is None:  # pragma: no cover - guarded by inspection.
        raise BybitPayloadError("Bybit response has no decoded payload")
    return inspection.payload


__all__ = [
    "BYBIT_ACCESS_TOO_FREQUENT_MINIMUM_DELAY_NS",
    "BybitPayloadError",
    "BybitResponseError",
    "BybitResponseInspection",
    "RetryAction",
    "bybit_rate_limit_headers",
    "classify_bybit_response",
    "inspect_bybit_response",
    "require_bybit_success",
]
