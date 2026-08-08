from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from crypto_collector.domain import RestMetadata, SourceContext
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges.errors import ExchangeContractError, ExchangeError
from crypto_collector.network import RetryAction, classify_http

_THROTTLE_CODES = frozenset({"-1003", "-1015"})
_BACKOFF_CODES = frozenset({"-1001", "-1006", "-1007", "-1008"})


class _ResponseLike(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def content(self) -> bytes: ...

    @property
    def headers(self) -> Any: ...


class BinancePayloadError(ExchangeContractError):
    """A Binance payload cannot satisfy the anonymous public-data contract."""


class BinanceResponseError(ExchangeError):
    """A classified Binance HTTP/business failure with raw evidence attached."""

    def __init__(
        self,
        *,
        http_status: int,
        exchange_code: str,
        exchange_message: str,
        retry_action: RetryAction,
        retry_after: str | None,
        raw_payload: JsonPayload,
    ) -> None:
        self.http_status = http_status
        self.exchange_code = exchange_code
        self.exchange_message = exchange_message
        self.retry_action = retry_action
        self.retry_after = retry_after
        self.raw_payload = raw_payload
        self.rest_metadata: RestMetadata | None = None
        self.source: SourceContext | None = None
        detail = exchange_message or "no message"
        super().__init__(
            f"Binance response failed with HTTP {http_status}, "
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
    ) -> BinanceResponseError:
        if type(rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if self.rest_metadata is not None or self.source is not None:
            raise ValueError("Binance response error already has request evidence")
        self.rest_metadata = rest_metadata
        self.source = source
        return self


@dataclass(frozen=True, slots=True)
class BinanceResponseInspection:
    payload: JsonPayload | None
    error: BinanceResponseError | None


def _status(value: object) -> int:
    if type(value) is not int or not 100 <= value <= 599:
        raise ValueError("response status_code must be an HTTP status integer")
    return value


def _retry_after(headers: Mapping[str, str]) -> str | None:
    for name, value in headers.items():
        if name.casefold() == "retry-after":
            return value
    return None


def _decode_payload(response: _ResponseLike) -> JsonPayload:
    try:
        decoded = decode_json(response.content)
    except (TypeError, ValueError) as error:
        raise BinancePayloadError(
            "Binance response body is not finite valid JSON"
        ) from error
    if decoded is None or type(decoded) in {bool, int, str}:
        return cast(JsonPayload, decoded)
    if isinstance(decoded, (list, dict)):
        return cast(JsonPayload, decoded)
    raise BinancePayloadError("Binance response contains unsupported JSON")


def _code(value: object) -> str | None:
    if type(value) is int:
        return str(value)
    if type(value) is str and value:
        return value
    return None


def _message(value: object) -> str:
    return value if type(value) is str else ""


def _error(
    *,
    response: _ResponseLike,
    code: str,
    message: str,
    action: RetryAction,
    payload: JsonPayload,
) -> BinanceResponseError:
    return BinanceResponseError(
        http_status=response.status_code,
        exchange_code=code,
        exchange_message=message,
        retry_action=action,
        retry_after=_retry_after(response.headers),
        raw_payload=payload,
    )


def inspect_binance_response(response: _ResponseLike) -> BinanceResponseInspection:
    """Decode once and classify bans/throttles without losing the response body."""

    status = _status(response.status_code)
    try:
        payload = _decode_payload(response)
    except BinancePayloadError:
        raw_text = response.content.decode("utf-8", errors="replace")
        classification = classify_http(status, _retry_after(response.headers))
        return BinanceResponseInspection(
            payload=None,
            error=_error(
                response=response,
                code="invalid_json",
                message="response body is not finite valid JSON",
                action=classification.action,
                payload=raw_text,
            ),
        )

    exchange_code: str | None = None
    exchange_message = ""
    if isinstance(payload, dict):
        exchange_code = _code(payload.get("code"))
        exchange_message = _message(payload.get("msg"))
    is_business_error = exchange_code is not None and exchange_code not in {"0", "200"}
    if 200 <= status < 300 and not is_business_error:
        return BinanceResponseInspection(payload=payload, error=None)

    if status == 418:
        action = RetryAction.BAN
    elif status == 429 or exchange_code in _THROTTLE_CODES:
        action = RetryAction.THROTTLE
    elif exchange_code in _BACKOFF_CODES:
        action = RetryAction.BACKOFF
    else:
        action = classify_http(status, _retry_after(response.headers)).action
    return BinanceResponseInspection(
        payload=payload,
        error=_error(
            response=response,
            code=exchange_code or f"http_{status}",
            message=exchange_message or "Binance request failed",
            action=action,
            payload=payload,
        ),
    )


def classify_binance_response(response: _ResponseLike) -> BinanceResponseError | None:
    return inspect_binance_response(response).error


def require_binance_success(response: _ResponseLike) -> JsonPayload:
    inspection = inspect_binance_response(response)
    if inspection.error is not None:
        raise inspection.error
    if inspection.payload is None:  # pragma: no cover - guarded above.
        raise BinancePayloadError("Binance response has no decoded payload")
    return inspection.payload


__all__ = [
    "BinancePayloadError",
    "BinanceResponseError",
    "BinanceResponseInspection",
    "classify_binance_response",
    "inspect_binance_response",
    "require_binance_success",
]
