from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol, cast

from crypto_collector.domain import RestMetadata, SourceContext
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges.errors import ExchangeContractError, ExchangeError
from crypto_collector.network import RetryAction, classify_http

_THROTTLE_CODES = frozenset({"50011", "50040"})
_BACKOFF_CODES = frozenset({"50004", "50013", "50026", "50061"})


class _ResponseLike(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def content(self) -> bytes: ...

    @property
    def headers(self) -> Any: ...


class OkxPayloadError(ExchangeContractError):
    """An OKX response cannot satisfy the anonymous public-data contract."""


class OkxResponseError(ExchangeError):
    """A classified HTTP or OKX business failure with its raw JSON attached."""

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
            f"OKX response failed with HTTP {http_status}, "
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
    ) -> OkxResponseError:
        if type(rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if self.rest_metadata is not None or self.source is not None:
            raise ValueError("OKX response error already has request evidence")
        self.rest_metadata = rest_metadata
        self.source = source
        return self


@dataclass(frozen=True, slots=True)
class OkxResponseInspection:
    payload: Mapping[str, JsonPayload] | None
    error: OkxResponseError | None


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
        raise OkxPayloadError("OKX response body is not finite valid JSON") from error
    if decoded is None or type(decoded) in {bool, int, str}:
        return cast(JsonPayload, decoded)
    if isinstance(decoded, (list, dict)):
        return cast(JsonPayload, decoded)
    raise OkxPayloadError("OKX response body contains an unsupported JSON value")


def _code(value: object) -> str | None:
    if type(value) is str:
        return value
    if type(value) is int:
        return str(value)
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
) -> OkxResponseError:
    return OkxResponseError(
        http_status=response.status_code,
        exchange_code=code,
        exchange_message=message,
        retry_action=action,
        retry_after=_retry_after(response.headers),
        raw_payload=payload,
    )


def inspect_okx_response(response: _ResponseLike) -> OkxResponseInspection:
    """Decode once, then classify JSON business status before HTTP status."""

    status = _status(response.status_code)
    try:
        raw_payload = _decode_payload(response)
    except OkxPayloadError:
        raw_text = response.content.decode("utf-8", errors="replace")
        classification = classify_http(status, _retry_after(response.headers))
        return OkxResponseInspection(
            payload=None,
            error=_error(
                response=response,
                code="invalid_json",
                message="response body is not finite valid JSON",
                action=classification.action,
                payload=raw_text,
            ),
        )

    if not isinstance(raw_payload, dict):
        classification = classify_http(status, _retry_after(response.headers))
        return OkxResponseInspection(
            payload=None,
            error=_error(
                response=response,
                code="invalid_envelope",
                message="response body is not an object",
                action=classification.action,
                payload=raw_payload,
            ),
        )

    payload = cast(dict[str, JsonPayload], raw_payload)
    exchange_code = _code(payload.get("code"))
    exchange_message = _message(payload.get("msg"))
    if exchange_code == "0" and 200 <= status < 300:
        return OkxResponseInspection(payload=payload, error=None)

    if status == 418:
        action = RetryAction.BAN
    elif exchange_code in _THROTTLE_CODES:
        action = RetryAction.THROTTLE
    elif exchange_code in _BACKOFF_CODES:
        action = RetryAction.BACKOFF
    elif not 200 <= status < 300:
        action = classify_http(status, _retry_after(response.headers)).action
    else:
        action = RetryAction.DO_NOT_RETRY

    return OkxResponseInspection(
        payload=payload,
        error=_error(
            response=response,
            code=exchange_code or "missing_code",
            message=exchange_message or "OKX success code is missing",
            action=action,
            payload=payload,
        ),
    )


def classify_okx_response(response: _ResponseLike) -> OkxResponseError | None:
    return inspect_okx_response(response).error


def require_okx_success(response: _ResponseLike) -> Mapping[str, JsonPayload]:
    inspection = inspect_okx_response(response)
    if inspection.error is not None:
        raise inspection.error
    if inspection.payload is None:  # pragma: no cover - guarded by inspection.
        raise OkxPayloadError("OKX response has no decoded payload")
    return inspection.payload


__all__ = [
    "OkxPayloadError",
    "OkxResponseError",
    "OkxResponseInspection",
    "classify_okx_response",
    "inspect_okx_response",
    "require_okx_success",
]
