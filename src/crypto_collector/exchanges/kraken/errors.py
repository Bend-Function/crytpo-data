from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from email.utils import formatdate
from enum import StrEnum
from typing import Any, Protocol, cast

from crypto_collector.domain import RestMetadata, SourceContext
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges.errors import ExchangeContractError, ExchangeError
from crypto_collector.network import RetryAction, classify_http

_SPOT_THROTTLED_UNTIL = re.compile(r"\AEService: Throttled: ([0-9]+)\Z")


class KrakenApi(StrEnum):
    SPOT = "spot"
    FUTURES = "futures"
    CHARTS = "charts"


class _ResponseLike(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def content(self) -> bytes: ...

    @property
    def headers(self) -> Any: ...


class KrakenPayloadError(ExchangeContractError):
    """A Kraken payload cannot satisfy the anonymous public-data contract."""


class KrakenProtocolError(KrakenPayloadError):
    def __init__(self, message: str, *, raw_text: str | None = None) -> None:
        self.raw_text = raw_text
        super().__init__(message)


class KrakenResponseError(ExchangeError):
    def __init__(
        self,
        *,
        api: KrakenApi,
        http_status: int,
        exchange_code: str,
        exchange_message: str,
        retry_action: RetryAction,
        retry_after: str | None,
        raw_payload: JsonPayload,
    ) -> None:
        self.api = api
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
            f"Kraken {api.value} response failed with HTTP {http_status}, "
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
    ) -> KrakenResponseError:
        if type(rest_metadata) is not RestMetadata:
            raise TypeError("rest_metadata must be RestMetadata")
        if type(source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        if self.rest_metadata is not None or self.source is not None:
            raise ValueError("Kraken response error already has request evidence")
        self.rest_metadata = rest_metadata
        self.source = source
        return self


@dataclass(frozen=True, slots=True)
class KrakenResponseInspection:
    payload: Mapping[str, JsonPayload] | None
    error: KrakenResponseError | None


def _status(value: object) -> int:
    if type(value) is not int or not 100 <= value <= 599:
        raise ValueError("response status_code must be an HTTP status integer")
    return value


def _retry_after(headers: Mapping[str, str]) -> str | None:
    for name, value in headers.items():
        if name.casefold() == "retry-after":
            return value
    return None


def _spot_business_retry_after(payload: JsonPayload) -> str | None:
    if not isinstance(payload, Mapping):
        return None
    errors = payload.get("error")
    if not isinstance(errors, list):
        return None
    for value in errors:
        if type(value) is not str:
            continue
        match = _SPOT_THROTTLED_UNTIL.fullmatch(value)
        if match is None:
            continue
        try:
            return formatdate(int(match.group(1)), usegmt=True)
        except (OverflowError, OSError, ValueError):
            return None
    return None


def _decode_payload(response: _ResponseLike) -> JsonPayload:
    try:
        value = decode_json(response.content)
    except (TypeError, ValueError) as error:
        raise KrakenPayloadError(
            "Kraken response body is not finite valid JSON"
        ) from error
    if value is None or type(value) in {bool, int, str}:
        return cast(JsonPayload, value)
    if isinstance(value, (list, dict)):
        return cast(JsonPayload, value)
    raise KrakenPayloadError("Kraken response body has an unsupported JSON value")


def _http_action(response: _ResponseLike) -> RetryAction:
    if response.status_code == 418:
        return RetryAction.BAN
    return classify_http(
        response.status_code,
        _retry_after(response.headers),
    ).action


def _response_error(
    response: _ResponseLike,
    *,
    api: KrakenApi,
    code: str,
    message: str,
    action: RetryAction,
    payload: JsonPayload,
) -> KrakenResponseError:
    retry_after = _retry_after(response.headers)
    if retry_after is None and api is KrakenApi.SPOT:
        # Kraken embeds an absolute Unix timestamp in this business error.  An
        # HTTP-date preserves that meaning for the shared Retry-After parser.
        retry_after = _spot_business_retry_after(payload)
    return KrakenResponseError(
        api=api,
        http_status=response.status_code,
        exchange_code=code,
        exchange_message=message,
        retry_action=action,
        retry_after=retry_after,
        raw_payload=payload,
    )


def _spot_failure(
    response: _ResponseLike,
    payload: Mapping[str, JsonPayload],
) -> tuple[str, str, RetryAction] | None:
    errors = payload.get("error")
    if not isinstance(errors, list) or any(type(item) is not str for item in errors):
        return (
            "invalid_envelope",
            "error must be an array of strings",
            _http_action(response),
        )
    if not errors and 200 <= response.status_code < 300:
        if "result" not in payload:
            return (
                "invalid_envelope",
                "Spot success response requires result",
                RetryAction.DO_NOT_RETRY,
            )
        return None
    message = "; ".join(cast(list[str], errors)) or "HTTP request failed"
    code = cast(list[str], errors)[0] if errors else f"http_{response.status_code}"
    if response.status_code == 418:
        action = RetryAction.BAN
    elif response.status_code == 429 or any(
        item.startswith(("EAPI:Rate limit exceeded", "EService: Throttled"))
        for item in cast(list[str], errors)
    ):
        action = RetryAction.THROTTLE
    elif any(
        item.startswith(
            ("EService:Unavailable", "EService:Busy", "EGeneral:Internal error")
        )
        for item in cast(list[str], errors)
    ):
        action = RetryAction.BACKOFF
    elif not 200 <= response.status_code < 300:
        action = _http_action(response)
    else:
        action = RetryAction.DO_NOT_RETRY
    return code, message, action


def _futures_failure(
    response: _ResponseLike,
    payload: Mapping[str, JsonPayload],
) -> tuple[str, str, RetryAction] | None:
    result = payload.get("result")
    if result == "success" and 200 <= response.status_code < 300:
        return None
    error_value = payload.get("error")
    message = error_value if type(error_value) is str else ""
    code = message or (
        result if type(result) is str and result != "success" else "missing_result"
    )
    if response.status_code == 418:
        action = RetryAction.BAN
    elif response.status_code == 429 or code == "apiLimitExceeded":
        action = RetryAction.THROTTLE
    elif not 200 <= response.status_code < 300:
        action = _http_action(response)
    elif code in {"Server Error", "Unavailable", "marketUnavailable"}:
        action = RetryAction.BACKOFF
    else:
        action = RetryAction.DO_NOT_RETRY
    return code, message or "Futures success result is missing", action


def _charts_failure(
    response: _ResponseLike,
    payload: Mapping[str, JsonPayload],
) -> tuple[str, str, RetryAction] | None:
    errors = payload.get("errors")
    singular = payload.get("error")
    result = payload.get("result")
    error_details: list[tuple[str, str]] = []
    if errors is not None:
        if not isinstance(errors, list):
            return (
                "invalid_envelope",
                "errors must be an array of objects",
                _http_action(response),
            )
        for index, value in enumerate(errors):
            if not isinstance(value, Mapping):
                return (
                    "invalid_envelope",
                    f"errors[{index}] must be an object",
                    _http_action(response),
                )
            item = cast(Mapping[str, JsonPayload], value)
            severity = item.get("severity")
            error_class = item.get("error_class")
            error_type = item.get("type")
            if any(
                type(field) is not str or not field
                for field in (severity, error_class, error_type)
            ):
                return (
                    "invalid_envelope",
                    f"errors[{index}] lacks severity, error_class, or type",
                    _http_action(response),
                )
            message = item.get("msg")
            field = item.get("field")
            if message is not None and type(message) is not str:
                return (
                    "invalid_envelope",
                    f"errors[{index}].msg must be string or null",
                    _http_action(response),
                )
            if field is not None and type(field) is not str:
                return (
                    "invalid_envelope",
                    f"errors[{index}].field must be string or null",
                    _http_action(response),
                )
            code = f"{error_class}:{error_type}"
            detail = message if type(message) is str and message else error_type
            if type(field) is str and field:
                detail = f"{detail} (field={field})"
            error_details.append((code, cast(str, detail)))
    if type(singular) is str and singular:
        error_details.append((singular, singular))
    if result == "error" and not error_details:
        error_details.append(("result=error", "result=error"))
    if not error_details and 200 <= response.status_code < 300:
        return None
    message = "; ".join(detail for _, detail in error_details) or "HTTP request failed"
    code = error_details[0][0] if error_details else f"http_{response.status_code}"
    if response.status_code == 418:
        action = RetryAction.BAN
    elif response.status_code == 429 or code == "apiLimitExceeded":
        action = RetryAction.THROTTLE
    elif not 200 <= response.status_code < 300:
        action = _http_action(response)
    else:
        action = RetryAction.DO_NOT_RETRY
    return code, message, action


def inspect_kraken_response(
    response: _ResponseLike,
    *,
    api: KrakenApi,
) -> KrakenResponseInspection:
    _status(response.status_code)
    if type(api) is not KrakenApi:
        raise TypeError("api must be KrakenApi")
    try:
        decoded = _decode_payload(response)
    except KrakenPayloadError:
        raw_text = response.content.decode("utf-8", errors="replace")
        return KrakenResponseInspection(
            payload=None,
            error=_response_error(
                response,
                api=api,
                code="invalid_json",
                message="response body is not finite valid JSON",
                action=_http_action(response),
                payload=raw_text,
            ),
        )
    if not isinstance(decoded, dict):
        return KrakenResponseInspection(
            payload=None,
            error=_response_error(
                response,
                api=api,
                code="invalid_envelope",
                message="response body is not an object",
                action=_http_action(response),
                payload=decoded,
            ),
        )
    payload = cast(dict[str, JsonPayload], decoded)
    failure = (
        _spot_failure(response, payload)
        if api is KrakenApi.SPOT
        else _futures_failure(response, payload)
        if api is KrakenApi.FUTURES
        else _charts_failure(response, payload)
    )
    if failure is None:
        return KrakenResponseInspection(payload=payload, error=None)
    code, message, action = failure
    return KrakenResponseInspection(
        payload=payload,
        error=_response_error(
            response,
            api=api,
            code=code,
            message=message,
            action=action,
            payload=payload,
        ),
    )


def classify_kraken_response(
    response: _ResponseLike,
    *,
    api: KrakenApi,
) -> KrakenResponseError | None:
    return inspect_kraken_response(response, api=api).error


def require_kraken_success(
    response: _ResponseLike,
    *,
    api: KrakenApi,
) -> Mapping[str, JsonPayload]:
    inspection = inspect_kraken_response(response, api=api)
    if inspection.error is not None:
        raise inspection.error
    if inspection.payload is None:  # pragma: no cover - guarded by inspection.
        raise KrakenPayloadError("Kraken success response has no payload")
    return inspection.payload


__all__ = [
    "KrakenApi",
    "KrakenPayloadError",
    "KrakenProtocolError",
    "KrakenResponseError",
    "KrakenResponseInspection",
    "classify_kraken_response",
    "inspect_kraken_response",
    "require_kraken_success",
]
