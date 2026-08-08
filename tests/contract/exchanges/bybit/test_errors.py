from __future__ import annotations

from decimal import Decimal

import httpx
import pytest

from crypto_collector.domain.json_codec import encode_json
from crypto_collector.exchanges.bybit.errors import (
    BYBIT_ACCESS_TOO_FREQUENT_MINIMUM_DELAY_NS,
    BybitResponseError,
    RetryAction,
    bybit_rate_limit_headers,
    classify_bybit_response,
    require_bybit_success,
)


def _response(
    status: int,
    payload: object,
    *,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(status, content=encode_json(payload), headers=headers)


def test_http_200_business_throttle_keeps_payload_and_exact_rate_headers() -> None:
    response = _response(
        200,
        {
            "retCode": 10006,
            "retMsg": "Too many visits!",
            "result": {},
            "futureErrorField": Decimal("1.25"),
        },
        headers={
            "Retry-After": "3",
            "X-Bapi-Limit": "10",
            "X-Bapi-Limit-Status": "0",
            "X-Bapi-Limit-Reset-Timestamp": "1672738134824",
            "X-Unrelated": "discarded",
        },
    )

    error = classify_bybit_response(response)

    assert error is not None
    assert error.exchange_code == "10006"
    assert error.retry_action is RetryAction.THROTTLE
    assert error.retry_after == "3"
    assert error.minimum_delay_ns == 0
    assert error.raw_payload["futureErrorField"] == Decimal("1.25")
    assert error.rate_limit_headers == {
        "retry-after": "3",
        "x-bapi-limit": "10",
        "x-bapi-limit-status": "0",
        "x-bapi-limit-reset-timestamp": "1672738134824",
    }


@pytest.mark.parametrize(
    "body",
    [
        b"403, access too frequent",
        b"<html><body>Access Too Frequent</body></html>",
        encode_json({"retCode": 0, "retMsg": "access too frequent", "result": {}}),
    ],
)
def test_only_access_too_frequent_403_is_a_ten_minute_ban(body: bytes) -> None:
    error = classify_bybit_response(httpx.Response(403, content=body))

    assert error is not None
    assert error.retry_action is RetryAction.BAN
    assert error.minimum_delay_ns == BYBIT_ACCESS_TOO_FREQUENT_MINIMUM_DELAY_NS
    assert error.minimum_delay_ns == 600_000_000_000


def test_generic_geographic_403_fails_closed_without_inventing_a_rate_ban() -> None:
    error = classify_bybit_response(
        httpx.Response(403, content=b"Forbidden in this region")
    )

    assert error is not None
    assert error.retry_action is RetryAction.DO_NOT_RETRY
    assert error.minimum_delay_ns == 0


def test_generic_403_does_not_become_throttle_from_a_business_code() -> None:
    error = classify_bybit_response(
        _response(
            403,
            {"retCode": 10006, "retMsg": "region restricted", "result": {}},
        )
    )

    assert error is not None
    assert error.retry_action is RetryAction.DO_NOT_RETRY
    assert error.minimum_delay_ns == 0


def test_http_429_is_throttle_even_when_json_ret_code_is_zero() -> None:
    error = classify_bybit_response(
        _response(429, {"retCode": 0, "retMsg": "", "result": {}})
    )

    assert error is not None
    assert error.retry_action is RetryAction.THROTTLE


@pytest.mark.parametrize(
    ("ret_code", "expected_action"),
    [
        (10000, RetryAction.BACKOFF),
        (10016, RetryAction.BACKOFF),
        (429, RetryAction.THROTTLE),
        (10006, RetryAction.THROTTLE),
        (10001, RetryAction.DO_NOT_RETRY),
        (10017, RetryAction.DO_NOT_RETRY),
        (10029, RetryAction.DO_NOT_RETRY),
    ],
)
def test_http_200_business_codes_have_evidenced_retry_policy(
    ret_code: int,
    expected_action: RetryAction,
) -> None:
    error = classify_bybit_response(
        _response(
            200,
            {"retCode": ret_code, "retMsg": "official business failure"},
        )
    )

    assert error is not None
    assert error.exchange_code == str(ret_code)
    assert error.retry_action is expected_action


def test_private_order_entry_ws_codes_are_not_claimed_as_public_rest_policy() -> None:
    for ret_code in (10429, 20003, 20006):
        error = classify_bybit_response(
            _response(200, {"retCode": ret_code, "retMsg": "not in REST evidence"})
        )

        assert error is not None
        assert error.retry_action is RetryAction.DO_NOT_RETRY


@pytest.mark.parametrize("ret_code", ["0", True, None])
def test_success_requires_an_integer_zero_ret_code(ret_code: object) -> None:
    error = classify_bybit_response(
        _response(200, {"retCode": ret_code, "retMsg": "", "result": {}})
    )

    assert error is not None
    assert error.exchange_code == "missing_or_invalid_ret_code"
    assert error.retry_action is RetryAction.DO_NOT_RETRY


def test_success_preserves_sparse_and_future_response_fields() -> None:
    payload = require_bybit_success(
        _response(
            200,
            {
                "retCode": 0,
                "retMsg": "OK",
                "result": {"list": []},
                "retExtInfo": {"future": [1, 2, 3]},
                "time": 1_700_000_000_000,
            },
        )
    )

    assert payload["retExtInfo"] == {"future": [1, 2, 3]}


def test_rate_header_filter_is_case_insensitive_and_does_not_guess_names() -> None:
    assert bybit_rate_limit_headers(
        {
            "RETRY-AFTER": "2",
            "X-BAPI-LIMIT": "20",
            "X-Bapi-Limit-Status": "19",
            "X-Bapi-Limit-Reset-Timestamp": "123",
            "X-Bapi-Unknown": "not-evidence",
        }
    ) == {
        "RETRY-AFTER": "2",
        "X-BAPI-LIMIT": "20",
        "X-Bapi-Limit-Status": "19",
        "X-Bapi-Limit-Reset-Timestamp": "123",
    }


def test_require_success_raises_typed_response_error() -> None:
    with pytest.raises(BybitResponseError) as raised:
        require_bybit_success(
            _response(200, {"retCode": 10006, "retMsg": "Too many visits!"})
        )

    assert raised.value.retry_action is RetryAction.THROTTLE
