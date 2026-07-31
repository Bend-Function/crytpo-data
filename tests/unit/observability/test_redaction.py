from __future__ import annotations

import logging

import pytest

from crypto_collector.observability.redaction import (
    install_dependency_log_redaction,
    redact,
)


@pytest.mark.parametrize(
    "text",
    [
        "https://user:pass@example.test/path?token=abc",
        "Authorization: Bearer abc",
        "x-oss-security-token: abc",
        "AWS_SECRET_ACCESS_KEY=abc",
    ],
)
def test_redactor_removes_supported_secret_forms(text: str) -> None:
    redacted = redact(text)

    assert "abc" not in redacted
    assert "pass" not in redacted


def test_redactor_preserves_nonsecret_url_components() -> None:
    redacted = redact(
        "request https://user:pass@example.test:8443/path?token=abc&limit=100"
    )

    assert "example.test:8443/path" in redacted
    assert "limit=100" in redacted
    assert "user" not in redacted
    assert "pass" not in redacted
    assert "abc" not in redacted


def test_exception_text_is_redacted_before_logging() -> None:
    error = ValueError("proxy failed: socks5h://user:password@127.0.0.1:1080?token=abc")

    redacted = redact(str(error))

    assert "password" not in redacted
    assert "abc" not in redacted
    assert "127.0.0.1:1080" in redacted


def test_redactor_removes_complete_comma_delimited_authorization_value() -> None:
    redacted = redact(
        'Authorization: Digest username="collector", response="secret-response"'
    )

    assert "collector" not in redacted
    assert "secret-response" not in redacted


def test_redactor_removes_aws_presigned_query_credentials() -> None:
    redacted = redact(
        "https://bucket.example/object?"
        "X-Amz-Credential=access-key&X-Amz-Signature=request-signature"
    )

    assert "access-key" not in redacted
    assert "request-signature" not in redacted


def test_redactor_removes_httpcore_proxy_auth_repr() -> None:
    redacted = redact("connect_tcp.started auth=(b'user', b'password') timeout=10")

    assert "user" not in redacted
    assert "password" not in redacted


def test_redactor_removes_auth_repr_with_parentheses_in_credentials() -> None:
    redacted = redact("connect_tcp.started auth=(b'user)', b'pass)word') timeout=10")

    assert "user" not in redacted
    assert "pass)word" not in redacted
    assert "timeout=10" in redacted


def test_redactor_does_not_match_auth_repr_across_carriage_return() -> None:
    text = "auth=(b'user', b'pass\rword') timeout=10"

    assert redact(text) == text


@pytest.mark.parametrize(
    "text",
    [
        "headers=[(b'Authorization', b'Bearer structured-secret')]",
        "headers={'Proxy-Authorization': 'Basic structured-secret'}",
        'headers={"x-amz-security-token": "structured-secret"}',
        "headers=[(b'X-MBX-APIKEY', b'structured-secret')]",
        "headers={'OK-ACCESS-PASSPHRASE': 'structured-secret'}",
    ],
)
def test_redactor_removes_structured_sensitive_headers(text: str) -> None:
    redacted = redact(text)

    assert "structured-secret" not in redacted


def test_dependency_log_filter_redacts_urls_headers_paths_and_exceptions(
    caplog: pytest.LogCaptureFixture,
) -> None:
    install_dependency_log_redaction()
    caplog.set_level(logging.DEBUG)

    logging.getLogger("httpx").info(
        "HTTP Request: GET %s",
        "https://user:url-secret@example.test/path?apiKey=query-secret",
    )
    logging.getLogger("httpcore.http11").debug(
        "receive_response_headers.complete headers=%r",
        [(b"Authorization", b"Bearer header-secret")],
    )
    logging.getLogger("websockets.client").debug("> GET /ws?token=path-secret HTTP/1.1")
    logging.getLogger("httpcore.connection").debug(
        "connect_tcp.failed exception=%r",
        ValueError("bare-exception-secret"),
    )

    assert "url-secret" not in caplog.text
    assert "query-secret" not in caplog.text
    assert "header-secret" not in caplog.text
    assert "path-secret" not in caplog.text
    assert "bare-exception-secret" not in caplog.text
