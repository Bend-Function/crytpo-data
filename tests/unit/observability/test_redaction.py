from __future__ import annotations

import pytest

from crypto_collector.observability.redaction import redact


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
