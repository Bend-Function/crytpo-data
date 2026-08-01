from __future__ import annotations

import logging
import re
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

_URL = re.compile(r"(?P<url>(?:https?|wss?|socks5h?)://[^\s]+)", re.IGNORECASE)
SENSITIVE_QUERY_NAMES = frozenset(
    {
        "access_key",
        "access_key_id",
        "access_token",
        "api_key",
        "apikey",
        "authorization",
        "client_secret",
        "ossaccesskeyid",
        "password",
        "security-token",
        "secret",
        "secret_key",
        "session_token",
        "sig",
        "signature",
        "token",
        "x-amz-credential",
        "x-amz-security-token",
        "x-amz-signature",
        "x-oss-security-token",
    }
)
SENSITIVE_HEADER_NAMES = frozenset(
    {
        "access-key",
        "access-passphrase",
        "access-sign",
        "api-key",
        "api-sign",
        "authorization",
        "cookie",
        "ok-access-key",
        "ok-access-passphrase",
        "ok-access-sign",
        "proxy-authorization",
        "set-cookie",
        "x-amz-security-token",
        "x-api-key",
        "x-bapi-api-key",
        "x-bapi-sign",
        "x-mbx-apikey",
        "x-oss-security-token",
    }
)
_SENSITIVE_HEADER_PATTERN = "|".join(
    re.escape(name) for name in sorted(SENSITIVE_HEADER_NAMES, key=len, reverse=True)
)
_SECRET_HEADER = re.compile(
    rf"(?im)\b(?P<name>{_SENSITIVE_HEADER_PATTERN})\s*:\s*[^\r\n]+"
)
_SECRET_HEADER_REPR = re.compile(
    rf"(?i)(?P<prefix>b?['\"](?:{_SENSITIVE_HEADER_PATTERN})"
    r"['\"]\s*[:,]\s*b?)"
    r"(?P<quote>['\"])(?:\\.|(?!(?P=quote)).)*(?P=quote)"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<name>[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|"
    r"ACCESS_KEY)[A-Z0-9_]*)\s*=\s*(?:"
    r'"(?:\\[^\r\n]|[^"\\\r\n])*"|'
    r"'(?:\\[^\r\n]|[^'\\\r\n])*'|"
    r"[^\s,;&]+)"
)
_AUTH_REPR = re.compile(
    r"(?i)\bauth[ \t]*=[ \t]*\([ \t]*"
    r"b?(?P<auth_user_quote>['\"])(?:\\[^\r\n]|(?!(?P=auth_user_quote))[^\r\n])*"
    r"(?P=auth_user_quote)[ \t]*,[ \t]*"
    r"b?(?P<auth_password_quote>['\"])(?:\\[^\r\n]|"
    r"(?!(?P=auth_password_quote))[^\r\n])*"
    r"(?P=auth_password_quote)[ \t]*\)"
)
_QUERY_ASSIGNMENT = re.compile(r"(?P<prefix>[?&])(?P<name>[^=&\s]+)=(?P<value>[^&\s]*)")
_DEPENDENCY_EXCEPTION = re.compile(r"(?is)\bexception\s*=.*$")
_DEPENDENCY_LOGGERS = (
    "httpx",
    "httpcore.connection",
    "httpcore.http11",
    "httpcore.http2",
    "httpcore.proxy",
    "httpcore.socks",
    "websockets.client",
)


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group("url")
    trailing = ""
    while raw and raw[-1] in ".,;)]}":
        trailing = raw[-1] + trailing
        raw = raw[:-1]
    try:
        parsed = urlsplit(raw)
        if parsed.scheme.casefold() in {"socks5", "socks5h"}:
            return "[REDACTED_PROXY]" + trailing
        host = parsed.hostname
        if host is None:
            return "[REDACTED_URL]" + trailing
        host_display = f"[{host}]" if ":" in host else host
        port = parsed.port
        netloc = host_display if port is None else f"{host_display}:{port}"
        query = urlencode(
            [
                (name, "***" if name.casefold() in SENSITIVE_QUERY_NAMES else value)
                for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            ]
        )
        return (
            urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))
            + trailing
        )
    except ValueError:
        return "[REDACTED_URL]" + trailing


def _redact_query_assignment(match: re.Match[str]) -> str:
    if unquote_plus(match.group("name")).casefold() not in SENSITIVE_QUERY_NAMES:
        return match.group(0)
    return f"{match.group('prefix')}{match.group('name')}=***"


def redact(text: str) -> str:
    redacted = _URL.sub(_redact_url, text)
    redacted = _QUERY_ASSIGNMENT.sub(_redact_query_assignment, redacted)
    redacted = _SECRET_HEADER.sub(lambda match: f"{match.group('name')}: ***", redacted)
    redacted = _SECRET_HEADER_REPR.sub(
        lambda match: (
            f"{match.group('prefix')}{match.group('quote')}***{match.group('quote')}"
        ),
        redacted,
    )
    redacted = _AUTH_REPR.sub("auth=(***)", redacted)
    return _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group('name')}=***",
        redacted,
    )


class _DependencyLogRedactionFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except (AttributeError, TypeError, ValueError):
            rendered = str(record.msg)
        rendered = redact(rendered)
        rendered = _DEPENDENCY_EXCEPTION.sub("exception=***", rendered)
        record.msg = rendered
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        return True


_DEPENDENCY_FILTER = _DependencyLogRedactionFilter()


def install_dependency_log_redaction() -> None:
    for name in _DEPENDENCY_LOGGERS:
        logger = logging.getLogger(name)
        if _DEPENDENCY_FILTER not in logger.filters:
            logger.addFilter(_DEPENDENCY_FILTER)
