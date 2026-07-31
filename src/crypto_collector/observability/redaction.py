from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_URL = re.compile(r"(?P<url>(?:https?|wss?|socks5h?)://[^\s]+)", re.IGNORECASE)
_SECRET_QUERY_NAMES = frozenset(
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
_SECRET_HEADER = re.compile(
    r"(?im)\b(?P<name>authorization|proxy-authorization|"
    r"x-oss-security-token|x-amz-security-token)\s*:\s*[^\r\n]+"
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?P<name>[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|"
    r"ACCESS_KEY)[A-Z0-9_]*)\s*=\s*[^\s,;&]+"
)
_AUTH_REPR = re.compile(r"(?i)\bauth\s*=\s*\([^\r\n)]*\)")


def _redact_url(match: re.Match[str]) -> str:
    raw = match.group("url")
    trailing = ""
    while raw and raw[-1] in ".,;)]}":
        trailing = raw[-1] + trailing
        raw = raw[:-1]
    try:
        parsed = urlsplit(raw)
        host = parsed.hostname
        if host is None:
            return "[REDACTED_URL]" + trailing
        host_display = f"[{host}]" if ":" in host else host
        port = parsed.port
        netloc = host_display if port is None else f"{host_display}:{port}"
        query = urlencode(
            [
                (name, "***" if name.casefold() in _SECRET_QUERY_NAMES else value)
                for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            ]
        )
        return (
            urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))
            + trailing
        )
    except ValueError:
        return "[REDACTED_URL]" + trailing


def redact(text: str) -> str:
    redacted = _URL.sub(_redact_url, text)
    redacted = _SECRET_HEADER.sub(lambda match: f"{match.group('name')}: ***", redacted)
    redacted = _AUTH_REPR.sub("auth=(***)", redacted)
    return _SECRET_ASSIGNMENT.sub(
        lambda match: f"{match.group('name')}=***",
        redacted,
    )
