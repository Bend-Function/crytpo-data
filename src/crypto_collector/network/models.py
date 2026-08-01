from __future__ import annotations

from dataclasses import dataclass
from typing import TypeAlias

from crypto_collector.config.models import EgressConfig
from crypto_collector.config.primitives import SecretValue
from crypto_collector.observability.redaction import redact

Egress: TypeAlias = EgressConfig


@dataclass(frozen=True, slots=True)
class HttpClientSpec:
    proxy: SecretValue | None
    trust_env: bool = False
    timeout_seconds: float = 10.0
    max_connections: int = 100
    max_keepalive_connections: int = 20

    def __repr__(self) -> str:
        proxy = "configured" if self.proxy is not None else None
        return (
            f"HttpClientSpec(proxy={proxy!r}, trust_env={self.trust_env!r}, "
            f"timeout_seconds={self.timeout_seconds!r}, "
            f"max_connections={self.max_connections!r}, "
            "max_keepalive_connections="
            f"{self.max_keepalive_connections!r})"
        )


@dataclass(frozen=True, slots=True)
class WebSocketConnectSpec:
    uri: str
    proxy: SecretValue | None
    open_timeout: float = 10.0
    close_timeout: float = 10.0
    max_queue: int = 16

    def __repr__(self) -> str:
        proxy = "configured" if self.proxy is not None else None
        return (
            f"WebSocketConnectSpec(uri={redact(self.uri)!r}, proxy={proxy!r}, "
            f"open_timeout={self.open_timeout!r}, "
            f"close_timeout={self.close_timeout!r}, max_queue={self.max_queue!r})"
        )
