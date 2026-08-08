from __future__ import annotations

import asyncio
import hashlib
import io
import json
from collections import defaultdict, deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Self, TypeAlias
from urllib.parse import urlsplit

import httpx
import zstandard

from crypto_collector.domain import Exchange, RawEnvelope, Transport
from crypto_collector.exchanges.contracts import (
    NetworkAdmissionLease,
    NetworkAdmissionReleaseDisposition,
    PublicQueryValue,
)
from crypto_collector.storage import RawManifestV1
from crypto_collector.storage.serialize import decode_envelope_jsonl

HttpOutcome: TypeAlias = httpx.Response | BaseException
WsOutcome: TypeAlias = str | bytes | BaseException


class AllowAllNetworkAdmission:
    def __init__(self) -> None:
        self.active_leases = 0

    async def acquire(
        self,
        *,
        exchange: Exchange,
        transport: Transport,
        egress_id: str,
        quota_group: str,
        deadline_monotonic_ns: int | None,
    ) -> NetworkAdmissionLease:
        del deadline_monotonic_ns
        self.active_leases += 1

        async def release(disposition: NetworkAdmissionReleaseDisposition) -> None:
            del disposition
            self.active_leases -= 1

        return NetworkAdmissionLease(
            exchange=exchange,
            transport=transport,
            egress_id=egress_id,
            quota_group=quota_group,
            _release=release,
        )


class NoopRetryEffects:
    def apply(self, dispatch: object, decision: object) -> None:
        del dispatch, decision


@dataclass(frozen=True, slots=True)
class RecordedPublicGet:
    url: str
    path: str
    params: Mapping[str, PublicQueryValue | Sequence[PublicQueryValue]]


def okx_response(
    payload: Mapping[str, object],
    *,
    status: int = 200,
    headers: Mapping[str, str] | None = None,
) -> httpx.Response:
    return httpx.Response(
        status,
        headers=headers,
        content=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
    )


class RouteScriptedHttpTransport:
    """In-memory public HTTP transport with path-specific response scripts."""

    def __init__(self) -> None:
        self._outcomes: dict[str, deque[HttpOutcome]] = defaultdict(deque)
        self.requests: list[RecordedPublicGet] = []
        self.closed = False

    def add(self, path: str, *outcomes: HttpOutcome) -> None:
        if not path.startswith("/") or "?" in path:
            raise ValueError(
                "scripted HTTP path must be an absolute path without query"
            )
        if not outcomes:
            raise ValueError("scripted HTTP route requires at least one outcome")
        self._outcomes[path].extend(outcomes)

    async def get(
        self,
        url: str,
        *,
        params: Mapping[
            str,
            PublicQueryValue | Sequence[PublicQueryValue],
        ]
        | None = None,
        timeout: float | None = None,
    ) -> httpx.Response:
        del timeout
        path = urlsplit(url).path
        normalized = {} if params is None else dict(params)
        self.requests.append(RecordedPublicGet(url=url, path=path, params=normalized))
        outcomes = self._outcomes.get(path)
        if not outcomes:
            raise AssertionError(f"no scripted HTTP outcome remains for {path!r}")
        outcome = outcomes.popleft()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    async def aclose(self) -> None:
        self.closed = True

    def remaining(self, path: str) -> int:
        return len(self._outcomes.get(path, ()))


class AutoAckWebSocketConnection:
    """One-shot WebSocket context that ACKs the exact subscribe message sent."""

    def __init__(self, connection_id: str, *outcomes: WsOutcome) -> None:
        if not connection_id:
            raise ValueError("connection_id must be non-empty")
        self.connection_id = connection_id
        self._outcomes = deque(outcomes)
        self._acks: deque[str] = deque()
        self._blocked = asyncio.Event()
        self.drained = asyncio.Event()
        self.sent: list[str] = []
        self.closed = False

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self.closed = True

    @property
    def subscribe_arguments(self) -> tuple[dict[str, object], ...]:
        """Return the exact arguments sent in subscribe commands."""

        arguments: list[dict[str, object]] = []
        for raw_message in self.sent:
            message = json.loads(raw_message)
            if not isinstance(message, dict):
                continue
            if message.get("op") != "subscribe":
                continue
            raw_arguments = message.get("args")
            if not isinstance(raw_arguments, list):
                raise TypeError("subscribe args must be a list")
            for raw_argument in raw_arguments:
                if not isinstance(raw_argument, dict):
                    raise TypeError("subscribe argument must be an object")
                arguments.append(dict(raw_argument))
        return tuple(arguments)

    async def send(self, message: str) -> None:
        self.sent.append(message)
        if message == "ping":
            return
        try:
            payload = json.loads(message)
        except json.JSONDecodeError:
            return
        if not isinstance(payload, dict) or payload.get("op") != "subscribe":
            return
        request_id = payload.get("id")
        arguments = payload.get("args")
        if not isinstance(request_id, str) or not isinstance(arguments, list):
            raise TypeError("OKX subscribe message lacks id or args")
        for argument in arguments:
            if not isinstance(argument, dict):
                raise TypeError("OKX subscribe args must be objects")
            self._acks.append(
                json.dumps(
                    {
                        "id": request_id,
                        "event": "subscribe",
                        "arg": argument,
                        "connId": self.connection_id,
                    },
                    separators=(",", ":"),
                )
            )

    async def recv(self) -> str | bytes:
        if self._acks:
            return self._acks.popleft()
        if self._outcomes:
            outcome = self._outcomes.popleft()
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome
        self.drained.set()
        await self._blocked.wait()
        raise AssertionError("unreachable scripted WebSocket wake")


class RouteScriptedWebSocketTransport:
    """In-memory WebSocket transport with endpoint-specific generations."""

    def __init__(self) -> None:
        self._connections: dict[str, deque[AutoAckWebSocketConnection]] = defaultdict(
            deque
        )
        self.uris: list[str] = []

    def add(self, uri: str, *connections: AutoAckWebSocketConnection) -> None:
        if urlsplit(uri).scheme not in {"ws", "wss"}:
            raise ValueError("scripted WebSocket URI must use ws or wss")
        if not connections:
            raise ValueError("scripted WebSocket route requires a connection")
        self._connections[uri].extend(connections)

    def connect(self, uri: str) -> AutoAckWebSocketConnection:
        self.uris.append(uri)
        connections = self._connections.get(uri)
        if not connections:
            raise AssertionError(
                f"no scripted WebSocket connection remains for {uri!r}"
            )
        return connections.popleft()

    def remaining(self, uri: str) -> int:
        return len(self._connections.get(uri, ()))


def read_raw_rows(
    data_root: Path,
    manifests: Sequence[RawManifestV1],
) -> dict[str, list[RawEnvelope]]:
    rows: dict[str, list[RawEnvelope]] = defaultdict(list)
    for manifest in manifests:
        source = data_root / manifest.data_relative_path
        compressed = source.read_bytes()
        if len(compressed) != manifest.file_size_bytes:
            raise AssertionError("raw file size does not match manifest")
        if hashlib.sha256(compressed).hexdigest() != manifest.file_sha256:
            raise AssertionError("raw file digest does not match manifest")
        with zstandard.ZstdDecompressor().stream_reader(
            io.BytesIO(compressed),
            read_across_frames=True,
        ) as reader:
            plain = reader.read()
        decoded = [decode_envelope_jsonl(line + b"\n") for line in plain.splitlines()]
        if len(decoded) != manifest.record_count:
            raise AssertionError("raw record count does not match manifest")
        rows[manifest.logical_stream].extend(decoded)
    for stream_rows in rows.values():
        stream_rows.sort(key=lambda row: row.writer_sequence)
    return dict(rows)


__all__ = [
    "AllowAllNetworkAdmission",
    "AutoAckWebSocketConnection",
    "NoopRetryEffects",
    "RecordedPublicGet",
    "RouteScriptedHttpTransport",
    "RouteScriptedWebSocketTransport",
    "okx_response",
    "read_raw_rows",
]
