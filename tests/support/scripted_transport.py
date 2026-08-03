from __future__ import annotations

from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import httpx

from crypto_collector.exchanges.contracts import PublicQueryValue


@dataclass(frozen=True, slots=True)
class RecordedGet:
    url: str
    params: Mapping[str, PublicQueryValue | Sequence[PublicQueryValue]] | None


class ScriptedHttpTransport:
    def __init__(self, *responses: httpx.Response) -> None:
        self._responses = deque(responses)
        self.requests: list[RecordedGet] = []

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
        self.requests.append(RecordedGet(url=url, params=params))
        if not self._responses:
            raise AssertionError("scripted HTTP transport has no response")
        return self._responses.popleft()


class ScriptedWebSocketTransport:
    def __init__(self, *connections: Any) -> None:
        self._connections = deque(connections)
        self.uris: list[str] = []

    def connect(self, uri: str) -> Any:
        self.uris.append(uri)
        if not self._connections:
            raise AssertionError("scripted WebSocket transport has no connection")
        return self._connections.popleft()
