from __future__ import annotations

import asyncio
import hmac
import ipaddress
from dataclasses import dataclass, field
from typing import Final

from websockets.asyncio.server import Server, ServerConnection, serve

_SOCKS_VERSION: Final = 5
_AUTH_NONE: Final = 0
_AUTH_USERNAME_PASSWORD: Final = 2
_AUTH_UNACCEPTABLE: Final = 0xFF
_ADDRESS_IPV4: Final = 1
_ADDRESS_DOMAIN: Final = 3
_ADDRESS_IPV6: Final = 4


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except (ConnectionError, OSError):
        pass


async def _relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65_536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


@dataclass(slots=True)
class LoopbackApps:
    http_server: asyncio.Server
    websocket_server: Server
    http_port: int
    websocket_port: int

    @property
    def http_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}/catalog"

    @property
    def websocket_url(self) -> str:
        return f"ws://127.0.0.1:{self.websocket_port}/ws"

    @property
    def proxied_http_url(self) -> str:
        return f"http://venue.invalid:{self.http_port}/catalog"

    @property
    def proxied_websocket_url(self) -> str:
        return f"ws://venue.invalid:{self.websocket_port}/ws"

    @classmethod
    async def start(cls) -> LoopbackApps:
        async def handle_http(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            try:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: 2\r\n"
                    b"Connection: close\r\n\r\n"
                    b"ok"
                )
                await writer.drain()
            finally:
                await _close_writer(writer)

        async def handle_websocket(connection: ServerConnection) -> None:
            await connection.send("ready")
            await connection.wait_closed()

        http_server = await asyncio.start_server(handle_http, "127.0.0.1", 0)
        http_socket = http_server.sockets[0]
        websocket_server = await serve(handle_websocket, "127.0.0.1", 0)
        websocket_socket = websocket_server.sockets[0]
        return cls(
            http_server=http_server,
            websocket_server=websocket_server,
            http_port=int(http_socket.getsockname()[1]),
            websocket_port=int(websocket_socket.getsockname()[1]),
        )

    async def close(self) -> None:
        self.http_server.close()
        self.websocket_server.close()
        await asyncio.gather(
            self.http_server.wait_closed(),
            self.websocket_server.wait_closed(),
        )


@dataclass(slots=True)
class LoopbackSocks5Server:
    server: asyncio.Server
    port: int
    destinations: dict[tuple[str, int], tuple[str, int]]
    username: str = "u"
    password: str = "secret"
    requested_domains: list[str] = field(default_factory=list)
    redacted_logs: list[str] = field(default_factory=list)

    @classmethod
    async def start(
        cls,
        *,
        destinations: dict[tuple[str, int], tuple[str, int]],
        username: str = "u",
        password: str = "secret",
    ) -> LoopbackSocks5Server:
        holder: dict[str, LoopbackSocks5Server] = {}

        async def handle(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await holder["server"]._handle_client(reader, writer)

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])
        instance = cls(
            server=server,
            port=port,
            destinations=dict(destinations),
            username=username,
            password=password,
        )
        holder["server"] = instance
        return instance

    def url(
        self,
        *,
        scheme: str = "socks5h",
        credentials: tuple[str, str] | None = None,
    ) -> str:
        username, password = credentials or (self.username, self.password)
        return f"{scheme}://{username}:{password}@127.0.0.1:{self.port}"

    async def close(self) -> None:
        self.server.close()
        await self.server.wait_closed()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            version, method_count = await reader.readexactly(2)
            methods = await reader.readexactly(method_count)
            if version != _SOCKS_VERSION:
                raise ValueError("unsupported SOCKS version")
            method = (
                _AUTH_USERNAME_PASSWORD
                if _AUTH_USERNAME_PASSWORD in methods
                else _AUTH_NONE
                if _AUTH_NONE in methods and not self.username
                else _AUTH_UNACCEPTABLE
            )
            writer.write(bytes((_SOCKS_VERSION, method)))
            await writer.drain()
            if method == _AUTH_UNACCEPTABLE:
                return
            if method == _AUTH_USERNAME_PASSWORD:
                await self._authenticate(reader, writer)

            version, command, _reserved, address_type = await reader.readexactly(4)
            if version != _SOCKS_VERSION or command != 1:
                raise ValueError("only SOCKS5 CONNECT is supported")
            host = await self._read_host(reader, address_type)
            port = int.from_bytes(await reader.readexactly(2), "big")
            destination = self.destinations.get((host, port))
            if destination is None:
                self.redacted_logs.append(f"rejected destination {host}:{port}")
                writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                return

            if address_type == _ADDRESS_DOMAIN:
                self.requested_domains.append(host)
            upstream_reader, upstream_writer = await asyncio.open_connection(
                *destination
            )
            writer.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
            await writer.drain()
            await asyncio.gather(
                _relay(reader, upstream_writer),
                _relay(upstream_reader, writer),
            )
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            OSError,
            ValueError,
        ) as error:
            self.redacted_logs.append(type(error).__name__)
        finally:
            if upstream_writer is not None:
                await _close_writer(upstream_writer)
            await _close_writer(writer)

    async def _authenticate(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        version, username_length = await reader.readexactly(2)
        username = (await reader.readexactly(username_length)).decode("utf-8")
        password_length = (await reader.readexactly(1))[0]
        password = (await reader.readexactly(password_length)).decode("utf-8")
        accepted = (
            version == 1
            and hmac.compare_digest(username, self.username)
            and hmac.compare_digest(password, self.password)
        )
        writer.write(bytes((1, 0 if accepted else 1)))
        await writer.drain()
        if not accepted:
            raise ValueError("SOCKS authentication failed")

    async def _read_host(self, reader: asyncio.StreamReader, address_type: int) -> str:
        if address_type == _ADDRESS_DOMAIN:
            size = (await reader.readexactly(1))[0]
            return (await reader.readexactly(size)).decode("idna")
        if address_type == _ADDRESS_IPV4:
            return str(ipaddress.ip_address(await reader.readexactly(4)))
        if address_type == _ADDRESS_IPV6:
            return str(ipaddress.ip_address(await reader.readexactly(16)))
        raise ValueError("unsupported SOCKS address type")
