from __future__ import annotations

import asyncio
import hmac
import ipaddress
import ssl
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
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
class TlsContexts:
    server: ssl.SSLContext
    client: ssl.SSLContext


def create_test_tls_contexts(directory: Path) -> TlsContexts:
    now = datetime.now(tz=UTC)
    ca_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Collector Test CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "venue.invalid")])
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("venue.invalid"),
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    ca_path = directory / "ca.pem"
    certificate_path = directory / "server.pem"
    key_path = directory / "server-key.pem"
    ca_path.write_bytes(ca_certificate.public_bytes(serialization.Encoding.PEM))
    certificate_path.write_bytes(
        server_certificate.public_bytes(serialization.Encoding.PEM)
    )
    key_path.write_bytes(
        server_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate_path, key_path)
    client_context = ssl.create_default_context(cafile=str(ca_path))
    return TlsContexts(server=server_context, client=client_context)


@dataclass(slots=True)
class LoopbackApps:
    http_server: asyncio.Server
    https_server: asyncio.Server
    websocket_server: Server
    secure_websocket_server: Server
    http_port: int
    https_port: int
    websocket_port: int
    secure_websocket_port: int
    https_connection_count: int = 0
    https_hosts: list[str] = field(default_factory=list)

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

    @property
    def proxied_https_url(self) -> str:
        return f"https://venue.invalid:{self.https_port}/catalog"

    @property
    def proxied_secure_websocket_url(self) -> str:
        return f"wss://venue.invalid:{self.secure_websocket_port}/ws"

    @classmethod
    async def start(cls, *, server_ssl: ssl.SSLContext) -> LoopbackApps:
        holder: dict[str, LoopbackApps] = {}

        async def serve_http(
            reader: asyncio.StreamReader,
            writer: asyncio.StreamWriter,
            *,
            record_tls_connection: bool,
        ) -> None:
            if record_tls_connection:
                holder["apps"].https_connection_count += 1
            try:
                while True:
                    try:
                        request = await reader.readuntil(b"\r\n\r\n")
                    except asyncio.IncompleteReadError:
                        break
                    if record_tls_connection:
                        for line in request.split(b"\r\n"):
                            if line.lower().startswith(b"host:"):
                                holder["apps"].https_hosts.append(
                                    line.partition(b":")[2].strip().decode("ascii")
                                )
                                break
                    writer.write(
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Length: 2\r\n"
                        b"Connection: keep-alive\r\n\r\n"
                        b"ok"
                    )
                    await writer.drain()
            finally:
                await _close_writer(writer)

        async def handle_http(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await serve_http(reader, writer, record_tls_connection=False)

        async def handle_https(
            reader: asyncio.StreamReader, writer: asyncio.StreamWriter
        ) -> None:
            await serve_http(reader, writer, record_tls_connection=True)

        async def handle_websocket(connection: ServerConnection) -> None:
            await connection.send("ready")
            await connection.wait_closed()

        http_server = await asyncio.start_server(handle_http, "127.0.0.1", 0)
        http_socket = http_server.sockets[0]
        https_server = await asyncio.start_server(
            handle_https,
            "127.0.0.1",
            0,
            ssl=server_ssl,
        )
        https_socket = https_server.sockets[0]
        websocket_server = await serve(handle_websocket, "127.0.0.1", 0)
        websocket_socket = websocket_server.sockets[0]
        secure_websocket_server = await serve(
            handle_websocket,
            "127.0.0.1",
            0,
            ssl=server_ssl,
        )
        secure_websocket_socket = secure_websocket_server.sockets[0]
        instance = cls(
            http_server=http_server,
            https_server=https_server,
            websocket_server=websocket_server,
            secure_websocket_server=secure_websocket_server,
            http_port=int(http_socket.getsockname()[1]),
            https_port=int(https_socket.getsockname()[1]),
            websocket_port=int(websocket_socket.getsockname()[1]),
            secure_websocket_port=int(secure_websocket_socket.getsockname()[1]),
        )
        holder["apps"] = instance
        return instance

    async def close(self) -> None:
        self.http_server.close()
        self.https_server.close()
        self.websocket_server.close()
        self.secure_websocket_server.close()
        await asyncio.gather(
            self.http_server.wait_closed(),
            self.https_server.wait_closed(),
            self.websocket_server.wait_closed(),
            self.secure_websocket_server.wait_closed(),
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
