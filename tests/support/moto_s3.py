from __future__ import annotations

import socket
import uuid
from collections.abc import Iterator
from dataclasses import dataclass

import boto3  # type: ignore[import-untyped]
import pytest
from moto.server import ThreadedMotoServer  # type: ignore[import-untyped]


@dataclass(frozen=True, slots=True)
class MotoS3:
    endpoint: str
    bucket: str
    region: str
    access_key: str
    secret_key: str


@pytest.fixture
def moto_s3(monkeypatch: pytest.MonkeyPatch) -> Iterator[MotoS3]:
    server = ThreadedMotoServer(
        ip_address="127.0.0.1",
        port=0,
        verbose=False,
    )
    with monkeypatch.context() as patch:
        patch.setattr(socket, "getfqdn", lambda name="": name or "127.0.0.1")
        server.start()
    try:
        host, port = server.get_host_and_port()
        endpoint = f"http://{host}:{port}"
        region = "us-east-1"
        access_key = "moto-access"
        secret_key = "moto-secret"
        bucket = f"crypto-collector-{uuid.uuid4().hex}"
        client = boto3.client(
            "s3",
            endpoint_url=endpoint,
            region_name=region,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )
        client.create_bucket(Bucket=bucket)
        client.put_bucket_versioning(
            Bucket=bucket,
            VersioningConfiguration={"Status": "Enabled"},
        )
        yield MotoS3(
            endpoint=endpoint,
            bucket=bucket,
            region=region,
            access_key=access_key,
            secret_key=secret_key,
        )
    finally:
        server.stop()


__all__ = ["MotoS3", "moto_s3"]
