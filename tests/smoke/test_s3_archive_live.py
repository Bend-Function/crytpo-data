"""Opt-in S3-compatible archive smoke test.

Enable with RUN_LIVE_ARCHIVE_TESTS=1 and the explicit S3_ARCHIVE_* settings
below. The unique smoke prefix is intentionally retained because archive v1
does not authorize remote deletion.
"""

from __future__ import annotations

import hashlib
import os
import uuid
from pathlib import Path

import pytest

from crypto_collector.archive.targets.base import ArchiveObjectSource
from crypto_collector.archive.targets.s3 import build_s3_target
from crypto_collector.config.models import S3TargetConfig
from crypto_collector.config.primitives import SecretRef, SecretSnapshot

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.getenv("RUN_LIVE_ARCHIVE_TESTS") != "1",
        reason="set RUN_LIVE_ARCHIVE_TESTS=1 for an explicit S3 endpoint",
    ),
]


def _required_env(name: str) -> str:
    value = os.getenv(name)
    assert value, f"{name} must be set for the live S3 archive smoke test"
    return value


def test_explicit_s3_endpoint_can_probe_put_verify_and_read_back(
    tmp_path: Path,
) -> None:
    endpoint = _required_env("S3_ARCHIVE_ENDPOINT")
    bucket = _required_env("S3_ARCHIVE_BUCKET")
    region = _required_env("S3_ARCHIVE_REGION")
    addressing_style = _required_env("S3_ARCHIVE_ADDRESSING_STYLE")
    access_ref = SecretRef.parse(_required_env("S3_ARCHIVE_ACCESS_KEY_REF"))
    secret_ref = SecretRef.parse(_required_env("S3_ARCHIVE_SECRET_KEY_REF"))
    session_source = os.getenv("S3_ARCHIVE_SESSION_TOKEN_REF")
    session_ref = None if session_source is None else SecretRef.parse(session_source)
    refs = [access_ref, secret_ref]
    if session_ref is not None:
        refs.append(session_ref)
    secrets = SecretSnapshot.resolve_all(refs)
    prefix = f"crypto-collector-live-smoke/{uuid.uuid4().hex}"
    credentials: dict[str, object] = {
        "access_key_id": access_ref.fingerprint_value(),
        "secret_access_key": secret_ref.fingerprint_value(),
    }
    if session_ref is not None:
        credentials["session_token"] = session_ref.fingerprint_value()
    config = S3TargetConfig.model_validate(
        {
            "id": "s3-live-smoke",
            "type": "s3",
            "required": True,
            "prefix": prefix,
            "bucket": bucket,
            "endpoint": endpoint,
            "region": region,
            "addressing_style": addressing_style,
            "credentials": credentials,
        }
    )
    target = build_s3_target(config, secrets=secrets)
    target.probe()

    data = b"crypto-collector-live-s3-smoke\n"
    path = tmp_path / "live-s3-smoke.bin"
    path.write_bytes(data)
    source = ArchiveObjectSource(
        path=path,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    key = f"{prefix}/objects/{uuid.uuid4().hex}.bin"
    result = target.put(source, key)
    verification = target.verify(
        key,
        source.size_bytes,
        source.sha256,
        provider_version_id=result.provider_version_id,
    )

    assert result.created
    assert verification.verified
    assert verification.cleanup_strong
    with target.open_reader(
        key,
        provider_version_id=result.provider_version_id,
    ) as reader:
        assert reader.read() == data
