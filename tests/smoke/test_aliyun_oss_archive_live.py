"""Opt-in Aliyun OSS archive round-trip smoke test.

Enable with RUN_LIVE_ARCHIVE_TESTS=1 and explicit ALIYUN_OSS_* environment
variables. The test intentionally leaves its uniquely-prefixed objects in OSS;
remote deletion is outside the v1 archiver contract.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest

from crypto_collector.archive.targets.aliyun_oss import build_aliyun_oss_target
from crypto_collector.archive.targets.base import ArchiveObjectSource
from crypto_collector.config.models import AliyunOssTargetConfig
from crypto_collector.config.primitives import SecretRef, SecretSnapshot

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("RUN_LIVE_ARCHIVE_TESTS") != "1",
        reason="set RUN_LIVE_ARCHIVE_TESTS=1 to contact Aliyun OSS",
    ),
]


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    assert value, f"{name} must be set when RUN_LIVE_ARCHIVE_TESTS=1"
    return value


def _live_config(prefix: str) -> tuple[AliyunOssTargetConfig, SecretSnapshot]:
    endpoint = _required_environment("ALIYUN_OSS_ENDPOINT")
    bucket = _required_environment("ALIYUN_OSS_BUCKET")
    access_ref = SecretRef.parse("env:ALIYUN_OSS_ACCESS_KEY_ID")
    secret_ref = SecretRef.parse("env:ALIYUN_OSS_ACCESS_KEY_SECRET")
    refs = [access_ref, secret_ref]
    credentials: dict[str, str] = {
        "access_key_id": access_ref.fingerprint_value(),
        "access_key_secret": secret_ref.fingerprint_value(),
    }
    if os.environ.get("ALIYUN_OSS_SECURITY_TOKEN"):
        token_ref = SecretRef.parse("env:ALIYUN_OSS_SECURITY_TOKEN")
        refs.append(token_ref)
        credentials["security_token"] = token_ref.fingerprint_value()
    config = AliyunOssTargetConfig.model_validate(
        {
            "id": "oss-live-smoke",
            "type": "aliyun_oss",
            "required": True,
            "bucket": bucket,
            "endpoint": endpoint,
            "region": os.environ.get("ALIYUN_OSS_REGION") or None,
            "prefix": prefix,
            "multipart_size": "100KiB",
            "concurrency": 1,
            "credentials": credentials,
        }
    )
    return config, SecretSnapshot.resolve_all(refs)


def test_aliyun_oss_probe_put_verify_restore_and_idempotency(
    tmp_path: Path,
) -> None:
    run_id = uuid.uuid4().hex
    prefix = f"crypto-collector-live-smoke/{run_id}"
    config, secrets = _live_config(prefix)
    payload = f"crypto-collector aliyun oss live smoke {run_id}\n".encode()
    source_path = tmp_path / "source.bin"
    source_path.write_bytes(payload)
    source = ArchiveObjectSource.from_path(source_path)
    key = f"{prefix}/_archive/v1/data.bin"

    with build_aliyun_oss_target(config, secrets=secrets) as target:
        probe = target.probe()
        assert probe.target_id == config.id
        assert probe.no_replace_capability == "x-oss-forbid-overwrite"

        uploaded = target.put(source, key)
        verification = target.verify(
            key,
            source.size_bytes,
            source.sha256,
            provider_version_id=uploaded.provider_version_id,
        )
        with target.open_reader(
            key,
            provider_version_id=uploaded.provider_version_id,
        ) as reader:
            restored = reader.read()
        repeated = target.put(source, key)

    assert uploaded.created is True
    assert verification.verified is True
    assert verification.cleanup_strong is True
    assert restored == payload
    assert repeated.created is False
    assert repeated.sha256 == source.sha256
