from __future__ import annotations

import hashlib
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    MultipartJournal,
    ResumeState,
)
from crypto_collector.archive.targets.s3 import (
    S3CheckpointPersistenceError,
    build_s3_target,
)
from crypto_collector.config.models import S3TargetConfig
from crypto_collector.config.primitives import SecretRef, SecretSnapshot

if TYPE_CHECKING:
    from tests.support.moto_s3 import MotoS3

pytestmark = pytest.mark.network
pytest_plugins = ("tests.support.moto_s3",)


class MemoryJournal(MultipartJournal):
    def __init__(self) -> None:
        self.resume: ResumeState | None = None
        self.save_calls = 0
        self.fail_after_saves: int | None = None

    def load(self) -> ResumeState | None:
        return self.resume

    def save(
        self,
        resume: ResumeState,
        expected_upload_id: str | None,
    ) -> None:
        self.save_calls += 1
        if (
            self.fail_after_saves is not None
            and self.save_calls > self.fail_after_saves
        ):
            raise OSError("injected durable journal failure")
        current_upload_id = None if self.resume is None else self.resume.upload_id
        if current_upload_id != expected_upload_id:
            raise AssertionError("multipart journal CAS mismatch")
        self.resume = resume

    def clear(self, expected_upload_id: str) -> None:
        current_upload_id = None if self.resume is None else self.resume.upload_id
        if current_upload_id != expected_upload_id:
            raise AssertionError("multipart journal CAS mismatch")
        self.resume = None


def _target(local: MotoS3, journal: MemoryJournal):
    access_ref = SecretRef.parse("env:TEST_S3_ACCESS_KEY")
    secret_ref = SecretRef.parse("env:TEST_S3_SECRET_KEY")
    config = S3TargetConfig.model_validate(
        {
            "id": "moto-s3",
            "type": "s3",
            "required": True,
            "prefix": "integration",
            "bucket": local.bucket,
            "endpoint": local.endpoint,
            "region": local.region,
            "addressing_style": "path",
            "multipart_size": "5MiB",
            "concurrency": 2,
            "credentials": {
                "access_key_id": access_ref.fingerprint_value(),
                "secret_access_key": secret_ref.fingerprint_value(),
            },
        }
    )
    secrets = SecretSnapshot.from_test_values(
        {
            access_ref: local.access_key,
            secret_ref: local.secret_key,
        }
    )
    return build_s3_target(
        config,
        secrets=secrets,
        journal_factory=lambda source, key: journal,
    )


def _source(tmp_path: Path, name: str, data: bytes) -> ArchiveObjectSource:
    path = tmp_path / name
    path.write_bytes(data)
    return ArchiveObjectSource(
        path=path,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def test_real_boto_client_put_verify_idempotency_and_multipart(
    moto_s3: MotoS3,
    tmp_path: Path,
) -> None:
    journal = MemoryJournal()
    target = _target(moto_s3, journal)
    small = _source(tmp_path, "small.bin", b"moto-s3-small")

    probe = target.probe()
    first = target.put(small, "integration/small.bin")
    verification = target.verify(
        first.key,
        small.size_bytes,
        small.sha256,
        provider_version_id=first.provider_version_id,
    )
    second = target.put(small, "integration/small.bin")

    assert probe.no_replace_capability == "if_none_match_star"
    assert first.created
    assert verification.verified
    assert verification.cleanup_strong
    assert not second.created
    with target.open_reader(
        first.key,
        provider_version_id=first.provider_version_id,
    ) as reader:
        assert reader.read() == b"moto-s3-small"

    large_data = b"m" * (5 * 1024 * 1024 + 17)
    large = _source(tmp_path, "large.bin", large_data)
    multipart = target.put(large, "integration/large.bin")
    multipart_verification = target.verify(
        multipart.key,
        large.size_bytes,
        large.sha256,
        provider_version_id=multipart.provider_version_id,
    )

    assert multipart.created
    assert journal.resume is not None
    assert len(journal.resume.parts) == 2
    assert multipart_verification.method == "readback_sha256"
    assert multipart_verification.cleanup_strong


def test_real_boto_multipart_resume_reconciles_remote_parts_after_crash(
    moto_s3: MotoS3,
    tmp_path: Path,
) -> None:
    journal = MemoryJournal()
    journal.fail_after_saves = 2
    target = _target(moto_s3, journal)
    large_data = b"r" * (10 * 1024 * 1024 + 17)
    source = _source(tmp_path, "resume.bin", large_data)

    with pytest.raises(S3CheckpointPersistenceError):
        target.put(source, "integration/resume.bin")

    interrupted = journal.resume
    assert interrupted is not None
    assert len(interrupted.parts) == 1
    journal.fail_after_saves = None

    resumed = target.put(
        source,
        "integration/resume.bin",
        resume=interrupted,
    )
    verification = target.verify(
        resumed.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=resumed.provider_version_id,
    )

    assert resumed.created
    assert resumed.resumed
    assert journal.resume is not None
    assert len(journal.resume.parts) == 3
    assert verification.verified
    assert verification.cleanup_strong
