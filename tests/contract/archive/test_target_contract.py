from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from crypto_collector.archive.models import (
    ArchiveVerificationLevel,
    MultipartPartV1,
)
from crypto_collector.archive.receipt import ProviderChecksumV1
from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    ArchiveTarget,
    MultipartJournal,
    MultipartJournalConflict,
    MultipartJournalFactory,
    PutResult,
    ResumeState,
    TargetProbe,
    TargetUnavailable,
    TargetVerificationError,
    VerifyResult,
    publish_receipt_last,
)


class ScriptedTarget:
    id = "filesystem-a"

    def __init__(self) -> None:
        self.objects: dict[str, tuple[int, str]] = {}
        self.trace: list[tuple[str, str]] = []
        self.fail_verification_for: str | None = None
        self.crc_verification = False
        self.forged_verification_for: str | None = None
        self.put_version: str | None = None
        self.verify_version: str | None = None

    def probe(self) -> TargetProbe:
        return TargetProbe(
            target_id=self.id,
            target_type="filesystem",
            no_replace_capability="hardlink",
            mount_identity="test-mount",
        )

    def put(
        self,
        source: ArchiveObjectSource,
        key: str,
        resume: ResumeState | None = None,
        *,
        no_replace: bool = True,
    ) -> PutResult:
        assert resume is None
        assert no_replace is True
        role = source.path.stem
        self.trace.append(("put", role))
        identity = (source.size_bytes, source.sha256)
        existing = self.objects.setdefault(key, identity)
        if existing != identity:
            raise AssertionError("scripted immutable-object conflict")
        return PutResult(
            key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            created=existing is identity,
            resumed=False,
            provider_version_id=self.put_version,
        )

    def verify(
        self,
        key: str,
        expected_size: int,
        expected_sha256: str,
        *,
        provider_version_id: str | None = None,
    ) -> VerifyResult:
        assert provider_version_id == self.put_version
        role = Path(key).stem
        self.trace.append(("verify", role))
        if self.fail_verification_for == role:
            raise OSError("injected verification failure")
        assert self.objects[key] == (expected_size, expected_sha256)
        result = VerifyResult(
            key=key,
            size_bytes=expected_size,
            sha256=expected_sha256,
            method=("provider_crc64" if self.crc_verification else "readback_sha256"),
            level=(
                ArchiveVerificationLevel.PROVIDER_CRC64
                if self.crc_verification
                else ArchiveVerificationLevel.STORED_SHA256
            ),
            provider_checksum=(
                ProviderChecksumV1(
                    algorithm="crc64",
                    checksum_type="provider_crc64",
                    value="123",
                )
                if self.crc_verification
                else None
            ),
            provider_version_id=self.verify_version,
            verified=True,
            cleanup_strong=not self.crc_verification,
        )
        if self.forged_verification_for == role:
            object.__setattr__(result, "level", ArchiveVerificationLevel.PROVIDER_CRC64)
            object.__setattr__(result, "method", "provider_crc64")
            object.__setattr__(result, "provider_checksum", None)
            object.__setattr__(result, "cleanup_strong", True)
        return result

    def open_reader(
        self,
        key: str,
        *,
        provider_version_id: str | None = None,
    ):
        del key, provider_version_id
        raise NotImplementedError


def source(tmp_path: Path, role: str, content: bytes) -> ArchiveObjectSource:
    path = tmp_path / role
    path.write_bytes(content)
    return ArchiveObjectSource.from_path(path)


def test_target_protocol_is_runtime_checkable() -> None:
    assert isinstance(ScriptedTarget(), ArchiveTarget)


def test_multipart_journal_protocol_freezes_job_scoped_cas_api() -> None:
    class Journal:
        def load(self) -> ResumeState | None:
            return None

        def save(
            self,
            state: ResumeState,
            expected: ResumeState | None,
        ) -> None:
            del state, expected

        def clear(self, expected: ResumeState | None) -> None:
            del expected

    class Factory:
        def __call__(
            self,
            source: ArchiveObjectSource,
            key: str,
        ) -> Journal:
            del source, key
            return Journal()

    assert isinstance(Journal(), MultipartJournal)
    assert isinstance(Factory(), MultipartJournalFactory)
    assert issubclass(MultipartJournalConflict, TargetUnavailable)
    assert tuple(inspect.signature(MultipartJournal.load).parameters) == ("self",)
    assert tuple(inspect.signature(MultipartJournal.save).parameters) == (
        "self",
        "state",
        "expected",
    )
    assert tuple(inspect.signature(MultipartJournal.clear).parameters) == (
        "self",
        "expected",
    )
    assert tuple(inspect.signature(MultipartJournalFactory.__call__).parameters) == (
        "self",
        "source",
        "key",
    )


def test_receipt_last_helper_requires_strong_verification_in_exact_order(
    tmp_path: Path,
) -> None:
    target = ScriptedTarget()
    data = source(tmp_path, "data", b"stored-data")
    manifest = source(tmp_path, "manifest", b"source-manifest\n")
    receipt = source(tmp_path, "receipt", b"archive-receipt\n")

    result = publish_receipt_last(
        target,
        data=data,
        data_key="objects/data",
        source_manifest=manifest,
        source_manifest_key="objects/manifest",
        receipt=receipt,
        receipt_key="objects/receipt",
    )

    assert target.trace == [
        ("put", "data"),
        ("verify", "data"),
        ("put", "manifest"),
        ("verify", "manifest"),
        ("put", "receipt"),
        ("verify", "receipt"),
    ]
    assert result.data.verification.cleanup_strong
    assert result.source_manifest.verification.cleanup_strong
    assert result.receipt.verification.cleanup_strong


@pytest.mark.parametrize("failed_role", ("data", "manifest"))
def test_receipt_last_helper_never_publishes_receipt_before_prior_verification(
    tmp_path: Path,
    failed_role: str,
) -> None:
    target = ScriptedTarget()
    target.fail_verification_for = failed_role

    with pytest.raises(OSError, match="verification failure"):
        publish_receipt_last(
            target,
            data=source(tmp_path, "data", b"stored-data"),
            data_key="objects/data",
            source_manifest=source(tmp_path, "manifest", b"manifest\n"),
            source_manifest_key="objects/manifest",
            receipt=source(tmp_path, "receipt", b"receipt\n"),
            receipt_key="objects/receipt",
        )

    assert ("put", "receipt") not in target.trace


def test_receipt_last_retry_is_exact_idempotent(tmp_path: Path) -> None:
    target = ScriptedTarget()
    arguments = {
        "data": source(tmp_path, "data", b"stored-data"),
        "data_key": "objects/data",
        "source_manifest": source(tmp_path, "manifest", b"manifest\n"),
        "source_manifest_key": "objects/manifest",
        "receipt": source(tmp_path, "receipt", b"receipt\n"),
        "receipt_key": "objects/receipt",
    }

    first = publish_receipt_last(target, **arguments)
    second = publish_receipt_last(target, **arguments)

    assert len(target.objects) == 3
    assert first.receipt.put.key == second.receipt.put.key == "objects/receipt"
    assert first.receipt.put.sha256 == second.receipt.put.sha256


@pytest.mark.parametrize("failure", ("forged_semantics", "version_mismatch"))
def test_receipt_last_rejects_incomplete_or_wrong_version_verification_before_receipt(
    tmp_path: Path,
    failure: str,
) -> None:
    target = ScriptedTarget()
    if failure == "forged_semantics":
        target.forged_verification_for = "manifest"
    else:
        target.put_version = "created-version"
        target.verify_version = "different-version"

    with pytest.raises(TargetVerificationError):
        publish_receipt_last(
            target,
            data=source(tmp_path, "data", b"stored-data"),
            data_key="objects/data",
            source_manifest=source(tmp_path, "manifest", b"manifest\n"),
            source_manifest_key="objects/manifest",
            receipt=source(tmp_path, "receipt", b"receipt\n"),
            receipt_key="objects/receipt",
        )

    assert ("put", "receipt") not in target.trace


def test_receipt_last_allows_consistent_optional_crc_verification(
    tmp_path: Path,
) -> None:
    target = ScriptedTarget()
    target.crc_verification = True

    result = publish_receipt_last(
        target,
        data=source(tmp_path, "data", b"stored-data"),
        data_key="objects/data",
        source_manifest=source(tmp_path, "manifest", b"manifest\n"),
        source_manifest_key="objects/manifest",
        receipt=source(tmp_path, "receipt", b"receipt\n"),
        receipt_key="objects/receipt",
    )

    assert result.receipt.verification.verified
    assert not result.receipt.verification.cleanup_strong
    assert result.receipt.verification.level is ArchiveVerificationLevel.PROVIDER_CRC64


@pytest.mark.parametrize(
    "overrides",
    (
        {
            "level": ArchiveVerificationLevel.PROVIDER_CRC64,
            "method": "provider_crc64",
            "provider_checksum": None,
            "cleanup_strong": False,
        },
        {
            "level": ArchiveVerificationLevel.STORED_SHA256,
            "method": "readback_sha256",
            "provider_checksum": ProviderChecksumV1(
                algorithm="crc64",
                checksum_type="provider_crc64",
                value="123",
            ),
            "cleanup_strong": True,
        },
        {
            "level": ArchiveVerificationLevel.STORED_SHA256,
            "method": "provider_full_object_sha256",
            "provider_checksum": ProviderChecksumV1(
                algorithm="sha256",
                checksum_type="full_object",
                value="b" * 64,
            ),
            "cleanup_strong": True,
        },
        {
            "level": ArchiveVerificationLevel.STORED_SHA256,
            "method": "provider_crc64",
            "provider_checksum": ProviderChecksumV1(
                algorithm="crc64",
                checksum_type="provider_crc64",
                value="123",
            ),
            "cleanup_strong": True,
        },
    ),
)
def test_verify_result_rejects_inconsistent_level_method_or_evidence(
    overrides: dict[str, object],
) -> None:
    payload = {
        "key": "objects/data",
        "size_bytes": 1,
        "sha256": "a" * 64,
        "method": "readback_sha256",
        "level": ArchiveVerificationLevel.STORED_SHA256,
        "provider_checksum": None,
        "provider_version_id": None,
        "verified": True,
        "cleanup_strong": True,
    }

    with pytest.raises(ValueError, match="inconsistent"):
        VerifyResult(**{**payload, **overrides})  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "kwargs",
    (
        {"key": "../escape"},
        {"size_bytes": 0},
        {"sha256": "not-a-sha"},
        {"provider_version_id": "bad\nversion"},
    ),
)
def test_put_result_rejects_invalid_runtime_identity(kwargs: dict[str, object]) -> None:
    payload = {
        "key": "objects/data",
        "size_bytes": 1,
        "sha256": "a" * 64,
        "created": True,
        "resumed": False,
    }

    with pytest.raises((TypeError, ValueError)):
        PutResult(**{**payload, **kwargs})  # type: ignore[arg-type]


def test_probe_and_resume_models_reject_inconsistent_runtime_facts() -> None:
    with pytest.raises(ValueError, match="mount identity"):
        TargetProbe(
            target_id="filesystem-a",
            target_type="filesystem",
            no_replace_capability="hardlink",
            mount_identity=None,
        )

    for capability in (None, " hardlink", "hardlink "):
        with pytest.raises(ValueError, match="no-replace capability"):
            TargetProbe(
                target_id="filesystem-a",
                target_type="filesystem",
                no_replace_capability=capability,  # type: ignore[arg-type]
                mount_identity="test-mount",
            )

    with pytest.raises(ValueError, match="sorted and unique"):
        ResumeState(
            upload_id="upload",
            parts=(
                MultipartPartV1(part_number=2, etag="second", size_bytes=1),
                MultipartPartV1(part_number=1, etag="first", size_bytes=1),
            ),
        )


def test_receipt_last_validates_every_key_before_first_side_effect(
    tmp_path: Path,
) -> None:
    target = ScriptedTarget()

    with pytest.raises(ValueError, match="object key"):
        publish_receipt_last(
            target,
            data=source(tmp_path, "data", b"stored-data"),
            data_key="objects/data",
            source_manifest=source(tmp_path, "manifest", b"manifest\n"),
            source_manifest_key="objects/manifest",
            receipt=source(tmp_path, "receipt", b"receipt\n"),
            receipt_key="../escape",
        )

    assert target.trace == []


@pytest.mark.parametrize(
    ("data_key", "manifest_key", "receipt_key"),
    (
        ("objects/same", "objects/same", "objects/receipt"),
        ("objects/data", "objects/same", "objects/same"),
        ("objects/same", "objects/manifest", "objects/same"),
        ("objects/same", "objects/same", "objects/same"),
    ),
)
def test_receipt_last_rejects_duplicate_keys_before_first_side_effect(
    tmp_path: Path,
    data_key: str,
    manifest_key: str,
    receipt_key: str,
) -> None:
    target = ScriptedTarget()

    with pytest.raises(ValueError, match="pairwise distinct"):
        publish_receipt_last(
            target,
            data=source(tmp_path, "data", b"same-bytes"),
            data_key=data_key,
            source_manifest=source(tmp_path, "manifest", b"same-bytes"),
            source_manifest_key=manifest_key,
            receipt=source(tmp_path, "receipt", b"same-bytes"),
            receipt_key=receipt_key,
        )

    assert target.trace == []
