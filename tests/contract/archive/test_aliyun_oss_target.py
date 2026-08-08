from __future__ import annotations

import hashlib
import logging
import sys
import threading
import traceback
from collections.abc import Iterable
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

import crypto_collector.archive.targets.aliyun_oss as aliyun_oss_module
from crypto_collector.archive.models import (
    ArchiveVerificationLevel,
    MultipartPartV1,
)
from crypto_collector.archive.state import (
    ExistingObjectMismatch,
    StoredObjectMismatch,
)
from crypto_collector.archive.targets.aliyun_oss import (
    OssBusinessError,
    OssObjectMetadata,
    OssPartPage,
    OssProviderError,
    OssProviderErrorKind,
    OssRemotePart,
    OssTargetUnavailable,
    OssUploadResult,
    build_aliyun_oss_target,
    crc64_ecma,
)
from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    ArchiveTarget,
    MultipartJournal,
    MultipartJournalFactory,
    ResumeState,
    TargetClosed,
    TargetUnavailable,
    TargetVerificationError,
    UnsafeObjectKey,
    publish_receipt_last,
)
from crypto_collector.config import SecretRef, SecretSnapshot
from crypto_collector.config.models import AliyunOssTargetConfig
from crypto_collector.config.primitives import SecretValue

PART_SIZE = 100 * 1024


def oss_config(
    *,
    required: bool = False,
    concurrency: int = 1,
    security_token: bool = False,
    multipart_size: str = "100KiB",
) -> AliyunOssTargetConfig:
    credentials: dict[str, str] = {
        "access_key_id": "env:TEST_OSS_ACCESS_KEY",
        "access_key_secret": "env:TEST_OSS_SECRET_KEY",
    }
    if security_token:
        credentials["security_token"] = "env:TEST_OSS_SECURITY_TOKEN"
    return AliyunOssTargetConfig.model_validate(
        {
            "id": "oss-primary",
            "type": "aliyun_oss",
            "required": required,
            "bucket": "market-data",
            "endpoint": "https://oss-ap-southeast-1.aliyuncs.com",
            "region": "ap-southeast-1",
            "storage_class": "Standard",
            "prefix": "research",
            "multipart_size": multipart_size,
            "concurrency": concurrency,
            "credentials": credentials,
        }
    )


def secret_snapshot(*, security_token: bool = False) -> SecretSnapshot:
    values = {
        SecretRef.parse("env:TEST_OSS_ACCESS_KEY"): "access-plaintext",
        SecretRef.parse("env:TEST_OSS_SECRET_KEY"): "secret-plaintext",
    }
    if security_token:
        values[SecretRef.parse("env:TEST_OSS_SECURITY_TOKEN")] = "token-plaintext"
    return SecretSnapshot.from_test_values(values)


def source_file(tmp_path: Path, data: bytes) -> ArchiveObjectSource:
    path = tmp_path / "stored.bin"
    path.write_bytes(data)
    return ArchiveObjectSource.from_path(path)


@dataclass
class _Upload:
    key: str
    parts: dict[int, bytes]


class MemoryJournal(MultipartJournal):
    def __init__(self) -> None:
        self.state: ResumeState | None = None
        self.events: list[tuple[str, str, tuple[int, ...]]] = []

    def load(self) -> ResumeState | None:
        return self.state

    def save(
        self,
        state: ResumeState,
        expected_upload_id: str | None,
    ) -> None:
        current = self.state
        if expected_upload_id is None:
            if current is not None:
                raise RuntimeError("checkpoint create lost compare-and-swap")
        elif current is None or current.upload_id != expected_upload_id:
            raise RuntimeError("checkpoint update lost compare-and-swap")
        self.state = state
        self.events.append(
            ("save", state.upload_id, tuple(part.part_number for part in state.parts))
        )

    def clear(self, expected_upload_id: str) -> None:
        current = self.state
        if current is None or current.upload_id != expected_upload_id:
            raise RuntimeError("checkpoint clear lost compare-and-swap")
        self.state = None
        self.events.append(("clear", expected_upload_id, ()))


class FailOnePartCheckpointJournal(MemoryJournal):
    def __init__(self) -> None:
        super().__init__()
        self._failed = False

    def save(
        self,
        state: ResumeState,
        expected_upload_id: str | None,
    ) -> None:
        if state.parts and not self._failed:
            self._failed = True
            raise RuntimeError("injected checkpoint failure")
        super().save(
            state,
            expected_upload_id,
        )


class FailInitialCheckpointJournal(MemoryJournal):
    def save(
        self,
        state: ResumeState,
        expected_upload_id: str | None,
    ) -> None:
        del state, expected_upload_id
        raise RuntimeError("injected initial checkpoint failure")


class SignalingJournal(MemoryJournal):
    def __init__(self) -> None:
        super().__init__()
        self.part_checkpointed = threading.Event()

    def save(
        self,
        state: ResumeState,
        expected_upload_id: str | None,
    ) -> None:
        super().save(
            state,
            expected_upload_id,
        )
        if state.parts:
            self.part_checkpointed.set()


class StaticJournalFactory(MultipartJournalFactory):
    def __init__(self, journal: MultipartJournal) -> None:
        self.journal = journal
        self.calls: list[tuple[ArchiveObjectSource, str]] = []

    def __call__(
        self,
        source: ArchiveObjectSource,
        key: str,
    ) -> MultipartJournal:
        self.calls.append((source, key))
        return self.journal


class FakeOssTransport:
    def __init__(self) -> None:
        self.objects: dict[tuple[str, str | None], bytes] = {}
        self.latest_versions: dict[str, str | None] = {}
        self.uploads: dict[str, _Upload] = {}
        self.next_upload = 1
        self.next_version = 1
        self.trace: list[tuple[object, ...]] = []
        self.failures: dict[tuple[str, int | None], list[BaseException]] = {}
        self.ignore_no_replace = False
        self.readback_count = 0
        self.abort_failure: BaseException | None = None
        self.complete_after_commit_failure: BaseException | None = None
        self.complete_crc_override: int | None = None
        self.max_upload_chunk_bytes = 0
        self.streaming_uploads = 0

    def _consume(self, data: Iterable[bytes], *, size_bytes: int) -> bytes:
        assert not isinstance(data, bytes)
        chunks: list[bytes] = []
        for chunk in data:
            assert type(chunk) is bytes
            self.max_upload_chunk_bytes = max(
                self.max_upload_chunk_bytes,
                len(chunk),
            )
            chunks.append(chunk)
        payload = b"".join(chunks)
        assert len(payload) == size_bytes
        self.streaming_uploads += 1
        return payload

    def fail_once(
        self,
        operation: str,
        error: BaseException,
        *,
        part_number: int | None = None,
    ) -> None:
        self.failures.setdefault((operation, part_number), []).append(error)

    def _raise_failure(self, operation: str, part_number: int | None = None) -> None:
        failures = self.failures.get((operation, part_number))
        if failures:
            raise failures.pop(0)

    def _version(self) -> str:
        version = f"version-{self.next_version}"
        self.next_version += 1
        return version

    def _latest(self, key: str) -> tuple[str | None, bytes]:
        if key not in self.latest_versions:
            raise OssProviderError.service(
                operation="head_object",
                status=404,
                code="NoSuchKey",
            )
        version = self.latest_versions[key]
        return version, self.objects[(key, version)]

    def _existing_conflict(self, key: str, headers: dict[str, str]) -> None:
        if (
            not self.ignore_no_replace
            and headers.get("x-oss-forbid-overwrite") == "true"
            and key in self.latest_versions
        ):
            raise OssProviderError.service(
                operation="put_object",
                status=409,
                code="FileAlreadyExists",
            )

    def init_multipart(self, key: str, *, headers: dict[str, str]) -> str:
        self._raise_failure("init_multipart")
        self._existing_conflict(key, headers)
        upload_id = f"upload-{self.next_upload}"
        self.next_upload += 1
        self.uploads[upload_id] = _Upload(key=key, parts={})
        self.trace.append(("init", key, dict(headers), upload_id))
        return upload_id

    def list_parts(
        self,
        key: str,
        upload_id: str,
        *,
        marker: str,
    ) -> OssPartPage:
        self._raise_failure("list_parts")
        upload = self.uploads.get(upload_id)
        if upload is None:
            raise OssProviderError.service(
                operation="list_parts",
                status=404,
                code="NoSuchUpload",
            )
        assert upload.key == key
        parts = tuple(
            OssRemotePart(
                part_number=number,
                etag=hashlib.md5(data, usedforsecurity=False).hexdigest(),
                size_bytes=len(data),
                crc64=None,
            )
            for number, data in sorted(upload.parts.items())
            if number > int(marker or 0)
        )
        self.trace.append(("list_parts", key, upload_id, marker))
        return OssPartPage(parts=parts, is_truncated=False, next_marker="")

    def upload_part(
        self,
        key: str,
        upload_id: str,
        part_number: int,
        data: Iterable[bytes],
        *,
        size_bytes: int,
    ) -> OssRemotePart:
        self._raise_failure("upload_part", part_number)
        payload = self._consume(data, size_bytes=size_bytes)
        upload = self.uploads[upload_id]
        assert upload.key == key
        upload.parts[part_number] = payload
        result = OssRemotePart(
            part_number=part_number,
            etag=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
            size_bytes=len(payload),
            crc64=crc64_ecma(payload),
        )
        self.trace.append(("part", key, upload_id, part_number, len(payload)))
        return result

    def complete_multipart(
        self,
        key: str,
        upload_id: str,
        parts: tuple[OssRemotePart, ...],
        *,
        headers: dict[str, str],
    ) -> OssUploadResult:
        self._raise_failure("complete_multipart")
        self._existing_conflict(key, headers)
        upload = self.uploads[upload_id]
        assert tuple(part.part_number for part in parts) == tuple(sorted(upload.parts))
        data = b"".join(upload.parts[number] for number in sorted(upload.parts))
        version = self._version()
        self.objects[(key, version)] = data
        self.latest_versions[key] = version
        del self.uploads[upload_id]
        self.trace.append(("complete", key, upload_id, dict(headers), version))
        result = OssUploadResult(
            etag="multipart-etag",
            crc64=(
                crc64_ecma(data)
                if self.complete_crc_override is None
                else self.complete_crc_override
            ),
            provider_version_id=version,
        )
        if self.complete_after_commit_failure is not None:
            error = self.complete_after_commit_failure
            self.complete_after_commit_failure = None
            raise error
        return result

    def abort_multipart(self, key: str, upload_id: str) -> None:
        if self.abort_failure is not None:
            raise self.abort_failure
        upload = self.uploads.get(upload_id)
        if upload is None:
            raise OssProviderError.service(
                operation="abort_multipart",
                status=404,
                code="NoSuchUpload",
            )
        assert upload.key == key
        del self.uploads[upload_id]
        self.trace.append(("abort", key, upload_id))

    def put_object(
        self,
        key: str,
        data: Iterable[bytes],
        *,
        size_bytes: int,
        headers: dict[str, str],
    ) -> OssUploadResult:
        self._raise_failure("put_object")
        self._existing_conflict(key, headers)
        payload = self._consume(data, size_bytes=size_bytes)
        version = self._version()
        self.objects[(key, version)] = payload
        self.latest_versions[key] = version
        self.trace.append(("put", key, dict(headers), version))
        return OssUploadResult(
            etag=hashlib.md5(payload, usedforsecurity=False).hexdigest(),
            crc64=crc64_ecma(payload),
            provider_version_id=version,
        )

    def head_object(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> OssObjectMetadata:
        self._raise_failure("head_object")
        if provider_version_id is None:
            version, data = self._latest(key)
        else:
            version = provider_version_id
            try:
                data = self.objects[(key, version)]
            except KeyError as error:
                raise OssProviderError.service(
                    operation="head_object",
                    status=404,
                    code="NoSuchVersion",
                ) from error
        self.trace.append(("head", key, provider_version_id))
        return OssObjectMetadata(
            size_bytes=len(data),
            crc64=crc64_ecma(data),
            provider_version_id=version,
        )

    def open_reader(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> BytesIO:
        self._raise_failure("open_reader")
        self.readback_count += 1
        if provider_version_id is None:
            _version, data = self._latest(key)
        else:
            data = self.objects[(key, provider_version_id)]
        self.trace.append(("read", key, provider_version_id))
        return BytesIO(data)


class GatedSecondPartTransport(FakeOssTransport):
    def __init__(self) -> None:
        super().__init__()
        self.first_part_finished = threading.Event()
        self.release_second_part = threading.Event()

    def upload_part(
        self,
        key: str,
        upload_id: str,
        part_number: int,
        data: Iterable[bytes],
        *,
        size_bytes: int,
    ) -> OssRemotePart:
        if part_number == 2 and not self.release_second_part.wait(timeout=5):
            raise RuntimeError("test did not release second part")
        result = super().upload_part(
            key,
            upload_id,
            part_number,
            data,
            size_bytes=size_bytes,
        )
        if part_number == 1:
            self.first_part_finished.set()
        return result


class MissingDuringAbortTransport(FakeOssTransport):
    def abort_multipart(self, key: str, upload_id: str) -> None:
        upload = self.uploads.pop(upload_id)
        assert upload.key == key
        raise OssProviderError.service(
            operation="abort_multipart",
            status=404,
            code="NoSuchUpload",
        )


class MissingDuringPartTransport(FakeOssTransport):
    def __init__(self) -> None:
        super().__init__()
        self.missing_once = True

    def upload_part(
        self,
        key: str,
        upload_id: str,
        part_number: int,
        data: Iterable[bytes],
        *,
        size_bytes: int,
    ) -> OssRemotePart:
        if self.missing_once:
            self.missing_once = False
            self.uploads.pop(upload_id)
            raise OssProviderError.service(
                operation="upload_part",
                status=404,
                code="NoSuchUpload",
            )
        return super().upload_part(
            key,
            upload_id,
            part_number,
            data,
            size_bytes=size_bytes,
        )


class MissingDuringCompleteTransport(FakeOssTransport):
    def __init__(self) -> None:
        super().__init__()
        self.missing_once = True

    def complete_multipart(
        self,
        key: str,
        upload_id: str,
        parts: tuple[OssRemotePart, ...],
        *,
        headers: dict[str, str],
    ) -> OssUploadResult:
        if self.missing_once:
            self.missing_once = False
            self.uploads.pop(upload_id)
            raise OssProviderError.service(
                operation="complete_multipart",
                status=404,
                code="NoSuchUpload",
            )
        return super().complete_multipart(
            key,
            upload_id,
            parts,
            headers=headers,
        )


def target(
    *,
    transport: FakeOssTransport,
    journal: MemoryJournal | None = None,
    required: bool = False,
    concurrency: int = 1,
    multipart_size: str = "100KiB",
):
    return build_aliyun_oss_target(
        oss_config(
            required=required,
            concurrency=concurrency,
            multipart_size=multipart_size,
        ),
        secrets=secret_snapshot(),
        transport=transport,
        journal_factory=(None if journal is None else StaticJournalFactory(journal)),
        time_ns=lambda: 1_000_000_000,
    )


def test_crc64_matches_crc64_xz_check_value() -> None:
    assert crc64_ecma(b"123456789") == 0x995DC9BBDF1939FA


def test_listed_remote_part_can_omit_crc64_like_oss2_2_19() -> None:
    listed = OssRemotePart(
        part_number=1,
        etag="opaque-etag",
        size_bytes=PART_SIZE,
        crc64=None,
    )

    assert listed.crc64 is None


def test_small_put_uses_storage_class_and_conditional_create(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    source = source_file(tmp_path, b"small-object")

    result = archive_target.put(source, "research/_archive/v1/data.bin")

    assert result.created is True
    assert result.resumed is False
    assert result.provider_version_id == "version-1"
    [operation] = transport.trace
    assert operation[:2] == ("put", "research/_archive/v1/data.bin")
    assert operation[2] == {
        "x-oss-forbid-overwrite": "true",
        "x-oss-storage-class": "Standard",
    }


def test_large_legal_part_size_streams_in_bounded_chunks(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(
        transport=transport,
        multipart_size="1GiB",
    )
    data = b"streamed" * (384 * 1024) + b"tail"
    source = source_file(tmp_path, data)

    result = archive_target.put(source, "research/_archive/v1/streamed.bin")

    assert transport.objects[(result.key, result.provider_version_id)] == data
    assert transport.streaming_uploads == 1
    assert 0 < transport.max_upload_chunk_bytes <= 1024 * 1024


def test_short_source_reads_keep_exact_multipart_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    data = b"a" * PART_SIZE + b"b" * PART_SIZE + b"tail"
    source = source_file(tmp_path, data)
    real_read = aliyun_oss_module.os.read

    def short_read(fd: int, size: int) -> bytes:
        return real_read(fd, min(size, 7 * 1024))

    monkeypatch.setattr(aliyun_oss_module.os, "read", short_read)

    result = archive_target.put(source, "research/_archive/v1/short-read.bin")

    assert transport.objects[(result.key, result.provider_version_id)] == data
    assert [entry[4] for entry in transport.trace if entry[0] == "part"] == [
        PART_SIZE,
        PART_SIZE,
        4,
    ]


def test_excessive_concurrency_fails_before_transport() -> None:
    transport = FakeOssTransport()

    with pytest.raises(TargetUnavailable, match="safe limit"):
        target(transport=transport, concurrency=33)

    assert transport.trace == []


def test_existing_exact_small_object_is_idempotent(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    source = source_file(tmp_path, b"same-content")
    first = archive_target.put(source, "research/_archive/v1/data.bin")

    second = archive_target.put(source, "research/_archive/v1/data.bin")

    assert first.created is True
    assert second.created is False
    assert second.sha256 == source.sha256
    assert transport.readback_count == 1


def test_existing_different_object_is_a_hard_conflict(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    original = source_file(tmp_path, b"first")
    archive_target.put(original, "research/_archive/v1/data.bin")
    replacement = source_file(tmp_path, b"other")

    with pytest.raises(ExistingObjectMismatch):
        archive_target.put(replacement, "research/_archive/v1/data.bin")


def test_existing_size_mismatch_fails_before_readback(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    original = source_file(tmp_path, b"small")
    key = "research/_archive/v1/size-conflict.bin"
    archive_target.put(original, key)
    replacement = source_file(tmp_path, b"different-size")

    with pytest.raises(ExistingObjectMismatch, match="size"):
        archive_target.put(replacement, key)

    assert transport.readback_count == 0


def test_multipart_checkpoint_resumes_same_upload_and_parts(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    data = b"a" * PART_SIZE + b"b" * PART_SIZE + b"c" * 17
    source = source_file(tmp_path, data)
    key = "research/_archive/v1/large.bin"
    transport.fail_once(
        "upload_part",
        OssProviderError.service(
            operation="upload_part",
            status=503,
            code="ServiceUnavailable",
            retry_after="7",
        ),
        part_number=3,
    )

    with pytest.raises(OssTargetUnavailable) as caught:
        archive_target.put(source, key)

    assert caught.value.retry_after_ns == 7_000_000_000
    resume = journal.load()
    assert resume is not None
    assert resume.upload_id == "upload-1"
    assert tuple(part.part_number for part in resume.parts) == (1, 2)
    resumed = archive_target.put(source, key, resume=resume)
    assert resumed.resumed is True
    assert resumed.created is True
    assert journal.load() is None
    assert transport.objects[(key, resumed.provider_version_id)] == data
    assert [entry[3] for entry in transport.trace if entry[0] == "part"] == [1, 2, 3]


def test_multipart_persists_upload_id_then_each_completed_part(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal, concurrency=2)
    source = source_file(tmp_path, b"x" * (PART_SIZE * 2 + 1))

    archive_target.put(source, "research/_archive/v1/checkpointed.bin")

    assert journal.events[0] == ("save", "upload-1", ())
    saved_part_sets = [event[2] for event in journal.events if event[0] == "save"]
    assert saved_part_sets[-1] == (1, 2, 3)
    assert journal.events[-1] == ("clear", "upload-1", ())


def test_concurrent_part_is_checkpointed_before_slower_peer_finishes(
    tmp_path: Path,
) -> None:
    transport = GatedSecondPartTransport()
    journal = SignalingJournal()
    archive_target = target(
        transport=transport,
        journal=journal,
        concurrency=2,
    )
    source = source_file(tmp_path, b"x" * (PART_SIZE * 2 + 1))
    errors: list[Exception] = []

    def upload() -> None:
        try:
            archive_target.put(
                source,
                "research/_archive/v1/immediate-checkpoint.bin",
            )
        except Exception as error:  # noqa: BLE001 - asserted in caller thread.
            errors.append(error)

    worker = threading.Thread(target=upload)
    worker.start()
    try:
        assert transport.first_part_finished.wait(timeout=2)
        checkpointed_before_release = journal.part_checkpointed.wait(timeout=2)
    finally:
        transport.release_second_part.set()
        worker.join(timeout=5)

    assert checkpointed_before_release is True
    assert worker.is_alive() is False
    assert errors == []


def test_part_checkpoint_failure_reuploads_untrusted_remote_part(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = FailOnePartCheckpointJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"a" * PART_SIZE + b"tail")
    key = "research/_archive/v1/checkpoint-recovery.bin"

    with pytest.raises(TargetUnavailable, match="checkpoint save"):
        archive_target.put(source, key)

    durable = journal.load()
    assert durable is not None
    assert durable.parts == ()
    assert tuple(transport.uploads[durable.upload_id].parts) == (1,)

    recovered = archive_target.put(source, key)

    assert recovered.resumed is True
    assert journal.load() is None
    assert [entry[3] for entry in transport.trace if entry[0] == "part"] == [1, 1, 2]


def test_multipart_requires_durable_journal_before_network(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))

    with pytest.raises(TargetUnavailable, match="checkpoint"):
        archive_target.put(source, "research/_archive/v1/large.bin")

    assert transport.trace == []


def test_initial_checkpoint_failure_treats_missing_abort_as_reset(
    tmp_path: Path,
) -> None:
    transport = MissingDuringAbortTransport()
    journal = FailInitialCheckpointJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))

    with pytest.raises(TargetUnavailable, match="checkpoint save"):
        archive_target.put(source, "research/_archive/v1/checkpoint-init.bin")

    assert transport.uploads == {}


def test_lost_complete_response_converges_to_exact_existing_object(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * PART_SIZE + b"finished")
    key = "research/_archive/v1/lost-complete-response.bin"
    transport.complete_after_commit_failure = OssProviderError.transport(
        operation="complete_multipart"
    )

    with pytest.raises(OssTargetUnavailable, match="complete_multipart"):
        archive_target.put(source, key)

    durable = journal.load()
    assert durable is not None
    assert durable.upload_id not in transport.uploads

    recovered = archive_target.put(source, key, resume=durable)

    assert recovered.created is False
    assert recovered.resumed is True
    assert recovered.sha256 == source.sha256
    assert journal.load() is None
    assert len([entry for entry in transport.trace if entry[0] == "complete"]) == 1


def test_multipart_full_object_crc_mismatch_clears_checkpoint(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * PART_SIZE + b"crc-mismatch")
    key = "research/_archive/v1/full-crc-mismatch.bin"
    transport.complete_crc_override = 0
    assert crc64_ecma(source.path.read_bytes()) != 0

    with pytest.raises(StoredObjectMismatch, match="full-object CRC64"):
        archive_target.put(source, key)

    assert journal.load() is None
    assert transport.uploads == {}
    assert key in transport.latest_versions


def test_resume_mismatch_aborts_clears_and_fails_closed(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    data = b"a" * PART_SIZE + b"b"
    source = source_file(tmp_path, data)
    key = "research/_archive/v1/mismatch.bin"
    upload_id = transport.init_multipart(
        key,
        headers={"x-oss-forbid-overwrite": "true"},
    )
    wrong_payload = b"z" * PART_SIZE
    wrong = transport.upload_part(
        key,
        upload_id,
        1,
        (wrong_payload,),
        size_bytes=len(wrong_payload),
    )
    resume = ResumeState(
        upload_id=upload_id,
        parts=(
            MultipartPartV1(
                part_number=1,
                etag=wrong.etag,
                size_bytes=wrong.size_bytes,
                checksum=str(wrong.crc64),
            ),
        ),
    )
    journal.save(resume, None)

    with pytest.raises(StoredObjectMismatch, match="resume"):
        archive_target.put(source, key, resume=resume)

    assert journal.load() is None
    assert upload_id not in transport.uploads
    assert ("abort", key, upload_id) in transport.trace


def test_abort_failure_keeps_checkpoint_and_masks_no_conflict(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"a" * (PART_SIZE + 1))
    key = "research/_archive/v1/abort-failure.bin"
    upload_id = transport.init_multipart(
        key,
        headers={"x-oss-forbid-overwrite": "true"},
    )
    remote_payload = b"z" * PART_SIZE
    remote = transport.upload_part(
        key,
        upload_id,
        1,
        (remote_payload,),
        size_bytes=len(remote_payload),
    )
    resume = ResumeState(
        upload_id=upload_id,
        parts=(
            MultipartPartV1(
                part_number=1,
                etag=remote.etag,
                size_bytes=remote.size_bytes,
                checksum=str(remote.crc64),
            ),
        ),
    )
    journal.save(resume, None)
    transport.abort_failure = OssProviderError.transport(operation="abort_multipart")

    with pytest.raises(OssTargetUnavailable, match="abort_multipart"):
        archive_target.put(source, key, resume=resume)

    assert journal.load() == resume
    assert upload_id in transport.uploads


def test_missing_remote_upload_resets_checkpoint_and_is_retryable(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))
    key = "research/_archive/v1/stale.bin"
    resume = ResumeState(upload_id="missing-upload", parts=())
    journal.save(resume, None)

    with pytest.raises(OssTargetUnavailable, match="NoSuchUpload"):
        archive_target.put(source, key, resume=resume)

    assert journal.load() is None


def test_missing_upload_during_part_clears_checkpoint_for_fresh_retry(
    tmp_path: Path,
) -> None:
    transport = MissingDuringPartTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))
    key = "research/_archive/v1/missing-during-part.bin"

    with pytest.raises(OssTargetUnavailable, match="NoSuchUpload"):
        archive_target.put(source, key)

    assert journal.load() is None
    recovered = archive_target.put(source, key)
    assert recovered.created is True
    assert recovered.resumed is False


def test_missing_upload_during_complete_checks_existing_then_retries_fresh(
    tmp_path: Path,
) -> None:
    transport = MissingDuringCompleteTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))
    key = "research/_archive/v1/missing-during-complete.bin"

    with pytest.raises(OssTargetUnavailable, match="NoSuchUpload"):
        archive_target.put(source, key)

    assert journal.load() is None
    recovered = archive_target.put(source, key)
    assert recovered.created is True
    assert recovered.resumed is False


def test_complete_no_such_upload_after_commit_converges_to_existing(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))
    key = "research/_archive/v1/complete-no-such-after-commit.bin"
    transport.complete_after_commit_failure = OssProviderError.service(
        operation="complete_multipart",
        status=404,
        code="NoSuchUpload",
    )

    result = archive_target.put(source, key)

    assert result.created is False
    assert result.sha256 == source.sha256
    assert journal.load() is None


def test_concurrent_retryable_parts_keep_longest_retry_after(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(
        transport=transport,
        journal=journal,
        concurrency=2,
    )
    source = source_file(tmp_path, b"x" * (PART_SIZE * 2 + 1))
    transport.fail_once(
        "upload_part",
        OssProviderError.service(
            operation="upload_part",
            status=503,
            code="ServiceUnavailable",
            retry_after="1",
        ),
        part_number=1,
    )
    transport.fail_once(
        "upload_part",
        OssProviderError.service(
            operation="upload_part",
            status=429,
            code="TooManyRequests",
            retry_after="60",
        ),
        part_number=2,
    )

    with pytest.raises(OssTargetUnavailable) as caught:
        archive_target.put(source, "research/_archive/v1/retry-after-batch.bin")

    assert caught.value.retry_after_ns == 60_000_000_000
    assert journal.load() is not None


def test_concurrent_generic_target_unavailable_is_preserved(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(
        transport=transport,
        journal=journal,
        concurrency=2,
    )
    source = source_file(tmp_path, b"x" * (PART_SIZE * 2 + 1))
    transport.fail_once(
        "upload_part",
        TargetUnavailable("generic retryable upload failure"),
        part_number=1,
    )

    with pytest.raises(TargetUnavailable, match="generic retryable"):
        archive_target.put(source, "research/_archive/v1/generic-retry.bin")

    assert journal.load() is not None


class StuckPaginationTransport(FakeOssTransport):
    def list_parts(
        self,
        key: str,
        upload_id: str,
        *,
        marker: str,
    ) -> OssPartPage:
        self.trace.append(("list_parts", key, upload_id, marker))
        return OssPartPage(parts=(), is_truncated=True, next_marker="stuck")


class AdvancingEmptyPaginationTransport(FakeOssTransport):
    def __init__(self) -> None:
        super().__init__()
        self.page_count = 0

    def list_parts(
        self,
        key: str,
        upload_id: str,
        *,
        marker: str,
    ) -> OssPartPage:
        del key, upload_id, marker
        self.page_count += 1
        return OssPartPage(
            parts=(),
            is_truncated=True,
            next_marker=str(self.page_count),
        )


class InconsistentListPartsTransport(FakeOssTransport):
    def list_parts(
        self,
        key: str,
        upload_id: str,
        *,
        marker: str,
    ) -> OssPartPage:
        del key, upload_id, marker
        raise OssProviderError.inconsistent(operation="list_parts")


def test_malformed_part_pagination_aborts_and_clears_checkpoint(
    tmp_path: Path,
) -> None:
    transport = StuckPaginationTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))
    key = "research/_archive/v1/stuck-pagination.bin"

    with pytest.raises(TargetVerificationError, match="pagination"):
        archive_target.put(source, key)

    assert journal.load() is None
    assert transport.uploads == {}


def test_advancing_empty_part_pages_have_a_hard_attempt_bound(
    tmp_path: Path,
) -> None:
    transport = AdvancingEmptyPaginationTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))

    with pytest.raises(TargetVerificationError, match="pagination"):
        archive_target.put(source, "research/_archive/v1/endless-pages.bin")

    assert transport.page_count <= 100
    assert journal.load() is None
    assert transport.uploads == {}


def test_inconsistent_list_parts_aborts_and_clears_checkpoint(
    tmp_path: Path,
) -> None:
    transport = InconsistentListPartsTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    source = source_file(tmp_path, b"x" * (PART_SIZE + 1))
    key = "research/_archive/v1/inconsistent-list.bin"

    with pytest.raises(StoredObjectMismatch, match="inconsistent"):
        archive_target.put(source, key)

    assert journal.load() is None
    assert transport.uploads == {}
    assert any(entry[0] == "abort" for entry in transport.trace)


def test_multipart_part_limit_fails_before_network(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    journal = MemoryJournal()
    archive_target = target(transport=transport, journal=journal)
    actual = source_file(tmp_path, b"small")
    claimed = ArchiveObjectSource(
        path=actual.path,
        size_bytes=PART_SIZE * 10_000 + 1,
        sha256=actual.sha256,
    )

    with pytest.raises(TargetUnavailable, match="10,000"):
        archive_target.put(claimed, "research/_archive/v1/too-many-parts.bin")

    assert transport.trace == []
    assert journal.state is None


def test_optional_verification_uses_crc64_without_cleanup_strength(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport, required=False)
    source = source_file(tmp_path, b"optional-backup")
    put = archive_target.put(source, "research/_archive/v1/optional.bin")

    verification = archive_target.verify(
        put.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=put.provider_version_id,
    )

    assert verification.verified is True
    assert verification.method == "provider_crc64"
    assert verification.level is ArchiveVerificationLevel.PROVIDER_CRC64
    assert verification.cleanup_strong is False
    assert verification.provider_checksum is not None
    assert verification.provider_checksum.algorithm == "crc64"
    assert verification.provider_checksum.value == str(crc64_ecma(b"optional-backup"))
    assert transport.readback_count == 0

    archive_target.verify(
        put.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=put.provider_version_id,
    )

    assert transport.readback_count == 1


def test_optional_crc_cache_is_bound_to_expected_sha256(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport, required=False)
    source = source_file(tmp_path, b"crc-cache-identity")
    put = archive_target.put(source, "research/_archive/v1/cache-identity.bin")
    wrong_sha256 = "0" * 64
    assert wrong_sha256 != source.sha256

    with pytest.raises(StoredObjectMismatch, match="SHA-256"):
        archive_target.verify(
            put.key,
            source.size_bytes,
            wrong_sha256,
            provider_version_id=put.provider_version_id,
        )

    assert transport.readback_count == 1


def test_optional_crc_evidence_cache_is_bounded(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport, required=False)
    source = source_file(tmp_path, b"bounded-cache")
    results = [
        archive_target.put(
            source,
            f"research/_archive/v1/cache/{index}.bin",
        )
        for index in range(1025)
    ]

    first, last = results[0], results[-1]
    archive_target.verify(
        first.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=first.provider_version_id,
    )
    reads_after_evicted = transport.readback_count
    archive_target.verify(
        last.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=last.provider_version_id,
    )

    assert reads_after_evicted == 1
    assert transport.readback_count == reads_after_evicted


def test_optional_restart_without_crc_evidence_reads_back_but_stays_weak(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    first = target(transport=transport, required=False)
    source = source_file(tmp_path, b"optional-restart")
    put = first.put(source, "research/_archive/v1/optional.bin")
    restarted = target(transport=transport, required=False)

    verification = restarted.verify(
        put.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=put.provider_version_id,
    )

    assert verification.method == "provider_crc64"
    assert verification.cleanup_strong is False
    assert transport.readback_count == 1


def test_required_verification_always_reads_back_sha256(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport, required=True)
    source = source_file(tmp_path, b"required-backup")
    put = archive_target.put(source, "research/_archive/v1/required.bin")

    verification = archive_target.verify(
        put.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=put.provider_version_id,
    )

    assert verification.method == "crc64_plus_readback_sha256"
    assert verification.level is ArchiveVerificationLevel.STORED_SHA256
    assert verification.cleanup_strong is True
    assert verification.sha256 == source.sha256
    assert transport.readback_count == 1


def test_receipt_last_commit_uses_strong_oss_evidence_in_order(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport, required=True)
    assert isinstance(archive_target, ArchiveTarget)
    data = source_file(tmp_path, b"data")
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_bytes(b'{"source":"manifest"}\n')
    manifest = ArchiveObjectSource.from_path(manifest_path)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(b'{"commit":"receipt-last"}\n')
    receipt = ArchiveObjectSource.from_path(receipt_path)
    keys = (
        "research/_archive/v1/data.bin",
        "research/_archive/v1/source.manifest.json",
        "research/_archive/v1/archive-receipt.json",
    )

    committed = publish_receipt_last(
        archive_target,
        data=data,
        data_key=keys[0],
        source_manifest=manifest,
        source_manifest_key=keys[1],
        receipt=receipt,
        receipt_key=keys[2],
    )

    assert [entry[1] for entry in transport.trace if entry[0] == "put"] == list(keys)
    for published in (
        committed.data,
        committed.source_manifest,
        committed.receipt,
    ):
        assert published.verification.method == "crc64_plus_readback_sha256"
        assert published.verification.cleanup_strong is True
        assert published.verification.provider_checksum is not None
        assert published.verification.provider_checksum.algorithm == "crc64"


def test_verify_fails_on_size_crc_or_readback_mismatch(
    tmp_path: Path,
) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport, required=True)
    source = source_file(tmp_path, b"verified")
    put = archive_target.put(source, "research/_archive/v1/verified.bin")
    version = put.provider_version_id
    assert version is not None

    transport.objects[(put.key, version)] = b"bad"
    with pytest.raises(StoredObjectMismatch):
        archive_target.verify(
            put.key,
            source.size_bytes,
            source.sha256,
            provider_version_id=version,
        )


def test_verify_and_reader_bind_exact_provider_version(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport, required=True)
    source = source_file(tmp_path, b"version-one")
    put = archive_target.put(source, "research/_archive/v1/versioned.bin")
    assert put.provider_version_id is not None
    newer_version = transport._version()
    transport.objects[(put.key, newer_version)] = b"different-latest"
    transport.latest_versions[put.key] = newer_version

    verification = archive_target.verify(
        put.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=put.provider_version_id,
    )
    with archive_target.open_reader(
        put.key,
        provider_version_id=put.provider_version_id,
    ) as reader:
        restored = reader.read()

    assert verification.provider_version_id == put.provider_version_id
    assert restored == b"version-one"
    assert ("head", put.key, put.provider_version_id) in transport.trace
    assert ("read", put.key, put.provider_version_id) in transport.trace


class WrongVersionHeadTransport(FakeOssTransport):
    def head_object(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> OssObjectMetadata:
        metadata = super().head_object(
            key,
            provider_version_id=provider_version_id,
        )
        return OssObjectMetadata(
            size_bytes=metadata.size_bytes,
            crc64=metadata.crc64,
            provider_version_id="wrong-version",
        )


def test_verify_rejects_provider_version_substitution(tmp_path: Path) -> None:
    transport = WrongVersionHeadTransport()
    archive_target = target(transport=transport, required=True)
    source = source_file(tmp_path, b"version-bound")
    put = archive_target.put(source, "research/_archive/v1/version-bound.bin")
    assert put.provider_version_id is not None

    with pytest.raises(StoredObjectMismatch, match="version"):
        archive_target.verify(
            put.key,
            source.size_bytes,
            source.sha256,
            provider_version_id=put.provider_version_id,
        )


def test_probe_requires_observed_no_replace_semantics() -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)

    probe = archive_target.probe()

    assert probe.target_type == "aliyun_oss"
    assert probe.target_id == "oss-primary"
    assert probe.no_replace_capability == "x-oss-forbid-overwrite"

    broken_transport = FakeOssTransport()
    broken_transport.ignore_no_replace = True
    broken = target(transport=broken_transport)
    with pytest.raises(TargetUnavailable, match="no-replace"):
        broken.probe()


def test_probe_size_mismatch_fails_before_readback() -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    key = "research/_archive/v1/_probes/target=oss-primary/no-replace-v1"
    payload = b"wrong-size"
    transport.put_object(
        key,
        iter((payload,)),
        size_bytes=len(payload),
        headers={"x-oss-forbid-overwrite": "true"},
    )

    with pytest.raises(TargetVerificationError, match="size"):
        archive_target.probe()

    assert transport.readback_count == 0


def test_probe_payload_uses_real_oss2_iterable_adapter() -> None:
    oss_utils = pytest.importorskip("oss2.utils")

    class Oss2AdapterTransport(FakeOssTransport):
        def put_object(
            self,
            key: str,
            data: Iterable[bytes],
            *,
            size_bytes: int,
            headers: dict[str, str],
        ) -> OssUploadResult:
            adapted = oss_utils.make_crc_adapter(data)
            return super().put_object(
                key,
                adapted,
                size_bytes=size_bytes,
                headers=headers,
            )

    transport = Oss2AdapterTransport()

    probe = target(transport=transport).probe()

    assert probe.no_replace_capability == "x-oss-forbid-overwrite"


@pytest.mark.parametrize(
    ("error", "retry_after_ns"),
    [
        (
            OssProviderError.transport(operation="head_object"),
            None,
        ),
        (
            OssProviderError.service(
                operation="head_object",
                status=429,
                code="TooManyRequests",
                retry_after="5",
            ),
            5_000_000_000,
        ),
        (
            OssProviderError.service(
                operation="head_object",
                status=503,
                code="ServiceUnavailable",
            ),
            None,
        ),
        (
            OssProviderError.service(
                operation="head_object",
                status=503,
                code="ServiceUnavailable",
                retry_after="Thu, 01 Jan 1970 00:00:06 GMT",
            ),
            5_000_000_000,
        ),
    ],
)
def test_retryable_provider_failures_preserve_retry_after(
    tmp_path: Path,
    error: OssProviderError,
    retry_after_ns: int | None,
) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    source = source_file(tmp_path, b"retry")
    put = archive_target.put(source, "research/_archive/v1/retry.bin")
    transport.fail_once("head_object", error)

    with pytest.raises(OssTargetUnavailable) as caught:
        archive_target.verify(put.key, source.size_bytes, source.sha256)

    assert caught.value.retry_after_ns == retry_after_ns


def test_business_error_is_terminal_and_redacted(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    source = source_file(tmp_path, b"business-error")
    transport.fail_once(
        "put_object",
        OssProviderError.service(
            operation="put_object",
            status=403,
            code="AccessDenied",
            unsafe_message="secret-plaintext Authorization=access-plaintext",
        ),
    )

    with pytest.raises(OssBusinessError) as caught:
        archive_target.put(source, "research/_archive/v1/error.bin")

    rendered = repr(caught.value) + str(caught.value)
    assert "secret-plaintext" not in rendered
    assert "access-plaintext" not in rendered
    assert caught.value.status == 403
    assert caught.value.error_code == "AccessDenied"


@pytest.mark.parametrize(
    "key",
    [
        "",
        "/absolute",
        "../escape",
        "research//empty",
        "research/./dot",
        "research/../escape",
        "research\\windows",
        "research/nul\x00key",
    ],
)
def test_unsafe_keys_fail_before_transport(tmp_path: Path, key: str) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    source = source_file(tmp_path, b"key")

    with pytest.raises(UnsafeObjectKey):
        archive_target.put(source, key)

    assert transport.trace == []


def test_archive_target_never_allows_overwrite_mode(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    source = source_file(tmp_path, b"immutable")

    with pytest.raises(UnsafeObjectKey, match="no-replace"):
        archive_target.put(
            source,
            "research/_archive/v1/immutable.bin",
            no_replace=False,
        )


class CountingSecretSnapshot:
    def __init__(self, values: dict[SecretRef, str]) -> None:
        self._values = values
        self.read_count: dict[SecretRef, int] = {}

    def value_for(self, ref: SecretRef) -> SecretValue:
        self.read_count[ref] = self.read_count.get(ref, 0) + 1
        return SecretValue(self._values[ref])

    def __repr__(self) -> str:
        return "CountingSecretSnapshot(***)"


def test_factory_consumes_each_secret_once_and_repr_is_redacted() -> None:
    config = oss_config(security_token=True)
    refs = {
        SecretRef.parse("env:TEST_OSS_ACCESS_KEY"): "access-plaintext",
        SecretRef.parse("env:TEST_OSS_SECRET_KEY"): "secret-plaintext",
        SecretRef.parse("env:TEST_OSS_SECURITY_TOKEN"): "token-plaintext",
    }
    secrets = CountingSecretSnapshot(refs)
    archive_target = build_aliyun_oss_target(
        config,
        secrets=secrets,  # type: ignore[arg-type]
        transport=FakeOssTransport(),
    )

    assert secrets.read_count == {ref: 1 for ref in refs}
    rendered = repr(archive_target)
    for plaintext in refs.values():
        assert plaintext not in rendered
    assert "env:TEST_OSS_ACCESS_KEY" in rendered
    assert "env:TEST_OSS_SECRET_KEY" in rendered


def test_provider_error_object_never_renders_unsafe_message() -> None:
    error = OssProviderError(
        operation="put_object",
        kind=OssProviderErrorKind.SERVICE,
        status=403,
        code="AccessDenied",
        retry_after=None,
        unsafe_message="Authorization: secret-plaintext",
    )

    assert "secret-plaintext" not in str(error)
    assert "secret-plaintext" not in repr(error)


def test_sdk_debug_logs_are_suppressed_before_credentials_are_consumed(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    def logged_auth(access_key_id: str, access_key_secret: str) -> object:
        logging.getLogger("oss2.auth").debug(
            "access_key_id: %s access_key_secret: %s",
            access_key_id,
            access_key_secret,
        )
        return object()

    class LoggedBucket:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            logging.getLogger("oss2.http").debug(
                "headers: {'authorization': 'OSS access-plaintext:secret-plaintext'}"
            )

    fake_oss2 = ModuleType("oss2")
    fake_oss2.Auth = logged_auth  # type: ignore[attr-defined]
    fake_oss2.StsAuth = logged_auth  # type: ignore[attr-defined]
    fake_oss2.Bucket = LoggedBucket  # type: ignore[attr-defined]
    fake_oss2.models = SimpleNamespace(PartInfo=object)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "oss2", fake_oss2)
    caplog.set_level(logging.DEBUG, logger="oss2.auth")
    caplog.set_level(logging.DEBUG, logger="oss2.http")

    build_aliyun_oss_target(
        oss_config(),
        secrets=secret_snapshot(),
    )

    assert "access-plaintext" not in caplog.text
    assert "secret-plaintext" not in caplog.text


def _non_test_exception_graph(error: BaseException) -> str:
    pending = [error]
    seen: set[int] = set()
    rendered: list[str] = []
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        rendered.extend((str(current), repr(current)))
        summary = traceback.TracebackException.from_exception(
            current,
            capture_locals=True,
        )
        rendered.extend(
            repr(frame.locals)
            for frame in summary.stack
            if Path(frame.filename).resolve() != Path(__file__).resolve()
        )
        if current.__cause__ is not None:
            pending.append(current.__cause__)
        if current.__context__ is not None:
            pending.append(current.__context__)
    return "\n".join(rendered)


def test_sdk_constructor_failure_is_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def exploding_sts(
        access_key_id: str,
        access_key_secret: str,
        security_token: str,
    ) -> object:
        raise RuntimeError(
            f"credentials={access_key_id}:{access_key_secret}:{security_token}"
        )

    fake_oss2 = ModuleType("oss2")
    fake_oss2.Auth = lambda *_args: object()  # type: ignore[attr-defined]
    fake_oss2.StsAuth = exploding_sts  # type: ignore[attr-defined]
    fake_oss2.Bucket = object  # type: ignore[attr-defined]
    fake_oss2.models = SimpleNamespace(PartInfo=object)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "oss2", fake_oss2)

    with pytest.raises(TargetUnavailable) as caught:
        build_aliyun_oss_target(
            oss_config(security_token=True),
            secrets=secret_snapshot(security_token=True),
        )

    rendered = _non_test_exception_graph(caught.value)
    for plaintext in (
        "access-plaintext",
        "secret-plaintext",
        "token-plaintext",
    ):
        assert plaintext not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_sdk_bucket_failure_clears_leaky_auth_local(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class LeakyAuth:
        def __repr__(self) -> str:
            return "LeakyAuth(access-plaintext,secret-plaintext,token-plaintext)"

    class LeakyBucket:
        def __init__(self, auth: object, *_args: object, **_kwargs: object) -> None:
            self.auth = auth

        def __repr__(self) -> str:
            return f"LeakyBucket({self.auth!r})"

    fake_oss2 = ModuleType("oss2")
    fake_oss2.Auth = lambda *_args: LeakyAuth()  # type: ignore[attr-defined]
    fake_oss2.StsAuth = lambda *_args: LeakyAuth()  # type: ignore[attr-defined]
    fake_oss2.Bucket = LeakyBucket  # type: ignore[attr-defined]
    fake_oss2.models = SimpleNamespace()  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "oss2", fake_oss2)

    with pytest.raises(TargetUnavailable) as caught:
        build_aliyun_oss_target(
            oss_config(security_token=True),
            secrets=secret_snapshot(security_token=True),
        )

    rendered = _non_test_exception_graph(caught.value)
    for plaintext in (
        "access-plaintext",
        "secret-plaintext",
        "token-plaintext",
    ):
        assert plaintext not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_secret_lookup_failure_detaches_partial_credentials() -> None:
    class ExplodingSecretSnapshot:
        def value_for(self, ref: SecretRef) -> SecretValue:
            if ref.target == "TEST_OSS_SECURITY_TOKEN":
                raise RuntimeError("access-plaintext:secret-plaintext:token-plaintext")
            if ref.target == "TEST_OSS_ACCESS_KEY":
                return SecretValue("access-plaintext")
            return SecretValue("secret-plaintext")

    with pytest.raises(TargetUnavailable) as caught:
        build_aliyun_oss_target(
            oss_config(security_token=True),
            secrets=ExplodingSecretSnapshot(),  # type: ignore[arg-type]
            transport=FakeOssTransport(),
        )

    rendered = _non_test_exception_graph(caught.value)
    for plaintext in (
        "access-plaintext",
        "secret-plaintext",
        "token-plaintext",
    ):
        assert plaintext not in rendered
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_malformed_sdk_integrity_response_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class MalformedBucket:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def put_object(
            self,
            key: str,
            data: Iterable[bytes],
            *,
            headers: dict[str, str],
        ) -> SimpleNamespace:
            del key, headers
            assert b"".join(data) == b"malformed-response"
            return SimpleNamespace(
                etag=None,
                crc=crc64_ecma(b"malformed-response"),
                versionid=None,
            )

    fake_oss2 = ModuleType("oss2")
    fake_oss2.Auth = lambda *_args: object()  # type: ignore[attr-defined]
    fake_oss2.StsAuth = lambda *_args: object()  # type: ignore[attr-defined]
    fake_oss2.Bucket = MalformedBucket  # type: ignore[attr-defined]
    fake_oss2.models = SimpleNamespace(PartInfo=object)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "oss2", fake_oss2)
    archive_target = build_aliyun_oss_target(
        oss_config(),
        secrets=secret_snapshot(),
    )
    source = source_file(tmp_path, b"malformed-response")

    with pytest.raises(StoredObjectMismatch, match="inconsistent"):
        archive_target.put(source, "research/_archive/v1/malformed.bin")


def test_sdk_head_must_echo_requested_version(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload = b"version-echo"

    class VersionOmittingBucket:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def put_object(
            self,
            key: str,
            data: Iterable[bytes],
            *,
            headers: dict[str, str],
        ) -> SimpleNamespace:
            del key
            assert headers["Content-Length"] == str(len(payload))
            assert b"".join(data) == payload
            return SimpleNamespace(
                etag="etag",
                crc=crc64_ecma(payload),
                versionid="version-1",
            )

        def head_object(
            self,
            key: str,
            *,
            params: dict[str, str] | None,
        ) -> SimpleNamespace:
            del key
            assert params == {"versionId": "version-1"}
            return SimpleNamespace(
                content_length=len(payload),
                server_crc=crc64_ecma(payload),
                versionid=None,
            )

    fake_oss2 = ModuleType("oss2")
    fake_oss2.Auth = lambda *_args: object()  # type: ignore[attr-defined]
    fake_oss2.StsAuth = lambda *_args: object()  # type: ignore[attr-defined]
    fake_oss2.Bucket = VersionOmittingBucket  # type: ignore[attr-defined]
    fake_oss2.models = SimpleNamespace(PartInfo=object)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "oss2", fake_oss2)
    archive_target = build_aliyun_oss_target(
        oss_config(),
        secrets=secret_snapshot(),
    )
    source = source_file(tmp_path, payload)
    put = archive_target.put(source, "research/_archive/v1/version-echo.bin")

    with pytest.raises(StoredObjectMismatch, match="inconsistent"):
        archive_target.verify(
            put.key,
            source.size_bytes,
            source.sha256,
            provider_version_id="version-1",
        )


def test_sdk_reader_must_echo_requested_version(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class VersionOmittingReader(BytesIO):
        versionid = None

    class VersionOmittingBucket:
        latest_reader: VersionOmittingReader | None = None

        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def get_object(
            self,
            key: str,
            *,
            params: dict[str, str] | None,
        ) -> VersionOmittingReader:
            del key
            assert params == {"versionId": "version-1"}
            reader = VersionOmittingReader(b"wrong-version")
            type(self).latest_reader = reader
            return reader

    fake_oss2 = ModuleType("oss2")
    fake_oss2.Auth = lambda *_args: object()  # type: ignore[attr-defined]
    fake_oss2.StsAuth = lambda *_args: object()  # type: ignore[attr-defined]
    fake_oss2.Bucket = VersionOmittingBucket  # type: ignore[attr-defined]
    fake_oss2.models = SimpleNamespace(PartInfo=object)  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "oss2", fake_oss2)
    archive_target = build_aliyun_oss_target(
        oss_config(),
        secrets=secret_snapshot(),
    )

    with pytest.raises(StoredObjectMismatch, match="inconsistent"):
        archive_target.open_reader(
            "research/_archive/v1/version-echo.bin",
            provider_version_id="version-1",
        )

    assert VersionOmittingBucket.latest_reader is not None
    assert VersionOmittingBucket.latest_reader.closed is True


def test_closed_target_rejects_all_io(tmp_path: Path) -> None:
    transport = FakeOssTransport()
    archive_target = target(transport=transport)
    source = source_file(tmp_path, b"closed")
    archive_target.close()

    with pytest.raises(TargetClosed):
        archive_target.put(source, "research/_archive/v1/closed.bin")
    with pytest.raises(TargetClosed):
        archive_target.verify(
            "research/_archive/v1/closed.bin",
            source.size_bytes,
            source.sha256,
        )
    with pytest.raises(TargetClosed):
        archive_target.open_reader("research/_archive/v1/closed.bin")

    assert transport.trace == []
