from __future__ import annotations

import base64
import hashlib
import io
import threading
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import format_datetime
from pathlib import Path
from typing import Any, Protocol, cast

import pytest
from botocore.exceptions import (  # type: ignore[import-untyped]
    ClientError,
    IncompleteReadError,
    ProxyConnectionError,
)

from crypto_collector.archive.models import MultipartPartV1
from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    ArchiveTarget,
    MultipartJournal,
    MultipartJournalConflict,
    ResumeState,
    TargetClosed,
    UnsafeObjectKey,
)
from crypto_collector.archive.targets.s3 import (
    S3AbortError,
    S3CheckpointConflict,
    S3CheckpointPersistenceError,
    S3FatalAbortError,
    S3FatalError,
    S3ObjectConflict,
    S3RetryableError,
    S3StoredObjectMismatch,
    S3Target,
    build_s3_target,
    classify_s3_error,
)
from crypto_collector.config.models import S3TargetConfig
from crypto_collector.config.primitives import SecretRef, SecretSnapshot, SecretValue

MIB = 1024 * 1024
PART_SIZE = 5 * MIB


def _client_error(
    code: str,
    status: int,
    operation: str,
    *,
    retry_after: str | None = None,
) -> ClientError:
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return ClientError(
        {
            "Error": {"Code": code, "Message": "provider detail is not public"},
            "ResponseMetadata": {
                "HTTPStatusCode": status,
                "HTTPHeaders": headers,
            },
        },
        operation,
    )


class _Readable(Protocol):
    def read(self, size: int = -1) -> bytes: ...


def _read_body(body: object) -> bytes:
    if isinstance(body, bytes):
        return body
    reader = cast(_Readable, body).read
    chunks: list[bytes] = []
    while True:
        chunk = reader(1024 * 1024)
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)


@dataclass
class _StoredObject:
    data: bytes
    version_id: str
    checksum_type: str | None = "FULL_OBJECT"
    checksum_sha256: str | None = None
    reported_size_delta: int = 0

    def __post_init__(self) -> None:
        if self.checksum_sha256 is None:
            self.checksum_sha256 = base64.b64encode(
                hashlib.sha256(self.data).digest()
            ).decode("ascii")


class FakeS3Client:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.objects: dict[str, _StoredObject] = {}
        self.uploads: dict[str, dict[int, tuple[bytes, str, str]]] = {}
        self.upload_keys: dict[str, str] = {}
        self.version_counter = 0
        self.upload_counter = 0
        self.upload_part_calls = 0
        self.fail_upload_part_after: int | None = None
        self.list_page_size = 1000
        self.list_checksums = True
        self.head_checksum_mode_unsupported = False
        self.race_object: tuple[str, bytes] | None = None
        self.complete_conflict: tuple[str, bytes] | None = None
        self.complete_retry_error: ClientError | None = None
        self.abort_error: ClientError | None = None
        self.etag_for_part: Callable[[int], str] = lambda number: f'"opaque-{number}"'

    def _record(self, operation: str, kwargs: dict[str, object]) -> None:
        self.calls.append((operation, dict(kwargs)))

    def _new_version(self) -> str:
        self.version_counter += 1
        return f"version-{self.version_counter}"

    def head_object(self, **kwargs: object) -> Mapping[str, object]:
        self._record("head_object", kwargs)
        if self.head_checksum_mode_unsupported and "ChecksumMode" in kwargs:
            raise _client_error("NotImplemented", 501, "HeadObject")
        key = str(kwargs["Key"])
        stored = self.objects.get(key)
        if stored is None:
            raise _client_error("NoSuchKey", 404, "HeadObject")
        requested_version = kwargs.get("VersionId")
        if requested_version is not None and requested_version != stored.version_id:
            raise _client_error("NoSuchVersion", 404, "HeadObject")
        result: dict[str, object] = {
            "ContentLength": len(stored.data) + stored.reported_size_delta,
            "ETag": '"definitely-not-md5"',
            "VersionId": stored.version_id,
        }
        if stored.checksum_type is not None:
            result["ChecksumType"] = stored.checksum_type
        if stored.checksum_sha256 is not None:
            result["ChecksumSHA256"] = stored.checksum_sha256
        return result

    def get_object(self, **kwargs: object) -> Mapping[str, object]:
        self._record("get_object", kwargs)
        key = str(kwargs["Key"])
        stored = self.objects.get(key)
        if stored is None:
            raise _client_error("NoSuchKey", 404, "GetObject")
        requested_version = kwargs.get("VersionId")
        if requested_version is not None and requested_version != stored.version_id:
            raise _client_error("NoSuchVersion", 404, "GetObject")
        return {
            "Body": io.BytesIO(stored.data),
            "ContentLength": len(stored.data),
            "VersionId": stored.version_id,
        }

    def put_object(self, **kwargs: object) -> Mapping[str, object]:
        self._record("put_object", kwargs)
        key = str(kwargs["Key"])
        if self.race_object is not None and self.race_object[0] == key:
            _, data = self.race_object
            self.objects[key] = _StoredObject(data, self._new_version())
            self.race_object = None
        if key in self.objects and kwargs.get("IfNoneMatch") == "*":
            raise _client_error("PreconditionFailed", 412, "PutObject")
        data = _read_body(kwargs["Body"])
        expected_checksum = base64.b64encode(hashlib.sha256(data).digest()).decode(
            "ascii"
        )
        assert kwargs["ChecksumSHA256"] == expected_checksum
        version_id = self._new_version()
        self.objects[key] = _StoredObject(data, version_id)
        return {
            "ETag": '"opaque-single-etag"',
            "ChecksumSHA256": expected_checksum,
            "ChecksumType": "FULL_OBJECT",
            "VersionId": version_id,
        }

    def create_multipart_upload(self, **kwargs: object) -> Mapping[str, object]:
        self._record("create_multipart_upload", kwargs)
        self.upload_counter += 1
        upload_id = f"upload-{self.upload_counter}"
        self.uploads[upload_id] = {}
        self.upload_keys[upload_id] = str(kwargs["Key"])
        return {"UploadId": upload_id}

    def upload_part(self, **kwargs: object) -> Mapping[str, object]:
        self._record("upload_part", kwargs)
        self.upload_part_calls += 1
        if (
            self.fail_upload_part_after is not None
            and self.upload_part_calls > self.fail_upload_part_after
        ):
            raise _client_error("SlowDown", 503, "UploadPart", retry_after="7")
        upload_id = str(kwargs["UploadId"])
        if upload_id not in self.uploads:
            raise _client_error("NoSuchUpload", 404, "UploadPart")
        data = _read_body(kwargs["Body"])
        raw_part_number = kwargs["PartNumber"]
        assert type(raw_part_number) is int
        part_number = raw_part_number
        checksum = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
        assert kwargs["ChecksumSHA256"] == checksum
        etag = self.etag_for_part(part_number)
        self.uploads[upload_id][part_number] = (data, etag, checksum)
        return {"ETag": etag, "ChecksumSHA256": checksum}

    def list_parts(self, **kwargs: object) -> Mapping[str, object]:
        self._record("list_parts", kwargs)
        upload_id = str(kwargs["UploadId"])
        if upload_id not in self.uploads:
            raise _client_error("NoSuchUpload", 404, "ListParts")
        raw_marker = kwargs.get("PartNumberMarker", 0)
        assert type(raw_marker) is int
        marker = raw_marker
        numbers = sorted(
            number for number in self.uploads[upload_id] if number > marker
        )
        selected = numbers[: self.list_page_size]
        parts = []
        for number in selected:
            part: dict[str, object] = {
                "PartNumber": number,
                "ETag": self.uploads[upload_id][number][1],
                "Size": len(self.uploads[upload_id][number][0]),
            }
            if self.list_checksums:
                part["ChecksumSHA256"] = self.uploads[upload_id][number][2]
            parts.append(part)
        truncated = len(selected) < len(numbers)
        result: dict[str, object] = {
            "Parts": parts,
            "IsTruncated": truncated,
            "UploadId": upload_id,
            "Key": self.upload_keys[upload_id],
        }
        if truncated:
            result["NextPartNumberMarker"] = selected[-1]
        return result

    def complete_multipart_upload(self, **kwargs: object) -> Mapping[str, object]:
        self._record("complete_multipart_upload", kwargs)
        upload_id = str(kwargs["UploadId"])
        if self.complete_retry_error is not None:
            error = self.complete_retry_error
            self.complete_retry_error = None
            raise error
        key = str(kwargs["Key"])
        if self.complete_conflict is not None:
            conflict_key, conflict_data = self.complete_conflict
            assert conflict_key == key
            self.objects[key] = _StoredObject(conflict_data, self._new_version())
            self.complete_conflict = None
        if key in self.objects and kwargs.get("IfNoneMatch") == "*":
            raise _client_error("PreconditionFailed", 412, "CompleteMultipartUpload")
        if upload_id not in self.uploads:
            raise _client_error("NoSuchUpload", 404, "CompleteMultipartUpload")
        requested = kwargs["MultipartUpload"]
        assert isinstance(requested, dict)
        requested_parts = requested["Parts"]
        assert isinstance(requested_parts, list)
        data = b"".join(
            self.uploads[upload_id][int(part["PartNumber"])][0]
            for part in requested_parts
        )
        version_id = self._new_version()
        self.objects[key] = _StoredObject(
            data,
            version_id,
            checksum_type="COMPOSITE",
        )
        del self.uploads[upload_id]
        del self.upload_keys[upload_id]
        return {
            "ETag": '"opaque-complete-etag-3"',
            "VersionId": version_id,
            "ChecksumType": "COMPOSITE",
        }

    def abort_multipart_upload(self, **kwargs: object) -> Mapping[str, object]:
        self._record("abort_multipart_upload", kwargs)
        if self.abort_error is not None:
            raise self.abort_error
        upload_id = str(kwargs["UploadId"])
        if upload_id not in self.uploads:
            raise _client_error("NoSuchUpload", 404, "AbortMultipartUpload")
        del self.uploads[upload_id]
        del self.upload_keys[upload_id]
        return {}


class MemoryJournal(MultipartJournal):
    def __init__(self, checkpoint: ResumeState | None = None) -> None:
        self.checkpoint = checkpoint
        self.saved: list[ResumeState] = []
        self.save_expected_states: list[ResumeState | None] = []
        self.cleared: list[ResumeState | None] = []
        self.fail_next_save = False
        self.conflict_next_save = False
        self.fail_next_clear = False

    def load(self) -> ResumeState | None:
        return self.checkpoint

    def save(
        self,
        checkpoint: ResumeState,
        expected: ResumeState | None,
    ) -> None:
        if self.fail_next_save:
            self.fail_next_save = False
            raise OSError("durable store unavailable")
        if self.conflict_next_save:
            self.conflict_next_save = False
            self.checkpoint = ResumeState(upload_id="competing-upload", parts=())
            raise MultipartJournalConflict("checkpoint CAS conflict")
        if self.checkpoint != expected:
            raise MultipartJournalConflict("checkpoint CAS conflict")
        self.checkpoint = checkpoint
        self.saved.append(checkpoint)
        self.save_expected_states.append(expected)

    def clear(self, expected: ResumeState | None) -> None:
        if self.fail_next_clear:
            self.fail_next_clear = False
            raise OSError("durable store unavailable")
        if self.checkpoint != expected:
            raise MultipartJournalConflict("checkpoint CAS conflict")
        self.checkpoint = None
        self.cleared.append(expected)


class CountingSnapshot:
    def __init__(self, values: Mapping[SecretRef, str]) -> None:
        self._values = dict(values)
        self.reads: dict[SecretRef, int] = {}

    def value_for(self, reference: SecretRef) -> SecretValue:
        self.reads[reference] = self.reads.get(reference, 0) + 1
        return SecretValue(self._values[reference])

    def __repr__(self) -> str:
        return "CountingSnapshot(***)"


def _config(**overrides: object) -> S3TargetConfig:
    source: dict[str, object] = {
        "id": "s3-primary",
        "type": "s3",
        "required": True,
        "bucket": "market-data",
        "endpoint": "http://127.0.0.1:9000",
        "region": "us-east-1",
        "addressing_style": "path",
        "multipart_size": "5MiB",
        "concurrency": 1,
        "storage_class": "STANDARD_IA",
        "credentials": {
            "access_key_id": "env:S3_ACCESS_KEY_ID",
            "secret_access_key": "env:S3_SECRET_ACCESS_KEY",
            "session_token": "env:S3_SESSION_TOKEN",
        },
    }
    source.update(overrides)
    return S3TargetConfig.model_validate(source)


def _target(
    client: FakeS3Client,
    *,
    config: S3TargetConfig | None = None,
    journal: MemoryJournal | None = None,
):
    config = _config() if config is None else config
    refs = config.credentials
    secrets = SecretSnapshot.from_test_values(
        {
            refs.access_key_id: "access",
            refs.secret_access_key: "secret",
            **({refs.session_token: "token"} if refs.session_token is not None else {}),
        }
    )
    return build_s3_target(
        config,
        secrets=secrets,
        journal_factory=(None if journal is None else lambda source, key: journal),
        client_factory=lambda **_kwargs: client,
        now_unix_ns=lambda: 0,
    )


def _source(
    tmp_path: Path,
    data: bytes,
    *,
    name: str = "source.bin",
) -> ArchiveObjectSource:
    path = tmp_path / name
    path.write_bytes(data)
    return ArchiveObjectSource(
        path=path,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )


def _operations(client: FakeS3Client) -> list[str]:
    return [operation for operation, _kwargs in client.calls]


def test_target_implements_common_runtime_protocol_and_probe_proves_no_replace() -> (
    None
):
    client = FakeS3Client()
    target = _target(client, config=_config(prefix="backup"))

    probe = target.probe()

    assert isinstance(target, ArchiveTarget)
    assert probe.target_id == "s3-primary"
    assert probe.target_type == "s3"
    assert probe.no_replace_capability == "if_none_match_star"
    assert probe.mount_identity is None
    marker = "backup/_crypto_collector/probes/s3-no-replace-v1/s3-primary.bin"
    assert client.objects[marker].data == b"crypto-collector:s3:no-replace:v1\n"
    puts = [kwargs for operation, kwargs in client.calls if operation == "put_object"]
    assert len(puts) == 2
    assert all(put["IfNoneMatch"] == "*" for put in puts)
    [complete] = [
        kwargs
        for operation, kwargs in client.calls
        if operation == "complete_multipart_upload"
    ]
    assert complete["IfNoneMatch"] == "*"
    assert "abort_multipart_upload" in _operations(client)


@pytest.mark.parametrize("ignored_operation", ["put", "complete"])
def test_probe_fails_when_endpoint_ignores_no_replace(
    ignored_operation: str,
) -> None:
    class IgnoringClient(FakeS3Client):
        def put_object(self, **kwargs: object) -> Mapping[str, object]:
            if ignored_operation == "put" and str(kwargs["Key"]) in self.objects:
                kwargs = {**kwargs, "IfNoneMatch": None}
            return super().put_object(**kwargs)

        def complete_multipart_upload(
            self,
            **kwargs: object,
        ) -> Mapping[str, object]:
            if ignored_operation == "complete":
                kwargs = {**kwargs, "IfNoneMatch": None}
            return super().complete_multipart_upload(**kwargs)

    with pytest.raises(S3FatalError, match="ignored"):
        _target(IgnoringClient()).probe()


def test_single_put_is_conditional_checksum_bound_and_versioned(tmp_path: Path) -> None:
    client = FakeS3Client()
    target = _target(client)
    source = _source(tmp_path, b"stored bytes")

    result = target.put(source, key="archive/data.bin")

    [put] = [kwargs for operation, kwargs in client.calls if operation == "put_object"]
    assert put["Bucket"] == "market-data"
    assert put["IfNoneMatch"] == "*"
    assert put["StorageClass"] == "STANDARD_IA"
    assert put["ContentLength"] == source.size_bytes
    assert result.provider_version_id == "version-1"
    assert result.created
    assert not result.resumed

    verification = target.verify(
        result.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=result.provider_version_id,
    )
    assert verification.method == "provider_full_object_sha256"
    assert verification.provider_version_id == "version-1"
    assert verification.provider_checksum is not None
    assert verification.provider_checksum.value == source.sha256
    assert "get_object" not in _operations(client)


def test_single_put_incomplete_success_evidence_is_recovered_on_retry(
    tmp_path: Path,
) -> None:
    class MissingEtagClient(FakeS3Client):
        def __init__(self) -> None:
            super().__init__()
            self._omit_once = True

        def put_object(self, **kwargs: object) -> Mapping[str, object]:
            response = dict(super().put_object(**kwargs))
            if self._omit_once:
                self._omit_once = False
                response.pop("ETag")
            return response

    client = MissingEtagClient()
    source = _source(tmp_path, b"ambiguous-single")
    target = _target(client)

    with pytest.raises(S3RetryableError, match="commit evidence"):
        target.put(source, key="archive/data.bin")

    recovered = target.put(source, key="archive/data.bin")

    assert not recovered.created
    assert recovered.provider_version_id == "version-1"
    assert _operations(client).count("put_object") == 1


def test_open_reader_is_bound_to_exact_provider_version(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"version-bound")
    target = _target(client)
    result = target.put(source, key="archive/data.bin")

    with target.open_reader(
        result.key,
        provider_version_id=result.provider_version_id,
    ) as reader:
        assert reader.read() == b"version-bound"


def test_verify_rejects_provider_that_does_not_echo_requested_version(
    tmp_path: Path,
) -> None:
    class WrongVersionClient(FakeS3Client):
        def head_object(self, **kwargs: object) -> Mapping[str, object]:
            result = dict(super().head_object(**kwargs))
            if "VersionId" in kwargs:
                result["VersionId"] = "different-version"
            return result

    client = WrongVersionClient()
    source = _source(tmp_path, b"version-bound")
    client.objects["archive/data.bin"] = _StoredObject(
        b"version-bound",
        "version-1",
    )

    with pytest.raises(S3StoredObjectMismatch, match="provider version"):
        _target(client).verify(
            "archive/data.bin",
            source.size_bytes,
            source.sha256,
            provider_version_id="version-1",
        )


def test_no_replace_false_and_closed_target_fail_before_network(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"value")
    target = _target(client)

    with pytest.raises(ValueError, match="no_replace"):
        target.put(source, "archive/data.bin", no_replace=False)
    target.close()
    with pytest.raises(TargetClosed):
        target.put(source, "archive/data.bin")

    assert client.calls == []


def test_existing_match_is_idempotent_without_put(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"same")
    client.objects["archive/data.bin"] = _StoredObject(
        b"same",
        "existing-version",
        checksum_type=None,
        checksum_sha256=None,
    )

    result = _target(client).put(source, key="archive/data.bin")

    assert not result.created
    assert result.provider_version_id == "existing-version"
    assert "put_object" not in _operations(client)
    assert "get_object" in _operations(client)


def test_precondition_race_accepts_only_fully_verified_match(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"same")
    client.race_object = ("archive/data.bin", b"same")

    result = _target(client).put(source, key="archive/data.bin")

    assert not result.created
    assert _operations(client).count("put_object") == 1
    assert _operations(client).count("head_object") >= 2


def test_existing_mismatch_is_a_hard_conflict_and_never_overwrites(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    client.objects["archive/data.bin"] = _StoredObject(
        b"different",
        "version-old",
        checksum_type=None,
        checksum_sha256=None,
    )
    source = _source(tmp_path, b"expected")

    with pytest.raises(S3ObjectConflict):
        _target(client).put(source, key="archive/data.bin")

    assert client.objects["archive/data.bin"].data == b"different"
    assert "put_object" not in _operations(client)


@pytest.mark.parametrize(
    ("checksum_type", "checksum", "size_delta"),
    [
        (None, None, 0),
        ("COMPOSITE", "expected", 0),
        ("FULL_OBJECT", "wrong", 0),
        ("FULL_OBJECT", "malformed", 0),
        ("FULL_OBJECT", "expected", 1),
        ("UNKNOWN", "expected", 0),
    ],
)
def test_non_exact_provider_checksum_evidence_falls_back_to_readback(
    tmp_path: Path,
    checksum_type: str | None,
    checksum: str | None,
    size_delta: int,
) -> None:
    data = b"read me"
    source = _source(tmp_path, data)
    expected = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
    observed = {
        None: None,
        "expected": expected,
        "wrong": base64.b64encode(b"x" * 32).decode("ascii"),
        "malformed": "not-base64!",
    }[checksum]
    client = FakeS3Client()
    client.objects["archive/data.bin"] = _StoredObject(
        data,
        "version-1",
        checksum_type=checksum_type,
        checksum_sha256=observed,
        reported_size_delta=size_delta,
    )

    verification = _target(client).verify(
        "archive/data.bin",
        source.size_bytes,
        source.sha256,
        provider_version_id="version-1",
    )

    assert verification.method == "readback_sha256"
    assert verification.provider_checksum is None
    [get] = [kwargs for operation, kwargs in client.calls if operation == "get_object"]
    assert get["VersionId"] == "version-1"


def test_checksum_mode_unsupported_falls_back_to_plain_head_and_readback(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    client.head_checksum_mode_unsupported = True
    source = _source(tmp_path, b"minio-compatible")
    client.objects["archive/data.bin"] = _StoredObject(
        b"minio-compatible",
        "version-1",
        checksum_type=None,
        checksum_sha256=None,
    )

    verification = _target(client).verify(
        "archive/data.bin",
        source.size_bytes,
        source.sha256,
    )

    assert verification.method == "readback_sha256"
    heads = [kwargs for operation, kwargs in client.calls if operation == "head_object"]
    assert heads[0]["ChecksumMode"] == "ENABLED"
    assert "ChecksumMode" not in heads[1]


def test_readback_mismatch_is_never_hidden_by_etag(tmp_path: Path) -> None:
    client = FakeS3Client()
    expected = _source(tmp_path, b"expected")
    client.objects["archive/data.bin"] = _StoredObject(
        b"wrong",
        "version-1",
        checksum_type=None,
        checksum_sha256=None,
    )

    with pytest.raises(S3StoredObjectMismatch):
        _target(client).verify(
            "archive/data.bin",
            expected.size_bytes,
            expected.sha256,
        )


@pytest.mark.parametrize("provider_version_id", [None, "missing-version"])
def test_verify_missing_key_or_exact_version_is_a_stored_object_mismatch(
    tmp_path: Path,
    provider_version_id: str | None,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"expected")
    if provider_version_id is not None:
        client.objects["archive/data.bin"] = _StoredObject(
            b"expected",
            "different-version",
        )

    with pytest.raises(S3StoredObjectMismatch):
        _target(client).verify(
            "archive/data.bin",
            source.size_bytes,
            source.sha256,
            provider_version_id=provider_version_id,
        )


def test_open_reader_missing_exact_version_is_a_stored_object_mismatch() -> None:
    client = FakeS3Client()
    client.objects["archive/data.bin"] = _StoredObject(
        b"expected",
        "different-version",
    )

    with pytest.raises(S3StoredObjectMismatch):
        _target(client).open_reader(
            "archive/data.bin",
            provider_version_id="missing-version",
        )


def test_incomplete_streamed_readback_is_retryable(tmp_path: Path) -> None:
    class IncompleteBody(io.BytesIO):
        def read(self, size: int | None = -1) -> bytes:
            raise IncompleteReadError(actual_bytes=4, expected_bytes=8)

    class IncompleteReadClient(FakeS3Client):
        def get_object(self, **kwargs: object) -> Mapping[str, object]:
            response = dict(super().get_object(**kwargs))
            response["Body"] = IncompleteBody()
            return response

    client = IncompleteReadClient()
    source = _source(tmp_path, b"expected")
    client.objects["archive/data.bin"] = _StoredObject(
        b"expected",
        "version-1",
        checksum_type=None,
        checksum_sha256=None,
    )

    with pytest.raises(S3RetryableError) as captured:
        _target(client).verify(
            "archive/data.bin",
            source.size_bytes,
            source.sha256,
        )

    assert captured.value.operation == "GetObjectBody"
    assert captured.value.__context__ is None


def test_multipart_interruption_persists_and_reuses_matching_parts(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    client.fail_upload_part_after = 2
    source = _source(tmp_path, b"a" * (PART_SIZE * 2 + 17))
    journal = MemoryJournal()
    target = _target(client, journal=journal)

    with pytest.raises(S3RetryableError) as captured:
        target.put(source, key="archive/large.bin")
    assert captured.value.retry_after_ns == 7_000_000_000
    assert captured.value.__context__ is None
    assert journal.checkpoint is not None
    interrupted = journal.checkpoint
    assert interrupted.upload_id == "upload-1"
    assert tuple(part.part_number for part in interrupted.parts) == (1, 2)
    assert all(part.checksum is not None for part in interrupted.parts)
    assert journal.save_expected_states[0] is None
    assert all(
        expected is not None and expected.upload_id == "upload-1"
        for expected in journal.save_expected_states[1:]
    )

    client.fail_upload_part_after = None
    before_resume = client.upload_part_calls
    result = target.put(
        source,
        key="archive/large.bin",
        resume=interrupted,
    )

    assert result.created
    assert result.resumed
    assert client.upload_part_calls == before_resume + 1
    assert journal.checkpoint is None
    completed = journal.cleared[-1]
    assert completed is not None
    assert tuple(part.part_number for part in completed.parts) == (1, 2, 3)
    verification = target.verify(
        result.key,
        source.size_bytes,
        source.sha256,
        provider_version_id=result.provider_version_id,
    )
    assert verification.method == "readback_sha256"


def test_source_changed_between_retries_aborts_and_clears_durable_upload(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    client.fail_upload_part_after = 0
    source = _source(tmp_path, b"s" * (PART_SIZE + 1))
    journal = MemoryJournal()
    target = _target(client, journal=journal)

    with pytest.raises(S3RetryableError):
        target.put(source, key="archive/large.bin")

    interrupted = journal.checkpoint
    assert interrupted is not None
    assert interrupted.upload_id in client.uploads
    source.path.write_bytes(b"changed")
    client.fail_upload_part_after = None

    with pytest.raises(S3CheckpointConflict, match="source identity"):
        target.put(
            source,
            key="archive/large.bin",
            resume=interrupted,
        )

    assert interrupted.upload_id not in client.uploads
    assert journal.checkpoint is None
    assert journal.cleared == [interrupted]


def test_upload_part_incomplete_success_evidence_is_reconciled_on_retry(
    tmp_path: Path,
) -> None:
    class MissingPartEtagClient(FakeS3Client):
        def __init__(self) -> None:
            super().__init__()
            self._omit_once = True

        def upload_part(self, **kwargs: object) -> Mapping[str, object]:
            response = dict(super().upload_part(**kwargs))
            if self._omit_once:
                self._omit_once = False
                response.pop("ETag")
            return response

    client = MissingPartEtagClient()
    source = _source(tmp_path, b"u" * (PART_SIZE + 1))
    journal = MemoryJournal()
    target = _target(client, journal=journal)

    with pytest.raises(S3RetryableError, match="commit evidence"):
        target.put(source, key="archive/large.bin")

    interrupted = journal.checkpoint
    assert interrupted is not None
    assert interrupted.parts == ()
    recovered = target.put(
        source,
        key="archive/large.bin",
        resume=interrupted,
    )

    assert recovered.created
    assert recovered.resumed
    assert client.upload_part_calls == 2


def test_complete_incomplete_success_evidence_is_recovered_on_retry(
    tmp_path: Path,
) -> None:
    class MissingCompleteEtagClient(FakeS3Client):
        def __init__(self) -> None:
            super().__init__()
            self._omit_once = True

        def complete_multipart_upload(
            self,
            **kwargs: object,
        ) -> Mapping[str, object]:
            response = dict(super().complete_multipart_upload(**kwargs))
            if self._omit_once:
                self._omit_once = False
                response.pop("ETag")
            return response

    client = MissingCompleteEtagClient()
    source = _source(tmp_path, b"c" * (PART_SIZE + 1))
    journal = MemoryJournal()
    target = _target(client, journal=journal)

    with pytest.raises(S3RetryableError, match="commit evidence"):
        target.put(source, key="archive/large.bin")

    interrupted = journal.checkpoint
    assert interrupted is not None
    assert len(interrupted.parts) == 2
    recovered = target.put(
        source,
        key="archive/large.bin",
        resume=interrupted,
    )

    assert not recovered.created
    assert recovered.resumed
    assert journal.checkpoint is None
    assert journal.cleared == [interrupted]


def test_complete_clear_cas_contention_retries_without_aborting_committed_upload(
    tmp_path: Path,
) -> None:
    class ClearContendingJournal(MemoryJournal):
        def __init__(self) -> None:
            super().__init__()
            self._contended = False

        def clear(self, expected: ResumeState | None) -> None:
            if not self._contended:
                self._contended = True
                assert expected is not None
                self.checkpoint = ResumeState(
                    upload_id=expected.upload_id,
                    parts=(),
                )
                raise MultipartJournalConflict("checkpoint clear CAS conflict")
            super().clear(expected)

    client = FakeS3Client()
    source = _source(tmp_path, b"z" * (PART_SIZE + 1))
    journal = ClearContendingJournal()
    target = _target(client, journal=journal)

    with pytest.raises(MultipartJournalConflict, match="clear CAS conflict"):
        target.put(source, key="archive/clear-contention.bin")

    durable = journal.checkpoint
    assert durable is not None
    assert durable.upload_id not in client.uploads
    assert "archive/clear-contention.bin" in client.objects
    assert "abort_multipart_upload" not in _operations(client)

    recovered = target.put(
        source,
        key="archive/clear-contention.bin",
        resume=durable,
    )

    assert not recovered.created
    assert recovered.resumed
    assert journal.checkpoint is None


def test_resume_lists_all_pages_before_reusing_parts(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"b" * (PART_SIZE * 2 + 1))
    journal = MemoryJournal()
    target = _target(client, journal=journal)
    client.complete_retry_error = _client_error(
        "SlowDown",
        503,
        "CompleteMultipartUpload",
    )
    with pytest.raises(S3RetryableError):
        target.put(source, key="archive/large.bin")
    checkpoint = journal.checkpoint
    assert checkpoint is not None

    client.list_page_size = 1
    before = client.upload_part_calls

    resumed = target.put(
        source,
        key="archive/large.bin",
        resume=checkpoint,
    )

    assert resumed.resumed
    assert client.upload_part_calls == before
    assert _operations(client).count("list_parts") == 3


def test_resume_recovers_remote_part_written_before_local_checkpoint(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"q" * (PART_SIZE + 1))
    first_data = b"q" * PART_SIZE
    first_checksum = base64.b64encode(hashlib.sha256(first_data).digest()).decode(
        "ascii"
    )
    checkpoint = ResumeState(
        upload_id="upload-existing",
        parts=(),
    )
    journal = MemoryJournal(checkpoint)
    client.uploads[checkpoint.upload_id] = {
        1: (first_data, '"remote-etag"', first_checksum)
    }
    client.upload_keys[checkpoint.upload_id] = "archive/large.bin"

    result = _target(client, journal=journal).put(
        source,
        key="archive/large.bin",
        resume=checkpoint,
    )

    assert result.resumed
    assert client.upload_part_calls == 1
    assert any(
        tuple(part.part_number for part in saved.parts) == (1,)
        for saved in journal.saved
    )


def test_resume_reuploads_locally_recorded_part_missing_from_provider(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"r" * (PART_SIZE + 1))
    first_checksum = base64.b64encode(hashlib.sha256(b"r" * PART_SIZE).digest()).decode(
        "ascii"
    )
    checkpoint = ResumeState(
        upload_id="upload-existing",
        parts=(
            MultipartPartV1(
                part_number=1,
                etag='"local-etag"',
                size_bytes=PART_SIZE,
                checksum=first_checksum,
            ),
        ),
    )
    journal = MemoryJournal(checkpoint)
    client.uploads[checkpoint.upload_id] = {}
    client.upload_keys[checkpoint.upload_id] = "archive/large.bin"

    result = _target(client, journal=journal).put(
        source,
        key="archive/large.bin",
        resume=checkpoint,
    )

    assert result.resumed
    assert client.upload_part_calls == 2
    assert journal.saved[0].parts == ()


def test_resume_reuploads_part_when_provider_cannot_list_part_checksum(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"s" * (PART_SIZE + 1))
    first_data = b"s" * PART_SIZE
    first_checksum = base64.b64encode(hashlib.sha256(first_data).digest()).decode(
        "ascii"
    )
    checkpoint = ResumeState(
        upload_id="upload-existing",
        parts=(
            MultipartPartV1(
                part_number=1,
                etag='"local-etag"',
                size_bytes=PART_SIZE,
                checksum=first_checksum,
            ),
        ),
    )
    journal = MemoryJournal(checkpoint)
    client.uploads[checkpoint.upload_id] = {
        1: (first_data, '"remote-etag"', first_checksum)
    }
    client.upload_keys[checkpoint.upload_id] = "archive/large.bin"
    client.list_checksums = False

    result = _target(client, journal=journal).put(
        source,
        key="archive/large.bin",
        resume=checkpoint,
    )

    assert result.resumed
    assert client.upload_part_calls == 2
    assert "abort_multipart_upload" not in _operations(client)


def test_configured_multipart_concurrency_is_used(tmp_path: Path) -> None:
    class ConcurrentClient(FakeS3Client):
        def __init__(self) -> None:
            super().__init__()
            self.barrier = threading.Barrier(2)
            self.lock = threading.Lock()
            self.active = 0
            self.max_active = 0

        def upload_part(self, **kwargs: object) -> Mapping[str, object]:
            with self.lock:
                self.active += 1
                self.max_active = max(self.max_active, self.active)
            try:
                self.barrier.wait(timeout=2)
                return super().upload_part(**kwargs)
            finally:
                with self.lock:
                    self.active -= 1

    client = ConcurrentClient()
    source = _source(tmp_path, b"t" * (PART_SIZE + 1))
    journal = MemoryJournal()
    target = _target(
        client,
        config=_config(concurrency=2),
        journal=journal,
    )

    result = target.put(source, key="archive/large.bin")

    assert result.created
    assert client.max_active == 2


def test_multipart_failure_stops_submitting_new_parts(tmp_path: Path) -> None:
    client = FakeS3Client()
    client.fail_upload_part_after = 0
    source = _source(tmp_path, b"w" * (PART_SIZE * 3 + 1))
    journal = MemoryJournal()

    with pytest.raises(S3RetryableError):
        _target(client, journal=journal).put(source, key="archive/large.bin")

    assert client.upload_part_calls == 1


def test_checkpoint_conflict_overrides_concurrent_retryable_part_error(
    tmp_path: Path,
) -> None:
    barrier = threading.Barrier(2)

    class MixedFailureClient(FakeS3Client):
        def upload_part(self, **kwargs: object) -> Mapping[str, object]:
            if kwargs["PartNumber"] == 1:
                self._record("upload_part", dict(kwargs))
                self.upload_part_calls += 1
                barrier.wait()
                raise _client_error("SlowDown", 503, "UploadPart")
            response = super().upload_part(**kwargs)
            barrier.wait()
            return response

    class ConflictingJournal(MemoryJournal):
        def save(
            self,
            checkpoint: ResumeState,
            expected: ResumeState | None,
        ) -> None:
            if expected is not None:
                self.checkpoint = ResumeState(
                    upload_id="competing-upload",
                    parts=(),
                )
                raise MultipartJournalConflict("checkpoint CAS conflict")
            super().save(checkpoint, expected)

    client = MixedFailureClient()
    source = _source(tmp_path, b"m" * (PART_SIZE * 2 + 1))
    journal = ConflictingJournal()

    with pytest.raises(MultipartJournalConflict, match="CAS conflict"):
        _target(
            client,
            config=_config(concurrency=2),
            journal=journal,
        ).put(source, key="archive/large.bin")

    assert client.upload_part_calls == 2
    assert "upload-1" in client.uploads
    assert journal.checkpoint == ResumeState(
        upload_id="competing-upload",
        parts=(),
    )


@pytest.mark.parametrize("resuming", [False, True])
def test_upload_part_missing_upload_clears_checkpoint_and_is_retryable(
    tmp_path: Path,
    resuming: bool,
) -> None:
    class DisappearingUploadClient(FakeS3Client):
        def __init__(self) -> None:
            super().__init__()
            self._disappearance_lock = threading.Lock()
            self._disappeared = False

        def upload_part(self, **kwargs: object) -> Mapping[str, object]:
            upload_id = str(kwargs["UploadId"])
            with self._disappearance_lock:
                if not self._disappeared:
                    self._disappeared = True
                    self.uploads.pop(upload_id, None)
                    self.upload_keys.pop(upload_id, None)
            return super().upload_part(**kwargs)

    client = DisappearingUploadClient()
    source = _source(tmp_path, b"d" * (PART_SIZE * 2 + 1))
    if resuming:
        checkpoint = ResumeState(upload_id="upload-existing", parts=())
        client.uploads[checkpoint.upload_id] = {}
        client.upload_keys[checkpoint.upload_id] = "archive/large.bin"
    else:
        checkpoint = None
    journal = MemoryJournal(checkpoint)
    target = _target(
        client,
        config=_config(concurrency=2),
        journal=journal,
    )

    with pytest.raises(S3RetryableError) as captured:
        target.put(
            source,
            key="archive/large.bin",
            resume=checkpoint,
        )

    expected_upload_id = "upload-existing" if resuming else "upload-1"
    assert captured.value.operation == "UploadPart"
    assert captured.value.error_code == "NoSuchUpload"
    assert journal.checkpoint is None
    assert len(journal.cleared) == 1
    assert journal.cleared[0] is not None
    assert journal.cleared[0].upload_id == expected_upload_id
    assert client.upload_part_calls == 2


def test_source_change_before_multipart_complete_aborts_and_resets(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path, b"x" * (PART_SIZE + 1))

    class MutatingClient(FakeS3Client):
        def upload_part(self, **kwargs: object) -> Mapping[str, object]:
            response = super().upload_part(**kwargs)
            if kwargs["PartNumber"] == 1:
                with source.path.open("r+b") as stream:
                    stream.seek(PART_SIZE)
                    stream.write(b"y")
            return response

    client = MutatingClient()
    journal = MemoryJournal()

    with pytest.raises(S3CheckpointConflict, match="source identity"):
        _target(client, journal=journal).put(source, key="archive/large.bin")

    assert "complete_multipart_upload" not in _operations(client)
    assert "abort_multipart_upload" in _operations(client)
    assert journal.checkpoint is None


def test_remote_part_checksum_divergence_aborts_resets_and_fails_closed(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"c" * (PART_SIZE + 1))
    checksum = base64.b64encode(hashlib.sha256(b"c" * PART_SIZE).digest()).decode(
        "ascii"
    )
    checkpoint = ResumeState(
        upload_id="upload-existing",
        parts=(
            MultipartPartV1(
                part_number=1,
                etag='"old-etag"',
                size_bytes=PART_SIZE,
                checksum=checksum,
            ),
        ),
    )
    journal = MemoryJournal(checkpoint)
    client.uploads[checkpoint.upload_id] = {
        1: (
            b"x" * PART_SIZE,
            '"remote-etag"',
            base64.b64encode(hashlib.sha256(b"x" * PART_SIZE).digest()).decode("ascii"),
        )
    }
    client.upload_keys[checkpoint.upload_id] = "archive/large.bin"

    with pytest.raises(S3CheckpointConflict):
        _target(client, journal=journal).put(
            source,
            key="archive/large.bin",
            resume=checkpoint,
        )

    assert "upload-existing" not in client.uploads
    assert journal.checkpoint is None
    assert journal.cleared == [checkpoint]
    assert "complete_multipart_upload" not in _operations(client)


def test_checkpoint_binding_mismatch_fails_before_network(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"d" * (PART_SIZE + 1))
    checkpoint = ResumeState(
        upload_id="upload-existing",
        parts=(),
    )
    requested = ResumeState(upload_id="different-upload", parts=())
    journal = MemoryJournal(checkpoint)

    with pytest.raises(MultipartJournalConflict):
        _target(client, journal=journal).put(
            source,
            key="archive/large.bin",
            resume=requested,
        )

    assert client.calls == []


def test_missing_remote_upload_resets_checkpoint_and_starts_again(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"e" * (PART_SIZE + 1))
    stale = ResumeState(
        upload_id="missing-upload",
        parts=(),
    )
    journal = MemoryJournal(stale)

    result = _target(client, journal=journal).put(
        source,
        key="archive/large.bin",
        resume=stale,
    )

    assert journal.cleared[0] == stale
    assert journal.checkpoint is None
    assert not result.resumed


def test_completed_before_crash_is_recovered_by_exact_existing_object(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"f" * (PART_SIZE + 1))
    stale = ResumeState(
        upload_id="completed-upload",
        parts=(),
    )
    journal = MemoryJournal(stale)
    client.objects["archive/large.bin"] = _StoredObject(
        source.path.read_bytes(),
        "completed-version",
        checksum_type=None,
        checksum_sha256=None,
    )

    result = _target(client, journal=journal).put(
        source,
        key="archive/large.bin",
        resume=stale,
    )

    assert not result.created
    assert result.resumed
    assert result.provider_version_id == "completed-version"
    assert journal.cleared == [stale]
    assert "abort_multipart_upload" in _operations(client)
    assert "create_multipart_upload" not in _operations(client)


def test_existing_object_retry_aborts_live_upload_before_clearing_checkpoint(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"x" * (PART_SIZE + 1))
    checkpoint = ResumeState(upload_id="ambiguous-complete", parts=())
    journal = MemoryJournal(checkpoint)
    client.objects["archive/large.bin"] = _StoredObject(
        source.path.read_bytes(),
        "completed-version",
        checksum_type=None,
        checksum_sha256=None,
    )
    client.uploads[checkpoint.upload_id] = {}
    client.upload_keys[checkpoint.upload_id] = "archive/large.bin"
    client.abort_error = _client_error(
        "InternalError",
        500,
        "AbortMultipartUpload",
    )
    target = _target(client, journal=journal)

    with pytest.raises(S3AbortError):
        target.put(
            source,
            key="archive/large.bin",
            resume=checkpoint,
        )

    assert journal.checkpoint == checkpoint
    assert checkpoint.upload_id in client.uploads

    client.abort_error = None
    result = target.put(
        source,
        key="archive/large.bin",
        resume=checkpoint,
    )

    assert not result.created
    assert result.resumed
    assert journal.checkpoint is None
    assert checkpoint.upload_id not in client.uploads


def test_multipart_requires_a_durable_journal_before_network(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"g" * (PART_SIZE + 1))

    with pytest.raises(S3CheckpointPersistenceError, match="journal"):
        _target(client).put(source, key="archive/large.bin")

    assert client.calls == []


def test_multipart_part_limit_is_rejected_before_remote_upload(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"z" * 10_001)
    journal = MemoryJournal()
    target = S3Target(
        target_id="s3-primary",
        bucket="market-data",
        remote_prefix="",
        addressing_style="path",
        storage_class=None,
        multipart_size_bytes=1,
        concurrency=1,
        client=client,
        journal_factory=lambda source, key: journal,
        now_unix_ns=lambda: 0,
    )

    with pytest.raises(S3FatalError, match="10000 parts"):
        target.put(source, "archive/too-many-parts.bin")

    assert client.calls == []
    assert journal.checkpoint is None


def test_failed_initial_checkpoint_aborts_upload_before_any_part(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"h" * (PART_SIZE + 1))
    journal = MemoryJournal()
    journal.fail_next_save = True

    with pytest.raises(S3CheckpointPersistenceError):
        _target(client, journal=journal).put(source, key="archive/large.bin")

    assert _operations(client) == [
        "head_object",
        "create_multipart_upload",
        "abort_multipart_upload",
    ]
    assert client.uploads == {}


def test_initial_save_and_abort_failure_repersists_upload_for_retry(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"r" * (PART_SIZE + 1))
    journal = MemoryJournal()
    journal.fail_next_save = True
    client.abort_error = _client_error(
        "InternalError",
        500,
        "AbortMultipartUpload",
    )
    target = _target(client, journal=journal)

    with pytest.raises(S3AbortError):
        target.put(source, key="archive/large.bin")

    recovered = journal.checkpoint
    assert recovered == ResumeState(upload_id="upload-1", parts=())
    assert recovered.upload_id in client.uploads

    client.abort_error = None
    result = target.put(
        source,
        key="archive/large.bin",
        resume=recovered,
    )

    assert result.created
    assert result.resumed


def test_initial_checkpoint_cas_conflict_is_retryable_and_aborts_new_upload(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"c" * (PART_SIZE + 1))
    journal = MemoryJournal()
    journal.conflict_next_save = True

    with pytest.raises(MultipartJournalConflict, match="CAS conflict"):
        _target(client, journal=journal).put(source, key="archive/large.bin")

    assert _operations(client) == [
        "head_object",
        "create_multipart_upload",
        "abort_multipart_upload",
    ]
    assert client.uploads == {}
    assert journal.checkpoint == ResumeState(
        upload_id="competing-upload",
        parts=(),
    )


def test_part_checkpoint_cas_conflict_keeps_shared_upload_and_competitor_state(
    tmp_path: Path,
) -> None:
    class ConflictAfterInitialSaveJournal(MemoryJournal):
        def save(
            self,
            checkpoint: ResumeState,
            expected: ResumeState | None,
        ) -> None:
            if expected is not None:
                candidate = checkpoint.parts[0]
                self.checkpoint = ResumeState(
                    upload_id=expected.upload_id,
                    parts=(
                        MultipartPartV1(
                            part_number=candidate.part_number,
                            etag='"competing-etag"',
                            size_bytes=candidate.size_bytes,
                            checksum=candidate.checksum,
                        ),
                    ),
                )
                raise MultipartJournalConflict("checkpoint CAS conflict")
            super().save(checkpoint, expected)

    client = FakeS3Client()
    source = _source(tmp_path, b"p" * (PART_SIZE + 1))
    journal = ConflictAfterInitialSaveJournal()

    with pytest.raises(MultipartJournalConflict, match="CAS conflict"):
        _target(client, journal=journal).put(source, key="archive/large.bin")

    assert "upload-1" in client.uploads
    assert "abort_multipart_upload" not in _operations(client)
    assert journal.checkpoint is not None
    assert journal.checkpoint.upload_id == "upload-1"
    assert journal.checkpoint.parts[0].etag == '"competing-etag"'


def test_source_truncated_during_part_upload_aborts_and_clears_checkpoint(
    tmp_path: Path,
) -> None:
    source = _source(tmp_path, b"t" * (PART_SIZE + 1))

    class TruncatingClient(FakeS3Client):
        def upload_part(self, **kwargs: object) -> Mapping[str, object]:
            response = super().upload_part(**kwargs)
            if kwargs["PartNumber"] == 1:
                source.path.write_bytes(b"t" * PART_SIZE)
            return response

    client = TruncatingClient()
    journal = MemoryJournal()

    with pytest.raises(S3CheckpointConflict, match="source changed"):
        _target(client, journal=journal).put(source, key="archive/large.bin")

    assert client.uploads == {}
    assert journal.checkpoint is None
    assert len(journal.cleared) == 1
    assert journal.cleared[0] is not None
    assert journal.cleared[0].upload_id == "upload-1"


def test_abort_failure_preserves_checkpoint_and_reports_fail_closed(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"i" * (PART_SIZE + 1))
    checksum = base64.b64encode(hashlib.sha256(b"i" * PART_SIZE).digest()).decode(
        "ascii"
    )
    checkpoint = ResumeState(
        upload_id="upload-existing",
        parts=(
            MultipartPartV1(
                part_number=1,
                etag='"local"',
                size_bytes=PART_SIZE,
                checksum=checksum,
            ),
        ),
    )
    journal = MemoryJournal(checkpoint)
    client.uploads[checkpoint.upload_id] = {
        1: (
            b"wrong" * (PART_SIZE // 5),
            '"remote"',
            base64.b64encode(hashlib.sha256(b"wrong").digest()).decode("ascii"),
        )
    }
    client.upload_keys[checkpoint.upload_id] = "archive/large.bin"
    client.abort_error = _client_error("InternalError", 500, "AbortMultipartUpload")

    with pytest.raises(S3AbortError) as captured:
        _target(client, journal=journal).put(
            source,
            key="archive/large.bin",
            resume=checkpoint,
        )

    assert isinstance(captured.value, S3RetryableError)
    assert journal.checkpoint == checkpoint
    assert journal.cleared == []


def test_nonretryable_abort_failure_is_fatal_and_preserves_checkpoint(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"u" * (PART_SIZE + 1))
    checksum = base64.b64encode(hashlib.sha256(b"u" * PART_SIZE).digest()).decode(
        "ascii"
    )
    checkpoint = ResumeState(
        upload_id="upload-existing",
        parts=(
            MultipartPartV1(
                part_number=1,
                etag='"local"',
                size_bytes=PART_SIZE,
                checksum=checksum,
            ),
        ),
    )
    journal = MemoryJournal(checkpoint)
    client.uploads[checkpoint.upload_id] = {
        1: (
            b"v" * PART_SIZE,
            '"remote"',
            base64.b64encode(hashlib.sha256(b"v" * PART_SIZE).digest()).decode("ascii"),
        )
    }
    client.upload_keys[checkpoint.upload_id] = "archive/large.bin"
    client.abort_error = _client_error("AccessDenied", 403, "AbortMultipartUpload")

    with pytest.raises(S3FatalAbortError):
        _target(client, journal=journal).put(
            source,
            key="archive/large.bin",
            resume=checkpoint,
        )

    assert journal.checkpoint == checkpoint
    assert journal.cleared == []


def test_complete_precondition_match_aborts_own_upload_and_returns_existing(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    data = b"j" * (PART_SIZE + 1)
    source = _source(tmp_path, data)
    client.complete_conflict = ("archive/large.bin", data)
    journal = MemoryJournal()

    result = _target(client, journal=journal).put(source, key="archive/large.bin")

    assert not result.created
    assert journal.checkpoint is None
    assert "abort_multipart_upload" in _operations(client)


def test_complete_precondition_mismatch_is_a_hard_conflict(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"k" * (PART_SIZE + 1))
    client.complete_conflict = ("archive/large.bin", b"wrong")
    journal = MemoryJournal()

    with pytest.raises(S3ObjectConflict):
        _target(client, journal=journal).put(source, key="archive/large.bin")

    assert journal.checkpoint is None
    assert "abort_multipart_upload" in _operations(client)


def test_complete_409_aborts_resets_and_surfaces_retryable_error(
    tmp_path: Path,
) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"l" * (PART_SIZE + 1))
    client.complete_retry_error = _client_error(
        "ConditionalRequestConflict",
        409,
        "CompleteMultipartUpload",
        retry_after="3",
    )
    journal = MemoryJournal()

    with pytest.raises(S3RetryableError) as captured:
        _target(client, journal=journal).put(source, key="archive/large.bin")

    assert captured.value.retry_after_ns == 3_000_000_000
    assert journal.checkpoint is None
    assert "abort_multipart_upload" in _operations(client)


@pytest.mark.parametrize(
    ("code", "status", "expected"),
    [
        ("SlowDown", 503, S3RetryableError),
        ("TooManyRequests", 429, S3RetryableError),
        ("RequestTimeout", 400, S3RetryableError),
        ("AccessDenied", 403, S3FatalError),
        ("InvalidArgument", 400, S3FatalError),
    ],
)
def test_s3_error_classification(
    code: str, status: int, expected: type[Exception]
) -> None:
    classified = classify_s3_error(
        _client_error(code, status, "PutObject", retry_after="4"),
        operation="PutObject",
        now_unix_ns=0,
    )

    assert isinstance(classified, expected)
    assert "provider detail" not in str(classified)
    if isinstance(classified, S3RetryableError):
        assert classified.retry_after_ns == 4_000_000_000


def test_proxy_connection_failure_is_retryable() -> None:
    classified = classify_s3_error(
        ProxyConnectionError(proxy_url="http://127.0.0.1:1080"),
        operation="HeadObject",
        now_unix_ns=0,
    )

    assert isinstance(classified, S3RetryableError)
    assert classified.error_code is None


def test_retry_after_http_date_and_malformed_value_are_classified() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    future = format_datetime(now + timedelta(seconds=9), usegmt=True)
    dated = classify_s3_error(
        _client_error("SlowDown", 503, "UploadPart", retry_after=future),
        operation="UploadPart",
        now_unix_ns=int(now.timestamp() * 1_000_000_000),
    )
    malformed = classify_s3_error(
        _client_error("SlowDown", 503, "UploadPart", retry_after="later"),
        operation="UploadPart",
        now_unix_ns=0,
    )

    assert isinstance(dated, S3RetryableError)
    assert dated.retry_after_ns == 9_000_000_000
    assert isinstance(malformed, S3RetryableError)
    assert malformed.retry_after_ns is None


@pytest.mark.parametrize("addressing_style", ["auto", "path", "virtual"])
def test_factory_maps_endpoint_addressing_concurrency_and_credentials_once(
    addressing_style: str,
) -> None:
    config = _config(addressing_style=addressing_style, concurrency=7)
    credentials = config.credentials
    refs = {
        credentials.access_key_id: "access-plaintext",
        credentials.secret_access_key: "secret-plaintext",
    }
    if credentials.session_token is not None:
        refs[credentials.session_token] = "session-plaintext"
    snapshot = CountingSnapshot(refs)
    captured: dict[str, Any] = {}

    def factory(**kwargs: object) -> FakeS3Client:
        captured.update(kwargs)
        return FakeS3Client()

    target = build_s3_target(
        config,
        secrets=snapshot,  # type: ignore[arg-type]
        client_factory=factory,
    )

    assert all(count == 1 for count in snapshot.reads.values())
    assert set(snapshot.reads) == set(refs)
    assert captured["endpoint_url"] == "http://127.0.0.1:9000"
    assert captured["region_name"] == "us-east-1"
    assert captured["aws_access_key_id"] == "access-plaintext"
    assert captured["aws_secret_access_key"] == "secret-plaintext"
    assert captured["aws_session_token"] == "session-plaintext"
    botocore_config = captured["config"]
    assert botocore_config.s3["addressing_style"] == addressing_style
    assert botocore_config.max_pool_connections == 7
    assert botocore_config.retries["total_max_attempts"] == 1
    rendered = repr(target)
    assert "access-plaintext" not in rendered
    assert "secret-plaintext" not in rendered
    assert "session-plaintext" not in rendered
    assert "127.0.0.1:9000" not in rendered


def test_factory_wraps_client_construction_without_leaking_secrets() -> None:
    config = _config()
    credentials = config.credentials
    secret = "extremely-private-secret"
    secrets = SecretSnapshot.from_test_values(
        {
            credentials.access_key_id: "access",
            credentials.secret_access_key: secret,
            credentials.session_token: "token",  # type: ignore[dict-item]
        }
    )

    def fail_factory(**_kwargs: object) -> FakeS3Client:
        raise RuntimeError(secret)

    with pytest.raises(S3FatalError) as captured:
        build_s3_target(config, secrets=secrets, client_factory=fail_factory)
    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    "key",
    ["/absolute", "archive//part", "archive/../part", "archive\\part", ""],
)
def test_unsafe_object_key_fails_before_network(tmp_path: Path, key: str) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"value")

    with pytest.raises(UnsafeObjectKey, match="object key"):
        _target(client).put(source, key=key)

    assert client.calls == []


def test_source_identity_mismatch_fails_before_network(tmp_path: Path) -> None:
    client = FakeS3Client()
    source = _source(tmp_path, b"original")
    source.path.write_bytes(b"changed!")

    with pytest.raises(S3CheckpointConflict, match="source identity"):
        _target(client).put(source, key="archive/data.bin")

    assert client.calls == []
