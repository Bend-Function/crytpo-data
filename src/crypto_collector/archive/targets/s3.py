from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import io
import os
import re
import stat
import time
from collections.abc import Callable, Mapping
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path, PurePosixPath
from typing import IO, Any, Literal, Protocol, Self, cast

from botocore.config import Config  # type: ignore[import-untyped]
from botocore.exceptions import (  # type: ignore[import-untyped]
    ConnectionClosedError,
    ConnectTimeoutError,
    EndpointConnectionError,
    HTTPClientError,
    IncompleteReadError,
    ProxyConnectionError,
    ReadTimeoutError,
)

from crypto_collector.archive.models import ArchiveVerificationLevel, MultipartPartV1
from crypto_collector.archive.receipt import ProviderChecksumV1
from crypto_collector.archive.state import (
    ArchiveTargetError,
    ExistingObjectMismatch,
    RetryableTargetError,
    StoredObjectMismatch,
)
from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    MultipartJournal,
    MultipartJournalConflict,
    MultipartJournalFactory,
    PutResult,
    ResumeState,
    TargetClosed,
    TargetProbe,
    UnsafeObjectKey,
    VerifyResult,
)
from crypto_collector.config.models import S3TargetConfig
from crypto_collector.config.primitives import SecretRef, SecretSnapshot, SecretValue

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})
_RETRYABLE_CODES = frozenset(
    {
        "ConditionalRequestConflict",
        "InternalError",
        "InternalServerError",
        "OperationAborted",
        "RequestTimeout",
        "RequestTimeoutException",
        "ServiceUnavailable",
        "SlowDown",
        "Throttling",
        "ThrottlingException",
        "TooManyRequests",
        "TooManyRequestsException",
    }
)
_CHECKSUM_MODE_UNSUPPORTED = frozenset(
    {"InvalidArgument", "InvalidRequest", "NotImplemented", "NotSupported"}
)
_TRANSPORT_ERRORS = (
    ConnectTimeoutError,
    ConnectionClosedError,
    EndpointConnectionError,
    HTTPClientError,
    IncompleteReadError,
    ProxyConnectionError,
    ReadTimeoutError,
)
_READ_CHUNK_BYTES = 1024 * 1024
_MAX_MULTIPART_PARTS = 10_000
_NS_PER_SECOND = 1_000_000_000
_MAX_RETRY_AFTER_DIGITS = 20
_PROBE_PAYLOAD = b"crypto-collector:s3:no-replace:v1\n"
_PROBE_SHA256 = hashlib.sha256(_PROBE_PAYLOAD).hexdigest()
_PROBE_CHECKSUM = base64.b64encode(bytes.fromhex(_PROBE_SHA256)).decode("ascii")


class S3FatalError(ArchiveTargetError):
    """An S3 operation cannot be retried without changing external state."""


class S3RetryableError(RetryableTargetError):
    """A transport/provider failure that the durable scheduler may retry."""

    def __init__(
        self,
        message: str,
        *,
        operation: str,
        status_code: int | None,
        error_code: str | None,
        retry_after_ns: int | None,
    ) -> None:
        super().__init__(message)
        self.operation = operation
        self.status_code = status_code
        self.error_code = error_code
        self.retry_after_ns = retry_after_ns


class S3ObjectConflict(ExistingObjectMismatch):
    """The immutable remote key already exists with another identity."""


class S3StoredObjectMismatch(StoredObjectMismatch):
    """Strong verification did not match the expected stored identity."""


class S3CheckpointConflict(ExistingObjectMismatch):
    """Multipart durable and provider state cannot be reconciled safely."""


class S3CheckpointPersistenceError(RetryableTargetError):
    """The local durable multipart journal could not be advanced."""


class S3AbortError(S3RetryableError):
    """A required multipart abort/reset did not finish safely."""


class S3FatalAbortError(S3FatalError):
    """A required multipart abort is not permitted or supported."""


class _S3ObjectNotFound(S3FatalError):
    pass


class _S3UploadNotFound(S3FatalError):
    pass


class _S3ChecksumModeUnsupported(S3FatalError):
    pass


class S3Client(Protocol):
    def head_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def get_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def put_object(self, **kwargs: object) -> Mapping[str, object]: ...

    def create_multipart_upload(self, **kwargs: object) -> Mapping[str, object]: ...

    def upload_part(self, **kwargs: object) -> Mapping[str, object]: ...

    def list_parts(self, **kwargs: object) -> Mapping[str, object]: ...

    def complete_multipart_upload(self, **kwargs: object) -> Mapping[str, object]: ...

    def abort_multipart_upload(self, **kwargs: object) -> Mapping[str, object]: ...


class S3ClientFactory(Protocol):
    def __call__(self, **kwargs: object) -> S3Client: ...


class SecretSnapshotPort(Protocol):
    def value_for(self, ref: SecretRef) -> SecretValue: ...


@dataclass(frozen=True, slots=True)
class _ErrorFacts:
    status_code: int | None
    error_code: str | None
    retry_after: str | None


@dataclass(frozen=True, slots=True)
class _RemotePart:
    part_number: int
    etag: str
    size_bytes: int
    checksum_sha256: str | None


class _FileSlice(io.RawIOBase):
    def __init__(self, path: Path, *, offset: int, size: int) -> None:
        super().__init__()
        self._fd = os.open(path, _source_open_flags())
        self._offset = offset
        self._size = size
        self._position = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def tell(self) -> int:
        return self._position

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence == os.SEEK_SET:
            position = offset
        elif whence == os.SEEK_CUR:
            position = self._position + offset
        elif whence == os.SEEK_END:
            position = self._size + offset
        else:
            raise ValueError("invalid seek mode")
        if not 0 <= position <= self._size:
            raise ValueError("seek is outside the file slice")
        self._position = position
        return position

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("I/O operation on closed file slice")
        remaining = self._size - self._position
        if remaining == 0:
            return b""
        requested = remaining if size is None or size < 0 else min(size, remaining)
        chunk = os.pread(self._fd, requested, self._offset + self._position)
        self._position += len(chunk)
        return chunk

    def close(self) -> None:
        if not self.closed:
            os.close(self._fd)
        super().close()


def _validate_object_key(key: str) -> str:
    if (
        type(key) is not str
        or not key
        or "\x00" in key
        or "\\" in key
        or key.startswith("/")
        or any(part in {"", ".", ".."} for part in key.split("/"))
        or PurePosixPath(key).as_posix() != key
    ):
        raise UnsafeObjectKey("S3 object key must be a normalized POSIX relative path")
    return key


def _source_open_flags() -> int:
    return os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)


def _hash_file(path: Path) -> tuple[int, str]:
    fd = os.open(path, _source_open_flags())
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("archive upload source is not a regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, _READ_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
        final = os.fstat(fd)
        if (final.st_dev, final.st_ino, final.st_size) != (
            info.st_dev,
            info.st_ino,
            info.st_size,
        ):
            raise OSError("archive upload source changed while hashing")
        return size, digest.hexdigest()
    finally:
        os.close(fd)


def _hash_range(path: Path, *, offset: int, size: int) -> str:
    digest = hashlib.sha256()
    position = 0
    fd = os.open(path, _source_open_flags())
    try:
        while position < size:
            chunk = os.pread(
                fd,
                min(_READ_CHUNK_BYTES, size - position),
                offset + position,
            )
            if not chunk:
                raise OSError("archive upload source ended inside a multipart part")
            digest.update(chunk)
            position += len(chunk)
    finally:
        os.close(fd)
    return base64.b64encode(digest.digest()).decode("ascii")


def _parse_retry_after_ns(value: str | None, *, now_unix_ns: int) -> int | None:
    if value is None or type(value) is not str or not value:
        return None
    if value.isascii() and value.isdigit():
        if len(value) > _MAX_RETRY_AFTER_DIGITS:
            return None
        return int(value) * _NS_PER_SECOND
    if type(now_unix_ns) is not int or now_unix_ns < 0:
        raise ValueError("now_unix_ns must be nonnegative")
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return None
    utc_value = parsed.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc_value - epoch
    target_ns = (
        delta.days * 86_400 + delta.seconds
    ) * _NS_PER_SECOND + delta.microseconds * 1_000
    return max(0, target_ns - now_unix_ns)


def _error_facts(error: BaseException) -> _ErrorFacts:
    response = getattr(error, "response", None)
    if not isinstance(response, Mapping):
        return _ErrorFacts(None, None, None)
    metadata = response.get("ResponseMetadata")
    status: int | None = None
    retry_after: str | None = None
    if isinstance(metadata, Mapping):
        candidate_status = metadata.get("HTTPStatusCode")
        if type(candidate_status) is int:
            status = candidate_status
        headers = metadata.get("HTTPHeaders")
        if isinstance(headers, Mapping):
            for name, value in headers.items():
                if str(name).lower() == "retry-after" and type(value) is str:
                    retry_after = value
                    break
    provider_error = response.get("Error")
    code: str | None = None
    if isinstance(provider_error, Mapping):
        candidate_code = provider_error.get("Code")
        if type(candidate_code) is str and candidate_code:
            code = candidate_code
    return _ErrorFacts(status, code, retry_after)


def classify_s3_error(
    error: BaseException,
    *,
    operation: str,
    now_unix_ns: int,
) -> ArchiveTargetError:
    if type(operation) is not str or not operation:
        raise ValueError("operation must be a nonempty string")
    if isinstance(error, ArchiveTargetError):
        return error
    facts = _error_facts(error)
    label = facts.error_code or "transport"
    message = f"S3 {operation} failed ({label})"
    retryable = (
        isinstance(error, _TRANSPORT_ERRORS)
        or facts.status_code in _RETRYABLE_STATUS
        or facts.error_code in _RETRYABLE_CODES
    )
    if retryable:
        return S3RetryableError(
            message,
            operation=operation,
            status_code=facts.status_code,
            error_code=facts.error_code,
            retry_after_ns=_parse_retry_after_ns(
                facts.retry_after,
                now_unix_ns=now_unix_ns,
            ),
        )
    if facts.status_code == 412 or facts.error_code == "PreconditionFailed":
        return S3ObjectConflict("S3 conditional create found an existing object")
    return S3FatalError(message)


def _string_field(
    response: Mapping[str, object],
    field: str,
    *,
    required: bool,
) -> str | None:
    value = response.get(field)
    if value is None and not required:
        return None
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise S3FatalError(f"S3 response has an invalid {field}")
    return value


def _strict_base64_sha256(value: object) -> bytes | None:
    if type(value) is not str or not value or not value.isascii():
        return None
    try:
        decoded = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    return decoded if len(decoded) == hashlib.sha256().digest_size else None


def _validate_version_id(value: str | None) -> None:
    if value is None:
        return
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError("provider_version_id must be a nonempty opaque string or None")


def _close_body_quietly(body: object) -> None:
    close = getattr(body, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception:  # noqa: BLE001 - streaming SDK boundary
        return


class S3Target:
    __slots__ = (
        "_addressing_style",
        "_bucket",
        "_client",
        "_closed",
        "_concurrency",
        "_journal_factory",
        "_multipart_size_bytes",
        "_now_unix_ns",
        "_remote_prefix",
        "_storage_class",
        "id",
    )

    def __init__(
        self,
        *,
        target_id: str,
        bucket: str,
        remote_prefix: str,
        addressing_style: Literal["auto", "path", "virtual"],
        storage_class: str | None,
        multipart_size_bytes: int,
        concurrency: int,
        client: S3Client,
        journal_factory: MultipartJournalFactory | None = None,
        now_unix_ns: Callable[[], int] = time.time_ns,
    ) -> None:
        if type(target_id) is not str or not target_id:
            raise ValueError("target_id must be nonempty")
        if type(bucket) is not str or not bucket:
            raise ValueError("bucket must be nonempty")
        if type(remote_prefix) is not str:
            raise TypeError("remote_prefix must be a string")
        if remote_prefix and _validate_object_key(remote_prefix) != remote_prefix:
            raise ValueError("remote_prefix is invalid")
        if addressing_style not in {"auto", "path", "virtual"}:
            raise ValueError("addressing_style is invalid")
        if storage_class is not None and (
            type(storage_class) is not str or not storage_class
        ):
            raise ValueError("storage_class must be nonempty or None")
        if type(multipart_size_bytes) is not int or multipart_size_bytes <= 0:
            raise ValueError("multipart_size_bytes must be positive")
        if type(concurrency) is not int or concurrency <= 0:
            raise ValueError("concurrency must be positive")
        if journal_factory is not None and not callable(journal_factory):
            raise TypeError("journal_factory must be callable or None")
        if not callable(now_unix_ns):
            raise TypeError("now_unix_ns must be callable")
        self.id = target_id
        self._bucket = bucket
        self._remote_prefix = remote_prefix
        self._addressing_style = addressing_style
        self._storage_class = storage_class
        self._multipart_size_bytes = multipart_size_bytes
        self._concurrency = concurrency
        self._client = client
        self._journal_factory = journal_factory
        self._now_unix_ns = now_unix_ns
        self._closed = False

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return (
            f"S3Target(id={self.id!r}, bucket={self._bucket!r}, "
            f"addressing_style={self._addressing_style!r}, state={state!r})"
        )

    def _require_not_closed(self) -> None:
        if self._closed:
            raise TargetClosed("S3 target is closed")

    def _invoke(
        self,
        operation: str,
        call: Callable[..., Mapping[str, object]],
        **kwargs: object,
    ) -> Mapping[str, object]:
        self._require_not_closed()
        now_unix_ns = self._now_unix_ns()
        if type(now_unix_ns) is not int or now_unix_ns < 0:
            raise S3FatalError("S3 target clock returned an invalid value")
        failure: ArchiveTargetError | None = None
        response: Mapping[str, object] | None = None
        try:
            response = call(**kwargs)
        except Exception as error:  # noqa: BLE001 - provider boundary
            facts = _error_facts(error)
            if facts.error_code == "NoSuchUpload":
                failure = _S3UploadNotFound("S3 multipart upload does not exist")
            elif operation in {"GetObject", "HeadObject"} and (
                facts.status_code == 404
                or facts.error_code in {"NoSuchKey", "NoSuchVersion", "NotFound"}
            ):
                failure = _S3ObjectNotFound("S3 object does not exist")
            elif operation == "HeadObject" and (
                facts.error_code in _CHECKSUM_MODE_UNSUPPORTED
            ):
                failure = _S3ChecksumModeUnsupported(
                    "S3 endpoint does not expose checksum-mode HEAD"
                )
            else:
                failure = classify_s3_error(
                    error,
                    operation=operation,
                    now_unix_ns=now_unix_ns,
                )
        if failure is not None:
            raise failure
        assert response is not None
        if not isinstance(response, Mapping):
            raise S3FatalError(f"S3 {operation} returned a non-mapping response")
        return response

    def _head(
        self,
        key: str,
        *,
        version_id: str | None,
        allow_missing: bool,
    ) -> Mapping[str, object] | None:
        base: dict[str, object] = {"Bucket": self._bucket, "Key": key}
        if version_id is not None:
            base["VersionId"] = version_id
        try:
            return self._invoke(
                "HeadObject",
                self._client.head_object,
                **base,
                ChecksumMode="ENABLED",
            )
        except _S3ChecksumModeUnsupported:
            try:
                return self._invoke(
                    "HeadObject",
                    self._client.head_object,
                    **base,
                )
            except _S3ObjectNotFound:
                if allow_missing:
                    return None
                raise S3StoredObjectMismatch(
                    "S3 object or provider version to verify does not exist"
                ) from None
        except _S3ObjectNotFound:
            if allow_missing:
                return None
            raise S3StoredObjectMismatch(
                "S3 object or provider version to verify does not exist"
            ) from None

    def _existing_result(
        self,
        source: ArchiveObjectSource,
        *,
        key: str,
        resumed: bool,
    ) -> PutResult | None:
        head = self._head(key, version_id=None, allow_missing=True)
        if head is None:
            return None
        version_id = _string_field(head, "VersionId", required=False)
        try:
            self.verify(
                key,
                source.size_bytes,
                source.sha256,
                provider_version_id=version_id,
            )
        except S3StoredObjectMismatch as error:
            raise S3ObjectConflict(
                "immutable S3 object key has a different stored identity"
            ) from error
        return PutResult(
            key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            created=False,
            resumed=resumed,
            provider_version_id=version_id,
        )

    @staticmethod
    def _load_journal(journal: MultipartJournal) -> ResumeState | None:
        try:
            checkpoint = journal.load()
        except ArchiveTargetError:
            raise
        except Exception:  # noqa: BLE001 - durable journal boundary
            raise S3CheckpointPersistenceError(
                "durable S3 multipart journal could not be loaded"
            ) from None
        if checkpoint is not None and type(checkpoint) is not ResumeState:
            raise S3CheckpointConflict("durable S3 multipart checkpoint is invalid")
        return checkpoint

    @staticmethod
    def _save_journal(
        journal: MultipartJournal,
        checkpoint: ResumeState,
        *,
        expected: ResumeState | None,
    ) -> None:
        try:
            journal.save(checkpoint, expected)
        except ArchiveTargetError:
            raise
        except Exception:  # noqa: BLE001 - durable journal boundary
            raise S3CheckpointPersistenceError(
                "durable S3 multipart checkpoint could not be saved"
            ) from None

    def _journal_for(
        self,
        source: ArchiveObjectSource,
        *,
        key: str,
    ) -> MultipartJournal:
        factory = self._journal_factory
        if factory is None:
            raise S3CheckpointPersistenceError(
                "multipart upload requires a durable journal factory"
            )
        try:
            journal = factory(source, key)
        except ArchiveTargetError:
            raise
        except Exception:  # noqa: BLE001 - durable journal boundary
            raise S3CheckpointPersistenceError(
                "durable S3 multipart journal could not be opened"
            ) from None
        if any(
            not callable(getattr(journal, method, None))
            for method in ("load", "save", "clear")
        ):
            raise S3CheckpointPersistenceError(
                "durable S3 multipart journal is invalid"
            )
        return journal

    @staticmethod
    def _clear_journal(
        journal: MultipartJournal,
        *,
        expected: ResumeState | None,
    ) -> None:
        try:
            journal.clear(expected)
        except ArchiveTargetError:
            raise
        except Exception:  # noqa: BLE001 - durable journal boundary
            raise S3CheckpointPersistenceError(
                "durable S3 multipart checkpoint could not be cleared"
            ) from None

    def _validate_source(self, source: ArchiveObjectSource) -> None:
        if type(source) is not ArchiveObjectSource:
            raise TypeError("source must be ArchiveObjectSource")
        try:
            observed = _hash_file(source.path)
        except OSError:
            raise S3CheckpointConflict(
                "S3 upload source identity could not be verified"
            ) from None
        if observed != (source.size_bytes, source.sha256):
            raise S3CheckpointConflict("S3 upload source identity does not match")

    def _probe_key(self) -> str:
        tail = f"_crypto_collector/probes/s3-no-replace-v1/{self.id}.bin"
        return f"{self._remote_prefix}/{tail}" if self._remote_prefix else tail

    def probe(self) -> TargetProbe:
        self._require_not_closed()
        key = self._probe_key()
        put_kwargs: dict[str, object] = {
            "Bucket": self._bucket,
            "Key": key,
            "Body": _PROBE_PAYLOAD,
            "ContentLength": len(_PROBE_PAYLOAD),
            "ChecksumSHA256": _PROBE_CHECKSUM,
            "IfNoneMatch": "*",
        }
        if self._storage_class is not None:
            put_kwargs["StorageClass"] = self._storage_class
        try:
            self._invoke("PutObject", self._client.put_object, **put_kwargs)
        except S3ObjectConflict:
            pass

        try:
            head = self._head(key, version_id=None, allow_missing=False)
        except S3StoredObjectMismatch:
            raise S3FatalError(
                "S3 no-replace capability marker disappeared after creation"
            ) from None
        assert head is not None
        version_id = _string_field(head, "VersionId", required=False)
        try:
            self.verify(
                key,
                len(_PROBE_PAYLOAD),
                _PROBE_SHA256,
                provider_version_id=version_id,
            )
        except S3StoredObjectMismatch:
            raise S3FatalError(
                "S3 no-replace capability marker has a different identity"
            ) from None

        try:
            self._invoke("PutObject", self._client.put_object, **put_kwargs)
        except S3ObjectConflict:
            pass
        else:
            raise S3FatalError("S3 endpoint ignored PutObject If-None-Match")

        create_kwargs: dict[str, object] = {
            "Bucket": self._bucket,
            "Key": key,
            "ChecksumAlgorithm": "SHA256",
        }
        if self._storage_class is not None:
            create_kwargs["StorageClass"] = self._storage_class
        created = self._invoke(
            "CreateMultipartUpload",
            self._client.create_multipart_upload,
            **create_kwargs,
        )
        checkpoint = ResumeState(
            upload_id=cast(
                str,
                _string_field(created, "UploadId", required=True),
            ),
            parts=(),
        )
        completion_rejected = False
        try:
            with io.BytesIO(_PROBE_PAYLOAD) as body:
                uploaded = self._invoke(
                    "UploadPart",
                    self._client.upload_part,
                    Bucket=self._bucket,
                    Key=key,
                    UploadId=checkpoint.upload_id,
                    PartNumber=1,
                    Body=body,
                    ContentLength=len(_PROBE_PAYLOAD),
                    ChecksumSHA256=_PROBE_CHECKSUM,
                )
            part_etag = cast(str, _string_field(uploaded, "ETag", required=True))
            try:
                self._invoke(
                    "CompleteMultipartUpload",
                    self._client.complete_multipart_upload,
                    Bucket=self._bucket,
                    Key=key,
                    UploadId=checkpoint.upload_id,
                    MultipartUpload={
                        "Parts": [
                            {
                                "PartNumber": 1,
                                "ETag": part_etag,
                                "ChecksumSHA256": _PROBE_CHECKSUM,
                            }
                        ]
                    },
                    IfNoneMatch="*",
                )
            except S3ObjectConflict:
                completion_rejected = True
        finally:
            self._abort_remote(checkpoint, key=key)
        if not completion_rejected:
            raise S3FatalError(
                "S3 endpoint ignored CompleteMultipartUpload If-None-Match"
            )
        return TargetProbe(
            target_id=self.id,
            target_type="s3",
            no_replace_capability="if_none_match_star",
            mount_identity=None,
        )

    def put(
        self,
        source: ArchiveObjectSource,
        key: str,
        resume: ResumeState | None = None,
        *,
        no_replace: bool = True,
    ) -> PutResult:
        self._require_not_closed()
        if no_replace is not True:
            raise ValueError("S3 archive target requires no_replace=True")
        key = _validate_object_key(key)
        if type(source) is not ArchiveObjectSource:
            raise TypeError("source must be ArchiveObjectSource")
        if resume is not None and type(resume) is not ResumeState:
            raise TypeError("resume must be ResumeState or None")
        multipart = source.size_bytes > self._multipart_size_bytes
        journal: MultipartJournal | None = None
        checkpoint: ResumeState | None = None
        if multipart:
            self._part_count(source)
            journal = self._journal_for(source, key=key)
            checkpoint = self._load_journal(journal)
            if checkpoint != resume:
                raise MultipartJournalConflict(
                    "requested resume state does not match the durable journal"
                )
            if checkpoint is not None:
                try:
                    self._validate_source(source)
                    self._validate_checkpoint_binding(checkpoint, source=source)
                except S3CheckpointConflict:
                    self._abort_and_clear(checkpoint, journal, key=key)
                    raise
            else:
                self._validate_source(source)
        else:
            self._validate_source(source)
            if resume is not None:
                raise S3CheckpointConflict(
                    "single PUT cannot consume a multipart resume state"
                )

        existing = self._existing_result(
            source,
            key=key,
            resumed=checkpoint is not None,
        )
        if existing is not None:
            if checkpoint is not None:
                assert journal is not None
                self._abort_and_clear(
                    checkpoint,
                    journal,
                    key=key,
                )
            return existing
        if not multipart:
            return self._put_single(source, key=key)
        assert journal is not None
        return self._put_multipart(
            source,
            key=key,
            journal=journal,
            checkpoint=checkpoint,
        )

    def _put_single(self, source: ArchiveObjectSource, *, key: str) -> PutResult:
        fd = os.open(source.path, _source_open_flags())
        try:
            body = os.fdopen(fd, "rb", closefd=True)
            fd = -1
            kwargs: dict[str, object] = {
                "Bucket": self._bucket,
                "Key": key,
                "Body": body,
                "ContentLength": source.size_bytes,
                "ChecksumSHA256": base64.b64encode(bytes.fromhex(source.sha256)).decode(
                    "ascii"
                ),
                "IfNoneMatch": "*",
            }
            if self._storage_class is not None:
                kwargs["StorageClass"] = self._storage_class
            try:
                response = self._invoke(
                    "PutObject",
                    self._client.put_object,
                    **kwargs,
                )
            except S3ObjectConflict:
                existing = self._existing_result(
                    source,
                    key=key,
                    resumed=False,
                )
                if existing is None:
                    raise S3RetryableError(
                        "S3 conditional create conflicted without a visible object",
                        operation="PutObject",
                        status_code=412,
                        error_code="PreconditionFailed",
                        retry_after_ns=None,
                    ) from None
                return existing
            finally:
                body.close()
        finally:
            if fd >= 0:
                os.close(fd)
        try:
            _string_field(response, "ETag", required=True)
            version_id = _string_field(
                response,
                "VersionId",
                required=False,
            )
        except S3FatalError:
            raise S3RetryableError(
                "S3 PutObject returned incomplete commit evidence",
                operation="PutObject",
                status_code=None,
                error_code=None,
                retry_after_ns=None,
            ) from None
        return PutResult(
            key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            created=True,
            resumed=False,
            provider_version_id=version_id,
        )

    def _part_count(self, source: ArchiveObjectSource) -> int:
        count = (
            source.size_bytes + self._multipart_size_bytes - 1
        ) // self._multipart_size_bytes
        if count > _MAX_MULTIPART_PARTS:
            raise S3FatalError("S3 multipart upload exceeds 10000 parts")
        return count

    def _part_identity(
        self,
        source: ArchiveObjectSource,
        *,
        part_number: int,
    ) -> tuple[int, str]:
        part_count = self._part_count(source)
        if not 1 <= part_number <= part_count:
            raise S3CheckpointConflict("multipart checkpoint part number is invalid")
        offset = (part_number - 1) * self._multipart_size_bytes
        size = min(self._multipart_size_bytes, source.size_bytes - offset)
        try:
            checksum = _hash_range(source.path, offset=offset, size=size)
        except OSError:
            raise S3CheckpointConflict(
                "S3 upload source changed while binding multipart parts"
            ) from None
        return size, checksum

    def _validate_checkpoint_binding(
        self,
        checkpoint: ResumeState,
        *,
        source: ArchiveObjectSource,
    ) -> None:
        for part in checkpoint.parts:
            expected_size, expected_checksum = self._part_identity(
                source,
                part_number=part.part_number,
            )
            if part.size_bytes != expected_size or (
                part.checksum is not None
                and not hmac.compare_digest(part.checksum, expected_checksum)
            ):
                raise S3CheckpointConflict(
                    "durable S3 multipart part identity does not match the source"
                )

    def _new_multipart(
        self,
        source: ArchiveObjectSource,
        *,
        key: str,
        journal: MultipartJournal,
    ) -> ResumeState:
        kwargs: dict[str, object] = {
            "Bucket": self._bucket,
            "Key": key,
            "ChecksumAlgorithm": "SHA256",
        }
        if self._storage_class is not None:
            kwargs["StorageClass"] = self._storage_class
        response = self._invoke(
            "CreateMultipartUpload",
            self._client.create_multipart_upload,
            **kwargs,
        )
        upload_id = cast(str, _string_field(response, "UploadId", required=True))
        checkpoint = ResumeState(
            upload_id=upload_id,
            parts=(),
        )
        try:
            self._save_journal(
                journal,
                checkpoint,
                expected=None,
            )
        except ArchiveTargetError:
            abort_error: ArchiveTargetError | None = None
            try:
                self._abort_remote(checkpoint, key=key)
            except ArchiveTargetError as error:
                abort_error = error
            if abort_error is not None:
                try:
                    self._save_journal(
                        journal,
                        checkpoint,
                        expected=None,
                    )
                except ArchiveTargetError:
                    pass
                raise abort_error from None
            raise
        return checkpoint

    def _list_parts(
        self,
        checkpoint: ResumeState,
        *,
        key: str,
    ) -> tuple[_RemotePart, ...]:
        marker = 0
        observed: dict[int, _RemotePart] = {}
        while True:
            kwargs: dict[str, object] = {
                "Bucket": self._bucket,
                "Key": key,
                "UploadId": checkpoint.upload_id,
                "MaxParts": 1000,
            }
            if marker:
                kwargs["PartNumberMarker"] = marker
            response = self._invoke(
                "ListParts",
                self._client.list_parts,
                **kwargs,
            )
            raw_parts = response.get("Parts", [])
            if not isinstance(raw_parts, list):
                raise S3FatalError("S3 ListParts response has invalid Parts")
            for raw in raw_parts:
                if not isinstance(raw, Mapping):
                    raise S3FatalError("S3 ListParts response has an invalid part")
                number = raw.get("PartNumber")
                size = raw.get("Size")
                etag = raw.get("ETag")
                if (
                    type(number) is not int
                    or number <= marker
                    or number in observed
                    or type(size) is not int
                    or size <= 0
                    or type(etag) is not str
                    or not etag
                ):
                    raise S3FatalError("S3 ListParts response is inconsistent")
                checksum_value = raw.get("ChecksumSHA256")
                checksum = checksum_value if type(checksum_value) is str else None
                observed[number] = _RemotePart(number, etag, size, checksum)
            truncated = response.get("IsTruncated", False)
            if type(truncated) is not bool:
                raise S3FatalError("S3 ListParts truncation marker is invalid")
            if not truncated:
                return tuple(observed[number] for number in sorted(observed))
            next_marker = response.get("NextPartNumberMarker")
            if type(next_marker) is not int or next_marker <= marker:
                raise S3FatalError("S3 ListParts pagination did not advance")
            marker = next_marker

    def _abort_remote(self, checkpoint: ResumeState, *, key: str) -> None:
        try:
            self._invoke(
                "AbortMultipartUpload",
                self._client.abort_multipart_upload,
                Bucket=self._bucket,
                Key=key,
                UploadId=checkpoint.upload_id,
            )
        except _S3UploadNotFound:
            return
        except S3RetryableError as error:
            raise S3AbortError(
                "S3 multipart upload could not be aborted",
                operation="AbortMultipartUpload",
                status_code=error.status_code,
                error_code=error.error_code,
                retry_after_ns=error.retry_after_ns,
            ) from None
        except ArchiveTargetError:
            raise S3FatalAbortError("S3 multipart upload cannot be aborted") from None

    def _abort_and_clear(
        self,
        checkpoint: ResumeState,
        journal: MultipartJournal,
        *,
        key: str,
    ) -> None:
        self._abort_remote(checkpoint, key=key)
        self._clear_journal(
            journal,
            expected=checkpoint,
        )

    def _reconcile(
        self,
        source: ArchiveObjectSource,
        *,
        key: str,
        checkpoint: ResumeState,
        journal: MultipartJournal,
    ) -> tuple[ResumeState, bool]:
        try:
            remote_parts = self._list_parts(checkpoint, key=key)
        except _S3UploadNotFound:
            self._clear_journal(
                journal,
                expected=checkpoint,
            )
            return self._new_multipart(
                source,
                key=key,
                journal=journal,
            ), False
        local = {part.part_number: part for part in checkpoint.parts}
        reusable: dict[int, MultipartPartV1] = {}
        for remote in remote_parts:
            try:
                expected_size, expected_checksum = self._part_identity(
                    source,
                    part_number=remote.part_number,
                )
            except S3CheckpointConflict:
                self._abort_and_clear(checkpoint, journal, key=key)
                raise S3CheckpointConflict(
                    "remote S3 multipart upload contains an impossible part"
                ) from None
            decoded_remote_checksum = _strict_base64_sha256(remote.checksum_sha256)
            remote_matches = (
                remote.size_bytes == expected_size
                and remote.checksum_sha256 is not None
                and decoded_remote_checksum is not None
                and hmac.compare_digest(
                    remote.checksum_sha256,
                    expected_checksum,
                )
            )
            local_part = local.get(remote.part_number)
            remote_explicitly_differs = remote.size_bytes != expected_size or (
                decoded_remote_checksum is not None
                and remote.checksum_sha256 is not None
                and not hmac.compare_digest(
                    remote.checksum_sha256,
                    expected_checksum,
                )
            )
            if local_part is not None and remote_explicitly_differs:
                self._abort_and_clear(checkpoint, journal, key=key)
                raise S3CheckpointConflict(
                    "remote S3 multipart part diverges from its durable checkpoint"
                )
            if remote_matches:
                reusable[remote.part_number] = MultipartPartV1(
                    part_number=remote.part_number,
                    etag=remote.etag,
                    size_bytes=remote.size_bytes,
                    checksum=expected_checksum,
                )
        reconciled = ResumeState(
            upload_id=checkpoint.upload_id,
            parts=tuple(reusable[number] for number in sorted(reusable)),
        )
        if reconciled != checkpoint:
            self._save_journal(
                journal,
                reconciled,
                expected=checkpoint,
            )
        return reconciled, True

    def _upload_part(
        self,
        source: ArchiveObjectSource,
        *,
        key: str,
        checkpoint: ResumeState,
        part_number: int,
    ) -> MultipartPartV1:
        size, checksum = self._part_identity(source, part_number=part_number)
        offset = (part_number - 1) * self._multipart_size_bytes
        with _FileSlice(source.path, offset=offset, size=size) as body:
            response = self._invoke(
                "UploadPart",
                self._client.upload_part,
                Bucket=self._bucket,
                Key=key,
                UploadId=checkpoint.upload_id,
                PartNumber=part_number,
                Body=body,
                ContentLength=size,
                ChecksumSHA256=checksum,
            )
        try:
            etag = cast(str, _string_field(response, "ETag", required=True))
        except S3FatalError:
            raise S3RetryableError(
                "S3 UploadPart returned incomplete commit evidence",
                operation="UploadPart",
                status_code=None,
                error_code=None,
                retry_after_ns=None,
            ) from None
        returned_checksum = response.get("ChecksumSHA256")
        if returned_checksum is not None and (
            type(returned_checksum) is not str
            or _strict_base64_sha256(returned_checksum) is None
            or not hmac.compare_digest(returned_checksum, checksum)
        ):
            raise S3RetryableError(
                "S3 UploadPart returned inconsistent commit evidence",
                operation="UploadPart",
                status_code=None,
                error_code=None,
                retry_after_ns=None,
            )
        return MultipartPartV1(
            part_number=part_number,
            etag=etag,
            size_bytes=size,
            checksum=checksum,
        )

    def _upload_missing_parts(
        self,
        source: ArchiveObjectSource,
        *,
        key: str,
        checkpoint: ResumeState,
        journal: MultipartJournal,
    ) -> ResumeState:
        part_count = self._part_count(source)
        parts = {part.part_number: part for part in checkpoint.parts}
        missing = [number for number in range(1, part_count + 1) if number not in parts]
        selected_error: BaseException | None = None
        selected_priority = -1
        selected_part_number = _MAX_MULTIPART_PARTS + 1
        futures: dict[Future[MultipartPartV1], int] = {}
        remaining = iter(missing)

        def error_priority(error: BaseException) -> int:
            if isinstance(error, MultipartJournalConflict):
                return 4
            if isinstance(error, S3CheckpointConflict):
                return 3
            if isinstance(error, RetryableTargetError):
                return 1
            return 2

        def submit_next(executor: ThreadPoolExecutor) -> bool:
            try:
                part_number = next(remaining)
            except StopIteration:
                return False
            future = executor.submit(
                self._upload_part,
                source,
                key=key,
                checkpoint=checkpoint,
                part_number=part_number,
            )
            futures[future] = part_number
            return True

        with ThreadPoolExecutor(
            max_workers=self._concurrency,
            thread_name_prefix=f"archive-s3-{self.id}",
        ) as executor:
            while len(futures) < self._concurrency and submit_next(executor):
                pass
            while futures:
                completed, _pending = wait(futures, return_when=FIRST_COMPLETED)
                for future in sorted(completed, key=futures.__getitem__):
                    part_number = futures.pop(future)
                    try:
                        part = future.result()
                        expected = checkpoint
                        updated_parts = dict(parts)
                        updated_parts[part.part_number] = part
                        updated = ResumeState(
                            upload_id=checkpoint.upload_id,
                            parts=tuple(
                                updated_parts[number]
                                for number in sorted(updated_parts)
                            ),
                        )
                        self._save_journal(
                            journal,
                            updated,
                            expected=expected,
                        )
                        parts = updated_parts
                        checkpoint = updated
                    except Exception as error:  # noqa: BLE001 - worker/provider boundary
                        priority = error_priority(error)
                        if priority > selected_priority or (
                            priority == selected_priority
                            and part_number < selected_part_number
                        ):
                            selected_error = error
                            selected_priority = priority
                            selected_part_number = part_number
                if selected_error is None:
                    while len(futures) < self._concurrency and submit_next(executor):
                        pass
        if selected_error is not None:
            if isinstance(selected_error, MultipartJournalConflict):
                raise selected_error
            if isinstance(selected_error, S3CheckpointConflict):
                self._abort_and_clear(checkpoint, journal, key=key)
                raise selected_error
            if isinstance(selected_error, _S3UploadNotFound):
                self._clear_journal(journal, expected=checkpoint)
                raise S3RetryableError(
                    "S3 multipart upload disappeared while uploading a part",
                    operation="UploadPart",
                    status_code=404,
                    error_code="NoSuchUpload",
                    retry_after_ns=None,
                ) from None
            raise selected_error
        return checkpoint

    def _complete(
        self,
        source: ArchiveObjectSource,
        *,
        key: str,
        checkpoint: ResumeState,
    ) -> Mapping[str, object]:
        expected_numbers = tuple(range(1, self._part_count(source) + 1))
        observed_numbers = tuple(part.part_number for part in checkpoint.parts)
        if observed_numbers != expected_numbers:
            raise S3CheckpointConflict(
                "multipart completion requires every source part exactly once"
            )
        request_parts: list[dict[str, object]] = []
        for part in checkpoint.parts:
            if part.checksum is None:
                raise S3CheckpointConflict(
                    "multipart completion requires a durable part checksum"
                )
            request_parts.append(
                {
                    "PartNumber": part.part_number,
                    "ETag": part.etag,
                    "ChecksumSHA256": part.checksum,
                }
            )
        return self._invoke(
            "CompleteMultipartUpload",
            self._client.complete_multipart_upload,
            Bucket=self._bucket,
            Key=key,
            UploadId=checkpoint.upload_id,
            MultipartUpload={"Parts": request_parts},
            IfNoneMatch="*",
        )

    def _put_multipart(
        self,
        source: ArchiveObjectSource,
        *,
        key: str,
        journal: MultipartJournal,
        checkpoint: ResumeState | None,
    ) -> PutResult:
        resumed = False
        if checkpoint is None:
            checkpoint = self._new_multipart(source, key=key, journal=journal)
        else:
            checkpoint, resumed = self._reconcile(
                source,
                key=key,
                checkpoint=checkpoint,
                journal=journal,
            )
        checkpoint = self._upload_missing_parts(
            source,
            key=key,
            checkpoint=checkpoint,
            journal=journal,
        )
        try:
            self._validate_source(source)
        except S3CheckpointConflict:
            self._abort_and_clear(checkpoint, journal, key=key)
            raise
        try:
            response = self._complete(source, key=key, checkpoint=checkpoint)
        except S3ObjectConflict:
            self._abort_and_clear(checkpoint, journal, key=key)
            existing = self._existing_result(
                source,
                key=key,
                resumed=resumed,
            )
            if existing is None:
                raise S3RetryableError(
                    "S3 multipart conditional create conflicted without a visible object",
                    operation="CompleteMultipartUpload",
                    status_code=412,
                    error_code="PreconditionFailed",
                    retry_after_ns=None,
                ) from None
            return existing
        except S3RetryableError as error:
            if (
                error.status_code == 409
                or error.error_code == "ConditionalRequestConflict"
            ):
                self._abort_and_clear(checkpoint, journal, key=key)
            raise
        except _S3UploadNotFound:
            existing = self._existing_result(
                source,
                key=key,
                resumed=resumed,
            )
            if existing is not None:
                self._clear_journal(
                    journal,
                    expected=checkpoint,
                )
                return existing
            self._clear_journal(
                journal,
                expected=checkpoint,
            )
            raise S3RetryableError(
                "S3 multipart upload disappeared before completion",
                operation="CompleteMultipartUpload",
                status_code=404,
                error_code="NoSuchUpload",
                retry_after_ns=None,
            ) from None
        try:
            _string_field(response, "ETag", required=True)
            version_id = _string_field(
                response,
                "VersionId",
                required=False,
            )
        except S3FatalError:
            raise S3RetryableError(
                "S3 CompleteMultipartUpload returned incomplete commit evidence",
                operation="CompleteMultipartUpload",
                status_code=None,
                error_code=None,
                retry_after_ns=None,
            ) from None
        self._clear_journal(journal, expected=checkpoint)
        return PutResult(
            key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            created=True,
            resumed=resumed,
            provider_version_id=version_id,
        )

    def verify(
        self,
        key: str,
        expected_size: int,
        expected_sha256: str,
        *,
        provider_version_id: str | None = None,
    ) -> VerifyResult:
        self._require_not_closed()
        key = _validate_object_key(key)
        if type(expected_size) is not int or expected_size <= 0:
            raise ValueError("expected_size must be positive")
        if (
            type(expected_sha256) is not str
            or _SHA256.fullmatch(expected_sha256) is None
        ):
            raise ValueError("expected_sha256 is invalid")
        _validate_version_id(provider_version_id)
        head = self._head(
            key,
            version_id=provider_version_id,
            allow_missing=False,
        )
        assert head is not None
        reported_version = _string_field(
            head,
            "VersionId",
            required=False,
        )
        if provider_version_id is not None and reported_version != provider_version_id:
            raise S3StoredObjectMismatch(
                "S3 HEAD did not bind the requested provider version"
            )
        effective_version = provider_version_id or reported_version
        reported_size = head.get("ContentLength")
        checksum_bytes = _strict_base64_sha256(head.get("ChecksumSHA256"))
        if (
            type(reported_size) is int
            and reported_size == expected_size
            and head.get("ChecksumType") == "FULL_OBJECT"
            and checksum_bytes is not None
            and hmac.compare_digest(checksum_bytes, bytes.fromhex(expected_sha256))
        ):
            provider = ProviderChecksumV1(
                algorithm="sha256",
                checksum_type="full_object",
                value=expected_sha256,
            )
            return VerifyResult(
                key=key,
                size_bytes=expected_size,
                sha256=expected_sha256,
                method="provider_full_object_sha256",
                level=ArchiveVerificationLevel.STORED_SHA256,
                provider_checksum=provider,
                provider_version_id=effective_version,
                verified=True,
                cleanup_strong=True,
            )
        observed_size, observed_sha = self._readback_identity(
            key,
            version_id=effective_version,
        )
        if observed_size != expected_size or not hmac.compare_digest(
            observed_sha,
            expected_sha256,
        ):
            raise S3StoredObjectMismatch(
                "S3 streamed readback does not match the expected stored identity"
            )
        return VerifyResult(
            key=key,
            size_bytes=observed_size,
            sha256=observed_sha,
            method="readback_sha256",
            level=ArchiveVerificationLevel.STORED_SHA256,
            provider_checksum=None,
            provider_version_id=effective_version,
            verified=True,
            cleanup_strong=True,
        )

    def open_reader(
        self,
        key: str,
        *,
        provider_version_id: str | None = None,
    ) -> IO[bytes]:
        self._require_not_closed()
        key = _validate_object_key(key)
        _validate_version_id(provider_version_id)
        kwargs: dict[str, object] = {"Bucket": self._bucket, "Key": key}
        if provider_version_id is not None:
            kwargs["VersionId"] = provider_version_id
        try:
            response = self._invoke(
                "GetObject",
                self._client.get_object,
                **kwargs,
            )
        except _S3ObjectNotFound:
            raise S3StoredObjectMismatch(
                "S3 object or provider version to read does not exist"
            ) from None
        body = response.get("Body")
        read = getattr(body, "read", None)
        close = getattr(body, "close", None)
        if not callable(read) or not callable(close):
            _close_body_quietly(body)
            raise S3FatalError("S3 GetObject response has no readable body")
        reported_version = _string_field(
            response,
            "VersionId",
            required=False,
        )
        if provider_version_id is not None and reported_version != provider_version_id:
            _close_body_quietly(body)
            raise S3StoredObjectMismatch(
                "S3 GET did not bind the requested provider version"
            )
        return cast(IO[bytes], body)

    def _readback_identity(
        self,
        key: str,
        *,
        version_id: str | None,
    ) -> tuple[int, str]:
        body = self.open_reader(key, provider_version_id=version_id)
        read = body.read
        digest = hashlib.sha256()
        size = 0
        primary_error: BaseException | None = None
        try:
            while True:
                read_failure: ArchiveTargetError | None = None
                chunk: object | None = None
                try:
                    chunk = read(_READ_CHUNK_BYTES)
                except Exception as error:  # noqa: BLE001 - streaming SDK boundary
                    read_failure = classify_s3_error(
                        error,
                        operation="GetObjectBody",
                        now_unix_ns=self._now_unix_ns(),
                    )
                if read_failure is not None:
                    raise read_failure
                if not chunk:
                    break
                if type(chunk) is not bytes:
                    raise S3FatalError("S3 GetObject body returned non-bytes data")
                digest.update(chunk)
                size += len(chunk)
        except BaseException as error:
            primary_error = error
            raise
        finally:
            close = getattr(body, "close", None)
            if callable(close):
                close_failed = False
                try:
                    close()
                except Exception:  # noqa: BLE001 - streaming SDK boundary
                    close_failed = True
                if close_failed and primary_error is None:
                    raise S3RetryableError(
                        "S3 GetObject body could not be closed",
                        operation="GetObjectBodyClose",
                        status_code=None,
                        error_code=None,
                        retry_after_ns=None,
                    )
        return size, digest.hexdigest()

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        close = getattr(self._client, "close", None)
        if not callable(close):
            return
        try:
            close()
        except Exception:  # noqa: BLE001 - provider boundary
            raise S3FatalError("S3 client could not be closed") from None

    def __enter__(self) -> Self:
        self._require_not_closed()
        return self

    def __exit__(self, *_ignored: object) -> None:
        self.close()


def _default_client_factory(**kwargs: object) -> S3Client:
    import boto3  # type: ignore[import-untyped]

    return cast(S3Client, boto3.client("s3", **kwargs))


def _reveal_once(secrets: SecretSnapshotPort, reference: SecretRef) -> str:
    value = secrets.value_for(reference)
    if type(value) is not SecretValue:
        raise TypeError("secret snapshot returned an invalid value")
    return value.reveal()


def _construct_client(
    config: S3TargetConfig,
    *,
    secrets: SecretSnapshotPort,
    client_factory: S3ClientFactory,
) -> S3Client:
    credentials = config.credentials
    access_key = _reveal_once(secrets, credentials.access_key_id)
    secret_key = _reveal_once(secrets, credentials.secret_access_key)
    session_token = (
        None
        if credentials.session_token is None
        else _reveal_once(secrets, credentials.session_token)
    )
    client_kwargs: dict[str, Any] = {
        "endpoint_url": config.endpoint,
        "region_name": config.region,
        "aws_access_key_id": access_key,
        "aws_secret_access_key": secret_key,
        "config": Config(
            signature_version="s3v4",
            s3={"addressing_style": config.addressing_style},
            max_pool_connections=config.concurrency,
            retries={"mode": "standard", "total_max_attempts": 1},
        ),
    }
    if session_token is not None:
        client_kwargs["aws_session_token"] = session_token
    return client_factory(**client_kwargs)


def build_s3_target(
    config: S3TargetConfig,
    *,
    secrets: SecretSnapshot | SecretSnapshotPort,
    journal_factory: MultipartJournalFactory | None = None,
    client_factory: S3ClientFactory = _default_client_factory,
    now_unix_ns: Callable[[], int] = time.time_ns,
) -> S3Target:
    if type(config) is not S3TargetConfig:
        raise TypeError("config must be S3TargetConfig")
    if not hasattr(secrets, "value_for"):
        raise TypeError("secrets must be a SecretSnapshot")
    if not callable(client_factory):
        raise TypeError("client_factory must be callable")
    if journal_factory is not None and not callable(journal_factory):
        raise TypeError("journal_factory must be callable or None")
    client: S3Client | None = None
    try:
        client = _construct_client(
            config,
            secrets=secrets,
            client_factory=client_factory,
        )
    except Exception:  # noqa: BLE001, S110 - redact SDK construction failure
        pass
    if client is None:
        raise S3FatalError("S3 client construction failed")
    return S3Target(
        target_id=config.id,
        bucket=config.bucket,
        remote_prefix=config.prefix,
        addressing_style=config.addressing_style,
        storage_class=config.storage_class,
        multipart_size_bytes=config.multipart_size_bytes,
        concurrency=config.concurrency,
        client=client,
        journal_factory=journal_factory,
        now_unix_ns=now_unix_ns,
    )


__all__ = [
    "S3AbortError",
    "S3CheckpointConflict",
    "S3CheckpointPersistenceError",
    "S3FatalAbortError",
    "S3FatalError",
    "S3ObjectConflict",
    "S3RetryableError",
    "S3StoredObjectMismatch",
    "S3Target",
    "build_s3_target",
    "classify_s3_error",
]
