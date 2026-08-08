from __future__ import annotations

import hashlib
import io
import logging
import math
import os
import re
import stat
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from enum import StrEnum
from functools import partial
from typing import IO, Literal, NoReturn, Protocol, Self, cast

from crypto_collector.archive.models import (
    ArchiveVerificationLevel,
    MultipartPartV1,
)
from crypto_collector.archive.receipt import ProviderChecksumV1
from crypto_collector.archive.state import (
    ArchiveTargetError,
    ExistingObjectMismatch,
    StoredObjectMismatch,
)
from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    MultipartJournal,
    MultipartJournalFactory,
    PutResult,
    ResumeState,
    TargetClosed,
    TargetProbe,
    TargetUnavailable,
    TargetVerificationError,
    UnsafeObjectKey,
    VerifyResult,
)
from crypto_collector.config.models import AliyunOssTargetConfig
from crypto_collector.config.primitives import SecretRef, SecretSnapshot, SecretValue
from crypto_collector.network.retry import parse_retry_after_ns
from crypto_collector.storage.raw_writer import open_readonly_nofollow

_CRC64_MASK = 2**64 - 1
_CRC64_REVERSED_POLYNOMIAL = 0xC96C5795D7870F42
_MAX_MULTIPART_PARTS = 10_000
_MAX_MULTIPART_CONCURRENCY = 32
_MAX_LIST_PART_PAGES = 100
_MAX_CRC_EVIDENCE = 1024
_READ_CHUNK_BYTES = 1024 * 1024
_SAFE_PROVIDER_CODE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_RETRYABLE_STATUSES = frozenset({408, 425, 429, 500, 502, 503, 504})
_RETRYABLE_CODES = frozenset(
    {
        "InternalError",
        "OperationAborted",
        "RequestTimeout",
        "ServerBusy",
        "ServiceUnavailable",
        "SlowDown",
        "TooManyRequests",
    }
)
_EXISTING_CODES = frozenset(
    {
        "FileAlreadyExists",
        "ObjectAlreadyExists",
        "PreconditionFailed",
    }
)
_NO_SUCH_UPLOAD_CODES = frozenset({"NoSuchUpload"})
_OSS_SDK_LOGGER_NAMES = frozenset(
    {
        "oss2",
        "oss2.api",
        "oss2.auth",
        "oss2.credentials",
        "oss2.http",
        "oss2.models",
        "oss2.utils",
    }
)
_MISSING = object()


class _DropOssSdkLogs(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        del record
        return False


_OSS_SDK_LOG_FILTER = _DropOssSdkLogs()


def _install_oss_sdk_log_safety() -> None:
    names = set(_OSS_SDK_LOGGER_NAMES)
    names.update(
        name
        for name in logging.Logger.manager.loggerDict
        if name == "oss2" or name.startswith("oss2.")
    )
    for name in names:
        logger = logging.getLogger(name)
        if _OSS_SDK_LOG_FILTER not in logger.filters:
            logger.addFilter(_OSS_SDK_LOG_FILTER)


def _crc64_table() -> tuple[int, ...]:
    values: list[int] = []
    for byte in range(256):
        current = byte
        for _ in range(8):
            current = (
                (current >> 1) ^ _CRC64_REVERSED_POLYNOMIAL
                if current & 1
                else current >> 1
            )
        values.append(current & _CRC64_MASK)
    return tuple(values)


_CRC64_TABLE = _crc64_table()


class _Crc64Ecma:
    __slots__ = ("_value",)

    def __init__(self) -> None:
        self._value = _CRC64_MASK

    def update(self, data: bytes) -> None:
        value = self._value
        for byte in data:
            value = _CRC64_TABLE[(value ^ byte) & 0xFF] ^ (value >> 8)
        self._value = value

    def digest(self) -> int:
        return self._value ^ _CRC64_MASK


def crc64_ecma(data: bytes) -> int:
    if type(data) is not bytes:
        raise TypeError("data must be bytes")
    checksum = _Crc64Ecma()
    checksum.update(data)
    return checksum.digest()


class OssProviderErrorKind(StrEnum):
    TRANSPORT = "transport"
    SERVICE = "service"
    INCONSISTENT = "inconsistent"


def _provider_code(value: str | None) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _SAFE_PROVIDER_CODE.fullmatch(value) is None:
        return "UnknownProviderError"
    return value


class OssProviderError(Exception):
    __slots__ = ("code", "kind", "operation", "retry_after", "status")

    operation: str
    kind: OssProviderErrorKind
    status: int | None
    code: str | None
    retry_after: str | None

    def __init__(
        self,
        *,
        operation: str,
        kind: OssProviderErrorKind,
        status: int | None,
        code: str | None,
        retry_after: str | None,
        unsafe_message: str | None = None,
    ) -> None:
        del unsafe_message
        if type(operation) is not str or not operation:
            raise ValueError("operation must be a nonempty string")
        if type(kind) is not OssProviderErrorKind:
            raise TypeError("kind must be OssProviderErrorKind")
        if status is not None and type(status) is not int:
            raise TypeError("status must be an integer or None")
        if retry_after is not None and type(retry_after) is not str:
            raise TypeError("retry_after must be a string or None")
        self.operation = operation
        self.kind = kind
        self.status = status
        self.code = _provider_code(code)
        self.retry_after = retry_after
        super().__init__(self._safe_message())

    def _safe_message(self) -> str:
        status = "none" if self.status is None else str(self.status)
        code = self.code or "none"
        return (
            f"Aliyun OSS {self.operation} failed "
            f"(kind={self.kind.value}, status={status}, code={code})"
        )

    def __repr__(self) -> str:
        return f"OssProviderError({self._safe_message()!r})"

    @classmethod
    def transport(cls, *, operation: str) -> Self:
        return cls(
            operation=operation,
            kind=OssProviderErrorKind.TRANSPORT,
            status=None,
            code=None,
            retry_after=None,
        )

    @classmethod
    def inconsistent(cls, *, operation: str) -> Self:
        return cls(
            operation=operation,
            kind=OssProviderErrorKind.INCONSISTENT,
            status=None,
            code="InconsistentError",
            retry_after=None,
        )

    @classmethod
    def service(
        cls,
        *,
        operation: str,
        status: int,
        code: str,
        retry_after: str | None = None,
        unsafe_message: str | None = None,
    ) -> Self:
        return cls(
            operation=operation,
            kind=OssProviderErrorKind.SERVICE,
            status=status,
            code=code,
            retry_after=retry_after,
            unsafe_message=unsafe_message,
        )


class OssTargetUnavailable(TargetUnavailable):
    __slots__ = ("error_code", "operation", "retry_after_ns", "status")

    def __init__(
        self,
        *,
        operation: str,
        status: int | None,
        error_code: str | None,
        retry_after_ns: int | None,
    ) -> None:
        self.operation = operation
        self.status = status
        self.error_code = error_code
        self.retry_after_ns = retry_after_ns
        status_text = "none" if status is None else str(status)
        code_text = error_code or "none"
        super().__init__(
            f"Aliyun OSS {operation} is retryable "
            f"(status={status_text}, code={code_text})"
        )


class OssBusinessError(ArchiveTargetError):
    __slots__ = ("error_code", "operation", "status")

    def __init__(
        self,
        *,
        operation: str,
        status: int | None,
        error_code: str | None,
    ) -> None:
        self.operation = operation
        self.status = status
        self.error_code = error_code
        status_text = "none" if status is None else str(status)
        code_text = error_code or "none"
        super().__init__(
            f"Aliyun OSS {operation} was rejected "
            f"(status={status_text}, code={code_text})"
        )


@dataclass(frozen=True, slots=True)
class OssRemotePart:
    part_number: int
    etag: str
    size_bytes: int
    crc64: int | None

    def __post_init__(self) -> None:
        if type(self.part_number) is not int or self.part_number <= 0:
            raise ValueError("part_number must be positive")
        if type(self.etag) is not str or not self.etag:
            raise ValueError("etag must be a nonempty string")
        if type(self.size_bytes) is not int or self.size_bytes <= 0:
            raise ValueError("size_bytes must be positive")
        if self.crc64 is not None and (
            type(self.crc64) is not int or not 0 <= self.crc64 <= _CRC64_MASK
        ):
            raise ValueError("crc64 must be an unsigned 64-bit integer or None")


@dataclass(frozen=True, slots=True)
class OssPartPage:
    parts: tuple[OssRemotePart, ...]
    is_truncated: bool
    next_marker: str

    def __post_init__(self) -> None:
        if any(type(part) is not OssRemotePart for part in self.parts):
            raise TypeError("parts must contain OssRemotePart values")
        if type(self.is_truncated) is not bool:
            raise TypeError("is_truncated must be bool")
        if type(self.next_marker) is not str:
            raise TypeError("next_marker must be a string")
        if self.is_truncated and not self.next_marker:
            raise ValueError("truncated part pages require a next marker")


@dataclass(frozen=True, slots=True)
class OssUploadResult:
    etag: str
    crc64: int
    provider_version_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.etag) is not str or not self.etag:
            raise ValueError("etag must be a nonempty string")
        if type(self.crc64) is not int or not 0 <= self.crc64 <= _CRC64_MASK:
            raise ValueError("crc64 must be an unsigned 64-bit integer")
        if self.provider_version_id is not None and (
            type(self.provider_version_id) is not str or not self.provider_version_id
        ):
            raise ValueError("provider_version_id must be nonempty or None")


@dataclass(frozen=True, slots=True)
class OssObjectMetadata:
    size_bytes: int
    crc64: int | None
    provider_version_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.size_bytes) is not int or self.size_bytes < 0:
            raise ValueError("size_bytes must be nonnegative")
        if self.crc64 is not None and (
            type(self.crc64) is not int or not 0 <= self.crc64 <= _CRC64_MASK
        ):
            raise ValueError("crc64 must be an unsigned 64-bit integer or None")
        if self.provider_version_id is not None and (
            type(self.provider_version_id) is not str or not self.provider_version_id
        ):
            raise ValueError("provider_version_id must be nonempty or None")


class OssTransport(Protocol):
    def init_multipart(self, key: str, *, headers: dict[str, str]) -> str: ...

    def list_parts(
        self,
        key: str,
        upload_id: str,
        *,
        marker: str,
    ) -> OssPartPage: ...

    def upload_part(
        self,
        key: str,
        upload_id: str,
        part_number: int,
        data: Iterable[bytes],
        *,
        size_bytes: int,
    ) -> OssRemotePart: ...

    def complete_multipart(
        self,
        key: str,
        upload_id: str,
        parts: tuple[OssRemotePart, ...],
        *,
        headers: dict[str, str],
    ) -> OssUploadResult: ...

    def abort_multipart(self, key: str, upload_id: str) -> None: ...

    def put_object(
        self,
        key: str,
        data: Iterable[bytes],
        *,
        size_bytes: int,
        headers: dict[str, str],
    ) -> OssUploadResult: ...

    def head_object(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> OssObjectMetadata: ...

    def open_reader(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> IO[bytes]: ...


class _SdkInitResultLike(Protocol):
    upload_id: object


class _SdkPartLike(Protocol):
    part_number: int | str
    etag: str
    size: int | str
    part_crc: int | str | None


class _SdkPartPageLike(Protocol):
    parts: Iterable[_SdkPartLike]
    is_truncated: object
    next_marker: object


class _SdkUploadResultLike(Protocol):
    etag: str
    crc: int | str
    versionid: str | None


class _SdkHeadResultLike(Protocol):
    content_length: int | str
    server_crc: int | str | None
    versionid: str | None


class _SdkPartInfoFactory(Protocol):
    def __call__(
        self,
        part_number: int,
        etag: str,
        *,
        size: int,
        part_crc: int,
    ) -> object: ...


class _SdkBucketLike(Protocol):
    def init_multipart_upload(
        self,
        key: str,
        *,
        headers: dict[str, str],
    ) -> object: ...

    def list_parts(
        self,
        key: str,
        upload_id: str,
        *,
        marker: str,
        max_parts: int,
    ) -> object: ...

    def upload_part(
        self,
        key: str,
        upload_id: str,
        part_number: int,
        data: Iterable[bytes],
        *,
        headers: dict[str, str] | None,
    ) -> object: ...

    def complete_multipart_upload(
        self,
        key: str,
        upload_id: str,
        parts: list[object],
        *,
        headers: dict[str, str],
    ) -> object: ...

    def abort_multipart_upload(self, key: str, upload_id: str) -> object: ...

    def put_object(
        self,
        key: str,
        data: Iterable[bytes],
        *,
        headers: dict[str, str],
    ) -> object: ...

    def head_object(
        self,
        key: str,
        *,
        params: dict[str, str] | None,
    ) -> object: ...

    def get_object(
        self,
        key: str,
        *,
        params: dict[str, str] | None,
    ) -> object: ...


def _sdk_nonempty_text(value: object) -> str:
    if type(value) is not str or not value:
        raise TypeError("SDK value is not nonempty text")
    return value


def _sdk_optional_text(value: object) -> str | None:
    if value is None:
        return None
    return _sdk_nonempty_text(value)


def _sdk_int(value: object) -> int:
    if type(value) is not int:
        raise TypeError("SDK value is not an integer")
    return value


def _required_part_crc64(part: OssRemotePart) -> int:
    if part.crc64 is None:
        raise OssProviderError.inconsistent(operation="complete_multipart")
    return part.crc64


def _sdk_error(operation: str, error: BaseException) -> OssProviderError:
    try:
        import oss2.exceptions as oss_exceptions  # type: ignore[import-untyped]
    except ImportError:
        return OssProviderError.transport(operation=operation)
    if isinstance(error, oss_exceptions.InconsistentError):
        return OssProviderError.inconsistent(operation=operation)
    if isinstance(error, oss_exceptions.RequestError):
        return OssProviderError.transport(operation=operation)
    if isinstance(error, oss_exceptions.OssError):
        headers = getattr(error, "headers", {})
        retry_after: str | None = None
        if hasattr(headers, "get"):
            observed = headers.get("Retry-After") or headers.get("retry-after")
            if type(observed) is str:
                retry_after = observed
        observed_status = getattr(error, "status", 0)
        status = observed_status if type(observed_status) is int else 0
        observed_code = getattr(error, "code", "UnknownProviderError")
        code = observed_code if type(observed_code) is str else "UnknownProviderError"
        return OssProviderError.service(
            operation=operation,
            status=status,
            code=code,
            retry_after=retry_after,
        )
    return OssProviderError.transport(operation=operation)


class _Oss2Transport:
    __slots__ = ("_bucket", "_part_info")

    def __init__(
        self,
        bucket: _SdkBucketLike,
        part_info: _SdkPartInfoFactory,
    ) -> None:
        self._bucket = bucket
        self._part_info = part_info

    @classmethod
    def build(
        cls,
        *,
        config: AliyunOssTargetConfig,
        access_key_id: SecretValue,
        access_key_secret: SecretValue,
        security_token: SecretValue | None,
    ) -> _Oss2Transport:
        result: _Oss2Transport | None = None
        failure: TargetUnavailable | None = None
        auth: object | None = None
        bucket: object | None = None
        try:
            import oss2  # type: ignore[import-untyped]

            _install_oss_sdk_log_safety()
            auth = (
                oss2.Auth(access_key_id.reveal(), access_key_secret.reveal())
                if security_token is None
                else oss2.StsAuth(
                    access_key_id.reveal(),
                    access_key_secret.reveal(),
                    security_token.reveal(),
                )
            )
            bucket = oss2.Bucket(
                auth,
                config.endpoint,
                config.bucket,
                enable_crc=True,
                region=config.region,
            )
            result = cls(
                cast(_SdkBucketLike, bucket),
                cast(_SdkPartInfoFactory, oss2.models.PartInfo),
            )
        except Exception:  # noqa: BLE001 - constructor errors may contain credentials.
            failure = TargetUnavailable("Aliyun OSS client construction failed")
        auth = None
        bucket = None
        if failure is not None:
            raise failure from None
        if result is None:
            raise TargetUnavailable("Aliyun OSS client construction failed")
        return result

    def _call(self, operation: str, callback: Callable[[], object]) -> object:
        result: object = _MISSING
        failure: OssProviderError | None = None
        try:
            result = callback()
        except ArchiveTargetError:
            raise
        except Exception as error:  # noqa: BLE001 - SDK boundary is normalized.
            failure = _sdk_error(operation, error)
        if failure is not None:
            raise failure from None
        return result

    def init_multipart(self, key: str, *, headers: dict[str, str]) -> str:
        result = self._call(
            "init_multipart",
            lambda: self._bucket.init_multipart_upload(key, headers=headers),
        )
        typed = cast(_SdkInitResultLike, result)
        upload_id = getattr(typed, "upload_id", None)
        if type(upload_id) is not str or not upload_id:
            raise OssProviderError.inconsistent(operation="init_multipart")
        return upload_id

    def list_parts(
        self,
        key: str,
        upload_id: str,
        *,
        marker: str,
    ) -> OssPartPage:
        result = self._call(
            "list_parts",
            lambda: self._bucket.list_parts(
                key,
                upload_id,
                marker=marker,
                max_parts=1000,
            ),
        )
        typed = cast(_SdkPartPageLike, result)
        try:
            parts = tuple(
                OssRemotePart(
                    part_number=_sdk_int(part.part_number),
                    etag=_sdk_nonempty_text(part.etag),
                    size_bytes=_sdk_int(part.size),
                    crc64=(None if part.part_crc is None else _sdk_int(part.part_crc)),
                )
                for part in typed.parts
            )
            if type(typed.is_truncated) is not bool:
                raise TypeError("SDK truncation flag is not a boolean")
            if type(typed.next_marker) is not str:
                raise TypeError("SDK next marker is not text")
            return OssPartPage(
                parts=parts,
                is_truncated=typed.is_truncated,
                next_marker=typed.next_marker,
            )
        except (AttributeError, TypeError, ValueError):
            raise OssProviderError.inconsistent(operation="list_parts") from None

    def upload_part(
        self,
        key: str,
        upload_id: str,
        part_number: int,
        data: Iterable[bytes],
        *,
        size_bytes: int,
    ) -> OssRemotePart:
        headers = {"Content-Length": str(size_bytes)}
        result = self._call(
            "upload_part",
            lambda: self._bucket.upload_part(
                key,
                upload_id,
                part_number,
                data,
                headers=headers,
            ),
        )
        typed = cast(_SdkUploadResultLike, result)
        try:
            return OssRemotePart(
                part_number=part_number,
                etag=_sdk_nonempty_text(typed.etag),
                size_bytes=size_bytes,
                crc64=_sdk_int(typed.crc),
            )
        except (AttributeError, TypeError, ValueError):
            raise OssProviderError.inconsistent(operation="upload_part") from None

    def complete_multipart(
        self,
        key: str,
        upload_id: str,
        parts: tuple[OssRemotePart, ...],
        *,
        headers: dict[str, str],
    ) -> OssUploadResult:
        sdk_parts = [
            self._part_info(
                part.part_number,
                part.etag,
                size=part.size_bytes,
                part_crc=_required_part_crc64(part),
            )
            for part in parts
        ]
        result = self._call(
            "complete_multipart",
            lambda: self._bucket.complete_multipart_upload(
                key,
                upload_id,
                sdk_parts,
                headers=headers,
            ),
        )
        return self._upload_result("complete_multipart", result)

    def abort_multipart(self, key: str, upload_id: str) -> None:
        self._call(
            "abort_multipart",
            lambda: self._bucket.abort_multipart_upload(key, upload_id),
        )

    def put_object(
        self,
        key: str,
        data: Iterable[bytes],
        *,
        size_bytes: int,
        headers: dict[str, str],
    ) -> OssUploadResult:
        upload_headers = dict(headers)
        upload_headers["Content-Length"] = str(size_bytes)
        result = self._call(
            "put_object",
            lambda: self._bucket.put_object(key, data, headers=upload_headers),
        )
        return self._upload_result("put_object", result)

    @staticmethod
    def _upload_result(operation: str, result: object) -> OssUploadResult:
        typed = cast(_SdkUploadResultLike, result)
        try:
            return OssUploadResult(
                etag=_sdk_nonempty_text(typed.etag),
                crc64=_sdk_int(typed.crc),
                provider_version_id=_sdk_optional_text(typed.versionid),
            )
        except (AttributeError, TypeError, ValueError):
            raise OssProviderError.inconsistent(operation=operation) from None

    def head_object(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> OssObjectMetadata:
        params = (
            None if provider_version_id is None else {"versionId": provider_version_id}
        )
        result = self._call(
            "head_object",
            lambda: self._bucket.head_object(key, params=params),
        )
        typed = cast(_SdkHeadResultLike, result)
        try:
            observed_version = _sdk_optional_text(typed.versionid)
            if (
                provider_version_id is not None
                and observed_version != provider_version_id
            ):
                raise ValueError("SDK returned a different object version")
            return OssObjectMetadata(
                size_bytes=_sdk_int(typed.content_length),
                crc64=(
                    None if typed.server_crc is None else _sdk_int(typed.server_crc)
                ),
                provider_version_id=(
                    provider_version_id
                    if provider_version_id is not None
                    else observed_version
                ),
            )
        except (AttributeError, TypeError, ValueError):
            raise OssProviderError.inconsistent(operation="head_object") from None

    def open_reader(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> IO[bytes]:
        params = (
            None if provider_version_id is None else {"versionId": provider_version_id}
        )
        result = self._call(
            "open_reader",
            lambda: self._bucket.get_object(key, params=params),
        )
        if provider_version_id is not None:
            try:
                observed_version = _sdk_optional_text(
                    getattr(result, "versionid", None)
                )
                if observed_version != provider_version_id:
                    raise ValueError("SDK returned a different object version")
            except (TypeError, ValueError):
                close = getattr(result, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:  # noqa: BLE001, S110 - preserve integrity failure.
                        pass
                raise OssProviderError.inconsistent(operation="open_reader") from None
        return cast(IO[bytes], result)


@dataclass(frozen=True, slots=True)
class _SourceIdentity:
    size_bytes: int
    sha256: str
    crc64: int


@dataclass(frozen=True, slots=True)
class _PartIdentity:
    part_number: int
    offset: int
    size_bytes: int
    sha256: str
    crc64: int


class _SourceSliceBody:
    __slots__ = (
        "_closed",
        "_crc",
        "_digest",
        "_fd",
        "_offset",
        "_position",
        "_remaining",
        "_size",
        "_started",
    )

    def __init__(
        self,
        source: ArchiveObjectSource,
        *,
        offset: int,
        size_bytes: int,
    ) -> None:
        self._fd = _open_source_fd(source)
        self._offset = offset
        self._position = 0
        self._remaining = size_bytes
        self._size = size_bytes
        self._digest = hashlib.sha256()
        self._crc = _Crc64Ecma()
        self._started = False
        self._closed = False

    def __iter__(self) -> Self:
        self._started = True
        return self

    def __next__(self) -> bytes:
        if self._remaining == 0:
            self.close()
            raise StopIteration
        if self._closed:
            raise TargetVerificationError(
                "archive object upload body was closed before completion"
            )
        try:
            chunk = os.pread(
                self._fd,
                min(_READ_CHUNK_BYTES, self._remaining),
                self._offset + self._position,
            )
        except OSError:
            self.close()
            raise TargetVerificationError("archive object source read failed") from None
        if not chunk:
            self.close()
            raise TargetVerificationError("archive object source changed during upload")
        self._digest.update(chunk)
        self._crc.update(chunk)
        self._position += len(chunk)
        self._remaining -= len(chunk)
        return chunk

    def identity(self) -> _SourceIdentity:
        if not self._started or self._remaining != 0:
            raise TargetVerificationError(
                "archive provider did not consume the complete upload body"
            )
        return _SourceIdentity(
            size_bytes=self._size,
            sha256=self._digest.hexdigest(),
            crc64=self._crc.digest(),
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        os.close(self._fd)


def _safe_key(key: str) -> str:
    if (
        type(key) is not str
        or not key
        or key.startswith("/")
        or "\\" in key
        or "\x00" in key
        or any(part in {"", ".", ".."} for part in key.split("/"))
    ):
        raise UnsafeObjectKey("OSS object key is not a normalized relative key")
    return key


def _headers(config: AliyunOssTargetConfig) -> dict[str, str]:
    headers = {"x-oss-forbid-overwrite": "true"}
    if config.storage_class is not None:
        headers["x-oss-storage-class"] = config.storage_class
    return headers


def _validate_runtime_limits(config: AliyunOssTargetConfig) -> None:
    if config.concurrency > _MAX_MULTIPART_CONCURRENCY:
        raise TargetUnavailable(
            "Aliyun OSS upload concurrency exceeds the safe limit of 32"
        )


def _validate_source(source: ArchiveObjectSource) -> ArchiveObjectSource:
    if type(source) is not ArchiveObjectSource:
        raise TypeError("source must be ArchiveObjectSource")
    return source


def _open_source_fd(source: ArchiveObjectSource) -> int:
    try:
        fd = open_readonly_nofollow(source.path)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("archive object source is not a regular file")
        return fd
    except (OSError, ValueError):
        raise TargetVerificationError("archive object source is unavailable") from None


def _scan_source(
    source: ArchiveObjectSource,
    *,
    part_size_bytes: int,
) -> tuple[_SourceIdentity, tuple[_PartIdentity, ...]]:
    fd = _open_source_fd(source)
    try:
        digest = hashlib.sha256()
        crc = _Crc64Ecma()
        size = 0
        part_digest = hashlib.sha256()
        part_crc = _Crc64Ecma()
        part_size = 0
        part_offset = 0
        parts: list[_PartIdentity] = []
        while True:
            chunk = os.read(
                fd,
                min(_READ_CHUNK_BYTES, part_size_bytes - part_size),
            )
            if not chunk:
                break
            digest.update(chunk)
            crc.update(chunk)
            size += len(chunk)
            part_digest.update(chunk)
            part_crc.update(chunk)
            part_size += len(chunk)
            if part_size == part_size_bytes:
                parts.append(
                    _PartIdentity(
                        part_number=len(parts) + 1,
                        offset=part_offset,
                        size_bytes=part_size,
                        sha256=part_digest.hexdigest(),
                        crc64=part_crc.digest(),
                    )
                )
                part_offset += part_size
                part_digest = hashlib.sha256()
                part_crc = _Crc64Ecma()
                part_size = 0
        if part_size:
            parts.append(
                _PartIdentity(
                    part_number=len(parts) + 1,
                    offset=part_offset,
                    size_bytes=part_size,
                    sha256=part_digest.hexdigest(),
                    crc64=part_crc.digest(),
                )
            )
        identity = _SourceIdentity(size, digest.hexdigest(), crc.digest())
    except OSError:
        raise TargetVerificationError("archive object source read failed") from None
    finally:
        os.close(fd)
    if (identity.size_bytes, identity.sha256) != (
        source.size_bytes,
        source.sha256,
    ):
        raise TargetVerificationError("archive object source identity changed")
    return identity, tuple(parts)


def _is_existing(error: OssProviderError) -> bool:
    return error.code in _EXISTING_CODES or (
        error.status in {409, 412} and error.code == "UnknownProviderError"
    )


def _is_no_such_upload(error: OssProviderError) -> bool:
    return error.code in _NO_SUCH_UPLOAD_CODES


def _mapped_provider_error(
    error: OssProviderError,
    *,
    now_unix_ns: int,
) -> ArchiveTargetError:
    if error.kind is OssProviderErrorKind.INCONSISTENT:
        return StoredObjectMismatch(
            f"Aliyun OSS {error.operation} returned inconsistent integrity evidence"
        )
    if error.kind is OssProviderErrorKind.TRANSPORT or (
        error.status in _RETRYABLE_STATUSES or error.code in _RETRYABLE_CODES
    ):
        retry_after_ns = parse_retry_after_ns(
            error.retry_after,
            now_unix_ns=now_unix_ns,
        )
        return OssTargetUnavailable(
            operation=error.operation,
            status=error.status,
            error_code=error.code,
            retry_after_ns=retry_after_ns,
        )
    if _is_existing(error):
        return ExistingObjectMismatch(
            f"Aliyun OSS {error.operation} found an existing immutable object"
        )
    return OssBusinessError(
        operation=error.operation,
        status=error.status,
        error_code=error.code,
    )


class _MappedReader(io.RawIOBase):
    __slots__ = ("_reader", "_time_ns")

    def __init__(self, reader: IO[bytes], time_ns: Callable[[], int]) -> None:
        super().__init__()
        self._reader = reader
        self._time_ns = time_ns

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        result: object = _MISSING
        failure: ArchiveTargetError | None = None
        try:
            result = self._reader.read(size)
        except OssProviderError as error:
            failure = _mapped_provider_error(
                error,
                now_unix_ns=self._time_ns(),
            )
        except Exception:  # noqa: BLE001 - provider reader errors are redacted.
            failure = OssTargetUnavailable(
                operation="read_object",
                status=None,
                error_code=None,
                retry_after_ns=None,
            )
        if failure is not None:
            raise failure from None
        if type(result) is not bytes:
            raise TargetVerificationError("OSS reader returned non-bytes content")
        return result

    def close(self) -> None:
        if self.closed:
            return
        failure: OssTargetUnavailable | None = None
        try:
            self._reader.close()
        except Exception:  # noqa: BLE001 - provider close errors are redacted.
            failure = OssTargetUnavailable(
                operation="close_reader",
                status=None,
                error_code=None,
                retry_after_ns=None,
            )
        finally:
            super().close()
        if failure is not None:
            raise failure from None


class AliyunOssTarget:
    __slots__ = (
        "_closed",
        "_config",
        "_crc_evidence",
        "_journal_factory",
        "_lock",
        "_time_ns",
        "_transport",
    )

    def __init__(
        self,
        *,
        config: AliyunOssTargetConfig,
        transport: OssTransport,
        journal_factory: MultipartJournalFactory | None,
        time_ns: Callable[[], int],
    ) -> None:
        _validate_runtime_limits(config)
        self._config = config
        self._transport = transport
        self._journal_factory = journal_factory
        self._time_ns = time_ns
        self._closed = False
        self._lock = threading.RLock()
        self._crc_evidence: OrderedDict[tuple[str, str | None], _SourceIdentity] = (
            OrderedDict()
        )

    @property
    def id(self) -> str:
        return self._config.id

    def __repr__(self) -> str:
        credentials = self._config.credentials
        refs = [
            credentials.access_key_id.fingerprint_value(),
            credentials.access_key_secret.fingerprint_value(),
        ]
        if credentials.security_token is not None:
            refs.append(credentials.security_token.fingerprint_value())
        return (
            "AliyunOssTarget("
            f"id={self.id!r}, bucket={self._config.bucket!r}, "
            f"endpoint={self._config.endpoint!r}, required={self._config.required!r}, "
            f"credential_references={tuple(refs)!r})"
        )

    def _require_open(self) -> None:
        if self._closed:
            raise TargetClosed(f"archive target {self.id!r} is closed")

    def _provider_call(
        self,
        operation: str,
        callback: Callable[[], object],
    ) -> object:
        self._require_open()
        result: object = _MISSING
        failure: OssTargetUnavailable | None = None
        try:
            result = callback()
        except ArchiveTargetError:
            raise
        except OssProviderError:
            raise
        except Exception:  # noqa: BLE001 - injected transport boundary is redacted.
            failure = OssTargetUnavailable(
                operation=operation,
                status=None,
                error_code=None,
                retry_after_ns=None,
            )
        if failure is not None:
            raise failure from None
        return result

    def _raise_mapped(self, error: OssProviderError) -> NoReturn:
        raise _mapped_provider_error(
            error,
            now_unix_ns=self._time_ns(),
        ) from None

    def _remember_crc_evidence(
        self,
        key: str,
        provider_version_id: str | None,
        identity: _SourceIdentity,
    ) -> None:
        if self._config.required:
            return
        cache_key = (key, provider_version_id)
        with self._lock:
            self._crc_evidence.pop(cache_key, None)
            self._crc_evidence[cache_key] = identity
            while len(self._crc_evidence) > _MAX_CRC_EVIDENCE:
                self._crc_evidence.popitem(last=False)

    def _journal_for(
        self,
        source: ArchiveObjectSource,
        key: str,
    ) -> MultipartJournal:
        factory = self._journal_factory
        if factory is None:
            raise TargetUnavailable("OSS multipart checkpoint journal is required")
        try:
            journal = factory(source, key)
        except ArchiveTargetError:
            raise
        except Exception:  # noqa: BLE001 - factory boundary is fail-closed.
            raise TargetUnavailable(
                "OSS multipart checkpoint journal creation failed"
            ) from None
        if not isinstance(journal, MultipartJournal):
            raise TargetVerificationError(
                "OSS multipart checkpoint factory returned an invalid journal"
            )
        return journal

    def _journal_load(self, journal: MultipartJournal) -> ResumeState | None:
        try:
            state = journal.load()
        except ArchiveTargetError:
            raise
        except Exception:  # noqa: BLE001 - journal boundary is fail-closed.
            raise TargetUnavailable("OSS multipart checkpoint load failed") from None
        if state is not None and type(state) is not ResumeState:
            raise TargetVerificationError(
                "OSS multipart checkpoint returned an invalid state"
            )
        return state

    def _journal_save(
        self,
        journal: MultipartJournal,
        state: ResumeState,
        *,
        expected_upload_id: str | None,
    ) -> None:
        try:
            journal.save(state, expected_upload_id)
        except ArchiveTargetError:
            raise
        except Exception:  # noqa: BLE001 - journal boundary is fail-closed.
            raise TargetUnavailable("OSS multipart checkpoint save failed") from None

    def _journal_clear(
        self,
        journal: MultipartJournal,
        *,
        expected_upload_id: str,
    ) -> None:
        try:
            journal.clear(expected_upload_id)
        except ArchiveTargetError:
            raise
        except Exception:  # noqa: BLE001 - journal boundary is fail-closed.
            raise TargetUnavailable("OSS multipart checkpoint clear failed") from None

    def _abort_and_clear(
        self,
        key: str,
        state: ResumeState,
        journal: MultipartJournal,
    ) -> None:
        try:
            self._provider_call(
                "abort_multipart",
                lambda: self._transport.abort_multipart(key, state.upload_id),
            )
        except OssProviderError as error:
            if not _is_no_such_upload(error):
                self._raise_mapped(error)
        self._journal_clear(journal, expected_upload_id=state.upload_id)

    def _read_remote(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> _SourceIdentity:
        digest = hashlib.sha256()
        crc = _Crc64Ecma()
        size = 0
        with self.open_reader(
            key,
            provider_version_id=provider_version_id,
        ) as reader:
            while True:
                chunk = reader.read(_READ_CHUNK_BYTES)
                if not chunk:
                    break
                digest.update(chunk)
                crc.update(chunk)
                size += len(chunk)
        return _SourceIdentity(size, digest.hexdigest(), crc.digest())

    def _head(
        self,
        key: str,
        *,
        provider_version_id: str | None,
    ) -> OssObjectMetadata:
        try:
            result = self._provider_call(
                "head_object",
                lambda: self._transport.head_object(
                    key,
                    provider_version_id=provider_version_id,
                ),
            )
        except OssProviderError as error:
            self._raise_mapped(error)
        if type(result) is not OssObjectMetadata:
            raise TargetVerificationError("OSS head returned invalid metadata")
        return result

    def _existing_result(
        self,
        key: str,
        source: ArchiveObjectSource,
        *,
        resumed: bool,
    ) -> PutResult:
        metadata = self._head(key, provider_version_id=None)
        if metadata.size_bytes != source.size_bytes:
            raise ExistingObjectMismatch(
                "existing Aliyun OSS object size differs from expected content"
            )
        observed = self._read_remote(
            key,
            provider_version_id=metadata.provider_version_id,
        )
        if (observed.size_bytes, observed.sha256) != (
            source.size_bytes,
            source.sha256,
        ):
            raise ExistingObjectMismatch(
                "existing Aliyun OSS object has a different content identity"
            )
        if metadata.size_bytes != observed.size_bytes or (
            metadata.crc64 is not None and metadata.crc64 != observed.crc64
        ):
            raise StoredObjectMismatch(
                "existing Aliyun OSS object metadata disagrees with readback"
            )
        self._remember_crc_evidence(key, metadata.provider_version_id, observed)
        return PutResult(
            key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            created=False,
            resumed=resumed,
            provider_version_id=metadata.provider_version_id,
        )

    def _probe_key(self) -> str:
        prefix = self._config.prefix
        tail = f"_archive/v1/_probes/target={self.id}/no-replace-v1"
        return f"{prefix}/{tail}" if prefix else tail

    def probe(self) -> TargetProbe:
        self._require_open()
        key = _safe_key(self._probe_key())
        payload = f"crypto-collector OSS no-replace probe v1:{self.id}\n".encode()
        headers = _headers(self._config)
        first_version: str | None = None
        try:
            first = self._provider_call(
                "put_object",
                lambda: self._transport.put_object(
                    key,
                    iter((payload,)),
                    size_bytes=len(payload),
                    headers=headers,
                ),
            )
        except OssProviderError as error:
            if not _is_existing(error):
                self._raise_mapped(error)
        else:
            if type(first) is not OssUploadResult:
                raise TargetVerificationError("OSS probe upload result is invalid")
            if first.crc64 != crc64_ecma(payload):
                raise TargetVerificationError("OSS probe CRC64 does not match")
            first_version = first.provider_version_id
        metadata = self._head(key, provider_version_id=first_version)
        if metadata.size_bytes != len(payload):
            raise TargetVerificationError(
                "OSS no-replace probe object size differs from expected"
            )
        observed = self._read_remote(
            key,
            provider_version_id=metadata.provider_version_id,
        )
        if observed != _SourceIdentity(
            len(payload),
            hashlib.sha256(payload).hexdigest(),
            crc64_ecma(payload),
        ):
            raise TargetVerificationError("OSS no-replace probe readback differs")
        try:
            self._provider_call(
                "put_object",
                lambda: self._transport.put_object(
                    key,
                    iter((payload,)),
                    size_bytes=len(payload),
                    headers=headers,
                ),
            )
        except OssProviderError as error:
            if not _is_existing(error):
                self._raise_mapped(error)
        else:
            raise TargetUnavailable(
                "Aliyun OSS endpoint did not enforce no-replace semantics"
            )
        return TargetProbe(
            target_id=self.id,
            target_type="aliyun_oss",
            no_replace_capability="x-oss-forbid-overwrite",
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
        self._require_open()
        source = _validate_source(source)
        key = _safe_key(key)
        if type(no_replace) is not bool:
            raise TypeError("no_replace must be bool")
        if not no_replace:
            raise UnsafeObjectKey("archive OSS target requires no-replace writes")
        if resume is not None and type(resume) is not ResumeState:
            raise TypeError("resume must be ResumeState or None")
        if source.size_bytes <= self._config.multipart_size_bytes:
            if resume is not None:
                raise TargetVerificationError(
                    "small OSS objects cannot carry multipart resume state"
                )
            return self._put_small(source, key)
        return self._put_multipart(source, key, resume=resume)

    def _put_small(self, source: ArchiveObjectSource, key: str) -> PutResult:
        identity, parts = _scan_source(
            source,
            part_size_bytes=self._config.multipart_size_bytes,
        )
        if len(parts) != 1:
            raise TargetVerificationError("archive object source part count changed")
        part = parts[0]
        body = _SourceSliceBody(
            source,
            offset=part.offset,
            size_bytes=part.size_bytes,
        )
        try:
            try:
                result = self._provider_call(
                    "put_object",
                    lambda: self._transport.put_object(
                        key,
                        body,
                        size_bytes=part.size_bytes,
                        headers=_headers(self._config),
                    ),
                )
            except OssProviderError as error:
                if _is_existing(error):
                    return self._existing_result(key, source, resumed=False)
                self._raise_mapped(error)
            uploaded = body.identity()
        finally:
            body.close()
        if uploaded != identity:
            raise TargetVerificationError("archive object source identity changed")
        if type(result) is not OssUploadResult:
            raise TargetVerificationError("OSS put returned an invalid result")
        if result.crc64 != identity.crc64:
            raise StoredObjectMismatch("OSS put CRC64 disagrees with uploaded bytes")
        self._remember_crc_evidence(key, result.provider_version_id, identity)
        return PutResult(
            key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            created=True,
            resumed=False,
            provider_version_id=result.provider_version_id,
        )

    def _resolved_resume(
        self,
        journal: MultipartJournal,
        explicit: ResumeState | None,
    ) -> ResumeState | None:
        loaded = self._journal_load(journal)
        if explicit is not None and loaded != explicit:
            raise TargetVerificationError(
                "explicit OSS resume state differs from durable checkpoint"
            )
        return explicit if explicit is not None else loaded

    def _new_upload(
        self,
        key: str,
        journal: MultipartJournal,
    ) -> ResumeState:
        try:
            upload_id = self._provider_call(
                "init_multipart",
                lambda: self._transport.init_multipart(
                    key,
                    headers=_headers(self._config),
                ),
            )
        except OssProviderError as error:
            if _is_existing(error):
                raise
            self._raise_mapped(error)
        if type(upload_id) is not str or not upload_id:
            raise TargetVerificationError("OSS multipart upload ID is invalid")
        state = ResumeState(upload_id=upload_id, parts=())
        try:
            self._journal_save(journal, state, expected_upload_id=None)
        except ArchiveTargetError:
            try:
                self._provider_call(
                    "abort_multipart",
                    lambda: self._transport.abort_multipart(key, upload_id),
                )
            except OssProviderError as error:
                if not _is_no_such_upload(error):
                    self._raise_mapped(error)
            raise
        return state

    def _remote_parts(
        self,
        key: str,
        state: ResumeState,
        journal: MultipartJournal,
    ) -> tuple[OssRemotePart, ...]:
        marker = ""
        markers: set[str] = set()
        parts: list[OssRemotePart] = []
        page_count = 0
        while True:
            if page_count >= _MAX_LIST_PART_PAGES:
                self._abort_and_clear(key, state, journal)
                raise TargetVerificationError(
                    "OSS list-parts pagination exceeds the attempt limit"
                )
            page_count += 1
            try:
                page = self._provider_call(
                    "list_parts",
                    partial(
                        self._transport.list_parts,
                        key,
                        state.upload_id,
                        marker=marker,
                    ),
                )
            except OssProviderError as error:
                if _is_no_such_upload(error):
                    self._journal_clear(
                        journal,
                        expected_upload_id=state.upload_id,
                    )
                    raise OssTargetUnavailable(
                        operation="list_parts",
                        status=error.status,
                        error_code=error.code,
                        retry_after_ns=None,
                    ) from None
                mapped = _mapped_provider_error(
                    error,
                    now_unix_ns=self._time_ns(),
                )
                if not isinstance(mapped, TargetUnavailable):
                    self._abort_and_clear(key, state, journal)
                raise mapped from None
            if type(page) is not OssPartPage:
                self._abort_and_clear(key, state, journal)
                raise TargetVerificationError("OSS list-parts result is invalid")
            parts.extend(page.parts)
            if len(parts) > _MAX_MULTIPART_PARTS:
                self._abort_and_clear(key, state, journal)
                raise TargetVerificationError(
                    "OSS list-parts response exceeds provider limits"
                )
            if not page.is_truncated:
                break
            try:
                next_marker_value = int(page.next_marker)
                current_marker_value = int(marker or "0")
            except ValueError:
                next_marker_value = -1
                current_marker_value = 0
            if (
                page.next_marker != str(next_marker_value)
                or next_marker_value <= current_marker_value
                or next_marker_value > _MAX_MULTIPART_PARTS
                or page.next_marker in markers
            ):
                self._abort_and_clear(key, state, journal)
                raise TargetVerificationError(
                    "OSS list-parts pagination did not advance"
                )
            markers.add(page.next_marker)
            marker = page.next_marker
        numbers = tuple(part.part_number for part in parts)
        if numbers != tuple(sorted(numbers)) or len(set(numbers)) != len(numbers):
            self._abort_and_clear(key, state, journal)
            raise StoredObjectMismatch("OSS multipart resume parts are not unique")
        return tuple(parts)

    @staticmethod
    def _persisted_part(part: OssRemotePart) -> MultipartPartV1:
        if part.crc64 is None:
            raise TargetVerificationError(
                "OSS uploaded part omitted required CRC64 evidence"
            )
        return MultipartPartV1(
            part_number=part.part_number,
            etag=part.etag,
            size_bytes=part.size_bytes,
            checksum=str(part.crc64),
        )

    def _save_part(
        self,
        journal: MultipartJournal,
        state: ResumeState,
        part: OssRemotePart,
    ) -> ResumeState:
        by_number = {item.part_number: item for item in state.parts}
        by_number[part.part_number] = self._persisted_part(part)
        updated = ResumeState(
            upload_id=state.upload_id,
            parts=tuple(by_number[number] for number in sorted(by_number)),
        )
        self._journal_save(
            journal,
            updated,
            expected_upload_id=state.upload_id,
        )
        return updated

    def _validate_persisted_remote(
        self,
        key: str,
        state: ResumeState,
        remote: tuple[OssRemotePart, ...],
        journal: MultipartJournal,
    ) -> tuple[OssRemotePart, ...]:
        remote_by_number = {part.part_number: part for part in remote}
        trusted: list[OssRemotePart] = []
        for persisted in state.parts:
            observed = remote_by_number.get(persisted.part_number)
            try:
                checksum = int(persisted.checksum or "")
            except ValueError:
                checksum = -1
            if observed is None or (
                observed.etag != persisted.etag
                or observed.size_bytes != persisted.size_bytes
                or persisted.checksum != str(checksum)
                or not 0 <= checksum <= _CRC64_MASK
                or (observed.crc64 is not None and observed.crc64 != checksum)
            ):
                self._abort_and_clear(key, state, journal)
                raise StoredObjectMismatch(
                    "OSS multipart resume differs from durable checkpoint"
                )
            trusted.append(
                OssRemotePart(
                    part_number=persisted.part_number,
                    etag=persisted.etag,
                    size_bytes=persisted.size_bytes,
                    crc64=checksum,
                )
            )
        return tuple(trusted)

    def _upload_scanned_part(
        self,
        source: ArchiveObjectSource,
        key: str,
        upload_id: str,
        part: _PartIdentity,
    ) -> OssRemotePart:
        body = _SourceSliceBody(
            source,
            offset=part.offset,
            size_bytes=part.size_bytes,
        )
        try:
            result = self._provider_call(
                "upload_part",
                lambda: self._transport.upload_part(
                    key,
                    upload_id,
                    part.part_number,
                    body,
                    size_bytes=part.size_bytes,
                ),
            )
            uploaded = body.identity()
        finally:
            body.close()
        if uploaded != _SourceIdentity(
            part.size_bytes,
            part.sha256,
            part.crc64,
        ):
            raise TargetVerificationError("archive object source identity changed")
        return cast(OssRemotePart, result)

    @staticmethod
    def _selected_batch_error(
        errors: list[tuple[int, ArchiveTargetError]],
    ) -> ArchiveTargetError:
        terminal = [
            item for item in errors if not isinstance(item[1], TargetUnavailable)
        ]
        if terminal:
            return min(terminal, key=lambda item: item[0])[1]
        retryable = [
            (part_number, cast(TargetUnavailable, error))
            for part_number, error in errors
        ]
        oss_retryable = [
            (part_number, error)
            for part_number, error in retryable
            if isinstance(error, OssTargetUnavailable)
        ]
        stale = [item for item in oss_retryable if item[1].error_code == "NoSuchUpload"]
        if not oss_retryable:
            return min(retryable, key=lambda item: item[0])[1]
        selected = min(stale or oss_retryable, key=lambda item: item[0])[1]
        retry_after_ns = max(
            (
                error.retry_after_ns
                for _, error in oss_retryable
                if error.retry_after_ns is not None
            ),
            default=None,
        )
        return OssTargetUnavailable(
            operation=selected.operation,
            status=selected.status,
            error_code=selected.error_code,
            retry_after_ns=retry_after_ns,
        )

    def _process_uploaded_batch(
        self,
        journal: MultipartJournal,
        state: ResumeState,
        futures: dict[Future[OssRemotePart], _PartIdentity],
    ) -> tuple[ResumeState, ArchiveTargetError | None]:
        errors: list[tuple[int, ArchiveTargetError]] = []
        for future in as_completed(futures):
            part = futures[future]
            try:
                result = future.result()
            except OssProviderError as error:
                mapped = (
                    OssTargetUnavailable(
                        operation="upload_part",
                        status=error.status,
                        error_code=error.code,
                        retry_after_ns=None,
                    )
                    if _is_no_such_upload(error)
                    else _mapped_provider_error(
                        error,
                        now_unix_ns=self._time_ns(),
                    )
                )
                errors.append(
                    (
                        part.part_number,
                        mapped,
                    )
                )
                continue
            except ArchiveTargetError as error:
                errors.append((part.part_number, error))
                continue
            except Exception:  # noqa: BLE001 - worker boundary is normalized.
                errors.append(
                    (
                        part.part_number,
                        OssTargetUnavailable(
                            operation="upload_part",
                            status=None,
                            error_code=None,
                            retry_after_ns=None,
                        ),
                    )
                )
                continue
            if type(result) is not OssRemotePart or (
                result.part_number != part.part_number
                or result.size_bytes != part.size_bytes
                or result.crc64 != part.crc64
            ):
                errors.append(
                    (
                        part.part_number,
                        StoredObjectMismatch(
                            "OSS uploaded part integrity evidence does not match"
                        ),
                    )
                )
                continue
            state = self._save_part(journal, state, result)
        if errors:
            return state, self._selected_batch_error(errors)
        return state, None

    def _multipart_stream(
        self,
        source: ArchiveObjectSource,
        key: str,
        state: ResumeState,
        trusted_remote: tuple[OssRemotePart, ...],
        journal: MultipartJournal,
        identity: _SourceIdentity,
        parts: tuple[_PartIdentity, ...],
        listed_remote: tuple[OssRemotePart, ...],
    ) -> tuple[ResumeState, tuple[OssRemotePart, ...], _SourceIdentity]:
        remote_by_number = {part.part_number: part for part in trusted_remote}
        if any(part.part_number > len(parts) for part in listed_remote):
            self._abort_and_clear(key, state, journal)
            raise StoredObjectMismatch("OSS multipart resume has extra remote parts")
        pending_parts: list[_PartIdentity] = []
        for part in parts:
            existing = remote_by_number.get(part.part_number)
            if existing is None:
                pending_parts.append(part)
            elif existing.size_bytes != part.size_bytes or existing.crc64 != part.crc64:
                self._abort_and_clear(key, state, journal)
                raise StoredObjectMismatch(
                    "OSS multipart resume bytes differ from local source"
                )
        first_error: ArchiveTargetError | None = None
        with ThreadPoolExecutor(
            max_workers=self._config.concurrency,
            thread_name_prefix=f"archive-{self.id}",
        ) as executor:
            for offset in range(0, len(pending_parts), self._config.concurrency):
                batch = pending_parts[offset : offset + self._config.concurrency]
                pending: dict[Future[OssRemotePart], _PartIdentity] = {}
                for part in batch:
                    future = executor.submit(
                        self._upload_scanned_part,
                        source,
                        key,
                        state.upload_id,
                        part,
                    )
                    pending[future] = part
                state, first_error = self._process_uploaded_batch(
                    journal,
                    state,
                    pending,
                )
                if first_error is not None:
                    break
        if first_error is not None:
            if (
                isinstance(first_error, OssTargetUnavailable)
                and first_error.error_code == "NoSuchUpload"
            ):
                self._journal_clear(journal, expected_upload_id=state.upload_id)
            elif not isinstance(first_error, TargetUnavailable):
                self._abort_and_clear(key, state, journal)
            raise first_error
        completed = {
            item.part_number: OssRemotePart(
                part_number=item.part_number,
                etag=item.etag,
                size_bytes=item.size_bytes,
                crc64=int(item.checksum or "-1"),
            )
            for item in state.parts
        }
        if tuple(sorted(completed)) != tuple(range(1, len(parts) + 1)):
            self._abort_and_clear(key, state, journal)
            raise StoredObjectMismatch("OSS multipart upload has missing parts")
        return (
            state,
            tuple(completed[number] for number in sorted(completed)),
            identity,
        )

    def _put_multipart(
        self,
        source: ArchiveObjectSource,
        key: str,
        *,
        resume: ResumeState | None,
    ) -> PutResult:
        part_count = math.ceil(source.size_bytes / self._config.multipart_size_bytes)
        if part_count > _MAX_MULTIPART_PARTS:
            raise TargetUnavailable("OSS multipart upload exceeds 10,000 parts")
        identity, scanned_parts = _scan_source(
            source,
            part_size_bytes=self._config.multipart_size_bytes,
        )
        if len(scanned_parts) != part_count:
            raise TargetVerificationError("archive object source part count changed")
        journal = self._journal_for(source, key)
        state = self._resolved_resume(journal, resume)
        was_resumed = state is not None
        if state is None:
            try:
                state = self._new_upload(key, journal)
            except OssProviderError as error:
                if _is_existing(error):
                    return self._existing_result(key, source, resumed=False)
                self._raise_mapped(error)
        try:
            remote = self._remote_parts(key, state, journal)
        except OssTargetUnavailable as error:
            if error.error_code == "NoSuchUpload":
                try:
                    return self._existing_result(key, source, resumed=True)
                except OssBusinessError as existing_error:
                    if existing_error.status != 404:
                        raise
            raise
        trusted_remote = self._validate_persisted_remote(
            key,
            state,
            remote,
            journal,
        )
        state, parts, identity = self._multipart_stream(
            source,
            key,
            state,
            trusted_remote,
            journal,
            identity,
            scanned_parts,
            remote,
        )
        try:
            result = self._provider_call(
                "complete_multipart",
                lambda: self._transport.complete_multipart(
                    key,
                    state.upload_id,
                    parts,
                    headers=_headers(self._config),
                ),
            )
        except OssProviderError as error:
            if _is_existing(error):
                self._abort_and_clear(key, state, journal)
                return self._existing_result(key, source, resumed=was_resumed)
            if _is_no_such_upload(error):
                self._journal_clear(journal, expected_upload_id=state.upload_id)
                try:
                    return self._existing_result(key, source, resumed=True)
                except OssBusinessError as existing_error:
                    if existing_error.status != 404:
                        raise
                raise OssTargetUnavailable(
                    operation="complete_multipart",
                    status=error.status,
                    error_code=error.code,
                    retry_after_ns=None,
                ) from None
            mapped = _mapped_provider_error(error, now_unix_ns=self._time_ns())
            if not isinstance(mapped, OssTargetUnavailable):
                self._abort_and_clear(key, state, journal)
            raise mapped from None
        if type(result) is not OssUploadResult:
            self._abort_and_clear(key, state, journal)
            raise TargetVerificationError("OSS multipart completion result is invalid")
        if result.crc64 != identity.crc64:
            self._journal_clear(journal, expected_upload_id=state.upload_id)
            raise StoredObjectMismatch(
                "OSS multipart full-object CRC64 disagrees with uploaded bytes"
            )
        self._journal_clear(journal, expected_upload_id=state.upload_id)
        self._remember_crc_evidence(key, result.provider_version_id, identity)
        return PutResult(
            key=key,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
            created=True,
            resumed=was_resumed,
            provider_version_id=result.provider_version_id,
        )

    def verify(
        self,
        key: str,
        expected_size: int,
        expected_sha256: str,
        *,
        provider_version_id: str | None = None,
    ) -> VerifyResult:
        self._require_open()
        key = _safe_key(key)
        if type(expected_size) is not int or expected_size <= 0:
            raise ValueError("expected_size must be positive")
        if (
            type(expected_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None
        ):
            raise ValueError("expected_sha256 must be lowercase SHA-256")
        if provider_version_id is not None and (
            type(provider_version_id) is not str or not provider_version_id
        ):
            raise ValueError("provider_version_id must be nonempty or None")
        metadata = self._head(
            key,
            provider_version_id=provider_version_id,
        )
        if (
            provider_version_id is not None
            and metadata.provider_version_id != provider_version_id
        ):
            raise StoredObjectMismatch(
                "OSS provider returned a different object version"
            )
        if metadata.size_bytes != expected_size:
            raise StoredObjectMismatch("OSS object size does not match expected size")
        if metadata.crc64 is None:
            raise TargetVerificationError("OSS object is missing provider CRC64")
        exact_version = metadata.provider_version_id
        with self._lock:
            cached_identity = self._crc_evidence.get((key, exact_version))
        expected_crc = (
            cached_identity.crc64
            if cached_identity is not None
            and (cached_identity.size_bytes, cached_identity.sha256)
            == (expected_size, expected_sha256)
            else None
        )
        readback: _SourceIdentity | None = None
        if self._config.required or expected_crc is None:
            readback = self._read_remote(
                key,
                provider_version_id=exact_version,
            )
            if (readback.size_bytes, readback.sha256) != (
                expected_size,
                expected_sha256,
            ):
                raise StoredObjectMismatch(
                    "OSS readback SHA-256 does not match expected content"
                )
            expected_crc = readback.crc64
        assert expected_crc is not None
        if metadata.crc64 != expected_crc:
            raise StoredObjectMismatch("OSS provider CRC64 does not match content")
        if not self._config.required:
            with self._lock:
                self._crc_evidence.pop((key, exact_version), None)
        checksum = ProviderChecksumV1(
            algorithm="crc64",
            checksum_type="provider_crc64",
            value=str(metadata.crc64),
        )
        if self._config.required:
            method: Literal["provider_crc64", "crc64_plus_readback_sha256"] = (
                "crc64_plus_readback_sha256"
            )
            level = ArchiveVerificationLevel.STORED_SHA256
            cleanup_strong = True
        else:
            method = "provider_crc64"
            level = ArchiveVerificationLevel.PROVIDER_CRC64
            cleanup_strong = False
        return VerifyResult(
            key=key,
            size_bytes=expected_size,
            sha256=expected_sha256,
            method=method,
            level=level,
            provider_checksum=checksum,
            provider_version_id=exact_version,
            verified=True,
            cleanup_strong=cleanup_strong,
        )

    def open_reader(
        self,
        key: str,
        *,
        provider_version_id: str | None = None,
    ) -> IO[bytes]:
        self._require_open()
        key = _safe_key(key)
        if provider_version_id is not None and (
            type(provider_version_id) is not str or not provider_version_id
        ):
            raise ValueError("provider_version_id must be nonempty or None")
        try:
            reader = self._provider_call(
                "open_reader",
                lambda: self._transport.open_reader(
                    key,
                    provider_version_id=provider_version_id,
                ),
            )
        except OssProviderError as error:
            self._raise_mapped(error)
        if not hasattr(reader, "read") or not hasattr(reader, "close"):
            raise TargetVerificationError("OSS transport returned an invalid reader")
        return cast(
            IO[bytes],
            _MappedReader(cast(IO[bytes], reader), self._time_ns),
        )

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._crc_evidence.clear()

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _secret_value(snapshot: SecretSnapshot, reference: SecretRef) -> SecretValue:
    value: object | None = None
    failure: TargetUnavailable | None = None
    try:
        value = snapshot.value_for(reference)
    except Exception:  # noqa: BLE001 - secret provider errors may contain plaintext.
        failure = TargetUnavailable(
            f"Aliyun OSS credential reference {reference.fingerprint_value()!r} "
            "is unavailable"
        )
    snapshot = SecretSnapshot.empty()
    if type(value) is not SecretValue:
        value = None
        if failure is None:
            failure = TargetUnavailable(
                f"Aliyun OSS credential reference {reference.fingerprint_value()!r} "
                "is unavailable"
            )
    if failure is not None:
        raise failure from None
    return cast(SecretValue, value)


def build_aliyun_oss_target(
    config: AliyunOssTargetConfig,
    *,
    secrets: SecretSnapshot,
    transport: OssTransport | None = None,
    journal_factory: MultipartJournalFactory | None = None,
    time_ns: Callable[[], int] = time.time_ns,
) -> AliyunOssTarget:
    if type(config) is not AliyunOssTargetConfig:
        raise TypeError("config must be AliyunOssTargetConfig")
    _validate_runtime_limits(config)
    if not callable(time_ns):
        raise TypeError("time_ns must be callable")
    credentials = config.credentials
    access_key_id: SecretValue | None = None
    access_key_secret: SecretValue | None = None
    security_token: SecretValue | None = None
    try:
        access_key_id = _secret_value(secrets, credentials.access_key_id)
        access_key_secret = _secret_value(secrets, credentials.access_key_secret)
        security_token = (
            None
            if credentials.security_token is None
            else _secret_value(secrets, credentials.security_token)
        )
        selected_transport = transport
        if selected_transport is None:
            selected_transport = _Oss2Transport.build(
                config=config,
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                security_token=security_token,
            )
        result = AliyunOssTarget(
            config=config,
            transport=selected_transport,
            journal_factory=journal_factory,
            time_ns=time_ns,
        )
    finally:
        access_key_id = None
        access_key_secret = None
        security_token = None
        secrets = SecretSnapshot.empty()
    return result


__all__ = [
    "AliyunOssTarget",
    "OssBusinessError",
    "OssObjectMetadata",
    "OssPartPage",
    "OssProviderError",
    "OssProviderErrorKind",
    "OssRemotePart",
    "OssTargetUnavailable",
    "OssTransport",
    "OssUploadResult",
    "build_aliyun_oss_target",
    "crc64_ecma",
]
