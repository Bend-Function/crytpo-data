from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import IO, Literal, Protocol, Self, runtime_checkable

from pydantic import ValidationError

from crypto_collector.archive.models import (
    ArchiveVerificationLevel,
    MultipartPartV1,
)
from crypto_collector.archive.receipt import ProviderChecksumV1
from crypto_collector.archive.state import (
    ArchiveConflictError,
    ArchiveTargetError,
    RetryableTargetError,
)
from crypto_collector.archive.transform import StoredArtifact
from crypto_collector.storage.raw_writer import (
    open_readonly_nofollow,
    size_and_sha256_fd,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_VERIFICATION_METHODS = frozenset(
    {
        "provider_full_object_sha256",
        "readback_sha256",
        "provider_crc64",
        "crc64_plus_readback_sha256",
    }
)


class TargetUnavailable(RetryableTargetError):
    pass


class TargetClosed(ArchiveTargetError):
    pass


class UnsafeObjectKey(ArchiveConflictError):
    pass


class TargetVerificationError(ArchiveConflictError):
    pass


def _absolute_file_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("archive object source path must be Path")
    if (
        not path.is_absolute()
        or path == Path(path.anchor)
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise ValueError("archive object source path must be normalized and absolute")
    return path


def _object_key(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or "\x00" in value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or PurePosixPath(value).as_posix() != value
    ):
        raise ValueError("archive object key must be a normalized relative POSIX path")
    return value


def _positive_size(value: int) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError("archive object size must be positive")
    return value


def _sha256(value: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError("archive object SHA-256 is invalid")
    return value


def _opaque_provider_value(value: str | None, *, field_name: str) -> str | None:
    if value is None:
        return None
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{field_name} must be a non-empty opaque string")
    return value


@dataclass(frozen=True, slots=True)
class ArchiveObjectSource:
    path: Path
    size_bytes: int
    sha256: str

    def __post_init__(self) -> None:
        _absolute_file_path(self.path)
        _positive_size(self.size_bytes)
        _sha256(self.sha256)

    @classmethod
    def from_path(cls, path: Path) -> Self:
        source_path = _absolute_file_path(path)
        fd = open_readonly_nofollow(source_path)
        try:
            size_bytes, sha256 = size_and_sha256_fd(fd)
        finally:
            os.close(fd)
        return cls(path=source_path, size_bytes=size_bytes, sha256=sha256)

    @classmethod
    def from_stored_artifact(cls, source: StoredArtifact) -> Self:
        if type(source) is not StoredArtifact:
            raise TypeError("source must be StoredArtifact")
        return cls(
            path=source.path,
            size_bytes=source.size_bytes,
            sha256=source.sha256,
        )


@dataclass(frozen=True, slots=True)
class ResumeState:
    upload_id: str
    parts: tuple[MultipartPartV1, ...]

    def __post_init__(self) -> None:
        if type(self.upload_id) is not str or not self.upload_id:
            raise ValueError("resume upload ID must be non-empty")
        if type(self.parts) is not tuple or any(
            type(part) is not MultipartPartV1 for part in self.parts
        ):
            raise TypeError("resume parts must be MultipartPartV1 values")
        try:
            validated = tuple(
                MultipartPartV1.model_validate(part.model_dump(mode="python"))
                for part in self.parts
            )
        except ValidationError as error:
            raise ValueError("resume part evidence is invalid") from error
        numbers = tuple(part.part_number for part in validated)
        if numbers != tuple(sorted(numbers)) or len(set(numbers)) != len(numbers):
            raise ValueError("resume parts must be sorted and unique")


@runtime_checkable
class MultipartJournal(Protocol):
    def load(self) -> ResumeState | None: ...

    def save(
        self,
        state: ResumeState,
        expected_upload_id: str | None,
    ) -> None: ...

    def clear(self, expected_upload_id: str) -> None: ...


@runtime_checkable
class MultipartJournalFactory(Protocol):
    def __call__(
        self,
        source: ArchiveObjectSource,
        key: str,
    ) -> MultipartJournal: ...


@dataclass(frozen=True, slots=True)
class TargetProbe:
    target_id: str
    target_type: Literal["aliyun_oss", "s3", "filesystem"]
    no_replace_capability: str
    mount_identity: str | None

    def __post_init__(self) -> None:
        if (
            type(self.target_id) is not str
            or _SAFE_IDENTIFIER.fullmatch(self.target_id) is None
        ):
            raise ValueError("archive target probe ID is invalid")
        if self.target_type not in {"aliyun_oss", "s3", "filesystem"}:
            raise ValueError("archive target probe type is invalid")
        capability = _opaque_provider_value(
            self.no_replace_capability,
            field_name="no-replace capability",
        )
        if capability is None or capability != capability.strip():
            raise ValueError(
                "no-replace capability must be a normalized non-empty string"
            )
        _opaque_provider_value(self.mount_identity, field_name="mount identity")
        if (self.target_type == "filesystem") != (self.mount_identity is not None):
            raise ValueError("mount identity is inconsistent with target type")


@dataclass(frozen=True, slots=True)
class PutResult:
    key: str
    size_bytes: int
    sha256: str
    created: bool
    resumed: bool
    provider_version_id: str | None = None
    path: Path | None = None

    def __post_init__(self) -> None:
        _object_key(self.key)
        _positive_size(self.size_bytes)
        _sha256(self.sha256)
        if type(self.created) is not bool or type(self.resumed) is not bool:
            raise TypeError("archive put flags must be booleans")
        _opaque_provider_value(
            self.provider_version_id,
            field_name="provider version ID",
        )
        if self.path is not None:
            _absolute_file_path(self.path)


VerificationMethod = Literal[
    "provider_full_object_sha256",
    "readback_sha256",
    "provider_crc64",
    "crc64_plus_readback_sha256",
]


@dataclass(frozen=True, slots=True)
class VerifyResult:
    key: str
    size_bytes: int
    sha256: str
    method: VerificationMethod
    level: ArchiveVerificationLevel
    provider_checksum: ProviderChecksumV1 | None
    provider_version_id: str | None
    verified: bool
    cleanup_strong: bool

    def __post_init__(self) -> None:
        _object_key(self.key)
        _positive_size(self.size_bytes)
        _sha256(self.sha256)
        if type(self.method) is not str or self.method not in _VERIFICATION_METHODS:
            raise ValueError("archive verification method is invalid")
        if type(self.level) is not ArchiveVerificationLevel:
            raise TypeError("archive verification level is invalid")
        if type(self.verified) is not bool or type(self.cleanup_strong) is not bool:
            raise TypeError("archive verification flags must be booleans")
        _opaque_provider_value(
            self.provider_version_id,
            field_name="provider version ID",
        )
        checksum = self.provider_checksum
        if checksum is not None:
            if type(checksum) is not ProviderChecksumV1:
                raise TypeError("provider checksum evidence is invalid")
            try:
                checksum = ProviderChecksumV1.model_validate(
                    checksum.model_dump(mode="python")
                )
            except ValidationError as error:
                raise ValueError("provider checksum evidence is invalid") from error

        if self.method == "provider_crc64":
            semantic_level = ArchiveVerificationLevel.PROVIDER_CRC64
            valid_evidence = checksum is not None and checksum.algorithm == "crc64"
        elif self.method == "provider_full_object_sha256":
            semantic_level = ArchiveVerificationLevel.STORED_SHA256
            valid_evidence = (
                checksum is not None
                and checksum.algorithm == "sha256"
                and hmac.compare_digest(checksum.value, self.sha256)
            )
        elif self.method == "crc64_plus_readback_sha256":
            semantic_level = ArchiveVerificationLevel.STORED_SHA256
            valid_evidence = checksum is not None and checksum.algorithm == "crc64"
        else:
            semantic_level = ArchiveVerificationLevel.STORED_SHA256
            valid_evidence = checksum is None
        if self.level is not semantic_level or not valid_evidence:
            raise ValueError(
                "archive verification level, method, and evidence are inconsistent"
            )
        expected_cleanup_strength = (
            self.verified and self.level is ArchiveVerificationLevel.STORED_SHA256
        )
        if self.cleanup_strong is not expected_cleanup_strength:
            raise ValueError("archive verification cleanup strength is inconsistent")


@runtime_checkable
class ArchiveTarget(Protocol):
    id: str

    def probe(self) -> TargetProbe: ...

    def put(
        self,
        source: ArchiveObjectSource,
        key: str,
        resume: ResumeState | None = None,
        *,
        no_replace: bool = True,
    ) -> PutResult: ...

    def verify(
        self,
        key: str,
        expected_size: int,
        expected_sha256: str,
        *,
        provider_version_id: str | None = None,
    ) -> VerifyResult: ...

    def open_reader(
        self,
        key: str,
        *,
        provider_version_id: str | None = None,
    ) -> IO[bytes]: ...


@dataclass(frozen=True, slots=True)
class PublishedObject:
    put: PutResult
    verification: VerifyResult


@dataclass(frozen=True, slots=True)
class ReceiptLastCommit:
    data: PublishedObject
    source_manifest: PublishedObject
    receipt: PublishedObject


def _validated_put_result(result: PutResult) -> PutResult:
    if type(result) is not PutResult:
        raise TargetVerificationError("archive target returned an invalid put result")
    try:
        return PutResult(
            key=result.key,
            size_bytes=result.size_bytes,
            sha256=result.sha256,
            created=result.created,
            resumed=result.resumed,
            provider_version_id=result.provider_version_id,
            path=result.path,
        )
    except (TypeError, ValueError):
        raise TargetVerificationError(
            "archive target returned an invalid put result"
        ) from None


def _validated_verify_result(result: VerifyResult) -> VerifyResult:
    if type(result) is not VerifyResult:
        raise TargetVerificationError(
            "archive target returned an invalid verification result"
        )
    try:
        return VerifyResult(
            key=result.key,
            size_bytes=result.size_bytes,
            sha256=result.sha256,
            method=result.method,
            level=result.level,
            provider_checksum=result.provider_checksum,
            provider_version_id=result.provider_version_id,
            verified=result.verified,
            cleanup_strong=result.cleanup_strong,
        )
    except (TypeError, ValueError):
        raise TargetVerificationError(
            "archive target returned an invalid verification result"
        ) from None


def _put_and_verify(
    target: ArchiveTarget,
    source: ArchiveObjectSource,
    key: str,
) -> PublishedObject:
    _object_key(key)
    put = _validated_put_result(target.put(source, key, no_replace=True))
    verification = _validated_verify_result(
        target.verify(
            key,
            source.size_bytes,
            source.sha256,
            provider_version_id=put.provider_version_id,
        )
    )
    if (
        not verification.verified
        or verification.size_bytes != source.size_bytes
        or not hmac.compare_digest(verification.sha256, source.sha256)
        or verification.key.encode("utf-8") != key.encode("utf-8")
        or verification.provider_version_id != put.provider_version_id
        or put.size_bytes != source.size_bytes
        or not hmac.compare_digest(put.sha256, source.sha256)
        or put.key.encode("utf-8") != key.encode("utf-8")
    ):
        raise TargetVerificationError(
            "archive target verification did not prove the expected object identity"
        )
    return PublishedObject(put=put, verification=verification)


def publish_receipt_last(
    target: ArchiveTarget,
    *,
    data: ArchiveObjectSource,
    data_key: str,
    source_manifest: ArchiveObjectSource,
    source_manifest_key: str,
    receipt: ArchiveObjectSource,
    receipt_key: str,
) -> ReceiptLastCommit:
    if not isinstance(target, ArchiveTarget):
        raise TypeError("target must implement ArchiveTarget")
    validated_sources: list[ArchiveObjectSource] = []
    for name, source in (
        ("data", data),
        ("source_manifest", source_manifest),
        ("receipt", receipt),
    ):
        if type(source) is not ArchiveObjectSource:
            raise TypeError(f"{name} must be ArchiveObjectSource")
        validated_sources.append(
            ArchiveObjectSource(
                path=source.path,
                size_bytes=source.size_bytes,
                sha256=source.sha256,
            )
        )
    validated_keys = tuple(
        _object_key(key) for key in (data_key, source_manifest_key, receipt_key)
    )
    if len({key.encode("utf-8") for key in validated_keys}) != len(validated_keys):
        raise ValueError("receipt-last object keys must be pairwise distinct")
    validated_data, validated_manifest, validated_receipt = validated_sources
    data_result = _put_and_verify(target, validated_data, data_key)
    manifest_result = _put_and_verify(
        target,
        validated_manifest,
        source_manifest_key,
    )
    receipt_result = _put_and_verify(target, validated_receipt, receipt_key)
    return ReceiptLastCommit(
        data=data_result,
        source_manifest=manifest_result,
        receipt=receipt_result,
    )


__all__ = [
    "ArchiveObjectSource",
    "ArchiveTarget",
    "MultipartJournal",
    "MultipartJournalFactory",
    "PublishedObject",
    "PutResult",
    "ReceiptLastCommit",
    "ResumeState",
    "TargetClosed",
    "TargetProbe",
    "TargetUnavailable",
    "TargetVerificationError",
    "UnsafeObjectKey",
    "VerifyResult",
    "publish_receipt_last",
]
