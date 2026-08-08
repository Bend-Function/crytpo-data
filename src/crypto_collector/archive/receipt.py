from __future__ import annotations

import hashlib
import hmac
import re
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, ValidationError, model_validator

from crypto_collector.archive.keys import data_key, uses_encoded_data
from crypto_collector.archive.models import (
    ArchiveJobKey,
    ArchivePolicyV1,
    ArchiveSourceRelativePath,
    ArchiveVerificationLevel,
    NormalizedRelativePath,
    PositiveInt,
    SafeIdentifier,
    Sha256,
    SignedInt64,
    SourceArtifact,
    canonical_json_bytes,
)
from crypto_collector.domain.envelope import FrozenStrictModel

_CRC64 = re.compile(r"^(0|[1-9][0-9]{0,19})$")
_MAX_UINT64 = 2**64 - 1
ProviderChecksumValue = Annotated[str, StringConstraints(min_length=1)]


class ReceiptValidationError(ValueError):
    pass


class ProviderChecksumV1(FrozenStrictModel):
    algorithm: Literal["sha256", "crc64"]
    checksum_type: Literal["full_object", "provider_crc64"]
    value: ProviderChecksumValue

    @model_validator(mode="after")
    def validate_checksum(self) -> Self:
        if self.algorithm == "sha256":
            if (
                self.checksum_type != "full_object"
                or re.fullmatch(r"[0-9a-f]{64}", self.value) is None
            ):
                raise ValueError("full-object SHA-256 evidence is invalid")
            return self
        if (
            self.checksum_type != "provider_crc64"
            or _CRC64.fullmatch(self.value) is None
            or int(self.value) > _MAX_UINT64
        ):
            raise ValueError("provider CRC64 evidence is invalid")
        return self


class ArchiveReceiptV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    source_manifest_sha256: Sha256
    artifact_role: SafeIdentifier
    source_path: ArchiveSourceRelativePath
    source_size_bytes: PositiveInt
    source_sha256: Sha256
    stored_key: NormalizedRelativePath
    stored_size_bytes: PositiveInt
    stored_sha256: Sha256
    transform_kind: Literal["passthrough", "zstd-v1"]
    codec: Literal["passthrough", "zstd"]
    codec_level: Annotated[int, Field(ge=-7, le=22)] | None
    codec_policy_version: Literal[1] | None
    codec_tool: Literal["python-zstandard"] | None
    codec_version: Annotated[str, StringConstraints(min_length=1)] | None
    transform_profile: Literal["zstd-v1-content-size-checksum"] | None
    transform_implementation_sha256: Sha256 | None
    target_id: SafeIdentifier
    policy_sha256: Sha256
    provider_checksum: ProviderChecksumV1 | None
    verification_level: ArchiveVerificationLevel
    verification_method: Literal[
        "provider_full_object_sha256",
        "readback_sha256",
        "provider_crc64",
        "crc64_plus_readback_sha256",
    ]
    verified_at_ns: SignedInt64
    commit_marker: Literal[True] = True
    receipt_sha256: Sha256

    @model_validator(mode="after")
    def validate_receipt(self) -> Self:
        codec_metadata = (
            self.codec_level,
            self.codec_policy_version,
            self.codec_tool,
            self.codec_version,
            self.transform_profile,
            self.transform_implementation_sha256,
        )
        if self.transform_kind == "passthrough":
            if self.codec != "passthrough" or any(
                item is not None for item in codec_metadata
            ):
                raise ValueError("passthrough receipt codec metadata is inconsistent")
            if (
                self.stored_size_bytes != self.source_size_bytes
                or not hmac.compare_digest(
                    self.stored_sha256,
                    self.source_sha256,
                )
            ):
                raise ValueError("passthrough receipt stored identity is inconsistent")
        else:
            if self.codec != "zstd" or any(item is None for item in codec_metadata):
                raise ValueError("zstd receipt codec metadata is incomplete")
            transform_identity = {
                "codec": self.codec,
                "codec_policy_version": self.codec_policy_version,
                "transform_profile": self.transform_profile,
                "codec_tool": self.codec_tool,
                "codec_tool_version": self.codec_version,
            }
            expected_transform = hashlib.sha256(
                canonical_json_bytes(transform_identity)
            ).hexdigest()
            implementation = self.transform_implementation_sha256
            if implementation is None:
                raise ValueError("zstd receipt transform identity is incomplete")
            if not hmac.compare_digest(
                implementation,
                expected_transform,
            ):
                raise ValueError("zstd receipt transform identity is inconsistent")

        checksum = self.provider_checksum
        if (
            checksum is not None
            and checksum.algorithm == "sha256"
            and not hmac.compare_digest(checksum.value, self.stored_sha256)
        ):
            raise ValueError("provider SHA-256 evidence disagrees with stored content")
        if self.verification_method == "provider_full_object_sha256":
            if checksum is None or checksum.algorithm != "sha256":
                raise ValueError(
                    "provider SHA-256 verification requires provider evidence"
                )
        elif self.verification_method in {
            "provider_crc64",
            "crc64_plus_readback_sha256",
        } and (checksum is None or checksum.algorithm != "crc64"):
            raise ValueError("CRC64 verification requires provider evidence")

        if self.verification_level is ArchiveVerificationLevel.PROVIDER_CRC64:
            if self.verification_method != "provider_crc64":
                raise ValueError("provider CRC64 level has inconsistent verification")
        elif self.verification_method == "provider_crc64":
            raise ValueError("stored SHA-256 level requires strong verification")

        expected = _receipt_hash(self.model_dump(mode="json"))
        if not hmac.compare_digest(self.receipt_sha256, expected):
            raise ValueError("receipt hash does not match canonical receipt")
        return self

    @property
    def job_key(self) -> ArchiveJobKey:
        return ArchiveJobKey(
            source_manifest_sha256=self.source_manifest_sha256,
            artifact_role=self.artifact_role,
            artifact_sha256=self.source_sha256,
            target_id=self.target_id,
            policy_sha256=self.policy_sha256,
        )

    def to_canonical_json(self) -> bytes:
        return canonical_json_bytes(self.model_dump(mode="json")) + b"\n"

    @classmethod
    def with_computed_hash(
        cls,
        *,
        job_key: ArchiveJobKey,
        source_path: str,
        source_size_bytes: int,
        stored_key: str,
        stored_size_bytes: int,
        stored_sha256: str,
        transform_kind: Literal["passthrough", "zstd-v1"],
        codec: Literal["passthrough", "zstd"],
        codec_level: int | None,
        codec_policy_version: Literal[1] | None,
        codec_tool: Literal["python-zstandard"] | None,
        codec_version: str | None,
        transform_profile: Literal["zstd-v1-content-size-checksum"] | None,
        transform_implementation_sha256: str | None,
        provider_checksum: ProviderChecksumV1 | None,
        verification_level: ArchiveVerificationLevel,
        verification_method: Literal[
            "provider_full_object_sha256",
            "readback_sha256",
            "provider_crc64",
            "crc64_plus_readback_sha256",
        ],
        verified_at_ns: int,
    ) -> ArchiveReceiptV1:
        if type(job_key) is not ArchiveJobKey:
            raise TypeError("job_key must be ArchiveJobKey")
        if (
            provider_checksum is not None
            and type(provider_checksum) is not ProviderChecksumV1
        ):
            raise TypeError("provider_checksum must be ProviderChecksumV1 or None")
        payload = {
            "schema_version": 1,
            "source_manifest_sha256": job_key.source_manifest_sha256,
            "artifact_role": job_key.artifact_role,
            "source_path": source_path,
            "source_size_bytes": source_size_bytes,
            "source_sha256": job_key.artifact_sha256,
            "stored_key": stored_key,
            "stored_size_bytes": stored_size_bytes,
            "stored_sha256": stored_sha256,
            "transform_kind": transform_kind,
            "codec": codec,
            "codec_level": codec_level,
            "codec_policy_version": codec_policy_version,
            "codec_tool": codec_tool,
            "codec_version": codec_version,
            "transform_profile": transform_profile,
            "transform_implementation_sha256": transform_implementation_sha256,
            "target_id": job_key.target_id,
            "policy_sha256": job_key.policy_sha256,
            "provider_checksum": (
                None
                if provider_checksum is None
                else provider_checksum.model_dump(mode="json")
            ),
            "verification_level": verification_level,
            "verification_method": verification_method,
            "verified_at_ns": verified_at_ns,
            "commit_marker": True,
        }
        return cls.model_validate({**payload, "receipt_sha256": _receipt_hash(payload)})


def _receipt_hash(payload: dict[str, object]) -> str:
    unhashed = {key: value for key, value in payload.items() if key != "receipt_sha256"}
    return hashlib.sha256(canonical_json_bytes(unhashed)).hexdigest()


def _job_key_bytes(key: ArchiveJobKey) -> bytes:
    return canonical_json_bytes(key.model_dump(mode="json"))


def _receipt_matches_expected_facts(
    receipt: ArchiveReceiptV1,
    *,
    job_key: ArchiveJobKey,
    artifact: SourceArtifact,
    policy: ArchivePolicyV1,
    stored_key: str,
    stored_size_bytes: int,
    stored_sha256: str,
) -> bool:
    try:
        target = policy.target(job_key.target_id)
        expected_job_key = ArchiveJobKey(
            source_manifest_sha256=job_key.source_manifest_sha256,
            artifact_role=artifact.artifact_role,
            artifact_sha256=artifact.sha256,
            target_id=target.target_id,
            policy_sha256=policy.policy_sha256,
        )
        expected_stored_key = data_key(
            artifact,
            policy,
            target_id=target.target_id,
        )
        encoded = uses_encoded_data(artifact, target)
    except (KeyError, TypeError, ValueError):
        return False
    expected_transform: tuple[
        str,
        str,
        int | None,
        int | None,
        str | None,
        str | None,
        str | None,
        str | None,
    ]
    if encoded:
        compression = target.compression
        expected_transform = (
            "zstd-v1",
            compression.codec,
            compression.level,
            compression.codec_policy_version,
            compression.codec_tool,
            compression.codec_tool_version,
            compression.transform_profile,
            compression.transform_implementation_sha256,
        )
    else:
        expected_transform = (
            "passthrough",
            "passthrough",
            None,
            None,
            None,
            None,
            None,
            None,
        )
    observed_transform = (
        receipt.transform_kind,
        receipt.codec,
        receipt.codec_level,
        receipt.codec_policy_version,
        receipt.codec_tool,
        receipt.codec_version,
        receipt.transform_profile,
        receipt.transform_implementation_sha256,
    )
    return (
        receipt.job_key == expected_job_key == job_key
        and receipt.source_path == artifact.relative_path
        and receipt.source_size_bytes == artifact.size_bytes
        and observed_transform == expected_transform
        and receipt.verification_level is target.verification_level
        and receipt.stored_size_bytes == stored_size_bytes
        and hmac.compare_digest(receipt.stored_sha256, stored_sha256)
        and hmac.compare_digest(
            receipt.stored_key.encode("utf-8"),
            stored_key.encode("utf-8"),
        )
        and hmac.compare_digest(
            receipt.stored_key.encode("utf-8"),
            expected_stored_key.encode("utf-8"),
        )
    )


def validate_receipt(
    source: bytes,
    *,
    expected_job_key: ArchiveJobKey | None = None,
    expected_artifact: SourceArtifact | None = None,
    expected_policy: ArchivePolicyV1 | None = None,
    expected_stored_key: str | None = None,
    expected_stored_size_bytes: int | None = None,
    expected_stored_sha256: str | None = None,
) -> ArchiveReceiptV1:
    if type(source) is not bytes:
        raise TypeError("source must be bytes")
    validated_expected_job_key: ArchiveJobKey | None = None
    validated_expected_artifact: SourceArtifact | None = None
    validated_expected_policy: ArchivePolicyV1 | None = None
    if expected_job_key is not None:
        if type(expected_job_key) is not ArchiveJobKey:
            raise TypeError("expected_job_key must be ArchiveJobKey")
        try:
            validated_expected_job_key = ArchiveJobKey.model_validate(
                expected_job_key.model_dump(mode="python")
            )
        except ValidationError:
            pass
        if validated_expected_job_key is None:
            raise ReceiptValidationError("expected archive job key is invalid")
        if type(expected_artifact) is not SourceArtifact:
            raise ReceiptValidationError(
                "job-bound receipt validation requires complete expected binding"
            )
        if type(expected_policy) is not ArchivePolicyV1:
            raise ReceiptValidationError(
                "job-bound receipt validation requires complete expected binding"
            )
        try:
            validated_expected_artifact = SourceArtifact.model_validate(
                expected_artifact.model_dump(mode="python")
            )
            validated_expected_policy = ArchivePolicyV1.model_validate(
                expected_policy.model_dump(mode="python")
            )
        except ValidationError:
            pass
        if (
            validated_expected_artifact is None
            or validated_expected_policy is None
            or expected_stored_key is None
            or type(expected_stored_size_bytes) is not int
            or expected_stored_size_bytes <= 0
            or type(expected_stored_sha256) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_stored_sha256) is None
        ):
            raise ReceiptValidationError(
                "job-bound receipt validation requires complete expected binding"
            )
    elif any(
        item is not None
        for item in (
            expected_artifact,
            expected_policy,
            expected_stored_size_bytes,
            expected_stored_sha256,
        )
    ):
        raise ReceiptValidationError(
            "artifact and policy expectations require an expected job key"
        )
    if expected_stored_key is not None and type(expected_stored_key) is not str:
        raise TypeError("expected_stored_key must be a string")
    receipt: ArchiveReceiptV1 | None = None
    try:
        receipt = ArchiveReceiptV1.model_validate_json(source)
    except (ValidationError, ValueError):
        pass
    if receipt is None:
        raise ReceiptValidationError("archive receipt is invalid")
    if receipt.to_canonical_json() != source:
        raise ReceiptValidationError("archive receipt is not canonical")
    if validated_expected_job_key is not None and not hmac.compare_digest(
        _job_key_bytes(receipt.job_key), _job_key_bytes(validated_expected_job_key)
    ):
        raise ReceiptValidationError("archive receipt job key does not match")
    if expected_stored_key is not None and not hmac.compare_digest(
        receipt.stored_key.encode("utf-8"), expected_stored_key.encode("utf-8")
    ):
        raise ReceiptValidationError("archive receipt stored key does not match")
    if validated_expected_job_key is not None:
        assert validated_expected_artifact is not None
        assert validated_expected_policy is not None
        assert expected_stored_key is not None
        assert expected_stored_size_bytes is not None
        assert expected_stored_sha256 is not None
        if not _receipt_matches_expected_facts(
            receipt,
            job_key=validated_expected_job_key,
            artifact=validated_expected_artifact,
            policy=validated_expected_policy,
            stored_key=expected_stored_key,
            stored_size_bytes=expected_stored_size_bytes,
            stored_sha256=expected_stored_sha256,
        ):
            raise ReceiptValidationError(
                "archive receipt binding does not match expected facts"
            )
    return receipt


__all__ = [
    "ArchiveReceiptV1",
    "ProviderChecksumV1",
    "ReceiptValidationError",
    "validate_receipt",
]
