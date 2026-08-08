from __future__ import annotations

import hashlib
from importlib.metadata import version as distribution_version
from pathlib import Path
from typing import Literal

from pydantic import ValidationError

from crypto_collector.archive.models import (
    ArchivePolicyV1,
    ArchiveVerificationLevel,
    CredentialReferenceV1,
    FrozenArchiveTargetV1,
    FrozenCompressionPolicyV1,
    build_policy,
    canonical_json_bytes,
)
from crypto_collector.config.models import (
    AliyunOssTargetConfig,
    ArchiveConfig,
    ArchiveTargetConfig,
    FilesystemTargetConfig,
    S3TargetConfig,
)
from crypto_collector.config.primitives import SecretRef

_ZSTANDARD_TOOL_VERSION = distribution_version("zstandard")


class ArchivePolicyError(ValueError):
    pass


def _reference(name: str, value: SecretRef | None) -> CredentialReferenceV1 | None:
    if value is None:
        return None
    return CredentialReferenceV1(name=name, reference=value.fingerprint_value())


def _normalized_prefix(value: str) -> str:
    if type(value) is not str:
        raise ArchivePolicyError("archive target prefix must be a string")
    if (
        value != value.strip("/")
        or "\x00" in value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ) and value:
        raise ArchivePolicyError("archive target prefix is not a safe object prefix")
    return value


def _target_fields(
    target: ArchiveTargetConfig,
) -> tuple[
    str | None,
    str | None,
    str | None,
    str | None,
    Literal["auto", "path", "virtual"] | None,
    str | None,
    str | None,
    str | None,
    Literal["backup_only", "operator_attested_fsync_readback"] | None,
    tuple[CredentialReferenceV1, ...],
]:
    if isinstance(target, AliyunOssTargetConfig):
        references = tuple(
            item
            for item in (
                _reference("access_key_id", target.credentials.access_key_id),
                _reference(
                    "access_key_secret",
                    target.credentials.access_key_secret,
                ),
                _reference("security_token", target.credentials.security_token),
            )
            if item is not None
        )
        return (
            target.bucket,
            target.endpoint,
            target.region,
            target.storage_class,
            None,
            None,
            None,
            None,
            None,
            references,
        )
    if isinstance(target, S3TargetConfig):
        references = tuple(
            item
            for item in (
                _reference("access_key_id", target.credentials.access_key_id),
                _reference(
                    "secret_access_key",
                    target.credentials.secret_access_key,
                ),
                _reference("session_token", target.credentials.session_token),
            )
            if item is not None
        )
        return (
            target.bucket,
            target.endpoint,
            target.region,
            target.storage_class,
            target.addressing_style,
            None,
            None,
            None,
            None,
            references,
        )
    if isinstance(target, FilesystemTargetConfig):
        reference = _reference("mount_guard_expected", target.mount_guard.expected)
        assert reference is not None
        return (
            None,
            None,
            None,
            None,
            None,
            Path(target.root).as_posix(),
            Path(target.mount_root).as_posix(),
            Path(target.mount_guard.path).as_posix(),
            target.durability_capability,
            (reference,),
        )
    raise TypeError(f"unsupported archive target type: {type(target).__name__}")


def _freeze_target(target: ArchiveTargetConfig) -> FrozenArchiveTargetV1:
    if target.required and not target.enabled:
        raise ArchivePolicyError(
            f"required archive target {target.id!r} cannot be disabled"
        )
    try:
        (
            bucket,
            endpoint,
            region,
            storage_class,
            addressing_style,
            root,
            mount_root,
            guard,
            durability_capability,
            references,
        ) = _target_fields(target)
        verification_level = (
            ArchiveVerificationLevel.STORED_SHA256
            if target.required or target.type != "aliyun_oss"
            else ArchiveVerificationLevel.PROVIDER_CRC64
        )
        transform_identity = {
            "codec": "zstd",
            "codec_policy_version": 1,
            "transform_profile": "zstd-v1-content-size-checksum",
            "codec_tool": "python-zstandard",
            "codec_tool_version": _ZSTANDARD_TOOL_VERSION,
        }
        return FrozenArchiveTargetV1(
            target_id=target.id,
            target_type=target.type,
            required=target.required,
            remote_prefix=_normalized_prefix(target.prefix),
            verification_level=verification_level,
            compression=FrozenCompressionPolicyV1(
                enabled=target.compression.enabled,
                mode=target.compression.mode,
                codec=target.compression.codec,
                transform_profile="zstd-v1-content-size-checksum",
                codec_tool="python-zstandard",
                codec_tool_version=_ZSTANDARD_TOOL_VERSION,
                transform_implementation_sha256=hashlib.sha256(
                    canonical_json_bytes(transform_identity)
                ).hexdigest(),
                level=target.compression.level,
                min_size_bytes=target.compression.min_size_bytes,
                recompress=target.compression.recompress,
            ),
            bucket=bucket,
            endpoint=endpoint,
            region=region,
            storage_class=storage_class,
            s3_addressing_style=addressing_style,
            filesystem_root=root,
            filesystem_mount_root=mount_root,
            mount_guard_path=guard,
            filesystem_durability_capability=durability_capability,
            credential_references=references,
        )
    except ValidationError as error:
        if any(issue["loc"] == ("target_id",) for issue in error.errors()):
            raise ArchivePolicyError(
                f"archive target ID {target.id!r} is not path safe"
            ) from error
        if any("userinfo" in issue["msg"] for issue in error.errors()):
            raise ArchivePolicyError(
                f"archive target {target.id!r} endpoint must not contain userinfo"
            ) from error
        raise ArchivePolicyError(f"invalid archive target {target.id!r}") from error


def freeze_policy(
    *,
    config: ArchiveConfig,
) -> ArchivePolicyV1:
    if type(config) is not ArchiveConfig:
        raise TypeError("config must be ArchiveConfig")
    enabled = tuple(target for target in config.targets if target.enabled)
    disabled_required = tuple(
        target.id for target in config.targets if target.required and not target.enabled
    )
    if disabled_required:
        raise ArchivePolicyError(
            "required archive targets cannot be disabled: "
            + ", ".join(sorted(disabled_required))
        )
    targets = tuple(
        sorted(
            (_freeze_target(target) for target in enabled), key=lambda x: x.target_id
        )
    )
    try:
        return build_policy(
            targets=targets,
        )
    except ValidationError as error:
        raise ArchivePolicyError("invalid frozen archive policy") from error


def migrate_policy(
    old: ArchivePolicyV1,
    *,
    config: ArchiveConfig,
    reason: str,
) -> ArchivePolicyV1:
    if type(old) is not ArchivePolicyV1:
        raise TypeError("old must be ArchivePolicyV1")
    if (
        type(reason) is not str
        or not reason.strip()
        or "\n" in reason
        or "\r" in reason
    ):
        raise ArchivePolicyError("policy migration reason must be one nonempty line")
    candidate = freeze_policy(
        config=config,
    )
    if candidate.policy_sha256 == old.policy_sha256:
        raise ArchivePolicyError("archive policy migration is a no-op")
    return candidate


def load_policy_bytes(source: bytes) -> ArchivePolicyV1:
    if type(source) is not bytes:
        raise TypeError("policy source must be bytes")
    if not source.endswith(b"\n"):
        raise ArchivePolicyError("archive policy bytes are not canonical")
    try:
        policy = ArchivePolicyV1.model_validate_json(source)
    except (ValidationError, ValueError) as error:
        message = (
            "archive policy hash is invalid"
            if b"policy_sha256" in source
            else "archive policy is invalid"
        )
        raise ArchivePolicyError(message) from error
    if policy.canonical_bytes() != source:
        raise ArchivePolicyError("archive policy bytes are not canonical")
    return policy


__all__ = [
    "ArchivePolicyError",
    "freeze_policy",
    "load_policy_bytes",
    "migrate_policy",
]
