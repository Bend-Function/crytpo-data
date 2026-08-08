from __future__ import annotations

import re
from typing import Literal

from pydantic import ValidationError

from crypto_collector.archive.models import (
    ArchivePolicyV1,
    FrozenArchiveTargetV1,
    SourceArtifact,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ArchiveKeyError(ValueError):
    pass


def _target(policy: ArchivePolicyV1, target_id: str) -> FrozenArchiveTargetV1:
    if type(policy) is not ArchivePolicyV1:
        raise TypeError("policy must be ArchivePolicyV1")
    if type(target_id) is not str:
        raise TypeError("target_id must be a string")
    try:
        validated = ArchivePolicyV1.model_validate(policy.model_dump(mode="python"))
        return validated.target(target_id)
    except ValidationError as error:
        raise ArchiveKeyError("archive policy identity is invalid") from error
    except KeyError as error:
        raise ArchiveKeyError("target is not present in the frozen policy") from error


def _artifact(artifact: SourceArtifact) -> SourceArtifact:
    if type(artifact) is not SourceArtifact:
        raise TypeError("artifact must be SourceArtifact")
    try:
        return SourceArtifact.model_validate(artifact.model_dump(mode="python"))
    except ValidationError as error:
        raise ArchiveKeyError("archive source path or identity is invalid") from error


def _validated_target(target: FrozenArchiveTargetV1) -> FrozenArchiveTargetV1:
    if type(target) is not FrozenArchiveTargetV1:
        raise TypeError("target must be FrozenArchiveTargetV1")
    try:
        return FrozenArchiveTargetV1.model_validate(target.model_dump(mode="python"))
    except ValidationError as error:
        raise ArchiveKeyError("archive target identity is invalid") from error


def _manifest_sha256(value: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ArchiveKeyError("source manifest SHA-256 is invalid")
    return value


def _prefix(target: FrozenArchiveTargetV1, tail: str) -> str:
    if target.remote_prefix:
        return f"{target.remote_prefix}/{tail}"
    return tail


def uses_encoded_data(
    artifact: SourceArtifact,
    target: FrozenArchiveTargetV1,
) -> bool:
    source = _artifact(artifact)
    compression = _validated_target(target).compression
    if not compression.enabled or compression.mode == "off":
        return False
    already_compressed = source.relative_path.endswith((".zst", ".parquet"))
    if already_compressed and not compression.recompress:
        return False
    return not (
        compression.mode == "auto" and source.size_bytes < compression.min_size_bytes
    )


def passthrough_key(
    artifact: SourceArtifact,
    policy: ArchivePolicyV1,
    *,
    target_id: str,
) -> str:
    source = _artifact(artifact)
    target = _target(policy, target_id)
    return _prefix(
        target,
        f"{policy.remote_namespace}/{source.relative_path}",
    )


def encoded_key(
    artifact: SourceArtifact,
    policy: ArchivePolicyV1,
    *,
    target_id: str,
    codec: Literal["zstd"] = "zstd",
    version: Literal[1] = 1,
) -> str:
    source = _artifact(artifact)
    target = _target(policy, target_id)
    compression = target.compression
    if (
        type(codec) is not str
        or type(version) is not int
        or codec != compression.codec
        or version != compression.codec_policy_version
    ):
        raise ArchiveKeyError("codec namespace does not match frozen target policy")
    return _prefix(
        target,
        (
            f"{policy.remote_namespace}/_encoded/{codec}/v{version}/"
            f"target={target.target_id}/{source.relative_path}."
            f"{source.sha256}.zst"
        ),
    )


def data_key(
    artifact: SourceArtifact,
    policy: ArchivePolicyV1,
    *,
    target_id: str,
) -> str:
    target = _target(policy, target_id)
    if uses_encoded_data(artifact, target):
        return encoded_key(artifact, policy, target_id=target_id)
    return passthrough_key(artifact, policy, target_id=target_id)


def source_manifest_key(
    source_manifest_sha256: str,
    policy: ArchivePolicyV1,
    *,
    target_id: str,
) -> str:
    manifest_sha = _manifest_sha256(source_manifest_sha256)
    target = _target(policy, target_id)
    return _prefix(
        target,
        (f"{policy.remote_namespace}/_manifests/{manifest_sha}.manifest.json"),
    )


def receipt_key(
    artifact: SourceArtifact,
    source_manifest_sha256: str,
    policy: ArchivePolicyV1,
    *,
    target_id: str,
) -> str:
    source = _artifact(artifact)
    manifest_sha = _manifest_sha256(source_manifest_sha256)
    target = _target(policy, target_id)
    return _prefix(
        target,
        (
            f"{policy.remote_namespace}/_receipts/{target.target_id}/"
            f"{manifest_sha}/{source.artifact_role}.{source.sha256}."
            "archive-receipt.json"
        ),
    )


__all__ = [
    "ArchiveKeyError",
    "data_key",
    "encoded_key",
    "passthrough_key",
    "receipt_key",
    "source_manifest_key",
    "uses_encoded_data",
]
