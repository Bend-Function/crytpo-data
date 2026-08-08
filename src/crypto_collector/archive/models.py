from __future__ import annotations

import hashlib
import re
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Annotated, Literal, Self
from urllib.parse import urlsplit

import simplejson  # type: ignore[import-untyped]
from pydantic import AfterValidator, Field, StringConstraints, model_validator

from crypto_collector.domain.envelope import FrozenStrictModel

if TYPE_CHECKING:
    from crypto_collector.storage.manifest import (
        CleanupProofEvidenceV1,
        LoadedRawManifest,
    )


_SAFE_IDENTIFIER = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_ENV_REFERENCE = re.compile(r"^env:[A-Za-z_][A-Za-z0-9_]*$")
NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]
SignedInt64 = Annotated[int, Field(ge=0, le=2**63 - 1)]


def _normalized_relative_path(value: str) -> str:
    if (
        type(value) is not str
        or not value
        or "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/"))
    ):
        raise ValueError("path must be a normalized POSIX relative path")
    if PurePosixPath(value).as_posix() != value:
        raise ValueError("path must be a normalized POSIX relative path")
    return value


def _safe_identifier(value: str) -> str:
    if _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError("identifier is not path safe")
    return value


def _normalized_remote_prefix(value: str) -> str:
    if (
        "\x00" in value
        or "\\" in value
        or value != value.strip("/")
        or (value and any(part in {"", ".", ".."} for part in value.split("/")))
    ):
        raise ValueError("remote prefix must be a normalized POSIX relative prefix")
    return value


def _normalized_absolute_path_string(value: str) -> str:
    if (
        "\x00" in value
        or "\\" in value
        or not value.startswith("/")
        or value == "/"
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        raise ValueError("filesystem path must be normalized and absolute")
    return value


def _credential_reference(value: str) -> str:
    if _ENV_REFERENCE.fullmatch(value) is not None:
        return value
    scheme, separator, target = value.partition(":")
    if separator != ":" or scheme != "file":
        raise ValueError("credential must be an env: or file: reference")
    _normalized_absolute_path_string(target)
    return value


NormalizedRelativePath = Annotated[str, AfterValidator(_normalized_relative_path)]
SafeIdentifier = Annotated[str, AfterValidator(_safe_identifier)]
NormalizedRemotePrefix = Annotated[str, AfterValidator(_normalized_remote_prefix)]
NormalizedAbsolutePathString = Annotated[
    str,
    AfterValidator(_normalized_absolute_path_string),
]
CredentialReference = Annotated[str, AfterValidator(_credential_reference)]


def canonical_json_bytes(value: object) -> bytes:
    return simplejson.dumps(
        value,
        use_decimal=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _canonical_model_bytes(model: FrozenStrictModel) -> bytes:
    return canonical_json_bytes(model.model_dump(mode="json")) + b"\n"


def _computed_model_sha256(
    model: FrozenStrictModel,
    *,
    hash_field: str,
) -> str:
    payload = model.model_dump(mode="json", exclude={hash_field})
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _validate_canonical_evidence(
    value: bytes | None,
    *,
    field_name: str,
) -> None:
    if value is None:
        return
    try:
        decoded = simplejson.loads(
            value,
            use_decimal=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field_name} is not valid JSON") from error
    if (
        type(decoded) is not dict
        or not decoded
        or canonical_json_bytes(decoded) != value
    ):
        raise ValueError(f"{field_name} must be a canonical nonempty JSON object")


class ArchiveVerificationLevel(StrEnum):
    PROVIDER_CRC64 = "provider_crc64"
    STORED_SHA256 = "stored_sha256"


class CleanupGatePolicyV1(FrozenStrictModel):
    source_kind: Literal["raw", "derived"]
    grace_ns: SignedInt64
    materializer_enabled: bool
    materializer_delay_ns: SignedInt64
    revision_horizon_ns: SignedInt64

    @model_validator(mode="after")
    def validate_source_gates(self) -> Self:
        if self.source_kind == "derived" and (
            self.materializer_enabled
            or self.materializer_delay_ns != 0
            or self.revision_horizon_ns != 0
        ):
            raise ValueError("derived sources cannot require raw materializer gates")
        if not self.materializer_enabled and (
            self.materializer_delay_ns != 0 or self.revision_horizon_ns != 0
        ):
            raise ValueError("disabled materializer gates must use zero durations")
        return self


class WorkflowCheckpoint(StrEnum):
    SOURCE = "source"
    STORED = "stored"
    DATA_UPLOADED = "data_uploaded"
    DATA_VERIFIED = "data_verified"
    SOURCE_MANIFEST_UPLOADED = "source_manifest_uploaded"
    SOURCE_MANIFEST_VERIFIED = "source_manifest_verified"
    RECEIPT_PUBLISHED = "receipt_published"


WORKFLOW_CHECKPOINT_ORDER = {
    checkpoint: index for index, checkpoint in enumerate(WorkflowCheckpoint)
}


class ArchiveJobState(StrEnum):
    DISCOVERED = "DISCOVERED"
    QUEUED = "QUEUED"
    TRANSFORMING = "TRANSFORMING"
    UPLOADING = "UPLOADING"
    VERIFYING = "VERIFYING"
    RETRYING = "RETRYING"
    COMMITTED = "COMMITTED"
    TERMINAL_CONFLICT = "TERMINAL_CONFLICT"
    ABANDONED_LOCAL_SOURCE_DELETED = "ABANDONED_LOCAL_SOURCE_DELETED"


TERMINAL_JOB_STATES = frozenset(
    {
        ArchiveJobState.COMMITTED,
        ArchiveJobState.TERMINAL_CONFLICT,
        ArchiveJobState.ABANDONED_LOCAL_SOURCE_DELETED,
    }
)


class SourceArtifact(FrozenStrictModel):
    relative_path: NormalizedRelativePath
    size_bytes: PositiveInt
    sha256: Sha256
    artifact_role: SafeIdentifier


class ArchiveSourceManifestV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    manifest_kind: Literal["raw", "derived"]
    manifest_schema: SafeIdentifier
    manifest_schema_version: PositiveInt
    source_manifest_relative_path: NormalizedRelativePath
    source_manifest_size_bytes: PositiveInt
    source_manifest_sha256: Sha256
    closed: Literal[True]
    closed_at_ns: SignedInt64
    storage_partition_end_ns: SignedInt64 | None
    artifacts: Annotated[tuple[SourceArtifact, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_artifacts(self) -> Self:
        identities = tuple(
            (artifact.artifact_role, artifact.relative_path, artifact.sha256)
            for artifact in self.artifacts
        )
        if identities != tuple(sorted(identities)):
            raise ValueError("source artifacts must be deterministically sorted")
        roles = tuple(artifact.artifact_role for artifact in self.artifacts)
        paths = tuple(artifact.relative_path for artifact in self.artifacts)
        if len(set(roles)) != len(roles):
            raise ValueError("source artifact roles must be unique")
        if len(set(paths)) != len(paths):
            raise ValueError("source artifact paths must be unique")
        if self.source_manifest_relative_path in set(paths):
            raise ValueError("source manifest and artifact paths must be distinct")
        if self.manifest_kind == "raw" and self.storage_partition_end_ns is None:
            raise ValueError("raw sources require a storage partition end")
        if (
            self.manifest_kind == "derived"
            and self.storage_partition_end_ns is not None
        ):
            raise ValueError("derived sources do not use a raw retention partition")
        return self

    @property
    def sha256(self) -> str:
        return self.source_manifest_sha256

    @classmethod
    def from_loaded_raw_manifest(
        cls,
        loaded: LoadedRawManifest,
        *,
        data_root: Path,
    ) -> ArchiveSourceManifestV1:
        from crypto_collector.storage.lease import SourceLease
        from crypto_collector.storage.manifest import (
            LoadedRawManifest,
            SourceDisposition,
            lease_path_for_data,
            load_raw_manifest,
            validate_local_source,
        )

        if type(loaded) is not LoadedRawManifest:
            raise TypeError("loaded must be LoadedRawManifest")
        if not isinstance(data_root, Path):
            raise TypeError("data_root must be Path")
        absolute_root = Path(data_root.absolute())
        manifest = loaded.manifest
        if not loaded.canonical_bytes.endswith(b"\n"):
            raise ValueError("raw source manifest must be canonical and closed")
        expected_manifest_path = absolute_root / manifest.manifest_relative_path
        reloaded = load_raw_manifest(expected_manifest_path)
        if reloaded != loaded:
            raise ValueError("raw manifest path is not bound to its relative identity")
        data_path = absolute_root / manifest.data_relative_path

        class MissingSourceIsUnavailable:
            def resolve_missing(
                self,
                *,
                loaded: LoadedRawManifest,
                data_path: Path,
                expected_data_sha256: str,
                expected_proof: CleanupProofEvidenceV1 | None = None,
            ) -> None:
                del loaded, data_path, expected_data_sha256, expected_proof

        with SourceLease.shared(lease_path_for_data(data_path)) as lease:
            validation = validate_local_source(
                reloaded,
                data_root=absolute_root,
                resolver=MissingSourceIsUnavailable(),
                lease=lease,
            )
        if validation.disposition is not SourceDisposition.PRESENT_VERIFIED:
            raise ValueError("raw source data is missing")
        return cls(
            manifest_kind="raw",
            manifest_schema="raw_manifest",
            manifest_schema_version=manifest.schema_version,
            source_manifest_relative_path=manifest.manifest_relative_path,
            source_manifest_size_bytes=len(loaded.canonical_bytes),
            source_manifest_sha256=loaded.sha256,
            closed=True,
            closed_at_ns=manifest.closed_at_ns,
            storage_partition_end_ns=(
                (manifest.last_received_at_ns // 3_600_000_000_000) + 1
            )
            * 3_600_000_000_000,
            artifacts=(
                SourceArtifact(
                    relative_path=manifest.data_relative_path,
                    size_bytes=manifest.file_size_bytes,
                    sha256=manifest.file_sha256,
                    artifact_role="raw_data",
                ),
            ),
        )


class CredentialReferenceV1(FrozenStrictModel):
    name: SafeIdentifier
    reference: CredentialReference


class FrozenCompressionPolicyV1(FrozenStrictModel):
    enabled: bool
    mode: Literal["off", "auto", "zstd"]
    codec: Literal["zstd"]
    codec_policy_version: Literal[1] = 1
    transform_profile: Literal["zstd-v1-content-size-checksum"]
    codec_tool: Literal["python-zstandard"]
    codec_tool_version: NonEmptyString
    transform_implementation_sha256: Sha256
    level: Annotated[int, Field(ge=-7, le=22)]
    min_size_bytes: NonNegativeInt
    recompress: bool

    @model_validator(mode="after")
    def validate_transform_identity(self) -> Self:
        identity = {
            "codec": self.codec,
            "codec_policy_version": self.codec_policy_version,
            "transform_profile": self.transform_profile,
            "codec_tool": self.codec_tool,
            "codec_tool_version": self.codec_tool_version,
        }
        expected = hashlib.sha256(canonical_json_bytes(identity)).hexdigest()
        if self.transform_implementation_sha256 != expected:
            raise ValueError("compression transform identity hash does not match")
        return self


class FrozenArchiveTargetV1(FrozenStrictModel):
    target_id: SafeIdentifier
    target_type: Literal["aliyun_oss", "s3", "filesystem"]
    required: bool
    remote_prefix: NormalizedRemotePrefix
    verification_level: ArchiveVerificationLevel
    compression: FrozenCompressionPolicyV1
    bucket: NonEmptyString | None
    endpoint: NonEmptyString | None
    region: NonEmptyString | None
    storage_class: NonEmptyString | None
    s3_addressing_style: Literal["auto", "path", "virtual"] | None
    filesystem_root: NormalizedAbsolutePathString | None
    filesystem_mount_root: NormalizedAbsolutePathString | None
    mount_guard_path: NormalizedAbsolutePathString | None
    filesystem_durability_capability: (
        Literal[
            "backup_only",
            "operator_attested_fsync_readback",
        ]
        | None
    )
    credential_references: tuple[CredentialReferenceV1, ...]

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        references = tuple(item.name for item in self.credential_references)
        if references != tuple(sorted(references)) or len(set(references)) != len(
            references
        ):
            raise ValueError("credential references must be sorted and unique")
        if self.required and (
            self.verification_level is not ArchiveVerificationLevel.STORED_SHA256
        ):
            raise ValueError("required targets must require stored SHA-256")
        if self.endpoint is not None:
            try:
                parsed_endpoint = urlsplit(self.endpoint)
                hostname = parsed_endpoint.hostname
                _parsed_port = parsed_endpoint.port
            except ValueError as error:
                raise ValueError("archive endpoint is invalid") from error
            if (
                parsed_endpoint.username is not None
                or parsed_endpoint.password is not None
            ):
                raise ValueError("archive endpoint must not contain userinfo")
            if (
                parsed_endpoint.scheme not in {"http", "https"}
                or not parsed_endpoint.netloc
                or hostname is None
                or any(
                    character.isspace() or ord(character) < 0x20
                    for character in hostname
                )
                or parsed_endpoint.query
                or parsed_endpoint.fragment
                or parsed_endpoint.path not in {"", "/"}
            ):
                raise ValueError(
                    "archive endpoint must be a root HTTP(S) URL without query or "
                    "fragment"
                )
        if self.target_type == "filesystem":
            if (
                self.filesystem_root is None
                or self.filesystem_mount_root is None
                or self.mount_guard_path is None
                or self.filesystem_durability_capability is None
                or self.bucket is not None
                or self.endpoint is not None
                or self.s3_addressing_style is not None
            ):
                raise ValueError("filesystem target fields are inconsistent")
        elif self.target_type == "s3":
            if (
                self.bucket is None
                or self.s3_addressing_style is None
                or self.filesystem_root is not None
                or self.filesystem_mount_root is not None
                or self.mount_guard_path is not None
                or self.filesystem_durability_capability is not None
            ):
                raise ValueError("S3 target fields are inconsistent")
        elif (
            self.bucket is None
            or self.endpoint is None
            or self.s3_addressing_style is not None
            or self.filesystem_root is not None
            or self.filesystem_mount_root is not None
            or self.mount_guard_path is not None
            or self.filesystem_durability_capability is not None
        ):
            raise ValueError("Aliyun OSS target fields are inconsistent")
        return self


class ArchivePolicyV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    object_key_namespace_version: Literal[1] = 1
    targets: tuple[FrozenArchiveTargetV1, ...]
    required_target_ids: tuple[SafeIdentifier, ...]
    policy_sha256: Sha256

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        target_ids = tuple(target.target_id for target in self.targets)
        if target_ids != tuple(sorted(target_ids)) or len(set(target_ids)) != len(
            target_ids
        ):
            raise ValueError("archive targets must be sorted and unique")
        required = tuple(target.target_id for target in self.targets if target.required)
        if self.required_target_ids != required:
            raise ValueError("required target IDs do not match frozen targets")
        expected = _computed_model_sha256(self, hash_field="policy_sha256")
        if self.policy_sha256 != expected:
            raise ValueError("archive policy hash does not match canonical policy")
        return self

    @property
    def sha256(self) -> str:
        return self.policy_sha256

    @property
    def remote_namespace(self) -> str:
        return f"_archive/v1/policy={self.policy_sha256}"

    def target(self, target_id: str) -> FrozenArchiveTargetV1:
        for target in self.targets:
            if target.target_id == target_id:
                return target
        raise KeyError(target_id)

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)


class ArchiveJobKey(FrozenStrictModel):
    source_manifest_sha256: Sha256
    artifact_role: SafeIdentifier
    artifact_sha256: Sha256
    target_id: SafeIdentifier
    policy_sha256: Sha256


class MultipartPartV1(FrozenStrictModel):
    part_number: PositiveInt
    etag: NonEmptyString
    size_bytes: PositiveInt
    checksum: NonEmptyString | None = None


class ArchiveJobV1(FrozenStrictModel):
    source_manifest_sha256: Sha256
    artifact_role: SafeIdentifier
    artifact_relative_path: NormalizedRelativePath
    artifact_sha256: Sha256
    target_id: SafeIdentifier
    policy_sha256: Sha256
    generation: PositiveInt
    target_required: bool
    state: ArchiveJobState
    attempt: NonNegativeInt
    retry_at_ns: NonNegativeInt | None
    workflow_checkpoint: WorkflowCheckpoint
    multipart_upload_id: NonEmptyString | None
    multipart_parts: tuple[MultipartPartV1, ...]
    staging_path: NonEmptyString | None
    data_key: NormalizedRelativePath
    source_manifest_key: NormalizedRelativePath
    receipt_key: NormalizedRelativePath
    stored_sha256: Sha256 | None
    stored_size: NonNegativeInt | None
    provider_checksum_json: bytes | None
    verification_json: bytes | None
    error_class: NonEmptyString | None
    updated_at_ns: NonNegativeInt

    @model_validator(mode="after")
    def validate_job(self) -> Self:
        part_numbers = tuple(part.part_number for part in self.multipart_parts)
        if part_numbers != tuple(sorted(part_numbers)) or len(set(part_numbers)) != len(
            part_numbers
        ):
            raise ValueError("multipart parts must be sorted and unique")
        if self.multipart_parts and self.multipart_upload_id is None:
            raise ValueError("multipart parts require an upload ID")
        if (self.stored_sha256 is None) != (self.stored_size is None):
            raise ValueError("stored SHA-256 and size must be paired")
        if (self.state is ArchiveJobState.RETRYING) != (self.retry_at_ns is not None):
            raise ValueError("retry deadline must exist exactly for RETRYING jobs")
        if self.state is ArchiveJobState.COMMITTED and (
            self.workflow_checkpoint is not WorkflowCheckpoint.RECEIPT_PUBLISHED
            or self.stored_sha256 is None
            or self.verification_json is None
        ):
            raise ValueError(
                "committed jobs require stored identity and verified receipt checkpoint"
            )
        _validate_canonical_evidence(
            self.provider_checksum_json,
            field_name="provider_checksum_json",
        )
        _validate_canonical_evidence(
            self.verification_json,
            field_name="verification_json",
        )
        return self

    @property
    def key(self) -> ArchiveJobKey:
        return ArchiveJobKey(
            source_manifest_sha256=self.source_manifest_sha256,
            artifact_role=self.artifact_role,
            artifact_sha256=self.artifact_sha256,
            target_id=self.target_id,
            policy_sha256=self.policy_sha256,
        )

    @property
    def part_numbers(self) -> tuple[int, ...]:
        return tuple(part.part_number for part in self.multipart_parts)


class ArchiveGenerationJobV1(FrozenStrictModel):
    artifact_role: SafeIdentifier
    artifact_relative_path: NormalizedRelativePath
    artifact_sha256: Sha256
    target_id: SafeIdentifier
    target_required: bool
    data_key: NormalizedRelativePath
    source_manifest_key: NormalizedRelativePath
    receipt_key: NormalizedRelativePath


class ArchiveCleanupFactsV1(FrozenStrictModel):
    grace_anchor_ns: SignedInt64
    grace_deadline_ns: SignedInt64
    materializer_ack_required: bool
    storage_partition_end_ns: SignedInt64 | None
    materializer_delay_ns: SignedInt64
    revision_horizon_ns: SignedInt64
    revision_deadline_ns: SignedInt64 | None

    @model_validator(mode="after")
    def validate_deadlines(self) -> Self:
        if self.grace_deadline_ns < self.grace_anchor_ns:
            raise ValueError("cleanup grace deadline precedes its anchor")
        raw_fields_present = self.storage_partition_end_ns is not None
        if self.materializer_ack_required:
            if not raw_fields_present or self.revision_deadline_ns is None:
                raise ValueError("materializer cleanup gates require raw deadlines")
            assert self.storage_partition_end_ns is not None
            expected = (
                self.storage_partition_end_ns
                + self.materializer_delay_ns
                + self.revision_horizon_ns
            )
            if expected != self.revision_deadline_ns:
                raise ValueError("revision deadline does not match frozen inputs")
        elif (
            self.materializer_delay_ns != 0
            or self.revision_horizon_ns != 0
            or self.revision_deadline_ns is not None
        ):
            raise ValueError("disabled materializer gate must not retain deadlines")
        return self


class ArchiveSourceGenerationFactV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    source: ArchiveSourceManifestV1
    generation: PositiveInt
    policy_sha256: Sha256
    previous_policy_sha256: Sha256 | None
    predecessor_generation_fact_sha256: Sha256 | None
    migration_reason: NonEmptyString | None
    required_target_ids: tuple[SafeIdentifier, ...]
    optional_target_ids: tuple[SafeIdentifier, ...]
    cleanup_facts: ArchiveCleanupFactsV1
    jobs: tuple[ArchiveGenerationJobV1, ...]
    generation_fact_sha256: Sha256

    @model_validator(mode="after")
    def validate_fact(self) -> Self:
        if (
            self.cleanup_facts.grace_anchor_ns != self.source.closed_at_ns
            or self.cleanup_facts.storage_partition_end_ns
            != self.source.storage_partition_end_ns
            or (
                self.source.manifest_kind == "derived"
                and self.cleanup_facts.materializer_ack_required
            )
        ):
            raise ValueError("cleanup facts do not bind the source manifest")
        identities = tuple(
            (job.artifact_role, job.artifact_sha256, job.target_id) for job in self.jobs
        )
        if identities != tuple(sorted(identities)) or len(set(identities)) != len(
            identities
        ):
            raise ValueError("generation jobs must be sorted and unique")
        job_targets = tuple(sorted({job.target_id for job in self.jobs}))
        target_ids = (*self.required_target_ids, *self.optional_target_ids)
        if (
            self.required_target_ids != tuple(sorted(self.required_target_ids))
            or self.optional_target_ids != tuple(sorted(self.optional_target_ids))
            or len(set(target_ids)) != len(target_ids)
            or tuple(sorted(target_ids)) != job_targets
        ):
            raise ValueError("generation target sets do not match jobs")
        if self.generation == 1 and (
            self.previous_policy_sha256 is not None
            or self.predecessor_generation_fact_sha256 is not None
            or self.migration_reason is not None
        ):
            raise ValueError("generation ancestry fields are inconsistent")
        if self.generation > 1 and (
            self.previous_policy_sha256 is None
            or self.predecessor_generation_fact_sha256 is None
            or self.migration_reason is None
        ):
            raise ValueError("generation ancestry fields are inconsistent")
        expected = _computed_model_sha256(
            self,
            hash_field="generation_fact_sha256",
        )
        if self.generation_fact_sha256 != expected:
            raise ValueError("generation fact hash does not match canonical fact")
        return self

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)


class ActiveGenerationPointerV1(FrozenStrictModel):
    generation: PositiveInt
    generation_fact_sha256: Sha256

    def canonical_bytes(self) -> bytes:
        return _canonical_model_bytes(self)


class ArchiveDiscoveryV1(FrozenStrictModel):
    source_sha: Sha256
    generation: PositiveInt
    policy_sha256: Sha256
    job_keys: tuple[ArchiveJobKey, ...]


def build_policy(
    *,
    targets: tuple[FrozenArchiveTargetV1, ...],
) -> ArchivePolicyV1:
    payload = {
        "schema_version": 1,
        "object_key_namespace_version": 1,
        "targets": [target.model_dump(mode="json") for target in targets],
        "required_target_ids": [
            target.target_id for target in targets if target.required
        ],
    }
    policy_sha256 = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return ArchivePolicyV1(
        targets=targets,
        required_target_ids=tuple(
            target.target_id for target in targets if target.required
        ),
        policy_sha256=policy_sha256,
    )


def build_generation_fact(
    *,
    source: ArchiveSourceManifestV1,
    generation: int,
    policy_sha256: str,
    previous_policy_sha256: str | None,
    predecessor_generation_fact_sha256: str | None,
    migration_reason: str | None,
    required_target_ids: tuple[str, ...],
    optional_target_ids: tuple[str, ...],
    cleanup_facts: ArchiveCleanupFactsV1,
    jobs: tuple[ArchiveGenerationJobV1, ...],
) -> ArchiveSourceGenerationFactV1:
    payload = {
        "schema_version": 1,
        "source": source.model_dump(mode="json"),
        "generation": generation,
        "policy_sha256": policy_sha256,
        "previous_policy_sha256": previous_policy_sha256,
        "predecessor_generation_fact_sha256": (predecessor_generation_fact_sha256),
        "migration_reason": migration_reason,
        "required_target_ids": required_target_ids,
        "optional_target_ids": optional_target_ids,
        "cleanup_facts": cleanup_facts.model_dump(mode="json"),
        "jobs": [job.model_dump(mode="json") for job in jobs],
    }
    digest = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    return ArchiveSourceGenerationFactV1(
        source=source,
        generation=generation,
        policy_sha256=policy_sha256,
        previous_policy_sha256=previous_policy_sha256,
        predecessor_generation_fact_sha256=(predecessor_generation_fact_sha256),
        migration_reason=migration_reason,
        required_target_ids=required_target_ids,
        optional_target_ids=optional_target_ids,
        cleanup_facts=cleanup_facts,
        jobs=jobs,
        generation_fact_sha256=digest,
    )


__all__ = [
    "TERMINAL_JOB_STATES",
    "WORKFLOW_CHECKPOINT_ORDER",
    "ActiveGenerationPointerV1",
    "ArchiveCleanupFactsV1",
    "ArchiveDiscoveryV1",
    "ArchiveGenerationJobV1",
    "ArchiveJobKey",
    "ArchiveJobState",
    "ArchiveJobV1",
    "ArchivePolicyV1",
    "ArchiveSourceGenerationFactV1",
    "ArchiveSourceManifestV1",
    "ArchiveVerificationLevel",
    "CleanupGatePolicyV1",
    "CredentialReferenceV1",
    "FrozenArchiveTargetV1",
    "FrozenCompressionPolicyV1",
    "MultipartPartV1",
    "SourceArtifact",
    "WorkflowCheckpoint",
    "build_generation_fact",
    "build_policy",
    "canonical_json_bytes",
]
