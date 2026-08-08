from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationInfo,
    field_validator,
    model_validator,
)

from crypto_collector.config.primitives import (
    SecretRef,
    SecretSnapshot,
    parse_duration_ns,
    parse_size_bytes,
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MINUTE_NS = 60_000_000_000
_HOUR_NS = 3_600_000_000_000
_MAX_SIGNED_INT64 = 2**63 - 1
_MAX_SCHEDULER_COLLECTION_ITEMS = 1_000_000
_S3_MIN_MULTIPART_SIZE_BYTES = 5 * 1024**2
_OSS_MIN_MULTIPART_SIZE_BYTES = 100 * 1024
_OBJECT_STORAGE_MAX_MULTIPART_SIZE_BYTES = 5 * 1024**3


def _duration_ns(value: object) -> int:
    if type(value) is not str:
        raise ValueError("duration must be a string with an explicit unit")
    return parse_duration_ns(value)


def _size_bytes(value: object) -> int:
    if type(value) is not str:
        raise ValueError("size must be a string with an explicit unit")
    return parse_size_bytes(value)


def _resolved_path(value: object, info: ValidationInfo) -> Path:
    if type(value) is not str:
        raise ValueError("path must be a string")
    candidate = Path(value).expanduser()
    if not candidate.is_absolute():
        base_dir = Path.cwd()
        if isinstance(info.context, Mapping) and "base_dir" in info.context:
            base_dir = Path(info.context["base_dir"])
        candidate = base_dir / candidate
    return candidate.resolve(strict=False)


def _secret_ref(value: object) -> SecretRef:
    if isinstance(value, SecretRef):
        return value
    if type(value) is not str:
        raise ValueError("secret must be an env: or file: reference")
    return SecretRef.parse(value)


def _tuple(value: object) -> object:
    if isinstance(value, (list, tuple)):
        return tuple(value)
    return value


def _normalized_unique_selection_strings(
    value: tuple[str, ...],
    *,
    field: str,
) -> tuple[str, ...]:
    normalized = tuple(item.strip() for item in value)
    if any(not item for item in normalized):
        raise ValueError(f"selection {field} must not contain blank values")
    folded = tuple(item.casefold() for item in normalized)
    if len(set(folded)) != len(folded):
        raise ValueError(f"selection {field} must be case-insensitively unique")
    return normalized


def _normalized_archive_prefix(value: str) -> str:
    if value == "":
        return value
    parts = value.split("/")
    if (
        "\x00" in value
        or "\\" in value
        or value.startswith("/")
        or value.endswith("/")
        or any(part in {"", ".", ".."} for part in parts)
    ):
        raise ValueError("archive prefix must be a normalized POSIX relative path")
    return value


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _validate_multipart_size(
    *,
    provider: str,
    value: int,
    minimum: int,
) -> None:
    if not minimum <= value <= _OBJECT_STORAGE_MAX_MULTIPART_SIZE_BYTES:
        raise ValueError(
            f"{provider} multipart_size must be between {minimum} and "
            f"{_OBJECT_STORAGE_MAX_MULTIPART_SIZE_BYTES} bytes"
        )


NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
ArchiveTargetId = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$"),
]
DurationNs = Annotated[int, BeforeValidator(_duration_ns), Field(ge=0)]
PositiveDurationNs = Annotated[int, BeforeValidator(_duration_ns), Field(gt=0)]
SizeBytes = Annotated[int, BeforeValidator(_size_bytes), Field(ge=0)]
PositiveSizeBytes = Annotated[int, BeforeValidator(_size_bytes), Field(gt=0)]
ResolvedPath = Annotated[Path, BeforeValidator(_resolved_path)]
SecretReference = Annotated[SecretRef, BeforeValidator(_secret_ref)]
StringTuple = Annotated[tuple[NonEmptyString, ...], BeforeValidator(_tuple)]
DurationTuple = Annotated[tuple[PositiveDurationNs, ...], BeforeValidator(_tuple)]


class StrictModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        validate_by_alias=True,
        validate_by_name=False,
    )


class WorkerRestartConfig(StrictModel):
    base_backoff_ns: PositiveDurationNs = Field(1_000_000_000, alias="base_backoff")
    max_backoff_ns: PositiveDurationNs = Field(60_000_000_000, alias="max_backoff")
    max_attempts: Annotated[int, Field(gt=0)] = 10
    window_ns: PositiveDurationNs = Field(600_000_000_000, alias="window")
    healthy_reset_ns: PositiveDurationNs = Field(600_000_000_000, alias="healthy_reset")

    @model_validator(mode="after")
    def validate_backoff(self) -> Self:
        if self.base_backoff_ns > self.max_backoff_ns:
            raise ValueError("worker restart base_backoff must not exceed max_backoff")
        return self


class RuntimeConfig(StrictModel):
    admin_timeout_ns: PositiveDurationNs = Field(10_000_000_000, alias="admin_timeout")
    reload_prepare_timeout_ns: PositiveDurationNs = Field(
        15_000_000_000, alias="reload_prepare_timeout"
    )
    shutdown_deadline_ns: PositiveDurationNs = Field(
        30_000_000_000, alias="shutdown_deadline"
    )
    worker_restart: WorkerRestartConfig = Field(
        default_factory=lambda: WorkerRestartConfig.model_validate({})
    )


class NewListingsConfig(StrictModel):
    enabled: bool = True
    capture_duration_ns: PositiveDurationNs = Field(
        259_200_000_000_000,
        alias="capture_duration",
        le=_MAX_SIGNED_INT64,
    )
    initial_lookback_ns: DurationNs = Field(
        259_200_000_000_000,
        alias="initial_lookback",
        le=_MAX_SIGNED_INT64,
    )


class SelectionConfig(StrictModel):
    quote_assets: StringTuple = ("USDT",)
    fixed_pairs: StringTuple = ()
    top_n: Annotated[int, Field(ge=0, le=_MAX_SIGNED_INT64)] = 20
    refresh_interval_ns: PositiveDurationNs = Field(
        300_000_000_000,
        alias="refresh_interval",
        le=_MAX_SIGNED_INT64,
    )
    turnover_max_age_ns: PositiveDurationNs = Field(
        900_000_000_000,
        alias="turnover_max_age",
        le=_MAX_SIGNED_INT64,
    )
    exit_grace_ns: DurationNs = Field(
        1_800_000_000_000,
        alias="exit_grace",
        le=_MAX_SIGNED_INT64,
    )
    capacity_policy: Literal["degrade_low_priority_with_warning", "fail"] = (
        "degrade_low_priority_with_warning"
    )
    new_listings: NewListingsConfig = Field(
        default_factory=lambda: NewListingsConfig.model_validate({})
    )

    @field_validator("quote_assets", "fixed_pairs", mode="after")
    @classmethod
    def normalize_selection_identifiers(
        cls,
        value: tuple[str, ...],
        info: ValidationInfo,
    ) -> tuple[str, ...]:
        assert info.field_name is not None
        normalized = _normalized_unique_selection_strings(
            value,
            field=info.field_name,
        )
        if info.field_name == "quote_assets" and not normalized:
            raise ValueError("quote_assets must not be empty")
        return normalized


class LiveBookConfig(StrictModel):
    enabled: bool = True


class DeepSnapshotConfig(StrictModel):
    enabled: bool = True
    requested_interval_ns: PositiveDurationNs = Field(
        30_000_000_000, alias="requested_interval"
    )
    depth: Annotated[int, Field(gt=0)] | Literal["max_supported"] = "max_supported"
    overload_policy: Literal["stretch_with_warning", "fail"] = "stretch_with_warning"


class BooksConfig(StrictModel):
    live: LiveBookConfig = Field(default_factory=LiveBookConfig)
    deep_snapshot: DeepSnapshotConfig = Field(
        default_factory=lambda: DeepSnapshotConfig.model_validate({})
    )


class DateGatedFeaturePolicy(StrictModel):
    enabled: bool = True
    required: bool | None = None

    @model_validator(mode="after")
    def validate_disabled_policy(self) -> Self:
        if not self.enabled and self.required is True:
            raise ValueError("a disabled date-gated feature cannot be required")
        return self


class CapabilityPolicyConfig(StrictModel):
    date_gated_default_required: bool = False
    date_gated_features: dict[
        NonEmptyString,
        dict[NonEmptyString, DateGatedFeaturePolicy],
    ] = Field(default_factory=dict)

    @field_validator("date_gated_features", mode="after")
    @classmethod
    def normalize_date_gated_features(
        cls,
        value: dict[str, dict[str, DateGatedFeaturePolicy]],
    ) -> dict[str, dict[str, DateGatedFeaturePolicy]]:
        for exchange_id, features in value.items():
            if exchange_id != exchange_id.strip():
                raise ValueError(
                    "date-gated exchange IDs must not contain outer whitespace"
                )
            for feature_id in features:
                if feature_id != feature_id.strip():
                    raise ValueError(
                        "date-gated feature IDs must not contain outer whitespace"
                    )
        return {
            exchange_id: dict(sorted(features.items()))
            for exchange_id, features in sorted(value.items())
        }


class WriterConfig(StrictModel):
    flush_interval_ns: PositiveDurationNs = Field(500_000_000, alias="flush_interval")
    durability_slo_ns: PositiveDurationNs = Field(1_000_000_000, alias="durability_slo")
    durability_critical_ns: PositiveDurationNs = Field(
        5_000_000_000, alias="durability_critical"
    )
    max_sync_concurrency: Annotated[int, Field(gt=0)] = 8
    rotate_interval_ns: PositiveDurationNs = Field(_HOUR_NS, alias="rotate_interval")
    max_compressed_size_bytes: PositiveSizeBytes = Field(
        1024**3, alias="max_compressed_size"
    )
    zstd_level: Annotated[int, Field(ge=1, le=22)] = 3
    max_plain_frame_bytes: PositiveSizeBytes = Field(
        1024**2, alias="max_plain_frame_bytes"
    )


class IngressConfig(StrictModel):
    shard_max_records: Annotated[int, Field(gt=0)] = 10_000
    shard_max_bytes: PositiveSizeBytes = Field(64 * 1024**2, alias="shard_max_bytes")
    worker_max_bytes: PositiveSizeBytes = Field(512 * 1024**2, alias="worker_max_bytes")
    high_water_ratio: Annotated[float, Field(gt=0, lt=1)] = 0.80
    control_reserve_records: Annotated[int, Field(gt=0)] = 1_024
    control_reserve_bytes: PositiveSizeBytes = Field(
        8 * 1024**2, alias="control_reserve_bytes"
    )

    @model_validator(mode="after")
    def validate_capacity_relationships(self) -> Self:
        if self.worker_max_bytes < self.shard_max_bytes:
            raise ValueError("worker ingress bytes must cover at least one shard")
        if self.control_reserve_records > self.shard_max_records:
            raise ValueError("control reserve records exceed the control shard ceiling")
        if self.control_reserve_bytes > self.shard_max_bytes:
            raise ValueError("control reserve bytes exceed the control shard ceiling")
        if self.control_reserve_bytes >= self.worker_max_bytes:
            raise ValueError(
                "control reserve bytes must be smaller than the worker ingress limit"
            )
        return self


class DiskConfig(StrictModel):
    warning_free_ratio: Annotated[float, Field(gt=0, lt=1)] = 0.15
    critical_free_ratio: Annotated[float, Field(gt=0, lt=1)] = 0.05
    recovery_free_ratio: Annotated[float, Field(gt=0, lt=1)] = 0.20
    warning_free_bytes: SizeBytes | None = None
    critical_free_bytes: SizeBytes | None = None
    recovery_free_bytes: SizeBytes | None = None
    auto_resume: bool = False


class MaterializerConfig(StrictModel):
    enabled: bool = True
    delay_ns: DurationNs = Field(300_000_000_000, alias="delay")
    intervals_ns: DurationTuple = Field(
        (
            30_000_000_000,
            60_000_000_000,
            300_000_000_000,
            900_000_000_000,
            _HOUR_NS,
        ),
        alias="intervals",
    )
    revision_horizon_ns: DurationNs = Field(
        86_400_000_000_000, alias="revision_horizon"
    )

    @field_validator("intervals_ns", mode="after")
    @classmethod
    def sort_intervals(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(sorted(value))

    @model_validator(mode="after")
    def validate_hourly_windows(self) -> Self:
        if self.delay_ns > _HOUR_NS:
            raise ValueError("materializer delay must be between 0 and 60m")
        if len(set(self.intervals_ns)) != len(self.intervals_ns) or any(
            interval < 30_000_000_000 or interval > _HOUR_NS or _HOUR_NS % interval
            for interval in self.intervals_ns
        ):
            raise ValueError(
                "materializer intervals must be unique 30s..1h divisors of one UTC hour"
            )
        return self


class EgressConfig(StrictModel):
    id: NonEmptyString
    type: Literal["direct", "socks5", "socks5h"]
    quota_group: NonEmptyString
    url: SecretReference | None = None
    max_http_concurrency: Annotated[int, Field(gt=0)] = 8
    max_ws_connections: Annotated[int, Field(gt=0)] = 20

    @model_validator(mode="before")
    @classmethod
    def default_quota_group(cls, value: object) -> object:
        if isinstance(value, Mapping) and value.get("quota_group") is None:
            normalized = dict(value)
            normalized["quota_group"] = value.get("id")
            return normalized
        return value

    @model_validator(mode="after")
    def validate_proxy_shape(self) -> Self:
        if self.type == "direct" and self.url is not None:
            raise ValueError("direct egress must not configure a URL")
        if self.type != "direct" and self.url is None:
            raise ValueError(f"{self.type} egress requires a secret URL reference")
        return self


class AssignmentConfig(StrictModel):
    strategy: Literal["rendezvous_hash"] = "rendezvous_hash"


class RetryConfig(StrictModel):
    rest_max_attempts: Annotated[int, Field(gt=0)] = 5
    base_backoff_ns: PositiveDurationNs = Field(250_000_000, alias="base_backoff")
    max_backoff_ns: PositiveDurationNs = Field(30_000_000_000, alias="max_backoff")
    ws_reconnect_max_backoff_ns: PositiveDurationNs = Field(
        60_000_000_000, alias="ws_reconnect_max_backoff"
    )

    @model_validator(mode="after")
    def validate_backoff(self) -> Self:
        if self.base_backoff_ns > self.max_backoff_ns:
            raise ValueError("REST base_backoff must not exceed max_backoff")
        return self


class SchedulerConfig(StrictModel):
    deep_snapshot_max_interval_ns: PositiveDurationNs = Field(
        900_000_000_000, alias="deep_snapshot_max_interval"
    )
    recovery_step_ratio: Annotated[float, Field(gt=0, le=1)] = 0.20
    healthy_refreshes_before_step_down: Annotated[int, Field(gt=0)] = 3
    max_pending_jobs: Annotated[
        int,
        Field(gt=0, le=_MAX_SCHEDULER_COLLECTION_ITEMS),
    ] = 10_000
    event_history_limit: Annotated[
        int,
        Field(gt=0, le=_MAX_SCHEDULER_COLLECTION_ITEMS),
    ] = 1_024


def _default_egress_pool() -> tuple[EgressConfig, ...]:
    return (EgressConfig.model_validate({"id": "direct", "type": "direct"}),)


class NetworkConfig(StrictModel):
    egress_pool: Annotated[
        tuple[EgressConfig, ...], BeforeValidator(_tuple), Field(min_length=1)
    ] = Field(default_factory=_default_egress_pool)
    assignment: AssignmentConfig = Field(default_factory=AssignmentConfig)
    retry: RetryConfig = Field(default_factory=lambda: RetryConfig.model_validate({}))
    scheduler: SchedulerConfig = Field(
        default_factory=lambda: SchedulerConfig.model_validate({})
    )


class ArchiveRetryConfig(StrictModel):
    max_attempts: Annotated[int, Field(gt=0)] = 5
    base_backoff_ns: PositiveDurationNs = Field(1_000_000_000, alias="base_backoff")
    max_backoff_ns: PositiveDurationNs = Field(60_000_000_000, alias="max_backoff")


class CompressionConfig(StrictModel):
    enabled: bool = False
    mode: Literal["off", "auto", "zstd"] = "auto"
    codec: Literal["zstd"] = "zstd"
    level: Annotated[int, Field(ge=-7, le=22)] = 3
    min_size_bytes: SizeBytes = Field(1024**2, alias="min_size")
    recompress: bool = False


class AliyunCredentials(StrictModel):
    access_key_id: SecretReference
    access_key_secret: SecretReference
    security_token: SecretReference | None = None


class S3Credentials(StrictModel):
    access_key_id: SecretReference
    secret_access_key: SecretReference
    session_token: SecretReference | None = None


class MountGuardConfig(StrictModel):
    path: ResolvedPath
    expected: SecretReference


class ArchiveTargetBase(StrictModel):
    id: ArchiveTargetId
    enabled: bool = True
    required: bool = False
    prefix: str = ""
    concurrency: Annotated[int, Field(gt=0)] = 4
    multipart_size_bytes: PositiveSizeBytes = Field(
        64 * 1024**2, alias="multipart_size"
    )
    retry: ArchiveRetryConfig = Field(
        default_factory=lambda: ArchiveRetryConfig.model_validate({})
    )
    compression: CompressionConfig = Field(
        default_factory=lambda: CompressionConfig.model_validate({})
    )

    @field_validator("prefix", mode="after")
    @classmethod
    def validate_prefix(cls, value: str) -> str:
        return _normalized_archive_prefix(value)

    @model_validator(mode="after")
    def validate_required_target(self) -> Self:
        if self.required and not self.enabled:
            raise ValueError("required archive target cannot be disabled")
        return self


class AliyunOssTargetConfig(ArchiveTargetBase):
    type: Literal["aliyun_oss"]
    bucket: NonEmptyString
    endpoint: NonEmptyString
    region: NonEmptyString | None = None
    storage_class: NonEmptyString | None = None
    credentials: AliyunCredentials

    @model_validator(mode="after")
    def validate_multipart_size(self) -> Self:
        _validate_multipart_size(
            provider="OSS",
            value=self.multipart_size_bytes,
            minimum=_OSS_MIN_MULTIPART_SIZE_BYTES,
        )
        return self


class S3TargetConfig(ArchiveTargetBase):
    type: Literal["s3"]
    bucket: NonEmptyString
    endpoint: NonEmptyString | None = None
    region: NonEmptyString | None = None
    storage_class: NonEmptyString | None = None
    addressing_style: Literal["auto", "path", "virtual"] = "auto"
    credentials: S3Credentials

    @model_validator(mode="after")
    def validate_multipart_size(self) -> Self:
        _validate_multipart_size(
            provider="S3",
            value=self.multipart_size_bytes,
            minimum=_S3_MIN_MULTIPART_SIZE_BYTES,
        )
        return self


class FilesystemTargetConfig(ArchiveTargetBase):
    type: Literal["filesystem"]
    root: ResolvedPath
    mount_root: ResolvedPath
    mount_guard: MountGuardConfig
    durability_capability: Literal[
        "backup_only",
        "operator_attested_fsync_readback",
    ] = "backup_only"

    @model_validator(mode="before")
    @classmethod
    def infer_legacy_mount_root(cls, value: object) -> object:
        if not isinstance(value, Mapping) or "mount_root" in value:
            return value
        guard = value.get("mount_guard")
        if not isinstance(guard, Mapping):
            return value
        guard_path = guard.get("path")
        if type(guard_path) is not str:
            return value
        normalized = dict(value)
        normalized["mount_root"] = str(Path(guard_path).parent)
        return normalized

    @model_validator(mode="after")
    def validate_mount_paths(self) -> Self:
        if self.root != self.mount_root and self.mount_root not in self.root.parents:
            raise ValueError("filesystem root must be inside mount_root")
        guard_path = self.mount_guard.path
        if guard_path == self.mount_root or self.mount_root not in guard_path.parents:
            raise ValueError("filesystem mount_guard.path must be inside mount_root")
        if guard_path == self.root:
            raise ValueError("filesystem mount_guard.path must not equal root")
        return self


ArchiveTargetConfig = Annotated[
    AliyunOssTargetConfig | S3TargetConfig | FilesystemTargetConfig,
    Field(discriminator="type"),
]


class ArchiveConfig(StrictModel):
    targets: Annotated[tuple[ArchiveTargetConfig, ...], BeforeValidator(_tuple)] = ()

    @model_validator(mode="after")
    def validate_unique_target_ids(self) -> Self:
        target_ids = [target.id for target in self.targets]
        if len(set(target_ids)) != len(target_ids):
            raise ValueError("archive target IDs must be unique")
        return self


class LocalCleanupConfig(StrictModel):
    enabled: bool = False
    grace_ns: DurationNs = Field(86_400_000_000_000, alias="grace")


class NewListingsOverride(StrictModel):
    enabled: bool | None = None
    capture_duration_ns: PositiveDurationNs | None = Field(
        None,
        alias="capture_duration",
        le=_MAX_SIGNED_INT64,
    )
    initial_lookback_ns: DurationNs | None = Field(
        None,
        alias="initial_lookback",
        le=_MAX_SIGNED_INT64,
    )


class SelectionOverride(StrictModel):
    quote_assets: StringTuple | None = None
    fixed_pairs: StringTuple | None = None
    top_n: Annotated[int, Field(ge=0, le=_MAX_SIGNED_INT64)] | None = None
    refresh_interval_ns: PositiveDurationNs | None = Field(
        None,
        alias="refresh_interval",
        le=_MAX_SIGNED_INT64,
    )
    turnover_max_age_ns: PositiveDurationNs | None = Field(
        None,
        alias="turnover_max_age",
        le=_MAX_SIGNED_INT64,
    )
    exit_grace_ns: DurationNs | None = Field(
        None,
        alias="exit_grace",
        le=_MAX_SIGNED_INT64,
    )
    capacity_policy: Literal["degrade_low_priority_with_warning", "fail"] | None = None
    new_listings: NewListingsOverride | None = None

    @field_validator("quote_assets", "fixed_pairs", mode="after")
    @classmethod
    def normalize_selection_identifiers(
        cls,
        value: tuple[str, ...] | None,
        info: ValidationInfo,
    ) -> tuple[str, ...] | None:
        if value is None:
            return None
        assert info.field_name is not None
        normalized = _normalized_unique_selection_strings(
            value,
            field=info.field_name,
        )
        if info.field_name == "quote_assets" and not normalized:
            raise ValueError("quote_assets must not be empty")
        return normalized


class DeepSnapshotOverride(StrictModel):
    enabled: bool | None = None
    requested_interval_ns: PositiveDurationNs | None = Field(
        None, alias="requested_interval"
    )
    depth: Annotated[int, Field(gt=0)] | Literal["max_supported"] | None = None
    overload_policy: Literal["stretch_with_warning", "fail"] | None = None


class BooksOverride(StrictModel):
    live: LiveBookConfig | None = None
    deep_snapshot: DeepSnapshotOverride | None = None


class SymbolOverride(StrictModel):
    enabled: bool = True
    selection: SelectionOverride = Field(
        default_factory=lambda: SelectionOverride.model_validate({})
    )
    books: BooksOverride = Field(default_factory=BooksOverride)

    @model_validator(mode="after")
    def reject_symbol_fixed_pairs(self) -> Self:
        if self.selection.fixed_pairs is not None:
            raise ValueError(
                "selection.fixed_pairs cannot be configured at symbol scope"
            )
        return self


class MarketOverride(StrictModel):
    enabled: bool = True
    selection: SelectionOverride = Field(
        default_factory=lambda: SelectionOverride.model_validate({})
    )
    books: BooksOverride = Field(default_factory=BooksOverride)
    symbols: dict[str, SymbolOverride] = Field(default_factory=dict)


class ExchangeOverride(StrictModel):
    enabled: bool = True
    endpoints: dict[str, NonEmptyString] = Field(default_factory=dict)
    selection: SelectionOverride = Field(
        default_factory=lambda: SelectionOverride.model_validate({})
    )
    books: BooksOverride = Field(default_factory=BooksOverride)
    markets: dict[str, MarketOverride] = Field(default_factory=dict)


class CollectorConfig(StrictModel):
    profile: NonEmptyString = "research-default"
    data_root: ResolvedPath
    state_root: ResolvedPath
    runtime: RuntimeConfig = Field(
        default_factory=lambda: RuntimeConfig.model_validate({})
    )
    selection: SelectionConfig = Field(
        default_factory=lambda: SelectionConfig.model_validate({})
    )
    books: BooksConfig = Field(default_factory=BooksConfig)
    capabilities: CapabilityPolicyConfig = Field(default_factory=CapabilityPolicyConfig)
    writer: WriterConfig = Field(
        default_factory=lambda: WriterConfig.model_validate({})
    )
    ingress: IngressConfig = Field(
        default_factory=lambda: IngressConfig.model_validate({})
    )
    disk: DiskConfig = Field(default_factory=DiskConfig)
    materializer: MaterializerConfig = Field(
        default_factory=lambda: MaterializerConfig.model_validate({})
    )
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    archive: ArchiveConfig = Field(default_factory=ArchiveConfig)
    local_cleanup: LocalCleanupConfig = Field(
        default_factory=lambda: LocalCleanupConfig.model_validate({})
    )
    exchanges: dict[str, ExchangeOverride] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_cross_model_invariants(self) -> Self:
        if self.writer.flush_interval_ns * 2 > self.writer.durability_slo_ns:
            raise ValueError("writer.flush_interval must be <= durability_slo / 2")
        if not (
            0
            < self.disk.critical_free_ratio
            < self.disk.warning_free_ratio
            < self.disk.recovery_free_ratio
            < 1
        ):
            raise ValueError(
                "disk thresholds must satisfy critical < warning < recovery"
            )

        egress_ids = [egress.id for egress in self.network.egress_pool]
        if len(set(egress_ids)) != len(egress_ids):
            raise ValueError("egress IDs must be unique")
        for target in self.archive.targets:
            if isinstance(target, FilesystemTargetConfig) and any(
                _paths_overlap(self.data_root, path)
                for path in (
                    target.mount_root,
                    target.root,
                    target.mount_guard.path,
                )
            ):
                raise ValueError(
                    "archive filesystem mount_root, root, and mount_guard.path "
                    "must not overlap data_root"
                )
        if self.local_cleanup.enabled:
            required_targets = tuple(
                target
                for target in self.archive.targets
                if target.enabled and target.required
            )
            if not required_targets:
                raise ValueError(
                    "local cleanup requires at least one enabled required target"
                )
            backup_only_filesystems = tuple(
                target.id
                for target in required_targets
                if isinstance(target, FilesystemTargetConfig)
                and target.durability_capability != "operator_attested_fsync_readback"
            )
            if backup_only_filesystems:
                raise ValueError(
                    "required filesystem targets must set durability_capability="
                    "operator_attested_fsync_readback before local cleanup: "
                    + ", ".join(sorted(backup_only_filesystems))
                )
        return self


class ConfigSecretError(ValueError):
    def __init__(self, issues: str | list[str]) -> None:
        normalized = [issues] if isinstance(issues, str) else issues
        super().__init__("invalid secret configuration: " + "; ".join(normalized))
        self.issues = tuple(normalized)


def iter_secret_refs(value: object) -> Iterator[SecretRef]:
    if isinstance(value, SecretRef):
        yield value
        return
    if isinstance(value, BaseModel):
        for name in type(value).model_fields:
            yield from iter_secret_refs(getattr(value, name))
        return
    if isinstance(value, Mapping):
        for item in value.values():
            yield from iter_secret_refs(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from iter_secret_refs(item)


def validate_secret_snapshot(
    config: CollectorConfig,
    snapshot: SecretSnapshot,
) -> None:
    issues: list[str] = []
    for egress in config.network.egress_pool:
        if egress.type == "direct":
            continue
        if egress.url is None:
            issues.append(
                f"egress {egress.id} is missing its {egress.type} URL reference"
            )
            continue
        try:
            secret_url = snapshot.value_for(egress.url).reveal()
        except ValueError:
            issues.append(f"egress {egress.id} secret was not resolved")
            continue
        try:
            parsed = urlsplit(secret_url)
        except ValueError:
            issues.append(f"egress {egress.id} requires a valid {egress.type} URL")
            continue
        if parsed.scheme != egress.type or not parsed.hostname:
            issues.append(f"egress {egress.id} requires a valid {egress.type} URL")

    if issues:
        raise ConfigSecretError(issues)


def validate_capability_registry_sha256(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise ValueError("capability_registry_sha256 must be lowercase SHA-256")
    return value
