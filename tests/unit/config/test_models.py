from collections.abc import Callable
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from crypto_collector.config.models import (
    ArchiveConfig,
    CollectorConfig,
    ConfigSecretError,
    FilesystemTargetConfig,
    IngressConfig,
    S3TargetConfig,
    SelectionConfig,
    SelectionOverride,
    SymbolOverride,
    WriterConfig,
    iter_secret_refs,
    validate_secret_snapshot,
)
from crypto_collector.config.primitives import SecretSnapshot
from crypto_collector.config.report import format_validation_error

BASE: dict[str, Any] = {
    "data_root": "./data",
    "state_root": "./state",
    "writer": {
        "flush_interval": "500ms",
        "durability_slo": "1s",
        "durability_critical": "5s",
        "max_sync_concurrency": 8,
        "rotate_interval": "1h",
        "max_compressed_size": "1GiB",
    },
    "selection": {
        "quote_assets": ["USDT"],
        "fixed_pairs": ["BTC/USDT"],
        "top_n": 20,
    },
    "ingress": {
        "shard_max_records": 10_000,
        "shard_max_bytes": "64MiB",
        "worker_max_bytes": "512MiB",
        "high_water_ratio": 0.80,
        "control_reserve_records": 1_024,
        "control_reserve_bytes": "8MiB",
    },
    "network": {
        "egress_pool": [
            {"id": "direct", "type": "direct", "quota_group": "direct"},
            {
                "id": "socks",
                "type": "socks5h",
                "quota_group": "proxy-nat",
                "url": "env:SOCKS_URL",
            },
        ]
    },
}


def _s3_archive_target(**overrides: object) -> dict[str, object]:
    target: dict[str, object] = {
        "id": "s3-primary",
        "type": "s3",
        "bucket": "market-data",
        "credentials": {
            "access_key_id": "env:S3_ACCESS_KEY_ID",
            "secret_access_key": "env:S3_SECRET_ACCESS_KEY",
        },
    }
    target.update(overrides)
    return target


def _oss_archive_target(**overrides: object) -> dict[str, object]:
    target: dict[str, object] = {
        "id": "oss-primary",
        "type": "aliyun_oss",
        "bucket": "market-data",
        "endpoint": "https://oss.example.test",
        "credentials": {
            "access_key_id": "env:OSS_ACCESS_KEY_ID",
            "access_key_secret": "env:OSS_ACCESS_KEY_SECRET",
        },
    }
    target.update(overrides)
    return target


def _filesystem_archive_target(
    mount_root: Path,
    **overrides: object,
) -> dict[str, object]:
    target: dict[str, object] = {
        "id": "mounted-backup",
        "type": "filesystem",
        "root": str(mount_root / "archive"),
        "mount_root": str(mount_root),
        "mount_guard": {
            "path": str(mount_root / ".collector-mount-id"),
            "expected": "env:MOUNT_GUARD",
        },
    }
    target.update(overrides)
    return target


def test_flush_interval_must_leave_half_the_slo_as_budget() -> None:
    invalid = BASE | {"writer": BASE["writer"] | {"flush_interval": "750ms"}}
    with pytest.raises(ValidationError, match="flush_interval"):
        CollectorConfig.model_validate(invalid)


def test_writer_config_owns_frame_codec_limits() -> None:
    config = WriterConfig.model_validate(
        {"zstd_level": 7, "max_plain_frame_bytes": "2MiB"}
    )

    assert config.zstd_level == 7
    assert config.max_plain_frame_bytes == 2 * 1024**2


@pytest.mark.parametrize("level", [0, 23, True, 3.0])
def test_writer_config_rejects_unsupported_zstd_level(level: object) -> None:
    with pytest.raises(ValidationError):
        WriterConfig.model_validate({"zstd_level": level})


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"shard_max_records": 1, "control_reserve_records": 2}, "records"),
        ({"shard_max_bytes": "1KiB", "control_reserve_bytes": "2KiB"}, "bytes"),
        ({"shard_max_bytes": "2KiB", "worker_max_bytes": "1KiB"}, "worker"),
        (
            {
                "shard_max_bytes": "2KiB",
                "worker_max_bytes": "2KiB",
                "control_reserve_bytes": "2KiB",
            },
            "worker",
        ),
    ],
)
def test_control_reserve_must_fit_ingress_ceilings(
    override: dict[str, object],
    message: str,
) -> None:
    invalid = deepcopy(BASE["ingress"])
    invalid.update(override)

    with pytest.raises(ValidationError, match=message):
        IngressConfig.model_validate(invalid)


def test_control_reserve_may_equal_its_shard_ceiling() -> None:
    source = deepcopy(BASE["ingress"])
    source.update(
        {
            "control_reserve_records": source["shard_max_records"],
            "control_reserve_bytes": source["shard_max_bytes"],
        }
    )

    value = IngressConfig.model_validate(source)

    assert value.control_reserve_records == value.shard_max_records
    assert value.control_reserve_bytes == value.shard_max_bytes


def test_unknown_key_is_rejected() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CollectorConfig.model_validate(BASE | {"typo_key": True})


def test_scalar_types_are_not_coerced() -> None:
    invalid = BASE | {"selection": BASE["selection"] | {"top_n": "20"}}
    with pytest.raises(ValidationError, match="int_type"):
        CollectorConfig.model_validate(invalid)


def test_runtime_safety_defaults_are_explicit() -> None:
    config = CollectorConfig.model_validate(BASE)
    runtime = config.runtime

    assert runtime.admin_timeout_ns == 10_000_000_000
    assert runtime.reload_prepare_timeout_ns == 15_000_000_000
    assert runtime.shutdown_deadline_ns == 30_000_000_000
    assert runtime.worker_restart.max_attempts == 10
    assert config.network.retry.rest_max_attempts == 5
    assert config.network.scheduler.deep_snapshot_max_interval_ns == 900_000_000_000
    assert config.network.scheduler.max_pending_jobs == 10_000
    assert config.network.scheduler.event_history_limit == 1_024
    assert config.selection.turnover_max_age_ns == 900_000_000_000


def test_date_gated_feature_policy_is_explicit_and_strict() -> None:
    source = deepcopy(BASE)
    source["capabilities"] = {
        "date_gated_default_required": False,
        "date_gated_features": {
            "okx": {
                "books_rpi": {"required": True},
            }
        },
    }

    config = CollectorConfig.model_validate(source)

    policy = config.capabilities.date_gated_features["okx"]["books_rpi"]
    assert policy.enabled is True
    assert policy.required is True

    source["capabilities"]["date_gated_features"]["okx"]["books_rpi"] = {
        "required": True,
        "typo": True,
    }
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CollectorConfig.model_validate(source)

    source["capabilities"]["date_gated_features"]["okx"]["books_rpi"] = {
        "enabled": False,
        "required": True,
    }
    with pytest.raises(ValidationError, match="disabled.*cannot be required"):
        CollectorConfig.model_validate(source)


def test_selection_turnover_max_age_is_configurable() -> None:
    config = CollectorConfig.model_validate(
        BASE | {"selection": BASE["selection"] | {"turnover_max_age": "30m"}}
    )

    assert config.selection.turnover_max_age_ns == 1_800_000_000_000


@pytest.mark.parametrize("field", ["quote_assets", "fixed_pairs"])
def test_selection_identifiers_are_trimmed_and_casefold_unique(field: str) -> None:
    selection = deepcopy(BASE["selection"])
    selection["quote_assets"] = [" USDT "]
    selection["fixed_pairs"] = [" BTC/USDT "]
    config = CollectorConfig.model_validate(BASE | {"selection": selection})

    assert config.selection.quote_assets == ("USDT",)
    assert config.selection.fixed_pairs == ("BTC/USDT",)

    selection[field] = ["USDT", " usdt "]
    with pytest.raises(ValidationError, match=f"{field}.*unique"):
        CollectorConfig.model_validate(BASE | {"selection": selection})


@pytest.mark.parametrize("field", ["quote_assets", "fixed_pairs"])
def test_selection_identifiers_reject_blank_values(field: str) -> None:
    selection = deepcopy(BASE["selection"])
    selection[field] = ["  "]

    with pytest.raises(ValidationError, match=field):
        CollectorConfig.model_validate(BASE | {"selection": selection})


def test_selection_quote_assets_cannot_be_empty() -> None:
    selection = deepcopy(BASE["selection"])
    selection["quote_assets"] = []

    with pytest.raises(ValidationError, match="quote_assets.*empty"):
        CollectorConfig.model_validate(BASE | {"selection": selection})


def test_selection_override_quote_assets_cannot_be_empty() -> None:
    with pytest.raises(ValidationError, match="quote_assets.*empty"):
        SelectionOverride.model_validate({"quote_assets": []})


def test_symbol_scope_rejects_fixed_pair_requests() -> None:
    with pytest.raises(ValidationError, match="fixed_pairs.*symbol scope"):
        SymbolOverride.model_validate({"selection": {"fixed_pairs": ["ETH/USDT"]}})


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (SelectionConfig, {"top_n": 2**63}),
        (SelectionConfig, {"refresh_interval": "9223372037s"}),
        (SelectionConfig, {"turnover_max_age": "9223372037s"}),
        (SelectionConfig, {"exit_grace": "9223372037s"}),
        (
            SelectionConfig,
            {"new_listings": {"capture_duration": "9223372037s"}},
        ),
        (
            SelectionConfig,
            {"new_listings": {"initial_lookback": "9223372037s"}},
        ),
        (SelectionOverride, {"top_n": 2**63}),
        (SelectionOverride, {"refresh_interval": "9223372037s"}),
        (SelectionOverride, {"turnover_max_age": "9223372037s"}),
        (SelectionOverride, {"exit_grace": "9223372037s"}),
        (
            SelectionOverride,
            {"new_listings": {"capture_duration": "9223372037s"}},
        ),
        (
            SelectionOverride,
            {"new_listings": {"initial_lookback": "9223372037s"}},
        ),
    ],
)
def test_selection_config_and_overrides_fit_signed_int64(
    model: type[SelectionConfig | SelectionOverride],
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="less than or equal"):
        model.model_validate(payload)


@pytest.mark.parametrize("field", ["max_pending_jobs", "event_history_limit"])
def test_scheduler_bounds_must_be_positive(field: str) -> None:
    invalid = deepcopy(BASE)
    invalid["network"]["scheduler"] = {field: 0}

    with pytest.raises(ValidationError, match=field):
        CollectorConfig.model_validate(invalid)


@pytest.mark.parametrize("field", ["max_pending_jobs", "event_history_limit"])
def test_scheduler_bounds_reject_unallocatable_values(field: str) -> None:
    invalid = deepcopy(BASE)
    invalid["network"]["scheduler"] = {field: 10**100}

    with pytest.raises(ValidationError, match=field):
        CollectorConfig.model_validate(invalid)


def test_materializer_intervals_fit_hourly_revision_partitions() -> None:
    invalid = BASE | {"materializer": {"intervals": ["7m"]}}
    with pytest.raises(ValidationError, match="UTC hour"):
        CollectorConfig.model_validate(invalid)


def test_materializer_intervals_are_canonicalized() -> None:
    config = CollectorConfig.model_validate(
        BASE | {"materializer": {"intervals": ["5m", "30s", "1m"]}}
    )

    assert config.materializer.intervals_ns == (
        30_000_000_000,
        60_000_000_000,
        300_000_000_000,
    )


def test_socks_type_must_match_resolved_url_scheme(monkeypatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5://127.0.0.1:1080")
    config = CollectorConfig.model_validate(BASE)
    secrets = SecretSnapshot.resolve_all(iter_secret_refs(config))

    with pytest.raises(ConfigSecretError, match="socks5h"):
        validate_secret_snapshot(config, secrets)


def test_duplicate_egress_ids_are_rejected() -> None:
    invalid = deepcopy(BASE)
    invalid["network"]["egress_pool"].append(
        {"id": "direct", "type": "direct", "quota_group": "other"}
    )

    with pytest.raises(ValidationError, match="egress IDs"):
        CollectorConfig.model_validate(invalid)


@pytest.mark.parametrize(
    "disk",
    [
        {
            "critical_free_ratio": 0.16,
            "warning_free_ratio": 0.15,
            "recovery_free_ratio": 0.20,
        },
        {
            "critical_free_ratio": 0.05,
            "warning_free_ratio": 0.25,
            "recovery_free_ratio": 0.20,
        },
    ],
)
def test_disk_thresholds_are_strictly_ordered(disk: dict[str, float]) -> None:
    with pytest.raises(ValidationError, match="critical < warning < recovery"):
        CollectorConfig.model_validate(BASE | {"disk": disk})


def test_direct_egress_rejects_proxy_url() -> None:
    invalid = deepcopy(BASE)
    invalid["network"]["egress_pool"][0]["url"] = "env:SOCKS_URL"

    with pytest.raises(ValidationError, match="direct.*URL"):
        CollectorConfig.model_validate(invalid)


def test_relative_paths_resolve_against_loader_context(tmp_path) -> None:
    config = CollectorConfig.model_validate(BASE, context={"base_dir": tmp_path})

    assert config.data_root == (tmp_path / "data").resolve()
    assert config.state_root == (tmp_path / "state").resolve()


def test_egress_quota_group_defaults_to_egress_id() -> None:
    config = CollectorConfig.model_validate(
        BASE | {"network": {"egress_pool": [{"id": "direct", "type": "direct"}]}}
    )

    assert config.network.egress_pool[0].quota_group == "direct"


def test_at_least_one_egress_is_required() -> None:
    with pytest.raises(ValidationError, match="egress_pool"):
        CollectorConfig.model_validate(BASE | {"network": {"egress_pool": []}})


def test_filesystem_archive_must_not_be_inside_data_root(tmp_path) -> None:
    invalid = deepcopy(BASE)
    invalid["data_root"] = str(tmp_path / "data")
    invalid["state_root"] = str(tmp_path / "state")
    invalid["archive"] = {
        "targets": [
            {
                "id": "bad-copy",
                "type": "filesystem",
                "root": str(tmp_path / "data" / "backup"),
                "mount_guard": {
                    "path": str(tmp_path / "guard"),
                    "expected": "env:MOUNT_GUARD",
                },
            }
        ]
    }

    with pytest.raises(ValidationError, match="data_root"):
        CollectorConfig.model_validate(invalid)


def test_required_archive_target_cannot_be_disabled() -> None:
    target = _s3_archive_target(required=True, enabled=False)

    with pytest.raises(ValidationError, match="required.*cannot be disabled"):
        ArchiveConfig.model_validate({"targets": [target]})


@pytest.mark.parametrize("targets", [[], [_s3_archive_target(required=False)]])
def test_cleanup_requires_an_enabled_required_target(
    targets: list[dict[str, object]],
) -> None:
    source = deepcopy(BASE)
    source["archive"] = {"targets": targets}
    source["local_cleanup"] = {"enabled": True}

    with pytest.raises(ValidationError, match="cleanup.*enabled required target"):
        CollectorConfig.model_validate(source)


@pytest.mark.parametrize(
    "target_id",
    ["Uppercase", "../escape", "a/b", ".", "two words", "a" * 65],
)
def test_archive_target_id_must_be_lowercase_and_path_safe(target_id: str) -> None:
    with pytest.raises(ValidationError, match="id"):
        ArchiveConfig.model_validate({"targets": [_s3_archive_target(id=target_id)]})


def test_archive_target_ids_are_unique() -> None:
    with pytest.raises(ValidationError, match="archive target IDs must be unique"):
        ArchiveConfig.model_validate(
            {
                "targets": [
                    _s3_archive_target(),
                    _oss_archive_target(id="s3-primary"),
                ]
            }
        )


@pytest.mark.parametrize(
    "prefix",
    ["/absolute", "trailing/", "a//b", "a/./b", "a/../b", "a\\b", "\x00"],
)
def test_archive_prefix_must_be_normalized_posix_relative(prefix: str) -> None:
    with pytest.raises(ValidationError, match="prefix"):
        ArchiveConfig.model_validate({"targets": [_s3_archive_target(prefix=prefix)]})


def test_archive_prefix_accepts_empty_or_normalized_relative_values() -> None:
    default = ArchiveConfig.model_validate({"targets": [_s3_archive_target()]})
    explicit = ArchiveConfig.model_validate(
        {"targets": [_s3_archive_target(prefix="research/raw/v1")]}
    )

    assert default.targets[0].prefix == ""
    assert explicit.targets[0].prefix == "research/raw/v1"


@pytest.mark.parametrize("addressing_style", ["auto", "path", "virtual"])
def test_s3_addressing_style_is_explicit(addressing_style: str) -> None:
    config = ArchiveConfig.model_validate(
        {"targets": [_s3_archive_target(addressing_style=addressing_style)]}
    )
    target = config.targets[0]

    assert isinstance(target, S3TargetConfig)
    assert target.addressing_style == addressing_style


def test_s3_addressing_style_defaults_to_auto() -> None:
    config = ArchiveConfig.model_validate({"targets": [_s3_archive_target()]})
    target = config.targets[0]

    assert isinstance(target, S3TargetConfig)
    assert target.addressing_style == "auto"


def test_s3_addressing_style_rejects_unknown_value() -> None:
    with pytest.raises(ValidationError, match="addressing_style"):
        ArchiveConfig.model_validate(
            {"targets": [_s3_archive_target(addressing_style="dns-magic")]}
        )


def test_archive_retry_base_backoff_must_not_exceed_max_backoff() -> None:
    with pytest.raises(ValidationError, match="base_backoff.*max_backoff"):
        ArchiveConfig.model_validate(
            {
                "targets": [
                    _s3_archive_target(
                        retry={
                            "base_backoff": "60s",
                            "max_backoff": "1s",
                        }
                    )
                ]
            }
        )


@pytest.mark.parametrize("target_factory", [_s3_archive_target, _oss_archive_target])
@pytest.mark.parametrize(
    "endpoint",
    [
        "https://user:plaintext-canary@example.test",
        "https://example.test?token=plaintext-canary",
        "https://example.test/#plaintext-canary",
        "https://example.test/base-path",
        "ftp://example.test",
        "https://example.test:99999",
        "not-a-url",
    ],
)
def test_archive_endpoint_rejects_unsafe_or_noncanonical_urls(
    target_factory: Callable[..., dict[str, object]],
    endpoint: str,
) -> None:
    with pytest.raises(ValidationError) as captured:
        ArchiveConfig.model_validate({"targets": [target_factory(endpoint=endpoint)]})

    assert "plaintext-canary" not in format_validation_error(captured.value)


@pytest.mark.parametrize("endpoint", ["https://example.test", "http://127.0.0.1:9000/"])
def test_archive_endpoint_accepts_root_http_urls(endpoint: str) -> None:
    ArchiveConfig.model_validate({"targets": [_s3_archive_target(endpoint=endpoint)]})


@pytest.mark.parametrize("multipart_size", ["5MiB", "5GiB"])
def test_s3_multipart_size_accepts_provider_bounds(multipart_size: str) -> None:
    ArchiveConfig.model_validate(
        {"targets": [_s3_archive_target(multipart_size=multipart_size)]}
    )


@pytest.mark.parametrize("multipart_size", ["4MiB", "6GiB"])
def test_s3_multipart_size_rejects_values_outside_provider_bounds(
    multipart_size: str,
) -> None:
    with pytest.raises(ValidationError, match="S3 multipart_size"):
        ArchiveConfig.model_validate(
            {"targets": [_s3_archive_target(multipart_size=multipart_size)]}
        )


@pytest.mark.parametrize("multipart_size", ["100KiB", "5GiB"])
def test_oss_multipart_size_accepts_provider_bounds(multipart_size: str) -> None:
    ArchiveConfig.model_validate(
        {"targets": [_oss_archive_target(multipart_size=multipart_size)]}
    )


@pytest.mark.parametrize("multipart_size", ["99KiB", "6GiB"])
def test_oss_multipart_size_rejects_values_outside_provider_bounds(
    multipart_size: str,
) -> None:
    with pytest.raises(ValidationError, match="OSS multipart_size"):
        ArchiveConfig.model_validate(
            {"targets": [_oss_archive_target(multipart_size=multipart_size)]}
        )


def test_filesystem_target_defaults_to_backup_only_and_infers_mount_root() -> None:
    config = ArchiveConfig.model_validate(
        {
            "targets": [
                {
                    "id": "legacy-mounted-backup",
                    "type": "filesystem",
                    "root": "/mnt/webdav/archive",
                    "mount_guard": {
                        "path": "/mnt/webdav/.collector-mount-id",
                        "expected": "env:MOUNT_GUARD",
                    },
                }
            ]
        }
    )
    target = config.targets[0]

    assert isinstance(target, FilesystemTargetConfig)
    assert target.durability_capability == "backup_only"
    assert target.mount_root == Path("/mnt/webdav")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"root": "/srv/archive"}, "root.*mount_root"),
        (
            {
                "mount_guard": {
                    "path": "/srv/.collector-mount-id",
                    "expected": "env:MOUNT_GUARD",
                }
            },
            "mount_guard.*mount_root",
        ),
    ],
)
def test_filesystem_root_and_guard_must_be_inside_mount_root(
    overrides: dict[str, object],
    message: str,
) -> None:
    target = _filesystem_archive_target(Path("/mnt/webdav"), **overrides)

    with pytest.raises(ValidationError, match=message):
        ArchiveConfig.model_validate({"targets": [target]})


def test_filesystem_mount_root_must_not_overlap_data_root(tmp_path) -> None:
    source = deepcopy(BASE)
    source["data_root"] = str(tmp_path / "mounted" / "collector-data")
    source["state_root"] = str(tmp_path / "state")
    source["archive"] = {"targets": [_filesystem_archive_target(tmp_path / "mounted")]}

    with pytest.raises(ValidationError, match="data_root"):
        CollectorConfig.model_validate(source)


def test_cleanup_rejects_backup_only_required_filesystem_target(tmp_path) -> None:
    source = deepcopy(BASE)
    source["data_root"] = str(tmp_path / "data")
    source["state_root"] = str(tmp_path / "state")
    source["archive"] = {
        "targets": [_filesystem_archive_target(tmp_path / "mounted", required=True)]
    }
    source["local_cleanup"] = {"enabled": True}

    with pytest.raises(ValidationError, match="operator_attested_fsync_readback"):
        CollectorConfig.model_validate(source)


def test_cleanup_accepts_attested_required_filesystem_target(tmp_path) -> None:
    source = deepcopy(BASE)
    source["data_root"] = str(tmp_path / "data")
    source["state_root"] = str(tmp_path / "state")
    source["archive"] = {
        "targets": [
            _filesystem_archive_target(
                tmp_path / "mounted",
                required=True,
                durability_capability="operator_attested_fsync_readback",
            )
        ]
    }
    source["local_cleanup"] = {"enabled": True}

    config = CollectorConfig.model_validate(source)

    assert config.local_cleanup.enabled is True


def test_backup_only_required_filesystem_target_is_compatible_without_cleanup(
    tmp_path,
) -> None:
    source = deepcopy(BASE)
    source["data_root"] = str(tmp_path / "data")
    source["state_root"] = str(tmp_path / "state")
    source["archive"] = {
        "targets": [_filesystem_archive_target(tmp_path / "mounted", required=True)]
    }

    config = CollectorConfig.model_validate(source)
    target = config.archive.targets[0]

    assert config.local_cleanup.enabled is False
    assert isinstance(target, FilesystemTargetConfig)
    assert target.durability_capability == "backup_only"


def test_cleanup_accepts_required_object_storage_target() -> None:
    source = deepcopy(BASE)
    source["archive"] = {"targets": [_s3_archive_target(required=True)]}
    source["local_cleanup"] = {"enabled": True}

    config = CollectorConfig.model_validate(source)

    assert config.local_cleanup.enabled is True
