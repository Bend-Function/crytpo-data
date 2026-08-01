from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from crypto_collector.config.models import (
    CollectorConfig,
    ConfigSecretError,
    SelectionConfig,
    SelectionOverride,
    iter_secret_refs,
    validate_secret_snapshot,
)
from crypto_collector.config.primitives import SecretSnapshot

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


def test_flush_interval_must_leave_half_the_slo_as_budget() -> None:
    invalid = BASE | {"writer": BASE["writer"] | {"flush_interval": "750ms"}}
    with pytest.raises(ValidationError, match="flush_interval"):
        CollectorConfig.model_validate(invalid)


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
