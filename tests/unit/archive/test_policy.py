from __future__ import annotations

import hashlib
import json

import pytest

import crypto_collector.archive.policy as archive_policy_module
from crypto_collector.archive.models import (
    ArchiveVerificationLevel,
    CredentialReferenceV1,
    canonical_json_bytes,
)
from crypto_collector.archive.policy import (
    ArchivePolicyError,
    freeze_policy,
    load_policy_bytes,
    migrate_policy,
)
from crypto_collector.config.models import ArchiveConfig


def archive_config(
    *,
    compression_level: int = 3,
    target_order: tuple[str, ...] = ("s3", "oss", "webdav"),
    s3_required: bool = True,
    oss_required: bool = False,
    s3_enabled: bool = True,
) -> ArchiveConfig:
    targets: dict[str, dict[str, object]] = {
        "s3": {
            "id": "s3",
            "type": "s3",
            "required": s3_required,
            "enabled": s3_enabled,
            "bucket": "research",
            "endpoint": "https://s3.example.test",
            "region": "test-1",
            "credentials": {
                "access_key_id": "env:S3_ACCESS_KEY",
                "secret_access_key": "env:S3_SECRET",
            },
            "compression": {
                "enabled": True,
                "mode": "auto",
                "level": compression_level,
                "min_size": "1MiB",
            },
        },
        "oss": {
            "id": "oss",
            "type": "aliyun_oss",
            "required": oss_required,
            "bucket": "research",
            "endpoint": "https://oss.example.test",
            "credentials": {
                "access_key_id": "env:OSS_ACCESS_KEY",
                "access_key_secret": "env:OSS_SECRET",
            },
        },
        "webdav": {
            "id": "webdav",
            "type": "filesystem",
            "required": False,
            "root": "/mnt/webdav/archive",
            "mount_guard": {
                "path": "/mnt/webdav/.archive-guard",
                "expected": "env:WEBDAV_GUARD",
            },
        },
    }
    return ArchiveConfig.model_validate(
        {"targets": [targets[target_id] for target_id in target_order]}
    )


def test_policy_hash_is_canonical_and_secret_independent(monkeypatch) -> None:
    monkeypatch.setenv("S3_SECRET", "first-secret-value")
    first = freeze_policy(
        config=archive_config(),
    )
    monkeypatch.setenv("S3_SECRET", "second-secret-value")
    second = freeze_policy(
        config=archive_config(),
    )

    assert second.policy_sha256 == first.policy_sha256
    assert first.canonical_bytes() == second.canonical_bytes()
    assert b"first-secret-value" not in first.canonical_bytes()
    assert b"second-secret-value" not in first.canonical_bytes()
    assert b"env:S3_SECRET" in first.canonical_bytes()


def test_policy_rejects_endpoint_userinfo_that_could_persist_plaintext() -> None:
    valid = archive_config()
    s3 = next(target for target in valid.targets if target.id == "s3")
    tainted = s3.model_copy(
        update={"endpoint": "https://operator:plaintext@s3.example.test"}
    )
    bypassed = valid.model_copy(
        update={
            "targets": tuple(
                tainted if target.id == "s3" else target for target in valid.targets
            )
        }
    )

    with pytest.raises(ArchivePolicyError, match="userinfo"):
        freeze_policy(config=bypassed)


@pytest.mark.parametrize(
    "endpoint",
    [
        "ftp://archive.example.test/secret",
        "https://archive.example.test/plaintext-token",
        "not-a-url",
        "https:///",
        "https://archive.example.test:invalid",
    ],
)
def test_durable_policy_loader_rejects_invalid_provider_endpoint(endpoint: str) -> None:
    document = json.loads(freeze_policy(config=archive_config()).canonical_bytes())
    s3 = next(target for target in document["targets"] if target["target_id"] == "s3")
    s3["endpoint"] = endpoint
    unhashed = {key: value for key, value in document.items() if key != "policy_sha256"}
    document["policy_sha256"] = hashlib.sha256(
        canonical_json_bytes(unhashed)
    ).hexdigest()
    source = canonical_json_bytes(document) + b"\n"

    with pytest.raises(ArchivePolicyError):
        load_policy_bytes(source)


@pytest.mark.parametrize(
    "reference",
    ["plaintext", "env:", "env:TWO WORDS", "file:relative", "file:/a/../secret"],
)
def test_frozen_credential_schema_accepts_references_only(reference: str) -> None:
    with pytest.raises(ValueError, match="credential|filesystem path"):
        CredentialReferenceV1(name="secret", reference=reference)


def test_policy_hash_is_independent_of_target_declaration_order() -> None:
    first = freeze_policy(
        config=archive_config(target_order=("s3", "oss", "webdav")),
    )
    second = freeze_policy(
        config=archive_config(target_order=("webdav", "s3", "oss")),
    )

    assert second == first
    assert tuple(target.target_id for target in first.targets) == (
        "oss",
        "s3",
        "webdav",
    )


def test_transform_tool_version_is_part_of_policy_identity(monkeypatch) -> None:
    first = freeze_policy(config=archive_config())
    monkeypatch.setattr(
        archive_policy_module,
        "_ZSTANDARD_TOOL_VERSION",
        "future-test-version",
        raising=False,
    )
    second = freeze_policy(config=archive_config())

    assert second.policy_sha256 != first.policy_sha256
    assert second.target("s3").compression.transform_implementation_sha256 != (
        first.target("s3").compression.transform_implementation_sha256
    )


def test_verification_minimum_is_explicit_and_cleanup_strong_for_required() -> None:
    policy = freeze_policy(
        config=archive_config(),
    )
    levels = {target.target_id: target.verification_level for target in policy.targets}

    assert levels == {
        "oss": ArchiveVerificationLevel.PROVIDER_CRC64,
        "s3": ArchiveVerificationLevel.STORED_SHA256,
        "webdav": ArchiveVerificationLevel.STORED_SHA256,
    }
    assert policy.required_target_ids == ("s3",)


def test_policy_freezes_provider_addressing_and_filesystem_durability() -> None:
    policy = freeze_policy(config=archive_config())

    assert policy.target("s3").s3_addressing_style == "auto"
    filesystem = policy.target("webdav")
    assert filesystem.filesystem_mount_root == "/mnt/webdav"
    assert filesystem.filesystem_root == "/mnt/webdav/archive"
    assert filesystem.filesystem_durability_capability == "backup_only"


def test_required_oss_uses_cleanup_strong_sha256() -> None:
    policy = freeze_policy(
        config=archive_config(s3_required=False, oss_required=True),
    )

    oss = next(target for target in policy.targets if target.target_id == "oss")
    assert oss.verification_level is ArchiveVerificationLevel.STORED_SHA256


def test_disabled_targets_are_excluded_but_disabled_required_is_rejected() -> None:
    policy = freeze_policy(
        config=archive_config(s3_enabled=False, s3_required=False),
    )
    assert "s3" not in {target.target_id for target in policy.targets}

    valid = archive_config()
    disabled_required = valid.targets[0].model_copy(
        update={"enabled": False, "required": True}
    )
    bypassed = valid.model_copy(
        update={"targets": (disabled_required, *valid.targets[1:])}
    )
    with pytest.raises(ArchivePolicyError, match="required.*disabled"):
        freeze_policy(config=bypassed)


@pytest.mark.parametrize("target_id", ["../escape", "a/b", ".", "two words"])
def test_policy_rejects_target_ids_that_are_not_remote_key_safe(target_id: str) -> None:
    valid = archive_config()
    invalid_target = valid.targets[0].model_copy(update={"id": target_id})
    bypassed = valid.model_copy(
        update={"targets": (invalid_target, *valid.targets[1:])}
    )
    with pytest.raises(ArchivePolicyError, match="target ID"):
        freeze_policy(config=bypassed)


def test_policy_round_trip_requires_exact_canonical_bytes_and_hash() -> None:
    policy = freeze_policy(
        config=archive_config(),
    )
    assert load_policy_bytes(policy.canonical_bytes()) == policy

    document = json.loads(policy.canonical_bytes())
    document["policy_sha256"] = "0" * 64
    tampered = json.dumps(document, separators=(",", ":")).encode() + b"\n"
    with pytest.raises(ArchivePolicyError, match="hash"):
        load_policy_bytes(tampered)

    noncanonical = (
        json.dumps(
            json.loads(policy.canonical_bytes()),
            indent=2,
            sort_keys=False,
        ).encode()
        + b"\n"
    )
    with pytest.raises(ArchivePolicyError, match="canonical"):
        load_policy_bytes(noncanonical)


def test_policy_migration_changes_namespace_and_rejects_noop() -> None:
    old = freeze_policy(
        config=archive_config(compression_level=3),
    )
    new = migrate_policy(
        old,
        config=archive_config(compression_level=9),
        reason="raise compression level",
    )

    assert old.policy_sha256 != new.policy_sha256
    assert old.remote_namespace != new.remote_namespace
    with pytest.raises(ArchivePolicyError, match="no-op"):
        migrate_policy(
            old,
            config=archive_config(),
            reason="same policy",
        )


@pytest.mark.parametrize("reason", ["", "   ", "bad\nreason"])
def test_policy_migration_reason_must_be_a_single_nonempty_line(reason: str) -> None:
    old = freeze_policy(
        config=archive_config(),
    )
    with pytest.raises(ArchivePolicyError, match="reason"):
        migrate_policy(
            old,
            config=archive_config(compression_level=9),
            reason=reason,
        )


def test_scheduler_tuning_does_not_change_remote_policy_identity() -> None:
    base = archive_config()
    first = base.targets[0]
    tuned = first.model_copy(
        update={
            "concurrency": 17,
            "multipart_size_bytes": 128 * 1024**2,
            "retry": first.retry.model_copy(
                update={
                    "max_attempts": 99,
                    "base_backoff_ns": 2_000_000_000,
                    "max_backoff_ns": 120_000_000_000,
                }
            ),
        }
    )
    tuned_config = base.model_copy(update={"targets": (tuned, *base.targets[1:])})

    assert freeze_policy(config=tuned_config) == freeze_policy(config=base)
