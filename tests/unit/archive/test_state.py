from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
from pydantic import ValidationError

from crypto_collector.archive.models import (
    ArchiveJobState,
    ArchiveSourceManifestV1,
    CleanupGatePolicyV1,
    MultipartPartV1,
    SourceArtifact,
    WorkflowCheckpoint,
    canonical_json_bytes,
)
from crypto_collector.archive.policy import ArchivePolicyError, freeze_policy
from crypto_collector.archive.state import (
    ArchiveState,
    ArchiveStateError,
    ArchiveTransition,
    ExistingObjectMismatch,
    InvalidArchiveTransition,
    RetryableTargetError,
)
from crypto_collector.config.models import ArchiveConfig
from crypto_collector.storage.manifest import RawManifestV1, load_raw_manifest
from tests.unit.storage.test_manifest import (
    DATA_RELATIVE_PATH,
    LAST_RECEIVED_NS,
    MANIFEST_RELATIVE_PATH,
    normal_manifest_values,
)

MAX_NS = 2**63 - 1
RAW_GATES = CleanupGatePolicyV1(
    source_kind="raw",
    grace_ns=86_400_000_000_000,
    materializer_enabled=True,
    materializer_delay_ns=300_000_000_000,
    revision_horizon_ns=86_400_000_000_000,
)


def archive_config(
    *,
    required: tuple[str, ...] = ("oss", "s3"),
    compression_level: int = 3,
) -> ArchiveConfig:
    return ArchiveConfig.model_validate(
        {
            "targets": [
                {
                    "id": "oss",
                    "type": "aliyun_oss",
                    "required": "oss" in required,
                    "bucket": "archive",
                    "endpoint": "https://oss.example.test",
                    "credentials": {
                        "access_key_id": "env:OSS_KEY",
                        "access_key_secret": "env:OSS_SECRET",
                    },
                    "compression": {
                        "enabled": True,
                        "mode": "auto",
                        "level": compression_level,
                        "min_size": "1MiB",
                    },
                },
                {
                    "id": "s3",
                    "type": "s3",
                    "required": "s3" in required,
                    "bucket": "archive",
                    "credentials": {
                        "access_key_id": "env:S3_KEY",
                        "secret_access_key": "env:S3_SECRET",
                    },
                },
            ]
        }
    )


def source_manifest(
    *,
    manifest_sha256: str = "a" * 64,
    data_sha256: str = "b" * 64,
) -> ArchiveSourceManifestV1:
    return ArchiveSourceManifestV1(
        source_manifest_sha256=manifest_sha256,
        source_manifest_relative_path="raw/okx/spot/BTC-USDT/trades/part.manifest.json",
        manifest_kind="raw",
        manifest_schema="raw_manifest",
        manifest_schema_version=1,
        source_manifest_size_bytes=1024,
        closed=True,
        closed_at_ns=3_500_000_000_000,
        storage_partition_end_ns=3_600_000_000_000,
        artifacts=(
            SourceArtifact(
                relative_path="raw/okx/spot/BTC-USDT/trades/part.jsonl.zst",
                size_bytes=2048,
                sha256=data_sha256,
                artifact_role="raw_data",
            ),
        ),
    )


def frozen_policy(
    source: ArchiveSourceManifestV1,
    *,
    required: tuple[str, ...] = ("oss", "s3"),
    compression_level: int = 3,
):
    return freeze_policy(
        config=archive_config(
            required=required,
            compression_level=compression_level,
        ),
    )


def discovered_store(tmp_path: Path) -> tuple[ArchiveState, ArchiveSourceManifestV1]:
    source = source_manifest()
    store = ArchiveState.open(tmp_path / "archive" / "archive.sqlite")
    store.discover(source, policy=frozen_policy(source), cleanup_gates=RAW_GATES)
    return store, source


def local_source(
    tmp_path: Path,
    *,
    data: bytes = b"source-data",
    manifest: bytes = b'{"closed":true}\n',
) -> tuple[Path, Path, Path, ArchiveSourceManifestV1]:
    data_root = tmp_path / "data"
    data_path = data_root / "raw/source.jsonl.zst"
    manifest_path = data_root / "raw/source.manifest.json"
    data_path.parent.mkdir(parents=True)
    data_path.write_bytes(data)
    manifest_path.write_bytes(manifest)
    source = ArchiveSourceManifestV1(
        source_manifest_sha256=hashlib.sha256(manifest).hexdigest(),
        source_manifest_relative_path="raw/source.manifest.json",
        manifest_kind="raw",
        manifest_schema="raw_manifest",
        manifest_schema_version=1,
        source_manifest_size_bytes=len(manifest),
        closed=True,
        closed_at_ns=3_500_000_000_000,
        storage_partition_end_ns=3_600_000_000_000,
        artifacts=(
            SourceArtifact(
                relative_path="raw/source.jsonl.zst",
                size_bytes=len(data),
                sha256=hashlib.sha256(data).hexdigest(),
                artifact_role="raw_data",
            ),
        ),
    )
    return data_root, data_path, manifest_path, source


def queue_job(store: ArchiveState, source: ArchiveSourceManifestV1, target: str = "s3"):
    job = next(job for job in store.jobs() if job.target_id == target)
    store.transition(job.key, ArchiveJobState.QUEUED)
    return store.job(job.key)


def record_current_verification(
    store: ArchiveState,
    source: ArchiveSourceManifestV1,
    job,
) -> None:
    checkpoint = store.job(job.key).workflow_checkpoint.value
    store.record_verification(
        job.key,
        stored_sha256=source.artifacts[0].sha256,
        stored_size=source.artifacts[0].size_bytes,
        provider_checksum_json=b'{"etag":"verified"}',
        verification_json=(f'{{"checkpoint":"{checkpoint}"}}').encode(),
    )


def advance_to_receipt_verification(
    store: ArchiveState,
    source: ArchiveSourceManifestV1,
    job,
) -> None:
    store.transition(job.key, "UPLOADING")
    store.transition(
        job.key,
        "VERIFYING",
        workflow_checkpoint="data_uploaded",
    )
    record_current_verification(store, source, job)
    store.transition(
        job.key,
        "UPLOADING",
        workflow_checkpoint="data_verified",
    )
    store.transition(
        job.key,
        "VERIFYING",
        workflow_checkpoint="source_manifest_uploaded",
    )
    record_current_verification(store, source, job)
    store.transition(
        job.key,
        "UPLOADING",
        workflow_checkpoint="source_manifest_verified",
    )
    store.transition(
        job.key,
        "VERIFYING",
        workflow_checkpoint="receipt_published",
    )


def test_removing_required_target_does_not_weaken_existing_source(tmp_path) -> None:
    source = source_manifest()
    store = ArchiveState.open(tmp_path / "archive.sqlite")
    discovered = store.discover(
        source,
        policy=frozen_policy(source),
        cleanup_gates=RAW_GATES,
    )
    store.reload_config(archive_config(required=("s3",)))
    rediscovered = store.discover(
        source,
        policy=frozen_policy(source, required=("s3",)),
        cleanup_gates=RAW_GATES,
    )

    assert discovered.source_sha == source.source_manifest_sha256
    assert rediscovered.policy_sha256 == discovered.policy_sha256
    assert store.policy_for(discovered.source_sha).required_target_ids == (
        "oss",
        "s3",
    )

    future_source = source_manifest(manifest_sha256="c" * 64)
    future = store.discover(future_source, cleanup_gates=RAW_GATES)
    assert store.policy_for(future.source_sha).required_target_ids == ("s3",)
    store.close()


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("DISCOVERED", "QUEUED"),
        ("QUEUED", "TRANSFORMING"),
        ("QUEUED", "UPLOADING"),
        ("TRANSFORMING", "UPLOADING"),
        ("UPLOADING", "VERIFYING"),
        ("VERIFYING", "UPLOADING"),
        ("VERIFYING", "COMMITTED"),
    ],
)
def test_allowed_archive_transitions(old: str, new: str) -> None:
    assert ArchiveTransition.validate(old, new)


@pytest.mark.parametrize(
    "old",
    ["QUEUED", "TRANSFORMING", "UPLOADING", "VERIFYING"],
)
def test_retryable_failure_enters_retrying(old: str) -> None:
    assert ArchiveTransition.validate(
        old,
        "RETRYING",
        error=RetryableTargetError("temporary"),
    )


@pytest.mark.parametrize(
    ("checkpoint", "expected"),
    [
        ("source", "TRANSFORMING"),
        ("stored", "UPLOADING"),
        ("data_uploaded", "VERIFYING"),
        ("data_verified", "UPLOADING"),
        ("source_manifest_uploaded", "VERIFYING"),
        ("source_manifest_verified", "UPLOADING"),
        ("receipt_published", "VERIFYING"),
    ],
)
def test_retry_resumes_only_from_durable_checkpoint(
    checkpoint: str,
    expected: str,
) -> None:
    assert (
        ArchiveTransition.resume_target("RETRYING", checkpoint=checkpoint) == expected
    )


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("DISCOVERED", "UPLOADING"),
        ("COMMITTED", "UPLOADING"),
        ("TERMINAL_CONFLICT", "RETRYING"),
        ("RETRYING", "ABANDONED_LOCAL_SOURCE_DELETED"),
    ],
)
def test_illegal_or_cleanup_only_transitions_fail_fast(old: str, new: str) -> None:
    with pytest.raises(InvalidArchiveTransition):
        ArchiveTransition.validate(old, new, target_required=False)


def test_store_transition_cannot_skip_upload_and_verification_checkpoints(
    tmp_path,
) -> None:
    store, source = discovered_store(tmp_path)
    job = queue_job(store, source)

    with pytest.raises(InvalidArchiveTransition, match="checkpoint"):
        store.transition(
            job.key,
            "UPLOADING",
            workflow_checkpoint="source_manifest_verified",
        )
    store.close()


def test_retry_schedule_and_multipart_checkpoint_survive_restart(tmp_path) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    store, source = discovered_store(tmp_path)
    job = queue_job(store, source)
    store.transition(job.key, "UPLOADING")
    parts = (
        MultipartPartV1(part_number=1, etag="etag-1", size_bytes=5),
        MultipartPartV1(part_number=2, etag="etag-2", size_bytes=7),
    )
    store.record_retry(
        job.key,
        retry_at_ns=30_000_000_000,
        attempt=3,
        workflow_checkpoint="data_uploaded",
        multipart_upload_id="upload-1",
        parts=parts,
        error=RetryableTargetError("throttled"),
    )
    store.close()

    reopened = ArchiveState.open(path)
    assert job.key not in {due.key for due in reopened.due_jobs(now_ns=29_000_000_000)}
    [due] = [
        item for item in reopened.due_jobs(now_ns=30_000_000_000) if item.key == job.key
    ]
    assert (due.attempt, due.workflow_checkpoint) == (
        3,
        WorkflowCheckpoint.DATA_UPLOADED,
    )
    assert (due.multipart_upload_id, due.part_numbers) == ("upload-1", (1, 2))

    resumed = reopened.resume_retry(due.key, now_ns=30_000_000_000)
    assert resumed.state is ArchiveJobState.VERIFYING
    assert resumed.multipart_parts == parts
    reopened.record_verification(
        due.key,
        stored_sha256=source.artifacts[0].sha256,
        stored_size=source.artifacts[0].size_bytes,
        provider_checksum_json=b'{"etag":"verified"}',
        verification_json=b'{"checkpoint":"data_uploaded"}',
        staging_path="/tmp/archive-stage.zst",
    )
    next_upload = reopened.transition(
        due.key,
        "UPLOADING",
        workflow_checkpoint="data_verified",
    )
    assert next_upload.multipart_upload_id is None
    assert next_upload.multipart_parts == ()
    assert next_upload.staging_path is None
    reopened.close()


def test_transform_result_and_staging_identity_survive_preupload_restart(
    tmp_path,
) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    store, source = discovered_store(tmp_path)
    job = queue_job(store, source)
    store.transition(job.key, "TRANSFORMING")
    staging = tmp_path / "archive-stage.zst"
    stored = b"deterministic-transformed-content"
    staging.write_bytes(stored)
    with pytest.raises(InvalidArchiveTransition, match="transform result"):
        store.transition(
            job.key,
            "UPLOADING",
            workflow_checkpoint="stored",
        )

    transformed = store.record_transform_result(
        job.key,
        staging_path=str(staging),
        stored_sha256=hashlib.sha256(stored).hexdigest(),
        stored_size=len(stored),
    )
    assert transformed.state is ArchiveJobState.UPLOADING
    assert transformed.workflow_checkpoint is WorkflowCheckpoint.STORED
    store.record_retry(
        job.key,
        retry_at_ns=7,
        attempt=1,
        workflow_checkpoint="stored",
        multipart_upload_id=None,
        parts=(),
        error=RetryableTargetError("pre-upload failure"),
    )
    store.close()

    reopened = ArchiveState.open(path)
    resumed = reopened.resume_retry(job.key, now_ns=7)
    assert resumed.state is ArchiveJobState.UPLOADING
    assert resumed.staging_path == str(staging)
    assert (resumed.stored_sha256, resumed.stored_size) == (
        hashlib.sha256(stored).hexdigest(),
        len(stored),
    )
    reopened.close()


def test_retry_checkpoint_cannot_regress_or_store_parts_without_upload_id(
    tmp_path,
) -> None:
    store, source = discovered_store(tmp_path)
    job = queue_job(store, source)
    store.transition(job.key, "UPLOADING")

    with pytest.raises(ArchiveStateError, match="upload ID"):
        store.record_retry(
            job.key,
            retry_at_ns=1,
            attempt=1,
            workflow_checkpoint="stored",
            multipart_upload_id=None,
            parts=(MultipartPartV1(part_number=1, etag="e", size_bytes=1),),
            error=RetryableTargetError(),
        )
    store.close()


def test_retry_checkpoint_cannot_skip_work_or_reuse_stale_verification(
    tmp_path,
) -> None:
    store, source = discovered_store(tmp_path)
    job = queue_job(store, source)
    with pytest.raises(ArchiveStateError, match="retry checkpoint"):
        store.record_retry(
            job.key,
            retry_at_ns=1,
            attempt=1,
            workflow_checkpoint="data_uploaded",
            multipart_upload_id=None,
            parts=(),
            error=RetryableTargetError(),
        )

    store.transition(job.key, "UPLOADING")
    store.transition(
        job.key,
        "VERIFYING",
        workflow_checkpoint="data_uploaded",
    )
    with pytest.raises(ArchiveStateError, match="retry checkpoint"):
        store.record_retry(
            job.key,
            retry_at_ns=1,
            attempt=1,
            workflow_checkpoint="data_verified",
            multipart_upload_id=None,
            parts=(),
            error=RetryableTargetError(),
        )

    record_current_verification(store, source, job)
    store.transition(
        job.key,
        "UPLOADING",
        workflow_checkpoint="data_verified",
    )
    retrying = store.record_retry(
        job.key,
        retry_at_ns=1,
        attempt=1,
        workflow_checkpoint="source_manifest_uploaded",
        multipart_upload_id=None,
        parts=(),
        error=RetryableTargetError(),
    )
    assert retrying.verification_json is None
    resumed = store.resume_retry(job.key, now_ns=1)
    assert resumed.state is ArchiveJobState.VERIFYING
    with pytest.raises(InvalidArchiveTransition, match="verification"):
        store.transition(
            job.key,
            "UPLOADING",
            workflow_checkpoint="source_manifest_verified",
        )
    store.close()


def test_upload_conflict_is_terminal_and_scheduler_excludes_it_after_restart(
    tmp_path,
) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    store, source = discovered_store(tmp_path)
    job = queue_job(store, source)
    store.transition(job.key, "UPLOADING")
    store.record_failure(job.key, ExistingObjectMismatch("remote differs"))
    store.close()

    reopened = ArchiveState.open(path)
    assert reopened.job(job.key).state is ArchiveJobState.TERMINAL_CONFLICT
    assert job.key not in {item.key for item in reopened.due_jobs(now_ns=MAX_NS)}
    with pytest.raises(InvalidArchiveTransition):
        ArchiveTransition.validate("TERMINAL_CONFLICT", "RETRYING")
    reopened.close()


def test_committed_job_is_terminal_and_not_due_after_restart(tmp_path) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    store, source = discovered_store(tmp_path)
    job = queue_job(store, source)
    advance_to_receipt_verification(store, source, job)
    with pytest.raises(InvalidArchiveTransition, match="verification"):
        store.transition(job.key, "COMMITTED")
    record_current_verification(store, source, job)
    store.transition(job.key, "COMMITTED")
    store.close()

    reopened = ArchiveState.open(path)
    assert job.key not in {item.key for item in reopened.due_jobs(now_ns=MAX_NS)}
    with pytest.raises(InvalidArchiveTransition):
        reopened.transition(job.key, "UPLOADING")
    reopened.close()


def test_discovery_publishes_reference_only_facts_before_jobs(tmp_path) -> None:
    source = source_manifest()
    archive_root = tmp_path / "archive"
    store = ArchiveState.open(archive_root / "archive.sqlite")
    discovery = store.discover(
        source,
        policy=frozen_policy(source),
        cleanup_gates=RAW_GATES,
    )

    policy_path = archive_root / "policies" / f"{discovery.policy_sha256}.json"
    generation_path = (
        archive_root / "sources" / source.source_manifest_sha256 / "generation-1.json"
    )
    active_path = generation_path.with_name("active.json")
    assert policy_path.is_file()
    assert generation_path.is_file()
    assert active_path.is_file()
    for path in (policy_path, generation_path, active_path):
        payload = path.read_bytes()
        assert payload.endswith(b"\n")
    assert b"env:S3_SECRET" in policy_path.read_bytes()
    assert b"credential-plaintext" not in policy_path.read_bytes()
    assert set(json.loads(active_path.read_bytes())) == {
        "generation",
        "generation_fact_sha256",
    }
    generation_document = json.loads(generation_path.read_bytes())
    assert generation_document["predecessor_generation_fact_sha256"] is None
    assert generation_document["cleanup_facts"] == {
        "grace_anchor_ns": 3_500_000_000_000,
        "grace_deadline_ns": 89_900_000_000_000,
        "materializer_ack_required": True,
        "materializer_delay_ns": 300_000_000_000,
        "revision_deadline_ns": 90_300_000_000_000,
        "revision_horizon_ns": 86_400_000_000_000,
        "storage_partition_end_ns": 3_600_000_000_000,
    }
    store.close()


def test_reopen_activates_complete_initial_generation_after_pointer_crash(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    source = source_manifest()
    policy = frozen_policy(source)
    original = ArchiveState._activate_generation

    def crash_before_pointer(self, fact) -> None:
        del self, fact
        raise OSError("simulated pointer crash")

    monkeypatch.setattr(ArchiveState, "_activate_generation", crash_before_pointer)
    store = ArchiveState.open(path)
    with pytest.raises(OSError, match="pointer crash"):
        store.discover(source, policy=policy, cleanup_gates=RAW_GATES)
    with pytest.raises(ArchiveStateError, match="closed"):
        store.jobs()
    store.close()
    monkeypatch.setattr(ArchiveState, "_activate_generation", original)

    reopened = ArchiveState.open(path)
    assert reopened.policy_for(source.source_manifest_sha256) == policy
    assert len(reopened.jobs()) == len(policy.targets)
    reopened.close()


def test_discovery_poison_state_after_pointer_then_sqlite_failure(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    source = source_manifest()
    policy = frozen_policy(source)
    store = ArchiveState.open(path)
    original = ArchiveState._insert_generation

    def fail_after_pointer(self, connection, *, policy, fact, active):
        if self is store:
            raise sqlite3.OperationalError("simulated discovery cache failure")
        return original(
            self,
            connection,
            policy=policy,
            fact=fact,
            active=active,
        )

    monkeypatch.setattr(ArchiveState, "_insert_generation", fail_after_pointer)
    with pytest.raises(sqlite3.OperationalError, match="cache failure"):
        store.discover(source, policy=policy, cleanup_gates=RAW_GATES)
    with pytest.raises(ArchiveStateError, match="closed"):
        store.jobs()

    reopened = ArchiveState.open(path)
    assert reopened.policy_for(source.source_manifest_sha256) == policy
    reopened.close()


def test_reopen_ignores_temp_only_generation_and_discovery_can_retry(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    source = source_manifest()
    policy = frozen_policy(source)
    original = ArchiveState._publish_generation

    def leave_temp_only(self, fact) -> None:
        generation_path = self._generation_path(
            fact.source.source_manifest_sha256,
            fact.generation,
        )
        generation_path.parent.mkdir(parents=True, exist_ok=True)
        generation_path.with_name(f".{generation_path.name}.crash.tmp").write_bytes(
            fact.canonical_bytes()
        )
        raise OSError("simulated generation publish crash")

    monkeypatch.setattr(ArchiveState, "_publish_generation", leave_temp_only)
    store = ArchiveState.open(path)
    with pytest.raises(OSError, match="generation publish crash"):
        store.discover(source, policy=policy, cleanup_gates=RAW_GATES)
    store.close()
    monkeypatch.setattr(ArchiveState, "_publish_generation", original)

    reopened = ArchiveState.open(path)
    assert reopened.jobs() == ()
    discovery = reopened.discover(
        source,
        policy=policy,
        cleanup_gates=RAW_GATES,
    )
    assert discovery.generation == 1
    reopened.close()


def test_multi_artifact_generation_has_collision_free_jobs_and_stable_order(
    tmp_path,
) -> None:
    source = ArchiveSourceManifestV1(
        manifest_kind="derived",
        manifest_schema="derived_manifest",
        manifest_schema_version=1,
        source_manifest_relative_path="derived/window.manifest.json",
        source_manifest_size_bytes=512,
        source_manifest_sha256="c" * 64,
        closed=True,
        closed_at_ns=4_000_000_000_000,
        storage_partition_end_ns=None,
        artifacts=(
            SourceArtifact(
                relative_path="derived/features.parquet",
                size_bytes=100,
                sha256="d" * 64,
                artifact_role="features",
            ),
            SourceArtifact(
                relative_path="derived/quality.parquet",
                size_bytes=50,
                sha256="e" * 64,
                artifact_role="quality",
            ),
        ),
    )
    gates = CleanupGatePolicyV1(
        source_kind="derived",
        grace_ns=1_000,
        materializer_enabled=False,
        materializer_delay_ns=0,
        revision_horizon_ns=0,
    )
    store = ArchiveState.open(tmp_path / "archive/archive.sqlite")
    discovery = store.discover(
        source,
        policy=freeze_policy(config=archive_config()),
        cleanup_gates=gates,
    )

    assert len(discovery.job_keys) == 4
    assert len(set(discovery.job_keys)) == 4
    assert tuple((job.artifact_role, job.target_id) for job in store.jobs()) == (
        ("features", "oss"),
        ("features", "s3"),
        ("quality", "oss"),
        ("quality", "s3"),
    )
    store.close()


def test_encoded_keys_isolate_targets_sharing_one_physical_prefix(tmp_path) -> None:
    shared_targets = []
    for target_id, level in (("primary", 3), ("secondary", 9)):
        shared_targets.append(
            {
                "id": target_id,
                "type": "s3",
                "bucket": "same-bucket",
                "endpoint": "https://s3.example.test",
                "prefix": "shared",
                "credentials": {
                    "access_key_id": "env:S3_KEY",
                    "secret_access_key": "env:S3_SECRET",
                },
                "compression": {
                    "enabled": True,
                    "mode": "zstd",
                    "level": level,
                    "min_size": "1B",
                    "recompress": True,
                },
            }
        )
    policy = freeze_policy(
        config=ArchiveConfig.model_validate({"targets": shared_targets})
    )
    source = source_manifest()
    store = ArchiveState.open(tmp_path / "archive/archive.sqlite")
    store.discover(source, policy=policy, cleanup_gates=RAW_GATES)

    keys = {job.target_id: job.data_key for job in store.jobs()}
    assert keys["primary"] != keys["secondary"]
    assert "/target=primary/" in keys["primary"]
    assert "/target=secondary/" in keys["secondary"]
    store.close()


def test_source_artifacts_must_be_sorted_and_roles_unique() -> None:
    common = {
        "manifest_kind": "derived",
        "manifest_schema": "derived_manifest",
        "manifest_schema_version": 1,
        "source_manifest_relative_path": "derived/window.manifest.json",
        "source_manifest_size_bytes": 512,
        "source_manifest_sha256": "c" * 64,
        "closed": True,
        "closed_at_ns": 4_000_000_000_000,
        "storage_partition_end_ns": None,
    }
    feature = SourceArtifact(
        relative_path="derived/features.parquet",
        size_bytes=100,
        sha256="d" * 64,
        artifact_role="features",
    )
    quality = SourceArtifact(
        relative_path="derived/quality.parquet",
        size_bytes=50,
        sha256="e" * 64,
        artifact_role="quality",
    )
    with pytest.raises(ValidationError, match="sorted"):
        ArchiveSourceManifestV1.model_validate(
            common | {"artifacts": (quality, feature)}
        )
    with pytest.raises(ValidationError, match="roles"):
        ArchiveSourceManifestV1.model_validate(
            common
            | {
                "artifacts": (
                    feature,
                    feature.model_copy(update={"sha256": "f" * 64}),
                )
            }
        )


def test_raw_source_adapter_requires_exact_present_closed_source(tmp_path) -> None:
    data = b"closed-raw-data"
    manifest = RawManifestV1.model_validate(
        normal_manifest_values(
            file_size_bytes=len(data),
            file_sha256=hashlib.sha256(data).hexdigest(),
        )
    )
    data_path = tmp_path / DATA_RELATIVE_PATH
    manifest_path = tmp_path / MANIFEST_RELATIVE_PATH
    data_path.parent.mkdir(parents=True)
    data_path.write_bytes(data)
    manifest_path.write_bytes(manifest.canonical_bytes())
    loaded = load_raw_manifest(manifest_path)

    source = ArchiveSourceManifestV1.from_loaded_raw_manifest(
        loaded,
        data_root=tmp_path,
    )

    assert source.source_manifest_sha256 == loaded.sha256
    assert source.artifacts[0].sha256 == hashlib.sha256(data).hexdigest()
    assert (
        source.storage_partition_end_ns
        == ((LAST_RECEIVED_NS // 3_600_000_000_000) + 1) * 3_600_000_000_000
    )

    data_path.unlink()
    with pytest.raises(ValueError, match="missing"):
        ArchiveSourceManifestV1.from_loaded_raw_manifest(
            loaded,
            data_root=tmp_path,
        )


def test_sqlite_rebuild_preserves_frozen_policy_and_exact_job_keys(tmp_path) -> None:
    state_root = tmp_path / "state"
    path = state_root / "archive" / "archive.sqlite"
    source = source_manifest()
    store = ArchiveState.open(path)
    discovered = store.discover(
        source,
        policy=frozen_policy(source),
        cleanup_gates=RAW_GATES,
    )
    expected_jobs = store.jobs()
    store.close()
    path.unlink()

    rebuilt = ArchiveState.open(path, rebuild=True)
    assert rebuilt.policy_for(discovered.source_sha).required_target_ids == (
        "oss",
        "s3",
    )
    assert [
        (job.key, job.data_key, job.source_manifest_key, job.receipt_key)
        for job in rebuilt.jobs()
    ] == [
        (job.key, job.data_key, job.source_manifest_key, job.receipt_key)
        for job in expected_jobs
    ]
    rebuilt.close()


def test_reopen_rejects_sqlite_source_without_durable_source_facts(tmp_path) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    source = source_manifest()
    store = ArchiveState.open(path)
    store.discover(
        source,
        policy=frozen_policy(source),
        cleanup_gates=RAW_GATES,
    )
    store.close()
    source_root = path.parent / "sources" / source.source_manifest_sha256
    source_root.rename(tmp_path / "detached-source-facts")

    with pytest.raises(ArchiveStateError, match="durable source facts"):
        ArchiveState.open(path)


def test_reopen_rejects_tampered_immutable_job_identity(tmp_path) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    store, _source = discovered_store(tmp_path)
    store.close()
    connection = sqlite3.connect(path)
    try:
        connection.execute("UPDATE archive_job SET data_key = '../../escape'")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ArchiveStateError, match="immutable job"):
        ArchiveState.open(path)


def test_reopen_rejects_tampered_job_first_discovered_generation(tmp_path) -> None:
    data_root, _data_path, _manifest_path, source = local_source(tmp_path)
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old_policy = frozen_policy(source, compression_level=3)
    store.discover(source, policy=old_policy, cleanup_gates=RAW_GATES)
    migrated = store.migrate_policy(
        source.source_manifest_sha256,
        from_policy_sha256=old_policy.policy_sha256,
        config=archive_config(compression_level=9),
        cleanup_gates=RAW_GATES,
        reason="change transform identity",
    )
    store.close()

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE archive_job SET generation = 1 WHERE policy_sha256 = ?",
            (migrated.policy_sha256,),
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ArchiveStateError, match="immutable job"):
        ArchiveState.open(path, data_root=data_root)


def test_rebuild_rejects_corrupt_or_missing_durable_policy_fact(tmp_path) -> None:
    path = tmp_path / "archive" / "archive.sqlite"
    source = source_manifest()
    store = ArchiveState.open(path)
    discovery = store.discover(
        source,
        policy=frozen_policy(source),
        cleanup_gates=RAW_GATES,
    )
    store.close()
    path.unlink()
    policy_path = path.parent / "policies" / f"{discovery.policy_sha256}.json"
    policy_path.write_text("{}\n", encoding="utf-8")

    with pytest.raises((ArchivePolicyError, ArchiveStateError)):
        ArchiveState.open(path, rebuild=True)


def test_migration_keeps_old_history_and_activates_new_namespace(tmp_path) -> None:
    data_root, _data_path, _manifest_path, source = local_source(tmp_path)
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old = frozen_policy(source, compression_level=3)
    old_discovery = store.discover(source, policy=old, cleanup_gates=RAW_GATES)

    migrated = store.migrate_policy(
        source.source_manifest_sha256,
        from_policy_sha256=old.policy_sha256,
        config=archive_config(compression_level=9),
        cleanup_gates=RAW_GATES,
        reason="raise compression level",
    )

    assert migrated.generation == 2
    assert migrated.policy_sha256 != old.policy_sha256
    assert store.policy_for(source.source_manifest_sha256).policy_sha256 == (
        migrated.policy_sha256
    )
    assert {job.policy_sha256 for job in store.jobs()} == {
        old.policy_sha256,
        migrated.policy_sha256,
    }
    assert {job.policy_sha256 for job in store.due_jobs(now_ns=MAX_NS)} == {
        migrated.policy_sha256
    }
    with pytest.raises(InvalidArchiveTransition, match="active generation"):
        store.transition(old_discovery.job_keys[0], "QUEUED")
    store.close()

    reopened = ArchiveState.open(path, data_root=data_root)
    assert reopened.policy_for(source.source_manifest_sha256).policy_sha256 == (
        migrated.policy_sha256
    )
    reopened.close()


def test_migration_poison_state_after_pointer_then_sqlite_statement_failure(
    tmp_path,
    monkeypatch,
) -> None:
    data_root, _data_path, _manifest_path, source = local_source(tmp_path)
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old = frozen_policy(source, compression_level=3)
    store.discover(source, policy=old, cleanup_gates=RAW_GATES)
    expected = frozen_policy(source, compression_level=9)
    original = ArchiveState._insert_generation

    def fail_after_pointer(self, connection, *, policy, fact, active):
        if self is store and fact.generation == 2:
            raise sqlite3.OperationalError("simulated cache statement failure")
        return original(
            self,
            connection,
            policy=policy,
            fact=fact,
            active=active,
        )

    monkeypatch.setattr(ArchiveState, "_insert_generation", fail_after_pointer)
    with pytest.raises(sqlite3.OperationalError, match="statement failure"):
        store.migrate_policy(
            source.source_manifest_sha256,
            from_policy_sha256=old.policy_sha256,
            config=archive_config(compression_level=9),
            cleanup_gates=RAW_GATES,
            reason="raise compression level",
        )
    with pytest.raises(ArchiveStateError, match="closed"):
        store.due_jobs(now_ns=MAX_NS)

    reopened = ArchiveState.open(path, data_root=data_root)
    assert reopened.policy_for(source.source_manifest_sha256) == expected
    reopened.close()


def test_migration_poison_state_after_pointer_then_sqlite_commit_failure(
    tmp_path,
    monkeypatch,
) -> None:
    data_root, _data_path, _manifest_path, source = local_source(tmp_path)
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old = frozen_policy(source, compression_level=3)
    store.discover(source, policy=old, cleanup_gates=RAW_GATES)
    expected = frozen_policy(source, compression_level=9)
    original = ArchiveState._insert_generation

    def defer_invalid_cache_row(self, connection, *, policy, fact, active):
        original(
            self,
            connection,
            policy=policy,
            fact=fact,
            active=active,
        )
        if self is store and fact.generation == 2:
            connection.execute("PRAGMA defer_foreign_keys = ON")
            connection.execute(
                """
                INSERT INTO archive_source(
                    source_manifest_sha256, source_json,
                    active_generation, active_policy_sha256
                ) VALUES (?, ?, 1, ?)
                """,
                ("f" * 64, b"{}\n", "e" * 64),
            )

    monkeypatch.setattr(ArchiveState, "_insert_generation", defer_invalid_cache_row)
    with pytest.raises(sqlite3.IntegrityError):
        store.migrate_policy(
            source.source_manifest_sha256,
            from_policy_sha256=old.policy_sha256,
            config=archive_config(compression_level=9),
            cleanup_gates=RAW_GATES,
            reason="raise compression level",
        )
    with pytest.raises(ArchiveStateError, match="closed"):
        store.policy_for(source.source_manifest_sha256)

    reopened = ArchiveState.open(path, data_root=data_root)
    assert reopened.policy_for(source.source_manifest_sha256) == expected
    reopened.close()


def test_cleanup_only_generation_reuses_committed_jobs(tmp_path) -> None:
    data_root, _data_path, _manifest_path, source = local_source(tmp_path)
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old = frozen_policy(source)
    store.discover(source, policy=old, cleanup_gates=RAW_GATES)
    committed = queue_job(store, source, target="s3")
    advance_to_receipt_verification(store, source, committed)
    record_current_verification(store, source, committed)
    store.transition(
        committed.key,
        "COMMITTED",
        workflow_checkpoint="receipt_published",
    )
    original_jobs = store.jobs()
    longer_grace = RAW_GATES.model_copy(update={"grace_ns": RAW_GATES.grace_ns * 2})

    migrated = store.migrate_policy(
        source.source_manifest_sha256,
        from_policy_sha256=old.policy_sha256,
        config=archive_config(),
        cleanup_gates=longer_grace,
        reason="extend cleanup grace",
    )

    assert migrated.generation == 2
    assert migrated.policy_sha256 == old.policy_sha256
    assert store.jobs() == original_jobs
    assert store.job(committed.key).state is ArchiveJobState.COMMITTED
    assert committed.key not in {job.key for job in store.due_jobs(now_ns=MAX_NS)}
    generation_two = json.loads(
        (
            path.parent
            / "sources"
            / source.source_manifest_sha256
            / "generation-2.json"
        ).read_bytes()
    )
    generation_one = json.loads(
        (
            path.parent
            / "sources"
            / source.source_manifest_sha256
            / "generation-1.json"
        ).read_bytes()
    )
    assert (
        generation_two["predecessor_generation_fact_sha256"]
        == (generation_one["generation_fact_sha256"])
    )
    assert generation_two["cleanup_facts"]["grace_deadline_ns"] == (
        source.closed_at_ns + longer_grace.grace_ns
    )
    store.close()

    reopened = ArchiveState.open(path, data_root=data_root)
    assert reopened.job(committed.key).state is ArchiveJobState.COMMITTED
    assert len(reopened.jobs()) == len(original_jobs)
    reopened.close()


def test_reopen_rejects_a_broken_generation_predecessor_chain(tmp_path) -> None:
    data_root, _data_path, _manifest_path, source = local_source(tmp_path)
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old = frozen_policy(source)
    store.discover(source, policy=old, cleanup_gates=RAW_GATES)
    store.migrate_policy(
        source.source_manifest_sha256,
        from_policy_sha256=old.policy_sha256,
        config=archive_config(),
        cleanup_gates=RAW_GATES.model_copy(update={"grace_ns": RAW_GATES.grace_ns * 2}),
        reason="extend cleanup grace",
    )
    store.close()
    generation_one = (
        path.parent / "sources" / source.source_manifest_sha256 / "generation-1.json"
    )
    generation_one.rename(tmp_path / "detached-generation-1.json")

    with pytest.raises(ArchiveStateError, match="generation chain"):
        ArchiveState.open(path, data_root=data_root)


def test_reopen_rejects_a_generation_chain_that_weakens_cleanup(tmp_path) -> None:
    data_root, _data_path, _manifest_path, source = local_source(tmp_path)
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old = frozen_policy(source)
    store.discover(source, policy=old, cleanup_gates=RAW_GATES)
    store.migrate_policy(
        source.source_manifest_sha256,
        from_policy_sha256=old.policy_sha256,
        config=archive_config(),
        cleanup_gates=RAW_GATES.model_copy(update={"grace_ns": RAW_GATES.grace_ns * 2}),
        reason="extend cleanup grace",
    )
    store.close()
    source_root = path.parent / "sources" / source.source_manifest_sha256
    generation_path = source_root / "generation-2.json"
    document = json.loads(generation_path.read_bytes())
    document["cleanup_facts"]["grace_deadline_ns"] = source.closed_at_ns
    unhashed = {
        key: value for key, value in document.items() if key != "generation_fact_sha256"
    }
    fact_sha = hashlib.sha256(canonical_json_bytes(unhashed)).hexdigest()
    document["generation_fact_sha256"] = fact_sha
    generation_path.write_bytes(canonical_json_bytes(document) + b"\n")
    pointer = {
        "generation": 2,
        "generation_fact_sha256": fact_sha,
    }
    (source_root / "active.json").write_bytes(canonical_json_bytes(pointer) + b"\n")
    path.unlink()

    with pytest.raises(ArchiveStateError, match="weaken cleanup"):
        ArchiveState.open(path, data_root=data_root)


@pytest.mark.parametrize(
    "weaker_gates",
    [
        RAW_GATES.model_copy(update={"grace_ns": RAW_GATES.grace_ns // 2}),
        CleanupGatePolicyV1(
            source_kind="raw",
            grace_ns=RAW_GATES.grace_ns,
            materializer_enabled=False,
            materializer_delay_ns=0,
            revision_horizon_ns=0,
        ),
        RAW_GATES.model_copy(
            update={"revision_horizon_ns": RAW_GATES.revision_horizon_ns // 2}
        ),
    ],
)
def test_migration_cannot_weaken_frozen_cleanup_gates(
    tmp_path,
    weaker_gates: CleanupGatePolicyV1,
) -> None:
    data_root, _data_path, _manifest_path, source = local_source(tmp_path)
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old = frozen_policy(source)
    store.discover(source, policy=old, cleanup_gates=RAW_GATES)

    with pytest.raises(ArchiveStateError, match="weaken cleanup"):
        store.migrate_policy(
            source.source_manifest_sha256,
            from_policy_sha256=old.policy_sha256,
            config=archive_config(compression_level=9),
            cleanup_gates=weaker_gates,
            reason="attempt to weaken cleanup gates",
        )
    store.close()


def test_migration_refuses_missing_source_tombstone_or_stale_policy(tmp_path) -> None:
    data_root, data_path, _manifest_path, source = local_source(
        tmp_path,
        data=b"source",
        manifest=b"manifest\n",
    )
    path = tmp_path / "state/archive/archive.sqlite"
    store = ArchiveState.open(path, data_root=data_root)
    old = frozen_policy(source)
    store.discover(source, policy=old, cleanup_gates=RAW_GATES)

    with pytest.raises(ArchiveStateError, match="active policy"):
        store.migrate_policy(
            source.source_manifest_sha256,
            from_policy_sha256="f" * 64,
            config=archive_config(compression_level=9),
            cleanup_gates=RAW_GATES,
            reason="stale",
        )

    data_path.unlink()
    with pytest.raises(ArchiveStateError, match="local source"):
        store.migrate_policy(
            source.source_manifest_sha256,
            from_policy_sha256=old.policy_sha256,
            config=archive_config(compression_level=9),
            cleanup_gates=RAW_GATES,
            reason="missing",
        )
    data_path.write_bytes(b"source")
    tombstone = (
        path.parent
        / "cleanup-tombstones"
        / f"{source.source_manifest_sha256}.tombstone.json"
    )
    tombstone.parent.mkdir()
    tombstone.write_text("{}\n", encoding="utf-8")
    with pytest.raises(ArchiveStateError, match="tombstone"):
        store.migrate_policy(
            source.source_manifest_sha256,
            from_policy_sha256=old.policy_sha256,
            config=archive_config(compression_level=9),
            cleanup_gates=RAW_GATES,
            reason="after cleanup",
        )
    store.close()


def test_store_uses_wal_full_sync_and_rejects_unknown_schema(tmp_path) -> None:
    path = tmp_path / "archive.sqlite"
    store = ArchiveState.open(path)
    store.close()
    connection = sqlite3.connect(path)
    try:
        assert connection.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
        assert connection.execute("PRAGMA synchronous").fetchone()[0] == 2
        connection.execute("PRAGMA user_version = 999")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ArchiveStateError, match="schema version"):
        ArchiveState.open(path)


def test_store_rejects_versioned_schema_without_constraints(tmp_path) -> None:
    reference_path = tmp_path / "reference.sqlite"
    reference = ArchiveState.open(reference_path)
    reference.close()

    reference_connection = sqlite3.connect(reference_path)
    try:
        tables = tuple(
            str(row[0])
            for row in reference_connection.execute(
                """
                SELECT name FROM sqlite_master
                 WHERE type = 'table' AND name LIKE 'archive_%'
                 ORDER BY name
                """
            ).fetchall()
        )
        columns = {
            table: tuple(
                str(row[1])
                for row in reference_connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            )
            for table in tables
        }
    finally:
        reference_connection.close()

    forged_path = tmp_path / "forged.sqlite"
    forged = sqlite3.connect(forged_path)
    try:
        for table, names in columns.items():
            declarations = ", ".join(f"{name} BLOB" for name in names)
            forged.execute(f"CREATE TABLE {table} ({declarations})")
        forged.execute("PRAGMA user_version = 1")
        forged.commit()
    finally:
        forged.close()

    with pytest.raises(ArchiveStateError, match="schema does not match"):
        ArchiveState.open(forged_path)


def test_store_rejects_a_symlink_sqlite_path(tmp_path) -> None:
    real_path = tmp_path / "real.sqlite"
    real = ArchiveState.open(real_path)
    real.close()
    linked_path = tmp_path / "linked.sqlite"
    linked_path.symlink_to(real_path)

    with pytest.raises(ArchiveStateError, match="regular file"):
        ArchiveState.open(linked_path)


def test_transaction_rolls_back_when_commit_fails(tmp_path) -> None:
    store = ArchiveState.open(tmp_path / "archive.sqlite")
    connection = store._require_connection()
    with pytest.raises(sqlite3.IntegrityError), store._transaction() as transaction:
        transaction.execute("PRAGMA defer_foreign_keys = ON")
        transaction.execute(
            """
            INSERT INTO archive_source(
                source_manifest_sha256, source_json,
                active_generation, active_policy_sha256
            ) VALUES (?, ?, 1, ?)
            """,
            ("a" * 64, b"{}\n", "b" * 64),
        )

    assert not connection.in_transaction
    with store._transaction():
        pass
    store.close()
