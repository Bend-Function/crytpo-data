from __future__ import annotations

import errno
import hashlib
import multiprocessing
import os
import stat
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from multiprocessing.connection import Connection
from pathlib import Path

import pytest
import zstandard

import crypto_collector.archive.transform as transform_module
from crypto_collector.archive.keys import (
    ArchiveKeyError,
    data_key,
    encoded_key,
    passthrough_key,
    receipt_key,
    source_manifest_key,
)
from crypto_collector.archive.models import (
    ArchiveJobKey,
    ArchiveSourceManifestV1,
    CleanupGatePolicyV1,
    SourceArtifact,
)
from crypto_collector.archive.policy import freeze_policy
from crypto_collector.archive.state import ArchiveState
from crypto_collector.archive.transform import (
    SourceIdentityMismatch,
    StagingBudget,
    StagingCapacityExceeded,
    StagingConflictError,
    StagingOwnershipError,
    StagingReconciliationError,
    StagingSpaceExhausted,
    TransformKind,
    TransformPlanMismatch,
    TransformRuntimeMismatch,
    execute_transform,
    plan_transform,
)
from crypto_collector.config.models import ArchiveConfig

SOURCE_MANIFEST_SHA = "a" * 64


def _staging_owner_probe(
    root: str,
    connection: Connection,
    *,
    crash: bool,
) -> None:
    try:
        budget = StagingBudget(Path(root), max_bytes=1024, max_concurrency=1)
    except StagingOwnershipError:
        connection.send("locked")
        connection.close()
        return
    connection.send("acquired")
    connection.close()
    if crash:
        os._exit(0)
    budget.close()


def archive_policy(
    *,
    mode: str = "zstd",
    enabled: bool = True,
    min_size: int = 1,
    recompress: bool = False,
    two_targets: bool = False,
):
    target_ids = ("target-a", "target-b") if two_targets else ("target-a",)
    targets = []
    for index, target_id in enumerate(target_ids):
        targets.append(
            {
                "id": target_id,
                "type": "s3",
                "required": False,
                "bucket": "shared-archive",
                "endpoint": "https://s3.example.test",
                "prefix": "shared-prefix",
                "credentials": {
                    "access_key_id": f"env:{target_id.upper().replace('-', '_')}_KEY",
                    "secret_access_key": (
                        f"env:{target_id.upper().replace('-', '_')}_SECRET"
                    ),
                },
                "compression": {
                    "enabled": enabled,
                    "mode": mode,
                    "level": 3 + (index * 6),
                    "min_size": f"{min_size}B",
                    "recompress": recompress,
                },
            }
        )
    return freeze_policy(config=ArchiveConfig.model_validate({"targets": targets}))


def install_artifact(
    tmp_path: Path,
    *,
    relative_path: str = "raw/okx/spot/BTC-USDT/trades/part.json",
    content: bytes = b"source-data" * 512,
    role: str = "raw_data",
) -> tuple[Path, SourceArtifact]:
    data_root = tmp_path / "data"
    source_path = data_root / relative_path
    source_path.parent.mkdir(parents=True)
    source_path.write_bytes(content)
    return data_root, SourceArtifact(
        relative_path=relative_path,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        artifact_role=role,
    )


@pytest.mark.parametrize(
    ("mode", "enabled", "relative_path", "size", "recompress", "expected"),
    [
        ("off", True, "raw/part.json", 2048, False, TransformKind.PASSTHROUGH),
        ("auto", True, "raw/part.jsonl.zst", 2048, False, TransformKind.PASSTHROUGH),
        ("auto", True, "raw/part.parquet", 2048, False, TransformKind.PASSTHROUGH),
        ("auto", True, "raw/large.json", 2048, False, TransformKind.ZSTD_V1),
        ("auto", True, "raw/small.json", 1023, False, TransformKind.PASSTHROUGH),
        ("zstd", True, "raw/large.json", 2048, False, TransformKind.ZSTD_V1),
        ("zstd", True, "raw/already.zst", 2048, False, TransformKind.PASSTHROUGH),
        ("zstd", True, "raw/already.zst", 2048, True, TransformKind.ZSTD_V1),
        ("zstd", False, "raw/large.json", 2048, True, TransformKind.PASSTHROUGH),
    ],
)
def test_transform_decision_uses_frozen_target_policy(
    tmp_path: Path,
    mode: str,
    enabled: bool,
    relative_path: str,
    size: int,
    recompress: bool,
    expected: TransformKind,
) -> None:
    data_root, artifact = install_artifact(
        tmp_path,
        relative_path=relative_path,
        content=b"x" * size,
    )
    policy = archive_policy(
        mode=mode,
        enabled=enabled,
        min_size=1024,
        recompress=recompress,
    )

    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )

    assert plan.kind is expected
    assert plan.job_key.artifact_sha256 == artifact.sha256
    assert plan.stored_key == data_key(artifact, policy, target_id="target-a")


def test_plan_rejects_symlink_or_changed_source_identity(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(b"outside")
    linked = data_root / "raw/linked.json"
    linked.parent.mkdir()
    linked.symlink_to(outside)
    artifact = SourceArtifact(
        relative_path="raw/linked.json",
        size_bytes=len(b"outside"),
        sha256=hashlib.sha256(b"outside").hexdigest(),
        artifact_role="raw_data",
    )
    policy = archive_policy()

    with pytest.raises(OSError):
        plan_transform(
            data_root,
            artifact,
            source_manifest_sha256=SOURCE_MANIFEST_SHA,
            policy=policy,
            target_id="target-a",
        )

    linked.unlink()
    linked.write_bytes(b"different")
    with pytest.raises(SourceIdentityMismatch):
        plan_transform(
            data_root,
            artifact,
            source_manifest_sha256=SOURCE_MANIFEST_SHA,
            policy=policy,
            target_id="target-a",
        )


def test_key_builders_match_task1_jobs_for_multi_artifact_shared_prefix(
    tmp_path: Path,
) -> None:
    policy = archive_policy(two_targets=True)
    artifacts = (
        SourceArtifact(
            relative_path="derived/features.parquet.raw",
            size_bytes=4096,
            sha256="b" * 64,
            artifact_role="features",
        ),
        SourceArtifact(
            relative_path="derived/quality.json",
            size_bytes=2048,
            sha256="c" * 64,
            artifact_role="quality",
        ),
    )
    source = ArchiveSourceManifestV1(
        manifest_kind="derived",
        manifest_schema="derived_manifest",
        manifest_schema_version=1,
        source_manifest_relative_path="derived/window.manifest.json",
        source_manifest_size_bytes=512,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        closed=True,
        closed_at_ns=123,
        storage_partition_end_ns=None,
        artifacts=artifacts,
    )
    store = ArchiveState.open(tmp_path / "archive/archive.sqlite")
    store.discover(
        source,
        policy=policy,
        cleanup_gates=CleanupGatePolicyV1(
            source_kind="derived",
            grace_ns=100,
            materializer_enabled=False,
            materializer_delay_ns=0,
            revision_horizon_ns=0,
        ),
    )

    for job in store.jobs():
        artifact = next(
            item for item in artifacts if item.artifact_role == job.artifact_role
        )
        assert job.data_key == data_key(artifact, policy, target_id=job.target_id)
        assert job.source_manifest_key == source_manifest_key(
            source.source_manifest_sha256,
            policy,
            target_id=job.target_id,
        )
        assert job.receipt_key == receipt_key(
            artifact,
            source.source_manifest_sha256,
            policy,
            target_id=job.target_id,
        )
    store.close()

    feature = artifacts[0]
    first = encoded_key(feature, policy, target_id="target-a")
    second = encoded_key(feature, policy, target_id="target-b")
    assert first != second
    assert "/target=target-a/" in first
    assert "/target=target-b/" in second
    assert receipt_key(
        feature,
        source.source_manifest_sha256,
        policy,
        target_id="target-a",
    ) != receipt_key(
        feature,
        source.source_manifest_sha256,
        policy,
        target_id="target-b",
    )


def test_passthrough_and_manifest_keys_share_only_identical_bytes() -> None:
    policy = archive_policy(mode="off", two_targets=True)
    artifact = SourceArtifact(
        relative_path="raw/part.jsonl.zst",
        size_bytes=2048,
        sha256="b" * 64,
        artifact_role="raw_data",
    )

    with pytest.raises(ArchiveKeyError):
        encoded_key(artifact, policy, target_id="target-a", version=True)  # type: ignore[arg-type]

    assert passthrough_key(artifact, policy, target_id="target-a") == (
        passthrough_key(artifact, policy, target_id="target-b")
    )
    assert source_manifest_key(
        SOURCE_MANIFEST_SHA,
        policy,
        target_id="target-a",
    ) == source_manifest_key(
        SOURCE_MANIFEST_SHA,
        policy,
        target_id="target-b",
    )


@pytest.mark.parametrize(
    "relative_path",
    (
        "_encoded/zstd/v1/target=target-a/collision.zst",
        "_manifests/collision.manifest.json",
        "_receipts/target-a/collision.archive-receipt.json",
        "other/collision.bin",
        "raw/../_receipts/collision.json",
        "raw//collision.bin",
        "raw\\collision.bin",
    ),
)
def test_key_builders_reject_forged_reserved_source_paths(
    relative_path: str,
) -> None:
    policy = archive_policy(mode="zstd")
    forged = SourceArtifact.model_construct(
        relative_path=relative_path,
        size_bytes=2048,
        sha256="b" * 64,
        artifact_role="raw_data",
    )

    with pytest.raises(ArchiveKeyError, match="source path"):
        data_key(forged, policy, target_id="target-a")
    with pytest.raises(ArchiveKeyError, match="source path"):
        receipt_key(
            forged,
            SOURCE_MANIFEST_SHA,
            policy,
            target_id="target-a",
        )


def test_transform_decision_revalidates_forged_target() -> None:
    frozen = archive_policy(mode="zstd")
    artifact = SourceArtifact(
        relative_path="raw/part.json",
        size_bytes=2048,
        sha256="b" * 64,
        artifact_role="raw_data",
    )
    target = frozen.target("target-a")
    forged_compression = target.compression.model_copy(update={"mode": "invalid"})
    forged = target.model_copy(update={"compression": forged_compression})

    with pytest.raises(ArchiveKeyError, match="target identity"):
        transform_module.uses_encoded_data(artifact, forged)


def test_zstd_transform_is_synced_no_replace_and_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root, artifact = install_artifact(tmp_path, content=b"compress-me\n" * 4096)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=2 * 1024 * 1024,
        max_concurrency=1,
    )
    events: list[tuple[str, int | None]] = []
    original_fsync = os.fsync

    def recording_fsync(fd: int) -> None:
        events.append(("fsync", stat.S_IFMT(os.fstat(fd).st_mode)))
        original_fsync(fd)

    original_publish = transform_module._publish_no_replace_at

    def recording_publish(
        parent_fd: int,
        source: Path,
        destination: Path,
        verification_fd: int,
    ) -> None:
        events.append(("publish", None))
        assert ".partial." in source.name
        assert verification_fd >= 0
        original_publish(parent_fd, source, destination, verification_fd)

    monkeypatch.setattr(transform_module.os, "fsync", recording_fsync)
    monkeypatch.setattr(
        transform_module,
        "_publish_no_replace_at",
        recording_publish,
    )

    first = execute_transform(plan, budget=budget)
    second = execute_transform(plan, budget=budget)

    assert first == second
    assert first.path.is_file()
    assert first.path.read_bytes() == second.path.read_bytes()
    assert hashlib.sha256(first.path.read_bytes()).hexdigest() == first.sha256
    assert zstandard.ZstdDecompressor().decompress(first.path.read_bytes()) == (
        b"compress-me\n" * 4096
    )
    parameters = zstandard.get_frame_parameters(first.path.read_bytes())
    assert parameters.has_checksum
    assert parameters.content_size == artifact.size_bytes
    publish_index = events.index(("publish", None))
    assert ("fsync", stat.S_IFREG) in events[:publish_index]
    assert not tuple(budget.root.rglob("*partial*"))
    assert (data_root / artifact.relative_path).read_bytes() == b"compress-me\n" * 4096


def test_transform_hashes_the_exact_source_bytes_fed_to_zstd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_bytes = b"manifest-source-a\n" * 512
    raced_bytes = b"raced----source-b\n" * 512
    assert len(original_bytes) == len(raced_bytes)
    data_root, artifact = install_artifact(tmp_path, content=original_bytes)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=2 * 1024 * 1024,
        max_concurrency=1,
    )
    original_read = transform_module.os.read
    replaced = False
    restored = False

    def race_source(fd: int, size: int) -> bytes:
        nonlocal replaced, restored
        if not replaced:
            plan.source_path.write_bytes(raced_bytes)
            replaced = True
        chunk = original_read(fd, size)
        if replaced and not restored and not chunk:
            plan.source_path.write_bytes(original_bytes)
            restored = True
        return chunk

    monkeypatch.setattr(transform_module.os, "read", race_source)

    with pytest.raises(SourceIdentityMismatch, match="streamed"):
        execute_transform(plan, budget=budget)

    assert replaced and restored
    assert plan.source_path.read_bytes() == original_bytes
    assert not tuple(budget.root.rglob("*.zst"))


def test_published_staging_is_reused_without_a_second_disk_reservation(
    tmp_path: Path,
) -> None:
    data_root, artifact = install_artifact(tmp_path, content=b"restart-safe\n" * 512)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    exact_bound = transform_module._compress_bound(artifact.size_bytes)
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=exact_bound,
        max_concurrency=1,
    )
    first = execute_transform(plan, budget=budget)
    retained = tuple(budget.root.rglob("*"))

    second = execute_transform(plan, budget=budget)

    assert second == first
    assert tuple(budget.root.rglob("*")) == retained


def test_concurrent_exact_publication_is_idempotent(
    tmp_path: Path, monkeypatch
) -> None:
    data_root, artifact = install_artifact(
        tmp_path,
        content=b"concurrent-publication\n" * 1024,
    )
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=4 * 1024 * 1024,
        max_concurrency=2,
    )
    rendezvous = threading.Barrier(2)
    original_publish = transform_module._publish_no_replace_at

    def synchronized_publish(
        parent_fd: int,
        partial: Path,
        destination: Path,
        verification_fd: int,
    ) -> None:
        rendezvous.wait(timeout=10)
        original_publish(parent_fd, partial, destination, verification_fd)

    monkeypatch.setattr(
        transform_module,
        "_publish_no_replace_at",
        synchronized_publish,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (
            executor.submit(execute_transform, plan, budget=budget),
            executor.submit(execute_transform, plan, budget=budget),
        )
        results = tuple(future.result(timeout=10) for future in futures)

    assert results[0] == results[1]
    assert len(tuple(budget.root.rglob("*.zst"))) == 1
    assert not tuple(budget.root.rglob("*partial*"))


def test_existing_transform_reuse_still_honors_concurrency_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_root, first_artifact = install_artifact(
        tmp_path,
        relative_path="raw/first/part.json",
        content=b"first\n" * 1024,
        role="first",
    )
    second_root, second_artifact = install_artifact(
        tmp_path,
        relative_path="raw/second/part.json",
        content=b"second\n" * 1024,
        role="second",
    )
    assert first_root == second_root
    policy = archive_policy(mode="zstd")
    first_plan = plan_transform(
        first_root,
        first_artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    second_plan = plan_transform(
        second_root,
        second_artifact,
        source_manifest_sha256="d" * 64,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=4 * 1024 * 1024,
        max_concurrency=1,
    )
    execute_transform(first_plan, budget=budget)
    execute_transform(second_plan, budget=budget)
    entered = threading.Event()
    release = threading.Event()
    original_stream = transform_module._stream_zstd_to_sink

    def blocking_stream(*args, **kwargs) -> None:
        entered.set()
        assert release.wait(timeout=10)
        original_stream(*args, **kwargs)

    monkeypatch.setattr(
        transform_module,
        "_stream_zstd_to_sink",
        blocking_stream,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        first = executor.submit(execute_transform, first_plan, budget=budget)
        assert entered.wait(timeout=10)
        try:
            with pytest.raises(StagingCapacityExceeded, match="concurrency"):
                execute_transform(second_plan, budget=budget)
        finally:
            release.set()
        assert first.result(timeout=10).job_key == first_plan.job_key


def test_execute_rejects_forged_plan_identity(tmp_path: Path) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=2 * 1024 * 1024,
        max_concurrency=1,
    )
    forged_key = ArchiveJobKey(
        source_manifest_sha256=plan.job_key.source_manifest_sha256,
        artifact_role=plan.job_key.artifact_role,
        artifact_sha256=plan.job_key.artifact_sha256,
        target_id=plan.job_key.target_id,
        policy_sha256="f" * 64,
    )

    with pytest.raises(TransformPlanMismatch):
        execute_transform(replace(plan, job_key=forged_key), budget=budget)
    with pytest.raises(TransformPlanMismatch):
        execute_transform(replace(plan, stored_key="archive/wrong"), budget=budget)


def test_transform_rejects_partial_inode_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=2 * 1024 * 1024,
        max_concurrency=1,
    )
    original_open = transform_module._open_regular_at
    replaced = False

    def replace_before_readonly_open(parent_fd: int, name: str) -> int:
        nonlocal replaced
        if ".partial." in name and not replaced:
            replaced = True
            os.rename(
                name,
                f"{name}.written",
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
            )
            replacement_fd = os.open(
                name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o640,
                dir_fd=parent_fd,
            )
            try:
                os.write(replacement_fd, b"replacement-bytes")
            finally:
                os.close(replacement_fd)
        return original_open(parent_fd, name)

    monkeypatch.setattr(
        transform_module,
        "_open_regular_at",
        replace_before_readonly_open,
    )

    with pytest.raises(StagingConflictError):
        execute_transform(plan, budget=budget)

    assert replaced
    assert not budget.path_for(plan.job_key).exists()


def test_transform_never_replaces_mismatched_staging_object(tmp_path: Path) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=2 * 1024 * 1024,
        max_concurrency=1,
    )
    first = execute_transform(plan, budget=budget)
    first.path.write_bytes(b"mismatched-existing-object")

    with pytest.raises(StagingConflictError):
        execute_transform(plan, budget=budget)

    assert first.path.read_bytes() == b"mismatched-existing-object"
    assert not tuple(budget.root.rglob("*partial*"))
    assert (data_root / artifact.relative_path).is_file()


@pytest.mark.parametrize("occupant", ("directory", "symlink", "fifo"))
def test_transform_classifies_nonregular_staging_occupant_as_conflict(
    tmp_path: Path,
    occupant: str,
) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=2 * 1024 * 1024,
        max_concurrency=1,
    )
    destination = budget.path_for(plan.job_key)
    destination.parent.mkdir(parents=True)
    if occupant == "directory":
        destination.mkdir()
    elif occupant == "symlink":
        outside = tmp_path / "outside.zst"
        outside.write_bytes(b"not-staging")
        destination.symlink_to(outside)
    else:
        os.mkfifo(destination)

    with pytest.raises(StagingConflictError):
        execute_transform(plan, budget=budget)


def test_staging_budget_counts_existing_bytes_and_limits_concurrency(
    tmp_path: Path,
) -> None:
    root = tmp_path / "staging"
    budget = StagingBudget(root, max_bytes=128, max_concurrency=1)
    retained = (
        root
        / f"policy={'a' * 64}"
        / "target=target-a"
        / ("b" * 64)
        / f"raw_data.{'c' * 64}.zst"
    )
    retained.parent.mkdir(parents=True)
    retained.write_bytes(b"x" * 96)

    with pytest.raises(StagingCapacityExceeded, match="bytes"), budget.reserve(64):
        pass

    retained.unlink()
    with budget.reserve(64):
        assert budget.active_reservations == 1
        with (
            pytest.raises(StagingCapacityExceeded, match="concurrency"),
            budget.reserve(1),
        ):
            pass
    assert budget.active_reservations == 0


def test_staging_budget_has_one_lifetime_owner_per_canonical_root(
    tmp_path: Path,
) -> None:
    root = tmp_path / "staging"
    first = StagingBudget(root, max_bytes=1024, max_concurrency=1)

    with pytest.raises(StagingOwnershipError):
        StagingBudget(root, max_bytes=1024, max_concurrency=1)

    first.close()
    with StagingBudget(root, max_bytes=1024, max_concurrency=1) as reopened:
        assert reopened.root == root


def test_staging_path_rejects_forged_job_key_traversal(tmp_path: Path) -> None:
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=1024,
        max_concurrency=1,
    )
    forged = ArchiveJobKey.model_construct(
        source_manifest_sha256="a" * 64,
        artifact_role="raw_data",
        artifact_sha256="b" * 64,
        target_id="../../outside",
        policy_sha256="../../escape",
    )

    with pytest.raises(StagingReconciliationError, match="job key"):
        budget.path_for(forged)

    budget.close()


def test_staging_owner_fails_closed_if_root_is_moved_or_replaced(
    tmp_path: Path,
) -> None:
    root = tmp_path / "staging"
    moved = tmp_path / "moved-staging"
    first = StagingBudget(root, max_bytes=1024, max_concurrency=1)
    root.rename(moved)
    second = StagingBudget(root, max_bytes=1024, max_concurrency=1)

    with (
        pytest.raises(StagingOwnershipError, match="replaced"),
        first.reserve(1),
    ):
        pass
    with second.reserve(1):
        assert second.active_reservations == 1

    first.close()
    second.close()


def test_transform_uses_pinned_root_if_path_is_replaced_after_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    root = tmp_path / "staging"
    moved = tmp_path / "moved-staging"
    budget = StagingBudget(root, max_bytes=2 * 1024 * 1024, max_concurrency=1)
    original_open_parent = StagingBudget._open_job_parent

    def replace_after_parent_open(
        self: StagingBudget,
        key: ArchiveJobKey,
        *,
        create: bool,
    ) -> int:
        parent_fd = original_open_parent(self, key, create=create)
        if create:
            root.rename(moved)
            root.mkdir()
        return parent_fd

    monkeypatch.setattr(
        StagingBudget,
        "_open_job_parent",
        replace_after_parent_open,
    )

    with pytest.raises(StagingOwnershipError, match="replaced"):
        execute_transform(plan, budget=budget)

    assert not tuple(root.rglob("*.zst"))
    assert tuple(moved.rglob("*.zst"))
    budget.close()


def test_transform_rejects_job_parent_moved_outside_owned_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=2 * 1024 * 1024,
        max_concurrency=1,
    )
    destination = budget.path_for(plan.job_key)
    escaped_parent = tmp_path / "escaped-job-parent"
    original_publish = transform_module._publish_no_replace_at

    def move_parent_after_publish(
        parent_fd: int,
        partial: Path,
        published: Path,
        verification_fd: int,
    ) -> None:
        original_publish(parent_fd, partial, published, verification_fd)
        published.parent.rename(escaped_parent)
        published.parent.mkdir()

    monkeypatch.setattr(
        transform_module,
        "_publish_no_replace_at",
        move_parent_after_publish,
    )

    with pytest.raises(StagingOwnershipError, match="job parent"):
        execute_transform(plan, budget=budget)

    assert not destination.exists()
    assert (escaped_parent / destination.name).is_file()


def test_staging_owner_lock_excludes_spawned_process_and_releases_on_crash(
    tmp_path: Path,
) -> None:
    context = multiprocessing.get_context("spawn")
    root = tmp_path / "staging"
    owner = StagingBudget(root, max_bytes=1024, max_concurrency=1)
    parent_connection, child_connection = context.Pipe(duplex=False)
    competitor = context.Process(
        target=_staging_owner_probe,
        args=(str(root), child_connection),
        kwargs={"crash": False},
    )
    competitor.start()
    child_connection.close()
    assert parent_connection.recv() == "locked"
    competitor.join(timeout=10)
    assert competitor.exitcode == 0
    parent_connection.close()
    owner.close()

    parent_connection, child_connection = context.Pipe(duplex=False)
    crashed = context.Process(
        target=_staging_owner_probe,
        args=(str(root), child_connection),
        kwargs={"crash": True},
    )
    crashed.start()
    child_connection.close()
    assert parent_connection.recv() == "acquired"
    crashed.join(timeout=10)
    assert crashed.exitcode == 0
    parent_connection.close()

    with StagingBudget(root, max_bytes=1024, max_concurrency=1):
        pass


def test_staging_reconcile_does_not_delete_unbound_files(tmp_path: Path) -> None:
    root = tmp_path / "staging"
    root.mkdir()
    unknown = root / "unknown.partial"
    unknown.write_bytes(b"operator-data")

    with pytest.raises(StagingReconciliationError):
        StagingBudget(root, max_bytes=1024, max_concurrency=1)

    assert unknown.read_bytes() == b"operator-data"


def test_staging_startup_reclaims_bound_orphan_partial(tmp_path: Path) -> None:
    root = tmp_path / "staging"
    orphan = (
        root
        / f"policy={'a' * 64}"
        / "target=target-a"
        / ("b" * 64)
        / f".raw_data.{'c' * 64}.zst.partial.crashed"
    )
    orphan.parent.mkdir(parents=True)
    orphan.write_bytes(b"incomplete")

    with StagingBudget(root, max_bytes=1024, max_concurrency=1):
        assert not orphan.exists()


def test_space_failure_retains_source_and_allows_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=transform_module._compress_bound(artifact.size_bytes),
        max_concurrency=1,
    )
    original_write_all = transform_module._write_all

    def no_space(_fd: int, _data: bytes | memoryview) -> None:
        raise OSError(errno.ENOSPC, "simulated staging full")

    monkeypatch.setattr(transform_module, "_write_all", no_space)
    with pytest.raises(StagingSpaceExhausted):
        execute_transform(plan, budget=budget)

    assert (data_root / artifact.relative_path).is_file()
    assert not tuple(budget.root.rglob("*partial*"))
    assert budget.active_reservations == 0
    monkeypatch.setattr(transform_module, "_write_all", original_write_all)
    assert execute_transform(plan, budget=budget).path.is_file()


def test_parent_directory_space_failure_is_classified_and_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=transform_module._compress_bound(artifact.size_bytes),
        max_concurrency=1,
    )
    destination = budget.path_for(plan.job_key)
    original_open_parent = StagingBudget._open_job_parent

    def no_space(
        self: StagingBudget,
        key: ArchiveJobKey,
        *,
        create: bool,
    ) -> int:
        del self, key, create
        raise OSError(errno.ENOSPC, "simulated directory allocation failure")

    monkeypatch.setattr(
        StagingBudget,
        "_open_job_parent",
        no_space,
    )
    with pytest.raises(StagingSpaceExhausted):
        execute_transform(plan, budget=budget)

    assert budget.active_reservations == 0
    assert not destination.exists()
    assert (data_root / artifact.relative_path).is_file()
    monkeypatch.setattr(
        StagingBudget,
        "_open_job_parent",
        original_open_parent,
    )
    assert execute_transform(plan, budget=budget).path == destination


def test_restart_reclaims_orphan_partial_before_budget_reservation(
    tmp_path: Path,
) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=transform_module._compress_bound(artifact.size_bytes),
        max_concurrency=1,
    )
    destination = budget.path_for(plan.job_key)
    destination.parent.mkdir(parents=True)
    orphan = destination.with_name(f".{destination.name}.partial.crashed")
    orphan.write_bytes(b"incomplete")

    stored = execute_transform(plan, budget=budget)

    assert stored.path == destination
    assert not orphan.exists()


def test_zstd_transform_rejects_runtime_version_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root, artifact = install_artifact(tmp_path)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=2 * 1024 * 1024,
        max_concurrency=1,
    )
    monkeypatch.setattr(transform_module, "_ZSTANDARD_RUNTIME_VERSION", "future")

    with pytest.raises(TransformRuntimeMismatch):
        execute_transform(plan, budget=budget)

    assert not tuple(budget.root.rglob("*.zst"))


def test_transform_rejects_job_larger_than_staging_limit(tmp_path: Path) -> None:
    data_root, artifact = install_artifact(tmp_path, content=b"x" * 2048)
    policy = archive_policy(mode="zstd")
    plan = plan_transform(
        data_root,
        artifact,
        source_manifest_sha256=SOURCE_MANIFEST_SHA,
        policy=policy,
        target_id="target-a",
    )
    budget = StagingBudget(
        tmp_path / "staging",
        max_bytes=artifact.size_bytes,
        max_concurrency=1,
    )

    with pytest.raises(StagingCapacityExceeded):
        execute_transform(plan, budget=budget)

    assert not tuple(budget.root.rglob("*partial*"))
    assert not tuple(budget.root.iterdir())
    assert (data_root / artifact.relative_path).is_file()
