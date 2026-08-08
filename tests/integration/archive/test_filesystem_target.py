from __future__ import annotations

import errno
import os
import stat
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import crypto_collector.archive.targets.filesystem as filesystem_module
from crypto_collector.archive.models import FrozenArchiveTargetV1
from crypto_collector.archive.policy import freeze_policy
from crypto_collector.archive.state import ExistingObjectMismatch, StoredObjectMismatch
from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    TargetUnavailable,
    UnsafeObjectKey,
    publish_receipt_last,
)
from crypto_collector.archive.targets.filesystem import FilesystemTarget
from crypto_collector.config.models import ArchiveConfig
from crypto_collector.config.primitives import SecretValue


class InjectedCrash(BaseException):
    pass


def frozen_filesystem_target(
    mount_root: Path,
    *,
    root: Path | None = None,
    guard_path: Path | None = None,
) -> FrozenArchiveTargetV1:
    archive_root = mount_root / "archive" if root is None else root
    guard = mount_root / ".collector-mount-id" if guard_path is None else guard_path
    policy = freeze_policy(
        config=ArchiveConfig.model_validate(
            {
                "targets": [
                    {
                        "id": "webdav-mount",
                        "type": "filesystem",
                        "required": False,
                        "root": str(archive_root),
                        "mount_root": str(mount_root),
                        "mount_guard": {
                            "path": str(guard),
                            "expected": "env:WEBDAV_MOUNT_GUARD",
                        },
                        "durability_capability": ("operator_attested_fsync_readback"),
                        "compression": {"enabled": False},
                    }
                ]
            }
        )
    )
    return policy.target("webdav-mount")


def accept_test_mount(monkeypatch: pytest.MonkeyPatch) -> None:
    def identity_token(_path: Path, fd: int) -> str:
        observed = os.fstat(fd)
        return f"test:{observed.st_dev}:{observed.st_ino}"

    monkeypatch.setattr(
        filesystem_module,
        "_mount_identity_token",
        identity_token,
    )
    monkeypatch.setattr(
        filesystem_module,
        "_require_independent_backing_storage",
        lambda _data_root_fd, _mount_root_fd: None,
    )


def source(tmp_path: Path, name: str = "source.bin", data: bytes = b"immutable"):
    path = tmp_path / name
    path.write_bytes(data)
    return ArchiveObjectSource.from_path(path)


def unprobed_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    guard: bytes | None = b"expected",
    phase_hook=None,
) -> tuple[FilesystemTarget, Path, Path]:
    mount_root = tmp_path / "mounted-webdav"
    mount_root.mkdir()
    guard_path = mount_root / ".collector-mount-id"
    if guard is not None:
        guard_path.write_bytes(guard)
    data_root = tmp_path / "data"
    data_root.mkdir(exist_ok=True)
    accept_test_mount(monkeypatch)
    target = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue("expected"),
        data_root=data_root,
        phase_hook=phase_hook,
    )
    return target, mount_root, mount_root / "archive"


def mounted_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    phase_hook=None,
) -> tuple[FilesystemTarget, Path, Path]:
    target, mount_root, root = unprobed_target(
        tmp_path,
        monkeypatch,
        phase_hook=phase_hook,
    )
    target.probe()
    return target, mount_root, root


def test_construction_is_io_free_and_secret_redacted(tmp_path: Path) -> None:
    mount_root = tmp_path / "not-created"
    canary = "plaintext-mount-guard-canary"
    target = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue(canary),
        data_root=tmp_path / "data",
    )

    assert not mount_root.exists()
    assert canary not in repr(target)


@pytest.mark.parametrize("guard", (None, b"wrong"))
def test_missing_or_wrong_guard_is_unavailable_without_creating_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    guard: bytes | None,
) -> None:
    target, _mount_root, root = unprobed_target(
        tmp_path,
        monkeypatch,
        guard=guard,
    )

    with pytest.raises(TargetUnavailable, match="mount guard"):
        target.probe()

    assert not root.exists()


def test_guard_symlink_is_rejected_without_creating_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount_root = tmp_path / "mounted-webdav"
    mount_root.mkdir()
    frozen = frozen_filesystem_target(mount_root)
    outside = tmp_path / "outside-guard"
    outside.write_bytes(b"expected")
    guard = mount_root / ".collector-mount-id"
    guard.symlink_to(outside)
    accept_test_mount(monkeypatch)
    target = FilesystemTarget(
        frozen,
        expected_guard=SecretValue("expected"),
        data_root=tmp_path / "data",
    )

    with pytest.raises(TargetUnavailable, match="mount guard"):
        target.probe()

    assert not (mount_root / "archive").exists()


def test_plain_directory_fallback_is_not_accepted_as_mount(tmp_path: Path) -> None:
    mount_root = tmp_path / "plain-directory"
    mount_root.mkdir()
    (mount_root / ".collector-mount-id").write_bytes(b"expected")
    target = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue("expected"),
        data_root=tmp_path / "data",
    )

    with pytest.raises(TargetUnavailable, match="mount point"):
        target.probe()

    assert not (mount_root / "archive").exists()


def test_probe_rejects_symlinked_data_root_alias_of_archive_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount_root = tmp_path / "mounted-webdav"
    root = mount_root / "archive"
    root.mkdir(parents=True)
    (mount_root / ".collector-mount-id").write_bytes(b"expected")
    data_root = tmp_path / "data-alias"
    data_root.symlink_to(root, target_is_directory=True)
    accept_test_mount(monkeypatch)
    target = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue("expected"),
        data_root=data_root,
    )

    with pytest.raises(TargetUnavailable, match="data_root"):
        target.probe()

    assert not tuple(root.glob(".crypto-collector-no-replace-probe.*"))


def test_probe_rejects_archive_mount_on_same_backing_storage_as_data_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount_root = tmp_path / "mounted-webdav"
    mount_root.mkdir()
    (mount_root / ".collector-mount-id").write_bytes(b"expected")
    data_root = tmp_path / "data"
    data_root.mkdir()
    monkeypatch.setattr(
        filesystem_module,
        "_mount_identity_token",
        lambda _path, _fd: "test-mount",
    )
    target = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue("expected"),
        data_root=data_root,
    )

    with pytest.raises(TargetUnavailable, match="independent storage"):
        target.probe()

    assert not tuple(mount_root.glob(".crypto-collector-no-replace-probe.*"))


def test_constructor_rejects_data_root_overlap_even_for_forged_policy(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    frozen = frozen_filesystem_target(tmp_path / "mounted")
    forged = frozen.model_copy(
        update={
            "filesystem_mount_root": str(data_root),
            "filesystem_root": str(data_root / "archive"),
            "mount_guard_path": str(data_root / ".guard"),
        }
    )

    with pytest.raises(ValueError, match="overlap data_root"):
        FilesystemTarget(
            forged,
            expected_guard=SecretValue("expected"),
            data_root=data_root,
        )


def test_constructor_rejects_root_outside_mount_even_for_forged_policy(
    tmp_path: Path,
) -> None:
    frozen = frozen_filesystem_target(tmp_path / "mounted")
    forged = frozen.model_copy(update={"filesystem_root": str(tmp_path / "outside")})

    with pytest.raises(ValueError, match="inside mount_root"):
        FilesystemTarget(
            forged,
            expected_guard=SecretValue("expected"),
            data_root=tmp_path / "data",
        )


@pytest.mark.parametrize("layout", ("root_is_mount", "guard_under_root"))
def test_constructor_rejects_guard_inside_archive_object_namespace(
    tmp_path: Path,
    layout: str,
) -> None:
    mount_root = tmp_path / "mounted"
    frozen = frozen_filesystem_target(mount_root)
    if layout == "root_is_mount":
        forged = frozen.model_copy(update={"filesystem_root": str(mount_root)})
        message = "strict descendant"
    else:
        forged = frozen.model_copy(
            update={"mount_guard_path": str(mount_root / "archive/.guard-secret")}
        )
        message = "must not overlap"

    with pytest.raises(ValueError, match=message) as caught:
        FilesystemTarget(
            forged,
            expected_guard=SecretValue("SECRET-CANARY"),
            data_root=tmp_path / "data",
        )

    assert "SECRET-CANARY" not in str(caught.value)


def test_darwin_mount_identity_uses_filesystem_id_not_device_number(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount_root = tmp_path / "mounted"
    mount_root.mkdir()
    mount_fd = os.open(mount_root, os.O_RDONLY)

    monkeypatch.setattr(
        filesystem_module,
        "_darwin_statfs",
        lambda fd: ((101, 7), mount_root if fd == mount_fd else mount_root.parent),
    )
    try:
        assert (
            filesystem_module._darwin_mount_identity(mount_root, mount_fd)
            == "darwin-fsid:101:7"
        )
    finally:
        os.close(mount_fd)


def test_darwin_plain_directory_same_fsid_is_not_a_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount_root = tmp_path / "plain"
    mount_root.mkdir()
    mount_fd = os.open(mount_root, os.O_RDONLY)
    monkeypatch.setattr(
        filesystem_module,
        "_darwin_statfs",
        lambda _fd: ((100, 0), mount_root.parent),
    )
    try:
        with pytest.raises(TargetUnavailable, match="mount point"):
            filesystem_module._darwin_mount_identity(mount_root, mount_fd)
    finally:
        os.close(mount_fd)


def test_darwin_mount_identity_allows_mount_directly_below_root(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount_root = Path("/dev")
    mount_fd = filesystem_module._open_absolute_directory(mount_root)

    monkeypatch.setattr(
        filesystem_module,
        "_darwin_statfs",
        lambda fd: ((101, 7), mount_root if fd == mount_fd else Path("/")),
    )
    try:
        assert (
            filesystem_module._darwin_mount_identity(mount_root, mount_fd)
            == "darwin-fsid:101:7"
        )
    finally:
        os.close(mount_fd)


def test_darwin_firmlink_path_is_not_accepted_as_exact_mount(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "firmlink"
    path.mkdir()
    fd = filesystem_module._open_absolute_directory(path)
    monkeypatch.setattr(
        filesystem_module,
        "_darwin_statfs",
        lambda _fd: ((101, 7), Path("/System/Volumes/Data")),
    )
    try:
        with pytest.raises(TargetUnavailable, match="mount point"):
            filesystem_module._darwin_mount_identity(path, fd)
    finally:
        os.close(fd)


def test_relative_directory_rejects_same_device_nested_mount_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "root"
    nested = root / "nested"
    nested.mkdir(parents=True)
    root_fd = filesystem_module._open_absolute_directory(root)
    root_inode = root.stat().st_ino

    def boundary(fd: int) -> str:
        inode = os.fstat(fd).st_ino
        return f"test-mount:{1 if inode == root_inode else 2}"

    monkeypatch.setattr(
        filesystem_module,
        "_filesystem_boundary_identity",
        boundary,
    )
    try:
        with pytest.raises(TargetUnavailable, match="nested mount"):
            filesystem_module._open_relative_directory(
                root_fd,
                ("nested",),
                create=False,
                expected_device=os.fstat(root_fd).st_dev,
                expected_boundary="test-mount:1",
            )
    finally:
        os.close(root_fd)


@pytest.mark.parametrize(
    "key",
    (
        "../escape",
        "/absolute",
        "raw/../../escape",
        "raw\\escape",
        "raw//empty",
        "raw/./dot",
        "raw/evil\x00name",
    ),
)
def test_filesystem_target_rejects_unsafe_object_key(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    key: str,
) -> None:
    target, _mount_root, _root = mounted_target(tmp_path, monkeypatch)
    try:
        with pytest.raises(UnsafeObjectKey):
            target.put(source(tmp_path), key)
    finally:
        target.close()


def test_put_is_partial_sync_no_replace_and_readback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    target, _mount_root, root = mounted_target(
        tmp_path,
        monkeypatch,
        phase_hook=events.append,
    )
    events.clear()
    upload = source(tmp_path, data=b"stored archive bytes")
    try:
        result = target.put(upload, "raw/part.jsonl.zst")
        verification = target.verify(
            result.key,
            upload.size_bytes,
            upload.sha256,
        )
    finally:
        target.close()

    assert result.created
    assert not result.resumed
    assert result.path == root / "raw/part.jsonl.zst"
    assert result.path.read_bytes() == b"stored archive bytes"
    assert stat.S_IMODE(result.path.stat().st_mode) == 0o640
    assert not tuple(root.rglob("*.partial.*"))
    assert verification.method == "readback_sha256"
    assert verification.cleanup_strong
    assert events.index("after_partial_file_fsync") < events.index(
        "after_namespace_publish"
    )
    assert events.index("after_namespace_publish") < events.index(
        "after_destination_directory_fsync"
    )
    assert events.index("after_destination_directory_fsync") < events.index(
        "after_readback"
    )


def test_filesystem_receipt_last_retry_is_exactly_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    arguments = {
        "data": source(tmp_path, "data.zst", b"stored-data"),
        "data_key": "_encoded/data.zst",
        "source_manifest": source(tmp_path, "source-manifest.json", b"manifest\n"),
        "source_manifest_key": "_manifests/source.json",
        "receipt": source(tmp_path, "receipt.json", b"receipt\n"),
        "receipt_key": "_receipts/receipt.json",
    }
    try:
        first = publish_receipt_last(target, **arguments)
        second = publish_receipt_last(target, **arguments)
    finally:
        target.close()

    assert first.data.put.created
    assert first.source_manifest.put.created
    assert first.receipt.put.created
    assert not second.data.put.created
    assert not second.source_manifest.put.created
    assert not second.receipt.put.created
    assert (root / "_encoded/data.zst").read_bytes() == b"stored-data"
    assert (root / "_manifests/source.json").read_bytes() == b"manifest\n"
    assert (root / "_receipts/receipt.json").read_bytes() == b"receipt\n"


def test_exact_existing_object_is_idempotent_and_mismatch_is_conflict(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    first_source = source(tmp_path, "first.bin", b"same")
    second_source = source(tmp_path, "second.bin", b"different")
    try:
        first = target.put(first_source, "raw/object")
        repeated = target.put(first_source, "raw/object")
        with pytest.raises(ExistingObjectMismatch):
            target.put(second_source, "raw/object")
    finally:
        target.close()

    assert first.created
    assert not repeated.created
    assert (root / "raw/object").read_bytes() == b"same"


def test_verify_detects_size_or_sha_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, _root = mounted_target(tmp_path, monkeypatch)
    upload = source(tmp_path)
    try:
        target.put(upload, "raw/object")
        with pytest.raises(StoredObjectMismatch):
            target.verify("raw/object", upload.size_bytes + 1, upload.sha256)
        with pytest.raises(StoredObjectMismatch):
            target.verify("raw/object", upload.size_bytes, "f" * 64)
    finally:
        target.close()


def test_open_reader_is_nofollow_and_returns_exact_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    upload = source(tmp_path)
    try:
        target.put(upload, "raw/object")
        with target.open_reader("raw/object") as reader:
            assert reader.read() == b"immutable"
        (root / "raw/object").unlink()
        outside = tmp_path / "outside"
        outside.write_bytes(b"outside")
        (root / "raw/object").symlink_to(outside)
        with pytest.raises(ExistingObjectMismatch):
            target.open_reader("raw/object")
    finally:
        target.close()


@pytest.mark.parametrize("operation", ("put", "verify", "open_reader"))
def test_transient_object_io_is_retryable_target_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    upload = source(tmp_path)
    if operation != "put":
        target.put(upload, "raw/object")
    real_open = filesystem_module._open_regular_at

    def fail_object(parent_fd: int, name: str) -> int:
        if name == "object":
            raise OSError(errno.EIO, "injected transient storage error")
        return real_open(parent_fd, name)

    monkeypatch.setattr(filesystem_module, "_open_regular_at", fail_object)
    try:
        with pytest.raises(TargetUnavailable):
            if operation == "put":
                target.put(upload, "raw/object")
            elif operation == "verify":
                target.verify("raw/object", upload.size_bytes, upload.sha256)
            else:
                target.open_reader("raw/object")
    finally:
        target.close()

    if operation == "put":
        assert not (root / "raw/object").exists()


def test_symlinked_object_parent_cannot_escape_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "raw").symlink_to(outside, target_is_directory=True)
    try:
        with pytest.raises(ExistingObjectMismatch):
            target.put(source(tmp_path), "raw/object")
    finally:
        target.close()

    assert not (outside / "object").exists()


def test_symlinked_upload_source_is_rejected_without_publishing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    original = source(tmp_path, "original.bin", b"source")
    linked = tmp_path / "linked.bin"
    linked.symlink_to(original.path)
    forged = ArchiveObjectSource(
        path=linked,
        size_bytes=original.size_bytes,
        sha256=original.sha256,
    )
    try:
        with pytest.raises(ExistingObjectMismatch, match="upload source"):
            target.put(forged, "raw/object")
    finally:
        target.close()

    assert not (root / "raw/object").exists()


def test_transient_upload_source_open_is_retryable_target_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    upload = source(tmp_path)
    monkeypatch.setattr(
        filesystem_module,
        "open_readonly_nofollow",
        lambda _path: (_ for _ in ()).throw(
            OSError(errno.EIO, "injected transient source error")
        ),
    )
    try:
        with pytest.raises(TargetUnavailable):
            target.put(upload, "raw/object")
    finally:
        target.close()

    assert not (root / "raw/object").exists()


def test_guard_identity_change_after_probe_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, mount_root, root = mounted_target(tmp_path, monkeypatch)
    guard = mount_root / ".collector-mount-id"
    guard.rename(mount_root / ".old-guard")
    guard.write_bytes(b"expected")
    try:
        with pytest.raises(TargetUnavailable, match="mount guard identity"):
            target.put(source(tmp_path), "raw/object")
    finally:
        target.close()

    assert not (root / "raw/object").exists()


def test_guard_content_change_after_probe_fails_closed_without_secret_echo(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, mount_root, root = mounted_target(tmp_path, monkeypatch)
    guard = mount_root / ".collector-mount-id"
    guard.write_bytes(b"plaintext-wrong-guard-canary")
    try:
        with pytest.raises(TargetUnavailable, match="mount guard content") as caught:
            target.put(source(tmp_path), "raw/object")
    finally:
        target.close()

    assert "plaintext-wrong-guard-canary" not in str(caught.value)
    assert not (root / "raw/object").exists()


def test_mount_replacement_never_writes_into_local_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, mount_root, _root = mounted_target(tmp_path, monkeypatch)
    moved = tmp_path / "detached-webdav"
    mount_root.rename(moved)
    mount_root.mkdir()
    (mount_root / ".collector-mount-id").write_bytes(b"expected")
    try:
        with pytest.raises(TargetUnavailable, match="mount identity"):
            target.put(source(tmp_path), "raw/object")
    finally:
        target.close()

    assert not (mount_root / "archive").exists()
    assert not (moved / "archive/raw/object").exists()


def test_mount_replacement_during_put_never_reports_or_writes_fallback_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mount_holder: list[Path] = []
    moved_holder: list[Path] = []

    def replace_mount(phase: str) -> None:
        if phase != "after_partial_file_fsync" or moved_holder:
            return
        mount_root = mount_holder[0]
        moved = mount_root.with_name("detached-during-put")
        mount_root.rename(moved)
        mount_root.mkdir()
        (mount_root / ".collector-mount-id").write_bytes(b"expected")
        moved_holder.append(moved)

    target, mount_root, _root = mounted_target(
        tmp_path,
        monkeypatch,
        phase_hook=replace_mount,
    )
    mount_holder.append(mount_root)
    try:
        with pytest.raises(TargetUnavailable, match="mount identity"):
            target.put(source(tmp_path), "raw/object")
    finally:
        target.close()

    moved = moved_holder[0]
    assert not (mount_root / "archive").exists()
    assert (moved / "archive/raw/object").read_bytes() == b"immutable"


def test_root_replacement_after_probe_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    moved = root.with_name("archive-moved")
    root.rename(moved)
    root.mkdir()
    try:
        with pytest.raises(TargetUnavailable, match="target root identity"):
            target.put(source(tmp_path), "raw/object")
    finally:
        target.close()

    assert not (root / "raw/object").exists()
    assert not (moved / "raw/object").exists()


def test_open_object_parent_rename_cannot_return_escaped_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    moved: Path | None = None
    root_holder: list[Path] = []

    def move_parent(phase: str) -> None:
        nonlocal moved
        if phase != "after_partial_file_fsync" or moved is not None:
            return
        root = root_holder[0]
        current = root / "raw"
        moved = root / "raw-moved"
        current.rename(moved)
        current.mkdir()

    target, _mount_root, root = mounted_target(
        tmp_path,
        monkeypatch,
        phase_hook=move_parent,
    )
    root_holder.append(root)
    try:
        with pytest.raises(
            ExistingObjectMismatch,
            match="parent identity|unavailable",
        ):
            target.put(source(tmp_path), "raw/object")
    finally:
        target.close()

    assert moved is not None
    assert not (root / "raw/object").exists()
    assert (moved / "object").read_bytes() == b"immutable"


def test_streamed_source_identity_detects_same_size_modify_restore_race(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    upload = source(tmp_path, data=b"frozen-A")
    original_copy = filesystem_module._copy_exact

    def raced_copy(source_fd: int, destination_fd: int, expected) -> None:
        upload.path.write_bytes(b"mutatedB")
        try:
            original_copy(source_fd, destination_fd, expected)
        finally:
            upload.path.write_bytes(b"frozen-A")

    monkeypatch.setattr(filesystem_module, "_copy_exact", raced_copy)
    try:
        with pytest.raises(ExistingObjectMismatch, match="frozen identity"):
            target.put(upload, "raw/object")
    finally:
        target.close()

    assert not (root / "raw/object").exists()


def test_second_target_owner_fails_fast_then_can_reopen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, mount_root, _root = mounted_target(tmp_path, monkeypatch)
    second = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue("expected"),
        data_root=tmp_path / "data",
    )
    try:
        with pytest.raises(TargetUnavailable, match="writer lock"):
            second.probe()
    finally:
        first.close()

    second.probe()
    second.close()


def test_second_process_cannot_acquire_same_target_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, mount_root, _root = mounted_target(tmp_path, monkeypatch)
    program = textwrap.dedent(
        """
        import os
        import sys
        from pathlib import Path

        import crypto_collector.archive.targets.filesystem as module
        from crypto_collector.archive.policy import freeze_policy
        from crypto_collector.archive.targets.base import TargetUnavailable
        from crypto_collector.archive.targets.filesystem import FilesystemTarget
        from crypto_collector.config.models import ArchiveConfig
        from crypto_collector.config.primitives import SecretValue

        mount_root = Path(sys.argv[1])
        data_root = Path(sys.argv[2])
        module._mount_identity_token = lambda _path, fd: (
            f"test:{os.fstat(fd).st_dev}:{os.fstat(fd).st_ino}"
        )
        module._require_independent_backing_storage = (
            lambda _data_root_fd, _mount_root_fd: None
        )
        policy = freeze_policy(config=ArchiveConfig.model_validate({
            "targets": [{
                "id": "webdav-mount",
                "type": "filesystem",
                "root": str(mount_root / "archive"),
                "mount_root": str(mount_root),
                "mount_guard": {
                    "path": str(mount_root / ".collector-mount-id"),
                    "expected": "env:WEBDAV_MOUNT_GUARD",
                },
                "durability_capability": "operator_attested_fsync_readback",
                "compression": {"enabled": False},
            }]
        }))
        target = FilesystemTarget(
            policy.target("webdav-mount"),
            expected_guard=SecretValue("expected"),
            data_root=data_root,
        )
        try:
            target.probe()
        except TargetUnavailable as error:
            sys.exit(0 if "writer lock" in str(error) else 2)
        else:
            target.close()
            sys.exit(1)
        """
    )
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                program,
                os.fspath(mount_root),
                os.fspath(tmp_path / "data"),
            ],
            check=False,
        )
    finally:
        first.close()

    assert completed.returncode == 0


def test_fork_child_close_cannot_release_parent_writer_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    child_pid = os.fork()
    if child_pid == 0:
        first.close()
        os._exit(0)
    waited_pid, status = os.waitpid(child_pid, 0)
    assert waited_pid == child_pid
    assert os.waitstatus_to_exitcode(status) == 0
    contender = textwrap.dedent(
        """
        import errno
        import fcntl
        import os
        import sys

        fd = os.open(sys.argv[1], os.O_RDONLY)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            sys.exit(0 if error.errno in {errno.EACCES, errno.EAGAIN} else 2)
        else:
            sys.exit(1)
        finally:
            os.close(fd)
        """
    )
    try:
        completed = subprocess.run(
            [sys.executable, "-c", contender, os.fspath(root)],
            check=False,
        )
    finally:
        first.close()

    assert completed.returncode == 0


def test_crash_after_partial_sync_resumes_without_recopied_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def crash(phase: str) -> None:
        if phase == "after_partial_file_fsync":
            raise InjectedCrash

    first, mount_root, root = mounted_target(
        tmp_path,
        monkeypatch,
        phase_hook=crash,
    )
    upload = source(tmp_path, data=b"resume-me")
    with pytest.raises(InjectedCrash):
        first.put(upload, "raw/object")
    first.close()
    assert len(tuple(root.rglob("*.partial.*"))) == 1

    restarted = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue("expected"),
        data_root=tmp_path / "data",
    )
    restarted.probe()
    try:
        result = restarted.put(upload, "raw/object")
    finally:
        restarted.close()

    assert result.created
    assert result.resumed
    assert (root / "raw/object").read_bytes() == b"resume-me"
    assert not tuple(root.rglob("*.partial.*"))


def test_truncated_crash_partial_is_replaced_on_restart(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def crash(phase: str) -> None:
        if phase == "after_partial_directory_fsync":
            raise InjectedCrash

    first, mount_root, root = mounted_target(
        tmp_path,
        monkeypatch,
        phase_hook=crash,
    )
    upload = source(tmp_path, data=b"replace-truncated-partial")
    with pytest.raises(InjectedCrash):
        first.put(upload, "raw/object")
    first.close()
    assert len(tuple(root.rglob("*.partial.*"))) == 1

    restarted = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue("expected"),
        data_root=tmp_path / "data",
    )
    restarted.probe()
    try:
        result = restarted.put(upload, "raw/object")
    finally:
        restarted.close()

    assert result.created
    assert not result.resumed
    assert (root / "raw/object").read_bytes() == b"replace-truncated-partial"
    assert not tuple(root.rglob("*.partial.*"))


def test_crash_after_namespace_publish_converges_without_second_object(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def crash(phase: str) -> None:
        if phase == "after_namespace_publish":
            raise InjectedCrash

    first, mount_root, root = mounted_target(
        tmp_path,
        monkeypatch,
        phase_hook=crash,
    )
    upload = source(tmp_path, data=b"published-before-crash")
    with pytest.raises(InjectedCrash):
        first.put(upload, "raw/object")
    first.close()
    assert (root / "raw/object").read_bytes() == b"published-before-crash"

    restarted = FilesystemTarget(
        frozen_filesystem_target(mount_root),
        expected_guard=SecretValue("expected"),
        data_root=tmp_path / "data",
    )
    restarted.probe()
    try:
        result = restarted.put(upload, "raw/object")
    finally:
        restarted.close()

    assert not result.created
    assert (root / "raw/object").read_bytes() == b"published-before-crash"
    assert not tuple(root.rglob("*.partial.*"))


def test_concurrent_exact_puts_are_idempotent_with_one_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, root = mounted_target(tmp_path, monkeypatch)
    upload = source(tmp_path)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = tuple(
                executor.map(
                    lambda _ignored: target.put(upload, "raw/object"),
                    range(2),
                )
            )
    finally:
        target.close()

    assert sorted(result.created for result in results) == [False, True]
    assert (root / "raw/object").read_bytes() == b"immutable"
    assert not tuple(root.rglob("*.partial.*"))


def test_probe_fails_when_no_replace_primitive_is_unavailable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, _root = unprobed_target(tmp_path, monkeypatch)

    def unavailable(_root_fd: int, _phase_hook=None):
        raise OSError(errno.ENOTSUP, "no no-replace primitive")

    monkeypatch.setattr(
        filesystem_module,
        "_probe_no_replace_capability",
        unavailable,
    )

    with pytest.raises(TargetUnavailable, match="no-replace"):
        target.probe()


def test_put_rejects_replace_and_multipart_resume_arguments(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target, _mount_root, _root = mounted_target(tmp_path, monkeypatch)
    upload = source(tmp_path)
    try:
        with pytest.raises(ValueError, match="no_replace"):
            target.put(upload, "raw/object", no_replace=False)
        with pytest.raises(ValueError, match="multipart resume"):
            target.put(upload, "raw/object", resume=object())  # type: ignore[arg-type]
    finally:
        target.close()
