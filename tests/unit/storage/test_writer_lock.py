from __future__ import annotations

import errno
import fcntl
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

import crypto_collector.storage.writer_lock as writer_lock_module
from crypto_collector.domain.types import Exchange
from crypto_collector.storage.writer_lock import (
    ExchangeWriterLock,
    WriterAlreadyRunning,
    create_exchange_root_no_symlinks,
)


def test_second_writer_cannot_hold_same_exchange_root(tmp_path: Path) -> None:
    first = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    try:
        with pytest.raises(WriterAlreadyRunning) as captured:
            ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    finally:
        first.release()

    assert captured.value.exchange_root == tmp_path / "raw" / "okx"


def test_second_process_cannot_hold_same_exchange_root(tmp_path: Path) -> None:
    first = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys; "
                    "from pathlib import Path; "
                    "from crypto_collector.domain.types import Exchange; "
                    "from crypto_collector.storage.writer_lock import "
                    "ExchangeWriterLock, WriterAlreadyRunning; "
                    "\ntry: ExchangeWriterLock.acquire("
                    "Path(sys.argv[1]), exchange=Exchange.OKX)"
                    "\nexcept WriterAlreadyRunning: sys.exit(0)"
                    "\nelse: sys.exit(1)"
                ),
                os.fspath(tmp_path),
            ],
            check=False,
        )
    finally:
        first.release()

    assert completed.returncode == 0


def test_unlinked_lock_filename_cannot_bypass_exchange_root_ownership(
    tmp_path: Path,
) -> None:
    first = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    lock_path = first.exchange_root / ".writer.lock"
    lock_path.unlink()
    try:
        with pytest.raises(WriterAlreadyRunning):
            ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    finally:
        first.release()

    replacement = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    replacement.release()


def test_renamed_exchange_root_cannot_bypass_writer_ownership(
    tmp_path: Path,
) -> None:
    first = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    moved_root = first.exchange_root.with_name("okx-moved")
    first.exchange_root.rename(moved_root)
    second: ExchangeWriterLock | None = None
    try:
        with pytest.raises(WriterAlreadyRunning):
            second = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    finally:
        if second is not None:
            second.release()
        first.release()

    assert not first.exchange_root.exists()


def test_renamed_raw_root_cannot_bypass_writer_ownership(tmp_path: Path) -> None:
    first = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    raw_root = tmp_path / "raw"
    moved_root = tmp_path / "raw-moved"
    raw_root.rename(moved_root)
    second: ExchangeWriterLock | None = None
    try:
        with pytest.raises(WriterAlreadyRunning):
            second = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    finally:
        if second is not None:
            second.release()
        first.release()

    assert not raw_root.exists()


def test_different_exchange_roots_have_independent_locks(tmp_path: Path) -> None:
    first = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    second = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.BYBIT)

    second.release()
    first.release()


def test_release_is_idempotent_and_context_manager_releases(tmp_path: Path) -> None:
    with ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX) as lock:
        fd = lock.fd
        root_fd = lock.root_fd
        anchor_fd = lock.anchor_fd
        assert os.fstat(fd).st_mode
        assert stat.S_ISDIR(os.fstat(root_fd).st_mode)
        assert stat.S_ISREG(os.fstat(anchor_fd).st_mode)

    for descriptor in (fd, root_fd, anchor_fd):
        with pytest.raises(OSError) as captured:
            os.fstat(descriptor)
        assert captured.value.errno == errno.EBADF
    lock.release()
    replacement = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    replacement.release()


def test_writer_lock_preserves_noncontention_oserror(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_flock = writer_lock_module.fcntl.flock

    def fail_lock(fd: int, operation: int) -> None:
        if operation & fcntl.LOCK_NB:
            raise OSError(errno.EIO, "injected lock I/O failure")
        original_flock(fd, operation)

    monkeypatch.setattr(writer_lock_module.fcntl, "flock", fail_lock)

    with pytest.raises(OSError) as captured:
        ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)

    assert type(captured.value) is OSError
    assert captured.value.errno == errno.EIO


def test_failed_flock_closes_the_open_lock_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock_fd: int | None = None
    original_open = writer_lock_module.os.open
    original_flock = writer_lock_module.fcntl.flock

    def tracking_open(path: object, *args: object, **kwargs: object) -> int:
        nonlocal lock_fd
        fd = original_open(path, *args, **kwargs)  # type: ignore[arg-type]
        if path == ".writer.lock":
            lock_fd = fd
        return fd

    monkeypatch.setattr(writer_lock_module.os, "open", tracking_open)

    def fail_file_lock(target_fd: int, operation: int) -> None:
        if lock_fd is not None and target_fd == lock_fd:
            raise OSError(errno.EIO, "io")
        original_flock(target_fd, operation)

    monkeypatch.setattr(writer_lock_module.fcntl, "flock", fail_file_lock)

    with pytest.raises(OSError):
        ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)

    assert lock_fd is not None
    with pytest.raises(OSError) as captured:
        os.fstat(lock_fd)
    assert captured.value.errno == errno.EBADF


def test_interrupted_flock_closes_the_open_lock_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InjectedInterruption(BaseException):
        pass

    lock_fd: int | None = None
    original_open = writer_lock_module.os.open
    original_flock = writer_lock_module.fcntl.flock

    def tracking_open(path: object, *args: object, **kwargs: object) -> int:
        nonlocal lock_fd
        fd = original_open(path, *args, **kwargs)  # type: ignore[arg-type]
        if path == ".writer.lock":
            lock_fd = fd
        return fd

    monkeypatch.setattr(writer_lock_module.os, "open", tracking_open)

    def interrupt_file_lock(target_fd: int, operation: int) -> None:
        if lock_fd is not None and target_fd == lock_fd:
            raise InjectedInterruption
        original_flock(target_fd, operation)

    monkeypatch.setattr(
        writer_lock_module.fcntl,
        "flock",
        interrupt_file_lock,
    )

    with pytest.raises(InjectedInterruption):
        ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)

    assert lock_fd is not None
    with pytest.raises(OSError) as captured:
        os.fstat(lock_fd)
    assert captured.value.errno == errno.EBADF


def test_failed_lock_object_construction_releases_owned_descriptors(
    tmp_path: Path,
) -> None:
    class ConstructionFailed(RuntimeError):
        pass

    class FailingWriterLock(ExchangeWriterLock):
        def __init__(self, **_kwargs: object) -> None:
            raise ConstructionFailed

    with pytest.raises(ConstructionFailed):
        FailingWriterLock.acquire(tmp_path, exchange=Exchange.OKX)

    replacement = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    replacement.release()


def test_release_closes_descriptor_even_when_unlock_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lock = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    fd = lock.fd
    original_flock = writer_lock_module.fcntl.flock

    def fail_unlock(target_fd: int, operation: int) -> None:
        if operation == fcntl.LOCK_UN:
            raise OSError(errno.EIO, "unlock failed")
        original_flock(target_fd, operation)

    monkeypatch.setattr(writer_lock_module.fcntl, "flock", fail_unlock)

    with pytest.raises(OSError, match="unlock failed"):
        lock.release()

    assert lock.released
    with pytest.raises(OSError) as captured:
        os.fstat(fd)
    assert captured.value.errno == errno.EBADF
    lock.release()


def test_writer_lock_rejects_symlink_leaf(tmp_path: Path) -> None:
    exchange_root = tmp_path / "raw" / Exchange.OKX.value
    exchange_root.mkdir(parents=True)
    (exchange_root / "target").write_text("", encoding="utf-8")
    (exchange_root / ".writer.lock").symlink_to("target")

    with pytest.raises(OSError):
        ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)


def test_writer_lock_rejects_symlink_anchor(tmp_path: Path) -> None:
    tmp_path.mkdir(exist_ok=True)
    (tmp_path / "target").write_text("", encoding="utf-8")
    (tmp_path / ".raw-writer-okx.lock").symlink_to("target")

    lock: ExchangeWriterLock | None = None
    try:
        with pytest.raises(OSError):
            lock = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    finally:
        if lock is not None:
            lock.release()

    assert not (tmp_path / "raw").exists()


def test_directory_walk_closes_parent_and_child_when_parent_close_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class InjectedCloseFailure(RuntimeError):
        pass

    opened_fds: list[int] = []
    failed = False
    original_open = writer_lock_module.os.open
    original_close = writer_lock_module.os.close

    def tracking_open(path: object, *args: object, **kwargs: object) -> int:
        fd = original_open(path, *args, **kwargs)  # type: ignore[arg-type]
        opened_fds.append(fd)
        return fd

    def fail_first_close(fd: int) -> None:
        nonlocal failed
        if not failed:
            failed = True
            raise InjectedCloseFailure("injected parent close failure")
        original_close(fd)

    monkeypatch.setattr(writer_lock_module.os, "open", tracking_open)
    monkeypatch.setattr(writer_lock_module.os, "close", fail_first_close)

    with pytest.raises(InjectedCloseFailure, match="parent close failure"):
        create_exchange_root_no_symlinks(tmp_path / "data", Exchange.OKX)

    assert failed
    assert len(opened_fds) == 2
    for descriptor in opened_fds:
        with pytest.raises(OSError) as captured:
            os.fstat(descriptor)
        assert captured.value.errno == errno.EBADF


def test_exchange_root_walk_rejects_symlinked_data_root_segment(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)

    with pytest.raises(OSError):
        create_exchange_root_no_symlinks(linked, Exchange.OKX)

    assert not (actual / "raw").exists()


def test_exchange_root_walk_fails_closed_without_nofollow_support(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(actual, target_is_directory=True)
    monkeypatch.setattr(writer_lock_module.os, "O_NOFOLLOW", 0)

    with pytest.raises(OSError) as captured:
        create_exchange_root_no_symlinks(linked, Exchange.OKX)

    assert captured.value.errno == errno.ENOTSUP
    assert not (actual / "raw").exists()


def test_exchange_root_walk_rejects_non_directory_segment(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    data_root.write_text("not a directory", encoding="utf-8")

    with pytest.raises(OSError):
        create_exchange_root_no_symlinks(data_root, Exchange.OKX)


def test_exchange_root_is_created_with_normalized_absolute_identity(
    tmp_path: Path,
) -> None:
    relative = tmp_path / "nested" / ".." / "data"

    result = create_exchange_root_no_symlinks(relative, Exchange.BITGET)

    assert result == tmp_path / "data" / "raw" / "bitget"
    assert result.is_dir()


def test_exchange_argument_must_be_the_frozen_enum(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="Exchange"):
        ExchangeWriterLock.acquire(tmp_path, exchange="okx")  # type: ignore[arg-type]
