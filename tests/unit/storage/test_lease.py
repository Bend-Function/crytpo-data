from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

import pytest

from crypto_collector.storage.lease import SourceLease, SourceLeaseBusy


def test_shared_leases_coexist_and_block_nonblocking_exclusive(tmp_path: Path) -> None:
    lease_path = tmp_path / "part.lease"

    with (
        SourceLease.shared(lease_path) as first,
        SourceLease.shared(lease_path) as second,
    ):
        assert first.lease_path == second.lease_path == lease_path
        with pytest.raises(SourceLeaseBusy):
            SourceLease.exclusive(lease_path, blocking=False)

    with SourceLease.exclusive(lease_path, blocking=False):
        pass


def test_new_lease_is_regular_with_restricted_mode_and_is_not_removed(
    tmp_path: Path,
) -> None:
    lease_path = tmp_path / "part.lease"

    with SourceLease.shared(lease_path):
        observed = lease_path.stat()
        assert stat.S_ISREG(observed.st_mode)
        assert stat.S_IMODE(observed.st_mode) == 0o640

    assert lease_path.exists()


def test_source_lease_rejects_leaf_and_parent_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target.lease"
    target.write_bytes(b"")
    leaf_link = tmp_path / "leaf.lease"
    leaf_link.symlink_to(target)

    with pytest.raises(OSError):
        SourceLease.shared(leaf_link)

    real_parent = tmp_path / "real"
    real_parent.mkdir()
    parent_link = tmp_path / "linked"
    parent_link.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(OSError):
        SourceLease.shared(parent_link / "part.lease")


def test_only_lock_contention_is_mapped_to_source_lease_busy(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_lock(_fd: int, _operation: int) -> None:
        raise OSError(errno.EPERM, "not contention")

    monkeypatch.setattr("crypto_collector.storage.lease.fcntl.flock", fail_lock)

    with pytest.raises(OSError, match="not contention") as raised:
        SourceLease.shared(tmp_path / "part.lease")
    assert not isinstance(raised.value, SourceLeaseBusy)


def test_released_lease_cannot_be_reentered(tmp_path: Path) -> None:
    lease = SourceLease.shared(tmp_path / "part.lease")
    lease.release()
    lease.release()

    with pytest.raises(RuntimeError, match="released"):
        lease.__enter__()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="requires POSIX FIFO support")
def test_source_lease_rejects_non_regular_existing_path(tmp_path: Path) -> None:
    lease_path = tmp_path / "part.lease"
    os.mkfifo(lease_path)

    with pytest.raises(OSError, match="regular"):
        SourceLease.shared(lease_path, blocking=False)
