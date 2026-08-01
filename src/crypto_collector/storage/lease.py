from __future__ import annotations

import errno
import fcntl
import os
import stat
from pathlib import Path
from typing import Self


class SourceLeaseBusy(RuntimeError):
    def __init__(self, lease_path: Path) -> None:
        self.lease_path = lease_path
        super().__init__(f"source lease is busy: {lease_path}")


def _required_open_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise OSError(errno.ENOTSUP, f"required open flag {name} is unavailable")
    return value


def _normalized_absolute_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("source lease path must be Path")
    if not path.name or path.name in {".", ".."} or "\x00" in os.fspath(path):
        raise ValueError("source lease path must name a normalized file")
    return Path(os.path.abspath(os.fspath(path)))


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_DIRECTORY")
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
    )


def _regular_flags(flags: int) -> int:
    return (
        flags
        | _required_open_flag("O_NOFOLLOW")
        | _required_open_flag("O_CLOEXEC")
        | getattr(os, "O_NONBLOCK", 0)
    )


def _open_parent_no_follow(path: Path) -> tuple[int, str, Path]:
    absolute = _normalized_absolute_path(path)
    parts = absolute.parts
    if not absolute.anchor or not parts:
        raise ValueError("source lease path must be absolute")
    parent_fd = os.open(absolute.anchor, _directory_flags())
    try:
        for segment in parts[1:-1]:
            if segment in {"", ".", ".."}:
                raise ValueError("source lease path must be normalized")
            next_fd = os.open(
                segment,
                _directory_flags(),
                dir_fd=parent_fd,
            )
            os.close(parent_fd)
            parent_fd = next_fd
        return parent_fd, parts[-1], absolute
    except BaseException:
        os.close(parent_fd)
        raise


def _open_regular_no_follow(path: Path, flags: int = os.O_RDONLY) -> tuple[int, Path]:
    parent_fd, name, absolute = _open_parent_no_follow(path)
    try:
        try:
            fd = os.open(name, _regular_flags(flags), dir_fd=parent_fd)
        except IsADirectoryError as error:
            raise OSError(errno.EINVAL, "path is not a regular file") from error
    finally:
        os.close(parent_fd)
    observed = os.fstat(fd)
    if not stat.S_ISREG(observed.st_mode):
        os.close(fd)
        raise OSError(errno.EINVAL, "path is not a regular file")
    return fd, absolute


def _open_or_create_lease(path: Path) -> tuple[int, Path]:
    parent_fd, name, absolute = _open_parent_no_follow(path)
    created = False
    try:
        try:
            fd = os.open(name, _regular_flags(os.O_RDWR), dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                fd = os.open(
                    name,
                    _regular_flags(os.O_RDWR | os.O_CREAT | os.O_EXCL),
                    0o640,
                    dir_fd=parent_fd,
                )
                created = True
            except FileExistsError:
                fd = os.open(name, _regular_flags(os.O_RDWR), dir_fd=parent_fd)
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode):
            os.close(fd)
            raise OSError(errno.EINVAL, "source lease is not a regular file")
        if created:
            os.fchmod(fd, 0o640)
            os.fsync(fd)
            os.fsync(parent_fd)
        return fd, absolute
    finally:
        os.close(parent_fd)


class SourceLease:
    __slots__ = ("_fd", "_identity", "lease_path")

    def __init__(self, lease_path: Path, fd: int) -> None:
        self.lease_path = lease_path
        self._fd: int | None = fd
        observed = os.fstat(fd)
        self._identity = (observed.st_dev, observed.st_ino)

    @classmethod
    def _acquire(
        cls,
        lease_path: Path,
        *,
        exclusive: bool,
        blocking: bool,
    ) -> SourceLease:
        if type(blocking) is not bool:
            raise TypeError("blocking must be bool")
        fd, absolute = _open_or_create_lease(lease_path)
        operation = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        if not blocking:
            operation |= fcntl.LOCK_NB
        try:
            fcntl.flock(fd, operation)
        except OSError as error:
            os.close(fd)
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise SourceLeaseBusy(absolute) from error
            raise
        return cls(absolute, fd)

    @classmethod
    def shared(cls, lease_path: Path, *, blocking: bool = True) -> SourceLease:
        return cls._acquire(lease_path, exclusive=False, blocking=blocking)

    @classmethod
    def exclusive(cls, lease_path: Path, *, blocking: bool = True) -> SourceLease:
        return cls._acquire(lease_path, exclusive=True, blocking=blocking)

    @property
    def held(self) -> bool:
        return self._fd is not None

    def _assert_held_for(self, expected_path: Path) -> None:
        fd = self._fd
        if fd is None:
            raise RuntimeError("source lease has been released")
        expected = _normalized_absolute_path(expected_path)
        if self.lease_path != expected:
            raise ValueError("source lease does not bind the expected data identity")
        observed = os.fstat(fd)
        if (observed.st_dev, observed.st_ino) != self._identity:
            raise ValueError("source lease descriptor identity changed")
        current_fd, _ = _open_regular_no_follow(expected)
        try:
            current = os.fstat(current_fd)
            if (current.st_dev, current.st_ino) != self._identity:
                raise ValueError("source lease path identity changed")
        finally:
            os.close(current_fd)

    def release(self) -> None:
        fd = self._fd
        if fd is None:
            return
        self._fd = None
        unlock_error: OSError | None = None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError as error:
            unlock_error = error
        try:
            os.close(fd)
        except OSError:
            if unlock_error is None:
                raise
        if unlock_error is not None:
            raise unlock_error

    def __enter__(self) -> Self:
        if self._fd is None:
            raise RuntimeError("source lease has been released")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()

    def __del__(self) -> None:
        try:
            self.release()
        except OSError:
            pass


__all__ = ["SourceLease", "SourceLeaseBusy"]
