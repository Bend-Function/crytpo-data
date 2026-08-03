from __future__ import annotations

import errno
import fcntl
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Self

from crypto_collector.domain.types import Exchange


def _required_open_flag(name: str) -> int:
    flag = getattr(os, name, None)
    if type(flag) is not int or flag == 0:
        raise OSError(errno.ENOTSUP, f"{name} is required for safe storage access")
    return flag


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_open_flag("O_DIRECTORY")
        | _required_open_flag("O_CLOEXEC")
        | _required_open_flag("O_NOFOLLOW")
    )


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _open_child_directory(parent_fd: int, part: str) -> int:
    child_fd: int | None = None
    try:
        try:
            child_fd = os.open(part, _directory_flags(), dir_fd=parent_fd)
        except FileNotFoundError:
            try:
                os.mkdir(part, mode=0o750, dir_fd=parent_fd)
            except FileExistsError:
                pass
            child_fd = os.open(part, _directory_flags(), dir_fd=parent_fd)
        if not stat.S_ISDIR(os.fstat(child_fd).st_mode):
            raise OSError(errno.ENOTDIR, "storage path segment is not a directory")
        os.fsync(parent_fd)
        return child_fd
    except BaseException:
        if child_fd is not None:
            _close_quietly(child_fd)
        raise


def _open_directory_chain_no_symlinks(
    data_root: str | os.PathLike[str],
    suffix: tuple[str, ...],
) -> tuple[Path, int]:
    absolute_root = Path(os.path.abspath(os.fspath(data_root)))
    anchor = absolute_root.anchor
    if not anchor:
        raise ValueError("data_root must resolve to an absolute path")
    target = absolute_root.joinpath(*suffix)
    parts = (*absolute_root.parts[1:], *suffix)
    current_fd = os.open(anchor, _directory_flags())
    try:
        for part in parts:
            if part in {"", ".", ".."}:
                raise ValueError("data_root must be normalized")
            child_fd = _open_child_directory(current_fd, part)
            try:
                os.close(current_fd)
            except BaseException:
                _close_quietly(child_fd)
                raise
            current_fd = child_fd
        return target, current_fd
    except BaseException:
        _close_quietly(current_fd)
        raise


def _open_data_root_no_symlinks(
    data_root: str | os.PathLike[str],
) -> tuple[Path, int]:
    return _open_directory_chain_no_symlinks(data_root, ())


def _open_exchange_root_no_symlinks(
    data_root: str | os.PathLike[str],
    exchange: Exchange,
) -> tuple[Path, int]:
    if type(exchange) is not Exchange:
        raise TypeError("exchange must be Exchange")
    return _open_directory_chain_no_symlinks(data_root, ("raw", exchange.value))


def create_exchange_root_no_symlinks(
    data_root: str | os.PathLike[str],
    exchange: Exchange,
) -> Path:
    exchange_root, fd = _open_exchange_root_no_symlinks(data_root, exchange)
    os.close(fd)
    return exchange_root


class WriterAlreadyRunning(RuntimeError):
    def __init__(self, exchange_root: Path) -> None:
        self.exchange_root = exchange_root
        super().__init__("an exchange writer already owns this storage root")


class _WriterLockContended(Exception):
    pass


def _flock_nonblocking(fd: int) -> None:
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        if error.errno in {errno.EACCES, errno.EAGAIN}:
            raise _WriterLockContended from error
        raise


@dataclass(slots=True)
class ExchangeWriterLock:
    exchange_root: Path
    fd: int
    root_fd: int
    anchor_fd: int
    _released: bool = False

    @classmethod
    def acquire(
        cls,
        data_root: str | os.PathLike[str],
        *,
        exchange: Exchange,
    ) -> ExchangeWriterLock:
        if type(exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        absolute_data_root, data_root_fd = _open_data_root_no_symlinks(data_root)
        raw_root = absolute_data_root / "raw"
        exchange_root = raw_root / exchange.value
        anchor_fd: int | None = None
        raw_root_fd: int | None = None
        root_fd: int | None = None
        fd: int | None = None
        try:
            # The data-root anchor survives a rename of raw/ or raw/<exchange>. The
            # configured data-root parent namespace is the administrative trust boundary.
            lock_flags = (
                os.O_CREAT
                | os.O_RDWR
                | _required_open_flag("O_CLOEXEC")
                | _required_open_flag("O_NOFOLLOW")
            )
            anchor_fd = os.open(
                f".raw-writer-{exchange.value}.lock",
                lock_flags,
                0o640,
                dir_fd=data_root_fd,
            )
            if not stat.S_ISREG(os.fstat(anchor_fd).st_mode):
                raise OSError(errno.EINVAL, "writer anchor lock is not a regular file")
            os.fsync(data_root_fd)
            _flock_nonblocking(anchor_fd)
            raw_root_fd = _open_child_directory(data_root_fd, "raw")
            root_fd = _open_child_directory(raw_root_fd, exchange.value)
            _flock_nonblocking(root_fd)
            fd = os.open(".writer.lock", lock_flags, 0o640, dir_fd=root_fd)
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise OSError(errno.EINVAL, "writer lock is not a regular file")
            os.fsync(root_fd)
            _flock_nonblocking(fd)
            instance = cls(
                exchange_root=exchange_root,
                fd=fd,
                root_fd=root_fd,
                anchor_fd=anchor_fd,
            )
            os.close(raw_root_fd)
            raw_root_fd = None
            os.close(data_root_fd)
            return instance
        except BaseException as error:
            if fd is not None:
                _close_quietly(fd)
            if root_fd is not None:
                _close_quietly(root_fd)
            if raw_root_fd is not None:
                _close_quietly(raw_root_fd)
            if anchor_fd is not None:
                _close_quietly(anchor_fd)
            _close_quietly(data_root_fd)
            if isinstance(error, _WriterLockContended):
                raise WriterAlreadyRunning(exchange_root) from error
            raise

    @property
    def released(self) -> bool:
        return self._released

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        errors: list[BaseException] = []
        for descriptor in (self.fd, self.root_fd, self.anchor_fd):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except BaseException as error:  # noqa: BLE001 - every FD must still close
                errors.append(error)
            try:
                os.close(descriptor)
            except BaseException as error:  # noqa: BLE001 - close the remaining FD
                errors.append(error)
        if errors:
            raise errors[0]

    def __enter__(self) -> Self:
        if self._released:
            raise ValueError("writer lock is already released")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()


__all__ = [
    "ExchangeWriterLock",
    "WriterAlreadyRunning",
    "create_exchange_root_no_symlinks",
]
