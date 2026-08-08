from __future__ import annotations

import ctypes
import errno
import fcntl
import hashlib
import hmac
import os
import re
import stat
import sys
import threading
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import IO, Self

from pydantic import ValidationError

from crypto_collector.archive.models import (
    ArchiveVerificationLevel,
    FrozenArchiveTargetV1,
)
from crypto_collector.archive.state import (
    ExistingObjectMismatch,
    StoredObjectMismatch,
)
from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    PutResult,
    ResumeState,
    TargetClosed,
    TargetProbe,
    TargetUnavailable,
    UnsafeObjectKey,
    VerifyResult,
)
from crypto_collector.config.primitives import SecretValue
from crypto_collector.storage.raw_writer import (
    open_readonly_nofollow,
    size_and_sha256_fd,
)

_IO_CHUNK_BYTES = 1024 * 1024
_MAX_GUARD_BYTES = 64 * 1024
_RENAME_NOREPLACE = 1
_DARWIN_RENAME_EXCL = 0x00000004
_OWNER_REGISTRY_LOCK = threading.Lock()
_OWNED_TARGET_ROOTS: set[tuple[int, int]] = set()
_OWNER_REGISTRY_PID = os.getpid()
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_INTERNAL_PREFIX = ".crypto-collector-"
PhaseHook = Callable[[str], None]


class FilesystemNoReplaceCapability(StrEnum):
    RENAME_NOREPLACE = "rename_noreplace"
    HARDLINK = "hardlink"


class _NoReplaceUnsupported(OSError):
    pass


class _DarwinFsid(ctypes.Structure):
    _fields_ = [("values", ctypes.c_int32 * 2)]


class _DarwinStatfs(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _DarwinFsid),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_reserved", ctypes.c_uint32 * 8),
    ]


@dataclass(frozen=True, slots=True)
class _ObjectKey:
    value: str
    parent_parts: tuple[str, ...]
    basename: str


def _required_flag(name: str) -> int:
    value = getattr(os, name, None)
    if type(value) is not int or value == 0:
        raise OSError(errno.ENOTSUP, f"required open flag {name} is unavailable")
    return value


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_DIRECTORY")
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
    )


def _readonly_flags() -> int:
    return (
        os.O_RDONLY
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
        | getattr(os, "O_NONBLOCK", 0)
    )


def _write_flags() -> int:
    return (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | _required_flag("O_NOFOLLOW")
        | _required_flag("O_CLOEXEC")
        | getattr(os, "O_NONBLOCK", 0)
    )


def _close_quietly(fd: int) -> None:
    with suppress(OSError):
        os.close(fd)


def _normalized_absolute(path: Path, *, field_name: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{field_name} must be Path")
    if (
        not path.is_absolute()
        or path == Path(path.anchor)
        or any(part in {"", ".", ".."} for part in path.parts[1:])
    ):
        raise ValueError(f"{field_name} must be a normalized non-root absolute path")
    return path


def _paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _open_absolute_directory(path: Path) -> int:
    if not isinstance(path, Path) or not path.is_absolute():
        raise ValueError("filesystem directory must be a normalized absolute path")
    if path == Path(path.anchor):
        return os.open(path.anchor, _directory_flags())
    absolute = _normalized_absolute(path, field_name="filesystem directory")
    current_fd = os.open(absolute.anchor, _directory_flags())
    try:
        for part in absolute.parts[1:]:
            child_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        _close_quietly(current_fd)
        raise


def _filesystem_boundary_identity(fd: int) -> str:
    if sys.platform.startswith("linux"):
        try:
            fields = Path(f"/proc/self/fdinfo/{fd}").read_bytes().splitlines()
        except OSError as error:
            raise TargetUnavailable(
                "filesystem mount boundary table is unavailable"
            ) from error
        for line in fields:
            name, separator, value = line.partition(b":")
            if name == b"mnt_id" and separator:
                try:
                    return f"linux-mount-id:{int(value.strip())}"
                except ValueError:
                    break
        raise TargetUnavailable("filesystem mount boundary identity is invalid")
    if sys.platform == "darwin":
        fsid, _mount_point = _darwin_statfs(fd)
        return f"darwin-fsid:{fsid[0]}:{fsid[1]}"
    return f"device:{os.fstat(fd).st_dev}"


def _open_relative_directory(
    root_fd: int,
    parts: tuple[str, ...],
    *,
    create: bool,
    expected_device: int,
    expected_boundary: str,
) -> int:
    current_fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                child_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, 0o750, dir_fd=current_fd)
                except FileExistsError:
                    pass
                else:
                    os.fsync(current_fd)
                child_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
            observed = os.fstat(child_fd)
            if (
                observed.st_dev != expected_device
                or _filesystem_boundary_identity(child_fd) != expected_boundary
            ):
                os.close(child_fd)
                raise TargetUnavailable(
                    "filesystem target path crosses a nested mount boundary"
                )
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        _close_quietly(current_fd)
        raise


def _open_regular_at(parent_fd: int, name: str) -> int:
    try:
        fd = os.open(name, _readonly_flags(), dir_fd=parent_fd)
    except FileNotFoundError:
        raise
    except OSError as error:
        if error.errno not in {
            errno.EISDIR,
            errno.ELOOP,
            errno.ENOTDIR,
            getattr(errno, "ENXIO", -1),
        }:
            raise
        raise ExistingObjectMismatch(
            "filesystem archive object is not a regular file"
        ) from None
    observed = os.fstat(fd)
    if not stat.S_ISREG(observed.st_mode):
        os.close(fd)
        raise ExistingObjectMismatch("filesystem archive object is not a regular file")
    return fd


def _require_named_inode(parent_fd: int, name: str, expected_fd: int) -> None:
    expected = os.fstat(expected_fd)
    current_fd = _open_regular_at(parent_fd, name)
    try:
        current = os.fstat(current_fd)
        if (expected.st_dev, expected.st_ino) != (current.st_dev, current.st_ino):
            raise ExistingObjectMismatch(
                "filesystem archive object identity changed during operation"
            )
    finally:
        os.close(current_fd)


def _key(value: str) -> _ObjectKey:
    if (
        type(value) is not str
        or not value
        or value.startswith("/")
        or "\x00" in value
        or "\\" in value
        or any(part in {"", ".", ".."} for part in value.split("/"))
        or PurePosixPath(value).as_posix() != value
        or any(part.startswith(_INTERNAL_PREFIX) for part in value.split("/"))
    ):
        raise UnsafeObjectKey("archive object key is not normalized and path safe")
    parts = tuple(value.split("/"))
    return _ObjectKey(value=value, parent_parts=parts[:-1], basename=parts[-1])


def _relative_parts(child: Path, parent: Path, *, field_name: str) -> tuple[str, ...]:
    if child == parent:
        return ()
    if parent not in child.parents:
        raise ValueError(f"{field_name} must be inside mount_root")
    return child.relative_to(parent).parts


def _decode_mountinfo_path(value: bytes) -> str:
    decoded = value
    for escaped, replacement in (
        (b"\\040", b" "),
        (b"\\011", b"\t"),
        (b"\\012", b"\n"),
        (b"\\134", b"\\"),
    ):
        decoded = decoded.replace(escaped, replacement)
    return os.fsdecode(decoded)


def _linux_mount_identity(path: Path, observed: os.stat_result) -> str:
    try:
        source = Path("/proc/self/mountinfo").read_bytes()
    except OSError as error:
        raise TargetUnavailable(
            "filesystem mount identity table is unavailable"
        ) from error
    device = f"{os.major(observed.st_dev)}:{os.minor(observed.st_dev)}"
    for line in source.splitlines():
        left, separator, _right = line.partition(b" - ")
        if not separator:
            continue
        fields = left.split()
        if len(fields) < 6:
            continue
        if _decode_mountinfo_path(fields[4]) != os.fspath(path):
            continue
        if os.fsdecode(fields[2]) != device:
            raise TargetUnavailable("filesystem mount identity is inconsistent")
        return f"linux:{os.fsdecode(fields[0])}:{device}"
    raise TargetUnavailable("filesystem mount_root is not an active mount point")


def _darwin_statfs(fd: int) -> tuple[tuple[int, int], Path]:
    if sys.platform != "darwin":
        raise TargetUnavailable("Darwin mount metadata is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        fstatfs = libc.fstatfs
    except AttributeError as error:
        raise TargetUnavailable("Darwin mount metadata is unavailable") from error
    fstatfs.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatfs)]
    fstatfs.restype = ctypes.c_int
    observed = _DarwinStatfs()
    if fstatfs(fd, ctypes.byref(observed)) != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))
    raw_mount_point = bytes(observed.f_mntonname).split(b"\x00", 1)[0]
    if not raw_mount_point:
        raise TargetUnavailable("Darwin mount metadata is invalid")
    return (
        (int(observed.f_fsid.values[0]), int(observed.f_fsid.values[1])),
        Path(os.fsdecode(raw_mount_point)),
    )


def _darwin_mount_identity(path: Path, fd: int) -> str:
    observed_fsid, mount_point = _darwin_statfs(fd)
    if mount_point != path:
        raise TargetUnavailable("filesystem mount_root is not an active mount point")
    return f"darwin-fsid:{observed_fsid[0]}:{observed_fsid[1]}"


def _mount_identity_token(path: Path, fd: int) -> str:
    observed = os.fstat(fd)
    if sys.platform.startswith("linux"):
        return _linux_mount_identity(path, observed)
    if sys.platform == "darwin":
        return _darwin_mount_identity(path, fd)
    parent_fd = _open_absolute_directory(path.parent)
    try:
        parent = os.fstat(parent_fd)
    finally:
        os.close(parent_fd)
    if observed.st_dev == parent.st_dev:
        raise TargetUnavailable("filesystem mount_root is not an active mount point")
    return f"device:{observed.st_dev}"


def _read_exact_guard(fd: int, expected: bytes) -> None:
    observed = os.fstat(fd)
    if not stat.S_ISREG(observed.st_mode) or observed.st_size > _MAX_GUARD_BYTES:
        raise TargetUnavailable("filesystem mount guard is invalid")
    data = bytearray()
    offset = 0
    limit = min(_MAX_GUARD_BYTES + 1, len(expected) + 1)
    while len(data) < limit:
        try:
            chunk = os.pread(fd, limit - len(data), offset)
        except InterruptedError:
            continue
        if not chunk:
            break
        data.extend(chunk)
        offset += len(chunk)
    if not hmac.compare_digest(bytes(data), expected):
        raise TargetUnavailable("filesystem mount guard content does not match")


def _open_guard(
    mount_fd: int,
    parts: tuple[str, ...],
    *,
    expected_device: int,
    expected_boundary: str,
) -> int:
    parent_fd = _open_relative_directory(
        mount_fd,
        parts[:-1],
        create=False,
        expected_device=expected_device,
        expected_boundary=expected_boundary,
    )
    try:
        fd = _open_regular_at(parent_fd, parts[-1])
    except (FileNotFoundError, ExistingObjectMismatch, OSError):
        raise TargetUnavailable("filesystem mount guard is unavailable") from None
    finally:
        os.close(parent_fd)
    if (
        os.fstat(fd).st_dev != expected_device
        or _filesystem_boundary_identity(fd) != expected_boundary
    ):
        os.close(fd)
        raise TargetUnavailable("filesystem mount guard is outside mount_root")
    return fd


def _directory_is_ancestor(ancestor_fd: int, descendant_fd: int) -> bool:
    ancestor = os.fstat(ancestor_fd)
    expected = (ancestor.st_dev, ancestor.st_ino)
    current_fd = os.dup(descendant_fd)
    visited: set[tuple[int, int]] = set()
    try:
        while True:
            current = os.fstat(current_fd)
            identity = (current.st_dev, current.st_ino)
            if identity == expected:
                return True
            if identity in visited:
                raise TargetUnavailable(
                    "filesystem directory ancestry contains an identity cycle"
                )
            visited.add(identity)
            parent_fd = os.open("..", _directory_flags(), dir_fd=current_fd)
            parent = os.fstat(parent_fd)
            parent_identity = (parent.st_dev, parent.st_ino)
            os.close(current_fd)
            current_fd = parent_fd
            if parent_identity == identity:
                return False
    finally:
        _close_quietly(current_fd)


def _directory_fds_overlap(first_fd: int, second_fd: int) -> bool:
    return _directory_is_ancestor(first_fd, second_fd) or _directory_is_ancestor(
        second_fd,
        first_fd,
    )


def _canonical_existing_path(path: Path, *, field_name: str) -> Path:
    try:
        return path.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise TargetUnavailable(f"filesystem {field_name} is unavailable") from error


def _backing_storage_identity(fd: int) -> tuple[str, int, int]:
    if sys.platform == "darwin":
        fsid, _mount_point = _darwin_statfs(fd)
        return ("darwin-fsid", fsid[0], fsid[1])
    observed = os.fstat(fd)
    return ("device", observed.st_dev, 0)


def _require_independent_backing_storage(data_root_fd: int, mount_root_fd: int) -> None:
    if _backing_storage_identity(data_root_fd) == _backing_storage_identity(
        mount_root_fd
    ):
        raise TargetUnavailable(
            "filesystem data_root and archive target must use independent storage"
        )


def _require_data_root_disjoint(
    *,
    data_root_path: Path,
    data_root_fd: int,
    mount_root_path: Path,
    mount_root_fd: int,
    root_path: Path,
    root_fd: int,
    guard_path: Path,
) -> None:
    _require_independent_backing_storage(data_root_fd, mount_root_fd)
    canonical_data_root = _canonical_existing_path(
        data_root_path,
        field_name="data_root",
    )
    canonical_paths = (
        _canonical_existing_path(mount_root_path, field_name="mount_root"),
        _canonical_existing_path(root_path, field_name="target root"),
        _canonical_existing_path(guard_path, field_name="mount guard"),
    )
    if (
        any(
            _paths_overlap(canonical_data_root, candidate)
            for candidate in canonical_paths
        )
        or _directory_fds_overlap(data_root_fd, mount_root_fd)
        or _directory_fds_overlap(
            data_root_fd,
            root_fd,
        )
    ):
        raise TargetUnavailable(
            "filesystem data_root aliases or overlaps the archive target"
        )


def _write_all(fd: int, source: bytes | memoryview) -> None:
    view = memoryview(source)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError(errno.EIO, "filesystem archive write made no progress")
        view = view[written:]


def _copy_exact(
    source_fd: int, destination_fd: int, source: ArchiveObjectSource
) -> None:
    initial = os.fstat(source_fd)
    digest = hashlib.sha256()
    offset = 0
    while offset < source.size_bytes:
        try:
            chunk = os.pread(
                source_fd,
                min(_IO_CHUNK_BYTES, source.size_bytes - offset),
                offset,
            )
        except InterruptedError:
            continue
        if not chunk:
            raise ExistingObjectMismatch(
                "archive upload source was truncated during copy"
            )
        digest.update(chunk)
        _write_all(destination_fd, chunk)
        offset += len(chunk)
    final = os.fstat(source_fd)
    if (
        (initial.st_dev, initial.st_ino) != (final.st_dev, final.st_ino)
        or final.st_size != source.size_bytes
        or offset != source.size_bytes
        or not hmac.compare_digest(digest.hexdigest(), source.sha256)
    ):
        raise ExistingObjectMismatch(
            "archive upload source does not match its frozen identity"
        )


def _renameat2_noreplace(parent_fd: int, source: str, destination: str) -> None:
    if not sys.platform.startswith("linux"):
        raise _NoReplaceUnsupported(errno.ENOTSUP, "renameat2 is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError as error:
        raise _NoReplaceUnsupported(
            errno.ENOTSUP,
            "renameat2 is unavailable",
        ) from error
    renameat2.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {
        errno.ENOSYS,
        errno.EINVAL,
        errno.EOPNOTSUPP,
        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
    }:
        raise _NoReplaceUnsupported(error_number, "renameat2 is unsupported")
    raise OSError(error_number, os.strerror(error_number))


def _darwin_rename_exclusive(parent_fd: int, source: str, destination: str) -> None:
    if sys.platform != "darwin":
        raise _NoReplaceUnsupported(errno.ENOTSUP, "renameatx_np is unavailable")
    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameatx_np = libc.renameatx_np
    except AttributeError as error:
        raise _NoReplaceUnsupported(
            errno.ENOTSUP,
            "renameatx_np is unavailable",
        ) from error
    renameatx_np.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx_np.restype = ctypes.c_int
    result = renameatx_np(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        _DARWIN_RENAME_EXCL,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {
        errno.ENOSYS,
        errno.EINVAL,
        errno.EOPNOTSUPP,
        getattr(errno, "ENOTSUP", errno.EOPNOTSUPP),
    }:
        raise _NoReplaceUnsupported(error_number, "renameatx_np is unsupported")
    raise OSError(error_number, os.strerror(error_number))


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    if sys.platform.startswith("linux"):
        _renameat2_noreplace(parent_fd, source, destination)
        return
    if sys.platform == "darwin":
        _darwin_rename_exclusive(parent_fd, source, destination)
        return
    raise _NoReplaceUnsupported(errno.ENOTSUP, "exclusive rename is unavailable")


def _publish_name_no_replace(
    parent_fd: int,
    source: str,
    destination: str,
    capability: FilesystemNoReplaceCapability,
) -> bool:
    try:
        if capability is FilesystemNoReplaceCapability.RENAME_NOREPLACE:
            _rename_noreplace(parent_fd, source, destination)
        else:
            os.link(
                source,
                destination,
                src_dir_fd=parent_fd,
                dst_dir_fd=parent_fd,
                follow_symlinks=False,
            )
    except FileExistsError:
        return False
    return True


def _remove_probe_name(root_fd: int, name: str) -> None:
    try:
        observed = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(observed.st_mode):
        raise OSError(errno.EINVAL, "no-replace probe path is not a regular file")
    os.unlink(name, dir_fd=root_fd)


def _probe_capability(
    root_fd: int,
    capability: FilesystemNoReplaceCapability,
) -> None:
    partial = f"{_INTERNAL_PREFIX}no-replace-probe.partial"
    collision = f"{_INTERNAL_PREFIX}no-replace-probe.collision"
    final = f"{_INTERNAL_PREFIX}no-replace-probe.final"
    for name in (partial, collision, final):
        _remove_probe_name(root_fd, name)
    os.fsync(root_fd)
    partial_fd = -1
    collision_fd = -1
    final_fd = -1
    try:
        partial_fd = os.open(partial, _write_flags(), 0o600, dir_fd=root_fd)
        _write_all(partial_fd, b"archive-no-replace-probe-a")
        os.fsync(partial_fd)
        collision_fd = os.open(collision, _write_flags(), 0o600, dir_fd=root_fd)
        _write_all(collision_fd, b"archive-no-replace-probe-b")
        os.fsync(collision_fd)
        if not _publish_name_no_replace(root_fd, partial, final, capability):
            raise OSError(errno.EEXIST, "probe destination unexpectedly exists")
        if _publish_name_no_replace(root_fd, collision, final, capability):
            raise OSError(errno.ENOTSUP, "no-replace probe overwrote its destination")
        final_fd = _open_regular_at(root_fd, final)
        size, sha256 = size_and_sha256_fd(final_fd)
        if size != len(b"archive-no-replace-probe-a") or not hmac.compare_digest(
            sha256,
            hashlib.sha256(b"archive-no-replace-probe-a").hexdigest(),
        ):
            raise OSError(errno.ENOTSUP, "no-replace probe changed final bytes")
        os.fsync(final_fd)
        os.fsync(root_fd)
    finally:
        for fd in (final_fd, collision_fd, partial_fd):
            if fd >= 0:
                _close_quietly(fd)
        for name in (partial, collision, final):
            _remove_probe_name(root_fd, name)
        os.fsync(root_fd)


def _probe_no_replace_capability(
    root_fd: int,
    phase_hook: PhaseHook | None = None,
) -> FilesystemNoReplaceCapability:
    del phase_hook
    failures: list[OSError] = []
    for capability in (
        FilesystemNoReplaceCapability.RENAME_NOREPLACE,
        FilesystemNoReplaceCapability.HARDLINK,
    ):
        try:
            _probe_capability(root_fd, capability)
        except (OSError, ExistingObjectMismatch) as error:
            if isinstance(error, OSError):
                failures.append(error)
            continue
        return capability
    if failures:
        raise OSError(errno.ENOTSUP, "no safe no-replace primitive is available")
    raise OSError(errno.ENOTSUP, "no safe no-replace primitive is available")


def _acquire_root_owner(root_fd: int) -> tuple[int, int]:
    global _OWNER_REGISTRY_PID

    observed = os.fstat(root_fd)
    identity = (observed.st_dev, observed.st_ino)
    with _OWNER_REGISTRY_LOCK:
        current_pid = os.getpid()
        if _OWNER_REGISTRY_PID != current_pid:
            _OWNED_TARGET_ROOTS.clear()
            _OWNER_REGISTRY_PID = current_pid
        if identity in _OWNED_TARGET_ROOTS:
            raise TargetUnavailable(
                "filesystem target root writer lock is already held"
            )
        try:
            fcntl.flock(root_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise TargetUnavailable(
                    "filesystem target root writer lock is already held"
                ) from None
            raise
        _OWNED_TARGET_ROOTS.add(identity)
    return identity


def _release_root_owner(root_fd: int, identity: tuple[int, int]) -> None:
    global _OWNER_REGISTRY_PID

    try:
        fcntl.flock(root_fd, fcntl.LOCK_UN)
    finally:
        with _OWNER_REGISTRY_LOCK:
            current_pid = os.getpid()
            if _OWNER_REGISTRY_PID != current_pid:
                _OWNED_TARGET_ROOTS.clear()
                _OWNER_REGISTRY_PID = current_pid
            else:
                _OWNED_TARGET_ROOTS.discard(identity)


def _partial_name(key: str, sha256: str) -> str:
    key_hash = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return f"{_INTERNAL_PREFIX}object.partial.{key_hash}.{sha256}"


def _validate_source(source: ArchiveObjectSource) -> ArchiveObjectSource:
    if type(source) is not ArchiveObjectSource:
        raise TypeError("source must be ArchiveObjectSource")
    return ArchiveObjectSource(
        path=source.path,
        size_bytes=source.size_bytes,
        sha256=source.sha256,
    )


class FilesystemTarget:
    def __init__(
        self,
        target: FrozenArchiveTargetV1,
        *,
        expected_guard: SecretValue,
        data_root: Path,
        phase_hook: PhaseHook | None = None,
    ) -> None:
        if type(target) is not FrozenArchiveTargetV1:
            raise TypeError("target must be FrozenArchiveTargetV1")
        if type(expected_guard) is not SecretValue:
            raise TypeError("expected_guard must be SecretValue")
        if phase_hook is not None and not callable(phase_hook):
            raise TypeError("phase_hook must be callable or None")
        try:
            frozen = FrozenArchiveTargetV1.model_validate(
                target.model_dump(mode="python")
            )
        except ValidationError as error:
            raise ValueError("frozen filesystem target is invalid") from error
        if frozen.target_type != "filesystem":
            raise ValueError("frozen target must be a filesystem target")
        if tuple(item.name for item in frozen.credential_references) != (
            "mount_guard_expected",
        ):
            raise ValueError(
                "filesystem target must freeze one mount guard credential reference"
            )
        assert frozen.filesystem_root is not None
        assert frozen.filesystem_mount_root is not None
        assert frozen.mount_guard_path is not None
        root = _normalized_absolute(
            Path(frozen.filesystem_root),
            field_name="filesystem root",
        )
        mount_root = _normalized_absolute(
            Path(frozen.filesystem_mount_root),
            field_name="filesystem mount_root",
        )
        guard_path = _normalized_absolute(
            Path(frozen.mount_guard_path),
            field_name="filesystem mount guard",
        )
        normalized_data_root = _normalized_absolute(data_root, field_name="data_root")
        root_parts = _relative_parts(root, mount_root, field_name="filesystem root")
        guard_parts = _relative_parts(
            guard_path,
            mount_root,
            field_name="filesystem mount guard",
        )
        if not root_parts:
            raise ValueError(
                "filesystem root must be a strict descendant of mount_root"
            )
        if not guard_parts or _paths_overlap(guard_path, root):
            raise ValueError("filesystem mount guard must not overlap the archive root")
        if any(
            _paths_overlap(normalized_data_root, path)
            for path in (mount_root, root, guard_path)
        ):
            raise ValueError("filesystem target paths must not overlap data_root")
        expected = expected_guard.reveal().encode("utf-8")
        if not expected or len(expected) > _MAX_GUARD_BYTES:
            raise ValueError("filesystem mount guard secret must be 1..64KiB")

        self.id = frozen.target_id
        self._target = frozen
        self._root = root
        self._mount_root = mount_root
        self._guard_path = guard_path
        self._data_root = normalized_data_root
        self._root_parts = root_parts
        self._guard_parts = guard_parts
        self._expected_guard = expected
        self._phase_hook = phase_hook
        self._operation_lock = threading.RLock()
        self._mount_fd: int | None = None
        self._guard_fd: int | None = None
        self._root_fd: int | None = None
        self._data_root_fd: int | None = None
        self._mount_identity: tuple[int, int, str] | None = None
        self._mount_boundary: str | None = None
        self._guard_identity: tuple[int, int] | None = None
        self._root_identity: tuple[int, int] | None = None
        self._data_root_identity: tuple[int, int] | None = None
        self._owner_pid: int | None = None
        self._capability: FilesystemNoReplaceCapability | None = None
        self._closed = False

    def __repr__(self) -> str:
        state = "closed" if self._closed else "open"
        return f"FilesystemTarget(id={self.id!r}, state={state!r})"

    def _notify(self, phase: str) -> None:
        hook = self._phase_hook
        if hook is not None:
            hook(phase)

    def _require_not_closed(self) -> None:
        if self._closed:
            raise TargetClosed("filesystem target is closed")

    def _release_probe_state(self) -> None:
        root_fd = self._root_fd
        root_identity = self._root_identity
        owner_pid = self._owner_pid
        self._root_fd = None
        self._root_identity = None
        self._owner_pid = None
        self._capability = None
        if (
            root_fd is not None
            and root_identity is not None
            and owner_pid == os.getpid()
        ):
            with suppress(OSError):
                _release_root_owner(root_fd, root_identity)
        for name in ("_data_root_fd", "_guard_fd", "_mount_fd"):
            fd = getattr(self, name)
            setattr(self, name, None)
            if fd is not None:
                _close_quietly(fd)
        if root_fd is not None:
            _close_quietly(root_fd)
        self._mount_identity = None
        self._mount_boundary = None
        self._guard_identity = None
        self._data_root_identity = None

    def _open_current_guard(self) -> int:
        mount_fd = self._mount_fd
        mount_identity = self._mount_identity
        mount_boundary = self._mount_boundary
        if mount_fd is None or mount_identity is None or mount_boundary is None:
            raise TargetUnavailable("filesystem target has not completed probe")
        return _open_guard(
            mount_fd,
            self._guard_parts,
            expected_device=mount_identity[0],
            expected_boundary=mount_boundary,
        )

    def _require_available(self) -> None:
        self._require_not_closed()
        mount_fd = self._mount_fd
        root_fd = self._root_fd
        data_root_fd = self._data_root_fd
        pinned_mount = self._mount_identity
        pinned_boundary = self._mount_boundary
        pinned_guard = self._guard_identity
        pinned_root = self._root_identity
        pinned_data_root = self._data_root_identity
        if (
            mount_fd is None
            or root_fd is None
            or data_root_fd is None
            or pinned_mount is None
            or pinned_boundary is None
            or pinned_guard is None
            or pinned_root is None
            or pinned_data_root is None
            or self._capability is None
        ):
            raise TargetUnavailable("filesystem target has not completed probe")
        if self._owner_pid != os.getpid():
            raise TargetUnavailable("filesystem target belongs to a different process")
        current_mount_fd = -1
        current_guard_fd = -1
        current_root_fd = -1
        current_data_root_fd = -1
        try:
            current_mount_fd = _open_absolute_directory(self._mount_root)
            current_mount_stat = os.fstat(current_mount_fd)
            current_boundary = _filesystem_boundary_identity(current_mount_fd)
            current_token = _mount_identity_token(
                self._mount_root,
                current_mount_fd,
            )
            current_mount = (
                current_mount_stat.st_dev,
                current_mount_stat.st_ino,
                current_token,
            )
            if (
                current_mount != pinned_mount
                or current_boundary != pinned_boundary
                or (
                    os.fstat(mount_fd).st_dev,
                    os.fstat(mount_fd).st_ino,
                )
                != pinned_mount[:2]
            ):
                raise TargetUnavailable("filesystem mount identity changed")
            current_guard_fd = self._open_current_guard()
            current_guard_stat = os.fstat(current_guard_fd)
            if (
                current_guard_stat.st_dev,
                current_guard_stat.st_ino,
            ) != pinned_guard:
                raise TargetUnavailable("filesystem mount guard identity changed")
            _read_exact_guard(current_guard_fd, self._expected_guard)
            current_root_fd = _open_relative_directory(
                mount_fd,
                self._root_parts,
                create=False,
                expected_device=pinned_mount[0],
                expected_boundary=pinned_boundary,
            )
            current_root_stat = os.fstat(current_root_fd)
            if (
                current_root_stat.st_dev,
                current_root_stat.st_ino,
            ) != pinned_root or (
                os.fstat(root_fd).st_dev,
                os.fstat(root_fd).st_ino,
            ) != pinned_root:
                raise TargetUnavailable("filesystem target root identity changed")
            try:
                current_data_root_fd = _open_absolute_directory(self._data_root)
            except OSError:
                raise TargetUnavailable(
                    "filesystem data_root is unavailable or unsafe"
                ) from None
            current_data_root = os.fstat(current_data_root_fd)
            if (
                current_data_root.st_dev,
                current_data_root.st_ino,
            ) != pinned_data_root or (
                os.fstat(data_root_fd).st_dev,
                os.fstat(data_root_fd).st_ino,
            ) != pinned_data_root:
                raise TargetUnavailable("filesystem data_root identity changed")
            _require_data_root_disjoint(
                data_root_path=self._data_root,
                data_root_fd=current_data_root_fd,
                mount_root_path=self._mount_root,
                mount_root_fd=current_mount_fd,
                root_path=self._root,
                root_fd=current_root_fd,
                guard_path=self._guard_path,
            )
        except TargetUnavailable:
            raise
        except OSError as error:
            raise TargetUnavailable(
                "filesystem target identity check failed"
            ) from error
        finally:
            for fd in (
                current_data_root_fd,
                current_root_fd,
                current_guard_fd,
                current_mount_fd,
            ):
                if fd >= 0:
                    _close_quietly(fd)

    def probe(self) -> TargetProbe:
        with self._operation_lock:
            self._require_not_closed()
            if self._mount_fd is not None:
                self._require_available()
                assert self._mount_identity is not None
                assert self._capability is not None
                return TargetProbe(
                    target_id=self.id,
                    target_type="filesystem",
                    no_replace_capability=self._capability.value,
                    mount_identity=self._mount_identity[2],
                )
            mount_fd = -1
            guard_fd = -1
            root_fd = -1
            data_root_fd = -1
            root_identity: tuple[int, int] | None = None
            try:
                mount_fd = _open_absolute_directory(self._mount_root)
                mount_stat = os.fstat(mount_fd)
                mount_boundary = _filesystem_boundary_identity(mount_fd)
                mount_token = _mount_identity_token(self._mount_root, mount_fd)
                guard_fd = _open_guard(
                    mount_fd,
                    self._guard_parts,
                    expected_device=mount_stat.st_dev,
                    expected_boundary=mount_boundary,
                )
                _read_exact_guard(guard_fd, self._expected_guard)
                guard_stat = os.fstat(guard_fd)
                try:
                    data_root_fd = _open_absolute_directory(self._data_root)
                except OSError:
                    raise TargetUnavailable(
                        "filesystem data_root is unavailable or unsafe"
                    ) from None
                data_root_stat = os.fstat(data_root_fd)
                root_fd = _open_relative_directory(
                    mount_fd,
                    self._root_parts,
                    create=True,
                    expected_device=mount_stat.st_dev,
                    expected_boundary=mount_boundary,
                )
                _require_data_root_disjoint(
                    data_root_path=self._data_root,
                    data_root_fd=data_root_fd,
                    mount_root_path=self._mount_root,
                    mount_root_fd=mount_fd,
                    root_path=self._root,
                    root_fd=root_fd,
                    guard_path=self._guard_path,
                )
                root_identity = _acquire_root_owner(root_fd)
                try:
                    capability = _probe_no_replace_capability(
                        root_fd,
                        self._phase_hook,
                    )
                except BaseException:
                    _release_root_owner(root_fd, root_identity)
                    root_identity = None
                    raise
                self._mount_fd = mount_fd
                self._guard_fd = guard_fd
                self._root_fd = root_fd
                self._data_root_fd = data_root_fd
                self._mount_identity = (
                    mount_stat.st_dev,
                    mount_stat.st_ino,
                    mount_token,
                )
                self._mount_boundary = mount_boundary
                self._guard_identity = (guard_stat.st_dev, guard_stat.st_ino)
                self._root_identity = root_identity
                self._data_root_identity = (
                    data_root_stat.st_dev,
                    data_root_stat.st_ino,
                )
                self._owner_pid = os.getpid()
                self._capability = capability
                mount_fd = guard_fd = root_fd = data_root_fd = -1
                self._require_available()
                return TargetProbe(
                    target_id=self.id,
                    target_type="filesystem",
                    no_replace_capability=capability.value,
                    mount_identity=mount_token,
                )
            except TargetUnavailable:
                self._release_probe_state()
                raise
            except OSError as error:
                self._release_probe_state()
                if error.errno == errno.ENOTSUP:
                    raise TargetUnavailable(
                        "filesystem target has no safe no-replace primitive"
                    ) from None
                raise TargetUnavailable("filesystem target probe failed") from error
            finally:
                for fd in (data_root_fd, root_fd, guard_fd, mount_fd):
                    if fd >= 0:
                        _close_quietly(fd)

    def _open_object_parent(self, key: _ObjectKey, *, create: bool) -> int:
        root_fd = self._root_fd
        mount = self._mount_identity
        boundary = self._mount_boundary
        if root_fd is None or mount is None or boundary is None:
            raise TargetUnavailable("filesystem target has not completed probe")
        try:
            return _open_relative_directory(
                root_fd,
                key.parent_parts,
                create=create,
                expected_device=mount[0],
                expected_boundary=boundary,
            )
        except FileNotFoundError:
            raise
        except TargetUnavailable:
            raise
        except OSError as error:
            if error.errno not in {errno.ELOOP, errno.ENOTDIR}:
                raise
            raise ExistingObjectMismatch(
                "filesystem archive object parent is unsafe"
            ) from None

    def _require_current_object_binding(
        self,
        key: _ObjectKey,
        parent_fd: int,
        object_fd: int,
    ) -> None:
        current_parent_fd = -1
        current_object_fd = -1
        try:
            current_parent_fd = self._open_object_parent(key, create=False)
            expected_parent = os.fstat(parent_fd)
            current_parent = os.fstat(current_parent_fd)
            if (expected_parent.st_dev, expected_parent.st_ino) != (
                current_parent.st_dev,
                current_parent.st_ino,
            ):
                raise ExistingObjectMismatch(
                    "filesystem archive object parent identity changed"
                )
            current_object_fd = _open_regular_at(current_parent_fd, key.basename)
            expected_object = os.fstat(object_fd)
            current_object = os.fstat(current_object_fd)
            if (expected_object.st_dev, expected_object.st_ino) != (
                current_object.st_dev,
                current_object.st_ino,
            ):
                raise ExistingObjectMismatch(
                    "filesystem archive object identity changed"
                )
        except FileNotFoundError:
            raise ExistingObjectMismatch(
                "filesystem archive object is unavailable at its configured path"
            ) from None
        finally:
            for fd in (current_object_fd, current_parent_fd):
                if fd >= 0:
                    _close_quietly(fd)

    @staticmethod
    def _identity(fd: int) -> tuple[int, str]:
        return size_and_sha256_fd(fd)

    def _existing_identity(
        self,
        parent_fd: int,
        name: str,
    ) -> tuple[int, str, int] | None:
        try:
            fd = _open_regular_at(parent_fd, name)
        except FileNotFoundError:
            return None
        try:
            size_bytes, sha256 = self._identity(fd)
            _require_named_inode(parent_fd, name, fd)
            return size_bytes, sha256, fd
        except BaseException:
            os.close(fd)
            raise

    @staticmethod
    def _unlink_open_name(parent_fd: int, name: str, expected_fd: int) -> None:
        _require_named_inode(parent_fd, name, expected_fd)
        os.unlink(name, dir_fd=parent_fd)
        os.fsync(parent_fd)

    def _clean_partial_if_present(self, parent_fd: int, partial_name: str) -> bool:
        existing = self._existing_identity(parent_fd, partial_name)
        if existing is None:
            return False
        _size, _sha, fd = existing
        try:
            self._unlink_open_name(parent_fd, partial_name, fd)
        finally:
            os.close(fd)
        return True

    def _stable_existing_result(
        self,
        key: _ObjectKey,
        source: ArchiveObjectSource,
        parent_fd: int,
        existing_fd: int,
        *,
        created: bool,
        resumed: bool,
    ) -> PutResult:
        os.fsync(existing_fd)
        os.fsync(parent_fd)
        self._notify("after_destination_directory_fsync")
        size_bytes, sha256 = self._identity(existing_fd)
        _require_named_inode(parent_fd, key.basename, existing_fd)
        if size_bytes != source.size_bytes or not hmac.compare_digest(
            sha256,
            source.sha256,
        ):
            raise ExistingObjectMismatch(
                "filesystem archive destination contains different bytes"
            )
        self._notify("after_readback")
        self._require_available()
        self._require_current_object_binding(key, parent_fd, existing_fd)
        return PutResult(
            key=key.value,
            size_bytes=size_bytes,
            sha256=sha256,
            created=created,
            resumed=resumed,
            provider_version_id=None,
            path=self._root.joinpath(*key.parent_parts, key.basename),
        )

    def put(
        self,
        source: ArchiveObjectSource,
        key: str,
        resume: ResumeState | None = None,
        *,
        no_replace: bool = True,
    ) -> PutResult:
        if type(no_replace) is not bool or not no_replace:
            raise ValueError("filesystem archive put requires no_replace=True")
        if resume is not None:
            raise ValueError("filesystem target does not accept multipart resume state")
        upload = _validate_source(source)
        object_key = _key(key)
        with self._operation_lock:
            self._require_available()
            source_fd = -1
            parent_fd = -1
            partial_fd = -1
            verification_fd = -1
            destination_fd = -1
            try:
                try:
                    source_fd = open_readonly_nofollow(upload.path)
                except OSError as error:
                    if error.errno not in {
                        errno.ENOENT,
                        errno.EISDIR,
                        errno.ELOOP,
                        errno.ENOTDIR,
                    }:
                        raise
                    raise ExistingObjectMismatch(
                        "archive upload source is not a no-follow regular file"
                    ) from None
                source_identity = self._identity(source_fd)
                if source_identity != (upload.size_bytes, upload.sha256):
                    raise ExistingObjectMismatch(
                        "archive upload source does not match its frozen identity"
                    )
                try:
                    parent_fd = self._open_object_parent(object_key, create=False)
                except FileNotFoundError:
                    parent_fd = self._open_object_parent(object_key, create=True)
                existing = self._existing_identity(parent_fd, object_key.basename)
                partial_name = _partial_name(object_key.value, upload.sha256)
                if existing is not None:
                    size_bytes, sha256, destination_fd = existing
                    if size_bytes != upload.size_bytes or not hmac.compare_digest(
                        sha256,
                        upload.sha256,
                    ):
                        raise ExistingObjectMismatch(
                            "filesystem archive destination contains different bytes"
                        )
                    resumed = self._clean_partial_if_present(parent_fd, partial_name)
                    return self._stable_existing_result(
                        object_key,
                        upload,
                        parent_fd,
                        destination_fd,
                        created=False,
                        resumed=resumed,
                    )

                partial = self._existing_identity(parent_fd, partial_name)
                resumed = False
                if partial is not None:
                    partial_size, partial_sha, partial_fd = partial
                    if partial_size == upload.size_bytes and hmac.compare_digest(
                        partial_sha,
                        upload.sha256,
                    ):
                        resumed = True
                        verification_fd = os.dup(partial_fd)
                    else:
                        self._unlink_open_name(parent_fd, partial_name, partial_fd)
                        os.close(partial_fd)
                        partial_fd = -1
                if verification_fd < 0:
                    partial_fd = os.open(
                        partial_name,
                        _write_flags(),
                        0o640,
                        dir_fd=parent_fd,
                    )
                    os.fchmod(partial_fd, 0o640)
                    os.fsync(parent_fd)
                    self._notify("after_partial_directory_fsync")
                    _copy_exact(source_fd, partial_fd, upload)
                    os.fsync(partial_fd)
                    self._notify("after_partial_file_fsync")
                    verification_fd = _open_regular_at(parent_fd, partial_name)
                    if (
                        os.fstat(partial_fd).st_dev,
                        os.fstat(partial_fd).st_ino,
                    ) != (
                        os.fstat(verification_fd).st_dev,
                        os.fstat(verification_fd).st_ino,
                    ):
                        raise ExistingObjectMismatch(
                            "filesystem archive partial identity changed"
                        )
                    if self._identity(verification_fd) != (
                        upload.size_bytes,
                        upload.sha256,
                    ):
                        raise ExistingObjectMismatch(
                            "filesystem archive partial failed stored identity check"
                        )
                capability = self._capability
                assert capability is not None
                created = _publish_name_no_replace(
                    parent_fd,
                    partial_name,
                    object_key.basename,
                    capability,
                )
                if created:
                    self._notify("after_namespace_publish")
                destination_fd = _open_regular_at(parent_fd, object_key.basename)
                if (
                    created
                    and capability is FilesystemNoReplaceCapability.HARDLINK
                    and (
                        os.fstat(destination_fd).st_dev,
                        os.fstat(destination_fd).st_ino,
                    )
                    != (
                        os.fstat(verification_fd).st_dev,
                        os.fstat(verification_fd).st_ino,
                    )
                ):
                    raise ExistingObjectMismatch(
                        "filesystem no-replace publication changed object identity"
                    )
                destination_identity = self._identity(destination_fd)
                if destination_identity != (upload.size_bytes, upload.sha256):
                    raise ExistingObjectMismatch(
                        "filesystem archive destination contains different bytes"
                    )
                os.fsync(destination_fd)
                os.fsync(parent_fd)
                self._notify("after_destination_directory_fsync")
                self._clean_partial_if_present(parent_fd, partial_name)
                self._notify("after_partial_unlink")
                os.fsync(parent_fd)
                self._notify("after_final_directory_fsync")
                return self._stable_existing_result(
                    object_key,
                    upload,
                    parent_fd,
                    destination_fd,
                    created=created,
                    resumed=resumed,
                )
            except (TargetUnavailable, ExistingObjectMismatch, UnsafeObjectKey):
                raise
            except OSError as error:
                raise TargetUnavailable("filesystem target put failed") from error
            finally:
                for fd in (
                    destination_fd,
                    verification_fd,
                    partial_fd,
                    parent_fd,
                    source_fd,
                ):
                    if fd >= 0:
                        _close_quietly(fd)

    @staticmethod
    def _expected_identity(expected_size: int, expected_sha256: str) -> None:
        if type(expected_size) is not int or expected_size <= 0:
            raise ValueError("expected object size must be positive")
        if (
            type(expected_sha256) is not str
            or _SHA256.fullmatch(expected_sha256) is None
        ):
            raise ValueError("expected object SHA-256 is invalid")

    def verify(
        self,
        key: str,
        expected_size: int,
        expected_sha256: str,
        *,
        provider_version_id: str | None = None,
    ) -> VerifyResult:
        if provider_version_id is not None:
            raise ValueError("filesystem target does not use provider version IDs")
        object_key = _key(key)
        self._expected_identity(expected_size, expected_sha256)
        with self._operation_lock:
            self._require_available()
            parent_fd = -1
            fd = -1
            try:
                parent_fd = self._open_object_parent(object_key, create=False)
                fd = _open_regular_at(parent_fd, object_key.basename)
                size_bytes, sha256 = self._identity(fd)
                _require_named_inode(parent_fd, object_key.basename, fd)
                self._require_available()
                self._require_current_object_binding(object_key, parent_fd, fd)
                if size_bytes != expected_size or not hmac.compare_digest(
                    sha256,
                    expected_sha256,
                ):
                    raise StoredObjectMismatch(
                        "filesystem archive readback does not match expected identity"
                    )
                return VerifyResult(
                    key=object_key.value,
                    size_bytes=size_bytes,
                    sha256=sha256,
                    method="readback_sha256",
                    level=ArchiveVerificationLevel.STORED_SHA256,
                    provider_checksum=None,
                    provider_version_id=None,
                    verified=True,
                    cleanup_strong=True,
                )
            except (TargetUnavailable, StoredObjectMismatch, ExistingObjectMismatch):
                raise
            except FileNotFoundError as error:
                raise StoredObjectMismatch(
                    "filesystem archive object is unavailable for readback"
                ) from error
            except OSError as error:
                raise TargetUnavailable("filesystem target readback failed") from error
            finally:
                for descriptor in (fd, parent_fd):
                    if descriptor >= 0:
                        _close_quietly(descriptor)

    def open_reader(
        self,
        key: str,
        *,
        provider_version_id: str | None = None,
    ) -> IO[bytes]:
        if provider_version_id is not None:
            raise ValueError("filesystem target does not use provider version IDs")
        object_key = _key(key)
        with self._operation_lock:
            self._require_available()
            parent_fd = -1
            fd = -1
            try:
                parent_fd = self._open_object_parent(object_key, create=False)
                fd = _open_regular_at(parent_fd, object_key.basename)
                _require_named_inode(parent_fd, object_key.basename, fd)
                self._require_available()
                self._require_current_object_binding(object_key, parent_fd, fd)
                reader = os.fdopen(fd, "rb", closefd=True)
                fd = -1
                return reader
            except (TargetUnavailable, ExistingObjectMismatch):
                raise
            except FileNotFoundError as error:
                raise ExistingObjectMismatch(
                    "filesystem archive object is unavailable for reading"
                ) from error
            except OSError as error:
                raise TargetUnavailable(
                    "filesystem target reader open failed"
                ) from error
            finally:
                for descriptor in (fd, parent_fd):
                    if descriptor >= 0:
                        _close_quietly(descriptor)

    def close(self) -> None:
        with self._operation_lock:
            if self._closed:
                return
            self._closed = True
            self._release_probe_state()

    def __enter__(self) -> Self:
        self._require_not_closed()
        return self

    def __exit__(self, *_ignored: object) -> None:
        self.close()

    def __del__(self) -> None:
        if not hasattr(self, "_operation_lock"):
            return
        with suppress(OSError):
            self.close()


__all__ = ["FilesystemNoReplaceCapability", "FilesystemTarget"]
