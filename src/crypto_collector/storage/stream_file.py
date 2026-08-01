from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Self

import zstandard

_MAX_SIGNED_INT64 = 2**63 - 1


def _integer(value: object, *, field: str, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field} must be {qualifier}")
    if value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field} must fit a signed 64-bit integer")
    return value


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field} must be a non-empty normalized string")
    return value


@dataclass(frozen=True, slots=True)
class BufferedRow:
    data: bytes
    accepted_monotonic_ns: int

    def __post_init__(self) -> None:
        if type(self.data) is not bytes:
            raise TypeError("buffered row data must be bytes")
        if not self.data or not self.data.endswith(b"\n") or b"\n" in self.data[:-1]:
            raise ValueError("buffered row must be exactly one non-empty JSONL row")
        object.__setattr__(
            self,
            "accepted_monotonic_ns",
            _integer(
                self.accepted_monotonic_ns,
                field="accepted_monotonic_ns",
            ),
        )


@dataclass(frozen=True, slots=True)
class PendingRows:
    rows: tuple[BufferedRow, ...]
    plain_bytes: int

    def __post_init__(self) -> None:
        if type(self.rows) is not tuple or any(
            type(item) is not BufferedRow for item in self.rows
        ):
            raise TypeError("pending rows must be a tuple of BufferedRow")
        if not self.rows:
            raise ValueError("pending rows must not be empty")
        plain_bytes = _integer(self.plain_bytes, field="plain_bytes", minimum=1)
        if plain_bytes != sum(len(item.data) for item in self.rows):
            raise ValueError("plain_bytes must equal the encoded row byte count")
        monotonic_values = tuple(item.accepted_monotonic_ns for item in self.rows)
        if any(current < previous for previous, current in pairwise(monotonic_values)):
            raise ValueError("pending row monotonic times must be non-decreasing")
        object.__setattr__(self, "plain_bytes", plain_bytes)


@dataclass(frozen=True, slots=True)
class WrittenFrame:
    first_monotonic_ns: int
    last_monotonic_ns: int
    record_monotonic_ns: tuple[int, ...]
    record_count: int
    compressed_bytes: int

    def __post_init__(self) -> None:
        first = _integer(self.first_monotonic_ns, field="first_monotonic_ns")
        last = _integer(self.last_monotonic_ns, field="last_monotonic_ns")
        if type(self.record_monotonic_ns) is not tuple or any(
            type(item) is not int or item < 0 or item > _MAX_SIGNED_INT64
            for item in self.record_monotonic_ns
        ):
            raise TypeError("record_monotonic_ns must be a tuple of non-negative ints")
        count = _integer(self.record_count, field="record_count", minimum=1)
        if count != len(self.record_monotonic_ns):
            raise ValueError("record_count must match record_monotonic_ns")
        if first != self.record_monotonic_ns[0] or last != self.record_monotonic_ns[-1]:
            raise ValueError("frame monotonic bounds must match its records")
        object.__setattr__(
            self,
            "compressed_bytes",
            _integer(self.compressed_bytes, field="compressed_bytes", minimum=1),
        )


class FrameSealRequired(RuntimeError):
    def __init__(
        self,
        *,
        current_plain_bytes: int,
        incoming_plain_bytes: int,
        max_plain_frame_bytes: int,
    ) -> None:
        self.current_plain_bytes = current_plain_bytes
        self.incoming_plain_bytes = incoming_plain_bytes
        self.max_plain_frame_bytes = max_plain_frame_bytes
        super().__init__("row would exceed the active plain-frame byte limit")


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _close_quietly(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _open_durable_parent(path: Path) -> int:
    parent = path.parent
    anchor = parent.anchor
    if not anchor:
        raise ValueError("stream file path must resolve to an absolute path")
    current_fd = os.open(anchor, _directory_flags())
    current_owned = True
    try:
        relative_parts = parent.parts[1:]
        for part in relative_parts:
            if part in {"", ".", ".."}:
                raise ValueError("stream file parent path must be normalized")
            child_fd: int | None = None
            try:
                try:
                    child_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
                except FileNotFoundError:
                    try:
                        os.mkdir(part, mode=0o750, dir_fd=current_fd)
                    except FileExistsError:
                        pass
                    child_fd = os.open(
                        part,
                        _directory_flags(),
                        dir_fd=current_fd,
                    )
                # Sync existing entries too: a prior allocator may have observed mkdir
                # success but failed before proving the entry durable.
                os.fsync(current_fd)
                current_owned = False
                os.close(current_fd)
            except BaseException:
                if child_fd is not None:
                    _close_quietly(child_fd)
                raise
            assert child_fd is not None
            current_fd = child_fd
            current_owned = True
        return current_fd
    except BaseException:
        if current_owned:
            _close_quietly(current_fd)
        raise


def write_all(fd: int, data: bytes) -> None:
    normalized_fd = _integer(fd, field="fd")
    if type(data) is not bytes or not data:
        raise ValueError("write_all data must be non-empty bytes")
    view = memoryview(data)
    while view:
        try:
            written = os.write(normalized_fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("write returned no progress")
        view = view[written:]


class StreamFile:
    __slots__ = (
        "_buffer",
        "_buffer_plain_bytes",
        "_compressor",
        "_fd",
        "_generation_id",
        "compressed_size",
        "max_plain_frame_bytes",
        "path",
        "zstd_level",
    )

    def __init__(
        self,
        *,
        path: Path,
        generation_id: str,
        fd: int,
        zstd_level: int,
        max_plain_frame_bytes: int,
        compressor: zstandard.ZstdCompressor,
    ) -> None:
        self.path = path
        self._generation_id = generation_id
        self._fd = fd
        self.zstd_level = zstd_level
        self.max_plain_frame_bytes = max_plain_frame_bytes
        self._compressor = compressor
        self._buffer: list[BufferedRow] = []
        self._buffer_plain_bytes = 0
        self.compressed_size = 0

    @property
    def generation_id(self) -> str:
        return self._generation_id

    @classmethod
    def allocate(
        cls,
        path: str | Path,
        *,
        zstd_level: int,
        max_plain_frame_bytes: int,
        generation_id: str | None = None,
    ) -> StreamFile:
        level = _integer(zstd_level, field="zstd_level", minimum=1)
        if level > 22:
            raise ValueError("zstd_level must be at most 22")
        frame_limit = _integer(
            max_plain_frame_bytes,
            field="max_plain_frame_bytes",
            minimum=1,
        )
        absolute_path = Path(os.path.abspath(os.fspath(path)))
        if not absolute_path.name or absolute_path.name in {".", ".."}:
            raise ValueError("stream file path must include a filename")
        identifier = _nonempty(
            (
                hashlib.sha256(os.fsencode(absolute_path)).hexdigest()
                if generation_id is None
                else generation_id
            ),
            field="generation_id",
        )
        compressor = zstandard.ZstdCompressor(
            level=level,
            write_checksum=True,
            write_content_size=True,
        )
        parent_fd = _open_durable_parent(absolute_path)
        fd: int | None = None
        try:
            flags = (
                os.O_CREAT
                | os.O_EXCL
                | os.O_APPEND
                | os.O_WRONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            fd = os.open(absolute_path.name, flags, 0o640, dir_fd=parent_fd)
            os.fsync(parent_fd)
        except BaseException:
            if fd is not None:
                _close_quietly(fd)
                fd = None
            _close_quietly(parent_fd)
            raise
        try:
            os.close(parent_fd)
        except BaseException:
            assert fd is not None
            _close_quietly(fd)
            fd = None
            raise
        assert fd is not None
        return cls(
            path=absolute_path,
            generation_id=identifier,
            fd=fd,
            zstd_level=level,
            max_plain_frame_bytes=frame_limit,
            compressor=compressor,
        )

    @property
    def closed(self) -> bool:
        return self._fd < 0

    @property
    def pending_plain_bytes(self) -> int:
        return self._buffer_plain_bytes

    def append(self, data: bytes, *, accepted_monotonic_ns: int) -> None:
        if self.closed:
            raise ValueError("stream file is closed")
        row = BufferedRow(data, accepted_monotonic_ns)
        if self._buffer_plain_bytes + len(row.data) > self.max_plain_frame_bytes:
            raise FrameSealRequired(
                current_plain_bytes=self._buffer_plain_bytes,
                incoming_plain_bytes=len(row.data),
                max_plain_frame_bytes=self.max_plain_frame_bytes,
            )
        self._buffer.append(row)
        self._buffer_plain_bytes += len(row.data)

    def take_pending(self) -> PendingRows | None:
        if not self._buffer:
            return None
        pending = PendingRows(tuple(self._buffer), self._buffer_plain_bytes)
        self._buffer.clear()
        self._buffer_plain_bytes = 0
        return pending

    def seal_for_sync(
        self,
        *,
        direct_rows: PendingRows | None = None,
        force_sync: bool = False,
    ) -> SealedFileWork | None:
        if type(force_sync) is not bool:
            raise TypeError("force_sync must be a boolean")
        pending: PendingRows | None
        if direct_rows is not None:
            if type(direct_rows) is not PendingRows:
                raise TypeError("direct_rows must be PendingRows or None")
            if self._buffer:
                raise ValueError("direct rows require an empty active buffer")
            if (
                len(direct_rows.rows) != 1
                or direct_rows.plain_bytes <= self.max_plain_frame_bytes
            ):
                raise ValueError("direct rows must contain one oversized record")
            pending = direct_rows
        else:
            pending = self.take_pending()
        if pending is None and not force_sync:
            return None
        return SealedFileWork(
            generation_id=self.generation_id,
            stream_file=self,
            pending=pending,
            force_sync=force_sync,
        )

    def write_frame(self, pending: PendingRows) -> WrittenFrame:
        if self.closed:
            raise ValueError("stream file is closed")
        if type(pending) is not PendingRows:
            raise TypeError("pending must be PendingRows")
        plain = b"".join(row.data for row in pending.rows)
        frame = self._compressor.compress(plain)
        write_all(self._fd, frame)
        result = WrittenFrame(
            first_monotonic_ns=pending.rows[0].accepted_monotonic_ns,
            last_monotonic_ns=pending.rows[-1].accepted_monotonic_ns,
            record_monotonic_ns=tuple(
                row.accepted_monotonic_ns for row in pending.rows
            ),
            record_count=len(pending.rows),
            compressed_bytes=len(frame),
        )
        self.compressed_size += result.compressed_bytes
        return result

    def close_fd(self) -> None:
        if self.closed:
            return
        fd = self._fd
        self._fd = -1
        os.close(fd)

    def __enter__(self) -> Self:
        if self.closed:
            raise ValueError("stream file is closed")
        return self

    def __exit__(self, *_args: object) -> None:
        self.close_fd()


@dataclass(frozen=True, slots=True)
class SealedFileWork:
    generation_id: str
    stream_file: StreamFile
    pending: PendingRows | None
    force_sync: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "generation_id",
            _nonempty(self.generation_id, field="generation_id"),
        )
        if type(self.stream_file) is not StreamFile:
            raise TypeError("stream_file must be StreamFile")
        if self.generation_id != self.stream_file.generation_id:
            raise ValueError("sealed work generation must match its stream file")
        if self.pending is not None and type(self.pending) is not PendingRows:
            raise TypeError("pending must be PendingRows or None")
        if type(self.force_sync) is not bool:
            raise TypeError("force_sync must be a boolean")
        if self.pending is None and not self.force_sync:
            raise ValueError("clean sealed work requires force_sync")


__all__ = [
    "BufferedRow",
    "FrameSealRequired",
    "PendingRows",
    "SealedFileWork",
    "StreamFile",
    "WrittenFrame",
    "write_all",
]
