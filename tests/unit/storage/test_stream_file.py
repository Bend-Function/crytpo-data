from __future__ import annotations

import os
from pathlib import Path

import pytest
import zstandard

import crypto_collector.storage.stream_file as stream_file_module
from crypto_collector.storage.stream_file import (
    BufferedRow,
    FrameSealRequired,
    PendingRows,
    StreamFile,
    write_all,
)


def allocate(path: Path, *, limit: int = 1024) -> StreamFile:
    return StreamFile.allocate(
        path,
        zstd_level=3,
        max_plain_frame_bytes=limit,
    )


def test_each_flush_is_an_independent_decompressible_frame(tmp_path: Path) -> None:
    path = tmp_path / "part.jsonl.zst.partial"
    stream = allocate(path)
    stream.append(b'{"writer_sequence":1}\n', accepted_monotonic_ns=10)
    first_pending = stream.take_pending()
    assert first_pending is not None
    first = stream.write_frame(first_pending)
    stream.append(b'{"writer_sequence":2}\n', accepted_monotonic_ns=20)
    second_pending = stream.take_pending()
    assert second_pending is not None
    second = stream.write_frame(second_pending)
    stream.close_fd()

    assert first.record_count == second.record_count == 1
    assert first.record_monotonic_ns == (10,)
    assert second.record_monotonic_ns == (20,)
    encoded = path.read_bytes()
    first_encoded = encoded[: first.compressed_bytes]
    second_encoded = encoded[first.compressed_bytes :]
    first_plain = b'{"writer_sequence":1}\n'
    second_plain = b'{"writer_sequence":2}\n'
    assert zstandard.ZstdDecompressor().decompress(first_encoded) == first_plain
    assert zstandard.ZstdDecompressor().decompress(second_encoded) == second_plain
    assert zstandard.get_frame_parameters(first_encoded).has_checksum is True
    assert zstandard.get_frame_parameters(first_encoded).content_size == len(
        first_plain
    )
    assert zstandard.get_frame_parameters(second_encoded).has_checksum is True
    assert zstandard.get_frame_parameters(second_encoded).content_size == len(
        second_plain
    )

    with path.open("rb") as source:
        assert zstandard.ZstdDecompressor().stream_reader(source).read() == (
            first_plain + second_plain
        )


def test_compressed_size_drives_rotation_threshold(tmp_path: Path) -> None:
    stream = allocate(tmp_path / "part.jsonl.zst.partial")
    stream.append(b'{"payload":"aaaaaaaa"}\n', accepted_monotonic_ns=1)
    pending = stream.take_pending()
    assert pending is not None

    frame = stream.write_frame(pending)

    assert stream.compressed_size == frame.compressed_bytes
    assert stream.compressed_size > 0
    stream.close_fd()


def test_allocation_refuses_stale_partial(tmp_path: Path) -> None:
    path = tmp_path / "part.jsonl.zst.partial"
    path.write_bytes(b"stale")

    with pytest.raises(FileExistsError):
        allocate(path)

    assert path.read_bytes() == b"stale"


def test_default_generation_id_is_unique_across_stream_paths(tmp_path: Path) -> None:
    first = allocate(tmp_path / "one" / "part-1-0.jsonl.zst.partial")
    second = allocate(tmp_path / "two" / "part-1-0.jsonl.zst.partial")

    assert first.generation_id != second.generation_id
    first.close_fd()
    second.close_fd()


def test_allocation_uses_exclusive_append_flags_and_syncs_parent_before_return(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "part.jsonl.zst.partial"
    events: list[str] = []
    real_open = stream_file_module.os.open
    real_fsync = stream_file_module.os.fsync

    def traced_open(path_value, flags, mode=0o777, *, dir_fd=None):  # type: ignore[no-untyped-def]
        if flags & os.O_CREAT:
            events.append("open_exclusive")
            assert flags & os.O_EXCL
            assert flags & os.O_APPEND
            assert flags & os.O_WRONLY
            assert mode == 0o640
        return real_open(path_value, flags, mode, dir_fd=dir_fd)

    def traced_fsync(fd: int) -> None:
        events.append("fsync_partial_parent")
        real_fsync(fd)

    monkeypatch.setattr(stream_file_module.os, "open", traced_open)
    monkeypatch.setattr(stream_file_module.os, "fsync", traced_fsync)

    stream = allocate(path)
    events.append("return_stream")
    stream.close_fd()

    assert events[-3:] == [
        "open_exclusive",
        "fsync_partial_parent",
        "return_stream",
    ]


def test_allocation_rejects_symlinked_parent(tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    redirected = tmp_path / "redirected"
    redirected.symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        allocate(redirected / "part.jsonl.zst.partial")

    assert tuple(outside.iterdir()) == ()


def test_allocation_closes_new_file_if_parent_sync_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    created_fd: int | None = None
    real_open = stream_file_module.os.open
    real_close = stream_file_module.os.close
    real_fsync = stream_file_module.os.fsync
    parent_identity = (tmp_path.stat().st_dev, tmp_path.stat().st_ino)

    def traced_open(path_value, flags, mode=0o777, *, dir_fd=None):  # type: ignore[no-untyped-def]
        nonlocal created_fd
        fd = real_open(path_value, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT:
            created_fd = fd
        return fd

    def traced_close(fd: int) -> None:
        real_close(fd)

    def fail_final_parent_sync(fd: int) -> None:
        stat_result = os.fstat(fd)
        if (stat_result.st_dev, stat_result.st_ino) == parent_identity:
            raise OSError("sync failed")
        real_fsync(fd)

    monkeypatch.setattr(stream_file_module.os, "open", traced_open)
    monkeypatch.setattr(stream_file_module.os, "close", traced_close)
    monkeypatch.setattr(
        stream_file_module.os,
        "fsync",
        fail_final_parent_sync,
    )

    with pytest.raises(OSError, match="sync failed"):
        allocate(tmp_path / "part.jsonl.zst.partial")

    assert created_fd is not None
    try:
        with pytest.raises(OSError):
            os.fstat(created_fd)
    finally:
        try:
            real_close(created_fd)
        except OSError:
            pass


def test_allocation_retry_resyncs_existing_directory_entry(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    parent = tmp_path / "created-before-failed-sync"
    path = parent / "part.jsonl.zst.partial"
    tmp_identity = (tmp_path.stat().st_dev, tmp_path.stat().st_ino)
    real_fsync = stream_file_module.os.fsync
    successful_syncs: list[tuple[int, int]] = []
    fail_first = True

    def flaky_fsync(fd: int) -> None:
        nonlocal fail_first
        stat_result = os.fstat(fd)
        identity = (stat_result.st_dev, stat_result.st_ino)
        if fail_first and identity == tmp_identity:
            fail_first = False
            raise OSError("injected directory sync failure")
        successful_syncs.append(identity)
        real_fsync(fd)

    monkeypatch.setattr(stream_file_module.os, "fsync", flaky_fsync)

    with pytest.raises(OSError, match="injected directory sync failure"):
        allocate(path)
    assert parent.is_dir()
    assert not path.exists()

    stream = allocate(path)
    stream.close_fd()

    assert tmp_identity in successful_syncs


def test_directory_walk_closes_opened_child_if_previous_close_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    real_open = stream_file_module.os.open
    real_close = stream_file_module.os.close
    opened_fds: list[int] = []
    leaked_candidate: int | None = None
    fail_first = True

    def tracked_open(path_value, flags, mode=0o777, *, dir_fd=None):  # type: ignore[no-untyped-def]
        fd = real_open(path_value, flags, mode, dir_fd=dir_fd)
        opened_fds.append(fd)
        return fd

    def flaky_close(fd: int) -> None:
        nonlocal fail_first, leaked_candidate
        if fail_first:
            fail_first = False
            leaked_candidate = opened_fds[-1]
            raise OSError("injected directory close failure")
        real_close(fd)

    monkeypatch.setattr(stream_file_module.os, "open", tracked_open)
    monkeypatch.setattr(stream_file_module.os, "close", flaky_close)

    with pytest.raises(OSError, match="injected directory close failure"):
        allocate(tmp_path / "nested" / "part.jsonl.zst.partial")

    assert leaked_candidate is not None
    try:
        with pytest.raises(OSError):
            os.fstat(leaked_candidate)
    finally:
        for fd in opened_fds:
            try:
                real_close(fd)
            except OSError:
                pass


def test_allocation_closes_data_fd_if_final_parent_close_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    real_open = stream_file_module.os.open
    real_close = stream_file_module.os.close
    data_fd: int | None = None
    failed = False

    def tracked_open(path_value, flags, mode=0o777, *, dir_fd=None):  # type: ignore[no-untyped-def]
        nonlocal data_fd
        fd = real_open(path_value, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT:
            data_fd = fd
        return fd

    def flaky_close(fd: int) -> None:
        nonlocal failed
        if data_fd is not None and fd != data_fd and not failed:
            failed = True
            raise OSError("injected final parent close failure")
        real_close(fd)

    monkeypatch.setattr(stream_file_module.os, "open", tracked_open)
    monkeypatch.setattr(stream_file_module.os, "close", flaky_close)

    with pytest.raises(OSError, match="injected final parent close failure"):
        allocate(tmp_path / "part.jsonl.zst.partial")

    assert data_fd is not None
    try:
        with pytest.raises(OSError):
            os.fstat(data_fd)
    finally:
        try:
            real_close(data_fd)
        except OSError:
            pass


def test_write_all_retries_eintr_and_short_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "bytes"
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
    real_write = stream_file_module.os.write
    calls = 0

    def scripted_write(target_fd: int, data: bytes | memoryview) -> int:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise InterruptedError
        count = min(3, len(data)) if calls == 2 else len(data)
        return real_write(target_fd, data[:count])

    monkeypatch.setattr(stream_file_module.os, "write", scripted_write)
    try:
        write_all(fd, b"0123456789")
    finally:
        os.close(fd)

    assert calls == 3
    assert path.read_bytes() == b"0123456789"


@pytest.mark.parametrize("progress", [0, -1])
def test_write_all_rejects_no_progress(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    progress: int,
) -> None:
    fd = os.open(tmp_path / "bytes", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o640)
    monkeypatch.setattr(stream_file_module.os, "write", lambda _fd, _data: progress)
    try:
        with pytest.raises(OSError, match="no progress"):
            write_all(fd, b"payload")
    finally:
        os.close(fd)


def test_append_refuses_to_cross_plain_frame_limit_without_mutating_buffer(
    tmp_path: Path,
) -> None:
    stream = allocate(tmp_path / "part.jsonl.zst.partial", limit=32)
    first = b'{"a":"1234567890"}\n'
    second = b'{"b":"1234567890"}\n'
    stream.append(first, accepted_monotonic_ns=10)

    with pytest.raises(FrameSealRequired):
        stream.append(second, accepted_monotonic_ns=20)

    pending = stream.take_pending()
    assert pending is not None
    assert tuple(row.accepted_monotonic_ns for row in pending.rows) == (10,)
    assert pending.plain_bytes == len(first)
    assert pending.plain_bytes <= 32
    stream.close_fd()


def test_oversized_row_uses_direct_sealed_work(tmp_path: Path) -> None:
    stream = allocate(tmp_path / "part.jsonl.zst.partial", limit=8)
    row = BufferedRow(b'{"oversized":true}\n', accepted_monotonic_ns=10)
    direct = PendingRows(rows=(row,), plain_bytes=len(row.data))

    work = stream.seal_for_sync(direct_rows=direct)

    assert work is not None
    assert work.generation_id == stream.generation_id
    assert work.pending is direct
    assert work.force_sync is False
    stream.close_fd()


def test_generation_id_is_immutable_after_sealing(tmp_path: Path) -> None:
    stream = allocate(tmp_path / "part.jsonl.zst.partial")
    stream.append(b"{}\n", accepted_monotonic_ns=1)
    work = stream.seal_for_sync()
    assert work is not None

    with pytest.raises(AttributeError):
        stream.generation_id = "replacement"  # type: ignore[misc]

    assert stream.generation_id == work.generation_id
    stream.close_fd()


def test_pending_rows_reject_mismatched_bytes_and_decreasing_time() -> None:
    first = BufferedRow(b'{"a":1}\n', accepted_monotonic_ns=20)
    second = BufferedRow(b'{"b":2}\n', accepted_monotonic_ns=10)

    with pytest.raises(ValueError, match="plain_bytes"):
        PendingRows(rows=(first,), plain_bytes=1)
    with pytest.raises(ValueError, match="monotonic"):
        PendingRows(
            rows=(first, second), plain_bytes=len(first.data) + len(second.data)
        )


def test_direct_rows_require_one_oversized_row_and_empty_buffer(
    tmp_path: Path,
) -> None:
    stream = allocate(tmp_path / "part.jsonl.zst.partial", limit=8)
    small = BufferedRow(b"{}\n", accepted_monotonic_ns=1)
    with pytest.raises(ValueError, match="oversized"):
        stream.seal_for_sync(
            direct_rows=PendingRows(rows=(small,), plain_bytes=len(small.data))
        )

    stream.append(b"{}\n", accepted_monotonic_ns=2)
    oversized = BufferedRow(b'{"oversized":true}\n', accepted_monotonic_ns=3)
    with pytest.raises(ValueError, match="empty"):
        stream.seal_for_sync(
            direct_rows=PendingRows(
                rows=(oversized,),
                plain_bytes=len(oversized.data),
            )
        )
    pending = stream.take_pending()
    assert pending is not None
    assert pending.rows == (small.__class__(b"{}\n", 2),)
    stream.close_fd()


def test_seal_detaches_buffer_and_clean_force_sync_is_explicit(tmp_path: Path) -> None:
    stream = allocate(tmp_path / "part.jsonl.zst.partial")
    assert stream.seal_for_sync() is None

    clean = stream.seal_for_sync(force_sync=True)
    assert clean is not None
    assert clean.pending is None
    assert clean.force_sync is True

    stream.append(b"{}\n", accepted_monotonic_ns=5)
    dirty = stream.seal_for_sync()
    assert dirty is not None
    assert dirty.pending is not None
    assert stream.take_pending() is None
    stream.close_fd()


@pytest.mark.parametrize(
    ("data", "accepted"),
    [(b"", 1), (b"{}", 1), (b"{}\n", -1), (b"{}\n", True)],
)
def test_append_rejects_invalid_rows_without_mutation(
    tmp_path: Path,
    data: bytes,
    accepted: object,
) -> None:
    stream = allocate(tmp_path / "part.jsonl.zst.partial")

    with pytest.raises((TypeError, ValueError)):
        stream.append(data, accepted_monotonic_ns=accepted)  # type: ignore[arg-type]

    assert stream.take_pending() is None
    stream.close_fd()
