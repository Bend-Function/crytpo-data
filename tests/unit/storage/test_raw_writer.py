from __future__ import annotations

import asyncio
import errno
import os
import stat
import threading
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import TypeVar

import pytest
import zstandard

import crypto_collector.storage.raw_writer as raw_writer_module
from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.types import CloseReason, Exchange, Market, Transport
from crypto_collector.storage.durability import (
    DurabilityBatch,
    DurabilityCoordinator,
    DurabilityTrigger,
    FileDurabilityResult,
    FileSyncCompleted,
    FileSyncCompletion,
    FileSyncCompletionSink,
    FileSyncFailed,
    PosixSyncBackend,
    StorageIoLimiter,
    WriterCriticalError,
    WriterCriticalReason,
)
from crypto_collector.storage.manifest import RawManifestV1, load_raw_manifest
from crypto_collector.storage.models import (
    AcceptedRecord,
    AcceptedRecordIdentityV1,
    StorageControlAssociationV1,
    StorageControlTargetV1,
)
from crypto_collector.storage.raw_writer import (
    NoReplaceCapability,
    PublicationConflict,
    _ActivePart,
    _ActivePartSet,
    _FinalBarrierControlDependency,
    _FinalBarrierController,
    atomic_write_and_sync_json_exclusive,
    fsync_directory,
    open_readonly_nofollow,
    publish_no_replace,
    require_path_is_open_inode,
    run_storage,
    size_and_sha256_fd,
)
from crypto_collector.storage.serialize import encode_envelope
from crypto_collector.storage.stats import CumulativeDurabilityHistogram
from crypto_collector.storage.stream_file import SealedFileWork

_HOUR_NS = 3_600_000_000_000
_BASE_NS = int(datetime(2026, 7, 31, tzinfo=UTC).timestamp()) * 1_000_000_000
_ResultT = TypeVar("_ResultT")


def test_recovery_control_close_uses_recovery_durability_trigger() -> None:
    assert raw_writer_module._CLOSE_TRIGGER[CloseReason.RECOVERY_CONTROL] is (
        DurabilityTrigger.RECOVERY
    )


class QueueCompletionSink:
    def __init__(self, messages: asyncio.Queue[object]) -> None:
        self._messages = messages

    def __call__(self, completion: FileSyncCompletion) -> None:
        self._messages.put_nowait(completion)


def file_completion_sink(
    messages: asyncio.Queue[object],
) -> FileSyncCompletionSink:
    return QueueCompletionSink(messages)


class FixedClock:
    def __init__(self, monotonic_ns: int = 1_000_000) -> None:
        self._monotonic_ns = monotonic_ns

    def time_ns(self) -> int:
        return _BASE_NS

    def monotonic_ns(self) -> int:
        return self._monotonic_ns


def make_record(
    *,
    received_at_ns: int = _BASE_NS + 1,
    monotonic_ns: int = 10,
    writer_sequence: int = 0,
    acceptance_ordinal: int | None = None,
    config_sha256: str = "a" * 64,
    config_generation: int = 0,
    instrument_key: str = "BTC-USDT",
) -> tuple[AcceptedRecord, AcceptedRecordIdentityV1]:
    envelope = RawEnvelope(
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key=instrument_key,
        wire_symbol=instrument_key,
        logical_stream="trade",
        native_channel="trades",
        transport=Transport.WEBSOCKET,
        event_time_ns=received_at_ns - 1,
        event_time_source="exchange",
        payload={"price": "1"},
        received_at_ns=received_at_ns,
        monotonic_ns=monotonic_ns,
        worker_instance_id="worker-1",
        connection_id="connection-1",
        connection_generation=1,
        writer_sequence=writer_sequence,
        egress_id="direct-primary",
        config_sha256=config_sha256,
    )
    record = AcceptedRecord(envelope=envelope, encoded_jsonl=encode_envelope(envelope))
    identity = AcceptedRecordIdentityV1(
        exchange=envelope.exchange,
        market=envelope.market,
        instrument_key=envelope.instrument_key,
        logical_stream=envelope.logical_stream,
        worker_instance_id=envelope.worker_instance_id,
        writer_sequence=envelope.writer_sequence,
        acceptance_ordinal=(
            writer_sequence if acceptance_ordinal is None else acceptance_ordinal
        ),
        config_sha256=config_sha256,
        config_generation=config_generation,
    )
    return record, identity


def make_result(
    generation_id: str,
    accepted_monotonic_ns: tuple[int, ...],
    *,
    completed_monotonic_ns: int,
    sync_duration_ns: int = 5,
) -> FileDurabilityResult:
    histogram = CumulativeDurabilityHistogram()
    for accepted_ns in accepted_monotonic_ns:
        histogram.add(completed_monotonic_ns - accepted_ns)
    snapshot = histogram.snapshot()
    return FileDurabilityResult(
        generation_id=generation_id,
        was_dirty=bool(accepted_monotonic_ns),
        record_count=len(accepted_monotonic_ns),
        sync_completed_monotonic_ns=completed_monotonic_ns,
        sync_duration_ns=sync_duration_ns,
        lag_p50_ns=snapshot.lag_p50_ns,
        lag_p95_ns=snapshot.lag_p95_ns,
        lag_p99_ns=snapshot.lag_p99_ns,
        lag_max_ns=snapshot.lag_max_ns,
    )


def allocate_part(
    tmp_path: Path,
    *,
    part_sequence: int = 0,
    generation_id: str = "generation-0",
    instrument_key: str = "BTC-USDT",
) -> _ActivePart:
    record, identity = make_record(instrument_key=instrument_key)
    return _ActivePart.allocate(
        data_root=tmp_path,
        first_record=record,
        first_identity=identity,
        generation_id=generation_id,
        part_start_ns=_BASE_NS,
        part_sequence=part_sequence,
        zstd_level=3,
        max_plain_frame_bytes=4096,
        durability_slo_ns=1_000_000_000,
    )


def make_control_record(
    *,
    control_event_id: str,
    control_kind: str = "gap_detected",
    monotonic_ns: int = 20,
    writer_sequence: int = 1,
    acceptance_ordinal: int = 1,
    config_generation: int = 0,
) -> tuple[AcceptedRecord, AcceptedRecordIdentityV1]:
    envelope = RawEnvelope(
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        event_time_ns=None,
        event_time_source=None,
        payload={"kind": control_kind, "control_event_id": control_event_id},
        received_at_ns=_BASE_NS + 2,
        monotonic_ns=monotonic_ns,
        worker_instance_id="worker-1",
        connection_id=None,
        connection_generation=None,
        writer_sequence=writer_sequence,
        egress_id=None,
        config_sha256="a" * 64,
    )
    record = AcceptedRecord(envelope=envelope, encoded_jsonl=encode_envelope(envelope))
    identity = AcceptedRecordIdentityV1(
        exchange=envelope.exchange,
        market=envelope.market,
        instrument_key=envelope.instrument_key,
        logical_stream=envelope.logical_stream,
        worker_instance_id=envelope.worker_instance_id,
        writer_sequence=envelope.writer_sequence,
        acceptance_ordinal=acceptance_ordinal,
        config_sha256=envelope.config_sha256,
        config_generation=config_generation,
    )
    return record, identity


def allocate_control_part(
    tmp_path: Path,
    *,
    generation_id: str = "control-generation-0",
) -> _ActivePart:
    record, identity = make_control_record(control_event_id="allocation-seed")
    return _ActivePart.allocate(
        data_root=tmp_path,
        first_record=record,
        first_identity=identity,
        generation_id=generation_id,
        part_start_ns=_BASE_NS,
        part_sequence=0,
        zstd_level=3,
        max_plain_frame_bytes=4096,
        durability_slo_ns=1_000_000_000,
    )


def make_control_dependency(
    *,
    control: _ActivePart,
    control_identity: AcceptedRecordIdentityV1,
    target: _ActivePart,
    control_event_id: str,
) -> _FinalBarrierControlDependency:
    association = StorageControlAssociationV1(
        control_kind="gap_detected",
        control_event_id=control_event_id,
        targets=(
            StorageControlTargetV1(
                generation_id=target.generation_id,
                data_relative_path=target.data_relative_path,
            ),
        ),
        acceptance_ordinal=control_identity.acceptance_ordinal,
        config_generation=control_identity.config_generation,
    )
    return _FinalBarrierControlDependency(
        control_part=control,
        control_identity=control_identity,
        association=association,
        targets=(target,),
    )


async def drive_final_barrier_messages(
    controller: _FinalBarrierController,
    messages: asyncio.Queue[object],
    waiter: asyncio.Task[_ResultT],
) -> _ResultT:
    await asyncio.sleep(0)
    while not waiter.done():
        message_waiter = asyncio.create_task(messages.get())
        completed, _pending = await asyncio.wait(
            (waiter, message_waiter),
            timeout=2,
            return_when=asyncio.FIRST_COMPLETED,
        )
        if waiter in completed:
            if not message_waiter.done():
                message_waiter.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await message_waiter
            break
        if message_waiter not in completed:
            message_waiter.cancel()
            with pytest.raises(asyncio.CancelledError):
                await message_waiter
            raise AssertionError(
                f"final barrier service pump stalled: commands={controller._commands!r}"
            )
        message = message_waiter.result()
        try:
            assert controller.handle_message(message)
        finally:
            messages.task_done()
        await asyncio.sleep(0)
    return await waiter


async def close_group_with_service_pump(
    controller: _FinalBarrierController,
    messages: asyncio.Queue[object],
    parts: tuple[_ActivePart, ...],
    *,
    reason: CloseReason,
    closed_at_ns: int,
    control_dependencies: tuple[_FinalBarrierControlDependency, ...] = (),
) -> tuple[RawManifestV1, ...]:
    waiter = asyncio.create_task(
        controller.close_group(
            parts,
            reason=reason,
            closed_at_ns=closed_at_ns,
            control_dependencies=control_dependencies,
        )
    )
    return await drive_final_barrier_messages(controller, messages, waiter)


def test_hardlink_fallback_makes_destination_durable_before_source_unlink(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "part.jsonl.zst.partial"
    destination = tmp_path / "part.jsonl.zst"
    source.write_bytes(b"immutable")
    events: list[str] = []
    real_link = os.link
    real_unlink = os.unlink
    real_fsync = os.fsync

    def traced_link(
        source_path: str,
        destination_path: str,
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        events.append("link")
        real_link(
            source_path,
            destination_path,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    def traced_fsync(fd: int) -> None:
        events.append("directory_fsync")
        real_fsync(fd)

    def traced_unlink(path: str, *, dir_fd: int | None = None) -> None:
        events.append("unlink_source")
        real_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(raw_writer_module.os, "link", traced_link)
    monkeypatch.setattr(raw_writer_module.os, "fsync", traced_fsync)
    monkeypatch.setattr(raw_writer_module.os, "unlink", traced_unlink)

    publish_no_replace(
        source,
        destination,
        capability=NoReplaceCapability.HARDLINK,
    )

    assert events == [
        "link",
        "directory_fsync",
        "unlink_source",
        "directory_fsync",
    ]
    assert not source.exists()
    assert destination.read_bytes() == b"immutable"


def test_renameat2_publication_is_same_parent_and_directory_durable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "part.jsonl.zst.partial"
    destination = tmp_path / "part.jsonl.zst"
    source.write_bytes(b"immutable")
    events: list[str] = []
    real_fsync = os.fsync

    def fake_renameat2(
        source_path: Path,
        destination_path: Path,
        *,
        dir_fd: int,
    ) -> None:
        events.append("renameat2_noreplace")
        os.rename(
            source_path.name,
            destination_path.name,
            src_dir_fd=dir_fd,
            dst_dir_fd=dir_fd,
        )

    def traced_fsync(fd: int) -> None:
        events.append("common_parent_directory_fsync")
        real_fsync(fd)

    monkeypatch.setattr(raw_writer_module, "_renameat2_noreplace", fake_renameat2)
    monkeypatch.setattr(raw_writer_module.os, "fsync", traced_fsync)

    publish_no_replace(
        source,
        destination,
        capability=NoReplaceCapability.RENAMEAT2_NOREPLACE,
    )

    assert events == [
        "renameat2_noreplace",
        "common_parent_directory_fsync",
    ]
    other_parent = tmp_path / "other"
    other_parent.mkdir()
    with pytest.raises(ValueError, match="same parent"):
        publish_no_replace(destination, other_parent / destination.name)


@pytest.mark.parametrize("suffix", [".jsonl.zst", ".manifest.json"])
def test_publication_collision_never_overwrites_existing_bytes(
    tmp_path: Path,
    suffix: str,
) -> None:
    source = tmp_path / f"part{suffix}.partial"
    destination = tmp_path / f"part{suffix}"
    source.write_bytes(b"new")
    destination.write_bytes(b"existing")

    with pytest.raises(PublicationConflict):
        publish_no_replace(
            source,
            destination,
            capability=NoReplaceCapability.HARDLINK,
        )

    assert source.read_bytes() == b"new"
    assert destination.read_bytes() == b"existing"


@pytest.mark.parametrize(
    "capability",
    [NoReplaceCapability.HARDLINK, NoReplaceCapability.RENAMEAT2_NOREPLACE],
)
def test_nonregular_publication_collision_is_immediate_conflict(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capability: NoReplaceCapability,
) -> None:
    source = tmp_path / "part.partial"
    destination = tmp_path / "part.final"
    source.write_bytes(b"new")
    os.mkfifo(destination)

    if capability is NoReplaceCapability.RENAMEAT2_NOREPLACE:

        def collide(
            _source: Path,
            _destination: Path,
            *,
            dir_fd: int,
        ) -> None:
            assert dir_fd >= 0
            raise FileExistsError(errno.EEXIST, "destination exists")

        monkeypatch.setattr(raw_writer_module, "_renameat2_noreplace", collide)

    with pytest.raises(PublicationConflict):
        publish_no_replace(source, destination, capability=capability)

    assert source.read_bytes() == b"new"
    assert stat.S_ISFIFO(destination.stat().st_mode)


def test_hardlink_first_parent_sync_failure_retains_same_inode_names(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "part.partial"
    destination = tmp_path / "part.final"
    source.write_bytes(b"evidence")

    def fail_sync(_fd: int) -> None:
        raise OSError(errno.EIO, "injected directory sync failure")

    monkeypatch.setattr(raw_writer_module.os, "fsync", fail_sync)

    with pytest.raises(OSError, match="directory sync failure"):
        publish_no_replace(
            source,
            destination,
            capability=NoReplaceCapability.HARDLINK,
        )

    assert source.exists() and destination.exists()
    assert (source.stat().st_dev, source.stat().st_ino) == (
        destination.stat().st_dev,
        destination.stat().st_ino,
    )


def test_hardlink_unlink_failure_retains_reconcilable_coexistence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "part.partial"
    destination = tmp_path / "part.final"
    source.write_bytes(b"evidence")

    def fail_unlink(_path: str, *, dir_fd: int) -> None:
        raise OSError(errno.EIO, "injected unlink failure")

    monkeypatch.setattr(raw_writer_module.os, "unlink", fail_unlink)

    with pytest.raises(OSError, match="unlink failure"):
        publish_no_replace(
            source,
            destination,
            capability=NoReplaceCapability.HARDLINK,
        )

    assert source.exists() and destination.exists()
    assert source.samefile(destination)


def test_hardlink_second_parent_sync_failure_retains_final_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "part.partial"
    destination = tmp_path / "part.final"
    source.write_bytes(b"evidence")
    real_fsync = os.fsync
    calls = 0

    def fail_second_sync(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError(errno.EIO, "injected final directory sync failure")
        real_fsync(fd)

    monkeypatch.setattr(raw_writer_module.os, "fsync", fail_second_sync)

    with pytest.raises(OSError, match="final directory sync failure"):
        publish_no_replace(
            source,
            destination,
            capability=NoReplaceCapability.HARDLINK,
        )

    assert not source.exists()
    assert destination.read_bytes() == b"evidence"


def test_existing_same_inode_coexistence_finishes_hardlink_protocol(
    tmp_path: Path,
) -> None:
    source = tmp_path / "part.partial"
    destination = tmp_path / "part.final"
    source.write_bytes(b"evidence")
    os.link(source, destination)

    publish_no_replace(
        source,
        destination,
        capability=NoReplaceCapability.HARDLINK,
    )

    assert not source.exists()
    assert destination.read_bytes() == b"evidence"


def test_absent_source_does_not_accept_existing_destination(tmp_path: Path) -> None:
    source = tmp_path / "missing.partial"
    destination = tmp_path / "part.final"
    destination.write_bytes(b"existing")

    with pytest.raises(FileNotFoundError):
        publish_no_replace(
            source,
            destination,
            capability=NoReplaceCapability.HARDLINK,
        )

    assert destination.read_bytes() == b"existing"


def test_publication_requires_distinct_normalized_basenames(tmp_path: Path) -> None:
    source = tmp_path / "part"
    source.write_bytes(b"data")

    with pytest.raises(ValueError, match="distinct"):
        publish_no_replace(source, source)
    child = tmp_path / "child"
    child.mkdir()
    with pytest.raises(ValueError, match="normalized"):
        publish_no_replace(child / ".." / "part", tmp_path / "next")


def test_fsync_directory_uses_directory_and_nofollow_flags(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    opened_flags: list[int] = []
    real_open = os.open

    def traced_open(
        path: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        opened_flags.append(flags)
        return real_open(path, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(raw_writer_module.os, "open", traced_open)

    fsync_directory(tmp_path)

    assert opened_flags
    assert opened_flags[0] & getattr(os, "O_DIRECTORY", 0)
    assert opened_flags[0] & getattr(os, "O_NOFOLLOW", 0)


def test_open_readonly_nofollow_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_bytes(b"data")
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(OSError):
        open_readonly_nofollow(link)


def test_open_readonly_nofollow_rejects_directory_and_parent_symlink(
    tmp_path: Path,
) -> None:
    with pytest.raises(OSError, match="regular file"):
        open_readonly_nofollow(tmp_path)
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    (real_parent / "data").write_bytes(b"data")
    linked_parent = tmp_path / "linked"
    linked_parent.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(OSError):
        open_readonly_nofollow(linked_parent / "data")


def test_open_readonly_nofollow_uses_nonblocking_open_for_special_files(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "data"
    path.write_bytes(b"data")
    real_open = os.open
    file_flags: list[int] = []

    def traced_open(
        path_value: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if path_value == path.name:
            file_flags.append(flags)
        return real_open(path_value, flags, mode, dir_fd=dir_fd)

    monkeypatch.setattr(raw_writer_module.os, "open", traced_open)
    descriptor = open_readonly_nofollow(path)
    os.close(descriptor)

    assert file_flags and file_flags == [file_flags[0]]
    assert file_flags[0] & os.O_NONBLOCK


def test_open_readonly_closes_file_fd_when_parent_close_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "data"
    path.write_bytes(b"data")
    real_open = os.open
    real_close = os.close
    file_fd: int | None = None
    closed_fds: list[int] = []
    injected = False

    def traced_open(
        path_value: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal file_fd
        descriptor = real_open(path_value, flags, mode, dir_fd=dir_fd)
        if path_value == path.name:
            file_fd = descriptor
        return descriptor

    def fail_final_parent_close(descriptor: int) -> None:
        nonlocal injected
        if file_fd is not None and descriptor != file_fd and not injected:
            injected = True
            real_close(descriptor)
            raise OSError(errno.EIO, "injected parent close failure")
        if file_fd is not None:
            closed_fds.append(descriptor)
        real_close(descriptor)

    monkeypatch.setattr(raw_writer_module.os, "open", traced_open)
    monkeypatch.setattr(raw_writer_module.os, "close", fail_final_parent_close)

    with pytest.raises(OSError, match="parent close failure"):
        open_readonly_nofollow(path)

    assert file_fd is not None
    assert file_fd in closed_fds


def test_require_path_is_open_inode_rejects_replacement(tmp_path: Path) -> None:
    original = tmp_path / "original"
    replacement = tmp_path / "replacement"
    original.write_bytes(b"first")
    replacement.write_bytes(b"second")
    fd = open_readonly_nofollow(original)
    try:
        with pytest.raises(PublicationConflict, match="inode"):
            require_path_is_open_inode(replacement, fd)
    finally:
        os.close(fd)


def test_size_and_sha256_fd_is_offset_independent(tmp_path: Path) -> None:
    path = tmp_path / "data"
    path.write_bytes(b"abcdef")
    fd = open_readonly_nofollow(path)
    try:
        assert os.read(fd, 2) == b"ab"
        assert size_and_sha256_fd(fd) == (
            6,
            "bef57ec7f53a6d40beb640a780a639c83bc29ac8a9816f1fc6c5c6dcd93c4721",
        )
        assert os.read(fd, 2) == b"cd"
    finally:
        os.close(fd)


def test_size_and_sha256_fd_retries_interrupted_pread(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "data"
    path.write_bytes(b"abcdef")
    real_pread = os.pread
    attempts = 0

    def interrupted_once(fd: int, count: int, offset: int) -> bytes:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise InterruptedError
        return real_pread(fd, count, offset)

    monkeypatch.setattr(raw_writer_module.os, "pread", interrupted_once)
    fd = open_readonly_nofollow(path)
    try:
        assert size_and_sha256_fd(fd)[0] == 6
    finally:
        os.close(fd)
    assert attempts == 2


@pytest.mark.parametrize("flag_name", ["O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC"])
def test_missing_required_open_flags_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    flag_name: str,
) -> None:
    path = tmp_path / "data"
    path.write_bytes(b"data")
    monkeypatch.setattr(raw_writer_module.os, flag_name, 0)

    with pytest.raises(OSError) as captured:
        open_readonly_nofollow(path)

    assert captured.value.errno == errno.ENOTSUP


def test_atomic_manifest_temp_is_exclusive_file_and_directory_durable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    path = tmp_path / "part.manifest.json.partial"
    events: list[str] = []
    real_open = os.open
    real_fsync = os.fsync

    def traced_open(
        path_value: str | Path,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if flags & os.O_CREAT:
            events.append("manifest_temp_create")
        return real_open(path_value, flags, mode, dir_fd=dir_fd)

    def traced_fsync(fd: int) -> None:
        mode = os.fstat(fd).st_mode
        events.append("directory_fd_fsync" if stat.S_ISDIR(mode) else "file_fsync")
        real_fsync(fd)

    monkeypatch.setattr(raw_writer_module.os, "open", traced_open)
    monkeypatch.setattr(raw_writer_module.os, "fsync", traced_fsync)

    atomic_write_and_sync_json_exclusive(path, b'{"schema_version":1}\n')

    assert path.read_bytes() == b'{"schema_version":1}\n'
    assert events == ["manifest_temp_create", "directory_fd_fsync", "file_fsync"]
    with pytest.raises(FileExistsError):
        atomic_write_and_sync_json_exclusive(path, b"replacement\n")
    assert path.read_bytes() == b'{"schema_version":1}\n'


@pytest.mark.asyncio
async def test_run_storage_uses_supplied_limiter_and_executor() -> None:
    event_loop_thread = threading.get_ident()
    limiter = StorageIoLimiter(max_concurrency=1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        worker_thread = await run_storage(
            limiter,
            executor,
            threading.get_ident,
        )

    assert worker_thread != event_loop_thread


@pytest.mark.asyncio
async def test_run_storage_propagates_cancellation_without_default_executor_use() -> (
    None
):
    started = threading.Event()
    release = threading.Event()

    def blocking() -> None:
        started.set()
        assert release.wait(timeout=2)

    limiter = StorageIoLimiter(max_concurrency=1)
    executor = ThreadPoolExecutor(max_workers=1)
    try:
        task = asyncio.create_task(run_storage(limiter, executor, blocking))
        await asyncio.to_thread(started.wait, 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        release.set()
        executor.shutdown(wait=True)


def test_part_accumulator_recomputes_exact_cross_batch_quantiles(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    records = (
        make_record(monotonic_ns=10, writer_sequence=0),
        make_record(monotonic_ns=20, writer_sequence=1),
        make_record(monotonic_ns=990_000, writer_sequence=2),
    )
    try:
        for record, identity in records[:2]:
            part.append_accepted(record, identity)
        first = part.seal_for_sync()
        assert first is not None
        part.apply_completion(
            first,
            make_result(
                part.generation_id,
                (10, 20),
                completed_monotonic_ns=100,
            ),
        )

        record, identity = records[2]
        part.append_accepted(record, identity)
        second = part.seal_for_sync()
        assert second is not None
        part.apply_completion(
            second,
            make_result(
                part.generation_id,
                (990_000,),
                completed_monotonic_ns=1_000_000,
            ),
        )
        clean = part.seal_for_sync(force_sync=True)
        assert clean is not None
        part.apply_completion(
            clean,
            make_result(
                part.generation_id,
                (),
                completed_monotonic_ns=1_000_001,
            ),
        )

        summary = part.freeze_summary()
        expected = CumulativeDurabilityHistogram()
        for lag_ns in (90, 80, 10_000):
            expected.add(lag_ns)
        expected_snapshot = expected.snapshot()
        assert summary.durability_sample_count == summary.record_count == 3
        assert summary.durability_lag_p50_ns == expected_snapshot.lag_p50_ns
        assert summary.durability_lag_p95_ns == expected_snapshot.lag_p95_ns
        assert summary.durability_lag_p99_ns == expected_snapshot.lag_p99_ns
        assert summary.durability_lag_max_ns == 10_000
        assert summary.sync_count == 3
    finally:
        part.close_fd_for_test()


def test_invalid_completion_is_atomic_and_does_not_consume_claims(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    record, identity = make_record(monotonic_ns=10)
    try:
        part.append_accepted(record, identity)
        claimed = part.seal_for_sync()
        assert claimed is not None
        invalid = make_result(
            part.generation_id,
            (10,),
            completed_monotonic_ns=100,
        )
        invalid = replace(invalid, generation_id="other-generation")

        with pytest.raises(ValueError, match="generation"):
            part.apply_completion(claimed, invalid)

        assert part.durability_sample_count == 0
        part.apply_completion(
            claimed,
            make_result(
                part.generation_id,
                (10,),
                completed_monotonic_ns=100,
            ),
        )
        assert part.durability_sample_count == 1
    finally:
        part.close_fd_for_test()


def test_only_exact_durable_control_targets_contribute_to_part_summary(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    record, identity = make_record(monotonic_ns=10)
    try:
        part.append_accepted(record, identity)
        claimed = part.seal_for_sync()
        assert claimed is not None
        part.apply_completion(
            claimed,
            make_result(
                part.generation_id,
                (10,),
                completed_monotonic_ns=100,
            ),
        )
        association = StorageControlAssociationV1(
            control_kind="gap_detected",
            control_event_id="gap:1",
            targets=(
                StorageControlTargetV1(
                    generation_id=part.generation_id,
                    data_relative_path=part.data_relative_path,
                ),
            ),
            acceptance_ordinal=1,
            config_generation=0,
        )
        part.fold_durable_control(association)

        summary = part.freeze_summary()
        assert summary.gap_count == 1
        assert summary.control_event_ids == ("gap:1",)

        with pytest.raises(ValueError, match="frozen"):
            part.fold_durable_control(association)
    finally:
        part.close_fd_for_test()


def test_received_hour_routes_forward_and_backward_before_append(
    tmp_path: Path,
) -> None:
    manager = _ActivePartSet(
        data_root=tmp_path,
        exchange=Exchange.OKX,
        config_sha256="a" * 64,
        config_generation=0,
        zstd_level=3,
        max_plain_frame_bytes=4096,
        max_compressed_size_bytes=1024 * 1024,
        rotate_interval_ns=5_000_000_000,
        durability_slo_ns=1_000_000_000,
    )
    before = make_record(received_at_ns=_BASE_NS + _HOUR_NS - 1)
    after = make_record(
        received_at_ns=_BASE_NS + _HOUR_NS,
        writer_sequence=1,
    )
    backward = make_record(
        received_at_ns=_BASE_NS + _HOUR_NS - 2,
        writer_sequence=2,
    )

    assert manager.append_accepted(*before) == ()
    first_retired = manager.append_accepted(*after)
    second_retired = manager.append_accepted(*backward)
    active = manager.detach_all(
        CloseReason.SHUTDOWN,
        closed_at_ns=_BASE_NS + _HOUR_NS + 1,
    )
    try:
        assert len(first_retired) == len(second_retired) == len(active) == 1
        assert "/2026/07/31/00/" in f"/{first_retired[0].data_relative_path}"
        assert "/2026/07/31/01/" in f"/{second_retired[0].data_relative_path}"
        assert "/2026/07/31/00/" in f"/{active[0].data_relative_path}"
        assert first_retired[0].record_count == 1
        assert second_retired[0].record_count == 1
        assert active[0].record_count == 1
    finally:
        for part in (*first_retired, *second_retired, *active):
            part.close_fd_for_test()


def test_hour_replacement_allocation_failure_keeps_old_generation_owned(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    manager = _ActivePartSet(
        data_root=tmp_path,
        exchange=Exchange.OKX,
        config_sha256="a" * 64,
        config_generation=0,
        zstd_level=3,
        max_plain_frame_bytes=4096,
        max_compressed_size_bytes=1024 * 1024,
        rotate_interval_ns=5_000_000_000,
        durability_slo_ns=1_000_000_000,
    )
    manager.append_accepted(*make_record(received_at_ns=_BASE_NS + 1))
    old_part = next(iter(manager._active.values()))

    def fail_allocate(*_args: object, **_kwargs: object) -> _ActivePart:
        raise OSError(errno.ENOSPC, "injected allocation failure")

    monkeypatch.setattr(manager, "_allocate", fail_allocate)
    try:
        with pytest.raises(OSError, match="allocation failure"):
            manager.append_accepted(
                *make_record(
                    received_at_ns=_BASE_NS + _HOUR_NS,
                    writer_sequence=1,
                )
            )

        assert tuple(manager._active.values()) == (old_part,)
        assert old_part.close_reason is None
        assert old_part.record_count == 1
    finally:
        old_part.close_fd_for_test()


def test_invalid_bulk_detach_keeps_every_active_generation_owned(
    tmp_path: Path,
) -> None:
    manager = _ActivePartSet(
        data_root=tmp_path,
        exchange=Exchange.OKX,
        config_sha256="a" * 64,
        config_generation=0,
        zstd_level=3,
        max_plain_frame_bytes=4096,
        max_compressed_size_bytes=1024 * 1024,
        rotate_interval_ns=5_000_000_000,
        durability_slo_ns=1_000_000_000,
    )
    manager.append_accepted(*make_record(instrument_key="BTC-USDT"))
    manager.append_accepted(
        *make_record(
            instrument_key="ETH-USDT",
            writer_sequence=1,
        )
    )
    active_before = tuple(manager._active.values())
    try:
        with pytest.raises(ValueError, match="closed_at_ns"):
            manager.detach_all(CloseReason.SHUTDOWN, closed_at_ns=-1)

        assert set(manager._active.values()) == set(active_before)
        assert all(part.close_reason is None for part in active_before)
    finally:
        for part in active_before:
            part.close_fd_for_test()


def test_config_rotation_never_shares_a_part(tmp_path: Path) -> None:
    manager = _ActivePartSet(
        data_root=tmp_path,
        exchange=Exchange.OKX,
        config_sha256="a" * 64,
        config_generation=0,
        zstd_level=3,
        max_plain_frame_bytes=4096,
        max_compressed_size_bytes=1024 * 1024,
        rotate_interval_ns=5_000_000_000,
        durability_slo_ns=1_000_000_000,
    )
    manager.append_accepted(*make_record(config_sha256="a" * 64))
    old = manager.rotate_for_config(
        "b" * 64,
        config_generation=1,
        closed_at_ns=_BASE_NS + 10,
    )
    manager.append_accepted(
        *make_record(
            config_sha256="b" * 64,
            config_generation=1,
            writer_sequence=1,
        )
    )
    new = manager.detach_all(
        CloseReason.SHUTDOWN,
        closed_at_ns=_BASE_NS + 20,
    )
    try:
        assert {part.close_reason for part in old} == {CloseReason.CONFIG_RELOAD}
        assert {part.config_sha256 for part in (*old, *new)} == {"a" * 64, "b" * 64}
    finally:
        for part in (*old, *new):
            part.close_fd_for_test()


def test_configured_interval_and_exact_size_threshold_are_independent(
    tmp_path: Path,
) -> None:
    manager = _ActivePartSet(
        data_root=tmp_path,
        exchange=Exchange.OKX,
        config_sha256="a" * 64,
        config_generation=0,
        zstd_level=3,
        max_plain_frame_bytes=4096,
        max_compressed_size_bytes=100,
        rotate_interval_ns=5_000_000_000,
        durability_slo_ns=1_000_000_000,
    )
    manager.append_accepted(*make_record())
    part = next(iter(manager._active.values()))
    part.stream_file.compressed_size = 100

    size_due = manager.detach_size_due(closed_at_ns=_BASE_NS + 2)
    try:
        assert size_due == (part,)
        assert part.close_reason is CloseReason.ROTATE_SIZE
    finally:
        part.close_fd_for_test()

    manager.append_accepted(*make_record(writer_sequence=1))
    interval_part = next(iter(manager._active.values()))
    assert (
        manager.detach_interval_due(
            now_ns=interval_part.created_at_ns + 5_000_000_000 - 1
        )
        == ()
    )
    interval_due = manager.detach_interval_due(
        now_ns=interval_part.created_at_ns + 5_000_000_000
    )
    try:
        assert interval_due == (interval_part,)
        assert interval_part.close_reason is CloseReason.ROTATE_TIME
    finally:
        interval_part.close_fd_for_test()


def test_due_rotation_installs_reserved_control_target_at_seal(
    tmp_path: Path,
) -> None:
    manager = _ActivePartSet(
        data_root=tmp_path,
        exchange=Exchange.OKX,
        config_sha256="a" * 64,
        config_generation=0,
        zstd_level=3,
        max_plain_frame_bytes=4096,
        max_compressed_size_bytes=1,
        rotate_interval_ns=5_000_000_000,
        durability_slo_ns=1_000_000_000,
    )
    record, identity = make_record()
    manager.append_accepted(record, identity)
    current = manager.active_part_for(record)
    assert current is not None
    current.stream_file.compressed_size = 1

    plans = manager.plan_due_rotations(
        now_ns=_BASE_NS + 2,
        seal_acceptance_ordinal=identity.acceptance_ordinal,
    )
    assert len(plans) == 1
    plan = plans[0]
    assert plan.seal_acceptance_ordinal == identity.acceptance_ordinal

    manager.begin_rotations(plans)
    reserved = manager.active_part_for_logical_identity(
        market=record.envelope.market,
        instrument_key=record.envelope.instrument_key,
        logical_stream=record.envelope.logical_stream,
    )
    assert reserved is plan.reservation
    assert current.close_reason is CloseReason.ROTATE_SIZE

    replacement = manager.materialize_rotation(plan)
    try:
        size_due, interval_due = manager.commit_rotations(((plan, replacement),))
        assert size_due == (current,)
        assert interval_due == ()
        assert manager.active_part_for(record) is replacement
    finally:
        current.close_fd_for_test()
        replacement.close_fd_for_test()


@pytest.mark.asyncio
async def test_final_barrier_duplicate_preflight_leaves_part_retryable(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))

    class NoCallCoordinator:
        called = False

        async def sync_batch(
            self,
            _work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            self.called = True
            raise AssertionError(f"unexpected sync call: {trigger}")

    coordinator = NoCallCoordinator()
    limiter = StorageIoLimiter(max_concurrency=1)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=asyncio.Queue(),
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(ValueError, match="unique|duplicate|already"):
                await controller.close_group(
                    (part, part),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )

        assert not coordinator.called
        assert part.close_reason is None
        assert len(part._pending_claims) == 1
        assert not part._claimed
    finally:
        part.close_fd_for_test()


def test_final_barrier_rejects_bounded_completion_queue() -> None:
    class NoCallCoordinator:
        async def sync_batch(
            self,
            _work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            raise AssertionError(f"unexpected sync call: {trigger}")

    limiter = StorageIoLimiter(max_concurrency=1)
    with (
        ThreadPoolExecutor(max_workers=1) as executor,
        pytest.raises(ValueError, match="unbounded"),
    ):
        _FinalBarrierController(
            durability_coordinator=NoCallCoordinator(),
            completion_queue=asyncio.Queue(maxsize=1),
            io_limiter=limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
        )


@pytest.mark.asyncio
async def test_final_barrier_waits_for_in_flight_member_before_final_batch(
    tmp_path: Path,
) -> None:
    first = allocate_part(tmp_path, generation_id="generation-0", part_sequence=0)
    second = allocate_part(tmp_path, generation_id="generation-1", part_sequence=1)
    first.append_accepted(*make_record(monotonic_ns=10, writer_sequence=0))
    second.append_accepted(*make_record(monotonic_ns=11, writer_sequence=1))
    second_claim = second.seal_for_sync(force_sync=True)
    assert second_claim is not None
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)

    class RecordingCoordinator:
        def __init__(self, inner: DurabilityCoordinator) -> None:
            self.inner = inner
            self.calls: list[tuple[str, ...]] = []

        async def sync_batch(
            self,
            work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            self.calls.append(tuple(item.generation_id for item in work_items))
            return await self.inner.sync_batch(work_items, trigger=trigger)

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            inner = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=PosixSyncBackend(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            coordinator = RecordingCoordinator(inner)
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            prior_sync = asyncio.create_task(
                inner.sync_batch(
                    (second_claim.work,),
                    trigger=DurabilityTrigger.PERIODIC,
                )
            )
            second.bind_claim_batch_task(second_claim, prior_sync)
            close_waiter = asyncio.create_task(
                controller.close_group(
                    (first, second),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )
            )
            await asyncio.sleep(0)
            assert not coordinator.calls
            assert not close_waiter.done()
            first_was_reserved = (
                first.generation_id in controller._command_by_generation
            )

            manifests = await drive_final_barrier_messages(
                controller,
                completions,
                close_waiter,
            )
            await prior_sync

        assert coordinator.calls == [
            (first.generation_id, second.generation_id),
        ]
        assert first_was_reserved
        assert tuple(item.data_relative_path for item in manifests) == (
            first.data_relative_path,
            second.data_relative_path,
        )
        assert second.durability_sample_count == 1
    finally:
        if second._claimed.get(second_claim.claim_id) is second_claim:
            second.apply_failure(second_claim, OSError(errno.EIO, "test cleanup"))
        first.close_fd_for_test()
        second.close_fd_for_test()


@pytest.mark.asyncio
async def test_final_barrier_rejects_untracked_in_flight_claim_atomically(
    tmp_path: Path,
) -> None:
    first = allocate_part(tmp_path, generation_id="generation-0", part_sequence=0)
    second = allocate_part(tmp_path, generation_id="generation-1", part_sequence=1)
    first.append_accepted(*make_record(monotonic_ns=10, writer_sequence=0))
    second.append_accepted(*make_record(monotonic_ns=11, writer_sequence=1))
    second_claim = second.seal_for_sync(force_sync=True)
    assert second_claim is not None

    class NoCallCoordinator:
        async def sync_batch(
            self,
            _work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            raise AssertionError(f"unexpected sync call: {trigger}")

    limiter = StorageIoLimiter(max_concurrency=1)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            controller = _FinalBarrierController(
                durability_coordinator=NoCallCoordinator(),
                completion_queue=asyncio.Queue(),
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(ValueError, match="settlement task"):
                controller._start_close_group(
                    (first, second),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                    control_dependencies=(),
                )

        assert first.close_reason is None
        assert second.close_reason is None
        assert not controller._commands
        assert not controller._command_by_generation
    finally:
        if second._claimed.get(second_claim.claim_id) is second_claim:
            second.apply_failure(second_claim, OSError(errno.EIO, "test cleanup"))
        first.close_fd_for_test()
        second.close_fd_for_test()


@pytest.mark.asyncio
async def test_missing_prerequisite_completion_fails_without_hanging(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))
    claimed = part.seal_for_sync(force_sync=True)
    assert claimed is not None
    result = make_result(
        part.generation_id,
        (10,),
        completed_monotonic_ns=20,
    )

    async def settle_without_completion() -> DurabilityBatch:
        await asyncio.sleep(0)
        return DurabilityBatch(
            batch_sequence=0,
            trigger=DurabilityTrigger.PERIODIC,
            started_monotonic_ns=1,
            completed_monotonic_ns=20,
            files=(result,),
        )

    class NoCallCoordinator:
        async def sync_batch(
            self,
            _work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            raise AssertionError(f"unexpected final sync call: {trigger}")

    prior_batch = asyncio.create_task(settle_without_completion())
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    try:
        part.bind_claim_batch_task(claimed, prior_batch)
        with ThreadPoolExecutor(max_workers=1) as executor:
            controller = _FinalBarrierController(
                durability_coordinator=NoCallCoordinator(),
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(WriterCriticalError) as captured:
                await close_group_with_service_pump(
                    controller,
                    completions,
                    (part,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )

        assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
        assert captured.value.affected_generation_ids == (part.generation_id,)
        assert part.stream_file.closed
        assert not part.closed_manifest_path.exists()
        assert not controller._commands
        assert not controller._command_by_generation
    finally:
        await prior_batch
        if part._claimed.get(claimed.claim_id) is claimed:
            part.apply_failure(claimed, OSError(errno.EIO, "test cleanup"))
        part.close_fd_for_test()


@pytest.mark.asyncio
async def test_missing_prerequisite_completion_preserves_batch_write_failure(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))
    claimed = part.seal_for_sync(force_sync=True)
    assert claimed is not None

    async def settle_with_write_failure() -> DurabilityBatch:
        await asyncio.sleep(0)
        raise WriterCriticalError(
            reason=WriterCriticalReason.WRITE_FAILED,
            affected_generation_ids=(part.generation_id,),
            completed_batches=(),
            message="injected prerequisite write failure",
        )

    class NoCallCoordinator:
        async def sync_batch(
            self,
            _work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            raise AssertionError(f"unexpected final sync call: {trigger}")

    prior_batch = asyncio.create_task(settle_with_write_failure())
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    try:
        part.bind_claim_batch_task(claimed, prior_batch)
        with ThreadPoolExecutor(max_workers=1) as executor:
            controller = _FinalBarrierController(
                durability_coordinator=NoCallCoordinator(),
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(WriterCriticalError) as captured:
                await close_group_with_service_pump(
                    controller,
                    completions,
                    (part,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )

        assert captured.value.reason is WriterCriticalReason.WRITE_FAILED
        assert captured.value.affected_generation_ids == (part.generation_id,)
        assert part.stream_file.closed
        assert not controller._commands
        assert not controller._command_by_generation
    finally:
        await asyncio.gather(prior_batch, return_exceptions=True)
        if part._claimed.get(claimed.claim_id) is claimed:
            part.apply_failure(claimed, OSError(errno.EIO, "test cleanup"))
        part.close_fd_for_test()


@pytest.mark.asyncio
async def test_settled_prerequisite_stays_reserved_until_final_batch(
    tmp_path: Path,
) -> None:
    first = allocate_part(tmp_path, generation_id="generation-0", part_sequence=0)
    second = allocate_part(tmp_path, generation_id="generation-1", part_sequence=1)
    first.append_accepted(*make_record(monotonic_ns=10, writer_sequence=0))
    second.append_accepted(*make_record(monotonic_ns=11, writer_sequence=1))
    first_claim = first.seal_for_sync(force_sync=True)
    second_claim = second.seal_for_sync(force_sync=True)
    assert first_claim is not None
    assert second_claim is not None
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=PosixSyncBackend(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            second_gate = asyncio.Event()

            async def settle_second_claim() -> DurabilityBatch:
                await second_gate.wait()
                return await coordinator.sync_batch(
                    (second_claim.work,),
                    trigger=DurabilityTrigger.PERIODIC,
                )

            first_prior_sync = asyncio.create_task(
                coordinator.sync_batch(
                    (first_claim.work,),
                    trigger=DurabilityTrigger.PERIODIC,
                )
            )
            second_prior_sync = asyncio.create_task(settle_second_claim())
            first.bind_claim_batch_task(first_claim, first_prior_sync)
            second.bind_claim_batch_task(second_claim, second_prior_sync)
            close_waiter = asyncio.create_task(
                controller.close_group(
                    (first, second),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )
            )
            await asyncio.sleep(0)

            first_completion = await asyncio.wait_for(completions.get(), timeout=2)
            try:
                assert type(first_completion) is FileSyncCompleted
                assert controller.handle_message(first_completion)
            finally:
                completions.task_done()
            await first_prior_sync
            first_command_id = controller._command_by_generation.get(
                first.generation_id
            )
            assert first_command_id is not None
            assert not close_waiter.done()

            second_gate.set()
            manifests = await drive_final_barrier_messages(
                controller,
                completions,
                close_waiter,
            )
            await second_prior_sync

        assert tuple(item.data_relative_path for item in manifests) == (
            first.data_relative_path,
            second.data_relative_path,
        )
        assert first_command_id not in controller._commands
        assert not controller._commands
        assert not controller._command_by_generation
    finally:
        if first._claimed.get(first_claim.claim_id) is first_claim:
            first.apply_failure(first_claim, OSError(errno.EIO, "test cleanup"))
        if second._claimed.get(second_claim.claim_id) is second_claim:
            second.apply_failure(second_claim, OSError(errno.EIO, "test cleanup"))
        first.close_fd_for_test()
        second.close_fd_for_test()


@pytest.mark.asyncio
async def test_failed_prerequisite_stays_reserved_until_peers_settle(
    tmp_path: Path,
) -> None:
    first = allocate_part(tmp_path, generation_id="generation-0", part_sequence=0)
    second = allocate_part(tmp_path, generation_id="generation-1", part_sequence=1)
    first.append_accepted(*make_record(monotonic_ns=10, writer_sequence=0))
    second.append_accepted(*make_record(monotonic_ns=11, writer_sequence=1))
    first_claim = first.seal_for_sync(force_sync=True)
    second_claim = second.seal_for_sync(force_sync=True)
    assert first_claim is not None
    assert second_claim is not None
    first_fd = first.stream_file.fileno()
    second_fd = second.stream_file.fileno()
    release_second = threading.Event()

    class OrderedSync:
        def sync(self, fd: int) -> None:
            if fd == first_fd:
                raise OSError(errno.EIO, "injected prerequisite failure")
            assert fd == second_fd
            assert release_second.wait(timeout=2)
            os.fsync(fd)

    class NoFinalBatchCoordinator:
        called = False

        async def sync_batch(
            self,
            _work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            self.called = True
            raise AssertionError(f"unexpected final sync call: {trigger}")

    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=2)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            prior_coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=OrderedSync(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            final_coordinator = NoFinalBatchCoordinator()
            controller = _FinalBarrierController(
                durability_coordinator=final_coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            first_prior_sync = asyncio.create_task(
                prior_coordinator.sync_batch(
                    (first_claim.work,),
                    trigger=DurabilityTrigger.PERIODIC,
                )
            )
            second_prior_sync = asyncio.create_task(
                prior_coordinator.sync_batch(
                    (second_claim.work,),
                    trigger=DurabilityTrigger.PERIODIC,
                )
            )
            first.bind_claim_batch_task(first_claim, first_prior_sync)
            second.bind_claim_batch_task(second_claim, second_prior_sync)
            result_future = controller._start_close_group(
                (first, second),
                reason=CloseReason.SHUTDOWN,
                closed_at_ns=_BASE_NS + 100,
                control_dependencies=(),
            )

            async def await_result() -> tuple[RawManifestV1, ...]:
                return await asyncio.shield(result_future)

            close_waiter = asyncio.create_task(await_result())
            try:
                while True:
                    message = await asyncio.wait_for(completions.get(), timeout=2)
                    try:
                        assert controller.handle_message(message)
                    finally:
                        completions.task_done()
                    if (
                        type(message) is FileSyncFailed
                        and message.generation_id == first.generation_id
                    ):
                        break

                first_command_id = controller._command_by_generation.get(
                    first.generation_id
                )
                assert first_command_id is not None
                assert not close_waiter.done()

                release_second.set()
                with pytest.raises(WriterCriticalError) as captured:
                    await drive_final_barrier_messages(
                        controller,
                        completions,
                        close_waiter,
                    )
            finally:
                release_second.set()
                await asyncio.gather(
                    first_prior_sync,
                    second_prior_sync,
                    return_exceptions=True,
                )

        assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
        assert first_command_id not in controller._commands
        assert not final_coordinator.called
        assert not controller._commands
        assert not controller._command_by_generation
        assert first.stream_file.closed
        assert second.stream_file.closed
    finally:
        release_second.set()
        if first._claimed.get(first_claim.claim_id) is first_claim:
            first.apply_failure(first_claim, OSError(errno.EIO, "test cleanup"))
        if second._claimed.get(second_claim.claim_id) is second_claim:
            second.apply_failure(second_claim, OSError(errno.EIO, "test cleanup"))
        first.close_fd_for_test()
        second.close_fd_for_test()


@pytest.mark.asyncio
async def test_control_dependency_requires_exact_pending_identity_atomically(
    tmp_path: Path,
) -> None:
    target = allocate_part(tmp_path)
    target.append_accepted(*make_record(monotonic_ns=10))
    control = allocate_control_part(tmp_path)
    control_record, control_identity = make_control_record(
        control_event_id="gap:pending",
        monotonic_ns=20,
        acceptance_ordinal=7,
    )
    control.append_accepted(control_record, control_identity)
    wrong_identity = control_identity.model_copy(update={"acceptance_ordinal": 8})
    dependency = _FinalBarrierControlDependency(
        control_part=control,
        control_identity=wrong_identity,
        association=StorageControlAssociationV1(
            control_kind="gap_detected",
            control_event_id="gap:pending",
            targets=(
                StorageControlTargetV1(
                    generation_id=target.generation_id,
                    data_relative_path=target.data_relative_path,
                ),
            ),
            acceptance_ordinal=wrong_identity.acceptance_ordinal,
            config_generation=wrong_identity.config_generation,
        ),
        targets=(target,),
    )

    class NoCallCoordinator:
        called = False

        async def sync_batch(
            self,
            _work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            self.called = True
            raise AssertionError(f"unexpected sync call: {trigger}")

    coordinator = NoCallCoordinator()
    limiter = StorageIoLimiter(max_concurrency=1)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=asyncio.Queue(),
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(ValueError, match="owned claim"):
                await controller.close_group(
                    (target,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                    control_dependencies=(dependency,),
                )

        assert not coordinator.called
        assert target.close_reason is None
        assert len(target._pending_claims) == 1
        assert len(control._pending_claims) == 1
        assert not target._claimed
        assert not control._claimed
    finally:
        target.close_fd_for_test()
        control.close_fd_for_test()


@pytest.mark.asyncio
async def test_final_barrier_service_loop_is_sole_completion_consumer(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        coordinator = DurabilityCoordinator(
            clock=FixedClock(),
            sync_backend=PosixSyncBackend(),
            io_limiter=limiter,
            storage_executor=executor,
            durability_slo_ns=1_000_000_000,
            durability_critical_ns=5_000_000_000,
            completion_sink=file_completion_sink(completions),
        )
        controller = _FinalBarrierController(
            durability_coordinator=coordinator,
            completion_queue=completions,
            io_limiter=limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
        )
        waiter = asyncio.create_task(
            controller.close_group(
                (part,),
                reason=CloseReason.SHUTDOWN,
                closed_at_ns=_BASE_NS + 100,
            )
        )
        message = await asyncio.wait_for(completions.get(), timeout=2)
        try:
            assert type(message) is FileSyncCompleted
            assert part.durability_sample_count == 0
            assert controller.handle_message(message)
            assert part.durability_sample_count == 1
            assert not controller.handle_message(message)
        finally:
            completions.task_done()
        manifests = await drive_final_barrier_messages(
            controller,
            completions,
            waiter,
        )

    assert len(manifests) == 1
    assert part.closed_manifest_path.exists()


@pytest.mark.asyncio
async def test_malformed_file_completion_fails_barrier_without_hanging(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))
    completions: asyncio.Queue[object] = asyncio.Queue()

    class MalformedCompletionCoordinator:
        async def sync_batch(
            self,
            work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            malformed = FileDurabilityResult(
                generation_id=work_items[0].generation_id,
                was_dirty=False,
                record_count=0,
                sync_completed_monotonic_ns=_BASE_NS,
                sync_duration_ns=1,
                lag_p50_ns=None,
                lag_p95_ns=None,
                lag_p99_ns=None,
                lag_max_ns=None,
            )
            completions.put_nowait(FileSyncCompleted(malformed))
            return DurabilityBatch(
                batch_sequence=0,
                trigger=trigger,
                started_monotonic_ns=1,
                completed_monotonic_ns=2,
                files=(malformed,),
            )

    limiter = StorageIoLimiter(max_concurrency=1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        controller = _FinalBarrierController(
            durability_coordinator=MalformedCompletionCoordinator(),
            completion_queue=completions,
            io_limiter=limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
        )
        with pytest.raises(WriterCriticalError) as captured:
            await close_group_with_service_pump(
                controller,
                completions,
                (part,),
                reason=CloseReason.SHUTDOWN,
                closed_at_ns=_BASE_NS + 100,
            )

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert captured.value.affected_generation_ids == (part.generation_id,)
    assert part.stream_file.closed
    assert not part.closed_manifest_path.exists()
    assert not controller._commands
    assert not controller._command_by_generation


@pytest.mark.asyncio
async def test_batch_settlement_without_file_completion_fails_without_hanging(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))
    completions: asyncio.Queue[object] = asyncio.Queue()

    class MissingCompletionCoordinator:
        async def sync_batch(
            self,
            work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            result = make_result(
                work_items[0].generation_id,
                (10,),
                completed_monotonic_ns=20,
            )
            return DurabilityBatch(
                batch_sequence=0,
                trigger=trigger,
                started_monotonic_ns=1,
                completed_monotonic_ns=20,
                files=(result,),
            )

    limiter = StorageIoLimiter(max_concurrency=1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        controller = _FinalBarrierController(
            durability_coordinator=MissingCompletionCoordinator(),
            completion_queue=completions,
            io_limiter=limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
        )
        with pytest.raises(WriterCriticalError) as captured:
            await close_group_with_service_pump(
                controller,
                completions,
                (part,),
                reason=CloseReason.SHUTDOWN,
                closed_at_ns=_BASE_NS + 100,
            )

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert captured.value.affected_generation_ids == (part.generation_id,)
    assert part.stream_file.closed
    assert not part.closed_manifest_path.exists()
    assert not controller._commands
    assert not controller._command_by_generation


@pytest.mark.asyncio
async def test_pending_control_joins_target_final_barrier_and_folds_before_freeze(
    tmp_path: Path,
) -> None:
    target = allocate_part(tmp_path)
    target.append_accepted(*make_record(monotonic_ns=10))
    control = allocate_control_part(tmp_path)
    control_record, control_identity = make_control_record(
        control_event_id="gap:barrier",
        monotonic_ns=20,
        acceptance_ordinal=7,
        config_generation=0,
    )
    control.append_accepted(control_record, control_identity)
    association = StorageControlAssociationV1(
        control_kind="gap_detected",
        control_event_id="gap:barrier",
        targets=(
            StorageControlTargetV1(
                generation_id=target.generation_id,
                data_relative_path=target.data_relative_path,
            ),
        ),
        acceptance_ordinal=control_identity.acceptance_ordinal,
        config_generation=control_identity.config_generation,
    )
    dependency = _FinalBarrierControlDependency(
        control_part=control,
        control_identity=control_identity,
        association=association,
        targets=(target,),
    )
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=2)

    class RecordingCoordinator:
        def __init__(self, inner: DurabilityCoordinator) -> None:
            self.inner = inner
            self.calls: list[tuple[str, ...]] = []

        async def sync_batch(
            self,
            work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            self.calls.append(tuple(item.generation_id for item in work_items))
            return await self.inner.sync_batch(work_items, trigger=trigger)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            coordinator = RecordingCoordinator(
                DurabilityCoordinator(
                    clock=FixedClock(),
                    sync_backend=PosixSyncBackend(),
                    io_limiter=limiter,
                    storage_executor=executor,
                    durability_slo_ns=1_000_000_000,
                    durability_critical_ns=5_000_000_000,
                    completion_sink=file_completion_sink(completions),
                )
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            manifests = await close_group_with_service_pump(
                controller,
                completions,
                (target,),
                reason=CloseReason.SHUTDOWN,
                closed_at_ns=_BASE_NS + 100,
                control_dependencies=(dependency,),
            )

        assert coordinator.calls == [
            (target.generation_id, control.generation_id),
        ]
        assert manifests[0].control_event_ids == ("gap:barrier",)
        assert manifests[0].gap_count == 1
        assert control.durability_sample_count == 1
        assert control.close_reason is None
        assert control.partial_path.exists()
    finally:
        target.close_fd_for_test()
        control.close_fd_for_test()


@pytest.mark.asyncio
async def test_in_flight_associated_control_is_folded_before_target_final_batch(
    tmp_path: Path,
) -> None:
    target = allocate_part(tmp_path)
    target.append_accepted(*make_record(monotonic_ns=10))
    control = allocate_control_part(tmp_path)
    control_record, control_identity = make_control_record(
        control_event_id="gap:in-flight",
        monotonic_ns=20,
        acceptance_ordinal=7,
    )
    control.append_accepted(control_record, control_identity)
    dependency = make_control_dependency(
        control=control,
        control_identity=control_identity,
        target=target,
        control_event_id="gap:in-flight",
    )
    control_claim = control.seal_for_sync(force_sync=True)
    assert control_claim is not None
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)

    class RecordingCoordinator:
        def __init__(self, inner: DurabilityCoordinator) -> None:
            self.inner = inner
            self.calls: list[tuple[str, ...]] = []

        async def sync_batch(
            self,
            work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            self.calls.append(tuple(item.generation_id for item in work_items))
            return await self.inner.sync_batch(work_items, trigger=trigger)

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            inner = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=PosixSyncBackend(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            coordinator = RecordingCoordinator(inner)
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            prior_sync = asyncio.create_task(
                inner.sync_batch(
                    (control_claim.work,),
                    trigger=DurabilityTrigger.PERIODIC,
                )
            )
            control.bind_claim_batch_task(control_claim, prior_sync)
            close_waiter = asyncio.create_task(
                controller.close_group(
                    (target,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                    control_dependencies=(dependency,),
                )
            )
            await asyncio.sleep(0)
            assert not coordinator.calls
            assert not close_waiter.done()

            manifests = await drive_final_barrier_messages(
                controller,
                completions,
                close_waiter,
            )
            await prior_sync

        assert coordinator.calls == [(target.generation_id,)]
        assert manifests[0].control_event_ids == ("gap:in-flight",)
        assert manifests[0].gap_count == 1
        assert control.durability_sample_count == 1
        assert not controller._commands
        assert not controller._command_by_generation
    finally:
        if control._claimed.get(control_claim.claim_id) is control_claim:
            control.apply_failure(control_claim, OSError(errno.EIO, "test cleanup"))
        target.close_fd_for_test()
        control.close_fd_for_test()


@pytest.mark.asyncio
async def test_pending_associated_control_waits_behind_unrelated_in_flight_claim(
    tmp_path: Path,
) -> None:
    target = allocate_part(tmp_path)
    target.append_accepted(*make_record(monotonic_ns=10))
    control = allocate_control_part(tmp_path)
    old_record, old_identity = make_control_record(
        control_event_id="gap:older",
        monotonic_ns=20,
        writer_sequence=1,
        acceptance_ordinal=6,
    )
    control.append_accepted(old_record, old_identity)
    old_claim = control.seal_for_sync(force_sync=True)
    assert old_claim is not None
    associated_record, associated_identity = make_control_record(
        control_event_id="gap:queued",
        monotonic_ns=21,
        writer_sequence=2,
        acceptance_ordinal=7,
    )
    control.append_accepted(associated_record, associated_identity)
    dependency = make_control_dependency(
        control=control,
        control_identity=associated_identity,
        target=target,
        control_event_id="gap:queued",
    )
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)

    class RecordingCoordinator:
        def __init__(self, inner: DurabilityCoordinator) -> None:
            self.inner = inner
            self.calls: list[tuple[str, ...]] = []

        async def sync_batch(
            self,
            work_items: Sequence[SealedFileWork],
            *,
            trigger: DurabilityTrigger,
        ) -> DurabilityBatch:
            self.calls.append(tuple(item.generation_id for item in work_items))
            return await self.inner.sync_batch(work_items, trigger=trigger)

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            inner = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=PosixSyncBackend(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            coordinator = RecordingCoordinator(inner)
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            prior_sync = asyncio.create_task(
                inner.sync_batch(
                    (old_claim.work,),
                    trigger=DurabilityTrigger.PERIODIC,
                )
            )
            control.bind_claim_batch_task(old_claim, prior_sync)
            close_waiter = asyncio.create_task(
                controller.close_group(
                    (target,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                    control_dependencies=(dependency,),
                )
            )
            await asyncio.sleep(0)
            assert not coordinator.calls
            assert not close_waiter.done()

            manifests = await drive_final_barrier_messages(
                controller,
                completions,
                close_waiter,
            )
            await prior_sync

        assert coordinator.calls == [
            (target.generation_id, control.generation_id),
        ]
        assert manifests[0].control_event_ids == ("gap:queued",)
        assert manifests[0].gap_count == 1
        assert control.durability_sample_count == 2
        assert not controller._commands
        assert not controller._command_by_generation
    finally:
        if control._claimed.get(old_claim.claim_id) is old_claim:
            control.apply_failure(old_claim, OSError(errno.EIO, "test cleanup"))
        target.close_fd_for_test()
        control.close_fd_for_test()


@pytest.mark.asyncio
async def test_old_barrier_cleanup_preserves_reowned_control_generation(
    tmp_path: Path,
) -> None:
    target = allocate_part(tmp_path)
    target.append_accepted(*make_record(monotonic_ns=10))
    control = allocate_control_part(tmp_path)
    control_record, control_identity = make_control_record(
        control_event_id="gap:reuse",
        monotonic_ns=20,
        acceptance_ordinal=7,
    )
    control.append_accepted(control_record, control_identity)
    dependency = _FinalBarrierControlDependency(
        control_part=control,
        control_identity=control_identity,
        association=StorageControlAssociationV1(
            control_kind="gap_detected",
            control_event_id="gap:reuse",
            targets=(
                StorageControlTargetV1(
                    generation_id=target.generation_id,
                    data_relative_path=target.data_relative_path,
                ),
            ),
            acceptance_ordinal=control_identity.acceptance_ordinal,
            config_generation=control_identity.config_generation,
        ),
        targets=(target,),
    )
    publication_started = threading.Event()
    release_publication = threading.Event()

    def block_target_publication(
        source: Path,
        destination: Path,
        *,
        capability: NoReplaceCapability | None = None,
        expected_source_fd: int | None = None,
    ) -> None:
        if destination == target.closed_data_path:
            publication_started.set()
            assert release_publication.wait(timeout=2)
        publish_no_replace(
            source,
            destination,
            capability=capability,
            expected_source_fd=expected_source_fd,
        )

    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=2)
    replacement_command_id = "replacement-command"
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=PosixSyncBackend(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
                publication_function=block_target_publication,
            )
            close_waiter = asyncio.create_task(
                controller.close_group(
                    (target,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                    control_dependencies=(dependency,),
                )
            )
            service_pump = asyncio.create_task(
                drive_final_barrier_messages(
                    controller,
                    completions,
                    close_waiter,
                )
            )
            assert await asyncio.to_thread(publication_started.wait, 1)
            assert control.generation_id not in controller._command_by_generation
            controller._command_by_generation[control.generation_id] = (
                replacement_command_id
            )
            release_publication.set()
            manifests = await service_pump

        assert len(manifests) == 1
        assert controller._command_by_generation[control.generation_id] == (
            replacement_command_id
        )
        del controller._command_by_generation[control.generation_id]
    finally:
        release_publication.set()
        target.close_fd_for_test()
        control.close_fd_for_test()


@pytest.mark.asyncio
async def test_control_sync_failure_withholds_target_normal_manifest(
    tmp_path: Path,
) -> None:
    target = allocate_part(tmp_path)
    target.append_accepted(*make_record(monotonic_ns=10))
    control = allocate_control_part(tmp_path)
    control_record, control_identity = make_control_record(
        control_event_id="gap:failed",
        monotonic_ns=20,
        acceptance_ordinal=7,
        config_generation=0,
    )
    control.append_accepted(control_record, control_identity)
    dependency = _FinalBarrierControlDependency(
        control_part=control,
        control_identity=control_identity,
        association=StorageControlAssociationV1(
            control_kind="gap_detected",
            control_event_id="gap:failed",
            targets=(
                StorageControlTargetV1(
                    generation_id=target.generation_id,
                    data_relative_path=target.data_relative_path,
                ),
            ),
            acceptance_ordinal=control_identity.acceptance_ordinal,
            config_generation=control_identity.config_generation,
        ),
        targets=(target,),
    )
    control_fd = control.stream_file.fileno()

    class FailControlSync:
        def sync(self, fd: int) -> None:
            if fd == control_fd:
                raise OSError(errno.EIO, "injected control sync failure")
            os.fsync(fd)

    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=2)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=FailControlSync(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(WriterCriticalError) as captured:
                await close_group_with_service_pump(
                    controller,
                    completions,
                    (target,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                    control_dependencies=(dependency,),
                )

        assert captured.value.reason is WriterCriticalReason.CONTROL_DURABILITY_FAILED
        assert captured.value.affected_generation_ids == (control.generation_id,)
        assert not target.closed_data_path.exists()
        assert not target.closed_manifest_path.exists()
    finally:
        target.close_fd_for_test()
        control.close_fd_for_test()


@pytest.mark.asyncio
async def test_closing_control_sync_failure_has_control_critical_reason(
    tmp_path: Path,
) -> None:
    control = allocate_control_part(tmp_path)
    control.append_accepted(
        *make_control_record(
            control_event_id="shutdown:failed",
            monotonic_ns=20,
            acceptance_ordinal=7,
        )
    )

    class FailingSync:
        def sync(self, _fd: int) -> None:
            raise OSError(errno.EIO, "injected control sync failure")

    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=FailingSync(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(WriterCriticalError) as captured:
                await close_group_with_service_pump(
                    controller,
                    completions,
                    (control,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )

        assert captured.value.reason is WriterCriticalReason.CONTROL_DURABILITY_FAILED
        assert captured.value.affected_generation_ids == (control.generation_id,)
        assert control.stream_file.closed
        assert not control.closed_manifest_path.exists()
    finally:
        control.close_fd_for_test()


@pytest.mark.asyncio
async def test_failed_barrier_cleanup_preserves_original_control_reason(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    control = allocate_control_part(tmp_path)
    control.append_accepted(
        *make_control_record(
            control_event_id="shutdown:cleanup-failed",
            monotonic_ns=20,
            acceptance_ordinal=7,
        )
    )

    class FailingSync:
        def sync(self, _fd: int) -> None:
            raise OSError(errno.EIO, "injected control sync failure")

    real_close = raw_writer_module.StreamFile.close_fd

    def close_then_fail(stream_file: object) -> None:
        real_close(stream_file)
        raise OSError(errno.EIO, "injected descriptor cleanup failure")

    monkeypatch.setattr(raw_writer_module.StreamFile, "close_fd", close_then_fail)
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=FailingSync(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(WriterCriticalError) as captured:
                await close_group_with_service_pump(
                    controller,
                    completions,
                    (control,),
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )

        assert captured.value.reason is WriterCriticalReason.CONTROL_DURABILITY_FAILED
        assert captured.value.affected_generation_ids == (control.generation_id,)
        assert isinstance(captured.value.__cause__, OSError)
        assert "descriptor cleanup" in str(captured.value.__cause__)
        assert control.stream_file.closed
    finally:
        real_close(control.stream_file)


@pytest.mark.asyncio
async def test_final_barrier_preserves_each_pre_retired_close_timestamp(
    tmp_path: Path,
) -> None:
    parts = (
        allocate_part(tmp_path, part_sequence=0, generation_id="generation-0"),
        allocate_part(tmp_path, part_sequence=1, generation_id="generation-1"),
    )
    for index, part in enumerate(parts):
        part.append_accepted(
            *make_record(monotonic_ns=10 + index, writer_sequence=index)
        )
        part.retire(CloseReason.ROTATE_TIME, closed_at_ns=_BASE_NS + 10 + index)
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=2)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=PosixSyncBackend(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            manifests = await close_group_with_service_pump(
                controller,
                completions,
                parts,
                reason=CloseReason.ROTATE_TIME,
                closed_at_ns=_BASE_NS + 10,
            )

        assert tuple(item.closed_at_ns for item in manifests) == (
            _BASE_NS + 10,
            _BASE_NS + 11,
        )
    finally:
        for part in parts:
            part.close_fd_for_test()


@pytest.mark.asyncio
async def test_final_barrier_closes_data_then_publishes_canonical_manifest(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    record, identity = make_record(monotonic_ns=10)
    part.append_accepted(record, identity)
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        coordinator = DurabilityCoordinator(
            clock=FixedClock(),
            sync_backend=PosixSyncBackend(),
            io_limiter=limiter,
            storage_executor=executor,
            durability_slo_ns=1_000_000_000,
            durability_critical_ns=5_000_000_000,
            completion_sink=file_completion_sink(completions),
        )
        controller = _FinalBarrierController(
            durability_coordinator=coordinator,
            completion_queue=completions,
            io_limiter=limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
        )
        manifests = await close_group_with_service_pump(
            controller,
            completions,
            (part,),
            reason=CloseReason.SHUTDOWN,
            closed_at_ns=_BASE_NS + 100,
        )

    assert len(manifests) == 1
    manifest = manifests[0]
    assert manifest.close_reason is CloseReason.SHUTDOWN
    assert part.closed_data_path.exists()
    assert part.closed_manifest_path.exists()
    assert not part.partial_path.exists()
    assert load_raw_manifest(part.closed_manifest_path).manifest == manifest
    with part.closed_data_path.open("rb") as source:
        plain = zstandard.ZstdDecompressor().stream_reader(source).read()
    assert plain == record.encoded_jsonl


@pytest.mark.asyncio
async def test_final_barrier_rejects_partial_inode_replacement_before_close(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))
    displaced = part.partial_path.with_name(part.partial_path.name + ".displaced")
    real_open_readonly = raw_writer_module.open_readonly_nofollow
    replaced = False

    def replace_before_open(path: Path) -> int:
        nonlocal replaced
        if path == part.partial_path and not replaced:
            replaced = True
            os.replace(path, displaced)
            path.write_bytes(b"replacement bytes")
        return real_open_readonly(path)

    monkeypatch.setattr(
        raw_writer_module,
        "open_readonly_nofollow",
        replace_before_open,
    )
    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        coordinator = DurabilityCoordinator(
            clock=FixedClock(),
            sync_backend=PosixSyncBackend(),
            io_limiter=limiter,
            storage_executor=executor,
            durability_slo_ns=1_000_000_000,
            durability_critical_ns=5_000_000_000,
            completion_sink=file_completion_sink(completions),
        )
        controller = _FinalBarrierController(
            durability_coordinator=coordinator,
            completion_queue=completions,
            io_limiter=limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
        )
        with pytest.raises(WriterCriticalError) as captured:
            await close_group_with_service_pump(
                controller,
                completions,
                (part,),
                reason=CloseReason.SHUTDOWN,
                closed_at_ns=_BASE_NS + 100,
            )

    assert captured.value.reason is WriterCriticalReason.PUBLICATION_FAILED
    assert displaced.exists()
    assert not part.closed_manifest_path.exists()


@pytest.mark.asyncio
async def test_final_barrier_rejects_manifest_temp_inode_replacement(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))
    displaced = part.manifest_partial_path.with_name(
        part.manifest_partial_path.name + ".displaced"
    )

    def replace_manifest_temp(
        source: Path,
        destination: Path,
        *,
        capability: NoReplaceCapability | None = None,
        expected_source_fd: int | None = None,
    ) -> None:
        if source == part.manifest_partial_path:
            os.replace(source, displaced)
            source.write_bytes(b'{"forged":true}\n')
        if expected_source_fd is None:
            publish_no_replace(source, destination, capability=capability)
        else:
            publish_no_replace(
                source,
                destination,
                capability=capability,
                expected_source_fd=expected_source_fd,
            )

    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        coordinator = DurabilityCoordinator(
            clock=FixedClock(),
            sync_backend=PosixSyncBackend(),
            io_limiter=limiter,
            storage_executor=executor,
            durability_slo_ns=1_000_000_000,
            durability_critical_ns=5_000_000_000,
            completion_sink=file_completion_sink(completions),
        )
        controller = _FinalBarrierController(
            durability_coordinator=coordinator,
            completion_queue=completions,
            io_limiter=limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
            publication_function=replace_manifest_temp,
        )
        with pytest.raises(WriterCriticalError) as captured:
            await close_group_with_service_pump(
                controller,
                completions,
                (part,),
                reason=CloseReason.SHUTDOWN,
                closed_at_ns=_BASE_NS + 100,
            )

    assert captured.value.reason is WriterCriticalReason.PUBLICATION_FAILED
    assert displaced.exists()
    assert not part.closed_manifest_path.exists()


@pytest.mark.asyncio
async def test_final_sync_failure_withholds_every_group_manifest(
    tmp_path: Path,
) -> None:
    parts = tuple(
        allocate_part(
            tmp_path,
            part_sequence=index,
            generation_id=f"generation-{index}",
        )
        for index in range(3)
    )
    for index, part in enumerate(parts):
        part.append_accepted(
            *make_record(monotonic_ns=10 + index, writer_sequence=index)
        )

    class FailingSync:
        def sync(self, _fd: int) -> None:
            raise OSError(errno.EIO, "injected final sync failure")

    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=2)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=FailingSync(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
            )
            with pytest.raises(WriterCriticalError) as captured:
                await close_group_with_service_pump(
                    controller,
                    completions,
                    parts,
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )

        assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
        assert not any(part.closed_manifest_path.exists() for part in parts)
        assert all(part.partial_path.exists() for part in parts)
        assert all(part.stream_file.closed for part in parts)
    finally:
        for part in parts:
            part.close_fd_for_test()


@pytest.mark.asyncio
async def test_later_publication_failure_preserves_prefix_and_affected_suffix(
    tmp_path: Path,
) -> None:
    parts = tuple(
        allocate_part(
            tmp_path,
            part_sequence=index,
            generation_id=f"generation-{index}",
        )
        for index in range(3)
    )
    for index, part in enumerate(parts):
        part.append_accepted(
            *make_record(monotonic_ns=10 + index, writer_sequence=index)
        )

    def fail_second_data(
        source: Path,
        destination: Path,
        *,
        capability: NoReplaceCapability | None = None,
        expected_source_fd: int | None = None,
    ) -> None:
        if destination == parts[1].closed_data_path:
            raise OSError(errno.EIO, "injected publication failure")
        publish_no_replace(
            source,
            destination,
            capability=capability,
            expected_source_fd=expected_source_fd,
        )

    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=2)
    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            coordinator = DurabilityCoordinator(
                clock=FixedClock(),
                sync_backend=PosixSyncBackend(),
                io_limiter=limiter,
                storage_executor=executor,
                durability_slo_ns=1_000_000_000,
                durability_critical_ns=5_000_000_000,
                completion_sink=file_completion_sink(completions),
            )
            controller = _FinalBarrierController(
                durability_coordinator=coordinator,
                completion_queue=completions,
                io_limiter=limiter,
                storage_executor=executor,
                no_replace_capability=NoReplaceCapability.HARDLINK,
                publication_function=fail_second_data,
            )
            with pytest.raises(WriterCriticalError) as captured:
                await close_group_with_service_pump(
                    controller,
                    completions,
                    parts,
                    reason=CloseReason.SHUTDOWN,
                    closed_at_ns=_BASE_NS + 100,
                )

        assert captured.value.reason is WriterCriticalReason.PUBLICATION_FAILED
        assert captured.value.affected_generation_ids == (
            parts[1].generation_id,
            parts[2].generation_id,
        )
        assert parts[0].closed_data_path.exists()
        assert parts[0].closed_manifest_path.exists()
        assert parts[1].partial_path.exists()
        assert not parts[1].closed_manifest_path.exists()
        assert parts[2].partial_path.exists()
        assert not parts[2].closed_data_path.exists()
        assert all(part.stream_file.closed for part in parts)
    finally:
        for part in parts:
            part.close_fd_for_test()


@pytest.mark.asyncio
async def test_final_barrier_waiter_cancellation_does_not_cancel_owned_work(
    tmp_path: Path,
) -> None:
    part = allocate_part(tmp_path)
    part.append_accepted(*make_record(monotonic_ns=10))
    started = threading.Event()
    release = threading.Event()

    class BlockingSync:
        def sync(self, _fd: int) -> None:
            started.set()
            assert release.wait(timeout=2)

    completions: asyncio.Queue[object] = asyncio.Queue()
    limiter = StorageIoLimiter(max_concurrency=1)
    with ThreadPoolExecutor(max_workers=1) as executor:
        coordinator = DurabilityCoordinator(
            clock=FixedClock(),
            sync_backend=BlockingSync(),
            io_limiter=limiter,
            storage_executor=executor,
            durability_slo_ns=1_000_000_000,
            durability_critical_ns=5_000_000_000,
            completion_sink=file_completion_sink(completions),
        )
        controller = _FinalBarrierController(
            durability_coordinator=coordinator,
            completion_queue=completions,
            io_limiter=limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
        )
        waiter = asyncio.create_task(
            controller.close_group(
                (part,),
                reason=CloseReason.SHUTDOWN,
                closed_at_ns=_BASE_NS + 100,
            )
        )
        assert await asyncio.to_thread(started.wait, 1)
        waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await waiter
        assert not part.closed_manifest_path.exists()
        detached_waiter = asyncio.create_task(controller.wait_for_detached())
        await asyncio.sleep(0)
        detached_waiter.cancel()
        with pytest.raises(asyncio.CancelledError):
            await detached_waiter
        release.set()
        terminal_waiter = asyncio.create_task(controller.wait_for_detached())
        outcomes = await drive_final_barrier_messages(
            controller,
            completions,
            terminal_waiter,
        )

    assert len(outcomes) == 1
    assert not isinstance(outcomes[0], BaseException)
    assert part.closed_data_path.exists()
    assert part.closed_manifest_path.exists()
