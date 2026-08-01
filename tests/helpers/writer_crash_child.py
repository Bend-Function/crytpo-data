from __future__ import annotations

import argparse
import asyncio
import base64
import errno
import fcntl
import hashlib
import json
import os
import signal
import stat
from pathlib import Path

import zstandard

from crypto_collector.config.models import IngressConfig, WriterConfig
from crypto_collector.domain.envelope import (
    NativeEventDraft,
    RawEnvelope,
    SourceContext,
)
from crypto_collector.domain.types import CloseReason, Exchange, Market, Transport
from crypto_collector.storage.durability import (
    WriterCriticalError,
    WriterCriticalReason,
)
from crypto_collector.storage.manifest import load_raw_manifest
from crypto_collector.storage.raw_writer import (
    NoReplaceCapability,
    publish_no_replace,
)
from crypto_collector.storage.recovery import (
    RecoveryControlOwnershipV1,
    load_recovery_chain,
)
from crypto_collector.storage.serialize import decode_envelope_jsonl, encode_envelope
from crypto_collector.storage.service import RawWriterService

_DARWIN_F_GETPATH = 50
from crypto_collector.storage.stream_file import StreamFile

_PART_RELATIVE_PATH = Path(
    "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/"
    "part-1785456000000000000-0.jsonl.zst.partial"
)


class _Clock:
    def __init__(self) -> None:
        self._wall_ns = 1_785_456_000_000_000_000
        self._monotonic_ns = 1_000_000

    def time_ns(self) -> int:
        self._wall_ns += 1
        return self._wall_ns

    def monotonic_ns(self) -> int:
        self._monotonic_ns += 1
        return self._monotonic_ns


class _PipePhaseHalt:
    def __init__(self, *, target: str, pipe_fd: int) -> None:
        self._target = target
        self._pipe_fd = pipe_fd

    def __call__(self, phase: str) -> None:
        if phase != self._target:
            return
        os.write(self._pipe_fd, f"{phase}\n".encode("ascii"))
        while True:
            signal.pause()


class _NeverSleeper:
    async def sleep_ns(self, _delay_ns: int) -> None:
        await asyncio.Future()


class _IoFailureHook:
    def __init__(self, *, target: str, error_number: int) -> None:
        self.target = target
        self.error_number = error_number
        self.triggered = False
        self.trace: list[str] = []
        self._original_data_sync = getattr(os, "fdatasync", os.fsync)
        self._original_fsync = os.fsync
        self._original_write = os.write

    def __call__(self, phase: str) -> None:
        self.trace.append(phase)

    def _fail(self) -> None:
        self.trace.append(f"attempt:{self.target}")
        self.triggered = True
        raise OSError(self.error_number, f"injected {self.target} failure")

    @staticmethod
    def _fd_path(fd: int) -> Path | None:
        try:
            return Path(os.readlink(f"/proc/self/fd/{fd}"))
        except OSError:
            pass
        try:
            raw_path = fcntl.fcntl(fd, _DARWIN_F_GETPATH, bytes(1024))
        except OSError:
            return None
        if type(raw_path) is not bytes:
            return None
        encoded = raw_path.split(b"\0", 1)[0]
        return None if not encoded else Path(os.fsdecode(encoded))

    @staticmethod
    def _directory_has_coexistence(fd: int, *, suffix: str) -> bool:
        if not stat.S_ISDIR(os.fstat(fd).st_mode):
            return False
        names = frozenset(os.listdir(fd))
        return any(
            name.endswith(suffix + ".partial")
            and name.removesuffix(".partial") in names
            for name in names
        )

    def _write(
        self,
        fd: int,
        data: bytes | bytearray | memoryview,
    ) -> int:
        path = self._fd_path(fd)
        if path is not None and (
            (self.target == "frame_write" and path.name.endswith(".jsonl.zst.partial"))
            or (
                self.target == "manifest_temp_write"
                and path.name.endswith(".manifest.json.partial")
            )
        ):
            self._fail()
        return self._original_write(fd, data)

    def _fsync(self, fd: int) -> None:
        path = self._fd_path(fd)
        if (
            self.target == "manifest_temp_sync"
            and path is not None
            and path.name.endswith(".manifest.json.partial")
        ):
            self._fail()
        if self.target == "data_directory_sync" and self._directory_has_coexistence(
            fd,
            suffix=".jsonl.zst",
        ):
            self._fail()
        if (
            self.target == "manifest_directory_fsync"
            and self._directory_has_coexistence(fd, suffix=".manifest.json")
        ):
            self._fail()
        self._original_fsync(fd)

    def _data_sync(self, fd: int) -> None:
        path = self._fd_path(fd)
        if path is not None and path.name.endswith(".jsonl.zst.partial"):
            self._fail()
        self._original_data_sync(fd)

    def install(self) -> None:
        if self.target in {"frame_write", "manifest_temp_write"}:
            os.write = self._write
        if self.target in {
            "data_directory_sync",
            "manifest_temp_sync",
            "manifest_directory_fsync",
        }:
            os.fsync = self._fsync
        if self.target == "data_sync":
            if hasattr(os, "fdatasync"):
                os.fdatasync = self._data_sync
            else:
                os.fsync = self._data_sync


def _allocation(root: Path, *, phase: str, pipe_fd: int) -> None:
    partial_path = root / "data" / _PART_RELATIVE_PATH
    StreamFile.allocate(
        partial_path,
        zstd_level=3,
        max_plain_frame_bytes=1024,
        generation_id="allocation-crash-generation",
        phase_hook=_PipePhaseHalt(target=phase, pipe_fd=pipe_fd),
    )
    raise RuntimeError("allocation crash phase was not reached")


def _owned_prefix(
    root: Path,
    *,
    fraction: float,
    phase: str,
    pipe_fd: int,
) -> None:
    exchange_root = root / "state/raw-recovery/okx"
    transaction_root = next(path for path in exchange_root.iterdir() if path.is_dir())
    chain = load_recovery_chain(transaction_root)
    ownership = chain[3]
    if type(ownership) is not RecoveryControlOwnershipV1:
        raise RuntimeError("owned prefix seed requires control ownership")
    frame = base64.b64decode(ownership.control_frame_base64, validate=True)
    prefix_size = int(len(frame) * fraction)
    partial = root / "data" / f"{ownership.control_data_relative_path}.partial"
    fd = os.open(partial, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
    try:
        view = memoryview(frame[:prefix_size])
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("owned prefix write made no progress")
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    _PipePhaseHalt(target=phase, pipe_fd=pipe_fd)(phase)


def _seed_recovery_partial(
    root: Path,
    *,
    add_bad_tail: bool = False,
    close_as_orphan: bool = False,
) -> None:
    draft = _trade_draft()
    envelope = RawEnvelope(
        **draft.model_dump(mode="python"),
        received_at_ns=1_785_456_000_000_000_000,
        monotonic_ns=1_000_000,
        worker_instance_id="recovery-seed-worker",
        connection_id="recovery-seed-connection",
        connection_generation=1,
        writer_sequence=0,
        egress_id="direct",
        config_sha256="a" * 64,
    )
    stream = StreamFile.allocate(
        root / "data" / _PART_RELATIVE_PATH,
        zstd_level=3,
        max_plain_frame_bytes=1024,
        generation_id="recovery-seed-generation",
    )
    stream.append(encode_envelope(envelope), accepted_monotonic_ns=1_000_000)
    pending = stream.take_pending()
    assert pending is not None
    stream.write_frame(pending)
    os.fsync(stream.fileno())
    stream.close_fd()
    partial = root / "data" / _PART_RELATIVE_PATH
    if add_bad_tail:
        fd = os.open(partial, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(fd, b"truncated-recovery-tail")
            os.fsync(fd)
        finally:
            os.close(fd)
    if close_as_orphan:
        final = partial.with_name(partial.name.removesuffix(".partial"))
        os.rename(partial, final)
        parent_fd = os.open(final.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)


def _trade_draft(*, instrument_key: str = "BTC-USDT") -> NativeEventDraft:
    return NativeEventDraft.model_validate(
        {
            "exchange": Exchange.OKX,
            "market": Market.SPOT,
            "instrument_key": instrument_key,
            "logical_stream": "trade",
            "wire_symbol": instrument_key,
            "native_channel": "trades",
            "transport": Transport.WEBSOCKET,
            "event_time_ns": 1_785_456_000_000_000_000,
            "event_time_source": "exchange",
            "payload": {"price": "100", "quantity": "1"},
        }
    )


async def _writer_close(root: Path, *, phase: str, pipe_fd: int) -> None:
    clock = _Clock()
    service = await RawWriterService.open(
        data_root=root / "data",
        state_root=root / "state",
        exchange=Exchange.OKX,
        worker_instance_id="writer-crash-worker",
        config_sha256="a" * 64,
        config_generation=0,
        writer_config=WriterConfig.model_validate({}),
        ingress_config=IngressConfig.model_validate({}),
        metric_stream_allowlist=("_control", "trade"),
        clock=clock,
        sleeper=_NeverSleeper(),
        phase_hook=_PipePhaseHalt(target=phase, pipe_fd=pipe_fd),
    )
    accepted = service.try_accept(
        _trade_draft(),
        source=SourceContext(
            connection_id="writer-crash-connection",
            connection_generation=1,
            egress_id="direct",
        ),
        shard="trade-0",
    )
    if not accepted.accepted:
        raise RuntimeError("writer crash child did not accept its trade")
    await service.close_all(CloseReason.SHUTDOWN, deadline_ns=10**18)
    raise RuntimeError("writer close crash phase was not reached")


async def _group_publication_failure(root: Path) -> None:
    clock = _Clock()
    service = await RawWriterService.open(
        data_root=root / "data",
        state_root=root / "state",
        exchange=Exchange.OKX,
        worker_instance_id="group-failure-worker",
        config_sha256="a" * 64,
        config_generation=0,
        writer_config=WriterConfig.model_validate({}),
        ingress_config=IngressConfig.model_validate({}),
        metric_stream_allowlist=("_control", "trade"),
        clock=clock,
        sleeper=_NeverSleeper(),
    )
    publication_count = 0

    def fail_second_data(
        source: Path,
        destination: Path,
        *,
        capability: NoReplaceCapability | None = None,
        expected_source_fd: int | None = None,
    ) -> None:
        nonlocal publication_count
        if destination.name.endswith(".jsonl.zst"):
            publication_count += 1
            if publication_count == 2:
                raise OSError(errno.EIO, "injected group publication failure")
        publish_no_replace(
            source,
            destination,
            capability=capability,
            expected_source_fd=expected_source_fd,
        )

    service._barrier._publication_function = fail_second_data
    for instrument in ("BTC-USDT", "ETH-USDT", "SOL-USDT"):
        accepted = service.try_accept(
            _trade_draft(instrument_key=instrument),
            source=SourceContext(
                connection_id="group-failure-connection",
                connection_generation=1,
                egress_id="direct",
            ),
            shard=f"{instrument}-trade",
        )
        if not accepted.accepted:
            raise RuntimeError("group failure child did not accept its trade")
    try:
        await service.close_all(CloseReason.SHUTDOWN, deadline_ns=10**18)
    except WriterCriticalError as error:
        if error.reason is not WriterCriticalReason.PUBLICATION_FAILED:
            raise
    else:
        raise RuntimeError("group publication failure was not injected")

    status = service.status()
    metrics = service.metrics_snapshot()
    manifests = sorted((root / "data").rglob("*.manifest.json"))
    if len(manifests) != 1:
        raise RuntimeError("group failure must publish exactly one prefix manifest")
    first_manifest = load_raw_manifest(manifests[0])
    sources = sorted(
        path.relative_to(root / "data").as_posix()
        for path in (root / "data").rglob("*.jsonl.zst*")
        if not path.name.endswith(".manifest.json")
    )
    print(
        json.dumps(
            {
                "first_manifest_relative_path": manifests[0]
                .relative_to(root / "data")
                .as_posix(),
                "first_manifest_sha256": first_manifest.sha256,
                "durability_sample_count": metrics.durability_sample_count,
                "durable_record_count": status.durable_record_count,
                "source_relative_paths": sources,
                "uncertain_record_count": status.uncertain_record_count,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


async def _io_failure(root: Path, *, phase: str, error_number: int) -> None:
    clock = _Clock()
    hook = _IoFailureHook(target=phase, error_number=error_number)
    service = await RawWriterService.open(
        data_root=root / "data",
        state_root=root / "state",
        exchange=Exchange.OKX,
        worker_instance_id="io-failure-worker",
        config_sha256="a" * 64,
        config_generation=0,
        writer_config=WriterConfig.model_validate({}),
        ingress_config=IngressConfig.model_validate({}),
        metric_stream_allowlist=("_control", "trade"),
        clock=clock,
        sleeper=_NeverSleeper(),
        phase_hook=hook,
    )
    hook.install()

    accepted = service.try_accept(
        _trade_draft(),
        source=SourceContext(
            connection_id="io-failure-connection",
            connection_generation=1,
            egress_id="direct",
        ),
        shard="trade-0",
    )
    if not accepted.accepted:
        raise RuntimeError("I/O failure child did not accept its trade")
    try:
        await service.close_all(CloseReason.SHUTDOWN, deadline_ns=10**18)
    except WriterCriticalError as error:
        critical = error
    else:
        raise RuntimeError(
            "configured I/O failure was not injected: "
            f"trace={hook.trace!r}, status={service.status()!r}"
        )
    if not hook.triggered:
        raise RuntimeError(
            "configured I/O failure phase was not reached: "
            f"critical={critical!r}, trace={hook.trace!r}"
        )
    status = service.status()
    print(
        json.dumps(
            {
                "critical_reason": critical.reason.value,
                "durable_record_count": status.durable_record_count,
                "incomplete": status.incomplete,
                "incomplete_reason": status.incomplete_reason,
                "last_attempted_phase": phase,
                "lifecycle": status.lifecycle.value,
                "normal_manifest_paths": sorted(
                    path.relative_to(root / "data").as_posix()
                    for path in (root / "data").rglob("*.manifest.json")
                ),
                "trace": hook.trace,
                "uncertain_record_count": status.uncertain_record_count,
            },
            sort_keys=True,
            separators=(",", ":"),
        ),
        flush=True,
    )


async def _recovery_edge(root: Path, *, phase: str, pipe_fd: int) -> None:
    _seed_recovery_partial(
        root,
        add_bad_tail=phase.startswith("quarantine_"),
        close_as_orphan=phase == "retained_data_parent_fsync",
    )
    clock = _Clock()
    await RawWriterService.open(
        data_root=root / "data",
        state_root=root / "state",
        exchange=Exchange.OKX,
        worker_instance_id="recovery-edge-worker",
        config_sha256="a" * 64,
        config_generation=0,
        writer_config=WriterConfig.model_validate({}),
        ingress_config=IngressConfig.model_validate({}),
        metric_stream_allowlist=("_control", "trade"),
        clock=clock,
        sleeper=_NeverSleeper(),
        phase_hook=_PipePhaseHalt(target=phase, pipe_fd=pipe_fd),
    )
    raise RuntimeError("recovery crash phase was not reached")


async def _replay_edge(root: Path, *, phase: str, pipe_fd: int) -> None:
    clock = _Clock()
    await RawWriterService.open(
        data_root=root / "data",
        state_root=root / "state",
        exchange=Exchange.OKX,
        worker_instance_id="recovery-replay-worker",
        config_sha256="a" * 64,
        config_generation=0,
        writer_config=WriterConfig.model_validate({}),
        ingress_config=IngressConfig.model_validate({}),
        metric_stream_allowlist=("_control", "trade"),
        clock=clock,
        sleeper=_NeverSleeper(),
        phase_hook=_PipePhaseHalt(target=phase, pipe_fd=pipe_fd),
    )
    raise RuntimeError("recovery replay crash phase was not reached")


async def _recover(root: Path) -> None:
    clock = _Clock()
    service = await RawWriterService.open(
        data_root=root / "data",
        state_root=root / "state",
        exchange=Exchange.OKX,
        worker_instance_id="crash-recovery-worker",
        config_sha256="a" * 64,
        config_generation=0,
        writer_config=WriterConfig.model_validate({}),
        ingress_config=IngressConfig.model_validate({}),
        metric_stream_allowlist=("_control", "trade"),
        clock=clock,
    )
    outcomes = tuple(service._completed_recovery_outcomes)
    await service.close_all(CloseReason.SHUTDOWN, deadline_ns=10**18)
    exchange_root = root / "state/raw-recovery/okx"
    transaction_ids = tuple(
        sorted(path.name for path in exchange_root.iterdir() if path.is_dir())
    )
    fact_chains = []
    for transaction_id in transaction_ids:
        chain = load_recovery_chain(exchange_root / transaction_id)
        fact_chains.append(
            {
                "transaction_id": transaction_id,
                "source_relative_path": chain[0].source_relative_path,
                "facts": [
                    {
                        "kind": fact.fact_kind,
                        "sha256": fact.fact_sha256,
                        "predecessor_sha256": fact.predecessor_sha256,
                    }
                    for fact in chain
                ],
            }
        )
    manifests = []
    for path in sorted((root / "data").rglob("*.manifest.json")):
        loaded = load_raw_manifest(path)
        manifest = loaded.manifest
        data_path = root / "data" / manifest.data_relative_path
        manifests.append(
            {
                "logical_stream": manifest.logical_stream,
                "record_count": manifest.record_count,
                "data_relative_path": manifest.data_relative_path,
                "manifest_relative_path": path.relative_to(root / "data").as_posix(),
                "manifest_sha256": loaded.sha256,
                "close_reason": manifest.close_reason.value,
                "recovery_transaction_id": manifest.recovery_transaction_id,
                "recovery_source_state": (
                    None
                    if manifest.recovery_source_state is None
                    else manifest.recovery_source_state.value
                ),
                "data_size_bytes": data_path.stat().st_size,
                "data_sha256": hashlib.sha256(data_path.read_bytes()).hexdigest(),
                "manifest_file_size_bytes": manifest.file_size_bytes,
                "manifest_file_sha256": manifest.file_sha256,
            }
        )
    closed_data = []
    for path in sorted((root / "data").rglob("*.jsonl.zst")):
        with path.open("rb") as source:
            plain = zstandard.ZstdDecompressor().stream_reader(source).read()
        envelopes = [
            decode_envelope_jsonl(line)
            for line in plain.splitlines(keepends=True)
            if line
        ]
        closed_data.append(
            {
                "relative_path": path.relative_to(root / "data").as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "envelopes": [
                    {
                        "exchange": envelope.exchange.value,
                        "instrument_key": envelope.instrument_key,
                        "logical_stream": envelope.logical_stream,
                        "writer_sequence": envelope.writer_sequence,
                        "payload": envelope.payload,
                    }
                    for envelope in envelopes
                ],
            }
        )
    quarantine = (
        [
            {
                "relative_path": path.relative_to(root / "data").as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in sorted((root / "data/quarantine").rglob("*"))
            if path.is_file()
        ]
        if (root / "data/quarantine").exists()
        else []
    )
    report = {
        "closed_data": closed_data,
        "fact_chains": fact_chains,
        "outcomes": [
            {
                "transaction_id": outcome.transaction_id,
                "source_relative_path": outcome.source_relative_path,
                "source_disposition": outcome.source_disposition.value,
                "source_sha256": outcome.source_sha256,
                "recovered_relative_path": outcome.recovered_relative_path,
                "quarantined_relative_path": outcome.quarantined_relative_path,
            }
            for outcome in outcomes
        ],
        "manifests": manifests,
        "partial_paths": tuple(
            sorted(
                path.relative_to(root / "data").as_posix()
                for path in (root / "data").rglob("*.partial")
            )
        ),
        "recovery_temporary_paths": tuple(
            sorted(
                path.relative_to(root / "data").as_posix()
                for path in (root / "data").rglob(".*.tmp-*")
            )
        ),
        "transaction_ids": transaction_ids,
        "quarantine": quarantine,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "mode",
        choices=(
            "allocation",
            "writer-close",
            "recovery-edge",
            "replay-edge",
            "owned-prefix",
            "group-failure",
            "io-error",
            "recover",
        ),
    )
    parser.add_argument("root", type=Path)
    parser.add_argument("--phase")
    parser.add_argument("--pipe-fd", type=int)
    parser.add_argument("--fraction", type=float)
    parser.add_argument("--errno", type=int)
    args = parser.parse_args()
    root = args.root.resolve()
    if args.mode == "allocation":
        if args.phase is None or args.pipe_fd is None:
            parser.error("allocation requires --phase and --pipe-fd")
        _allocation(root, phase=args.phase, pipe_fd=args.pipe_fd)
        return
    if args.mode == "writer-close":
        if args.phase is None or args.pipe_fd is None:
            parser.error("writer-close requires --phase and --pipe-fd")
        asyncio.run(_writer_close(root, phase=args.phase, pipe_fd=args.pipe_fd))
        return
    if args.mode == "recovery-edge":
        if args.phase is None or args.pipe_fd is None:
            parser.error("recovery-edge requires --phase and --pipe-fd")
        asyncio.run(_recovery_edge(root, phase=args.phase, pipe_fd=args.pipe_fd))
        return
    if args.mode == "replay-edge":
        if args.phase is None or args.pipe_fd is None:
            parser.error("replay-edge requires --phase and --pipe-fd")
        asyncio.run(_replay_edge(root, phase=args.phase, pipe_fd=args.pipe_fd))
        return
    if args.mode == "owned-prefix":
        if args.phase is None or args.pipe_fd is None or args.fraction is None:
            parser.error("owned-prefix requires --phase, --pipe-fd, and --fraction")
        if args.fraction not in {0.0, 0.5, 1.0}:
            parser.error("owned-prefix fraction must be 0, 0.5, or 1")
        _owned_prefix(
            root,
            fraction=args.fraction,
            phase=args.phase,
            pipe_fd=args.pipe_fd,
        )
        return
    if args.mode == "group-failure":
        asyncio.run(_group_publication_failure(root))
        return
    if args.mode == "io-error":
        if args.phase is None or args.errno not in {errno.ENOSPC, errno.EIO}:
            parser.error("io-error requires --phase and --errno ENOSPC/EIO")
        asyncio.run(_io_failure(root, phase=args.phase, error_number=args.errno))
        return
    asyncio.run(_recover(root))


if __name__ == "__main__":
    main()
