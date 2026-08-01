from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import signal
from pathlib import Path

import zstandard

from crypto_collector.config.models import IngressConfig, WriterConfig
from crypto_collector.domain.envelope import NativeEventDraft, SourceContext
from crypto_collector.domain.types import CloseReason, Exchange, Market, Transport
from crypto_collector.storage.manifest import load_raw_manifest
from crypto_collector.storage.serialize import decode_envelope_jsonl
from crypto_collector.storage.service import RawWriterService
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


def _trade_draft() -> NativeEventDraft:
    return NativeEventDraft.model_validate(
        {
            "exchange": Exchange.OKX,
            "market": Market.SPOT,
            "instrument_key": "BTC-USDT",
            "logical_stream": "trade",
            "wire_symbol": "BTC-USDT",
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
        "transaction_ids": transaction_ids,
        "quarantine": quarantine,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("allocation", "writer-close", "recover"))
    parser.add_argument("root", type=Path)
    parser.add_argument("--phase")
    parser.add_argument("--pipe-fd", type=int)
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
    asyncio.run(_recover(root))


if __name__ == "__main__":
    main()
