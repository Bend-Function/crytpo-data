from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
import zstandard

from crypto_collector.config.models import IngressConfig, WriterConfig
from crypto_collector.domain import (
    CloseReason,
    Exchange,
    Market,
    NativeEventDraft,
    SourceContext,
    Transport,
)
from crypto_collector.domain.clock import SystemClock
from crypto_collector.exchanges import (
    AdapterPlan,
    CollectionRequest,
    StreamExpectation,
    WebSocketSubscription,
)
from crypto_collector.runtime.state import WorkerState
from crypto_collector.runtime.worker import ExchangeWorker
from crypto_collector.scheduler import IntervalPlan
from crypto_collector.storage import EnqueueStatus, RawManifestV1, RawWriterService
from crypto_collector.storage.serialize import decode_envelope_jsonl

FIXTURE = Path(__file__).parents[2] / "fixtures/exchanges/scripted/session.jsonl"


class ScriptedAdapter:
    exchange = Exchange.OKX

    def __init__(self) -> None:
        self.complete = False
        self.closed_generations: set[int] = set()

    def plan(self, request: CollectionRequest) -> AdapterPlan:
        del request
        return AdapterPlan(
            exchange=Exchange.OKX,
            ws=(
                WebSocketSubscription(
                    id="okx:spot:btc:trades",
                    market=Market.SPOT,
                    instrument_key="BTC-USDT",
                    wire_symbol="BTC-USDT",
                    channel="trades",
                    endpoint="wss://ws.okx.test/ws/v5/public",
                    egress_id="direct-primary",
                    shard_id="spot-0",
                    logical_stream="trade",
                ),
            ),
            rest=(),
            expectations=(
                StreamExpectation(
                    market=None,
                    instrument_key=None,
                    logical_stream="_control",
                    shard_id="_control",
                ),
                StreamExpectation(
                    market=Market.SPOT,
                    instrument_key="BTC-USDT",
                    logical_stream="trade",
                    shard_id="spot-0",
                ),
            ),
            disabled_optional_features=(),
        )

    async def run(self, plan: AdapterPlan, runtime: Any, sink: Any) -> None:
        del plan
        source = SourceContext(
            connection_id="scripted-ws",
            connection_generation=1,
            egress_id="direct-primary",
        )
        for raw_line in FIXTURE.read_text(encoding="utf-8").splitlines():
            row = json.loads(raw_line)
            result = sink.try_emit(
                NativeEventDraft(
                    exchange=Exchange.OKX,
                    market=Market.SPOT,
                    instrument_key="BTC-USDT",
                    wire_symbol="BTC-USDT",
                    logical_stream="trade",
                    native_channel="trades",
                    transport=Transport.WEBSOCKET,
                    event_time_ns=row["event_time_ns"],
                    event_time_source="ts",
                    payload=row["payload"],
                ),
                source=source,
                shard="spot-0",
            )
            if not result.accepted:
                self.closed_generations.add(1)
                break
        self.complete = True
        await runtime.stop.wait()


class Runtime:
    def __init__(self, stop: object) -> None:
        self.stop = stop


def request() -> CollectionRequest:
    return CollectionRequest.model_validate(
        {
            "exchange": Exchange.OKX,
            "selected": {Market.SPOT: ()},
            "enabled_streams": {Market.SPOT: frozenset({"trade"})},
            "interval_plans": {"book_deep_snapshot": IntervalPlan(30, 30, None)},
            "config_sha256": "a" * 64,
        }
    )


def constrained_ingress() -> IngressConfig:
    return IngressConfig.model_validate(
        {
            "shard_max_records": 2,
            "shard_max_bytes": "64KiB",
            "worker_max_bytes": "128KiB",
            "control_reserve_records": 2,
            "control_reserve_bytes": "32KiB",
        }
    )


def control_draft(index: int) -> NativeEventDraft:
    return NativeEventDraft(
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        event_time_ns=None,
        event_time_source=None,
        payload={"kind": "scripted_control", "index": index},
    )


@pytest.mark.asyncio
async def test_scripted_worker_writes_data_and_expectation_control(
    tmp_path: Path,
) -> None:
    clock = SystemClock()
    adapter = ScriptedAdapter()

    async def writer_factory(*, on_critical: object) -> RawWriterService:
        return await RawWriterService.open(
            data_root=tmp_path / "data",
            state_root=tmp_path / "state",
            exchange=Exchange.OKX,
            worker_instance_id="worker-1",
            config_sha256="a" * 64,
            config_generation=0,
            writer_config=WriterConfig.model_validate({}),
            ingress_config=IngressConfig.model_validate({}),
            metric_stream_allowlist=("_control", "trade"),
            clock=clock,
            on_critical=on_critical,  # type: ignore[arg-type]
        )

    async def runtime_factory(stop: object) -> Runtime:
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=adapter,
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
        clock=clock,
    )
    await worker.start()
    for _ in range(100):
        if adapter.complete:
            break
        await worker.yield_once()
    assert adapter.complete

    manifests = await worker.stop(deadline_ns=clock.monotonic_ns() + 5_000_000_000)
    typed = tuple(item for item in manifests if type(item) is RawManifestV1)
    streams = {item.logical_stream for item in typed}
    assert streams == {"_control", "trade"}
    assert (
        sum(item.record_count for item in typed if item.logical_stream == "trade") == 2
    )
    assert worker.state is WorkerState.STOPPED
    assert adapter.closed_generations == set()
    assert all(item.close_reason is CloseReason.SHUTDOWN for item in typed)
    control_manifest = next(item for item in typed if item.logical_stream == "_control")
    compressed = (tmp_path / "data" / control_manifest.data_relative_path).read_bytes()
    plain = zstandard.ZstdDecompressor().decompress(compressed)
    control_rows = [decode_envelope_jsonl(line + b"\n") for line in plain.splitlines()]
    assert [row.payload["kind"] for row in control_rows] == [
        "subscription_expectation",
        "subscription_expectation",
    ]
    assert "effective_end_ns" not in control_rows[0].payload
    assert (
        control_rows[1].payload["effective_end_ns"]
        >= control_rows[1].payload["effective_start_ns"]
    )
    assert await worker.stop(deadline_ns=clock.monotonic_ns()) == manifests


@pytest.mark.asyncio
async def test_real_writer_normal_overflow_persists_reserved_control(
    tmp_path: Path,
) -> None:
    clock = SystemClock()
    overflow_seen = asyncio.Event()
    writer: RawWriterService | None = None

    class OverflowAdapter(ScriptedAdapter):
        async def run(self, plan: AdapterPlan, runtime: Any, sink: Any) -> None:
            del plan
            source = SourceContext(
                connection_id="scripted-ws",
                connection_generation=1,
                egress_id="direct-primary",
            )
            for index in range(3):
                result = sink.try_emit(
                    NativeEventDraft(
                        exchange=Exchange.OKX,
                        market=Market.SPOT,
                        instrument_key="BTC-USDT",
                        wire_symbol="BTC-USDT",
                        logical_stream="trade",
                        native_channel="trades",
                        transport=Transport.WEBSOCKET,
                        event_time_ns=index,
                        event_time_source="ts",
                        payload={"tradeId": str(index)},
                    ),
                    source=source,
                    shard="spot-0",
                )
                if result.status is EnqueueStatus.OVERFLOW:
                    self.closed_generations.add(1)
                    overflow_seen.set()
                    break
            await runtime.stop.wait()

    adapter = OverflowAdapter()

    async def writer_factory(*, on_critical: object) -> RawWriterService:
        nonlocal writer
        writer = await RawWriterService.open(
            data_root=tmp_path / "data",
            state_root=tmp_path / "state",
            exchange=Exchange.OKX,
            worker_instance_id="worker-1",
            config_sha256="a" * 64,
            config_generation=0,
            writer_config=WriterConfig.model_validate({}),
            ingress_config=constrained_ingress(),
            metric_stream_allowlist=("_control", "trade"),
            clock=clock,
            on_critical=on_critical,  # type: ignore[arg-type]
        )
        return writer

    async def runtime_factory(stop: object) -> Runtime:
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=adapter,
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
        clock=clock,
    )
    await worker.start()
    await asyncio.wait_for(overflow_seen.wait(), 1)
    assert writer is not None
    await writer.sync_now()

    manifests = await worker.stop(deadline_ns=clock.monotonic_ns() + 5_000_000_000)
    typed = tuple(item for item in manifests if type(item) is RawManifestV1)
    assert worker.status().gap_count == 1
    assert adapter.closed_generations == {1}
    assert (
        sum(item.record_count for item in typed if item.logical_stream == "trade") == 2
    )
    control_manifest = next(item for item in typed if item.logical_stream == "_control")
    compressed = (tmp_path / "data" / control_manifest.data_relative_path).read_bytes()
    plain = zstandard.ZstdDecompressor().decompress(compressed)
    rows = [decode_envelope_jsonl(line + b"\n") for line in plain.splitlines()]
    assert "queue_overflow" in [row.payload["kind"] for row in rows]
    assert control_manifest.close_reason is CloseReason.SHUTDOWN


@pytest.mark.asyncio
async def test_real_writer_control_overflow_never_publishes_complete_manifest(
    tmp_path: Path,
) -> None:
    clock = SystemClock()
    writer: RawWriterService | None = None

    class ControlFloodAdapter(ScriptedAdapter):
        async def run(self, plan: AdapterPlan, runtime: Any, sink: Any) -> None:
            del plan
            for index in range(3):
                result = sink.try_emit(
                    control_draft(index),
                    source=SourceContext.internal(),
                    shard="_control",
                )
                if not result.accepted:
                    assert result.status is EnqueueStatus.CONTROL_OVERFLOW
                    break
            await runtime.stop.wait()

    async def writer_factory(*, on_critical: object) -> RawWriterService:
        nonlocal writer
        writer = await RawWriterService.open(
            data_root=tmp_path / "data",
            state_root=tmp_path / "state",
            exchange=Exchange.OKX,
            worker_instance_id="worker-1",
            config_sha256="a" * 64,
            config_generation=0,
            writer_config=WriterConfig.model_validate({}),
            ingress_config=constrained_ingress(),
            metric_stream_allowlist=("_control", "trade"),
            clock=clock,
            on_critical=on_critical,  # type: ignore[arg-type]
        )
        return writer

    async def runtime_factory(stop: object) -> Runtime:
        return Runtime(stop)

    worker = ExchangeWorker(
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        request=request(),
        adapter=ControlFloodAdapter(),
        writer_factory=writer_factory,
        runtime_factory=runtime_factory,
        clock=clock,
    )
    await worker.start()
    await worker.wait_until_state(WorkerState.PAUSED_WRITER, timeout=1)

    assert worker.status().last_failure == "control_overflow"
    assert writer is not None
    assert await worker.stop(deadline_ns=clock.monotonic_ns()) == ()
    assert not tuple((tmp_path / "data").rglob("*.manifest.json"))
