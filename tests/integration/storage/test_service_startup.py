from __future__ import annotations

import asyncio
import errno
import hashlib
import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from crypto_collector.config.models import IngressConfig, WriterConfig
from crypto_collector.domain.envelope import NativeEventDraft, SourceContext
from crypto_collector.domain.types import CloseReason, Exchange, Market, Transport
from crypto_collector.storage.durability import (
    AsyncSleeper,
    DurabilitySloState,
    DurabilitySloTransition,
    SyncBackend,
    WriterCriticalError,
    WriterCriticalReason,
)
from crypto_collector.storage.errors import RecoveryBlocked
from crypto_collector.storage.manifest import (
    RawManifestV1,
    RecoverySourceState,
    load_raw_manifest,
)
from crypto_collector.storage.models import (
    AdmissionState,
    EnqueueStatus,
    WriterLifecycle,
)
from crypto_collector.storage.raw_writer import _ActivePart
from crypto_collector.storage.recovery import (
    PendingRecoveryControl,
    RecoveryContext,
    RecoveryControlAdmission,
    RecoveryControlPayloadV1,
    RecoveryControlReceipt,
    RecoveryOutcome,
    RecoveryReconciliation,
    RecoverySourceDisposition,
    whole_source_quarantine_relative_path,
)
from crypto_collector.storage.service import RawWriterService
from crypto_collector.storage.writer_lock import (
    ExchangeWriterLock,
    WriterAlreadyRunning,
)


class FakeClock:
    def __init__(self) -> None:
        self.wall_ns = 1_785_456_000_000_000_000
        self.monotonic = 1_000_000

    def time_ns(self) -> int:
        value = self.wall_ns
        self.wall_ns += 1
        return value

    def monotonic_ns(self) -> int:
        value = self.monotonic
        self.monotonic += 1
        return value


class EmptyRecoveryBackend:
    async def reconcile(self, context: RecoveryContext) -> RecoveryReconciliation:
        assert context.exchange is Exchange.OKX
        return RecoveryReconciliation(completed_outcomes=(), pending_controls=())

    async def bind_control_ownership(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        admission: RecoveryControlAdmission,
    ) -> None:
        raise AssertionError("empty recovery has no pending control")

    async def acknowledge_control_durable(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        receipt: RecoveryControlReceipt,
    ) -> RecoveryOutcome:
        raise AssertionError("empty recovery has no pending control")


class FailingRecoveryBackend(EmptyRecoveryBackend):
    async def reconcile(self, context: RecoveryContext) -> RecoveryReconciliation:
        raise RecoveryBlocked("injected recovery failure")


class ManualSleeper:
    def __init__(self) -> None:
        self._waiters: asyncio.Queue[asyncio.Event] = asyncio.Queue()

    async def sleep_ns(self, delay_ns: int) -> None:
        assert delay_ns > 0
        waiter = asyncio.Event()
        self._waiters.put_nowait(waiter)
        await waiter.wait()

    async def wake_once(self) -> None:
        waiter = await self._waiters.get()
        self._waiters.task_done()
        waiter.set()


class FailingSleeper:
    def __init__(self) -> None:
        self.failed = asyncio.Event()

    async def sleep_ns(self, _delay_ns: int) -> None:
        self.failed.set()
        raise RuntimeError("injected ticker failure")


class BlockingSyncBackend:
    def __init__(self) -> None:
        self.started = threading.Event()
        self.release = threading.Event()

    def sync(self, fd: int) -> None:
        assert fd >= 0
        self.started.set()
        assert self.release.wait(timeout=5)


class BlockingNthSyncBackend:
    def __init__(self, *, block_on_call: int) -> None:
        self.block_on_call = block_on_call
        self.call_count = 0
        self.started = threading.Event()
        self.release = threading.Event()

    def sync(self, fd: int) -> None:
        assert fd >= 0
        self.call_count += 1
        if self.call_count != self.block_on_call:
            return
        self.started.set()
        assert self.release.wait(timeout=5)


class FailingNthSyncBackend:
    def __init__(self, *, fail_on_call: int) -> None:
        self.fail_on_call = fail_on_call
        self.call_count = 0
        self._lock = threading.Lock()

    def sync(self, fd: int) -> None:
        assert fd >= 0
        with self._lock:
            self.call_count += 1
            call = self.call_count
        if call == self.fail_on_call:
            raise OSError(errno.EIO, "injected grouped sync failure")


class AdvancingSyncBackend:
    def __init__(self, clock: FakeClock, *, advance_ns: int) -> None:
        self.clock = clock
        self.advance_ns = advance_ns

    def sync(self, fd: int) -> None:
        assert fd >= 0
        self.clock.monotonic += self.advance_ns


def pending_recovery_control() -> PendingRecoveryControl:
    transaction_id = "123e4567-e89b-42d3-a456-426614174000"
    source_relative_path = (
        "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/"
        "part-1785456000000000000-4.jsonl.zst.partial"
    )
    source_sha256 = hashlib.sha256(b"unreadable").hexdigest()
    quarantine_relative_path = whole_source_quarantine_relative_path(
        source_relative_path
    )
    payload = RecoveryControlPayloadV1(
        recovery_control_event_id=f"raw-recovery-lineage:v1:{transaction_id}",
        transaction_id=transaction_id,
        source_state=RecoverySourceState.PARTIAL_TRUNCATED,
        source_disposition=RecoverySourceDisposition.MOVED_TO_QUARANTINE,
        source_market=Market.SPOT,
        source_instrument_key="BTC-USDT",
        source_logical_stream="trade",
        source_relative_path=source_relative_path,
        source_sha256=source_sha256,
        recovered_generation_id=None,
        recovered_relative_path=None,
        recovered_sha256=None,
        quarantined_relative_path=quarantine_relative_path,
        quarantined_sha256=source_sha256,
        informational_only=False,
        affected_markets=(Market.SPOT,),
    )
    draft = NativeEventDraft(
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        event_time_ns=None,
        event_time_source=None,
        payload=payload.model_dump(mode="json"),
    )
    return PendingRecoveryControl(
        transaction_id=transaction_id,
        recovery_control_event_id=payload.recovery_control_event_id,
        source_state=payload.source_state,
        source_disposition=payload.source_disposition,
        draft=draft,
        target=None,
    )


class RecordingRecoveryBackend(EmptyRecoveryBackend):
    def __init__(self, *, data_root: Path, pending: PendingRecoveryControl) -> None:
        self.data_root = data_root
        self.pending = pending
        self.calls: list[str] = []
        self.admission: RecoveryControlAdmission | None = None
        self.receipt: RecoveryControlReceipt | None = None

    async def reconcile(self, context: RecoveryContext) -> RecoveryReconciliation:
        self.calls.append("reconcile")
        return RecoveryReconciliation(
            completed_outcomes=(), pending_controls=(self.pending,)
        )

    async def bind_control_ownership(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        admission: RecoveryControlAdmission,
    ) -> None:
        self.calls.append("bind")
        assert pending is self.pending
        self.admission = admission
        data_path = self.data_root / admission.control_data_relative_path
        assert not data_path.exists()
        assert not data_path.with_name(data_path.name + ".partial").exists()
        assert not (self.data_root / admission.control_manifest_relative_path).exists()

    async def acknowledge_control_durable(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        receipt: RecoveryControlReceipt,
    ) -> RecoveryOutcome:
        self.calls.append("ack")
        self.receipt = receipt
        assert self.admission is not None
        data_path = self.data_root / receipt.control_data_relative_path
        assert data_path.exists()
        manifest_path = self.data_root / self.admission.control_manifest_relative_path
        assert manifest_path.exists()
        return RecoveryOutcome(
            transaction_id=pending.transaction_id,
            recovery_control_event_id=pending.recovery_control_event_id,
            source_state=pending.source_state,
            source_disposition=pending.source_disposition,
            source_relative_path=cast(
                str, pending.draft.payload["source_relative_path"]
            ),
            source_sha256=cast(str, pending.draft.payload["source_sha256"]),
            recovered_generation_id=None,
            recovered_relative_path=None,
            recovered_sha256=None,
            quarantined_relative_path=cast(
                str, pending.draft.payload["quarantined_relative_path"]
            ),
            quarantined_sha256=cast(str, pending.draft.payload["quarantined_sha256"]),
            informational_only=False,
        )


def trade_draft(
    *,
    exchange: Exchange = Exchange.OKX,
    instrument_key: str = "BTC-USDT",
) -> NativeEventDraft:
    return NativeEventDraft.model_validate(
        {
            "exchange": exchange,
            "market": Market.SPOT,
            "instrument_key": instrument_key,
            "wire_symbol": instrument_key,
            "logical_stream": "trade",
            "native_channel": "trades",
            "transport": Transport.WEBSOCKET,
            "event_time_ns": None,
            "event_time_source": None,
            "payload": {"price": "100", "size": "1"},
        }
    )


def websocket_source() -> SourceContext:
    return SourceContext(
        connection_id="ws-1",
        connection_generation=1,
        egress_id="direct",
    )


def associated_control_draft() -> NativeEventDraft:
    return NativeEventDraft.model_validate(
        {
            "exchange": Exchange.OKX,
            "market": None,
            "instrument_key": None,
            "wire_symbol": None,
            "logical_stream": "_control",
            "native_channel": None,
            "transport": Transport.INTERNAL,
            "event_time_ns": None,
            "event_time_source": None,
            "payload": {
                "kind": "gap_detected",
                "storage_association": {
                    "schema_version": 1,
                    "control_event_id": "gap:btc:1",
                    "affected_markets": ["spot"],
                    "target_logical_identities": [
                        {
                            "market": "spot",
                            "instrument_key": "BTC-USDT",
                            "logical_stream": "trade",
                        }
                    ],
                },
            },
        }
    )


async def open_service(
    tmp_path: Path,
    *,
    recovery_backend: EmptyRecoveryBackend | None = None,
    sleeper: AsyncSleeper | None = None,
    sync_backend: SyncBackend | None = None,
    writer_config: WriterConfig | None = None,
    metric_stream_allowlist: tuple[str, ...] = ("_control", "trade"),
    clock: FakeClock | None = None,
    on_slo_transition: Callable[[DurabilitySloTransition], None] | None = None,
) -> tuple[RawWriterService, FakeClock]:
    selected_clock = clock or FakeClock()
    service = await RawWriterService.open(
        data_root=tmp_path / "data",
        state_root=tmp_path / "state",
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        config_sha256="a" * 64,
        config_generation=0,
        writer_config=writer_config or WriterConfig.model_validate({}),
        ingress_config=IngressConfig.model_validate({}),
        metric_stream_allowlist=metric_stream_allowlist,
        clock=selected_clock,
        sleeper=sleeper,
        sync_backend=sync_backend,
        recovery_backend=recovery_backend or EmptyRecoveryBackend(),
        on_slo_transition=on_slo_transition,
    )
    return service, selected_clock


@pytest.mark.asyncio
async def test_empty_recovery_opens_accepting_service(tmp_path: Path) -> None:
    service, clock = await open_service(tmp_path)
    try:
        status = service.status()
        assert status.lifecycle is WriterLifecycle.ACCEPTING
        assert status.admission_state is AdmissionState.OPEN
        assert service.metrics_snapshot().accepted_record_count == 0
    finally:
        await service.close_all(
            CloseReason.SHUTDOWN,
            deadline_ns=clock.monotonic_ns() + 1_000_000_000,
        )
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_accept_sync_and_close_publish_one_manifest(tmp_path: Path) -> None:
    service, clock = await open_service(tmp_path)
    accepted = service.try_accept(
        trade_draft(),
        source=websocket_source(),
        shard="trade-0",
    )
    assert accepted.accepted
    batches = await service.sync_now()
    assert sum(batch.record_count for batch in batches) == 1
    assert service.status().durable_record_count == 1

    manifests = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )
    assert len(manifests) == 1
    assert manifests[0].record_count == 1
    assert manifests[0].close_reason is CloseReason.SHUTDOWN
    assert (tmp_path / "data" / manifests[0].data_relative_path).exists()
    assert (tmp_path / "data" / manifests[0].manifest_relative_path).exists()
    assert service.status().lifecycle is WriterLifecycle.CLOSED


@pytest.mark.asyncio
async def test_cross_exchange_rejection_consumes_no_sequence(tmp_path: Path) -> None:
    service, clock = await open_service(tmp_path)
    try:
        rejected = service.try_accept(
            trade_draft(exchange=Exchange.BYBIT),
            source=websocket_source(),
            shard="trade-0",
        )
        assert rejected.status is EnqueueStatus.NOT_ACCEPTING
        accepted = service.try_accept(
            trade_draft(),
            source=websocket_source(),
            shard="trade-0",
        )
        assert accepted.record is not None
        assert accepted.record.envelope.writer_sequence == 0
        assert accepted.record_identity is not None
        assert accepted.record_identity.acceptance_ordinal == 0
    finally:
        await service.close_all(
            CloseReason.SHUTDOWN,
            deadline_ns=clock.monotonic_ns() + 1_000_000_000,
        )


@pytest.mark.asyncio
async def test_recovery_failure_releases_lock_and_opens_no_partial(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    with pytest.raises(RecoveryBlocked, match="injected recovery failure"):
        await open_service(tmp_path, recovery_backend=FailingRecoveryBackend())
    assert not list(data_root.rglob("*.jsonl.zst.partial"))
    with ExchangeWriterLock.acquire(data_root, exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_invalid_metric_allowlist_has_no_filesystem_side_effect(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    with pytest.raises(ValueError, match="sorted and unique"):
        await RawWriterService.open(
            data_root=data_root,
            state_root=state_root,
            exchange=Exchange.OKX,
            worker_instance_id="worker-1",
            config_sha256="a" * 64,
            config_generation=0,
            writer_config=WriterConfig.model_validate({}),
            ingress_config=IngressConfig.model_validate({}),
            metric_stream_allowlist=("trade", "_control"),
            clock=FakeClock(),
            recovery_backend=EmptyRecoveryBackend(),
        )
    assert not data_root.exists()
    assert not state_root.exists()


@pytest.mark.asyncio
async def test_restart_allocator_skips_existing_part_sequences(tmp_path: Path) -> None:
    existing = (
        tmp_path
        / "data/raw/okx/spot/BTC-USDT/trade/2026/07/31/00"
        / "part-1785456000000000000-7.jsonl.zst"
    )
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"immutable-existing")

    service, clock = await open_service(tmp_path)
    accepted = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert accepted.accepted
    manifests = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )
    assert len(manifests) == 1
    assert Path(manifests[0].data_relative_path).name.endswith("-8.jsonl.zst")
    assert existing.read_bytes() == b"immutable-existing"


@pytest.mark.asyncio
async def test_restart_allocator_counts_manifest_lease_and_manifest_temp_sequences(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "data/raw/okx/spot/BTC-USDT/trade/2026/07/31/00"
    directory.mkdir(parents=True)
    for name in (
        "part-1785456000000000000-9.manifest.json",
        "part-1785456000000000000-10.lease",
        "part-1785456000000000000-11.manifest.json.partial",
    ):
        (directory / name).write_bytes(b"retained-evidence")

    service, clock = await open_service(tmp_path)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    manifests = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )
    assert len(manifests) == 1
    assert Path(manifests[0].data_relative_path).name.endswith("-12.jsonl.zst")


@pytest.mark.asyncio
async def test_periodic_timer_flushes_without_public_barrier(tmp_path: Path) -> None:
    sleeper = ManualSleeper()
    service, clock = await open_service(tmp_path, sleeper=sleeper)
    accepted = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert accepted.accepted
    await sleeper.wake_once()
    for _ in range(100):
        if service.metrics_snapshot().durable_record_count == 1:
            break
        await asyncio.sleep(0)
    assert service.metrics_snapshot().durable_record_count == 1
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_cancelled_close_waiter_does_not_release_owned_io_or_lock(
    tmp_path: Path,
) -> None:
    sync = BlockingSyncBackend()
    service, clock = await open_service(tmp_path, sync_backend=sync)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    deadline = clock.monotonic_ns() + 1_000_000_000
    close_waiter = asyncio.create_task(
        service.close_all(CloseReason.SHUTDOWN, deadline_ns=deadline)
    )
    assert await asyncio.to_thread(sync.started.wait, 5)
    close_waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await close_waiter
    with pytest.raises(WriterAlreadyRunning):
        ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX)

    sync.release.set()
    manifests = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=deadline,
    )
    assert len(manifests) == 1
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_final_barrier_start_failure_clears_service_claims_and_releases_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, clock = await open_service(tmp_path)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted

    async def fail_close_group(*_args: object, **_kwargs: object) -> tuple[object, ...]:
        raise ValueError("injected final barrier start failure")

    monkeypatch.setattr(service._barrier, "close_mixed_group", fail_close_group)
    with pytest.raises(WriterCriticalError) as captured:
        await asyncio.wait_for(
            service.close_all(
                CloseReason.SHUTDOWN,
                deadline_ns=clock.monotonic_ns() + 1_000_000_000,
            ),
            timeout=1,
        )
    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    snapshot = service.status()
    assert snapshot.sync_inflight == 0
    assert snapshot.uncertain_record_count == 1
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_pending_recovery_control_binds_before_carrier_io_and_acks_after_publish(
    tmp_path: Path,
) -> None:
    pending = pending_recovery_control()
    backend = RecordingRecoveryBackend(
        data_root=tmp_path / "data",
        pending=pending,
    )
    service, clock = await open_service(tmp_path, recovery_backend=backend)
    assert backend.calls == ["reconcile", "bind", "ack"]
    assert backend.admission is not None
    assert backend.receipt is not None
    assert backend.receipt.control_record_identity == (
        backend.admission.control_record_identity
    )
    snapshot = service.metrics_snapshot()
    assert (
        snapshot.accepted_record_count,
        snapshot.durable_record_count,
        snapshot.durability_sample_count,
    ) == (1, 1, 1)
    manifest = load_raw_manifest(
        tmp_path / "data" / backend.admission.control_manifest_relative_path
    ).manifest
    assert manifest.close_reason is CloseReason.RECOVERY_CONTROL
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


def test_service_is_exported_from_storage_package() -> None:
    from crypto_collector.storage import RawWriterService as PublicRawWriterService

    assert PublicRawWriterService is RawWriterService


@pytest.mark.asyncio
async def test_production_recovery_reaches_complete_before_open_returns(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    partial = (
        data_root
        / "raw/okx/spot/BTC-USDT/trade/2026/07/31/00"
        / "part-1785456000000000000-3.jsonl.zst.partial"
    )
    partial.parent.mkdir(parents=True)
    partial.write_bytes(b"not-a-zstd-frame")
    clock = FakeClock()

    service = await RawWriterService.open(
        data_root=data_root,
        state_root=state_root,
        exchange=Exchange.OKX,
        worker_instance_id="worker-1",
        config_sha256="a" * 64,
        config_generation=0,
        writer_config=WriterConfig.model_validate({}),
        ingress_config=IngressConfig.model_validate({}),
        metric_stream_allowlist=("_control", "trade"),
        clock=clock,
    )
    assert not partial.exists()
    assert len(list(data_root.rglob("*.whole"))) == 1
    assert len(list(state_root.glob("raw-recovery/okx/*/complete.json"))) == 1
    snapshot = service.metrics_snapshot()
    assert snapshot.accepted_record_count == snapshot.durable_record_count == 1
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_received_hour_change_publishes_old_part_before_new_hour_append(
    tmp_path: Path,
) -> None:
    service, clock = await open_service(tmp_path)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    clock.wall_ns = 1_785_459_600_000_000_000
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    rotated_paths = tuple((tmp_path / "data").rglob("*.manifest.json"))
    assert len(rotated_paths) == 1
    rotated = load_raw_manifest(rotated_paths[0]).manifest
    assert rotated.close_reason is CloseReason.ROTATE_TIME
    assert rotated.record_count == 1
    assert "/2026/07/31/00/" in f"/{rotated.data_relative_path}"

    final = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )
    assert len(final) == 1
    assert final[0].record_count == 1
    assert "/2026/07/31/01/" in f"/{final[0].data_relative_path}"


@pytest.mark.asyncio
async def test_hour_rotation_group_failure_publishes_no_member(tmp_path: Path) -> None:
    sync_backend = FailingNthSyncBackend(fail_on_call=6)
    service, clock = await open_service(tmp_path, sync_backend=sync_backend)
    for instrument in ("BTC-USDT", "ETH-USDT"):
        assert service.try_accept(
            trade_draft(instrument_key=instrument),
            source=websocket_source(),
            shard=f"{instrument}-trade",
        ).accepted
    await service.sync_now()

    clock.wall_ns = 1_785_459_600_000_000_000
    for instrument in ("BTC-USDT", "ETH-USDT"):
        assert service.try_accept(
            trade_draft(instrument_key=instrument),
            source=websocket_source(),
            shard=f"{instrument}-trade",
        ).accepted
    with pytest.raises(WriterCriticalError) as captured:
        await service.sync_now()

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert sync_backend.call_count == 6
    assert not tuple((tmp_path / "data").rglob("*.manifest.json"))
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.parametrize("command", ("config", "shutdown"))
@pytest.mark.asyncio
async def test_pending_hour_and_command_parts_share_one_prepublication_batch(
    tmp_path: Path,
    command: str,
) -> None:
    sync_backend = FailingNthSyncBackend(fail_on_call=3)
    service, clock = await open_service(tmp_path, sync_backend=sync_backend)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    clock.wall_ns = 1_785_459_600_000_000_000
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    with pytest.raises(WriterCriticalError) as captured:
        if command == "config":
            await service.rotate_for_config("b" * 64, config_generation=1)
        else:
            await service.close_all(
                CloseReason.SHUTDOWN,
                deadline_ns=clock.monotonic_ns() + 1_000_000_000,
            )

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert sync_backend.call_count == 3
    assert not tuple((tmp_path / "data").rglob("*.manifest.json"))
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_size_and_interval_due_failure_publish_no_normal_manifest(
    tmp_path: Path,
) -> None:
    sync_backend = FailingNthSyncBackend(fail_on_call=4)
    service, clock = await open_service(tmp_path, sync_backend=sync_backend)
    incompressible_payload = "".join(
        hashlib.sha256(str(index).encode()).hexdigest() for index in range(512)
    )
    assert service.try_accept(
        trade_draft(instrument_key="BTC-USDT"),
        source=websocket_source(),
        shard="btc-trade",
    ).accepted
    assert service.try_accept(
        trade_draft(instrument_key="ETH-USDT").model_copy(
            update={"payload": {"blob": incompressible_payload}}
        ),
        source=websocket_source(),
        shard="eth-trade",
    ).accepted
    await service.sync_now()

    btc_part = next(
        part
        for part in service._parts.active_parts()
        if "/BTC-USDT/" in f"/{part.data_relative_path}"
    )
    eth_part = next(
        part
        for part in service._parts.active_parts()
        if "/ETH-USDT/" in f"/{part.data_relative_path}"
    )
    btc_size = btc_part.stream_file.compressed_size
    eth_size = eth_part.stream_file.compressed_size
    assert btc_size < eth_size
    service._parts._max_compressed_size_bytes = eth_size
    service._parts._rotate_interval_ns = 1
    btc_part.created_at_ns = 0
    eth_part.created_at_ns = clock.wall_ns

    with pytest.raises(WriterCriticalError) as captured:
        await service.rotate_due_files()

    assert captured.value.reason is WriterCriticalReason.SYNC_FAILED
    assert sync_backend.call_count == 4
    assert not tuple((tmp_path / "data").rglob("*.manifest.json"))
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_size_threshold_rotates_after_sync_and_keeps_replacement_active(
    tmp_path: Path,
) -> None:
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, clock = await open_service(tmp_path, writer_config=writer_config)
    first = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert first.accepted
    await service.sync_now()

    rotated_paths = tuple((tmp_path / "data").rglob("*.manifest.json"))
    assert len(rotated_paths) == 1
    rotated = load_raw_manifest(rotated_paths[0]).manifest
    assert rotated.close_reason is CloseReason.ROTATE_SIZE
    assert service.status().active_logical_generation_count == 1
    assert service.status().open_file_descriptor_count == 1

    second = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert second.accepted
    final = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )
    assert len(final) == 1
    assert final[0].data_relative_path != rotated.data_relative_path


@pytest.mark.asyncio
async def test_durable_control_folds_into_empty_size_replacement(
    tmp_path: Path,
) -> None:
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, clock = await open_service(tmp_path, writer_config=writer_config)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    control = service.try_accept(
        associated_control_draft(),
        source=SourceContext.internal(),
        shard="_control",
    )
    assert control.accepted
    await service.sync_now()
    assert service.status().active_logical_generation_count == 2
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted

    manifests = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )
    trade_manifest = next(item for item in manifests if item.logical_stream == "trade")
    assert trade_manifest.control_event_ids == ("gap:btc:1",)
    assert trade_manifest.gap_count == 1


@pytest.mark.asyncio
async def test_shutdown_elides_empty_replacement_after_durable_control(
    tmp_path: Path,
) -> None:
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, clock = await open_service(tmp_path, writer_config=writer_config)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()
    service._parts._max_compressed_size_bytes = 1024 * 1024
    assert service.try_accept(
        associated_control_draft(),
        source=SourceContext.internal(),
        shard="_control",
    ).accepted
    await service.sync_now()

    target = next(
        part for part in service._parts.active_parts() if part.logical_stream == "trade"
    )
    assert target.record_count == 0
    target_partial = target.partial_path
    target_manifest = target.closed_manifest_path

    manifests = cast(
        tuple[RawManifestV1, ...],
        await service.close_all(
            CloseReason.SHUTDOWN,
            deadline_ns=clock.monotonic_ns() + 1_000_000_000,
        ),
    )
    assert {manifest.logical_stream for manifest in manifests} == {"_control"}
    assert not target_partial.exists()
    assert not target_manifest.exists()
    status = service.status()
    assert status.lifecycle is WriterLifecycle.CLOSED
    assert status.accepted_record_count == status.durable_record_count == 2
    assert status.uncertain_record_count == 0


@pytest.mark.asyncio
async def test_control_accepted_while_size_replacement_materializes_targets_replacement(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    allocation_started = threading.Event()
    release_allocation = threading.Event()
    original = cast(Callable[..., _ActivePart], _ActivePart.allocate_empty_replacement)

    def block_replacement(cls: type[_ActivePart], **kwargs: object) -> _ActivePart:
        allocation_started.set()
        assert release_allocation.wait(timeout=5)
        return original(**kwargs)

    monkeypatch.setattr(
        _ActivePart,
        "allocate_empty_replacement",
        classmethod(block_replacement),
    )
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, clock = await open_service(tmp_path, writer_config=writer_config)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted

    rotating = asyncio.create_task(service.sync_now())
    try:
        assert await asyncio.to_thread(allocation_started.wait, 5)
        assert service.try_accept(
            associated_control_draft(),
            source=SourceContext.internal(),
            shard="_control",
        ).accepted
    finally:
        release_allocation.set()
        await rotating

    rotated_paths = tuple((tmp_path / "data").rglob("*.manifest.json"))
    assert len(rotated_paths) == 1
    old_manifest = load_raw_manifest(rotated_paths[0]).manifest
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted

    manifests = cast(
        tuple[RawManifestV1, ...],
        await service.close_all(
            CloseReason.SHUTDOWN,
            deadline_ns=clock.monotonic_ns() + 1_000_000_000,
        ),
    )
    target_manifest = next(item for item in manifests if item.logical_stream == "trade")
    assert target_manifest.data_relative_path != old_manifest.data_relative_path
    assert target_manifest.control_event_ids == ("gap:btc:1",)
    assert target_manifest.gap_count == 1


@pytest.mark.asyncio
async def test_size_replacement_buffers_new_rows_while_old_final_sync_is_blocked(
    tmp_path: Path,
) -> None:
    sync_backend = BlockingNthSyncBackend(block_on_call=2)
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, clock = await open_service(
        tmp_path,
        writer_config=writer_config,
        sync_backend=sync_backend,
    )
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    rotating = asyncio.create_task(service.sync_now())
    assert await asyncio.to_thread(sync_backend.started.wait, 5)

    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    for _ in range(100):
        if service.status().buffered_records == 1:
            break
        await asyncio.sleep(0)
    during = service.status()
    assert during.active_logical_generation_count == 1
    assert during.retiring_generation_count == 1
    assert during.open_file_descriptor_count == 2
    assert during.buffered_records == 1

    sync_backend.release.set()
    await rotating
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_empty_size_replacement_is_removed_on_shutdown(tmp_path: Path) -> None:
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, clock = await open_service(tmp_path, writer_config=writer_config)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()
    assert service.status().open_file_descriptor_count == 1

    manifests = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )
    assert manifests == ()
    assert not tuple((tmp_path / "data").rglob("*.partial"))


@pytest.mark.asyncio
async def test_config_rotation_discards_empty_size_replacement(tmp_path: Path) -> None:
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, clock = await open_service(tmp_path, writer_config=writer_config)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    assert await service.rotate_for_config("b" * 64, config_generation=1) == ()
    assert service.status().active_logical_generation_count == 0
    assert service.status().open_file_descriptor_count == 0
    assert not tuple((tmp_path / "data").rglob("*.partial"))
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_new_hour_supersedes_and_removes_empty_size_replacement(
    tmp_path: Path,
) -> None:
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, clock = await open_service(tmp_path, writer_config=writer_config)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    clock.wall_ns = 1_785_459_600_000_000_000
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()
    assert not any(
        "/2026/07/31/00/" in f"/{path.relative_to(tmp_path / 'data').as_posix()}"
        for path in (tmp_path / "data").rglob("*.partial")
    )
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_target_manifest_waits_for_and_folds_associated_control(
    tmp_path: Path,
) -> None:
    service, clock = await open_service(tmp_path)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    control = service.try_accept(
        associated_control_draft(),
        source=SourceContext.internal(),
        shard="_control",
    )
    assert control.accepted
    manifests = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )

    trade_manifest = next(item for item in manifests if item.logical_stream == "trade")
    assert trade_manifest.control_event_ids == ("gap:btc:1",)
    assert trade_manifest.gap_count == 1


@pytest.mark.asyncio
async def test_part_allocation_failure_terminalizes_actor_and_releases_lock(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _clock = await open_service(tmp_path)

    def fail_allocate(cls: type[_ActivePart], **_kwargs: object) -> _ActivePart:
        raise OSError(errno.ENOSPC, "injected allocation failure")

    monkeypatch.setattr(_ActivePart, "allocate", classmethod(fail_allocate))
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted

    with pytest.raises(WriterCriticalError) as captured:
        await service.sync_now()
    assert captured.value.reason is WriterCriticalReason.WRITE_FAILED
    assert service.status().lifecycle is WriterLifecycle.CRITICAL
    assert service.status().uncertain_record_count == 1
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_terminal_accounting_failure_cannot_resolve_command_as_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _clock = await open_service(tmp_path)
    original_refresh = service._refresh_metrics_cache

    def fail_terminal_refresh() -> None:
        if service._lifecycle is WriterLifecycle.CRITICAL:
            raise RuntimeError("injected terminal cache failure")
        original_refresh()

    monkeypatch.setattr(service, "_refresh_metrics_cache", fail_terminal_refresh)

    with pytest.raises(RuntimeError, match="injected terminal cache failure"):
        await service.mark_incomplete("injected incomplete state")
    snapshot = service.metrics_snapshot()
    assert snapshot.lifecycle is WriterLifecycle.CRITICAL
    assert snapshot.admission_state is AdmissionState.CLOSED
    assert snapshot.critical_reason is WriterCriticalReason.MARKED_INCOMPLETE
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_terminal_snapshot_fallback_rebuilds_conserved_metrics(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, _clock = await open_service(tmp_path)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    previous = service.metrics_snapshot()
    original_build = service._build_metrics_snapshot
    original_enter = service._enter_terminal_error
    terminal_inputs: list[BaseException] = []

    async def trace_terminal(error: BaseException) -> BaseException:
        terminal_inputs.append(error)
        return await original_enter(error)

    def fail_terminal_build() -> object:
        if service._lifecycle is WriterLifecycle.CRITICAL:
            raise RuntimeError("injected terminal snapshot failure")
        return original_build()

    monkeypatch.setattr(service, "_build_metrics_snapshot", fail_terminal_build)
    monkeypatch.setattr(service, "_enter_terminal_error", trace_terminal)

    with pytest.raises(RuntimeError, match="injected terminal snapshot failure"):
        await service.mark_incomplete("injected incomplete state")

    assert len(terminal_inputs) == 1
    assert isinstance(terminal_inputs[0], WriterCriticalError)
    assert terminal_inputs[0].reason is WriterCriticalReason.MARKED_INCOMPLETE
    snapshot = service.metrics_snapshot()
    assert snapshot.observed_monotonic_ns > previous.observed_monotonic_ns
    assert snapshot.lifecycle is WriterLifecycle.CRITICAL
    assert snapshot.admission_state is AdmissionState.CLOSED
    assert snapshot.critical_reason is WriterCriticalReason.MARKED_INCOMPLETE
    assert snapshot.accepted_record_count == 1
    assert snapshot.durable_record_count == 0
    assert snapshot.unpersisted_record_count == 0
    assert snapshot.uncertain_record_count == 1
    assert snapshot.queued_records == 0
    assert snapshot.buffered_records == 0
    assert snapshot.in_flight_records == 0
    assert snapshot.resident_record_bytes == 0
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_resource_release_failure_cannot_leave_close_future_pending(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    service, clock = await open_service(tmp_path)
    original_release = service._release_resources

    async def release_then_fail() -> None:
        await original_release()
        raise RuntimeError("injected resource release failure")

    monkeypatch.setattr(service, "_release_resources", release_then_fail)

    with pytest.raises(RuntimeError, match="injected resource release failure"):
        await asyncio.wait_for(
            service.close_all(
                CloseReason.SHUTDOWN,
                deadline_ns=clock.monotonic_ns() + 1_000_000_000,
            ),
            timeout=1,
        )
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_ticker_failure_still_releases_every_owned_resource(
    tmp_path: Path,
) -> None:
    sleeper = FailingSleeper()
    service, clock = await open_service(tmp_path, sleeper=sleeper)
    await asyncio.wait_for(sleeper.failed.wait(), timeout=1)

    with pytest.raises(RuntimeError, match="injected ticker failure"):
        await asyncio.wait_for(
            service.close_all(
                CloseReason.SHUTDOWN,
                deadline_ns=clock.monotonic_ns() + 1_000_000_000,
            ),
            timeout=1,
        )

    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.parametrize(
    "command",
    ("sync", "rotate_due", "rotate_config", "close", "incomplete"),
)
@pytest.mark.asyncio
async def test_command_after_terminal_error_fails_without_reentering_stopped_actor(
    tmp_path: Path,
    command: str,
) -> None:
    service, clock = await open_service(tmp_path)
    with pytest.raises(WriterCriticalError) as terminal:
        await service.mark_incomplete("injected terminal state")
    assert terminal.value.reason is WriterCriticalReason.MARKED_INCOMPLETE

    if command == "sync":
        pending = service.sync_now()
    elif command == "rotate_due":
        pending = service.rotate_due_files()
    elif command == "rotate_config":
        pending = service.rotate_for_config("b" * 64, 1)
    elif command == "incomplete":
        pending = service.mark_incomplete("repeated incomplete state")
    else:
        pending = service.close_all(
            CloseReason.SHUTDOWN,
            deadline_ns=clock.monotonic_ns() + 1_000_000_000,
        )
    with pytest.raises(WriterCriticalError) as repeated:
        await asyncio.wait_for(pending, timeout=1)
    assert repeated.value.reason is WriterCriticalReason.MARKED_INCOMPLETE


@pytest.mark.asyncio
async def test_failed_replacement_preallocation_removes_uncommitted_empty_parts(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    writer_config = WriterConfig.model_validate({"max_compressed_size": "1B"})
    service, _clock = await open_service(tmp_path, writer_config=writer_config)
    original = _ActivePart.allocate_empty_replacement.__func__
    call_count = 0

    def fail_second(cls: type[_ActivePart], **kwargs: object) -> _ActivePart:
        nonlocal call_count
        call_count += 1
        if call_count == 2:
            raise OSError(errno.ENOSPC, "injected replacement allocation failure")
        return original(cls, **kwargs)

    monkeypatch.setattr(
        _ActivePart,
        "allocate_empty_replacement",
        classmethod(fail_second),
    )
    assert service.try_accept(
        trade_draft(instrument_key="BTC-USDT"),
        source=websocket_source(),
        shard="btc-trade",
    ).accepted
    assert service.try_accept(
        trade_draft(instrument_key="ETH-USDT"),
        source=websocket_source(),
        shard="eth-trade",
    ).accepted

    with pytest.raises(WriterCriticalError) as captured:
        await service.sync_now()
    assert captured.value.reason is WriterCriticalReason.WRITE_FAILED
    partials = tuple((tmp_path / "data").rglob("*.partial"))
    assert len(partials) == 2
    assert all(path.stat().st_size > 0 for path in partials)
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_hour_rotation_still_closes_old_part_for_oversized_first_row(
    tmp_path: Path,
) -> None:
    writer_config = WriterConfig.model_validate({"max_plain_frame_bytes": "1KiB"})
    service, clock = await open_service(tmp_path, writer_config=writer_config)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    clock.wall_ns = 1_785_459_600_000_000_000
    oversized = trade_draft().model_copy(update={"payload": {"blob": "x" * 5_000}})
    assert service.try_accept(
        oversized, source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()

    rotated = tuple((tmp_path / "data").rglob("*.manifest.json"))
    assert len(rotated) == 1
    assert (
        load_raw_manifest(rotated[0]).manifest.close_reason is CloseReason.ROTATE_TIME
    )
    assert service.status().durable_record_count == 2
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_slo_callback_emits_only_breach_and_expiry_transitions(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    sleeper = ManualSleeper()
    transitions: list[DurabilitySloTransition] = []
    service, _ = await open_service(
        tmp_path,
        clock=clock,
        sleeper=sleeper,
        sync_backend=AdvancingSyncBackend(clock, advance_ns=1_000_000_001),
        on_slo_transition=transitions.append,
    )
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.sync_now()
    assert [item.state for item in transitions] == [DurabilitySloState.BREACHED]
    assert service.metrics_snapshot().slo_breach_count == 1

    clock.monotonic += 60_000_000_000
    await sleeper.wake_once()
    for _ in range(100):
        if len(transitions) == 2:
            break
        await asyncio.sleep(0)
    assert [item.state for item in transitions] == [
        DurabilitySloState.BREACHED,
        DurabilitySloState.RECOVERED,
    ]
    assert transitions[-1].rolling_max_ns is None
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_slo_callback_failure_keeps_completed_row_durable(
    tmp_path: Path,
) -> None:
    clock = FakeClock()

    def fail_callback(_transition: DurabilitySloTransition) -> None:
        raise RuntimeError("injected callback failure")

    service, _ = await open_service(
        tmp_path,
        clock=clock,
        sync_backend=AdvancingSyncBackend(clock, advance_ns=1_000_000_001),
        on_slo_transition=fail_callback,
    )
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    with pytest.raises(WriterCriticalError) as captured:
        await service.sync_now()
    assert captured.value.reason is WriterCriticalReason.SLO_TRANSITION_CALLBACK_FAILED
    snapshot = service.metrics_snapshot()
    assert snapshot.durable_record_count == 1
    assert snapshot.uncertain_record_count == 0
    assert snapshot.sync_inflight == 0
    assert snapshot.in_flight_records == 0
    assert snapshot.slo_breach_count == 1


@pytest.mark.asyncio
async def test_config_rotation_closes_old_identity_without_resetting_sequence(
    tmp_path: Path,
) -> None:
    service, clock = await open_service(tmp_path)
    first = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert first.record is not None
    old = await service.rotate_for_config("b" * 64, config_generation=1)
    assert len(old) == 1
    assert old[0].close_reason is CloseReason.CONFIG_RELOAD
    assert old[0].config_sha256 == "a" * 64

    second = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert second.record is not None
    assert first.record.envelope.writer_sequence == 0
    assert second.record.envelope.writer_sequence == 1
    assert second.record.envelope.config_sha256 == "b" * 64
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_invalid_config_rotation_does_not_close_healthy_admission(
    tmp_path: Path,
) -> None:
    service, clock = await open_service(tmp_path)
    with pytest.raises(ValueError, match="strictly greater"):
        await service.rotate_for_config("b" * 64, config_generation=0)
    assert service.status().lifecycle is WriterLifecycle.ACCEPTING
    assert service.status().admission_state is AdmissionState.OPEN
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_oversized_row_becomes_generation_bound_while_prior_sync_is_blocked(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    sleeper = ManualSleeper()
    sync = BlockingSyncBackend()
    service, _ = await open_service(
        tmp_path,
        clock=clock,
        sleeper=sleeper,
        sync_backend=sync,
        writer_config=WriterConfig.model_validate({"max_plain_frame_bytes": "1KiB"}),
    )
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await sleeper.wake_once()
    assert await asyncio.to_thread(sync.started.wait, 5)

    oversized = trade_draft().model_copy(update={"payload": {"blob": "x" * 5_000}})
    assert service.try_accept(
        oversized, source=websocket_source(), shard="trade-0"
    ).accepted
    for _ in range(100):
        if service.status().buffered_records == 1:
            break
        await asyncio.sleep(0)
    status = service.status()
    sync.release.set()
    assert status.in_flight_records == 1
    assert status.buffered_records == 1
    assert status.queued_records == 0

    await service.sync_now()
    assert service.status().durable_record_count == 2
    manifests = await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )
    assert len(manifests) == 1
    assert manifests[0].record_count == 2


@pytest.mark.asyncio
async def test_oversized_row_emits_bounded_size_warning(
    caplog: pytest.LogCaptureFixture,
    tmp_path: Path,
) -> None:
    caplog.set_level(logging.WARNING, logger="crypto_collector.storage.service")
    service, clock = await open_service(
        tmp_path,
        writer_config=WriterConfig.model_validate({"max_plain_frame_bytes": "1KiB"}),
    )
    oversized = trade_draft().model_copy(
        update={"payload": {"blob": "secret-value-" + "x" * 5_000}}
    )
    accepted = service.try_accept(
        oversized,
        source=websocket_source(),
        shard="trade-0",
    )
    assert accepted.accepted
    await service.sync_now()

    warnings = [
        record
        for record in caplog.records
        if record.getMessage() == "raw record exceeds configured frame size"
    ]
    assert len(warnings) == 1
    assert warnings[0].record_bytes > warnings[0].max_plain_frame_bytes
    assert "secret-value" not in caplog.text
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.parametrize(
    "reason",
    (CloseReason.RECOVERY, CloseReason.RECOVERY_CONTROL),
)
@pytest.mark.asyncio
async def test_close_all_rejects_recovery_only_reasons(
    tmp_path: Path,
    reason: CloseReason,
) -> None:
    service, clock = await open_service(tmp_path)
    with pytest.raises(ValueError, match="normal close reason"):
        await service.close_all(
            reason,
            deadline_ns=clock.monotonic_ns() + 1_000_000_000,
        )
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_sync_watermark_excludes_records_accepted_after_command(
    tmp_path: Path,
) -> None:
    sync = BlockingSyncBackend()
    service, clock = await open_service(tmp_path, sync_backend=sync)
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    first_sync = asyncio.create_task(service.sync_now())
    assert await asyncio.to_thread(sync.started.wait, 5)

    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await asyncio.sleep(0)
    during = service.status()
    assert during.in_flight_records == 1
    assert during.queued_records == 1
    assert during.buffered_records == 0

    sync.release.set()
    first_batches = await first_sync
    assert sum(batch.record_count for batch in first_batches) == 1
    assert service.status().durable_record_count == 1
    await service.sync_now()
    assert service.status().durable_record_count == 2
    await service.close_all(
        CloseReason.SHUTDOWN,
        deadline_ns=clock.monotonic_ns() + 1_000_000_000,
    )


@pytest.mark.asyncio
async def test_close_deadline_after_confirmed_sync_withholds_normal_manifest(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    service, _ = await open_service(
        tmp_path,
        clock=clock,
        sync_backend=AdvancingSyncBackend(clock, advance_ns=1_000),
    )
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    deadline = clock.monotonic_ns() + 10

    with pytest.raises(WriterCriticalError) as captured:
        await service.close_all(CloseReason.SHUTDOWN, deadline_ns=deadline)
    assert captured.value.reason is WriterCriticalReason.CLOSE_DEADLINE
    snapshot = service.status()
    assert snapshot.lifecycle is WriterLifecycle.CRITICAL
    assert snapshot.durable_record_count == 1
    assert snapshot.uncertain_record_count == 0
    assert service.metrics_snapshot().publication_failure_count == 0
    assert not tuple((tmp_path / "data").rglob("*.manifest.json"))
    with ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_watchdog_enters_critical_while_sync_remains_owned(
    tmp_path: Path,
) -> None:
    clock = FakeClock()
    sleeper = ManualSleeper()
    sync = BlockingSyncBackend()
    service, _ = await open_service(
        tmp_path,
        clock=clock,
        sleeper=sleeper,
        sync_backend=sync,
        writer_config=WriterConfig.model_validate({"durability_critical": "1s"}),
    )
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    await sleeper.wake_once()
    assert await asyncio.to_thread(sync.started.wait, 5)

    clock.monotonic += 1_000_000_001
    await sleeper.wake_once()
    for _ in range(100):
        if service.status().lifecycle is WriterLifecycle.CRITICAL:
            break
        await asyncio.sleep(0)
    try:
        assert service.status().lifecycle is WriterLifecycle.CRITICAL
        assert (
            service.status().critical_reason
            is WriterCriticalReason.OLDEST_UNPERSISTED_AGE
        )
        with pytest.raises(WriterAlreadyRunning):
            ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX)
    finally:
        sync.release.set()
    for _ in range(100):
        try:
            lock = ExchangeWriterLock.acquire(tmp_path / "data", exchange=Exchange.OKX)
        except WriterAlreadyRunning:
            await asyncio.sleep(0)
        else:
            lock.release()
            break
    else:
        pytest.fail("writer lock was not released after watchdog drain")
    assert service.status().durable_record_count == 1
    assert service.status().uncertain_record_count == 0
