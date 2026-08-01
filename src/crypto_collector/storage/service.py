from __future__ import annotations

import asyncio
import errno
import hashlib
import logging
import os
import re
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import cast

import zstandard

from crypto_collector.config.models import IngressConfig, WriterConfig
from crypto_collector.domain.clock import Clock
from crypto_collector.domain.envelope import NativeEventDraft, SourceContext
from crypto_collector.domain.types import CloseReason, Exchange, Market
from crypto_collector.storage.durability import (
    AsyncioSleeper,
    AsyncSleeper,
    DurabilityBatch,
    DurabilityCoordinator,
    DurabilitySloState,
    DurabilitySloTransition,
    DurabilityTrigger,
    FileDurabilityResult,
    FilePersistenceError,
    FileSyncCompleted,
    FileSyncCompletion,
    FileSyncCompletionSink,
    FileSyncFailed,
    PosixSyncBackend,
    RecoveryAccountingMode,
    RecoveryDurabilityCoordinator,
    StorageIoLimiter,
    SyncBackend,
    WriterAffinityError,
    WriterCriticalError,
    WriterCriticalReason,
    discard_file_sync_completion,
)
from crypto_collector.storage.errors import RecoveryBlocked
from crypto_collector.storage.ingress import RawIngress, ResidentBudget
from crypto_collector.storage.manifest import manifest_path_for_data
from crypto_collector.storage.models import (
    AcceptedRecord,
    AcceptedRecordIdentityV1,
    AdmissionContractError,
    AdmissionState,
    DurabilityHistogramSeriesV1,
    EnqueueResult,
    EnqueueStatus,
    PublicationState,
    StorageControlAssociationV1,
    StorageControlTargetV1,
    ValidatedControlDraft,
    WriterLifecycle,
    WriterMetricsSnapshotV1,
    WriterStatus,
)
from crypto_collector.storage.phases import StoragePhaseHook
from crypto_collector.storage.raw_writer import (
    NoReplaceCapability,
    _ActivePart,
    _ActivePartReservation,
    _ActivePartRotation,
    _ActivePartSet,
    _ClaimedSealedWork,
    _FinalBarrierCloseMember,
    _FinalBarrierControlDependency,
    _FinalBarrierController,
    run_storage,
)
from crypto_collector.storage.recovery import (
    PendingRecoveryControl,
    PosixRecoveryBackend,
    RecoveryBackend,
    RecoveryContext,
    RecoveryControlAdmission,
    RecoveryControlReceipt,
    RecoveryOutcome,
    RecoveryReconciliation,
    SourceDispositionResolver,
)
from crypto_collector.storage.stats import (
    MAX_DURABILITY_METRIC_STREAM_LABELS,
    OTHER_DURABILITY_METRIC_STREAM_LABEL,
    CumulativeDurabilityHistogram,
    DurabilityLedger,
    DurabilityStage,
    RollingDurabilityHistogram,
)
from crypto_collector.storage.stream_file import FrameSealRequired
from crypto_collector.storage.writer_lock import ExchangeWriterLock

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PART_SEQUENCE = re.compile(
    r"^part-(?:0|[1-9][0-9]*)-((?:0|[1-9][0-9]*))"
    r"(?:\.jsonl\.zst(?:\.partial)?|\.manifest\.json(?:\.partial)?|\.lease)$"
)
_MAX_SIGNED_INT64 = 2**63 - 1
_LOGGER = logging.getLogger(__name__)
_CLOSE_TRIGGER = {
    CloseReason.ROTATE_TIME: DurabilityTrigger.HOUR,
    CloseReason.ROTATE_SIZE: DurabilityTrigger.SIZE,
    CloseReason.CONFIG_RELOAD: DurabilityTrigger.CONFIG,
    CloseReason.SHUTDOWN: DurabilityTrigger.SHUTDOWN,
    CloseReason.RECOVERY_CONTROL: DurabilityTrigger.RECOVERY,
}


class _NoCleanupProofResolver:
    def resolve_missing(self, **_kwargs: object) -> None:
        return None


class _QueueCompletionSink:
    def __init__(self, queue: asyncio.Queue[object]) -> None:
        self._queue = queue

    def __call__(self, completion: FileSyncCompletion) -> None:
        self._queue.put_nowait(completion)


@dataclass(slots=True)
class _ServiceCommand:
    kind: str
    args: tuple[object, ...]
    future: asyncio.Future[object]
    watermark: int | None


@dataclass(frozen=True, slots=True)
class _ClaimRow:
    identity: AcceptedRecordIdentityV1
    accepted_monotonic_ns: int


@dataclass(slots=True)
class _CompletionClaim:
    part: _ActivePart
    claimed: _ClaimedSealedWork | None
    rows: tuple[_ClaimRow, ...]
    final_barrier: bool


@dataclass(frozen=True, slots=True)
class _DeferredRecord:
    record: AcceptedRecord
    identity: AcceptedRecordIdentityV1


def _normalized_root(value: object, *, field_name: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"{field_name} must be Path")
    if not value.is_absolute():
        raise ValueError(f"{field_name} must be absolute")
    normalized = Path(os.path.abspath(os.fspath(value)))
    if normalized != value or any(part in {"", ".", ".."} for part in value.parts[1:]):
        raise ValueError(f"{field_name} must be normalized")
    return normalized


def _nonempty(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a normalized nonempty string")
    return value


def _nonnegative(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < 0 or value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must be a signed-64 non-negative integer")
    return value


def _validate_metric_allowlist(value: object) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError("metric_stream_allowlist must be a tuple")
    if not value:
        raise ValueError("metric_stream_allowlist must be nonempty")
    if len(value) > MAX_DURABILITY_METRIC_STREAM_LABELS:
        raise ValueError("metric_stream_allowlist exceeds its bounded vocabulary")
    normalized = tuple(
        _nonempty(item, field_name="metric stream label") for item in value
    )
    if normalized != tuple(sorted(normalized)) or len(set(normalized)) != len(
        normalized
    ):
        raise ValueError("metric_stream_allowlist must be sorted and unique")
    if OTHER_DURABILITY_METRIC_STREAM_LABEL in normalized:
        raise ValueError("metric_stream_allowlist cannot contain the fallback label")
    return normalized


def _scan_next_part_sequence(data_root: Path, exchange: Exchange) -> int:
    exchange_root = data_root / "raw" / exchange.value
    maximum = -1
    pending = [exchange_root]
    while pending:
        directory = pending.pop()
        try:
            entries = tuple(os.scandir(directory))
        except FileNotFoundError:
            continue
        for entry in entries:
            if entry.is_symlink():
                raise RecoveryBlocked("raw sequence scan found a symbolic link")
            if entry.is_dir(follow_symlinks=False):
                pending.append(Path(entry.path))
                continue
            if not entry.is_file(follow_symlinks=False):
                raise RecoveryBlocked("raw sequence scan found an unsafe entry")
            match = _PART_SEQUENCE.fullmatch(entry.name)
            if match is not None:
                maximum = max(maximum, int(match.group(1)))
    if maximum >= _MAX_SIGNED_INT64:
        raise RecoveryBlocked("raw part sequence space is exhausted")
    return maximum + 1


def _ensure_directory_root(path: Path) -> None:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    if not all(
        type(getattr(os, name, None)) is int and getattr(os, name) != 0
        for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    ):
        raise OSError(errno.ENOTSUP, "secure directory flags are unavailable")
    current_fd = os.open(path.anchor, flags)
    try:
        for segment in path.parts[1:]:
            try:
                child_fd = os.open(segment, flags, dir_fd=current_fd)
            except FileNotFoundError:
                os.mkdir(segment, 0o750, dir_fd=current_fd)
                os.fsync(current_fd)
                child_fd = os.open(segment, flags, dir_fd=current_fd)
            os.close(current_fd)
            current_fd = child_fd
    finally:
        os.close(current_fd)


class RawWriterService:
    def __init__(
        self,
        *,
        data_root: Path,
        state_root: Path,
        exchange: Exchange,
        worker_instance_id: str,
        config_sha256: str,
        config_generation: int,
        writer_config: WriterConfig,
        ingress_config: IngressConfig,
        metric_stream_allowlist: tuple[str, ...],
        clock: Clock,
        sleeper: AsyncSleeper,
        writer_lock: ExchangeWriterLock,
        executor: ThreadPoolExecutor,
        io_limiter: StorageIoLimiter,
        recovery_backend: RecoveryBackend,
        recovery_context: RecoveryContext,
        live_coordinator: DurabilityCoordinator,
        completion_queue: asyncio.Queue[object],
        initial_part_sequence: int,
        on_slo_transition: Callable[[DurabilitySloTransition], None] | None,
        on_critical: Callable[[WriterCriticalError], None] | None,
        phase_hook: StoragePhaseHook | None,
    ) -> None:
        self._data_root = data_root
        self._state_root = state_root
        self._exchange = exchange
        self._worker_instance_id = worker_instance_id
        self._config_sha256 = config_sha256
        self._config_generation = config_generation
        self._writer_config = writer_config
        self._ingress_config = ingress_config
        self._metric_stream_allowlist = frozenset(metric_stream_allowlist)
        self._clock = clock
        self._sleeper = sleeper
        self._writer_lock = writer_lock
        self._executor = executor
        self._io_limiter = io_limiter
        self._recovery_backend = recovery_backend
        self._recovery_context = recovery_context
        self._coordinator = live_coordinator
        self._completion_queue = completion_queue
        self._on_slo_transition = on_slo_transition
        self._on_critical = on_critical
        self._owner_loop = asyncio.get_running_loop()
        self._owner_thread = threading.get_ident()

        self._resident_budget = ResidentBudget.from_config(ingress_config)
        self._parts = _ActivePartSet(
            data_root=data_root,
            exchange=exchange,
            config_sha256=config_sha256,
            config_generation=config_generation,
            zstd_level=writer_config.zstd_level,
            max_plain_frame_bytes=writer_config.max_plain_frame_bytes,
            max_compressed_size_bytes=writer_config.max_compressed_size_bytes,
            rotate_interval_ns=writer_config.rotate_interval_ns,
            durability_slo_ns=writer_config.durability_slo_ns,
            initial_part_sequence=initial_part_sequence,
            phase_hook=phase_hook,
        )
        self._ingress = RawIngress(
            config=ingress_config,
            worker_instance_id=worker_instance_id,
            config_sha256=config_sha256,
            config_generation=config_generation,
            resident_budget=self._resident_budget,
            clock=clock,
            control_association_resolver=self._resolve_control_association,
        )
        self._barrier = _FinalBarrierController(
            durability_coordinator=live_coordinator,
            completion_queue=completion_queue,
            io_limiter=io_limiter,
            storage_executor=executor,
            no_replace_capability=NoReplaceCapability.HARDLINK,
            phase_hook=phase_hook,
        )
        self._ledger = DurabilityLedger(clock=clock)
        self._histogram = CumulativeDurabilityHistogram()
        self._rolling_histogram = RollingDurabilityHistogram()
        self._slo_breached = False
        self._series: dict[
            tuple[Market | None, str], CumulativeDurabilityHistogram
        ] = {}
        self._record_charge_bytes: dict[AcceptedRecordIdentityV1, int] = {}
        self._record_stages: dict[AcceptedRecordIdentityV1, DurabilityStage] = {}
        self._control_associations: dict[
            AcceptedRecordIdentityV1, StorageControlAssociationV1
        ] = {}
        self._completion_claims: dict[str, _CompletionClaim] = {}
        self._deferred_by_generation: dict[str, list[_DeferredRecord]] = {}
        self._retiring: dict[str, _ActivePart] = {}
        self._pending_hour_retired: dict[str, _ActivePart] = {}
        self._completed_recovery_outcomes: tuple[object, ...] = ()

        self._lifecycle = WriterLifecycle.STARTING
        self._admission_state = AdmissionState.CLOSED
        self._publication_state = PublicationState.IDLE
        self._incomplete_reason: str | None = None
        self._critical_reason: WriterCriticalReason | None = None
        self._not_accepting_count = 0
        self._sync_count = 0
        self._sync_duration_total_ns = 0
        self._sync_duration_max_ns = 0
        self._slo_breach_count = 0
        self._write_failure_count = 0
        self._sync_failure_count = 0
        self._publication_failure_count = 0
        self._critical_callback_called = False
        self._last_observed_monotonic_ns = 0

        self._commands: asyncio.Queue[_ServiceCommand] = asyncio.Queue()
        self._work_event = asyncio.Event()
        self._periodic_due = False
        self._command_active = False
        self._stopping = False
        self._resources_released = False
        self._ticker_task: asyncio.Task[None] | None = None
        self._loop_task: asyncio.Task[None] | None = None
        self._close_future: asyncio.Future[object] | None = None
        self._active_close_deadline_ns: int | None = None
        self._pending_oldest_error: WriterCriticalError | None = None
        self._critical_draining = False
        self._closed_manifests: tuple[object, ...] | None = None
        self._metrics_cache = self._build_metrics_snapshot()

    @classmethod
    async def open(
        cls,
        *,
        data_root: Path,
        state_root: Path,
        exchange: Exchange,
        worker_instance_id: str,
        config_sha256: str,
        config_generation: int,
        writer_config: WriterConfig,
        ingress_config: IngressConfig,
        metric_stream_allowlist: tuple[str, ...],
        clock: Clock,
        sleeper: AsyncSleeper | None = None,
        sync_backend: SyncBackend | None = None,
        recovery_backend: RecoveryBackend | None = None,
        source_disposition_resolver: SourceDispositionResolver | None = None,
        on_slo_transition: Callable[[DurabilitySloTransition], None] | None = None,
        on_critical: Callable[[WriterCriticalError], None] | None = None,
        phase_hook: StoragePhaseHook | None = None,
    ) -> RawWriterService:
        root = _normalized_root(data_root, field_name="data_root")
        state = _normalized_root(state_root, field_name="state_root")
        if type(exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        worker = _nonempty(worker_instance_id, field_name="worker_instance_id")
        if type(config_sha256) is not str or _SHA256.fullmatch(config_sha256) is None:
            raise ValueError("config_sha256 must be lowercase SHA-256")
        generation = _nonnegative(config_generation, field_name="config_generation")
        if type(writer_config) is not WriterConfig:
            raise TypeError("writer_config must be WriterConfig")
        if type(ingress_config) is not IngressConfig:
            raise TypeError("ingress_config must be IngressConfig")
        allowlist = _validate_metric_allowlist(metric_stream_allowlist)
        if not callable(getattr(clock, "time_ns", None)) or not callable(
            getattr(clock, "monotonic_ns", None)
        ):
            raise TypeError("clock must implement time_ns and monotonic_ns")
        selected_sleeper = AsyncioSleeper() if sleeper is None else sleeper
        if not callable(getattr(selected_sleeper, "sleep_ns", None)):
            raise TypeError("sleeper must implement sleep_ns")
        selected_sync = PosixSyncBackend() if sync_backend is None else sync_backend
        if not callable(getattr(selected_sync, "sync", None)):
            raise TypeError("sync_backend must implement sync")
        selected_recovery = (
            PosixRecoveryBackend() if recovery_backend is None else recovery_backend
        )
        for method_name in (
            "reconcile",
            "bind_control_ownership",
            "acknowledge_control_durable",
        ):
            if not callable(getattr(selected_recovery, method_name, None)):
                raise TypeError("recovery_backend does not implement its protocol")
        resolver = (
            _NoCleanupProofResolver()
            if source_disposition_resolver is None
            else source_disposition_resolver
        )
        if not callable(getattr(resolver, "resolve_missing", None)):
            raise TypeError(
                "source_disposition_resolver does not implement its protocol"
            )
        if on_slo_transition is not None and not callable(on_slo_transition):
            raise TypeError("on_slo_transition must be callable or None")
        if on_critical is not None and not callable(on_critical):
            raise TypeError("on_critical must be callable or None")
        if phase_hook is not None and not callable(phase_hook):
            raise TypeError("phase_hook must be callable or None")

        writer_lock: ExchangeWriterLock | None = None
        executor: ThreadPoolExecutor | None = None
        try:
            writer_lock = ExchangeWriterLock.acquire(root, exchange=exchange)
            executor = ThreadPoolExecutor(
                max_workers=writer_config.max_sync_concurrency,
                thread_name_prefix=f"raw-{exchange.value}",
            )
            io_limiter = StorageIoLimiter(writer_config.max_sync_concurrency)
            completion_queue: asyncio.Queue[object] = asyncio.Queue()
            live_coordinator = DurabilityCoordinator(
                clock=clock,
                sync_backend=selected_sync,
                io_limiter=io_limiter,
                storage_executor=executor,
                durability_slo_ns=writer_config.durability_slo_ns,
                durability_critical_ns=writer_config.durability_critical_ns,
                completion_sink=_QueueCompletionSink(completion_queue),
            )
            recovery_coordinator = RecoveryDurabilityCoordinator(
                accounting_mode=RecoveryAccountingMode.UNMEASURED,
                clock=clock,
                sync_backend=selected_sync,
                io_limiter=io_limiter,
                storage_executor=executor,
                completion_sink=cast(
                    FileSyncCompletionSink,
                    discard_file_sync_completion,
                ),
            )
            recovery_context = RecoveryContext(
                data_root=root,
                state_root=state,
                exchange=exchange,
                worker_instance_id=worker,
                config_sha256=config_sha256,
                config_generation=generation,
                clock=clock,
                io_limiter=io_limiter,
                recovery_coordinator=recovery_coordinator,
                storage_executor=executor,
                source_disposition_resolver=resolver,
            )
            await run_storage(
                io_limiter,
                executor,
                _ensure_directory_root,
                state,
            )
            reconciliation = await selected_recovery.reconcile(recovery_context)
            initial_sequence = await run_storage(
                io_limiter,
                executor,
                _scan_next_part_sequence,
                root,
                exchange,
            )
            service = cls(
                data_root=root,
                state_root=state,
                exchange=exchange,
                worker_instance_id=worker,
                config_sha256=config_sha256,
                config_generation=generation,
                writer_config=writer_config,
                ingress_config=ingress_config,
                metric_stream_allowlist=allowlist,
                clock=clock,
                sleeper=selected_sleeper,
                writer_lock=writer_lock,
                executor=executor,
                io_limiter=io_limiter,
                recovery_backend=selected_recovery,
                recovery_context=recovery_context,
                live_coordinator=live_coordinator,
                completion_queue=completion_queue,
                initial_part_sequence=initial_sequence,
                on_slo_transition=on_slo_transition,
                on_critical=on_critical,
                phase_hook=phase_hook,
            )
            writer_lock = None
            executor = None
            service._loop_task = asyncio.create_task(service._run())
            startup = service._enqueue_command("startup", reconciliation)
            try:
                await asyncio.shield(startup)
            except BaseException:
                assert service._loop_task is not None
                await asyncio.shield(service._loop_task)
                raise
            return service
        except BaseException:
            if executor is not None:
                executor.shutdown(wait=True, cancel_futures=False)
            if writer_lock is not None:
                writer_lock.release()
            raise

    def _assert_affinity(self) -> None:
        if threading.get_ident() != self._owner_thread:
            raise WriterAffinityError("writer called from a foreign thread")
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError as error:
            raise WriterAffinityError(
                "writer requires its owning event loop"
            ) from error
        if loop is not self._owner_loop:
            raise WriterAffinityError("writer called from a foreign event loop")

    def _resolve_control_association(
        self,
        control: ValidatedControlDraft,
        identity: AcceptedRecordIdentityV1,
    ) -> StorageControlAssociationV1 | None:
        if control.association_request is None:
            return None
        request = control.association_request
        targets: list[StorageControlTargetV1] = []
        for logical in request.target_logical_identities:
            part = self._parts.active_part_for_logical_identity(
                market=logical.market,
                instrument_key=logical.instrument_key,
                logical_stream=logical.logical_stream,
            )
            if part is None:
                raise AdmissionContractError(
                    "control association target has no active raw generation"
                )
            targets.append(
                StorageControlTargetV1(
                    generation_id=part.generation_id,
                    data_relative_path=part.data_relative_path,
                )
            )
        return StorageControlAssociationV1(
            control_kind=control.control_kind,
            control_event_id=request.control_event_id,
            targets=tuple(
                sorted(
                    targets,
                    key=lambda item: (item.generation_id, item.data_relative_path),
                )
            ),
            acceptance_ordinal=identity.acceptance_ordinal,
            config_generation=identity.config_generation,
        )

    def _owned_part_for_generation(self, generation_id: str) -> _ActivePart | None:
        active = self._parts.part_for_generation(generation_id)
        if active is not None:
            return active
        return self._retiring.get(generation_id)

    def _control_part_for_identity(
        self,
        identity: AcceptedRecordIdentityV1,
    ) -> _ActivePart:
        matches: list[_ActivePart] = []
        for part in (*self._parts.active_parts(), *self._retiring.values()):
            if identity in part.pending_identities():
                matches.append(part)
                continue
            claimed = part.in_flight_claim()
            if claimed is not None and any(
                claim.identity == identity for claim in claimed.claims
            ):
                matches.append(part)
        if len(matches) != 1:
            raise ValueError(
                "associated control identity must belong to one owned generation"
            )
        return matches[0]

    def _fold_control_association(
        self,
        association: StorageControlAssociationV1,
    ) -> None:
        for target in association.targets:
            part = self._owned_part_for_generation(target.generation_id)
            if part is None or part.data_relative_path != target.data_relative_path:
                raise ValueError("associated control target is no longer owned")
            part.fold_durable_control(association)

    def _control_dependencies_for_close(
        self,
        parts: tuple[_ActivePart, ...],
    ) -> tuple[_FinalBarrierControlDependency, ...]:
        closing_ids = {part.generation_id for part in parts}
        dependencies: list[_FinalBarrierControlDependency] = []
        for identity, association in self._control_associations.items():
            if not closing_ids.intersection(
                target.generation_id for target in association.targets
            ):
                continue
            targets: list[_ActivePart] = []
            for target in association.targets:
                part = self._owned_part_for_generation(target.generation_id)
                if part is None or part.data_relative_path != target.data_relative_path:
                    raise ValueError("associated close target is no longer owned")
                targets.append(part)
            dependencies.append(
                _FinalBarrierControlDependency(
                    control_part=self._control_part_for_identity(identity),
                    control_identity=identity,
                    association=association,
                    targets=tuple(targets),
                )
            )
        return tuple(dependencies)

    def _enqueue_command(self, kind: str, *args: object) -> asyncio.Future[object]:
        future: asyncio.Future[object] = self._owner_loop.create_future()
        self._commands.put_nowait(
            _ServiceCommand(
                kind,
                args,
                future,
                self._ingress.acceptance_ordinal_high_water(),
            )
        )
        self._work_event.set()
        return future

    def try_accept(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> EnqueueResult:
        self._assert_affinity()
        if type(draft) is not NativeEventDraft:
            raise TypeError("draft must be NativeEventDraft")
        if (
            self._admission_state is not AdmissionState.OPEN
            or draft.exchange is not self._exchange
        ):
            self._not_accepting_count += 1
            result = EnqueueResult(
                status=EnqueueStatus.NOT_ACCEPTING,
                record=None,
                record_identity=None,
            )
            self._refresh_metrics_cache()
            return result
        result = self._ingress.try_accept(draft, source=source, shard=shard)
        if result.accepted:
            assert result.record is not None
            assert result.record_identity is not None
            identity = result.record_identity
            self._ledger.register_accepted(
                record_id=identity,
                accepted_monotonic_ns=result.record.accepted_monotonic_ns,
            )
            self._record_charge_bytes[identity] = self._resident_budget.charge_bytes(
                identity
            )
            self._record_stages[identity] = DurabilityStage.QUEUED
            self._work_event.set()
        self._refresh_metrics_cache()
        return result

    async def sync_now(self) -> tuple[DurabilityBatch, ...]:
        self._assert_affinity()
        future = self._enqueue_command("sync")
        return cast(tuple[DurabilityBatch, ...], await asyncio.shield(future))

    async def rotate_due_files(self) -> tuple[object, ...]:
        self._assert_affinity()
        future = self._enqueue_command("rotate_due")
        return cast(tuple[object, ...], await asyncio.shield(future))

    async def rotate_for_config(
        self,
        config_sha256: str,
        config_generation: int,
    ) -> tuple[object, ...]:
        self._assert_affinity()
        if type(config_sha256) is not str or _SHA256.fullmatch(config_sha256) is None:
            raise ValueError("config_sha256 must be lowercase SHA-256")
        generation = _nonnegative(
            config_generation,
            field_name="config_generation",
        )
        if generation <= self._config_generation:
            raise ValueError("config_generation must be strictly greater")
        if self._lifecycle is not WriterLifecycle.ACCEPTING:
            raise RuntimeError("config rotation requires an accepting writer")
        if self._admission_state is AdmissionState.OPEN:
            self._admission_state = AdmissionState.CLOSED
            self._lifecycle = WriterLifecycle.ROTATING
            self._refresh_metrics_cache()
        future = self._enqueue_command("rotate_config", config_sha256, generation)
        return cast(tuple[object, ...], await asyncio.shield(future))

    async def close_all(
        self,
        reason: CloseReason,
        deadline_ns: int,
    ) -> tuple[object, ...]:
        self._assert_affinity()
        if type(reason) is not CloseReason or reason in {
            CloseReason.RECOVERY,
            CloseReason.RECOVERY_CONTROL,
        }:
            raise ValueError("close_all requires a normal close reason")
        deadline = _nonnegative(deadline_ns, field_name="deadline_ns")
        if self._close_future is None:
            self._admission_state = AdmissionState.CLOSED
            if self._lifecycle is not WriterLifecycle.CRITICAL:
                self._lifecycle = WriterLifecycle.CLOSING
            self._refresh_metrics_cache()
            self._close_future = self._enqueue_command("close", reason, deadline)
        return cast(tuple[object, ...], await asyncio.shield(self._close_future))

    async def mark_incomplete(self, reason: str) -> None:
        self._assert_affinity()
        normalized = _nonempty(reason, field_name="reason")
        self._admission_state = AdmissionState.CLOSED
        future = self._enqueue_command("incomplete", normalized)
        await asyncio.shield(future)

    def status(self) -> WriterStatus:
        self._assert_affinity()
        return self._build_status()

    def metrics_snapshot(self) -> WriterMetricsSnapshotV1:
        self._assert_affinity()
        return self._metrics_cache

    def _stage_bytes(self, stage: DurabilityStage) -> int:
        return sum(
            self._record_charge_bytes[identity]
            for identity, current in self._record_stages.items()
            if current is stage
        )

    def _build_status(self) -> WriterStatus:
        queued = self._ledger.stage_count(DurabilityStage.QUEUED)
        buffered = self._ledger.stage_count(DurabilityStage.BUFFERED)
        in_flight = self._ledger.stage_count(DurabilityStage.IN_FLIGHT)
        active = self._parts.active_parts()
        dirty = sum(
            1
            for part in (*active, *self._retiring.values())
            if part.pending_identities() or part.in_flight_claim() is not None
        )
        return WriterStatus(
            lifecycle=self._lifecycle,
            admission_state=self._admission_state,
            publication_state=self._publication_state,
            accepting=self._admission_state is AdmissionState.OPEN,
            incomplete=self._incomplete_reason is not None,
            incomplete_reason=self._incomplete_reason,
            critical_reason=self._critical_reason,
            queued_records=queued,
            queued_bytes=self._stage_bytes(DurabilityStage.QUEUED),
            buffered_records=buffered,
            buffered_bytes=self._stage_bytes(DurabilityStage.BUFFERED),
            in_flight_records=in_flight,
            in_flight_bytes=self._stage_bytes(DurabilityStage.IN_FLIGHT),
            active_logical_generation_count=(
                self._parts.active_logical_generation_count()
            ),
            retiring_generation_count=len(self._retiring),
            open_file_descriptor_count=sum(
                not part.stream_file.closed
                for part in (*active, *self._retiring.values())
            ),
            dirty_file_count=dirty,
            sync_inflight=len(self._completion_claims),
            oldest_unpersisted_age_ns=self._ledger.oldest_unpersisted_age_ns(),
            accepted_record_count=self._ledger.accepted_count,
            durable_record_count=self._ledger.durable_count,
            unpersisted_record_count=self._ledger.unpersisted_count,
            uncertain_record_count=self._ledger.uncertain_count,
        )

    def _sample_monotonic(self) -> int:
        sampled = _nonnegative(
            self._clock.monotonic_ns(), field_name="clock.monotonic_ns()"
        )
        self._last_observed_monotonic_ns = max(
            sampled,
            self._last_observed_monotonic_ns + 1,
        )
        return self._last_observed_monotonic_ns

    def _evaluate_slo(self, *, observed_monotonic_ns: int) -> None:
        rolling = self._rolling_histogram.snapshot(
            now_monotonic_ns=observed_monotonic_ns
        )
        breached = (
            rolling.lag_max_ns is not None
            and rolling.lag_max_ns > self._writer_config.durability_slo_ns
        ) or (
            rolling.lag_p99_ns is not None
            and rolling.lag_p99_ns > self._writer_config.durability_slo_ns
        )
        if breached == self._slo_breached:
            return
        self._slo_breached = breached
        if breached:
            self._slo_breach_count += 1
        transition = DurabilitySloTransition(
            state=(
                DurabilitySloState.BREACHED
                if breached
                else DurabilitySloState.RECOVERED
            ),
            observed_monotonic_ns=observed_monotonic_ns,
            rolling_p99_ns=rolling.lag_p99_ns,
            rolling_max_ns=rolling.lag_max_ns,
        )
        if self._on_slo_transition is None:
            return
        try:
            self._on_slo_transition(transition)
        except BaseException as error:
            critical = WriterCriticalError(
                reason=WriterCriticalReason.SLO_TRANSITION_CALLBACK_FAILED,
                affected_generation_ids=tuple(
                    part.generation_id
                    for part in (*self._parts.active_parts(), *self._retiring.values())
                ),
                completed_batches=(),
                message="durability SLO transition callback failed",
            )
            raise critical from error

    def _begin_oldest_critical(self) -> WriterCriticalError | None:
        if self._pending_oldest_error is not None:
            return self._pending_oldest_error
        critical_age = self._ledger.classify_critical_age(
            durability_critical_ns=self._writer_config.durability_critical_ns
        )
        if critical_age is None:
            return None
        critical = WriterCriticalError(
            reason=WriterCriticalReason.OLDEST_UNPERSISTED_AGE,
            affected_generation_ids=tuple(
                sorted(
                    part.generation_id
                    for part in (
                        *self._parts.active_parts(),
                        *self._retiring.values(),
                    )
                )
            ),
            completed_batches=(),
            message="oldest raw record exceeded its durability deadline",
        )
        self._pending_oldest_error = critical
        self._critical_reason = critical.reason
        self._lifecycle = WriterLifecycle.CRITICAL
        self._admission_state = AdmissionState.CLOSED
        self._incomplete_reason = critical.reason.value
        if not self._critical_callback_called and self._on_critical is not None:
            self._critical_callback_called = True
            try:
                self._on_critical(critical)
            except BaseException as callback_error:  # noqa: BLE001 - retain ownership
                critical.add_note(
                    f"on_critical callback also failed: {type(callback_error).__name__}"
                )
        self._refresh_metrics_cache()
        return critical

    async def _finish_oldest_critical_drain(self) -> None:
        if self._pending_oldest_error is None or self._critical_draining:
            return
        self._critical_draining = True
        try:
            await self._drain_ingress()
            while True:
                batch = await self._sync_parts(
                    self._parts.active_parts(),
                    DurabilityTrigger.PERIODIC,
                )
                if batch is None:
                    break
        finally:
            self._critical_draining = False

    def _sample_wall(self) -> int:
        return _nonnegative(self._clock.time_ns(), field_name="clock.time_ns()")

    def _build_metrics_snapshot(self) -> WriterMetricsSnapshotV1:
        status = self._build_status()
        ingress = self._ingress.snapshot_for_test()
        resident = self._resident_budget.snapshot()
        aggregate = self._histogram.snapshot()
        series: list[DurabilityHistogramSeriesV1] = []
        for (market, stream), histogram in sorted(
            self._series.items(),
            key=lambda item: (
                "" if item[0][0] is None else item[0][0].value,
                item[0][1],
            ),
        ):
            snapshot = histogram.snapshot()
            series.append(
                DurabilityHistogramSeriesV1(
                    exchange=self._exchange,
                    market=market,
                    logical_stream=stream,
                    bucket_counts=snapshot.bucket_counts,
                    sample_count=snapshot.sample_count,
                    lag_p50_ns=snapshot.lag_p50_ns,
                    lag_p95_ns=snapshot.lag_p95_ns,
                    lag_p99_ns=snapshot.lag_p99_ns,
                    lag_max_ns=snapshot.lag_max_ns,
                )
            )
        return WriterMetricsSnapshotV1(
            observed_monotonic_ns=self._sample_monotonic(),
            exchange=self._exchange,
            worker_instance_id=self._worker_instance_id,
            config_sha256=self._config_sha256,
            config_generation=self._config_generation,
            lifecycle=self._lifecycle,
            admission_state=self._admission_state,
            publication_state=self._publication_state,
            critical_reason=self._critical_reason,
            acceptance_ordinal_high_water=(
                None
                if self._ledger.accepted_count == 0
                else self._ledger.accepted_count - 1
            ),
            accepted_record_count=self._ledger.accepted_count,
            durable_record_count=self._ledger.durable_count,
            unpersisted_record_count=self._ledger.unpersisted_count,
            uncertain_record_count=self._ledger.uncertain_count,
            queued_records=status.queued_records,
            queued_bytes=status.queued_bytes,
            buffered_records=status.buffered_records,
            buffered_bytes=status.buffered_bytes,
            in_flight_records=status.in_flight_records,
            in_flight_bytes=status.in_flight_bytes,
            resident_record_bytes=resident.resident_bytes,
            resident_control_records=resident.control_resident_records,
            resident_control_bytes=resident.control_resident_bytes,
            oldest_unpersisted_age_ns=status.oldest_unpersisted_age_ns,
            enqueue_high_water_count=ingress.enqueue_high_water_count,
            normal_overflow_count=ingress.normal_overflow_count,
            control_overflow_count=ingress.control_overflow_count,
            not_accepting_count=self._not_accepting_count,
            active_logical_generation_count=status.active_logical_generation_count,
            retiring_generation_count=status.retiring_generation_count,
            open_file_descriptor_count=status.open_file_descriptor_count,
            sync_inflight=status.sync_inflight,
            durability_histogram_schema_version=1,
            durability_bucket_counts=aggregate.bucket_counts,
            durability_sample_count=aggregate.sample_count,
            durability_lag_p50_ns=aggregate.lag_p50_ns,
            durability_lag_p95_ns=aggregate.lag_p95_ns,
            durability_lag_p99_ns=aggregate.lag_p99_ns,
            durability_lag_max_ns=aggregate.lag_max_ns,
            durability_histogram_series=tuple(series),
            sync_count=self._sync_count,
            sync_duration_total_ns=self._sync_duration_total_ns,
            sync_duration_max_ns=self._sync_duration_max_ns,
            slo_breach_count=self._slo_breach_count,
            write_failure_count=self._write_failure_count,
            sync_failure_count=self._sync_failure_count,
            publication_failure_count=self._publication_failure_count,
        )

    def _refresh_metrics_cache(self) -> None:
        self._metrics_cache = self._build_metrics_snapshot()

    async def _periodic_timer(self) -> None:
        while not self._stopping:
            await self._sleeper.sleep_ns(self._writer_config.flush_interval_ns)
            if self._stopping:
                return
            self._periodic_due = True
            self._work_event.set()

    async def _ensure_part(
        self,
        record: AcceptedRecord,
        identity: AcceptedRecordIdentityV1,
    ) -> tuple[_ActivePart, _ActivePart | None]:
        current = self._parts.active_entry_for(record)
        received_hour = record.envelope.received_at_ns // (60 * 60 * 1_000_000_000)
        if type(current) is _ActivePart and current.received_hour == received_hour:
            return current, None
        if (
            type(current) is _ActivePartReservation
            and current.received_hour == received_hour
        ):
            reservation = current
        else:
            reservation = self._parts.reserve_part(record)
        part = await run_storage(
            self._io_limiter,
            self._executor,
            self._parts.materialize_reserved,
            reservation,
            record,
            identity,
            created_at_ns=reservation.created_at_ns,
        )
        if current is None:
            self._parts.install_reserved(reservation, part)
            return part, None
        if current is reservation:
            self._parts.install_reserved(reservation, part)
            return part, None
        closed_at_ns = max(self._sample_wall(), current.created_at_ns)
        retired = self._parts.replace_reserved_for_hour(
            reservation,
            part,
            closed_at_ns=closed_at_ns,
        )
        if retired is not None:
            self._retiring[retired.generation_id] = retired
        return part, retired

    def _mark_buffered(self, identity: AcceptedRecordIdentityV1) -> None:
        self._ledger.mark_buffered(identity)
        self._record_stages[identity] = DurabilityStage.BUFFERED

    def _mark_claim_in_flight(
        self,
        part: _ActivePart,
        claimed: _ClaimedSealedWork,
    ) -> tuple[_ClaimRow, ...]:
        rows = tuple(
            _ClaimRow(claim.identity, claim.accepted_monotonic_ns)
            for claim in claimed.claims
        )
        for row in rows:
            self._ledger.mark_in_flight(row.identity)
            self._record_stages[row.identity] = DurabilityStage.IN_FLIGHT
        return rows

    def _defer_record(
        self,
        part: _ActivePart,
        record: AcceptedRecord,
        identity: AcceptedRecordIdentityV1,
    ) -> None:
        self._mark_buffered(identity)
        self._deferred_by_generation.setdefault(part.generation_id, []).append(
            _DeferredRecord(record, identity)
        )

    @staticmethod
    def _warn_oversized(part: _ActivePart, record: AcceptedRecord) -> None:
        _LOGGER.warning(
            "raw record exceeds configured frame size",
            extra={
                "generation_id": part.generation_id,
                "logical_stream": part.logical_stream,
                "record_bytes": len(record.encoded_jsonl),
                "max_plain_frame_bytes": part.stream_file.max_plain_frame_bytes,
            },
        )

    async def _drain_deferred(self, *, watermark: int | None) -> None:
        for generation_id in tuple(self._deferred_by_generation):
            part = self._owned_part_for_generation(generation_id)
            if part is None:
                raise ValueError("deferred record generation is no longer owned")
            deferred = self._deferred_by_generation[generation_id]
            while deferred:
                if (
                    watermark is not None
                    and deferred[0].identity.acceptance_ordinal > watermark
                ):
                    break
                if part.in_flight_claim() is not None:
                    break
                item = deferred[0]
                try:
                    part.append_accepted(item.record, item.identity)
                except FrameSealRequired:
                    await self._sync_parts((part,), DurabilityTrigger.SIZE)
                    try:
                        part.append_accepted(item.record, item.identity)
                    except FrameSealRequired:
                        self._warn_oversized(part, item.record)
                        claimed = part.seal_oversized(item.record, item.identity)
                        await self._sync_claims(
                            ((part, claimed),),
                            DurabilityTrigger.SIZE,
                        )
                deferred.pop(0)
            if not deferred:
                del self._deferred_by_generation[generation_id]

    def _can_drain_without_storage_io(self, shard: str) -> bool:
        result = self._ingress.peek_one(shard)
        if result is None:
            return False
        assert result.record is not None
        part = self._parts.active_part_for(result.record)
        if part is None:
            return False
        received_hour = result.record.envelope.received_at_ns // (
            60 * 60 * 1_000_000_000
        )
        return part.received_hour == received_hour

    async def _drain_ingress(
        self,
        *,
        allow_storage_io: bool = True,
        watermark: int | None = None,
    ) -> None:
        if allow_storage_io:
            await self._drain_deferred(watermark=watermark)
        while True:
            shards = self._ingress.nonempty_shards()
            if not shards:
                return
            progressed = False
            for shard in shards:
                head = self._ingress.peek_one(shard)
                if head is None:
                    continue
                assert head.record_identity is not None
                if (
                    watermark is not None
                    and head.record_identity.acceptance_ordinal > watermark
                ):
                    continue
                if not allow_storage_io and not self._can_drain_without_storage_io(
                    shard
                ):
                    continue
                result = self._ingress.drain_one(shard)
                if result is None:
                    continue
                progressed = True
                assert result.record is not None
                assert result.record_identity is not None
                record = result.record
                identity = result.record_identity
                association = self._ingress.take_control_association(identity)
                if association is not None:
                    self._control_associations[identity] = association
                part, hour_retired = await self._ensure_part(record, identity)
                if part.generation_id in self._deferred_by_generation:
                    self._defer_record(part, record, identity)
                    continue
                oversized_synced = False
                try:
                    part.append_accepted(record, identity)
                except FrameSealRequired:
                    if not allow_storage_io or part.in_flight_claim() is not None:
                        self._defer_record(part, record, identity)
                        continue
                    await self._sync_parts((part,), DurabilityTrigger.SIZE)
                    try:
                        part.append_accepted(record, identity)
                    except FrameSealRequired:
                        self._warn_oversized(part, record)
                        claimed = part.seal_oversized(record, identity)
                        self._mark_buffered(identity)
                        await self._sync_claims(
                            ((part, claimed),), DurabilityTrigger.SIZE
                        )
                        oversized_synced = True
                if not oversized_synced:
                    self._mark_buffered(identity)
                if hour_retired is not None:
                    self._pending_hour_retired[hour_retired.generation_id] = (
                        hour_retired
                    )
            self._refresh_metrics_cache()
            if not progressed:
                return

    async def _sync_parts(
        self,
        parts: tuple[_ActivePart, ...],
        trigger: DurabilityTrigger,
    ) -> DurabilityBatch | None:
        claimed: list[tuple[_ActivePart, _ClaimedSealedWork]] = []
        for part in parts:
            work = part.seal_for_sync()
            if work is not None:
                claimed.append((part, work))
        if not claimed:
            return None
        return await self._sync_claims(tuple(claimed), trigger)

    async def _rotate_due_parts(self) -> tuple[object, ...]:
        now = self._sample_wall()
        seal_ordinal = self._ingress.acceptance_ordinal_high_water()
        plans = (
            ()
            if seal_ordinal is None
            else self._parts.plan_due_rotations(
                now_ns=now,
                seal_acceptance_ordinal=seal_ordinal,
            )
        )
        self._parts.begin_rotations(plans)
        for plan in plans:
            self._retiring[plan.current.generation_id] = plan.current
        materialized: list[tuple[_ActivePartRotation, _ActivePart]] = []
        try:
            for plan in plans:
                coroutine = run_storage(
                    self._io_limiter,
                    self._executor,
                    self._parts.materialize_rotation,
                    plan,
                )
                try:
                    task = asyncio.create_task(coroutine)
                except BaseException:
                    coroutine.close()
                    raise
                replacement = cast(_ActivePart, await self._pump_task(task))
                materialized.append((plan, replacement))
            self._parts.commit_rotations(tuple(materialized))
        except BaseException as rotation_error:
            for _plan, replacement in materialized:
                try:
                    await run_storage(
                        self._io_limiter,
                        self._executor,
                        replacement.discard_empty,
                    )
                except BaseException as cleanup_error:  # noqa: BLE001
                    rotation_error.add_note(
                        f"empty replacement cleanup failed: {cleanup_error!r}"
                    )
            raise
        members = self._pending_hour_close_members() + tuple(
            _FinalBarrierCloseMember(
                part=plan.current,
                reason=plan.reason,
                closed_at_ns=plan.closed_at_ns,
            )
            for plan in plans
        )
        if not members:
            return ()
        self._lifecycle = WriterLifecycle.ROTATING
        reasons = {member.reason for member in members}
        trigger = (
            _CLOSE_TRIGGER[next(iter(reasons))]
            if len(reasons) == 1
            else DurabilityTrigger.BARRIER
        )
        manifests = await self._close_members(
            members,
            trigger=trigger,
        )
        self._clear_pending_hour_members(members)
        self._lifecycle = WriterLifecycle.ACCEPTING
        self._refresh_metrics_cache()
        return manifests

    def _pending_hour_close_members(self) -> tuple[_FinalBarrierCloseMember, ...]:
        return tuple(
            _FinalBarrierCloseMember(
                part=part,
                reason=CloseReason.ROTATE_TIME,
                closed_at_ns=cast(int, part.closed_at_ns),
            )
            for part in sorted(
                self._pending_hour_retired.values(),
                key=lambda item: item.data_relative_path,
            )
        )

    def _clear_pending_hour_members(
        self,
        members: tuple[_FinalBarrierCloseMember, ...],
    ) -> None:
        for member in members:
            self._pending_hour_retired.pop(member.part.generation_id, None)

    async def _close_pending_hour_parts(self) -> tuple[object, ...]:
        members = self._pending_hour_close_members()
        if not members:
            return ()
        manifests = await self._close_members(
            members,
            trigger=DurabilityTrigger.HOUR,
        )
        self._clear_pending_hour_members(members)
        return manifests

    async def _sync_claims(
        self,
        claims: tuple[tuple[_ActivePart, _ClaimedSealedWork], ...],
        trigger: DurabilityTrigger,
    ) -> DurabilityBatch:
        for part, claimed in claims:
            rows = self._mark_claim_in_flight(part, claimed)
            self._completion_claims[part.generation_id] = _CompletionClaim(
                part=part,
                claimed=claimed,
                rows=rows,
                final_barrier=False,
            )
        coroutine = self._coordinator.sync_batch(
            tuple(claimed.work for _part, claimed in claims),
            trigger=trigger,
        )
        try:
            task = asyncio.create_task(coroutine)
        except BaseException:
            coroutine.close()
            raise
        for part, claimed in claims:
            part.bind_claim_batch_task(claimed, task)
        batch = cast(DurabilityBatch, await self._pump_task(task))
        if self._pending_oldest_error is not None and not self._critical_draining:
            await self._finish_oldest_critical_drain()
            raise self._pending_oldest_error
        return batch

    async def _close_parts(
        self,
        parts: tuple[_ActivePart, ...],
        *,
        reason: CloseReason,
        closed_at_ns: int,
    ) -> tuple[object, ...]:
        return await self._close_members(
            tuple(
                _FinalBarrierCloseMember(
                    part=part,
                    reason=reason,
                    closed_at_ns=closed_at_ns,
                )
                for part in parts
            ),
            trigger=_CLOSE_TRIGGER[reason],
        )

    async def _close_members(
        self,
        members: tuple[_FinalBarrierCloseMember, ...],
        *,
        trigger: DurabilityTrigger,
    ) -> tuple[object, ...]:
        empty_members = tuple(
            member for member in members if member.part.record_count == 0
        )
        members = tuple(member for member in members if member.part.record_count != 0)
        for member in empty_members:
            part = member.part
            await run_storage(
                self._io_limiter,
                self._executor,
                part.discard_empty,
            )
            self._retiring.pop(part.generation_id, None)
        if not members:
            return ()
        parts = tuple(member.part for member in members)
        for part in parts:
            self._retiring[part.generation_id] = part
        dependencies = self._control_dependencies_for_close(parts)
        work_parts = list(parts)
        for dependency in dependencies:
            if dependency.control_part not in work_parts:
                work_parts.append(dependency.control_part)
        for part in work_parts:
            if part.generation_id in self._completion_claims:
                continue
            rows = tuple(
                _ClaimRow(claim.identity, claim.accepted_monotonic_ns)
                for claim in part._pending_claims
            )
            for row in rows:
                self._ledger.mark_in_flight(row.identity)
                self._record_stages[row.identity] = DurabilityStage.IN_FLIGHT
            self._completion_claims[part.generation_id] = _CompletionClaim(
                part=part,
                claimed=None,
                rows=rows,
                final_barrier=True,
            )
        self._publication_state = PublicationState.FINAL_SYNC
        self._refresh_metrics_cache()
        task = asyncio.create_task(
            self._barrier.close_mixed_group(
                members,
                trigger=trigger,
                control_dependencies=dependencies,
            )
        )
        try:
            manifests = cast(tuple[object, ...], await self._pump_task(task))
        except BaseException as error:
            if not (
                isinstance(error, WriterCriticalError)
                and error.reason is WriterCriticalReason.CLOSE_DEADLINE
            ):
                self._publication_failure_count += 1
            self._publication_state = PublicationState.FAILED
            raise
        self._publication_state = PublicationState.IDLE
        for part in parts:
            self._retiring.pop(part.generation_id, None)
        self._refresh_metrics_cache()
        return manifests

    async def _pump_task(self, task: asyncio.Task[object]) -> object:
        wake_after_task = False
        while True:
            while True:
                try:
                    message = self._completion_queue.get_nowait()
                except asyncio.QueueEmpty:
                    break
                self._completion_queue.task_done()
                self._handle_completion(message)
            if task.done() and self._completion_claims:
                unowned_final = tuple(
                    generation_id
                    for generation_id, claim in self._completion_claims.items()
                    if claim.final_barrier
                    and not self._barrier.owns_generation(generation_id)
                )
                for generation_id in unowned_final:
                    self._completion_claims.pop(generation_id, None)
                if unowned_final:
                    self._refresh_metrics_cache()
            if task.done() and not self._completion_claims:
                if wake_after_task:
                    self._work_event.set()
                return task.result()
            get_message = asyncio.create_task(self._completion_queue.get())
            wake = asyncio.create_task(self._work_event.wait())
            done, _pending = await asyncio.wait(
                (task, get_message, wake),
                return_when=asyncio.FIRST_COMPLETED,
            )
            if get_message in done:
                message = get_message.result()
                self._completion_queue.task_done()
                self._handle_completion(message)
            if wake in done:
                self._work_event.clear()
                oldest_error = self._begin_oldest_critical()
                if oldest_error is not None:
                    wake_after_task = True
                elif (
                    self._lifecycle is not WriterLifecycle.STARTING
                    and self._commands.empty()
                    and (not self._command_active or bool(self._retiring))
                ):
                    await self._drain_ingress(allow_storage_io=False)
                else:
                    wake_after_task = True
                wake_after_task = wake_after_task or self._periodic_due
            for waiter in (get_message, wake):
                if waiter in done:
                    continue
                waiter.cancel()
                try:
                    await waiter
                except asyncio.CancelledError:
                    pass
            if task.done() and not self._completion_claims:
                if wake_after_task:
                    self._work_event.set()
                return task.result()

    def _handle_completion(self, message: object) -> None:
        try:
            if type(message) is FileSyncCompleted:
                generation_id = message.result.generation_id
                claim = self._completion_claims.get(generation_id)
                if claim is None:
                    if not self._barrier.handle_message(message):
                        raise ValueError("unknown file sync completion")
                    return
                try:
                    if claim.final_barrier:
                        barrier_message: FileSyncCompleted | FileSyncFailed = message
                        barrier_error = self._pending_oldest_error
                        deadline = self._active_close_deadline_ns
                        if (
                            barrier_error is None
                            and claim.rows
                            and deadline is not None
                            and self._sample_monotonic() >= deadline
                        ):
                            barrier_error = WriterCriticalError(
                                reason=WriterCriticalReason.CLOSE_DEADLINE,
                                affected_generation_ids=tuple(sorted(self._retiring)),
                                completed_batches=(),
                                message="raw writer close deadline elapsed",
                            )
                        if barrier_error is not None:
                            barrier_message = FileSyncFailed(
                                generation_id, barrier_error
                            )
                        if not self._barrier.handle_message(barrier_message):
                            raise ValueError(
                                "final barrier rejected its file completion"
                            )
                    else:
                        assert claim.claimed is not None
                        claim.part.apply_completion(claim.claimed, message.result)
                    self._account_durable(claim, message.result)
                finally:
                    self._completion_claims.pop(generation_id, None)
            elif type(message) is FileSyncFailed:
                generation_id = message.generation_id
                claim = self._completion_claims.get(generation_id)
                if claim is None:
                    if not self._barrier.handle_message(message):
                        raise ValueError("unknown file sync failure")
                    return
                try:
                    if claim.final_barrier:
                        if not self._barrier.handle_message(message):
                            raise ValueError("final barrier rejected its file failure")
                    else:
                        assert claim.claimed is not None
                        claim.part.apply_failure(claim.claimed, message.error)
                    self._account_uncertain(claim, message.error)
                finally:
                    self._completion_claims.pop(generation_id, None)
            elif not self._barrier.handle_message(message):
                raise ValueError("unknown storage completion message")
        finally:
            self._refresh_metrics_cache()

    def _account_durable(
        self,
        claim: _CompletionClaim,
        result: FileDurabilityResult,
    ) -> None:
        if result.record_count != len(claim.rows):
            raise ValueError("file completion count does not match service claims")
        completed = result.sync_completed_monotonic_ns
        if completed is None:
            raise ValueError("file completion lacks its monotonic timestamp")
        for row in claim.rows:
            lag = completed - row.accepted_monotonic_ns
            if lag < 0:
                raise ValueError("file completion precedes record acceptance")
            association = self._control_associations.get(row.identity)
            if association is not None and not claim.final_barrier:
                self._fold_control_association(association)
            self._ledger.mark_durable(row.identity)
            self._record_stages.pop(row.identity, None)
            self._record_charge_bytes.pop(row.identity)
            self._resident_budget.release(row.identity)
            self._histogram.add(lag)
            self._rolling_histogram.add(
                lag_ns=lag,
                sync_completed_monotonic_ns=completed,
            )
            stream = (
                row.identity.logical_stream
                if row.identity.logical_stream in self._metric_stream_allowlist
                else OTHER_DURABILITY_METRIC_STREAM_LABEL
            )
            histogram = self._series.setdefault(
                (row.identity.market, stream), CumulativeDurabilityHistogram()
            )
            histogram.add(lag)
            self._control_associations.pop(row.identity, None)
        self._sync_count += 1
        self._sync_duration_total_ns += result.sync_duration_ns
        self._sync_duration_max_ns = max(
            self._sync_duration_max_ns, result.sync_duration_ns
        )
        self._evaluate_slo(observed_monotonic_ns=completed)

    def _account_uncertain(
        self,
        claim: _CompletionClaim,
        error: BaseException,
    ) -> None:
        for row in claim.rows:
            self._ledger.mark_uncertain(row.identity)
            self._record_stages.pop(row.identity, None)
            self._record_charge_bytes.pop(row.identity)
            self._resident_budget.release(row.identity)
            self._control_associations.pop(row.identity, None)
        reason = (
            error.reason
            if isinstance(error, FilePersistenceError)
            else WriterCriticalReason.SYNC_FAILED
        )
        if reason is WriterCriticalReason.WRITE_FAILED:
            self._write_failure_count += 1
        else:
            self._sync_failure_count += 1

    async def _process_pending_recovery_control(
        self,
        pending: PendingRecoveryControl,
    ) -> RecoveryOutcome:
        result = self._ingress.try_accept(
            pending.draft,
            source=SourceContext.internal(),
            shard="_control",
        )
        if not result.accepted:
            raise RecoveryBlocked("reserved recovery control admission was rejected")
        assert result.record is not None
        assert result.record_identity is not None
        drained = self._ingress.drain_one("_control")
        if drained is not result:
            raise AssertionError("startup control was not the reserved queue head")
        record = result.record
        identity = result.record_identity
        self._ledger.register_accepted(
            record_id=identity,
            accepted_monotonic_ns=record.accepted_monotonic_ns,
        )
        self._record_charge_bytes[identity] = self._resident_budget.charge_bytes(
            identity
        )
        self._record_stages[identity] = DurabilityStage.QUEUED

        reservation = self._parts.reserve_part(record)
        control_data_relative_path = (
            reservation.partial_path.relative_to(self._data_root)
            .as_posix()
            .removesuffix(".partial")
        )
        control_manifest_relative_path = manifest_path_for_data(
            control_data_relative_path
        ).as_posix()
        association = (
            None
            if pending.target is None
            else StorageControlAssociationV1(
                schema_version=1,
                control_kind="recovery_reconciled",
                control_event_id=pending.recovery_control_event_id,
                targets=(
                    StorageControlTargetV1(
                        generation_id=pending.target.generation_id,
                        data_relative_path=pending.target.data_relative_path,
                    ),
                ),
                acceptance_ordinal=identity.acceptance_ordinal,
                config_generation=identity.config_generation,
            )
        )
        control_frame_bytes = zstandard.ZstdCompressor(
            level=self._writer_config.zstd_level,
            write_checksum=True,
            write_content_size=True,
        ).compress(record.encoded_jsonl)
        admission = RecoveryControlAdmission(
            transaction_id=pending.transaction_id,
            recovery_control_event_id=pending.recovery_control_event_id,
            control_record=record,
            control_record_identity=identity,
            control_generation_id=reservation.generation_id,
            control_data_relative_path=control_data_relative_path,
            control_manifest_relative_path=control_manifest_relative_path,
            association=association,
            control_frame_bytes=control_frame_bytes,
            zstd_level=self._writer_config.zstd_level,
            max_plain_frame_bytes=self._writer_config.max_plain_frame_bytes,
        )
        part: _ActivePart | None = None
        try:
            await self._recovery_backend.bind_control_ownership(
                self._recovery_context,
                pending=pending,
                admission=admission,
            )
            carrier_created_at_ns = self._sample_wall()
            part = await run_storage(
                self._io_limiter,
                self._executor,
                self._parts.materialize_reserved,
                reservation,
                record,
                identity,
                created_at_ns=carrier_created_at_ns,
            )
            part.append_accepted(record, identity)
            self._mark_buffered(identity)
            await self._close_parts(
                (part,),
                reason=CloseReason.RECOVERY_CONTROL,
                closed_at_ns=self._sample_wall(),
            )
            receipt = RecoveryControlReceipt(
                transaction_id=pending.transaction_id,
                recovery_control_event_id=pending.recovery_control_event_id,
                control_record_identity=identity,
                control_generation_id=reservation.generation_id,
                control_data_relative_path=control_data_relative_path,
                control_encoded_sha256=hashlib.sha256(record.encoded_jsonl).hexdigest(),
                durable_at_monotonic_ns=self._sample_monotonic(),
            )
            return await self._recovery_backend.acknowledge_control_durable(
                self._recovery_context,
                pending=pending,
                receipt=receipt,
            )
        except BaseException as error:
            if part is not None and not part.stream_file.closed:
                part.close_fd_for_test()
            critical = WriterCriticalError(
                reason=WriterCriticalReason.CONTROL_DURABILITY_FAILED,
                affected_generation_ids=(reservation.generation_id,),
                completed_batches=(),
                message="startup recovery control did not become durable",
            )
            raise critical from error

    async def _execute_command(self, command: _ServiceCommand) -> object:
        if command.kind == "startup":
            reconciliation = cast(RecoveryReconciliation, command.args[0])
            outcomes = list(reconciliation.completed_outcomes)
            for pending in reconciliation.pending_controls:
                outcomes.append(await self._process_pending_recovery_control(pending))
            self._completed_recovery_outcomes = tuple(outcomes)
            self._lifecycle = WriterLifecycle.ACCEPTING
            self._admission_state = AdmissionState.OPEN
            self._ticker_task = asyncio.create_task(self._periodic_timer())
            self._refresh_metrics_cache()
            return self
        if command.kind == "sync":
            batch = await self._sync_parts(
                self._parts.active_parts(), DurabilityTrigger.BARRIER
            )
            await self._rotate_due_parts()
            self._evaluate_slo(observed_monotonic_ns=self._sample_monotonic())
            return () if batch is None else (batch,)
        if command.kind == "rotate_due":
            return await self._rotate_due_parts()
        if command.kind == "rotate_config":
            config_sha256 = cast(str, command.args[0])
            config_generation = cast(int, command.args[1])
            now = self._sample_wall()
            parts = self._parts.prepare_config_rotation(
                config_sha256,
                config_generation=config_generation,
                closed_at_ns=now,
            )
            members = self._pending_hour_close_members() + tuple(
                _FinalBarrierCloseMember(
                    part=part,
                    reason=CloseReason.CONFIG_RELOAD,
                    closed_at_ns=now,
                )
                for part in parts
            )
            manifests = await self._close_members(
                members,
                trigger=DurabilityTrigger.CONFIG,
            )
            self._clear_pending_hour_members(members)
            self._parts.commit_config_rotation(
                config_sha256,
                config_generation=config_generation,
            )
            self._ingress = self._ingress.replacement_for_config(
                config_sha256=config_sha256,
                config_generation=config_generation,
            )
            self._config_sha256 = config_sha256
            self._config_generation = config_generation
            self._lifecycle = WriterLifecycle.ACCEPTING
            self._admission_state = AdmissionState.OPEN
            self._refresh_metrics_cache()
            return manifests
        if command.kind == "close":
            reason = cast(CloseReason, command.args[0])
            deadline = cast(int, command.args[1])
            observed_monotonic_ns = self._sample_monotonic()
            if observed_monotonic_ns >= deadline and self._ledger.unpersisted_count:
                raise WriterCriticalError(
                    reason=WriterCriticalReason.CLOSE_DEADLINE,
                    affected_generation_ids=tuple(
                        part.generation_id for part in self._parts.active_parts()
                    ),
                    completed_batches=(),
                    message="raw writer close deadline elapsed",
                )
            closed_at_ns = self._sample_wall()
            parts = self._parts.detach_all(reason, closed_at_ns=closed_at_ns)
            members = self._pending_hour_close_members() + tuple(
                _FinalBarrierCloseMember(
                    part=part,
                    reason=reason,
                    closed_at_ns=closed_at_ns,
                )
                for part in parts
            )
            self._active_close_deadline_ns = deadline
            try:
                manifests = await self._close_members(
                    members,
                    trigger=_CLOSE_TRIGGER[reason],
                )
            finally:
                self._active_close_deadline_ns = None
            self._clear_pending_hour_members(members)
            self._closed_manifests = manifests
            self._lifecycle = WriterLifecycle.CLOSED
            self._admission_state = AdmissionState.CLOSED
            self._stopping = True
            self._refresh_metrics_cache()
            return manifests
        if command.kind == "incomplete":
            incomplete_reason = cast(str, command.args[0])
            self._incomplete_reason = incomplete_reason
            raise WriterCriticalError(
                reason=WriterCriticalReason.MARKED_INCOMPLETE,
                affected_generation_ids=tuple(
                    part.generation_id for part in self._parts.active_parts()
                ),
                completed_batches=(),
                message="raw writer was marked incomplete",
            )
        raise ValueError(f"unknown service command: {command.kind}")

    async def _run(self) -> None:
        terminal_command: _ServiceCommand | None = None
        terminal_result: object | None = None
        terminal_error: BaseException | None = None
        try:
            while not self._stopping:
                await self._work_event.wait()
                self._work_event.clear()
                if (
                    self._lifecycle is not WriterLifecycle.STARTING
                    and self._commands.empty()
                ):
                    await self._drain_ingress()
                while True:
                    try:
                        command = self._commands.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                    self._commands.task_done()
                    terminal_command = command
                    self._command_active = True
                    try:
                        if command.kind != "startup":
                            await self._drain_ingress(watermark=command.watermark)
                        result = await self._execute_command(command)
                    except BaseException as error:  # noqa: BLE001 - terminalize actor
                        terminal_error = await self._enter_terminal_error(error)
                        self._stopping = True
                        break
                    finally:
                        self._command_active = False
                    if command.kind == "close":
                        terminal_result = result
                        self._stopping = True
                        break
                    if not command.future.done():
                        command.future.set_result(result)
                    terminal_command = None
                if self._stopping:
                    break
                if self._periodic_due:
                    self._periodic_due = False
                    oldest_error = self._begin_oldest_critical()
                    if oldest_error is not None:
                        await self._finish_oldest_critical_drain()
                        raise oldest_error
                    await self._sync_parts(
                        self._parts.active_parts(), DurabilityTrigger.PERIODIC
                    )
                    await self._rotate_due_parts()
                    self._evaluate_slo(observed_monotonic_ns=self._sample_monotonic())
        except BaseException as error:  # noqa: BLE001 - terminalize every actor path
            terminal_error = await self._enter_terminal_error(error)
            self._stopping = True
        finally:
            await self._release_resources()
            if terminal_command is not None and not terminal_command.future.done():
                if terminal_error is None:
                    terminal_command.future.set_result(terminal_result)
                else:
                    terminal_command.future.set_exception(terminal_error)
            while True:
                try:
                    command = self._commands.get_nowait()
                except asyncio.QueueEmpty:
                    break
                self._commands.task_done()
                if not command.future.done():
                    command.future.set_exception(
                        terminal_error
                        if terminal_error is not None
                        else RuntimeError("raw writer service has stopped")
                    )

    async def _enter_terminal_error(self, error: BaseException) -> BaseException:
        if isinstance(error, RecoveryBlocked) and self._ledger.accepted_count == 0:
            return error
        critical = (
            error
            if isinstance(error, WriterCriticalError)
            else WriterCriticalError(
                reason=(
                    WriterCriticalReason.WRITE_FAILED
                    if isinstance(error, OSError)
                    else WriterCriticalReason.SYNC_FAILED
                ),
                affected_generation_ids=tuple(
                    part.generation_id
                    for part in (*self._parts.active_parts(), *self._retiring.values())
                ),
                completed_batches=(),
                message="raw writer service failed",
            )
        )
        if critical is not error:
            critical.__cause__ = error
        self._critical_reason = critical.reason
        self._lifecycle = WriterLifecycle.CRITICAL
        self._admission_state = AdmissionState.CLOSED
        if self._incomplete_reason is None:
            self._incomplete_reason = critical.reason.value
        for identity in tuple(self._record_stages):
            self._ledger.mark_uncertain(identity)
            self._record_stages.pop(identity, None)
            self._record_charge_bytes.pop(identity, None)
            try:
                self._resident_budget.release(identity)
            except KeyError:
                pass
        self._deferred_by_generation.clear()
        if not self._critical_callback_called and self._on_critical is not None:
            self._critical_callback_called = True
            try:
                self._on_critical(critical)
            except BaseException as callback_error:  # noqa: BLE001 - preserve cleanup
                critical.add_note(
                    f"on_critical callback also failed: {type(callback_error).__name__}"
                )
        self._refresh_metrics_cache()
        return critical

    async def _release_resources(self) -> None:
        if self._resources_released:
            return
        self._resources_released = True
        if self._ticker_task is not None:
            self._ticker_task.cancel()
            try:
                await self._ticker_task
            except asyncio.CancelledError:
                pass
        self._executor.shutdown(wait=True, cancel_futures=False)
        first_error: BaseException | None = None
        try:
            for part in (*self._parts.active_parts(), *self._retiring.values()):
                try:
                    part.close_fd_for_test()
                except BaseException as error:  # noqa: BLE001 - close every owned FD
                    if first_error is None:
                        first_error = error
        finally:
            self._writer_lock.release()
        if first_error is not None:
            raise first_error


__all__ = ["AsyncSleeper", "AsyncioSleeper", "RawWriterService"]
