# Durable Raw Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every accepted raw record into independently recoverable zstd frames, close immutable manifests, and prove required writer conservation/recovery and bounded short multi-round stability. Retain one-second target qualification as optional release performance evidence.

**Architecture:** Each exchange worker owns one raw-writer service and one durability coordinator. Stream files buffer JSONL records independently, while the coordinator synchronizes all dirty files with bounded concurrency and records record-level durability lag without modifying raw rows.

**Tech Stack:** asyncio, simplejson with Decimal, python-zstandard, portable `fdatasync/fsync`, Pydantic, Prometheus client, pytest, Hypothesis.

---

> **Completion scope amendment (2026-08-08):** The approved
> [`functional-completion scope amendment`](../specs/2026-08-08-functional-completion-scope-amendment.md)
> overrides later wording that makes `1s` or `10m@2x` qualification a prerequisite for
> connector expansion or project completion. Tasks 1-6, functional writer evidence,
> manifests/recovery, zero unrecorded loss, bounded resources, lag/watchdog behavior,
> and `PAUSED_WRITER` remain required. The retained target qualification machinery and
> its strict PASS/FAIL semantics remain available but optional.

## Authoritative Contract Amendment (2026-08-01)

This section is normative and overrides any later prose or code sample that conflicts
with it. Task 1 is already implemented on this plan branch; Tasks 2-7 must preserve
its public `AcceptedRecord`, path, and encoding behavior while adding the contracts
below. The approved design remains authoritative for requirements not amended here.

### Configuration and dependency injection

Plan 02 extends the foundation `WriterConfig` with these strict fields and tests them
in `tests/unit/config/test_models.py`:

```python
class WriterConfig(StrictModel):
    # Existing fields remain unchanged.
    zstd_level: Annotated[int, Field(ge=1, le=22)] = 3
    max_plain_frame_bytes: PositiveSizeBytes = Field(
        1 * 1024**2, alias="max_plain_frame_bytes"
    )
```

Shared storage scalar types used by the public models are defined once in
`storage.models`:

```python
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CanonicalUuid = Annotated[
    str,
    StringConstraints(
        pattern=(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
            r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
        )
    ),
]


def validate_normalized_data_relative_path(value: str) -> str:
    if (not value or "\x00" in value or "\\" in value or value.startswith("/")
            or any(part in {"", ".", ".."} for part in value.split("/"))):
        raise ValueError("path must be normalized POSIX relative data path")
    return value


NormalizedDataRelativePath = Annotated[
    str, AfterValidator(validate_normalized_data_relative_path)
]
NormalizedStateRelativePath = Annotated[
    str, AfterValidator(validate_normalized_data_relative_path)
]
```

`RawWriterService.open` accepts both `WriterConfig` and `IngressConfig`; production
dependencies default inside the service, while tests may inject deterministic
implementations. The Plan 01 `Clock` remains unchanged. Plan 02 defines a separate
`AsyncSleeper` protocol in `storage.durability` so fake-clock sleeps do not silently
expand the frozen domain clock contract.
`config_generation` is a strict non-negative runtime epoch independent of the config
SHA; reload requires a strictly greater value.
`metric_stream_allowlist` is required, sorted/unique, excludes the reserved `_other`
metric label, and has at most `MAX_DURABILITY_METRIC_STREAM_LABELS` members. Runtime
derives it from the validated bounded capability-supported stream vocabulary, not the
selected instruments; changing it requires worker
restart and therefore cannot occur inside Gate B qualification. `open` validates the
tuple, including every `NonEmptyString`, before acquiring the writer lock or creating a
root, executor, journal, or partial file.

```python
class AsyncSleeper(Protocol):
    async def sleep_ns(self, delay_ns: int) -> None: ...


class RawWriterService:
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
        metric_stream_allowlist: tuple[NonEmptyString, ...],
        clock: Clock,
        sleeper: AsyncSleeper | None = None,
        sync_backend: SyncBackend | None = None,
        recovery_backend: RecoveryBackend | None = None,
        source_disposition_resolver: SourceDispositionResolver | None = None,
        on_slo_transition: Callable[[DurabilitySloTransition], None] | None = None,
        on_critical: Callable[[WriterCriticalError], None] | None = None,
    ) -> "RawWriterService": ...

    def try_accept(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> EnqueueResult: ...

    async def sync_now(self) -> tuple[DurabilityBatch, ...]: ...
    async def rotate_due_files(self) -> tuple[RawManifestV1, ...]: ...
    async def rotate_for_config(
        self, config_sha256: str, config_generation: int
    ) -> tuple[RawManifestV1, ...]: ...
    async def close_all(
        self, reason: CloseReason, deadline_ns: int
    ) -> tuple[RawManifestV1, ...]: ...
    async def mark_incomplete(self, reason: str) -> None: ...
    def status(self) -> WriterStatus: ...
    def metrics_snapshot(self) -> WriterMetricsSnapshotV1: ...
```

`CloseReason` is not a Plan 02 type. Import the frozen
`crypto_collector.domain.types.CloseReason`; in particular, configuration rotation is
`CloseReason.CONFIG_RELOAD` with wire value `"config_reload"`. The other names in the
public surface are frozen here rather than left as test-double conventions:

```python
from crypto_collector.domain.types import CloseReason


class DurabilityTrigger(StrEnum):
    PERIODIC = "periodic"
    SIZE = "size"
    HOUR = "hour"
    CONFIG = "config"
    RECOVERY = "recovery"
    SHUTDOWN = "shutdown"
    BARRIER = "barrier"


class RecoveryAccountingMode(StrEnum):
    UNMEASURED = "unmeasured"


_CLOSE_TRIGGER: Final[Mapping[CloseReason, DurabilityTrigger]] = {
    CloseReason.ROTATE_TIME: DurabilityTrigger.HOUR,
    CloseReason.ROTATE_SIZE: DurabilityTrigger.SIZE,
    CloseReason.CONFIG_RELOAD: DurabilityTrigger.CONFIG,
    CloseReason.SHUTDOWN: DurabilityTrigger.SHUTDOWN,
    CloseReason.RECOVERY: DurabilityTrigger.RECOVERY,
}


@dataclass(frozen=True, slots=True)
class SealedFileWork:
    generation_id: str
    stream_file: "StreamFile"
    pending: "PendingRows | None"
    force_sync: bool


@dataclass(frozen=True, slots=True)
class FileDurabilityResult:
    generation_id: str
    was_dirty: bool
    record_count: int
    sync_completed_monotonic_ns: int | None
    sync_duration_ns: int
    lag_p50_ns: int | None
    lag_p95_ns: int | None
    lag_p99_ns: int | None
    lag_max_ns: int | None


@dataclass(frozen=True, slots=True)
class FileSyncCompleted:
    result: FileDurabilityResult


@dataclass(frozen=True, slots=True)
class FileSyncFailed:
    generation_id: str
    error: BaseException


FileSyncCompletion: TypeAlias = FileSyncCompleted | FileSyncFailed


class FileSyncCompletionSink(Protocol):
    def __call__(self, completion: FileSyncCompletion) -> None: ...


def discard_file_sync_completion(_completion: FileSyncCompletion) -> None:
    pass


@dataclass(frozen=True, slots=True)
class DurabilityBatch:
    batch_sequence: int
    trigger: DurabilityTrigger
    started_monotonic_ns: int
    completed_monotonic_ns: int
    files: tuple[FileDurabilityResult, ...]

    @property
    def record_count(self) -> int:
        return sum(item.record_count for item in self.files)


class WriterCriticalReason(StrEnum):
    OLDEST_UNPERSISTED_AGE = "oldest_unpersisted_age"
    WRITE_FAILED = "write_failed"
    SYNC_FAILED = "sync_failed"
    PUBLICATION_FAILED = "publication_failed"
    CONTROL_DURABILITY_FAILED = "control_durability_failed"
    SLO_TRANSITION_CALLBACK_FAILED = "slo_transition_callback_failed"
    CLOSE_DEADLINE = "close_deadline"
    MARKED_INCOMPLETE = "marked_incomplete"


class WriterAffinityError(RuntimeError):
    """A public writer API was called outside its owning thread/event loop."""


# Defined in storage.recovery and re-exported from crypto_collector.storage.
class RecoveryBlocked(RuntimeError):
    """Startup recovery could not establish a safe state before admission."""


class DurabilitySloState(StrEnum):
    BREACHED = "breached"
    RECOVERED = "recovered"


@dataclass(frozen=True, slots=True)
class DurabilitySloTransition:
    state: DurabilitySloState
    observed_monotonic_ns: int
    rolling_p99_ns: int | None
    rolling_max_ns: int | None


class WriterCriticalError(RuntimeError):
    def __init__(
        self,
        *,
        reason: WriterCriticalReason,
        affected_generation_ids: tuple[str, ...],
        completed_batches: tuple[DurabilityBatch, ...],
        message: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class RecoveryOutcome:
    transaction_id: CanonicalUuid
    recovery_control_event_id: NonEmptyString
    source_state: RecoverySourceState
    source_disposition: RecoverySourceDisposition
    source_relative_path: NormalizedDataRelativePath
    source_sha256: Sha256
    recovered_generation_id: NonEmptyString | None
    recovered_relative_path: NormalizedDataRelativePath | None
    recovered_sha256: Sha256 | None
    quarantined_relative_path: NormalizedDataRelativePath | None
    quarantined_sha256: Sha256 | None
    informational_only: bool


@dataclass(frozen=True, slots=True)
class PendingRecoveryControl:
    transaction_id: CanonicalUuid
    recovery_control_event_id: NonEmptyString
    source_state: RecoverySourceState
    source_disposition: RecoverySourceDisposition
    draft: NativeEventDraft
    target: StorageControlTargetV1 | None


@dataclass(frozen=True, slots=True)
class RecoveryControlAdmission:
    transaction_id: CanonicalUuid
    recovery_control_event_id: NonEmptyString
    control_record: AcceptedRecord
    control_record_identity: AcceptedRecordIdentityV1
    control_generation_id: NonEmptyString
    control_data_relative_path: NormalizedDataRelativePath
    control_manifest_relative_path: NormalizedDataRelativePath
    association: StorageControlAssociationV1 | None
    control_frame_bytes: bytes
    zstd_level: int
    max_plain_frame_bytes: PositiveInt


@dataclass(frozen=True, slots=True)
class RecoveryControlReceipt:
    transaction_id: CanonicalUuid
    recovery_control_event_id: NonEmptyString
    control_record_identity: AcceptedRecordIdentityV1
    control_generation_id: NonEmptyString
    control_data_relative_path: NormalizedDataRelativePath
    control_encoded_sha256: Sha256
    durable_at_monotonic_ns: NonNegativeInt


@dataclass(frozen=True, slots=True)
class RecoveryReconciliation:
    completed_outcomes: tuple[RecoveryOutcome, ...]
    pending_controls: tuple[PendingRecoveryControl, ...]


class RecoveryDurabilityCoordinator(Protocol):
    @property
    def accounting_mode(self) -> Literal[RecoveryAccountingMode.UNMEASURED]: ...

    async def sync_batch(
        self, work_items: Sequence[SealedFileWork], *,
        trigger: Literal[DurabilityTrigger.RECOVERY],
    ) -> DurabilityBatch: ...


@dataclass(frozen=True, slots=True)
class RecoveryContext:
    data_root: Path
    state_root: Path
    exchange: Exchange
    worker_instance_id: str
    config_sha256: str
    config_generation: int
    clock: Clock
    io_limiter: StorageIoLimiter
    recovery_coordinator: RecoveryDurabilityCoordinator
    storage_executor: Executor
    source_disposition_resolver: SourceDispositionResolver


class RecoveryBackend(Protocol):
    async def reconcile(self, context: RecoveryContext) -> RecoveryReconciliation: ...

    async def bind_control_ownership(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        admission: RecoveryControlAdmission,
    ) -> None: ...

    async def acknowledge_control_durable(
        self,
        context: RecoveryContext,
        *,
        pending: PendingRecoveryControl,
        receipt: RecoveryControlReceipt,
    ) -> RecoveryOutcome: ...
```

`RecoveryBackend.reconcile` advances every filesystem transaction through
`source-settled.json`, finishes an already `control-durable` transaction through
`complete.json`, and returns, in canonical transaction-ID order, disjoint completed and
pending sets. It never starts or calls the live writer. A pending item is the immutable
bridge from the source-settled journal to the service-owned live control path; its draft
is the exact reserved `_control` row and its optional `target` is the one journal-verified
recovered generation/path to associate after admission. It does not carry a
`StorageControlAssociationV1`: the acceptance ordinal and config generation required by
that model do not exist until the service accepts the row. Empty or duplicate
transaction IDs, a target that disagrees with the durable artifacts fact, or a
completed/pending overlap are invalid.

`RawWriterService.open` alone starts its service loop in `STARTING`, internally admits
each pending draft to the reserved control shard. At that successful admission
linearization point it constructs the complete association from `pending.target`, the
actual acceptance ordinal, and the current config generation. It reserves a dedicated
one-row `_control` generation without creating its `.partial`, then calls
`bind_control_ownership` with the exact accepted envelope/identity/hash inputs,
association, precompressed one-frame bytes, carrier paths, and codec settings. During
that call the backend samples `created_at_ns` once, derives and validates the canonical
contingency recovery manifest from the admission and prior facts, and durably publishes
`control-ownership.json`; only after that fact's parent-directory fsync may the service
allocate, write, or sync the named carrier. No ordinary control or second recovery
control can share that generation.

The service waits on the live coordinator's record-exact durability watermark and
normally closes and publishes the dedicated carrier data and manifest before it
constructs `RecoveryControlReceipt` from the actual accepted identity, encoded row hash,
generation, planned final data path, and measured completion time and calls
`acknowledge_control_durable`. That backend method
freshly reloads the transaction, requires it to be the same source-settled intent,
validates every receipt field against the ownership fact and durable row, publishes
`control-durable.json` and `complete.json`, and returns the canonical outcome. It is
idempotent when the exact complete chain already exists and rejects any other state or
receipt. `bind_control_ownership` is idempotent only for the exact canonical admission;
an existing different ownership fact is a conflict. These three backend methods are the
only APIs allowed to mutate recovery
artifacts; the backend never receives the live coordinator or admission port.

If a process dies after ownership is durable, startup reserves the owned carrier's
partial/final/manifest identities before the general source scan. From the canonical
envelope in `control-ownership.json`, recovery either verifies the exact single row
already present or resumes the exact bound frame with the unmeasured recovery
coordinator. An exact final carrier plus its exact canonical normal manifest is only
validated and advanced to `control-durable.json`; replay must not replace it with a
recovery manifest. If no manifest exists, replay finishes the absent/prefix-only carrier
and publishes the ownership fact's frozen contingency recovery-manifest bytes. An
already published byte-exact contingency manifest is validated and advanced. Any other
manifest, extra row, non-prefix byte, hash mismatch, or name collision blocks startup.
It may not create a source transaction or a new lineage event for that carrier. Thus
every owned byte is recovered while a crash after normal-manifest sync still produces
exactly the original transaction and event ID without a no-replace collision.
The service loop processes pending controls in their canonical order and holds its
startup mutation phase across live sync, receipt construction, and all acknowledgements;
no periodic flush, rotation command, public admission, or later recovery-control append
can interleave. The backend runs its journal reads/writes through the shared
`StorageIoLimiter` and executor. On the same process it never resubmits the live row to
the unmeasured recovery coordinator; only a fresh-process replay of an already durable
ownership fact may use that exact canonical row there. Only after every acknowledgement returns may the loop leave
`STARTING`.

`SealedFileWork` is the coordinator's sole write/sync input. Its `generation_id`
is the immutable open-file generation owned by `stream_file`; a non-`None` `pending`
value is already detached from the active buffer, and `pending=None` is legal only
with `force_sync=True` for a clean final-sync view. `StreamFile.seal_for_sync(*,
direct_rows: PendingRows | None = None, force_sync: bool = False)` is the only creator:
without `direct_rows` it atomically detaches the current buffer, while `direct_rows`
must be one oversized row and requires an empty active buffer. It returns `None` only
when both sources are empty and `force_sync=False`. The service loop moves every
included ledger entry to `IN_FLIGHT` in the same turn before submitting the work.
`DurabilityCoordinator.sync_batch(work_items, *, trigger)` accepts only a nonempty
`Sequence[SealedFileWork]` and rejects a duplicate generation within the batch or
against any currently in-flight batch. Sequential batches for one still-open generation
are valid, but the same detached `PendingRows` object is never submitted twice.
Time, size, config, shutdown, and recovery close paths use the correspondingly named
trigger; `sync_now` uses `BARRIER`, and a timer-only flush uses `PERIODIC`. No caller
infers a trigger from an arbitrary string.

Tuples preserve input generation order. A clean file passed to a group final sync has
one `FileDurabilityResult(was_dirty=False, record_count=0, ...)`, so every requested
generation has a view even when its last periodic sync already made it durable.
Failures raise `WriterCriticalError`; `completed_batches` and the chained cause expose
only fully accounted, non-secret facts. Test doubles implement these protocols and may
not rely on extra service internals. `sync_now` returns the ordered tuple of batches it
had to await or start for its watermark and returns `()` when that watermark was
already durable.

`None` selects `AsyncioSleeper`, `PosixSyncBackend`, the production recovery backend,
and `NoCleanupProofResolver`. Runtime callers therefore never construct or wire a lock,
ingress, stream file, coordinator, or recovery scanner; `RawWriterService.open` owns
that construction. `ExchangeWriterLock.acquire` also accepts
`Exchange`, not arbitrary `str`; it maps only `EACCES`/`EAGAIN` lock contention to
`WriterAlreadyRunning` and preserves unrelated `OSError` causes.
The service owns one `ThreadPoolExecutor(max_workers=writer_config.max_sync_concurrency)`
for every blocking storage operation. It is created before recovery and shut down only
after all owned jobs complete; no path uses the process default executor.

### Frozen public models and lifecycle

#### Task 6 persisted-format closure (2026-08-01)

The following rules close ambiguities found before Task 6 implementation and are
normative for every recovery journal written by V1:

- `planned_data_generation_id` is the lowercase canonical UUIDv5 of the exact
  UTF-8 `planned_data_relative_path`, using namespace UUID
  `54c28b47-77d8-5f40-a39d-486f57a98f44`. This rule applies to both newly allocated
  recovered parts and retained closed orphans. Validation parses the canonical part
  path, verifies its scope/hour/`part_start_ns`/sequence structure, and recomputes the
  UUIDv5; the intent therefore needs no duplicate allocator fields. Live generations
  and the service-owned recovery-control carrier remain separately allocated identities
  frozen by their owning service/journal facts.
- A whole-source quarantine destination is exactly
  `quarantine/<source_relative_path>.whole`; a bad suffix accompanying a recovered
  prefix is exactly `quarantine/<source_relative_path>.bad-tail`. Both are relative to
  `data_root`, are published with no-replace, and are accepted on replay only after an
  exact intent-bound size/hash check.
- The production implementation is named `PosixRecoveryBackend`. Tests may inject the
  `RecoveryBackend` protocol but runtime constructs this concrete backend by default.
- Shared public storage exceptions live in `storage.errors`; `raw_writer`, `manifest`,
  `recovery`, and the package root re-export the same class objects rather than defining
  compatible-looking copies.
- Same-process recovery control carriers close with the normal measured-manifest reason
  `CloseReason.RECOVERY_CONTROL`; their durability trigger is independently
  `DurabilityTrigger.RECOVERY`. A carrier reconstructed by fresh-process ownership
  replay uses the frozen contingency manifest with `CloseReason.RECOVERY` and
  unavailable durability fields.

The exact recovery control payload is generated from this strict model and then passed
to `NativeEventDraft` as `model_dump(mode="json")`; no `storage_association` member is
embedded. The service constructs the optional association only from the journal-bound
`PendingRecoveryControl.target` at acceptance.

```python
class RecoveryControlPayloadV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    kind: Literal["recovery_reconciled"] = "recovery_reconciled"
    recovery_control_event_id: NonEmptyString
    transaction_id: CanonicalUuid
    source_state: RecoverySourceState
    source_disposition: RecoverySourceDisposition
    source_market: Market | None
    source_instrument_key: NonEmptyString | None
    source_logical_stream: NonEmptyString
    source_relative_path: NormalizedDataRelativePath
    source_sha256: Sha256
    recovered_generation_id: NonEmptyString | None
    recovered_relative_path: NormalizedDataRelativePath | None
    recovered_sha256: Sha256 | None
    quarantined_relative_path: NormalizedDataRelativePath | None
    quarantined_sha256: Sha256 | None
    informational_only: bool
    affected_markets: tuple[Market, ...]
```

The recovered generation/path/SHA group is all present or all `None`; the quarantine
path/SHA pair is likewise paired. `_control` source context requires null market and
instrument with empty `affected_markets`; every other source requires a market and
`affected_markets == (source_market,)`. Instrument nullability follows the existing
market-scoped stream rule. `informational_only` is true exactly for
`LEGITIMATELY_MISSING`. The payload fields, declared order, nulls, and arrays are part of
the V1 wire contract; consumers use `recovery_control_event_id` as the idempotency key.

Plan 02 owns these public contracts in their canonical modules. Later plans import
them and do not redefine compatible-looking copies.

```python
class EnqueueStatus(StrEnum):
    ACCEPTED = "accepted"
    ACCEPTED_HIGH_WATER = "accepted_high_water"
    OVERFLOW = "overflow"
    CONTROL_OVERFLOW = "control_overflow"
    NOT_ACCEPTING = "not_accepting"


class AcceptedRecordIdentityV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    exchange: Exchange
    market: Market | None
    instrument_key: NonEmptyString | None
    logical_stream: NonEmptyString
    worker_instance_id: NonEmptyString
    writer_sequence: NonNegativeInt
    acceptance_ordinal: NonNegativeInt
    config_sha256: Sha256
    config_generation: NonNegativeInt


@dataclass(frozen=True, slots=True)
class EnqueueResult:
    status: EnqueueStatus
    record: AcceptedRecord | None
    record_identity: AcceptedRecordIdentityV1 | None

    def __post_init__(self) -> None:
        if self.accepted and (self.record is None or self.record_identity is None):
            raise ValueError("accepted status requires record and identity")
        if not self.accepted and (
            self.record is not None or self.record_identity is not None
        ):
            raise ValueError("accepted status, record, and identity must agree")

    @property
    def accepted(self) -> bool:
        return self.status in {
            EnqueueStatus.ACCEPTED,
            EnqueueStatus.ACCEPTED_HIGH_WATER,
        }


class WriterLifecycle(StrEnum):
    STARTING = "starting"
    ACCEPTING = "accepting"
    ROTATING = "rotating"
    CRITICAL = "critical"
    CLOSING = "closing"
    CLOSED = "closed"


class AdmissionState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"


class PublicationState(StrEnum):
    IDLE = "idle"
    SEALING = "sealing"
    FINAL_SYNC = "final_sync"
    PUBLISHING = "publishing"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class WriterStatus:
    lifecycle: WriterLifecycle
    admission_state: AdmissionState
    publication_state: PublicationState
    accepting: bool
    incomplete: bool
    incomplete_reason: str | None
    critical_reason: WriterCriticalReason | None
    queued_records: int
    queued_bytes: int
    buffered_records: int
    buffered_bytes: int
    in_flight_records: int
    in_flight_bytes: int
    active_logical_generation_count: int
    retiring_generation_count: int
    open_file_descriptor_count: int
    dirty_file_count: int
    sync_inflight: int
    oldest_unpersisted_age_ns: int | None
    accepted_record_count: int
    durable_record_count: int
    unpersisted_record_count: int
    uncertain_record_count: int


class DurabilityHistogramSeriesV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    exchange: Exchange
    market: Market | None
    logical_stream: NonEmptyString
    bucket_counts: tuple[NonNegativeInt, ...]
    sample_count: NonNegativeInt
    lag_p50_ns: NonNegativeInt | None
    lag_p95_ns: NonNegativeInt | None
    lag_p99_ns: NonNegativeInt | None
    lag_max_ns: NonNegativeInt | None


class WriterMetricsSnapshotV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    observed_monotonic_ns: NonNegativeInt
    exchange: Exchange
    worker_instance_id: NonEmptyString
    config_sha256: Sha256
    config_generation: NonNegativeInt
    lifecycle: WriterLifecycle
    admission_state: AdmissionState
    publication_state: PublicationState
    critical_reason: WriterCriticalReason | None
    acceptance_ordinal_high_water: NonNegativeInt | None
    accepted_record_count: NonNegativeInt
    durable_record_count: NonNegativeInt
    unpersisted_record_count: NonNegativeInt
    uncertain_record_count: NonNegativeInt
    queued_records: NonNegativeInt
    queued_bytes: NonNegativeInt
    buffered_records: NonNegativeInt
    buffered_bytes: NonNegativeInt
    in_flight_records: NonNegativeInt
    in_flight_bytes: NonNegativeInt
    resident_record_bytes: NonNegativeInt
    resident_control_records: NonNegativeInt
    resident_control_bytes: NonNegativeInt
    oldest_unpersisted_age_ns: NonNegativeInt | None
    enqueue_high_water_count: NonNegativeInt
    normal_overflow_count: NonNegativeInt
    control_overflow_count: NonNegativeInt
    not_accepting_count: NonNegativeInt
    active_logical_generation_count: NonNegativeInt
    retiring_generation_count: NonNegativeInt
    open_file_descriptor_count: NonNegativeInt
    sync_inflight: NonNegativeInt
    durability_histogram_schema_version: Literal[1]
    durability_bucket_counts: tuple[NonNegativeInt, ...]
    durability_sample_count: NonNegativeInt
    durability_lag_p50_ns: NonNegativeInt | None
    durability_lag_p95_ns: NonNegativeInt | None
    durability_lag_p99_ns: NonNegativeInt | None
    durability_lag_max_ns: NonNegativeInt | None
    durability_histogram_series: tuple[DurabilityHistogramSeriesV1, ...]
    sync_count: NonNegativeInt
    sync_duration_total_ns: NonNegativeInt
    sync_duration_max_ns: NonNegativeInt
    slo_breach_count: NonNegativeInt
    write_failure_count: NonNegativeInt
    sync_failure_count: NonNegativeInt
    publication_failure_count: NonNegativeInt
```

`metrics_snapshot()` is the sole public metrics read API. It is an event-loop-affine,
synchronous getter of one already-built `WriterMetricsSnapshotV1` cache reference; it
never enqueues a request, waits for the service task, reads mutable counters, or builds
a snapshot on demand. Construction installs an initial `STARTING` cache. A successful
`try_accept` refreshes it before returning, and the service loop atomically replaces it
at the end of every completion, command, publication, failure, and watchdog turn that
changes a snapshot field. The cache is replaced only after the whole state transition
and all invariants validate, so readers see the prior or next immutable model, never a
partially applied transition. Every actual replacement sets
`observed_monotonic_ns = max(clock.monotonic_ns(), previous_observed_monotonic_ns + 1)`;
different canonical snapshot bytes therefore always have a strictly later observation
timestamp even when an injected or coarse monotonic clock returns the same value. An
unchanged getter does not manufacture time: it returns the identical cache object and
timestamp.

The returned snapshot is point-in-time state as of its own
`observed_monotonic_ns`. Consecutive calls with no intervening cache refresh return the
same object and timestamp. A call may therefore precede an executor completion still
queued in the service mailbox; callers needing causal freshness first await the
relevant public `sync_now`, rotation, or close future, whose resolution occurs only
after its final cache refresh. Time-derived age/window fields do not advance inside the
getter; their freshness is likewise the last completion/watchdog turn and is explicit
in `observed_monotonic_ns`. All service APIs, including this getter, reject use from a
thread or event loop other than the service owner with `WriterAffinityError`. Thread
identity and the exact running-loop object are captured at successful service open and
checked before reading the cache or performing any other public operation. On terminal
close, the loop freezes
one final `CLOSED` or `CRITICAL` snapshot after all owned accounting and before it
stops; later reads return that same cached immutable value. Plan 08 consumes this model
for Prometheus/health aggregation, and Gate B hashes successive snapshots.
`canonical_bytes()` uses declared field order, compact Decimal-aware JSON, enum values,
and one trailing newline.
The aggregate histogram tuple length must equal
`len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)`, its sum must equal
`durability_sample_count`, and all record, stage, resident-byte, and histogram
invariants below are revalidated when constructing the snapshot. These vectors are
disjoint per-bound buckets; Plan 08 computes the required Prometheus cumulative prefix
sums. Each series uses the
same schema/bounds, has `sum(bucket_counts) == sample_count`, and the tuple is
sorted/unique by `(exchange.value, market.value if market is not None else "",
logical_stream)`. Every series exchange equals the outer snapshot exchange. The
elementwise sum of all series buckets equals the outer aggregate buckets, and the sum
of their samples equals the outer sample count. The outer max is the maximum non-null
series max, and all aggregate/series quantiles must equal the deterministic nearest-rank
value recomputed from their own bucket vector.

The public aggregate and series are process-lifetime cumulative values from this
service instance's first accepted row. Bucket counts, sample counts, and observed maxima
are monotonic and survive active-part retirement and manifest publication. Nearest-rank
p50/p95/p99 are recomputed from cumulative buckets and may increase or decrease as new
samples arrive; no validator treats a quantile decrease as a reset. None of these
values comes from the private rolling alert window. On every live-coordinator completion
for a current-process accepted row, including a newly emitted recovery `_control` row,
the service loop advances the durable count, aggregate histogram, and exactly one
series in the same state transition, so `durability_sample_count ==
durable_record_count` for the current process. The separate prior-process
`RecoveryDurabilityCoordinator(UNMEASURED)` cannot enter any of those counters.

Series keys are bounded independently of instruments. `RawWriterService.open` receives
a sorted/unique `metric_stream_allowlist` of at most
`MAX_DURABILITY_METRIC_STREAM_LABELS`; configured names retain their exact label and
every other storage stream maps only for metrics to
`OTHER_DURABILITY_METRIC_STREAM_LABEL`. `exchange` is fixed by the service and `market`
is the finite domain enum plus `None`; no instrument, symbol, config hash, connection,
or proxy value enters a series key. Consequently one worker can expose at most
`(len(Market) + 1) * (MAX_DURABILITY_METRIC_STREAM_LABELS + 1)` series. Raw envelopes
and paths keep their original logical stream. Plan 08 converts these exact cumulative
series to Prometheus `exchange/market/stream` deltas keyed by worker instance; it does
not reconstruct labeled histograms from manifests or private state. It encodes
`market=None` with the single stable Prometheus label value `_exchange`.

The private alert ring has exactly 60 reusable one-second slots keyed only by
`sync_completed_monotonic_ns // 1_000_000_000` (the row's durable completion). A slot stores its integer monotonic-second
tag, the shared bucket vector, sample count, and exact max. Before inserting or on each
watchdog tick, slots whose tags are outside `[current_second - 59, current_second]` are
logically empty; reusing a slot resets it before adding the sample. A jump of 60 seconds
or more clears all slots in bounded `O(60)` work, and no wall-clock value participates.
Rolling p99 and exact rolling max are recomputed over only those tagged slots. This
ring is private state used only for SLO transitions; manifests retain separate
immutable per-part aggregates.

`try_accept` verifies `draft.exchange == service.exchange`. A call made while
`admission_state=CLOSED` returns `NOT_ACCEPTING` with `record=None`; it never consumes
a sequence or acceptance ordinal and has `record_identity=None`. On success, the
identity fields must exactly equal the accepted envelope plus the service's ordinal and
current config generation; that immutable identity is the key used by the ledger,
control associations, Gate B trace, and terminal conservation tests. `sync_now` is a
watermark barrier: when it returns,
every record accepted before the call is either durably accounted or the service is
terminal critical.

The durable-row join key is `(exchange, market, instrument_key, logical_stream,
worker_instance_id, writer_sequence, config_sha256)`. It is unique within one service
run and is exactly the subset of `AcceptedRecordIdentityV1` stored in `RawEnvelope`.
`acceptance_ordinal` and `config_generation` remain service/trace metadata. Gate B
requires a one-to-one join from every trace identity to exactly one decoded manifest
row by this key and independently verifies ordinals are contiguous from the run's
first accepted ordinal; a count-only match is insufficient.
`close_all` is idempotent, retains ownership of background work after caller
cancellation, and releases the writer lock only after the service loop has stopped,
all blocking jobs have completed, and all descriptors are closed. A second successful
call returns the same immutable manifest tuple. Concurrent close calls share the first
call's owned command, reason, and deadline; later arguments do not replace them.
`mark_incomplete` closes admission
immediately, records the reason in status and durable recovery evidence when storage
permits, and never publishes a normal complete manifest for an uncertain part.

The only lifecycle transitions are `STARTING -> ACCEPTING`, `ACCEPTING -> ROTATING ->
ACCEPTING`, `ACCEPTING|ROTATING -> CLOSING -> CLOSED`, and any nonterminal state to
terminal `CRITICAL`. Admission and publication are orthogonal: hour/size rotation may
have `lifecycle=ROTATING`, `admission_state=OPEN`, and
`publication_state=FINAL_SYNC|PUBLISHING`, while config reload and shutdown close the
gate before sealing. `accepting == (admission_state is AdmissionState.OPEN)`.
`mark_incomplete`, a close deadline with uncertain records, and any
write/sync/publication uncertainty enter `CRITICAL`; that state never later reports
`CLOSED`, even after all resources have been released. Status counts are non-negative,
`accepted_record_count == durable_record_count + unpersisted_record_count +
uncertain_record_count`, and `unpersisted_record_count == queued_records +
buffered_records + in_flight_records`; `incomplete == (incomplete_reason is not None)`.
`on_critical` is invoked exactly once on the first transition to `CRITICAL`.

### Acceptance ownership and the single service loop

```python
class DurabilityStage(StrEnum):
    QUEUED = "queued"
    BUFFERED = "buffered"
    IN_FLIGHT = "in_flight"
    DURABLE = "durable"
    UNCERTAIN = "uncertain"
```

The successful `put_nowait` remains the acceptance linearization point. Because
`try_accept` contains no `await`, it must register the accepted timestamp in the
service-owned durability ledger after the queue insert and before returning the
successful `EnqueueResult`. It peeks the next sequence and acceptance ordinal, embeds
that candidate identity in the immutable queued item, and commits both counters only
after `put_nowait` succeeds; the event loop cannot drain the item during this
non-awaiting call. The same ledger entry moves through `QUEUED`, `BUFFERED`,
`IN_FLIGHT`, and either terminal `DURABLE` or terminal `UNCERTAIN`; moving between
stages never resets its timestamp. Queue
records and unclaimed stream buffers therefore participate in both durability lag and
the critical-age watchdog. Failed admission removes no ledger entry because none was
published and consumes no writer sequence.
Normal transitions never move backward: `QUEUED -> BUFFERED -> IN_FLIGHT -> DURABLE`.
Any nonterminal stage may instead enter `UNCERTAIN` on terminal storage/lifecycle
failure. Both terminal stages leave the oldest-unpersisted index; only `DURABLE`
increments the durable count.

### Control scope, capacity class, and storage association

Every control draft must have `logical_stream="_control"`, `market=None`,
`instrument_key=None`, and `wire_symbol=None`. Market context is data, not storage
scope: affected markets appear only in the payload's sorted `affected_markets` array
or other kind-specific payload fields and, when storage identities are affected, in
the association request/targets below. A control
row always uses `raw/<exchange>/_control/...`; neither its path nor its own manifest
may acquire a market segment. Conversely, a non-control draft must have a market and
can never use the `_control` shard.

`validate_control_draft` accepts an already domain-validated `NativeEventDraft`,
enforces the null scope above, and returns an immutable `ValidatedControlDraft` while
preserving its kind-specific JSON payload. This validation, not a caller assertion or
shard name, confers control capacity. A control need not affect a storage generation;
when it does, its payload has a reserved `storage_association` member that strictly
validates as `StorageControlRequestV1`. Unknown/missing/extra keys inside that reserved
member are rejected before admission; other kind-specific payload keys remain valid.
Recovery builds a validated control draft internally with payload
`kind="recovery_reconciled"` and its independent recovery-lineage event ID, but the
service constructs its association directly from the journal-verified closed recovery
outcome rather than pretending that closed generation is logically active.

```python
class StorageScopeError(ValueError):
    pass


class AdmissionContractError(ValueError):
    pass


class CapacityClass(StrEnum):
    NORMAL = "normal"
    CONTROL = "control"


class StorageLogicalTargetV1(FrozenStrictModel):
    market: Market | None
    instrument_key: NonEmptyString | None
    logical_stream: NonEmptyString


class StorageControlRequestV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    control_event_id: NonEmptyString
    affected_markets: tuple[Market, ...]
    target_logical_identities: tuple[StorageLogicalTargetV1, ...]


class StorageControlTargetV1(FrozenStrictModel):
    generation_id: NonEmptyString
    data_relative_path: NormalizedDataRelativePath


class StorageControlAssociationV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    control_kind: NonEmptyString
    control_event_id: NonEmptyString
    targets: tuple[StorageControlTargetV1, ...]
    acceptance_ordinal: NonNegativeInt
    config_generation: NonNegativeInt
```

An association request requires nonempty sorted/unique `target_logical_identities` and
sorted/unique `affected_markets`. A target has `market=None` only for `_control`; every
non-null target market must appear in `affected_markets`, and the market array may be
empty only when every target is exchange-scoped. Instrument nullability follows the
target stream's storage scope. The outer payload
must also contain nonempty string `kind`, which becomes the association's
`control_kind`. Producers can request logical targets only; generations and paths are
forbidden in the request.

`targets` is nonempty, sorted by `(generation_id, data_relative_path)`, and unique in
both generation ID and path. The service, never the producer, resolves each requested
logical identity to the exact logical generation and final data-relative path current
at the successful control acceptance linearization point. It then creates one frozen
association using that control record's service acceptance ordinal and current config
generation. A normal manifest derives `control_event_ids` and every control summary
only from associations whose exact target names that manifest generation; payload
proximity, market equality, and wall-clock windows are not associations.
An association is eligible for that summary only after its accepted control identity is
`DURABLE`. Before publishing a targeted generation, the service must wait for any
already in-flight associated control work and must add pending associated control
generation work to the same group-sync barrier even when that control generation is not
itself due to close. If an associated control cannot become durable, the target's normal
manifest is withheld and terminal critical accounting applies; a manifest may never
refer to a control row that can still be lost. The private startup-recovery association
is the explicit exception to summary materialization: its recovery manifest is already
immutable with `control_event_ids=None`, and the exact link instead remains in the
verified recovery fact chain and recovery control row.
Until that durability transition, the association follows the control ledger entry and
its bytes remain in the same resident-stage charge. On confirmed sync the service-loop
turn first folds its exact ID/kind into every named active or retiring target's bounded
manifest accumulator, then makes the control `DURABLE` and releases the association
charge. A target cannot leave the retiring map while such a fold or barrier is pending.
`StorageControlAssociationV1.canonical_bytes()` uses its declared field order,
Decimal-aware compact JSON, enum values, and one trailing newline; its exact bytes are
charged to the resident budget and golden-tested. `data_relative_path` is the final
`.jsonl.zst` path for the named generation, never its temporary `.partial` name.
If any requested logical identity has no current active generation, the entire control
admission raises `AdmissionContractError` and consumes nothing; the service never
silently drops a target or associates it with a later generation.
The only non-active resolution path is the private startup recovery path: it accepts
exact `StorageControlTargetV1` values only from a verified
`RecoveryArtifactsDurableV1`/manifest pair in the same transaction. External drafts
can never supply or select that path.

Capacity classification is not trusted from `shard`: a successfully validated control
draft is `CapacityClass.CONTROL`; every other valid domain draft is
`CapacityClass.NORMAL`. Control class requires `shard="_control"`, normal class rejects
that shard, and any mismatch raises `AdmissionContractError` without consuming a
sequence, ordinal, queue slot, or resident-budget charge. Invalid `_control` drafts are
rejected rather than downgraded to normal capacity. A control-capacity failure returns
`CONTROL_OVERFLOW`; a normal-capacity failure returns `OVERFLOW`; neither creates an
association.

Rotation tests freeze the boundary: a control accepted through seal ordinal `N`
associates only with the old exact generations selected at that linearization point;
a control accepted after an hour/size seal associates only with the replacement
generations. Config reload closes admission first, so no control can race its old/new
config generation. Overflow tests assert that rejected controls produce neither an
association nor a manifest event ID and that shard/class mismatches consume nothing.

### Resident memory budget

The service owns one resident budget spanning the full nonterminal lifetime of each
accepted record. A record is charged once at acceptance for
`len(encoded_jsonl) + len(association.canonical_bytes())` (the second term is zero
without an association), retains that exact charge through `QUEUED`, `BUFFERED`, and
`IN_FLIGHT`, and releases it only on `DURABLE` or `UNCERTAIN`. Moving a row out of an
ingress queue therefore never frees worker capacity. At all times:

`queued_bytes`, `buffered_bytes`, and `in_flight_bytes` all mean this resident charge,
not container allocation estimates or compressed bytes. Association bytes stay in the
same stage as their control record.

```text
resident_record_bytes == queued_bytes + buffered_bytes + in_flight_bytes
resident_record_bytes <= ingress_config.worker_max_bytes
normal_resident_bytes <= worker_max_bytes - control_reserve_bytes
```

The dedicated `_control` shard always retains at least `control_reserve_records` queue
slots, and normal records can consume neither those slots nor
`control_reserve_bytes`. Control records may use the reserved bytes and then the shared
remainder, but may never exceed `worker_max_bytes`; control associations are charged to
the same class. Per-shard record/byte ceilings still apply in addition to the resident
budget. Configuration therefore requires
`control_reserve_records <= shard_max_records` and
`control_reserve_bytes <= shard_max_bytes`, in addition to the worker-wide byte
constraints; a configuration that cannot physically honor either reserve is rejected.
The high-water result is computed from resident utilization, not queue-only utilization.

Blocked-sync tests must drain normal rows from queues into stream buffers and in-flight
work, keep the sync backend blocked, and prove further normal admission overflows while
a validated `_control` draft still fits its reserve. A second test fills the control
reserve under the same blocked sync and proves `CONTROL_OVERFLOW` at the global ceiling.
Both tests assert the stage-byte identity above before and after releasing sync and
verify that terminal accounting releases every charge exactly once.

Each service owns exactly one asyncio service-loop task. It is the only task allowed
to drain ingress shards, mutate active-file mappings, seal frames, initiate periodic
flush, execute rotation/config/shutdown commands, or transition lifecycle state.
Commands enter a private FIFO command queue and carry watermarks. The loop drains
shards fairly, reserves control capacity, seals a frame before its plain-byte limit is
exceeded, and makes an oversized single record its own sealed frame. No append API may
allow the active plain buffer to grow beyond one configured frame.

A loop turn follows this state machine:

1. Consume every completed per-file notification, advancing ledger entries to
   `DURABLE` or terminal uncertain and waking affected command barriers.
2. Drain at most one record from each currently nonempty shard in round-robin order,
   then return to command/timer processing before another round. `_control` is a
   reserved shard, not a permanently higher-priority drain loop.
3. Seal any full/due buffers and start eligible coordinator batches as owned tasks;
   never await a whole batch inline. A blocked sync therefore cannot stop queue
   admission, completion accounting for other files, or watchdog checks.
4. Advance the oldest lifecycle command as a state machine. It may seal, start one
   group batch, wait for its watermark, and publish completed parts, but a later
   lifecycle command cannot overtake it.
5. Evaluate periodic-flush and critical-age deadlines. When no immediate work remains,
   wait for either the service wake event, an owned-job completion, or the next injected
   sleeper deadline. Temporary wait tasks may exist; there is still only one task that
   executes service-loop state transitions.

Successful admission assigns a monotonically increasing service-local acceptance
ordinal and sets the wake event before returning. `sync_now` and hour rotation snapshot
that ordinal into their command watermark, but an hour command is only a drain/finalize
barrier and never chooses a record's partition. Config rotation, shutdown close, and
`mark_incomplete` synchronously close the admission gate and then snapshot the ordinal
before their first `await`; this tiny gate operation is the only mutation outside the
service loop and cannot interleave with synchronous `try_accept`. Config and shutdown
commands drain records through their watermark into the old config identity; size
rotation uses its recorded seal ordinal. Hour routing is instead decided independently
for every accepted record from `envelope.received_at_ns`: immediately before append,
the service loop derives its UTC hour and, when it differs from the logical-active
generation's hour, atomically seals that generation and installs a correctly partitioned
new generation before appending the record. This applies to forward and backward hour
changes and may allocate another sequence in an earlier hour; no acceptance ordinal or
current wall clock may place a row in the wrong hour. Public methods
enqueue the command and await its result under `asyncio.shield`; caller cancellation
detaches the caller but does not cancel or remove the command. Executor/coordinator
tasks may produce immutable completion messages but cannot mutate active-file mappings
or lifecycle state.

Sealing and publication are different boundaries. For a received-hour change, the loop
atomically removes the mismatched generation from the logical-active map, installs the
record's hour-specific next `generation_id`, and records the last ordinal actually
appended to the retiring file before starting final sync; the different-hour record is
the first append to the replacement. For size rotation it installs the next same-hour
generation and records seal ordinal `N`; ordinals already appended through `N` remain in
the retiring generation and later drained rows use the replacement. An hour-rotation
command waits through its watermark, groups every generation already retired because of
hour mismatch, and finalizes them; it does not reroute queued rows by ordinal. In either
case,
the old file descriptor may remain open in the retiring map until its owned sync and
publication finish, but it is never logical-active again. At most one file descriptor
per generation exists, no generation enters overlapping batches, no detached work is
submitted twice, and the worker-wide sync semaphore covers active and retiring
generations together. Config rotation instead
closes admission, drains through its watermark, publishes every old-config generation
with `CloseReason.CONFIG_RELOAD`, installs the strictly greater `config_generation`
and new SHA, then reopens admission. Shutdown never installs replacements.

`active_logical_generation_count`, `retiring_generation_count`, and
`open_file_descriptor_count` are separate snapshot fields. Gate B uses the first for
the 3,505 identity requirement and reports the other two independently. Qualification
defines the first as the cardinality of the admission-routing map, the second as sealed
generations still owned through sync/publication, and the third as currently open
service-owned `StreamFile` data descriptors across both maps. It does not fold the
writer-lock FD or transient directory FDs into that third field; Gate B's separately
sampled process `open_fds_peak` includes all process descriptors.
Qualification
must choose monotonic admission start/end whose corresponding UTC wall-clock values
are in the same hour and must leave enough preflight margin for the full declared
duration; crossing an hour is a qualification failure rather than an unaccounted file
overlap. Functional mode may cross an hour only if its report reconciles every retiring
generation and open descriptor explicitly.

The loop uses the injected sleeper for both the periodic flush deadline and watchdog.
Tests advance a fake clock and wake fake sleepers; production uses `asyncio.sleep`.
Runtime owns producer stop/reconnect behavior, but the storage gate itself is
synchronous and race-safe.

### Coordinator concurrency, accounting, and cancellation

The worker owns one `StorageIoLimiter` and its one semaphore for the full lock lifetime;
it is never created inside a batch. The live `DurabilityCoordinator` and the startup
`RecoveryDurabilityCoordinator` share that limiter and the one bounded executor, so
periodic, size, hour, config, recovered-prefix, and shutdown work together can never
exceed `max_sync_concurrency`. The recovery coordinator is constructed with mandatory
`RecoveryAccountingMode.UNMEASURED` and has its own transaction-local result collector.
It never receives the current process `DurabilityLedger`, live per-part statistics,
rolling histogram, SLO callback, or `WriterMetricsSnapshotV1` counters. Recovered
prior-process rows therefore create no current-process accepted/durable or lag samples.
It still returns the single executable `FileDurabilityResult` type, with recovered
`record_count`, `was_dirty`, sync timing, and every lag quantile/max set to `None`; those
results may form a transaction-local `DurabilityBatch(trigger=RECOVERY)` but never
enter live per-part statistics, the live rolling window, or a public snapshot.
Recovery journals, quarantine suffixes, hashes, and manifest metadata use the same
limiter/executor and remain outside both record ledgers.
This rule applies to prior-process recovered bytes. A newly emitted recovery `_control`
row is a current-process accepted record: the single service loop registers it in the
live ledger, persists it with the live coordinator using `DurabilityTrigger.RECOVERY`,
and includes its measured sample in its eventual normal control manifest.
The service loop prevents two batches from targeting the same open file; the
coordinator additionally rejects a duplicate `SealedFileWork.generation_id` already
in flight. If a frame-cap seal is in flight when an oversized record for that same
generation arrives, the loop retains the one-row `PendingRows` in its bounded
generation work queue at `BUFFERED`; the completion notification then permits
`seal_for_sync(direct_rows=...)`. It never submits concurrent work for one FD and
never returns the record to ingress.

When the service loop consumes each successful per-file completion, it updates all
owned statistics and removes those records from the oldest-unpersisted index without
waiting for an unrelated blocked file. When it consumes a sync or write failure, it
marks the affected records terminal uncertain, invokes `on_critical` once, and keeps
all other already-started blocking jobs owned until they finish. Caller cancellation detaches the caller but never
cancels or abandons the internal batch task. After complete accounting, a writer
critical error takes precedence over cancellation; otherwise the original cancellation
is propagated. Repeated cancellation cannot return while a thread may still use an FD.

At submission, the service loop installs exactly one
`generation_id -> tuple[(AcceptedRecordIdentityV1, accepted_monotonic_ns), ...]`
in-flight claim from that immutable `SealedFileWork.pending`; the generation exclusion
rule makes the lookup unambiguous even across sequential batches for one file. A
completion's `record_count` must equal its claim length and its
`sync_completed_monotonic_ns` must be present for dirty work. The loop computes every
lag and bucket delta from that claim plus the completion time, applies the same delta to
the per-part, public aggregate, labeled-series, and private-ring owners, then removes the
claim. Coordinator-provided quantile/max fields are an immutable result cross-check, not
a statistics source. A mismatch is terminal `SYNC_FAILED`; the loop never guesses which
generation rows completed.

Terminal critical accounting is generation- and record-exact. The first critical
transition closes admission and freezes one disposition plan for every record then in
`QUEUED`, `BUFFERED`, or `IN_FLIGHT`; later errors cannot omit or double-classify a
record. The service continues consuming completion messages until all started blocking
jobs finish, and it exposes `CRITICAL` immediately but does not claim terminal resource
cleanup until `unpersisted_record_count == 0`. The reason-specific rules are:

- `OLDEST_UNPERSISTED_AGE`: continue a critical drain of all queued/buffered rows
  already accepted, seal them, and settle every sync; successes become `DURABLE` and
  any write/sync uncertainty becomes `UNCERTAIN`;
- `WRITE_FAILED` or `SYNC_FAILED`: the failed work's rows become `UNCERTAIN`; no new
  writes are initiated, all queued/buffered rows become `UNCERTAIN`, and other already
  in-flight jobs become `DURABLE` or `UNCERTAIN` from their actual result;
- `PUBLICATION_FAILED`: rows whose final file sync completed remain `DURABLE` even when
  a manifest/name is withheld; queued/buffered rows in replacement generations become
  `UNCERTAIN`, and unrelated already in-flight work is settled from its actual result;
- `CONTROL_DURABILITY_FAILED` uses the write/sync rule for any live accepted control,
  including a startup recovery control. After startup control admission, failure to
  durably publish its `control-durable.json` or `complete.json` acknowledgement is also
  this reason; a control with confirmed raw sync remains `DURABLE`, while an
  unconfirmed one becomes `UNCERTAIN`. A control rejected before acceptance contributes
  no identity or ledger entry;
- `SLO_TRANSITION_CALLBACK_FAILED` occurs only after the completion or watchdog turn
  has atomically updated the ring and SLO state. The just-completed rows remain
  `DURABLE`; admission closes, queued/buffered rows become `UNCERTAIN`, and already
  in-flight rows settle from their actual result. The callback exception is retained as
  the `WriterCriticalError` cause;
- `CLOSE_DEADLINE` or `MARKED_INCOMPLETE`: rows not submitted when the gate/deadline
  takes effect become `UNCERTAIN`; already in-flight rows are still owned and become
  `DURABLE` on confirmed sync or `UNCERTAIN` on failure;
`RecoveryBlocked` is the distinct pre-service startup failure boundary, not a
`WriterCriticalError` reason. It is raised only before the first current-process record
or recovery-control acceptance, so no `RawWriterService` is returned, no writer
lifecycle/status snapshot exists for the failed open, `on_critical` is not called, and
all current-process record counts remain zero. `RawWriterService.open` still closes all
owned resources and releases the writer lock before propagating it. Once any recovery
control is accepted, every later failure uses `CONTROL_DURABILITY_FAILED` and the
record-exact terminal accounting above.

During critical drain, the normal conservation equations continue to hold. After all
owned work and dispositions finish, terminal `CRITICAL` additionally requires
`queued_records == buffered_records == in_flight_records == unpersisted_record_count ==
resident_record_bytes == 0` and
`accepted_record_count == durable_record_count + uncertain_record_count`. The exact
accepted identity set equals the disjoint union of the durable and uncertain identity
sets. Tests inject every reason with records in all three nonterminal stages, block and
release unrelated jobs, repeat cancellation, and assert these invariants before the
writer lock or any descriptor is released.
The identity-set equality is a semantic/test-instrumentation invariant, not permission
to retain an unbounded production set of every durable identity. Production discards
terminal ledger entries after updating bounded counters/per-part aggregates; tests and
Gate B derive the set proof from their external transition/admission traces.

Durability statistics have three non-overlapping owners: immutable per-part aggregates
for manifests, a process-lifetime cumulative public histogram for
`WriterMetricsSnapshotV1`, and a private last-60-seconds alert ring. All use the same
versioned integer bucket boundaries and deterministic nearest-rank p50/p95/p99; their
schema and rounding are golden-tested. After every completion and watchdog tick, the
service evaluates the same 60-slot snapshot. It is breached exactly when
`rolling_max_ns > durability_slo_ns` or
`rolling_p99_ns > durability_slo_ns`; `None` is non-breaching. It emits `BREACHED` only
on a false-to-true transition, increments `slo_breach_count` only then, and emits
`RECOVERED` only on a true-to-false transition after both values are `None` or at most
the SLO. The watchdog performs this evaluation even without new completions, so an old
breach recovers at the exact monotonic-second expiry boundary. A later breach emits a
new event. Every `DurabilitySloTransition` carries the exact rolling p99 and rolling
max from that evaluation; no batch-local max participates. Manifest snapshots contain
only their part aggregate, never the public lifetime aggregate, the rolling ring, or an
unbounded list of every batch. The service loop is the sole writer of all three after
consuming an immutable per-file completion.
The service invokes `on_slo_transition` synchronously once for each breach/recovery
transition. Plan 04 production runtime injects a callback that converts it to a
reserved control draft and requires successful admission; callback failure enters
`CRITICAL` with `WriterCriticalReason.SLO_TRANSITION_CALLBACK_FAILED`. The service
records the transition before invoking the callback and invokes `on_critical` exactly
once with the causal exception. Benchmarks and isolated storage tests may leave the
callback unset.

```python
DURABILITY_HISTOGRAM_SCHEMA_VERSION = 1
MAX_DURABILITY_METRIC_STREAM_LABELS = 64
OTHER_DURABILITY_METRIC_STREAM_LABEL = "_other"
DURABILITY_BUCKET_UPPER_BOUNDS_NS = (
    0,
    100_000, 250_000, 500_000,
    1_000_000, 2_500_000, 5_000_000,
    10_000_000, 25_000_000, 50_000_000,
    100_000_000, 250_000_000, 500_000_000, 750_000_000,
    1_000_000_000, 1_500_000_000, 2_000_000_000,
    3_000_000_000, 5_000_000_000, 10_000_000_000,
    60_000_000_000, 2**63 - 1,
)
```

For quantile `q`, rank is `max(1, ceil(q * count))`; return the smallest bucket upper
bound whose cumulative count reaches the rank. The exact sample count, total, and max
are tracked separately. Empty histograms report all quantiles and max as `None`.
Only counts and max have a monotonicity contract; a cumulative nearest-rank quantile can
move downward after enough lower-lag samples and that is valid.

### Group final sync and immutable publication

Hour, config, and shutdown rotation first atomically seal and detach every due part,
then call one `sync_batch(all_due_work, trigger=...)`. The returned result contains per-file
`FileDurabilityResult` views. It is the only post-sync file result type. Only after
every started blocking job is accounted may
the service close and publish files one by one. Size rotation follows the same path
with its smaller due set. Records arriving after a seal go only to the next part.
Every requested generation appears in the result, including a clean/no-op member. If
any member fails write or sync, no member of that rotation group is normally published;
the service enters `CRITICAL` and leaves every sealed partial for journaled startup
recovery. Successfully synced members remain durably accounted even though their
normal manifests were withheld.

The all-or-none guarantee ends after final write/sync classification. Data and
manifest publication is deliberately sequential because immutable no-replace names
cannot be rolled back safely. If publication of member N fails, members already fully
published remain valid and visible; N and every later member retain all partial,
temporary, or coexistence names. The service records `PUBLICATION_FAILED` with the
affected generation IDs, enters `CRITICAL`, and performs no rollback or overwrite.
Startup recovery reconciles every generation independently to exactly one complete or
quarantined outcome and accepts already complete earlier members after full validation.

Every blocking compression, write, sync, SHA-256 scan, rename/link, directory sync,
and manifest write runs through the service's bounded storage executor. Publication
uses `publish_no_replace(source, destination)`, which is explicitly restricted to
two distinct basenames in the same already-open parent directory and rejects different
parents. Linux uses `renameat2(RENAME_NOREPLACE)` followed by one sync of that common
parent. The fallback is exactly `link(source, destination) -> fsync(common_parent) ->
unlink(source) -> fsync(common_parent)`. Cross-directory recovery moves first create
and sync a temporary sibling of the destination, then use this same-parent helper; they
never pass different parents to it. The helper returns only after this protocol. Probe
`data_root` and `state_root`
independently; if neither primitive is supported on either required filesystem, open
fails. `exists()` followed by overwriting `os.rename()` is forbidden.
On `EEXIST`, open both names with `O_NOFOLLOW` and compare `fstat`: the same device/
inode is recoverable fallback coexistence, while a different identity is an immutable
conflict even if its current bytes happen to hash equally. A retry with an absent
source accepts an existing destination only through the matching recovery journal.

The first directory entry is itself part of durability. `StreamFile.allocate` creates
any missing layout directories through no-follow directory FDs and fsyncs each parent
after `mkdir`; it creates each `.partial` with `O_CREAT | O_EXCL`, then fsyncs its
parent directory before the
file can receive an accepted record or the allocator can return it. Every exclusive
manifest/journal temporary is likewise directory-synced at first creation before any
later fact is allowed to depend on that name. Unit traces and SIGKILL subprocess tests
cover failure immediately before and after these initial parent-directory syncs.

### Manifest, lease, and recovery schemas

`RawManifestV1` is a frozen strict structural model; parsing it never requires the
data file to still exist. Canonical manifest bytes use the declared model field order,
sorted tuple members, Decimal-aware JSON, and one trailing newline. The
source-manifest SHA-256 is the hash of those exact closed bytes and is exposed by the
manifest loader. The exact V1 JSON keys, grouped below only for readability, are:

`RawManifestV1.canonical_bytes() -> bytes` emits fields in the order listed below,
enum values as strings, tuples as arrays, compact separators, UTF-8, and one final
newline. `load_raw_manifest` requires the source bytes to equal that result exactly.

- identity: `schema_version: Literal[1]`, `exchange: Exchange`,
  `market: Market | None`, `instrument_key: str | None`, `logical_stream: str`,
  `wire_symbols: tuple[str, ...]`, `data_relative_path: str`, and
  `manifest_relative_path: str`;
- file: `file_size_bytes: int`, `file_sha256: Sha256`, `zstd_level: int | None`,
  `zstd_write_checksum: Literal[True]`, `zstd_write_content_size: Literal[True]`, and
  `max_plain_frame_bytes: int | None`;
- rows: `record_count: int`, `first_received_at_ns: int`, `last_received_at_ns: int`,
  `first_event_time_ns: int | None`, `last_event_time_ns: int | None`,
  `worker_instance_id: str`, `connection_generations: tuple[int, ...]`,
  `writer_sequence_first: int`, `writer_sequence_last: int`,
  `config_sha256: Sha256`, `egress_ids: tuple[str, ...]`,
  `requested_intervals_ns: tuple[int, ...]`, and
  `effective_intervals_ns: tuple[int, ...]`;
- control: `gap_count`, `reconnect_count`, `parse_error_count`,
  `checksum_error_count`, and `queue_overflow_count`, each `int | None`, plus
  `control_event_ids: tuple[str, ...] | None`. Normal manifests require non-negative
  values and derive them only from exact `StorageControlAssociationV1` targets.
  Recovery manifests set all six summary fields to `None`; recovery never reconstructs
  original association semantics from nearby rows or invents original event IDs;
- durability: `durability_measurement: Literal["measured", "unavailable_after_crash"]`,
  `durability_sample_count`, `durability_lag_p50_ns`, `durability_lag_p95_ns`,
  `durability_lag_p99_ns`, `durability_lag_max_ns`, `sync_count`,
  `sync_duration_total_ns`, `sync_duration_max_ns`, `slo_breach_count`,
  `write_failure_count`, and `sync_failure_count`, each typed `int | None`. Values are
  non-negative when present; normal manifests require every value, while recovery
  manifests use `None` for every value not reconstructable from durable bytes;
- close/recovery: `close_reason: CloseReason`, `created_at_ns: int | None`,
  `closed_at_ns: int`, `recovery_transaction_id: str | None`,
  `recovery_source_state: RecoverySourceState | None`,
  `recovery_source_relative_path: str | None`,
  `recovery_source_bytes: int | None`, `recovery_source_sha256: Sha256 | None`,
  `recovery_control_event_id: str | None`,
  `recovered_frame_count: int | None`,
  `recovered_record_count: int | None`, `recovered_bytes: int | None`,
  `recovered_sha256: Sha256 | None`, `quarantined_suffix_relative_path: str | None`,
  `quarantined_suffix_bytes: int | None`, `quarantined_suffix_sha256: Sha256 | None`,
  and `unavailable_fields: tuple[str, ...]`.

All present counts and nanosecond timestamps are strict non-negative integers; sizes
and normal record counts are positive. Plan 02 tightens control scope at its boundary:
`logical_stream="_control"` requires `market=None` and `instrument_key=None`;
non-control manifests require a market, market-scoped identities permit
`instrument_key=None`, and instrument identities require it. All tuples are
deduplicated and sorted. Empty
normal parts are never published. A normal manifest requires `zstd_level` and
`max_plain_frame_bytes`, every control/durability summary, all recovery lineage fields
including `recovery_control_event_id` to be `None`,
`unavailable_fields=()`, and `durability_sample_count == record_count`.
Both relative paths are normalized POSIX paths below `data_root`; absolute paths,
`..`, empty segments, and backslashes are invalid.

```python
class RecoverySourceState(StrEnum):
    PARTIAL_COMPLETE = "partial_complete"
    PARTIAL_TRUNCATED = "partial_truncated"
    ORPHAN_CLOSED_DATA = "orphan_closed_data"
    OWNED_CONTROL_CARRIER = "owned_control_carrier"
    PUBLICATION_COEXISTENCE = "publication_coexistence"
    CLEANUP_INTENT = "cleanup_intent"
    CLEANUP_TOMBSTONE = "cleanup_tombstone"
```

The identity fields and both relative paths must also reproduce the canonical layout
derived from the rows: exchange/scope/stream segments and UTC received-time hour must
match, the data name ends in `.jsonl.zst`, and the manifest is its exact sibling.
Recovery transaction IDs are canonical lowercase UUID strings.

Normal manifests require all normal fields. Recovery manifests require
`close_reason=RECOVERY`, transaction/source state/path/size/SHA, recovered prefix
frame/record/byte/hash facts, and `durability_measurement="unavailable_after_crash"`.
For copied-prefix recovery, `recovered_bytes == file_size_bytes` and
`recovered_sha256 == file_sha256`; if a suffix exists, its path/size/SHA triple is all
present and `recovered_bytes + quarantined_suffix_bytes == recovery_source_bytes`.
For a fully valid retained closed orphan, recovered and source size/hash are
equal, `RecoveryOutcome.recovered_relative_path` equals the unchanged source path, and
the quarantine triple is all `None`. An invalid closed orphan gets no recovery manifest
and is wholly quarantined. For the four discovered-source branches, `closed_at_ns` is
the recovery intent's frozen wall-clock close time, never a guessed original close
time. The owned-control contingency manifest instead uses its later, admission-backed
`RecoveryControlOwnershipV1.created_at_ns` as specified below.
The cleanup enum values are informational `RecoveryOutcome` states only and never
replace the retained normal source manifest with a recovery manifest.
Each recovery manifest carries its intent's independent lineage ID only in
`recovery_control_event_id`; `control_event_ids` remains `None` because it represents
lost original-process associations. Startup cannot accept traffic until the lineage ID
has been durably emitted or re-emitted and acknowledged by the transaction fact chain.

Schema-inapplicable nulls, such as `_control.market`, absent event time, or an absent
quarantine suffix, are ordinary nulls and are not listed as unavailable. Every recovery
manifest uses this exact sorted lost-summary set:

```python
RECOVERY_UNAVAILABLE_FIELDS = tuple(sorted({
    "zstd_level", "max_plain_frame_bytes", "created_at_ns",
    "gap_count", "reconnect_count", "parse_error_count",
    "checksum_error_count", "queue_overflow_count", "control_event_ids",
    "durability_sample_count", "durability_lag_p50_ns",
    "durability_lag_p95_ns", "durability_lag_p99_ns",
    "durability_lag_max_ns", "sync_count", "sync_duration_total_ns",
    "sync_duration_max_ns", "slo_breach_count", "write_failure_count",
    "sync_failure_count",
}))
```

Every named field must be `None`, no other normally required field may be `None`, and
schema-inapplicable fields are not named. Recovery may not invent a codec setting,
original creation time, original control summary/event ID, durability value, or
failure count. `load_raw_manifest` performs structural/canonical validation.
`validate_local_source` separately returns a `LocalSourceValidation` whose disposition
is `PRESENT_VERIFIED`, `CLEANUP_INTENT`, `CLEANUP_TOMBSTONE`, or
`MISSING_UNEXPLAINED` and whose proof is populated only for a validated cleanup state.

`manifest_path_for_data` and `lease_path_for_data` are the sole public sibling-path
builders and both require a complete `.jsonl.zst` filename. They replace that entire
suffix with `.manifest.json` and `.lease`, respectively. The public loader contract
is:

```python
@dataclass(frozen=True, slots=True)
class LoadedRawManifest:
    path: Path
    manifest: RawManifestV1
    canonical_bytes: bytes
    sha256: Sha256


class SourceDisposition(StrEnum):
    PRESENT_VERIFIED = "present_verified"
    CLEANUP_INTENT = "cleanup_intent"
    CLEANUP_TOMBSTONE = "cleanup_tombstone"
    MISSING_UNEXPLAINED = "missing_unexplained"


class CleanupProofKind(StrEnum):
    DURABLE_INTENT = "durable_intent"
    FINAL_TOMBSTONE = "final_tombstone"


class CleanupProofEvidenceV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    kind: CleanupProofKind
    proof_relative_path: NormalizedStateRelativePath
    proof_size_bytes: PositiveInt
    proof_sha256: Sha256
    source_manifest_relative_path: NormalizedDataRelativePath
    source_manifest_sha256: Sha256
    source_data_relative_path: NormalizedDataRelativePath
    source_data_size_bytes: PositiveInt
    source_data_sha256: Sha256


@dataclass(frozen=True, slots=True)
class LocalSourceValidation:
    disposition: SourceDisposition
    cleanup_proof: CleanupProofEvidenceV1 | None


class SourceDispositionResolver(Protocol):
    def resolve_missing(
        self,
        *,
        loaded: LoadedRawManifest,
        data_path: Path,
        expected_data_sha256: str,
        expected_proof: CleanupProofEvidenceV1 | None = None,
    ) -> CleanupProofEvidenceV1 | None: ...


def load_raw_manifest(path: Path) -> LoadedRawManifest: ...
def validate_local_source(
    loaded: LoadedRawManifest,
    *,
    data_root: Path,
    resolver: SourceDispositionResolver,
    lease: SourceLease,
    expected_cleanup_proof: CleanupProofEvidenceV1 | None = None,
) -> LocalSourceValidation: ...


class SourceLease:
    lease_path: Path

    @classmethod
    def shared(cls, lease_path: Path, *, blocking: bool = True) -> "SourceLease": ...

    @classmethod
    def exclusive(cls, lease_path: Path, *, blocking: bool = True) -> "SourceLease": ...

    def release(self) -> None: ...
    def __enter__(self) -> "SourceLease": ...
    def __exit__(self, *_exc: object) -> None: ...


class RawManifestReader:
    def __init__(self, manifest_path: Path) -> None: ...
    def __enter__(self) -> "RawManifestReader": ...
    def __iter__(self) -> Iterator[RawEnvelope]: ...
    def __exit__(self, *_exc: object) -> None: ...
```

`RawManifestReader` holds a shared `SourceLease` for its entire validation/read
lifetime; any recovery action that mutates an already closed data identity holds an
exclusive lease. Lock and lease opens use `O_NOFOLLOW`, verify `fstat` reports a
regular file, and reject symlinks and non-regular files. A missing lease is created
with `O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW`, mode `0o640`, and is never removed
when source data is cleaned. Parent directories are opened segment-by-segment with
directory FDs and `O_DIRECTORY | O_NOFOLLOW`; neither reader nor recovery follows a
symlink in a manifest/data/lease path. `validate_local_source` verifies that the supplied lease
is for the manifest's exact data identity and is still held. Only `EACCES`/`EAGAIN`
maps to `SourceLeaseBusy`; other `OSError` values retain their causes. Structural or
canonical failures raise `ManifestValidationError`, a non-present reader source raises
`SourceUnavailable`, immutable destination collisions raise `PublicationConflict`,
and incomplete/corrupt recovery facts raise `RecoveryBlocked`.
`RawManifestReader(manifest_path)` infers `data_root` only by stripping the validated
`manifest_relative_path` suffix from that absolute path; any mismatch is a manifest
validation error. It acquires the derived data lease before local size/hash validation
and retains it until iterator/context exit.

Plan 07 owns cleanup-intent/tombstone schemas and supplies their validator through the
Plan 02 `SourceDispositionResolver` protocol. A final validated tombstone or a durable
validated cleanup intent that binds the exact manifest path/SHA and source path/SHA is
a legitimate missing-data state: recovery preserves the manifest and lease and emits
an informational recovery outcome. An absent, temporary, corrupt, or mismatched proof
does not authorize quarantine or deletion; recovery preserves the manifest, reports
`MISSING_UNEXPLAINED`, and blocks startup for operator repair. Before Plan 07 is
installed, the default resolver returns `None`.
`PRESENT_VERIFIED` is computed only by local size/hash validation. For a missing source,
the resolver returns either one fully validated `CleanupProofEvidenceV1` or `None`;
`validate_local_source` maps its kind to the corresponding cleanup disposition or maps
`None` to `MISSING_UNEXPLAINED`. The proof path is relative to `state_root`; its SHA is
over the proof's exact canonical on-disk bytes, and its remaining fields are independently
checked against the loaded manifest and expected data identity. On initial discovery,
the resolver deterministically prefers a final tombstone over a durable intent. On
replay, recovery passes `expected_proof`; the resolver must open and revalidate that
exact path/size/SHA/kind and return byte-for-byte equal evidence even if a newer proof
also exists. A temporary, symlinked, non-canonical, mismatched, missing, or substituted
proof returns no match and blocks replay; an enum-only assertion is never evidence.

Recovery uses the Decimal-aware `decode_json` path, explicitly converts the known
enum fields to their domain enum instances, and only then calls strict
`RawEnvelope.model_validate`. It must not use Pydantic's default JSON parser, which
would turn payload JSON numbers into binary floats. Every complete frame is withheld
until its checksum, frame end, JSONL boundaries, and every full envelope validate.

Validation also binds bytes to their source identity. Every recovered row must match
the exchange, scope, logical stream, and UTC received-time hour encoded by its source
path; instrument-scoped wire symbols must produce the manifest's exact sorted set.
Every row in one part has the same worker instance and config SHA, and writer sequences
are strictly increasing for that part's sequence identity. A mismatch, duplicate,
reversal, cross-hour row, or trailing non-JSONL byte makes that frame and every later
byte ineligible for the recovered prefix. Orphan closed data is subject to the same
checks before a recovery manifest is created.

Each startup reconciliation is a canonical hash-linked transaction rooted at
`<state_root>/raw-recovery/<exchange>/<transaction-uuid>/`. These are the exact V1
schemas; no implementation-specific keys are permitted:

```python
class RecoverySourceDisposition(StrEnum):
    RETAINED = "retained"
    REMOVED = "removed"
    MOVED_TO_QUARANTINE = "moved_to_quarantine"
    LEGITIMATELY_MISSING = "legitimately_missing"


class RecoveryIntentV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    fact_kind: Literal["intent"] = "intent"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: None = None
    source_state: RecoverySourceState
    source_relative_path: NormalizedDataRelativePath
    source_size_bytes: NonNegativeInt
    source_sha256: Sha256
    planned_source_disposition: RecoverySourceDisposition
    planned_data_generation_id: NonEmptyString | None
    planned_data_relative_path: NormalizedDataRelativePath | None
    planned_data_size_bytes: PositiveInt | None
    planned_data_sha256: Sha256 | None
    planned_manifest_relative_path: NormalizedDataRelativePath | None
    planned_manifest_size_bytes: PositiveInt | None
    planned_manifest_sha256: Sha256 | None
    planned_quarantine_relative_path: NormalizedDataRelativePath | None
    planned_quarantine_size_bytes: NonNegativeInt | None
    planned_quarantine_sha256: Sha256 | None
    cleanup_proof_kind: CleanupProofKind | None
    cleanup_proof_relative_path: NormalizedStateRelativePath | None
    cleanup_proof_size_bytes: PositiveInt | None
    cleanup_proof_sha256: Sha256 | None
    recovery_control_event_id: NonEmptyString
    fact_sha256: Sha256


class RecoveryArtifactsDurableV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    fact_kind: Literal["artifacts_durable"] = "artifacts_durable"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    data_generation_id: NonEmptyString | None
    data_relative_path: NormalizedDataRelativePath | None
    data_size_bytes: PositiveInt | None
    data_sha256: Sha256 | None
    manifest_relative_path: NormalizedDataRelativePath | None
    manifest_size_bytes: PositiveInt | None
    manifest_sha256: Sha256 | None
    quarantine_relative_path: NormalizedDataRelativePath | None
    quarantine_size_bytes: NonNegativeInt | None
    quarantine_sha256: Sha256 | None
    fact_sha256: Sha256


class RecoverySourceSettledV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    fact_kind: Literal["source_settled"] = "source_settled"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    source_relative_path: NormalizedDataRelativePath
    source_disposition: RecoverySourceDisposition
    settled_relative_path: NormalizedDataRelativePath | None
    settled_size_bytes: NonNegativeInt | None
    settled_sha256: Sha256 | None
    fact_sha256: Sha256


class RecoveryControlOwnershipV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    fact_kind: Literal["control_ownership"] = "control_ownership"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    recovery_control_event_id: NonEmptyString
    control_record_identity: AcceptedRecordIdentityV1
    control_envelope: RawEnvelope
    control_encoded_sha256: Sha256
    control_frame_base64: NonEmptyString
    control_frame_size_bytes: PositiveInt
    control_frame_sha256: Sha256
    control_recovery_manifest_base64: NonEmptyString
    control_recovery_manifest_size_bytes: PositiveInt
    control_recovery_manifest_sha256: Sha256
    control_generation_id: NonEmptyString
    control_data_relative_path: NormalizedDataRelativePath
    control_manifest_relative_path: NormalizedDataRelativePath
    control_association: StorageControlAssociationV1 | None
    zstd_level: int
    max_plain_frame_bytes: PositiveInt
    fact_sha256: Sha256


class RecoveryControlDurableV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    fact_kind: Literal["control_durable"] = "control_durable"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    recovery_control_event_id: NonEmptyString
    control_record_identity: AcceptedRecordIdentityV1
    control_generation_id: NonEmptyString
    control_data_relative_path: NormalizedDataRelativePath
    control_encoded_sha256: Sha256
    durable_at_monotonic_ns: NonNegativeInt
    fact_sha256: Sha256


class RecoveryCompleteV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    fact_kind: Literal["complete"] = "complete"
    transaction_id: CanonicalUuid
    created_at_ns: NonNegativeInt
    predecessor_sha256: Sha256
    recovery_control_event_id: NonEmptyString
    source_state: RecoverySourceState
    source_disposition: RecoverySourceDisposition
    outcome_sha256: Sha256
    fact_sha256: Sha256
```

For every fact, `hash_payload_bytes()` is `encode_json(model_dump(mode="python",
exclude={"fact_sha256"})) + b"\n"` in declared model field order; `fact_sha256` is the
lowercase SHA-256 of those bytes. `canonical_fact_bytes()` is the same encoding with
`fact_sha256` included. A loader requires on-disk bytes to equal
`canonical_fact_bytes()` and recomputes the hash. Each non-intent predecessor equals
the immediately prior fact's `fact_sha256`. Every `created_at_ns` is injected UTC
wall-clock nanoseconds; only `durable_at_monotonic_ns` is monotonic. Fact filenames and
the sole legal chain are exactly:

```text
intent.json
  -> artifacts-durable.json
  -> source-settled.json
  -> control-ownership.json
  -> control-durable.json
  -> complete.json
```

`recovery_control_event_id` is exactly
`"raw-recovery-lineage:v1:" + transaction_id`; it is a new lineage identity and is
never copied from or substituted for an unavailable original control event ID. A
discovered-source recovery manifest uses `closed_at_ns=intent.created_at_ns`. The owned
control contingency manifest uses
`closed_at_ns=control_ownership.created_at_ns`; both timestamps are frozen before the
corresponding filesystem mutation. `RecoveryCompleteV1.outcome_sha256` hashes
`encode_json(dataclasses.asdict(RecoveryOutcome)) + b"\n"` in the dataclass field order
shown in the public contract.
`RecoveryControlOwnershipV1` is published only after the in-memory acceptance succeeds
but before any carrier path is allocated or written. Its envelope must re-encode to
`control_encoded_sha256`; its identity must exactly match that envelope plus its
acceptance ordinal/config generation; its optional association must be exactly the one
constructed from `PendingRecoveryControl.target` at that admission. Its final data and
manifest are a canonical dedicated `_control` sibling pair for
`control_generation_id`, and the derived `.partial` contains exactly this one row. The
service compresses that row to one independent frame in memory before binding. The fact
stores canonical padded RFC 4648 base64 of those exact bounded bytes; decoding must
equal `control_frame_size_bytes`/`control_frame_sha256` and decompress to exactly the
one encoded envelope. Before hashing the ownership fact, the backend also builds the
complete contingency `RawManifestV1` described below and stores its canonical bytes as
padded RFC 4648 base64 plus exact size/SHA. Decoding must equal
`control_recovery_manifest_size_bytes`/`control_recovery_manifest_sha256`, parse as one
canonical manifest, and re-encode byte-for-byte. The codec fields freeze replay
validation. This fact owns all three carrier names for the
original transaction, so the general orphan scanner may reserve them but may never
derive a second transaction from them.
`RecoveryControlDurableV1.predecessor_sha256` must therefore equal the ownership fact,
never `source-settled.json` directly; a receipt supplied without exact ownership is
invalid even if a matching-looking row happens to exist elsewhere.

The frozen contingency manifest has a complete, ownership-backed mapping. Its identity
is `schema_version=1`, the ownership identity's exchange,
`market=None`, `instrument_key=None`, `logical_stream="_control"`,
`wire_symbols=()`, and the exact owned final data/manifest paths. Its file group uses
the frame size/SHA, both zstd flags true, and `None` for the codec values that the
generic recovery schema marks unavailable; the ownership fact's codec fields instead
validate the frozen frame itself. Its row
group is the standard one-row manifest projection of the exact owned envelope and
accepted identity: count one; first/last receive and event times, worker, optional
connection generation, writer-sequence bounds, config SHA, egress ID, and requested/
effective intervals all come only from that row. Its six control summaries and every
durability value are `None`, with
`durability_measurement="unavailable_after_crash"`. Its close/recovery group is
`close_reason=RECOVERY`, `created_at_ns=None`,
`closed_at_ns=control_ownership.created_at_ns`, this transaction/event ID,
`recovery_source_state=OWNED_CONTROL_CARRIER`, and the canonical derived `.partial`
path. For this state only, source size/SHA denote the ownership-bound complete logical
carrier, not the possibly shorter crash residue, so they equal the frame size/SHA;
recovered frame/record counts are one, recovered size/SHA equal the frame, quarantine
fields are `None`, and `unavailable_fields=RECOVERY_UNAVAILABLE_FIELDS`. No field may
depend on the observed prefix length, replay clock, host, or scan order. The ownership
loader reconstructs that mapping from the prior facts, envelope, identity, frame,
paths, and codec; it rejects the transaction unless the embedded manifest bytes, size,
and SHA all match. This mapping is the sole exception to discovered-source
`recovery_source_*` semantics.

`RecoveryControlDurableV1.control_data_relative_path` is the ownership fact's planned
final `.jsonl.zst` path. Before publishing `control-durable.json`, the exact encoded row
must be found by identity/hash in its validated closed carrier or recovered from the
owned, directory-durable `.partial`. Same-process completion publishes a normal
one-record control manifest with its measured sample. Fresh replay classifies the owned
manifest path before mutation: (1) exact canonical normal manifest plus exact final
frame: validate every normal field and advance without publishing a manifest; (2) the
exact frozen contingency manifest plus exact final frame: validate and advance; (3)
manifest absent: create/resume the carrier from the ownership frame, publish the frozen
contingency bytes with no-replace, fsync its parent, then advance; (4) anything else:
block. In branch 3 an absent carrier is created from those bytes, while an existing
`.partial` must be an exact prefix and is appended/fsynced to completion; an exact final
without a manifest is retained and paired with the contingency manifest. Any
non-prefix, extra byte, second frame, simultaneous partial/final identity, or unexpected
manifest blocks startup. The exact normal-manifest validation covers its one row,
identity/generation/path/codec, measured durability sample, association-derived control
summaries, and data size/SHA. Recovery does not emit another recovery control or
`RecoveryOutcome`. The owned `.partial` is settled before `control-durable.json`, so
recover-all leaves no carrier source behind. Coexistence is accepted only through the
no-replace recovery rules. Once
`complete.json` is durable, later replay validates the hash chain rather than requiring
that historical local control path to remain present.
Likewise, a later Plan 07 cleanup may make the recovered data path legitimately absent
only when `SourceDispositionResolver` verifies the exact recovery manifest/data hash
binding. The manifest/lease stay present under that contract. V1 defines no cleanup
proof for a quarantine artifact, so its unexplained disappearance still blocks replay.

On first use, create `raw-recovery` and its exchange directory one segment at a time
through no-follow directory FDs and fsync each containing parent immediately after
`mkdir`. Creating a transaction directory is then `mkdir` followed by fsync of the
exchange journal directory. Publishing each fact is create unique sibling temp with
`O_EXCL`, fsync the transaction directory to persist that first name, write all bytes,
fsync the temp, same-parent `publish_no_replace`, then fsync that transaction
directory before the transition is considered durable. A crash-durable claim is never
made for a new journal name before that directory sync. Fact temps are named exactly
`.<final-name>.tmp-<canonical-uuid>` and are never facts. Replay first opens each known
temp without following links: if its final is absent, unlink the temp and sync the
transaction directory before recomputing the next action; if final/temp are the same
inode from a hard-link fallback, finish the source unlink and parent sync; a different
inode is a conflict. Unknown entries or non-regular temps block startup.
A canonical final fact found without its temp is revalidated and its parent directory
is fsynced before the transition is accepted, covering a crash after rename but before
the original directory sync.

An empty transaction directory left before `intent.json` binds no source: after known
temp cleanup, replay may remove it only after proving it contains no entries and syncing
its parent. Any other nonempty directory without a valid intent, a later fact with a
missing predecessor, a wrong filename/kind, an invalid hash/link, or a fact that
disagrees with the intent is `RecoveryBlocked`.

The intent is published before any recovery-owned source mutation and binds exact source
facts, the exact planned source disposition, plus every planned artifact and cleanup
proof. For a cleanup state the data is already legitimately missing: the source
path/size/SHA are expected facts independently bound by the retained manifest and the
validated proof, not a claim that recovery read absent bytes. The planner freezes that
disposition from its already validated inputs before journal publication; replay never
derives it again from whichever names happen to remain after a crash. A partial source,
whether truncated or composed only of valid complete frames, always allocates a new
recovery `generation_id`, part sequence, data path, and
sibling manifest path distinct from the `.partial` source; it never turns the source
name into the recovered part in place. A valid closed `.jsonl.zst` orphan retains its
original data path and bytes: its intent sets planned data path/size/SHA equal to the
source and recovery publishes only the missing sibling manifest. It never copies or
renames that valid orphan to a new data identity. The data
generation/path/size/SHA group is all present or all `None`; each manifest and
quarantine path/size/SHA triple is likewise all present or all `None`. The cleanup proof
kind/path/size/SHA group is also all present or all `None`. Every present artifact and
proof must match its intent exactly. The generation ID and canonical part path are
one deterministic allocation: replay and validation recompute their binding from the
frozen allocator inputs (`part_start_ns`, part sequence, scope, and received-hour)
rather than trusting either field independently.

Discovery has exactly four mutually exclusive byte-handling branches:

| discovered source | required plan and result |
|---|---|
| `.partial` with at least one complete, checksum-valid, identity-valid frame | Copy the nonempty contiguous valid prefix to a new recovery generation and manifest, plan `REMOVED`, and quarantine only a strictly positive invalid suffix when present. |
| empty `.partial` or `.partial` with zero valid frames | Plan `MOVED_TO_QUARANTINE` for the complete source, including a zero-byte artifact when empty; planned data generation/path/size/SHA and planned manifest path/size/SHA are all `None`. |
| closed orphan whose complete bytes validate | Plan `RETAINED`, keep its exact generation/path/bytes, and create only the missing sibling recovery manifest after the source-parent sync below. |
| closed orphan with any invalid frame, row, identity, or trailing byte | Never salvage a prefix. Plan `MOVED_TO_QUARANTINE` for the complete orphan; planned data and manifest groups are all `None`. |

The owned recovery-control carrier path is not a fifth discovery branch: its prior
`control-ownership.json` removes it from the unbound set and the original transaction
must settle all of its exact bytes.

`RecoverySourceSettledV1` enforces: `RETAINED` repeats the original source
path/size/SHA; `MOVED_TO_QUARANTINE` repeats the intent's quarantine path/size/SHA;
`REMOVED` and `LEGITIMATELY_MISSING` require all three settled fields to be `None`.
Only a validated closed orphan may be `RETAINED`; only an exact intent-bound cleanup
proof may be `LEGITIMATELY_MISSING`. The source manifest remains present in cleanup
states, but it is an evidence artifact and does not make the missing data source
`RETAINED`.

`planned_source_disposition` is mandatory and validates against the complete intent:
`RETAINED` requires `ORPHAN_CLOSED_DATA` and forbids any source mutation; planning
`REMOVED` requires an exact replacement data/manifest plan or a fully specified
publication-coexistence destination, while executing the removal is forbidden until
that exact destination has been freshly verified durable;
`MOVED_TO_QUARANTINE` requires the quarantine triple to describe the complete original
source bytes, not merely a bad suffix, and requires both planned data and manifest
groups to be all `None`; and `LEGITIMATELY_MISSING` requires
`CLEANUP_INTENT` or `CLEANUP_TOMBSTONE` plus the exact bound cleanup proof. Cleanup
states require a positive expected source size, the retained existing manifest triple,
no planned data or quarantine artifact, and the proof group; their kind must respectively
be `DURABLE_INTENT` or `FINAL_TOMBSTONE`. Every non-cleanup state requires all cleanup
proof fields to be `None`. A bad-tail
quarantine triple may accompany a `REMOVED` partial-source plan, but it never changes the
source disposition to `MOVED_TO_QUARANTINE`. `RecoverySourceSettledV1.source_disposition`
and `RecoveryCompleteV1.source_disposition` must equal the intent's frozen value. Any
inconsistent state/disposition/artifact combination is invalid before the intent can be
published and blocks replay if found on disk.

Quarantine size is non-negative only because a directory-durable partial can be empty
when the worker crashes immediately after allocation. For
`MOVED_TO_QUARANTINE`, the planned and durable quarantine artifacts are the complete
source and their size must equal `source_size_bytes`, including zero; the SHA-256 is
still mandatory and the zero-byte artifact must be published and directory-synced.
For a bad-tail quarantine accompanying a recovered prefix, the suffix must be nonempty,
so both quarantine sizes must be strictly positive and equal the manifest's
`quarantined_suffix_bytes`. No other zero-size quarantine is valid.

For a valid retained closed orphan, recovery holds its exclusive source lease, opens and
revalidates the exact inode without following links, and fsyncs the source data parent
directory before creating or accepting the sibling manifest. Only after that parent
sync may it publish the recovery manifest and `artifacts-durable.json`. This step is
mandatory even when the orphan name already existed at discovery: it covers a prior
process death after data rename but before that process's parent-directory fsync.

Replay accepts only the longest valid contiguous prefix and takes one deterministic
next action:

- intent only: freshly verify any existing planned output against the intent, otherwise
  create/sync it with `RecoveryDurabilityCoordinator`; then publish artifacts durable;
- artifacts durable: reverify every named artifact, settle the source exactly once,
  sync the affected parent, then publish source settled;
- source settled: `reconcile` returns the exact `PendingRecoveryControl` and performs no
  live admission; after service admission, `bind_control_ownership` publishes the exact
  ownership fact before any carrier file I/O;
- control ownership: on the same run the service writes only the owned dedicated carrier
  and supplies its matching durable receipt; after a crash, `reconcile` reserves those
  names, applies the four owned-manifest branches above, settles any partial carrier
  within this transaction, and publishes control durable without live admission;
- control durable: `reconcile` or an idempotent acknowledgement verifies the exact raw
  control identity/hash remains represented by its recovered-control generation,
  computes the canonical `RecoveryOutcome` hash, and publishes complete;
- complete: verify the full chain, validate each still-required artifact or exact
  Plan 07 cleanup proof under the historical rules above, report the outcome, and
  perform no mutation.

For the artifacts-to-source transition, a present source must still match the intent
before the exact `planned_source_disposition` action. If it is already absent after a
crash, replay accepts `REMOVED` only when removal was the intent, accepts
`MOVED_TO_QUARANTINE` only when the exact quarantine artifact verifies, and accepts
`LEGITIMATELY_MISSING` only when the resolver revalidates evidence exactly equal to the
proof reconstructed from the intent; any other absence, proof substitution, or byte
mismatch blocks. A retained source must remain present and exact. Thus replay never
guesses an unjournaled external disappearance.

An existing next fact is idempotently accepted only when its canonical bytes and hash
equal the recomputed fact. Existing output names are accepted only when both the intent
and a fresh size/hash verification match; any collision or mismatch blocks startup.
Replay all incomplete directories first and reserve every bound source/destination,
including every `control-ownership.json` carrier identity. A control-owned transaction
is advanced through complete by its original transaction before the unbound scan; none
of its carrier names is eligible to seed another transaction. Then scan for unbound
partial/orphan identities. One source identity belongs to only
one transaction. Startup has a global phase barrier: every transaction must advance
through `source-settled.json`, and every unbound source must be reconciled to that same
point, before the service loop accepts the first recovery control. Thus
`RecoveryBlocked` cannot follow current-process acceptance; all failures from the
subsequent control/acknowledgement phase are `CONTROL_DURABILITY_FAILED` and use its
record-exact accounting rule.
Before creating a transaction for an otherwise unbound `_control` source, the scanner
also rejects any row whose `recovery_control_event_id` names an existing recovery
transaction but lacks that transaction's valid ownership fact. That state violates the
write-before-bind ordering and blocks operator-visible startup; it is never converted
into a derived transaction.

Construct the bounded executor, worker-global `StorageIoLimiter`, and separate
unmeasured `RecoveryDurabilityCoordinator` before invoking the production backend.
Recovered prefix writes/final syncs use that recovery coordinator with
`DurabilityTrigger.RECOVERY`; journals, manifests, hashes, and quarantine work use the
same limiter/executor without touching the live ledger or live stats. Only after every
artifact is durable may recovery remove/move a partial source and sync its parent. A
fully valid closed orphan uses `RETAINED`; an invalid closed orphan moves its complete
bytes to quarantine. Prefix salvage is never applied to either closed-orphan branch.

After filesystem reconciliation, `RawWriterService.open` owns the returned pending
controls and starts the single service loop non-accepting in `STARTING`. A recovery
`_control` row has `market=None`; affected markets and exact
source context appear in its payload. When an outcome has a recovered generation, its
exact generation/path appears in `StorageControlAssociationV1`; an informational or
no-prefix outcome has no association. None of this context appears in its `_control`
path. A crash before `control-ownership.json` leaves no carrier filesystem mutation and
may re-admit the same lineage ID. A crash after ownership, including after control sync
but before `control-durable.json`, reuses the exact owned row and carrier in the original
transaction; it neither re-admits the row nor derives a lineage event. Consumers still
treat `recovery_control_event_id` as the idempotency key. Enter `ACCEPTING` only after
every complete fact is durable. Failure leaves admission closed and releases the writer
lock only after the single service loop is cancelled/joined, final owned sync work is
accounted, every descriptor is closed, and the bounded executor is shut down.

Crash-edge tests halt before and after transaction-directory fsync, each fact file
fsync, each fact rename, each fact parent-directory fsync, every artifact sync/publish,
zero-byte partial allocation parent sync, retained-orphan data-parent sync, source
settlement, control ownership, owned-carrier sync/publication, and complete publication.
Fresh-process
replay must reach exactly one valid chain/outcome, or intentionally block on injected
corruption; it may never infer a missing fact or allocate a second source transaction.

### Writer-only Gate B contract

The workload distinguishes fixed-scope files from scalable instrument files:

```yaml
fixed_scope_file_count: 5
scalable_file_count: 1750
active_file_count: 1755
```

`multiplier` is an integer at least one. It scales record/byte rates and the 1,750
instrument files; the five exchange `_control` identities remain fixed. Therefore the
exact two-times target is `5 + 2 * 1750 = 3505`, not 3510. Stream instance counts,
synthetic instruments, and the measured peak must reconcile to that formula.

Before opening storage, build immutable `WorkloadPlanV1` from the committed YAML,
duration, multiplier, and seed. Parse rates as `Decimal`, never binary float. For each
stream define `required_admitted_rate_per_second = Decimal(base_instances) *
mean_records_per_second * multiplier` and
`expected_record_count = ceil(required_admitted_rate_per_second * duration_ns / 1e9)`.
`base_instances` is `instances` for ordinary/control streams and `file_instances` for
the derivative row; schema validation requires its instrument/logical-stream product
to equal that value.
Scalable streams distribute that exact total over `base_instances * multiplier`
identities, while `_control` keeps five exchange identities, all with `market=None`,
and scales their per-identity schedules. `expected_min_record_count` in reports equals
this exact planned count; attempted, accepted, durable, sampled, and manifested counts
must equal it, not merely exceed a floor.

The plan contains a deterministic due offset for every planned event. For stream `S`,
let `N=expected_record_count`, `required_B = base_instances * burst_records_in_1s *
multiplier`, `B=min(N, required_B)`, and
`burst_second = int.from_bytes(sha256(f"{seed}:{S}".encode("utf-8")).digest()[:8],
"big", signed=False) % duration_seconds`. Qualification
requires `N >= required_B` and an integral-second duration; short functional mode may
exercise the capped `B`. Assign the first
`B` seeded event IDs to offsets
`burst_start_ns + floor(i * 1e9 / B)` for zero-based `i`, where
`burst_start_ns = burst_second * 1e9`. For zero-based remaining index `j`, let
`outside_span_ns = duration_ns - 1e9` and
`compressed_offset_ns = floor(j * outside_span_ns / (N-B))`; its due offset is that
value when it is below `burst_start_ns`, otherwise that value plus `1e9`. Skip this
formula when `N == B`. Then sort by `(due_offset_ns, planned_event_id)`. This produces
an exact reproducible burst bucket of `B`; the validator reruns the algorithm and
compares every due offset.

The seeded generator defines exactly those payloads, and `expected_min_byte_count` is
the exact sum of canonical `len(encode_json(draft.payload))` before envelope metadata.
Encoded raw and compressed byte totals are reported separately and never mixed into
that predicate. Hash the full canonical stream plan, due-offset schedule, identities,
counts, and payload-byte totals into `workload_plan_sha256` before the run.
The configured warmup is the initial prefix of `duration_ns`, not extra unmeasured
runtime; its records participate in every attempted/durable/manifest equality, while
RSS/FD slope checks may exclude that prefix as stated by their fields.

Qualification writes a canonical zstd JSONL admission trace and hashes its exact bytes.
Each row is one frozen model, and rows are ordered by `(due_monotonic_ns,
planned_event_id)`:

```python
class GateAdmissionTraceV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    planned_event_id: NonEmptyString
    stream_name: NonEmptyString
    due_monotonic_ns: NonNegativeInt
    attempt_started_monotonic_ns: NonNegativeInt
    admission_completed_monotonic_ns: NonNegativeInt
    enqueue_status: EnqueueStatus
    payload_bytes: NonNegativeInt
    accepted_identity: AcceptedRecordIdentityV1 | None


class GateSecondBucketV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    stream_name: NonEmptyString
    second_index: NonNegativeInt
    scheduled_count: NonNegativeInt
    attempted_count: NonNegativeInt
    accepted_count: NonNegativeInt
    admitted_in_actual_second_count: NonNegativeInt
    payload_bytes: NonNegativeInt
    early_count: NonNegativeInt
    late_count: NonNegativeInt
    out_of_window_count: NonNegativeInt
```

The scheduler records `run_started_monotonic_ns`,
`admission_started_monotonic_ns`, deterministic
`admission_scheduled_end_monotonic_ns = admission_started_monotonic_ns + duration_ns`,
the actual `admission_ended_monotonic_ns` captured after waiting through that boundary,
and `run_ended_monotonic_ns` after final sync, close, and manifest validation. It may
attempt a row only at or after its due time. `early_count` means attempt before due;
`late_count` means successful admission at or after the end of the row's scheduled
one-second bucket; `out_of_window_count` means any attempt/admission outside
`[admission_started, admission_scheduled_end)`. Every stream has one bucket row for
every second, including zeros. `per_second_bucket_sha256` hashes their canonical JSONL
in `(stream_name, second_index)` order.
`GateAdmissionTraceV1` also validates that an accepted enqueue status has one exact
identity and every other status has `accepted_identity=None`, and that attempt start
does not follow admission completion.

The validator streams the admission trace, validates every returned exact accepted
identity, reruns due-time/payload generation, and recomputes the trace SHA, bucket rows,
bucket SHA, monotonic ordering, declared and observed durations, per-stream admitted
rate, exact counts/bytes, burst maximum, and the UTC hour set of all decoded durable
rows. Qualification requires exactly one received-time UTC hour, zero early, late,
and out-of-window rows; each stream's burst bucket must contain exactly `B` scheduled,
attempted, and accepted rows; and
`Decimal(accepted_count) * 1e9 / duration_ns >=
required_admitted_rate_per_second`. Serialized summary counters or digests never
override recomputed trace facts.

Qualification requires all of the following, with no permissive fallback:

- workload schema, fixed/scalable cardinality, deterministic seed, and committed
  workload SHA-256 validate;
- the monotonic admission window is at least 10 minutes, multiplier is at least two,
  and the recorded run start/end ordering is valid;
- the trace/schedule/bucket digests validate, all early/late/out-of-window counts are
  zero, every required burst bucket matches, and every recomputed admitted rate is at
  least the exact two-times rate;
- attempted records/bytes equal every per-stream planned value, and
  `attempted == accepted == durable == durability_sample_count == manifest_record_count`;
- each declared exchange retains one worker identity for the whole run, every
  cumulative snapshot sequence is monotonic, and counts/histogram buckets are summed
  only from the five final `CLOSED` barrier snapshots;
- recorded and unrecorded loss, overflow, stream conformance, manifest validation,
  write failure, sync failure, and storage-health error counts are all zero;
- measured active-logical-generation peak equals the formula above, while retiring and
  open-FD peaks are separately reported; storage-health sampling meets
  count/gap/coverage rules, and max durability lag is at most 1 second;
- `functional_passed` is true, RSS/FD limits pass, and the runtime image ID is a valid
  SHA-256 exactly equal to the expected immutable image ID.

Qualification additionally requires a canonical `GateTargetV1` declaration created
on the actual Linux host before the run. It independently binds and probes both the
data and state roots, including device, filesystem, selected mount entry/options,
free-space floor, and sync/no-replace capability. The benchmark reprobes both mounted
roots and rejects any mismatch. `--target-declaration` is mandatory in
qualification mode and forbidden as evidence substitution in functional mode.
`/declared/target` below is only the standardized example target root. Target hardware
is required to publish qualification evidence, not to commit the benchmark
implementation, workload, tests, image recipe, or operating instructions. A macOS
Docker Desktop bind mount is not Linux deployment evidence.

```python
GATE_B_MINIMUM_FREE_BYTES = 100 * 1024**3
GATE_B_STATE_MINIMUM_FREE_BYTES = 100 * 1024**3


def validate_absolute_real_directory(value: Path) -> Path:
    if not value.is_absolute() or value != value.resolve(strict=True) or not value.is_dir():
        raise ValueError("gate root must be an absolute symlink-free real directory")
    return value


AbsolutePath = Annotated[Path, AfterValidator(validate_absolute_real_directory)]


class NoReplaceCapability(StrEnum):
    RENAMEAT2_NOREPLACE = "renameat2_noreplace"
    HARDLINK = "hardlink"


class GateRootProbeV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    root: AbsolutePath
    storage_device: Annotated[str, StringConstraints(pattern=r"^[0-9]+:[0-9]+$")]
    filesystem: NonEmptyString
    mount_point: AbsolutePath
    mount_options: tuple[NonEmptyString, ...]
    minimum_free_bytes: PositiveInt
    declared_available_bytes: NonNegativeInt
    no_replace_capability: NoReplaceCapability
    same_parent_publication_only: Literal[True] = True
    file_sync_supported: Literal[True] = True
    directory_sync_supported: Literal[True] = True


class GateTargetV1(FrozenStrictModel):
    schema_version: Literal[1] = 1
    target_id: NonEmptyString
    data_root: GateRootProbeV1
    state_root: GateRootProbeV1
    deployment_purpose: Literal["raw-writer-gate-b"]
    created_at_ns: NonNegativeInt
    declaration_sha256: Sha256
```

`data_root.root` and `state_root.root` are absolute, symlink-free `realpath` values and must be
different directories. For each root, `storage_device` is Linux `major:minor` and
`mount_point`/`filesystem` come from that root's independently longest matching
`/proc/self/mountinfo` entry. `mount_options` is the sorted/deduplicated union of
entries prefixed `mount:` and `super:` from that same entry. Declaration probes a
temporary same-parent data publication and a temporary same-parent journal publication
under their respective roots, including file sync, selected no-replace primitive, and
parent-directory sync. It records the selected capability; qualification repeats both
probes, removes the probe artifacts, syncs their parents again, and requires the same
result. A declaration may show the same underlying mount
for both roots, but it may not copy data-root facts into the state-root fields without
an independent lookup and probe.

`data_root.minimum_free_bytes` is exactly `GATE_B_MINIMUM_FREE_BYTES`;
`state_root.minimum_free_bytes`
is exactly `GATE_B_STATE_MINIMUM_FREE_BYTES`. `declared_available_bytes` records the
declaration-time `statvfs` value, and both declaration and qualification require each
root's current available bytes to meet its own floor; the current value is reported but
need not equal the earlier declaration value. `created_at_ns` is Unix UTC wall-clock
nanoseconds.
If both roots resolve to the same device and mount point, its one current available-byte
value must instead be at least the sum of both floors; the validator may not count the
same free bytes twice.
`declaration_sha256` hashes `encode_json` of every preceding field in model order with
that field omitted from `model_dump(mode="json")`, plus one trailing newline; JSON mode
converts all `Path` values to canonical POSIX strings. The final declaration uses
the same encoding with the hash included and is written once with no-replace
publication and a parent-directory sync.

Task 7 has separate implementation and evidence commits, with no circular hardware
gate. After unit/performance validator tests, the short functional run, and repository
offline tests pass, commit the benchmark code, workload, Dockerfile, tests, and runbook.
Then build from a clean checkout of that exact commit using a base image pinned by
digest, `requirements/collector.lock`, a wheel whose `SOURCE_DATE_EPOCH` equals the
commit timestamp, and no untracked inputs. Two clean builds from the same
source/lock/epoch must produce byte-identical wheel SHA-256 values and the same
immutable image ID. If a build fix is needed, commit it and repeat against the new exact
source commit. Target unavailability leaves external qualification pending; it does
not reject or delay these implementation commits or the reproducible image build.

The later target report contains `implementation_source_commit`,
`collector_wheel_sha256`, `requirements_lock_sha256`, `workload_sha256`,
`dockerfile_sha256`, `source_date_epoch`, `runtime_image_id`, and
`expected_image_id`. The validator requires a clean checkout of that exact source
commit to reproduce the wheel hash and image ID before accepting evidence. Redacted
report/declaration files are committed separately as an evidence commit whose parent
contains (or descends from) the bound implementation commit. A report generated from
the evidence commit itself is invalid because adding evidence must not change the
source identity being qualified.

### Cross-plan ownership

Plan 03 owns network, quotas, scheduler, and selection. It may publish a reserved
`NativeEventDraft` only through an injected control-emission port; it never imports
`RawWriterService`, `RawIngress`, or storage queues. Plan 04 owns adapter production
of `NativeEventDraft`/`SourceContext`/`RestMetadata`, `EventSink`, interpretation of
`EnqueueResult`, generation invalidation, producer stop, worker pause, reload, and
shutdown orchestration. It passes the supervisor's committed non-negative config epoch
as `config_generation` and increments it on reload. Plan 06 reads validated
manifests/data under shared leases.
Plan 07 reads under shared leases, acquires exclusive leases only for cleanup, retains
source manifests/leases, and supplies `SourceDispositionResolver`. Plan 08 owns
Prometheus aggregation, health endpoints, disk-pressure policy, Compose, the full-
collector gate, and soak testing. Plan 02 owns only storage snapshots/callbacks and
writer-only Gate B.

---

### Task 1: Raw Layout, Serialization, and Accepted Record

**Files:**
- Create: `src/crypto_collector/storage/__init__.py`
- Create: `src/crypto_collector/storage/models.py`
- Create: `src/crypto_collector/storage/layout.py`
- Create: `src/crypto_collector/storage/serialize.py`
- Test: `tests/unit/storage/test_layout.py`
- Test: `tests/unit/storage/test_serialize.py`

- [ ] **Step 1: Write failing path and serialization tests**

```python
def test_received_time_selects_the_utc_hour_partition(tmp_path) -> None:
    envelope = make_envelope(
        exchange="kraken",
        market="spot",
        instrument_key="BTC/USDT",
        wire_symbol="BTC/USDT",
        logical_stream="trade",
        received_at_ns=1_785_473_918_123_456_789,
        event_time_ns=0,
    )
    path = raw_partial_path(tmp_path, envelope, part_start_ns=1_785_470_400_000_000_000, sequence=0)
    assert path.relative_to(tmp_path).as_posix().startswith(
        "raw/kraken/spot/BTC%2FUSDT/trade/2026/07/31/"
    )
    assert path.name.endswith(".jsonl.zst.partial")


def test_raw_json_preserves_payload_shape_and_uses_one_newline() -> None:
    envelope = make_envelope(payload={"asks": [["1.00", "2.50"]], "flag": None})
    encoded = encode_envelope(envelope)
    assert encoded.endswith(b"\n")
    assert encoded.count(b"\n") == 1
    assert decode_json(encoded)["payload"] == {"asks": [["1.00", "2.50"]], "flag": None}


def test_exchange_control_and_market_scope_use_distinct_reserved_layouts(tmp_path) -> None:
    control_envelope = exchange_control_envelope("okx")
    assert control_envelope.market is None
    exchange_control = raw_partial_path(tmp_path, control_envelope,
                                        part_start_ns=hour_ns(), sequence=0)
    market_status = raw_partial_path(tmp_path, market_envelope("okx", "spot", "status"),
                                     part_start_ns=hour_ns(), sequence=0)
    assert exchange_control.relative_to(tmp_path).as_posix().startswith("raw/okx/_control/")
    assert market_status.relative_to(tmp_path).as_posix().startswith(
        "raw/okx/spot/_market/status/")


def test_control_scope_rejects_market_context() -> None:
    invalid = make_envelope(logical_stream="_control", market=Market.SPOT,
                            instrument_key=None, wire_symbol=None)
    with pytest.raises(StorageScopeError):
        raw_partial_path(Path("/data"), invalid, part_start_ns=hour_ns(), sequence=0)
```

- [ ] **Step 2: Run and verify missing storage modules**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_layout.py tests/unit/storage/test_serialize.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement the storage-facing contracts**

```python
# src/crypto_collector/storage/models.py
from dataclasses import dataclass

from crypto_collector.domain.envelope import RawEnvelope


@dataclass(frozen=True, slots=True)
class AcceptedRecord:
    envelope: RawEnvelope
    encoded_jsonl: bytes

    @property
    def accepted_monotonic_ns(self) -> int:
        return self.envelope.monotonic_ns
```

`layout.py` must use `received_at_ns` converted with UTC, encode the stable instrument key with `encode_instrument_key`, reserve `_market` for symbol-less market streams and `_control` only for exchange controls with `market=None`, and reject path traversal after resolution. Affected markets remain payload/association data and never add a segment below `_control`. `serialize.py` calls the foundation Decimal-aware `encode_json(envelope.model_dump(mode="python")) + b"\n"`; it must preserve `Decimal` as a JSON number and reject binary float or non-JSON values.

- [ ] **Step 4: Run storage layout tests**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_layout.py tests/unit/storage/test_serialize.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/storage tests/unit/storage
git commit -m "feat: define raw storage layout"
```

### Task 2: Concatenated Independent zstd Frames

**Files:**
- Modify: `src/crypto_collector/config/models.py`
- Create: `src/crypto_collector/storage/stream_file.py`
- Test: `tests/unit/config/test_models.py`
- Test: `tests/unit/storage/test_stream_file.py`

- [ ] **Step 1: Write failing frame and byte-threshold tests**

```python
def test_each_flush_is_an_independent_decompressible_frame(tmp_path) -> None:
    stream = StreamFile.allocate(tmp_path / "part.jsonl.zst.partial", zstd_level=3,
                                 max_plain_frame_bytes=1024)
    stream.append(b'{"writer_sequence":1}\n', accepted_monotonic_ns=10)
    first = stream.write_frame(stream.take_pending())
    stream.append(b'{"writer_sequence":2}\n', accepted_monotonic_ns=20)
    second = stream.write_frame(stream.take_pending())
    stream.close_fd()

    assert first.record_count == second.record_count == 1
    with open(tmp_path / "part.jsonl.zst.partial", "rb") as source:
        assert zstandard.ZstdDecompressor().stream_reader(source).read() == (
            b'{"writer_sequence":1}\n{"writer_sequence":2}\n'
        )


def test_compressed_size_drives_rotation_threshold(tmp_path) -> None:
    stream = StreamFile.allocate(tmp_path / "part.jsonl.zst.partial", zstd_level=3,
                                 max_plain_frame_bytes=1024)
    stream.append(b'{"payload":"aaaaaaaa"}\n', accepted_monotonic_ns=1)
    frame = stream.write_frame(stream.take_pending())
    assert stream.compressed_size == frame.compressed_bytes


def test_allocation_refuses_stale_partial(tmp_path) -> None:
    path = tmp_path / "part.jsonl.zst.partial"
    path.write_bytes(b"stale")
    with pytest.raises(FileExistsError):
        StreamFile.allocate(path, zstd_level=3, max_plain_frame_bytes=1024)


def test_first_partial_entry_is_directory_durable_before_allocate_returns(tmp_path) -> None:
    trace = allocate_stream_with_tracing(tmp_path / "part.jsonl.zst.partial")
    assert trace[:3] == ("open_exclusive", "fsync_partial_parent", "return_stream")


def test_write_all_retries_eintr_and_short_write(monkeypatch, tmp_path) -> None:
    writes = scripted_writes(InterruptedError(), 3, 10_000)
    monkeypatch.setattr(os, "write", writes)
    stream = StreamFile.allocate(tmp_path / "part.jsonl.zst.partial", zstd_level=3,
                                 max_plain_frame_bytes=1024)
    stream.append(b'{"writer_sequence":1}\n', accepted_monotonic_ns=10)
    stream.write_frame(stream.take_pending())
    assert writes.total_written == writes.expected_bytes


def test_append_refuses_to_grow_active_buffer_past_plain_frame_limit(tmp_path) -> None:
    stream = StreamFile.allocate(tmp_path / "part.jsonl.zst.partial", zstd_level=3,
                                 max_plain_frame_bytes=32)
    stream.append(b'{"a":"1234567890"}\n', accepted_monotonic_ns=10)
    with pytest.raises(FrameSealRequired):
        stream.append(b'{"b":"1234567890"}\n', accepted_monotonic_ns=20)
    pending = stream.take_pending()
    assert tuple(row.accepted_monotonic_ns for row in pending.rows) == (10,)
    assert pending.plain_bytes <= 32


def test_writer_config_owns_frame_codec_limits() -> None:
    config = WriterConfig.model_validate(
        {"zstd_level": 7, "max_plain_frame_bytes": "2MiB"}
    )
    assert config.zstd_level == 7
    assert config.max_plain_frame_bytes == 2 * 1024**2


@pytest.mark.parametrize("level", [0, 23])
def test_writer_config_rejects_unsupported_zstd_level(level) -> None:
    with pytest.raises(ValidationError):
        WriterConfig.model_validate({"zstd_level": level})


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"shard_max_records": 1, "control_reserve_records": 2}, "records"),
        ({"shard_max_bytes": "1KiB", "control_reserve_bytes": "2KiB"}, "bytes"),
        ({"shard_max_bytes": "2KiB", "worker_max_bytes": "1KiB"}, "worker"),
        ({"worker_max_bytes": "2KiB", "control_reserve_bytes": "2KiB"}, "worker"),
    ],
)
def test_control_reserve_must_fit_control_shard_ceiling(override, message) -> None:
    invalid = deepcopy(BASE["ingress"])
    invalid.update(override)
    with pytest.raises(ValidationError, match=message):
        IngressConfig.model_validate(invalid)
```

- [ ] **Step 2: Run and confirm `StreamFile` is missing**

Run: `.venv/bin/python -m pytest tests/unit/config/test_models.py tests/unit/storage/test_stream_file.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement one compressor invocation per frame**

```python
@dataclass(frozen=True, slots=True)
class PendingRows:
    rows: tuple[BufferedRow, ...]
    plain_bytes: int


@dataclass(frozen=True, slots=True)
class SealedFileWork:
    generation_id: str
    stream_file: "StreamFile"
    pending: PendingRows | None
    force_sync: bool


@dataclass(frozen=True, slots=True)
class WrittenFrame:
    first_monotonic_ns: int
    last_monotonic_ns: int
    record_monotonic_ns: tuple[int, ...]
    record_count: int
    compressed_bytes: int


def take_pending(self) -> PendingRows | None:
    if not self._buffer:
        return None
    pending = PendingRows(tuple(self._buffer), sum(len(row.data) for row in self._buffer))
    self._buffer.clear()
    return pending


def seal_for_sync(
    self,
    *,
    direct_rows: PendingRows | None = None,
    force_sync: bool = False,
) -> SealedFileWork | None:
    if direct_rows is not None:
        if self._buffer:
            raise ValueError("direct rows require an empty active buffer")
        if (len(direct_rows.rows) != 1 or
                direct_rows.plain_bytes <= self.max_plain_frame_bytes):
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
    plain = b"".join(row.data for row in pending.rows)
    frame = self._compressor.compress(plain)
    write_all(self._fd, frame)
    result = WrittenFrame(
        first_monotonic_ns=pending.rows[0].accepted_monotonic_ns,
        last_monotonic_ns=pending.rows[-1].accepted_monotonic_ns,
        record_monotonic_ns=tuple(row.accepted_monotonic_ns for row in pending.rows),
        record_count=len(pending.rows),
        compressed_bytes=len(frame),
    )
    self.compressed_size += len(frame)
    return result


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            written = os.write(fd, view)
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("write returned no progress")
        view = view[written:]
```

Extend `WriterConfig` with the two amendment fields before constructing stream files.
Move all ingress-local byte invariants into one `IngressConfig` after-validator: reject
`worker_max_bytes < shard_max_bytes`, reject
`control_reserve_bytes >= worker_max_bytes`, reject a control record reserve larger
than `shard_max_records`, and reject a control byte reserve larger than
`shard_max_bytes`. Equality with the shard ceiling is valid because `_control` may
consume the complete shard ceiling; equality with the worker ceiling is invalid
because normal capacity must remain nonzero. These invariants must hold even when
`IngressConfig` is constructed directly for a service or test, not only when nested in
`CollectorConfig`; remove the duplicated checks from the outer model.
Allocate with `os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_WRONLY | os.O_CLOEXEC`, mode `0o640`, after startup recovery and atomic sequence allocation under the exchange writer lock. Fsync the new partial's parent directory before allocation returns or any accepted row can target it. Use a reusable `ZstdCompressor(level=writer_config.zstd_level, write_checksum=True, write_content_size=True)`. The service loop seals before accepting another buffered row that would exceed `writer_config.max_plain_frame_bytes`; an oversized single row forms one frame and emits a size warning. Compression, write, synchronization, and the initial directory sync are blocking methods invoked only by the coordinator's bounded executor path.

`StreamFile.append` raises `FrameSealRequired` without mutating its buffer when the
new row would cross the limit. The service loop seals the existing rows and retries
that record. When one encoded row itself exceeds the limit, the loop never appends it
to the active buffer: it constructs a one-row `PendingRows`, emits the warning, and
passes `stream_file.seal_for_sync(direct_rows=rows)` to the coordinator when that
generation is free. If an earlier seal for the generation is still in flight, the
loop retains the direct rows in its bounded generation queue until the completion
notification. Normal buffers, oversized rows, and clean final syncs therefore all
reach the coordinator as the same generation-bound `SealedFileWork` type.

- [ ] **Step 4: Run the frame tests**

Run: `.venv/bin/python -m pytest tests/unit/config/test_models.py tests/unit/storage/test_stream_file.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/config/models.py src/crypto_collector/storage/stream_file.py tests/unit/config/test_models.py tests/unit/storage/test_stream_file.py
git commit -m "feat: write independent raw zstd frames"
```

### Task 3: Bounded Durability Coordinator

**Files:**
- Create: `src/crypto_collector/storage/durability.py`
- Create: `src/crypto_collector/storage/stats.py`
- Test: `tests/unit/storage/test_durability.py`

- [ ] **Step 1: Write fake-clock tests for sync completion and critical pause**

```python
@pytest.mark.asyncio
async def test_lag_is_measured_at_sync_completion() -> None:
    clock = FakeClock(monotonic_ns=100)
    sync = FakeSync(clock=clock, advance_ns=400)
    io_limiter = StorageIoLimiter(max_concurrency=2)
    coordinator = DurabilityCoordinator(
        clock=clock,
        sync_backend=sync,
        io_limiter=io_limiter,
        storage_executor=BoundedFakeExecutor(max_workers=2),
        durability_slo_ns=1_000,
        durability_critical_ns=5_000,
        completion_sink=discard_file_sync_completion,
    )
    work = fake_work(fd=7, records=(100, 200))
    result = await coordinator.sync_batch(
        [work], trigger=DurabilityTrigger.PERIODIC
    )
    assert result.trigger is DurabilityTrigger.PERIODIC
    assert result.files[0].lag_p50_ns == 100_000
    assert result.files[0].lag_p95_ns == 100_000
    assert result.files[0].lag_p99_ns == 100_000
    assert result.files[0].lag_max_ns == 400


def test_critical_age_classification_includes_accepted_but_unclaimed_rows() -> None:
    clock = FakeClock(monotonic_ns=100)
    ledger = DurabilityLedger(clock=clock)
    ledger.register_accepted(record_id="queued", accepted_monotonic_ns=100)
    clock.advance_ns(5_001)
    error = ledger.classify_critical_age(durability_critical_ns=5_000)
    assert error.reason == "oldest_unpersisted_age"
    assert error.record_stage is DurabilityStage.QUEUED


def test_rolling_ring_uses_exactly_sixty_monotonic_second_slots() -> None:
    ring = RollingDurabilityHistogram()
    ring.add(lag_ns=900_000_000, sync_completed_monotonic_ns=10_999_999_999)
    included = ring.snapshot(now_monotonic_ns=69_999_999_999)
    expired = ring.snapshot(now_monotonic_ns=70_000_000_000)
    assert included.sample_count == 1
    assert included.lag_max_ns == 900_000_000
    assert expired.sample_count == 0
    assert expired.lag_p99_ns is expired.lag_max_ns is None
    ring.add(lag_ns=1, sync_completed_monotonic_ns=130_000_000_000)
    assert ring.allocated_slot_count == 60
    assert ring.snapshot(now_monotonic_ns=130_000_000_000).sample_count == 1


def test_cumulative_quantile_may_decrease_without_counter_reset() -> None:
    histogram = CumulativeDurabilityHistogram()
    histogram.add(1_500_000_000)
    before = histogram.snapshot()
    for _ in range(100):
        histogram.add(100_000)
    after = histogram.snapshot()
    assert after.sample_count > before.sample_count
    assert all(b >= a for a, b in zip(before.bucket_counts, after.bucket_counts, strict=True))
    assert after.lag_p50_ns < before.lag_p50_ns


@pytest.mark.asyncio
async def test_sync_error_is_independently_critical() -> None:
    coordinator = make_coordinator(sync_backend=FailingSync(OSError(errno.EIO, "io")))
    with pytest.raises(WriterCriticalError, match="sync"):
        await coordinator.sync_batch(
            [fake_work(fd=7, records=(100,))],
            trigger=DurabilityTrigger.PERIODIC,
        )
```

```python
@pytest.mark.asyncio
async def test_sync_concurrency_is_bounded() -> None:
    sync = BlockingSync()
    coordinator = make_coordinator(max_sync_concurrency=2, sync_backend=sync)
    task = asyncio.create_task(coordinator.sync_batch(
        [fake_work(fd=n) for n in range(10)],
        trigger=DurabilityTrigger.PERIODIC,
    ))
    await sync.wait_until_started(2)
    assert sync.max_active == 2
    sync.release_all()
    await task


@pytest.mark.asyncio
async def test_sync_concurrency_limit_is_global_across_overlapping_batches() -> None:
    sync = BlockingSync()
    coordinator = make_coordinator(max_sync_concurrency=2, sync_backend=sync)
    first = asyncio.create_task(coordinator.sync_batch(
        [fake_work(1), fake_work(2)], trigger=DurabilityTrigger.PERIODIC
    ))
    await sync.wait_until_started(2)
    second = asyncio.create_task(coordinator.sync_batch(
        [fake_work(3), fake_work(4)], trigger=DurabilityTrigger.SIZE
    ))
    await asyncio.sleep(0)
    assert sync.max_active == sync.active == 2
    sync.release_all()
    await asyncio.gather(first, second)


@pytest.mark.asyncio
async def test_sync_limit_is_shared_by_live_and_recovery_coordinators() -> None:
    sync = BlockingUntilReleasedSync()
    executor = BoundedFakeExecutor(max_workers=4)
    io_limiter = StorageIoLimiter(max_concurrency=2)
    live = make_coordinator(
        io_limiter=io_limiter, storage_executor=executor, sync_backend=sync
    )
    recovery = make_recovery_coordinator(
        accounting_mode=RecoveryAccountingMode.UNMEASURED,
        io_limiter=io_limiter,
        storage_executor=executor,
        sync_backend=sync,
    )
    live_task = asyncio.create_task(live.sync_batch(
        [fake_work(1), fake_work(2)], trigger=DurabilityTrigger.PERIODIC
    ))
    recovery_task = asyncio.create_task(recovery.sync_batch(
        [fake_recovery_work(3), fake_recovery_work(4)],
        trigger=DurabilityTrigger.RECOVERY,
    ))
    await sync.wait_until_attempted(4)
    assert sync.max_active == sync.active == 2
    sync.release_all_and_stop_blocking()
    await asyncio.gather(live_task, recovery_task)


@pytest.mark.asyncio
async def test_overlapping_batches_reject_same_file_generation() -> None:
    sync = BlockingSync()
    coordinator = make_coordinator(sync_backend=sync)
    work = fake_work(1)
    first = asyncio.create_task(coordinator.sync_batch(
        [work], trigger=DurabilityTrigger.PERIODIC
    ))
    await sync.wait_until_started(1)
    with pytest.raises(DuplicateFileGeneration):
        await coordinator.sync_batch([work], trigger=DurabilityTrigger.BARRIER)
    sync.release_all()
    await first


@pytest.mark.asyncio
async def test_fast_file_completion_is_emitted_before_unrelated_file_finishes() -> None:
    backend = OneFastOneBlockingSync()
    completions: asyncio.Queue[FileSyncCompletion] = asyncio.Queue()
    coordinator = make_coordinator(max_sync_concurrency=2, sync_backend=backend,
                                   completion_sink=completions.put_nowait)
    task = asyncio.create_task(coordinator.sync_batch(
        [fake_work(1), fake_work(2)], trigger=DurabilityTrigger.PERIODIC
    ))
    await backend.fast_file_completed()
    completion = completions.get_nowait()
    assert isinstance(completion, FileSyncCompleted)
    assert completion.result.generation_id == fake_work(1).generation_id
    assert not task.done()
    backend.release_blocked()
    await task


@pytest.mark.asyncio
async def test_one_sync_failure_waits_for_other_inflight_jobs() -> None:
    backend = OneFailureOneBlockingSync()
    coordinator = make_coordinator(max_sync_concurrency=2, sync_backend=backend)
    task = asyncio.create_task(coordinator.sync_batch(
        [fake_work(1), fake_work(2)], trigger=DurabilityTrigger.PERIODIC
    ))
    await backend.failure_observed()
    assert not task.done()
    backend.release_success()
    with pytest.raises(WriterCriticalError):
        await task


@pytest.mark.asyncio
async def test_cancellation_waits_for_inflight_sync_before_propagating() -> None:
    backend = BlockingSync()
    completions: list[FileSyncCompletion] = []
    stream = FakeDirtyFile(fd=7, records=(100,))
    work = sealed_work(stream)
    coordinator = make_coordinator(sync_backend=backend,
                                   completion_sink=completions.append)
    task = asyncio.create_task(coordinator.sync_batch(
        [work], trigger=DurabilityTrigger.PERIODIC
    ))
    await backend.wait_until_started(1)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    assert stream.close_called is False
    backend.release_all()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert backend.active == 0
    assert len(completions) == 1
    assert isinstance(completions[0], FileSyncCompleted)


@pytest.mark.asyncio
async def test_sync_error_wins_over_concurrent_cancellation_after_full_accounting() -> None:
    backend = CancelThenFailSync(OSError(errno.EIO, "io"))
    completions: list[FileSyncCompletion] = []
    coordinator = make_coordinator(sync_backend=backend,
                                   completion_sink=completions.append)
    task = asyncio.create_task(coordinator.sync_batch(
        [fake_work(1), fake_work(2)], trigger=DurabilityTrigger.PERIODIC
    ))
    await backend.wait_until_started(2)
    task.cancel("first cancellation")
    await asyncio.sleep(0)
    task.cancel("second cancellation")
    backend.release_all()
    with pytest.raises(WriterCriticalError, match="sync") as captured:
        await task
    assert isinstance(captured.value.__cause__, asyncio.CancelledError)
    assert captured.value.__cause__.args == ("first cancellation",)
    assert sum(isinstance(item, FileSyncCompleted) for item in completions) == 1
    assert sum(isinstance(item, FileSyncFailed) for item in completions) == 1


def test_portable_sync_prefers_fdatasync_and_falls_back_to_fsync(monkeypatch) -> None:
    called = []
    monkeypatch.delattr(os, "fdatasync", raising=False)
    monkeypatch.setattr(os, "fsync", lambda fd: called.append(fd))
    PosixSyncBackend().sync(7)
    assert called == [7]
```

- [ ] **Step 2: Run and verify the coordinator is missing**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_durability.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement group flush and bounded `fdatasync`**

```python
class SyncBackend(Protocol):
    def sync(self, fd: int) -> None: ...


class PosixSyncBackend:
    def sync(self, fd: int) -> None:
        sync = getattr(os, "fdatasync", os.fsync)
        sync(fd)


class StorageIoLimiter:
    def __init__(self, max_concurrency: int) -> None:
        self._slots = asyncio.Semaphore(max_concurrency)

    def slot(self) -> AbstractAsyncContextManager[None]: ...


class DurabilityCoordinator:
    def __init__(
        self,
        *,
        clock: Clock,
        sync_backend: SyncBackend,
        io_limiter: StorageIoLimiter,
        storage_executor: Executor,
        durability_slo_ns: int,
        durability_critical_ns: int,
        completion_sink: FileSyncCompletionSink,
    ) -> None:
        self._io_limiter = io_limiter
        self._storage_executor = storage_executor
        self._completion_sink = completion_sink
        self._inflight_generations: set[str] = set()
        self._owned_batches: set[asyncio.Task[DurabilityBatch]] = set()

    async def _persist_one(self, work: SealedFileWork) -> FileDurabilityResult:
        try:
            async with self._io_limiter.slot():
                result = await asyncio.get_running_loop().run_in_executor(
                    self._storage_executor, self._persist_blocking, work
                )
        except Exception as error:
            self._completion_sink(FileSyncFailed(work.generation_id, error))
            raise
        else:
            self._completion_sink(FileSyncCompleted(result))
            return result
        finally:
            self._inflight_generations.remove(work.generation_id)

    async def sync_batch(
        self,
        work_items: Sequence[SealedFileWork],
        *,
        trigger: DurabilityTrigger,
    ) -> DurabilityBatch:
        # _register_work is atomic: it rejects an empty batch, duplicate generation
        # in this batch, or a generation already owned by an overlapping batch.
        owned = self._register_work(work_items)
        internal = asyncio.create_task(
            self._run_owned_batch(owned, trigger=trigger)
        )
        self._owned_batches.add(internal)
        internal.add_done_callback(self._owned_batches.discard)

        cancellation: asyncio.CancelledError | None = None
        while not internal.done():
            try:
                await asyncio.shield(internal)
            except asyncio.CancelledError as error:
                cancellation = cancellation or error
            except WriterCriticalError:
                # The owned task is now terminal; resolve it exactly once below so
                # an earlier caller cancellation can be installed as the cause.
                pass

        # _run_owned_batch uses gather(return_exceptions=True), collects every outcome,
        # and raises WriterCriticalError only after all claimed work has completed.
        try:
            batch = internal.result()
        except WriterCriticalError as critical:
            if cancellation is not None:
                raise critical from cancellation
            raise
        if cancellation is not None:
            raise cancellation
        return batch
```

The service ledger, not a coordinator-local pending list, remains the complete
oldest-unpersisted index. The coordinator owns blocking write/sync execution and
generation exclusion only. It receives no ledger, stats accumulator, histogram, or SLO
callback and emits exactly one immutable `FileSyncCompleted` or `FileSyncFailed`
notification for each file before the enclosing batch can finish. The single service
loop is the sole consumer and sole owner of all state mutation: a claimed entry stays
`IN_FLIGHT` until that loop consumes its individual notification, then becomes
`DURABLE` or `UNCERTAIN`; in the same turn the loop updates the per-part aggregate,
process-lifetime public histogram, private 60-second ring, failure counters, resident
budget, command watermarks, and any SLO transition. It drains completion notifications
before waiting for unrelated files or processing more admission work.
For each submitted generation it retains the exact ordered accepted-identity/timestamp
claim until that notification; it verifies `record_count`, derives all lag bucket deltas
from `sync_completed_monotonic_ns`, and clears the claim only after applying them.
`FileSyncCompletionSink` is a required, synchronous, nonblocking, non-raising
event-loop callback. Production passes the service-loop mailbox's `put_nowait`; direct
coordinator tests that do not inspect notifications explicitly pass
`discard_file_sync_completion`. The `try/except/else` emission structure is normative:
one claimed generation invokes the sink exactly once, success cannot be caught and
re-emitted as failure if the sink contract is violated, and batch settlement is posted
only after all per-file emissions. The service loop rejects a duplicate or unknown
generation completion as terminal `SYNC_FAILED`; it never applies one twice.

The single service loop drives watchdog checks using the injected `AsyncSleeper`; crossing
`durability_critical` enters terminal critical state and invokes `on_critical` once,
while already-running executor work remains owned. Tests run the actual service loop
and wake the fake sleeper rather than calling the checker directly. A sync error is
independently critical even when record age is below the threshold.

The constructor takes one consistently named `sync_backend: SyncBackend`, defaulting
to `PosixSyncBackend`, plus the worker's shared `StorageIoLimiter` and one bounded
executor. It never constructs a semaphore. Test helper `make_coordinator` constructs a
standalone limiter and `discard_file_sync_completion` only when they are not supplied;
the cross-coordinator test supplies the same limiter explicitly. The same
coordinator method is mandatory for periodic flush, time/size/config rotation,
recovery, and shutdown. `_run_owned_batch` gathers with `return_exceptions=True`, but
every per-file notification is emitted as soon as that file settles, and the service
loop applies it promptly rather than waiting for the group result. The returned
`DurabilityBatch` is a lifecycle/barrier result only; consuming it must not apply the
same transition again. After all files settle, the service finishes critical
classification before propagating anything. A `WriterCriticalError` wins over concurrent cancellation
(chained from it); only an otherwise successful fully accounted batch re-raises the
original `CancelledError`.

- [ ] **Step 4: Run durability tests**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_durability.py -q`

Expected: PASS without wall-clock sleeps.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/storage/durability.py src/crypto_collector/storage/stats.py tests/unit/storage/test_durability.py
git commit -m "feat: coordinate bounded durable writes"
```

### Task 4: Bounded Ingress and Exclusive Writer Ownership

**Files:**
- Modify: `src/crypto_collector/storage/models.py`
- Create: `src/crypto_collector/storage/ingress.py`
- Create: `src/crypto_collector/storage/writer_lock.py`
- Test: `tests/unit/storage/test_ingress.py`
- Test: `tests/unit/storage/test_writer_lock.py`

- [ ] **Step 1: Write failing acceptance, overflow, and lock tests**

```python
def test_successful_nonblocking_insert_defines_acceptance(fake_clock) -> None:
    ingress = make_ingress(shard_max_records=2, shard_max_bytes=100_000,
                           worker_max_bytes=200_000, high_water_ratio=0.8,
                           control_reserve_records=1, control_reserve_bytes=50_000,
                           worker_instance_id="worker-1", config_sha256="a" * 64,
                           clock=fake_clock)
    result = ingress.try_accept(make_native_event_draft(payload={"value": 1}),
                                source=websocket_source(), shard="book-0")
    assert result.status is EnqueueStatus.ACCEPTED
    assert result.record.envelope.monotonic_ns == result.record.accepted_monotonic_ns
    assert result.record.envelope.worker_instance_id == "worker-1"
    assert result.record.envelope.config_sha256 == "a" * 64


def test_record_or_byte_overflow_never_counts_as_accepted(fake_clock) -> None:
    ingress = make_ingress(shard_max_records=1, shard_max_bytes=100_000, clock=fake_clock)
    assert ingress.try_accept(small_draft(), source=websocket_source(), shard="trade-0").accepted
    overflow = ingress.try_accept(small_draft(), source=websocket_source(), shard="trade-0")
    assert overflow.status is EnqueueStatus.OVERFLOW
    assert ingress.accepted_count == 1


def test_writer_sequence_is_per_stream_and_overflow_does_not_consume_it(fake_clock) -> None:
    ingress = make_ingress(shard_max_records=1, clock=fake_clock)
    first = ingress.try_accept(draft(instrument_key="BTC-USDT", stream="trade"), source=websocket_source(), shard="trade-0")
    rejected = ingress.try_accept(draft(instrument_key="BTC-USDT", stream="trade"), source=websocket_source(), shard="trade-0")
    ingress.drain_one("trade-0")
    second = ingress.try_accept(draft(instrument_key="BTC-USDT", stream="trade"), source=websocket_source(), shard="trade-0")
    other = ingress.try_accept(draft(instrument_key="BTC-USDT", stream="bbo"), source=websocket_source(), shard="bbo-0")
    assert (first.record.envelope.writer_sequence, second.record.envelope.writer_sequence) == (0, 1)
    assert rejected.status is EnqueueStatus.OVERFLOW
    assert other.record.envelope.writer_sequence == 0


def test_control_reserve_is_not_consumed_by_market_rows() -> None:
    ingress = make_ingress(worker_max_bytes=1_000_000, control_reserve_bytes=200_000)
    fill_market_bytes(ingress, 800_000)
    assert ingress.try_accept(validated_control_draft(size=1_000), source=SourceContext.internal(),
                              shard="_control").accepted
    assert ingress.try_accept(market_draft(size=1_000), source=websocket_source(),
                              shard="trade-0").status is EnqueueStatus.OVERFLOW


@pytest.mark.parametrize(
    ("draft", "shard"),
    [(validated_control_draft(), "trade-0"), (market_draft(), "_control")],
)
def test_capacity_class_and_shard_mismatch_consumes_nothing(ingress, draft, shard) -> None:
    before = ingress.snapshot_for_test()
    with pytest.raises(AdmissionContractError):
        ingress.try_accept(draft, source=source_for(draft), shard=shard)
    assert ingress.snapshot_for_test() == before


@pytest.mark.parametrize(
    ("draft", "source"),
    [
        (websocket_draft(), SourceContext(
            connection_id=None, connection_generation=None, egress_id="direct"
        )),
        (rest_draft(stream="book_live_bootstrap"), SourceContext(
            connection_id=None, connection_generation=None, egress_id="direct"
        )),
        (rest_draft(stream="ticker"), SourceContext(
            connection_id="ws-1", connection_generation=1, egress_id="direct"
        )),
        (internal_control_draft(), SourceContext(
            connection_id=None, connection_generation=None, egress_id="direct"
        )),
    ],
)
def test_draft_source_scope_mismatch_is_rejected_without_acceptance(draft, source) -> None:
    ingress = make_ingress()
    with pytest.raises(SourceContextError):
        ingress.try_accept(draft, source=source, shard="test")
    assert ingress.accepted_count == 0


def test_second_writer_cannot_hold_same_exchange_root(tmp_path) -> None:
    first = ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    with pytest.raises(WriterAlreadyRunning):
        ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    first.release()


def test_writer_lock_preserves_noncontention_oserror(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(fcntl, "flock",
                        lambda *_args: (_ for _ in ()).throw(OSError(errno.EIO, "io")))
    with pytest.raises(OSError) as caught:
        ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
    assert caught.value.errno == errno.EIO


def test_writer_lock_rejects_symlink(tmp_path) -> None:
    exchange_root = tmp_path / "raw" / Exchange.OKX.value
    exchange_root.mkdir(parents=True)
    (exchange_root / "target").write_text("", encoding="utf-8")
    (exchange_root / ".writer.lock").symlink_to("target")
    with pytest.raises(OSError):
        ExchangeWriterLock.acquire(tmp_path, exchange=Exchange.OKX)
```

- [ ] **Step 2: Run and verify ingress/lock modules are absent**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_ingress.py tests/unit/storage/test_writer_lock.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement nonblocking admission and `flock` ownership**

`RawIngress` is constructed from immutable `IngressConfig`, `worker_instance_id`,
`config_sha256`, `config_generation`, and the service-owned resident budget.
`RawIngress.try_accept(draft: NativeEventDraft, *, source:
SourceContext, shard: str)` owns final-envelope construction. It validates draft/source
compatibility, peeks the next `writer_sequence` for `(worker_instance_id, market,
instrument_key-or-reserved-scope, logical_stream)`, stamps both wall-clock
`received_at_ns` and authoritative `monotonic_ns = clock.monotonic_ns()`, serializes
once into `AcceptedRecord.encoded_jsonl`, checks per-shard record/byte and worker byte
limits against the actual resident charge across queued/buffered/in-flight stages, and
performs one `put_nowait`. Capacity class comes only from validated draft scope and must
match the shard as amended above. Commit the sequence/acceptance ordinal and construct
the exact `AcceptedRecordIdentityV1` only on `ACCEPTED` or
`ACCEPTED_HIGH_WATER`; overflow cannot consume identity or count as accepted.
`RawWriterService.try_accept` immediately registers the successful result in its
durability ledger before returning. Runtime treats
market overflow as a generation-invalidating gap and control overflow as a fatal
incomplete-part condition.

```python
@dataclass(slots=True)
class ExchangeWriterLock:
    exchange_root: Path
    fd: int
    _released: bool = False

    @classmethod
    def acquire(cls, data_root: Path, *, exchange: Exchange) -> "ExchangeWriterLock":
        exchange_root = create_exchange_root_no_symlinks(data_root, exchange)
        root_fd = os.open(
            exchange_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            fd = os.open(
                ".writer.lock",
                os.O_CREAT | os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o640,
                dir_fd=root_fd,
            )
        finally:
            os.close(root_fd)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            raise OSError(errno.EINVAL, "writer lock is not a regular file")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(fd)
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise WriterAlreadyRunning(exchange_root) from error
            raise
        return cls(exchange_root=exchange_root, fd=fd)

    def release(self) -> None:
        if not self._released:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            finally:
                os.close(self.fd)
                self._released = True

    def __enter__(self) -> "ExchangeWriterLock":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()
```

`EnqueueResult` and the frozen lifecycle/status models are implemented in
`storage.models` exactly as amended above; do not define a second result type in
`ingress.py`. `ExchangeWriterLock.acquire(data_root, exchange=...)` is the only public
acquisition API; it returns the object used by tests and by `RawWriterService`. Hold it
for the full exchange-worker lifetime. Under that lock, finish startup recovery and
scan all closed/partial names before atomically allocating the next part sequence with
`O_EXCL`. `create_exchange_root_no_symlinks` creates/opens each `raw/<exchange>`
segment relative to a canonical data-root directory FD and rejects a symlink or
non-directory at any level; it does not perform a check-then-follow path walk.

- [ ] **Step 4: Run ingress and ownership tests**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_ingress.py tests/unit/storage/test_writer_lock.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/storage/models.py src/crypto_collector/storage/ingress.py src/crypto_collector/storage/writer_lock.py tests/unit/storage/test_ingress.py tests/unit/storage/test_writer_lock.py
git commit -m "feat: bound raw ingress ownership"
```

### Task 5: Rotation, Atomic Close, and Raw Manifest

**Files:**
- Create: `src/crypto_collector/storage/manifest.py`
- Create: `src/crypto_collector/storage/raw_writer.py`
- Test: `tests/unit/storage/test_raw_writer.py`
- Test: `tests/unit/storage/test_manifest.py`

- [ ] **Step 1: Write failing time, size, and config-boundary tests**

```python
@pytest.mark.asyncio
async def test_received_hour_routes_each_row_before_rotation_barrier(
    raw_writer_harness,
) -> None:
    before = make_record(received_at_ns=ns("2026-07-31T00:59:59.999Z"))
    after = make_record(received_at_ns=ns("2026-07-31T01:00:00Z"))
    raw_writer_harness.append_accepted(before)
    raw_writer_harness.append_accepted(after)
    old_manifests = await raw_writer_harness.rotate_due_files()
    new_manifests = await raw_writer_harness.close_all(CloseReason.SHUTDOWN)
    assert len(old_manifests) == len(new_manifests) == 1
    old, new = old_manifests[0], new_manifests[0]
    assert old.close_reason is CloseReason.ROTATE_TIME
    assert "/2026/07/31/00/" in f"/{old.data_relative_path}"
    assert "/2026/07/31/01/" in f"/{new.data_relative_path}"
    assert raw_writer_harness.decode_rows(old) == (before.envelope,)
    assert raw_writer_harness.decode_rows(new) == (after.envelope,)
    assert not Path(old.data_relative_path).name.endswith(".partial")


@pytest.mark.asyncio
async def test_config_reload_never_shares_a_closed_part(raw_writer_harness) -> None:
    raw_writer_harness.append_accepted(make_record(config_sha256="a" * 64))
    old_manifests = await raw_writer_harness.rotate_for_config(
        "b" * 64, config_generation=1
    )
    raw_writer_harness.append_accepted(make_record(config_sha256="b" * 64))
    new_manifests = await raw_writer_harness.close_all(
        CloseReason.SHUTDOWN
    )
    manifests = old_manifests + new_manifests
    assert {manifest.close_reason for manifest in old_manifests} == {
        CloseReason.CONFIG_RELOAD
    }
    assert {manifest.config_sha256 for manifest in manifests} == {"a" * 64, "b" * 64}


@pytest.mark.asyncio
async def test_hour_rotation_group_syncs_all_due_files_before_any_publication(
    raw_writer_harness, blocking_coordinator
) -> None:
    due = await raw_writer_harness.seed_three_due_files()
    rotation = asyncio.create_task(raw_writer_harness.rotate_due_files())
    submitted = await blocking_coordinator.wait_for_batch()
    assert submitted.generation_ids == tuple(item.generation_id for item in due)
    assert submitted.trigger is DurabilityTrigger.HOUR
    assert blocking_coordinator.call_count == 1
    assert not any(item.closed_path.exists() for item in due)
    blocking_coordinator.release_success()
    await rotation


@pytest.mark.asyncio
async def test_final_barrier_consumes_fast_file_before_unrelated_file_settles(
    raw_writer_harness, one_fast_one_blocked_coordinator
) -> None:
    first, second = await raw_writer_harness.seed_two_due_files()
    rotation = asyncio.create_task(raw_writer_harness.rotate_due_files())
    await one_fast_one_blocked_coordinator.wait_for_file_completion(first.generation_id)
    await raw_writer_harness.wait_for_completion_applied(first.generation_id)
    summary = raw_writer_harness.part_summary(first.generation_id)
    assert summary.durability_sample_count == first.record_count
    assert raw_writer_harness.stage_for(first.generation_id) is DurabilityStage.DURABLE
    assert raw_writer_harness.stage_for(second.generation_id) is DurabilityStage.IN_FLIGHT
    assert one_fast_one_blocked_coordinator.snapshot_read_count == 0
    assert not rotation.done()
    one_fast_one_blocked_coordinator.release(second.generation_id)
    await rotation


@pytest.mark.asyncio
async def test_one_group_sync_failure_withholds_every_normal_manifest(
    raw_writer_harness, one_failure_coordinator
) -> None:
    due = await raw_writer_harness.seed_three_due_files()
    with pytest.raises(WriterCriticalError):
        await raw_writer_harness.rotate_due_files()
    assert not any(item.closed_manifest_path.exists() for item in due)


def test_raw_manifest_has_independent_schema_version(raw_writer_harness) -> None:
    manifest = raw_writer_harness.close_one_part()
    assert manifest.schema_version == 1
    assert decode_json(manifest.canonical_bytes())["schema_version"] == 1
    with pytest.raises(UnsupportedManifestSchema):
        RawManifestV1.model_validate({**manifest.model_dump(), "schema_version": 2})


def test_hardlink_fallback_makes_destination_durable_before_source_unlink(tmp_path) -> None:
    source, destination = write_publication_source(tmp_path)
    trace = publish_with_tracing(source, destination, force_hardlink=True)
    assert trace == (
        "link", "destination_directory_fsync", "unlink_source",
        "source_directory_fsync",
    )


def test_renameat2_publication_is_same_parent_and_directory_durable(tmp_path) -> None:
    source, destination = write_publication_source(tmp_path)
    trace = publish_with_tracing(source, destination, force_renameat2=True)
    assert source.parent == destination.parent
    assert trace == ("renameat2_noreplace", "common_parent_directory_fsync")
    other_parent = tmp_path / "other"
    other_parent.mkdir()
    with pytest.raises(ValueError, match="same parent"):
        publish_no_replace(destination, other_parent / destination.name)


def test_publication_collision_never_overwrites_existing_bytes(tmp_path) -> None:
    source, destination = write_conflicting_publication(tmp_path)
    before = destination.read_bytes()
    with pytest.raises(PublicationConflict):
        publish_no_replace(source, destination)
    assert destination.read_bytes() == before


def test_close_hashes_published_inode_before_manifest_temp(raw_writer_harness) -> None:
    trace = raw_writer_harness.close_one_part_with_tracing()
    assert trace.index("data_publish") < trace.index("data_parent_directory_fsync")
    assert trace.index("data_parent_directory_fsync") < trace.index("hash_closed_data")
    assert trace.index("hash_closed_data") < trace.index("manifest_temp_create")
    assert trace.published_data_sha256 == sha256_file(trace.closed_data_path)


@pytest.mark.asyncio
async def test_later_publication_failure_preserves_earlier_member_and_recovery_inputs(
    raw_writer_harness, publication_backend
) -> None:
    due = await raw_writer_harness.seed_three_due_files()
    publication_backend.fail_on(due[1].closed_data_path, OSError(errno.EIO, "io"))
    with pytest.raises(WriterCriticalError) as captured:
        await raw_writer_harness.rotate_due_files()
    assert captured.value.reason is WriterCriticalReason.PUBLICATION_FAILED
    assert due[0].closed_path.exists()
    assert due[0].closed_manifest_path.exists()
    assert_reconcilable_names_retained(due[1:])
    assert captured.value.affected_generation_ids == tuple(
        item.generation_id for item in due[1:]
    )
```

- [ ] **Step 2: Run and verify missing writer/manifest modules**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_raw_writer.py tests/unit/storage/test_manifest.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement the close protocol exactly**

For one hour, max-compressed-size, config, or shutdown close command, create one
service-owned final-barrier command. In particular,
`CloseReason.ROTATE_SIZE` uses this path; it is distinct from a non-closing frame-cap
flush even though both map to `DurabilityTrigger.SIZE`.
The service loop submits the group and immediately returns to its message pump; it does
not await the batch and does not read coordinator statistics:

```python
due_files, associated_controls = preflight_close_group(reason)
work_files = due_files + associated_controls
prerequisites = {}
prerequisite_batches = {}
for stream_file in work_files:
    claim = stream_file.in_flight_claim()
    if claim is None:
        continue
    batch_task = stream_file.claim_batch_task(claim)
    if batch_task is None:
        raise UntrackedInFlightClaim(stream_file.generation_id)
    prerequisites[stream_file.generation_id] = claim
    prerequisite_batches.setdefault(batch_task, []).append(
        stream_file.generation_id
    )
for generation_id in (item.generation_id for item in work_files):
    if generation_id in self._final_barrier_by_generation_id:
        raise DuplicateFileGeneration(generation_id)
retire_and_detach(due_files, reason)

command = FinalBarrierCommandState(
    command_id=uuid.uuid4(),
    due_files=due_files,
    work_files=work_files,
    prerequisites=prerequisites,
    prerequisite_batches=prerequisite_batches,
    remaining_prerequisite_generation_ids=set(prerequisites),
    remaining_generation_ids=set(),
    batch_settled=False,
    result_future=loop.create_future(),
)
self._owned_commands[command.command_id] = command
for generation_id in (item.generation_id for item in work_files):
    self._final_barrier_by_generation_id[generation_id] = command.command_id
for batch_task in prerequisite_batches:
    batch_task.add_done_callback(
        lambda task: self._post_prerequisite_batch_settled(
            command.command_id, task
        )
    )
if not prerequisites:
    self._submit_final_batch(command)

def _submit_final_batch(command: FinalBarrierCommandState) -> None:
    # An in-flight associated control that completed successfully has already been
    # folded. A still-pending associated control joins this batch even when it is not
    # itself due to close.
    final_files = command.due_files + command.pending_associated_controls()
    due_work = tuple(
        stream_file.seal_for_sync(force_sync=True)
        for stream_file in final_files
    )
    command.remaining_generation_ids = {
        item.generation_id for item in due_work
    }
    command.batch_task = asyncio.create_task(
        durability_coordinator.sync_batch(
            due_work,
            trigger=command.trigger,
        )
    )
    command.batch_task.add_done_callback(
        lambda task: self._post_batch_settled(command.command_id, task)
    )

# These cases run in ordinary service-loop FIFO turns. This helper is also used by
# periodic/frame-cap/barrier completions and is the sole ledger/statistics writer.
match message:
    case FileSyncCompleted(result=result):
        self._apply_file_completion(result)
        self._note_final_barrier_file_settled(result.generation_id, failure=None)

    case FileSyncFailed(generation_id=generation_id, error=error):
        self._apply_file_failure(generation_id, error)
        self._note_final_barrier_file_settled(generation_id, failure=error)

    case FinalBarrierPrerequisiteBatchSettled(command_id=command_id, task=task):
        command = self._owned_commands.get(command_id)
        if command is not None:
            # A settled originating batch must have emitted one per-file completion.
            # Missing notifications terminalize those prerequisite claims; inherit an
            # explicit WRITE_FAILED/SYNC_FAILED reason for affected generations.
            self._fail_missing_prerequisite_completions(command, task)
            self._try_advance_prerequisites(command)

    case FinalBarrierBatchSettled(command_id=command_id, outcome=outcome):
        command = self._owned_commands[command_id]
        command.batch_settled = True
        command.batch_outcome = outcome
        self._fail_missing_final_completions(command)
        self._try_finish_final_barrier(command)

def _note_final_barrier_file_settled(
    generation_id: str, *, failure: BaseException | None
) -> None:
    command_id = self._final_barrier_by_generation_id.get(generation_id)
    if command_id is None:
        # Periodic, frame-cap flush, and explicit sync work has no final-barrier state.
        return
    command = self._owned_commands[command_id]
    if generation_id in command.remaining_prerequisite_generation_ids:
        self._settle_prerequisite(command, generation_id, failure=failure)
        self._try_advance_prerequisites(command)
        return
    self._final_barrier_by_generation_id.pop(generation_id)
    command.remaining_generation_ids.remove(generation_id)
    if failure is not None:
        command.file_errors[generation_id] = failure
    self._try_finish_final_barrier(command)

def _try_finish_final_barrier(command: FinalBarrierCommandState) -> None:
    if command.remaining_generation_ids or not command.batch_settled:
        return
    if command.file_errors or command.batch_outcome.is_error:
        self._finish_failed_barrier_without_publication(command)
        return
    summaries = {
        stream_file.generation_id: self._part_accumulators[
            stream_file.generation_id
        ].freeze()
        for stream_file in command.due_files
    }
    command.publication_task = asyncio.create_task(
        self._publish_group_io(command.due_files, summaries)
    )
    command.publication_task.add_done_callback(
        lambda task: self._post_publication_settled(command.command_id, task)
    )
```

Completion accounting is unconditional, but final-barrier bookkeeping is conditional
on the explicit generation-to-command index installed when the close command is
created. Periodic, non-closing plaintext frame-cap, and `sync_now` generations initially
have no `FinalBarrierCommandState`; this does not include `CloseReason.ROTATE_SIZE`.
If a close command encounters one of those claims still in flight, it adopts the exact
claim and its tracked originating batch task as a prerequisite, then reserves every
closing and associated-control generation before returning to the message pump. A
settled prerequisite keeps its reservation when it must join the final batch; a durable
non-closing control may release its reservation after its association is folded. Failed
prerequisite reservations are released together only after every prerequisite settles.
Untracked in-flight claims are rejected before retirement. Ordinary completions with no
adopting command are fully applied and return from
`_note_final_barrier_file_settled` without lookup failure. Conversely, every generation
reserved by a final command must release exactly its own index entry before the command
can publish or fail, and command cleanup asserts no entry owned by that command remains.

`_publish_group_io` receives only immutable service-owned summary snapshots and performs
sequential filesystem work through `run_storage`; it cannot mutate the ledger,
histograms, counters, lifecycle, or accumulators. Its terminal message is consumed by
the service loop, which alone publishes the command result/lifecycle transition. The
caller awaits a shielded `result_future`; cancellation never cancels `batch_task` or
`publication_task`. The publication coroutine applies this exact per-file protocol:

```python
async def publish_group_io(due_files, summaries) -> None:
    for stream_file in due_files:
        durability_summary = summaries[stream_file.generation_id]
        await run_storage(io_limiter, storage_executor, stream_file.close_fd)
        verification_fd = await run_storage(
            io_limiter,
            storage_executor,
            open_readonly_nofollow,
            stream_file.partial_path,
        )
        try:
            await run_storage(
                io_limiter,
                storage_executor,
                publish_no_replace,
                stream_file.partial_path,
                stream_file.closed_data_path,
            )
            await run_storage(
                io_limiter,
                storage_executor,
                require_path_is_open_inode,
                stream_file.closed_data_path,
                verification_fd,
            )
            data_size, data_sha256 = await run_storage(
                io_limiter, storage_executor, size_and_sha256_fd, verification_fd
            )
        finally:
            await run_storage(io_limiter, storage_executor, os.close, verification_fd)
        manifest = build_manifest(
            stream_file, durability_summary, data_size, data_sha256
        )
        await run_storage(
            io_limiter,
            storage_executor,
            atomic_write_and_sync_json_exclusive,
            stream_file.manifest_partial_path,
            manifest.canonical_bytes(),
        )
        await run_storage(
            io_limiter,
            storage_executor,
            publish_no_replace,
            stream_file.manifest_partial_path,
            stream_file.closed_manifest_path,
        )
```

`seal_and_detach_all_due_files` is atomic with respect to the service loop: records
accepted afterward target new parts. A group member is not closed or published until
all final per-file completion messages have been consumed, their ledger transitions and
per-part accumulators have been applied, and the owned batch has settled. The enclosing
`DurabilityBatch` is only a barrier/error consistency result and never causes the same
completion to be applied twice. If any final write or sync fails, no group member is
published. Once sequential publication begins, a later
member can fail after earlier members are already immutable; retain every name, report
the affected generation suffix as `PUBLICATION_FAILED`, and let Task 6 reconcile each
identity without rollback. Size rotation uses the
same final-command function with its due subset and installs the same
generation-to-command index before sync. `publish_no_replace` implements the probed
`renameat2(RENAME_NOREPLACE)` or hard-link fallback from the amendment; check-then-
rename is forbidden. The helper performs its own required directory sync(s);
`fsync_directory` opens the directory with `O_RDONLY | O_DIRECTORY` and calls
`os.fsync`. Failures are fatal and leave startup reconciliation evidence. Every
operation shown after `sync_batch`, including close, SHA-256, publication, and
directory sync, stays off the event loop. `run_storage` is the thin
wrapper that enters the supplied worker-global `io_limiter.slot()` and then awaits
`loop.run_in_executor(storage_executor, function, *args)`; it is not a second executor,
semaphore, or work queue.

The close order is normative: close the writable descriptor; retain a no-follow
read-only descriptor for that inode; publish data with no-replace semantics and complete
the destination-parent directory sync; verify the closed path still names that open
inode; only then hash/size the published inode, build and sync the manifest temporary,
and publish the manifest. Hashing the `.partial` pathname or constructing a manifest
before directory-durable data publication is forbidden. The read descriptor closes on
every success/failure path, and a path/inode mismatch is `PublicationConflict` with no
manifest publication.

`RawManifestV1` implements the exact amended V1 fields and rejects unsupported
versions. Persist only bounded per-part durability aggregates including the final
group sync, never every batch object. `load_raw_manifest` validates canonical bytes
and structure without requiring the referenced data file. Task 5 does not implement
lease-aware local-source validation: Task 6 creates `lease.py`, modifies
`manifest.py`, and adds `validate_local_source` plus `RawManifestReader` only after
`SourceLease` exists. Add collision tests proving an existing destination is never
overwritten for both data and manifest publication.

The `writer` fixture in this task exercises the package-private active-part implementation directly. It is not a runtime contract. Task 6 wraps it in the only public `RawWriterService`; production callers cannot call `put` or close individual parts.

- [ ] **Step 4: Run rotation and manifest tests**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_raw_writer.py tests/unit/storage/test_manifest.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/storage/manifest.py src/crypto_collector/storage/raw_writer.py tests/unit/storage/test_raw_writer.py tests/unit/storage/test_manifest.py
git commit -m "feat: close immutable raw manifests"
```

### Task 6: Crash Recovery, Orphan Reconciliation, and Source Leases

**Files:**
- Modify: `src/crypto_collector/domain/types.py`
- Modify: `src/crypto_collector/storage/__init__.py`
- Create: `src/crypto_collector/storage/errors.py`
- Modify: `src/crypto_collector/storage/durability.py`
- Modify: `src/crypto_collector/storage/serialize.py`
- Modify: `src/crypto_collector/storage/manifest.py`
- Modify: `src/crypto_collector/storage/raw_writer.py`
- Create: `src/crypto_collector/storage/recovery.py`
- Create: `src/crypto_collector/storage/lease.py`
- Create: `src/crypto_collector/storage/service.py`
- Create: `tests/helpers/writer_crash_child.py`
- Test: `tests/unit/storage/test_lease.py`
- Test: `tests/integration/storage/test_recovery.py`
- Test: `tests/integration/storage/test_service_startup.py`
- Test: `tests/integration/storage/test_writer_crash_points.py`

- [ ] **Step 1: Write kill-tail recovery tests**

```python
@pytest.mark.asyncio
async def test_complete_frames_are_recovered_and_bad_tail_is_quarantined(tmp_path) -> None:
    async with production_recovery_harness(tmp_path) as harness:
        partial = write_two_frames_and_truncated_third(harness.context.data_root)
        reconciliation = await harness.backend.reconcile(harness.context)
        outcomes = await harness.drive_pending_controls(reconciliation)
    result = only_outcome_for(outcomes, partial)
    assert result.recovered_generation_id is not None
    assert result.recovered_relative_path is not None
    assert result.recovered_relative_path != partial.relative_to(
        harness.context.data_root
    ).as_posix().removesuffix(".partial")
    assert result.quarantined_relative_path is not None
    recovered_path = harness.context.data_root / result.recovered_relative_path
    envelopes = [
        decode_envelope_jsonl(line)
        for line in read_all_jsonl_bytes(recovered_path)
    ]
    assert [envelope.writer_sequence for envelope in envelopes] == [1, 2]
    manifest = load_raw_manifest(manifest_path_for_data(recovered_path)).manifest
    assert manifest.close_reason is CloseReason.RECOVERY
    assert manifest.control_event_ids is None
    assert manifest.recovery_control_event_id == result.recovery_control_event_id
    assert manifest.unavailable_fields == RECOVERY_UNAVAILABLE_FIELDS
    assert manifest.quarantined_suffix_bytes > 0
    assert (harness.context.data_root / result.quarantined_relative_path).exists()


@pytest.mark.asyncio
async def test_complete_nonempty_partial_is_recovered_without_quarantine(tmp_path) -> None:
    async with production_recovery_harness(tmp_path) as harness:
        partial = write_one_complete_frame(harness.context.data_root)
        reconciliation = await harness.backend.reconcile(harness.context)
        outcomes = await harness.drive_pending_controls(reconciliation)
    result = only_outcome_for(outcomes, partial)
    assert result.source_state is RecoverySourceState.PARTIAL_COMPLETE
    assert result.source_disposition is RecoverySourceDisposition.REMOVED
    assert result.recovered_relative_path is not None
    assert result.quarantined_relative_path is None
    assert not partial.exists()
    assert manifest_path_for_data(
        harness.context.data_root / result.recovered_relative_path
    ).exists()


@pytest.mark.parametrize("source_bytes", [b"", b"not-zstd"], ids=["empty", "unreadable"])
@pytest.mark.asyncio
async def test_empty_or_unreadable_partial_is_wholly_quarantined(
    tmp_path, source_bytes
) -> None:
    async with production_recovery_harness(tmp_path) as harness:
        partial = harness.context.data_root / valid_partial_relative_path()
        partial.parent.mkdir(parents=True)
        partial.write_bytes(source_bytes)
        reconciliation = await harness.backend.reconcile(harness.context)
        outcomes = await harness.drive_pending_controls(reconciliation)
        result = only_outcome_for(outcomes, partial)
        intent = load_recovery_intent_for_source(harness.context.state_root, partial)
        assert result.quarantined_relative_path is not None
        quarantine = harness.context.data_root / result.quarantined_relative_path
        assert result.source_disposition is RecoverySourceDisposition.MOVED_TO_QUARANTINE
        assert result.recovered_relative_path is None
        assert result.quarantined_sha256 == sha256_bytes(source_bytes)
        assert quarantine.read_bytes() == source_bytes
        assert not partial.exists()
        assert not list(harness.context.data_root.rglob("*.manifest.json"))
        assert intent.planned_data_generation_id is None
        assert intent.planned_data_relative_path is None
        assert intent.planned_data_size_bytes is None
        assert intent.planned_data_sha256 is None
        assert intent.planned_manifest_relative_path is None
        assert intent.planned_manifest_size_bytes is None
        assert intent.planned_manifest_sha256 is None

        replay = await harness.backend.reconcile(harness.context)
        replay_outcomes = await harness.drive_pending_controls(replay)
        assert only_outcome_for(replay_outcomes, partial) == result
        assert quarantine.read_bytes() == source_bytes


@pytest.mark.parametrize(
    "edge", ["partial_create_before_parent_fsync", "partial_parent_fsync"]
)
def test_sigkill_around_allocation_parent_fsync_recovers_zero_byte_partial(
    tmp_path, edge
) -> None:
    crashed = run_writer_allocation_crash_child(tmp_path, halt_at=edge)
    assert crashed.returncode == -signal.SIGKILL
    assert crashed.partial_path.exists()
    assert crashed.partial_path.stat().st_size == 0
    report = run_recovery_in_fresh_process(tmp_path)
    outcome = report.only_outcome_for(crashed.partial_path)
    assert outcome.source_disposition is RecoverySourceDisposition.MOVED_TO_QUARANTINE
    assert outcome.recovered_relative_path is None
    assert outcome.source_sha256 == sha256_bytes(b"")
    quarantine = tmp_path / outcome.quarantined_relative_path
    assert quarantine.read_bytes() == b""
    assert not crashed.partial_path.exists()
    assert_no_unbound_partial_or_orphan(tmp_path)
    replay = run_recovery_in_fresh_process(tmp_path)
    assert replay.only_outcome_for(crashed.partial_path) == outcome
    assert replay.recovery_transaction_count == 1


@pytest.mark.asyncio
async def test_cross_identity_frame_and_every_later_byte_are_not_recovered(tmp_path) -> None:
    async with production_recovery_harness(tmp_path) as harness:
        partial = write_frames(
            harness.context.data_root,
            [valid_rows_for_path(), valid_rows_for_other_instrument(), valid_rows_for_path()],
        )
        reconciliation = await harness.backend.reconcile(harness.context)
        outcomes = await harness.drive_pending_controls(reconciliation)
    result = only_outcome_for(outcomes, partial)
    assert result.recovered_relative_path is not None
    recovered_path = harness.context.data_root / result.recovered_relative_path
    assert [row.writer_sequence for row in read_recovered_envelopes(recovered_path)] == [0, 1]
    manifest = load_raw_manifest(manifest_path_for_data(recovered_path)).manifest
    assert manifest.recovery_source_state is RecoverySourceState.PARTIAL_TRUNCATED


@pytest.mark.parametrize("halt_after", [
    "intent", "artifacts_durable", "source_settled", "control_ownership",
    "control_sync", "control_durable",
])
def test_recovery_transaction_replays_to_complete_with_stable_event_id(
    tmp_path, halt_after
) -> None:
    first = run_recovery_crash_child(tmp_path, halt_after=halt_after)
    event_id = first.intent.recovery_control_event_id
    planned_disposition = first.intent.planned_source_disposition
    report = run_recovery_in_fresh_process(tmp_path)
    assert report.complete_transaction_ids == (first.intent.transaction_id,)
    assert set(report.recovery_control_event_ids) == {event_id}
    assert report.complete_source_dispositions == {planned_disposition}
    assert report.recovery_transaction_count == 1
    assert report.unbound_partial_or_orphan_count == 0
    assert_transaction_fact_chain_valid(first.intent.transaction_root)


@pytest.mark.parametrize("written_fraction", [0, 0.5, 1])
def test_owned_control_carrier_resumes_exact_bound_frame_without_new_transaction(
    tmp_path, written_fraction
) -> None:
    first = run_owned_control_carrier_crash_child(
        tmp_path, written_fraction=written_fraction
    )
    report = run_recovery_in_fresh_process(tmp_path)
    ownership = load_recovery_control_ownership(first.transaction_root)
    loaded = load_raw_manifest(first.control_manifest_path)
    assert report.recovery_transaction_count == 1
    assert report.complete_transaction_ids == (first.transaction_id,)
    assert read_only_control_envelope(report.control_manifest) == first.control_envelope
    assert loaded.manifest.recovery_source_state is RecoverySourceState.OWNED_CONTROL_CARRIER
    assert first.control_manifest_path.read_bytes() == base64.b64decode(
        ownership.control_recovery_manifest_base64, validate=True
    )
    assert loaded.manifest.file_sha256 == ownership.control_frame_sha256
    assert_manifest_matches_data(loaded.manifest, first.control_data_path)
    assert (
        report.current_process_metrics.accepted_record_count,
        report.current_process_metrics.durable_record_count,
        report.current_process_metrics.durability_sample_count,
    ) == (0, 0, 0)
    assert report.current_process_metrics.durability_histogram_series == ()
    assert not first.control_partial_path.exists()
    assert_no_owned_control_carrier_seeded_a_source_transaction(tmp_path)


def test_owned_control_exact_normal_manifest_is_validated_not_replaced(tmp_path) -> None:
    first = run_owned_control_normal_manifest_crash_child(
        tmp_path, halt_at="owned_control_normal_manifest_parent_fsync"
    )
    original_manifest_bytes = first.control_manifest_path.read_bytes()
    original = load_raw_manifest(first.control_manifest_path).manifest
    assert original.durability_measurement == "measured"
    assert original.recovery_source_state is None

    report = run_recovery_in_fresh_process(tmp_path)

    assert report.complete_transaction_ids == (first.transaction_id,)
    assert first.control_manifest_path.read_bytes() == original_manifest_bytes
    replayed = load_raw_manifest(first.control_manifest_path).manifest
    assert replayed == original
    assert_manifest_matches_data(replayed, first.control_data_path)
    assert report.owned_control_recovery_manifest_publish_count == 0
    assert_no_owned_control_carrier_seeded_a_source_transaction(tmp_path)


def test_owned_control_carrier_nonprefix_bytes_block_without_deriving_transaction(
    tmp_path,
) -> None:
    first = run_owned_control_carrier_crash_child(tmp_path, written_fraction=0.5)
    first.control_partial_path.write_bytes(b"not-the-owned-frame")
    with pytest.raises(RecoveryBlocked, match="owned control carrier"):
        run_recovery_in_fresh_process(tmp_path)
    assert recovery_transaction_ids(tmp_path) == (first.transaction_id,)


@pytest.mark.parametrize("edge", [
    "recovery_root_mkdir", "recovery_root_parent_fsync",
    "exchange_journal_mkdir", "exchange_journal_parent_fsync",
    "transaction_mkdir", "transaction_parent_fsync",
    "intent_temp_create", "intent_temp_parent_fsync", "intent_file_fsync",
    "intent_rename", "intent_parent_fsync",
    "recovered_data_temp_create", "recovered_data_temp_parent_fsync",
    "recovered_data_file_fsync", "recovered_data_publish",
    "recovered_data_parent_fsync", "retained_data_parent_fsync",
    "recovery_manifest_temp_create",
    "recovery_manifest_temp_parent_fsync", "recovery_manifest_file_fsync",
    "recovery_manifest_publish", "recovery_manifest_parent_fsync",
    "quarantine_temp_create", "quarantine_temp_parent_fsync",
    "quarantine_file_fsync", "quarantine_publish", "quarantine_parent_fsync",
    "artifacts_temp_create", "artifacts_temp_parent_fsync",
    "artifacts_file_fsync", "artifacts_rename", "artifacts_parent_fsync",
    "source_settlement_mutation", "source_settlement_parent_fsync",
    "source_settled_temp_create", "source_settled_temp_parent_fsync",
    "source_settled_file_fsync", "source_settled_rename",
    "source_settled_parent_fsync", "control_ownership_temp_create",
    "control_ownership_temp_parent_fsync", "control_ownership_file_fsync",
    "control_ownership_rename", "control_ownership_parent_fsync",
    "owned_control_partial_create", "owned_control_partial_parent_fsync",
    "owned_control_frame_write", "recovery_control_sync",
    "owned_control_data_publish", "owned_control_data_parent_fsync",
    "owned_control_normal_manifest_publish",
    "owned_control_normal_manifest_parent_fsync",
    "owned_control_recovery_manifest_publish",
    "owned_control_recovery_manifest_parent_fsync",
    "control_durable_temp_create", "control_durable_temp_parent_fsync",
    "control_durable_file_fsync", "control_durable_rename",
    "control_durable_parent_fsync", "complete_temp_create",
    "complete_temp_parent_fsync", "complete_file_fsync", "complete_rename",
    "complete_parent_fsync",
])
def test_sigkill_at_every_recovery_journal_durability_edge_replays_exactly(
    tmp_path, edge
) -> None:
    crash_recovery_at_edge(tmp_path, edge)
    report = run_recovery_in_fresh_process(tmp_path)
    assert report.terminal_outcome_count == 1
    assert report.recovery_transaction_count == 1
    carrier = load_raw_manifest(report.control_manifest_path).manifest
    assert carrier.record_count == 1
    assert_manifest_matches_data(carrier, report.control_data_path)
    assert read_only_control_envelope(carrier) == report.recovery_control_envelope
    assert_all_recovery_fact_chains_canonical_and_hash_linked(tmp_path)
    assert_each_source_is_bound_to_at_most_one_transaction(tmp_path)
    assert_no_owned_control_carrier_seeded_a_source_transaction(tmp_path)


@pytest.mark.asyncio
async def test_closed_data_without_manifest_is_reconciled(tmp_path) -> None:
    async with production_recovery_harness(tmp_path) as harness:
        data_path = write_valid_closed_data_without_manifest(harness.context.data_root)
        reconciliation = await harness.backend.reconcile(harness.context)
        outcomes = await harness.drive_pending_controls(reconciliation)
    manifest = load_raw_manifest(manifest_path_for_data(data_path)).manifest
    assert manifest.close_reason is CloseReason.RECOVERY
    assert manifest.recovery_source_state is RecoverySourceState.ORPHAN_CLOSED_DATA
    assert manifest.data_relative_path == data_path.relative_to(
        harness.context.data_root
    ).as_posix()
    assert not recovery_created_second_data_identity(harness.context.data_root, data_path)
    outcome = only_outcome_for(outcomes, data_path)
    assert outcome.source_state is RecoverySourceState.ORPHAN_CLOSED_DATA
    assert outcome.recovered_generation_id == generation_id_from_data_path(data_path)
    assert outcome.recovered_relative_path == manifest.data_relative_path
    assert harness.trace.index("retained_data_parent_fsync") < harness.trace.index(
        "recovery_manifest_temp_create"
    )


def test_retained_orphan_survives_writer_crash_then_recovery_crash(tmp_path) -> None:
    first = run_writer_publication_crash_child(
        tmp_path, halt_at="data_publish_before_parent_fsync"
    )
    assert first.closed_data_path.exists()
    assert not first.closed_manifest_path.exists()
    second = run_recovery_crash_child(
        tmp_path,
        source=first.closed_data_path,
        halt_at="retained_data_parent_fsync",
    )
    assert second.returncode == -signal.SIGKILL
    report = run_recovery_in_fresh_process(tmp_path)
    outcome = report.only_outcome_for(first.closed_data_path)
    assert outcome.source_disposition is RecoverySourceDisposition.RETAINED
    assert first.closed_data_path.exists()
    assert first.closed_manifest_path.exists()
    assert report.recovery_transaction_count == 1
    assert_transaction_fact_chain_valid(report.only_transaction_root)


@pytest.mark.asyncio
async def test_corrupt_closed_orphan_is_wholly_quarantined_not_salvaged(tmp_path) -> None:
    async with production_recovery_harness(tmp_path) as harness:
        data_path = write_valid_closed_data_without_manifest(harness.context.data_root)
        original = data_path.read_bytes() + b"corrupt-closed-tail"
        data_path.write_bytes(original)
        reconciliation = await harness.backend.reconcile(harness.context)
        outcomes = await harness.drive_pending_controls(reconciliation)
    outcome = only_outcome_for(outcomes, data_path)
    intent = load_recovery_intent_for_source(harness.context.state_root, data_path)
    assert outcome.quarantined_relative_path is not None
    quarantine = harness.context.data_root / outcome.quarantined_relative_path
    assert outcome.source_state is RecoverySourceState.ORPHAN_CLOSED_DATA
    assert outcome.source_disposition is RecoverySourceDisposition.MOVED_TO_QUARANTINE
    assert outcome.recovered_relative_path is None
    assert outcome.quarantined_sha256 == sha256_bytes(original)
    assert quarantine.read_bytes() == original
    assert not data_path.exists()
    assert not manifest_path_for_data(data_path).exists()
    assert intent.planned_data_generation_id is None
    assert intent.planned_data_relative_path is None
    assert intent.planned_data_size_bytes is None
    assert intent.planned_data_sha256 is None
    assert intent.planned_manifest_relative_path is None
    assert intent.planned_manifest_size_bytes is None
    assert intent.planned_manifest_sha256 is None


@pytest.mark.asyncio
async def test_reconcile_stops_at_source_settled_until_exact_live_receipt(tmp_path) -> None:
    async with production_recovery_harness(tmp_path) as harness:
        partial = write_one_complete_frame(harness.context.data_root)
        reconciliation = await harness.backend.reconcile(harness.context)
        pending = only_pending_for(reconciliation.pending_controls, partial)
        assert not recovery_fact_exists(pending.transaction_id, "control-durable")
        receipt = await harness.persist_pending_control(pending)
        assert harness.trace.index("control_ownership_parent_fsync") < harness.trace.index(
            "owned_control_partial_create"
        )
        assert recovery_fact_exists(pending.transaction_id, "control-ownership")
        with pytest.raises(RecoveryBlocked, match="receipt"):
            await harness.backend.acknowledge_control_durable(
                harness.context,
                pending=pending,
                receipt=dataclasses.replace(
                    receipt, control_encoded_sha256="f" * 64
                ),
            )
        outcome = await harness.backend.acknowledge_control_durable(
            harness.context, pending=pending, receipt=receipt
        )
        repeated = await harness.backend.acknowledge_control_durable(
            harness.context, pending=pending, receipt=receipt
        )
    assert repeated == outcome
    assert outcome.source_disposition is pending.source_disposition
    assert_recovery_fact_chain_ends_at_complete(pending.transaction_id)


@pytest.mark.parametrize("proof_kind", ["durable_intent", "final_tombstone"])
@pytest.mark.asyncio
async def test_manifest_without_data_and_valid_cleanup_proof_is_preserved(
    tmp_path, proof_kind
) -> None:
    data_root = tmp_path / "data"
    manifest_path = write_manifest_with_missing_data(data_root)
    resolver = exact_cleanup_proof(manifest_path, proof_kind=proof_kind)
    async with production_recovery_harness(
        tmp_path, data_root=data_root, resolver=resolver
    ) as harness:
        reconciliation = await harness.backend.reconcile(harness.context)
        outcomes = await harness.drive_pending_controls(reconciliation)
    assert manifest_path.exists()
    outcome = only_outcome_for(outcomes, manifest_path)
    assert outcome.informational_only
    assert outcome.source_state in {
        RecoverySourceState.CLEANUP_INTENT,
        RecoverySourceState.CLEANUP_TOMBSTONE,
    }
    intent = load_recovery_intent(outcome.transaction_id)
    assert intent.planned_source_disposition is RecoverySourceDisposition.LEGITIMATELY_MISSING
    assert intent.cleanup_proof_sha256 == resolver.evidence.proof_sha256
    assert intent.cleanup_proof_relative_path == resolver.evidence.proof_relative_path


def test_cleanup_replay_rejects_a_different_valid_proof_than_frozen_intent(tmp_path) -> None:
    source = write_manifest_with_missing_data(tmp_path / "data")
    durable_intent = write_exact_cleanup_intent(source)
    first = run_recovery_crash_child(
        tmp_path, resolver=cleanup_resolver(durable_intent), halt_after="intent"
    )
    remove_proof_and_publish_valid_tombstone_for_same_source(durable_intent)
    with pytest.raises(RecoveryBlocked, match="cleanup proof"):
        run_recovery_in_fresh_process(tmp_path)
    assert first.intent.cleanup_proof_kind is CleanupProofKind.DURABLE_INTENT


@pytest.mark.asyncio
async def test_manifest_without_data_and_without_valid_cleanup_proof_blocks(tmp_path) -> None:
    data_root = tmp_path / "data"
    manifest_path = write_manifest_with_missing_data(data_root)
    async with production_recovery_harness(
        tmp_path, data_root=data_root, resolver=NoCleanupProofResolver()
    ) as harness:
        with pytest.raises(RecoveryBlocked, match="MISSING_UNEXPLAINED"):
            await harness.backend.reconcile(harness.context)
    assert manifest_path.exists()
    assert not list(data_root.rglob("*.manifest-missing-data"))


def test_cleanup_exclusive_lease_waits_for_materializer_shared_lease(tmp_path) -> None:
    lease_path = lease_path_for_data(tmp_path / "part.jsonl.zst")
    assert lease_path.name == "part.lease"
    with SourceLease.shared(lease_path):
        with pytest.raises(SourceLeaseBusy):
            SourceLease.exclusive(lease_path, blocking=False)


@pytest.mark.parametrize("phase", [
    "after_frame_write", "after_data_sync", "after_data_publish",
    "after_manifest_temp_sync", "after_manifest_publish",
])
def test_sigkill_at_close_phase_converges_to_one_visible_outcome(tmp_path, phase) -> None:
    child = start_writer_crash_child(tmp_path, halt_at=phase)
    wait_for_phase_marker(tmp_path, phase)
    child.kill()
    child.wait(timeout=10)
    report = run_recovery_in_fresh_process(tmp_path)
    assert report.complete_parts + report.quarantined_parts == 1
    assert_no_path_has_both_partial_and_complete_identity(tmp_path)


@pytest.mark.parametrize("phase", [
    "after_link", "after_destination_directory_fsync", "after_source_unlink",
])
def test_sigkill_during_hardlink_fallback_preserves_one_durable_name(
    tmp_path, phase
) -> None:
    child = start_writer_crash_child(tmp_path, halt_at=phase, force_hardlink=True)
    wait_for_phase_marker(tmp_path, phase)
    child.kill()
    child.wait(timeout=10)
    run_recovery_in_fresh_process(tmp_path)
    assert_one_closed_identity_with_valid_hash(tmp_path)


def test_recovery_reconciles_group_after_later_publication_failure(tmp_path) -> None:
    failed = run_group_close_with_publication_failure(tmp_path, fail_member_index=1)
    first_manifest_sha256 = sha256_file(failed.members[0].closed_manifest_path)
    report = run_recovery_in_fresh_process(tmp_path)
    assert report.complete_parts + report.quarantined_parts == 3
    assert sha256_file(failed.members[0].closed_manifest_path) == first_manifest_sha256
    assert_each_generation_has_exactly_one_terminal_outcome(tmp_path, failed.members)


@pytest.mark.parametrize("phase", [
    "frame_write", "data_sync", "data_directory_sync",
    "manifest_temp_write", "manifest_temp_sync",
])
@pytest.mark.parametrize("error", [OSError(errno.ENOSPC, "full"), OSError(errno.EIO, "io")])
def test_prepublication_io_error_matrix_never_publishes_normal_manifest(
    tmp_path, phase, error,
) -> None:
    result = run_writer_with_injected_io_error(tmp_path, error, at=phase)
    assert result.writer_status.lifecycle is WriterLifecycle.CRITICAL
    assert result.writer_status.incomplete
    assert result.writer_status.incomplete_reason is not None
    assert result.writer_status.uncertain_record_count > 0
    assert result.trace.last_attempted_phase == phase
    assert not list(tmp_path.rglob("*.manifest.json"))
    recovered = run_recovery_in_fresh_process(tmp_path)
    assert recovered.complete_parts + recovered.quarantined_parts == 1
    assert_no_path_has_both_partial_and_complete_identity(tmp_path)


def test_manifest_publish_is_followed_by_directory_fsync_and_eio_converges(tmp_path) -> None:
    result = run_writer_with_injected_io_error(
        tmp_path, OSError(errno.EIO, "io"), at="manifest_directory_fsync")
    assert result.trace[-2:] == ("manifest_publish", "manifest_directory_fsync")
    assert result.writer_status.lifecycle is WriterLifecycle.CRITICAL
    recovered = run_recovery_in_fresh_process(tmp_path)
    assert recovered.complete_parts + recovered.quarantined_parts == 1
    assert_no_path_has_both_partial_and_complete_identity(tmp_path)


@pytest.mark.asyncio
async def test_unrecoverable_recovery_failure_opens_no_ingress_or_part(tmp_path) -> None:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    with pytest.raises(RecoveryBlocked):
        await RawWriterService.open(
            data_root=data_root, state_root=state_root, exchange=Exchange.OKX,
            worker_instance_id="worker-1", config_sha256="a" * 64,
            config_generation=0,
            writer_config=test_writer_config(), ingress_config=test_ingress_config(),
            metric_stream_allowlist=("_control",),
            clock=FakeClock(), sync_backend=FakeSync(),
            recovery_backend=FailingRecovery(errno.EIO))
    assert not list(data_root.rglob("*.jsonl.zst.partial"))
    with ExchangeWriterLock.acquire(data_root, exchange=Exchange.OKX):
        pass


@pytest.mark.asyncio
async def test_service_config_rotation_swaps_identity_without_sequence_reset(service) -> None:
    first = service.try_accept(trade_draft(), source=websocket_source(), shard="trade-0")
    old_manifests = await service.rotate_for_config("b" * 64, config_generation=1)
    second = service.try_accept(trade_draft(), source=websocket_source(), shard="trade-0")
    assert first.record.envelope.config_sha256 == "a" * 64
    assert second.record.envelope.config_sha256 == "b" * 64
    assert (first.record.envelope.writer_sequence,
            second.record.envelope.writer_sequence) == (0, 1)
    assert {manifest.config_sha256 for manifest in old_manifests} == {"a" * 64}


@pytest.mark.asyncio
async def test_max_compressed_size_rotation_publishes_old_part_and_replaces_generation(
    service_harness,
) -> None:
    service = await service_harness.open(
        writer_config=service_harness.writer_config(max_compressed_size_bytes=1)
    )
    first = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    old_generation = service_harness.generation_id_for(first.record_identity)
    await service.sync_now()
    await service_harness.wait_for_size_rotation(old_generation)

    assert service_harness.closed_data_path(old_generation).exists()
    manifest_path = service_harness.closed_manifest_path(old_generation)
    manifest = load_raw_manifest(manifest_path).manifest
    assert manifest.close_reason is CloseReason.ROTATE_SIZE
    assert_manifest_matches_data(
        manifest, service_harness.closed_data_path(old_generation)
    )
    assert service_harness.final_barrier_completed_for(old_generation)

    second = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert service_harness.generation_id_for(second.record_identity) != old_generation
    assert service.status().lifecycle is WriterLifecycle.ACCEPTING


@pytest.mark.asyncio
async def test_control_association_freezes_exact_pre_rotation_target(service_harness) -> None:
    service = await service_harness.open(config_generation=7)
    target = await service_harness.current_target(Market.SPOT, "BTC-USDT", "trade")
    accepted = service.try_accept(
        validated_control_draft(
            control_kind="gap_detected", control_event_id="gap:1",
            affected_markets=[Market.SPOT],
            target_logical_identities=[target.logical_identity],
        ),
        source=SourceContext.internal(), shard="_control",
    )
    association = service_harness.association_for(accepted.record_identity)
    assert association == StorageControlAssociationV1(
        control_kind="gap_detected",
        control_event_id="gap:1",
        targets=(StorageControlTargetV1(
            generation_id=target.generation_id,
            data_relative_path=target.data_relative_path,
        ),),
        acceptance_ordinal=accepted.record_identity.acceptance_ordinal,
        config_generation=7,
    )
    manifests = await service.rotate_due_files()
    assert manifest_for_generation(manifests, target.generation_id).control_event_ids == (
        "gap:1",
    )


@pytest.mark.asyncio
async def test_target_manifest_waits_for_associated_control_durability(
    service_harness,
) -> None:
    service, sync = await service_harness.open_with_blocked_sync()
    target = await service_harness.current_target(Market.SPOT, "BTC-USDT", "trade")
    control = service.try_accept(
        validated_control_draft(
            control_event_id="gap:durability",
            target_logical_identities=[target.logical_identity],
        ),
        source=SourceContext.internal(),
        shard="_control",
    )
    service_harness.mark_due(target.generation_id)
    rotation = asyncio.create_task(service.rotate_due_files())
    submitted = await sync.wait_for_group_containing(control.record_identity)
    assert target.generation_id in submitted.generation_ids
    assert not service_harness.manifest_path(target.generation_id).exists()
    sync.release_all()
    manifests = await rotation
    assert control.record_identity in service_harness.durable_identities
    assert manifest_for_generation(manifests, target.generation_id).control_event_ids == (
        "gap:durability",
    )


@pytest.mark.asyncio
async def test_control_overflow_creates_no_identity_or_association(
    service_harness,
) -> None:
    service = await service_harness.open_with_control_reserve_full()
    before = service_harness.association_count
    rejected = service.try_accept(
        validated_control_draft(control_event_id="gap:overflow"),
        source=SourceContext.internal(), shard="_control",
    )
    assert rejected.status is EnqueueStatus.CONTROL_OVERFLOW
    assert rejected.record is rejected.record_identity is None
    assert service_harness.association_count == before


@pytest.mark.asyncio
async def test_config_rotation_closes_gate_before_its_first_await(service_harness) -> None:
    service = await service_harness.open(block_config_close=True)
    rotation = asyncio.create_task(
        service.rotate_for_config("b" * 64, config_generation=1)
    )
    await service_harness.wait_for_admission_closed()
    rejected = service.try_accept(trade_draft(), source=websocket_source(), shard="trade-0")
    assert rejected.status is EnqueueStatus.NOT_ACCEPTING
    service_harness.release_config_close()
    await rotation


@pytest.mark.asyncio
async def test_startup_recovery_controls_are_durable_before_admission(open_harness) -> None:
    pending = pending_recovery_control()
    recovery = FakeRecovery(reconciliation=RecoveryReconciliation(
        completed_outcomes=(), pending_controls=(pending,)
    ))
    sync = BlockingSync()
    opening = asyncio.create_task(open_harness.open(recovery_backend=recovery,
                                                    sync_backend=sync))
    control = await sync.wait_for_control_record("recovery_reconciled")
    assert control.market is None
    assert control.logical_stream == "_control"
    assert not opening.done()
    sync.release_all()
    service = await opening
    assert service.status().lifecycle is WriterLifecycle.ACCEPTING
    snapshot = service.metrics_snapshot()
    assert (
        snapshot.accepted_record_count,
        snapshot.durable_record_count,
        snapshot.durability_sample_count,
    ) == (1, 1, 1)
    assert [(item.market, item.logical_stream, item.sample_count)
            for item in snapshot.durability_histogram_series] == [(None, "_control", 1)]


@pytest.mark.parametrize(
    ("failure_boundary", "expected_durable", "expected_uncertain"),
    [
        ("owned_control_before_raw_sync_confirmation", 0, 1),
        ("control_durable_publish", 1, 0),
        ("complete_publish", 1, 0),
    ],
)
@pytest.mark.asyncio
async def test_startup_control_failure_boundary_preserves_exact_durability_stage(
    tmp_path, failure_boundary, expected_durable, expected_uncertain
) -> None:
    async with production_startup_control_harness(tmp_path) as harness:
        await harness.seed_one_pending_recovery_control()
        harness.fail_once_at(failure_boundary, OSError(errno.EIO, "injected"))
        with pytest.raises(WriterCriticalError) as captured:
            await harness.open()
        snapshot = harness.terminal_snapshot

    assert captured.value.reason is WriterCriticalReason.CONTROL_DURABILITY_FAILED
    assert captured.value.affected_generation_ids == (
        harness.startup_control_generation_id,
    )
    assert snapshot.lifecycle is WriterLifecycle.CRITICAL
    assert snapshot.accepted_record_count == 1
    assert snapshot.durable_record_count == expected_durable
    assert snapshot.durability_sample_count == expected_durable
    assert snapshot.uncertain_record_count == expected_uncertain
    assert snapshot.unpersisted_record_count == 0
    assert harness.lock_released_only_after_accounting_and_owned_io


@pytest.mark.asyncio
async def test_pending_recovery_target_becomes_association_only_after_live_admission(
    open_harness,
) -> None:
    target = recovered_storage_target()
    pending = pending_recovery_control(target=target)
    assert pending.target == target
    assert not hasattr(pending, "association")
    recovery = BlockingOwnershipRecovery(pending)
    opening = asyncio.create_task(open_harness.open(recovery_backend=recovery))
    admission = await recovery.wait_for_control_ownership()
    assert admission.association.targets == (target,)
    assert admission.association.acceptance_ordinal == (
        admission.control_record_identity.acceptance_ordinal
    )
    assert admission.association.config_generation == (
        admission.control_record_identity.config_generation
    )
    recovery.release_ownership()
    await opening


@pytest.mark.asyncio
async def test_completed_recovery_outcomes_are_not_reemitted(open_harness) -> None:
    completed = recovered_prefix_outcome()
    recovery = FakeRecovery(reconciliation=RecoveryReconciliation(
        completed_outcomes=(completed,), pending_controls=()
    ))
    sync = RecordingSync()
    service = await open_harness.open(recovery_backend=recovery, sync_backend=sync)
    assert sync.control_record_count == 0
    assert recovery.acknowledgement_count == 0
    assert open_harness.completed_recovery_outcomes == (completed,)
    assert service.status().lifecycle is WriterLifecycle.ACCEPTING
    snapshot = service.metrics_snapshot()
    assert (
        snapshot.accepted_record_count,
        snapshot.durable_record_count,
        snapshot.durability_sample_count,
    ) == (0, 0, 0)
    assert snapshot.durability_histogram_series == ()


@pytest.mark.asyncio
async def test_service_loop_periodically_flushes_without_a_lifecycle_call(
    service_harness, fake_clock, fake_sleeper
) -> None:
    sync = RecordingSync()
    service = await service_harness.open(clock=fake_clock, sleeper=fake_sleeper,
                                         sync_backend=sync)
    accepted = service.try_accept(trade_draft(), source=websocket_source(), shard="trade-0")
    assert accepted.accepted
    fake_clock.advance_ns(service_harness.flush_interval_ns)
    await fake_sleeper.wake_due()
    await sync.wait_for_calls(1)
    await service.sync_now()
    assert service.status().durable_record_count == 1


@pytest.mark.asyncio
async def test_periodic_completion_needs_no_final_barrier_command(
    service_harness, fake_clock, fake_sleeper
) -> None:
    sync = RecordingSync()
    service = await service_harness.open(
        clock=fake_clock, sleeper=fake_sleeper, sync_backend=sync
    )
    accepted = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    generation_id = service_harness.generation_id_for(accepted.record_identity)
    fake_clock.advance_ns(service_harness.flush_interval_ns)
    await fake_sleeper.wake_due()
    await service_harness.wait_for_completion_applied(generation_id)
    assert service_harness.final_barrier_command_count == 0
    assert service.status().lifecycle is WriterLifecycle.ACCEPTING
    assert service.metrics_snapshot().durable_record_count == 1


@pytest.mark.asyncio
async def test_service_applies_each_file_completion_before_batch_finishes(
    service_harness,
) -> None:
    sync = OneFastOneBlockingSync()
    service = await service_harness.open(sync_backend=sync)
    first, second = service_harness.accept_rows_for_two_generations(service)
    flushing = asyncio.create_task(service.sync_now())
    await sync.fast_file_completed()
    await service_harness.wait_for_completion_applied(first.generation_id)
    snapshot = service.metrics_snapshot()
    assert snapshot.durable_record_count == 1
    assert snapshot.durability_sample_count == 1
    assert snapshot.in_flight_records == 1
    assert not service_harness.has_inflight_claim(first.generation_id)
    assert service_harness.has_inflight_claim(second.generation_id)
    assert not flushing.done()
    sync.release_blocked()
    await flushing
    assert service.metrics_snapshot().durable_record_count == 2


@pytest.mark.asyncio
async def test_slo_transition_uses_rolling_max_and_recovers_on_exact_expiry(
    service_harness, fake_clock, fake_sleeper
) -> None:
    transitions: list[DurabilitySloTransition] = []
    service = await service_harness.open(
        clock=fake_clock,
        sleeper=fake_sleeper,
        writer_config=service_harness.writer_config(durability_slo_ns=1_000_000_000),
        on_slo_transition=transitions.append,
    )
    await service_harness.persist_rows_with_lags(
        service,
        lags_ns=[1_000_000_001] + [1] * 100,
        sync_completed_monotonic_ns=10_999_999_999,
    )
    assert [item.state for item in transitions] == [DurabilitySloState.BREACHED]
    assert transitions[0].rolling_max_ns == 1_000_000_001
    assert transitions[0].rolling_p99_ns == 1

    fake_clock.set_monotonic_ns(70_000_000_000)
    await fake_sleeper.wake_due()
    await service_harness.wait_for_slo_state(DurabilitySloState.RECOVERED)
    assert [item.state for item in transitions] == [
        DurabilitySloState.BREACHED,
        DurabilitySloState.RECOVERED,
    ]
    assert transitions[-1].rolling_max_ns is None
    assert transitions[-1].rolling_p99_ns is None


@pytest.mark.asyncio
async def test_slo_callback_failure_has_explicit_critical_reason_and_keeps_sync_durable(
    service_harness, fake_clock
) -> None:
    def fail_transition(_transition: DurabilitySloTransition) -> None:
        raise RuntimeError("control admission failed")

    sync = FakeSync(clock=fake_clock, advance_ns=1_000_000_001)
    service = await service_harness.open(
        clock=fake_clock,
        sync_backend=sync,
        writer_config=service_harness.writer_config(durability_slo_ns=1_000_000_000),
        on_slo_transition=fail_transition,
    )
    assert service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    ).accepted
    with pytest.raises(WriterCriticalError) as captured:
        await service.sync_now()
    assert captured.value.reason is WriterCriticalReason.SLO_TRANSITION_CALLBACK_FAILED
    assert isinstance(captured.value.__cause__, RuntimeError)
    snapshot = service.metrics_snapshot()
    assert snapshot.accepted_record_count == snapshot.durable_record_count == 1
    assert snapshot.uncertain_record_count == 0
    assert snapshot.slo_breach_count == 1


@pytest.mark.asyncio
async def test_public_metrics_snapshot_is_frozen_consistent_and_exported(
    service_harness,
) -> None:
    from crypto_collector.storage import DurabilityHistogramSeriesV1 as PublicSeries
    from crypto_collector.storage import RawWriterService as PublicRawWriterService
    from crypto_collector.storage import RecoveryBlocked as PublicRecoveryBlocked
    from crypto_collector.storage import WriterAffinityError as PublicAffinityError
    from crypto_collector.storage import WriterCriticalError as PublicCriticalError
    from crypto_collector.storage import WriterMetricsSnapshotV1 as PublicSnapshot

    service = await service_harness.open()
    snapshot = service.metrics_snapshot()
    assert isinstance(snapshot, WriterMetricsSnapshotV1)
    assert snapshot.unpersisted_record_count == (
        snapshot.queued_records + snapshot.buffered_records + snapshot.in_flight_records
    )
    assert snapshot.resident_record_bytes == (
        snapshot.queued_bytes + snapshot.buffered_bytes + snapshot.in_flight_bytes
    )
    assert sum(snapshot.durability_bucket_counts) == snapshot.durability_sample_count
    assert sum(item.sample_count for item in snapshot.durability_histogram_series) == (
        snapshot.durability_sample_count
    )
    assert tuple(
        sum(item.bucket_counts[index] for item in snapshot.durability_histogram_series)
        for index in range(len(DURABILITY_BUCKET_UPPER_BOUNDS_NS))
    ) == snapshot.durability_bucket_counts
    with pytest.raises(ValidationError):
        snapshot.accepted_record_count = 0
    assert PublicSnapshot is WriterMetricsSnapshotV1
    assert PublicSeries is DurabilityHistogramSeriesV1
    assert PublicRawWriterService is RawWriterService
    assert PublicRecoveryBlocked is RecoveryBlocked
    assert PublicAffinityError is WriterAffinityError
    assert PublicCriticalError is WriterCriticalError


@pytest.mark.asyncio
async def test_metrics_snapshot_is_nonblocking_immutable_cache_getter(
    service_harness,
) -> None:
    service = await service_harness.open()
    before = service.metrics_snapshot()
    assert service.metrics_snapshot() is before

    accepted = service.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert accepted.accepted
    refreshed = service.metrics_snapshot()
    assert refreshed is not before
    assert refreshed.observed_monotonic_ns > before.observed_monotonic_ns
    assert refreshed.accepted_record_count == before.accepted_record_count + 1
    assert service.metrics_snapshot() is refreshed


@pytest.mark.asyncio
async def test_metrics_snapshot_rejects_foreign_thread(service) -> None:
    with pytest.raises(WriterAffinityError):
        await asyncio.to_thread(service.metrics_snapshot)


def test_metrics_snapshot_rejects_same_thread_different_event_loop(
    service_harness,
) -> None:
    owner_loop = asyncio.new_event_loop()
    foreign_loop = asyncio.new_event_loop()
    try:
        service = owner_loop.run_until_complete(
            service_harness.open_for_explicit_loop_test()
        )

        async def read_from_foreign_loop() -> None:
            service.metrics_snapshot()

        with pytest.raises(WriterAffinityError):
            foreign_loop.run_until_complete(read_from_foreign_loop())
    finally:
        owner_loop.run_until_complete(service_harness.close_explicit_loop_test())
        foreign_loop.close()
        owner_loop.close()


@pytest.mark.asyncio
async def test_public_histogram_is_lifetime_cumulative_across_part_retirement(
    service_harness,
) -> None:
    service = await service_harness.open(sync_backend=RecordingSync())
    service_harness.accept_one(service)
    await service.sync_now()
    before = service.metrics_snapshot()
    await service_harness.retire_and_publish_current_part(service)
    service_harness.accept_one(service)
    await service.sync_now()
    after = service.metrics_snapshot()

    assert before.durability_sample_count == before.durable_record_count == 1
    assert after.durability_sample_count == after.durable_record_count == 2
    assert all(
        later >= earlier
        for earlier, later in zip(
            before.durability_bucket_counts,
            after.durability_bucket_counts,
            strict=True,
        )
    )
    assert sum(after.durability_bucket_counts) == 2


@pytest.mark.asyncio
async def test_public_histogram_series_are_bounded_without_instrument_labels(
    service_harness,
) -> None:
    service = await service_harness.open(
        sync_backend=RecordingSync(), metric_stream_allowlist=("trade",)
    )
    for index in range(1_000):
        accepted = service.try_accept(
            trade_draft(
                logical_stream=f"extension-{index}",
                instrument_key=f"COIN-{index}-USDT",
            ),
            source=websocket_source(),
            shard=f"extension-{index}",
        )
        assert accepted.accepted
    await service.sync_now()
    snapshot = service.metrics_snapshot()
    assert {item.logical_stream for item in snapshot.durability_histogram_series} == {
        OTHER_DURABILITY_METRIC_STREAM_LABEL
    }
    assert all("instrument" not in item.model_fields for item in snapshot.durability_histogram_series)
    assert len(snapshot.durability_histogram_series) <= (
        (len(Market) + 1) * (MAX_DURABILITY_METRIC_STREAM_LABELS + 1)
    )


@pytest.mark.parametrize("allowlist", [
    ("",),
    (OTHER_DURABILITY_METRIC_STREAM_LABEL,),
    ("trade", "trade"),
    ("trade", "book_live"),
    tuple(
        f"extension-{index:03d}"
        for index in range(MAX_DURABILITY_METRIC_STREAM_LABELS + 1)
    ),
])
@pytest.mark.asyncio
async def test_open_rejects_invalid_metric_stream_allowlist_before_storage_mutation(
    service_harness, allowlist
) -> None:
    with pytest.raises(ValueError, match="metric_stream_allowlist"):
        await service_harness.open(metric_stream_allowlist=allowlist)
    assert service_harness.storage_mutation_count == 0
    assert not service_harness.writer_lock_exists


@pytest.mark.asyncio
async def test_oversized_row_waits_as_generation_bound_work_without_fd_overlap(
    service_harness, fake_clock, fake_sleeper
) -> None:
    sync = PerGenerationBlockingSync()
    service = await service_harness.open(
        clock=fake_clock,
        sleeper=fake_sleeper,
        sync_backend=sync,
        writer_config=test_writer_config(max_plain_frame_bytes=1024),
    )
    first = service.try_accept(
        small_trade_draft(), source=websocket_source(), shard="trade-0"
    )
    fake_clock.advance_ns(service_harness.flush_interval_ns)
    await fake_sleeper.wake_due()
    first_work = await service_harness.wait_for_submitted_work()
    oversized = service.try_accept(
        oversized_trade_draft(encoded_payload_bytes=1025),
        source=websocket_source(), shard="trade-0",
    )
    await service_harness.wait_for_generation_buffered(first_work.generation_id)
    assert first.accepted and oversized.accepted
    assert sync.max_active_for(first_work.generation_id) == 1
    sync.release(first_work.generation_id)
    direct_work = await service_harness.wait_for_submitted_work(call_index=2)
    assert direct_work.generation_id == first_work.generation_id
    assert direct_work.pending is not None
    assert len(direct_work.pending.rows) == 1
    assert direct_work.pending.plain_bytes > 1024
    assert sync.max_active_for(first_work.generation_id) == 1
    sync.release(direct_work.generation_id)
    await service.sync_now()
    assert service.status().durable_record_count == 2


@pytest.mark.asyncio
async def test_blocked_sync_keeps_buffered_and_inflight_bytes_charged_and_reserve_free(
    service_harness,
) -> None:
    service, sync = await service_harness.open_with_blocked_sync_and_small_budget()
    await service_harness.fill_normal_records_across_queued_buffered_and_inflight()
    snapshot = service.metrics_snapshot()
    assert snapshot.resident_record_bytes == (
        snapshot.queued_bytes + snapshot.buffered_bytes + snapshot.in_flight_bytes
    )
    assert service.try_accept(
        market_draft(), source=websocket_source(), shard="trade-0"
    ).status is EnqueueStatus.OVERFLOW
    control = service.try_accept(
        validated_control_draft(), source=SourceContext.internal(), shard="_control"
    )
    assert control.accepted
    sync.release_all()
    await service.sync_now()
    assert service.metrics_snapshot().resident_record_bytes == 0


@pytest.mark.parametrize("reason", [
    WriterCriticalReason.OLDEST_UNPERSISTED_AGE,
    WriterCriticalReason.WRITE_FAILED,
    WriterCriticalReason.SYNC_FAILED,
    WriterCriticalReason.PUBLICATION_FAILED,
    WriterCriticalReason.CONTROL_DURABILITY_FAILED,
    WriterCriticalReason.SLO_TRANSITION_CALLBACK_FAILED,
    WriterCriticalReason.CLOSE_DEADLINE,
    WriterCriticalReason.MARKED_INCOMPLETE,
])
@pytest.mark.asyncio
async def test_terminal_critical_accounts_every_stage_before_resource_release(
    service_harness, reason
) -> None:
    service = await service_harness.seed_queued_buffered_and_inflight_then_fail(reason)
    await service_harness.wait_for_terminal_critical_accounting()
    status = service.status()
    assert status.lifecycle is WriterLifecycle.CRITICAL
    assert status.queued_records == status.buffered_records == 0
    assert status.in_flight_records == status.unpersisted_record_count == 0
    assert status.accepted_record_count == (
        status.durable_record_count + status.uncertain_record_count
    )
    assert service_harness.accepted_identities == (
        service_harness.durable_identities | service_harness.uncertain_identities
    )
    assert not (service_harness.durable_identities & service_harness.uncertain_identities)
    assert service_harness.lock_released_only_after_accounting


@pytest.mark.asyncio
async def test_service_watchdog_keeps_original_acceptance_age_through_sync(
    service_harness, fake_clock, fake_sleeper
) -> None:
    sync = BlockingSync()
    service = await service_harness.open(clock=fake_clock, sleeper=fake_sleeper,
                                         sync_backend=sync)
    accepted = service.try_accept(trade_draft(), source=websocket_source(), shard="trade-0")
    assert accepted.accepted
    assert service.status().oldest_unpersisted_age_ns == 0
    fake_clock.advance_ns(service_harness.durability_critical_ns + 1)
    await fake_sleeper.wake_due()
    await sync.wait_until_started(1)
    await service_harness.wait_for_critical("oldest_unpersisted_age")
    assert service.status().lifecycle is WriterLifecycle.CRITICAL
    sync.release_all()
    await service_harness.wait_for_owned_io()
```

`production_recovery_harness` is a test-only async resource factory. It constructs the
exact `RecoveryContext` above with the test roots, typed exchange, default production
recovery backend, one bounded executor, one worker-global `StorageIoLimiter`, and one
separate `RecoveryDurabilityCoordinator(UNMEASURED)` using them. It never constructs a
live ledger/stats coordinator. Its exit waits for recovery work and shuts down the
executor. The harness itself performs no scanning, mutation, sync, publication, or
cleanup. Filesystem reconciliation is driven only by awaited
`RecoveryBackend.reconcile(context)` calls; the test-only `drive_pending_controls`
uses the real live service-loop primitive and then calls
`acknowledge_control_durable(...)` for each exact receipt. Completed outcomes are only
merged into the returned result and are never submitted to the live writer. Do not
expose or implement mutating `recover_partial(...)` or
`recover_exchange_root(...)` shortcuts.

- [ ] **Step 2: Run and verify recovery is missing**

Run: `.venv/bin/python -m pytest tests/integration/storage/test_recovery.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement streaming frame validation**

Add the one public storage decoder beside `encode_envelope`:

```python
_ENUM_TYPES = {
    "exchange": Exchange,
    "market": Market,
    "transport": Transport,
    "integrity_mode": IntegrityMode,
    "coverage": CoverageMode,
}


def decode_envelope_jsonl(line: bytes) -> RawEnvelope:
    if not line.endswith(b"\n"):
        raise ValueError("raw envelope line must end with newline")
    wire = decode_json(line[:-1])
    if type(wire) is not dict:
        raise ValueError("raw envelope line must contain one JSON object")
    for field, enum_type in _ENUM_TYPES.items():
        if wire.get(field) is not None:
            wire[field] = enum_type(wire[field])
    return RawEnvelope.model_validate(wire)
```

Walk zstd frame boundaries without accepting decoder output after the first
corrupt/truncated frame. The crash helper writes full valid `RawEnvelope` rows; no
recovery test may substitute a minimal `{"writer_sequence": ...}` object that
production validation would reject. For a `.partial` only, copy a nonempty valid prefix
into a new recovery generation, close it through the normal
group-sync/no-replace protocol, and publish a strictly positive bad tail at
`data/quarantine/<relative-source>.bad-tail` without overwriting an existing artifact.
An empty/unreadable partial instead moves its complete bytes to quarantine and creates
no data or manifest. Validate a closed orphan as one indivisible file: retain it and
create its missing manifest only if every byte validates, otherwise quarantine the
whole file without prefix salvage or planned data/manifest. Before publishing the
retained manifest, fsync the verified orphan's data parent. `manifest_path_for_data()`
requires the full `.jsonl.zst` suffix
and replaces it with `.manifest.json`; never use `Path.with_suffix()` one suffix at a
time.

Each reconciliation uses the amended immutable transaction/lineage fields and holds
an exclusive source lease before changing a closed identity. Reconcile manifest
temporaries, closed data without a manifest, validated cleanup-removed data, and
unexplained missing data under the writer lock. Preserve legitimate Plan 07 cleanup
manifests, and preserve plus block on unexplained missing data; neither case is
quarantined. Recovery distinguishes unknowable from schema-inapplicable nulls exactly
as amended; it never invents compression or durability values.

Implement `SourceLease` in `lease.py`; extend `manifest.py` with
`RawManifestReader`, `validate_local_source`, the two public path helpers, and
`SourceDispositionResolver` exactly as amended. Materializer, archiver, and restore
use `LOCK_SH`; cleanup and recovery mutation use `LOCK_EX`, then revalidate facts and
files. The subprocess helper exposes test-only phase hooks through an injected
callback, never an environment-controlled production backdoor. Implement the complete
allocation tests in a real child process: the child reports the exact create/parent-sync
phase over a pipe and is then sent `SIGKILL`; no mocked `fsync`, in-process exception,
or `write_bytes` fixture substitutes for either boundary. Implement the complete
intent/stage-fact replay protocol above, including deterministic control event IDs and
existing-output hash reconciliation. Every outcome carries its transaction ID, but
only each item in `RecoveryReconciliation.pending_controls` becomes one reserved
recovery control record. Items in `completed_outcomes` already have a durable complete
fact and must never be re-emitted.
`production_recovery_harness.drive_pending_controls` is only a test driver: it starts
the same live service-loop primitive, accepts each pending row, durably binds its exact
ownership before carrier I/O, constructs an actual receipt, invokes
`acknowledge_control_durable`, and combines those outcomes with
`completed_outcomes`. It is not an alternate production sink or public recovery API.
`RecoveryBackend.reconcile(RecoveryContext)` and
`bind_control_ownership(...)` and `acknowledge_control_durable(...)` are the only
recovery APIs that may mutate, sync,
publish, quarantine, settle a source, or publish journal facts. Internal frame scanners
and transaction planners are pure: they return validated facts/byte ranges and cannot
accept roots or perform I/O publication on their own.

Implement the singular worker-facing `RawWriterService` declaration in the
authoritative amendment in `storage.service`; runtime must not assemble
lock/recovery/ingress/writer pieces itself. Do not redeclare a compatible-looking
service class in this task.

`open` acquires the typed `ExchangeWriterLock`, constructs the one bounded executor and
worker-global `StorageIoLimiter`, then constructs the separate unmeasured recovery
coordinator and live coordinator sharing that limiter. It passes only the recovery
coordinator into journal replay/source scanning and never opens admission. Recovery
destination sequences are frozen in synced
intents. After reconciliation it starts the one service loop in `STARTING`, submits
every returned pending control to the reserved control shard, constructs its optional
association only from the successful live identity and pending target, reserves a
dedicated one-row carrier without filesystem mutation, and durably binds that exact
admission through `control-ownership.json`. Only then may it allocate/write/sync/close
the carrier, wait for its exact live durability watermark, and pass the resulting
receipt back to the backend for control/complete fact publication. Startup first
reserves and finishes any carrier already named by an ownership fact inside its original
transaction; the unbound-source scan cannot create a transaction for it. The service
transitions to `ACCEPTING` and returns only when
all transactions are complete. An error before any recovery control is accepted closes
all owned resources, creates no new market part, and raises `RecoveryBlocked`. Once a
recovery control is accepted, an admission/sync/receipt/journal failure instead closes
all owned resources and raises `WriterCriticalError` with
`CONTROL_DURABILITY_FAILED`, the exact control generation, and every completed live
batch; it is never relabeled `RecoveryBlocked`. In either case the writer lock is
released only after executor work ends. `try_accept` is the sole
public record-input method, rejects a draft for another exchange, and registers every
accepted queue record in the service ledger before return. There is no public
`writer.put`, alternate sink, raw lock file descriptor, coordinator loop, or separate
runtime close protocol.

The startup failure-boundary integration test uses the production service loop,
coordinator, ledger, and recovery backend: an injected write/sync failure before raw
sync confirmation makes the accepted control `UNCERTAIN`, while an injected
`control-durable.json` or `complete.json` publication failure after confirmed raw sync
leaves it `DURABLE`. All three paths raise
`CONTROL_DURABILITY_FAILED`, drain owned I/O, and assert the terminal snapshot rather
than mutating test counters directly.

The service loop alone performs fair ingress draining, frame-cap sealing, periodic
flush/watchdog checks through `AsyncSleeper`, rotation commands, and lifecycle
transitions. `sync_now`, rotations, `mark_incomplete`, and `close_all` enqueue private
watermarked commands; they do not race direct mutation from caller tasks. Tests cover
periodic flush without a lifecycle call, queue-stage critical age, admission closure
without sequence consumption, cross-exchange rejection, generation-bound oversized
work without FD overlap, cancellation ownership, and idempotent close. Every
coordinator submission supplies exactly one `DurabilityTrigger`: periodic timer,
size/frame cap, UTC hour, config, recovery, shutdown, or explicit barrier.

`deadline_ns` is an absolute `clock.monotonic_ns()` deadline. Reaching it closes
admission and marks any not-yet-durable part incomplete, but does not release the lock,
close an FD still used by an executor job, or abandon reconciliation. The close task
continues to own those jobs to terminal accounting; its result is the immutable tuple
of complete manifests only, with incomplete identities reported through status and
recovery evidence.

`rotate_for_config(new_sha, config_generation=new_generation)` is an atomic service
operation invoked only after runtime has stopped the affected producers. It requires
`new_generation > current_generation`, closes the admission gate, drains and durably
closes every old-config part with `CloseReason.CONFIG_RELOAD`, replaces the owned
immutable `RawIngress` with a new instance carrying both new values, transfers the
per-stream next-sequence ledger without incrementing it, and reopens admission. On any
drain/sync/close error, do not install the new ingress; mark the service
incomplete/critical. Thus no accepted record can carry the old hash after rotation
returns, no file mixes hashes, and immutability of an individual ingress is preserved.

- [ ] **Step 4: Run recovery and full storage tests**

Run: `.venv/bin/python -m pytest tests/unit/storage tests/integration/storage -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/storage/__init__.py src/crypto_collector/storage/serialize.py src/crypto_collector/storage/manifest.py src/crypto_collector/storage/recovery.py src/crypto_collector/storage/lease.py src/crypto_collector/storage/service.py tests/helpers/writer_crash_child.py tests/unit/storage/test_lease.py tests/integration/storage
git commit -m "feat: reconcile crashed raw parts"
```

### Task 7: Durability Performance Gate

> **Superseded on 2026-08-02:** Do not execute the legacy Task 7 steps below. The
> authoritative approved design is
> `docs/superpowers/specs/2026-08-02-writer-gate-b-auditable-evidence-design.md`, and
> the executable replacement plan is
> `docs/superpowers/plans/2026-08-02-writer-gate-b-auditable-evidence.md`. The legacy
> text remains only as historical context; where it conflicts, the 2026-08-02 design
> and plan control.

**Files:**
- Create: `src/crypto_collector/benchmarks/__init__.py`
- Create: `src/crypto_collector/benchmarks/writer.py`
- Create: `benchmarks/workloads/research-default-v1.yaml`
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `tests/performance/test_writer_durability.py`
- Create: `docs/operations/writer-benchmark.md`

- [ ] **Step 1: Write the report-validation test**

```python
def test_benchmark_fails_any_record_over_slo() -> None:
    report = replace(passing_report(), durability_lag_max_ns=1_000_000_001)
    assert report.qualification_accepted is False


def test_benchmark_rejects_underdriven_or_unhealthy_storage() -> None:
    report = passing_report()
    underdriven = replace_stream(
        report, "trade",
        attempted_record_count=report.stream("trade").expected_min_record_count - 1,
    )
    assert underdriven.qualification_accepted is False
    underdriven_bytes = replace_stream(
        report, "book_live",
        attempted_byte_count=report.stream("book_live").expected_min_byte_count - 1,
    )
    assert underdriven_bytes.qualification_accepted is False
    assert replace(report, accepted_record_count=
                   report.attempted_record_count - 1).qualification_accepted is False
    assert replace(report, active_logical_generation_peak=
                   report.expected_active_file_count - 1).qualification_accepted is False
    assert replace(report, overflow_count=1).qualification_accepted is False
    assert replace(report, manifest_validation_error_count=1).qualification_accepted is False
    assert replace(report, storage_health_error_count=1).qualification_accepted is False
    assert replace(report, storage_health_sample_count=
                   report.expected_min_storage_health_samples - 1).qualification_accepted is False
    assert replace(report, storage_health_sample_max_gap_ns=
                   report.storage_health_max_allowed_gap_ns + 1).qualification_accepted is False
    assert replace(report, storage_health_coverage_ns=
                   report.duration_ns - 2 * report.storage_health_sample_interval_ns - 1
                   ).qualification_accepted is False
    assert replace(report, runtime_image_id="sha256:" + "b" * 64).qualification_accepted is False
    assert replace(report, runtime_image_id="not-a-digest").qualification_accepted is False
    assert replace(report, target_declaration_valid=False).qualification_accepted is False
    assert replace(report, state_root_probe_matches=False).qualification_accepted is False
    assert replace(report, late_admission_count=1).qualification_accepted is False
    assert replace(report, out_of_window_count=1).qualification_accepted is False
    assert replace(report, per_second_bucket_sha256="b" * 64).qualification_accepted is False
    assert replace(report, collector_wheel_sha256="b" * 64).qualification_accepted is False


def test_validator_recomputes_due_times_rates_bursts_and_bucket_digest(trace_fixture) -> None:
    report = passing_report(admission_trace=trace_fixture)
    assert validate_report(report).qualification_accepted
    for mutation in (
        move_one_due_time(), move_one_admission_to_next_second(),
        remove_one_accepted_identity(), reduce_one_burst_bucket(),
    ):
        assert not validate_report(mutation.apply(report)).qualification_accepted


def test_gate_aggregates_only_each_stable_workers_final_barrier_snapshot() -> None:
    sequences = passing_worker_snapshot_sequences()
    summary = aggregate_final_worker_snapshots(sequences)
    assert summary.accepted_record_count == sum(
        snapshots[-1].accepted_record_count for snapshots in sequences.values()
    )
    assert summary.accepted_record_count != sum(
        snapshot.accepted_record_count
        for snapshots in sequences.values()
        for snapshot in snapshots
    )
    assert summary.durability_bucket_counts == elementwise_sum(
        snapshots[-1].durability_bucket_counts for snapshots in sequences.values()
    )
    assert summary.durability_lag_max_ns == max(
        snapshots[-1].durability_lag_max_ns for snapshots in sequences.values()
    )
    assert summary.durability_lag_p99_ns == nearest_rank_from_buckets(
        summary.durability_bucket_counts, Decimal("0.99")
    )


def test_qualification_rejects_restart_or_nonmonotonic_worker_sequence() -> None:
    report = passing_report()
    assert not validate_report(replace_worker_id_midrun(report)).qualification_accepted
    assert not validate_report(decrease_one_cumulative_bucket(report)).qualification_accepted
    assert not validate_report(remove_one_final_worker_snapshot(report)).qualification_accepted
    assert not validate_report(make_final_worker_nonterminal(report)).qualification_accepted


def test_qualification_requires_exactly_the_five_declared_worker_keys() -> None:
    report = passing_report()
    assert not validate_report(remove_declared_worker_sequence(report)).qualification_accepted
    assert not validate_report(add_sixth_worker_sequence(report)).qualification_accepted
    assert not validate_report(duplicate_exchange_worker_slot(report)).qualification_accepted


@pytest.mark.parametrize("field", [
    "queued_records", "queued_bytes", "buffered_records", "buffered_bytes",
    "in_flight_records", "in_flight_bytes", "resident_record_bytes",
    "resident_control_records", "resident_control_bytes",
    "active_logical_generation_count", "retiring_generation_count",
    "open_file_descriptor_count", "sync_inflight",
])
def test_qualification_rejects_nonzero_final_worker_gauge(field) -> None:
    report = set_one_final_worker_gauge(passing_report(), field, 1)
    assert not validate_report(report).qualification_accepted


def test_qualification_rejects_understated_worker_or_report_maximum() -> None:
    report = passing_report()
    assert not validate_report(
        understate_one_final_worker_maximum(report)
    ).qualification_accepted
    assert not validate_report(
        understate_report_maximum_below_final_workers(report)
    ).qualification_accepted


def test_worker_quantile_decrease_is_not_treated_as_counter_reset() -> None:
    report = lower_quantile_with_monotonic_buckets(passing_report())
    assert validate_report(report).qualification_accepted


def test_gate_allows_identical_cache_reads_but_rejects_same_time_different_state() -> None:
    repeated = repeat_one_worker_cache_snapshot_in_next_round(passing_report())
    assert validate_report(repeated).qualification_accepted
    changed = mutate_repeated_snapshot_without_advancing_observed_time(repeated)
    assert not validate_report(changed).qualification_accepted


def test_short_functional_mode_never_claims_qualification() -> None:
    report = passing_report(duration_ns=10_000_000_000, mode="functional")
    assert report.functional_passed is True
    assert report.qualification_accepted is False
```

- [ ] **Step 2: Run and verify benchmark contracts are missing**

Run: `.venv/bin/python -m pytest tests/performance/test_writer_durability.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement the target-volume load generator**

Commit this concrete baseline workload; changes require a new versioned filename rather than overwriting evidence semantics:

```yaml
schema_version: 1
name: research-default-v1
generation_seed: 20260731
exchange_workers: 5
markets_per_worker: 2
symbols_per_market: 25
fixed_scope_file_count: 5
scalable_file_count: 1750
active_file_count: 1755
streams:
  trade: {instances: 250, mean_records_per_second: "50", burst_records_in_1s: 500, payload_p50_bytes: 600, payload_p95_bytes: 1400, payload_max_bytes: 8192}
  book_live: {instances: 250, mean_records_per_second: "20", burst_records_in_1s: 100, payload_p50_bytes: 8192, payload_p95_bytes: 32768, payload_max_bytes: 262144}
  ticker: {instances: 250, mean_records_per_second: "1", burst_records_in_1s: 5, payload_p50_bytes: 1200, payload_p95_bytes: 2400, payload_max_bytes: 8192}
  bbo: {instances: 250, mean_records_per_second: "10", burst_records_in_1s: 50, payload_p50_bytes: 500, payload_p95_bytes: 1000, payload_max_bytes: 4096}
  derivative: {instrument_instances: 125, file_instances: 250, markets: [perpetual], logical_streams_per_instrument: 2, mean_records_per_second: "2", burst_records_in_1s: 10, payload_p50_bytes: 1400, payload_p95_bytes: 3000, payload_max_bytes: 16384}
  candle_1m: {instances: 250, mean_records_per_second: "0.5", burst_records_in_1s: 2, payload_p50_bytes: 1000, payload_p95_bytes: 2000, payload_max_bytes: 4096}
  book_deep_snapshot: {instances: 250, mean_records_per_second: "0.0334", burst_records_in_1s: 1, payload_p50_bytes: 131072, payload_p95_bytes: 262144, payload_max_bytes: 1048576}
  control: {instances: 5, scope: exchange, mean_records_per_second: "0.1", burst_records_in_1s: 10, payload_p50_bytes: 800, payload_p95_bytes: 2000, payload_max_bytes: 8192}
payload_generation: {decimal_string_fraction: "0.70", repeated_key_fraction: "0.80", incompressible_fraction: "0.20"}
queues:
  shard_max_records: 10000
  shard_max_bytes: 67108864
  worker_max_bytes: 536870912
  control_reserve_records: 1024
  control_reserve_bytes: 8388608
qualification:
  warmup_seconds: 120
  storage_health_sample_interval_seconds: 1
  storage_health_max_gap_seconds: 2
  max_rss_bytes: 4294967296
  max_rss_slope_bytes_per_minute: 2097152
  max_open_fds: 4096
  max_fd_growth_after_warmup: 10
  durability_lag_max_ns: 1000000000
```

The baseline file count is an exact path-identity calculation: six 250-file symbol
streams (`trade`, `book_live`, `ticker`, `bbo`, `candle_1m`,
`book_deep_snapshot`) contribute 1,500 scalable files; 125 perpetual instruments
times two derivative logical streams contribute 250 scalable files; and the
exchange-level `_control` namespace contributes five fixed files. Thus
`fixed_scope_file_count + scalable_file_count == active_file_count == 1,755`.
Event producers or burst lanes do not count as separate files when they share one
storage identity.

The CLI accepts `--workload`, `--multiplier`, `--duration`, `--data-root`,
`--state-root`, `--report`, qualification-only required `--admission-trace`,
required qualification-only `--expected-image-id` and `--target-declaration`, and
explicit `--functional-only`. The same module exposes `declare-target` to write a
canonical `GateTargetV1` on the target Linux host. The container launcher injects the
actually selected immutable ID as `COLLECTOR_RUNTIME_IMAGE_ID`; qualification refuses
a missing/malformed value or a mismatch with `--expected-image-id`. `--data-root`,
`--state-root`, and `--target-declaration` are mandatory for qualification. Functional
mode forbids a target declaration, may omit both roots, and then owns a fresh
`TemporaryDirectory` for the full run/validation lifecycle.
Qualification preflight compares injected monotonic and UTC clocks and refuses to
start unless the current UTC hour has at least `duration_ns + 30_000_000_000` remaining.
It records the admission boundary wall times and fails validation if they cross an
hour; this prevents the 3,505 logical-identity claim from hiding cross-hour retiring
generations or descriptor overlap.
The target directories themselves may contain the declaration/report directory, but
qualification requires every selected exchange's `data_root/raw/<exchange>` and
`state_root/raw-recovery/<exchange>` subtree to be absent. It never deletes or reuses
prior raw/recovery state; the operator must choose fresh roots. Consequently Gate B
requires no startup recovery outcomes and acceptance ordinals start at zero.

Generate envelopes from the committed deterministic seed across exactly the declared
distribution using the production ingress and writer. The module carries a tested
`RESEARCH_DEFAULT_V1_SHA256` constant and refuses qualification when the loaded bytes
do not match it. Build and hash `WorkloadPlanV1` with the exact Decimal/ceil,
due-offset, burst, identity, and canonical payload-byte rules in the amendment. Write
and hash every `GateAdmissionTraceV1` row, derive all `GateSecondBucketV1` rows, and
compute per-stream counts/bytes/rates only from that trace. The
multiplier scales record/byte targets and only the 1,750
instrument files; the five `_control` files remain fixed. Therefore
`expected_active_file_count = 5 + multiplier * 1750`, and multiplier two requires
exactly 3,505 active files. Add deterministic synthetic instruments until that target
is exact. Reject workloads whose stream instances do not reconcile separately to
their fixed/scalable declarations. Every generated control draft is validated before
reserve admission, has `market=None`, and carries affected markets only in its payload;
the five control manifests and paths remain exchange-scoped.
Gate sampling calls only the public `RawWriterService.metrics_snapshot()` and hashes
the canonical sequence of `WriterMetricsSnapshotV1` values; it never reaches into
`coordinator.stats`, a ledger, ingress queues, or recovery accounting internals.
The sequence is partitioned by exact `(exchange, worker_instance_id)`. Within each
worker, external round numbers and request-start times are strictly increasing, while
cached snapshot `observed_monotonic_ns` is nondecreasing. Equal observed times are
legal only for byte-identical repeated cache reads; equal time with different canonical
snapshot bytes is invalid. Cumulative counters, aggregate and per-series bucket/sample
counts, and maxima may not decrease; series keys may only appear, never disappear.
Quantiles are explicitly excluded from the monotonic check.
Qualification binds exactly one initial worker identity for each of the five declared
exchange worker slots and rejects any replacement identity, missing interval, duplicate
identity, config change, or process restart. Functional mode records resets but cannot
turn them into qualification evidence. The sorted expected key tuple and sorted final
key tuple must be identical and contain exactly five distinct
`(exchange, worker_instance_id)` pairs, one for each declared exchange; an extra sixth
sequence is invalid rather than ignored.

Sampling is grouped into numbered rounds. A valid qualification round contains exactly
one snapshot from each bound worker, records its request-start and completion monotonic
times, and stays within the declared sampling-gap bound; missing, duplicate, or
overlapping rounds invalidate evidence. Current gauges such as active/retiring
generations, resident bytes, in-flight records, and open descriptors are summed only
within a round, and the report peak is the maximum round sum. It never sums independent
per-worker peaks that occurred in different rounds.

After admission ends, the benchmark requests each worker's final barrier and
`close_all`, validates every returned manifest, then takes one final snapshot with
`lifecycle=CLOSED`, `admission_state=CLOSED`, `sync_inflight=0`,
`unpersisted_record_count=0`, `uncertain_record_count=0`, and
`accepted_record_count == durable_record_count == durability_sample_count`. It also
requires `publication_state=IDLE`, `oldest_unpersisted_age_ns=None`, and every queued,
buffered, in-flight, resident record/control, active-generation, retiring-generation,
and open-file-descriptor gauge/byte count to be zero. Only that
terminal snapshot from each stable worker contributes cumulative counts or buckets to
the report. Earlier samples are used only for monotonic validation and gauge peaks; they
are never summed. Cross-worker counts are sums of the five final values, bucket vectors
are summed elementwise, and the report's exact `durability_lag_max_ns` is the maximum of
the five final cumulative worker maxima. Every final maximum is non-null when that
worker has samples. Global p50/p95/p99 are recomputed from the resulting bucket vector
rather than summing or averaging worker quantiles. The final accepted/durable totals
must independently equal the admission trace and decoded manifest rows.

Record `mode`, deterministic seed/workload/workload-plan SHAs, admission-trace,
worker-snapshot-sequence and per-second-bucket SHAs; the sorted expected/final
`(exchange, worker_instance_id)` sets, restart count, sequence-valid flag, and
final-barrier-valid flag; target declaration identity/hash and separate data/state probe
results; `functional_passed`, and `qualification_accepted`;
run/admission start, scheduled end, actual admission end, and run end monotonic times;
their corresponding UTC wall times and same-hour result; exact source commit, wheel,
lock, workload, and Dockerfile hashes;
expected/attempted/
accepted/durable records and bytes per stream; durability sample and manifest record
counts; exact accepted record identities; measured logical-active, retiring, and open
FD peaks; early/late/out-of-window counts and recomputed admitted rates/burst maxima;
every loss/overflow/conformance/manifest/write/
sync/storage-health error count; storage-health sample interval/count/coverage/max
gap; CPU model/count, memory, runtime/expected image IDs, OS, both roots' storage
devices, filesystems, mount points/options, free bytes and capability probes;
compressed bytes, sync calls/IOPS/durations, resident/stage queue
high-water marks, RSS/FD samples and slopes, and durability p50/p95/p99/max. For a run
of duration `D` and configured interval `I`, compute
`expected_min_storage_health_samples = max(2, ceil(D / I) - 1)` and require coverage
through at least `D - 2I`; a burst of samples at startup cannot qualify the run.
The report validator streams the trace and recomputes schedule/duration/rate/burst,
bucket digest, exact identity uniqueness, per-stream rows, stable worker identities,
per-worker monotonicity, final-barrier state, final-only aggregate counts/buckets, and
the exact maximum from the five final worker snapshots. It recomputes p50/p95/p99 from
the aggregate buckets and then recomputes `qualification_accepted`; serialized summary
booleans or totals that disagree with those primary facts invalidate the report.

Functional mode exits zero only when schema/workload/cardinality/schedule
reconciliation succeeds, exact per-stream planned values are met, attempted, accepted,
durable, sampled, and
manifest record counts are equal, every loss/overflow/conformance/manifest/write/
sync/storage-health error count is zero, and generated manifests validate. It always
writes `qualification_accepted=false`. Qualification mode exits nonzero unless all
conditions hold:

```python
qualification_accepted = (
    mode == "qualification"
    and functional_passed
    and workload_schema_valid
    and workload_sha256 == RESEARCH_DEFAULT_V1_SHA256
    and generated_seed == workload.generation_seed
    and workload_plan_valid
    and workload_plan_sha256 == recomputed_workload_plan_sha256
    and cardinality_reconciled
    and expected_active_file_count == (
        workload.fixed_scope_file_count
        + multiplier * workload.scalable_file_count
    )
    and target_declaration_valid
    and data_root_probe_matches
    and state_root_probe_matches
    and run_started_monotonic_ns <= admission_started_monotonic_ns
    and admission_scheduled_end_monotonic_ns == (
        admission_started_monotonic_ns + duration_ns
    )
    and admission_scheduled_end_monotonic_ns <= admission_ended_monotonic_ns
    and admission_ended_monotonic_ns <= run_ended_monotonic_ns
    and admission_same_utc_hour
    and decoded_received_utc_hours == (declared_admission_utc_hour,)
    and duration_ns >= 600_000_000_000
    and multiplier >= 2
    and worker_snapshot_sequences_valid
    and worker_sampling_rounds_valid
    and worker_restart_count == 0
    and final_worker_barriers_valid
    and final_worker_snapshot_aggregation_valid
    and admission_trace_valid
    and admission_trace_sha256 == recomputed_admission_trace_sha256
    and per_second_bucket_sha256 == recomputed_per_second_bucket_sha256
    and early_admission_count == 0
    and late_admission_count == 0
    and out_of_window_count == 0
    and per_stream_admitted_rates_met
    and per_stream_bursts_met
    and attempted_record_count == expected_min_record_count
    and attempted_byte_count == expected_min_byte_count
    and attempted_record_count == accepted_record_count
    and accepted_record_count == durable_record_count
    and durable_record_count == durability_sample_count
    and durability_sample_count == manifest_record_count
    and recorded_loss_count == 0
    and unrecorded_loss_count == 0
    and overflow_count == 0
    and stream_conformance_failures == ()
    and manifest_validation_error_count == 0
    and write_failure_count == 0
    and sync_failure_count == 0
    and accepted_record_identities_valid
    and active_logical_generation_peak == expected_active_file_count
    and storage_health_sample_count >= expected_min_storage_health_samples
    and storage_health_sample_max_gap_ns <= storage_health_max_allowed_gap_ns
    and storage_health_coverage_ns >= duration_ns - 2 * storage_health_sample_interval_ns
    and storage_health_error_count == 0
    and durability_lag_max_ns <= 1_000_000_000
    and rss_peak_bytes <= limits.max_rss_bytes
    and rss_slope_bytes_per_minute <= limits.max_rss_slope_bytes_per_minute
    and open_fds_peak <= limits.max_open_fds
    and fd_growth_after_warmup <= limits.max_fd_growth_after_warmup
    and implementation_provenance_valid
    and implementation_source_commit == recomputed_source_commit
    and collector_wheel_sha256 == recomputed_wheel_sha256
    and requirements_lock_sha256 == recomputed_requirements_lock_sha256
    and dockerfile_sha256 == recomputed_dockerfile_sha256
    and runtime_image_id == expected_image_id
    and is_sha256_image_id(runtime_image_id)
)
```

`GateTargetV1` contains the exact amended fields and its SHA is computed over canonical
JSON with `declaration_sha256` omitted, then included in the final no-replace file.
`declare-target` independently probes the actual data and state roots and rejects a
non-Linux host, symlinks, equal/non-directory roots, insufficient free space, an
unidentifiable mount, or missing file-sync/directory-sync/same-parent no-replace
capability on either root. Qualification recomputes the declaration hash, checks its
target ID and fixed deployment-purpose assertion, and separately re-probes each root's
canonical path, device `major:minor`, filesystem, mount point, prefixed mount/super
options, current free-space floor, and declared capability before generating records.

After the implementation commit, build the minimal production Linux image from its
clean tree and `requirements/collector.lock`. The base image is pinned by digest and
the build records source commit, source epoch, lock hash, and installed wheel hash as
OCI labels and in canonical read-only `/app/build-provenance-v1.json`; the benchmark
requires the file and labels to agree. Its collector stage ends with the fixed numeric identity
`USER 65532:65532`; both gate containers also pass `--user 65532:65532`, and the host
bind roots are pre-provisioned for that exact UID/GID. The image contains only
collector dependencies, the installed wheel, and a copied read-only
`/app/benchmarks/workloads/` directory; it declares no archive/materializer SDKs.
Evidence is valid only in this declared image on the declared target volume; Docker
Desktop bind-mount results on this macOS development host do not substitute for a
Linux deployment target.

- [ ] **Step 4: Run the short functional benchmark**

Run: `.venv/bin/python -m crypto_collector.benchmarks.writer --workload benchmarks/workloads/research-default-v1.yaml --multiplier 2 --duration 10s --report /tmp/writer-short.json --functional-only`

Expected: exit `0`; report schema is valid, `functional_passed=true`, `qualification_accepted=false`, accepted equals durable, and all generated manifests validate. The functional mode is not SLO evidence.

- [ ] **Step 5: Run the repository-wide offline regression gate**

Run: `.venv/bin/python -m pytest -q -m "not live and not performance" --ignore=tests/smoke`

Expected: PASS with external sockets denied and performance/live cases excluded.

- [ ] **Step 6: Commit the Gate B implementation without waiting for target hardware**

```bash
git add src/crypto_collector/benchmarks benchmarks/workloads Dockerfile .dockerignore \
  tests/performance docs/operations/writer-benchmark.md
git commit -m "test: establish raw writer durability gate"
```

This is the implementation commit. Target hardware availability is not a condition for
creating it. Any later build fix is another implementation commit and becomes the new
source commit that evidence must bind.

- [ ] **Step 7: Reproduce the image from the exact clean implementation commit**

```bash
test -z "$(git status --porcelain)"
COLLECTOR_SOURCE_COMMIT="$(git rev-parse HEAD)"
COLLECTOR_SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$COLLECTOR_SOURCE_COMMIT")"
docker build --no-cache --target collector \
  --build-arg SOURCE_DATE_EPOCH="$COLLECTOR_SOURCE_DATE_EPOCH" \
  --build-arg COLLECTOR_SOURCE_COMMIT="$COLLECTOR_SOURCE_COMMIT" \
  -t crypto-collector:repro-a .
COLLECTOR_IMAGE_A="$(docker image inspect --format '{{.Id}}' crypto-collector:repro-a)"
COLLECTOR_WHEEL_A="$(docker image inspect --format \
  '{{index .Config.Labels "org.crypto-collector.wheel-sha256"}}' crypto-collector:repro-a)"
docker build --no-cache --target collector \
  --build-arg SOURCE_DATE_EPOCH="$COLLECTOR_SOURCE_DATE_EPOCH" \
  --build-arg COLLECTOR_SOURCE_COMMIT="$COLLECTOR_SOURCE_COMMIT" \
  -t crypto-collector:test .
COLLECTOR_IMAGE_B="$(docker image inspect --format '{{.Id}}' crypto-collector:test)"
COLLECTOR_WHEEL_B="$(docker image inspect --format \
  '{{index .Config.Labels "org.crypto-collector.wheel-sha256"}}' crypto-collector:test)"
test "$COLLECTOR_IMAGE_A" = "$COLLECTOR_IMAGE_B"
test "$COLLECTOR_WHEEL_A" = "$COLLECTOR_WHEEL_B"
test "$(docker image inspect --format '{{.Config.User}}' crypto-collector:test)" = "65532:65532"
```

Expected: both clean builds use the pinned base/lock and produce the same image ID and
wheel SHA; the image carries the exact source commit/epoch labels, contains the workload
file, and runs as `65532:65532`. If no target is available, record qualification as
pending and stop here without reverting or withholding the implementation commit.

- [ ] **Step 8: Run and archive the real gate on the target volume**

Run these host commands on the declared production Linux target as a provisioning
account allowed to create and `chown` the bind roots and invoke Docker. They launch
the fixed production image; they are not commands to run from inside a container:

```bash
COLLECTOR_BENCH_UID=65532
COLLECTOR_BENCH_GID=65532
install -d -m 0750 -o "$COLLECTOR_BENCH_UID" -g "$COLLECTOR_BENCH_GID" \
  /declared/target/data /declared/target/state /declared/target/state/reports
COLLECTOR_BENCH_IMAGE_ID="$(docker image inspect --format '{{.Id}}' crypto-collector:test)"
test "$(docker image inspect --format '{{.Config.User}}' "$COLLECTOR_BENCH_IMAGE_ID")" \
  = "$COLLECTOR_BENCH_UID:$COLLECTOR_BENCH_GID"
printf '%s\n' "$COLLECTOR_BENCH_IMAGE_ID" \
  > /declared/target/state/reports/collector-image.id
test -n "$COLLECTOR_GATE_TARGET_ID"
docker run --rm \
  --user "$COLLECTOR_BENCH_UID:$COLLECTOR_BENCH_GID" \
  --network none \
  --mount type=bind,src=/declared/target/data,dst=/data \
  --mount type=bind,src=/declared/target/state,dst=/state \
  "$COLLECTOR_BENCH_IMAGE_ID" python -m crypto_collector.benchmarks.writer \
  declare-target \
  --target-id "$COLLECTOR_GATE_TARGET_ID" \
  --deployment-purpose raw-writer-gate-b \
  --data-root /data \
  --state-root /state \
  --data-minimum-free-bytes 107374182400 \
  --state-minimum-free-bytes 107374182400 \
  --output /state/reports/gate-target-v1.json
docker run --rm \
  --user "$COLLECTOR_BENCH_UID:$COLLECTOR_BENCH_GID" \
  --network none \
  --env COLLECTOR_RUNTIME_IMAGE_ID="$COLLECTOR_BENCH_IMAGE_ID" \
  --mount type=bind,src=/declared/target/data,dst=/data \
  --mount type=bind,src=/declared/target/state,dst=/state \
  "$COLLECTOR_BENCH_IMAGE_ID" python -m crypto_collector.benchmarks.writer \
  --workload /app/benchmarks/workloads/research-default-v1.yaml \
  --multiplier 2 \
  --duration 10m \
  --data-root /data \
  --state-root /state \
  --target-declaration /state/reports/gate-target-v1.json \
  --expected-image-id "$COLLECTOR_BENCH_IMAGE_ID" \
  --admission-trace /state/reports/writer-admission-trace-v1.jsonl.zst \
  --report /state/reports/writer-durability.json
```

Expected: both commands exit `0`; the report binds the validated target declaration,
its runtime/expected image IDs exactly match `collector-image.id`, the
active-logical-generation peak is
3,505, the admission window is a same-UTC-hour monotonic interval of at least ten
minutes, every trace/due-time/bucket digest and admitted rate/burst recomputes, all
attempted records have unique exact accepted identities and are durable, sampled, and
represented in valid manifests, max durability lag is at most `1_000_000_000ns`,
RSS/FD remain bounded, both target roots reprobe exactly, and all
loss/overflow/conformance/manifest/write/sync/storage-health/early/late/out-of-window
counts are zero.
Running by immutable image ID is part of the evidence. Copy the redacted report and
target declaration to `docs/operations/evidence/` and document the exact target data
volume in `docs/operations/writer-benchmark.md`.

- [ ] **Step 9: Commit immutable evidence separately**

```bash
git add docs/operations/evidence docs/operations/writer-benchmark.md
git commit -m "evidence: qualify raw writer durability"
```

The evidence commit is allowed only after the validator reproduces the bound source
commit, wheel hash, lock/workload/Dockerfile hashes, and image ID. If the real gate
fails because active-file sync IOPS cannot meet the SLO, retain the implementation
commit, do not create the evidence commit, and amend the approved design with the
measured journal/group-commit alternative.
