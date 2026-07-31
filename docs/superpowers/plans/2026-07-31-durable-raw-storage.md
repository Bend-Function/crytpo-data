# Durable Raw Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Persist every accepted raw record into independently recoverable zstd frames, close immutable manifests, and prove the one-second durability SLO on the target storage before scaling connector work.

**Architecture:** Each exchange worker owns one raw-writer service and one durability coordinator. Stream files buffer JSONL records independently, while the coordinator synchronizes all dirty files with bounded concurrency and records record-level durability lag without modifying raw rows.

**Tech Stack:** asyncio, simplejson with Decimal, python-zstandard, portable `fdatasync/fsync`, Pydantic, Prometheus client, pytest, Hypothesis.

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
    exchange_control = raw_partial_path(tmp_path, exchange_control_envelope("okx"),
                                        part_start_ns=hour_ns(), sequence=0)
    market_status = raw_partial_path(tmp_path, market_envelope("okx", "spot", "status"),
                                     part_start_ns=hour_ns(), sequence=0)
    assert exchange_control.relative_to(tmp_path).as_posix().startswith("raw/okx/_control/")
    assert market_status.relative_to(tmp_path).as_posix().startswith(
        "raw/okx/spot/_market/status/")
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

`layout.py` must use `received_at_ns` converted with UTC, encode the stable instrument key with `encode_instrument_key`, reserve `_market` for symbol-less market streams and `_control` for exchange control streams, and reject path traversal after resolution. `serialize.py` calls the foundation Decimal-aware `encode_json(envelope.model_dump(mode="python")) + b"\n"`; it must preserve `Decimal` as a JSON number and reject binary float or non-JSON values.

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
- Create: `src/crypto_collector/storage/stream_file.py`
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


def test_write_all_retries_eintr_and_short_write(monkeypatch, tmp_path) -> None:
    writes = scripted_writes(InterruptedError(), 3, 10_000)
    monkeypatch.setattr(os, "write", writes)
    stream = StreamFile.allocate(tmp_path / "part.jsonl.zst.partial", zstd_level=3,
                                 max_plain_frame_bytes=1024)
    stream.append(b'{"writer_sequence":1}\n', accepted_monotonic_ns=10)
    stream.write_frame(stream.take_pending())
    assert writes.total_written == writes.expected_bytes
```

- [ ] **Step 2: Run and confirm `StreamFile` is missing**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_stream_file.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement one compressor invocation per frame**

```python
@dataclass(frozen=True, slots=True)
class PendingRows:
    rows: tuple[BufferedRow, ...]
    plain_bytes: int


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

Allocate with `os.O_CREAT | os.O_EXCL | os.O_APPEND | os.O_WRONLY | os.O_CLOEXEC`, mode `0o640`, after startup recovery and atomic sequence allocation under the exchange writer lock. Use a reusable `ZstdCompressor(level=configured_level, write_checksum=True, write_content_size=True)`. Bound the uncompressed frame buffer by `max_plain_frame_bytes`; an oversized single row forms one frame and emits a size warning. Compression, write, and synchronization are blocking methods invoked only by the coordinator's bounded executor path.

- [ ] **Step 4: Run the frame tests**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_stream_file.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/storage/stream_file.py tests/unit/storage/test_stream_file.py
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
    coordinator = DurabilityCoordinator(
        clock=clock,
        sync_backend=sync,
        durability_slo_ns=1_000,
        durability_critical_ns=5_000,
        max_sync_concurrency=2,
    )
    dirty = FakeDirtyFile(fd=7, records=(100, 200))
    result = await coordinator.sync_batch([dirty])
    assert result.lags_ns == (400, 300)
    assert result.slo_breach_count == 0


@pytest.mark.asyncio
async def test_running_watchdog_pauses_worker_while_sync_thread_is_still_blocked() -> None:
    clock = FakeClock(monotonic_ns=100)
    sync = BlockingSync()
    paused = asyncio.Event()
    coordinator = make_coordinator(clock, sync_backend=sync, durability_critical_ns=5_000,
                                   watchdog_interval_ns=100,
                                   on_critical=lambda _error: paused.set())
    watchdog = asyncio.create_task(coordinator.run_watchdog())
    task = asyncio.create_task(coordinator.sync_batch([FakeDirtyFile(fd=7, records=(100,))]))
    await sync.wait_until_started(1)
    clock.advance_ns(5_001)
    await clock.run_ready_sleepers()
    await asyncio.wait_for(paused.wait(), timeout=1)
    await asyncio.wait_for(watchdog, timeout=1)
    assert coordinator.critical_error.reason == "oldest_unpersisted_age"
    assert sync.active == 1
    sync.release_all()
    await task


@pytest.mark.asyncio
async def test_sync_error_is_independently_critical() -> None:
    coordinator = make_coordinator(sync_backend=FailingSync(OSError(errno.EIO, "io")))
    with pytest.raises(WriterCriticalError, match="sync"):
        await coordinator.sync_batch([FakeDirtyFile(fd=7, records=(100,))])
```

```python
@pytest.mark.asyncio
async def test_sync_concurrency_is_bounded() -> None:
    sync = BlockingSync()
    coordinator = make_coordinator(max_sync_concurrency=2, sync_backend=sync)
    task = asyncio.create_task(coordinator.sync_batch([FakeDirtyFile(fd=n) for n in range(10)]))
    await sync.wait_until_started(2)
    assert sync.max_active == 2
    sync.release_all()
    await task


@pytest.mark.asyncio
async def test_one_sync_failure_waits_for_other_inflight_jobs() -> None:
    backend = OneFailureOneBlockingSync()
    coordinator = make_coordinator(max_sync_concurrency=2, sync_backend=backend)
    task = asyncio.create_task(coordinator.sync_batch([fake_file(1), fake_file(2)]))
    await backend.failure_observed()
    assert not task.done()
    backend.release_success()
    with pytest.raises(WriterCriticalError):
        await task


@pytest.mark.asyncio
async def test_cancellation_waits_for_inflight_sync_before_propagating() -> None:
    backend = BlockingSync()
    stream = FakeDirtyFile(fd=7, records=(100,))
    coordinator = make_coordinator(sync_backend=backend)
    task = asyncio.create_task(coordinator.sync_batch([stream]))
    await backend.wait_until_started(1)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    assert stream.close_called is False
    backend.release_all()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert backend.active == 0
    assert coordinator.stats.synced_record_count == 1


@pytest.mark.asyncio
async def test_sync_error_wins_over_concurrent_cancellation_after_full_accounting() -> None:
    backend = CancelThenFailSync(OSError(errno.EIO, "io"))
    coordinator = make_coordinator(sync_backend=backend)
    task = asyncio.create_task(coordinator.sync_batch([fake_file(1), fake_file(2)]))
    await backend.wait_until_started(2)
    task.cancel()
    backend.release_all()
    with pytest.raises(WriterCriticalError, match="sync"):
        await task
    assert coordinator.stats.synced_record_count == 1
    assert coordinator.stats.sync_failure_count == 1


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


async def sync_batch(self, dirty_files: Sequence[StreamFile]) -> DurabilityBatch:
    work: list[tuple[StreamFile, PendingRows]] = []
    for stream_file in dirty_files:
        pending = stream_file.take_pending()
        if pending is not None:
            work.append((stream_file, pending))
    semaphore = asyncio.Semaphore(self.max_sync_concurrency)

    def persist_blocking(stream_file: StreamFile, pending: PendingRows) -> SyncedFrame:
        frame = stream_file.write_frame(pending)
        started = self.clock.monotonic_ns()
        self.sync_backend.sync(stream_file.fd)
        completed = self.clock.monotonic_ns()
        return SyncedFrame(stream_file=stream_file, frame=frame, completed_ns=completed,
                           sync_duration_ns=completed - started)

    async def persist_one(stream_file: StreamFile, pending: PendingRows) -> SyncedFrame:
        async with semaphore:
            return await asyncio.to_thread(persist_blocking, stream_file, pending)

    group = asyncio.gather(
        *(persist_one(stream_file, pending) for stream_file, pending in work),
        return_exceptions=True,
    )
    cancellation: asyncio.CancelledError | None = None
    try:
        results = await asyncio.shield(group)
    except asyncio.CancelledError as error:
        cancellation = error
        results = await group
    synced = tuple(result for result in results if isinstance(result, SyncedFrame))
    errors = tuple(result for result in results if isinstance(result, BaseException))
    batch = self.stats.record_batch(synced=synced, errors=errors)
    if errors:
        critical = WriterCriticalError.from_batch(errors=errors, completed=batch)
        if cancellation is not None:
            raise critical from cancellation
        raise critical
    if cancellation is not None:
        raise cancellation
    return batch
```

The coordinator keeps claimed in-flight rows in its oldest-unpersisted index until sync completion. Its worker-owned `run_watchdog()` task sleeps on the injected clock at the configured bounded cadence and calls `check_critical_age()` independently of batch completion; crossing `durability_critical` invokes the critical callback, records the terminal critical error, and returns so the worker can stop new inputs immediately, while already-running thread work is awaited before descriptors close. The test must run this actual task and wake the fake clock, not call the checker directly. A sync error is independently critical even when record age is below the threshold.

The constructor takes one consistently named `sync_backend: SyncBackend`, defaulting to `PosixSyncBackend`. The same coordinator method is mandatory for periodic flush, time/size/config rotation, and shutdown; no close path may directly write or sync and omit its last records from durability statistics. Shield the `gather(..., return_exceptions=True)` group from caller cancellation and retain the caught cancellation. Await the group, record every successful frame and every sync failure, and finish critical classification before propagating anything. A `WriterCriticalError` wins over concurrent cancellation (chained from it); only an otherwise successful fully accounted batch re-raises the original `CancelledError`. This ensures all non-cancellable thread work finishes and all outcomes are accounted before descriptors close or the worker enters `PAUSED_WRITER`. Expose count/p50/p95/p99/max using an integer histogram whose manifest snapshot is deterministic. Emit an ERROR control callback whenever the batch max or rolling p99 exceeds the SLO.

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
- Create: `src/crypto_collector/storage/ingress.py`
- Create: `src/crypto_collector/storage/writer_lock.py`
- Test: `tests/unit/storage/test_ingress.py`
- Test: `tests/unit/storage/test_writer_lock.py`

- [ ] **Step 1: Write failing acceptance, overflow, and lock tests**

```python
def test_successful_nonblocking_insert_defines_acceptance(fake_clock) -> None:
    ingress = RawIngress(shard_max_records=2, shard_max_bytes=100,
                         worker_max_bytes=200, high_water_ratio=0.8,
                         control_reserve_records=1, control_reserve_bytes=50,
                         worker_instance_id="worker-1", config_sha256="a" * 64,
                         clock=fake_clock)
    result = ingress.try_accept(make_native_event_draft(payload={"value": 1}),
                                source=websocket_source(), shard="book-0")
    assert result.status is EnqueueStatus.ACCEPTED
    assert result.record.envelope.monotonic_ns == result.record.accepted_monotonic_ns
    assert result.record.envelope.worker_instance_id == "worker-1"
    assert result.record.envelope.config_sha256 == "a" * 64


def test_record_or_byte_overflow_never_counts_as_accepted(fake_clock) -> None:
    ingress = make_ingress(shard_max_records=1, shard_max_bytes=20, clock=fake_clock)
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
    ingress = make_ingress(worker_max_bytes=100, control_reserve_bytes=20)
    fill_market_bytes(ingress, 80)
    assert ingress.try_accept(control_draft(size=20), source=SourceContext.internal(),
                              shard="_control").accepted
    assert ingress.try_accept(market_draft(size=1), source=websocket_source(),
                              shard="trade-0").status is EnqueueStatus.OVERFLOW


@pytest.mark.parametrize(
    ("draft", "source"),
    [
        (websocket_draft(), SourceContext(None, None, "direct")),
        (rest_draft(stream="book_live_bootstrap"), SourceContext(None, None, "direct")),
        (rest_draft(stream="ticker"), SourceContext("ws-1", 1, "direct")),
        (internal_control_draft(), SourceContext(None, None, "direct")),
    ],
)
def test_draft_source_scope_mismatch_is_rejected_without_acceptance(draft, source) -> None:
    ingress = make_ingress()
    with pytest.raises(SourceContextError):
        ingress.try_accept(draft, source=source, shard="test")
    assert ingress.accepted_count == 0


def test_second_writer_cannot_hold_same_exchange_root(tmp_path) -> None:
    first = ExchangeWriterLock.acquire(tmp_path, exchange="okx")
    with pytest.raises(WriterAlreadyRunning):
        ExchangeWriterLock.acquire(tmp_path, exchange="okx")
    first.release()
```

- [ ] **Step 2: Run and verify ingress/lock modules are absent**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_ingress.py tests/unit/storage/test_writer_lock.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement nonblocking admission and `flock` ownership**

`RawIngress` is constructed with immutable `worker_instance_id` and `config_sha256`. `RawIngress.try_accept(draft: NativeEventDraft, *, source: SourceContext, shard: str)` owns final-envelope construction. It validates draft/source compatibility, peeks the next `writer_sequence` for `(worker_instance_id, market, instrument_key-or-reserved-scope, logical_stream)`, stamps both wall-clock `received_at_ns` and authoritative `monotonic_ns = clock.monotonic_ns()`, serializes once into `AcceptedRecord.encoded_jsonl`, checks per-shard record/byte and worker byte limits, and performs one `put_nowait`. Commit the sequence counter only on `ACCEPTED` or `ACCEPTED_HIGH_WATER`; overflow cannot consume a sequence or count as accepted. Runtime treats market overflow as a generation-invalidating gap and control overflow as a fatal incomplete-part condition.

```python
class EnqueueStatus(StrEnum):
    ACCEPTED = "accepted"
    ACCEPTED_HIGH_WATER = "accepted_high_water"
    OVERFLOW = "overflow"
    CONTROL_OVERFLOW = "control_overflow"


@dataclass(slots=True)
class ExchangeWriterLock:
    exchange_root: Path
    fd: int
    _released: bool = False

    @classmethod
    def acquire(cls, data_root: Path, *, exchange: str) -> "ExchangeWriterLock":
        exchange_root = data_root / "raw" / exchange
        exchange_root.mkdir(parents=True, exist_ok=True)
        fd = os.open(exchange_root / ".writer.lock",
                     os.O_CREAT | os.O_RDWR | os.O_CLOEXEC, 0o640)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(fd)
            raise WriterAlreadyRunning(exchange_root) from error
        return cls(exchange_root=exchange_root, fd=fd)

    def release(self) -> None:
        if not self._released:
            fcntl.flock(self.fd, fcntl.LOCK_UN)
            os.close(self.fd)
            self._released = True

    def __enter__(self) -> "ExchangeWriterLock":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.release()
```

`ExchangeWriterLock.acquire(data_root, exchange=...)` is the only public acquisition API; it returns the object used by the tests and by `RawWriterService`. Hold it for the full exchange-worker lifetime. Under that lock, finish startup recovery and scan all closed/partial names before atomically allocating the next part sequence with `O_EXCL`.

- [ ] **Step 4: Run ingress and ownership tests**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_ingress.py tests/unit/storage/test_writer_lock.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/storage/ingress.py src/crypto_collector/storage/writer_lock.py tests/unit/storage/test_ingress.py tests/unit/storage/test_writer_lock.py
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
async def test_utc_hour_rotation_closes_data_before_manifest(writer, clock) -> None:
    await writer.put(make_record(received_at_ns=ns("2026-07-31T00:59:59.999Z")))
    await writer.sync_now()
    clock.set_time_ns(ns("2026-07-31T01:00:00Z"))
    await writer.put(make_record(received_at_ns=ns("2026-07-31T01:00:00Z")))
    manifests = await writer.rotate_due_files()
    assert manifests[0].close_reason == "rotate_time"
    assert not Path(manifests[0].relative_path).name.endswith(".partial")


@pytest.mark.asyncio
async def test_config_change_never_shares_a_closed_part(writer) -> None:
    await writer.put(make_record(config_sha256="a" * 64))
    await writer.rotate_for_config("b" * 64)
    await writer.put(make_record(config_sha256="b" * 64))
    manifests = await writer.close_all(CloseReason.SHUTDOWN)
    assert {manifest.config_sha256 for manifest in manifests} == {"a" * 64, "b" * 64}


def test_raw_manifest_has_independent_schema_version(writer) -> None:
    manifest = close_one_part(writer)
    assert manifest.schema_version == 1
    assert json.loads(manifest.to_json())["schema_version"] == 1
    with pytest.raises(UnsupportedManifestSchema):
        RawManifestV1.model_validate({**manifest.model_dump(), "schema_version": 2})
```

- [ ] **Step 2: Run and verify missing writer/manifest modules**

Run: `.venv/bin/python -m pytest tests/unit/storage/test_raw_writer.py tests/unit/storage/test_manifest.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement the close protocol exactly**

For every active file execute:

```python
final_batch = await durability_coordinator.sync_batch([file])
file.close_fd()
if closed_data_path.exists():
    raise FileExistsError(closed_data_path)
os.rename(partial_path, closed_data_path)
fsync_directory(closed_data_path.parent)
data_sha256 = sha256_file(closed_data_path)
manifest = build_manifest(file, final_batch, data_sha256)
atomic_write_and_sync_json_exclusive(manifest_partial, manifest.model_dump(mode="python"))
if closed_manifest_path.exists():
    raise FileExistsError(closed_manifest_path)
os.rename(manifest_partial, closed_manifest_path)
fsync_directory(closed_manifest_path.parent)
```

`fsync_directory` opens the directory with `O_RDONLY | O_DIRECTORY` and calls `os.fsync`; failures are fatal and leave startup reconciliation evidence. `RawManifestV1` declares its own `schema_version: Literal[1] = 1`, independent of envelope/workload schemas, and rejects unsupported versions. It must contain every field listed in spec section 11.4, including instrument key and wire-symbol set, relative paths, zstd settings, record/time/sequence ranges, config hash, egress IDs, control counters/references, requested/effective REST intervals, all durability batches including the final one, sync duration, failure counts, recovery state, and close reason. Reject a manifest unless the referenced closed data file exists, has the recorded size, and matches SHA-256.

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
def test_complete_frames_are_recovered_and_bad_tail_is_quarantined(tmp_path) -> None:
    partial = write_two_frames_and_truncated_third(tmp_path)
    result = recover_partial(partial, recovery_root=tmp_path / "quarantine")
    assert [row["writer_sequence"] for row in read_all_jsonl(result.recovered_data_path)] == [1, 2]
    assert all(RawEnvelope.model_validate(row) for row in read_all_jsonl(result.recovered_data_path))
    assert result.manifest.close_reason == "recovery"
    assert result.manifest.recovery["truncated_tail_bytes"] > 0
    assert result.quarantined_tail_path.exists()


def test_empty_or_unreadable_partial_never_gets_complete_manifest(tmp_path) -> None:
    partial = tmp_path / "broken.jsonl.zst.partial"
    partial.write_bytes(b"not-zstd")
    result = recover_partial(partial, recovery_root=tmp_path / "quarantine")
    assert result.recovered_data_path is None
    assert result.complete_manifest_path is None


def test_closed_data_without_manifest_is_reconciled(tmp_path) -> None:
    data_path = write_valid_closed_data_without_manifest(tmp_path)
    report = recover_exchange_root(tmp_path)
    manifest = load_manifest(manifest_path_for_data(data_path))
    assert manifest.close_reason == "recovery"
    assert manifest.recovery["source_state"] == "orphan_closed_data"
    assert report.orphan_data_recovered == 1


def test_manifest_without_data_is_quarantined(tmp_path) -> None:
    manifest_path = write_manifest_with_missing_data(tmp_path)
    report = recover_exchange_root(tmp_path)
    assert not manifest_path.exists()
    assert report.manifest_missing_data == 1
    assert list((tmp_path / "quarantine").glob("*.manifest-missing-data"))


def test_cleanup_exclusive_lease_waits_for_materializer_shared_lease(tmp_path) -> None:
    lease_path = tmp_path / "part.lease"
    with SourceLease.shared(lease_path):
        with pytest.raises(SourceLeaseBusy):
            SourceLease.exclusive(lease_path, blocking=False)


@pytest.mark.parametrize("phase", [
    "after_frame_write", "after_data_sync", "after_data_rename",
    "after_manifest_temp_sync", "after_manifest_rename",
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
    "frame_write", "data_sync", "data_directory_sync",
    "manifest_temp_write", "manifest_temp_sync",
])
@pytest.mark.parametrize("error", [OSError(errno.ENOSPC, "full"), OSError(errno.EIO, "io")])
def test_prepublication_io_error_matrix_never_publishes_normal_manifest(
    tmp_path, phase, error,
) -> None:
    result = run_writer_with_injected_io_error(tmp_path, error, at=phase)
    assert result.state == "PAUSED_WRITER"
    assert result.trace.last_attempted_phase == phase
    assert not list(tmp_path.rglob("*.manifest.json"))
    recovered = run_recovery_in_fresh_process(tmp_path)
    assert recovered.complete_parts + recovered.quarantined_parts == 1
    assert_no_path_has_both_partial_and_complete_identity(tmp_path)


def test_manifest_rename_is_followed_by_directory_fsync_and_eio_converges(tmp_path) -> None:
    result = run_writer_with_injected_io_error(
        tmp_path, OSError(errno.EIO, "io"), at="manifest_directory_fsync")
    assert result.trace[-2:] == ("manifest_rename", "manifest_directory_fsync")
    assert result.state == "PAUSED_WRITER"
    recovered = run_recovery_in_fresh_process(tmp_path)
    assert recovered.complete_parts + recovered.quarantined_parts == 1
    assert_no_path_has_both_partial_and_complete_identity(tmp_path)


@pytest.mark.asyncio
async def test_unrecoverable_recovery_failure_opens_no_ingress_or_part(tmp_path) -> None:
    with pytest.raises(RecoveryBlocked):
        await RawWriterService.open(
            data_root=tmp_path, exchange="okx", worker_instance_id="worker-1",
            config_sha256="a" * 64, writer_config=test_writer_config(),
            clock=FakeClock(), sync_backend=FakeSync(),
            recovery_backend=FailingRecovery(errno.EIO))
    assert not list(tmp_path.rglob("*.jsonl.zst.partial"))
    with ExchangeWriterLock.acquire(tmp_path, exchange="okx"):
        pass


@pytest.mark.asyncio
async def test_service_config_rotation_swaps_identity_without_sequence_reset(service) -> None:
    first = service.try_accept(trade_draft(), source=websocket_source(), shard="trade-0")
    old_manifests = await service.rotate_for_config("b" * 64)
    second = service.try_accept(trade_draft(), source=websocket_source(), shard="trade-0")
    assert first.record.envelope.config_sha256 == "a" * 64
    assert second.record.envelope.config_sha256 == "b" * 64
    assert (first.record.envelope.writer_sequence,
            second.record.envelope.writer_sequence) == (0, 1)
    assert {manifest.config_sha256 for manifest in old_manifests} == {"a" * 64}
```

- [ ] **Step 2: Run and verify recovery is missing**

Run: `.venv/bin/python -m pytest tests/integration/storage/test_recovery.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement streaming frame validation**

Walk zstd frame boundaries without accepting decoder output after the first corrupt/truncated frame. The crash helper writes full valid `RawEnvelope` rows; no recovery test may substitute a minimal `{"writer_sequence": ...}` object that production validation would reject. Copy only complete frame byte ranges into a new `.partial`, validate every JSON line as `RawEnvelope`, close it through the normal close protocol with reason `recovery`, and move the original bad tail to `data/quarantine/<relative-source>.bad-tail`. `manifest_path_for_data()` requires the full `.jsonl.zst` suffix and replaces it with `.manifest.json`; never use `Path.with_suffix()` one suffix at a time. Reconcile manifest temporaries, closed data without a manifest, manifests whose data is missing, and next-sequence allocation under the writer lock. Recovered durability quantiles that cannot be reconstructed are explicitly `null` with `durability_measurement="unavailable_after_crash"`.

Implement `SourceLease` with a stable `.lease` sidecar and `fcntl.flock`: materializer, archiver, and restore use `LOCK_SH`; cleanup uses `LOCK_EX`, then revalidates policy and files before unlink. The subprocess helper exposes test-only phase hooks through an injected callback, never an environment-controlled production backdoor. Emit recovery control records for every reconciled or quarantined identity. Never mutate the only source artifact before the replacement/quarantine outcome is durable.

Freeze the worker-facing API in `storage.service`; runtime must not assemble lock/recovery/ingress/writer pieces itself:

```python
class RawWriterService:
    @classmethod
    async def open(cls, *, data_root: Path, exchange: str, worker_instance_id: str,
                   config_sha256: str, writer_config: WriterConfig, clock: Clock,
                   sync_backend: SyncBackend,
                   recovery_backend: RecoveryBackend = DEFAULT_RECOVERY) -> "RawWriterService": ...
    def try_accept(self, draft: NativeEventDraft, *, source: SourceContext,
                   shard: str) -> EnqueueResult: ...
    async def sync_now(self) -> tuple[DurabilityBatch, ...]: ...
    async def rotate_due_files(self) -> tuple[RawManifestV1, ...]: ...
    async def rotate_for_config(self, config_sha256: str) -> tuple[RawManifestV1, ...]: ...
    async def close_all(self, reason: CloseReason,
                        deadline_ns: int) -> tuple[RawManifestV1, ...]: ...
    async def mark_incomplete(self, reason: str) -> None: ...
    def status(self) -> WriterStatus: ...
```

`open` acquires `ExchangeWriterLock`, completes and durably records all startup reconciliation, allocates next sequences, starts the single coordinator, and only then exposes an accepting service. Any unexpected recovery/lock/sequence error closes resources, releases the lock, creates no new active part, raises `RecoveryBlocked`, and therefore blocks adapter probes/connections. `try_accept` is the sole public record-input method and delegates to its owned `RawIngress`; the remaining async methods are the sole runtime lifecycle surface. There is no public `writer.put`, alternate sink, raw lock file descriptor, or separate runtime close protocol.

`rotate_for_config(new_sha)` is an atomic service operation invoked only after runtime has stopped the affected producers: close the admission gate, drain and durably close every old-config part, replace the owned immutable `RawIngress` with a new instance carrying `new_sha`, transfer the per-stream next-sequence ledger without incrementing it, and reopen admission. On any drain/sync/close error, do not install the new ingress; mark the service incomplete/critical. Thus no accepted record can carry the old hash after rotation returns, no file mixes hashes, and immutability of an individual ingress is preserved.

- [ ] **Step 4: Run recovery and full storage tests**

Run: `.venv/bin/python -m pytest tests/unit/storage tests/integration/storage -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/storage/recovery.py src/crypto_collector/storage/lease.py src/crypto_collector/storage/service.py tests/helpers/writer_crash_child.py tests/unit/storage/test_lease.py tests/integration/storage
git commit -m "feat: reconcile crashed raw parts"
```

### Task 7: Durability Performance Gate

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
    assert report.accepted is False


def test_benchmark_rejects_underdriven_or_unhealthy_storage() -> None:
    report = passing_report()
    assert replace(report, attempted_records=report.expected_min_records - 1).accepted is False
    assert replace(report, active_file_peak=report.expected_active_file_count - 1).accepted is False
    assert replace(report, storage_health_error_count=1).accepted is False
    assert replace(report, storage_health_sample_count=
                   report.expected_min_storage_health_samples - 1).accepted is False
    assert replace(report, storage_health_sample_max_gap_ns=
                   report.storage_health_max_allowed_gap_ns + 1).accepted is False
    assert replace(report, storage_health_coverage_ns=
                   report.duration_ns - 2 * report.storage_health_sample_interval_ns - 1
                   ).accepted is False
    assert replace(report, runtime_image_id="sha256:" + "b" * 64).accepted is False
    assert replace(report, runtime_image_id="not-a-digest").accepted is False


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
exchange_workers: 5
markets_per_worker: 2
symbols_per_market: 25
active_file_count: 1755
streams:
  trade: {instances: 250, mean_records_per_second: 50, burst_records_in_1s: 500, payload_p50_bytes: 600, payload_p95_bytes: 1400, payload_max_bytes: 8192}
  book_live: {instances: 250, mean_records_per_second: 20, burst_records_in_1s: 100, payload_p50_bytes: 8192, payload_p95_bytes: 32768, payload_max_bytes: 262144}
  ticker: {instances: 250, mean_records_per_second: 1, burst_records_in_1s: 5, payload_p50_bytes: 1200, payload_p95_bytes: 2400, payload_max_bytes: 8192}
  bbo: {instances: 250, mean_records_per_second: 10, burst_records_in_1s: 50, payload_p50_bytes: 500, payload_p95_bytes: 1000, payload_max_bytes: 4096}
  derivative: {instrument_instances: 125, file_instances: 250, markets: [perpetual], logical_streams_per_instrument: 2, mean_records_per_second: 2, burst_records_in_1s: 10, payload_p50_bytes: 1400, payload_p95_bytes: 3000, payload_max_bytes: 16384}
  candle_1m: {instances: 250, mean_records_per_second: 0.5, burst_records_in_1s: 2, payload_p50_bytes: 1000, payload_p95_bytes: 2000, payload_max_bytes: 4096}
  book_deep_snapshot: {instances: 250, mean_records_per_second: 0.0334, burst_records_in_1s: 1, payload_p50_bytes: 131072, payload_p95_bytes: 262144, payload_max_bytes: 1048576}
  control: {instances: 5, scope: exchange, mean_records_per_second: 0.1, burst_records_in_1s: 10, payload_p50_bytes: 800, payload_p95_bytes: 2000, payload_max_bytes: 8192}
payload_generation: {decimal_string_fraction: 0.70, repeated_key_fraction: 0.80, incompressible_fraction: 0.20}
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

The declared file count is an exact path-identity calculation: six 250-file symbol streams (`trade`, `book_live`, `ticker`, `bbo`, `candle_1m`, `book_deep_snapshot`) contribute 1500; 125 perpetual instruments times two derivative logical streams contribute 250; and the exchange-level `_control` namespace contributes five, for 1755 active files. Event producers or burst lanes do not count as separate files when they share one storage identity.

The CLI accepts `--workload`, `--multiplier`, `--duration`, `--data-root`, `--report`, required qualification-only `--expected-image-id`, and explicit `--functional-only`. The container launcher injects the actually selected immutable ID as `COLLECTOR_RUNTIME_IMAGE_ID`; qualification refuses a missing/malformed value or a mismatch with `--expected-image-id`. `--data-root` is mandatory for qualification; functional mode may omit it and then owns a fresh `TemporaryDirectory` for the full run/validation lifecycle. Generate envelopes across exactly that distribution using the production ingress and writer. The multiplier scales both record rates and active-file cardinality; keep five exchange workers/two markets and add deterministic synthetic instruments until the scaled active-file target is exact. The report rejects a workload whose declared stream instances do not reconcile to `active_file_count`. Record `mode`, `functional_passed`, and `qualification_accepted` plus expected/attempted/accepted per-stream records and bytes, measured active-file count, storage-health sample interval/count/coverage/max gap/errors, CPU model/count, memory, runtime/expected image IDs, OS, storage device, filesystem, mount options, data root, compressed bytes, sync calls/IOPS/durations, queue high-water marks, RSS/FD samples and slopes, durability p50/p95/p99/max, and recorded/unrecorded loss counts. For a run of duration `D` and configured interval `I`, compute `expected_min_storage_health_samples = max(2, ceil(D / I) - 1)` and require coverage through at least `D - 2I`; a burst of samples at startup cannot qualify the run.

Functional mode exits zero only when schema/workload reconciliation succeeds, every accepted record is durable, manifests validate, storage has no errors, and unrecorded loss is zero. It always writes `qualification_accepted=false`. Qualification mode exits nonzero unless all conditions hold:

```python
accepted = (
    duration_ns >= 600_000_000_000
    and multiplier >= 2
    and attempted_records >= expected_min_records
    and attempted_bytes >= expected_min_bytes
    and stream_conformance_failures == ()
    and active_file_peak == expected_active_file_count
    and storage_health_sample_count >= expected_min_storage_health_samples
    and storage_health_sample_max_gap_ns <= storage_health_max_allowed_gap_ns
    and storage_health_coverage_ns >= duration_ns - 2 * storage_health_sample_interval_ns
    and storage_health_error_count == 0
    and accepted_count == durable_count
    and durability_lag_max_ns <= 1_000_000_000
    and unrecorded_loss_count == 0
    and rss_peak_bytes <= limits.max_rss_bytes
    and rss_slope_bytes_per_minute <= limits.max_rss_slope_bytes_per_minute
    and open_fds_peak <= limits.max_open_fds
    and fd_growth_after_warmup <= limits.max_fd_growth_after_warmup
    and runtime_image_id == expected_image_id
    and is_sha256_image_id(runtime_image_id)
)
```

Build the minimal production Linux image from `requirements/collector.lock` before either invocation. It runs as a non-root user, contains only collector dependencies, the installed wheel, and a copied read-only `/app/benchmarks/workloads/` directory; it declares no archive/materializer SDKs. Evidence is valid only when run in this declared production image on the target data volume; Docker Desktop bind-mount results on this macOS development host do not substitute for a Linux deployment target.

- [ ] **Step 4: Run the short functional benchmark**

Run: `docker build --target collector -t crypto-collector:test .`

Expected: the collector target builds from `requirements/collector.lock` and contains the workload file.

Run: `.venv/bin/python -m crypto_collector.benchmarks.writer --workload benchmarks/workloads/research-default-v1.yaml --multiplier 2 --duration 10s --report /tmp/writer-short.json --functional-only`

Expected: exit `0`; report schema is valid, `functional_passed=true`, `qualification_accepted=false`, accepted equals durable, and all generated manifests validate. The functional mode is not SLO evidence.

- [ ] **Step 5: Run and archive the real gate on the target volume**

Run in the production Linux image:

```bash
install -d -m 0750 /declared/target/data /declared/target/state/reports
docker image inspect --format '{{.Id}}' crypto-collector:test \
  > /declared/target/state/reports/collector-image.id
COLLECTOR_BENCH_IMAGE_ID="$(sed -n '1p' /declared/target/state/reports/collector-image.id)"
docker run --rm \
  --network none \
  --env COLLECTOR_RUNTIME_IMAGE_ID="$COLLECTOR_BENCH_IMAGE_ID" \
  --mount type=bind,src=/declared/target/data,dst=/data \
  --mount type=bind,src=/declared/target/state,dst=/state \
  "$COLLECTOR_BENCH_IMAGE_ID" python -m crypto_collector.benchmarks.writer \
  --workload /app/benchmarks/workloads/research-default-v1.yaml \
  --multiplier 2 \
  --duration 10m \
  --data-root /data \
  --expected-image-id "$COLLECTOR_BENCH_IMAGE_ID" \
  --report /state/reports/writer-durability.json
```

Expected: exit `0`, the report's runtime/expected image IDs both exactly match `collector-image.id`, max durability lag is at most `1_000_000_000ns`, RSS/FD remain bounded, and unrecorded loss is zero. Running the container by that immutable image ID, rather than the mutable tag, is part of the evidence. Copy the redacted report to `docs/operations/evidence/writer-durability-<host>-<date>.json` and document the exact target data volume in `docs/operations/writer-benchmark.md`.

- [ ] **Step 6: Run the repository-wide offline regression gate**

Run: `.venv/bin/python -m pytest -q -m "not live and not performance"`

Expected: PASS with external sockets denied and performance/live cases excluded.

- [ ] **Step 7: Commit only after both gates pass**

```bash
git add src/crypto_collector/benchmarks benchmarks/workloads Dockerfile .dockerignore tests/performance docs/operations
git commit -m "test: establish raw writer durability gate"
```

If the real gate fails because active-file sync IOPS cannot meet the SLO, stop this plan without the final commit and amend the approved design with a measured journal/group-commit alternative.
