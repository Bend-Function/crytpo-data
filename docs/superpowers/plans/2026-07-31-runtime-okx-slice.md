# Runtime and OKX Vertical Slice Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Freeze the exchange-adapter/runtime contract and run a real OKX Spot and perpetual collector through the production network, bounded ingress, durable writer, worker, supervisor, and admin-control boundaries.

**Architecture:** A scripted adapter first proves runtime behavior without the internet. OKX then becomes the reference connector because one API family exercises catalogs, HTTP-200 business errors, public/business WebSockets, deep REST books, derivatives, and a snapshot/delta book without protocol bootstrap.

**Tech Stack:** asyncio, multiprocessing spawn, HTTPX, websockets, Pydantic, SQLite, Typer, pytest, Hypothesis, local scripted transports.

---

### Task 1: Exchange Contracts and Fixture Provenance

**Files:**
- Modify: `docs/exchanges/okx/README.md`
- Modify: `docs/exchanges/okx/sources/api-guide-en.html`
- Modify: `docs/exchanges/okx/sources/changelog-en.html`
- Create: `src/crypto_collector/exchanges/__init__.py`
- Create: `src/crypto_collector/exchanges/contracts.py`
- Create: `src/crypto_collector/exchanges/errors.py`
- Create: `src/crypto_collector/exchanges/registry.py`
- Create: `tests/support/scripted_transport.py`
- Create: `tests/support/exchange_contract.py`
- Test: `tests/unit/exchanges/test_contracts.py`

- [ ] **Step 1: Refresh and verify official OKX evidence before coding**

Fetch the two official pages already identified in `docs/exchanges/okx/README.md` into temporary files, verify they are non-empty OKX documents, then replace the archived copies and update retrieval time and SHA-256 values. Review relevant endpoint/channel/change sections and amend the plan/spec before implementation if the live contract changed.

Run: `shasum -a 256 docs/exchanges/okx/sources/api-guide-en.html docs/exchanges/okx/sources/changelog-en.html`

Expected: hashes exactly match the updated provenance table; no connector coding proceeds on a mismatch or unexplained protocol change.

- [ ] **Step 2: Write failing identity, integrity, and anonymous-boundary tests**

```python
def test_one_instrument_can_have_distinct_wire_symbols() -> None:
    instrument = Instrument(
        exchange=Exchange.KRAKEN,
        market=Market.SPOT,
        instrument_key="BTC/USDT",
        canonical_pair="BTC/USDT",
        wire_symbols={"rest": "XBTUSDT", "ws_v2": "BTC/USDT"},
        quote_asset="USDT",
        tradable=True,
    )
    assert instrument.wire_symbol("rest") == "XBTUSDT"
    assert instrument.wire_symbol("ws_v2") == "BTC/USDT"


def test_integrity_levels_are_explicit() -> None:
    assert BookIntegrity.SEQUENCE_VERIFIED.is_research_valid
    assert BookIntegrity.CHECKSUM_VERIFIED.is_research_valid
    assert BookIntegrity.BEST_EFFORT.is_research_valid
    assert not BookIntegrity.INVALID.is_research_valid


def test_collection_request_cannot_carry_credentials_or_private_channels() -> None:
    body = valid_collection_request_dict()
    body["headers"] = {"Authorization": "Bearer secret"}
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CollectionRequest.model_validate(body)
```

- [ ] **Step 3: Run and verify exchange contracts are missing**

Run: `.venv/bin/python -m pytest tests/unit/exchanges/test_contracts.py -q`

Expected: FAIL during import.

- [ ] **Step 4: Define narrow shared contracts**

```python
from crypto_collector.domain.envelope import NativeEventDraft, SourceContext
from crypto_collector.domain.types import CoverageMode, IntegrityMode
from crypto_collector.config.probe_contracts import ProbeProvider

BookIntegrity = IntegrityMode


@dataclass(frozen=True, slots=True)
class ConnectionGeneration:
    connection_id: str
    generation: int
    egress_id: str

    def source_context(self) -> SourceContext:
        return SourceContext(
            connection_id=self.connection_id,
            connection_generation=self.generation,
            egress_id=self.egress_id,
        )


Instrument = InstrumentRecord
InstrumentCatalog = CompleteCatalogSnapshot


class CollectionRequest(StrictModel):
    exchange: Exchange
    selected: Mapping[Market, tuple[Instrument, ...]]
    enabled_streams: Mapping[Market, frozenset[str]]
    interval_plans: Mapping[str, IntervalPlan]
    config_sha256: str


@dataclass(frozen=True, slots=True)
class AdapterPlan:
    exchange: Exchange
    ws: tuple[WebSocketSubscription, ...]
    rest: tuple[RestPlanItem, ...]
    expectations: tuple[StreamExpectation, ...]
    disabled_optional_features: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class AdapterRuntime:
    transports: Mapping[str, EgressTransport]
    scheduler: RestSchedulerPort
    clock: Clock
    stop: StopToken


class EventSink(Protocol):
    def try_emit(self, draft: NativeEventDraft, *, source: SourceContext,
                 shard: str) -> EnqueueResult: ...


class ExchangeAdapter(ProbeProvider, Protocol):
    exchange: Exchange
    async def probe(self, request: ProbeRequest) -> CapabilityProbe: ...
    async def fetch_catalog(self, runtime: AdapterRuntime, market: Market) -> InstrumentCatalog: ...
    def plan(self, request: CollectionRequest) -> AdapterPlan: ...
    async def run(self, plan: AdapterPlan, runtime: AdapterRuntime, sink: EventSink) -> None: ...
```

`InstrumentRecord` and `CompleteCatalogSnapshot`, established by Plan 03, are the single canonical owners of instrument identity/lifecycle and complete catalog provenance; this plan exports them as `Instrument` and `InstrumentCatalog` rather than creating lossy duplicates. `CapabilityProbe`, `WebSocketSubscription`, `RestPlanItem`, `StreamExpectation`, and `IntervalPlan` are frozen value objects with explicit fields for feature/result evidence, market/instrument/channel/egress, endpoint/cost/priority/interval/generation affinity, storage shard ID, expected raw stream scope, and expected coverage respectively. A `RestPlanItem` is a clock-free template: runtime calls its explicit `materialize(...)` boundary to create a scheduler `RestJob` occurrence after monotonic time and, for `LIVE_BOOTSTRAP` only, the exact connection generation are known. Independent deep snapshots reject generation affinity. `AdapterRuntime` exposes public transports through an egress-ID mapping because each SOCKS/direct egress owns distinct clients. `PublicHttpTransport` and `PublicWebSocketTransport` expose anonymous request/connect operations only; they have no arbitrary headers, credentials, or query-string escape hatch. Venue connectors must additionally allowlist their public REST paths and WS channels because the shared layer cannot identify venue-specific private names. `StopToken` exposes cancellation state without owning tasks. Validate all collection/plan objects on construction: selected instruments must belong to the exchange/market, every request must be anonymous/public, each planned stream must map to an expectation, and every emitted event uses the shard ID assigned by that plan item. Task 2 implements a plan-bound sink that validates the full event/expectation/shard tuple before delegating to `RawWriterService.try_accept`; the shared protocol alone is not treated as enforcement.

Keep venue book state machines in venue packages. Shared code may carry generation-scoped inputs, integrity outcomes, control events, and recovery actions, but may not assume universal sequence/checksum behavior. `NativeEventDraft` and `SourceContext` are imported from the Plan 01 canonical module, never redefined here. A plan-bound `EventSink.try_emit(draft, *, source, shard=...)` returns the storage `EnqueueResult`; its adapter validates the plan assignment before calling the similarly shaped, keyword-only `RawWriterService.try_accept`. Adapters must invalidate a generation after market overflow.

Every fixture directory contains exact raw bytes plus `manifest.json` with official source URL, retrieval time, SHA-256, protocol, and expected parser action.

- [ ] **Step 5: Run contract tests**

Run: `.venv/bin/python -m pytest tests/unit/exchanges/test_contracts.py -q`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add docs/exchanges/okx src/crypto_collector/exchanges tests/support tests/unit/exchanges
git commit -m "feat: define anonymous exchange contracts"
```

### Task 2: Scripted Worker Lifecycle and Backpressure

**Files:**
- Create: `src/crypto_collector/runtime/__init__.py`
- Create: `src/crypto_collector/runtime/messages.py`
- Create: `src/crypto_collector/runtime/state.py`
- Create: `src/crypto_collector/runtime/worker.py`
- Create: `tests/fixtures/exchanges/scripted/session.jsonl`
- Test: `tests/unit/runtime/test_worker.py`
- Test: `tests/integration/runtime/test_scripted_worker.py`

- [ ] **Step 1: Write failing lifecycle and overflow tests**

```python
@pytest.mark.asyncio
async def test_scripted_worker_writes_data_and_expectation_control(tmp_path) -> None:
    worker = make_worker(tmp_path, adapter=ScriptedAdapter.from_fixture("session.jsonl"))
    await worker.start()
    await worker.wait_until_script_complete()
    manifests = await worker.stop(deadline_ns=worker.clock.monotonic_ns() + seconds(5))
    assert streams(manifests) >= {"trade", "_control"}
    assert any_control(manifests, event="subscription_expectation")


@pytest.mark.asyncio
async def test_market_overflow_invalidates_only_that_generation(tmp_path) -> None:
    adapter = FloodingScriptedAdapter(channel="book_live", count=100)
    worker = make_worker(tmp_path, adapter=adapter, shard_max_records=1)
    await worker.run_until(lambda state: state.gap_count == 1)
    assert adapter.closed_generations == {1}
    assert worker.state is WorkerState.RUNNING
    assert any_control(worker.closed_manifests, event="queue_overflow")


@pytest.mark.asyncio
async def test_writer_critical_stops_inputs_but_is_not_a_crash(tmp_path) -> None:
    worker = make_worker(tmp_path, sync_backend=FailingSync(OSError(errno.EIO, "io")))
    await worker.start()
    await worker.wait_until_state(WorkerState.PAUSED_WRITER)
    assert worker.adapter.connections_open == 0
    assert worker.exit_code is None


@pytest.mark.asyncio
async def test_startup_recovery_failure_precedes_every_network_action(tmp_path) -> None:
    adapter = RecordingScriptedAdapter()
    worker = make_worker(tmp_path, adapter=adapter,
                         raw_writer_factory=failing_recovery_factory(errno.EIO))
    await worker.start()
    await worker.wait_until_state(WorkerState.PAUSED_WRITER)
    assert adapter.http_requests == []
    assert adapter.connections_open == 0
    assert worker.status().last_failure == "storage_recovery_blocked"


@pytest.mark.asyncio
async def test_control_overflow_is_fatal_and_never_publishes_complete_part(tmp_path) -> None:
    worker = make_worker(tmp_path, adapter=ControlFloodAdapter(),
                         control_reserve_records=1)
    await worker.start()
    await worker.wait_until_state(WorkerState.PAUSED_WRITER)
    assert worker.status().last_failure == "control_overflow"
    assert worker.adapter.connections_open == 0
    assert worker.active_part_is_marked_incomplete


```

- [ ] **Step 2: Run and verify runtime modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/runtime/test_worker.py tests/integration/runtime/test_scripted_worker.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement one event loop per exchange worker**

```python
class WorkerState(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    PAUSED_WRITER = "paused_writer"
    PAUSED_LOW_DISK = "paused_low_disk"
    STOPPING = "stopping"
    STOPPED = "stopped"
```

This task freezes the single-loop worker around an already prepared immutable `CollectionRequest` plus writer/runtime factories. It calls only Plan 02's `RawWriterService.open`, which owns lock acquisition, startup recovery, sequence allocation, ingress, coordinator, stream writers, rotation, incomplete marking, and close. A `RecoveryBlocked` result enters `PAUSED_WRITER` before invoking the runtime factory or issuing any adapter HTTP/WS action. Startup, fatal pause, and shutdown share one lifecycle mutex; a stop request is latched before waiting for that mutex so a writer factory that completes concurrently cannot revive a stopped worker or open later network resources. After storage is accepting, construct clients, build and validate the adapter plan, require a complete `_control` expectation, emit a `subscription_expectation` checkpoint, and only then start the long-running adapter task. Invalid plans reject prepare before subscriptions open. Task 6 owns `ConfigBundle`/secret resolution, initial probe/catalog/selection preparation, periodic catalog refresh, and transactional plan replacement once the OKX adapter surface exists; those concerns are not duplicated in this scripted lifecycle task.

`EventSink.try_emit(draft, source=source, shard=plan_item.shard_id)` validates the event against the plan-bound expectation and then delegates immediately to `RawWriterService.try_accept(draft, source=source, shard=shard)`, which invokes the Plan 02 nonblocking ingress and adds receive time, worker/config identity, source connection/egress fields, and writer sequence. Queue overflow writes a reserved control event and requests that channel generation close/rebuild. `CONTROL_OVERFLOW` or writer failure always takes priority over an adapter failure, latches the sink closed, joins adapter cancellation, closes all exchange inputs, calls `RawWriterService.mark_incomplete`, and enters `PAUSED_WRITER`; that state remains alive but unready. An unexpected normal return or exception from the long-running adapter writes a generic control record, closes its expectation interval, terminalizes the writer as incomplete, and exposes exit code 1 in `DEGRADED` so Task 6 can restart the worker. A normal stop emits the expectation's `effective_end_ns`, joins adapter cleanup before closing network/writer resources, and only then publishes `STOPPED`; cancellation of the stop caller is deferred until this owned cleanup completes. Rotation, reload boundaries, sync, and shutdown call only the other frozen service methods; runtime never opens storage files or acquires writer locks itself.

Emit expectation checkpoints on config commit, selected-set change, every UTC hour boundary, and interval close. The payload contains effective start, optional end, and sorted exchange/market/instrument/stream keys so completely silent quality windows remain discoverable.

- [ ] **Step 4: Run worker tests**

Run: `.venv/bin/python -m pytest tests/unit/runtime/test_worker.py tests/integration/runtime/test_scripted_worker.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/runtime tests/fixtures/exchanges/scripted tests/unit/runtime tests/integration/runtime
git commit -m "feat: run bounded exchange workers"
```

### Task 3: OKX Catalog, REST, and Business Errors

**Files:**
- Create: `src/crypto_collector/exchanges/okx/__init__.py`
- Create: `src/crypto_collector/exchanges/okx/catalog.py`
- Create: `src/crypto_collector/exchanges/okx/rest.py`
- Create: `src/crypto_collector/exchanges/okx/errors.py`
- Create: `tests/fixtures/exchanges/okx/manifest.json`
- Create: `tests/fixtures/exchanges/okx/instruments-spot.json`
- Create: `tests/fixtures/exchanges/okx/instruments-swap.json`
- Create: `tests/fixtures/exchanges/okx/tickers.json`
- Create: `tests/fixtures/exchanges/okx/books-full.json`
- Create: `tests/fixtures/exchanges/okx/error-50011.json`
- Test: `tests/contract/exchanges/okx/test_catalog.py`
- Test: `tests/contract/exchanges/okx/test_rest.py`

- [ ] **Step 1: Write failing catalog, turnover, and HTTP-200 error tests**

```python
def test_okx_catalog_separates_spot_and_linear_swap(fixtures) -> None:
    spot = parse_instruments(fixtures.json("instruments-spot.json"), Market.SPOT)
    swaps = parse_instruments(fixtures.json("instruments-swap.json"), Market.PERPETUAL)
    assert spot.by_key("BTC-USDT").wire_symbol("rest") == "BTC-USDT"
    assert swaps.by_key("BTC-USDT-SWAP").settle_asset == "USDT"
    assert all(item.instrument_type == "SWAP" for item in swaps)


def test_okx_top_n_uses_quote_volume_not_contract_count(fixtures) -> None:
    observations = parse_tickers(fixtures.json("tickers.json"), catalog=fixtures.catalog)
    btc = next(item for item in observations if item.instrument_key == "BTC-USDT-SWAP")
    assert btc.quote_turnover == Decimal("1234567.89")
    assert btc.turnover_method == "volCcy24h"


def test_http_200_business_limit_code_is_throttle(fixtures) -> None:
    response = FakeResponse(status_code=200, json=fixtures.json("error-50011.json"))
    error = classify_okx_response(response)
    assert error.retry_action is RetryAction.THROTTLE
    assert error.exchange_code == "50011"


def test_deep_snapshot_keeps_requested_and_effective_interval(fixtures) -> None:
    draft = parse_deep_book(fixtures.response("books-full.json"), request_context=deep_context(30, 120))
    assert draft.logical_stream == "book_deep_snapshot"
    assert draft.rest_metadata.requested_interval_ns == seconds(30)
    assert draft.rest_metadata.effective_interval_ns == seconds(120)
```

- [ ] **Step 2: Run and verify OKX REST modules are missing**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/okx/test_catalog.py tests/contract/exchanges/okx/test_rest.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement anonymous OKX REST endpoints**

Support `GET /api/v5/public/instruments` for `SPOT` and `SWAP`, `/api/v5/market/tickers`, `/api/v5/market/books-full`, `/api/v5/public/time`, public status, candles, and configured derivative reference endpoints. Filter perpetuals by `instType=SWAP`, `settleCcy=USDT`, state, and catalog identity. Every parser preserves unknown fields inside payload and requires only routing fields. Classify JSON `code` before trusting HTTP status; `0` is success and `50011` is throttling. Deep book remains independent from live `books`.

Use only endpoint paths evidenced in `docs/exchanges/okx/sources/api-guide-en.html`. Record method, redacted path/params, timing, status, attempt, rate headers, egress ID, requested/effective interval, and exact response payload.

- [ ] **Step 4: Run OKX REST contract tests**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/okx/test_catalog.py tests/contract/exchanges/okx/test_rest.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/exchanges/okx tests/fixtures/exchanges/okx tests/contract/exchanges/okx
git commit -m "feat: parse okx public rest data"
```

### Task 4: OKX WebSockets and Book Integrity

**Files:**
- Create: `src/crypto_collector/exchanges/okx/ws.py`
- Create: `src/crypto_collector/exchanges/okx/book.py`
- Create: `tests/fixtures/exchanges/okx/ws-session.jsonl`
- Test: `tests/protocol/exchanges/okx/test_book.py`
- Test: `tests/property/exchanges/okx/test_book.py`
- Test: `tests/contract/exchanges/okx/test_ws.py`

- [ ] **Step 1: Write failing heartbeat, maintenance, and true-gap tests**

```python
def test_snapshot_then_linked_update_is_sequence_verified() -> None:
    state = OkxBookState()
    state.apply(snapshot(seq=100, bids=[["10", "1"]], asks=[["11", "1"]]))
    outcome = state.apply(update(prev_seq=100, seq=101, bids=[["10", "2"]]))
    assert outcome.integrity is BookIntegrity.SEQUENCE_VERIFIED


def test_empty_sequence_heartbeat_does_not_create_gap() -> None:
    state = seeded_okx_book(seq=100)
    outcome = state.apply(update(prev_seq=100, seq=100, bids=[], asks=[]))
    assert outcome.action is BookAction.HEARTBEAT
    assert outcome.emit_original_to_stream == "book_live"
    assert outcome.count_as_book_update is False


def test_documented_maintenance_sequence_reset_applies_and_continues() -> None:
    state = seeded_okx_book(seq=100)
    outcome = state.apply(maintenance_reset(prev_seq=100, seq=1))
    assert outcome.action is BookAction.APPLY
    assert outcome.integrity is BookIntegrity.SEQUENCE_VERIFIED
    assert outcome.generation_valid is True
    assert outcome.control_reason == "maintenance_sequence_reset"


def test_real_prev_sequence_mismatch_invalidates_generation() -> None:
    state = seeded_okx_book(seq=100)
    outcome = state.apply(update(prev_seq=98, seq=101, bids=[["10", "2"]]))
    assert outcome.integrity is BookIntegrity.INVALID
    assert outcome.action is BookAction.RECONNECT


def test_post_2026_checksum_zero_is_not_crc_failure() -> None:
    state = seeded_okx_book(seq=100)
    outcome = state.apply(update(prev_seq=100, seq=101, checksum=0))
    assert outcome.integrity is BookIntegrity.SEQUENCE_VERIFIED


@given(start=st.integers(min_value=2, max_value=2**31),
       advances=st.lists(st.integers(min_value=1, max_value=10_000),
                         min_size=1, max_size=100))
def test_any_linked_chain_stays_valid_and_first_true_mismatch_invalidates(start, advances) -> None:
    state = OkxBookState()
    state.apply(snapshot(seq=start, bids=[["10", "1"]], asks=[["11", "1"]]))
    previous = start
    for advance in advances:
        current = previous + advance
        outcome = state.apply(update(prev_seq=previous, seq=current))
        assert outcome.integrity is BookIntegrity.SEQUENCE_VERIFIED
        assert outcome.generation_valid
        previous = current
    mismatch = state.apply(update(prev_seq=previous - 1, seq=previous + 1))
    assert mismatch.integrity is BookIntegrity.INVALID
    assert mismatch.action is BookAction.RECONNECT
    assert not mismatch.generation_valid
```

- [ ] **Step 2: Run and verify OKX WS/book modules are missing**

Run: `.venv/bin/python -m pytest tests/protocol/exchanges/okx/test_book.py tests/property/exchanges/okx/test_book.py tests/contract/exchanges/okx/test_ws.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement public and business sockets**

Implement literal application `ping`/`pong`, subscription ACK/error routing, idle timeout, reconnect backoff, and generation-scoped state. Use the public endpoint for `books`, ticker/BBO, instruments, open interest, funding, liquidation, and platform status; use the business endpoint only for configured anonymous channels such as candles/unaggregated trades. Preserve each raw message before applying minimal integrity state.

For `books`, snapshot replaces state; update requires documented `prevSeqId/seqId` linkage except recognized empty heartbeat and maintenance-reset forms. Preserve a legal empty heartbeat's original payload once in `book_live`, keep the current integrity state, refresh liveness, and do not duplicate it into `_control` or increment the book-update count. A documented maintenance reset has `prevSeqId == prior seqId` and a lower new `seqId`; apply its payload, continue from the lower sequence, retain a valid generation, and emit only an informational reset control event. Ignore checksum value `0` under the archived post-2026 rule. A real mismatch emits a gap control event, marks the generation invalid, closes it, and resubscribes for a new snapshot. Never use periodic deep REST snapshots to repair this state. The Hypothesis suite is a required gate, not an optional fuzz job: it generates valid chains and a single mutated link and proves that only an authoritative snapshot/reset can leave the invalid state.

- [ ] **Step 4: Run OKX protocol tests**

Run: `.venv/bin/python -m pytest tests/protocol/exchanges/okx tests/property/exchanges/okx tests/contract/exchanges/okx -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/exchanges/okx tests/fixtures/exchanges/okx tests/protocol/exchanges/okx tests/property/exchanges/okx tests/contract/exchanges/okx
git commit -m "feat: collect okx public websocket data"
```

### Task 5: OKX Adapter Plan and Scripted End-to-End Session

**Files:**
- Create: `src/crypto_collector/exchanges/okx/adapter.py`
- Create: `src/crypto_collector/exchanges/okx/probe.py`
- Modify: `src/crypto_collector/exchanges/registry.py`
- Modify: `src/crypto_collector/cli.py`
- Test: `tests/integration/exchanges/test_okx_session.py`
- Test: `tests/contract/exchanges/test_registry.py`
- Test: `tests/cli/test_config_probe.py`

- [ ] **Step 1: Write failing plan and session tests**

```python
def test_okx_plan_uses_one_live_book_and_independent_deep_jobs(resolved_okx_config) -> None:
    plan = OkxAdapter().plan(collection_request(resolved_okx_config, instruments=["BTC-USDT"]))
    assert plan.ws.count(channel="books", instrument_key="BTC-USDT") == 1
    assert plan.rest.count(stream="book_deep_snapshot", instrument_key="BTC-USDT") == 1
    assert not plan.rest.first(stream="book_deep_snapshot").requires_generation


def test_okx_research_default_plan_has_the_complete_declared_surface(resolved_okx_config) -> None:
    plan = OkxAdapter().plan(collection_request(resolved_okx_config, instruments=["BTC-USDT"]))
    assert plan.expected_logical_streams() == {
        "instrument", "status", "trade", "ticker", "bbo", "book_live",
        "book_deep_snapshot", "candle_1m", "mark_price", "index_ticker",
        "premium", "funding_rate", "open_interest", "price_limit",
        "insurance_fund", "liquidation", "_control",
    }


@pytest.mark.network
@pytest.mark.asyncio
async def test_scripted_okx_session_closes_valid_raw_manifests(tmp_path, scripted_okx_server) -> None:
    worker = okx_worker(tmp_path, endpoints=scripted_okx_server.endpoints)
    await worker.run_until(lambda status: status.records_by_stream["book_live"] >= 2)
    manifests = await worker.stop(deadline_ns=worker.clock.monotonic_ns() + seconds(5))
    assert_manifest_streams(manifests, worker.plan.expected_logical_streams())
    assert all(validate_manifest(manifest) for manifest in manifests)


@pytest.mark.network
def test_config_probe_uses_okx_provider_and_writes_no_raw_data(config_tree, scripted_okx_server) -> None:
    configure_only_okx(config_tree, endpoints=scripted_okx_server.endpoints)
    result = CliRunner().invoke(app, ["config", "probe", str(config_tree), "--json"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["observed_at_ns"] > 0
    assert body["exchanges"]["okx"]["selection"]["fixed"]["instrument_keys"]
    assert not (config_tree / "data").exists()
```

- [ ] **Step 2: Run and verify adapter integration is missing**

Run: `.venv/bin/python -m pytest tests/integration/exchanges/test_okx_session.py tests/contract/exchanges/test_registry.py tests/cli/test_config_probe.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement complete OKX planning and routing**

Build selected instrument/channel plans from capability and capacity outputs, assign egress before egress-local shard packing, schedule deep/reference REST by priority, and route all research-default streams to distinct logical stream names. Capability probes disable only explicitly optional features; required catalog/trade/book failures reject startup. OKX liquidation records carry top-level `coverage="lossy_window"` outside the native payload.

Implement `OkxAdapter.probe(ProbeRequest)` over the same catalog/probe parsers and worker-local public transports used by runtime, satisfying the existing Plan 03 `ProbeProvider` contract inherited by `ExchangeAdapter`. Register it with the Plan 03 `ProbeEngine` and add `collector config probe CONFIG_PATH [--json]`. At this stage it accepts OKX-only enabled configurations; an enabled unregistered venue fails with `provider_unavailable` instead of being omitted. The command reports `observed_at_ns`, endpoint/egress/quota-group evidence, resolved fixed/Top-N/new selection, shards, requested/effective intervals, disabled optional capabilities, and failures, and creates no raw/state files. A configured public-IP echo can warn when logical egress IDs with distinct quota groups share an address, but neither the address nor proxy value becomes a metric label or report secret.

The scripted server returns every declared research-default route at least once, plus HTTP-200 `50011`, valid and invalid book sequences, heartbeat, disconnect, and schema-added payloads. Assert retry, reconnect, generation change, control records, every expected stream, and raw preservation without external network.

- [ ] **Step 4: Run the full OKX offline vertical slice**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/okx tests/protocol/exchanges/okx tests/integration/exchanges/test_okx_session.py tests/cli/test_config_probe.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/exchanges/okx src/crypto_collector/exchanges/registry.py src/crypto_collector/cli.py tests/integration/exchanges tests/contract/exchanges tests/cli/test_config_probe.py
git commit -m "feat: integrate okx exchange adapter"
```

### Task 6: Supervisor, Admin Socket, Reload Epoch, and Shutdown

**Files:**
- Create: `src/crypto_collector/runtime/state_store.py`
- Create: `src/crypto_collector/runtime/admin.py`
- Create: `src/crypto_collector/runtime/reload.py`
- Create: `src/crypto_collector/runtime/supervisor.py`
- Create: `src/crypto_collector/runtime/signals.py`
- Modify: `src/crypto_collector/cli.py`
- Test: `tests/unit/runtime/test_reload.py`
- Test: `tests/integration/runtime/test_supervisor.py`
- Test: `tests/cli/test_admin.py`
- Test: `tests/cli/test_run.py`

- [ ] **Step 1: Write failing process-isolation, reload, and secret-rotation tests**

```python
def test_one_worker_crash_does_not_restart_healthy_worker(supervisor) -> None:
    before = supervisor.status()
    supervisor.test_only_kill_worker("okx")
    after = supervisor.wait_for_worker_generation("okx", before.okx.generation + 1)
    assert after.binance.generation == before.binance.generation


def test_prepare_failure_keeps_last_committed_epoch(supervisor, invalid_reload) -> None:
    old = supervisor.status().config_epoch
    result = supervisor.reload(invalid_reload)
    assert result.committed is False
    assert supervisor.status().config_epoch == old


def test_restart_only_change_is_rejected_with_exact_keys(supervisor, config_with_new_roots) -> None:
    result = supervisor.reload(config_with_new_roots)
    assert result.committed is False
    assert result.restart_required_keys == ("data_root", "state_root")


def test_exchange_crash_loop_does_not_restart_healthy_workers(supervisor) -> None:
    before = supervisor.status().binance.generation
    supervisor.test_only_crash_repeatedly("okx", attempts=10, within=minutes(10))
    assert supervisor.status().okx.state == "failed_crash_loop"
    assert supervisor.status().binance.generation == before


def test_resume_rejects_until_recovery_gates_pass(supervisor) -> None:
    supervisor.enter_low_disk_pause()
    rejected = supervisor.resume(disk=recovered_disk(cooldown_elapsed=False))
    assert rejected.committed is False
    resumed = supervisor.resume(disk=recovered_disk(cooldown_elapsed=True), writer_probe="ok")
    assert resumed.committed is True


def test_supervisor_commit_crash_converges_after_fresh_supervisor_start(
    supervisor_process, valid_reload,
) -> None:
    old_epoch = supervisor_process.status().config_epoch
    supervisor_process.inject_test_crash(process="supervisor", phase="after_commit_record")
    with pytest.raises(AdminConnectionLost):
        supervisor_process.reload(valid_reload)
    supervisor_process.wait_for_exit()
    restarted = start_supervisor(supervisor_process.config_path)
    status = restarted.wait_until_converged()
    assert status.config_epoch == old_epoch + 1
    assert status.worker_epochs == {status.config_epoch}
    assert restarted.control_events.for_epoch(status.config_epoch) >= {
        "config_reload_planned", "config_reload_committed",
    }


def test_prepare_failure_emits_planned_and_failed_audit_events(supervisor, invalid_reload) -> None:
    result = supervisor.reload(invalid_reload)
    assert result.committed is False
    assert supervisor.control_events.for_epoch(result.epoch) >= {
        "config_reload_planned", "config_reload_failed",
    }


def test_same_secret_reference_with_changed_value_rotates_clients(supervisor, monkeypatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5h://first@127.0.0.1:1080")
    supervisor.start()
    old_generation = supervisor.status().okx.network_generation
    monkeypatch.setenv("SOCKS_URL", "socks5h://second@127.0.0.1:1080")
    supervisor.reload(supervisor.config_path)
    assert supervisor.status().okx.network_generation == old_generation + 1
    event = supervisor.control_events.last("secret_rotated")
    assert event.payload == {"reference": "env:SOCKS_URL"}


def test_collector_run_starts_supervisor_and_worker(run_cli, scripted_okx_config) -> None:
    process = run_cli(["run", str(scripted_okx_config)])
    assert wait_for_admin_status(scripted_okx_config).workers["okx"].state == "running"
    assert run_cli(["stop", "--state-root", state_root(scripted_okx_config)]).exit_code == 0
    assert process.wait(timeout=10) == 0


@pytest.mark.parametrize("command", ["reload", "status", "stop", "resume"])
def test_admin_commands_require_explicit_state_root(run_cli, command) -> None:
    result = run_cli([command])
    assert result.exit_code == 2
    assert "--state-root" in result.stdout


def test_status_uses_only_the_selected_state_root(run_cli, two_supervisors) -> None:
    first, second = two_supervisors
    result = run_cli(["status", "--state-root", str(second.state_root), "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["instance_id"] == second.instance_id
    assert first.instance_id not in result.stdout
```

- [ ] **Step 2: Run and verify supervisor/admin modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/runtime/test_reload.py tests/integration/runtime/test_supervisor.py tests/cli/test_admin.py tests/cli/test_run.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement spawn isolation and durable two-phase reload**

Use `multiprocessing.get_context("spawn")`; pass each worker an immutable reference-only `ConfigBundle`, state paths, and versioned control connection. Secret snapshots are resolved and consumed inside each worker during prepare and are never pickled or sent through IPC. Persist `reload_intent`, prepared worker ACKs, the single supervisor commit point, and audit delivery state in `<state_root>/supervisor_state.sqlite`. Worker state lives under `<state_root>/workers/<exchange>/` with `catalog.sqlite` and `network.sqlite`; the admin socket is `<state_root>/admin.sock`. Before the commit point, abort all prepared workers; after it, every current/restarted worker converges to the new epoch. A freshly started supervisor reads the committed epoch before spawning workers, completing or rolling back an interrupted reload deterministically. Workers close affected raw files under the old config hash before accepting records under the new hash. Emit durable `config_reload_planned`, `config_reload_committed`, and `config_reload_failed` `_control` events with epoch/reference-only context. Reject changes to `data_root`, `state_root`, or the process model before prepare and return the sorted restart-required keys.

Restart only the crashed exchange with full-jitter exponential backoff using the configured 1s base and 60s cap. Ten abnormal exits inside 10 minutes move that exchange to `FAILED_CRASH_LOOP`; a continuous 10-minute healthy period resets its budget. This state leaves the supervisor and other workers alive but makes readiness fail until an operator reload/restart.

`collector run CONFIG_PATH` is the foreground production entry point: it calls the reference-only loader, creates state directories with restrictive permissions, starts the supervisor, spawns exactly one worker for each enabled exchange, installs signal handling, and blocks until an admin/signal stop completes. No worker is started until the initial config epoch is durable. The admin protocol is length-prefixed JSON over `<state_root>/admin.sock`, mode `0600`, with versioned `status`, `reload`, `stop`, and `resume` requests. Peer access is limited by filesystem permissions; never carry secret values. Every admin client requires `--state-root PATH`: `collector reload --state-root PATH`, `collector status --state-root PATH [--json]`, `collector stop --state-root PATH`, and `collector resume --state-root PATH [--exchange ID]`. The path is normalized and validated locally, and the client opens only `PATH/admin.sock`; it does not guess from the current directory, scan processes, read an unrelated config, or fall back to `./state`. Reload tells the selected supervisor to reread the config path stored in its committed epoch. Resume refuses to commit until disk recovery ratio/bytes, cooldown, and writer probe gates pass; a scoped writer pause can resume one exchange, while shared low disk defaults to all. Defaults are 10s admin timeout, 15s reload prepare timeout, and 30s shutdown deadline. Stop order is new requests/subscriptions off, WS close, bounded drain, coordinator sync, file/manifest close, state ACK, process exit.

On every reload, each affected worker resolves one new snapshot separately from config SHA comparison, validates and builds replacement clients from that same snapshot, and compares values only in worker memory. Changed values rotate affected clients and WS generations and emit a reference-only control event; unchanged values do not force a network generation merely because the snapshot object is new.

- [ ] **Step 4: Run runtime integration tests**

Run: `.venv/bin/python -m pytest tests/unit/runtime tests/integration/runtime tests/cli/test_admin.py tests/cli/test_run.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/runtime src/crypto_collector/cli.py tests/unit/runtime tests/integration/runtime tests/cli/test_admin.py tests/cli/test_run.py
git commit -m "feat: supervise transactional exchange workers"
```

### Task 7: Opt-In OKX Live Vertical Check

**Files:**
- Modify: `tests/smoke/test_okx_public_api.py`
- Create: `tests/smoke/test_okx_connector_live.py`
- Create: `docs/operations/evidence/okx-live-check.md`

- [ ] **Step 1: Mark existing public tests and add a connector-generated live test**

```python
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.getenv("RUN_LIVE_API_TESTS") != "1",
                       reason="set RUN_LIVE_API_TESTS=1 to contact OKX"),
]


@pytest.mark.asyncio
async def test_okx_connector_live_writes_spot_and_swap_raw(tmp_path) -> None:
    config = live_okx_fixed_pair_config(tmp_path, pairs=["BTC/USDT"], rotate_interval="15s")
    result = await run_worker_for(config, duration=seconds(20))
    assert result.exit_reason == "test_deadline"
    assert result.catalog_instruments("spot") > 0
    assert result.catalog_instruments("perpetual") > 0
    assert result.records("spot", "trade") > 0
    assert result.records("perpetual", "ticker") > 0
    assert result.records("spot", "book_live") > 0
    assert result.records("perpetual", "book_live") > 0
    assert result.records("perpetual", "funding_rate") > 0
    assert result.records("perpetual", "open_interest") > 0
    assert result.required_route_failures == ()
    assert result.quiet_optional_routes <= {"liquidation"}
    assert result.subscription_acknowledged("liquidation")
    assert all(validate_manifest(path) for path in result.manifests)
```

- [ ] **Step 2: Verify the live cases skip offline**

Run: `.venv/bin/python -m pytest tests/smoke/test_okx_public_api.py tests/smoke/test_okx_connector_live.py -q`

Expected: every case skips and no socket is opened.

- [ ] **Step 3: Run the explicit live check**

Run: `RUN_LIVE_API_TESTS=1 .venv/bin/python -m pytest tests/smoke/test_okx_public_api.py tests/smoke/test_okx_connector_live.py -q -m live`

Expected: PASS or a recorded environmental skip with an exact regional/network reason. A protocol assertion failure is not converted to skip.

- [ ] **Step 4: Inspect artifacts and record evidence**

Validate zstd decompression, envelope schemas, both-market required route/ACK coverage, control generation events, closed manifests, hashes, and absence of secret values. Quiet event-driven channels such as liquidation pass only with a successful subscription ACK plus no protocol error; other required routes need a response/record. Record date, refreshed official-source hashes, config SHA, endpoint region, route-level counts/ACKs, and test output in `docs/operations/evidence/okx-live-check.md`.

- [ ] **Step 5: Commit**

```bash
git add tests/smoke/test_okx_public_api.py tests/smoke/test_okx_connector_live.py docs/operations/evidence/okx-live-check.md
git commit -m "test: verify okx connector live"
```

- [ ] **Step 6: Run the repository-wide offline regression gate**

Run: `.venv/bin/python scripts/verify_role_locks.py --require-entry collector`

Expected: all four clean lock installs pass and the collector role imports its production entry modules while retaining the forbidden-extra checks.

Run: `.venv/bin/python -m pytest -q -m "not live and not performance"`

Expected: PASS with every live test skipped and no external socket opened.
