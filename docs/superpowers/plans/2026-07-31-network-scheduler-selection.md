# Network, Scheduler, and Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build explicit direct/SOCKS egress clients, per-quota-group budgets/cooldowns, per-egress transport health, a priority REST scheduler, and deterministic fixed/Top-N/new-listing admission.

**Architecture:** Each exchange worker owns transport state per `(exchange, egress_id)` and IP budget state per `(exchange, quota_group)`, persisting cooldowns across restarts. Instruments first receive a rendezvous-hash sticky egress, then deterministic egress-local shard packing; REST jobs enter a priority scheduler that stretches low-priority deep snapshots when capacity is insufficient.

**Tech Stack:** asyncio, HTTPX, websockets, python-socks, SQLite, Pydantic, pytest, pytest-asyncio, Hypothesis, respx.

---

### Task 1: Secret-Safe HTTP and WebSocket Client Factories

**Files:**
- Create: `src/crypto_collector/network/__init__.py`
- Create: `src/crypto_collector/network/models.py`
- Create: `src/crypto_collector/network/clients.py`
- Create: `src/crypto_collector/observability/redaction.py`
- Create: `tests/support/socks5_server.py`
- Test: `tests/unit/network/test_clients.py`
- Test: `tests/unit/observability/test_redaction.py`
- Test: `tests/integration/network/test_socks_clients.py`

- [ ] **Step 1: Write failing direct/proxy and redaction tests**

```python
def test_direct_http_client_ignores_host_proxy_environment(monkeypatch) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://unexpected.invalid:8080")
    spec = build_http_client_spec(Egress(id="direct", type="direct"),
                                  secrets=SecretSnapshot.empty())
    assert spec.trust_env is False
    assert spec.proxy is None


def test_direct_websocket_disables_auto_proxy_detection() -> None:
    spec = build_websocket_connect_spec(
        Egress(id="direct", type="direct"), "wss://example.test/ws",
        secrets=SecretSnapshot.empty(),
    )
    assert spec.proxy is None


def test_socks5h_resolves_proxy_reference_only_at_client_creation(monkeypatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:password@127.0.0.1:1080")
    egress = Egress(id="socks-1", type="socks5h", url=SecretRef.parse("env:SOCKS_URL"))
    secrets = SecretSnapshot.resolve_all([egress.url])
    spec = build_http_client_spec(egress, secrets=secrets)
    ws_spec = build_websocket_connect_spec(
        egress, "wss://example.test/ws", secrets=secrets,
    )
    assert spec.proxy.reveal().startswith("socks5h://")
    assert "password" not in repr(spec)
    assert "password" not in repr(ws_spec)


@pytest.mark.parametrize("text", [
    "https://user:pass@example.test/path?token=abc",
    "Authorization: Bearer abc",
    "x-oss-security-token: abc",
    "AWS_SECRET_ACCESS_KEY=abc",
])
def test_redactor_removes_supported_secret_forms(text: str) -> None:
    assert "abc" not in redact(text)
    assert "pass" not in redact(text)


@pytest.mark.network
@pytest.mark.asyncio
async def test_socks5h_http_and_websocket_delegate_dns_to_proxy(loopback_socks5, loopback_apps) -> None:
    ref = SecretRef.parse("env:SOCKS_URL")
    secrets = SecretSnapshot.from_test_values({
        ref: loopback_socks5.url(scheme="socks5h", credentials=("u", "secret")),
    })
    clients = build_clients(socks_egress(ref), secrets=secrets)
    assert (await clients.http.get("http://venue.invalid/catalog")).status_code == 200
    async with clients.websocket.connect("ws://venue.invalid/ws") as websocket:
        assert await websocket.recv() == "ready"
    assert loopback_socks5.requested_domains == ["venue.invalid", "venue.invalid"]
    assert "secret" not in repr(clients)
    assert "secret" not in loopback_socks5.redacted_logs


@pytest.mark.network
@pytest.mark.asyncio
async def test_direct_clients_ignore_host_proxy_environment(monkeypatch, loopback_apps) -> None:
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:1")
    clients = build_clients(direct_egress(), secrets=SecretSnapshot.empty())
    assert (await clients.http.get(loopback_apps.http_url)).status_code == 200
    async with clients.websocket.connect(loopback_apps.ws_url) as websocket:
        assert await websocket.recv() == "ready"
```

- [ ] **Step 2: Run and verify imports fail**

Run: `.venv/bin/python -m pytest tests/unit/network/test_clients.py tests/unit/observability/test_redaction.py tests/integration/network/test_socks_clients.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement explicit transport specs**

```python
@dataclass(frozen=True, slots=True)
class HttpClientSpec:
    proxy: SecretValue | None
    trust_env: bool = False

    def __repr__(self) -> str:
        return f"HttpClientSpec(proxy={'configured' if self.proxy else None!r}, trust_env={self.trust_env!r})"


@dataclass(frozen=True, slots=True)
class WebSocketConnectSpec:
    uri: str
    proxy: SecretValue | None
    open_timeout: int = 10
    close_timeout: int = 10
    max_queue: int = 16

    def __repr__(self) -> str:
        return (f"WebSocketConnectSpec(uri={self.uri!r}, "
                f"proxy={'configured' if self.proxy else None!r}, "
                f"open_timeout={self.open_timeout!r}, "
                f"close_timeout={self.close_timeout!r}, max_queue={self.max_queue!r})")


def build_http_client_spec(egress: Egress, *, secrets: SecretSnapshot) -> HttpClientSpec:
    proxy = None if egress.type == "direct" else secrets.value_for(egress.url)
    return HttpClientSpec(proxy=proxy, trust_env=False)


def build_websocket_connect_spec(
    egress: Egress, uri: str, *, secrets: SecretSnapshot,
) -> WebSocketConnectSpec:
    proxy = None if egress.type == "direct" else secrets.value_for(egress.url)
    return WebSocketConnectSpec(uri=uri, proxy=proxy)
```

Direct egress uses `SecretSnapshot.empty()` so both builders retain one signature. Builders never resolve a reference and never store plaintext strings in repr-able objects. Client constructors are the only consumers of `SecretValue.reveal()`: HTTPX receives `proxy=None | spec.proxy.reveal()`, `trust_env=False`, explicit timeouts/limits, and `follow_redirects=False`; `websockets.connect` receives explicit `proxy=None | spec.proxy.reveal()` plus the timeout/queue fields. The redactor must parse URLs and redact userinfo plus known secret query/header/env names. All exception logging passes through it. Verify the foundation's locked HTTPX SOCKS and `python-socks[asyncio]` dependencies are installed; never use host `HTTP_PROXY`, `HTTPS_PROXY`, or `ALL_PROXY` implicitly.

The function-scoped `tests/support/socks5_server.py` implements only the SOCKS5 greeting, optional username/password auth, and CONNECT required by the tests. It records the requested address type/domain before proxying to an explicitly mapped loopback HTTP or WebSocket server, so `socks5h` remote-name resolution is observable without external DNS. It rejects any destination not in the test mapping and stores only redacted diagnostics.

- [ ] **Step 4: Run client and redaction tests**

Run: `.venv/bin/python -m pytest tests/unit/network/test_clients.py tests/unit/observability/test_redaction.py tests/integration/network/test_socks_clients.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/network src/crypto_collector/observability tests/support/socks5_server.py tests/unit/network tests/unit/observability tests/integration/network/test_socks_clients.py
git commit -m "feat: create explicit direct and socks clients"
```

### Task 2: Sticky Assignment and Persistent Egress Health

**Files:**
- Modify: `src/crypto_collector/network/__init__.py`
- Create: `src/crypto_collector/network/assignment.py`
- Create: `src/crypto_collector/network/health.py`
- Create: `src/crypto_collector/network/state_store.py`
- Test: `tests/unit/network/test_assignment.py`
- Test: `tests/unit/network/test_health.py`
- Test: `tests/integration/network/test_egress_failover.py`

- [ ] **Step 1: Write failing stickiness and restart tests**

```python
def test_rendezvous_assignment_is_order_independent() -> None:
    key = "binance/spot/BTCUSDT/book_live"
    first = choose_egress(key, [egress("a"), egress("b"), egress("c")])
    second = choose_egress(key, [egress("c"), egress("a"), egress("b")])
    assert first.id == second.id


def test_unhealthy_egress_is_skipped_only_for_new_generation() -> None:
    assignment = StickyAssignment.create(
        "okx/spot/BTC-USDT/books", egress("a"), generation=7
    )
    health = HealthSnapshot(unavailable=frozenset({("okx", "a")}))
    assert assignment.egress_id == "a"
    assert choose_egress(assignment.key, [egress("a"), egress("b")], health).id == "b"


def test_ban_survives_worker_restart(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "okx-network.sqlite")
    store.record_ban(
        exchange="okx", quota_group="nat-a", until_unix_ns=9_000, reason="429"
    )
    store.close()
    reopened = EgressStateStore.open(tmp_path / "okx-network.sqlite")
    assert reopened.load_quota("okx", "nat-a").ban_until_unix_ns == 9_000


def test_assignment_precedes_deterministic_egress_local_sharding() -> None:
    assignments = assign_instruments(
        ["BTCUSDT", "ETHUSDT", "SOLUSDT"],
        exchange="binance", market="spot", channel="trade",
        egresses=[egress("a", max_ws_connections=2), egress("b", max_ws_connections=2)],
        subscriptions_per_connection=2,
    )
    shards = pack_egress_shards(
        assignments,
        egresses=[egress("a", max_ws_connections=2), egress("b", max_ws_connections=2)],
        subscriptions_per_connection=2,
    )
    assert all(len(shard.instrument_keys) <= 2 for shard in shards)
    assert all(len({item.egress_id for item in shard.assignments}) == 1 for shard in shards)


@pytest.mark.network
@pytest.mark.asyncio
async def test_failed_proxy_moves_only_the_new_connection_generation(
    failover_socks_pair, loopback_apps, tmp_path,
) -> None:
    first_proxy, _second_proxy = failover_socks_pair
    first_assignment = choose_egress(assignment_key, egresses)
    async with build_clients(first_assignment, secrets=secrets) as first_generation:
        assert (await first_generation.http.get(loopback_apps.proxied_http_url)).status_code == 200
    await first_proxy.close()
    with EgressStateStore.open(tmp_path / "okx-network.sqlite") as store:
        store.record_transport_failure(
            exchange="okx", egress_id=first_assignment.id, reason="connect_error"
        )
        admitted = store.admit_health(
            exchange="okx", egresses=egresses, now_unix_ns=1, now_monotonic_ns=1
        )
        second_assignment = choose_egress(
            assignment_key, egresses, health=admitted.snapshot(now_monotonic_ns=1)
        )
        assert second_assignment.id != first_assignment.id
```

- [ ] **Step 2: Run and verify assignment modules are absent**

Run: `.venv/bin/python -m pytest tests/unit/network/test_assignment.py tests/unit/network/test_health.py tests/integration/network/test_egress_failover.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement stable rendezvous hashing and SQLite state**

Use `sha256(f"{exchange}/{market}/{instrument_key}/{channel}\0{egress_id}".encode()).digest()` as the unsigned score and select the highest healthy candidate with remaining configured capacity. Assignment keys have four conceptual non-empty components: parse the first two `/` separators as exchange and market, the final separator as channel, and preserve the complete middle substring as `instrument_key`. This is required for stable keys such as Kraken Spot `BTC/USDT`; exchange, market, and channel themselves may not contain `/`. Validate those slash constraints before iterating instruments so an empty cohort cannot bypass them. Reject duplicate egress IDs and duplicate instrument keys rather than resolving them by input order. `choose_egress()` returns the selected immutable `Egress`; `StickyAssignment.create(..., generation=N)` freezes the decision that the runtime binds to a connection generation.

Do not include a shard ID in the hash. `assign_instruments()` first sorts instruments, then chooses the highest-ranked healthy egress with remaining capacity. The explicit capacity of one egress for this assignment cohort is `egress.max_ws_connections * subscriptions_per_connection`, where the latter value comes from the capability registry or an admitted conservative override. `pack_egress_shards()` then sorts by canonical assignment key and chunks per egress without exceeding either limit. Capacity is checked before returning any partial plan.

Plan 03 owns only assignment, health, and immutable generation-decision records. Plan 04 owns opening, invalidating, closing, and incrementing actual connection generations. A transport failure never mutates a `StickyAssignment` or migrates an open client in place; the Plan 04 runtime closes the failed generation and asks Plan 03 to choose for the next generation. The integration test exercises this boundary with the real local SOCKS clients from Task 1, but does not introduce a second production generation manager here.

All persisted `*_until_ns` and `last_success_ns` values are UTC Unix epoch nanoseconds; `last_latency_ns` is an elapsed duration. Monotonic values are process-local and must never be stored. `EgressStateStore.admit_health(..., now_unix_ns, now_monotonic_ns)` opens one explicit WAL read transaction, atomically reads all quota and transport restrictions, and converts each remaining epoch duration exactly once into an immutable process-local monotonic deadline. The returned `AdmittedHealth` also carries immutable `QuotaProbeAdmission` and `TransportProbeAdmission` tokens containing the restriction revision captured by that same transaction. Thereafter `AdmittedHealth.snapshot(now_monotonic_ns=...)` classifies probe eligibility using monotonic time only. It keeps every restricted egress unavailable after expiry until an explicit successful public probe; a persisted revision change requires explicit re-admission and is never silently cached inside the store. SQLite uses WAL, `synchronous=FULL`, a busy timeout, exact schema version fencing, and separate transport and quota tables:

```sql
CREATE TABLE quota_state (
  exchange TEXT NOT NULL,
  quota_group TEXT NOT NULL,
  ban_until_ns INTEGER NOT NULL,
  cooldown_until_ns INTEGER NOT NULL,
  current_rate_multiplier TEXT NOT NULL,
  last_reason TEXT,
  restriction_revision INTEGER NOT NULL,
  PRIMARY KEY (exchange, quota_group)
);
CREATE TABLE egress_state (
  exchange TEXT NOT NULL,
  egress_id TEXT NOT NULL,
  consecutive_transport_failures INTEGER NOT NULL,
  transport_cooldown_until_ns INTEGER NOT NULL,
  last_success_ns INTEGER,
  last_latency_ns INTEGER,
  last_reason TEXT,
  restriction_revision INTEGER NOT NULL,
  PRIMARY KEY (exchange, egress_id)
);
```

Quota and transport restriction updates use `MAX(existing_until, observed_until)` so an out-of-order response cannot shorten an active restriction, and increment the corresponding `restriction_revision`. Probe success accepts only a token minted by that store's admission, checks its monotonic deadline, and conditionally clears only the captured revision. Each immutable mint binds its store identity to every public claim (kind, exchange, quota-group or egress key, restriction revision, and monotonic deadline); the aggregate `AdmittedHealth` mint also binds its deadline set and exact child-token identities. Claim matching is type-sensitive and accepts only the exact private mint type; claim keys must be non-empty exact built-in `str` values, so subclasses with overridden equality and duck-typed mints cannot impersonate another key or store. The store additionally records a weak reference and frozen original claims for each exact child admission object returned by a successfully completed `admit_health()` call. Probe success requires that same registered object and original claims; merely reading the store identity and calling an underscored constructor, copying/replacing a token, or mutating an issued object's fields cannot create authority. Weak-reference cleanup prevents repeated health admissions from creating an unbounded registry. Probe-success authority also requires the exact `QuotaProbeAdmission` or `TransportProbeAdmission` class, rejecting subclasses before their overridable methods are called. Probe success never compares the persisted epoch deadline to a fresh wall clock after admission, so a backward wall-clock jump cannot prolong an already eligible probe and a late success can never clear a newer 429, ban, cooldown, or transport failure. A process restart opens and admits this state before scheduling any request. Multiple egresses that share one `(exchange, quota_group)` share quota restriction state, while transport failures remain isolated by `(exchange, egress_id)`.

Opening applies WAL mode and acquires `BEGIN IMMEDIATE` before reading `user_version`, so a concurrent initializer cannot race the exact version fence. The WAL switch itself can return `SQLITE_BUSY` before the transaction exists; initialization therefore retries only `SQLITE_BUSY`/`SQLITE_LOCKED` with bounded exponential delay, 100ms per-attempt SQLite waits, and one five-second monotonic deadline covering WAL setup and schema initialization. The deadline is checked before every subsequent attempt, so contention cannot expire and then succeed through one extra initialization. It restores the normal five-second connection busy timeout only after successful initialization. A database already declaring version 1 is validated without running any creation statement; fresh/version-0 initialization creates, validates, and sets version 1 in that same transaction. Validation uses `PRAGMA table_xinfo` for the complete ordered column contract, including affinity, nullability, composite-primary-key ordinal, and the hidden/generated flag. It also uses `PRAGMA index_xinfo` to require the exact primary-key columns in ascending order with `BINARY` collation, then compares the complete non-internal `sqlite_schema` object set and canonical table DDL. Extra tables, indexes, views, or triggers and semantic DDL drift such as `CHECK`, non-key `COLLATE`, `STRICT`, or `WITHOUT ROWID` fail the version fence. `set_rate_multiplier()` accepts only exact built-in, finite `Decimal` values in `(0, 1]`, because Task 3 may shrink admitted rate but may never exceed hard configured capacity; values are stored with `str(Decimal)` without ambient-context normalization. The Task 2 assignment, admission, snapshot, probe-token, state-store, and stale-probe symbols deliberately exported from `network/__init__.py` are part of this public API.

- [ ] **Step 4: Run assignment and state tests**

Run: `.venv/bin/python -m pytest tests/unit/network/test_assignment.py tests/unit/network/test_health.py tests/integration/network/test_egress_failover.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/network tests/unit/network tests/integration/network/test_egress_failover.py
git commit -m "feat: persist sticky egress health"
```

### Task 3: Token Budgets and Retry Classification

**Files:**
- Create: `src/crypto_collector/network/rate_limit.py`
- Create: `src/crypto_collector/network/retry.py`
- Test: `tests/unit/network/test_rate_limit.py`
- Test: `tests/unit/network/test_retry.py`
- Test: `tests/property/network/test_rate_limit.py`
- Test: `tests/property/network/test_retry.py`

- [ ] **Step 1: Write failing deterministic-clock tests**

```python
def test_token_bucket_is_keyed_by_exchange_quota_group_and_endpoint() -> None:
    clock = FakeClock(0)
    budgets = BudgetRegistry(clock)
    budgets.add(("binance", "shared-nat", "depth"), capacity=10, refill_per_second=1)
    assert budgets.try_acquire(("binance", "shared-nat", "depth"), cost=10)
    assert not budgets.try_acquire(("binance", "shared-nat", "depth"), cost=1)
    assert budgets.try_acquire(("okx", "shared-nat", "depth"), cost=1, default_capacity=10)


@pytest.mark.parametrize(
    ("status", "retry_after", "expected"),
    [(429, "3", RetryAction.THROTTLE), (418, "120", RetryAction.BAN),
     (503, None, RetryAction.BACKOFF), (400, None, RetryAction.DO_NOT_RETRY)],
)
def test_http_retry_classification(status, retry_after, expected) -> None:
    assert classify_http(status, retry_after=retry_after).action is expected


def test_full_jitter_never_exceeds_cap() -> None:
    rng = random.Random(7)
    assert all(0 <= full_jitter_ns(5, base_ns=1_000, cap_ns=10_000, rng=rng) <= 10_000
               for _ in range(100))


def test_rest_retry_stops_at_attempt_or_job_deadline() -> None:
    policy = retry_policy(max_attempts=5)
    assert policy.decide(attempt=5, now_ns=0, deadline_ns=seconds(60)).retry is False
    decision = policy.decide(attempt=1, now_ns=0, deadline_ns=seconds(2), retry_after="3")
    assert decision.retry is False
    assert decision.reason == "retry_after_exceeds_deadline"


@given(attempt=st.integers(min_value=0, max_value=20),
       base_ns=st.integers(min_value=1, max_value=seconds(10)),
       cap_ns=st.integers(min_value=1, max_value=minutes(2)),
       seed=st.integers(min_value=0, max_value=2**32 - 1))
def test_full_jitter_is_always_inside_exponential_cap(attempt, base_ns, cap_ns, seed) -> None:
    delay = full_jitter_ns(attempt, base_ns, cap_ns, random.Random(seed))
    assert 0 <= delay <= min(cap_ns, base_ns * 2**attempt)


@given(bucket_actions())
def test_token_bucket_never_goes_negative_or_above_capacity(actions) -> None:
    bucket, clock = token_bucket(capacity=100)
    for action in actions:
        apply_bucket_action(bucket, clock, action)
        assert Decimal(0) <= bucket.tokens <= bucket.capacity


@given(retry_scenarios())
def test_retry_decision_never_crosses_attempt_or_monotonic_deadline(scenario) -> None:
    decision = scenario.policy.decide(**scenario.inputs)
    if decision.retry:
        assert scenario.inputs["attempt"] < scenario.policy.max_attempts
        assert scenario.inputs["now_ns"] + decision.delay_ns <= scenario.inputs["deadline_ns"]
```

- [ ] **Step 2: Run and verify budget/retry modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/network/test_rate_limit.py tests/unit/network/test_retry.py tests/property/network/test_rate_limit.py tests/property/network/test_retry.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement endpoint token buckets and bounded retry decisions**

Token refill uses injected monotonic time and never exceeds capacity. Apply server rate headers through exchange-specific observers without allowing a malformed header to increase configured hard capacity. Retry only anonymous GET, WebSocket connect, and subscribe. A REST job defaults to at most five attempts and may never sleep/retry beyond its monotonic deadline; a later periodic run is a new job. One injected `Clock` supplies both domains: retry-job deadlines and sleeps use `monotonic_ns()`, while HTTP-date parsing and persisted restriction deadlines use `time_ns()`. `Retry-After` accepts integer seconds and HTTP-date; explicit exchange ban codes persist state. Schema/parse failures consume a channel error budget but do not loop network retries. WS generations may reconnect indefinitely with a 60s backoff cap, but cannot bypass active egress/quota-group circuits.

```python
now_monotonic_ns = clock.monotonic_ns()
now_unix_ns = clock.time_ns()
delay_ns = max(parsed_retry_after_ns, full_jitter_ns(attempt, base_ns, cap_ns, rng))
# RetryPolicy compares now_monotonic_ns + delay_ns with the job's monotonic deadline.
if decision.action is RetryAction.BAN:
    state_store.record_ban(
        exchange=exchange,
        quota_group=quota_group,
        until_unix_ns=now_unix_ns + delay_ns,
        reason=decision.reason,
    )
elif decision.action is RetryAction.THROTTLE:
    budget.shrink(multiplier=0.5, floor=minimum_rate)
```

- [ ] **Step 4: Run deterministic budget/retry tests**

Run: `.venv/bin/python -m pytest tests/unit/network/test_rate_limit.py tests/unit/network/test_retry.py tests/property/network/test_rate_limit.py tests/property/network/test_retry.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/network/rate_limit.py src/crypto_collector/network/retry.py tests/unit/network tests/property/network
git commit -m "feat: enforce per-quota-group request budgets"
```

### Task 4: Priority REST Scheduler and Interval Stretching

**Files:**
- Create: `src/crypto_collector/scheduler/__init__.py`
- Create: `src/crypto_collector/scheduler/models.py`
- Create: `src/crypto_collector/scheduler/rest.py`
- Create: `src/crypto_collector/scheduler/interval_observability.py`
- Test: `tests/unit/scheduler/test_rest.py`
- Test: `tests/unit/scheduler/test_interval_observability.py`

- [ ] **Step 1: Write failing priority and hysteresis tests**

```python
@pytest.mark.asyncio
async def test_bootstrap_runs_before_deep_snapshot() -> None:
    scheduler = RestScheduler(fake_budgets(tokens=1))
    await scheduler.submit(job("deep", priority=RestPriority.DEEP_SNAPSHOT))
    await scheduler.submit(job("bootstrap", priority=RestPriority.LIVE_BOOTSTRAP))
    assert (await scheduler.next_ready()).id == "bootstrap"


@pytest.mark.asyncio
async def test_future_high_priority_does_not_block_ready_lower_priority(fake_clock) -> None:
    scheduler = RestScheduler(fake_budgets(tokens=10), clock=fake_clock)
    await scheduler.submit(job("future-bootstrap", priority=RestPriority.LIVE_BOOTSTRAP,
                               ready_monotonic_ns=seconds(30)))
    await scheduler.submit(job("ready-deep", priority=RestPriority.DEEP_SNAPSHOT,
                               ready_monotonic_ns=0))
    assert (await scheduler.next_ready()).id == "ready-deep"
    assert fake_clock.monotonic_ns() == 0


@pytest.mark.asyncio
async def test_expired_waiting_job_is_dropped_without_dispatch(fake_clock) -> None:
    scheduler = RestScheduler(fake_budgets(tokens=10), clock=fake_clock)
    await scheduler.submit(job("expired", ready_monotonic_ns=seconds(20),
                               deadline_ns=seconds(10)))
    fake_clock.advance(seconds(20))
    assert await scheduler.next_ready_or_none() is None
    assert scheduler.expired_ids() == ("expired",)


def test_overloaded_deep_interval_stretches_and_emits_context() -> None:
    plan = solve_interval(requested_ns=30_000_000_000, jobs=100, cost=50,
                          available_tokens_per_second=50, policy="stretch_with_warning")
    assert plan.effective_ns == 100_000_000_000
    assert plan.warning.requested_ns == 30_000_000_000
    assert plan.warning.affected_symbols == 100


def test_capacity_recovery_steps_down_without_request_spike() -> None:
    controller = IntervalController(current_ns=120_000_000_000, recovery_step=0.20,
                                    healthy_refreshes_required=3)
    assert controller.recover_toward(30_000_000_000) == 120_000_000_000
    assert controller.recover_toward(30_000_000_000) == 120_000_000_000
    assert controller.recover_toward(30_000_000_000) == 96_000_000_000


def test_periodic_replaceable_jobs_coalesce_instead_of_backlogging() -> None:
    scheduler = RestScheduler(fake_budgets(tokens=0))
    scheduler.submit_nowait(job("deep-btc", logical_key=("btc", "deep"), scheduled_ns=1))
    scheduler.submit_nowait(job("deep-btc-new", logical_key=("btc", "deep"), scheduled_ns=2))
    assert scheduler.pending_ids() == ("deep-btc-new",)


def test_deep_interval_above_max_is_capacity_failure() -> None:
    with pytest.raises(CapacityError, match="max effective interval"):
        solve_interval(requested_ns=seconds(30), jobs=1000, cost=250,
                       available_tokens_per_second=1, max_effective_ns=minutes(15))


def test_interval_change_is_visible_in_log_metric_control_and_rest_metadata() -> None:
    sinks = recording_interval_sinks()
    change = interval_change(exchange="okx", endpoint="books-full",
                             requested_ns=seconds(30), effective_ns=minutes(2),
                             healthy_egress_count=2,
                             symbols=("BTC-USDT", "ETH-USDT"), config_sha256="a" * 64,
                             cause="capacity_shortfall", direction="stretch")
    published = IntervalChangePublisher(sinks).publish(change)
    expected_context = {
        "event_id": published.event_id,
        "requested_interval_ns": seconds(30),
        "effective_interval_ns": minutes(2),
        "endpoint": "books-full",
        "healthy_egress_count": 2,
        "affected_instrument_keys": ["BTC-USDT", "ETH-USDT"],
        "config_sha256": "a" * 64,
        "cause": "capacity_shortfall",
        "direction": "stretch",
    }
    assert {key: sinks.logs.one()[key] for key in expected_context} == expected_context
    assert {key: sinks.controls.one().payload[key] for key in expected_context} == expected_context
    assert sinks.metrics.counter("collector_interval_changes_total",
                                 exchange="okx", endpoint="books-full",
                                 direction="stretch").value == 1
    assert sinks.metrics.gauge("collector_requested_interval_seconds",
                               exchange="okx", endpoint="books-full").value == 30
    assert sinks.metrics.gauge("collector_effective_interval_seconds",
                               exchange="okx", endpoint="books-full").value == 120
    assert sinks.metrics.gauge("collector_healthy_egresses",
                               exchange="okx", endpoint="books-full").value == 2
    assert sinks.metrics.gauge("collector_interval_affected_instruments",
                               exchange="okx", endpoint="books-full").value == 2
    assert sinks.metrics.label_names == {"exchange", "endpoint", "direction"}
    assert sinks.controls.one().logical_stream == "_control"
    assert published.rest_metadata.requested_interval_ns == seconds(30)
    assert published.rest_metadata.effective_interval_ns == minutes(2)
    assert "config_sha256" not in sinks.metrics.label_names
    assert "instrument" not in sinks.metrics.label_names
```

- [ ] **Step 2: Run and verify scheduler modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/scheduler/test_rest.py tests/unit/scheduler/test_interval_observability.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement the five priority classes**

Keep two bounded heaps plus a logical-key index: future jobs use `(ready_monotonic_ns, insertion_sequence)`, while currently dispatchable jobs use `(priority, insertion_sequence)`. Before each dispatch, move every now-ready future job into the ready heap and discard/report jobs whose monotonic deadline has passed; sleep until the earliest future readiness only when the ready heap is empty. This prevents a future high-priority job from idling capacity while lower-priority work is ready. Priorities are live bootstrap/gap recovery, catalog/status/time, core derivative REST, deep snapshot, then replaceable reference data. A job carries requested/effective interval, endpoint cost, eligible egress IDs, generation-stickiness requirement, deadline, attempt, logical coalescing key, and control context. High priorities are strict among currently ready jobs; periodic deep/reference jobs are replaceable and coalesce by logical key across both heaps so throttling cannot create stale backlog. Stretching is deterministic from admitted symbols and healthy quota-group budgets, capped by the configured 15m default. Fixed/required work above that cap is a capacity error; other symbols return to admission policy. Require three healthy refreshes, then shorten by 20% per refresh.

Every effective-interval change creates one immutable `IntervalChange` with a generated event ID and publishes it synchronously to three injected sinks before the new schedule becomes active: a structured JSON warning, bounded-cardinality Prometheus counter/gauges, and a reserved `_control` `NativeEventDraft`. The log and control payload include requested/effective interval, endpoint, healthy-egress count, affected instrument keys, config SHA, cause, and direction. Metrics expose requested/effective seconds, healthy-egress count, affected-instrument count, and change count as numeric values; their only labels are the bounded `exchange`, `endpoint`, and where applicable `direction`. Config hashes and instrument keys are never metric labels. Failure to enqueue the reserved control record rejects the schedule change and enters the writer-critical path rather than creating a silent stretch. The same requested/effective values are attached to every resulting REST envelope through `RestMetadata`. Startup calculation, periodic stretch/recovery, and reload all use this publisher; unchanged intervals emit nothing.

- [ ] **Step 4: Run scheduler tests**

Run: `.venv/bin/python -m pytest tests/unit/scheduler/test_rest.py tests/unit/scheduler/test_interval_observability.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/scheduler tests/unit/scheduler
git commit -m "feat: schedule prioritized public rest jobs"
```

### Task 5: Catalog State and Fixed/Top-N/New-Listing Union

**Files:**
- Create: `src/crypto_collector/selection/__init__.py`
- Create: `src/crypto_collector/selection/models.py`
- Create: `src/crypto_collector/selection/catalog_store.py`
- Create: `src/crypto_collector/selection/selector.py`
- Test: `tests/unit/selection/test_catalog_store.py`
- Test: `tests/unit/selection/test_selector.py`

- [ ] **Step 1: Write failing first-run, turnover, and grace tests**

```python
def test_first_catalog_is_baseline_not_mass_new_listing(tmp_path) -> None:
    store = CatalogStore.open(tmp_path / "catalog.sqlite")
    changes = store.apply_snapshot(exchange="binance", market="spot", observed_at_ns=100,
                                   instruments=[instrument("BTCUSDT"), instrument("NEWUSDT")])
    assert changes.new_listings == ()


def test_recent_official_tradable_time_can_enter_on_first_baseline(tmp_path) -> None:
    store = CatalogStore.open(tmp_path / "catalog.sqlite")
    changes = store.apply_snapshot(
        exchange="bitget", market="perpetual", observed_at_ns=ns("2026-07-31T12:00:00Z"),
        instruments=[instrument("NEWUSDT", tradable_at_ns=ns("2026-07-31T11:00:00Z"),
                                tradable_at_source="exchange")], initial_lookback_ns=hours(72))
    assert [item.instrument_key for item in changes.new_listings] == ["NEWUSDT"]


def test_selection_is_union_with_fixed_priority_and_top_n_per_quote() -> None:
    fixed = ResolvedFixedSelection(instrument_keys=frozenset({"PF_XBTUSD"}))
    result = select(catalog(), fixed=fixed, quotes=["USDT"], top_n=2,
                    active_new=["NEWUSDT"], now_ns=1_000)
    assert result.selected == frozenset({"PF_XBTUSD", "BTCUSDT", "ETHUSDT", "NEWUSDT"})
    assert result.reason("PF_XBTUSD").fixed is True


def test_top_n_exit_grace_prevents_boundary_churn() -> None:
    previous = selected_top("ALTUSDT", last_selected_ns=100)
    result = select(updated_catalog_without_alt(), previous=previous, now_ns=120, exit_grace_ns=30)
    assert "ALTUSDT" in result.selected
```

- [ ] **Step 2: Run and verify selection modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/selection -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement persistent catalog provenance and selection reasons**

Persist stable instrument key, all protocol wire symbols, canonical pair, quote/base/settlement, status, lifecycle fields, `tradable_at`, its source, first/last seen, turnover value/method/currency, and raw catalog reference. Compare Top N only within one exchange/market/quote. Never treat contract count as quote turnover. The selector accepts only `ResolvedFixedSelection`, never raw user strings; Task 6 resolves those against a current venue catalog. Fixed instrument keys bypass quote filters. New-listing expiry is `tradable_at + capture_duration`; announcements are hints until the catalog confirms tradability. Return a reason bitset plus rank and admission priority for every instrument.

- [ ] **Step 4: Run selection tests**

Run: `.venv/bin/python -m pytest tests/unit/selection -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/selection tests/unit/selection
git commit -m "feat: select fixed top and new symbols"
```

### Task 6: Fixed-Pair Resolution, Capacity Admission, and Probe Contracts

**Files:**
- Create: `src/crypto_collector/selection/capacity.py`
- Create: `src/crypto_collector/selection/fixed.py`
- Create: `src/crypto_collector/config/probe_contracts.py`
- Test: `tests/unit/selection/test_capacity.py`
- Test: `tests/unit/selection/test_fixed.py`
- Test: `tests/unit/config/test_probe_contracts.py`

- [ ] **Step 1: Write failing resolution, admission, and provider-contract tests**

```python
def test_capacity_trims_lowest_top_then_latest_new_but_never_fixed() -> None:
    result = admit(
        candidates=[fixed("BTC"), top("ETH", rank=1), top("ALT", rank=20),
                    new("NEW1", first_seen_ns=10), new("NEW2", first_seen_ns=20)],
        slots=3, policy="degrade_low_priority_with_warning")
    assert result.admitted == ("BTC", "NEW1", "NEW2")
    assert result.rejected == ("ALT", "ETH")


def test_fixed_pairs_over_capacity_always_fail() -> None:
    with pytest.raises(CapacityError, match="fixed pairs"):
        admit([fixed("BTC"), fixed("ETH")], slots=1,
              policy="degrade_low_priority_with_warning")


def test_canonical_fixed_pair_resolves_to_one_stable_instrument_key() -> None:
    catalog = fake_catalog(instruments=[instrument("BTC-USDT", canonical_pair="BTC/USDT")])
    result = resolve_fixed_requests(["BTC/USDT"], catalog)
    assert result.instrument_keys == frozenset({"BTC-USDT"})


@pytest.mark.parametrize("request", ["UNKNOWN/USDT", "AMBIGUOUS/USDT"])
def test_unknown_or_ambiguous_canonical_fixed_pair_fails(request, catalog_with_ambiguity) -> None:
    with pytest.raises(FixedPairResolutionError):
        resolve_fixed_requests([request], catalog_with_ambiguity)


@pytest.mark.asyncio
async def test_probe_engine_is_provider_neutral_and_timestamped(fake_probe_provider) -> None:
    result = await ProbeEngine(clock=FakeClock(time_ns=123)).run(
        config_bundle(), providers={"okx": fake_probe_provider},
    )
    assert result.observed_at_ns == 123
    assert result.exchanges["okx"].selection.fixed.instrument_keys == {"BTC-USDT"}
```

- [ ] **Step 2: Run and verify resolution/capacity/probe contracts are missing**

Run: `.venv/bin/python -m pytest tests/unit/selection/test_capacity.py tests/unit/selection/test_fixed.py tests/unit/config/test_probe_contracts.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement deterministic resolution, admission, and provider-neutral probing**

Resolve each fixed request within one `(exchange, market)` catalog. An exact stable `instrument_key` match wins; otherwise a canonical-pair match must produce exactly one tradable instrument. Zero or multiple matches are startup/probe failures with candidate keys, never guessed by string rewriting. Return `ResolvedFixedSelection` for the selector. Offline `config check` reports the configured requests but labels them `catalog_unresolved`; it cannot claim an actual fixed selection without a current provider catalog.

Calculate available WS shards/subscriptions and HTTP concurrency from healthy `(exchange, egress_id)` states, but calculate endpoint/IP demand from `(exchange, quota_group)`. `fail` rejects any shortfall. `degrade_low_priority_with_warning` rejects lowest-ranked Top N first, then new listings from latest `first_seen` to earliest, preserving fixed pairs. Emit rejected symbols, exact budget, and config SHA.

Define dependency-injected `ProbeProvider` and `ProbeEngine` contracts over catalog, public time, date-gated capability, endpoint budget, and egress reachability results. The engine receives already constructed providers, produces a timestamped `ProbeReport`, and never imports venue packages or constructs clients itself. It performs fixed resolution, selection, admission, sharding, and interval solution over provider results. Plan 04 wires the command for OKX; Plan 05 registers the remaining four providers. This task intentionally contains no production exchange HTTP path.

- [ ] **Step 4: Run all network, scheduler, selection, and probe-contract tests**

Run: `.venv/bin/python -m pytest tests/unit/network tests/unit/scheduler tests/unit/selection tests/unit/config/test_probe_contracts.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/selection src/crypto_collector/config/probe_contracts.py tests/unit/selection tests/unit/config/test_probe_contracts.py
git commit -m "feat: resolve fixed pairs and admit capacity"
```

- [ ] **Step 6: Run the repository-wide offline regression gate**

Run: `.venv/bin/python -m pytest -q -m "not live and not performance"`

Expected: PASS with sockets denied except marked loopback fixtures.
