# Operations and Acceptance Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the three services observable and deployable, enforce disk-pressure safety, exercise the complete data lifecycle and fault matrix, and produce final durability/leak/security evidence.

**Architecture:** Workers publish bounded cumulative metric snapshots to the supervisor; high-cardinality research context stays in status/log/control data. Collector, materializer, and archiver remain separate Compose services sharing only closed files, state paths, and explicit pause signals.

**Tech Stack:** Prometheus client, JSON logging, local HTTP health server, Docker/Compose, pytest system tests, synthetic exchange servers, Linux performance benchmarks.

---

### Task 1: Structured Logging, Metrics, and Status Snapshots

**Files:**
- Create: `src/crypto_collector/observability/logging.py`
- Create: `src/crypto_collector/observability/metrics.py`
- Create: `src/crypto_collector/observability/status.py`
- Create: `src/crypto_collector/runtime/metric_snapshot.py`
- Test: `tests/unit/observability/test_logging.py`
- Test: `tests/unit/observability/test_metrics.py`
- Test: `tests/unit/observability/test_status.py`

- [ ] **Step 1: Write failing redaction, label, and cardinality tests**

```python
def test_json_log_contains_context_and_no_secret(secret_canaries) -> None:
    line = render_log(
        level="ERROR", event="request_failed", exchange="okx", market="spot",
        instrument_key="BTC-USDT", egress_id="socks-a", error=secret_canaries.exception)
    body = json.loads(line)
    assert body["event"] == "request_failed"
    assert body["exchange"] == "okx"
    assert not any(canary in line for canary in secret_canaries.values)


def test_histograms_have_bounded_labels() -> None:
    registry = build_registry()
    labels = metric_labels(registry, "collector_durability_lag_seconds")
    assert labels == {"exchange", "market", "stream"}
    forbidden = {"instrument_key", "wire_symbol", "config_sha256", "connection_id",
                 "connection_generation", "error", "proxy_url"}
    assert not labels & forbidden


def test_reloads_do_not_create_config_hash_series() -> None:
    registry = build_registry()
    for index in range(100):
        ingest_snapshot(metric_snapshot(config_sha256=f"{index:064x}"))
    assert series_count(registry) <= METRIC_SERIES_BUDGET


def test_per_symbol_gauges_only_contain_current_selected_set() -> None:
    aggregator = MetricAggregator()
    aggregator.apply(snapshot(selected={"BTC-USDT", "ETH-USDT"}))
    aggregator.apply(snapshot(selected={"BTC-USDT"}))
    assert aggregator.symbol_series == {"BTC-USDT"}
```

- [ ] **Step 2: Run and verify observability modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/observability -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement cumulative worker snapshots and bounded aggregation**

Every exchange worker sends `MetricSnapshotV1` over control IPC at a bounded interval. It contains cumulative counters/histogram buckets and current gauges, never market records. Supervisor calculates deltas by worker instance, handles restart resets, and exposes one Prometheus registry. Histograms aggregate by exchange/market/stream; per-instrument gauges are restricted to the current selected set and removed on deselection. Config hashes, connection IDs/generations, exact errors, rejected-instrument lists, and proxy details appear only in status, JSON logs, and `_control`.

Snapshot-test all metric names, help text, labels, bucket boundaries, and an explicit maximum series count for the research-default selected-set cardinality. JSON logging always passes URLs, headers, exceptions, and config fragments through the shared redactor.

- [ ] **Step 4: Run observability tests**

Run: `.venv/bin/python -m pytest tests/unit/observability -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/observability src/crypto_collector/runtime/metric_snapshot.py tests/unit/observability
git commit -m "feat: expose bounded collector telemetry"
```

### Task 2: Liveness, Readiness, and Disk-Pressure Coordination

**Files:**
- Create: `src/crypto_collector/observability/http.py`
- Create: `src/crypto_collector/runtime/disk.py`
- Create: `src/crypto_collector/runtime/pause.py`
- Test: `tests/unit/observability/test_http.py`
- Test: `tests/unit/runtime/test_disk.py`
- Test: `tests/integration/runtime/test_disk_pause.py`

- [ ] **Step 1: Write failing health and threshold tests**

```python
@pytest.mark.parametrize("state", [
    "RUNNING", "DEGRADED", "PAUSED_WRITER", "PAUSED_LOW_DISK", "FAILED_CRASH_LOOP",
])
def test_livez_is_ok_while_supervisor_loop_is_alive(state) -> None:
    response = health_app(supervisor_state=state).get("/livez")
    assert response.status_code == 200


@pytest.mark.parametrize("state", [
    "PAUSED_WRITER", "PAUSED_LOW_DISK", "FAILED_CRASH_LOOP", "STARTING",
])
def test_readyz_reports_unready_without_requesting_restart(state) -> None:
    response = health_app(required_worker_state=state).get("/readyz")
    assert response.status_code == 503
    assert response.json()["state"] == state


def test_disk_state_uses_more_conservative_ratio_or_bytes() -> None:
    policy = disk_policy(warning_ratio=.15, critical_ratio=.05, recovery_ratio=.20,
                         warning_bytes=100, critical_bytes=20, recovery_bytes=200)
    assert classify_disk(total=1000, free=40, policy=policy) is DiskState.CRITICAL
    assert classify_disk(total=1000, free=120, policy=policy) is DiskState.WARNING


@pytest.mark.asyncio
async def test_critical_disk_pauses_collectors_but_archiver_continues(system) -> None:
    await system.inject_free_space(ratio=.04)
    await system.wait_for_state("PAUSED_LOW_DISK")
    assert system.materializer.accepting_new_jobs is False
    assert system.archiver.running is True
    assert all(worker.connections_open == 0 for worker in system.collector.workers)


def test_manual_resume_uses_admin_gate(system) -> None:
    system.enter_low_disk_pause()
    assert system.cli("resume", "--state-root", system.state_root).exit_code != 0
    system.inject_free_space(ratio=.25, bytes_above_recovery=True)
    system.advance_past_recovery_cooldown()
    assert system.cli("resume", "--state-root", system.state_root).exit_code == 0
    assert system.collector.ready
```

- [ ] **Step 2: Run and verify health/disk modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/observability/test_http.py tests/unit/runtime/test_disk.py tests/integration/runtime/test_disk_pause.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement three-level disk state and service actions**

Warning pauses new materializer jobs, raises archiver scheduling priority, and permits deletion only through ordinary cleanup eligibility. Critical asks every collector to unsubscribe, drain, sync, close manifests, and enter `PAUSED_LOW_DISK`; materializer stays paused and archiver continues. No threshold deletes unverified data. Recovery requires both configured ratio/bytes, cooldown, a successful writer probe, and admin `resume` by default; auto-resume is opt-in and hysteretic but uses the same gate.

`/livez` reflects process/event-loop liveness. `/readyz` returns detailed required-worker/service readiness and is 503 for paused states. Compose uses `/livez`, not `/readyz`, so an intentional safety pause does not cause a restart loop. Bind loopback by default.

- [ ] **Step 4: Run health and disk integration tests**

Run: `.venv/bin/python -m pytest tests/unit/observability/test_http.py tests/unit/runtime/test_disk.py tests/integration/runtime/test_disk_pause.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/observability/http.py src/crypto_collector/runtime/disk.py src/crypto_collector/runtime/pause.py tests/unit/observability/test_http.py tests/unit/runtime/test_disk.py tests/integration/runtime/test_disk_pause.py
git commit -m "feat: pause safely under disk pressure"
```

### Task 3: Hardened Images and Compose Services

**Files:**
- Modify: `Dockerfile`
- Modify: `.dockerignore`
- Create: `compose.yaml`
- Create: `docker/entrypoint.sh`
- Create: `config/docker/config.yaml`
- Test: `tests/system/test_compose_config.py`
- Test: `tests/system/test_container_permissions.py`

- [ ] **Step 1: Write failing Compose boundary tests**

```python
def test_compose_has_three_top_level_services() -> None:
    model = load_compose("compose.yaml")
    assert set(model.services) == {"collector", "materializer", "archiver"}
    assert all(service.healthcheck.test[-1].endswith("/livez")
               for service in model.services.values())


def test_service_dependency_sets_are_separate() -> None:
    assert image_packages("collector").isdisjoint({"pyarrow", "boto3", "oss2"})
    assert "pyarrow" in image_packages("materializer")
    assert {"boto3", "oss2"} <= image_packages("archiver")


def test_containers_are_non_root_and_config_is_read_only() -> None:
    model = load_compose("compose.yaml")
    assert all(service.user not in {None, "0", "root"} for service in model.services.values())
    assert all(config_mount(service).read_only for service in model.services.values())


def test_every_service_command_has_an_explicit_config_path() -> None:
    model = load_compose("compose.yaml")
    assert model.services["collector"].command == ["run", "/config/config.yaml"]
    assert model.services["materializer"].command[:2] == ["materialize", "/config/config.yaml"]
    assert model.services["archiver"].command == ["archive", "run", "/config/config.yaml"]
```

- [ ] **Step 2: Run and verify Compose artifacts are missing/incomplete**

Run: `.venv/bin/python -m pytest tests/system/test_compose_config.py tests/system/test_container_permissions.py -q`

Expected: FAIL.

- [ ] **Step 3: Build role-specific non-root images**

Use one multi-stage Dockerfile with `collector`, `materializer`, and `archiver` targets installed from their corresponding hash-locked requirements. Copy an already-built wheel into each runtime image and copy the versioned workload YAMLs read-only to `/app/benchmarks/workloads/` in collector images. Run as a fixed non-root UID/GID, use read-only config, and mount writable data/state/staging explicitly. Compose commands are exactly `collector run /config/config.yaml`, `collector materialize /config/config.yaml`, and `collector archive run /config/config.yaml`; no role guesses a config path. Compose owns only top-level service restart; the collector supervisor owns exchange children.

Expose health/metrics only on the Compose network unless configured otherwise. Inject secrets through environment references or Docker secret files under `/run/secrets`, referenced as `file:/run/secrets/name`. Validate filesystem archive root differs from data root and mount guard exists. Do not bake config secrets or local data into images.

- [ ] **Step 4: Build and validate all targets**

Run: `docker compose config --quiet`

Expected: exit `0`.

Run: `docker build --target collector -t crypto-collector:test .`

Run: `docker build --target materializer -t crypto-materializer:test .`

Run: `docker build --target archiver -t crypto-archiver:test .`

Expected: all three commands exit `0` with distinct target/tag pairs; then run the two system tests successfully. Never retag a materializer/archiver target as `crypto-collector:test`.

- [ ] **Step 5: Commit**

```bash
git add Dockerfile .dockerignore compose.yaml docker config/docker tests/system/test_compose_config.py tests/system/test_container_permissions.py
git commit -m "build: add isolated compose services"
```

### Task 4: Complete Offline Lifecycle System Test

**Files:**
- Create: `tests/system/support/five_exchange_lab.py`
- Create: `tests/system/test_data_lifecycle.py`
- Create: `tests/system/test_consumer_isolation.py`
- Create: `tests/system/fixtures/lifecycle-config.yaml`

- [ ] **Step 1: Write the failing raw-to-restore lifecycle test**

```python
@pytest.mark.network
def test_five_exchange_file_lifecycle(tmp_path, five_exchange_lab) -> None:
    system = five_exchange_lab.start(tmp_path, fixed_pairs_only=True, rotate_interval="5s")
    system.wait_for_raw_manifests(exchange_count=5)
    system.stop_collectors_cleanly()

    derived = system.materialize(intervals=["30s", "1m"])
    assert {"trade_bars", "book_live_features", "book_deep_features",
            "derivative_windows", "quality_windows"} <= derived.datasets
    assert derived.canonical_hashes_stable_on_rerun()

    archive = system.archive_to_required_filesystem(compression="auto")
    assert archive.all_required_committed
    restored = system.restore_one_raw_receipt()
    assert restored.source_sha256_verified

    cleaned = system.cleanup_after_advancing_clock_past_all_gates()
    assert cleaned.tombstone_exists
    assert cleaned.source_manifest_exists


@pytest.mark.network
def test_slow_or_dead_consumers_do_not_change_collector(system) -> None:
    baseline = system.collector_snapshot()
    system.pause_materializer()
    system.make_archive_target_block()
    system.collect_for(seconds=20)
    after = system.collector_snapshot()
    assert after.connections_healthy
    assert after.durability_lag_max_ns <= baseline.durability_slo_ns
    assert after.queue_overflow_count == baseline.queue_overflow_count
```

- [ ] **Step 2: Run and verify lifecycle fixtures are missing**

Run: `.venv/bin/python -m pytest tests/system/test_data_lifecycle.py tests/system/test_consumer_isolation.py -q`

Expected: FAIL during fixture setup.

- [ ] **Step 3: Implement deterministic five-exchange lab**

Run local HTTP/WS scripted servers for all five adapters, one Spot and one perpetual fixed instrument each. Generate event times spanning 30s/1m boundaries, valid books, a silent expected stream, lossy liquidation silence, catalog changes, and late data. Start real supervisor workers and writer, then real materializer and filesystem archiver as separate subprocesses using the same config/data/state layout as Compose.

Assert no process reaches into another process queue, `.partial` is ignored by consumers, manifest/receipt/ACK commit ordering holds, hashes validate, live/deep remain separate, and cleanup waits for the retention fence and exclusive lease.

- [ ] **Step 4: Run lifecycle twice from clean temporary roots**

Run the following command twice, allowing each run to create a fresh pytest temporary root:

`.venv/bin/python -m pytest tests/system/test_data_lifecycle.py tests/system/test_consumer_isolation.py -q`

Expected: PASS with identical canonical derived hashes and no external network.

- [ ] **Step 5: Commit**

```bash
git add tests/system/support tests/system/fixtures tests/system/test_data_lifecycle.py tests/system/test_consumer_isolation.py
git commit -m "test: exercise complete data lifecycle"
```

### Task 5: Fault-Injection Matrix and Secret Canary Scan

**Files:**
- Create: `tests/system/test_fault_matrix.py`
- Create: `tests/system/test_secret_canaries.py`
- Create: `tests/system/fixtures/secret-canaries.json`
- Create: `ops/prometheus/alerts.yml`
- Test: `tests/unit/observability/test_alert_rules.py`

- [ ] **Step 1: Write the parameterized failure matrix**

```python
@pytest.mark.parametrize(("fault","expected_scope","expected_state"), [
    ("ws_disconnect", "channel", "RECONNECTING"),
    ("book_sequence_gap", "channel", "RECONNECTING"),
    ("rest_429", "quota_group", "THROTTLED"),
    ("queue_overflow", "channel", "RECONNECTING"),
    ("sync_delay", "exchange", "PAUSED_WRITER"),
    ("sync_eio", "exchange", "PAUSED_WRITER"),
    ("worker_sigkill", "exchange", "RESTARTING"),
    ("disk_critical", "all_collectors", "PAUSED_LOW_DISK"),
    ("archive_multipart_interrupt", "archive_target", "RETRYING"),
    ("materializer_sigkill", "materializer", "REPLAYING"),
])
@pytest.mark.network
def test_fault_is_scoped_and_recorded(system, fault, expected_scope, expected_state) -> None:
    result = system.inject(fault)
    assert result.scope == expected_scope
    assert result.state == expected_state
    assert result.control_or_recovery_evidence
    assert result.unaffected_services_continue


@pytest.mark.network
def test_sync_delay_exercises_running_watchdog_and_stops_exchange_inputs(system) -> None:
    result = system.inject_blocking_sync_past_critical_age(exchange="okx")
    assert result.watchdog_task_observed_critical_age
    assert result.state == "PAUSED_WRITER"
    assert result.exchange_connections_open == 0
    assert result.accepted_count_after_pause == result.accepted_count_at_pause
    assert result.partial_or_recovery_evidence
    assert result.other_exchange_workers_healthy


def test_secret_canaries_absent_from_every_output(system, secret_canaries) -> None:
    system.inject_all_secret_forms(secret_canaries)
    system.exercise_errors_status_metrics_manifests_receipts_and_tracebacks()
    for artifact in system.text_artifacts():
        assert not any(canary in artifact.read_text(errors="replace")
                       for canary in secret_canaries.values)
```

- [ ] **Step 2: Run and verify fault/canary tests fail before fixtures exist**

Run: `.venv/bin/python -m pytest tests/system/test_fault_matrix.py tests/system/test_secret_canaries.py tests/unit/observability/test_alert_rules.py -q`

Expected: FAIL.

- [ ] **Step 3: Implement reproducible faults and alert rules**

Inject protocol and I/O failures through scripted transports/backends, process signals, fake disk stats, and local target failures. The `sync_delay` fault blocks the real sync backend while the real coordinator watchdog task advances on an injected clock; it must not substitute a direct checker call. Every fault asserts state transition, scope, durable evidence, recovery behavior, and unaffected service progress. Never add production environment switches that trigger faults.

Create Prometheus rules for durability SLO breach/critical age, worker paused/crash loop, queue high-water/overflow, stale expected streams, reconnect/gap rate, quota-group ban/throttle, low disk, materializer backlog/failure, required archive backlog/failure, and optional abandonment. Alert labels stay bounded; detailed identifiers come from linked status/control context.

- [ ] **Step 4: Run the system fault suite**

Run: `.venv/bin/python -m pytest tests/system/test_fault_matrix.py tests/system/test_secret_canaries.py tests/unit/observability/test_alert_rules.py -q`

Expected: PASS with no secret canary and no silent gap/loss.

- [ ] **Step 5: Commit**

```bash
git add tests/system/test_fault_matrix.py tests/system/test_secret_canaries.py tests/system/fixtures/secret-canaries.json ops/prometheus/alerts.yml tests/unit/observability/test_alert_rules.py
git commit -m "test: cover operational fault matrix"
```

### Task 6: Full Performance Gate and Long Soak

**Files:**
- Create: `src/crypto_collector/benchmarks/full.py`
- Create: `src/crypto_collector/benchmarks/soak.py`
- Create: `tests/performance/test_full_collector.py`
- Create: `tests/performance/test_soak_report.py`
- Create: `docs/operations/performance-acceptance.md`

- [ ] **Step 1: Write failing numerical acceptance tests**

```python
def test_full_report_requires_every_record_durable_within_slo() -> None:
    report = load_report("full-collector.json")
    report.durability_lag_max_ns = 1_000_000_001
    assert evaluate_full_report(report).accepted is False


def test_full_report_requires_exact_immutable_runtime_image() -> None:
    report = passing_full_report(expected_image_id="sha256:" + "a" * 64,
                                 runtime_image_id="sha256:" + "b" * 64)
    assert evaluate_full_report(report).accepted is False


def test_soak_rejects_rss_or_fd_growth() -> None:
    report = soak_report(duration_hours=4, rss_slope_bytes_per_hour=10_000_000,
                         fd_growth_after_warmup=30)
    limits = soak_limits(max_rss_slope_bytes_per_hour=4_194_304, max_fd_growth=10)
    assert evaluate_soak(report, limits).accepted is False


def test_soak_requires_full_four_hours_and_matching_image() -> None:
    report = passing_soak(duration_hours=3.99,
                          expected_image_id="sha256:" + "a" * 64,
                          runtime_image_id="sha256:" + "b" * 64)
    assert evaluate_soak(report, soak_limits()).accepted is False
```

- [ ] **Step 2: Run and verify full/soak benchmark modules are missing**

Run: `.venv/bin/python -m pytest tests/performance/test_full_collector.py tests/performance/test_soak_report.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement production-mode qualification**

Use `research-default-v1.yaml` at 2x rates/cardinality for at least 10 minutes against the declared Linux container, storage device, filesystem, and mount options. Unlike the writer-only Gate B, `benchmarks.full` starts loopback scripted HTTP/WebSocket endpoints for all five adapters, the real supervisor/exchange processes, selector, egress/rate scheduler, ingress, and writer. It must exercise both markets, reconnect/control traffic, REST scheduling, and exact active-file cardinality without contacting the internet. Report input bursts/bytes, active files, queue levels/loss evidence, REST schedule load, CPU/RSS/FD, sync IOPS/durations, durability p50/p95/p99/max, worker states, and per-service backlogs. Acceptance requires every accepted record at or below 1.000s, accepted equals durable, zero unrecorded loss, and all numeric RSS/FD limits.

Then run at expected 1x load for at least 4 hours. Reject post-warmup RSS growth above 4MiB/hour, FD growth above 10, monotonic backlog growth without an injected target outage, or reconnect/sync failure leak. Store image/config/capability/workload/lock hashes in the report.

- [ ] **Step 4: Run gates on the actual target environment**

Run:

```bash
install -d -m 0750 /declared/target/data /declared/target/state/reports
docker image inspect --format '{{.Id}}' crypto-collector:test \
  > /declared/target/state/reports/collector-acceptance-image.id
COLLECTOR_ACCEPTANCE_IMAGE_ID="$(sed -n '1p' /declared/target/state/reports/collector-acceptance-image.id)"
docker run --rm \
  --network none \
  --env COLLECTOR_RUNTIME_IMAGE_ID="$COLLECTOR_ACCEPTANCE_IMAGE_ID" \
  --mount type=bind,src=/declared/target/data,dst=/data \
  --mount type=bind,src=/declared/target/state,dst=/state \
  "$COLLECTOR_ACCEPTANCE_IMAGE_ID" python -m crypto_collector.benchmarks.full \
  --workload /app/benchmarks/workloads/research-default-v1.yaml \
  --multiplier 2 --duration 10m --data-root /data \
  --expected-image-id "$COLLECTOR_ACCEPTANCE_IMAGE_ID" \
  --report /state/reports/full-collector.json

docker run --rm \
  --network none \
  --env COLLECTOR_RUNTIME_IMAGE_ID="$COLLECTOR_ACCEPTANCE_IMAGE_ID" \
  --mount type=bind,src=/declared/target/data,dst=/data \
  --mount type=bind,src=/declared/target/state,dst=/state \
  "$COLLECTOR_ACCEPTANCE_IMAGE_ID" python -m crypto_collector.benchmarks.soak \
  --workload /app/benchmarks/workloads/research-default-v1.yaml \
  --multiplier 1 --duration 4h --warmup 15m --sample-interval 10s \
  --data-root /data --state-root /state \
  --max-rss-slope-bytes-per-hour 4194304 --max-fd-growth 10 \
  --expected-image-id "$COLLECTOR_ACCEPTANCE_IMAGE_ID" \
  --report /state/reports/soak-4h.json
```

Expected: both commands exit `0`, both reports' runtime/expected image IDs exactly equal `collector-acceptance-image.id`, and both reject missing/malformed/mismatched IDs. The soak report must state `duration_ns >= 14400000000000`, `warmup_ns`, sample count, post-warmup RSS regression slope, FD baseline/peak/final/growth, backlog slopes, reconnect/sync failures, every identity hash listed above, and `accepted=true`; the CLI must return non-zero when any acceptance predicate fails or the run ends early. Record the literal target image ID, device, filesystem, and mount options alongside both reports. A macOS/Docker Desktop bind mount is development evidence only unless it is the declared deployment target.

- [ ] **Step 5: Commit redacted evidence and report validators**

```bash
git add src/crypto_collector/benchmarks/full.py src/crypto_collector/benchmarks/soak.py tests/performance docs/operations/performance-acceptance.md docs/operations/evidence
git commit -m "test: qualify collector performance and soak"
```

If the writer stage fails its 1s gate, stop final acceptance and return to the storage design; do not hide the failure by reducing expected active files or stream coverage.

### Task 7: CI, Schemas, Runbooks, and Final Acceptance Record

**Files:**
- Create: `.github/workflows/offline.yml`
- Create: `.github/workflows/performance.yml`
- Modify: `.github/workflows/live-exchange-smoke.yml`
- Create: `docs/reference/config.md`
- Create: `docs/reference/raw-schema.md`
- Create: `docs/reference/derived-schema.md`
- Create: `docs/reference/archive-schema.md`
- Create: `docs/reference/paths.md`
- Create: `docs/operations/runbooks/collector.md`
- Create: `docs/operations/runbooks/writer-pause.md`
- Create: `docs/operations/runbooks/low-disk.md`
- Create: `docs/operations/runbooks/api-ban.md`
- Create: `docs/operations/runbooks/materializer.md`
- Create: `docs/operations/runbooks/archive-restore.md`
- Create: `docs/operations/final-acceptance.md`
- Modify: `README.md`
- Test: `tests/docs/test_examples.py`
- Test: `tests/docs/test_schema_examples.py`

- [ ] **Step 1: Write failing documentation/schema example tests**

```python
def test_every_json_example_validates_against_named_schema() -> None:
    for example in discover_schema_examples("docs/reference"):
        assert example.schema.model_validate_json(example.body)


def test_documented_config_passes_offline_check(tmp_path) -> None:
    config_path = extract_config_example("docs/reference/config.md", tmp_path)
    result = CliRunner().invoke(app, ["config", "check", str(config_path), "--json"])
    assert result.exit_code == 0


def test_offline_workflow_never_enables_live_tests() -> None:
    workflow = load_yaml(".github/workflows/offline.yml")
    text = json.dumps(workflow)
    assert "RUN_LIVE_API_TESTS=1" not in text
    assert "pytest" in text
```

- [ ] **Step 2: Run and verify docs/workflow checks fail**

Run: `.venv/bin/python -m pytest tests/docs -q`

Expected: FAIL because reference/runbook artifacts are absent.

- [ ] **Step 3: Write operator-facing contracts and CI**

Document install/locks, complete configuration precedence and secret refs, static check versus online probe, fixed/Top-N/new selection, quota groups, live/deep separation, raw/derived/archive paths and schemas, revision reading, status/health/metrics, Compose operation, safe shutdown/reload, backup/verify/restore, cleanup gates, and every paused/degraded recovery procedure. Include commands with expected exit/state and never include real credentials.

Offline CI installs `requirements/dev.lock` with hashes, runs Ruff, mypy, docs/schema checks, and `pytest -m "not live and not performance"` with sockets disabled. Live workflow stays manual/scheduled with environment secrets and preserves skips. Performance workflow is manual/self-hosted on the declared target storage and uploads redacted reports; it does not claim success on a generic hosted runner.

Populate `final-acceptance.md` with each approved spec completion item, command, date, commit/image/config/capability/workload/lock hashes, result, evidence path, and explicit environmental skips. A skip is allowed only for external provider/environment availability, not a failing offline contract.

- [ ] **Step 4: Run final verification from a clean environment**

Run:

```bash
.venv/bin/python scripts/verify_role_locks.py --require-entry collector --require-entry materializer --require-entry archiver
.venv/bin/ruff check src tests
.venv/bin/mypy src
.venv/bin/python -m pytest -q -m "not live and not performance"
docker compose config --quiet
git diff --check
```

Expected: every command exits `0`; live tests remain skipped unless explicitly invoked; the worktree contains only intended final-acceptance evidence changes.

- [ ] **Step 5: Commit the operational handoff**

```bash
git add .github/workflows docs/reference docs/operations README.md tests/docs
git commit -m "docs: complete collector operations handoff"
```
