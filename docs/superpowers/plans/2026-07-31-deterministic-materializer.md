# Deterministic Materializer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert closed raw manifests into deterministic configurable 30s+ Parquet trade, live-book, deep-book, derivative, and quality windows without affecting collection.

**Architecture:** The materializer discovers only valid closed manifests, holds shared source leases, derives deterministic source locators, and writes hourly immutable revisions. Dataset builders share window/time/quality contracts but never join exchanges or bridge live and deep books.

**Tech Stack:** Python 3.11+, Decimal, python-zstandard, PyArrow, simplejson, SQLite, pytest, Hypothesis, golden fixtures.

---

### Task 1: Closed-Manifest Discovery and Canonical Source Order

**Files:**
- Create: `src/crypto_collector/materializer/__init__.py`
- Create: `src/crypto_collector/materializer/models.py`
- Create: `src/crypto_collector/materializer/discovery.py`
- Create: `src/crypto_collector/materializer/raw_reader.py`
- Create: `src/crypto_collector/materializer/ordering.py`
- Test: `tests/unit/materializer/test_discovery.py`
- Test: `tests/property/materializer/test_ordering.py`

- [ ] **Step 1: Write failing closed-only and shuffled-order tests**

```python
def test_discovery_ignores_partial_or_unverified_manifest(tmp_path) -> None:
    valid = write_closed_raw_part(tmp_path, manifest=True, checksum_valid=True)
    write_partial_raw_part(tmp_path)
    write_closed_raw_part(tmp_path, manifest=False)
    write_closed_raw_part(tmp_path, manifest=True, checksum_valid=False)
    discovered = discover_raw_inputs(tmp_path)
    assert [item.manifest_path for item in discovered] == [valid.manifest_path]


@given(st.permutations(SOURCE_ROWS))
def test_canonical_event_order_is_independent_of_discovery_order(rows) -> None:
    ordered = canonical_event_order(rows)
    assert [row.source_locator for row in ordered] == EXPECTED_LOCATORS


@given(st.permutations(BOOK_ROWS_FROM_TWO_WORKER_INSTANCES))
def test_book_replay_order_uses_worker_monotonic_causality(rows) -> None:
    ordered = canonical_replay_order(rows)
    assert [row.source_locator for row in ordered] == EXPECTED_CAUSAL_LOCATORS


def test_reader_holds_shared_lease_for_iteration(tmp_path) -> None:
    source = write_closed_raw_part(tmp_path)
    with RawManifestReader(source.manifest_path) as reader:
        with pytest.raises(SourceLeaseBusy):
            SourceLease.exclusive(source.lease_path, blocking=False)
        assert list(reader)
```

- [ ] **Step 2: Run and verify materializer inputs are missing**

Run: `.venv/bin/python -m pytest tests/unit/materializer/test_discovery.py tests/property/materializer/test_ordering.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement deterministic source locators**

```python
@dataclass(frozen=True, slots=True, order=True)
class SourceLocator:
    manifest_sha256: str
    zero_based_record_index: int


@dataclass(frozen=True, slots=True)
class SourceRecord:
    envelope: RawEnvelope
    locator: SourceLocator
    effective_event_time_ns: int
    time_source: TimeSource


def canonical_event_sort_key(record: SourceRecord) -> tuple[int, int, str, int]:
    return (
        record.effective_event_time_ns,
        record.envelope.received_at_ns,
        record.locator.manifest_sha256,
        record.locator.zero_based_record_index,
    )
```

Discovery requires a closed manifest, referenced closed data, matching size/SHA-256, supported schema, and no tombstone indicating local deletion. Sort input manifests by SHA-256, not filesystem path. The reader acquires a shared lease, streams concatenated zstd frames, validates every envelope, and assigns the zero-based physical record index from that manifest.

Freeze two distinct deterministic orders. Event aggregation uses `canonical_event_sort_key` above. Stateful protocol replay must not reorder messages by exchange event time: group rows into non-overlapping `worker_instance_id` runs ordered by each run's earliest `received_at_ns` plus stable ID, then order within a run by `monotonic_ns`, `received_at_ns`, and source locator. Validate per-stream `writer_sequence` strictly increases within each worker run. A worker boundary invalidates inherited connection generations unless a new authoritative snapshot/bootstrap appears. Venue-native sequence/checksum logic remains the final continuity authority.

- [ ] **Step 4: Run discovery and ordering tests**

Run: `.venv/bin/python -m pytest tests/unit/materializer/test_discovery.py tests/property/materializer/test_ordering.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/materializer tests/unit/materializer tests/property/materializer
git commit -m "feat: discover deterministic raw inputs"
```

### Task 2: UTC Window and Event-Time Policy

**Files:**
- Create: `src/crypto_collector/materializer/time_policy.py`
- Create: `src/crypto_collector/materializer/windows.py`
- Test: `tests/property/materializer/test_windows.py`
- Test: `tests/unit/materializer/test_time_policy.py`

- [ ] **Step 1: Write failing boundary and fallback tests**

```python
@pytest.mark.parametrize("interval_ns", [seconds(30), minutes(1), minutes(5), hours(1)])
def test_windows_align_to_unix_epoch(interval_ns) -> None:
    timestamp = ns("2026-07-31T00:00:30Z")
    window = window_for(timestamp, interval_ns)
    assert window.start_ns % interval_ns == 0
    assert window.start_ns <= timestamp < window.end_ns


def test_half_open_boundary_belongs_to_next_window() -> None:
    assert window_for(seconds(30), seconds(30)).start_ns == seconds(30)


def test_missing_or_implausible_exchange_time_falls_back_to_receive_time() -> None:
    policy = EventTimePolicy(max_past_skew_ns=days(7), max_future_skew_ns=minutes(5))
    missing = policy.choose(event_time_ns=None, received_at_ns=seconds(100))
    future = policy.choose(event_time_ns=days(1), received_at_ns=seconds(100))
    assert missing == ChosenTime(seconds(100), TimeSource.RECEIVE_MISSING)
    assert future == ChosenTime(seconds(100), TimeSource.RECEIVE_OUTLIER)
```

- [ ] **Step 2: Run and verify time/window modules are missing**

Run: `.venv/bin/python -m pytest tests/property/materializer/test_windows.py tests/unit/materializer/test_time_policy.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement integer-only epoch windows**

```python
def window_for(timestamp_ns: int, interval_ns: int) -> Window:
    if timestamp_ns < 0 or interval_ns <= 0:
        raise ValueError("timestamp and interval must be positive")
    start_ns = timestamp_ns // interval_ns * interval_ns
    return Window(start_ns=start_ns, end_ns=start_ns + interval_ns)
```

Event time is used only when present and within configured past/future skew relative to receive time. Persist `time_source` and aggregate its counts/ratio in every output. Do not replace the raw event field or use local timezone/calendar rounding.

- [ ] **Step 4: Run time/window tests**

Run: `.venv/bin/python -m pytest tests/property/materializer/test_windows.py tests/unit/materializer/test_time_policy.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/materializer/time_policy.py src/crypto_collector/materializer/windows.py tests/property/materializer/test_windows.py tests/unit/materializer/test_time_policy.py
git commit -m "feat: align deterministic utc windows"
```

### Task 3: 30-Second Trade Bars and Expected Quality Rows

**Files:**
- Create: `src/crypto_collector/materializer/datasets/__init__.py`
- Create: `src/crypto_collector/materializer/datasets/trades.py`
- Create: `src/crypto_collector/materializer/datasets/quality.py`
- Create: `tests/golden/materializer/trades/raw.jsonl`
- Create: `tests/golden/materializer/trades/expected-30s.json`
- Create: `tests/golden/materializer/trades/expected-1m.json`
- Test: `tests/unit/materializer/datasets/test_trades.py`
- Test: `tests/unit/materializer/datasets/test_quality.py`

- [ ] **Step 1: Write failing Decimal bar and silent-expectation tests**

```python
def test_trade_bar_uses_decimal_and_aggressor_side() -> None:
    rows = build_trade_bars([
        trade(time_ns=1, price="10.10", quantity="2", side="buy"),
        trade(time_ns=2, price="10.30", quantity="1", side="sell"),
    ], interval_ns=seconds(30))
    assert rows[0].open == Decimal("10.10")
    assert rows[0].high == Decimal("10.30")
    assert rows[0].vwap == Decimal("30.50") / Decimal("3")
    assert rows[0].buy_base_volume == Decimal("2")
    assert rows[0].sell_base_volume == Decimal("1")
    assert rows[0].signed_base_volume == Decimal("1")


def test_empty_trade_window_has_null_prices_and_zero_activity() -> None:
    row = build_empty_trade_bar(window(0, 30))
    assert row.open is row.high is row.low is row.close is row.vwap is None
    assert row.base_volume == row.quote_volume == Decimal("0")
    assert row.trade_count == 0


def test_replayed_trade_id_is_counted_once_and_reported() -> None:
    duplicate = trade(trade_id="venue-42", time_ns=1, price="10", quantity="2")
    row = build_trade_bars([duplicate, duplicate], interval_ns=seconds(30))[0]
    assert row.trade_count == 1
    assert row.duplicate_input_count == 1


def test_missing_trade_id_is_not_heuristically_deduplicated() -> None:
    first = trade(trade_id=None, time_ns=1, price="10", quantity="2")
    row = build_trade_bars([first, first], interval_ns=seconds(30))[0]
    assert row.trade_count == 2
    assert row.deduplication_mode == "unavailable"


def test_completely_silent_expected_stream_still_has_quality_row() -> None:
    expectations = expectation_timeline(stream="trade", start_ns=0, end_ns=seconds(60))
    rows = build_quality_windows(expectations, actual_records=[], interval_ns=seconds(30))
    assert [row.input_count for row in rows] == [0, 0]
    assert all(row.expected and row.last_event_age_ns is None for row in rows)


def test_trade_fixture_matches_30_second_and_one_minute_goldens() -> None:
    records = load_trade_fixture("raw.jsonl")
    assert canonical_rows(build_trade_bars(records, seconds(30))) == load_golden("expected-30s.json")
    assert canonical_rows(build_trade_bars(records, minutes(1))) == load_golden("expected-1m.json")
```

- [ ] **Step 2: Run and verify dataset builders are missing**

Run: `.venv/bin/python -m pytest tests/unit/materializer/datasets/test_trades.py tests/unit/materializer/datasets/test_quality.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement trade normalization and expectation timeline**

Each venue supplies a pure derived-layer trade normalizer that returns trade ID, event/trade time, Decimal price/quantity, optional quote quantity, and aggressor side/unknown. Deduplicate only on a venue-documented stable trade identity scoped by exchange/market/instrument; retain the first canonical source locator and report duplicate counts. When no stable ID exists, do not invent a price/time/quantity heuristic: count the records and mark deduplication unavailable. Compute OHLC, VWAP, base/quote volume, buy/sell/signed volume, count, duplicate count, first/last trade time, and time-source counts. Never use binary float or forward-fill empty prices.

Build expectation intervals from `subscription_expectation` control checkpoints, closing a prior interval on selection/config changes. Produce a quality row for every expected instrument/stream/window even with zero data. Aggregate gaps, reconnects, checksum/sequence errors, queue overflow, latency, egress changes, throttles, and interval stretches from data/control manifests.

- [ ] **Step 4: Run unit and golden 30s tests**

Run: `.venv/bin/python -m pytest tests/unit/materializer/datasets/test_trades.py tests/unit/materializer/datasets/test_quality.py -q`

Expected: PASS and exact match with `expected-30s.json`.

- [ ] **Step 5: Commit the first analysis-ready output**

```bash
git add src/crypto_collector/materializer/datasets tests/golden/materializer/trades tests/unit/materializer/datasets
git commit -m "feat: materialize 30 second trade bars"
```

### Task 4: Live Book Replay and Causal Invalidity

**Files:**
- Create: `src/crypto_collector/materializer/books/__init__.py`
- Create: `src/crypto_collector/materializer/books/replay.py`
- Create: `src/crypto_collector/materializer/books/checkpoint.py`
- Create: `src/crypto_collector/materializer/datasets/book_live.py`
- Create: `tests/golden/materializer/book-live/raw.json`
- Create: `tests/golden/materializer/book-live/expected-30s.json`
- Test: `tests/unit/materializer/books/test_replay.py`
- Test: `tests/unit/materializer/datasets/test_book_live.py`

- [ ] **Step 1: Write failing valid, gap, and late-causality tests**

```python
def test_valid_book_window_outputs_end_state_features() -> None:
    rows = build_live_book_features(valid_snapshot_and_updates(), interval_ns=seconds(30), depths=[1, 5])
    row = rows[0]
    assert row.book_valid
    assert row.integrity_mode == "sequence_verified"
    assert row.mid == Decimal("10.5")
    assert row.spread == Decimal("1")
    assert row.depth_1_bid_notional == Decimal("20")
    assert row.update_count == 2


def test_gap_nulls_state_dependent_features_until_authoritative_snapshot() -> None:
    rows = build_live_book_features(stream_with_gap_then_snapshot(), interval_ns=seconds(30))
    assert rows[0].book_valid is False and rows[0].mid is None
    assert rows[0].gap_reason == "sequence_mismatch"
    assert rows[1].book_valid is True


def test_late_update_invalidates_checkpoints_until_next_snapshot() -> None:
    planner = BookImpactPlanner(revision_horizon_ns=hours(24))
    impact = planner.affected_range(
        late_event_ns=seconds(35),
        authoritative_snapshot_times=[seconds(120)],
        horizon_end_ns=hours(24),
    )
    assert impact == TimeRange(seconds(30), seconds(120))


def test_first_window_of_hour_replays_from_prior_live_authority() -> None:
    rows = build_live_book_features_for_hour(
        hour_start_ns=hours(1),
        prior_live=[live_snapshot(time_ns=minutes(59)), live_delta(time_ns=minutes(59) + 30)],
        current_hour=[live_delta(time_ns=hours(1) + 5)],
        deep_records=[deep_snapshot(time_ns=hours(1) + 1)],
        interval_ns=seconds(30),
    )
    assert rows[0].book_valid is True
    assert rows[0].authoritative_source_stream == "book_live"
    assert rows[0].lineage_manifest_shas == prior_and_current_live_manifest_shas()
```

- [ ] **Step 2: Run and verify live-book materializer is missing**

Run: `.venv/bin/python -m pytest tests/unit/materializer/books/test_replay.py tests/unit/materializer/datasets/test_book_live.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Reuse venue replay semantics without bridging deep data**

The replay registry invokes each connector's reviewed book transition logic over Task 1's canonical causal replay order, not event-time sort order. An authoritative input is that venue's WS snapshot or generation-affine `book_live_bootstrap`; `book_deep_snapshot` is never accepted. For an hourly output, discover the most recent valid authoritative live input before the hour plus every subsequent live delta/control through the hour end. This lookback may cross raw-hour boundaries, and every contributing source-manifest SHA belongs in the derived lineage even when its event lies before the output hour. Checkpoints contain state, source locator, integrity mode, authoritative ancestor, and source-prefix digest but are discardable accelerators, never lineage inputs; a mismatch forces replay from raw.

For valid coverage compute end mid/spread/microprice, configured level/notional depth, imbalance, update count, stale duration, and coverage ratio. On gap/disconnect/checksum failure, set state-dependent values null and remain invalid until an authoritative live snapshot. Preserve `BEST_EFFORT` separately from verified integrity. If a venue capability such as Bitget deletion semantics is disabled, output `book_valid=false` with the capability reason rather than guessing.

- [ ] **Step 4: Run live-book unit/golden tests**

Run: `.venv/bin/python -m pytest tests/unit/materializer/books tests/unit/materializer/datasets/test_book_live.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/materializer/books src/crypto_collector/materializer/datasets/book_live.py tests/golden/materializer/book-live tests/unit/materializer/books tests/unit/materializer/datasets/test_book_live.py
git commit -m "feat: replay live book windows"
```

### Task 5: Independent Deep Book and Derivative Windows

**Files:**
- Create: `src/crypto_collector/materializer/datasets/book_deep.py`
- Create: `src/crypto_collector/materializer/datasets/derivatives.py`
- Create: `tests/golden/materializer/book-deep/raw.json`
- Create: `tests/golden/materializer/book-deep/expected-30s.json`
- Create: `tests/golden/materializer/derivatives/raw.json`
- Create: `tests/golden/materializer/derivatives/expected-30s.json`
- Test: `tests/unit/materializer/datasets/test_book_deep.py`
- Test: `tests/unit/materializer/datasets/test_derivatives.py`

- [ ] **Step 1: Write failing independence and coverage tests**

```python
def test_deep_features_use_only_discrete_deep_snapshots() -> None:
    rows = build_deep_features(
        deep_records=[deep_snapshot(time_ns=10, bids=[["100", "2"]], asks=[["101", "3"]])],
        live_records=[live_snapshot_with_more_levels()],
        interval_ns=seconds(30),
    )
    assert rows[0].snapshot_count == 1
    assert rows[0].bid_notional_end == Decimal("200")
    assert rows[0].source_streams == ("book_deep_snapshot",)


def test_no_deep_snapshot_outputs_null_values_and_zero_count() -> None:
    row = build_empty_deep_window(window(0, 30))
    assert row.snapshot_count == 0
    assert row.bid_notional_end is None


def test_lossy_liquidation_silence_is_unknown_not_zero() -> None:
    row = build_derivative_window(
        expectations=liquidation_expectation(coverage="lossy_window"), records=[])
    assert row.liquidation_count is None
    assert row.liquidation_coverage == "lossy"


def test_complete_healthy_liquidation_silence_may_be_observed_zero() -> None:
    row = build_derivative_window(
        expectations=liquidation_expectation(coverage="complete", feed_healthy=True), records=[])
    assert row.liquidation_count == 0
    assert row.liquidation_coverage == "complete"
```

- [ ] **Step 2: Run and verify builders are missing**

Run: `.venv/bin/python -m pytest tests/unit/materializer/datasets/test_book_deep.py tests/unit/materializer/datasets/test_derivatives.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement independent snapshot curves and derivative normalization**

For each deep snapshot compute configured level, bps, and notional liquidity curves using Decimal, then aggregate snapshot count and min/mean/max/end per window. Do not carry a snapshot across windows and do not read live records.

Normalize mark/index/premium, funding, OI and change, price limits, risk/ADL/insurance/index components, and liquidation values while retaining source coverage `complete`, `lossy`, or `unknown`. Unknown/missing fields remain null. Store source stream/count and time-source ratios in every row.

- [ ] **Step 4: Run deep/derivative golden tests**

Run: `.venv/bin/python -m pytest tests/unit/materializer/datasets/test_book_deep.py tests/unit/materializer/datasets/test_derivatives.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/materializer/datasets tests/golden/materializer/book-deep tests/golden/materializer/derivatives tests/unit/materializer/datasets
git commit -m "feat: materialize deep and derivative windows"
```

### Task 6: Canonical Digest, Parquet Commit, and Derived Manifest

**Files:**
- Create: `src/crypto_collector/materializer/canonical.py`
- Create: `src/crypto_collector/materializer/identity.py`
- Create: `src/crypto_collector/materializer/parquet.py`
- Create: `src/crypto_collector/materializer/manifest.py`
- Test: `tests/property/materializer/test_canonical.py`
- Test: `tests/integration/materializer/test_parquet_commit.py`

- [ ] **Step 1: Write failing cross-directory and writer-fingerprint tests**

```python
def test_canonical_rows_digest_ignores_temp_root_and_input_discovery_order(tmp_path) -> None:
    rows = fixed_trade_rows()
    first = materialize_fixture(tmp_path / "a", input_order=[2, 0, 1], rows=rows)
    second = materialize_fixture(tmp_path / "b", input_order=[1, 2, 0], rows=rows)
    assert first.manifest.canonical_rows_sha256 == second.manifest.canonical_rows_sha256
    assert first.logical_rows == second.logical_rows


def test_materialization_identity_includes_code_lock_and_writer_fingerprint() -> None:
    base = identity_input(materializer_code_sha256="c" * 64,
                          materializer_lock_sha="a" * 64,
                          writer_fingerprint="pyarrow-1")
    assert materialization_identity(base) != materialization_identity(
        replace(base, materializer_code_sha256="d" * 64))
    assert materialization_identity(base) != materialization_identity(
        replace(base, materializer_lock_sha="b" * 64))
    assert materialization_identity(base) != materialization_identity(
        replace(base, writer_fingerprint="pyarrow-2"))


def test_code_digest_uses_distribution_relative_paths_and_bytes_only() -> None:
    first = code_digest({"materializer/a.py": b"x\n", "exchanges/okx/book.py": b"y\n"})
    reordered = code_digest({"exchanges/okx/book.py": b"y\n", "materializer/a.py": b"x\n"})
    changed = code_digest({"materializer/a.py": b"changed\n", "exchanges/okx/book.py": b"y\n"})
    assert first == reordered
    assert first != changed


def test_different_writer_fingerprint_can_be_semantically_equal() -> None:
    first = write_parquet(fixed_rows(), writer=fingerprint("one"))
    second = write_parquet(fixed_rows(), writer=fingerprint("two"))
    assert first.canonical_rows_sha256 == second.canonical_rows_sha256
    assert first.output_sha256 != second.output_sha256
```

- [ ] **Step 2: Run and verify commit modules are missing**

Run: `.venv/bin/python -m pytest tests/property/materializer/test_canonical.py tests/integration/materializer/test_parquet_commit.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement fixed-schema canonical encoding and atomic Parquet**

Canonical row bytes use dataset schema field order, explicit type tags for null/bool/int/Decimal/string/timestamp/list/struct, normalized Decimal coefficient+scale, nanosecond UTC integers, and one row delimiter. Sort rows by window start plus source-derived stable keys before hashing. Materialization identity hashes the sorted input raw-manifest SHA set, resolved config SHA, `materializer_code_sha256`, `requirements/materializer.lock` SHA, algorithm/schema versions, and this writer fingerprint.

`materializer_code_sha256` is content-addressed, not obtained from `git`, a branch name, an environment variable, or a mutable version string. At process start, enumerate every installed `.py` resource in the `crypto_collector` distribution (excluding `__pycache__` and tests), sort by normalized distribution-relative POSIX path, and hash a versioned length-prefixed sequence of `(path UTF-8 bytes, file bytes)`. This deliberately includes shared and venue normalizer/book code as well as the materializer package, so a semantic code change cannot reuse an old identity. Absolute install paths, mtimes, file modes, `.pyc` files, and discovery order do not participate. Compute it once per process and put the exact digest into every derived manifest and status report. Qualification and production run from an immutable wheel/container; editable installs are marked `development_unsealed` in the manifest and are not acceptable provenance for a production-derived revision.

Use this writer fingerprint:

```python
writer_fingerprint = {
    "implementation": "pyarrow",
    "version": pyarrow.__version__,
    "compression": "zstd",
    "compression_level": 3,
    "row_group_rows": 65536,
    "dictionary_columns": sorted(dictionary_columns),
    "metadata_policy": "stable-v1",
}
```

Write `*.parquet.partial`, sync, rename, sync directory, hash output, then write/sync/rename the derived manifest last. The manifest contains hourly partition identity, revision, superseded revision, input paths/hashes, materialization identity, row count, canonical rows hash, output hash, window range, schemas, writer fingerprint, and quality summary. A missing manifest means the revision is invisible.

- [ ] **Step 4: Run canonical and Parquet integration tests**

Run: `.venv/bin/python -m pytest tests/property/materializer/test_canonical.py tests/integration/materializer/test_parquet_commit.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/materializer/canonical.py src/crypto_collector/materializer/identity.py src/crypto_collector/materializer/parquet.py src/crypto_collector/materializer/manifest.py tests/property/materializer/test_canonical.py tests/integration/materializer/test_parquet_commit.py
git commit -m "feat: commit deterministic parquet revisions"
```

### Task 7: Hourly Revisions, ACKs, and CLI Service

**Files:**
- Create: `src/crypto_collector/materializer/revisions.py`
- Create: `src/crypto_collector/materializer/ack.py`
- Create: `src/crypto_collector/materializer/state.py`
- Create: `src/crypto_collector/materializer/service.py`
- Modify: `src/crypto_collector/cli.py`
- Test: `tests/unit/materializer/test_revisions.py`
- Test: `tests/integration/materializer/test_service.py`
- Test: `tests/cli/test_materialize.py`

- [ ] **Step 1: Write failing revision-range and ACK-gate tests**

```python
def test_revision_identity_is_hourly() -> None:
    identity = PartitionIdentity("okx", "spot", "BTC-USDT", "trade_bars", seconds(30),
                                 ns("2026-07-31T12:00:00Z"))
    assert identity.path_suffix == "interval=30s/date=2026-07-31/hour=12"


def test_late_trade_revises_only_affected_hour_windows() -> None:
    plan = RevisionPlanner(hours(24)).plan(late_trade_manifest(at=ns("2026-07-31T12:10:01Z")))
    assert plan.partitions == {partition(hour=12, dataset="trade_bars")}


def test_late_book_revises_through_next_authoritative_snapshot() -> None:
    plan = RevisionPlanner(hours(24)).plan(
        late_book_manifest(at=seconds(35)), snapshots=[seconds(20), seconds(120)])
    assert plan.affected_range == TimeRange(seconds(30), seconds(120))


def test_late_book_revision_crosses_hour_partitions_until_next_snapshot() -> None:
    plan = RevisionPlanner(hours(24)).plan(
        late_book_manifest(at=minutes(59) + 50),
        snapshots=[hours(2) + minutes(5)],
    )
    assert plan.partition_hours == (0, 1, 2)
    assert plan.affected_range == TimeRange(minutes(59) + 30, hours(2) + minutes(5))


def test_ack_waits_for_every_enabled_dataset_commit(tmp_path) -> None:
    tracker = AckTracker(enabled={"trade_bars", "quality_windows"})
    tracker.record_commit("raw-sha", dataset="trade_bars", derived_manifest_sha="a" * 64)
    assert tracker.maybe_commit_ack("raw-sha", tmp_path) is None
    tracker.record_commit("raw-sha", dataset="quality_windows", derived_manifest_sha="b" * 64)
    ack = tracker.maybe_commit_ack("raw-sha", tmp_path)
    assert ack.required_datasets == ("quality_windows", "trade_bars")


def test_materialize_requires_explicit_config_path() -> None:
    result = CliRunner().invoke(app, ["materialize"])
    assert result.exit_code == 2
    assert "CONFIG_PATH" in result.stdout
```

- [ ] **Step 2: Run and verify revision/service modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/materializer/test_revisions.py tests/integration/materializer/test_service.py tests/cli/test_materialize.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement idempotent hourly revision planning**

The logical key is `(exchange, market, instrument_key, dataset, interval, UTC hour)`. New late inputs within the 24-hour horizon create the next immutable revision as a complete replacement for that hourly partition. Trade/deep/derivative impact only their windows; live-book impact extends to the next authoritative snapshot or horizon boundary, invalidating cache checkpoints. Outside the horizon, process only under explicit `--reprocess`.

Maintain rebuildable SQLite discovery/commit state. After all enabled datasets affected by one raw manifest have visible derived manifests, atomically publish `*.materializer-ack.json` with raw manifest SHA and derived manifest SHAs. Never ACK a partial dataset set.

`collector materialize CONFIG_PATH [--from ISO --to ISO --reprocess]` and service mode load that explicit config, enforce its configured 0-60 minute delay, scan only closed manifests, acquire shared source leases, and exit/retry idempotently after crashes. There is no implicit config-path or current-directory fallback. They never open exchange sockets or write collector queues.

- [ ] **Step 4: Run the full materializer suite twice with shuffled discovery**

Run: `.venv/bin/python -m pytest tests/unit/materializer tests/property/materializer tests/integration/materializer tests/cli/test_materialize.py -q`

Expected: PASS; golden 30s/1m outputs and canonical hashes remain identical under separate temporary roots and shuffled discovery.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/materializer src/crypto_collector/cli.py tests/unit/materializer tests/property/materializer tests/integration/materializer tests/cli/test_materialize.py
git commit -m "feat: materialize hourly deterministic revisions"
```

- [ ] **Step 6: Run the repository-wide offline regression gate**

Run: `.venv/bin/python scripts/verify_role_locks.py --require-entry materializer`

Expected: all four clean lock installs pass and the materializer production entry imports under its role-only environment.

Run: `.venv/bin/python -m pytest -q -m "not live and not performance"`

Expected: PASS with external sockets denied.
