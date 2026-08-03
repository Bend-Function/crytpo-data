# Writer Gate B Auditable Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic writer-only durability benchmark whose final qualification verdict is independently reproducible from primary runtime, raw-storage, target, source, wheel, and container evidence.

**Architecture:** A strict workload loader feeds a streaming deterministic oracle. A
spawn supervisor coordinates five exchange child processes; each child owns one
production `RawWriterService` and one primary trace partition. A fresh-process runtime
verifier heap-merges those partitions and recomputes storage facts, and a host-side
provenance verifier binds the exact source and executed image. Candidate reports never
self-qualify; only the final acceptance receipt can set
`qualification_accepted=true`.

**Tech Stack:** Python 3.11, asyncio, Pydantic v2, ruamel.yaml, simplejson, zstandard, SQLite, Typer, pytest, Ruff, mypy, POSIX/Linux filesystem APIs, Docker/BuildKit, Git.

---

## Authority And Execution Rules

This plan supersedes only Task 7 in
`docs/superpowers/plans/2026-07-31-durable-raw-storage.md`. The approved design is
`docs/superpowers/specs/2026-08-02-writer-gate-b-auditable-evidence-design.md`.
Tasks 1-6 of Plan02 remain implemented at commit `4927ac1`; design commit `f640d93`
is the base for this plan.

Execute in `/Users/funcma/Project/crytpo-data/.worktrees/plan02-durable-storage` on
branch `codex/plan02-durable-storage`. Do not stage unrelated files. The existing
untracked workload/package/RED-test files are the Task 1 starting point, not evidence
of completion.

For every implementation task:

1. A fresh implementer subagent follows the listed RED/GREEN steps and commits.
2. A fresh specification reviewer checks the commit against this plan and the design.
3. A fresh code-quality reviewer checks correctness, strictness, tests, and scope.
4. Findings are fixed with new commits; published commits are not amended.
5. Focused tests, Ruff, mypy, and `git diff --check` pass before push.

No target report, runtime receipt, or evidence disclosure is committed until a real
Linux target and immutable evidence backend satisfy Task 10. Docker Desktop results
are implementation/reproducibility checks only.

## File Map

- `src/crypto_collector/benchmarks/workload.py`: strict workload models, YAML loading,
  raw-byte SHA, cross-field reconciliation.
- `src/crypto_collector/benchmarks/contracts.py`: versioned frozen primary-artifact,
  report, receipt, inventory, and disclosure models.
- `src/crypto_collector/benchmarks/oracle.py`: identities, allocation, payloads,
  schedules, plan summaries, streaming plan hash.
- `src/crypto_collector/benchmarks/artifacts.py`: canonical JSON/JSONL, zstd transport,
  streaming hashes, no-replace publication, evidence hash DAG.
- `src/crypto_collector/benchmarks/aggregation.py`: worker-round validation,
  final-only aggregation, histograms, RSS/FD/storage-health calculations.
- `src/crypto_collector/benchmarks/runtime_verifier.py`: trace/oracle/raw/manifest
  replay, SQLite joins, runtime receipt.
- `src/crypto_collector/benchmarks/target.py`: Linux mount lookup, sync/hard-link
  probes, target declaration and re-probe.
- `src/crypto_collector/benchmarks/runner.py`: production writer orchestration and
  candidate artifact generation.
- `src/crypto_collector/benchmarks/provenance.py`: source archive, wheel/image,
  container, immutable archive, acceptance receipt, and disclosure checks.
- `src/crypto_collector/benchmarks/writer.py`: Typer CLI facade only.
- `benchmarks/workloads/research-default-v1.yaml`: immutable workload input.
- `benchmarks/workloads/research-default-v1.golden.json`: reviewed literal vectors.
- `tests/unit/benchmarks/`: pure contract, oracle, artifact, aggregation, target,
  verifier, runner, and provenance tests.
- `tests/integration/benchmarks/test_writer_functional.py`: production-path micro and
  exact 10-second functional tests.
- `tests/performance/test_writer_durability.py`: complete Gate B contract and opt-in
  target-host qualification test.
- `scripts/reproduce-writer-image.sh`: two clean-source reproducible builds and checks.
- `Dockerfile`, `.dockerignore`: pinned collector image.
- `docs/operations/writer-benchmark.md`: implementation, target, validation, archive,
  disclosure, and failure runbook.

## Pre-Task-3 Contract And Process Amendment

This section supersedes conflicting Task 3, Task 4, and Task 7 wording below. It was
added before any of those tasks were implemented after two measured facts:

- one process can generate only about 29,000 planned drafts/s and the production
  admission path measured about 21,500 accepts/s on the development host, below the
  41,768/s aggregate mean and far below a global 250,000-event trade burst;
- the collector architecture already requires one spawned process per exchange.

The runner therefore uses `multiprocessing.get_context("spawn")` with one supervisor
and exactly five canonical exchange children. Each child opens one service, uses an
efficient exchange-partitioned oracle iterator, writes one canonical trace partition,
and samples its own `/proc/self`. Planned events and trace rows never cross IPC. All
children receive one future monotonic/UTC admission anchor only after a complete
readiness handshake. There is no automatic child restart during a gate run.

Primary admission trace is an ordered five-part set, not a physical global file plus
five duplicates. Each part has its own decompressed/compressed sizes and SHA values.
The set additionally binds row count, byte count, and semantic SHA of a virtual
five-way heap merge by `(due_monotonic_ns, planned_event_id)`. The runtime verifier
performs that merge directly from bounded zstd readers and compares it to the global
oracle. Missing, duplicate, reordered, cross-exchange, or internally unsorted parts
reject the run.

Resource rounds contain six stable process keys: supervisor first, followed by the
five exchange children in canonical exchange order. RSS and open FDs are summed within
each complete round. Peak, post-warmup RSS OLS slope, FD baseline/peak/final/growth,
and configured limits use those totals. A per-process application of the 4 GiB/4096-FD
limits is forbidden because it would multiply the approved resource budget.

Canonical schema ownership is incremental. Task 3 defines only the foundational
primary rows and artifact codecs whose exact field order is frozen in the approved
design: `GateArtifactRefV1`, `GateExchangeArtifactPartitionV1`,
`GateAdmissionTraceSetV1`, `GateAdmissionTraceV1`, `GateSecondBucketV1`,
`GateWorkerKeyV1`, `GateWorkerSampleV1`, `GateSamplingRoundV1`,
`GateProcessKeyV1`, `GateProcessResourceSampleV1`,
`GateResourceSamplingRoundV1`, `GateWorkerHealthV1`, and
`GateStorageHealthSampleV1`. Do not create placeholder future models.

Later tasks add their models only after their own RED tests freeze every field and its
order:

- Task 4: final worker/resource/storage summary models;
- Task 5: candidate report, run index, raw/manifest inventory, runtime receipt, and
  runtime index models required by the verifier fixture;
- Task 6: target declaration and re-probe models;
- Task 7: no new evidence schema; it must consume the frozen Task 3-6 models;
- Task 8: file/archive/provenance/acceptance/disclosure models and the complete hash
  DAG chain.

Every later self-hashing model places `sha256` last, publishes canonical bytes with it,
and computes the digest with only that field omitted. A task must not implement a
future model until its field order, invariants, public/private classification, and
predecessor references are explicit in tests and the design.

Task 6 is an implementation prerequisite for Task 5 even though the historical task
numbers are retained below. Implement and review the target declaration/re-probe
contracts first, then implement the runtime verifier against those concrete models.
Task 5 must not substitute a boolean or an untyped mapping for target evidence. This
ordering correction does not move runner, provenance, image, or external qualification
work across their original boundaries.

### Task 1: Freeze Workload Schema And Baseline Bytes

**Files:**
- Create: `src/crypto_collector/benchmarks/__init__.py`
- Create: `src/crypto_collector/benchmarks/workload.py`
- Create: `benchmarks/workloads/research-default-v1.yaml`
- Create: `tests/unit/benchmarks/__init__.py`
- Create: `tests/unit/benchmarks/test_workload.py`
- Modify: `tests/performance/test_writer_durability.py`

- [x] **Step 1: Replace the import-only RED test with strict workload tests**

Add tests that import only the intended public loader and models:

```python
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from crypto_collector.benchmarks.workload import (
    RESEARCH_DEFAULT_V1_SHA256,
    GateWorkloadV1,
    load_workload,
)

WORKLOAD = Path("benchmarks/workloads/research-default-v1.yaml")


def test_research_default_v1_freezes_scope_and_algorithms() -> None:
    loaded = load_workload(WORKLOAD)
    assert loaded.sha256 == RESEARCH_DEFAULT_V1_SHA256
    assert loaded.workload.exchanges == (
        "binance", "okx", "bybit", "bitget", "kraken"
    )
    assert loaded.workload.markets == ("spot", "perpetual")
    assert loaded.workload.derivative_logical_streams == (
        "funding", "open_interest"
    )
    assert loaded.workload.identity_algorithm == "gate-identity-v1"
    assert loaded.workload.payload_algorithm == "gate-payload-v1"
    assert loaded.workload.schedule_algorithm == (
        "gate-schedule-v2-full-second-burst"
    )
    assert loaded.workload.streams["trade"].mean_records_per_second == Decimal("50")
    assert loaded.workload.fixed_scope_file_count == 5
    assert loaded.workload.scalable_file_count == 1_750
    assert loaded.workload.active_file_count == 1_755


@pytest.mark.parametrize("value", [1.0, True, "1.0", {"unexpected": 1}])
def test_workload_rejects_noncanonical_schema_version(value: object) -> None:
    with pytest.raises((TypeError, ValidationError, ValueError)):
        GateWorkloadV1.model_validate({"schema_version": value})
```

Also test duplicate exchange/market/derivative names, unknown transport, non-string
rates/fractions, non-finite/negative decimals, `instrument_instances *
logical_streams_per_instrument != file_instances`, and every mismatch among fixed,
scalable, and active counts.

- [x] **Step 2: Run the focused test and verify RED**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_workload.py \
  tests/performance/test_writer_durability.py -q
```

Expected: collection fails because `crypto_collector.benchmarks.workload` does not
exist.

- [x] **Step 3: Commit the exact baseline YAML shape**

Extend the already-created baseline values with these exact top-level keys:

```yaml
schema_version: 1
name: research-default-v1
generation_seed: 20260731
exchanges: [binance, okx, bybit, bitget, kraken]
markets: [spot, perpetual]
symbols_per_market: 25
derivative_logical_streams: [funding, open_interest]
identity_algorithm: gate-identity-v1
payload_algorithm: gate-payload-v1
schedule_algorithm: gate-schedule-v2-full-second-burst
stream_transports:
  trade: websocket
  book_live: websocket
  ticker: websocket
  bbo: websocket
  funding: websocket
  open_interest: websocket
  candle_1m: websocket
  book_deep_snapshot: rest
  _control: internal
```

Retain the exact stream rates/sizes, payload fractions, queue settings, and
qualification limits from the approved design and prior Task 7 snippet. Remove the
redundant `exchange_workers` and `markets_per_worker` keys because the explicit tuples
are authoritative.

- [x] **Step 4: Implement the strict loader**

Use frozen strict Pydantic models and `ruamel.yaml.YAML(typ="safe", pure=True)`.
Expose exactly this public shape:

```text
LoadedWorkload(workload: GateWorkloadV1, source_bytes: bytes, sha256: str)
load_workload(path: Path) -> LoadedWorkload
```

`LoadedWorkload` is a frozen slotted dataclass. `load_workload` performs the byte read,
hash, strict YAML parse, model validation, and cross-field reconciliation before
constructing it.

Reject symlinks, non-files, invalid UTF-8, duplicate YAML keys, multi-document YAML,
non-mapping roots, extra fields, booleans-as-integers, and all cross-field cardinality
errors. Compute SHA-256 over exact source bytes before parsing. Set
`RESEARCH_DEFAULT_V1_SHA256` to the lowercase digest printed by:

```bash
shasum -a 256 benchmarks/workloads/research-default-v1.yaml
```

- [x] **Step 5: Run focused tests and static checks**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_workload.py \
  tests/performance/test_writer_durability.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks tests/unit/benchmarks \
  tests/performance/test_writer_durability.py
.venv/bin/mypy src/crypto_collector/benchmarks
git diff --check
```

Expected: PASS. Keep Task 2 oracle imports out of the performance test until Task 2
Step 1 creates its next RED state.

- [x] **Step 6: Commit Task 1**

```bash
git add src/crypto_collector/benchmarks/__init__.py \
  src/crypto_collector/benchmarks/workload.py \
  benchmarks/workloads/research-default-v1.yaml \
  tests/unit/benchmarks tests/performance/test_writer_durability.py
git commit -m "feat: freeze writer gate workload contract"
```

### Task 2: Implement The Streaming Identity, Count, Schedule, And Payload Oracle

**Files:**
- Create: `src/crypto_collector/benchmarks/oracle.py`
- Create: `benchmarks/workloads/research-default-v1.golden.json`
- Create: `tests/unit/benchmarks/test_oracle.py`
- Modify: `tests/performance/test_writer_durability.py`

- [x] **Step 1: Write identity, count, and touched-cardinality RED tests**

```python
def test_multiplier_two_exact_counts_and_touched_files() -> None:
    plan = build_workload_plan(load_workload(WORKLOAD), multiplier=2,
                               duration_ns=10_000_000_000)
    assert plan.expected_record_count == 417_677
    assert plan.declared_file_identity_count == 3_505
    assert plan.expected_touched_file_identity_count == 3_172
    assert plan.stream("trade").expected_record_count == 250_000
    assert plan.stream("book_deep_snapshot").expected_record_count == 167
    assert plan.stream("control").expected_record_count == 10


def test_qualification_plan_touches_every_declared_identity() -> None:
    plan = build_workload_plan(load_workload(WORKLOAD), multiplier=2,
                               duration_ns=600_000_000_000)
    assert plan.expected_record_count == 25_060_620
    assert plan.expected_touched_file_identity_count == 3_505
```

Assert the first ordinary identity is
`gate-identity-v1:binance:spot:GATE-BINANCE-SPOT-L0000-S0000:trade`, the first
derivative identities are `funding` then `open_interest`, the final fixed identity is
`gate-identity-v1:kraken:-:-:_control`, allocation is `q+1` for the first `r`
identities, and local sequences are contiguous from zero.

- [x] **Step 2: Write schedule and payload RED tests**

Use a compact strict test workload and assert:

```python
assert all(event.due_offset_ns == burst_start for event in burst_events)
assert all(event.deadline_offset_ns == burst_start + 1_000_000_000
           for event in burst_events)
assert tuple(events) == tuple(sorted(events,
                                    key=lambda item: (item.due_offset_ns,
                                                      item.planned_event_id)))
assert max(event.deadline_offset_ns for event in events) <= duration_ns
assert len(encode_json(event.payload)) == event.payload_bytes
assert sha256(encode_json(event.payload)).hexdigest() == event.payload_sha256
```

Cover `N > B`, `N == B`, functional `N < required_B`, burst seconds zero and the final
schedulable second, equal-due event-ID ordering, multiplier/identity overflow, and
non-integral/sub-10-second duration rejection.

- [x] **Step 3: Run tests and verify RED**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_oracle.py \
  tests/performance/test_writer_durability.py -q
```

Expected: FAIL because `build_workload_plan` and oracle types do not exist.

- [x] **Step 4: Implement immutable summaries and streaming iterators**

Expose these exact public call shapes:

```text
build_workload_plan(loaded: LoadedWorkload, *, multiplier: int,
                    duration_ns: int) -> WorkloadPlanV1
iter_plan_events(plan: WorkloadPlanV1) -> Iterator[PlannedEventV1]
build_native_draft(event: PlannedEventV1, *, admission_started_utc_ns: int)
    -> tuple[NativeEventDraft, SourceContext, str]
```

Implement exact Decimal/ceiling math, explicit identity ordering, zero-based
allocation, SHA event IDs, full-second burst schedule, payload selectors/padding, and
the deterministic `NativeEventDraft`/source/shard profile in design sections 4.2-4.8.
Use at most one per-stream burst tie group plus one event per stream in memory; merge
the fixed stream iterators with `heapq.merge`.

Hash `WorkloadPlanHeaderV1`, declared-order stream summaries, and globally merged
`PlannedEventV1` canonical lines. Never materialize the 10-minute plan.

- [x] **Step 5: Add literal golden vectors**

The JSON file must contain exact 10-second and 10-minute summary counts, the fixed
3,172/3,505 touched counts, per-stream burst seconds/counts, selected identity/event/
payload hashes, and complete payloads only for the <=1,024-byte micro profile. Generate
candidate values with a one-off independent reference command, review each against the
design formula, then type the literals into JSON. Production code must not contain a
golden-file writer.

Normal unit tests validate micro and 10-second vectors. Mark the full 10-minute
streamed plan-hash test `@pytest.mark.performance` and require
`CRYPTO_COLLECTOR_FULL_GATE_ORACLE=1` so the offline suite stays bounded. Golden
maintenance and qualification verification run that opt-in test explicitly.

- [x] **Step 6: Run focused and property tests**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_oracle.py -q
.venv/bin/python -m pytest tests/performance/test_writer_durability.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks/oracle.py \
  tests/unit/benchmarks/test_oracle.py
.venv/bin/mypy src/crypto_collector/benchmarks/oracle.py
git diff --check
```

Expected: PASS, including exact `417677`, `25060620`, `3172`, and `3505` facts.
For the reviewed full-hash maintenance run, additionally execute:

```bash
CRYPTO_COLLECTOR_FULL_GATE_ORACLE=1 .venv/bin/python -m pytest \
  tests/performance/test_writer_durability.py::test_qualification_plan_matches_literal_golden_hash -q
```

- [x] **Step 7: Commit Task 2**

```bash
git add src/crypto_collector/benchmarks/oracle.py \
  benchmarks/workloads/research-default-v1.golden.json \
  tests/unit/benchmarks/test_oracle.py tests/performance/test_writer_durability.py
git commit -m "feat: add deterministic writer gate oracle"
```

### Task 2A: Add Exchange-Partitioned Streaming Iteration

**Files:**
- Modify: `src/crypto_collector/benchmarks/oracle.py`
- Modify: `tests/unit/benchmarks/test_oracle.py`

- [x] **Step 1: Write partition-equivalence RED tests**

Build a strict two-exchange micro plan. Assert every partition contains only its
requested exchange and this merge is exact at the model and canonical-byte levels:

```python
partitions = tuple(iter_exchange_plan_events(plan, exchange)
                   for exchange in plan.streams[0].exchanges)
merged = heapq.merge(*partitions,
                     key=lambda event: (event.due_offset_ns,
                                        event.planned_event_id))
assert tuple(merged) == tuple(iter_plan_events(plan))
```

Cover control identities, capped sparse allocation, burst and smooth rows, all eight
stream groups, invalid exchange type, and an exchange absent from the plan. Assert
each partition count equals the sum of allocations for that exchange. The test must
fail because `iter_exchange_plan_events` does not exist.

- [x] **Step 2: Implement bounded partition iteration**

Expose:

```text
iter_exchange_plan_events(plan: WorkloadPlanV1, exchange: Exchange)
    -> Iterator[PlannedEventV1]
```

Derive each exchange's contiguous identity span, ordinal start, per-identity burst
prefix, and global smooth index arithmetically. Do not filter `iter_plan_events` and do
not scan or build payloads for another exchange. Within a stream, sort only that
exchange's burst tie group and same-due smooth group; heap-merge the fixed eight stream
iterators. The five exchange iterators must merge exactly to the existing global
iterator, so this addition cannot change any workload-plan or golden hash.

- [x] **Step 3: Run focused and full oracle gates**

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_oracle.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks/oracle.py \
  tests/unit/benchmarks/test_oracle.py
.venv/bin/ruff format --check src/crypto_collector/benchmarks/oracle.py \
  tests/unit/benchmarks/test_oracle.py
.venv/bin/mypy src/crypto_collector/benchmarks/oracle.py
git diff --check
```

- [x] **Step 4: Review, commit, and push**

```bash
git add src/crypto_collector/benchmarks/oracle.py \
  tests/unit/benchmarks/test_oracle.py
git commit -m "feat: partition writer gate events by exchange"
```

### Task 3: Define Foundational Primary Artifacts And Partitioned Codecs

**Files:**
- Create: `src/crypto_collector/benchmarks/contracts.py`
- Create: `src/crypto_collector/benchmarks/artifacts.py`
- Create: `tests/unit/benchmarks/test_artifacts.py`
- Modify: `tests/performance/test_writer_durability.py`

- [x] **Step 1: Write strict-model and canonical-codec RED tests**

Create model fixtures and assert:

```python
def test_trace_identity_status_and_timestamps_are_strict() -> None:
    accepted = trace_row(enqueue_status="accepted", accepted_identity=identity())
    assert GateAdmissionTraceV1.model_validate(accepted).accepted_identity is not None
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate({**accepted,
            "admission_completed_monotonic_ns":
                accepted["attempt_started_monotonic_ns"] - 1})
    with pytest.raises(ValidationError):
        GateAdmissionTraceV1.model_validate({**accepted,
            "enqueue_status": "overflow", "accepted_identity": identity()})


def test_semantic_hash_ignores_zstd_frame_variation(tmp_path: Path) -> None:
    first = write_trace(tmp_path / "a.zst", rows(), zstd_level=3)
    second = write_trace(tmp_path / "b.zst", rows(), zstd_level=19)
    assert first.content_sha256 == second.content_sha256
    assert first.compressed_sha256 != second.compressed_sha256
```

Reject bool/int confusion, extra fields, invalid SHA values, duplicate/sorted-key
violations, noncanonical JSON bytes, missing final newline, trailing bytes, malformed
zstd, accepted/nonaccepted identity disagreement, incomplete worker/process rounds,
and unstable process IDs.

- [x] **Step 2: Write partitioned-hash and no-replace RED tests**

Create five small exchange partitions and assert:

```python
trace_set = validate_trace_partitions(canonical_five_partitions())
assert trace_set.merged_content_sha256 == hash_global_trace_rows()
assert trace_set.merged_row_count == sum(part.artifact.row_count
                                         for part in trace_set.partitions)
```

Mutation tests reject missing/sixth/duplicate/reordered partitions, an exchange row in
the wrong part, internally unsorted rows, merged count/size/hash disagreement, and a
planned-event-ID collision. Also prove existing destinations are never overwritten,
temp sync/close precedes hard-link publication, directory sync follows, failed writes
retain `.partial` evidence, and partial files never parse as completed evidence. The
complete one-way hash-DAG test moves to Task 8, when every node actually exists.

- [x] **Step 3: Run tests and verify RED**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_artifacts.py -q
```

Expected: FAIL because contracts and artifact writers do not exist.

- [x] **Step 4: Implement frozen contracts and canonical artifacts**

Define only these strict version-one models in the exact approved field order:

```text
GateArtifactRefV1, GateExchangeArtifactPartitionV1,
GateAdmissionTraceSetV1, GateAdmissionTraceV1, GateSecondBucketV1,
GateWorkerKeyV1, GateWorkerSampleV1, GateSamplingRoundV1,
GateProcessKeyV1, GateProcessResourceSampleV1,
GateResourceSamplingRoundV1, GateWorkerHealthV1,
GateStorageHealthSampleV1
```

Paths stored in evidence are normalized POSIX-relative strings. Reuse the canonical
storage `AcceptedRecordIdentityV1`, `EnqueueStatus`, and `WriterMetricsSnapshotV1`
instead of redefining them.

Expose these exact foundational call shapes (with a bounded Pydantic model type
variable `RowT`):

```text
write_jsonl_zstd(root: Path, relative_path: str, rows: Iterable[RowT], *,
                 zstd_level: int) -> GateArtifactRefV1
iter_jsonl_zstd(root: Path, artifact: GateArtifactRefV1,
                model_type: type[RowT], *, max_rows: int,
                max_content_bytes: int, max_line_bytes: int) -> Iterator[RowT]
iter_merged_trace_partitions(root: Path,
                             partitions: Sequence[GateExchangeArtifactPartitionV1],
                             *, max_rows: int, max_content_bytes: int,
                             max_line_bytes: int)
    -> Iterator[GateAdmissionTraceV1]
build_admission_trace_set(root: Path,
                          partitions: Sequence[GateExchangeArtifactPartitionV1],
                          *, max_rows: int, max_content_bytes: int,
                          max_line_bytes: int) -> GateAdmissionTraceSetV1
```

`root` is an absolute normalized directory; artifact paths never escape it. Generic
rows must be frozen strict models with canonical bytes. Readers first validate the
compressed file size/SHA through no-follow descriptors, then enforce all three
caller-provided bounds while decompressing and require exact canonical re-encoding.

Implement streaming JSONL/zstd read/write with content and compressed SHA-256 values,
where canonical JSONL is exactly `encode_json(model_dump(mode="json")) + b"\n"`.
Require strict canonical-byte comparison after model parsing, bounded decompression, and
same-parent sync/hard-link/directory-sync publication. Implement bounded five-reader
heap merge validation without writing a sixth trace. Reuse the production
`NoReplaceCapability.HARDLINK` semantics explicitly; do not depend on the Linux
renameat2 default and do not add rename-overwrite fallbacks.

- [x] **Step 5: Run focused tests and checks**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_artifacts.py \
  tests/performance/test_writer_durability.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks/contracts.py \
  src/crypto_collector/benchmarks/artifacts.py tests/unit/benchmarks/test_artifacts.py
.venv/bin/mypy src/crypto_collector/benchmarks/contracts.py \
  src/crypto_collector/benchmarks/artifacts.py
git diff --check
```

Expected: PASS.

- [x] **Step 6: Commit Task 3**

```bash
git add src/crypto_collector/benchmarks/contracts.py \
  src/crypto_collector/benchmarks/artifacts.py \
  tests/unit/benchmarks/test_artifacts.py tests/performance/test_writer_durability.py
git commit -m "feat: add writer gate evidence artifacts"
```

### Task 4: Validate Worker Rounds, Final-Only Aggregation, And Resource Samples

**Files:**
- Create: `src/crypto_collector/benchmarks/aggregation.py`
- Create: `tests/unit/benchmarks/test_aggregation.py`
- Modify: `src/crypto_collector/benchmarks/contracts.py`
- Modify: `tests/performance/test_writer_durability.py`

The exact Task 4 aggregate model field orders and insufficient-post-warmup semantics
are frozen in design section 5.5. Periodic health samples preserve independent data
and state free-space minima but do not infer shared mounts; shared-mount floor
accounting belongs to Task 6, where device and mount identities are available.

- [x] **Step 1: Write worker-sequence RED tests**

Build five two-sample sequences plus final CLOSED snapshots. Assert only final
cumulative facts are summed, gauge peaks come from same-round sums, bucket vectors are
elementwise sums, max is the maximum final worker max, and p50/p95/p99 are recomputed
with production histogram bounds.

Mutation tests must reject worker/config replacement, missing/sixth/duplicate workers,
round overlap, duplicate/missing samples, decreasing counters/buckets/maxima, removed
series, equal observed time with changed bytes, and every nonzero final gauge. Permit
byte-identical cache repeats and decreasing quantiles with monotonic cumulative buckets.

- [x] **Step 2: Write resource/health RED tests**

```python
def test_rss_ols_and_fd_growth_use_only_post_warmup_samples() -> None:
    summary = summarize_resources(
        six_process_rounds(),
        expected_processes=canonical_process_keys(),
        warmup_ended_monotonic_ns=120,
    )
    assert summary.rss_slope_bytes_per_minute == Decimal("120")
    assert summary.fd_growth_after_warmup == 3


def test_storage_health_rejects_burst_sampling() -> None:
    summary = summarize_storage_health(bunched_samples(), duration_ns=600,
                                       interval_ns=10)
    assert summary.sample_count >= summary.expected_min_sample_count
    assert summary.coverage_valid is False
```

Cover same-round six-process RSS/FD sums, missing/seventh/duplicate processes, changed
PID or process key, negative OLS slope flooring to zero, one/zero post-warmup rounds,
exact Decimal conversion, scheduled-time gaps, completion coverage, two independent
root `statvfs` facts, and conservative free-space treatment without inferring shared
mounts. Fewer than two post-warmup rounds produce a null RSS slope; zero post-warmup
rounds also produce null FD growth, while one produces FD growth zero. The summary
records the observed scheduled-time maximum gap; Task 5 compares it with the
independently configured workload gap limit.

All three input sequences preserve evidence order, start at round zero, advance round
indices by one, and strictly advance scheduled times. Adjacent request intervals may
touch at one endpoint but cannot overlap. A resource or health sampling exception
fails the runner before candidate-report publication and is covered in Task 7.

- [x] **Step 3: Run tests and verify RED**

Run: `.venv/bin/python -m pytest tests/unit/benchmarks/test_aggregation.py -q`

Expected: FAIL because aggregation functions do not exist.

- [x] **Step 4: Implement aggregation**

Expose these exact public call shapes:

```text
validate_worker_rounds(rounds: Iterable[GateSamplingRoundV1], *,
                       expected_workers: Sequence[GateWorkerKeyV1])
    -> ValidatedWorkerSequences
aggregate_final_worker_snapshots(sequences: ValidatedWorkerSequences)
    -> FinalWorkerAggregateV1
summarize_resources(rounds: Iterable[GateResourceSamplingRoundV1], *,
                    expected_processes: Sequence[GateProcessKeyV1],
                    warmup_ended_monotonic_ns: int)
    -> GateResourceSummaryV1
summarize_storage_health(samples: Iterable[GateStorageHealthSampleV1], *,
                         duration_ns: int, interval_ns: int)
    -> GateStorageHealthSummaryV1
```

Use canonical snapshot bytes for equal-time comparisons, explicit cumulative/max/gauge
field tuples, the repository durability histogram bounds, and same-round total process
resources. Do not introspect `RawWriterService` internals and do not apply resource
limits separately to each process.

Define `FinalWorkerAggregateV1`, `GateResourceSummaryV1`, and
`GateStorageHealthSummaryV1` as frozen strict models in `contracts.py`. Keep
`ValidatedWorkerSequences` as an immutable internal aggregation type; use the
canonical `GateWorkerKeyV1` at the artifact boundary.

- [x] **Step 5: Run focused tests and checks**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_aggregation.py \
  tests/performance/test_writer_durability.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks/aggregation.py \
  tests/unit/benchmarks/test_aggregation.py
.venv/bin/mypy src/crypto_collector/benchmarks/aggregation.py
git diff --check
```

Expected: PASS.

- [x] **Step 6: Commit Task 4**

```bash
git add src/crypto_collector/benchmarks/aggregation.py \
  src/crypto_collector/benchmarks/contracts.py \
  tests/unit/benchmarks/test_aggregation.py tests/performance/test_writer_durability.py
git commit -m "feat: aggregate writer gate primary samples"
```

### Task 5: Build The Fresh-Process Runtime Verifier

**Files:**
- Create: `src/crypto_collector/benchmarks/runtime_verifier.py`
- Create: `tests/support/writer_gate_crash_child.py`
- Create: `tests/support/writer_gate_evidence.py`
- Create: `tests/support/writer_gate_mutations.py`
- Create: `tests/unit/benchmarks/test_runtime_fixture.py`
- Create: `tests/unit/benchmarks/test_runtime_verifier_interruption.py`
- Create: `tests/unit/benchmarks/test_runtime_verifier_mutations.py`
- Create: `tests/unit/benchmarks/test_runtime_verifier.py`
- Modify: `src/crypto_collector/benchmarks/contracts.py`
- Modify: `tests/performance/test_writer_durability.py`
- Modify: `tests/unit/benchmarks/test_artifacts.py`

- [x] **Step 1: Write a passing micro-evidence fixture and mutation RED tests**

Before constructing the fixture, freeze every field, order, invariant, status/successor
rule, and digest input for `GateCandidateReportV1`, `GateRunIndexV1`,
`GateRawInventoryV1`, `GateManifestInventoryV1`, `GateRuntimeReceiptV1`, and
`GateRuntimeIndexV1`. The fixture must contain committed workload bytes, plan rows,
five canonical trace
partitions plus their virtual merge hash, buckets, five worker sequences, six-process
resource rounds, health samples, raw zstd parts, and valid manifests. Do not construct
a verdict boolean directly.

```python
def test_runtime_verifier_recomputes_acceptance(tmp_path: Path) -> None:
    evidence = write_passing_micro_evidence(tmp_path)
    receipt = validate_runtime_evidence(evidence.run_index_path,
                                        target_probe=None)
    assert receipt.runtime_evidence_valid is True
    assert receipt.qualification_runtime_accepted is False


@pytest.mark.parametrize("mutation", RUNTIME_EVIDENCE_MUTATIONS)
def test_runtime_verifier_rejects_primary_fact_mutation(tmp_path: Path,
                                                        mutation: Mutation) -> None:
    evidence = write_passing_micro_evidence(tmp_path)
    mutation.apply(evidence)
    receipt = validate_runtime_evidence(evidence.run_index_path,
                                        target_probe=None)
    assert receipt.runtime_evidence_valid is False
    assert receipt.qualification_runtime_accepted is False
```

Mutations cover every workload/plan/trace/bucket/sample/report/inventory hash, due time,
payload byte/SHA, attempt/completion boundary, accepted identity, duplicate ordinal,
raw row, manifest count/hash, UTC hour, final worker field, resource limit, storage
health gap/coverage, resource prefix/gap/coverage, target claim, and serialized
candidate summary. Resource rounds must cover the bound admission-plus-drain sampling
interval; two valid post-warmup points followed by a truncated artifact are rejected.

The micro fixture is functional evidence. It cannot claim qualification because the
only qualifying workload is the compiled research-default workload at multiplier at
least two and duration at least 600 seconds (25,060,620 events). Test the qualification
receipt truth table with exact model facts here; the full verifier qualification path
is exercised only by the opt-in target-host test and Task 10. No test-only workload or
target bypass is permitted.

- [x] **Step 2: Run tests and verify RED**

Run: `.venv/bin/python -m pytest tests/unit/benchmarks/test_runtime_verifier.py -q`

Expected: FAIL because the verifier does not exist.

- [x] **Step 3: Implement disk-backed streaming validation**

Expose this exact public call shape:

```text
validate_runtime_evidence(run_index_path: Path, *,
                          target_probe: TargetProbePort | None)
    -> GateRuntimeReceiptV1
```

Qualification evidence requires a non-null target probe. Functional evidence forbids
one, can set `runtime_evidence_valid=true`, and must always set
`qualification_runtime_accepted=false`.

`TargetProbePort` accepts the loaded `GateTargetV1` plus the expected target ID and
returns a concrete `GateTargetReprobeV1`; an untyped mapping or boolean result is
forbidden. The real adapter is `reprobe_target`. The input path must be the canonical
`run-index.json`; outputs are its same-parent `runtime-receipt.json` and
`runtime-index.json`, so no caller-provided output can escape the trusted evidence
root. Use a unique attempt suffix for partial output. Reuse and validate an existing
receipt after interruption; never overwrite either final node.

Open a temporary SQLite database beneath the declared state root with
`journal_mode=WAL`, `synchronous=FULL`, strict tables, and primary keys for planned
event ID, exact accepted identity tuple, and durable row identity. Open the exact five
trace partitions with bounded readers, verify each part, heap-merge them by
`(due_monotonic_ns, planned_event_id)`, and stream-join that virtual trace with the
global oracle. Then stream manifests/raw rows through `load_raw_manifest` and
`validate_local_source`. Reject missing/extra/duplicate facts, partition/hash
disagreement, and noncontiguous per-worker acceptance ordinals.

Recompute buckets, counts, payload bytes, rates, bursts, UTC hours, worker aggregation,
resource/health predicates, and target re-probe facts. Compare candidate summaries
only to reject disagreement. Publish the receipt and runtime index without replacement;
remove the temporary SQLite files only after a successful directory sync.

- [x] **Step 4: Prove bounded memory and fail-closed interruption**

Add a marked performance test that validates five generated partitions totaling one
million synthetic rows under a test RSS bound. Unit tests use 10,000 rows. Interrupt
after each artifact boundary, rerun from a fresh verifier, and prove no partial
receipt is accepted or overwritten. An interruption before the receipt may retain its
unique partial; an interruption after receipt publication reuses that exact receipt
and publishes only the missing runtime index.

- [x] **Step 5: Run focused tests and checks**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_runtime_verifier.py \
  tests/performance/test_writer_durability.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks/runtime_verifier.py \
  src/crypto_collector/benchmarks/contracts.py \
  tests/unit/benchmarks/test_runtime_verifier.py
.venv/bin/mypy src/crypto_collector/benchmarks/runtime_verifier.py \
  src/crypto_collector/benchmarks/contracts.py
git diff --check
```

Expected: PASS.

- [x] **Step 6: Commit Task 5**

```bash
git add src/crypto_collector/benchmarks/runtime_verifier.py \
  src/crypto_collector/benchmarks/contracts.py \
  tests/unit/benchmarks/test_runtime_verifier.py \
  tests/performance/test_writer_durability.py
git commit -m "feat: independently verify writer gate runtime evidence"
```

### Task 6: Declare And Re-Probe The Linux Target

**Files:**
- Create: `src/crypto_collector/benchmarks/target.py`
- Create: `tests/unit/benchmarks/test_target.py`
- Modify: `src/crypto_collector/benchmarks/contracts.py`
- Modify: `tests/performance/test_writer_durability.py`

- [x] **Step 1: Write mount/probe/declaration RED tests**

Before writing implementation code, freeze the exact field order in the approved
design for `GateRootProbeV1`, `GateTargetV1`, and `GateTargetReprobeV1`. Both target
objects are private self-hashing documents: their `sha256` is the SHA-256 of canonical
JSON plus one newline with only the final `sha256` field omitted. A downstream document
reference separately hashes the complete published bytes, including that field.

Test decoded mountinfo escapes (`\040`, `\011`, `\134`), component-boundary matching,
longest mount selection, independent data/state lookups, sorted prefixed mount/super
options, major/minor device facts, exact 100 GiB floors, and one 200 GiB requirement
when device and mount are shared.

Test absolute real symlink-free distinct directories, non-Linux rejection, regular-file
sync, production hard-link no-replace, directory sync, cleanup plus cleanup-parent sync,
capability mismatch, target-ID mismatch, declaration SHA tampering, and no-replace
declaration publication.

- [x] **Step 2: Run tests and verify RED**

Run: `.venv/bin/python -m pytest tests/unit/benchmarks/test_target.py -q`

Expected: FAIL because target APIs do not exist.

- [x] **Step 3: Implement exact Linux probes**

Expose these exact public call shapes:

```text
declare_target(*, target_id: str, data_root: Path, state_root: Path,
               output: Path) -> GateTargetV1
reprobe_target(declaration: GateTargetV1, *, expected_target_id: str)
    -> GateTargetReprobeV1
```

Parse `/proc/self/mountinfo` without shell commands, unescape octal fields, and match
resolved paths on component boundaries. Probe the actual hard-link primitive used by
`RawWriterService`; do not accept `renameat2` as a substitute. Use `os.open` with
directory/file flags, `os.fsync`, `os.link`, and explicit cleanup syncs. Hash the
declaration with its digest omitted, then publish once through the artifact publisher.

- [x] **Step 4: Run focused tests and checks**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_target.py \
  tests/performance/test_writer_durability.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks/target.py \
  tests/unit/benchmarks/test_target.py
.venv/bin/mypy src/crypto_collector/benchmarks/target.py
git diff --check
```

Expected: PASS on macOS through injected Linux fixtures; real declaration remains
Linux-only.

- [x] **Step 5: Commit Task 6**

```bash
git add src/crypto_collector/benchmarks/target.py \
  src/crypto_collector/benchmarks/contracts.py \
  tests/unit/benchmarks/test_target.py tests/performance/test_writer_durability.py
git commit -m "feat: bind writer gate Linux target"
```

### Task 7: Run The Production Writer And Publish Candidate Evidence

**Files:**
- Create: `src/crypto_collector/benchmarks/runner.py`
- Create: `src/crypto_collector/benchmarks/writer.py`
- Create: `tests/unit/benchmarks/test_runner.py`
- Create: `tests/integration/benchmarks/__init__.py`
- Create: `tests/integration/benchmarks/test_writer_functional.py`
- Modify: `tests/performance/test_writer_durability.py`

- [x] **Step 1: Write CLI mode and preflight RED tests**

Use Typer's test runner to assert exact mode rules:

```text
functional: --functional-only required; target declaration forbidden; roots optional;
qualification: data/state/declaration/expected target/image IDs required;
both: workload, multiplier, integral duration, report/evidence root required.
```

Reject multiplier below one, functional duration below 10 seconds, qualification
duration below 10 minutes, nonintegral durations, UTC-hour capacity below
`duration + 30s`, existing raw/recovery exchange subtrees, malformed image IDs, and
wrong target IDs. Functional reports must never expose authoritative acceptance.

- [x] **Step 2: Write a micro production-path integration RED test**

Use a real spawn context and a tiny workload. Start one supervisor and five child
processes, have each child open its real `RawWriterService`, run its exchange iterator,
publish its trace partition, and close. Validate manifests/raw rows and the virtual
five-part merge, then invoke the fresh runtime verifier. Assert exact record/payload
conservation, five stable workers, six stable process keys, expected touched files,
zero error counters, and a passing runtime receipt. A separate injected in-process
child harness may cover deterministic clock edge cases, but it cannot replace the
spawn integration test.

Inject one periodic `statvfs` failure and one worker-health sampling failure. Each
must stop the run, retain its completed/partial health artifact, and forbid candidate
report publication even if a later probe would succeed.

- [x] **Step 3: Run tests and verify RED**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_runner.py \
  tests/integration/benchmarks/test_writer_functional.py -q
```

Expected: FAIL because runner/CLI APIs do not exist.

- [x] **Step 4: Implement runner orchestration**

Use `multiprocessing.get_context("spawn")` to create exactly five canonical exchange
children. Inside each child, open one service using public `RawWriterService.open`
arguments: data/state roots, exchange, deterministic worker ID, canonical config SHA,
generation zero, writer/ingress configs, exact metric-stream allowlist, and production
clock. Derive the config digest from the fully resolved benchmark writer/ingress
configs and require every child to report the same digest and workload-plan hash. Set
the raw-frame bound to `max(1 MiB, workload payload maximum + 256 KiB)` so a
maximum-size payload plus its canonical envelope remains one bounded frame.

Compute the 25-million-row global workload-plan hash once in the supervisor before
spawn/admission. Each child validates the exact workload source SHA and canonical plan
header/stream summaries and binds the supervisor-provided global hash; children must
not each recompute the global event hash.

After all readiness handshakes, the supervisor chooses one future monotonic and UTC
admission anchor. Each child uses only `iter_exchange_plan_events(plan, exchange)`,
sleeps until due time, calls only `try_accept(draft, source=source, shard=shard)`, and
streams timing/status/identity facts into its own trace partition. Continue after
overflow only to retain complete failure evidence. No planned event or trace row uses
IPC. The supervisor issues bounded sample commands and accepts a round only when all
five worker samples and all six process resource samples are complete and stable.

Qualification stops attempts at the admission boundary. Functional mode continues
until every planned event has an admission result, recording lateness instead of
dropping the tail. Each child then calls `sync_now`,
`close_all(CloseReason.SHUTDOWN, deadline)`, validates returned manifests, and captures
final CLOSED snapshots. The supervisor validates the five trace parts and virtual
merge, then publishes inventories, buckets, candidate report, and run index. Any child
exit, IPC timeout, missing round, or anchor/config disagreement stops the others,
publishes no authoritative run index, and forbids restart or exchange-subtree reuse.

All artifacts use same-parent no-replace publication. On failure after artifact
publisher initialization, retain partial/raw state and emit only non-DAG diagnostics.
Never inspect service private fields or delete/reuse target exchange trees.

Functional mode is an eventual-correctness check. It records scheduling lateness,
durability SLO/resource limits, sampling gaps, and sampled topology peaks but does not
use them as pass predicates. It still requires exact record/byte/identity
conservation, readable canonical raw files, final CLOSED workers, no critical worker
observation, and zero data-path errors or loss. Qualification retains all schedule,
SLO, coverage, resource, and peak limits. Use a 24-hour functional liveness watchdog
only to terminate a deadlock; do not describe it as a throughput requirement.

Expose CLI commands:

```text
python -m crypto_collector.benchmarks.writer run --workload PATH --multiplier INT
  --duration DURATION --evidence-root PATH --report PATH [qualification options]
python -m crypto_collector.benchmarks.writer validate-runtime --run-index PATH
  --expected-target-id ID
python -m crypto_collector.benchmarks.writer declare-target --target-id ID
  --data-root PATH --state-root PATH --output PATH
```

Keep backward-compatible default invocation equivalent to `run` for the documented
functional command.

- [x] **Step 5: Run the exact short functional gate**

Run:

```bash
GATE_FUNCTIONAL_ROOT="$(mktemp -d /tmp/writer-gate-functional.XXXXXX)"
.venv/bin/python -m crypto_collector.benchmarks.writer \
  --workload benchmarks/workloads/research-default-v1.yaml \
  --multiplier 2 --duration 10s \
  --evidence-root "$GATE_FUNCTIONAL_ROOT/evidence" \
  --report "$GATE_FUNCTIONAL_ROOT/writer-short.json" --functional-only
test -f "$GATE_FUNCTIONAL_ROOT/writer-short.json"
```

Expected: exit 0; `candidate_runtime_passed=true`; no authoritative acceptance field;
417,677 attempted/accepted/durable/sampled/manifest rows; exact planned payload bytes;
3,172 touched files; valid raw/manifests; runtime receipt has
`runtime_evidence_valid=true` and `qualification_runtime_accepted=false`; every error
count is zero. Record the printed `GATE_FUNCTIONAL_ROOT` for inspection; functional
temporary data/state roots remain owned for the entire verification lifecycle.

- [x] **Step 6: Run focused tests and checks**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_runner.py \
  tests/integration/benchmarks/test_writer_functional.py \
  tests/performance/test_writer_durability.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks/runner.py \
  src/crypto_collector/benchmarks/writer.py tests/unit/benchmarks/test_runner.py \
  tests/integration/benchmarks/test_writer_functional.py
.venv/bin/mypy src/crypto_collector/benchmarks/runner.py \
  src/crypto_collector/benchmarks/writer.py
git diff --check
```

Expected: PASS.

- [x] **Step 7: Commit Task 7**

```bash
git add src/crypto_collector/benchmarks/runner.py \
  src/crypto_collector/benchmarks/writer.py tests/unit/benchmarks/test_runner.py \
  tests/integration/benchmarks tests/performance/test_writer_durability.py
git commit -m "feat: run auditable writer durability workload"
```

### Task 8: Reproduce Provenance, Acceptance, And Disclosure

**Files:**
- Create: `src/crypto_collector/benchmarks/provenance.py`
- Create: `tests/unit/benchmarks/test_provenance.py`
- Create: `scripts/reproduce-writer-image.sh`
- Create: `requirements/build.in`
- Modify: `src/crypto_collector/benchmarks/writer.py`
- Modify: `src/crypto_collector/benchmarks/contracts.py`
- Create: `requirements/build.lock`
- Modify: `tests/performance/test_writer_durability.py`

- [x] **Step 1: Write source/image/container/archive RED tests**

Mock Git/Docker/provider command ports and assert two `git archive` source contexts,
identical commit/epoch/lock/workload/Docker hashes, complete build lock including
Hatchling, identical wheel/image IDs, exact OCI labels/provenance file, platform,
builder/frontend facts, `65532:65532`, retained successful writer/verifier containers,
and `.Image` equality.

Reject dirty checkout inputs, untracked/ignored build inputs, mismatched builds,
caller-only image claims, removed/failed containers, mutable/unversioned archives,
WebDAV-only evidence, inventory mismatch, receipt/index disagreement, private paths in
disclosure, and any attempt to qualify functional mode.

This is also the first task where the complete one-way DAG exists. Freeze every field
order before implementation and assert the exact predecessor chain:

```python
assert runtime_receipt.run_index_sha256 == run_index.sha256
assert runtime_index.runtime_receipt_sha256 == runtime_receipt.sha256
assert provenance.runtime_index_sha256 == runtime_index.sha256
assert acceptance.provenance_receipt_sha256 == provenance.sha256
assert disclosure.acceptance_receipt_sha256 == acceptance.sha256
```

Reject self/future references, a predecessor of the wrong schema or mode, and any node
whose last `sha256` field does not equal the digest of its preceding canonical fields.

- [x] **Step 2: Run tests and verify RED**

Run: `.venv/bin/python -m pytest tests/unit/benchmarks/test_provenance.py -q`

Expected: FAIL because provenance APIs do not exist.

- [x] **Step 3: Implement host-side provenance ports and receipts**

Expose these exact public call shapes:

```text
validate_provenance(*, source_commit: str, runtime_index: Path,
                    archive_attestation: Path, writer_container: str,
                    verifier_container: str, docker: DockerPort, git: GitPort,
                    archive_provider: ArchiveProviderPort)
    -> GateAcceptanceReceiptV1
build_disclosure(acceptance: GateAcceptanceReceiptV1)
    -> GateEvidenceDisclosureV1
```

Treat every subprocess/API response as untrusted structured input. Validate exact
digests and container image IDs before writing receipts. The disclosure allowlist must
exclude absolute paths, hostnames, raw locators, credentials, environment values, and
mount facts; include only safe plan/result/provenance facts and opaque locator digest.

Add `validate-provenance` and `build-disclosure` CLI commands. Do not add boto3/oss2 to
the collector image. Accept a strict operator-side S3 Object Lock or OSS WORM
attestation; WebDAV is represented only as an optional verified backup.

- [x] **Step 4: Lock deterministic build dependencies**

Create `requirements/build.in` containing exactly the existing build-system constraint
`hatchling>=1.27,<2`, then compile its transitive dependencies:

```bash
.venv/bin/pip-compile --generate-hashes \
  --output-file=requirements/build.lock requirements/build.in
.venv/bin/python -m pip install --dry-run --require-hashes \
  -r requirements/build.lock
.venv/bin/python -m pip install --dry-run --require-hashes \
  -r requirements/collector.lock
```

Keep `requirements/collector.lock` unchanged and runtime-only. Verify neither lock
contains archive/materializer SDKs and every non-comment requirement has hashes.

- [x] **Step 5: Implement the reproducibility script**

The script must use `set -euo pipefail`, explicit temporary directories from `mktemp
-d`, trap cleanup, `git archive <exact-commit>`, fixed `linux/amd64`, pinned BuildKit/
frontend facts, `--provenance=false`, `--sbom=false`, exact `SOURCE_DATE_EPOCH`, two
`--no-cache` builds, and structured `docker image/container inspect`. It writes a
canonical transcript but no acceptance receipt; Python validates that transcript.

- [x] **Step 6: Run focused tests and checks**

Run:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks/test_provenance.py \
  tests/performance/test_writer_durability.py -q
.venv/bin/ruff check src/crypto_collector/benchmarks/provenance.py \
  tests/unit/benchmarks/test_provenance.py
.venv/bin/mypy src/crypto_collector/benchmarks/provenance.py
sh -n scripts/reproduce-writer-image.sh
git diff --check
```

Expected: PASS.

- [x] **Step 7: Commit Task 8**

```bash
git add src/crypto_collector/benchmarks/provenance.py \
  src/crypto_collector/benchmarks/writer.py \
  src/crypto_collector/benchmarks/contracts.py \
  tests/unit/benchmarks/test_provenance.py \
  tests/performance/test_writer_durability.py scripts/reproduce-writer-image.sh \
  requirements/build.in requirements/build.lock
git commit -m "feat: verify writer gate provenance"
```

### Task 9: Pin The Image, Write Operations, And Pass Implementation Gates

**Files:**
- Create: `Dockerfile`
- Create: `.dockerignore`
- Create: `docs/operations/writer-benchmark.md`
- Modify: `tests/performance/test_writer_durability.py`

- [x] **Step 1: Write Docker/runbook contract RED tests**

Parse the Dockerfile and runbook as text plus structured Docker inspect fixtures.
Require digest-pinned Linux base, lock-only installs, deterministic wheel build,
read-only `/app/build-provenance-v1.json`, workload copy, final `USER 65532:65532`, no
archive/materializer SDKs, fixed CLI entry behavior, no secret values, and exact
runner/runtime/provenance/archive/disclosure command order.

The runbook must distinguish implementation PASS, Docker reproducibility PASS, target
pending, runtime failure, provenance failure, immutable archive failure, and accepted
evidence. It must prohibit redacting canonical originals and prohibit WebDAV-only
qualification evidence.

- [x] **Step 2: Run tests and verify RED**

Run: `.venv/bin/python -m pytest tests/performance/test_writer_durability.py -q`

Expected: FAIL on missing Dockerfile/runbook contracts.

- [x] **Step 3: Implement the pinned multi-stage image**

Use a Python base pinned by registry SHA-256 digest and a fixed `# syntax=` frontend.
Build a wheel from the exact source archive using `requirements/build.lock`, install
only `requirements/collector.lock` dependencies into the runtime stage, copy the
immutable workload/golden files, emit labels and canonical provenance, remove build
caches, and switch to numeric UID/GID 65532. `.dockerignore` excludes Git metadata,
worktrees, virtualenvs, caches, raw/evidence outputs, secrets, and unrelated local
files.

- [x] **Step 4: Write the complete runbook**

Document prerequisites, fresh root provisioning, target declaration, fixed named
writer container, fresh-process runtime verifier container, private file inventory,
S3 Object Lock/OSS WORM archival attestation, two-build provenance validation,
acceptance/disclosure generation, WebDAV backup, cleanup ordering, and evidence commit
rules. Commands retain containers until host inspection succeeds.

- [x] **Step 5: Run all precommit gates**

Run fresh:

```bash
.venv/bin/python -m pytest tests/unit/benchmarks \
  tests/integration/benchmarks tests/performance/test_writer_durability.py -q
GATE_FUNCTIONAL_ROOT="$(mktemp -d /tmp/writer-gate-functional.XXXXXX)"
.venv/bin/python -m crypto_collector.benchmarks.writer \
  --workload benchmarks/workloads/research-default-v1.yaml \
  --multiplier 2 --duration 10s \
  --evidence-root "$GATE_FUNCTIONAL_ROOT/evidence" \
  --report "$GATE_FUNCTIONAL_ROOT/writer-short.json" --functional-only
test -f "$GATE_FUNCTIONAL_ROOT/writer-short.json"
.venv/bin/python -m pytest -q -m "not live and not performance" --ignore=tests/smoke
.venv/bin/ruff check .
.venv/bin/ruff format --check .
.venv/bin/mypy src
git diff --check
```

Expected: every command exits 0; functional candidate/runtime receipt pass but no
acceptance receipt exists and `qualification_runtime_accepted` remains false.

- [x] **Step 6: Commit the implementation gate**

```bash
git add Dockerfile .dockerignore docs/operations/writer-benchmark.md \
  tests/performance/test_writer_durability.py
git commit -m "test: establish auditable writer durability gate"
```

- [x] **Step 7: Perform final two-stage branch review**

Dispatch one plan/spec reviewer and one code-quality reviewer over every Task 1-9
commit and the approved design. Fix every P0/P1/P2 with separate commits, rerun the
full precommit gate, and push only after both reviewers report no remaining P0/P1/P2.

- [ ] **Step 8: Reproduce the image when Docker is available**

From the exact clean implementation commit run:

```bash
scripts/reproduce-writer-image.sh "$(git rev-parse HEAD)"
```

Expected: two clean `git archive` builds have identical wheel SHA and image ID; image
user is `65532:65532`; labels/provenance/workload match. If Docker is unavailable,
record this gate as pending without reverting or withholding reviewed implementation
commits. A build fix is a new implementation commit and restarts this step.

### Task 10: Run Real Linux Qualification And Commit Disclosure Separately

**Files:**
- Create after successful target run: `docs/operations/evidence/gate-b-disclosure-v1.json`
- Create after successful target run: `docs/operations/evidence/gate-b-acceptance-public-v1.json`
- Create after successful target run: `docs/operations/evidence/gate-b-validation-transcript.txt`
- Modify after successful target run: `docs/operations/writer-benchmark.md`

- [ ] **Step 1: Provision a real Linux target and immutable evidence backend**

Use the runbook with fresh data/state roots, each exact 100 GiB floor (or exact 200 GiB
combined floor on one shared mount), Docker access, S3 Object Lock or OSS WORM
retention, and optional WebDAV backup. Do not use macOS Docker Desktop as target
evidence.

- [ ] **Step 2: Execute immutable-image run and runtime verification**

Declare the target, run the 10-minute multiplier-two workload in a fixed named
container without network, retain the container, then run `validate-runtime` in a
second fixed named container. Expected runtime receipt: exact 25,060,620 records,
3,505 active/touched identities, full-second bursts, <=1s durability max, all equality/
zero-error/resource/target predicates true.

- [ ] **Step 3: Archive private evidence and validate provenance**

Inventory every private file, upload under immutable provider retention, verify object
version and inventory hash, make the WebDAV backup when enabled, then run two clean
builds and `validate-provenance`. Inspect retained container `.Image` values before
cleanup. Expected final acceptance receipt: `qualification_accepted=true`.

- [ ] **Step 4: Generate and review the public disclosure**

Run `build-disclosure`, scan it and the sanitized transcript for absolute paths,
hostnames, credentials, private locators, environment values, and mount facts, and
verify all are absent. Re-run receipt/disclosure validators from a clean checkout.

- [ ] **Step 5: Commit evidence separately**

```bash
git add docs/operations/evidence docs/operations/writer-benchmark.md
git commit -m "evidence: qualify auditable raw writer gate"
```

If any target/runtime/archive/provenance predicate fails, retain the private failure
evidence, do not create this commit, and record qualification as pending/failed in the
runbook. The reviewed Task 1-9 implementation remains valid.

## Plan02 Merge Gate

Before merging `codex/plan02-durable-storage` into master:

1. Rebase/merge current master non-destructively and resolve only genuine conflicts.
2. Re-run repository offline/full tests, benchmark contract tests, Ruff, format, mypy,
   `git diff --check`, and image reproducibility when Docker is available.
3. Obtain fresh plan/spec and code-quality reviews over the integrated diff.
4. Confirm branch/remote clean and every Plan02 Task 1-9 implementation artifact is
   present. Task 10 external evidence may remain explicitly pending when no real target
   exists, as permitted by the approved design.
5. Merge to master and push only after all required implementation gates pass. Never
   rewrite or discard unrelated master/user changes.
