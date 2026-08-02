# Writer Gate B Auditable Evidence Design

Date: 2026-08-02

Status: approved design direction (option A); written specification awaiting user review

## 1. Purpose

Writer Gate B proves that the production raw-writer path can accept and durably
publish the committed research workload without loss, while keeping enough primary
evidence for a later independent verifier to reproduce the verdict.

This design replaces ambiguous Task 7 clauses in
`docs/superpowers/plans/2026-07-31-durable-raw-storage.md`. In particular, it removes
the self-validating report, the practically unattainable final-event burst deadline,
and the instruction to redact canonical evidence in place.

The implementation remains writer-only. It does not add exchange network traffic,
selection, materialization, archival policy, or full-collector operations.

## 2. Required Outcomes

Gate B must provide all of the following:

1. A versioned workload whose identities, payloads, counts, bytes, due times, and
   burst deadlines are deterministic from committed inputs.
2. A production-path runner that uses only public `RawWriterService` APIs.
3. Primary artifacts that allow counts, payload bytes, accepted identities, writer
   snapshots, durable rows, and manifests to be joined without trusting report
   summaries.
4. A runtime verifier that re-reads persisted artifacts after the runner exits.
5. A provenance verifier that independently binds the source commit, wheel, lock,
   Dockerfile, workload, image, and executed container.
6. An authoritative acceptance receipt. A runner-generated report is never itself
   proof of qualification.
7. A separate disclosure document for Git. Canonical private evidence is never
   modified or presented as valid after redaction.

The implementation may be committed without target hardware. Qualification remains
pending until both verifier stages succeed on retained target evidence.

## 3. Architecture

The public facade remains `crypto_collector.benchmarks.writer`. Internally, Task 7 is
split into bounded modules:

- `contracts.py`: strict frozen evidence models and canonical JSON encoding.
- `oracle.py`: deterministic identity, payload, count, and schedule oracle.
- `artifacts.py`: streaming JSONL/zstd readers and no-replace artifact publication.
- `aggregation.py`: worker-sequence, sampling-round, resource, and histogram logic.
- `target.py`: Linux target declaration and repeatable root probes.
- `runner.py`: production `RawWriterService` orchestration.
- `runtime_verifier.py`: independent replay of workload, trace, raw, manifest, and
  target facts.
- `provenance.py`: clean-source, wheel, image, and executed-container verification.
- `writer.py`: CLI composition only.

The runner imports the oracle; it does not contain a second workload algorithm. The
runtime verifier also invokes the versioned oracle, while committed literal golden
vectors prevent a changed oracle from silently redefining both production and
validation behavior.

## 4. Immutable Workload Contract

### 4.1 Versioned inputs

`research-default-v1.yaml` is immutable once evidence exists. Any semantic change
requires a new filename and schema/name version. The schema contains these explicit
values rather than relying on enum iteration or dictionary order:

- ordered exchanges: `binance`, `okx`, `bybit`, `bitget`, `kraken`;
- ordered markets per exchange: `spot`, `perpetual`;
- 25 base symbols per exchange/market;
- derivative logical streams: `funding`, `open_interest`;
- transport per stream;
- `identity_algorithm: gate-identity-v1`;
- `payload_algorithm: gate-payload-v1`;
- `schedule_algorithm: gate-schedule-v2-full-second-burst`;
- the existing exact rates, payload sizes, queue limits, and qualification limits.

The workload SHA-256 is over the exact committed YAML bytes. Qualification accepts
only the compiled-in SHA for that version.

### 4.2 Scalable identities

For multiplier `M`, canonical identity lanes are ordered by:

```
(exchange_index, market_index, lane_index, symbol_index, logical_stream)
```

where `0 <= lane_index < M` and `0 <= symbol_index < 25`. Instrument and wire keys
are the same ASCII string:

```
GATE-<EXCHANGE>-<MARKET>-L<lane:04d>-S<symbol:04d>
```

`EXCHANGE` and `MARKET` are the uppercase enum values. Lane and symbol values outside
their four-digit representations are rejected instead of changing the grammar. The
canonical storage identity string is:

```
gate-identity-v1:<exchange>:<market>:<instrument-key>:<logical-stream>
```

The control form is exactly
`gate-identity-v1:<exchange>:-:-:_control`. Ordinary logical stream names equal their
stream-group names. The derivative group expands in order to `funding` then
`open_interest`; the control group emits `_control`. No locale or runtime hash
participates.

Each of the six ordinary streams has `250 * M` file identities. Perpetual identities
have two derivative logical streams and therefore contribute `125 * M * 2` files.
Exactly one exchange-scoped `_control` identity exists per exchange and remains fixed
at five. Consequently:

```
scalable_file_count = 6 * 250 + 2 * 125 = 1750
expected_active_file_count = 5 + M * 1750
```

At multiplier two the required peak is exactly 3,505.

The plan distinguishes `declared_file_identity_count` from
`expected_touched_file_identity_count`. An identity is touched only when its allocated
event count is nonzero. Qualification counts guarantee every declared identity is
touched and therefore require the measured peak to be 3,505. In the 10-second
multiplier-two functional plan, deep snapshot has only 167 events for 500 declared
identities; its exact touched-file expectation is consequently 3,172. Functional mode
must match that computed value and can never use the declared count as a fake measured
peak.

### 4.3 Exact counts and allocation

Rates are strict decimal strings parsed as `Decimal`. Binary float input is rejected.
Every Decimal used by the oracle is converted to its exact integer numerator and
denominator before multiplication, ceiling, or selector-threshold floor. The process
Decimal context therefore cannot affect any count, payload, or hash.
For each stream group:

```
required_rate = base_instances * mean_records_per_second * M
N = ceil(required_rate * duration_ns / 1_000_000_000)
```

`base_instances` is the stream's `instances` for ordinary/control groups and
`file_instances` for the derivative group. Derivative `instrument_instances` exists
only to prove that each instrument expands to exactly the declared `funding` and
`open_interest` files; it is not the rate multiplier.

Ordinary and derivative rows allocate `N` over their scaled identity count. Control
allocates `N` over five fixed identities; multiplier affects its rate, not its files.
For canonical identity index `k`, `divmod(N, identity_count)` gives `(q, r)` and the
first `r` identities receive `q + 1` events. The remainder receive `q`.
Identity-local sequence numbers are zero-based and contiguous through that identity's
allocated count.

For each identity-local sequence, the planned event ID is lowercase SHA-256 hex over
the newline-free ASCII record:

```
gate-event-v1:<seed>:<stream-group>:<canonical-identity>:<local-sequence>
```

This ID is the tie-breaker for all schedules and artifacts.

### 4.4 Full-second burst semantics

Qualification duration is an integral number of seconds and at least 600 seconds.
Functional duration is integral and at least 10 seconds. The final second is a drain
reserve, so planned due times are confined to `[0, duration_ns - 1s)`.

For stream `S`:

```
required_B = base_instances * burst_records_in_1s * M
B = min(N, required_B)
burst_second = uint64_be(sha256(f"{seed}:{S}".encode("ascii")).digest()[:8]) % (duration_seconds - 1)
burst_start_ns = burst_second * 1_000_000_000
```

Qualification requires `N >= required_B`. Functional mode may use capped `B`.
The first `B` events in canonical identity/local-sequence enumeration all have exactly
`due_offset_ns = burst_start_ns`; ties at that due time are ordered by planned event ID.
They may not be attempted early and every one must complete accepted before
`burst_start_ns + 1s`. This gives the last event the same full-second deadline as the
first and directly measures admission of the whole burst.

The remaining events are distributed deterministically over the schedulable span
excluding the burst second. Let `J = N - B`, `schedulable_ns = duration_ns - 1s`, and
`outside_ns = schedulable_ns - 1s`. For zero-based remaining event index `j` in
canonical identity/local-sequence order:

```
compressed = floor(j * outside_ns / J)
due = compressed if compressed < burst_start_ns else compressed + 1s
```

The formula is skipped when `J == 0`. The final event order is
`(due_offset_ns, planned_event_id)`. Every event has an exclusive completion deadline
of `due_offset_ns + 1s`; the drain reserve ensures this is no later than the admission
window end. `early` means attempt start before due. `late` means admission completion
at or after the event deadline. `out_of_window` means either attempt start or admission
completion is outside `[admission_started, admission_started + duration_ns)`.

Per-second bucket rows cover every admission second including the zero-scheduled drain
second. They separately record scheduled, attempted, accepted, and accepted-in-actual-
second counts. Scheduled, attempted, accepted, payload, early, late, and out-of-window
facts are attributed to the event's scheduled second. Actual-second acceptance uses
`floor((admission_completed - admission_started) / 1s)`. The burst predicate requires
the selected stream/bucket to contain exactly `B` scheduled, attempted, accepted, and
accepted-in-actual-second rows. Smooth traffic may complete in a later second while
still meeting its one-second deadline.

### 4.5 Exact payloads

`gate-payload-v1` uses only `sha256`, `shake_256`, integer arithmetic, ASCII, and the
repository JSON encoder.

For selector name `X`, a selector lane is defined exactly as:

```
uint64_be(
  sha256(f"gate-payload-v1:{planned_event_id}:{X}".encode("ascii")).digest()[:8]
)
```

Independent selector names `size`, `decimal`, `common-key`, `incompressible`,
`decimal-whole`, `decimal-fraction`, and `uncommon-key` are used. They select:

- target payload length from `size % 100`: p50 for 0-49, p95 for 50-94, max for
  95-99;
- decimal-string layout using the exact configured fraction threshold;
- common-key layout using the exact repeated-key fraction threshold;
- pseudorandom padding using the exact incompressible fraction threshold.

Fraction thresholds are computed as exact integer division
`numerator(fraction) * 2**64 // denominator(fraction)`, and a feature is selected when
its lane is strictly below its threshold. Common layouts use the key `value`;
uncommon layouts use `value_00` through `value_15`, selected by
`uncommon-key % 16`. The selected value is the integer `decimal-whole % 100000000`
unless decimal layout is selected, in which case it is the string
`<whole>.<fraction:08d>` using `decimal-fraction % 100000000`.

The payload mapping insertion order is exactly `algorithm`, `event_id`, `stream`,
`identity`, `local_sequence`, the selected value key, then `padding`. Control payloads
insert `kind: "writer_gate_control"` and
`affected_markets: ["spot", "perpetual"]`, in that order, immediately before
`padding`. This makes the generated draft valid under the production control-ingress
contract without changing the payload after its SHA is bound. The repository encoder
preserves that order. No other optional field is omitted.

The payload `stream` value is always the expanded identity's logical stream. In
particular derivative payloads use `funding` or `open_interest`, never the
`derivative` stream-group name.

The encoder first measures the base payload with an empty `padding` string. It rejects
a target smaller than that encoding. Padding is then exactly the remaining number of
bytes. Compressible padding is repeated `A`. Pseudorandom padding is generated by
`shake_256(f"gate-padding-v1:{planned_event_id}".encode("ascii"))`; each output byte's
low six bits index `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_`.
Encoding is repeated once and must equal the target length exactly; disagreement is a
contract error.

`expected_payload_byte_count` is the streaming sum of those exact canonical payload
lengths. Raw envelope bytes and compressed file bytes are separate observations and
cannot satisfy this predicate.

### 4.6 Canonical workload-plan rows

Every workload-plan record is repository canonical JSON followed by one ASCII newline.
Enums use their string values, Decimal fields use their canonical strings, null fields
remain explicit JSON `null`, and no key sorting is applied. The hash input is exactly
one header row, eight stream-summary rows in declared stream-group order, and every
event row globally ordered by `(due_offset_ns, planned_event_id)`. The payload body is
not embedded in an event row; its exact byte count and SHA bind it instead.

The header key order is exactly:

```text
schema_version, record_type, workload_sha256, workload_name, generation_seed,
identity_algorithm, event_algorithm, payload_algorithm, schedule_algorithm,
multiplier, duration_ns, duration_seconds, declared_file_identity_count,
expected_touched_file_identity_count, expected_record_count
```

The stream-summary key order is exactly:

```text
schema_version, record_type, stream_group, logical_streams, transports, exchanges,
markets, symbols_per_market, generation_seed, identity_algorithm, event_algorithm,
payload_algorithm, schedule_algorithm, multiplier, duration_ns, base_instance_count,
identity_count, mean_records_per_second, burst_records_in_1s, payload_p50_bytes,
payload_p95_bytes, payload_max_bytes, decimal_string_fraction,
repeated_key_fraction, incompressible_fraction, expected_record_count,
expected_touched_file_identity_count, required_burst_count, scheduled_burst_count,
burst_second, burst_start_ns, expected_payload_byte_count
```

The event key order is exactly:

```text
schema_version, record_type, identity_algorithm, event_algorithm, payload_algorithm,
schedule_algorithm, planned_event_id, stream_group, logical_stream, exchange, market,
lane_index, symbol_index, instrument_key, canonical_identity, identity_index,
local_sequence, transport, due_offset_ns, deadline_offset_ns, payload_bytes,
payload_sha256
```

`PlannedEventV1` validates the standalone row shape, identity grammar, transport,
deadline, and canonical payload binding. It cannot by itself prove the seed-derived
event ID, allocation index, or plan-derived due time because those inputs are not
duplicated into each row. Only events emitted by `iter_plan_events(plan)` may be passed
to `build_native_draft`; evidence deserialization is never an authenticity boundary.
The runtime verifier establishes authenticity by rebuilding the bound plan and
requiring an exact canonical-line match in global order.

### 4.7 Golden vectors

A committed `research-default-v1.golden.json` contains literal, reviewable values:

- workload SHA;
- 10-second and 10-minute multiplier-two plan summaries and plan SHA values;
- each stream's count, required/capped burst, burst second, and payload-byte total;
- the first, boundary, and last canonical identities;
- selected baseline event IDs, due offsets, deadlines, target payload lengths, and
  payload SHA values for every stream;
- complete canonical payload bytes for a separate small golden profile whose target
  sizes are at most 1,024 bytes;
- fixed declared and touched file-identity counts.

Tests compare oracle output with these literals. Tests must not generate or update the
golden file through the production oracle. A separate reviewed maintenance command may
print candidate vectors, but it cannot overwrite the committed file.

### 4.8 Deterministic draft and source profile

Every exchange worker ID is exactly `gate-worker-v1-<exchange>`. The workload declares
these stream transports:

- WebSocket: `trade`, `book_live`, `ticker`, `bbo`, `funding`, `open_interest`, and
  `candle_1m`;
- REST: `book_deep_snapshot`;
- internal: `_control`.

Non-control native channels are `gate.v1.<logical-stream>`. Their event timestamp is
`admission_started_utc_ns + due_offset_ns` with source `gate_due_time`. WebSocket
sources use connection ID `gate-ws-v1-<exchange>-<market>`, generation zero, and egress
ID `gate-egress-v1-<exchange>`. REST sources have no connection fields and use the same
egress ID. Deep-snapshot REST metadata has scheduled UTC start/end times equal to the
event timestamp, method `GET`, path `/gate/v1/book-deep-snapshot`, one `instrument`
parameter, status 200, attempt one, empty rate-limit headers, and null interval fields.

`book_live` uses `sequence_verified` integrity; `book_deep_snapshot` uses
`snapshot_chain`; both use complete coverage. Other streams omit integrity and
coverage. Control drafts have null market/instrument/wire/channel/event-time fields,
internal transport/context, logical stream `_control`, and the exact affected-markets
payload field above.

The runtime verifier rebuilds this profile from the admission UTC anchor and compares
all decoded durable envelope fields other than writer-assigned received/monotonic time,
writer sequence, acceptance ordinal, config hash/generation, and compression facts.
Those assigned fields are instead joined exactly to the accepted identity, trace, and
stable worker snapshots.

## 5. Primary Artifact Contract

### 5.1 Canonical content

Evidence models are strict, frozen, versioned Pydantic models with extra fields
forbidden and strict integer/boolean handling. Canonical JSONL is
`encode_json(model_dump(mode="json")) + b"\n"` in the declared row order.

Zstd is an archive transport, not a canonical encoding. Artifact hashes used for
qualification are over decompressed canonical JSONL bytes. A separate compressed-file
SHA is required for transfer integrity. Therefore zstd library or frame metadata
cannot change the semantic evidence identity.

Every artifact is written to a same-parent temporary file, file-synced, closed,
published without replacement, and followed by a parent-directory sync. Partial
artifacts are retained and marked incomplete; they never qualify.

### 5.2 Artifact set

Evidence is a one-way hash DAG with no self-reference:

1. `GateRunIndexV1` binds the runner's primary artifacts and candidate report.
2. `GateRuntimeReceiptV1` binds the run-index hash and recomputed runtime facts.
3. `GateRuntimeIndexV1` binds the run index and runtime receipt.
4. The private immutable archive binds those three objects and all primary/raw data.
5. `GateProvenanceReceiptV1` binds the runtime-index hash and immutable archive
   version/hash.
6. `GateAcceptanceReceiptV1` binds both receipts, the runtime index, archive identity,
   and final verdict.
7. `GateEvidenceDisclosureV1` binds the acceptance receipt and safe public projection.

The required `GateRunIndexV1` binding set is:

- workload and streamed workload-plan hashes;
- admission trace content/compressed hashes;
- per-second bucket content hash;
- worker-sampling artifact hash;
- process-resource and storage-health artifact hashes;
- candidate report hash;
- target declaration hash;
- raw-root inventory and manifest inventory hashes;
- source commit, wheel, lock, Dockerfile, workload, and image identifiers;
- the artifact schema and algorithm versions.

Every node is published without replacement. Existing bytes are never edited, and a
later node may refer only to earlier nodes.

### 5.3 Admission trace

Each `GateAdmissionTraceV1` row records the planned event ID, stream, canonical
identity, local sequence, due and deadline monotonic times, attempt start, admission
completion, enqueue status, exact payload bytes/SHA, and exact accepted identity when
accepted. Accepted statuses require one identity; every other status forbids it.

`WorkloadPlanHeaderV1`, the declared-order stream summaries, and every
`PlannedEventV1` canonical line form the workload-plan hash input. Event rows are a
heap merge of the fixed number of per-stream iterators ordered by
`(due_offset_ns, planned_event_id)`. Each row includes identity/local sequence, payload
length/SHA, due/deadline offsets, and algorithm versions. Only equal-due groups need
local event-ID ordering; the full plan is never sorted or retained in memory.

The runtime verifier streams the trace and simultaneously rebuilds expected oracle
rows. It checks ordering, one-to-one event correspondence, exact payload facts,
timestamps, status/identity agreement, count/rate/burst buckets, and content hash.
It uses a temporary strict SQLite database under the state root for global identity
uniqueness and joins, so 25 million events are not materialized in RAM.

### 5.4 Writer samples

`GateWorkerSampleV1` wraps one canonical `WriterMetricsSnapshotV1` with round index,
request-start monotonic time, and request-completion monotonic time.
`GateSamplingRoundV1` declares the exact five expected worker keys and contains exactly
one sample per key. Worker requests within one round may overlap. A round's interval is
the minimum request start through maximum request completion; consecutive round
intervals must not overlap.

Within each stable worker sequence:

- external round and request times strictly increase;
- observed snapshot time is nondecreasing;
- an equal observed time requires byte-identical snapshot bytes;
- cumulative counters, bucket/sample counts, maxima, and series membership never
  decrease;
- quantiles may decrease and are not treated as counters;
- exchange, worker ID, config digest, and config generation never change.

Only each worker's final CLOSED barrier snapshot contributes cumulative totals and
histogram buckets. Round sums determine gauge peaks. Aggregate histogram quantiles are
nearest-rank values recomputed from elementwise-summed final buckets.

### 5.5 Resource and health samples

Process samples use Linux `/proc/self/status` `VmRSS` and a count of numeric entries in
`/proc/self/fd`. Samples are taken in monotonic rounds at the configured interval.
After warmup, RSS slope is the ordinary least-squares slope over
`(observed_monotonic_ns, rss_bytes)`, computed with `Decimal`, converted to bytes per
minute, and floored at zero. FD growth is maximum post-warmup FD count minus the first
post-warmup FD count, floored at zero.

Storage-health samples independently call `statvfs` for data and state roots and record
worker lifecycle/critical state. Sample gap is the difference between consecutive
scheduled monotonic times. Coverage is final completion time minus first request time.
The expected count and coverage predicates remain those in Plan02. Preflight and
post-run capability probes are separate from periodic health sampling.

## 6. Runner And Candidate Report

The runner opens exactly one `RawWriterService` per declared exchange with deterministic
worker IDs and immutable config. It uses production `try_accept`, `sync_now`,
`metrics_snapshot`, final barrier, `close_all`, manifest loading, and raw validation.
It never reads coordinator, ledger, ingress-queue, or recovery internals.

Qualification requires fresh data/recovery exchange subtrees, a same-hour UTC
preflight, multiplier at least two, duration at least ten minutes, a target declaration,
and the immutable image claim. Functional mode owns temporary roots, runs the exact
10-second workload, forbids a target declaration, and can never produce an acceptance
receipt.

The runner waits until each due time without busy spinning, attempts every planned
event exactly once, samples workers/resources concurrently, waits through the drain
second, closes and validates all outputs, and publishes a `GateCandidateReportV1`.
That report contains `candidate_runtime_passed`, but it has no authoritative
`qualification_accepted=true` field. Runner exit zero means only that candidate runtime
checks passed and all required primary artifacts were published.

All runner errors fail closed. The runner records the failure in a successor index if
possible, retains completed/partial artifacts, and does not delete or reuse target raw
state.

## 7. Target Declaration

Target declaration is Linux-only. Data and state roots must be distinct absolute,
symlink-free real directories. Each root is independently matched to the longest
component-boundary mount point in decoded `/proc/self/mountinfo`; mount and superblock
options remain separately prefixed before sorting/deduplication.

The declaration and runtime re-probe bind device major/minor, filesystem, mount point,
options, available bytes, file sync, directory sync, same-parent publication, and the
actual production no-replace primitive. Because Plan02 production publication uses
hard links, Gate B probes and requires hard-link no-replace. It must not claim
`renameat2` support as a substitute.

Each root has its exact 100 GiB floor. If both roots share device and mount point, one
current available-byte observation must meet the sum of both floors. Probe artifacts
are removed and their parent directories are synced again. Qualification requires an
explicit expected target ID and rejects any declaration or re-probe mismatch.

The declaration SHA covers its complete canonical private model with only the SHA field
omitted. It is published once without replacement. It is never redacted in place.

## 8. Two-Stage Independent Verification

### 8.1 Runtime receipt

After the writer container exits, a separate `validate-runtime` invocation starts from
the same immutable image but a fresh process. It reads the workload, target declaration,
evidence index, trace, samples, raw files, and manifests. It re-runs target probes and
the workload oracle, performs disk-backed joins, recomputes every runtime predicate,
and writes `GateRuntimeReceiptV1` without replacement.

The receipt binds every primary artifact hash, the recomputed candidate facts, verifier
version, target ID, source/image claims, and a runtime verdict. Serialized totals and
booleans in the candidate report are compared for disagreement but never override
recomputed facts.

### 8.2 Provenance receipt

`validate-provenance` runs on the target/build host with access to Git and Docker. It:

1. creates two source contexts using `git archive` from the exact clean commit, so
   ignored and untracked files cannot enter either build;
2. verifies the pinned Linux platform, base digest, Docker/BuildKit/frontend versions,
   disabled ambient provenance/SBOM metadata, and complete runtime/build locks;
3. builds twice with the exact commit timestamp as `SOURCE_DATE_EPOCH`;
4. requires identical wheel hashes and immutable image IDs;
5. verifies OCI labels, read-only provenance file, workload, dependency boundary, and
   final numeric user `65532:65532`;
6. inspects the retained writer and runtime-verifier containers and proves their
   `.Image` value equals the reproduced image ID and their exit states are successful;
7. verifies the runtime receipt and external evidence archive identity;
8. writes `GateProvenanceReceiptV1` and final `GateAcceptanceReceiptV1` without
   replacement.

Writer/verifier containers use fixed names and are not removed until provenance
inspection completes. The runtime environment image-ID variable is an untrusted claim;
it must equal Docker's independently inspected container image.

Only `GateAcceptanceReceiptV1.qualification_accepted=true` is authoritative. It is
possible only in qualification mode when both subordinate receipts pass and all bound
hashes agree. Functional mode, candidate reports, and runtime receipts alone cannot
claim qualification.

## 9. Private Evidence And Public Disclosure

The original trace, samples, report, target declaration, manifests, and raw dataset
remain a private immutable evidence set. Before any evidence commit, the operator must
retain the raw tree or archive it to a backend that supplies an immutable object version
or retention proof. The evidence index records that locator, object version/retention
facts, size, and content inventory hash. WebDAV without an enforceable immutable
version is a backup copy, not qualification evidence storage.

The archive manifest contains one `GateFileInventoryV1` row per regular file, ordered
by normalized relative POSIX path, with exact size and SHA-256. Symlinks, devices,
sockets, duplicate paths, and files outside the declared roots are rejected. Its
canonical content hash binds the complete raw, recovery, manifest, trace, sample,
report, run-index, runtime-receipt, and runtime-index set before upload. S3 Object Lock
or OSS WORM/version retention can satisfy the immutability predicate. Task 7 does not
add archive SDKs to the collector image; an operator-side archival command supplies
and verifies the provider version/retention attestation. WebDAV remains an additional
verified backup destination only.

Git receives a distinct `GateEvidenceDisclosureV1`, never a modified private model.
The disclosure contains safe workload/result/provenance facts, hashes of the complete
private index and receipts, and an opaque locator digest when the real locator is
sensitive. It omits mount paths, hostnames, raw object locators, and other private
fields. Its own SHA covers only the disclosure model.

The evidence commit contains the disclosure, acceptance receipt or a deliberately
public receipt projection, and a sanitized validation transcript. Documentation must
say where authorized operators can resolve the private evidence. A redacted report or
declaration must never be fed to the canonical verifier or described as the original.

## 10. Acceptance Predicates

Runtime acceptance is recomputed from primary artifacts and requires every following
predicate:

- exact workload/schema/seed/cardinality/plan/payload/schedule hashes;
- duration at least 600 seconds and multiplier at least two;
- exactly five stable workers and complete non-overlapping rounds;
- exact attempted/accepted/durable/sample/manifest record equality;
- exact attempted/accepted planned payload-byte equality;
- unique accepted identities joined one-to-one with decoded durable rows;
- exact per-stream rates and full-second bursts;
- zero early, late, out-of-window, loss, overflow, conformance, manifest, write, sync,
  publication, restart, and storage-health errors;
- valid final CLOSED snapshots, zero terminal gauges, final-only aggregation, and
  recomputed histogram quantiles/max;
- declared identity count exactly `5 + multiplier * 1750` and measured
  active-generation peak exactly equal to the oracle's touched-identity count, which
  must equal the declared count in qualification mode;
- one received-time UTC hour, target re-probe agreement, resource/health coverage,
  durability maximum at most one second, and configured RSS/FD limits.

Final acceptance additionally requires exact source/wheel/lock/workload/Docker/image
reproduction, executed-container binding, external private-evidence immutability, and
agreement between all index and receipt hashes.

Any missing primary artifact, unsupported schema/algorithm version, duplicate row,
trailing noncanonical bytes, hash mismatch, unverifiable external locator, or summary
disagreement rejects qualification.

## 11. Test Strategy

Implementation follows TDD in four reviewed increments.

1. Contracts and oracle:
   strict-model adversarial tests, literal golden vectors, Decimal/ceil counts,
   cardinalities, allocation remainders, all schedule edges, exact payload sizes, and
   streaming plan hashes.
2. Artifacts and runtime verification:
   every trace/status/time/hash mutation, SQLite uniqueness joins, buckets, worker
   sequence/round/final-only aggregation, resource formulas, terminal gauges, and
   report-summary disagreement.
3. Target and runner:
   mountinfo escapes/component boundaries, shared free-space accounting, actual
   hard-link/sync probes, CLI mode/preflight/fresh-root rules, injected clocks, and a
   micro-workload production-path integration test.
4. Provenance and operations:
   clean-context construction, labels/provenance/container inspection, disclosure
   separation, evidence-index mutations, short exact functional run, and runbook
   command tests.

Before an implementation commit, the complete performance-contract test file must be
run in PASS state, followed by the 10-second functional command and the repository
offline suite. Ruff, format, mypy, `git diff --check`, and two-stage subagent review are
mandatory. Docker reproducibility is a later implementation/build gate when a daemon
is available. Real Linux target evidence is a separate commit after both receipts pass.

## 12. Git And Delivery Sequence

All work remains on `codex/plan02-durable-storage` in its dedicated worktree.

1. Commit and push this design only.
2. Amend Task 7 into small TDD implementation tasks after user review.
3. Commit and push each reviewed implementation increment in dependency order.
4. Produce the clean reproducible-image evidence against the final implementation
   commit; commit build fixes separately and repeat when needed.
5. Produce external target evidence only after a real Linux qualification succeeds.
6. Merge Plan02 to master only after branch-wide tests, review, clean status, and
   requirement-by-requirement completion audit pass.

Plan01/Plan03 work and unrelated user changes are not modified by this sequence.
