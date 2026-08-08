# Writer Gate B Auditable Evidence Design

Date: 2026-08-02

Status: approved design direction (option A); written specification awaiting user review

> **Scope authority (2026-08-08):** This evidence design is retained, but the
> [`functional-completion scope amendment`](2026-08-08-functional-completion-scope-amendment.md)
> makes its `1s`, `10m@2x`, and target qualification predicates optional release
> performance evidence. Functional conservation/recovery and bounded short multi-round
> checks remain required. A qualification failure remains a failure and must not be
> presented as `qualification_accepted` or `EVIDENCE_ACCEPTED`.

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
For ordinary and derivative streams, each identity contributes its first
`min(allocated_count, burst_records_in_1s)` local events. Control has five fixed
identities while its rate scales with `M`, so each control identity instead contributes
its first `min(allocated_count, burst_records_in_1s * M)` local events. These per-
identity prefixes contain exactly `B` events because allocation counts differ by at
most one. Every selected event has exactly `due_offset_ns = burst_start_ns`; ties at
that due time are ordered by planned event ID. This prevents the canonical identity
ordering from concentrating a nominally global burst in the first exchange. Selected
events may not be attempted early and every one must complete accepted before
`burst_start_ns + 1s`. This gives the last event the same full-second deadline as the
first and directly measures admission of the whole burst.

`gate-schedule-v2-full-second-burst` is frozen to this distributed-prefix definition.
An earlier unmerged development implementation selected one global first-`B` prefix;
it produced no target declaration, runtime receipt, or acceptance evidence, and its
candidate hashes are not a supported schedule variant.

The remaining events are distributed deterministically over the schedulable span
excluding the burst second. Let `J = N - B`, `schedulable_ns = duration_ns - 1s`, and
`outside_ns = schedulable_ns - 1s`. Exclude the selected prefix from each identity,
then enumerate the remaining events in canonical identity/local-sequence order. For
zero-based remaining event index `j`:

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

Canonical field order is part of the version-one contract. Models are added by the
task that first has enough primary facts to test every field; Task 3 must not create
placeholder report, receipt, archive, provenance, acceptance, or disclosure models.
Those later self-hashing models put their own `sha256` field last, include it in their
published canonical bytes, and omit only that field from their digest input.

Task 3 freezes these foundational field orders:

```text
GateArtifactRefV1:
schema_version, record_type, relative_path, row_count, content_size_bytes,
content_sha256, compressed_size_bytes, compressed_sha256

GateExchangeArtifactPartitionV1:
schema_version, record_type, exchange, artifact

GateAdmissionTraceSetV1:
schema_version, record_type, partitions, merged_row_count,
merged_content_size_bytes, merged_content_sha256

GateAdmissionTraceV1:
schema_version, record_type, planned_event_id, stream_group, logical_stream,
exchange, market, instrument_key, canonical_identity, identity_index,
local_sequence, due_monotonic_ns, deadline_monotonic_ns,
attempt_started_monotonic_ns, admission_completed_monotonic_ns, enqueue_status,
payload_bytes, payload_sha256, accepted_identity

GateSecondBucketV1:
schema_version, record_type, stream_group, second_index, scheduled_count,
attempted_count, accepted_count, admitted_in_actual_second_count,
scheduled_payload_bytes, attempted_payload_bytes, accepted_payload_bytes,
early_count, late_count, out_of_window_count

GateWorkerKeyV1:
exchange, worker_instance_id

GateWorkerSampleV1:
schema_version, record_type, round_index, round_kind, scheduled_monotonic_ns,
request_started_monotonic_ns, request_completed_monotonic_ns, snapshot

GateSamplingRoundV1:
schema_version, record_type, round_index, round_kind, scheduled_monotonic_ns,
expected_worker_keys, samples

GateProcessKeyV1:
role, exchange, worker_instance_id

GateProcessResourceSampleV1:
schema_version, record_type, round_index, scheduled_monotonic_ns,
request_started_monotonic_ns, request_completed_monotonic_ns, process_key,
process_id, rss_bytes, open_fd_count

GateResourceSamplingRoundV1:
schema_version, record_type, round_index, scheduled_monotonic_ns,
expected_process_keys, samples

GateWorkerHealthV1:
exchange, worker_instance_id, lifecycle, critical_reason

GateStorageHealthSampleV1:
schema_version, record_type, round_index, scheduled_monotonic_ns,
request_started_monotonic_ns, request_completed_monotonic_ns,
data_available_bytes, state_available_bytes, workers
```

All ordered key/partition/sample tuples are sorted, unique, and complete. Version
fields reject booleans and numeric coercion. Trace timing permits early and late rows
to be serialized as failure evidence, but requires due before deadline and attempt
start no later than admission completion. Accepted and accepted-high-water statuses
require an accepted identity whose routing fields equal the trace; every other status
forbids one. Final worker rounds require five CLOSED snapshots. Evidence paths are
normalized POSIX-relative paths with no NUL, backslash, absolute prefix, or empty,
`.` or `..` component.

The one supervisor process key has role `supervisor` and null exchange/worker fields.
Each `exchange_worker` key has its canonical exchange and exact
`gate-worker-v1-<exchange>` ID. Process-key order is supervisor followed by canonical
exchange order; worker-key order is canonical exchange order. Nested sample round
indices and scheduled times equal their parent, request timing is
`scheduled <= started <= completed`, process IDs are positive signed-64 integers, and
neither a key nor PID may change. Trace partitions use normalized `.jsonl.zst` paths,
contain only rows for their declared exchange, and their merged row/byte counts equal
the sums of their refs. Readers take caller-derived maximum rows, decompressed bytes,
and line bytes from the bound workload/schema; they never trust claimed artifact sizes
as decompression limits.

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
- the ordered five-part admission trace set, every part's content/compressed hashes,
  and the virtual merged content hash;
- per-second bucket content hash;
- worker-sampling artifact hash;
- process-resource and storage-health artifact hashes;
- candidate report hash;
- target declaration hash;
- raw-root inventory and manifest inventory hashes;
- source commit, wheel, lock, Dockerfile, workload, and image identifiers;
- the artifact schema and algorithm versions.

Authoritative run and runtime indexes are terminal complete nodes, not mutable status
logs. `GateRunIndexV1.status` and `GateRuntimeIndexV1.status` are literal `complete`.
A failed or interrupted runner publishes no run index; it retains partial artifacts
and emits ordinary diagnostics outside the accepted hash DAG. A stale complete index
cannot therefore be followed by a failed "successor" that a verifier might overlook.
Every evidence root owns exactly `run-index.json`, `runtime-receipt.json`, and
`runtime-index.json`; the latter two names are fixed outputs derived from the trusted
parent of the canonical run-index path. Unique attempt-suffixed partial files may be
retained, but final names are never replaced. If a receipt already exists after an
interruption, a fresh verifier validates and reuses it before publishing the missing
runtime index.

Task 5 adds the following exact helper and evidence-document field orders. A document
reference hashes the complete published bytes, while every model whose last field is
`sha256` hashes its preceding canonical fields plus one newline.

```text
GateEvidenceDocumentRefV1:
schema_version, record_type, relative_path, content_size_bytes, content_sha256

GateManifestInventoryEntryV1:
ordinal, manifest, data, manifest_record_count

GateRawInventoryV1:
schema_version, record_type, raw_files, file_count, record_count,
content_size_bytes, compressed_size_bytes, sha256

GateManifestInventoryV1:
schema_version, record_type, manifests, file_count, record_count,
manifest_content_size_bytes, sha256

GateStreamRuntimeSummaryV1:
stream_group, expected_record_count, expected_payload_bytes, scheduled_record_count,
scheduled_payload_bytes, attempted_record_count, attempted_payload_bytes,
accepted_record_count, accepted_payload_bytes, early_count, late_count,
out_of_window_count, required_burst_count, scheduled_burst_count, burst_second,
burst_scheduled_count, burst_attempted_count, burst_accepted_count,
burst_admitted_in_actual_second_count, planned_values_match,
admission_values_match, burst_valid

GateRuntimeSummaryV1:
expected_record_count, expected_payload_bytes, scheduled_record_count,
scheduled_payload_bytes, attempted_record_count, attempted_payload_bytes,
accepted_record_count, accepted_payload_bytes, durable_record_count,
durable_payload_bytes, durability_sample_count, manifest_record_count,
raw_file_count, manifest_file_count, declared_file_identity_count,
expected_touched_file_identity_count, observed_touched_file_identity_count,
accepted_identity_count, unique_accepted_identity_count, early_count, late_count,
out_of_window_count, received_utc_hours, stream_summaries,
final_worker_aggregate, resource_summary, storage_health_summary

GateCandidateReportV1:
schema_version, record_type, run_id, mode, workload_sha256,
workload_plan_sha256, multiplier, duration_ns, run_started_monotonic_ns,
admission_started_monotonic_ns, admission_scheduled_end_monotonic_ns,
admission_ended_monotonic_ns, run_ended_monotonic_ns,
admission_started_utc_ns, admission_ended_utc_ns, declared_admission_utc_hour,
expected_target_id, target_declaration_sha256, expected_image_id,
runtime_image_id, runtime_summary, runtime_failure_codes,
candidate_runtime_passed, sha256

GateRunIndexV1:
schema_version, record_type, run_id, status, mode, artifact_schema_version,
identity_algorithm, event_algorithm, payload_algorithm, schedule_algorithm,
data_root, state_root, workload_document, workload_sha256,
workload_plan_sha256, admission_trace_set, second_bucket_artifact,
worker_sampling_artifact, resource_sampling_artifact, storage_health_artifact,
raw_inventory, manifest_inventory, candidate_report, expected_target_id,
target_declaration, implementation_source_commit, collector_wheel_sha256,
requirements_lock_sha256, dockerfile_sha256, expected_image_id,
runtime_image_id, sha256

GateRuntimeReceiptV1:
schema_version, record_type, verifier_version, verified_at_unix_ns, run_id, mode,
run_index_sha256, run_index_content_sha256, expected_target_id,
recomputed_summary, target_reprobe, failure_codes, evidence_integrity_valid,
candidate_summary_matches, runtime_predicates_passed, runtime_evidence_valid,
qualification_runtime_accepted, sha256

GateRuntimeIndexV1:
schema_version, record_type, run_id, status, mode, run_index, runtime_receipt,
sha256
```

Document paths are normalized POSIX-relative paths. `GateEvidenceDocumentRefV1`
accepts canonical `.json` or `.yaml` files and binds nonzero size plus full-file SHA.
Raw entries are ordered strictly by data path; manifest entries are ordered strictly
by manifest path and each binds its exact sibling data ref. Ordinals are zero-based
and consecutive. Inventory totals equal their entry sums, all paths and hashes are
unique in their respective namespaces, and neither inventory is empty for a complete
run.

`GateRuntimeSummaryV1` totals equal the eight ordered stream summaries and the nested
aggregate facts. Received UTC hours are sorted, unique `YYYY/MM/DD/HH` strings. Stream
planned/admission/burst booleans are exact functions of their preceding counts, not
caller-selected verdicts. The candidate report has a sorted unique failure-code tuple
and `candidate_runtime_passed` is exactly true when that tuple is empty. Its monotonic
boundaries satisfy run start <= admission start < scheduled end <= actual admission
end <= run end, with scheduled end exactly start plus duration; UTC start does not
follow UTC end.

Functional mode forbids all four target/image claims. Qualification mode requires all
four plus the provenance claims in the run index. Both modes always bind absolute
normalized distinct data/state roots, the copied workload document, every primary
artifact, both inventories, and the candidate report. The workload document content
SHA equals `workload_sha256`. Run/index/report modes and run IDs must agree.

The receipt distinguishes integrity, candidate agreement, and measured predicates.
`runtime_evidence_valid` is exactly integrity AND candidate agreement AND measured
predicates AND, in qualification mode, a valid concrete `GateTargetReprobeV1`.
Functional mode forbids a target re-probe and always has
`qualification_runtime_accepted=false`; qualification acceptance is exactly mode is
qualification AND runtime evidence is valid. A structural failure before the run
index establishes safe evidence/data/state roots raises without publishing. Once the
trust root is established, a complete validation disagreement publishes a rejecting
receipt with sorted unique failure codes.

Every node is published without replacement. Existing bytes are never edited, and a
later node may refer only to earlier nodes.

### 5.3 Admission trace

Each `GateAdmissionTraceV1` row records the planned event ID, stream, canonical
identity, local sequence, due and deadline monotonic times, attempt start, admission
completion, enqueue status, exact payload bytes/SHA, and exact accepted identity when
accepted. Accepted statuses require one identity; every other status forbids it.

Admission trace is five primary zstd JSONL partitions in canonical exchange order,
not one duplicated merged file. Each exchange child writes only its partition, ordered
by `(due_monotonic_ns, planned_event_id)`. `GateAdmissionTraceSetV1` binds every
partition and a virtual semantic stream produced by a five-way heap merge on that same
key. Its merged row count, decompressed byte count, and SHA are computed while merging;
there is no sixth physical trace. Missing, duplicate, reordered, cross-exchange, or
internally unsorted partitions fail closed. Planned-event-ID collision is a contract
error even though the ordering key remains deterministic for the committed workload.

`WorkloadPlanHeaderV1`, the declared-order stream summaries, and every
`PlannedEventV1` canonical line form the workload-plan hash input. Event rows are a
heap merge of the fixed number of per-stream iterators ordered by
`(due_offset_ns, planned_event_id)`. Each row includes identity/local sequence, payload
length/SHA, due/deadline offsets, and algorithm versions. Only equal-due groups need
local event-ID ordering; the full plan is never sorted or retained in memory.

The runtime verifier heap-merges the five trace readers and simultaneously rebuilds
the global expected oracle stream. It checks ordering, one-to-one event correspondence,
exact payload facts,
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

- external round indices are zero-based and consecutive, while scheduled and
  per-worker request-start times strictly increase;
- observed snapshot time is nondecreasing;
- an equal observed time requires byte-identical snapshot bytes;
- cumulative counters, bucket/sample counts, maxima, and series membership never
  decrease;
- quantiles may decrease and are not treated as counters;
- exchange, worker ID, config digest, and config generation never change.

Input order is evidence order and is never repaired by sorting. A round interval is
the minimum request start through maximum request completion. The next interval may
start exactly at the previous completion but must not start before it. Exactly the
last round has kind `final`; earlier samples cannot already be CLOSED.

Only each worker's final CLOSED barrier snapshot contributes cumulative totals and
histogram buckets. Round sums determine gauge peaks. Aggregate histogram quantiles are
nearest-rank values recomputed from elementwise-summed final buckets.

### 5.5 Resource and health samples

Each process samples its own Linux `/proc/self/status` `VmRSS` and numeric entries in
`/proc/self/fd`. A complete monotonic round contains the supervisor plus the five
canonical exchange children. Process keys and PIDs remain stable. For every round,
RSS and FD counts are summed across all six processes; limits are applied to those
same-round totals, never once per process. After warmup, RSS slope is the ordinary
least-squares slope over `(round_scheduled_monotonic_ns, total_rss_bytes)`, computed
with `Decimal`, converted to bytes per minute, and floored at zero. FD growth is the
maximum post-warmup total FD count minus the first post-warmup total, floored at zero.
This preserves the original one-process resource budget rather than multiplying it by
six.

Storage-health samples independently call `statvfs` for data and state roots and record
worker lifecycle/critical state. Sample gap is the difference between consecutive
scheduled monotonic times. Coverage is final completion time minus first request time.
The expected count and coverage predicates remain those in Plan02. Preflight and
post-run capability probes are separate from periodic health sampling.
Resource and health inputs are nonempty, preserve their incoming order, use zero-based
consecutive round indices and strictly increasing scheduled times, and use the same
non-overlapping interval rule as worker rounds. Duplicate, missing, reordered, or
overlapping rounds fail instead of being sorted or skipped.

Task 4 freezes these aggregate field orders:

```text
FinalWorkerAggregateV1:
schema_version, record_type, worker_count, sampling_round_count, final_round_index,
accepted_record_count, durable_record_count, unpersisted_record_count,
uncertain_record_count, enqueue_high_water_count, normal_overflow_count,
control_overflow_count, not_accepting_count, durability_histogram_schema_version,
durability_bucket_counts, durability_sample_count, durability_lag_p50_ns,
durability_lag_p95_ns, durability_lag_p99_ns, durability_lag_max_ns, sync_count,
sync_duration_total_ns, sync_duration_max_ns, slo_breach_count, write_failure_count,
sync_failure_count, publication_failure_count, unpersisted_record_count_peak,
queued_records_peak, queued_bytes_peak, buffered_records_peak, buffered_bytes_peak,
in_flight_records_peak, in_flight_bytes_peak, resident_record_bytes_peak,
resident_control_records_peak, resident_control_bytes_peak,
oldest_unpersisted_age_max_ns,
active_logical_generation_count_peak, retiring_generation_count_peak,
open_file_descriptor_count_peak, sync_inflight_peak

GateResourceSummaryV1:
schema_version, record_type, process_count, round_count, post_warmup_round_count,
warmup_ended_monotonic_ns, resource_trend_valid, first_request_monotonic_ns,
final_completion_monotonic_ns, coverage_ns, sample_max_gap_ns, rss_peak_bytes,
rss_slope_bytes_per_minute, open_fds_peak, first_open_fds_after_warmup,
max_open_fds_after_warmup, final_open_fds_after_warmup, fd_growth_after_warmup

GateStorageHealthSummaryV1:
schema_version, record_type, duration_ns, interval_ns, sample_count,
expected_min_sample_count, first_request_monotonic_ns,
final_completion_monotonic_ns, coverage_ns, required_coverage_ns,
sample_max_gap_ns, minimum_data_available_bytes, minimum_state_available_bytes,
minimum_available_bytes_if_shared, critical_worker_observation_count,
sample_count_valid, coverage_valid, workers_healthy
```

The worker aggregate sums cumulative values only from the five final snapshots.
`sync_duration_max_ns` and `durability_lag_max_ns` are cross-worker maxima. Every
other `*_peak` except `oldest_unpersisted_age_max_ns` is the maximum of same-round
worker sums; the age maximum is the maximum non-null worker age observed in any
round. Final unpersisted and uncertain counts remain explicit terminal facts even
though unpersisted records are also represented by a same-round peak. Uncertain
records are a monotonic terminal-error counter, not a gauge; a valid CLOSED sequence
therefore keeps that count zero throughout and has no redundant uncertain peak.

Resource summaries retain an unavailable result rather than manufacturing a zero:
fewer than two post-warmup rounds produce a null RSS slope, zero post-warmup rounds
produce null first/max/final FD totals and null FD growth, and one post-warmup round
produces equal first/max/final FD totals and FD growth zero. With two or more rounds,
all four FD facts and the RSS slope are non-null. `resource_trend_valid` is true
exactly when at least two post-warmup rounds make both trends qualification-usable.
Qualification requires it. OLS computes its numerator and denominator entirely with
Python integers and performs only the final division in a newly constructed
`Context(prec=50, rounding=ROUND_HALF_EVEN, Emin=-999999, Emax=999999,
capitals=1, clamp=0, flags=[], traps=[InvalidOperation, DivisionByZero, Overflow])`;
no ambient or mutable default Decimal context is copied.
The warmup predicate is
`scheduled_monotonic_ns >= warmup_ended_monotonic_ns`.
For post-warmup pairs `(x_i, y_i)`, subtract the first scheduled time from every
`x_i`, let `y_i` be the six-process RSS sum, and compute
`(n*sum(x_i*y_i)-sum(x_i)*sum(y_i)) * 60_000_000_000 /
(n*sum(x_i*x_i)-sum(x_i)**2)`, floored at zero. FD baseline, maximum, and final are
the first, maximum, and last post-warmup same-round totals; growth is
`max(0, maximum - baseline)` rather than final-minus-baseline.
The nullable slope uses a canonical nonnegative Decimal contract: constructors accept
only a `Decimal` or its canonical JSON string, reject booleans/integers/floats,
non-finite values, signs, exponents, leading zeroes, and redundant fractional zeroes,
and normalize computed values to plain base-ten notation before serialization. This
makes strict JSONL decoding reproduce the same model and canonical bytes.
Resource coverage is final completion minus first request start and its measured
maximum gap uses consecutive scheduled times, with zero for one round. Task 5 aligns
these facts with the bound admission-plus-drain sampling interval and rejects a
truncated prefix even when that prefix contains two valid post-warmup points.

Worker, resource, and health periodic sampling reuse the workload's
`storage_health_sample_interval_seconds` and `storage_health_max_gap_seconds`; Task 7
does not introduce a looser runner-selected cadence. For resource rounds, the first
request must start no later than `admission_started + interval`, the final completion
must be at or after `admission_scheduled_end`, coverage must be at least
`duration - interval`, and measured scheduled-time maximum gap must not exceed the
workload maximum. Warmup ends exactly at
`admission_started + warmup_seconds * 1_000_000_000`. These inequalities, plus the
existing complete six-process rounds, reject both prefix and suffix truncation.

Health summaries require at least one sample. The exact predicates are
`max(2, ceil(duration_ns / interval_ns) - 1)` and required coverage
`max(0, duration_ns - 2 * interval_ns)`. `sample_max_gap_ns` is only the measured
maximum scheduled-time gap. The allowed maximum gap is a separate workload setting,
so Task 5 compares the measurement with that bound instead of Task 4 inventing one.
The two root minima remain independent primary facts.
`minimum_available_bytes_if_shared` is their conservative minimum and is never their
sum. Task 4 cannot infer a shared mount from available-byte values because its input
has no device or mount identity; shared-mount floor accounting is performed in Task 6
from target-probe facts.
`sample_count_valid` is exactly `sample_count >= expected_min_sample_count`.
`coverage_ns` is exactly final completion minus first request start and
`coverage_valid` is exactly `coverage_ns >= required_coverage_ns`. A single sample has
`sample_max_gap_ns=0`; otherwise it is the maximum consecutive scheduled-time
difference. Root minima are the independent column minima and the conditional shared
value is the minimum of those two facts. `critical_worker_observation_count` counts
every CRITICAL worker row, and `workers_healthy` is true exactly when that count is
zero.

Any periodic `statvfs` or worker-health sampling exception fails the run immediately,
retains the completed/partial health artifact, and forbids publication of a candidate
report. A later successful sample cannot erase that failure. Because an exception is
not a successful sample row, this fail-closed runner rule is the primary error fact;
Task 7 tests it explicitly.

All three Task 4 summary models are private, primary-derived evidence. They may be
embedded in the private candidate/report DAG and compared against fresh recomputation,
but are not authoritative verdicts or public disclosure models.

## 6. Runner And Candidate Report

The runner is one supervisor plus exactly five children created with
`multiprocessing.get_context("spawn")`, matching the production process boundary.
Each child owns one exchange, one event loop, and one `RawWriterService` with its
deterministic worker ID and immutable config. It uses production `try_accept`,
`sync_now`, `metrics_snapshot`, final barrier, `close_all`, manifest loading, and raw
validation, and never reads coordinator, ledger, ingress-queue, or recovery internals.
The supervisor computes the global workload-plan hash once before admission. It sends
only immutable workload/config inputs, that bound hash, absolute monotonic/UTC
admission anchors, sampling commands, and bounded status/control messages over IPC;
planned market events and trace rows never cross IPC. Children independently validate
the exact workload source SHA plus plan header/stream-summary bytes, but do not each
repeat the 25-million-row global plan hash.

Every child uses an exchange-partitioned oracle iterator whose five-way heap merge is
byte-for-byte equal to the global iterator. Children complete readiness handshakes
before the supervisor chooses a future admission anchor. A child crash, missing round,
clock/plan/config disagreement, or failed final barrier stops all admission and fails
the run closed while retaining every completed and partial artifact. The supervisor
never restarts a qualification child and never reuses its exchange subtree.

Qualification requires fresh data/recovery exchange subtrees, a same-hour UTC
preflight, multiplier at least two, duration at least ten minutes, a target declaration,
and the immutable image claim. Functional mode owns temporary roots, runs the exact
10-second workload, forbids a target declaration, and can never produce an acceptance
receipt.

Each child waits until its due times without busy spinning, attempts every partitioned
event exactly once, and writes its primary trace. The supervisor coordinates complete
worker/resource rounds, waits through the drain
second, closes and validates all outputs, and publishes a `GateCandidateReportV1`.
That report contains `candidate_runtime_passed`, but it has no authoritative
`qualification_accepted=true` field. Runner exit zero means only that candidate runtime
checks passed and all required primary artifacts were published.

All runner errors fail closed. The runner publishes no authoritative run index,
retains completed/partial artifacts, emits non-DAG diagnostics, and does not delete or
reuse target raw state.

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

Task 6 is an implementation prerequisite for Task 5. The historical task numbers stay
unchanged, but the concrete target models and re-probe implementation are completed
before the runtime verifier; an untyped or boolean-only `TargetProbePort` is forbidden.

The exact Task 6 field order is:

```text
GateRootProbeV1:
schema_version, record_type, root, storage_device, filesystem, mount_point,
mount_options, minimum_available_bytes, observed_available_bytes,
no_replace_capability, same_parent_publication_only, file_sync_supported,
directory_sync_supported

GateTargetV1:
schema_version, record_type, target_id, data_root, state_root, deployment_purpose,
created_at_unix_ns, sha256

GateTargetReprobeV1:
schema_version, record_type, target_id, expected_target_id, declaration_sha256,
probed_at_unix_ns, data_root, state_root, shared_mount,
shared_required_available_bytes, shared_observed_available_bytes,
target_id_matches, declaration_facts_match, available_space_valid, reprobe_valid,
sha256
```

All three are strict, frozen private models. `GateRootProbeV1.root` and `mount_point`
are lexically normalized absolute POSIX paths. The root may not be `/`; the mount point
may. Operational APIs additionally require the root to exist, be a real directory,
and contain no symlink component. `storage_device` is canonical unsigned
`major:minor`. Mount options are sorted, unique, nonempty values prefixed `mount:` or
`super:`. `minimum_available_bytes` is exactly 100 GiB, and the only accepted
no-replace capability is the production `hardlink` primitive. All three capability
booleans are literal true.

`GateTargetV1` requires distinct roots, both individual free-space floors, and, when
device plus mount point are shared, the conservative minimum of the two independently
observed available-byte values to meet the sum of both floors. Its target ID is a
bounded printable identifier, its deployment purpose is exactly `raw-writer-gate-b`,
and `created_at_unix_ns` is a nonnegative Unix wall-clock timestamp.

Re-probe records fresh complete root facts even when a comparison fails. Immutable
fact comparison includes root, device, filesystem, mount point, options, floor, and
capabilities, but excludes the changing available-byte observation. `shared_mount` is
derived from equal device and mount point. The two shared-byte fields are both null
when roots do not share a mount; otherwise they equal the sum of the two floors and
the minimum of the two fresh observations. `target_id_matches` compares the declaration
and caller expectation, `declaration_facts_match` compares both immutable root
projections, `available_space_valid` applies both individual floors plus the shared
floor, and `reprobe_valid` is exactly the conjunction of those three booleans.

For both self-hashing target documents, digest input is exactly
`encode_json(model_dump(mode="json", exclude={"sha256"})) + b"\n"`. Published
canonical bytes include the final `sha256` field and one newline. The declaration is
written from a same-parent unique temporary file, file-synced, hard-link-published
without replacement, and parent-directory-synced. Probe cleanup removes every probe
name and syncs the probed root again, including on a failed capability check.

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
2. verifies the pinned Linux platform, base digest, Docker Engine, Buildx, BuildKit,
   and frontend versions, disabled ambient provenance/SBOM metadata, and complete
   runtime/build locks;
3. builds twice with the exact commit timestamp as `SOURCE_DATE_EPOCH`;
4. requires identical wheel hashes and immutable image IDs;
5. verifies OCI labels, read-only provenance file, workload, dependency boundary, and
   final numeric user `65532:65532`;
6. inspects the retained writer and runtime-verifier containers and proves their
   `.Image` value equals the reproduced image ID and their exit states are successful;
7. verifies `runtime receipt <= archive attestation <= provider observation <= final
   receipts`, rejects future timestamps, and independently queries the provider for
   the exact object version, COMPLIANCE/WORM retention, and a complete archive
   read-back whose tar inventory and bytes match the local inventory;
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

This section defines strict verdicts for the retained benchmark. Its functional
predicates are required project evidence; its runtime/provenance qualification
predicates are optional release performance evidence under the 2026-08-08 amendment.
The verifier logic and negative verdicts remain unchanged.

Functional acceptance proves eventual correctness, not target throughput. It requires
exact scheduled, attempted, accepted, durable, sample, manifest, payload, identity,
and raw-file conservation; canonical readable evidence; final CLOSED workers; and
zero overflow, rejection, uncertainty, unpersisted records, or write/sync/publication
failures. Lateness, out-of-window completion, durability SLO breaches, sampled active
or retiring generation peaks, resource limits/trends, and sample coverage/gaps remain
recorded facts but do not reject functional evidence. A writer critical observation
remains a correctness failure in every mode.
Sampling structure, stable identities, monotonic counters, and per-request causal
ordering remain mandatory. Functional orchestration uses a 24-hour safety watchdog to
terminate deadlocks; it is not a processing-time acceptance target.

The Gate writer derives `max_plain_frame_bytes` from the bound workload as
`max(1 MiB, maximum payload bytes + 256 KiB envelope allowance)`. Both the runner and
independent verifier derive this value rather than trusting manifest declarations.

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
