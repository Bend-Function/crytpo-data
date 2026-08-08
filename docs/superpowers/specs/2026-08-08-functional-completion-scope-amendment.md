# Functional Completion Scope Amendment

- Date: 2026-08-08
- Status: approved
- Scope: project completion, release gates, and performance-evidence classification

## 1. Authority

This amendment is normative for the distinction between **required functional
completion** and **optional release performance evidence**. It overrides conflicting
completion, sequencing, or gate language in these documents only:

- `2026-07-31-crypto-market-data-collector-design.md`;
- `2026-07-31-crypto-market-data-collector-roadmap.md`;
- `2026-08-02-writer-gate-b-auditable-evidence-design.md` and its implementation plan;
- `2026-07-31-durable-raw-storage.md`;
- `2026-07-31-operations-acceptance.md`;
- `docs/operations/writer-benchmark.md`;
- `docs/zh-CN/使用指南.md`.

All other architecture, schema, recovery, safety, and evidence contracts remain in
force. In particular, this amendment does not remove or weaken benchmark code,
durability-lag measurement, watchdogs, alerts, `PAUSED_WRITER`, manifests, recovery,
or loss accounting.

## 2. Decision

Project implementation and connector expansion are gated by functional correctness,
data conservation, recoverability, bounded operation, and repeatable short-run
stability. They are not gated by a fixed processing-time target or by access to a
particular performance host.

The following are **optional release performance evidence**, not prerequisites for
functional completion or merge to the main development line:

1. every accepted record reaching durable storage within `1.000s`;
2. a `10m` run at `2x` the versioned workload and active-file cardinality;
3. a `4h` soak and its numerical RSS/FD/backlog slope thresholds.

These measurements remain useful for deployment sizing and release qualification.
When run, their original workload, target, provenance, and verifier contracts still
apply; this amendment does not make a reduced workload a passing qualification run.

## 3. Required Functional Completion

The following evidence remains **REQUIRED**:

1. Protocol and domain correctness: strict config/capability validation, anonymous
   public endpoints only, exchange-specific sequence/checksum/gap rules, deterministic
   selection, and no silent unsupported stream or symbol omission.
2. Writer conservation on clean drain and controlled recovery: accepted records are
   durably represented, `accepted_count == durable_count`, queues and unpersisted
   ledgers drain to zero, and persisted rows reconcile with manifest counts.
3. Zero unrecorded loss: overflow, rejection, gap, incomplete generation, and recovery
   uncertainty are either absent or represented by the specified control/evidence
   path. No test may infer success from missing evidence.
4. Manifest and recovery correctness: atomic publication, checksum validation,
   incomplete/partial handling, replay/idempotence, and recovery outcomes are tested.
5. Bounded resources by construction: queues, pending jobs, sync concurrency, active
   and retiring generations, open files, and process/service ownership have explicit
   limits and exercise their limit behavior without silent loss. Violating a
   configured structural cap or leaving owned resources open at the terminal barrier
   is a functional failure. Target-specific RSS/FD performance thresholds and growth
   slopes belong to optional performance evidence; this distinction does not make
   queues, files, tasks, or concurrency unbounded.
6. Short multi-round stability: the functional workload runs at least twice from
   fresh roots, completes clean drain and manifest validation in every round, stays
   within configured hard resource bounds, and leaves no growing
   queue, task, generation, file-descriptor, or recovery-state residue. The rounds
   are evaluated together by a system-test assertion, not merely by observing two
   independent zero exit codes. They are lifecycle evidence, not wall-clock throughput
   targets.
7. Required lifecycle, fault, consumer-isolation, materializer, archiver, security,
   and user-documentation acceptance from the main design and roadmap.

An injected critical writer fault passes a functional test only when it produces the
specified scoped pause, control evidence, and recovery behavior. An unexpected
`PAUSED_WRITER`, write/sync/publication error, invalid manifest, or unreconciled record
in a nominal clean round is still a functional failure.

## 4. Operational Safety Remains Required

`writer.durability_slo`, `writer.durability_critical`, rolling lag observations,
watchdog evaluation, and the `PAUSED_WRITER` transition remain runtime safety policy.
They continue to expose slow or unhealthy storage and prevent an affected exchange
from accepting new input at the configured critical boundary.

A configured SLO breach is therefore never hidden. It is reported in metrics, logs,
status, control data, manifests/evidence, and any performance report that observes it.
Removing the release-blocking fixed-latency requirement does not authorize disabling
those measurements or safety transitions.

## 5. Result Classification

Functional and performance results are separate axes:

| Axis | Allowed states | Meaning |
| --- | --- | --- |
| Functional completion | `PASS`, `FAIL` | Required correctness, conservation, recovery, boundedness, and short multi-round stability. |
| Optional performance evidence | `NOT_RUN`, `PASS`, `FAIL` | Fixed-latency, `10m@2x`, and/or `4h` evidence on its declared target. |

Rules:

- `functional=PASS, performance=NOT_RUN` is a valid functionally complete release.
- `functional=PASS, performance=FAIL` remains functionally complete, but the release
  record must visibly say that optional performance qualification failed.
- A failed or incomplete performance run must never be relabeled `PASS`,
  `EVIDENCE_ACCEPTED`, or an equivalent success state.
- Existing `qualification_accepted`, runtime/provenance receipts, and
  `EVIDENCE_ACCEPTED` retain their strict meaning: they are true only when the complete
  optional qualification predicates actually pass.
- `functional_passed=true` with `qualification_accepted=false` is expected for the
  required short functional path and is not a contradiction.

## 6. Plan Consequences

- Gate B's short, repeated functional writer checks remain required before connector
  fan-out.
- Target-host qualification, `10m@2x`, the universal `1.000s` predicate, and the `4h`
  soak are optional release-performance work and do not stop later feature plans.
- Performance test modules and validators may still be implemented, maintained, and
  run on demand. Their negative tests remain valid and their verdicts remain strict.
- Final project acceptance records both axes and cannot use a missing or failed
  optional performance run to claim performance qualification.
