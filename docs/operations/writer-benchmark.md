# Writer Gate B Operations

This runbook qualifies one exact collector implementation on one declared production
Linux storage target. A passing functional run is an implementation check, not storage
qualification. Docker Desktop bind mounts on macOS are never qualification evidence.

## Gate States

Record exactly one current state and its supporting artifact hashes in the operator
log. A later state never rewrites evidence from an earlier attempt.

| State | Meaning |
| --- | --- |
| `IMPLEMENTATION_PASS` | Offline tests, static checks, and the 10-second functional candidate plus its runtime receipt pass. This does not qualify a target. |
| `DOCKER_REPRODUCIBILITY_PASS` | Two clean `git archive` builds of the same commit produce the same wheel SHA-256 and immutable image ID, and image inspection passes. |
| `TARGET_PENDING` | Implementation and reproducibility pass, but no suitable real Linux target or immutable archive backend is available. |
| `RUNTIME_FAILURE` | Target declaration, writer execution, or the independent runtime verifier rejects evidence. |
| `PROVENANCE_FAILURE` | Host-side source, build, image, or retained-container reproduction rejects evidence. |
| `IMMUTABLE_ARCHIVE_FAILURE` | The private inventory, upload, object version, retention, or read-back attestation is missing or invalid. |
| `EVIDENCE_ACCEPTED` | The acceptance receipt alone says `qualification_accepted=true`, after runtime, archive, and provenance verification. |

Only `EVIDENCE_ACCEPTED` is qualification. Candidate reports and runtime receipts do
not make that claim.

## Prerequisites

- Use a clean checkout of the exact implementation commit. Do not build from a working
  directory, ignored file, untracked file, or retained failure-evidence directory.
- Use Docker with BuildKit on a disposable, real `linux/amd64` host. The reproduction
  script refuses macOS before reading the repository or executing project build code.
  Record the Docker engine, BuildKit, and pinned Dockerfile frontend versions in the
  build transcript.
- Provision fresh, distinct, symlink-free data and state roots beneath one declared
  target root. Each root needs at least 100 GiB available; roots on one shared mount
  need at least 200 GiB total. Bind the target root at the same absolute path inside
  every container so mount identity and later host-side inventory paths remain stable.
- Pre-provision all bind roots for numeric UID/GID `65532:65532`.
- Provide an S3 bucket with Object Lock or an Aliyun OSS bucket with WORM/version
  retention enabled before upload. Retention is an operator-side responsibility.
- Use short-lived workload identity, an instance role, or a local credential helper.
  Never put credentials in commands, transcripts, images, evidence, or this document.
- Optionally provide an already-mounted WebDAV filesystem for an additional verified
  backup. A mount guard must prove that the remote filesystem is present.

Use a unique run ID and fresh paths for every attempt. Never reuse a failed target
subtree. The ignored-input preflight tolerates only regular, non-symlink `.pyc` files
directly beneath a `__pycache__` directory; every other ignored build path fails.

```bash
export PYTHONDONTWRITEBYTECODE=1
export COLLECTOR_SOURCE_COMMIT="$(git rev-parse HEAD)"
export COLLECTOR_SOURCE_DATE_EPOCH="$(git show -s --format=%ct "$COLLECTOR_SOURCE_COMMIT")"
export COLLECTOR_GATE_TARGET_ID="writer-gate-b-production-01"
export COLLECTOR_GATE_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
export COLLECTOR_GATE_TARGET_HOST="/declared/target"
export COLLECTOR_GATE_DATA_HOST="/declared/target/data/${COLLECTOR_GATE_RUN_ID}"
export COLLECTOR_GATE_STATE_HOST="/declared/target/state/${COLLECTOR_GATE_RUN_ID}"
export COLLECTOR_GATE_EVIDENCE_HOST="/declared/target/evidence/${COLLECTOR_GATE_RUN_ID}"
export COLLECTOR_GATE_REPORT_HOST="/declared/target/reports/${COLLECTOR_GATE_RUN_ID}"
export COLLECTOR_GATE_PRIVATE_HOST="/operator/private/writer-gate-b/${COLLECTOR_GATE_RUN_ID}"
test -z "$(git status --porcelain)"
test "$(git rev-parse HEAD)" = "$COLLECTOR_SOURCE_COMMIT"
ignored_input_failure=0
while IFS= read -r -d '' ignored_path; do
  ignored_parent=${ignored_path%/*}
  case "$ignored_path" in
    *.pyc)
      if [ "${ignored_parent##*/}" = "__pycache__" ] && \
        test -f "$ignored_path" && test ! -L "$ignored_path"; then
        continue
      fi
      ;;
  esac
  printf 'ignored build input: %s\n' "$ignored_path" >&2
  ignored_input_failure=1
done < <(
  git ls-files --others --ignored --exclude-standard -z -- \
    .dockerignore Dockerfile README.md pyproject.toml requirements \
    benchmarks src scripts
)
test "$ignored_input_failure" = 0
install -d -m 0750 -o 65532 -g 65532 \
  "$COLLECTOR_GATE_DATA_HOST" \
  "$COLLECTOR_GATE_STATE_HOST" \
  "$COLLECTOR_GATE_STATE_HOST/reports" \
  "$COLLECTOR_GATE_EVIDENCE_HOST" \
  "$COLLECTOR_GATE_REPORT_HOST" \
  "$COLLECTOR_GATE_PRIVATE_HOST"
```

## 1. Implementation Gate

Run the complete implementation checks from the repository root. External sockets
stay disabled, and live/performance cases are excluded from the offline suite.

```bash
.venv/bin/python -m pytest tests/unit/benchmarks \
  tests/integration/benchmarks tests/performance -q
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

The candidate report and fresh-process runtime receipt must pass, while
`qualification_runtime_accepted` remains false and no acceptance receipt exists.
The functional pass is independent of completion latency: late/out-of-window counts,
SLO breaches, sampled resource limits, sampling gaps, and active/retiring generation
peaks are diagnostic facts. Exact record, byte, identity, raw-file and manifest
conservation plus healthy workers and zero loss/write/sync/publication errors remain
mandatory. The 24-hour functional watchdog exists only to stop a deadlocked run.
Record `IMPLEMENTATION_PASS` only after every command exits zero.

## 2. Reproduce The Collector Image

Run this step only inside the disposable Linux build VM. The reproduction script
creates two temporary source contexts with `git archive`, uses the commit timestamp as
`SOURCE_DATE_EPOCH`, performs two no-cache `linux/amd64` builds, disables ambient
provenance/SBOM metadata, and compares the wheel and image identities. It records the
observed Docker Engine, Buildx, BuildKit, and pinned Dockerfile frontend versions. It
also parses `requirements/collector.lock` and requires each image's installed
distributions to equal that exact name/version set plus the collector wheel; missing,
changed, or extra runtime packages fail validation.

```bash
scripts/reproduce-writer-image.sh \
  --source-commit "$COLLECTOR_SOURCE_COMMIT" \
  --source-date-epoch "$COLLECTOR_SOURCE_DATE_EPOCH" \
  > "$COLLECTOR_GATE_REPORT_HOST/reproduction-transcript.json"
export COLLECTOR_GATE_IMAGE_ID="$(docker image inspect \
  --format '{{.Id}}' crypto-collector:writer-gate-b)"
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' \
  "$COLLECTOR_GATE_IMAGE_ID")" = "linux/amd64"
test "$(docker image inspect --format '{{.Config.User}}' \
  "$COLLECTOR_GATE_IMAGE_ID")" = "65532:65532"
printf '%s\n' "$COLLECTOR_GATE_IMAGE_ID" \
  > "$COLLECTOR_GATE_STATE_HOST/reports/collector-image.id"
```

Do not rebuild or retag after recording the image ID. Record
`DOCKER_REPRODUCIBILITY_PASS` only when the structured reproduction transcript and
image inspection both pass. Otherwise record `PROVENANCE_FAILURE` and retain the
transcript.

## 3. Declare The Target

Target declaration precedes admission. The image entrypoint is the writer-gate CLI, so
container arguments begin with the subcommand.

```bash
docker create \
  --name crypto-writer-gate-b-target-declaration \
  --user 65532:65532 \
  --network none \
  --mount "type=bind,src=$COLLECTOR_GATE_TARGET_HOST,dst=$COLLECTOR_GATE_TARGET_HOST" \
  "$COLLECTOR_GATE_IMAGE_ID" \
  declare-target \
  --target-id "$COLLECTOR_GATE_TARGET_ID" \
  --data-root "$COLLECTOR_GATE_DATA_HOST" \
  --state-root "$COLLECTOR_GATE_STATE_HOST" \
  --output "$COLLECTOR_GATE_STATE_HOST/reports/gate-target-v1.json"
docker start --attach crypto-writer-gate-b-target-declaration
docker container inspect crypto-writer-gate-b-target-declaration \
  > "$COLLECTOR_GATE_STATE_HOST/reports/target-container-inspect.json"
test "$(docker inspect --format '{{.State.ExitCode}}' \
  crypto-writer-gate-b-target-declaration)" = "0"
```

Reject a non-Linux target, symlink, reused raw/recovery subtree, root alias, wrong
mount, insufficient free space, or failed file sync, directory sync, or hard-link
no-replace probe. Record `RUNTIME_FAILURE` and stop on any rejection.

## 4. Run The Qualification Writer

Start early enough that the entire ten-minute admission window plus drain stays inside
one UTC hour. Use the immutable image ID, a fixed container name, no network, and fresh
roots. The 4 GiB limit applies once to the supervisor plus all five workers; set the
container memory and memory-plus-swap limits to the same value so swap cannot hide an
RSS breach. Do not use `--rm`: host-side provenance must inspect the stopped container.

```bash
docker create \
  --name crypto-writer-gate-b \
  --user 65532:65532 \
  --network none \
  --memory 4g \
  --memory-swap 4g \
  --env COLLECTOR_RUNTIME_IMAGE_ID="$COLLECTOR_GATE_IMAGE_ID" \
  --mount "type=bind,src=$COLLECTOR_GATE_TARGET_HOST,dst=$COLLECTOR_GATE_TARGET_HOST" \
  "$COLLECTOR_GATE_IMAGE_ID" \
  run \
  --workload /app/benchmarks/workloads/research-default-v1.yaml \
  --multiplier 2 \
  --duration 10m \
  --data-root "$COLLECTOR_GATE_DATA_HOST" \
  --state-root "$COLLECTOR_GATE_STATE_HOST" \
  --target-declaration "$COLLECTOR_GATE_STATE_HOST/reports/gate-target-v1.json" \
  --expected-target-id "$COLLECTOR_GATE_TARGET_ID" \
  --expected-image-id "$COLLECTOR_GATE_IMAGE_ID" \
  --evidence-root "$COLLECTOR_GATE_EVIDENCE_HOST" \
  --report "$COLLECTOR_GATE_REPORT_HOST/writer-durability.json"
docker start --attach crypto-writer-gate-b
docker container inspect crypto-writer-gate-b \
  > "$COLLECTOR_GATE_STATE_HOST/reports/writer-container-inspect.json"
test "$(docker inspect --format '{{.State.ExitCode}}' crypto-writer-gate-b)" = "0"
test "$(docker inspect --format '{{.Image}}' crypto-writer-gate-b)" \
  = "$COLLECTOR_GATE_IMAGE_ID"
test "$(docker inspect --format '{{.HostConfig.Memory}}' \
  crypto-writer-gate-b)" = "4294967296"
test "$(docker inspect --format '{{.HostConfig.MemorySwap}}' \
  crypto-writer-gate-b)" = "4294967296"
test "$(docker inspect --format '{{.State.OOMKilled}}' \
  crypto-writer-gate-b)" = "false"
cmp "$COLLECTOR_GATE_REPORT_HOST/writer-durability.json" \
  "$COLLECTOR_GATE_EVIDENCE_HOST/candidate-report.json"
```

A successful writer exit publishes a candidate run index; it is not authoritative
acceptance. A missing/mismatched hard limit, enabled swap, or OOM state is
`RUNTIME_FAILURE`. On a nonzero exit, copy container logs into the private evidence
root, record `RUNTIME_FAILURE`, and stop without modifying or deleting any output.

## 5. Verify Runtime In A Fresh Container

Run the verifier as a second fixed container from the exact same image. It independently
reads the complete private run index and primary artifacts. Keep it stopped for later
host inspection.

```bash
docker create \
  --name crypto-writer-gate-b-runtime-verifier \
  --user 65532:65532 \
  --network none \
  --mount "type=bind,src=$COLLECTOR_GATE_TARGET_HOST,dst=$COLLECTOR_GATE_TARGET_HOST" \
  "$COLLECTOR_GATE_IMAGE_ID" \
  validate-runtime \
  --run-index "$COLLECTOR_GATE_EVIDENCE_HOST/run-index.json" \
  --expected-target-id "$COLLECTOR_GATE_TARGET_ID"
docker start --attach crypto-writer-gate-b-runtime-verifier
docker container inspect crypto-writer-gate-b-runtime-verifier \
  > "$COLLECTOR_GATE_STATE_HOST/reports/runtime-verifier-container-inspect.json"
test "$(docker inspect --format '{{.State.ExitCode}}' \
  crypto-writer-gate-b-runtime-verifier)" = "0"
test "$(docker inspect --format '{{.Image}}' \
  crypto-writer-gate-b-runtime-verifier)" = "$COLLECTOR_GATE_IMAGE_ID"
```

The runtime receipt must bind the run-index hash and recomputed facts. A functional
receipt, serialized candidate boolean, caller-supplied image value, or altered summary
cannot substitute. Record `RUNTIME_FAILURE` and stop on rejection.

## 6. Build The Private File Inventory

Freeze admission, writer, and verifier outputs before upload. Run the approved
operator-side `build-inventory` command over the declared data, state, and evidence
roots. It must emit one
canonical `GateFileInventoryV1` row per regular file, sorted by normalized relative
POSIX path, with exact size and SHA-256. Its index must cover raw data, recovery state,
manifests, traces, samples, candidate report, run index, runtime receipt, and runtime
index.

Reject symlinks, devices, sockets, duplicate paths, path escapes, missing files, and
any mutation while hashing. Store the canonical inventory and its hash inside the
private evidence set. Do not edit, redact, rename, or recompress any inventoried file.

## 7. Archive Private Immutable Evidence

Upload the complete private inventory as one content-addressed archive using an
operator-side tool, then read it back and verify size, inventory hash, and every file
hash. The archive attestation must be canonical and bind the provider, object/version
identity, retention mode/deadline, archive size/hash, inventory hash, and read-back
result.

The qualification object is a zstd-compressed tar. Every regular member is named
`evidence/<relative-path>`, `data/<relative-path>`, or `state/<relative-path>` and must
exactly match the attested ordered inventory. Links, devices, sockets, duplicate
members, undeclared roots, and excess decompressed bytes are rejected. Raw files and
archive members are hashed as streams, so the 32 MiB canonical-document limit does
not constrain dataset size.

- For S3, require S3 Object Lock in COMPLIANCE mode and retain
  the concrete `VersionId`, `ObjectLockMode`, and `ObjectLockRetainUntilDate` returned
  by the provider. An ETag is not a content hash.
- For Aliyun OSS, require OSS WORM/version retention and retain the concrete version,
  retention rule/expiry, size, checksum, and read-back verification.
- A mounted WebDAV copy is optional. Verify the mount guard before writing and compare
  the complete inventory after copying. WebDAV-only storage is not qualification
  evidence, even when the copy hashes match; it is an additional backup only. In
  short: WebDAV-only is not qualification evidence.

If immutable version or retention proof cannot be verified, record
`IMMUTABLE_ARCHIVE_FAILURE`, retain the local private immutable evidence, and stop.

The build host must have authenticated provider tooling available: AWS CLI as `aws`
for `s3://` locators, or ossutil 2.x as `ossutil` for `oss://` locators. The verifier
independently executes a version-specific HEAD, queries COMPLIANCE retention, and
downloads that exact version into a private temporary path. Self-reported attestation
fields, ETags, and WebDAV copies never substitute for this provider read-back.

## 8. Validate Host Provenance

Host-side provenance validation runs only after immutable archival succeeds. It repeats
the two clean builds, inspects both retained containers, proves their `.Image` fields
equal the reproduced image ID, validates the runtime receipt and archive attestation,
then publishes provenance and acceptance receipts without replacement.
The required timestamp order is runtime receipt <= archive attestation <= provider
observation <= provenance receipt = acceptance receipt; future timestamps fail closed.

```bash
.venv/bin/python -m crypto_collector.benchmarks.writer validate-provenance \
  --source-commit "$COLLECTOR_SOURCE_COMMIT" \
  --runtime-index "$COLLECTOR_GATE_EVIDENCE_HOST/runtime-index.json" \
  --archive-attestation "$COLLECTOR_GATE_PRIVATE_HOST/archive-attestation.json" \
  --writer-container crypto-writer-gate-b \
  --verifier-container crypto-writer-gate-b-runtime-verifier
```

If source, lock, workload, Dockerfile, wheel, image, container, runtime-index, or
archive facts disagree, record `PROVENANCE_FAILURE`; never repair the canonical
originals. A build fix is a new implementation commit and a completely new run. The
file under the report root is a byte-identical operational copy of
`evidence/candidate-report.json`; the evidence-root document is the canonical report.

## 9. Build The Public Disclosure

Generate the allowlisted public model from the accepted receipt. Never make a public
artifact by redacting a private model.

```bash
.venv/bin/python -m crypto_collector.benchmarks.writer build-disclosure \
  --acceptance "$COLLECTOR_GATE_PRIVATE_HOST/acceptance-receipt.json" \
  --output "$COLLECTOR_GATE_STATE_HOST/reports/gate-b-disclosure-v1.json"
```

Scan the disclosure and sanitized validation transcript for absolute paths, hostnames,
credentials, environment values, mount facts, and raw object locators. All must be
absent. The disclosure may include only safe workload/result/provenance facts, receipt
and private-index hashes, and an opaque locator digest. Document where authorized
operators can resolve that opaque locator to the private immutable evidence.

Canonical originals are never redactable: never redact, truncate, or replace the
target declaration, trace, samples, raw data, manifests, report, run index, runtime
receipt/index, inventory, archive attestation, provenance receipt, or acceptance
receipt. A redacted report or declaration is not an original and must never be passed
to a canonical verifier.

Record `EVIDENCE_ACCEPTED` only when the final canonical acceptance receipt says
`qualification_accepted=true` and clean-checkout validation of the disclosure passes.

## 10. Commit And Cleanup

The evidence commit is separate from the implementation commit. Commit only the public
disclosure, an approved public acceptance projection, the sanitized transcript, and a
runbook status update. Never commit private immutable evidence, provider locators,
target paths, host facts, container inspect output, or credentials.

```bash
git add docs/operations/evidence docs/operations/writer-benchmark.md
git commit -m "evidence: qualify auditable raw writer gate"
```

Before cleanup, independently verify the external archive again and preserve the
container inspect documents. Cleanup is forbidden after any earlier step failed unless
the failed private evidence has first been retained under the incident policy.

```bash
docker container inspect \
  crypto-writer-gate-b-target-declaration \
  crypto-writer-gate-b \
  crypto-writer-gate-b-runtime-verifier \
  > "$COLLECTOR_GATE_STATE_HOST/reports/final-container-inspect.json"
docker container rm \
  crypto-writer-gate-b-target-declaration \
  crypto-writer-gate-b \
  crypto-writer-gate-b-runtime-verifier
```

Local raw evidence remains protected by normal retention rules. Never delete local
data merely because an upload command returned success.
