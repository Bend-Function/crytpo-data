# Archiver and Retention Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Archive closed raw/derived artifacts to Aliyun OSS, S3-compatible storage, or a mounted WebDAV/filesystem target with strong verification, optional precompression, deterministic receipts, safe restore, and gated local cleanup.

**Architecture:** Source manifests remain the data facts; a rebuildable WAL SQLite database drives jobs through an explicit state machine. Every target uploads data and source manifest first, verifies stored content, and publishes a target receipt last as the commit marker.

**Tech Stack:** Python 3.11+, SQLite, boto3, oss2, python-zstandard, SHA-256, CRC64, POSIX atomic files/leases, pytest, local S3-compatible integration service.

---

### Task 1: Frozen Archive Policy and Job State Machine

**Files:**
- Create: `src/crypto_collector/archive/__init__.py`
- Create: `src/crypto_collector/archive/models.py`
- Create: `src/crypto_collector/archive/policy.py`
- Create: `src/crypto_collector/archive/state.py`
- Test: `tests/unit/archive/test_policy.py`
- Test: `tests/unit/archive/test_state.py`

- [ ] **Step 1: Write failing policy and transition tests**

```python
def test_policy_hash_is_canonical_and_secret_independent(monkeypatch) -> None:
    monkeypatch.setenv("S3_SECRET", "first")
    first = freeze_policy(source_manifest_sha="a" * 64, config=archive_config()).sha256
    monkeypatch.setenv("S3_SECRET", "second")
    assert freeze_policy(source_manifest_sha="a" * 64, config=archive_config()).sha256 == first


def test_removing_required_target_does_not_weaken_existing_source(tmp_path) -> None:
    store = ArchiveState.open(tmp_path / "archive.sqlite")
    frozen = store.discover(source_manifest(), policy=policy(required={"s3", "oss"}))
    store.reload_config(policy(required={"s3"}))
    assert store.policy_for(frozen.source_sha).required_target_ids == ("oss", "s3")


@pytest.mark.parametrize("old,new", [
    ("DISCOVERED", "QUEUED"), ("QUEUED", "TRANSFORMING"),
    ("QUEUED", "UPLOADING"), ("TRANSFORMING", "UPLOADING"),
    ("UPLOADING", "VERIFYING"), ("VERIFYING", "COMMITTED"),
])
def test_allowed_archive_transitions(old, new) -> None:
    assert ArchiveTransition.validate(old, new)


@pytest.mark.parametrize("old", [
    "QUEUED", "TRANSFORMING", "UPLOADING", "VERIFYING",
])
def test_retryable_failure_enters_retrying(old) -> None:
    assert ArchiveTransition.validate(old, "RETRYING", error=RetryableTargetError())


@pytest.mark.parametrize(("checkpoint", "expected"), [
    ("source", "TRANSFORMING"),
    ("stored", "UPLOADING"),
    ("data_uploaded", "VERIFYING"),
    ("data_verified", "UPLOADING"),
    ("source_manifest_uploaded", "VERIFYING"),
    ("source_manifest_verified", "UPLOADING"),
    ("receipt_published", "VERIFYING"),
])
def test_retry_resumes_only_from_durable_checkpoint(checkpoint, expected) -> None:
    assert ArchiveTransition.resume_target("RETRYING", checkpoint=checkpoint) == expected


def test_retry_schedule_and_multipart_checkpoint_survive_restart(tmp_path) -> None:
    path = tmp_path / "archive.sqlite"
    store = ArchiveState.open(path)
    store.record_retry(job_key(), retry_at_ns=seconds(30), attempt=3,
                       workflow_checkpoint="data_uploaded",
                       multipart_upload_id="upload-1", parts=[part(1), part(2)])
    store.close()
    reopened = ArchiveState.open(path)
    assert reopened.due_jobs(now_ns=seconds(29)) == ()
    [job] = reopened.due_jobs(now_ns=seconds(30))
    assert (job.attempt, job.workflow_checkpoint) == (3, "data_uploaded")
    assert (job.multipart_upload_id, job.part_numbers) == ("upload-1", (1, 2))


def test_upload_conflict_is_terminal_and_scheduler_excludes_it_after_restart(tmp_path) -> None:
    path = tmp_path / "archive.sqlite"
    store = ArchiveState.open(path)
    store.insert(job(state="UPLOADING"))
    store.record_failure(job_key(), ExistingObjectMismatch())
    store.close()
    reopened = ArchiveState.open(path)
    assert reopened.job(job_key()).state == "TERMINAL_CONFLICT"
    assert job_key() not in {job.key for job in reopened.due_jobs(now_ns=MAX_NS)}
    with pytest.raises(InvalidArchiveTransition):
        ArchiveTransition.validate("TERMINAL_CONFLICT", "RETRYING")


def test_generic_transition_api_cannot_abandon_even_an_optional_job() -> None:
    with pytest.raises(InvalidArchiveTransition):
        ArchiveTransition.validate("RETRYING", "ABANDONED_LOCAL_SOURCE_DELETED",
                                   target_required=False)


def test_committed_cannot_transition_back_to_uploading() -> None:
    with pytest.raises(InvalidArchiveTransition):
        ArchiveTransition.validate("COMMITTED", "UPLOADING")


def test_policy_migration_creates_distinct_remote_namespace() -> None:
    source = source_manifest()
    old = freeze_policy(source_manifest_sha=source.sha256,
                        config=archive_config(compression_level=3))
    new = migrate_policy(old, config=archive_config(compression_level=9),
                         reason="raise compression")
    assert old.sha256 != new.sha256
    assert data_key(source.artifact, old) != data_key(source.artifact, new)
    assert manifest_key(source, old) != manifest_key(source, new)
    assert receipt_key(source.artifact, old, target_id="s3") != receipt_key(
        source.artifact, new, target_id="s3")


def test_sqlite_rebuild_preserves_frozen_policy_from_durable_facts(tmp_path) -> None:
    state_root = tmp_path / "state"
    store = ArchiveState.open(state_root / "archive" / "archive.sqlite")
    discovered = store.discover(source_manifest(), policy=policy(required={"s3", "oss"}))
    store.close()
    (state_root / "archive" / "archive.sqlite").unlink()
    rebuilt = ArchiveState.open(state_root / "archive" / "archive.sqlite", rebuild=True)
    assert rebuilt.policy_for(discovered.source_sha).required_target_ids == ("oss", "s3")
```

- [ ] **Step 2: Run and verify archive state modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/archive/test_policy.py tests/unit/archive/test_state.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement immutable policy records and WAL state**

Freeze source manifest SHA, enabled/required targets, verification level, object-key/compression policy, and reference-only credential configuration into `ArchivePolicyV1`. State rows use `(source_manifest_sha, target_id, policy_sha)` and persist attempt, retry time, workflow checkpoint, multipart upload ID/parts, staging path, remote key, stored hash/size, provider checksum, error class, and transition time. The checkpoint enum records every durable boundary: source ready, transform stored, data uploaded/verified, source manifest uploaded/verified, and receipt published.

The state graph is explicit: active work may enter `RETRYING` only for classified retryable failures; a due retry resumes from its last durable checkpoint; an existing-object/hash/policy conflict enters `TERMINAL_CONFLICT`; `COMMITTED` and `TERMINAL_CONFLICT` have no outgoing automatic transitions and are excluded from scheduler queries after restart. The generic transition API never accepts `ABANDONED_LOCAL_SOURCE_DELETED`; only Task 7's cleanup reconciler may transact that state after loading and validating a durably published tombstone. Required targets can never be abandoned. Persist retry deadline, error class, workflow checkpoint, and upload checkpoint in the same transaction as the transition, so restart neither retries early nor loses multipart progress.

```sql
CREATE TABLE archive_job (
  source_manifest_sha TEXT NOT NULL,
  target_id TEXT NOT NULL,
  policy_sha TEXT NOT NULL,
  state TEXT NOT NULL,
  attempt INTEGER NOT NULL,
  retry_at_ns INTEGER,
  workflow_checkpoint TEXT NOT NULL CHECK (workflow_checkpoint IN (
    'source', 'stored', 'data_uploaded', 'data_verified',
    'source_manifest_uploaded', 'source_manifest_verified', 'receipt_published'
  )),
  multipart_upload_id TEXT,
  multipart_parts_json TEXT NOT NULL,
  staging_path TEXT,
  data_key TEXT NOT NULL,
  source_manifest_key TEXT NOT NULL,
  receipt_key TEXT NOT NULL,
  stored_sha256 TEXT,
  stored_size INTEGER,
  provider_checksum_json TEXT,
  verification_json TEXT,
  error_class TEXT,
  updated_at_ns INTEGER NOT NULL,
  PRIMARY KEY (source_manifest_sha, target_id, policy_sha)
);
```

Removing a required target only affects newly discovered sources. Existing policy can change only through `archive policy migrate`, which writes a new immutable policy record and audit control event naming old/new hashes and operator reason without secrets. Migration is allowed only while every affected local source still exists and no cleanup tombstone exists; the old policy/jobs/receipts remain immutable audit history, while cleanup eligibility follows the explicitly active policy generation. A migration to an identical canonical policy hash is rejected as a no-op.

SQLite is a rebuildable scheduler cache, not the only copy of cleanup facts. Before inserting a discovered job, atomically write/sync `<state_root>/archive/policies/<policy_sha256>.json` and append-only `<state_root>/archive/sources/<source-manifest-sha256>/generation-<n>.json`; an atomically replaced/synced `active.json` pointer contains only generation number and generation-fact SHA. Migration publishes the new policy and generation facts before advancing that pointer, so a crash selects either the complete old generation or the complete new one. These reference-only schema-versioned facts contain their own canonical SHA-256 and old generations are never overwritten. Database rebuild scans source manifests plus these facts, receipt indexes, and tombstones. Missing/corrupt facts block cleanup and require operator repair; they never fall back to current config and weaken an old requirement.

- [ ] **Step 4: Run policy/state tests**

Run: `.venv/bin/python -m pytest tests/unit/archive/test_policy.py tests/unit/archive/test_state.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/archive tests/unit/archive
git commit -m "feat: persist frozen archive policies"
```

### Task 2: Deterministic Transform, Object Keys, and Receipts

**Files:**
- Create: `src/crypto_collector/archive/transform.py`
- Create: `src/crypto_collector/archive/keys.py`
- Create: `src/crypto_collector/archive/receipt.py`
- Test: `tests/unit/archive/test_transform.py`
- Test: `tests/unit/archive/test_receipt.py`

- [ ] **Step 1: Write failing off/auto/zstd and identity tests**

```python
@pytest.mark.parametrize(("mode","source","expected"), [
    ("off", "part.json", "passthrough"),
    ("auto", "part.jsonl.zst", "passthrough"),
    ("auto", "part.parquet", "passthrough"),
    ("auto", "large.json", "zstd-v1"),
    ("zstd", "large.json", "zstd-v1"),
])
def test_transform_decision(mode, source, expected, tmp_path) -> None:
    path = tmp_path / source
    path.write_bytes(b"x" * 2048)
    assert plan_transform(path, compression(mode=mode, min_size=1024)).kind == expected


def test_auto_below_min_size_passes_through(tmp_path) -> None:
    path = tmp_path / "small.json"
    path.write_bytes(b"x" * 1023)
    assert plan_transform(path, compression(mode="auto", min_size=1024)).kind == "passthrough"


def test_explicit_zstd_still_honors_recompress_false(tmp_path) -> None:
    path = tmp_path / "already.jsonl.zst"
    path.write_bytes(b"x" * 2048)
    policy = compression(mode="zstd", min_size=1024, recompress=False)
    assert plan_transform(path, policy).kind == "passthrough"


def test_encoded_key_cannot_overwrite_passthrough_or_another_policy_key() -> None:
    source = SourceArtifact(relative_path="raw/okx/part.json", sha256="a" * 64)
    first = policy(sha256="b" * 64)
    second = policy(sha256="c" * 64)
    assert passthrough_key(source, first).startswith("_archive/v1/policy=" + "b" * 64)
    assert encoded_key(source, first, codec="zstd", version=1).startswith(
        "_archive/v1/policy=" + "b" * 64 + "/_encoded/zstd/v1/")
    assert encoded_key(source, first, codec="zstd", version=1) != passthrough_key(source, first)
    assert encoded_key(source, first, codec="zstd", version=1) != encoded_key(
        source, second, codec="zstd", version=1)


def valid_receipt() -> ArchiveReceiptV1:
    return ArchiveReceiptV1.with_computed_hash(
        schema_version=1,
        source_path="raw/okx/spot/BTC-USDT/trades/part.jsonl.zst",
        source_size=2048,
        source_sha256="a" * 64,
        stored_key="_archive/v1/policy=" + "d" * 64 + "/_encoded/zstd/v1/part.zst",
        stored_size=1024,
        stored_sha256="b" * 64,
        source_manifest_sha256="c" * 64,
        codec="zstd",
        codec_level=3,
        codec_tool="python-zstandard",
        codec_version="0.25.0",
        target_id="s3-primary",
        policy_sha256="d" * 64,
        provider_checksum={"algorithm": "SHA256", "value": "b" * 64},
        verification_method="provider_full_object_sha256",
        verified_at_ns=123,
        commit_marker=True,
    )


def test_receipt_binds_source_and_stored_hashes() -> None:
    receipt = valid_receipt()
    validated = validate_receipt(receipt.to_canonical_json())
    assert validated.receipt_sha256 == receipt.receipt_sha256
    assert validated.target_id == "s3-primary"
    assert validated.commit_marker is True


@pytest.mark.parametrize(("field", "tampered"), [
    ("source_sha256", "f" * 64),
    ("stored_size", 1025),
    ("receipt_sha256", "0" * 64),
])
def test_receipt_validator_rejects_tampered_field_or_hash(field, tampered) -> None:
    document = json.loads(valid_receipt().to_canonical_json())
    document[field] = tampered
    with pytest.raises(ReceiptValidationError):
        validate_receipt(canonical_json(document))


def test_receipt_validator_rejects_missing_required_field() -> None:
    document = json.loads(valid_receipt().to_canonical_json())
    del document["target_id"]
    with pytest.raises(ReceiptValidationError):
        validate_receipt(canonical_json(document))
```

- [ ] **Step 2: Run and verify transform/receipt modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/archive/test_transform.py tests/unit/archive/test_receipt.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement bounded staging and canonical receipts**

`off` always passes through. `auto` compresses only sources at/above `min_size` that are not `.zst` and not already compressed Parquet; `zstd` requests compression but still honors `recompress=false`. Write staging `.partial`, sync, rename, hash, and enforce configured staging byte/concurrency limits. On space failure retain the source and job retry state without changing codec.

Every remote object key starts with the collision-proof namespace `_archive/v1/policy=<policy_sha256>/`. Pass-through data then mirrors the source relative path. Encoded data uses `_encoded/zstd/v1/<source-relative>.<source-sha256>.zst`; source manifests use `_manifests/<source-manifest-sha256>.manifest.json`; target-specific receipts use `_receipts/<target-id>/<source-manifest-sha256>/<artifact-role>.<source-sha256>.archive-receipt.json`. Target IDs are validated path-safe configuration identifiers. All key builders require the frozen `ArchivePolicyV1`, and the job persists the resulting exact keys before transformation/upload. Consequently a policy migration, including only a codec level/tool version change, can coexist with old remote data and receipts rather than hitting an existing-object hash conflict, while two target IDs sharing one physical prefix cannot overwrite each other's receipt. Target configured prefixes wrap this namespace but do not replace it.

Receipt V1 contains source path/size/SHA, stored key/size/SHA, codec/level/tool/version, source manifest SHA, target/policy IDs, provider checksum, verification method/time, and receipt SHA. Define `receipt_sha256` as SHA-256 of canonical JSON with that field omitted; validation removes the field, recomputes, and constant-time compares it. Serialize final canonical JSON once and never include credentials.

- [ ] **Step 4: Run transform/receipt tests**

Run: `.venv/bin/python -m pytest tests/unit/archive/test_transform.py tests/unit/archive/test_receipt.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/archive/transform.py src/crypto_collector/archive/keys.py src/crypto_collector/archive/receipt.py tests/unit/archive
git commit -m "feat: prepare deterministic archive objects"
```

### Task 3: Mounted WebDAV/Filesystem Target

**Files:**
- Create: `src/crypto_collector/archive/targets/__init__.py`
- Create: `src/crypto_collector/archive/targets/base.py`
- Create: `src/crypto_collector/archive/targets/filesystem.py`
- Test: `tests/contract/archive/test_target_contract.py`
- Test: `tests/integration/archive/test_filesystem_target.py`

- [ ] **Step 1: Write failing mount-guard and atomic-copy tests**

```python
def test_missing_guard_makes_target_unavailable_without_creating_root(tmp_path) -> None:
    root = tmp_path / "webdav" / "archive"
    ref = SecretRef.parse("env:GUARD")
    target = FilesystemTarget(root=root, guard_path=tmp_path / "webdav" / ".guard",
                              expected_guard=SecretSnapshot.from_test_values({ref: "expected"}).value_for(ref))
    with pytest.raises(TargetUnavailable, match="mount guard"):
        target.probe()
    assert not root.exists()


def test_guard_content_must_match(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GUARD", "expected")
    guard = tmp_path / ".guard"
    guard.write_text("wrong", encoding="utf-8")
    ref = SecretRef.parse("env:GUARD")
    secrets = SecretSnapshot.resolve_all([ref])
    with pytest.raises(TargetUnavailable):
        FilesystemTarget(tmp_path / "archive", guard, secrets.value_for(ref)).probe()


def test_filesystem_put_is_partial_sync_rename_and_readback(tmp_path, mounted_target) -> None:
    result = mounted_target.put(source_file(), key="raw/part.jsonl.zst")
    assert result.path.exists()
    assert not result.path.with_suffix(result.path.suffix + ".partial").exists()
    assert sha256_file(result.path) == source_file().sha256


@pytest.mark.parametrize("key", ["../escape", "/absolute", "raw/../../escape", "raw\\escape"])
def test_filesystem_target_rejects_unsafe_object_key(mounted_target, key) -> None:
    with pytest.raises(UnsafeObjectKey):
        mounted_target.put(source_file(), key=key)
```

- [ ] **Step 2: Run and verify target modules are missing**

Run: `.venv/bin/python -m pytest tests/contract/archive/test_target_contract.py tests/integration/archive/test_filesystem_target.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement target contract and safe mounted copy**

```python
class ArchiveTarget(Protocol):
    id: str
    def probe(self) -> TargetProbe: ...
    def put(self, source: StoredArtifact, key: str, resume: ResumeState | None = None,
            *, no_replace: bool = True) -> PutResult: ...
    def verify(self, key: str, expected_size: int, expected_sha256: str) -> VerifyResult: ...
    def open_reader(self, key: str) -> BinaryIO: ...
```

Filesystem target construction accepts a redacted `SecretValue`, never a `SecretRef`, and does not re-read env/files. Probe validates the existing guard before each batch and never creates root/guard on failure. Accept only normalized relative POSIX object keys with no empty/`.`/`..` segments, backslashes, NULs, or absolute prefix; reject any resolved parent or existing symlink that escapes the configured root. All archive service puts use `no_replace=True`; an implementation may return idempotent success only after verifying an existing object against the expected stored hash.

Acquire one target-root writer lock for the archiver lifetime. Put writes a sibling unique `.partial`, fsyncs data, then uses a probed no-replace primitive (`renameat2(RENAME_NOREPLACE)`, platform equivalent, or same-filesystem hard-link publication) before syncing parent directories and reading back SHA-256. If the mount supports none of those primitives, the target probe fails clearly instead of using check-then-overwrite. Treat an existing exact-hash object/receipt as idempotent success and a mismatch as a hard conflict. Upload data, source manifest, then receipt last.

- [ ] **Step 4: Run filesystem target round trip**

Run: `.venv/bin/python -m pytest tests/contract/archive/test_target_contract.py tests/integration/archive/test_filesystem_target.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/archive/targets tests/contract/archive tests/integration/archive/test_filesystem_target.py
git commit -m "feat: archive to mounted filesystem"
```

### Task 4: S3-Compatible Multipart Target

**Files:**
- Create: `src/crypto_collector/archive/targets/s3.py`
- Create: `tests/support/moto_s3.py`
- Create: `tests/integration/archive/test_s3_target.py`
- Create: `tests/smoke/test_s3_archive_live.py`

- [ ] **Step 1: Write failing resume and checksum tests**

```python
@pytest.mark.network
def test_multipart_resume_reuses_persisted_upload_and_parts(local_s3, archive_store) -> None:
    access_ref = SecretRef.parse("env:TEST_S3_ACCESS_KEY")
    secret_ref = SecretRef.parse("env:TEST_S3_SECRET_KEY")
    config = local_s3.config_with_credentials(access_ref, secret_ref)
    secrets = SecretSnapshot.from_test_values({access_ref: "access", secret_ref: "secret"})
    transport = InterruptAfterParts(local_s3.transport, count=2)
    target = build_s3_target(config, secrets=secrets, state=archive_store,
                             transport=transport)
    with pytest.raises(InjectedTransportFailure):
        target.put(large_source(), key="raw/large.bin")
    interrupted = archive_store.job(job_key_for("raw/large.bin")).resume_state
    transport.disable_failure()
    resumed = target.put(large_source(), key="raw/large.bin", resume=interrupted)
    assert resumed.upload_id == interrupted.upload_id
    assert resumed.reused_part_numbers == (1, 2)


@pytest.mark.network
def test_etag_alone_never_commits(local_s3) -> None:
    local_s3.disable_checksum_api()
    target = local_s3.target_from_secret_snapshot()
    result = target.put(source_file(), key="raw/part")
    verification = target.verify(result.key, source_file().size, source_file().sha256)
    assert verification.method == "readback_sha256"
    assert verification.verified


@pytest.mark.network
def test_composite_sha256_checksum_falls_back_to_readback(local_s3) -> None:
    local_s3.stub_head_checksum(algorithm="SHA256", checksum_type="COMPOSITE")
    target = local_s3.target_from_secret_snapshot()
    result = target.put(source_file(), key="raw/composite")
    verification = target.verify(result.key, source_file().size, source_file().sha256)
    assert verification.method == "readback_sha256"
    assert verification.verified


@pytest.mark.network
@pytest.mark.parametrize(("checksum_type", "digest", "size_delta", "expected_method"), [
    ("FULL_OBJECT", "expected", 0, "provider_full_object_sha256"),
    ("FULL_OBJECT", "wrong", 0, "readback_sha256"),
    ("FULL_OBJECT", "expected", 1, "readback_sha256"),
    ("FULL_OBJECT", "malformed", 0, "readback_sha256"),
    ("UNKNOWN", "expected", 0, "readback_sha256"),
])
def test_s3_checksum_evidence_requires_exact_full_object_match(
    local_s3, checksum_type, digest, size_delta, expected_method,
) -> None:
    source = source_file()
    local_s3.stub_head_checksum(
        algorithm="SHA256", checksum_type=checksum_type,
        digest=digest_for_test(digest, expected=source.sha256),
        reported_size=source.size + size_delta,
    )
    target = local_s3.target_from_secret_snapshot()
    result = target.put(source, key="raw/checksum-evidence")
    verification = target.verify(result.key, source.size, source.sha256)
    assert verification.method == expected_method
    assert verification.verified
    assert verification.cleanup_strong
    assert local_s3.readback_count == (0 if expected_method.startswith("provider_") else 1)


def test_s3_factory_consumes_one_snapshot_and_keeps_credentials_redacted(local_s3) -> None:
    access_ref = SecretRef.parse("env:TEST_S3_ACCESS_KEY")
    secret_ref = SecretRef.parse("env:TEST_S3_SECRET_KEY")
    config = local_s3.config_with_credentials(access_ref, secret_ref)
    secrets = CountingSecretSnapshot({access_ref: "access", secret_ref: "secret"})
    target = build_s3_target(config, secrets=secrets, state=in_memory_archive_state())
    assert secrets.read_count == {access_ref: 1, secret_ref: 1}
    assert "access" not in repr(target)
    assert "secret" not in repr(target)
```

- [ ] **Step 2: Run and verify S3 target is missing**

Run: `.venv/bin/python -m pytest tests/integration/archive/test_s3_target.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement idempotent multipart and strong verification**

Use configured endpoint, region, addressing style, storage class, multipart size, and concurrency. The S3 factory accepts the process-local `SecretSnapshot`, obtains each configured credential once from it, and passes plaintext only into the SDK constructor; target/spec repr and exceptions remain redacted. Persist upload ID and completed `(part_number, etag, checksum)` after every part. On retry, list/validate remote parts and resume only matching content. Accept a provider `ChecksumSHA256` as cleanup-strength evidence only when the response also declares `ChecksumType=FULL_OBJECT` (or a separately probed, documented endpoint equivalent), its decoded bytes equal the expected SHA-256, and size matches. `COMPOSITE`, missing, malformed, or unknown checksum types always fall back to a streamed readback SHA-256; see the [AWS checksum type contract](https://docs.aws.amazon.com/AmazonS3/latest/API/API_Checksum.html). Never treat single- or multipart ETag as a content hash. Small source-manifest and receipt publication uses an S3-compatible conditional create (`If-None-Match: *` or an endpoint-probed equivalent); a precondition conflict is accepted only after fetching and fully validating the existing object. Data multipart keys are content/policy addressed, but a concurrent existing mismatch is still a hard conflict. A target whose endpoint cannot supply these semantics fails its probe for required use.

The dev lock includes `moto[s3,server]`. `tests/support/moto_s3.py` provides a function-scoped `ThreadedMotoServer(ip_address="127.0.0.1", port=0)`, obtains its literal loopback host/port with `get_host_and_port()`, creates a uniquely named bucket through the real boto3 client, and always stops the server in fixture teardown. Mark these cases `network`; the global pytest policy allows only `127.0.0.1`/`::1`. Use injected boto/HTTP fixtures for checksum API branches Moto does not emulate; do not silently skip those assertions.

The opt-in live test requires explicit endpoint/bucket/credential environment references, uploads a unique test prefix, verifies and restores it, and does not delete it because v1 remote deletion is outside scope.

- [ ] **Step 4: Run local S3-compatible contract tests**

Run: `.venv/bin/python -m pytest tests/contract/archive/test_target_contract.py tests/integration/archive/test_s3_target.py -q`

Expected: PASS, including interrupted resume, existing-match idempotency, existing-mismatch refusal, checksum fallback, and redacted errors.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/archive/targets/s3.py tests/support/moto_s3.py tests/integration/archive/test_s3_target.py tests/smoke/test_s3_archive_live.py
git commit -m "feat: archive to s3 compatible storage"
```

### Task 5: Aliyun OSS Target

**Files:**
- Create: `src/crypto_collector/archive/targets/aliyun_oss.py`
- Create: `tests/contract/archive/test_aliyun_oss_target.py`
- Create: `tests/smoke/test_aliyun_oss_archive_live.py`

- [ ] **Step 1: Write failing CRC64 versus cleanup-strength tests**

```python
def test_optional_backup_can_record_crc64_fast_verification(fake_oss) -> None:
    access_ref = SecretRef.parse("env:TEST_OSS_ACCESS_KEY")
    secret_ref = SecretRef.parse("env:TEST_OSS_SECRET_KEY")
    secrets = SecretSnapshot.from_test_values({access_ref: "access", secret_ref: "secret"})
    target = build_aliyun_oss_target(
        fake_oss.config_with_credentials(access_ref, secret_ref),
        secrets=secrets, required=False, transport=fake_oss.transport)
    result = target.put(source_file(), key="raw/part")
    verification = target.verify(result.key, source_file().size, source_file().sha256)
    assert verification.provider_crc64 is not None
    assert verification.level == "provider_crc64"
    assert not verification.cleanup_strong


def test_required_cleanup_verification_reads_back_sha256(fake_oss) -> None:
    access_ref = SecretRef.parse("env:TEST_OSS_ACCESS_KEY")
    secret_ref = SecretRef.parse("env:TEST_OSS_SECRET_KEY")
    secrets = SecretSnapshot.from_test_values({access_ref: "access", secret_ref: "secret"})
    target = build_aliyun_oss_target(
        fake_oss.config_with_credentials(access_ref, secret_ref),
        secrets=secrets, required=True, transport=fake_oss.transport)
    result = target.put(source_file(), key="raw/part")
    verification = target.verify(result.key, source_file().size, source_file().sha256)
    assert verification.method == "crc64_plus_readback_sha256"
    assert verification.cleanup_strong
```

- [ ] **Step 2: Run and verify OSS target is missing**

Run: `.venv/bin/python -m pytest tests/contract/archive/test_aliyun_oss_target.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement resumable OSS multipart and receipt evidence**

Use endpoint, bucket, prefix, storage class, multipart size/concurrency, and `env:`/`file:` credential references. The OSS factory consumes the same process-local `SecretSnapshot` once and reveals values only to the SDK constructor; no target/spec repr contains plaintext. Persist upload ID/parts and validate resume. Record remote size and provider CRC64. For every required target whose receipt may unlock cleanup, stream-read and compute stored SHA-256; CRC64 alone never sets `cleanup_strong=true`. Optional no-cleanup backups may use provider CRC64 as a declared lower verification level. Source-manifest and receipt commit markers use an OSS conditional no-overwrite header/API verified during target probe; on precondition conflict, fetch and fully validate the existing object. Required OSS targets are unavailable if the configured endpoint cannot provide that semantic.

Contract tests use an injected OSS transport/SDK facade and exact request/response fixtures. Real provider tests are `live` and require explicit credentials; they never turn SDK/business errors into skips.

- [ ] **Step 4: Run OSS contract tests**

Run: `.venv/bin/python -m pytest tests/contract/archive/test_aliyun_oss_target.py -q`

Expected: PASS, including multipart resume, CRC mismatch, readback mismatch, credentials redaction, and idempotent existing objects.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/archive/targets/aliyun_oss.py tests/contract/archive/test_aliyun_oss_target.py tests/smoke/test_aliyun_oss_archive_live.py
git commit -m "feat: archive to aliyun oss"
```

### Task 6: Archive Service, Verify, and Restore

**Files:**
- Create: `src/crypto_collector/archive/discovery.py`
- Create: `src/crypto_collector/archive/service.py`
- Create: `src/crypto_collector/archive/verify.py`
- Create: `src/crypto_collector/archive/restore.py`
- Modify: `src/crypto_collector/cli.py`
- Test: `tests/integration/archive/test_service.py`
- Test: `tests/cli/test_archive.py`

- [ ] **Step 1: Write failing commit-order and dual-hash restore tests**

```python
def test_receipt_is_uploaded_after_data_and_source_manifest(scripted_target, archive_service) -> None:
    archive_service.run_once()
    assert scripted_target.trace == [
        ("put", "data"), ("verify", "data"),
        ("put", "source_manifest"), ("verify", "source_manifest"),
        ("put_no_replace", "receipt"), ("verify", "receipt"),
    ]
    assert all(call.key.startswith("_archive/v1/policy=")
               for call in scripted_target.object_calls)
    assert archive_service.state.jobs()[0].state == "COMMITTED"


def test_manifest_verification_failure_never_publishes_receipt(
    scripted_target, archive_service,
) -> None:
    scripted_target.fail_verify(role="source_manifest", error=RetryableTargetError())
    archive_service.run_once()
    assert ("put_no_replace", "receipt") not in scripted_target.trace
    assert archive_service.state.jobs()[0].state == "RETRYING"


def test_receipt_verify_failure_stays_uncommitted_then_point_read_converges(
    scripted_target, archive_service,
) -> None:
    scripted_target.fail_verify_once(role="receipt", error=RetryableTargetError())
    archive_service.run_once()
    assert scripted_target.receipt_version_count == 1
    assert archive_service.state.jobs()[0].state == "RETRYING"
    assert archive_service.state.jobs()[0].workflow_checkpoint == "receipt_published"
    assert scripted_target.trace[-2:] == [
        ("put_no_replace", "receipt"), ("verify_failed", "receipt"),
    ]

    restarted = restart_archive_service(archive_service)
    restarted.run_once()
    assert scripted_target.trace[-2:] == [
        ("point_read", "receipt"), ("verify", "receipt"),
    ]
    assert scripted_target.receipt_version_count == 1
    assert restarted.state.jobs()[0].state == "COMMITTED"


def test_restore_verifies_stored_then_source_hash(tmp_path, committed_receipt, target) -> None:
    destination = tmp_path / "restore" / "part.json"
    result = restore(committed_receipt, target=target, destination=destination)
    assert result.stored_sha256_verified
    assert result.source_sha256_verified
    assert sha256_file(destination) == committed_receipt.source_sha256


def test_restore_refuses_existing_destination(tmp_path, committed_receipt, target) -> None:
    destination = tmp_path / "part.json"
    destination.write_text("existing", encoding="utf-8")
    with pytest.raises(FileExistsError):
        restore(committed_receipt, target=target, destination=destination)


def test_database_rebuild_fetches_only_deterministic_receipt_keys(tmp_path, committed_target) -> None:
    rebuilt = rebuild_archive_state(state_root=tmp_path / "state",
                                    data_root=tmp_path / "data",
                                    targets=[committed_target])
    assert rebuilt.jobs[0].state == "COMMITTED"
    assert committed_target.list_calls == []
    assert committed_target.get_calls == [rebuilt.jobs[0].receipt_key]


def test_concurrent_receipt_create_has_one_winner_and_validated_idempotent_loser(target) -> None:
    first, second = race_two_services_on_same_source(target)
    assert sorted([first.created_receipt, second.created_receipt]) == [False, True]
    assert first.receipt.source_sha256 == second.receipt.source_sha256
    assert first.receipt.stored_sha256 == second.receipt.stored_sha256
    assert target.receipt_version_count == 1


@pytest.mark.parametrize("args", [
    ["archive", "run"],
    ["archive", "verify", "receipt.json"],
    ["archive", "restore", "receipt.json", "--destination", "restore.bin"],
])
def test_archive_commands_never_guess_config_path(args) -> None:
    result = CliRunner().invoke(app, args)
    assert result.exit_code == 2
    assert "CONFIG_PATH" in result.stdout
```

- [ ] **Step 2: Run and verify service/CLI modules are missing**

Run: `.venv/bin/python -m pytest tests/integration/archive/test_service.py tests/cli/test_archive.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement closed-manifest discovery and receipt-last commit**

Discover raw and derived closed manifests, ignore `.partial`, acquire a shared source lease, freeze and durably publish policy/source facts, and enqueue target jobs. For each artifact, the exact commit trace is: put data, verify data, put source manifest, verify source manifest, conditionally create receipt with no-replace semantics, then fetch/verify the receipt. Any failure before receipt publication leaves no receipt; any failure during receipt publication/verification is reconciled by point-reading the deterministic receipt key and validating its full content. Transition to `COMMITTED` only after that final verification. After strong receipt validation, atomically write `<state_root>/archive/receipt-index/<source-manifest-sha256>/<target-id>/<policy-sha256>.json`, containing the deterministic remote receipt key/hash and no credentials. Retry persists with bounded full jitter and provider-specific throttling; deterministic conflicts enter `TERMINAL_CONFLICT` and are never retried automatically. Rebuild missing SQLite state by scanning source manifests plus policy/source facts, receipt indexes, and tombstones; when an index is absent, derive the exact receipt key from the frozen policy and issue a point read to each configured target. Do not require remote listing, guess keys from current config, or consider an unvalidated index/receipt committed.

`collector archive run CONFIG_PATH` calls `load_resolved_config` once, retains its `SecretSnapshot` for target construction, and never resolves individual references again. `archive verify CONFIG_PATH RECEIPT`, `archive restore CONFIG_PATH RECEIPT --destination PATH`, and `archive policy migrate CONFIG_PATH --source-manifest-sha SHA --from-policy SHA --reason TEXT` use the same service boundary and never guess a default config. Migration verifies that the selected source and active old policy match before writing a new generation. Verify validates receipt hash, stored size/SHA/provider evidence, then optional decode and source SHA. Restore streams into destination `.partial`, syncs, atomically renames without overwrite unless explicit `--overwrite`, and syncs its directory. Redact all provider/proxy secrets from exceptions and status.

- [ ] **Step 4: Run all offline archive round trips**

Run: `.venv/bin/python -m pytest tests/unit/archive tests/contract/archive tests/integration/archive tests/cli/test_archive.py -q`

Expected: PASS for pass-through and zstd, filesystem, local S3-compatible, injected OSS, interruption/restart, verification mismatch, and restore mismatch.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/archive src/crypto_collector/cli.py tests/integration/archive tests/cli/test_archive.py
git commit -m "feat: verify and restore archived data"
```

### Task 7: Cleanup Eligibility, Optional Abandonment, and Tombstones

**Files:**
- Create: `src/crypto_collector/archive/cleanup.py`
- Create: `src/crypto_collector/archive/tombstone.py`
- Test: `tests/unit/archive/test_cleanup.py`
- Test: `tests/integration/archive/test_cleanup_crash.py`

- [ ] **Step 1: Write failing multi-gate and lease-race tests**

```python
def test_raw_cleanup_requires_receipts_ack_grace_and_revision_fence() -> None:
    source = cleanup_source(
        required_committed=True,
        materializer_ack=True,
        grace_elapsed=True,
        now_ns=partition_end() + materializer_delay() + revision_horizon() - 1,
    )
    assert eligibility(source).eligible is False
    assert eligibility(source).blocked_by == ("revision_retention_fence",)


def test_required_receipt_must_be_cleanup_strong() -> None:
    source = cleanup_source(required_receipts=[receipt(verification="provider_crc64")])
    assert eligibility(source).eligible is False
    assert "strong_verification" in eligibility(source).blocked_by


def test_cleanup_revalidates_after_exclusive_lease(tmp_path) -> None:
    source = eligible_source(tmp_path)
    with SourceLease.shared(source.lease_path):
        assert cleanup_once(source).status == "LEASE_BUSY"
    source.remove_required_receipt_for_test()
    assert cleanup_once(source).status == "NO_LONGER_ELIGIBLE"
    assert source.data_path.exists()


def test_optional_job_becomes_explicit_abandonment_after_valid_cleanup(tmp_path) -> None:
    source = eligible_source(tmp_path, optional_pending={"webdav"}, optional_state="RETRYING")
    result = cleanup_once(source, sync_backend=recording_sync_backend())
    assert result.tombstone.optional_targets["webdav"] == "ABANDONED_LOCAL_SOURCE_DELETED"
    assert result.permanent_warning
    assert result.sync_trace[-4:] == [
        "tombstone_temp_write", "tombstone_file_sync",
        "tombstone_rename", "tombstone_directory_sync",
    ]
    source.archive_state.close()
    reopened = ArchiveState.open(source.archive_state_path)
    reconcile_cleanup_tombstone(result.tombstone_path, state=reopened)
    assert reopened.job(source.job_key("webdav")).state == "ABANDONED_LOCAL_SOURCE_DELETED"


def test_abandonment_rejects_unpublished_or_other_target_tombstone(tmp_path) -> None:
    source = eligible_source(tmp_path / "source", optional_pending={"webdav"},
                             optional_state="RETRYING")
    unpublished = write_tombstone_temp_for_test(source, optional_targets={"webdav"})
    other = eligible_source(tmp_path / "other", optional_pending={"cold-backup"})
    wrong_target = cleanup_once(other).tombstone_path
    for proof_path in (unpublished, wrong_target):
        with pytest.raises(DurableCleanupProofError):
            reconcile_cleanup_tombstone(proof_path, state=source.archive_state)
    assert source.archive_state.job(source.job_key("webdav")).state == "RETRYING"


@pytest.mark.parametrize("phase", [
    "intent_temp_write", "intent_file_sync", "intent_rename",
    "intent_directory_sync", "data_unlink", "data_directory_sync",
    "tombstone_temp_write", "tombstone_file_sync", "tombstone_rename",
    "tombstone_directory_sync",
])
def test_cleanup_power_loss_boundaries_converge_in_fresh_process(tmp_path, phase) -> None:
    source = eligible_source(tmp_path)
    child = start_cleanup_crash_child(source, halt_at=phase)
    wait_for_phase_marker(source.state_root, phase)
    child.kill()
    child.wait(timeout=10)
    result = reconcile_cleanup_in_fresh_process(source)
    assert result.state in {"SOURCE_PRESENT", "CLEANED_WITH_TOMBSTONE"}
    assert result.intent_is_durable_if_source_missing
    assert result.tombstone_is_durable_if_committed
    assert result.source_hash_or_tombstone_source_hash == source.sha256
```

- [ ] **Step 2: Run and verify cleanup modules are missing**

Run: `.venv/bin/python -m pytest tests/unit/archive/test_cleanup.py tests/integration/archive/test_cleanup_crash.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement a pure gate followed by exclusive revalidation**

Raw eligibility requires every frozen required target COMMITTED with cleanup-strong verification, materializer ACK when enabled, cleanup grace, `partition_end + materializer.delay + revision_horizon`, and no active lease. Derived eligibility omits ACK/revision input retention but still requires policy receipts/grace/lease. Optional jobs never block eligibility.

Cleanup first computes eligibility without mutation, acquires an exclusive source lease, and recomputes it from disk/state. It then follows this power-loss protocol exactly:

1. Build canonical `CleanupIntentV1` containing source path/size/SHA, source-manifest SHA, active policy generation/SHA, receipt and ACK hashes, retention/grace evidence, optional-job disposition, and its own canonical hash.
2. Create a unique sibling intent temp with `O_CREAT | O_EXCL`, write all bytes, `fdatasync/fsync` the file, close it, no-replace rename it to `<state_root>/archive/cleanup-intents/<source-sha>.intent.json`, then fsync that parent directory. An existing final intent is reusable only after exact validation.
3. Only after the intent-directory sync succeeds, unlink the data file and fsync the data parent directory. Never delete the source manifest, leases, policy/source facts, receipt indexes, or ACK.
4. Write `CleanupTombstoneV1` to an exclusive temp, sync/close it, no-replace rename to its final path, then fsync the tombstone parent directory. The tombstone binds the intent hash and source hash. Preserve the intent and tombstone permanently as small audit facts.

Any error before step 2's directory sync leaves the source untouched. Startup reconciliation treats a durable intent plus present source as retryable and a durable intent plus missing source as cleanup-in-progress; it revalidates all hashes and completes the tombstone without pretending the file still exists. A final tombstone is committed only after its directory sync. The subprocess phase hooks above cover temp write, file sync, rename-before-directory-sync, directory sync, unlink, and tombstone boundaries in a fresh process; they are injected callbacks, never production environment switches. Only the cleanup reconciler can transition an optional job to `ABANDONED_LOCAL_SOURCE_DELETED`: it must load the final (never temp/symlink) tombstone from the configured tombstone directory, verify schema/canonical hash, intent/source/policy bindings, and that the exact target ID is named optional-abandoned, then transact the SQLite state. Restart can replay this idempotently because the tombstone is authoritative; a temp, unverified, wrong-source, or wrong-target document is rejected. Required jobs never take this transition. Do not delete remote objects.

- [ ] **Step 4: Run cleanup crash-point matrix**

Run: `.venv/bin/python -m pytest tests/unit/archive/test_cleanup.py tests/integration/archive/test_cleanup_crash.py -q`

Expected: PASS across every listed file-write/file-sync/rename/directory-sync/unlink boundary, with no source deletion unless a durable validated intent survives and no committed cleanup unless a durable validated tombstone survives.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/archive/cleanup.py src/crypto_collector/archive/tombstone.py tests/unit/archive/test_cleanup.py tests/integration/archive/test_cleanup_crash.py
git commit -m "feat: gate local archive cleanup"
```

- [ ] **Step 6: Run the repository-wide offline regression gate**

Run: `.venv/bin/python scripts/verify_role_locks.py --require-entry archiver`

Expected: all four clean lock installs pass and the archiver production entry imports under its role-only environment.

Run: `.venv/bin/python -m pytest -q -m "not live and not performance"`

Expected: PASS with external sockets denied; local object-store fixtures remain explicitly loopback-marked.
