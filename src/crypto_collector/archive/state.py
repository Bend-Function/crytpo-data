from __future__ import annotations

import errno
import hashlib
import os
import sqlite3
import stat
import time
import uuid
from collections.abc import Callable, Iterable, Iterator
from contextlib import ExitStack, contextmanager, suppress
from pathlib import Path
from typing import ClassVar, Self

from pydantic import ValidationError

from crypto_collector.archive.models import (
    TERMINAL_JOB_STATES,
    WORKFLOW_CHECKPOINT_ORDER,
    ActiveGenerationPointerV1,
    ArchiveCleanupFactsV1,
    ArchiveDiscoveryV1,
    ArchiveGenerationJobV1,
    ArchiveJobKey,
    ArchiveJobState,
    ArchiveJobV1,
    ArchivePolicyV1,
    ArchiveSourceGenerationFactV1,
    ArchiveSourceManifestV1,
    CleanupGatePolicyV1,
    FrozenArchiveTargetV1,
    MultipartPartV1,
    WorkflowCheckpoint,
    build_generation_fact,
    canonical_json_bytes,
    validate_source_manifest,
)
from crypto_collector.archive.policy import (
    ArchivePolicyError,
    freeze_policy,
    load_policy_bytes,
    migrate_policy,
)
from crypto_collector.config.models import ArchiveConfig
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.storage.lease import SourceLease
from crypto_collector.storage.manifest import lease_path_for_data

_SCHEMA_VERSION = 1
_MAX_NS = 2**63 - 1
_ACTIVE_STATES = tuple(
    state.value for state in ArchiveJobState if state not in TERMINAL_JOB_STATES
)


class ArchiveStateError(RuntimeError):
    pass


class InvalidArchiveTransition(ArchiveStateError):
    pass


class ArchiveTargetError(RuntimeError):
    pass


class RetryableTargetError(ArchiveTargetError):
    pass


class ArchiveConflictError(ArchiveTargetError):
    pass


class ExistingObjectMismatch(ArchiveConflictError):
    pass


class StoredObjectMismatch(ArchiveConflictError):
    pass


class RemotePolicyMismatch(ArchiveConflictError):
    pass


def _job_state(value: ArchiveJobState | str) -> ArchiveJobState:
    try:
        return value if type(value) is ArchiveJobState else ArchiveJobState(value)
    except (TypeError, ValueError) as error:
        raise InvalidArchiveTransition(f"unknown archive state {value!r}") from error


def _checkpoint(value: WorkflowCheckpoint | str) -> WorkflowCheckpoint:
    try:
        return value if type(value) is WorkflowCheckpoint else WorkflowCheckpoint(value)
    except (TypeError, ValueError) as error:
        raise ArchiveStateError(f"unknown workflow checkpoint {value!r}") from error


class ArchiveTransition:
    _ALLOWED = frozenset(
        {
            (ArchiveJobState.DISCOVERED, ArchiveJobState.QUEUED),
            (ArchiveJobState.QUEUED, ArchiveJobState.TRANSFORMING),
            (ArchiveJobState.QUEUED, ArchiveJobState.UPLOADING),
            (ArchiveJobState.TRANSFORMING, ArchiveJobState.UPLOADING),
            (ArchiveJobState.UPLOADING, ArchiveJobState.VERIFYING),
            (ArchiveJobState.VERIFYING, ArchiveJobState.UPLOADING),
            (ArchiveJobState.VERIFYING, ArchiveJobState.COMMITTED),
        }
    )
    _RETRYABLE_FROM = frozenset(
        {
            ArchiveJobState.QUEUED,
            ArchiveJobState.TRANSFORMING,
            ArchiveJobState.UPLOADING,
            ArchiveJobState.VERIFYING,
        }
    )
    _RESUME: ClassVar[dict[WorkflowCheckpoint, ArchiveJobState]] = {
        WorkflowCheckpoint.SOURCE: ArchiveJobState.TRANSFORMING,
        WorkflowCheckpoint.STORED: ArchiveJobState.UPLOADING,
        WorkflowCheckpoint.DATA_UPLOADED: ArchiveJobState.VERIFYING,
        WorkflowCheckpoint.DATA_VERIFIED: ArchiveJobState.UPLOADING,
        WorkflowCheckpoint.SOURCE_MANIFEST_UPLOADED: ArchiveJobState.VERIFYING,
        WorkflowCheckpoint.SOURCE_MANIFEST_VERIFIED: ArchiveJobState.UPLOADING,
        WorkflowCheckpoint.RECEIPT_PUBLISHED: ArchiveJobState.VERIFYING,
    }

    @classmethod
    def validate(
        cls,
        old: ArchiveJobState | str,
        new: ArchiveJobState | str,
        *,
        error: BaseException | None = None,
        target_required: bool = True,
    ) -> bool:
        if type(target_required) is not bool:
            raise TypeError("target_required must be bool")
        old_state = _job_state(old)
        new_state = _job_state(new)
        if new_state is ArchiveJobState.ABANDONED_LOCAL_SOURCE_DELETED:
            raise InvalidArchiveTransition(
                "local-source abandonment is cleanup-reconciler only"
            )
        if old_state in TERMINAL_JOB_STATES:
            raise InvalidArchiveTransition(
                f"terminal state {old_state.value} has no outgoing transition"
            )
        if new_state is ArchiveJobState.RETRYING:
            if old_state not in cls._RETRYABLE_FROM or not isinstance(
                error,
                RetryableTargetError,
            ):
                raise InvalidArchiveTransition(
                    "RETRYING requires an active state and RetryableTargetError"
                )
            return True
        if error is not None:
            raise InvalidArchiveTransition(
                "errors may be supplied only for classified retry transitions"
            )
        if (old_state, new_state) not in cls._ALLOWED:
            raise InvalidArchiveTransition(
                f"archive transition {old_state.value} -> {new_state.value} is invalid"
            )
        return True

    @classmethod
    def resume_target(
        cls,
        state: ArchiveJobState | str,
        *,
        checkpoint: WorkflowCheckpoint | str,
    ) -> ArchiveJobState:
        if _job_state(state) is not ArchiveJobState.RETRYING:
            raise InvalidArchiveTransition("only RETRYING jobs can resume")
        return cls._RESUME[_checkpoint(checkpoint)]


_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS archive_policy (
        policy_sha256 TEXT PRIMARY KEY,
        canonical_json BLOB NOT NULL,
        CHECK (length(policy_sha256) = 64)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS archive_source (
        source_manifest_sha256 TEXT PRIMARY KEY,
        source_json BLOB NOT NULL,
        active_generation INTEGER NOT NULL,
        active_policy_sha256 TEXT NOT NULL,
        CHECK (length(source_manifest_sha256) = 64),
        CHECK (active_generation > 0),
        CHECK (length(active_policy_sha256) = 64),
        FOREIGN KEY (active_policy_sha256)
            REFERENCES archive_policy(policy_sha256)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS archive_source_generation (
        source_manifest_sha256 TEXT NOT NULL,
        generation INTEGER NOT NULL,
        policy_sha256 TEXT NOT NULL,
        generation_fact_sha256 TEXT NOT NULL,
        canonical_json BLOB NOT NULL,
        active INTEGER NOT NULL CHECK (active IN (0, 1)),
        PRIMARY KEY (source_manifest_sha256, generation),
        UNIQUE (source_manifest_sha256, generation_fact_sha256),
        CHECK (generation > 0),
        CHECK (length(policy_sha256) = 64),
        CHECK (length(generation_fact_sha256) = 64),
        FOREIGN KEY (source_manifest_sha256)
            REFERENCES archive_source(source_manifest_sha256),
        FOREIGN KEY (policy_sha256)
            REFERENCES archive_policy(policy_sha256)
    )
    """,
    """
    CREATE UNIQUE INDEX IF NOT EXISTS archive_one_active_generation
    ON archive_source_generation(source_manifest_sha256)
    WHERE active = 1
    """,
    """
    CREATE TABLE IF NOT EXISTS archive_job (
        source_manifest_sha256 TEXT NOT NULL,
        artifact_role TEXT NOT NULL,
        artifact_relative_path TEXT NOT NULL,
        artifact_sha256 TEXT NOT NULL,
        target_id TEXT NOT NULL,
        policy_sha256 TEXT NOT NULL,
        generation INTEGER NOT NULL,
        target_required INTEGER NOT NULL CHECK (target_required IN (0, 1)),
        state TEXT NOT NULL CHECK (state IN (
            'DISCOVERED', 'QUEUED', 'TRANSFORMING', 'UPLOADING',
            'VERIFYING', 'RETRYING', 'COMMITTED', 'TERMINAL_CONFLICT',
            'ABANDONED_LOCAL_SOURCE_DELETED'
        )),
        attempt INTEGER NOT NULL CHECK (attempt >= 0),
        retry_at_ns INTEGER,
        workflow_checkpoint TEXT NOT NULL CHECK (workflow_checkpoint IN (
            'source', 'stored', 'data_uploaded', 'data_verified',
            'source_manifest_uploaded', 'source_manifest_verified',
            'receipt_published'
        )),
        multipart_upload_id TEXT,
        multipart_parts_json BLOB NOT NULL,
        staging_path TEXT,
        data_key TEXT NOT NULL,
        source_manifest_key TEXT NOT NULL,
        receipt_key TEXT NOT NULL,
        stored_sha256 TEXT,
        stored_size INTEGER,
        provider_checksum_json BLOB,
        verification_json BLOB,
        error_class TEXT,
        updated_at_ns INTEGER NOT NULL CHECK (updated_at_ns >= 0),
        PRIMARY KEY (
            source_manifest_sha256, artifact_role, artifact_sha256,
            target_id, policy_sha256
        ),
        CHECK ((state = 'RETRYING') = (retry_at_ns IS NOT NULL)),
        CHECK ((stored_sha256 IS NULL) = (stored_size IS NULL)),
        FOREIGN KEY (source_manifest_sha256, generation)
            REFERENCES archive_source_generation(source_manifest_sha256, generation),
        FOREIGN KEY (policy_sha256)
            REFERENCES archive_policy(policy_sha256)
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS archive_job_due
    ON archive_job(state, retry_at_ns, updated_at_ns)
    """,
    """
    CREATE TABLE IF NOT EXISTS archive_generation_job (
        source_manifest_sha256 TEXT NOT NULL,
        generation INTEGER NOT NULL,
        artifact_role TEXT NOT NULL,
        artifact_sha256 TEXT NOT NULL,
        target_id TEXT NOT NULL,
        policy_sha256 TEXT NOT NULL,
        PRIMARY KEY (
            source_manifest_sha256, generation, artifact_role,
            artifact_sha256, target_id, policy_sha256
        ),
        FOREIGN KEY (source_manifest_sha256, generation)
            REFERENCES archive_source_generation(source_manifest_sha256, generation),
        FOREIGN KEY (
            source_manifest_sha256, artifact_role, artifact_sha256,
            target_id, policy_sha256
        ) REFERENCES archive_job(
            source_manifest_sha256, artifact_role, artifact_sha256,
            target_id, policy_sha256
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS archive_policy_migration (
        source_manifest_sha256 TEXT NOT NULL,
        generation INTEGER NOT NULL,
        old_policy_sha256 TEXT NOT NULL,
        new_policy_sha256 TEXT NOT NULL,
        operator_reason TEXT NOT NULL,
        recorded_at_ns INTEGER NOT NULL CHECK (recorded_at_ns >= 0),
        PRIMARY KEY (source_manifest_sha256, generation),
        FOREIGN KEY (source_manifest_sha256, generation)
            REFERENCES archive_source_generation(source_manifest_sha256, generation)
    )
    """,
)


def _archive_schema_objects(
    connection: sqlite3.Connection,
) -> tuple[tuple[str, str, str, str | None], ...]:
    return tuple(
        (
            str(row[0]),
            str(row[1]),
            str(row[2]),
            None if row[3] is None else str(row[3]),
        )
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
              FROM sqlite_master
             WHERE name GLOB 'archive_*' OR tbl_name GLOB 'archive_*'
             ORDER BY type, name, tbl_name
            """
        ).fetchall()
    )


def _expected_archive_schema_objects() -> tuple[tuple[str, str, str, str | None], ...]:
    reference = sqlite3.connect(":memory:")
    try:
        for statement in _SCHEMA:
            reference.execute(statement)
        return _archive_schema_objects(reference)
    finally:
        reference.close()


_EXPECTED_SCHEMA_OBJECTS = _expected_archive_schema_objects()

_EXPECTED_COLUMNS = {
    "archive_policy": ("policy_sha256", "canonical_json"),
    "archive_source": (
        "source_manifest_sha256",
        "source_json",
        "active_generation",
        "active_policy_sha256",
    ),
    "archive_source_generation": (
        "source_manifest_sha256",
        "generation",
        "policy_sha256",
        "generation_fact_sha256",
        "canonical_json",
        "active",
    ),
    "archive_job": (
        "source_manifest_sha256",
        "artifact_role",
        "artifact_relative_path",
        "artifact_sha256",
        "target_id",
        "policy_sha256",
        "generation",
        "target_required",
        "state",
        "attempt",
        "retry_at_ns",
        "workflow_checkpoint",
        "multipart_upload_id",
        "multipart_parts_json",
        "staging_path",
        "data_key",
        "source_manifest_key",
        "receipt_key",
        "stored_sha256",
        "stored_size",
        "provider_checksum_json",
        "verification_json",
        "error_class",
        "updated_at_ns",
    ),
    "archive_generation_job": (
        "source_manifest_sha256",
        "generation",
        "artifact_role",
        "artifact_sha256",
        "target_id",
        "policy_sha256",
    ),
    "archive_policy_migration": (
        "source_manifest_sha256",
        "generation",
        "old_policy_sha256",
        "new_policy_sha256",
        "operator_reason",
        "recorded_at_ns",
    ),
}


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA synchronous = FULL")
    mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
    if mode is None or str(mode[0]).casefold() != "wal":
        raise ArchiveStateError("archive state requires SQLite WAL mode")
    connection.execute("PRAGMA synchronous = FULL")
    connection.execute("BEGIN IMMEDIATE")
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in (0, _SCHEMA_VERSION):
            raise ArchiveStateError(f"unsupported archive schema version {version}")
        if version == 0:
            for statement in _SCHEMA:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        for table, expected in _EXPECTED_COLUMNS.items():
            rows = connection.execute(f"PRAGMA table_info({table})").fetchall()
            observed = tuple(str(row[1]) for row in rows)
            if observed != expected:
                raise ArchiveStateError(
                    f"{table} schema does not match version {_SCHEMA_VERSION}"
                )
        if _archive_schema_objects(connection) != _EXPECTED_SCHEMA_OBJECTS:
            raise ArchiveStateError(
                f"archive schema does not match version {_SCHEMA_VERSION}"
            )
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise ArchiveStateError("archive SQLite foreign-key integrity check failed")
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _ensure_directory(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.anchor:
        raise ArchiveStateError(f"archive state directory is not absolute: {path}")
    cursor = Path(absolute.anchor)
    try:
        root = cursor.lstat()
    except FileNotFoundError as error:
        raise ArchiveStateError("archive filesystem root is unavailable") from error
    if not stat.S_ISDIR(root.st_mode) or stat.S_ISLNK(root.st_mode):
        raise ArchiveStateError("archive filesystem root is not a real directory")
    for segment in absolute.parts[1:]:
        cursor = cursor / segment
        try:
            observed = cursor.lstat()
        except FileNotFoundError:
            try:
                cursor.mkdir(mode=0o750)
            except FileExistsError:
                observed = cursor.lstat()
            else:
                _fsync_directory(cursor.parent)
                observed = cursor.lstat()
        if not stat.S_ISDIR(observed.st_mode) or stat.S_ISLNK(observed.st_mode):
            raise ArchiveStateError(
                f"archive state path is not a real directory: {cursor}"
            )


def _read_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode):
            raise ArchiveStateError(f"archive fact is not a regular file: {path}")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
    finally:
        os.close(fd)


def _write_synced_temp(directory: Path, final_name: str, content: bytes) -> Path:
    _ensure_directory(directory)
    name = f".{final_name}.{uuid.uuid4().hex}.tmp"
    path = directory / name
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = os.open(path, flags, 0o640)
    try:
        view = memoryview(content)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(errno.EIO, "archive fact write made no progress")
            view = view[written:]
        os.fsync(fd)
    except BaseException:
        try:
            os.close(fd)
        finally:
            path.unlink(missing_ok=True)
        raise
    else:
        os.close(fd)
    return path


def _publish_immutable(path: Path, content: bytes) -> None:
    if _path_entry_exists(path):
        if _read_regular(path) != content:
            raise ArchiveStateError(f"immutable archive fact conflict: {path}")
        _fsync_directory(path.parent)
        return
    temporary = _write_synced_temp(path.parent, path.name, content)
    try:
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if _read_regular(path) != content:
                raise ArchiveStateError(f"immutable archive fact conflict: {path}")
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _replace_pointer(path: Path, content: bytes) -> None:
    temporary = _write_synced_temp(path.parent, path.name, content)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _path_entry_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _lease_path_for_artifact(
    source: ArchiveSourceManifestV1,
    data_path: Path,
) -> Path:
    if source.manifest_kind == "raw":
        return lease_path_for_data(data_path)
    return data_path.with_name(f"{data_path.name}.lease")


def _load_generation_bytes(source: bytes) -> ArchiveSourceGenerationFactV1:
    if not source.endswith(b"\n"):
        raise ArchiveStateError("source generation fact is not canonical")
    try:
        fact = ArchiveSourceGenerationFactV1.model_validate_json(source)
    except (ValidationError, ValueError) as error:
        raise ArchiveStateError("source generation fact is invalid") from error
    if fact.canonical_bytes() != source:
        raise ArchiveStateError("source generation fact is not canonical")
    return fact


def _load_pointer_bytes(source: bytes) -> ActiveGenerationPointerV1:
    if not source.endswith(b"\n"):
        raise ArchiveStateError("active generation pointer is not canonical")
    try:
        pointer = ActiveGenerationPointerV1.model_validate_json(source)
    except (ValidationError, ValueError) as error:
        raise ArchiveStateError("active generation pointer is invalid") from error
    if pointer.canonical_bytes() != source:
        raise ArchiveStateError("active generation pointer is not canonical")
    return pointer


def _prefix_key(prefix: str, key: str) -> str:
    return f"{prefix}/{key}" if prefix else key


def _should_encode(
    artifact_path: str,
    size_bytes: int,
    target: FrozenArchiveTargetV1,
) -> bool:
    compression = target.compression
    if not compression.enabled or compression.mode == "off":
        return False
    already_compressed = artifact_path.endswith((".zst", ".parquet"))
    if already_compressed and not compression.recompress:
        return False
    return not (compression.mode == "auto" and size_bytes < compression.min_size_bytes)


def _generation_jobs(
    source: ArchiveSourceManifestV1,
    policy: ArchivePolicyV1,
) -> tuple[ArchiveGenerationJobV1, ...]:
    jobs: list[ArchiveGenerationJobV1] = []
    namespace = policy.remote_namespace
    for artifact in source.artifacts:
        for target in policy.targets:
            if _should_encode(artifact.relative_path, artifact.size_bytes, target):
                data_tail = (
                    f"_encoded/zstd/v1/target={target.target_id}/"
                    f"{artifact.relative_path}."
                    f"{artifact.sha256}.zst"
                )
            else:
                data_tail = artifact.relative_path
            data_key = _prefix_key(
                target.remote_prefix,
                f"{namespace}/{data_tail}",
            )
            source_manifest_key = _prefix_key(
                target.remote_prefix,
                f"{namespace}/_manifests/{source.source_manifest_sha256}.manifest.json",
            )
            receipt_key = _prefix_key(
                target.remote_prefix,
                f"{namespace}/_receipts/{target.target_id}/"
                f"{source.source_manifest_sha256}/{artifact.artifact_role}."
                f"{artifact.sha256}.archive-receipt.json",
            )
            jobs.append(
                ArchiveGenerationJobV1(
                    artifact_role=artifact.artifact_role,
                    artifact_relative_path=artifact.relative_path,
                    artifact_sha256=artifact.sha256,
                    target_id=target.target_id,
                    target_required=target.required,
                    data_key=data_key,
                    source_manifest_key=source_manifest_key,
                    receipt_key=receipt_key,
                )
            )
    return tuple(
        sorted(
            jobs,
            key=lambda job: (
                job.artifact_role,
                job.artifact_sha256,
                job.target_id,
            ),
        )
    )


def _checked_add(*values: int) -> int:
    result = sum(values)
    if result > _MAX_NS:
        raise ArchiveStateError("frozen cleanup deadline exceeds signed int64")
    return result


def _cleanup_facts(
    source: ArchiveSourceManifestV1,
    gates: CleanupGatePolicyV1,
) -> ArchiveCleanupFactsV1:
    if gates.source_kind != source.manifest_kind:
        raise ArchiveStateError("cleanup gate source kind does not match manifest")
    grace_deadline = _checked_add(source.closed_at_ns, gates.grace_ns)
    ack_required = source.manifest_kind == "raw" and gates.materializer_enabled
    if ack_required:
        partition_end = source.storage_partition_end_ns
        if partition_end is None:
            raise ArchiveStateError("raw cleanup gates require a partition end")
        revision_deadline = _checked_add(
            partition_end,
            gates.materializer_delay_ns,
            gates.revision_horizon_ns,
        )
        delay = gates.materializer_delay_ns
        horizon = gates.revision_horizon_ns
    else:
        partition_end = source.storage_partition_end_ns
        revision_deadline = None
        delay = 0
        horizon = 0
    return ArchiveCleanupFactsV1(
        grace_anchor_ns=source.closed_at_ns,
        grace_deadline_ns=grace_deadline,
        materializer_ack_required=ack_required,
        storage_partition_end_ns=partition_end,
        materializer_delay_ns=delay,
        revision_horizon_ns=horizon,
        revision_deadline_ns=revision_deadline,
    )


def _source_bytes(source: ArchiveSourceManifestV1) -> bytes:
    return canonical_json_bytes(source.model_dump(mode="json")) + b"\n"


def _parts_bytes(parts: tuple[MultipartPartV1, ...]) -> bytes:
    return canonical_json_bytes([part.model_dump(mode="json") for part in parts])


def _parts_from_bytes(source: bytes) -> tuple[MultipartPartV1, ...]:
    value = decode_json(source)
    if type(value) is not list:
        raise ArchiveStateError("multipart checkpoint is not a JSON array")
    try:
        parts = tuple(MultipartPartV1.model_validate(item) for item in value)
    except (ValidationError, ValueError) as error:
        raise ArchiveStateError("multipart checkpoint is invalid") from error
    if _parts_bytes(parts) != source:
        raise ArchiveStateError("multipart checkpoint is not canonical")
    return parts


def _canonical_document(source: bytes, *, field_name: str) -> bytes:
    if type(source) is not bytes:
        raise TypeError(f"{field_name} must be bytes")
    try:
        decoded = decode_json(source)
        canonical = canonical_json_bytes(decoded)
    except (TypeError, ValueError) as error:
        raise ArchiveStateError(f"{field_name} is not valid JSON") from error
    if source != canonical:
        raise ArchiveStateError(f"{field_name} must use canonical JSON")
    if type(decoded) is not dict or not decoded:
        raise ArchiveStateError(f"{field_name} must be a nonempty JSON object")
    return source


def _job_from_row(row: sqlite3.Row) -> ArchiveJobV1:
    try:
        return ArchiveJobV1(
            source_manifest_sha256=str(row["source_manifest_sha256"]),
            artifact_role=str(row["artifact_role"]),
            artifact_relative_path=str(row["artifact_relative_path"]),
            artifact_sha256=str(row["artifact_sha256"]),
            target_id=str(row["target_id"]),
            policy_sha256=str(row["policy_sha256"]),
            generation=int(row["generation"]),
            target_required=bool(row["target_required"]),
            state=ArchiveJobState(str(row["state"])),
            attempt=int(row["attempt"]),
            retry_at_ns=(
                None if row["retry_at_ns"] is None else int(row["retry_at_ns"])
            ),
            workflow_checkpoint=WorkflowCheckpoint(str(row["workflow_checkpoint"])),
            multipart_upload_id=(
                None
                if row["multipart_upload_id"] is None
                else str(row["multipart_upload_id"])
            ),
            multipart_parts=_parts_from_bytes(bytes(row["multipart_parts_json"])),
            staging_path=(
                None if row["staging_path"] is None else str(row["staging_path"])
            ),
            data_key=str(row["data_key"]),
            source_manifest_key=str(row["source_manifest_key"]),
            receipt_key=str(row["receipt_key"]),
            stored_sha256=(
                None if row["stored_sha256"] is None else str(row["stored_sha256"])
            ),
            stored_size=(
                None if row["stored_size"] is None else int(row["stored_size"])
            ),
            provider_checksum_json=(
                None
                if row["provider_checksum_json"] is None
                else bytes(row["provider_checksum_json"])
            ),
            verification_json=(
                None
                if row["verification_json"] is None
                else bytes(row["verification_json"])
            ),
            error_class=(
                None if row["error_class"] is None else str(row["error_class"])
            ),
            updated_at_ns=int(row["updated_at_ns"]),
        )
    except (ValidationError, ValueError) as error:
        raise ArchiveStateError("archive job row is invalid") from error


def _key_parameters(key: ArchiveJobKey) -> tuple[str, str, str, str, str]:
    if type(key) is not ArchiveJobKey:
        raise TypeError("key must be ArchiveJobKey")
    return (
        key.source_manifest_sha256,
        key.artifact_role,
        key.artifact_sha256,
        key.target_id,
        key.policy_sha256,
    )


class ArchiveState:
    __slots__ = (
        "_archive_root",
        "_clock_ns",
        "_connection",
        "_data_root",
        "_future_config",
        "path",
    )

    def __init__(
        self,
        path: Path,
        connection: sqlite3.Connection,
        *,
        archive_root: Path,
        data_root: Path | None,
        clock_ns: Callable[[], int],
    ) -> None:
        self.path = path
        self._connection: sqlite3.Connection | None = connection
        self._archive_root = archive_root
        self._data_root = data_root
        self._clock_ns = clock_ns
        self._future_config: ArchiveConfig | None = None

    @classmethod
    def open(
        cls,
        path: str | Path,
        *,
        data_root: str | Path | None = None,
        rebuild: bool = False,
        clock_ns: Callable[[], int] = time.time_ns,
    ) -> ArchiveState:
        candidate = Path(path)
        if not candidate.name or candidate.name in {".", ".."}:
            raise ValueError("archive state path must name a SQLite file")
        absolute = Path(os.path.abspath(os.fspath(candidate)))
        _ensure_directory(absolute.parent)
        database_existed = _path_entry_exists(absolute)
        if database_existed:
            observed_database = absolute.lstat()
            if not stat.S_ISREG(observed_database.st_mode) or stat.S_ISLNK(
                observed_database.st_mode
            ):
                raise ArchiveStateError(
                    "archive SQLite path must be a real regular file"
                )
        root = (
            None
            if data_root is None
            else Path(os.path.abspath(os.fspath(Path(data_root))))
        )
        if not callable(clock_ns):
            raise TypeError("clock_ns must be callable")
        connection = sqlite3.connect(
            absolute,
            isolation_level=None,
            timeout=5.0,
        )
        connection.row_factory = sqlite3.Row
        try:
            _initialize_schema(connection)
            observed_database = absolute.lstat()
            if not stat.S_ISREG(observed_database.st_mode) or stat.S_ISLNK(
                observed_database.st_mode
            ):
                raise ArchiveStateError(
                    "archive SQLite path must remain a real regular file"
                )
            if not database_existed:
                _fsync_directory(absolute.parent)
            state = cls(
                absolute,
                connection,
                archive_root=absolute.parent,
                data_root=root,
                clock_ns=clock_ns,
            )
            if rebuild:
                state._clear_cache()
            state._reconcile_durable_facts()
            return state
        except BaseException:
            connection.close()
            raise

    def _require_connection(self) -> sqlite3.Connection:
        connection = self._connection
        if connection is None:
            raise ArchiveStateError("archive state is closed")
        return connection

    @contextmanager
    def _transaction(
        self,
        *,
        poison_if: Callable[[], bool] | None = None,
    ) -> Iterator[sqlite3.Connection]:
        connection = self._require_connection()
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            with suppress(sqlite3.Error):
                connection.rollback()
            if poison_if is not None and poison_if():
                self._poison_connection(connection)
            raise
        else:
            try:
                connection.commit()
            except BaseException:
                with suppress(sqlite3.Error):
                    connection.rollback()
                if poison_if is not None and poison_if():
                    self._poison_connection(connection)
                raise

    def _poison_connection(self, connection: sqlite3.Connection) -> None:
        if self._connection is connection:
            self._connection = None
        with suppress(sqlite3.Error):
            connection.close()

    def _clear_cache(self) -> None:
        with self._transaction() as connection:
            connection.execute("DELETE FROM archive_policy_migration")
            connection.execute("DELETE FROM archive_generation_job")
            connection.execute("DELETE FROM archive_job")
            connection.execute("DELETE FROM archive_source_generation")
            connection.execute("DELETE FROM archive_source")
            connection.execute("DELETE FROM archive_policy")

    @property
    def policies_root(self) -> Path:
        return self._archive_root / "policies"

    @property
    def sources_root(self) -> Path:
        return self._archive_root / "sources"

    def _policy_path(self, policy_sha256: str) -> Path:
        return self.policies_root / f"{policy_sha256}.json"

    def _source_root(self, source_sha256: str) -> Path:
        return self.sources_root / source_sha256

    def _generation_path(self, source_sha256: str, generation: int) -> Path:
        return self._source_root(source_sha256) / f"generation-{generation}.json"

    def _active_path(self, source_sha256: str) -> Path:
        return self._source_root(source_sha256) / "active.json"

    def _tombstone_path(self, source_sha256: str) -> Path:
        return (
            self._archive_root
            / "cleanup-tombstones"
            / f"{source_sha256}.tombstone.json"
        )

    def _cleanup_intent_path(self, source_sha256: str) -> Path:
        return self._archive_root / "cleanup-intents" / f"{source_sha256}.intent.json"

    def _publish_policy(self, policy: ArchivePolicyV1) -> None:
        _publish_immutable(
            self._policy_path(policy.policy_sha256),
            policy.canonical_bytes(),
        )

    def _publish_generation(self, fact: ArchiveSourceGenerationFactV1) -> None:
        _publish_immutable(
            self._generation_path(fact.source.source_manifest_sha256, fact.generation),
            fact.canonical_bytes(),
        )

    def _activate_generation(self, fact: ArchiveSourceGenerationFactV1) -> None:
        pointer = ActiveGenerationPointerV1(
            generation=fact.generation,
            generation_fact_sha256=fact.generation_fact_sha256,
        )
        _replace_pointer(
            self._active_path(fact.source.source_manifest_sha256),
            pointer.canonical_bytes(),
        )

    def _insert_policy(
        self,
        connection: sqlite3.Connection,
        policy: ArchivePolicyV1,
    ) -> None:
        canonical = policy.canonical_bytes()
        row = connection.execute(
            "SELECT canonical_json FROM archive_policy WHERE policy_sha256 = ?",
            (policy.policy_sha256,),
        ).fetchone()
        if row is not None:
            if bytes(row["canonical_json"]) != canonical:
                raise ArchiveStateError("SQLite policy hash collision")
            return
        connection.execute(
            "INSERT INTO archive_policy(policy_sha256, canonical_json) VALUES (?, ?)",
            (policy.policy_sha256, canonical),
        )

    def _insert_generation(
        self,
        connection: sqlite3.Connection,
        *,
        policy: ArchivePolicyV1,
        fact: ArchiveSourceGenerationFactV1,
        active: bool,
    ) -> None:
        if fact.policy_sha256 != policy.policy_sha256:
            raise ArchiveStateError("generation references the wrong policy")
        if fact.required_target_ids != policy.required_target_ids:
            raise ArchiveStateError("generation required target set is inconsistent")
        expected_optional = tuple(
            target.target_id for target in policy.targets if not target.required
        )
        if fact.optional_target_ids != expected_optional:
            raise ArchiveStateError("generation optional target set is inconsistent")
        expected_jobs = _generation_jobs(fact.source, policy)
        if fact.jobs != expected_jobs:
            raise ArchiveStateError("generation job facts are inconsistent")
        source_json = _source_bytes(fact.source)
        source_sha = fact.source.source_manifest_sha256
        existing_source = connection.execute(
            "SELECT source_json FROM archive_source WHERE source_manifest_sha256 = ?",
            (source_sha,),
        ).fetchone()
        if existing_source is None:
            connection.execute(
                """
                INSERT INTO archive_source(
                    source_manifest_sha256, source_json,
                    active_generation, active_policy_sha256
                ) VALUES (?, ?, ?, ?)
                """,
                (source_sha, source_json, fact.generation, fact.policy_sha256),
            )
        elif bytes(existing_source["source_json"]) != source_json:
            raise ArchiveStateError("source manifest identity conflict")

        fact_json = fact.canonical_bytes()
        existing_generation = connection.execute(
            """
            SELECT policy_sha256, generation_fact_sha256, canonical_json
              FROM archive_source_generation
             WHERE source_manifest_sha256 = ? AND generation = ?
            """,
            (source_sha, fact.generation),
        ).fetchone()
        if existing_generation is None:
            connection.execute(
                """
                INSERT INTO archive_source_generation(
                    source_manifest_sha256, generation, policy_sha256,
                    generation_fact_sha256, canonical_json, active
                ) VALUES (?, ?, ?, ?, ?, 0)
                """,
                (
                    source_sha,
                    fact.generation,
                    fact.policy_sha256,
                    fact.generation_fact_sha256,
                    fact_json,
                ),
            )
        elif (
            str(existing_generation["policy_sha256"]) != fact.policy_sha256
            or str(existing_generation["generation_fact_sha256"])
            != fact.generation_fact_sha256
            or bytes(existing_generation["canonical_json"]) != fact_json
        ):
            raise ArchiveStateError("source generation identity conflict")

        now_ns = self._now_ns()
        for job in fact.jobs:
            connection.execute(
                """
                INSERT OR IGNORE INTO archive_job(
                    source_manifest_sha256, artifact_role,
                    artifact_relative_path, artifact_sha256,
                    target_id, policy_sha256, generation, target_required,
                    state, attempt, retry_at_ns, workflow_checkpoint,
                    multipart_upload_id, multipart_parts_json, staging_path,
                    data_key, source_manifest_key, receipt_key,
                    stored_sha256, stored_size, provider_checksum_json,
                    verification_json, error_class, updated_at_ns
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, 'DISCOVERED', 0, NULL, 'source',
                    NULL, ?, NULL, ?, ?, ?, NULL, NULL, NULL, NULL, NULL, ?
                )
                """,
                (
                    source_sha,
                    job.artifact_role,
                    job.artifact_relative_path,
                    job.artifact_sha256,
                    job.target_id,
                    fact.policy_sha256,
                    fact.generation,
                    int(job.target_required),
                    _parts_bytes(()),
                    job.data_key,
                    job.source_manifest_key,
                    job.receipt_key,
                    now_ns,
                ),
            )
            existing_job = connection.execute(
                """
                SELECT artifact_relative_path, generation, target_required,
                       data_key, source_manifest_key, receipt_key
                  FROM archive_job
                 WHERE source_manifest_sha256 = ?
                   AND artifact_role = ? AND artifact_sha256 = ?
                   AND target_id = ? AND policy_sha256 = ?
                """,
                (
                    source_sha,
                    job.artifact_role,
                    job.artifact_sha256,
                    job.target_id,
                    fact.policy_sha256,
                ),
            ).fetchone()
            if existing_job is None or (
                str(existing_job["artifact_relative_path"])
                != job.artifact_relative_path
                or int(existing_job["generation"]) > fact.generation
                or bool(existing_job["target_required"]) != job.target_required
                or str(existing_job["data_key"]) != job.data_key
                or str(existing_job["source_manifest_key"]) != job.source_manifest_key
                or str(existing_job["receipt_key"]) != job.receipt_key
            ):
                raise ArchiveStateError("cached immutable job identity is inconsistent")
            connection.execute(
                """
                INSERT OR IGNORE INTO archive_generation_job(
                    source_manifest_sha256, generation, artifact_role,
                    artifact_sha256, target_id, policy_sha256
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    source_sha,
                    fact.generation,
                    job.artifact_role,
                    job.artifact_sha256,
                    job.target_id,
                    fact.policy_sha256,
                ),
            )
        expected_associations = tuple(
            (
                job.artifact_role,
                job.artifact_sha256,
                job.target_id,
                fact.policy_sha256,
            )
            for job in fact.jobs
        )
        observed_associations = tuple(
            tuple(str(value) for value in row)
            for row in connection.execute(
                """
                SELECT artifact_role, artifact_sha256, target_id, policy_sha256
                  FROM archive_generation_job
                 WHERE source_manifest_sha256 = ? AND generation = ?
                 ORDER BY artifact_role, artifact_sha256, target_id, policy_sha256
                """,
                (source_sha, fact.generation),
            ).fetchall()
        )
        if observed_associations != expected_associations:
            raise ArchiveStateError(
                "cached generation-job associations are inconsistent"
            )
        if active:
            connection.execute(
                "UPDATE archive_source_generation SET active = 0 WHERE source_manifest_sha256 = ?",
                (source_sha,),
            )
            connection.execute(
                """
                UPDATE archive_source_generation
                   SET active = 1
                 WHERE source_manifest_sha256 = ? AND generation = ?
                """,
                (source_sha, fact.generation),
            )
            connection.execute(
                """
                UPDATE archive_source
                   SET active_generation = ?, active_policy_sha256 = ?
                 WHERE source_manifest_sha256 = ?
                """,
                (fact.generation, fact.policy_sha256, source_sha),
            )

    def _now_ns(self) -> int:
        value = self._clock_ns()
        if type(value) is not int or value < 0 or value > _MAX_NS:
            raise ArchiveStateError("archive clock returned an invalid time")
        return value

    def _load_all_policy_facts(self) -> dict[str, ArchivePolicyV1]:
        if not self.policies_root.exists():
            return {}
        if self.policies_root.is_symlink() or not self.policies_root.is_dir():
            raise ArchiveStateError("archive policies root is not a directory")
        policies: dict[str, ArchivePolicyV1] = {}
        for path in sorted(self.policies_root.iterdir(), key=lambda item: item.name):
            if path.name.startswith(".") and path.name.endswith(".tmp"):
                continue
            if not path.name.endswith(".json"):
                raise ArchiveStateError(f"unexpected archive policy fact: {path}")
            try:
                policy = load_policy_bytes(_read_regular(path))
            except ArchivePolicyError as error:
                raise ArchiveStateError(
                    f"invalid archive policy fact: {path}"
                ) from error
            if path.name != f"{policy.policy_sha256}.json":
                raise ArchiveStateError(
                    "archive policy filename does not match its hash"
                )
            policies[policy.policy_sha256] = policy
        return policies

    def _load_source_facts(
        self,
    ) -> tuple[tuple[ArchiveSourceGenerationFactV1, ...], dict[str, int]]:
        if not self.sources_root.exists():
            return (), {}
        if self.sources_root.is_symlink() or not self.sources_root.is_dir():
            raise ArchiveStateError("archive sources root is not a directory")
        facts: list[ArchiveSourceGenerationFactV1] = []
        active: dict[str, int] = {}
        for source_root in sorted(
            self.sources_root.iterdir(), key=lambda item: item.name
        ):
            if source_root.is_symlink() or not source_root.is_dir():
                raise ArchiveStateError(
                    f"invalid archive source fact root: {source_root}"
                )
            if len(source_root.name) != 64 or any(
                character not in "0123456789abcdef" for character in source_root.name
            ):
                raise ArchiveStateError(
                    f"invalid archive source fact identity: {source_root}"
                )
            active_path = source_root / "active.json"
            pointer: ActiveGenerationPointerV1 | None = None
            if _path_entry_exists(active_path):
                if not active_path.is_file() or active_path.is_symlink():
                    raise ArchiveStateError(
                        f"archive source active pointer is invalid: {source_root}"
                    )
                pointer = _load_pointer_bytes(_read_regular(active_path))
            source_facts: dict[int, ArchiveSourceGenerationFactV1] = {}
            generation_paths: list[Path] = []
            for path in sorted(source_root.iterdir(), key=lambda item: item.name):
                if path.name == "active.json":
                    continue
                if path.name.startswith(".") and path.name.endswith(".tmp"):
                    continue
                if not (
                    path.name.startswith("generation-") and path.name.endswith(".json")
                ):
                    raise ArchiveStateError(
                        f"unexpected archive source generation fact: {path}"
                    )
                generation_paths.append(path)
            for path in generation_paths:
                fact = _load_generation_bytes(_read_regular(path))
                expected_name = f"generation-{fact.generation}.json"
                if path.name != expected_name:
                    raise ArchiveStateError("generation filename does not match fact")
                if fact.source.source_manifest_sha256 != source_root.name:
                    raise ArchiveStateError("generation source directory is mismatched")
                if fact.generation in source_facts:
                    raise ArchiveStateError("duplicate source generation fact")
                source_facts[fact.generation] = fact
            if not source_facts:
                if pointer is not None:
                    raise ArchiveStateError("archive source has no generation facts")
                continue
            generations = tuple(sorted(source_facts))
            if generations != tuple(range(1, generations[-1] + 1)):
                raise ArchiveStateError("archive source generation chain is incomplete")
            first_source = source_facts[1].source
            for generation in generations:
                fact = source_facts[generation]
                if fact.source != first_source:
                    raise ArchiveStateError(
                        "archive source generation chain changed source"
                    )
                if generation > 1:
                    predecessor = source_facts[generation - 1]
                    if (
                        fact.predecessor_generation_fact_sha256
                        != predecessor.generation_fact_sha256
                        or fact.previous_policy_sha256 != predecessor.policy_sha256
                    ):
                        raise ArchiveStateError(
                            "archive source generation chain predecessor is invalid"
                        )
                    self._reject_weaker_cleanup_facts(
                        predecessor.cleanup_facts,
                        fact.cleanup_facts,
                    )
                facts.append(fact)
            if pointer is None:
                if generations != (1,):
                    raise ArchiveStateError(
                        "archive source generation chain lacks active pointer"
                    )
                initial = source_facts[1]
                pointer = ActiveGenerationPointerV1(
                    generation=1,
                    generation_fact_sha256=initial.generation_fact_sha256,
                )
                _replace_pointer(active_path, pointer.canonical_bytes())
            selected = source_facts.get(pointer.generation)
            if selected is None or (
                selected.generation_fact_sha256 != pointer.generation_fact_sha256
            ):
                raise ArchiveStateError(
                    "active pointer does not bind a generation fact"
                )
            active[source_root.name] = pointer.generation
        return tuple(facts), active

    def _reconcile_durable_facts(self) -> None:
        policies = self._load_all_policy_facts()
        facts, active = self._load_source_facts()
        with self._transaction() as connection:
            for policy in policies.values():
                self._insert_policy(connection, policy)
            for fact in sorted(
                facts,
                key=lambda item: (
                    item.source.source_manifest_sha256,
                    item.generation,
                ),
            ):
                try:
                    policy = policies[fact.policy_sha256]
                except KeyError as error:
                    raise ArchiveStateError(
                        "source generation references a missing policy fact"
                    ) from error
                self._insert_generation(
                    connection,
                    policy=policy,
                    fact=fact,
                    active=(
                        active[fact.source.source_manifest_sha256] == fact.generation
                    ),
                )
            self._validate_cache_matches_facts(
                connection,
                policies=policies,
                facts=facts,
                active=active,
            )

    @staticmethod
    def _validate_cache_matches_facts(
        connection: sqlite3.Connection,
        *,
        policies: dict[str, ArchivePolicyV1],
        facts: tuple[ArchiveSourceGenerationFactV1, ...],
        active: dict[str, int],
    ) -> None:
        cached_policies = {
            str(row[0])
            for row in connection.execute(
                "SELECT policy_sha256 FROM archive_policy"
            ).fetchall()
        }
        if cached_policies != set(policies):
            raise ArchiveStateError("SQLite policy cache lacks matching durable facts")

        cached_sources = {
            str(row[0])
            for row in connection.execute(
                "SELECT source_manifest_sha256 FROM archive_source"
            ).fetchall()
        }
        if cached_sources != set(active):
            raise ArchiveStateError("SQLite source lacks matching durable source facts")

        expected_generations = {
            (
                fact.source.source_manifest_sha256,
                fact.generation,
                fact.generation_fact_sha256,
            )
            for fact in facts
        }
        cached_generations = {
            (str(row[0]), int(row[1]), str(row[2]))
            for row in connection.execute(
                """
                SELECT source_manifest_sha256, generation,
                       generation_fact_sha256
                  FROM archive_source_generation
                """
            ).fetchall()
        }
        if cached_generations != expected_generations:
            raise ArchiveStateError(
                "SQLite generation cache lacks matching durable facts"
            )

        expected_jobs: dict[
            tuple[str, str, str, str, str],
            tuple[str, str, str, str, str, str, int, int, str, str, str],
        ] = {}
        for fact in sorted(
            facts,
            key=lambda item: (
                item.source.source_manifest_sha256,
                item.generation,
            ),
        ):
            for job in fact.jobs:
                key = (
                    fact.source.source_manifest_sha256,
                    job.artifact_role,
                    job.artifact_sha256,
                    job.target_id,
                    fact.policy_sha256,
                )
                expected_jobs.setdefault(
                    key,
                    (
                        *key,
                        job.artifact_relative_path,
                        fact.generation,
                        int(job.target_required),
                        job.data_key,
                        job.source_manifest_key,
                        job.receipt_key,
                    ),
                )
        cached_jobs = {
            (
                str(row[0]),
                str(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
                int(row[6]),
                int(row[7]),
                str(row[8]),
                str(row[9]),
                str(row[10]),
            )
            for row in connection.execute(
                """
                SELECT source_manifest_sha256, artifact_role, artifact_sha256,
                       target_id, policy_sha256, artifact_relative_path,
                       generation, target_required, data_key,
                       source_manifest_key, receipt_key
                  FROM archive_job
                """
            ).fetchall()
        }
        if cached_jobs != set(expected_jobs.values()):
            raise ArchiveStateError(
                "SQLite immutable job cache lacks matching durable facts"
            )

        expected_associations = {
            (
                fact.source.source_manifest_sha256,
                fact.generation,
                job.artifact_role,
                job.artifact_sha256,
                job.target_id,
                fact.policy_sha256,
            )
            for fact in facts
            for job in fact.jobs
        }
        cached_associations = {
            (
                str(row[0]),
                int(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
            )
            for row in connection.execute(
                """
                SELECT source_manifest_sha256, generation, artifact_role,
                       artifact_sha256, target_id, policy_sha256
                  FROM archive_generation_job
                """
            ).fetchall()
        }
        if cached_associations != expected_associations:
            raise ArchiveStateError(
                "SQLite generation-job cache lacks matching durable facts"
            )

    def discover(
        self,
        source: ArchiveSourceManifestV1,
        *,
        cleanup_gates: CleanupGatePolicyV1,
        policy: ArchivePolicyV1 | None = None,
    ) -> ArchiveDiscoveryV1:
        if type(source) is not ArchiveSourceManifestV1:
            raise TypeError("source must be ArchiveSourceManifestV1")
        try:
            source = validate_source_manifest(source)
        except ValidationError as error:
            raise ArchiveStateError("source manifest is invalid") from error
        if type(cleanup_gates) is not CleanupGatePolicyV1:
            raise TypeError("cleanup_gates must be CleanupGatePolicyV1")
        if policy is None:
            if self._future_config is None:
                raise ArchiveStateError(
                    "discover requires a policy or a reloaded archive config"
                )
            policy = freeze_policy(config=self._future_config)
        elif type(policy) is not ArchivePolicyV1:
            raise TypeError("policy must be ArchivePolicyV1 or None")
        source_sha = source.source_manifest_sha256
        activation_attempted = False
        with self._transaction(poison_if=lambda: activation_attempted) as connection:
            existing = connection.execute(
                """
                SELECT source_json, active_generation, active_policy_sha256
                  FROM archive_source
                 WHERE source_manifest_sha256 = ?
                """,
                (source_sha,),
            ).fetchone()
            if existing is not None:
                if bytes(existing["source_json"]) != _source_bytes(source):
                    raise ArchiveStateError("source manifest identity conflict")
                generation = int(existing["active_generation"])
                policy_sha = str(existing["active_policy_sha256"])
                keys = self._job_keys_for_generation(
                    connection,
                    source_sha,
                    generation,
                )
                return ArchiveDiscoveryV1(
                    source_sha=source_sha,
                    generation=generation,
                    policy_sha256=policy_sha,
                    job_keys=keys,
                )

            jobs = _generation_jobs(source, policy)
            cleanup = _cleanup_facts(source, cleanup_gates)
            fact = build_generation_fact(
                source=source,
                generation=1,
                policy_sha256=policy.policy_sha256,
                previous_policy_sha256=None,
                predecessor_generation_fact_sha256=None,
                migration_reason=None,
                required_target_ids=policy.required_target_ids,
                optional_target_ids=tuple(
                    target.target_id for target in policy.targets if not target.required
                ),
                cleanup_facts=cleanup,
                jobs=jobs,
            )
            self._publish_policy(policy)
            self._publish_generation(fact)
            activation_attempted = True
            self._activate_generation(fact)
            self._insert_policy(connection, policy)
            self._insert_generation(
                connection,
                policy=policy,
                fact=fact,
                active=True,
            )
            return ArchiveDiscoveryV1(
                source_sha=source_sha,
                generation=1,
                policy_sha256=policy.policy_sha256,
                job_keys=tuple(
                    ArchiveJobKey(
                        source_manifest_sha256=source_sha,
                        artifact_role=job.artifact_role,
                        artifact_sha256=job.artifact_sha256,
                        target_id=job.target_id,
                        policy_sha256=policy.policy_sha256,
                    )
                    for job in jobs
                ),
            )

    def _job_keys_for_generation(
        self,
        connection: sqlite3.Connection,
        source_sha: str,
        generation: int,
    ) -> tuple[ArchiveJobKey, ...]:
        rows = connection.execute(
            """
            SELECT source_manifest_sha256, artifact_role, artifact_sha256,
                   target_id, policy_sha256
              FROM archive_generation_job
             WHERE source_manifest_sha256 = ? AND generation = ?
             ORDER BY artifact_role, artifact_sha256, target_id
            """,
            (source_sha, generation),
        ).fetchall()
        return tuple(
            ArchiveJobKey(
                source_manifest_sha256=str(row["source_manifest_sha256"]),
                artifact_role=str(row["artifact_role"]),
                artifact_sha256=str(row["artifact_sha256"]),
                target_id=str(row["target_id"]),
                policy_sha256=str(row["policy_sha256"]),
            )
            for row in rows
        )

    def reload_config(self, config: ArchiveConfig) -> None:
        if type(config) is not ArchiveConfig:
            raise TypeError("config must be ArchiveConfig")
        self._future_config = config

    def policy_for(self, source_manifest_sha256: str) -> ArchivePolicyV1:
        connection = self._require_connection()
        row = connection.execute(
            """
            SELECT p.canonical_json
              FROM archive_source AS s
              JOIN archive_policy AS p
                ON p.policy_sha256 = s.active_policy_sha256
             WHERE s.source_manifest_sha256 = ?
            """,
            (source_manifest_sha256,),
        ).fetchone()
        if row is None:
            raise KeyError(source_manifest_sha256)
        try:
            return load_policy_bytes(bytes(row["canonical_json"]))
        except ArchivePolicyError as error:
            raise ArchiveStateError("cached archive policy is invalid") from error

    def jobs(self) -> tuple[ArchiveJobV1, ...]:
        rows = (
            self._require_connection()
            .execute(
                """
            SELECT * FROM archive_job
             ORDER BY source_manifest_sha256, generation,
                      artifact_role, artifact_sha256, target_id
            """
            )
            .fetchall()
        )
        return tuple(_job_from_row(row) for row in rows)

    def job(self, key: ArchiveJobKey) -> ArchiveJobV1:
        row = (
            self._require_connection()
            .execute(
                """
            SELECT * FROM archive_job
             WHERE source_manifest_sha256 = ?
               AND artifact_role = ? AND artifact_sha256 = ?
               AND target_id = ? AND policy_sha256 = ?
            """,
                _key_parameters(key),
            )
            .fetchone()
        )
        if row is None:
            raise KeyError(key)
        return _job_from_row(row)

    def due_jobs(self, *, now_ns: int) -> tuple[ArchiveJobV1, ...]:
        if type(now_ns) is not int or now_ns < 0 or now_ns > _MAX_NS:
            raise ValueError("now_ns must be a nonnegative signed int64")
        placeholders = ",".join("?" for _ in _ACTIVE_STATES)
        rows = (
            self._require_connection()
            .execute(
                f"""
            SELECT j.*
              FROM archive_source_generation AS g
              JOIN archive_generation_job AS gj
                ON gj.source_manifest_sha256 = g.source_manifest_sha256
               AND gj.generation = g.generation
              JOIN archive_job AS j
                ON j.source_manifest_sha256 = gj.source_manifest_sha256
               AND j.artifact_role = gj.artifact_role
               AND j.artifact_sha256 = gj.artifact_sha256
               AND j.target_id = gj.target_id
               AND j.policy_sha256 = gj.policy_sha256
             WHERE g.active = 1
               AND j.state IN ({placeholders})
               AND (j.state <> 'RETRYING' OR j.retry_at_ns <= ?)
             ORDER BY COALESCE(j.retry_at_ns, 0), j.updated_at_ns,
                      j.source_manifest_sha256, j.artifact_role,
                      j.artifact_sha256, j.target_id
            """,
                (*_ACTIVE_STATES, now_ns),
            )
            .fetchall()
        )
        return tuple(_job_from_row(row) for row in rows)

    def transition(
        self,
        key: ArchiveJobKey,
        new: ArchiveJobState | str,
        *,
        workflow_checkpoint: WorkflowCheckpoint | str | None = None,
    ) -> ArchiveJobV1:
        new_state = _job_state(new)
        if new_state is ArchiveJobState.RETRYING:
            raise InvalidArchiveTransition("use record_retry for RETRYING")
        with self._transaction() as connection:
            current = self._job_in_transaction(
                connection,
                key,
                require_active=True,
            )
            ArchiveTransition.validate(
                current.state,
                new_state,
                target_required=current.target_required,
            )
            checkpoint = (
                current.workflow_checkpoint
                if workflow_checkpoint is None
                else _checkpoint(workflow_checkpoint)
            )
            self._validate_checkpoint_progress(current.workflow_checkpoint, checkpoint)
            self._validate_transition_checkpoint(
                current,
                new_state=new_state,
                checkpoint=checkpoint,
            )
            verification_json = (
                None
                if new_state is ArchiveJobState.VERIFYING
                else current.verification_json
            )
            completed_upload = (
                current.state is ArchiveJobState.VERIFYING
                and new_state in {ArchiveJobState.UPLOADING, ArchiveJobState.COMMITTED}
            )
            multipart_upload_id = (
                None if completed_upload else current.multipart_upload_id
            )
            multipart_parts = () if completed_upload else current.multipart_parts
            staging_path = None if completed_upload else current.staging_path
            connection.execute(
                """
                UPDATE archive_job
                   SET state = ?, workflow_checkpoint = ?, retry_at_ns = NULL,
                       multipart_upload_id = ?, multipart_parts_json = ?,
                       staging_path = ?, verification_json = ?,
                       error_class = NULL, updated_at_ns = ?
                 WHERE source_manifest_sha256 = ?
                   AND artifact_role = ? AND artifact_sha256 = ?
                   AND target_id = ? AND policy_sha256 = ?
                """,
                (
                    new_state.value,
                    checkpoint.value,
                    multipart_upload_id,
                    _parts_bytes(multipart_parts),
                    staging_path,
                    verification_json,
                    self._now_ns(),
                    *_key_parameters(key),
                ),
            )
            return self._job_in_transaction(connection, key)

    @staticmethod
    def _validate_checkpoint_progress(
        old: WorkflowCheckpoint,
        new: WorkflowCheckpoint,
    ) -> None:
        if WORKFLOW_CHECKPOINT_ORDER[new] < WORKFLOW_CHECKPOINT_ORDER[old]:
            raise ArchiveStateError("workflow checkpoint cannot regress")

    @staticmethod
    def _validate_transition_checkpoint(
        current: ArchiveJobV1,
        *,
        new_state: ArchiveJobState,
        checkpoint: WorkflowCheckpoint,
    ) -> None:
        if (
            current.state
            in {
                ArchiveJobState.DISCOVERED,
                ArchiveJobState.QUEUED,
            }
            and checkpoint is not WorkflowCheckpoint.SOURCE
        ):
            raise InvalidArchiveTransition(
                "new archive work must begin from the source checkpoint"
            )
        if new_state is ArchiveJobState.VERIFYING:
            expected = {
                WorkflowCheckpoint.SOURCE: WorkflowCheckpoint.DATA_UPLOADED,
                WorkflowCheckpoint.STORED: WorkflowCheckpoint.DATA_UPLOADED,
                WorkflowCheckpoint.DATA_VERIFIED: (
                    WorkflowCheckpoint.SOURCE_MANIFEST_UPLOADED
                ),
                WorkflowCheckpoint.SOURCE_MANIFEST_VERIFIED: (
                    WorkflowCheckpoint.RECEIPT_PUBLISHED
                ),
            }.get(current.workflow_checkpoint)
            if checkpoint is not expected:
                raise InvalidArchiveTransition(
                    "VERIFYING requires the next uploaded workflow checkpoint"
                )
            return
        if current.state is ArchiveJobState.VERIFYING:
            if current.verification_json is None:
                raise InvalidArchiveTransition(
                    "VERIFYING cannot advance without verification evidence"
                )
            if new_state is ArchiveJobState.UPLOADING:
                expected = {
                    WorkflowCheckpoint.DATA_UPLOADED: (
                        WorkflowCheckpoint.DATA_VERIFIED
                    ),
                    WorkflowCheckpoint.SOURCE_MANIFEST_UPLOADED: (
                        WorkflowCheckpoint.SOURCE_MANIFEST_VERIFIED
                    ),
                }.get(current.workflow_checkpoint)
                if checkpoint is not expected:
                    raise InvalidArchiveTransition(
                        "verified upload requires the next verified checkpoint"
                    )
                return
            if new_state is ArchiveJobState.COMMITTED and (
                current.workflow_checkpoint is not WorkflowCheckpoint.RECEIPT_PUBLISHED
                or checkpoint is not WorkflowCheckpoint.RECEIPT_PUBLISHED
                or current.stored_sha256 is None
            ):
                raise InvalidArchiveTransition(
                    "COMMITTED requires stored identity and verified receipt checkpoint"
                )
        if current.state is ArchiveJobState.TRANSFORMING and (
            new_state is ArchiveJobState.UPLOADING
        ):
            raise InvalidArchiveTransition(
                "TRANSFORMING must persist its transform result before upload"
            )

    @staticmethod
    def _validate_retry_checkpoint(
        current: ArchiveJobV1,
        checkpoint: WorkflowCheckpoint,
    ) -> None:
        allowed = {current.workflow_checkpoint}
        if current.state is ArchiveJobState.UPLOADING:
            uploaded = {
                WorkflowCheckpoint.SOURCE: WorkflowCheckpoint.DATA_UPLOADED,
                WorkflowCheckpoint.STORED: WorkflowCheckpoint.DATA_UPLOADED,
                WorkflowCheckpoint.DATA_VERIFIED: (
                    WorkflowCheckpoint.SOURCE_MANIFEST_UPLOADED
                ),
                WorkflowCheckpoint.SOURCE_MANIFEST_VERIFIED: (
                    WorkflowCheckpoint.RECEIPT_PUBLISHED
                ),
            }.get(current.workflow_checkpoint)
            if uploaded is not None:
                allowed.add(uploaded)
        if checkpoint not in allowed:
            raise ArchiveStateError(
                "retry checkpoint is not reachable from the current job state"
            )

    def record_transform_result(
        self,
        key: ArchiveJobKey,
        *,
        staging_path: str,
        stored_sha256: str,
        stored_size: int,
    ) -> ArchiveJobV1:
        if type(staging_path) is not str or not staging_path or "\x00" in staging_path:
            raise ValueError("staging_path must be a nonempty absolute path")
        path = Path(staging_path)
        if not path.is_absolute() or os.path.abspath(staging_path) != staging_path:
            raise ValueError("staging_path must be a normalized absolute path")
        if type(stored_sha256) is not str:
            raise TypeError("stored_sha256 must be a string")
        if type(stored_size) is not int or stored_size <= 0:
            raise ValueError("stored_size must be a positive integer")
        try:
            observed = _hash_regular(path)
        except OSError as error:
            raise ArchiveStateError("stored staging artifact is unavailable") from error
        if observed != (stored_size, stored_sha256):
            raise ArchiveStateError("stored staging artifact identity does not match")
        with self._transaction() as connection:
            current = self._job_in_transaction(
                connection,
                key,
                require_active=True,
            )
            if (
                current.state is not ArchiveJobState.TRANSFORMING
                or current.workflow_checkpoint is not WorkflowCheckpoint.SOURCE
            ):
                raise InvalidArchiveTransition(
                    "transform result requires TRANSFORMING at source checkpoint"
                )
            connection.execute(
                """
                UPDATE archive_job
                   SET state = 'UPLOADING', workflow_checkpoint = 'stored',
                       staging_path = ?, stored_sha256 = ?, stored_size = ?,
                       multipart_upload_id = NULL, multipart_parts_json = ?,
                       verification_json = NULL, retry_at_ns = NULL,
                       error_class = NULL, updated_at_ns = ?
                 WHERE source_manifest_sha256 = ?
                   AND artifact_role = ? AND artifact_sha256 = ?
                   AND target_id = ? AND policy_sha256 = ?
                """,
                (
                    staging_path,
                    stored_sha256,
                    stored_size,
                    _parts_bytes(()),
                    self._now_ns(),
                    *_key_parameters(key),
                ),
            )
            return self._job_in_transaction(connection, key)

    def record_verification(
        self,
        key: ArchiveJobKey,
        *,
        stored_sha256: str,
        stored_size: int,
        provider_checksum_json: bytes | None,
        verification_json: bytes,
        staging_path: str | None = None,
    ) -> ArchiveJobV1:
        if type(stored_sha256) is not str:
            raise TypeError("stored_sha256 must be a string")
        if type(stored_size) is not int or stored_size < 0:
            raise ValueError("stored_size must be a nonnegative integer")
        if staging_path is not None and (
            type(staging_path) is not str or not staging_path
        ):
            raise ValueError("staging_path must be a nonempty string or None")
        provider = (
            None
            if provider_checksum_json is None
            else _canonical_document(
                provider_checksum_json,
                field_name="provider_checksum_json",
            )
        )
        verification = _canonical_document(
            verification_json,
            field_name="verification_json",
        )
        with self._transaction() as connection:
            current = self._job_in_transaction(
                connection,
                key,
                require_active=True,
            )
            if current.state is not ArchiveJobState.VERIFYING:
                raise InvalidArchiveTransition(
                    "verification evidence requires a VERIFYING job"
                )
            if current.workflow_checkpoint not in {
                WorkflowCheckpoint.DATA_UPLOADED,
                WorkflowCheckpoint.SOURCE_MANIFEST_UPLOADED,
                WorkflowCheckpoint.RECEIPT_PUBLISHED,
            }:
                raise InvalidArchiveTransition(
                    "verification evidence does not match an uploaded checkpoint"
                )
            if current.stored_sha256 is not None and (
                current.stored_sha256 != stored_sha256
                or current.stored_size != stored_size
            ):
                raise ArchiveStateError(
                    "verified stored identity differs from the transform result"
                )
            effective_staging_path = (
                current.staging_path if staging_path is None else staging_path
            )
            connection.execute(
                """
                UPDATE archive_job
                   SET stored_sha256 = ?, stored_size = ?,
                       provider_checksum_json = ?, verification_json = ?,
                       staging_path = ?, updated_at_ns = ?
                 WHERE source_manifest_sha256 = ?
                   AND artifact_role = ? AND artifact_sha256 = ?
                   AND target_id = ? AND policy_sha256 = ?
                """,
                (
                    stored_sha256,
                    stored_size,
                    provider,
                    verification,
                    effective_staging_path,
                    self._now_ns(),
                    *_key_parameters(key),
                ),
            )
            return self._job_in_transaction(connection, key)

    def _job_in_transaction(
        self,
        connection: sqlite3.Connection,
        key: ArchiveJobKey,
        *,
        require_active: bool = False,
    ) -> ArchiveJobV1:
        row = connection.execute(
            """
            SELECT * FROM archive_job
             WHERE source_manifest_sha256 = ?
               AND artifact_role = ? AND artifact_sha256 = ?
               AND target_id = ? AND policy_sha256 = ?
            """,
            _key_parameters(key),
        ).fetchone()
        if row is None:
            raise KeyError(key)
        if require_active:
            active = connection.execute(
                """
                SELECT 1
                  FROM archive_generation_job AS gj
                  JOIN archive_source_generation AS g
                    ON g.source_manifest_sha256 = gj.source_manifest_sha256
                   AND g.generation = gj.generation
                 WHERE gj.source_manifest_sha256 = ?
                   AND gj.artifact_role = ? AND gj.artifact_sha256 = ?
                   AND gj.target_id = ? AND gj.policy_sha256 = ?
                   AND g.active = 1
                 LIMIT 1
                """,
                _key_parameters(key),
            ).fetchone()
            if active is None:
                raise InvalidArchiveTransition(
                    "job is not referenced by the active generation"
                )
        return _job_from_row(row)

    def record_retry(
        self,
        key: ArchiveJobKey,
        *,
        retry_at_ns: int,
        attempt: int,
        workflow_checkpoint: WorkflowCheckpoint | str,
        multipart_upload_id: str | None,
        parts: Iterable[MultipartPartV1],
        error: RetryableTargetError,
    ) -> ArchiveJobV1:
        if type(retry_at_ns) is not int or not 0 <= retry_at_ns <= _MAX_NS:
            raise ValueError("retry_at_ns must be a nonnegative signed int64")
        if type(attempt) is not int or attempt <= 0:
            raise ValueError("attempt must be a positive integer")
        if not isinstance(error, RetryableTargetError):
            raise TypeError("error must be RetryableTargetError")
        checkpoint = _checkpoint(workflow_checkpoint)
        normalized_parts = tuple(parts)
        if any(type(part) is not MultipartPartV1 for part in normalized_parts):
            raise TypeError("parts must contain MultipartPartV1 values")
        part_numbers = tuple(part.part_number for part in normalized_parts)
        if part_numbers != tuple(sorted(part_numbers)) or len(set(part_numbers)) != len(
            part_numbers
        ):
            raise ArchiveStateError("multipart parts must be sorted and unique")
        if normalized_parts and not multipart_upload_id:
            raise ArchiveStateError("multipart parts require an upload ID")
        with self._transaction() as connection:
            current = self._job_in_transaction(
                connection,
                key,
                require_active=True,
            )
            ArchiveTransition.validate(
                current.state,
                ArchiveJobState.RETRYING,
                error=error,
                target_required=current.target_required,
            )
            if attempt <= current.attempt:
                raise ArchiveStateError("retry attempt must advance")
            self._validate_checkpoint_progress(current.workflow_checkpoint, checkpoint)
            self._validate_retry_checkpoint(current, checkpoint)
            verification_json = current.verification_json
            if checkpoint != current.workflow_checkpoint and checkpoint in {
                WorkflowCheckpoint.DATA_UPLOADED,
                WorkflowCheckpoint.SOURCE_MANIFEST_UPLOADED,
                WorkflowCheckpoint.RECEIPT_PUBLISHED,
            }:
                verification_json = None
            connection.execute(
                """
                UPDATE archive_job
                   SET state = 'RETRYING', attempt = ?, retry_at_ns = ?,
                       workflow_checkpoint = ?, multipart_upload_id = ?,
                       multipart_parts_json = ?, verification_json = ?,
                       error_class = ?, updated_at_ns = ?
                 WHERE source_manifest_sha256 = ?
                   AND artifact_role = ? AND artifact_sha256 = ?
                   AND target_id = ? AND policy_sha256 = ?
                """,
                (
                    attempt,
                    retry_at_ns,
                    checkpoint.value,
                    multipart_upload_id,
                    _parts_bytes(normalized_parts),
                    verification_json,
                    type(error).__name__,
                    self._now_ns(),
                    *_key_parameters(key),
                ),
            )
            return self._job_in_transaction(connection, key)

    def resume_retry(self, key: ArchiveJobKey, *, now_ns: int) -> ArchiveJobV1:
        if type(now_ns) is not int or not 0 <= now_ns <= _MAX_NS:
            raise ValueError("now_ns must be a nonnegative signed int64")
        with self._transaction() as connection:
            current = self._job_in_transaction(
                connection,
                key,
                require_active=True,
            )
            if current.state is not ArchiveJobState.RETRYING:
                raise InvalidArchiveTransition("only RETRYING jobs can resume")
            assert current.retry_at_ns is not None
            if current.retry_at_ns > now_ns:
                raise InvalidArchiveTransition("retry deadline has not arrived")
            resumed = ArchiveTransition.resume_target(
                current.state,
                checkpoint=current.workflow_checkpoint,
            )
            connection.execute(
                """
                UPDATE archive_job
                   SET state = ?, retry_at_ns = NULL,
                       error_class = NULL, updated_at_ns = ?
                 WHERE source_manifest_sha256 = ?
                   AND artifact_role = ? AND artifact_sha256 = ?
                   AND target_id = ? AND policy_sha256 = ?
                """,
                (resumed.value, self._now_ns(), *_key_parameters(key)),
            )
            return self._job_in_transaction(connection, key)

    def record_failure(
        self,
        key: ArchiveJobKey,
        error: ArchiveConflictError,
    ) -> ArchiveJobV1:
        if not isinstance(error, ArchiveConflictError):
            raise TypeError("error must be ArchiveConflictError")
        with self._transaction() as connection:
            current = self._job_in_transaction(
                connection,
                key,
                require_active=True,
            )
            if current.state in TERMINAL_JOB_STATES:
                raise InvalidArchiveTransition("terminal job cannot record a failure")
            if current.state not in ArchiveTransition._RETRYABLE_FROM:
                raise InvalidArchiveTransition(
                    "conflict can be recorded only from an active work state"
                )
            connection.execute(
                """
                UPDATE archive_job
                   SET state = 'TERMINAL_CONFLICT', retry_at_ns = NULL,
                       error_class = ?, updated_at_ns = ?
                 WHERE source_manifest_sha256 = ?
                   AND artifact_role = ? AND artifact_sha256 = ?
                   AND target_id = ? AND policy_sha256 = ?
                """,
                (type(error).__name__, self._now_ns(), *_key_parameters(key)),
            )
            return self._job_in_transaction(connection, key)

    def _active_fact(
        self,
        connection: sqlite3.Connection,
        source_sha: str,
    ) -> tuple[ArchivePolicyV1, ArchiveSourceGenerationFactV1]:
        row = connection.execute(
            """
            SELECT p.canonical_json AS policy_json,
                   g.canonical_json AS generation_json
              FROM archive_source AS s
              JOIN archive_policy AS p
                ON p.policy_sha256 = s.active_policy_sha256
              JOIN archive_source_generation AS g
                ON g.source_manifest_sha256 = s.source_manifest_sha256
               AND g.generation = s.active_generation
             WHERE s.source_manifest_sha256 = ?
            """,
            (source_sha,),
        ).fetchone()
        if row is None:
            raise KeyError(source_sha)
        try:
            policy = load_policy_bytes(bytes(row["policy_json"]))
        except ArchivePolicyError as error:
            raise ArchiveStateError("cached policy is invalid") from error
        fact = _load_generation_bytes(bytes(row["generation_json"]))
        return policy, fact

    def _validate_local_source(self, source: ArchiveSourceManifestV1) -> None:
        data_root = self._data_root
        if data_root is None:
            raise ArchiveStateError(
                "policy migration requires ArchiveState.open(..., data_root=...)"
            )
        expected = (
            (
                source.source_manifest_relative_path,
                source.source_manifest_size_bytes,
                source.source_manifest_sha256,
            ),
            *(
                (artifact.relative_path, artifact.size_bytes, artifact.sha256)
                for artifact in source.artifacts
            ),
        )
        for relative_path, expected_size, expected_sha in expected:
            path = data_root / relative_path
            try:
                observed_size, observed_sha = _hash_regular(path)
            except (FileNotFoundError, OSError) as error:
                raise ArchiveStateError(
                    f"local source is unavailable: {path}"
                ) from error
            if (observed_size, observed_sha) != (expected_size, expected_sha):
                raise ArchiveStateError(f"local source identity mismatch: {path}")

    @contextmanager
    def _shared_source_leases(
        self,
        source: ArchiveSourceManifestV1,
    ) -> Iterator[None]:
        data_root = self._data_root
        if data_root is None:
            raise ArchiveStateError(
                "policy migration requires ArchiveState.open(..., data_root=...)"
            )
        with ExitStack() as stack:
            try:
                for artifact in sorted(
                    source.artifacts,
                    key=lambda item: item.relative_path,
                ):
                    data_path = data_root / artifact.relative_path
                    stack.enter_context(
                        SourceLease.shared(_lease_path_for_artifact(source, data_path))
                    )
            except (OSError, ValueError) as error:
                raise ArchiveStateError(
                    "policy migration could not acquire source leases"
                ) from error
            yield

    @staticmethod
    def _reject_weaker_cleanup_facts(
        old: ArchiveCleanupFactsV1,
        new: ArchiveCleanupFactsV1,
    ) -> None:
        weakened = new.grace_deadline_ns < old.grace_deadline_ns
        if old.materializer_ack_required:
            weakened = weakened or not new.materializer_ack_required
            old_revision = old.revision_deadline_ns
            new_revision = new.revision_deadline_ns
            weakened = weakened or (
                old_revision is not None
                and (new_revision is None or new_revision < old_revision)
            )
        if weakened:
            raise ArchiveStateError(
                "policy migration cannot weaken cleanup grace or materializer gates"
            )

    def migrate_policy(
        self,
        source_manifest_sha256: str,
        *,
        from_policy_sha256: str,
        config: ArchiveConfig,
        cleanup_gates: CleanupGatePolicyV1,
        reason: str,
    ) -> ArchiveDiscoveryV1:
        old_policy, snapshot = self._active_fact(
            self._require_connection(),
            source_manifest_sha256,
        )
        if old_policy.policy_sha256 != from_policy_sha256:
            raise ArchiveStateError("from-policy is not the active policy")
        with self._shared_source_leases(snapshot.source):
            return self._migrate_policy_under_lease(
                source_manifest_sha256,
                from_policy_sha256=from_policy_sha256,
                config=config,
                cleanup_gates=cleanup_gates,
                reason=reason,
                expected_generation_fact_sha256=(snapshot.generation_fact_sha256),
            )

    def _migrate_policy_under_lease(
        self,
        source_manifest_sha256: str,
        *,
        from_policy_sha256: str,
        config: ArchiveConfig,
        cleanup_gates: CleanupGatePolicyV1,
        reason: str,
        expected_generation_fact_sha256: str,
    ) -> ArchiveDiscoveryV1:
        activation_attempted = False
        with self._transaction(poison_if=lambda: activation_attempted) as connection:
            old_policy, old_fact = self._active_fact(
                connection,
                source_manifest_sha256,
            )
            if old_policy.policy_sha256 != from_policy_sha256:
                raise ArchiveStateError("from-policy is not the active policy")
            if old_fact.generation_fact_sha256 != expected_generation_fact_sha256:
                raise ArchiveStateError(
                    "active generation changed while acquiring source leases"
                )
            if _path_entry_exists(self._tombstone_path(source_manifest_sha256)):
                raise ArchiveStateError("cleanup tombstone blocks policy migration")
            if _path_entry_exists(self._cleanup_intent_path(source_manifest_sha256)):
                raise ArchiveStateError("cleanup intent blocks policy migration")
            self._validate_local_source(old_fact.source)
            candidate = freeze_policy(config=config)
            new_cleanup_facts = _cleanup_facts(old_fact.source, cleanup_gates)
            self._reject_weaker_cleanup_facts(
                old_fact.cleanup_facts,
                new_cleanup_facts,
            )
            if candidate.policy_sha256 == old_policy.policy_sha256:
                if (
                    type(reason) is not str
                    or not reason.strip()
                    or "\n" in reason
                    or "\r" in reason
                ):
                    raise ArchivePolicyError(
                        "policy migration reason must be one nonempty line"
                    )
                if new_cleanup_facts == old_fact.cleanup_facts:
                    raise ArchivePolicyError("archive generation migration is a no-op")
                new_policy = candidate
            else:
                new_policy = migrate_policy(
                    old_policy,
                    config=config,
                    reason=reason,
                )
            jobs = _generation_jobs(old_fact.source, new_policy)
            generation = old_fact.generation + 1
            fact = build_generation_fact(
                source=old_fact.source,
                generation=generation,
                policy_sha256=new_policy.policy_sha256,
                previous_policy_sha256=old_policy.policy_sha256,
                predecessor_generation_fact_sha256=(old_fact.generation_fact_sha256),
                migration_reason=reason.strip(),
                required_target_ids=new_policy.required_target_ids,
                optional_target_ids=tuple(
                    target.target_id
                    for target in new_policy.targets
                    if not target.required
                ),
                cleanup_facts=new_cleanup_facts,
                jobs=jobs,
            )
            self._publish_policy(new_policy)
            self._publish_generation(fact)
            activation_attempted = True
            self._activate_generation(fact)
            self._insert_policy(connection, new_policy)
            self._insert_generation(
                connection,
                policy=new_policy,
                fact=fact,
                active=True,
            )
            connection.execute(
                """
                INSERT INTO archive_policy_migration(
                    source_manifest_sha256, generation,
                    old_policy_sha256, new_policy_sha256,
                    operator_reason, recorded_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    source_manifest_sha256,
                    generation,
                    old_policy.policy_sha256,
                    new_policy.policy_sha256,
                    reason.strip(),
                    self._now_ns(),
                ),
            )
            return ArchiveDiscoveryV1(
                source_sha=source_manifest_sha256,
                generation=generation,
                policy_sha256=new_policy.policy_sha256,
                job_keys=tuple(
                    ArchiveJobKey(
                        source_manifest_sha256=source_manifest_sha256,
                        artifact_role=job.artifact_role,
                        artifact_sha256=job.artifact_sha256,
                        target_id=job.target_id,
                        policy_sha256=new_policy.policy_sha256,
                    )
                    for job in jobs
                ),
            )

    def close(self) -> None:
        connection = self._connection
        if connection is None:
            return
        self._connection = None
        connection.close()

    def __enter__(self) -> Self:
        self._require_connection()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


def _hash_regular(path: Path) -> tuple[int, str]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    try:
        observed = os.fstat(fd)
        if not stat.S_ISREG(observed.st_mode):
            raise OSError(errno.EINVAL, "archive source is not a regular file")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                return size, digest.hexdigest()
            size += len(chunk)
            digest.update(chunk)
    finally:
        os.close(fd)


__all__ = [
    "ArchiveConflictError",
    "ArchiveState",
    "ArchiveStateError",
    "ArchiveTargetError",
    "ArchiveTransition",
    "ExistingObjectMismatch",
    "InvalidArchiveTransition",
    "RemotePolicyMismatch",
    "RetryableTargetError",
    "StoredObjectMismatch",
]
