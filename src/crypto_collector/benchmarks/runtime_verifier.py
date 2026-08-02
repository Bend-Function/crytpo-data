from __future__ import annotations

import hashlib
import heapq
import io
import os
import sqlite3
import stat
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import pairwise, zip_longest
from pathlib import Path
from typing import BinaryIO, Protocol, TypeVar, cast

import zstandard
from pydantic import BaseModel, ValidationError

from crypto_collector.benchmarks.aggregation import (
    aggregate_final_worker_snapshots,
    summarize_resources,
    summarize_storage_health,
    validate_worker_rounds,
)
from crypto_collector.benchmarks.artifacts import iter_jsonl_zstd
from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    FinalWorkerAggregateV1,
    GateAdmissionTraceV1,
    GateArtifactRefV1,
    GateCandidateReportV1,
    GateEvidenceDocumentRefV1,
    GateManifestInventoryV1,
    GateRawInventoryV1,
    GateResourceSamplingRoundV1,
    GateResourceSummaryV1,
    GateRunIndexV1,
    GateRuntimeIndexV1,
    GateRuntimeReceiptV1,
    GateRuntimeSummaryV1,
    GateSamplingRoundV1,
    GateSecondBucketV1,
    GateStorageHealthSampleV1,
    GateStorageHealthSummaryV1,
    GateStreamRuntimeSummaryV1,
    GateTargetReprobeV1,
    GateTargetV1,
    StreamGroup,
)
from crypto_collector.benchmarks.oracle import (
    PlannedEventV1,
    WorkloadPlanV1,
    build_native_draft,
    build_workload_plan,
    iter_plan_events,
)
from crypto_collector.benchmarks.workload import (
    RESEARCH_DEFAULT_V1_SHA256,
    LoadedWorkload,
    load_workload,
)
from crypto_collector.domain.envelope import NativeEventDraft, RawEnvelope
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.domain.types import CloseReason, Exchange
from crypto_collector.storage.lease import SourceLease
from crypto_collector.storage.manifest import (
    LoadedRawManifest,
    RawManifestV1,
    SourceDisposition,
    lease_path_for_data,
    validate_local_source,
)
from crypto_collector.storage.models import AcceptedRecordIdentityV1, EnqueueStatus
from crypto_collector.storage.raw_writer import (
    NoReplaceCapability,
    atomic_write_and_sync_json_exclusive,
    fsync_directory,
    open_readonly_nofollow,
    publish_no_replace,
)
from crypto_collector.storage.serialize import decode_envelope_jsonl, encode_envelope

_RUN_INDEX_NAME = "run-index.json"
_RUNTIME_RECEIPT_NAME = "runtime-receipt.json"
_RUNTIME_INDEX_NAME = "runtime-index.json"
_MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_SQLITE_CACHE_KIB = 8 * 1024
_SQLITE_COMMIT_ROWS = 50_000
_ONE_SECOND_NS = 1_000_000_000
_TRACE_MAX_LINE_BYTES = 64 * 1024
_SAMPLE_MAX_LINE_BYTES = 64 * 1024
_RAW_MAX_LINE_OVERHEAD_BYTES = 256 * 1024
_RAW_DIRECTORY_ENTRY_MULTIPLIER = 20
_RAW_DIRECTORY_ENTRY_FLOOR = 1_024
_ZSTD_FRAME_HEADER_MAX_BYTES = 18
_ZSTD_SCAN_CHUNK_BYTES = 64 * 1024
_STREAM_GROUPS: tuple[StreamGroup, ...] = (
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "derivative",
    "candle_1m",
    "book_deep_snapshot",
    "control",
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


class RuntimeEvidenceValidationError(ValueError):
    """The runtime evidence cannot establish or satisfy its validation contract."""


class TargetProbePort(Protocol):
    def __call__(
        self,
        declaration: GateTargetV1,
        *,
        expected_target_id: str,
    ) -> GateTargetReprobeV1: ...


def _trusted_run_index_path(path: Path) -> Path:
    if not isinstance(path, Path):
        raise TypeError("run_index_path must be Path")
    if path.name != _RUN_INDEX_NAME:
        raise RuntimeEvidenceValidationError(
            "runtime verification requires canonical run-index.json"
        )
    if not path.is_absolute():
        raise RuntimeEvidenceValidationError("run-index.json path must be absolute")
    if path.parent == Path(path.anchor):
        raise RuntimeEvidenceValidationError(
            "run-index.json may not live at filesystem root"
        )
    try:
        resolved_parent = path.parent.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
    except OSError as error:
        raise RuntimeEvidenceValidationError(
            "run-index.json and its parent must exist"
        ) from error
    if resolved_parent != path.parent or resolved_path != path:
        raise RuntimeEvidenceValidationError(
            "run-index.json path may not traverse symbolic links"
        )
    if not path.parent.is_dir():
        raise RuntimeEvidenceValidationError(
            "run-index.json parent must be a directory"
        )
    return path


def _read_regular_file(path: Path, *, max_bytes: int) -> bytes:
    try:
        fd = open_readonly_nofollow(path)
    except OSError as error:
        raise RuntimeEvidenceValidationError(
            f"evidence document is unavailable: {path.name}"
        ) from error
    primary_error: BaseException | None = None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeEvidenceValidationError(
                f"evidence document is not regular: {path.name}"
            )
        if metadata.st_size <= 0 or metadata.st_size > max_bytes:
            raise RuntimeEvidenceValidationError(
                f"evidence document size is invalid: {path.name}"
            )
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(fd, min(64 * 1024, remaining))
            if not chunk:
                raise RuntimeEvidenceValidationError(
                    f"evidence document changed while reading: {path.name}"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise RuntimeEvidenceValidationError(
                f"evidence document grew while reading: {path.name}"
            )
        return b"".join(chunks)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            os.close(fd)
        except OSError as error:
            if primary_error is None:
                raise RuntimeEvidenceValidationError(
                    f"evidence document close failed: {path.name}"
                ) from error
            primary_error.add_note(f"evidence document close also failed: {error!r}")


def _load_run_index(path: Path) -> tuple[GateRunIndexV1, bytes]:
    source = _read_regular_file(path, max_bytes=_MAX_DOCUMENT_BYTES)
    try:
        model = GateRunIndexV1.model_validate_json(source, strict=True)
    except (TypeError, ValueError, ValidationError) as error:
        raise RuntimeEvidenceValidationError(
            "run-index.json does not match GateRunIndexV1"
        ) from error
    if model.canonical_bytes() != source:
        raise RuntimeEvidenceValidationError("run-index.json is not canonical JSON")
    return model, source


def _trusted_root(path: str, *, label: str) -> Path:
    root = Path(path)
    if not root.is_absolute() or root == Path(root.anchor):
        raise RuntimeEvidenceValidationError(
            f"declared {label} must be a non-root absolute directory"
        )
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise RuntimeEvidenceValidationError(f"declared {label} must exist") from error
    if resolved != root or not root.is_dir():
        raise RuntimeEvidenceValidationError(
            f"declared {label} must be a normalized non-symlink directory"
        )
    return root


def _referenced_path(root: Path, relative_path: str) -> Path:
    candidate = root.joinpath(*relative_path.split("/"))
    if not candidate.is_relative_to(root):
        raise RuntimeEvidenceValidationError("evidence path escaped its trusted root")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise RuntimeEvidenceValidationError(
            f"referenced evidence is unavailable: {relative_path}"
        ) from error
    if resolved != candidate or not candidate.is_file():
        raise RuntimeEvidenceValidationError(
            f"referenced evidence traverses a symlink: {relative_path}"
        )
    return candidate


def _read_document_ref(
    root: Path,
    reference: GateEvidenceDocumentRefV1,
) -> tuple[Path, bytes]:
    path = _referenced_path(root, reference.relative_path)
    source = _read_regular_file(path, max_bytes=_MAX_DOCUMENT_BYTES)
    if len(source) != reference.content_size_bytes:
        raise RuntimeEvidenceValidationError(
            f"document size disagrees with its ref: {reference.relative_path}"
        )
    if hashlib.sha256(source).hexdigest() != reference.content_sha256:
        raise RuntimeEvidenceValidationError(
            f"document SHA disagrees with its ref: {reference.relative_path}"
        )
    return path, source


def _load_referenced_model(
    root: Path,
    reference: GateEvidenceDocumentRefV1,
    model_type: type[_ModelT],
) -> tuple[_ModelT, bytes]:
    _, source = _read_document_ref(root, reference)
    try:
        model = model_type.model_validate_json(source, strict=True)
    except (TypeError, ValueError, ValidationError) as error:
        raise RuntimeEvidenceValidationError(
            f"document does not match {model_type.__name__}: {reference.relative_path}"
        ) from error
    canonical_method = getattr(model, "canonical_bytes", None)
    if not callable(canonical_method) or canonical_method() != source:
        raise RuntimeEvidenceValidationError(
            f"document is not canonical JSON: {reference.relative_path}"
        )
    return model, source


@dataclass(slots=True)
class _ScratchDatabase:
    connection: sqlite3.Connection
    path: Path
    worker_ids: dict[str, tuple[int, bytes, int]]
    route_ids: dict[tuple[str, str, str, str, str, bytes, int], int]

    @classmethod
    def open(cls, state_root: Path) -> _ScratchDatabase:
        path = state_root / f".gate-runtime-{uuid.uuid4().hex}.sqlite.partial"
        connection = sqlite3.connect(path)
        try:
            journal_mode = connection.execute("PRAGMA journal_mode=WAL").fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != "wal":
                raise RuntimeEvidenceValidationError(
                    "runtime verifier SQLite WAL mode is unavailable"
                )
            connection.execute("PRAGMA synchronous=FULL")
            synchronous = connection.execute("PRAGMA synchronous").fetchone()
            if synchronous is None or int(synchronous[0]) != 2:
                raise RuntimeEvidenceValidationError(
                    "runtime verifier SQLite FULL sync is unavailable"
                )
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            connection.execute(f"PRAGMA cache_size=-{_SQLITE_CACHE_KIB}")
            connection.execute("PRAGMA temp_store=FILE")
            connection.executescript(
                """
                CREATE TABLE planned (
                    planned_event_id BLOB PRIMARY KEY
                        CHECK (length(planned_event_id) = 32),
                    payload_sha256 BLOB NOT NULL
                        CHECK (length(payload_sha256) = 32),
                    payload_bytes INTEGER NOT NULL CHECK (payload_bytes > 0),
                    expected_native_sha256 BLOB NOT NULL
                        CHECK (length(expected_native_sha256) = 32)
                ) STRICT, WITHOUT ROWID;
                CREATE TABLE worker (
                    worker_id INTEGER PRIMARY KEY,
                    worker_instance_id TEXT NOT NULL,
                    config_sha256 BLOB NOT NULL
                        CHECK (length(config_sha256) = 32),
                    config_generation INTEGER NOT NULL
                        CHECK (config_generation >= 0),
                    UNIQUE (worker_instance_id)
                ) STRICT;
                CREATE TABLE route (
                    route_id INTEGER PRIMARY KEY,
                    exchange TEXT NOT NULL,
                    market_key TEXT NOT NULL,
                    instrument_key TEXT NOT NULL,
                    logical_stream TEXT NOT NULL,
                    worker_id INTEGER NOT NULL REFERENCES worker(worker_id),
                    UNIQUE (
                        exchange, market_key, instrument_key, logical_stream,
                        worker_id
                    ),
                    UNIQUE (route_id, worker_id)
                ) STRICT;
                CREATE TABLE accepted (
                    route_id INTEGER NOT NULL,
                    worker_id INTEGER NOT NULL,
                    writer_sequence INTEGER NOT NULL
                        CHECK (writer_sequence >= 0),
                    acceptance_ordinal INTEGER NOT NULL
                        CHECK (acceptance_ordinal >= 0),
                    planned_event_id BLOB NOT NULL UNIQUE
                        REFERENCES planned(planned_event_id),
                    PRIMARY KEY (route_id, writer_sequence, acceptance_ordinal),
                    UNIQUE (route_id, writer_sequence),
                    UNIQUE (worker_id, acceptance_ordinal),
                    FOREIGN KEY (route_id, worker_id)
                        REFERENCES route(route_id, worker_id)
                ) STRICT, WITHOUT ROWID;
                CREATE TABLE durable (
                    manifest_ordinal INTEGER NOT NULL
                        CHECK (manifest_ordinal >= 0),
                    row_index INTEGER NOT NULL CHECK (row_index >= 0),
                    route_id INTEGER NOT NULL,
                    writer_sequence INTEGER NOT NULL
                        CHECK (writer_sequence >= 0),
                    PRIMARY KEY (manifest_ordinal, row_index),
                    UNIQUE (route_id, writer_sequence),
                    FOREIGN KEY (route_id, writer_sequence)
                        REFERENCES accepted(route_id, writer_sequence)
                ) STRICT, WITHOUT ROWID;
                """
            )
            connection.commit()
        except BaseException:
            connection.close()
            raise
        return cls(
            connection=connection,
            path=path,
            worker_ids={},
            route_ids={},
        )

    def close(self) -> None:
        self.connection.close()

    def cleanup(self) -> None:
        for path in (
            self.path,
            Path(f"{self.path}-wal"),
            Path(f"{self.path}-shm"),
            Path(f"{self.path}-journal"),
        ):
            path.unlink(missing_ok=True)


@dataclass(slots=True)
class _MutableBucket:
    scheduled_count: int = 0
    attempted_count: int = 0
    accepted_count: int = 0
    admitted_in_actual_second_count: int = 0
    scheduled_payload_bytes: int = 0
    attempted_payload_bytes: int = 0
    accepted_payload_bytes: int = 0
    early_count: int = 0
    late_count: int = 0
    out_of_window_count: int = 0

    def freeze(
        self,
        *,
        stream_group: StreamGroup,
        second_index: int,
    ) -> GateSecondBucketV1:
        return GateSecondBucketV1(
            stream_group=stream_group,
            second_index=second_index,
            scheduled_count=self.scheduled_count,
            attempted_count=self.attempted_count,
            accepted_count=self.accepted_count,
            admitted_in_actual_second_count=self.admitted_in_actual_second_count,
            scheduled_payload_bytes=self.scheduled_payload_bytes,
            attempted_payload_bytes=self.attempted_payload_bytes,
            accepted_payload_bytes=self.accepted_payload_bytes,
            early_count=self.early_count,
            late_count=self.late_count,
            out_of_window_count=self.out_of_window_count,
        )


@dataclass(frozen=True, slots=True)
class _PrimaryDocuments:
    workload: LoadedWorkload
    candidate: GateCandidateReportV1
    raw_inventory: GateRawInventoryV1
    manifest_inventory: GateManifestInventoryV1


@dataclass(frozen=True, slots=True)
class _TraceValidation:
    buckets: tuple[GateSecondBucketV1, ...]
    accepted_record_count: int
    accepted_payload_bytes: int
    early_count: int
    late_count: int
    out_of_window_count: int


_WorkerSyncFacts = tuple[tuple[str, int, int, int], ...]
_WorkerRecordCounts = tuple[tuple[str, int], ...]


@dataclass(frozen=True, slots=True)
class _RawValidation:
    durable_record_count: int
    durable_payload_bytes: int
    received_utc_hours: tuple[str, ...]
    observed_touched_file_identity_count: int
    sync_count: int
    sync_duration_total_ns: int
    sync_duration_max_ns: int
    worker_sync_facts: _WorkerSyncFacts
    worker_record_counts: _WorkerRecordCounts


@dataclass(frozen=True, slots=True)
class _SampleValidation:
    final_worker_aggregate: FinalWorkerAggregateV1
    resource_summary: GateResourceSummaryV1
    storage_health_summary: GateStorageHealthSummaryV1
    worker_sync_facts: _WorkerSyncFacts
    worker_record_counts: _WorkerRecordCounts


def _load_primary_documents(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    *,
    target_declaration_sha256: str | None,
) -> _PrimaryDocuments:
    workload_path, workload_source = _read_document_ref(
        evidence_root,
        run_index.workload_document,
    )
    try:
        workload = load_workload(workload_path)
    except (OSError, TypeError, ValueError) as error:
        raise RuntimeEvidenceValidationError("workload document is invalid") from error
    if (
        workload.source_bytes != workload_source
        or workload.sha256 != run_index.workload_sha256
    ):
        raise RuntimeEvidenceValidationError(
            "workload bytes disagree with the run index"
        )
    candidate, _ = _load_referenced_model(
        evidence_root,
        run_index.candidate_report,
        GateCandidateReportV1,
    )
    raw_inventory, _ = _load_referenced_model(
        evidence_root,
        run_index.raw_inventory,
        GateRawInventoryV1,
    )
    manifest_inventory, _ = _load_referenced_model(
        evidence_root,
        run_index.manifest_inventory,
        GateManifestInventoryV1,
    )
    if (
        candidate.run_id != run_index.run_id
        or candidate.mode != run_index.mode
        or candidate.workload_sha256 != run_index.workload_sha256
        or candidate.workload_plan_sha256 != run_index.workload_plan_sha256
        or candidate.expected_target_id != run_index.expected_target_id
        or candidate.expected_image_id != run_index.expected_image_id
        or candidate.runtime_image_id != run_index.runtime_image_id
    ):
        raise RuntimeEvidenceValidationError(
            "candidate identity and run-index claims disagree"
        )
    if candidate.target_declaration_sha256 != target_declaration_sha256:
        raise RuntimeEvidenceValidationError(
            "candidate target declaration claim disagrees with the loaded declaration"
        )
    inventory_data = tuple(entry.data for entry in manifest_inventory.manifests)
    if tuple(sorted(inventory_data, key=lambda item: item.relative_path)) != (
        raw_inventory.raw_files
    ):
        raise RuntimeEvidenceValidationError(
            "raw and manifest inventories do not bind the same data files"
        )
    return _PrimaryDocuments(
        workload=workload,
        candidate=candidate,
        raw_inventory=raw_inventory,
        manifest_inventory=manifest_inventory,
    )


def _validate_artifact_path(root: Path, artifact: GateArtifactRefV1) -> None:
    path = _referenced_path(root, artifact.relative_path)
    metadata = path.stat(follow_symlinks=False)
    if metadata.st_size != artifact.compressed_size_bytes:
        raise RuntimeEvidenceValidationError(
            f"artifact size disagrees with its ref: {artifact.relative_path}"
        )


def _route_key(
    identity: AcceptedRecordIdentityV1,
) -> tuple[str, str, str, str, str, bytes, int]:
    return (
        identity.exchange.value,
        "" if identity.market is None else identity.market.value,
        "" if identity.instrument_key is None else identity.instrument_key,
        identity.logical_stream,
        identity.worker_instance_id,
        bytes.fromhex(identity.config_sha256),
        identity.config_generation,
    )


def _route_id(
    database: _ScratchDatabase,
    identity: AcceptedRecordIdentityV1,
) -> tuple[int, int]:
    key = _route_key(identity)
    cached = database.route_ids.get(key)
    if cached is not None:
        return cached, database.worker_ids[key[4]][0]
    worker_name = key[4]
    config_sha256 = key[5]
    config_generation = key[6]
    cached_worker = database.worker_ids.get(worker_name)
    if cached_worker is None:
        worker_row = database.connection.execute(
            """
            SELECT worker_id, config_sha256, config_generation FROM worker
            WHERE worker_instance_id = ?
            """,
            (worker_name,),
        ).fetchone()
        if worker_row is None:
            worker_cursor = database.connection.execute(
                """
                INSERT INTO worker (
                    worker_instance_id, config_sha256, config_generation
                ) VALUES (?, ?, ?)
                """,
                (worker_name, config_sha256, config_generation),
            )
            if worker_cursor.lastrowid is None:
                raise RuntimeEvidenceValidationError(
                    "normalized worker insertion returned no identity"
                )
            worker_id = worker_cursor.lastrowid
        else:
            worker_id = int(worker_row[0])
            if (bytes(worker_row[1]), int(worker_row[2])) != (
                config_sha256,
                config_generation,
            ):
                raise RuntimeEvidenceValidationError(
                    "accepted identities disagree on immutable worker config facts"
                )
        database.worker_ids[worker_name] = (
            worker_id,
            config_sha256,
            config_generation,
        )
    else:
        worker_id, observed_sha256, observed_generation = cached_worker
        if (observed_sha256, observed_generation) != (
            config_sha256,
            config_generation,
        ):
            raise RuntimeEvidenceValidationError(
                "accepted identities disagree on immutable worker config facts"
            )
    route_key = (key[0], key[1], key[2], key[3], worker_id)
    row = database.connection.execute(
        """
        SELECT route_id FROM route
        WHERE exchange = ? AND market_key = ? AND instrument_key = ?
          AND logical_stream = ? AND worker_id = ?
        """,
        route_key,
    ).fetchone()
    if row is None:
        cursor = database.connection.execute(
            """
            INSERT INTO route (
                exchange, market_key, instrument_key, logical_stream,
                worker_id
            ) VALUES (?, ?, ?, ?, ?)
            """,
            route_key,
        )
        if cursor.lastrowid is None:
            raise RuntimeEvidenceValidationError(
                "normalized route insertion returned no identity"
            )
        normalized = cursor.lastrowid
    else:
        normalized = int(row[0])
    database.route_ids[key] = normalized
    return normalized, worker_id


def _expected_native_sha256(
    event: PlannedEventV1,
    *,
    admission_started_utc_ns: int,
) -> bytes:
    draft, source, _ = build_native_draft(
        event,
        admission_started_utc_ns=admission_started_utc_ns,
    )
    draft_projection = draft.model_dump(mode="json")
    del draft_projection["payload"]
    projection = encode_json(
        {
            "draft": draft_projection,
            "source": {
                "connection_id": source.connection_id,
                "connection_generation": source.connection_generation,
                "egress_id": source.egress_id,
            },
        }
    )
    return hashlib.sha256(projection).digest()


def _iter_trace_partition(
    evidence_root: Path,
    exchange: Exchange,
    artifact: GateArtifactRefV1,
    *,
    max_rows: int,
    max_content_bytes: int,
) -> Iterator[GateAdmissionTraceV1]:
    _validate_artifact_path(evidence_root, artifact)
    previous_key: tuple[int, str] | None = None
    for row in iter_jsonl_zstd(
        evidence_root,
        artifact,
        GateAdmissionTraceV1,
        max_rows=max_rows,
        max_content_bytes=max_content_bytes,
        max_line_bytes=_TRACE_MAX_LINE_BYTES,
    ):
        if row.exchange is not exchange:
            raise RuntimeEvidenceValidationError(
                "trace row does not match its exchange partition"
            )
        key = (row.due_monotonic_ns, row.planned_event_id)
        if previous_key is not None and key <= previous_key:
            raise RuntimeEvidenceValidationError(
                "trace partition order is not strictly increasing"
            )
        previous_key = key
        yield row


def _validate_trace(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    candidate: GateCandidateReportV1,
    plan: WorkloadPlanV1,
    database: _ScratchDatabase,
) -> _TraceValidation:
    if plan.workload_plan_sha256 != run_index.workload_plan_sha256:
        raise RuntimeEvidenceValidationError(
            "recomputed workload-plan SHA disagrees with the run index"
        )
    content_bound = max(1, plan.expected_record_count * _TRACE_MAX_LINE_BYTES)
    readers = tuple(
        _iter_trace_partition(
            evidence_root,
            partition.exchange,
            partition.artifact,
            max_rows=plan.expected_record_count,
            max_content_bytes=content_bound,
        )
        for partition in run_index.admission_trace_set.partitions
    )
    merged = heapq.merge(
        *readers,
        key=lambda row: (row.due_monotonic_ns, row.planned_event_id),
    )
    buckets = {
        (stream_group, second_index): _MutableBucket()
        for stream_group in _STREAM_GROUPS
        for second_index in range(plan.duration_seconds)
    }
    merged_digest = hashlib.sha256()
    merged_size = 0
    merged_count = 0
    accepted_count = 0
    accepted_payload_bytes = 0
    sentinel = object()
    connection = database.connection
    connection.execute("BEGIN")
    for expected, observed in zip_longest(
        iter_plan_events(plan),
        merged,
        fillvalue=sentinel,
    ):
        if expected is sentinel or observed is sentinel:
            raise RuntimeEvidenceValidationError(
                "trace and workload oracle cardinalities disagree"
            )
        assert isinstance(expected, PlannedEventV1)
        assert isinstance(observed, GateAdmissionTraceV1)
        due = candidate.admission_started_monotonic_ns + expected.due_offset_ns
        deadline = (
            candidate.admission_started_monotonic_ns + expected.deadline_offset_ns
        )
        expected_facts = (
            expected.planned_event_id,
            expected.stream_group,
            expected.logical_stream,
            expected.exchange,
            expected.market,
            expected.instrument_key,
            expected.canonical_identity,
            expected.identity_index,
            expected.local_sequence,
            due,
            deadline,
            expected.payload_bytes,
            expected.payload_sha256,
        )
        observed_facts = (
            observed.planned_event_id,
            observed.stream_group,
            observed.logical_stream,
            observed.exchange,
            observed.market,
            observed.instrument_key,
            observed.canonical_identity,
            observed.identity_index,
            observed.local_sequence,
            observed.due_monotonic_ns,
            observed.deadline_monotonic_ns,
            observed.payload_bytes,
            observed.payload_sha256,
        )
        if observed_facts != expected_facts:
            raise RuntimeEvidenceValidationError(
                "trace row disagrees with the workload oracle"
            )
        line = observed.canonical_bytes()
        merged_digest.update(line)
        merged_size += len(line)
        merged_count += 1
        second_index = expected.due_offset_ns // _ONE_SECOND_NS
        bucket = buckets[(expected.stream_group, second_index)]
        bucket.scheduled_count += 1
        bucket.scheduled_payload_bytes += expected.payload_bytes
        bucket.attempted_count += 1
        bucket.attempted_payload_bytes += expected.payload_bytes
        early = observed.attempt_started_monotonic_ns < due
        late = observed.admission_completed_monotonic_ns >= deadline
        window_start = candidate.admission_started_monotonic_ns
        window_end = candidate.admission_scheduled_end_monotonic_ns
        out_of_window = not (
            window_start <= observed.attempt_started_monotonic_ns < window_end
            and window_start <= observed.admission_completed_monotonic_ns < window_end
        )
        bucket.early_count += int(early)
        bucket.late_count += int(late)
        bucket.out_of_window_count += int(out_of_window)
        connection.execute(
            "INSERT INTO planned VALUES (?, ?, ?, ?)",
            (
                bytes.fromhex(expected.planned_event_id),
                bytes.fromhex(expected.payload_sha256),
                expected.payload_bytes,
                _expected_native_sha256(
                    expected,
                    admission_started_utc_ns=candidate.admission_started_utc_ns,
                ),
            ),
        )
        identity = observed.accepted_identity
        accepted = observed.enqueue_status in {
            EnqueueStatus.ACCEPTED,
            EnqueueStatus.ACCEPTED_HIGH_WATER,
        }
        if accepted:
            assert identity is not None
            route_id, worker_id = _route_id(database, identity)
            bucket.accepted_count += 1
            bucket.accepted_payload_bytes += expected.payload_bytes
            accepted_count += 1
            accepted_payload_bytes += expected.payload_bytes
            actual_second = (
                observed.admission_completed_monotonic_ns - window_start
            ) // _ONE_SECOND_NS
            if 0 <= actual_second < plan.duration_seconds:
                buckets[
                    (expected.stream_group, actual_second)
                ].admitted_in_actual_second_count += 1
            try:
                connection.execute(
                    "INSERT INTO accepted VALUES (?, ?, ?, ?, ?)",
                    (
                        route_id,
                        worker_id,
                        identity.writer_sequence,
                        identity.acceptance_ordinal,
                        bytes.fromhex(expected.planned_event_id),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise RuntimeEvidenceValidationError(
                    "trace accepted identities are duplicate or ambiguous"
                ) from error
        if merged_count % _SQLITE_COMMIT_ROWS == 0:
            connection.commit()
            connection.execute("BEGIN")
    connection.commit()
    trace_set = run_index.admission_trace_set
    if (
        merged_count != trace_set.merged_row_count
        or merged_size != trace_set.merged_content_size_bytes
        or merged_digest.hexdigest() != trace_set.merged_content_sha256
    ):
        raise RuntimeEvidenceValidationError(
            "virtual merged trace facts disagree with the run index"
        )
    ordinal_rows = connection.execute(
        """
        SELECT worker.worker_instance_id, COUNT(*), MIN(acceptance_ordinal),
               MAX(acceptance_ordinal)
        FROM accepted JOIN worker USING (worker_id)
        GROUP BY worker.worker_instance_id
        """
    ).fetchall()
    if len(ordinal_rows) != len(CANONICAL_EXCHANGES) or any(
        int(count) <= 0 or int(minimum) != 0 or int(maximum) != int(count) - 1
        for _, count, minimum, maximum in ordinal_rows
    ):
        raise RuntimeEvidenceValidationError(
            "per-worker acceptance ordinals are not contiguous"
        )
    frozen_buckets = tuple(
        buckets[(stream_group, second_index)].freeze(
            stream_group=stream_group,
            second_index=second_index,
        )
        for stream_group in _STREAM_GROUPS
        for second_index in range(plan.duration_seconds)
    )
    return _TraceValidation(
        buckets=frozen_buckets,
        accepted_record_count=accepted_count,
        accepted_payload_bytes=accepted_payload_bytes,
        early_count=sum(item.early_count for item in frozen_buckets),
        late_count=sum(item.late_count for item in frozen_buckets),
        out_of_window_count=sum(item.out_of_window_count for item in frozen_buckets),
    )


def _artifact_rows(
    evidence_root: Path,
    artifact: GateArtifactRefV1,
    model_type: type[_ModelT],
    *,
    max_rows: int,
    max_line_bytes: int,
) -> Iterator[_ModelT]:
    _validate_artifact_path(evidence_root, artifact)
    yield from iter_jsonl_zstd(
        evidence_root,
        artifact,
        model_type,
        max_rows=max_rows,
        max_content_bytes=max(1, max_rows * max_line_bytes),
        max_line_bytes=max_line_bytes,
    )


def _validate_bucket_artifact(
    evidence_root: Path,
    artifact: GateArtifactRefV1,
    expected: tuple[GateSecondBucketV1, ...],
) -> None:
    sentinel = object()
    observed_rows = _artifact_rows(
        evidence_root,
        artifact,
        GateSecondBucketV1,
        max_rows=len(expected),
        max_line_bytes=_TRACE_MAX_LINE_BYTES,
    )
    for expected_row, observed_row in zip_longest(
        expected,
        observed_rows,
        fillvalue=sentinel,
    ):
        if expected_row is sentinel or observed_row is sentinel:
            raise RuntimeEvidenceValidationError(
                "second-bucket artifact cardinality is incomplete"
            )
        if observed_row != expected_row:
            raise RuntimeEvidenceValidationError(
                "second-bucket artifact disagrees with recomputed trace facts"
            )


def _validate_sample_artifacts(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    documents: _PrimaryDocuments,
    database: _ScratchDatabase,
) -> _SampleValidation:
    candidate = documents.candidate
    plan = build_workload_plan(
        documents.workload,
        multiplier=candidate.multiplier,
        duration_ns=candidate.duration_ns,
    )
    row_bound = plan.duration_seconds + 3
    worker_rounds = tuple(
        _artifact_rows(
            evidence_root,
            run_index.worker_sampling_artifact,
            GateSamplingRoundV1,
            max_rows=row_bound,
            max_line_bytes=_SAMPLE_MAX_LINE_BYTES,
        )
    )
    if not worker_rounds:
        raise RuntimeEvidenceValidationError("worker sample artifact is empty")
    sequences = validate_worker_rounds(
        worker_rounds,
        expected_workers=worker_rounds[0].expected_worker_keys,
    )
    aggregate = aggregate_final_worker_snapshots(sequences)
    sample_interval_ns = (
        documents.workload.workload.qualification.storage_health_sample_interval_seconds
        * _ONE_SECOND_NS
    )
    sample_max_gap_ns = (
        documents.workload.workload.qualification.storage_health_max_gap_seconds
        * _ONE_SECOND_NS
    )
    first_worker_request = min(
        sample.request_started_monotonic_ns for sample in sequences.rounds[0].samples
    )
    final_worker_completion = max(
        sample.request_completed_monotonic_ns for sample in sequences.rounds[-1].samples
    )
    worker_max_gap = max(
        (
            current.scheduled_monotonic_ns - previous.scheduled_monotonic_ns
            for previous, current in pairwise(sequences.rounds)
        ),
        default=0,
    )
    if (
        first_worker_request
        > candidate.admission_started_monotonic_ns + sample_interval_ns
        or final_worker_completion < candidate.admission_scheduled_end_monotonic_ns
        or final_worker_completion - first_worker_request
        < max(0, candidate.duration_ns - sample_interval_ns)
        or worker_max_gap > sample_max_gap_ns
    ):
        raise RuntimeEvidenceValidationError(
            "worker samples do not cover the bound admission and drain interval"
        )
    accepted_worker_facts = {
        str(worker): (
            bytes(config_sha).hex(),
            int(config_generation),
            int(record_count),
            int(minimum_ordinal),
            int(maximum_ordinal),
        )
        for (
            worker,
            config_sha,
            config_generation,
            record_count,
            minimum_ordinal,
            maximum_ordinal,
        ) in database.connection.execute(
            """
            SELECT worker.worker_instance_id, MIN(worker.config_sha256),
                   MIN(worker.config_generation), COUNT(*),
                   MIN(accepted.acceptance_ordinal),
                   MAX(accepted.acceptance_ordinal)
            FROM accepted JOIN worker USING (worker_id)
            GROUP BY worker.worker_instance_id
            HAVING COUNT(DISTINCT worker.config_sha256) = 1
               AND COUNT(DISTINCT worker.config_generation) = 1
            """
        )
    }
    for sequence in sequences.worker_sequences:
        snapshot = sequence[-1].snapshot
        if accepted_worker_facts.get(snapshot.worker_instance_id) != (
            snapshot.config_sha256,
            snapshot.config_generation,
            snapshot.accepted_record_count,
            0,
            snapshot.acceptance_ordinal_high_water,
        ):
            raise RuntimeEvidenceValidationError(
                "accepted identity facts disagree with worker samples"
            )
    worker_sync_facts = tuple(
        sorted(
            (
                sequence[-1].snapshot.worker_instance_id,
                sequence[-1].snapshot.sync_count,
                sequence[-1].snapshot.sync_duration_total_ns,
                sequence[-1].snapshot.sync_duration_max_ns,
            )
            for sequence in sequences.worker_sequences
        )
    )
    worker_record_counts = tuple(
        sorted(
            (
                sequence[-1].snapshot.worker_instance_id,
                sequence[-1].snapshot.durable_record_count,
            )
            for sequence in sequences.worker_sequences
        )
    )
    del worker_rounds, sequences

    resource_rounds = tuple(
        _artifact_rows(
            evidence_root,
            run_index.resource_sampling_artifact,
            GateResourceSamplingRoundV1,
            max_rows=row_bound,
            max_line_bytes=_SAMPLE_MAX_LINE_BYTES,
        )
    )
    if not resource_rounds:
        raise RuntimeEvidenceValidationError("resource sample artifact is empty")
    warmup_ns = (
        documents.workload.workload.qualification.warmup_seconds * _ONE_SECOND_NS
    )
    resource_summary = summarize_resources(
        resource_rounds,
        expected_processes=resource_rounds[0].expected_process_keys,
        warmup_ended_monotonic_ns=(
            candidate.admission_started_monotonic_ns + warmup_ns
        ),
    )
    del resource_rounds
    health_samples = tuple(
        _artifact_rows(
            evidence_root,
            run_index.storage_health_artifact,
            GateStorageHealthSampleV1,
            max_rows=row_bound,
            max_line_bytes=_SAMPLE_MAX_LINE_BYTES,
        )
    )
    if not health_samples:
        raise RuntimeEvidenceValidationError("storage-health artifact is empty")
    health_summary = summarize_storage_health(
        health_samples,
        duration_ns=candidate.duration_ns,
        interval_ns=sample_interval_ns,
    )
    if (
        health_summary.first_request_monotonic_ns
        > candidate.admission_started_monotonic_ns + sample_interval_ns
        or health_summary.final_completion_monotonic_ns
        < candidate.admission_scheduled_end_monotonic_ns - sample_interval_ns
        or health_summary.sample_max_gap_ns > sample_max_gap_ns
    ):
        raise RuntimeEvidenceValidationError(
            "storage-health samples do not align with the admission interval"
        )
    return _SampleValidation(
        final_worker_aggregate=aggregate,
        resource_summary=resource_summary,
        storage_health_summary=health_summary,
        worker_sync_facts=worker_sync_facts,
        worker_record_counts=worker_record_counts,
    )


class _NoCleanupProofResolver:
    def resolve_missing(self, **_kwargs: object) -> None:
        return None


def _observed_native_sha256(envelope: RawEnvelope) -> bytes:
    observed = envelope.model_dump(mode="json")
    draft = {
        field: observed[field]
        for field in NativeEventDraft.model_fields
        if field != "payload"
    }
    projection = encode_json(
        {
            "draft": draft,
            "source": {
                "connection_id": envelope.connection_id,
                "connection_generation": envelope.connection_generation,
                "egress_id": envelope.egress_id,
            },
        }
    )
    return hashlib.sha256(projection).digest()


def _validate_raw_zstd_frames(
    data_path: Path,
    *,
    max_plain_frame_bytes: int,
) -> None:
    fd = open_readonly_nofollow(data_path)
    primary_error: BaseException | None = None
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise RuntimeEvidenceValidationError(
                "raw zstd source is not a nonempty regular file"
            )
        with os.fdopen(os.dup(fd), "rb", closefd=True) as source:
            pending = b""
            frame_count = 0
            while True:
                if not pending:
                    pending = source.read(_ZSTD_SCAN_CHUNK_BYTES)
                    if not pending:
                        break
                while True:
                    try:
                        parameters = zstandard.get_frame_parameters(pending)
                    except zstandard.ZstdError as error:
                        if len(pending) >= _ZSTD_FRAME_HEADER_MAX_BYTES:
                            raise RuntimeEvidenceValidationError(
                                "raw zstd frame header is invalid"
                            ) from error
                        chunk = source.read(_ZSTD_FRAME_HEADER_MAX_BYTES - len(pending))
                        if not chunk:
                            raise RuntimeEvidenceValidationError(
                                "raw zstd frame header is truncated"
                            ) from error
                        pending += chunk
                        continue
                    break
                if (
                    not parameters.has_checksum
                    or parameters.content_size
                    in {zstandard.CONTENTSIZE_UNKNOWN, zstandard.CONTENTSIZE_ERROR}
                    or parameters.content_size <= 0
                    or parameters.content_size > max_plain_frame_bytes
                    or parameters.window_size > max_plain_frame_bytes
                ):
                    raise RuntimeEvidenceValidationError(
                        "raw zstd frame physical facts violate the manifest contract"
                    )
                decompressor = zstandard.ZstdDecompressor().decompressobj()
                plain_size = 0
                last_plain_byte: int | None = None
                while True:
                    try:
                        decoded = decompressor.decompress(pending)
                    except zstandard.ZstdError as error:
                        raise RuntimeEvidenceValidationError(
                            "raw zstd frame checksum or content is invalid"
                        ) from error
                    plain_size += len(decoded)
                    if plain_size > max_plain_frame_bytes:
                        raise RuntimeEvidenceValidationError(
                            "raw zstd frame exceeds its plain-byte bound"
                        )
                    if decoded:
                        last_plain_byte = decoded[-1]
                    if decompressor.eof:
                        pending = bytes(decompressor.unused_data)
                        break
                    pending = source.read(_ZSTD_SCAN_CHUNK_BYTES)
                    if not pending:
                        raise RuntimeEvidenceValidationError(
                            "raw zstd frame is truncated"
                        )
                if plain_size != parameters.content_size or last_plain_byte != ord(
                    "\n"
                ):
                    raise RuntimeEvidenceValidationError(
                        "raw zstd frame is not independently recoverable JSONL"
                    )
                frame_count += 1
            if frame_count == 0:
                raise RuntimeEvidenceValidationError(
                    "raw zstd source contains no complete frames"
                )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            os.close(fd)
        except OSError as error:
            if primary_error is None:
                raise RuntimeEvidenceValidationError(
                    "raw zstd source close failed"
                ) from error
            primary_error.add_note(f"raw zstd source close also failed: {error!r}")


def _iter_bounded_raw_rows(
    data_path: Path,
    *,
    max_rows: int,
    max_line_bytes: int,
) -> Iterator[RawEnvelope]:
    fd = open_readonly_nofollow(data_path)
    source: BinaryIO | None = None
    zstd_reader: BinaryIO | None = None
    buffered: io.BufferedReader | None = None
    primary_error: BaseException | None = None
    try:
        source = os.fdopen(os.dup(fd), "rb", closefd=True)
        zstd_reader = cast(
            BinaryIO,
            zstandard.ZstdDecompressor().stream_reader(
                source,
                read_across_frames=True,
                closefd=False,
            ),
        )
        buffered = io.BufferedReader(cast(io.RawIOBase, zstd_reader))
        row_count = 0
        while True:
            line = buffered.readline(max_line_bytes + 1)
            if not line:
                break
            if len(line) > max_line_bytes:
                raise RuntimeEvidenceValidationError(
                    "raw source row exceeds the verifier line bound"
                )
            if not line.endswith(b"\n"):
                raise RuntimeEvidenceValidationError(
                    "raw source row is truncated or missing its newline"
                )
            row_count += 1
            if row_count > max_rows:
                raise RuntimeEvidenceValidationError(
                    "raw source exceeds its manifest row count"
                )
            try:
                envelope = decode_envelope_jsonl(line)
            except (TypeError, ValueError) as error:
                raise RuntimeEvidenceValidationError(
                    "raw source row is not a valid envelope"
                ) from error
            if encode_envelope(envelope) != line:
                raise RuntimeEvidenceValidationError(
                    "raw source row is not canonical JSONL"
                )
            yield envelope
        if row_count != max_rows:
            raise RuntimeEvidenceValidationError(
                "raw source row count disagrees with its manifest"
            )
    except (OSError, zstandard.ZstdError) as error:
        primary_error = error
        raise RuntimeEvidenceValidationError("raw zstd source is malformed") from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        for resource in (buffered, zstd_reader, source):
            if resource is None:
                continue
            try:
                resource.close()
            except BaseException as error:  # noqa: BLE001 - close all stream layers
                cleanup_errors.append(error)
        try:
            os.close(fd)
        except OSError as error:
            cleanup_errors.append(error)
        if primary_error is None and cleanup_errors:
            raise cleanup_errors[0]
        if primary_error is not None and cleanup_errors:
            primary_error.add_note(
                "raw reader cleanup also failed: "
                + ", ".join(type(error).__name__ for error in cleanup_errors)
            )


def _validate_raw_manifest_rows(
    data_root: Path,
    loaded: LoadedRawManifest,
    entry_data: GateArtifactRefV1,
    database: _ScratchDatabase,
    *,
    manifest_ordinal: int,
    max_line_bytes: int,
) -> tuple[int, int, set[str], set[str]]:
    manifest = loaded.manifest
    data_path = _referenced_path(data_root, manifest.data_relative_path)
    with SourceLease.shared(lease_path_for_data(data_path)) as lease:
        source_validation = validate_local_source(
            loaded,
            data_root=data_root,
            resolver=_NoCleanupProofResolver(),
            lease=lease,
        )
        if source_validation.disposition is not SourceDisposition.PRESENT_VERIFIED:
            raise RuntimeEvidenceValidationError(
                "raw manifest source is not present and verified"
            )
        assert manifest.max_plain_frame_bytes is not None
        _validate_raw_zstd_frames(
            data_path,
            max_plain_frame_bytes=manifest.max_plain_frame_bytes,
        )
        content_digest = hashlib.sha256()
        content_size = 0
        first_envelope: RawEnvelope | None = None
        last_envelope: RawEnvelope | None = None
        previous_writer_sequence: int | None = None
        first_event_time_ns: int | None = None
        last_event_time_ns: int | None = None
        wire_symbols: set[str] = set()
        connection_generations: set[int] = set()
        egress_ids: set[str] = set()
        requested_intervals: set[int] = set()
        effective_intervals: set[int] = set()
        utc_hours: set[str] = set()
        touched_identities: set[str] = set()
        row_count = 0
        payload_bytes = 0
        for row_index, envelope in enumerate(
            _iter_bounded_raw_rows(
                data_path,
                max_rows=manifest.record_count,
                max_line_bytes=max_line_bytes,
            )
        ):
            line = encode_envelope(envelope)
            content_digest.update(line)
            content_size += len(line)
            row_count += 1
            if first_envelope is None:
                first_envelope = envelope
            last_envelope = envelope
            if (
                previous_writer_sequence is not None
                and envelope.writer_sequence <= previous_writer_sequence
            ):
                raise RuntimeEvidenceValidationError(
                    "raw writer sequences are not strictly increasing"
                )
            previous_writer_sequence = envelope.writer_sequence
            observed_route = (
                envelope.exchange,
                envelope.market,
                envelope.instrument_key,
                envelope.logical_stream,
                envelope.worker_instance_id,
                envelope.config_sha256,
            )
            expected_route = (
                manifest.exchange,
                manifest.market,
                manifest.instrument_key,
                manifest.logical_stream,
                manifest.worker_instance_id,
                manifest.config_sha256,
            )
            if observed_route != expected_route:
                raise RuntimeEvidenceValidationError(
                    "raw envelope identity disagrees with its manifest"
                )
            payload = envelope.payload
            if not isinstance(payload, dict):
                raise RuntimeEvidenceValidationError(
                    "raw envelope payload must be an object"
                )
            event_id = payload.get("event_id")
            identity = payload.get("identity")
            if type(event_id) is not str or type(identity) is not str:
                raise RuntimeEvidenceValidationError(
                    "raw envelope payload lacks its planned identity"
                )
            accepted_rows = database.connection.execute(
                """
                SELECT accepted.planned_event_id, planned.payload_sha256,
                       planned.payload_bytes, planned.expected_native_sha256,
                       accepted.route_id
                FROM accepted
                JOIN route USING (route_id)
                JOIN worker USING (worker_id)
                JOIN planned USING (planned_event_id)
                WHERE route.exchange = ? AND route.market_key = ?
                  AND route.instrument_key = ? AND route.logical_stream = ?
                  AND worker.worker_instance_id = ?
                  AND worker.config_sha256 = ?
                  AND accepted.writer_sequence = ?
                """,
                (
                    envelope.exchange.value,
                    "" if envelope.market is None else envelope.market.value,
                    "" if envelope.instrument_key is None else envelope.instrument_key,
                    envelope.logical_stream,
                    envelope.worker_instance_id,
                    bytes.fromhex(envelope.config_sha256),
                    envelope.writer_sequence,
                ),
            ).fetchmany(2)
            if len(accepted_rows) != 1:
                raise RuntimeEvidenceValidationError(
                    "durable envelope does not join to one accepted identity"
                )
            accepted = accepted_rows[0]
            if bytes(accepted[0]).hex() != event_id:
                raise RuntimeEvidenceValidationError(
                    "durable envelope event ID disagrees with its accepted identity"
                )
            payload_canonical = encode_json(payload)
            if len(payload_canonical) != int(accepted[2]) or hashlib.sha256(
                payload_canonical
            ).digest() != bytes(accepted[1]):
                raise RuntimeEvidenceValidationError(
                    "durable envelope payload disagrees with the workload oracle"
                )
            expected_native_sha256 = bytes(accepted[3])
            if _observed_native_sha256(envelope) != expected_native_sha256:
                raise RuntimeEvidenceValidationError(
                    "durable native envelope fields disagree with the oracle"
                )
            try:
                database.connection.execute(
                    "INSERT INTO durable VALUES (?, ?, ?, ?)",
                    (
                        manifest_ordinal,
                        row_index,
                        int(accepted[4]),
                        envelope.writer_sequence,
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise RuntimeEvidenceValidationError(
                    "durable rows are duplicate or ambiguously joined"
                ) from error
            payload_bytes += int(accepted[2])
            touched_identities.add(identity)
            try:
                utc_hours.add(
                    datetime.fromtimestamp(
                        envelope.received_at_ns // _ONE_SECOND_NS,
                        tz=UTC,
                    ).strftime("%Y/%m/%d/%H")
                )
            except (OverflowError, OSError, ValueError) as error:
                raise RuntimeEvidenceValidationError(
                    "durable received timestamp is out of range"
                ) from error
            if envelope.event_time_ns is not None:
                if first_event_time_ns is None:
                    first_event_time_ns = envelope.event_time_ns
                last_event_time_ns = envelope.event_time_ns
            if envelope.wire_symbol is not None:
                wire_symbols.add(envelope.wire_symbol)
            if envelope.connection_generation is not None:
                connection_generations.add(envelope.connection_generation)
            if envelope.egress_id is not None:
                egress_ids.add(envelope.egress_id)
            if envelope.rest_metadata is not None:
                if envelope.rest_metadata.requested_interval_ns is not None:
                    requested_intervals.add(
                        envelope.rest_metadata.requested_interval_ns
                    )
                if envelope.rest_metadata.effective_interval_ns is not None:
                    effective_intervals.add(
                        envelope.rest_metadata.effective_interval_ns
                    )
            if row_count % _SQLITE_COMMIT_ROWS == 0:
                database.connection.commit()
        assert first_envelope is not None
        assert last_envelope is not None
        manifest_facts = (
            manifest.record_count,
            manifest.first_received_at_ns,
            manifest.last_received_at_ns,
            manifest.first_event_time_ns,
            manifest.last_event_time_ns,
            manifest.writer_sequence_first,
            manifest.writer_sequence_last,
            manifest.wire_symbols,
            manifest.connection_generations,
            manifest.egress_ids,
            manifest.requested_intervals_ns,
            manifest.effective_intervals_ns,
        )
        observed_facts = (
            row_count,
            first_envelope.received_at_ns,
            last_envelope.received_at_ns,
            first_event_time_ns,
            last_event_time_ns,
            first_envelope.writer_sequence,
            last_envelope.writer_sequence,
            tuple(sorted(wire_symbols)),
            tuple(sorted(connection_generations)),
            tuple(sorted(egress_ids)),
            tuple(sorted(requested_intervals)),
            tuple(sorted(effective_intervals)),
        )
        if manifest_facts != observed_facts:
            raise RuntimeEvidenceValidationError(
                "raw manifest facts disagree with decoded rows"
            )
        if (
            content_size != entry_data.content_size_bytes
            or content_digest.hexdigest() != entry_data.content_sha256
        ):
            raise RuntimeEvidenceValidationError(
                "raw decompressed content disagrees with its inventory ref"
            )
        database.connection.commit()
        return row_count, payload_bytes, utc_hours, touched_identities


def _load_bounded_raw_manifest(
    path: Path,
    reference: GateEvidenceDocumentRefV1,
) -> LoadedRawManifest:
    source = _read_regular_file(path, max_bytes=_MAX_MANIFEST_BYTES)
    if (
        len(source) != reference.content_size_bytes
        or hashlib.sha256(source).hexdigest() != reference.content_sha256
    ):
        raise RuntimeEvidenceValidationError(
            "manifest bytes disagree with their inventory ref"
        )
    try:
        manifest = RawManifestV1.model_validate_json(source)
    except (RuntimeError, TypeError, ValueError, ValidationError) as error:
        raise RuntimeEvidenceValidationError(
            "raw manifest structure is invalid"
        ) from error
    canonical = manifest.canonical_bytes()
    if canonical != source:
        raise RuntimeEvidenceValidationError("raw manifest bytes are not canonical")
    return LoadedRawManifest(
        path=path,
        manifest=manifest,
        canonical_bytes=canonical,
        sha256=hashlib.sha256(canonical).hexdigest(),
    )


def _validate_raw_directory_inventory(
    data_root: Path,
    documents: _PrimaryDocuments,
) -> None:
    raw_root = data_root / "raw"
    try:
        if raw_root.resolve(strict=True) != raw_root or not raw_root.is_dir():
            raise RuntimeEvidenceValidationError(
                "raw inventory root must be a real directory"
            )
    except OSError as error:
        raise RuntimeEvidenceValidationError(
            "raw inventory root is unavailable"
        ) from error
    expected_data = {
        entry.data.relative_path for entry in documents.manifest_inventory.manifests
    }
    expected_manifests = {
        entry.manifest.relative_path for entry in documents.manifest_inventory.manifests
    }
    allowed_writer_locks = {
        f"raw/{exchange.value}/.writer.lock" for exchange in CANONICAL_EXCHANGES
    }
    allowed_source_leases = {
        lease_path_for_data(data_root / entry.data.relative_path)
        .relative_to(data_root)
        .as_posix()
        for entry in documents.manifest_inventory.manifests
    }
    observed_data: set[str] = set()
    observed_manifests: set[str] = set()
    entry_limit = max(
        _RAW_DIRECTORY_ENTRY_FLOOR,
        documents.manifest_inventory.file_count * _RAW_DIRECTORY_ENTRY_MULTIPLIER,
    )
    entry_count = 0
    pending = [raw_root]
    while pending:
        directory = pending.pop()
        try:
            if directory.resolve(strict=True) != directory or not directory.is_dir():
                raise RuntimeEvidenceValidationError(
                    "raw inventory directory traverses a symbolic link"
                )
            entries = os.scandir(directory)
        except OSError as error:
            raise RuntimeEvidenceValidationError(
                "raw inventory directory cannot be enumerated"
            ) from error
        with entries:
            for entry in entries:
                entry_count += 1
                if entry_count > entry_limit:
                    raise RuntimeEvidenceValidationError(
                        "raw inventory directory exceeds its bounded entry count"
                    )
                if entry.is_symlink():
                    raise RuntimeEvidenceValidationError(
                        "raw inventory directory contains a symbolic link"
                    )
                path = Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                    continue
                if not entry.is_file(follow_symlinks=False):
                    raise RuntimeEvidenceValidationError(
                        "raw inventory directory contains an unsupported node"
                    )
                relative_path = path.relative_to(data_root).as_posix()
                if entry.name.endswith(".jsonl.zst"):
                    observed_data.add(relative_path)
                elif entry.name.endswith(".manifest.json"):
                    observed_manifests.add(relative_path)
                elif relative_path in allowed_writer_locks | allowed_source_leases:
                    if entry.stat(follow_symlinks=False).st_size != 0:
                        raise RuntimeEvidenceValidationError(
                            "raw inventory lock and lease files must be empty"
                        )
                else:
                    raise RuntimeEvidenceValidationError(
                        "raw inventory directory contains an unclassified file"
                    )
    if observed_data != expected_data or observed_manifests != expected_manifests:
        raise RuntimeEvidenceValidationError(
            "raw directory finals do not exactly match their inventories"
        )


def _validate_raw_evidence(
    data_root: Path,
    documents: _PrimaryDocuments,
    database: _ScratchDatabase,
    plan: WorkloadPlanV1,
) -> _RawValidation:
    _validate_raw_directory_inventory(data_root, documents)
    record_count = 0
    payload_bytes = 0
    utc_hours: set[str] = set()
    touched_identities: set[str] = set()
    codec_by_config: dict[str, tuple[int, bool, bool, int]] = {}
    sync_count = 0
    sync_duration_total_ns = 0
    sync_duration_max_ns = 0
    sync_by_worker: dict[str, list[int]] = {}
    max_line_bytes = (
        max(stream.payload_max_bytes for stream in plan.streams)
        + _RAW_MAX_LINE_OVERHEAD_BYTES
    )
    for entry in documents.manifest_inventory.manifests:
        manifest_path = _referenced_path(data_root, entry.manifest.relative_path)
        loaded = _load_bounded_raw_manifest(manifest_path, entry.manifest)
        if (
            len(loaded.canonical_bytes) != entry.manifest.content_size_bytes
            or loaded.sha256 != entry.manifest.content_sha256
            or loaded.manifest.data_relative_path != entry.data.relative_path
            or loaded.manifest.manifest_relative_path != entry.manifest.relative_path
            or loaded.manifest.record_count != entry.manifest_record_count
            or loaded.manifest.file_size_bytes != entry.data.compressed_size_bytes
            or loaded.manifest.file_sha256 != entry.data.compressed_sha256
        ):
            raise RuntimeEvidenceValidationError(
                "manifest inventory entry disagrees with its source manifest"
            )
        manifest = loaded.manifest
        control_failures = (
            manifest.gap_count,
            manifest.reconnect_count,
            manifest.parse_error_count,
            manifest.checksum_error_count,
            manifest.queue_overflow_count,
            manifest.slo_breach_count,
            manifest.write_failure_count,
            manifest.sync_failure_count,
        )
        if (
            manifest.close_reason
            not in {
                CloseReason.ROTATE_TIME,
                CloseReason.ROTATE_SIZE,
                CloseReason.SHUTDOWN,
            }
            or manifest.durability_measurement != "measured"
            or any(value != 0 for value in control_failures)
            or manifest.control_event_ids != ()
            or manifest.durability_lag_max_ns is None
            or manifest.durability_lag_max_ns
            > documents.workload.workload.qualification.durability_lag_max_ns
            or manifest.sync_count is None
            or manifest.sync_count <= 0
        ):
            raise RuntimeEvidenceValidationError(
                "raw manifest records an error, recovery, or invalid durability fact"
            )
        assert manifest.zstd_level is not None
        assert manifest.max_plain_frame_bytes is not None
        assert manifest.sync_count is not None
        assert manifest.sync_duration_total_ns is not None
        assert manifest.sync_duration_max_ns is not None
        sync_count += manifest.sync_count
        sync_duration_total_ns += manifest.sync_duration_total_ns
        sync_duration_max_ns = max(
            sync_duration_max_ns,
            manifest.sync_duration_max_ns,
        )
        worker_sync = sync_by_worker.setdefault(manifest.worker_instance_id, [0, 0, 0])
        worker_sync[0] += manifest.sync_count
        worker_sync[1] += manifest.sync_duration_total_ns
        worker_sync[2] = max(worker_sync[2], manifest.sync_duration_max_ns)
        codec = (
            manifest.zstd_level,
            manifest.zstd_write_checksum,
            manifest.zstd_write_content_size,
            manifest.max_plain_frame_bytes,
        )
        prior_codec = codec_by_config.setdefault(manifest.config_sha256, codec)
        if prior_codec != codec:
            raise RuntimeEvidenceValidationError(
                "raw manifests disagree on codec facts for one config digest"
            )
        rows, bytes_, hours, identities = _validate_raw_manifest_rows(
            data_root,
            loaded,
            entry.data,
            database,
            manifest_ordinal=entry.ordinal,
            max_line_bytes=max_line_bytes,
        )
        record_count += rows
        payload_bytes += bytes_
        utc_hours.update(hours)
        touched_identities.update(identities)
    database.connection.commit()

    _validate_complete_durable_set(
        database,
        expected_record_count=record_count,
    )
    worker_record_counts = tuple(
        (str(worker), int(worker_record_count))
        for worker, worker_record_count in database.connection.execute(
            """
            SELECT worker.worker_instance_id, COUNT(*)
            FROM durable
            JOIN route USING (route_id)
            JOIN worker USING (worker_id)
            GROUP BY worker.worker_instance_id
            ORDER BY worker.worker_instance_id
            """
        )
    )
    if (
        record_count != documents.raw_inventory.record_count
        or record_count != documents.manifest_inventory.record_count
    ):
        raise RuntimeEvidenceValidationError(
            "accepted, durable, and manifest row sets do not agree"
        )
    return _RawValidation(
        durable_record_count=record_count,
        durable_payload_bytes=payload_bytes,
        received_utc_hours=tuple(sorted(utc_hours)),
        observed_touched_file_identity_count=len(touched_identities),
        sync_count=sync_count,
        sync_duration_total_ns=sync_duration_total_ns,
        sync_duration_max_ns=sync_duration_max_ns,
        worker_sync_facts=tuple(
            (worker, facts[0], facts[1], facts[2])
            for worker, facts in sorted(sync_by_worker.items())
        ),
        worker_record_counts=worker_record_counts,
    )


def _validate_complete_durable_set(
    database: _ScratchDatabase,
    *,
    expected_record_count: int,
) -> None:
    counts = database.connection.execute(
        """
        SELECT
            (SELECT COUNT(*) FROM accepted),
            (SELECT COUNT(*) FROM durable),
            (SELECT COUNT(*) FROM accepted
             LEFT JOIN durable USING (route_id, writer_sequence)
             WHERE durable.route_id IS NULL),
            (SELECT COUNT(*) FROM durable
             LEFT JOIN accepted USING (route_id, writer_sequence)
             WHERE accepted.route_id IS NULL)
        """
    ).fetchone()
    if (
        counts is None
        or int(counts[0]) != expected_record_count
        or int(counts[1]) != expected_record_count
        or int(counts[2]) != 0
        or int(counts[3]) != 0
    ):
        raise RuntimeEvidenceValidationError(
            "accepted and durable row sets do not form an exact join"
        )


def _stream_runtime_summaries(
    plan: WorkloadPlanV1,
    buckets: tuple[GateSecondBucketV1, ...],
) -> tuple[GateStreamRuntimeSummaryV1, ...]:
    summaries: list[GateStreamRuntimeSummaryV1] = []
    for stream_plan in plan.streams:
        stream_buckets = tuple(
            bucket
            for bucket in buckets
            if bucket.stream_group == stream_plan.stream_group
        )
        if len(stream_buckets) != plan.duration_seconds:
            raise RuntimeEvidenceValidationError(
                "recomputed stream buckets do not cover the admission duration"
            )
        burst = stream_buckets[stream_plan.burst_second]
        summaries.append(
            GateStreamRuntimeSummaryV1(
                stream_group=stream_plan.stream_group,
                expected_record_count=stream_plan.expected_record_count,
                expected_payload_bytes=stream_plan.expected_payload_byte_count,
                scheduled_record_count=sum(
                    bucket.scheduled_count for bucket in stream_buckets
                ),
                scheduled_payload_bytes=sum(
                    bucket.scheduled_payload_bytes for bucket in stream_buckets
                ),
                attempted_record_count=sum(
                    bucket.attempted_count for bucket in stream_buckets
                ),
                attempted_payload_bytes=sum(
                    bucket.attempted_payload_bytes for bucket in stream_buckets
                ),
                accepted_record_count=sum(
                    bucket.accepted_count for bucket in stream_buckets
                ),
                accepted_payload_bytes=sum(
                    bucket.accepted_payload_bytes for bucket in stream_buckets
                ),
                early_count=sum(bucket.early_count for bucket in stream_buckets),
                late_count=sum(bucket.late_count for bucket in stream_buckets),
                out_of_window_count=sum(
                    bucket.out_of_window_count for bucket in stream_buckets
                ),
                required_burst_count=stream_plan.required_burst_count,
                scheduled_burst_count=stream_plan.scheduled_burst_count,
                burst_second=stream_plan.burst_second,
                burst_scheduled_count=burst.scheduled_count,
                burst_attempted_count=burst.attempted_count,
                burst_accepted_count=burst.accepted_count,
                burst_admitted_in_actual_second_count=(
                    burst.admitted_in_actual_second_count
                ),
                planned_values_match=(
                    sum(bucket.scheduled_count for bucket in stream_buckets)
                    == stream_plan.expected_record_count
                    and sum(bucket.scheduled_payload_bytes for bucket in stream_buckets)
                    == stream_plan.expected_payload_byte_count
                ),
                admission_values_match=(
                    sum(bucket.attempted_count for bucket in stream_buckets)
                    == sum(bucket.accepted_count for bucket in stream_buckets)
                    == stream_plan.expected_record_count
                    and sum(bucket.attempted_payload_bytes for bucket in stream_buckets)
                    == sum(bucket.accepted_payload_bytes for bucket in stream_buckets)
                    == stream_plan.expected_payload_byte_count
                    and not any(
                        bucket.early_count
                        or bucket.late_count
                        or bucket.out_of_window_count
                        for bucket in stream_buckets
                    )
                ),
                burst_valid=all(
                    value == stream_plan.scheduled_burst_count
                    for value in (
                        burst.scheduled_count,
                        burst.attempted_count,
                        burst.accepted_count,
                        burst.admitted_in_actual_second_count,
                    )
                ),
            )
        )
    return tuple(summaries)


def _build_runtime_summary(
    plan: WorkloadPlanV1,
    documents: _PrimaryDocuments,
    trace: _TraceValidation,
    samples: _SampleValidation,
    raw: _RawValidation,
    database: _ScratchDatabase,
) -> GateRuntimeSummaryV1:
    streams = _stream_runtime_summaries(plan, trace.buckets)
    aggregate = samples.final_worker_aggregate
    if (
        raw.sync_count,
        raw.sync_duration_total_ns,
        raw.sync_duration_max_ns,
    ) != (
        aggregate.sync_count,
        aggregate.sync_duration_total_ns,
        aggregate.sync_duration_max_ns,
    ):
        raise RuntimeEvidenceValidationError(
            "raw manifest and worker sync facts do not agree"
        )
    if raw.worker_sync_facts != samples.worker_sync_facts:
        raise RuntimeEvidenceValidationError(
            "raw manifest and per-worker sync facts do not agree"
        )
    if raw.worker_record_counts != samples.worker_record_counts:
        raise RuntimeEvidenceValidationError(
            "raw rows and per-worker final record counts do not agree"
        )
    unique_accepted = database.connection.execute(
        "SELECT COUNT(*) FROM accepted"
    ).fetchone()
    assert unique_accepted is not None
    scheduled_count = sum(item.scheduled_record_count for item in streams)
    scheduled_bytes = sum(item.scheduled_payload_bytes for item in streams)
    attempted_count = sum(item.attempted_record_count for item in streams)
    attempted_bytes = sum(item.attempted_payload_bytes for item in streams)
    return GateRuntimeSummaryV1(
        expected_record_count=plan.expected_record_count,
        expected_payload_bytes=plan.expected_payload_byte_count,
        scheduled_record_count=scheduled_count,
        scheduled_payload_bytes=scheduled_bytes,
        attempted_record_count=attempted_count,
        attempted_payload_bytes=attempted_bytes,
        accepted_record_count=trace.accepted_record_count,
        accepted_payload_bytes=trace.accepted_payload_bytes,
        durable_record_count=raw.durable_record_count,
        durable_payload_bytes=raw.durable_payload_bytes,
        durability_sample_count=(
            samples.final_worker_aggregate.durability_sample_count
        ),
        manifest_record_count=documents.manifest_inventory.record_count,
        raw_file_count=documents.raw_inventory.file_count,
        manifest_file_count=documents.manifest_inventory.file_count,
        declared_file_identity_count=plan.declared_file_identity_count,
        expected_touched_file_identity_count=(
            plan.expected_touched_file_identity_count
        ),
        observed_touched_file_identity_count=(raw.observed_touched_file_identity_count),
        accepted_identity_count=trace.accepted_record_count,
        unique_accepted_identity_count=int(unique_accepted[0]),
        early_count=trace.early_count,
        late_count=trace.late_count,
        out_of_window_count=trace.out_of_window_count,
        received_utc_hours=raw.received_utc_hours,
        stream_summaries=streams,
        final_worker_aggregate=samples.final_worker_aggregate,
        resource_summary=samples.resource_summary,
        storage_health_summary=samples.storage_health_summary,
    )


def _runtime_predicates_pass(
    run_index: GateRunIndexV1,
    documents: _PrimaryDocuments,
    plan: WorkloadPlanV1,
    summary: GateRuntimeSummaryV1,
    target_reprobe: GateTargetReprobeV1 | None,
) -> bool:
    limits = documents.workload.workload.qualification
    aggregate = summary.final_worker_aggregate
    resource = summary.resource_summary
    health = summary.storage_health_summary
    interval_ns = limits.storage_health_sample_interval_seconds * _ONE_SECOND_NS
    max_gap_ns = limits.storage_health_max_gap_seconds * _ONE_SECOND_NS
    exact_counts = (
        summary.scheduled_record_count
        == summary.attempted_record_count
        == summary.accepted_record_count
        == summary.durable_record_count
        == summary.durability_sample_count
        == summary.manifest_record_count
        == summary.expected_record_count
    )
    exact_payloads = (
        summary.scheduled_payload_bytes
        == summary.attempted_payload_bytes
        == summary.accepted_payload_bytes
        == summary.durable_payload_bytes
        == summary.expected_payload_bytes
    )
    worker_valid = (
        aggregate.worker_count == 5
        and aggregate.accepted_record_count == summary.expected_record_count
        and aggregate.durable_record_count == summary.expected_record_count
        and aggregate.durability_sample_count == summary.expected_record_count
        and aggregate.unpersisted_record_count == 0
        and aggregate.uncertain_record_count == 0
        and aggregate.normal_overflow_count == 0
        and aggregate.control_overflow_count == 0
        and aggregate.not_accepting_count == 0
        and aggregate.slo_breach_count == 0
        and aggregate.write_failure_count == 0
        and aggregate.sync_failure_count == 0
        and aggregate.publication_failure_count == 0
        and aggregate.retiring_generation_count_peak == 0
        and aggregate.durability_lag_max_ns is not None
        and aggregate.durability_lag_max_ns <= limits.durability_lag_max_ns
        and aggregate.active_logical_generation_count_peak
        == summary.expected_touched_file_identity_count
    )
    resource_valid = (
        resource.resource_trend_valid
        and resource.first_request_monotonic_ns
        <= documents.candidate.admission_started_monotonic_ns + interval_ns
        and resource.final_completion_monotonic_ns
        >= documents.candidate.admission_scheduled_end_monotonic_ns
        and resource.coverage_ns
        >= max(0, documents.candidate.duration_ns - interval_ns)
        and resource.sample_max_gap_ns <= max_gap_ns
        and resource.rss_peak_bytes <= limits.max_rss_bytes
        and resource.rss_slope_bytes_per_minute is not None
        and resource.rss_slope_bytes_per_minute <= limits.max_rss_slope_bytes_per_minute
        and resource.open_fds_peak <= limits.max_open_fds
        and resource.fd_growth_after_warmup is not None
        and resource.fd_growth_after_warmup <= limits.max_fd_growth_after_warmup
    )
    health_valid = (
        health.sample_count_valid
        and health.coverage_valid
        and health.workers_healthy
        and health.sample_max_gap_ns <= max_gap_ns
    )
    stream_valid = all(
        item.planned_values_match and item.admission_values_match and item.burst_valid
        for item in summary.stream_summaries
    )
    identity_valid = (
        summary.accepted_identity_count
        == summary.unique_accepted_identity_count
        == summary.expected_record_count
        and summary.observed_touched_file_identity_count
        == summary.expected_touched_file_identity_count
    )
    timing_valid = (
        summary.early_count == 0
        and summary.late_count == 0
        and summary.out_of_window_count == 0
        and len(summary.received_utc_hours) == 1
        and summary.received_utc_hours[0]
        == documents.candidate.declared_admission_utc_hour
    )
    mode_valid = True
    if run_index.mode == "qualification":
        mode_valid = (
            documents.workload.sha256 == RESEARCH_DEFAULT_V1_SHA256
            and documents.candidate.multiplier >= 2
            and documents.candidate.duration_ns >= 600 * _ONE_SECOND_NS
            and plan.declared_file_identity_count == 5 + plan.multiplier * 1_750
            and plan.expected_touched_file_identity_count
            == plan.declared_file_identity_count
            and target_reprobe is not None
            and target_reprobe.reprobe_valid
        )
    return all(
        (
            exact_counts,
            exact_payloads,
            worker_valid,
            resource_valid,
            health_valid,
            stream_valid,
            identity_valid,
            timing_valid,
            mode_valid,
        )
    )


def _self_hashed(model_type: type[_ModelT], unsigned: dict[str, object]) -> _ModelT:
    digest = hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest()
    return model_type.model_validate_json(
        encode_json({**unsigned, "sha256": digest}),
        strict=True,
    )


def _document_ref(path: Path, *, relative_path: str) -> GateEvidenceDocumentRefV1:
    source = _read_regular_file(path, max_bytes=_MAX_DOCUMENT_BYTES)
    return GateEvidenceDocumentRefV1(
        relative_path=relative_path,
        content_size_bytes=len(source),
        content_sha256=hashlib.sha256(source).hexdigest(),
    )


def _load_direct_model(path: Path, model_type: type[_ModelT]) -> _ModelT:
    source = _read_regular_file(path, max_bytes=_MAX_DOCUMENT_BYTES)
    try:
        model = model_type.model_validate_json(source, strict=True)
    except (TypeError, ValueError, ValidationError) as error:
        raise RuntimeEvidenceValidationError(
            f"existing {path.name} is invalid"
        ) from error
    canonical = getattr(model, "canonical_bytes", None)
    if not callable(canonical) or canonical() != source:
        raise RuntimeEvidenceValidationError(f"existing {path.name} is not canonical")
    return model


def _publish_document_no_replace(
    path: Path,
    content: bytes,
    *,
    phase_prefix: str,
) -> None:
    temporary = path.parent / f".{path.name}.partial.{uuid.uuid4().hex}"
    source_fd: int | None = None
    primary_error: BaseException | None = None
    try:
        atomic_write_and_sync_json_exclusive(
            temporary,
            content,
            phase_prefix=phase_prefix,
        )
        source_fd = open_readonly_nofollow(temporary)
        publish_no_replace(
            temporary,
            path,
            capability=NoReplaceCapability.HARDLINK,
            expected_source_fd=source_fd,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        if source_fd is not None:
            try:
                os.close(source_fd)
            except BaseException as error:  # noqa: BLE001 - preserve primary failure
                cleanup_errors.append(error)
        try:
            temporary.unlink(missing_ok=True)
            fsync_directory(path.parent)
        except BaseException as error:  # noqa: BLE001 - preserve primary failure
            cleanup_errors.append(error)
        if primary_error is None and cleanup_errors:
            raise cleanup_errors[0]
        if primary_error is not None and cleanup_errors:
            primary_error.add_note(
                "runtime document cleanup also failed: "
                + ", ".join(type(error).__name__ for error in cleanup_errors)
            )


def _publish_runtime_index(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    run_index_path: Path,
    receipt: GateRuntimeReceiptV1,
) -> None:
    receipt_path = evidence_root / _RUNTIME_RECEIPT_NAME
    runtime_index_path = evidence_root / _RUNTIME_INDEX_NAME
    unsigned: dict[str, object] = {
        "schema_version": 1,
        "record_type": "gate_runtime_index_v1",
        "run_id": run_index.run_id,
        "status": "complete",
        "mode": run_index.mode,
        "run_index": _document_ref(
            run_index_path,
            relative_path=_RUN_INDEX_NAME,
        ).model_dump(mode="json"),
        "runtime_receipt": _document_ref(
            receipt_path,
            relative_path=_RUNTIME_RECEIPT_NAME,
        ).model_dump(mode="json"),
    }
    runtime_index = _self_hashed(GateRuntimeIndexV1, unsigned)
    if runtime_index_path.exists():
        existing = _load_direct_model(runtime_index_path, GateRuntimeIndexV1)
        if existing != runtime_index:
            raise RuntimeEvidenceValidationError(
                "existing runtime-index.json conflicts with verified predecessors"
            )
        return
    _publish_document_no_replace(
        runtime_index_path,
        runtime_index.canonical_bytes(),
        phase_prefix="gate_runtime_index",
    )


def _publish_runtime_receipt(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    run_index_path: Path,
    receipt: GateRuntimeReceiptV1,
) -> None:
    _publish_document_no_replace(
        evidence_root / _RUNTIME_RECEIPT_NAME,
        receipt.canonical_bytes(),
        phase_prefix="gate_runtime_receipt",
    )
    _publish_runtime_index(
        evidence_root,
        run_index,
        run_index_path,
        receipt,
    )


def _load_existing_receipt(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    run_index_source: bytes,
) -> GateRuntimeReceiptV1 | None:
    receipt_path = evidence_root / _RUNTIME_RECEIPT_NAME
    runtime_index_path = evidence_root / _RUNTIME_INDEX_NAME
    if runtime_index_path.exists() and not receipt_path.exists():
        raise RuntimeEvidenceValidationError(
            "runtime-index.json exists without its receipt predecessor"
        )
    if not receipt_path.exists():
        return None
    receipt = _load_direct_model(receipt_path, GateRuntimeReceiptV1)
    expected = (
        run_index.run_id,
        run_index.mode,
        run_index.sha256,
        hashlib.sha256(run_index_source).hexdigest(),
        run_index.expected_target_id,
    )
    observed = (
        receipt.run_id,
        receipt.mode,
        receipt.run_index_sha256,
        receipt.run_index_content_sha256,
        receipt.expected_target_id,
    )
    if observed != expected:
        raise RuntimeEvidenceValidationError(
            "existing runtime-receipt.json binds a different run"
        )
    return receipt


def _target_reprobe(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    target_probe: TargetProbePort | None,
) -> GateTargetReprobeV1 | None:
    if run_index.mode == "functional":
        if target_probe is not None:
            raise RuntimeEvidenceValidationError(
                "functional runtime evidence forbids a target probe"
            )
        return None
    if target_probe is None:
        raise RuntimeEvidenceValidationError(
            "qualification runtime evidence requires a target probe"
        )
    assert run_index.target_declaration is not None
    assert run_index.expected_target_id is not None
    declaration, _ = _load_referenced_model(
        evidence_root,
        run_index.target_declaration,
        GateTargetV1,
    )
    if (
        declaration.target_id != run_index.expected_target_id
        or declaration.data_root.root != run_index.data_root
        or declaration.state_root.root != run_index.state_root
    ):
        raise RuntimeEvidenceValidationError(
            "target declaration disagrees with qualification claims"
        )
    reprobe = target_probe(
        declaration,
        expected_target_id=run_index.expected_target_id,
    )
    if type(reprobe) is not GateTargetReprobeV1:
        raise RuntimeEvidenceValidationError(
            "target probe did not return GateTargetReprobeV1"
        )
    try:
        verified = GateTargetReprobeV1.model_validate(
            reprobe.model_dump(mode="python"),
            strict=True,
        )
    except ValidationError as error:
        raise RuntimeEvidenceValidationError(
            "target probe returned structurally invalid evidence"
        ) from error
    if (
        verified.target_id != declaration.target_id
        or verified.expected_target_id != run_index.expected_target_id
        or verified.declaration_sha256 != declaration.sha256
        or verified.data_root.root != run_index.data_root
        or verified.state_root.root != run_index.state_root
    ):
        raise RuntimeEvidenceValidationError(
            "target re-probe does not bind the loaded declaration and run"
        )
    return verified


def _immutable_root_projection(root: object) -> dict[str, object]:
    if not isinstance(root, BaseModel):
        raise TypeError("target root must be a Pydantic model")
    projection = root.model_dump(mode="json")
    projection.pop("observed_available_bytes", None)
    return cast(dict[str, object], projection)


def _target_reprobe_for_attempt(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    target_probe: TargetProbePort | None,
    existing_receipt: GateRuntimeReceiptV1 | None,
) -> GateTargetReprobeV1 | None:
    fresh = _target_reprobe(evidence_root, run_index, target_probe)
    if existing_receipt is None:
        return fresh
    recorded = existing_receipt.target_reprobe
    if run_index.mode == "functional":
        if recorded is not None or fresh is not None:
            raise RuntimeEvidenceValidationError(
                "functional receipt contains unexpected target evidence"
            )
        return None
    if recorded is None or fresh is None:
        raise RuntimeEvidenceValidationError(
            "qualification receipt lacks reusable target evidence"
        )
    recorded_binding = (
        recorded.target_id,
        recorded.expected_target_id,
        recorded.declaration_sha256,
        _immutable_root_projection(recorded.data_root),
        _immutable_root_projection(recorded.state_root),
    )
    fresh_binding = (
        fresh.target_id,
        fresh.expected_target_id,
        fresh.declaration_sha256,
        _immutable_root_projection(fresh.data_root),
        _immutable_root_projection(fresh.state_root),
    )
    if recorded_binding != fresh_binding:
        raise RuntimeEvidenceValidationError(
            "fresh target re-probe disagrees with the existing receipt"
        )
    if recorded.reprobe_valid and not fresh.reprobe_valid:
        raise RuntimeEvidenceValidationError(
            "fresh target re-probe no longer supports the existing receipt"
        )
    return recorded


def _runtime_receipt(
    run_index: GateRunIndexV1,
    run_index_source: bytes,
    *,
    recomputed_summary: GateRuntimeSummaryV1 | None,
    target_reprobe: GateTargetReprobeV1 | None,
    failure_codes: tuple[str, ...],
    evidence_integrity_valid: bool,
    candidate_summary_matches: bool,
    runtime_predicates_passed: bool,
    verified_at_unix_ns: int,
) -> GateRuntimeReceiptV1:
    runtime_evidence_valid = (
        evidence_integrity_valid
        and candidate_summary_matches
        and runtime_predicates_passed
        and recomputed_summary is not None
        and (target_reprobe is None or target_reprobe.reprobe_valid)
    )
    unsigned: dict[str, object] = {
        "schema_version": 1,
        "record_type": "gate_runtime_receipt_v1",
        "verifier_version": "gate-runtime-verifier-v1",
        "verified_at_unix_ns": verified_at_unix_ns,
        "run_id": run_index.run_id,
        "mode": run_index.mode,
        "run_index_sha256": run_index.sha256,
        "run_index_content_sha256": hashlib.sha256(run_index_source).hexdigest(),
        "expected_target_id": run_index.expected_target_id,
        "recomputed_summary": (
            None
            if recomputed_summary is None
            else recomputed_summary.model_dump(mode="json")
        ),
        "target_reprobe": (
            None if target_reprobe is None else target_reprobe.model_dump(mode="json")
        ),
        "failure_codes": sorted(set(failure_codes)),
        "evidence_integrity_valid": evidence_integrity_valid,
        "candidate_summary_matches": candidate_summary_matches,
        "runtime_predicates_passed": runtime_predicates_passed,
        "runtime_evidence_valid": runtime_evidence_valid,
        "qualification_runtime_accepted": (
            run_index.mode == "qualification" and runtime_evidence_valid
        ),
    }
    return _self_hashed(GateRuntimeReceiptV1, unsigned)


def _finish_scratch_database(database: _ScratchDatabase) -> None:
    database.connection.commit()
    checkpoint = database.connection.execute("PRAGMA wal_checkpoint(FULL)").fetchone()
    if checkpoint is None or int(checkpoint[0]) != 0:
        raise RuntimeEvidenceValidationError(
            "runtime verifier SQLite WAL checkpoint did not complete"
        )
    database.close()


def _publish_or_reuse_receipt(
    evidence_root: Path,
    run_index: GateRunIndexV1,
    run_index_path: Path,
    receipt: GateRuntimeReceiptV1,
    existing: GateRuntimeReceiptV1 | None,
) -> None:
    if existing is None:
        _publish_runtime_receipt(
            evidence_root,
            run_index,
            run_index_path,
            receipt,
        )
        return
    if receipt != existing:
        raise RuntimeEvidenceValidationError(
            "existing runtime receipt disagrees with fresh recomputation"
        )
    _publish_runtime_index(
        evidence_root,
        run_index,
        run_index_path,
        existing,
    )


def validate_runtime_evidence(
    run_index_path: Path,
    *,
    target_probe: TargetProbePort | None,
) -> GateRuntimeReceiptV1:
    if target_probe is not None and not callable(target_probe):
        raise TypeError("target_probe must be callable or None")
    trusted_path = _trusted_run_index_path(run_index_path)
    run_index, run_index_source = _load_run_index(trusted_path)
    evidence_root = trusted_path.parent
    data_root = _trusted_root(run_index.data_root, label="data root")
    state_root = _trusted_root(run_index.state_root, label="state root")
    if run_index.mode == "functional" and target_probe is not None:
        raise RuntimeEvidenceValidationError(
            "functional runtime evidence forbids a target probe"
        )
    if run_index.mode == "qualification" and target_probe is None:
        raise RuntimeEvidenceValidationError(
            "qualification runtime evidence requires a target probe"
        )
    existing = _load_existing_receipt(
        evidence_root,
        run_index,
        run_index_source,
    )
    verified_at_unix_ns = (
        time.time_ns() if existing is None else existing.verified_at_unix_ns
    )
    receipt: GateRuntimeReceiptV1
    try:
        target_reprobe = _target_reprobe_for_attempt(
            evidence_root,
            run_index,
            target_probe,
            existing,
        )
    except RuntimeEvidenceValidationError:
        receipt = _runtime_receipt(
            run_index,
            run_index_source,
            recomputed_summary=None,
            target_reprobe=None,
            failure_codes=("target_evidence_invalid",),
            evidence_integrity_valid=False,
            candidate_summary_matches=False,
            runtime_predicates_passed=False,
            verified_at_unix_ns=verified_at_unix_ns,
        )
        _publish_or_reuse_receipt(
            evidence_root,
            run_index,
            trusted_path,
            receipt,
            existing,
        )
        return receipt
    database = _ScratchDatabase.open(state_root)
    try:
        try:
            documents = _load_primary_documents(
                evidence_root,
                run_index,
                target_declaration_sha256=(
                    None
                    if target_reprobe is None
                    else target_reprobe.declaration_sha256
                ),
            )
            plan = build_workload_plan(
                documents.workload,
                multiplier=documents.candidate.multiplier,
                duration_ns=documents.candidate.duration_ns,
            )
            trace = _validate_trace(
                evidence_root,
                run_index,
                documents.candidate,
                plan,
                database,
            )
            _validate_bucket_artifact(
                evidence_root,
                run_index.second_bucket_artifact,
                trace.buckets,
            )
            samples = _validate_sample_artifacts(
                evidence_root,
                run_index,
                documents,
                database,
            )
            raw = _validate_raw_evidence(data_root, documents, database, plan)
            summary = _build_runtime_summary(
                plan,
                documents,
                trace,
                samples,
                raw,
                database,
            )
            runtime_predicates_passed = _runtime_predicates_pass(
                run_index,
                documents,
                plan,
                summary,
                target_reprobe,
            )
            candidate_summary_matches = (
                documents.candidate.runtime_summary == summary
                and documents.candidate.candidate_runtime_passed
                == runtime_predicates_passed
            )
            failure_codes: list[str] = []
            if not candidate_summary_matches:
                failure_codes.append("candidate_summary_mismatch")
            if not runtime_predicates_passed:
                failure_codes.append("runtime_predicate_failed")
            if target_reprobe is not None and not target_reprobe.reprobe_valid:
                failure_codes.append("target_reprobe_failed")
            receipt = _runtime_receipt(
                run_index,
                run_index_source,
                recomputed_summary=summary,
                target_reprobe=target_reprobe,
                failure_codes=tuple(failure_codes),
                evidence_integrity_valid=True,
                candidate_summary_matches=candidate_summary_matches,
                runtime_predicates_passed=runtime_predicates_passed,
                verified_at_unix_ns=verified_at_unix_ns,
            )
        except RuntimeEvidenceValidationError:
            database.connection.rollback()
            receipt = _runtime_receipt(
                run_index,
                run_index_source,
                recomputed_summary=None,
                target_reprobe=target_reprobe,
                failure_codes=("evidence_integrity_invalid",),
                evidence_integrity_valid=False,
                candidate_summary_matches=False,
                runtime_predicates_passed=False,
                verified_at_unix_ns=verified_at_unix_ns,
            )
        except (OSError, sqlite3.Error, ValueError, zstandard.ZstdError) as error:
            database.connection.rollback()
            receipt = _runtime_receipt(
                run_index,
                run_index_source,
                recomputed_summary=None,
                target_reprobe=target_reprobe,
                failure_codes=("evidence_integrity_invalid",),
                evidence_integrity_valid=False,
                candidate_summary_matches=False,
                runtime_predicates_passed=False,
                verified_at_unix_ns=verified_at_unix_ns,
            )
            error.add_note("runtime evidence validation failed closed")
        _finish_scratch_database(database)
        _publish_or_reuse_receipt(
            evidence_root,
            run_index,
            trusted_path,
            receipt,
            existing,
        )
    except BaseException:
        try:
            database.close()
        except sqlite3.Error:
            pass
        raise
    database.cleanup()
    fsync_directory(state_root)
    return receipt


__all__ = [
    "RuntimeEvidenceValidationError",
    "TargetProbePort",
    "validate_runtime_evidence",
]
