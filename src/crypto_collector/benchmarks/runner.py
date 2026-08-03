from __future__ import annotations

import asyncio
import gc
import hashlib
import multiprocessing
import os
import queue
import re
import resource
import sqlite3
import stat
import sys
import time
import uuid
from collections.abc import Callable, Generator, Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from itertools import groupby, zip_longest
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Literal, Self, TypeVar, cast

import orjson
import zstandard
from pydantic import BaseModel, ConfigDict, model_validator

from crypto_collector.benchmarks.aggregation import (
    aggregate_final_worker_snapshots,
    summarize_resources,
    summarize_storage_health,
    validate_worker_rounds,
)
from crypto_collector.benchmarks.artifacts import (
    StreamingJsonlZstdWriter,
    build_admission_trace_set,
    iter_merged_trace_partitions,
    write_jsonl_zstd,
)
from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    RAW_RECORD_FRAME_MIN_BYTES,
    RAW_RECORD_FRAME_OVERHEAD_BYTES,
    GateAdmissionTraceV1,
    GateArtifactRefV1,
    GateCandidateReportV1,
    GateEvidenceDocumentRefV1,
    GateExchangeArtifactPartitionV1,
    GateManifestInventoryEntryV1,
    GateManifestInventoryV1,
    GateProcessKeyV1,
    GateProcessResourceSampleV1,
    GateRawInventoryV1,
    GateResourceSamplingRoundV1,
    GateRunIndexV1,
    GateRuntimeSummaryV1,
    GateSamplingRoundV1,
    GateSecondBucketV1,
    GateStorageHealthSampleV1,
    GateStreamRuntimeSummaryV1,
    GateWorkerHealthV1,
    GateWorkerKeyV1,
    GateWorkerSampleV1,
    LogicalStream,
    StreamGroup,
)
from crypto_collector.benchmarks.oracle import (
    _TRUSTED_NATIVE_DRAFT_FIELDS,
    _TRUSTED_REST_METADATA_FIELDS,
    PlannedEventV1,
    WorkloadPlanV1,
    _construct_trusted_model,
    build_native_draft,
    build_workload_plan,
    iter_exchange_plan_events,
    iter_plan_events,
)
from crypto_collector.benchmarks.runtime_verifier import evaluate_runtime_candidate
from crypto_collector.benchmarks.target import load_target_declaration, reprobe_target
from crypto_collector.benchmarks.workload import (
    RESEARCH_DEFAULT_V1_SHA256,
    LoadedWorkload,
    load_workload,
)
from crypto_collector.config.models import IngressConfig, WriterConfig
from crypto_collector.config.primitives import parse_duration_ns
from crypto_collector.domain.clock import SystemClock
from crypto_collector.domain.envelope import (
    NativeEventDraft,
    RestMetadata,
    SourceContext,
)
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.domain.types import CloseReason, Exchange, Market
from crypto_collector.storage.manifest import (
    RawManifestV1,
    lease_path_for_data,
    load_raw_manifest,
)
from crypto_collector.storage.models import (
    AcceptedRecordIdentityV1,
    EnqueueStatus,
    WriterLifecycle,
)
from crypto_collector.storage.raw_writer import (
    NoReplaceCapability,
    open_readonly_nofollow,
    publish_no_replace,
    size_and_sha256_fd,
)
from crypto_collector.storage.serialize import decode_envelope_jsonl, encode_envelope
from crypto_collector.storage.service import RawWriterService

EvidenceMode = Literal["functional", "qualification"]
_ThreadResultT = TypeVar("_ThreadResultT")
_ONE_SECOND_NS = 1_000_000_000
_ONE_HOUR_NS = 3_600 * _ONE_SECOND_NS
_FUNCTIONAL_DURABILITY_CRITICAL_NS = 7 * 24 * _ONE_HOUR_NS
_START_MARGIN_NS = 30 * _ONE_SECOND_NS
_CHILD_READY_TIMEOUT_SECONDS = 300.0
_QUALIFICATION_CHILD_FINISH_GRACE_SECONDS = 180.0
_FUNCTIONAL_CHILD_FINISH_GRACE_SECONDS = 24 * 60 * 60.0
_QUALIFICATION_CHILD_CLOSE_GRACE_NS = 120 * _ONE_SECOND_NS
_FUNCTIONAL_CHILD_CLOSE_GRACE_NS = 24 * 60 * 60 * _ONE_SECOND_NS
_CHILD_COMMAND_POLL_SECONDS = 0.05
_QUALIFICATION_CHILD_FINAL_COMMAND_TIMEOUT_SECONDS = 60.0
_QUALIFICATION_PARENT_COORDINATION_TIMEOUT_SECONDS = 30.0
_CHILD_INCOMPLETE_TIMEOUT_SECONDS = 10.0
_STATUS_QUEUE_MAX_MESSAGES = 256
_TRACE_MAX_LINE_BYTES = 64 * 1024
_SPOOL_MAX_LINE_BYTES = 2 * 1024 * 1024
_SPOOL_ZSTD_LEVEL = 1
_SPOOL_LOOKAHEAD_SECONDS = 3
_ADMISSION_QUEUE_MAX_CHUNKS = 2
_ADMISSION_CHUNK_MAX_ROWS = 1_024
_ADMISSION_CHUNK_MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
_ADMISSION_ABORT_CHECK_RECORDS = 256
_ADMISSION_GC_PAUSE_MIN_RECORDS = 10_000
_ADMISSION_YIELD_BYTES = 1 * 1024 * 1024
_TRACE_WRITE_CHUNK_ROWS = 1_024
_ARTIFACT_ZSTD_LEVEL = 3
_RAW_RECORD_FRAME_OVERHEAD_BYTES = RAW_RECORD_FRAME_OVERHEAD_BYTES


def _child_finish_grace_seconds(mode: EvidenceMode) -> float:
    return (
        _QUALIFICATION_CHILD_FINISH_GRACE_SECONDS
        if mode == "qualification"
        else _FUNCTIONAL_CHILD_FINISH_GRACE_SECONDS
    )


def _child_close_grace_ns(mode: EvidenceMode) -> int:
    return (
        _QUALIFICATION_CHILD_CLOSE_GRACE_NS
        if mode == "qualification"
        else _FUNCTIONAL_CHILD_CLOSE_GRACE_NS
    )


def _child_final_command_timeout_seconds(mode: EvidenceMode) -> float:
    return (
        _QUALIFICATION_CHILD_FINAL_COMMAND_TIMEOUT_SECONDS
        if mode == "qualification"
        else _FUNCTIONAL_CHILD_FINISH_GRACE_SECONDS
    )


def _parent_coordination_timeout_seconds(mode: EvidenceMode) -> float:
    return (
        _QUALIFICATION_PARENT_COORDINATION_TIMEOUT_SECONDS
        if mode == "qualification"
        else _FUNCTIONAL_CHILD_FINISH_GRACE_SECONDS
    )


_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_VM_RSS = re.compile(rb"^VmRSS:\s+([0-9]+)\s+kB$")
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
_METRIC_STREAM_ALLOWLIST = (
    "_control",
    "bbo",
    "book_deep_snapshot",
    "book_live",
    "candle_1m",
    "funding",
    "open_interest",
    "ticker",
    "trade",
)


class RunnerPreflightError(ValueError):
    """The writer gate cannot safely start with the supplied inputs."""


class WriterGateRunError(RuntimeError):
    """A started writer gate failed closed before authoritative publication."""


@dataclass(frozen=True, slots=True)
class QualificationClaims:
    target_declaration_path: Path
    expected_target_id: str
    expected_image_id: str
    runtime_image_id: str
    implementation_source_commit: str
    collector_wheel_sha256: str
    requirements_lock_sha256: str
    dockerfile_sha256: str


@dataclass(frozen=True, slots=True)
class RunRequest:
    workload_path: Path
    multiplier: int
    duration_ns: int
    evidence_root: Path
    report_path: Path
    functional_only: bool
    data_root: Path | None = None
    state_root: Path | None = None
    qualification: QualificationClaims | None = None


@dataclass(frozen=True, slots=True)
class PreparedRun:
    request: RunRequest
    mode: EvidenceMode
    evidence_root: Path
    data_root: Path
    state_root: Path
    report_path: Path
    workload: LoadedWorkload
    plan: WorkloadPlanV1
    writer_config: WriterConfig
    ingress_config: IngressConfig
    config_sha256: str
    target_declaration_source: bytes | None


@dataclass(frozen=True, slots=True)
class WriterRunResult:
    run_index_path: Path
    report_path: Path
    run_index: GateRunIndexV1
    candidate_report: GateCandidateReportV1
    child_process_count: int


@dataclass(frozen=True, slots=True)
class _ChildSpec:
    workload_path: str
    workload_sha256: str
    multiplier: int
    duration_ns: int
    data_root: str
    state_root: str
    evidence_root: str
    exchange: str
    mode: EvidenceMode
    config_sha256: str
    workload_plan_sha256: str
    plan_header_bytes: bytes
    stream_summary_bytes: tuple[bytes, ...]


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
        self, stream_group: StreamGroup, second_index: int
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
class _WorkerJoinFacts:
    worker_instance_id: str
    config_sha256: str
    config_generation: int
    accepted_record_count: int
    durable_record_count: int
    acceptance_ordinal_min: int
    acceptance_ordinal_max: int


@dataclass(frozen=True, slots=True)
class _JoinFacts:
    unique_accepted_count: int
    durable_record_count: int
    durable_payload_bytes: int
    touched_identity_count: int
    received_utc_hours: tuple[str, ...]
    workers: tuple[_WorkerJoinFacts, ...]


class _PreparedAdmissionWireV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal[1] = 1
    record_type: Literal["writer_gate_prepared_admission_v1"] = (
        "writer_gate_prepared_admission_v1"
    )
    planned_event_id: str
    stream_group: StreamGroup
    logical_stream: LogicalStream
    exchange: Exchange
    market: Market | None
    instrument_key: str | None
    canonical_identity: str
    identity_index: int
    local_sequence: int
    due_offset_ns: int
    deadline_offset_ns: int
    payload_bytes: int
    payload_sha256: str
    draft_template: NativeEventDraft
    source: SourceContext
    shard: str

    @model_validator(mode="after")
    def validate_prepared_admission(self) -> Self:
        if (
            self.identity_index < 0
            or self.local_sequence < 0
            or self.due_offset_ns < 0
            or self.deadline_offset_ns != self.due_offset_ns + _ONE_SECOND_NS
            or self.payload_bytes <= 0
            or not _SHA256.fullmatch(self.planned_event_id)
            or not _SHA256.fullmatch(self.payload_sha256)
        ):
            raise ValueError("prepared admission scalar facts are invalid")
        draft = self.draft_template
        draft_facts = (
            draft.exchange,
            draft.market,
            draft.instrument_key,
            draft.logical_stream,
        )
        planned_facts = (
            self.exchange,
            self.market,
            self.instrument_key,
            self.logical_stream,
        )
        expected_shard = (
            "_control"
            if self.logical_stream == "_control"
            else f"gate-{self.logical_stream}-{self.identity_index}"
        )
        if draft_facts != planned_facts or self.shard != expected_shard:
            raise ValueError("prepared admission route facts disagree")
        payload = encode_json(draft.payload)
        if (
            len(payload) != self.payload_bytes
            or hashlib.sha256(payload).hexdigest() != self.payload_sha256
            or not isinstance(draft.payload, dict)
            or draft.payload.get("event_id") != self.planned_event_id
        ):
            raise ValueError("prepared admission payload facts disagree")
        if self.logical_stream == "_control":
            if draft.event_time_ns is not None or draft.rest_metadata is not None:
                raise ValueError("prepared control template has event time facts")
        else:
            if draft.event_time_ns != self.due_offset_ns:
                raise ValueError("prepared event template is not zero-based")
            rest = draft.rest_metadata
            if rest is not None and (
                rest.request_started_at_ns != self.due_offset_ns
                or rest.request_ended_at_ns != self.due_offset_ns
            ):
                raise ValueError("prepared REST template is not zero-based")
        draft.validate_source(self.source)
        return self

    def canonical_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="json")) + b"\n"


@dataclass(frozen=True, slots=True)
class _AdmissionSpoolPartition:
    second_index: int
    path: Path | None
    row_count: int
    pause_cyclic_gc: bool
    content_size_bytes: int
    content_sha256: str
    compressed_size_bytes: int
    compressed_sha256: str


@dataclass(frozen=True, slots=True)
class _PreparedAdmission:
    planned_event_id: str
    stream_group: StreamGroup
    logical_stream: LogicalStream
    exchange: Exchange
    market: Market | None
    instrument_key: str | None
    canonical_identity: str
    identity_index: int
    local_sequence: int
    due_offset_ns: int
    deadline_offset_ns: int
    payload_bytes: int
    payload_sha256: str
    draft: NativeEventDraft
    source: SourceContext
    shard: str


@dataclass(frozen=True, slots=True)
class _AdmissionChunk:
    second_index: int
    chunk_index: int
    rows: tuple[_PreparedAdmission, ...]
    payload_bytes: int
    last_for_second: bool
    pause_cyclic_gc: bool = False

    def __post_init__(self) -> None:
        if type(self.second_index) is not int or self.second_index < 0:
            raise ValueError("admission chunk second is invalid")
        if type(self.chunk_index) is not int or self.chunk_index < 0:
            raise ValueError("admission chunk index is invalid")
        if type(self.last_for_second) is not bool:
            raise TypeError("admission chunk boundary flag must be boolean")
        if not self.rows and not self.last_for_second:
            raise ValueError("only the final admission chunk may be empty")
        if len(self.rows) > _ADMISSION_CHUNK_MAX_ROWS:
            raise ValueError("admission chunk exceeds its row bound")
        expected_payload_bytes = sum(row.payload_bytes for row in self.rows)
        if (
            self.payload_bytes != expected_payload_bytes
            or self.payload_bytes > _ADMISSION_CHUNK_MAX_PAYLOAD_BYTES
        ):
            raise ValueError("admission chunk exceeds its payload bound")
        if any(
            row.due_offset_ns // _ONE_SECOND_NS != self.second_index
            for row in self.rows
        ):
            raise ValueError("admission chunk crosses a scheduled-second boundary")


@dataclass(frozen=True, slots=True)
class _AdmissionOutcome:
    planned_event_id: str
    attempt_started_monotonic_ns: int
    admission_completed_monotonic_ns: int
    enqueue_status: EnqueueStatus
    accepted_identity: AcceptedRecordIdentityV1 | None


@dataclass(frozen=True, slots=True)
class _AdmissionTraceSeed:
    planned_event_id: str
    stream_group: StreamGroup
    logical_stream: LogicalStream
    exchange: Exchange
    market: Market | None
    instrument_key: str | None
    canonical_identity: str
    identity_index: int
    local_sequence: int
    due_monotonic_ns: int
    deadline_monotonic_ns: int
    attempt_started_monotonic_ns: int
    admission_completed_monotonic_ns: int
    enqueue_status: EnqueueStatus
    payload_bytes: int
    payload_sha256: str
    accepted_identity: AcceptedRecordIdentityV1 | None

    def to_trace(self) -> GateAdmissionTraceV1:
        return GateAdmissionTraceV1(
            planned_event_id=self.planned_event_id,
            stream_group=self.stream_group,
            logical_stream=self.logical_stream,
            exchange=self.exchange,
            market=self.market,
            instrument_key=self.instrument_key,
            canonical_identity=self.canonical_identity,
            identity_index=self.identity_index,
            local_sequence=self.local_sequence,
            due_monotonic_ns=self.due_monotonic_ns,
            deadline_monotonic_ns=self.deadline_monotonic_ns,
            attempt_started_monotonic_ns=self.attempt_started_monotonic_ns,
            admission_completed_monotonic_ns=self.admission_completed_monotonic_ns,
            enqueue_status=self.enqueue_status,
            payload_bytes=self.payload_bytes,
            payload_sha256=self.payload_sha256,
            accepted_identity=self.accepted_identity,
        )


_ACCEPTED_IDENTITY_FIELDS = (
    "schema_version",
    "exchange",
    "market",
    "instrument_key",
    "logical_stream",
    "worker_instance_id",
    "writer_sequence",
    "acceptance_ordinal",
    "config_sha256",
    "config_generation",
)
if tuple(AcceptedRecordIdentityV1.model_fields) != _ACCEPTED_IDENTITY_FIELDS:
    raise RuntimeError("trusted accepted-identity trace fields are stale")


def _trace_seed_canonical_line(seed: _AdmissionTraceSeed) -> bytes:
    identity = seed.accepted_identity
    identity_wire = (
        None
        if identity is None
        else {
            "schema_version": identity.schema_version,
            "exchange": identity.exchange,
            "market": identity.market,
            "instrument_key": identity.instrument_key,
            "logical_stream": identity.logical_stream,
            "worker_instance_id": identity.worker_instance_id,
            "writer_sequence": identity.writer_sequence,
            "acceptance_ordinal": identity.acceptance_ordinal,
            "config_sha256": identity.config_sha256,
            "config_generation": identity.config_generation,
        }
    )
    return (
        orjson.dumps(
            {
                "schema_version": 1,
                "record_type": "gate_admission_trace_v1",
                "planned_event_id": seed.planned_event_id,
                "stream_group": seed.stream_group,
                "logical_stream": seed.logical_stream,
                "exchange": seed.exchange,
                "market": seed.market,
                "instrument_key": seed.instrument_key,
                "canonical_identity": seed.canonical_identity,
                "identity_index": seed.identity_index,
                "local_sequence": seed.local_sequence,
                "due_monotonic_ns": seed.due_monotonic_ns,
                "deadline_monotonic_ns": seed.deadline_monotonic_ns,
                "attempt_started_monotonic_ns": seed.attempt_started_monotonic_ns,
                "admission_completed_monotonic_ns": (
                    seed.admission_completed_monotonic_ns
                ),
                "enqueue_status": seed.enqueue_status,
                "payload_bytes": seed.payload_bytes,
                "payload_sha256": seed.payload_sha256,
                "accepted_identity": identity_wire,
            }
        )
        + b"\n"
    )


@dataclass(frozen=True, slots=True)
class _ExchangeAdmissionSpool:
    root: Path
    exchange: Exchange
    partitions: tuple[_AdmissionSpoolPartition, ...]
    row_count: int

    def iter_partition_chunks(
        self,
        partition: _AdmissionSpoolPartition,
        *,
        admission_started_utc_ns: int,
    ) -> Generator[_AdmissionChunk, None, None]:
        if partition not in self.partitions:
            raise ValueError("admission spool partition is not owned by this spool")
        if type(admission_started_utc_ns) is not int or admission_started_utc_ns < 0:
            raise ValueError("admission UTC anchor must be non-negative")
        if partition.row_count == 0:
            if (
                partition.path is not None
                or partition.pause_cyclic_gc
                or partition.content_size_bytes != 0
                or partition.compressed_size_bytes != 0
                or partition.content_sha256 != hashlib.sha256(b"").hexdigest()
                or partition.compressed_sha256 != hashlib.sha256(b"").hexdigest()
            ):
                raise WriterGateRunError("empty admission spool facts changed")
            yield _AdmissionChunk(
                second_index=partition.second_index,
                chunk_index=0,
                rows=(),
                payload_bytes=0,
                last_for_second=True,
                pause_cyclic_gc=partition.pause_cyclic_gc,
            )
            return
        path = partition.path
        if path is None:
            raise WriterGateRunError("nonempty admission spool partition has no file")
        fd = open_readonly_nofollow(path)
        source: Any | None = None
        reader: Any | None = None
        primary_error: BaseException | None = None
        try:
            compressed_size, compressed_sha256 = size_and_sha256_fd(fd)
            if (
                compressed_size != partition.compressed_size_bytes
                or compressed_sha256 != partition.compressed_sha256
            ):
                raise WriterGateRunError("admission spool compressed facts changed")
            source = os.fdopen(os.dup(fd), "rb", closefd=True)
            reader = zstandard.ZstdDecompressor().stream_reader(
                source,
                read_across_frames=True,
                closefd=False,
            )
            digest = hashlib.sha256()
            content_size = 0
            pending = bytearray()
            chunk_rows: list[_PreparedAdmission] = []
            chunk_payload_bytes = 0
            chunk_index = 0
            row_count = 0
            final_chunk: _AdmissionChunk | None = None
            while True:
                compressed_chunk = reader.read(64 * 1024)
                if not compressed_chunk:
                    break
                digest.update(compressed_chunk)
                content_size += len(compressed_chunk)
                pending.extend(compressed_chunk)
                while True:
                    newline = pending.find(b"\n")
                    if newline < 0:
                        break
                    line = bytes(pending[: newline + 1])
                    del pending[: newline + 1]
                    try:
                        wire = _PreparedAdmissionWireV1.model_validate_json(
                            line,
                            strict=True,
                        )
                    except (TypeError, ValueError) as error:
                        raise WriterGateRunError(
                            "admission spool row is invalid"
                        ) from error
                    if (
                        wire.canonical_bytes() != line
                        or wire.exchange is not self.exchange
                    ):
                        raise WriterGateRunError(
                            "admission spool row is noncanonical or cross-exchange"
                        )
                    if row_count >= partition.row_count:
                        raise WriterGateRunError(
                            "admission spool has rows beyond its declared count"
                        )
                    prepared = _rebase_prepared_admission(
                        wire,
                        admission_started_utc_ns=admission_started_utc_ns,
                    )
                    if prepared.payload_bytes > _ADMISSION_CHUNK_MAX_PAYLOAD_BYTES:
                        raise WriterGateRunError(
                            "prepared admission row exceeds the chunk payload bound"
                        )
                    if chunk_rows and (
                        len(chunk_rows) >= _ADMISSION_CHUNK_MAX_ROWS
                        or chunk_payload_bytes + prepared.payload_bytes
                        > _ADMISSION_CHUNK_MAX_PAYLOAD_BYTES
                    ):
                        yield _AdmissionChunk(
                            second_index=partition.second_index,
                            chunk_index=chunk_index,
                            rows=tuple(chunk_rows),
                            payload_bytes=chunk_payload_bytes,
                            last_for_second=False,
                            pause_cyclic_gc=partition.pause_cyclic_gc,
                        )
                        chunk_index += 1
                        chunk_rows = []
                        chunk_payload_bytes = 0
                    chunk_rows.append(prepared)
                    chunk_payload_bytes += prepared.payload_bytes
                    row_count += 1
                    if (
                        row_count == partition.row_count
                        or len(chunk_rows) == _ADMISSION_CHUNK_MAX_ROWS
                        or chunk_payload_bytes == _ADMISSION_CHUNK_MAX_PAYLOAD_BYTES
                    ):
                        last_for_second = row_count == partition.row_count
                        completed_chunk = _AdmissionChunk(
                            second_index=partition.second_index,
                            chunk_index=chunk_index,
                            rows=tuple(chunk_rows),
                            payload_bytes=chunk_payload_bytes,
                            last_for_second=last_for_second,
                            pause_cyclic_gc=partition.pause_cyclic_gc,
                        )
                        if last_for_second:
                            final_chunk = completed_chunk
                            del completed_chunk
                        else:
                            yield completed_chunk
                            del completed_chunk
                        chunk_index += 1
                        chunk_rows = []
                        chunk_payload_bytes = 0
                if len(pending) > _SPOOL_MAX_LINE_BYTES:
                    raise WriterGateRunError("admission spool row exceeds its bound")
            if pending:
                raise WriterGateRunError("admission spool lacks a final newline")
            if (
                row_count != partition.row_count
                or chunk_rows
                or final_chunk is None
                or content_size != partition.content_size_bytes
                or digest.hexdigest() != partition.content_sha256
            ):
                raise WriterGateRunError("admission spool content facts changed")
            yield final_chunk
        except BaseException as error:
            primary_error = error
            raise
        finally:
            if reader is not None:
                reader.close()
            if source is not None:
                source.close()
            try:
                os.close(fd)
            except OSError as error:
                if primary_error is None:
                    raise
                primary_error.add_note(f"admission spool close also failed: {error!r}")

    def iter_second(
        self,
        second_index: int,
        *,
        admission_started_utc_ns: int,
    ) -> Iterator[_PreparedAdmission]:
        if type(second_index) is not int or not 0 <= second_index < len(
            self.partitions
        ):
            raise IndexError(second_index)
        if type(admission_started_utc_ns) is not int or admission_started_utc_ns < 0:
            raise ValueError("admission UTC anchor must be non-negative")
        for chunk in self.iter_partition_chunks(
            self.partitions[second_index],
            admission_started_utc_ns=admission_started_utc_ns,
        ):
            yield from chunk.rows

    def iter_trace_rows(
        self,
        outcomes: Sequence[_AdmissionOutcome],
        *,
        admission_started_monotonic_ns: int,
        admission_started_utc_ns: int,
    ) -> Iterator[GateAdmissionTraceV1]:
        ordinal = 0
        for partition in self.partitions:
            for prepared in self.iter_second(
                partition.second_index,
                admission_started_utc_ns=admission_started_utc_ns,
            ):
                if ordinal >= len(outcomes):
                    raise WriterGateRunError(
                        "admission outcomes end before the prepared spool"
                    )
                outcome = outcomes[ordinal]
                ordinal += 1
                if outcome.planned_event_id != prepared.planned_event_id:
                    raise WriterGateRunError(
                        "admission outcome order disagrees with the prepared spool"
                    )
                yield GateAdmissionTraceV1(
                    planned_event_id=prepared.planned_event_id,
                    stream_group=prepared.stream_group,
                    logical_stream=prepared.logical_stream,
                    exchange=prepared.exchange,
                    market=prepared.market,
                    instrument_key=prepared.instrument_key,
                    canonical_identity=prepared.canonical_identity,
                    identity_index=prepared.identity_index,
                    local_sequence=prepared.local_sequence,
                    due_monotonic_ns=(
                        admission_started_monotonic_ns + prepared.due_offset_ns
                    ),
                    deadline_monotonic_ns=(
                        admission_started_monotonic_ns + prepared.deadline_offset_ns
                    ),
                    attempt_started_monotonic_ns=(outcome.attempt_started_monotonic_ns),
                    admission_completed_monotonic_ns=(
                        outcome.admission_completed_monotonic_ns
                    ),
                    enqueue_status=outcome.enqueue_status,
                    payload_bytes=prepared.payload_bytes,
                    payload_sha256=prepared.payload_sha256,
                    accepted_identity=outcome.accepted_identity,
                )
        if ordinal != len(outcomes):
            raise WriterGateRunError(
                "admission outcomes continue beyond the prepared spool"
            )

    def cleanup(self) -> None:
        for partition in self.partitions:
            if partition.path is not None:
                partition.path.unlink(missing_ok=True)
        self.root.rmdir()


def _rebase_prepared_admission(
    wire: _PreparedAdmissionWireV1,
    *,
    admission_started_utc_ns: int,
) -> _PreparedAdmission:
    template = wire.draft_template
    draft = _rebase_draft_template(
        template,
        due_offset_ns=wire.due_offset_ns,
        admission_started_utc_ns=admission_started_utc_ns,
    )
    return _PreparedAdmission(
        planned_event_id=wire.planned_event_id,
        stream_group=wire.stream_group,
        logical_stream=wire.logical_stream,
        exchange=wire.exchange,
        market=wire.market,
        instrument_key=wire.instrument_key,
        canonical_identity=wire.canonical_identity,
        identity_index=wire.identity_index,
        local_sequence=wire.local_sequence,
        due_offset_ns=wire.due_offset_ns,
        deadline_offset_ns=wire.deadline_offset_ns,
        payload_bytes=wire.payload_bytes,
        payload_sha256=wire.payload_sha256,
        draft=draft,
        source=wire.source,
        shard=wire.shard,
    )


def _rebase_draft_template(
    template: NativeEventDraft,
    *,
    due_offset_ns: int,
    admission_started_utc_ns: int,
) -> NativeEventDraft:
    draft_values = template.__dict__.copy()
    if template.event_time_ns is not None:
        draft_values["event_time_ns"] = admission_started_utc_ns + due_offset_ns
    if template.rest_metadata is not None:
        rest = template.rest_metadata
        rest_values = rest.__dict__.copy()
        rebased = admission_started_utc_ns + due_offset_ns
        rest_values["request_started_at_ns"] = rebased
        rest_values["request_ended_at_ns"] = rebased
        draft_values["rest_metadata"] = _construct_trusted_model(
            RestMetadata,
            rest_values,
            _TRUSTED_REST_METADATA_FIELDS,
        )
    return _construct_trusted_model(
        NativeEventDraft,
        draft_values,
        _TRUSTED_NATIVE_DRAFT_FIELDS,
    )


def _prepared_admission(event: PlannedEventV1) -> _PreparedAdmission:
    draft, source, shard = build_native_draft(
        event,
        admission_started_utc_ns=0,
    )
    return _PreparedAdmission(
        planned_event_id=event.planned_event_id,
        stream_group=event.stream_group,
        logical_stream=event.logical_stream,
        exchange=event.exchange,
        market=event.market,
        instrument_key=event.instrument_key,
        canonical_identity=event.canonical_identity,
        identity_index=event.identity_index,
        local_sequence=event.local_sequence,
        due_offset_ns=event.due_offset_ns,
        deadline_offset_ns=event.deadline_offset_ns,
        payload_bytes=event.payload_bytes,
        payload_sha256=event.payload_sha256,
        draft=draft,
        source=source,
        shard=shard,
    )


def _prepared_wire(event: PlannedEventV1) -> _PreparedAdmissionWireV1:
    prepared = _prepared_admission(event)
    return _PreparedAdmissionWireV1(
        planned_event_id=prepared.planned_event_id,
        stream_group=prepared.stream_group,
        logical_stream=prepared.logical_stream,
        exchange=prepared.exchange,
        market=prepared.market,
        instrument_key=prepared.instrument_key,
        canonical_identity=prepared.canonical_identity,
        identity_index=prepared.identity_index,
        local_sequence=prepared.local_sequence,
        due_offset_ns=prepared.due_offset_ns,
        deadline_offset_ns=prepared.deadline_offset_ns,
        payload_bytes=prepared.payload_bytes,
        payload_sha256=prepared.payload_sha256,
        draft_template=prepared.draft,
        source=prepared.source,
        shard=prepared.shard,
    )


def _write_spool_partition(
    root: Path,
    second_index: int,
    events: Iterator[PlannedEventV1],
) -> _AdmissionSpoolPartition:
    path = root / f"second-{second_index:06d}.jsonl.zst"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    for flag_name in ("O_NOFOLLOW", "O_CLOEXEC"):
        flag = getattr(os, flag_name, None)
        if type(flag) is not int or flag == 0:
            raise OSError(f"required open flag {flag_name} is unavailable")
        flags |= flag
    fd = os.open(path, flags, 0o600)
    raw = os.fdopen(fd, "wb", closefd=True)
    compressor = zstandard.ZstdCompressor(level=_SPOOL_ZSTD_LEVEL).stream_writer(
        raw,
        closefd=False,
    )
    digest = hashlib.sha256()
    content_size = 0
    row_count = 0
    due_run_offset_ns: int | None = None
    due_run_count = 0
    pause_cyclic_gc = False
    primary_error: BaseException | None = None
    try:
        for event in events:
            if due_run_offset_ns != event.due_offset_ns:
                pause_cyclic_gc = pause_cyclic_gc or (
                    due_run_count >= _ADMISSION_GC_PAUSE_MIN_RECORDS
                )
                due_run_offset_ns = event.due_offset_ns
                due_run_count = 0
            due_run_count += 1
            line = _prepared_wire(event).canonical_bytes()
            if len(line) > _SPOOL_MAX_LINE_BYTES:
                raise WriterGateRunError(
                    "prepared admission spool row exceeds its bound"
                )
            compressor.write(line)
            digest.update(line)
            content_size += len(line)
            row_count += 1
        pause_cyclic_gc = pause_cyclic_gc or (
            due_run_count >= _ADMISSION_GC_PAUSE_MIN_RECORDS
        )
        compressor.flush(zstandard.FLUSH_FRAME)
        compressor.close()
        raw.flush()
        os.fsync(raw.fileno())
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if not compressor.closed:
            try:
                compressor.close()
            except BaseException as error:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    "admission spool compressor close also failed: "
                    + type(error).__name__
                )
        try:
            raw.close()
        except OSError as error:
            if primary_error is None:
                raise
            primary_error.add_note(f"admission spool file close also failed: {error!r}")
    verification_fd = open_readonly_nofollow(path)
    try:
        compressed_size, compressed_sha256 = size_and_sha256_fd(verification_fd)
    finally:
        os.close(verification_fd)
    return _AdmissionSpoolPartition(
        second_index=second_index,
        path=path,
        row_count=row_count,
        pause_cyclic_gc=pause_cyclic_gc,
        content_size_bytes=content_size,
        content_sha256=digest.hexdigest(),
        compressed_size_bytes=compressed_size,
        compressed_sha256=compressed_sha256,
    )


def _empty_spool_partition(second_index: int) -> _AdmissionSpoolPartition:
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    return _AdmissionSpoolPartition(
        second_index=second_index,
        path=None,
        row_count=0,
        pause_cyclic_gc=False,
        content_size_bytes=0,
        content_sha256=empty_sha256,
        compressed_size_bytes=0,
        compressed_sha256=empty_sha256,
    )


@dataclass(slots=True)
class _ExchangeSpoolBuilder:
    root: Path
    exchange: Exchange
    duration_seconds: int
    grouped: Iterator[tuple[int, Iterator[PlannedEventV1]]]
    next_group: tuple[int, Iterator[PlannedEventV1]] | None
    partitions: list[_AdmissionSpoolPartition]
    row_count: int = 0

    @classmethod
    def open(
        cls,
        plan: WorkloadPlanV1,
        exchange: Exchange,
        root: Path,
    ) -> _ExchangeSpoolBuilder:
        if type(plan) is not WorkloadPlanV1:
            raise TypeError("plan must be WorkloadPlanV1")
        if type(exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        if not isinstance(root, Path) or not root.is_absolute():
            raise ValueError("admission spool root must be an absolute Path")
        grouped = iter(
            groupby(
                iter_exchange_plan_events(plan, exchange),
                key=lambda event: event.due_offset_ns // _ONE_SECOND_NS,
            )
        )
        next_group = next(grouped, None)
        root.parent.mkdir(parents=True, exist_ok=True)
        root.mkdir(mode=0o700, exist_ok=False)
        return cls(
            root=root,
            exchange=exchange,
            duration_seconds=plan.duration_seconds,
            grouped=grouped,
            next_group=next_group,
            partitions=[],
        )

    def prepare_next(self) -> _AdmissionSpoolPartition:
        second_index = len(self.partitions)
        if second_index >= self.duration_seconds:
            raise WriterGateRunError("admission spool is already complete")
        if self.next_group is None or self.next_group[0] > second_index:
            partition = _empty_spool_partition(second_index)
        elif self.next_group[0] == second_index:
            partition = _write_spool_partition(
                self.root,
                second_index,
                self.next_group[1],
            )
            self.next_group = next(self.grouped, None)
        else:
            raise WriterGateRunError("admission spool schedule moved backwards")
        self.partitions.append(partition)
        self.row_count += partition.row_count
        return partition

    def prepare_until(self, partition_count: int) -> None:
        if type(partition_count) is not int or not (
            0 <= partition_count <= self.duration_seconds
        ):
            raise ValueError("admission spool partition bound is invalid")
        while len(self.partitions) < partition_count:
            self.prepare_next()

    def finish(self) -> _ExchangeAdmissionSpool:
        if len(self.partitions) != self.duration_seconds:
            raise WriterGateRunError("admission spool ended before the run duration")
        if self.next_group is not None:
            raise WriterGateRunError("prepared admission escaped the run duration")
        if self.row_count <= 0:
            raise WriterGateRunError("prepared admission spool is empty")
        return _ExchangeAdmissionSpool(
            root=self.root,
            exchange=self.exchange,
            partitions=tuple(self.partitions),
            row_count=self.row_count,
        )

    def abort(self) -> None:
        if not self.root.exists():
            return
        for remaining in self.root.iterdir():
            if remaining.is_file():
                remaining.unlink(missing_ok=True)
        self.root.rmdir()


def _expected_exchange_record_count(
    plan: WorkloadPlanV1,
    exchange: Exchange,
) -> int:
    total = 0
    for summary in plan.streams:
        exchange_index = summary.exchanges.index(exchange)
        identities_per_exchange, remainder = divmod(
            summary.identity_count,
            len(summary.exchanges),
        )
        if remainder:
            raise WriterGateRunError("plan identities are not exchange-balanced")
        identity_start = exchange_index * identities_per_exchange
        identity_stop = identity_start + identities_per_exchange
        quotient, allocation_remainder = divmod(
            summary.expected_record_count,
            summary.identity_count,
        )

        ordinal_start = identity_start * quotient + min(
            identity_start,
            allocation_remainder,
        )
        ordinal_stop = identity_stop * quotient + min(
            identity_stop,
            allocation_remainder,
        )
        total += ordinal_stop - ordinal_start
    if total <= 0:
        raise WriterGateRunError("exchange plan has no records")
    return total


def _prepare_exchange_spool(
    plan: WorkloadPlanV1,
    exchange: Exchange,
    root: Path,
) -> _ExchangeAdmissionSpool:
    builder = _ExchangeSpoolBuilder.open(plan, exchange, root)
    try:
        builder.prepare_until(plan.duration_seconds)
        return builder.finish()
    except BaseException:
        builder.abort()
        raise


class _RunnerJoinDatabase:
    def __init__(self, state_root: Path) -> None:
        self.path = (
            state_root / f".writer-gate-runner-{uuid.uuid4().hex}.sqlite.partial"
        )
        self.connection = sqlite3.connect(self.path)
        try:
            self.connection.execute("PRAGMA journal_mode=OFF")
            self.connection.execute("PRAGMA synchronous=OFF")
            self.connection.execute("PRAGMA cache_size=-8192")
            self.connection.executescript(
                """
                CREATE TABLE accepted (
                    route TEXT NOT NULL,
                    writer_sequence INTEGER NOT NULL,
                    worker_instance_id TEXT NOT NULL,
                    acceptance_ordinal INTEGER NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    config_generation INTEGER NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    payload_sha256 TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL,
                    PRIMARY KEY (route, writer_sequence),
                    UNIQUE (worker_instance_id, acceptance_ordinal)
                ) WITHOUT ROWID;
                CREATE TABLE durable (
                    route TEXT NOT NULL,
                    writer_sequence INTEGER NOT NULL,
                    worker_instance_id TEXT NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    payload_sha256 TEXT NOT NULL,
                    payload_bytes INTEGER NOT NULL,
                    received_utc_hour TEXT NOT NULL,
                    PRIMARY KEY (route, writer_sequence)
                ) WITHOUT ROWID;
                """
            )
        except BaseException:
            self.connection.close()
            self.path.unlink(missing_ok=True)
            raise

    def add_accepted(self, trace: GateAdmissionTraceV1) -> None:
        identity = trace.accepted_identity
        if identity is None:
            raise WriterGateRunError("accepted trace is missing its identity")
        try:
            self.connection.execute(
                "INSERT INTO accepted VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    trace.canonical_identity,
                    identity.writer_sequence,
                    identity.worker_instance_id,
                    identity.acceptance_ordinal,
                    identity.config_sha256,
                    identity.config_generation,
                    trace.planned_event_id,
                    trace.payload_sha256,
                    trace.payload_bytes,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise WriterGateRunError(
                "accepted identities or event IDs are not unique"
            ) from error

    def add_durable(
        self,
        *,
        route: str,
        writer_sequence: int,
        worker_instance_id: str,
        event_id: str,
        payload_sha256: str,
        payload_bytes: int,
        received_utc_hour: str,
    ) -> None:
        try:
            self.connection.execute(
                "INSERT INTO durable VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    route,
                    writer_sequence,
                    worker_instance_id,
                    event_id,
                    payload_sha256,
                    payload_bytes,
                    received_utc_hour,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise WriterGateRunError(
                "durable identities or event IDs are not unique"
            ) from error

    def finalize(self) -> _JoinFacts:
        self.connection.commit()
        disagreement = self.connection.execute(
            """
            SELECT COUNT(*) FROM (
                SELECT a.route FROM accepted AS a
                LEFT JOIN durable AS d
                  ON d.route = a.route AND d.writer_sequence = a.writer_sequence
                WHERE d.route IS NULL
                   OR a.worker_instance_id != d.worker_instance_id
                   OR a.event_id != d.event_id
                   OR a.payload_sha256 != d.payload_sha256
                   OR a.payload_bytes != d.payload_bytes
                UNION ALL
                SELECT d.route FROM durable AS d
                LEFT JOIN accepted AS a
                  ON a.route = d.route AND a.writer_sequence = d.writer_sequence
                WHERE a.route IS NULL
            )
            """
        ).fetchone()
        if disagreement is None or int(disagreement[0]) != 0:
            raise WriterGateRunError(
                "accepted trace and durable raw rows do not form an exact join"
            )
        accepted = self.connection.execute("SELECT COUNT(*) FROM accepted").fetchone()
        durable = self.connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(payload_bytes), 0) FROM durable"
        ).fetchone()
        touched = self.connection.execute(
            "SELECT COUNT(DISTINCT route) FROM durable"
        ).fetchone()
        assert accepted is not None and durable is not None and touched is not None
        hours = tuple(
            str(row[0])
            for row in self.connection.execute(
                "SELECT DISTINCT received_utc_hour FROM durable ORDER BY received_utc_hour"
            )
        )
        inconsistent_worker = self.connection.execute(
            """
            SELECT worker_instance_id FROM accepted
            GROUP BY worker_instance_id
            HAVING COUNT(DISTINCT config_sha256) != 1
                OR COUNT(DISTINCT config_generation) != 1
            LIMIT 1
            """
        ).fetchone()
        if inconsistent_worker is not None:
            raise WriterGateRunError(
                "accepted identities disagree on immutable worker config facts"
            )
        worker_rows = tuple(
            self.connection.execute(
                """
                SELECT accepted.worker_instance_id,
                       accepted.config_sha256,
                       accepted.config_generation,
                       COUNT(*),
                       MIN(accepted.acceptance_ordinal),
                       MAX(accepted.acceptance_ordinal),
                       (
                           SELECT COUNT(*) FROM durable
                           WHERE durable.worker_instance_id = accepted.worker_instance_id
                       )
                FROM accepted
                GROUP BY accepted.worker_instance_id,
                         accepted.config_sha256,
                         accepted.config_generation
                ORDER BY accepted.worker_instance_id
                """
            )
        )
        worker_facts: list[_WorkerJoinFacts] = []
        for (
            worker,
            config_sha256,
            config_generation,
            accepted_count,
            ordinal_min,
            ordinal_max,
            durable_count,
        ) in worker_rows:
            count = int(accepted_count)
            minimum = int(ordinal_min)
            maximum = int(ordinal_max)
            if minimum != 0 or maximum != count - 1:
                raise WriterGateRunError(
                    "accepted ordinals are not contiguous for one worker"
                )
            worker_facts.append(
                _WorkerJoinFacts(
                    worker_instance_id=str(worker),
                    config_sha256=str(config_sha256),
                    config_generation=int(config_generation),
                    accepted_record_count=count,
                    durable_record_count=int(durable_count),
                    acceptance_ordinal_min=minimum,
                    acceptance_ordinal_max=maximum,
                )
            )
        return _JoinFacts(
            unique_accepted_count=int(accepted[0]),
            durable_record_count=int(durable[0]),
            durable_payload_bytes=int(durable[1]),
            touched_identity_count=int(touched[0]),
            received_utc_hours=hours,
            workers=tuple(worker_facts),
        )

    def close(self) -> None:
        self.connection.close()
        self.path.unlink(missing_ok=True)


def parse_gate_duration(value: str) -> int:
    if type(value) is not str:
        raise TypeError("duration must be a string")
    duration_ns = parse_duration_ns(value)
    if duration_ns <= 0 or duration_ns % _ONE_SECOND_NS != 0:
        raise ValueError("duration must be a positive integral number of seconds")
    return duration_ns


def _normalized_planned_path(path: Path, *, field_name: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{field_name} must be Path")
    if not path.is_absolute() or path == Path(path.anchor):
        raise RunnerPreflightError(f"{field_name} must be an absolute non-root path")
    normalized = Path(os.path.abspath(os.fspath(path)))
    if normalized != path:
        raise RunnerPreflightError(f"{field_name} must be lexically normalized")
    existing = path
    while not existing.exists() and not os.path.lexists(existing):
        if existing.parent == existing:
            break
        existing = existing.parent
    try:
        resolved_existing = existing.resolve(strict=True)
    except OSError as error:
        raise RunnerPreflightError(
            f"{field_name} must have an existing real ancestor"
        ) from error
    if resolved_existing != existing:
        raise RunnerPreflightError(f"{field_name} may not traverse symbolic links")
    if os.path.lexists(path):
        try:
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise RunnerPreflightError(f"{field_name} is not a usable path") from error
        if resolved != path:
            raise RunnerPreflightError(f"{field_name} may not be a symbolic link")
    return path


def _require_empty_or_absent_directory(path: Path, *, field_name: str) -> None:
    if not os.path.lexists(path):
        return
    if not path.is_dir():
        raise RunnerPreflightError(f"{field_name} must be a directory")
    try:
        if next(path.iterdir(), None) is not None:
            raise RunnerPreflightError(f"{field_name} must be empty")
    except OSError as error:
        raise RunnerPreflightError(f"{field_name} cannot be inspected") from error


def _resolved_configs(
    workload: LoadedWorkload,
    *,
    mode: EvidenceMode,
) -> tuple[WriterConfig, IngressConfig, str]:
    if type(mode) is not str or mode not in ("functional", "qualification"):
        raise ValueError("evidence mode is invalid")
    max_payload_bytes = max(
        stream.payload_max_bytes for stream in workload.workload.streams.values()
    )
    frame_bytes = max(
        RAW_RECORD_FRAME_MIN_BYTES,
        max_payload_bytes + _RAW_RECORD_FRAME_OVERHEAD_BYTES,
    )
    writer_values: dict[str, object] = {"max_plain_frame_bytes": f"{frame_bytes}B"}
    if mode == "functional":
        writer_values["durability_critical"] = "7d"
    writer = WriterConfig.model_validate(writer_values)
    queues = workload.workload.queues
    ingress = IngressConfig.model_validate(
        {
            "shard_max_records": queues.shard_max_records,
            "shard_max_bytes": f"{queues.shard_max_bytes}B",
            "worker_max_bytes": f"{queues.worker_max_bytes}B",
            "high_water_ratio": 0.80,
            "control_reserve_records": queues.control_reserve_records,
            "control_reserve_bytes": f"{queues.control_reserve_bytes}B",
        }
    )
    document = {
        "schema_version": 1,
        "writer_config": writer.model_dump(mode="json"),
        "ingress_config": ingress.model_dump(mode="json"),
        "metric_stream_allowlist": list(_METRIC_STREAM_ALLOWLIST),
    }
    digest = hashlib.sha256(encode_json(document) + b"\n").hexdigest()
    return writer, ingress, digest


def _validate_qualification_claims(claims: QualificationClaims) -> None:
    if not isinstance(claims, QualificationClaims):
        raise RunnerPreflightError("qualification requires complete claims")
    if not _IMAGE_ID.fullmatch(claims.expected_image_id) or not _IMAGE_ID.fullmatch(
        claims.runtime_image_id
    ):
        raise RunnerPreflightError("qualification image ID is malformed")
    if claims.expected_image_id != claims.runtime_image_id:
        raise RunnerPreflightError("qualification image IDs do not match")
    if not _GIT_COMMIT.fullmatch(claims.implementation_source_commit):
        raise RunnerPreflightError("qualification source commit is malformed")
    for field_name in (
        "collector_wheel_sha256",
        "requirements_lock_sha256",
        "dockerfile_sha256",
    ):
        if not _SHA256.fullmatch(getattr(claims, field_name)):
            raise RunnerPreflightError(f"qualification {field_name} is malformed")


def _validate_hour_capacity(now_utc_ns: int, duration_ns: int) -> None:
    if type(now_utc_ns) is not int or now_utc_ns < 0:
        raise TypeError("now_utc_ns must be a non-negative integer")
    next_hour = (now_utc_ns // _ONE_HOUR_NS + 1) * _ONE_HOUR_NS
    if next_hour - now_utc_ns < duration_ns + _START_MARGIN_NS:
        raise RunnerPreflightError(
            "current UTC hour lacks duration plus the required start margin"
        )


def _reject_existing_exchange_subtrees(data_root: Path, state_root: Path) -> None:
    conflicts = (
        *(data_root / "raw" / exchange.value for exchange in CANONICAL_EXCHANGES),
        *(
            state_root / "raw-recovery" / exchange.value
            for exchange in CANONICAL_EXCHANGES
        ),
    )
    if any(os.path.lexists(path) for path in conflicts):
        raise RunnerPreflightError(
            "writer gate requires fresh exchange subtrees for raw and recovery state"
        )


def prepare_run(
    request: RunRequest,
    *,
    now_utc_ns: int | None = None,
) -> PreparedRun:
    if not isinstance(request, RunRequest):
        raise TypeError("request must be RunRequest")
    if type(request.multiplier) is not int or request.multiplier < 1:
        raise RunnerPreflightError("multiplier must be an integer at least one")
    if type(request.duration_ns) is not int:
        raise RunnerPreflightError("duration must use integral seconds")
    if type(request.functional_only) is not bool:
        raise RunnerPreflightError("functional_only must be boolean")

    mode: EvidenceMode = "functional" if request.functional_only else "qualification"
    if mode == "functional":
        if request.duration_ns != 10 * _ONE_SECOND_NS:
            raise RunnerPreflightError(
                "functional duration must be exactly ten seconds"
            )
        if request.qualification is not None:
            raise RunnerPreflightError("functional mode forbids qualification claims")
        if (request.data_root is None) != (request.state_root is None):
            raise RunnerPreflightError(
                "functional data and state roots must be supplied together"
            )
    else:
        if request.duration_ns % _ONE_SECOND_NS:
            raise RunnerPreflightError("duration must use integral seconds")
        if request.duration_ns < 600 * _ONE_SECOND_NS or request.multiplier < 2:
            raise RunnerPreflightError(
                "qualification requires at least ten minutes and multiplier two"
            )
        if request.data_root is None or request.state_root is None:
            raise RunnerPreflightError(
                "qualification requires explicit data and state roots"
            )
        if request.qualification is None:
            raise RunnerPreflightError("qualification requires complete claims")
        _validate_qualification_claims(request.qualification)
        if not sys.platform.startswith("linux"):
            raise RunnerPreflightError("qualification requires a Linux runtime")

    evidence_root = _normalized_planned_path(
        request.evidence_root,
        field_name="evidence root",
    )
    report_path = _normalized_planned_path(request.report_path, field_name="report")
    _require_empty_or_absent_directory(evidence_root, field_name="evidence root")
    if os.path.lexists(report_path):
        raise RunnerPreflightError("report path already exists")

    data_root = (
        evidence_root / "data"
        if request.data_root is None
        else _normalized_planned_path(request.data_root, field_name="data root")
    )
    state_root = (
        evidence_root / "state"
        if request.state_root is None
        else _normalized_planned_path(request.state_root, field_name="state root")
    )
    if data_root == state_root:
        raise RunnerPreflightError("data and state roots must be distinct")
    for root, label in (
        (evidence_root, "evidence"),
        (data_root, "data"),
        (state_root, "state"),
    ):
        if (
            report_path == root
            or report_path.is_relative_to(root)
            or root.is_relative_to(report_path)
        ):
            raise RunnerPreflightError(
                f"report path must be disjoint from the {label} root"
            )
    _reject_existing_exchange_subtrees(data_root, state_root)

    workload_path = _normalized_planned_path(
        request.workload_path,
        field_name="workload",
    )
    try:
        workload = load_workload(workload_path)
    except (OSError, ValueError) as error:
        raise RunnerPreflightError("workload document is invalid") from error
    if mode == "qualification" and workload.sha256 != RESEARCH_DEFAULT_V1_SHA256:
        raise RunnerPreflightError(
            "qualification requires the immutable research-default-v1 workload"
        )
    target_declaration_source: bytes | None = None
    if mode == "qualification":
        assert request.qualification is not None
        try:
            target = load_target_declaration(
                _normalized_planned_path(
                    request.qualification.target_declaration_path,
                    field_name="target declaration",
                )
            )
        except (OSError, ValueError) as error:
            raise RunnerPreflightError("target declaration is invalid") from error
        if target.target_id != request.qualification.expected_target_id:
            raise RunnerPreflightError("target declaration ID does not match")
        declared_roots = (target.data_root.root, target.state_root.root)
        if declared_roots != (data_root.as_posix(), state_root.as_posix()):
            raise RunnerPreflightError("target declaration roots do not match")
        target_declaration_source = target.canonical_bytes()

    clock_value = time.time_ns() if now_utc_ns is None else now_utc_ns
    _validate_hour_capacity(clock_value, request.duration_ns)
    plan = build_workload_plan(
        workload,
        multiplier=request.multiplier,
        duration_ns=request.duration_ns,
    )
    writer_config, ingress_config, config_sha256 = _resolved_configs(
        workload,
        mode=mode,
    )
    return PreparedRun(
        request=request,
        mode=mode,
        evidence_root=evidence_root,
        data_root=data_root,
        state_root=state_root,
        report_path=report_path,
        workload=workload,
        plan=plan,
        writer_config=writer_config,
        ingress_config=ingress_config,
        config_sha256=config_sha256,
        target_declaration_source=target_declaration_source,
    )


def _abort_requested(abort_event: Any | None) -> bool:
    return abort_event is not None and bool(abort_event.is_set())


async def _sleep_until(
    clock: SystemClock,
    target_monotonic_ns: int,
    *,
    abort_event: Any | None = None,
) -> int:
    while True:
        if _abort_requested(abort_event):
            raise WriterGateRunError("writer child observed a global abort")
        observed = clock.monotonic_ns()
        remaining = target_monotonic_ns - observed
        if remaining <= 0:
            return observed
        await asyncio.sleep(min(remaining / _ONE_SECOND_NS, 0.1))


async def _receive_child_command(
    command: Connection,
    *,
    abort_event: Any,
    timeout_seconds: float,
    expected_kind: str,
) -> dict[str, object]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        if _abort_requested(abort_event):
            raise WriterGateRunError("writer child command wait was aborted")
        try:
            if command.poll(0):
                message = command.recv()
                break
        except (EOFError, OSError) as error:
            raise WriterGateRunError("writer child control channel failed") from error
        if time.monotonic() >= deadline:
            raise WriterGateRunError("writer child command wait timed out")
        await asyncio.sleep(_CHILD_COMMAND_POLL_SECONDS)
    if not isinstance(message, dict) or message.get("kind") != expected_kind:
        raise WriterGateRunError("writer child received an invalid control command")
    return cast(dict[str, object], message)


def _required_command_int(message: dict[str, object], field_name: str) -> int:
    value = message.get(field_name)
    if type(value) is not int:
        raise WriterGateRunError(
            f"writer child command field {field_name} must be an integer"
        )
    return value


def _required_command_int_tuple(
    message: dict[str, object],
    field_name: str,
) -> tuple[int, ...]:
    value = message.get(field_name)
    if not isinstance(value, (list, tuple)) or any(
        type(item) is not int for item in value
    ):
        raise WriterGateRunError(
            f"writer child command field {field_name} must be an integer sequence"
        )
    return tuple(cast(Sequence[int], value))


def _put_child_status(
    result_queue: Any,
    message: dict[str, object],
    *,
    abort_event: Any,
) -> None:
    while True:
        if _abort_requested(abort_event):
            raise WriterGateRunError("writer child status publication was aborted")
        try:
            result_queue.put(message, timeout=0.1)
            return
        except queue.Full:
            continue


def _try_put_child_error(
    result_queue: Any,
    *,
    exchange: str,
    error: BaseException,
) -> None:
    try:
        result_queue.put(
            {
                "kind": "error",
                "exchange": exchange,
                "error_type": type(error).__name__,
                "message": str(error)[:500],
            },
            timeout=0.5,
        )
    except (OSError, queue.Full, ValueError):
        pass


def _open_fd_count() -> int:
    proc_fd = Path("/proc/self/fd")
    if proc_fd.is_dir():
        try:
            return sum(entry.name.isdigit() for entry in os.scandir(proc_fd))
        except OSError as error:
            raise OSError("failed to inspect Linux process descriptors") from error
    try:
        return len(os.listdir("/dev/fd"))
    except OSError as error:
        raise OSError(
            "the platform does not expose a process file-descriptor directory"
        ) from error


def _rss_bytes() -> int:
    status = Path("/proc/self/status")
    if status.is_file():
        try:
            matches = tuple(
                match
                for line in status.read_bytes().splitlines()
                if (match := _VM_RSS.fullmatch(line)) is not None
            )
        except OSError as error:
            raise OSError("failed to inspect Linux process RSS") from error
        if len(matches) != 1:
            raise OSError("Linux process status has no unique VmRSS field")
        return int(matches[0].group(1)) * 1024
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024


def _process_resource_sample(
    *,
    round_index: int,
    scheduled_monotonic_ns: int,
    process_key: GateProcessKeyV1,
    clock: SystemClock,
) -> GateProcessResourceSampleV1:
    started = max(scheduled_monotonic_ns, clock.monotonic_ns())
    rss_bytes = _rss_bytes()
    open_fd_count = _open_fd_count()
    completed = max(started, clock.monotonic_ns())
    return GateProcessResourceSampleV1(
        round_index=round_index,
        scheduled_monotonic_ns=scheduled_monotonic_ns,
        request_started_monotonic_ns=started,
        request_completed_monotonic_ns=completed,
        process_key=process_key,
        process_id=os.getpid(),
        rss_bytes=rss_bytes,
        open_fd_count=open_fd_count,
    )


async def _child_periodic_samples(
    *,
    service: RawWriterService,
    exchange: Exchange,
    schedules: tuple[int, ...],
    result_queue: Any,
    clock: SystemClock,
    abort_event: Any,
) -> None:
    process_key = GateProcessKeyV1(
        role="exchange_worker",
        exchange=exchange,
        worker_instance_id=f"gate-worker-v1-{exchange.value}",
    )
    for round_index, scheduled in enumerate(schedules):
        await _sleep_until(clock, scheduled, abort_event=abort_event)
        started = max(scheduled, clock.monotonic_ns())
        snapshot = service.metrics_snapshot()
        completed = max(started, clock.monotonic_ns())
        worker = GateWorkerSampleV1(
            round_index=round_index,
            round_kind="periodic",
            scheduled_monotonic_ns=scheduled,
            request_started_monotonic_ns=started,
            request_completed_monotonic_ns=completed,
            snapshot=snapshot,
        )
        process = _process_resource_sample(
            round_index=round_index,
            scheduled_monotonic_ns=scheduled,
            process_key=process_key,
            clock=clock,
        )
        _put_child_status(
            result_queue,
            {
                "kind": "sample",
                "exchange": exchange.value,
                "round_index": round_index,
                "worker": worker.canonical_bytes(),
                "resource": process.canonical_bytes(),
            },
            abort_event=abort_event,
        )


async def _child_admit_events(
    *,
    service: RawWriterService,
    exchange: Exchange,
    prefetched: asyncio.Queue[_AdmissionChunk | None],
    producer: asyncio.Task[int],
    trace_batches: asyncio.Queue[tuple[_AdmissionTraceSeed, ...] | None],
    duration_seconds: int,
    expected_row_count: int,
    admission_started_monotonic_ns: int,
    admission_started_utc_ns: int,
    duration_ns: int,
    enforce_hard_schedule: bool,
    clock: SystemClock,
    abort_event: Any,
) -> int:
    scheduled_end = admission_started_monotonic_ns + duration_ns
    attempted_count = 0

    async def next_chunk() -> _AdmissionChunk | None:
        while True:
            if _abort_requested(abort_event):
                raise WriterGateRunError("writer admission was globally aborted")
            if producer.done():
                if producer.cancelled():
                    raise WriterGateRunError("admission generator was cancelled")
                producer_error = producer.exception()
                if producer_error is not None:
                    raise producer_error
            try:
                return await asyncio.wait_for(
                    prefetched.get(),
                    timeout=_CHILD_COMMAND_POLL_SECONDS,
                )
            except TimeoutError:
                continue

    expected_second = 0
    expected_chunk = 0
    prior_order_key: tuple[int, str] | None = None
    bytes_since_yield = 0
    restore_cyclic_gc = False
    pause_cyclic_gc_for_second = False
    try:
        while expected_second < duration_seconds:
            item = await next_chunk()
            if (
                type(item) is not _AdmissionChunk
                or item.second_index != expected_second
                or item.chunk_index != expected_chunk
            ):
                raise WriterGateRunError("admission chunk order changed")
            if expected_chunk == 0:
                pause_cyclic_gc_for_second = item.pause_cyclic_gc
                restore_cyclic_gc = pause_cyclic_gc_for_second and gc.isenabled()
                if restore_cyclic_gc:
                    gc.disable()
                prior_order_key = None
                bytes_since_yield = 0
            elif item.pause_cyclic_gc != pause_cyclic_gc_for_second:
                raise WriterGateRunError("admission chunk GC facts changed")
            rows = item.rows
            last_for_second = item.last_for_second
            del item
            mutable_rows: list[_PreparedAdmission | None] = list(rows)
            del rows
            trace_seeds: list[_AdmissionTraceSeed] = []
            try:
                for index in range(len(mutable_rows)):
                    if (
                        attempted_count % _ADMISSION_ABORT_CHECK_RECORDS == 0
                        and _abort_requested(abort_event)
                    ):
                        raise WriterGateRunError(
                            "writer admission was globally aborted"
                        )
                    template = mutable_rows[index]
                    if template is None:
                        raise AssertionError(
                            "prepared admission row was released early"
                        )
                    prepared = template
                    order_key = (
                        prepared.due_offset_ns,
                        prepared.planned_event_id,
                    )
                    if prior_order_key is not None and order_key <= prior_order_key:
                        raise WriterGateRunError(
                            "admission rows are not globally ordered within a second"
                        )
                    prior_order_key = order_key
                    draft = _rebase_draft_template(
                        prepared.draft,
                        due_offset_ns=prepared.due_offset_ns,
                        admission_started_utc_ns=admission_started_utc_ns,
                    )
                    mutable_rows[index] = None
                    due = admission_started_monotonic_ns + prepared.due_offset_ns
                    observed = clock.monotonic_ns()
                    if observed < due:
                        observed = await _sleep_until(
                            clock,
                            due,
                            abort_event=abort_event,
                        )
                    if enforce_hard_schedule and observed >= scheduled_end:
                        raise WriterGateRunError(
                            "writer admission crossed its hard scheduled boundary: "
                            f"exchange={exchange.value} second={expected_second} "
                            f"chunk={expected_chunk} attempted={attempted_count} "
                            f"phase=attempt overrun_ns={observed - scheduled_end}"
                        )
                    attempt_started = max(due, observed)
                    result = service.try_accept(
                        draft,
                        source=prepared.source,
                        shard=prepared.shard,
                    )
                    completed = max(attempt_started, clock.monotonic_ns())
                    trace_seeds.append(
                        _AdmissionTraceSeed(
                            prepared.planned_event_id,
                            prepared.stream_group,
                            prepared.logical_stream,
                            prepared.exchange,
                            prepared.market,
                            prepared.instrument_key,
                            prepared.canonical_identity,
                            prepared.identity_index,
                            prepared.local_sequence,
                            admission_started_monotonic_ns + prepared.due_offset_ns,
                            admission_started_monotonic_ns
                            + prepared.deadline_offset_ns,
                            attempt_started,
                            completed,
                            result.status,
                            prepared.payload_bytes,
                            prepared.payload_sha256,
                            result.record_identity,
                        )
                    )
                    attempted_count += 1
                    if enforce_hard_schedule and completed >= scheduled_end:
                        raise WriterGateRunError(
                            "writer admission crossed its hard scheduled boundary: "
                            f"exchange={exchange.value} second={expected_second} "
                            f"chunk={expected_chunk} attempted={attempted_count} "
                            "phase=completion "
                            f"overrun_ns={completed - scheduled_end}"
                        )
                    bytes_since_yield += prepared.payload_bytes
                    if bytes_since_yield >= _ADMISSION_YIELD_BYTES:
                        bytes_since_yield = 0
                        await asyncio.sleep(0)
                await _put_trace_batch(
                    trace_batches,
                    tuple(trace_seeds),
                    abort_event=abort_event,
                )
            finally:
                prefetched.task_done()
            if last_for_second:
                if restore_cyclic_gc:
                    gc.enable()
                restore_cyclic_gc = False
                expected_second += 1
                expected_chunk = 0
            else:
                expected_chunk += 1
    finally:
        if restore_cyclic_gc:
            gc.enable()
    terminal = await next_chunk()
    if terminal is not None:
        raise WriterGateRunError("admission generation has extra groups")
    prefetched.task_done()
    await producer
    produced_count = producer.result()
    if attempted_count != expected_row_count or attempted_count != produced_count:
        raise WriterGateRunError("admission outcomes do not cover the generated plan")
    await _put_trace_batch(trace_batches, None, abort_event=abort_event)
    return attempted_count


async def _put_trace_batch(
    trace_batches: asyncio.Queue[tuple[_AdmissionTraceSeed, ...] | None],
    batch: tuple[_AdmissionTraceSeed, ...] | None,
    *,
    abort_event: Any,
) -> None:
    while True:
        if _abort_requested(abort_event):
            raise WriterGateRunError("writer trace streaming was globally aborted")
        try:
            await asyncio.wait_for(
                trace_batches.put(batch),
                timeout=_CHILD_COMMAND_POLL_SECONDS,
            )
            return
        except TimeoutError:
            continue


def _write_trace_seed_batch(
    writer: StreamingJsonlZstdWriter,
    batch: tuple[_AdmissionTraceSeed, ...],
    abort_event: Any,
) -> int:
    for start in range(0, len(batch), _TRACE_WRITE_CHUNK_ROWS):
        if _abort_requested(abort_event):
            raise WriterGateRunError("writer trace streaming was globally aborted")
        stop = min(start + _TRACE_WRITE_CHUNK_ROWS, len(batch))
        chunk = b"".join(_trace_seed_canonical_line(seed) for seed in batch[start:stop])
        writer.write_trusted_lines(
            chunk,
            GateAdmissionTraceV1,
            row_count=stop - start,
        )
    return len(batch)


async def _write_trace_batches(
    writer: StreamingJsonlZstdWriter,
    trace_batches: asyncio.Queue[tuple[_AdmissionTraceSeed, ...] | None],
    abort_event: Any,
) -> int:
    written_count = 0
    try:
        while True:
            if _abort_requested(abort_event):
                raise WriterGateRunError("writer trace streaming was globally aborted")
            try:
                batch = await asyncio.wait_for(
                    trace_batches.get(),
                    timeout=_CHILD_COMMAND_POLL_SECONDS,
                )
            except TimeoutError:
                continue
            try:
                if batch is None:
                    return written_count
                written_count += await asyncio.to_thread(
                    _write_trace_seed_batch,
                    writer,
                    batch,
                    abort_event,
                )
            finally:
                trace_batches.task_done()
                del batch
    except BaseException as error:
        abort_event.set()
        writer.abort(error)
        raise


async def _settle_tasks_despite_cancellation(
    tasks: Sequence[asyncio.Task[Any]],
) -> tuple[Any, ...]:
    if not tasks:
        return ()
    settlement = asyncio.gather(*tasks, return_exceptions=True)
    while not settlement.done():
        try:
            await asyncio.shield(settlement)
        except asyncio.CancelledError:
            continue
    return tuple(settlement.result())


async def _owned_to_thread(
    function: Callable[..., _ThreadResultT],
    *args: object,
) -> _ThreadResultT:
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except BaseException as error:
        outcome = (await _settle_tasks_despite_cancellation((task,)))[0]
        thread_error = outcome if isinstance(outcome, BaseException) else None
        if thread_error is not None and thread_error is not error:
            error.add_note(
                "owned thread call also failed: " + type(thread_error).__name__
            )
        raise


async def _gather_child_runtime_tasks(
    admission_task: asyncio.Task[int],
    sampling_task: asyncio.Task[None],
    *,
    abort_event: Any,
) -> int:
    tasks = (admission_task, sampling_task)
    try:
        attempted_count, _ = await asyncio.gather(*tasks)
        return attempted_count
    except BaseException:
        abort_event.set()
        for task in tasks:
            if not task.done():
                task.cancel()
        await _settle_tasks_despite_cancellation(tasks)
        raise


async def _put_spool_partition(
    partitions: asyncio.Queue[_AdmissionSpoolPartition | None],
    partition: _AdmissionSpoolPartition | None,
    *,
    abort_event: Any,
) -> None:
    while True:
        if _abort_requested(abort_event):
            raise WriterGateRunError("admission spool generation was globally aborted")
        try:
            await asyncio.wait_for(
                partitions.put(partition),
                timeout=_CHILD_COMMAND_POLL_SECONDS,
            )
            return
        except TimeoutError:
            continue


async def _produce_spool_partitions(
    builder: _ExchangeSpoolBuilder,
    partitions: asyncio.Queue[_AdmissionSpoolPartition | None],
    *,
    first_second: int,
    abort_event: Any,
) -> _ExchangeAdmissionSpool:
    for _ in range(first_second):
        await _owned_to_thread(builder.prepare_next)
    for second_index in range(first_second, builder.duration_seconds):
        if _abort_requested(abort_event):
            raise WriterGateRunError("admission spool generation was globally aborted")
        partition = await _owned_to_thread(builder.prepare_next)
        if partition.second_index != second_index:
            raise WriterGateRunError("admission spool partition order changed")
        await _put_spool_partition(
            partitions,
            partition,
            abort_event=abort_event,
        )
    completed = builder.finish()
    await _put_spool_partition(partitions, None, abort_event=abort_event)
    return completed


async def _next_spool_partition(
    partitions: asyncio.Queue[_AdmissionSpoolPartition | None],
    producer: asyncio.Task[_ExchangeAdmissionSpool],
    *,
    abort_event: Any,
) -> _AdmissionSpoolPartition | None:
    while True:
        if _abort_requested(abort_event):
            raise WriterGateRunError("admission spool replay was globally aborted")
        if producer.done():
            if producer.cancelled():
                raise WriterGateRunError("admission spool generation was cancelled")
            producer_error = producer.exception()
            if producer_error is not None:
                raise producer_error
        try:
            return await asyncio.wait_for(
                partitions.get(),
                timeout=_CHILD_COMMAND_POLL_SECONDS,
            )
        except TimeoutError:
            continue


def _next_admission_chunk(
    chunks: Iterator[_AdmissionChunk],
) -> _AdmissionChunk | None:
    try:
        return next(chunks)
    except StopIteration:
        return None


async def _put_admission_chunk(
    prefetched: asyncio.Queue[_AdmissionChunk | None],
    chunk: _AdmissionChunk | None,
    *,
    abort_event: Any,
) -> None:
    while True:
        if _abort_requested(abort_event):
            raise WriterGateRunError("admission chunk replay was globally aborted")
        try:
            await asyncio.wait_for(
                prefetched.put(chunk),
                timeout=_CHILD_COMMAND_POLL_SECONDS,
            )
            return
        except TimeoutError:
            continue


async def _produce_admission_chunks(
    plan: WorkloadPlanV1,
    exchange: Exchange,
    prefetched: asyncio.Queue[_AdmissionChunk | None],
    first_second: int,
    abort_event: Any,
    *,
    spool_root: Path,
) -> int:
    if type(first_second) is not int or not 0 <= first_second <= plan.duration_seconds:
        raise ValueError("first admission second is outside the plan duration")
    builder = _ExchangeSpoolBuilder.open(plan, exchange, spool_root)
    partitions: asyncio.Queue[_AdmissionSpoolPartition | None] = asyncio.Queue(
        maxsize=_SPOOL_LOOKAHEAD_SECONDS
    )
    spool_task = asyncio.create_task(
        _produce_spool_partitions(
            builder,
            partitions,
            first_second=first_second,
            abort_event=abort_event,
        )
    )
    active_chunks: Generator[_AdmissionChunk, None, None] | None = None
    completed_spool: _ExchangeAdmissionSpool | None = None
    decoded_count = 0
    primary_error: BaseException | None = None
    try:
        expected_second = first_second
        while True:
            partition = await _next_spool_partition(
                partitions,
                spool_task,
                abort_event=abort_event,
            )
            if partition is None:
                partitions.task_done()
                break
            try:
                if partition.second_index != expected_second:
                    raise WriterGateRunError("admission spool replay order changed")
                partition_spool = _ExchangeAdmissionSpool(
                    root=builder.root,
                    exchange=builder.exchange,
                    partitions=(partition,),
                    row_count=partition.row_count,
                )
                active_chunks = partition_spool.iter_partition_chunks(
                    partition,
                    admission_started_utc_ns=0,
                )
                expected_chunk = 0
                while True:
                    chunk = await _owned_to_thread(
                        _next_admission_chunk,
                        active_chunks,
                    )
                    if chunk is None:
                        break
                    if (
                        chunk.second_index != expected_second
                        or chunk.chunk_index != expected_chunk
                    ):
                        raise WriterGateRunError("admission chunk replay order changed")
                    decoded_count += len(chunk.rows)
                    await _put_admission_chunk(
                        prefetched,
                        chunk,
                        abort_event=abort_event,
                    )
                    expected_chunk += 1
                active_chunks = None
                if expected_chunk <= 0:
                    raise WriterGateRunError(
                        "admission spool partition emitted no chunk"
                    )
                if partition.path is not None:
                    partition.path.unlink()
                expected_second += 1
            finally:
                partitions.task_done()
        completed_spool = await spool_task
        expected_count = sum(
            partition.row_count
            for partition in completed_spool.partitions[first_second:]
        )
        if expected_second != plan.duration_seconds or decoded_count != expected_count:
            raise WriterGateRunError("admission spool replay count changed")
        await _put_admission_chunk(prefetched, None, abort_event=abort_event)
        completed_spool.cleanup()
        completed_spool = None
        return decoded_count
    except BaseException as error:
        primary_error = error
        abort_event.set()
        raise
    finally:
        if active_chunks is not None:
            try:
                await _owned_to_thread(active_chunks.close)
            except BaseException as cleanup_error:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    "admission spool reader cleanup also failed: "
                    + type(cleanup_error).__name__
                )
        if not spool_task.done():
            spool_task.cancel()
        if completed_spool is None:
            await _settle_tasks_despite_cancellation((spool_task,))
        try:
            if completed_spool is not None:
                completed_spool.cleanup()
            elif builder.root.exists():
                builder.abort()
        except BaseException as cleanup_error:
            if primary_error is None:
                raise
            primary_error.add_note(
                "admission spool cleanup also failed: " + type(cleanup_error).__name__
            )


async def _run_child(
    spec: _ChildSpec,
    command: Connection,
    result_queue: Any,
    abort_event: Any,
) -> None:
    if type(spec.mode) is not str or spec.mode not in (
        "functional",
        "qualification",
    ):
        raise ValueError("child evidence mode is invalid")
    exchange = Exchange(spec.exchange)
    clock = SystemClock()
    workload = load_workload(Path(spec.workload_path))
    if workload.sha256 != spec.workload_sha256:
        raise ValueError("child workload SHA disagrees with the supervisor")
    plan = build_workload_plan(
        workload,
        multiplier=spec.multiplier,
        duration_ns=spec.duration_ns,
    )
    if (
        plan.header.canonical_bytes() != spec.plan_header_bytes
        or tuple(
            encode_json(summary.model_dump(mode="json")) + b"\n"
            for summary in plan.streams
        )
        != spec.stream_summary_bytes
    ):
        raise ValueError("child workload plan summaries disagree with the supervisor")
    writer_config, ingress_config, config_sha256 = _resolved_configs(
        workload,
        mode=spec.mode,
    )
    if config_sha256 != spec.config_sha256:
        raise ValueError("child writer config digest disagrees with the supervisor")

    service: RawWriterService | None = None
    trace_writer: StreamingJsonlZstdWriter | None = None
    trace_task: asyncio.Task[int] | None = None
    producer: asyncio.Task[int] | None = None
    admission_task: asyncio.Task[int] | None = None
    sampling_task: asyncio.Task[None] | None = None
    try:
        expected_row_count = _expected_exchange_record_count(plan, exchange)
        spool_root = Path(spec.state_root).parent / (
            f".writer-gate-admission-spool-{exchange.value}-{uuid.uuid4().hex}"
        )
        prefetched: asyncio.Queue[_AdmissionChunk | None] = asyncio.Queue(
            maxsize=_ADMISSION_QUEUE_MAX_CHUNKS
        )
        producer = asyncio.create_task(
            _produce_admission_chunks(
                plan,
                exchange,
                prefetched,
                0,
                abort_event,
                spool_root=spool_root,
            )
        )
        while prefetched.empty():
            if producer.done():
                if producer.cancelled():
                    raise WriterGateRunError("admission generator was cancelled")
                producer_error = producer.exception()
                if producer_error is not None:
                    raise producer_error
                raise WriterGateRunError("admission generator ended before readiness")
            if _abort_requested(abort_event):
                raise WriterGateRunError("admission generation was globally aborted")
            await asyncio.sleep(_CHILD_COMMAND_POLL_SECONDS)
        service = await RawWriterService.open(
            data_root=Path(spec.data_root),
            state_root=Path(spec.state_root),
            exchange=exchange,
            worker_instance_id=f"gate-worker-v1-{exchange.value}",
            config_sha256=config_sha256,
            config_generation=0,
            writer_config=writer_config,
            ingress_config=ingress_config,
            metric_stream_allowlist=_METRIC_STREAM_ALLOWLIST,
            clock=clock,
        )
        _put_child_status(
            result_queue,
            {
                "kind": "ready",
                "exchange": exchange.value,
                "pid": os.getpid(),
                "config_sha256": config_sha256,
                "workload_sha256": workload.sha256,
                "workload_plan_sha256": spec.workload_plan_sha256,
                "planned_row_count": expected_row_count,
            },
            abort_event=abort_event,
        )
        start = await _receive_child_command(
            command,
            abort_event=abort_event,
            timeout_seconds=_CHILD_READY_TIMEOUT_SECONDS,
            expected_kind="start",
        )
        admission_started_monotonic_ns = _required_command_int(start, "monotonic_ns")
        admission_started_utc_ns = _required_command_int(start, "utc_ns")
        schedules = _required_command_int_tuple(start, "sample_schedules")
        if len(schedules) != spec.duration_ns // _ONE_SECOND_NS:
            raise ValueError("child sample schedule cardinality is invalid")

        trace_writer = StreamingJsonlZstdWriter(
            Path(spec.evidence_root),
            f"primary/trace/{exchange.value}.jsonl.zst",
            zstd_level=_ARTIFACT_ZSTD_LEVEL,
        )
        trace_batches: asyncio.Queue[tuple[_AdmissionTraceSeed, ...] | None] = (
            asyncio.Queue(maxsize=1)
        )
        trace_task = asyncio.create_task(
            _write_trace_batches(trace_writer, trace_batches, abort_event)
        )
        admission_task = asyncio.create_task(
            _child_admit_events(
                service=service,
                exchange=exchange,
                prefetched=prefetched,
                producer=producer,
                trace_batches=trace_batches,
                duration_seconds=plan.duration_seconds,
                expected_row_count=expected_row_count,
                admission_started_monotonic_ns=admission_started_monotonic_ns,
                admission_started_utc_ns=admission_started_utc_ns,
                duration_ns=spec.duration_ns,
                enforce_hard_schedule=spec.mode == "qualification",
                clock=clock,
                abort_event=abort_event,
            )
        )
        sampling_task = asyncio.create_task(
            _child_periodic_samples(
                service=service,
                exchange=exchange,
                schedules=schedules,
                result_queue=result_queue,
                clock=clock,
                abort_event=abort_event,
            )
        )
        attempted_count = await _gather_child_runtime_tasks(
            admission_task,
            sampling_task,
            abort_event=abort_event,
        )
        trace_count = await trace_task
        if attempted_count != expected_row_count or trace_count != expected_row_count:
            raise WriterGateRunError(
                "completed admission trace disagrees with the exchange plan count"
            )
        scheduled_end = admission_started_monotonic_ns + spec.duration_ns
        await _sleep_until(clock, scheduled_end, abort_event=abort_event)
        await service.sync_now()
        manifests = await service.close_all(
            CloseReason.SHUTDOWN,
            clock.monotonic_ns() + _child_close_grace_ns(spec.mode),
        )
        if any(type(manifest) is not RawManifestV1 for manifest in manifests):
            raise TypeError("writer close returned an invalid manifest")
        typed_manifests = cast(tuple[RawManifestV1, ...], manifests)
        if any(
            RawManifestV1.model_validate_json(manifest.canonical_bytes()) != manifest
            for manifest in typed_manifests
        ):
            raise ValueError("writer close returned a non-canonical manifest")
        trace_ref = trace_writer.close()
        trace_writer = None
        if trace_ref.row_count != attempted_count:
            raise WriterGateRunError("published admission trace row count changed")
        _put_child_status(
            result_queue,
            {
                "kind": "closed",
                "exchange": exchange.value,
                "attempted": attempted_count,
                "manifest_count": len(typed_manifests),
                "trace_ref": trace_ref.canonical_bytes(),
            },
            abort_event=abort_event,
        )

        final_command = await _receive_child_command(
            command,
            abort_event=abort_event,
            timeout_seconds=_child_final_command_timeout_seconds(spec.mode),
            expected_kind="final",
        )
        round_index = _required_command_int(final_command, "round_index")
        scheduled = _required_command_int(
            final_command,
            "scheduled_monotonic_ns",
        )
        await _sleep_until(clock, scheduled, abort_event=abort_event)
        started = max(scheduled, clock.monotonic_ns())
        final_snapshot = service.metrics_snapshot()
        completed = max(started, clock.monotonic_ns())
        final_worker = GateWorkerSampleV1(
            round_index=round_index,
            round_kind="final",
            scheduled_monotonic_ns=scheduled,
            request_started_monotonic_ns=started,
            request_completed_monotonic_ns=completed,
            snapshot=final_snapshot,
        )
        final_resource = _process_resource_sample(
            round_index=round_index,
            scheduled_monotonic_ns=scheduled,
            process_key=GateProcessKeyV1(
                role="exchange_worker",
                exchange=exchange,
                worker_instance_id=f"gate-worker-v1-{exchange.value}",
            ),
            clock=clock,
        )
        _put_child_status(
            result_queue,
            {
                "kind": "final",
                "exchange": exchange.value,
                "worker": final_worker.canonical_bytes(),
                "resource": final_resource.canonical_bytes(),
            },
            abort_event=abort_event,
        )
    except BaseException as error:
        abort_event.set()
        _try_put_child_error(
            result_queue,
            exchange=spec.exchange,
            error=error,
        )
        runtime_tasks = tuple(
            task for task in (admission_task, sampling_task) if task is not None
        )
        for task in runtime_tasks:
            if not task.done():
                task.cancel()
        await _settle_tasks_despite_cancellation(runtime_tasks)
        if producer is not None and not producer.done():
            producer.cancel()
        if producer is not None:
            await _settle_tasks_despite_cancellation((producer,))
        if trace_task is not None:
            await _settle_tasks_despite_cancellation((trace_task,))
        if trace_writer is not None:
            trace_writer.abort(error)
        if service is not None:
            try:
                await asyncio.wait_for(
                    service.mark_incomplete("writer_gate_child_failure"),
                    timeout=_CHILD_INCOMPLETE_TIMEOUT_SECONDS,
                )
            except BaseException as cleanup_error:  # noqa: BLE001
                error.add_note(
                    "writer child cleanup also failed: " + type(cleanup_error).__name__
                )
        raise


def _child_entry(
    spec: _ChildSpec,
    command: Connection,
    result_queue: Any,
    abort_event: Any,
) -> None:
    try:
        asyncio.run(_run_child(spec, command, result_queue, abort_event))
    except BaseException as error:
        abort_event.set()
        _try_put_child_error(
            result_queue,
            exchange=spec.exchange,
            error=error,
        )
        raise


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _self_hashed(model_type: type[_ModelT], unsigned: dict[str, object]) -> _ModelT:
    digest = hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest()
    return model_type.model_validate_json(
        encode_json({**unsigned, "sha256": digest}),
        strict=True,
    )


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        try:
            written = os.write(fd, data[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise OSError("exclusive evidence write made no progress")
        offset += written


def _publish_bytes_no_replace(path: Path, data: bytes) -> None:
    if type(data) is not bytes or not data:
        raise ValueError("published evidence must be nonempty bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(f".{path.name}.{uuid.uuid4().hex}.partial")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    for flag_name in ("O_NOFOLLOW", "O_CLOEXEC"):
        flag = getattr(os, flag_name, None)
        if type(flag) is not int or flag == 0:
            raise OSError(f"required open flag {flag_name} is unavailable")
        flags |= flag
    fd = os.open(partial, flags, 0o640)
    primary_error: BaseException | None = None
    try:
        _write_all(fd, data)
        os.fsync(fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            os.close(fd)
        except OSError as error:
            if primary_error is None:
                raise
            primary_error.add_note(f"evidence temporary close also failed: {error!r}")
    verification_fd = open_readonly_nofollow(partial)
    publication_error: BaseException | None = None
    try:
        publish_no_replace(
            partial,
            path,
            capability=NoReplaceCapability.HARDLINK,
            expected_source_fd=verification_fd,
        )
    except BaseException as error:
        publication_error = error
        raise
    finally:
        try:
            os.close(verification_fd)
        except OSError as error:
            if publication_error is None:
                raise
            publication_error.add_note(
                f"evidence verification close also failed: {error!r}"
            )


def _document_ref(root: Path, path: Path) -> GateEvidenceDocumentRefV1:
    source = path.read_bytes()
    return GateEvidenceDocumentRefV1(
        relative_path=path.relative_to(root).as_posix(),
        content_size_bytes=len(source),
        content_sha256=hashlib.sha256(source).hexdigest(),
    )


def _document_ref_from_source(
    *,
    relative_path: str,
    source: bytes,
) -> GateEvidenceDocumentRefV1:
    if type(source) is not bytes or not source:
        raise TypeError("evidence document source must be nonempty bytes")
    return GateEvidenceDocumentRefV1(
        relative_path=relative_path,
        content_size_bytes=len(source),
        content_sha256=hashlib.sha256(source).hexdigest(),
    )


def _materialize_run(prepared: PreparedRun) -> Path:
    _require_empty_or_absent_directory(
        prepared.evidence_root,
        field_name="evidence root",
    )
    if prepared.evidence_root.exists():
        evidence_root = prepared.evidence_root.resolve(strict=True)
        if evidence_root != prepared.evidence_root:
            raise RunnerPreflightError("evidence root changed after preflight")
    else:
        prepared.evidence_root.mkdir(parents=False, exist_ok=False)
    for root in (prepared.data_root, prepared.state_root):
        if root.exists():
            if root.resolve(strict=True) != root or not root.is_dir():
                raise RunnerPreflightError("writer root changed after preflight")
        else:
            root.mkdir(parents=True, exist_ok=False)
    _reject_existing_exchange_subtrees(prepared.data_root, prepared.state_root)
    workload_path = prepared.evidence_root / "workload.yaml"
    workload_source = prepared.request.workload_path.read_bytes()
    if hashlib.sha256(workload_source).hexdigest() != prepared.workload.sha256:
        raise RunnerPreflightError("workload changed after preflight")
    _publish_bytes_no_replace(workload_path, workload_source)
    return workload_path


def _envelope_route(envelope: Any) -> str:
    if envelope.logical_stream == "_control":
        return f"gate-identity-v1:{envelope.exchange.value}:-:-:_control"
    if envelope.market is None or envelope.instrument_key is None:
        raise WriterGateRunError("raw envelope route is incomplete")
    return (
        f"gate-identity-v1:{envelope.exchange.value}:{envelope.market.value}:"
        f"{envelope.instrument_key}:{envelope.logical_stream}"
    )


def _read_raw_plain_facts(
    path: Path,
    *,
    manifest: RawManifestV1,
    database: _RunnerJoinDatabase,
    expected_config_sha256: str,
    max_line_bytes: int,
) -> tuple[int, int, str, int, str]:
    fd = open_readonly_nofollow(path)
    primary_error: BaseException | None = None
    try:
        compressed_size, compressed_sha256 = size_and_sha256_fd(fd)
        source = os.fdopen(os.dup(fd), "rb", closefd=True)
        reader = zstandard.ZstdDecompressor().stream_reader(
            source,
            read_across_frames=True,
            closefd=False,
        )
        content_digest = hashlib.sha256()
        content_size = 0
        row_count = 0
        pending = bytearray()
        first_sequence: int | None = None
        previous_sequence: int | None = None
        try:
            while True:
                chunk = reader.read(64 * 1024)
                if not chunk:
                    break
                content_digest.update(chunk)
                content_size += len(chunk)
                pending.extend(chunk)
                while True:
                    newline = pending.find(b"\n")
                    if newline < 0:
                        break
                    line = bytes(pending[: newline + 1])
                    del pending[: newline + 1]
                    envelope = decode_envelope_jsonl(line)
                    if encode_envelope(envelope) != line:
                        raise WriterGateRunError("raw envelope is not canonical JSONL")
                    expected_route_facts = (
                        manifest.exchange,
                        manifest.market,
                        manifest.instrument_key,
                        manifest.logical_stream,
                        manifest.worker_instance_id,
                        manifest.config_sha256,
                    )
                    observed_route_facts = (
                        envelope.exchange,
                        envelope.market,
                        envelope.instrument_key,
                        envelope.logical_stream,
                        envelope.worker_instance_id,
                        envelope.config_sha256,
                    )
                    if observed_route_facts != expected_route_facts or (
                        envelope.config_sha256 != expected_config_sha256
                    ):
                        raise WriterGateRunError(
                            "raw envelope route/config disagrees with its manifest"
                        )
                    payload = encode_json(envelope.payload)
                    if not isinstance(envelope.payload, dict):
                        raise WriterGateRunError(
                            "raw envelope payload is not a JSON object"
                        )
                    event_id = envelope.payload.get("event_id")
                    if type(event_id) is not str or not _SHA256.fullmatch(event_id):
                        raise WriterGateRunError(
                            "raw envelope payload has no canonical event ID"
                        )
                    database.add_durable(
                        route=_envelope_route(envelope),
                        writer_sequence=envelope.writer_sequence,
                        worker_instance_id=envelope.worker_instance_id,
                        event_id=event_id,
                        payload_sha256=hashlib.sha256(payload).hexdigest(),
                        payload_bytes=len(payload),
                        received_utc_hour=datetime.fromtimestamp(
                            envelope.received_at_ns // _ONE_SECOND_NS,
                            tz=UTC,
                        ).strftime("%Y/%m/%d/%H"),
                    )
                    if previous_sequence is not None and (
                        envelope.writer_sequence <= previous_sequence
                    ):
                        raise WriterGateRunError(
                            "raw writer sequences are not strictly increasing"
                        )
                    if first_sequence is None:
                        first_sequence = envelope.writer_sequence
                    previous_sequence = envelope.writer_sequence
                    row_count += 1
                if len(pending) > max_line_bytes:
                    raise WriterGateRunError("raw envelope line exceeds its bound")
        finally:
            reader.close()
            source.close()
        if content_size == 0 or pending:
            raise WriterGateRunError(
                "raw artifact is empty or missing its final newline"
            )
        if (
            first_sequence is None
            or previous_sequence is None
            or (
                first_sequence != manifest.writer_sequence_first
                or previous_sequence != manifest.writer_sequence_last
            )
        ):
            raise WriterGateRunError("raw writer sequence facts are invalid")
        return (
            compressed_size,
            content_size,
            content_digest.hexdigest(),
            row_count,
            compressed_sha256,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            os.close(fd)
        except OSError as error:
            if primary_error is None:
                raise
            primary_error.add_note(f"raw inventory fd close also failed: {error!r}")


def _scan_raw_inventories(
    data_root: Path,
    *,
    database: _RunnerJoinDatabase,
    expected_config_sha256: str,
    expected_writer_config: WriterConfig,
) -> tuple[GateRawInventoryV1, GateManifestInventoryV1, tuple[RawManifestV1, ...]]:
    manifest_paths = tuple(sorted((data_root / "raw").rglob("*.manifest.json")))
    if not manifest_paths:
        raise WriterGateRunError("writer produced no raw manifests")
    pairs: list[tuple[GateEvidenceDocumentRefV1, GateArtifactRefV1, RawManifestV1]] = []
    for manifest_path in manifest_paths:
        loaded = load_raw_manifest(manifest_path)
        manifest = loaded.manifest
        if (
            manifest.config_sha256 != expected_config_sha256
            or manifest.zstd_level != expected_writer_config.zstd_level
            or manifest.max_plain_frame_bytes
            != expected_writer_config.max_plain_frame_bytes
        ):
            raise WriterGateRunError(
                "raw manifest codec/config facts disagree with the resolved writer config"
            )
        declared_manifest_path = data_root / manifest.manifest_relative_path
        if declared_manifest_path != manifest_path:
            raise WriterGateRunError(
                "raw manifest pathname disagrees with its declared relative path"
            )
        data_path = data_root / manifest.data_relative_path
        if not data_path.is_relative_to(data_root):
            raise WriterGateRunError("raw data path escapes the data root")
        (
            compressed_size,
            content_size,
            content_sha256,
            row_count,
            compressed_sha256,
        ) = _read_raw_plain_facts(
            data_path,
            manifest=manifest,
            database=database,
            expected_config_sha256=expected_config_sha256,
            max_line_bytes=expected_writer_config.max_plain_frame_bytes,
        )
        if (
            compressed_size != manifest.file_size_bytes
            or compressed_sha256 != manifest.file_sha256
            or row_count != manifest.record_count
        ):
            raise WriterGateRunError("raw file facts disagree with its manifest")
        manifest_ref = GateEvidenceDocumentRefV1(
            relative_path=manifest.manifest_relative_path,
            content_size_bytes=len(loaded.canonical_bytes),
            content_sha256=loaded.sha256,
        )
        data_ref = GateArtifactRefV1(
            relative_path=manifest.data_relative_path,
            row_count=row_count,
            content_size_bytes=content_size,
            content_sha256=content_sha256,
            compressed_size_bytes=compressed_size,
            compressed_sha256=compressed_sha256,
        )
        pairs.append((manifest_ref, data_ref, manifest))
    pairs.sort(key=lambda item: item[0].relative_path)
    raw_root = data_root / "raw"
    expected_files = {
        *(data_root / item[1].relative_path for item in pairs),
        *(data_root / item[0].relative_path for item in pairs),
        *(
            raw_root / exchange.value / ".writer.lock"
            for exchange in CANONICAL_EXCHANGES
        ),
    }
    for _manifest_ref, data_ref, _manifest in pairs:
        lease = lease_path_for_data(data_root / data_ref.relative_path)
        if os.path.lexists(lease):
            expected_files.add(lease)
    expected_directories = {raw_root}
    for expected_file in expected_files:
        current = expected_file.parent
        while current.is_relative_to(raw_root):
            expected_directories.add(current)
            if current == raw_root:
                break
            current = current.parent
    observed_files: set[Path] = set()
    observed_directories: set[Path] = set()

    def reject_walk_error(error: OSError) -> None:
        raise WriterGateRunError("raw tree walk failed") from error

    for directory, directory_names, file_names in os.walk(
        raw_root,
        topdown=True,
        onerror=reject_walk_error,
        followlinks=False,
    ):
        directory_path = Path(directory)
        metadata = os.lstat(directory_path)
        if not stat.S_ISDIR(metadata.st_mode):
            raise WriterGateRunError("raw inventory contains a non-directory ancestor")
        observed_directories.add(directory_path)
        for name in directory_names:
            child = directory_path / name
            if not stat.S_ISDIR(os.lstat(child).st_mode):
                raise WriterGateRunError("raw inventory contains a linked directory")
        for name in file_names:
            child = directory_path / name
            metadata = os.lstat(child)
            if not stat.S_ISREG(metadata.st_mode):
                raise WriterGateRunError("raw inventory contains a non-regular file")
            if child.name.endswith(".partial"):
                raise WriterGateRunError("raw inventory contains a partial file")
            if (
                child.name in {".writer.lock"} or child.suffix == ".lease"
            ) and metadata.st_size != 0:
                raise WriterGateRunError("raw lock/lease file is nonempty")
            observed_files.add(child)
    if observed_files != expected_files or observed_directories != expected_directories:
        raise WriterGateRunError("raw tree does not exactly match its inventories")
    raw_files = tuple(
        sorted((item[1] for item in pairs), key=lambda item: item.relative_path)
    )
    raw_inventory = _self_hashed(
        GateRawInventoryV1,
        {
            "schema_version": 1,
            "record_type": "gate_raw_inventory_v1",
            "raw_files": [item.model_dump(mode="json") for item in raw_files],
            "file_count": len(raw_files),
            "record_count": sum(item.row_count for item in raw_files),
            "content_size_bytes": sum(item.content_size_bytes for item in raw_files),
            "compressed_size_bytes": sum(
                item.compressed_size_bytes for item in raw_files
            ),
        },
    )
    entries = tuple(
        GateManifestInventoryEntryV1(
            ordinal=ordinal,
            manifest=manifest_ref,
            data=data_ref,
            manifest_record_count=manifest.record_count,
        )
        for ordinal, (manifest_ref, data_ref, manifest) in enumerate(pairs)
    )
    manifest_inventory = _self_hashed(
        GateManifestInventoryV1,
        {
            "schema_version": 1,
            "record_type": "gate_manifest_inventory_v1",
            "manifests": [entry.model_dump(mode="json") for entry in entries],
            "file_count": len(entries),
            "record_count": sum(entry.manifest_record_count for entry in entries),
            "manifest_content_size_bytes": sum(
                entry.manifest.content_size_bytes for entry in entries
            ),
        },
    )
    return raw_inventory, manifest_inventory, tuple(item[2] for item in pairs)


def _derive_buckets(
    *,
    evidence_root: Path,
    trace_set: Any,
    plan: WorkloadPlanV1,
    admission_started_monotonic_ns: int,
    database: _RunnerJoinDatabase,
    expected_config_sha256: str,
) -> tuple[tuple[GateSecondBucketV1, ...], int, int, int]:
    mutable = {
        (stream_group, second_index): _MutableBucket()
        for stream_group in _STREAM_GROUPS
        for second_index in range(plan.duration_seconds)
    }
    merged = iter_merged_trace_partitions(
        evidence_root,
        trace_set.partitions,
        max_rows=plan.expected_record_count,
        max_content_bytes=max(1, trace_set.merged_content_size_bytes),
        max_line_bytes=_TRACE_MAX_LINE_BYTES,
    )
    sentinel = object()
    accepted_count = 0
    accepted_payload_bytes = 0
    window_end = admission_started_monotonic_ns + plan.duration_ns
    admission_completed_monotonic_ns_max = admission_started_monotonic_ns
    for expected, observed in zip_longest(
        iter_plan_events(plan),
        merged,
        fillvalue=sentinel,
    ):
        if expected is sentinel or observed is sentinel:
            raise WriterGateRunError("trace and workload plan cardinalities disagree")
        assert isinstance(expected, PlannedEventV1)
        assert isinstance(observed, GateAdmissionTraceV1)
        due = admission_started_monotonic_ns + expected.due_offset_ns
        deadline = admission_started_monotonic_ns + expected.deadline_offset_ns
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
            raise WriterGateRunError("trace row disagrees with the workload plan")
        admission_completed_monotonic_ns_max = max(
            admission_completed_monotonic_ns_max,
            observed.admission_completed_monotonic_ns,
        )
        second_index = expected.due_offset_ns // _ONE_SECOND_NS
        bucket = mutable[(expected.stream_group, second_index)]
        bucket.scheduled_count += 1
        bucket.scheduled_payload_bytes += expected.payload_bytes
        bucket.attempted_count += 1
        bucket.attempted_payload_bytes += expected.payload_bytes
        bucket.early_count += int(observed.attempt_started_monotonic_ns < due)
        bucket.late_count += int(observed.admission_completed_monotonic_ns >= deadline)
        bucket.out_of_window_count += int(
            not (
                admission_started_monotonic_ns
                <= observed.attempt_started_monotonic_ns
                < window_end
                and admission_started_monotonic_ns
                <= observed.admission_completed_monotonic_ns
                < window_end
            )
        )
        if observed.enqueue_status in {
            EnqueueStatus.ACCEPTED,
            EnqueueStatus.ACCEPTED_HIGH_WATER,
        }:
            identity = observed.accepted_identity
            if (
                identity is None
                or identity.config_sha256 != expected_config_sha256
                or identity.config_generation != 0
            ):
                raise WriterGateRunError("accepted identity config binding is invalid")
            database.add_accepted(observed)
            bucket.accepted_count += 1
            bucket.accepted_payload_bytes += expected.payload_bytes
            accepted_count += 1
            accepted_payload_bytes += expected.payload_bytes
            actual_second = (
                observed.admission_completed_monotonic_ns
                - admission_started_monotonic_ns
            ) // _ONE_SECOND_NS
            if 0 <= actual_second < plan.duration_seconds:
                mutable[
                    (expected.stream_group, actual_second)
                ].admitted_in_actual_second_count += 1
    buckets = tuple(
        mutable[(stream_group, second_index)].freeze(stream_group, second_index)
        for stream_group in _STREAM_GROUPS
        for second_index in range(plan.duration_seconds)
    )
    return (
        buckets,
        accepted_count,
        accepted_payload_bytes,
        max(window_end, admission_completed_monotonic_ns_max),
    )


def _stream_runtime_summaries(
    plan: WorkloadPlanV1,
    buckets: tuple[GateSecondBucketV1, ...],
) -> tuple[GateStreamRuntimeSummaryV1, ...]:
    result: list[GateStreamRuntimeSummaryV1] = []
    for stream_plan in plan.streams:
        rows = tuple(
            bucket
            for bucket in buckets
            if bucket.stream_group == stream_plan.stream_group
        )
        burst = rows[stream_plan.burst_second]
        scheduled_count = sum(row.scheduled_count for row in rows)
        scheduled_bytes = sum(row.scheduled_payload_bytes for row in rows)
        attempted_count = sum(row.attempted_count for row in rows)
        attempted_bytes = sum(row.attempted_payload_bytes for row in rows)
        accepted_count = sum(row.accepted_count for row in rows)
        accepted_bytes = sum(row.accepted_payload_bytes for row in rows)
        early = sum(row.early_count for row in rows)
        late = sum(row.late_count for row in rows)
        out_of_window = sum(row.out_of_window_count for row in rows)
        result.append(
            GateStreamRuntimeSummaryV1(
                stream_group=stream_plan.stream_group,
                expected_record_count=stream_plan.expected_record_count,
                expected_payload_bytes=stream_plan.expected_payload_byte_count,
                scheduled_record_count=scheduled_count,
                scheduled_payload_bytes=scheduled_bytes,
                attempted_record_count=attempted_count,
                attempted_payload_bytes=attempted_bytes,
                accepted_record_count=accepted_count,
                accepted_payload_bytes=accepted_bytes,
                early_count=early,
                late_count=late,
                out_of_window_count=out_of_window,
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
                    scheduled_count == stream_plan.expected_record_count
                    and scheduled_bytes == stream_plan.expected_payload_byte_count
                ),
                admission_values_match=(
                    attempted_count
                    == accepted_count
                    == stream_plan.expected_record_count
                    and attempted_bytes
                    == accepted_bytes
                    == stream_plan.expected_payload_byte_count
                    and early == late == out_of_window == 0
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
    return tuple(result)


def _effective_warmup_ns(
    mode: EvidenceMode,
    *,
    configured_seconds: int,
    duration_ns: int,
    interval_ns: int,
) -> int:
    del mode, duration_ns, interval_ns
    configured_ns = configured_seconds * _ONE_SECOND_NS
    return configured_ns


def _runtime_summary(
    *,
    prepared: PreparedRun,
    admission_started_monotonic_ns: int,
    admission_started_utc_ns: int,
    buckets: tuple[GateSecondBucketV1, ...],
    worker_rounds: tuple[GateSamplingRoundV1, ...],
    resource_rounds: tuple[GateResourceSamplingRoundV1, ...],
    health_samples: tuple[GateStorageHealthSampleV1, ...],
    raw_inventory: GateRawInventoryV1,
    manifest_inventory: GateManifestInventoryV1,
    join_facts: _JoinFacts,
    accepted_count: int,
    accepted_payload_bytes: int,
) -> GateRuntimeSummaryV1:
    worker_sequences = validate_worker_rounds(
        worker_rounds,
        expected_workers=worker_rounds[0].expected_worker_keys,
        require_nonoverlap=prepared.mode == "qualification",
    )
    worker_aggregate = aggregate_final_worker_snapshots(worker_sequences)
    interval_ns = (
        prepared.workload.workload.qualification.storage_health_sample_interval_seconds
        * _ONE_SECOND_NS
    )
    warmup_ns = _effective_warmup_ns(
        prepared.mode,
        configured_seconds=prepared.workload.workload.qualification.warmup_seconds,
        duration_ns=prepared.request.duration_ns,
        interval_ns=interval_ns,
    )
    resource_summary = summarize_resources(
        resource_rounds,
        expected_processes=resource_rounds[0].expected_process_keys,
        warmup_ended_monotonic_ns=admission_started_monotonic_ns + warmup_ns,
        require_nonoverlap=prepared.mode == "qualification",
    )
    health_summary = summarize_storage_health(
        health_samples,
        duration_ns=prepared.request.duration_ns,
        interval_ns=interval_ns,
        require_nonoverlap=prepared.mode == "qualification",
    )
    stream_summaries = _stream_runtime_summaries(prepared.plan, buckets)
    final_worker_snapshots = {
        sample.snapshot.worker_instance_id: sample.snapshot
        for sample in worker_rounds[-1].samples
    }
    joined_workers = {facts.worker_instance_id: facts for facts in join_facts.workers}
    if joined_workers.keys() != final_worker_snapshots.keys():
        raise WriterGateRunError(
            "joined worker identities disagree with final worker snapshots"
        )
    for worker_instance_id, snapshot in final_worker_snapshots.items():
        facts = joined_workers[worker_instance_id]
        expected_high_water = facts.accepted_record_count - 1
        if (
            snapshot.lifecycle is not WriterLifecycle.CLOSED
            or facts.config_sha256 != snapshot.config_sha256
            or facts.config_generation != snapshot.config_generation
            or facts.accepted_record_count != snapshot.accepted_record_count
            or facts.durable_record_count != snapshot.durable_record_count
            or facts.acceptance_ordinal_min != 0
            or facts.acceptance_ordinal_max != expected_high_water
            or snapshot.acceptance_ordinal_high_water != expected_high_water
        ):
            raise WriterGateRunError(
                "joined worker facts disagree with final worker snapshots"
            )
    if (
        join_facts.unique_accepted_count != accepted_count
        or join_facts.durable_record_count != raw_inventory.record_count
        or join_facts.durable_record_count != manifest_inventory.record_count
        or join_facts.durable_payload_bytes != accepted_payload_bytes
    ):
        raise WriterGateRunError(
            "joined raw facts disagree with trace or inventory totals"
        )
    declared_hour = datetime.fromtimestamp(
        admission_started_utc_ns // _ONE_SECOND_NS,
        tz=UTC,
    ).strftime("%Y/%m/%d/%H")
    if join_facts.received_utc_hours != (declared_hour,):
        raise WriterGateRunError(
            "durable raw rows escaped the declared admission UTC hour"
        )
    expected = prepared.plan.expected_record_count
    expected_payload = prepared.plan.expected_payload_byte_count
    return GateRuntimeSummaryV1(
        expected_record_count=expected,
        expected_payload_bytes=expected_payload,
        scheduled_record_count=sum(item.scheduled_count for item in buckets),
        scheduled_payload_bytes=sum(item.scheduled_payload_bytes for item in buckets),
        attempted_record_count=sum(item.attempted_count for item in buckets),
        attempted_payload_bytes=sum(item.attempted_payload_bytes for item in buckets),
        accepted_record_count=accepted_count,
        accepted_payload_bytes=accepted_payload_bytes,
        durable_record_count=join_facts.durable_record_count,
        durable_payload_bytes=join_facts.durable_payload_bytes,
        durability_sample_count=worker_aggregate.durability_sample_count,
        manifest_record_count=manifest_inventory.record_count,
        raw_file_count=raw_inventory.file_count,
        manifest_file_count=manifest_inventory.file_count,
        declared_file_identity_count=prepared.plan.declared_file_identity_count,
        expected_touched_file_identity_count=(
            prepared.plan.expected_touched_file_identity_count
        ),
        observed_touched_file_identity_count=join_facts.touched_identity_count,
        accepted_identity_count=accepted_count,
        unique_accepted_identity_count=join_facts.unique_accepted_count,
        early_count=sum(item.early_count for item in buckets),
        late_count=sum(item.late_count for item in buckets),
        out_of_window_count=sum(item.out_of_window_count for item in buckets),
        received_utc_hours=join_facts.received_utc_hours,
        stream_summaries=stream_summaries,
        final_worker_aggregate=worker_aggregate,
        resource_summary=resource_summary,
        storage_health_summary=health_summary,
    )


def _assert_runtime_candidate_passes(
    prepared: PreparedRun,
    summary: GateRuntimeSummaryV1,
) -> None:
    qualification = prepared.mode == "qualification"
    expected = summary.expected_record_count
    expected_payload = summary.expected_payload_bytes
    counts = (
        summary.scheduled_record_count,
        summary.attempted_record_count,
        summary.accepted_record_count,
        summary.durable_record_count,
        summary.durability_sample_count,
        summary.manifest_record_count,
    )
    payloads = (
        summary.scheduled_payload_bytes,
        summary.attempted_payload_bytes,
        summary.accepted_payload_bytes,
        summary.durable_payload_bytes,
    )
    aggregate = summary.final_worker_aggregate
    limits = prepared.workload.workload.qualification
    interval_ns = limits.storage_health_sample_interval_seconds * _ONE_SECOND_NS
    max_gap_ns = limits.storage_health_max_gap_seconds * _ONE_SECOND_NS
    resource = summary.resource_summary
    qualification_trend_failure = qualification and (
        not resource.resource_trend_valid
        or resource.rss_slope_bytes_per_minute is None
        or resource.rss_slope_bytes_per_minute > limits.max_rss_slope_bytes_per_minute
        or resource.fd_growth_after_warmup is None
        or resource.fd_growth_after_warmup > limits.max_fd_growth_after_warmup
    )
    stream_failure = not all(
        stream.planned_values_match
        and (
            (stream.admission_values_match and stream.burst_valid)
            if qualification
            else (
                stream.scheduled_record_count
                == stream.attempted_record_count
                == stream.accepted_record_count
                == stream.expected_record_count
                and stream.scheduled_payload_bytes
                == stream.attempted_payload_bytes
                == stream.accepted_payload_bytes
                == stream.expected_payload_bytes
                and stream.early_count == 0
                and stream.burst_scheduled_count
                == stream.burst_attempted_count
                == stream.burst_accepted_count
                == stream.scheduled_burst_count
            )
        )
        for stream in summary.stream_summaries
    )
    qualification_timing_failure = qualification and (
        summary.late_count != 0 or summary.out_of_window_count != 0
    )
    qualification_worker_failure = qualification and (
        aggregate.slo_breach_count != 0
        or aggregate.durability_lag_max_ns is None
        or aggregate.durability_lag_max_ns > limits.durability_lag_max_ns
        or aggregate.active_logical_generation_count_peak
        != summary.expected_touched_file_identity_count
        or aggregate.retiring_generation_count_peak != 0
    )
    qualification_resource_failure = qualification and (
        resource.rss_peak_bytes > limits.max_rss_bytes
        or resource.open_fds_peak > limits.max_open_fds
        or resource.coverage_ns < max(0, prepared.request.duration_ns - interval_ns)
        or resource.sample_max_gap_ns > max_gap_ns
        or not summary.storage_health_summary.sample_count_valid
        or not summary.storage_health_summary.coverage_valid
    )
    failure = (
        any(value != expected for value in counts)
        or any(value != expected_payload for value in payloads)
        or summary.raw_file_count != summary.expected_touched_file_identity_count
        or summary.manifest_file_count != summary.expected_touched_file_identity_count
        or summary.observed_touched_file_identity_count
        != summary.expected_touched_file_identity_count
        or summary.accepted_identity_count != summary.unique_accepted_identity_count
        or summary.early_count != 0
        or qualification_timing_failure
        or len(summary.received_utc_hours) != 1
        or stream_failure
        or any(
            value != 0
            for value in (
                aggregate.unpersisted_record_count,
                aggregate.uncertain_record_count,
                aggregate.normal_overflow_count,
                aggregate.control_overflow_count,
                aggregate.not_accepting_count,
                aggregate.write_failure_count,
                aggregate.sync_failure_count,
                aggregate.publication_failure_count,
            )
        )
        or qualification_worker_failure
        or qualification_resource_failure
        or qualification_trend_failure
        or not summary.storage_health_summary.workers_healthy
    )
    if failure:
        raise WriterGateRunError("writer runtime predicates did not pass")


def _available_bytes(path: Path) -> int:
    facts = os.statvfs(path)
    return int(facts.f_bavail) * int(facts.f_frsize)


def _abort_processes(processes: Sequence[Any]) -> tuple[str, ...]:
    errors: list[str] = []
    for process in processes:
        try:
            if process.is_alive():
                process.terminate()
        except BaseException as error:  # noqa: BLE001 - signal every process
            errors.append(f"terminate:{process.name}:{type(error).__name__}")
    terminate_deadline = time.monotonic() + 10.0
    for process in processes:
        try:
            process.join(timeout=max(0.0, terminate_deadline - time.monotonic()))
        except BaseException as error:  # noqa: BLE001 - join every process
            errors.append(f"join:{process.name}:{type(error).__name__}")
    survivors: list[Any] = []
    for process in processes:
        try:
            if process.is_alive():
                survivors.append(process)
                process.kill()
        except BaseException as error:  # noqa: BLE001 - kill every survivor
            errors.append(f"kill:{process.name}:{type(error).__name__}")
    kill_deadline = time.monotonic() + 10.0
    for process in survivors:
        try:
            process.join(timeout=max(0.0, kill_deadline - time.monotonic()))
            if process.is_alive():
                errors.append(f"survivor:{process.name}:{process.pid}")
        except BaseException as error:  # noqa: BLE001 - account every survivor
            errors.append(f"kill-join:{process.name}:{type(error).__name__}")
    return tuple(errors)


def _start_processes(processes: Sequence[Any], abort_event: Any) -> tuple[Any, ...]:
    started: list[Any] = []
    try:
        for process in processes:
            process.start()
            started.append(process)
    except BaseException as error:
        abort_event.set()
        for abort_error in _abort_processes(started):
            error.add_note("partial process-start cleanup failed: " + abort_error)
        raise
    return tuple(started)


def _close_runner_resources(
    *,
    join_database: _RunnerJoinDatabase | None,
    parent_commands: Sequence[Connection],
    child_connections: Sequence[Connection],
    result_queue: Any,
) -> tuple[BaseException, ...]:
    errors: list[BaseException] = []
    if join_database is not None:
        try:
            join_database.close()
        except BaseException as error:  # noqa: BLE001 - close all resources
            errors.append(error)
    for connection in (*parent_commands, *child_connections):
        try:
            connection.close()
        except BaseException as error:  # noqa: BLE001 - close all resources
            errors.append(error)
    try:
        result_queue.close()
    except BaseException as error:  # noqa: BLE001 - preserve every cleanup error
        errors.append(error)
    try:
        result_queue.join_thread()
    except BaseException as error:  # noqa: BLE001 - preserve every cleanup error
        errors.append(error)
    return tuple(errors)


def _raise_cleanup_failure(errors: Sequence[BaseException]) -> None:
    if not errors:
        return
    failure = WriterGateRunError("writer runner resource cleanup failed")
    for error in errors[1:]:
        failure.add_note(f"additional cleanup failure: {type(error).__name__}")
    raise failure from errors[0]


def _decode_sample(model_type: type[_ModelT], source: object) -> _ModelT:
    if type(source) is not bytes:
        raise WriterGateRunError("child sample message is not canonical bytes")
    try:
        model = model_type.model_validate_json(source, strict=True)
    except (TypeError, ValueError) as error:
        raise WriterGateRunError("child sample message is invalid") from error
    canonical_bytes = getattr(model, "canonical_bytes", None)
    if not callable(canonical_bytes) or canonical_bytes() != source:
        raise WriterGateRunError("child sample message is not canonical")
    return model


def _worker_keys() -> tuple[GateWorkerKeyV1, ...]:
    return tuple(
        GateWorkerKeyV1(
            exchange=exchange,
            worker_instance_id=f"gate-worker-v1-{exchange.value}",
        )
        for exchange in CANONICAL_EXCHANGES
    )


def _process_keys() -> tuple[GateProcessKeyV1, ...]:
    return (
        GateProcessKeyV1(
            role="supervisor",
            exchange=None,
            worker_instance_id=None,
        ),
        *(
            GateProcessKeyV1(
                role="exchange_worker",
                exchange=exchange,
                worker_instance_id=f"gate-worker-v1-{exchange.value}",
            )
            for exchange in CANONICAL_EXCHANGES
        ),
    )


def _health_rows(
    *,
    schedules: tuple[int, ...],
    worker_samples: dict[tuple[int, Exchange], GateWorkerSampleV1],
    availability: dict[int, tuple[int, int, int, int]],
) -> tuple[GateStorageHealthSampleV1, ...]:
    rows: list[GateStorageHealthSampleV1] = []
    for round_index in range(len(schedules)):
        facts = availability.get(round_index)
        samples = tuple(
            worker_samples.get((round_index, exchange))
            for exchange in CANONICAL_EXCHANGES
        )
        if facts is None or any(sample is None for sample in samples):
            break
        started, completed, data_available, state_available = facts
        typed_samples = cast(tuple[GateWorkerSampleV1, ...], samples)
        rows.append(
            GateStorageHealthSampleV1(
                round_index=len(rows),
                scheduled_monotonic_ns=schedules[round_index],
                request_started_monotonic_ns=started,
                request_completed_monotonic_ns=completed,
                data_available_bytes=data_available,
                state_available_bytes=state_available,
                workers=tuple(
                    GateWorkerHealthV1(
                        exchange=sample.snapshot.exchange,
                        worker_instance_id=sample.snapshot.worker_instance_id,
                        lifecycle=sample.snapshot.lifecycle,
                        critical_reason=sample.snapshot.critical_reason,
                    )
                    for sample in typed_samples
                ),
            )
        )
    return tuple(rows)


def _publish_partial_health(
    evidence_root: Path,
    *,
    schedules: tuple[int, ...],
    worker_samples: dict[tuple[int, Exchange], GateWorkerSampleV1],
    availability: dict[int, tuple[int, int, int, int]],
) -> None:
    worker_path = evidence_root / "diagnostics/workers-partial.jsonl.zst"
    if not worker_path.exists() and not Path(f"{worker_path}.partial").exists():
        worker_rows = tuple(
            worker_samples[(round_index, exchange)]
            for round_index in sorted({key[0] for key in worker_samples})
            for exchange in CANONICAL_EXCHANGES
            if (round_index, exchange) in worker_samples
        )
        write_jsonl_zstd(
            evidence_root,
            "diagnostics/workers-partial.jsonl.zst",
            worker_rows,
            zstd_level=_ARTIFACT_ZSTD_LEVEL,
        )

    health_path = evidence_root / "diagnostics/storage-health-partial.jsonl.zst"
    if health_path.exists() or Path(f"{health_path}.partial").exists():
        return
    health_rows = _health_rows(
        schedules=schedules,
        worker_samples=worker_samples,
        availability=availability,
    )
    write_jsonl_zstd(
        evidence_root,
        "diagnostics/storage-health-partial.jsonl.zst",
        health_rows,
        zstd_level=_ARTIFACT_ZSTD_LEVEL,
    )


def _message_exchange(message: dict[str, object]) -> Exchange:
    source = message.get("exchange")
    if type(source) is not str:
        raise WriterGateRunError("child message has an invalid exchange")
    try:
        return Exchange(source)
    except ValueError as error:
        raise WriterGateRunError("child message has an invalid exchange") from error


def _store_child_message(
    message: object,
    *,
    ready: dict[Exchange, dict[str, object]],
    worker_samples: dict[tuple[int, Exchange], GateWorkerSampleV1],
    resource_samples: dict[tuple[int, Exchange], GateProcessResourceSampleV1],
    closed: dict[Exchange, dict[str, object]],
    final_workers: dict[Exchange, GateWorkerSampleV1],
    final_resources: dict[Exchange, GateProcessResourceSampleV1],
) -> None:
    if not isinstance(message, dict) or type(message.get("kind")) is not str:
        raise WriterGateRunError("child emitted an invalid status message")
    kind = cast(str, message["kind"])
    exchange = _message_exchange(cast(dict[str, object], message))
    if kind == "error":
        raise WriterGateRunError(
            "writer child failed: "
            + str(message.get("error_type", "unknown"))
            + ": "
            + str(message.get("message", ""))
        )
    if kind == "ready":
        if exchange in ready:
            raise WriterGateRunError("writer child emitted duplicate readiness")
        ready[exchange] = cast(dict[str, object], message)
        return
    if kind == "sample":
        round_index = message.get("round_index")
        if type(round_index) is not int:
            raise WriterGateRunError("writer child sample round is invalid")
        key = (round_index, exchange)
        if key in worker_samples or key in resource_samples:
            raise WriterGateRunError("writer child emitted a duplicate sample")
        worker_samples[key] = _decode_sample(
            GateWorkerSampleV1,
            message.get("worker"),
        )
        resource_samples[key] = _decode_sample(
            GateProcessResourceSampleV1,
            message.get("resource"),
        )
        return
    if kind == "closed":
        if exchange in closed:
            raise WriterGateRunError("writer child emitted duplicate close status")
        closed[exchange] = cast(dict[str, object], message)
        return
    if kind == "final":
        if exchange in final_workers or exchange in final_resources:
            raise WriterGateRunError("writer child emitted duplicate final status")
        final_workers[exchange] = _decode_sample(
            GateWorkerSampleV1,
            message.get("worker"),
        )
        final_resources[exchange] = _decode_sample(
            GateProcessResourceSampleV1,
            message.get("resource"),
        )
        return
    raise WriterGateRunError("writer child emitted an unknown status message")


def _publish_candidate_dag(
    *,
    prepared: PreparedRun,
    workload_document_path: Path,
    run_started_monotonic_ns: int,
    admission_started_monotonic_ns: int,
    admission_started_utc_ns: int,
    admission_ended_monotonic_ns: int,
    trace_set: Any,
    bucket_ref: GateArtifactRefV1,
    worker_ref: GateArtifactRefV1,
    resource_ref: GateArtifactRefV1,
    health_ref: GateArtifactRefV1,
    raw_inventory: GateRawInventoryV1,
    manifest_inventory: GateManifestInventoryV1,
    summary: GateRuntimeSummaryV1,
) -> WriterRunResult:
    evidence_root = prepared.evidence_root
    raw_inventory_path = evidence_root / "raw-inventory.json"
    manifest_inventory_path = evidence_root / "manifest-inventory.json"
    _publish_bytes_no_replace(raw_inventory_path, raw_inventory.canonical_bytes())
    _publish_bytes_no_replace(
        manifest_inventory_path,
        manifest_inventory.canonical_bytes(),
    )

    target_ref: GateEvidenceDocumentRefV1 | None = None
    target_sha256: str | None = None
    claims = prepared.request.qualification
    if claims is not None:
        frozen_target_source = prepared.target_declaration_source
        if frozen_target_source is None:
            raise WriterGateRunError(
                "qualification target declaration was not frozen at preflight"
            )
        try:
            current_target = load_target_declaration(claims.target_declaration_path)
        except (OSError, ValueError) as error:
            raise WriterGateRunError(
                "qualification target declaration changed after preflight"
            ) from error
        if current_target.canonical_bytes() != frozen_target_source:
            raise WriterGateRunError(
                "qualification target declaration changed after preflight"
            )
        target_path = evidence_root / "target-declaration.json"
        _publish_bytes_no_replace(target_path, frozen_target_source)
        target_ref = _document_ref(evidence_root, target_path)
        target_sha256 = current_target.sha256

    run_id = str(uuid.uuid4())
    scheduled_end_monotonic_ns = (
        admission_started_monotonic_ns + prepared.request.duration_ns
    )
    if admission_ended_monotonic_ns < scheduled_end_monotonic_ns:
        raise WriterGateRunError("admission ended before its scheduled boundary")
    run_ended_monotonic_ns = max(admission_ended_monotonic_ns, time.monotonic_ns())
    admission_ended_utc_ns = admission_started_utc_ns + (
        admission_ended_monotonic_ns - admission_started_monotonic_ns
    )
    candidate = _self_hashed(
        GateCandidateReportV1,
        {
            "schema_version": 1,
            "record_type": "gate_candidate_report_v1",
            "run_id": run_id,
            "mode": prepared.mode,
            "workload_sha256": prepared.workload.sha256,
            "workload_plan_sha256": prepared.plan.workload_plan_sha256,
            "multiplier": prepared.request.multiplier,
            "duration_ns": prepared.request.duration_ns,
            "run_started_monotonic_ns": run_started_monotonic_ns,
            "admission_started_monotonic_ns": admission_started_monotonic_ns,
            "admission_scheduled_end_monotonic_ns": scheduled_end_monotonic_ns,
            "admission_ended_monotonic_ns": admission_ended_monotonic_ns,
            "run_ended_monotonic_ns": run_ended_monotonic_ns,
            "admission_started_utc_ns": admission_started_utc_ns,
            "admission_ended_utc_ns": admission_ended_utc_ns,
            "declared_admission_utc_hour": datetime.fromtimestamp(
                admission_started_utc_ns // _ONE_SECOND_NS,
                tz=UTC,
            ).strftime("%Y/%m/%d/%H"),
            "expected_target_id": None if claims is None else claims.expected_target_id,
            "target_declaration_sha256": target_sha256,
            "expected_image_id": None if claims is None else claims.expected_image_id,
            "runtime_image_id": None if claims is None else claims.runtime_image_id,
            "runtime_summary": summary.model_dump(mode="json"),
            "runtime_failure_codes": [],
            "candidate_runtime_passed": True,
        },
    )
    candidate_path = evidence_root / "candidate-report.json"
    candidate_source = candidate.canonical_bytes()
    candidate_ref = _document_ref_from_source(
        relative_path="candidate-report.json",
        source=candidate_source,
    )

    run_index = _self_hashed(
        GateRunIndexV1,
        {
            "schema_version": 1,
            "record_type": "gate_run_index_v1",
            "run_id": run_id,
            "status": "complete",
            "mode": prepared.mode,
            "artifact_schema_version": 1,
            "identity_algorithm": "gate-identity-v1",
            "event_algorithm": "gate-event-v1",
            "payload_algorithm": "gate-payload-v1",
            "schedule_algorithm": "gate-schedule-v2-full-second-burst",
            "data_root": prepared.data_root.as_posix(),
            "state_root": prepared.state_root.as_posix(),
            "workload_document": _document_ref(
                evidence_root,
                workload_document_path,
            ).model_dump(mode="json"),
            "workload_sha256": prepared.workload.sha256,
            "workload_plan_sha256": prepared.plan.workload_plan_sha256,
            "admission_trace_set": trace_set.model_dump(mode="json"),
            "second_bucket_artifact": bucket_ref.model_dump(mode="json"),
            "worker_sampling_artifact": worker_ref.model_dump(mode="json"),
            "resource_sampling_artifact": resource_ref.model_dump(mode="json"),
            "storage_health_artifact": health_ref.model_dump(mode="json"),
            "raw_inventory": _document_ref(
                evidence_root,
                raw_inventory_path,
            ).model_dump(mode="json"),
            "manifest_inventory": _document_ref(
                evidence_root,
                manifest_inventory_path,
            ).model_dump(mode="json"),
            "candidate_report": candidate_ref.model_dump(mode="json"),
            "expected_target_id": None if claims is None else claims.expected_target_id,
            "target_declaration": (
                None if target_ref is None else target_ref.model_dump(mode="json")
            ),
            "implementation_source_commit": (
                None if claims is None else claims.implementation_source_commit
            ),
            "collector_wheel_sha256": (
                None if claims is None else claims.collector_wheel_sha256
            ),
            "requirements_lock_sha256": (
                None if claims is None else claims.requirements_lock_sha256
            ),
            "dockerfile_sha256": None if claims is None else claims.dockerfile_sha256,
            "expected_image_id": None if claims is None else claims.expected_image_id,
            "runtime_image_id": None if claims is None else claims.runtime_image_id,
        },
    )
    evaluation = evaluate_runtime_candidate(
        evidence_root=evidence_root,
        run_index=run_index,
        candidate_source=candidate_source,
        target_probe=None if claims is None else reprobe_target,
    )
    if not evaluation.runtime_evidence_valid:
        codes = ",".join(evaluation.failure_codes) or "unknown"
        raise WriterGateRunError(
            "precommit runtime verifier rejected the candidate: " + codes
        )
    _publish_bytes_no_replace(candidate_path, candidate_source)
    if _document_ref(evidence_root, candidate_path) != candidate_ref:
        raise WriterGateRunError(
            "published candidate report changed after verification"
        )
    run_index_path = evidence_root / "run-index.json"
    result = WriterRunResult(
        run_index_path=run_index_path,
        report_path=prepared.report_path,
        run_index=run_index,
        candidate_report=candidate,
        child_process_count=len(CANONICAL_EXCHANGES),
    )
    _publish_bytes_no_replace(prepared.report_path, candidate.canonical_bytes())
    _publish_bytes_no_replace(run_index_path, run_index.canonical_bytes())
    return result


def run_writer_gate(request: RunRequest) -> WriterRunResult:
    prepared = prepare_run(request)
    workload_document_path = _materialize_run(prepared)
    run_started_monotonic_ns = time.monotonic_ns()
    workload_plan_sha256 = prepared.plan.workload_plan_sha256
    plan_header_bytes = prepared.plan.header.canonical_bytes()
    stream_summary_bytes = tuple(
        encode_json(summary.model_dump(mode="json")) + b"\n"
        for summary in prepared.plan.streams
    )

    context = multiprocessing.get_context("spawn")
    result_queue = context.Queue(maxsize=_STATUS_QUEUE_MAX_MESSAGES)
    abort_event = context.Event()
    parent_commands: dict[Exchange, Connection] = {}
    child_connections: list[Connection] = []
    processes_list: list[Any] = []
    for exchange in CANONICAL_EXCHANGES:
        parent_command, child_command = context.Pipe(duplex=True)
        parent_commands[exchange] = parent_command
        child_connections.append(child_command)
        spawned_process = context.Process(
            target=_child_entry,
            name=f"writer-gate-{exchange.value}",
            args=(
                _ChildSpec(
                    workload_path=prepared.request.workload_path.as_posix(),
                    workload_sha256=prepared.workload.sha256,
                    multiplier=prepared.request.multiplier,
                    duration_ns=prepared.request.duration_ns,
                    data_root=prepared.data_root.as_posix(),
                    state_root=prepared.state_root.as_posix(),
                    evidence_root=prepared.evidence_root.as_posix(),
                    exchange=exchange.value,
                    mode=prepared.mode,
                    config_sha256=prepared.config_sha256,
                    workload_plan_sha256=workload_plan_sha256,
                    plan_header_bytes=plan_header_bytes,
                    stream_summary_bytes=stream_summary_bytes,
                ),
                child_command,
                result_queue,
                abort_event,
            ),
        )
        processes_list.append(spawned_process)
    processes = tuple(processes_list)

    ready: dict[Exchange, dict[str, object]] = {}
    worker_samples: dict[tuple[int, Exchange], GateWorkerSampleV1] = {}
    child_resource_samples: dict[tuple[int, Exchange], GateProcessResourceSampleV1] = {}
    closed: dict[Exchange, dict[str, object]] = {}
    final_workers: dict[Exchange, GateWorkerSampleV1] = {}
    final_resources: dict[Exchange, GateProcessResourceSampleV1] = {}
    supervisor_resources: dict[int, GateProcessResourceSampleV1] = {}
    availability: dict[int, tuple[int, int, int, int]] = {}
    started_processes: list[Any] = []
    schedules: tuple[int, ...] = ()
    join_database: _RunnerJoinDatabase | None = None
    resources_closed = False

    try:
        started_processes.extend(_start_processes(processes, abort_event))
        for child_connection in child_connections:
            child_connection.close()

        ready_deadline = time.monotonic() + _CHILD_READY_TIMEOUT_SECONDS
        while len(ready) < len(CANONICAL_EXCHANGES):
            remaining = ready_deadline - time.monotonic()
            if remaining <= 0:
                raise WriterGateRunError("writer child readiness timed out")
            try:
                message = result_queue.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                if any(
                    child_process.exitcode is not None
                    for child_process in started_processes
                ):
                    raise WriterGateRunError("writer child exited before readiness")
                if _abort_requested(abort_event):
                    raise WriterGateRunError(
                        "writer child requested a global abort before readiness"
                    )
                continue
            _store_child_message(
                message,
                ready=ready,
                worker_samples=worker_samples,
                resource_samples=child_resource_samples,
                closed=closed,
                final_workers=final_workers,
                final_resources=final_resources,
            )
        for exchange in CANONICAL_EXCHANGES:
            facts = ready[exchange]
            if (
                facts.get("config_sha256") != prepared.config_sha256
                or facts.get("workload_sha256") != prepared.workload.sha256
                or facts.get("workload_plan_sha256") != workload_plan_sha256
                or type(facts.get("pid")) is not int
                or type(facts.get("planned_row_count")) is not int
            ):
                raise WriterGateRunError("writer child readiness facts disagree")
        if (
            sum(
                cast(int, ready[exchange]["planned_row_count"])
                for exchange in CANONICAL_EXCHANGES
            )
            != prepared.plan.expected_record_count
        ):
            raise WriterGateRunError(
                "writer child generators do not cover the global workload plan"
            )
        ready_pids = tuple(
            cast(int, ready[exchange]["pid"]) for exchange in CANONICAL_EXCHANGES
        )
        if (
            len(set(ready_pids)) != len(CANONICAL_EXCHANGES)
            or os.getpid() in ready_pids
        ):
            raise WriterGateRunError("writer child process identities are not unique")

        _validate_hour_capacity(time.time_ns(), prepared.request.duration_ns)
        start_delay_ns = 2 * _ONE_SECOND_NS
        admission_started_monotonic_ns = time.monotonic_ns() + start_delay_ns
        admission_started_utc_ns = time.time_ns() + start_delay_ns
        interval_ns = (
            prepared.workload.workload.qualification.storage_health_sample_interval_seconds
            * _ONE_SECOND_NS
        )
        schedules = tuple(
            range(
                admission_started_monotonic_ns,
                admission_started_monotonic_ns + prepared.request.duration_ns,
                interval_ns,
            )
        )
        start_command = {
            "kind": "start",
            "monotonic_ns": admission_started_monotonic_ns,
            "utc_ns": admission_started_utc_ns,
            "sample_schedules": schedules,
        }
        for command in parent_commands.values():
            command.send(start_command)

        finish_deadline = (
            time.monotonic()
            + start_delay_ns / _ONE_SECOND_NS
            + prepared.request.duration_ns / _ONE_SECOND_NS
            + _child_finish_grace_seconds(prepared.mode)
        )
        next_sample_index = 0
        supervisor_key = _process_keys()[0]
        while len(closed) < len(CANONICAL_EXCHANGES):
            now_monotonic_ns = time.monotonic_ns()
            while (
                next_sample_index < len(schedules)
                and now_monotonic_ns >= schedules[next_sample_index]
            ):
                scheduled = schedules[next_sample_index]
                supervisor_resources[next_sample_index] = _process_resource_sample(
                    round_index=next_sample_index,
                    scheduled_monotonic_ns=scheduled,
                    process_key=supervisor_key,
                    clock=SystemClock(),
                )
                health_started = max(scheduled, time.monotonic_ns())
                try:
                    data_available = _available_bytes(prepared.data_root)
                    state_available = _available_bytes(prepared.state_root)
                except OSError as error:
                    _publish_partial_health(
                        prepared.evidence_root,
                        schedules=schedules,
                        worker_samples=worker_samples,
                        availability=availability,
                    )
                    raise WriterGateRunError(
                        "periodic storage-health statvfs failed"
                    ) from error
                health_completed = max(health_started, time.monotonic_ns())
                availability[next_sample_index] = (
                    health_started,
                    health_completed,
                    data_available,
                    state_available,
                )
                next_sample_index += 1
                now_monotonic_ns = time.monotonic_ns()

            if time.monotonic() >= finish_deadline:
                raise WriterGateRunError("writer children did not close before timeout")
            timeout = 0.25
            if next_sample_index < len(schedules):
                timeout = min(
                    timeout,
                    max(
                        0.001,
                        (schedules[next_sample_index] - time.monotonic_ns())
                        / _ONE_SECOND_NS,
                    ),
                )
            try:
                message = result_queue.get(timeout=timeout)
            except queue.Empty:
                if any(
                    child_process.exitcode is not None
                    for child_process in started_processes
                ):
                    raise WriterGateRunError("writer child exited during admission")
                if _abort_requested(abort_event):
                    raise WriterGateRunError(
                        "writer child requested a global abort during admission"
                    )
                continue
            _store_child_message(
                message,
                ready=ready,
                worker_samples=worker_samples,
                resource_samples=child_resource_samples,
                closed=closed,
                final_workers=final_workers,
                final_resources=final_resources,
            )

        while next_sample_index < len(schedules):
            scheduled = schedules[next_sample_index]
            delay = scheduled - time.monotonic_ns()
            if delay > 0:
                time.sleep(delay / _ONE_SECOND_NS)
            supervisor_resources[next_sample_index] = _process_resource_sample(
                round_index=next_sample_index,
                scheduled_monotonic_ns=scheduled,
                process_key=supervisor_key,
                clock=SystemClock(),
            )
            health_started = max(scheduled, time.monotonic_ns())
            data_available = _available_bytes(prepared.data_root)
            state_available = _available_bytes(prepared.state_root)
            health_completed = max(health_started, time.monotonic_ns())
            availability[next_sample_index] = (
                health_started,
                health_completed,
                data_available,
                state_available,
            )
            next_sample_index += 1

        expected_periodic = len(schedules) * len(CANONICAL_EXCHANGES)
        sample_deadline = time.monotonic() + _parent_coordination_timeout_seconds(
            prepared.mode
        )
        while (
            len(worker_samples) < expected_periodic
            or len(child_resource_samples) < expected_periodic
        ):
            remaining = sample_deadline - time.monotonic()
            if remaining <= 0:
                _publish_partial_health(
                    prepared.evidence_root,
                    schedules=schedules,
                    worker_samples=worker_samples,
                    availability=availability,
                )
                raise WriterGateRunError("writer periodic sampling is incomplete")
            try:
                message = result_queue.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                if _abort_requested(abort_event):
                    raise WriterGateRunError(
                        "writer child requested a global abort during sampling"
                    )
                continue
            _store_child_message(
                message,
                ready=ready,
                worker_samples=worker_samples,
                resource_samples=child_resource_samples,
                closed=closed,
                final_workers=final_workers,
                final_resources=final_resources,
            )

        final_round_index = len(schedules)
        final_scheduled = max(
            admission_started_monotonic_ns + prepared.request.duration_ns,
            time.monotonic_ns() + 200_000_000,
        )
        final_command = {
            "kind": "final",
            "round_index": final_round_index,
            "scheduled_monotonic_ns": final_scheduled,
        }
        for command in parent_commands.values():
            command.send(final_command)
        delay = final_scheduled - time.monotonic_ns()
        if delay > 0:
            time.sleep(delay / _ONE_SECOND_NS)
        supervisor_resources[final_round_index] = _process_resource_sample(
            round_index=final_round_index,
            scheduled_monotonic_ns=final_scheduled,
            process_key=supervisor_key,
            clock=SystemClock(),
        )
        final_deadline = time.monotonic() + _parent_coordination_timeout_seconds(
            prepared.mode
        )
        while len(final_workers) < len(CANONICAL_EXCHANGES):
            remaining = final_deadline - time.monotonic()
            if remaining <= 0:
                raise WriterGateRunError("writer final sampling is incomplete")
            try:
                message = result_queue.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                if _abort_requested(abort_event):
                    raise WriterGateRunError(
                        "writer child requested a global abort before final sampling"
                    )
                continue
            _store_child_message(
                message,
                ready=ready,
                worker_samples=worker_samples,
                resource_samples=child_resource_samples,
                closed=closed,
                final_workers=final_workers,
                final_resources=final_resources,
            )

        join_deadline = time.monotonic() + _parent_coordination_timeout_seconds(
            prepared.mode
        )
        for child_process in processes:
            child_process.join(timeout=max(0.0, join_deadline - time.monotonic()))
        if any(child_process.exitcode != 0 for child_process in processes):
            raise WriterGateRunError("writer child did not exit successfully")
        for exchange in CANONICAL_EXCHANGES:
            if closed[exchange].get("attempted") != ready[exchange].get(
                "planned_row_count"
            ):
                raise WriterGateRunError(
                    "writer child outcomes do not cover its generated plan"
                )

        worker_keys = _worker_keys()
        process_keys = _process_keys()
        worker_rounds_list: list[GateSamplingRoundV1] = []
        resource_rounds_list: list[GateResourceSamplingRoundV1] = []
        for round_index, scheduled in enumerate(schedules):
            ordered_workers = tuple(
                worker_samples[(round_index, exchange)]
                for exchange in CANONICAL_EXCHANGES
            )
            ordered_resources = (
                supervisor_resources[round_index],
                *(
                    child_resource_samples[(round_index, exchange)]
                    for exchange in CANONICAL_EXCHANGES
                ),
            )
            worker_rounds_list.append(
                GateSamplingRoundV1(
                    round_index=round_index,
                    round_kind="periodic",
                    scheduled_monotonic_ns=scheduled,
                    expected_worker_keys=worker_keys,
                    samples=ordered_workers,
                )
            )
            resource_rounds_list.append(
                GateResourceSamplingRoundV1(
                    round_index=round_index,
                    scheduled_monotonic_ns=scheduled,
                    expected_process_keys=process_keys,
                    samples=ordered_resources,
                )
            )
        worker_rounds_list.append(
            GateSamplingRoundV1(
                round_index=final_round_index,
                round_kind="final",
                scheduled_monotonic_ns=final_scheduled,
                expected_worker_keys=worker_keys,
                samples=tuple(
                    final_workers[exchange] for exchange in CANONICAL_EXCHANGES
                ),
            )
        )
        resource_rounds_list.append(
            GateResourceSamplingRoundV1(
                round_index=final_round_index,
                scheduled_monotonic_ns=final_scheduled,
                expected_process_keys=process_keys,
                samples=(
                    supervisor_resources[final_round_index],
                    *(final_resources[exchange] for exchange in CANONICAL_EXCHANGES),
                ),
            )
        )
        worker_rounds = tuple(worker_rounds_list)
        resource_rounds = tuple(resource_rounds_list)
        health_samples = _health_rows(
            schedules=schedules,
            worker_samples=worker_samples,
            availability=availability,
        )
        if len(health_samples) != len(schedules):
            _publish_partial_health(
                prepared.evidence_root,
                schedules=schedules,
                worker_samples=worker_samples,
                availability=availability,
            )
            raise WriterGateRunError("writer health sampling is incomplete")

        partitions = tuple(
            GateExchangeArtifactPartitionV1(
                exchange=exchange,
                artifact=_decode_sample(
                    GateArtifactRefV1,
                    closed[exchange].get("trace_ref"),
                ),
            )
            for exchange in CANONICAL_EXCHANGES
        )
        trace_content_bound = sum(
            partition.artifact.content_size_bytes for partition in partitions
        )
        trace_set = build_admission_trace_set(
            prepared.evidence_root,
            partitions,
            max_rows=prepared.plan.expected_record_count,
            max_content_bytes=max(1, trace_content_bound),
            max_line_bytes=_TRACE_MAX_LINE_BYTES,
        )
        join_database = _RunnerJoinDatabase(prepared.state_root)
        (
            buckets,
            accepted_count,
            accepted_payload_bytes,
            admission_ended_monotonic_ns,
        ) = _derive_buckets(
            evidence_root=prepared.evidence_root,
            trace_set=trace_set,
            plan=prepared.plan,
            admission_started_monotonic_ns=admission_started_monotonic_ns,
            database=join_database,
            expected_config_sha256=prepared.config_sha256,
        )
        bucket_ref = write_jsonl_zstd(
            prepared.evidence_root,
            "primary/buckets.jsonl.zst",
            buckets,
            zstd_level=_ARTIFACT_ZSTD_LEVEL,
        )
        worker_ref = write_jsonl_zstd(
            prepared.evidence_root,
            "primary/workers.jsonl.zst",
            worker_rounds,
            zstd_level=_ARTIFACT_ZSTD_LEVEL,
        )
        resource_ref = write_jsonl_zstd(
            prepared.evidence_root,
            "primary/resources.jsonl.zst",
            resource_rounds,
            zstd_level=_ARTIFACT_ZSTD_LEVEL,
        )
        health_ref = write_jsonl_zstd(
            prepared.evidence_root,
            "primary/health.jsonl.zst",
            health_samples,
            zstd_level=_ARTIFACT_ZSTD_LEVEL,
        )
        raw_inventory, manifest_inventory, _manifests = _scan_raw_inventories(
            prepared.data_root,
            database=join_database,
            expected_config_sha256=prepared.config_sha256,
            expected_writer_config=prepared.writer_config,
        )
        join_facts = join_database.finalize()
        summary = _runtime_summary(
            prepared=prepared,
            admission_started_monotonic_ns=admission_started_monotonic_ns,
            admission_started_utc_ns=admission_started_utc_ns,
            buckets=buckets,
            worker_rounds=worker_rounds,
            resource_rounds=resource_rounds,
            health_samples=health_samples,
            raw_inventory=raw_inventory,
            manifest_inventory=manifest_inventory,
            join_facts=join_facts,
            accepted_count=accepted_count,
            accepted_payload_bytes=accepted_payload_bytes,
        )
        _assert_runtime_candidate_passes(prepared, summary)
        cleanup_errors = _close_runner_resources(
            join_database=join_database,
            parent_commands=tuple(parent_commands.values()),
            child_connections=tuple(child_connections),
            result_queue=result_queue,
        )
        resources_closed = True
        join_database = None
        _raise_cleanup_failure(cleanup_errors)
        return _publish_candidate_dag(
            prepared=prepared,
            workload_document_path=workload_document_path,
            run_started_monotonic_ns=run_started_monotonic_ns,
            admission_started_monotonic_ns=admission_started_monotonic_ns,
            admission_started_utc_ns=admission_started_utc_ns,
            admission_ended_monotonic_ns=admission_ended_monotonic_ns,
            trace_set=trace_set,
            bucket_ref=bucket_ref,
            worker_ref=worker_ref,
            resource_ref=resource_ref,
            health_ref=health_ref,
            raw_inventory=raw_inventory,
            manifest_inventory=manifest_inventory,
            summary=summary,
        )
    except BaseException as error:
        abort_event.set()
        abort_errors = _abort_processes(tuple(started_processes))
        for abort_error in abort_errors:
            error.add_note("writer process abort cleanup failed: " + abort_error)
        if schedules:
            try:
                _publish_partial_health(
                    prepared.evidence_root,
                    schedules=schedules,
                    worker_samples=worker_samples,
                    availability=availability,
                )
            except BaseException as diagnostic_error:  # noqa: BLE001
                error.add_note(
                    "partial health publication also failed: "
                    + type(diagnostic_error).__name__
                )
        raise
    finally:
        if not resources_closed:
            cleanup_errors = _close_runner_resources(
                join_database=join_database,
                parent_commands=tuple(parent_commands.values()),
                child_connections=tuple(child_connections),
                result_queue=result_queue,
            )
            active_error = sys.exception()
            if cleanup_errors:
                if active_error is None:
                    _raise_cleanup_failure(cleanup_errors)
                assert active_error is not None
                for cleanup_error in cleanup_errors:
                    active_error.add_note(
                        "writer runner cleanup also failed: "
                        + type(cleanup_error).__name__
                    )


__all__ = [
    "PreparedRun",
    "QualificationClaims",
    "RunRequest",
    "RunnerPreflightError",
    "WriterGateRunError",
    "WriterRunResult",
    "parse_gate_duration",
    "prepare_run",
    "run_writer_gate",
]
