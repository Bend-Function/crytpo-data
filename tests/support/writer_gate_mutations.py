from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol, TypeVar, cast

import zstandard
from pydantic import BaseModel

from crypto_collector.benchmarks.artifacts import (
    build_admission_trace_set,
    iter_jsonl_zstd,
    write_jsonl_zstd,
)
from crypto_collector.benchmarks.contracts import (
    GateAdmissionTraceV1,
    GateArtifactRefV1,
    GateCandidateReportV1,
    GateEvidenceDocumentRefV1,
    GateExchangeArtifactPartitionV1,
    GateManifestInventoryEntryV1,
    GateManifestInventoryV1,
    GateRawInventoryV1,
    GateResourceSamplingRoundV1,
    GateRunIndexV1,
    GateRuntimeSummaryV1,
    GateSamplingRoundV1,
    GateSecondBucketV1,
    GateStorageHealthSampleV1,
)
from crypto_collector.benchmarks.oracle import build_workload_plan
from crypto_collector.benchmarks.workload import load_workload
from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.domain.types import CloseReason
from crypto_collector.storage.manifest import (
    RawManifestV1,
    lease_path_for_data,
    load_raw_manifest,
)
from crypto_collector.storage.models import EnqueueStatus
from crypto_collector.storage.serialize import decode_envelope_jsonl, encode_envelope
from tests.support.writer_gate_evidence import PassingMicroEvidence

_ModelT = TypeVar("_ModelT", bound=BaseModel)
_BAD_SHA256 = "f" * 64
_ONE_SECOND_NS = 1_000_000_000


class _CanonicalDocument(Protocol):
    def canonical_bytes(self) -> bytes: ...


@dataclass(frozen=True, slots=True)
class RuntimeEvidenceMutation:
    name: str
    operation: Callable[[PassingMicroEvidence], None]
    expected_failure_codes: tuple[str, ...] = ("evidence_integrity_invalid",)

    def apply(self, evidence: PassingMicroEvidence) -> None:
        self.operation(evidence)

    def __str__(self) -> str:
        return self.name


def _self_hashed(model_type: type[_ModelT], unsigned: dict[str, Any]) -> _ModelT:
    digest = hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest()
    return model_type.model_validate_json(
        encode_json({**unsigned, "sha256": digest}),
    )


def _updated(model: _ModelT, **updates: Any) -> _ModelT:
    data = model.model_dump(mode="python")
    for key, value in updates.items():
        data[key] = value
    return type(model).model_validate(data)


def _document_ref(root: Path, path: Path) -> GateEvidenceDocumentRefV1:
    source = path.read_bytes()
    return GateEvidenceDocumentRefV1(
        relative_path=path.relative_to(root).as_posix(),
        content_size_bytes=len(source),
        content_sha256=hashlib.sha256(source).hexdigest(),
    )


def _current_run_index(evidence: PassingMicroEvidence) -> GateRunIndexV1:
    return GateRunIndexV1.model_validate_json(evidence.run_index_path.read_bytes())


def _replace_run_index(evidence: PassingMicroEvidence, **updates: Any) -> None:
    current = _current_run_index(evidence)
    unsigned = current.model_dump(mode="json", exclude={"sha256"})
    for key, value in updates.items():
        unsigned[key] = (
            value.model_dump(mode="json") if isinstance(value, BaseModel) else value
        )
    replacement = _self_hashed(GateRunIndexV1, unsigned)
    evidence.run_index_path.write_bytes(replacement.canonical_bytes())


def _rewrite_document(
    evidence: PassingMicroEvidence,
    field_name: str,
    document: _CanonicalDocument,
) -> None:
    run_index = _current_run_index(evidence)
    reference = cast(GateEvidenceDocumentRefV1, getattr(run_index, field_name))
    path = evidence.root / reference.relative_path
    canonical_bytes = cast(Callable[[], bytes], document.canonical_bytes)
    path.write_bytes(canonical_bytes())
    _replace_run_index(evidence, **{field_name: _document_ref(evidence.root, path)})


def _corrupt_self_hash(
    evidence: PassingMicroEvidence,
    field_name: str,
) -> None:
    run_index = _current_run_index(evidence)
    reference = cast(GateEvidenceDocumentRefV1, getattr(run_index, field_name))
    path = evidence.root / reference.relative_path
    value = decode_json(path.read_bytes())
    assert isinstance(value, dict)
    value["sha256"] = _BAD_SHA256
    path.write_bytes(encode_json(value) + b"\n")
    _replace_run_index(evidence, **{field_name: _document_ref(evidence.root, path)})


def _replace_artifact_rows(
    evidence: PassingMicroEvidence,
    field_name: str,
    model_type: type[_ModelT],
    transform: Callable[[list[_ModelT]], Sequence[_ModelT]],
) -> None:
    run_index = _current_run_index(evidence)
    reference = cast(GateArtifactRefV1, getattr(run_index, field_name))
    rows = list(
        iter_jsonl_zstd(
            evidence.root,
            reference,
            model_type,
            max_rows=max(reference.row_count + 10, 100),
            max_content_bytes=max(reference.content_size_bytes * 2, 1_000_000),
            max_line_bytes=1_000_000,
        )
    )
    path = evidence.root / reference.relative_path
    path.unlink()
    replacement = write_jsonl_zstd(
        evidence.root,
        reference.relative_path,
        transform(rows),
        zstd_level=3,
    )
    _replace_run_index(evidence, **{field_name: replacement})


def _replace_trace_rows(
    evidence: PassingMicroEvidence,
    transform: Callable[[list[GateAdmissionTraceV1]], Sequence[GateAdmissionTraceV1]],
) -> None:
    run_index = _current_run_index(evidence)
    partitions = list(run_index.admission_trace_set.partitions)
    partition = partitions[0]
    rows = list(
        iter_jsonl_zstd(
            evidence.root,
            partition.artifact,
            GateAdmissionTraceV1,
            max_rows=100,
            max_content_bytes=1_000_000,
            max_line_bytes=64_000,
        )
    )
    changed = sorted(
        transform(rows),
        key=lambda row: (row.due_monotonic_ns, row.planned_event_id),
    )
    path = evidence.root / partition.artifact.relative_path
    path.unlink()
    artifact = write_jsonl_zstd(
        evidence.root,
        partition.artifact.relative_path,
        changed,
        zstd_level=3,
    )
    partitions[0] = GateExchangeArtifactPartitionV1(
        exchange=partition.exchange,
        artifact=artifact,
    )
    trace_set = build_admission_trace_set(
        evidence.root,
        partitions,
        max_rows=100,
        max_content_bytes=5_000_000,
        max_line_bytes=64_000,
    )
    _replace_run_index(evidence, admission_trace_set=trace_set)


def _corrupt_artifact_content_hash(
    evidence: PassingMicroEvidence,
    field_name: str,
) -> None:
    run_index = _current_run_index(evidence)
    artifact = cast(GateArtifactRefV1, getattr(run_index, field_name))
    _replace_run_index(
        evidence,
        **{field_name: _updated(artifact, content_sha256=_BAD_SHA256)},
    )


def _mutate_workload(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    path = evidence.root / run_index.workload_document.relative_path
    value = decode_json(path.read_bytes())
    assert isinstance(value, dict)
    generation_seed = value["generation_seed"]
    assert type(generation_seed) is int
    value["generation_seed"] = generation_seed + 1
    source = encode_json(value)
    path.write_bytes(source)
    reference = _document_ref(evidence.root, path)
    candidate_path = evidence.root / run_index.candidate_report.relative_path
    candidate = GateCandidateReportV1.model_validate_json(candidate_path.read_bytes())
    plan = build_workload_plan(
        load_workload(path),
        multiplier=candidate.multiplier,
        duration_ns=candidate.duration_ns,
    )
    candidate_unsigned = candidate.model_dump(mode="json", exclude={"sha256"})
    candidate_unsigned["workload_sha256"] = reference.content_sha256
    candidate_unsigned["workload_plan_sha256"] = plan.workload_plan_sha256
    changed_candidate = _self_hashed(GateCandidateReportV1, candidate_unsigned)
    candidate_path.write_bytes(changed_candidate.canonical_bytes())
    _replace_run_index(
        evidence,
        workload_document=reference,
        workload_sha256=reference.content_sha256,
        workload_plan_sha256=plan.workload_plan_sha256,
        candidate_report=_document_ref(evidence.root, candidate_path),
    )


def _mutate_plan_hash(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    candidate_path = evidence.root / run_index.candidate_report.relative_path
    candidate = GateCandidateReportV1.model_validate_json(candidate_path.read_bytes())
    unsigned = candidate.model_dump(mode="json", exclude={"sha256"})
    unsigned["workload_plan_sha256"] = _BAD_SHA256
    changed = _self_hashed(GateCandidateReportV1, unsigned)
    candidate_path.write_bytes(changed.canonical_bytes())
    _replace_run_index(
        evidence,
        workload_plan_sha256=_BAD_SHA256,
        candidate_report=_document_ref(evidence.root, candidate_path),
    )


def _mutate_trace_hash(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    trace_set = _updated(
        run_index.admission_trace_set,
        merged_content_sha256=_BAD_SHA256,
    )
    _replace_run_index(evidence, admission_trace_set=trace_set)


def _mutate_trace_missing(evidence: PassingMicroEvidence) -> None:
    _replace_trace_rows(evidence, lambda rows: rows[:-1])


def _mutate_trace_extra(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        rows.append(_updated(rows[-1], planned_event_id=_BAD_SHA256))
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_trace_due(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        rows[0] = _updated(rows[0], due_monotonic_ns=rows[0].due_monotonic_ns + 1)
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_trace_payload_bytes(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        rows[0] = _updated(rows[0], payload_bytes=rows[0].payload_bytes + 1)
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_trace_payload_hash(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        rows[0] = _updated(rows[0], payload_sha256=_BAD_SHA256)
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_trace_early_boundary(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        row_index = next(
            index
            for index, row in enumerate(rows)
            if row.due_monotonic_ns > 1_000_000_000
        )
        row = rows[row_index]
        rows[row_index] = _updated(
            row,
            attempt_started_monotonic_ns=row.due_monotonic_ns - 1,
        )
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_trace_late_boundary(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        row = rows[0]
        rows[0] = _updated(
            row,
            admission_completed_monotonic_ns=row.deadline_monotonic_ns,
        )
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_accepted_identity(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        row = rows[0]
        assert row.accepted_identity is not None
        identity = _updated(
            row.accepted_identity,
            writer_sequence=row.accepted_identity.writer_sequence + 100,
        )
        rows[0] = _updated(row, accepted_identity=identity)
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_accepted_status(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        rows[0] = _updated(
            rows[0],
            enqueue_status=EnqueueStatus.OVERFLOW,
            accepted_identity=None,
        )
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_accepted_config(
    evidence: PassingMicroEvidence,
    *,
    field_name: str,
    value: object,
) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        identity = rows[0].accepted_identity
        assert identity is not None
        rows[0] = _updated(
            rows[0],
            accepted_identity=_updated(identity, **{field_name: value}),
        )
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_duplicate_ordinal(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        first = rows[0].accepted_identity
        second = rows[1].accepted_identity
        assert first is not None and second is not None
        rows[1] = _updated(
            rows[1],
            accepted_identity=_updated(
                second,
                acceptance_ordinal=first.acceptance_ordinal,
            ),
        )
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_acceptance_ordinal_gap(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateAdmissionTraceV1]) -> Sequence[GateAdmissionTraceV1]:
        identity = rows[1].accepted_identity
        assert identity is not None
        rows[1] = _updated(
            rows[1],
            accepted_identity=_updated(
                identity,
                acceptance_ordinal=identity.acceptance_ordinal + 10_000,
            ),
        )
        return rows

    _replace_trace_rows(evidence, transform)


def _mutate_bucket_fact(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateSecondBucketV1]) -> Sequence[GateSecondBucketV1]:
        rows[0] = _updated(
            rows[0],
            admitted_in_actual_second_count=(
                rows[0].admitted_in_actual_second_count + 1
            ),
        )
        return rows

    _replace_artifact_rows(
        evidence,
        "second_bucket_artifact",
        GateSecondBucketV1,
        transform,
    )


def _mutate_final_worker_field(evidence: PassingMicroEvidence) -> None:
    def transform(rows: list[GateSamplingRoundV1]) -> Sequence[GateSamplingRoundV1]:
        final_round = rows[-1]
        samples = list(final_round.samples)
        sample = samples[0]
        samples[0] = _updated(
            sample,
            snapshot=_updated(sample.snapshot, publication_failure_count=1),
        )
        rows[-1] = _updated(final_round, samples=tuple(samples))
        return rows

    _replace_artifact_rows(
        evidence,
        "worker_sampling_artifact",
        GateSamplingRoundV1,
        transform,
    )


def _mutate_worker_and_candidate_sync_zero(evidence: PassingMicroEvidence) -> None:
    def transform(
        rows: list[GateSamplingRoundV1],
    ) -> Sequence[GateSamplingRoundV1]:
        for round_index, round_ in enumerate(rows):
            samples = tuple(
                _updated(
                    sample,
                    snapshot=_updated(
                        sample.snapshot,
                        sync_count=0,
                        sync_duration_total_ns=0,
                        sync_duration_max_ns=0,
                    ),
                )
                for sample in round_.samples
            )
            rows[round_index] = _updated(round_, samples=samples)
        return rows

    _replace_artifact_rows(
        evidence,
        "worker_sampling_artifact",
        GateSamplingRoundV1,
        transform,
    )
    run_index = _current_run_index(evidence)
    candidate_path = evidence.root / run_index.candidate_report.relative_path
    candidate = GateCandidateReportV1.model_validate_json(candidate_path.read_bytes())
    summary = candidate.runtime_summary
    aggregate = _updated(
        summary.final_worker_aggregate,
        sync_count=0,
        sync_duration_total_ns=0,
        sync_duration_max_ns=0,
    )
    changed_summary = _updated(summary, final_worker_aggregate=aggregate)
    unsigned = candidate.model_dump(mode="json", exclude={"sha256"})
    unsigned["runtime_summary"] = changed_summary.model_dump(mode="json")
    _rewrite_document(
        evidence,
        "candidate_report",
        _self_hashed(GateCandidateReportV1, unsigned),
    )


def _mutate_worker_sync_ownership(evidence: PassingMicroEvidence) -> None:
    def transform(
        rows: list[GateSamplingRoundV1],
    ) -> Sequence[GateSamplingRoundV1]:
        for round_index, round_ in enumerate(rows):
            samples = list(round_.samples)
            donor = samples[0]
            recipient = samples[1]
            assert donor.snapshot.sync_count > 0
            assert donor.snapshot.sync_duration_total_ns > 0
            donor_count = donor.snapshot.sync_count - 1
            samples[0] = _updated(
                donor,
                snapshot=_updated(
                    donor.snapshot,
                    sync_count=donor_count,
                    sync_duration_total_ns=(donor.snapshot.sync_duration_total_ns - 1),
                    sync_duration_max_ns=(
                        0 if donor_count == 0 else donor.snapshot.sync_duration_max_ns
                    ),
                ),
            )
            samples[1] = _updated(
                recipient,
                snapshot=_updated(
                    recipient.snapshot,
                    sync_count=recipient.snapshot.sync_count + 1,
                    sync_duration_total_ns=(
                        recipient.snapshot.sync_duration_total_ns + 1
                    ),
                    sync_duration_max_ns=max(
                        recipient.snapshot.sync_duration_max_ns,
                        1,
                    ),
                ),
            )
            rows[round_index] = _updated(round_, samples=tuple(samples))
        return rows

    _replace_artifact_rows(
        evidence,
        "worker_sampling_artifact",
        GateSamplingRoundV1,
        transform,
    )


def _mutate_worker_record_ownership(evidence: PassingMicroEvidence) -> None:
    metric_fields = (
        "acceptance_ordinal_high_water",
        "accepted_record_count",
        "durable_record_count",
        "durability_bucket_counts",
        "durability_sample_count",
        "durability_lag_p50_ns",
        "durability_lag_p95_ns",
        "durability_lag_p99_ns",
        "durability_lag_max_ns",
    )

    def transferred_metrics(source: Any, destination: Any) -> dict[str, object]:
        return {
            **{field: getattr(source, field) for field in metric_fields},
            "durability_histogram_series": tuple(
                _updated(series, exchange=destination.exchange)
                for series in source.durability_histogram_series
            ),
        }

    def transform(
        rows: list[GateSamplingRoundV1],
    ) -> Sequence[GateSamplingRoundV1]:
        for round_index, round_ in enumerate(rows):
            samples = list(round_.samples)
            first = samples[0]
            second = samples[1]
            samples[0] = _updated(
                first,
                snapshot=_updated(
                    first.snapshot,
                    **transferred_metrics(second.snapshot, first.snapshot),
                ),
            )
            samples[1] = _updated(
                second,
                snapshot=_updated(
                    second.snapshot,
                    **transferred_metrics(first.snapshot, second.snapshot),
                ),
            )
            rows[round_index] = _updated(round_, samples=tuple(samples))
        return rows

    _replace_artifact_rows(
        evidence,
        "worker_sampling_artifact",
        GateSamplingRoundV1,
        transform,
    )


def _mutate_resource_limit(evidence: PassingMicroEvidence) -> None:
    def transform(
        rows: list[GateResourceSamplingRoundV1],
    ) -> Sequence[GateResourceSamplingRoundV1]:
        round_ = rows[-1]
        samples = list(round_.samples)
        samples[0] = _updated(samples[0], rss_bytes=5 * 1024**3)
        rows[-1] = _updated(round_, samples=tuple(samples))
        return rows

    _replace_artifact_rows(
        evidence,
        "resource_sampling_artifact",
        GateResourceSamplingRoundV1,
        transform,
    )


def _retime_resource_round(
    round_: GateResourceSamplingRoundV1,
    scheduled_monotonic_ns: int,
) -> GateResourceSamplingRoundV1:
    samples = tuple(
        _updated(
            sample,
            scheduled_monotonic_ns=scheduled_monotonic_ns,
            request_started_monotonic_ns=scheduled_monotonic_ns,
            request_completed_monotonic_ns=scheduled_monotonic_ns,
        )
        for sample in round_.samples
    )
    return _updated(
        round_,
        scheduled_monotonic_ns=scheduled_monotonic_ns,
        samples=samples,
    )


def _mutate_resource_prefix(evidence: PassingMicroEvidence) -> None:
    _replace_artifact_rows(
        evidence,
        "resource_sampling_artifact",
        GateResourceSamplingRoundV1,
        lambda rows: rows[1:],
    )


def _mutate_resource_gap(evidence: PassingMicroEvidence) -> None:
    def transform(
        rows: list[GateResourceSamplingRoundV1],
    ) -> Sequence[GateResourceSamplingRoundV1]:
        shift_ns = _ONE_SECOND_NS + 1
        for index in range(5, len(rows)):
            rows[index] = _retime_resource_round(
                rows[index],
                rows[index].scheduled_monotonic_ns + shift_ns,
            )
        return rows

    _replace_artifact_rows(
        evidence,
        "resource_sampling_artifact",
        GateResourceSamplingRoundV1,
        transform,
    )


def _mutate_resource_coverage(evidence: PassingMicroEvidence) -> None:
    _replace_artifact_rows(
        evidence,
        "resource_sampling_artifact",
        GateResourceSamplingRoundV1,
        lambda rows: rows[:-1],
    )


def _mutate_truncated_resource_tail(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    artifact = run_index.resource_sampling_artifact
    path = evidence.root / artifact.relative_path
    plain = zstandard.ZstdDecompressor().decompress(
        path.read_bytes(),
        max_output_size=artifact.content_size_bytes + 1,
    )
    malformed_plain = plain + b'{"schema_version":1'
    compressed = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    ).compress(malformed_plain)
    path.write_bytes(compressed)
    replacement = _updated(
        artifact,
        row_count=artifact.row_count + 1,
        content_size_bytes=len(malformed_plain),
        content_sha256=hashlib.sha256(malformed_plain).hexdigest(),
        compressed_size_bytes=len(compressed),
        compressed_sha256=hashlib.sha256(compressed).hexdigest(),
    )
    _replace_run_index(evidence, resource_sampling_artifact=replacement)


def _retime_health_sample(
    sample: GateStorageHealthSampleV1,
    scheduled_monotonic_ns: int,
) -> GateStorageHealthSampleV1:
    return _updated(
        sample,
        scheduled_monotonic_ns=scheduled_monotonic_ns,
        request_started_monotonic_ns=scheduled_monotonic_ns,
        request_completed_monotonic_ns=scheduled_monotonic_ns,
    )


def _mutate_health_gap(evidence: PassingMicroEvidence) -> None:
    def transform(
        rows: list[GateStorageHealthSampleV1],
    ) -> Sequence[GateStorageHealthSampleV1]:
        shift_ns = _ONE_SECOND_NS + 1
        for index in range(4, len(rows)):
            rows[index] = _retime_health_sample(
                rows[index],
                rows[index].scheduled_monotonic_ns + shift_ns,
            )
        return rows

    _replace_artifact_rows(
        evidence,
        "storage_health_artifact",
        GateStorageHealthSampleV1,
        transform,
    )


def _mutate_health_coverage(evidence: PassingMicroEvidence) -> None:
    _replace_artifact_rows(
        evidence,
        "storage_health_artifact",
        GateStorageHealthSampleV1,
        lambda rows: rows[:-1],
    )


def _raw_artifact_ref(
    relative_path: str,
    plain: bytes,
    compressed: bytes,
    row_count: int,
) -> GateArtifactRefV1:
    return GateArtifactRefV1(
        relative_path=relative_path,
        row_count=row_count,
        content_size_bytes=len(plain),
        content_sha256=hashlib.sha256(plain).hexdigest(),
        compressed_size_bytes=len(compressed),
        compressed_sha256=hashlib.sha256(compressed).hexdigest(),
    )


def _publish_raw_metadata(
    evidence: PassingMicroEvidence,
    *,
    entry_index: int,
    manifest: RawManifestV1,
    data_ref: GateArtifactRefV1,
) -> None:
    run_index = _current_run_index(evidence)
    raw_path = evidence.root / run_index.raw_inventory.relative_path
    manifest_inventory_path = evidence.root / run_index.manifest_inventory.relative_path
    raw_inventory = GateRawInventoryV1.model_validate_json(raw_path.read_bytes())
    manifest_inventory = GateManifestInventoryV1.model_validate_json(
        manifest_inventory_path.read_bytes()
    )
    manifest_path = evidence.data_root / manifest.manifest_relative_path
    manifest_path.write_bytes(manifest.canonical_bytes())

    raw_files = list(raw_inventory.raw_files)
    raw_file_index = next(
        index
        for index, item in enumerate(raw_files)
        if item.relative_path == data_ref.relative_path
    )
    raw_files[raw_file_index] = data_ref
    raw_unsigned = {
        "schema_version": 1,
        "record_type": "gate_raw_inventory_v1",
        "raw_files": [item.model_dump(mode="json") for item in raw_files],
        "file_count": len(raw_files),
        "record_count": sum(item.row_count for item in raw_files),
        "content_size_bytes": sum(item.content_size_bytes for item in raw_files),
        "compressed_size_bytes": sum(item.compressed_size_bytes for item in raw_files),
    }
    new_raw_inventory = _self_hashed(GateRawInventoryV1, raw_unsigned)

    entries = list(manifest_inventory.manifests)
    old_entry = entries[entry_index]
    entries[entry_index] = GateManifestInventoryEntryV1(
        ordinal=old_entry.ordinal,
        manifest=_document_ref(evidence.data_root, manifest_path),
        data=data_ref,
        manifest_record_count=manifest.record_count,
    )
    manifest_unsigned = {
        "schema_version": 1,
        "record_type": "gate_manifest_inventory_v1",
        "manifests": [entry.model_dump(mode="json") for entry in entries],
        "file_count": len(entries),
        "record_count": sum(entry.manifest_record_count for entry in entries),
        "manifest_content_size_bytes": sum(
            entry.manifest.content_size_bytes for entry in entries
        ),
    }
    new_manifest_inventory = _self_hashed(
        GateManifestInventoryV1,
        manifest_unsigned,
    )
    raw_path.write_bytes(new_raw_inventory.canonical_bytes())
    manifest_inventory_path.write_bytes(new_manifest_inventory.canonical_bytes())
    _replace_run_index(
        evidence,
        raw_inventory=_document_ref(evidence.root, raw_path),
        manifest_inventory=_document_ref(evidence.root, manifest_inventory_path),
    )


def _mutate_raw_inventory_only(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    path = evidence.root / run_index.raw_inventory.relative_path
    inventory = GateRawInventoryV1.model_validate_json(path.read_bytes())
    raw_files = inventory.raw_files[1:]
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_raw_inventory_v1",
        "raw_files": [item.model_dump(mode="json") for item in raw_files],
        "file_count": len(raw_files),
        "record_count": sum(item.row_count for item in raw_files),
        "content_size_bytes": sum(item.content_size_bytes for item in raw_files),
        "compressed_size_bytes": sum(item.compressed_size_bytes for item in raw_files),
    }
    changed = _self_hashed(GateRawInventoryV1, unsigned)
    path.write_bytes(changed.canonical_bytes())
    _replace_run_index(
        evidence,
        raw_inventory=_document_ref(evidence.root, path),
    )


def _mutate_manifest_inventory_only(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(path.read_bytes())
    entries = tuple(
        GateManifestInventoryEntryV1(
            ordinal=ordinal,
            manifest=entry.manifest,
            data=entry.data,
            manifest_record_count=entry.manifest_record_count,
        )
        for ordinal, entry in enumerate(inventory.manifests[1:])
    )
    unsigned = {
        "schema_version": 1,
        "record_type": "gate_manifest_inventory_v1",
        "manifests": [entry.model_dump(mode="json") for entry in entries],
        "file_count": len(entries),
        "record_count": sum(entry.manifest_record_count for entry in entries),
        "manifest_content_size_bytes": sum(
            entry.manifest.content_size_bytes for entry in entries
        ),
    }
    changed = _self_hashed(GateManifestInventoryV1, unsigned)
    path.write_bytes(changed.canonical_bytes())
    _replace_run_index(
        evidence,
        manifest_inventory=_document_ref(evidence.root, path),
    )


def _mutate_raw_row(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    inventory_path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(inventory_path.read_bytes())
    entry = inventory.manifests[0]
    manifest_path = evidence.data_root / entry.manifest.relative_path
    manifest = load_raw_manifest(manifest_path).manifest
    data_path = evidence.data_root / entry.data.relative_path
    plain = zstandard.ZstdDecompressor().decompress(data_path.read_bytes())
    rows = [decode_envelope_jsonl(line + b"\n") for line in plain.splitlines()]
    first = rows[0]
    assert isinstance(first.payload, dict)
    payload = dict(first.payload)
    payload["event_id"] = _BAD_SHA256
    rows[0] = RawEnvelope.model_validate(
        {**first.model_dump(mode="python"), "payload": payload}
    )
    changed_plain = b"".join(encode_envelope(row) for row in rows)
    compressed = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    ).compress(changed_plain)
    data_path.write_bytes(compressed)
    data_ref = _raw_artifact_ref(
        entry.data.relative_path,
        changed_plain,
        compressed,
        len(rows),
    )
    changed_manifest = _updated(
        manifest,
        file_size_bytes=len(compressed),
        file_sha256=hashlib.sha256(compressed).hexdigest(),
    )
    _publish_raw_metadata(
        evidence,
        entry_index=0,
        manifest=changed_manifest,
        data_ref=data_ref,
    )


def _rewrite_multirow_raw_group(
    evidence: PassingMicroEvidence,
    transform: Callable[[list[RawEnvelope]], Sequence[RawEnvelope]],
) -> None:
    run_index = _current_run_index(evidence)
    inventory_path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(inventory_path.read_bytes())
    entry_index = next(
        index
        for index, candidate in enumerate(inventory.manifests)
        if candidate.manifest_record_count > 1
    )
    entry = inventory.manifests[entry_index]
    manifest_path = evidence.data_root / entry.manifest.relative_path
    manifest = load_raw_manifest(manifest_path).manifest
    data_path = evidence.data_root / entry.data.relative_path
    plain = zstandard.ZstdDecompressor().decompress(data_path.read_bytes())
    rows = [decode_envelope_jsonl(line + b"\n") for line in plain.splitlines()]
    changed_rows = list(transform(rows))
    if not changed_rows:
        raise AssertionError("raw mutation must retain at least one row")
    changed_plain = b"".join(encode_envelope(row) for row in changed_rows)
    compressed = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    ).compress(changed_plain)
    data_path.write_bytes(compressed)
    event_times = tuple(
        row.event_time_ns for row in changed_rows if row.event_time_ns is not None
    )
    changed_manifest = _updated(
        manifest,
        file_size_bytes=len(compressed),
        file_sha256=hashlib.sha256(compressed).hexdigest(),
        record_count=len(changed_rows),
        first_received_at_ns=changed_rows[0].received_at_ns,
        last_received_at_ns=changed_rows[-1].received_at_ns,
        first_event_time_ns=event_times[0] if event_times else None,
        last_event_time_ns=event_times[-1] if event_times else None,
        wire_symbols=tuple(
            sorted(
                {row.wire_symbol for row in changed_rows if row.wire_symbol is not None}
            )
        ),
        connection_generations=tuple(
            sorted(
                {
                    row.connection_generation
                    for row in changed_rows
                    if row.connection_generation is not None
                }
            )
        ),
        writer_sequence_first=changed_rows[0].writer_sequence,
        writer_sequence_last=changed_rows[-1].writer_sequence,
        egress_ids=tuple(
            sorted({row.egress_id for row in changed_rows if row.egress_id is not None})
        ),
        requested_intervals_ns=tuple(
            sorted(
                {
                    row.rest_metadata.requested_interval_ns
                    for row in changed_rows
                    if row.rest_metadata is not None
                    and row.rest_metadata.requested_interval_ns is not None
                }
            )
        ),
        effective_intervals_ns=tuple(
            sorted(
                {
                    row.rest_metadata.effective_interval_ns
                    for row in changed_rows
                    if row.rest_metadata is not None
                    and row.rest_metadata.effective_interval_ns is not None
                }
            )
        ),
        durability_sample_count=len(changed_rows),
    )
    data_ref = _raw_artifact_ref(
        entry.data.relative_path,
        changed_plain,
        compressed,
        len(changed_rows),
    )
    _publish_raw_metadata(
        evidence,
        entry_index=entry_index,
        manifest=changed_manifest,
        data_ref=data_ref,
    )


def _mutate_raw_missing(evidence: PassingMicroEvidence) -> None:
    _rewrite_multirow_raw_group(evidence, lambda rows: rows[:-1])


def _mutate_raw_extra(evidence: PassingMicroEvidence) -> None:
    _rewrite_multirow_raw_group(evidence, lambda rows: (*rows, rows[-1]))


def _mutate_raw_frame_codec(
    evidence: PassingMicroEvidence,
    *,
    write_checksum: bool,
    write_content_size: bool,
) -> None:
    run_index = _current_run_index(evidence)
    inventory_path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(inventory_path.read_bytes())
    entry = inventory.manifests[0]
    manifest_path = evidence.data_root / entry.manifest.relative_path
    manifest = load_raw_manifest(manifest_path).manifest
    data_path = evidence.data_root / entry.data.relative_path
    plain = zstandard.ZstdDecompressor().decompress(data_path.read_bytes())
    compressed = zstandard.ZstdCompressor(
        level=3,
        write_checksum=write_checksum,
        write_content_size=write_content_size,
    ).compress(plain)
    data_path.write_bytes(compressed)
    changed_manifest = _updated(
        manifest,
        file_size_bytes=len(compressed),
        file_sha256=hashlib.sha256(compressed).hexdigest(),
    )
    _publish_raw_metadata(
        evidence,
        entry_index=0,
        manifest=changed_manifest,
        data_ref=_raw_artifact_ref(
            entry.data.relative_path,
            plain,
            compressed,
            entry.data.row_count,
        ),
    )


def _mutate_raw_frame_without_checksum(evidence: PassingMicroEvidence) -> None:
    _mutate_raw_frame_codec(
        evidence,
        write_checksum=False,
        write_content_size=True,
    )


def _mutate_raw_frame_without_content_size(evidence: PassingMicroEvidence) -> None:
    _mutate_raw_frame_codec(
        evidence,
        write_checksum=True,
        write_content_size=False,
    )


def _mutate_manifest_frame_bound_below_physical(
    evidence: PassingMicroEvidence,
) -> None:
    for entry_index in range(evidence.manifest_inventory.file_count):
        run_index = _current_run_index(evidence)
        inventory_path = evidence.root / run_index.manifest_inventory.relative_path
        inventory = GateManifestInventoryV1.model_validate_json(
            inventory_path.read_bytes()
        )
        entry = inventory.manifests[entry_index]
        manifest_path = evidence.data_root / entry.manifest.relative_path
        manifest = load_raw_manifest(manifest_path).manifest
        _publish_raw_metadata(
            evidence,
            entry_index=entry_index,
            manifest=_updated(manifest, max_plain_frame_bytes=1),
            data_ref=entry.data,
        )


def _mutate_manifest_frame_bound_above_expected(
    evidence: PassingMicroEvidence,
) -> None:
    for entry_index in range(evidence.manifest_inventory.file_count):
        run_index = _current_run_index(evidence)
        inventory_path = evidence.root / run_index.manifest_inventory.relative_path
        inventory = GateManifestInventoryV1.model_validate_json(
            inventory_path.read_bytes()
        )
        entry = inventory.manifests[entry_index]
        manifest_path = evidence.data_root / entry.manifest.relative_path
        manifest = load_raw_manifest(manifest_path).manifest
        _publish_raw_metadata(
            evidence,
            entry_index=entry_index,
            manifest=_updated(manifest, max_plain_frame_bytes=2 * 1024 * 1024),
            data_ref=entry.data,
        )


def _mutate_unlisted_closed_raw(evidence: PassingMicroEvidence) -> None:
    entry = evidence.manifest_inventory.manifests[0]
    source = evidence.data_root / entry.data.relative_path
    destination = source.with_name(
        source.name.removesuffix(".jsonl.zst") + "-unlisted.jsonl.zst"
    )
    destination.write_bytes(source.read_bytes())


def _mutate_unlisted_final_manifest(evidence: PassingMicroEvidence) -> None:
    entry = evidence.manifest_inventory.manifests[0]
    source = evidence.data_root / entry.manifest.relative_path
    destination = source.with_name(
        source.name.removesuffix(".manifest.json") + "-unlisted.manifest.json"
    )
    destination.write_bytes(source.read_bytes())


def _mutate_raw_directory_entry_limit(evidence: PassingMicroEvidence) -> None:
    raw_root = evidence.data_root / "raw"
    for ordinal in range(1_025):
        (raw_root / f"ignored-{ordinal:04d}").mkdir()


def _mutate_raw_partial(evidence: PassingMicroEvidence) -> None:
    (evidence.data_root / "raw" / "hidden.jsonl.zst.partial").write_bytes(
        b"uncommitted raw bytes"
    )


def _mutate_unexpected_lease(evidence: PassingMicroEvidence) -> None:
    (evidence.data_root / "raw" / "unexpected.lease").write_bytes(b"")


def _mutate_nonempty_expected_lease(evidence: PassingMicroEvidence) -> None:
    data_ref = evidence.raw_inventory.raw_files[0]
    lease_path_for_data(evidence.data_root / data_ref.relative_path).write_bytes(
        b"hidden bytes"
    )


def _mutate_misplaced_writer_lock(evidence: PassingMicroEvidence) -> None:
    misplaced = evidence.data_root / "raw" / "unexpected" / ".writer.lock"
    misplaced.parent.mkdir()
    misplaced.write_bytes(b"")


def _mutate_manifest_count(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    inventory_path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(inventory_path.read_bytes())
    entry = inventory.manifests[0]
    manifest_path = evidence.data_root / entry.manifest.relative_path
    manifest = load_raw_manifest(manifest_path).manifest
    changed_manifest = _updated(
        manifest,
        record_count=manifest.record_count + 1,
        durability_sample_count=manifest.record_count + 1,
    )
    changed_data = _updated(entry.data, row_count=entry.data.row_count + 1)
    _publish_raw_metadata(
        evidence,
        entry_index=0,
        manifest=changed_manifest,
        data_ref=changed_data,
    )


def _mutate_manifest_hash(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(path.read_bytes())
    entries = list(inventory.manifests)
    entry = entries[0]
    entries[0] = _updated(
        entry,
        manifest=_updated(entry.manifest, content_sha256=_BAD_SHA256),
    )
    unsigned = inventory.model_dump(mode="json", exclude={"sha256"})
    unsigned["manifests"] = [item.model_dump(mode="json") for item in entries]
    replacement = _self_hashed(GateManifestInventoryV1, unsigned)
    _rewrite_document(evidence, "manifest_inventory", replacement)


def _mutate_manifest_error_fact(
    evidence: PassingMicroEvidence,
    field_name: str,
) -> None:
    run_index = _current_run_index(evidence)
    inventory_path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(inventory_path.read_bytes())
    entry = inventory.manifests[0]
    manifest_path = evidence.data_root / entry.manifest.relative_path
    manifest = load_raw_manifest(manifest_path).manifest
    changed_manifest = _updated(manifest, **{field_name: 1})
    _publish_raw_metadata(
        evidence,
        entry_index=0,
        manifest=changed_manifest,
        data_ref=entry.data,
    )


def _mutate_manifest_sync_summary(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    inventory_path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(inventory_path.read_bytes())
    entry = inventory.manifests[0]
    manifest_path = evidence.data_root / entry.manifest.relative_path
    manifest = load_raw_manifest(manifest_path).manifest
    assert manifest.sync_count is not None
    assert manifest.sync_duration_total_ns is not None
    assert manifest.sync_duration_max_ns is not None
    changed_manifest = _updated(
        manifest,
        sync_count=manifest.sync_count + 1,
        sync_duration_total_ns=manifest.sync_duration_total_ns + 1,
        sync_duration_max_ns=manifest.sync_duration_max_ns + 1,
    )
    _publish_raw_metadata(
        evidence,
        entry_index=0,
        manifest=changed_manifest,
        data_ref=entry.data,
    )


def _mutate_manifest_config_reload(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    inventory_path = evidence.root / run_index.manifest_inventory.relative_path
    inventory = GateManifestInventoryV1.model_validate_json(inventory_path.read_bytes())
    entry = inventory.manifests[0]
    manifest_path = evidence.data_root / entry.manifest.relative_path
    manifest = load_raw_manifest(manifest_path).manifest
    _publish_raw_metadata(
        evidence,
        entry_index=0,
        manifest=_updated(manifest, close_reason=CloseReason.CONFIG_RELOAD),
        data_ref=entry.data,
    )


def _mutate_candidate_utc_hour(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    path = evidence.root / run_index.candidate_report.relative_path
    candidate = GateCandidateReportV1.model_validate_json(path.read_bytes())
    shifted_start = candidate.admission_started_utc_ns + 3_600 * _ONE_SECOND_NS
    shifted_end = candidate.admission_ended_utc_ns + 3_600 * _ONE_SECOND_NS
    declared_hour = datetime.fromtimestamp(
        shifted_start // _ONE_SECOND_NS,
        tz=UTC,
    ).strftime("%Y/%m/%d/%H")
    unsigned = candidate.model_dump(mode="json", exclude={"sha256"})
    unsigned.update(
        {
            "admission_started_utc_ns": shifted_start,
            "admission_ended_utc_ns": shifted_end,
            "declared_admission_utc_hour": declared_hour,
        }
    )
    replacement = _self_hashed(GateCandidateReportV1, unsigned)
    _rewrite_document(evidence, "candidate_report", replacement)


def _mutate_candidate_admission_end(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    path = evidence.root / run_index.candidate_report.relative_path
    candidate = GateCandidateReportV1.model_validate_json(path.read_bytes())
    unsigned = candidate.model_dump(mode="json", exclude={"sha256"})
    unsigned.update(
        {
            "admission_ended_monotonic_ns": (
                candidate.admission_ended_monotonic_ns + 1
            ),
            "admission_ended_utc_ns": candidate.admission_ended_utc_ns + 1,
        }
    )
    replacement = _self_hashed(GateCandidateReportV1, unsigned)
    _rewrite_document(evidence, "candidate_report", replacement)


def _mutate_candidate_summary(evidence: PassingMicroEvidence) -> None:
    run_index = _current_run_index(evidence)
    path = evidence.root / run_index.candidate_report.relative_path
    candidate = GateCandidateReportV1.model_validate_json(path.read_bytes())
    summary = candidate.runtime_summary
    changed_resource = _updated(
        summary.resource_summary,
        rss_peak_bytes=summary.resource_summary.rss_peak_bytes + 1,
    )
    changed_summary = _updated(
        cast(GateRuntimeSummaryV1, summary),
        resource_summary=changed_resource,
    )
    unsigned = candidate.model_dump(mode="json", exclude={"sha256"})
    unsigned["runtime_summary"] = changed_summary.model_dump(mode="json")
    replacement = _self_hashed(GateCandidateReportV1, unsigned)
    _rewrite_document(evidence, "candidate_report", replacement)


RUNTIME_EVIDENCE_MUTATIONS: tuple[RuntimeEvidenceMutation, ...] = (
    RuntimeEvidenceMutation("workload_hash", _mutate_workload),
    RuntimeEvidenceMutation("workload_plan_hash", _mutate_plan_hash),
    RuntimeEvidenceMutation("trace_hash", _mutate_trace_hash),
    RuntimeEvidenceMutation("trace_missing", _mutate_trace_missing),
    RuntimeEvidenceMutation("trace_extra", _mutate_trace_extra),
    RuntimeEvidenceMutation(
        "bucket_hash",
        lambda evidence: _corrupt_artifact_content_hash(
            evidence,
            "second_bucket_artifact",
        ),
    ),
    RuntimeEvidenceMutation(
        "worker_sample_hash",
        lambda evidence: _corrupt_artifact_content_hash(
            evidence,
            "worker_sampling_artifact",
        ),
    ),
    RuntimeEvidenceMutation(
        "resource_sample_hash",
        lambda evidence: _corrupt_artifact_content_hash(
            evidence,
            "resource_sampling_artifact",
        ),
    ),
    RuntimeEvidenceMutation(
        "health_sample_hash",
        lambda evidence: _corrupt_artifact_content_hash(
            evidence,
            "storage_health_artifact",
        ),
    ),
    RuntimeEvidenceMutation(
        "candidate_report_hash",
        lambda evidence: _corrupt_self_hash(evidence, "candidate_report"),
    ),
    RuntimeEvidenceMutation(
        "raw_inventory_hash",
        lambda evidence: _corrupt_self_hash(evidence, "raw_inventory"),
    ),
    RuntimeEvidenceMutation(
        "manifest_inventory_hash",
        lambda evidence: _corrupt_self_hash(evidence, "manifest_inventory"),
    ),
    RuntimeEvidenceMutation("trace_due", _mutate_trace_due),
    RuntimeEvidenceMutation("trace_payload_bytes", _mutate_trace_payload_bytes),
    RuntimeEvidenceMutation("trace_payload_hash", _mutate_trace_payload_hash),
    RuntimeEvidenceMutation("trace_early_boundary", _mutate_trace_early_boundary),
    RuntimeEvidenceMutation("trace_late_boundary", _mutate_trace_late_boundary),
    RuntimeEvidenceMutation("accepted_identity", _mutate_accepted_identity),
    RuntimeEvidenceMutation("accepted_status", _mutate_accepted_status),
    RuntimeEvidenceMutation(
        "accepted_config_sha256",
        lambda evidence: _mutate_accepted_config(
            evidence,
            field_name="config_sha256",
            value=_BAD_SHA256,
        ),
    ),
    RuntimeEvidenceMutation(
        "accepted_config_generation",
        lambda evidence: _mutate_accepted_config(
            evidence,
            field_name="config_generation",
            value=1,
        ),
    ),
    RuntimeEvidenceMutation("duplicate_acceptance_ordinal", _mutate_duplicate_ordinal),
    RuntimeEvidenceMutation("acceptance_ordinal_gap", _mutate_acceptance_ordinal_gap),
    RuntimeEvidenceMutation("bucket_fact", _mutate_bucket_fact),
    RuntimeEvidenceMutation("raw_row", _mutate_raw_row),
    RuntimeEvidenceMutation("raw_inventory_only", _mutate_raw_inventory_only),
    RuntimeEvidenceMutation(
        "manifest_inventory_only",
        _mutate_manifest_inventory_only,
    ),
    RuntimeEvidenceMutation("raw_missing", _mutate_raw_missing),
    RuntimeEvidenceMutation("raw_extra", _mutate_raw_extra),
    RuntimeEvidenceMutation(
        "raw_frame_without_checksum",
        _mutate_raw_frame_without_checksum,
    ),
    RuntimeEvidenceMutation(
        "raw_frame_without_content_size",
        _mutate_raw_frame_without_content_size,
    ),
    RuntimeEvidenceMutation(
        "manifest_frame_bound_below_physical",
        _mutate_manifest_frame_bound_below_physical,
    ),
    RuntimeEvidenceMutation(
        "manifest_frame_bound_above_expected",
        _mutate_manifest_frame_bound_above_expected,
    ),
    RuntimeEvidenceMutation("unlisted_closed_raw", _mutate_unlisted_closed_raw),
    RuntimeEvidenceMutation(
        "unlisted_final_manifest",
        _mutate_unlisted_final_manifest,
    ),
    RuntimeEvidenceMutation(
        "raw_directory_entry_limit",
        _mutate_raw_directory_entry_limit,
    ),
    RuntimeEvidenceMutation("raw_partial", _mutate_raw_partial),
    RuntimeEvidenceMutation("unexpected_lease", _mutate_unexpected_lease),
    RuntimeEvidenceMutation(
        "nonempty_expected_lease",
        _mutate_nonempty_expected_lease,
    ),
    RuntimeEvidenceMutation(
        "misplaced_writer_lock",
        _mutate_misplaced_writer_lock,
    ),
    RuntimeEvidenceMutation("manifest_count", _mutate_manifest_count),
    RuntimeEvidenceMutation("manifest_hash", _mutate_manifest_hash),
    RuntimeEvidenceMutation(
        "manifest_gap_count",
        lambda evidence: _mutate_manifest_error_fact(evidence, "gap_count"),
    ),
    RuntimeEvidenceMutation(
        "manifest_write_failure_count",
        lambda evidence: _mutate_manifest_error_fact(evidence, "write_failure_count"),
    ),
    RuntimeEvidenceMutation(
        "manifest_sync_failure_count",
        lambda evidence: _mutate_manifest_error_fact(evidence, "sync_failure_count"),
    ),
    RuntimeEvidenceMutation("manifest_sync_summary", _mutate_manifest_sync_summary),
    RuntimeEvidenceMutation("manifest_config_reload", _mutate_manifest_config_reload),
    RuntimeEvidenceMutation("utc_hour", _mutate_candidate_utc_hour),
    RuntimeEvidenceMutation("admission_end", _mutate_candidate_admission_end),
    RuntimeEvidenceMutation(
        "final_worker_field",
        _mutate_final_worker_field,
        ("candidate_summary_mismatch", "runtime_predicate_failed"),
    ),
    RuntimeEvidenceMutation(
        "worker_candidate_sync_zero",
        _mutate_worker_and_candidate_sync_zero,
    ),
    RuntimeEvidenceMutation(
        "worker_sync_ownership",
        _mutate_worker_sync_ownership,
    ),
    RuntimeEvidenceMutation(
        "worker_record_ownership",
        _mutate_worker_record_ownership,
    ),
    RuntimeEvidenceMutation(
        "resource_limit",
        _mutate_resource_limit,
        ("candidate_summary_mismatch",),
    ),
    RuntimeEvidenceMutation("resource_prefix", _mutate_resource_prefix),
    RuntimeEvidenceMutation(
        "resource_gap",
        _mutate_resource_gap,
        ("candidate_summary_mismatch",),
    ),
    RuntimeEvidenceMutation(
        "resource_coverage",
        _mutate_resource_coverage,
        ("candidate_summary_mismatch",),
    ),
    RuntimeEvidenceMutation(
        "resource_truncated_after_post_warmup",
        _mutate_truncated_resource_tail,
    ),
    RuntimeEvidenceMutation(
        "storage_health_gap",
        _mutate_health_gap,
        ("candidate_summary_mismatch",),
    ),
    RuntimeEvidenceMutation(
        "storage_health_coverage",
        _mutate_health_coverage,
        ("candidate_summary_mismatch",),
    ),
    RuntimeEvidenceMutation(
        "candidate_summary",
        _mutate_candidate_summary,
        ("candidate_summary_mismatch",),
    ),
)


__all__ = ["RUNTIME_EVIDENCE_MUTATIONS", "RuntimeEvidenceMutation"]
