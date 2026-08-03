from __future__ import annotations

from crypto_collector.benchmarks.artifacts import iter_jsonl_zstd
from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    GateAdmissionTraceV1,
    GateSecondBucketV1,
)
from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.storage.manifest import RawManifestReader, load_raw_manifest
from tests.support.writer_gate_evidence import write_passing_micro_evidence


def test_passing_micro_evidence_writes_the_frozen_functional_shape(tmp_path) -> None:
    evidence = write_passing_micro_evidence(tmp_path)

    assert evidence.run_index_path == evidence.root / "run-index.json"
    assert evidence.run_index_path.read_bytes() == evidence.run_index.canonical_bytes()
    assert evidence.run_index.mode == "functional"
    assert evidence.run_index.status == "complete"
    assert evidence.plan.expected_record_count == 17
    assert evidence.plan.expected_payload_byte_count == 6_336
    assert evidence.plan.expected_touched_file_identity_count == 12
    assert evidence.plan.declared_file_identity_count == 75

    partition_counts = tuple(
        len(
            tuple(
                iter_jsonl_zstd(
                    evidence.root,
                    partition.artifact,
                    GateAdmissionTraceV1,
                    max_rows=17,
                    max_content_bytes=1_000_000,
                    max_line_bytes=64_000,
                )
            )
        )
        for partition in evidence.run_index.admission_trace_set.partitions
    )
    assert (
        tuple(
            partition.exchange
            for partition in evidence.run_index.admission_trace_set.partitions
        )
        == CANONICAL_EXCHANGES
    )
    assert partition_counts == (9, 2, 2, 2, 2)

    buckets = tuple(
        iter_jsonl_zstd(
            evidence.root,
            evidence.run_index.second_bucket_artifact,
            GateSecondBucketV1,
            max_rows=80,
            max_content_bytes=1_000_000,
            max_line_bytes=64_000,
        )
    )
    assert len(buckets) == 80
    assert evidence.raw_inventory.file_count == 12
    assert evidence.raw_inventory.record_count == 17
    assert evidence.manifest_inventory.file_count == 12
    assert evidence.manifest_inventory.record_count == 17
    loaded_manifests = tuple(
        load_raw_manifest(evidence.data_root / entry.manifest.relative_path)
        for entry in evidence.manifest_inventory.manifests
    )
    assert tuple(
        loaded.manifest.data_relative_path for loaded in loaded_manifests
    ) == tuple(
        entry.data.relative_path for entry in evidence.manifest_inventory.manifests
    )
    assert tuple(loaded.sha256 for loaded in loaded_manifests) == tuple(
        entry.manifest.content_sha256 for entry in evidence.manifest_inventory.manifests
    )
    durable_rows: list[RawEnvelope] = []
    for loaded in loaded_manifests:
        with RawManifestReader(loaded.path) as reader:
            durable_rows.extend(reader)
    assert len(durable_rows) == 17
    durable_event_ids: set[object] = set()
    for row in durable_rows:
        assert isinstance(row.payload, dict)
        durable_event_ids.add(row.payload["event_id"])
    assert durable_event_ids == {event.planned_event_id for event in evidence.events}

    summary = evidence.candidate_report.runtime_summary
    assert summary.expected_record_count == 17
    assert summary.accepted_record_count == 17
    assert summary.durable_record_count == 17
    assert summary.manifest_record_count == 17
    assert summary.raw_file_count == 12
    assert summary.manifest_file_count == 12
    assert summary.observed_touched_file_identity_count == 12
    assert summary.final_worker_aggregate.active_logical_generation_count_peak == 12
    assert summary.final_worker_aggregate.sampling_round_count == 11
    assert summary.resource_summary.round_count == 11
    assert summary.resource_summary.post_warmup_round_count == 2
    assert summary.storage_health_summary.sample_count == 9
    assert evidence.candidate_report.candidate_runtime_passed is True
