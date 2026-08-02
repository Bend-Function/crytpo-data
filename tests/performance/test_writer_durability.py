from __future__ import annotations

import os
from pathlib import Path
from typing import Any, cast

import pytest

from crypto_collector.benchmarks.contracts import (
    FinalWorkerAggregateV1,
    GateAdmissionTraceSetV1,
    GateAdmissionTraceV1,
    GateArtifactRefV1,
    GateResourceSummaryV1,
    GateRootProbeV1,
    GateStorageHealthSummaryV1,
    GateTargetReprobeV1,
    GateTargetV1,
)
from crypto_collector.benchmarks.oracle import build_workload_plan
from crypto_collector.benchmarks.workload import load_workload
from crypto_collector.domain.json_codec import decode_json

WORKLOAD_PATH = Path("benchmarks/workloads/research-default-v1.yaml")
GOLDEN_PATH = Path("benchmarks/workloads/research-default-v1.golden.json")


def test_writer_gate_foundational_artifact_surface_is_frozen() -> None:
    assert tuple(GateArtifactRefV1.model_fields)[:3] == (
        "schema_version",
        "record_type",
        "relative_path",
    )
    assert "planned_event_id" in GateAdmissionTraceV1.model_fields
    assert tuple(GateAdmissionTraceSetV1.model_fields)[-3:] == (
        "merged_row_count",
        "merged_content_size_bytes",
        "merged_content_sha256",
    )


def test_writer_gate_aggregation_surface_is_frozen() -> None:
    assert tuple(FinalWorkerAggregateV1.model_fields)[:5] == (
        "schema_version",
        "record_type",
        "worker_count",
        "sampling_round_count",
        "final_round_index",
    )


def test_writer_gate_target_surface_is_frozen() -> None:
    assert tuple(GateRootProbeV1.model_fields)[-5:] == (
        "observed_available_bytes",
        "no_replace_capability",
        "same_parent_publication_only",
        "file_sync_supported",
        "directory_sync_supported",
    )
    assert tuple(GateTargetV1.model_fields)[-2:] == (
        "created_at_unix_ns",
        "sha256",
    )
    assert tuple(GateTargetReprobeV1.model_fields)[-5:] == (
        "target_id_matches",
        "declaration_facts_match",
        "available_space_valid",
        "reprobe_valid",
        "sha256",
    )
    assert tuple(GateResourceSummaryV1.model_fields)[-4:] == (
        "first_open_fds_after_warmup",
        "max_open_fds_after_warmup",
        "final_open_fds_after_warmup",
        "fd_growth_after_warmup",
    )
    assert tuple(GateStorageHealthSummaryV1.model_fields)[-3:] == (
        "sample_count_valid",
        "coverage_valid",
        "workers_healthy",
    )


def test_research_default_workload_has_exact_multiplier_two_cardinalities() -> None:
    workload = load_workload(WORKLOAD_PATH)
    functional = build_workload_plan(
        workload,
        multiplier=2,
        duration_ns=10_000_000_000,
    )
    qualification = build_workload_plan(
        workload,
        multiplier=2,
        duration_ns=600_000_000_000,
    )

    assert (
        functional.expected_record_count,
        functional.expected_touched_file_identity_count,
        functional.declared_file_identity_count,
    ) == (417_677, 3_172, 3_505)
    assert (
        qualification.expected_record_count,
        qualification.expected_touched_file_identity_count,
        qualification.declared_file_identity_count,
    ) == (25_060_620, 3_505, 3_505)


@pytest.mark.performance
@pytest.mark.skipif(
    os.environ.get("CRYPTO_COLLECTOR_FULL_GATE_ORACLE") != "1",
    reason="set CRYPTO_COLLECTOR_FULL_GATE_ORACLE=1 for the 10-minute plan hash",
)
def test_qualification_plan_matches_literal_golden_hash() -> None:
    decoded = decode_json(GOLDEN_PATH.read_bytes())
    assert isinstance(decoded, dict)
    golden = cast(dict[str, Any], decoded)["plans"]["qualification_10m_multiplier_2"]
    plan = build_workload_plan(
        load_workload(WORKLOAD_PATH),
        multiplier=2,
        duration_ns=600_000_000_000,
    )

    assert {
        "duration_ns": plan.duration_ns,
        "multiplier": plan.multiplier,
        "expected_record_count": plan.expected_record_count,
        "declared_file_identity_count": plan.declared_file_identity_count,
        "expected_touched_file_identity_count": (
            plan.expected_touched_file_identity_count
        ),
        "expected_payload_byte_count": plan.expected_payload_byte_count,
        "workload_plan_sha256": plan.workload_plan_sha256,
    } == {key: value for key, value in golden.items() if key != "streams"}
    assert {
        summary.stream_group: {
            "summary": {
                "expected_record_count": summary.expected_record_count,
                "identity_count": summary.identity_count,
                "expected_touched_file_identity_count": (
                    summary.expected_touched_file_identity_count
                ),
                "required_burst_count": summary.required_burst_count,
                "scheduled_burst_count": summary.scheduled_burst_count,
                "burst_second": summary.burst_second,
                "expected_payload_byte_count": (summary.expected_payload_byte_count),
            }
        }
        for summary in plan.streams
    } == golden["streams"]
