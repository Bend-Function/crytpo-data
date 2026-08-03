from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from crypto_collector.benchmarks import runner, writer
from crypto_collector.benchmarks.contracts import GateRuntimeSummaryV1
from crypto_collector.benchmarks.oracle import (
    build_workload_plan,
    iter_exchange_plan_events,
)
from crypto_collector.benchmarks.runner import (
    QualificationClaims,
    RunnerPreflightError,
    RunRequest,
    parse_gate_duration,
    prepare_run,
)
from crypto_collector.benchmarks.workload import load_workload
from crypto_collector.domain.types import Exchange
from crypto_collector.storage.models import EnqueueStatus
from tests.support.writer_gate_evidence import (
    _micro_workload_bytes,
    write_passing_micro_evidence,
)


def _functional_request(tmp_path: Path, **overrides: object) -> RunRequest:
    values: dict[str, object] = {
        "workload_path": Path(
            "benchmarks/workloads/research-default-v1.yaml"
        ).resolve(),
        "multiplier": 2,
        "duration_ns": 10_000_000_000,
        "evidence_root": tmp_path / "evidence",
        "report_path": tmp_path / "writer-short.json",
        "functional_only": True,
    }
    values.update(overrides)
    return RunRequest(**values)  # type: ignore[arg-type]


def _qualification_claims(tmp_path: Path) -> QualificationClaims:
    return QualificationClaims(
        target_declaration_path=tmp_path / "target.json",
        expected_target_id="gate-target-a",
        expected_image_id="sha256:" + "1" * 64,
        runtime_image_id="sha256:" + "1" * 64,
        implementation_source_commit="2" * 40,
        collector_wheel_sha256="3" * 64,
        requirements_lock_sha256="4" * 64,
        dockerfile_sha256="5" * 64,
    )


def _utc_ns(year: int, month: int, day: int, hour: int, minute: int = 0) -> int:
    return int(datetime(year, month, day, hour, minute, tzinfo=UTC).timestamp()) * (
        1_000_000_000
    )


def _micro_plan(tmp_path: Path) -> object:
    workload_path = tmp_path / "micro-workload.json"
    workload_path.write_bytes(_micro_workload_bytes())
    return build_workload_plan(
        load_workload(workload_path),
        multiplier=1,
        duration_ns=10_000_000_000,
    )


def _late_complete_summary(summary: GateRuntimeSummaryV1) -> GateRuntimeSummaryV1:
    streams = list(summary.stream_summaries)
    stream = summary.stream_summaries[0]
    streams[0] = type(stream).model_validate(
        {
            **stream.model_dump(mode="python"),
            "late_count": 1,
            "out_of_window_count": 1,
            "admission_values_match": False,
        }
    )
    return GateRuntimeSummaryV1.model_validate(
        {
            **summary.model_dump(mode="python"),
            "late_count": 1,
            "out_of_window_count": 1,
            "stream_summaries": tuple(streams),
        }
    )


def _performance_degraded_summary(
    summary: GateRuntimeSummaryV1,
) -> GateRuntimeSummaryV1:
    aggregate = summary.final_worker_aggregate
    resource = summary.resource_summary
    health = summary.storage_health_summary
    return GateRuntimeSummaryV1.model_validate(
        {
            **summary.model_dump(mode="python"),
            "final_worker_aggregate": type(aggregate).model_validate(
                {
                    **aggregate.model_dump(mode="python"),
                    "slo_breach_count": 1,
                    "active_logical_generation_count_peak": 1,
                    "retiring_generation_count_peak": 1,
                }
            ),
            "resource_summary": type(resource).model_validate(
                {
                    **resource.model_dump(mode="python"),
                    "sample_max_gap_ns": resource.coverage_ns,
                    "rss_peak_bytes": 10**12,
                    "open_fds_peak": 10**6,
                }
            ),
            "storage_health_summary": type(health).model_validate(
                {
                    **health.model_dump(mode="python"),
                    "sample_max_gap_ns": health.coverage_ns,
                }
            ),
        }
    )


def test_functional_runtime_predicates_allow_recorded_lateness_but_qualification_does_not(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    summary = _late_complete_summary(evidence.candidate_report.runtime_summary)
    prepared = SimpleNamespace(
        mode="functional",
        workload=SimpleNamespace(workload=evidence.workload),
        request=SimpleNamespace(duration_ns=10_000_000_000),
    )

    runner._assert_runtime_candidate_passes(prepared, summary)  # type: ignore[attr-defined,arg-type]

    prepared.mode = "qualification"
    with pytest.raises(runner.WriterGateRunError, match="runtime predicates"):
        runner._assert_runtime_candidate_passes(prepared, summary)  # type: ignore[attr-defined,arg-type]


def test_functional_runtime_records_performance_threshold_breaches_without_failing(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    summary = _performance_degraded_summary(evidence.candidate_report.runtime_summary)
    prepared = SimpleNamespace(
        mode="functional",
        workload=SimpleNamespace(workload=evidence.workload),
        request=SimpleNamespace(duration_ns=10_000_000_000),
    )

    runner._assert_runtime_candidate_passes(prepared, summary)  # type: ignore[attr-defined,arg-type]

    prepared.mode = "qualification"
    with pytest.raises(runner.WriterGateRunError, match="runtime predicates"):
        runner._assert_runtime_candidate_passes(prepared, summary)  # type: ignore[attr-defined,arg-type]


def test_functional_runtime_rejects_critical_worker_observation(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence((tmp_path / "evidence").resolve())
    summary = evidence.candidate_report.runtime_summary
    health = summary.storage_health_summary
    changed = GateRuntimeSummaryV1.model_validate(
        {
            **summary.model_dump(mode="python"),
            "storage_health_summary": type(health).model_validate(
                {
                    **health.model_dump(mode="python"),
                    "critical_worker_observation_count": 1,
                    "workers_healthy": False,
                }
            ),
        }
    )
    prepared = SimpleNamespace(
        mode="functional",
        workload=SimpleNamespace(workload=evidence.workload),
        request=SimpleNamespace(duration_ns=10_000_000_000),
    )

    with pytest.raises(runner.WriterGateRunError, match="runtime predicates"):
        runner._assert_runtime_candidate_passes(prepared, changed)  # type: ignore[attr-defined,arg-type]


def test_functional_writer_config_records_lag_without_five_second_critical(
    tmp_path: Path,
) -> None:
    workload_path = tmp_path / "workload.json"
    workload_path.write_bytes(_micro_workload_bytes())
    workload = load_workload(workload_path)

    functional, _, functional_sha = runner._resolved_configs(  # type: ignore[attr-defined]
        workload,
        mode="functional",
    )
    qualification, _, qualification_sha = runner._resolved_configs(  # type: ignore[attr-defined]
        workload,
        mode="qualification",
    )

    assert functional.durability_slo_ns == qualification.durability_slo_ns
    assert qualification.durability_critical_ns == 5_000_000_000
    expected_minimum_frame_bytes = max(
        stream.payload_max_bytes for stream in workload.workload.streams.values()
    ) + int(runner._RAW_RECORD_FRAME_OVERHEAD_BYTES)  # type: ignore[attr-defined]
    assert functional.max_plain_frame_bytes >= expected_minimum_frame_bytes
    assert qualification.max_plain_frame_bytes >= expected_minimum_frame_bytes
    assert functional.durability_critical_ns > (
        10_000_000_000
        + int(
            runner._child_finish_grace_seconds("functional")  # type: ignore[attr-defined]
            * 1_000_000_000
        )
    )
    assert functional_sha != qualification_sha


def test_research_workload_expands_raw_frame_for_full_envelope() -> None:
    workload = load_workload(
        Path("benchmarks/workloads/research-default-v1.yaml").resolve()
    )

    functional, _, _ = runner._resolved_configs(  # type: ignore[attr-defined]
        workload,
        mode="functional",
    )
    qualification, _, _ = runner._resolved_configs(  # type: ignore[attr-defined]
        workload,
        mode="qualification",
    )

    assert functional.max_plain_frame_bytes == 1_310_720
    assert qualification.max_plain_frame_bytes == 1_310_720


def test_functional_mode_uses_safety_watchdogs_not_qualification_deadlines() -> None:
    qualification_finish = runner._child_finish_grace_seconds(  # type: ignore[attr-defined]
        "qualification"
    )
    functional_finish = runner._child_finish_grace_seconds(  # type: ignore[attr-defined]
        "functional"
    )
    qualification_close = runner._child_close_grace_ns(  # type: ignore[attr-defined]
        "qualification"
    )
    functional_close = runner._child_close_grace_ns(  # type: ignore[attr-defined]
        "functional"
    )
    qualification_final_command = runner._child_final_command_timeout_seconds(  # type: ignore[attr-defined]
        "qualification"
    )
    functional_final_command = runner._child_final_command_timeout_seconds(  # type: ignore[attr-defined]
        "functional"
    )
    qualification_coordination = runner._parent_coordination_timeout_seconds(  # type: ignore[attr-defined]
        "qualification"
    )
    functional_coordination = runner._parent_coordination_timeout_seconds(  # type: ignore[attr-defined]
        "functional"
    )

    assert qualification_finish == 180.0
    assert qualification_close == 120_000_000_000
    assert functional_finish >= 24 * 60 * 60
    assert functional_close >= 24 * 60 * 60 * 1_000_000_000
    assert qualification_final_command == 60.0
    assert functional_final_command >= functional_finish
    assert qualification_coordination == 30.0
    assert functional_coordination >= functional_finish


def test_exchange_spool_round_trips_plan_and_rebases_utc_anchor(
    tmp_path: Path,
) -> None:
    plan = _micro_plan(tmp_path)
    spool = runner._prepare_exchange_spool(  # type: ignore[attr-defined]
        plan,
        Exchange.BINANCE,
        tmp_path / "spool",
    )
    expected = tuple(iter_exchange_plan_events(plan, Exchange.BINANCE))  # type: ignore[arg-type]

    assert spool.row_count == len(expected) == 9
    assert len(spool.partitions) == 10
    assert tuple(partition.row_count for partition in spool.partitions) == (
        1,
        0,
        0,
        0,
        5,
        1,
        0,
        2,
        0,
        0,
    )

    anchor = 1_800_000_000_000_000_000
    prepared = tuple(spool.iter_second(4, admission_started_utc_ns=anchor))
    expected_second = tuple(
        event for event in expected if event.due_offset_ns == 4_000_000_000
    )

    assert tuple(row.planned_event_id for row in prepared) == tuple(
        event.planned_event_id for event in expected_second
    )
    trade = next(row for row in prepared if row.logical_stream == "trade")
    assert trade.draft.event_time_ns == anchor + 4_000_000_000
    assert trade.draft.payload["event_id"] == trade.planned_event_id
    assert trade.source.connection_id == "gate-ws-v1-binance-spot"
    assert trade.shard == f"gate-trade-{trade.identity_index}"

    spool.cleanup()
    assert not spool.root.exists()


def test_exchange_spool_builder_primes_only_bounded_lookahead(
    tmp_path: Path,
) -> None:
    plan = _micro_plan(tmp_path)
    builder = runner._ExchangeSpoolBuilder.open(  # type: ignore[attr-defined]
        plan,
        Exchange.BINANCE,
        tmp_path / "spool",
    )

    builder.prepare_until(runner._SPOOL_LOOKAHEAD_SECONDS)  # type: ignore[attr-defined]

    assert len(builder.partitions) == 3
    assert tuple(partition.second_index for partition in builder.partitions) == (
        0,
        1,
        2,
    )
    assert (
        runner._expected_exchange_record_count(  # type: ignore[attr-defined]
            plan,
            Exchange.BINANCE,
        )
        == 9
    )
    assert (
        sum(
            runner._expected_exchange_record_count(plan, exchange)  # type: ignore[attr-defined]
            for exchange in Exchange
        )
        == plan.expected_record_count
    )

    builder.abort()
    assert not builder.root.exists()


def test_exchange_spool_rejects_physical_mutation(tmp_path: Path) -> None:
    plan = _micro_plan(tmp_path)
    spool = runner._prepare_exchange_spool(  # type: ignore[attr-defined]
        plan,
        Exchange.BINANCE,
        tmp_path / "spool",
    )
    partition = next(item for item in spool.partitions if item.row_count)
    partition.path.write_bytes(partition.path.read_bytes() + b"mutated")

    with pytest.raises(runner.WriterGateRunError, match="spool"):
        tuple(spool.iter_second(partition.second_index, admission_started_utc_ns=1))


def test_exchange_spool_replays_trace_after_admission(tmp_path: Path) -> None:
    plan = _micro_plan(tmp_path)
    spool = runner._prepare_exchange_spool(  # type: ignore[attr-defined]
        plan,
        Exchange.BINANCE,
        tmp_path / "spool",
    )
    outcomes = tuple(
        runner._AdmissionOutcome(  # type: ignore[attr-defined]
            planned_event_id=event.planned_event_id,
            attempt_started_monotonic_ns=10_000_000_000 + event.due_offset_ns,
            admission_completed_monotonic_ns=(10_000_000_001 + event.due_offset_ns),
            enqueue_status=EnqueueStatus.OVERFLOW,
            accepted_identity=None,
        )
        for event in iter_exchange_plan_events(plan, Exchange.BINANCE)  # type: ignore[arg-type]
    )

    rows = tuple(
        spool.iter_trace_rows(
            outcomes,
            admission_started_monotonic_ns=10_000_000_000,
            admission_started_utc_ns=1_800_000_000_000_000_000,
        )
    )

    assert len(rows) == len(outcomes)
    assert tuple(row.planned_event_id for row in rows) == tuple(
        outcome.planned_event_id for outcome in outcomes
    )
    assert all(row.enqueue_status is EnqueueStatus.OVERFLOW for row in rows)
    assert all(row.accepted_identity is None for row in rows)


@pytest.mark.parametrize(
    ("source", "expected"),
    (("10s", 10_000_000_000), ("10m", 600_000_000_000), ("1h", 3_600_000_000_000)),
)
def test_parse_gate_duration_accepts_integral_seconds(
    source: str,
    expected: int,
) -> None:
    assert parse_gate_duration(source) == expected


@pytest.mark.parametrize("source", ("", "10", "0s", "10.5s", "1.1m", "true"))
def test_parse_gate_duration_rejects_nonintegral_or_invalid_values(source: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_gate_duration(source)


def test_functional_preflight_plans_fresh_optional_roots_without_side_effects(
    tmp_path: Path,
) -> None:
    request = _functional_request(tmp_path)

    prepared = prepare_run(
        request,
        now_utc_ns=_utc_ns(2026, 8, 2, 10),
    )

    assert prepared.mode == "functional"
    assert prepared.data_root == (tmp_path / "evidence" / "data").resolve()
    assert prepared.state_root == (tmp_path / "evidence" / "state").resolve()
    assert not prepared.evidence_root.exists()
    assert not prepared.data_root.exists()
    assert not prepared.state_root.exists()


@pytest.mark.parametrize("duration_ns", (1, 9_000_000_000, 11_000_000_000))
def test_functional_preflight_requires_exactly_ten_seconds(
    tmp_path: Path,
    duration_ns: int,
) -> None:
    with pytest.raises(RunnerPreflightError, match="exactly ten seconds"):
        prepare_run(
            _functional_request(tmp_path, duration_ns=duration_ns),
            now_utc_ns=_utc_ns(2026, 8, 2, 10),
        )


def test_functional_preflight_forbids_qualification_claims(tmp_path: Path) -> None:
    with pytest.raises(RunnerPreflightError, match="forbids qualification claims"):
        prepare_run(
            _functional_request(
                tmp_path,
                qualification=_qualification_claims(tmp_path),
            ),
            now_utc_ns=_utc_ns(2026, 8, 2, 10),
        )


def test_qualification_preflight_requires_all_roots_and_claims(tmp_path: Path) -> None:
    with pytest.raises(
        RunnerPreflightError, match="requires explicit data and state roots"
    ):
        prepare_run(
            _functional_request(
                tmp_path,
                functional_only=False,
                duration_ns=600_000_000_000,
                qualification=_qualification_claims(tmp_path),
            ),
            now_utc_ns=_utc_ns(2026, 8, 2, 10),
        )


def test_qualification_preflight_rejects_image_claim_mismatch(tmp_path: Path) -> None:
    claims = _qualification_claims(tmp_path)
    mismatched = replace(claims, runtime_image_id="sha256:" + "9" * 64)
    with pytest.raises(RunnerPreflightError, match="image IDs do not match"):
        prepare_run(
            _functional_request(
                tmp_path,
                functional_only=False,
                duration_ns=600_000_000_000,
                data_root=tmp_path / "data",
                state_root=tmp_path / "state",
                qualification=mismatched,
            ),
            now_utc_ns=_utc_ns(2026, 8, 2, 10),
        )


def test_preflight_rejects_multiplier_below_one(tmp_path: Path) -> None:
    with pytest.raises(RunnerPreflightError, match="multiplier"):
        prepare_run(
            _functional_request(tmp_path, multiplier=0),
            now_utc_ns=_utc_ns(2026, 8, 2, 10),
        )


def test_preflight_rejects_insufficient_utc_hour_capacity(tmp_path: Path) -> None:
    with pytest.raises(RunnerPreflightError, match="UTC hour"):
        prepare_run(
            _functional_request(tmp_path),
            now_utc_ns=_utc_ns(2026, 8, 2, 10, 59) + 30_000_000_000,
        )


@pytest.mark.parametrize(
    ("root_name", "relative"),
    (("data", "raw/okx"), ("state", "raw-recovery/okx")),
)
def test_preflight_rejects_existing_exchange_subtrees(
    tmp_path: Path,
    root_name: str,
    relative: str,
) -> None:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    data_root.mkdir()
    state_root.mkdir()
    selected = data_root if root_name == "data" else state_root
    (selected / relative).mkdir(parents=True)

    with pytest.raises(RunnerPreflightError, match="fresh exchange subtrees"):
        prepare_run(
            _functional_request(
                tmp_path,
                data_root=data_root,
                state_root=state_root,
            ),
            now_utc_ns=_utc_ns(2026, 8, 2, 10),
        )


def test_default_invocation_and_run_subcommand_build_identical_request(
    tmp_path: Path,
) -> None:
    common = [
        "--workload",
        "benchmarks/workloads/research-default-v1.yaml",
        "--multiplier",
        "2",
        "--duration",
        "10s",
        "--evidence-root",
        str(tmp_path / "evidence"),
        "--report",
        str(tmp_path / "report.json"),
        "--functional-only",
    ]
    captured: list[dict[str, object]] = []

    def capture(**kwargs: object) -> None:
        captured.append(kwargs)

    runner = CliRunner()
    with patch.object(writer, "_execute_run", capture):
        default = runner.invoke(writer.app, common)
        command = runner.invoke(writer.app, ["run", *common])

    assert default.exit_code == 0, default.output
    assert command.exit_code == 0, command.output
    assert captured[0] == captured[1]


def test_cli_preflight_errors_exit_two(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        writer.app,
        [
            "--workload",
            "benchmarks/workloads/research-default-v1.yaml",
            "--multiplier",
            "2",
            "--duration",
            "11s",
            "--evidence-root",
            str(tmp_path / "evidence"),
            "--report",
            str(tmp_path / "report.json"),
            "--functional-only",
        ],
    )

    assert result.exit_code == 2
    assert "exactly ten seconds" in result.output
