from __future__ import annotations

import errno
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from crypto_collector.benchmarks import runner
from crypto_collector.benchmarks.runner import PreparedRun, RunRequest
from crypto_collector.benchmarks.workload import load_workload
from crypto_collector.domain.types import Exchange
from crypto_collector.storage.manifest import load_raw_manifest
from tests.support.writer_gate_evidence import (
    PassingMicroEvidence,
    write_passing_micro_evidence,
)


def _join_database_with_accepted_traces(
    evidence: PassingMicroEvidence,
) -> runner._RunnerJoinDatabase:  # type: ignore[attr-defined]
    database = runner._RunnerJoinDatabase(  # type: ignore[attr-defined]
        evidence.state_root
    )
    for trace in evidence.traces:
        database.add_accepted(trace)
    return database


def _prepared_run(evidence: PassingMicroEvidence) -> PreparedRun:
    workload_path = evidence.root / "workload.json"
    workload = load_workload(workload_path)
    writer_config, ingress_config, config_sha256 = runner._resolved_configs(  # type: ignore[attr-defined]
        workload,
        mode="functional",
    )
    request = RunRequest(
        workload_path=workload_path,
        multiplier=1,
        duration_ns=evidence.plan.duration_ns,
        evidence_root=evidence.root,
        report_path=evidence.root.parent / "writer-short.json",
        functional_only=True,
        data_root=evidence.data_root,
        state_root=evidence.state_root,
    )
    return PreparedRun(
        request=request,
        mode="functional",
        evidence_root=evidence.root,
        data_root=evidence.data_root,
        state_root=evidence.state_root,
        report_path=request.report_path,
        workload=workload,
        plan=evidence.plan,
        writer_config=writer_config,
        ingress_config=ingress_config,
        config_sha256=config_sha256,
        target_declaration_source=None,
    )


def test_join_database_rejects_noncontiguous_acceptance_ordinals(
    tmp_path: Path,
) -> None:
    database = runner._RunnerJoinDatabase(tmp_path)  # type: ignore[attr-defined]
    accepted_rows = (
        (
            "route",
            0,
            "gate-worker-v1-binance",
            0,
            "c" * 64,
            0,
            "event-0",
            "a" * 64,
            10,
        ),
        (
            "route",
            1,
            "gate-worker-v1-binance",
            2,
            "c" * 64,
            0,
            "event-1",
            "b" * 64,
            11,
        ),
    )
    durable_rows = tuple(
        (
            route,
            writer_sequence,
            worker_instance_id,
            event_id,
            payload_sha256,
            payload_bytes,
            "2027/01/15/08",
        )
        for (
            route,
            writer_sequence,
            worker_instance_id,
            _acceptance_ordinal,
            _config_sha256,
            _config_generation,
            event_id,
            payload_sha256,
            payload_bytes,
        ) in accepted_rows
    )
    database.connection.executemany(
        "INSERT INTO accepted VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        accepted_rows,
    )
    database.connection.executemany(
        "INSERT INTO durable VALUES (?, ?, ?, ?, ?, ?, ?)",
        durable_rows,
    )

    try:
        with pytest.raises(runner.WriterGateRunError, match="ordinal.*contiguous"):
            database.finalize()
    finally:
        database.close()


def test_runtime_summary_binds_accepted_generation_to_final_worker_snapshot(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    database = runner._RunnerJoinDatabase(  # type: ignore[attr-defined]
        evidence.state_root
    )
    changed = 0
    for trace in evidence.traces:
        accepted_identity = trace.accepted_identity
        if trace.exchange is Exchange.BINANCE:
            assert accepted_identity is not None
            accepted_identity = accepted_identity.model_copy(
                update={"config_generation": accepted_identity.config_generation + 1}
            )
            changed += 1
        database.add_accepted(
            trace.model_copy(update={"accepted_identity": accepted_identity})
        )
    assert changed > 0

    try:
        prepared = _prepared_run(evidence)
        raw_inventory, manifest_inventory, _manifests = runner._scan_raw_inventories(  # type: ignore[attr-defined]
            evidence.data_root,
            database=database,
            expected_config_sha256="c" * 64,
            expected_writer_config=prepared.writer_config,
        )
        join_facts = database.finalize()

        with pytest.raises(
            runner.WriterGateRunError,
            match="final worker snapshots",
        ):
            runner._runtime_summary(  # type: ignore[attr-defined]
                prepared=_prepared_run(evidence),
                admission_started_monotonic_ns=1_000_000_000,
                admission_started_utc_ns=1_800_000_000_000_000_000,
                buckets=evidence.buckets,
                worker_rounds=evidence.worker_rounds,
                resource_rounds=evidence.resource_rounds,
                health_samples=evidence.health_samples,
                raw_inventory=raw_inventory,
                manifest_inventory=manifest_inventory,
                join_facts=join_facts,
                accepted_count=len(evidence.traces),
                accepted_payload_bytes=sum(
                    trace.payload_bytes for trace in evidence.traces
                ),
            )
    finally:
        database.close()


def test_raw_inventory_rejects_cross_swapped_manifest_paths(tmp_path: Path) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    manifest_paths = tuple(
        sorted((evidence.data_root / "raw").rglob("*.manifest.json"))
    )
    assert len(manifest_paths) >= 2
    first, second = manifest_paths[:2]
    first_bytes = first.read_bytes()
    second_bytes = second.read_bytes()
    first.write_bytes(second_bytes)
    second.write_bytes(first_bytes)
    database = _join_database_with_accepted_traces(evidence)

    try:
        with pytest.raises(runner.WriterGateRunError, match="manifest.*path"):
            runner._scan_raw_inventories(  # type: ignore[attr-defined]
                evidence.data_root,
                database=database,
                expected_config_sha256="c" * 64,
                expected_writer_config=_prepared_run(evidence).writer_config,
            )
    finally:
        database.close()


def test_raw_inventory_converts_walk_errors_to_closed_gate_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    database = _join_database_with_accepted_traces(evidence)

    def inaccessible_walk(
        *_args: object,
        **kwargs: Any,
    ) -> Iterator[tuple[str, list[str], list[str]]]:
        error = OSError(errno.EACCES, "permission denied")
        onerror = kwargs.get("onerror")
        if onerror is None:
            raise error
        onerror(error)
        raise AssertionError("os.walk onerror unexpectedly returned")

    monkeypatch.setattr(runner.os, "walk", inaccessible_walk)
    try:
        with pytest.raises(runner.WriterGateRunError, match="walk"):
            runner._scan_raw_inventories(  # type: ignore[attr-defined]
                evidence.data_root,
                database=database,
                expected_config_sha256="c" * 64,
                expected_writer_config=_prepared_run(evidence).writer_config,
            )
    finally:
        database.close()


def test_raw_inventory_rejects_manifest_frame_bound_above_config(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    manifest_path = min((evidence.data_root / "raw").rglob("*.manifest.json"))
    manifest = load_raw_manifest(manifest_path).manifest
    changed = manifest.model_copy(update={"max_plain_frame_bytes": 2 * 1024 * 1024})
    manifest_path.write_bytes(changed.canonical_bytes())
    database = _join_database_with_accepted_traces(evidence)

    try:
        with pytest.raises(runner.WriterGateRunError, match="codec"):
            runner._scan_raw_inventories(  # type: ignore[attr-defined]
                evidence.data_root,
                database=database,
                expected_config_sha256="c" * 64,
                expected_writer_config=_prepared_run(evidence).writer_config,
            )
    finally:
        database.close()
