from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from crypto_collector.runtime.reload import (
    ReferenceConfigSnapshot,
    ReferenceDocumentError,
)
from crypto_collector.runtime.state_store import (
    AuditEvent,
    ConflictingRecordError,
    EpochStatus,
    IncompletePrepareError,
    ReloadAuditPayload,
    ReloadAuditStatus,
    ReloadStateError,
    ReloadStateStore,
    StaleWorkerAckError,
    WorkerAckFence,
    WorkerTarget,
)


def _snapshot(tmp_path: Path, marker: str) -> ReferenceConfigSnapshot:
    return ReferenceConfigSnapshot(
        config_sha256=marker * 64,
        capability_registry_sha256="f" * 64,
        config_path=str(tmp_path / "collector.yaml"),
        base_dir=str(tmp_path),
        source_document={
            "data_root": str(tmp_path / "data"),
            "selection": {"fixed_pairs": ["BTC-USDT"]},
            "archive": {"access_key_secret": "env:ARCHIVE_SECRET"},
        },
    )


def _fence(epoch: int, exchange: str, generation: int = 7) -> WorkerAckFence:
    return WorkerAckFence(
        epoch=epoch,
        exchange=exchange,
        supervisor_instance_id="supervisor-a",
        request_id="reload-1",
        worker_instance_id=f"{exchange}-worker-a",
        worker_generation=generation,
    )


def _planned_event(epoch: int, exchange: str) -> AuditEvent:
    return AuditEvent(
        event_id=f"reload-{epoch}-{exchange}-planned",
        exchange=exchange,
        kind="config_reload_planned",
        payload=ReloadAuditPayload(
            epoch=epoch,
            status=ReloadAuditStatus.PLANNED,
            changed_paths=("network.egress_pool[0].url",),
        ),
    )


@pytest.mark.parametrize(
    "payload",
    [
        {"access_key_secret": "plaintext"},
        {"clientSecret": "plaintext"},
        {"apiKey": "plaintext"},
        {"proxy_url": "socks5://127.0.0.1:1080"},
        {"proxy_url": "socks5://user:plaintext@127.0.0.1:1080"},
        {"mount_guard": {"expected": "plaintext"}},
        {"error": "exception text is not an error code"},
    ],
)
@pytest.mark.parametrize(
    "kind",
    [
        "config_reload_planned",
        "config_reload_committed",
        "config_reload_failed",
    ],
)
def test_audit_event_rejects_non_reference_secret_or_narrative_payloads(
    payload: dict[str, object], kind: str
) -> None:
    with pytest.raises(TypeError, match="ReloadAuditPayload"):
        AuditEvent(
            "event-1",
            "okx",
            kind,
            payload,  # type: ignore[arg-type]
        )


def test_initial_epoch_and_atomic_commit_survive_reopen(tmp_path: Path) -> None:
    path = tmp_path / "runtime" / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        initial = store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        candidate = store.begin_reload(
            _snapshot(tmp_path, "b"),
            supervisor_instance_id="supervisor-a",
            request_id="reload-1",
            workers=(
                WorkerTarget("okx", "okx-worker-a", 7),
                WorkerTarget("bybit", "bybit-worker-a", 3),
            ),
            planned_events=(
                _planned_event(2, "okx"),
                _planned_event(2, "bybit"),
            ),
            created_at_ns=20,
        )

        assert initial.epoch == 1
        assert candidate.epoch == 2
        assert candidate.status is EpochStatus.PREPARING
        assert store.current_epoch().epoch == 1  # type: ignore[union-attr]
        assert [event.kind for event in store.pending_audit("okx")] == [
            "config_reload_planned"
        ]

        store.ack_prepared(_fence(2, "okx"), plan_sha256="1" * 64, at_ns=30)
        store.ack_prepared(_fence(2, "bybit", 3), plan_sha256="2" * 64, at_ns=31)
        committed = store.commit_prepared_epoch(
            2,
            committed_at_ns=40,
            committed_events=(
                AuditEvent(
                    event_id="reload-2-okx-committed",
                    exchange="okx",
                    kind="config_reload_committed",
                    payload=ReloadAuditPayload(
                        epoch=2,
                        status=ReloadAuditStatus.COMMITTED,
                    ),
                ),
            ),
        )

        assert committed.status is EpochStatus.COMMITTED
        assert store.current_epoch().epoch == 2  # type: ignore[union-attr]
        assert store.ack_applied(_fence(2, "okx"), at_ns=41) is True
        assert store.ack_applied(_fence(2, "okx"), at_ns=42) is False
        assert store.epoch_converged(2) is False
        store.ack_applied(_fence(2, "bybit", 3), at_ns=43)
        assert store.epoch_converged(2) is True

    with ReloadStateStore.open(path) as reopened:
        assert reopened.current_epoch().epoch == 2  # type: ignore[union-attr]
        assert reopened.epoch(2).snapshot == _snapshot(tmp_path, "b")  # type: ignore[union-attr]
        assert reopened.epoch_converged(2) is True


def test_store_reopens_a_legacy_version_one_reference_snapshot(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )

    with sqlite3.connect(path) as connection:
        encoded = connection.execute(
            "SELECT config_snapshot FROM reload_epoch WHERE epoch = 1"
        ).fetchone()[0]
        legacy = json.loads(bytes(encoded))
        legacy["schema_version"] = 1
        del legacy["document_sha256"]
        connection.execute(
            "UPDATE reload_epoch SET config_snapshot = ? WHERE epoch = 1",
            (
                json.dumps(legacy, separators=(",", ":"), sort_keys=True).encode(
                    "utf-8"
                ),
            ),
        )

    with ReloadStateStore.open(path) as reopened:
        current = reopened.current_epoch()
        assert current is not None
        assert current.snapshot.schema_version == 2
        assert current.snapshot.document_sha256 is not None

    with sqlite3.connect(path) as connection:
        persisted = json.loads(
            bytes(
                connection.execute(
                    "SELECT config_snapshot FROM reload_epoch WHERE epoch = 1"
                ).fetchone()[0]
            )
        )
    assert persisted["schema_version"] == 2
    assert len(persisted["document_sha256"]) == 64


def test_ack_fence_rejects_stale_supervisor_request_worker_and_generation(
    tmp_path: Path,
) -> None:
    with ReloadStateStore.open(tmp_path / "reload.sqlite3") as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        store.begin_reload(
            _snapshot(tmp_path, "b"),
            supervisor_instance_id="supervisor-a",
            request_id="reload-1",
            workers=(WorkerTarget("okx", "okx-worker-a", 7),),
            planned_events=(_planned_event(2, "okx"),),
            created_at_ns=20,
        )

        valid = _fence(2, "okx")
        stale_fences = (
            replace(valid, supervisor_instance_id="old"),
            replace(valid, request_id="old"),
            replace(valid, worker_instance_id="old"),
            replace(valid, worker_generation=6),
        )

        for stale in stale_fences:
            with pytest.raises(StaleWorkerAckError):
                store.ack_prepared(stale, plan_sha256="1" * 64, at_ns=30)

        assert store.ack_prepared(valid, plan_sha256="1" * 64, at_ns=30)
        store.abort_preparing_epoch(2, failure_code="prepare_failed", failed_at_ns=31)
        with pytest.raises(ReloadStateError, match="aborted epoch"):
            store.ack_prepared(valid, plan_sha256="1" * 64, at_ns=32)


def test_precommit_failure_keeps_old_pointer_and_recovery_aborts_intent(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        store.begin_reload(
            _snapshot(tmp_path, "b"),
            supervisor_instance_id="supervisor-a",
            request_id="reload-1",
            workers=(WorkerTarget("okx", "okx-worker-a", 7),),
            planned_events=(_planned_event(2, "okx"),),
            created_at_ns=20,
        )

        with pytest.raises(IncompletePrepareError):
            store.commit_prepared_epoch(2, committed_at_ns=30)
        assert store.current_epoch().epoch == 1  # type: ignore[union-attr]

    with ReloadStateStore.open(path) as reopened:
        recovered = reopened.recover_interrupted_prepares(
            failure_code="supervisor_restarted",
            failed_at_ns=40,
        )
        assert recovered == (2,)
        assert reopened.epoch(2).status is EpochStatus.ABORTED  # type: ignore[union-attr]
        assert reopened.current_epoch().epoch == 1  # type: ignore[union-attr]


def test_oversized_candidate_never_changes_durable_current(tmp_path: Path) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        oversized = ReferenceConfigSnapshot(
            config_sha256="b" * 64,
            capability_registry_sha256="f" * 64,
            config_path=str(tmp_path / "collector.yaml"),
            base_dir=str(tmp_path),
            source_document={"padding": "x" * (8 * 1024 * 1024)},
        )

        with pytest.raises(ReferenceDocumentError, match="exceeds 8 MiB"):
            store.begin_reload(
                oversized,
                supervisor_instance_id="supervisor-a",
                request_id="reload-1",
                workers=(),
                created_at_ns=20,
            )
        assert store.current_epoch().epoch == 1  # type: ignore[union-attr]
        assert store.epoch(2) is None

    with ReloadStateStore.open(path) as reopened:
        assert reopened.current_epoch().epoch == 1  # type: ignore[union-attr]


def test_oversized_initial_snapshot_leaves_an_empty_readable_store(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reload.sqlite3"
    oversized = ReferenceConfigSnapshot(
        config_sha256="a" * 64,
        capability_registry_sha256="f" * 64,
        config_path=str(tmp_path / "collector.yaml"),
        base_dir=str(tmp_path),
        source_document={"profile": "x" * (8 * 1024 * 1024)},
    )
    with ReloadStateStore.open(path) as store:
        with pytest.raises(ReferenceDocumentError, match="exceeds 8 MiB"):
            store.commit_initial_epoch(
                oversized,
                supervisor_instance_id="supervisor-a",
                request_id="startup-1",
                committed_at_ns=10,
            )
        assert store.current_epoch() is None
        assert store.epoch(1) is None

    with ReloadStateStore.open(path) as reopened:
        assert reopened.current_epoch() is None


def test_postcommit_recovery_preserves_current_until_workers_converge(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        store.begin_reload(
            _snapshot(tmp_path, "b"),
            supervisor_instance_id="supervisor-a",
            request_id="reload-1",
            workers=(WorkerTarget("okx", "okx-worker-a", 7),),
            planned_events=(_planned_event(2, "okx"),),
            created_at_ns=20,
        )
        store.ack_prepared(_fence(2, "okx"), plan_sha256="1" * 64, at_ns=30)
        store.commit_prepared_epoch(2, committed_at_ns=40)

    with ReloadStateStore.open(path) as reopened:
        assert (
            reopened.recover_interrupted_prepares(
                failure_code="supervisor_restarted", failed_at_ns=50
            )
            == ()
        )
        assert reopened.current_epoch().epoch == 2  # type: ignore[union-attr]
        assert reopened.epoch_converged(2) is False

        recovery_fence = WorkerAckFence(
            epoch=2,
            exchange="okx",
            supervisor_instance_id="supervisor-b",
            request_id="recovery-1",
            worker_instance_id="okx-worker-b",
            worker_generation=8,
        )
        assert reopened.register_committed_worker(
            recovery_fence, plan_sha256="3" * 64, registered_at_ns=60
        )
        assert reopened.ack_applied(recovery_fence, at_ns=61)
        assert reopened.epoch_converged(2) is True


def test_committed_worker_refence_requires_current_epoch_and_new_generation(
    tmp_path: Path,
) -> None:
    with ReloadStateStore.open(tmp_path / "reload.sqlite3") as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        first = WorkerAckFence(
            epoch=1,
            exchange="okx",
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            worker_instance_id="okx-worker-a",
            worker_generation=1,
        )
        assert store.register_committed_worker(
            first, plan_sha256="1" * 64, registered_at_ns=11
        )
        assert not store.register_committed_worker(
            first, plan_sha256="1" * 64, registered_at_ns=12
        )

        with pytest.raises(StaleWorkerAckError):
            store.register_committed_worker(
                replace(first, supervisor_instance_id="supervisor-b"),
                plan_sha256="1" * 64,
                registered_at_ns=13,
            )
        with pytest.raises(StaleWorkerAckError, match="predecessor plus one"):
            store.register_committed_worker(
                replace(
                    first,
                    supervisor_instance_id="supervisor-b",
                    request_id="recovery-gap",
                    worker_instance_id="okx-worker-gap",
                    worker_generation=3,
                ),
                plan_sha256="2" * 64,
                registered_at_ns=13,
            )

        replacement = replace(
            first,
            supervisor_instance_id="supervisor-b",
            request_id="recovery-1",
            worker_instance_id="okx-worker-b",
            worker_generation=2,
        )
        assert store.register_committed_worker(
            replacement, plan_sha256="2" * 64, registered_at_ns=14
        )
        assert store.workers_for_epoch(1)[0].fence == replacement


def test_audit_outbox_is_idempotent_durable_and_ack_fenced(tmp_path: Path) -> None:
    path = tmp_path / "reload.sqlite3"
    event = _planned_event(2, "okx")
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        old_fence = WorkerAckFence(
            epoch=1,
            exchange="okx",
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            worker_instance_id="okx-worker-a",
            worker_generation=7,
        )
        store.register_committed_worker(
            old_fence, plan_sha256="9" * 64, registered_at_ns=11
        )
        store.ack_applied(old_fence, at_ns=12)
        store.begin_reload(
            _snapshot(tmp_path, "b"),
            supervisor_instance_id="supervisor-a",
            request_id="reload-1",
            workers=(WorkerTarget("okx", "okx-worker-a", 7),),
            planned_events=(event,),
            created_at_ns=20,
        )
        assert store.enqueue_audit(2, event, created_at_ns=20) is False
        with pytest.raises(ConflictingRecordError):
            store.enqueue_audit(
                2,
                AuditEvent(
                    event.event_id,
                    "okx",
                    "config_reload_committed",
                    ReloadAuditPayload(
                        epoch=2,
                        status=ReloadAuditStatus.COMMITTED,
                    ),
                ),
                created_at_ns=20,
            )

    with ReloadStateStore.open(path) as reopened:
        with pytest.raises(StaleWorkerAckError):
            reopened.ack_audit_delivery(old_fence, event.event_id, delivered_at_ns=29)
        stale = replace(_fence(2, "okx"), worker_generation=6)
        with pytest.raises(StaleWorkerAckError):
            reopened.ack_audit_delivery(stale, event.event_id, delivered_at_ns=30)
        assert reopened.ack_audit_delivery(
            _fence(2, "okx"), event.event_id, delivered_at_ns=30
        )
        assert not reopened.ack_audit_delivery(
            _fence(2, "okx"), event.event_id, delivered_at_ns=31
        )
        assert reopened.pending_audit("okx") == ()


def test_recovery_worker_can_deliver_audit_from_aborted_candidate(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        store.begin_reload(
            _snapshot(tmp_path, "b"),
            supervisor_instance_id="supervisor-a",
            request_id="reload-1",
            workers=(WorkerTarget("okx", "okx-worker-a", 1),),
            created_at_ns=20,
        )
        store.abort_preparing_epoch(2, failure_code="prepare_failed", failed_at_ns=30)

        active = WorkerAckFence(
            epoch=1,
            exchange="okx",
            supervisor_instance_id="supervisor-b",
            request_id="recovery-1",
            worker_instance_id="okx-worker-b",
            worker_generation=2,
        )
        store.register_committed_worker(
            active, plan_sha256="3" * 64, registered_at_ns=40
        )
        failed = next(
            event
            for event in store.pending_audit("okx")
            if event.kind == "config_reload_failed"
        )

        assert store.ack_audit_delivery(active, failed.event_id, delivered_at_ns=41)


def test_next_reload_waits_for_current_epoch_convergence(tmp_path: Path) -> None:
    with ReloadStateStore.open(tmp_path / "reload.sqlite3") as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        current = WorkerAckFence(
            epoch=1,
            exchange="okx",
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            worker_instance_id="okx-worker-a",
            worker_generation=1,
        )
        store.register_committed_worker(
            current, plan_sha256="1" * 64, registered_at_ns=11
        )

        with pytest.raises(ConflictingRecordError, match="converged"):
            store.begin_reload(
                _snapshot(tmp_path, "b"),
                supervisor_instance_id="supervisor-a",
                request_id="reload-1",
                workers=(WorkerTarget("okx", "okx-worker-a", 1),),
                created_at_ns=20,
            )

        store.ack_applied(current, at_ns=21)
        with pytest.raises(StaleWorkerAckError, match="predecessor"):
            store.begin_reload(
                _snapshot(tmp_path, "b"),
                supervisor_instance_id="supervisor-a",
                request_id="reload-1",
                workers=(WorkerTarget("okx", "stale-worker", 1),),
                created_at_ns=22,
            )
        assert (
            store.begin_reload(
                _snapshot(tmp_path, "b"),
                supervisor_instance_id="supervisor-a",
                request_id="reload-1",
                workers=(WorkerTarget("okx", "okx-worker-a", 1),),
                created_at_ns=23,
            ).epoch
            == 2
        )


def test_crash_window_is_durable_idempotent_and_requires_continuous_health(
    tmp_path: Path,
) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=1,
        )
        first = WorkerAckFence(
            epoch=1,
            exchange="okx",
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            worker_instance_id="okx-worker-a",
            worker_generation=1,
        )
        store.register_committed_worker(first, plan_sha256="1" * 64, registered_at_ns=2)
        store.ack_applied(first, at_ns=3)
        store.mark_worker_healthy(first, at_ns=3)
        assert store.record_abnormal_exit(
            first, occurred_at_ns=100, exit_code=1, reason="worker_crashed"
        )
        assert not store.record_abnormal_exit(
            first, occurred_at_ns=100, exit_code=1, reason="worker_crashed"
        )
        with pytest.raises(ConflictingRecordError):
            store.record_abnormal_exit(
                first, occurred_at_ns=101, exit_code=2, reason="different"
            )
        second = replace(
            first,
            request_id="restart-2",
            worker_instance_id="okx-worker-b",
            worker_generation=2,
        )
        store.register_committed_worker(
            second, plan_sha256="2" * 64, registered_at_ns=101
        )
        store.ack_applied(second, at_ns=150)
        store.mark_worker_healthy(second, at_ns=150)
        store.record_abnormal_exit(
            second, occurred_at_ns=200, exit_code=1, reason="worker_crashed"
        )
        assert store.crash_count("okx", now_ns=250, window_ns=100) == 1
        with pytest.raises(StaleWorkerAckError):
            store.reset_crash_window_if_healthy(
                first, observed_at_ns=300, reset_after_ns=100
            )
        third = replace(
            second,
            request_id="restart-3",
            worker_instance_id="okx-worker-c",
            worker_generation=3,
        )
        store.register_committed_worker(
            third, plan_sha256="3" * 64, registered_at_ns=201
        )
        store.ack_applied(third, at_ns=201)
        store.mark_worker_healthy(third, at_ns=201)
        assert not store.reset_crash_window_if_healthy(
            third, observed_at_ns=300, reset_after_ns=100
        )
        with pytest.raises(ValueError, match="normalized code"):
            store.record_abnormal_exit(
                third,
                occurred_at_ns=250,
                exit_code=1,
                reason="exception included plaintext secret",
            )

    with ReloadStateStore.open(path) as reopened:
        assert reopened.crash_count("okx", now_ns=250, window_ns=1_000) == 2
        assert reopened.reset_crash_window_if_healthy(
            third, observed_at_ns=301, reset_after_ns=100
        )
        assert reopened.crash_count("okx", now_ns=301, window_ns=1_000) == 0


def test_historical_epoch_fence_cannot_pollute_current_crash_budget(
    tmp_path: Path,
) -> None:
    with ReloadStateStore.open(tmp_path / "reload.sqlite3") as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        old = WorkerAckFence(
            epoch=1,
            exchange="okx",
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            worker_instance_id="okx-worker-a",
            worker_generation=7,
        )
        store.register_committed_worker(old, plan_sha256="1" * 64, registered_at_ns=11)
        store.ack_applied(old, at_ns=12)
        store.begin_reload(
            _snapshot(tmp_path, "b"),
            supervisor_instance_id="supervisor-a",
            request_id="reload-1",
            workers=(WorkerTarget("okx", "okx-worker-a", 7),),
            created_at_ns=20,
        )
        current = _fence(2, "okx")
        store.ack_prepared(current, plan_sha256="2" * 64, at_ns=21)
        store.commit_prepared_epoch(2, committed_at_ns=22)
        store.ack_applied(current, at_ns=23)

        with pytest.raises(StaleWorkerAckError, match="current committed"):
            store.record_abnormal_exit(
                old,
                occurred_at_ns=24,
                exit_code=1,
                reason="worker_crashed",
            )
        assert store.crash_count("okx", now_ns=24, window_ns=100) == 0


def test_open_rejects_same_version_schema_with_weakened_index(tmp_path: Path) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path):
        pass

    connection = sqlite3.connect(path)
    try:
        connection.execute("DROP INDEX worker_crash_window")
        connection.execute("CREATE INDEX worker_crash_window ON worker_crash(exchange)")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="schema objects"):
        ReloadStateStore.open(path)


def test_open_rejects_epoch_column_and_snapshot_digest_drift(tmp_path: Path) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )

    connection = sqlite3.connect(path)
    try:
        connection.execute(
            "UPDATE reload_epoch SET config_sha256 = ? WHERE epoch = 1", ("b" * 64,)
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="digest does not match"):
        ReloadStateStore.open(path)


def test_open_rejects_audit_envelope_and_payload_drift(tmp_path: Path) -> None:
    path = tmp_path / "reload.sqlite3"
    with ReloadStateStore.open(path) as store:
        store.commit_initial_epoch(
            _snapshot(tmp_path, "a"),
            supervisor_instance_id="supervisor-a",
            request_id="startup-1",
            committed_at_ns=10,
        )
        store.begin_reload(
            _snapshot(tmp_path, "b"),
            supervisor_instance_id="supervisor-a",
            request_id="reload-1",
            workers=(WorkerTarget("okx", "okx-worker-a", 1),),
            created_at_ns=20,
        )

    connection = sqlite3.connect(path)
    try:
        connection.execute("UPDATE audit_outbox SET kind = 'config_reload_committed'")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="payload does not match"):
        ReloadStateStore.open(path)
