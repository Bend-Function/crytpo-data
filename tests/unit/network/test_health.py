from __future__ import annotations

import sqlite3
import time
from decimal import Decimal

import pytest

from crypto_collector.network.models import Egress
from crypto_collector.network.state_store import EgressStateStore, StaleProbeError


def egress(egress_id: str, *, quota_group: str) -> Egress:
    return Egress.model_validate(
        {"id": egress_id, "type": "direct", "quota_group": quota_group}
    )


def test_ban_survives_worker_restart(tmp_path) -> None:
    path = tmp_path / "okx-network.sqlite"
    store = EgressStateStore.open(path)
    store.record_ban(
        exchange="okx",
        quota_group="nat-a",
        until_unix_ns=9_000,
        reason="429",
    )
    store.close()

    reopened = EgressStateStore.open(path)
    try:
        state = reopened.load_quota("okx", "nat-a")
        assert state.ban_until_unix_ns == 9_000
        assert state.last_reason == "429"
        assert reopened.journal_mode == "wal"
    finally:
        reopened.close()


def test_expired_restriction_requires_explicit_successful_probe(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    egresses = [egress("a", quota_group="nat"), egress("b", quota_group="other")]
    try:
        store.record_cooldown(
            exchange="okx",
            quota_group="nat",
            until_unix_ns=100,
            reason="rate_limit",
        )

        admitted = store.admit_health(
            exchange="okx",
            egresses=egresses,
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        quota_probe = admitted.quota_probe(exchange="okx", quota_group="nat")
        assert quota_probe is not None
        active = admitted.snapshot(now_monotonic_ns=1_000)
        expired = admitted.snapshot(now_monotonic_ns=1_001)

        assert ("okx", "a") in active.unavailable
        assert ("okx", "a") not in active.probe_eligible
        assert ("okx", "a") in expired.unavailable
        assert ("okx", "a") in expired.probe_eligible
        assert ("okx", "b") not in expired.unavailable

        store.record_quota_probe_success(
            admission=quota_probe,
            observed_monotonic_ns=1_001,
        )
        still_admitted = admitted.snapshot(now_monotonic_ns=2_000)
        recovered = store.admit_health(
            exchange="okx",
            egresses=egresses,
            now_unix_ns=101,
            now_monotonic_ns=2_000,
        ).snapshot(now_monotonic_ns=2_000)
        assert ("okx", "a") in still_admitted.unavailable
        assert ("okx", "a") not in recovered.unavailable
        assert ("okx", "a") not in recovered.probe_eligible
    finally:
        store.close()


def test_stale_quota_update_cannot_shorten_existing_restriction(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=200, reason="first"
        )
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="stale"
        )

        assert store.load_quota("okx", "nat").ban_until_unix_ns == 200
    finally:
        store.close()


def test_zero_length_restriction_still_requires_probe(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    candidate = egress("a", quota_group="nat")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=0, reason="manual"
        )

        snapshot = store.admit_health(
            exchange="okx",
            egresses=[candidate],
            now_unix_ns=0,
            now_monotonic_ns=10,
        ).snapshot(now_monotonic_ns=10)

        assert ("okx", "a") in snapshot.unavailable
        assert ("okx", "a") in snapshot.probe_eligible
    finally:
        store.close()


def test_transport_failure_persists_until_probe_success(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    first = EgressStateStore.open(path)
    first.record_transport_failure(
        exchange="okx", egress_id="proxy-a", reason="connect_error"
    )
    first.close()

    second = EgressStateStore.open(path)
    try:
        failed = second.load_egress("okx", "proxy-a")
        assert failed.consecutive_transport_failures == 1
        admitted = second.admit_health(
            exchange="okx",
            egresses=[egress("proxy-a", quota_group="nat-a")],
            now_unix_ns=1_000,
            now_monotonic_ns=10_000,
        )
        snapshot = admitted.snapshot(now_monotonic_ns=10_000)
        assert ("okx", "proxy-a") in snapshot.unavailable
        assert ("okx", "proxy-a") in snapshot.probe_eligible

        transport_probe = admitted.transport_probe(exchange="okx", egress_id="proxy-a")
        assert transport_probe is not None
        second.record_transport_probe_success(
            admission=transport_probe,
            observed_monotonic_ns=10_000,
            observed_unix_ns=1_001,
            latency_ns=12,
        )
        healthy = second.load_egress("okx", "proxy-a")
        assert healthy.consecutive_transport_failures == 0
        assert healthy.last_success_unix_ns == 1_001
        assert healthy.last_latency_ns == 12
    finally:
        second.close()


def test_transport_cooldown_survives_restart_and_blocks_early_probe(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    first = EgressStateStore.open(path)
    first.record_transport_failure(
        exchange="okx",
        egress_id="proxy-a",
        reason="connect_error",
        cooldown_until_unix_ns=500,
    )
    first.close()

    second = EgressStateStore.open(path)
    candidate = egress("proxy-a", quota_group="nat-a")
    try:
        admitted = second.admit_health(
            exchange="okx",
            egresses=[candidate],
            now_unix_ns=499,
            now_monotonic_ns=2_000,
        )
        active = admitted.snapshot(now_monotonic_ns=2_000)
        expired = admitted.snapshot(now_monotonic_ns=2_001)
        transport_probe = admitted.transport_probe(exchange="okx", egress_id="proxy-a")
        assert transport_probe is not None

        assert second.load_egress("okx", "proxy-a").cooldown_until_unix_ns == 500
        assert ("okx", "proxy-a") in active.unavailable
        assert ("okx", "proxy-a") not in active.probe_eligible
        assert ("okx", "proxy-a") in expired.probe_eligible
        with pytest.raises(ValueError, match="active transport cooldown"):
            second.record_transport_probe_success(
                admission=transport_probe,
                observed_monotonic_ns=2_000,
                observed_unix_ns=499,
                latency_ns=1,
            )
    finally:
        second.close()


def test_stale_quota_probe_cannot_clear_newer_restriction(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    probe_store = EgressStateStore.open(path)
    update_store = EgressStateStore.open(path)
    try:
        probe_store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="first"
        )
        admitted = probe_store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=100,
            now_monotonic_ns=1_000,
        )
        quota_probe = admitted.quota_probe(exchange="okx", quota_group="nat")
        assert quota_probe is not None
        update_store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=200, reason="newer"
        )

        with pytest.raises(StaleProbeError, match="quota probe"):
            probe_store.record_quota_probe_success(
                admission=quota_probe,
                observed_monotonic_ns=1_000,
            )

        current = probe_store.load_quota("okx", "nat")
        assert current.ban_until_unix_ns == 200
        assert current.last_reason == "newer"
    finally:
        probe_store.close()
        update_store.close()


def test_stale_transport_probe_cannot_clear_newer_failure(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    probe_store = EgressStateStore.open(path)
    update_store = EgressStateStore.open(path)
    try:
        probe_store.record_transport_failure(
            exchange="okx", egress_id="a", reason="first"
        )
        admitted = probe_store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=1,
            now_monotonic_ns=1,
        )
        transport_probe = admitted.transport_probe(exchange="okx", egress_id="a")
        assert transport_probe is not None
        update_store.record_transport_failure(
            exchange="okx", egress_id="a", reason="newer"
        )

        with pytest.raises(StaleProbeError, match="transport probe"):
            probe_store.record_transport_probe_success(
                admission=transport_probe,
                observed_monotonic_ns=1,
                observed_unix_ns=1,
                latency_ns=1,
            )

        current = probe_store.load_egress("okx", "a")
        assert current.consecutive_transport_failures == 2
        assert current.last_reason == "newer"
    finally:
        probe_store.close()
        update_store.close()


def test_quota_multiplier_round_trips_as_decimal_text(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.set_rate_multiplier(
            exchange="binance", quota_group="nat", multiplier=Decimal("0.125")
        )
        assert store.load_quota("binance", "nat").current_rate_multiplier == Decimal(
            "0.125"
        )
    finally:
        store.close()


def test_quota_multiplier_preserves_more_than_context_precision(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    multiplier = Decimal("0.123456789012345678901234567890123456789")
    try:
        store.set_rate_multiplier(
            exchange="binance", quota_group="nat", multiplier=multiplier
        )

        assert store.load_quota("binance", "nat").current_rate_multiplier == multiplier
        stored = store._connection.execute(
            "SELECT current_rate_multiplier FROM quota_state"
        ).fetchone()[0]
        assert stored == str(multiplier)
    finally:
        store.close()


@pytest.mark.parametrize(
    "value",
    [
        Decimal(0),
        Decimal("-0.1"),
        Decimal("1.01"),
        Decimal("NaN"),
        Decimal("Infinity"),
        Decimal("-Infinity"),
    ],
)
def test_quota_multiplier_must_be_in_open_zero_closed_one(tmp_path, value) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        with pytest.raises(ValueError, match="multiplier"):
            store.set_rate_multiplier(
                exchange="binance", quota_group="nat", multiplier=value
            )
    finally:
        store.close()


@pytest.mark.parametrize("value", [1, True])
def test_quota_multiplier_requires_decimal_input(tmp_path, value) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        with pytest.raises(TypeError, match="Decimal"):
            store.set_rate_multiplier(
                exchange="binance", quota_group="nat", multiplier=value
            )
    finally:
        store.close()


def test_negative_persisted_timestamps_are_rejected(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        with pytest.raises(ValueError, match="until_unix_ns"):
            store.record_ban(
                exchange="okx", quota_group="nat", until_unix_ns=-1, reason="429"
            )
    finally:
        store.close()


def test_open_rejects_unknown_schema_version(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 2")
    connection.close()

    with pytest.raises(
        RuntimeError, match="unsupported network state schema version 2"
    ):
        EgressStateStore.open(path)


def test_open_rechecks_schema_version_after_acquiring_initialization_lock(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "state.sqlite"
    real_connect = sqlite3.connect

    class RacingConnection:
        def __init__(self, connection) -> None:
            self._connection = connection
            self._raced = False

        def execute(self, sql, parameters=()):
            if sql.strip().upper() == "BEGIN IMMEDIATE" and not self._raced:
                self._raced = True
                writer = real_connect(path)
                try:
                    writer.execute("PRAGMA user_version = 2")
                    writer.commit()
                finally:
                    writer.close()
            return self._connection.execute(sql, parameters)

        def __getattr__(self, name):
            return getattr(self._connection, name)

    def racing_connect(database, *args, **kwargs):
        return RacingConnection(real_connect(database, *args, **kwargs))

    monkeypatch.setattr(sqlite3, "connect", racing_connect)
    opened = None
    try:
        with pytest.raises(
            RuntimeError, match="unsupported network state schema version 2"
        ):
            opened = EgressStateStore.open(path)
    finally:
        if opened is not None:
            opened.close()

    connection = real_connect(path)
    try:
        assert int(connection.execute("PRAGMA user_version").fetchone()[0]) == 2
    finally:
        connection.close()


def test_open_rejects_same_version_with_drifted_schema(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE quota_state (exchange TEXT NOT NULL)")
    connection.execute("PRAGMA user_version = 1")
    connection.close()

    with pytest.raises(
        RuntimeError, match="quota_state schema does not match version 1"
    ):
        EgressStateStore.open(path)


def test_open_rejects_version_one_database_missing_a_table_without_recreating_it(
    tmp_path,
) -> None:
    path = tmp_path / "state.sqlite"
    store = EgressStateStore.open(path)
    store.close()
    connection = sqlite3.connect(path)
    connection.execute("DROP TABLE egress_state")
    connection.close()

    with pytest.raises(
        RuntimeError, match="egress_state schema does not match version 1"
    ):
        EgressStateStore.open(path)

    connection = sqlite3.connect(path)
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }
        assert "egress_state" not in tables
    finally:
        connection.close()


def test_open_rejects_generated_or_hidden_schema_column(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    store = EgressStateStore.open(path)
    store.close()
    connection = sqlite3.connect(path)
    connection.execute(
        """
        ALTER TABLE quota_state
        ADD COLUMN generated_key TEXT
        GENERATED ALWAYS AS (exchange || '/' || quota_group) VIRTUAL
        """
    )
    connection.close()

    with pytest.raises(
        RuntimeError, match="quota_state schema does not match version 1"
    ):
        EgressStateStore.open(path)


def test_open_rejects_primary_key_collation_drift(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE quota_state (
          exchange TEXT COLLATE NOCASE NOT NULL,
          quota_group TEXT NOT NULL,
          ban_until_ns INTEGER NOT NULL,
          cooldown_until_ns INTEGER NOT NULL,
          current_rate_multiplier TEXT NOT NULL,
          last_reason TEXT,
          restriction_revision INTEGER NOT NULL,
          PRIMARY KEY (exchange, quota_group)
        );
        CREATE TABLE egress_state (
          exchange TEXT NOT NULL,
          egress_id TEXT NOT NULL,
          consecutive_transport_failures INTEGER NOT NULL,
          transport_cooldown_until_ns INTEGER NOT NULL,
          last_success_ns INTEGER,
          last_latency_ns INTEGER,
          last_reason TEXT,
          restriction_revision INTEGER NOT NULL,
          PRIMARY KEY (exchange, egress_id)
        );
        PRAGMA user_version = 1;
        """
    )
    connection.close()

    with pytest.raises(
        RuntimeError, match="quota_state schema does not match version 1"
    ):
        EgressStateStore.open(path)


def test_failed_version_zero_initialization_rolls_back_new_tables(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE quota_state (exchange TEXT NOT NULL)")
    connection.close()

    with pytest.raises(
        RuntimeError, match="quota_state schema does not match version 1"
    ):
        EgressStateStore.open(path)

    connection = sqlite3.connect(path)
    try:
        tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        assert tables == {"quota_state"}
        assert version == 0
    finally:
        connection.close()


def test_open_rejects_same_columns_without_primary_key_constraints(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE quota_state (
          exchange TEXT NOT NULL,
          quota_group TEXT NOT NULL,
          ban_until_ns INTEGER NOT NULL,
          cooldown_until_ns INTEGER NOT NULL,
          current_rate_multiplier TEXT NOT NULL,
          last_reason TEXT,
          restriction_revision INTEGER NOT NULL
        );
        CREATE TABLE egress_state (
          exchange TEXT NOT NULL,
          egress_id TEXT NOT NULL,
          consecutive_transport_failures INTEGER NOT NULL,
          transport_cooldown_until_ns INTEGER NOT NULL,
          last_success_ns INTEGER,
          last_latency_ns INTEGER,
          last_reason TEXT,
          restriction_revision INTEGER NOT NULL
        );
        PRAGMA user_version = 1;
        """
    )
    connection.close()

    with pytest.raises(
        RuntimeError, match="quota_state schema does not match version 1"
    ):
        EgressStateStore.open(path)


def test_health_admission_is_one_transaction_for_shared_quota_group(
    tmp_path, monkeypatch
) -> None:
    path = tmp_path / "state.sqlite"
    reader = EgressStateStore.open(path)
    writer = EgressStateStore.open(path)
    candidates = [
        egress("a", quota_group="shared-nat"),
        egress("b", quota_group="shared-nat"),
    ]
    original_load = reader.load_quota
    calls = 0

    def interleaved_load(exchange: str, quota_group: str):
        nonlocal calls
        state = original_load(exchange, quota_group)
        calls += 1
        if calls == 1:
            writer.record_ban(
                exchange="okx",
                quota_group="shared-nat",
                until_unix_ns=100,
                reason="concurrent",
            )
        return state

    monkeypatch.setattr(reader, "load_quota", interleaved_load)
    try:
        snapshot = reader.admit_health(
            exchange="okx",
            egresses=candidates,
            now_unix_ns=1,
            now_monotonic_ns=1,
        ).snapshot(now_monotonic_ns=1)

        assert snapshot.unavailable == frozenset()
        assert writer.load_quota("okx", "shared-nat").last_reason == "concurrent"
        assert reader._connection.in_transaction is False
    finally:
        reader.close()
        writer.close()


def test_admitted_health_ignores_wall_clock_jumps_after_single_conversion(
    tmp_path, monkeypatch
) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    candidate = egress("a", quota_group="nat")
    try:
        store.record_cooldown(
            exchange="okx",
            quota_group="nat",
            until_unix_ns=1_100,
            reason="rate_limit",
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[candidate],
            now_unix_ns=1_000,
            now_monotonic_ns=5_000,
        )

        monkeypatch.setattr(time, "time_ns", lambda: 0)
        before_backward_jump = admitted.snapshot(now_monotonic_ns=5_099)
        monkeypatch.setattr(time, "time_ns", lambda: 10**20)
        before_forward_jump = admitted.snapshot(now_monotonic_ns=5_099)
        at_deadline = admitted.snapshot(now_monotonic_ns=5_100)

        assert not before_backward_jump.may_probe("okx", "a")
        assert not before_forward_jump.may_probe("okx", "a")
        assert at_deadline.may_probe("okx", "a")
        assert not at_deadline.is_available("okx", "a")
    finally:
        store.close()


def test_health_admission_rejects_boolean_clock_values(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        with pytest.raises(ValueError, match="now_unix_ns"):
            store.admit_health(
                exchange="okx",
                egresses=[],
                now_unix_ns=True,
                now_monotonic_ns=1,
            )

        admitted = store.admit_health(
            exchange="okx",
            egresses=[],
            now_unix_ns=1,
            now_monotonic_ns=1,
        )
        with pytest.raises(ValueError, match="now_monotonic_ns"):
            admitted.snapshot(now_monotonic_ns=True)
    finally:
        store.close()


def test_task_two_api_is_exported_from_network_package(tmp_path) -> None:
    from crypto_collector import network

    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        admitted = store.admit_health(
            exchange="okx",
            egresses=[],
            now_unix_ns=1,
            now_monotonic_ns=1,
        )
        snapshot = admitted.snapshot(now_monotonic_ns=1)

        expected_exports = {
            "AdmittedHealth",
            "EgressShard",
            "EgressStateStore",
            "HealthSnapshot",
            "NoAvailableEgressError",
            "QuotaProbeAdmission",
            "StaleProbeError",
            "StickyAssignment",
            "TransportProbeAdmission",
            "assign_instruments",
            "choose_egress",
            "pack_egress_shards",
        }
        assert expected_exports <= set(network.__all__)
        assert network.AdmittedHealth is type(admitted)
        assert network.HealthSnapshot is type(snapshot)
    finally:
        store.close()


def test_quota_probe_uses_revision_captured_before_connect(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    candidate = egress("a", quota_group="nat")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="first"
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[candidate],
            now_unix_ns=100,
            now_monotonic_ns=1_000,
        )
        probe = admitted.quota_probe(exchange="okx", quota_group="nat")
        assert probe is not None

        with pytest.raises(ValueError, match="observed_monotonic_ns"):
            store.record_quota_probe_success(
                admission=probe,
                observed_monotonic_ns=True,
            )

        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="newer"
        )

        with pytest.raises(StaleProbeError, match="quota probe"):
            store.record_quota_probe_success(
                admission=probe,
                observed_monotonic_ns=1_000,
            )
    finally:
        store.close()


def test_probe_admission_cannot_be_replayed_through_another_store(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    admitting_store = EgressStateStore.open(path)
    other_store = EgressStateStore.open(path)
    try:
        admitting_store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=0, reason="manual"
        )
        admitted = admitting_store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=0,
            now_monotonic_ns=1,
        )
        probe = admitted.quota_probe(exchange="okx", quota_group="nat")
        assert probe is not None

        with pytest.raises(ValueError, match="different store"):
            other_store.record_quota_probe_success(
                admission=probe,
                observed_monotonic_ns=1,
            )
    finally:
        admitting_store.close()
        other_store.close()


def test_probe_success_uses_admitted_monotonic_deadline_after_wall_clock_rewind(
    tmp_path,
) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    candidate = egress("a", quota_group="nat")
    try:
        store.record_transport_failure(
            exchange="okx",
            egress_id="a",
            reason="connect_error",
            cooldown_until_unix_ns=1_100,
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[candidate],
            now_unix_ns=1_000,
            now_monotonic_ns=5_000,
        )
        probe = admitted.transport_probe(exchange="okx", egress_id="a")
        assert probe is not None

        store.record_transport_probe_success(
            admission=probe,
            observed_monotonic_ns=5_100,
            observed_unix_ns=0,
            latency_ns=12,
        )

        recovered = store.load_egress("okx", "a")
        assert recovered.consecutive_transport_failures == 0
        assert recovered.last_success_unix_ns == 0
    finally:
        store.close()
