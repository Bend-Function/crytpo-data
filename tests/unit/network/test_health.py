from __future__ import annotations

import gc
import multiprocessing
import sqlite3
import time
from dataclasses import replace
from decimal import Decimal
from typing import cast
from weakref import ref

import pytest

import crypto_collector.network.state_store as state_store_module
from crypto_collector.network.health import (
    QuotaProbeAdmission,
    TransportProbeAdmission,
    _AdmissionMint,
)
from crypto_collector.network.models import Egress
from crypto_collector.network.state_store import EgressStateStore, StaleProbeError


class _EqualString(str):
    def __eq__(self, other: object) -> bool:
        del other
        return True

    __hash__ = str.__hash__


class _FakeMint:
    def matches(self, _claims: tuple[object, ...]) -> bool:
        return True

    def belongs_to(self, _store_identity: object) -> bool:
        return True


class _EqualTuple(tuple[object, ...]):
    def __eq__(self, other: object) -> bool:
        del other
        return True

    __hash__ = tuple.__hash__


class _ForgedQuotaProbeAdmission(QuotaProbeAdmission):
    def __post_init__(self) -> None:
        pass

    def _belongs_to(self, _store_identity: object) -> bool:
        return True


class _ForgedTransportProbeAdmission(TransportProbeAdmission):
    def __post_init__(self) -> None:
        pass

    def _belongs_to(self, _store_identity: object) -> bool:
        return True


def egress(egress_id: str, *, quota_group: str) -> Egress:
    return Egress.model_validate(
        {"id": egress_id, "type": "direct", "quota_group": quota_group}
    )


class _WalBarrierConnection:
    def __init__(self, connection, barrier) -> None:
        self._connection = connection
        self._barrier = barrier
        self._waited_for_wal = False

    def execute(self, sql, parameters=()):
        if (
            sql.strip().upper() == "PRAGMA JOURNAL_MODE = WAL"
            and not self._waited_for_wal
        ):
            self._waited_for_wal = True
            self._barrier.wait(timeout=30)
        return self._connection.execute(sql, parameters)

    def __getattr__(self, name):
        return getattr(self._connection, name)


def _concurrent_open_worker(
    root: str,
    rounds: int,
    barrier,
    results,
) -> None:
    failures: list[tuple[int, str, str]] = []
    real_connect = sqlite3.connect

    def barrier_connect(database, *args, **kwargs):
        return _WalBarrierConnection(
            real_connect(database, *args, **kwargs),
            barrier,
        )

    state_store_module.sqlite3.connect = barrier_connect
    try:
        for round_number in range(rounds):
            store = None
            try:
                store = EgressStateStore.open(
                    f"{root}/concurrent-{round_number}.sqlite"
                )
            except BaseException as error:  # noqa: BLE001 - returned to parent
                failures.append((round_number, type(error).__name__, str(error)))
            finally:
                if store is not None:
                    store.close()
    finally:
        state_store_module.sqlite3.connect = real_connect
        results.put(failures)


_QUOTA_TABLE_DDL = """CREATE TABLE quota_state (
  exchange TEXT NOT NULL,
  quota_group TEXT NOT NULL,
  ban_until_ns INTEGER NOT NULL,
  cooldown_until_ns INTEGER NOT NULL,
  current_rate_multiplier TEXT NOT NULL,
  last_reason TEXT,
  restriction_revision INTEGER NOT NULL,
  PRIMARY KEY (exchange, quota_group)
)"""
_EGRESS_TABLE_DDL = """CREATE TABLE egress_state (
  exchange TEXT NOT NULL,
  egress_id TEXT NOT NULL,
  consecutive_transport_failures INTEGER NOT NULL,
  transport_cooldown_until_ns INTEGER NOT NULL,
  last_success_ns INTEGER,
  last_latency_ns INTEGER,
  last_reason TEXT,
  restriction_revision INTEGER NOT NULL,
  PRIMARY KEY (exchange, egress_id)
)"""


def _create_version_one_database(
    path,
    *,
    quota_ddl: str = _QUOTA_TABLE_DDL,
    egress_ddl: str = _EGRESS_TABLE_DDL,
    extra_ddl: str = "",
) -> None:
    connection = sqlite3.connect(path)
    try:
        connection.executescript(
            f"{quota_ddl};\n{egress_ddl};\n{extra_ddl}\nPRAGMA user_version = 1;"
        )
    finally:
        connection.close()


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


def test_concurrent_first_open_is_retry_safe_across_processes(tmp_path) -> None:
    context = multiprocessing.get_context("spawn")
    process_count = 8
    rounds = 8
    barrier = context.Barrier(process_count)
    results = context.Queue()
    workers = [
        context.Process(
            target=_concurrent_open_worker,
            args=(str(tmp_path), rounds, barrier, results),
        )
        for _ in range(process_count)
    ]

    try:
        for worker in workers:
            worker.start()
        join_deadline = time.monotonic() + 60
        for worker in workers:
            worker.join(timeout=max(0.0, join_deadline - time.monotonic()))

        exit_codes = [worker.exitcode for worker in workers]
        assert exit_codes == [0] * process_count
        failures = [results.get(timeout=5) for _worker in workers]
        assert failures == [[] for _worker in workers]
    finally:
        for worker in workers:
            if worker.is_alive():
                worker.terminate()
        for worker in workers:
            worker.join(timeout=5)
        results.close()
        results.join_thread()

    for round_number in range(rounds):
        with EgressStateStore.open(
            tmp_path / f"concurrent-{round_number}.sqlite"
        ) as store:
            assert store.journal_mode == "wal"
            assert (
                int(store._connection.execute("PRAGMA user_version").fetchone()[0]) == 1
            )
            tables = {
                str(row[0])
                for row in store._connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'table'"
                )
            }
            assert tables == {"quota_state", "egress_state"}


@pytest.mark.parametrize(
    "error_code",
    [sqlite3.SQLITE_BUSY_RECOVERY, sqlite3.SQLITE_LOCKED_SHAREDCACHE],
    ids=["busy-extended", "locked-extended"],
)
def test_schema_initialization_retries_sqlite_lock_contention(
    monkeypatch, error_code: int
) -> None:
    attempts = 0

    def initialize(_connection) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            error = sqlite3.OperationalError("database is locked")
            error.sqlite_errorcode = error_code
            raise error

    class Connection:
        in_transaction = False

    monkeypatch.setattr(state_store_module, "_initialize_schema", initialize)
    monkeypatch.setattr(state_store_module.time, "sleep", lambda _delay: None)

    state_store_module._initialize_schema_with_retry(
        cast(sqlite3.Connection, Connection())
    )

    assert attempts == 2


def test_schema_initialization_does_not_retry_other_sqlite_errors(
    monkeypatch,
) -> None:
    attempts = 0

    def initialize(_connection) -> None:
        nonlocal attempts
        attempts += 1
        error = sqlite3.OperationalError("disk input/output error")
        error.sqlite_errorcode = sqlite3.SQLITE_IOERR
        raise error

    class Connection:
        in_transaction = False

    monkeypatch.setattr(state_store_module, "_initialize_schema", initialize)

    with pytest.raises(sqlite3.OperationalError, match="input/output"):
        state_store_module._initialize_schema_with_retry(
            cast(sqlite3.Connection, Connection())
        )

    assert attempts == 1


def test_schema_initialization_lock_retry_has_one_total_deadline(monkeypatch) -> None:
    attempts = 0
    monotonic_values = iter([0.0, 0.0, 4.9, 5.1])

    def initialize(_connection) -> None:
        nonlocal attempts
        attempts += 1
        error = sqlite3.OperationalError("database is locked")
        error.sqlite_errorcode = sqlite3.SQLITE_BUSY
        raise error

    class Connection:
        in_transaction = False

    monkeypatch.setattr(state_store_module, "_initialize_schema", initialize)
    monkeypatch.setattr(
        state_store_module.time,
        "monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr(state_store_module.time, "sleep", lambda _delay: None)

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        state_store_module._initialize_schema_with_retry(
            cast(sqlite3.Connection, Connection())
        )

    assert attempts == 2


def test_schema_initialization_does_not_start_attempt_after_deadline(
    monkeypatch,
) -> None:
    attempts = 0
    monotonic_values = iter([0.0, 0.0, 5.1])

    def initialize(_connection) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            error = sqlite3.OperationalError("database is locked")
            error.sqlite_errorcode = sqlite3.SQLITE_BUSY
            raise error

    class Connection:
        in_transaction = False

    monkeypatch.setattr(state_store_module, "_initialize_schema", initialize)
    monkeypatch.setattr(
        state_store_module.time,
        "monotonic",
        lambda: next(monotonic_values),
    )
    monkeypatch.setattr(state_store_module.time, "sleep", lambda _delay: None)

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        state_store_module._initialize_schema_with_retry(
            cast(sqlite3.Connection, Connection())
        )

    assert attempts == 1


def test_open_closes_connection_when_schema_initialization_exhausts(
    tmp_path, monkeypatch
) -> None:
    class Connection:
        closed = False

        def execute(self, _sql):
            return None

        def close(self) -> None:
            self.closed = True

    connection = Connection()
    contention = sqlite3.OperationalError("database is locked")
    contention.sqlite_errorcode = sqlite3.SQLITE_BUSY

    def fail_initialization(_connection) -> None:
        raise contention

    monkeypatch.setattr(
        state_store_module.sqlite3,
        "connect",
        lambda *_args, **_kwargs: connection,
    )
    monkeypatch.setattr(
        state_store_module,
        "_initialize_schema_with_retry",
        fail_initialization,
    )

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        EgressStateStore.open(tmp_path / "state.sqlite")

    assert connection.closed


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


class _MisleadingDecimal(Decimal):
    def is_finite(self) -> bool:
        return True

    def __le__(self, other: object) -> bool:
        del other
        return True

    def __str__(self) -> str:
        return "NaN"


@pytest.mark.parametrize("value", [1, True, _MisleadingDecimal("2")])
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


@pytest.mark.parametrize(
    "quota_ddl",
    [
        pytest.param(
            _QUOTA_TABLE_DDL.replace(
                "current_rate_multiplier TEXT NOT NULL",
                "current_rate_multiplier TEXT COLLATE NOCASE NOT NULL",
            ),
            id="non-key-collation",
        ),
        pytest.param(
            _QUOTA_TABLE_DDL.replace(
                "restriction_revision INTEGER NOT NULL",
                "restriction_revision INTEGER NOT NULL CHECK (restriction_revision >= 0)",
            ),
            id="check-constraint",
        ),
        pytest.param(
            f"{_QUOTA_TABLE_DDL} STRICT",
            id="strict-table",
            marks=pytest.mark.skipif(
                sqlite3.sqlite_version_info < (3, 37),
                reason="STRICT tables require SQLite 3.37 or newer",
            ),
        ),
        pytest.param(
            f"{_QUOTA_TABLE_DDL} WITHOUT ROWID",
            id="without-rowid",
        ),
    ],
)
def test_open_rejects_noncanonical_table_ddl(tmp_path, quota_ddl: str) -> None:
    path = tmp_path / "state.sqlite"
    _create_version_one_database(path, quota_ddl=quota_ddl)

    with pytest.raises(RuntimeError, match="schema objects do not match version 1"):
        EgressStateStore.open(path)


def test_open_rejects_unexpected_trigger_on_owned_table(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    _create_version_one_database(
        path,
        extra_ddl="""
        CREATE TRIGGER rewrite_quota_revision
        AFTER UPDATE ON quota_state
        BEGIN
          UPDATE quota_state
             SET restriction_revision = 0
           WHERE exchange = NEW.exchange
             AND quota_group = NEW.quota_group;
        END;
        """,
    )

    with pytest.raises(RuntimeError, match="schema objects do not match version 1"):
        EgressStateStore.open(path)


@pytest.mark.parametrize(
    "extra_ddl",
    [
        "CREATE TABLE unrelated_state (value TEXT);",
        "CREATE TABLE sqliteEvil (value TEXT);",
        "CREATE VIEW quota_state_view AS SELECT * FROM quota_state;",
    ],
    ids=["table", "sqlite-prefix-lookalike", "view"],
)
def test_open_rejects_unexpected_application_schema_object(
    tmp_path, extra_ddl: str
) -> None:
    path = tmp_path / "state.sqlite"
    _create_version_one_database(path, extra_ddl=extra_ddl)

    with pytest.raises(RuntimeError, match="schema objects do not match version 1"):
        EgressStateStore.open(path)


def test_open_allows_sqlite_internal_analyze_statistics(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    with EgressStateStore.open(path):
        pass
    connection = sqlite3.connect(path)
    try:
        connection.execute("ANALYZE")
        connection.commit()
        internal_tables = {
            str(row[0])
            for row in connection.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table'"
            )
        }
        assert "sqlite_stat1" in internal_tables
    finally:
        connection.close()

    with EgressStateStore.open(path) as reopened:
        assert reopened.journal_mode == "wal"


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


def test_probe_admission_registry_releases_unreferenced_tokens(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=0, reason="manual"
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=0,
            now_monotonic_ns=1,
        )
        probe = admitted.quota_probe(exchange="okx", quota_group="nat")
        assert probe is not None
        probe_reference = ref(probe)
        registry = store._EgressStateStore__issued_probe_admissions  # type: ignore[attr-defined]
        assert len(registry) == 1

        del probe, admitted
        gc.collect()

        assert probe_reference() is None
        assert registry == {}
    finally:
        store.close()


def test_quota_probe_cannot_be_forged_from_readable_store_identity(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=999, reason="429"
        )
        forged = QuotaProbeAdmission._minted(
            exchange="okx",
            quota_group="nat",
            restriction_revision=1,
            probe_after_monotonic_ns=0,
            store_identity=store._admission_identity,
        )

        with pytest.raises(ValueError, match="issued by admit_health"):
            store.record_quota_probe_success(
                admission=forged,
                observed_monotonic_ns=0,
            )

        state = store.load_quota("okx", "nat")
        assert state.ban_until_unix_ns == 999
        assert state.restriction_revision == 1
    finally:
        store.close()


def test_transport_probe_cannot_be_forged_from_readable_store_identity(
    tmp_path,
) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_transport_failure(
            exchange="okx",
            egress_id="a",
            reason="connect_error",
            cooldown_until_unix_ns=999,
        )
        forged = TransportProbeAdmission._minted(
            exchange="okx",
            egress_id="a",
            restriction_revision=1,
            probe_after_monotonic_ns=0,
            store_identity=store._admission_identity,
        )

        with pytest.raises(ValueError, match="issued by admit_health"):
            store.record_transport_probe_success(
                admission=forged,
                observed_monotonic_ns=0,
                observed_unix_ns=1,
                latency_ns=1,
            )

        state = store.load_egress("okx", "a")
        assert state.cooldown_until_unix_ns == 999
        assert state.restriction_revision == 1
    finally:
        store.close()


def test_registered_probe_cannot_change_claims_with_reflective_mutation(
    tmp_path,
) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        for quota_group in ("original", "target"):
            store.record_ban(
                exchange="okx",
                quota_group=quota_group,
                until_unix_ns=0,
                reason="429",
            )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="original")],
            now_unix_ns=0,
            now_monotonic_ns=0,
        )
        probe = admitted.quota_probe(exchange="okx", quota_group="original")
        assert probe is not None
        object.__setattr__(probe, "quota_group", "target")
        object.__setattr__(
            probe,
            "_mint",
            _AdmissionMint(store._admission_identity, probe._claims()),
        )

        with pytest.raises(ValueError, match="issued by admit_health"):
            store.record_quota_probe_success(
                admission=probe,
                observed_monotonic_ns=0,
            )

        target = store.load_quota("okx", "target")
        assert target.last_reason == "429"
        assert target.restriction_revision == 1
    finally:
        store.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"quota_group": "other"},
        {"restriction_revision": 2},
        {"probe_after_monotonic_ns": 0},
    ],
    ids=["key", "revision", "deadline"],
)
def test_quota_probe_admission_rejects_replaced_claims(tmp_path, changes) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="429"
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        probe = admitted.quota_probe(exchange="okx", quota_group="nat")
        assert probe is not None

        with pytest.raises(ValueError, match="minted claims"):
            replace(probe, **changes)
    finally:
        store.close()


def test_quota_probe_admission_rejects_equal_string_subclass_claim(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="429"
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        probe = admitted.quota_probe(exchange="okx", quota_group="nat")
        assert probe is not None

        with pytest.raises(ValueError, match="strings"):
            replace(probe, exchange=_EqualString("binance"))
    finally:
        store.close()


def test_quota_probe_admission_rejects_duck_typed_mint(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="429"
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        probe = admitted.quota_probe(exchange="okx", quota_group="nat")
        assert probe is not None

        with pytest.raises(ValueError, match="mint"):
            replace(probe, _mint=_FakeMint())  # type: ignore[arg-type]
    finally:
        store.close()


def test_quota_probe_success_rejects_admission_subclass(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="binance",
            quota_group="nat",
            until_unix_ns=0,
            reason="429",
        )
        forged = _ForgedQuotaProbeAdmission(
            exchange="binance",
            quota_group="nat",
            restriction_revision=1,
            probe_after_monotonic_ns=0,
            _mint=object(),  # type: ignore[arg-type]
        )

        with pytest.raises(TypeError, match="QuotaProbeAdmission"):
            store.record_quota_probe_success(
                admission=forged,
                observed_monotonic_ns=0,
            )

        assert store.load_quota("binance", "nat").last_reason == "429"
    finally:
        store.close()


@pytest.mark.parametrize(
    "changes",
    [
        {"egress_id": "other"},
        {"restriction_revision": 2},
        {"probe_after_monotonic_ns": 0},
    ],
    ids=["key", "revision", "deadline"],
)
def test_transport_probe_admission_rejects_replaced_claims(tmp_path, changes) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_transport_failure(
            exchange="okx",
            egress_id="a",
            reason="connect_error",
            cooldown_until_unix_ns=100,
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        probe = admitted.transport_probe(exchange="okx", egress_id="a")
        assert probe is not None

        with pytest.raises(ValueError, match="minted claims"):
            replace(probe, **changes)
    finally:
        store.close()


def test_transport_probe_admission_rejects_equal_string_subclass_claim(
    tmp_path,
) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_transport_failure(
            exchange="okx",
            egress_id="a",
            reason="connect_error",
            cooldown_until_unix_ns=100,
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        probe = admitted.transport_probe(exchange="okx", egress_id="a")
        assert probe is not None

        with pytest.raises(ValueError, match="strings"):
            replace(probe, egress_id=_EqualString("other"))
    finally:
        store.close()


def test_transport_probe_admission_rejects_duck_typed_mint(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_transport_failure(
            exchange="okx",
            egress_id="a",
            reason="connect_error",
            cooldown_until_unix_ns=100,
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        probe = admitted.transport_probe(exchange="okx", egress_id="a")
        assert probe is not None

        with pytest.raises(ValueError, match="mint"):
            replace(probe, _mint=_FakeMint())  # type: ignore[arg-type]
    finally:
        store.close()


def test_transport_probe_success_rejects_admission_subclass(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_transport_failure(
            exchange="binance",
            egress_id="a",
            reason="connect_error",
        )
        forged = _ForgedTransportProbeAdmission(
            exchange="binance",
            egress_id="a",
            restriction_revision=1,
            probe_after_monotonic_ns=0,
            _mint=object(),  # type: ignore[arg-type]
        )

        with pytest.raises(TypeError, match="TransportProbeAdmission"):
            store.record_transport_probe_success(
                admission=forged,
                observed_monotonic_ns=0,
                observed_unix_ns=1,
                latency_ns=1,
            )

        assert store.load_egress("binance", "a").last_reason == "connect_error"
    finally:
        store.close()


def test_admitted_health_rejects_replaced_deadline_claims(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="429"
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )

        with pytest.raises(ValueError, match="minted claims"):
            replace(
                admitted,
                probe_after_monotonic_ns=((("okx", "a"), 0),),
            )
    finally:
        store.close()


def test_admitted_health_rejects_cloned_quota_child_token(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="429"
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        child = admitted.quota_probe_admissions[0]

        with pytest.raises(ValueError, match="minted claims"):
            replace(admitted, quota_probe_admissions=(replace(child),))
    finally:
        store.close()


def test_admitted_health_rejects_cloned_transport_child_token(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_transport_failure(
            exchange="okx",
            egress_id="a",
            reason="connect_error",
            cooldown_until_unix_ns=100,
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        child = admitted.transport_probe_admissions[0]

        with pytest.raises(ValueError, match="minted claims"):
            replace(admitted, transport_probe_admissions=(replace(child),))
    finally:
        store.close()


def test_admitted_health_rejects_duck_typed_mint(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        admitted = store.admit_health(
            exchange="okx",
            egresses=[],
            now_unix_ns=1,
            now_monotonic_ns=1,
        )

        with pytest.raises(ValueError, match="mint"):
            replace(admitted, _mint=_FakeMint())  # type: ignore[arg-type]
    finally:
        store.close()


def test_admitted_health_rejects_equal_tuple_subclass_claims(tmp_path) -> None:
    store = EgressStateStore.open(tmp_path / "state.sqlite")
    try:
        store.record_ban(
            exchange="okx", quota_group="nat", until_unix_ns=100, reason="429"
        )
        admitted = store.admit_health(
            exchange="okx",
            egresses=[egress("a", quota_group="nat")],
            now_unix_ns=99,
            now_monotonic_ns=1_000,
        )
        forged_deadlines = _EqualTuple(((("binance", "b"), 0),))

        with pytest.raises(ValueError, match="minted claims"):
            replace(
                admitted,
                probe_after_monotonic_ns=forged_deadlines,  # type: ignore[arg-type]
            )
    finally:
        store.close()


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
