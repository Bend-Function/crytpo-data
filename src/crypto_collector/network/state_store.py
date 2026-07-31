from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from decimal import Decimal
from pathlib import Path
from types import TracebackType
from typing import Self

from crypto_collector.network.health import (
    AdmittedHealth,
    EgressHealthState,
    QuotaProbeAdmission,
    QuotaState,
    TransportProbeAdmission,
)
from crypto_collector.network.models import Egress

_SCHEMA_VERSION = 1


class StaleProbeError(RuntimeError):
    pass


_SCHEMA = (
    """
CREATE TABLE IF NOT EXISTS quota_state (
  exchange TEXT NOT NULL,
  quota_group TEXT NOT NULL,
  ban_until_ns INTEGER NOT NULL,
  cooldown_until_ns INTEGER NOT NULL,
  current_rate_multiplier TEXT NOT NULL,
  last_reason TEXT,
  restriction_revision INTEGER NOT NULL,
  PRIMARY KEY (exchange, quota_group)
)
""",
    """
CREATE TABLE IF NOT EXISTS egress_state (
  exchange TEXT NOT NULL,
  egress_id TEXT NOT NULL,
  consecutive_transport_failures INTEGER NOT NULL,
  transport_cooldown_until_ns INTEGER NOT NULL,
  last_success_ns INTEGER,
  last_latency_ns INTEGER,
  last_reason TEXT,
  restriction_revision INTEGER NOT NULL,
  PRIMARY KEY (exchange, egress_id)
)
""",
)
_EXPECTED_COLUMNS = {
    "quota_state": (
        ("exchange", "TEXT", 1, None, 1, 0),
        ("quota_group", "TEXT", 1, None, 2, 0),
        ("ban_until_ns", "INTEGER", 1, None, 0, 0),
        ("cooldown_until_ns", "INTEGER", 1, None, 0, 0),
        ("current_rate_multiplier", "TEXT", 1, None, 0, 0),
        ("last_reason", "TEXT", 0, None, 0, 0),
        ("restriction_revision", "INTEGER", 1, None, 0, 0),
    ),
    "egress_state": (
        ("exchange", "TEXT", 1, None, 1, 0),
        ("egress_id", "TEXT", 1, None, 2, 0),
        ("consecutive_transport_failures", "INTEGER", 1, None, 0, 0),
        ("transport_cooldown_until_ns", "INTEGER", 1, None, 0, 0),
        ("last_success_ns", "INTEGER", 0, None, 0, 0),
        ("last_latency_ns", "INTEGER", 0, None, 0, 0),
        ("last_reason", "TEXT", 0, None, 0, 0),
        ("restriction_revision", "INTEGER", 1, None, 0, 0),
    ),
}
_EXPECTED_PRIMARY_KEYS = {
    "quota_state": ("exchange", "quota_group"),
    "egress_state": ("exchange", "egress_id"),
}


def _nonempty(value: str, *, field: str) -> str:
    if not value:
        raise ValueError(f"{field} must be non-empty")
    return value


def _nonnegative(value: int, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _validate_schema(connection: sqlite3.Connection) -> None:
    for table, expected in _EXPECTED_COLUMNS.items():
        actual = tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                row[4],
                int(row[5]),
                int(row[6]),
            )
            for row in connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
        )
        indexes = connection.execute(f"PRAGMA index_list({table})").fetchall()
        has_primary_key_index = (
            len(indexes) == 1
            and int(indexes[0][2]) == 1
            and str(indexes[0][3]) == "pk"
            and int(indexes[0][4]) == 0
        )
        actual_primary_key: tuple[tuple[int, int, str, int, str, int], ...] = ()
        if has_primary_key_index:
            index_name = str(indexes[0][1]).replace('"', '""')
            actual_primary_key = tuple(
                (
                    int(row[0]),
                    int(row[1]),
                    str(row[2]),
                    int(row[3]),
                    str(row[4]).upper(),
                    int(row[5]),
                )
                for row in connection.execute(
                    f'PRAGMA index_xinfo("{index_name}")'
                ).fetchall()
                if int(row[5]) == 1
            )
        expected_primary_key = tuple(
            (position, position, column, 0, "BINARY", 1)
            for position, column in enumerate(_EXPECTED_PRIMARY_KEYS[table])
        )
        has_exact_primary_key = (
            has_primary_key_index and actual_primary_key == expected_primary_key
        )
        if actual != expected or not has_exact_primary_key:
            raise RuntimeError(
                f"{table} schema does not match version {_SCHEMA_VERSION}"
            )


class EgressStateStore:
    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        self._admission_identity = object()
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        self.journal_mode = str(mode[0]).casefold()

    @classmethod
    def open(cls, path: str | Path) -> Self:
        resolved = Path(path).expanduser().resolve(strict=False)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(resolved, timeout=5.0)
        try:
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA synchronous = FULL")
            mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
            if mode is None or str(mode[0]).casefold() != "wal":
                raise RuntimeError("network state store requires SQLite WAL mode")
            connection.execute("BEGIN IMMEDIATE")
            try:
                version = int(connection.execute("PRAGMA user_version").fetchone()[0])
                if version not in (0, _SCHEMA_VERSION):
                    raise RuntimeError(
                        f"unsupported network state schema version {version}"
                    )
                if version == 0:
                    for statement in _SCHEMA:
                        connection.execute(statement)
                _validate_schema(connection)
                if version == 0:
                    connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()
        except BaseException:
            connection.close()
            raise
        return cls(resolved, connection)

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc, traceback
        self.close()

    def close(self) -> None:
        self._connection.close()

    def load_quota(self, exchange: str, quota_group: str) -> QuotaState:
        exchange = _nonempty(exchange, field="exchange")
        quota_group = _nonempty(quota_group, field="quota_group")
        row = self._connection.execute(
            """
            SELECT ban_until_ns, cooldown_until_ns, current_rate_multiplier,
                   last_reason, restriction_revision
              FROM quota_state
             WHERE exchange = ? AND quota_group = ?
            """,
            (exchange, quota_group),
        ).fetchone()
        if row is None:
            return QuotaState(exchange=exchange, quota_group=quota_group)
        return QuotaState(
            exchange=exchange,
            quota_group=quota_group,
            ban_until_unix_ns=int(row[0]),
            cooldown_until_unix_ns=int(row[1]),
            current_rate_multiplier=Decimal(str(row[2])),
            last_reason=None if row[3] is None else str(row[3]),
            restriction_revision=int(row[4]),
        )

    def load_egress(self, exchange: str, egress_id: str) -> EgressHealthState:
        exchange = _nonempty(exchange, field="exchange")
        egress_id = _nonempty(egress_id, field="egress_id")
        row = self._connection.execute(
            """
            SELECT consecutive_transport_failures, transport_cooldown_until_ns,
                   last_success_ns, last_latency_ns, last_reason,
                   restriction_revision
              FROM egress_state
             WHERE exchange = ? AND egress_id = ?
            """,
            (exchange, egress_id),
        ).fetchone()
        if row is None:
            return EgressHealthState(exchange=exchange, egress_id=egress_id)
        return EgressHealthState(
            exchange=exchange,
            egress_id=egress_id,
            consecutive_transport_failures=int(row[0]),
            cooldown_until_unix_ns=int(row[1]),
            last_success_unix_ns=None if row[2] is None else int(row[2]),
            last_latency_ns=None if row[3] is None else int(row[3]),
            last_reason=None if row[4] is None else str(row[4]),
            restriction_revision=int(row[5]),
        )

    def record_ban(
        self,
        *,
        exchange: str,
        quota_group: str,
        until_unix_ns: int,
        reason: str,
    ) -> None:
        self._record_quota_restriction(
            exchange=exchange,
            quota_group=quota_group,
            column="ban_until_ns",
            until_unix_ns=until_unix_ns,
            reason=reason,
        )

    def record_cooldown(
        self,
        *,
        exchange: str,
        quota_group: str,
        until_unix_ns: int,
        reason: str,
    ) -> None:
        self._record_quota_restriction(
            exchange=exchange,
            quota_group=quota_group,
            column="cooldown_until_ns",
            until_unix_ns=until_unix_ns,
            reason=reason,
        )

    def _record_quota_restriction(
        self,
        *,
        exchange: str,
        quota_group: str,
        column: str,
        until_unix_ns: int,
        reason: str,
    ) -> None:
        exchange = _nonempty(exchange, field="exchange")
        quota_group = _nonempty(quota_group, field="quota_group")
        until_unix_ns = _nonnegative(until_unix_ns, field="until_unix_ns")
        reason = _nonempty(reason, field="reason")
        if column not in {"ban_until_ns", "cooldown_until_ns"}:
            raise ValueError("invalid quota restriction column")
        initial_ban = until_unix_ns if column == "ban_until_ns" else 0
        initial_cooldown = until_unix_ns if column == "cooldown_until_ns" else 0
        with self._connection:
            self._connection.execute(
                f"""
                INSERT INTO quota_state (
                    exchange, quota_group, ban_until_ns, cooldown_until_ns,
                    current_rate_multiplier, last_reason, restriction_revision
                ) VALUES (?, ?, ?, ?, '1', ?, 1)
                ON CONFLICT(exchange, quota_group) DO UPDATE SET
                    {column} = MAX(quota_state.{column}, excluded.{column}),
                    last_reason = excluded.last_reason,
                    restriction_revision = quota_state.restriction_revision + 1
                """,
                (
                    exchange,
                    quota_group,
                    initial_ban,
                    initial_cooldown,
                    reason,
                ),
            )

    def record_quota_probe_success(
        self,
        *,
        admission: QuotaProbeAdmission,
        observed_monotonic_ns: int,
    ) -> None:
        if not isinstance(admission, QuotaProbeAdmission):
            raise TypeError("admission must be a QuotaProbeAdmission")
        if admission._store_identity is not self._admission_identity:
            raise ValueError("quota probe admission belongs to a different store")
        observed_monotonic_ns = _nonnegative(
            observed_monotonic_ns,
            field="observed_monotonic_ns",
        )
        if observed_monotonic_ns < admission.probe_after_monotonic_ns:
            raise ValueError("quota probe cannot recover an active restriction")
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE quota_state
                   SET ban_until_ns = 0,
                       cooldown_until_ns = 0,
                       last_reason = NULL,
                       restriction_revision = restriction_revision + 1
                 WHERE exchange = ? AND quota_group = ?
                   AND restriction_revision = ?
                   AND last_reason IS NOT NULL
                """,
                (
                    admission.exchange,
                    admission.quota_group,
                    admission.restriction_revision,
                ),
            )
        if cursor.rowcount == 1:
            return
        state = self.load_quota(admission.exchange, admission.quota_group)
        if state.restriction_revision != admission.restriction_revision:
            raise StaleProbeError("quota probe observed a stale restriction revision")
        raise StaleProbeError("quota probe has no matching pending restriction")

    def set_rate_multiplier(
        self,
        *,
        exchange: str,
        quota_group: str,
        multiplier: Decimal,
    ) -> None:
        exchange = _nonempty(exchange, field="exchange")
        quota_group = _nonempty(quota_group, field="quota_group")
        if not isinstance(multiplier, Decimal):
            raise TypeError("multiplier must be a Decimal")
        if not multiplier.is_finite() or not Decimal(0) < multiplier <= Decimal(1):
            raise ValueError("multiplier must be finite and in the interval (0, 1]")
        encoded = str(multiplier)
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO quota_state (
                    exchange, quota_group, ban_until_ns, cooldown_until_ns,
                    current_rate_multiplier, last_reason, restriction_revision
                ) VALUES (?, ?, 0, 0, ?, NULL, 0)
                ON CONFLICT(exchange, quota_group) DO UPDATE SET
                    current_rate_multiplier = excluded.current_rate_multiplier
                """,
                (exchange, quota_group, encoded),
            )

    def record_transport_failure(
        self,
        *,
        exchange: str,
        egress_id: str,
        reason: str,
        cooldown_until_unix_ns: int = 0,
    ) -> None:
        exchange = _nonempty(exchange, field="exchange")
        egress_id = _nonempty(egress_id, field="egress_id")
        reason = _nonempty(reason, field="reason")
        cooldown_until_unix_ns = _nonnegative(
            cooldown_until_unix_ns, field="cooldown_until_unix_ns"
        )
        with self._connection:
            self._connection.execute(
                """
                INSERT INTO egress_state (
                    exchange, egress_id, consecutive_transport_failures,
                    transport_cooldown_until_ns, last_success_ns,
                    last_latency_ns, last_reason, restriction_revision
                ) VALUES (?, ?, 1, ?, NULL, NULL, ?, 1)
                ON CONFLICT(exchange, egress_id) DO UPDATE SET
                    consecutive_transport_failures =
                        egress_state.consecutive_transport_failures + 1,
                    transport_cooldown_until_ns = MAX(
                        egress_state.transport_cooldown_until_ns,
                        excluded.transport_cooldown_until_ns
                    ),
                    last_reason = excluded.last_reason,
                    restriction_revision = egress_state.restriction_revision + 1
                """,
                (exchange, egress_id, cooldown_until_unix_ns, reason),
            )

    def record_transport_probe_success(
        self,
        *,
        admission: TransportProbeAdmission,
        observed_monotonic_ns: int,
        observed_unix_ns: int,
        latency_ns: int,
    ) -> None:
        if not isinstance(admission, TransportProbeAdmission):
            raise TypeError("admission must be a TransportProbeAdmission")
        if admission._store_identity is not self._admission_identity:
            raise ValueError("transport probe admission belongs to a different store")
        observed_monotonic_ns = _nonnegative(
            observed_monotonic_ns,
            field="observed_monotonic_ns",
        )
        observed_unix_ns = _nonnegative(observed_unix_ns, field="observed_unix_ns")
        latency_ns = _nonnegative(latency_ns, field="latency_ns")
        if observed_monotonic_ns < admission.probe_after_monotonic_ns:
            raise ValueError("probe cannot recover an active transport cooldown")
        with self._connection:
            cursor = self._connection.execute(
                """
                UPDATE egress_state
                   SET consecutive_transport_failures = 0,
                       transport_cooldown_until_ns = 0,
                       last_success_ns = ?,
                       last_latency_ns = ?,
                       last_reason = NULL,
                       restriction_revision = restriction_revision + 1
                 WHERE exchange = ? AND egress_id = ?
                   AND restriction_revision = ?
                   AND consecutive_transport_failures > 0
                """,
                (
                    observed_unix_ns,
                    latency_ns,
                    admission.exchange,
                    admission.egress_id,
                    admission.restriction_revision,
                ),
            )
        if cursor.rowcount == 1:
            return
        state = self.load_egress(admission.exchange, admission.egress_id)
        if state.restriction_revision != admission.restriction_revision:
            raise StaleProbeError(
                "transport probe observed a stale restriction revision"
            )
        raise StaleProbeError("transport probe has no matching pending restriction")

    def admit_health(
        self,
        *,
        exchange: str,
        egresses: Iterable[Egress],
        now_unix_ns: int,
        now_monotonic_ns: int,
    ) -> AdmittedHealth:
        exchange = _nonempty(exchange, field="exchange")
        now_unix_ns = _nonnegative(now_unix_ns, field="now_unix_ns")
        now_monotonic_ns = _nonnegative(now_monotonic_ns, field="now_monotonic_ns")
        candidates = tuple(egresses)
        ids = [candidate.id for candidate in candidates]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate egress id")

        self._connection.execute("BEGIN DEFERRED")
        try:
            return self._admit_health_in_transaction(
                exchange=exchange,
                candidates=candidates,
                now_unix_ns=now_unix_ns,
                now_monotonic_ns=now_monotonic_ns,
            )
        finally:
            self._connection.rollback()

    def _admit_health_in_transaction(
        self,
        *,
        exchange: str,
        candidates: tuple[Egress, ...],
        now_unix_ns: int,
        now_monotonic_ns: int,
    ) -> AdmittedHealth:
        admitted: list[tuple[tuple[str, str], int]] = []
        quota_probes: dict[tuple[str, str], QuotaProbeAdmission] = {}
        transport_probes: dict[tuple[str, str], TransportProbeAdmission] = {}
        for candidate in candidates:
            quota = self.load_quota(exchange, candidate.quota_group)
            transport = self.load_egress(exchange, candidate.id)
            monotonic_deadlines = []
            if quota.requires_probe:
                quota_deadline = now_monotonic_ns + max(
                    0, quota.restriction_until_unix_ns - now_unix_ns
                )
                quota_admission = QuotaProbeAdmission(
                    exchange=exchange,
                    quota_group=candidate.quota_group,
                    restriction_revision=quota.restriction_revision,
                    probe_after_monotonic_ns=quota_deadline,
                    _store_identity=self._admission_identity,
                )
                quota_probes.setdefault(
                    (exchange, candidate.quota_group), quota_admission
                )
                monotonic_deadlines.append(quota_deadline)
            if transport.requires_probe:
                transport_deadline = now_monotonic_ns + max(
                    0, transport.cooldown_until_unix_ns - now_unix_ns
                )
                transport_admission = TransportProbeAdmission(
                    exchange=exchange,
                    egress_id=candidate.id,
                    restriction_revision=transport.restriction_revision,
                    probe_after_monotonic_ns=transport_deadline,
                    _store_identity=self._admission_identity,
                )
                transport_probes[(exchange, candidate.id)] = transport_admission
                monotonic_deadlines.append(transport_deadline)
            if monotonic_deadlines:
                admitted.append(
                    (
                        (exchange, candidate.id),
                        max(monotonic_deadlines),
                    )
                )
        return AdmittedHealth(
            probe_after_monotonic_ns=tuple(admitted),
            quota_probe_admissions=tuple(quota_probes.values()),
            transport_probe_admissions=tuple(transport_probes.values()),
        )
