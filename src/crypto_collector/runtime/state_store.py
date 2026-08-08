from __future__ import annotations

import re
import sqlite3
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Self

from crypto_collector.runtime.reload import (
    ReferenceConfigSnapshot,
    decode_reference_config,
    decode_reference_payload,
    encode_reference_config,
    encode_reference_payload,
)

_SCHEMA_VERSION = 1
_OPEN_RETRY_TIMEOUT_SECONDS = 5.0
_OPEN_ATTEMPT_BUSY_TIMEOUT_MS = 100
_BUSY_TIMEOUT_MS = 5_000
_INITIAL_RETRY_DELAY_SECONDS = 0.005
_MAX_RETRY_DELAY_SECONDS = 0.100
_NORMALIZED_CODE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class EpochStatus(StrEnum):
    PREPARING = "preparing"
    COMMITTED = "committed"
    ABORTED = "aborted"


class ReloadAuditStatus(StrEnum):
    PLANNED = "planned"
    COMMITTED = "committed"
    FAILED = "failed"


class ReloadStateError(RuntimeError):
    pass


class StaleWorkerAckError(ReloadStateError):
    pass


class IncompletePrepareError(ReloadStateError):
    pass


class ConflictingRecordError(ReloadStateError):
    pass


def _nonempty(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field_name} must be a non-empty string")
    return str(value)


def _nonnegative(value: object, *, field_name: str) -> int:
    if type(value) is not int or int(value) < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return int(value)


def _sha256(value: object, *, field_name: str) -> str:
    text = _nonempty(value, field_name=field_name)
    if len(text) != 64 or any(
        character not in "0123456789abcdef" for character in text
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return text


def _normalized_code(value: object, *, field_name: str) -> str:
    text = _nonempty(value, field_name=field_name)
    if _NORMALIZED_CODE.fullmatch(text) is None:
        raise ValueError(
            f"{field_name} must be a lowercase normalized code of at most 64 characters"
        )
    return text


@dataclass(frozen=True, slots=True)
class WorkerTarget:
    exchange: str
    worker_instance_id: str
    worker_generation: int

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "exchange", _nonempty(self.exchange, field_name="exchange")
        )
        object.__setattr__(
            self,
            "worker_instance_id",
            _nonempty(self.worker_instance_id, field_name="worker_instance_id"),
        )
        object.__setattr__(
            self,
            "worker_generation",
            _nonnegative(self.worker_generation, field_name="worker_generation"),
        )


@dataclass(frozen=True, slots=True)
class WorkerAckFence:
    epoch: int
    exchange: str
    supervisor_instance_id: str
    request_id: str
    worker_instance_id: str
    worker_generation: int

    def __post_init__(self) -> None:
        epoch = _nonnegative(self.epoch, field_name="epoch")
        if epoch == 0:
            raise ValueError("epoch must be positive")
        object.__setattr__(self, "epoch", epoch)
        for field_name in (
            "exchange",
            "supervisor_instance_id",
            "request_id",
            "worker_instance_id",
        ):
            object.__setattr__(
                self,
                field_name,
                _nonempty(getattr(self, field_name), field_name=field_name),
            )
        object.__setattr__(
            self,
            "worker_generation",
            _nonnegative(self.worker_generation, field_name="worker_generation"),
        )

    def as_dict(self) -> dict[str, str | int]:
        return {
            "epoch": self.epoch,
            "exchange": self.exchange,
            "supervisor_instance_id": self.supervisor_instance_id,
            "request_id": self.request_id,
            "worker_instance_id": self.worker_instance_id,
            "worker_generation": self.worker_generation,
        }


@dataclass(frozen=True, slots=True)
class ReloadAuditPayload:
    epoch: int
    status: ReloadAuditStatus
    config_sha256: str | None = None
    previous_config_sha256: str | None = None
    capability_registry_sha256: str | None = None
    request_id: str | None = None
    failure_code: str | None = None
    changed_paths: tuple[str, ...] = ()
    restart_required_keys: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        epoch = _nonnegative(self.epoch, field_name="epoch")
        if epoch == 0:
            raise ValueError("epoch must be positive")
        object.__setattr__(self, "epoch", epoch)
        if not isinstance(self.status, ReloadAuditStatus):
            raise TypeError("status must be ReloadAuditStatus")
        for field_name in (
            "config_sha256",
            "previous_config_sha256",
            "capability_registry_sha256",
        ):
            value = getattr(self, field_name)
            if value is not None:
                object.__setattr__(
                    self, field_name, _sha256(value, field_name=field_name)
                )
        if self.request_id is not None:
            object.__setattr__(
                self,
                "request_id",
                _nonempty(self.request_id, field_name="request_id"),
            )
        if self.status is ReloadAuditStatus.FAILED:
            if self.failure_code is None:
                raise ValueError("failed audit payload requires failure_code")
            object.__setattr__(
                self,
                "failure_code",
                _normalized_code(self.failure_code, field_name="failure_code"),
            )
        elif self.failure_code is not None:
            raise ValueError("non-failed audit payload must not contain failure_code")
        for field_name in ("changed_paths", "restart_required_keys"):
            values = getattr(self, field_name)
            if not isinstance(values, tuple) or any(
                type(value) is not str or not value for value in values
            ):
                raise TypeError(f"{field_name} must be a tuple of non-empty strings")
            if tuple(sorted(set(values))) != values:
                raise ValueError(f"{field_name} must be sorted and unique")

    def as_document(self) -> Mapping[str, object]:
        return {
            "capability_registry_sha256": self.capability_registry_sha256,
            "changed_paths": self.changed_paths,
            "config_sha256": self.config_sha256,
            "epoch": self.epoch,
            "failure_code": self.failure_code,
            "previous_config_sha256": self.previous_config_sha256,
            "request_id": self.request_id,
            "restart_required_keys": self.restart_required_keys,
            "status": self.status.value,
        }

    @classmethod
    def from_document(cls, document: Mapping[str, object]) -> Self:
        expected = frozenset(
            {
                "capability_registry_sha256",
                "changed_paths",
                "config_sha256",
                "epoch",
                "failure_code",
                "previous_config_sha256",
                "request_id",
                "restart_required_keys",
                "status",
            }
        )
        if frozenset(document) != expected:
            raise RuntimeError("audit payload fields do not match version 1")
        try:
            return cls(
                epoch=document["epoch"],  # type: ignore[arg-type]
                status=ReloadAuditStatus(str(document["status"])),
                config_sha256=document["config_sha256"],  # type: ignore[arg-type]
                previous_config_sha256=document["previous_config_sha256"],  # type: ignore[arg-type]
                capability_registry_sha256=document["capability_registry_sha256"],  # type: ignore[arg-type]
                request_id=document["request_id"],  # type: ignore[arg-type]
                failure_code=document["failure_code"],  # type: ignore[arg-type]
                changed_paths=document["changed_paths"],  # type: ignore[arg-type]
                restart_required_keys=document["restart_required_keys"],  # type: ignore[arg-type]
            )
        except (TypeError, ValueError):
            raise RuntimeError(
                "audit payload contains invalid version 1 values"
            ) from None


@dataclass(frozen=True, slots=True)
class AuditEvent:
    event_id: str
    exchange: str
    kind: str
    payload: ReloadAuditPayload = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "event_id", _nonempty(self.event_id, field_name="event_id")
        )
        object.__setattr__(
            self, "exchange", _nonempty(self.exchange, field_name="exchange")
        )
        object.__setattr__(self, "kind", _normalized_code(self.kind, field_name="kind"))
        if not isinstance(self.payload, ReloadAuditPayload):
            raise TypeError("payload must be ReloadAuditPayload")
        expected_kind = f"config_reload_{self.payload.status.value}"
        if self.kind != expected_kind:
            raise ValueError(f"audit event kind must be {expected_kind}")


@dataclass(frozen=True, slots=True)
class EpochRecord:
    epoch: int
    status: EpochStatus
    supervisor_instance_id: str
    request_id: str
    snapshot: ReferenceConfigSnapshot
    created_at_ns: int
    committed_at_ns: int | None
    failed_at_ns: int | None
    failure_code: str | None


@dataclass(frozen=True, slots=True)
class WorkerEpochRecord:
    fence: WorkerAckFence
    prepared_at_ns: int | None
    plan_sha256: str | None
    applied_at_ns: int | None
    healthy_since_ns: int | None


@dataclass(frozen=True, slots=True)
class AuditRecord:
    event_id: str
    epoch: int
    exchange: str
    kind: str
    payload: ReloadAuditPayload = field(repr=False)
    created_at_ns: int = 0
    delivered_at_ns: int | None = None
    delivery_fence: WorkerAckFence | None = None


_TABLE_DEFINITIONS = {
    "reload_epoch": """(
  epoch INTEGER PRIMARY KEY CHECK (epoch > 0),
  status TEXT NOT NULL CHECK (status IN ('preparing', 'committed', 'aborted')),
  supervisor_instance_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  config_sha256 TEXT NOT NULL,
  config_snapshot BLOB NOT NULL,
  created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
  committed_at_ns INTEGER,
  failed_at_ns INTEGER,
  failure_code TEXT,
  UNIQUE (supervisor_instance_id, request_id),
  CHECK (
    (status = 'preparing' AND committed_at_ns IS NULL AND failed_at_ns IS NULL
      AND failure_code IS NULL)
    OR (status = 'committed' AND committed_at_ns IS NOT NULL
      AND failed_at_ns IS NULL AND failure_code IS NULL)
    OR (status = 'aborted' AND committed_at_ns IS NULL
      AND failed_at_ns IS NOT NULL AND failure_code IS NOT NULL)
  )
)""",
    "current_epoch": """(
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  epoch INTEGER NOT NULL REFERENCES reload_epoch(epoch)
)""",
    "worker_epoch": """(
  epoch INTEGER NOT NULL REFERENCES reload_epoch(epoch),
  exchange TEXT NOT NULL,
  supervisor_instance_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  worker_instance_id TEXT NOT NULL,
  worker_generation INTEGER NOT NULL CHECK (worker_generation >= 0),
  prepared_at_ns INTEGER,
  plan_sha256 TEXT,
  applied_at_ns INTEGER,
  healthy_since_ns INTEGER,
  PRIMARY KEY (epoch, exchange),
  CHECK ((prepared_at_ns IS NULL AND plan_sha256 IS NULL)
    OR (prepared_at_ns IS NOT NULL AND plan_sha256 IS NOT NULL)),
  CHECK (applied_at_ns IS NULL OR prepared_at_ns IS NOT NULL),
  CHECK (healthy_since_ns IS NULL OR applied_at_ns IS NOT NULL)
)""",
    "audit_outbox": """(
  event_id TEXT PRIMARY KEY,
  epoch INTEGER NOT NULL,
  exchange TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload BLOB NOT NULL,
  created_at_ns INTEGER NOT NULL CHECK (created_at_ns >= 0),
  delivered_at_ns INTEGER,
  delivered_by_epoch INTEGER,
  delivered_by_supervisor_instance_id TEXT,
  delivered_by_request_id TEXT,
  delivered_by_worker_instance_id TEXT,
  delivered_by_worker_generation INTEGER,
  FOREIGN KEY (epoch, exchange) REFERENCES worker_epoch(epoch, exchange),
  CHECK (
    (delivered_at_ns IS NULL AND delivered_by_epoch IS NULL
      AND delivered_by_supervisor_instance_id IS NULL
      AND delivered_by_request_id IS NULL
      AND delivered_by_worker_instance_id IS NULL
      AND delivered_by_worker_generation IS NULL)
    OR (delivered_at_ns IS NOT NULL AND delivered_by_epoch IS NOT NULL
      AND delivered_by_supervisor_instance_id IS NOT NULL
      AND delivered_by_request_id IS NOT NULL
      AND delivered_by_worker_instance_id IS NOT NULL
      AND delivered_by_worker_generation IS NOT NULL)
  )
)""",
    "worker_crash": """(
  exchange TEXT NOT NULL,
  worker_generation INTEGER NOT NULL CHECK (worker_generation >= 0),
  epoch INTEGER NOT NULL CHECK (epoch > 0),
  supervisor_instance_id TEXT NOT NULL,
  request_id TEXT NOT NULL,
  worker_instance_id TEXT NOT NULL,
  occurred_at_ns INTEGER NOT NULL CHECK (occurred_at_ns >= 0),
  exit_code INTEGER NOT NULL,
  reason TEXT NOT NULL,
  PRIMARY KEY (exchange, worker_generation)
)""",
}
_INDEX_DEFINITIONS = {
    "reload_epoch_one_preparing": (
        "reload_epoch",
        (
            "CREATE UNIQUE INDEX IF NOT EXISTS reload_epoch_one_preparing "
            "ON reload_epoch(status) WHERE status = 'preparing'"
        ),
    ),
    "audit_outbox_pending": (
        "audit_outbox",
        (
            "CREATE INDEX IF NOT EXISTS audit_outbox_pending "
            "ON audit_outbox(exchange, created_at_ns, event_id) "
            "WHERE delivered_at_ns IS NULL"
        ),
    ),
    "worker_crash_window": (
        "worker_crash",
        (
            "CREATE INDEX IF NOT EXISTS worker_crash_window "
            "ON worker_crash(exchange, occurred_at_ns)"
        ),
    ),
}
_EXPECTED_COLUMNS = {
    "reload_epoch": (
        ("epoch", "INTEGER", 0, 1),
        ("status", "TEXT", 1, 0),
        ("supervisor_instance_id", "TEXT", 1, 0),
        ("request_id", "TEXT", 1, 0),
        ("config_sha256", "TEXT", 1, 0),
        ("config_snapshot", "BLOB", 1, 0),
        ("created_at_ns", "INTEGER", 1, 0),
        ("committed_at_ns", "INTEGER", 0, 0),
        ("failed_at_ns", "INTEGER", 0, 0),
        ("failure_code", "TEXT", 0, 0),
    ),
    "current_epoch": (
        ("singleton", "INTEGER", 0, 1),
        ("epoch", "INTEGER", 1, 0),
    ),
    "worker_epoch": (
        ("epoch", "INTEGER", 1, 1),
        ("exchange", "TEXT", 1, 2),
        ("supervisor_instance_id", "TEXT", 1, 0),
        ("request_id", "TEXT", 1, 0),
        ("worker_instance_id", "TEXT", 1, 0),
        ("worker_generation", "INTEGER", 1, 0),
        ("prepared_at_ns", "INTEGER", 0, 0),
        ("plan_sha256", "TEXT", 0, 0),
        ("applied_at_ns", "INTEGER", 0, 0),
        ("healthy_since_ns", "INTEGER", 0, 0),
    ),
    "audit_outbox": (
        ("event_id", "TEXT", 0, 1),
        ("epoch", "INTEGER", 1, 0),
        ("exchange", "TEXT", 1, 0),
        ("kind", "TEXT", 1, 0),
        ("payload", "BLOB", 1, 0),
        ("created_at_ns", "INTEGER", 1, 0),
        ("delivered_at_ns", "INTEGER", 0, 0),
        ("delivered_by_epoch", "INTEGER", 0, 0),
        ("delivered_by_supervisor_instance_id", "TEXT", 0, 0),
        ("delivered_by_request_id", "TEXT", 0, 0),
        ("delivered_by_worker_instance_id", "TEXT", 0, 0),
        ("delivered_by_worker_generation", "INTEGER", 0, 0),
    ),
    "worker_crash": (
        ("exchange", "TEXT", 1, 1),
        ("worker_generation", "INTEGER", 1, 2),
        ("epoch", "INTEGER", 1, 0),
        ("supervisor_instance_id", "TEXT", 1, 0),
        ("request_id", "TEXT", 1, 0),
        ("worker_instance_id", "TEXT", 1, 0),
        ("occurred_at_ns", "INTEGER", 1, 0),
        ("exit_code", "INTEGER", 1, 0),
        ("reason", "TEXT", 1, 0),
    ),
}


def _is_lock_contention(error: sqlite3.OperationalError) -> bool:
    error_code = getattr(error, "sqlite_errorcode", None)
    return type(error_code) is int and error_code & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }


def _validate_schema(connection: sqlite3.Connection) -> None:
    for table, expected in _EXPECTED_COLUMNS.items():
        actual = tuple(
            (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5]))
            for row in connection.execute(f"PRAGMA table_xinfo({table})").fetchall()
        )
        if actual != expected:
            raise RuntimeError(
                f"{table} schema does not match runtime state version {_SCHEMA_VERSION}"
            )
    objects = tuple(
        (
            str(row[0]),
            str(row[1]),
            str(row[2]),
            None if row[3] is None else str(row[3]),
        )
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
              FROM sqlite_schema
             WHERE lower(substr(name, 1, 7)) <> 'sqlite_'
             ORDER BY type, name, tbl_name
            """
        ).fetchall()
    )
    expected_objects = tuple(
        sorted(
            (
                *(
                    ("table", name, name, f"CREATE TABLE {name} {definition}")
                    for name, definition in _TABLE_DEFINITIONS.items()
                ),
                *(
                    (
                        "index",
                        name,
                        table,
                        statement.replace(" IF NOT EXISTS", ""),
                    )
                    for name, (table, statement) in _INDEX_DEFINITIONS.items()
                ),
            )
        )
    )
    if objects != expected_objects:
        raise RuntimeError(
            f"runtime state schema objects do not match version {_SCHEMA_VERSION}"
        )


def _validate_durable_epoch_rows(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        "SELECT epoch, config_sha256, config_snapshot FROM reload_epoch ORDER BY epoch"
    ).fetchall()
    for row in rows:
        try:
            snapshot = decode_reference_config(bytes(row["config_snapshot"]))
        except ValueError:
            raise RuntimeError(
                f"epoch {int(row['epoch'])} contains an invalid config snapshot"
            ) from None
        if str(row["config_sha256"]) != snapshot.config_sha256:
            raise RuntimeError(
                f"epoch {int(row['epoch'])} config digest does not match its snapshot"
            )
    current = connection.execute(
        """
        SELECT current_epoch.epoch, reload_epoch.status
          FROM current_epoch
          JOIN reload_epoch USING (epoch)
         WHERE current_epoch.singleton = 1
        """
    ).fetchone()
    if rows and current is None:
        raise RuntimeError("runtime state has epochs but no current committed pointer")
    if current is not None and str(current["status"]) != EpochStatus.COMMITTED:
        raise RuntimeError("current_epoch points to a non-committed epoch")
    latest_committed = connection.execute(
        "SELECT MAX(epoch) FROM reload_epoch WHERE status = 'committed'"
    ).fetchone()
    if current is not None and int(current["epoch"]) != int(latest_committed[0]):
        raise RuntimeError("current_epoch is not the latest committed epoch")
    audit_rows = connection.execute(
        "SELECT event_id, epoch, kind, payload FROM audit_outbox ORDER BY event_id"
    ).fetchall()
    for row in audit_rows:
        try:
            payload = ReloadAuditPayload.from_document(
                decode_reference_payload(bytes(row["payload"]))
            )
        except (RuntimeError, ValueError):
            raise RuntimeError("audit outbox contains an invalid payload") from None
        if (
            payload.epoch != int(row["epoch"])
            or str(row["kind"]) != f"config_reload_{payload.status.value}"
        ):
            raise RuntimeError("audit outbox payload does not match its envelope")


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
    if mode is None or str(mode[0]).casefold() != "wal":
        raise RuntimeError("runtime state store requires SQLite WAL mode")
    connection.execute("BEGIN IMMEDIATE")
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in (0, _SCHEMA_VERSION):
            raise RuntimeError(f"unsupported runtime state schema version {version}")
        if version == 0:
            for table, definition in _TABLE_DEFINITIONS.items():
                connection.execute(f"CREATE TABLE IF NOT EXISTS {table} {definition}")
            for _, statement in _INDEX_DEFINITIONS.values():
                connection.execute(statement)
        _validate_schema(connection)
        _validate_durable_epoch_rows(connection)
        if version == 0:
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def _initialize_schema_with_retry(connection: sqlite3.Connection) -> None:
    deadline = time.monotonic() + _OPEN_RETRY_TIMEOUT_SECONDS
    delay = _INITIAL_RETRY_DELAY_SECONDS
    while True:
        try:
            _initialize_schema(connection)
            return
        except sqlite3.OperationalError as error:
            if connection.in_transaction:
                connection.rollback()
            if not _is_lock_contention(error) or time.monotonic() >= deadline:
                raise
            remaining = deadline - time.monotonic()
            time.sleep(min(delay, max(0.0, remaining)))
            delay = min(delay * 2, _MAX_RETRY_DELAY_SECONDS)


def _row_to_epoch(row: sqlite3.Row) -> EpochRecord:
    snapshot = decode_reference_config(bytes(row["config_snapshot"]))
    if str(row["config_sha256"]) != snapshot.config_sha256:
        raise RuntimeError("epoch config digest does not match its snapshot")
    return EpochRecord(
        epoch=int(row["epoch"]),
        status=EpochStatus(str(row["status"])),
        supervisor_instance_id=str(row["supervisor_instance_id"]),
        request_id=str(row["request_id"]),
        snapshot=snapshot,
        created_at_ns=int(row["created_at_ns"]),
        committed_at_ns=(
            None if row["committed_at_ns"] is None else int(row["committed_at_ns"])
        ),
        failed_at_ns=(
            None if row["failed_at_ns"] is None else int(row["failed_at_ns"])
        ),
        failure_code=(
            None if row["failure_code"] is None else str(row["failure_code"])
        ),
    )


def _row_to_audit(row: sqlite3.Row) -> AuditRecord:
    delivery_fence = None
    if row["delivered_at_ns"] is not None:
        delivery_fence = WorkerAckFence(
            epoch=int(row["delivered_by_epoch"]),
            exchange=str(row["exchange"]),
            supervisor_instance_id=str(row["delivered_by_supervisor_instance_id"]),
            request_id=str(row["delivered_by_request_id"]),
            worker_instance_id=str(row["delivered_by_worker_instance_id"]),
            worker_generation=int(row["delivered_by_worker_generation"]),
        )
    payload_document = decode_reference_payload(bytes(row["payload"]))
    payload = ReloadAuditPayload.from_document(payload_document)
    kind = str(row["kind"])
    epoch = int(row["epoch"])
    if payload.epoch != epoch or kind != f"config_reload_{payload.status.value}":
        raise RuntimeError("audit outbox payload does not match its envelope")
    return AuditRecord(
        event_id=str(row["event_id"]),
        epoch=epoch,
        exchange=str(row["exchange"]),
        kind=kind,
        payload=payload,
        created_at_ns=int(row["created_at_ns"]),
        delivered_at_ns=(
            None if row["delivered_at_ns"] is None else int(row["delivered_at_ns"])
        ),
        delivery_fence=delivery_fence,
    )


class ReloadStateStore:
    def __init__(self, path: Path, connection: sqlite3.Connection) -> None:
        self.path = path
        self._connection = connection
        mode = connection.execute("PRAGMA journal_mode").fetchone()
        self.journal_mode = str(mode[0]).casefold()

    @classmethod
    def open(cls, path: str | Path) -> Self:
        resolved = Path(path).expanduser().resolve(strict=False)
        resolved.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            resolved,
            timeout=_OPEN_ATTEMPT_BUSY_TIMEOUT_MS / 1_000,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute(f"PRAGMA busy_timeout = {_OPEN_ATTEMPT_BUSY_TIMEOUT_MS}")
            _initialize_schema_with_retry(connection)
            connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
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

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._connection.rollback()
            raise
        else:
            self._connection.commit()

    def epoch(self, epoch: int) -> EpochRecord | None:
        epoch = _nonnegative(epoch, field_name="epoch")
        row = self._connection.execute(
            "SELECT * FROM reload_epoch WHERE epoch = ?", (epoch,)
        ).fetchone()
        return None if row is None else _row_to_epoch(row)

    def current_epoch(self) -> EpochRecord | None:
        row = self._connection.execute(
            """
            SELECT reload_epoch.*
              FROM current_epoch
              JOIN reload_epoch USING (epoch)
             WHERE current_epoch.singleton = 1
            """
        ).fetchone()
        if row is None:
            return None
        record = _row_to_epoch(row)
        if record.status is not EpochStatus.COMMITTED:
            raise RuntimeError("current_epoch points to a non-committed epoch")
        return record

    def workers_for_epoch(self, epoch: int) -> tuple[WorkerEpochRecord, ...]:
        epoch = _nonnegative(epoch, field_name="epoch")
        rows = self._connection.execute(
            """
            SELECT *
              FROM worker_epoch
             WHERE epoch = ?
             ORDER BY exchange
            """,
            (epoch,),
        ).fetchall()
        return tuple(
            WorkerEpochRecord(
                fence=WorkerAckFence(
                    epoch=int(row["epoch"]),
                    exchange=str(row["exchange"]),
                    supervisor_instance_id=str(row["supervisor_instance_id"]),
                    request_id=str(row["request_id"]),
                    worker_instance_id=str(row["worker_instance_id"]),
                    worker_generation=int(row["worker_generation"]),
                ),
                prepared_at_ns=(
                    None
                    if row["prepared_at_ns"] is None
                    else int(row["prepared_at_ns"])
                ),
                plan_sha256=(
                    None if row["plan_sha256"] is None else str(row["plan_sha256"])
                ),
                applied_at_ns=(
                    None if row["applied_at_ns"] is None else int(row["applied_at_ns"])
                ),
                healthy_since_ns=(
                    None
                    if row["healthy_since_ns"] is None
                    else int(row["healthy_since_ns"])
                ),
            )
            for row in rows
        )

    def register_committed_worker(
        self,
        fence: WorkerAckFence,
        *,
        plan_sha256: str,
        registered_at_ns: int,
    ) -> bool:
        """Fence a startup/replacement worker against the current committed epoch."""

        if not isinstance(fence, WorkerAckFence):
            raise TypeError("fence must be WorkerAckFence")
        plan = _sha256(plan_sha256, field_name="plan_sha256")
        timestamp = _nonnegative(registered_at_ns, field_name="registered_at_ns")
        with self._transaction():
            current = self._connection.execute(
                """
                SELECT reload_epoch.epoch, reload_epoch.status
                  FROM current_epoch
                  JOIN reload_epoch USING (epoch)
                 WHERE current_epoch.singleton = 1
                """
            ).fetchone()
            if (
                current is None
                or int(current["epoch"]) != fence.epoch
                or str(current["status"]) != EpochStatus.COMMITTED
            ):
                raise StaleWorkerAckError(
                    "worker can only be registered for the current committed epoch"
                )
            if (
                self._connection.execute(
                    "SELECT 1 FROM reload_epoch WHERE status = 'preparing'"
                ).fetchone()
                is not None
            ):
                raise ConflictingRecordError(
                    "cannot replace a committed worker while a reload is preparing"
                )
            row = self._connection.execute(
                """
                SELECT *
                  FROM worker_epoch
                 WHERE epoch = ? AND exchange = ?
                """,
                (fence.epoch, fence.exchange),
            ).fetchone()
            if row is None:
                self._connection.execute(
                    """
                    INSERT INTO worker_epoch(
                        epoch, exchange, supervisor_instance_id, request_id,
                        worker_instance_id, worker_generation,
                        prepared_at_ns, plan_sha256
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fence.epoch,
                        fence.exchange,
                        fence.supervisor_instance_id,
                        fence.request_id,
                        fence.worker_instance_id,
                        fence.worker_generation,
                        timestamp,
                        plan,
                    ),
                )
                return True
            existing_fence = WorkerAckFence(
                epoch=int(row["epoch"]),
                exchange=str(row["exchange"]),
                supervisor_instance_id=str(row["supervisor_instance_id"]),
                request_id=str(row["request_id"]),
                worker_instance_id=str(row["worker_instance_id"]),
                worker_generation=int(row["worker_generation"]),
            )
            if fence == existing_fence:
                if str(row["plan_sha256"]) != plan:
                    raise ConflictingRecordError(
                        "worker registration plan differs from the durable plan"
                    )
                return False
            if fence.worker_generation != existing_fence.worker_generation + 1:
                raise StaleWorkerAckError(
                    "replacement worker generation must equal its predecessor plus one"
                )
            self._connection.execute(
                """
                UPDATE worker_epoch
                   SET supervisor_instance_id = ?, request_id = ?,
                       worker_instance_id = ?, worker_generation = ?,
                       prepared_at_ns = ?, plan_sha256 = ?, applied_at_ns = NULL,
                       healthy_since_ns = NULL
                 WHERE epoch = ? AND exchange = ?
                """,
                (
                    fence.supervisor_instance_id,
                    fence.request_id,
                    fence.worker_instance_id,
                    fence.worker_generation,
                    timestamp,
                    plan,
                    fence.epoch,
                    fence.exchange,
                ),
            )
        return True

    def commit_initial_epoch(
        self,
        snapshot: ReferenceConfigSnapshot,
        *,
        supervisor_instance_id: str,
        request_id: str,
        committed_at_ns: int,
    ) -> EpochRecord:
        if not isinstance(snapshot, ReferenceConfigSnapshot):
            raise TypeError("snapshot must be ReferenceConfigSnapshot")
        supervisor = _nonempty(
            supervisor_instance_id, field_name="supervisor_instance_id"
        )
        request = _nonempty(request_id, field_name="request_id")
        timestamp = _nonnegative(committed_at_ns, field_name="committed_at_ns")
        encoded_snapshot = encode_reference_config(snapshot)
        with self._transaction():
            if (
                self._connection.execute(
                    "SELECT 1 FROM reload_epoch LIMIT 1"
                ).fetchone()
                is not None
            ):
                raise ConflictingRecordError("initial epoch already exists")
            self._connection.execute(
                """
                INSERT INTO reload_epoch(
                    epoch, status, supervisor_instance_id, request_id,
                    config_sha256, config_snapshot, created_at_ns, committed_at_ns
                ) VALUES (1, 'committed', ?, ?, ?, ?, ?, ?)
                """,
                (
                    supervisor,
                    request,
                    snapshot.config_sha256,
                    encoded_snapshot,
                    timestamp,
                    timestamp,
                ),
            )
            self._connection.execute(
                "INSERT INTO current_epoch(singleton, epoch) VALUES (1, 1)"
            )
        record = self.epoch(1)
        if record is None:  # pragma: no cover - transaction invariant
            raise RuntimeError("initial epoch commit disappeared")
        return record

    def begin_reload(
        self,
        snapshot: ReferenceConfigSnapshot,
        *,
        supervisor_instance_id: str,
        request_id: str,
        workers: Iterable[WorkerTarget],
        planned_events: Iterable[AuditEvent] = (),
        created_at_ns: int,
    ) -> EpochRecord:
        if not isinstance(snapshot, ReferenceConfigSnapshot):
            raise TypeError("snapshot must be ReferenceConfigSnapshot")
        supervisor = _nonempty(
            supervisor_instance_id, field_name="supervisor_instance_id"
        )
        request = _nonempty(request_id, field_name="request_id")
        timestamp = _nonnegative(created_at_ns, field_name="created_at_ns")
        targets = tuple(workers)
        if any(not isinstance(target, WorkerTarget) for target in targets):
            raise TypeError("workers must contain WorkerTarget values")
        by_exchange = {target.exchange: target for target in targets}
        if len(by_exchange) != len(targets):
            raise ValueError("workers must contain one target per exchange")
        supplied_events = tuple(planned_events)
        if any(not isinstance(event, AuditEvent) for event in supplied_events):
            raise TypeError("planned_events must contain AuditEvent values")
        encoded_snapshot = encode_reference_config(snapshot)
        with self._transaction():
            if (
                self._connection.execute(
                    "SELECT 1 FROM reload_epoch WHERE status = 'preparing'"
                ).fetchone()
                is not None
            ):
                raise ConflictingRecordError("another reload is already preparing")
            current = self._connection.execute(
                "SELECT epoch FROM current_epoch WHERE singleton = 1"
            ).fetchone()
            if current is None:
                raise ConflictingRecordError("initial epoch has not been committed")
            if (
                self._connection.execute(
                    """
                SELECT 1
                  FROM worker_epoch
                 WHERE epoch = ? AND applied_at_ns IS NULL
                 LIMIT 1
                """,
                    (int(current["epoch"]),),
                ).fetchone()
                is not None
            ):
                raise ConflictingRecordError(
                    "current epoch must be converged before preparing another reload"
                )
            predecessors = {
                str(row["exchange"]): (
                    str(row["worker_instance_id"]),
                    int(row["worker_generation"]),
                )
                for row in self._connection.execute(
                    """
                    SELECT exchange, worker_instance_id, worker_generation
                      FROM worker_epoch
                     WHERE epoch = ?
                    """,
                    (int(current["epoch"]),),
                ).fetchall()
            }
            for target in targets:
                predecessor = predecessors.get(target.exchange)
                if predecessor is not None and predecessor != (
                    target.worker_instance_id,
                    target.worker_generation,
                ):
                    raise StaleWorkerAckError(
                        "reload target does not match the current worker predecessor"
                    )
            maximum = self._connection.execute(
                "SELECT COALESCE(MAX(epoch), 0) FROM reload_epoch"
            ).fetchone()
            next_epoch = int(maximum[0]) + 1
            self._connection.execute(
                """
                INSERT INTO reload_epoch(
                    epoch, status, supervisor_instance_id, request_id,
                    config_sha256, config_snapshot, created_at_ns
                ) VALUES (?, 'preparing', ?, ?, ?, ?, ?)
                """,
                (
                    next_epoch,
                    supervisor,
                    request,
                    snapshot.config_sha256,
                    encoded_snapshot,
                    timestamp,
                ),
            )
            for target in sorted(targets, key=lambda item: item.exchange):
                self._connection.execute(
                    """
                    INSERT INTO worker_epoch(
                        epoch, exchange, supervisor_instance_id, request_id,
                        worker_instance_id, worker_generation
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (
                        next_epoch,
                        target.exchange,
                        supervisor,
                        request,
                        target.worker_instance_id,
                        target.worker_generation,
                    ),
                )
            events_by_exchange: dict[str, AuditEvent] = {}
            for event in supplied_events:
                if event.exchange not in by_exchange:
                    raise ValueError("planned event exchange must have a worker target")
                if (
                    event.payload.status is not ReloadAuditStatus.PLANNED
                    or event.payload.epoch != next_epoch
                ):
                    raise ValueError(
                        "planned event payload must match the candidate epoch"
                    )
                if event.exchange in events_by_exchange:
                    raise ValueError("only one planned event is allowed per exchange")
                events_by_exchange[event.exchange] = event
            for exchange in sorted(by_exchange):
                event = events_by_exchange.get(exchange) or self._default_audit_event(
                    next_epoch, exchange, ReloadAuditStatus.PLANNED
                )
                self._insert_audit(next_epoch, event, timestamp)
        record = self.epoch(next_epoch)
        if record is None:  # pragma: no cover - transaction invariant
            raise RuntimeError("reload intent disappeared")
        return record

    @staticmethod
    def _default_audit_event(
        epoch: int,
        exchange: str,
        status: ReloadAuditStatus,
        *,
        failure_code: str | None = None,
    ) -> AuditEvent:
        kind = f"config_reload_{status.value}"
        return AuditEvent(
            event_id=f"reload:{epoch}:{exchange}:{kind}",
            exchange=exchange,
            kind=kind,
            payload=ReloadAuditPayload(
                epoch=epoch,
                status=status,
                failure_code=failure_code,
            ),
        )

    def _insert_audit(self, epoch: int, event: AuditEvent, created_at_ns: int) -> bool:
        encoded = encode_reference_payload(event.payload.as_document())
        existing = self._connection.execute(
            """
            SELECT epoch, exchange, kind, payload, created_at_ns
              FROM audit_outbox
             WHERE event_id = ?
            """,
            (event.event_id,),
        ).fetchone()
        expected = (
            epoch,
            event.exchange,
            event.kind,
            encoded,
            created_at_ns,
        )
        if existing is not None:
            actual = (
                int(existing["epoch"]),
                str(existing["exchange"]),
                str(existing["kind"]),
                bytes(existing["payload"]),
                int(existing["created_at_ns"]),
            )
            if actual != expected:
                raise ConflictingRecordError(
                    f"audit event {event.event_id!r} conflicts with durable record"
                )
            return False
        try:
            self._connection.execute(
                """
                INSERT INTO audit_outbox(
                    event_id, epoch, exchange, kind, payload, created_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    epoch,
                    event.exchange,
                    event.kind,
                    encoded,
                    created_at_ns,
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ConflictingRecordError(
                "audit event exchange is not registered for the epoch"
            ) from error
        return True

    def enqueue_audit(
        self, epoch: int, event: AuditEvent, *, created_at_ns: int
    ) -> bool:
        epoch = _nonnegative(epoch, field_name="epoch")
        if not isinstance(event, AuditEvent):
            raise TypeError("event must be AuditEvent")
        timestamp = _nonnegative(created_at_ns, field_name="created_at_ns")
        with self._transaction():
            return self._insert_audit(epoch, event, timestamp)

    def _expected_worker_row(self, fence: WorkerAckFence) -> sqlite3.Row:
        if not isinstance(fence, WorkerAckFence):
            raise TypeError("fence must be WorkerAckFence")
        row = self._connection.execute(
            """
            SELECT worker_epoch.*, reload_epoch.status
              FROM worker_epoch
              JOIN reload_epoch USING (epoch)
             WHERE worker_epoch.epoch = ? AND worker_epoch.exchange = ?
            """,
            (fence.epoch, fence.exchange),
        ).fetchone()
        if row is None:
            raise StaleWorkerAckError("worker is not registered for this epoch")
        expected = (
            str(row["supervisor_instance_id"]),
            str(row["request_id"]),
            str(row["worker_instance_id"]),
            int(row["worker_generation"]),
        )
        received = (
            fence.supervisor_instance_id,
            fence.request_id,
            fence.worker_instance_id,
            fence.worker_generation,
        )
        if received != expected:
            raise StaleWorkerAckError("worker ACK does not match the durable fence")
        return row

    def ack_prepared(
        self,
        fence: WorkerAckFence,
        *,
        plan_sha256: str,
        at_ns: int,
    ) -> bool:
        plan = _sha256(plan_sha256, field_name="plan_sha256")
        timestamp = _nonnegative(at_ns, field_name="at_ns")
        with self._transaction():
            row = self._expected_worker_row(fence)
            status = EpochStatus(str(row["status"]))
            if status is EpochStatus.ABORTED:
                raise ReloadStateError("aborted epoch rejects prepared ACK replay")
            if row["prepared_at_ns"] is not None:
                if str(row["plan_sha256"]) != plan:
                    raise ConflictingRecordError(
                        "prepared ACK plan differs from the durable ACK"
                    )
                return False
            if status is not EpochStatus.PREPARING:
                raise ReloadStateError("epoch is no longer preparing")
            self._connection.execute(
                """
                UPDATE worker_epoch
                   SET prepared_at_ns = ?, plan_sha256 = ?
                 WHERE epoch = ? AND exchange = ?
                """,
                (timestamp, plan, fence.epoch, fence.exchange),
            )
        return True

    def commit_prepared_epoch(
        self,
        epoch: int,
        *,
        committed_at_ns: int,
        committed_events: Iterable[AuditEvent] = (),
    ) -> EpochRecord:
        epoch = _nonnegative(epoch, field_name="epoch")
        timestamp = _nonnegative(committed_at_ns, field_name="committed_at_ns")
        supplied = tuple(committed_events)
        if any(not isinstance(event, AuditEvent) for event in supplied):
            raise TypeError("committed_events must contain AuditEvent values")
        with self._transaction():
            epoch_row = self._connection.execute(
                "SELECT status FROM reload_epoch WHERE epoch = ?", (epoch,)
            ).fetchone()
            if epoch_row is None:
                raise ReloadStateError("unknown epoch")
            status = EpochStatus(str(epoch_row["status"]))
            if status is EpochStatus.COMMITTED:
                record = self.epoch(epoch)
                if record is None:  # pragma: no cover
                    raise RuntimeError("committed epoch disappeared")
                return record
            if status is EpochStatus.ABORTED:
                raise ReloadStateError("aborted epoch cannot be committed")
            missing = tuple(
                str(row[0])
                for row in self._connection.execute(
                    """
                    SELECT exchange
                      FROM worker_epoch
                     WHERE epoch = ? AND prepared_at_ns IS NULL
                     ORDER BY exchange
                    """,
                    (epoch,),
                ).fetchall()
            )
            if missing:
                raise IncompletePrepareError(
                    f"workers have not prepared epoch {epoch}: {', '.join(missing)}"
                )
            exchanges = tuple(
                str(row[0])
                for row in self._connection.execute(
                    "SELECT exchange FROM worker_epoch WHERE epoch = ? ORDER BY exchange",
                    (epoch,),
                ).fetchall()
            )
            events_by_exchange: dict[str, AuditEvent] = {}
            for event in supplied:
                if event.exchange not in exchanges:
                    raise ValueError(
                        "committed event exchange must have a worker target"
                    )
                if (
                    event.payload.status is not ReloadAuditStatus.COMMITTED
                    or event.payload.epoch != epoch
                ):
                    raise ValueError(
                        "committed event payload must match the committed epoch"
                    )
                if event.exchange in events_by_exchange:
                    raise ValueError("only one committed event is allowed per exchange")
                events_by_exchange[event.exchange] = event
            for exchange in exchanges:
                event = events_by_exchange.get(exchange) or self._default_audit_event(
                    epoch, exchange, ReloadAuditStatus.COMMITTED
                )
                self._insert_audit(epoch, event, timestamp)
            self._connection.execute(
                """
                UPDATE reload_epoch
                   SET status = 'committed', committed_at_ns = ?
                 WHERE epoch = ? AND status = 'preparing'
                """,
                (timestamp, epoch),
            )
            self._connection.execute(
                "UPDATE current_epoch SET epoch = ? WHERE singleton = 1", (epoch,)
            )
        record = self.epoch(epoch)
        if record is None:  # pragma: no cover - transaction invariant
            raise RuntimeError("committed epoch disappeared")
        return record

    def ack_applied(self, fence: WorkerAckFence, *, at_ns: int) -> bool:
        timestamp = _nonnegative(at_ns, field_name="at_ns")
        with self._transaction():
            row = self._expected_worker_row(fence)
            if str(row["status"]) != EpochStatus.COMMITTED:
                raise ReloadStateError("apply ACK requires a committed epoch")
            if row["prepared_at_ns"] is None:
                raise ReloadStateError("apply ACK requires a prepared ACK")
            if row["applied_at_ns"] is not None:
                return False
            self._connection.execute(
                """
                UPDATE worker_epoch
                   SET applied_at_ns = ?
                 WHERE epoch = ? AND exchange = ?
                """,
                (timestamp, fence.epoch, fence.exchange),
            )
        return True

    def mark_worker_healthy(self, fence: WorkerAckFence, *, at_ns: int) -> bool:
        if not isinstance(fence, WorkerAckFence):
            raise TypeError("fence must be WorkerAckFence")
        timestamp = _nonnegative(at_ns, field_name="at_ns")
        with self._transaction():
            row = self._expected_worker_row(fence)
            current = self._connection.execute(
                "SELECT epoch FROM current_epoch WHERE singleton = 1"
            ).fetchone()
            if (
                current is None
                or int(current["epoch"]) != fence.epoch
                or str(row["status"]) != EpochStatus.COMMITTED
            ):
                raise StaleWorkerAckError(
                    "health can only be reported by the current committed worker"
                )
            if row["applied_at_ns"] is None:
                raise ReloadStateError("health requires an applied config epoch")
            if row["healthy_since_ns"] is not None:
                return False
            self._connection.execute(
                """
                UPDATE worker_epoch
                   SET healthy_since_ns = ?
                 WHERE epoch = ? AND exchange = ?
                """,
                (timestamp, fence.epoch, fence.exchange),
            )
        return True

    def mark_worker_unhealthy(self, fence: WorkerAckFence) -> bool:
        if not isinstance(fence, WorkerAckFence):
            raise TypeError("fence must be WorkerAckFence")
        with self._transaction():
            row = self._expected_worker_row(fence)
            current = self._connection.execute(
                "SELECT epoch FROM current_epoch WHERE singleton = 1"
            ).fetchone()
            if current is None or int(current["epoch"]) != fence.epoch:
                raise StaleWorkerAckError(
                    "health can only be cleared by the current committed worker"
                )
            if row["healthy_since_ns"] is None:
                return False
            self._connection.execute(
                """
                UPDATE worker_epoch
                   SET healthy_since_ns = NULL
                 WHERE epoch = ? AND exchange = ?
                """,
                (fence.epoch, fence.exchange),
            )
        return True

    def epoch_converged(self, epoch: int) -> bool:
        epoch = _nonnegative(epoch, field_name="epoch")
        row = self._connection.execute(
            """
            SELECT reload_epoch.status,
                   COUNT(worker_epoch.exchange) AS total,
                   COUNT(worker_epoch.applied_at_ns) AS applied
              FROM reload_epoch
              LEFT JOIN worker_epoch USING (epoch)
             WHERE reload_epoch.epoch = ?
             GROUP BY reload_epoch.epoch
            """,
            (epoch,),
        ).fetchone()
        if row is None:
            raise ReloadStateError("unknown epoch")
        return str(row["status"]) == EpochStatus.COMMITTED and int(row["total"]) == int(
            row["applied"]
        )

    def _abort_epoch(
        self,
        epoch: int,
        *,
        failure_code: str,
        failed_at_ns: int,
        failed_events: Iterable[AuditEvent] = (),
    ) -> None:
        failure = _normalized_code(failure_code, field_name="failure_code")
        timestamp = _nonnegative(failed_at_ns, field_name="failed_at_ns")
        exchanges = tuple(
            str(row[0])
            for row in self._connection.execute(
                "SELECT exchange FROM worker_epoch WHERE epoch = ? ORDER BY exchange",
                (epoch,),
            ).fetchall()
        )
        supplied = tuple(failed_events)
        events_by_exchange: dict[str, AuditEvent] = {}
        for event in supplied:
            if not isinstance(event, AuditEvent):
                raise TypeError("failed_events must contain AuditEvent values")
            if event.exchange not in exchanges:
                raise ValueError("failed event exchange must have a worker target")
            if (
                event.payload.status is not ReloadAuditStatus.FAILED
                or event.payload.epoch != epoch
                or event.payload.failure_code != failure
            ):
                raise ValueError("failed event payload must match the aborted epoch")
            if event.exchange in events_by_exchange:
                raise ValueError("only one failed event is allowed per exchange")
            events_by_exchange[event.exchange] = event
        for exchange in exchanges:
            event = events_by_exchange.get(exchange) or self._default_audit_event(
                epoch,
                exchange,
                ReloadAuditStatus.FAILED,
                failure_code=failure,
            )
            self._insert_audit(epoch, event, timestamp)
        cursor = self._connection.execute(
            """
            UPDATE reload_epoch
               SET status = 'aborted', failed_at_ns = ?, failure_code = ?
             WHERE epoch = ? AND status = 'preparing'
            """,
            (timestamp, failure, epoch),
        )
        if cursor.rowcount != 1:
            raise ReloadStateError("only a preparing epoch can be aborted")

    def abort_preparing_epoch(
        self,
        epoch: int,
        *,
        failure_code: str,
        failed_at_ns: int,
        failed_events: Iterable[AuditEvent] = (),
    ) -> EpochRecord:
        epoch = _nonnegative(epoch, field_name="epoch")
        with self._transaction():
            self._abort_epoch(
                epoch,
                failure_code=failure_code,
                failed_at_ns=failed_at_ns,
                failed_events=failed_events,
            )
        record = self.epoch(epoch)
        if record is None:  # pragma: no cover
            raise RuntimeError("aborted epoch disappeared")
        return record

    def recover_interrupted_prepares(
        self, *, failure_code: str, failed_at_ns: int
    ) -> tuple[int, ...]:
        failure = _normalized_code(failure_code, field_name="failure_code")
        timestamp = _nonnegative(failed_at_ns, field_name="failed_at_ns")
        with self._transaction():
            epochs = tuple(
                int(row[0])
                for row in self._connection.execute(
                    "SELECT epoch FROM reload_epoch WHERE status = 'preparing' ORDER BY epoch"
                ).fetchall()
            )
            for epoch in epochs:
                self._abort_epoch(
                    epoch,
                    failure_code=failure,
                    failed_at_ns=timestamp,
                )
        return epochs

    def pending_audit(self, exchange: str) -> tuple[AuditRecord, ...]:
        exchange = _nonempty(exchange, field_name="exchange")
        return tuple(
            _row_to_audit(row)
            for row in self._connection.execute(
                """
                SELECT *
                  FROM audit_outbox
                 WHERE exchange = ? AND delivered_at_ns IS NULL
                 ORDER BY created_at_ns, event_id
                """,
                (exchange,),
            ).fetchall()
        )

    def ack_audit_delivery(
        self,
        fence: WorkerAckFence,
        event_id: str,
        *,
        delivered_at_ns: int,
    ) -> bool:
        event = _nonempty(event_id, field_name="event_id")
        timestamp = _nonnegative(delivered_at_ns, field_name="delivered_at_ns")
        with self._transaction():
            self._expected_worker_row(fence)
            row = self._connection.execute(
                "SELECT * FROM audit_outbox WHERE event_id = ?", (event,)
            ).fetchone()
            if row is None:
                raise ReloadStateError("unknown audit event")
            if str(row["exchange"]) != fence.exchange:
                raise StaleWorkerAckError("audit event does not match the worker fence")
            event_epoch = int(row["epoch"])
            event_status_row = self._connection.execute(
                "SELECT status FROM reload_epoch WHERE epoch = ?", (event_epoch,)
            ).fetchone()
            current_row = self._connection.execute(
                "SELECT epoch FROM current_epoch WHERE singleton = 1"
            ).fetchone()
            if event_status_row is None or current_row is None:  # pragma: no cover
                raise RuntimeError("audit outbox references invalid epoch state")
            authority_epoch = (
                event_epoch
                if str(event_status_row["status"]) == EpochStatus.PREPARING
                else int(current_row["epoch"])
            )
            if fence.epoch != authority_epoch:
                raise StaleWorkerAckError(
                    "audit delivery fence is not active for the event state"
                )
            if row["delivered_at_ns"] is not None:
                if (
                    int(row["delivered_by_epoch"]) != fence.epoch
                    or str(row["delivered_by_supervisor_instance_id"])
                    != fence.supervisor_instance_id
                    or str(row["delivered_by_request_id"]) != fence.request_id
                    or str(row["delivered_by_worker_instance_id"])
                    != fence.worker_instance_id
                    or int(row["delivered_by_worker_generation"])
                    != fence.worker_generation
                ):
                    raise StaleWorkerAckError(
                        "audit delivery was acknowledged by another worker fence"
                    )
                return False
            self._connection.execute(
                """
                UPDATE audit_outbox
                   SET delivered_at_ns = ?,
                       delivered_by_epoch = ?,
                       delivered_by_supervisor_instance_id = ?,
                       delivered_by_request_id = ?,
                       delivered_by_worker_instance_id = ?,
                       delivered_by_worker_generation = ?
                 WHERE event_id = ?
                """,
                (
                    timestamp,
                    fence.epoch,
                    fence.supervisor_instance_id,
                    fence.request_id,
                    fence.worker_instance_id,
                    fence.worker_generation,
                    event,
                ),
            )
        return True

    def record_abnormal_exit(
        self,
        fence: WorkerAckFence,
        *,
        occurred_at_ns: int,
        exit_code: int,
        reason: str,
    ) -> bool:
        if not isinstance(fence, WorkerAckFence):
            raise TypeError("fence must be WorkerAckFence")
        timestamp = _nonnegative(occurred_at_ns, field_name="occurred_at_ns")
        if type(exit_code) is not int:
            raise ValueError("exit_code must be an integer")
        failure = _normalized_code(reason, field_name="reason")
        with self._transaction():
            worker = self._expected_worker_row(fence)
            current = self._connection.execute(
                "SELECT epoch FROM current_epoch WHERE singleton = 1"
            ).fetchone()
            if (
                current is None
                or int(current["epoch"]) != fence.epoch
                or str(worker["status"]) != EpochStatus.COMMITTED
            ):
                raise StaleWorkerAckError(
                    "crash budget accepts only the current committed worker fence"
                )
            row = self._connection.execute(
                """
                SELECT epoch, supervisor_instance_id, request_id,
                       worker_instance_id, occurred_at_ns, exit_code, reason
                  FROM worker_crash
                 WHERE exchange = ? AND worker_generation = ?
                """,
                (fence.exchange, fence.worker_generation),
            ).fetchone()
            expected = (
                fence.epoch,
                fence.supervisor_instance_id,
                fence.request_id,
                fence.worker_instance_id,
                timestamp,
                exit_code,
                failure,
            )
            if row is not None:
                actual = (
                    int(row[0]),
                    str(row[1]),
                    str(row[2]),
                    str(row[3]),
                    int(row[4]),
                    int(row[5]),
                    str(row[6]),
                )
                if actual != expected:
                    raise ConflictingRecordError(
                        "worker generation has a different durable crash record"
                    )
                return False
            self._connection.execute(
                """
                INSERT INTO worker_crash(
                    exchange, worker_generation, epoch, supervisor_instance_id,
                    request_id, worker_instance_id, occurred_at_ns, exit_code, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fence.exchange,
                    fence.worker_generation,
                    fence.epoch,
                    fence.supervisor_instance_id,
                    fence.request_id,
                    fence.worker_instance_id,
                    timestamp,
                    exit_code,
                    failure,
                ),
            )
            self._connection.execute(
                """
                UPDATE worker_epoch
                   SET healthy_since_ns = NULL
                 WHERE epoch = ? AND exchange = ?
                """,
                (fence.epoch, fence.exchange),
            )
        return True

    def crash_count(self, exchange: str, *, now_ns: int, window_ns: int) -> int:
        exchange = _nonempty(exchange, field_name="exchange")
        now = _nonnegative(now_ns, field_name="now_ns")
        window = _nonnegative(window_ns, field_name="window_ns")
        lower = max(0, now - window)
        row = self._connection.execute(
            """
            SELECT COUNT(*)
              FROM worker_crash
             WHERE exchange = ? AND occurred_at_ns BETWEEN ? AND ?
            """,
            (exchange, lower, now),
        ).fetchone()
        return int(row[0])

    def reset_crash_window_if_healthy(
        self,
        fence: WorkerAckFence,
        *,
        observed_at_ns: int,
        reset_after_ns: int,
    ) -> bool:
        if not isinstance(fence, WorkerAckFence):
            raise TypeError("fence must be WorkerAckFence")
        observed = _nonnegative(observed_at_ns, field_name="observed_at_ns")
        reset_after = _nonnegative(reset_after_ns, field_name="reset_after_ns")
        with self._transaction():
            worker = self._expected_worker_row(fence)
            current = self._connection.execute(
                "SELECT epoch FROM current_epoch WHERE singleton = 1"
            ).fetchone()
            if current is None or int(current["epoch"]) != fence.epoch:
                raise StaleWorkerAckError(
                    "crash budget can only be reset by the current committed worker"
                )
            if str(worker["status"]) != EpochStatus.COMMITTED:
                raise StaleWorkerAckError(
                    "crash budget can only be reset by a committed worker"
                )
            if worker["healthy_since_ns"] is None:
                return False
            healthy_since = int(worker["healthy_since_ns"])
            if observed < healthy_since:
                raise ValueError("observed_at_ns precedes durable healthy start")
            if observed - healthy_since < reset_after:
                return False
            interruption = self._connection.execute(
                """
                SELECT 1
                  FROM worker_crash
                 WHERE exchange = ? AND occurred_at_ns BETWEEN ? AND ?
                 LIMIT 1
                """,
                (fence.exchange, healthy_since, observed),
            ).fetchone()
            if interruption is not None:
                return False
            self._connection.execute(
                "DELETE FROM worker_crash WHERE exchange = ? AND occurred_at_ns <= ?",
                (fence.exchange, observed),
            )
        return True


__all__ = [
    "AuditEvent",
    "AuditRecord",
    "ConflictingRecordError",
    "EpochRecord",
    "EpochStatus",
    "IncompletePrepareError",
    "ReloadAuditPayload",
    "ReloadAuditStatus",
    "ReloadStateError",
    "ReloadStateStore",
    "StaleWorkerAckError",
    "WorkerAckFence",
    "WorkerEpochRecord",
    "WorkerTarget",
]
