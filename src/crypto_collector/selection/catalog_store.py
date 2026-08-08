from __future__ import annotations

import sqlite3
import time
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, replace
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from types import TracebackType
from typing import Self, TypeAlias

from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.domain.types import Exchange, Market
from crypto_collector.selection.models import (
    AnnouncementHint,
    CatalogChanges,
    CatalogControlChange,
    CatalogDelta,
    CatalogInstrument,
    CatalogScope,
    CatalogSnapshot,
    CatalogView,
    CompleteCatalogSnapshot,
    CompleteTurnoverSnapshot,
    FrozenJsonPayload,
    InstrumentRecord,
    LifecyclePhase,
    ListingState,
    SnapshotPage,
    StoredAnnouncementHint,
    TradableAtSource,
    Turnover,
    TurnoverChanges,
    TurnoverMethod,
    mutable_json_copy,
)
from crypto_collector.selection.selector import (
    SelectionEntry,
    SelectionReason,
    SelectionResult,
    SelectionState,
)

_SCHEMA_VERSION = 1
_OPEN_RETRY_TIMEOUT_SECONDS = 5.0
_OPEN_ATTEMPT_BUSY_TIMEOUT_MS = 100
_BUSY_TIMEOUT_MS = 5_000
_INITIAL_RETRY_DELAY_SECONDS = 0.005
_MAX_RETRY_DELAY_SECONDS = 0.100
_ColumnContract: TypeAlias = tuple[str, str, int, str | None, int, int]


class CatalogStoreError(RuntimeError):
    pass


class StaleCatalogSnapshotError(CatalogStoreError):
    pass


class CatalogSnapshotConflictError(CatalogStoreError):
    pass


class StaleTurnoverSnapshotError(CatalogStoreError):
    pass


class TurnoverSnapshotConflictError(CatalogStoreError):
    pass


class CatalogRevisionConflictError(CatalogStoreError):
    pass


class SelectionStateConflictError(CatalogStoreError):
    pass


class AnnouncementHintConflictError(CatalogStoreError):
    pass


_SCHEMA = (
    """
    CREATE TABLE IF NOT EXISTS catalog_scope_state (
        exchange TEXT NOT NULL,
        market TEXT NOT NULL,
        last_observed_at_ns INTEGER NOT NULL,
        snapshot_digest TEXT NOT NULL,
        revision INTEGER NOT NULL,
        complete INTEGER NOT NULL CHECK (complete IN (0, 1)),
        snapshot_id TEXT NOT NULL,
        page_raw_references_json BLOB NOT NULL,
        turnover_last_observed_at_ns INTEGER,
        turnover_snapshot_digest TEXT,
        turnover_revision INTEGER NOT NULL DEFAULT 0,
        turnover_snapshot_id TEXT,
        turnover_page_raw_references_json BLOB,
        turnover_catalog_revision INTEGER,
        turnover_covered_keys_json BLOB,
        PRIMARY KEY (exchange, market),
        CHECK (last_observed_at_ns >= 0),
        CHECK (revision > 0),
        CHECK (length(snapshot_digest) = 64),
        CHECK (complete = 1),
        CHECK (
            (turnover_revision = 0
             AND turnover_last_observed_at_ns IS NULL
             AND turnover_snapshot_digest IS NULL
             AND turnover_snapshot_id IS NULL
             AND turnover_page_raw_references_json IS NULL
             AND turnover_catalog_revision IS NULL
             AND turnover_covered_keys_json IS NULL)
            OR
            (turnover_revision > 0
             AND turnover_last_observed_at_ns IS NOT NULL
             AND turnover_snapshot_digest IS NOT NULL
             AND length(turnover_snapshot_digest) = 64
             AND turnover_snapshot_id IS NOT NULL
             AND turnover_page_raw_references_json IS NOT NULL
             AND turnover_catalog_revision IS NOT NULL
             AND turnover_catalog_revision > 0
             AND turnover_covered_keys_json IS NOT NULL)
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS catalog_instrument (
        exchange TEXT NOT NULL,
        market TEXT NOT NULL,
        instrument_key TEXT NOT NULL,
        canonical_pair TEXT NOT NULL,
        wire_symbols_json BLOB NOT NULL,
        base_asset TEXT NOT NULL,
        quote_asset TEXT NOT NULL,
        settlement_asset TEXT,
        status TEXT NOT NULL,
        lifecycle_phase TEXT NOT NULL DEFAULT 'unknown',
        tradable INTEGER NOT NULL CHECK (tradable IN (0, 1)),
        lifecycle_json BLOB NOT NULL,
        tradable_at_ns INTEGER,
        tradable_at_source TEXT,
        first_seen_ns INTEGER NOT NULL,
        last_seen_ns INTEGER NOT NULL,
        turnover_value TEXT,
        turnover_method TEXT,
        turnover_currency TEXT,
        turnover_observed_at_ns INTEGER,
        turnover_raw_reference TEXT,
        raw_catalog_reference TEXT NOT NULL,
        present INTEGER NOT NULL CHECK (present IN (0, 1)),
        listing_state TEXT NOT NULL CHECK (
            listing_state IN (
                'baseline', 'pending', 'pending_official',
                'relist_pending', 'active_new'
            )
        ),
        first_tradable_seen_ns INTEGER,
        listing_generation INTEGER NOT NULL DEFAULT 0,
        last_terminal_seen_ns INTEGER,
        new_listing_started_at_ns INTEGER,
        new_listing_source TEXT,
        new_listing_eligible INTEGER NOT NULL DEFAULT 0
            CHECK (new_listing_eligible IN (0, 1)),
        PRIMARY KEY (exchange, market, instrument_key),
        CHECK (first_seen_ns >= 0),
        CHECK (last_seen_ns >= first_seen_ns),
        CHECK (listing_generation >= 0),
        CHECK (
            lifecycle_phase IN ('unknown', 'preopen', 'tradable', 'paused', 'delisted')
        ),
        CHECK (
            (lifecycle_phase = 'tradable' AND tradable = 1)
            OR (lifecycle_phase <> 'tradable' AND tradable = 0)
        ),
        CHECK (
            listing_state NOT IN ('pending', 'pending_official', 'relist_pending')
            OR tradable = 0
        ),
        CHECK (
            lifecycle_phase <> 'delisted'
            OR
            (listing_state = 'relist_pending'
             AND last_terminal_seen_ns = last_seen_ns)
        ),
        CHECK (
            (turnover_value IS NULL AND turnover_method IS NULL
             AND turnover_currency IS NULL)
            OR
            (turnover_value IS NOT NULL AND turnover_method IS NOT NULL
             AND turnover_currency IS NOT NULL)
        ),
        CHECK (
            (turnover_observed_at_ns IS NULL AND turnover_raw_reference IS NULL)
            OR
            (turnover_observed_at_ns IS NOT NULL
             AND turnover_observed_at_ns >= 0 AND turnover_raw_reference IS NOT NULL)
        ),
        CHECK (
            (tradable_at_ns IS NULL AND tradable_at_source IS NULL)
            OR
            (tradable_at_ns IS NOT NULL AND tradable_at_source IS NOT NULL)
        ),
        CHECK (
            (new_listing_started_at_ns IS NULL AND new_listing_source IS NULL)
            OR
            (new_listing_started_at_ns IS NOT NULL AND new_listing_source IS NOT NULL
             AND new_listing_started_at_ns >= 0)
        ),
        CHECK (
            (listing_state = 'active_new' AND new_listing_eligible = 1
             AND new_listing_started_at_ns IS NOT NULL)
            OR
            (listing_state <> 'active_new' AND new_listing_eligible = 0)
        ),
        CHECK (
            listing_state NOT IN ('baseline', 'pending', 'pending_official')
            OR new_listing_started_at_ns IS NULL
        ),
        CHECK (
            last_terminal_seen_ns IS NULL
            OR
            (last_terminal_seen_ns >= first_seen_ns
             AND last_terminal_seen_ns <= last_seen_ns
             AND listing_state IN ('relist_pending', 'active_new'))
        ),
        CHECK (
            listing_state <> 'relist_pending'
            OR last_terminal_seen_ns IS NOT NULL
        ),
        CHECK (
            listing_state <> 'active_new'
            OR last_terminal_seen_ns IS NULL
            OR new_listing_started_at_ns > last_terminal_seen_ns
        )
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS catalog_announcement_hint (
        exchange TEXT NOT NULL,
        market TEXT NOT NULL,
        hint_id TEXT NOT NULL,
        candidate_instrument_key TEXT,
        candidate_canonical_pair TEXT,
        announced_at_ns INTEGER NOT NULL,
        raw_reference TEXT NOT NULL,
        confirmed_at_ns INTEGER,
        PRIMARY KEY (exchange, market, hint_id),
        CHECK (announced_at_ns >= 0),
        CHECK (confirmed_at_ns IS NULL OR confirmed_at_ns >= announced_at_ns),
        CHECK (
            candidate_instrument_key IS NOT NULL
            OR candidate_canonical_pair IS NOT NULL
        )
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS catalog_announcement_candidate
        ON catalog_announcement_hint (
            exchange, market, candidate_instrument_key,
            candidate_canonical_pair, confirmed_at_ns
        )
    """,
    """
    CREATE TABLE IF NOT EXISTS catalog_change_outbox (
        event_id TEXT PRIMARY KEY,
        exchange TEXT NOT NULL,
        market TEXT NOT NULL,
        catalog_revision INTEGER NOT NULL,
        event_ordinal INTEGER NOT NULL,
        kind TEXT NOT NULL,
        instrument_key TEXT NOT NULL,
        payload_json BLOB NOT NULL,
        UNIQUE (exchange, market, catalog_revision, event_ordinal),
        CHECK (catalog_revision > 0),
        CHECK (event_ordinal >= 0),
        CHECK (
            kind IN (
                'added', 'updated', 'removed', 'new_listing',
                'announcement_confirmed'
            )
        )
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS catalog_change_outbox_scope
        ON catalog_change_outbox (
            exchange, market, catalog_revision, event_ordinal
        )
    """,
    """
    CREATE TABLE IF NOT EXISTS selection_state (
        exchange TEXT NOT NULL,
        market TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        state_revision INTEGER NOT NULL,
        catalog_revision INTEGER NOT NULL,
        turnover_revision INTEGER NOT NULL,
        entries_json BLOB NOT NULL,
        PRIMARY KEY (exchange, market, policy_id),
        CHECK (length(policy_id) = 64),
        CHECK (state_revision > 0),
        CHECK (catalog_revision > 0),
        CHECK (turnover_revision >= 0)
    )
    """,
    """
    CREATE TABLE IF NOT EXISTS selection_change_outbox (
        event_id TEXT PRIMARY KEY,
        exchange TEXT NOT NULL,
        market TEXT NOT NULL,
        policy_id TEXT NOT NULL,
        state_revision INTEGER NOT NULL,
        catalog_revision INTEGER NOT NULL,
        event_ordinal INTEGER NOT NULL,
        kind TEXT NOT NULL,
        instrument_key TEXT NOT NULL,
        payload_json BLOB NOT NULL,
        UNIQUE (
            exchange, market, policy_id, state_revision, event_ordinal
        ),
        CHECK (length(policy_id) = 64),
        CHECK (state_revision > 0),
        CHECK (catalog_revision > 0),
        CHECK (event_ordinal >= 0),
        CHECK (kind IN ('selection_added', 'selection_updated', 'selection_removed'))
    )
    """,
    """
    CREATE INDEX IF NOT EXISTS selection_change_outbox_scope
        ON selection_change_outbox (
            exchange, market, policy_id, state_revision, event_ordinal
        )
    """,
)

_EXPECTED_COLUMNS = {
    "catalog_scope_state": (
        "exchange",
        "market",
        "last_observed_at_ns",
        "snapshot_digest",
        "revision",
        "complete",
        "snapshot_id",
        "page_raw_references_json",
        "turnover_last_observed_at_ns",
        "turnover_snapshot_digest",
        "turnover_revision",
        "turnover_snapshot_id",
        "turnover_page_raw_references_json",
        "turnover_catalog_revision",
        "turnover_covered_keys_json",
    ),
    "catalog_instrument": (
        "exchange",
        "market",
        "instrument_key",
        "canonical_pair",
        "wire_symbols_json",
        "base_asset",
        "quote_asset",
        "settlement_asset",
        "status",
        "lifecycle_phase",
        "tradable",
        "lifecycle_json",
        "tradable_at_ns",
        "tradable_at_source",
        "first_seen_ns",
        "last_seen_ns",
        "turnover_value",
        "turnover_method",
        "turnover_currency",
        "turnover_observed_at_ns",
        "turnover_raw_reference",
        "raw_catalog_reference",
        "present",
        "listing_state",
        "first_tradable_seen_ns",
        "listing_generation",
        "last_terminal_seen_ns",
        "new_listing_started_at_ns",
        "new_listing_source",
        "new_listing_eligible",
    ),
    "catalog_announcement_hint": (
        "exchange",
        "market",
        "hint_id",
        "candidate_instrument_key",
        "candidate_canonical_pair",
        "announced_at_ns",
        "raw_reference",
        "confirmed_at_ns",
    ),
    "catalog_change_outbox": (
        "event_id",
        "exchange",
        "market",
        "catalog_revision",
        "event_ordinal",
        "kind",
        "instrument_key",
        "payload_json",
    ),
    "selection_state": (
        "exchange",
        "market",
        "policy_id",
        "state_revision",
        "catalog_revision",
        "turnover_revision",
        "entries_json",
    ),
    "selection_change_outbox": (
        "event_id",
        "exchange",
        "market",
        "policy_id",
        "state_revision",
        "catalog_revision",
        "event_ordinal",
        "kind",
        "instrument_key",
        "payload_json",
    ),
}


def _normalize_schema_sql(value: object) -> str | None:
    if value is None:
        return None
    return " ".join(str(value).split())


def _read_schema_contract(
    connection: sqlite3.Connection,
) -> tuple[
    dict[str, tuple[_ColumnContract, ...]],
    tuple[tuple[str, str, str, str | None], ...],
]:
    columns = {
        table: tuple(
            (
                str(row[1]),
                str(row[2]).upper(),
                int(row[3]),
                None if row[4] is None else str(row[4]),
                int(row[5]),
                int(row[6]),
            )
            for row in connection.execute(f"PRAGMA table_xinfo({table})")
        )
        for table in _EXPECTED_COLUMNS
    }
    objects = tuple(
        (
            str(row[0]),
            str(row[1]),
            str(row[2]),
            _normalize_schema_sql(row[3]),
        )
        for row in connection.execute(
            """
            SELECT type, name, tbl_name, sql
              FROM sqlite_schema
             WHERE lower(substr(name, 1, 7)) <> 'sqlite_'
             ORDER BY type, name, tbl_name
            """
        )
    )
    return columns, objects


def _build_expected_schema_contract() -> tuple[
    dict[str, tuple[_ColumnContract, ...]],
    tuple[tuple[str, str, str, str | None], ...],
]:
    reference = sqlite3.connect(":memory:")
    try:
        for statement in _SCHEMA:
            reference.execute(statement)
        return _read_schema_contract(reference)
    finally:
        reference.close()


_EXPECTED_COLUMN_DETAILS, _EXPECTED_SCHEMA_OBJECTS = _build_expected_schema_contract()


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    if value > 2**63 - 1:
        raise ValueError(f"{field} must fit a signed 64-bit integer")
    return value


def _resolve_scope(
    *,
    scope: CatalogScope | None,
    exchange: Exchange | str | None,
    market: Market | str | None,
) -> CatalogScope:
    if scope is not None:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be CatalogScope")
        if exchange is not None or market is not None:
            raise ValueError("provide scope or exchange/market, not both")
        return scope
    if exchange is None or market is None:
        raise ValueError("scope or both exchange and market are required")
    return CatalogScope(exchange, market)


def _typed_json_node(value: FrozenJsonPayload) -> object:
    if isinstance(value, Mapping):
        return [
            "object",
            [[key, _typed_json_node(value[key])] for key in sorted(value)],
        ]
    if isinstance(value, tuple):
        return ["array", [_typed_json_node(item) for item in value]]
    if value is None:
        return ["null"]
    if type(value) is bool:
        return ["bool", value]
    if type(value) is int:
        return ["int", str(value)]
    if type(value) is Decimal:
        return ["decimal", str(value)]
    if type(value) is str:
        return ["string", value]
    raise TypeError(f"unsupported frozen JSON value: {type(value).__name__}")


def _decode_typed_json_node(node: object) -> object:
    if type(node) is not list or not node or type(node[0]) is not str:
        raise RuntimeError("catalog lifecycle contains malformed typed JSON")
    tag = node[0]
    if tag == "null" and len(node) == 1:
        return None
    if tag == "bool" and len(node) == 2 and type(node[1]) is bool:
        return node[1]
    if tag == "int" and len(node) == 2 and type(node[1]) is str:
        try:
            return int(node[1])
        except ValueError as error:
            raise RuntimeError("catalog lifecycle contains invalid integer") from error
    if tag == "decimal" and len(node) == 2 and type(node[1]) is str:
        try:
            value = Decimal(node[1])
        except Exception as error:
            raise RuntimeError("catalog lifecycle contains invalid Decimal") from error
        if not value.is_finite():
            raise RuntimeError("catalog lifecycle contains non-finite Decimal")
        return value
    if tag == "string" and len(node) == 2 and type(node[1]) is str:
        return node[1]
    if tag == "array" and len(node) == 2 and type(node[1]) is list:
        return [_decode_typed_json_node(item) for item in node[1]]
    if tag == "object" and len(node) == 2 and type(node[1]) is list:
        result: dict[str, object] = {}
        for pair in node[1]:
            if (
                type(pair) is not list
                or len(pair) != 2
                or type(pair[0]) is not str
                or pair[0] in result
            ):
                raise RuntimeError("catalog lifecycle contains malformed object")
            result[pair[0]] = _decode_typed_json_node(pair[1])
        return result
    raise RuntimeError("catalog lifecycle contains unknown typed JSON node")


def _encode_typed_json(value: FrozenJsonPayload) -> bytes:
    return encode_json(_typed_json_node(value))


def _decode_typed_json(value: bytes) -> object:
    return _decode_typed_json_node(decode_json(value))


def _decode_string_array(value: object, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise CatalogStoreError(f"{field} must be stored as JSON bytes")
    decoded = decode_json(bytes(value))
    if type(decoded) is not list or any(type(item) is not str for item in decoded):
        raise RuntimeError(f"{field} must be a JSON string array")
    result = tuple(decoded)
    if len(set(result)) != len(result) or any(not item for item in result):
        raise RuntimeError(f"{field} must contain unique non-empty strings")
    return result


def _record_payload(record: InstrumentRecord) -> dict[str, object]:
    turnover: dict[str, object] | None = None
    if record.turnover is not None:
        turnover = {
            "value": str(record.turnover.value),
            "method": record.turnover.method.value,
            "currency": record.turnover.currency,
            "observed_at_ns": record.turnover.observed_at_ns,
            "raw_reference": record.turnover.raw_reference,
        }
    return {
        "exchange": record.exchange.value,
        "market": record.market.value,
        "instrument_key": record.instrument_key,
        "canonical_pair": record.canonical_pair,
        "wire_symbols": {
            key: record.wire_symbols[key] for key in sorted(record.wire_symbols)
        },
        "base_asset": record.base_asset,
        "quote_asset": record.quote_asset,
        "settlement_asset": record.settlement_asset,
        "status": record.status,
        "lifecycle_phase": record.lifecycle_phase.value,
        "tradable": record.tradable,
        "lifecycle": _typed_json_node(record.lifecycle),
        "tradable_at_ns": record.tradable_at_ns,
        "tradable_at_source": (
            None
            if record.tradable_at_source is None
            else record.tradable_at_source.value
        ),
        "turnover": turnover,
        "raw_catalog_reference": record.raw_catalog_reference,
    }


def _snapshot_digest(
    records: Sequence[InstrumentRecord],
    *,
    initial_lookback_ns: int,
) -> str:
    payload = {
        "initial_lookback_ns": initial_lookback_ns,
        "instruments": [_record_payload(record) for record in records],
    }
    return sha256(encode_json(payload)).hexdigest()


def _complete_catalog_digest(
    snapshot: CompleteCatalogSnapshot,
    *,
    initial_lookback_ns: int,
) -> str:
    payload = {
        "authoritative_empty": snapshot.authoritative_empty,
        "initial_lookback_ns": initial_lookback_ns,
        "instruments": [
            _record_payload(record)
            for record in sorted(
                snapshot.instruments,
                key=lambda item: item.instrument_key,
            )
        ],
        "pages": [_snapshot_page_payload(page) for page in snapshot.pages],
        "reported_total_count": snapshot.reported_total_count,
        "snapshot_id": snapshot.snapshot_id,
    }
    return sha256(encode_json(payload)).hexdigest()


def _turnover_snapshot_digest(snapshot: CompleteTurnoverSnapshot) -> str:
    payload = {
        "authoritative_empty": snapshot.authoritative_empty,
        "catalog_revision": snapshot.catalog_revision,
        "covered_instrument_keys": sorted(snapshot.covered_instrument_keys),
        "observations": [
            {
                "currency": item.currency,
                "instrument_key": item.instrument_key,
                "method": item.method.value,
                "raw_reference": item.raw_reference,
                "value": str(item.value),
            }
            for item in sorted(
                snapshot.observations,
                key=lambda item: item.instrument_key,
            )
        ],
        "pages": [_snapshot_page_payload(page) for page in snapshot.pages],
        "reported_total_count": snapshot.reported_total_count,
        "snapshot_id": snapshot.snapshot_id,
    }
    return sha256(encode_json(payload)).hexdigest()


def _snapshot_page_payload(page: SnapshotPage) -> dict[str, str | None]:
    return {
        "raw_reference": page.raw_reference,
        "request_cursor": page.request_cursor,
        "next_cursor": page.next_cursor,
    }


def _catalog_instrument_payload(record: CatalogInstrument) -> dict[str, object]:
    payload = _record_payload(record)
    payload.update(
        {
            "first_seen_ns": record.first_seen_ns,
            "first_tradable_seen_ns": record.first_tradable_seen_ns,
            "last_seen_ns": record.last_seen_ns,
            "last_terminal_seen_ns": record.last_terminal_seen_ns,
            "listing_generation": record.listing_generation,
            "listing_state": record.listing_state.value,
            "new_listing_eligible": record.new_listing_eligible,
            "new_listing_source": (
                None
                if record.new_listing_source is None
                else record.new_listing_source.value
            ),
            "new_listing_started_at_ns": record.new_listing_started_at_ns,
            "present": record.present,
        }
    )
    return payload


def _catalog_instrument_from_payload(value: object) -> CatalogInstrument:
    expected_fields = {
        "base_asset",
        "canonical_pair",
        "exchange",
        "first_seen_ns",
        "first_tradable_seen_ns",
        "instrument_key",
        "last_seen_ns",
        "last_terminal_seen_ns",
        "lifecycle",
        "lifecycle_phase",
        "listing_generation",
        "listing_state",
        "market",
        "new_listing_eligible",
        "new_listing_source",
        "new_listing_started_at_ns",
        "present",
        "quote_asset",
        "raw_catalog_reference",
        "settlement_asset",
        "status",
        "tradable",
        "tradable_at_ns",
        "tradable_at_source",
        "turnover",
        "wire_symbols",
    }
    if type(value) is not dict or set(value) != expected_fields:
        raise ValueError("selection instrument snapshot has malformed fields")

    turnover_node = value["turnover"]
    turnover: Turnover | None
    if turnover_node is None:
        turnover = None
    else:
        turnover_fields = {
            "currency",
            "method",
            "observed_at_ns",
            "raw_reference",
            "value",
        }
        if type(turnover_node) is not dict or set(turnover_node) != turnover_fields:
            raise ValueError("selection instrument turnover has malformed fields")
        encoded_value = turnover_node["value"]
        if type(encoded_value) is not str:
            raise TypeError("selection instrument turnover value must be a string")
        try:
            decimal_value = Decimal(encoded_value)
        except Exception as error:
            raise ValueError(
                "selection instrument turnover value is invalid"
            ) from error
        turnover = Turnover(
            value=decimal_value,
            method=turnover_node["method"],
            currency=turnover_node["currency"],
            observed_at_ns=turnover_node["observed_at_ns"],
            raw_reference=turnover_node["raw_reference"],
        )

    return CatalogInstrument(
        exchange=value["exchange"],
        market=value["market"],
        instrument_key=value["instrument_key"],
        canonical_pair=value["canonical_pair"],
        wire_symbols=value["wire_symbols"],
        base_asset=value["base_asset"],
        quote_asset=value["quote_asset"],
        settlement_asset=value["settlement_asset"],
        status=value["status"],
        lifecycle_phase=value["lifecycle_phase"],
        tradable=value["tradable"],
        lifecycle=_decode_typed_json_node(value["lifecycle"]),
        tradable_at_ns=value["tradable_at_ns"],
        tradable_at_source=value["tradable_at_source"],
        turnover=turnover,
        raw_catalog_reference=value["raw_catalog_reference"],
        first_seen_ns=value["first_seen_ns"],
        last_seen_ns=value["last_seen_ns"],
        present=value["present"],
        listing_state=value["listing_state"],
        first_tradable_seen_ns=value["first_tradable_seen_ns"],
        listing_generation=value["listing_generation"],
        last_terminal_seen_ns=value["last_terminal_seen_ns"],
        new_listing_started_at_ns=value["new_listing_started_at_ns"],
        new_listing_source=value["new_listing_source"],
        new_listing_eligible=value["new_listing_eligible"],
    )


def _announcement_hint_payload(
    hint: StoredAnnouncementHint,
) -> dict[str, object]:
    return {
        "announced_at_ns": hint.announced_at_ns,
        "candidate_canonical_pair": hint.candidate_canonical_pair,
        "candidate_instrument_key": hint.candidate_instrument_key,
        "confirmed_at_ns": hint.confirmed_at_ns,
        "hint_id": hint.hint_id,
        "raw_reference": hint.raw_reference,
    }


def _resolve_announcement_target(
    row: sqlite3.Row,
    current: Mapping[str, CatalogInstrument],
) -> str | None:
    candidate_key = (
        None
        if row["candidate_instrument_key"] is None
        else str(row["candidate_instrument_key"])
    )
    candidate_pair = (
        None
        if row["candidate_canonical_pair"] is None
        else str(row["candidate_canonical_pair"])
    )
    if candidate_key is not None:
        instrument = current.get(candidate_key)
        if (
            instrument is not None
            and instrument.present
            and instrument.tradable
            and (candidate_pair is None or instrument.canonical_pair == candidate_pair)
        ):
            return instrument.instrument_key
        return None
    if candidate_pair is None:
        return None
    matches = tuple(
        item.instrument_key
        for item in current.values()
        if item.present and item.tradable and item.canonical_pair == candidate_pair
    )
    return matches[0] if len(matches) == 1 else None


def _control_event_id(
    scope: CatalogScope,
    *,
    revision: int,
    ordinal: int,
    kind: str,
    instrument_key: str,
) -> str:
    identity = {
        "exchange": scope.exchange.value,
        "instrument_key": instrument_key,
        "kind": kind,
        "market": scope.market.value,
        "ordinal": ordinal,
        "revision": revision,
    }
    return sha256(encode_json(identity)).hexdigest()


def _selection_entry_payload(entry: SelectionEntry) -> dict[str, object]:
    return {
        "admission_priority": int(entry.admission_priority),
        "instrument": _catalog_instrument_payload(entry.instrument),
        "reasons": int(entry.reasons),
        "top_exit_started_at_ns": entry.top_exit_started_at_ns,
        "top_n_rank": entry.top_n_rank,
    }


def _selection_state_entries_payload(
    state: SelectionState,
) -> list[dict[str, object]]:
    return [
        {
            "instrument_key": key,
            "instrument": _catalog_instrument_payload(entry.instrument),
            "reasons": int(entry.reasons),
            "top_exit_started_at_ns": entry.top_exit_started_at_ns,
            "top_n_rank": entry.top_n_rank,
        }
        for key, entry in sorted(state.entries.items())
    ]


def _selection_event_id(
    scope: CatalogScope,
    *,
    policy_id: str,
    state_revision: int,
    ordinal: int,
    kind: str,
    instrument_key: str,
) -> str:
    identity = {
        "exchange": scope.exchange.value,
        "instrument_key": instrument_key,
        "kind": kind,
        "market": scope.market.value,
        "ordinal": ordinal,
        "policy_id": policy_id,
        "state_revision": state_revision,
    }
    return sha256(encode_json(identity)).hexdigest()


def _validate_sha256(value: object, *, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _is_lock_contention(error: sqlite3.OperationalError) -> bool:
    error_code = getattr(error, "sqlite_errorcode", None)
    return type(error_code) is int and error_code & 0xFF in {
        sqlite3.SQLITE_BUSY,
        sqlite3.SQLITE_LOCKED,
    }


def _initialize_schema(connection: sqlite3.Connection) -> None:
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA synchronous = FULL")
    mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
    if mode is None or str(mode[0]).casefold() != "wal":
        raise RuntimeError("catalog store requires SQLite WAL mode")
    connection.execute("BEGIN IMMEDIATE")
    try:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if version not in (0, _SCHEMA_VERSION):
            raise RuntimeError(f"unsupported catalog schema version {version}")
        if version == 0:
            for statement in _SCHEMA:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
        actual_columns, actual_objects = _read_schema_contract(connection)
        for table, expected in _EXPECTED_COLUMN_DETAILS.items():
            if actual_columns[table] != expected:
                raise RuntimeError(
                    f"{table} schema does not match version {_SCHEMA_VERSION}"
                )
        if actual_objects != _EXPECTED_SCHEMA_OBJECTS:
            raise RuntimeError(
                f"catalog schema objects do not match version {_SCHEMA_VERSION}"
            )
    except BaseException:
        connection.rollback()
        raise
    else:
        connection.commit()


def _initialize_schema_with_retry(connection: sqlite3.Connection) -> None:
    deadline = time.monotonic() + _OPEN_RETRY_TIMEOUT_SECONDS
    delay = _INITIAL_RETRY_DELAY_SECONDS
    last_contention_error: sqlite3.OperationalError | None = None
    while True:
        if last_contention_error is not None and time.monotonic() >= deadline:
            raise last_contention_error
        try:
            _initialize_schema(connection)
            return
        except sqlite3.OperationalError as error:
            if connection.in_transaction:
                connection.rollback()
            if not _is_lock_contention(error):
                raise
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise
            last_contention_error = error
            time.sleep(min(delay, remaining))
            delay = min(delay * 2, _MAX_RETRY_DELAY_SECONDS)


def _turnover_from_row(row: sqlite3.Row) -> Turnover | None:
    value = row["turnover_value"]
    if value is None:
        return None
    return Turnover(
        value=Decimal(str(value)),
        method=TurnoverMethod(str(row["turnover_method"])),
        currency=str(row["turnover_currency"]),
        observed_at_ns=(
            None
            if row["turnover_observed_at_ns"] is None
            else int(row["turnover_observed_at_ns"])
        ),
        raw_reference=(
            None
            if row["turnover_raw_reference"] is None
            else str(row["turnover_raw_reference"])
        ),
    )


def _instrument_from_row(row: sqlite3.Row) -> CatalogInstrument:
    wire_symbols = decode_json(bytes(row["wire_symbols_json"]))
    lifecycle = _decode_typed_json(bytes(row["lifecycle_json"]))
    if type(wire_symbols) is not dict or type(lifecycle) is not dict:
        raise RuntimeError("catalog JSON columns contain invalid object values")
    return CatalogInstrument(
        exchange=str(row["exchange"]),
        market=str(row["market"]),
        instrument_key=str(row["instrument_key"]),
        canonical_pair=str(row["canonical_pair"]),
        wire_symbols=wire_symbols,
        base_asset=str(row["base_asset"]),
        quote_asset=str(row["quote_asset"]),
        settlement_asset=(
            None if row["settlement_asset"] is None else str(row["settlement_asset"])
        ),
        status=str(row["status"]),
        lifecycle_phase=str(row["lifecycle_phase"]),
        tradable=bool(row["tradable"]),
        lifecycle=lifecycle,
        tradable_at_ns=(
            None if row["tradable_at_ns"] is None else int(row["tradable_at_ns"])
        ),
        tradable_at_source=(
            None
            if row["tradable_at_source"] is None
            else str(row["tradable_at_source"])
        ),
        turnover=_turnover_from_row(row),
        raw_catalog_reference=str(row["raw_catalog_reference"]),
        first_seen_ns=int(row["first_seen_ns"]),
        last_seen_ns=int(row["last_seen_ns"]),
        present=bool(row["present"]),
        listing_state=str(row["listing_state"]),
        first_tradable_seen_ns=(
            None
            if row["first_tradable_seen_ns"] is None
            else int(row["first_tradable_seen_ns"])
        ),
        listing_generation=int(row["listing_generation"]),
        last_terminal_seen_ns=(
            None
            if row["last_terminal_seen_ns"] is None
            else int(row["last_terminal_seen_ns"])
        ),
        new_listing_started_at_ns=(
            None
            if row["new_listing_started_at_ns"] is None
            else int(row["new_listing_started_at_ns"])
        ),
        new_listing_source=(
            None
            if row["new_listing_source"] is None
            else str(row["new_listing_source"])
        ),
        new_listing_eligible=bool(row["new_listing_eligible"]),
    )


def _hint_from_row(row: sqlite3.Row) -> StoredAnnouncementHint:
    return StoredAnnouncementHint(
        scope=CatalogScope(str(row["exchange"]), str(row["market"])),
        hint_id=str(row["hint_id"]),
        candidate_instrument_key=(
            None
            if row["candidate_instrument_key"] is None
            else str(row["candidate_instrument_key"])
        ),
        candidate_canonical_pair=(
            None
            if row["candidate_canonical_pair"] is None
            else str(row["candidate_canonical_pair"])
        ),
        announced_at_ns=int(row["announced_at_ns"]),
        raw_reference=str(row["raw_reference"]),
        confirmed_at_ns=(
            None if row["confirmed_at_ns"] is None else int(row["confirmed_at_ns"])
        ),
    )


def _with_presence(record: CatalogInstrument, *, present: bool) -> CatalogInstrument:
    return CatalogInstrument(
        exchange=record.exchange,
        market=record.market,
        instrument_key=record.instrument_key,
        canonical_pair=record.canonical_pair,
        wire_symbols=record.wire_symbols,
        base_asset=record.base_asset,
        quote_asset=record.quote_asset,
        settlement_asset=record.settlement_asset,
        status=record.status,
        lifecycle_phase=record.lifecycle_phase,
        tradable=record.tradable,
        lifecycle=mutable_json_copy(record.lifecycle),
        tradable_at_ns=record.tradable_at_ns,
        tradable_at_source=record.tradable_at_source,
        turnover=record.turnover,
        raw_catalog_reference=record.raw_catalog_reference,
        first_seen_ns=record.first_seen_ns,
        last_seen_ns=record.last_seen_ns,
        present=present,
        listing_state=record.listing_state,
        first_tradable_seen_ns=record.first_tradable_seen_ns,
        listing_generation=record.listing_generation,
        last_terminal_seen_ns=record.last_terminal_seen_ns,
        new_listing_started_at_ns=record.new_listing_started_at_ns,
        new_listing_source=record.new_listing_source,
        new_listing_eligible=record.new_listing_eligible,
    )


def _with_listing_state(
    record: CatalogInstrument,
    listing_state: ListingState,
) -> CatalogInstrument:
    retains_episode = listing_state in {
        ListingState.ACTIVE_NEW,
        ListingState.RELIST_PENDING,
    }
    last_terminal_seen_ns = (
        record.last_seen_ns
        if (
            listing_state is ListingState.RELIST_PENDING
            and record.lifecycle_phase is LifecyclePhase.DELISTED
        )
        else record.last_terminal_seen_ns
        if retains_episode
        else None
    )
    return CatalogInstrument(
        exchange=record.exchange,
        market=record.market,
        instrument_key=record.instrument_key,
        canonical_pair=record.canonical_pair,
        wire_symbols=record.wire_symbols,
        base_asset=record.base_asset,
        quote_asset=record.quote_asset,
        settlement_asset=record.settlement_asset,
        status=record.status,
        lifecycle_phase=record.lifecycle_phase,
        tradable=record.tradable,
        lifecycle=mutable_json_copy(record.lifecycle),
        tradable_at_ns=record.tradable_at_ns,
        tradable_at_source=record.tradable_at_source,
        turnover=record.turnover,
        raw_catalog_reference=record.raw_catalog_reference,
        first_seen_ns=record.first_seen_ns,
        last_seen_ns=record.last_seen_ns,
        present=record.present,
        listing_state=listing_state,
        first_tradable_seen_ns=record.first_tradable_seen_ns,
        listing_generation=record.listing_generation,
        last_terminal_seen_ns=last_terminal_seen_ns,
        new_listing_started_at_ns=(
            record.new_listing_started_at_ns if retains_episode else None
        ),
        new_listing_source=(record.new_listing_source if retains_episode else None),
        new_listing_eligible=listing_state is ListingState.ACTIVE_NEW,
    )


def _materialize_record(
    record: InstrumentRecord,
    *,
    prior: CatalogInstrument | None,
    observed_at_ns: int,
) -> CatalogInstrument:
    first_seen_ns = observed_at_ns if prior is None else prior.first_seen_ns
    listing_state = ListingState.PENDING if prior is None else prior.listing_state
    if record.lifecycle_phase is LifecyclePhase.DELISTED:
        listing_state = ListingState.RELIST_PENDING
    elif record.tradable and listing_state in {
        ListingState.PENDING,
        ListingState.PENDING_OFFICIAL,
        ListingState.RELIST_PENDING,
    }:
        # Pending states are consumed only after the complete snapshot confirms
        # tradability. Keep this intermediate value inside the public truth table.
        listing_state = ListingState.BASELINE
    retains_episode = listing_state in {
        ListingState.ACTIVE_NEW,
        ListingState.RELIST_PENDING,
    }
    if record.tradable_at_ns is None:
        if (
            prior is not None
            and prior.lifecycle_phase is not LifecyclePhase.DELISTED
            and prior.tradable_at_ns is not None
        ):
            tradable_at_ns = prior.tradable_at_ns
            tradable_at_source = prior.tradable_at_source
        elif record.tradable:
            tradable_at_ns = observed_at_ns
            tradable_at_source = TradableAtSource.FIRST_TRADABLE_SEEN
        else:
            tradable_at_ns = None
            tradable_at_source = None
    else:
        tradable_at_ns = record.tradable_at_ns
        tradable_at_source = record.tradable_at_source
    return CatalogInstrument(
        exchange=record.exchange,
        market=record.market,
        instrument_key=record.instrument_key,
        canonical_pair=record.canonical_pair,
        wire_symbols=record.wire_symbols,
        base_asset=record.base_asset,
        quote_asset=record.quote_asset,
        settlement_asset=record.settlement_asset,
        status=record.status,
        lifecycle_phase=record.lifecycle_phase,
        tradable=record.tradable,
        lifecycle=mutable_json_copy(record.lifecycle),
        tradable_at_ns=tradable_at_ns,
        tradable_at_source=tradable_at_source,
        turnover=(
            record.turnover
            if (
                record.turnover is not None
                or prior is None
                or prior.quote_asset != record.quote_asset
            )
            else prior.turnover
        ),
        raw_catalog_reference=record.raw_catalog_reference,
        first_seen_ns=first_seen_ns,
        last_seen_ns=observed_at_ns,
        present=True,
        listing_state=listing_state,
        first_tradable_seen_ns=(
            observed_at_ns
            if record.tradable
            and (prior is None or prior.first_tradable_seen_ns is None)
            else None
            if prior is None
            else prior.first_tradable_seen_ns
        ),
        listing_generation=(0 if prior is None else prior.listing_generation),
        last_terminal_seen_ns=(
            observed_at_ns
            if record.lifecycle_phase is LifecyclePhase.DELISTED
            else prior.last_terminal_seen_ns
            if prior is not None and retains_episode
            else None
        ),
        new_listing_started_at_ns=(
            prior.new_listing_started_at_ns
            if prior is not None and retains_episode
            else None
        ),
        new_listing_source=(
            prior.new_listing_source if prior is not None and retains_episode else None
        ),
        new_listing_eligible=listing_state is ListingState.ACTIVE_NEW,
    )


def materialize_initial_catalog_instrument(
    record: InstrumentRecord,
    *,
    observed_at_ns: int,
    initial_lookback_ns: int,
) -> CatalogInstrument:
    """Materialize one record using CatalogStore's initial-baseline semantics."""

    if type(record) is not InstrumentRecord:
        raise TypeError("record must be an exact InstrumentRecord")
    observed_at = _nonnegative_int(observed_at_ns, field="observed_at_ns")
    lookback = _nonnegative_int(
        initial_lookback_ns,
        field="initial_lookback_ns",
    )
    if record.tradable_at_source is TradableAtSource.FIRST_TRADABLE_SEEN:
        raise ValueError("first_tradable_seen time is owned by CatalogStore")
    if (
        record.turnover is not None
        and record.turnover.observed_at_ns is not None
        and record.turnover.observed_at_ns > observed_at
    ):
        raise ValueError(
            "turnover observed_at_ns must not be after catalog observation"
        )

    item = _materialize_record(
        record,
        prior=None,
        observed_at_ns=observed_at,
    )
    official_recent = (
        lookback > 0
        and item.tradable_at_source is not None
        and item.tradable_at_source.is_official
        and item.tradable_at_ns is not None
        and item.tradable_at_ns <= observed_at
        and observed_at - item.tradable_at_ns <= lookback
    )
    if item.tradable and official_recent:
        return replace(
            item,
            listing_state=ListingState.ACTIVE_NEW,
            listing_generation=1,
            first_tradable_seen_ns=observed_at,
            last_terminal_seen_ns=None,
            new_listing_started_at_ns=item.tradable_at_ns,
            new_listing_source=item.tradable_at_source,
            new_listing_eligible=True,
        )
    if item.lifecycle_phase is LifecyclePhase.PREOPEN:
        listing_state = (
            ListingState.PENDING_OFFICIAL if official_recent else ListingState.PENDING
        )
    elif item.lifecycle_phase is LifecyclePhase.DELISTED:
        listing_state = ListingState.RELIST_PENDING
    else:
        listing_state = ListingState.BASELINE
    return _with_listing_state(item, listing_state)


def _provider_fields(record: CatalogInstrument) -> tuple[object, ...]:
    return (
        record.canonical_pair,
        tuple(sorted(record.wire_symbols.items())),
        record.base_asset,
        record.quote_asset,
        record.settlement_asset,
        record.status,
        record.lifecycle_phase,
        record.tradable,
        _typed_json_node(record.lifecycle),
        record.tradable_at_ns,
        record.tradable_at_source,
        record.raw_catalog_reference,
        record.present,
        record.last_terminal_seen_ns,
    )


@dataclass(frozen=True, slots=True)
class _PriorRecord:
    instrument: CatalogInstrument
    listing_state: ListingState


class CatalogStore:
    """Synchronous durable catalog state; call from a worker outside event loops."""

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
            isolation_level=None,
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
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        self._connection.close()

    def _load_prior_records(self, scope: CatalogScope) -> dict[str, _PriorRecord]:
        rows = self._connection.execute(
            """
            SELECT *
              FROM catalog_instrument
             WHERE exchange = ? AND market = ?
            """,
            (scope.exchange.value, scope.market.value),
        ).fetchall()
        return {
            str(row["instrument_key"]): _PriorRecord(
                instrument=_instrument_from_row(row),
                listing_state=ListingState(str(row["listing_state"])),
            )
            for row in rows
        }

    def _selection_state_from_row(
        self,
        scope: CatalogScope,
        row: sqlite3.Row,
    ) -> SelectionState:
        decoded = decode_json(bytes(row["entries_json"]))
        if type(decoded) is not list:
            raise RuntimeError("selection state entries must be a JSON array")
        entries: dict[str, SelectionEntry] = {}
        for node in decoded:
            if type(node) is not dict or set(node) != {
                "instrument_key",
                "instrument",
                "reasons",
                "top_exit_started_at_ns",
                "top_n_rank",
            }:
                raise RuntimeError("selection state contains a malformed entry")
            instrument_key = node["instrument_key"]
            reasons = node["reasons"]
            if type(instrument_key) is not str or not instrument_key:
                raise RuntimeError("selection state has an invalid instrument key")
            if type(reasons) is not int:
                raise RuntimeError("selection state reasons must be an integer")
            try:
                instrument = _catalog_instrument_from_payload(node["instrument"])
                if instrument.scope != scope:
                    raise ValueError("selection instrument scope mismatch")
                if instrument.instrument_key != instrument_key:
                    raise ValueError("selection instrument key mismatch")
                entry = SelectionEntry(
                    instrument=instrument,
                    reasons=SelectionReason(reasons),
                    top_n_rank=node["top_n_rank"],
                    top_exit_started_at_ns=node["top_exit_started_at_ns"],
                )
            except (TypeError, ValueError) as error:
                raise RuntimeError(
                    "selection state contains invalid entry values"
                ) from error
            if instrument_key in entries:
                raise RuntimeError("selection state contains duplicate instrument keys")
            entries[instrument_key] = entry
        return SelectionState(
            scope=scope,
            catalog_revision=int(row["catalog_revision"]),
            turnover_revision=int(row["turnover_revision"]),
            policy_id=str(row["policy_id"]),
            revision=int(row["state_revision"]),
            entries=entries,
        )

    def load_selection_state(
        self,
        scope: CatalogScope,
        policy_id: str,
    ) -> SelectionState | None:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        policy = _validate_sha256(policy_id, field="policy_id")
        self._connection.execute("BEGIN")
        try:
            row = self._connection.execute(
                """
                SELECT policy_id, state_revision, catalog_revision,
                       turnover_revision, entries_json
                  FROM selection_state
                 WHERE exchange = ? AND market = ? AND policy_id = ?
                """,
                (scope.exchange.value, scope.market.value, policy),
            ).fetchone()
            state = None if row is None else self._selection_state_from_row(scope, row)
            self._connection.commit()
        except BaseException:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise
        return state

    def apply_catalog_snapshot(
        self,
        snapshot: CompleteCatalogSnapshot,
        *,
        initial_lookback_ns: int = 0,
    ) -> CatalogChanges:
        if type(snapshot) is not CompleteCatalogSnapshot:
            raise TypeError("snapshot must be CompleteCatalogSnapshot")
        lookback = _nonnegative_int(
            initial_lookback_ns,
            field="initial_lookback_ns",
        )
        return self._apply_snapshot(
            scope=snapshot.scope,
            observed_at_ns=snapshot.observed_at_ns,
            instruments=snapshot.instruments,
            initial_lookback_ns=lookback,
            _snapshot_id=snapshot.snapshot_id,
            _page_raw_references=snapshot.page_raw_references,
            _provided_snapshot_digest=_complete_catalog_digest(
                snapshot,
                initial_lookback_ns=lookback,
            ),
        )

    def _apply_snapshot(
        self,
        *,
        observed_at_ns: int,
        instruments: Iterable[InstrumentRecord],
        initial_lookback_ns: int = 0,
        complete: bool = True,
        scope: CatalogScope | None = None,
        exchange: Exchange | str | None = None,
        market: Market | str | None = None,
        _snapshot_id: str | None = None,
        _page_raw_references: tuple[str, ...] | None = None,
        _provided_snapshot_digest: str | None = None,
    ) -> CatalogChanges:
        resolved_scope = _resolve_scope(
            scope=scope,
            exchange=exchange,
            market=market,
        )
        observed_at = _nonnegative_int(observed_at_ns, field="observed_at_ns")
        lookback = _nonnegative_int(
            initial_lookback_ns,
            field="initial_lookback_ns",
        )
        if type(complete) is not bool:
            raise TypeError("complete must be a boolean")
        if not complete:
            raise ValueError("catalog snapshots must be complete")
        records = tuple(instruments)
        if any(type(record) is not InstrumentRecord for record in records):
            raise TypeError("instruments must contain exact InstrumentRecord values")
        keys: set[str] = set()
        for record in records:
            if record.scope != resolved_scope:
                raise ValueError("instrument scope does not match snapshot scope")
            if record.tradable_at_source is TradableAtSource.FIRST_TRADABLE_SEEN:
                raise ValueError("first_tradable_seen time is owned by CatalogStore")
            if (
                record.turnover is not None
                and record.turnover.observed_at_ns is not None
                and record.turnover.observed_at_ns > observed_at
            ):
                raise ValueError(
                    "turnover observed_at_ns must not be after catalog observation"
                )
            if record.instrument_key in keys:
                raise ValueError(
                    f"duplicate instrument_key in snapshot: {record.instrument_key}"
                )
            keys.add(record.instrument_key)
        ordered = tuple(sorted(records, key=lambda item: item.instrument_key))
        digest = (
            _snapshot_digest(ordered, initial_lookback_ns=lookback)
            if _provided_snapshot_digest is None
            else _provided_snapshot_digest
        )
        snapshot_id = (
            f"legacy:{resolved_scope.exchange.value}:{resolved_scope.market.value}:"
            f"{observed_at}"
            if _snapshot_id is None
            else _snapshot_id
        )
        page_raw_references = (
            tuple(sorted({item.raw_catalog_reference for item in ordered}))
            or (f"legacy:authoritative-empty:{snapshot_id}",)
            if _page_raw_references is None
            else _page_raw_references
        )

        self._connection.execute("BEGIN IMMEDIATE")
        try:
            state = self._connection.execute(
                """
                SELECT last_observed_at_ns, snapshot_digest, revision, complete
                  FROM catalog_scope_state
                 WHERE exchange = ? AND market = ?
                """,
                (resolved_scope.exchange.value, resolved_scope.market.value),
            ).fetchone()
            if state is not None:
                if not bool(state["complete"]):
                    raise RuntimeError("persisted catalog state is incomplete")
                last_observed_at = int(state["last_observed_at_ns"])
                if observed_at < last_observed_at:
                    raise StaleCatalogSnapshotError(
                        "catalog snapshot observed_at_ns moved backwards"
                    )
                if observed_at == last_observed_at:
                    if digest != str(state["snapshot_digest"]):
                        raise CatalogSnapshotConflictError(
                            "same-time catalog snapshot has conflicting contents"
                        )
                    result = CatalogChanges(
                        scope=resolved_scope,
                        observed_at_ns=observed_at,
                        is_initial_baseline=False,
                        idempotent=True,
                        added=(),
                        updated=(),
                        removed=(),
                        new_listings=(),
                        confirmed_announcement_hints=(),
                        revision=int(state["revision"]),
                        digest_sha256=str(state["snapshot_digest"]),
                    )
                    self._connection.commit()
                    return result

            is_initial = state is None
            revision = 1 if state is None else int(state["revision"]) + 1
            prior = self._load_prior_records(resolved_scope)
            added: list[CatalogInstrument] = []
            updated: list[CatalogInstrument] = []
            new_listings: list[CatalogInstrument] = []
            current: dict[str, CatalogInstrument] = {}

            for record in ordered:
                old = prior.get(record.instrument_key)
                item = (
                    materialize_initial_catalog_instrument(
                        record,
                        observed_at_ns=observed_at,
                        initial_lookback_ns=lookback,
                    )
                    if is_initial and old is None
                    else _materialize_record(
                        record,
                        prior=None if old is None else old.instrument,
                        observed_at_ns=observed_at,
                    )
                )
                is_new_listing = False
                relisting_terminal_seen_ns: int | None = None
                if old is None:
                    has_observed_official_time = (
                        item.tradable_at_source is not None
                        and item.tradable_at_source.is_official
                        and item.tradable_at_ns is not None
                        and item.tradable_at_ns <= observed_at
                    )
                    if is_initial:
                        listing_state = item.listing_state
                        is_new_listing = listing_state is ListingState.ACTIVE_NEW
                    elif item.tradable:
                        if (
                            item.tradable_at_ns is not None
                            and item.tradable_at_ns > observed_at
                        ):
                            item = replace(
                                item,
                                tradable_at_ns=observed_at,
                                tradable_at_source=(
                                    TradableAtSource.FIRST_TRADABLE_SEEN
                                ),
                            )
                        listing_state = ListingState.ACTIVE_NEW
                        is_new_listing = True
                    elif item.lifecycle_phase is LifecyclePhase.PREOPEN:
                        listing_state = (
                            ListingState.PENDING_OFFICIAL
                            if has_observed_official_time
                            else ListingState.PENDING
                        )
                    elif item.lifecycle_phase is LifecyclePhase.DELISTED:
                        listing_state = ListingState.RELIST_PENDING
                    else:
                        listing_state = ListingState.BASELINE
                else:
                    listing_state = old.listing_state
                    if item.lifecycle_phase is LifecyclePhase.DELISTED:
                        listing_state = ListingState.RELIST_PENDING
                    is_relisting = (
                        listing_state is ListingState.RELIST_PENDING
                        and item.lifecycle_phase is LifecyclePhase.TRADABLE
                    )
                    if is_relisting:
                        terminal_seen_at = old.instrument.last_terminal_seen_ns
                        if terminal_seen_at is None:
                            raise RuntimeError(
                                "relist-pending catalog state lacks terminal evidence"
                            )
                        relisting_terminal_seen_ns = terminal_seen_at
                        has_new_official_time = (
                            item.tradable_at_source is not None
                            and item.tradable_at_source.is_official
                            and item.tradable_at_ns is not None
                            and item.tradable_at_ns <= observed_at
                            and item.tradable_at_ns > terminal_seen_at
                        )
                        if not has_new_official_time:
                            item = replace(
                                item,
                                tradable_at_ns=observed_at,
                                tradable_at_source=(
                                    TradableAtSource.FIRST_TRADABLE_SEEN
                                ),
                            )
                    is_pending_activation = (
                        listing_state
                        in {ListingState.PENDING, ListingState.PENDING_OFFICIAL}
                        and item.tradable
                    )
                    if is_pending_activation:
                        official_floor = (
                            old.instrument.tradable_at_ns
                            if listing_state is ListingState.PENDING_OFFICIAL
                            else old.instrument.first_seen_ns
                        )
                        has_eligible_official_time = (
                            item.tradable_at_source is not None
                            and item.tradable_at_source.is_official
                            and item.tradable_at_ns is not None
                            and official_floor is not None
                            and official_floor <= item.tradable_at_ns <= observed_at
                        )
                        if not has_eligible_official_time:
                            item = replace(
                                item,
                                tradable_at_ns=observed_at,
                                tradable_at_source=(
                                    TradableAtSource.FIRST_TRADABLE_SEEN
                                ),
                            )
                    if is_pending_activation or is_relisting:
                        listing_state = ListingState.ACTIVE_NEW
                        is_new_listing = True
                if is_new_listing and not is_initial:
                    item = replace(
                        item,
                        listing_state=listing_state,
                        listing_generation=(
                            1 if old is None else old.instrument.listing_generation + 1
                        ),
                        first_tradable_seen_ns=observed_at,
                        last_terminal_seen_ns=relisting_terminal_seen_ns,
                        new_listing_started_at_ns=item.tradable_at_ns,
                        new_listing_source=item.tradable_at_source,
                        new_listing_eligible=True,
                    )
                elif not is_new_listing:
                    item = _with_listing_state(item, listing_state)
                current[item.instrument_key] = item

                if old is None or not old.instrument.present:
                    added.append(item)
                elif _provider_fields(old.instrument) != _provider_fields(item):
                    updated.append(item)
                if is_new_listing:
                    new_listings.append(item)

            removed = [
                _with_presence(old.instrument, present=False)
                for key, old in sorted(prior.items())
                if old.instrument.present and key not in current
            ]
            if removed:
                self._connection.executemany(
                    """
                    UPDATE catalog_instrument
                       SET present = 0
                     WHERE exchange = ? AND market = ? AND instrument_key = ?
                    """,
                    [
                        (
                            resolved_scope.exchange.value,
                            resolved_scope.market.value,
                            item.instrument_key,
                        )
                        for item in removed
                    ],
                )

            for item in current.values():
                turnover = item.turnover
                self._connection.execute(
                    """
                    INSERT INTO catalog_instrument (
                        exchange, market, instrument_key, canonical_pair,
                        wire_symbols_json, base_asset, quote_asset,
                        settlement_asset, status, tradable, lifecycle_json,
                        lifecycle_phase,
                        tradable_at_ns, tradable_at_source, first_seen_ns,
                        last_seen_ns, turnover_value, turnover_method,
                        turnover_currency, turnover_observed_at_ns,
                        turnover_raw_reference, raw_catalog_reference,
                        present, listing_state, first_tradable_seen_ns,
                        listing_generation, last_terminal_seen_ns,
                        new_listing_started_at_ns,
                        new_listing_source, new_listing_eligible
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (exchange, market, instrument_key) DO UPDATE SET
                        canonical_pair = excluded.canonical_pair,
                        wire_symbols_json = excluded.wire_symbols_json,
                        base_asset = excluded.base_asset,
                        quote_asset = excluded.quote_asset,
                        settlement_asset = excluded.settlement_asset,
                        status = excluded.status,
                        lifecycle_phase = excluded.lifecycle_phase,
                        tradable = excluded.tradable,
                        lifecycle_json = excluded.lifecycle_json,
                        tradable_at_ns = excluded.tradable_at_ns,
                        tradable_at_source = excluded.tradable_at_source,
                        last_seen_ns = excluded.last_seen_ns,
                        turnover_value = excluded.turnover_value,
                        turnover_method = excluded.turnover_method,
                        turnover_currency = excluded.turnover_currency,
                        turnover_observed_at_ns = excluded.turnover_observed_at_ns,
                        turnover_raw_reference = excluded.turnover_raw_reference,
                        raw_catalog_reference = excluded.raw_catalog_reference,
                        present = 1,
                        listing_state = excluded.listing_state,
                        first_tradable_seen_ns = excluded.first_tradable_seen_ns,
                        listing_generation = excluded.listing_generation,
                        last_terminal_seen_ns = excluded.last_terminal_seen_ns,
                        new_listing_started_at_ns = excluded.new_listing_started_at_ns,
                        new_listing_source = excluded.new_listing_source,
                        new_listing_eligible = excluded.new_listing_eligible
                    """,
                    (
                        item.exchange.value,
                        item.market.value,
                        item.instrument_key,
                        item.canonical_pair,
                        encode_json(dict(item.wire_symbols)),
                        item.base_asset,
                        item.quote_asset,
                        item.settlement_asset,
                        item.status,
                        int(item.tradable),
                        _encode_typed_json(item.lifecycle),
                        item.lifecycle_phase.value,
                        item.tradable_at_ns,
                        (
                            None
                            if item.tradable_at_source is None
                            else item.tradable_at_source.value
                        ),
                        item.first_seen_ns,
                        item.last_seen_ns,
                        None if turnover is None else str(turnover.value),
                        None if turnover is None else turnover.method.value,
                        None if turnover is None else turnover.currency,
                        None if turnover is None else turnover.observed_at_ns,
                        None if turnover is None else turnover.raw_reference,
                        item.raw_catalog_reference,
                        item.listing_state.value,
                        item.first_tradable_seen_ns,
                        item.listing_generation,
                        item.last_terminal_seen_ns,
                        item.new_listing_started_at_ns,
                        (
                            None
                            if item.new_listing_source is None
                            else item.new_listing_source.value
                        ),
                        int(item.new_listing_eligible),
                    ),
                )

            candidate_hint_rows = self._connection.execute(
                """
                    SELECT *
                      FROM catalog_announcement_hint
                     WHERE exchange = ? AND market = ?
                       AND confirmed_at_ns IS NULL
                       AND announced_at_ns <= ?
                     ORDER BY hint_id
                """,
                (
                    resolved_scope.exchange.value,
                    resolved_scope.market.value,
                    observed_at,
                ),
            ).fetchall()
            confirmed_matches: list[tuple[sqlite3.Row, str]] = []
            for row in candidate_hint_rows:
                target_key = _resolve_announcement_target(row, current)
                if target_key is not None:
                    confirmed_matches.append((row, target_key))
            if confirmed_matches:
                self._connection.executemany(
                    """
                    UPDATE catalog_announcement_hint
                       SET confirmed_at_ns = ?
                     WHERE exchange = ? AND market = ? AND hint_id = ?
                    """,
                    [
                        (
                            observed_at,
                            resolved_scope.exchange.value,
                            resolved_scope.market.value,
                            str(row["hint_id"]),
                        )
                        for row, _target_key in confirmed_matches
                    ],
                )

            event_specs: list[tuple[str, str, dict[str, object]]] = []
            catalog_deltas: list[CatalogDelta] = []
            for item in sorted(added, key=lambda value: value.instrument_key):
                old = prior.get(item.instrument_key)
                previous = None if old is None else old.instrument
                catalog_deltas.append(
                    CatalogDelta(
                        kind="added",
                        instrument_key=item.instrument_key,
                        previous=previous,
                        current=item,
                    )
                )
                event_specs.append(
                    (
                        "added",
                        item.instrument_key,
                        {
                            "current": _catalog_instrument_payload(item),
                            "previous": (
                                None
                                if previous is None
                                else _catalog_instrument_payload(previous)
                            ),
                        },
                    )
                )
            for item in sorted(updated, key=lambda value: value.instrument_key):
                previous = prior[item.instrument_key].instrument
                catalog_deltas.append(
                    CatalogDelta(
                        kind="updated",
                        instrument_key=item.instrument_key,
                        previous=previous,
                        current=item,
                    )
                )
                event_specs.append(
                    (
                        "updated",
                        item.instrument_key,
                        {
                            "current": _catalog_instrument_payload(item),
                            "previous": _catalog_instrument_payload(previous),
                        },
                    )
                )
            for item in sorted(removed, key=lambda value: value.instrument_key):
                previous = prior[item.instrument_key].instrument
                catalog_deltas.append(
                    CatalogDelta(
                        kind="removed",
                        instrument_key=item.instrument_key,
                        previous=previous,
                        current=item,
                    )
                )
                event_specs.append(
                    (
                        "removed",
                        item.instrument_key,
                        {
                            "current": _catalog_instrument_payload(item),
                            "previous": _catalog_instrument_payload(previous),
                        },
                    )
                )
            for item in sorted(new_listings, key=lambda value: value.instrument_key):
                old = prior.get(item.instrument_key)
                previous = None if old is None else old.instrument
                catalog_deltas.append(
                    CatalogDelta(
                        kind="new_listing",
                        instrument_key=item.instrument_key,
                        previous=previous,
                        current=item,
                    )
                )
                event_specs.append(
                    (
                        "new_listing",
                        item.instrument_key,
                        {
                            "current": _catalog_instrument_payload(item),
                            "previous": (
                                None
                                if previous is None
                                else _catalog_instrument_payload(previous)
                            ),
                        },
                    )
                )
            for row, instrument_key in confirmed_matches:
                previous_hint = _hint_from_row(row)
                current_hint = replace(previous_hint, confirmed_at_ns=observed_at)
                catalog_deltas.append(
                    CatalogDelta(
                        kind="announcement_confirmed",
                        instrument_key=instrument_key,
                        previous=previous_hint,
                        current=current_hint,
                    )
                )
                event_specs.append(
                    (
                        "announcement_confirmed",
                        instrument_key,
                        {
                            "current": _announcement_hint_payload(current_hint),
                            "previous": _announcement_hint_payload(previous_hint),
                        },
                    )
                )

            control_event_ids: list[str] = []
            for ordinal, (kind, instrument_key, payload) in enumerate(event_specs):
                event_id = _control_event_id(
                    resolved_scope,
                    revision=revision,
                    ordinal=ordinal,
                    kind=kind,
                    instrument_key=instrument_key,
                )
                self._connection.execute(
                    """
                    INSERT INTO catalog_change_outbox (
                        event_id, exchange, market, catalog_revision,
                        event_ordinal, kind, instrument_key, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        resolved_scope.exchange.value,
                        resolved_scope.market.value,
                        revision,
                        ordinal,
                        kind,
                        instrument_key,
                        encode_json(payload),
                    ),
                )
                control_event_ids.append(event_id)

            self._connection.execute(
                """
                INSERT INTO catalog_scope_state (
                    exchange, market, last_observed_at_ns, snapshot_digest,
                    revision, complete, snapshot_id, page_raw_references_json
                ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                ON CONFLICT (exchange, market) DO UPDATE SET
                    last_observed_at_ns = excluded.last_observed_at_ns,
                    snapshot_digest = excluded.snapshot_digest,
                    revision = excluded.revision,
                    complete = 1,
                    snapshot_id = excluded.snapshot_id,
                    page_raw_references_json = excluded.page_raw_references_json
                """,
                (
                    resolved_scope.exchange.value,
                    resolved_scope.market.value,
                    observed_at,
                    digest,
                    revision,
                    snapshot_id,
                    encode_json(list(page_raw_references)),
                ),
            )
            confirmed = tuple(
                StoredAnnouncementHint(
                    scope=resolved_scope,
                    hint_id=str(row["hint_id"]),
                    announced_at_ns=int(row["announced_at_ns"]),
                    raw_reference=str(row["raw_reference"]),
                    candidate_instrument_key=(
                        None
                        if row["candidate_instrument_key"] is None
                        else str(row["candidate_instrument_key"])
                    ),
                    candidate_canonical_pair=(
                        None
                        if row["candidate_canonical_pair"] is None
                        else str(row["candidate_canonical_pair"])
                    ),
                    confirmed_at_ns=observed_at,
                )
                for row, _target_key in confirmed_matches
            )
            result = CatalogChanges(
                scope=resolved_scope,
                observed_at_ns=observed_at,
                is_initial_baseline=is_initial,
                idempotent=False,
                added=tuple(added),
                updated=tuple(updated),
                removed=tuple(removed),
                new_listings=tuple(new_listings),
                confirmed_announcement_hints=confirmed,
                revision=revision,
                digest_sha256=digest,
                control_event_ids=tuple(control_event_ids),
                deltas=tuple(catalog_deltas),
            )
            self._connection.commit()
        except BaseException:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise

        return result

    def apply_turnover_snapshot(
        self,
        snapshot: CompleteTurnoverSnapshot,
    ) -> TurnoverChanges:
        if type(snapshot) is not CompleteTurnoverSnapshot:
            raise TypeError("snapshot must be CompleteTurnoverSnapshot")
        digest = _turnover_snapshot_digest(snapshot)
        scope = snapshot.scope
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            state = self._connection.execute(
                """
                SELECT revision, last_observed_at_ns, turnover_last_observed_at_ns,
                       turnover_snapshot_digest, turnover_revision
                  FROM catalog_scope_state
                 WHERE exchange = ? AND market = ?
                """,
                (scope.exchange.value, scope.market.value),
            ).fetchone()
            if state is None:
                raise CatalogRevisionConflictError(
                    "turnover snapshot requires an existing catalog revision"
                )
            catalog_revision = int(state["revision"])
            if snapshot.catalog_revision != catalog_revision:
                raise CatalogRevisionConflictError(
                    "turnover snapshot catalog revision does not match current catalog"
                )
            if snapshot.observed_at_ns < int(state["last_observed_at_ns"]):
                raise StaleTurnoverSnapshotError(
                    "turnover snapshot cannot predate its bound catalog revision"
                )

            previous_observed_at = state["turnover_last_observed_at_ns"]
            if previous_observed_at is not None:
                last_observed_at = int(previous_observed_at)
                if snapshot.observed_at_ns < last_observed_at:
                    raise StaleTurnoverSnapshotError(
                        "turnover snapshot observed_at_ns moved backwards"
                    )
                if snapshot.observed_at_ns == last_observed_at:
                    if digest != str(state["turnover_snapshot_digest"]):
                        raise TurnoverSnapshotConflictError(
                            "same-time turnover snapshot has conflicting contents"
                        )
                    result = TurnoverChanges(
                        scope=scope,
                        catalog_revision=catalog_revision,
                        observed_at_ns=snapshot.observed_at_ns,
                        revision=int(state["turnover_revision"]),
                        idempotent=True,
                        changed_instrument_keys=(),
                    )
                    self._connection.commit()
                    return result

            rows = self._connection.execute(
                """
                SELECT instrument_key, quote_asset, turnover_value,
                       turnover_method, turnover_currency,
                       turnover_observed_at_ns, turnover_raw_reference,
                       present
                  FROM catalog_instrument
                 WHERE exchange = ? AND market = ?
                """,
                (scope.exchange.value, scope.market.value),
            ).fetchall()
            current_rows = {str(row["instrument_key"]): row for row in rows}
            present_keys = {
                key for key, row in current_rows.items() if bool(row["present"])
            }
            covered = set(snapshot.covered_instrument_keys)
            outside = covered.difference(present_keys)
            if outside:
                raise CatalogRevisionConflictError(
                    "turnover coverage contains keys outside the current catalog: "
                    + ", ".join(sorted(outside))
                )

            observations = {item.instrument_key: item for item in snapshot.observations}
            changed: list[str] = []
            for instrument_key in sorted(current_rows):
                row = current_rows[instrument_key]
                observation = (
                    observations.get(instrument_key)
                    if instrument_key in covered
                    else None
                )
                if observation is not None and observation.currency != str(
                    row["quote_asset"]
                ):
                    raise ValueError(
                        "turnover currency must match the catalog quote_asset"
                    )
                previous = (
                    row["turnover_value"],
                    row["turnover_method"],
                    row["turnover_currency"],
                    row["turnover_observed_at_ns"],
                    row["turnover_raw_reference"],
                )
                current = (
                    (None, None, None, None, None)
                    if observation is None
                    else (
                        str(observation.value),
                        observation.method.value,
                        observation.currency,
                        snapshot.observed_at_ns,
                        observation.raw_reference,
                    )
                )
                if previous != current:
                    changed.append(instrument_key)
                self._connection.execute(
                    """
                    UPDATE catalog_instrument
                       SET turnover_value = ?, turnover_method = ?,
                           turnover_currency = ?, turnover_observed_at_ns = ?,
                           turnover_raw_reference = ?
                     WHERE exchange = ? AND market = ? AND instrument_key = ?
                    """,
                    (
                        *current,
                        scope.exchange.value,
                        scope.market.value,
                        instrument_key,
                    ),
                )

            revision = int(state["turnover_revision"]) + 1
            self._connection.execute(
                """
                UPDATE catalog_scope_state
                   SET turnover_last_observed_at_ns = ?,
                       turnover_snapshot_digest = ?, turnover_revision = ?,
                       turnover_snapshot_id = ?,
                       turnover_page_raw_references_json = ?,
                       turnover_catalog_revision = ?,
                       turnover_covered_keys_json = ?
                 WHERE exchange = ? AND market = ?
                """,
                (
                    snapshot.observed_at_ns,
                    digest,
                    revision,
                    snapshot.snapshot_id,
                    encode_json(list(snapshot.page_raw_references)),
                    snapshot.catalog_revision,
                    encode_json(sorted(snapshot.covered_instrument_keys)),
                    scope.exchange.value,
                    scope.market.value,
                ),
            )
            result = TurnoverChanges(
                scope=scope,
                catalog_revision=catalog_revision,
                observed_at_ns=snapshot.observed_at_ns,
                revision=revision,
                idempotent=False,
                changed_instrument_keys=tuple(changed),
            )
            self._connection.commit()
        except BaseException:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise
        return result

    def commit_selection(
        self,
        result: SelectionResult,
        *,
        expected_catalog_revision: int,
        expected_turnover_revision: int,
        expected_state_revision: int | None,
    ) -> SelectionState:
        if type(result) is not SelectionResult:
            raise TypeError("result must be SelectionResult")
        expected_catalog = _nonnegative_int(
            expected_catalog_revision,
            field="expected_catalog_revision",
        )
        if expected_catalog == 0:
            raise ValueError("expected_catalog_revision must be positive")
        expected_turnover = _nonnegative_int(
            expected_turnover_revision,
            field="expected_turnover_revision",
        )
        if expected_state_revision is None:
            expected_state = None
        else:
            expected_state = _nonnegative_int(
                expected_state_revision,
                field="expected_state_revision",
            )
            if expected_state == 0:
                raise ValueError("expected_state_revision must be positive")
        scope = result.scope
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            header = self._connection.execute(
                """
                SELECT revision, turnover_revision
                  FROM catalog_scope_state
                 WHERE exchange = ? AND market = ?
                """,
                (scope.exchange.value, scope.market.value),
            ).fetchone()
            if header is None or int(header["revision"]) != expected_catalog:
                raise CatalogRevisionConflictError(
                    "expected catalog revision does not match current catalog"
                )
            if int(header["turnover_revision"]) != expected_turnover:
                raise CatalogRevisionConflictError(
                    "expected turnover revision does not match current turnover"
                )
            if (
                result.catalog_revision != expected_catalog
                or result.next_state.catalog_revision != expected_catalog
            ):
                raise CatalogRevisionConflictError(
                    "selection result catalog revision does not match expectation"
                )
            if (
                result.turnover_revision != expected_turnover
                or result.next_state.turnover_revision != expected_turnover
            ):
                raise CatalogRevisionConflictError(
                    "selection result turnover revision does not match expectation"
                )

            current_instruments = {
                key: value.instrument
                for key, value in self._load_prior_records(scope).items()
            }
            for key, entry in result.entries.items():
                if current_instruments.get(key) != entry.instrument:
                    raise SelectionStateConflictError(
                        "selection entry does not match the current catalog"
                    )
                if not entry.instrument.present or not entry.instrument.tradable:
                    raise SelectionStateConflictError(
                        "selection entry must be present and tradable"
                    )

            row = self._connection.execute(
                """
                SELECT policy_id, state_revision, catalog_revision,
                       turnover_revision, entries_json
                  FROM selection_state
                 WHERE exchange = ? AND market = ? AND policy_id = ?
                """,
                (scope.exchange.value, scope.market.value, result.policy_id),
            ).fetchone()
            previous = (
                None if row is None else self._selection_state_from_row(scope, row)
            )
            actual_state_revision = None if previous is None else previous.revision
            if actual_state_revision != expected_state:
                raise SelectionStateConflictError(
                    "expected state revision does not match persisted state revision"
                )
            carried_revision = 0 if previous is None else previous.revision
            if result.next_state.revision != carried_revision:
                raise SelectionStateConflictError(
                    "selection result was not derived from the expected state revision"
                )
            previous_entries = {} if previous is None else previous.entries
            delta_by_key = {delta.instrument_key: delta for delta in result.deltas}
            all_keys = set(previous_entries) | set(result.entries)
            required_delta_keys = {
                key
                for key in all_keys
                if previous_entries.get(key) != result.entries.get(key)
            }
            if set(delta_by_key) != required_delta_keys:
                raise SelectionStateConflictError(
                    "selection deltas do not match the persisted previous state"
                )
            for key, delta in delta_by_key.items():
                if delta.previous != previous_entries.get(
                    key
                ) or delta.current != result.entries.get(key):
                    raise SelectionStateConflictError(
                        "selection delta values do not match the persisted state"
                    )

            state_revision = 1 if previous is None else previous.revision + 1
            persisted = replace(result.next_state, revision=state_revision)
            self._connection.execute(
                """
                INSERT INTO selection_state (
                    exchange, market, policy_id, state_revision,
                    catalog_revision, turnover_revision, entries_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (exchange, market, policy_id) DO UPDATE SET
                    state_revision = excluded.state_revision,
                    catalog_revision = excluded.catalog_revision,
                    turnover_revision = excluded.turnover_revision,
                    entries_json = excluded.entries_json
                """,
                (
                    scope.exchange.value,
                    scope.market.value,
                    result.policy_id,
                    state_revision,
                    result.catalog_revision,
                    result.turnover_revision,
                    encode_json(_selection_state_entries_payload(persisted)),
                ),
            )

            for ordinal, delta in enumerate(result.deltas):
                kind = (
                    "selection_added"
                    if delta.previous is None
                    else "selection_removed"
                    if delta.current is None
                    else "selection_updated"
                )
                event_id = _selection_event_id(
                    scope,
                    policy_id=result.policy_id,
                    state_revision=state_revision,
                    ordinal=ordinal,
                    kind=kind,
                    instrument_key=delta.instrument_key,
                )
                payload = {
                    "catalog_revision": result.catalog_revision,
                    "current": (
                        None
                        if delta.current is None
                        else _selection_entry_payload(delta.current)
                    ),
                    "policy_id": result.policy_id,
                    "previous": (
                        None
                        if delta.previous is None
                        else _selection_entry_payload(delta.previous)
                    ),
                    "state_revision": state_revision,
                    "turnover_revision": result.turnover_revision,
                }
                self._connection.execute(
                    """
                    INSERT INTO selection_change_outbox (
                        event_id, exchange, market, policy_id, state_revision,
                        catalog_revision, event_ordinal, kind,
                        instrument_key, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_id,
                        scope.exchange.value,
                        scope.market.value,
                        result.policy_id,
                        state_revision,
                        result.catalog_revision,
                        ordinal,
                        kind,
                        delta.instrument_key,
                        encode_json(payload),
                    ),
                )
            self._connection.commit()
        except BaseException:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise
        return persisted

    def load_catalog(
        self,
        scope: CatalogScope,
        *,
        include_missing: bool = False,
    ) -> CatalogSnapshot:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be CatalogScope")
        if type(include_missing) is not bool:
            raise TypeError("include_missing must be a boolean")
        query = """
            SELECT *
              FROM catalog_instrument
             WHERE exchange = ? AND market = ?
        """
        if not include_missing:
            query += " AND present = 1"
        query += " ORDER BY instrument_key"
        self._connection.execute("BEGIN")
        try:
            state = self._connection.execute(
                """
                SELECT last_observed_at_ns, snapshot_digest, revision, complete
                  FROM catalog_scope_state
                 WHERE exchange = ? AND market = ?
                """,
                (scope.exchange.value, scope.market.value),
            ).fetchone()
            rows = self._connection.execute(
                query,
                (scope.exchange.value, scope.market.value),
            ).fetchall()
            self._connection.commit()
        except BaseException:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise
        return CatalogSnapshot(
            scope=scope,
            observed_at_ns=(
                None if state is None else int(state["last_observed_at_ns"])
            ),
            revision=0 if state is None else int(state["revision"]),
            digest_sha256=(None if state is None else str(state["snapshot_digest"])),
            complete=False if state is None else bool(state["complete"]),
            instruments=tuple(_instrument_from_row(row) for row in rows),
        )

    def load_view(self, scope: CatalogScope) -> CatalogView:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        self._connection.execute("BEGIN")
        try:
            state = self._connection.execute(
                """
                SELECT last_observed_at_ns, snapshot_digest, revision,
                       snapshot_id, page_raw_references_json,
                       turnover_last_observed_at_ns,
                       turnover_snapshot_digest, turnover_revision,
                       turnover_catalog_revision, turnover_snapshot_id,
                       turnover_page_raw_references_json,
                       turnover_covered_keys_json
                  FROM catalog_scope_state
                 WHERE exchange = ? AND market = ?
                """,
                (scope.exchange.value, scope.market.value),
            ).fetchone()
            rows = self._connection.execute(
                """
                SELECT *
                  FROM catalog_instrument
                 WHERE exchange = ? AND market = ?
                 ORDER BY instrument_key
                """,
                (scope.exchange.value, scope.market.value),
            ).fetchall()
            self._connection.commit()
        except BaseException:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise
        return CatalogView(
            scope=scope,
            catalog_observed_at_ns=(
                None if state is None else int(state["last_observed_at_ns"])
            ),
            catalog_revision=0 if state is None else int(state["revision"]),
            catalog_digest_sha256=(
                None if state is None else str(state["snapshot_digest"])
            ),
            catalog_snapshot_id=(None if state is None else str(state["snapshot_id"])),
            catalog_page_raw_references=(
                ()
                if state is None
                else _decode_string_array(
                    state["page_raw_references_json"],
                    field="catalog page references",
                )
            ),
            turnover_observed_at_ns=(
                None
                if state is None or state["turnover_last_observed_at_ns"] is None
                else int(state["turnover_last_observed_at_ns"])
            ),
            turnover_revision=(0 if state is None else int(state["turnover_revision"])),
            turnover_digest_sha256=(
                None
                if state is None or state["turnover_snapshot_digest"] is None
                else str(state["turnover_snapshot_digest"])
            ),
            turnover_catalog_revision=(
                None
                if state is None or state["turnover_catalog_revision"] is None
                else int(state["turnover_catalog_revision"])
            ),
            turnover_snapshot_id=(
                None
                if state is None or state["turnover_snapshot_id"] is None
                else str(state["turnover_snapshot_id"])
            ),
            turnover_page_raw_references=(
                ()
                if state is None or state["turnover_page_raw_references_json"] is None
                else _decode_string_array(
                    state["turnover_page_raw_references_json"],
                    field="turnover page references",
                )
            ),
            turnover_covered_instrument_keys=(
                ()
                if state is None or state["turnover_covered_keys_json"] is None
                else _decode_string_array(
                    state["turnover_covered_keys_json"],
                    field="turnover covered instrument keys",
                )
            ),
            instruments=tuple(_instrument_from_row(row) for row in rows),
        )

    def pending_changes(
        self,
        scope: CatalogScope,
    ) -> tuple[CatalogControlChange, ...]:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        rows = self._connection.execute(
            """
            SELECT event_id, catalog_revision, kind, instrument_key, payload_json,
                   stream_order, stream_revision, event_ordinal
              FROM (
                    SELECT event_id, catalog_revision, kind, instrument_key,
                           payload_json, 0 AS stream_order,
                           catalog_revision AS stream_revision, event_ordinal
                      FROM catalog_change_outbox
                     WHERE exchange = ? AND market = ?
                    UNION ALL
                    SELECT event_id, catalog_revision, kind, instrument_key,
                           payload_json, 1 AS stream_order,
                           state_revision AS stream_revision, event_ordinal
                      FROM selection_change_outbox
                     WHERE exchange = ? AND market = ?
              )
             ORDER BY catalog_revision, stream_order, stream_revision,
                      event_ordinal, event_id
            """,
            (
                scope.exchange.value,
                scope.market.value,
                scope.exchange.value,
                scope.market.value,
            ),
        ).fetchall()
        changes: list[CatalogControlChange] = []
        for row in rows:
            payload = decode_json(bytes(row["payload_json"]))
            if type(payload) is not dict:
                raise RuntimeError("catalog outbox payload must be a JSON object")
            changes.append(
                CatalogControlChange(
                    event_id=str(row["event_id"]),
                    scope=scope,
                    catalog_revision=int(row["catalog_revision"]),
                    kind=str(row["kind"]),
                    instrument_key=str(row["instrument_key"]),
                    payload=payload,
                )
            )
        return tuple(changes)

    def ack_change(self, event_id: str) -> bool:
        if type(event_id) is not str or not event_id:
            raise ValueError("event_id must be a non-empty string")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            catalog_cursor = self._connection.execute(
                "DELETE FROM catalog_change_outbox WHERE event_id = ?",
                (event_id,),
            )
            selection_cursor = self._connection.execute(
                "DELETE FROM selection_change_outbox WHERE event_id = ?",
                (event_id,),
            )
            deleted = catalog_cursor.rowcount + selection_cursor.rowcount > 0
            self._connection.commit()
        except BaseException:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise
        return deleted

    def load_active_new_listings(
        self,
        scope: CatalogScope,
        *,
        now_ns: int,
        capture_duration_ns: int,
    ) -> tuple[CatalogInstrument, ...]:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be CatalogScope")
        now = _nonnegative_int(now_ns, field="now_ns")
        duration = _nonnegative_int(
            capture_duration_ns,
            field="capture_duration_ns",
        )
        if duration == 0:
            return ()
        candidates = self._connection.execute(
            """
            SELECT *
              FROM catalog_instrument
             WHERE exchange = ? AND market = ?
               AND present = 1 AND tradable = 1
               AND listing_state = 'active_new'
               AND new_listing_eligible = 1
             ORDER BY instrument_key
            """,
            (scope.exchange.value, scope.market.value),
        ).fetchall()
        active: list[CatalogInstrument] = []
        for row in candidates:
            item = _instrument_from_row(row)
            tradable_at_ns = item.new_listing_started_at_ns
            if (
                tradable_at_ns is not None
                and now >= tradable_at_ns
                and now - tradable_at_ns < duration
            ):
                active.append(item)
        return tuple(active)

    def record_announcement_hint(self, hint: AnnouncementHint) -> bool:
        if type(hint) is not AnnouncementHint:
            raise TypeError("hint must be AnnouncementHint")
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            existing = self._connection.execute(
                """
                SELECT candidate_instrument_key, candidate_canonical_pair,
                       announced_at_ns, raw_reference
                  FROM catalog_announcement_hint
                 WHERE exchange = ? AND market = ? AND hint_id = ?
                """,
                (
                    hint.scope.exchange.value,
                    hint.scope.market.value,
                    hint.hint_id,
                ),
            ).fetchone()
            if existing is not None:
                identity = (
                    (
                        None
                        if existing["candidate_instrument_key"] is None
                        else str(existing["candidate_instrument_key"])
                    ),
                    (
                        None
                        if existing["candidate_canonical_pair"] is None
                        else str(existing["candidate_canonical_pair"])
                    ),
                    int(existing["announced_at_ns"]),
                    str(existing["raw_reference"]),
                )
                expected = (
                    hint.candidate_instrument_key,
                    hint.candidate_canonical_pair,
                    hint.announced_at_ns,
                    hint.raw_reference,
                )
                if identity != expected:
                    raise AnnouncementHintConflictError(
                        "announcement hint ID has conflicting contents"
                    )
                self._connection.commit()
                return False
            self._connection.execute(
                """
                INSERT INTO catalog_announcement_hint (
                    exchange, market, hint_id, candidate_instrument_key,
                    candidate_canonical_pair, announced_at_ns, raw_reference,
                    confirmed_at_ns
                ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    hint.scope.exchange.value,
                    hint.scope.market.value,
                    hint.hint_id,
                    hint.candidate_instrument_key,
                    hint.candidate_canonical_pair,
                    hint.announced_at_ns,
                    hint.raw_reference,
                ),
            )
            self._connection.commit()
            return True
        except BaseException:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise

    def load_announcement_hints(
        self,
        scope: CatalogScope,
    ) -> tuple[StoredAnnouncementHint, ...]:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be CatalogScope")
        rows = self._connection.execute(
            """
            SELECT *
              FROM catalog_announcement_hint
             WHERE exchange = ? AND market = ?
             ORDER BY hint_id
            """,
            (scope.exchange.value, scope.market.value),
        ).fetchall()
        return tuple(_hint_from_row(row) for row in rows)
