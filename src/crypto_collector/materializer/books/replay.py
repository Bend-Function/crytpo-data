from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum

from crypto_collector.domain.types import Exchange, IntegrityMode, Market
from crypto_collector.materializer.datasets.quality import (
    QualityEventKind,
    QualityStreamKey,
    TimedQualityEvent,
)
from crypto_collector.materializer.models import (
    ConnectionGenerationScope,
    SourceLocator,
    SourceRecord,
    TimeSource,
)
from crypto_collector.materializer.ordering import canonical_replay_order
from crypto_collector.materializer.time_policy import EventTimePolicy

_MAX_SIGNED_INT64 = 2**63 - 1
_INPUT_MAX_PRECISION = 38
_INPUT_MAX_SCALE = 18
_FIXED_NONNEGATIVE_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")


class BookGapReason(StrEnum):
    MISSING_AUTHORITY = "missing_authority"
    SEQUENCE_MISMATCH = "sequence_mismatch"
    CHECKSUM_PROTOCOL_VIOLATION = "checksum_protocol_violation"
    CHECKSUM_ERROR = "checksum_error"
    CONNECTION_GENERATION_CHANGED = "connection_generation_changed"
    WORKER_BOUNDARY = "worker_boundary"
    EXPLICIT_GAP = "explicit_gap"
    RECONNECT = "reconnect"
    SEQUENCE_ERROR = "sequence_error"
    INVALID_PAYLOAD = "invalid_payload"


@dataclass(frozen=True, slots=True, order=True)
class BookScope:
    exchange: Exchange
    market: Market
    instrument_key: str

    def __post_init__(self) -> None:
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        if type(self.market) is not Market:
            raise TypeError("market must be Market")
        if type(self.instrument_key) is not str or not self.instrument_key:
            raise ValueError("instrument_key must be non-empty")

    @property
    def quality_key(self) -> QualityStreamKey:
        return QualityStreamKey(
            self.exchange,
            self.market,
            self.instrument_key,
            "book_live",
        )


@dataclass(frozen=True, slots=True)
class TimedBookRecord:
    source: SourceRecord
    effective_event_time_ns: int
    time_source: TimeSource

    def __post_init__(self) -> None:
        if type(self.source) is not SourceRecord:
            raise TypeError("source must be SourceRecord")
        if (
            type(self.effective_event_time_ns) is not int
            or not 0 <= self.effective_event_time_ns <= _MAX_SIGNED_INT64
        ):
            raise ValueError("effective_event_time_ns must fit non-negative int64")
        if type(self.time_source) is not TimeSource:
            raise TypeError("time_source must be TimeSource")
        envelope = self.source.envelope
        native = envelope.event_time_ns
        received = envelope.received_at_ns
        if self.time_source is TimeSource.EVENT:
            consistent = native is not None and self.effective_event_time_ns == native
        elif self.time_source is TimeSource.RECEIVE_MISSING:
            consistent = native is None and self.effective_event_time_ns == received
        else:
            consistent = (
                native is not None
                and native != received
                and self.effective_event_time_ns == received
            )
        if not consistent:
            raise ValueError(
                "time_source must match source envelope and effective event time"
            )


def apply_book_time_policy(
    records: Iterable[SourceRecord],
    policy: EventTimePolicy,
) -> tuple[TimedBookRecord, ...]:
    if type(policy) is not EventTimePolicy:
        raise TypeError("policy must be EventTimePolicy")
    timed: list[TimedBookRecord] = []
    locators: set[SourceLocator] = set()
    for source in records:
        if type(source) is not SourceRecord:
            raise TypeError("records must contain SourceRecord values")
        if source.locator in locators:
            raise ValueError("book source locators must be unique")
        locators.add(source.locator)
        envelope = source.envelope
        if envelope.logical_stream not in {"book_live", "book_live_bootstrap"}:
            raise ValueError("book replay accepts only authoritative live streams")
        chosen = policy.choose(
            event_time_ns=envelope.event_time_ns,
            received_at_ns=envelope.received_at_ns,
        )
        timed.append(
            TimedBookRecord(
                source=source,
                effective_event_time_ns=chosen.effective_event_time_ns,
                time_source=chosen.time_source,
            )
        )
    return tuple(timed)


@dataclass(frozen=True, slots=True)
class BookValidityTransition:
    effective_event_time_ns: int
    book_valid: bool
    reason: BookGapReason | None
    source_locator: SourceLocator


@dataclass(frozen=True, slots=True)
class ReplayedBook:
    scope: BookScope | None
    book_valid: bool
    integrity_mode: IntegrityMode
    gap_reason: BookGapReason | None
    bids: tuple[tuple[Decimal, Decimal], ...]
    asks: tuple[tuple[Decimal, Decimal], ...]
    sequence_id: int | None
    connection_scope: ConnectionGenerationScope | None
    authoritative_ancestor: SourceLocator | None
    authoritative_source_stream: str | None
    accepted_update_count: int
    heartbeat_count: int
    sequence_reset_count: int
    last_book_update_time_ns: int | None
    last_activity_time_ns: int | None
    validity_transitions: tuple[BookValidityTransition, ...]
    accepted_update_times_ns: tuple[int, ...]
    heartbeat_times_ns: tuple[int, ...]
    sequence_reset_times_ns: tuple[int, ...]
    lineage_manifest_sha256s: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _OkxMessage:
    timed: TimedBookRecord
    action: str
    bids: tuple[tuple[Decimal, Decimal], ...]
    asks: tuple[tuple[Decimal, Decimal], ...]
    sequence_id: int
    previous_sequence_id: int
    checksum: int

    @property
    def is_snapshot(self) -> bool:
        return self.action == "snapshot"


def _json_int(value: object, *, field_name: str, allow_minus_one: bool = False) -> int:
    minimum = -1 if allow_minus_one else 0
    if type(value) is not int or not minimum <= value <= _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must be a JSON integer >= {minimum}")
    return value


def _decimal_string(value: object, *, field_name: str, allow_zero: bool) -> Decimal:
    if (
        type(value) is not str
        or _FIXED_NONNEGATIVE_DECIMAL.fullmatch(value) is None
    ):
        raise ValueError(f"{field_name} must be a non-negative fixed-point string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f"{field_name} must be a finite decimal string") from error
    if not parsed.is_finite() or parsed < 0 or (not allow_zero and parsed == 0):
        raise ValueError(f"{field_name} is outside the supported decimal domain")
    _, digits, exponent = parsed.as_tuple()
    assert isinstance(exponent, int)
    precision = len(digits) + max(exponent, 0)
    scale = max(-exponent, 0)
    integer_digits = 0 if parsed.is_zero() else max(parsed.adjusted() + 1, 0)
    if (
        precision > _INPUT_MAX_PRECISION
        or scale > _INPUT_MAX_SCALE
        or integer_digits > _INPUT_MAX_PRECISION - _INPUT_MAX_SCALE
    ):
        raise ValueError(f"{field_name} exceeds decimal(38,18) bounds")
    return parsed


def _levels(value: object, *, side: str) -> tuple[tuple[Decimal, Decimal], ...]:
    if type(value) is not list:
        raise ValueError(f"{side} must be a JSON array")
    levels: list[tuple[Decimal, Decimal]] = []
    prices: set[Decimal] = set()
    for raw in value:
        if type(raw) is not list or len(raw) < 2:
            raise ValueError(f"{side} levels must contain price and quantity")
        price = _decimal_string(raw[0], field_name=f"{side} price", allow_zero=False)
        quantity = _decimal_string(
            raw[1], field_name=f"{side} quantity", allow_zero=True
        )
        if price in prices:
            raise ValueError(f"{side} message contains duplicate price levels")
        prices.add(price)
        levels.append((price, quantity))
    return tuple(levels)


def _decode_okx(timed: TimedBookRecord) -> _OkxMessage:
    envelope = timed.source.envelope
    if envelope.exchange is not Exchange.OKX:
        raise ValueError("OkxBookReplayer accepts only OKX evidence")
    if envelope.logical_stream != "book_live" or envelope.native_channel != "books":
        raise ValueError("OKX v1 replay supports only the frozen books live channel")
    if envelope.integrity_mode not in {None, IntegrityMode.SEQUENCE_VERIFIED}:
        raise ValueError("OKX books cannot claim a non-sequence integrity mode")
    payload = envelope.payload
    if type(payload) is not dict:
        raise ValueError("OKX book payload must be an object")
    action = payload.get("action")
    if type(action) is not str or action not in {"snapshot", "update"}:
        raise ValueError("OKX book action must be snapshot or update")
    arg = payload.get("arg")
    if type(arg) is not dict or arg.get("channel") != "books":
        raise ValueError("OKX book payload channel mismatch")
    if arg.get("instId") != envelope.wire_symbol:
        raise ValueError("OKX book payload instrument mismatch")
    data = payload.get("data")
    if type(data) is not list or len(data) != 1 or type(data[0]) is not dict:
        raise ValueError("OKX books raw record must contain exactly one data item")
    item = data[0]
    timestamp = item.get("ts")
    if type(timestamp) is not str or not timestamp.isascii() or not timestamp.isdigit():
        raise ValueError("OKX book ts must be a millisecond integer string")
    native_time_ns = int(timestamp) * 1_000_000
    if envelope.event_time_ns != native_time_ns:
        raise ValueError("OKX envelope event time must match data.ts")
    return _OkxMessage(
        timed=timed,
        action=action,
        bids=_levels(item.get("bids"), side="bids"),
        asks=_levels(item.get("asks"), side="asks"),
        sequence_id=_json_int(item.get("seqId"), field_name="seqId"),
        previous_sequence_id=_json_int(
            item.get("prevSeqId"), field_name="prevSeqId", allow_minus_one=True
        ),
        checksum=_json_int(item.get("checksum"), field_name="checksum"),
    )


def is_okx_authoritative_snapshot(timed: TimedBookRecord) -> bool:
    if type(timed) is not TimedBookRecord:
        raise TypeError("timed must be TimedBookRecord")
    try:
        message = _decode_okx(timed)
    except ValueError:
        return False
    return (
        message.is_snapshot
        and message.previous_sequence_id == -1
        and message.checksum == 0
    )


_FAULT_REASONS = {
    QualityEventKind.GAP: BookGapReason.EXPLICIT_GAP,
    QualityEventKind.RECONNECT: BookGapReason.RECONNECT,
    QualityEventKind.CHECKSUM_ERROR: BookGapReason.CHECKSUM_ERROR,
    QualityEventKind.SEQUENCE_ERROR: BookGapReason.SEQUENCE_ERROR,
}


class OkxBookReplayer:
    """Reviewed transition logic for anonymous OKX `books` evidence."""

    def replay(
        self,
        records: Iterable[TimedBookRecord],
        *,
        quality_events: Iterable[TimedQualityEvent] = (),
        scope: BookScope | QualityStreamKey | None = None,
    ) -> ReplayedBook:
        timed_values = tuple(records)
        if any(type(item) is not TimedBookRecord for item in timed_values):
            raise TypeError("records must contain TimedBookRecord values")
        by_locator = {item.source.locator: item for item in timed_values}
        if len(by_locator) != len(timed_values):
            raise ValueError("book source locators must be unique")

        if scope is None:
            replay_scope: BookScope | None = None
        elif type(scope) is BookScope:
            replay_scope = scope
        elif type(scope) is QualityStreamKey:
            if (
                scope.logical_stream != "book_live"
                or scope.market is None
                or scope.instrument_key is None
            ):
                raise ValueError("scope must identify one book_live instrument")
            replay_scope = BookScope(scope.exchange, scope.market, scope.instrument_key)
        else:
            raise TypeError("scope must be BookScope, QualityStreamKey, or None")
        for item in timed_values:
            envelope = item.source.envelope
            item_scope = BookScope(
                envelope.exchange,
                envelope.market,  # type: ignore[arg-type]
                envelope.instrument_key,  # type: ignore[arg-type]
            )
            if replay_scope is None:
                replay_scope = item_scope
            elif replay_scope != item_scope:
                raise ValueError("one replay cannot mix book scopes")

        fault_values = tuple(quality_events)
        if any(type(event) is not TimedQualityEvent for event in fault_values):
            raise TypeError("quality_events must contain TimedQualityEvent values")
        if replay_scope is None and fault_values:
            raise ValueError("quality faults without book records require an explicit scope")
        faults_by_locator: dict[SourceLocator, TimedQualityEvent] = {}
        for event in fault_values:
            if event.event.kind not in _FAULT_REASONS or (
                replay_scope is not None
                and replay_scope.quality_key not in event.event.targets
            ):
                continue
            locator = event.event.source.locator
            if locator in by_locator or locator in faults_by_locator:
                raise ValueError("causal replay source locators must be globally unique")
            faults_by_locator[locator] = event

        ordered = canonical_replay_order(
            [item.source for item in timed_values]
            + [item.event.source for item in faults_by_locator.values()]
        )
        bids: dict[Decimal, Decimal] = {}
        asks: dict[Decimal, Decimal] = {}
        valid = False
        reason: BookGapReason | None = BookGapReason.MISSING_AUTHORITY
        sequence_id: int | None = None
        connection_scope: ConnectionGenerationScope | None = None
        ancestor: SourceLocator | None = None
        ancestor_stream: str | None = None
        transitions: list[BookValidityTransition] = []
        updates: list[int] = []
        heartbeats: list[int] = []
        resets: list[int] = []
        last_update: int | None = None
        last_activity: int | None = None
        lineage: set[str] = set()

        def invalidate(
            gap_reason: BookGapReason,
            *,
            timestamp: int,
            locator: SourceLocator,
        ) -> None:
            nonlocal valid, reason, sequence_id, connection_scope
            nonlocal ancestor, ancestor_stream
            if not valid and reason is not BookGapReason.MISSING_AUTHORITY:
                return
            transitions.append(
                BookValidityTransition(timestamp, False, gap_reason, locator)
            )
            valid = False
            reason = gap_reason
            bids.clear()
            asks.clear()
            sequence_id = None
            connection_scope = None
            ancestor = None
            ancestor_stream = None

        for ordered_record in ordered:
            source = ordered_record.source
            locator = source.locator
            lineage.add(locator.manifest_sha256)
            fault = faults_by_locator.get(locator)
            if fault is not None:
                invalidate(
                    _FAULT_REASONS[fault.event.kind],
                    timestamp=fault.effective_event_time_ns,
                    locator=locator,
                )
                continue

            timed = by_locator[locator]
            message = _decode_okx(timed)
            envelope = source.envelope
            message_scope = BookScope(
                envelope.exchange,
                envelope.market,  # type: ignore[arg-type]
                envelope.instrument_key,  # type: ignore[arg-type]
            )
            if replay_scope != message_scope:
                raise ValueError("one replay cannot mix book scopes")

            if ordered_record.invalidates_inherited_generation and not message.is_snapshot:
                invalidate(
                    BookGapReason.WORKER_BOUNDARY,
                    timestamp=timed.effective_event_time_ns,
                    locator=locator,
                )
            if message.checksum != 0:
                invalidate(
                    BookGapReason.CHECKSUM_PROTOCOL_VIOLATION,
                    timestamp=timed.effective_event_time_ns,
                    locator=locator,
                )
                continue
            if message.is_snapshot:
                if message.previous_sequence_id != -1:
                    invalidate(
                        BookGapReason.INVALID_PAYLOAD,
                        timestamp=timed.effective_event_time_ns,
                        locator=locator,
                    )
                    continue
                bids = {price: quantity for price, quantity in message.bids if quantity}
                asks = {price: quantity for price, quantity in message.asks if quantity}
                valid = True
                reason = None
                sequence_id = message.sequence_id
                connection_scope = ordered_record.connection_generation_scope
                ancestor = locator
                ancestor_stream = envelope.logical_stream
                last_update = timed.effective_event_time_ns
                last_activity = timed.effective_event_time_ns
                transitions.append(
                    BookValidityTransition(
                        timed.effective_event_time_ns,
                        True,
                        None,
                        locator,
                    )
                )
                continue

            if not valid:
                continue
            if ordered_record.connection_generation_scope != connection_scope:
                invalidate(
                    BookGapReason.CONNECTION_GENERATION_CHANGED,
                    timestamp=timed.effective_event_time_ns,
                    locator=locator,
                )
                continue
            assert sequence_id is not None
            is_heartbeat = (
                not message.bids
                and not message.asks
                and message.previous_sequence_id == sequence_id
                and message.sequence_id == sequence_id
            )
            is_reset = (
                message.previous_sequence_id == sequence_id
                and message.sequence_id < message.previous_sequence_id
            )
            continuous = message.previous_sequence_id == sequence_id
            if not continuous:
                invalidate(
                    BookGapReason.SEQUENCE_MISMATCH,
                    timestamp=timed.effective_event_time_ns,
                    locator=locator,
                )
                continue
            last_activity = timed.effective_event_time_ns
            if is_heartbeat:
                heartbeats.append(timed.effective_event_time_ns)
                continue
            for price, quantity in message.bids:
                if quantity == 0:
                    bids.pop(price, None)
                else:
                    bids[price] = quantity
            for price, quantity in message.asks:
                if quantity == 0:
                    asks.pop(price, None)
                else:
                    asks[price] = quantity
            sequence_id = message.sequence_id
            updates.append(timed.effective_event_time_ns)
            last_update = timed.effective_event_time_ns
            if is_reset:
                resets.append(timed.effective_event_time_ns)

        return ReplayedBook(
            scope=replay_scope,
            book_valid=valid,
            integrity_mode=(
                IntegrityMode.SEQUENCE_VERIFIED if valid else IntegrityMode.INVALID
            ),
            gap_reason=reason,
            bids=tuple(sorted(bids.items(), reverse=True)) if valid else (),
            asks=tuple(sorted(asks.items())) if valid else (),
            sequence_id=sequence_id,
            connection_scope=connection_scope,
            authoritative_ancestor=ancestor,
            authoritative_source_stream=ancestor_stream,
            accepted_update_count=len(updates),
            heartbeat_count=len(heartbeats),
            sequence_reset_count=len(resets),
            last_book_update_time_ns=last_update if valid else None,
            last_activity_time_ns=last_activity if valid else None,
            validity_transitions=tuple(transitions),
            accepted_update_times_ns=tuple(updates),
            heartbeat_times_ns=tuple(heartbeats),
            sequence_reset_times_ns=tuple(resets),
            lineage_manifest_sha256s=tuple(sorted(lineage)),
        )


__all__ = [
    "BookGapReason",
    "BookScope",
    "BookValidityTransition",
    "OkxBookReplayer",
    "ReplayedBook",
    "TimedBookRecord",
    "apply_book_time_policy",
    "is_okx_authoritative_snapshot",
]
