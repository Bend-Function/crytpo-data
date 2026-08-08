from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum

from crypto_collector.domain import IntegrityMode

_MAX_SIGNED_64 = 2**63 - 1


class BitgetBookParseError(ValueError):
    pass


class BookAction(StrEnum):
    SNAPSHOT = "snapshot"
    APPLY = "apply"
    RESUBSCRIBE = "resubscribe"


@dataclass(frozen=True, slots=True)
class BitgetBookLevel:
    """One native level; quantity zero is evidence, not a delete instruction."""

    price: Decimal
    quantity: Decimal
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.price) is not Decimal
            or not self.price.is_finite()
            or self.price <= 0
        ):
            raise ValueError("book level price must be a finite positive Decimal")
        if (
            type(self.quantity) is not Decimal
            or not self.quantity.is_finite()
            or self.quantity < 0
        ):
            raise ValueError(
                "book level quantity must be a finite non-negative Decimal"
            )
        if (
            type(self.fields) is not tuple
            or len(self.fields) < 2
            or any(type(item) is not str for item in self.fields)
        ):
            raise TypeError("book level fields must be a tuple of at least two strings")
        try:
            fields_match = (
                Decimal(self.fields[0]) == self.price
                and Decimal(self.fields[1]) == self.quantity
            )
        except InvalidOperation as error:
            raise ValueError(
                "book level fields must contain decimal price and quantity"
            ) from error
        if not fields_match:
            raise ValueError("book level fields must match parsed price and quantity")


@dataclass(frozen=True, slots=True)
class BitgetBookFrame:
    action: str
    bids: tuple[BitgetBookLevel, ...]
    asks: tuple[BitgetBookLevel, ...]
    timestamp_ns: int
    pseq: int
    seq: int
    max_depth: int | None

    def __post_init__(self) -> None:
        if self.action not in {"snapshot", "update"}:
            raise ValueError("book action must be snapshot or update")
        if type(self.bids) is not tuple or any(
            type(level) is not BitgetBookLevel for level in self.bids
        ):
            raise TypeError("bids must be a tuple of BitgetBookLevel")
        if type(self.asks) is not tuple or any(
            type(level) is not BitgetBookLevel for level in self.asks
        ):
            raise TypeError("asks must be a tuple of BitgetBookLevel")
        _nonnegative_int(self.timestamp_ns, field="timestamp_ns")
        _nonnegative_int(self.pseq, field="pseq")
        _nonnegative_int(self.seq, field="seq")
        if self.max_depth is not None:
            maximum = _nonnegative_int(self.max_depth, field="max_depth")
            if maximum > 1_000:
                raise ValueError("max_depth must not exceed 1000")


@dataclass(frozen=True, slots=True)
class BookOutcome:
    action: BookAction
    integrity: IntegrityMode
    generation_valid: bool
    emit_original_to_stream: str
    count_as_book_update: bool
    control_reason: str | None
    sequence_id: int | None


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SIGNED_64:
        raise ValueError(f"{field} must fit a non-negative signed 64-bit integer")
    return value


def _parse_integer(value: object, *, field: str) -> int:
    if type(value) is int:
        parsed = value
    elif type(value) is str and value and value == value.strip():
        try:
            parsed = int(value)
        except ValueError as error:
            raise BitgetBookParseError(f"{field} must be an integer") from error
    else:
        raise BitgetBookParseError(f"{field} must be an integer")
    try:
        return _nonnegative_int(parsed, field=field)
    except ValueError as error:
        raise BitgetBookParseError(str(error)) from error


def _parse_decimal(value: object, *, field: str, allow_zero: bool) -> Decimal:
    if type(value) is not str or not value or value != value.strip():
        raise BitgetBookParseError(f"{field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise BitgetBookParseError(f"{field} must be a decimal string") from error
    if not parsed.is_finite() or parsed < 0 or (not allow_zero and parsed == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise BitgetBookParseError(f"{field} must be finite and {qualifier}")
    return parsed


def _levels(value: object, *, field: str) -> tuple[BitgetBookLevel, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise BitgetBookParseError(f"{field} must be an array")
    levels: list[BitgetBookLevel] = []
    for index, raw_level in enumerate(value):
        if not isinstance(raw_level, Sequence) or isinstance(
            raw_level, (str, bytes, bytearray)
        ):
            raise BitgetBookParseError(f"{field}[{index}] must be an array")
        fields = tuple(raw_level)
        if len(fields) < 2 or any(type(item) is not str for item in fields):
            raise BitgetBookParseError(
                f"{field}[{index}] must contain at least two strings"
            )
        price = _parse_decimal(
            fields[0],
            field=f"{field}[{index}][0]",
            allow_zero=False,
        )
        quantity = _parse_decimal(
            fields[1],
            field=f"{field}[{index}][1]",
            allow_zero=True,
        )
        levels.append(BitgetBookLevel(price, quantity, fields))
    return tuple(levels)


def _mapping(value: object, *, field: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BitgetBookParseError(f"{field} must be an object")
    return value


def parse_book_message(message: object) -> tuple[BitgetBookFrame, ...]:
    """Parse a UTA v3 ``books`` push without assigning level semantics."""

    envelope = _mapping(message, field="Bitget book message")
    action = envelope.get("action")
    if type(action) is not str or action not in {"snapshot", "update"}:
        raise BitgetBookParseError("action must be snapshot or update")
    argument = _mapping(envelope.get("arg"), field="arg")
    if argument.get("topic") != "books":
        raise BitgetBookParseError("arg.topic must be books")
    data = envelope.get("data")
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes, bytearray)):
        raise BitgetBookParseError("data must be an array")
    if len(data) != 1:
        raise BitgetBookParseError("books data must contain exactly one row")
    row = _mapping(data[0], field="data[0]")
    timestamp_ms = _parse_integer(row.get("ts"), field="data[0].ts")
    try:
        timestamp_ns = _nonnegative_int(
            timestamp_ms * 1_000_000,
            field="timestamp_ns",
        )
    except ValueError as error:
        raise BitgetBookParseError(str(error)) from error
    max_depth_raw = row.get("maxDepth")
    max_depth = (
        None
        if max_depth_raw is None or max_depth_raw == ""
        else _parse_integer(max_depth_raw, field="data[0].maxDepth")
    )
    if max_depth is not None and max_depth > 1_000:
        raise BitgetBookParseError("data[0].maxDepth must not exceed 1000")
    return (
        BitgetBookFrame(
            action=action,
            bids=_levels(row.get("b"), field="data[0].b"),
            asks=_levels(row.get("a"), field="data[0].a"),
            timestamp_ns=timestamp_ns,
            pseq=_parse_integer(row.get("pseq"), field="data[0].pseq"),
            seq=_parse_integer(row.get("seq"), field="data[0].seq"),
            max_depth=max_depth,
        ),
    )


class BitgetBook:
    """Validate UTA ``pseq`` continuity without reconstructing book levels."""

    def __init__(self) -> None:
        self._snapshot_seq: int | None = None
        self._last_update_seq: int | None = None
        self._generation_valid = True

    @property
    def sequence_id(self) -> int | None:
        return (
            self._snapshot_seq
            if self._last_update_seq is None
            else self._last_update_seq
        )

    @property
    def generation_valid(self) -> bool:
        return self._generation_valid

    @property
    def has_incremental_chain(self) -> bool:
        return self._last_update_seq is not None

    def apply(self, frame: BitgetBookFrame) -> BookOutcome:
        if type(frame) is not BitgetBookFrame:
            raise TypeError("frame must be BitgetBookFrame")
        if frame.action == "snapshot":
            return self._apply_snapshot(frame)
        if not self._generation_valid:
            return self._invalid("book_generation_invalid")
        snapshot_seq = self._snapshot_seq
        if snapshot_seq is None:
            self._generation_valid = False
            return self._invalid("book_update_before_snapshot")

        previous_update = self._last_update_seq
        if previous_update is None:
            if not frame.pseq <= snapshot_seq <= frame.seq or frame.seq <= frame.pseq:
                self._generation_valid = False
                return self._invalid("book_first_update_does_not_overlap_snapshot")
        elif frame.pseq == 0:
            self._generation_valid = False
            return self._invalid("book_sequence_reset")
        elif frame.pseq != previous_update or frame.seq <= previous_update:
            self._generation_valid = False
            return self._invalid("book_sequence_gap")

        self._last_update_seq = frame.seq
        return BookOutcome(
            action=BookAction.APPLY,
            integrity=IntegrityMode.SEQUENCE_VERIFIED,
            generation_valid=True,
            emit_original_to_stream="book_live",
            count_as_book_update=True,
            control_reason=None,
            sequence_id=frame.seq,
        )

    def _apply_snapshot(self, frame: BitgetBookFrame) -> BookOutcome:
        if frame.seq <= frame.pseq:
            self._generation_valid = False
            return self._invalid("book_snapshot_sequence_regression")
        self._snapshot_seq = frame.seq
        self._last_update_seq = None
        self._generation_valid = True
        return BookOutcome(
            action=BookAction.SNAPSHOT,
            integrity=IntegrityMode.SNAPSHOT_CHAIN,
            generation_valid=True,
            emit_original_to_stream="book_live",
            count_as_book_update=True,
            control_reason=None,
            sequence_id=frame.seq,
        )

    def _invalid(self, reason: str) -> BookOutcome:
        return BookOutcome(
            action=BookAction.RESUBSCRIBE,
            integrity=IntegrityMode.INVALID,
            generation_valid=False,
            emit_original_to_stream="book_live",
            count_as_book_update=False,
            control_reason=reason,
            sequence_id=self.sequence_id,
        )


BitgetBookState = BitgetBook


__all__ = [
    "BitgetBook",
    "BitgetBookFrame",
    "BitgetBookLevel",
    "BitgetBookParseError",
    "BitgetBookState",
    "BookAction",
    "BookOutcome",
    "parse_book_message",
]
