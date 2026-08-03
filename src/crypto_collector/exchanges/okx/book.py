from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum

from crypto_collector.domain import IntegrityMode

_MAX_SIGNED_64 = 2**63 - 1


class OkxBookParseError(ValueError):
    pass


class BookAction(StrEnum):
    SNAPSHOT = "snapshot"
    APPLY = "apply"
    HEARTBEAT = "heartbeat"
    RECONNECT = "reconnect"


@dataclass(frozen=True, slots=True)
class OkxBookLevel:
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
class OkxBookFrame:
    action: str
    bids: tuple[OkxBookLevel, ...]
    asks: tuple[OkxBookLevel, ...]
    timestamp_ns: int
    prev_seq_id: int | None
    seq_id: int
    checksum: int | None

    def __post_init__(self) -> None:
        if self.action not in {"snapshot", "update"}:
            raise ValueError("book action must be snapshot or update")
        if type(self.bids) is not tuple or any(
            type(level) is not OkxBookLevel for level in self.bids
        ):
            raise TypeError("bids must be a tuple of OkxBookLevel")
        if type(self.asks) is not tuple or any(
            type(level) is not OkxBookLevel for level in self.asks
        ):
            raise TypeError("asks must be a tuple of OkxBookLevel")
        _nonnegative_int(self.timestamp_ns, field="timestamp_ns")
        _nonnegative_int(self.seq_id, field="seq_id")
        if self.prev_seq_id is not None:
            _signed_int(self.prev_seq_id, field="prev_seq_id")
        if self.checksum is not None:
            _signed_int(self.checksum, field="checksum")


@dataclass(frozen=True, slots=True)
class BookOutcome:
    action: BookAction
    integrity: IntegrityMode
    generation_valid: bool
    emit_original_to_stream: str | None
    count_as_book_update: bool
    control_reason: str | None
    sequence_id: int | None


def _signed_int(value: object, *, field: str) -> int:
    if type(value) is not int or not -(2**63) <= value <= _MAX_SIGNED_64:
        raise ValueError(f"{field} must fit a signed 64-bit integer")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    parsed = _signed_int(value, field=field)
    if parsed < 0:
        raise ValueError(f"{field} must be non-negative")
    return parsed


def _parse_integer(value: object, *, field: str, nonnegative: bool = False) -> int:
    if type(value) is int:
        parsed = value
    elif type(value) is str and value and value == value.strip():
        try:
            parsed = int(value)
        except ValueError as error:
            raise OkxBookParseError(f"{field} must be an integer") from error
    else:
        raise OkxBookParseError(f"{field} must be an integer")
    try:
        return (
            _nonnegative_int(parsed, field=field)
            if nonnegative
            else _signed_int(parsed, field=field)
        )
    except ValueError as error:
        raise OkxBookParseError(str(error)) from error


def _parse_decimal(value: object, *, field: str, allow_zero: bool) -> Decimal:
    if type(value) is not str or not value or value != value.strip():
        raise OkxBookParseError(f"{field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise OkxBookParseError(f"{field} must be a decimal string") from error
    if not parsed.is_finite() or parsed < 0 or (not allow_zero and parsed == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise OkxBookParseError(f"{field} must be a finite {qualifier} decimal")
    return parsed


def _parse_levels(value: object, *, side: str) -> tuple[OkxBookLevel, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise OkxBookParseError(f"{side} must be an array")
    levels: list[OkxBookLevel] = []
    prices: set[Decimal] = set()
    for index, raw_level in enumerate(value):
        if not isinstance(raw_level, Sequence) or isinstance(
            raw_level, (str, bytes, bytearray)
        ):
            raise OkxBookParseError(f"{side}[{index}] must be an array")
        fields = tuple(raw_level)
        if len(fields) < 2 or any(type(item) is not str for item in fields):
            raise OkxBookParseError(
                f"{side}[{index}] must contain at least two string fields"
            )
        price = _parse_decimal(
            fields[0], field=f"{side}[{index}].price", allow_zero=False
        )
        quantity = _parse_decimal(
            fields[1],
            field=f"{side}[{index}].quantity",
            allow_zero=True,
        )
        if price in prices:
            raise OkxBookParseError(f"{side} contains a duplicate price")
        prices.add(price)
        levels.append(OkxBookLevel(price=price, quantity=quantity, fields=fields))
    return tuple(levels)


def parse_book_message(message: object) -> tuple[OkxBookFrame, ...]:
    if not isinstance(message, Mapping):
        raise OkxBookParseError("book message must be an object")
    action = message.get("action")
    if action not in {"snapshot", "update"}:
        raise OkxBookParseError("book message action must be snapshot or update")
    data = message.get("data")
    if not isinstance(data, Sequence) or isinstance(data, (str, bytes, bytearray)):
        raise OkxBookParseError("book message data must be an array")
    if not data:
        raise OkxBookParseError("book message data must not be empty")
    frames: list[OkxBookFrame] = []
    for index, item in enumerate(data):
        if not isinstance(item, Mapping):
            raise OkxBookParseError(f"book data[{index}] must be an object")
        timestamp_ms = _parse_integer(
            item.get("ts"),
            field=f"data[{index}].ts",
            nonnegative=True,
        )
        if timestamp_ms > _MAX_SIGNED_64 // 1_000_000:
            raise OkxBookParseError("book timestamp overflows nanoseconds")
        prev_raw = item.get("prevSeqId")
        prev_seq_id = (
            None
            if prev_raw is None
            else _parse_integer(prev_raw, field=f"data[{index}].prevSeqId")
        )
        checksum_raw = item.get("checksum")
        checksum = (
            None
            if checksum_raw is None
            else _parse_integer(checksum_raw, field=f"data[{index}].checksum")
        )
        frames.append(
            OkxBookFrame(
                action=action,
                bids=_parse_levels(item.get("bids"), side=f"data[{index}].bids"),
                asks=_parse_levels(item.get("asks"), side=f"data[{index}].asks"),
                timestamp_ns=timestamp_ms * 1_000_000,
                prev_seq_id=prev_seq_id,
                seq_id=_parse_integer(
                    item.get("seqId"),
                    field=f"data[{index}].seqId",
                    nonnegative=True,
                ),
                checksum=checksum,
            )
        )
    return tuple(frames)


class OkxBookState:
    def __init__(self, *, allow_crossed: bool = False) -> None:
        if type(allow_crossed) is not bool:
            raise TypeError("allow_crossed must be a bool")
        self._allow_crossed = allow_crossed
        self._bids: dict[Decimal, OkxBookLevel] = {}
        self._asks: dict[Decimal, OkxBookLevel] = {}
        self._seq_id: int | None = None
        self._generation_valid = True

    @property
    def sequence_id(self) -> int | None:
        return self._seq_id

    @property
    def generation_valid(self) -> bool:
        return self._generation_valid

    @property
    def bids(self) -> tuple[OkxBookLevel, ...]:
        return tuple(self._bids[price] for price in sorted(self._bids, reverse=True))

    @property
    def asks(self) -> tuple[OkxBookLevel, ...]:
        return tuple(self._asks[price] for price in sorted(self._asks))

    def apply(self, frame: OkxBookFrame) -> BookOutcome:
        if type(frame) is not OkxBookFrame:
            raise TypeError("frame must be OkxBookFrame")
        if frame.action == "snapshot":
            return self._apply_snapshot(frame)
        if not self._generation_valid:
            return self._invalid("book_generation_invalid")
        previous = self._seq_id
        if previous is None:
            self._generation_valid = False
            return self._invalid("book_update_before_snapshot")
        if (
            not frame.bids
            and not frame.asks
            and frame.prev_seq_id == previous
            and frame.seq_id == previous
        ):
            return BookOutcome(
                action=BookAction.HEARTBEAT,
                integrity=IntegrityMode.SEQUENCE_VERIFIED,
                generation_valid=True,
                emit_original_to_stream="book_live",
                count_as_book_update=False,
                control_reason=None,
                sequence_id=previous,
            )
        if frame.prev_seq_id != previous or frame.seq_id == previous:
            self._generation_valid = False
            return self._invalid("book_sequence_gap")

        bids = dict(self._bids)
        asks = dict(self._asks)
        self._apply_levels(bids, frame.bids)
        self._apply_levels(asks, frame.asks)
        if not self._valid_spread(bids, asks):
            self._generation_valid = False
            return self._invalid("book_crossed")
        self._bids = bids
        self._asks = asks
        self._seq_id = frame.seq_id
        maintenance_reset = frame.seq_id < previous
        return BookOutcome(
            action=BookAction.APPLY,
            integrity=IntegrityMode.SEQUENCE_VERIFIED,
            generation_valid=True,
            emit_original_to_stream="book_live",
            count_as_book_update=True,
            control_reason=(
                "maintenance_sequence_reset" if maintenance_reset else None
            ),
            sequence_id=frame.seq_id,
        )

    def _apply_snapshot(self, frame: OkxBookFrame) -> BookOutcome:
        if any(level.quantity == 0 for level in (*frame.bids, *frame.asks)):
            self._generation_valid = False
            return self._invalid("book_snapshot_zero_quantity")
        bids = {level.price: level for level in frame.bids}
        asks = {level.price: level for level in frame.asks}
        if not self._valid_spread(bids, asks):
            self._generation_valid = False
            return self._invalid("book_crossed")
        self._bids = bids
        self._asks = asks
        self._seq_id = frame.seq_id
        self._generation_valid = True
        return BookOutcome(
            action=BookAction.SNAPSHOT,
            integrity=IntegrityMode.SEQUENCE_VERIFIED,
            generation_valid=True,
            emit_original_to_stream="book_live",
            count_as_book_update=True,
            control_reason=None,
            sequence_id=frame.seq_id,
        )

    @staticmethod
    def _apply_levels(
        side: dict[Decimal, OkxBookLevel],
        updates: tuple[OkxBookLevel, ...],
    ) -> None:
        for level in updates:
            if level.quantity == 0:
                side.pop(level.price, None)
            else:
                side[level.price] = level

    def _valid_spread(
        self,
        bids: Mapping[Decimal, OkxBookLevel],
        asks: Mapping[Decimal, OkxBookLevel],
    ) -> bool:
        return self._allow_crossed or not bids or not asks or max(bids) < min(asks)

    def _invalid(self, reason: str) -> BookOutcome:
        return BookOutcome(
            action=BookAction.RECONNECT,
            integrity=IntegrityMode.INVALID,
            generation_valid=False,
            emit_original_to_stream="book_live",
            count_as_book_update=False,
            control_reason=reason,
            sequence_id=self._seq_id,
        )


__all__ = [
    "BookAction",
    "BookOutcome",
    "OkxBookFrame",
    "OkxBookLevel",
    "OkxBookParseError",
    "OkxBookState",
    "parse_book_message",
]
