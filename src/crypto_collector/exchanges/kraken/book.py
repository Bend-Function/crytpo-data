from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import cast

from crypto_collector.domain import IntegrityMode
from crypto_collector.domain.json_codec import JsonPayload
from crypto_collector.exchanges.kraken.checksum import (
    kraken_spot_checksum_input,
    kraken_spot_crc32,
)
from crypto_collector.exchanges.kraken.errors import KrakenPayloadError

_PLAIN_DECIMAL = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")
_RFC3339_TIMESTAMP = re.compile(
    r"\A(?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})T"
    r"(?P<time>[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?"
    r"(?P<offset>Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_MAX_SIGNED_64 = 2**63 - 1
_SPOT_DEPTHS = frozenset({10, 25, 100, 500, 1000})


class KrakenBookParseError(KrakenPayloadError):
    """A Kraken book frame cannot be parsed without losing native semantics."""


class KrakenBookAction(StrEnum):
    SNAPSHOT = "snapshot"
    APPLY = "apply"
    RECONNECT = "reconnect"


@dataclass(frozen=True, slots=True)
class KrakenBookLevel:
    price: Decimal
    quantity: Decimal
    raw_price: str
    raw_quantity: str

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
        if type(self.raw_price) is not str or type(self.raw_quantity) is not str:
            raise TypeError("book level raw values must be strings")
        if not _PLAIN_DECIMAL.fullmatch(self.raw_price) or not _PLAIN_DECIMAL.fullmatch(
            self.raw_quantity
        ):
            raise ValueError("book level raw values must use plain unsigned notation")
        try:
            matches = (
                Decimal(self.raw_price) == self.price
                and Decimal(self.raw_quantity) == self.quantity
            )
        except InvalidOperation as error:  # pragma: no cover - guarded by regex.
            raise ValueError("book level raw values must be exact decimals") from error
        if not matches:
            raise ValueError("book level raw values must match parsed values")


@dataclass(frozen=True, slots=True)
class KrakenSpotBookFrame:
    action: str
    symbol: str
    bids: tuple[KrakenBookLevel, ...]
    asks: tuple[KrakenBookLevel, ...]
    checksum: int
    timestamp_ns: int | None

    def __post_init__(self) -> None:
        if self.action not in {"snapshot", "update"}:
            raise ValueError("Spot book action must be snapshot or update")
        _nonempty(self.symbol, field="symbol")
        _levels(self.bids, field="bids")
        _levels(self.asks, field="asks")
        _unsigned_32(self.checksum, field="checksum")
        if self.timestamp_ns is not None:
            _nonnegative_int(self.timestamp_ns, field="timestamp_ns")


@dataclass(frozen=True, slots=True)
class KrakenFuturesBookFrame:
    action: str
    product_id: str
    bids: tuple[KrakenBookLevel, ...]
    asks: tuple[KrakenBookLevel, ...]
    timestamp_ns: int
    sequence_id: int

    def __post_init__(self) -> None:
        if self.action not in {"snapshot", "update"}:
            raise ValueError("Futures book action must be snapshot or update")
        _nonempty(self.product_id, field="product_id")
        _levels(self.bids, field="bids")
        _levels(self.asks, field="asks")
        _nonnegative_int(self.timestamp_ns, field="timestamp_ns")
        _nonnegative_int(self.sequence_id, field="sequence_id")


@dataclass(frozen=True, slots=True)
class KrakenBookOutcome:
    action: KrakenBookAction
    integrity: IntegrityMode
    generation_valid: bool
    emit_original_to_stream: str
    count_as_book_update: bool
    control_reason: str | None
    sequence_id: int | None


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SIGNED_64:
        raise ValueError(f"{field} must fit signed 64-bit non-negative integer")
    return value


def _unsigned_32(value: object, *, field: str) -> int:
    if type(value) is not int or not 0 <= value <= 0xFFFFFFFF:
        raise ValueError(f"{field} must fit an unsigned 32-bit integer")
    return value


def _levels(value: object, *, field: str) -> tuple[KrakenBookLevel, ...]:
    if type(value) is not tuple or any(
        type(item) is not KrakenBookLevel for item in value
    ):
        raise TypeError(f"{field} must be a tuple of KrakenBookLevel")
    return cast(tuple[KrakenBookLevel, ...], value)


def _decimal_token(
    value: object, *, field: str, allow_zero: bool
) -> tuple[str, Decimal]:
    if type(value) is str:
        raw = value
    elif type(value) is int:
        raw = str(value)
    elif type(value) is Decimal:
        raw = format(value, "f")
    else:
        raise KrakenBookParseError(
            f"{field} must be a string, integer, or Decimal; float is forbidden"
        )
    if not _PLAIN_DECIMAL.fullmatch(raw):
        raise KrakenBookParseError(f"{field} must use plain unsigned decimal notation")
    try:
        parsed = Decimal(raw)
    except InvalidOperation as error:  # pragma: no cover - guarded by regex.
        raise KrakenBookParseError(f"{field} must be a decimal") from error
    if not parsed.is_finite() or parsed < 0 or (not allow_zero and parsed == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise KrakenBookParseError(f"{field} must be a finite {qualifier} decimal")
    return raw, parsed


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise KrakenBookParseError(f"{field} must be an object")
    return cast(Mapping[str, JsonPayload], value)


def _sequence(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise KrakenBookParseError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _parse_object_level(value: object, *, field: str) -> KrakenBookLevel:
    item = _mapping(value, field=field)
    raw_price, price = _decimal_token(
        item.get("price"), field=f"{field}.price", allow_zero=False
    )
    raw_quantity, quantity = _decimal_token(
        item.get("qty"), field=f"{field}.qty", allow_zero=True
    )
    return KrakenBookLevel(price, quantity, raw_price, raw_quantity)


def _parse_object_levels(value: object, *, field: str) -> tuple[KrakenBookLevel, ...]:
    return tuple(
        _parse_object_level(item, field=f"{field}[{index}]")
        for index, item in enumerate(_sequence(value, field=field))
    )


def _parse_rfc3339_ns(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    if type(value) is not str or not value:
        raise KrakenBookParseError(f"{field} must be an RFC3339 string")
    match = _RFC3339_TIMESTAMP.fullmatch(value)
    if match is None:
        raise KrakenBookParseError(f"{field} must be an RFC3339 string")
    offset = match.group("offset")
    normalized_offset = "+00:00" if offset == "Z" else offset
    try:
        parsed = datetime.fromisoformat(
            f"{match.group('date')}T{match.group('time')}{normalized_offset}"
        )
    except ValueError as error:
        raise KrakenBookParseError(f"{field} must be an RFC3339 string") from error
    normalized = parsed.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = normalized - epoch
    seconds = delta.days * 86_400 + delta.seconds
    fraction = match.group("fraction") or ""
    fractional_ns = int(fraction.ljust(9, "0")) if fraction else 0
    nanoseconds = seconds * 1_000_000_000 + fractional_ns
    if not 0 <= nanoseconds <= _MAX_SIGNED_64:
        raise KrakenBookParseError(f"{field} overflows signed 64-bit nanoseconds")
    return nanoseconds


def parse_spot_book_message(message: object) -> tuple[KrakenSpotBookFrame, ...]:
    envelope = _mapping(message, field="Spot book message")
    if envelope.get("channel") != "book":
        raise KrakenBookParseError("Spot book message channel must be book")
    action = envelope.get("type")
    if action not in {"snapshot", "update"}:
        raise KrakenBookParseError("Spot book message type must be snapshot or update")
    parsed_action = cast(str, action)
    frames: list[KrakenSpotBookFrame] = []
    rows = _sequence(envelope.get("data"), field="Spot book message data")
    if not rows:
        raise KrakenBookParseError("Spot book message data must not be empty")
    for index, value in enumerate(rows):
        item = _mapping(value, field=f"Spot book data[{index}]")
        checksum = item.get("checksum")
        try:
            parsed_checksum = _unsigned_32(checksum, field="checksum")
        except ValueError as error:
            raise KrakenBookParseError(str(error)) from error
        symbol = item.get("symbol")
        if type(symbol) is not str or not symbol:
            raise KrakenBookParseError("Spot book symbol must be a non-empty string")
        frames.append(
            KrakenSpotBookFrame(
                action=parsed_action,
                symbol=symbol,
                bids=_parse_object_levels(item.get("bids"), field="bids"),
                asks=_parse_object_levels(item.get("asks"), field="asks"),
                checksum=parsed_checksum,
                timestamp_ns=_parse_rfc3339_ns(
                    item.get("timestamp"), field="timestamp"
                ),
            )
        )
    return tuple(frames)


def _parse_futures_level(value: object, *, field: str) -> KrakenBookLevel:
    item = _mapping(value, field=field)
    raw_price, price = _decimal_token(
        item.get("price"), field=f"{field}.price", allow_zero=False
    )
    raw_quantity, quantity = _decimal_token(
        item.get("qty"), field=f"{field}.qty", allow_zero=True
    )
    return KrakenBookLevel(price, quantity, raw_price, raw_quantity)


def _milliseconds_ns(value: object, *, field: str) -> int:
    try:
        milliseconds = _nonnegative_int(value, field=field)
    except ValueError as error:
        raise KrakenBookParseError(str(error)) from error
    if milliseconds > _MAX_SIGNED_64 // 1_000_000:
        raise KrakenBookParseError(f"{field} overflows nanoseconds")
    return milliseconds * 1_000_000


def parse_futures_book_message(message: object) -> KrakenFuturesBookFrame:
    item = _mapping(message, field="Futures book message")
    feed = item.get("feed")
    product_id = item.get("product_id")
    if type(product_id) is not str or not product_id:
        raise KrakenBookParseError("Futures book product_id must be non-empty")
    sequence_id = item.get("seq")
    try:
        parsed_sequence = _nonnegative_int(sequence_id, field="seq")
    except ValueError as error:
        raise KrakenBookParseError(str(error)) from error
    timestamp_ns = _milliseconds_ns(item.get("timestamp"), field="timestamp")
    if feed == "book_snapshot":
        return KrakenFuturesBookFrame(
            action="snapshot",
            product_id=product_id,
            bids=tuple(
                _parse_futures_level(level, field=f"bids[{index}]")
                for index, level in enumerate(_sequence(item.get("bids"), field="bids"))
            ),
            asks=tuple(
                _parse_futures_level(level, field=f"asks[{index}]")
                for index, level in enumerate(_sequence(item.get("asks"), field="asks"))
            ),
            timestamp_ns=timestamp_ns,
            sequence_id=parsed_sequence,
        )
    if feed != "book":
        raise KrakenBookParseError("Futures book feed must be book_snapshot or book")
    side = item.get("side")
    if side not in {"buy", "sell"}:
        raise KrakenBookParseError("Futures book side must be buy or sell")
    level = _parse_futures_level(item, field="book delta")
    return KrakenFuturesBookFrame(
        action="update",
        product_id=product_id,
        bids=(level,) if side == "buy" else (),
        asks=(level,) if side == "sell" else (),
        timestamp_ns=timestamp_ns,
        sequence_id=parsed_sequence,
    )


def _apply_levels(
    side: dict[Decimal, KrakenBookLevel],
    updates: tuple[KrakenBookLevel, ...],
) -> None:
    for level in updates:
        if level.quantity == 0:
            side.pop(level.price, None)
        else:
            side[level.price] = level


def _valid_spread(
    bids: Mapping[Decimal, KrakenBookLevel],
    asks: Mapping[Decimal, KrakenBookLevel],
    *,
    allow_crossed: bool,
) -> bool:
    return allow_crossed or not bids or not asks or max(bids) < min(asks)


class KrakenSpotBook:
    def __init__(
        self,
        *,
        depth: int,
        symbol: str | None = None,
        allow_crossed: bool = False,
    ) -> None:
        if type(depth) is not int or depth not in _SPOT_DEPTHS:
            raise ValueError("Spot book depth must be one of 10, 25, 100, 500, 1000")
        if symbol is not None:
            _nonempty(symbol, field="symbol")
        if type(allow_crossed) is not bool:
            raise TypeError("allow_crossed must be bool")
        self.depth = depth
        self._symbol = symbol
        self._allow_crossed = allow_crossed
        self._bids: dict[Decimal, KrakenBookLevel] = {}
        self._asks: dict[Decimal, KrakenBookLevel] = {}
        self._generation_valid = False

    @property
    def symbol(self) -> str | None:
        return self._symbol

    @property
    def generation_valid(self) -> bool:
        return self._generation_valid

    @property
    def bids(self) -> tuple[KrakenBookLevel, ...]:
        return tuple(self._bids[price] for price in sorted(self._bids, reverse=True))

    @property
    def asks(self) -> tuple[KrakenBookLevel, ...]:
        return tuple(self._asks[price] for price in sorted(self._asks))

    def checksum_input(self) -> str:
        return kraken_spot_checksum_input(
            ((level.raw_price, level.raw_quantity) for level in self.asks[:10]),
            ((level.raw_price, level.raw_quantity) for level in self.bids[:10]),
        )

    def verify_crc(self, expected: int) -> bool:
        _unsigned_32(expected, field="expected")
        return kraken_spot_crc32(self.checksum_input()) == expected

    def apply(self, frame: KrakenSpotBookFrame) -> KrakenBookOutcome:
        if type(frame) is not KrakenSpotBookFrame:
            raise TypeError("frame must be KrakenSpotBookFrame")
        if self._symbol is not None and frame.symbol != self._symbol:
            self._generation_valid = False
            return self._invalid("book_symbol_mismatch")
        if frame.action == "snapshot":
            return self._apply_snapshot(frame)
        if not self._generation_valid:
            return self._invalid("book_generation_invalid")
        return self._apply_update(frame)

    def _apply_snapshot(self, frame: KrakenSpotBookFrame) -> KrakenBookOutcome:
        if any(level.quantity == 0 for level in (*frame.bids, *frame.asks)):
            self._generation_valid = False
            return self._invalid("book_snapshot_zero_quantity")
        return self._commit_candidate(frame, {}, {}, snapshot=True)

    def _apply_update(self, frame: KrakenSpotBookFrame) -> KrakenBookOutcome:
        return self._commit_candidate(
            frame,
            dict(self._bids),
            dict(self._asks),
            snapshot=False,
        )

    def _commit_candidate(
        self,
        frame: KrakenSpotBookFrame,
        bids: dict[Decimal, KrakenBookLevel],
        asks: dict[Decimal, KrakenBookLevel],
        *,
        snapshot: bool,
    ) -> KrakenBookOutcome:
        _apply_levels(bids, frame.bids)
        _apply_levels(asks, frame.asks)
        bids = {
            price: bids[price] for price in sorted(bids, reverse=True)[: self.depth]
        }
        asks = {price: asks[price] for price in sorted(asks)[: self.depth]}
        if not _valid_spread(bids, asks, allow_crossed=self._allow_crossed):
            self._generation_valid = False
            return self._invalid("book_crossed")
        checksum_input = kraken_spot_checksum_input(
            (
                (asks[price].raw_price, asks[price].raw_quantity)
                for price in sorted(asks)[:10]
            ),
            (
                (bids[price].raw_price, bids[price].raw_quantity)
                for price in sorted(bids, reverse=True)[:10]
            ),
        )
        if kraken_spot_crc32(checksum_input) != frame.checksum:
            self._generation_valid = False
            return self._invalid("book_checksum_mismatch")
        self._bids = bids
        self._asks = asks
        self._symbol = frame.symbol
        self._generation_valid = True
        return KrakenBookOutcome(
            action=KrakenBookAction.SNAPSHOT if snapshot else KrakenBookAction.APPLY,
            integrity=IntegrityMode.CHECKSUM_VERIFIED,
            generation_valid=True,
            emit_original_to_stream="book_live",
            count_as_book_update=True,
            control_reason=None,
            sequence_id=None,
        )

    def _invalid(self, reason: str) -> KrakenBookOutcome:
        return KrakenBookOutcome(
            action=KrakenBookAction.RECONNECT,
            integrity=IntegrityMode.INVALID,
            generation_valid=False,
            emit_original_to_stream="book_live",
            count_as_book_update=False,
            control_reason=reason,
            sequence_id=None,
        )


class KrakenFuturesBook:
    def __init__(
        self,
        *,
        product_id: str | None = None,
        allow_crossed: bool = False,
    ) -> None:
        if product_id is not None:
            _nonempty(product_id, field="product_id")
        if type(allow_crossed) is not bool:
            raise TypeError("allow_crossed must be bool")
        self._product_id = product_id
        self._allow_crossed = allow_crossed
        self._bids: dict[Decimal, KrakenBookLevel] = {}
        self._asks: dict[Decimal, KrakenBookLevel] = {}
        self._sequence_id: int | None = None
        self._generation_valid = False

    @property
    def product_id(self) -> str | None:
        return self._product_id

    @property
    def sequence_id(self) -> int | None:
        return self._sequence_id

    @property
    def generation_valid(self) -> bool:
        return self._generation_valid

    @property
    def bids(self) -> tuple[KrakenBookLevel, ...]:
        return tuple(self._bids[price] for price in sorted(self._bids, reverse=True))

    @property
    def asks(self) -> tuple[KrakenBookLevel, ...]:
        return tuple(self._asks[price] for price in sorted(self._asks))

    def apply(self, frame: KrakenFuturesBookFrame) -> KrakenBookOutcome:
        if type(frame) is not KrakenFuturesBookFrame:
            raise TypeError("frame must be KrakenFuturesBookFrame")
        if self._product_id is not None and frame.product_id != self._product_id:
            self._generation_valid = False
            return self._invalid("book_symbol_mismatch")
        if frame.action == "snapshot":
            return self._apply_snapshot(frame)
        if not self._generation_valid:
            return self._invalid("book_generation_invalid")
        previous = self._sequence_id
        if previous is None:
            self._generation_valid = False
            return self._invalid("book_update_before_snapshot")
        if frame.sequence_id <= previous:
            self._generation_valid = False
            return self._invalid("book_sequence_regression")
        bids = dict(self._bids)
        asks = dict(self._asks)
        _apply_levels(bids, frame.bids)
        _apply_levels(asks, frame.asks)
        if not _valid_spread(bids, asks, allow_crossed=self._allow_crossed):
            self._generation_valid = False
            return self._invalid("book_crossed")
        self._bids = bids
        self._asks = asks
        self._sequence_id = frame.sequence_id
        return KrakenBookOutcome(
            action=KrakenBookAction.APPLY,
            integrity=IntegrityMode.BEST_EFFORT,
            generation_valid=True,
            emit_original_to_stream="book_live",
            count_as_book_update=True,
            control_reason=None,
            sequence_id=frame.sequence_id,
        )

    def _apply_snapshot(self, frame: KrakenFuturesBookFrame) -> KrakenBookOutcome:
        if any(level.quantity == 0 for level in (*frame.bids, *frame.asks)):
            self._generation_valid = False
            return self._invalid("book_snapshot_zero_quantity")
        bids = {level.price: level for level in frame.bids}
        asks = {level.price: level for level in frame.asks}
        if len(bids) != len(frame.bids) or len(asks) != len(frame.asks):
            self._generation_valid = False
            return self._invalid("book_snapshot_duplicate_price")
        if not _valid_spread(bids, asks, allow_crossed=self._allow_crossed):
            self._generation_valid = False
            return self._invalid("book_crossed")
        self._bids = bids
        self._asks = asks
        self._product_id = frame.product_id
        self._sequence_id = frame.sequence_id
        self._generation_valid = True
        return KrakenBookOutcome(
            action=KrakenBookAction.SNAPSHOT,
            integrity=IntegrityMode.SNAPSHOT_CHAIN,
            generation_valid=True,
            emit_original_to_stream="book_live",
            count_as_book_update=True,
            control_reason=None,
            sequence_id=frame.sequence_id,
        )

    def _invalid(self, reason: str) -> KrakenBookOutcome:
        return KrakenBookOutcome(
            action=KrakenBookAction.RECONNECT,
            integrity=IntegrityMode.INVALID,
            generation_valid=False,
            emit_original_to_stream="book_live",
            count_as_book_update=False,
            control_reason=reason,
            sequence_id=self._sequence_id,
        )


__all__ = [
    "KrakenBookAction",
    "KrakenBookLevel",
    "KrakenBookOutcome",
    "KrakenBookParseError",
    "KrakenFuturesBook",
    "KrakenFuturesBookFrame",
    "KrakenSpotBook",
    "KrakenSpotBookFrame",
    "parse_futures_book_message",
    "parse_spot_book_message",
]
