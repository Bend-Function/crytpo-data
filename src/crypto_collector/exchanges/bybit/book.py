from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum

from crypto_collector.domain import IntegrityMode
from crypto_collector.domain.clock import Clock, SystemClock

_MAX_SIGNED_64 = 2**63 - 1
_STANDARD_DEPTHS = frozenset({1, 50, 200, 1000})
_FULL_DELTA_ESTIMATE_BASE_BYTES = 128


class BybitBookParseError(ValueError):
    pass


class BybitStandardMessageKind(StrEnum):
    SNAPSHOT = "snapshot"
    DELTA = "delta"


class BybitBookAction(StrEnum):
    SNAPSHOT = "snapshot"
    BOOTSTRAP = "bootstrap"
    APPLY = "apply"
    HEARTBEAT = "heartbeat"
    BUFFER = "buffer"
    IGNORE = "ignore"
    RECONNECT = "reconnect"
    REFETCH_BOOTSTRAP = "refetch_bootstrap"


class BybitFullBookPhase(StrEnum):
    BUFFERING = "buffering"
    LIVE = "live"


class BybitBookAvailability(StrEnum):
    UNKNOWN = "unknown"
    AVAILABLE = "available"
    NO_BOOK = "no_book"


@dataclass(frozen=True, slots=True)
class BybitFullBookBufferLimits:
    max_deltas: int = 4096
    max_estimated_bytes: int = 64 * 1024 * 1024
    max_elapsed_ns: int = 30_000_000_000

    def __post_init__(self) -> None:
        _positive_int(self.max_deltas, field="max_deltas")
        _positive_int(self.max_estimated_bytes, field="max_estimated_bytes")
        _positive_int(self.max_elapsed_ns, field="max_elapsed_ns")


@dataclass(frozen=True, slots=True)
class BybitBookLevel:
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
            raise TypeError("book level fields must contain at least two strings")
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
            raise ValueError("book level fields must match price and quantity")


@dataclass(frozen=True, slots=True)
class BybitStandardBookFrame:
    topic: str
    depth: int
    symbol: str
    kind: BybitStandardMessageKind
    bids: tuple[BybitBookLevel, ...]
    asks: tuple[BybitBookLevel, ...]
    timestamp_ns: int
    matching_timestamp_ns: int
    update_id: int
    sequence_id: int

    def __post_init__(self) -> None:
        _nonempty_string(self.topic, field="topic")
        _positive_int(self.depth, field="depth")
        if self.depth not in _STANDARD_DEPTHS:
            raise ValueError("depth must be one of 1, 50, 200, or 1000")
        _nonempty_string(self.symbol, field="symbol")
        if type(self.kind) is not BybitStandardMessageKind:
            raise TypeError("kind must be BybitStandardMessageKind")
        _validate_levels(self.bids, field="bids")
        _validate_levels(self.asks, field="asks")
        _nonnegative_int(self.timestamp_ns, field="timestamp_ns")
        _nonnegative_int(
            self.matching_timestamp_ns,
            field="matching_timestamp_ns",
        )
        _positive_int(self.update_id, field="update_id")
        _nonnegative_int(self.sequence_id, field="sequence_id")


@dataclass(frozen=True, slots=True)
class BybitFullBookDelta:
    topic: str
    symbol: str
    bids: tuple[BybitBookLevel, ...]
    asks: tuple[BybitBookLevel, ...]
    timestamp_ns: int
    matching_timestamp_ns: int
    update_id: int
    sequence_id: int

    def __post_init__(self) -> None:
        _nonempty_string(self.topic, field="topic")
        _nonempty_string(self.symbol, field="symbol")
        _validate_levels(self.bids, field="bids")
        _validate_levels(self.asks, field="asks")
        _nonnegative_int(self.timestamp_ns, field="timestamp_ns")
        _nonnegative_int(
            self.matching_timestamp_ns,
            field="matching_timestamp_ns",
        )
        _positive_int(self.update_id, field="update_id")
        _nonnegative_int(self.sequence_id, field="sequence_id")


@dataclass(frozen=True, slots=True)
class BybitFullBookSnapshot:
    symbol: str
    bids: tuple[BybitBookLevel, ...]
    asks: tuple[BybitBookLevel, ...]
    timestamp_ns: int
    matching_timestamp_ns: int
    update_id: int
    sequence_id: int

    def __post_init__(self) -> None:
        _nonempty_string(self.symbol, field="symbol")
        _validate_levels(self.bids, field="bids")
        _validate_levels(self.asks, field="asks")
        _nonnegative_int(self.timestamp_ns, field="timestamp_ns")
        _nonnegative_int(
            self.matching_timestamp_ns,
            field="matching_timestamp_ns",
        )
        _positive_int(self.update_id, field="update_id")
        _nonnegative_int(self.sequence_id, field="sequence_id")


@dataclass(frozen=True, slots=True)
class BybitBookOutcome:
    action: BybitBookAction
    integrity: IntegrityMode
    generation_valid: bool
    emit_original_to_stream: str | None
    count_as_book_update: bool
    control_reason: str | None
    update_id: int | None
    sequence_id: int | None
    buffered_count: int
    availability: BybitBookAvailability


def _nonempty_string(value: object, *, field: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field} must be a non-empty trimmed string")
    return value


def _signed_int(value: object, *, field: str) -> int:
    if type(value) is not int or not -(2**63) <= value <= _MAX_SIGNED_64:
        raise ValueError(f"{field} must fit a signed 64-bit integer")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    parsed = _signed_int(value, field=field)
    if parsed < 0:
        raise ValueError(f"{field} must be non-negative")
    return parsed


def _positive_int(value: object, *, field: str) -> int:
    parsed = _nonnegative_int(value, field=field)
    if parsed == 0:
        raise ValueError(f"{field} must be positive")
    return parsed


def _parse_integer(value: object, *, field: str, positive: bool = False) -> int:
    if type(value) is not int:
        raise BybitBookParseError(f"{field} must be a JSON integer")
    try:
        return (
            _positive_int(value, field=field)
            if positive
            else _nonnegative_int(value, field=field)
        )
    except ValueError as error:
        raise BybitBookParseError(str(error)) from error


def _parse_timestamp_ns(
    value: object,
    *,
    field: str,
) -> int:
    milliseconds = _parse_integer(value, field=field)
    if milliseconds > _MAX_SIGNED_64 // 1_000_000:
        raise BybitBookParseError(f"{field} overflows nanoseconds")
    return milliseconds * 1_000_000


def _parse_decimal(value: object, *, field: str, allow_zero: bool) -> Decimal:
    if type(value) is not str or not value or value != value.strip():
        raise BybitBookParseError(f"{field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise BybitBookParseError(f"{field} must be a decimal string") from error
    if not parsed.is_finite() or parsed < 0 or (not allow_zero and parsed == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise BybitBookParseError(f"{field} must be a finite {qualifier} decimal")
    return parsed


def _validate_levels(
    levels: object,
    *,
    field: str,
) -> tuple[BybitBookLevel, ...]:
    if type(levels) is not tuple or any(
        type(level) is not BybitBookLevel for level in levels
    ):
        raise TypeError(f"{field} must be a tuple of BybitBookLevel")
    prices = [level.price for level in levels]
    if len(prices) != len(set(prices)):
        raise ValueError(f"{field} contains a duplicate price")
    return levels


def _parse_levels(
    value: object,
    *,
    field: str,
    snapshot: bool,
    descending: bool,
    enforce_order: bool,
) -> tuple[BybitBookLevel, ...]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise BybitBookParseError(f"{field} must be an array")
    levels: list[BybitBookLevel] = []
    prices: set[Decimal] = set()
    prior_price: Decimal | None = None
    for index, raw_level in enumerate(value):
        if not isinstance(raw_level, Sequence) or isinstance(
            raw_level,
            (str, bytes, bytearray),
        ):
            raise BybitBookParseError(f"{field}[{index}] must be an array")
        fields = tuple(raw_level)
        if len(fields) < 2 or any(type(item) is not str for item in fields):
            raise BybitBookParseError(
                f"{field}[{index}] must contain at least two string fields"
            )
        price = _parse_decimal(
            fields[0],
            field=f"{field}[{index}].price",
            allow_zero=False,
        )
        quantity = _parse_decimal(
            fields[1],
            field=f"{field}[{index}].quantity",
            allow_zero=not snapshot,
        )
        if price in prices:
            raise BybitBookParseError(f"{field} contains a duplicate price")
        if (
            enforce_order
            and prior_price is not None
            and (
                (descending and price >= prior_price)
                or (not descending and price <= prior_price)
            )
        ):
            order = "descending" if descending else "ascending"
            raise BybitBookParseError(f"{field} prices must be strictly {order}")
        prices.add(price)
        prior_price = price
        levels.append(BybitBookLevel(price=price, quantity=quantity, fields=fields))
    return tuple(levels)


def _parse_data(
    data: object,
    *,
    field: str,
    snapshot: bool,
    enforce_order: bool,
) -> tuple[
    str,
    tuple[BybitBookLevel, ...],
    tuple[BybitBookLevel, ...],
    int,
    int,
]:
    if not isinstance(data, Mapping):
        raise BybitBookParseError(f"{field} must be an object")
    symbol_raw = data.get("s")
    try:
        symbol = _nonempty_string(symbol_raw, field=f"{field}.s")
    except ValueError as error:
        raise BybitBookParseError(str(error)) from error
    return (
        symbol,
        _parse_levels(
            data.get("b"),
            field=f"{field}.b",
            snapshot=snapshot,
            descending=True,
            enforce_order=enforce_order,
        ),
        _parse_levels(
            data.get("a"),
            field=f"{field}.a",
            snapshot=snapshot,
            descending=False,
            enforce_order=enforce_order,
        ),
        _parse_integer(data.get("u"), field=f"{field}.u", positive=True),
        _parse_integer(data.get("seq"), field=f"{field}.seq"),
    )


def _parse_standard_topic(topic: object) -> tuple[str, int, str]:
    try:
        parsed_topic = _nonempty_string(topic, field="topic")
    except ValueError as error:
        raise BybitBookParseError(str(error)) from error
    parts = parsed_topic.split(".")
    if len(parts) != 3 or parts[0] != "orderbook" or not parts[1].isdigit():
        raise BybitBookParseError("topic must have the form orderbook.{depth}.{symbol}")
    try:
        depth = _positive_int(int(parts[1]), field="topic depth")
        symbol = _nonempty_string(parts[2], field="topic symbol")
    except ValueError as error:
        raise BybitBookParseError(str(error)) from error
    if depth not in _STANDARD_DEPTHS:
        raise BybitBookParseError(
            "standard orderbook depth must be one of 1, 50, 200, or 1000"
        )
    return parsed_topic, depth, symbol


def parse_standard_book_message(message: object) -> BybitStandardBookFrame:
    if not isinstance(message, Mapping):
        raise BybitBookParseError("standard book message must be an object")
    topic, depth, topic_symbol = _parse_standard_topic(message.get("topic"))
    kind_raw = message.get("type")
    if type(kind_raw) is not str:
        raise BybitBookParseError("standard book type must be snapshot or delta")
    try:
        kind = BybitStandardMessageKind(kind_raw)
    except ValueError as error:
        raise BybitBookParseError(
            "standard book type must be snapshot or delta"
        ) from error
    symbol, bids, asks, update_id, sequence_id = _parse_data(
        message.get("data"),
        field="data",
        snapshot=kind is BybitStandardMessageKind.SNAPSHOT,
        enforce_order=kind is BybitStandardMessageKind.SNAPSHOT,
    )
    if symbol != topic_symbol:
        raise BybitBookParseError("topic symbol and data.s must match")
    if depth == 1 and kind is not BybitStandardMessageKind.SNAPSHOT:
        raise BybitBookParseError("standard depth 1 is snapshot-only")
    timestamp_ns = _parse_timestamp_ns(message.get("ts"), field="ts")
    matching_timestamp_ns = _parse_timestamp_ns(
        message.get("cts"),
        field="cts",
    )
    return BybitStandardBookFrame(
        topic=topic,
        depth=depth,
        symbol=symbol,
        kind=kind,
        bids=bids,
        asks=asks,
        timestamp_ns=timestamp_ns,
        matching_timestamp_ns=matching_timestamp_ns,
        update_id=update_id,
        sequence_id=sequence_id,
    )


def parse_full_book_delta(message: object) -> BybitFullBookDelta:
    if not isinstance(message, Mapping):
        raise BybitBookParseError("full book message must be an object")
    topic_raw = message.get("topic")
    try:
        topic = _nonempty_string(topic_raw, field="topic")
    except ValueError as error:
        raise BybitBookParseError(str(error)) from error
    parts = topic.split(".")
    if len(parts) != 3 or parts[:2] != ["orderbook", "full"]:
        raise BybitBookParseError(
            "full book topic must have the form orderbook.full.{symbol}"
        )
    if message.get("type") != "delta":
        raise BybitBookParseError("full book messages must be delta")
    symbol, bids, asks, update_id, sequence_id = _parse_data(
        message.get("data"),
        field="data",
        snapshot=False,
        enforce_order=True,
    )
    if symbol != parts[2]:
        raise BybitBookParseError("topic symbol and data.s must match")
    timestamp_ns = _parse_timestamp_ns(message.get("ts"), field="ts")
    matching_timestamp_ns = _parse_timestamp_ns(
        message.get("cts"),
        field="cts",
    )
    return BybitFullBookDelta(
        topic=topic,
        symbol=symbol,
        bids=bids,
        asks=asks,
        timestamp_ns=timestamp_ns,
        matching_timestamp_ns=matching_timestamp_ns,
        update_id=update_id,
        sequence_id=sequence_id,
    )


def parse_full_book_snapshot(result: object) -> BybitFullBookSnapshot:
    symbol, bids, asks, update_id, sequence_id = _parse_data(
        result,
        field="result",
        snapshot=True,
        enforce_order=True,
    )
    assert isinstance(result, Mapping)
    timestamp_ns = _parse_timestamp_ns(result.get("ts"), field="result.ts")
    matching_timestamp_ns = _parse_timestamp_ns(
        result.get("cts"),
        field="result.cts",
    )
    return BybitFullBookSnapshot(
        symbol=symbol,
        bids=bids,
        asks=asks,
        timestamp_ns=timestamp_ns,
        matching_timestamp_ns=matching_timestamp_ns,
        update_id=update_id,
        sequence_id=sequence_id,
    )


def parse_full_book_snapshot_response(response: object) -> BybitFullBookSnapshot:
    if not isinstance(response, Mapping):
        raise BybitBookParseError("full book response must be an object")
    if type(response.get("retCode")) is not int or response.get("retCode") != 0:
        raise BybitBookParseError("full book response retCode must be zero")
    if type(response.get("retMsg")) is not str:
        raise BybitBookParseError("full book response retMsg must be a string")
    return parse_full_book_snapshot(response.get("result"))


def _apply_levels(
    side: dict[Decimal, BybitBookLevel],
    updates: tuple[BybitBookLevel, ...],
) -> None:
    for level in updates:
        if level.quantity == 0:
            side.pop(level.price, None)
        else:
            side[level.price] = level


def _spread_is_valid(
    bids: Mapping[Decimal, BybitBookLevel],
    asks: Mapping[Decimal, BybitBookLevel],
) -> bool:
    return not bids or not asks or max(bids) < min(asks)


def estimate_full_book_delta_bytes(delta: BybitFullBookDelta) -> int:
    if type(delta) is not BybitFullBookDelta:
        raise TypeError("delta must be BybitFullBookDelta")
    total = (
        _FULL_DELTA_ESTIMATE_BASE_BYTES
        + len(delta.topic.encode("utf-8"))
        + len(delta.symbol.encode("utf-8"))
    )
    for level in (*delta.bids, *delta.asks):
        total += 32
        total += sum(len(field.encode("utf-8")) for field in level.fields)
    return total


class BybitStandardBookState:
    def __init__(self) -> None:
        self._bids: dict[Decimal, BybitBookLevel] = {}
        self._asks: dict[Decimal, BybitBookLevel] = {}
        self._topic: str | None = None
        self._depth: int | None = None
        self._symbol: str | None = None
        self._update_id: int | None = None
        self._sequence_id: int | None = None
        self._generation_valid = False
        self._availability = BybitBookAvailability.UNKNOWN
        self._last_delta: BybitStandardBookFrame | None = None

    @property
    def bids(self) -> tuple[BybitBookLevel, ...]:
        return tuple(self._bids[price] for price in sorted(self._bids, reverse=True))

    @property
    def asks(self) -> tuple[BybitBookLevel, ...]:
        return tuple(self._asks[price] for price in sorted(self._asks))

    @property
    def update_id(self) -> int | None:
        return self._update_id

    @property
    def sequence_id(self) -> int | None:
        return self._sequence_id

    @property
    def generation_valid(self) -> bool:
        return self._generation_valid

    @property
    def availability(self) -> BybitBookAvailability:
        return self._availability

    def apply_message(self, message: object) -> BybitBookOutcome:
        try:
            frame = parse_standard_book_message(message)
        except BybitBookParseError:
            self.invalidate("book_malformed")
            raise
        return self.apply(frame)

    def apply(self, frame: BybitStandardBookFrame) -> BybitBookOutcome:
        if type(frame) is not BybitStandardBookFrame:
            raise TypeError("frame must be BybitStandardBookFrame")
        if frame.kind is BybitStandardMessageKind.SNAPSHOT:
            return self._apply_snapshot(frame)
        if not self._generation_valid:
            return self._invalid("book_generation_invalid")
        if not self._same_stream(frame):
            return self.invalidate("book_stream_mismatch")
        if frame.depth == 1:
            return self.invalidate("book_l1_delta")
        if frame.update_id == 1:
            return self.invalidate("book_u1_delta_ambiguous")
        if frame == self._last_delta:
            return self._outcome(
                action=BybitBookAction.IGNORE,
                integrity=IntegrityMode.SNAPSHOT_CHAIN,
                count=False,
                reason="book_duplicate_delta",
            )
        assert self._sequence_id is not None
        if frame.sequence_id < self._sequence_id:
            return self.invalidate("book_sequence_regression")
        bids = dict(self._bids)
        asks = dict(self._asks)
        _apply_levels(bids, frame.bids)
        _apply_levels(asks, frame.asks)
        if not _spread_is_valid(bids, asks):
            return self.invalidate("book_crossed")
        self._bids = bids
        self._asks = asks
        self._update_id = frame.update_id
        self._sequence_id = frame.sequence_id
        self._last_delta = frame
        return self._outcome(
            action=BybitBookAction.APPLY,
            integrity=IntegrityMode.SNAPSHOT_CHAIN,
            count=True,
            reason=None,
        )

    def invalidate(self, reason: str) -> BybitBookOutcome:
        _nonempty_string(reason, field="reason")
        self._generation_valid = False
        self._availability = BybitBookAvailability.UNKNOWN
        return self._invalid(reason)

    def _apply_snapshot(self, frame: BybitStandardBookFrame) -> BybitBookOutcome:
        if self._topic is not None and not self._same_stream(frame):
            return self.invalidate("book_stream_mismatch")
        if any(level.quantity == 0 for level in (*frame.bids, *frame.asks)):
            return self.invalidate("book_snapshot_zero_quantity")
        bids = {level.price: level for level in frame.bids}
        asks = {level.price: level for level in frame.asks}
        if not _spread_is_valid(bids, asks):
            return self.invalidate("book_crossed")
        heartbeat = (
            self._generation_valid
            and frame.depth == 1
            and frame.update_id == self._update_id
            and bids == self._bids
            and asks == self._asks
        )
        self._bids = bids
        self._asks = asks
        self._topic = frame.topic
        self._depth = frame.depth
        self._symbol = frame.symbol
        self._update_id = frame.update_id
        self._sequence_id = frame.sequence_id
        self._generation_valid = True
        self._availability = (
            BybitBookAvailability.AVAILABLE
            if bids or asks
            else BybitBookAvailability.NO_BOOK
        )
        self._last_delta = None
        return self._outcome(
            action=(
                BybitBookAction.HEARTBEAT if heartbeat else BybitBookAction.SNAPSHOT
            ),
            integrity=IntegrityMode.SNAPSHOT_CHAIN,
            count=not heartbeat,
            reason=(
                None
                if heartbeat or frame.update_id != 1
                else "book_service_reinitialization"
            ),
        )

    def _same_stream(self, frame: BybitStandardBookFrame) -> bool:
        return (
            frame.topic == self._topic
            and frame.depth == self._depth
            and frame.symbol == self._symbol
        )

    def _outcome(
        self,
        *,
        action: BybitBookAction,
        integrity: IntegrityMode,
        count: bool,
        reason: str | None,
    ) -> BybitBookOutcome:
        return BybitBookOutcome(
            action=action,
            integrity=integrity,
            generation_valid=self._generation_valid,
            emit_original_to_stream="book_live",
            count_as_book_update=count,
            control_reason=reason,
            update_id=self._update_id,
            sequence_id=self._sequence_id,
            buffered_count=0,
            availability=self._availability,
        )

    def _invalid(self, reason: str) -> BybitBookOutcome:
        return self._outcome(
            action=BybitBookAction.RECONNECT,
            integrity=IntegrityMode.INVALID,
            count=False,
            reason=reason,
        )


class BybitFullBookState:
    def __init__(
        self,
        *,
        buffer_limits: BybitFullBookBufferLimits | None = None,
        clock: Clock | None = None,
    ) -> None:
        if (
            buffer_limits is not None
            and type(buffer_limits) is not BybitFullBookBufferLimits
        ):
            raise TypeError("buffer_limits must be BybitFullBookBufferLimits or None")
        self._bids: dict[Decimal, BybitBookLevel] = {}
        self._asks: dict[Decimal, BybitBookLevel] = {}
        self._topic: str | None = None
        self._symbol: str | None = None
        self._update_id: int | None = None
        self._sequence_id: int | None = None
        self._generation_valid = False
        self._availability = BybitBookAvailability.UNKNOWN
        self._phase = BybitFullBookPhase.BUFFERING
        self._buffer_limits = (
            BybitFullBookBufferLimits() if buffer_limits is None else buffer_limits
        )
        self._clock = SystemClock() if clock is None else clock
        self._buffer: list[BybitFullBookDelta] = []
        self._buffer_estimated_bytes = 0
        self._buffer_started_ns: int | None = None
        self._last_delta: BybitFullBookDelta | None = None

    @property
    def bids(self) -> tuple[BybitBookLevel, ...]:
        return tuple(self._bids[price] for price in sorted(self._bids, reverse=True))

    @property
    def asks(self) -> tuple[BybitBookLevel, ...]:
        return tuple(self._asks[price] for price in sorted(self._asks))

    @property
    def update_id(self) -> int | None:
        return self._update_id

    @property
    def sequence_id(self) -> int | None:
        return self._sequence_id

    @property
    def generation_valid(self) -> bool:
        return self._generation_valid

    @property
    def availability(self) -> BybitBookAvailability:
        return self._availability

    @property
    def phase(self) -> BybitFullBookPhase:
        return self._phase

    @property
    def buffered_deltas(self) -> tuple[BybitFullBookDelta, ...]:
        return tuple(self._buffer)

    @property
    def buffered_estimated_bytes(self) -> int:
        return self._buffer_estimated_bytes

    @property
    def buffer_started_ns(self) -> int | None:
        return self._buffer_started_ns

    def apply_delta_message(self, message: object) -> BybitBookOutcome:
        try:
            delta = parse_full_book_delta(message)
        except BybitBookParseError:
            self.invalidate("full_book_malformed_delta")
            raise
        return self.apply_delta(delta)

    def apply_snapshot_response(self, response: object) -> BybitBookOutcome:
        try:
            snapshot = parse_full_book_snapshot_response(response)
        except BybitBookParseError:
            self._restart_without_delta("full_book_malformed_snapshot")
            raise
        return self.apply_snapshot(snapshot)

    def apply_delta(self, delta: BybitFullBookDelta) -> BybitBookOutcome:
        if type(delta) is not BybitFullBookDelta:
            raise TypeError("delta must be BybitFullBookDelta")
        if self._topic is None:
            self._topic = delta.topic
            self._symbol = delta.symbol
        elif delta.topic != self._topic or delta.symbol != self._symbol:
            return self.invalidate("full_book_stream_mismatch")
        if self._phase is BybitFullBookPhase.LIVE:
            return self._apply_live_delta(delta)
        return self._buffer_delta(delta)

    def apply_snapshot(
        self,
        snapshot: BybitFullBookSnapshot,
    ) -> BybitBookOutcome:
        if type(snapshot) is not BybitFullBookSnapshot:
            raise TypeError("snapshot must be BybitFullBookSnapshot")
        if self._symbol is None or snapshot.symbol != self._symbol:
            return self._refetch("full_book_snapshot_symbol_mismatch")
        if self._phase is BybitFullBookPhase.LIVE:
            return self._outcome(
                action=BybitBookAction.IGNORE,
                integrity=IntegrityMode.SEQUENCE_VERIFIED,
                count=False,
                reason="full_book_unexpected_snapshot_ignored",
                stream="book_live_bootstrap",
            )
        expired_reason = self._buffer_expired_reason()
        if expired_reason is not None:
            return self._restart_without_delta(expired_reason)
        if any(level.quantity == 0 for level in (*snapshot.bids, *snapshot.asks)):
            return self._refetch("full_book_snapshot_zero_quantity")
        if not self._buffer:
            return self._refetch("full_book_snapshot_without_buffer")

        first = self._buffer[0]
        if snapshot.sequence_id < first.sequence_id:
            return self._refetch("full_book_snapshot_too_old")
        aligned_index: int | None = None
        for index, delta in enumerate(self._buffer):
            if delta.sequence_id < snapshot.sequence_id:
                continue
            if (
                delta.sequence_id == snapshot.sequence_id
                and delta.update_id == snapshot.update_id
            ):
                aligned_index = index
            break
        if aligned_index is None:
            return self._refetch("full_book_snapshot_handoff_mismatch")

        bids = {level.price: level for level in snapshot.bids}
        asks = {level.price: level for level in snapshot.asks}
        if not _spread_is_valid(bids, asks):
            return self._refetch("full_book_crossed_snapshot")
        update_id = snapshot.update_id
        sequence_id = snapshot.sequence_id
        for delta in self._buffer[aligned_index + 1 :]:
            if delta.update_id != update_id + 1:
                return self._restart_without_delta("full_book_buffer_u_gap")
            if delta.sequence_id < sequence_id:
                return self._restart_without_delta(
                    "full_book_buffer_sequence_regression"
                )
            _apply_levels(bids, delta.bids)
            _apply_levels(asks, delta.asks)
            if not _spread_is_valid(bids, asks):
                return self._restart_without_delta("full_book_crossed")
            update_id = delta.update_id
            sequence_id = delta.sequence_id

        self._bids = bids
        self._asks = asks
        self._update_id = update_id
        self._sequence_id = sequence_id
        self._generation_valid = True
        self._availability = (
            BybitBookAvailability.AVAILABLE
            if bids or asks
            else BybitBookAvailability.NO_BOOK
        )
        self._phase = BybitFullBookPhase.LIVE
        self._last_delta = self._buffer[-1]
        self._clear_buffer()
        return self._outcome(
            action=BybitBookAction.BOOTSTRAP,
            integrity=IntegrityMode.SEQUENCE_VERIFIED,
            count=True,
            reason=(
                None
                if self._availability is BybitBookAvailability.AVAILABLE
                else "full_book_no_book"
            ),
            stream="book_live_bootstrap",
        )

    def invalidate(self, reason: str) -> BybitBookOutcome:
        _nonempty_string(reason, field="reason")
        self._discard_live_book()
        self._clear_buffer()
        return self._refetch(reason)

    def _buffer_delta(self, delta: BybitFullBookDelta) -> BybitBookOutcome:
        expired_reason = self._buffer_expired_reason()
        if expired_reason is not None:
            return self._restart_without_delta(expired_reason)
        if self._buffer and delta == self._buffer[-1]:
            return self._outcome(
                action=BybitBookAction.IGNORE,
                integrity=IntegrityMode.INVALID,
                count=False,
                reason="full_book_duplicate_buffered_delta",
            )
        if not self._buffer:
            limit_reason = self._start_buffer(delta)
            if limit_reason is not None:
                return self._restart_without_delta(limit_reason)
            return self._outcome(
                action=(
                    BybitBookAction.REFETCH_BOOTSTRAP
                    if delta.update_id == 1
                    else BybitBookAction.BUFFER
                ),
                integrity=IntegrityMode.INVALID,
                count=False,
                reason=("full_book_reinitialization" if delta.update_id == 1 else None),
            )

        prior = self._buffer[-1]
        if delta.update_id == prior.update_id:
            return self._restart_without_delta("full_book_conflicting_duplicate")
        if delta.update_id == 1:
            return self._restart_with_delta(
                delta,
                "full_book_reinitialization",
            )
        if delta.sequence_id < prior.sequence_id:
            return self._outcome(
                action=BybitBookAction.IGNORE,
                integrity=IntegrityMode.INVALID,
                count=False,
                reason="full_book_buffer_sequence_regression",
            )
        if delta.update_id != prior.update_id + 1:
            return self._restart_with_delta(
                delta,
                "full_book_buffer_u_discontinuity",
            )
        limit_reason = self._append_buffer(delta)
        if limit_reason is not None:
            return self._restart_without_delta(limit_reason)
        return self._outcome(
            action=BybitBookAction.BUFFER,
            integrity=IntegrityMode.INVALID,
            count=False,
            reason=None,
        )

    def _apply_live_delta(self, delta: BybitFullBookDelta) -> BybitBookOutcome:
        assert self._update_id is not None
        assert self._sequence_id is not None
        if delta.update_id == self._update_id:
            if delta != self._last_delta:
                return self._restart_without_delta("full_book_conflicting_duplicate")
            return self._outcome(
                action=BybitBookAction.IGNORE,
                integrity=IntegrityMode.SEQUENCE_VERIFIED,
                count=False,
                reason="full_book_duplicate_delta",
            )
        if delta.update_id == 1:
            return self._restart_with_delta(
                delta,
                "full_book_reinitialization",
            )
        if delta.update_id < self._update_id:
            return self._outcome(
                action=BybitBookAction.IGNORE,
                integrity=IntegrityMode.SEQUENCE_VERIFIED,
                count=False,
                reason="full_book_stale_or_duplicate_delta",
            )
        if delta.sequence_id < self._sequence_id:
            return self._restart_without_delta("full_book_sequence_regression")
        if delta.update_id > self._update_id + 1:
            return self._restart_with_delta(delta, "full_book_u_gap")

        bids = dict(self._bids)
        asks = dict(self._asks)
        _apply_levels(bids, delta.bids)
        _apply_levels(asks, delta.asks)
        if not _spread_is_valid(bids, asks):
            return self._restart_without_delta("full_book_crossed")
        self._bids = bids
        self._asks = asks
        self._update_id = delta.update_id
        self._sequence_id = delta.sequence_id
        self._last_delta = delta
        self._availability = (
            BybitBookAvailability.AVAILABLE
            if bids or asks
            else BybitBookAvailability.NO_BOOK
        )
        return self._outcome(
            action=BybitBookAction.APPLY,
            integrity=IntegrityMode.SEQUENCE_VERIFIED,
            count=True,
            reason=None,
        )

    def _restart_with_delta(
        self,
        delta: BybitFullBookDelta,
        reason: str,
    ) -> BybitBookOutcome:
        self._discard_live_book()
        self._clear_buffer()
        limit_reason = self._start_buffer(delta)
        if limit_reason is not None:
            return self._refetch(limit_reason)
        return self._refetch(reason)

    def _restart_without_delta(self, reason: str) -> BybitBookOutcome:
        self._discard_live_book()
        self._clear_buffer()
        return self._refetch(reason)

    def _start_buffer(self, delta: BybitFullBookDelta) -> str | None:
        estimated_bytes = estimate_full_book_delta_bytes(delta)
        if estimated_bytes > self._buffer_limits.max_estimated_bytes:
            return "full_book_buffer_bytes_exceeded"
        now_ns = self._now_ns()
        self._buffer.append(delta)
        self._buffer_estimated_bytes = estimated_bytes
        self._buffer_started_ns = now_ns
        return None

    def _append_buffer(self, delta: BybitFullBookDelta) -> str | None:
        if len(self._buffer) + 1 > self._buffer_limits.max_deltas:
            return "full_book_buffer_count_exceeded"
        estimated_bytes = estimate_full_book_delta_bytes(delta)
        if (
            self._buffer_estimated_bytes + estimated_bytes
            > self._buffer_limits.max_estimated_bytes
        ):
            return "full_book_buffer_bytes_exceeded"
        self._buffer.append(delta)
        self._buffer_estimated_bytes += estimated_bytes
        return None

    def _buffer_expired_reason(self) -> str | None:
        if not self._buffer:
            return None
        assert self._buffer_started_ns is not None
        now_ns = self._now_ns()
        if now_ns < self._buffer_started_ns:
            return "full_book_buffer_clock_regression"
        if now_ns - self._buffer_started_ns > self._buffer_limits.max_elapsed_ns:
            return "full_book_buffer_elapsed_exceeded"
        return None

    def _now_ns(self) -> int:
        return _nonnegative_int(
            self._clock.monotonic_ns(),
            field="clock.monotonic_ns",
        )

    def _clear_buffer(self) -> None:
        self._buffer.clear()
        self._buffer_estimated_bytes = 0
        self._buffer_started_ns = None

    def _discard_live_book(self) -> None:
        self._bids.clear()
        self._asks.clear()
        self._update_id = None
        self._sequence_id = None
        self._generation_valid = False
        self._availability = BybitBookAvailability.UNKNOWN
        self._phase = BybitFullBookPhase.BUFFERING
        self._last_delta = None

    def _refetch(self, reason: str) -> BybitBookOutcome:
        return self._outcome(
            action=BybitBookAction.REFETCH_BOOTSTRAP,
            integrity=IntegrityMode.INVALID,
            count=False,
            reason=reason,
        )

    def _outcome(
        self,
        *,
        action: BybitBookAction,
        integrity: IntegrityMode,
        count: bool,
        reason: str | None,
        stream: str = "book_live",
    ) -> BybitBookOutcome:
        return BybitBookOutcome(
            action=action,
            integrity=integrity,
            generation_valid=self._generation_valid,
            emit_original_to_stream=stream,
            count_as_book_update=count,
            control_reason=reason,
            update_id=self._update_id,
            sequence_id=self._sequence_id,
            buffered_count=len(self._buffer),
            availability=self._availability,
        )


__all__ = [
    "BybitBookAction",
    "BybitBookAvailability",
    "BybitBookLevel",
    "BybitBookOutcome",
    "BybitBookParseError",
    "BybitFullBookBufferLimits",
    "BybitFullBookDelta",
    "BybitFullBookPhase",
    "BybitFullBookSnapshot",
    "BybitFullBookState",
    "BybitStandardBookFrame",
    "BybitStandardBookState",
    "BybitStandardMessageKind",
    "estimate_full_book_delta_bytes",
    "parse_full_book_delta",
    "parse_full_book_snapshot",
    "parse_full_book_snapshot_response",
    "parse_standard_book_message",
]
