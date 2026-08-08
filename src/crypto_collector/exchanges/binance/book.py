from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from enum import StrEnum
from typing import cast

from crypto_collector.domain import IntegrityMode, Market
from crypto_collector.domain.json_codec import JsonPayload
from crypto_collector.exchanges.binance.errors import BinancePayloadError

_MILLISECONDS_TO_NANOSECONDS = 1_000_000
_MAX_SIGNED_64 = 2**63 - 1


class BinanceBookParseError(BinancePayloadError):
    """A Binance snapshot/diff cannot be represented without guessing."""


class BookAction(StrEnum):
    SNAPSHOT = "snapshot"
    APPLY = "apply"
    IGNORE_STALE = "ignore_stale"
    FETCH_BOOTSTRAP = "fetch_bootstrap"


@dataclass(frozen=True, slots=True)
class BinanceBookLevel:
    price: Decimal
    quantity: Decimal
    fields: tuple[str, ...]

    def __post_init__(self) -> None:
        if (
            type(self.price) is not Decimal
            or not self.price.is_finite()
            or self.price <= 0
        ):
            raise ValueError("book price must be a finite positive Decimal")
        if (
            type(self.quantity) is not Decimal
            or not self.quantity.is_finite()
            or self.quantity < 0
        ):
            raise ValueError("book quantity must be a finite non-negative Decimal")
        if (
            type(self.fields) is not tuple
            or len(self.fields) < 2
            or any(type(item) is not str for item in self.fields)
        ):
            raise ValueError("book level fields must preserve at least two strings")
        try:
            raw_price = Decimal(self.fields[0])
            raw_quantity = Decimal(self.fields[1])
        except InvalidOperation as error:
            raise ValueError(
                "book level fields must start with decimal strings"
            ) from error
        if raw_price != self.price or raw_quantity != self.quantity:
            raise ValueError("book level fields must match parsed price and quantity")


@dataclass(frozen=True, slots=True)
class BinanceBookSnapshot:
    last_update_id: int
    bids: tuple[BinanceBookLevel, ...]
    asks: tuple[BinanceBookLevel, ...]
    event_time_ns: int | None = None
    transaction_time_ns: int | None = None

    def __post_init__(self) -> None:
        _sequence(self.last_update_id, field="lastUpdateId")
        _levels_tuple(self.bids, field="snapshot bids", allow_zero=False)
        _levels_tuple(self.asks, field="snapshot asks", allow_zero=False)
        _optional_ns(self.event_time_ns, field="snapshot event_time_ns")
        _optional_ns(self.transaction_time_ns, field="snapshot transaction_time_ns")


@dataclass(frozen=True, slots=True)
class BinanceBookDiff:
    market: Market
    symbol: str
    first_update_id: int
    final_update_id: int
    previous_final_update_id: int | None
    bids: tuple[BinanceBookLevel, ...]
    asks: tuple[BinanceBookLevel, ...]
    event_time_ns: int
    transaction_time_ns: int | None = None

    def __post_init__(self) -> None:
        if type(self.market) is not Market:
            raise TypeError("market must be Market")
        if type(self.symbol) is not str or not self.symbol:
            raise ValueError("symbol must be a non-empty string")
        first = _sequence(self.first_update_id, field="U")
        final = _sequence(self.final_update_id, field="u")
        if first > final:
            raise ValueError("first update ID must not exceed final update ID")
        if self.market is Market.SPOT:
            if self.previous_final_update_id is not None:
                raise ValueError("Spot depth updates must not invent pu")
        elif self.previous_final_update_id is None:
            raise ValueError("Futures depth updates require pu")
        else:
            _sequence(self.previous_final_update_id, field="pu")
        _levels_tuple(self.bids, field="diff bids", allow_zero=True)
        _levels_tuple(self.asks, field="diff asks", allow_zero=True)
        _optional_ns(self.event_time_ns, field="diff event_time_ns", required=True)
        _optional_ns(self.transaction_time_ns, field="diff transaction_time_ns")


@dataclass(frozen=True, slots=True)
class BookOutcome:
    action: BookAction
    integrity: IntegrityMode
    generation_valid: bool
    control_reason: str | None = None
    count_as_book_update: bool = False

    def __post_init__(self) -> None:
        if type(self.action) is not BookAction:
            raise TypeError("action must be BookAction")
        if type(self.integrity) is not IntegrityMode:
            raise TypeError("integrity must be IntegrityMode")
        if type(self.generation_valid) is not bool:
            raise TypeError("generation_valid must be a boolean")
        if self.control_reason is not None and (
            type(self.control_reason) is not str or not self.control_reason
        ):
            raise ValueError("control_reason must be non-empty or None")


def _sequence(value: object, *, field: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SIGNED_64:
        raise ValueError(f"{field} must be a non-negative signed 64-bit integer")
    return value


def _optional_ns(value: object, *, field: str, required: bool = False) -> int | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    return _sequence(value, field=field)


def _levels_tuple(
    value: object, *, field: str, allow_zero: bool
) -> tuple[BinanceBookLevel, ...]:
    if type(value) is not tuple or any(
        type(item) is not BinanceBookLevel for item in value
    ):
        raise TypeError(f"{field} must be a tuple of BinanceBookLevel")
    levels = cast(tuple[BinanceBookLevel, ...], value)
    if not allow_zero and any(item.quantity == 0 for item in levels):
        raise ValueError(f"{field} cannot contain zero quantities")
    prices = tuple(item.price for item in levels)
    if len(set(prices)) != len(prices):
        raise ValueError(f"{field} contains duplicate price levels")
    return levels


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BinanceBookParseError(f"{field} must be a JSON object")
    return cast(Mapping[str, JsonPayload], value)


def _parse_decimal(value: object, *, field: str, allow_zero: bool) -> Decimal:
    if type(value) is not str or not value:
        raise BinanceBookParseError(f"{field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise BinanceBookParseError(f"{field} must be a decimal string") from error
    if not parsed.is_finite() or parsed < 0 or (not allow_zero and parsed == 0):
        qualifier = "non-negative" if allow_zero else "positive"
        raise BinanceBookParseError(f"{field} must be finite and {qualifier}")
    return parsed


def _parse_levels(
    value: object, *, side: str, allow_zero: bool
) -> tuple[BinanceBookLevel, ...]:
    if not isinstance(value, (list, tuple)):
        raise BinanceBookParseError(f"Binance {side} must be an array")
    levels: list[BinanceBookLevel] = []
    for index, raw in enumerate(value):
        if (
            not isinstance(raw, (list, tuple))
            or len(raw) < 2
            or any(type(item) is not str for item in raw)
        ):
            raise BinanceBookParseError(
                f"Binance {side}[{index}] must preserve string fields"
            )
        fields = tuple(cast(Sequence[str], raw))
        levels.append(
            BinanceBookLevel(
                price=_parse_decimal(
                    fields[0], field=f"{side}[{index}].price", allow_zero=False
                ),
                quantity=_parse_decimal(
                    fields[1],
                    field=f"{side}[{index}].quantity",
                    allow_zero=allow_zero,
                ),
                fields=fields,
            )
        )
    try:
        _levels_tuple(tuple(levels), field=side, allow_zero=allow_zero)
    except (TypeError, ValueError) as error:
        raise BinanceBookParseError(str(error)) from error
    return tuple(levels)


def _millisecond_timestamp(value: object, *, field: str) -> int:
    try:
        milliseconds = _sequence(value, field=field)
    except ValueError as error:
        raise BinanceBookParseError(str(error)) from error
    nanoseconds = milliseconds * _MILLISECONDS_TO_NANOSECONDS
    if nanoseconds > _MAX_SIGNED_64:
        raise BinanceBookParseError(f"{field} does not fit signed 64-bit nanoseconds")
    return nanoseconds


def _optional_millisecond_timestamp(
    item: Mapping[str, JsonPayload], field: str
) -> int | None:
    value = item.get(field)
    return None if value is None else _millisecond_timestamp(value, field=field)


def parse_book_snapshot(payload: object, market: Market) -> BinanceBookSnapshot:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    item = _mapping(payload, field="Binance depth snapshot")
    try:
        last_update_id = _sequence(item.get("lastUpdateId"), field="lastUpdateId")
    except ValueError as error:
        raise BinanceBookParseError(str(error)) from error
    event_time_ns = (
        _optional_millisecond_timestamp(item, "E")
        if market is Market.SPOT
        else _millisecond_timestamp(item.get("E"), field="E")
    )
    transaction_time_ns = (
        _optional_millisecond_timestamp(item, "T")
        if market is Market.SPOT
        else _millisecond_timestamp(item.get("T"), field="T")
    )
    return BinanceBookSnapshot(
        last_update_id=last_update_id,
        bids=_parse_levels(item.get("bids"), side="bids", allow_zero=False),
        asks=_parse_levels(item.get("asks"), side="asks", allow_zero=False),
        event_time_ns=event_time_ns,
        transaction_time_ns=transaction_time_ns,
    )


def parse_book_diff(payload: object, market: Market) -> BinanceBookDiff:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    item = _mapping(payload, field="Binance depth update")
    if item.get("e") != "depthUpdate":
        raise BinanceBookParseError("Binance depth update requires e=depthUpdate")
    symbol = item.get("s")
    if type(symbol) is not str or not symbol:
        raise BinanceBookParseError("Binance depth update requires symbol s")
    try:
        return BinanceBookDiff(
            market=market,
            symbol=symbol,
            first_update_id=_sequence(item.get("U"), field="U"),
            final_update_id=_sequence(item.get("u"), field="u"),
            previous_final_update_id=(
                None if market is Market.SPOT else _sequence(item.get("pu"), field="pu")
            ),
            bids=_parse_levels(item.get("b"), side="bids", allow_zero=True),
            asks=_parse_levels(item.get("a"), side="asks", allow_zero=True),
            event_time_ns=_millisecond_timestamp(item.get("E"), field="E"),
            transaction_time_ns=_optional_millisecond_timestamp(item, "T"),
        )
    except (TypeError, ValueError) as error:
        if isinstance(error, BinanceBookParseError):
            raise
        raise BinanceBookParseError(str(error)) from error


class BinanceBookState:
    def __init__(self, market: Market, symbol: str) -> None:
        if type(market) is not Market:
            raise TypeError("market must be Market")
        if type(symbol) is not str or not symbol:
            raise ValueError("symbol must be a non-empty string")
        self._market = market
        self._symbol = symbol
        self._bids: dict[Decimal, BinanceBookLevel] = {}
        self._asks: dict[Decimal, BinanceBookLevel] = {}
        self._last_update_id: int | None = None
        self._awaiting_first = True
        self._valid = False
        self._integrity = IntegrityMode.INVALID
        self._last_diff: BinanceBookDiff | None = None

    @property
    def market(self) -> Market:
        return self._market

    @property
    def symbol(self) -> str:
        return self._symbol

    @property
    def generation_valid(self) -> bool:
        return self._valid

    @property
    def integrity(self) -> IntegrityMode:
        return self._integrity

    @property
    def last_update_id(self) -> int | None:
        return self._last_update_id

    @property
    def bids(self) -> tuple[BinanceBookLevel, ...]:
        return tuple(
            sorted(self._bids.values(), key=lambda item: item.price, reverse=True)
        )

    @property
    def asks(self) -> tuple[BinanceBookLevel, ...]:
        return tuple(sorted(self._asks.values(), key=lambda item: item.price))

    def apply_snapshot(self, snapshot: BinanceBookSnapshot) -> BookOutcome:
        if type(snapshot) is not BinanceBookSnapshot:
            raise TypeError("snapshot must be BinanceBookSnapshot")
        self._bids = {item.price: item for item in snapshot.bids}
        self._asks = {item.price: item for item in snapshot.asks}
        self._last_update_id = snapshot.last_update_id
        self._awaiting_first = True
        self._valid = True
        self._integrity = IntegrityMode.SNAPSHOT_CHAIN
        self._last_diff = None
        return BookOutcome(
            BookAction.SNAPSHOT,
            IntegrityMode.SNAPSHOT_CHAIN,
            True,
            count_as_book_update=True,
        )

    def _invalidate(self, reason: str) -> BookOutcome:
        self._valid = False
        self._integrity = IntegrityMode.INVALID
        return BookOutcome(
            BookAction.FETCH_BOOTSTRAP,
            IntegrityMode.INVALID,
            False,
            control_reason=reason,
        )

    def _apply_levels(self, diff: BinanceBookDiff) -> None:
        bids = dict(self._bids)
        asks = dict(self._asks)
        for target, levels in ((bids, diff.bids), (asks, diff.asks)):
            for level in levels:
                if level.quantity == 0:
                    target.pop(level.price, None)
                else:
                    target[level.price] = level
        self._bids = bids
        self._asks = asks

    def _apply_valid(self, diff: BinanceBookDiff) -> BookOutcome:
        self._apply_levels(diff)
        self._last_update_id = diff.final_update_id
        self._awaiting_first = False
        self._integrity = IntegrityMode.SEQUENCE_VERIFIED
        self._last_diff = diff
        return BookOutcome(
            BookAction.APPLY,
            IntegrityMode.SEQUENCE_VERIFIED,
            True,
            count_as_book_update=True,
        )

    def _apply_spot(self, diff: BinanceBookDiff, last: int) -> BookOutcome:
        if diff.final_update_id < last:
            return BookOutcome(BookAction.IGNORE_STALE, self._integrity, True)
        if diff.final_update_id == last:
            if self._awaiting_first or diff == self._last_diff:
                return BookOutcome(BookAction.IGNORE_STALE, self._integrity, True)
            return self._invalidate("sequence_conflict")
        if self._awaiting_first:
            if not diff.first_update_id <= last <= diff.final_update_id:
                return self._invalidate("bootstrap_range_mismatch")
            return self._apply_valid(diff)
        if diff.first_update_id > last + 1:
            return self._invalidate("sequence_gap")
        return self._apply_valid(diff)

    def _apply_futures(self, diff: BinanceBookDiff, last: int) -> BookOutcome:
        if self._awaiting_first:
            if diff.final_update_id < last:
                return BookOutcome(BookAction.IGNORE_STALE, self._integrity, True)
            if not diff.first_update_id <= last <= diff.final_update_id:
                return self._invalidate("bootstrap_range_mismatch")
            return self._apply_valid(diff)
        if diff == self._last_diff:
            return BookOutcome(BookAction.IGNORE_STALE, self._integrity, True)
        if diff.previous_final_update_id != last:
            return self._invalidate("previous_update_id_mismatch")
        if diff.final_update_id <= last:
            return self._invalidate("sequence_regression")
        return self._apply_valid(diff)

    def apply(self, diff: BinanceBookDiff) -> BookOutcome:
        if type(diff) is not BinanceBookDiff:
            raise TypeError("diff must be BinanceBookDiff")
        if diff.market is not self._market:
            raise ValueError("depth update market does not match book state")
        if diff.symbol != self._symbol:
            return self._invalidate("symbol_mismatch")
        if not self._valid or self._last_update_id is None:
            return BookOutcome(
                BookAction.FETCH_BOOTSTRAP,
                IntegrityMode.INVALID,
                False,
                control_reason="generation_invalid",
            )
        return (
            self._apply_spot(diff, self._last_update_id)
            if self._market is Market.SPOT
            else self._apply_futures(diff, self._last_update_id)
        )


class BinanceSpotBook(BinanceBookState):
    def __init__(self, symbol: str) -> None:
        super().__init__(Market.SPOT, symbol)


class BinanceFuturesBook(BinanceBookState):
    def __init__(self, symbol: str) -> None:
        super().__init__(Market.PERPETUAL, symbol)


class BinanceSpotBookBootstrap(BinanceSpotBook):
    def __init__(
        self,
        snapshot_last_update_id: int,
        *,
        symbol: str,
        bids: tuple[BinanceBookLevel, ...] = (),
        asks: tuple[BinanceBookLevel, ...] = (),
    ) -> None:
        super().__init__(symbol)
        self.apply_snapshot(BinanceBookSnapshot(snapshot_last_update_id, bids, asks))


class BinanceFuturesBookBootstrap(BinanceFuturesBook):
    def __init__(
        self,
        snapshot_last_update_id: int,
        *,
        symbol: str,
        bids: tuple[BinanceBookLevel, ...] = (),
        asks: tuple[BinanceBookLevel, ...] = (),
    ) -> None:
        super().__init__(symbol)
        self.apply_snapshot(BinanceBookSnapshot(snapshot_last_update_id, bids, asks))


__all__ = [
    "BinanceBookDiff",
    "BinanceBookLevel",
    "BinanceBookParseError",
    "BinanceBookSnapshot",
    "BinanceBookState",
    "BinanceFuturesBook",
    "BinanceFuturesBookBootstrap",
    "BinanceSpotBook",
    "BinanceSpotBookBootstrap",
    "BookAction",
    "BookOutcome",
    "parse_book_diff",
    "parse_book_snapshot",
]
