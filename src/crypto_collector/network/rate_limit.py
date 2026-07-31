from __future__ import annotations

import re
from decimal import Decimal, DecimalException, localcontext
from typing import TypeAlias

from crypto_collector.domain.clock import Clock

BudgetKey: TypeAlias = tuple[str, str, str]
DecimalInput: TypeAlias = int | Decimal

_NANOSECONDS_PER_SECOND = Decimal(1_000_000_000)
_NONNEGATIVE_DECIMAL_TEXT = re.compile(r"[0-9]+(?:\.[0-9]+)?\Z")


def _decimal_input(
    value: DecimalInput,
    *,
    field: str,
    allow_zero: bool,
) -> Decimal:
    if type(value) is int:
        normalized = Decimal(value)
    elif type(value) is Decimal:
        normalized = value
    else:
        raise TypeError(f"{field} must be an int or Decimal")
    if not normalized.is_finite() or normalized < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    if not allow_zero and normalized == 0:
        raise ValueError(f"{field} must be positive")
    return normalized


def _nonnegative_nanoseconds(value: int, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _calculation_precision(*values: Decimal, integer_digits: int = 1) -> int:
    decimal_digits = 0
    for value in values:
        parts = value.as_tuple()
        exponent = parts.exponent
        if not isinstance(exponent, int):  # Finite inputs make this unreachable.
            raise TypeError("calculation values must be finite decimals")
        decimal_digits += len(parts.digits) + abs(exponent)
    return max(64, decimal_digits + integer_digits + 16)


def _validate_key(key: BudgetKey) -> BudgetKey:
    if (
        type(key) is not tuple
        or len(key) != 3
        or any(type(part) is not str or not part for part in key)
    ):
        raise ValueError(
            "budget key must contain non-empty exchange, quota group, and endpoint"
        )
    return key


class TokenBucket:
    __slots__ = (
        "_capacity",
        "_clock",
        "_hard_capacity",
        "_hard_refill_per_second",
        "_last_refill_ns",
        "_refill_per_second",
        "_tokens",
    )

    def __init__(
        self,
        *,
        capacity: DecimalInput,
        refill_per_second: DecimalInput,
        clock: Clock,
    ) -> None:
        hard_capacity = _decimal_input(
            capacity,
            field="capacity",
            allow_zero=False,
        )
        hard_refill = _decimal_input(
            refill_per_second,
            field="refill_per_second",
            allow_zero=False,
        )
        self._clock = clock
        self._hard_capacity = hard_capacity
        self._capacity = hard_capacity
        self._hard_refill_per_second = hard_refill
        self._refill_per_second = hard_refill
        self._tokens = hard_capacity
        self._last_refill_ns = _nonnegative_nanoseconds(
            clock.monotonic_ns(),
            field="clock.monotonic_ns()",
        )

    @property
    def hard_capacity(self) -> Decimal:
        return self._hard_capacity

    @property
    def capacity(self) -> Decimal:
        return self._capacity

    @property
    def hard_refill_per_second(self) -> Decimal:
        return self._hard_refill_per_second

    @property
    def refill_per_second(self) -> Decimal:
        return self._refill_per_second

    @property
    def tokens(self) -> Decimal:
        self._refill()
        return self._tokens

    def _refill(self) -> None:
        now_ns = _nonnegative_nanoseconds(
            self._clock.monotonic_ns(),
            field="clock.monotonic_ns()",
        )
        if now_ns <= self._last_refill_ns:
            return
        elapsed_ns = now_ns - self._last_refill_ns
        precision = _calculation_precision(
            self._tokens,
            self._capacity,
            self._refill_per_second,
            integer_digits=len(str(elapsed_ns)),
        )
        with localcontext() as context:
            context.prec = precision
            replenished = (
                self._refill_per_second * Decimal(elapsed_ns)
            ) / _NANOSECONDS_PER_SECOND
            self._tokens = min(self._capacity, self._tokens + replenished)
        self._last_refill_ns = now_ns

    def try_acquire(self, cost: DecimalInput) -> bool:
        normalized_cost = _decimal_input(
            cost,
            field="cost",
            allow_zero=False,
        )
        if normalized_cost > self._hard_capacity:
            raise ValueError("cost cannot exceed the bucket hard capacity")
        self._refill()
        if normalized_cost > self._tokens:
            return False
        with localcontext() as context:
            context.prec = _calculation_precision(self._tokens, normalized_cost)
            self._tokens -= normalized_cost
        return True

    def observe_available(self, raw_available: str) -> bool:
        if type(raw_available) is not str or not _NONNEGATIVE_DECIMAL_TEXT.fullmatch(
            raw_available
        ):
            return False
        try:
            observed = Decimal(raw_available)
        except DecimalException:  # pragma: no cover - guarded by the exact grammar
            return False
        if not observed.is_finite() or observed < 0:
            return False
        self._refill()
        self._tokens = min(self._tokens, self._capacity, observed)
        return True

    def shrink(self, *, multiplier: DecimalInput, floor: DecimalInput) -> None:
        normalized_multiplier = _decimal_input(
            multiplier,
            field="multiplier",
            allow_zero=False,
        )
        normalized_floor = _decimal_input(
            floor,
            field="floor",
            allow_zero=True,
        )
        if normalized_multiplier > 1:
            raise ValueError("multiplier must be in the interval (0, 1]")
        if normalized_floor > self._hard_refill_per_second:
            raise ValueError("floor cannot exceed the hard refill rate")
        self._refill()
        with localcontext() as context:
            context.prec = _calculation_precision(
                self._refill_per_second,
                normalized_multiplier,
                normalized_floor,
            )
            reduced = self._refill_per_second * normalized_multiplier
            self._refill_per_second = min(
                self._refill_per_second,
                max(normalized_floor, reduced),
            )

    def set_refill_multiplier(
        self,
        multiplier: DecimalInput,
        *,
        floor: DecimalInput,
    ) -> None:
        normalized_multiplier = _decimal_input(
            multiplier,
            field="multiplier",
            allow_zero=False,
        )
        normalized_floor = _decimal_input(
            floor,
            field="floor",
            allow_zero=True,
        )
        if normalized_multiplier > 1:
            raise ValueError("multiplier must be in the interval (0, 1]")
        if normalized_floor > self._hard_refill_per_second:
            raise ValueError("floor cannot exceed the hard refill rate")
        self._refill()
        with localcontext() as context:
            context.prec = _calculation_precision(
                self._hard_refill_per_second,
                normalized_multiplier,
                normalized_floor,
            )
            self._refill_per_second = max(
                normalized_floor,
                self._hard_refill_per_second * normalized_multiplier,
            )


class BudgetRegistry:
    __slots__ = ("_buckets", "_clock")

    def __init__(self, clock: Clock) -> None:
        self._clock = clock
        self._buckets: dict[BudgetKey, TokenBucket] = {}

    def add(
        self,
        key: BudgetKey,
        *,
        capacity: DecimalInput,
        refill_per_second: DecimalInput,
    ) -> TokenBucket:
        validated_key = _validate_key(key)
        if validated_key in self._buckets:
            raise ValueError(f"budget key {validated_key!r} already exists")
        bucket = TokenBucket(
            capacity=capacity,
            refill_per_second=refill_per_second,
            clock=self._clock,
        )
        self._buckets[validated_key] = bucket
        return bucket

    def bucket(self, key: BudgetKey) -> TokenBucket:
        return self._buckets[_validate_key(key)]

    def try_acquire(
        self,
        key: BudgetKey,
        *,
        cost: DecimalInput,
        default_capacity: DecimalInput | None = None,
        default_refill_per_second: DecimalInput | None = None,
    ) -> bool:
        validated_key = _validate_key(key)
        bucket = self._buckets.get(validated_key)
        if bucket is None:
            if default_capacity is None:
                raise KeyError(validated_key)
            bucket = self.add(
                validated_key,
                capacity=default_capacity,
                refill_per_second=(
                    default_capacity
                    if default_refill_per_second is None
                    else default_refill_per_second
                ),
            )
        return bucket.try_acquire(cost)

    def observe_available(self, key: BudgetKey, raw_available: str) -> bool:
        return self.bucket(key).observe_available(raw_available)

    def shrink(
        self,
        key: BudgetKey,
        *,
        multiplier: DecimalInput,
        floor: DecimalInput,
    ) -> None:
        self.bucket(key).shrink(multiplier=multiplier, floor=floor)

    def set_refill_multiplier(
        self,
        key: BudgetKey,
        multiplier: DecimalInput,
        *,
        floor: DecimalInput,
    ) -> None:
        self.bucket(key).set_refill_multiplier(multiplier, floor=floor)
