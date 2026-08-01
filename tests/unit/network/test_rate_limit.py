from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal, localcontext

import pytest

from crypto_collector.network.rate_limit import BudgetRegistry, TokenBucket


@dataclass
class FakeClock:
    now_ns: int = 0

    def time_ns(self) -> int:
        return self.now_ns

    def monotonic_ns(self) -> int:
        return self.now_ns

    def advance(self, nanoseconds: int) -> None:
        self.now_ns += nanoseconds


def test_token_bucket_is_keyed_by_exchange_quota_group_and_endpoint() -> None:
    clock = FakeClock()
    budgets = BudgetRegistry(clock)
    budgets.add(
        ("binance", "shared-nat", "depth"),
        capacity=10,
        refill_per_second=1,
    )

    assert budgets.try_acquire(("binance", "shared-nat", "depth"), cost=10)
    assert not budgets.try_acquire(("binance", "shared-nat", "depth"), cost=1)
    assert budgets.try_acquire(
        ("okx", "shared-nat", "depth"),
        cost=1,
        default_capacity=10,
    )


def test_token_bucket_refills_from_injected_monotonic_time() -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=10, refill_per_second=2, clock=clock)
    assert bucket.try_acquire(10)

    clock.advance(1_500_000_000)

    assert bucket.tokens == Decimal(3)
    assert bucket.try_acquire(3)
    assert not bucket.try_acquire(1)


def test_decimal_refill_is_independent_of_ambient_context_precision() -> None:
    clock = FakeClock()
    bucket = TokenBucket(
        capacity=1,
        refill_per_second=Decimal("0.1"),
        clock=clock,
    )
    assert bucket.try_acquire(1)
    clock.advance(1)

    with localcontext() as context:
        context.prec = 2
        assert bucket.tokens == Decimal("0.0000000001")


def test_large_decimal_capacity_acquisition_is_exact() -> None:
    capacity = Decimal("1E+100")
    bucket = TokenBucket(
        capacity=capacity,
        refill_per_second=1,
        clock=FakeClock(),
    )

    assert bucket.try_acquire(1)
    with localcontext() as context:
        context.prec = 120
        expected = capacity - 1

    assert bucket.tokens == expected


def test_backward_clock_step_neither_mints_tokens_nor_moves_refill_baseline() -> None:
    clock = FakeClock(now_ns=10_000_000_000)
    bucket = TokenBucket(capacity=10, refill_per_second=1, clock=clock)
    assert bucket.try_acquire(10)

    clock.now_ns = 5_000_000_000
    assert bucket.tokens == 0
    clock.now_ns = 11_000_000_000

    assert bucket.tokens == 1


def test_server_available_observation_can_only_reduce_local_tokens() -> None:
    clock = FakeClock()
    budgets = BudgetRegistry(clock)
    key = ("okx", "nat-a", "public-rest")
    budgets.add(key, capacity=10, refill_per_second=5)
    assert budgets.try_acquire(key, cost=2)

    assert budgets.observe_available(key, "3.5")
    assert budgets.bucket(key).tokens == Decimal("3.5")
    assert budgets.observe_available(key, "9")
    assert budgets.bucket(key).tokens == Decimal("3.5")


@pytest.mark.parametrize("raw", ["", "nan", "Infinity", "-1", "1_000", "x"])
def test_malformed_server_available_observation_is_ignored(raw: str) -> None:
    clock = FakeClock()
    budgets = BudgetRegistry(clock)
    key = ("okx", "nat-a", "public-rest")
    budgets.add(key, capacity=10, refill_per_second=5)

    assert not budgets.observe_available(key, raw)
    assert budgets.bucket(key).tokens == 10
    assert budgets.bucket(key).hard_capacity == 10


def test_shrink_reduces_refill_rate_without_changing_hard_capacity() -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=10, refill_per_second=8, clock=clock)

    bucket.shrink(multiplier=Decimal("0.5"), floor=Decimal(3))
    bucket.shrink(multiplier=Decimal("0.5"), floor=Decimal(3))

    assert bucket.refill_per_second == 3
    assert bucket.hard_refill_per_second == 8
    assert bucket.capacity == 10
    assert bucket.hard_capacity == 10


def test_absolute_refill_multiplier_can_recover_without_exceeding_hard_rate() -> None:
    bucket = TokenBucket(capacity=10, refill_per_second=8, clock=FakeClock())
    bucket.shrink(multiplier=Decimal("0.5"), floor=0)

    bucket.set_refill_multiplier(Decimal("0.75"), floor=0)

    assert bucket.refill_per_second == 6
    assert bucket.hard_refill_per_second == 8
    with pytest.raises(ValueError, match="multiplier"):
        bucket.set_refill_multiplier(Decimal("1.01"), floor=0)


def test_cost_above_hard_capacity_is_configuration_error() -> None:
    bucket = TokenBucket(capacity=10, refill_per_second=1, clock=FakeClock())

    with pytest.raises(ValueError, match="hard capacity"):
        bucket.try_acquire(11)


@pytest.mark.parametrize(
    ("capacity", "refill"),
    [
        (0, 1),
        (-1, 1),
        (True, 1),
        (1, 0),
        (1, Decimal("NaN")),
        (1.0, 1),
    ],
)
def test_bucket_requires_strict_positive_finite_decimal_compatible_values(
    capacity: object,
    refill: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        TokenBucket(capacity=capacity, refill_per_second=refill, clock=FakeClock())  # type: ignore[arg-type]


@pytest.mark.parametrize("cost", [0, -1, True, Decimal("NaN"), 1.0])
def test_acquire_rejects_invalid_cost(cost: object) -> None:
    bucket = TokenBucket(capacity=10, refill_per_second=1, clock=FakeClock())

    with pytest.raises((TypeError, ValueError)):
        bucket.try_acquire(cost)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "key",
    [
        ("", "nat", "depth"),
        ("okx", "", "depth"),
        ("okx", "nat", ""),
        ("okx", "nat"),
        ("okx", "nat", "depth", "extra"),
    ],
)
def test_registry_rejects_invalid_budget_keys(key: tuple[str, ...]) -> None:
    budgets = BudgetRegistry(FakeClock())

    with pytest.raises(ValueError, match="budget key"):
        budgets.add(key, capacity=10, refill_per_second=1)  # type: ignore[arg-type]


def test_registry_rejects_duplicate_budget_key() -> None:
    budgets = BudgetRegistry(FakeClock())
    key = ("okx", "nat", "depth")
    budgets.add(key, capacity=10, refill_per_second=1)

    with pytest.raises(ValueError, match="already exists"):
        budgets.add(key, capacity=10, refill_per_second=1)


def test_quote_reports_exact_ready_time_without_consuming_tokens() -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=10, refill_per_second=2, clock=clock)
    assert bucket.try_acquire(10)

    assert bucket.ready_at_ns(3) == 1_500_000_000
    assert bucket.tokens == 0

    clock.advance(1_500_000_000)
    assert bucket.ready_at_ns(3) == 1_500_000_000
    assert bucket.tokens == 3


def test_quote_subtraction_ignores_ambient_decimal_precision() -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=1, refill_per_second=1, clock=clock)
    assert bucket.try_acquire(Decimal("0.876543211"))

    with localcontext() as context:
        context.prec = 2
        assert bucket.ready_at_ns(1) == 876_543_211


def test_registry_atomically_acquires_first_ready_distinct_candidate() -> None:
    clock = FakeClock()
    budgets = BudgetRegistry(clock)
    blocked = ("okx", "nat-a", "depth")
    ready = ("okx", "nat-b", "depth")
    budgets.add(blocked, capacity=1, refill_per_second=1)
    budgets.add(ready, capacity=1, refill_per_second=1)
    assert budgets.try_acquire(blocked, cost=1)

    selected = budgets.try_acquire_one((blocked, blocked, ready), cost=1)

    assert selected == ready
    assert budgets.bucket(blocked).tokens == 0
    assert budgets.bucket(ready).tokens == 0


def test_registry_quote_uses_current_throttled_rate() -> None:
    clock = FakeClock()
    budgets = BudgetRegistry(clock)
    key = ("okx", "nat-a", "depth")
    budgets.add(key, capacity=10, refill_per_second=4)
    assert budgets.try_acquire(key, cost=10)
    budgets.set_refill_multiplier(key, Decimal("0.5"), floor=0)

    assert budgets.ready_at_ns(key, cost=3) == 1_500_000_000
