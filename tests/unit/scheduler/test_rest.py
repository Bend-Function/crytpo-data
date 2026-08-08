from __future__ import annotations

import asyncio
from collections.abc import Coroutine, Mapping
from dataclasses import dataclass, replace
from decimal import Decimal, localcontext

import pytest

from crypto_collector.domain import SourceContext
from crypto_collector.domain.json_codec import JsonPayload
from crypto_collector.network.rate_limit import BudgetRegistry
from crypto_collector.scheduler import (
    CapacityError,
    EventMonotonicWaiter,
    IntervalController,
    IntervalProposal,
    RestBudgetRoute,
    RestDispatch,
    RestIntervalContext,
    RestJob,
    RestPriority,
    RestScheduler,
    SchedulerClosed,
    StableCadence,
    SubmitResult,
    solve_interval,
)

SECOND_NS = 1_000_000_000
OKX_DEPTH = ("okx", "nat-a", "books-full")
BINANCE_DEPTH = ("binance", "nat-b", "depth")
OKX_DEPTH_B = ("okx", "nat-b", "books-full")


@dataclass
class FakeClock:
    now_ns: int = 0

    def time_ns(self) -> int:
        return self.now_ns

    def monotonic_ns(self) -> int:
        return self.now_ns

    def advance(self, nanoseconds: int) -> None:
        self.now_ns += nanoseconds


@dataclass
class ScriptedClock:
    now_ns: int = 0
    scripted_monotonic_ns: list[int] | None = None

    def time_ns(self) -> int:
        return self.now_ns

    def monotonic_ns(self) -> int:
        if self.scripted_monotonic_ns:
            self.now_ns = self.scripted_monotonic_ns.pop(0)
        return self.now_ns


def budgets(
    clock: FakeClock,
    *,
    okx_tokens: int = 10,
    binance_tokens: int = 10,
) -> BudgetRegistry:
    registry = BudgetRegistry(clock)
    registry.add(
        OKX_DEPTH,
        capacity=max(okx_tokens, 1),
        refill_per_second=1,
    )
    registry.add(
        BINANCE_DEPTH,
        capacity=max(binance_tokens, 1),
        refill_per_second=1,
    )
    if okx_tokens == 0:
        assert registry.try_acquire(OKX_DEPTH, cost=1)
    if binance_tokens == 0:
        assert registry.try_acquire(BINANCE_DEPTH, cost=1)
    return registry


@pytest.mark.asyncio
async def test_submit_is_cancellation_atomic_around_commit() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)

    cancelled_before_start = asyncio.create_task(
        scheduler.submit(job("cancelled-before-start"))
    )
    cancelled_before_start.cancel()
    with pytest.raises(asyncio.CancelledError):
        await cancelled_before_start
    assert scheduler.pending_ids() == ()

    committed = asyncio.create_task(scheduler.submit(job("committed")))
    asyncio.get_running_loop().call_soon(committed.cancel)
    assert await committed is SubmitResult.ENQUEUED
    assert scheduler.pending_ids() == ("committed",)


def job(
    job_id: str,
    *,
    priority: RestPriority = RestPriority.DEEP_SNAPSHOT,
    budget_key: tuple[str, str, str] = OKX_DEPTH,
    ready_monotonic_ns: int = 0,
    deadline_ns: int | None = None,
    logical_key: tuple[str, ...] | None = None,
    replaceable: bool = False,
    scheduled_ns: int = 0,
    endpoint_cost: int = 1,
) -> RestJob:
    return RestJob(
        id=job_id,
        priority=priority,
        routes=(RestBudgetRoute(egress_id="direct", budget_key=budget_key),),
        endpoint_cost=endpoint_cost,
        ready_monotonic_ns=ready_monotonic_ns,
        deadline_ns=deadline_ns,
        interval=RestIntervalContext(
            requested_interval_ns=30 * SECOND_NS,
            effective_interval_ns=30 * SECOND_NS,
        ),
        generation_source=(
            SourceContext(
                connection_id="ws-1",
                connection_generation=1,
                egress_id="direct",
            )
            if priority is RestPriority.LIVE_BOOTSTRAP
            else None
        ),
        attempt=1,
        logical_key=logical_key,
        replaceable=replaceable,
        scheduled_ns=scheduled_ns,
        control_context={"reason": "test"},
    )


@pytest.mark.asyncio
async def test_bootstrap_runs_before_deep_snapshot() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    await scheduler.submit(job("deep"))
    await scheduler.submit(job("bootstrap", priority=RestPriority.LIVE_BOOTSTRAP))

    assert (await scheduler.next_ready()).id == "bootstrap"


@pytest.mark.asyncio
async def test_all_five_ready_priority_classes_have_strict_order() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    submitted = (
        ("reference", RestPriority.REFERENCE_DATA),
        ("deep", RestPriority.DEEP_SNAPSHOT),
        ("derivative", RestPriority.CORE_DERIVATIVE),
        ("catalog", RestPriority.CATALOG_STATUS_TIME),
        ("bootstrap", RestPriority.LIVE_BOOTSTRAP),
    )
    for job_id, priority in submitted:
        await scheduler.submit(job(job_id, priority=priority))

    assert [(await scheduler.next_ready()).id for _ in submitted] == [
        "bootstrap",
        "catalog",
        "derivative",
        "deep",
        "reference",
    ]


@pytest.mark.asyncio
async def test_equal_priority_dispatches_in_insertion_order() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    await scheduler.submit(job("first"))
    await scheduler.submit(job("second"))

    assert (await scheduler.next_ready()).id == "first"
    assert (await scheduler.next_ready()).id == "second"


@pytest.mark.asyncio
async def test_future_high_priority_does_not_block_ready_lower_priority() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    await scheduler.submit(
        job(
            "future-bootstrap",
            priority=RestPriority.LIVE_BOOTSTRAP,
            ready_monotonic_ns=30 * SECOND_NS,
        )
    )
    await scheduler.submit(job("ready-deep"))

    assert (await scheduler.next_ready()).id == "ready-deep"
    assert clock.monotonic_ns() == 0


@pytest.mark.asyncio
async def test_budget_blocked_job_does_not_idle_an_independent_budget() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(
        budgets(clock, okx_tokens=0, binance_tokens=1),
        clock=clock,
    )
    await scheduler.submit(
        job("blocked-bootstrap", priority=RestPriority.LIVE_BOOTSTRAP)
    )
    await scheduler.submit(job("ready-deep", budget_key=BINANCE_DEPTH))

    assert (await scheduler.next_ready()).id == "ready-deep"
    assert scheduler.pending_ids() == ("blocked-bootstrap",)


@pytest.mark.asyncio
async def test_dispatch_atomically_selects_egress_whose_budget_was_acquired() -> None:
    clock = FakeClock()
    registry = BudgetRegistry(clock)
    registry.add(OKX_DEPTH, capacity=1, refill_per_second=1)
    registry.add(OKX_DEPTH_B, capacity=1, refill_per_second=1)
    assert registry.try_acquire(OKX_DEPTH, cost=1)
    routed = replace(
        job("routed"),
        routes=(
            RestBudgetRoute("proxy-a", OKX_DEPTH),
            RestBudgetRoute("proxy-b", OKX_DEPTH_B),
        ),
    )
    scheduler = RestScheduler(registry, clock=clock)
    await scheduler.submit(routed)

    dispatch = await scheduler.next_ready()

    assert dispatch.route.egress_id == "proxy-b"
    assert dispatch.route.budget_key == OKX_DEPTH_B
    assert dispatch.source_context.egress_id == "proxy-b"
    assert registry.bucket(OKX_DEPTH).tokens == 0
    assert registry.bucket(OKX_DEPTH_B).tokens == 0


@pytest.mark.asyncio
async def test_generation_sticky_job_never_fails_over_to_another_route() -> None:
    clock = FakeClock()
    registry = BudgetRegistry(clock)
    registry.add(OKX_DEPTH, capacity=1, refill_per_second=1)
    registry.add(OKX_DEPTH_B, capacity=1, refill_per_second=1)
    assert registry.try_acquire(OKX_DEPTH_B, cost=1)
    sticky = replace(
        job("sticky"),
        routes=(
            RestBudgetRoute("proxy-a", OKX_DEPTH),
            RestBudgetRoute("proxy-b", OKX_DEPTH_B),
        ),
        generation_source=SourceContext(
            connection_id="ws-1",
            connection_generation=7,
            egress_id="proxy-b",
        ),
    )
    scheduler = RestScheduler(registry, clock=clock)
    await scheduler.submit(sticky)

    assert await scheduler.next_ready_or_none() is None
    assert registry.bucket(OKX_DEPTH).tokens == 1


@pytest.mark.asyncio
async def test_budget_blocked_priority_is_strict_within_the_same_budget() -> None:
    clock = FakeClock()
    registry = BudgetRegistry(clock)
    registry.add(OKX_DEPTH, capacity=2, refill_per_second=1)
    assert registry.try_acquire(OKX_DEPTH, cost=1)
    scheduler = RestScheduler(registry, clock=clock)
    await scheduler.submit(
        job(
            "blocked-bootstrap",
            priority=RestPriority.LIVE_BOOTSTRAP,
            endpoint_cost=2,
        )
    )
    await scheduler.submit(job("affordable-deep", endpoint_cost=1))

    assert await scheduler.next_ready_or_none() is None
    assert scheduler.pending_ids() == ("blocked-bootstrap", "affordable-deep")


@pytest.mark.asyncio
async def test_expired_waiting_job_is_dropped_without_dispatch() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    await scheduler.submit(
        job(
            "expired",
            ready_monotonic_ns=20 * SECOND_NS,
            deadline_ns=10 * SECOND_NS,
        )
    )

    clock.advance(20 * SECOND_NS)

    assert await scheduler.next_ready_or_none() is None
    assert scheduler.expired_ids() == ("expired",)


@pytest.mark.asyncio
async def test_future_deadline_expires_behind_a_budget_blocked_ready_job() -> None:
    clock = FakeClock()
    registry = BudgetRegistry(clock)
    registry.add(
        OKX_DEPTH,
        capacity=1,
        refill_per_second=Decimal("0.01"),
    )
    assert registry.try_acquire(OKX_DEPTH, cost=1)
    scheduler = RestScheduler(registry, clock=clock)
    await scheduler.submit(job("blocked"))
    await scheduler.submit(
        job(
            "future-expired",
            ready_monotonic_ns=20 * SECOND_NS,
            deadline_ns=10 * SECOND_NS,
        )
    )

    clock.advance(10 * SECOND_NS + 1)

    assert await scheduler.next_ready_or_none() is None
    assert scheduler.expired_ids() == ("future-expired",)
    assert scheduler.pending_ids() == ("blocked",)


@pytest.mark.asyncio
async def test_job_at_its_deadline_remains_dispatchable() -> None:
    clock = FakeClock(now_ns=10 * SECOND_NS)
    scheduler = RestScheduler(budgets(clock), clock=clock)
    await scheduler.submit(job("at-deadline", deadline_ns=10 * SECOND_NS))

    assert (await scheduler.next_ready()).id == "at-deadline"


@pytest.mark.asyncio
async def test_budget_becoming_ready_at_inclusive_deadline_dispatches() -> None:
    clock = FakeClock()
    waiter = AdvancingWaiter(clock, [])
    registry = budgets(clock, okx_tokens=0)
    scheduler = RestScheduler(registry, clock=clock, waiter=waiter)
    await scheduler.submit(job("at-deadline", deadline_ns=SECOND_NS))

    dispatch = await scheduler.next_ready()

    assert dispatch.id == "at-deadline"
    assert dispatch.dispatched_monotonic_ns == SECOND_NS
    assert scheduler.expired_ids() == ()


@pytest.mark.asyncio
async def test_deadline_check_and_budget_acquisition_share_one_clock_sample() -> None:
    clock = ScriptedClock()
    registry = BudgetRegistry(clock)
    registry.add(OKX_DEPTH, capacity=1, refill_per_second=SECOND_NS)
    assert registry.try_acquire(OKX_DEPTH, cost=1)
    scheduler = RestScheduler(registry, clock=clock)
    await scheduler.submit(job("deadline-race", deadline_ns=0))
    clock.scripted_monotonic_ns = [0, 1]

    assert await scheduler.next_ready_or_none() is None
    assert await scheduler.next_ready_or_none() is None
    assert registry.bucket(OKX_DEPTH).tokens == 1
    assert scheduler.expired_ids() == ("deadline-race",)


def test_periodic_replaceable_jobs_coalesce_across_both_heaps() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock, okx_tokens=0), clock=clock)
    scheduler.submit_nowait(
        job(
            "deep-btc-future",
            ready_monotonic_ns=60 * SECOND_NS,
            logical_key=("BTC-USDT", "deep"),
            replaceable=True,
            scheduled_ns=1,
        )
    )
    scheduler.submit_nowait(
        job(
            "deep-btc-ready",
            logical_key=("BTC-USDT", "deep"),
            replaceable=True,
            scheduled_ns=2,
        )
    )

    assert scheduler.pending_ids() == ("deep-btc-ready",)
    assert scheduler.physical_heap_entries == 1


def test_repeated_replacement_keeps_physical_heaps_bounded() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(
        budgets(clock, okx_tokens=0),
        clock=clock,
        max_pending=4,
    )

    for sequence in range(1_000):
        scheduler.submit_nowait(
            job(
                f"deep-btc-{sequence}",
                ready_monotonic_ns=(sequence % 2) * SECOND_NS,
                logical_key=("BTC-USDT", "deep"),
                replaceable=True,
                scheduled_ns=sequence,
            )
        )

    assert scheduler.pending_ids() == ("deep-btc-999",)
    assert scheduler.physical_heap_entries == 1


def test_old_occurrence_is_ignored_and_same_occurrence_conflict_is_rejected() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    newest = job(
        "newest",
        logical_key=("BTC-USDT", "deep"),
        replaceable=True,
        scheduled_ns=2,
    )
    assert scheduler.submit_nowait(newest) is SubmitResult.ENQUEUED

    assert (
        scheduler.submit_nowait(
            job(
                "old",
                logical_key=("BTC-USDT", "deep"),
                replaceable=True,
                scheduled_ns=1,
            )
        )
        is SubmitResult.STALE_IGNORED
    )
    assert scheduler.submit_nowait(newest) is SubmitResult.IDEMPOTENT
    with pytest.raises(ValueError, match="occurrence"):
        scheduler.submit_nowait(
            job(
                "conflict",
                logical_key=("BTC-USDT", "deep"),
                replaceable=True,
                scheduled_ns=2,
                ready_monotonic_ns=1,
            )
        )
    assert scheduler.pending_ids() == ("newest",)


def test_logical_key_may_contain_repeated_ordered_components() -> None:
    repeated = job(
        "repeated-key",
        logical_key=("scope", "scope"),
        replaceable=True,
    )

    assert repeated.logical_key == ("scope", "scope")


def test_routes_reject_duplicate_egress_scope_drift_and_invalid_stickiness() -> None:
    base = job("invalid-routes")
    with pytest.raises(ValueError, match="egress"):
        replace(
            base,
            routes=(
                RestBudgetRoute("same", OKX_DEPTH),
                RestBudgetRoute("same", OKX_DEPTH_B),
            ),
        )
    with pytest.raises(ValueError, match="one exchange"):
        replace(
            base,
            routes=(
                RestBudgetRoute("okx", OKX_DEPTH),
                RestBudgetRoute("binance", BINANCE_DEPTH),
            ),
        )
    with pytest.raises(ValueError, match="present in routes"):
        replace(
            base,
            generation_source=SourceContext(
                connection_id="ws-1",
                connection_generation=1,
                egress_id="missing",
            ),
        )


def test_non_replaceable_job_cannot_reuse_an_existing_id() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    scheduler.submit_nowait(job("duplicate"))

    with pytest.raises(ValueError, match="job id"):
        scheduler.submit_nowait(job("duplicate", ready_monotonic_ns=1))


def test_pending_capacity_rejects_new_work_but_allows_replacement() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock, max_pending=1)
    scheduler.submit_nowait(
        job(
            "old",
            logical_key=("BTC-USDT", "deep"),
            replaceable=True,
            scheduled_ns=1,
        )
    )

    scheduler.submit_nowait(
        job(
            "replacement",
            logical_key=("BTC-USDT", "deep"),
            replaceable=True,
            scheduled_ns=2,
        )
    )
    with pytest.raises(CapacityError, match="pending"):
        scheduler.submit_nowait(job("new"))

    assert scheduler.pending_ids() == ("replacement",)


def test_full_scheduler_evicts_lowest_replaceable_for_bootstrap() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock, max_pending=1)
    scheduler.submit_nowait(
        job(
            "reference",
            priority=RestPriority.REFERENCE_DATA,
            logical_key=("BTC-USDT", "reference"),
            replaceable=True,
            scheduled_ns=1,
        )
    )

    result = scheduler.submit_nowait(
        job("bootstrap", priority=RestPriority.LIVE_BOOTSTRAP)
    )

    assert result is SubmitResult.EVICTED_AND_ENQUEUED
    assert scheduler.pending_ids() == ("bootstrap",)
    assert scheduler.evicted_ids() == ("reference",)


def test_full_scheduler_does_not_evict_for_replaceable_incoming_work() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock, max_pending=1)
    scheduler.submit_nowait(
        job(
            "reference",
            priority=RestPriority.REFERENCE_DATA,
            logical_key=("BTC-USDT", "reference"),
            replaceable=True,
            scheduled_ns=1,
        )
    )

    with pytest.raises(CapacityError, match="pending"):
        scheduler.submit_nowait(
            job(
                "deep",
                priority=RestPriority.DEEP_SNAPSHOT,
                logical_key=("BTC-USDT", "deep"),
                replaceable=True,
                scheduled_ns=1,
            )
        )

    assert scheduler.pending_ids() == ("reference",)
    assert scheduler.evicted_ids() == ()


def test_expired_fixed_work_does_not_evict_a_live_replaceable_job() -> None:
    clock = FakeClock(now_ns=10)
    scheduler = RestScheduler(budgets(clock), clock=clock, max_pending=1)
    scheduler.submit_nowait(
        job(
            "reference",
            priority=RestPriority.REFERENCE_DATA,
            logical_key=("BTC-USDT", "reference"),
            replaceable=True,
            scheduled_ns=1,
        )
    )

    result = scheduler.submit_nowait(
        job(
            "expired-bootstrap",
            priority=RestPriority.LIVE_BOOTSTRAP,
            deadline_ns=9,
        )
    )

    assert result is SubmitResult.EXPIRED
    assert scheduler.pending_ids() == ("reference",)
    assert scheduler.expired_ids() == ("expired-bootstrap",)
    assert scheduler.evicted_ids() == ()


def test_expired_incumbent_is_swept_before_capacity_admission() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock, max_pending=1)
    scheduler.submit_nowait(job("expired-incumbent", deadline_ns=0))
    clock.advance(1)

    result = scheduler.submit_nowait(
        job("fresh-bootstrap", priority=RestPriority.LIVE_BOOTSTRAP)
    )

    assert result is SubmitResult.ENQUEUED
    assert scheduler.pending_ids() == ("fresh-bootstrap",)
    assert scheduler.expired_ids() == ("expired-incumbent",)


def test_expired_newer_occurrence_supersedes_older_periodic_work() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    scheduler.submit_nowait(
        job(
            "old",
            logical_key=("BTC-USDT", "deep"),
            replaceable=True,
            scheduled_ns=1,
        )
    )
    clock.advance(10)

    result = scheduler.submit_nowait(
        job(
            "expired-new",
            logical_key=("BTC-USDT", "deep"),
            replaceable=True,
            scheduled_ns=2,
            deadline_ns=9,
        )
    )

    assert result is SubmitResult.EXPIRED
    assert scheduler.pending_ids() == ()
    assert scheduler.expired_ids() == ("expired-new",)


def test_nested_control_context_is_immutable_and_replaceable() -> None:
    source_symbols: list[JsonPayload] = ["BTC-USDT"]
    source_selection: dict[str, JsonPayload] = {"symbols": source_symbols}
    source_context: dict[str, JsonPayload] = {"selection": source_selection}
    queued = replace(job("immutable-context"), control_context=source_context)
    source_symbols.append("ETH-USDT")

    selection = queued.control_context["selection"]
    assert isinstance(selection, Mapping)
    symbols = selection["symbols"]
    assert symbols == ("BTC-USDT",)
    with pytest.raises(TypeError):
        selection["reason"] = "mutated"  # type: ignore[index]
    with pytest.raises(AttributeError):
        symbols.append("ETH-USDT")  # type: ignore[attr-defined,union-attr]

    scheduler = RestScheduler(budgets(FakeClock()))
    assert scheduler.submit_nowait(queued) is SubmitResult.ENQUEUED
    exact_repeat = replace(queued)
    assert scheduler.submit_nowait(exact_repeat) is SubmitResult.IDEMPOTENT


def test_expired_and_evicted_histories_are_bounded() -> None:
    clock = FakeClock(now_ns=10)
    scheduler = RestScheduler(
        budgets(clock),
        clock=clock,
        max_pending=1,
        max_history=2,
    )

    for index in range(3):
        scheduler.submit_nowait(job(f"expired-{index}", deadline_ns=0))

    assert scheduler.expired_ids() == ("expired-1", "expired-2")


def test_default_event_history_limit_matches_scheduler_config() -> None:
    clock = FakeClock(now_ns=10)
    scheduler = RestScheduler(budgets(clock), clock=clock)

    for index in range(1_025):
        scheduler.submit_nowait(job(f"expired-{index}", deadline_ns=0))

    assert len(scheduler.expired_ids()) == 1_024
    assert scheduler.expired_ids()[0] == "expired-1"


@pytest.mark.parametrize("field", ["max_pending", "max_history"])
def test_scheduler_rejects_unallocatable_collection_bounds(field: str) -> None:
    clock = FakeClock()
    arguments = {field: 10**100}

    with pytest.raises(ValueError, match=field):
        RestScheduler(budgets(clock), clock=clock, **arguments)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_bulk_expiry_clears_physical_heaps_in_submission_order() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(
        budgets(clock),
        clock=clock,
        max_history=256,
    )
    for index in range(200):
        await scheduler.submit(
            job(
                f"expired-{index}",
                ready_monotonic_ns=index % 2,
                deadline_ns=0,
            )
        )

    clock.advance(1)

    assert await scheduler.next_ready_or_none() is None
    assert scheduler.pending_ids() == ()
    assert scheduler.physical_heap_entries == 0
    assert scheduler.expired_ids() == tuple(f"expired-{index}" for index in range(200))


@dataclass
class AdvancingWaiter:
    clock: FakeClock
    deadlines: list[int | None]

    async def wait_until(
        self,
        *,
        deadline_ns: int | None,
        wake_event: asyncio.Event,
        now_ns: int,
    ) -> None:
        self.deadlines.append(deadline_ns)
        assert deadline_ns is not None
        self.clock.now_ns = deadline_ns
        await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_future_and_budget_waits_use_injected_monotonic_waiter() -> None:
    clock = FakeClock()
    waiter = AdvancingWaiter(clock, [])
    registry = budgets(clock, okx_tokens=0)
    scheduler = RestScheduler(registry, clock=clock, waiter=waiter)
    await scheduler.submit(job("future", ready_monotonic_ns=2 * SECOND_NS))

    dispatched = await scheduler.next_ready()

    assert dispatched.id == "future"
    assert waiter.deadlines == [2 * SECOND_NS]


@pytest.mark.asyncio
async def test_budget_wait_uses_exact_bucket_ready_time() -> None:
    clock = FakeClock()
    waiter = AdvancingWaiter(clock, [])
    scheduler = RestScheduler(
        budgets(clock, okx_tokens=0),
        clock=clock,
        waiter=waiter,
    )
    await scheduler.submit(job("budget-blocked"))

    dispatched = await scheduler.next_ready()

    assert dispatched.id == "budget-blocked"
    assert waiter.deadlines == [SECOND_NS]


@pytest.mark.asyncio
async def test_waiting_future_job_is_preempted_by_new_ready_submission() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(
        budgets(clock),
        clock=clock,
        waiter=EventMonotonicWaiter(),
    )
    await scheduler.submit(job("future", ready_monotonic_ns=60 * SECOND_NS))
    pending = asyncio.create_task(scheduler.next_ready())
    await asyncio.sleep(0)

    await scheduler.submit(job("ready"))

    assert (await asyncio.wait_for(pending, timeout=0.2)).id == "ready"


@pytest.mark.asyncio
async def test_waiter_handles_unrepresentably_large_deadline_until_event() -> None:
    wake_event = asyncio.Event()
    waiting = asyncio.create_task(
        EventMonotonicWaiter().wait_until(
            deadline_ns=10**1_000,
            wake_event=wake_event,
            now_ns=0,
        )
    )
    await asyncio.sleep(0)
    wake_event.set()

    await waiting


@pytest.mark.asyncio
async def test_waiter_uses_full_finite_deadline_without_daily_poll(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_timeouts: list[float] = []

    async def capture_wait_for(
        awaitable: Coroutine[object, object, bool],
        timeout: float,
    ) -> bool:
        observed_timeouts.append(timeout)
        awaitable.close()
        raise TimeoutError

    monkeypatch.setattr(asyncio, "wait_for", capture_wait_for)

    await EventMonotonicWaiter().wait_until(
        deadline_ns=2 * 86_400 * SECOND_NS,
        wake_event=asyncio.Event(),
        now_ns=0,
    )

    assert observed_timeouts == [172_800.0]


@pytest.mark.asyncio
async def test_close_wakes_empty_scheduler_without_lost_waiter() -> None:
    clock = FakeClock()
    scheduler = RestScheduler(budgets(clock), clock=clock)
    pending = asyncio.create_task(scheduler.next_ready())
    await asyncio.sleep(0)

    scheduler.close()

    with pytest.raises(SchedulerClosed):
        await asyncio.wait_for(pending, timeout=0.2)


@pytest.mark.asyncio
async def test_scheduler_monotonic_baseline_does_not_move_backward() -> None:
    clock = FakeClock(now_ns=100)
    scheduler = RestScheduler(budgets(clock), clock=clock)
    clock.now_ns = 50
    await scheduler.submit(
        job(
            "rollback",
            ready_monotonic_ns=100,
            deadline_ns=100,
        )
    )

    dispatch = await scheduler.next_ready()

    assert dispatch.id == "rollback"
    assert dispatch.dispatched_monotonic_ns == 100


def test_scheduler_rejects_a_different_clock_from_its_budgets() -> None:
    budget_clock = FakeClock()
    scheduler_clock = FakeClock()

    with pytest.raises(ValueError, match="share one clock"):
        RestScheduler(budgets(budget_clock), clock=scheduler_clock)


def test_overloaded_deep_interval_stretches_and_emits_context() -> None:
    plan = solve_interval(
        requested_ns=30 * SECOND_NS,
        jobs=100,
        cost=50,
        available_tokens_per_second=50,
        policy="stretch_with_warning",
    )

    assert plan.effective_ns == 100 * SECOND_NS
    assert plan.warning is not None
    assert plan.warning.requested_ns == 30 * SECOND_NS
    assert plan.warning.affected_symbols == 100


def test_interval_solver_uses_exact_ceiling_and_ignores_decimal_context() -> None:
    with localcontext() as context:
        context.prec = 2
        plan = solve_interval(
            requested_ns=1,
            jobs=1,
            cost=Decimal("0.1"),
            available_tokens_per_second=Decimal("0.3"),
            policy="stretch_with_warning",
            max_effective_ns=SECOND_NS,
        )

    assert plan.effective_ns == 333_333_334


def test_interval_maximum_is_inclusive_and_one_nanosecond_over_fails() -> None:
    maximum = 15 * 60 * SECOND_NS
    exact = solve_interval(
        requested_ns=30 * SECOND_NS,
        jobs=900,
        cost=1,
        available_tokens_per_second=1,
        max_effective_ns=maximum,
    )

    assert exact.effective_ns == maximum
    with pytest.raises(CapacityError, match="max effective interval"):
        solve_interval(
            requested_ns=30 * SECOND_NS,
            jobs=maximum + 1,
            cost=1,
            available_tokens_per_second=SECOND_NS,
            max_effective_ns=maximum,
        )


def test_interval_solver_handles_huge_exact_decimal_ratios() -> None:
    plan = solve_interval(
        requested_ns=1,
        jobs=1,
        cost=Decimal("1E+10000"),
        available_tokens_per_second=Decimal("1E+10000"),
        max_effective_ns=SECOND_NS,
    )

    assert plan.effective_ns == SECOND_NS


def test_interval_solver_does_not_stretch_when_capacity_is_sufficient() -> None:
    plan = solve_interval(
        requested_ns=30 * SECOND_NS,
        jobs=10,
        cost=5,
        available_tokens_per_second=100,
    )

    assert plan.effective_ns == 30 * SECOND_NS
    assert plan.warning is None


def test_recovery_step_ignores_ambient_decimal_precision() -> None:
    controller = IntervalController(
        current_ns=SECOND_NS,
        recovery_step=Decimal("0.349"),
        healthy_refreshes_required=1,
    )

    with localcontext() as context:
        context.prec = 2
        proposal = controller.propose_toward(1, refresh_id=1)

    assert proposal.effective_ns == 651_000_000


def test_recovery_step_makes_progress_at_nanosecond_rounding_boundary() -> None:
    controller = IntervalController(
        current_ns=2,
        recovery_step=Decimal("0.2"),
        healthy_refreshes_required=1,
    )

    proposal = controller.propose_toward(1, refresh_id=1)

    assert proposal.effective_ns == 1


def test_stable_cadence_spreads_symbols_and_never_catches_up_missed_slots() -> None:
    interval_ns = 30 * SECOND_NS
    cadences = [
        StableCadence(
            anchor_monotonic_ns=0,
            interval_ns=interval_ns,
            phase_key=f"okx/spot/SYMBOL-{index}",
        )
        for index in range(100)
    ]
    phases = {cadence.phase_ns for cadence in cadences}

    assert len(phases) > 90
    assert all(0 <= phase < interval_ns for phase in phases)
    cadence = cadences[0]
    now_ns = 10 * interval_ns + cadence.phase_ns + 1
    latest = cadence.latest_due_ns(now_ns)
    assert latest == 10 * interval_ns + cadence.phase_ns
    assert cadence.next_due_ns(now_ns) == 11 * interval_ns + cadence.phase_ns


def test_interval_change_rephases_to_a_future_slot_without_immediate_burst() -> None:
    now_ns = 123 * SECOND_NS
    recovered = StableCadence(
        anchor_monotonic_ns=0,
        interval_ns=30 * SECOND_NS,
        phase_key="okx/spot/BTC-USDT/deep",
    )

    assert recovered.next_due_ns(now_ns) > now_ns
    assert recovered.next_due_ns(now_ns) - now_ns <= 30 * SECOND_NS


def test_dispatch_builds_validated_metadata_from_frozen_job_context() -> None:
    dispatch = RestDispatch(
        job=replace(
            job("metadata"),
            attempt=3,
            interval=RestIntervalContext(
                requested_interval_ns=30 * SECOND_NS,
                effective_interval_ns=120 * SECOND_NS,
                change_event_id="interval-1",
            ),
        ),
        route=RestBudgetRoute("direct", OKX_DEPTH),
        dispatched_monotonic_ns=10,
    )
    params: dict[str, object] = {"symbols": ["BTC-USDT"]}
    headers = {"x-ratelimit-remaining": "10"}

    metadata = dispatch.build_rest_metadata(
        request_started_at_ns=11,
        request_ended_at_ns=12,
        method="GET",
        path="/api/v5/market/books",
        params=params,  # type: ignore[arg-type]
        status=200,
        rate_limit_headers=headers,
    )
    symbols = params["symbols"]
    assert isinstance(symbols, list)
    symbols.append("ETH-USDT")
    headers["x-ratelimit-remaining"] = "0"

    assert metadata.attempt == 3
    assert metadata.requested_interval_ns == 30 * SECOND_NS
    assert metadata.effective_interval_ns == 120 * SECOND_NS
    assert metadata.params == {"symbols": ["BTC-USDT"]}
    assert metadata.rate_limit_headers == {"x-ratelimit-remaining": "10"}


def test_fail_policy_rejects_any_required_stretch() -> None:
    with pytest.raises(CapacityError, match="requested interval"):
        solve_interval(
            requested_ns=30 * SECOND_NS,
            jobs=100,
            cost=50,
            available_tokens_per_second=50,
            policy="fail",
        )


def test_deep_interval_above_max_is_capacity_failure() -> None:
    with pytest.raises(CapacityError, match="max effective interval"):
        solve_interval(
            requested_ns=30 * SECOND_NS,
            jobs=1_000,
            cost=250,
            available_tokens_per_second=1,
            max_effective_ns=15 * 60 * SECOND_NS,
        )


def test_zero_healthy_budget_is_capacity_failure_for_nonempty_work() -> None:
    with pytest.raises(CapacityError, match="available token rate"):
        solve_interval(
            requested_ns=30 * SECOND_NS,
            jobs=1,
            cost=1,
            available_tokens_per_second=0,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requested_ns", True),
        ("jobs", -1),
        ("cost", 1.0),
        ("available_tokens_per_second", Decimal("NaN")),
        ("max_effective_ns", 0),
    ],
)
def test_interval_solver_rejects_ambiguous_or_invalid_numbers(
    field: str,
    value: object,
) -> None:
    arguments: dict[str, object] = {
        "requested_ns": 30 * SECOND_NS,
        "jobs": 1,
        "cost": 1,
        "available_tokens_per_second": 1,
        "max_effective_ns": 15 * 60 * SECOND_NS,
    }
    arguments[field] = value

    with pytest.raises((TypeError, ValueError)):
        solve_interval(**arguments)  # type: ignore[arg-type]


def test_capacity_recovery_waits_then_steps_down_without_undershoot() -> None:
    controller = IntervalController(
        current_ns=120 * SECOND_NS,
        recovery_step=0.20,
        healthy_refreshes_required=3,
    )

    first = controller.propose_toward(30 * SECOND_NS, refresh_id=1)
    assert first.effective_ns == 120 * SECOND_NS
    controller.commit(first)
    second = controller.propose_toward(30 * SECOND_NS, refresh_id=2)
    assert second.effective_ns == 120 * SECOND_NS
    controller.commit(second)

    third = controller.propose_toward(30 * SECOND_NS, refresh_id=3)

    assert third.effective_ns == 96 * SECOND_NS
    assert controller.current_ns == 120 * SECOND_NS
    with pytest.raises(ValueError, match="require publication"):
        controller.commit(third)


def test_direct_interval_proposal_cannot_bypass_recovery_hysteresis() -> None:
    controller = IntervalController(
        current_ns=120 * SECOND_NS,
        recovery_step=Decimal("0.2"),
        healthy_refreshes_required=3,
    )

    with pytest.raises(ValueError, match="recovery"):
        controller.propose_interval(30 * SECOND_NS)

    forged = IntervalProposal(
        controller_revision=0,
        previous_effective_ns=120 * SECOND_NS,
        effective_ns=120 * SECOND_NS,
        healthy_refreshes=3,
        refresh_id=1,
    )
    with pytest.raises(ValueError, match="proposal"):
        controller.commit(forged)


def test_live_bootstrap_requires_exact_generation_source() -> None:
    with pytest.raises(ValueError, match="generation_source"):
        replace(
            job("generationless-bootstrap"),
            priority=RestPriority.LIVE_BOOTSTRAP,
        )


def test_unhealthy_refresh_resets_recovery_hysteresis() -> None:
    controller = IntervalController(
        current_ns=120 * SECOND_NS,
        recovery_step=Decimal("0.2"),
        healthy_refreshes_required=3,
    )
    controller.commit(controller.propose_toward(30 * SECOND_NS, refresh_id=1))
    controller.commit(controller.propose_toward(30 * SECOND_NS, refresh_id=2))

    controller.mark_unhealthy()

    after_reset = controller.propose_toward(30 * SECOND_NS, refresh_id=3)
    assert after_reset.effective_ns == 120 * SECOND_NS
    controller.commit(after_reset)
    second = controller.propose_toward(30 * SECOND_NS, refresh_id=4)
    assert second.effective_ns == 120 * SECOND_NS
    controller.commit(second)
    assert (
        controller.propose_toward(30 * SECOND_NS, refresh_id=5).effective_ns
        == 96 * SECOND_NS
    )
