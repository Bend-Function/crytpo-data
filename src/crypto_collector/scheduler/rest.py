from __future__ import annotations

import asyncio
import heapq
from collections import deque
from collections.abc import Awaitable
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from typing import TYPE_CHECKING, Literal, Protocol, TypeAlias

from crypto_collector.domain.clock import Clock
from crypto_collector.network.rate_limit import BudgetRegistry
from crypto_collector.scheduler.models import RestBudgetRoute, RestDispatch, RestJob

if TYPE_CHECKING:
    from crypto_collector.scheduler.interval_observability import (
        IntervalChange,
        IntervalChangePublisher,
        PublishedIntervalChange,
    )

DecimalInput: TypeAlias = int | Decimal
OverloadPolicy: TypeAlias = Literal["stretch_with_warning", "fail"]

_NANOSECONDS_PER_SECOND = 1_000_000_000
_DEFAULT_MAX_EFFECTIVE_NS = 15 * 60 * _NANOSECONDS_PER_SECOND
_MAX_SCHEDULER_COLLECTION_ITEMS = 1_000_000


def _positive_int(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _bounded_collection_size(value: object, *, field: str) -> int:
    normalized = _positive_int(value, field=field)
    if normalized > _MAX_SCHEDULER_COLLECTION_ITEMS:
        raise ValueError(f"{field} must not exceed {_MAX_SCHEDULER_COLLECTION_ITEMS}")
    return normalized


def _nonnegative_decimal(value: object, *, field: str) -> Decimal:
    if type(value) is int:
        normalized = Decimal(value)
    elif type(value) is Decimal:
        normalized = value
    else:
        raise TypeError(f"{field} must be an int or Decimal")
    if not normalized.is_finite() or normalized < 0:
        raise ValueError(f"{field} must be finite and non-negative")
    return normalized


def _positive_decimal(value: object, *, field: str) -> Decimal:
    normalized = _nonnegative_decimal(value, field=field)
    if normalized == 0:
        raise ValueError(f"{field} must be positive")
    return normalized


def _ceil_ratio(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


class CapacityError(RuntimeError):
    pass


class SchedulerClosed(RuntimeError):
    pass


class SubmitResult(StrEnum):
    ENQUEUED = "enqueued"
    REPLACED = "replaced"
    STALE_IGNORED = "stale_ignored"
    IDEMPOTENT = "idempotent"
    EVICTED_AND_ENQUEUED = "evicted_and_enqueued"
    EXPIRED = "expired"


class MonotonicWaiter(Protocol):
    def wait_until(
        self,
        *,
        deadline_ns: int | None,
        wake_event: asyncio.Event,
        now_ns: int,
    ) -> Awaitable[None]: ...


class EventMonotonicWaiter:
    async def wait_until(
        self,
        *,
        deadline_ns: int | None,
        wake_event: asyncio.Event,
        now_ns: int,
    ) -> None:
        if wake_event.is_set():
            return
        if deadline_ns is None:
            await wake_event.wait()
            return
        now_ns = _nonnegative_int(now_ns, field="now_ns")
        if now_ns >= deadline_ns:
            return
        delta_ns = deadline_ns - now_ns
        whole_seconds, remainder_ns = divmod(delta_ns, _NANOSECONDS_PER_SECOND)
        try:
            timeout = float(whole_seconds) + (remainder_ns / _NANOSECONDS_PER_SECOND)
        except OverflowError:
            await wake_event.wait()
            return
        try:
            await asyncio.wait_for(wake_event.wait(), timeout=timeout)
        except TimeoutError:
            pass


@dataclass(frozen=True, slots=True)
class IntervalWarning:
    requested_ns: int
    effective_ns: int
    affected_symbols: int


@dataclass(frozen=True, slots=True)
class IntervalPlan:
    requested_ns: int
    effective_ns: int
    warning: IntervalWarning | None


def solve_interval(
    *,
    requested_ns: int,
    jobs: int,
    cost: DecimalInput,
    available_tokens_per_second: DecimalInput,
    policy: OverloadPolicy = "stretch_with_warning",
    max_effective_ns: int = _DEFAULT_MAX_EFFECTIVE_NS,
) -> IntervalPlan:
    requested = _positive_int(requested_ns, field="requested_ns")
    job_count = _nonnegative_int(jobs, field="jobs")
    normalized_cost = _positive_decimal(cost, field="cost")
    available = _nonnegative_decimal(
        available_tokens_per_second,
        field="available_tokens_per_second",
    )
    maximum = _positive_int(max_effective_ns, field="max_effective_ns")
    if type(policy) is not str or policy not in {"stretch_with_warning", "fail"}:
        raise ValueError("policy must be stretch_with_warning or fail")
    if requested > maximum:
        raise CapacityError("requested interval exceeds max effective interval")
    if job_count == 0:
        return IntervalPlan(requested, requested, None)
    if available == 0:
        raise CapacityError("available token rate is zero for non-empty work")

    cost_numerator, cost_denominator = normalized_cost.as_integer_ratio()
    rate_numerator, rate_denominator = available.as_integer_ratio()
    required_ns = _ceil_ratio(
        job_count * cost_numerator * rate_denominator * _NANOSECONDS_PER_SECOND,
        cost_denominator * rate_numerator,
    )
    effective = max(requested, required_ns)
    if effective > maximum:
        raise CapacityError("required interval exceeds max effective interval")
    if effective == requested:
        return IntervalPlan(requested, requested, None)
    if policy == "fail":
        raise CapacityError("capacity cannot satisfy the requested interval")
    return IntervalPlan(
        requested_ns=requested,
        effective_ns=effective,
        warning=IntervalWarning(
            requested_ns=requested,
            effective_ns=effective,
            affected_symbols=job_count,
        ),
    )


def _step_decimal(value: object) -> Decimal:
    if type(value) is Decimal:
        normalized = value
    elif type(value) is float:
        normalized = Decimal(str(value))
    else:
        raise TypeError("recovery_step must be a float or Decimal")
    if not normalized.is_finite() or normalized <= 0 or normalized > 1:
        raise ValueError("recovery_step must be in the interval (0, 1]")
    return normalized


class IntervalController:
    __slots__ = (
        "_activation_in_progress",
        "_current_ns",
        "_healthy_refreshes",
        "_healthy_refreshes_required",
        "_last_refresh_id",
        "_recovery_step",
        "_revision",
    )

    def __init__(
        self,
        *,
        current_ns: int,
        recovery_step: float | Decimal,
        healthy_refreshes_required: int,
    ) -> None:
        self._current_ns = _positive_int(current_ns, field="current_ns")
        self._recovery_step = _step_decimal(recovery_step)
        self._healthy_refreshes_required = _positive_int(
            healthy_refreshes_required,
            field="healthy_refreshes_required",
        )
        self._healthy_refreshes = 0
        self._last_refresh_id: int | None = None
        self._revision = 0
        self._activation_in_progress = False

    @property
    def current_ns(self) -> int:
        return self._current_ns

    @property
    def healthy_refreshes(self) -> int:
        return self._healthy_refreshes

    def mark_unhealthy(self) -> None:
        self._require_not_activating()
        self._healthy_refreshes = 0
        self._revision += 1

    def _require_not_activating(self) -> None:
        if self._activation_in_progress:
            raise RuntimeError("interval activation is already in progress")

    def propose_interval(self, effective_ns: int) -> IntervalProposal:
        effective = _positive_int(effective_ns, field="effective_ns")
        if effective < self._current_ns:
            raise ValueError("interval recovery must use propose_toward")
        return IntervalProposal(
            controller_revision=self._revision,
            previous_effective_ns=self._current_ns,
            effective_ns=effective,
            healthy_refreshes=0,
            refresh_id=None,
        )

    def _recovery_transition(self, target_ns: int) -> tuple[int, int]:
        if target_ns >= self._current_ns:
            return self._current_ns, 0
        healthy_refreshes = min(
            self._healthy_refreshes + 1,
            self._healthy_refreshes_required,
        )
        if healthy_refreshes < self._healthy_refreshes_required:
            return self._current_ns, healthy_refreshes
        step_numerator, step_denominator = self._recovery_step.as_integer_ratio()
        keep_numerator = step_denominator - step_numerator
        rounded_step = _ceil_ratio(
            self._current_ns * keep_numerator,
            step_denominator,
        )
        candidate = max(target_ns, min(self._current_ns - 1, rounded_step))
        return candidate, healthy_refreshes

    def propose_toward(
        self,
        target_ns: int,
        *,
        refresh_id: int,
    ) -> IntervalProposal:
        target = _positive_int(target_ns, field="target_ns")
        refresh = _nonnegative_int(refresh_id, field="refresh_id")
        if self._last_refresh_id is not None and refresh <= self._last_refresh_id:
            raise ValueError("refresh_id must increase after every committed refresh")
        candidate, healthy_refreshes = self._recovery_transition(target)
        return IntervalProposal(
            controller_revision=self._revision,
            previous_effective_ns=self._current_ns,
            effective_ns=candidate,
            healthy_refreshes=healthy_refreshes,
            refresh_id=refresh,
            recovery_target_ns=target,
        )

    def _set_current_ns(self, value: int) -> None:
        self._current_ns = _positive_int(value, field="current_ns")

    def commit(self, proposal: IntervalProposal) -> None:
        self._require_not_activating()
        if type(proposal) is not IntervalProposal:
            raise TypeError("proposal must be an IntervalProposal")
        if proposal.effective_ns != proposal.previous_effective_ns:
            raise ValueError("changed interval proposals require publication")
        self._validate_proposal(proposal)
        self._apply_proposal(proposal)

    def _validate_proposal(self, proposal: IntervalProposal) -> None:
        if type(proposal) is not IntervalProposal:
            raise TypeError("proposal must be an IntervalProposal")
        if (
            proposal.controller_revision != self._revision
            or proposal.previous_effective_ns != self._current_ns
        ):
            raise ValueError("interval proposal is stale")
        if proposal.healthy_refreshes > self._healthy_refreshes_required:
            raise ValueError("interval proposal has an invalid healthy refresh count")
        if (
            proposal.refresh_id is not None
            and self._last_refresh_id is not None
            and proposal.refresh_id <= self._last_refresh_id
        ):
            raise ValueError("interval refresh proposal is stale")
        target = proposal.recovery_target_ns
        if target is None:
            if (
                proposal.refresh_id is not None
                or proposal.healthy_refreshes != 0
                or proposal.effective_ns < self._current_ns
            ):
                raise ValueError("interval proposal is not a legal direct transition")
            return
        if proposal.refresh_id is None:
            raise ValueError("interval proposal is missing its refresh identity")
        expected_effective, expected_refreshes = self._recovery_transition(target)
        if (
            proposal.effective_ns != expected_effective
            or proposal.healthy_refreshes != expected_refreshes
        ):
            raise ValueError("interval proposal is not a legal recovery transition")

    def _apply_proposal(self, proposal: IntervalProposal) -> None:
        self._set_current_ns(proposal.effective_ns)
        self._healthy_refreshes = proposal.healthy_refreshes
        if proposal.refresh_id is not None:
            self._last_refresh_id = proposal.refresh_id
        self._revision += 1

    def activate(
        self,
        proposal: IntervalProposal,
        change: IntervalChange,
        publisher: IntervalChangePublisher,
    ) -> PublishedIntervalChange:
        from crypto_collector.scheduler.interval_observability import IntervalChange

        if type(change) is not IntervalChange:
            raise TypeError("change must be an IntervalChange")
        if type(proposal) is not IntervalProposal:
            raise TypeError("proposal must be an IntervalProposal")
        if (
            change.previous_effective_ns != proposal.previous_effective_ns
            or change.effective_ns != proposal.effective_ns
        ):
            raise ValueError("interval change does not match its proposal")
        if change.effective_ns == change.previous_effective_ns:
            raise ValueError("unchanged proposals do not require publication")
        self._require_not_activating()
        self._validate_proposal(proposal)
        self._activation_in_progress = True
        try:
            published = publisher.publish(change)
            self._apply_proposal(proposal)
            return published
        finally:
            self._activation_in_progress = False


@dataclass(frozen=True, slots=True)
class IntervalProposal:
    controller_revision: int
    previous_effective_ns: int
    effective_ns: int
    healthy_refreshes: int
    refresh_id: int | None
    recovery_target_ns: int | None = None

    def __post_init__(self) -> None:
        _nonnegative_int(self.controller_revision, field="controller_revision")
        _positive_int(self.previous_effective_ns, field="previous_effective_ns")
        _positive_int(self.effective_ns, field="effective_ns")
        _nonnegative_int(self.healthy_refreshes, field="healthy_refreshes")
        if self.refresh_id is not None:
            _nonnegative_int(self.refresh_id, field="refresh_id")
        if self.recovery_target_ns is not None:
            _positive_int(self.recovery_target_ns, field="recovery_target_ns")


@dataclass(frozen=True, slots=True)
class _Pending:
    job: RestJob
    sequence: int


class RestScheduler:
    def __init__(
        self,
        budgets: BudgetRegistry,
        *,
        clock: Clock | None = None,
        max_pending: int = 10_000,
        max_history: int = 1_024,
        waiter: MonotonicWaiter | None = None,
    ) -> None:
        if type(budgets) is not BudgetRegistry:
            raise TypeError("budgets must be a BudgetRegistry")
        self._budgets = budgets
        self._clock = budgets.clock if clock is None else clock
        if self._clock is not budgets.clock:
            raise ValueError("scheduler and budget registry must share one clock")
        self._max_pending = _bounded_collection_size(
            max_pending,
            field="max_pending",
        )
        history_limit = _bounded_collection_size(
            max_history,
            field="max_history",
        )
        self._waiter = EventMonotonicWaiter() if waiter is None else waiter
        now = _nonnegative_int(
            self._clock.monotonic_ns(),
            field="clock.monotonic_ns()",
        )
        self._last_now_ns = now
        self._sequence = 0
        self._jobs: dict[str, _Pending] = {}
        self._logical_index: dict[tuple[str, ...], str] = {}
        self._future: list[tuple[int, int, str]] = []
        self._ready: list[tuple[int, int, str]] = []
        self._expired: deque[str] = deque(maxlen=history_limit)
        self._evicted: deque[str] = deque(maxlen=history_limit)
        self._next_budget_ready_ns: int | None = None
        self._revision = 0
        self._changed = asyncio.Event()
        self._closed = False

    @property
    def physical_heap_entries(self) -> int:
        return len(self._future) + len(self._ready)

    def _now_ns(self) -> int:
        observed = _nonnegative_int(
            self._clock.monotonic_ns(),
            field="clock.monotonic_ns()",
        )
        self._last_now_ns = max(self._last_now_ns, observed)
        return self._last_now_ns

    def pending_ids(self) -> tuple[str, ...]:
        return tuple(
            pending.job.id
            for pending in sorted(
                self._jobs.values(),
                key=lambda item: item.sequence,
            )
        )

    def expired_ids(self) -> tuple[str, ...]:
        return tuple(self._expired)

    def evicted_ids(self) -> tuple[str, ...]:
        return tuple(self._evicted)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._revision += 1
        self._changed.set()

    def notify_resources_changed(self) -> None:
        if self._closed:
            return
        self._revision += 1
        self._changed.set()

    async def submit(self, job: RestJob) -> SubmitResult:
        return self.submit_nowait(job)

    def submit_nowait(self, job: RestJob) -> SubmitResult:
        if self._closed:
            raise SchedulerClosed("REST scheduler is closed")
        if type(job) is not RestJob:
            raise TypeError("job must be a RestJob")
        existing_by_id = self._jobs.get(job.id)
        if existing_by_id is not None:
            if existing_by_id.job == job:
                return SubmitResult.IDEMPOTENT
            raise ValueError(f"job id {job.id!r} is already pending")
        for key in job.budget_keys:
            bucket = self._budgets.bucket(key)
            if job.endpoint_cost > bucket.hard_capacity:
                raise CapacityError(
                    "job endpoint cost exceeds a route budget hard capacity"
                )

        replaced_id: str | None = None
        result = SubmitResult.ENQUEUED
        if job.replaceable:
            if job.logical_key is None:  # pragma: no cover - RestJob validates this
                raise ValueError("replaceable jobs require a logical key")
            replaced_id = self._logical_index.get(job.logical_key)
            if replaced_id is not None:
                replaced = self._jobs[replaced_id].job
                if job.scheduled_ns < replaced.scheduled_ns:
                    return SubmitResult.STALE_IGNORED
                if job.scheduled_ns == replaced.scheduled_ns:
                    raise ValueError("conflicting jobs share one logical occurrence")
        now = self._now_ns()
        if job.deadline_ns is not None and now > job.deadline_ns:
            if replaced_id is not None:
                self._remove_pending(replaced_id)
                self._revision += 1
                self._changed.set()
            self._expired.append(job.id)
            return SubmitResult.EXPIRED
        expired_count = self._expire_all(now)
        if expired_count:
            self._revision += 1
            self._changed.set()
        if replaced_id is not None and replaced_id not in self._jobs:
            replaced_id = None
        if replaced_id is None and len(self._jobs) >= self._max_pending:
            evicted_id = self._eviction_candidate(job)
            if evicted_id is None:
                raise CapacityError("REST scheduler pending capacity is exhausted")
            self._remove_pending(evicted_id)
            self._evicted.append(evicted_id)
            result = SubmitResult.EVICTED_AND_ENQUEUED
        if replaced_id is not None:
            self._remove_pending(replaced_id)
            result = SubmitResult.REPLACED

        self._sequence += 1
        pending = _Pending(job=job, sequence=self._sequence)
        self._jobs[job.id] = pending
        if job.logical_key is not None and job.replaceable:
            self._logical_index[job.logical_key] = job.id
        if job.ready_monotonic_ns <= now:
            heapq.heappush(
                self._ready,
                (int(job.priority), pending.sequence, job.id),
            )
        else:
            heapq.heappush(
                self._future,
                (job.ready_monotonic_ns, pending.sequence, job.id),
            )
        self._revision += 1
        self._changed.set()
        return result

    def _eviction_candidate(self, incoming: RestJob) -> str | None:
        if incoming.replaceable:
            return None
        candidates = [
            pending
            for pending in self._jobs.values()
            if pending.job.replaceable and pending.job.priority > incoming.priority
        ]
        if not candidates:
            return None
        return max(
            candidates,
            key=lambda pending: (int(pending.job.priority), pending.sequence),
        ).job.id

    def _remove_pending(self, job_id: str) -> None:
        pending = self._jobs.pop(job_id)
        logical_key = pending.job.logical_key
        if logical_key is not None and self._logical_index.get(logical_key) == job_id:
            del self._logical_index[logical_key]
        self._future = [entry for entry in self._future if entry[2] != job_id]
        self._ready = [entry for entry in self._ready if entry[2] != job_id]
        heapq.heapify(self._future)
        heapq.heapify(self._ready)

    def _complete_pending(self, pending: _Pending) -> None:
        self._jobs.pop(pending.job.id, None)
        logical_key = pending.job.logical_key
        if (
            logical_key is not None
            and self._logical_index.get(logical_key) == pending.job.id
        ):
            del self._logical_index[logical_key]

    def _expire(self, pending: _Pending) -> None:
        self._remove_pending(pending.job.id)
        self._expired.append(pending.job.id)

    def _expire_all(self, now_ns: int) -> int:
        expired = sorted(
            (
                pending
                for pending in self._jobs.values()
                if pending.job.deadline_ns is not None
                and now_ns > pending.job.deadline_ns
            ),
            key=lambda item: item.sequence,
        )
        if not expired:
            return 0
        expired_ids = {pending.job.id for pending in expired}
        for pending in expired:
            self._jobs.pop(pending.job.id)
            logical_key = pending.job.logical_key
            if (
                logical_key is not None
                and self._logical_index.get(logical_key) == pending.job.id
            ):
                del self._logical_index[logical_key]
            self._expired.append(pending.job.id)
        self._future = [entry for entry in self._future if entry[2] not in expired_ids]
        self._ready = [entry for entry in self._ready if entry[2] not in expired_ids]
        heapq.heapify(self._future)
        heapq.heapify(self._ready)
        return len(expired)

    def _promote_ready(self, now_ns: int) -> None:
        while self._future and self._future[0][0] <= now_ns:
            _, sequence, job_id = heapq.heappop(self._future)
            pending = self._jobs.get(job_id)
            if pending is None or pending.sequence != sequence:
                continue
            if pending.job.deadline_ns is not None and now_ns > pending.job.deadline_ns:
                self._expire(pending)
                continue
            heapq.heappush(
                self._ready,
                (int(pending.job.priority), sequence, job_id),
            )

    @staticmethod
    def _eligible_routes(job: RestJob) -> tuple[RestBudgetRoute, ...]:
        source = job.generation_source
        if source is None:
            return job.routes
        return tuple(
            route for route in job.routes if route.egress_id == source.egress_id
        )

    def _next_ready(self) -> RestDispatch | None:
        if self._closed:
            raise SchedulerClosed("REST scheduler is closed")
        now = self._now_ns()
        self._expire_all(now)
        self._promote_ready(now)
        blocked: list[tuple[int, int, str]] = []
        blocked_budgets: set[tuple[str, str, str]] = set()
        next_budget_ready_ns: int | None = None
        selected: RestDispatch | None = None
        while self._ready:
            entry = heapq.heappop(self._ready)
            _, sequence, job_id = entry
            pending = self._jobs.get(job_id)
            if pending is None or pending.sequence != sequence:
                continue
            if pending.job.deadline_ns is not None and now > pending.job.deadline_ns:
                self._expire(pending)
                continue
            routes = self._eligible_routes(pending.job)
            budget_keys = tuple(dict.fromkeys(route.budget_key for route in routes))
            available_keys = tuple(
                key for key in budget_keys if key not in blocked_budgets
            )
            if not available_keys:
                blocked.append(entry)
                continue
            selected_key = self._budgets.try_acquire_one(
                available_keys,
                cost=pending.job.endpoint_cost,
                now_ns=now,
            )
            if selected_key is None:
                blocked_budgets.update(available_keys)
                for key in available_keys:
                    ready_at = self._budgets.ready_at_ns(
                        key,
                        cost=pending.job.endpoint_cost,
                        now_ns=now,
                    )
                    if ready_at is not None:
                        next_budget_ready_ns = (
                            ready_at
                            if next_budget_ready_ns is None
                            else min(next_budget_ready_ns, ready_at)
                        )
                blocked.append(entry)
                continue
            self._complete_pending(pending)
            selected_route = next(
                route for route in routes if route.budget_key == selected_key
            )
            selected = RestDispatch(
                job=pending.job,
                route=selected_route,
                dispatched_monotonic_ns=now,
            )
            break
        for entry in blocked:
            heapq.heappush(self._ready, entry)
        self._next_budget_ready_ns = next_budget_ready_ns
        return selected

    async def next_ready_or_none(self) -> RestDispatch | None:
        return self._next_ready()

    def _next_wait_deadline_ns(self, now_ns: int) -> int | None:
        candidates: list[int] = []
        if self._next_budget_ready_ns is not None:
            candidates.append(max(now_ns, self._next_budget_ready_ns))
        if self._future:
            candidates.append(max(now_ns, self._future[0][0]))
        deadline_wakes = [
            pending.job.deadline_ns + 1
            for pending in self._jobs.values()
            if pending.job.deadline_ns is not None
        ]
        candidates.extend(deadline_wakes)
        return min(candidates) if candidates else None

    async def next_ready(self) -> RestDispatch:
        while True:
            if self._closed:
                raise SchedulerClosed("REST scheduler is closed")
            selected = self._next_ready()
            if selected is not None:
                return selected
            now = self._now_ns()
            deadline_ns = self._next_wait_deadline_ns(now)
            revision = self._revision
            self._changed.clear()
            if revision != self._revision:
                continue
            await self._waiter.wait_until(
                deadline_ns=deadline_ns,
                wake_event=self._changed,
                now_ns=now,
            )
