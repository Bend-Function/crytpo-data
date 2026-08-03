from __future__ import annotations

import heapq
from collections.abc import Hashable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal

from crypto_collector.domain.clock import Clock

DURABILITY_HISTOGRAM_SCHEMA_VERSION = 1
MAX_DURABILITY_METRIC_STREAM_LABELS = 64
OTHER_DURABILITY_METRIC_STREAM_LABEL = "_other"
DURABILITY_BUCKET_UPPER_BOUNDS_NS = (
    0,
    100_000,
    250_000,
    500_000,
    1_000_000,
    2_500_000,
    5_000_000,
    10_000_000,
    25_000_000,
    50_000_000,
    100_000_000,
    250_000_000,
    500_000_000,
    750_000_000,
    1_000_000_000,
    1_500_000_000,
    2_000_000_000,
    3_000_000_000,
    5_000_000_000,
    10_000_000_000,
    60_000_000_000,
    2**63 - 1,
)

_MAX_SIGNED_INT64 = 2**63 - 1
_ROLLING_SLOT_COUNT = 60
_NS_PER_SECOND = 1_000_000_000


def _integer(value: object, *, field_name: str, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field_name} must be {qualifier}")
    if value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must fit a signed 64-bit integer")
    return value


def _bucket_index(lag_ns: int) -> int:
    low = 0
    high = len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    while low < high:
        middle = (low + high) // 2
        if DURABILITY_BUCKET_UPPER_BOUNDS_NS[middle] < lag_ns:
            low = middle + 1
        else:
            high = middle
    if low == len(DURABILITY_BUCKET_UPPER_BOUNDS_NS):
        raise ValueError("lag_ns exceeds the histogram schema")
    return low


def _nearest_rank(
    bucket_counts: tuple[int, ...],
    *,
    sample_count: int,
    numerator: int,
) -> int | None:
    if sample_count == 0:
        return None
    rank = max(1, (numerator * sample_count + 99) // 100)
    cumulative = 0
    for upper_bound, count in zip(
        DURABILITY_BUCKET_UPPER_BOUNDS_NS,
        bucket_counts,
        strict=True,
    ):
        cumulative += count
        if cumulative >= rank:
            return upper_bound
    raise AssertionError("histogram sample count does not match its buckets")


@dataclass(frozen=True, slots=True)
class DurabilityHistogramSnapshot:
    bucket_counts: tuple[int, ...]
    sample_count: int
    lag_total_ns: int
    lag_p50_ns: int | None
    lag_p95_ns: int | None
    lag_p99_ns: int | None
    lag_max_ns: int | None

    def __post_init__(self) -> None:
        if type(self.bucket_counts) is not tuple or len(self.bucket_counts) != len(
            DURABILITY_BUCKET_UPPER_BOUNDS_NS
        ):
            raise ValueError("bucket_counts must match the durability histogram schema")
        if any(type(count) is not int or count < 0 for count in self.bucket_counts):
            raise TypeError("bucket_counts must contain non-negative integers")
        sample_count = _integer(self.sample_count, field_name="sample_count")
        if sum(self.bucket_counts) != sample_count:
            raise ValueError("sample_count must equal the disjoint bucket sum")
        if type(self.lag_total_ns) is not int or self.lag_total_ns < 0:
            raise TypeError("lag_total_ns must be a non-negative integer")
        expected = (
            _nearest_rank(self.bucket_counts, sample_count=sample_count, numerator=50),
            _nearest_rank(self.bucket_counts, sample_count=sample_count, numerator=95),
            _nearest_rank(self.bucket_counts, sample_count=sample_count, numerator=99),
        )
        observed = (self.lag_p50_ns, self.lag_p95_ns, self.lag_p99_ns)
        if observed != expected:
            raise ValueError("durability quantiles must match nearest-rank buckets")
        if self.lag_max_ns is None:
            if sample_count != 0:
                raise ValueError("a nonempty histogram requires lag_max_ns")
            if self.lag_total_ns != 0:
                raise ValueError("an empty histogram must have zero lag_total_ns")
        else:
            maximum = _integer(self.lag_max_ns, field_name="lag_max_ns")
            if sample_count == 0:
                raise ValueError("an empty histogram cannot have lag_max_ns")
            highest_nonempty_bucket = max(
                index for index, count in enumerate(self.bucket_counts) if count
            )
            if _bucket_index(maximum) != highest_nonempty_bucket:
                raise ValueError("lag maximum must fall in the highest nonempty bucket")
            if self.lag_total_ns < maximum:
                raise ValueError("lag_total_ns cannot be smaller than lag_max_ns")


def _snapshot(
    bucket_counts: tuple[int, ...],
    *,
    sample_count: int,
    lag_total_ns: int,
    lag_max_ns: int | None,
) -> DurabilityHistogramSnapshot:
    return DurabilityHistogramSnapshot(
        bucket_counts=bucket_counts,
        sample_count=sample_count,
        lag_total_ns=lag_total_ns,
        lag_p50_ns=_nearest_rank(
            bucket_counts,
            sample_count=sample_count,
            numerator=50,
        ),
        lag_p95_ns=_nearest_rank(
            bucket_counts,
            sample_count=sample_count,
            numerator=95,
        ),
        lag_p99_ns=_nearest_rank(
            bucket_counts,
            sample_count=sample_count,
            numerator=99,
        ),
        lag_max_ns=lag_max_ns,
    )


class CumulativeDurabilityHistogram:
    def __init__(self) -> None:
        self._bucket_counts = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
        self._sample_count = 0
        self._lag_total_ns = 0
        self._lag_max_ns: int | None = None

    def add(self, lag_ns: int) -> None:
        lag = _integer(lag_ns, field_name="lag_ns")
        self._bucket_counts[_bucket_index(lag)] += 1
        self._sample_count += 1
        self._lag_total_ns += lag
        self._lag_max_ns = (
            lag if self._lag_max_ns is None else max(self._lag_max_ns, lag)
        )

    def snapshot(self) -> DurabilityHistogramSnapshot:
        return _snapshot(
            tuple(self._bucket_counts),
            sample_count=self._sample_count,
            lag_total_ns=self._lag_total_ns,
            lag_max_ns=self._lag_max_ns,
        )


@dataclass(slots=True)
class _RollingSlot:
    second: int | None = None
    bucket_counts: list[int] = field(
        default_factory=lambda: [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    )
    sample_count: int = 0
    lag_total_ns: int = 0
    lag_max_ns: int | None = None

    def clear(self) -> None:
        self.second = None
        for index in range(len(self.bucket_counts)):
            self.bucket_counts[index] = 0
        self.sample_count = 0
        self.lag_total_ns = 0
        self.lag_max_ns = None

    def reset(self, second: int) -> None:
        self.clear()
        self.second = second

    def add(self, lag_ns: int) -> None:
        self.bucket_counts[_bucket_index(lag_ns)] += 1
        self.sample_count += 1
        self.lag_total_ns += lag_ns
        self.lag_max_ns = (
            lag_ns if self.lag_max_ns is None else max(self.lag_max_ns, lag_ns)
        )


class RollingDurabilityHistogram:
    def __init__(self) -> None:
        self._slots = tuple(_RollingSlot() for _ in range(_ROLLING_SLOT_COUNT))
        self._latest_second: int | None = None

    @property
    def allocated_slot_count(self) -> int:
        return len(self._slots)

    @property
    def active_slot_count(self) -> int:
        return sum(slot.second is not None for slot in self._slots)

    def _advance(self, current_second: int) -> None:
        if self._latest_second is not None and current_second < self._latest_second:
            raise ValueError("rolling histogram time must not move backward")
        self._latest_second = current_second
        first_second = current_second - (_ROLLING_SLOT_COUNT - 1)
        for slot in self._slots:
            if slot.second is not None and not (
                first_second <= slot.second <= current_second
            ):
                slot.clear()

    def add(self, *, lag_ns: int, sync_completed_monotonic_ns: int) -> None:
        lag = _integer(lag_ns, field_name="lag_ns")
        completed = _integer(
            sync_completed_monotonic_ns,
            field_name="sync_completed_monotonic_ns",
        )
        second = completed // _NS_PER_SECOND
        latest = self._latest_second
        if latest is not None and second < latest - 59:
            return
        if latest is None or second > latest:
            self._advance(second)
        slot = self._slots[second % _ROLLING_SLOT_COUNT]
        if slot.second != second:
            slot.reset(second)
        slot.add(lag)

    def snapshot(self, *, now_monotonic_ns: int) -> DurabilityHistogramSnapshot:
        now = _integer(now_monotonic_ns, field_name="now_monotonic_ns")
        current_second = now // _NS_PER_SECOND
        if self._latest_second is None or current_second > self._latest_second:
            self._advance(current_second)
        elif current_second < self._latest_second:
            raise ValueError("rolling histogram time must not move backward")
        first_second = current_second - (_ROLLING_SLOT_COUNT - 1)
        bucket_counts = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
        sample_count = 0
        lag_total_ns = 0
        maxima: list[int] = []
        for slot in self._slots:
            if slot.second is None or not first_second <= slot.second <= current_second:
                continue
            sample_count += slot.sample_count
            lag_total_ns += slot.lag_total_ns
            for index, count in enumerate(slot.bucket_counts):
                bucket_counts[index] += count
            if slot.lag_max_ns is not None:
                maxima.append(slot.lag_max_ns)
        return _snapshot(
            tuple(bucket_counts),
            sample_count=sample_count,
            lag_total_ns=lag_total_ns,
            lag_max_ns=max(maxima) if maxima else None,
        )


class DurabilityStage(StrEnum):
    QUEUED = "queued"
    BUFFERED = "buffered"
    IN_FLIGHT = "in_flight"
    DURABLE = "durable"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True, slots=True)
class DurabilityAgeCritical:
    reason: Literal["oldest_unpersisted_age"]
    record_id: Hashable
    record_stage: DurabilityStage
    accepted_monotonic_ns: int
    observed_monotonic_ns: int
    age_ns: int


@dataclass(slots=True)
class _LedgerEntry:
    record_id: Hashable
    accepted_monotonic_ns: int
    stage: DurabilityStage
    token: int


class DurabilityLedger:
    def __init__(self, *, clock: Clock) -> None:
        self._clock = clock
        self._entries: dict[Hashable, _LedgerEntry] = {}
        self._oldest_heap: list[tuple[int, int, Hashable]] = []
        self._next_token = 0
        self._accepted_count = 0
        self._durable_count = 0
        self._uncertain_count = 0
        self._nonterminal_stage_counts = {
            DurabilityStage.QUEUED: 0,
            DurabilityStage.BUFFERED: 0,
            DurabilityStage.IN_FLIGHT: 0,
        }
        self._last_observed_monotonic_ns = 0

    @property
    def accepted_count(self) -> int:
        return self._accepted_count

    @property
    def durable_count(self) -> int:
        return self._durable_count

    @property
    def uncertain_count(self) -> int:
        return self._uncertain_count

    @property
    def unpersisted_count(self) -> int:
        return len(self._entries)

    @property
    def heap_entry_count(self) -> int:
        return len(self._oldest_heap)

    def stage_count(self, stage: DurabilityStage) -> int:
        if type(stage) is not DurabilityStage:
            raise TypeError("stage must be DurabilityStage")
        if stage is DurabilityStage.DURABLE:
            return self._durable_count
        if stage is DurabilityStage.UNCERTAIN:
            return self._uncertain_count
        return self._nonterminal_stage_counts[stage]

    def register_accepted(
        self,
        *,
        record_id: Hashable,
        accepted_monotonic_ns: int,
    ) -> None:
        try:
            hash(record_id)
        except TypeError as error:
            raise TypeError("record_id must be hashable") from error
        if record_id in self._entries:
            raise ValueError("duplicate durability record_id")
        accepted = _integer(
            accepted_monotonic_ns,
            field_name="accepted_monotonic_ns",
        )
        token = self._next_token
        self._next_token += 1
        entry = _LedgerEntry(
            record_id=record_id,
            accepted_monotonic_ns=accepted,
            stage=DurabilityStage.QUEUED,
            token=token,
        )
        self._entries[record_id] = entry
        heapq.heappush(self._oldest_heap, (accepted, token, record_id))
        self._accepted_count += 1
        self._nonterminal_stage_counts[DurabilityStage.QUEUED] += 1

    def _transition(self, record_id: Hashable, target: DurabilityStage) -> None:
        try:
            entry = self._entries[record_id]
        except KeyError as error:
            raise KeyError("unknown durability record_id") from error
        allowed = (
            (
                entry.stage is DurabilityStage.QUEUED
                and target is DurabilityStage.BUFFERED
            )
            or (
                entry.stage is DurabilityStage.BUFFERED
                and target is DurabilityStage.IN_FLIGHT
            )
            or (
                entry.stage is DurabilityStage.IN_FLIGHT
                and target is DurabilityStage.DURABLE
            )
            or (
                entry.stage
                in {
                    DurabilityStage.QUEUED,
                    DurabilityStage.BUFFERED,
                    DurabilityStage.IN_FLIGHT,
                }
                and target is DurabilityStage.UNCERTAIN
            )
        )
        if not allowed:
            raise ValueError(
                f"invalid durability transition {entry.stage.value} -> {target.value}"
            )
        self._nonterminal_stage_counts[entry.stage] -= 1
        if target in {DurabilityStage.DURABLE, DurabilityStage.UNCERTAIN}:
            del self._entries[record_id]
            if target is DurabilityStage.DURABLE:
                self._durable_count += 1
            else:
                self._uncertain_count += 1
            self._compact_oldest_heap_if_needed()
        else:
            entry.stage = target
            self._nonterminal_stage_counts[target] += 1

    def _compact_oldest_heap_if_needed(self) -> None:
        if len(self._oldest_heap) <= max(64, 2 * len(self._entries)):
            return
        self._oldest_heap = [
            (entry.accepted_monotonic_ns, entry.token, entry.record_id)
            for entry in self._entries.values()
        ]
        heapq.heapify(self._oldest_heap)

    def mark_buffered(self, record_id: Hashable) -> None:
        self._transition(record_id, DurabilityStage.BUFFERED)

    def mark_in_flight(self, record_id: Hashable) -> None:
        self._transition(record_id, DurabilityStage.IN_FLIGHT)

    def mark_durable(self, record_id: Hashable) -> None:
        self._transition(record_id, DurabilityStage.DURABLE)

    def mark_uncertain(self, record_id: Hashable) -> None:
        self._transition(record_id, DurabilityStage.UNCERTAIN)

    def _oldest_entry(self) -> _LedgerEntry | None:
        while self._oldest_heap:
            _accepted, token, record_id = self._oldest_heap[0]
            current = self._entries.get(record_id)
            if current is not None and current.token == token:
                return current
            heapq.heappop(self._oldest_heap)
        return None

    def _observe_monotonic_ns(self) -> int:
        sampled = _integer(
            self._clock.monotonic_ns(),
            field_name="clock.monotonic_ns()",
        )
        observed = max(sampled, self._last_observed_monotonic_ns)
        self._last_observed_monotonic_ns = observed
        return observed

    def oldest_unpersisted_age_ns(self) -> int | None:
        oldest = self._oldest_entry()
        if oldest is None:
            return None
        observed = self._observe_monotonic_ns()
        return max(0, observed - oldest.accepted_monotonic_ns)

    def classify_critical_age(
        self,
        *,
        durability_critical_ns: int,
    ) -> DurabilityAgeCritical | None:
        threshold = _integer(
            durability_critical_ns,
            field_name="durability_critical_ns",
        )
        oldest = self._oldest_entry()
        if oldest is None:
            return None
        observed = self._observe_monotonic_ns()
        age = max(0, observed - oldest.accepted_monotonic_ns)
        if age <= threshold:
            return None
        return DurabilityAgeCritical(
            reason="oldest_unpersisted_age",
            record_id=oldest.record_id,
            record_stage=oldest.stage,
            accepted_monotonic_ns=oldest.accepted_monotonic_ns,
            observed_monotonic_ns=observed,
            age_ns=age,
        )


__all__ = [
    "DURABILITY_BUCKET_UPPER_BOUNDS_NS",
    "DURABILITY_HISTOGRAM_SCHEMA_VERSION",
    "MAX_DURABILITY_METRIC_STREAM_LABELS",
    "OTHER_DURABILITY_METRIC_STREAM_LABEL",
    "CumulativeDurabilityHistogram",
    "DurabilityAgeCritical",
    "DurabilityHistogramSnapshot",
    "DurabilityLedger",
    "DurabilityStage",
    "RollingDurabilityHistogram",
]
