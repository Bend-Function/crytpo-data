from __future__ import annotations

from dataclasses import dataclass

from crypto_collector.materializer.models import TimeSource

_MAX_SIGNED_INT64 = 2**63 - 1


def _nonnegative_int64(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    if value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must fit a signed 64-bit integer")
    return value


@dataclass(frozen=True, slots=True)
class ChosenTime:
    effective_event_time_ns: int
    time_source: TimeSource

    def __post_init__(self) -> None:
        _nonnegative_int64(
            self.effective_event_time_ns,
            field_name="effective_event_time_ns",
        )
        if type(self.time_source) is not TimeSource:
            raise TypeError("time_source must be TimeSource")


@dataclass(frozen=True, slots=True)
class EventTimePolicy:
    max_past_skew_ns: int
    max_future_skew_ns: int

    def __post_init__(self) -> None:
        _nonnegative_int64(
            self.max_past_skew_ns,
            field_name="max_past_skew_ns",
        )
        _nonnegative_int64(
            self.max_future_skew_ns,
            field_name="max_future_skew_ns",
        )

    def choose(
        self,
        *,
        event_time_ns: int | None,
        received_at_ns: int,
    ) -> ChosenTime:
        received = _nonnegative_int64(
            received_at_ns,
            field_name="received_at_ns",
        )
        if event_time_ns is None:
            return ChosenTime(received, TimeSource.RECEIVE_MISSING)

        event = _nonnegative_int64(event_time_ns, field_name="event_time_ns")
        if event <= received:
            within_skew = received - event <= self.max_past_skew_ns
        else:
            within_skew = event - received <= self.max_future_skew_ns
        if within_skew:
            return ChosenTime(event, TimeSource.EVENT)
        return ChosenTime(received, TimeSource.RECEIVE_OUTLIER)


__all__ = ["ChosenTime", "EventTimePolicy", "TimeSource"]
