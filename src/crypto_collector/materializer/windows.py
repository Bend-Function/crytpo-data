from __future__ import annotations

from dataclasses import dataclass

_NANOSECONDS_PER_SECOND = 1_000_000_000
_MIN_WINDOW_INTERVAL_NS = 30 * _NANOSECONDS_PER_SECOND
_MAX_WINDOW_INTERVAL_NS = 60 * 60 * _NANOSECONDS_PER_SECOND
_MAX_SIGNED_INT64 = 2**63 - 1


def _nonnegative_int64(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    if value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must fit a signed 64-bit integer")
    return value


def _window_interval(value: object) -> int:
    interval_ns = _nonnegative_int64(value, field_name="interval_ns")
    if not _MIN_WINDOW_INTERVAL_NS <= interval_ns <= _MAX_WINDOW_INTERVAL_NS:
        raise ValueError("interval_ns must be between 30 seconds and 1 hour")
    if _MAX_WINDOW_INTERVAL_NS % interval_ns != 0:
        raise ValueError("interval_ns must evenly divide one hour")
    return interval_ns


@dataclass(frozen=True, slots=True, order=True)
class Window:
    start_ns: int
    end_ns: int

    def __post_init__(self) -> None:
        start_ns = _nonnegative_int64(self.start_ns, field_name="start_ns")
        end_ns = _nonnegative_int64(self.end_ns, field_name="end_ns")
        if end_ns <= start_ns:
            raise ValueError("end_ns must be greater than start_ns")
        interval_ns = _window_interval(end_ns - start_ns)
        if start_ns % interval_ns != 0:
            raise ValueError("window start must align to the Unix epoch")

    @property
    def interval_ns(self) -> int:
        return self.end_ns - self.start_ns


def window_for(timestamp_ns: int, interval_ns: int) -> Window:
    timestamp = _nonnegative_int64(timestamp_ns, field_name="timestamp_ns")
    interval = _window_interval(interval_ns)
    start_ns = timestamp // interval * interval
    end_ns = start_ns + interval
    if end_ns > _MAX_SIGNED_INT64:
        raise ValueError("window end_ns must fit a signed 64-bit integer")
    return Window(start_ns=start_ns, end_ns=end_ns)


__all__ = ["Window", "window_for"]
