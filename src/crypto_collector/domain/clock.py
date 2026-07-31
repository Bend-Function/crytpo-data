import time
from typing import Protocol


class Clock(Protocol):
    def time_ns(self) -> int: ...

    def monotonic_ns(self) -> int: ...


class SystemClock:
    def time_ns(self) -> int:
        return time.time_ns()

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()
