from __future__ import annotations

from dataclasses import dataclass
from decimal import Decimal

from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.network.rate_limit import TokenBucket


@dataclass
class FakeClock:
    now_ns: int = 0

    def time_ns(self) -> int:
        return self.now_ns

    def monotonic_ns(self) -> int:
        return self.now_ns


Action = tuple[str, int]


@given(
    st.lists(
        st.tuples(
            st.sampled_from(["advance", "rewind", "acquire", "observe"]),
            st.integers(min_value=0, max_value=1_000_000_000),
        ),
        max_size=100,
    )
)
def test_token_bucket_never_goes_negative_or_above_capacity(
    actions: list[Action],
) -> None:
    clock = FakeClock()
    bucket = TokenBucket(capacity=100, refill_per_second=7, clock=clock)

    for kind, value in actions:
        if kind == "advance":
            clock.now_ns += value
        elif kind == "rewind":
            clock.now_ns = max(0, clock.now_ns - value)
        elif kind == "acquire":
            bucket.try_acquire(1 + value % 100)
        else:
            bucket.observe_available(str(value % 151))

        assert Decimal(0) <= bucket.tokens <= bucket.capacity
        assert bucket.capacity <= bucket.hard_capacity
