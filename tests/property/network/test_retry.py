from __future__ import annotations

import random
from dataclasses import dataclass

from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.network.retry import full_jitter_ns, retry_policy


@dataclass
class FakeClock:
    wall_ns: int = 0

    def time_ns(self) -> int:
        return self.wall_ns

    def monotonic_ns(self) -> int:
        return 0


@given(
    attempt=st.integers(min_value=0, max_value=20),
    base_ns=st.integers(min_value=1, max_value=10_000_000_000),
    cap_ns=st.integers(min_value=1, max_value=120_000_000_000),
    seed=st.integers(min_value=0, max_value=2**32 - 1),
)
def test_full_jitter_is_always_inside_exponential_cap(
    attempt: int,
    base_ns: int,
    cap_ns: int,
    seed: int,
) -> None:
    delay = full_jitter_ns(
        attempt,
        base_ns=base_ns,
        cap_ns=cap_ns,
        rng=random.Random(seed),
    )

    assert 0 <= delay <= min(cap_ns, base_ns * 2**attempt)


@given(
    attempt=st.integers(min_value=0, max_value=10),
    max_attempts=st.integers(min_value=1, max_value=10),
    now_ns=st.integers(min_value=0, max_value=10**15),
    budget_ns=st.integers(min_value=0, max_value=120_000_000_000),
    retry_after_seconds=st.one_of(
        st.none(),
        st.integers(min_value=0, max_value=180).map(str),
    ),
    seed=st.integers(min_value=0, max_value=2**32 - 1),
)
def test_retry_decision_never_crosses_attempt_or_monotonic_deadline(
    attempt: int,
    max_attempts: int,
    now_ns: int,
    budget_ns: int,
    retry_after_seconds: str | None,
    seed: int,
) -> None:
    deadline_ns = now_ns + budget_ns
    policy = retry_policy(
        clock=FakeClock(),
        rng=random.Random(seed),
        max_attempts=max_attempts,
    )

    decision = policy.decide(
        attempt=attempt,
        now_ns=now_ns,
        deadline_ns=deadline_ns,
        retry_after=retry_after_seconds,
    )

    if decision.retry:
        assert attempt < max_attempts
        assert now_ns + decision.delay_ns <= deadline_ns
