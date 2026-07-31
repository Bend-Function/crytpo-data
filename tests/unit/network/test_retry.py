from __future__ import annotations

import random
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from email.utils import format_datetime

import pytest

from crypto_collector.network.rate_limit import TokenBucket
from crypto_collector.network.retry import (
    RetryAction,
    apply_quota_retry_effect,
    classify_http,
    full_jitter_ns,
    parse_retry_after_ns,
    retry_policy,
)
from crypto_collector.network.state_store import EgressStateStore

SECOND_NS = 1_000_000_000


@dataclass
class FakeClock:
    wall_ns: int = 0
    monotonic: int = 0

    def time_ns(self) -> int:
        return self.wall_ns

    def monotonic_ns(self) -> int:
        return self.monotonic


@pytest.mark.parametrize(
    ("status", "retry_after", "expected"),
    [
        (429, "3", RetryAction.THROTTLE),
        (418, "120", RetryAction.BAN),
        (408, None, RetryAction.BACKOFF),
        (500, None, RetryAction.BACKOFF),
        (503, None, RetryAction.BACKOFF),
        (400, None, RetryAction.DO_NOT_RETRY),
        (404, None, RetryAction.DO_NOT_RETRY),
    ],
)
def test_http_retry_classification(
    status: int,
    retry_after: str | None,
    expected: RetryAction,
) -> None:
    classification = classify_http(status, retry_after=retry_after)

    assert classification.action is expected
    assert classification.retry_after == retry_after


def test_explicit_exchange_ban_overrides_status_classification() -> None:
    classification = classify_http(400, explicit_ban=True)

    assert classification.action is RetryAction.BAN
    assert classification.reason == "exchange_ban"


def test_retry_after_accepts_integer_seconds() -> None:
    assert parse_retry_after_ns("3", now_unix_ns=999) == 3 * SECOND_NS


def test_retry_after_accepts_http_date_using_injected_wall_time() -> None:
    now = datetime(2026, 8, 1, tzinfo=UTC)
    future = datetime(2026, 8, 1, 0, 0, 3, tzinfo=UTC)

    assert (
        parse_retry_after_ns(
            format_datetime(future, usegmt=True),
            now_unix_ns=int(now.timestamp() * SECOND_NS),
        )
        == 3 * SECOND_NS
    )


def test_retry_after_past_http_date_is_immediately_eligible() -> None:
    now = datetime(2026, 8, 1, 0, 0, 3, tzinfo=UTC)
    past = datetime(2026, 8, 1, tzinfo=UTC)

    assert (
        parse_retry_after_ns(
            format_datetime(past, usegmt=True),
            now_unix_ns=int(now.timestamp() * SECOND_NS),
        )
        == 0
    )


@pytest.mark.parametrize(
    "value",
    [None, "", "-1", "+1", "1.5", "NaN", "not-a-date", " 3", "3 "],
)
def test_retry_after_rejects_malformed_values(value: str | None) -> None:
    assert parse_retry_after_ns(value, now_unix_ns=0) is None


def test_retry_after_rejects_oversized_integer_without_raising() -> None:
    assert parse_retry_after_ns("9" * 5_000, now_unix_ns=0) is None


def test_full_jitter_never_exceeds_exponential_cap() -> None:
    rng = random.Random(7)

    assert all(
        0 <= full_jitter_ns(5, base_ns=1_000, cap_ns=10_000, rng=rng) <= 10_000
        for _ in range(100)
    )


def test_full_jitter_handles_extreme_attempt_without_building_huge_integer() -> None:
    assert (
        full_jitter_ns(
            1_000_000_000,
            base_ns=1,
            cap_ns=10,
            rng=random.Random(7),
        )
        <= 10
    )


def test_retry_policy_stops_at_attempt_limit() -> None:
    policy = retry_policy(clock=FakeClock(), rng=random.Random(1), max_attempts=5)

    decision = policy.decide(
        attempt=5,
        now_ns=0,
        deadline_ns=60 * SECOND_NS,
    )

    assert not decision.retry
    assert decision.reason == "attempt_limit"


def test_default_rest_backoff_matches_configured_design_limits() -> None:
    policy = retry_policy(clock=FakeClock(), rng=random.Random(1))

    assert policy.base_ns == 250_000_000
    assert policy.cap_ns == 30 * SECOND_NS


def test_plain_backoff_does_not_read_wall_clock() -> None:
    policy = retry_policy(
        clock=FakeClock(wall_ns=-1),
        rng=random.Random(1),
    )

    decision = policy.decide(
        attempt=1,
        now_ns=0,
        deadline_ns=60 * SECOND_NS,
    )

    assert decision.retry


def test_integer_retry_after_does_not_read_wall_clock() -> None:
    policy = retry_policy(
        clock=FakeClock(wall_ns=-1),
        rng=random.Random(1),
    )

    decision = policy.decide(
        attempt=1,
        now_ns=0,
        deadline_ns=60 * SECOND_NS,
        retry_after="3",
    )

    assert decision.retry
    assert decision.delay_ns == 3 * SECOND_NS


def test_retry_policy_stops_when_retry_after_crosses_job_deadline() -> None:
    policy = retry_policy(clock=FakeClock(), rng=random.Random(1), max_attempts=5)

    decision = policy.decide(
        attempt=1,
        now_ns=0,
        deadline_ns=2 * SECOND_NS,
        retry_after="3",
    )

    assert not decision.retry
    assert decision.delay_ns == 3 * SECOND_NS
    assert decision.reason == "retry_after_exceeds_deadline"


def test_ban_delay_survives_attempt_limit_for_persistent_cooldown() -> None:
    policy = retry_policy(clock=FakeClock(), rng=random.Random(1), max_attempts=1)

    decision = policy.decide(
        attempt=1,
        now_ns=0,
        deadline_ns=SECOND_NS,
        classification=classify_http(418, retry_after="120"),
    )

    assert not decision.retry
    assert decision.action is RetryAction.BAN
    assert decision.delay_ns == 120 * SECOND_NS
    assert decision.cause == "http_418"
    assert decision.reason == "attempt_limit"


def test_ban_effect_persists_even_when_job_attempts_are_exhausted(tmp_path) -> None:
    clock = FakeClock(wall_ns=1_000)
    bucket = TokenBucket(capacity=10, refill_per_second=8, clock=clock)
    decision = retry_policy(clock=clock, rng=random.Random(1), max_attempts=1).decide(
        attempt=1,
        now_ns=0,
        deadline_ns=SECOND_NS,
        classification=classify_http(418, retry_after="120"),
    )
    path = tmp_path / "network.sqlite"

    with EgressStateStore.open(path) as store:
        apply_quota_retry_effect(
            decision,
            exchange="binance",
            quota_group="nat-a",
            now_unix_ns=clock.time_ns(),
            state_store=store,
            budget=bucket,
        )

    with EgressStateStore.open(path) as reopened:
        state = reopened.load_quota("binance", "nat-a")
        assert state.ban_until_unix_ns == 1_000 + 120 * SECOND_NS
        assert state.last_reason == "http_418"


def test_throttle_effect_shrinks_endpoint_rate_without_group_ban(tmp_path) -> None:
    clock = FakeClock(wall_ns=2_000)
    bucket = TokenBucket(capacity=10, refill_per_second=8, clock=clock)
    decision = retry_policy(clock=clock, rng=random.Random(1)).decide(
        attempt=1,
        now_ns=0,
        deadline_ns=60 * SECOND_NS,
        classification=classify_http(429, retry_after="3"),
    )

    with EgressStateStore.open(tmp_path / "network.sqlite") as store:
        apply_quota_retry_effect(
            decision,
            exchange="okx",
            quota_group="nat-a",
            now_unix_ns=clock.time_ns(),
            state_store=store,
            budget=bucket,
            throttle_multiplier=Decimal("0.5"),
            minimum_refill_per_second=Decimal(1),
        )
        state = store.load_quota("okx", "nat-a")

    assert state.cooldown_until_unix_ns == 0
    assert state.last_reason is None
    assert bucket.refill_per_second == 4


def test_retry_policy_uses_injected_wall_time_for_http_date() -> None:
    now = datetime(2026, 8, 1, tzinfo=UTC)
    future = datetime(2026, 8, 1, 0, 0, 5, tzinfo=UTC)
    clock = FakeClock(wall_ns=int(now.timestamp() * SECOND_NS))
    policy = retry_policy(clock=clock, rng=random.Random(1))

    decision = policy.decide(
        attempt=1,
        now_ns=10,
        deadline_ns=10 + 5 * SECOND_NS,
        retry_after=format_datetime(future, usegmt=True),
    )

    assert decision.retry
    assert decision.delay_ns == 5 * SECOND_NS


def test_non_retryable_classification_never_retries() -> None:
    policy = retry_policy(clock=FakeClock(), rng=random.Random(1))

    decision = policy.decide(
        attempt=1,
        now_ns=0,
        deadline_ns=60 * SECOND_NS,
        classification=classify_http(400),
    )

    assert not decision.retry
    assert decision.action is RetryAction.DO_NOT_RETRY
    assert decision.reason == "http_400"


def test_throttle_classification_preserves_action_and_retry_after() -> None:
    policy = retry_policy(clock=FakeClock(), rng=random.Random(1))

    decision = policy.decide(
        attempt=1,
        now_ns=0,
        deadline_ns=60 * SECOND_NS,
        classification=classify_http(429, retry_after="3"),
    )

    assert decision.retry
    assert decision.action is RetryAction.THROTTLE
    assert decision.delay_ns >= 3 * SECOND_NS


def test_malformed_retry_after_cannot_expand_backoff() -> None:
    first = retry_policy(clock=FakeClock(), rng=random.Random(9)).decide(
        attempt=1,
        now_ns=0,
        deadline_ns=60 * SECOND_NS,
        retry_after="not-a-date",
    )
    second = retry_policy(clock=FakeClock(), rng=random.Random(9)).decide(
        attempt=1,
        now_ns=0,
        deadline_ns=60 * SECOND_NS,
    )

    assert first.delay_ns == second.delay_ns


@pytest.mark.parametrize(
    "kwargs",
    [
        {"attempt": True, "now_ns": 0, "deadline_ns": 1},
        {"attempt": 1, "now_ns": -1, "deadline_ns": 1},
        {"attempt": 1, "now_ns": 2, "deadline_ns": 1},
    ],
)
def test_retry_policy_rejects_invalid_clock_and_attempt_inputs(kwargs) -> None:
    policy = retry_policy(clock=FakeClock(), rng=random.Random(1))

    with pytest.raises(ValueError):
        policy.decide(**kwargs)
