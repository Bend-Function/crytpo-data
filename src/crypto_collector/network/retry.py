from __future__ import annotations

import random
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from email.utils import parsedate_to_datetime
from enum import Enum
from typing import Protocol

from crypto_collector.domain.clock import Clock, SystemClock
from crypto_collector.network.rate_limit import DecimalInput, TokenBucket

_NANOSECONDS_PER_SECOND = 1_000_000_000
_DELAY_SECONDS = re.compile(r"[0-9]+\Z")
_MAX_DELAY_SECONDS_DIGITS = 20
_RETRYABLE_HTTP_STATUSES = frozenset({408, 425, 500, 502, 503, 504})


def _nonnegative_integer(value: int, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _positive_integer(value: int, *, field: str) -> int:
    value = _nonnegative_integer(value, field=field)
    if value == 0:
        raise ValueError(f"{field} must be positive")
    return value


class RetryAction(str, Enum):
    DO_NOT_RETRY = "do_not_retry"
    BACKOFF = "backoff"
    THROTTLE = "throttle"
    BAN = "ban"


@dataclass(frozen=True, slots=True)
class RetryClassification:
    action: RetryAction
    retry_after: str | None
    reason: str

    def __post_init__(self) -> None:
        if type(self.action) is not RetryAction:
            raise TypeError("action must be a RetryAction")
        if self.retry_after is not None and type(self.retry_after) is not str:
            raise TypeError("retry_after must be a string or None")
        if type(self.reason) is not str or not self.reason:
            raise ValueError("reason must be a non-empty string")


@dataclass(frozen=True, slots=True)
class RetryDecision:
    retry: bool
    delay_ns: int
    action: RetryAction
    cause: str
    reason: str

    def __post_init__(self) -> None:
        if type(self.retry) is not bool:
            raise TypeError("retry must be a boolean")
        _nonnegative_integer(self.delay_ns, field="delay_ns")
        if type(self.action) is not RetryAction:
            raise TypeError("action must be a RetryAction")
        if type(self.cause) is not str or not self.cause:
            raise ValueError("cause must be a non-empty string")
        if type(self.reason) is not str or not self.reason:
            raise ValueError("reason must be a non-empty string")


class QuotaRestrictionStore(Protocol):
    def record_ban(
        self,
        *,
        exchange: str,
        quota_group: str,
        until_unix_ns: int,
        reason: str,
    ) -> None: ...


def classify_http(
    status: int,
    retry_after: str | None = None,
    *,
    explicit_ban: bool = False,
) -> RetryClassification:
    if type(status) is not int or not 100 <= status <= 599:
        raise ValueError("status must be an HTTP status integer")
    if retry_after is not None and type(retry_after) is not str:
        raise TypeError("retry_after must be a string or None")
    if type(explicit_ban) is not bool:
        raise TypeError("explicit_ban must be a boolean")
    if explicit_ban:
        return RetryClassification(RetryAction.BAN, retry_after, "exchange_ban")
    if status == 418:
        return RetryClassification(RetryAction.BAN, retry_after, "http_418")
    if status == 429:
        return RetryClassification(RetryAction.THROTTLE, retry_after, "http_429")
    if status in _RETRYABLE_HTTP_STATUSES:
        return RetryClassification(
            RetryAction.BACKOFF,
            retry_after,
            f"http_{status}",
        )
    return RetryClassification(
        RetryAction.DO_NOT_RETRY,
        retry_after,
        f"http_{status}",
    )


def _datetime_to_unix_ns(value: datetime) -> int:
    utc_value = value.astimezone(UTC)
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    delta = utc_value - epoch
    return (
        delta.days * 86_400 + delta.seconds
    ) * _NANOSECONDS_PER_SECOND + delta.microseconds * 1_000


def parse_retry_after_ns(value: str | None, *, now_unix_ns: int) -> int | None:
    if value is None:
        return None
    if type(value) is not str or not value:
        return None
    if _DELAY_SECONDS.fullmatch(value):
        if len(value) > _MAX_DELAY_SECONDS_DIGITS:
            return None
        return int(value) * _NANOSECONDS_PER_SECOND
    now_unix_ns = _nonnegative_integer(now_unix_ns, field="now_unix_ns")
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed.tzinfo is None:
        return None
    target_unix_ns = _datetime_to_unix_ns(parsed)
    return max(0, target_unix_ns - now_unix_ns)


def _exponential_limit(*, attempt: int, base_ns: int, cap_ns: int) -> int:
    if base_ns >= cap_ns or attempt > cap_ns.bit_length():
        return cap_ns
    return min(cap_ns, base_ns * (1 << attempt))


def full_jitter_ns(
    attempt: int,
    base_ns: int,
    cap_ns: int,
    rng: random.Random,
) -> int:
    attempt = _nonnegative_integer(attempt, field="attempt")
    base_ns = _positive_integer(base_ns, field="base_ns")
    cap_ns = _positive_integer(cap_ns, field="cap_ns")
    if not isinstance(rng, random.Random):
        raise TypeError("rng must be a random.Random")
    upper = _exponential_limit(attempt=attempt, base_ns=base_ns, cap_ns=cap_ns)
    return rng.randrange(upper + 1)


class RetryPolicy:
    __slots__ = ("_base_ns", "_cap_ns", "_clock", "_max_attempts", "_rng")

    def __init__(
        self,
        *,
        clock: Clock,
        rng: random.Random,
        max_attempts: int,
        base_ns: int,
        cap_ns: int,
    ) -> None:
        self._clock = clock
        if not isinstance(rng, random.Random):
            raise TypeError("rng must be a random.Random")
        self._rng = rng
        self._max_attempts = _positive_integer(max_attempts, field="max_attempts")
        self._base_ns = _positive_integer(base_ns, field="base_ns")
        self._cap_ns = _positive_integer(cap_ns, field="cap_ns")

    @property
    def max_attempts(self) -> int:
        return self._max_attempts

    @property
    def base_ns(self) -> int:
        return self._base_ns

    @property
    def cap_ns(self) -> int:
        return self._cap_ns

    def decide(
        self,
        *,
        attempt: int,
        now_ns: int,
        deadline_ns: int,
        retry_after: str | None = None,
        classification: RetryClassification | None = None,
    ) -> RetryDecision:
        attempt = _nonnegative_integer(attempt, field="attempt")
        now_ns = _nonnegative_integer(now_ns, field="now_ns")
        deadline_ns = _nonnegative_integer(deadline_ns, field="deadline_ns")
        if deadline_ns < now_ns:
            raise ValueError("deadline_ns cannot precede now_ns")
        if (
            classification is not None
            and type(classification) is not RetryClassification
        ):
            raise TypeError("classification must be a RetryClassification")
        if classification is not None and retry_after is not None:
            raise ValueError("retry_after is already carried by classification")
        selected = classification or RetryClassification(
            RetryAction.BACKOFF,
            retry_after,
            "transient_failure",
        )
        if selected.action is RetryAction.DO_NOT_RETRY:
            return RetryDecision(
                False,
                0,
                selected.action,
                selected.reason,
                selected.reason,
            )

        parsed_retry_after_ns = None
        if selected.retry_after is not None:
            retry_after_wall_ns = 0
            if not _DELAY_SECONDS.fullmatch(selected.retry_after):
                retry_after_wall_ns = _nonnegative_integer(
                    self._clock.time_ns(),
                    field="clock.time_ns()",
                )
            parsed_retry_after_ns = parse_retry_after_ns(
                selected.retry_after,
                now_unix_ns=retry_after_wall_ns,
            )
        jitter_ns = full_jitter_ns(
            attempt,
            base_ns=self._base_ns,
            cap_ns=self._cap_ns,
            rng=self._rng,
        )
        delay_ns = max(parsed_retry_after_ns or 0, jitter_ns)
        if attempt >= self._max_attempts:
            return RetryDecision(
                False,
                delay_ns,
                selected.action,
                selected.reason,
                "attempt_limit",
            )
        remaining_ns = deadline_ns - now_ns
        if parsed_retry_after_ns is not None and parsed_retry_after_ns > remaining_ns:
            return RetryDecision(
                False,
                delay_ns,
                selected.action,
                selected.reason,
                "retry_after_exceeds_deadline",
            )
        if delay_ns > remaining_ns:
            return RetryDecision(
                False,
                delay_ns,
                selected.action,
                selected.reason,
                "backoff_exceeds_deadline",
            )
        return RetryDecision(
            True,
            delay_ns,
            selected.action,
            selected.reason,
            selected.reason,
        )


def apply_quota_retry_effect(
    decision: RetryDecision,
    *,
    exchange: str,
    quota_group: str,
    now_unix_ns: int,
    state_store: QuotaRestrictionStore,
    budget: TokenBucket,
    throttle_multiplier: DecimalInput = Decimal("0.5"),
    minimum_refill_per_second: DecimalInput = 0,
) -> None:
    if type(decision) is not RetryDecision:
        raise TypeError("decision must be a RetryDecision")
    if decision.action is RetryAction.BAN:
        now_unix_ns = _nonnegative_integer(now_unix_ns, field="now_unix_ns")
        state_store.record_ban(
            exchange=exchange,
            quota_group=quota_group,
            until_unix_ns=now_unix_ns + decision.delay_ns,
            reason=decision.cause,
        )
    elif decision.action is RetryAction.THROTTLE:
        budget.shrink(
            multiplier=throttle_multiplier,
            floor=minimum_refill_per_second,
        )


def retry_policy(
    *,
    clock: Clock | None = None,
    rng: random.Random | None = None,
    max_attempts: int = 5,
    base_ns: int = 250_000_000,
    cap_ns: int = 30_000_000_000,
) -> RetryPolicy:
    return RetryPolicy(
        clock=SystemClock() if clock is None else clock,
        rng=random.SystemRandom() if rng is None else rng,
        max_attempts=max_attempts,
        base_ns=base_ns,
        cap_ns=cap_ns,
    )
