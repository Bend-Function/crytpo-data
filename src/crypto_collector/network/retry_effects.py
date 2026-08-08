from __future__ import annotations

from decimal import Decimal
from typing import TYPE_CHECKING

from crypto_collector.domain.clock import Clock
from crypto_collector.network.rate_limit import BudgetRegistry, DecimalInput
from crypto_collector.network.retry import (
    QuotaRestrictionStore,
    RetryDecision,
    apply_quota_retry_effect,
)

if TYPE_CHECKING:
    from crypto_collector.scheduler import RestDispatch


class RestRetryEffects:
    """Apply one classified REST retry effect to its selected quota route."""

    def __init__(
        self,
        *,
        budgets: BudgetRegistry,
        state_store: QuotaRestrictionStore,
        clock: Clock,
        throttle_multiplier: DecimalInput = Decimal("0.5"),
        minimum_refill_per_second: DecimalInput = 0,
    ) -> None:
        if type(budgets) is not BudgetRegistry:
            raise TypeError("budgets must be BudgetRegistry")
        if budgets.clock is not clock:
            raise ValueError("retry effects and budgets must share one clock")
        if not callable(getattr(state_store, "record_ban", None)):
            raise TypeError("state_store must provide record_ban()")
        self._budgets = budgets
        self._state_store = state_store
        self._clock = clock
        self._throttle_multiplier = throttle_multiplier
        self._minimum_refill_per_second = minimum_refill_per_second

    def apply(self, dispatch: RestDispatch, decision: RetryDecision) -> None:
        if not hasattr(dispatch, "job") or not hasattr(dispatch, "source_context"):
            raise TypeError("dispatch must provide REST dispatch evidence")
        route = getattr(dispatch, "route", None)
        if route is None or not hasattr(route, "budget_key"):
            raise TypeError("dispatch must provide a REST budget route")
        if type(decision) is not RetryDecision:
            raise TypeError("decision must be RetryDecision")
        exchange, quota_group, _logical_endpoint = route.budget_key
        apply_quota_retry_effect(
            decision,
            exchange=exchange,
            quota_group=quota_group,
            now_unix_ns=self._clock.time_ns(),
            state_store=self._state_store,
            budget=self._budgets.bucket(route.budget_key),
            throttle_multiplier=self._throttle_multiplier,
            minimum_refill_per_second=self._minimum_refill_per_second,
        )


__all__ = ["RestRetryEffects"]
