from __future__ import annotations

import os
import subprocess
import sys
from decimal import Decimal
from pathlib import Path

import pytest

from crypto_collector.network import (
    BudgetRegistry,
    EgressStateStore,
    RestRetryEffects,
    RetryAction,
    RetryDecision,
)
from crypto_collector.scheduler import (
    RestBudgetRoute,
    RestDispatch,
    RestJob,
    RestPriority,
)


class FixedClock:
    def time_ns(self) -> int:
        return 1_800_000_000_000_000_000

    def monotonic_ns(self) -> int:
        return 100


def _dispatch(route: RestBudgetRoute) -> RestDispatch:
    job = RestJob(
        id="rest-1",
        priority=RestPriority.DEEP_SNAPSHOT,
        routes=(route,),
        endpoint_cost=1,
        ready_monotonic_ns=100,
        deadline_ns=1_000,
        interval=None,
        generation_source=None,
        attempt=1,
        logical_key=None,
        replaceable=False,
        scheduled_ns=100,
        control_context={},
    )
    return RestDispatch(job=job, route=route, dispatched_monotonic_ns=100)


def test_retry_effects_shrink_selected_budget_and_persist_ban(tmp_path: Path) -> None:
    clock = FixedClock()
    budgets = BudgetRegistry(clock)
    route = RestBudgetRoute("socks-a", ("okx", "shared-nat", "books-full"))
    bucket = budgets.add(route.budget_key, capacity=10, refill_per_second=10)
    with EgressStateStore.open(tmp_path / "network-state.sqlite") as state_store:
        effects = RestRetryEffects(
            budgets=budgets,
            state_store=state_store,
            clock=clock,
        )
        dispatch = _dispatch(route)

        effects.apply(
            dispatch,
            RetryDecision(
                retry=True,
                delay_ns=500,
                action=RetryAction.THROTTLE,
                cause="okx_50011",
                reason="okx_50011",
            ),
        )
        effects.apply(
            dispatch,
            RetryDecision(
                retry=True,
                delay_ns=1_000,
                action=RetryAction.BAN,
                cause="http_418",
                reason="http_418",
            ),
        )

        quota = state_store.load_quota("okx", "shared-nat")

    assert bucket.refill_per_second == Decimal(5)
    assert quota.ban_until_unix_ns == clock.time_ns() + 1_000
    assert quota.last_reason == "http_418"


@pytest.mark.parametrize(
    "module",
    ["crypto_collector.scheduler", "crypto_collector.network"],
)
def test_network_and_scheduler_public_imports_work_in_fresh_processes(
    module: str,
) -> None:
    project_root = Path(__file__).resolve().parents[3]
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(project_root / "src")

    result = subprocess.run(
        [sys.executable, "-c", f"import {module}"],
        cwd=project_root,
        env=environment,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )

    assert result.returncode == 0, result.stderr
