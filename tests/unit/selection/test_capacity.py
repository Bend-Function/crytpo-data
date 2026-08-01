from __future__ import annotations

from dataclasses import replace

import pytest

from crypto_collector.config.models import EgressConfig
from crypto_collector.scheduler.rest import CapacityError
from crypto_collector.selection.capacity import (
    CapacityCandidate,
    CapacityPolicy,
    ScopedCapacityDemand,
    ScopedCapacityError,
    admit,
    admit_exchange_capacity,
    calculate_egress_capacity,
)
from crypto_collector.selection.models import CatalogScope
from crypto_collector.selection.selector import AdmissionPriority

SHA256 = "a" * 64


def fixed(key: str) -> CapacityCandidate:
    return CapacityCandidate(key, AdmissionPriority.FIXED, first_seen_ns=1)


def top(key: str, rank: int) -> CapacityCandidate:
    return CapacityCandidate(
        key,
        AdmissionPriority.TOP_N,
        top_n_rank=rank,
        first_seen_ns=1,
    )


def new(key: str, first_seen_ns: int) -> CapacityCandidate:
    return CapacityCandidate(
        key,
        AdmissionPriority.NEW_LISTING,
        first_seen_ns=first_seen_ns,
    )


def egress(
    identifier: str,
    *,
    quota_group: str | None = None,
    http: int = 2,
    ws: int = 1,
) -> EgressConfig:
    return EgressConfig.model_validate(
        {
            "id": identifier,
            "type": "direct",
            "quota_group": quota_group or identifier,
            "max_http_concurrency": http,
            "max_ws_connections": ws,
        }
    )


def test_capacity_trims_lowest_top_then_latest_new_but_never_fixed() -> None:
    result = admit(
        candidates=(
            fixed("BTC"),
            top("ETH", rank=1),
            top("ALT", rank=20),
            new("NEW1", first_seen_ns=10),
            new("NEW2", first_seen_ns=20),
        ),
        slots=3,
        policy="degrade_low_priority_with_warning",
        config_sha256=SHA256,
    )

    assert result.admitted == ("BTC", "NEW1", "NEW2")
    assert result.rejected == ("ALT", "ETH")
    assert result.warning is not None
    assert result.warning.required_slots == 5
    assert result.warning.available_slots == 3
    assert result.warning.rejected == ("ALT", "ETH")
    assert result.warning.config_sha256 == SHA256


def test_capacity_removes_latest_new_after_all_top_candidates() -> None:
    result = admit(
        (
            new("NEW2", 20),
            top("ETH", 1),
            fixed("BTC"),
            new("NEW1", 10),
            top("ALT", 20),
        ),
        slots=2,
        policy="degrade_low_priority_with_warning",
        config_sha256=SHA256,
    )

    assert result.admitted == ("BTC", "NEW1")
    assert result.rejected == ("ALT", "ETH", "NEW2")


def test_admission_is_independent_of_candidate_input_order() -> None:
    candidates = (
        fixed("BTC"),
        top("ETH", 1),
        top("ALT", 20),
        new("NEW1", 10),
    )

    assert (
        admit(candidates, slots=2, config_sha256=SHA256).admitted
        == admit(tuple(reversed(candidates)), slots=2, config_sha256=SHA256).admitted
    )


def test_fixed_pairs_over_capacity_always_fail() -> None:
    with pytest.raises(CapacityError, match="fixed pairs"):
        admit(
            (fixed("BTC"), fixed("ETH")),
            slots=1,
            policy="degrade_low_priority_with_warning",
            config_sha256=SHA256,
        )


def test_fail_policy_rejects_any_shortfall() -> None:
    with pytest.raises(CapacityError, match="capacity shortfall"):
        admit(
            (fixed("BTC"), top("ETH", 1)),
            slots=1,
            policy="fail",
            config_sha256=SHA256,
        )


def test_exact_capacity_has_no_warning_or_rejections() -> None:
    result = admit((top("ETH", 1), fixed("BTC")), slots=2, config_sha256=SHA256)

    assert result.admitted == ("BTC", "ETH")
    assert result.rejected == ()
    assert result.warning is None


def test_egress_capacity_does_not_merge_unusable_connection_remainders() -> None:
    capacity = calculate_egress_capacity(
        exchange="binance",
        egresses=(
            egress("direct", quota_group="nat", http=4, ws=1),
            egress("proxy", quota_group="nat", http=2, ws=2),
        ),
        reachable_egress_ids=frozenset({"direct", "proxy"}),
        subscriptions_per_connection=5,
        subscriptions_per_instrument=2,
    )

    assert capacity.healthy_egress_ids == ("direct", "proxy")
    assert capacity.quota_groups == ("nat",)
    assert capacity.ws_connections == 3
    assert capacity.ws_subscription_slots == 15
    assert capacity.instrument_slots == 6
    assert capacity.http_concurrency == 6


def test_unreachable_egress_contributes_no_transport_capacity() -> None:
    capacity = calculate_egress_capacity(
        exchange="okx",
        egresses=(egress("direct", ws=2), egress("proxy", ws=3)),
        reachable_egress_ids=frozenset({"proxy"}),
        subscriptions_per_connection=4,
        subscriptions_per_instrument=1,
    )

    assert capacity.healthy_egress_ids == ("proxy",)
    assert capacity.instrument_slots == 12


def test_capacity_rejects_unknown_reachability_and_invalid_candidates() -> None:
    with pytest.raises(ValueError, match="unknown reachable egress"):
        calculate_egress_capacity(
            exchange="okx",
            egresses=(egress("direct"),),
            reachable_egress_ids=frozenset({"missing"}),
            subscriptions_per_connection=4,
            subscriptions_per_instrument=1,
        )
    with pytest.raises(ValueError, match="unique"):
        admit((fixed("BTC"), fixed("BTC")), slots=2, config_sha256=SHA256)
    with pytest.raises(ValueError, match="top_n_rank"):
        replace(top("BTC", 1), top_n_rank=None)
    with pytest.raises((TypeError, ValueError)):
        admit(
            (fixed("BTC"),),
            slots=True,
            config_sha256=SHA256,  # type: ignore[arg-type]
        )


def demand(
    market: str,
    candidates: tuple[CapacityCandidate, ...],
    *,
    per_connection: int = 1,
    policy: CapacityPolicy = "degrade_low_priority_with_warning",
) -> ScopedCapacityDemand:
    return ScopedCapacityDemand(
        scope=CatalogScope("okx", market),
        candidates=candidates,
        instruments_per_connection=per_connection,
        policies={item.instrument_key: policy for item in candidates},
    )


def test_exchange_capacity_is_reserved_once_across_market_scopes() -> None:
    spot = demand("spot", (top("BTC", 1),))
    perpetual = demand("perpetual", (top("BTC", 1),))

    result = admit_exchange_capacity(
        (spot, perpetual),
        ws_connections=1,
        config_sha256=SHA256,
    )

    assert result.connections_available == 1
    assert result.connections_used == 1
    assert sum(result.connections_by_scope.values()) == 1
    assert sum(len(item.admitted) for item in result.admissions.values()) == 1
    assert {item.scope for item in (spot, perpetual)} == set(result.admissions)


def test_exchange_capacity_keeps_connection_chunks_intact() -> None:
    spot = demand("spot", (top("BTC", 1), top("ETH", 2)), per_connection=2)
    perpetual = demand("perpetual", (top("BTC", 1), top("ETH", 2)), per_connection=2)

    result = admit_exchange_capacity(
        (perpetual, spot),
        ws_connections=1,
        config_sha256=SHA256,
    )

    assert sorted(len(item.admitted) for item in result.admissions.values()) == [0, 2]
    assert sorted(len(item.rejected) for item in result.admissions.values()) == [0, 2]


def test_fixed_pairs_across_markets_must_fit_physical_connections() -> None:
    with pytest.raises(ScopedCapacityError, match="fixed pairs") as caught:
        admit_exchange_capacity(
            (
                demand("spot", (fixed("BTC"),)),
                demand("perpetual", (fixed("BTC"),)),
            ),
            ws_connections=1,
            config_sha256=SHA256,
        )

    assert caught.value.scope == CatalogScope("okx", "spot")


def test_scoped_capacity_fail_policy_rejects_its_own_shortfall() -> None:
    with pytest.raises(ScopedCapacityError, match="capacity shortfall") as caught:
        admit_exchange_capacity(
            (
                demand("spot", (top("BTC", 1),), policy="fail"),
                demand("perpetual", (new("NEW", 1),)),
            ),
            ws_connections=1,
            config_sha256=SHA256,
        )

    assert caught.value.scope == CatalogScope("okx", "spot")


def test_admission_requires_config_hash_even_without_a_warning() -> None:
    with pytest.raises(TypeError):
        admit((fixed("BTC"),), slots=1)  # type: ignore[call-arg]
