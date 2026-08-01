from __future__ import annotations

import random
from hashlib import sha256

import pytest

from crypto_collector.network.assignment import (
    NoAvailableEgressError,
    StickyAssignment,
    assign_instruments,
    choose_egress,
    pack_egress_shards,
)
from crypto_collector.network.health import HealthSnapshot
from crypto_collector.network.models import Egress


def egress(egress_id: str, *, max_ws_connections: int = 2) -> Egress:
    return Egress.model_validate(
        {
            "id": egress_id,
            "type": "direct",
            "max_ws_connections": max_ws_connections,
        }
    )


def test_rendezvous_assignment_is_order_independent() -> None:
    key = "binance/spot/BTCUSDT/book_live"
    candidates = [egress("a"), egress("b"), egress("c")]

    first = choose_egress(key, candidates)
    second = choose_egress(key, list(reversed(candidates)))

    assert first.id == second.id


def test_rendezvous_assignment_matches_sha256_golden_mapping() -> None:
    candidates = [egress("direct-a"), egress("proxy-b"), egress("proxy-c")]
    expected = {
        "binance/spot/BTCUSDT/book_live": "proxy-b",
        "okx/perpetual/BTC-USDT-SWAP/books": "proxy-c",
        "kraken/spot/BTC/USDT/trade": "proxy-b",
        "bybit/perpetual/ETHUSDT/ticker": "proxy-c",
    }

    assert {key: choose_egress(key, candidates).id for key in expected} == expected
    assert (
        sha256(b"binance/spot/BTCUSDT/book_live\0proxy-b").hexdigest()
        == "ac0fb322177b80e6d7717eaae543e36bc0e35679b0b9cdc2ba732a8f035b2eed"
    )


def test_assignment_key_preserves_instrument_keys_with_path_separators() -> None:
    candidate = egress("a")

    chosen = choose_egress("kraken/spot/BTC/USDT/trade", [candidate])
    assignment = StickyAssignment.create(
        "kraken/spot/BTC/USDT/trade", chosen, generation=3
    )

    assert assignment.key == "kraken/spot/BTC/USDT/trade"
    assert assignment.instrument_key == "BTC/USDT"
    assert assignment.channel == "trade"

    assigned = assign_instruments(
        ["BTC/USDT"],
        exchange="kraken",
        market="spot",
        channel="trade",
        egresses=[candidate],
        subscriptions_per_connection=1,
    )
    assert assigned == (assignment.__class__.create(assignment.key, candidate),)


def test_unhealthy_egress_is_skipped_only_for_new_generation() -> None:
    key = "okx/spot/BTC-USDT/books"
    candidates = [egress("a"), egress("b")]
    first = choose_egress(key, candidates)
    health = HealthSnapshot(
        unavailable=frozenset({("okx", first.id)}),
        probe_eligible=frozenset(),
    )

    second = choose_egress(key, candidates, health=health)

    assert first.id != second.id
    assert first.id in {"a", "b"}


def test_sticky_assignment_is_an_immutable_generation_record() -> None:
    assignment = StickyAssignment.create(
        "okx/spot/BTC-USDT/books", egress("a"), generation=7
    )

    assert assignment.egress_id == "a"
    assert assignment.generation == 7
    with pytest.raises((AttributeError, TypeError)):
        assignment.egress_id = "b"  # type: ignore[misc]


def test_sticky_assignment_rejects_boolean_generation() -> None:
    with pytest.raises(ValueError, match="generation"):
        StickyAssignment.create("okx/spot/BTC-USDT/books", egress("a"), generation=True)


def test_no_healthy_egress_is_explicit() -> None:
    key = "okx/spot/BTC-USDT/books"
    candidates = [egress("a"), egress("b")]
    health = HealthSnapshot(
        unavailable=frozenset({("okx", "a"), ("okx", "b")}),
        probe_eligible=frozenset(),
    )

    with pytest.raises(NoAvailableEgressError, match="okx"):
        choose_egress(key, candidates, health=health)


def test_duplicate_egress_ids_are_rejected() -> None:
    with pytest.raises(ValueError, match="duplicate egress id"):
        choose_egress(
            "okx/spot/BTC-USDT/books",
            [egress("same"), egress("same")],
        )


def test_assignment_precedes_deterministic_egress_local_sharding() -> None:
    instruments = ["BTCUSDT", "ETHUSDT", "SOLUSDT", "XRPUSDT", "ADAUSDT"]
    candidates = [
        egress("a", max_ws_connections=2),
        egress("b", max_ws_connections=2),
    ]

    assignments = assign_instruments(
        instruments,
        exchange="binance",
        market="spot",
        channel="trade",
        egresses=candidates,
        subscriptions_per_connection=2,
    )
    shuffled = list(instruments)
    random.Random(42).shuffle(shuffled)
    reordered = assign_instruments(
        shuffled,
        exchange="binance",
        market="spot",
        channel="trade",
        egresses=list(reversed(candidates)),
        subscriptions_per_connection=2,
    )
    shards = pack_egress_shards(
        assignments,
        egresses=candidates,
        subscriptions_per_connection=2,
    )

    assert assignments == reordered
    assert sum(len(shard.assignments) for shard in shards) == len(instruments)
    assert all(len(shard.instrument_keys) <= 2 for shard in shards)
    assert all(
        len({item.egress_id for item in shard.assignments}) == 1 for shard in shards
    )
    assert all(
        shard.assignments == tuple(sorted(shard.assignments, key=lambda item: item.key))
        for shard in shards
    )


def test_assignment_rejects_demand_above_total_healthy_capacity() -> None:
    candidates = [egress("a", max_ws_connections=1)]

    with pytest.raises(NoAvailableEgressError, match="capacity"):
        assign_instruments(
            ["BTCUSDT", "ETHUSDT", "SOLUSDT"],
            exchange="binance",
            market="spot",
            channel="trade",
            egresses=candidates,
            subscriptions_per_connection=2,
        )


def test_assignment_uses_next_ranked_egress_when_first_choice_is_full() -> None:
    candidates = [
        egress("a", max_ws_connections=1),
        egress("b", max_ws_connections=1),
    ]
    assert choose_egress("binance/spot/B/trade", candidates).id == "b"
    assert choose_egress("binance/spot/C/trade", candidates).id == "b"

    assignments = assign_instruments(
        ["C", "B"],
        exchange="binance",
        market="spot",
        channel="trade",
        egresses=candidates,
        subscriptions_per_connection=1,
    )

    assert tuple((item.instrument_key, item.egress_id) for item in assignments) == (
        ("B", "b"),
        ("C", "a"),
    )


def test_assignment_rejects_duplicate_instrument_keys() -> None:
    with pytest.raises(ValueError, match="instrument keys must be unique"):
        assign_instruments(
            ["BTCUSDT", "BTCUSDT"],
            exchange="binance",
            market="spot",
            channel="trade",
            egresses=[egress("a")],
            subscriptions_per_connection=2,
        )


def test_assignment_rejects_boolean_subscription_capacity() -> None:
    with pytest.raises(ValueError, match="subscriptions_per_connection"):
        assign_instruments(
            ["BTCUSDT"],
            exchange="binance",
            market="spot",
            channel="trade",
            egresses=[egress("a")],
            subscriptions_per_connection=True,
        )


def test_sharding_rejects_boolean_subscription_capacity() -> None:
    with pytest.raises(ValueError, match="subscriptions_per_connection"):
        pack_egress_shards(
            [],
            egresses=[egress("a")],
            subscriptions_per_connection=True,
        )


def test_sharding_rejects_mixed_connection_generations() -> None:
    candidate = egress("a")
    assignments = [
        StickyAssignment.create(
            f"okx/spot/{instrument}/books", candidate, generation=generation
        )
        for instrument, generation in (("BTC-USDT", 1), ("ETH-USDT", 2))
    ]

    with pytest.raises(ValueError, match="one assignment cohort"):
        pack_egress_shards(
            assignments,
            egresses=[candidate],
            subscriptions_per_connection=2,
        )


def test_sharding_rejects_assignment_from_old_egress_quota_group() -> None:
    old = Egress.model_validate({"id": "a", "type": "direct", "quota_group": "old-nat"})
    current = Egress.model_validate(
        {"id": "a", "type": "direct", "quota_group": "new-nat"}
    )
    assignment = StickyAssignment.create("okx/spot/BTC-USDT/books", old, generation=1)

    with pytest.raises(ValueError, match="quota group"):
        pack_egress_shards(
            [assignment],
            egresses=[current],
            subscriptions_per_connection=2,
        )


def test_sharding_rejects_manual_assignments_above_connection_capacity() -> None:
    candidate = egress("a", max_ws_connections=1)
    assignments = [
        StickyAssignment.create(f"okx/spot/{instrument}/books", candidate)
        for instrument in ("BTC-USDT", "ETH-USDT", "SOL-USDT")
    ]

    with pytest.raises(NoAvailableEgressError, match="shard capacity"):
        pack_egress_shards(
            assignments,
            egresses=[candidate],
            subscriptions_per_connection=2,
        )


@pytest.mark.parametrize(
    "key",
    ["", "okx", "okx/spot/BTC-USDT", "okx//BTC-USDT/books", "/spot/BTC/books"],
)
def test_assignment_key_requires_four_nonempty_components(key: str) -> None:
    with pytest.raises(ValueError, match="assignment key"):
        choose_egress(key, [egress("a")])


@pytest.mark.parametrize(
    ("component", "value"),
    [("exchange", "ok/x"), ("market", "sp/ot"), ("channel", "bo/oks")],
)
def test_empty_assignment_cohort_still_rejects_component_slashes(
    component: str, value: str
) -> None:
    parts = {"exchange": "okx", "market": "spot", "channel": "books"}
    parts[component] = value

    with pytest.raises(ValueError, match="assignment key components"):
        assign_instruments(
            [],
            exchange=parts["exchange"],
            market=parts["market"],
            channel=parts["channel"],
            egresses=[egress("a")],
            subscriptions_per_connection=1,
        )
