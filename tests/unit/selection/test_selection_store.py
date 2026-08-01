from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal
from threading import Barrier

import pytest

from crypto_collector.domain.types import Exchange, Market
from crypto_collector.selection import catalog_store as catalog_store_module
from crypto_collector.selection.catalog_store import (
    CatalogRevisionConflictError,
    CatalogStore,
    SelectionStateConflictError,
)
from crypto_collector.selection.models import (
    CompleteCatalogSnapshot,
    CompleteTurnoverSnapshot,
    InstrumentRecord,
    LifecyclePhase,
    SelectionScope,
    SnapshotPage,
    TurnoverMethod,
    TurnoverObservation,
)
from crypto_collector.selection.selector import (
    ResolvedFixedSelection,
    SelectionDelta,
    SelectionPolicy,
    select,
)

SCOPE = SelectionScope(Exchange.BINANCE, Market.SPOT)


def _record(key: str) -> InstrumentRecord:
    base = key.removesuffix("USDT")
    return InstrumentRecord(
        exchange=SCOPE.exchange,
        market=SCOPE.market,
        instrument_key=key,
        canonical_pair=f"{base}/USDT",
        wire_symbols={"rest": key},
        base_asset=base,
        quote_asset="USDT",
        settlement_asset=None,
        status="trading",
        lifecycle_phase=LifecyclePhase.TRADABLE,
        tradable=True,
        lifecycle={"native": "trading"},
        tradable_at_ns=None,
        tradable_at_source=None,
        turnover=None,
        raw_catalog_reference=f"raw/catalog/{key}",
    )


def _catalog(observed_at_ns: int, *keys: str) -> CompleteCatalogSnapshot:
    records = tuple(_record(key) for key in keys)
    return CompleteCatalogSnapshot(
        scope=SCOPE,
        observed_at_ns=observed_at_ns,
        snapshot_id=f"catalog-{observed_at_ns}",
        pages=(SnapshotPage(f"raw/catalog-{observed_at_ns}", None, None),),
        reported_total_count=len(records),
        authoritative_empty=False,
        instruments=records,
    )


def _turnover(
    *,
    catalog_revision: int,
    observed_at_ns: int,
    values: dict[str, str],
) -> CompleteTurnoverSnapshot:
    observations = tuple(
        TurnoverObservation(
            instrument_key=key,
            value=Decimal(value),
            method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
            currency="USDT",
            raw_reference=f"raw/turnover/{key}/{observed_at_ns}",
        )
        for key, value in sorted(values.items())
    )
    return CompleteTurnoverSnapshot(
        scope=SCOPE,
        catalog_revision=catalog_revision,
        observed_at_ns=observed_at_ns,
        snapshot_id=f"turnover-{observed_at_ns}",
        pages=(SnapshotPage(f"raw/turnover-{observed_at_ns}", None, None),),
        reported_total_count=len(observations),
        covered_instrument_keys=tuple(sorted(values)),
        observations=observations,
    )


def _policy(
    *,
    top_n: int = 1,
    exit_grace_ns: int = 30,
    new_listing_capture_duration_ns: int = 1_000,
) -> SelectionPolicy:
    return SelectionPolicy(
        scope=SCOPE,
        quote_assets=("USDT",),
        top_n=top_n,
        turnover_max_age_ns=1_000,
        new_listings_enabled=True,
        new_listing_capture_duration_ns=new_listing_capture_duration_ns,
        exit_grace_ns=exit_grace_ns,
    )


def _select(store: CatalogStore, policy: SelectionPolicy, *, previous=None, now=120):
    view = store.load_view(SCOPE)
    return select(
        view,
        fixed=ResolvedFixedSelection(
            scope=SCOPE,
            catalog_revision=view.catalog_revision,
            instrument_keys=frozenset(),
        ),
        policy=policy,
        previous=previous,
        now_ns=now,
    )


def _ack_all(store: CatalogStore) -> None:
    for change in store.pending_changes(SCOPE):
        assert store.ack_change(change.event_id)


def test_selection_state_round_trips_across_restart(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    policy = _policy()
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(catalog_revision=1, observed_at_ns=110, values={"BTCUSDT": "10"})
        )
        result = _select(store, policy)
        persisted = store.commit_selection(
            result,
            expected_catalog_revision=1,
            expected_turnover_revision=1,
            expected_state_revision=None,
        )
    with CatalogStore.open(path) as reopened:
        loaded = reopened.load_selection_state(SCOPE, policy.policy_id)

    assert persisted.revision == 1
    assert loaded is not None
    assert loaded.revision == persisted.revision
    assert loaded.selected == persisted.selected
    assert loaded.entry("BTCUSDT").reasons == persisted.entry("BTCUSDT").reasons
    assert loaded.entry("BTCUSDT").top_n_rank == 1


def test_selection_commit_is_compare_and_swap_and_failure_is_zero_write(
    tmp_path,
) -> None:
    policy = _policy()
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(catalog_revision=1, observed_at_ns=110, values={"BTCUSDT": "10"})
        )
        _ack_all(store)
        result = _select(store, policy)
        first = store.commit_selection(
            result,
            expected_catalog_revision=1,
            expected_turnover_revision=1,
            expected_state_revision=None,
        )
        pending_before = store.pending_changes(SCOPE)
        with pytest.raises(SelectionStateConflictError, match="state revision"):
            store.commit_selection(
                result,
                expected_catalog_revision=1,
                expected_turnover_revision=1,
                expected_state_revision=None,
            )
        with pytest.raises(CatalogRevisionConflictError, match="catalog revision"):
            store.commit_selection(
                result,
                expected_catalog_revision=2,
                expected_turnover_revision=1,
                expected_state_revision=first.revision,
            )

        assert store.load_selection_state(SCOPE, policy.policy_id) == first
        assert store.pending_changes(SCOPE) == pending_before


def test_selection_commit_rejects_entry_not_from_current_catalog(tmp_path) -> None:
    policy = _policy()
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(
                catalog_revision=1,
                observed_at_ns=110,
                values={"BTCUSDT": "10"},
            )
        )
        _ack_all(store)
        result = _select(store, policy)
        forged_entry = replace(
            result.entry("BTCUSDT"),
            instrument=replace(
                result.entry("BTCUSDT").instrument,
                last_seen_ns=101,
            ),
        )
        forged_state = replace(
            result.next_state,
            entries={"BTCUSDT": forged_entry},
        )
        forged = replace(
            result,
            entries={"BTCUSDT": forged_entry},
            next_state=forged_state,
            deltas=(
                SelectionDelta(
                    instrument_key="BTCUSDT",
                    previous=None,
                    current=forged_entry,
                ),
            ),
        )

        with pytest.raises(SelectionStateConflictError, match="current catalog"):
            store.commit_selection(
                forged,
                expected_catalog_revision=1,
                expected_turnover_revision=1,
                expected_state_revision=None,
            )

        assert store.load_selection_state(SCOPE, policy.policy_id) is None
        assert store.pending_changes(SCOPE) == ()


def test_selection_commit_rejects_noop_delta(tmp_path) -> None:
    policy = _policy()
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(
                catalog_revision=1,
                observed_at_ns=110,
                values={"BTCUSDT": "10"},
            )
        )
        _ack_all(store)
        first = store.commit_selection(
            _select(store, policy),
            expected_catalog_revision=1,
            expected_turnover_revision=1,
            expected_state_revision=None,
        )
        _ack_all(store)
        unchanged = _select(store, policy, previous=first)
        entry = unchanged.entry("BTCUSDT")
        forged = replace(
            unchanged,
            deltas=(
                SelectionDelta(
                    instrument_key="BTCUSDT",
                    previous=entry,
                    current=entry,
                ),
            ),
        )

        with pytest.raises(SelectionStateConflictError, match="deltas"):
            store.commit_selection(
                forged,
                expected_catalog_revision=1,
                expected_turnover_revision=1,
                expected_state_revision=first.revision,
            )

        assert store.load_selection_state(SCOPE, policy.policy_id) == first
        assert store.pending_changes(SCOPE) == ()


def test_selection_change_outbox_contains_full_immutable_delta(tmp_path) -> None:
    policy = _policy()
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(catalog_revision=1, observed_at_ns=110, values={"BTCUSDT": "10"})
        )
        _ack_all(store)
        result = _select(store, policy)
        store.commit_selection(
            result,
            expected_catalog_revision=1,
            expected_turnover_revision=1,
            expected_state_revision=None,
        )
        pending = store.pending_changes(SCOPE)

    assert [change.kind for change in pending] == ["selection_added"]
    assert pending[0].payload["previous"] is None
    assert pending[0].payload["current"] is not None
    with pytest.raises(TypeError):
        pending[0].payload["current"] = None  # type: ignore[index]


def test_two_open_handles_linearize_selection_compare_and_swap(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    policy = _policy()
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(catalog_revision=1, observed_at_ns=110, values={"BTCUSDT": "10"})
        )
        _ack_all(store)

    ready = Barrier(2)

    def commit_once() -> str:
        with CatalogStore.open(path) as store:
            result = _select(store, policy)
            ready.wait()
            try:
                store.commit_selection(
                    result,
                    expected_catalog_revision=1,
                    expected_turnover_revision=1,
                    expected_state_revision=None,
                )
            except SelectionStateConflictError:
                return "conflict"
            return "committed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = tuple(executor.map(lambda _: commit_once(), range(2)))

    assert sorted(outcomes) == ["committed", "conflict"]
    with CatalogStore.open(path) as reopened:
        state = reopened.load_selection_state(SCOPE, policy.policy_id)
        pending = reopened.pending_changes(SCOPE)
    assert state is not None
    assert state.revision == 1
    assert [item.kind for item in pending] == ["selection_added"]


def test_selection_state_and_outbox_rollback_on_midstream_failure(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "catalog.sqlite"
    policy = _policy(top_n=2)
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT", "ETHUSDT"))
        store.apply_turnover_snapshot(
            _turnover(
                catalog_revision=1,
                observed_at_ns=110,
                values={"BTCUSDT": "10", "ETHUSDT": "9"},
            )
        )
        _ack_all(store)
        result = _select(store, policy)
        calls = 0
        real_event_id = catalog_store_module._selection_event_id

        def fail_second_event(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("injected selection outbox failure")
            return real_event_id(*args, **kwargs)

        monkeypatch.setattr(
            catalog_store_module,
            "_selection_event_id",
            fail_second_event,
        )
        with pytest.raises(RuntimeError, match="selection outbox failure"):
            store.commit_selection(
                result,
                expected_catalog_revision=1,
                expected_turnover_revision=1,
                expected_state_revision=None,
            )

        assert store.load_selection_state(SCOPE, policy.policy_id) is None
        assert store.pending_changes(SCOPE) == ()

    with CatalogStore.open(path) as reopened:
        assert reopened.load_selection_state(SCOPE, policy.policy_id) is None
        assert reopened.pending_changes(SCOPE) == ()


def test_top_exit_deadline_survives_selection_store_restart(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    policy = _policy(top_n=1, exit_grace_ns=30)
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(_catalog(100, "ALTUSDT", "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(
                catalog_revision=1,
                observed_at_ns=110,
                values={"ALTUSDT": "20", "BTCUSDT": "10"},
            )
        )
        first_result = _select(store, policy, now=120)
        first = store.commit_selection(
            first_result,
            expected_catalog_revision=1,
            expected_turnover_revision=1,
            expected_state_revision=None,
        )
        store.apply_turnover_snapshot(
            _turnover(
                catalog_revision=1,
                observed_at_ns=130,
                values={"ALTUSDT": "10", "BTCUSDT": "20"},
            )
        )
        exited_result = _select(store, policy, previous=first, now=130)
        exited = store.commit_selection(
            exited_result,
            expected_catalog_revision=1,
            expected_turnover_revision=2,
            expected_state_revision=first.revision,
        )
        assert exited.entry("ALTUSDT").top_exit_started_at_ns == 130
    with CatalogStore.open(path) as reopened:
        previous = reopened.load_selection_state(SCOPE, policy.policy_id)
        assert previous is not None
        before_expiry = _select(reopened, policy, previous=previous, now=159)
        at_expiry = _select(reopened, policy, previous=previous, now=160)

    assert "ALTUSDT" in before_expiry.selected
    assert "ALTUSDT" not in at_expiry.selected


def test_selection_checkpoint_preserves_full_previous_instrument(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    policy = _policy()
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(
                catalog_revision=1,
                observed_at_ns=110,
                values={"BTCUSDT": "10"},
            )
        )
        committed = store.commit_selection(
            _select(store, policy, now=110),
            expected_catalog_revision=1,
            expected_turnover_revision=1,
            expected_state_revision=None,
        )
        assert committed.entry("BTCUSDT").instrument.last_seen_ns == 100
        store.apply_catalog_snapshot(_catalog(120, "BTCUSDT"))
        assert store.load_view(SCOPE).instruments[0].last_seen_ns == 120

    with CatalogStore.open(path) as reopened:
        previous = reopened.load_selection_state(SCOPE, policy.policy_id)

    assert previous is not None
    assert previous.entry("BTCUSDT").instrument.last_seen_ns == 100


def test_relisting_generation_does_not_inherit_persisted_top_grace(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    policy = _policy(
        top_n=1,
        exit_grace_ns=30,
        new_listing_capture_duration_ns=1,
    )
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(_catalog(100, "BTCUSDT"))
        store.apply_catalog_snapshot(_catalog(110, "ALTUSDT", "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(
                catalog_revision=2,
                observed_at_ns=120,
                values={"ALTUSDT": "20", "BTCUSDT": "10"},
            )
        )
        first = store.commit_selection(
            _select(store, policy, now=120),
            expected_catalog_revision=2,
            expected_turnover_revision=1,
            expected_state_revision=None,
        )
        assert first.entry("ALTUSDT").instrument.listing_generation == 1

        delisted = _record("ALTUSDT")
        object.__setattr__(delisted, "lifecycle_phase", LifecyclePhase.DELISTED)
        object.__setattr__(delisted, "tradable", False)
        store.apply_catalog_snapshot(
            CompleteCatalogSnapshot(
                scope=SCOPE,
                observed_at_ns=130,
                snapshot_id="catalog-130",
                pages=(SnapshotPage("raw/catalog-130", None, None),),
                reported_total_count=2,
                authoritative_empty=False,
                instruments=(delisted, _record("BTCUSDT")),
            )
        )
        store.apply_catalog_snapshot(_catalog(140, "ALTUSDT", "BTCUSDT"))
        store.apply_turnover_snapshot(
            _turnover(
                catalog_revision=4,
                observed_at_ns=150,
                values={"ALTUSDT": "10", "BTCUSDT": "20"},
            )
        )
    with CatalogStore.open(path) as reopened:
        previous = reopened.load_selection_state(SCOPE, policy.policy_id)
        assert previous is not None
        assert previous.entry("ALTUSDT").instrument.listing_generation == 1
        result = _select(reopened, policy, previous=previous, now=150)

    assert "ALTUSDT" not in result.selected
