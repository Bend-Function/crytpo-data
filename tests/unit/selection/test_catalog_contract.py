from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from decimal import Decimal

import pytest

from crypto_collector.domain.types import Exchange, Market
from crypto_collector.selection import catalog_store as catalog_store_module
from crypto_collector.selection.catalog_store import (
    CatalogRevisionConflictError,
    CatalogSnapshotConflictError,
    CatalogStore,
    StaleCatalogSnapshotError,
    StaleTurnoverSnapshotError,
    TurnoverSnapshotConflictError,
)
from crypto_collector.selection.models import (
    AnnouncementHint,
    CatalogSnapshot,
    CatalogView,
    CompleteCatalogSnapshot,
    CompleteTurnoverSnapshot,
    InstrumentRecord,
    LifecyclePhase,
    SelectionScope,
    SnapshotPage,
    TradableAtSource,
    TurnoverMethod,
    TurnoverObservation,
)

SCOPE = SelectionScope(Exchange.BINANCE, Market.SPOT)


def instrument(
    key: str,
    *,
    phase: LifecyclePhase = LifecyclePhase.TRADABLE,
    tradable_at_ns: int | None = None,
    tradable_at_source: TradableAtSource | None = None,
) -> InstrumentRecord:
    base = key.removesuffix("USDT")
    return InstrumentRecord(
        exchange=SCOPE.exchange,
        market=SCOPE.market,
        instrument_key=key,
        canonical_pair=f"{base}/USDT",
        wire_symbols={"rest": key, "websocket": key.lower()},
        base_asset=base,
        quote_asset="USDT",
        settlement_asset=None,
        status=phase.value,
        lifecycle_phase=phase,
        tradable=phase is LifecyclePhase.TRADABLE,
        lifecycle={"native_status": phase.value},
        tradable_at_ns=tradable_at_ns,
        tradable_at_source=tradable_at_source,
        turnover=None,
        raw_catalog_reference=f"raw/catalog/{key}",
    )


def catalog_snapshot(
    observed_at_ns: int,
    *records: InstrumentRecord,
    authoritative_empty: bool = False,
    snapshot_id: str | None = None,
) -> CompleteCatalogSnapshot:
    identity = snapshot_id or f"catalog-{observed_at_ns}"
    return CompleteCatalogSnapshot(
        scope=SCOPE,
        observed_at_ns=observed_at_ns,
        snapshot_id=identity,
        pages=(SnapshotPage(f"raw/{identity}/page-1", None, None),),
        reported_total_count=len(records),
        authoritative_empty=authoritative_empty,
        instruments=tuple(records),
    )


def turnover_snapshot(
    observed_at_ns: int,
    *observations: TurnoverObservation,
    snapshot_id: str | None = None,
    covered_instrument_keys: tuple[str, ...] | None = None,
    catalog_revision: int = 1,
    authoritative_empty: bool = False,
) -> CompleteTurnoverSnapshot:
    identity = snapshot_id or f"turnover-{observed_at_ns}"
    coverage = (
        tuple(item.instrument_key for item in observations)
        if covered_instrument_keys is None
        else covered_instrument_keys
    )
    return CompleteTurnoverSnapshot(
        scope=SCOPE,
        catalog_revision=catalog_revision,
        observed_at_ns=observed_at_ns,
        snapshot_id=identity,
        pages=(SnapshotPage(f"raw/{identity}/page-1", None, None),),
        reported_total_count=len(coverage),
        authoritative_empty=authoritative_empty,
        covered_instrument_keys=coverage,
        observations=tuple(observations),
    )


def turnover(key: str, value: str) -> TurnoverObservation:
    return TurnoverObservation(
        instrument_key=key,
        value=Decimal(value),
        method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
        currency="USDT",
        raw_reference=f"raw/ticker/{key}",
    )


def by_key(view, key: str):
    return next(item for item in view.instruments if item.instrument_key == key)


def test_complete_snapshot_rejects_unproven_empty_or_incomplete_pages() -> None:
    with pytest.raises(ValueError, match="authoritative_empty"):
        catalog_snapshot(100)
    with pytest.raises(ValueError, match="terminal cursor"):
        CompleteCatalogSnapshot(
            scope=SCOPE,
            observed_at_ns=100,
            snapshot_id="partial",
            pages=(SnapshotPage("raw/page-1", None, "page-2"),),
            reported_total_count=1,
            authoritative_empty=False,
            instruments=(instrument("BTCUSDT"),),
        )


def test_complete_snapshot_carries_a_contiguous_terminal_page_chain() -> None:
    snapshot = CompleteCatalogSnapshot(
        scope=SCOPE,
        observed_at_ns=100,
        snapshot_id="complete-two-page",
        pages=(
            SnapshotPage("raw/page-1", None, "cursor-2"),
            SnapshotPage("raw/page-2", "cursor-2", None),
        ),
        reported_total_count=1,
        authoritative_empty=False,
        instruments=(instrument("BTCUSDT"),),
    )

    assert snapshot.page_count == 2
    assert snapshot.page_raw_references == ("raw/page-1", "raw/page-2")
    with pytest.raises(ValueError, match="reported_total_count"):
        CompleteCatalogSnapshot(
            scope=SCOPE,
            observed_at_ns=100,
            snapshot_id="truncated",
            pages=(SnapshotPage("raw/page-1", None, None),),
            reported_total_count=2,
            authoritative_empty=False,
            instruments=(instrument("BTCUSDT"),),
        )


def test_turnover_reported_count_tracks_coverage_not_observation_count() -> None:
    snapshot = CompleteTurnoverSnapshot(
        scope=SCOPE,
        catalog_revision=1,
        observed_at_ns=100,
        snapshot_id="turnover-100",
        pages=(SnapshotPage("raw/turnover-100/page-1", None, None),),
        reported_total_count=2,
        covered_instrument_keys=("BTCUSDT", "ETHUSDT"),
        observations=(turnover("BTCUSDT", "100"),),
    )

    assert snapshot.reported_total_count == 2
    assert len(snapshot.observations) == 1


def test_first_baseline_fallback_is_suppressed_across_restart(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(100, instrument("BTCUSDT")),
            initial_lookback_ns=1_000,
        )
    with CatalogStore.open(path) as reopened:
        item = by_key(reopened.load_view(SCOPE), "BTCUSDT")

    assert item.first_seen_ns == 100
    assert item.first_tradable_seen_ns == 100
    assert item.new_listing_started_at_ns is None
    assert item.new_listing_eligible is False


def test_preopen_fallback_starts_at_first_catalog_confirmed_tradability(
    tmp_path,
) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(
                100,
                instrument("NEWUSDT", phase=LifecyclePhase.PREOPEN),
            )
        )
        changes = store.apply_catalog_snapshot(
            catalog_snapshot(200, instrument("NEWUSDT"))
        )
    with CatalogStore.open(path) as reopened:
        item = by_key(reopened.load_view(SCOPE), "NEWUSDT")

    assert [event.instrument_key for event in changes.new_listing_episodes] == [
        "NEWUSDT"
    ]
    assert item.first_seen_ns == 100
    assert item.first_tradable_seen_ns == 200
    assert item.new_listing_started_at_ns == 200
    assert item.new_listing_source is TradableAtSource.FIRST_TRADABLE_SEEN
    assert item.listing_generation == 1


def test_catalog_instrument_rejects_invalid_fallback_episode_times(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(
                100,
                instrument("NEWUSDT", phase=LifecyclePhase.PREOPEN),
            )
        )
        store.apply_catalog_snapshot(catalog_snapshot(200, instrument("NEWUSDT")))
        item = by_key(store.load_view(SCOPE), "NEWUSDT")

    with pytest.raises(ValueError, match="first_tradable_seen_ns"):
        replace(item, first_tradable_seen_ns=99)
    with pytest.raises(ValueError, match="FIRST_TRADABLE_SEEN"):
        replace(item, new_listing_started_at_ns=199)

    official = replace(
        item,
        tradable_at_ns=190,
        tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
        new_listing_started_at_ns=190,
        new_listing_source=TradableAtSource.EXCHANGE_LAUNCH,
    )
    with pytest.raises(ValueError, match="first_tradable_seen_ns"):
        replace(official, first_tradable_seen_ns=None)
    with pytest.raises(ValueError, match="episode start"):
        replace(official, new_listing_started_at_ns=201)


def test_sqlite_rejects_invalid_listing_lifecycle_states(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))

    connection = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                UPDATE catalog_instrument
                   SET listing_state = 'pending'
                 WHERE exchange = 'binance' AND market = 'spot'
                   AND instrument_key = 'BTCUSDT'
                """
            )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                UPDATE catalog_instrument
                   SET lifecycle_phase = 'delisted', tradable = 0
                 WHERE exchange = 'binance' AND market = 'spot'
                   AND instrument_key = 'BTCUSDT'
                """
            )
    finally:
        connection.close()


def test_catalog_quote_change_invalidates_inherited_turnover(tmp_path) -> None:
    corrected = replace(
        instrument("BTCUSDT"),
        canonical_pair="BTC/USD",
        quote_asset="USD",
    )
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_turnover_snapshot(turnover_snapshot(110, turnover("BTCUSDT", "42")))

        changes = store.apply_catalog_snapshot(catalog_snapshot(200, corrected))
        item = by_key(store.load_view(SCOPE), "BTCUSDT")

    assert changes.revision == 2
    assert item.quote_asset == "USD"
    assert item.turnover is None


def test_preopen_ignores_stale_official_time_when_tradability_is_confirmed(
    tmp_path,
) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(
                100,
                instrument(
                    "NEWUSDT",
                    phase=LifecyclePhase.PREOPEN,
                    tradable_at_ns=10,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
            ),
            initial_lookback_ns=20,
        )
        store.apply_catalog_snapshot(
            catalog_snapshot(
                200,
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=10,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
            )
        )
        item = by_key(store.load_view(SCOPE), "NEWUSDT")

    assert item.new_listing_started_at_ns == 200
    assert item.new_listing_source is TradableAtSource.FIRST_TRADABLE_SEEN


def test_preopen_preserves_eligible_official_time_until_tradable(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(
                100,
                instrument(
                    "NEWUSDT",
                    phase=LifecyclePhase.PREOPEN,
                    tradable_at_ns=90,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
            ),
            initial_lookback_ns=20,
        )
        store.apply_catalog_snapshot(
            catalog_snapshot(
                120,
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=90,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
            )
        )
        item = by_key(store.load_view(SCOPE), "NEWUSDT")

    assert item.new_listing_started_at_ns == 90
    assert item.new_listing_source is TradableAtSource.EXCHANGE_LAUNCH


def test_initial_pause_resume_does_not_create_new_listing_episode(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(
                100,
                instrument("OLDUSDT", phase=LifecyclePhase.PAUSED),
            )
        )
        changes = store.apply_catalog_snapshot(
            catalog_snapshot(200, instrument("OLDUSDT"))
        )
        resumed = by_key(store.load_view(SCOPE), "OLDUSDT")

    assert changes.new_listing_episodes == ()
    assert resumed.listing_generation == 0
    assert resumed.new_listing_eligible is False


def test_initial_tradable_future_official_time_stays_baseline(tmp_path) -> None:
    record = instrument(
        "OLDUSDT",
        tradable_at_ns=200,
        tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
    )
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(100, record),
            initial_lookback_ns=100,
        )
        changes = store.apply_catalog_snapshot(catalog_snapshot(150, record))
        item = by_key(store.load_view(SCOPE), "OLDUSDT")

    assert changes.new_listing_episodes == ()
    assert item.listing_generation == 0
    assert item.new_listing_eligible is False


def test_recent_official_baseline_time_is_durably_eligible(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(
                1_000,
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=950,
                    tradable_at_source=TradableAtSource.EXCHANGE_CONTINUOUS,
                ),
            ),
            initial_lookback_ns=100,
        )
    with CatalogStore.open(path) as reopened:
        item = by_key(reopened.load_view(SCOPE), "NEWUSDT")

    assert item.new_listing_eligible is True
    assert item.new_listing_started_at_ns == 950
    assert item.new_listing_source is TradableAtSource.EXCHANGE_CONTINUOUS


def test_missing_reappearance_and_pause_resume_do_not_restart_episode(
    tmp_path,
) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_catalog_snapshot(
            catalog_snapshot(200, instrument("BTCUSDT"), instrument("NEWUSDT"))
        )
        started = by_key(store.load_view(SCOPE), "NEWUSDT")
        store.apply_catalog_snapshot(
            catalog_snapshot(
                250,
                instrument("BTCUSDT"),
                instrument("NEWUSDT", phase=LifecyclePhase.PAUSED),
            )
        )
        store.apply_catalog_snapshot(
            catalog_snapshot(260, instrument("BTCUSDT"), instrument("NEWUSDT"))
        )
        resumed = by_key(store.load_view(SCOPE), "NEWUSDT")
        store.apply_catalog_snapshot(catalog_snapshot(300, instrument("BTCUSDT")))
        store.apply_catalog_snapshot(
            catalog_snapshot(310, instrument("BTCUSDT"), instrument("NEWUSDT"))
        )
        reappeared = by_key(store.load_view(SCOPE), "NEWUSDT")

    assert resumed.new_listing_started_at_ns == started.new_listing_started_at_ns
    assert resumed.listing_generation == started.listing_generation
    assert reappeared.new_listing_started_at_ns == started.new_listing_started_at_ns
    assert reappeared.listing_generation == started.listing_generation


def test_explicit_delist_then_relist_creates_new_generation(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_catalog_snapshot(
            catalog_snapshot(200, instrument("BTCUSDT"), instrument("NEWUSDT"))
        )
        first = by_key(store.load_view(SCOPE), "NEWUSDT")
        store.apply_catalog_snapshot(
            catalog_snapshot(
                300,
                instrument("BTCUSDT"),
                instrument("NEWUSDT", phase=LifecyclePhase.DELISTED),
            )
        )
        pending = by_key(store.load_view(SCOPE), "NEWUSDT")
        store.apply_catalog_snapshot(
            catalog_snapshot(
                400,
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=390,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
                instrument("BTCUSDT"),
            )
        )
        relisted = by_key(store.load_view(SCOPE), "NEWUSDT")

    assert pending.listing_state.value == "relist_pending"
    assert pending.new_listing_eligible is False
    assert pending.new_listing_started_at_ns == first.new_listing_started_at_ns
    assert pending.last_terminal_seen_ns == 300
    assert relisted.listing_generation == first.listing_generation + 1
    assert relisted.last_terminal_seen_ns == 300
    assert relisted.new_listing_started_at_ns == 390
    assert relisted.new_listing_source is TradableAtSource.EXCHANGE_LAUNCH


def test_delist_evidence_survives_preopen_before_relisting(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_catalog_snapshot(
            catalog_snapshot(200, instrument("BTCUSDT"), instrument("NEWUSDT"))
        )
        first = by_key(store.load_view(SCOPE), "NEWUSDT")
        store.apply_catalog_snapshot(
            catalog_snapshot(
                300,
                instrument("BTCUSDT"),
                instrument("NEWUSDT", phase=LifecyclePhase.DELISTED),
            )
        )
        store.apply_catalog_snapshot(
            catalog_snapshot(
                350,
                instrument("BTCUSDT"),
                instrument("NEWUSDT", phase=LifecyclePhase.PREOPEN),
            )
        )
        store.apply_catalog_snapshot(
            catalog_snapshot(400, instrument("BTCUSDT"), instrument("NEWUSDT"))
        )
        relisted = by_key(store.load_view(SCOPE), "NEWUSDT")

    assert relisted.listing_generation == first.listing_generation + 1
    assert relisted.last_terminal_seen_ns == 300
    assert relisted.new_listing_started_at_ns == 400
    assert relisted.new_listing_source is TradableAtSource.FIRST_TRADABLE_SEEN


def test_relist_ignores_stale_official_time_from_prior_generation(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_catalog_snapshot(
            catalog_snapshot(
                200,
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=190,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
                instrument("BTCUSDT"),
            )
        )
        first = by_key(store.load_view(SCOPE), "NEWUSDT")
        store.apply_catalog_snapshot(
            catalog_snapshot(
                300,
                instrument("BTCUSDT"),
                instrument("NEWUSDT", phase=LifecyclePhase.DELISTED),
            )
        )
        store.apply_catalog_snapshot(
            catalog_snapshot(
                400,
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=190,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
                instrument("BTCUSDT"),
            )
        )
        relisted = by_key(store.load_view(SCOPE), "NEWUSDT")

    assert relisted.listing_generation == first.listing_generation + 1
    assert relisted.last_terminal_seen_ns == 300
    assert relisted.new_listing_started_at_ns == 400
    assert relisted.new_listing_source is TradableAtSource.FIRST_TRADABLE_SEEN


def test_relist_ignores_official_time_before_terminal_evidence_across_restart(
    tmp_path,
) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_catalog_snapshot(
            catalog_snapshot(
                200,
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=190,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
                instrument("BTCUSDT"),
            )
        )
        first = by_key(store.load_view(SCOPE), "NEWUSDT")
        store.apply_catalog_snapshot(
            catalog_snapshot(
                300,
                instrument("BTCUSDT"),
                instrument("NEWUSDT", phase=LifecyclePhase.DELISTED),
            )
        )

    with CatalogStore.open(path) as reopened:
        reopened.apply_catalog_snapshot(
            catalog_snapshot(
                400,
                instrument("BTCUSDT"),
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=250,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
            )
        )
        relisted = by_key(reopened.load_view(SCOPE), "NEWUSDT")

    assert relisted.listing_generation == first.listing_generation + 1
    assert relisted.last_terminal_seen_ns == 300
    assert relisted.new_listing_started_at_ns == 400
    assert relisted.new_listing_source is TradableAtSource.FIRST_TRADABLE_SEEN


def test_latest_terminal_evidence_is_the_relisting_time_floor(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_catalog_snapshot(
            catalog_snapshot(200, instrument("BTCUSDT"), instrument("NEWUSDT"))
        )
        first = by_key(store.load_view(SCOPE), "NEWUSDT")
        for observed_at in (300, 350):
            store.apply_catalog_snapshot(
                catalog_snapshot(
                    observed_at,
                    instrument("BTCUSDT"),
                    instrument("NEWUSDT", phase=LifecyclePhase.DELISTED),
                )
            )
        store.apply_catalog_snapshot(
            catalog_snapshot(
                400,
                instrument("BTCUSDT"),
                instrument(
                    "NEWUSDT",
                    tradable_at_ns=325,
                    tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
                ),
            )
        )
        relisted = by_key(store.load_view(SCOPE), "NEWUSDT")

    assert relisted.listing_generation == first.listing_generation + 1
    assert relisted.last_terminal_seen_ns == 350
    assert relisted.new_listing_started_at_ns == 400
    assert relisted.new_listing_source is TradableAtSource.FIRST_TRADABLE_SEEN


def test_catalog_high_water_is_linearized_and_revision_bound(tmp_path) -> None:
    snapshot = catalog_snapshot(100, instrument("BTCUSDT"))
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        first = store.apply_catalog_snapshot(snapshot)
        replay = store.apply_catalog_snapshot(snapshot)
        with pytest.raises(CatalogSnapshotConflictError):
            store.apply_catalog_snapshot(
                catalog_snapshot(
                    100,
                    instrument("ETHUSDT"),
                    snapshot_id="same-time-conflict",
                )
            )
        with pytest.raises(StaleCatalogSnapshotError):
            store.apply_catalog_snapshot(catalog_snapshot(99, instrument("BTCUSDT")))
        view = store.load_view(SCOPE)

    assert first.revision == 1
    assert replay.idempotent is True
    assert replay.revision == first.revision
    assert view.catalog_revision == first.revision


def test_same_time_catalog_conflicts_when_pagination_proof_changes(tmp_path) -> None:
    record = instrument("BTCUSDT")
    first = CompleteCatalogSnapshot(
        scope=SCOPE,
        observed_at_ns=100,
        snapshot_id="catalog-100",
        pages=(
            SnapshotPage("raw/page-1", None, "cursor-a"),
            SnapshotPage("raw/page-2", "cursor-a", None),
        ),
        reported_total_count=1,
        authoritative_empty=False,
        instruments=(record,),
    )
    conflicting = replace(
        first,
        pages=(
            SnapshotPage("raw/page-1", None, "cursor-b"),
            SnapshotPage("raw/page-2", "cursor-b", None),
        ),
    )

    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(first)

        with pytest.raises(CatalogSnapshotConflictError):
            store.apply_catalog_snapshot(conflicting)


def test_same_time_turnover_conflicts_when_pagination_proof_changes(tmp_path) -> None:
    first = CompleteTurnoverSnapshot(
        scope=SCOPE,
        catalog_revision=1,
        observed_at_ns=110,
        snapshot_id="turnover-110",
        pages=(
            SnapshotPage("raw/turnover/page-1", None, "cursor-a"),
            SnapshotPage("raw/turnover/page-2", "cursor-a", None),
        ),
        reported_total_count=1,
        covered_instrument_keys=("BTCUSDT",),
        observations=(turnover("BTCUSDT", "100"),),
    )
    conflicting = replace(
        first,
        pages=(
            SnapshotPage("raw/turnover/page-1", None, "cursor-b"),
            SnapshotPage("raw/turnover/page-2", "cursor-b", None),
        ),
    )

    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_turnover_snapshot(first)

        with pytest.raises(TurnoverSnapshotConflictError):
            store.apply_turnover_snapshot(conflicting)


def test_catalog_changes_expose_full_previous_and_current_values(tmp_path) -> None:
    original = instrument("BTCUSDT")
    updated = replace(
        original,
        status="renamed-status",
        lifecycle={"native_status": "renamed-status"},
    )
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, original))
        changes = store.apply_catalog_snapshot(catalog_snapshot(200, updated))

    delta = changes.deltas[0]
    assert delta.kind == "updated"
    assert delta.instrument_key == "BTCUSDT"
    assert delta.previous is not None
    assert delta.previous.status == "tradable"
    assert delta.current is not None
    assert delta.current.status == "renamed-status"


def test_catalog_snapshot_rejects_revision_completeness_contradictions(
    tmp_path,
) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        persisted = store.load_catalog(SCOPE)

    with pytest.raises(ValueError, match="complete"):
        replace(persisted, complete=False)
    with pytest.raises(ValueError, match="instruments"):
        CatalogSnapshot(
            scope=SCOPE,
            observed_at_ns=None,
            revision=0,
            digest_sha256=None,
            complete=False,
            instruments=persisted.instruments,
        )


def test_wire_symbol_mapping_order_does_not_create_a_catalog_update(tmp_path) -> None:
    original = instrument("BTCUSDT")
    reordered = replace(
        original,
        wire_symbols={"websocket": "btcusdt", "rest": "BTCUSDT"},
    )

    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, original))
        changes = store.apply_catalog_snapshot(catalog_snapshot(200, reordered))

    assert changes.updated == ()
    assert changes.deltas == ()


def test_catalog_replay_conflicts_when_initial_lookback_changes(tmp_path) -> None:
    snapshot = catalog_snapshot(
        1_000,
        instrument(
            "NEWUSDT",
            tradable_at_ns=950,
            tradable_at_source=TradableAtSource.EXCHANGE_LAUNCH,
        ),
    )
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(snapshot, initial_lookback_ns=0)

        with pytest.raises(CatalogSnapshotConflictError):
            store.apply_catalog_snapshot(snapshot, initial_lookback_ns=100)


def test_turnover_has_independent_high_water_and_provenance(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(100, instrument("BTCUSDT"), instrument("ETHUSDT"))
        )
        first = store.apply_turnover_snapshot(
            turnover_snapshot(
                110,
                turnover("BTCUSDT", "100.00"),
                covered_instrument_keys=("BTCUSDT", "ETHUSDT"),
            )
        )
        replay = store.apply_turnover_snapshot(
            turnover_snapshot(
                110,
                turnover("BTCUSDT", "100.00"),
                covered_instrument_keys=("BTCUSDT", "ETHUSDT"),
            )
        )
        with pytest.raises(TurnoverSnapshotConflictError):
            store.apply_turnover_snapshot(
                turnover_snapshot(
                    110,
                    turnover("BTCUSDT", "101"),
                    snapshot_id="same-time-conflict",
                )
            )
        with pytest.raises(StaleTurnoverSnapshotError):
            store.apply_turnover_snapshot(
                turnover_snapshot(109, turnover("BTCUSDT", "100"))
            )
        view = store.load_view(SCOPE)
        btc = by_key(view, "BTCUSDT")
        eth = by_key(view, "ETHUSDT")

    assert first.revision == 1
    assert first.catalog_revision == 1
    assert replay.idempotent is True
    assert replay.catalog_revision == 1
    assert view.catalog_revision == 1
    assert view.turnover_revision == 1
    assert view.catalog_snapshot_id == "catalog-100"
    assert view.catalog_page_raw_references == ("raw/catalog-100/page-1",)
    assert view.turnover_snapshot_id == "turnover-110"
    assert view.turnover_page_raw_references == ("raw/turnover-110/page-1",)
    assert view.turnover_covered_instrument_keys == ("BTCUSDT", "ETHUSDT")
    assert btc.turnover.value == Decimal("100.00")
    assert btc.turnover.observed_at_ns == 110
    assert eth.turnover is None


def test_turnover_cannot_predate_its_bound_catalog_revision(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))

        with pytest.raises(StaleTurnoverSnapshotError, match="predate"):
            store.apply_turnover_snapshot(
                turnover_snapshot(99, turnover("BTCUSDT", "100"))
            )

        view = store.load_view(SCOPE)

    assert view.turnover_revision == 0


def test_turnover_requires_authoritative_proof_for_empty_coverage() -> None:
    with pytest.raises(ValueError, match="authoritative_empty"):
        turnover_snapshot(100, covered_instrument_keys=())
    snapshot = turnover_snapshot(
        100,
        covered_instrument_keys=(),
        authoritative_empty=True,
    )
    assert snapshot.authoritative_empty is True


def test_new_turnover_coverage_clears_values_outside_latest_snapshot(
    tmp_path,
) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(100, instrument("BTCUSDT"), instrument("ETHUSDT"))
        )
        store.apply_turnover_snapshot(
            turnover_snapshot(
                110,
                turnover("BTCUSDT", "100"),
                turnover("ETHUSDT", "200"),
                covered_instrument_keys=("BTCUSDT", "ETHUSDT"),
            )
        )
        changes = store.apply_turnover_snapshot(
            turnover_snapshot(
                120,
                turnover("BTCUSDT", "90"),
                covered_instrument_keys=("BTCUSDT",),
            )
        )
        view = store.load_view(SCOPE)

    assert changes.catalog_revision == 1
    assert changes.changed_instrument_keys == ("BTCUSDT", "ETHUSDT")
    assert by_key(view, "BTCUSDT").turnover.value == Decimal(90)
    assert by_key(view, "ETHUSDT").turnover is None
    assert view.turnover_covered_instrument_keys == ("BTCUSDT",)


def test_catalog_refresh_preserves_independent_turnover_binding(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_turnover_snapshot(turnover_snapshot(110, turnover("BTCUSDT", "42")))
        store.apply_catalog_snapshot(catalog_snapshot(120, instrument("BTCUSDT")))
        view = store.load_view(SCOPE)

    assert by_key(view, "BTCUSDT").turnover.value == Decimal(42)
    assert view.catalog_revision == 2
    assert view.turnover_revision == 1
    assert view.turnover_catalog_revision == 1


def test_turnover_revision_or_coverage_conflict_rolls_back(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        with pytest.raises(CatalogRevisionConflictError, match="revision"):
            store.apply_turnover_snapshot(
                turnover_snapshot(
                    110,
                    turnover("BTCUSDT", "1"),
                    catalog_revision=2,
                )
            )
        with pytest.raises(CatalogRevisionConflictError, match="outside"):
            store.apply_turnover_snapshot(
                turnover_snapshot(
                    110,
                    turnover("UNKNOWNUSDT", "1"),
                )
            )
        view = store.load_view(SCOPE)

    assert view.turnover_revision == 0
    assert by_key(view, "BTCUSDT").turnover is None


def test_turnover_result_validation_failure_rolls_back_everything(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))

        def fail_result_validation(*args, **kwargs):
            raise RuntimeError("injected turnover result validation failure")

        monkeypatch.setattr(
            catalog_store_module,
            "TurnoverChanges",
            fail_result_validation,
        )
        with pytest.raises(RuntimeError, match="turnover result validation"):
            store.apply_turnover_snapshot(
                turnover_snapshot(110, turnover("BTCUSDT", "10"))
            )

        view = store.load_view(SCOPE)
        assert view.turnover_revision == 0
        assert by_key(view, "BTCUSDT").turnover is None

    with CatalogStore.open(path) as reopened:
        view = reopened.load_view(SCOPE)
        assert view.turnover_revision == 0
        assert by_key(view, "BTCUSDT").turnover is None


def test_catalog_and_outbox_rollback_together_on_event_failure(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        baseline = store.apply_catalog_snapshot(
            catalog_snapshot(100, instrument("BTCUSDT"))
        )
        for event_id in baseline.control_event_ids:
            store.ack_change(event_id)

        calls = 0
        real_event_id = catalog_store_module._control_event_id

        def fail_second_event(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("injected outbox failure")
            return real_event_id(*args, **kwargs)

        monkeypatch.setattr(
            catalog_store_module,
            "_control_event_id",
            fail_second_event,
        )
        with pytest.raises(RuntimeError, match="injected outbox failure"):
            store.apply_catalog_snapshot(
                catalog_snapshot(200, instrument("BTCUSDT"), instrument("NEWUSDT"))
            )
        view = store.load_view(SCOPE)

    assert view.catalog_revision == 1
    assert [item.instrument_key for item in view.instruments] == ["BTCUSDT"]
    with CatalogStore.open(path) as reopened:
        assert reopened.pending_changes(SCOPE) == ()


def test_catalog_result_validation_failure_rolls_back_everything(
    tmp_path,
    monkeypatch,
) -> None:
    path = tmp_path / "catalog.sqlite"
    hint = AnnouncementHint(
        scope=SCOPE,
        hint_id="rollback-hint",
        candidate_instrument_key="NEWUSDT",
        announced_at_ns=50,
        raw_reference="raw/rollback-hint",
    )
    with CatalogStore.open(path) as store:
        baseline = store.apply_catalog_snapshot(
            catalog_snapshot(100, instrument("BTCUSDT"))
        )
        for event_id in baseline.control_event_ids:
            store.ack_change(event_id)
        store.record_announcement_hint(hint)

        def fail_result_validation(*args, **kwargs):
            raise RuntimeError("injected result validation failure")

        monkeypatch.setattr(
            catalog_store_module,
            "CatalogChanges",
            fail_result_validation,
        )
        with pytest.raises(RuntimeError, match="result validation"):
            store.apply_catalog_snapshot(
                catalog_snapshot(200, instrument("BTCUSDT"), instrument("NEWUSDT"))
            )

        view = store.load_view(SCOPE)
        persisted_hint = store.load_announcement_hints(SCOPE)[0]
        assert view.catalog_revision == 1
        assert [item.instrument_key for item in view.instruments] == ["BTCUSDT"]
        assert persisted_hint.confirmed_at_ns is None
        assert store.pending_changes(SCOPE) == ()

    with CatalogStore.open(path) as reopened:
        assert reopened.load_view(SCOPE).catalog_revision == 1
        assert reopened.load_announcement_hints(SCOPE)[0].confirmed_at_ns is None
        assert reopened.pending_changes(SCOPE) == ()


def test_open_rejects_same_version_with_weakened_schema(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path):
        pass
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA writable_schema = ON")
        connection.execute(
            """
            UPDATE sqlite_schema
               SET sql = replace(
                   sql,
                   'complete INTEGER NOT NULL CHECK (complete IN (0, 1))',
                   'complete INTEGER NOT NULL'
               )
             WHERE name = 'catalog_scope_state'
            """
        )
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(RuntimeError, match="schema"):
        CatalogStore.open(path)


def test_concurrent_first_open_is_retry_safe(tmp_path) -> None:
    path = tmp_path / "concurrent.sqlite"

    def open_once(_: int) -> str:
        with CatalogStore.open(path) as store:
            return store.journal_mode

    with ThreadPoolExecutor(max_workers=8) as executor:
        modes = tuple(executor.map(open_once, range(24)))

    assert modes == ("wal",) * 24
    with CatalogStore.open(path) as store:
        assert store.load_view(SCOPE).catalog_revision == 0


def test_catalog_changes_survive_restart_until_explicit_ack(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        baseline = store.apply_catalog_snapshot(
            catalog_snapshot(100, instrument("BTCUSDT"))
        )
        for event_id in baseline.control_event_ids:
            assert store.ack_change(event_id) is True
        changes = store.apply_catalog_snapshot(
            catalog_snapshot(200, instrument("BTCUSDT"), instrument("NEWUSDT"))
        )
        expected_ids = changes.control_event_ids
    with CatalogStore.open(path) as reopened:
        pending = reopened.pending_changes(SCOPE)
        assert tuple(item.event_id for item in pending) == expected_ids
        with pytest.raises(TypeError):
            pending[0].payload["current"] = None  # type: ignore[index]
        assert reopened.ack_change(expected_ids[0]) is True
        assert reopened.ack_change(expected_ids[0]) is False
    with CatalogStore.open(path) as reopened:
        remaining = tuple(item.event_id for item in reopened.pending_changes(SCOPE))

    assert remaining == expected_ids[1:]


def test_catalog_view_rejects_boolean_revisions() -> None:
    with pytest.raises((TypeError, ValueError)):
        CatalogView(
            scope=SCOPE,
            catalog_observed_at_ns=100,
            catalog_revision=True,  # type: ignore[arg-type]
            catalog_digest_sha256="a" * 64,
            catalog_snapshot_id="catalog-100",
            catalog_page_raw_references=("raw/catalog-100",),
            turnover_observed_at_ns=None,
            turnover_revision=0,
            turnover_digest_sha256=None,
            turnover_catalog_revision=None,
            turnover_snapshot_id=None,
            turnover_page_raw_references=(),
            turnover_covered_instrument_keys=(),
            instruments=(),
        )


def test_catalog_view_rejects_impossible_missing_timestamp(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        store.apply_catalog_snapshot(catalog_snapshot(200, authoritative_empty=True))
        view = store.load_view(SCOPE)

    impossible = replace(view.instruments[0], last_seen_ns=200)
    with pytest.raises(ValueError, match="missing instrument last_seen_ns"):
        replace(view, instruments=(impossible,))


def test_current_turnover_coverage_cannot_include_missing_instrument(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(
            catalog_snapshot(100, instrument("BTCUSDT"), instrument("ETHUSDT"))
        )
        store.apply_catalog_snapshot(
            catalog_snapshot(200, instrument("BTCUSDT"), instrument("ETHUSDT"))
        )
        store.apply_turnover_snapshot(
            turnover_snapshot(
                210,
                turnover("BTCUSDT", "10"),
                covered_instrument_keys=("BTCUSDT", "ETHUSDT"),
                catalog_revision=2,
            )
        )
        view = store.load_view(SCOPE)

    eth = by_key(view, "ETHUSDT")
    missing_eth = replace(eth, present=False, last_seen_ns=150)
    instruments = tuple(
        missing_eth if item.instrument_key == "ETHUSDT" else item
        for item in view.instruments
    )
    with pytest.raises(ValueError, match="present instruments"):
        replace(view, instruments=instruments)


def test_current_turnover_view_cannot_predate_catalog_observation(tmp_path) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.apply_catalog_snapshot(catalog_snapshot(100, instrument("BTCUSDT")))
        view = store.load_view(SCOPE)

    with pytest.raises(ValueError, match="predate"):
        CatalogView(
            scope=SCOPE,
            catalog_observed_at_ns=100,
            catalog_revision=1,
            catalog_digest_sha256=view.catalog_digest_sha256,
            catalog_snapshot_id=view.catalog_snapshot_id,
            catalog_page_raw_references=view.catalog_page_raw_references,
            turnover_observed_at_ns=99,
            turnover_revision=1,
            turnover_digest_sha256="b" * 64,
            turnover_catalog_revision=1,
            turnover_snapshot_id="turnover-99",
            turnover_page_raw_references=("raw/turnover-99",),
            turnover_covered_instrument_keys=(),
            instruments=view.instruments,
        )


def test_catalog_snapshot_scope_cannot_be_injected(tmp_path) -> None:
    other_scope = SelectionScope(Exchange.BYBIT, Market.SPOT)
    with pytest.raises(ValueError, match="scope"):
        CompleteCatalogSnapshot(
            scope=other_scope,
            observed_at_ns=100,
            snapshot_id="cross-scope",
            pages=(SnapshotPage("raw/cross-scope", None, None),),
            reported_total_count=1,
            authoritative_empty=False,
            instruments=(instrument("BTCUSDT"),),
        )
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        assert store.load_view(SCOPE).catalog_revision == 0
