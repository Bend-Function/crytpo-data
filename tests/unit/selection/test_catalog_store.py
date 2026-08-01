from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import replace
from decimal import Decimal
from typing import cast

import pytest

from crypto_collector.selection.catalog_store import (
    CatalogSnapshotConflictError,
    CatalogStore,
    StaleCatalogSnapshotError,
)
from crypto_collector.selection.models import (
    AnnouncementHint,
    CatalogScope,
    CompleteCatalogSnapshot,
    CompleteTurnoverSnapshot,
    InstrumentRecord,
    LifecyclePhase,
    SnapshotPage,
    TradableAtSource,
    Turnover,
    TurnoverMethod,
    TurnoverObservation,
)


def instrument(
    instrument_key: str,
    *,
    exchange: str = "binance",
    market: str = "spot",
    status: str = "online",
    tradable: bool = True,
    tradable_at_ns: int | None = None,
    tradable_at_source: TradableAtSource | str | None = None,
    turnover: Turnover | None = None,
) -> InstrumentRecord:
    return InstrumentRecord(
        exchange=exchange,
        market=market,
        instrument_key=instrument_key,
        canonical_pair=f"{instrument_key.removesuffix('USDT')}/USDT",
        wire_symbols={
            "rest": instrument_key,
            "websocket": instrument_key.lower(),
        },
        base_asset=instrument_key.removesuffix("USDT"),
        quote_asset="USDT",
        settlement_asset=None if market == "spot" else "USDT",
        status=status,
        tradable=tradable,
        lifecycle_phase=(
            LifecyclePhase.PREOPEN if status == "prelaunch" and not tradable else None
        ),
        lifecycle={"status": status, "filters": [{"tick": Decimal("0.01")}]},
        tradable_at_ns=tradable_at_ns,
        tradable_at_source=tradable_at_source,
        turnover=turnover,
        raw_catalog_reference=f"raw/{exchange}/{market}/catalog-1",
    )


def _apply_snapshot(
    store: CatalogStore,
    *,
    scope: CatalogScope,
    observed_at_ns: int,
    instruments: Iterable[InstrumentRecord],
    initial_lookback_ns: int = 0,
    complete: bool = True,
):
    if not complete:
        raise ValueError("catalog snapshots must be complete")
    records = tuple(instruments)
    snapshot_id = f"test:{scope.exchange.value}:{scope.market.value}:{observed_at_ns}"
    return store.apply_catalog_snapshot(
        CompleteCatalogSnapshot(
            scope=scope,
            observed_at_ns=observed_at_ns,
            snapshot_id=snapshot_id,
            pages=(SnapshotPage(f"raw/{snapshot_id}", None, None),),
            reported_total_count=len(records),
            authoritative_empty=not records,
            instruments=records,
        ),
        initial_lookback_ns=initial_lookback_ns,
    )


def _apply_turnover(
    store: CatalogStore,
    *,
    scope: CatalogScope,
    observed_at_ns: int,
    values: dict[str, Turnover],
) -> None:
    view = store.load_view(scope)
    observations = tuple(
        TurnoverObservation(
            instrument_key=key,
            value=value.value,
            method=value.method,
            currency=value.currency,
            raw_reference=value.raw_reference or f"raw/turnover/{key}",
        )
        for key, value in sorted(values.items())
    )
    store.apply_turnover_snapshot(
        CompleteTurnoverSnapshot(
            scope=scope,
            catalog_revision=view.catalog_revision,
            observed_at_ns=observed_at_ns,
            snapshot_id=f"turnover-{observed_at_ns}",
            pages=(SnapshotPage(f"raw/turnover-{observed_at_ns}", None, None),),
            reported_total_count=len(observations),
            covered_instrument_keys=tuple(sorted(values)),
            observations=observations,
        )
    )


def test_first_catalog_is_baseline_not_mass_new_listing(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        changes = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("BTCUSDT"), instrument("NEWUSDT")],
        )

        assert changes.is_initial_baseline is True
        assert changes.new_listings == ()
        persisted = store.load_catalog(scope)

    assert [item.instrument_key for item in persisted.instruments] == [
        "BTCUSDT",
        "NEWUSDT",
    ]
    assert persisted.instruments[0].first_seen_ns == 100
    assert persisted.instruments[0].last_seen_ns == 100
    assert persisted.instruments[0].tradable_at_ns == 100
    assert (
        persisted.instruments[0].tradable_at_source
        is TradableAtSource.FIRST_TRADABLE_SEEN
    )


def test_recent_official_tradable_time_can_enter_on_first_baseline(tmp_path) -> None:
    scope = CatalogScope("bitget", "perpetual")
    now_ns = 100 * 60 * 60
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        changes = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=now_ns,
            instruments=[
                instrument(
                    "NEWUSDT",
                    exchange="bitget",
                    market="perpetual",
                    tradable_at_ns=now_ns - 60 * 60,
                    tradable_at_source="exchange",
                )
            ],
            initial_lookback_ns=72 * 60 * 60,
        )

    assert [item.instrument_key for item in changes.new_listings] == ["NEWUSDT"]
    assert changes.new_listings[0].tradable_at_source is TradableAtSource.EXCHANGE


@pytest.mark.parametrize(
    ("tradable_at_ns", "tradable", "lookback_ns"),
    [
        (10, True, 50),  # too old
        (101, True, 100),  # official future time
        (90, False, 100),  # catalog has not confirmed tradability
        (100, True, 0),  # zero explicitly disables first-baseline lookback
    ],
)
def test_first_baseline_rejects_ineligible_official_times(
    tmp_path, tradable_at_ns: int, tradable: bool, lookback_ns: int
) -> None:
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        changes = _apply_snapshot(
            store,
            scope=CatalogScope("binance", "spot"),
            observed_at_ns=100,
            instruments=[
                instrument(
                    "NEWUSDT",
                    status="online" if tradable else "prelaunch",
                    tradable=tradable,
                    tradable_at_ns=tradable_at_ns,
                    tradable_at_source="exchange",
                )
            ],
            initial_lookback_ns=lookback_ns,
        )

    assert changes.new_listings == ()


def test_nontradable_instrument_becomes_new_only_when_catalog_confirms_it(
    tmp_path,
) -> None:
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        initial = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("NEWUSDT", status="prelaunch", tradable=False)],
        )
        confirmed = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=200,
            instruments=[instrument("NEWUSDT")],
        )

    assert initial.new_listings == ()
    assert [item.instrument_key for item in confirmed.new_listings] == ["NEWUSDT"]
    assert confirmed.new_listings[0].first_seen_ns == 100
    assert confirmed.new_listings[0].tradable_at_ns == 200
    assert (
        confirmed.new_listings[0].tradable_at_source
        is TradableAtSource.FIRST_TRADABLE_SEEN
    )


def test_announcement_is_only_a_hint_until_catalog_confirmation(tmp_path) -> None:
    scope = CatalogScope("bybit", "spot")
    hint = AnnouncementHint(
        scope=scope,
        hint_id="announcement-1",
        candidate_instrument_key="NEWUSDT",
        announced_at_ns=50,
        raw_reference="raw/bybit/announcement-1",
    )
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        assert store.record_announcement_hint(hint) is True
        assert store.record_announcement_hint(hint) is False
        baseline = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[],
        )
        confirmed = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=200,
            instruments=[instrument("NEWUSDT", exchange="bybit")],
        )
        stored_hint = store.load_announcement_hints(scope)[0]

    assert baseline.new_listings == ()
    assert baseline.confirmed_announcement_hints == ()
    assert [item.instrument_key for item in confirmed.new_listings] == ["NEWUSDT"]
    assert [item.hint_id for item in confirmed.confirmed_announcement_hints] == [
        "announcement-1"
    ]
    announcement_delta = next(
        item for item in confirmed.deltas if item.kind == "announcement_confirmed"
    )
    assert announcement_delta.previous is not None
    assert announcement_delta.previous.confirmed_at_ns is None
    assert announcement_delta.current.confirmed_at_ns == 200
    assert confirmed.new_listings[0].tradable_at_ns == 200
    assert (
        confirmed.new_listings[0].tradable_at_source
        is TradableAtSource.FIRST_TRADABLE_SEEN
    )
    assert stored_hint.confirmed_at_ns == 200


def test_multiple_hints_for_one_instrument_confirm_atomically(tmp_path) -> None:
    scope = CatalogScope("bybit", "spot")
    hints = tuple(
        AnnouncementHint(
            scope=scope,
            hint_id=f"announcement-{ordinal}",
            candidate_instrument_key="NEWUSDT",
            announced_at_ns=ordinal,
            raw_reference=f"raw/bybit/announcement-{ordinal}",
        )
        for ordinal in (1, 2)
    )
    path = tmp_path / "catalog.sqlite"

    with CatalogStore.open(path) as store:
        for hint in hints:
            assert store.record_announcement_hint(hint)
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[],
        )
        changes = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=200,
            instruments=[instrument("NEWUSDT", exchange="bybit")],
        )

        assert [item.hint_id for item in changes.confirmed_announcement_hints] == [
            "announcement-1",
            "announcement-2",
        ]
        announcement_deltas = tuple(
            item for item in changes.deltas if item.kind == "announcement_confirmed"
        )
        assert [item.instrument_key for item in announcement_deltas] == [
            "NEWUSDT",
            "NEWUSDT",
        ]
        assert [item.identity_key for item in announcement_deltas] == [
            "announcement-1",
            "announcement-2",
        ]

    with CatalogStore.open(path) as reopened:
        assert reopened.load_view(scope).catalog_revision == 2
        assert [
            item.confirmed_at_ns for item in reopened.load_announcement_hints(scope)
        ] == [200, 200]


def test_hint_key_and_pair_must_match_the_same_tradable_instrument(tmp_path) -> None:
    scope = CatalogScope("bybit", "spot")
    hint = AnnouncementHint(
        scope=scope,
        hint_id="cross-instrument-hint",
        candidate_instrument_key="NEWUSDT",
        candidate_canonical_pair="BTC/USDT",
        announced_at_ns=50,
        raw_reference="raw/bybit/cross-instrument-hint",
    )

    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        assert store.record_announcement_hint(hint)
        baseline = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("BTCUSDT", exchange="bybit")],
        )
        changes = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=200,
            instruments=[instrument("BTCUSDT", exchange="bybit")],
        )
        persisted = store.load_announcement_hints(scope)[0]

    assert baseline.confirmed_announcement_hints == ()
    assert changes.confirmed_announcement_hints == ()
    assert persisted.confirmed_at_ns is None


def test_equal_snapshot_is_idempotent_but_conflicting_replay_fails(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    records = [instrument("BTCUSDT")]
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        _apply_snapshot(store, scope=scope, observed_at_ns=100, instruments=records)
        replay = _apply_snapshot(
            store, scope=scope, observed_at_ns=100, instruments=records
        )
        with pytest.raises(CatalogSnapshotConflictError):
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=100,
                instruments=[instrument("ETHUSDT")],
            )

    assert replay.idempotent is True
    assert replay.added == ()
    assert replay.updated == ()
    assert replay.removed == ()
    assert replay.new_listings == ()


def test_snapshot_time_cannot_move_backwards(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        _apply_snapshot(
            store, scope=scope, observed_at_ns=100, instruments=[instrument("BTCUSDT")]
        )
        with pytest.raises(StaleCatalogSnapshotError):
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=99,
                instruments=[instrument("BTCUSDT")],
            )


def test_restart_preserves_baseline_and_does_not_replay_new_listing(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(path) as store:
        first = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("BTCUSDT")],
        )
    with CatalogStore.open(path) as reopened:
        second = _apply_snapshot(
            reopened,
            scope=scope,
            observed_at_ns=200,
            instruments=[instrument("BTCUSDT")],
        )
        persisted = reopened.load_catalog(scope).instruments[0]

    assert first.new_listings == ()
    assert second.new_listings == ()
    assert persisted.first_seen_ns == 100
    assert persisted.last_seen_ns == 200


def test_missing_instrument_is_retained_as_history_but_not_current(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        _apply_snapshot(
            store, scope=scope, observed_at_ns=100, instruments=[instrument("BTCUSDT")]
        )
        changes = _apply_snapshot(
            store, scope=scope, observed_at_ns=200, instruments=[]
        )
        current = store.load_catalog(scope)
        historical = store.load_catalog(scope, include_missing=True)

    assert [item.instrument_key for item in changes.removed] == ["BTCUSDT"]
    assert current.instruments == ()
    assert len(historical.instruments) == 1
    assert historical.instruments[0].present is False
    assert historical.instruments[0].last_seen_ns == 100


def test_catalog_round_trips_all_provenance_without_mutable_aliases(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    turnover = Turnover(
        value=Decimal("123456789.123456789"),
        method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
        currency="USDT",
        observed_at_ns=101,
        raw_reference="raw/binance/ticker-101",
    )
    source = instrument("BTCUSDT")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        _apply_snapshot(store, scope=scope, observed_at_ns=100, instruments=[source])
        _apply_turnover(
            store,
            scope=scope,
            observed_at_ns=101,
            values={"BTCUSDT": turnover},
        )
        persisted = store.load_catalog(scope).instruments[0]

    assert dict(persisted.wire_symbols) == {
        "rest": "BTCUSDT",
        "websocket": "btcusdt",
    }
    lifecycle = cast(Mapping[str, object], persisted.lifecycle)
    filters = cast(tuple[object, ...], lifecycle["filters"])
    first_filter = cast(Mapping[str, object], filters[0])
    assert first_filter["tick"] == Decimal("0.01")
    assert persisted.turnover == turnover
    assert persisted.raw_catalog_reference == "raw/binance/spot/catalog-1"
    with pytest.raises(TypeError):
        persisted.wire_symbols["rest"] = "mutated"  # type: ignore[index]
    with pytest.raises(TypeError):
        persisted.lifecycle["status"] = "mutated"  # type: ignore[index]


def test_duplicate_or_cross_scope_records_are_rejected_without_partial_write(
    tmp_path,
) -> None:
    scope = CatalogScope("binance", "spot")
    path = tmp_path / "catalog.sqlite"
    with CatalogStore.open(path) as store:
        with pytest.raises(ValueError, match="unique"):
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=100,
                instruments=[instrument("BTCUSDT"), instrument("BTCUSDT")],
            )
        with pytest.raises(ValueError, match="scope"):
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=100,
                instruments=[instrument("BTCUSDT", exchange="bybit")],
            )
        assert store.load_catalog(scope).instruments == ()


def test_turnover_rejects_contract_counts_and_wrong_quote_currency() -> None:
    with pytest.raises(ValueError):
        Turnover(
            value=Decimal(100),
            method="contract_count",
            currency="USDT",
        )
    with pytest.raises(ValueError, match="quote_asset"):
        instrument(
            "BTCUSDT",
            turnover=Turnover(
                value=Decimal(100),
                method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
                currency="USD",
            ),
        )


@pytest.mark.parametrize(
    "bad_update",
    [
        {"instrument_key": ""},
        {"tradable": 1},
        {"tradable_at_ns": True, "tradable_at_source": "exchange"},
        {"tradable_at_ns": 100, "tradable_at_source": None},
        {"raw_catalog_reference": ""},
    ],
)
def test_instrument_record_strictly_rejects_malformed_input(bad_update) -> None:
    with pytest.raises((TypeError, ValueError)):
        replace(instrument("BTCUSDT"), **bad_update)


def test_store_rejects_bool_timestamps_and_lookback(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        with pytest.raises((TypeError, ValueError)):
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=True,
                instruments=[],  # type: ignore[arg-type]
            )
        with pytest.raises((TypeError, ValueError)):
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=100,
                instruments=[],
                initial_lookback_ns=True,  # type: ignore[arg-type]
            )


def test_active_new_listing_state_survives_restart_without_reviving_baseline(
    tmp_path,
) -> None:
    path = tmp_path / "catalog.sqlite"
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(path) as store:
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("BTCUSDT")],
        )
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=200,
            instruments=[instrument("BTCUSDT"), instrument("NEWUSDT")],
        )
    with CatalogStore.open(path) as reopened:
        active = reopened.load_active_new_listings(
            scope,
            now_ns=250,
            capture_duration_ns=100,
        )
        expired = reopened.load_active_new_listings(
            scope,
            now_ns=300,
            capture_duration_ns=100,
        )
        all_records = reopened.load_catalog(scope).instruments

    assert [item.instrument_key for item in active] == ["NEWUSDT"]
    assert expired == ()
    assert {item.instrument_key: item.listing_state.value for item in all_records} == {
        "BTCUSDT": "baseline",
        "NEWUSDT": "active_new",
    }


def test_official_first_baseline_new_listing_is_active_after_restart(tmp_path) -> None:
    path = tmp_path / "catalog.sqlite"
    scope = CatalogScope("bitget", "perpetual")
    with CatalogStore.open(path) as store:
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=1_000,
            initial_lookback_ns=100,
            instruments=[
                instrument(
                    "NEWUSDT",
                    exchange="bitget",
                    market="perpetual",
                    tradable_at_ns=950,
                    tradable_at_source="exchange_continuous",
                )
            ],
        )
    with CatalogStore.open(path) as reopened:
        active = reopened.load_active_new_listings(
            scope,
            now_ns=1_049,
            capture_duration_ns=100,
        )

    assert [item.instrument_key for item in active] == ["NEWUSDT"]


def test_partial_snapshot_cannot_mark_catalog_entries_missing(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("BTCUSDT")],
        )
        with pytest.raises(ValueError, match="complete"):
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=200,
                instruments=[],
                complete=False,
            )
        assert [
            item.instrument_key for item in store.load_catalog(scope).instruments
        ] == ["BTCUSDT"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("observed_at_ns", 2**63),
        ("initial_lookback_ns", 2**63),
    ],
)
def test_store_rejects_values_outside_sqlite_int64(tmp_path, field, value) -> None:
    scope = CatalogScope("binance", "spot")
    with (
        CatalogStore.open(tmp_path / "catalog.sqlite") as store,
        pytest.raises(ValueError, match="signed 64-bit"),
    ):
        if field == "observed_at_ns":
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=value,
                initial_lookback_ns=0,
                instruments=[],
            )
        else:
            _apply_snapshot(
                store,
                scope=scope,
                observed_at_ns=100,
                initial_lookback_ns=value,
                instruments=[],
            )


def test_frozen_lifecycle_can_be_reused_and_decimal_integer_is_exact(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    original = replace(
        instrument("BTCUSDT"),
        lifecycle={"integer_decimal": Decimal(1), "scaled": Decimal("1.00")},
    )
    reused = replace(original, status="online")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[reused],
        )
        lifecycle = cast(
            Mapping[str, object],
            store.load_catalog(scope).instruments[0].lifecycle,
        )

    assert type(lifecycle["integer_decimal"]) is Decimal
    assert lifecycle["integer_decimal"] == Decimal(1)
    assert cast(Decimal, lifecycle["scaled"]).as_tuple() == Decimal("1.00").as_tuple()


def test_snapshot_exposes_scope_revision_digest_and_completeness(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("BTCUSDT"), instrument("ETHUSDT")],
        )
        first = store.load_catalog(scope)
        replay = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("ETHUSDT"), instrument("BTCUSDT")],
        )
        second = store.load_catalog(scope)

    assert first.revision == 1
    assert first.complete is True
    assert first.digest_sha256 is not None
    assert len(first.digest_sha256) == 64
    assert replay.idempotent is True
    assert second.revision == first.revision
    assert second.digest_sha256 == first.digest_sha256


def test_canonical_only_announcement_hint_can_trigger_refresh_and_confirm(
    tmp_path,
) -> None:
    scope = CatalogScope("bybit", "spot")
    hint = AnnouncementHint(
        scope=scope,
        hint_id="canonical-hint",
        candidate_instrument_key=None,
        candidate_canonical_pair="NEW/USDT",
        announced_at_ns=50,
        raw_reference="raw/bybit/announcement-canonical",
    )
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.record_announcement_hint(hint)
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[],
        )
        changes = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=200,
            instruments=[instrument("NEWUSDT", exchange="bybit")],
        )
        announcement_events = tuple(
            item
            for item in store.pending_changes(scope)
            if item.kind == "announcement_confirmed"
        )

    assert [item.hint_id for item in changes.confirmed_announcement_hints] == [
        "canonical-hint"
    ]
    announcement_delta = next(
        item for item in changes.deltas if item.kind == "announcement_confirmed"
    )
    assert announcement_delta.instrument_key == "NEWUSDT"
    assert [item.instrument_key for item in announcement_events] == ["NEWUSDT"]


def test_canonical_only_announcement_requires_one_unique_tradable_match(
    tmp_path,
) -> None:
    scope = CatalogScope("bybit", "spot")
    hint = AnnouncementHint(
        scope=scope,
        hint_id="ambiguous-canonical-hint",
        candidate_instrument_key=None,
        candidate_canonical_pair="NEW/USDT",
        announced_at_ns=50,
        raw_reference="raw/bybit/announcement-ambiguous",
    )
    alias = replace(
        instrument("ALIASUSDT", exchange="bybit"),
        canonical_pair="NEW/USDT",
    )

    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        store.record_announcement_hint(hint)
        changes = _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=100,
            instruments=[instrument("NEWUSDT", exchange="bybit"), alias],
        )
        persisted = store.load_announcement_hints(scope)[0]

    assert changes.confirmed_announcement_hints == ()
    assert all(item.kind != "announcement_confirmed" for item in changes.deltas)
    assert persisted.confirmed_at_ns is None


def test_turnover_observation_provenance_round_trips(tmp_path) -> None:
    scope = CatalogScope("binance", "spot")
    turnover = Turnover(
        value=Decimal("42.25"),
        method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
        currency="USDT",
        observed_at_ns=90,
        raw_reference="raw/binance/ticker-90",
    )
    with CatalogStore.open(tmp_path / "catalog.sqlite") as store:
        _apply_snapshot(
            store,
            scope=scope,
            observed_at_ns=80,
            instruments=[instrument("BTCUSDT")],
        )
        _apply_turnover(
            store,
            scope=scope,
            observed_at_ns=90,
            values={"BTCUSDT": turnover},
        )
        persisted = store.load_catalog(scope).instruments[0]

    assert persisted.turnover == turnover
