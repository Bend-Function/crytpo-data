from __future__ import annotations

import re
from dataclasses import replace
from decimal import Decimal, localcontext

import pytest

import crypto_collector.selection as selection_package
from crypto_collector.domain.types import Exchange, Market
from crypto_collector.selection.catalog_store import CatalogStore
from crypto_collector.selection.models import (
    CatalogInstrument,
    CatalogScope,
    CatalogView,
    LifecyclePhase,
    ListingState,
    TradableAtSource,
    Turnover,
    TurnoverMethod,
)
from crypto_collector.selection.selector import (
    ResolvedFixedSelection,
    SelectionDelta,
    SelectionEntry,
    SelectionPolicy,
    SelectionReason,
    SelectionState,
    select,
)


def _instrument(
    key: str,
    *,
    quote: str = "USDT",
    turnover: str | None = None,
    turnover_at: int = 900,
    present: bool = True,
    tradable: bool = True,
    new_started_at: int | None = None,
    listing_generation: int | None = None,
) -> CatalogInstrument:
    return CatalogInstrument(
        exchange=Exchange.BINANCE,
        market=Market.SPOT,
        instrument_key=key,
        canonical_pair=f"{key}/{quote}",
        wire_symbols={"rest": key},
        base_asset=key,
        quote_asset=quote,
        settlement_asset=None,
        status="trading" if tradable else "paused",
        lifecycle_phase=(
            LifecyclePhase.TRADABLE if tradable else LifecyclePhase.PAUSED
        ),
        tradable=tradable,
        lifecycle={"native": {"state": "live"}},
        tradable_at_ns=new_started_at,
        tradable_at_source=(
            TradableAtSource.EXCHANGE if new_started_at is not None else None
        ),
        turnover=(
            Turnover(
                Decimal(turnover),
                TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
                quote,
                observed_at_ns=turnover_at,
                raw_reference=f"raw/{key}",
            )
            if turnover is not None
            else None
        ),
        raw_catalog_reference=f"catalog/{key}",
        first_seen_ns=100,
        last_seen_ns=max(
            100,
            new_started_at or 0,
            turnover_at if turnover is not None else 0,
        ),
        present=present,
        listing_state=(
            ListingState.ACTIVE_NEW
            if new_started_at is not None
            else ListingState.BASELINE
        ),
        first_tradable_seen_ns=(
            new_started_at if new_started_at is not None else 100 if tradable else None
        ),
        listing_generation=(
            (1 if new_started_at is not None else 0)
            if listing_generation is None
            else listing_generation
        ),
        new_listing_started_at_ns=new_started_at,
        new_listing_source=(
            TradableAtSource.EXCHANGE if new_started_at is not None else None
        ),
        new_listing_eligible=new_started_at is not None,
    )


SCOPE = CatalogScope(Exchange.BINANCE, Market.SPOT)


def _view(
    *instruments: CatalogInstrument,
    catalog_observed_at_ns: int | None = None,
    catalog_revision: int = 7,
    turnover_revision: int = 3,
    turnover_observed_at_ns: int | None = None,
    turnover_catalog_revision: int | None = None,
    turnover_covered_instrument_keys: tuple[str, ...] | None = None,
) -> CatalogView:
    if catalog_observed_at_ns is None:
        latest_seen = max(
            (item.last_seen_ns for item in instruments),
            default=900,
        )
        catalog_observed_at_ns = latest_seen + int(
            any(
                not item.present and item.last_seen_ns == latest_seen
                for item in instruments
            )
        )
        instruments = tuple(
            replace(item, last_seen_ns=catalog_observed_at_ns)
            if item.present and item.last_seen_ns != catalog_observed_at_ns
            else item
            for item in instruments
        )
    observed_turnover_times = {
        item.turnover.observed_at_ns
        for item in instruments
        if item.turnover is not None
    }
    if turnover_observed_at_ns is None:
        turnover_observed_at_ns = (
            observed_turnover_times.pop()
            if len(observed_turnover_times) == 1
            else max(900, catalog_observed_at_ns)
        )
    return CatalogView(
        scope=SCOPE,
        catalog_observed_at_ns=catalog_observed_at_ns,
        catalog_revision=catalog_revision,
        catalog_digest_sha256="a" * 64,
        catalog_snapshot_id="catalog-900",
        catalog_page_raw_references=("raw/catalog-900",),
        turnover_observed_at_ns=(
            turnover_observed_at_ns if turnover_revision else None
        ),
        turnover_revision=turnover_revision,
        turnover_digest_sha256="b" * 64 if turnover_revision else None,
        turnover_catalog_revision=(
            catalog_revision
            if turnover_revision and turnover_catalog_revision is None
            else turnover_catalog_revision
        ),
        turnover_snapshot_id="turnover-900" if turnover_revision else None,
        turnover_page_raw_references=(
            ("raw/turnover-900",) if turnover_revision else ()
        ),
        turnover_covered_instrument_keys=(
            (
                tuple(item.instrument_key for item in instruments if item.present)
                if turnover_covered_instrument_keys is None
                else turnover_covered_instrument_keys
            )
            if turnover_revision
            else ()
        ),
        instruments=tuple(instruments),
    )


def _policy(
    *,
    scope: CatalogScope = SCOPE,
    quotes: tuple[str, ...] = ("USDT",),
    top_n: int = 1,
    turnover_max_age_ns: int = 200,
    new_listings_enabled: bool = True,
    new_listing_capture_duration_ns: int = 100,
    exit_grace_ns: int = 30,
) -> SelectionPolicy:
    return SelectionPolicy(
        scope=scope,
        quote_assets=quotes,
        top_n=top_n,
        turnover_max_age_ns=turnover_max_age_ns,
        new_listings_enabled=new_listings_enabled,
        new_listing_capture_duration_ns=new_listing_capture_duration_ns,
        exit_grace_ns=exit_grace_ns,
    )


def _fixed(
    view: CatalogView,
    *keys: str,
    scope: CatalogScope | None = None,
    revision: int | None = None,
) -> ResolvedFixedSelection:
    return ResolvedFixedSelection(
        scope=scope or view.scope,
        catalog_revision=(view.catalog_revision if revision is None else revision),
        instrument_keys=frozenset(keys),
    )


def _select(
    view: CatalogView,
    *,
    policy: SelectionPolicy | None = None,
    fixed: ResolvedFixedSelection | None = None,
    previous: SelectionState | None = None,
    now_ns: int = 1_000,
):
    return select(
        view,
        fixed=fixed or _fixed(view),
        policy=policy or _policy(),
        previous=previous,
        now_ns=now_ns,
    )


def test_selection_is_fixed_new_and_quote_local_top_union_with_priority() -> None:
    view = _view(
        _instrument("BTC", turnover="100", turnover_at=950),
        _instrument("ETH", turnover="90", turnover_at=950),
        _instrument("NEW", turnover="1", turnover_at=950, new_started_at=950),
        _instrument("PF_XBTUSD", quote="USD", turnover="1000", turnover_at=950),
    )

    result = _select(view, fixed=_fixed(view, "PF_XBTUSD"))

    assert result.selected == frozenset({"BTC", "NEW", "PF_XBTUSD"})
    assert result.reason("PF_XBTUSD").fixed
    assert not result.reason("PF_XBTUSD").top_n
    assert result.reason("NEW").new_listing
    assert (
        result.entry("PF_XBTUSD").admission_priority
        > result.entry("NEW").admission_priority
    )
    assert (
        result.entry("NEW").admission_priority > result.entry("BTC").admission_priority
    )


def test_overlapping_fixed_new_and_top_reasons_are_all_preserved() -> None:
    item = _instrument("NEW", turnover="100", turnover_at=950, new_started_at=950)
    view = _view(item)

    result = _select(view, fixed=_fixed(view, "NEW"))

    assert result.reason("NEW") == (
        SelectionReason.FIXED | SelectionReason.NEW_LISTING | SelectionReason.TOP_N
    )
    assert result.entry("NEW").top_n_rank == 1


def test_top_n_is_ranked_per_quote_with_decimal_precision_and_stable_ties() -> None:
    view = _view(
        _instrument("Z-USDT", turnover="1.000000000000000000000000001"),
        _instrument("A-USDT", turnover="1.000000000000000000000000001"),
        _instrument("B-USDT", turnover="0.999999999999999999999999999"),
        _instrument("B-USD", quote="USD", turnover="2"),
        _instrument("A-USD", quote="USD", turnover="3"),
    )
    policy = _policy(quotes=("USDT", "USD"), top_n=2)

    result = _select(view, policy=policy)

    assert result.selected == frozenset({"A-USDT", "Z-USDT", "A-USD", "B-USD"})
    assert result.entry("A-USDT").top_n_rank == 1
    assert result.entry("Z-USDT").top_n_rank == 2
    assert result.entry("A-USD").top_n_rank == 1


def test_top_n_ranking_does_not_round_through_ambient_decimal_context() -> None:
    with localcontext() as context:
        context.prec = 3
        view = _view(
            _instrument(
                "HIGH",
                turnover="1.0000000000000000000000000000000000000002",
            ),
            _instrument(
                "LOW",
                turnover="1.0000000000000000000000000000000000000001",
            ),
        )
        result = _select(view)
    assert result.selected == frozenset({"HIGH"})


def test_turnover_is_fresh_through_the_exact_max_age_boundary() -> None:
    item = _instrument("BTC", turnover="10", turnover_at=800)
    assert _select(_view(item), now_ns=1_000).selected == frozenset({"BTC"})


@pytest.mark.parametrize(
    "item",
    [
        _instrument("MISSING-TURNOVER"),
        _instrument("STALE", turnover="10", turnover_at=799),
        _instrument("FUTURE", turnover="10", turnover_at=1_001),
        _instrument("MISSING", turnover="10", present=False),
        _instrument("PAUSED", turnover="10", tradable=False),
    ],
)
def test_top_n_rejects_ineligible_turnover_or_catalog_state(
    item: CatalogInstrument,
) -> None:
    view = (
        _view(
            item,
            turnover_catalog_revision=6,
            turnover_covered_instrument_keys=(item.instrument_key,),
        )
        if not item.present
        else _view(item)
    )
    result = _select(view)
    assert result.selected == frozenset()


def test_wrong_currency_turnover_is_defensively_ignored() -> None:
    item = _instrument("BTC", turnover="100")
    object.__setattr__(
        item,
        "turnover",
        Turnover(
            Decimal(100),
            TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
            "USD",
            observed_at_ns=900,
            raw_reference="raw/BTC",
        ),
    )
    assert _select(_view(item)).selected == frozenset()


def test_top_n_rejects_turnover_bound_to_a_different_catalog_revision() -> None:
    view = _view(
        _instrument("BTC", turnover="100"),
        turnover_catalog_revision=6,
    )
    assert _select(view).selected == frozenset()


@pytest.mark.parametrize("now_ns", [949, 1_050])
def test_new_listing_window_is_half_open(now_ns: int) -> None:
    item = _instrument("NEW", new_started_at=950)
    assert _select(_view(item), now_ns=now_ns).selected == frozenset()


@pytest.mark.parametrize("now_ns", [950, 1_049])
def test_new_listing_window_includes_start_and_last_nanosecond(now_ns: int) -> None:
    item = _instrument("NEW", new_started_at=950)
    assert _select(_view(item), now_ns=now_ns).selected == frozenset({"NEW"})


def test_disabled_new_listing_policy_does_not_admit_active_episode() -> None:
    item = _instrument("NEW", new_started_at=950)
    result = _select(
        _view(item),
        policy=_policy(new_listings_enabled=False),
        now_ns=950,
    )
    assert result.selected == frozenset()


def test_top_n_uses_only_latest_turnover_snapshot_coverage() -> None:
    view = _view(
        _instrument("BTC", turnover="100"),
        _instrument("ETH"),
        turnover_covered_instrument_keys=("BTC",),
    )

    result = _select(view)

    assert result.selected == frozenset({"BTC"})


def test_catalog_view_rejects_turnover_outside_latest_coverage() -> None:
    with pytest.raises(ValueError, match="coverage"):
        _view(
            _instrument("BTC", turnover="100"),
            turnover_covered_instrument_keys=(),
        )


def test_catalog_view_rejects_turnover_timestamp_mismatching_header() -> None:
    item = _instrument("BTC", turnover="100")
    mismatched = replace(
        item,
        turnover=Turnover(
            value=Decimal(100),
            method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
            currency="USDT",
            observed_at_ns=899,
            raw_reference="ticker/BTC/899",
        ),
    )

    with pytest.raises(ValueError, match="observation"):
        _view(mismatched, turnover_observed_at_ns=900)


def test_catalog_view_rejects_turnover_without_header_revision() -> None:
    with pytest.raises(ValueError, match="revision"):
        _view(_instrument("BTC", turnover="100"), turnover_revision=0)


@pytest.mark.parametrize("last_seen_ns", [899, 901])
def test_catalog_view_rejects_present_instrument_not_seen_at_snapshot_header(
    last_seen_ns: int,
) -> None:
    impossible = replace(_instrument("BTC"), last_seen_ns=last_seen_ns)

    with pytest.raises(ValueError, match="last_seen_ns"):
        _view(impossible, catalog_observed_at_ns=900)


@pytest.mark.parametrize("present,tradable", [(False, True), (True, False)])
def test_fixed_still_requires_present_and_tradable(
    present: bool,
    tradable: bool,
) -> None:
    item = _instrument("FIXED", present=present, tradable=tradable)
    view = _view(item)
    with pytest.raises(ValueError, match="present and tradable"):
        _select(view, fixed=_fixed(view, "FIXED"))


def test_fixed_requires_existing_key() -> None:
    view = _view(_instrument("BTC"))
    with pytest.raises(ValueError, match="not in catalog"):
        _select(view, fixed=_fixed(view, "UNKNOWN"))


@pytest.mark.parametrize("mismatch", ["policy", "fixed_scope", "fixed_revision"])
def test_scope_and_fixed_catalog_revision_are_strictly_bound(
    mismatch: str,
) -> None:
    view = _view(_instrument("BTC"))
    other = CatalogScope(Exchange.OKX, Market.SPOT)
    policy = _policy(scope=other) if mismatch == "policy" else _policy()
    fixed = _fixed(
        view,
        scope=other if mismatch == "fixed_scope" else None,
        revision=8 if mismatch == "fixed_revision" else None,
    )
    with pytest.raises(ValueError, match="scope|revision"):
        _select(view, policy=policy, fixed=fixed)


def test_first_top_exit_freezes_grace_start_across_refreshes() -> None:
    initial = _select(_view(_instrument("ALT", turnover="10")), now_ns=1_000)
    assert initial.reason("ALT").top_n

    exited = _select(
        _view(_instrument("ALT", turnover="10"), _instrument("BTC", turnover="20")),
        previous=initial.next_state,
        now_ns=1_010,
    )
    assert exited.reason("ALT").top_n_grace
    assert exited.entry("ALT").top_exit_started_at_ns == 1_010

    with pytest.raises(ValueError, match="precedes a persisted"):
        _select(
            _view(
                _instrument("ALT", turnover="10"),
                _instrument("BTC", turnover="20"),
            ),
            previous=exited.next_state,
            now_ns=1_009,
        )
    with pytest.raises(ValueError, match="precedes a persisted"):
        _select(
            _view(
                _instrument("ALT", turnover="30"),
                _instrument("BTC", turnover="20"),
            ),
            previous=exited.next_state,
            now_ns=1_009,
        )

    after_clock_recovers = _select(
        _view(_instrument("ALT", turnover="10"), _instrument("BTC", turnover="20")),
        previous=exited.next_state,
        now_ns=1_011,
    )
    assert after_clock_recovers.reason("ALT").top_n_grace
    assert after_clock_recovers.entry("ALT").top_exit_started_at_ns == 1_010

    repeated = _select(
        _view(_instrument("ALT", turnover="10"), _instrument("BTC", turnover="20")),
        previous=exited.next_state,
        now_ns=1_039,
    )
    assert repeated.reason("ALT").top_n_grace
    assert repeated.entry("ALT").top_exit_started_at_ns == 1_010

    expired = _select(
        _view(_instrument("ALT", turnover="10"), _instrument("BTC", turnover="20")),
        previous=repeated.next_state,
        now_ns=1_040,
    )
    assert "ALT" not in expired.selected


def test_reentry_clears_grace_and_second_exit_starts_new_period() -> None:
    first = _select(_view(_instrument("ALT", turnover="20")), now_ns=1_000)
    exit_one = _select(
        _view(_instrument("ALT", turnover="10"), _instrument("BTC", turnover="20")),
        previous=first.next_state,
        now_ns=1_010,
    )
    reentered = _select(
        _view(_instrument("ALT", turnover="30"), _instrument("BTC", turnover="20")),
        previous=exit_one.next_state,
        now_ns=1_020,
    )
    assert reentered.reason("ALT").top_n
    assert reentered.entry("ALT").top_exit_started_at_ns is None

    exit_two = _select(
        _view(_instrument("ALT", turnover="10"), _instrument("BTC", turnover="20")),
        previous=reentered.next_state,
        now_ns=1_025,
    )
    assert exit_two.entry("ALT").top_exit_started_at_ns == 1_025


def test_top_exit_grace_does_not_cross_a_relisting_generation() -> None:
    first = _select(
        _view(_instrument("ALT", turnover="20", listing_generation=1)),
        now_ns=1_000,
    )
    relisted_view = _view(
        _instrument("ALT", turnover="10", listing_generation=2),
        _instrument("BTC", turnover="20"),
    )

    result = _select(relisted_view, previous=first.next_state, now_ns=1_010)

    assert "ALT" not in result.selected


def test_grace_never_admits_an_instrument_that_is_no_longer_tradable() -> None:
    first = _select(_view(_instrument("ALT", turnover="20")), now_ns=1_000)
    result = _select(
        _view(_instrument("ALT", turnover="20", tradable=False)),
        previous=first.next_state,
        now_ns=1_010,
    )
    assert result.selected == frozenset()


@pytest.mark.parametrize(
    "listing_state",
    [ListingState.BASELINE, ListingState.RELIST_PENDING],
)
def test_eligible_episode_requires_active_new_listing_state(listing_state) -> None:
    active = _instrument("NEW", new_started_at=850)
    updates = {"listing_state": listing_state}
    if listing_state is ListingState.RELIST_PENDING:
        updates["last_terminal_seen_ns"] = 800

    with pytest.raises(ValueError, match="listing state"):
        replace(active, **updates)


def test_relist_pending_can_retain_prior_episode_without_eligibility() -> None:
    active = _instrument("NEW", new_started_at=850)

    pending = replace(
        active,
        status="delisted",
        lifecycle_phase=LifecyclePhase.DELISTED,
        tradable=False,
        last_seen_ns=900,
        listing_state=ListingState.RELIST_PENDING,
        last_terminal_seen_ns=900,
        new_listing_eligible=False,
    )

    assert pending.new_listing_started_at_ns == 850
    assert pending.last_terminal_seen_ns == 900
    with pytest.raises(ValueError, match="terminal evidence"):
        replace(active, last_terminal_seen_ns=850)


def test_delisted_lifecycle_requires_current_relist_terminal_evidence() -> None:
    active = _instrument("NEW", new_started_at=850)
    delisted = {
        "status": "delisted",
        "lifecycle_phase": LifecyclePhase.DELISTED,
        "tradable": False,
        "last_seen_ns": 900,
    }

    with pytest.raises(ValueError, match="delisted lifecycle"):
        replace(active, **delisted)
    with pytest.raises(ValueError, match="terminal.*last_seen"):
        replace(
            active,
            **delisted,
            listing_state=ListingState.RELIST_PENDING,
            last_terminal_seen_ns=899,
            new_listing_eligible=False,
        )


@pytest.mark.parametrize(
    "listing_state",
    [
        ListingState.PENDING,
        ListingState.PENDING_OFFICIAL,
        ListingState.RELIST_PENDING,
    ],
)
def test_pending_listing_states_cannot_be_tradable(listing_state) -> None:
    instrument = _instrument("ALT")
    updates = {"listing_state": listing_state}
    if listing_state is ListingState.RELIST_PENDING:
        updates["last_terminal_seen_ns"] = instrument.last_seen_ns

    with pytest.raises(ValueError, match="non-tradable"):
        replace(instrument, **updates)


def test_selector_defensively_requires_active_new_listing_state() -> None:
    corrupted = _instrument("NEW", new_started_at=850)
    object.__setattr__(corrupted, "listing_state", ListingState.RELIST_PENDING)

    result = _select(_view(corrupted), now_ns=900)

    assert result.selected == frozenset()


def test_previous_state_must_match_scope_policy_and_not_be_from_future() -> None:
    view = _view(_instrument("BTC", turnover="20"))
    first = _select(view)
    cases = [
        replace(
            first.next_state,
            scope=CatalogScope(Exchange.OKX, Market.SPOT),
            entries={},
        ),
        replace(first.next_state, policy_id="0" * 64),
        replace(first.next_state, catalog_revision=8),
        replace(first.next_state, turnover_revision=4),
    ]
    for previous in cases:
        with pytest.raises(ValueError, match="state"):
            _select(view, previous=previous)


def test_result_maps_and_nested_catalog_json_are_immutable() -> None:
    result = _select(_view(_instrument("BTC", turnover="20")))
    with pytest.raises(TypeError):
        result.entries["ETH"] = result.entry("BTC")  # type: ignore[index]
    with pytest.raises(TypeError):
        result.entry("BTC").instrument.lifecycle["native"] = {}  # type: ignore[index]
    nested = result.entry("BTC").instrument.lifecycle["native"]
    assert not isinstance(nested, dict)


def test_result_delta_contains_full_previous_and_current_values() -> None:
    first = _select(_view(_instrument("ALT", turnover="20")), now_ns=1_000)
    second = _select(
        _view(_instrument("ALT", turnover="10"), _instrument("BTC", turnover="20")),
        previous=first.next_state,
        now_ns=1_010,
    )
    by_key = {delta.instrument_key: delta for delta in second.deltas}
    assert by_key["ALT"].previous == first.entry("ALT")
    assert by_key["ALT"].current == second.entry("ALT")
    assert by_key["BTC"].previous is None
    assert by_key["BTC"].current == second.entry("BTC")


def test_selection_result_rejects_delta_that_contradicts_current_entries() -> None:
    result = _select(_view(_instrument("BTC", turnover="20")))
    contradictory = SelectionDelta(
        instrument_key="BTC",
        previous=result.entry("BTC"),
        current=None,
    )

    with pytest.raises(ValueError, match="delta current"):
        replace(result, deltas=(contradictory,))


def test_policy_id_is_canonical_scope_independent_and_quote_order_sensitive() -> None:
    first = _policy(quotes=("USDT", "USD"))
    same_values_other_scope = _policy(
        scope=CatalogScope(Exchange.OKX, Market.PERPETUAL),
        quotes=("USDT", "USD"),
    )
    reordered = _policy(quotes=("USD", "USDT"))
    assert re.fullmatch(r"[0-9a-f]{64}", first.policy_id)
    assert first.policy_id == same_values_other_scope.policy_id
    assert first.policy_id != reordered.policy_id


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("top_n", True),
        ("top_n", 1.0),
        ("turnover_max_age_ns", True),
        ("turnover_max_age_ns", 1.0),
        ("new_listing_capture_duration_ns", True),
        ("new_listing_capture_duration_ns", 1.0),
        ("exit_grace_ns", True),
        ("exit_grace_ns", 1.0),
    ],
)
def test_policy_rejects_boolean_and_float_integers(field: str, value: object) -> None:
    arguments: dict[str, object] = {
        "scope": SCOPE,
        "quote_assets": ("USDT",),
        "top_n": 1,
        "turnover_max_age_ns": 200,
        "new_listings_enabled": True,
        "new_listing_capture_duration_ns": 100,
        "exit_grace_ns": 30,
    }
    arguments[field] = value
    with pytest.raises((TypeError, ValueError)):
        SelectionPolicy(**arguments)  # type: ignore[arg-type]


def test_selector_rejects_boolean_and_float_now() -> None:
    view = _view(_instrument("BTC", turnover="20"))
    for value in (True, 1.0):
        with pytest.raises((TypeError, ValueError)):
            _select(view, now_ns=value)  # type: ignore[arg-type]


def test_policy_rejects_blank_or_casefold_duplicate_quotes() -> None:
    for quotes in (("  ",), ("USDT", "usdt")):
        with pytest.raises(ValueError):
            _policy(quotes=quotes)


def test_value_objects_reject_mutable_or_invalid_collections() -> None:
    with pytest.raises(TypeError):
        ResolvedFixedSelection(SCOPE, 7, {"BTC"})  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        SelectionState(
            scope=SCOPE,
            catalog_revision=7,
            turnover_revision=3,
            policy_id="a" * 64,
            revision=1,
            entries={"BTC": object()},  # type: ignore[dict-item]
        )
    with pytest.raises(ValueError):
        SelectionEntry(
            instrument=_instrument("BTC"),
            reasons=SelectionReason(0),
            top_n_rank=None,
            top_exit_started_at_ns=None,
        )


def test_selection_package_exports_the_supported_public_boundary() -> None:
    assert selection_package.CatalogStore is CatalogStore
    assert selection_package.SelectionPolicy is SelectionPolicy
    assert selection_package.ResolvedFixedSelection is ResolvedFixedSelection
    assert selection_package.select is select
