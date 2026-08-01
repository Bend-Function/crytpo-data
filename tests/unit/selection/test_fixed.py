from __future__ import annotations

from dataclasses import replace

import pytest

from crypto_collector.selection.fixed import (
    FixedPairResolutionError,
    resolve_fixed_requests,
)
from crypto_collector.selection.models import (
    CatalogInstrument,
    CatalogScope,
    CatalogView,
    LifecyclePhase,
    ListingState,
)

SCOPE = CatalogScope("binance", "spot")


def instrument(
    key: str,
    pair: str,
    *,
    present: bool = True,
    tradable: bool = True,
) -> CatalogInstrument:
    return CatalogInstrument(
        exchange=SCOPE.exchange,
        market=SCOPE.market,
        instrument_key=key,
        canonical_pair=pair,
        wire_symbols={"rest": key},
        base_asset=pair.partition("/")[0],
        quote_asset=pair.partition("/")[2],
        settlement_asset=None,
        status="trading" if tradable else "paused",
        lifecycle_phase=(
            LifecyclePhase.TRADABLE if tradable else LifecyclePhase.PAUSED
        ),
        tradable=tradable,
        lifecycle={"status": "trading" if tradable else "paused"},
        tradable_at_ns=None,
        tradable_at_source=None,
        turnover=None,
        raw_catalog_reference=f"raw/catalog/{key}",
        first_seen_ns=100,
        last_seen_ns=200 if present else 100,
        present=present,
        listing_state=ListingState.BASELINE,
    )


def view(*items: CatalogInstrument, revision: int = 7) -> CatalogView:
    normalized = tuple(
        replace(item, last_seen_ns=200) if item.present else item for item in items
    )
    return CatalogView(
        scope=SCOPE,
        catalog_observed_at_ns=200,
        catalog_revision=revision,
        catalog_digest_sha256="a" * 64,
        catalog_snapshot_id="catalog-200",
        catalog_page_raw_references=("raw/catalog-200",),
        turnover_observed_at_ns=None,
        turnover_revision=0,
        turnover_digest_sha256=None,
        turnover_catalog_revision=None,
        turnover_snapshot_id=None,
        turnover_page_raw_references=(),
        turnover_covered_instrument_keys=(),
        instruments=normalized,
    )


def test_canonical_fixed_pair_resolves_to_one_stable_instrument_key() -> None:
    catalog = view(instrument("BTC-USDT", "BTC/USDT"))

    result = resolve_fixed_requests(("BTC/USDT",), catalog)

    assert result.scope == SCOPE
    assert result.catalog_revision == 7
    assert result.instrument_keys == frozenset({"BTC-USDT"})


def test_exact_stable_key_wins_before_canonical_pair_matching() -> None:
    catalog = view(
        instrument("BTC/USDT", "LEGACY/USDT"),
        instrument("BTC-USDT", "BTC/USDT"),
        instrument("XBT-USDT", "BTC/USDT"),
    )

    result = resolve_fixed_requests(("BTC/USDT",), catalog)

    assert result.instrument_keys == frozenset({"BTC/USDT"})


@pytest.mark.parametrize(
    ("fixed_request", "expected_candidates"),
    [
        ("UNKNOWN/USDT", ()),
        ("AMBIGUOUS/USDT", ("ALT-A", "ALT-B")),
        ("PAUSED/USDT", ("PAUSED",)),
    ],
)
def test_unknown_ambiguous_or_nontradable_request_fails_with_candidates(
    fixed_request: str,
    expected_candidates: tuple[str, ...],
) -> None:
    catalog = view(
        instrument("ALT-B", "AMBIGUOUS/USDT"),
        instrument("ALT-A", "AMBIGUOUS/USDT"),
        instrument("PAUSED", "PAUSED/USDT", tradable=False),
    )

    with pytest.raises(FixedPairResolutionError) as captured:
        resolve_fixed_requests((fixed_request,), catalog)

    assert captured.value.request == fixed_request
    assert captured.value.scope == SCOPE
    assert captured.value.candidate_keys == expected_candidates


def test_exact_nontradable_key_does_not_fall_back_to_pair_match() -> None:
    catalog = view(
        instrument("TARGET/USDT", "OTHER/USDT", tradable=False),
        instrument("OTHER", "TARGET/USDT"),
    )

    with pytest.raises(FixedPairResolutionError) as captured:
        resolve_fixed_requests(("TARGET/USDT",), catalog)

    assert captured.value.candidate_keys == ("TARGET/USDT",)


def test_multiple_requests_may_resolve_to_the_same_union_member() -> None:
    catalog = view(instrument("BTC-USDT", "BTC/USDT"))

    result = resolve_fixed_requests(("BTC-USDT", "BTC/USDT"), catalog)

    assert result.instrument_keys == frozenset({"BTC-USDT"})


@pytest.mark.parametrize("requests", [[], ("",), (" BTC/USDT",), (1,)])
def test_fixed_requests_are_strict_normalized_tuples(requests: object) -> None:
    with pytest.raises((TypeError, ValueError)):
        resolve_fixed_requests(requests, view(instrument("BTC", "BTC/USDT")))  # type: ignore[arg-type]
