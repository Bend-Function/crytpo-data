from __future__ import annotations

from collections.abc import Mapping
from decimal import Decimal
from pathlib import Path
from typing import cast

import pytest

from crypto_collector.domain import IntegrityMode, Market
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.exchanges.binance.book import (
    BinanceBookDiff,
    BinanceBookLevel,
    BinanceBookParseError,
    BinanceBookSnapshot,
    BinanceFuturesBook,
    BinanceSpotBook,
    BinanceSpotBookBootstrap,
    BookAction,
    parse_book_diff,
    parse_book_snapshot,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "binance"


def level(price: str, quantity: str) -> BinanceBookLevel:
    return BinanceBookLevel(
        Decimal(price),
        Decimal(quantity),
        (price, quantity),
    )


def diff(
    market: Market,
    *,
    first: int,
    final: int,
    previous: int | None = None,
    bids: tuple[BinanceBookLevel, ...] = (),
    asks: tuple[BinanceBookLevel, ...] = (),
    symbol: str = "BTCUSDT",
) -> BinanceBookDiff:
    return BinanceBookDiff(
        market=market,
        symbol=symbol,
        first_update_id=first,
        final_update_id=final,
        previous_final_update_id=previous,
        bids=bids,
        asks=asks,
        event_time_ns=1,
    )


def seeded_spot(*, last: int = 100) -> BinanceSpotBook:
    state = BinanceSpotBook("BTCUSDT")
    state.apply_snapshot(
        BinanceBookSnapshot(
            last,
            (level("10", "1"),),
            (level("11", "1"),),
        )
    )
    return state


def seeded_futures(*, last: int = 200) -> BinanceFuturesBook:
    state = BinanceFuturesBook("BTCUSDT")
    state.apply_snapshot(
        BinanceBookSnapshot(
            last,
            (level("10", "1"),),
            (level("11", "1"),),
        )
    )
    return state


def test_spot_bootstrap_accepts_covering_first_event() -> None:
    state = BinanceSpotBookBootstrap(snapshot_last_update_id=100, symbol="BTCUSDT")

    first = state.apply(diff(Market.SPOT, first=99, final=101))
    second = state.apply(diff(Market.SPOT, first=102, final=103))

    assert first.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert second.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert state.last_update_id == 103


def test_spot_discards_stale_bootstrap_events_before_covering_event() -> None:
    state = seeded_spot()

    stale = state.apply(diff(Market.SPOT, first=98, final=100))
    covering = state.apply(diff(Market.SPOT, first=99, final=102))

    assert stale.action is BookAction.IGNORE_STALE
    assert stale.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert covering.action is BookAction.APPLY


def test_spot_gap_invalidates_generation_and_update_is_atomic() -> None:
    state = seeded_spot()
    state.apply(diff(Market.SPOT, first=99, final=101))

    outcome = state.apply(
        diff(
            Market.SPOT,
            first=103,
            final=104,
            bids=(level("10", "9"),),
        )
    )

    assert outcome.integrity is IntegrityMode.INVALID
    assert outcome.action is BookAction.FETCH_BOOTSTRAP
    assert outcome.control_reason == "sequence_gap"
    assert not outcome.generation_valid
    assert state.bids[0].quantity == Decimal(1)
    assert state.last_update_id == 101


def test_invalid_spot_generation_cannot_be_repaired_by_ordinary_delta() -> None:
    state = seeded_spot()
    state.apply(diff(Market.SPOT, first=99, final=101))
    state.apply(diff(Market.SPOT, first=103, final=104))

    still_invalid = state.apply(diff(Market.SPOT, first=102, final=105))
    reset = state.apply_snapshot(
        BinanceBookSnapshot(500, (level("20", "1"),), (level("21", "1"),))
    )
    restored = state.apply(diff(Market.SPOT, first=499, final=501))

    assert still_invalid.integrity is IntegrityMode.INVALID
    assert reset.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert restored.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert state.last_update_id == 501


def test_futures_requires_previous_u_link_after_covering_bootstrap() -> None:
    state = seeded_futures()

    first = state.apply(diff(Market.PERPETUAL, first=199, final=201, previous=198))
    linked = state.apply(diff(Market.PERPETUAL, first=202, final=203, previous=201))
    mismatch = state.apply(diff(Market.PERPETUAL, first=204, final=205, previous=199))

    assert first.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert linked.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert mismatch.integrity is IntegrityMode.INVALID
    assert mismatch.action is BookAction.FETCH_BOOTSTRAP
    assert mismatch.control_reason == "previous_update_id_mismatch"


def test_futures_regression_invalidates_even_when_pu_matches() -> None:
    state = seeded_futures()
    state.apply(diff(Market.PERPETUAL, first=199, final=201, previous=198))

    outcome = state.apply(diff(Market.PERPETUAL, first=201, final=201, previous=201))

    assert outcome.integrity is IntegrityMode.INVALID
    assert outcome.control_reason == "sequence_regression"


def test_absolute_quantities_replace_and_zero_deletes_missing_or_existing_levels() -> (
    None
):
    state = seeded_spot()
    state.apply(diff(Market.SPOT, first=99, final=101))

    outcome = state.apply(
        diff(
            Market.SPOT,
            first=102,
            final=102,
            bids=(level("10", "2.500"), level("9", "0")),
            asks=(level("11", "0"),),
        )
    )

    assert outcome.action is BookAction.APPLY
    assert state.bids[0].quantity == Decimal("2.500")
    assert state.asks == ()


def test_same_futures_event_is_idempotent_without_changing_book() -> None:
    state = seeded_futures()
    message = diff(
        Market.PERPETUAL,
        first=199,
        final=201,
        previous=198,
        bids=(level("10", "2"),),
    )

    first = state.apply(message)
    duplicate = state.apply(message)

    assert first.action is BookAction.APPLY
    assert duplicate.action is BookAction.IGNORE_STALE
    assert state.bids[0].quantity == Decimal(2)
    assert state.last_update_id == 201


def test_same_spot_u_with_conflicting_payload_invalidates_generation() -> None:
    state = seeded_spot()
    accepted = diff(
        Market.SPOT,
        first=99,
        final=101,
        bids=(level("10", "2"),),
    )
    conflict = diff(
        Market.SPOT,
        first=99,
        final=101,
        bids=(level("10", "3"),),
    )

    assert state.apply(accepted).action is BookAction.APPLY
    outcome = state.apply(conflict)

    assert outcome.action is BookAction.FETCH_BOOTSTRAP
    assert outcome.integrity is IntegrityMode.INVALID
    assert outcome.control_reason == "sequence_conflict"
    assert state.bids[0].quantity == Decimal(2)


def test_cross_symbol_diff_invalidates_bound_generation() -> None:
    state = seeded_spot()

    outcome = state.apply(diff(Market.SPOT, first=99, final=101, symbol="ETHUSDT"))

    assert outcome.action is BookAction.FETCH_BOOTSTRAP
    assert outcome.integrity is IntegrityMode.INVALID
    assert outcome.control_reason == "symbol_mismatch"
    assert state.last_update_id == 100


def test_snapshot_fixtures_parse_decimal_strings_and_futures_times() -> None:
    spot = parse_book_snapshot(
        decode_json((_FIXTURES / "spot-depth.json").read_bytes()),
        Market.SPOT,
    )
    futures = parse_book_snapshot(
        decode_json((_FIXTURES / "futures-depth.json").read_bytes()),
        Market.PERPETUAL,
    )

    assert spot.last_update_id == 1_027_024
    assert spot.bids[0].price == Decimal("4.00000000")
    assert type(spot.bids[0].price) is Decimal
    assert spot.bids[0].fields == ("4.00000000", "431.00000000")
    assert futures.event_time_ns == 1_589_436_922_972_000_000
    assert futures.transaction_time_ns == 1_589_436_922_959_000_000


@pytest.mark.parametrize("missing", ["E", "T"])
def test_futures_snapshot_requires_both_exchange_times(missing: str) -> None:
    payload = {
        "lastUpdateId": 1,
        "E": 2,
        "T": 3,
        "bids": [],
        "asks": [],
    }
    del payload[missing]

    with pytest.raises(BinanceBookParseError, match=missing):
        parse_book_snapshot(payload, Market.PERPETUAL)


def test_ws_diff_fixture_preserves_sequence_and_native_level_strings() -> None:
    frames = decode_json((_FIXTURES / "ws-session.json").read_bytes())
    assert isinstance(frames, Mapping)
    envelope = decode_json(cast(str, frames["futures_depth"]))
    assert isinstance(envelope, Mapping)

    parsed = parse_book_diff(envelope["data"], Market.PERPETUAL)

    assert parsed.first_update_id == 201
    assert parsed.final_update_id == 202
    assert parsed.previous_final_update_id == 200
    assert parsed.bids[0].fields == ("20000.10", "1.25")
    assert parsed.asks[0].quantity == 0


@pytest.mark.parametrize(
    "payload",
    [
        {"lastUpdateId": 1, "bids": [[10.0, "1"]], "asks": []},
        {"lastUpdateId": 1, "bids": [["10", "NaN"]], "asks": []},
        {"lastUpdateId": 1, "bids": [["10", "0"]], "asks": []},
        {"lastUpdateId": True, "bids": [], "asks": []},
    ],
)
def test_snapshot_type_or_decimal_drift_fails_closed(payload: object) -> None:
    with pytest.raises(BinanceBookParseError):
        parse_book_snapshot(payload, Market.SPOT)


def test_diff_market_fields_are_exact_and_futures_pu_is_required() -> None:
    spot_with_pu = {
        "e": "depthUpdate",
        "E": 1,
        "s": "BTCUSDT",
        "U": 1,
        "u": 2,
        "pu": 0,
        "b": [],
        "a": [],
    }
    del spot_with_pu["pu"]
    futures_without_pu = dict(spot_with_pu)

    assert parse_book_diff(spot_with_pu, Market.SPOT).previous_final_update_id is None
    with pytest.raises(BinanceBookParseError, match="pu"):
        parse_book_diff(futures_without_pu, Market.PERPETUAL)
