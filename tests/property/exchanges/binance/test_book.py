from __future__ import annotations

from dataclasses import replace
from decimal import Decimal

from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.domain import IntegrityMode, Market
from crypto_collector.exchanges.binance.book import (
    BinanceBookDiff,
    BinanceBookLevel,
    BinanceBookSnapshot,
    BinanceBookState,
    BookAction,
    BookOutcome,
)


def level(price: str, quantity: str) -> BinanceBookLevel:
    return BinanceBookLevel(Decimal(price), Decimal(quantity), (price, quantity))


def message(
    market: Market,
    *,
    first: int,
    final: int,
    previous: int | None,
    quantity: str,
) -> BinanceBookDiff:
    return BinanceBookDiff(
        market=market,
        symbol="BTCUSDT",
        first_update_id=first,
        final_update_id=final,
        previous_final_update_id=previous,
        bids=(level("10.00000000", quantity),),
        asks=(),
        event_time_ns=1,
    )


def legal_chain(
    market: Market,
    *,
    start: int,
    steps: list[tuple[int, int]],
) -> tuple[BinanceBookDiff, ...]:
    chain: list[BinanceBookDiff] = []
    previous = start
    for index, (advance, quantity) in enumerate(steps):
        current = previous + advance
        chain.append(
            message(
                market,
                first=previous - 1 if index == 0 else previous + 1,
                final=current,
                previous=(
                    None
                    if market is Market.SPOT
                    else previous - 2
                    if index == 0
                    else previous
                ),
                quantity=str(quantity),
            )
        )
        previous = current
    return tuple(chain)


def replay(
    market: Market,
    *,
    start: int,
    chain: tuple[BinanceBookDiff, ...],
) -> tuple[tuple[BookOutcome, ...], tuple[BinanceBookLevel, ...], int | None]:
    state = BinanceBookState(market, "BTCUSDT")
    state.apply_snapshot(
        BinanceBookSnapshot(
            start,
            (level("10.00000000", "1"),),
            (level("11.00000000", "1"),),
        )
    )
    outcomes = tuple(state.apply(item) for item in chain)
    return outcomes, state.bids, state.last_update_id


@given(
    market=st.sampled_from((Market.SPOT, Market.PERPETUAL)),
    start=st.integers(min_value=10, max_value=2**31),
    steps=st.lists(
        st.tuples(
            st.integers(min_value=1, max_value=1000),
            st.integers(min_value=1, max_value=1_000_000),
        ),
        min_size=1,
        max_size=30,
    ),
)
def test_generated_legal_chain_mutated_link_and_authoritative_reset(
    market: Market,
    start: int,
    steps: list[tuple[int, int]],
) -> None:
    chain = legal_chain(market, start=start, steps=steps)

    first_replay = replay(market, start=start, chain=chain)
    second_replay = replay(market, start=start, chain=chain)

    assert first_replay == second_replay
    outcomes, bids, last = first_replay
    assert all(
        outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED
        and outcome.generation_valid
        for outcome in outcomes
    )
    assert last is not None
    assert bids
    assert all(type(item.price) is Decimal for item in bids)
    assert all(type(item.quantity) is Decimal for item in bids)
    assert all(type(field) is str for item in bids for field in item.fields)

    state = BinanceBookState(market, "BTCUSDT")
    snapshot = BinanceBookSnapshot(
        start,
        (level("10.00000000", "1"),),
        (level("11.00000000", "1"),),
    )
    assert state.apply_snapshot(snapshot).integrity is IntegrityMode.SNAPSHOT_CHAIN
    for item in chain:
        assert state.apply(item).integrity is IntegrityMode.SEQUENCE_VERIFIED

    before_duplicate = (state.bids, state.asks, state.last_update_id)
    duplicate = state.apply(chain[-1])
    assert duplicate.action is BookAction.IGNORE_STALE
    assert (state.bids, state.asks, state.last_update_id) == before_duplicate

    if market is Market.SPOT:
        conflict_state = BinanceBookState(market, "BTCUSDT")
        conflict_state.apply_snapshot(snapshot)
        for item in chain:
            conflict_state.apply(item)
        last_message = chain[-1]
        conflict = message(
            market,
            first=last_message.first_update_id,
            final=last_message.final_update_id,
            previous=None,
            quantity=str(int(steps[-1][1]) + 1),
        )

        conflict_outcome = conflict_state.apply(conflict)

        assert conflict_outcome.integrity is IntegrityMode.INVALID
        assert conflict_outcome.action is BookAction.FETCH_BOOTSTRAP
        assert conflict_outcome.control_reason == "sequence_conflict"

    symbol_state = BinanceBookState(market, "BTCUSDT")
    symbol_state.apply_snapshot(snapshot)
    for item in chain:
        symbol_state.apply(item)

    symbol_outcome = symbol_state.apply(replace(chain[-1], symbol="ETHUSDT"))

    assert symbol_outcome.integrity is IntegrityMode.INVALID
    assert symbol_outcome.action is BookAction.FETCH_BOOTSTRAP
    assert symbol_outcome.control_reason == "symbol_mismatch"

    if market is Market.SPOT:
        broken = message(
            market,
            first=last + 2,
            final=last + 2,
            previous=None,
            quantity="2",
        )
        ordinary = message(
            market,
            first=last + 1,
            final=last + 1,
            previous=None,
            quantity="3",
        )
    else:
        broken = message(
            market,
            first=last + 1,
            final=last + 1,
            previous=last - 1,
            quantity="2",
        )
        ordinary = message(
            market,
            first=last + 1,
            final=last + 1,
            previous=last,
            quantity="3",
        )

    invalid = state.apply(broken)
    still_invalid = state.apply(ordinary)

    assert invalid.integrity is IntegrityMode.INVALID
    assert invalid.action is BookAction.FETCH_BOOTSTRAP
    assert not invalid.generation_valid
    assert still_invalid.integrity is IntegrityMode.INVALID
    assert not still_invalid.generation_valid

    reset_id = last + 1000
    reset = state.apply_snapshot(
        BinanceBookSnapshot(
            reset_id,
            (level("20.00000000", "1"),),
            (level("21.00000000", "1"),),
        )
    )
    restored = state.apply(
        message(
            market,
            first=reset_id - 1,
            final=reset_id + 1,
            previous=None if market is Market.SPOT else reset_id - 2,
            quantity="4",
        )
    )

    assert reset.action is BookAction.SNAPSHOT
    assert reset.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert restored.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert restored.generation_valid


@given(
    integer=st.integers(min_value=1, max_value=10**18),
    fraction=st.integers(min_value=0, max_value=999_999_999),
)
def test_decimal_level_strings_never_pass_through_binary_float(
    integer: int, fraction: int
) -> None:
    price = f"{integer}.{fraction:09d}"
    parsed = level(price, "0.000000001")

    assert parsed.price == Decimal(price)
    assert parsed.quantity == Decimal("0.000000001")
    assert parsed.fields == (price, "0.000000001")
    assert type(parsed.price) is Decimal
    assert type(parsed.quantity) is Decimal
