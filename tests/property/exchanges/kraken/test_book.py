from __future__ import annotations

from decimal import Decimal

from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_collector.domain import IntegrityMode
from crypto_collector.exchanges.kraken import (
    KrakenBookAction,
    KrakenBookLevel,
    KrakenFuturesBook,
    KrakenFuturesBookFrame,
    KrakenSpotBook,
    KrakenSpotBookFrame,
    kraken_spot_checksum_input,
    kraken_spot_crc32,
)


def level(price: str, quantity: str) -> KrakenBookLevel:
    return KrakenBookLevel(Decimal(price), Decimal(quantity), price, quantity)


def spot_crc(
    asks: tuple[KrakenBookLevel, ...],
    bids: tuple[KrakenBookLevel, ...],
) -> int:
    return kraken_spot_crc32(
        kraken_spot_checksum_input(
            ((item.raw_price, item.raw_quantity) for item in asks[:10]),
            ((item.raw_price, item.raw_quantity) for item in bids[:10]),
        )
    )


def spot_frame(
    *,
    action: str,
    bids: tuple[KrakenBookLevel, ...],
    asks: tuple[KrakenBookLevel, ...],
    checksum: int,
) -> KrakenSpotBookFrame:
    return KrakenSpotBookFrame(
        action=action,
        symbol="BTC/USDT",
        bids=bids,
        asks=asks,
        checksum=checksum,
        timestamp_ns=None,
    )


@settings(max_examples=75, deadline=None)
@given(
    bid_price=st.integers(min_value=10, max_value=10_000),
    quantities=st.lists(
        st.integers(min_value=1, max_value=99_999_999),
        min_size=1,
        max_size=20,
    ),
)
def test_spot_generated_checksum_chain_is_exact_sticky_and_deterministic(
    bid_price: int,
    quantities: list[int],
) -> None:
    bid_raw = f"{bid_price}.00000000"
    ask_raw = f"{bid_price + 1}.00000000"
    ask = level(ask_raw, "1.00000000")
    initial_bid = level(bid_raw, "1.00000000")
    snapshot = spot_frame(
        action="snapshot",
        bids=(initial_bid,),
        asks=(ask,),
        checksum=spot_crc((ask,), (initial_bid,)),
    )
    legal: list[KrakenSpotBookFrame] = [snapshot]
    final_bid = initial_bid
    for quantity in quantities:
        final_bid = level(bid_raw, f"0.{quantity:08d}")
        legal.append(
            spot_frame(
                action="update",
                bids=(final_bid,),
                asks=(),
                checksum=spot_crc((ask,), (final_bid,)),
            )
        )

    first = KrakenSpotBook(depth=10, symbol="BTC/USDT")
    second = KrakenSpotBook(depth=10, symbol="BTC/USDT")
    first_outcomes = tuple(first.apply(item) for item in legal)
    second_outcomes = tuple(second.apply(item) for item in legal)

    assert first_outcomes == second_outcomes
    assert first.bids == second.bids == (final_bid,)
    assert first.asks == second.asks == (ask,)
    assert all(
        outcome.integrity is IntegrityMode.CHECKSUM_VERIFIED
        for outcome in first_outcomes
    )
    assert all(
        type(value) is Decimal
        for item in (*first.bids, *first.asks)
        for value in (item.price, item.quantity)
    )

    mutated_bid = level(bid_raw, "2.00000000")
    correct_checksum = spot_crc((ask,), (mutated_bid,))
    broken = spot_frame(
        action="update",
        bids=(mutated_bid,),
        asks=(),
        checksum=correct_checksum ^ 1,
    )
    mismatch = first.apply(broken)
    sticky = first.apply(
        spot_frame(
            action="update",
            bids=(mutated_bid,),
            asks=(),
            checksum=correct_checksum,
        )
    )
    reset_bid = level(f"{bid_price + 10}.00000000", "1.00000000")
    reset_ask = level(f"{bid_price + 11}.00000000", "1.00000000")
    restored = first.apply(
        spot_frame(
            action="snapshot",
            bids=(reset_bid,),
            asks=(reset_ask,),
            checksum=spot_crc((reset_ask,), (reset_bid,)),
        )
    )

    assert mismatch.integrity is IntegrityMode.INVALID
    assert mismatch.control_reason == "book_checksum_mismatch"
    assert sticky.integrity is IntegrityMode.INVALID
    assert sticky.control_reason == "book_generation_invalid"
    assert restored.action is KrakenBookAction.SNAPSHOT
    assert restored.integrity is IntegrityMode.CHECKSUM_VERIFIED


def futures_frame(
    *,
    action: str,
    sequence: int,
    quantity: int,
) -> KrakenFuturesBookFrame:
    return KrakenFuturesBookFrame(
        action=action,
        product_id="PF_XBTUSD",
        bids=(level("10.00000000", f"{quantity}.00000000"),),
        asks=(level("11.00000000", "1.00000000"),) if action == "snapshot" else (),
        timestamp_ns=1,
        sequence_id=sequence,
    )


@settings(max_examples=75, deadline=None)
@given(
    start=st.integers(min_value=1, max_value=2**31),
    advances=st.lists(
        st.integers(min_value=1, max_value=10_000),
        min_size=1,
        max_size=30,
    ),
)
def test_futures_generated_sequence_chain_accepts_gaps_but_rejects_regression(
    start: int,
    advances: list[int],
) -> None:
    legal = [futures_frame(action="snapshot", sequence=start, quantity=1)]
    current = start
    for index, advance in enumerate(advances, start=2):
        current += advance
        legal.append(futures_frame(action="update", sequence=current, quantity=index))

    first = KrakenFuturesBook(product_id="PF_XBTUSD")
    second = KrakenFuturesBook(product_id="PF_XBTUSD")
    first_outcomes = tuple(first.apply(item) for item in legal)
    second_outcomes = tuple(second.apply(item) for item in legal)

    assert first_outcomes == second_outcomes
    assert first.bids == second.bids
    assert first.sequence_id == second.sequence_id == current
    assert first_outcomes[0].integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert all(
        outcome.integrity is IntegrityMode.BEST_EFFORT for outcome in first_outcomes[1:]
    )
    assert all(
        type(value) is Decimal
        for item in (*first.bids, *first.asks)
        for value in (item.price, item.quantity)
    )

    regression = first.apply(
        futures_frame(action="update", sequence=current, quantity=999)
    )
    sticky = first.apply(
        futures_frame(action="update", sequence=current + 1, quantity=1000)
    )
    restored = first.apply(
        KrakenFuturesBookFrame(
            action="snapshot",
            product_id="PF_XBTUSD",
            bids=(level("20.00000000", "1.00000000"),),
            asks=(level("21.00000000", "1.00000000"),),
            timestamp_ns=2,
            sequence_id=current + 100,
        )
    )

    assert regression.integrity is IntegrityMode.INVALID
    assert regression.control_reason == "book_sequence_regression"
    assert sticky.integrity is IntegrityMode.INVALID
    assert sticky.control_reason == "book_generation_invalid"
    assert restored.action is KrakenBookAction.SNAPSHOT
    assert restored.integrity is IntegrityMode.SNAPSHOT_CHAIN
