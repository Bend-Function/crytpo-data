from __future__ import annotations

from decimal import Decimal

from hypothesis import assume, given
from hypothesis import strategies as st

from crypto_collector.domain import IntegrityMode
from crypto_collector.exchanges.bitget.book import (
    BitgetBook,
    BitgetBookFrame,
    BitgetBookLevel,
    BookAction,
)


def _frame(*, action: str, pseq: int, seq: int, quantity: str = "1") -> BitgetBookFrame:
    level = BitgetBookLevel(
        price=Decimal(10),
        quantity=Decimal(quantity),
        fields=("10", quantity),
    )
    return BitgetBookFrame(
        action=action,
        bids=(level,),
        asks=(),
        timestamp_ns=1,
        pseq=pseq,
        seq=seq,
        max_depth=1_000,
    )


@given(
    snapshot_seq=st.integers(min_value=1, max_value=2**31),
    left_overlap=st.integers(min_value=0, max_value=100),
    first_advance=st.integers(min_value=0, max_value=10_000),
    advances=st.lists(
        st.integers(min_value=1, max_value=10_000),
        min_size=0,
        max_size=100,
    ),
)
def test_documented_overlap_then_exact_links_remain_valid(
    snapshot_seq: int,
    left_overlap: int,
    first_advance: int,
    advances: list[int],
) -> None:
    state = BitgetBook()
    state.apply(_frame(action="snapshot", pseq=0, seq=snapshot_seq))
    first_seq = snapshot_seq + first_advance
    first_pseq = max(0, snapshot_seq - left_overlap)
    assume(first_seq > first_pseq)
    first = state.apply(_frame(action="update", pseq=first_pseq, seq=first_seq))
    assert first.integrity is IntegrityMode.SEQUENCE_VERIFIED

    previous = first_seq
    for advance in advances:
        current = previous + advance
        outcome = state.apply(_frame(action="update", pseq=previous, seq=current))
        assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED
        assert outcome.generation_valid
        previous = current


@given(
    snapshot_seq=st.integers(min_value=2, max_value=2**31),
    mismatch=st.integers(min_value=1, max_value=10_000),
)
def test_first_mismatch_is_invalid_and_sticky(
    snapshot_seq: int,
    mismatch: int,
) -> None:
    state = BitgetBook()
    state.apply(_frame(action="snapshot", pseq=0, seq=snapshot_seq))
    rejected = state.apply(
        _frame(
            action="update",
            pseq=snapshot_seq + mismatch,
            seq=snapshot_seq + mismatch + 1,
        )
    )
    still_invalid = state.apply(
        _frame(action="update", pseq=snapshot_seq, seq=snapshot_seq + 1)
    )

    assert rejected.action is BookAction.RESUBSCRIBE
    assert rejected.integrity is IntegrityMode.INVALID
    assert still_invalid.control_reason == "book_generation_invalid"


@given(
    snapshot_seq=st.integers(min_value=1, max_value=2**31),
    quantity=st.sampled_from(("0", "0.0", "1", "123.456")),
)
def test_level_quantity_never_changes_sequence_decision(
    snapshot_seq: int,
    quantity: str,
) -> None:
    first = BitgetBook()
    second = BitgetBook()
    snapshot = _frame(action="snapshot", pseq=0, seq=snapshot_seq)
    update = _frame(
        action="update",
        pseq=snapshot_seq,
        seq=snapshot_seq + 1,
        quantity=quantity,
    )

    outcomes = []
    for state in (first, second):
        outcomes.append((state.apply(snapshot), state.apply(update)))

    assert outcomes[0] == outcomes[1]
    assert outcomes[0][1].integrity is IntegrityMode.SEQUENCE_VERIFIED
