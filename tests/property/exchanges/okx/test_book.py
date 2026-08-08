from __future__ import annotations

from decimal import Decimal

from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.domain import IntegrityMode
from crypto_collector.exchanges.okx.book import (
    BookAction,
    OkxBookFrame,
    OkxBookLevel,
    OkxBookState,
)


def frame(*, action: str, previous: int | None, current: int) -> OkxBookFrame:
    return OkxBookFrame(
        action=action,
        bids=(
            OkxBookLevel(
                price=Decimal(10),
                quantity=Decimal(1),
                fields=("10", "1"),
            ),
        ),
        asks=(
            OkxBookLevel(
                price=Decimal(11),
                quantity=Decimal(1),
                fields=("11", "1"),
            ),
        ),
        timestamp_ns=1,
        prev_seq_id=previous,
        seq_id=current,
        checksum=0,
    )


@given(
    start=st.integers(min_value=2, max_value=2**31),
    advances=st.lists(
        st.integers(min_value=1, max_value=10_000),
        min_size=1,
        max_size=100,
    ),
)
def test_linked_chain_stays_valid_and_first_true_mismatch_invalidates(
    start: int,
    advances: list[int],
) -> None:
    state = OkxBookState()
    state.apply(frame(action="snapshot", previous=-1, current=start))
    previous = start
    for advance in advances:
        current = previous + advance
        outcome = state.apply(
            frame(action="update", previous=previous, current=current)
        )
        assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED
        assert outcome.generation_valid
        previous = current

    mismatch = state.apply(
        frame(action="update", previous=previous - 1, current=previous + 1)
    )
    assert mismatch.integrity is IntegrityMode.INVALID
    assert mismatch.action is BookAction.RECONNECT
    assert not mismatch.generation_valid
