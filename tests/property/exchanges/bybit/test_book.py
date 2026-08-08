from __future__ import annotations

from decimal import Decimal
from typing import Literal

from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.domain import IntegrityMode
from crypto_collector.exchanges.bybit.book import (
    BybitBookAction,
    BybitBookAvailability,
    BybitBookLevel,
    BybitFullBookDelta,
    BybitFullBookSnapshot,
    BybitFullBookState,
    BybitStandardBookFrame,
    BybitStandardBookState,
    BybitStandardMessageKind,
)


def _level(price: int, quantity: int) -> BybitBookLevel:
    price_text = str(price)
    quantity_text = str(quantity)
    return BybitBookLevel(
        price=Decimal(price_text),
        quantity=Decimal(quantity_text),
        fields=(price_text, quantity_text),
    )


def _standard_frame(
    *,
    kind: BybitStandardMessageKind,
    depth: int,
    update_id: int,
    sequence_id: int,
    bid_quantity: int,
    ask_quantity: int,
) -> BybitStandardBookFrame:
    return BybitStandardBookFrame(
        topic=f"orderbook.{depth}.BTCUSDT",
        depth=depth,
        symbol="BTCUSDT",
        kind=kind,
        bids=(_level(10, bid_quantity),),
        asks=(_level(11, ask_quantity),),
        timestamp_ns=sequence_id,
        matching_timestamp_ns=sequence_id,
        update_id=update_id,
        sequence_id=sequence_id,
    )


@st.composite
def authoritative_snapshots(
    draw: st.DrawFn,
) -> BybitStandardBookFrame:
    return _standard_frame(
        kind=BybitStandardMessageKind.SNAPSHOT,
        depth=draw(st.sampled_from((50, 200, 1000))),
        update_id=draw(st.integers(min_value=1, max_value=2**31)),
        sequence_id=draw(st.integers(min_value=0, max_value=2**31)),
        bid_quantity=draw(st.integers(min_value=1, max_value=10**9)),
        ask_quantity=draw(st.integers(min_value=1, max_value=10**9)),
    )


@st.composite
def non_empty_legal_chains(
    draw: st.DrawFn,
) -> tuple[BybitStandardBookFrame, tuple[BybitStandardBookFrame, ...]]:
    depth = draw(st.sampled_from((50, 200, 1000)))
    start_u = draw(st.integers(min_value=2, max_value=10**6))
    start_seq = draw(st.integers(min_value=0, max_value=10**6))
    snapshot = _standard_frame(
        kind=BybitStandardMessageKind.SNAPSHOT,
        depth=depth,
        update_id=start_u,
        sequence_id=start_seq,
        bid_quantity=1,
        ask_quantity=1,
    )
    jumps = draw(
        st.lists(
            st.tuples(
                st.integers(min_value=1, max_value=10_000),
                st.integers(min_value=0, max_value=10_000),
                st.integers(min_value=1, max_value=10**9),
            ),
            min_size=1,
            max_size=40,
        )
    )
    update_id = start_u
    sequence_id = start_seq
    frames: list[BybitStandardBookFrame] = []
    for u_jump, seq_jump, quantity in jumps:
        update_id += u_jump
        sequence_id += seq_jump
        frames.append(
            _standard_frame(
                kind=BybitStandardMessageKind.DELTA,
                depth=depth,
                update_id=update_id,
                sequence_id=sequence_id,
                bid_quantity=quantity,
                ask_quantity=quantity,
            )
        )
    return snapshot, tuple(frames)


@st.composite
def legal_reset_or_heartbeat(
    draw: st.DrawFn,
) -> tuple[Literal["reset", "heartbeat"], BybitStandardBookFrame]:
    mode = draw(st.sampled_from(("reset", "heartbeat")))
    quantity = draw(st.integers(min_value=1, max_value=10**9))
    if mode == "reset":
        return (
            "reset",
            _standard_frame(
                kind=BybitStandardMessageKind.SNAPSHOT,
                depth=200,
                update_id=1,
                sequence_id=draw(st.integers(min_value=0, max_value=10**6)),
                bid_quantity=quantity,
                ask_quantity=quantity,
            ),
        )
    return (
        "heartbeat",
        _standard_frame(
            kind=BybitStandardMessageKind.SNAPSHOT,
            depth=1,
            update_id=draw(st.integers(min_value=2, max_value=10**6)),
            sequence_id=draw(st.integers(min_value=0, max_value=10**6)),
            bid_quantity=quantity,
            ask_quantity=quantity,
        ),
    )


def _full_delta(*, update_id: int, sequence_id: int) -> BybitFullBookDelta:
    return BybitFullBookDelta(
        topic="orderbook.full.BTCUSDT",
        symbol="BTCUSDT",
        bids=(),
        asks=(),
        timestamp_ns=sequence_id,
        matching_timestamp_ns=sequence_id,
        update_id=update_id,
        sequence_id=sequence_id,
    )


def _full_snapshot(
    *,
    update_id: int,
    sequence_id: int,
    empty: bool = False,
) -> BybitFullBookSnapshot:
    return BybitFullBookSnapshot(
        symbol="BTCUSDT",
        bids=() if empty else (_level(10, 1),),
        asks=() if empty else (_level(11, 1),),
        timestamp_ns=sequence_id,
        matching_timestamp_ns=sequence_id,
        update_id=update_id,
        sequence_id=sequence_id,
    )


@st.composite
def minimally_mutated_standard_links(
    draw: st.DrawFn,
) -> tuple[
    BybitStandardBookFrame,
    BybitStandardBookFrame,
    BybitStandardBookFrame,
]:
    start_u = draw(st.integers(min_value=2, max_value=10**6))
    start_seq = draw(st.integers(min_value=1, max_value=10**6))
    u_jump = draw(st.integers(min_value=1, max_value=10_000))
    seq_jump = draw(st.integers(min_value=1, max_value=10_000))
    snapshot = _standard_frame(
        kind=BybitStandardMessageKind.SNAPSHOT,
        depth=200,
        update_id=start_u,
        sequence_id=start_seq,
        bid_quantity=1,
        ask_quantity=1,
    )
    legal = _standard_frame(
        kind=BybitStandardMessageKind.DELTA,
        depth=200,
        update_id=start_u + u_jump,
        sequence_id=start_seq + seq_jump,
        bid_quantity=2,
        ask_quantity=2,
    )
    regression = _standard_frame(
        kind=BybitStandardMessageKind.DELTA,
        depth=200,
        update_id=legal.update_id + 1,
        sequence_id=legal.sequence_id - 1,
        bid_quantity=3,
        ask_quantity=3,
    )
    return snapshot, legal, regression


@st.composite
def minimally_mutated_links(
    draw: st.DrawFn,
) -> tuple[BybitFullBookDelta, BybitFullBookDelta, str]:
    update_id = draw(st.integers(min_value=2, max_value=10**9))
    sequence_id = draw(st.integers(min_value=1, max_value=10**9))
    mutation = draw(st.sampled_from(("u_gap", "seq_regression")))
    base = _full_delta(update_id=update_id, sequence_id=sequence_id)
    if mutation == "u_gap":
        return (
            base,
            _full_delta(update_id=update_id + 2, sequence_id=sequence_id + 1),
            mutation,
        )
    return (
        base,
        _full_delta(update_id=update_id + 1, sequence_id=sequence_id - 1),
        mutation,
    )


@given(snapshot=authoritative_snapshots())
def test_authoritative_snapshot_restores_invalid_generation_exactly(
    snapshot: BybitStandardBookFrame,
) -> None:
    state = BybitStandardBookState()
    state.invalidate("injected_gap")

    outcome = state.apply(snapshot)

    assert outcome.action is BybitBookAction.SNAPSHOT
    assert outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert outcome.generation_valid
    assert state.bids == snapshot.bids
    assert state.asks == snapshot.asks
    assert state.update_id == snapshot.update_id
    assert state.sequence_id == snapshot.sequence_id


@given(chain=non_empty_legal_chains())
def test_non_empty_standard_chain_accepts_nonconsecutive_u_and_seq(
    chain: tuple[BybitStandardBookFrame, tuple[BybitStandardBookFrame, ...]],
) -> None:
    snapshot, deltas = chain
    left = BybitStandardBookState()
    right = BybitStandardBookState()

    left_outcomes = [left.apply(snapshot), *(left.apply(delta) for delta in deltas)]
    right_outcomes = [
        right.apply(snapshot),
        *(right.apply(delta) for delta in deltas),
    ]

    assert left_outcomes == right_outcomes
    assert all(outcome.generation_valid for outcome in left_outcomes)
    assert all(
        outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN for outcome in left_outcomes
    )
    before = (left.bids, left.asks, left.update_id, left.sequence_id)
    duplicate = left.apply(deltas[-1])
    assert duplicate.action is BybitBookAction.IGNORE
    assert (left.bids, left.asks, left.update_id, left.sequence_id) == before


@given(case=legal_reset_or_heartbeat())
def test_legal_reset_and_l1_heartbeat_preserve_protocol_validity(
    case: tuple[Literal["reset", "heartbeat"], BybitStandardBookFrame],
) -> None:
    mode, frame = case
    state = BybitStandardBookState()
    state.apply(frame)

    outcome = state.apply(frame)

    assert outcome.generation_valid
    assert outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert outcome.action is (
        BybitBookAction.HEARTBEAT if mode == "heartbeat" else BybitBookAction.SNAPSHOT
    )


@given(link=minimally_mutated_standard_links())
def test_minimal_standard_seq_regression_fails_closed_but_forward_jump_is_legal(
    link: tuple[
        BybitStandardBookFrame,
        BybitStandardBookFrame,
        BybitStandardBookFrame,
    ],
) -> None:
    snapshot, legal, regression = link
    state = BybitStandardBookState()
    state.apply(snapshot)

    forward = state.apply(legal)
    invalid = state.apply(regression)

    assert forward.action is BybitBookAction.APPLY
    assert forward.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert invalid.action is BybitBookAction.RECONNECT
    assert invalid.integrity is IntegrityMode.INVALID
    assert invalid.control_reason == "book_sequence_regression"
    assert not invalid.generation_valid


@given(link=minimally_mutated_links())
def test_minimally_mutated_full_link_never_silently_applies(
    link: tuple[BybitFullBookDelta, BybitFullBookDelta, str],
) -> None:
    handoff, mutated, mutation = link
    state = BybitFullBookState()
    state.apply_delta(handoff)
    state.apply_snapshot(
        _full_snapshot(
            update_id=handoff.update_id,
            sequence_id=handoff.sequence_id,
        )
    )

    outcome = state.apply_delta(mutated)

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert outcome.integrity is IntegrityMode.INVALID
    assert not outcome.generation_valid
    assert outcome.control_reason == (
        "full_book_u_gap" if mutation == "u_gap" else "full_book_sequence_regression"
    )


@given(
    update_id=st.integers(min_value=2, max_value=10**9),
    sequence_id=st.integers(min_value=1, max_value=10**9),
)
def test_buffer_seq_regression_is_discarded_but_original_chain_survives(
    update_id: int,
    sequence_id: int,
) -> None:
    state = BybitFullBookState()
    first = _full_delta(update_id=update_id, sequence_id=sequence_id)
    regression = _full_delta(
        update_id=update_id + 1,
        sequence_id=sequence_id - 1,
    )
    legal = _full_delta(
        update_id=update_id + 1,
        sequence_id=sequence_id + 17,
    )
    state.apply_delta(first)

    discarded = state.apply_delta(regression)
    accepted = state.apply_delta(legal)

    assert discarded.action is BybitBookAction.IGNORE
    assert accepted.action is BybitBookAction.BUFFER
    assert state.buffered_deltas == (first, legal)


@given(
    sequence_id=st.integers(min_value=0, max_value=10**9),
)
def test_legal_empty_u1_reset_bootstraps_as_explicit_no_book(
    sequence_id: int,
) -> None:
    state = BybitFullBookState()
    reset = _full_delta(update_id=1, sequence_id=sequence_id)

    signal = state.apply_delta(reset)
    bootstrap = state.apply_snapshot(
        _full_snapshot(update_id=1, sequence_id=sequence_id, empty=True)
    )

    assert signal.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert bootstrap.action is BybitBookAction.BOOTSTRAP
    assert bootstrap.generation_valid
    assert bootstrap.availability is BybitBookAvailability.NO_BOOK
    assert bootstrap.control_reason == "full_book_no_book"
    assert state.bids == ()
    assert state.asks == ()


@given(
    update_id=st.integers(min_value=2, max_value=10**6),
    sequence_id=st.integers(min_value=0, max_value=10**6),
    seq_jumps=st.lists(
        st.integers(min_value=0, max_value=10_000),
        min_size=1,
        max_size=40,
    ),
)
def test_full_exact_handoff_accepts_consecutive_u_and_nonconsecutive_seq(
    update_id: int,
    sequence_id: int,
    seq_jumps: list[int],
) -> None:
    state = BybitFullBookState()
    handoff = _full_delta(update_id=update_id, sequence_id=sequence_id)
    state.apply_delta(handoff)
    buffered = [handoff]
    current_u = update_id
    current_seq = sequence_id
    for jump in seq_jumps:
        current_u += 1
        current_seq += jump
        delta = _full_delta(update_id=current_u, sequence_id=current_seq)
        state.apply_delta(delta)
        buffered.append(delta)

    outcome = state.apply_snapshot(
        _full_snapshot(update_id=update_id, sequence_id=sequence_id)
    )

    assert outcome.action is BybitBookAction.BOOTSTRAP
    assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert outcome.generation_valid
    assert state.update_id == current_u
    assert state.sequence_id == current_seq
    before = (state.bids, state.asks, state.update_id, state.sequence_id)
    duplicate = state.apply_delta(buffered[-1])
    assert duplicate.action is BybitBookAction.IGNORE
    assert (state.bids, state.asks, state.update_id, state.sequence_id) == before
