from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from crypto_collector.domain import IntegrityMode
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.exchanges.bitget.book import (
    BitgetBook,
    BitgetBookFrame,
    BitgetBookLevel,
    BitgetBookParseError,
    BookAction,
    parse_book_message,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "bitget"


def _json(name: str) -> object:
    return decode_json((_FIXTURES / name).read_bytes())


def _frame(name: str) -> BitgetBookFrame:
    return parse_book_message(_json(name))[0]


def _level(price: str = "10", quantity: str = "1") -> BitgetBookLevel:
    return BitgetBookLevel(Decimal(price), Decimal(quantity), (price, quantity))


def _manual(
    *,
    action: str,
    pseq: int,
    seq: int,
    bids: tuple[BitgetBookLevel, ...] = (),
    asks: tuple[BitgetBookLevel, ...] = (),
) -> BitgetBookFrame:
    return BitgetBookFrame(
        action=action,
        bids=bids,
        asks=asks,
        timestamp_ns=1,
        pseq=pseq,
        seq=seq,
        max_depth=50,
    )


def _seeded_snapshot() -> BitgetBook:
    state = BitgetBook()
    outcome = state.apply(_frame("book-snapshot.json"))
    assert outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN
    return state


def test_initial_snapshot_may_legitimately_have_pseq_zero() -> None:
    state = BitgetBook()

    outcome = state.apply(_frame("book-snapshot.json"))

    assert outcome.action is BookAction.SNAPSHOT
    assert outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert outcome.generation_valid
    assert state.sequence_id == 100


def test_first_update_requires_inclusive_snapshot_overlap() -> None:
    valid = _seeded_snapshot()
    invalid = _seeded_snapshot()

    accepted = valid.apply(_frame("book-first-update.json"))
    rejected = invalid.apply(_manual(action="update", pseq=101, seq=102))

    assert accepted.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert accepted.sequence_id == 101
    assert rejected.action is BookAction.RESUBSCRIBE
    assert rejected.integrity is IntegrityMode.INVALID
    assert rejected.control_reason == "book_first_update_does_not_overlap_snapshot"


def test_first_update_accepts_snapshot_at_upper_closed_interval_boundary() -> None:
    state = _seeded_snapshot()

    outcome = state.apply(_manual(action="update", pseq=99, seq=100))

    assert outcome.action is BookAction.APPLY
    assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert outcome.sequence_id == 100


def test_first_update_still_requires_seq_to_advance_beyond_pseq() -> None:
    state = _seeded_snapshot()

    outcome = state.apply(_manual(action="update", pseq=100, seq=100))

    assert outcome.action is BookAction.RESUBSCRIBE
    assert outcome.integrity is IntegrityMode.INVALID


def test_first_update_can_use_zero_pseq_when_it_overlaps_snapshot() -> None:
    state = _seeded_snapshot()

    outcome = state.apply(_manual(action="update", pseq=0, seq=101))

    assert outcome.action is BookAction.APPLY
    assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED


def test_later_update_requires_exact_pseq_and_zero_means_reset() -> None:
    state = _seeded_snapshot()
    assert state.apply(_frame("book-first-update.json")).generation_valid
    accepted = state.apply(_frame("book-update.json"))
    reset = state.apply(_manual(action="update", pseq=0, seq=103))

    assert accepted.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert accepted.sequence_id == 102
    assert reset.action is BookAction.RESUBSCRIBE
    assert reset.control_reason == "book_sequence_reset"
    assert not reset.generation_valid


def test_invalid_generation_is_sticky_until_authoritative_snapshot() -> None:
    state = _seeded_snapshot()
    state.apply(_manual(action="update", pseq=101, seq=102))

    still_invalid = state.apply(_manual(action="update", pseq=100, seq=101))
    restored = state.apply(
        _manual(
            action="snapshot",
            pseq=0,
            seq=500,
            bids=(_level(),),
            asks=(_level("11"),),
        )
    )

    assert still_invalid.action is BookAction.RESUBSCRIBE
    assert still_invalid.control_reason == "book_generation_invalid"
    assert restored.action is BookAction.SNAPSHOT
    assert restored.generation_valid
    assert state.sequence_id == 500


def test_update_before_snapshot_invalidates_generation() -> None:
    state = BitgetBook()

    outcome = state.apply(_manual(action="update", pseq=0, seq=1))

    assert outcome.action is BookAction.RESUBSCRIBE
    assert outcome.control_reason == "book_update_before_snapshot"


def test_zero_quantity_is_preserved_without_materializing_delete_semantics() -> None:
    frame = _frame("book-first-update.json")
    state = _seeded_snapshot()

    outcome = state.apply(frame)

    assert frame.bids[0].quantity == Decimal(0)
    assert frame.bids[0].fields == ("10", "0")
    assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert not hasattr(state, "bids")
    assert not hasattr(state, "asks")


def test_parser_keeps_native_strings_and_converts_row_timestamp() -> None:
    frame = _frame("book-snapshot.json")

    assert frame.timestamp_ns == 1_746_698_732_562_000_000
    assert frame.max_depth == 50
    assert frame.bids[0].fields == ("10", "2")


@pytest.mark.parametrize(
    "message",
    (
        {"arg": {"topic": "books"}, "action": "update", "data": []},
        {"arg": {"topic": "books"}, "action": [], "data": []},
        {
            "arg": {"topic": "books1"},
            "action": "snapshot",
            "data": [{}],
        },
        {
            "arg": {"topic": "books"},
            "action": "update",
            "data": [
                {
                    "a": [],
                    "b": [["10", "nan"]],
                    "pseq": 1,
                    "seq": 2,
                    "ts": "1",
                }
            ],
        },
        {
            "arg": {"topic": "books"},
            "action": "update",
            "data": [
                {
                    "a": [],
                    "b": [[10, 1]],
                    "pseq": 1,
                    "seq": 2,
                    "ts": "1",
                }
            ],
        },
    ),
)
def test_malformed_or_non_books_messages_are_rejected(message: object) -> None:
    with pytest.raises(BitgetBookParseError):
        parse_book_message(message)


def test_snapshot_sequence_regression_is_invalid() -> None:
    state = BitgetBook()

    outcome = state.apply(_manual(action="snapshot", pseq=2, seq=1))

    assert outcome.action is BookAction.RESUBSCRIBE
    assert outcome.integrity is IntegrityMode.INVALID
