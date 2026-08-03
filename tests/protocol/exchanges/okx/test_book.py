from __future__ import annotations

from decimal import Decimal

import pytest

from crypto_collector.domain import IntegrityMode
from crypto_collector.exchanges.okx.book import (
    BookAction,
    OkxBookFrame,
    OkxBookLevel,
    OkxBookParseError,
    OkxBookState,
    parse_book_message,
)


def level(price: str, quantity: str) -> OkxBookLevel:
    return OkxBookLevel(
        price=Decimal(price),
        quantity=Decimal(quantity),
        fields=(price, quantity, "0", "1"),
    )


def frame(
    *,
    action: str = "update",
    seq: int,
    prev_seq: int | None,
    bids: tuple[OkxBookLevel, ...] = (),
    asks: tuple[OkxBookLevel, ...] = (),
    checksum: int | None = 0,
) -> OkxBookFrame:
    return OkxBookFrame(
        action=action,
        bids=bids,
        asks=asks,
        timestamp_ns=1_000_000,
        prev_seq_id=prev_seq,
        seq_id=seq,
        checksum=checksum,
    )


def seeded_book(*, seq: int = 100) -> OkxBookState:
    state = OkxBookState()
    outcome = state.apply(
        frame(
            action="snapshot",
            prev_seq=-1,
            seq=seq,
            bids=(level("10", "1"),),
            asks=(level("11", "1"),),
        )
    )
    assert outcome.action is BookAction.SNAPSHOT
    return state


def test_snapshot_then_linked_update_is_sequence_verified() -> None:
    state = seeded_book()

    outcome = state.apply(frame(prev_seq=100, seq=101, bids=(level("10", "2"),)))

    assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert state.bids[0].quantity == Decimal(2)


def test_empty_sequence_heartbeat_does_not_create_gap() -> None:
    state = seeded_book()

    outcome = state.apply(frame(prev_seq=100, seq=100))

    assert outcome.action is BookAction.HEARTBEAT
    assert outcome.emit_original_to_stream == "book_live"
    assert outcome.count_as_book_update is False
    assert state.sequence_id == 100


def test_documented_maintenance_sequence_reset_applies_and_continues() -> None:
    state = seeded_book()

    reset = state.apply(frame(prev_seq=100, seq=1, bids=(level("10", "2"),)))
    linked = state.apply(frame(prev_seq=1, seq=2, asks=(level("11", "0"),)))

    assert reset.action is BookAction.APPLY
    assert reset.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert reset.generation_valid
    assert reset.control_reason == "maintenance_sequence_reset"
    assert linked.generation_valid
    assert state.sequence_id == 2
    assert state.asks == ()


def test_real_prev_sequence_mismatch_invalidates_generation() -> None:
    state = seeded_book()

    outcome = state.apply(frame(prev_seq=98, seq=101, bids=(level("10", "2"),)))

    assert outcome.integrity is IntegrityMode.INVALID
    assert outcome.action is BookAction.RECONNECT
    assert not outcome.generation_valid
    assert state.sequence_id == 100
    assert state.bids[0].quantity == Decimal(1)


def test_post_2026_checksum_zero_is_not_crc_failure() -> None:
    state = seeded_book()

    outcome = state.apply(
        frame(
            prev_seq=100,
            seq=101,
            checksum=0,
            bids=(level("10", "2"),),
        )
    )

    assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED


def test_invalid_generation_rejects_updates_until_new_snapshot() -> None:
    state = seeded_book()
    state.apply(frame(prev_seq=99, seq=101))

    still_invalid = state.apply(frame(prev_seq=100, seq=101))
    restored = state.apply(
        frame(
            action="snapshot",
            prev_seq=-1,
            seq=500,
            bids=(level("20", "1"),),
            asks=(level("21", "1"),),
        )
    )

    assert still_invalid.action is BookAction.RECONNECT
    assert restored.action is BookAction.SNAPSHOT
    assert restored.generation_valid
    assert state.sequence_id == 500


def test_crossing_update_is_atomic_and_invalidates_generation() -> None:
    state = seeded_book()

    outcome = state.apply(frame(prev_seq=100, seq=101, bids=(level("12", "1"),)))

    assert outcome.control_reason == "book_crossed"
    assert state.bids[0].price == Decimal(10)
    assert state.sequence_id == 100


def test_parser_keeps_native_level_fields_and_converts_milliseconds() -> None:
    frames = parse_book_message(
        {
            "arg": {"channel": "books", "instId": "BTC-USDT"},
            "action": "snapshot",
            "data": [
                {
                    "bids": [["10", "1", "0", "2", "future-field"]],
                    "asks": [["11", "1", "0", "3"]],
                    "ts": "123",
                    "checksum": "0",
                    "prevSeqId": "-1",
                    "seqId": "100",
                    "unknown": {"kept-by-raw-envelope": True},
                }
            ],
        }
    )

    assert len(frames) == 1
    assert frames[0].timestamp_ns == 123_000_000
    assert frames[0].bids[0].fields[-1] == "future-field"


@pytest.mark.parametrize(
    "message",
    (
        {"action": "update", "data": []},
        {"action": "unknown", "data": [{}]},
        {
            "action": "update",
            "data": [
                {
                    "bids": [["10", "nan"]],
                    "asks": [],
                    "ts": "1",
                    "prevSeqId": "1",
                    "seqId": "2",
                }
            ],
        },
    ),
)
def test_malformed_book_messages_are_rejected(message: object) -> None:
    with pytest.raises(OkxBookParseError):
        parse_book_message(message)
