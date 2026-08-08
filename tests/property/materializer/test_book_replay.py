from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.materializer.books.replay import (
    OkxBookReplayer,
    apply_book_time_policy,
)
from tests.unit.materializer.books.test_replay import POLICY, SECOND, book

ROWS = (
    book(
        "property-snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    ),
    book(
        "property-delta-1",
        action="update",
        seq_id=11,
        prev_seq_id=10,
        bids=[["10", "4", "0", "2"]],
        asks=[],
        event_time_ns=2 * SECOND,
        writer_sequence=2,
    ),
    book(
        "property-heartbeat",
        action="update",
        seq_id=11,
        prev_seq_id=11,
        bids=[],
        asks=[],
        event_time_ns=3 * SECOND,
        writer_sequence=3,
    ),
    book(
        "property-reset",
        action="update",
        seq_id=2,
        prev_seq_id=11,
        bids=[],
        asks=[["11", "5", "0", "2"]],
        event_time_ns=4 * SECOND,
        writer_sequence=4,
    ),
)


@given(st.permutations(ROWS))
def test_okx_replay_is_independent_of_input_discovery_order(rows) -> None:
    result = OkxBookReplayer().replay(apply_book_time_policy(rows, POLICY))
    assert result.book_valid
    assert result.sequence_id == 2
    assert result.accepted_update_count == 2
    assert result.heartbeat_count == 1
    assert result.sequence_reset_count == 1
    assert result.lineage_manifest_sha256s == tuple(
        sorted(row.locator.manifest_sha256 for row in ROWS)
    )
