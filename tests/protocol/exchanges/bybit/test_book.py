from __future__ import annotations

from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from crypto_collector.domain import IntegrityMode
from crypto_collector.domain.json_codec import JsonPayload, decode_json
from crypto_collector.exchanges.bybit.book import (
    BybitBookAction,
    BybitBookAvailability,
    BybitBookLevel,
    BybitBookParseError,
    BybitFullBookBufferLimits,
    BybitFullBookDelta,
    BybitFullBookPhase,
    BybitFullBookSnapshot,
    BybitFullBookState,
    BybitStandardBookFrame,
    BybitStandardBookState,
    BybitStandardMessageKind,
    estimate_full_book_delta_bytes,
    parse_full_book_delta,
    parse_full_book_snapshot_response,
    parse_standard_book_message,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "bybit"
_FIXTURE_HASHES = {
    "book-standard.json": (
        "3de15ccebbc597b0189cd7bfef431f2a60c75bec55fdca1a08f47816e1e5069c"
    ),
    "book-full-ws.json": (
        "6e2d4c4fe9148fce070c2c559e313083ce725e5acba3b7053c4c07ddcb6f8296"
    ),
    "book-full-rest.json": (
        "ce2820c9444b064a9f576c4c56a64790cbdbb51da2f113c19e8afa3fd22557f1"
    ),
}


class _Clock:
    def __init__(self, now_ns: int = 0) -> None:
        self.now_ns = now_ns

    def time_ns(self) -> int:
        return self.now_ns

    def monotonic_ns(self) -> int:
        return self.now_ns


def _fixture(name: str) -> dict[str, JsonPayload]:
    payload = decode_json((_FIXTURES / name).read_bytes())
    assert isinstance(payload, dict)
    return payload


def _level(price: str, quantity: str) -> BybitBookLevel:
    return BybitBookLevel(
        price=Decimal(price),
        quantity=Decimal(quantity),
        fields=(price, quantity),
    )


def _standard(
    *,
    kind: BybitStandardMessageKind = BybitStandardMessageKind.DELTA,
    depth: int = 200,
    update_id: int,
    sequence_id: int,
    bids: tuple[BybitBookLevel, ...] = (),
    asks: tuple[BybitBookLevel, ...] = (),
) -> BybitStandardBookFrame:
    return BybitStandardBookFrame(
        topic=f"orderbook.{depth}.BTCUSDT",
        depth=depth,
        symbol="BTCUSDT",
        kind=kind,
        bids=bids,
        asks=asks,
        timestamp_ns=1,
        matching_timestamp_ns=1,
        update_id=update_id,
        sequence_id=sequence_id,
    )


def _full_delta(
    *,
    update_id: int,
    sequence_id: int,
    bids: tuple[BybitBookLevel, ...] = (),
    asks: tuple[BybitBookLevel, ...] = (),
) -> BybitFullBookDelta:
    return BybitFullBookDelta(
        topic="orderbook.full.BTCUSDT",
        symbol="BTCUSDT",
        bids=bids,
        asks=asks,
        timestamp_ns=1,
        matching_timestamp_ns=1,
        update_id=update_id,
        sequence_id=sequence_id,
    )


def _full_snapshot(
    *,
    update_id: int,
    sequence_id: int,
    bids: tuple[BybitBookLevel, ...] = (_level("10", "1"),),
    asks: tuple[BybitBookLevel, ...] = (_level("11", "1"),),
) -> BybitFullBookSnapshot:
    return BybitFullBookSnapshot(
        symbol="BTCUSDT",
        bids=bids,
        asks=asks,
        timestamp_ns=1,
        matching_timestamp_ns=1,
        update_id=update_id,
        sequence_id=sequence_id,
    )


def _seed_standard() -> BybitStandardBookState:
    state = BybitStandardBookState()
    outcome = state.apply(
        _standard(
            kind=BybitStandardMessageKind.SNAPSHOT,
            update_id=100,
            sequence_id=1000,
            bids=(_level("10", "1"),),
            asks=(_level("11", "1"),),
        )
    )
    assert outcome.action is BybitBookAction.SNAPSHOT
    return state


def _seed_full() -> BybitFullBookState:
    state = BybitFullBookState()
    state.apply_delta(_full_delta(update_id=100, sequence_id=1000))
    outcome = state.apply_snapshot(_full_snapshot(update_id=100, sequence_id=1000))
    assert outcome.action is BybitBookAction.BOOTSTRAP
    return state


def test_book_fixtures_are_exact_and_locally_pinned() -> None:
    assert {
        name: sha256((_FIXTURES / name).read_bytes()).hexdigest()
        for name in _FIXTURE_HASHES
    } == _FIXTURE_HASHES


def test_standard_fixture_uses_decimal_levels_and_snapshot_chain_integrity() -> None:
    fixture = _fixture("book-standard.json")
    state = BybitStandardBookState()

    snapshot = parse_standard_book_message(fixture["snapshot"])
    delta = parse_standard_book_message(fixture["delta"])
    snapshot_outcome = state.apply(snapshot)
    delta_outcome = state.apply(delta)

    assert snapshot.timestamp_ns == 1_786_248_000_000_000_000
    assert snapshot.bids[0].price == Decimal("100.25")
    assert type(snapshot.bids[0].price) is Decimal
    assert snapshot_outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert delta_outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert delta.update_id - snapshot.update_id == 20
    assert delta.sequence_id - snapshot.sequence_id == 7
    assert state.bids == (_level("100.25", "2.750"),)
    assert state.asks == (
        _level("100.50", "3.000"),
        _level("100.75", "1.250"),
        _level("101.00", "4.000"),
    )


def test_standard_does_not_invent_u_or_seq_consecutiveness() -> None:
    state = _seed_standard()

    outcome = state.apply(
        _standard(
            update_id=10_000,
            sequence_id=50_000,
            bids=(_level("10", "2"),),
        )
    )

    assert outcome.action is BybitBookAction.APPLY
    assert outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert state.bids[0].quantity == Decimal(2)


def test_any_later_standard_snapshot_is_authoritative_and_u1_is_legal_reset() -> None:
    fixture = _fixture("book-standard.json")
    state = BybitStandardBookState()
    state.apply(parse_standard_book_message(fixture["snapshot"]))
    state.apply(parse_standard_book_message(fixture["delta"]))

    outcome = state.apply(parse_standard_book_message(fixture["reset"]))

    assert outcome.action is BybitBookAction.SNAPSHOT
    assert outcome.control_reason == "book_service_reinitialization"
    assert outcome.generation_valid
    assert state.update_id == 1
    assert state.bids == (_level("99.50", "5"),)
    assert state.asks == (_level("100.00", "6"),)


def test_u1_delta_is_ambiguous_and_cannot_restore_without_snapshot() -> None:
    state = _seed_standard()

    invalid = state.apply(_standard(update_id=1, sequence_id=1001))
    ordinary = state.apply(_standard(update_id=2, sequence_id=1002))
    restored = state.apply(
        _standard(
            kind=BybitStandardMessageKind.SNAPSHOT,
            update_id=2,
            sequence_id=1002,
            bids=(_level("20", "1"),),
            asks=(_level("21", "1"),),
        )
    )

    assert invalid.control_reason == "book_u1_delta_ambiguous"
    assert invalid.integrity is IntegrityMode.INVALID
    assert ordinary.control_reason == "book_generation_invalid"
    assert restored.action is BybitBookAction.SNAPSHOT
    assert restored.generation_valid


def test_standard_sequence_regression_fails_closed_without_calling_jumps_gaps() -> None:
    state = _seed_standard()
    state.apply(_standard(update_id=101, sequence_id=2000))

    outcome = state.apply(_standard(update_id=102, sequence_id=1999))

    assert outcome.action is BybitBookAction.RECONNECT
    assert outcome.integrity is IntegrityMode.INVALID
    assert outcome.control_reason == "book_sequence_regression"
    assert not outcome.generation_valid


def test_standard_delta_duplicate_is_idempotent() -> None:
    state = _seed_standard()
    delta = _standard(
        update_id=101,
        sequence_id=1001,
        bids=(_level("10", "2"),),
    )

    first = state.apply(delta)
    before = (state.bids, state.asks, state.update_id, state.sequence_id)
    duplicate = state.apply(delta)

    assert first.action is BybitBookAction.APPLY
    assert duplicate.action is BybitBookAction.IGNORE
    assert duplicate.control_reason == "book_duplicate_delta"
    assert (state.bids, state.asks, state.update_id, state.sequence_id) == before


def test_l1_same_u_authoritative_repeat_is_a_snapshot_heartbeat() -> None:
    fixture = _fixture("book-standard.json")
    frame = parse_standard_book_message(fixture["l1Heartbeat"])
    state = BybitStandardBookState()
    state.apply(frame)

    heartbeat = state.apply(frame)

    assert heartbeat.action is BybitBookAction.HEARTBEAT
    assert heartbeat.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert not heartbeat.count_as_book_update


def test_crossed_standard_update_is_atomic_and_invalidates_generation() -> None:
    state = _seed_standard()
    before = (state.bids, state.asks, state.update_id, state.sequence_id)

    outcome = state.apply(
        _standard(
            update_id=101,
            sequence_id=1001,
            bids=(_level("12", "1"),),
        )
    )

    assert outcome.control_reason == "book_crossed"
    assert outcome.integrity is IntegrityMode.INVALID
    assert (state.bids, state.asks, state.update_id, state.sequence_id) == before


def test_malformed_standard_message_invalidates_active_generation() -> None:
    state = _seed_standard()
    malformed = {
        "topic": "orderbook.200.BTCUSDT",
        "type": "delta",
        "ts": 1,
        "data": {
            "s": "BTCUSDT",
            "b": [["10", 2.0]],
            "a": [],
            "u": 101,
            "seq": 1001,
        },
    }

    with pytest.raises(BybitBookParseError, match="string fields"):
        state.apply_message(malformed)

    assert not state.generation_valid
    rejected = state.apply(_standard(update_id=102, sequence_id=1002))
    assert rejected.control_reason == "book_generation_invalid"


def test_full_fixture_handoff_requires_exact_seq_and_u_then_replays_tail() -> None:
    ws = _fixture("book-full-ws.json")
    rest = _fixture("book-full-rest.json")
    state = BybitFullBookState()
    first = state.apply_delta(parse_full_book_delta(ws["handoff"]))
    second = state.apply_delta(parse_full_book_delta(ws["next"]))

    bootstrap = state.apply_snapshot(parse_full_book_snapshot_response(rest))

    assert first.action is BybitBookAction.BUFFER
    assert second.action is BybitBookAction.BUFFER
    assert bootstrap.action is BybitBookAction.BOOTSTRAP
    assert bootstrap.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert bootstrap.emit_original_to_stream == "book_live_bootstrap"
    assert state.phase is BybitFullBookPhase.LIVE
    assert state.update_id == 501
    assert state.sequence_id == 19008
    assert state.bids == (_level("100.25", "2.750"),)
    assert state.asks == (
        _level("100.50", "3.000"),
        _level("100.75", "1.250"),
        _level("101.00", "4.000"),
    )


def test_full_snapshot_handoff_mismatch_keeps_buffer_for_refetch() -> None:
    state = BybitFullBookState()
    first = _full_delta(update_id=100, sequence_id=1000)
    second = _full_delta(update_id=101, sequence_id=1005)
    state.apply_delta(first)
    state.apply_delta(second)

    mismatch = state.apply_snapshot(_full_snapshot(update_id=99, sequence_id=1000))
    aligned = state.apply_snapshot(_full_snapshot(update_id=100, sequence_id=1000))

    assert mismatch.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert mismatch.control_reason == "full_book_snapshot_handoff_mismatch"
    assert mismatch.buffered_count == 2
    assert aligned.action is BybitBookAction.BOOTSTRAP
    assert state.update_id == 101


def test_full_snapshot_older_than_first_buffered_delta_is_refetched() -> None:
    state = BybitFullBookState()
    handoff = _full_delta(update_id=100, sequence_id=1000)
    state.apply_delta(handoff)

    outcome = state.apply_snapshot(_full_snapshot(update_id=99, sequence_id=999))

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert outcome.control_reason == "full_book_snapshot_too_old"
    assert state.buffered_deltas == (handoff,)


def test_crossed_full_snapshot_fails_closed_without_consuming_buffer() -> None:
    state = BybitFullBookState()
    handoff = _full_delta(update_id=100, sequence_id=1000)
    state.apply_delta(handoff)

    outcome = state.apply_snapshot(
        _full_snapshot(
            update_id=100,
            sequence_id=1000,
            bids=(_level("12", "1"),),
            asks=(_level("11", "1"),),
        )
    )

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert outcome.control_reason == "full_book_crossed_snapshot"
    assert state.buffered_deltas == (handoff,)
    assert not state.generation_valid


def test_full_buffer_discards_decreased_seq_without_poisoning_chain() -> None:
    state = BybitFullBookState()
    first = _full_delta(update_id=100, sequence_id=1000)
    regression = _full_delta(update_id=101, sequence_id=999)
    legal = _full_delta(update_id=101, sequence_id=1005)
    state.apply_delta(first)

    discarded = state.apply_delta(regression)
    accepted = state.apply_delta(legal)

    assert discarded.action is BybitBookAction.IGNORE
    assert discarded.control_reason == "full_book_buffer_sequence_regression"
    assert accepted.action is BybitBookAction.BUFFER
    assert state.buffered_deltas == (first, legal)


def test_full_buffer_u_discontinuity_restarts_from_current_delta() -> None:
    state = BybitFullBookState()
    state.apply_delta(_full_delta(update_id=100, sequence_id=1000))
    current = _full_delta(update_id=103, sequence_id=1005)

    outcome = state.apply_delta(current)

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert outcome.control_reason == "full_book_buffer_u_discontinuity"
    assert state.buffered_deltas == (current,)


def test_full_buffer_u1_resets_even_when_sequence_also_restarts() -> None:
    state = BybitFullBookState()
    state.apply_delta(_full_delta(update_id=100, sequence_id=1000))
    reset = _full_delta(update_id=1, sequence_id=1)

    outcome = state.apply_delta(reset)

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert outcome.control_reason == "full_book_reinitialization"
    assert state.buffered_deltas == (reset,)


def test_full_buffer_count_limit_accepts_boundary_then_fails_closed() -> None:
    state = BybitFullBookState(
        buffer_limits=BybitFullBookBufferLimits(
            max_deltas=2,
            max_estimated_bytes=1_000_000,
            max_elapsed_ns=1_000_000,
        ),
        clock=_Clock(),
    )
    first = state.apply_delta(_full_delta(update_id=100, sequence_id=1000))
    boundary = state.apply_delta(_full_delta(update_id=101, sequence_id=1001))

    exceeded = state.apply_delta(_full_delta(update_id=102, sequence_id=1002))

    assert first.buffered_count == 1
    assert boundary.buffered_count == 2
    assert exceeded.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert exceeded.control_reason == "full_book_buffer_count_exceeded"
    assert exceeded.buffered_count == 0
    assert state.buffered_estimated_bytes == 0
    assert state.buffer_started_ns is None


def test_full_buffer_estimated_byte_limit_has_an_exact_boundary() -> None:
    first = _full_delta(update_id=100, sequence_id=1000)
    second = _full_delta(
        update_id=101,
        sequence_id=1001,
        bids=(_level("10", "123456789"),),
    )
    exact_bytes = estimate_full_book_delta_bytes(
        first
    ) + estimate_full_book_delta_bytes(second)
    at_boundary = BybitFullBookState(
        buffer_limits=BybitFullBookBufferLimits(
            max_deltas=10,
            max_estimated_bytes=exact_bytes,
            max_elapsed_ns=1_000_000,
        ),
        clock=_Clock(),
    )
    at_boundary.apply_delta(first)
    accepted = at_boundary.apply_delta(second)
    assert accepted.action is BybitBookAction.BUFFER
    assert at_boundary.buffered_estimated_bytes == exact_bytes

    exceeded_state = BybitFullBookState(
        buffer_limits=BybitFullBookBufferLimits(
            max_deltas=10,
            max_estimated_bytes=exact_bytes - 1,
            max_elapsed_ns=1_000_000,
        ),
        clock=_Clock(),
    )
    exceeded_state.apply_delta(first)
    exceeded = exceeded_state.apply_delta(second)
    assert exceeded.control_reason == "full_book_buffer_bytes_exceeded"
    assert exceeded.buffered_count == 0
    assert exceeded_state.buffered_estimated_bytes == 0


def test_full_buffer_elapsed_limit_is_checked_before_bootstrap_handoff() -> None:
    clock = _Clock()
    state = BybitFullBookState(
        buffer_limits=BybitFullBookBufferLimits(
            max_deltas=10,
            max_estimated_bytes=1_000_000,
            max_elapsed_ns=10,
        ),
        clock=clock,
    )
    state.apply_delta(_full_delta(update_id=100, sequence_id=1000))
    clock.now_ns = 10
    accepted_at_boundary = state.apply_delta(
        _full_delta(update_id=101, sequence_id=1001)
    )
    assert accepted_at_boundary.action is BybitBookAction.BUFFER

    clock.now_ns = 11
    exceeded = state.apply_snapshot(_full_snapshot(update_id=100, sequence_id=1000))
    assert exceeded.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert exceeded.control_reason == "full_book_buffer_elapsed_exceeded"
    assert exceeded.buffered_count == 0


def test_full_buffer_same_u_conflict_is_not_an_exact_duplicate() -> None:
    state = BybitFullBookState()
    state.apply_delta(_full_delta(update_id=100, sequence_id=1000))

    outcome = state.apply_delta(
        _full_delta(
            update_id=100,
            sequence_id=1000,
            bids=(_level("10", "2"),),
        )
    )

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert outcome.control_reason == "full_book_conflicting_duplicate"
    assert state.buffered_deltas == ()


def test_full_live_same_u_conflict_invalidates_instead_of_ignoring() -> None:
    state = _seed_full()

    outcome = state.apply_delta(
        _full_delta(
            update_id=100,
            sequence_id=1000,
            bids=(_level("10", "2"),),
        )
    )

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert outcome.control_reason == "full_book_conflicting_duplicate"
    assert not outcome.generation_valid
    assert state.buffered_deltas == ()


def test_full_connection_generation_change_clears_all_protocol_state() -> None:
    state = _seed_full()

    outcome = state.invalidate("connection_generation_changed")

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert not state.generation_valid
    assert state.bids == ()
    assert state.asks == ()
    assert state.buffered_deltas == ()
    assert state.buffered_estimated_bytes == 0
    assert state.buffer_started_ns is None


def test_full_live_requires_consecutive_u_but_not_consecutive_seq() -> None:
    state = _seed_full()

    legal = state.apply_delta(
        _full_delta(
            update_id=101,
            sequence_id=50_000,
            bids=(_level("10", "2"),),
        )
    )
    duplicate = state.apply_delta(
        _full_delta(
            update_id=101,
            sequence_id=50_000,
            bids=(_level("10", "2"),),
        )
    )

    assert legal.action is BybitBookAction.APPLY
    assert legal.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert duplicate.action is BybitBookAction.IGNORE
    assert state.generation_valid


@pytest.mark.parametrize(
    ("delta", "reason", "buffered"),
    (
        (_full_delta(update_id=103, sequence_id=1003), "full_book_u_gap", 1),
        (
            _full_delta(update_id=1, sequence_id=1),
            "full_book_reinitialization",
            1,
        ),
        (
            _full_delta(update_id=101, sequence_id=999),
            "full_book_sequence_regression",
            0,
        ),
    ),
)
def test_full_live_integrity_failure_discards_book_and_requires_rebootstrap(
    delta: BybitFullBookDelta,
    reason: str,
    buffered: int,
) -> None:
    state = _seed_full()

    outcome = state.apply_delta(delta)

    assert outcome.action is BybitBookAction.REFETCH_BOOTSTRAP
    assert outcome.control_reason == reason
    assert outcome.buffered_count == buffered
    assert not state.generation_valid
    assert state.phase is BybitFullBookPhase.BUFFERING
    assert state.bids == ()
    assert state.asks == ()


def test_full_crossed_delta_invalidates_atomically_without_poisoning_buffer() -> None:
    state = _seed_full()
    crossing = _full_delta(
        update_id=101,
        sequence_id=1001,
        bids=(_level("12", "1"),),
    )

    outcome = state.apply_delta(crossing)

    assert outcome.control_reason == "full_book_crossed"
    assert not state.generation_valid
    assert state.buffered_deltas == ()
    assert state.bids == ()
    assert state.asks == ()


def test_full_live_seq_regression_wins_over_simultaneous_u_gap() -> None:
    state = _seed_full()

    outcome = state.apply_delta(_full_delta(update_id=103, sequence_id=999))

    assert outcome.control_reason == "full_book_sequence_regression"
    assert outcome.buffered_count == 0
    assert state.buffered_deltas == ()


@pytest.mark.parametrize(
    "message",
    (
        {
            "topic": "orderbook.200.BTCUSDT",
            "type": "snapshot",
            "ts": 1.0,
            "data": {
                "s": "BTCUSDT",
                "b": [["10", "1"]],
                "a": [["11", "1"]],
                "u": 1,
                "seq": 1,
            },
        },
        {
            "topic": "orderbook.200.BTCUSDT",
            "type": "snapshot",
            "ts": 1,
            "data": {
                "s": "ETHUSDT",
                "b": [["10", "1"]],
                "a": [["11", "1"]],
                "u": 1,
                "seq": 1,
            },
        },
        {
            "topic": "orderbook.200.BTCUSDT",
            "type": "snapshot",
            "ts": 1,
            "data": {
                "s": "BTCUSDT",
                "b": [["9", "1"], ["10", "1"]],
                "a": [["11", "1"]],
                "u": 1,
                "seq": 1,
            },
        },
        {
            "topic": "orderbook.1.BTCUSDT",
            "type": "delta",
            "ts": 1,
            "data": {
                "s": "BTCUSDT",
                "b": [["10", "1"]],
                "a": [],
                "u": 2,
                "seq": 2,
            },
        },
    ),
)
def test_malformed_standard_wire_values_are_rejected(message: object) -> None:
    with pytest.raises(BybitBookParseError):
        parse_standard_book_message(message)


def test_full_parser_rejects_snapshot_ws_and_numeric_level_values() -> None:
    payload = cast(dict[str, object], _fixture("book-full-ws.json")["handoff"])
    snapshot_ws = dict(payload)
    snapshot_ws["type"] = "snapshot"
    numeric_level = dict(payload)
    numeric_level["data"] = {
        "s": "BTCUSDT",
        "b": [[100.25, "1"]],
        "a": [],
        "u": 500,
        "seq": 19000,
    }

    with pytest.raises(BybitBookParseError, match="must be delta"):
        parse_full_book_delta(snapshot_ws)
    with pytest.raises(BybitBookParseError, match="string fields"):
        parse_full_book_delta(numeric_level)


def test_standard_delta_does_not_require_snapshot_sort_order() -> None:
    payload = {
        "topic": "orderbook.200.BTCUSDT",
        "type": "delta",
        "ts": 1,
        "cts": 1,
        "data": {
            "s": "BTCUSDT",
            "b": [["9", "1"], ["10", "2"]],
            "a": [["12", "1"], ["11", "2"]],
            "u": 2,
            "seq": 2,
        },
    }

    frame = parse_standard_book_message(payload)

    assert tuple(level.price for level in frame.bids) == (Decimal(9), Decimal(10))
    assert tuple(level.price for level in frame.asks) == (Decimal(12), Decimal(11))


def test_standard_parser_rejects_undocumented_depth() -> None:
    payload = {
        "topic": "orderbook.25.BTCUSDT",
        "type": "snapshot",
        "ts": 1,
        "data": {
            "s": "BTCUSDT",
            "b": [["10", "1"]],
            "a": [["11", "1"]],
            "u": 2,
            "seq": 2,
        },
    }

    with pytest.raises(BybitBookParseError, match="one of"):
        parse_standard_book_message(payload)


def test_false_is_not_accepted_as_successful_rest_retcode() -> None:
    response = dict(_fixture("book-full-rest.json"))
    response["retCode"] = False

    with pytest.raises(BybitBookParseError, match="retCode"):
        parse_full_book_snapshot_response(response)


def test_cts_is_required_for_standard_and_full_wire_messages() -> None:
    standard = cast(dict[str, object], _fixture("book-standard.json")["snapshot"])
    full = cast(dict[str, object], _fixture("book-full-ws.json")["handoff"])
    without_standard_cts = dict(standard)
    without_full_cts = dict(full)
    without_standard_cts.pop("cts")
    without_full_cts.pop("cts")

    with pytest.raises(BybitBookParseError, match="cts"):
        parse_standard_book_message(without_standard_cts)
    with pytest.raises(BybitBookParseError, match="cts"):
        parse_full_book_delta(without_full_cts)

    rest = cast(dict[str, object], dict(_fixture("book-full-rest.json")))
    result = cast(dict[str, object], rest["result"])
    without_rest_cts = dict(result)
    without_rest_cts.pop("cts")
    rest["result"] = without_rest_cts
    with pytest.raises(BybitBookParseError, match="cts"):
        parse_full_book_snapshot_response(rest)


def test_empty_u1_full_bootstrap_is_valid_but_explicitly_no_book() -> None:
    state = BybitFullBookState()
    reset = _full_delta(update_id=1, sequence_id=1)
    state.apply_delta(reset)

    outcome = state.apply_snapshot(
        _full_snapshot(
            update_id=1,
            sequence_id=1,
            bids=(),
            asks=(),
        )
    )

    assert outcome.action is BybitBookAction.BOOTSTRAP
    assert outcome.integrity is IntegrityMode.SEQUENCE_VERIFIED
    assert outcome.availability is BybitBookAvailability.NO_BOOK
    assert outcome.control_reason == "full_book_no_book"
    assert state.generation_valid

    duplicate = state.apply_delta(reset)
    assert duplicate.action is BybitBookAction.IGNORE
    assert duplicate.control_reason == "full_book_duplicate_delta"

    state.apply_delta(_full_delta(update_id=2, sequence_id=2))
    state.apply_delta(_full_delta(update_id=1, sequence_id=2))
    available = state.apply_snapshot(_full_snapshot(update_id=1, sequence_id=2))
    assert available.availability is BybitBookAvailability.AVAILABLE
    assert available.control_reason is None
