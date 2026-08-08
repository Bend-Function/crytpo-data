from __future__ import annotations

import hashlib
from decimal import Decimal

import pytest

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.types import Exchange, IntegrityMode, Market, Transport
from crypto_collector.materializer.books.checkpoint import (
    BookImpactPlanner,
    BookReplayCheckpoint,
    TimeRange,
    source_prefix_digest,
)
from crypto_collector.materializer.books.replay import (
    BookGapReason,
    OkxBookReplayer,
    TimedBookRecord,
    apply_book_time_policy,
)
from crypto_collector.materializer.datasets.quality import (
    QualityEvent,
    QualityEventKind,
    QualityStreamKey,
    TimedQualityEvent,
)
from crypto_collector.materializer.models import SourceLocator, SourceRecord, TimeSource
from crypto_collector.materializer.time_policy import EventTimePolicy

SECOND = 1_000_000_000


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def book(
    label: str,
    *,
    action: str,
    seq_id: int,
    prev_seq_id: int,
    bids: list[list[str]],
    asks: list[list[str]],
    event_time_ns: int,
    writer_sequence: int,
    monotonic_ns: int | None = None,
    worker: str = "worker-a",
    generation: int = 1,
    checksum: int = 0,
) -> SourceRecord:
    envelope = RawEnvelope(
        schema_version=1,
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="book_live",
        native_channel="books",
        transport=Transport.WEBSOCKET,
        event_time_ns=event_time_ns,
        event_time_source="okx.data.ts",
        integrity_mode=IntegrityMode.SEQUENCE_VERIFIED,
        coverage=None,
        rest_metadata=None,
        payload={
            "arg": {"channel": "books", "instId": "BTC-USDT"},
            "action": action,
            "data": [
                {
                    "asks": asks,
                    "bids": bids,
                    "ts": str(event_time_ns // 1_000_000),
                    "checksum": checksum,
                    "prevSeqId": prev_seq_id,
                    "seqId": seq_id,
                }
            ],
        },
        received_at_ns=event_time_ns + 10,
        monotonic_ns=monotonic_ns or writer_sequence,
        worker_instance_id=worker,
        connection_id=f"connection-{worker}",
        connection_generation=generation,
        writer_sequence=writer_sequence,
        egress_id="direct-primary",
        config_sha256="a" * 64,
    )
    return SourceRecord(
        envelope=envelope,
        locator=SourceLocator(_sha(label), 0),
    )


POLICY = EventTimePolicy(max_past_skew_ns=SECOND, max_future_skew_ns=SECOND)


def _replay(*records: SourceRecord):
    timed = apply_book_time_policy(records, POLICY)
    return OkxBookReplayer().replay(timed)


def fault(
    label: str,
    *,
    kind: QualityEventKind,
    event_time_ns: int,
    writer_sequence: int,
    instrument_key: str = "BTC-USDT",
) -> TimedQualityEvent:
    source = SourceRecord(
        RawEnvelope(
            schema_version=1,
            exchange=Exchange.OKX,
            market=None,
            instrument_key=None,
            wire_symbol=None,
            logical_stream="_control",
            native_channel=None,
            transport=Transport.INTERNAL,
            event_time_ns=None,
            event_time_source=None,
            integrity_mode=None,
            coverage=None,
            rest_metadata=None,
            payload={"event_id": label, "kind": kind.value},
            received_at_ns=event_time_ns + 10,
            monotonic_ns=writer_sequence,
            worker_instance_id="worker-a",
            connection_id=None,
            connection_generation=None,
            writer_sequence=writer_sequence,
            egress_id=None,
            config_sha256="a" * 64,
        ),
        SourceLocator(_sha(label), 0),
    )
    return TimedQualityEvent(
        QualityEvent(
            source=source,
            targets=(
                QualityStreamKey(
                    Exchange.OKX,
                    Market.SPOT,
                    instrument_key,
                    "book_live",
                ),
            ),
            event_id=label,
            kind=kind,
            event_time_ns=event_time_ns,
        ),
        effective_event_time_ns=event_time_ns,
        time_source=TimeSource.EVENT,
    )


def test_okx_snapshot_and_delta_replay_exact_decimal_state() -> None:
    snapshot = book(
        "snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=1 * SECOND,
        writer_sequence=1,
    )
    delta = book(
        "delta",
        action="update",
        seq_id=11,
        prev_seq_id=10,
        bids=[["10", "0", "0", "0"], ["9", "4", "0", "2"]],
        asks=[["11", "5", "0", "2"]],
        event_time_ns=2 * SECOND,
        writer_sequence=2,
    )

    result = _replay(delta, snapshot)

    assert result.book_valid
    assert result.integrity_mode is IntegrityMode.SEQUENCE_VERIFIED
    assert result.sequence_id == 11
    assert result.bids == ((Decimal(9), Decimal(4)),)
    assert result.asks == ((Decimal(11), Decimal(5)),)
    assert result.accepted_update_count == 1
    assert result.authoritative_ancestor == snapshot.locator


def test_sequence_gap_invalidates_until_authoritative_snapshot() -> None:
    snapshot = book(
        "snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )
    gap = book(
        "gap",
        action="update",
        seq_id=13,
        prev_seq_id=12,
        bids=[["10", "4", "0", "2"]],
        asks=[],
        event_time_ns=2 * SECOND,
        writer_sequence=2,
    )
    later_delta = book(
        "later",
        action="update",
        seq_id=14,
        prev_seq_id=13,
        bids=[["9", "1", "0", "1"]],
        asks=[],
        event_time_ns=3 * SECOND,
        writer_sequence=3,
    )

    invalid = _replay(snapshot, gap, later_delta)
    assert invalid.book_valid is False
    assert invalid.gap_reason is BookGapReason.SEQUENCE_MISMATCH
    assert invalid.bids == invalid.asks == ()

    recovery = book(
        "recovery",
        action="snapshot",
        seq_id=20,
        prev_seq_id=-1,
        bids=[["20", "1", "0", "1"]],
        asks=[["21", "1", "0", "1"]],
        event_time_ns=4 * SECOND,
        writer_sequence=4,
    )
    recovered = _replay(snapshot, gap, later_delta, recovery)
    assert recovered.book_valid
    assert recovered.sequence_id == 20
    assert recovered.authoritative_ancestor == recovery.locator


def test_okx_empty_sequence_heartbeat_and_maintenance_reset_are_valid() -> None:
    snapshot = book(
        "snapshot",
        action="snapshot",
        seq_id=15,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )
    heartbeat = book(
        "heartbeat",
        action="update",
        seq_id=15,
        prev_seq_id=15,
        bids=[],
        asks=[],
        event_time_ns=2 * SECOND,
        writer_sequence=2,
    )
    reset = book(
        "reset",
        action="update",
        seq_id=3,
        prev_seq_id=15,
        bids=[["10", "4", "0", "2"]],
        asks=[],
        event_time_ns=3 * SECOND,
        writer_sequence=3,
    )

    result = _replay(reset, heartbeat, snapshot)

    assert result.book_valid
    assert result.sequence_id == 3
    assert result.accepted_update_count == 1
    assert result.heartbeat_count == 1
    assert result.sequence_reset_count == 1
    assert result.bids[0] == (Decimal(10), Decimal(4))


def test_typed_checksum_fault_invalidates_until_next_snapshot() -> None:
    snapshot = book(
        "snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )
    checksum_fault = fault(
        "checksum-fault",
        kind=QualityEventKind.CHECKSUM_ERROR,
        event_time_ns=2 * SECOND,
        writer_sequence=2,
    )
    delta = book(
        "delta",
        action="update",
        seq_id=11,
        prev_seq_id=10,
        bids=[["10", "4", "0", "2"]],
        asks=[],
        event_time_ns=3 * SECOND,
        writer_sequence=3,
    )

    invalid = OkxBookReplayer().replay(
        apply_book_time_policy([snapshot, delta], POLICY),
        quality_events=[checksum_fault],
    )
    assert invalid.book_valid is False
    assert invalid.gap_reason is BookGapReason.CHECKSUM_ERROR

    recovery = book(
        "recovery",
        action="snapshot",
        seq_id=20,
        prev_seq_id=-1,
        bids=[["20", "1", "0", "1"]],
        asks=[["21", "1", "0", "1"]],
        event_time_ns=4 * SECOND,
        writer_sequence=4,
    )
    recovered = OkxBookReplayer().replay(
        apply_book_time_policy([snapshot, delta, recovery], POLICY),
        quality_events=[checksum_fault],
    )
    assert recovered.book_valid
    assert recovered.authoritative_ancestor == recovery.locator


def test_unrelated_quality_fault_cannot_invalidate_replay_scope() -> None:
    snapshot = book(
        "snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=2 * SECOND,
        writer_sequence=2,
    )
    unrelated = fault(
        "eth-gap",
        kind=QualityEventKind.GAP,
        event_time_ns=SECOND,
        writer_sequence=1,
        instrument_key="ETH-USDT",
    )
    result = OkxBookReplayer().replay(
        apply_book_time_policy([snapshot], POLICY),
        quality_events=[unrelated],
        scope=QualityStreamKey(
            Exchange.OKX,
            Market.SPOT,
            "BTC-USDT",
            "book_live",
        ),
    )
    assert result.book_valid
    assert result.gap_reason is None
    assert result.lineage_manifest_sha256s == (snapshot.locator.manifest_sha256,)


def test_timed_book_record_rejects_forged_time_choice() -> None:
    snapshot = book(
        "snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )
    with pytest.raises(ValueError, match="time_source"):
        TimedBookRecord(snapshot, 2 * SECOND, TimeSource.EVENT)


def test_first_causal_invalidity_reason_is_preserved() -> None:
    snapshot = book(
        "snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )
    first_fault = fault(
        "gap",
        kind=QualityEventKind.GAP,
        event_time_ns=2 * SECOND,
        writer_sequence=2,
    )
    later_fault = fault(
        "checksum",
        kind=QualityEventKind.CHECKSUM_ERROR,
        event_time_ns=3 * SECOND,
        writer_sequence=3,
    )
    result = OkxBookReplayer().replay(
        apply_book_time_policy([snapshot], POLICY),
        quality_events=[later_fault, first_fault],
    )
    assert result.gap_reason is BookGapReason.EXPLICIT_GAP


def test_worker_boundary_invalidates_inherited_generation() -> None:
    snapshot = book(
        "worker-a-snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
        worker="worker-a",
    )
    inherited_delta = book(
        "worker-b-delta",
        action="update",
        seq_id=11,
        prev_seq_id=10,
        bids=[["10", "4", "0", "2"]],
        asks=[],
        event_time_ns=2 * SECOND,
        writer_sequence=1,
        worker="worker-b",
    )
    result = _replay(snapshot, inherited_delta)
    assert result.book_valid is False
    assert result.gap_reason is BookGapReason.WORKER_BOUNDARY


@pytest.mark.parametrize(
    ("records", "reason"),
    [
        (
            lambda: [
                book(
                    "bad-checksum",
                    action="snapshot",
                    seq_id=1,
                    prev_seq_id=-1,
                    bids=[["10", "1", "0", "1"]],
                    asks=[["11", "1", "0", "1"]],
                    event_time_ns=SECOND,
                    writer_sequence=1,
                    checksum=7,
                )
            ],
            BookGapReason.CHECKSUM_PROTOCOL_VIOLATION,
        ),
        (
            lambda: [
                book(
                    "snapshot-a",
                    action="snapshot",
                    seq_id=1,
                    prev_seq_id=-1,
                    bids=[["10", "1", "0", "1"]],
                    asks=[["11", "1", "0", "1"]],
                    event_time_ns=SECOND,
                    writer_sequence=1,
                ),
                book(
                    "delta-new-generation",
                    action="update",
                    seq_id=2,
                    prev_seq_id=1,
                    bids=[["10", "2", "0", "2"]],
                    asks=[],
                    event_time_ns=2 * SECOND,
                    writer_sequence=2,
                    generation=2,
                ),
            ],
            BookGapReason.CONNECTION_GENERATION_CHANGED,
        ),
    ],
)
def test_protocol_violation_is_causally_invalid(
    records,
    reason: BookGapReason,
) -> None:
    result = _replay(*records())
    assert result.book_valid is False
    assert result.gap_reason is reason


def test_late_impact_stops_at_next_authoritative_snapshot() -> None:
    planner = BookImpactPlanner(revision_horizon_ns=24 * 60 * 60 * SECOND)
    impact = planner.affected_range(
        late_event_ns=35 * SECOND,
        authoritative_snapshot_times=[120 * SECOND],
        horizon_end_ns=24 * 60 * 60 * SECOND,
        interval_ns=30 * SECOND,
    )
    assert impact == TimeRange(30 * SECOND, 120 * SECOND)


def test_late_impact_without_snapshot_extends_to_horizon() -> None:
    planner = BookImpactPlanner(revision_horizon_ns=24 * 60 * 60 * SECOND)
    assert planner.affected_range(
        late_event_ns=35 * SECOND,
        authoritative_snapshot_times=[],
        horizon_end_ns=24 * 60 * 60 * SECOND,
        interval_ns=30 * SECOND,
    ) == TimeRange(30 * SECOND, 24 * 60 * 60 * SECOND)


def test_checkpoint_prefix_mismatch_forces_raw_replay() -> None:
    first = SourceLocator("a" * 64, 0)
    second = SourceLocator("b" * 64, 1)
    checkpoint = BookReplayCheckpoint(
        source_locator=second,
        integrity_mode=IntegrityMode.SEQUENCE_VERIFIED,
        authoritative_ancestor=first,
        source_prefix_sha256=source_prefix_digest([first, second]),
        bids=(("10", "2"),),
        asks=(("11", "3"),),
        sequence_id=10,
    )
    assert checkpoint.matches_prefix([first, second])
    assert not checkpoint.matches_prefix([first, SourceLocator("c" * 64, 1)])
