from __future__ import annotations

import json
from decimal import Decimal, localcontext
from pathlib import Path

import pytest

from crypto_collector.domain.types import CoverageMode, Exchange, Market
from crypto_collector.materializer.books.replay import BookGapReason
from crypto_collector.materializer.datasets.book_live import (
    build_live_book_features,
    select_hourly_live_records,
)
from crypto_collector.materializer.datasets.quality import (
    ExpectationSegment,
    QualityStreamKey,
    QualityWindowRow,
    build_quality_windows,
)
from crypto_collector.materializer.models import TimedSourceRecord
from crypto_collector.materializer.time_policy import EventTimePolicy
from crypto_collector.materializer.windows import Window
from tests.unit.materializer.books.test_replay import POLICY, SECOND, book

GOLDEN = Path(__file__).parents[3] / "golden/materializer/book-live"
KEY = QualityStreamKey(Exchange.OKX, Market.SPOT, "BTC-USDT", "book_live")


def quality(window: Window, *, expected: bool = True) -> QualityWindowRow:
    return QualityWindowRow(
        key=KEY,
        window=window,
        expected=expected,
        expected_duration_ns=window.interval_ns if expected else 0,
        coverage=CoverageMode.COMPLETE if expected else None,
        input_count=0,
        event_time_count=0,
        receive_missing_count=0,
        receive_outlier_count=0,
        event_time_ratio=None,
        quality_event_count=0,
        quality_event_event_time_count=0,
        quality_event_receive_missing_count=0,
        quality_event_receive_outlier_count=0,
        latency_count=0,
        latency_min_ns=None,
        latency_max_ns=None,
        last_event_age_ns=None,
        gap_count=0,
        reconnect_count=0,
        parse_error_count=0,
        checksum_error_count=0,
        sequence_error_count=0,
        queue_overflow_count=0,
        egress_change_count=0,
        throttle_count=0,
        interval_stretch_count=0,
        quality_complete=True,
        lineage_manifest_sha256s=("f" * 64,),
    )


def test_valid_window_outputs_end_state_features_and_quality_link() -> None:
    window = Window(0, 30 * SECOND)
    snapshot = book(
        "snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"], ["9", "3", "0", "1"]],
        asks=[["11", "4", "0", "1"], ["12", "5", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )
    first = book(
        "first",
        action="update",
        seq_id=11,
        prev_seq_id=10,
        bids=[["10", "3", "0", "2"]],
        asks=[],
        event_time_ns=10 * SECOND,
        writer_sequence=2,
    )
    second = book(
        "second",
        action="update",
        seq_id=12,
        prev_seq_id=11,
        bids=[],
        asks=[["11", "5", "0", "2"]],
        event_time_ns=20 * SECOND,
        writer_sequence=3,
    )

    linked_quality = quality(window)
    row = build_live_book_features(
        [second, snapshot, first],
        policy=POLICY,
        windows=[window],
        depths=[1, 2],
        quality_rows=[linked_quality],
    )[0]

    assert row.book_valid
    assert row.mid == Decimal("10.5")
    assert row.spread == Decimal(1)
    assert row.microprice == Decimal("10.375")
    assert row.depth_at(1).bid_notional == Decimal(30)
    assert row.depth_at(2).ask_notional == Decimal(115)
    assert row.update_count == 2
    assert row.stale_duration_ns == 10 * SECOND
    assert row.valid_coverage_ratio == Decimal(
        "0.966666666666666666666666666666666667"
    )
    assert row.quality is linked_quality
    assert row.expected and row.quality_complete
    assert set(row.lineage_manifest_sha256s) == {
        snapshot.locator.manifest_sha256,
        first.locator.manifest_sha256,
        second.locator.manifest_sha256,
        "f" * 64,
    }


def test_gap_nulls_state_until_snapshot_in_later_window() -> None:
    windows = [Window(0, 30 * SECOND), Window(30 * SECOND, 60 * SECOND)]
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
        event_time_ns=20 * SECOND,
        writer_sequence=2,
    )
    recovery = book(
        "recovery",
        action="snapshot",
        seq_id=20,
        prev_seq_id=-1,
        bids=[["20", "1", "0", "1"]],
        asks=[["21", "1", "0", "1"]],
        event_time_ns=35 * SECOND,
        writer_sequence=3,
    )

    rows = build_live_book_features(
        [gap, recovery, snapshot],
        policy=POLICY,
        windows=windows,
        depths=[1],
        quality_rows=[quality(item) for item in windows],
    )

    assert rows[0].book_valid is False and rows[0].mid is None
    assert rows[0].depth_at(1).bid_notional is None
    assert rows[0].gap_reason is BookGapReason.SEQUENCE_MISMATCH
    assert rows[1].book_valid and rows[1].mid == Decimal("20.5")


def test_window_projection_never_skips_a_causal_predecessor() -> None:
    window = Window(0, 30 * SECOND)
    snapshot = book(
        "causal-prefix-snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )
    future_predecessor = book(
        "future-predecessor",
        action="update",
        seq_id=11,
        prev_seq_id=10,
        bids=[["10", "4", "0", "2"]],
        asks=[],
        event_time_ns=35 * SECOND,
        writer_sequence=2,
    )
    regressed_successor = book(
        "regressed-successor",
        action="update",
        seq_id=12,
        prev_seq_id=11,
        bids=[["10", "5", "0", "3"]],
        asks=[],
        event_time_ns=25 * SECOND,
        writer_sequence=3,
    )
    row = build_live_book_features(
        [regressed_successor, snapshot, future_predecessor],
        policy=POLICY,
        windows=[window],
        depths=[1],
        quality_rows=[quality(window)],
    )[0]
    assert row.book_valid
    assert row.update_count == 0
    assert row.depth_at(1).bid_quantity == Decimal(2)


def test_quality_linkage_requires_exact_book_live_window() -> None:
    window = Window(0, 30 * SECOND)
    with pytest.raises(ValueError, match="quality row"):
        build_live_book_features(
            [],
            policy=POLICY,
            windows=[window],
            depths=[1],
            quality_rows=[],
            scope=KEY,
        )


@pytest.mark.parametrize("interval_ns", [30 * SECOND, 60 * SECOND])
def test_features_link_shared_expected_quality_rows(interval_ns: int) -> None:
    snapshot = book(
        f"quality-snapshot-{interval_ns}",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )
    chosen = POLICY.choose(
        event_time_ns=snapshot.envelope.event_time_ns,
        received_at_ns=snapshot.envelope.received_at_ns,
    )
    actual = TimedSourceRecord(
        snapshot,
        chosen.effective_event_time_ns,
        chosen.time_source,
    )
    expectation = ExpectationSegment(
        key=KEY,
        start_ns=0,
        end_ns=60 * SECOND,
        start_time_source=None,
        end_time_source=None,
        coverage=CoverageMode.COMPLETE,
        config_sha256="a" * 64,
        shard_id="book-live-shard",
        lineage_manifest_sha256s=("e" * 64,),
    )
    quality_rows = build_quality_windows(
        [expectation],
        [actual],
        interval_ns=interval_ns,
    )
    windows = [row.window for row in quality_rows]
    features = build_live_book_features(
        [snapshot],
        policy=POLICY,
        windows=windows,
        depths=[1],
        quality_rows=quality_rows,
    )
    assert all(row.expected for row in features)
    assert [row.quality for row in features] == list(quality_rows)
    assert sum(row.quality.input_count for row in features) == 1


def test_hour_lookback_uses_prior_live_snapshot_and_never_deep_book() -> None:
    hour = 60 * 60 * SECOND
    prior = book(
        "prior",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=hour - SECOND,
        writer_sequence=1,
    )
    current = book(
        "current",
        action="update",
        seq_id=11,
        prev_seq_id=10,
        bids=[["10", "4", "0", "2"]],
        asks=[],
        event_time_ns=hour + 5 * SECOND,
        writer_sequence=2,
    )
    deep = prior.envelope.model_copy(
        update={"logical_stream": "book_deep_snapshot", "native_channel": "books-full"}
    )
    selected = select_hourly_live_records(
        [current, prior, type(prior)(deep, prior.locator)],
        policy=POLICY,
        hour_start_ns=hour,
        hour_end_ns=2 * hour,
    )
    assert selected == (prior, current)


def test_hour_lookback_does_not_promote_malformed_snapshot_to_authority() -> None:
    hour = 60 * 60 * SECOND
    prior = book(
        "prior-valid",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10", "2", "0", "1"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=hour - 3 * SECOND,
        writer_sequence=1,
    )
    malformed = book(
        "malformed-snapshot",
        action="snapshot",
        seq_id=11,
        prev_seq_id=10,
        bids=[["10", "4", "0", "2"]],
        asks=[["11", "3", "0", "1"]],
        event_time_ns=hour - 2 * SECOND,
        writer_sequence=2,
    )
    current = book(
        "current-after-malformed",
        action="update",
        seq_id=12,
        prev_seq_id=11,
        bids=[["10", "5", "0", "3"]],
        asks=[],
        event_time_ns=hour + SECOND,
        writer_sequence=3,
    )
    assert select_hourly_live_records(
        [current, malformed, prior],
        policy=POLICY,
        hour_start_ns=hour,
        hour_end_ns=2 * hour,
    ) == (prior, malformed, current)


def test_features_do_not_depend_on_process_decimal_context() -> None:
    window = Window(0, 30 * SECOND)
    snapshot = book(
        "decimal-snapshot",
        action="snapshot",
        seq_id=10,
        prev_seq_id=-1,
        bids=[["10.12345", "2.12345", "0", "1"]],
        asks=[["11.98765", "3.98765", "0", "1"]],
        event_time_ns=SECOND,
        writer_sequence=1,
    )

    def build():
        return build_live_book_features(
            [snapshot],
            policy=POLICY,
            windows=[window],
            depths=[1],
            quality_rows=[quality(window)],
        )[0]

    baseline = build()
    with localcontext() as context:
        context.prec = 3
        constrained = build()
    assert constrained.mid == baseline.mid
    assert constrained.microprice == baseline.microprice
    assert constrained.depths == baseline.depths


def _canonical(row) -> dict[str, object]:
    return {
        "window_start_ns": row.window.start_ns,
        "window_end_ns": row.window.end_ns,
        "book_valid": row.book_valid,
        "gap_reason": None if row.gap_reason is None else row.gap_reason.value,
        "mid": None if row.mid is None else str(row.mid),
        "spread": None if row.spread is None else str(row.spread),
        "update_count": row.update_count,
        "heartbeat_count": row.heartbeat_count,
        "sequence_reset_count": row.sequence_reset_count,
        "expected": row.expected,
        "quality_complete": row.quality_complete,
    }


@pytest.mark.parametrize(
    ("interval_ns", "expected_name"),
    [(30 * SECOND, "expected-30s.json"), (60 * SECOND, "expected-1m.json")],
)
def test_okx_book_fixture_matches_goldens(interval_ns: int, expected_name: str) -> None:
    raw = json.loads((GOLDEN / "raw.json").read_text())
    records = [book(**item) for item in raw]
    end_ns = 60 * SECOND
    windows = [Window(start, start + interval_ns) for start in range(0, end_ns, interval_ns)]
    rows = build_live_book_features(
        records,
        policy=EventTimePolicy(SECOND, SECOND),
        windows=windows,
        depths=[1],
        quality_rows=[quality(window) for window in windows],
    )
    assert [_canonical(row) for row in rows] == json.loads(
        (GOLDEN / expected_name).read_text()
    )
