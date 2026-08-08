from __future__ import annotations

import hashlib
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal, Subnormal, localcontext
from pathlib import Path
from typing import Any

import pytest

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.types import (
    CloseReason,
    CoverageMode,
    Exchange,
    Market,
    Transport,
)
from crypto_collector.materializer.datasets.quality import (
    ExpectationContractError,
    ExpectationSegment,
    ManifestQualityCount,
    ManifestQualityReconciliation,
    QualityEvent,
    QualityEventKind,
    QualityStreamKey,
    SubscriptionExpectationCheckpoint,
    TimedQualityEvent,
    apply_quality_event_time_policy,
    build_expectation_segments,
    build_quality_windows,
    decode_subscription_expectation,
    reconcile_manifest_quality,
)
from crypto_collector.materializer.models import (
    DiscoveredRawInput,
    SourceLocator,
    SourceRecord,
    TimedSourceRecord,
    TimeSource,
)
from crypto_collector.materializer.time_policy import EventTimePolicy
from crypto_collector.storage.manifest import (
    RECOVERY_UNAVAILABLE_FIELDS,
    RawManifestV1,
    RecoverySourceState,
    lease_path_for_data,
    manifest_path_for_data,
)

SECOND_NS = 1_000_000_000
WINDOW_NS = 30 * SECOND_NS
HOUR_NS = 60 * 60 * SECOND_NS
MAX_SIGNED_INT64 = 2**63 - 1
CONFIG_SHA = "a" * 64
TRADE_KEY = QualityStreamKey(
    exchange=Exchange.OKX,
    market=Market.SPOT,
    instrument_key="BTC-USDT",
    logical_stream="trade",
)
BOOK_KEY = QualityStreamKey(
    exchange=Exchange.OKX,
    market=Market.SPOT,
    instrument_key="BTC-USDT",
    logical_stream="book_l2",
)
CHECKPOINT_POLICY = EventTimePolicy(
    max_past_skew_ns=HOUR_NS,
    max_future_skew_ns=HOUR_NS,
)


def _expectation_item(
    *,
    market: str | None = "spot",
    instrument_key: str | None = "BTC-USDT",
    logical_stream: str = "trade",
    shard_id: str = "spot-0",
    coverage: str = "complete",
) -> dict[str, object]:
    return {
        "market": market,
        "instrument_key": instrument_key,
        "logical_stream": logical_stream,
        "shard_id": shard_id,
        "coverage": coverage,
    }


def _control_item() -> dict[str, object]:
    return _expectation_item(
        market=None,
        instrument_key=None,
        logical_stream="_control",
        shard_id="_control",
    )


def _checkpoint_payload(
    *,
    start_ns: int = 0,
    end_ns: int | None = None,
    config_sha256: str = CONFIG_SHA,
    expectations: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "kind": "subscription_expectation",
        "effective_start_ns": start_ns,
        "config_sha256": config_sha256,
        "expectations": expectations or [_control_item(), _expectation_item()],
    }
    if end_ns is not None:
        payload["effective_end_ns"] = end_ns
    return payload


def _control_source(
    payload: Any,
    *,
    received_at_ns: int = 1,
    manifest_sha: str = "b" * 64,
    record_index: int = 0,
    writer_sequence: int = 1,
    worker_instance_id: str = "worker-1",
    config_sha256: str = CONFIG_SHA,
) -> SourceRecord:
    envelope = RawEnvelope(
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
        payload=payload,
        received_at_ns=received_at_ns,
        monotonic_ns=received_at_ns,
        worker_instance_id=worker_instance_id,
        connection_id=None,
        connection_generation=None,
        writer_sequence=writer_sequence,
        egress_id=None,
        config_sha256=config_sha256,
    )
    return SourceRecord(
        envelope=envelope,
        locator=SourceLocator(
            manifest_sha256=manifest_sha,
            zero_based_record_index=record_index,
        ),
    )


def _actual(
    *,
    event_time_ns: int | None,
    received_at_ns: int,
    effective_event_time_ns: int,
    time_source: TimeSource,
    manifest_sha: str,
    record_index: int,
) -> TimedSourceRecord:
    envelope = RawEnvelope(
        schema_version=1,
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="trade",
        native_channel="trades",
        transport=Transport.WEBSOCKET,
        event_time_ns=event_time_ns,
        event_time_source="venue" if event_time_ns is not None else None,
        integrity_mode=None,
        coverage=None,
        rest_metadata=None,
        payload={"trade_id": f"trade-{record_index}"},
        received_at_ns=received_at_ns,
        monotonic_ns=received_at_ns,
        worker_instance_id="worker-1",
        connection_id="connection-1",
        connection_generation=1,
        writer_sequence=record_index + 1,
        egress_id="direct-primary",
        config_sha256=CONFIG_SHA,
    )
    return TimedSourceRecord(
        source=SourceRecord(
            envelope=envelope,
            locator=SourceLocator(
                manifest_sha256=manifest_sha,
                zero_based_record_index=record_index,
            ),
        ),
        effective_event_time_ns=effective_event_time_ns,
        time_source=time_source,
    )


def _decode_checkpoint(
    *,
    start_ns: int,
    end_ns: int | None = None,
    manifest_sha: str,
    record_index: int = 0,
    received_at_ns: int | None = None,
    expectations: list[dict[str, object]] | None = None,
    config_sha256: str = CONFIG_SHA,
    policy: EventTimePolicy = CHECKPOINT_POLICY,
) -> SubscriptionExpectationCheckpoint:
    decoded = decode_subscription_expectation(
        _control_source(
            _checkpoint_payload(
                start_ns=start_ns,
                end_ns=end_ns,
                config_sha256=config_sha256,
                expectations=expectations,
            ),
            received_at_ns=(start_ns + 1 if received_at_ns is None else received_at_ns),
            manifest_sha=manifest_sha,
            record_index=record_index,
            writer_sequence=record_index + 1,
            config_sha256=config_sha256,
        ),
        policy=policy,
    )
    assert decoded is not None
    return decoded


def _quality_event(
    kind: QualityEventKind,
    *,
    event_id: str,
    effective_event_time_ns: int = SECOND_NS,
    manifest_sha: str = "e" * 64,
    record_index: int = 0,
    targets: tuple[QualityStreamKey, ...] = (TRADE_KEY,),
) -> TimedQualityEvent:
    source = _control_source(
        {"kind": "typed-fixture"},
        received_at_ns=effective_event_time_ns,
        manifest_sha=manifest_sha,
        record_index=record_index,
        writer_sequence=record_index + 1,
    )
    return TimedQualityEvent(
        event=QualityEvent(
            source=source,
            targets=targets,
            event_id=event_id,
            kind=kind,
            event_time_ns=None,
        ),
        effective_event_time_ns=effective_event_time_ns,
        time_source=TimeSource.RECEIVE_MISSING,
    )


def test_decoder_accepts_only_the_exact_plan04_checkpoint_shape() -> None:
    source = _control_source(_checkpoint_payload(start_ns=10), received_at_ns=11)

    checkpoint = decode_subscription_expectation(source, policy=CHECKPOINT_POLICY)

    assert checkpoint is not None
    assert checkpoint.source is source
    assert checkpoint.declared_start_ns == 10
    assert checkpoint.declared_end_ns is None
    assert checkpoint.effective_start_ns == 10
    assert checkpoint.start_time_source is TimeSource.EVENT
    assert checkpoint.effective_end_ns is None
    assert checkpoint.end_time_source is None
    assert checkpoint.config_sha256 == CONFIG_SHA
    assert [item.key.logical_stream for item in checkpoint.expectations] == [
        "_control",
        "trade",
    ]
    assert checkpoint.expectations[1].coverage is CoverageMode.COMPLETE
    assert (
        decode_subscription_expectation(
            _control_source({"kind": "queue_overflow"}),
            policy=CHECKPOINT_POLICY,
        )
        is None
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda payload: payload.update(extra="not-frozen"),
        lambda payload: payload.update(effective_start_ns=True),
        lambda payload: payload.update(effective_end_ns=None),
        lambda payload: payload.update(effective_end_ns=-1),
        lambda payload: payload.update(config_sha256="c" * 64),
        lambda payload: payload.update(
            expectations=list(reversed(payload["expectations"]))
        ),
        lambda payload: payload["expectations"][1].update(extra="not-frozen"),
        lambda payload: payload["expectations"].append(
            _expectation_item(shard_id="spot-1")
        ),
        lambda payload: payload.update(expectations=[_expectation_item()]),
    ],
)
def test_decoder_fails_closed_on_malformed_or_ambiguous_checkpoint(
    mutation: Any,
) -> None:
    payload = _checkpoint_payload(start_ns=10, end_ns=20)
    mutation(payload)

    with pytest.raises(ExpectationContractError):
        decode_subscription_expectation(
            _control_source(payload),
            policy=CHECKPOINT_POLICY,
        )


def test_decoder_rejects_reversed_but_allows_zero_length_close() -> None:
    with pytest.raises(ExpectationContractError, match="end"):
        decode_subscription_expectation(
            _control_source(_checkpoint_payload(start_ns=20, end_ns=19)),
            policy=CHECKPOINT_POLICY,
        )

    closed = decode_subscription_expectation(
        _control_source(_checkpoint_payload(start_ns=20, end_ns=20)),
        policy=CHECKPOINT_POLICY,
    )
    assert closed is not None and closed.effective_end_ns == 20


def test_decoder_rejects_control_source_with_inapplicable_top_level_coverage() -> None:
    source = _control_source(_checkpoint_payload())
    envelope = source.envelope.model_copy(update={"coverage": CoverageMode.UNKNOWN})
    invalid = SourceRecord(envelope=envelope, locator=source.locator)

    with pytest.raises(ExpectationContractError, match="control"):
        decode_subscription_expectation(invalid, policy=CHECKPOINT_POLICY)


def test_checkpoint_model_cannot_bypass_the_control_source_contract() -> None:
    valid = _decode_checkpoint(start_ns=0, manifest_sha="1" * 64)
    data_source = _actual(
        event_time_ns=1,
        received_at_ns=1,
        effective_event_time_ns=1,
        time_source=TimeSource.EVENT,
        manifest_sha="2" * 64,
        record_index=0,
    ).source

    with pytest.raises(ValueError, match="control"):
        replace(valid, source=data_source)


def test_checkpoint_model_cannot_bypass_payload_binding() -> None:
    valid = _decode_checkpoint(start_ns=10, manifest_sha="1" * 64)

    with pytest.raises(ValueError, match="subscription_expectation"):
        replace(valid, source=_control_source({"kind": "queue_overflow"}))
    with pytest.raises(ValueError, match="payload"):
        replace(
            valid,
            source=_control_source(
                _checkpoint_payload(start_ns=999),
                received_at_ns=1_000,
            ),
        )


def test_checkpoint_policy_chooses_open_start_and_close_end_independently() -> None:
    strict = EventTimePolicy(max_past_skew_ns=0, max_future_skew_ns=0)
    opened = decode_subscription_expectation(
        _control_source(
            _checkpoint_payload(start_ns=10),
            received_at_ns=20,
            manifest_sha="1" * 64,
        ),
        policy=strict,
    )
    closed = decode_subscription_expectation(
        _control_source(
            _checkpoint_payload(start_ns=10, end_ns=40),
            received_at_ns=30,
            manifest_sha="2" * 64,
        ),
        policy=strict,
    )

    assert opened is not None and closed is not None
    assert opened.declared_start_ns == closed.declared_start_ns == 10
    assert opened.declared_end_ns is None
    assert closed.declared_end_ns == 40
    assert opened.effective_start_ns == 20
    assert opened.start_time_source is TimeSource.RECEIVE_OUTLIER
    assert opened.effective_end_ns is None
    assert closed.effective_start_ns is None
    assert closed.start_time_source is None
    assert closed.effective_end_ns == 30
    assert closed.end_time_source is TimeSource.RECEIVE_OUTLIER

    segment = build_expectation_segments(
        (opened, closed),
        range_start_ns=0,
        range_end_ns=100,
    )[0]
    assert (segment.start_ns, segment.end_ns) == (20, 30)
    assert segment.start_time_source is TimeSource.RECEIVE_OUTLIER
    assert segment.end_time_source is TimeSource.RECEIVE_OUTLIER


def test_checkpoint_policy_is_unique_per_config_but_may_change_with_config() -> None:
    strict = EventTimePolicy(max_past_skew_ns=0, max_future_skew_ns=0)
    permissive = EventTimePolicy(
        max_past_skew_ns=HOUR_NS,
        max_future_skew_ns=HOUR_NS,
    )
    opened = _decode_checkpoint(
        start_ns=10,
        received_at_ns=20,
        manifest_sha="1" * 64,
        policy=strict,
    )
    closed_with_other_policy = _decode_checkpoint(
        start_ns=10,
        end_ns=40,
        received_at_ns=30,
        manifest_sha="2" * 64,
        policy=permissive,
    )

    with pytest.raises(ExpectationContractError, match="policy"):
        build_expectation_segments(
            (opened, closed_with_other_policy),
            range_start_ns=0,
            range_end_ns=100,
        )

    next_config = "b" * 64
    changed = _decode_checkpoint(
        start_ns=WINDOW_NS,
        received_at_ns=WINDOW_NS,
        manifest_sha="3" * 64,
        config_sha256=next_config,
        policy=permissive,
    )
    segments = build_expectation_segments(
        (opened, changed),
        range_start_ns=0,
        range_end_ns=2 * WINDOW_NS,
    )
    assert {segment.config_sha256 for segment in segments} == {
        CONFIG_SHA,
        next_config,
    }


def test_checkpoint_close_requires_one_exact_declared_start_open() -> None:
    close = _decode_checkpoint(
        start_ns=10,
        end_ns=20,
        manifest_sha="1" * 64,
    )

    with pytest.raises(ExpectationContractError, match="open"):
        build_expectation_segments(
            (close,),
            range_start_ns=0,
            range_end_ns=100,
        )


def test_checkpoint_rejects_chosen_end_before_chosen_open_start() -> None:
    strict = EventTimePolicy(max_past_skew_ns=0, max_future_skew_ns=0)
    opened = decode_subscription_expectation(
        _control_source(
            _checkpoint_payload(start_ns=10),
            received_at_ns=20,
            manifest_sha="1" * 64,
        ),
        policy=strict,
    )
    closed = decode_subscription_expectation(
        _control_source(
            _checkpoint_payload(start_ns=10, end_ns=15),
            received_at_ns=15,
            manifest_sha="2" * 64,
        ),
        policy=strict,
    )

    assert opened is not None and closed is not None
    with pytest.raises(ExpectationContractError, match="precedes"):
        build_expectation_segments(
            (opened, closed),
            range_start_ns=0,
            range_end_ns=100,
        )


def test_checkpoint_declared_token_rejects_duplicate_open_or_close() -> None:
    opens = (
        _decode_checkpoint(start_ns=10, manifest_sha="1" * 64, record_index=0),
        _decode_checkpoint(start_ns=10, manifest_sha="2" * 64, record_index=1),
    )
    with pytest.raises(ExpectationContractError, match="multiple open"):
        build_expectation_segments(opens, range_start_ns=0, range_end_ns=100)

    close_one = _decode_checkpoint(
        start_ns=10,
        end_ns=20,
        manifest_sha="3" * 64,
        record_index=2,
    )
    close_two = _decode_checkpoint(
        start_ns=10,
        end_ns=20,
        manifest_sha="4" * 64,
        record_index=3,
    )
    with pytest.raises(ExpectationContractError, match="multiple close"):
        build_expectation_segments(
            (opens[0], close_one, close_two),
            range_start_ns=0,
            range_end_ns=100,
        )


def test_query_range_clamps_have_no_fabricated_time_source() -> None:
    opened = _decode_checkpoint(start_ns=10, manifest_sha="1" * 64)
    closed = _decode_checkpoint(
        start_ns=10,
        end_ns=40,
        manifest_sha="2" * 64,
    )

    segment = build_expectation_segments(
        (opened, closed),
        range_start_ns=15,
        range_end_ns=35,
    )[0]

    assert (segment.start_ns, segment.end_ns) == (15, 35)
    assert segment.start_time_source is None
    assert segment.end_time_source is None


def test_checkpoint_fallback_effective_start_collisions_fail_closed() -> None:
    strict = EventTimePolicy(max_past_skew_ns=0, max_future_skew_ns=0)
    checkpoints = tuple(
        decode_subscription_expectation(
            _control_source(
                _checkpoint_payload(start_ns=declared_start),
                received_at_ns=10,
                manifest_sha=marker * 64,
                record_index=index,
            ),
            policy=strict,
        )
        for index, (declared_start, marker) in enumerate(((0, "1"), (1, "2")))
    )

    with pytest.raises(ExpectationContractError, match="effective start"):
        build_expectation_segments(
            (item for item in checkpoints if item is not None),
            range_start_ns=0,
            range_end_ns=100,
        )


def test_timeline_merges_same_start_close_and_uses_next_snapshot_as_boundary() -> None:
    first = _decode_checkpoint(start_ns=0, manifest_sha="1" * 64)
    hourly = _decode_checkpoint(
        start_ns=WINDOW_NS,
        manifest_sha="2" * 64,
        record_index=1,
    )
    close = _decode_checkpoint(
        start_ns=WINDOW_NS,
        end_ns=2 * WINDOW_NS,
        manifest_sha="3" * 64,
        record_index=2,
    )

    segments = build_expectation_segments(
        reversed((first, hourly, close)),
        range_start_ns=0,
        range_end_ns=2 * WINDOW_NS,
    )
    trades = [segment for segment in segments if segment.key == TRADE_KEY]

    assert [(item.start_ns, item.end_ns) for item in trades] == [
        (0, WINDOW_NS),
        (WINDOW_NS, 2 * WINDOW_NS),
    ]
    assert trades[0].lineage_manifest_sha256s == ("1" * 64, "2" * 64, "3" * 64)
    assert trades[1].lineage_manifest_sha256s == ("2" * 64, "3" * 64)


def test_timeline_closes_removed_stream_and_zero_length_state_covers_nothing() -> None:
    selected = _decode_checkpoint(start_ns=0, manifest_sha="1" * 64)
    removed = _decode_checkpoint(
        start_ns=45 * SECOND_NS,
        manifest_sha="2" * 64,
        expectations=[_control_item()],
    )
    zero = _decode_checkpoint(
        start_ns=50 * SECOND_NS,
        end_ns=50 * SECOND_NS,
        manifest_sha="3" * 64,
        expectations=[_control_item()],
    )
    zero_open = _decode_checkpoint(
        start_ns=50 * SECOND_NS,
        manifest_sha="4" * 64,
        record_index=3,
        expectations=[_control_item()],
    )

    segments = build_expectation_segments(
        (zero, zero_open, removed, selected),
        range_start_ns=0,
        range_end_ns=2 * WINDOW_NS,
    )

    assert [
        (segment.start_ns, segment.end_ns)
        for segment in segments
        if segment.key == TRADE_KEY
    ] == [(0, 45 * SECOND_NS)]


def test_timeline_rejects_conflicting_same_start_or_overlapping_explicit_end() -> None:
    first_close = _decode_checkpoint(
        start_ns=0,
        end_ns=2 * WINDOW_NS,
        manifest_sha="1" * 64,
    )
    first_open = _decode_checkpoint(start_ns=0, manifest_sha="4" * 64)
    conflict = _decode_checkpoint(
        start_ns=0,
        manifest_sha="2" * 64,
        expectations=[_control_item()],
    )
    later = _decode_checkpoint(start_ns=WINDOW_NS, manifest_sha="3" * 64)

    with pytest.raises(ExpectationContractError, match="conflict"):
        build_expectation_segments(
            (first_close, conflict),
            range_start_ns=0,
            range_end_ns=2 * WINDOW_NS,
        )
    with pytest.raises(ExpectationContractError, match="overlaps"):
        build_expectation_segments(
            (first_open, first_close, later),
            range_start_ns=0,
            range_end_ns=2 * WINDOW_NS,
        )


def test_completely_silent_expected_stream_still_has_quality_rows() -> None:
    opened = _decode_checkpoint(start_ns=0, manifest_sha="1" * 64)
    closed = _decode_checkpoint(
        start_ns=0,
        end_ns=2 * WINDOW_NS,
        manifest_sha="2" * 64,
    )
    segments = build_expectation_segments(
        (opened, closed),
        range_start_ns=0,
        range_end_ns=2 * WINDOW_NS,
    )

    rows = build_quality_windows(
        segments,
        actual_records=(),
        interval_ns=WINDOW_NS,
    )
    trades = [row for row in rows if row.key == TRADE_KEY]

    assert [row.input_count for row in trades] == [0, 0]
    assert all(row.expected for row in trades)
    assert all(row.expected_duration_ns == WINDOW_NS for row in trades)
    assert all(row.event_time_ratio is None for row in trades)
    assert all(row.latency_min_ns is row.latency_max_ns is None for row in trades)
    assert all(row.last_event_age_ns is None for row in trades)
    assert all(row.lineage_manifest_sha256s == ("1" * 64, "2" * 64) for row in trades)


def test_empty_builder_still_validates_the_window_interval() -> None:
    with pytest.raises(ValueError, match="interval"):
        build_quality_windows(
            expectations=(),
            actual_records=(),
            quality_events=(),
            interval_ns=1,
        )


def test_silent_expectation_segment_requires_checkpoint_lineage() -> None:
    with pytest.raises(ValueError, match="lineage"):
        ExpectationSegment(
            key=TRADE_KEY,
            start_ns=0,
            end_ns=WINDOW_NS,
            start_time_source=TimeSource.EVENT,
            end_time_source=TimeSource.EVENT,
            coverage=CoverageMode.COMPLETE,
            config_sha256=CONFIG_SHA,
            shard_id="spot-0",
            lineage_manifest_sha256s=(),
        )


def test_half_open_and_partial_expectation_coverage_are_exact() -> None:
    opened = _decode_checkpoint(
        start_ns=10 * SECOND_NS,
        manifest_sha="1" * 64,
    )
    closed = _decode_checkpoint(
        start_ns=10 * SECOND_NS,
        end_ns=40 * SECOND_NS,
        manifest_sha="2" * 64,
    )
    segments = build_expectation_segments(
        (opened, closed),
        range_start_ns=0,
        range_end_ns=2 * WINDOW_NS,
    )
    boundary_actual = _actual(
        event_time_ns=WINDOW_NS,
        received_at_ns=WINDOW_NS,
        effective_event_time_ns=WINDOW_NS,
        time_source=TimeSource.EVENT,
        manifest_sha="4" * 64,
        record_index=0,
    )

    rows = [
        row
        for row in build_quality_windows(
            segments,
            actual_records=(boundary_actual,),
            quality_events=(),
            interval_ns=WINDOW_NS,
        )
        if row.key == TRADE_KEY
    ]

    assert [(row.window.start_ns, row.expected_duration_ns) for row in rows] == [
        (0, 20 * SECOND_NS),
        (WINDOW_NS, 10 * SECOND_NS),
    ]
    assert [row.input_count for row in rows] == [0, 1]


def test_actual_only_row_and_timed_record_metrics_are_deterministic() -> None:
    records = (
        _actual(
            event_time_ns=5 * SECOND_NS,
            received_at_ns=8 * SECOND_NS,
            effective_event_time_ns=5 * SECOND_NS,
            time_source=TimeSource.EVENT,
            manifest_sha="3" * 64,
            record_index=0,
        ),
        _actual(
            event_time_ns=None,
            received_at_ns=6 * SECOND_NS,
            effective_event_time_ns=6 * SECOND_NS,
            time_source=TimeSource.RECEIVE_MISSING,
            manifest_sha="2" * 64,
            record_index=0,
        ),
        _actual(
            event_time_ns=100 * SECOND_NS,
            received_at_ns=7 * SECOND_NS,
            effective_event_time_ns=7 * SECOND_NS,
            time_source=TimeSource.RECEIVE_OUTLIER,
            manifest_sha="1" * 64,
            record_index=0,
        ),
    )

    with localcontext() as ambient:
        ambient.Emin = 0
        ambient.traps[Subnormal] = True
        rows = build_quality_windows(
            expectations=(),
            actual_records=reversed(records),
            quality_events=(),
            interval_ns=WINDOW_NS,
        )

    assert len(rows) == 1
    row = rows[0]
    assert row.key == TRADE_KEY
    assert row.expected is False and row.expected_duration_ns == 0
    assert row.coverage is None
    assert row.input_count == 3
    assert row.event_time_count == 1
    assert row.receive_missing_count == 1
    assert row.receive_outlier_count == 1
    assert row.event_time_ratio == Decimal("0.333333333333333333333333333333333333")
    assert row.latency_count == 3
    assert row.latency_min_ns == 0
    assert row.latency_max_ns == 3 * SECOND_NS
    assert row.last_event_age_ns == 23 * SECOND_NS
    assert row.lineage_manifest_sha256s == (
        "1" * 64,
        "2" * 64,
        "3" * 64,
    )


def test_latency_is_received_minus_effective_and_may_be_negative() -> None:
    future_exchange_time = _actual(
        event_time_ns=10 * SECOND_NS,
        received_at_ns=8 * SECOND_NS,
        effective_event_time_ns=10 * SECOND_NS,
        time_source=TimeSource.EVENT,
        manifest_sha="1" * 64,
        record_index=0,
    )

    row = build_quality_windows(
        expectations=(),
        actual_records=(future_exchange_time,),
        quality_events=(),
        interval_ns=WINDOW_NS,
    )[0]

    assert row.latency_min_ns == row.latency_max_ns == -2 * SECOND_NS


def test_every_typed_quality_event_has_an_independent_window_counter() -> None:
    events = tuple(
        _quality_event(
            kind,
            event_id=f"event-{index}",
            manifest_sha=f"{index + 1:x}" * 64,
            record_index=index,
        )
        for index, kind in enumerate(QualityEventKind)
    )

    row = build_quality_windows(
        expectations=(),
        actual_records=(),
        quality_events=reversed(events),
        interval_ns=WINDOW_NS,
    )[0]

    for kind in QualityEventKind:
        assert getattr(row, f"{kind.value}_count") == 1
    assert row.input_count == 0
    assert row.quality_event_count == len(QualityEventKind)
    assert row.quality_event_event_time_count == 0
    assert row.quality_event_receive_missing_count == len(QualityEventKind)
    assert row.quality_event_receive_outlier_count == 0
    assert row.last_event_age_ns is None
    assert row.quality_complete is False


def test_one_quality_event_projects_once_to_each_canonical_target() -> None:
    event = _quality_event(
        QualityEventKind.GAP,
        event_id="multi-target",
        targets=(BOOK_KEY, TRADE_KEY),
    )

    rows = build_quality_windows(
        expectations=(),
        actual_records=(),
        quality_events=(event,),
        interval_ns=WINDOW_NS,
    )

    assert [row.key for row in rows] == [BOOK_KEY, TRADE_KEY]
    assert [row.gap_count for row in rows] == [1, 1]
    assert [row.quality_event_count for row in rows] == [1, 1]


@pytest.mark.parametrize(
    "targets",
    [(), (TRADE_KEY, TRADE_KEY), (TRADE_KEY, BOOK_KEY)],
)
def test_quality_event_targets_must_be_nonempty_sorted_and_unique(
    targets: tuple[QualityStreamKey, ...],
) -> None:
    source = _control_source({"kind": "typed-fixture"})

    with pytest.raises(ValueError, match="targets"):
        QualityEvent(
            source=source,
            targets=targets,
            event_id="event-1",
            kind=QualityEventKind.GAP,
            event_time_ns=None,
        )


def test_quality_event_time_policy_is_preserved_in_separate_row_counters() -> None:
    raw_events = tuple(
        QualityEvent(
            source=_control_source(
                {"kind": "typed-fixture"},
                received_at_ns=received_at_ns,
                manifest_sha=marker * 64,
                record_index=index,
            ),
            targets=(TRADE_KEY,),
            event_id=f"event-{index}",
            kind=QualityEventKind.GAP,
            event_time_ns=event_time_ns,
        )
        for index, (event_time_ns, received_at_ns, marker) in enumerate(
            ((5, 6, "1"), (None, 7, "2"), (100, 8, "3"))
        )
    )

    timed = apply_quality_event_time_policy(
        raw_events,
        EventTimePolicy(max_past_skew_ns=2, max_future_skew_ns=2),
    )
    assert [item.time_source for item in timed] == [
        TimeSource.EVENT,
        TimeSource.RECEIVE_MISSING,
        TimeSource.RECEIVE_OUTLIER,
    ]

    row = build_quality_windows(
        expectations=(),
        actual_records=(),
        quality_events=timed,
        interval_ns=WINDOW_NS,
    )[0]
    assert row.input_count == 0
    assert row.event_time_count == 0
    assert row.receive_missing_count == 0
    assert row.receive_outlier_count == 0
    assert row.quality_event_count == 3
    assert row.quality_event_event_time_count == 1
    assert row.quality_event_receive_missing_count == 1
    assert row.quality_event_receive_outlier_count == 1


def test_quality_models_reject_duplicate_event_ids_and_are_immutable() -> None:
    event = _quality_event(QualityEventKind.GAP, event_id="duplicate")

    with pytest.raises(ValueError, match="event_id"):
        build_quality_windows(
            expectations=(),
            actual_records=(),
            quality_events=(event, event),
            interval_ns=WINDOW_NS,
        )
    with pytest.raises(FrozenInstanceError):
        event.effective_event_time_ns = 2  # type: ignore[misc]


def test_quality_window_counters_must_fit_signed_int64() -> None:
    event = _quality_event(QualityEventKind.GAP, event_id="event-1")
    row = build_quality_windows(
        expectations=(),
        actual_records=(),
        quality_events=(event,),
        interval_ns=WINDOW_NS,
    )[0]

    with pytest.raises(ValueError, match="signed 64-bit"):
        replace(row, gap_count=MAX_SIGNED_INT64 + 1)

    with pytest.raises(ValueError, match="kind counts"):
        replace(row, gap_count=0)


@pytest.mark.parametrize("ratio", [1, 1.0])
def test_quality_window_event_time_ratio_requires_decimal(ratio: Any) -> None:
    row = build_quality_windows(
        expectations=(),
        actual_records=(
            _actual(
                event_time_ns=1,
                received_at_ns=2,
                effective_event_time_ns=1,
                time_source=TimeSource.EVENT,
                manifest_sha="a" * 64,
                record_index=0,
            ),
        ),
        interval_ns=WINDOW_NS,
    )[0]

    with pytest.raises(TypeError, match="Decimal"):
        replace(row, event_time_ratio=ratio)


def test_timed_quality_event_rejects_raw_receive_time_outside_int64() -> None:
    source = _control_source(
        {"kind": "typed-fixture"},
        received_at_ns=MAX_SIGNED_INT64 + 1,
    )
    event = QualityEvent(
        source=source,
        targets=(TRADE_KEY,),
        event_id="event-1",
        kind=QualityEventKind.GAP,
        event_time_ns=1,
    )

    with pytest.raises(ValueError, match="signed 64-bit"):
        TimedQualityEvent(
            event=event,
            effective_event_time_ns=1,
            time_source=TimeSource.EVENT,
        )


def _manifest_input(
    tmp_path: Path,
    *,
    manifest_sha_marker: str = "f",
    logical_stream: str = "trade",
    counters: dict[str, int | None] | None = None,
    control_event_ids: tuple[str, ...] | None = (),
    recovery: bool = False,
) -> DiscoveredRawInput:
    received_at_ns = SECOND_NS
    data_relative_path = (
        "raw/okx/spot/BTC-USDT/"
        f"{logical_stream}/1970/01/01/00/part-{received_at_ns}-0.jsonl.zst"
    )
    values: dict[str, object] = {
        "schema_version": 1,
        "exchange": Exchange.OKX,
        "market": Market.SPOT,
        "instrument_key": "BTC-USDT",
        "logical_stream": logical_stream,
        "wire_symbols": ("BTC-USDT",),
        "data_relative_path": data_relative_path,
        "manifest_relative_path": manifest_path_for_data(data_relative_path).as_posix(),
        "file_size_bytes": 1,
        "file_sha256": manifest_sha_marker * 64,
        "zstd_level": 3,
        "zstd_write_checksum": True,
        "zstd_write_content_size": True,
        "max_plain_frame_bytes": 1,
        "record_count": 1,
        "first_received_at_ns": received_at_ns,
        "last_received_at_ns": received_at_ns,
        "first_event_time_ns": received_at_ns,
        "last_event_time_ns": received_at_ns,
        "worker_instance_id": "worker-1",
        "connection_generations": (1,),
        "writer_sequence_first": 1,
        "writer_sequence_last": 1,
        "config_sha256": CONFIG_SHA,
        "egress_ids": ("direct-primary",),
        "requested_intervals_ns": (),
        "effective_intervals_ns": (),
        "gap_count": 0,
        "reconnect_count": 0,
        "parse_error_count": 0,
        "checksum_error_count": 0,
        "queue_overflow_count": 0,
        "control_event_ids": control_event_ids,
        "durability_measurement": "measured",
        "durability_sample_count": 1,
        "durability_lag_p50_ns": 1,
        "durability_lag_p95_ns": 1,
        "durability_lag_p99_ns": 1,
        "durability_lag_max_ns": 1,
        "sync_count": 1,
        "sync_duration_total_ns": 1,
        "sync_duration_max_ns": 1,
        "slo_breach_count": 0,
        "write_failure_count": 0,
        "sync_failure_count": 0,
        "close_reason": CloseReason.SHUTDOWN,
        "created_at_ns": 0,
        "closed_at_ns": received_at_ns,
        "recovery_transaction_id": None,
        "recovery_source_state": None,
        "recovery_source_relative_path": None,
        "recovery_source_bytes": None,
        "recovery_source_sha256": None,
        "recovery_control_event_id": None,
        "recovered_frame_count": None,
        "recovered_record_count": None,
        "recovered_bytes": None,
        "recovered_sha256": None,
        "quarantined_suffix_relative_path": None,
        "quarantined_suffix_bytes": None,
        "quarantined_suffix_sha256": None,
        "unavailable_fields": (),
    }
    if counters:
        values.update(counters)
    if recovery:
        transaction_id = "123e4567-e89b-42d3-a456-426614174000"
        values.update(
            zstd_level=None,
            max_plain_frame_bytes=None,
            gap_count=None,
            reconnect_count=None,
            parse_error_count=None,
            checksum_error_count=None,
            queue_overflow_count=None,
            control_event_ids=None,
            durability_measurement="unavailable_after_crash",
            durability_sample_count=None,
            durability_lag_p50_ns=None,
            durability_lag_p95_ns=None,
            durability_lag_p99_ns=None,
            durability_lag_max_ns=None,
            sync_count=None,
            sync_duration_total_ns=None,
            sync_duration_max_ns=None,
            slo_breach_count=None,
            write_failure_count=None,
            sync_failure_count=None,
            close_reason=CloseReason.RECOVERY,
            created_at_ns=None,
            recovery_transaction_id=transaction_id,
            recovery_source_state=RecoverySourceState.PARTIAL_COMPLETE,
            recovery_source_relative_path=data_relative_path + ".partial",
            recovery_source_bytes=1,
            recovery_source_sha256=manifest_sha_marker * 64,
            recovery_control_event_id=f"raw-recovery-lineage:v1:{transaction_id}",
            recovered_frame_count=1,
            recovered_record_count=1,
            recovered_bytes=1,
            recovered_sha256=manifest_sha_marker * 64,
            unavailable_fields=RECOVERY_UNAVAILABLE_FIELDS,
        )
    manifest = RawManifestV1.model_validate(values)
    manifest_sha = hashlib.sha256(manifest.canonical_bytes()).hexdigest()
    data_root = tmp_path.absolute()
    data_path = data_root / manifest.data_relative_path
    return DiscoveredRawInput(
        data_root=data_root,
        manifest_path=data_root / manifest.manifest_relative_path,
        data_path=data_path,
        lease_path=lease_path_for_data(data_path),
        manifest_sha256=manifest_sha,
        manifest=manifest,
    )


def _counter(
    result: ManifestQualityReconciliation,
    kind: QualityEventKind,
) -> ManifestQualityCount:
    return next(item for item in result.counts if item.kind is kind)


def test_manifest_quality_count_requires_the_exact_kind_enum() -> None:
    with pytest.raises(TypeError, match="QualityEventKind"):
        ManifestQualityCount(
            kind="gap",  # type: ignore[arg-type]
            manifest_total=0,
            located_count=0,
            unlocated_count=0,
        )


def test_manifest_reconciliation_reports_located_and_unlocated_without_window_spread(
    tmp_path: Path,
) -> None:
    source = _manifest_input(
        tmp_path,
        counters={"gap_count": 2, "queue_overflow_count": 1},
        control_event_ids=("gap-1", "queue-1"),
    )
    events = (
        _quality_event(QualityEventKind.GAP, event_id="gap-1").event,
        _quality_event(QualityEventKind.QUEUE_OVERFLOW, event_id="queue-1").event,
    )

    result = reconcile_manifest_quality(source, reversed(events))

    assert result.manifest_sha256 == source.manifest_sha256
    assert (result.hour_start_ns, result.hour_end_ns) == (0, HOUR_NS)
    assert _counter(result, QualityEventKind.GAP) == ManifestQualityCount(
        kind=QualityEventKind.GAP,
        manifest_total=2,
        located_count=1,
        unlocated_count=1,
    )
    assert _counter(result, QualityEventKind.QUEUE_OVERFLOW).unlocated_count == 0
    assert result.missing_control_event_ids == ()
    assert result.located_control_event_ids == ("gap-1", "queue-1")
    assert result.quality_complete is False

    with pytest.raises(ValueError, match="unlocated_count"):
        replace(
            _counter(result, QualityEventKind.GAP),
            unlocated_count=0,
        )
    with pytest.raises(ValueError, match="quality_complete"):
        replace(result, quality_complete=True)


def test_manifest_reconciliation_is_complete_only_on_exact_available_match(
    tmp_path: Path,
) -> None:
    source = _manifest_input(
        tmp_path,
        counters={"gap_count": 1},
        control_event_ids=("gap-1",),
    )
    event = _quality_event(QualityEventKind.GAP, event_id="gap-1").event

    result = reconcile_manifest_quality(source, (event,))

    assert _counter(result, QualityEventKind.GAP).located_count == 1
    assert all(item.unlocated_count == 0 for item in result.counts)
    assert result.missing_control_event_ids == ()
    assert result.located_control_event_ids == ("gap-1",)
    assert result.diagnostics == ()
    assert result.quality_complete is True

    with pytest.raises(ValueError, match="located_count"):
        replace(
            result,
            located_control_events=(
                replace(
                    result.located_control_events[0],
                    kind=QualityEventKind.RECONNECT,
                ),
            ),
        )
    with pytest.raises(ValueError, match="manifest SHA"):
        replace(result, manifest_sha256="0" * 64)
    with pytest.raises(ValueError, match="hour"):
        replace(
            result,
            hour_start_ns=HOUR_NS,
            hour_end_ns=2 * HOUR_NS,
        )
    changed_gap_count = replace(
        _counter(result, QualityEventKind.GAP),
        manifest_total=2,
        unlocated_count=1,
    )
    with pytest.raises(ValueError, match="manifest_total"):
        replace(
            result,
            counts=tuple(
                changed_gap_count if item.kind is QualityEventKind.GAP else item
                for item in result.counts
            ),
        )


def test_multi_target_event_reconciles_once_in_each_target_manifest(
    tmp_path: Path,
) -> None:
    trade_source = _manifest_input(
        tmp_path,
        manifest_sha_marker="1",
        logical_stream="trade",
        counters={"gap_count": 1},
        control_event_ids=("multi-target",),
    )
    book_source = _manifest_input(
        tmp_path,
        manifest_sha_marker="2",
        logical_stream="book_l2",
        counters={"gap_count": 1},
        control_event_ids=("multi-target",),
    )
    event = QualityEvent(
        source=_control_source(
            {"kind": "typed-fixture"},
            received_at_ns=HOUR_NS - 1,
        ),
        kind=QualityEventKind.GAP,
        event_id="multi-target",
        event_time_ns=HOUR_NS + 1,
        targets=(BOOK_KEY, TRADE_KEY),
    )

    trade = reconcile_manifest_quality(trade_source, (event,))
    book = reconcile_manifest_quality(book_source, (event,))

    assert trade.key == TRADE_KEY
    assert book.key == BOOK_KEY
    assert _counter(trade, QualityEventKind.GAP).located_count == 1
    assert _counter(book, QualityEventKind.GAP).located_count == 1
    assert trade.located_control_event_ids == ("multi-target",)
    assert book.located_control_event_ids == ("multi-target",)
    assert trade.quality_complete is book.quality_complete is True

    timed_event = TimedQualityEvent(
        event=event,
        effective_event_time_ns=HOUR_NS + 1,
        time_source=TimeSource.EVENT,
    )
    one_target = build_quality_windows(
        expectations=(),
        actual_records=(),
        quality_events=(timed_event,),
        reconciliations=(trade,),
        interval_ns=WINDOW_NS,
    )
    assert {row.key: row.quality_complete for row in one_target} == {
        BOOK_KEY: False,
        TRADE_KEY: True,
    }
    one_target_by_key = {row.key: row for row in one_target}
    assert (
        trade.manifest_sha256 in one_target_by_key[TRADE_KEY].lineage_manifest_sha256s
    )
    assert (
        trade.manifest_sha256
        not in one_target_by_key[BOOK_KEY].lineage_manifest_sha256s
    )
    both_targets = build_quality_windows(
        expectations=(),
        actual_records=(),
        quality_events=(timed_event,),
        reconciliations=(trade, book),
        interval_ns=WINDOW_NS,
    )
    assert all(row.quality_complete for row in both_targets)
    both_targets_by_key = {row.key: row for row in both_targets}
    assert (
        trade.manifest_sha256 in both_targets_by_key[TRADE_KEY].lineage_manifest_sha256s
    )
    assert (
        book.manifest_sha256 in both_targets_by_key[BOOK_KEY].lineage_manifest_sha256s
    )


def test_cross_hour_control_event_inherits_incomplete_association_reconciliation(
    tmp_path: Path,
) -> None:
    target_source = _manifest_input(
        tmp_path,
        counters={"gap_count": 2},
        control_event_ids=("cross-hour",),
    )
    event = QualityEvent(
        source=_control_source(
            {"kind": "typed-fixture"},
            received_at_ns=HOUR_NS - 1,
        ),
        targets=(TRADE_KEY,),
        event_id="cross-hour",
        kind=QualityEventKind.GAP,
        event_time_ns=HOUR_NS + 1,
    )
    timed_event = TimedQualityEvent(
        event=event,
        effective_event_time_ns=HOUR_NS + 1,
        time_source=TimeSource.EVENT,
    )
    reconciliation = reconcile_manifest_quality(target_source, (event,))
    assert reconciliation.quality_complete is False

    row = build_quality_windows(
        expectations=(),
        actual_records=(),
        quality_events=(timed_event,),
        reconciliations=(reconciliation,),
        interval_ns=WINDOW_NS,
    )[0]

    assert row.window.start_ns == HOUR_NS
    assert row.quality_complete is False
    assert reconciliation.manifest_sha256 in row.lineage_manifest_sha256s


def test_builder_rejects_unproved_or_target_mismatched_located_event_ids(
    tmp_path: Path,
) -> None:
    ghost_event = _quality_event(QualityEventKind.GAP, event_id="ghost").event
    ghost_source = _manifest_input(
        tmp_path,
        counters={"gap_count": 1},
        control_event_ids=("ghost",),
    )
    ghost_reconciliation = reconcile_manifest_quality(
        ghost_source,
        (ghost_event,),
    )

    with pytest.raises(ValueError, match="unknown quality event"):
        build_quality_windows(
            expectations=(),
            actual_records=(),
            reconciliations=(ghost_reconciliation,),
            interval_ns=WINDOW_NS,
        )

    timed_event = _quality_event(QualityEventKind.GAP, event_id="event-1")
    book_event = _quality_event(
        QualityEventKind.GAP,
        event_id="event-1",
        targets=(BOOK_KEY,),
    ).event
    book_source = _manifest_input(
        tmp_path,
        manifest_sha_marker="1",
        logical_stream="book_l2",
        counters={"gap_count": 1},
        control_event_ids=("event-1",),
    )
    book_reconciliation = reconcile_manifest_quality(book_source, (book_event,))
    with pytest.raises(ValueError, match="target"):
        build_quality_windows(
            expectations=(),
            actual_records=(),
            quality_events=(timed_event,),
            reconciliations=(book_reconciliation,),
            interval_ns=WINDOW_NS,
        )


def test_builder_rejects_changed_semantics_for_a_located_event_id(
    tmp_path: Path,
) -> None:
    original = _quality_event(QualityEventKind.GAP, event_id="same-id")
    source = _manifest_input(
        tmp_path,
        counters={"gap_count": 1},
        control_event_ids=("same-id",),
    )
    reconciliation = reconcile_manifest_quality(source, (original.event,))
    changed_time_event = replace(
        original.event,
        event_time_ns=SECOND_NS + 1,
    )
    mutations = (
        _quality_event(QualityEventKind.THROTTLE, event_id="same-id"),
        TimedQualityEvent(
            event=changed_time_event,
            effective_event_time_ns=SECOND_NS + 1,
            time_source=TimeSource.EVENT,
        ),
        _quality_event(
            QualityEventKind.GAP,
            event_id="same-id",
            manifest_sha="d" * 64,
        ),
        _quality_event(
            QualityEventKind.GAP,
            event_id="same-id",
            effective_event_time_ns=SECOND_NS + 1,
        ),
        _quality_event(
            QualityEventKind.GAP,
            event_id="same-id",
            targets=(BOOK_KEY, TRADE_KEY),
        ),
    )

    for mutation in mutations:
        with pytest.raises(ValueError, match="evidence"):
            build_quality_windows(
                expectations=(),
                actual_records=(),
                quality_events=(mutation,),
                reconciliations=(reconciliation,),
                interval_ns=WINDOW_NS,
            )


def test_actual_manifests_require_exact_complete_reconciliations(
    tmp_path: Path,
) -> None:
    source_one = _manifest_input(tmp_path, manifest_sha_marker="1")
    source_two = _manifest_input(tmp_path, manifest_sha_marker="2")
    reconciliation_one = reconcile_manifest_quality(source_one, ())
    reconciliation_two = reconcile_manifest_quality(source_two, ())
    records = (
        _actual(
            event_time_ns=1,
            received_at_ns=1,
            effective_event_time_ns=1,
            time_source=TimeSource.EVENT,
            manifest_sha=reconciliation_one.manifest_sha256,
            record_index=0,
        ),
        _actual(
            event_time_ns=2,
            received_at_ns=2,
            effective_event_time_ns=2,
            time_source=TimeSource.EVENT,
            manifest_sha=reconciliation_two.manifest_sha256,
            record_index=0,
        ),
    )

    missing_one = build_quality_windows(
        expectations=(),
        actual_records=records,
        reconciliations=(reconciliation_one,),
        interval_ns=WINDOW_NS,
    )[0]
    assert missing_one.quality_complete is False

    exact = build_quality_windows(
        expectations=(),
        actual_records=records,
        reconciliations=(reconciliation_one, reconciliation_two),
        interval_ns=WINDOW_NS,
    )[0]
    assert exact.quality_complete is True

    wrong_sha = build_quality_windows(
        expectations=(),
        actual_records=(records[0],),
        reconciliations=(reconciliation_two,),
        interval_ns=WINDOW_NS,
    )[0]
    assert wrong_sha.quality_complete is False


def test_actual_manifest_exact_binding_survives_event_time_crossing_hour(
    tmp_path: Path,
) -> None:
    source = _manifest_input(tmp_path)
    reconciliation = reconcile_manifest_quality(source, ())
    actual = _actual(
        event_time_ns=HOUR_NS + 1,
        received_at_ns=HOUR_NS - 1,
        effective_event_time_ns=HOUR_NS + 1,
        time_source=TimeSource.EVENT,
        manifest_sha=reconciliation.manifest_sha256,
        record_index=0,
    )

    row = build_quality_windows(
        expectations=(),
        actual_records=(actual,),
        reconciliations=(reconciliation,),
        interval_ns=WINDOW_NS,
    )[0]

    assert row.window.start_ns == HOUR_NS
    assert row.quality_complete is True

    with pytest.raises(ValueError, match="hour"):
        replace(
            reconciliation,
            hour_start_ns=HOUR_NS,
            hour_end_ns=2 * HOUR_NS,
        )


def test_incomplete_reconciliation_marks_existing_silent_and_actual_rows_only(
    tmp_path: Path,
) -> None:
    manifest_source = _manifest_input(
        tmp_path,
        counters={"gap_count": 1},
        control_event_ids=(),
    )
    reconciliation = reconcile_manifest_quality(manifest_source, ())
    opened = _decode_checkpoint(start_ns=0, manifest_sha="1" * 64)
    closed = _decode_checkpoint(
        start_ns=0,
        end_ns=WINDOW_NS,
        manifest_sha="2" * 64,
    )
    expectations = build_expectation_segments(
        (opened, closed),
        range_start_ns=0,
        range_end_ns=3 * WINDOW_NS,
    )
    actual = _actual(
        event_time_ns=2 * WINDOW_NS,
        received_at_ns=2 * WINDOW_NS,
        effective_event_time_ns=2 * WINDOW_NS,
        time_source=TimeSource.EVENT,
        manifest_sha="3" * 64,
        record_index=0,
    )

    rows = build_quality_windows(
        expectations,
        actual_records=(actual,),
        reconciliations=(reconciliation,),
        interval_ns=WINDOW_NS,
    )

    assert [row.window.start_ns for row in rows] == [0, 2 * WINDOW_NS]
    assert all(row.quality_complete is False for row in rows)
    assert all(
        reconciliation.manifest_sha256 in row.lineage_manifest_sha256s for row in rows
    )
    assert all(row.gap_count == 0 for row in rows)

    with pytest.raises(ValueError, match="manifest_sha256"):
        build_quality_windows(
            expectations,
            actual_records=(actual,),
            reconciliations=(reconciliation, reconciliation),
            interval_ns=WINDOW_NS,
        )


def test_manifest_reconciliation_detects_missing_conflicting_and_excess_events(
    tmp_path: Path,
) -> None:
    source = _manifest_input(
        tmp_path,
        counters={"gap_count": 0},
        control_event_ids=("gap-1", "missing"),
    )
    gap = _quality_event(QualityEventKind.GAP, event_id="gap-1").event

    result = reconcile_manifest_quality(source, (gap,))

    assert _counter(result, QualityEventKind.GAP).located_count == 1
    assert _counter(result, QualityEventKind.GAP).unlocated_count == 0
    assert result.missing_control_event_ids == ("missing",)
    assert result.quality_complete is False
    assert result.diagnostics

    target_mismatch = reconcile_manifest_quality(
        source,
        (replace(gap, targets=(BOOK_KEY,)),),
    )
    assert target_mismatch.located_control_event_ids == ()
    assert target_mismatch.missing_control_event_ids == ("gap-1", "missing")
    assert any(
        item.startswith("control_target_mismatch:gap-1")
        for item in target_mismatch.diagnostics
    )

    with pytest.raises(ValueError, match="event_id"):
        reconcile_manifest_quality(source, (gap, replace(gap)))


def test_recovery_manifest_quality_is_unknown_not_zero(tmp_path: Path) -> None:
    source = _manifest_input(tmp_path, recovery=True)

    result = reconcile_manifest_quality(source, ())

    assert all(item.manifest_total is None for item in result.counts)
    assert all(item.unlocated_count is None for item in result.counts)
    assert result.quality_complete is False
