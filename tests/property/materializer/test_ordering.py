from __future__ import annotations

import hashlib

import pytest
from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.domain.envelope import RawEnvelope, RestMetadata
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.materializer.models import (
    ConnectionGenerationScope,
    ReplayOrderedRecord,
    SourceLocator,
    SourceRecord,
    TimedSourceRecord,
)
from crypto_collector.materializer.ordering import (
    DuplicateSourceLocator,
    ReplaySequenceError,
    canonical_event_order,
    canonical_event_sort_key,
    canonical_replay_order,
)


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def _source(
    label: str,
    *,
    worker_instance_id: str = "worker-a",
    monotonic_ns: int,
    received_at_ns: int,
    writer_sequence: int,
    event_time_ns: int | None = None,
    logical_stream: str = "book_live",
    manifest_sha256: str | None = None,
    record_index: int = 0,
    connection_id: str = "shared-connection",
    connection_generation: int = 1,
    market: Market = Market.SPOT,
    instrument_key: str = "BTC-USDT",
) -> SourceRecord:
    envelope = RawEnvelope(
        schema_version=1,
        exchange=Exchange.OKX,
        market=market,
        instrument_key=instrument_key,
        wire_symbol=instrument_key,
        logical_stream=logical_stream,
        native_channel=logical_stream,
        transport=Transport.WEBSOCKET,
        event_time_ns=event_time_ns,
        event_time_source="venue" if event_time_ns is not None else None,
        integrity_mode=None,
        coverage=None,
        rest_metadata=None,
        payload={"label": label},
        received_at_ns=received_at_ns,
        monotonic_ns=monotonic_ns,
        worker_instance_id=worker_instance_id,
        connection_id=connection_id,
        connection_generation=connection_generation,
        writer_sequence=writer_sequence,
        egress_id="direct-primary",
        config_sha256="a" * 64,
    )
    return SourceRecord(
        envelope=envelope,
        locator=SourceLocator(
            manifest_sha256=manifest_sha256 or _sha(label),
            zero_based_record_index=record_index,
        ),
    )


def _rest_source(label: str) -> SourceRecord:
    envelope = RawEnvelope(
        schema_version=1,
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="book_deep_snapshot",
        native_channel="books-full",
        transport=Transport.REST,
        event_time_ns=1,
        event_time_source="venue",
        integrity_mode=None,
        coverage=None,
        rest_metadata=RestMetadata(
            request_started_at_ns=1,
            request_ended_at_ns=2,
            method="GET",
            path="/api/v5/market/books-full",
            params={},
            status=200,
            attempt=1,
            rate_limit_headers={},
        ),
        payload={"label": label},
        received_at_ns=2,
        monotonic_ns=2,
        worker_instance_id="worker-a",
        connection_id=None,
        connection_generation=None,
        writer_sequence=1,
        egress_id="direct-primary",
        config_sha256="a" * 64,
    )
    return SourceRecord(
        envelope=envelope,
        locator=SourceLocator(
            manifest_sha256=_sha(label),
            zero_based_record_index=0,
        ),
    )


def _label(source: SourceRecord) -> str:
    payload = source.envelope.payload
    assert isinstance(payload, dict)
    label = payload["label"]
    assert isinstance(label, str)
    return label


EVENT_ROWS = (
    TimedSourceRecord(
        source=_source(
            "late-effective",
            monotonic_ns=1,
            received_at_ns=100,
            writer_sequence=1,
            manifest_sha256="c" * 64,
        ),
        effective_event_time_ns=20,
    ),
    TimedSourceRecord(
        source=_source(
            "later-receive",
            monotonic_ns=2,
            received_at_ns=101,
            writer_sequence=2,
            manifest_sha256="b" * 64,
            record_index=1,
        ),
        effective_event_time_ns=10,
    ),
    TimedSourceRecord(
        source=_source(
            "locator-b",
            monotonic_ns=3,
            received_at_ns=100,
            writer_sequence=3,
            manifest_sha256="b" * 64,
            record_index=0,
        ),
        effective_event_time_ns=10,
    ),
    TimedSourceRecord(
        source=_source(
            "locator-a",
            monotonic_ns=4,
            received_at_ns=100,
            writer_sequence=4,
            manifest_sha256="a" * 64,
            record_index=9,
        ),
        effective_event_time_ns=10,
    ),
)


@given(st.permutations(EVENT_ROWS))
def test_canonical_event_order_is_independent_of_discovery_order(
    rows: list[TimedSourceRecord],
) -> None:
    ordered = canonical_event_order(rows)

    assert [_label(item.source) for item in ordered] == [
        "locator-a",
        "locator-b",
        "later-receive",
        "late-effective",
    ]


def test_canonical_event_sort_key_is_the_frozen_four_part_key() -> None:
    row = EVENT_ROWS[2]

    assert canonical_event_sort_key(row) == (
        row.effective_event_time_ns,
        row.source.envelope.received_at_ns,
        row.source.locator.manifest_sha256,
        row.source.locator.zero_based_record_index,
    )


@pytest.mark.parametrize("effective_event_time_ns", [True, -1])
def test_timed_source_record_requires_non_negative_integer_time(
    effective_event_time_ns: object,
) -> None:
    with pytest.raises(ValueError, match="effective_event_time_ns"):
        TimedSourceRecord(
            source=EVENT_ROWS[0].source,
            effective_event_time_ns=effective_event_time_ns,  # type: ignore[arg-type]
        )


def test_event_order_rejects_duplicate_source_locators() -> None:
    first = EVENT_ROWS[0]
    duplicate = TimedSourceRecord(
        source=SourceRecord(
            envelope=EVENT_ROWS[1].source.envelope,
            locator=first.source.locator,
        ),
        effective_event_time_ns=1,
    )

    with pytest.raises(DuplicateSourceLocator):
        canonical_event_order((first, duplicate))


REPLAY_ROWS = (
    _source(
        "a-late",
        worker_instance_id="worker-a",
        monotonic_ns=20,
        received_at_ns=300,
        writer_sequence=11,
        event_time_ns=1,
    ),
    _source(
        "b-late",
        worker_instance_id="worker-b",
        monotonic_ns=2,
        received_at_ns=200,
        writer_sequence=2,
        event_time_ns=1,
    ),
    _source(
        "a-early",
        worker_instance_id="worker-a",
        monotonic_ns=10,
        received_at_ns=100,
        writer_sequence=10,
        event_time_ns=999,
    ),
    _source(
        "b-early",
        worker_instance_id="worker-b",
        monotonic_ns=1,
        received_at_ns=100,
        writer_sequence=1,
        event_time_ns=999,
    ),
)


@given(st.permutations(REPLAY_ROWS))
def test_book_replay_order_uses_worker_monotonic_causality(
    rows: list[SourceRecord],
) -> None:
    ordered = canonical_replay_order(rows)

    worker_a_received = [
        item.envelope.received_at_ns
        for item in REPLAY_ROWS
        if item.envelope.worker_instance_id == "worker-a"
    ]
    worker_b_received = [
        item.envelope.received_at_ns
        for item in REPLAY_ROWS
        if item.envelope.worker_instance_id == "worker-b"
    ]
    assert max(worker_a_received) > min(worker_b_received)
    assert [_label(item.source) for item in ordered] == [
        "a-early",
        "a-late",
        "b-early",
        "b-late",
    ]
    assert [item.worker_run_ordinal for item in ordered] == [0, 0, 1, 1]
    assert [item.starts_worker_run for item in ordered] == [True, False, True, False]
    assert [item.invalidates_inherited_generation for item in ordered] == [
        False,
        False,
        True,
        False,
    ]


def test_replay_ties_use_manifest_sha_then_physical_record_index() -> None:
    rows = (
        _source(
            "b-index-1",
            monotonic_ns=1,
            received_at_ns=1,
            writer_sequence=3,
            manifest_sha256="b" * 64,
            record_index=1,
        ),
        _source(
            "a-index-9",
            monotonic_ns=1,
            received_at_ns=1,
            writer_sequence=1,
            manifest_sha256="a" * 64,
            record_index=9,
        ),
        _source(
            "b-index-0",
            monotonic_ns=1,
            received_at_ns=1,
            writer_sequence=2,
            manifest_sha256="b" * 64,
            record_index=0,
        ),
    )

    ordered = canonical_replay_order(reversed(rows))

    assert [_label(item.source) for item in ordered] == [
        "a-index-9",
        "b-index-0",
        "b-index-1",
    ]


def test_replay_locator_tie_breaker_does_not_hide_sequence_reversal() -> None:
    rows = (
        _source(
            "locator-a-sequence-2",
            monotonic_ns=1,
            received_at_ns=1,
            writer_sequence=2,
            manifest_sha256="a" * 64,
        ),
        _source(
            "locator-b-sequence-1",
            monotonic_ns=1,
            received_at_ns=1,
            writer_sequence=1,
            manifest_sha256="b" * 64,
        ),
    )

    with pytest.raises(ReplaySequenceError, match="strictly increase"):
        canonical_replay_order(reversed(rows))


def test_worker_scope_prevents_numeric_connection_generation_inheritance() -> None:
    ordered = canonical_replay_order(REPLAY_ROWS)
    first_scope = ordered[0].connection_generation_scope
    second_scope = ordered[2].connection_generation_scope

    assert first_scope is not None and second_scope is not None
    assert first_scope.connection_id == second_scope.connection_id
    assert first_scope.connection_generation == second_scope.connection_generation
    assert first_scope.worker_instance_id == "worker-a"
    assert second_scope.worker_instance_id == "worker-b"
    assert first_scope != second_scope


def test_rest_record_has_no_connection_generation_scope() -> None:
    ordered = canonical_replay_order((_rest_source("deep"),))

    assert ordered[0].connection_generation_scope is None


@pytest.mark.parametrize("writer_sequences", [(10, 10), (11, 10)])
def test_replay_rejects_non_increasing_writer_sequence_within_stream(
    writer_sequences: tuple[int, int],
) -> None:
    rows = (
        _source(
            "first",
            monotonic_ns=1,
            received_at_ns=1,
            writer_sequence=writer_sequences[0],
        ),
        _source(
            "second",
            monotonic_ns=2,
            received_at_ns=2,
            writer_sequence=writer_sequences[1],
        ),
    )

    with pytest.raises(ReplaySequenceError, match="strictly increase"):
        canonical_replay_order(rows)


def test_writer_sequence_is_scoped_by_stream_and_resets_across_workers() -> None:
    rows = (
        _source(
            "a-trade-100",
            monotonic_ns=1,
            received_at_ns=1,
            writer_sequence=100,
            logical_stream="trade",
        ),
        _source(
            "a-book-1",
            monotonic_ns=2,
            received_at_ns=2,
            writer_sequence=1,
            logical_stream="book_live",
        ),
        _source(
            "a-trade-101",
            monotonic_ns=3,
            received_at_ns=3,
            writer_sequence=101,
            logical_stream="trade",
        ),
        _source(
            "b-book-1",
            worker_instance_id="worker-b",
            monotonic_ns=1,
            received_at_ns=4,
            writer_sequence=1,
            logical_stream="book_live",
        ),
    )

    ordered = canonical_replay_order(reversed(rows))

    assert [_label(item.source) for item in ordered] == [
        "a-trade-100",
        "a-book-1",
        "a-trade-101",
        "b-book-1",
    ]


def test_writer_sequence_identity_includes_market_and_instrument() -> None:
    rows = (
        _source(
            "btc-10",
            monotonic_ns=1,
            received_at_ns=1,
            writer_sequence=10,
        ),
        _source(
            "eth-1",
            monotonic_ns=2,
            received_at_ns=2,
            writer_sequence=1,
            instrument_key="ETH-USDT",
        ),
        _source(
            "perpetual-1",
            monotonic_ns=3,
            received_at_ns=3,
            writer_sequence=1,
            market=Market.PERPETUAL,
        ),
        _source(
            "btc-11",
            monotonic_ns=4,
            received_at_ns=4,
            writer_sequence=11,
        ),
    )

    assert len(canonical_replay_order(rows)) == 4


def test_replay_output_model_rejects_inconsistent_boundary_metadata() -> None:
    source = REPLAY_ROWS[0]
    scope = ConnectionGenerationScope(
        worker_instance_id=source.envelope.worker_instance_id,
        connection_id="shared-connection",
        connection_generation=1,
    )

    with pytest.raises(ValueError, match="later worker runs"):
        ReplayOrderedRecord(
            source=source,
            worker_run_ordinal=0,
            starts_worker_run=True,
            invalidates_inherited_generation=True,
            connection_generation_scope=scope,
        )


def test_replay_rejects_duplicate_source_locators() -> None:
    first = REPLAY_ROWS[0]
    duplicate = SourceRecord(
        envelope=REPLAY_ROWS[1].envelope,
        locator=first.locator,
    )

    with pytest.raises(DuplicateSourceLocator):
        canonical_replay_order((first, duplicate))


def test_empty_orders_are_stable() -> None:
    assert canonical_event_order(()) == ()
    assert canonical_replay_order(()) == ()
