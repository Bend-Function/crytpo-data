from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest
from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.materializer.models import (
    SourceLocator,
    SourceRecord,
    TimedSourceRecord,
    TimeSource,
)
from crypto_collector.materializer.time_policy import ChosenTime, EventTimePolicy

SECOND_NS = 1_000_000_000
MINUTE_NS = 60 * SECOND_NS
DAY_NS = 24 * 60 * MINUTE_NS
MAX_SIGNED_INT64 = 2**63 - 1


def _source(
    *,
    event_time_ns: int | None,
    received_at_ns: int,
) -> SourceRecord:
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
        payload={"trade_id": "one"},
        received_at_ns=received_at_ns,
        monotonic_ns=1,
        worker_instance_id="worker-a",
        connection_id="connection-a",
        connection_generation=1,
        writer_sequence=1,
        egress_id="direct-primary",
        config_sha256="a" * 64,
    )
    return SourceRecord(
        envelope=envelope,
        locator=SourceLocator(
            manifest_sha256="b" * 64,
            zero_based_record_index=0,
        ),
    )


def test_missing_or_implausible_exchange_time_falls_back_to_receive_time() -> None:
    policy = EventTimePolicy(
        max_past_skew_ns=7 * DAY_NS,
        max_future_skew_ns=5 * MINUTE_NS,
    )
    received_at_ns = 10 * DAY_NS

    missing = policy.choose(event_time_ns=None, received_at_ns=received_at_ns)
    past = policy.choose(event_time_ns=0, received_at_ns=received_at_ns)
    future = policy.choose(
        event_time_ns=received_at_ns + 5 * MINUTE_NS + 1,
        received_at_ns=received_at_ns,
    )

    assert missing == ChosenTime(received_at_ns, TimeSource.RECEIVE_MISSING)
    assert past == ChosenTime(received_at_ns, TimeSource.RECEIVE_OUTLIER)
    assert future == ChosenTime(received_at_ns, TimeSource.RECEIVE_OUTLIER)


@given(
    received_at_ns=st.integers(min_value=10_000, max_value=10**18),
    past_skew_ns=st.integers(min_value=0, max_value=10_000),
    future_skew_ns=st.integers(min_value=0, max_value=10_000),
)
def test_event_time_skew_boundaries_are_inclusive(
    received_at_ns: int,
    past_skew_ns: int,
    future_skew_ns: int,
) -> None:
    policy = EventTimePolicy(
        max_past_skew_ns=past_skew_ns,
        max_future_skew_ns=future_skew_ns,
    )
    past_boundary = received_at_ns - past_skew_ns
    future_boundary = received_at_ns + future_skew_ns

    assert policy.choose(
        event_time_ns=past_boundary,
        received_at_ns=received_at_ns,
    ) == ChosenTime(past_boundary, TimeSource.EVENT)
    assert policy.choose(
        event_time_ns=future_boundary,
        received_at_ns=received_at_ns,
    ) == ChosenTime(future_boundary, TimeSource.EVENT)


def test_event_time_policy_uses_integer_differences_at_int64_edges() -> None:
    policy = EventTimePolicy(
        max_past_skew_ns=MAX_SIGNED_INT64,
        max_future_skew_ns=MAX_SIGNED_INT64,
    )

    assert policy.choose(
        event_time_ns=MAX_SIGNED_INT64,
        received_at_ns=0,
    ) == ChosenTime(MAX_SIGNED_INT64, TimeSource.EVENT)
    assert policy.choose(
        event_time_ns=0,
        received_at_ns=MAX_SIGNED_INT64,
    ) == ChosenTime(0, TimeSource.EVENT)


@pytest.mark.parametrize(
    ("field_name", "value", "expected_error"),
    [
        ("max_past_skew_ns", True, TypeError),
        ("max_past_skew_ns", 1.0, TypeError),
        ("max_past_skew_ns", -1, ValueError),
        ("max_past_skew_ns", 2**63, ValueError),
        ("max_future_skew_ns", True, TypeError),
        ("max_future_skew_ns", 1.0, TypeError),
        ("max_future_skew_ns", -1, ValueError),
        ("max_future_skew_ns", 2**63, ValueError),
    ],
)
def test_event_time_policy_rejects_invalid_skew_configuration(
    field_name: str,
    value: object,
    expected_error: type[Exception],
) -> None:
    values: dict[str, object] = {
        "max_past_skew_ns": 0,
        "max_future_skew_ns": 0,
    }
    values[field_name] = value

    with pytest.raises(expected_error):
        EventTimePolicy(**values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("event_time_ns", "received_at_ns", "expected_error"),
    [
        (True, 0, TypeError),
        (1.0, 0, TypeError),
        (-1, 0, ValueError),
        (2**63, 0, ValueError),
        (None, True, TypeError),
        (None, 1.0, TypeError),
        (None, -1, ValueError),
        (None, 2**63, ValueError),
    ],
)
def test_event_time_policy_rejects_invalid_input_timestamps(
    event_time_ns: object,
    received_at_ns: object,
    expected_error: type[Exception],
) -> None:
    policy = EventTimePolicy(max_past_skew_ns=0, max_future_skew_ns=0)

    with pytest.raises(expected_error):
        policy.choose(
            event_time_ns=event_time_ns,  # type: ignore[arg-type]
            received_at_ns=received_at_ns,  # type: ignore[arg-type]
        )


def test_timed_source_record_persists_policy_choice() -> None:
    source = _source(event_time_ns=None, received_at_ns=100)
    chosen = EventTimePolicy(
        max_past_skew_ns=0,
        max_future_skew_ns=0,
    ).choose(
        event_time_ns=source.envelope.event_time_ns,
        received_at_ns=source.envelope.received_at_ns,
    )

    timed = TimedSourceRecord(
        source=source,
        effective_event_time_ns=chosen.effective_event_time_ns,
        time_source=chosen.time_source,
    )

    assert timed.time_source is TimeSource.RECEIVE_MISSING
    assert timed.effective_event_time_ns == source.envelope.received_at_ns


def test_timed_source_record_rejects_raw_timestamp_overflow() -> None:
    source = _source(event_time_ns=1, received_at_ns=2**63)

    with pytest.raises(ValueError, match="signed 64-bit"):
        TimedSourceRecord(
            source=source,
            effective_event_time_ns=1,
            time_source=TimeSource.EVENT,
        )


def test_one_to_one_timed_record_cannot_substitute_a_batch_child_time() -> None:
    source = _source(event_time_ns=90, received_at_ns=100)

    with pytest.raises(ValueError, match="time_source"):
        TimedSourceRecord(
            source=source,
            effective_event_time_ns=91,
            time_source=TimeSource.EVENT,
        )


@pytest.mark.parametrize(
    ("effective_event_time_ns", "expected_error"),
    [
        (True, TypeError),
        (-1, ValueError),
        (2**63, ValueError),
    ],
)
def test_chosen_time_rejects_invalid_effective_timestamp(
    effective_event_time_ns: object,
    expected_error: type[Exception],
) -> None:
    with pytest.raises(expected_error):
        ChosenTime(
            effective_event_time_ns,  # type: ignore[arg-type]
            TimeSource.EVENT,
        )


def test_chosen_time_requires_a_time_source_enum() -> None:
    with pytest.raises(TypeError, match="TimeSource"):
        ChosenTime(1, "event")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("event_time_ns", "effective_event_time_ns", "time_source"),
    [
        (None, 100, TimeSource.EVENT),
        (90, 90, TimeSource.RECEIVE_MISSING),
        (90, 90, TimeSource.RECEIVE_OUTLIER),
        (90, 100, TimeSource.EVENT),
    ],
)
def test_timed_source_record_rejects_inconsistent_time_source_binding(
    event_time_ns: int | None,
    effective_event_time_ns: int,
    time_source: TimeSource,
) -> None:
    source = _source(event_time_ns=event_time_ns, received_at_ns=100)

    with pytest.raises(ValueError, match="time_source"):
        TimedSourceRecord(
            source=source,
            effective_event_time_ns=effective_event_time_ns,
            time_source=time_source,
        )


def test_chosen_time_and_policy_are_immutable() -> None:
    chosen = ChosenTime(1, TimeSource.EVENT)
    policy = EventTimePolicy(max_past_skew_ns=1, max_future_skew_ns=1)

    with pytest.raises(FrozenInstanceError):
        chosen.effective_event_time_ns = 2  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        policy.max_past_skew_ns = 2  # type: ignore[misc]
