from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.materializer.windows import Window, window_for

SECOND_NS = 1_000_000_000
MINUTE_NS = 60 * SECOND_NS
HOUR_NS = 60 * MINUTE_NS
MAX_SIGNED_INT64 = 2**63 - 1
VALID_INTERVALS_NS = (
    30 * SECOND_NS,
    40 * SECOND_NS,
    45 * SECOND_NS,
    MINUTE_NS,
    5 * MINUTE_NS,
    15 * MINUTE_NS,
    HOUR_NS,
)


@given(
    timestamp_ns=st.integers(min_value=0, max_value=10**18),
    interval_ns=st.sampled_from(VALID_INTERVALS_NS),
)
def test_windows_align_to_unix_epoch_and_contain_timestamp(
    timestamp_ns: int,
    interval_ns: int,
) -> None:
    window = window_for(timestamp_ns, interval_ns)

    assert window.start_ns % interval_ns == 0
    assert window.start_ns <= timestamp_ns < window.end_ns
    assert window.end_ns - window.start_ns == interval_ns
    assert window.interval_ns == interval_ns


@given(interval_ns=st.sampled_from(VALID_INTERVALS_NS))
def test_half_open_boundary_belongs_to_next_window(interval_ns: int) -> None:
    previous = window_for(interval_ns - 1, interval_ns)
    boundary = window_for(interval_ns, interval_ns)

    assert previous == Window(start_ns=0, end_ns=interval_ns)
    assert boundary == Window(start_ns=interval_ns, end_ns=2 * interval_ns)


@pytest.mark.parametrize(
    "interval_ns",
    [30 * SECOND_NS, MINUTE_NS, 5 * MINUTE_NS, 15 * MINUTE_NS, HOUR_NS],
)
def test_configured_standard_intervals_never_cross_utc_hour(
    interval_ns: int,
) -> None:
    final_window = window_for(HOUR_NS - 1, interval_ns)

    assert final_window.end_ns == HOUR_NS


@pytest.mark.parametrize(
    ("interval_ns", "expected_error"),
    [
        (True, TypeError),
        (30.0 * SECOND_NS, TypeError),
        (0, ValueError),
        (-1, ValueError),
        (30 * SECOND_NS - 1, ValueError),
        (HOUR_NS + 1, ValueError),
        (31 * SECOND_NS, ValueError),
        (2**63, ValueError),
    ],
)
def test_window_interval_rejects_invalid_values(
    interval_ns: object,
    expected_error: type[Exception],
) -> None:
    with pytest.raises(expected_error):
        window_for(0, interval_ns)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("timestamp_ns", "expected_error"),
    [
        (True, TypeError),
        (1.0, TypeError),
        (-1, ValueError),
        (2**63, ValueError),
    ],
)
def test_window_timestamp_rejects_invalid_values(
    timestamp_ns: object,
    expected_error: type[Exception],
) -> None:
    with pytest.raises(expected_error):
        window_for(timestamp_ns, 30 * SECOND_NS)  # type: ignore[arg-type]


@pytest.mark.parametrize("interval_ns", VALID_INTERVALS_NS)
def test_window_end_must_fit_signed_int64(interval_ns: int) -> None:
    first_unrepresentable_start = (MAX_SIGNED_INT64 // interval_ns) * interval_ns

    final_complete = window_for(first_unrepresentable_start - 1, interval_ns)
    assert final_complete.end_ns == first_unrepresentable_start

    with pytest.raises(ValueError, match="signed 64-bit"):
        window_for(first_unrepresentable_start, interval_ns)


@pytest.mark.parametrize(
    ("start_ns", "end_ns"),
    [
        (True, 30 * SECOND_NS),
        (0, 30.0 * SECOND_NS),
        (-1, 30 * SECOND_NS - 1),
        (0, 2**63),
        (0, 30 * SECOND_NS - 1),
        (0, HOUR_NS + 1),
        (1, 30 * SECOND_NS + 1),
        (0, 31 * SECOND_NS),
    ],
)
def test_window_model_rejects_noncanonical_ranges(
    start_ns: object,
    end_ns: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        Window(start_ns=start_ns, end_ns=end_ns)  # type: ignore[arg-type]
