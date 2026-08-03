from __future__ import annotations

from decimal import ROUND_DOWN, Decimal, localcontext
from typing import Any

import pytest
from pydantic import ValidationError

from crypto_collector.benchmarks.aggregation import (
    aggregate_final_worker_snapshots,
    summarize_resources,
    summarize_storage_health,
    validate_worker_rounds,
)
from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    FinalWorkerAggregateV1,
    GateProcessKeyV1,
    GateProcessResourceSampleV1,
    GateResourceSamplingRoundV1,
    GateResourceSummaryV1,
    GateSamplingRoundV1,
    GateStorageHealthSampleV1,
    GateStorageHealthSummaryV1,
    GateWorkerHealthV1,
    GateWorkerKeyV1,
    GateWorkerSampleV1,
)
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.domain.types import Exchange, Market
from crypto_collector.storage.durability import WriterCriticalReason
from crypto_collector.storage.models import (
    AdmissionState,
    DurabilityHistogramSeriesV1,
    PublicationState,
    WriterLifecycle,
    WriterMetricsSnapshotV1,
)
from crypto_collector.storage.stats import DURABILITY_BUCKET_UPPER_BOUNDS_NS

_NS_PER_MINUTE = 60_000_000_000

_FINAL_WORKER_AGGREGATE_FIELDS = (
    "schema_version",
    "record_type",
    "worker_count",
    "sampling_round_count",
    "final_round_index",
    "accepted_record_count",
    "durable_record_count",
    "unpersisted_record_count",
    "uncertain_record_count",
    "enqueue_high_water_count",
    "normal_overflow_count",
    "control_overflow_count",
    "not_accepting_count",
    "durability_histogram_schema_version",
    "durability_bucket_counts",
    "durability_sample_count",
    "durability_lag_p50_ns",
    "durability_lag_p95_ns",
    "durability_lag_p99_ns",
    "durability_lag_max_ns",
    "sync_count",
    "sync_duration_total_ns",
    "sync_duration_max_ns",
    "slo_breach_count",
    "write_failure_count",
    "sync_failure_count",
    "publication_failure_count",
    "unpersisted_record_count_peak",
    "queued_records_peak",
    "queued_bytes_peak",
    "buffered_records_peak",
    "buffered_bytes_peak",
    "in_flight_records_peak",
    "in_flight_bytes_peak",
    "resident_record_bytes_peak",
    "resident_control_records_peak",
    "resident_control_bytes_peak",
    "oldest_unpersisted_age_max_ns",
    "active_logical_generation_count_peak",
    "retiring_generation_count_peak",
    "open_file_descriptor_count_peak",
    "sync_inflight_peak",
)

_RESOURCE_SUMMARY_FIELDS = (
    "schema_version",
    "record_type",
    "process_count",
    "round_count",
    "post_warmup_round_count",
    "warmup_ended_monotonic_ns",
    "resource_trend_valid",
    "first_request_monotonic_ns",
    "final_completion_monotonic_ns",
    "coverage_ns",
    "sample_max_gap_ns",
    "rss_peak_bytes",
    "rss_slope_bytes_per_minute",
    "open_fds_peak",
    "first_open_fds_after_warmup",
    "max_open_fds_after_warmup",
    "final_open_fds_after_warmup",
    "fd_growth_after_warmup",
)

_HEALTH_SUMMARY_FIELDS = (
    "schema_version",
    "record_type",
    "duration_ns",
    "interval_ns",
    "sample_count",
    "expected_min_sample_count",
    "first_request_monotonic_ns",
    "final_completion_monotonic_ns",
    "coverage_ns",
    "required_coverage_ns",
    "sample_max_gap_ns",
    "minimum_data_available_bytes",
    "minimum_state_available_bytes",
    "minimum_available_bytes_if_shared",
    "critical_worker_observation_count",
    "sample_count_valid",
    "coverage_valid",
    "workers_healthy",
)


def _worker_id(exchange: Exchange) -> str:
    return f"gate-worker-v1-{exchange.value}"


def _worker_keys() -> tuple[GateWorkerKeyV1, ...]:
    return tuple(
        GateWorkerKeyV1(exchange=exchange, worker_instance_id=_worker_id(exchange))
        for exchange in CANONICAL_EXCHANGES
    )


def _process_keys() -> tuple[GateProcessKeyV1, ...]:
    return (
        GateProcessKeyV1(role="supervisor", exchange=None, worker_instance_id=None),
        *(
            GateProcessKeyV1(
                role="exchange_worker",
                exchange=exchange,
                worker_instance_id=_worker_id(exchange),
            )
            for exchange in CANONICAL_EXCHANGES
        ),
    )


def _nearest_rank(bucket_counts: tuple[int, ...], numerator: int) -> int | None:
    sample_count = sum(bucket_counts)
    if sample_count == 0:
        return None
    rank = max(1, (numerator * sample_count + 99) // 100)
    cumulative = 0
    for bound, count in zip(
        DURABILITY_BUCKET_UPPER_BOUNDS_NS,
        bucket_counts,
        strict=True,
    ):
        cumulative += count
        if cumulative >= rank:
            return bound
    raise AssertionError("test histogram is inconsistent")


def _buckets(*, count: int, index: int) -> tuple[int, ...]:
    values = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    values[index] = count
    return tuple(values)


def _series(
    exchange: Exchange,
    bucket_counts: tuple[int, ...],
    *,
    market: Market = Market.SPOT,
    logical_stream: str = "trade",
    lag_max_ns: int | None = None,
) -> DurabilityHistogramSeriesV1:
    sample_count = sum(bucket_counts)
    maximum = lag_max_ns
    if sample_count and maximum is None:
        maximum = DURABILITY_BUCKET_UPPER_BOUNDS_NS[
            max(index for index, count in enumerate(bucket_counts) if count)
        ]
    return DurabilityHistogramSeriesV1(
        exchange=exchange,
        market=market,
        logical_stream=logical_stream,
        bucket_counts=bucket_counts,
        sample_count=sample_count,
        lag_p50_ns=_nearest_rank(bucket_counts, 50),
        lag_p95_ns=_nearest_rank(bucket_counts, 95),
        lag_p99_ns=_nearest_rank(bucket_counts, 99),
        lag_max_ns=maximum,
    )


def _snapshot(
    exchange: Exchange,
    *,
    observed_ns: int,
    bucket_counts: tuple[int, ...],
    final: bool,
    queued_records: int = 0,
    buffered_records: int = 0,
    in_flight_records: int = 0,
    resident_control_records: int = 0,
    active_generations: int = 0,
    retiring_generations: int = 0,
    open_fds: int = 0,
    sync_inflight: int = 0,
    oldest_unpersisted_age_ns: int | None = None,
    config_sha256: str = "a" * 64,
    config_generation: int = 0,
    enqueue_high_water_count: int = 0,
    normal_overflow_count: int = 0,
    control_overflow_count: int = 0,
    not_accepting_count: int = 0,
    sync_count: int | None = None,
    sync_duration_total_ns: int | None = None,
    sync_duration_max_ns: int | None = None,
    slo_breach_count: int = 0,
    write_failure_count: int = 0,
    sync_failure_count: int = 0,
    publication_failure_count: int = 0,
    lag_max_ns: int | None = None,
    histogram_series: tuple[DurabilityHistogramSeriesV1, ...] | None = None,
) -> WriterMetricsSnapshotV1:
    durable = sum(bucket_counts)
    unpersisted = queued_records + buffered_records + in_flight_records
    accepted = durable + unpersisted
    queued_bytes = queued_records * 10
    buffered_bytes = buffered_records * 10
    in_flight_bytes = in_flight_records * 10
    resident_bytes = queued_bytes + buffered_bytes + in_flight_bytes
    if unpersisted and oldest_unpersisted_age_ns is None:
        oldest_unpersisted_age_ns = observed_ns
    if not unpersisted:
        oldest_unpersisted_age_ns = None
    if histogram_series is None:
        histogram_series = (
            (_series(exchange, bucket_counts, lag_max_ns=lag_max_ns),)
            if durable
            else ()
        )
    aggregate_max = lag_max_ns
    if durable and aggregate_max is None:
        aggregate_max = max(
            item.lag_max_ns for item in histogram_series if item.lag_max_ns is not None
        )
    return WriterMetricsSnapshotV1(
        observed_monotonic_ns=observed_ns,
        exchange=exchange,
        worker_instance_id=_worker_id(exchange),
        config_sha256=config_sha256,
        config_generation=config_generation,
        lifecycle=(WriterLifecycle.CLOSED if final else WriterLifecycle.ACCEPTING),
        admission_state=(AdmissionState.CLOSED if final else AdmissionState.OPEN),
        publication_state=PublicationState.IDLE,
        critical_reason=None,
        acceptance_ordinal_high_water=(None if accepted == 0 else accepted - 1),
        accepted_record_count=accepted,
        durable_record_count=durable,
        unpersisted_record_count=unpersisted,
        uncertain_record_count=0,
        queued_records=queued_records,
        queued_bytes=queued_bytes,
        buffered_records=buffered_records,
        buffered_bytes=buffered_bytes,
        in_flight_records=in_flight_records,
        in_flight_bytes=in_flight_bytes,
        resident_record_bytes=resident_bytes,
        resident_control_records=resident_control_records,
        resident_control_bytes=resident_control_records * 10,
        oldest_unpersisted_age_ns=oldest_unpersisted_age_ns,
        enqueue_high_water_count=enqueue_high_water_count,
        normal_overflow_count=normal_overflow_count,
        control_overflow_count=control_overflow_count,
        not_accepting_count=not_accepting_count,
        active_logical_generation_count=active_generations,
        retiring_generation_count=retiring_generations,
        open_file_descriptor_count=open_fds,
        sync_inflight=sync_inflight,
        durability_histogram_schema_version=1,
        durability_bucket_counts=bucket_counts,
        durability_sample_count=durable,
        durability_lag_p50_ns=_nearest_rank(bucket_counts, 50),
        durability_lag_p95_ns=_nearest_rank(bucket_counts, 95),
        durability_lag_p99_ns=_nearest_rank(bucket_counts, 99),
        durability_lag_max_ns=aggregate_max,
        durability_histogram_series=histogram_series,
        sync_count=durable if sync_count is None else sync_count,
        sync_duration_total_ns=(
            durable * 10 if sync_duration_total_ns is None else sync_duration_total_ns
        ),
        sync_duration_max_ns=(
            durable if sync_duration_max_ns is None else sync_duration_max_ns
        ),
        slo_breach_count=slo_breach_count,
        write_failure_count=write_failure_count,
        sync_failure_count=sync_failure_count,
        publication_failure_count=publication_failure_count,
    )


def _worker_round(
    round_index: int,
    snapshots: tuple[WriterMetricsSnapshotV1, ...],
    *,
    scheduled_ns: int,
    final: bool = False,
    completion_ns: int | None = None,
) -> GateSamplingRoundV1:
    kind = "final" if final else "sample"
    completed = scheduled_ns + 1 if completion_ns is None else completion_ns
    samples = tuple(
        GateWorkerSampleV1(
            round_index=round_index,
            round_kind=kind,
            scheduled_monotonic_ns=scheduled_ns,
            request_started_monotonic_ns=scheduled_ns,
            request_completed_monotonic_ns=completed,
            snapshot=snapshot,
        )
        for snapshot in snapshots
    )
    return GateSamplingRoundV1(
        round_index=round_index,
        round_kind=kind,
        scheduled_monotonic_ns=scheduled_ns,
        expected_worker_keys=_worker_keys(),
        samples=samples,
    )


def _valid_worker_rounds() -> tuple[GateSamplingRoundV1, ...]:
    final_counts = (10, 11, 12, 13, 14)
    first_gauges = (
        {"queued_records": 4, "resident_control_records": 2},
        {},
        {"buffered_records": 3},
        {},
        {"in_flight_records": 2},
    )
    second_gauges = (
        {},
        {"queued_records": 3},
        {},
        {"buffered_records": 4},
        {"in_flight_records": 1},
    )
    rounds: list[GateSamplingRoundV1] = []
    first: list[WriterMetricsSnapshotV1] = []
    second: list[WriterMetricsSnapshotV1] = []
    final: list[WriterMetricsSnapshotV1] = []
    for index, (exchange, count) in enumerate(
        zip(CANONICAL_EXCHANGES, final_counts, strict=True)
    ):
        bucket_index = index + 1
        first.append(
            _snapshot(
                exchange,
                observed_ns=10,
                bucket_counts=_buckets(count=count - 6, index=bucket_index),
                final=False,
                active_generations=(5 if index == 0 else 2 if index == 2 else 0),
                open_fds=(9 if index == 0 else 4 if index == 2 else 0),
                sync_inflight=(1 if index in {0, 2} else 0),
                enqueue_high_water_count=index,
                sync_duration_max_ns=90 + index,
                **first_gauges[index],
            )
        )
        second.append(
            _snapshot(
                exchange,
                observed_ns=20,
                bucket_counts=_buckets(
                    count=(
                        count - sum(second_gauges[index].values())
                        if second_gauges[index]
                        else count - 2
                    ),
                    index=bucket_index,
                ),
                final=False,
                active_generations=(8 if index == 1 else 0),
                open_fds=(15 if index == 1 else 0),
                sync_inflight=(2 if index == 1 else 0),
                enqueue_high_water_count=index,
                sync_duration_max_ns=95 + index,
                **second_gauges[index],
            )
        )
        final.append(
            _snapshot(
                exchange,
                observed_ns=30,
                bucket_counts=_buckets(count=count, index=bucket_index),
                final=True,
                enqueue_high_water_count=index,
                sync_duration_max_ns=100 + index,
            )
        )
    rounds.append(_worker_round(0, tuple(first), scheduled_ns=10))
    rounds.append(_worker_round(1, tuple(second), scheduled_ns=20))
    rounds.append(_worker_round(2, tuple(final), scheduled_ns=30, final=True))
    return tuple(rounds)


def _replace_worker_snapshot(
    round_: GateSamplingRoundV1,
    worker_index: int,
    snapshot: WriterMetricsSnapshotV1,
) -> GateSamplingRoundV1:
    samples = list(round_.samples)
    samples[worker_index] = samples[worker_index].model_copy(
        update={"snapshot": snapshot}
    )
    return round_.model_copy(update={"samples": tuple(samples)})


def _resource_round(
    round_index: int,
    *,
    scheduled_ns: int,
    total_rss: int,
    total_fds: int,
    completion_ns: int | None = None,
    process_ids: tuple[int, ...] = (100, 101, 102, 103, 104, 105),
) -> GateResourceSamplingRoundV1:
    completed = scheduled_ns + 1 if completion_ns is None else completion_ns
    keys = _process_keys()
    samples = tuple(
        GateProcessResourceSampleV1(
            round_index=round_index,
            scheduled_monotonic_ns=scheduled_ns,
            request_started_monotonic_ns=scheduled_ns,
            request_completed_monotonic_ns=completed,
            process_key=key,
            process_id=process_ids[index],
            rss_bytes=(total_rss if index == 0 else 0),
            open_fd_count=(total_fds if index == 0 else 0),
        )
        for index, key in enumerate(keys)
    )
    return GateResourceSamplingRoundV1(
        round_index=round_index,
        scheduled_monotonic_ns=scheduled_ns,
        expected_process_keys=keys,
        samples=samples,
    )


def _healthy_workers() -> tuple[GateWorkerHealthV1, ...]:
    return tuple(
        GateWorkerHealthV1(
            exchange=exchange,
            worker_instance_id=_worker_id(exchange),
            lifecycle=WriterLifecycle.ACCEPTING,
            critical_reason=None,
        )
        for exchange in CANONICAL_EXCHANGES
    )


def _health_sample(
    round_index: int,
    *,
    scheduled_ns: int,
    completed_ns: int | None = None,
    data_available_bytes: int = 1_000,
    state_available_bytes: int = 2_000,
    workers: tuple[GateWorkerHealthV1, ...] | None = None,
) -> GateStorageHealthSampleV1:
    completed = scheduled_ns + 1 if completed_ns is None else completed_ns
    return GateStorageHealthSampleV1(
        round_index=round_index,
        scheduled_monotonic_ns=scheduled_ns,
        request_started_monotonic_ns=scheduled_ns,
        request_completed_monotonic_ns=completed,
        data_available_bytes=data_available_bytes,
        state_available_bytes=state_available_bytes,
        workers=_healthy_workers() if workers is None else workers,
    )


def test_aggregate_contract_field_order_is_frozen() -> None:
    assert tuple(FinalWorkerAggregateV1.model_fields) == _FINAL_WORKER_AGGREGATE_FIELDS
    assert tuple(GateResourceSummaryV1.model_fields) == _RESOURCE_SUMMARY_FIELDS
    assert tuple(GateStorageHealthSummaryV1.model_fields) == _HEALTH_SUMMARY_FIELDS


def test_final_only_aggregation_and_same_round_gauge_peaks() -> None:
    sequences = validate_worker_rounds(
        _valid_worker_rounds(), expected_workers=_worker_keys()
    )
    summary = aggregate_final_worker_snapshots(sequences)

    expected_buckets = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    for index, count in enumerate((10, 11, 12, 13, 14), start=1):
        expected_buckets[index] = count
    assert summary.worker_count == 5
    assert summary.sampling_round_count == 3
    assert summary.final_round_index == 2
    assert summary.accepted_record_count == 60
    assert summary.durable_record_count == 60
    assert summary.durability_sample_count == 60
    assert summary.durability_bucket_counts == tuple(expected_buckets)
    assert summary.durability_lag_p50_ns == DURABILITY_BUCKET_UPPER_BOUNDS_NS[3]
    assert summary.durability_lag_p95_ns == DURABILITY_BUCKET_UPPER_BOUNDS_NS[5]
    assert summary.durability_lag_p99_ns == DURABILITY_BUCKET_UPPER_BOUNDS_NS[5]
    assert summary.durability_lag_max_ns == DURABILITY_BUCKET_UPPER_BOUNDS_NS[5]
    assert summary.sync_count == 60
    assert summary.sync_duration_total_ns == 600
    assert summary.sync_duration_max_ns == 104
    assert summary.enqueue_high_water_count == 10

    assert summary.unpersisted_record_count == 0
    assert summary.uncertain_record_count == 0
    assert summary.unpersisted_record_count_peak == 9
    assert summary.queued_records_peak == 4
    assert summary.queued_bytes_peak == 40
    assert summary.buffered_records_peak == 4
    assert summary.buffered_bytes_peak == 40
    assert summary.in_flight_records_peak == 2
    assert summary.in_flight_bytes_peak == 20
    assert summary.resident_record_bytes_peak == 90
    assert summary.resident_control_records_peak == 2
    assert summary.resident_control_bytes_peak == 20
    assert summary.oldest_unpersisted_age_max_ns == 20
    assert summary.active_logical_generation_count_peak == 8
    assert summary.open_file_descriptor_count_peak == 15
    assert summary.sync_inflight_peak == 2


def test_all_aggregate_summaries_round_trip_their_canonical_bytes() -> None:
    worker_summary = aggregate_final_worker_snapshots(
        validate_worker_rounds(_valid_worker_rounds(), expected_workers=_worker_keys())
    )
    resource_summary = summarize_resources(
        (
            _resource_round(0, scheduled_ns=10, total_rss=100, total_fds=2),
            _resource_round(
                1,
                scheduled_ns=10 + _NS_PER_MINUTE,
                total_rss=101,
                total_fds=3,
            ),
        ),
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=10,
    )
    health_summary = summarize_storage_health(
        (_health_sample(0, scheduled_ns=10),),
        duration_ns=10,
        interval_ns=10,
    )

    for summary in (worker_summary, resource_summary, health_summary):
        loaded = type(summary).model_validate_json(
            summary.canonical_bytes(), strict=True
        )
        assert loaded == summary
        assert loaded.canonical_bytes() == summary.canonical_bytes()


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("final_round_index", 1),
        ("durable_record_count", 59),
        ("unpersisted_record_count", 1),
        ("durability_lag_p50_ns", 0),
        ("durability_lag_max_ns", 100_000),
        ("oldest_unpersisted_age_max_ns", None),
    ],
)
def test_final_aggregate_rejects_derived_fact_mutation(
    field: str, replacement: object
) -> None:
    summary = aggregate_final_worker_snapshots(
        validate_worker_rounds(_valid_worker_rounds(), expected_workers=_worker_keys())
    )
    with pytest.raises(ValidationError):
        FinalWorkerAggregateV1.model_validate(
            {**summary.model_dump(mode="python"), field: replacement}
        )


def test_round_intervals_may_touch_but_must_not_overlap() -> None:
    rounds = list(_valid_worker_rounds())
    first_samples = tuple(
        sample.model_copy(update={"request_completed_monotonic_ns": 20})
        for sample in rounds[0].samples
    )
    rounds[0] = rounds[0].model_copy(update={"samples": first_samples})
    validate_worker_rounds(rounds, expected_workers=_worker_keys())

    overlapping_samples = list(first_samples)
    overlapping_samples[0] = overlapping_samples[0].model_copy(
        update={"request_completed_monotonic_ns": 21}
    )
    rounds[0] = rounds[0].model_copy(update={"samples": tuple(overlapping_samples)})
    with pytest.raises(ValueError, match="overlap"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())
    relaxed = validate_worker_rounds(
        rounds,
        expected_workers=_worker_keys(),
        require_nonoverlap=False,
    )
    assert aggregate_final_worker_snapshots(relaxed).worker_count == 5


@pytest.mark.parametrize(
    "expected_workers",
    [
        _worker_keys()[:-1],
        (*_worker_keys(), _worker_keys()[0]),
        (*_worker_keys()[:-1], _worker_keys()[0]),
    ],
)
def test_worker_expectation_must_be_exact_and_unique(
    expected_workers: tuple[GateWorkerKeyV1, ...],
) -> None:
    with pytest.raises(ValueError, match="expected workers"):
        validate_worker_rounds(
            _valid_worker_rounds(), expected_workers=expected_workers
        )


@pytest.mark.parametrize("mode", ["missing", "duplicate", "sixth"])
def test_each_worker_round_must_have_exactly_one_sample(mode: str) -> None:
    rounds = list(_valid_worker_rounds())
    samples = rounds[1].samples
    if mode == "missing":
        changed = samples[:-1]
    elif mode == "duplicate":
        changed = (*samples[:-1], samples[0])
    else:
        changed = (*samples, samples[0])
    rounds[1] = rounds[1].model_copy(update={"samples": changed})
    with pytest.raises(ValueError, match="worker"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())


@pytest.mark.parametrize(
    "rounds",
    [
        _valid_worker_rounds()[1:],
        (_valid_worker_rounds()[0], _valid_worker_rounds()[2]),
        (
            _valid_worker_rounds()[0],
            _valid_worker_rounds()[1].model_copy(update={"round_index": 0}),
            _valid_worker_rounds()[2],
        ),
        (
            _valid_worker_rounds()[0],
            _valid_worker_rounds()[1].model_copy(update={"scheduled_monotonic_ns": 10}),
            _valid_worker_rounds()[2],
        ),
    ],
)
def test_worker_round_order_is_zero_based_consecutive_and_monotonic(
    rounds: tuple[GateSamplingRoundV1, ...],
) -> None:
    with pytest.raises(ValueError, match="round"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())


def test_worker_and_config_replacement_are_rejected() -> None:
    rounds = list(_valid_worker_rounds())
    original = rounds[1].samples[0].snapshot
    replacement = original.model_copy(update={"worker_instance_id": "replacement"})
    rounds[1] = _replace_worker_snapshot(rounds[1], 0, replacement)
    with pytest.raises(ValueError, match="worker"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())

    rounds = list(_valid_worker_rounds())
    original = rounds[1].samples[0].snapshot
    replacement = original.model_copy(update={"config_sha256": "b" * 64})
    rounds[1] = _replace_worker_snapshot(rounds[1], 0, replacement)
    with pytest.raises(ValueError, match="config"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())


def test_equal_observed_time_requires_identical_canonical_snapshot_bytes() -> None:
    rounds = list(_valid_worker_rounds())
    cached = rounds[0].samples[0].snapshot
    rounds[1] = _replace_worker_snapshot(rounds[1], 0, cached)
    validate_worker_rounds(rounds, expected_workers=_worker_keys())

    changed = _snapshot(
        Exchange.BINANCE,
        observed_ns=cached.observed_monotonic_ns,
        bucket_counts=_buckets(count=9, index=1),
        final=False,
        enqueue_high_water_count=1,
    )
    rounds[1] = _replace_worker_snapshot(rounds[1], 0, changed)
    with pytest.raises(ValueError, match="equal observed"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())


def test_quantiles_may_decrease_when_cumulative_buckets_do_not() -> None:
    high = _buckets(count=1, index=10)
    later_values = list(high)
    later_values[1] = 2
    later = tuple(later_values)
    first = tuple(
        _snapshot(
            exchange,
            observed_ns=10,
            bucket_counts=(high if index == 0 else _buckets(count=0, index=1)),
            final=False,
        )
        for index, exchange in enumerate(CANONICAL_EXCHANGES)
    )
    final = tuple(
        _snapshot(
            exchange,
            observed_ns=20,
            bucket_counts=(later if index == 0 else _buckets(count=0, index=1)),
            final=True,
        )
        for index, exchange in enumerate(CANONICAL_EXCHANGES)
    )
    rounds = (
        _worker_round(0, first, scheduled_ns=10),
        _worker_round(1, final, scheduled_ns=20, final=True),
    )

    sequences = validate_worker_rounds(rounds, expected_workers=_worker_keys())
    assert (
        first[0].durability_lag_p50_ns > final[0].durability_lag_p50_ns  # type: ignore[operator]
    )
    assert aggregate_final_worker_snapshots(sequences).durability_sample_count == 3


def test_decreasing_counters_buckets_maxima_and_removed_series_are_rejected() -> None:
    base = list(_valid_worker_rounds())

    lower_counter = _snapshot(
        Exchange.BINANCE,
        observed_ns=30,
        bucket_counts=_buckets(count=1, index=1),
        final=True,
    )
    counter_rounds = list(base)
    counter_rounds[-1] = _replace_worker_snapshot(counter_rounds[-1], 0, lower_counter)
    with pytest.raises(ValueError, match="cumulative"):
        validate_worker_rounds(counter_rounds, expected_workers=_worker_keys())

    earlier_buckets = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    earlier_buckets[1] = 2
    later_buckets = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    later_buckets[1] = 1
    later_buckets[2] = 2
    bucket_rounds = list(base)
    bucket_rounds[0] = _replace_worker_snapshot(
        bucket_rounds[0],
        0,
        _snapshot(
            Exchange.BINANCE,
            observed_ns=10,
            bucket_counts=tuple(earlier_buckets),
            final=False,
        ),
    )
    bucket_rounds[1] = _replace_worker_snapshot(
        bucket_rounds[1],
        0,
        _snapshot(
            Exchange.BINANCE,
            observed_ns=20,
            bucket_counts=tuple(later_buckets),
            final=False,
        ),
    )
    with pytest.raises(ValueError, match="bucket"):
        validate_worker_rounds(bucket_rounds, expected_workers=_worker_keys())

    maximum_rounds = list(base)
    maximum_rounds[0] = _replace_worker_snapshot(
        maximum_rounds[0],
        0,
        _snapshot(
            Exchange.BINANCE,
            observed_ns=10,
            bucket_counts=_buckets(count=1, index=5),
            final=False,
            lag_max_ns=2_000_000,
            sync_duration_max_ns=200,
        ),
    )
    maximum_rounds[1] = _replace_worker_snapshot(
        maximum_rounds[1],
        0,
        _snapshot(
            Exchange.BINANCE,
            observed_ns=20,
            bucket_counts=_buckets(count=2, index=5),
            final=False,
            lag_max_ns=1_500_000,
            sync_duration_max_ns=100,
        ),
    )
    with pytest.raises(ValueError, match="maximum"):
        validate_worker_rounds(maximum_rounds, expected_workers=_worker_keys())

    first_a = _series(
        Exchange.BINANCE,
        _buckets(count=1, index=1),
        logical_stream="bbo",
    )
    first_b = _series(
        Exchange.BINANCE,
        _buckets(count=1, index=2),
        logical_stream="trade",
    )
    combined = tuple(
        left + right
        for left, right in zip(
            first_a.bucket_counts, first_b.bucket_counts, strict=True
        )
    )
    removed_rounds = list(base)
    removed_rounds[0] = _replace_worker_snapshot(
        removed_rounds[0],
        0,
        _snapshot(
            Exchange.BINANCE,
            observed_ns=10,
            bucket_counts=combined,
            final=False,
            histogram_series=(first_a, first_b),
        ),
    )
    removed_rounds[1] = _replace_worker_snapshot(
        removed_rounds[1],
        0,
        _snapshot(
            Exchange.BINANCE,
            observed_ns=20,
            bucket_counts=_buckets(count=3, index=2),
            final=False,
            histogram_series=(
                _series(
                    Exchange.BINANCE,
                    _buckets(count=3, index=2),
                    logical_stream="trade",
                ),
            ),
        ),
    )
    with pytest.raises(ValueError, match="series"):
        validate_worker_rounds(removed_rounds, expected_workers=_worker_keys())


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("unpersisted_record_count", 1),
        ("uncertain_record_count", 1),
        ("queued_records", 1),
        ("queued_bytes", 1),
        ("buffered_records", 1),
        ("buffered_bytes", 1),
        ("in_flight_records", 1),
        ("in_flight_bytes", 1),
        ("resident_record_bytes", 1),
        ("resident_control_records", 1),
        ("resident_control_bytes", 1),
        ("oldest_unpersisted_age_ns", 1),
        ("active_logical_generation_count", 1),
        ("retiring_generation_count", 1),
        ("open_file_descriptor_count", 1),
        ("sync_inflight", 1),
    ],
)
def test_every_nonzero_final_gauge_is_rejected(field: str, value: int) -> None:
    rounds = list(_valid_worker_rounds())
    final = rounds[-1].samples[0].snapshot.model_copy(update={field: value})
    rounds[-1] = _replace_worker_snapshot(rounds[-1], 0, final)
    with pytest.raises(ValueError, match="final"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())


def test_final_round_is_unique_last_and_prior_snapshots_are_not_closed() -> None:
    rounds = list(_valid_worker_rounds())
    rounds[1] = rounds[1].model_copy(update={"round_kind": "final"})
    with pytest.raises(ValueError, match="final"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())

    rounds = list(_valid_worker_rounds())
    closed_early = (
        rounds[0]
        .samples[0]
        .snapshot.model_copy(
            update={
                "lifecycle": WriterLifecycle.CLOSED,
                "admission_state": AdmissionState.CLOSED,
            }
        )
    )
    rounds[0] = _replace_worker_snapshot(rounds[0], 0, closed_early)
    with pytest.raises(ValueError, match="CLOSED"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())


def test_nonfinal_round_kind_is_not_artificially_restricted() -> None:
    rounds = list(_valid_worker_rounds())
    samples = tuple(
        sample.model_copy(update={"round_kind": "initial"})
        for sample in rounds[0].samples
    )
    rounds[0] = rounds[0].model_copy(
        update={"round_kind": "initial", "samples": samples}
    )
    validate_worker_rounds(rounds, expected_workers=_worker_keys())


def test_critical_worker_cannot_recover_into_a_final_closed_snapshot() -> None:
    rounds = list(_valid_worker_rounds())
    critical = (
        rounds[1]
        .samples[0]
        .snapshot.model_copy(
            update={
                "lifecycle": WriterLifecycle.CRITICAL,
                "admission_state": AdmissionState.CLOSED,
                "critical_reason": WriterCriticalReason.WRITE_FAILED,
            }
        )
    )
    rounds[1] = _replace_worker_snapshot(rounds[1], 0, critical)
    with pytest.raises(ValueError, match="CRITICAL"):
        validate_worker_rounds(rounds, expected_workers=_worker_keys())


def test_rss_ols_and_fd_growth_use_same_round_post_warmup_totals() -> None:
    rounds = (
        _resource_round(0, scheduled_ns=0, total_rss=5_000, total_fds=100),
        _resource_round(
            1,
            scheduled_ns=_NS_PER_MINUTE,
            total_rss=4_000,
            total_fds=80,
        ),
        _resource_round(
            2,
            scheduled_ns=2 * _NS_PER_MINUTE,
            total_rss=1_000,
            total_fds=10,
        ),
        _resource_round(
            3,
            scheduled_ns=3 * _NS_PER_MINUTE,
            total_rss=1_120,
            total_fds=13,
        ),
        _resource_round(
            4,
            scheduled_ns=4 * _NS_PER_MINUTE,
            total_rss=1_240,
            total_fds=9,
        ),
    )
    summary = summarize_resources(
        rounds,
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=2 * _NS_PER_MINUTE,
    )

    assert summary.process_count == 6
    assert summary.round_count == 5
    assert summary.post_warmup_round_count == 3
    assert summary.resource_trend_valid is True
    assert summary.rss_peak_bytes == 5_000
    assert summary.rss_slope_bytes_per_minute == Decimal(120)
    assert summary.open_fds_peak == 100
    assert summary.first_open_fds_after_warmup == 10
    assert summary.max_open_fds_after_warmup == 13
    assert summary.final_open_fds_after_warmup == 9
    assert summary.fd_growth_after_warmup == 3
    assert summary.first_request_monotonic_ns == 0
    assert summary.final_completion_monotonic_ns == 4 * _NS_PER_MINUTE + 1
    assert summary.coverage_ns == 4 * _NS_PER_MINUTE + 1
    assert summary.sample_max_gap_ns == _NS_PER_MINUTE


def test_resource_peaks_sum_processes_only_within_the_same_round() -> None:
    first = _resource_round(0, scheduled_ns=10, total_rss=0, total_fds=0)
    second = _resource_round(
        1,
        scheduled_ns=10 + _NS_PER_MINUTE,
        total_rss=0,
        total_fds=0,
    )
    first_samples = list(first.samples)
    second_samples = list(second.samples)
    for index in range(6):
        first_samples[index] = first_samples[index].model_copy(
            update={"rss_bytes": index + 1, "open_fd_count": index + 1}
        )
        second_samples[index] = second_samples[index].model_copy(
            update={"rss_bytes": 6 - index, "open_fd_count": 6 - index}
        )
    first = first.model_copy(update={"samples": tuple(first_samples)})
    second = second.model_copy(update={"samples": tuple(second_samples)})

    summary = summarize_resources(
        (first, second),
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=10,
    )
    assert summary.rss_peak_bytes == 21
    assert summary.open_fds_peak == 21
    assert summary.rss_slope_bytes_per_minute == Decimal(0)
    assert summary.fd_growth_after_warmup == 0


def test_time_arguments_follow_the_unbounded_strict_integer_contract() -> None:
    beyond_signed_int64 = 2**63
    resources = summarize_resources(
        (_resource_round(0, scheduled_ns=10, total_rss=1, total_fds=1),),
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=beyond_signed_int64,
    )
    assert resources.warmup_ended_monotonic_ns == beyond_signed_int64

    health = summarize_storage_health(
        (_health_sample(0, scheduled_ns=10),),
        duration_ns=beyond_signed_int64,
        interval_ns=beyond_signed_int64,
    )
    assert health.duration_ns == beyond_signed_int64
    assert health.interval_ns == beyond_signed_int64


def test_resource_ols_uses_fixed_decimal_context_and_not_endpoint_slope() -> None:
    base = 2**62
    rounds = (
        _resource_round(0, scheduled_ns=base, total_rss=100, total_fds=1),
        _resource_round(
            1,
            scheduled_ns=base + _NS_PER_MINUTE,
            total_rss=101,
            total_fds=1,
        ),
        _resource_round(
            2,
            scheduled_ns=base + 3 * _NS_PER_MINUTE,
            total_rss=102,
            total_fds=1,
        ),
    )
    with localcontext() as context:
        context.prec = 3
        context.rounding = ROUND_DOWN
        first = summarize_resources(
            rounds,
            expected_processes=_process_keys(),
            warmup_ended_monotonic_ns=base,
        )
    with localcontext() as context:
        context.prec = 9
        second = summarize_resources(
            rounds,
            expected_processes=_process_keys(),
            warmup_ended_monotonic_ns=base,
        )

    expected = Decimal("0.64285714285714285714285714285714285714285714285714")
    assert first.rss_slope_bytes_per_minute == expected
    assert second.rss_slope_bytes_per_minute == expected
    assert first.canonical_bytes() == second.canonical_bytes()
    loaded = GateResourceSummaryV1.model_validate(decode_json(first.canonical_bytes()))
    assert loaded == first


def test_negative_resource_slope_is_floored_to_zero() -> None:
    summary = summarize_resources(
        (
            _resource_round(0, scheduled_ns=10, total_rss=200, total_fds=3),
            _resource_round(
                1,
                scheduled_ns=10 + _NS_PER_MINUTE,
                total_rss=100,
                total_fds=2,
            ),
        ),
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=10,
    )
    assert summary.rss_slope_bytes_per_minute == Decimal(0)
    assert summary.fd_growth_after_warmup == 0


def test_zero_and_one_post_warmup_rounds_remain_explicitly_unavailable() -> None:
    rounds = (
        _resource_round(0, scheduled_ns=10, total_rss=100, total_fds=5),
        _resource_round(1, scheduled_ns=20, total_rss=110, total_fds=6),
    )
    none = summarize_resources(
        rounds,
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=30,
    )
    assert none.post_warmup_round_count == 0
    assert none.resource_trend_valid is False
    assert none.rss_slope_bytes_per_minute is None
    assert none.first_open_fds_after_warmup is None
    assert none.max_open_fds_after_warmup is None
    assert none.final_open_fds_after_warmup is None
    assert none.fd_growth_after_warmup is None

    one = summarize_resources(
        rounds,
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=20,
    )
    assert one.post_warmup_round_count == 1
    assert one.resource_trend_valid is False
    assert one.rss_slope_bytes_per_minute is None
    assert one.first_open_fds_after_warmup == 6
    assert one.max_open_fds_after_warmup == 6
    assert one.final_open_fds_after_warmup == 6
    assert one.fd_growth_after_warmup == 0


@pytest.mark.parametrize("mode", ["missing", "duplicate", "seventh"])
def test_resource_round_requires_exact_six_processes(mode: str) -> None:
    first = _resource_round(0, scheduled_ns=10, total_rss=100, total_fds=10)
    second = _resource_round(1, scheduled_ns=20, total_rss=110, total_fds=11)
    samples = second.samples
    if mode == "missing":
        changed = samples[:-1]
    elif mode == "duplicate":
        changed = (*samples[:-1], samples[0])
    else:
        changed = (*samples, samples[0])
    second = second.model_copy(update={"samples": changed})
    with pytest.raises(ValueError, match="process"):
        summarize_resources(
            (first, second),
            expected_processes=_process_keys(),
            warmup_ended_monotonic_ns=0,
        )


def test_resource_process_key_and_pid_must_remain_stable() -> None:
    first = _resource_round(0, scheduled_ns=10, total_rss=100, total_fds=10)
    changed_pid = _resource_round(
        1,
        scheduled_ns=20,
        total_rss=110,
        total_fds=11,
        process_ids=(100, 101, 102, 103, 104, 999),
    )
    with pytest.raises(ValueError, match="PID"):
        summarize_resources(
            (first, changed_pid),
            expected_processes=_process_keys(),
            warmup_ended_monotonic_ns=0,
        )

    samples = list(changed_pid.samples)
    samples[0] = samples[0].model_copy(update={"process_key": _process_keys()[1]})
    changed_key = changed_pid.model_copy(update={"samples": tuple(samples)})
    with pytest.raises(ValueError, match="process"):
        summarize_resources(
            (first, changed_key),
            expected_processes=_process_keys(),
            warmup_ended_monotonic_ns=0,
        )


@pytest.mark.parametrize(
    "rounds",
    [
        (),
        (_resource_round(1, scheduled_ns=10, total_rss=100, total_fds=1),),
        (
            _resource_round(0, scheduled_ns=10, total_rss=100, total_fds=1),
            _resource_round(2, scheduled_ns=20, total_rss=100, total_fds=1),
        ),
        (
            _resource_round(0, scheduled_ns=10, total_rss=100, total_fds=1),
            _resource_round(1, scheduled_ns=10, total_rss=100, total_fds=1),
        ),
        (
            _resource_round(
                0,
                scheduled_ns=10,
                total_rss=100,
                total_fds=1,
                completion_ns=21,
            ),
            _resource_round(1, scheduled_ns=20, total_rss=100, total_fds=1),
        ),
    ],
)
def test_resource_round_sequence_is_complete_ordered_and_nonoverlapping(
    rounds: tuple[GateResourceSamplingRoundV1, ...],
) -> None:
    with pytest.raises(ValueError, match="round|empty|overlap"):
        summarize_resources(
            rounds,
            expected_processes=_process_keys(),
            warmup_ended_monotonic_ns=0,
        )


def test_resource_round_overlap_can_be_recorded_without_qualification_gate() -> None:
    rounds = (
        _resource_round(
            0,
            scheduled_ns=10,
            total_rss=100,
            total_fds=1,
            completion_ns=21,
        ),
        _resource_round(1, scheduled_ns=20, total_rss=100, total_fds=1),
    )

    summary = summarize_resources(
        rounds,
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=0,
        require_nonoverlap=False,
    )

    assert summary.round_count == 2


def test_resource_expected_processes_are_exact_and_unique() -> None:
    rounds = (_resource_round(0, scheduled_ns=10, total_rss=100, total_fds=1),)
    with pytest.raises(ValueError, match="expected processes"):
        summarize_resources(
            rounds,
            expected_processes=(*_process_keys()[:-1], _process_keys()[0]),
            warmup_ended_monotonic_ns=0,
        )


def test_storage_health_count_can_pass_while_coverage_fails() -> None:
    samples = tuple(_health_sample(index, scheduled_ns=index) for index in range(59))
    summary = summarize_storage_health(samples, duration_ns=600, interval_ns=10)
    assert summary.sample_count == summary.expected_min_sample_count == 59
    assert summary.sample_count_valid is True
    assert summary.coverage_ns == 59
    assert summary.required_coverage_ns == 580
    assert summary.coverage_valid is False
    assert summary.sample_max_gap_ns == 1


def test_storage_health_derives_coverage_gaps_health_and_independent_minima() -> None:
    workers = list(_healthy_workers())
    workers[0] = GateWorkerHealthV1(
        exchange=Exchange.BINANCE,
        worker_instance_id=_worker_id(Exchange.BINANCE),
        lifecycle=WriterLifecycle.CRITICAL,
        critical_reason=WriterCriticalReason.WRITE_FAILED,
    )
    samples = (
        _health_sample(
            0,
            scheduled_ns=100,
            completed_ns=101,
            data_available_bytes=900,
            state_available_bytes=700,
        ),
        _health_sample(
            1,
            scheduled_ns=300,
            completed_ns=301,
            data_available_bytes=800,
            state_available_bytes=1_200,
            workers=tuple(workers),
        ),
        _health_sample(
            2,
            scheduled_ns=679,
            completed_ns=680,
            data_available_bytes=1_100,
            state_available_bytes=600,
        ),
    )
    summary = summarize_storage_health(samples, duration_ns=600, interval_ns=10)

    assert summary.first_request_monotonic_ns == 100
    assert summary.final_completion_monotonic_ns == 680
    assert summary.coverage_ns == summary.required_coverage_ns == 580
    assert summary.coverage_valid is True
    assert summary.sample_max_gap_ns == 379
    assert summary.minimum_data_available_bytes == 800
    assert summary.minimum_state_available_bytes == 600
    assert summary.minimum_available_bytes_if_shared == 600
    assert summary.critical_worker_observation_count == 1
    assert summary.workers_healthy is False


@pytest.mark.parametrize(
    ("duration_ns", "interval_ns", "expected"),
    [(600, 10, 59), (601, 10, 60), (5, 10, 2)],
)
def test_storage_health_expected_count_uses_integer_ceil(
    duration_ns: int, interval_ns: int, expected: int
) -> None:
    summary = summarize_storage_health(
        (_health_sample(0, scheduled_ns=10),),
        duration_ns=duration_ns,
        interval_ns=interval_ns,
    )
    assert summary.expected_min_sample_count == expected
    assert summary.sample_max_gap_ns == 0


def test_storage_health_preserves_equal_root_facts_without_inferring_a_mount() -> None:
    summary = summarize_storage_health(
        (
            _health_sample(
                0,
                scheduled_ns=10,
                data_available_bytes=150,
                state_available_bytes=150,
            ),
        ),
        duration_ns=10,
        interval_ns=10,
    )
    assert summary.minimum_data_available_bytes == 150
    assert summary.minimum_state_available_bytes == 150
    assert summary.minimum_available_bytes_if_shared == 150
    assert "shared" not in type(summary).model_fields


@pytest.mark.parametrize(
    "samples",
    [
        (),
        (_health_sample(1, scheduled_ns=10),),
        (_health_sample(0, scheduled_ns=10), _health_sample(2, scheduled_ns=20)),
        (_health_sample(0, scheduled_ns=10), _health_sample(1, scheduled_ns=10)),
        (
            _health_sample(0, scheduled_ns=10, completed_ns=21),
            _health_sample(1, scheduled_ns=20),
        ),
    ],
)
def test_storage_health_sequence_is_complete_ordered_and_nonoverlapping(
    samples: tuple[GateStorageHealthSampleV1, ...],
) -> None:
    with pytest.raises(ValueError, match="sample|round|empty|overlap"):
        summarize_storage_health(samples, duration_ns=600, interval_ns=10)


def test_storage_health_overlap_can_be_recorded_without_qualification_gate() -> None:
    samples = (
        _health_sample(0, scheduled_ns=10, completed_ns=21),
        _health_sample(1, scheduled_ns=20),
    )

    summary = summarize_storage_health(
        samples,
        duration_ns=600,
        interval_ns=10,
        require_nonoverlap=False,
    )

    assert summary.sample_count == 2


def test_storage_health_revalidates_worker_completeness() -> None:
    sample = _health_sample(0, scheduled_ns=10)
    sample = sample.model_copy(update={"workers": sample.workers[:-1]})
    with pytest.raises(ValueError, match="worker"):
        summarize_storage_health((sample,), duration_ns=600, interval_ns=10)


@pytest.mark.parametrize(
    ("duration_ns", "interval_ns"),
    [(0, 1), (1, 0), (True, 1), (1, True), (1.0, 1), (1, 1.0)],
)
def test_storage_health_duration_and_interval_are_strict_positive_integers(
    duration_ns: Any, interval_ns: Any
) -> None:
    with pytest.raises((TypeError, ValueError), match="duration|interval"):
        summarize_storage_health(
            (_health_sample(0, scheduled_ns=10),),
            duration_ns=duration_ns,
            interval_ns=interval_ns,
        )


def test_resource_decimal_contract_is_strict_canonical_and_self_consistent() -> None:
    summary = summarize_resources(
        (
            _resource_round(0, scheduled_ns=10, total_rss=100, total_fds=1),
            _resource_round(
                1,
                scheduled_ns=10 + _NS_PER_MINUTE,
                total_rss=101,
                total_fds=1,
            ),
        ),
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=10,
    )
    values = summary.model_dump(mode="json")
    for invalid in [1, 1.0, True, "01", "+1", "1.0", "1e0", "-0", "NaN"]:
        values["rss_slope_bytes_per_minute"] = invalid
        with pytest.raises(ValidationError, match="rss_slope"):
            GateResourceSummaryV1.model_validate(values)


def test_summary_models_reject_derived_fact_disagreement() -> None:
    resources = summarize_resources(
        (
            _resource_round(0, scheduled_ns=10, total_rss=100, total_fds=1),
            _resource_round(
                1,
                scheduled_ns=10 + _NS_PER_MINUTE,
                total_rss=101,
                total_fds=2,
            ),
        ),
        expected_processes=_process_keys(),
        warmup_ended_monotonic_ns=10,
    )
    with pytest.raises(ValidationError, match="resource trend"):
        GateResourceSummaryV1.model_validate(
            {**resources.model_dump(mode="python"), "resource_trend_valid": False}
        )
    with pytest.raises(ValidationError, match="FD growth"):
        GateResourceSummaryV1.model_validate(
            {**resources.model_dump(mode="python"), "fd_growth_after_warmup": 99}
        )

    health = summarize_storage_health(
        (_health_sample(0, scheduled_ns=10),), duration_ns=10, interval_ns=10
    )
    for field, value in (
        ("expected_min_sample_count", 3),
        ("coverage_ns", 99),
        ("sample_max_gap_ns", 1),
        ("minimum_available_bytes_if_shared", 999),
        ("sample_count_valid", True),
        ("workers_healthy", False),
    ):
        with pytest.raises(ValidationError):
            GateStorageHealthSummaryV1.model_validate(
                {**health.model_dump(mode="python"), field: value}
            )
