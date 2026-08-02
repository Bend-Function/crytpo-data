from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DivisionByZero,
    InvalidOperation,
    Overflow,
)
from itertools import pairwise
from typing import TypeVar

from pydantic import BaseModel, ValidationError

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
    GateWorkerKeyV1,
    GateWorkerSampleV1,
)
from crypto_collector.domain.types import Exchange
from crypto_collector.storage.models import (
    AdmissionState,
    DurabilityHistogramSeriesV1,
    PublicationState,
    WriterLifecycle,
    WriterMetricsSnapshotV1,
)
from crypto_collector.storage.stats import DURABILITY_BUCKET_UPPER_BOUNDS_NS

_NS_PER_MINUTE = 60_000_000_000

_CUMULATIVE_FIELDS = (
    "accepted_record_count",
    "durable_record_count",
    "uncertain_record_count",
    "enqueue_high_water_count",
    "normal_overflow_count",
    "control_overflow_count",
    "not_accepting_count",
    "durability_sample_count",
    "sync_count",
    "sync_duration_total_ns",
    "slo_breach_count",
    "write_failure_count",
    "sync_failure_count",
    "publication_failure_count",
)
_MAXIMUM_FIELDS = ("durability_lag_max_ns", "sync_duration_max_ns")
_FINAL_ZERO_FIELDS = (
    "unpersisted_record_count",
    "uncertain_record_count",
    "queued_records",
    "queued_bytes",
    "buffered_records",
    "buffered_bytes",
    "in_flight_records",
    "in_flight_bytes",
    "resident_record_bytes",
    "resident_control_records",
    "resident_control_bytes",
    "active_logical_generation_count",
    "retiring_generation_count",
    "open_file_descriptor_count",
    "sync_inflight",
)
_FINAL_SUM_FIELDS = (
    "accepted_record_count",
    "durable_record_count",
    "unpersisted_record_count",
    "uncertain_record_count",
    "enqueue_high_water_count",
    "normal_overflow_count",
    "control_overflow_count",
    "not_accepting_count",
    "durability_sample_count",
    "sync_count",
    "sync_duration_total_ns",
    "slo_breach_count",
    "write_failure_count",
    "sync_failure_count",
    "publication_failure_count",
)
_ROUND_SUM_PEAK_FIELDS = (
    "unpersisted_record_count",
    "queued_records",
    "queued_bytes",
    "buffered_records",
    "buffered_bytes",
    "in_flight_records",
    "in_flight_bytes",
    "resident_record_bytes",
    "resident_control_records",
    "resident_control_bytes",
    "active_logical_generation_count",
    "retiring_generation_count",
    "open_file_descriptor_count",
    "sync_inflight",
)

_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _strict_integer(value: object, *, field_name: str, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field_name} must be {qualifier}")
    return value


def _revalidate(value: object, model_type: type[_ModelT], *, label: str) -> _ModelT:
    if not isinstance(value, model_type):
        raise TypeError(f"{label} must be {model_type.__name__}")
    try:
        return model_type.model_validate(value.model_dump(mode="python"))
    except ValidationError as error:
        raise ValueError(f"{label} is not a valid {model_type.__name__}") from error


def _worker_id(exchange: Exchange) -> str:
    return f"gate-worker-v1-{exchange.value}"


def _canonical_worker_pairs() -> tuple[tuple[Exchange, str], ...]:
    return tuple((exchange, _worker_id(exchange)) for exchange in CANONICAL_EXCHANGES)


def _worker_pairs(
    workers: Sequence[GateWorkerKeyV1],
) -> tuple[tuple[Exchange, str], ...]:
    return tuple((worker.exchange, worker.worker_instance_id) for worker in workers)


def _validate_expected_workers(
    expected_workers: Sequence[GateWorkerKeyV1],
) -> tuple[GateWorkerKeyV1, ...]:
    workers = tuple(expected_workers)
    if _worker_pairs(workers) != _canonical_worker_pairs():
        raise ValueError("expected workers must be the five canonical workers")
    return tuple(
        _revalidate(worker, GateWorkerKeyV1, label="expected worker")
        for worker in workers
    )


def _series_key(
    series: DurabilityHistogramSeriesV1,
) -> tuple[str, str, str]:
    return (
        series.exchange.value,
        "" if series.market is None else series.market.value,
        series.logical_stream,
    )


def _nondecreasing_optional_maximum(previous: int | None, current: int | None) -> bool:
    return previous is None or (current is not None and current >= previous)


def _validate_snapshot_progression(
    previous: WriterMetricsSnapshotV1,
    current: WriterMetricsSnapshotV1,
) -> None:
    if (
        previous.lifecycle is WriterLifecycle.CRITICAL
        and current.lifecycle is not WriterLifecycle.CRITICAL
    ):
        raise ValueError("a CRITICAL worker lifecycle cannot recover")
    if current.observed_monotonic_ns < previous.observed_monotonic_ns:
        raise ValueError("worker snapshot observed time decreased")
    if current.observed_monotonic_ns == previous.observed_monotonic_ns:
        if current.canonical_bytes() != previous.canonical_bytes():
            raise ValueError("equal observed times require identical snapshot bytes")
        return
    for field_name in _CUMULATIVE_FIELDS:
        if getattr(current, field_name) < getattr(previous, field_name):
            raise ValueError(f"worker cumulative field decreased: {field_name}")
    previous_series = {
        _series_key(series): series for series in previous.durability_histogram_series
    }
    current_series = {
        _series_key(series): series for series in current.durability_histogram_series
    }
    if not previous_series.keys() <= current_series.keys():
        raise ValueError("worker durability histogram series was removed")
    for key, prior in previous_series.items():
        present = current_series[key]
        if present.sample_count < prior.sample_count:
            raise ValueError("worker series cumulative sample count decreased")
        if any(
            current_count < previous_count
            for previous_count, current_count in zip(
                prior.bucket_counts,
                present.bucket_counts,
                strict=True,
            )
        ):
            raise ValueError("worker series bucket count decreased")
        if not _nondecreasing_optional_maximum(prior.lag_max_ns, present.lag_max_ns):
            raise ValueError("worker series cumulative maximum decreased")
    if any(
        current_count < previous_count
        for previous_count, current_count in zip(
            previous.durability_bucket_counts,
            current.durability_bucket_counts,
            strict=True,
        )
    ):
        raise ValueError("worker durability bucket count decreased")
    for field_name in _MAXIMUM_FIELDS:
        if not _nondecreasing_optional_maximum(
            getattr(previous, field_name), getattr(current, field_name)
        ):
            raise ValueError(f"worker cumulative maximum decreased: {field_name}")


def _validate_final_snapshot(snapshot: WriterMetricsSnapshotV1) -> None:
    if (
        snapshot.lifecycle is not WriterLifecycle.CLOSED
        or snapshot.admission_state is not AdmissionState.CLOSED
        or snapshot.publication_state is not PublicationState.IDLE
        or snapshot.critical_reason is not None
    ):
        raise ValueError("final worker snapshot is not in the CLOSED barrier state")
    if any(getattr(snapshot, field_name) != 0 for field_name in _FINAL_ZERO_FIELDS):
        raise ValueError("final worker snapshot has a nonzero terminal gauge")
    if snapshot.oldest_unpersisted_age_ns is not None:
        raise ValueError("final worker snapshot retains an oldest unpersisted age")
    if not (
        snapshot.accepted_record_count
        == snapshot.durable_record_count
        == snapshot.durability_sample_count
    ):
        raise ValueError("final worker snapshot counts do not agree")


@dataclass(frozen=True, slots=True)
class ValidatedWorkerSequences:
    expected_workers: tuple[GateWorkerKeyV1, ...]
    rounds: tuple[GateSamplingRoundV1, ...]
    worker_sequences: tuple[tuple[GateWorkerSampleV1, ...], ...]


def validate_worker_rounds(
    rounds: Iterable[GateSamplingRoundV1],
    *,
    expected_workers: Sequence[GateWorkerKeyV1],
) -> ValidatedWorkerSequences:
    workers = _validate_expected_workers(expected_workers)
    materialized = tuple(rounds)
    if not materialized:
        raise ValueError("worker sampling rounds cannot be empty")

    sequences: list[list[GateWorkerSampleV1]] = [[] for _ in range(len(workers))]
    previous_scheduled: int | None = None
    previous_interval_end: int | None = None
    expected_pairs = _worker_pairs(workers)
    last_index = len(materialized) - 1

    for expected_index, round_ in enumerate(materialized):
        if not isinstance(round_, GateSamplingRoundV1):
            raise TypeError("worker round must be GateSamplingRoundV1")
        if round_.round_index != expected_index:
            raise ValueError("worker round indices must be zero-based and consecutive")
        if (expected_index == last_index) != (round_.round_kind == "final"):
            raise ValueError("exactly the final worker round must have kind final")
        if (
            previous_scheduled is not None
            and round_.scheduled_monotonic_ns <= previous_scheduled
        ):
            raise ValueError("worker round scheduled time must strictly increase")
        if _worker_pairs(round_.expected_worker_keys) != expected_pairs:
            raise ValueError("worker round expected workers changed")
        if len(round_.samples) != len(workers):
            raise ValueError("worker round has a missing or extra worker sample")

        observed_pairs = tuple(
            (sample.snapshot.exchange, sample.snapshot.worker_instance_id)
            for sample in round_.samples
        )
        if observed_pairs != expected_pairs:
            raise ValueError("worker round samples are missing, duplicate, or replaced")

        interval_start: int | None = None
        interval_end: int | None = None
        for worker_index, sample in enumerate(round_.samples):
            if (
                sample.round_index != round_.round_index
                or sample.round_kind != round_.round_kind
                or sample.scheduled_monotonic_ns != round_.scheduled_monotonic_ns
            ):
                raise ValueError("worker sample parent round facts changed")
            if not (
                round_.scheduled_monotonic_ns
                <= sample.request_started_monotonic_ns
                <= sample.request_completed_monotonic_ns
            ):
                raise ValueError("worker sample request timing is invalid")
            snapshot = sample.snapshot
            if (
                expected_index != last_index
                and snapshot.lifecycle is WriterLifecycle.CLOSED
            ):
                raise ValueError("a non-final worker sample cannot already be CLOSED")
            if expected_index == last_index:
                _validate_final_snapshot(snapshot)
            prior_samples = sequences[worker_index]
            if prior_samples:
                prior_sample = prior_samples[-1]
                if (
                    sample.request_started_monotonic_ns
                    <= prior_sample.request_started_monotonic_ns
                ):
                    raise ValueError("worker request start time did not increase")
                prior_snapshot = prior_sample.snapshot
                if (
                    snapshot.exchange is not prior_snapshot.exchange
                    or snapshot.worker_instance_id != prior_snapshot.worker_instance_id
                ):
                    raise ValueError("worker identity was replaced")
                if (
                    snapshot.config_sha256 != prior_snapshot.config_sha256
                    or snapshot.config_generation != prior_snapshot.config_generation
                ):
                    raise ValueError("worker config changed during sampling")
                if (
                    snapshot.durability_histogram_schema_version
                    != prior_snapshot.durability_histogram_schema_version
                ):
                    raise ValueError("worker histogram schema changed")
                _validate_snapshot_progression(prior_snapshot, snapshot)
            _revalidate(snapshot, WriterMetricsSnapshotV1, label="worker snapshot")
            _revalidate(sample, GateWorkerSampleV1, label="worker sample")
            prior_samples.append(sample)
            interval_start = (
                sample.request_started_monotonic_ns
                if interval_start is None
                else min(interval_start, sample.request_started_monotonic_ns)
            )
            interval_end = (
                sample.request_completed_monotonic_ns
                if interval_end is None
                else max(interval_end, sample.request_completed_monotonic_ns)
            )

        assert interval_start is not None
        assert interval_end is not None
        if previous_interval_end is not None and interval_start < previous_interval_end:
            raise ValueError("worker sampling round intervals overlap")
        _revalidate(round_, GateSamplingRoundV1, label="worker round")
        previous_scheduled = round_.scheduled_monotonic_ns
        previous_interval_end = interval_end

    return ValidatedWorkerSequences(
        expected_workers=workers,
        rounds=materialized,
        worker_sequences=tuple(tuple(sequence) for sequence in sequences),
    )


def _nearest_rank(bucket_counts: tuple[int, ...], *, numerator: int) -> int | None:
    sample_count = sum(bucket_counts)
    if sample_count == 0:
        return None
    rank = max(1, (numerator * sample_count + 99) // 100)
    cumulative = 0
    for upper_bound, count in zip(
        DURABILITY_BUCKET_UPPER_BOUNDS_NS,
        bucket_counts,
        strict=True,
    ):
        cumulative += count
        if cumulative >= rank:
            return upper_bound
    raise AssertionError("aggregate histogram buckets are inconsistent")


def aggregate_final_worker_snapshots(
    sequences: ValidatedWorkerSequences,
) -> FinalWorkerAggregateV1:
    if not isinstance(sequences, ValidatedWorkerSequences):
        raise TypeError("sequences must be ValidatedWorkerSequences")
    validated = validate_worker_rounds(
        sequences.rounds,
        expected_workers=sequences.expected_workers,
    )
    final_snapshots = tuple(
        sequence[-1].snapshot for sequence in validated.worker_sequences
    )
    final_sums = {
        field_name: sum(getattr(snapshot, field_name) for snapshot in final_snapshots)
        for field_name in _FINAL_SUM_FIELDS
    }
    bucket_counts = tuple(
        sum(snapshot.durability_bucket_counts[index] for snapshot in final_snapshots)
        for index in range(len(DURABILITY_BUCKET_UPPER_BOUNDS_NS))
    )
    lag_maxima = tuple(
        snapshot.durability_lag_max_ns
        for snapshot in final_snapshots
        if snapshot.durability_lag_max_ns is not None
    )
    round_peaks = {
        field_name: max(
            sum(getattr(sample.snapshot, field_name) for sample in round_.samples)
            for round_ in validated.rounds
        )
        for field_name in _ROUND_SUM_PEAK_FIELDS
    }
    ages = tuple(
        sample.snapshot.oldest_unpersisted_age_ns
        for round_ in validated.rounds
        for sample in round_.samples
        if sample.snapshot.oldest_unpersisted_age_ns is not None
    )

    return FinalWorkerAggregateV1(
        worker_count=5,
        sampling_round_count=len(validated.rounds),
        final_round_index=validated.rounds[-1].round_index,
        accepted_record_count=final_sums["accepted_record_count"],
        durable_record_count=final_sums["durable_record_count"],
        unpersisted_record_count=final_sums["unpersisted_record_count"],
        uncertain_record_count=final_sums["uncertain_record_count"],
        enqueue_high_water_count=final_sums["enqueue_high_water_count"],
        normal_overflow_count=final_sums["normal_overflow_count"],
        control_overflow_count=final_sums["control_overflow_count"],
        not_accepting_count=final_sums["not_accepting_count"],
        durability_histogram_schema_version=1,
        durability_bucket_counts=bucket_counts,
        durability_sample_count=final_sums["durability_sample_count"],
        durability_lag_p50_ns=_nearest_rank(bucket_counts, numerator=50),
        durability_lag_p95_ns=_nearest_rank(bucket_counts, numerator=95),
        durability_lag_p99_ns=_nearest_rank(bucket_counts, numerator=99),
        durability_lag_max_ns=max(lag_maxima) if lag_maxima else None,
        sync_count=final_sums["sync_count"],
        sync_duration_total_ns=final_sums["sync_duration_total_ns"],
        sync_duration_max_ns=max(
            snapshot.sync_duration_max_ns for snapshot in final_snapshots
        ),
        slo_breach_count=final_sums["slo_breach_count"],
        write_failure_count=final_sums["write_failure_count"],
        sync_failure_count=final_sums["sync_failure_count"],
        publication_failure_count=final_sums["publication_failure_count"],
        unpersisted_record_count_peak=round_peaks["unpersisted_record_count"],
        queued_records_peak=round_peaks["queued_records"],
        queued_bytes_peak=round_peaks["queued_bytes"],
        buffered_records_peak=round_peaks["buffered_records"],
        buffered_bytes_peak=round_peaks["buffered_bytes"],
        in_flight_records_peak=round_peaks["in_flight_records"],
        in_flight_bytes_peak=round_peaks["in_flight_bytes"],
        resident_record_bytes_peak=round_peaks["resident_record_bytes"],
        resident_control_records_peak=round_peaks["resident_control_records"],
        resident_control_bytes_peak=round_peaks["resident_control_bytes"],
        oldest_unpersisted_age_max_ns=max(ages) if ages else None,
        active_logical_generation_count_peak=round_peaks[
            "active_logical_generation_count"
        ],
        retiring_generation_count_peak=round_peaks["retiring_generation_count"],
        open_file_descriptor_count_peak=round_peaks["open_file_descriptor_count"],
        sync_inflight_peak=round_peaks["sync_inflight"],
    )


def _canonical_process_pairs() -> tuple[tuple[str, Exchange | None, str | None], ...]:
    return (
        ("supervisor", None, None),
        *(
            ("exchange_worker", exchange, _worker_id(exchange))
            for exchange in CANONICAL_EXCHANGES
        ),
    )


def _process_pairs(
    processes: Sequence[GateProcessKeyV1],
) -> tuple[tuple[str, Exchange | None, str | None], ...]:
    return tuple(
        (process.role, process.exchange, process.worker_instance_id)
        for process in processes
    )


def _validate_expected_processes(
    expected_processes: Sequence[GateProcessKeyV1],
) -> tuple[GateProcessKeyV1, ...]:
    processes = tuple(expected_processes)
    if _process_pairs(processes) != _canonical_process_pairs():
        raise ValueError("expected processes must be the six canonical processes")
    return tuple(
        _revalidate(process, GateProcessKeyV1, label="expected process")
        for process in processes
    )


def _rss_ols_bytes_per_minute(points: Sequence[tuple[int, int]]) -> Decimal | None:
    if len(points) < 2:
        return None
    first_time = points[0][0]
    x_values = tuple(scheduled - first_time for scheduled, _ in points)
    y_values = tuple(rss for _, rss in points)
    count = len(points)
    numerator = count * sum(
        x * y for x, y in zip(x_values, y_values, strict=True)
    ) - sum(x_values) * sum(y_values)
    denominator = count * sum(x * x for x in x_values) - sum(x_values) ** 2
    if denominator <= 0:
        raise ValueError("resource OLS denominator must be positive")
    if numerator <= 0:
        return Decimal(0)
    context = Context(
        prec=50,
        rounding=ROUND_HALF_EVEN,
        Emin=-999999,
        Emax=999999,
        capitals=1,
        clamp=0,
        flags=[],
        traps=[InvalidOperation, DivisionByZero, Overflow],
    )
    return context.divide(
        Decimal(numerator * _NS_PER_MINUTE),
        Decimal(denominator),
    )


def summarize_resources(
    rounds: Iterable[GateResourceSamplingRoundV1],
    *,
    expected_processes: Sequence[GateProcessKeyV1],
    warmup_ended_monotonic_ns: int,
) -> GateResourceSummaryV1:
    warmup_ended = _strict_integer(
        warmup_ended_monotonic_ns,
        field_name="warmup_ended_monotonic_ns",
    )
    processes = _validate_expected_processes(expected_processes)
    materialized = tuple(rounds)
    if not materialized:
        raise ValueError("resource rounds cannot be empty")

    expected_pairs = _process_pairs(processes)
    stable_pids: dict[tuple[str, Exchange | None, str | None], int] = {}
    totals: list[tuple[int, int, int]] = []
    previous_scheduled: int | None = None
    previous_interval_end: int | None = None
    first_request: int | None = None
    final_completion: int | None = None

    for expected_index, round_ in enumerate(materialized):
        if not isinstance(round_, GateResourceSamplingRoundV1):
            raise TypeError("resource round must be GateResourceSamplingRoundV1")
        if round_.round_index != expected_index:
            raise ValueError(
                "resource round indices must be zero-based and consecutive"
            )
        if (
            previous_scheduled is not None
            and round_.scheduled_monotonic_ns <= previous_scheduled
        ):
            raise ValueError("resource round scheduled time must strictly increase")
        if _process_pairs(round_.expected_process_keys) != expected_pairs:
            raise ValueError("resource round expected process keys changed")
        if len(round_.samples) != len(processes):
            raise ValueError("resource round has a missing or extra process sample")
        observed_pairs = tuple(
            (
                sample.process_key.role,
                sample.process_key.exchange,
                sample.process_key.worker_instance_id,
            )
            for sample in round_.samples
        )
        if observed_pairs != expected_pairs:
            raise ValueError(
                "resource process samples are missing, duplicate, or replaced"
            )
        process_ids = tuple(sample.process_id for sample in round_.samples)
        if len(set(process_ids)) != len(process_ids):
            raise ValueError("resource round contains duplicate process PIDs")

        interval_start: int | None = None
        interval_end: int | None = None
        for sample in round_.samples:
            if (
                sample.round_index != round_.round_index
                or sample.scheduled_monotonic_ns != round_.scheduled_monotonic_ns
            ):
                raise ValueError("resource sample parent round facts changed")
            if not (
                round_.scheduled_monotonic_ns
                <= sample.request_started_monotonic_ns
                <= sample.request_completed_monotonic_ns
            ):
                raise ValueError("resource process request timing is invalid")
            key = (
                sample.process_key.role,
                sample.process_key.exchange,
                sample.process_key.worker_instance_id,
            )
            prior_pid = stable_pids.setdefault(key, sample.process_id)
            if sample.process_id != prior_pid:
                raise ValueError("resource process PID changed")
            _revalidate(
                sample,
                GateProcessResourceSampleV1,
                label="resource process sample",
            )
            interval_start = (
                sample.request_started_monotonic_ns
                if interval_start is None
                else min(interval_start, sample.request_started_monotonic_ns)
            )
            interval_end = (
                sample.request_completed_monotonic_ns
                if interval_end is None
                else max(interval_end, sample.request_completed_monotonic_ns)
            )
        assert interval_start is not None
        assert interval_end is not None
        if previous_interval_end is not None and interval_start < previous_interval_end:
            raise ValueError("resource sampling round intervals overlap")
        _revalidate(round_, GateResourceSamplingRoundV1, label="resource round")
        total_rss = sum(sample.rss_bytes for sample in round_.samples)
        total_fds = sum(sample.open_fd_count for sample in round_.samples)
        totals.append((round_.scheduled_monotonic_ns, total_rss, total_fds))
        first_request = interval_start if first_request is None else first_request
        final_completion = interval_end
        previous_scheduled = round_.scheduled_monotonic_ns
        previous_interval_end = interval_end

    post_warmup = tuple(row for row in totals if row[0] >= warmup_ended)
    fd_totals = tuple(row[2] for row in post_warmup)
    if not fd_totals:
        first_fd = maximum_fd = final_fd = growth = None
    else:
        first_fd = fd_totals[0]
        maximum_fd = max(fd_totals)
        final_fd = fd_totals[-1]
        growth = max(0, maximum_fd - first_fd)
    assert first_request is not None
    assert final_completion is not None
    scheduled_times = tuple(row[0] for row in totals)
    sample_max_gap = max(
        (current - previous for previous, current in pairwise(scheduled_times)),
        default=0,
    )
    return GateResourceSummaryV1(
        process_count=6,
        round_count=len(materialized),
        post_warmup_round_count=len(post_warmup),
        warmup_ended_monotonic_ns=warmup_ended,
        resource_trend_valid=len(post_warmup) >= 2,
        first_request_monotonic_ns=first_request,
        final_completion_monotonic_ns=final_completion,
        coverage_ns=final_completion - first_request,
        sample_max_gap_ns=sample_max_gap,
        rss_peak_bytes=max(row[1] for row in totals),
        rss_slope_bytes_per_minute=_rss_ols_bytes_per_minute(
            tuple((row[0], row[1]) for row in post_warmup)
        ),
        open_fds_peak=max(row[2] for row in totals),
        first_open_fds_after_warmup=first_fd,
        max_open_fds_after_warmup=maximum_fd,
        final_open_fds_after_warmup=final_fd,
        fd_growth_after_warmup=growth,
    )


def summarize_storage_health(
    samples: Iterable[GateStorageHealthSampleV1],
    *,
    duration_ns: int,
    interval_ns: int,
) -> GateStorageHealthSummaryV1:
    duration = _strict_integer(duration_ns, field_name="duration_ns", minimum=1)
    interval = _strict_integer(interval_ns, field_name="interval_ns", minimum=1)
    materialized = tuple(samples)
    if not materialized:
        raise ValueError("storage health samples cannot be empty")

    expected_worker_pairs = _canonical_worker_pairs()
    previous_scheduled: int | None = None
    previous_completion: int | None = None
    for expected_index, sample in enumerate(materialized):
        if not isinstance(sample, GateStorageHealthSampleV1):
            raise TypeError("health sample must be GateStorageHealthSampleV1")
        if sample.round_index != expected_index:
            raise ValueError(
                "health sample round indices must be zero-based and consecutive"
            )
        if (
            previous_scheduled is not None
            and sample.scheduled_monotonic_ns <= previous_scheduled
        ):
            raise ValueError("health sample scheduled time must strictly increase")
        if not (
            sample.scheduled_monotonic_ns
            <= sample.request_started_monotonic_ns
            <= sample.request_completed_monotonic_ns
        ):
            raise ValueError("health sample request timing is invalid")
        if (
            previous_completion is not None
            and sample.request_started_monotonic_ns < previous_completion
        ):
            raise ValueError("health sample intervals overlap")
        observed_worker_pairs = tuple(
            (worker.exchange, worker.worker_instance_id) for worker in sample.workers
        )
        if observed_worker_pairs != expected_worker_pairs:
            raise ValueError(
                "health sample workers are missing, duplicate, or replaced"
            )
        _revalidate(sample, GateStorageHealthSampleV1, label="health sample")
        previous_scheduled = sample.scheduled_monotonic_ns
        previous_completion = sample.request_completed_monotonic_ns

    expected_count = max(2, (duration + interval - 1) // interval - 1)
    required_coverage = max(0, duration - 2 * interval)
    first_request = materialized[0].request_started_monotonic_ns
    final_completion = materialized[-1].request_completed_monotonic_ns
    coverage = final_completion - first_request
    sample_max_gap = max(
        (
            current.scheduled_monotonic_ns - previous.scheduled_monotonic_ns
            for previous, current in pairwise(materialized)
        ),
        default=0,
    )
    minimum_data = min(sample.data_available_bytes for sample in materialized)
    minimum_state = min(sample.state_available_bytes for sample in materialized)
    critical_observations = sum(
        worker.lifecycle is WriterLifecycle.CRITICAL
        for sample in materialized
        for worker in sample.workers
    )
    return GateStorageHealthSummaryV1(
        duration_ns=duration,
        interval_ns=interval,
        sample_count=len(materialized),
        expected_min_sample_count=expected_count,
        first_request_monotonic_ns=first_request,
        final_completion_monotonic_ns=final_completion,
        coverage_ns=coverage,
        required_coverage_ns=required_coverage,
        sample_max_gap_ns=sample_max_gap,
        minimum_data_available_bytes=minimum_data,
        minimum_state_available_bytes=minimum_state,
        minimum_available_bytes_if_shared=min(minimum_data, minimum_state),
        critical_worker_observation_count=critical_observations,
        sample_count_valid=len(materialized) >= expected_count,
        coverage_valid=coverage >= required_coverage,
        workers_healthy=critical_observations == 0,
    )


__all__ = [
    "ValidatedWorkerSequences",
    "aggregate_final_worker_snapshots",
    "summarize_resources",
    "summarize_storage_health",
    "validate_worker_rounds",
]
