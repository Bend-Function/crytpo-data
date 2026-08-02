from __future__ import annotations

from decimal import ROUND_CEILING, Decimal
from pathlib import Path
from typing import Any

from crypto_collector.benchmarks.workload import load_workload

WORKLOAD_PATH = Path("benchmarks/workloads/research-default-v1.yaml")


def _ceiling(value: Decimal) -> int:
    return int(value.to_integral_value(rounding=ROUND_CEILING))


def _stream_count(
    stream: Any,
    *,
    multiplier: int,
    duration_seconds: int,
) -> int:
    base_file_count = (
        stream.file_instances if hasattr(stream, "file_instances") else stream.instances
    )
    return _ceiling(
        Decimal(base_file_count)
        * stream.mean_records_per_second
        * multiplier
        * duration_seconds
    )


def _cardinalities(
    *,
    multiplier: int,
    duration_seconds: int,
) -> tuple[int, int, int]:
    workload = load_workload(WORKLOAD_PATH).workload
    record_count = 0
    touched_file_count = 0
    for name, stream in workload.streams.items():
        count = _stream_count(
            stream,
            multiplier=multiplier,
            duration_seconds=duration_seconds,
        )
        identity_count = (
            stream.instances
            if name == "control"
            else (
                stream.file_instances
                if hasattr(stream, "file_instances")
                else stream.instances
            )
            * multiplier
        )
        record_count += count
        touched_file_count += min(count, identity_count)

    declared_file_count = (
        workload.fixed_scope_file_count + multiplier * workload.scalable_file_count
    )
    return record_count, touched_file_count, declared_file_count


def test_research_default_workload_has_exact_multiplier_two_cardinalities() -> None:
    functional = _cardinalities(multiplier=2, duration_seconds=10)
    qualification = _cardinalities(multiplier=2, duration_seconds=600)

    assert functional == (417_677, 3_172, 3_505)
    assert qualification == (25_060_620, 3_505, 3_505)
