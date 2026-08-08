from __future__ import annotations

from collections.abc import Iterable

from crypto_collector.materializer.models import (
    ConnectionGenerationScope,
    ReplayOrderedRecord,
    SourceLocator,
    SourceRecord,
    TimedSourceRecord,
)


class OrderingContractError(ValueError):
    pass


class DuplicateSourceLocator(OrderingContractError):
    def __init__(self, locator: SourceLocator) -> None:
        self.locator = locator
        super().__init__("source locators must be globally unique")


class ReplaySequenceError(OrderingContractError):
    def __init__(
        self,
        *,
        worker_instance_id: str,
        stream_identity: tuple[object, ...],
        previous_writer_sequence: int,
        writer_sequence: int,
    ) -> None:
        self.worker_instance_id = worker_instance_id
        self.stream_identity = stream_identity
        self.previous_writer_sequence = previous_writer_sequence
        self.writer_sequence = writer_sequence
        super().__init__(
            "writer_sequence must strictly increase within one worker run and stream"
        )


def _require_unique_locators(records: Iterable[SourceRecord]) -> None:
    seen: set[SourceLocator] = set()
    for record in records:
        locator = record.locator
        if locator in seen:
            raise DuplicateSourceLocator(locator)
        seen.add(locator)


def canonical_event_sort_key(
    record: TimedSourceRecord,
) -> tuple[int, int, str, int]:
    if type(record) is not TimedSourceRecord:
        raise TypeError("record must be TimedSourceRecord")
    source = record.source
    return (
        record.effective_event_time_ns,
        source.envelope.received_at_ns,
        source.locator.manifest_sha256,
        source.locator.zero_based_record_index,
    )


def canonical_event_order(
    records: Iterable[TimedSourceRecord],
) -> tuple[TimedSourceRecord, ...]:
    materialized = tuple(records)
    if any(type(record) is not TimedSourceRecord for record in materialized):
        raise TypeError("records must contain TimedSourceRecord values")
    _require_unique_locators(record.source for record in materialized)
    return tuple(sorted(materialized, key=canonical_event_sort_key))


def _worker_record_sort_key(record: SourceRecord) -> tuple[int, int, str, int]:
    return (
        record.envelope.monotonic_ns,
        record.envelope.received_at_ns,
        record.locator.manifest_sha256,
        record.locator.zero_based_record_index,
    )


def _stream_identity(record: SourceRecord) -> tuple[object, ...]:
    envelope = record.envelope
    return (
        envelope.exchange,
        envelope.market,
        envelope.instrument_key,
        envelope.logical_stream,
    )


def _validate_worker_sequences(
    worker_instance_id: str,
    records: tuple[SourceRecord, ...],
) -> None:
    previous_by_stream: dict[tuple[object, ...], int] = {}
    for record in records:
        identity = _stream_identity(record)
        writer_sequence = record.envelope.writer_sequence
        previous = previous_by_stream.get(identity)
        if previous is not None and writer_sequence <= previous:
            raise ReplaySequenceError(
                worker_instance_id=worker_instance_id,
                stream_identity=identity,
                previous_writer_sequence=previous,
                writer_sequence=writer_sequence,
            )
        previous_by_stream[identity] = writer_sequence


def _connection_generation_scope(
    record: SourceRecord,
) -> ConnectionGenerationScope | None:
    envelope = record.envelope
    if envelope.connection_id is None:
        return None
    assert envelope.connection_generation is not None
    return ConnectionGenerationScope(
        worker_instance_id=envelope.worker_instance_id,
        connection_id=envelope.connection_id,
        connection_generation=envelope.connection_generation,
    )


def canonical_replay_order(
    records: Iterable[SourceRecord],
) -> tuple[ReplayOrderedRecord, ...]:
    materialized = tuple(records)
    if any(type(record) is not SourceRecord for record in materialized):
        raise TypeError("records must contain SourceRecord values")
    _require_unique_locators(materialized)

    records_by_worker: dict[str, list[SourceRecord]] = {}
    for record in materialized:
        worker_instance_id = record.envelope.worker_instance_id
        records_by_worker.setdefault(worker_instance_id, []).append(record)

    runs = sorted(
        records_by_worker.items(),
        key=lambda item: (
            min(record.envelope.received_at_ns for record in item[1]),
            item[0],
        ),
    )
    ordered: list[ReplayOrderedRecord] = []
    for run_ordinal, (worker_instance_id, worker_records) in enumerate(runs):
        causal_records = tuple(sorted(worker_records, key=_worker_record_sort_key))
        _validate_worker_sequences(worker_instance_id, causal_records)
        for record_ordinal, record in enumerate(causal_records):
            starts_worker_run = record_ordinal == 0
            ordered.append(
                ReplayOrderedRecord(
                    source=record,
                    worker_run_ordinal=run_ordinal,
                    starts_worker_run=starts_worker_run,
                    invalidates_inherited_generation=(
                        starts_worker_run and run_ordinal > 0
                    ),
                    connection_generation_scope=_connection_generation_scope(record),
                )
            )
    return tuple(ordered)


__all__ = [
    "DuplicateSourceLocator",
    "OrderingContractError",
    "ReplaySequenceError",
    "canonical_event_order",
    "canonical_event_sort_key",
    "canonical_replay_order",
]
