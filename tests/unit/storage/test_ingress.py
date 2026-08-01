from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import FrozenInstanceError
from typing import Any

import pytest
from pydantic import ValidationError

import crypto_collector.storage as storage_package
import crypto_collector.storage.ingress as ingress_module
from crypto_collector.config.models import IngressConfig
from crypto_collector.domain.envelope import (
    NativeEventDraft,
    RestMetadata,
    SourceContext,
)
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.storage.durability import WriterCriticalReason
from crypto_collector.storage.ingress import (
    AdmissionContractError,
    CapacityClass,
    RawIngress,
    ResidentBudget,
    SourceContextError,
    StorageScopeError,
)
from crypto_collector.storage.models import (
    AcceptedRecordIdentityV1,
    AdmissionState,
    DurabilityHistogramSeriesV1,
    EnqueueResult,
    EnqueueStatus,
    PublicationState,
    StorageControlAssociationV1,
    StorageControlRequestV1,
    StorageControlTargetV1,
    ValidatedControlDraft,
    WriterLifecycle,
    WriterMetricsSnapshotV1,
    WriterStatus,
    validate_control_draft,
)
from crypto_collector.storage.stats import DURABILITY_BUCKET_UPPER_BOUNDS_NS


class FakeClock:
    def __init__(self, *, wall_ns: int = 1_785_473_918_000_000_000) -> None:
        self.wall_ns = wall_ns
        self.monotonic = 100

    def time_ns(self) -> int:
        return self.wall_ns

    def monotonic_ns(self) -> int:
        value = self.monotonic
        self.monotonic += 1
        return value


def ingress_config(**overrides: object) -> IngressConfig:
    values: dict[str, object] = {
        "shard_max_records": 4,
        "shard_max_bytes": "20000B",
        "worker_max_bytes": "40000B",
        "high_water_ratio": 0.8,
        "control_reserve_records": 1,
        "control_reserve_bytes": "5000B",
    }
    values.update(overrides)
    for field_name in (
        "shard_max_bytes",
        "worker_max_bytes",
        "control_reserve_bytes",
    ):
        value = values[field_name]
        if type(value) is int:
            values[field_name] = f"{value}B"
    return IngressConfig.model_validate(values)


def websocket_source() -> SourceContext:
    return SourceContext(
        connection_id="ws-1",
        connection_generation=1,
        egress_id="direct",
    )


def rest_source() -> SourceContext:
    return SourceContext(
        connection_id=None,
        connection_generation=None,
        egress_id="direct",
    )


def trade_draft(**overrides: Any) -> NativeEventDraft:
    values: dict[str, Any] = {
        "exchange": Exchange.OKX,
        "market": Market.SPOT,
        "instrument_key": "BTC-USDT",
        "wire_symbol": "BTC-USDT",
        "logical_stream": "trade",
        "native_channel": "trades",
        "transport": Transport.WEBSOCKET,
        "event_time_ns": None,
        "event_time_source": None,
        "payload": {"price": "100", "size": "1"},
    }
    values.update(overrides)
    return NativeEventDraft.model_validate(values)


def rest_draft(**overrides: Any) -> NativeEventDraft:
    values: dict[str, Any] = {
        "exchange": Exchange.OKX,
        "market": Market.SPOT,
        "instrument_key": "BTC-USDT",
        "wire_symbol": "BTC-USDT",
        "logical_stream": "ticker",
        "native_channel": "ticker",
        "transport": Transport.REST,
        "event_time_ns": None,
        "event_time_source": None,
        "rest_metadata": RestMetadata(
            request_started_at_ns=1,
            request_ended_at_ns=2,
            method="GET",
            path="/ticker",
            params={},
            status=200,
            attempt=1,
            rate_limit_headers={},
        ),
        "payload": {"last": "100"},
    }
    values.update(overrides)
    return NativeEventDraft.model_validate(values)


def control_draft(**payload_overrides: Any) -> NativeEventDraft:
    payload: dict[str, Any] = {"kind": "gap_detected"}
    payload.update(payload_overrides)
    return NativeEventDraft(
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        event_time_ns=None,
        event_time_source=None,
        payload=payload,
    )


def make_ingress(
    *,
    config: IngressConfig | None = None,
    clock: FakeClock | None = None,
    association_resolver: Callable[
        [ValidatedControlDraft, AcceptedRecordIdentityV1],
        StorageControlAssociationV1 | None,
    ]
    | None = None,
) -> tuple[RawIngress, ResidentBudget, FakeClock]:
    resolved_config = config or ingress_config()
    resolved_clock = clock or FakeClock()
    budget = ResidentBudget.from_config(resolved_config)
    ingress = RawIngress(
        config=resolved_config,
        worker_instance_id="worker-1",
        config_sha256="a" * 64,
        config_generation=7,
        resident_budget=budget,
        clock=resolved_clock,
        control_association_resolver=association_resolver,
    )
    return ingress, budget, resolved_clock


def storage_association_request() -> dict[str, object]:
    return {
        "schema_version": 1,
        "control_event_id": "gap:1",
        "affected_markets": ["spot"],
        "target_logical_identities": [
            {
                "market": "spot",
                "instrument_key": "BTC-USDT",
                "logical_stream": "trade",
            }
        ],
    }


def resolve_test_association(
    control: ValidatedControlDraft,
    identity: AcceptedRecordIdentityV1,
) -> StorageControlAssociationV1 | None:
    request = control.association_request
    if request is None:
        return None
    return StorageControlAssociationV1(
        control_kind=control.control_kind,
        control_event_id=request.control_event_id,
        targets=(
            StorageControlTargetV1(
                generation_id="generation-1",
                data_relative_path=("raw/okx/spot/BTC-USDT/trade/part.jsonl.zst"),
            ),
        ),
        acceptance_ordinal=identity.acceptance_ordinal,
        config_generation=identity.config_generation,
    )


def test_successful_nonblocking_insert_defines_acceptance() -> None:
    ingress, budget, clock = make_ingress()

    result = ingress.try_accept(
        trade_draft(),
        source=websocket_source(),
        shard="trade-0",
    )

    assert result.status is EnqueueStatus.ACCEPTED
    assert result.accepted
    assert result.record is not None
    assert result.record_identity is not None
    assert result.record.envelope.received_at_ns == clock.wall_ns
    assert result.record.envelope.monotonic_ns == 100
    assert result.record.accepted_monotonic_ns == 100
    assert result.record.envelope.worker_instance_id == "worker-1"
    assert result.record.envelope.config_sha256 == "a" * 64
    assert result.record.envelope.connection_id == "ws-1"
    assert result.record_identity.acceptance_ordinal == 0
    assert result.record_identity.config_generation == 7
    assert budget.resident_bytes == len(result.record.encoded_jsonl)
    assert ingress.queued_bytes("trade-0") == len(result.record.encoded_jsonl)


def test_record_overflow_never_consumes_sequence_or_acceptance_ordinal() -> None:
    config = ingress_config(shard_max_records=1)
    ingress, budget, _clock = make_ingress(config=config)
    first = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )

    rejected = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )

    assert rejected == EnqueueResult(
        status=EnqueueStatus.OVERFLOW,
        record=None,
        record_identity=None,
    )
    assert ingress.accepted_count == 1
    assert budget.resident_record_count == 1
    drained = ingress.drain_one("trade-0")
    assert drained == first
    second = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert second.record is not None
    assert second.record_identity is not None
    assert second.record.envelope.writer_sequence == 1
    assert second.record_identity.acceptance_ordinal == 1


def test_writer_sequence_is_per_logical_stream_identity() -> None:
    ingress, _budget, _clock = make_ingress()
    first = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    other_stream = ingress.try_accept(
        trade_draft(logical_stream="bbo", native_channel="bbo"),
        source=websocket_source(),
        shard="bbo-0",
    )
    other_market = ingress.try_accept(
        trade_draft(
            market=Market.PERPETUAL,
            instrument_key="BTC-USDT-SWAP",
            wire_symbol="BTC-USDT-SWAP",
        ),
        source=websocket_source(),
        shard="trade-perpetual-0",
    )

    assert first.record is not None
    assert other_stream.record is not None
    assert other_market.record is not None
    assert first.record.envelope.writer_sequence == 0
    assert other_stream.record.envelope.writer_sequence == 0
    assert other_market.record.envelope.writer_sequence == 0
    assert tuple(
        item.record_identity.acceptance_ordinal
        for item in (first, other_stream, other_market)
        if item.record_identity is not None
    ) == (0, 1, 2)


def test_config_replacement_preserves_sequences_ordinals_and_counters() -> None:
    config = ingress_config(shard_max_records=1)
    ingress, budget, _clock = make_ingress(config=config)
    first = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    overflow = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert overflow.status is EnqueueStatus.OVERFLOW
    assert first.record_identity is not None
    assert ingress.drain_one("trade-0") == first
    budget.release(first.record_identity)

    replacement = ingress.replacement_for_config(
        config_sha256="b" * 64,
        config_generation=8,
    )
    second = replacement.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )

    assert second.record is not None
    assert second.record_identity is not None
    assert second.record.envelope.config_sha256 == "b" * 64
    assert second.record.envelope.writer_sequence == 1
    assert second.record_identity.acceptance_ordinal == 1
    assert second.record_identity.config_generation == 8
    snapshot = replacement.snapshot_for_test()
    assert snapshot.accepting
    assert snapshot.accepted_count == 2
    assert snapshot.normal_overflow_count == 1
    assert not ingress.snapshot_for_test().accepting

    retired = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert retired.status is EnqueueStatus.NOT_ACCEPTING
    assert retired.record is retired.record_identity is None


def test_failed_config_replacement_leaves_current_ingress_usable() -> None:
    ingress, budget, _clock = make_ingress()
    first = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert first.record_identity is not None
    before = ingress.snapshot_for_test()

    with pytest.raises(AdmissionContractError, match="quiescent"):
        ingress.replacement_for_config(
            config_sha256="b" * 64,
            config_generation=8,
        )

    assert ingress.snapshot_for_test() == before
    assert ingress.drain_one("trade-0") == first
    budget.release(first.record_identity)
    second = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert second.record is not None
    assert second.record.envelope.writer_sequence == 1


def test_config_replacement_requires_a_strictly_newer_generation() -> None:
    ingress, _budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()

    with pytest.raises(ValueError, match="strictly greater"):
        ingress.replacement_for_config(
            config_sha256="b" * 64,
            config_generation=7,
        )

    assert ingress.snapshot_for_test() == before


def test_byte_overflow_uses_actual_encoded_jsonl_size() -> None:
    probe, _budget, _clock = make_ingress()
    accepted = probe.try_accept(
        trade_draft(payload={"blob": "x" * 1_000}),
        source=websocket_source(),
        shard="trade-0",
    )
    assert accepted.record is not None
    encoded_size = len(accepted.record.encoded_jsonl)
    config = ingress_config(
        shard_max_bytes=encoded_size - 1,
        worker_max_bytes=encoded_size + 5_000,
        control_reserve_bytes=1,
    )
    ingress, budget, _clock = make_ingress(config=config)

    result = ingress.try_accept(
        trade_draft(payload={"blob": "x" * 1_000}),
        source=websocket_source(),
        shard="trade-0",
    )

    assert result.status is EnqueueStatus.OVERFLOW
    assert result.record is result.record_identity is None
    assert budget.resident_bytes == 0
    assert ingress.queued_bytes("trade-0") == 0


def test_drain_frees_queue_capacity_but_not_resident_budget() -> None:
    ingress, budget, _clock = make_ingress()
    accepted = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    assert accepted.record_identity is not None
    charged = budget.resident_bytes

    assert ingress.drain_one("trade-0") == accepted

    assert ingress.queued_bytes("trade-0") == 0
    assert budget.resident_bytes == charged
    budget.release(accepted.record_identity)
    assert budget.resident_bytes == 0
    with pytest.raises(KeyError, match="resident charge"):
        budget.release(accepted.record_identity)


def test_normal_records_cannot_consume_control_byte_reserve() -> None:
    config = ingress_config(
        shard_max_records=20,
        shard_max_bytes=30_000,
        worker_max_bytes=30_000,
        control_reserve_bytes=5_000,
    )
    ingress, budget, _clock = make_ingress(config=config)
    last = None
    while True:
        last = ingress.try_accept(
            trade_draft(payload={"blob": "x" * 3_000}),
            source=websocket_source(),
            shard="trade-0",
        )
        if not last.accepted:
            break

    assert last.status is EnqueueStatus.OVERFLOW
    assert budget.normal_resident_bytes <= 25_000
    control = ingress.try_accept(
        control_draft(), source=SourceContext.internal(), shard="_control"
    )
    assert control.accepted
    assert budget.control_resident_records == 1


def test_control_overflow_is_distinct_and_does_not_consume_identity() -> None:
    config = ingress_config(shard_max_records=1, control_reserve_records=1)
    ingress, budget, _clock = make_ingress(config=config)
    first = ingress.try_accept(
        control_draft(), source=SourceContext.internal(), shard="_control"
    )
    before = ingress.snapshot_for_test()

    rejected = ingress.try_accept(
        control_draft(), source=SourceContext.internal(), shard="_control"
    )

    assert first.accepted
    assert rejected.status is EnqueueStatus.CONTROL_OVERFLOW
    assert rejected.record is rejected.record_identity is None
    after = ingress.snapshot_for_test()
    assert after.accepted_count == before.accepted_count
    assert after.acceptance_ordinal_next == before.acceptance_ordinal_next
    assert after.next_sequences == before.next_sequences
    assert after.queues == before.queues
    assert after.resident_budget == before.resident_budget
    assert after.control_overflow_count == before.control_overflow_count + 1
    assert budget.control_resident_records == 1


def test_drained_control_rows_still_reach_the_global_resident_limit() -> None:
    config = ingress_config(
        shard_max_records=2,
        shard_max_bytes=20_000,
        worker_max_bytes=20_000,
        control_reserve_bytes=5_000,
    )
    ingress, budget, _clock = make_ingress(config=config)
    accepted = []

    for index in range(20):
        result = ingress.try_accept(
            control_draft(sequence=index, blob="x" * 2_000),
            source=SourceContext.internal(),
            shard="_control",
        )
        if not result.accepted:
            break
        accepted.append(result)
        assert ingress.drain_one("_control") == result
    else:
        pytest.fail("control admission did not reach its resident byte limit")

    assert result.status is EnqueueStatus.CONTROL_OVERFLOW
    assert ingress.queued_records("_control") == 0
    assert budget.control_resident_records == len(accepted)
    assert budget.resident_bytes <= config.worker_max_bytes
    assert result.record is result.record_identity is None


def test_unexpected_put_nowait_full_rolls_back_every_candidate_side_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class AlwaysFullQueue(asyncio.Queue[EnqueueResult]):
        def put_nowait(self, item: EnqueueResult) -> None:
            raise asyncio.QueueFull

    ingress, budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()
    with monkeypatch.context() as context:
        context.setattr(ingress_module.asyncio, "Queue", AlwaysFullQueue)
        rejected = ingress.try_accept(
            trade_draft(),
            source=websocket_source(),
            shard="trade-0",
        )

    assert rejected.status is EnqueueStatus.OVERFLOW
    after = ingress.snapshot_for_test()
    assert after.accepted_count == before.accepted_count
    assert after.acceptance_ordinal_next == before.acceptance_ordinal_next
    assert after.next_sequences == before.next_sequences
    assert after.queues == before.queues
    assert after.resident_budget == before.resident_budget
    assert after.normal_overflow_count == before.normal_overflow_count + 1
    assert budget.resident_record_count == 0

    accepted = ingress.try_accept(
        trade_draft(),
        source=websocket_source(),
        shard="trade-0",
    )
    assert accepted.record_identity is not None
    assert accepted.record_identity.acceptance_ordinal == 0
    assert accepted.record is not None
    assert accepted.record.envelope.writer_sequence == 0


class InjectedQueueInterruption(BaseException):
    pass


@pytest.mark.parametrize("failure_type", [RuntimeError, InjectedQueueInterruption])
def test_unexpected_put_nowait_failure_rolls_back_before_propagating(
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    class FailingQueue(asyncio.Queue[EnqueueResult]):
        def put_nowait(self, item: EnqueueResult) -> None:
            raise failure_type("injected queue failure")

    ingress, budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()
    with monkeypatch.context() as context:
        context.setattr(ingress_module.asyncio, "Queue", FailingQueue)
        with pytest.raises(failure_type, match="injected queue failure"):
            ingress.try_accept(
                trade_draft(),
                source=websocket_source(),
                shard="trade-0",
            )

    assert ingress.snapshot_for_test() == before
    assert budget.resident_record_count == 0
    accepted = ingress.try_accept(
        trade_draft(),
        source=websocket_source(),
        shard="trade-0",
    )
    assert accepted.record_identity is not None
    assert accepted.record_identity.acceptance_ordinal == 0
    assert accepted.record is not None
    assert accepted.record.envelope.writer_sequence == 0


@pytest.mark.parametrize("failure_type", [RuntimeError, InjectedQueueInterruption])
def test_queue_construction_failure_rolls_back_before_propagating(
    monkeypatch: pytest.MonkeyPatch,
    failure_type: type[BaseException],
) -> None:
    class FailingQueue(asyncio.Queue[EnqueueResult]):
        def __init__(self, *args: object, **kwargs: object) -> None:
            raise failure_type("injected queue construction failure")

    ingress, budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()
    with monkeypatch.context() as context:
        context.setattr(ingress_module.asyncio, "Queue", FailingQueue)
        with pytest.raises(failure_type, match="queue construction failure"):
            ingress.try_accept(
                trade_draft(),
                source=websocket_source(),
                shard="trade-0",
            )

    assert ingress.snapshot_for_test() == before
    assert budget.resident_record_count == 0


@pytest.mark.parametrize(
    ("draft", "source", "shard"),
    [
        (control_draft(), SourceContext.internal(), "trade-0"),
        (trade_draft(), websocket_source(), "_control"),
    ],
)
def test_capacity_class_and_shard_mismatch_is_atomic(
    draft: NativeEventDraft,
    source: SourceContext,
    shard: str,
) -> None:
    ingress, _budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()

    with pytest.raises(AdmissionContractError):
        ingress.try_accept(draft, source=source, shard=shard)

    assert ingress.snapshot_for_test() == before


@pytest.mark.parametrize(
    ("draft", "source"),
    [
        (trade_draft(), rest_source()),
        (rest_draft(), websocket_source()),
        (control_draft(), rest_source()),
    ],
)
def test_draft_source_scope_mismatch_is_rejected_without_acceptance(
    draft: NativeEventDraft,
    source: SourceContext,
) -> None:
    ingress, _budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()
    shard = "_control" if draft.logical_stream == "_control" else "test-0"

    with pytest.raises(SourceContextError):
        ingress.try_accept(draft, source=source, shard=shard)

    assert ingress.snapshot_for_test() == before


def test_invalid_control_scope_is_rejected_not_downgraded() -> None:
    ingress, _budget, _clock = make_ingress()
    invalid = NativeEventDraft(
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="_control",
        native_channel="control",
        transport=Transport.INTERNAL,
        event_time_ns=None,
        event_time_source=None,
        payload={"kind": "gap_detected"},
    )
    before = ingress.snapshot_for_test()

    with pytest.raises(StorageScopeError):
        ingress.try_accept(
            invalid,
            source=SourceContext.internal(),
            shard="_control",
        )

    assert ingress.snapshot_for_test() == before


def test_high_water_is_based_on_resident_utilization() -> None:
    config = ingress_config(high_water_ratio=0.01)
    ingress, _budget, _clock = make_ingress(config=config)

    result = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )

    assert result.status is EnqueueStatus.ACCEPTED_HIGH_WATER


def test_resident_budget_requires_matching_config() -> None:
    config = ingress_config()
    mismatched = ResidentBudget(worker_max_bytes=40_001, control_reserve_bytes=5_000)

    with pytest.raises(ValueError, match="resident budget"):
        RawIngress(
            config=config,
            worker_instance_id="worker-1",
            config_sha256="a" * 64,
            config_generation=0,
            resident_budget=mismatched,
            clock=FakeClock(),
        )


def test_enqueue_result_is_frozen_and_enforces_status_payload_agreement() -> None:
    result = EnqueueResult(
        status=EnqueueStatus.OVERFLOW,
        record=None,
        record_identity=None,
    )
    with pytest.raises(FrozenInstanceError):
        result.status = EnqueueStatus.ACCEPTED  # type: ignore[misc]

    ingress, _budget, _clock = make_ingress()
    accepted = ingress.try_accept(
        trade_draft(), source=websocket_source(), shard="trade-0"
    )
    with pytest.raises(ValueError, match="accepted status"):
        EnqueueResult(
            status=EnqueueStatus.ACCEPTED,
            record=accepted.record,
            record_identity=None,
        )


def test_capacity_class_values_are_stable() -> None:
    assert CapacityClass.NORMAL.value == "normal"
    assert CapacityClass.CONTROL.value == "control"


def test_task4_public_types_are_reexported_from_storage_package() -> None:
    assert storage_package.RawIngress is RawIngress
    assert storage_package.ResidentBudget is ResidentBudget
    assert storage_package.EnqueueResult is EnqueueResult
    assert storage_package.ExchangeWriterLock.__name__ == "ExchangeWriterLock"
    assert storage_package.WriterMetricsSnapshotV1 is WriterMetricsSnapshotV1


def test_control_association_request_is_strictly_parsed_from_json_domain() -> None:
    draft = control_draft(storage_association=storage_association_request())

    validated = validate_control_draft(draft)

    assert validated.draft is draft
    assert validated.control_kind == "gap_detected"
    assert validated.association_request is not None
    assert validated.association_request.affected_markets == (Market.SPOT,)
    assert validated.association_request.target_logical_identities[0].market is (
        Market.SPOT
    )


def test_control_association_is_resolved_and_charged_before_acceptance() -> None:
    ingress, budget, _clock = make_ingress(
        association_resolver=resolve_test_association
    )

    result = ingress.try_accept(
        control_draft(storage_association=storage_association_request()),
        source=SourceContext.internal(),
        shard="_control",
    )

    assert result.accepted
    assert result.record is not None
    assert result.record_identity is not None
    assert ingress.snapshot_for_test().pending_control_association_count == 1
    association = ingress.take_control_association(result.record_identity)
    assert association is not None
    expected_charge = len(result.record.encoded_jsonl) + len(
        association.canonical_bytes()
    )
    assert budget.charge_bytes(result.record_identity) == expected_charge
    assert budget.control_resident_bytes == expected_charge
    assert ingress.queued_bytes("_control") == expected_charge
    assert ingress.snapshot_for_test().pending_control_association_count == 0
    assert ingress.take_control_association(result.record_identity) is None


@pytest.mark.parametrize(
    ("affected_markets", "logical_target", "data_relative_path"),
    [
        (
            ["spot"],
            {
                "market": "spot",
                "instrument_key": None,
                "logical_stream": "status",
            },
            "raw/okx/spot/_market/status/part.jsonl.zst",
        ),
        (
            [],
            {
                "market": None,
                "instrument_key": None,
                "logical_stream": "_control",
            },
            "raw/okx/_control/part.jsonl.zst",
        ),
    ],
)
def test_control_association_path_mapping_supports_every_storage_scope(
    affected_markets: list[str],
    logical_target: dict[str, object],
    data_relative_path: str,
) -> None:
    request = storage_association_request()
    request["affected_markets"] = affected_markets
    request["target_logical_identities"] = [logical_target]

    def scoped_resolver(
        control: ValidatedControlDraft,
        identity: AcceptedRecordIdentityV1,
    ) -> StorageControlAssociationV1:
        association_request = control.association_request
        assert association_request is not None
        return StorageControlAssociationV1(
            control_kind=control.control_kind,
            control_event_id=association_request.control_event_id,
            targets=(
                StorageControlTargetV1(
                    generation_id="generation-1",
                    data_relative_path=data_relative_path,
                ),
            ),
            acceptance_ordinal=identity.acceptance_ordinal,
            config_generation=identity.config_generation,
        )

    ingress, _budget, _clock = make_ingress(association_resolver=scoped_resolver)

    result = ingress.try_accept(
        control_draft(storage_association=request),
        source=SourceContext.internal(),
        shard="_control",
    )

    assert result.accepted


def test_control_request_without_association_resolver_is_rejected_atomically() -> None:
    ingress, _budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()

    with pytest.raises(AdmissionContractError, match="association resolver"):
        ingress.try_accept(
            control_draft(storage_association=storage_association_request()),
            source=SourceContext.internal(),
            shard="_control",
        )

    assert ingress.snapshot_for_test() == before


def test_association_bytes_can_cause_control_overflow_without_an_identity() -> None:
    probe, _probe_budget, _clock = make_ingress(
        association_resolver=resolve_test_association
    )
    accepted = probe.try_accept(
        control_draft(storage_association=storage_association_request()),
        source=SourceContext.internal(),
        shard="_control",
    )
    assert accepted.record is not None
    assert accepted.record_identity is not None
    association = probe.take_control_association(accepted.record_identity)
    assert association is not None
    encoded_bytes = len(accepted.record.encoded_jsonl)
    total_charge = encoded_bytes + len(association.canonical_bytes())
    assert encoded_bytes < total_charge
    config = ingress_config(
        shard_max_bytes=total_charge - 1,
        worker_max_bytes=total_charge - 1,
        control_reserve_bytes=1,
    )
    ingress, budget, _clock = make_ingress(
        config=config,
        association_resolver=resolve_test_association,
    )
    before = ingress.snapshot_for_test()

    rejected = ingress.try_accept(
        control_draft(storage_association=storage_association_request()),
        source=SourceContext.internal(),
        shard="_control",
    )

    assert rejected.status is EnqueueStatus.CONTROL_OVERFLOW
    assert rejected.record is rejected.record_identity is None
    after = ingress.snapshot_for_test()
    assert after.accepted_count == before.accepted_count
    assert after.acceptance_ordinal_next == before.acceptance_ordinal_next
    assert after.next_sequences == before.next_sequences
    assert after.resident_budget == before.resident_budget
    assert after.control_overflow_count == before.control_overflow_count + 1
    assert budget.resident_bytes == 0


@pytest.mark.parametrize(
    "mismatch",
    ["control_kind", "control_event_id", "acceptance_ordinal", "config_generation"],
)
def test_mismatched_resolved_association_is_rejected_atomically(
    mismatch: str,
) -> None:
    def mismatched_resolver(
        control: ValidatedControlDraft,
        identity: AcceptedRecordIdentityV1,
    ) -> StorageControlAssociationV1:
        request = control.association_request
        assert request is not None
        values: dict[str, object] = {
            "control_kind": control.control_kind,
            "control_event_id": request.control_event_id,
            "targets": (
                StorageControlTargetV1(
                    generation_id="generation-1",
                    data_relative_path=("raw/okx/spot/BTC-USDT/trade/part.jsonl.zst"),
                ),
            ),
            "acceptance_ordinal": identity.acceptance_ordinal,
            "config_generation": identity.config_generation,
        }
        values[mismatch] = {
            "control_kind": "wrong_kind",
            "control_event_id": "wrong:event",
            "acceptance_ordinal": identity.acceptance_ordinal + 1,
            "config_generation": identity.config_generation + 1,
        }[mismatch]
        return StorageControlAssociationV1.model_validate(values)

    ingress, budget, _clock = make_ingress(association_resolver=mismatched_resolver)
    before = ingress.snapshot_for_test()

    with pytest.raises(AdmissionContractError, match="association"):
        ingress.try_accept(
            control_draft(storage_association=storage_association_request()),
            source=SourceContext.internal(),
            shard="_control",
        )

    assert ingress.snapshot_for_test() == before
    assert budget.resident_bytes == 0


def test_resolved_association_must_cover_every_requested_target() -> None:
    request = storage_association_request()
    request["target_logical_identities"] = [
        {
            "market": "spot",
            "instrument_key": "BTC-USDT",
            "logical_stream": "trade",
        },
        {
            "market": "spot",
            "instrument_key": "ETH-USDT",
            "logical_stream": "trade",
        },
    ]

    def incomplete_resolver(
        control: ValidatedControlDraft,
        identity: AcceptedRecordIdentityV1,
    ) -> StorageControlAssociationV1:
        association_request = control.association_request
        assert association_request is not None
        return StorageControlAssociationV1(
            control_kind=control.control_kind,
            control_event_id=association_request.control_event_id,
            targets=(
                StorageControlTargetV1(
                    generation_id="generation-1",
                    data_relative_path=("raw/okx/spot/BTC-USDT/trade/part.jsonl.zst"),
                ),
            ),
            acceptance_ordinal=identity.acceptance_ordinal,
            config_generation=identity.config_generation,
        )

    ingress, budget, _clock = make_ingress(association_resolver=incomplete_resolver)
    before = ingress.snapshot_for_test()

    with pytest.raises(AdmissionContractError, match="requested target"):
        ingress.try_accept(
            control_draft(storage_association=request),
            source=SourceContext.internal(),
            shard="_control",
        )

    assert ingress.snapshot_for_test() == before
    assert budget.resident_bytes == 0


def test_resolved_association_must_match_requested_logical_targets() -> None:
    request = storage_association_request()
    request["target_logical_identities"] = [
        {
            "market": "spot",
            "instrument_key": "BTC-USDT",
            "logical_stream": "trade",
        },
        {
            "market": "spot",
            "instrument_key": "ETH-USDT",
            "logical_stream": "trade",
        },
    ]

    def wrong_target_resolver(
        control: ValidatedControlDraft,
        identity: AcceptedRecordIdentityV1,
    ) -> StorageControlAssociationV1:
        association_request = control.association_request
        assert association_request is not None
        return StorageControlAssociationV1(
            control_kind=control.control_kind,
            control_event_id=association_request.control_event_id,
            targets=(
                StorageControlTargetV1(
                    generation_id="generation-1",
                    data_relative_path=("raw/okx/spot/DOGE-USDT/trade/part.jsonl.zst"),
                ),
                StorageControlTargetV1(
                    generation_id="generation-2",
                    data_relative_path=("raw/okx/spot/SOL-USDT/trade/part.jsonl.zst"),
                ),
            ),
            acceptance_ordinal=identity.acceptance_ordinal,
            config_generation=identity.config_generation,
        )

    ingress, budget, _clock = make_ingress(association_resolver=wrong_target_resolver)
    before = ingress.snapshot_for_test()

    with pytest.raises(AdmissionContractError, match="logical targets"):
        ingress.try_accept(
            control_draft(storage_association=request),
            source=SourceContext.internal(),
            shard="_control",
        )

    assert ingress.snapshot_for_test() == before
    assert budget.resident_bytes == 0


@pytest.mark.parametrize(
    "association",
    [
        {
            "schema_version": 1,
            "control_event_id": "gap:1",
            "affected_markets": [],
        },
        {
            "schema_version": 1,
            "control_event_id": "gap:1",
            "affected_markets": [],
            "target_logical_identities": [],
            "unexpected": True,
        },
        {
            "schema_version": 1,
            "control_event_id": "gap:1",
            "affected_markets": ["perpetual", "spot"],
            "target_logical_identities": [
                {
                    "market": "spot",
                    "instrument_key": "BTC-USDT",
                    "logical_stream": "trade",
                },
                {
                    "market": "perpetual",
                    "instrument_key": "BTC-USDT-SWAP",
                    "logical_stream": "trade",
                },
            ],
        },
    ],
)
def test_invalid_control_association_never_receives_control_capacity(
    association: dict[str, object],
) -> None:
    ingress, _budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()

    with pytest.raises(StorageScopeError):
        ingress.try_accept(
            control_draft(storage_association=association),
            source=SourceContext.internal(),
            shard="_control",
        )

    assert ingress.snapshot_for_test() == before


@pytest.mark.parametrize(
    "association",
    [
        None,
        {
            "schema_version": True,
            "control_event_id": "gap:1",
            "affected_markets": [],
            "target_logical_identities": [
                {
                    "market": None,
                    "instrument_key": None,
                    "logical_stream": "_control",
                }
            ],
        },
        {
            "schema_version": 1,
            "control_event_id": "gap:1",
            "affected_markets": ["spot"],
            "target_logical_identities": [
                {
                    "market": "spot",
                    "instrument_key": "BTC-USDT",
                }
            ],
        },
        {
            "schema_version": 1,
            "control_event_id": "gap:1",
            "affected_markets": ["spot"],
            "target_logical_identities": [
                {
                    "market": "spot",
                    "instrument_key": "BTC-USDT",
                    "logical_stream": "trade",
                    "generation_id": "producer-must-not-select-this",
                }
            ],
        },
    ],
)
def test_reserved_control_association_rejects_null_or_noncanonical_shape(
    association: object,
) -> None:
    ingress, _budget, _clock = make_ingress()
    before = ingress.snapshot_for_test()

    with pytest.raises(StorageScopeError):
        ingress.try_accept(
            control_draft(storage_association=association),
            source=SourceContext.internal(),
            shard="_control",
        )

    assert ingress.snapshot_for_test() == before


def test_versioned_storage_models_reject_bool_schema_versions() -> None:
    target = StorageControlTargetV1(
        generation_id="generation-1",
        data_relative_path="raw/okx/_control/part.jsonl.zst",
    )
    logical_target = {
        "market": None,
        "instrument_key": None,
        "logical_stream": "_control",
    }

    with pytest.raises(ValidationError, match="schema_version"):
        StorageControlRequestV1.model_validate(
            {
                "schema_version": True,
                "control_event_id": "gap:1",
                "affected_markets": (),
                "target_logical_identities": (logical_target,),
            }
        )
    with pytest.raises(ValidationError, match="schema_version"):
        StorageControlAssociationV1(
            schema_version=True,  # type: ignore[arg-type]
            control_kind="gap_detected",
            control_event_id="gap:1",
            targets=(target,),
            acceptance_ordinal=0,
            config_generation=0,
        )
    with pytest.raises(ValidationError, match="schema_version"):
        AcceptedRecordIdentityV1(
            schema_version=True,  # type: ignore[arg-type]
            exchange=Exchange.OKX,
            market=Market.SPOT,
            instrument_key="BTC-USDT",
            logical_stream="trade",
            worker_instance_id="worker-1",
            writer_sequence=0,
            acceptance_ordinal=0,
            config_sha256="a" * 64,
            config_generation=0,
        )


def test_control_association_canonical_bytes_are_ordered_and_newline_terminated() -> (
    None
):
    association = StorageControlAssociationV1(
        control_kind="gap_detected",
        control_event_id="gap:1",
        targets=(
            StorageControlTargetV1(
                generation_id="generation-1",
                data_relative_path="raw/okx/spot/BTC-USDT/trade/part.jsonl.zst",
            ),
        ),
        acceptance_ordinal=9,
        config_generation=7,
    )

    encoded = association.canonical_bytes()

    assert encoded == (
        b'{"schema_version":1,"control_kind":"gap_detected",'
        b'"control_event_id":"gap:1","targets":[{"generation_id":'
        b'"generation-1","data_relative_path":"raw/okx/spot/BTC-USDT/'
        b'trade/part.jsonl.zst"}],"acceptance_ordinal":9,'
        b'"config_generation":7}\n'
    )
    assert list(decode_json(encoded)) == [
        "schema_version",
        "control_kind",
        "control_event_id",
        "targets",
        "acceptance_ordinal",
        "config_generation",
    ]
    with pytest.raises(ValidationError, match="normalized"):
        StorageControlTargetV1(
            generation_id="generation-1",
            data_relative_path="raw/okx/../escape",
        )


@pytest.mark.parametrize(
    "data_relative_path",
    [
        "raw/okx/spot/BTC-USDT/trade/part.jsonl.zst.partial",
        "raw/okx/spot/BTC-USDT/trade/part.manifest.json",
        "quarantine/okx/spot/BTC-USDT/trade/part.jsonl.zst",
    ],
)
def test_control_target_requires_a_final_raw_data_path(
    data_relative_path: str,
) -> None:
    with pytest.raises(ValidationError, match="final raw data path"):
        StorageControlTargetV1(
            generation_id="generation-1",
            data_relative_path=data_relative_path,
        )


def make_writer_status(**overrides: object) -> WriterStatus:
    values: dict[str, object] = {
        "lifecycle": WriterLifecycle.ACCEPTING,
        "admission_state": AdmissionState.OPEN,
        "publication_state": PublicationState.IDLE,
        "accepting": True,
        "incomplete": False,
        "incomplete_reason": None,
        "critical_reason": None,
        "queued_records": 1,
        "queued_bytes": 10,
        "buffered_records": 1,
        "buffered_bytes": 20,
        "in_flight_records": 1,
        "in_flight_bytes": 30,
        "active_logical_generation_count": 1,
        "retiring_generation_count": 0,
        "open_file_descriptor_count": 1,
        "dirty_file_count": 1,
        "sync_inflight": 1,
        "oldest_unpersisted_age_ns": 100,
        "accepted_record_count": 5,
        "durable_record_count": 2,
        "unpersisted_record_count": 3,
        "uncertain_record_count": 0,
    }
    values.update(overrides)
    return WriterStatus(**values)  # type: ignore[arg-type]


def test_writer_status_enforces_lifecycle_and_record_conservation() -> None:
    status = make_writer_status()
    assert status.accepted_record_count == 5

    with pytest.raises(ValueError, match="admission_state"):
        make_writer_status(accepting=False)
    with pytest.raises(ValueError, match="record conservation"):
        make_writer_status(accepted_record_count=6)
    with pytest.raises(ValueError, match="stage conservation"):
        make_writer_status(unpersisted_record_count=2, accepted_record_count=4)
    critical = make_writer_status(
        lifecycle=WriterLifecycle.CRITICAL,
        admission_state=AdmissionState.CLOSED,
        accepting=False,
        critical_reason=WriterCriticalReason.WRITE_FAILED,
    )
    assert critical.critical_reason is WriterCriticalReason.WRITE_FAILED


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {
                "lifecycle": WriterLifecycle.CLOSED,
                "admission_state": AdmissionState.OPEN,
                "accepting": True,
            },
            "lifecycle admission",
        ),
        ({"queued_bytes": 0}, "queued record/byte"),
        ({"oldest_unpersisted_age_ns": None}, "oldest_unpersisted_age_ns"),
    ],
)
def test_writer_status_rejects_impossible_state_combinations(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        make_writer_status(**overrides)


def closed_writer_status(**overrides: object) -> WriterStatus:
    values: dict[str, object] = {
        "lifecycle": WriterLifecycle.CLOSED,
        "admission_state": AdmissionState.CLOSED,
        "publication_state": PublicationState.IDLE,
        "accepting": False,
        "queued_records": 0,
        "queued_bytes": 0,
        "buffered_records": 0,
        "buffered_bytes": 0,
        "in_flight_records": 0,
        "in_flight_bytes": 0,
        "active_logical_generation_count": 0,
        "retiring_generation_count": 0,
        "open_file_descriptor_count": 0,
        "dirty_file_count": 0,
        "sync_inflight": 0,
        "oldest_unpersisted_age_ns": None,
        "accepted_record_count": 2,
        "durable_record_count": 2,
        "unpersisted_record_count": 0,
        "uncertain_record_count": 0,
    }
    values.update(overrides)
    return make_writer_status(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"publication_state": PublicationState.PUBLISHING},
        {"active_logical_generation_count": 1},
        {"retiring_generation_count": 1},
        {"open_file_descriptor_count": 1},
        {"dirty_file_count": 1},
        {"sync_inflight": 1},
        {"accepted_record_count": 3, "uncertain_record_count": 1},
        {
            "accepted_record_count": 3,
            "unpersisted_record_count": 1,
            "queued_records": 1,
            "queued_bytes": 1,
            "oldest_unpersisted_age_ns": 0,
        },
    ],
)
def test_closed_writer_status_requires_a_fully_released_terminal_state(
    overrides: dict[str, object],
) -> None:
    assert closed_writer_status().lifecycle is WriterLifecycle.CLOSED
    with pytest.raises(ValueError, match="closed writer terminal state"):
        closed_writer_status(**overrides)


def make_metrics_snapshot(**overrides: object) -> WriterMetricsSnapshotV1:
    empty_buckets = (0,) * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    values: dict[str, object] = {
        "observed_monotonic_ns": 1,
        "exchange": Exchange.OKX,
        "worker_instance_id": "worker-1",
        "config_sha256": "a" * 64,
        "config_generation": 0,
        "lifecycle": WriterLifecycle.STARTING,
        "admission_state": AdmissionState.CLOSED,
        "publication_state": PublicationState.IDLE,
        "critical_reason": None,
        "acceptance_ordinal_high_water": None,
        "accepted_record_count": 0,
        "durable_record_count": 0,
        "unpersisted_record_count": 0,
        "uncertain_record_count": 0,
        "queued_records": 0,
        "queued_bytes": 0,
        "buffered_records": 0,
        "buffered_bytes": 0,
        "in_flight_records": 0,
        "in_flight_bytes": 0,
        "resident_record_bytes": 0,
        "resident_control_records": 0,
        "resident_control_bytes": 0,
        "oldest_unpersisted_age_ns": None,
        "enqueue_high_water_count": 0,
        "normal_overflow_count": 0,
        "control_overflow_count": 0,
        "not_accepting_count": 0,
        "active_logical_generation_count": 0,
        "retiring_generation_count": 0,
        "open_file_descriptor_count": 0,
        "sync_inflight": 0,
        "durability_histogram_schema_version": 1,
        "durability_bucket_counts": empty_buckets,
        "durability_sample_count": 0,
        "durability_lag_p50_ns": None,
        "durability_lag_p95_ns": None,
        "durability_lag_p99_ns": None,
        "durability_lag_max_ns": None,
        "durability_histogram_series": (),
        "sync_count": 0,
        "sync_duration_total_ns": 0,
        "sync_duration_max_ns": 0,
        "slo_breach_count": 0,
        "write_failure_count": 0,
        "sync_failure_count": 0,
        "publication_failure_count": 0,
    }
    values.update(overrides)
    return WriterMetricsSnapshotV1.model_validate(values)


def test_metrics_snapshot_validates_aggregate_series_and_canonical_bytes() -> None:
    buckets = [0] * len(DURABILITY_BUCKET_UPPER_BOUNDS_NS)
    buckets[1] = 1
    series = DurabilityHistogramSeriesV1(
        exchange=Exchange.OKX,
        market=Market.SPOT,
        logical_stream="trade",
        bucket_counts=tuple(buckets),
        sample_count=1,
        lag_p50_ns=100_000,
        lag_p95_ns=100_000,
        lag_p99_ns=100_000,
        lag_max_ns=100_000,
    )
    snapshot = make_metrics_snapshot(
        acceptance_ordinal_high_water=0,
        accepted_record_count=1,
        durable_record_count=1,
        durability_bucket_counts=tuple(buckets),
        durability_sample_count=1,
        durability_lag_p50_ns=100_000,
        durability_lag_p95_ns=100_000,
        durability_lag_p99_ns=100_000,
        durability_lag_max_ns=100_000,
        durability_histogram_series=(series,),
    )

    assert snapshot.canonical_bytes().endswith(b"\n")
    with pytest.raises(ValidationError, match="series sample"):
        make_metrics_snapshot(
            acceptance_ordinal_high_water=0,
            accepted_record_count=1,
            durable_record_count=1,
            durability_bucket_counts=tuple(buckets),
            durability_sample_count=1,
            durability_lag_p50_ns=100_000,
            durability_lag_p95_ns=100_000,
            durability_lag_p99_ns=100_000,
            durability_lag_max_ns=100_000,
            durability_histogram_series=(),
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        (
            {"lifecycle": WriterLifecycle.CRITICAL, "critical_reason": None},
            "critical lifecycle",
        ),
        ({"acceptance_ordinal_high_water": 0}, "acceptance ordinal"),
        (
            {
                "accepted_record_count": 1,
                "uncertain_record_count": 1,
                "acceptance_ordinal_high_water": None,
            },
            "acceptance ordinal",
        ),
        (
            {
                "accepted_record_count": 1,
                "uncertain_record_count": 1,
                "acceptance_ordinal_high_water": 1,
            },
            "acceptance ordinal",
        ),
        (
            {
                "accepted_record_count": 1,
                "acceptance_ordinal_high_water": 0,
                "unpersisted_record_count": 1,
                "queued_records": 1,
                "queued_bytes": 0,
                "oldest_unpersisted_age_ns": 1,
            },
            "queued record/byte",
        ),
        (
            {
                "accepted_record_count": 1,
                "acceptance_ordinal_high_water": 0,
                "unpersisted_record_count": 1,
                "queued_records": 1,
                "queued_bytes": 1,
                "resident_record_bytes": 1,
                "oldest_unpersisted_age_ns": None,
            },
            "oldest_unpersisted_age_ns",
        ),
    ],
)
def test_metrics_snapshot_rejects_impossible_state_combinations(
    overrides: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        make_metrics_snapshot(**overrides)


@pytest.mark.parametrize(
    "overrides",
    [
        {"publication_state": PublicationState.FAILED},
        {"active_logical_generation_count": 1},
        {"retiring_generation_count": 1},
        {"open_file_descriptor_count": 1},
        {"sync_inflight": 1},
        {
            "acceptance_ordinal_high_water": 0,
            "accepted_record_count": 1,
            "uncertain_record_count": 1,
        },
        {
            "acceptance_ordinal_high_water": 0,
            "accepted_record_count": 1,
            "unpersisted_record_count": 1,
            "queued_records": 1,
            "queued_bytes": 1,
            "resident_record_bytes": 1,
            "oldest_unpersisted_age_ns": 0,
        },
    ],
)
def test_closed_metrics_snapshot_requires_a_fully_released_terminal_state(
    overrides: dict[str, object],
) -> None:
    assert make_metrics_snapshot(lifecycle=WriterLifecycle.CLOSED).lifecycle is (
        WriterLifecycle.CLOSED
    )
    with pytest.raises(ValidationError, match="closed writer terminal state"):
        make_metrics_snapshot(lifecycle=WriterLifecycle.CLOSED, **overrides)
