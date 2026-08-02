from __future__ import annotations

import re
from copy import deepcopy
from decimal import localcontext
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import crypto_collector.benchmarks.oracle as oracle_module
from crypto_collector.benchmarks.oracle import (
    EVENT_ALGORITHM_V1,
    PlannedEventV1,
    PlannedIdentityV1,
    StreamPlanV1,
    WorkloadPlanV1,
    build_native_draft,
    build_workload_plan,
    iter_plan_events,
)
from crypto_collector.benchmarks.workload import (
    GateWorkloadV1,
    LoadedWorkload,
    load_workload,
)
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.domain.types import CoverageMode, IntegrityMode, Transport
from crypto_collector.storage.models import validate_control_draft

WORKLOAD = Path("benchmarks/workloads/research-default-v1.yaml")
GOLDEN = Path("benchmarks/workloads/research-default-v1.golden.json")
ONE_SECOND_NS = 1_000_000_000
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
STREAM_GROUPS = (
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "derivative",
    "candle_1m",
    "book_deep_snapshot",
    "control",
)


def _baseline_data() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        deepcopy(load_workload(WORKLOAD).workload.model_dump(mode="json")),
    )


def _micro_loaded(*, seed: int = 20260731) -> LoadedWorkload:
    data = _baseline_data()
    data.update(
        {
            "name": "research-micro-v1",
            "generation_seed": seed,
            "exchanges": ["binance"],
            "markets": ["spot", "perpetual"],
            "symbols_per_market": 1,
            "fixed_scope_file_count": 1,
            "scalable_file_count": 14,
            "active_file_count": 15,
        }
    )
    streams = cast(dict[str, dict[str, Any]], data["streams"])
    for name, stream in streams.items():
        stream.update(
            {
                "mean_records_per_second": "0.1",
                "burst_records_in_1s": 1,
                "payload_p50_bytes": 320,
                "payload_p95_bytes": 384,
                "payload_max_bytes": 512,
            }
        )
        if name == "derivative":
            stream["instrument_instances"] = 1
            stream["file_instances"] = 2
        elif name == "control":
            stream["instances"] = 1
        else:
            stream["instances"] = 2
    streams["trade"]["mean_records_per_second"] = "1"
    streams["trade"]["burst_records_in_1s"] = 2
    streams["ticker"]["mean_records_per_second"] = "0.05"
    streams["ticker"]["burst_records_in_1s"] = 2
    model = GateWorkloadV1.model_validate(data)
    source = encode_json(data)
    return LoadedWorkload(
        workload=model,
        source_bytes=source,
        sha256=sha256(source).hexdigest(),
    )


def _event(plan: WorkloadPlanV1, stream_group: str) -> PlannedEventV1:
    return next(
        event for event in iter_plan_events(plan) if event.stream_group == stream_group
    )


def _golden() -> dict[str, Any]:
    decoded = decode_json(GOLDEN.read_bytes())
    assert isinstance(decoded, dict)
    return cast(dict[str, Any], decoded)


def _summary_vector(summary: StreamPlanV1) -> dict[str, int]:
    return {
        "expected_record_count": summary.expected_record_count,
        "identity_count": summary.identity_count,
        "expected_touched_file_identity_count": (
            summary.expected_touched_file_identity_count
        ),
        "required_burst_count": summary.required_burst_count,
        "scheduled_burst_count": summary.scheduled_burst_count,
        "burst_second": summary.burst_second,
        "expected_payload_byte_count": summary.expected_payload_byte_count,
    }


def _selected_event(summary: StreamPlanV1) -> PlannedEventV1:
    event_id, _, _ = oracle_module._event_id_at(summary, 0)
    return oracle_module._build_event(
        oracle_module._ScheduledEvent(
            summary=summary,
            ordinal=0,
            due_offset_ns=summary.burst_start_ns,
            event_id=event_id,
        )
    )


def _event_vector(event: PlannedEventV1, *, include_payload: bool) -> dict[str, Any]:
    vector: dict[str, Any] = {
        "planned_event_id": event.planned_event_id,
        "canonical_identity": event.canonical_identity,
        "local_sequence": event.local_sequence,
        "due_offset_ns": event.due_offset_ns,
        "deadline_offset_ns": event.deadline_offset_ns,
        "payload_bytes": event.payload_bytes,
        "payload_sha256": event.payload_sha256,
    }
    if include_payload:
        vector["payload"] = event.payload
    return vector


def _seed_for_burst_second(stream_group: str, target_second: int) -> int:
    for seed in range(100_000):
        digest = sha256(f"{seed}:{stream_group}".encode("ascii")).digest()
        if int.from_bytes(digest[:8], "big") % 9 == target_second:
            return seed
    raise AssertionError("test seed search failed")


def test_compact_strict_workload_preserves_declared_relative_order() -> None:
    loaded = _micro_loaded()

    assert loaded.workload.exchanges == ("binance",)
    assert loaded.workload.markets == ("spot", "perpetual")
    data = loaded.workload.model_dump(mode="json")
    data["exchanges"] = ["okx", "binance"]
    with pytest.raises(ValidationError, match="canonical relative order"):
        GateWorkloadV1.model_validate(data)


def test_multiplier_two_exact_counts_and_touched_files() -> None:
    plan = build_workload_plan(
        load_workload(WORKLOAD),
        multiplier=2,
        duration_ns=10_000_000_000,
    )

    assert plan.expected_record_count == 417_677
    assert plan.declared_file_identity_count == 3_505
    assert plan.expected_touched_file_identity_count == 3_172
    assert plan.stream("trade").expected_record_count == 250_000
    assert plan.stream("book_deep_snapshot").expected_record_count == 167
    assert plan.stream("control").expected_record_count == 10


def test_qualification_plan_touches_every_declared_identity() -> None:
    plan = build_workload_plan(
        load_workload(WORKLOAD),
        multiplier=2,
        duration_ns=600_000_000_000,
    )

    assert plan.expected_record_count == 25_060_620
    assert plan.expected_touched_file_identity_count == 3_505


def test_identity_order_allocation_and_local_sequences_are_exact() -> None:
    plan = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )
    trade = tuple(plan.stream("trade").iter_identities())
    derivative = tuple(plan.stream("derivative").iter_identities())
    control = tuple(plan.stream("control").iter_identities())

    assert trade[0].canonical_identity == (
        "gate-identity-v1:binance:spot:GATE-BINANCE-SPOT-L0000-S0000:trade"
    )
    assert [item.logical_stream for item in derivative[:2]] == [
        "funding",
        "open_interest",
    ]
    assert control[-1].canonical_identity == "gate-identity-v1:binance:-:-:_control"
    ticker = tuple(plan.stream("ticker").iter_identities())
    assert [item.allocated_event_count for item in ticker] == [1, 0]

    first_identity_events = [
        event
        for event in iter_plan_events(plan)
        if event.canonical_identity == trade[0].canonical_identity
    ]
    assert sorted(event.local_sequence for event in first_identity_events) == list(
        range(trade[0].allocated_event_count)
    )


def test_baseline_identity_boundaries_are_exact() -> None:
    plan = build_workload_plan(
        load_workload(WORKLOAD), multiplier=2, duration_ns=10_000_000_000
    )

    assert next(plan.stream("trade").iter_identities()).canonical_identity == (
        "gate-identity-v1:binance:spot:GATE-BINANCE-SPOT-L0000-S0000:trade"
    )
    derivative = plan.stream("derivative").iter_identities()
    assert next(derivative).canonical_identity == (
        "gate-identity-v1:binance:perpetual:GATE-BINANCE-PERPETUAL-L0000-S0000:funding"
    )
    assert tuple(plan.stream("control").iter_identities())[-1].canonical_identity == (
        "gate-identity-v1:kraken:-:-:_control"
    )


def test_literal_golden_identity_boundaries_match_the_oracle() -> None:
    plan = build_workload_plan(
        load_workload(WORKLOAD), multiplier=2, duration_ns=10_000_000_000
    )
    golden = _golden()

    for vector in golden["identity_vectors"]:
        identity = tuple(plan.stream(vector["stream_group"]).iter_identities())[
            vector["identity_index"]
        ]
        assert {
            "name": vector["name"],
            "stream_group": identity.stream_group,
            "identity_index": identity.identity_index,
            "canonical_identity": identity.canonical_identity,
            "allocated_event_count": identity.allocated_event_count,
        } == vector


def test_literal_golden_file_has_complete_version_one_shape() -> None:
    golden = _golden()

    assert tuple(golden) == (
        "schema_version",
        "workload_name",
        "workload_sha256",
        "algorithms",
        "identity_vectors",
        "plans",
        "micro_profile",
    )
    assert golden["algorithms"] == {
        "identity": "gate-identity-v1",
        "event": "gate-event-v1",
        "payload": "gate-payload-v1",
        "schedule": "gate-schedule-v2-full-second-burst",
    }
    assert SHA256_PATTERN.fullmatch(golden["workload_sha256"])
    assert tuple(golden["plans"]) == (
        "functional_10s_multiplier_2",
        "qualification_10m_multiplier_2",
    )
    for vector in (*golden["plans"].values(), golden["micro_profile"]):
        assert SHA256_PATTERN.fullmatch(vector["workload_plan_sha256"])
        assert tuple(vector["streams"]) == STREAM_GROUPS
    for stream in golden["plans"]["functional_10s_multiplier_2"]["streams"].values():
        assert "payload" not in stream["selected_event"]
    assert all(
        "payload" in stream["selected_event"]
        for stream in golden["micro_profile"]["streams"].values()
    )


def test_functional_plan_matches_literal_golden_vectors() -> None:
    plan = build_workload_plan(
        load_workload(WORKLOAD), multiplier=2, duration_ns=10_000_000_000
    )
    golden = _golden()
    vector = golden["plans"]["functional_10s_multiplier_2"]

    assert golden["schema_version"] == 1
    assert golden["workload_sha256"] == plan.workload_sha256
    assert {
        "duration_ns": plan.duration_ns,
        "multiplier": plan.multiplier,
        "expected_record_count": plan.expected_record_count,
        "declared_file_identity_count": plan.declared_file_identity_count,
        "expected_touched_file_identity_count": (
            plan.expected_touched_file_identity_count
        ),
        "expected_payload_byte_count": plan.expected_payload_byte_count,
        "workload_plan_sha256": plan.workload_plan_sha256,
    } == {key: value for key, value in vector.items() if key != "streams"}
    assert {
        summary.stream_group: _summary_vector(summary) for summary in plan.streams
    } == {name: stream["summary"] for name, stream in vector["streams"].items()}
    assert {
        summary.stream_group: _event_vector(
            _selected_event(summary), include_payload=False
        )
        for summary in plan.streams
    } == {name: stream["selected_event"] for name, stream in vector["streams"].items()}


def test_micro_plan_matches_literal_complete_payload_vectors() -> None:
    plan = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )
    vector = _golden()["micro_profile"]

    assert {
        "workload_sha256": plan.workload_sha256,
        "duration_ns": plan.duration_ns,
        "multiplier": plan.multiplier,
        "expected_record_count": plan.expected_record_count,
        "declared_file_identity_count": plan.declared_file_identity_count,
        "expected_touched_file_identity_count": (
            plan.expected_touched_file_identity_count
        ),
        "expected_payload_byte_count": plan.expected_payload_byte_count,
        "workload_plan_sha256": plan.workload_plan_sha256,
    } == {key: value for key, value in vector.items() if key != "streams"}
    assert {
        summary.stream_group: _summary_vector(summary) for summary in plan.streams
    } == {name: stream["summary"] for name, stream in vector["streams"].items()}
    assert {
        summary.stream_group: _event_vector(
            _selected_event(summary), include_payload=True
        )
        for summary in plan.streams
    } == {name: stream["selected_event"] for name, stream in vector["streams"].items()}


def test_schedule_payload_and_global_order_are_exact() -> None:
    duration_ns = 10_000_000_000
    plan = build_workload_plan(_micro_loaded(), multiplier=1, duration_ns=duration_ns)
    events = tuple(iter_plan_events(plan))

    assert tuple(events) == tuple(
        sorted(events, key=lambda item: (item.due_offset_ns, item.planned_event_id))
    )
    assert max(event.deadline_offset_ns for event in events) <= duration_ns
    for summary in plan.streams:
        stream_events = [
            event for event in events if event.stream_group == summary.stream_group
        ]
        burst_start = summary.burst_second * ONE_SECOND_NS
        burst_events = [
            event for event in stream_events if event.due_offset_ns == burst_start
        ]
        assert len(burst_events) == summary.scheduled_burst_count
        assert all(
            event.deadline_offset_ns == burst_start + ONE_SECOND_NS
            for event in burst_events
        )
    for event in events:
        payload_bytes = encode_json(event.payload)
        assert len(payload_bytes) == event.payload_bytes
        assert sha256(payload_bytes).hexdigest() == event.payload_sha256

    assert (
        plan.stream("trade").expected_record_count
        > plan.stream("trade").scheduled_burst_count
    )
    assert (
        plan.stream("book_live").expected_record_count
        == plan.stream("book_live").scheduled_burst_count
    )
    assert (
        plan.stream("ticker").expected_record_count
        < plan.stream("ticker").required_burst_count
    )


@pytest.mark.parametrize("target_second", [0, 8])
def test_burst_can_use_first_or_final_schedulable_second(target_second: int) -> None:
    seed = _seed_for_burst_second("trade", target_second)
    plan = build_workload_plan(
        _micro_loaded(seed=seed),
        multiplier=1,
        duration_ns=10_000_000_000,
    )

    assert plan.stream("trade").burst_second == target_second


def test_equal_due_events_are_ordered_by_event_id() -> None:
    plan = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )
    events = tuple(iter_plan_events(plan))

    for summary in plan.streams:
        burst_due = summary.burst_second * ONE_SECOND_NS
        event_ids = [
            event.planned_event_id
            for event in events
            if event.stream_group == summary.stream_group
            and event.due_offset_ns == burst_due
        ]
        assert event_ids == sorted(event_ids)


@pytest.mark.parametrize("multiplier", [True, 0, -1, 10_001])
def test_plan_rejects_invalid_or_identity_overflow_multiplier(
    multiplier: object,
) -> None:
    with pytest.raises((TypeError, ValueError), match="multiplier"):
        build_workload_plan(
            _micro_loaded(),
            multiplier=cast(int, multiplier),
            duration_ns=10_000_000_000,
        )


@pytest.mark.parametrize("duration_ns", [9_000_000_000, 10_000_000_001, True])
def test_plan_rejects_short_nonintegral_or_boolean_duration(
    duration_ns: object,
) -> None:
    with pytest.raises((TypeError, ValueError), match="duration"):
        build_workload_plan(
            _micro_loaded(),
            multiplier=1,
            duration_ns=cast(int, duration_ns),
        )


@pytest.mark.parametrize("value", [True, 1.0, "1"])
def test_planned_event_schema_version_is_strict(value: object) -> None:
    event = _event(
        build_workload_plan(_micro_loaded(), multiplier=1, duration_ns=10_000_000_000),
        "trade",
    )
    data = event.model_dump(mode="python")
    data["payload_canonical_bytes"] = event.payload_canonical_bytes
    data["schema_version"] = value

    with pytest.raises(ValidationError):
        PlannedEventV1.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("canonical_identity", "gate-identity-v1:okx:spot:WRONG:trade"),
        ("logical_stream", "bbo"),
        ("transport", Transport.REST),
        ("instrument_key", "GATE-BINANCE-SPOT-L9999-S9999"),
    ],
)
def test_planned_event_rejects_identity_or_transport_disagreement(
    field: str,
    value: object,
) -> None:
    event = _event(
        build_workload_plan(_micro_loaded(), multiplier=1, duration_ns=10_000_000_000),
        "trade",
    )
    data = event.model_dump(mode="python")
    data["payload_canonical_bytes"] = event.payload_canonical_bytes
    data[field] = value

    with pytest.raises(ValidationError):
        PlannedEventV1.model_validate(data)


def test_planned_event_rejects_noncanonical_payload_bytes() -> None:
    event = _event(
        build_workload_plan(_micro_loaded(), multiplier=1, duration_ns=10_000_000_000),
        "trade",
    )
    changed = b" " + event.payload_canonical_bytes
    data = event.model_dump(mode="python")
    data.update(
        {
            "payload_canonical_bytes": changed,
            "payload_bytes": len(changed),
            "payload_sha256": sha256(changed).hexdigest(),
        }
    )

    with pytest.raises(ValidationError, match="canonical JSON"):
        PlannedEventV1.model_validate(data)


def test_planned_identity_rejects_noncanonical_identity_grammar() -> None:
    identity = next(
        build_workload_plan(_micro_loaded(), multiplier=1, duration_ns=10_000_000_000)
        .stream("trade")
        .iter_identities()
    )
    data = identity.model_dump(mode="python")
    data["canonical_identity"] += ":suffix"

    with pytest.raises(ValidationError, match="canonical identity"):
        PlannedIdentityV1.model_validate(data)


def test_stream_plan_rejects_recomputed_count_or_burst_disagreement() -> None:
    summary = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    ).stream("trade")
    count_data = summary.model_dump(mode="python")
    count_data["expected_record_count"] += 1
    count_data["expected_touched_file_identity_count"] = min(
        count_data["expected_record_count"], count_data["identity_count"]
    )
    with pytest.raises(ValidationError, match="record count"):
        StreamPlanV1.model_validate(count_data)

    burst_data = summary.model_dump(mode="python")
    burst_data["burst_second"] = (burst_data["burst_second"] + 1) % 9
    burst_data["burst_start_ns"] = burst_data["burst_second"] * ONE_SECOND_NS
    with pytest.raises(ValidationError, match="burst second"):
        StreamPlanV1.model_validate(burst_data)


def test_workload_plan_rejects_summary_header_disagreement() -> None:
    plan = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )
    data = plan.model_dump(mode="python")
    data["generation_seed"] += 1

    with pytest.raises(ValidationError, match="summary inputs"):
        WorkloadPlanV1.model_validate(data)


def test_plan_rejects_loaded_workload_sha_disagreement() -> None:
    loaded = _micro_loaded()

    with pytest.raises(ValueError, match="source SHA"):
        LoadedWorkload(
            workload=loaded.workload,
            source_bytes=loaded.source_bytes,
            sha256="0" * 64,
        )


def test_loaded_workload_rejects_model_not_parsed_from_its_source_bytes() -> None:
    loaded = load_workload(WORKLOAD)
    changed = loaded.workload.model_dump(mode="json")
    changed["generation_seed"] += 1

    with pytest.raises(ValueError, match="source bytes"):
        LoadedWorkload(
            workload=GateWorkloadV1.model_validate(changed),
            source_bytes=loaded.source_bytes,
            sha256=loaded.sha256,
        )


def test_loaded_workload_binds_exact_decimal_source_representation() -> None:
    loaded = load_workload(WORKLOAD)
    changed = loaded.workload.model_dump(mode="json")
    changed["payload_generation"]["decimal_string_fraction"] = "0.7"

    with pytest.raises(ValueError, match="source bytes"):
        LoadedWorkload(
            workload=GateWorkloadV1.model_validate(changed),
            source_bytes=loaded.source_bytes,
            sha256=loaded.sha256,
        )


def test_counts_and_payload_algorithms_ignore_ambient_decimal_context() -> None:
    baseline = build_workload_plan(
        load_workload(WORKLOAD),
        multiplier=2,
        duration_ns=600_000_000_000,
    )
    baseline_micro = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )
    with localcontext() as context:
        context.prec = 3
        perturbed = build_workload_plan(
            load_workload(WORKLOAD),
            multiplier=2,
            duration_ns=600_000_000_000,
        )
        perturbed_micro = build_workload_plan(
            _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
        )
        perturbed_hash = perturbed_micro.workload_plan_sha256

    assert perturbed.expected_record_count == baseline.expected_record_count
    assert (
        perturbed.stream("book_deep_snapshot").expected_record_count
        == baseline.stream("book_deep_snapshot").expected_record_count
    )
    assert perturbed_hash == baseline_micro.workload_plan_sha256


def test_plan_canonical_record_keys_are_frozen_and_payload_body_is_omitted() -> None:
    plan = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )
    summary = decode_json(plan.stream("trade").canonical_bytes())
    event = _event(plan, "trade")
    header = decode_json(plan.header.canonical_bytes())
    event_row = decode_json(event.canonical_bytes())

    assert tuple(header) == (
        "schema_version",
        "record_type",
        "workload_sha256",
        "workload_name",
        "generation_seed",
        "identity_algorithm",
        "event_algorithm",
        "payload_algorithm",
        "schedule_algorithm",
        "multiplier",
        "duration_ns",
        "duration_seconds",
        "declared_file_identity_count",
        "expected_touched_file_identity_count",
        "expected_record_count",
    )
    assert tuple(summary) == (
        "schema_version",
        "record_type",
        "stream_group",
        "logical_streams",
        "transports",
        "exchanges",
        "markets",
        "symbols_per_market",
        "generation_seed",
        "identity_algorithm",
        "event_algorithm",
        "payload_algorithm",
        "schedule_algorithm",
        "multiplier",
        "duration_ns",
        "base_instance_count",
        "identity_count",
        "mean_records_per_second",
        "burst_records_in_1s",
        "payload_p50_bytes",
        "payload_p95_bytes",
        "payload_max_bytes",
        "decimal_string_fraction",
        "repeated_key_fraction",
        "incompressible_fraction",
        "expected_record_count",
        "expected_touched_file_identity_count",
        "required_burst_count",
        "scheduled_burst_count",
        "burst_second",
        "burst_start_ns",
        "expected_payload_byte_count",
    )
    assert "payload_canonical_bytes" not in event_row
    assert tuple(event_row) == (
        "schema_version",
        "record_type",
        "identity_algorithm",
        "event_algorithm",
        "payload_algorithm",
        "schedule_algorithm",
        "planned_event_id",
        "stream_group",
        "logical_stream",
        "exchange",
        "market",
        "lane_index",
        "symbol_index",
        "instrument_key",
        "canonical_identity",
        "identity_index",
        "local_sequence",
        "transport",
        "due_offset_ns",
        "deadline_offset_ns",
        "payload_bytes",
        "payload_sha256",
    )


def test_optimized_event_rows_match_strict_public_canonical_events() -> None:
    plan = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )
    scheduled_events = tuple(oracle_module._iter_plan_schedule(plan))
    public_events = tuple(iter_plan_events(plan))

    assert len(scheduled_events) == len(public_events) == plan.expected_record_count
    for scheduled, event in zip(scheduled_events, public_events, strict=True):
        assert scheduled.event_id == event.planned_event_id
        assert oracle_module._scheduled_event_canonical_bytes(scheduled) == (
            event.canonical_bytes()
        )
        values = event.model_dump(mode="python")
        values["payload_canonical_bytes"] = event.payload_canonical_bytes
        assert PlannedEventV1.model_validate(values) == event


def test_plan_build_is_lazy_about_payload_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_payload(**_: object) -> bytes:
        raise AssertionError("payload generation must remain lazy")

    monkeypatch.setattr(oracle_module, "_payload_bytes", unexpected_payload)
    plan = build_workload_plan(
        load_workload(WORKLOAD),
        multiplier=2,
        duration_ns=600_000_000_000,
    )

    assert plan.expected_record_count == 25_060_620
    with pytest.raises(AssertionError, match="remain lazy"):
        next(iter_plan_events(plan))


def test_native_draft_source_and_shard_profiles_are_exact() -> None:
    plan = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )
    anchor = 1_800_000_000_000_000_000

    trade, trade_source, trade_shard = build_native_draft(
        _event(plan, "trade"), admission_started_utc_ns=anchor
    )
    assert trade.transport is Transport.WEBSOCKET
    assert trade.native_channel == "gate.v1.trade"
    assert trade.event_time_ns is not None
    assert trade.event_time_source == "gate_due_time"
    assert trade_source.connection_id == "gate-ws-v1-binance-spot"
    assert trade_source.connection_generation == 0
    assert trade_source.egress_id == "gate-egress-v1-binance"
    assert trade_shard == "trade"

    live, _, live_shard = build_native_draft(
        _event(plan, "book_live"), admission_started_utc_ns=anchor
    )
    assert live.integrity_mode is IntegrityMode.SEQUENCE_VERIFIED
    assert live.coverage is CoverageMode.COMPLETE
    assert live_shard == "book_live"

    deep, deep_source, deep_shard = build_native_draft(
        _event(plan, "book_deep_snapshot"), admission_started_utc_ns=anchor
    )
    assert deep.transport is Transport.REST
    assert deep.integrity_mode is IntegrityMode.SNAPSHOT_CHAIN
    assert deep.coverage is CoverageMode.COMPLETE
    assert deep.rest_metadata is not None
    assert deep.rest_metadata.request_started_at_ns == deep.event_time_ns
    assert deep.rest_metadata.request_ended_at_ns == deep.event_time_ns
    assert deep.rest_metadata.path == "/gate/v1/book-deep-snapshot"
    assert deep.rest_metadata.params == {"instrument": deep.instrument_key}
    assert deep_source.connection_id is None
    assert deep_source.connection_generation is None
    assert deep_shard == "book_deep_snapshot"

    control, control_source, control_shard = build_native_draft(
        _event(plan, "control"), admission_started_utc_ns=anchor
    )
    assert control.market is None
    assert control.instrument_key is None
    assert control.logical_stream == "_control"
    assert control.transport is Transport.INTERNAL
    assert control.event_time_ns is None
    assert control.payload["affected_markets"] == ["spot", "perpetual"]
    assert control_source == control_source.internal()
    assert control_shard == "_control"
    validated_control = validate_control_draft(control)
    assert validated_control.control_kind == "writer_gate_control"
    assert validated_control.association_request is None


def test_plan_models_freeze_algorithm_versions_and_hash() -> None:
    plan = build_workload_plan(
        _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
    )

    assert plan.event_algorithm == EVENT_ALGORITHM_V1
    assert len(plan.workload_plan_sha256) == 64
    assert (
        plan.workload_plan_sha256
        == build_workload_plan(
            _micro_loaded(), multiplier=1, duration_ns=10_000_000_000
        ).workload_plan_sha256
    )
    with pytest.raises(ValidationError):
        plan.duration_ns = 1
