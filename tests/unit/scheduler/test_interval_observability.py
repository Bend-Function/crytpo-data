from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal
from enum import StrEnum
from typing import Any

import pytest
from prometheus_client import CollectorRegistry

from crypto_collector.domain import (
    Exchange,
    NativeEventDraft,
    RestMetadata,
    SourceContext,
    Transport,
)
from crypto_collector.scheduler import (
    ControlEnqueueResult,
    IntervalChange,
    IntervalChangePublisher,
    IntervalController,
    IntervalPublicationError,
    IntervalSinks,
    PrometheusIntervalMetrics,
    RestIntervalContext,
    new_interval_change,
)

SECOND_NS = 1_000_000_000
ALLOWED_SERIES = frozenset({(Exchange.OKX, "books-full")})


@dataclass
class RecordingLogs:
    records: list[dict[str, Any]] = field(default_factory=list)

    def emit(self, record: dict[str, Any]) -> None:
        self.records.append(record)


@dataclass
class RecordingControls:
    result: ControlEnqueueResult = ControlEnqueueResult.ACCEPTED
    records: list[NativeEventDraft] = field(default_factory=list)
    sources: list[SourceContext] = field(default_factory=list)
    shards: list[str] = field(default_factory=list)

    def try_emit(
        self,
        record: NativeEventDraft,
        source: SourceContext,
        *,
        shard: str,
    ) -> ControlEnqueueResult:
        if self.result in {
            ControlEnqueueResult.ACCEPTED,
            ControlEnqueueResult.ACCEPTED_HIGH_WATER,
        }:
            self.records.append(record)
            self.sources.append(source)
            self.shards.append(shard)
        return self.result


class WriterStyleEnqueueStatus(StrEnum):
    ACCEPTED = "accepted"
    ACCEPTED_HIGH_WATER = "accepted_high_water"
    CONTROL_OVERFLOW = "control_overflow"


@dataclass(frozen=True)
class WriterStyleEnqueueResult:
    status: WriterStyleEnqueueStatus

    @property
    def accepted(self) -> bool:
        return self.status in {
            WriterStyleEnqueueStatus.ACCEPTED,
            WriterStyleEnqueueStatus.ACCEPTED_HIGH_WATER,
        }


@dataclass
class WriterStyleControls:
    result: WriterStyleEnqueueResult
    records: list[NativeEventDraft] = field(default_factory=list)

    def try_emit(
        self,
        record: NativeEventDraft,
        source: SourceContext,
        *,
        shard: str,
    ) -> WriterStyleEnqueueResult:
        if self.result.accepted:
            self.records.append(record)
        return self.result


@dataclass
class RecordingCritical:
    entries: list[tuple[str, str]] = field(default_factory=list)

    def enter(self, *, reason: str, event_id: str) -> None:
        self.entries.append((reason, event_id))


@dataclass
class FailingLogs:
    def emit(self, record: dict[str, Any]) -> None:
        raise RuntimeError("log unavailable")


@dataclass
class FailingMetrics:
    def observe(self, change: IntervalChange) -> None:
        raise RuntimeError("metrics unavailable")


@dataclass
class RaisingControls:
    def try_emit(
        self,
        record: NativeEventDraft,
        source: SourceContext,
        *,
        shard: str,
    ) -> ControlEnqueueResult:
        raise RuntimeError("writer unavailable")


def interval_change(**overrides: object) -> IntervalChange:
    values: dict[str, object] = {
        "event_id": "interval-event-1",
        "exchange": Exchange.OKX,
        "endpoint": "books-full",
        "requested_ns": 30 * SECOND_NS,
        "previous_effective_ns": 30 * SECOND_NS,
        "effective_ns": 120 * SECOND_NS,
        "healthy_egress_count": 2,
        "affected_instrument_keys": ("BTC-USDT", "ETH-USDT"),
        "config_sha256": "a" * 64,
        "cause": "capacity_shortfall",
        "direction": "stretch",
    }
    values.update(overrides)
    return IntervalChange(**values)  # type: ignore[arg-type]


def test_interval_change_factory_generates_event_id_before_publication() -> None:
    change = new_interval_change(
        exchange=Exchange.OKX,
        endpoint="books-full",
        requested_ns=30 * SECOND_NS,
        previous_effective_ns=30 * SECOND_NS,
        effective_ns=120 * SECOND_NS,
        healthy_egress_count=1,
        affected_instrument_keys=("BTC-USDT",),
        config_sha256="a" * 64,
        cause="capacity_shortfall",
        direction="stretch",
        event_id_factory=lambda: "generated-event",
    )

    assert change.event_id == "generated-event"


def metric_value(
    registry: CollectorRegistry,
    name: str,
    labels: dict[str, str],
) -> float:
    return registry.get_sample_value(name, labels) or 0.0


def test_interval_change_is_visible_in_all_bounded_observability_surfaces() -> None:
    registry = CollectorRegistry()
    logs = RecordingLogs()
    controls = RecordingControls()
    critical = RecordingCritical()
    metrics = PrometheusIntervalMetrics(
        allowed_metric_series=ALLOWED_SERIES,
        registry=registry,
    )
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=logs,
            controls=controls,
            metrics=metrics,
            critical=critical,
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )

    published = publisher.publish(interval_change())

    expected_context = {
        "event_id": published.event_id,
        "requested_interval_ns": 30 * SECOND_NS,
        "previous_effective_interval_ns": 30 * SECOND_NS,
        "effective_interval_ns": 120 * SECOND_NS,
        "endpoint": "books-full",
        "healthy_egress_count": 2,
        "affected_instrument_keys": ["BTC-USDT", "ETH-USDT"],
        "config_sha256": "a" * 64,
        "cause": "capacity_shortfall",
        "direction": "stretch",
    }
    assert {key: logs.records[0][key] for key in expected_context} == expected_context
    control_payload = controls.records[0].payload
    assert isinstance(control_payload, dict)
    assert {key: control_payload[key] for key in expected_context} == expected_context
    assert controls.records[0].logical_stream == "_control"
    assert controls.records[0].transport is Transport.INTERNAL
    assert controls.records[0].exchange is Exchange.OKX
    assert controls.sources == [SourceContext.internal()]
    assert controls.shards == ["_control"]
    assert critical.entries == []

    assert (
        metric_value(
            registry,
            "collector_interval_changes_total",
            {"exchange": "okx", "endpoint": "books-full", "direction": "stretch"},
        )
        == 1
    )
    metric_labels = {"exchange": "okx", "endpoint": "books-full"}
    assert (
        metric_value(registry, "collector_requested_interval_seconds", metric_labels)
        == 30
    )
    assert (
        metric_value(registry, "collector_effective_interval_seconds", metric_labels)
        == 120
    )
    assert metric_value(registry, "collector_healthy_egresses", metric_labels) == 2
    assert (
        metric_value(registry, "collector_interval_affected_instruments", metric_labels)
        == 2
    )
    assert metrics.label_names == {"exchange", "endpoint", "direction"}
    assert metrics.labels_by_metric == {
        "collector_interval_changes_total": (
            "exchange",
            "endpoint",
            "direction",
        ),
        "collector_requested_interval_seconds": ("exchange", "endpoint"),
        "collector_effective_interval_seconds": ("exchange", "endpoint"),
        "collector_healthy_egresses": ("exchange", "endpoint"),
        "collector_interval_affected_instruments": ("exchange", "endpoint"),
    }
    assert "config_sha256" not in metrics.label_names
    assert "instrument" not in metrics.label_names

    assert published.rest_intervals.requested_interval_ns == 30 * SECOND_NS
    assert published.rest_intervals.effective_interval_ns == 120 * SECOND_NS


def test_published_interval_values_are_attached_to_real_rest_metadata() -> None:
    registry = CollectorRegistry()
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=RecordingLogs(),
            controls=RecordingControls(),
            metrics=PrometheusIntervalMetrics(
                allowed_metric_series=ALLOWED_SERIES,
                registry=registry,
            ),
            critical=RecordingCritical(),
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )
    published = publisher.publish(interval_change())
    metadata = RestMetadata(
        request_started_at_ns=1,
        request_ended_at_ns=2,
        method="GET",
        path="/api/v5/market/books-full",
        params={},
        status=200,
        attempt=1,
        rate_limit_headers={},
    )

    attached = published.rest_intervals.attach(metadata)

    assert attached.requested_interval_ns == 30 * SECOND_NS
    assert attached.effective_interval_ns == 120 * SECOND_NS
    assert metadata.requested_interval_ns is None
    assert metadata.effective_interval_ns is None


def test_interval_context_rejects_invalid_values_and_conflicting_metadata() -> None:
    with pytest.raises((TypeError, ValueError)):
        RestIntervalContext(  # type: ignore[arg-type]
            requested_interval_ns=-1,
            effective_interval_ns=True,
        )
    context = RestIntervalContext(
        requested_interval_ns=30 * SECOND_NS,
        effective_interval_ns=120 * SECOND_NS,
    )
    conflicting = RestMetadata(
        request_started_at_ns=1,
        request_ended_at_ns=2,
        method="GET",
        path="/books",
        params={},
        status=200,
        attempt=1,
        rate_limit_headers={},
        requested_interval_ns=30 * SECOND_NS,
        effective_interval_ns=60 * SECOND_NS,
    )

    with pytest.raises(ValueError, match="conflicting"):
        context.attach(conflicting)


def test_control_rejection_enters_critical_and_rejects_schedule_activation() -> None:
    registry = CollectorRegistry()
    logs = RecordingLogs()
    controls = RecordingControls(result=ControlEnqueueResult.CONTROL_OVERFLOW)
    critical = RecordingCritical()
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=logs,
            controls=controls,
            metrics=PrometheusIntervalMetrics(
                allowed_metric_series=ALLOWED_SERIES,
                registry=registry,
            ),
            critical=critical,
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )
    controller = IntervalController(
        current_ns=30 * SECOND_NS,
        recovery_step=Decimal("0.2"),
        healthy_refreshes_required=3,
    )
    change = interval_change()
    proposal = controller.propose_interval(change.effective_ns)

    with pytest.raises(IntervalPublicationError, match="control"):
        controller.activate(proposal, change, publisher)

    assert controller.current_ns == 30 * SECOND_NS
    assert critical.entries == [("interval_control_enqueue_failed", "interval-event-1")]
    assert logs.records == []
    assert controls.records == []
    assert (
        metric_value(
            registry,
            "collector_interval_changes_total",
            {"exchange": "okx", "endpoint": "books-full", "direction": "stretch"},
        )
        == 0
    )


@pytest.mark.parametrize(
    "result",
    [ControlEnqueueResult.ACCEPTED, ControlEnqueueResult.ACCEPTED_HIGH_WATER],
)
def test_both_control_acceptance_states_commit(result: ControlEnqueueResult) -> None:
    registry = CollectorRegistry()
    controls = RecordingControls(result=result)
    controller = IntervalController(
        current_ns=30 * SECOND_NS,
        recovery_step=Decimal("0.2"),
        healthy_refreshes_required=3,
    )
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=RecordingLogs(),
            controls=controls,
            metrics=PrometheusIntervalMetrics(
                allowed_metric_series=ALLOWED_SERIES,
                registry=registry,
            ),
            critical=RecordingCritical(),
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )
    change = interval_change()

    controller.activate(
        controller.propose_interval(change.effective_ns),
        change,
        publisher,
    )

    assert controller.current_ns == 120 * SECOND_NS
    assert len(controls.records) == 1


def test_plan02_writer_style_enqueue_result_is_accepted_directly() -> None:
    controls = WriterStyleControls(
        WriterStyleEnqueueResult(WriterStyleEnqueueStatus.ACCEPTED_HIGH_WATER)
    )
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=RecordingLogs(),
            controls=controls,
            metrics=PrometheusIntervalMetrics(
                allowed_metric_series=ALLOWED_SERIES,
                registry=CollectorRegistry(),
            ),
            critical=RecordingCritical(),
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )

    published = publisher.publish(interval_change())

    assert published.event_id == "interval-event-1"
    assert len(controls.records) == 1


def test_unknown_metric_series_is_rejected_before_control_side_effect() -> None:
    registry = CollectorRegistry()
    controls = RecordingControls()
    logs = RecordingLogs()
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=logs,
            controls=controls,
            metrics=PrometheusIntervalMetrics(
                allowed_metric_series=ALLOWED_SERIES,
                registry=registry,
            ),
            critical=RecordingCritical(),
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )

    with pytest.raises(ValueError, match="not registered"):
        publisher.publish(interval_change(endpoint="trades"))

    assert controls.records == []
    assert logs.records == []


def test_control_exception_enters_critical_once_without_secondary_effects() -> None:
    critical = RecordingCritical()
    logs = RecordingLogs()
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=logs,
            controls=RaisingControls(),
            metrics=FailingMetrics(),
            critical=critical,
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )

    with pytest.raises(IntervalPublicationError, match="control"):
        publisher.publish(interval_change())

    assert critical.entries == [("interval_control_enqueue_failed", "interval-event-1")]
    assert logs.records == []


def test_successful_publication_precedes_schedule_activation() -> None:
    order: list[str] = []

    @dataclass
    class OrderedLogs:
        def emit(self, record: dict[str, Any]) -> None:
            order.append("log")

    @dataclass
    class OrderedControls:
        def try_emit(
            self,
            record: NativeEventDraft,
            source: SourceContext,
            *,
            shard: str,
        ) -> ControlEnqueueResult:
            order.append("control")
            return ControlEnqueueResult.ACCEPTED

    @dataclass
    class OrderedMetrics:
        def observe(self, change: IntervalChange) -> None:
            order.append("metrics")

    class OrderedController(IntervalController):
        def _set_current_ns(self, value: int) -> None:
            order.append("activate")
            super()._set_current_ns(value)

    controller = OrderedController(
        current_ns=30 * SECOND_NS,
        recovery_step=Decimal("0.2"),
        healthy_refreshes_required=3,
    )
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=OrderedLogs(),
            controls=OrderedControls(),
            metrics=OrderedMetrics(),
            critical=RecordingCritical(),
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )

    change = interval_change()
    controller.activate(
        controller.propose_interval(change.effective_ns),
        change,
        publisher,
    )

    assert order == ["control", "log", "metrics", "activate"]
    assert controller.current_ns == 120 * SECOND_NS


def test_secondary_sink_failure_does_not_reject_committed_control_or_activation() -> (
    None
):
    controls = RecordingControls()
    critical = RecordingCritical()
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=FailingLogs(),
            controls=controls,
            metrics=FailingMetrics(),
            critical=critical,
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )
    controller = IntervalController(
        current_ns=30 * SECOND_NS,
        recovery_step=Decimal("0.2"),
        healthy_refreshes_required=3,
    )

    change = interval_change()
    published = controller.activate(
        controller.propose_interval(change.effective_ns),
        change,
        publisher,
    )

    assert controller.current_ns == 120 * SECOND_NS
    assert len(controls.records) == 1
    assert published.degraded_sinks == ("logs", "metrics")
    assert critical.entries == [
        ("interval_observability_publish_failed", "interval-event-1")
    ]


def test_third_healthy_recovery_publishes_before_commit_and_can_retry() -> None:
    registry = CollectorRegistry()
    controls = RecordingControls(result=ControlEnqueueResult.CONTROL_OVERFLOW)
    publisher = IntervalChangePublisher(
        IntervalSinks(
            logs=RecordingLogs(),
            controls=controls,
            metrics=PrometheusIntervalMetrics(
                allowed_metric_series=ALLOWED_SERIES,
                registry=registry,
            ),
            critical=RecordingCritical(),
        ),
        allowed_metric_series=ALLOWED_SERIES,
    )
    controller = IntervalController(
        current_ns=120 * SECOND_NS,
        recovery_step=Decimal("0.2"),
        healthy_refreshes_required=3,
    )
    controller.commit(controller.propose_toward(30 * SECOND_NS, refresh_id=1))
    controller.commit(controller.propose_toward(30 * SECOND_NS, refresh_id=2))
    proposal = controller.propose_toward(30 * SECOND_NS, refresh_id=3)
    change = interval_change(
        previous_effective_ns=120 * SECOND_NS,
        effective_ns=96 * SECOND_NS,
        direction="recover",
        cause="capacity_recovered",
    )

    with pytest.raises(IntervalPublicationError):
        controller.activate(proposal, change, publisher)
    assert controller.current_ns == 120 * SECOND_NS
    assert controller.healthy_refreshes == 2

    controls.result = ControlEnqueueResult.ACCEPTED
    controller.activate(proposal, change, publisher)

    assert controller.current_ns == 96 * SECOND_NS
    assert controller.healthy_refreshes == 3
    assert (
        controller.propose_toward(
            30 * SECOND_NS,
            refresh_id=4,
        ).effective_ns
        == 76_800_000_000
    )


def test_unchanged_interval_is_not_a_publishable_change() -> None:
    with pytest.raises(ValueError, match="unchanged"):
        interval_change(
            previous_effective_ns=120 * SECOND_NS,
            effective_ns=120 * SECOND_NS,
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"event_id": ""},
        {"exchange": "not-an-exchange"},
        {"endpoint": ""},
        {"endpoint": "/api/v5/market/books"},
        {"requested_ns": True},
        {
            "requested_ns": 30 * SECOND_NS,
            "previous_effective_ns": 20 * SECOND_NS,
            "effective_ns": 40 * SECOND_NS,
        },
        {"previous_effective_ns": 0},
        {"effective_ns": -1},
        {"healthy_egress_count": True},
        {"affected_instrument_keys": ("ETH-USDT", "BTC-USDT")},
        {"affected_instrument_keys": ("BTC-USDT", "BTC-USDT")},
        {"config_sha256": "A" * 64},
        {"cause": ""},
        {"direction": "sideways"},
    ],
)
def test_interval_change_rejects_ambiguous_or_noncanonical_context(
    overrides: dict[str, object],
) -> None:
    with pytest.raises((TypeError, ValueError)):
        interval_change(**overrides)
