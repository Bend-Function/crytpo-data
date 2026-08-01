from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal, Protocol
from uuid import uuid4

from prometheus_client import REGISTRY, CollectorRegistry, Counter, Gauge

from crypto_collector.domain import (
    Exchange,
    NativeEventDraft,
    SourceContext,
    Transport,
)
from crypto_collector.domain.json_codec import JsonPayload
from crypto_collector.scheduler.models import RestIntervalContext

IntervalDirection = Literal["stretch", "recover"]
_CONFIG_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_ENDPOINT_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
_NANOSECONDS_PER_SECOND = 1_000_000_000


def _nonempty_string(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _positive_int(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class IntervalChange:
    event_id: str
    exchange: Exchange
    endpoint: str
    requested_ns: int
    previous_effective_ns: int
    effective_ns: int
    healthy_egress_count: int
    affected_instrument_keys: tuple[str, ...]
    config_sha256: str
    cause: str
    direction: IntervalDirection

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "event_id",
            _nonempty_string(self.event_id, field="event_id"),
        )
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange must be an Exchange")
        object.__setattr__(
            self,
            "endpoint",
            _nonempty_string(self.endpoint, field="endpoint"),
        )
        if not _ENDPOINT_ID.fullmatch(self.endpoint):
            raise ValueError("endpoint must be a bounded registry identifier")
        requested = _positive_int(self.requested_ns, field="requested_ns")
        previous = _positive_int(
            self.previous_effective_ns,
            field="previous_effective_ns",
        )
        effective = _positive_int(self.effective_ns, field="effective_ns")
        if previous < requested:
            raise ValueError(
                "previous effective interval must not be below requested interval"
            )
        if effective < requested:
            raise ValueError("effective interval must not be below requested interval")
        if effective == previous:
            raise ValueError("unchanged intervals must not be published")
        healthy = _nonnegative_int(
            self.healthy_egress_count,
            field="healthy_egress_count",
        )
        object.__setattr__(self, "requested_ns", requested)
        object.__setattr__(self, "previous_effective_ns", previous)
        object.__setattr__(self, "effective_ns", effective)
        object.__setattr__(self, "healthy_egress_count", healthy)
        if type(self.affected_instrument_keys) is not tuple:
            raise TypeError("affected_instrument_keys must be a tuple")
        keys = self.affected_instrument_keys
        if not keys or any(type(key) is not str or not key for key in keys):
            raise ValueError("affected_instrument_keys must contain non-empty strings")
        if tuple(sorted(set(keys))) != keys:
            raise ValueError("affected_instrument_keys must be sorted and unique")
        if type(self.config_sha256) is not str or not _CONFIG_SHA256.fullmatch(
            self.config_sha256
        ):
            raise ValueError("config_sha256 must be lowercase SHA-256 hex")
        object.__setattr__(
            self,
            "cause",
            _nonempty_string(self.cause, field="cause"),
        )
        if type(self.direction) is not str or self.direction not in {
            "stretch",
            "recover",
        }:
            raise ValueError("direction must be stretch or recover")
        if self.direction == "stretch" and effective <= previous:
            raise ValueError("stretch changes must increase the effective interval")
        if self.direction == "recover" and effective >= previous:
            raise ValueError("recover changes must decrease the effective interval")

    def context(self) -> dict[str, JsonPayload]:
        return {
            "event_id": self.event_id,
            "requested_interval_ns": self.requested_ns,
            "previous_effective_interval_ns": self.previous_effective_ns,
            "effective_interval_ns": self.effective_ns,
            "endpoint": self.endpoint,
            "healthy_egress_count": self.healthy_egress_count,
            "affected_instrument_keys": list(self.affected_instrument_keys),
            "config_sha256": self.config_sha256,
            "cause": self.cause,
            "direction": self.direction,
        }


def new_interval_change(
    *,
    exchange: Exchange,
    endpoint: str,
    requested_ns: int,
    previous_effective_ns: int,
    effective_ns: int,
    healthy_egress_count: int,
    affected_instrument_keys: tuple[str, ...],
    config_sha256: str,
    cause: str,
    direction: IntervalDirection,
    event_id_factory: Callable[[], str] = lambda: str(uuid4()),
) -> IntervalChange:
    if not callable(event_id_factory):
        raise TypeError("event_id_factory must be callable")
    return IntervalChange(
        event_id=event_id_factory(),
        exchange=exchange,
        endpoint=endpoint,
        requested_ns=requested_ns,
        previous_effective_ns=previous_effective_ns,
        effective_ns=effective_ns,
        healthy_egress_count=healthy_egress_count,
        affected_instrument_keys=affected_instrument_keys,
        config_sha256=config_sha256,
        cause=cause,
        direction=direction,
    )


class IntervalLogSink(Protocol):
    def emit(self, record: dict[str, JsonPayload]) -> None: ...


class ControlEnqueueResult(StrEnum):
    ACCEPTED = "accepted"
    ACCEPTED_HIGH_WATER = "accepted_high_water"
    CONTROL_OVERFLOW = "control_overflow"
    NOT_ACCEPTING = "not_accepting"


class ControlEnqueueResultLike(Protocol):
    @property
    def status(self) -> StrEnum: ...

    @property
    def accepted(self) -> bool: ...


def _control_result_accepted(value: object) -> bool:
    if type(value) is ControlEnqueueResult:
        return value in {
            ControlEnqueueResult.ACCEPTED,
            ControlEnqueueResult.ACCEPTED_HIGH_WATER,
        }
    try:
        status = value.status  # type: ignore[attr-defined]
        accepted = value.accepted  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - isolate an injected writer result boundary
        return False
    return (
        type(accepted) is bool
        and accepted
        and isinstance(status, StrEnum)
        and type(status.value) is str
        and status.value
        in {
            ControlEnqueueResult.ACCEPTED.value,
            ControlEnqueueResult.ACCEPTED_HIGH_WATER.value,
        }
    )


class IntervalControlSink(Protocol):
    def try_emit(
        self,
        record: NativeEventDraft,
        source: SourceContext,
        *,
        shard: str,
    ) -> ControlEnqueueResult | ControlEnqueueResultLike: ...


class IntervalMetricSink(Protocol):
    def observe(self, change: IntervalChange) -> None: ...


class WriterCriticalSink(Protocol):
    def enter(self, *, reason: str, event_id: str) -> None: ...


@dataclass(frozen=True, slots=True)
class IntervalSinks:
    logs: IntervalLogSink
    controls: IntervalControlSink
    metrics: IntervalMetricSink
    critical: WriterCriticalSink


MetricSeries = tuple[Exchange, str]


def _metric_series_allowlist(value: object) -> frozenset[MetricSeries]:
    if type(value) is not frozenset or not value:
        raise ValueError("allowed_metric_series must be a non-empty frozenset")
    for item in value:
        if (
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not Exchange
            or type(item[1]) is not str
            or not _ENDPOINT_ID.fullmatch(item[1])
        ):
            raise ValueError("allowed_metric_series contains an invalid series")
    return value


class PrometheusIntervalMetrics:
    label_names = frozenset({"exchange", "endpoint", "direction"})

    def __init__(
        self,
        *,
        allowed_metric_series: frozenset[MetricSeries],
        registry: CollectorRegistry = REGISTRY,
    ) -> None:
        self._allowed_metric_series = _metric_series_allowlist(allowed_metric_series)
        self._changes = Counter(
            "collector_interval_changes_total",
            "Effective REST interval changes",
            ("exchange", "endpoint", "direction"),
            registry=registry,
        )
        self._requested = Gauge(
            "collector_requested_interval_seconds",
            "Configured REST request interval in seconds",
            ("exchange", "endpoint"),
            registry=registry,
        )
        self._effective = Gauge(
            "collector_effective_interval_seconds",
            "Active REST request interval in seconds",
            ("exchange", "endpoint"),
            registry=registry,
        )
        self._healthy = Gauge(
            "collector_healthy_egresses",
            "Healthy egresses admitted for a REST endpoint",
            ("exchange", "endpoint"),
            registry=registry,
        )
        self._affected = Gauge(
            "collector_interval_affected_instruments",
            "Instruments affected by the active REST interval",
            ("exchange", "endpoint"),
            registry=registry,
        )

    def observe(self, change: IntervalChange) -> None:
        if (change.exchange, change.endpoint) not in self._allowed_metric_series:
            raise ValueError("interval metric series is not registered")
        exchange = change.exchange.value
        endpoint = change.endpoint
        self._changes.labels(exchange, endpoint, change.direction).inc()
        self._requested.labels(exchange, endpoint).set(
            change.requested_ns / _NANOSECONDS_PER_SECOND
        )
        self._effective.labels(exchange, endpoint).set(
            change.effective_ns / _NANOSECONDS_PER_SECOND
        )
        self._healthy.labels(exchange, endpoint).set(change.healthy_egress_count)
        self._affected.labels(exchange, endpoint).set(
            len(change.affected_instrument_keys)
        )

    @property
    def labels_by_metric(self) -> dict[str, tuple[str, ...]]:
        return {
            "collector_interval_changes_total": (
                "exchange",
                "endpoint",
                "direction",
            ),
            "collector_requested_interval_seconds": ("exchange", "endpoint"),
            "collector_effective_interval_seconds": ("exchange", "endpoint"),
            "collector_healthy_egresses": ("exchange", "endpoint"),
            "collector_interval_affected_instruments": (
                "exchange",
                "endpoint",
            ),
        }


@dataclass(frozen=True, slots=True)
class PublishedIntervalChange:
    event_id: str
    rest_intervals: RestIntervalContext
    control: NativeEventDraft
    degraded_sinks: tuple[str, ...] = ()


class IntervalPublicationError(RuntimeError):
    pass


class IntervalChangePublisher:
    def __init__(
        self,
        sinks: IntervalSinks,
        *,
        allowed_metric_series: frozenset[MetricSeries],
    ) -> None:
        if type(sinks) is not IntervalSinks:
            raise TypeError("sinks must be IntervalSinks")
        self._sinks = sinks
        self._allowed_metric_series = _metric_series_allowlist(allowed_metric_series)

    @staticmethod
    def _control_record(change: IntervalChange) -> NativeEventDraft:
        payload = change.context()
        payload["type"] = "effective_interval_changed"
        payload["exchange"] = change.exchange.value
        return NativeEventDraft(
            exchange=change.exchange,
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

    def _enter_critical(self, *, reason: str, event_id: str) -> bool:
        try:
            self._sinks.critical.enter(reason=reason, event_id=event_id)
        except Exception:  # noqa: BLE001 - isolate the terminal sink boundary
            return False
        return True

    def publish(self, change: IntervalChange) -> PublishedIntervalChange:
        if type(change) is not IntervalChange:
            raise TypeError("change must be an IntervalChange")
        if (change.exchange, change.endpoint) not in self._allowed_metric_series:
            raise ValueError("interval metric series is not registered")
        control = self._control_record(change)
        try:
            accepted = self._sinks.controls.try_emit(
                control,
                SourceContext.internal(),
                shard="_control",
            )
        except Exception as error:
            self._enter_critical(
                reason="interval_control_enqueue_failed",
                event_id=change.event_id,
            )
            raise IntervalPublicationError("interval control enqueue failed") from error
        if not _control_result_accepted(accepted):
            self._enter_critical(
                reason="interval_control_enqueue_failed",
                event_id=change.event_id,
            )
            raise IntervalPublicationError("interval control enqueue was rejected")

        log_record = change.context()
        log_record["event"] = "effective_interval_changed"
        log_record["exchange"] = change.exchange.value
        degraded: list[str] = []
        try:
            self._sinks.logs.emit(log_record)
        except Exception:  # noqa: BLE001 - isolate an injected sink boundary
            degraded.append("logs")
        try:
            self._sinks.metrics.observe(change)
        except Exception:  # noqa: BLE001 - isolate an injected sink boundary
            degraded.append("metrics")
        if degraded:
            critical_recorded = self._enter_critical(
                reason="interval_observability_publish_failed",
                event_id=change.event_id,
            )
            if not critical_recorded:
                degraded.append("critical")
        return PublishedIntervalChange(
            event_id=change.event_id,
            rest_intervals=RestIntervalContext(
                requested_interval_ns=change.requested_ns,
                effective_interval_ns=change.effective_ns,
                change_event_id=change.event_id,
            ),
            control=control,
            degraded_sinks=tuple(degraded),
        )
