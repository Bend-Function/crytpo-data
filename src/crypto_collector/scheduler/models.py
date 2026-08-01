from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import IntEnum
from hashlib import sha256
from types import MappingProxyType
from typing import TypeAlias

from crypto_collector.domain import RestMetadata, SourceContext
from crypto_collector.domain.json_codec import (
    JsonPayload,
    ValidatedJsonPayload,
    validate_json_payload,
)
from crypto_collector.network.rate_limit import BudgetKey

DecimalInput: TypeAlias = int | Decimal
FrozenJsonPayload: TypeAlias = (
    bool
    | int
    | Decimal
    | str
    | None
    | tuple["FrozenJsonPayload", ...]
    | Mapping[str, "FrozenJsonPayload"]
)


def _nonempty_string(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _positive_int(value: object, *, field: str) -> int:
    normalized = _nonnegative_int(value, field=field)
    if normalized == 0:
        raise ValueError(f"{field} must be positive")
    return normalized


def _positive_decimal(value: object, *, field: str) -> Decimal:
    if type(value) is int:
        normalized = Decimal(value)
    elif type(value) is Decimal:
        normalized = value
    else:
        raise TypeError(f"{field} must be an int or Decimal")
    if not normalized.is_finite() or normalized <= 0:
        raise ValueError(f"{field} must be finite and positive")
    return normalized


def _budget_key(value: object) -> BudgetKey:
    if (
        type(value) is not tuple
        or len(value) != 3
        or any(type(part) is not str or not part for part in value)
    ):
        raise ValueError(
            "budget_key must contain non-empty exchange, quota group, and endpoint"
        )
    return value


def _mutable_json_copy(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _mutable_json_copy(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mutable_json_copy(item) for item in value]
    return value


def _freeze_json_payload(value: JsonPayload) -> FrozenJsonPayload:
    if isinstance(value, list):
        return tuple(_freeze_json_payload(item) for item in value)
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_json_payload(item) for key, item in value.items()}
        )
    return value


def _string_tuple(
    value: object,
    *,
    field: str,
    allow_empty: bool,
    unique: bool,
) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{field} must be a tuple")
    if not allow_empty and not value:
        raise ValueError(f"{field} must not be empty")
    if any(type(item) is not str or not item for item in value):
        raise ValueError(f"{field} must contain non-empty strings")
    if unique and len(set(value)) != len(value):
        raise ValueError(f"{field} must not contain duplicates")
    return value


class RestPriority(IntEnum):
    LIVE_BOOTSTRAP = 0
    CATALOG_STATUS_TIME = 1
    CORE_DERIVATIVE = 2
    DEEP_SNAPSHOT = 3
    REFERENCE_DATA = 4


@dataclass(frozen=True, slots=True)
class StableCadence:
    anchor_monotonic_ns: int
    interval_ns: int
    phase_key: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "anchor_monotonic_ns",
            _nonnegative_int(
                self.anchor_monotonic_ns,
                field="anchor_monotonic_ns",
            ),
        )
        object.__setattr__(
            self,
            "interval_ns",
            _positive_int(self.interval_ns, field="interval_ns"),
        )
        object.__setattr__(
            self,
            "phase_key",
            _nonempty_string(self.phase_key, field="phase_key"),
        )

    @property
    def phase_ns(self) -> int:
        digest = sha256(self.phase_key.encode("utf-8")).digest()
        fraction = int.from_bytes(digest[:16], "big")
        return (fraction * self.interval_ns) // (1 << 128)

    def latest_due_ns(self, now_ns: int) -> int | None:
        now = _nonnegative_int(now_ns, field="now_ns")
        first = self.anchor_monotonic_ns + self.phase_ns
        if now < first:
            return None
        return first + ((now - first) // self.interval_ns) * self.interval_ns

    def next_due_ns(self, now_ns: int) -> int:
        now = _nonnegative_int(now_ns, field="now_ns")
        first = self.anchor_monotonic_ns + self.phase_ns
        if now < first:
            return first
        return first + (((now - first) // self.interval_ns) + 1) * self.interval_ns


@dataclass(frozen=True, slots=True)
class RestBudgetRoute:
    egress_id: str
    budget_key: BudgetKey

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "egress_id",
            _nonempty_string(self.egress_id, field="egress_id"),
        )
        object.__setattr__(self, "budget_key", _budget_key(self.budget_key))


@dataclass(frozen=True, slots=True)
class RestIntervalContext:
    requested_interval_ns: int
    effective_interval_ns: int
    change_event_id: str | None = None

    def __post_init__(self) -> None:
        requested = _positive_int(
            self.requested_interval_ns,
            field="requested_interval_ns",
        )
        effective = _positive_int(
            self.effective_interval_ns,
            field="effective_interval_ns",
        )
        if effective < requested:
            raise ValueError(
                "effective_interval_ns must not be below requested_interval_ns"
            )
        if self.change_event_id is not None:
            object.__setattr__(
                self,
                "change_event_id",
                _nonempty_string(self.change_event_id, field="change_event_id"),
            )
        object.__setattr__(self, "requested_interval_ns", requested)
        object.__setattr__(self, "effective_interval_ns", effective)

    def attach(self, metadata: RestMetadata) -> RestMetadata:
        if type(metadata) is not RestMetadata:
            raise TypeError("metadata must be RestMetadata")
        existing = (
            metadata.requested_interval_ns,
            metadata.effective_interval_ns,
        )
        intended = (
            self.requested_interval_ns,
            self.effective_interval_ns,
        )
        if existing != (None, None):
            if existing != intended:
                raise ValueError("REST metadata contains conflicting interval values")
            return metadata
        values = metadata.model_dump()
        values.update(
            requested_interval_ns=self.requested_interval_ns,
            effective_interval_ns=self.effective_interval_ns,
        )
        return RestMetadata.model_validate(values)


@dataclass(frozen=True, slots=True)
class RestJob:
    id: str
    priority: RestPriority
    routes: tuple[RestBudgetRoute, ...]
    endpoint_cost: DecimalInput
    ready_monotonic_ns: int
    deadline_ns: int | None
    interval: RestIntervalContext | None
    generation_source: SourceContext | None
    attempt: int
    logical_key: tuple[str, ...] | None
    replaceable: bool
    scheduled_ns: int
    control_context: Mapping[str, JsonPayload | FrozenJsonPayload]

    def __post_init__(self) -> None:
        object.__setattr__(self, "id", _nonempty_string(self.id, field="id"))
        if type(self.priority) is not RestPriority:
            raise TypeError("priority must be a RestPriority")
        if type(self.routes) is not tuple or not self.routes:
            raise ValueError("routes must be a non-empty tuple")
        if any(type(route) is not RestBudgetRoute for route in self.routes):
            raise TypeError("routes must contain RestBudgetRoute values")
        egress_ids = tuple(route.egress_id for route in self.routes)
        if len(set(egress_ids)) != len(egress_ids):
            raise ValueError("routes must not repeat an egress_id")
        route_scopes = {
            (route.budget_key[0], route.budget_key[2]) for route in self.routes
        }
        if len(route_scopes) != 1:
            raise ValueError("all routes must use one exchange and logical endpoint")
        object.__setattr__(
            self,
            "endpoint_cost",
            _positive_decimal(self.endpoint_cost, field="endpoint_cost"),
        )
        object.__setattr__(
            self,
            "ready_monotonic_ns",
            _nonnegative_int(
                self.ready_monotonic_ns,
                field="ready_monotonic_ns",
            ),
        )
        if self.deadline_ns is not None:
            object.__setattr__(
                self,
                "deadline_ns",
                _nonnegative_int(self.deadline_ns, field="deadline_ns"),
            )
        if self.interval is not None and type(self.interval) is not RestIntervalContext:
            raise TypeError("interval must be RestIntervalContext or None")
        if self.generation_source is not None:
            if type(self.generation_source) is not SourceContext:
                raise TypeError("generation_source must be SourceContext or None")
            if self.generation_source.connection_id is None:
                raise ValueError(
                    "generation_source must identify a connection generation"
                )
            if self.generation_source.egress_id not in egress_ids:
                raise ValueError("generation_source egress must be present in routes")
        if (
            self.priority is RestPriority.LIVE_BOOTSTRAP
            and self.generation_source is None
        ):
            raise ValueError("LIVE_BOOTSTRAP requires an exact generation_source")
        object.__setattr__(
            self,
            "attempt",
            _positive_int(self.attempt, field="attempt"),
        )
        if self.logical_key is not None:
            object.__setattr__(
                self,
                "logical_key",
                _string_tuple(
                    self.logical_key,
                    field="logical_key",
                    allow_empty=False,
                    unique=False,
                ),
            )
        if type(self.replaceable) is not bool:
            raise TypeError("replaceable must be a bool")
        if self.replaceable:
            if self.logical_key is None:
                raise ValueError("replaceable jobs require a logical_key")
            if self.priority not in {
                RestPriority.DEEP_SNAPSHOT,
                RestPriority.REFERENCE_DATA,
            }:
                raise ValueError(
                    "only deep snapshot and reference jobs may be replaceable"
                )
        object.__setattr__(
            self,
            "scheduled_ns",
            _nonnegative_int(self.scheduled_ns, field="scheduled_ns"),
        )
        if not isinstance(self.control_context, Mapping):
            raise TypeError("control_context must be a mapping")
        validated = validate_json_payload(_mutable_json_copy(self.control_context))
        if not isinstance(validated, dict):  # pragma: no cover - dict input is stable
            raise TypeError("control_context must be a JSON object")
        object.__setattr__(
            self,
            "control_context",
            MappingProxyType(
                {key: _freeze_json_payload(item) for key, item in validated.items()}
            ),
        )

    @property
    def eligible_egress_ids(self) -> tuple[str, ...]:
        return tuple(route.egress_id for route in self.routes)

    @property
    def budget_keys(self) -> tuple[BudgetKey, ...]:
        return tuple(dict.fromkeys(route.budget_key for route in self.routes))


@dataclass(frozen=True, slots=True)
class RestDispatch:
    job: RestJob
    route: RestBudgetRoute
    dispatched_monotonic_ns: int

    def __post_init__(self) -> None:
        if type(self.job) is not RestJob:
            raise TypeError("job must be RestJob")
        if type(self.route) is not RestBudgetRoute or self.route not in self.job.routes:
            raise ValueError("route must be one of the job routes")
        object.__setattr__(
            self,
            "dispatched_monotonic_ns",
            _nonnegative_int(
                self.dispatched_monotonic_ns,
                field="dispatched_monotonic_ns",
            ),
        )
        source = self.job.generation_source
        if source is not None and source.egress_id != self.route.egress_id:
            raise ValueError("generation-sticky dispatch must use its exact egress")

    @property
    def id(self) -> str:
        return self.job.id

    @property
    def source_context(self) -> SourceContext:
        if self.job.generation_source is not None:
            return self.job.generation_source
        return SourceContext(
            connection_id=None,
            connection_generation=None,
            egress_id=self.route.egress_id,
        )

    def build_rest_metadata(
        self,
        *,
        request_started_at_ns: int,
        request_ended_at_ns: int,
        method: str,
        path: str,
        params: Mapping[str, ValidatedJsonPayload],
        status: int,
        rate_limit_headers: Mapping[str, str],
    ) -> RestMetadata:
        metadata = RestMetadata(
            request_started_at_ns=request_started_at_ns,
            request_ended_at_ns=request_ended_at_ns,
            method=method,
            path=path,
            params=dict(params),
            status=status,
            attempt=self.job.attempt,
            rate_limit_headers=dict(rate_limit_headers),
        )
        if self.job.interval is None:
            return metadata
        return self.job.interval.attach(metadata)
