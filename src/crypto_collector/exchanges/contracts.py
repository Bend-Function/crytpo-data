from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from decimal import Decimal
from enum import Enum
from math import isfinite
from threading import Lock
from types import MappingProxyType, TracebackType
from typing import Any, Protocol, Self, TypeAlias
from urllib.parse import urlsplit

import httpx
from pydantic import ConfigDict, model_validator

from crypto_collector.config.probe_contracts import ExchangeProbeEvidence
from crypto_collector.domain import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    NativeEventDraft,
    SourceContext,
    Transport,
)
from crypto_collector.domain.clock import Clock
from crypto_collector.domain.envelope import MARKET_SCOPED_STREAMS, FrozenStrictModel
from crypto_collector.network import RetryDecision
from crypto_collector.scheduler import (
    IntervalPlan,
    RestBudgetRoute,
    RestDispatch,
    RestIntervalContext,
    RestPriority,
    SubmitResult,
)
from crypto_collector.scheduler import RestJob as ScheduledRestJob
from crypto_collector.selection import CompleteCatalogSnapshot, InstrumentRecord
from crypto_collector.storage import EnqueueResult

BookIntegrity = IntegrityMode
CapabilityProbe = ExchangeProbeEvidence
Instrument = InstrumentRecord
InstrumentCatalog = CompleteCatalogSnapshot
PublicQueryValue: TypeAlias = str | int | float | bool | None
PublicQueryParams: TypeAlias = Mapping[
    str,
    PublicQueryValue | Sequence[PublicQueryValue],
]


def _nonempty_string(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _enum_member(value: object, enum_type: type[Any], *, field: str) -> Any:
    if type(value) is not enum_type:
        raise TypeError(f"{field} must be {enum_type.__name__}")
    return value


def _public_uri(value: object, *, field: str, schemes: frozenset[str]) -> str:
    uri = _nonempty_string(value, field=field)
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except (UnicodeError, ValueError) as error:
        raise ValueError(f"{field} must be a valid public URI") from error
    if (
        parsed.scheme not in schemes
        or parsed.hostname is None
        or "%" in parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "?" in uri
        or "#" in uri
        or "\\" in uri
        or parsed.query
        or parsed.fragment
        or parsed.netloc.endswith(":")
        or (port is not None and not 1 <= port <= 65_535)
        or any(
            character.isspace()
            or ord(character) < 0x20
            or 0x7F <= ord(character) <= 0x9F
            for character in uri
        )
    ):
        raise ValueError(f"{field} must be an anonymous public URI")
    return uri


def _public_query_scalar(value: object, *, field: str) -> PublicQueryValue:
    if value is None or type(value) in {bool, int, str}:
        return value  # type: ignore[return-value]
    if type(value) is float and isfinite(value):
        return value
    raise ValueError(f"{field} must be a finite public query scalar")


def _public_params(
    value: object,
) -> Mapping[str, PublicQueryValue | Sequence[PublicQueryValue]]:
    if not isinstance(value, Mapping):
        raise TypeError("params must be a mapping")
    from crypto_collector.observability.redaction import SENSITIVE_QUERY_NAMES

    normalized: dict[str, PublicQueryValue | Sequence[PublicQueryValue]] = {}
    for key, item in value.items():
        normalized_key = _nonempty_string(key, field="query parameter name")
        if normalized_key.casefold() in SENSITIVE_QUERY_NAMES:
            raise ValueError("sensitive query parameters are not permitted")
        if type(item) in {list, tuple}:
            normalized[normalized_key] = tuple(
                _public_query_scalar(
                    part,
                    field=f"query parameter {normalized_key!r}",
                )
                for part in item
            )
        else:
            normalized[normalized_key] = _public_query_scalar(
                item,
                field=f"query parameter {normalized_key!r}",
            )
    return MappingProxyType(normalized)


@dataclass(frozen=True, slots=True)
class ConnectionGeneration:
    connection_id: str
    generation: int
    egress_id: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "connection_id",
            _nonempty_string(self.connection_id, field="connection_id"),
        )
        object.__setattr__(
            self,
            "generation",
            _nonnegative_int(self.generation, field="generation"),
        )
        object.__setattr__(
            self,
            "egress_id",
            _nonempty_string(self.egress_id, field="egress_id"),
        )

    def source_context(self) -> SourceContext:
        return SourceContext(
            connection_id=self.connection_id,
            connection_generation=self.generation,
            egress_id=self.egress_id,
        )


class CollectionRequest(FrozenStrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        arbitrary_types_allowed=True,
    )

    exchange: Exchange
    selected: Mapping[Market, tuple[Any, ...]]
    enabled_streams: Mapping[Market, frozenset[str]]
    interval_plans: Mapping[str, IntervalPlan]
    config_sha256: str

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        if len(self.config_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in self.config_sha256
        ):
            raise ValueError("config_sha256 must be a lowercase SHA-256 digest")
        for market, instruments in self.selected.items():
            if type(market) is not Market:
                raise TypeError("selected market keys must be Market values")
            if type(instruments) is not tuple:
                raise TypeError("selected instruments must be tuples")
            keys: set[str] = set()
            for instrument in instruments:
                if not isinstance(instrument, InstrumentRecord):
                    raise TypeError(
                        "selected values must contain InstrumentRecord values"
                    )
                if (
                    instrument.exchange is not self.exchange
                    or instrument.market is not market
                ):
                    raise ValueError("selected instrument scope does not match request")
                if instrument.instrument_key in keys:
                    raise ValueError("selected instruments must be unique per market")
                keys.add(instrument.instrument_key)
        if not set(self.enabled_streams).issubset(self.selected):
            raise ValueError(
                "enabled stream markets must have a selected instrument set"
            )
        for market, streams in self.enabled_streams.items():
            if type(market) is not Market or type(streams) is not frozenset:
                raise TypeError("enabled_streams must map Market to frozenset")
            if any(type(stream) is not str or not stream for stream in streams):
                raise ValueError("enabled stream IDs must be non-empty strings")
        for key, interval in self.interval_plans.items():
            _nonempty_string(key, field="interval plan key")
            if type(interval) is not IntervalPlan:
                raise TypeError("interval_plans must contain IntervalPlan values")
            if (
                type(interval.requested_ns) is not int
                or interval.requested_ns <= 0
                or type(interval.effective_ns) is not int
                or interval.effective_ns < interval.requested_ns
            ):
                raise ValueError("interval plans must contain valid positive intervals")
            warning = interval.warning
            if interval.effective_ns == interval.requested_ns:
                if warning is not None:
                    raise ValueError(
                        "unchanged interval plan must not contain a warning"
                    )
            elif (
                warning is None
                or type(warning.requested_ns) is not int
                or warning.requested_ns != interval.requested_ns
                or type(warning.effective_ns) is not int
                or warning.effective_ns != interval.effective_ns
                or type(warning.affected_symbols) is not int
                or warning.affected_symbols <= 0
            ):
                raise ValueError(
                    "stretched interval plan requires matching warning evidence"
                )
        object.__setattr__(self, "selected", MappingProxyType(dict(self.selected)))
        object.__setattr__(
            self,
            "enabled_streams",
            MappingProxyType(dict(self.enabled_streams)),
        )
        object.__setattr__(
            self,
            "interval_plans",
            MappingProxyType(dict(self.interval_plans)),
        )
        return self


@dataclass(frozen=True, slots=True)
class WebSocketSubscription:
    id: str
    market: Market
    instrument_key: str | None
    wire_symbol: str | None
    channel: str
    endpoint: str
    egress_id: str
    quota_group: str
    shard_id: str
    logical_stream: str
    params: Mapping[str, PublicQueryValue | Sequence[PublicQueryValue]] = (
        dataclass_field(default_factory=dict)
    )

    def __post_init__(self) -> None:
        for field in (
            "id",
            "channel",
            "egress_id",
            "quota_group",
            "shard_id",
            "logical_stream",
        ):
            object.__setattr__(
                self,
                field,
                _nonempty_string(getattr(self, field), field=field),
            )
        _enum_member(self.market, Market, field="market")
        if (self.instrument_key is None) != (self.wire_symbol is None):
            raise ValueError("instrument_key and wire_symbol must be present together")
        if self.instrument_key is not None:
            object.__setattr__(
                self,
                "instrument_key",
                _nonempty_string(self.instrument_key, field="instrument_key"),
            )
            object.__setattr__(
                self,
                "wire_symbol",
                _nonempty_string(self.wire_symbol, field="wire_symbol"),
            )
        object.__setattr__(
            self,
            "endpoint",
            _public_uri(
                self.endpoint,
                field="endpoint",
                schemes=frozenset({"ws", "wss"}),
            ),
        )
        object.__setattr__(self, "params", _public_params(self.params))


@dataclass(frozen=True, slots=True)
class RestPlanItem:
    id: str
    exchange: Exchange
    market: Market
    instrument_key: str | None
    wire_symbol: str | None
    endpoint: str
    path: str
    params: Mapping[str, PublicQueryValue | Sequence[PublicQueryValue]]
    egress_id: str
    shard_id: str
    logical_stream: str
    quota_group: str
    logical_endpoint: str
    priority: RestPriority
    endpoint_cost: Decimal
    interval_plan: IntervalPlan | None
    requires_generation: bool
    replaceable: bool
    routes: tuple[RestBudgetRoute, ...] = ()

    def __post_init__(self) -> None:
        for field in (
            "id",
            "egress_id",
            "shard_id",
            "logical_stream",
            "quota_group",
            "logical_endpoint",
        ):
            object.__setattr__(
                self,
                field,
                _nonempty_string(getattr(self, field), field=field),
            )
        _enum_member(self.exchange, Exchange, field="exchange")
        _enum_member(self.market, Market, field="market")
        if (self.instrument_key is None) != (self.wire_symbol is None):
            raise ValueError("instrument_key and wire_symbol must be present together")
        if self.instrument_key is not None:
            _nonempty_string(self.instrument_key, field="instrument_key")
            _nonempty_string(self.wire_symbol, field="wire_symbol")
        object.__setattr__(
            self,
            "endpoint",
            _public_uri(
                self.endpoint,
                field="endpoint",
                schemes=frozenset({"https"}),
            ),
        )
        if (
            type(self.path) is not str
            or not self.path.startswith("/")
            or self.path.startswith("//")
            or "?" in self.path
            or "#" in self.path
            or "\\" in self.path
            or any(
                character.isspace()
                or ord(character) < 0x20
                or 0x7F <= ord(character) <= 0x9F
                for character in self.path
            )
        ):
            raise ValueError("path must be a normalized anonymous HTTP path")
        object.__setattr__(self, "params", _public_params(self.params))
        _enum_member(self.priority, RestPriority, field="priority")
        if type(self.endpoint_cost) is not Decimal:
            raise TypeError("endpoint_cost must be Decimal")
        if not self.endpoint_cost.is_finite() or self.endpoint_cost <= 0:
            raise ValueError("endpoint_cost must be finite and positive")
        primary_route = RestBudgetRoute(
            egress_id=self.egress_id,
            budget_key=(
                self.exchange.value,
                self.quota_group,
                self.logical_endpoint,
            ),
        )
        if type(self.routes) is not tuple:
            raise TypeError("routes must be a tuple of RestBudgetRoute values")
        routes = self.routes or (primary_route,)
        if any(type(route) is not RestBudgetRoute for route in routes):
            raise TypeError("routes must contain RestBudgetRoute values")
        if routes[0] != primary_route:
            raise ValueError(
                "routes[0] must match the primary egress_id, quota_group, "
                "and logical_endpoint"
            )
        if len({route.egress_id for route in routes}) != len(routes):
            raise ValueError("routes must not repeat an egress_id")
        if any(
            route.budget_key[0] != self.exchange.value
            or route.budget_key[2] != self.logical_endpoint
            for route in routes
        ):
            raise ValueError(
                "all routes must use the plan item exchange and logical_endpoint"
            )
        object.__setattr__(self, "routes", routes)
        if self.interval_plan is not None:
            if type(self.interval_plan) is not IntervalPlan:
                raise TypeError("interval_plan must be IntervalPlan or None")
            self._validate_interval_plan(self.interval_plan)
        if type(self.requires_generation) is not bool:
            raise TypeError("requires_generation must be a bool")
        if self.requires_generation != (self.priority is RestPriority.LIVE_BOOTSTRAP):
            raise ValueError(
                "generation affinity is reserved for LIVE_BOOTSTRAP plan items"
            )
        if self.requires_generation and self.interval_plan is not None:
            raise ValueError("REST bootstrap plan items must be one-shot")
        if self.requires_generation and len(self.routes) != 1:
            raise ValueError("REST bootstrap plan items require exactly one route")
        if type(self.replaceable) is not bool:
            raise TypeError("replaceable must be a bool")
        if self.replaceable and self.priority not in {
            RestPriority.DEEP_SNAPSHOT,
            RestPriority.REFERENCE_DATA,
        }:
            raise ValueError(
                "only deep snapshot and reference items may be replaceable"
            )

    @staticmethod
    def _validate_interval_plan(plan: IntervalPlan) -> None:
        if (
            type(plan.requested_ns) is not int
            or plan.requested_ns <= 0
            or type(plan.effective_ns) is not int
            or plan.effective_ns < plan.requested_ns
        ):
            raise ValueError("interval_plan must contain valid positive intervals")
        warning = plan.warning
        if plan.effective_ns == plan.requested_ns:
            if warning is not None:
                raise ValueError("unchanged interval plan must not contain a warning")
        elif (
            warning is None
            or type(warning.requested_ns) is not int
            or warning.requested_ns != plan.requested_ns
            or type(warning.effective_ns) is not int
            or warning.effective_ns != plan.effective_ns
            or type(warning.affected_symbols) is not int
            or warning.affected_symbols <= 0
        ):
            raise ValueError(
                "stretched interval plan requires matching warning evidence"
            )

    def materialize(
        self,
        *,
        ready_monotonic_ns: int,
        scheduled_ns: int,
        attempt: int = 1,
        deadline_ns: int | None = None,
        generation: ConnectionGeneration | None = None,
    ) -> ScheduledRestJob:
        if self.requires_generation:
            if type(generation) is not ConnectionGeneration:
                raise ValueError("REST bootstrap requires a connection generation")
            if generation.egress_id != self.egress_id:
                raise ValueError(
                    "REST bootstrap generation must use the planned egress"
                )
            generation_source = generation.source_context()
        else:
            if generation is not None:
                raise ValueError("independent REST item cannot bind to a generation")
            generation_source = None
        interval = (
            None
            if self.interval_plan is None
            else RestIntervalContext(
                requested_interval_ns=self.interval_plan.requested_ns,
                effective_interval_ns=self.interval_plan.effective_ns,
            )
        )
        return ScheduledRestJob(
            id=f"{self.id}:{scheduled_ns}:{attempt}",
            priority=self.priority,
            routes=self.routes,
            endpoint_cost=self.endpoint_cost,
            ready_monotonic_ns=ready_monotonic_ns,
            deadline_ns=deadline_ns,
            interval=interval,
            generation_source=generation_source,
            attempt=attempt,
            logical_key=(
                self.exchange.value,
                self.market.value,
                self.instrument_key or "_market",
                self.logical_stream,
            ),
            replaceable=self.replaceable,
            scheduled_ns=scheduled_ns,
            control_context={
                "plan_item_id": self.id,
                "shard_id": self.shard_id,
            },
        )


@dataclass(frozen=True, slots=True)
class StreamExpectation:
    market: Market | None
    instrument_key: str | None
    logical_stream: str
    shard_id: str
    coverage: CoverageMode = CoverageMode.COMPLETE

    def __post_init__(self) -> None:
        if self.market is not None:
            _enum_member(self.market, Market, field="market")
        if self.instrument_key is not None:
            object.__setattr__(
                self,
                "instrument_key",
                _nonempty_string(self.instrument_key, field="instrument_key"),
            )
        for field in ("logical_stream", "shard_id"):
            object.__setattr__(
                self,
                field,
                _nonempty_string(getattr(self, field), field=field),
            )
        _enum_member(self.coverage, CoverageMode, field="coverage")
        if self.logical_stream == "_control":
            if (
                self.market is not None
                or self.instrument_key is not None
                or self.shard_id != "_control"
            ):
                raise ValueError("_control expectation must be exchange-scoped")
        elif self.shard_id == "_control":
            raise ValueError("non-control expectation cannot use the _control shard")
        elif self.market is None:
            raise ValueError("non-control expectation requires a market")
        elif (
            self.logical_stream not in MARKET_SCOPED_STREAMS
            and self.instrument_key is None
        ):
            raise ValueError("instrument-scoped expectation requires an instrument")

    @property
    def key(self) -> tuple[Market | None, str | None, str, str]:
        return (
            self.market,
            self.instrument_key,
            self.logical_stream,
            self.shard_id,
        )


@dataclass(frozen=True, slots=True)
class AdapterPlan:
    exchange: Exchange
    ws: tuple[WebSocketSubscription, ...]
    rest: tuple[RestPlanItem, ...]
    expectations: tuple[StreamExpectation, ...]
    disabled_optional_features: tuple[str, ...]
    catalog: tuple[RestPlanItem, ...] = ()
    instruments: tuple[InstrumentRecord, ...] = ()
    egress_quota_groups: Mapping[str, str] = dataclass_field(default_factory=dict)

    def __post_init__(self) -> None:
        _enum_member(self.exchange, Exchange, field="exchange")
        self._validate_tuple(self.ws, WebSocketSubscription, field="ws")
        self._validate_tuple(self.rest, RestPlanItem, field="rest")
        self._validate_tuple(self.catalog, RestPlanItem, field="catalog")
        self._validate_tuple(
            self.expectations,
            StreamExpectation,
            field="expectations",
        )
        if type(self.instruments) is not tuple or any(
            not isinstance(item, InstrumentRecord) for item in self.instruments
        ):
            raise TypeError("instruments must be a tuple of InstrumentRecord values")
        instruments = tuple(
            sorted(
                self.instruments,
                key=lambda item: (item.market.value, item.instrument_key),
            )
        )
        instrument_keys = tuple(
            (item.market, item.instrument_key) for item in instruments
        )
        if len(set(instrument_keys)) != len(instrument_keys):
            raise ValueError("plan instruments must be unique per market")
        if any(item.exchange is not self.exchange for item in instruments):
            raise ValueError("plan instruments must belong to the plan exchange")
        object.__setattr__(self, "instruments", instruments)
        if type(self.disabled_optional_features) is not tuple or any(
            type(item) is not str or not item
            for item in self.disabled_optional_features
        ):
            raise TypeError("disabled_optional_features must be a tuple of strings")
        if len(set(self.disabled_optional_features)) != len(
            self.disabled_optional_features
        ):
            raise ValueError("disabled_optional_features must be unique")
        if not isinstance(self.egress_quota_groups, Mapping):
            raise TypeError("egress_quota_groups must be a mapping")
        egress_quota_groups: dict[str, str] = {}
        for egress_id, quota_group in self.egress_quota_groups.items():
            normalized_egress = _nonempty_string(egress_id, field="egress ID")
            normalized_quota = _nonempty_string(quota_group, field="quota group")
            egress_quota_groups[normalized_egress] = normalized_quota
        object.__setattr__(
            self,
            "egress_quota_groups",
            MappingProxyType(dict(sorted(egress_quota_groups.items()))),
        )
        ids = (
            tuple(item.id for item in self.ws)
            + tuple(item.id for item in self.rest)
            + tuple(item.id for item in self.catalog)
        )
        if len(set(ids)) != len(ids):
            raise ValueError("plan item IDs must be unique")
        expectation_keys = tuple(item.key for item in self.expectations)
        if len(set(expectation_keys)) != len(expectation_keys):
            raise ValueError("stream expectations must be unique")
        expected = set(expectation_keys)
        for ws_item in self.ws:
            if egress_quota_groups.get(ws_item.egress_id) != ws_item.quota_group:
                raise ValueError(
                    f"WebSocket item {ws_item.id!r} has no exact egress quota mapping"
                )
            if not self._has_expectation(
                expected,
                market=ws_item.market,
                instrument_key=ws_item.instrument_key,
                logical_stream=ws_item.logical_stream,
                shard_id=ws_item.shard_id,
            ):
                raise ValueError(
                    f"missing stream expectation for plan item {ws_item.id!r}"
                )
        for rest_item in (*self.rest, *self.catalog):
            if rest_item.exchange is not self.exchange:
                raise ValueError("REST item exchange does not match plan")
            for route in rest_item.routes:
                if egress_quota_groups.get(route.egress_id) != route.budget_key[1]:
                    raise ValueError(
                        f"REST item {rest_item.id!r} has no exact egress quota mapping"
                    )
            if not self._has_expectation(
                expected,
                market=rest_item.market,
                instrument_key=rest_item.instrument_key,
                logical_stream=rest_item.logical_stream,
                shard_id=rest_item.shard_id,
            ):
                raise ValueError(
                    f"missing stream expectation for plan item {rest_item.id!r}"
                )
        indexed = set(instrument_keys)
        referenced = (
            {
                (item.market, item.instrument_key)
                for item in self.ws
                if item.instrument_key is not None
            }
            | {
                (item.market, item.instrument_key)
                for item in self.rest
                if item.instrument_key is not None
            }
            | {
                (item.market, item.instrument_key)
                for item in self.catalog
                if item.instrument_key is not None
            }
            | {
                (item.market, item.instrument_key)
                for item in self.expectations
                if item.market is not None and item.instrument_key is not None
            }
        )
        missing = referenced - indexed
        if missing:
            detail = ", ".join(
                f"{market.value}/{instrument_key}"
                for market, instrument_key in sorted(
                    missing,
                    key=lambda item: (item[0].value, item[1]),
                )
            )
            raise ValueError(f"plan instruments do not cover {detail}")

    @staticmethod
    def _validate_tuple(value: object, expected: type[Any], *, field: str) -> None:
        if type(value) is not tuple or any(
            type(item) is not expected for item in value
        ):
            raise TypeError(f"{field} must be a tuple of {expected.__name__}")

    @staticmethod
    def _has_expectation(
        expectations: set[tuple[Market | None, str | None, str, str]],
        *,
        market: Market,
        instrument_key: str | None,
        logical_stream: str,
        shard_id: str,
    ) -> bool:
        return (market, instrument_key, logical_stream, shard_id) in expectations

    def expected_logical_streams(self) -> frozenset[str]:
        return frozenset(item.logical_stream for item in self.expectations)


class PublicHttpTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        params: PublicQueryParams | None = None,
        timeout: float | None = None,
    ) -> Awaitable[httpx.Response]:
        """Return a fully-read response whose ``content`` is immediately available."""

        ...


class PublicWebSocketTransport(Protocol):
    def connect(self, uri: str) -> Any: ...


class RestSchedulerPort(Protocol):
    """Worker-private scheduler boundary used by exactly one exchange adapter."""

    async def submit(self, job: ScheduledRestJob) -> SubmitResult:
        """Commit cancellation-atomically.

        A cancellation that escapes guarantees the job was not committed. Once
        committed, implementations must return ``SubmitResult`` without another
        cancellation point.
        """
        ...

    async def next_ready(self) -> RestDispatch: ...


class StopToken(Protocol):
    """Level-triggered stop signal; wait() returns only after is_set() is true."""

    def is_set(self) -> bool: ...

    async def wait(self) -> None: ...


class RetryEffectsPort(Protocol):
    def apply(self, dispatch: RestDispatch, decision: RetryDecision) -> None: ...


class NetworkAdmissionExpired(TimeoutError):
    """Network work was not admitted before its scheduler deadline."""


class NetworkAdmissionReleaseError(RuntimeError):
    """An admission lease could not be safely released or poisoned."""


class NetworkAdmissionReleaseDisposition(str, Enum):
    NORMAL = "normal"
    FAIL_CLOSED = "fail_closed"


async def _invoke_network_admission_release(
    callback: Callable[[NetworkAdmissionReleaseDisposition], Awaitable[None]],
    disposition: NetworkAdmissionReleaseDisposition,
) -> bool:
    try:
        await callback(disposition)
    except BaseException:  # noqa: BLE001 - provider details never cross the port.
        return False
    return True


class _NetworkAdmissionReleaseState:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.task: asyncio.Future[bool] | None = None
        self.disposition: NetworkAdmissionReleaseDisposition | None = None

    async def close(
        self,
        release: Callable[[NetworkAdmissionReleaseDisposition], Awaitable[None]],
        disposition: NetworkAdmissionReleaseDisposition,
    ) -> None:
        async with self.lock:
            if self.task is None:
                self.disposition = disposition
                coroutine = _invoke_network_admission_release(release, disposition)
                try:
                    self.task = asyncio.create_task(coroutine)
                except BaseException:  # noqa: BLE001 - memoize a safe setup failure.
                    coroutine.close()
                    failed = asyncio.get_running_loop().create_future()
                    failed.set_result(False)
                    self.task = failed
                del coroutine
            task = self.task
        del release
        cancellation: asyncio.CancelledError | None = None
        while not task.done():
            try:
                await asyncio.shield(task)
            except asyncio.CancelledError as error:
                if cancellation is None:
                    cancellation = error
        released = task.result()
        if cancellation is not None:
            if not released:
                cancellation.add_note("network admission release also failed")
            raise cancellation
        if not released:
            raise NetworkAdmissionReleaseError(
                "network admission release failed"
            ) from None


@dataclass(frozen=True, slots=True)
class NetworkAdmissionLease:
    """One exact admitted identity held for an I/O attempt or generation.

    The release callback must atomically apply its disposition before releasing
    capacity or waking waiters. If it raises, the coordinator must keep the
    identity held or poisoned; callers never downgrade a failed release.
    """

    exchange: Exchange
    transport: Transport
    egress_id: str
    quota_group: str
    _release: Callable[[NetworkAdmissionReleaseDisposition], Awaitable[None]] = (
        dataclass_field(
            repr=False,
            compare=False,
        )
    )
    _release_state: _NetworkAdmissionReleaseState = dataclass_field(
        default_factory=_NetworkAdmissionReleaseState,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        _enum_member(self.exchange, Exchange, field="exchange")
        _enum_member(self.transport, Transport, field="transport")
        object.__setattr__(
            self,
            "egress_id",
            _nonempty_string(self.egress_id, field="egress_id"),
        )
        object.__setattr__(
            self,
            "quota_group",
            _nonempty_string(self.quota_group, field="quota_group"),
        )
        if not callable(self._release):
            raise TypeError("network admission lease release must be callable")

    async def aclose(self) -> None:
        await self._release_state.close(
            self._release,
            NetworkAdmissionReleaseDisposition.NORMAL,
        )

    async def fail_closed(self) -> None:
        await self._release_state.close(
            self._release,
            NetworkAdmissionReleaseDisposition.FAIL_CLOSED,
        )

    @property
    def release_disposition(self) -> NetworkAdmissionReleaseDisposition | None:
        return self._release_state.disposition

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        del exc_type, exc_value, traceback
        await self.aclose()


class NetworkAdmissionPort(Protocol):
    async def acquire(
        self,
        *,
        exchange: Exchange,
        transport: Transport,
        egress_id: str,
        quota_group: str,
        deadline_monotonic_ns: int | None,
    ) -> NetworkAdmissionLease: ...


class TransportHealthPort(Protocol):
    """Narrow runtime boundary for egress health and WS generation selection."""

    def is_egress_available(
        self,
        *,
        exchange: Exchange,
        egress_id: str,
    ) -> bool: ...

    def choose_websocket_egress(
        self,
        *,
        exchange: Exchange,
        market: Market,
        endpoint: str,
        preferred_egress_id: str,
        previous_egress_id: str | None,
    ) -> str: ...

    def record_transport_failure(
        self,
        *,
        exchange: Exchange,
        transport: Transport,
        egress_id: str,
        reason: str,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class AdapterRetrySettings:
    rest_max_attempts: int = 5
    base_backoff_ns: int = 250_000_000
    max_backoff_ns: int = 30_000_000_000
    ws_reconnect_max_backoff_ns: int = 60_000_000_000

    def __post_init__(self) -> None:
        for field_name in (
            "rest_max_attempts",
            "base_backoff_ns",
            "max_backoff_ns",
            "ws_reconnect_max_backoff_ns",
        ):
            value = getattr(self, field_name)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
        if self.base_backoff_ns > self.max_backoff_ns:
            raise ValueError("base_backoff_ns must not exceed max_backoff_ns")
        if self.base_backoff_ns > self.ws_reconnect_max_backoff_ns:
            raise ValueError(
                "base_backoff_ns must not exceed ws_reconnect_max_backoff_ns"
            )


@dataclass(frozen=True, slots=True)
class EgressTransport:
    egress_id: str
    http: PublicHttpTransport
    websocket: PublicWebSocketTransport

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "egress_id",
            _nonempty_string(self.egress_id, field="egress_id"),
        )
        if not callable(getattr(self.http, "get", None)):
            raise TypeError("http transport must provide get()")
        if not callable(getattr(self.websocket, "connect", None)):
            raise TypeError("websocket transport must provide connect()")


class _AdapterRuntimeRunState:
    def __init__(self) -> None:
        self._lock = Lock()
        self._state = "fresh"

    def claim(self) -> None:
        with self._lock:
            if self._state != "fresh":
                raise RuntimeError("adapter runtime is single-use")
            self._state = "run_claimed"

    def ensure_unclaimed(self) -> None:
        with self._lock:
            if self._state == "run_claimed":
                raise RuntimeError("adapter runtime has already been consumed")
            if self._state == "poisoned":
                raise RuntimeError("adapter runtime is poisoned")

    def poison(self) -> None:
        with self._lock:
            if self._state == "fresh":
                self._state = "poisoned"


@dataclass(frozen=True, slots=True)
class AdapterRuntime:
    """Worker-private, single-run network and scheduler resources."""

    transports: Mapping[str, EgressTransport]
    scheduler: RestSchedulerPort
    clock: Clock
    stop: StopToken
    retry: AdapterRetrySettings = dataclass_field(default_factory=AdapterRetrySettings)
    retry_effects: RetryEffectsPort | None = None
    transport_health: TransportHealthPort | None = None
    network_admission: NetworkAdmissionPort | None = None
    _run_state: _AdapterRuntimeRunState = dataclass_field(
        default_factory=_AdapterRuntimeRunState,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if not isinstance(self.transports, Mapping) or not self.transports:
            raise ValueError("transports must be a non-empty mapping")
        normalized: dict[str, EgressTransport] = {}
        for egress_id, transport in self.transports.items():
            key = _nonempty_string(egress_id, field="transport egress ID")
            if type(transport) is not EgressTransport or transport.egress_id != key:
                raise ValueError("transport mapping key must match its egress ID")
            normalized[key] = transport
        if not callable(getattr(self.scheduler, "submit", None)) or not callable(
            getattr(self.scheduler, "next_ready", None)
        ):
            raise TypeError("scheduler must provide submit() and next_ready()")
        if not callable(getattr(self.clock, "time_ns", None)) or not callable(
            getattr(self.clock, "monotonic_ns", None)
        ):
            raise TypeError("clock must provide time_ns() and monotonic_ns()")
        if not callable(getattr(self.stop, "is_set", None)) or not callable(
            getattr(self.stop, "wait", None)
        ):
            raise TypeError("stop token must provide is_set() and wait()")
        if type(self.retry) is not AdapterRetrySettings:
            raise TypeError("retry must be AdapterRetrySettings")
        if self.retry_effects is not None and not callable(
            getattr(self.retry_effects, "apply", None)
        ):
            raise TypeError("retry_effects must provide apply()")
        if self.transport_health is not None and (
            not callable(getattr(self.transport_health, "is_egress_available", None))
            or not callable(
                getattr(self.transport_health, "choose_websocket_egress", None)
            )
            or not callable(
                getattr(self.transport_health, "record_transport_failure", None)
            )
        ):
            raise TypeError(
                "transport_health must provide is_egress_available(), "
                "choose_websocket_egress(), and record_transport_failure()"
            )
        if self.network_admission is not None and not callable(
            getattr(self.network_admission, "acquire", None)
        ):
            raise TypeError("network_admission must provide acquire()")
        object.__setattr__(self, "transports", MappingProxyType(normalized))

    def transport_for(self, egress_id: str) -> EgressTransport:
        try:
            return self.transports[egress_id]
        except KeyError:
            raise LookupError(
                f"runtime egress {egress_id!r} is not available"
            ) from None

    def claim_run(self) -> None:
        self._run_state.claim()

    def ensure_run_not_claimed(self) -> None:
        self._run_state.ensure_unclaimed()

    def poison(self) -> None:
        """Prevent reuse after terminal standalone adapter work."""

        self._run_state.poison()

    async def aclose(self) -> None:
        closed: set[int] = set()
        first_error: Exception | None = None
        for transport in self.transports.values():
            http = transport.http
            identity = id(http)
            if identity in closed:
                continue
            closed.add(identity)
            close = getattr(http, "aclose", None)
            if callable(close):
                try:
                    await close()
                except Exception as error:  # noqa: BLE001 - close remaining clients.
                    if first_error is None:
                        first_error = error
        if first_error is not None:
            raise first_error


class EventSink(Protocol):
    def try_emit(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> EnqueueResult: ...


class ExchangeAdapter(Protocol):
    exchange: Exchange

    async def fetch_catalog(
        self,
        runtime: AdapterRuntime,
        market: Market,
    ) -> InstrumentCatalog: ...

    def plan(self, request: CollectionRequest) -> AdapterPlan: ...

    async def run(
        self,
        plan: AdapterPlan,
        runtime: AdapterRuntime,
        sink: EventSink,
    ) -> None: ...
