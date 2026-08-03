from __future__ import annotations

from collections.abc import Awaitable, Mapping, Sequence
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from decimal import Decimal
from math import isfinite
from types import MappingProxyType
from typing import Any, Protocol, Self, TypeAlias
from urllib.parse import urlsplit

import httpx
from pydantic import ConfigDict, model_validator

from crypto_collector.config.probe_contracts import (
    ExchangeProbeEvidence,
    ProbeProvider,
)
from crypto_collector.domain import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    NativeEventDraft,
    SourceContext,
)
from crypto_collector.domain.clock import Clock
from crypto_collector.domain.envelope import MARKET_SCOPED_STREAMS, FrozenStrictModel
from crypto_collector.scheduler import (
    IntervalPlan,
    RestBudgetRoute,
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
            routes=(
                RestBudgetRoute(
                    egress_id=self.egress_id,
                    budget_key=(
                        self.exchange.value,
                        self.quota_group,
                        self.logical_endpoint,
                    ),
                ),
            ),
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

    def __post_init__(self) -> None:
        _enum_member(self.exchange, Exchange, field="exchange")
        self._validate_tuple(self.ws, WebSocketSubscription, field="ws")
        self._validate_tuple(self.rest, RestPlanItem, field="rest")
        self._validate_tuple(
            self.expectations,
            StreamExpectation,
            field="expectations",
        )
        if type(self.disabled_optional_features) is not tuple or any(
            type(item) is not str or not item
            for item in self.disabled_optional_features
        ):
            raise TypeError("disabled_optional_features must be a tuple of strings")
        if len(set(self.disabled_optional_features)) != len(
            self.disabled_optional_features
        ):
            raise ValueError("disabled_optional_features must be unique")
        ids = tuple(item.id for item in self.ws) + tuple(item.id for item in self.rest)
        if len(set(ids)) != len(ids):
            raise ValueError("plan item IDs must be unique")
        expectation_keys = tuple(item.key for item in self.expectations)
        if len(set(expectation_keys)) != len(expectation_keys):
            raise ValueError("stream expectations must be unique")
        expected = set(expectation_keys)
        for ws_item in self.ws:
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
        for rest_item in self.rest:
            if rest_item.exchange is not self.exchange:
                raise ValueError("REST item exchange does not match plan")
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
        if instrument_key is not None:
            return (market, instrument_key, logical_stream, shard_id) in expectations
        return any(
            expected_market is market
            and expected_stream == logical_stream
            and expected_shard == shard_id
            for (
                expected_market,
                _expected_instrument,
                expected_stream,
                expected_shard,
            ) in expectations
        )

    def expected_logical_streams(self) -> frozenset[str]:
        return frozenset(item.logical_stream for item in self.expectations)


class PublicHttpTransport(Protocol):
    def get(
        self,
        url: str,
        *,
        params: PublicQueryParams | None = None,
        timeout: float | None = None,
    ) -> Awaitable[httpx.Response]: ...


class PublicWebSocketTransport(Protocol):
    def connect(self, uri: str) -> Any: ...


class RestSchedulerPort(Protocol):
    async def submit(self, job: ScheduledRestJob) -> SubmitResult: ...


class StopToken(Protocol):
    def is_set(self) -> bool: ...

    async def wait(self) -> None: ...


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


@dataclass(frozen=True, slots=True)
class AdapterRuntime:
    transports: Mapping[str, EgressTransport]
    scheduler: RestSchedulerPort
    clock: Clock
    stop: StopToken

    def __post_init__(self) -> None:
        if not isinstance(self.transports, Mapping) or not self.transports:
            raise ValueError("transports must be a non-empty mapping")
        normalized: dict[str, EgressTransport] = {}
        for egress_id, transport in self.transports.items():
            key = _nonempty_string(egress_id, field="transport egress ID")
            if type(transport) is not EgressTransport or transport.egress_id != key:
                raise ValueError("transport mapping key must match its egress ID")
            normalized[key] = transport
        if not callable(getattr(self.scheduler, "submit", None)):
            raise TypeError("scheduler must provide submit()")
        if not callable(getattr(self.clock, "time_ns", None)) or not callable(
            getattr(self.clock, "monotonic_ns", None)
        ):
            raise TypeError("clock must provide time_ns() and monotonic_ns()")
        if not callable(getattr(self.stop, "is_set", None)) or not callable(
            getattr(self.stop, "wait", None)
        ):
            raise TypeError("stop token must provide is_set() and wait()")
        object.__setattr__(self, "transports", MappingProxyType(normalized))

    def transport_for(self, egress_id: str) -> EgressTransport:
        try:
            return self.transports[egress_id]
        except KeyError:
            raise LookupError(
                f"runtime egress {egress_id!r} is not available"
            ) from None


class EventSink(Protocol):
    def try_emit(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> EnqueueResult: ...


class ExchangeAdapter(ProbeProvider, Protocol):
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
