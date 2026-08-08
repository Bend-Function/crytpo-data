from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, timedelta
from decimal import Decimal
from fractions import Fraction
from types import MappingProxyType
from typing import Literal, Never, Protocol

from crypto_collector.config.effective import EffectiveScopeConfig, effective_scope
from crypto_collector.config.loader import ConfigBundle
from crypto_collector.config.models import EgressConfig
from crypto_collector.domain.clock import Clock
from crypto_collector.domain.types import Exchange, Market
from crypto_collector.network.assignment import (
    EgressShard,
    StickyAssignment,
    assign_instruments,
    pack_egress_shards,
)
from crypto_collector.scheduler.rest import (
    CapacityError,
    IntervalPlan,
    IntervalWarning,
)
from crypto_collector.selection.capacity import (
    CapacityAdmission,
    CapacityCandidate,
    EgressCapacity,
    ScopedCapacityDemand,
    ScopedCapacityError,
    admit_exchange_capacity,
    calculate_egress_capacity,
)
from crypto_collector.selection.fixed import (
    FixedPairResolutionError,
    resolve_fixed_requests,
)
from crypto_collector.selection.models import (
    CatalogScope,
    CatalogView,
)
from crypto_collector.selection.selector import (
    AdmissionPriority,
    ResolvedFixedSelection,
    SelectionDelta,
    SelectionEntry,
    SelectionPolicy,
    SelectionResult,
    SelectionState,
    select,
)

_MAX_INT64 = 2**63 - 1
_DAY_NS = 86_400_000_000_000
_UNIX_EPOCH_DATE = date(1970, 1, 1)


def _integer(value: object, *, field: str, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field} must be {qualifier}")
    if value > _MAX_INT64:
        raise ValueError(f"{field} must fit a signed 64-bit integer")
    return value


def _exact_integer(value: object, *, field: str, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field} must be {qualifier}")
    return value


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _sha256(value: object, *, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _decimal(
    value: object,
    *,
    field: str,
    positive: bool,
) -> Decimal:
    if type(value) is not Decimal:
        raise TypeError(f"{field} must be Decimal")
    if not value.is_finite() or (value <= 0 if positive else value < 0):
        qualifier = "positive" if positive else "non-negative"
        raise ValueError(f"{field} must be finite and {qualifier}")
    return value


@dataclass(frozen=True, slots=True)
class PublicTimeProbe:
    exchange_time_ns: int
    observed_at_ns: int
    raw_reference: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "exchange_time_ns",
            _integer(self.exchange_time_ns, field="exchange_time_ns"),
        )
        object.__setattr__(
            self,
            "observed_at_ns",
            _integer(self.observed_at_ns, field="observed_at_ns"),
        )
        object.__setattr__(
            self,
            "raw_reference",
            _nonempty(self.raw_reference, field="raw_reference"),
        )


@dataclass(frozen=True, slots=True)
class TransportReachabilityProbe:
    transport: Literal["http", "websocket"]
    endpoint_role: str
    reachable: bool
    observed_at_ns: int
    raw_reference: str

    def __post_init__(self) -> None:
        if type(self.transport) is not str or self.transport not in {
            "http",
            "websocket",
        }:
            raise ValueError("transport must be http or websocket")
        object.__setattr__(
            self,
            "endpoint_role",
            _nonempty(self.endpoint_role, field="endpoint_role"),
        )
        if type(self.reachable) is not bool:
            raise TypeError("reachable must be a boolean")
        object.__setattr__(
            self,
            "observed_at_ns",
            _integer(self.observed_at_ns, field="observed_at_ns"),
        )
        object.__setattr__(
            self,
            "raw_reference",
            _nonempty(self.raw_reference, field="raw_reference"),
        )


@dataclass(frozen=True, slots=True)
class EgressReachabilityProbe:
    egress_id: str
    reachable: bool
    observed_at_ns: int
    raw_reference: str
    transports: tuple[TransportReachabilityProbe, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "egress_id", _nonempty(self.egress_id, field="egress_id")
        )
        if type(self.reachable) is not bool:
            raise TypeError("reachable must be a boolean")
        object.__setattr__(
            self,
            "observed_at_ns",
            _integer(self.observed_at_ns, field="observed_at_ns"),
        )
        object.__setattr__(
            self,
            "raw_reference",
            _nonempty(self.raw_reference, field="raw_reference"),
        )
        if type(self.transports) is not tuple or any(
            type(item) is not TransportReachabilityProbe for item in self.transports
        ):
            raise TypeError("transports must be a tuple of TransportReachabilityProbe")
        keys = tuple((item.transport, item.endpoint_role) for item in self.transports)
        if len(set(keys)) != len(keys):
            raise ValueError("transport reachability keys must be unique")
        if self.transports:
            kinds = {item.transport for item in self.transports}
            if kinds != {"http", "websocket"}:
                raise ValueError(
                    "detailed reachability must include HTTP and WebSocket evidence"
                )
            if self.reachable is not all(item.reachable for item in self.transports):
                raise ValueError(
                    "egress reachable must equal all detailed transport evidence"
                )
            if self.observed_at_ns != max(
                item.observed_at_ns for item in self.transports
            ):
                raise ValueError(
                    "egress observed_at_ns must equal the latest transport observation"
                )
        object.__setattr__(
            self,
            "transports",
            tuple(
                sorted(
                    self.transports,
                    key=lambda item: (item.transport, item.endpoint_role),
                )
            ),
        )

    @property
    def http_reachable(self) -> bool:
        if not self.transports:
            return self.reachable
        return all(
            item.reachable for item in self.transports if item.transport == "http"
        )

    @property
    def websocket_reachable(self) -> bool:
        if not self.transports:
            return self.reachable
        return all(
            item.reachable for item in self.transports if item.transport == "websocket"
        )


@dataclass(frozen=True, slots=True)
class DateGateProbe:
    feature_id: str
    available: bool
    observed_at_ns: int
    raw_reference: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "feature_id",
            _nonempty(self.feature_id, field="feature_id"),
        )
        if type(self.available) is not bool:
            raise TypeError("available must be a boolean")
        object.__setattr__(
            self,
            "observed_at_ns",
            _integer(self.observed_at_ns, field="observed_at_ns"),
        )
        object.__setattr__(
            self,
            "raw_reference",
            _nonempty(self.raw_reference, field="raw_reference"),
        )


@dataclass(frozen=True, slots=True, init=False)
class EndpointBudgetProbe:
    quota_group: str
    logical_endpoint: str
    available_tokens_per_second: Decimal
    observed_at_ns: int
    raw_reference: str

    def __init__(
        self,
        quota_group: str,
        logical_endpoint: str,
        available_tokens_per_second: Decimal,
        *,
        observed_at_ns: int,
        raw_reference: str,
    ) -> None:
        object.__setattr__(
            self,
            "quota_group",
            _nonempty(quota_group, field="quota_group"),
        )
        object.__setattr__(
            self,
            "logical_endpoint",
            _nonempty(logical_endpoint, field="logical_endpoint"),
        )
        object.__setattr__(
            self,
            "available_tokens_per_second",
            _decimal(
                available_tokens_per_second,
                field="available_tokens_per_second",
                positive=False,
            ),
        )
        object.__setattr__(
            self,
            "observed_at_ns",
            _integer(observed_at_ns, field="observed_at_ns"),
        )
        object.__setattr__(
            self,
            "raw_reference",
            _nonempty(raw_reference, field="raw_reference"),
        )


@dataclass(frozen=True, slots=True, init=False)
class EndpointWork:
    logical_endpoint: str
    kind: Literal["deep_snapshot", "periodic_reference"]
    depth: int | Literal["max_supported"] | None
    cost: Decimal
    jobs_per_instrument: int
    jobs_per_market: int
    requested_interval_ns: int | None
    observed_at_ns: int
    raw_reference: str

    def __init__(
        self,
        logical_endpoint: str,
        cost: Decimal,
        *,
        jobs_per_instrument: int,
        jobs_per_market: int = 0,
        kind: Literal["deep_snapshot", "periodic_reference"] = "deep_snapshot",
        depth: int | Literal["max_supported"] | None = None,
        requested_interval_ns: int | None = None,
        observed_at_ns: int,
        raw_reference: str,
    ) -> None:
        object.__setattr__(
            self,
            "logical_endpoint",
            _nonempty(logical_endpoint, field="logical_endpoint"),
        )
        if type(kind) is not str or kind not in {
            "deep_snapshot",
            "periodic_reference",
        }:
            raise ValueError(
                "endpoint work kind must be deep_snapshot or periodic_reference"
            )
        if kind == "deep_snapshot":
            depth = "max_supported" if depth is None else depth
            if depth != "max_supported":
                depth = _integer(depth, field="endpoint work depth", minimum=1)
            if requested_interval_ns is not None:
                raise ValueError(
                    "deep snapshot workload cadence comes from effective config"
                )
        else:
            if depth is not None:
                raise ValueError("periodic reference workload must not declare depth")
            requested_interval_ns = _integer(
                requested_interval_ns,
                field="periodic reference requested_interval_ns",
                minimum=1,
            )
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "depth", depth)
        object.__setattr__(
            self,
            "cost",
            _decimal(cost, field="cost", positive=True),
        )
        object.__setattr__(
            self,
            "jobs_per_instrument",
            _integer(jobs_per_instrument, field="jobs_per_instrument"),
        )
        object.__setattr__(
            self,
            "jobs_per_market",
            _integer(jobs_per_market, field="jobs_per_market"),
        )
        if self.jobs_per_instrument == 0 and self.jobs_per_market == 0:
            raise ValueError("endpoint work must schedule a positive number of jobs")
        if kind == "deep_snapshot" and (
            self.jobs_per_instrument == 0 or self.jobs_per_market != 0
        ):
            raise ValueError(
                "deep snapshot work must schedule only per-instrument jobs"
            )
        object.__setattr__(self, "requested_interval_ns", requested_interval_ns)
        object.__setattr__(
            self,
            "observed_at_ns",
            _integer(observed_at_ns, field="endpoint work observed_at_ns"),
        )
        object.__setattr__(
            self,
            "raw_reference",
            _nonempty(raw_reference, field="endpoint work raw_reference"),
        )


@dataclass(frozen=True, slots=True)
class MarketProbeEvidence:
    catalog: CatalogView
    subscriptions_per_connection: int
    subscriptions_per_instrument: int
    endpoint_work: tuple[EndpointWork, ...] = ()

    def __post_init__(self) -> None:
        if type(self.catalog) is not CatalogView or self.catalog.catalog_revision <= 0:
            raise ValueError("catalog must be a complete CatalogView")
        object.__setattr__(
            self,
            "subscriptions_per_connection",
            _integer(
                self.subscriptions_per_connection,
                field="subscriptions_per_connection",
                minimum=1,
            ),
        )
        object.__setattr__(
            self,
            "subscriptions_per_instrument",
            _integer(
                self.subscriptions_per_instrument,
                field="subscriptions_per_instrument",
                minimum=1,
            ),
        )
        if type(self.endpoint_work) is not tuple or any(
            type(item) is not EndpointWork for item in self.endpoint_work
        ):
            raise TypeError("endpoint_work must be a tuple of EndpointWork")
        identities = tuple(
            (item.kind, item.logical_endpoint, item.depth)
            for item in self.endpoint_work
        )
        if len(set(identities)) != len(identities):
            raise ValueError("endpoint_work identities must be unique")
        object.__setattr__(
            self,
            "endpoint_work",
            tuple(
                sorted(
                    self.endpoint_work,
                    key=lambda item: (
                        item.kind,
                        item.logical_endpoint,
                        str(item.depth),
                    ),
                )
            ),
        )

    @property
    def scope(self) -> CatalogScope:
        return self.catalog.scope


@dataclass(frozen=True, slots=True)
class ExchangeProbeEvidence:
    exchange: Exchange
    public_time: PublicTimeProbe
    egresses: tuple[EgressReachabilityProbe, ...]
    markets: tuple[MarketProbeEvidence, ...]
    endpoint_budgets: tuple[EndpointBudgetProbe, ...] = ()
    date_gates: tuple[DateGateProbe, ...] = ()

    def __post_init__(self) -> None:
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        if type(self.public_time) is not PublicTimeProbe:
            raise TypeError("public_time must be PublicTimeProbe")
        self._validate_tuple(
            self.egresses,
            expected=EgressReachabilityProbe,
            field="egresses",
        )
        self._validate_tuple(
            self.markets,
            expected=MarketProbeEvidence,
            field="markets",
        )
        self._validate_tuple(
            self.endpoint_budgets,
            expected=EndpointBudgetProbe,
            field="endpoint_budgets",
        )
        self._validate_tuple(
            self.date_gates,
            expected=DateGateProbe,
            field="date_gates",
        )
        if any(item.scope.exchange is not self.exchange for item in self.markets):
            raise ValueError("market probe scope does not match exchange")
        self._require_unique(
            tuple(item.egress_id for item in self.egresses),
            field="egress probe IDs",
        )
        self._require_unique(
            tuple(item.scope.market for item in self.markets),
            field="market probe scopes",
        )
        self._require_unique(
            tuple(
                (item.quota_group, item.logical_endpoint)
                for item in self.endpoint_budgets
            ),
            field="endpoint budget keys",
        )
        self._require_unique(
            tuple(item.feature_id for item in self.date_gates),
            field="date gate features",
        )
        object.__setattr__(
            self,
            "egresses",
            tuple(sorted(self.egresses, key=lambda item: item.egress_id)),
        )
        object.__setattr__(
            self,
            "markets",
            tuple(sorted(self.markets, key=lambda item: item.scope.market.value)),
        )
        object.__setattr__(
            self,
            "endpoint_budgets",
            tuple(
                sorted(
                    self.endpoint_budgets,
                    key=lambda item: (item.quota_group, item.logical_endpoint),
                )
            ),
        )
        object.__setattr__(
            self,
            "date_gates",
            tuple(sorted(self.date_gates, key=lambda item: item.feature_id)),
        )

    @staticmethod
    def _validate_tuple(value: object, *, expected: type[object], field: str) -> None:
        if type(value) is not tuple or any(
            type(item) is not expected for item in value
        ):
            raise TypeError(f"{field} must be a tuple of {expected.__name__}")

    @staticmethod
    def _require_unique(value: tuple[object, ...], *, field: str) -> None:
        if len(set(value)) != len(value):
            raise ValueError(f"{field} must be unique")


@dataclass(frozen=True, slots=True)
class DateGateRequest:
    feature_id: str
    markets: tuple[Market, ...]
    required: bool
    available_from: str | None
    requires_live_probe: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "feature_id",
            _nonempty(self.feature_id, field="date gate request feature_id"),
        )
        if type(self.required) is not bool:
            raise TypeError("date gate request required must be a boolean")
        if type(self.markets) is not tuple or any(
            type(item) is not Market for item in self.markets
        ):
            raise TypeError("date gate request markets must be a tuple of Market")
        normalized_markets = tuple(
            sorted(set(self.markets), key=lambda item: item.value)
        )
        if not normalized_markets or normalized_markets != self.markets:
            raise ValueError("date gate request markets must be non-empty and sorted")
        if self.available_from is not None:
            if type(self.available_from) is not str:
                raise TypeError(
                    "date gate request available_from must be a string or None"
                )
            try:
                date.fromisoformat(self.available_from)
            except ValueError as error:
                raise ValueError(
                    "date gate request available_from must be an ISO date"
                ) from error
        if type(self.requires_live_probe) is not bool:
            raise TypeError("requires_live_probe must be a boolean")

    def archived_available_at(self, exchange_time_ns: int) -> bool:
        normalized_time = _integer(
            exchange_time_ns,
            field="date gate exchange_time_ns",
        )
        if self.available_from is None:
            return True
        exchange_date = _UNIX_EPOCH_DATE + timedelta(days=normalized_time // _DAY_NS)
        return exchange_date >= date.fromisoformat(self.available_from)


@dataclass(frozen=True, slots=True)
class ProbeRequest:
    exchange: Exchange
    markets: tuple[CatalogScope, ...]
    egress_ids: tuple[str, ...]
    initial_lookback_ns: Mapping[tuple[Market, str | None], int]
    config_sha256: str
    observed_at_ns: int
    date_gates: tuple[DateGateRequest, ...] = ()

    def __post_init__(self) -> None:
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        if type(self.markets) is not tuple or any(
            type(item) is not CatalogScope for item in self.markets
        ):
            raise TypeError("markets must be a tuple of CatalogScope")
        if not self.markets:
            raise ValueError("markets must not be empty")
        if any(item.exchange is not self.exchange for item in self.markets):
            raise ValueError("market scopes must match request exchange")
        if len({item.market for item in self.markets}) != len(self.markets):
            raise ValueError("market scopes must be unique")
        if type(self.egress_ids) is not tuple or any(
            type(item) is not str or not item for item in self.egress_ids
        ):
            raise TypeError("egress_ids must be a tuple of strings")
        if len(set(self.egress_ids)) != len(self.egress_ids):
            raise ValueError("egress_ids must be unique")
        if not isinstance(self.initial_lookback_ns, Mapping):
            raise TypeError("initial_lookback_ns must be a mapping")
        requested_markets = {item.market for item in self.markets}
        normalized_lookbacks: dict[tuple[Market, str | None], int] = {}
        for key, value in self.initial_lookback_ns.items():
            if (
                type(key) is not tuple
                or len(key) != 2
                or type(key[0]) is not Market
                or (key[1] is not None and (type(key[1]) is not str or not key[1]))
            ):
                raise TypeError(
                    "initial_lookback_ns keys must be "
                    "(Market, instrument_key | None) tuples"
                )
            if key[0] not in requested_markets:
                raise ValueError(
                    "initial_lookback_ns keys must belong to requested markets"
                )
            normalized_lookbacks[key] = _integer(
                value,
                field="initial_lookback_ns value",
            )
        base_markets = {
            market
            for market, instrument_key in normalized_lookbacks
            if instrument_key is None
        }
        if base_markets != requested_markets:
            raise ValueError(
                "initial_lookback_ns must define a market-level fallback for "
                "every requested market"
            )
        object.__setattr__(
            self,
            "initial_lookback_ns",
            MappingProxyType(
                dict(
                    sorted(
                        normalized_lookbacks.items(),
                        key=lambda item: (
                            item[0][0].value,
                            "" if item[0][1] is None else item[0][1],
                        ),
                    )
                )
            ),
        )
        object.__setattr__(
            self,
            "config_sha256",
            _sha256(self.config_sha256, field="config_sha256"),
        )
        object.__setattr__(
            self,
            "observed_at_ns",
            _integer(self.observed_at_ns, field="observed_at_ns"),
        )
        if type(self.date_gates) is not tuple or any(
            type(item) is not DateGateRequest for item in self.date_gates
        ):
            raise TypeError("date_gates must be a tuple of DateGateRequest")
        feature_ids = tuple(item.feature_id for item in self.date_gates)
        if len(set(feature_ids)) != len(feature_ids):
            raise ValueError("date gate request features must be unique")
        object.__setattr__(
            self,
            "date_gates",
            tuple(sorted(self.date_gates, key=lambda item: item.feature_id)),
        )
        if any(
            not set(item.markets).issubset(requested_markets)
            for item in self.date_gates
        ):
            raise ValueError(
                "date gate request markets must belong to the probe request"
            )

    def initial_lookback_for(
        self,
        market: Market,
        instrument_key: str,
    ) -> int:
        if type(market) is not Market:
            raise TypeError("market must be Market")
        key = _nonempty(instrument_key, field="instrument_key")
        try:
            return self.initial_lookback_ns.get(
                (market, key),
                self.initial_lookback_ns[(market, None)],
            )
        except KeyError:
            raise ValueError("market does not belong to the probe request") from None


class ProbeProvider(Protocol):
    exchange: Exchange

    async def probe(self, request: ProbeRequest) -> ExchangeProbeEvidence: ...


@dataclass(frozen=True, slots=True)
class ProbeFailure:
    exchange: Exchange
    code: str
    message: str
    market: str | None = None
    feature_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.exchange) is not Exchange:
            raise TypeError("failure exchange must be Exchange")
        object.__setattr__(self, "code", _nonempty(self.code, field="failure code"))
        object.__setattr__(
            self,
            "message",
            _nonempty(self.message, field="failure message"),
        )
        for field in ("market", "feature_id"):
            value = getattr(self, field)
            if value is not None:
                object.__setattr__(self, field, _nonempty(value, field=field))


@dataclass(frozen=True, slots=True)
class ProbeShard:
    egress_id: str
    quota_group: str
    index: int
    instrument_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "egress_id",
            _nonempty(self.egress_id, field="shard egress_id"),
        )
        object.__setattr__(
            self,
            "quota_group",
            _nonempty(self.quota_group, field="shard quota_group"),
        )
        object.__setattr__(self, "index", _integer(self.index, field="shard index"))
        if type(self.instrument_keys) is not tuple or any(
            type(item) is not str or not item for item in self.instrument_keys
        ):
            raise TypeError("shard instrument_keys must be a tuple of strings")
        if not self.instrument_keys or len(set(self.instrument_keys)) != len(
            self.instrument_keys
        ):
            raise ValueError("shard instrument_keys must be non-empty and unique")


@dataclass(frozen=True, slots=True)
class ProbeIntervalCohort:
    logical_endpoint: str
    depth: int | Literal["max_supported"] | None
    instrument_keys: tuple[str, ...]
    plan: IntervalPlan

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "logical_endpoint",
            _nonempty(self.logical_endpoint, field="cohort logical_endpoint"),
        )
        if self.depth is not None and self.depth != "max_supported":
            object.__setattr__(
                self,
                "depth",
                _integer(self.depth, field="cohort depth", minimum=1),
            )
        if type(self.instrument_keys) is not tuple or any(
            type(item) is not str or not item for item in self.instrument_keys
        ):
            raise TypeError("cohort instrument_keys must be a tuple of strings")
        if self.instrument_keys != tuple(sorted(set(self.instrument_keys))):
            raise ValueError("cohort instrument_keys must be sorted and unique")
        if self.depth is not None and not self.instrument_keys:
            raise ValueError("deep snapshot cohort instrument_keys must be non-empty")
        if type(self.plan) is not IntervalPlan:
            raise TypeError("cohort plan must be IntervalPlan")


@dataclass(frozen=True, slots=True)
class ProbeRestCapacityRejection:
    instrument_key: str
    logical_endpoint: str
    depth: int | Literal["max_supported"] | None
    requested_interval_ns: int
    cost: Decimal
    jobs_per_instrument: int
    available_rate_numerator: int
    available_rate_denominator: int
    required_rate_numerator: int
    required_rate_denominator: int
    max_effective_ns: int
    reason: Literal["max_effective_interval", "overload_policy", "zero_rate"]
    config_sha256: str

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "instrument_key",
            _nonempty(self.instrument_key, field="REST rejection instrument_key"),
        )
        object.__setattr__(
            self,
            "logical_endpoint",
            _nonempty(self.logical_endpoint, field="REST rejection logical_endpoint"),
        )
        if self.depth is not None and self.depth != "max_supported":
            object.__setattr__(
                self,
                "depth",
                _integer(self.depth, field="REST rejection depth", minimum=1),
            )
        object.__setattr__(
            self,
            "requested_interval_ns",
            _integer(
                self.requested_interval_ns,
                field="REST rejection requested_interval_ns",
                minimum=1,
            ),
        )
        object.__setattr__(
            self,
            "cost",
            _decimal(self.cost, field="REST rejection cost", positive=True),
        )
        object.__setattr__(
            self,
            "jobs_per_instrument",
            _integer(
                self.jobs_per_instrument,
                field="REST rejection jobs_per_instrument",
                minimum=1,
            ),
        )
        for field in ("available_rate_numerator", "required_rate_numerator"):
            object.__setattr__(
                self,
                field,
                _exact_integer(getattr(self, field), field=f"REST rejection {field}"),
            )
        for field in ("available_rate_denominator", "required_rate_denominator"):
            object.__setattr__(
                self,
                field,
                _exact_integer(
                    getattr(self, field),
                    field=f"REST rejection {field}",
                    minimum=1,
                ),
            )
        object.__setattr__(
            self,
            "max_effective_ns",
            _integer(
                self.max_effective_ns,
                field="REST rejection max_effective_ns",
                minimum=1,
            ),
        )
        if self.reason not in {
            "max_effective_interval",
            "overload_policy",
            "zero_rate",
        }:
            raise ValueError("unsupported REST rejection reason")
        object.__setattr__(
            self,
            "config_sha256",
            _sha256(self.config_sha256, field="REST rejection config_sha256"),
        )


@dataclass(frozen=True, slots=True)
class ProbeMarketReport:
    scope: CatalogScope
    config_sha256: str
    catalog: CatalogView
    fixed: ResolvedFixedSelection
    selection: SelectionResult
    exchange_capacity_ceiling: EgressCapacity
    admission: CapacityAdmission
    rest_rejections: tuple[ProbeRestCapacityRejection, ...]
    shards: tuple[ProbeShard, ...]
    endpoint_work: tuple[EndpointWork, ...]
    interval_cohorts: tuple[ProbeIntervalCohort, ...]
    intervals: Mapping[str, IntervalPlan]

    def __post_init__(self) -> None:
        if type(self.scope) is not CatalogScope:
            raise TypeError("market report scope must be CatalogScope")
        object.__setattr__(
            self,
            "config_sha256",
            _sha256(self.config_sha256, field="market report config_sha256"),
        )
        if type(self.catalog) is not CatalogView:
            raise TypeError("market report catalog must be CatalogView")
        if self.catalog.scope != self.scope:
            raise ValueError("market report catalog scope mismatch")
        if (
            type(self.fixed) is not ResolvedFixedSelection
            or self.fixed.scope != self.scope
            or type(self.selection) is not SelectionResult
            or self.selection.scope != self.scope
        ):
            raise ValueError("market report selection scope mismatch")
        if (
            self.fixed.catalog_revision != self.catalog.catalog_revision
            or self.selection.catalog_revision != self.catalog.catalog_revision
            or self.selection.turnover_revision != self.catalog.turnover_revision
        ):
            raise ValueError("market report catalog revision mismatch")
        if self.selection.policy_id != self.config_sha256:
            raise ValueError("market report selection config SHA mismatch")
        if not self.fixed.instrument_keys.issubset(self.selection.entries):
            raise ValueError("market report selection omits resolved fixed instruments")
        if type(self.exchange_capacity_ceiling) is not EgressCapacity:
            raise TypeError(
                "market report exchange_capacity_ceiling must be EgressCapacity"
            )
        if self.exchange_capacity_ceiling.exchange != self.scope.exchange.value:
            raise ValueError("market report capacity ceiling exchange mismatch")
        if type(self.admission) is not CapacityAdmission:
            raise TypeError("market report admission must be CapacityAdmission")
        if self.admission.config_sha256 != self.config_sha256:
            raise ValueError("market report admission config SHA mismatch")
        if type(self.rest_rejections) is not tuple or any(
            type(item) is not ProbeRestCapacityRejection
            for item in self.rest_rejections
        ):
            raise TypeError(
                "rest_rejections must be a tuple of ProbeRestCapacityRejection"
            )
        rejection_keys = tuple(item.instrument_key for item in self.rest_rejections)
        if rejection_keys != tuple(sorted(rejection_keys)) or len(
            set(rejection_keys)
        ) != len(rejection_keys):
            raise ValueError("REST rejection instrument keys must be unique and sorted")
        if not set(rejection_keys).issubset(self.selection.entries) or set(
            rejection_keys
        ).intersection(self.admission.admitted):
            raise ValueError("REST rejections do not match final market admission")
        if any(
            item.config_sha256 != self.config_sha256 for item in self.rest_rejections
        ):
            raise ValueError("market report REST rejection config SHA mismatch")
        expected_capacity_keys = set(self.selection.entries) - set(rejection_keys)
        capacity_keys = set(self.admission.admitted) | set(self.admission.rejected)
        if capacity_keys != expected_capacity_keys:
            raise ValueError("market report admission does not cover final selection")
        if type(self.shards) is not tuple or any(
            type(item) is not ProbeShard for item in self.shards
        ):
            raise TypeError("market report shards must be a tuple of ProbeShard")
        shard_keys = tuple(
            instrument_key
            for shard in self.shards
            for instrument_key in shard.instrument_keys
        )
        if len(set(shard_keys)) != len(shard_keys) or set(shard_keys) != set(
            self.admission.admitted
        ):
            raise ValueError("market report shards must exactly cover admitted symbols")
        if type(self.endpoint_work) is not tuple or any(
            type(item) is not EndpointWork for item in self.endpoint_work
        ):
            raise TypeError("endpoint_work must be a tuple of EndpointWork")
        if type(self.interval_cohorts) is not tuple or any(
            type(item) is not ProbeIntervalCohort for item in self.interval_cohorts
        ):
            raise TypeError("interval_cohorts must be a tuple of ProbeIntervalCohort")
        cohort_keys = [
            (
                item.logical_endpoint,
                str(item.depth),
                item.plan.requested_ns,
                item.instrument_keys,
            )
            for item in self.interval_cohorts
        ]
        if cohort_keys != sorted(cohort_keys) or len(cohort_keys) != len(
            set(cohort_keys)
        ):
            raise ValueError("interval_cohorts must be unique and sorted")
        admitted = frozenset(self.admission.admitted)
        if any(
            not set(item.instrument_keys).issubset(admitted)
            for item in self.interval_cohorts
        ):
            raise ValueError("interval cohort contains a non-admitted instrument")
        if not isinstance(self.intervals, Mapping) or any(
            type(key) is not str or not key or type(value) is not IntervalPlan
            for key, value in self.intervals.items()
        ):
            raise TypeError("intervals must map endpoint strings to IntervalPlan")
        object.__setattr__(
            self,
            "intervals",
            MappingProxyType(dict(sorted(self.intervals.items()))),
        )


@dataclass(frozen=True, slots=True)
class ProbeExchangeReport:
    exchange: Exchange
    started_at_ns: int
    completed_at_ns: int
    public_time: PublicTimeProbe
    egresses: tuple[EgressReachabilityProbe, ...]
    market_evidence: tuple[MarketProbeEvidence, ...]
    date_gate_requests: tuple[DateGateRequest, ...]
    date_gates: tuple[DateGateProbe, ...]
    endpoint_budgets: tuple[EndpointBudgetProbe, ...]
    disabled_optional_features: tuple[str, ...]
    markets: Mapping[str, ProbeMarketReport]

    def __post_init__(self) -> None:
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange report exchange must be Exchange")
        started = _integer(self.started_at_ns, field="exchange started_at_ns")
        completed = _integer(self.completed_at_ns, field="exchange completed_at_ns")
        if completed < started:
            raise ValueError("exchange completion precedes its start")
        if type(self.public_time) is not PublicTimeProbe:
            raise TypeError("exchange public_time must be PublicTimeProbe")
        if type(self.market_evidence) is not tuple or any(
            type(item) is not MarketProbeEvidence for item in self.market_evidence
        ):
            raise TypeError("market_evidence must be a tuple of MarketProbeEvidence")
        if any(
            item.scope.exchange is not self.exchange for item in self.market_evidence
        ):
            raise ValueError("market evidence exchange mismatch")
        evidence_markets = tuple(item.scope.market for item in self.market_evidence)
        if len(set(evidence_markets)) != len(evidence_markets):
            raise ValueError("market evidence scopes must be unique")
        object.__setattr__(
            self,
            "market_evidence",
            tuple(
                sorted(
                    self.market_evidence,
                    key=lambda item: item.scope.market.value,
                )
            ),
        )
        if type(self.date_gate_requests) is not tuple or any(
            type(item) is not DateGateRequest for item in self.date_gate_requests
        ):
            raise TypeError("date_gate_requests must be a tuple of DateGateRequest")
        request_features = tuple(item.feature_id for item in self.date_gate_requests)
        if len(set(request_features)) != len(request_features):
            raise ValueError("date gate request features must be unique")
        object.__setattr__(
            self,
            "date_gate_requests",
            tuple(sorted(self.date_gate_requests, key=lambda item: item.feature_id)),
        )
        for field, expected in (
            ("egresses", EgressReachabilityProbe),
            ("date_gates", DateGateProbe),
            ("endpoint_budgets", EndpointBudgetProbe),
        ):
            values = getattr(self, field)
            if type(values) is not tuple or any(
                type(item) is not expected for item in values
            ):
                raise TypeError(f"{field} must be a tuple of {expected.__name__}")
        if type(self.disabled_optional_features) is not tuple or any(
            type(item) is not str or not item
            for item in self.disabled_optional_features
        ):
            raise TypeError("disabled_optional_features must be a tuple of strings")
        if not isinstance(self.markets, Mapping):
            raise TypeError("exchange report markets must be a mapping")
        for key, value in self.markets.items():
            if (
                type(key) is not str
                or type(value) is not ProbeMarketReport
                or key != value.scope.market.value
                or value.scope.exchange is not self.exchange
            ):
                raise ValueError("exchange report market binding mismatch")
        object.__setattr__(
            self,
            "markets",
            MappingProxyType(dict(sorted(self.markets.items()))),
        )


@dataclass(frozen=True, slots=True)
class ProbeReport:
    started_at_ns: int
    observed_at_ns: int
    config_sha256: str
    capability_registry_sha256: str
    exchanges: Mapping[str, ProbeExchangeReport]
    failures: tuple[ProbeFailure, ...]

    def __post_init__(self) -> None:
        started = _integer(self.started_at_ns, field="started_at_ns")
        object.__setattr__(
            self,
            "observed_at_ns",
            _integer(self.observed_at_ns, field="observed_at_ns"),
        )
        if self.observed_at_ns < started:
            raise ValueError("probe observation precedes its start")
        if not isinstance(self.exchanges, Mapping):
            raise TypeError("exchanges must be a mapping")
        for key, value in self.exchanges.items():
            if (
                type(key) is not str
                or type(value) is not ProbeExchangeReport
                or key != value.exchange.value
            ):
                raise ValueError("probe exchange report binding mismatch")
        if type(self.failures) is not tuple or any(
            type(item) is not ProbeFailure for item in self.failures
        ):
            raise TypeError("failures must be a tuple of ProbeFailure")
        object.__setattr__(
            self,
            "config_sha256",
            _sha256(self.config_sha256, field="config_sha256"),
        )
        object.__setattr__(
            self,
            "capability_registry_sha256",
            _sha256(
                self.capability_registry_sha256,
                field="capability_registry_sha256",
            ),
        )
        object.__setattr__(
            self,
            "exchanges",
            MappingProxyType(dict(sorted(self.exchanges.items()))),
        )

    @property
    def success(self) -> bool:
        return not self.failures


class _MarketProbeError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True, slots=True)
class _MarketDraft:
    evidence: MarketProbeEvidence
    scope_config: EffectiveScopeConfig
    fixed: ResolvedFixedSelection
    selection: SelectionResult
    capacity: EgressCapacity
    instruments_per_connection: int


@dataclass(frozen=True, slots=True)
class _ConnectionReservation:
    egress: EgressConfig
    physical_indices: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _IntervalDemand:
    scope: CatalogScope
    logical_endpoint: str
    depth: int | Literal["max_supported"] | None
    instrument_keys: tuple[str, ...]
    requested_ns: int
    policy: str
    jobs: int
    jobs_per_instrument: int
    cost: Decimal


@dataclass(frozen=True, slots=True)
class _IntervalAllocation:
    plans: Mapping[CatalogScope, Mapping[str, IntervalPlan]]
    cohorts: Mapping[CatalogScope, tuple[ProbeIntervalCohort, ...]]


class _IntervalAllocationError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        scopes: tuple[CatalogScope, ...],
    ) -> None:
        self.code = code
        self.scopes = scopes
        super().__init__(message)


class _RestCapacityReduction(RuntimeError):
    def __init__(
        self,
        *,
        scope: CatalogScope,
        rejection: ProbeRestCapacityRejection,
    ) -> None:
        self.scope = scope
        self.rejection = rejection
        super().__init__(
            f"evict {rejection.instrument_key} from "
            f"{rejection.logical_endpoint} REST capacity"
        )


def _selection_eviction_order(
    scope: CatalogScope,
    entry: SelectionEntry,
) -> tuple[int, int, str, str]:
    priority = entry.admission_priority
    if priority is AdmissionPriority.TOP_N:
        assert entry.top_n_rank is not None
        return (0, -entry.top_n_rank, scope.market.value, entry.instrument_key)
    if priority is AdmissionPriority.NEW_LISTING:
        return (
            1,
            -entry.instrument.first_seen_ns,
            scope.market.value,
            entry.instrument_key,
        )
    return (2, 0, scope.market.value, entry.instrument_key)


class ProbeEngine:
    def __init__(self, *, clock: Clock) -> None:
        if not callable(getattr(clock, "time_ns", None)):
            raise TypeError("clock must provide time_ns()")
        self._clock = clock

    async def run(
        self,
        bundle: ConfigBundle,
        *,
        providers: Mapping[str, ProbeProvider],
    ) -> ProbeReport:
        if type(bundle) is not ConfigBundle:
            raise TypeError("bundle must be ConfigBundle")
        if not isinstance(providers, Mapping):
            raise TypeError("providers must be a mapping")
        started_at_ns = _integer(self._clock.time_ns(), field="clock time_ns")
        observed_at_ns = started_at_ns
        config = bundle.config
        failures: list[ProbeFailure] = []
        reports: dict[str, ProbeExchangeReport] = {}
        scopes_by_exchange: dict[str, tuple[CatalogScope, ...]] = {}
        for exchange_id, exchange_config in sorted(config.exchanges.items()):
            enabled_scopes = tuple(
                CatalogScope(exchange_id, market_id)
                for market_id in sorted(exchange_config.markets)
                if effective_scope(config, exchange_id, market_id).enabled
            )
            if enabled_scopes:
                scopes_by_exchange[exchange_id] = enabled_scopes

        for exchange_id, scopes in scopes_by_exchange.items():
            try:
                exchange = Exchange(exchange_id)
            except ValueError:
                failures.append(
                    ProbeFailure(
                        exchange=Exchange.BINANCE,
                        code="unsupported_exchange",
                        message=f"unsupported configured exchange {exchange_id!r}",
                    )
                )
                continue
            try:
                provider = providers.get(exchange_id)
            except Exception:  # noqa: BLE001 - provider registries are isolated.
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="provider_error",
                        message="provider registry lookup failed",
                    )
                )
                continue
            if provider is None:
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="provider_unavailable",
                        message="no probe provider is registered",
                    )
                )
                continue
            try:
                provider_exchange = provider.exchange
                provider_probe = provider.probe
            except Exception:  # noqa: BLE001 - providers are an isolation boundary.
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="provider_error",
                        message="provider contract inspection failed",
                    )
                )
                continue
            if provider_exchange is not exchange or not callable(provider_probe):
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="provider_contract",
                        message="probe provider identity does not match its registry key",
                    )
                )
                continue
            request_started_at_ns = _integer(
                self._clock.time_ns(), field="clock time_ns"
            )
            request = ProbeRequest(
                exchange=exchange,
                markets=scopes,
                egress_ids=tuple(item.id for item in config.network.egress_pool),
                initial_lookback_ns=self._initial_lookback_policy(
                    bundle,
                    exchange_id=exchange_id,
                    scopes=scopes,
                ),
                config_sha256=bundle.config_sha256,
                observed_at_ns=request_started_at_ns,
                date_gates=self._date_gate_requests(
                    bundle,
                    exchange_id=exchange_id,
                    scopes=scopes,
                ),
            )
            try:
                evidence = await provider_probe(request)
            except Exception:  # noqa: BLE001 - providers are an isolation boundary.
                observed_at_ns = _integer(self._clock.time_ns(), field="clock time_ns")
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="provider_error",
                        message="provider probe failed",
                    )
                )
                continue
            completed_at_ns = _integer(self._clock.time_ns(), field="clock time_ns")
            observed_at_ns = completed_at_ns
            if (
                type(evidence) is not ExchangeProbeEvidence
                or evidence.exchange is not exchange
            ):
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="provider_contract",
                        message="provider returned mismatched exchange evidence",
                    )
                )
                continue
            if not self._evidence_within_window(
                evidence,
                started_at_ns=request_started_at_ns,
                completed_at_ns=completed_at_ns,
            ):
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="provider_contract",
                        message="provider evidence is outside the probe time window",
                    )
                )
                continue
            report, exchange_failures = self._compose_exchange(
                bundle,
                request,
                evidence,
                observed_at_ns=completed_at_ns,
            )
            failures.extend(exchange_failures)
            if report is not None:
                reports[exchange_id] = report

        failures.sort(
            key=lambda item: (
                item.exchange.value,
                item.market or "",
                item.feature_id or "",
                item.code,
            )
        )
        return ProbeReport(
            started_at_ns=started_at_ns,
            observed_at_ns=observed_at_ns,
            config_sha256=bundle.config_sha256,
            capability_registry_sha256=bundle.capabilities.sha256,
            exchanges=reports,
            failures=tuple(failures),
        )

    @staticmethod
    def _initial_lookback_policy(
        bundle: ConfigBundle,
        *,
        exchange_id: str,
        scopes: tuple[CatalogScope, ...],
    ) -> Mapping[tuple[Market, str | None], int]:
        exchange_config = bundle.config.exchanges[exchange_id]
        policy: dict[tuple[Market, str | None], int] = {}
        for scope in scopes:
            market_id = scope.market.value
            policy[(scope.market, None)] = effective_scope(
                bundle.config,
                exchange_id,
                market_id,
            ).selection.new_listings.initial_lookback_ns
            market_config = exchange_config.markets[market_id]
            for instrument_key in sorted(market_config.symbols):
                policy[(scope.market, instrument_key)] = effective_scope(
                    bundle.config,
                    exchange_id,
                    market_id,
                    instrument_key,
                ).selection.new_listings.initial_lookback_ns
        return MappingProxyType(policy)

    @staticmethod
    def _date_gate_requests(
        bundle: ConfigBundle,
        *,
        exchange_id: str,
        scopes: tuple[CatalogScope, ...],
    ) -> tuple[DateGateRequest, ...]:
        policies = bundle.config.capabilities.date_gated_features.get(exchange_id, {})
        enabled_markets = {scope.market.value for scope in scopes}
        requests = []
        for feature in bundle.capabilities.for_exchange(
            exchange_id
        ).date_gated_features:
            policy = policies.get(feature.id)
            if (
                policy is None
                or not policy.enabled
                or not enabled_markets.intersection(feature.markets)
            ):
                continue
            required = (
                bundle.config.capabilities.date_gated_default_required
                if policy.required is None
                else policy.required
            )
            applicable_markets = tuple(
                sorted(
                    (
                        scope.market
                        for scope in scopes
                        if scope.market.value in feature.markets
                    ),
                    key=lambda item: item.value,
                )
            )
            requests.append(
                DateGateRequest(
                    feature_id=feature.id,
                    markets=applicable_markets,
                    required=required,
                    available_from=feature.available_from,
                    requires_live_probe=feature.requires_live_probe,
                )
            )
        return tuple(requests)

    @staticmethod
    def _evidence_within_window(
        evidence: ExchangeProbeEvidence,
        *,
        started_at_ns: int,
        completed_at_ns: int,
    ) -> bool:
        if completed_at_ns < started_at_ns:
            return False
        timestamps = [
            evidence.public_time.observed_at_ns,
            *(item.observed_at_ns for item in evidence.egresses),
            *(
                transport.observed_at_ns
                for item in evidence.egresses
                for transport in item.transports
            ),
            *(item.observed_at_ns for item in evidence.endpoint_budgets),
            *(item.observed_at_ns for item in evidence.date_gates),
        ]
        for market in evidence.markets:
            catalog_observed = market.catalog.catalog_observed_at_ns
            if catalog_observed is not None:
                timestamps.append(catalog_observed)
            turnover_observed = market.catalog.turnover_observed_at_ns
            if turnover_observed is not None:
                timestamps.append(turnover_observed)
            timestamps.extend(item.observed_at_ns for item in market.endpoint_work)
        return all(started_at_ns <= item <= completed_at_ns for item in timestamps)

    def _compose_exchange(
        self,
        bundle: ConfigBundle,
        request: ProbeRequest,
        evidence: ExchangeProbeEvidence,
        *,
        observed_at_ns: int,
    ) -> tuple[ProbeExchangeReport | None, tuple[ProbeFailure, ...]]:
        exchange = request.exchange
        configured_egress_ids = set(request.egress_ids)
        probed_egress_ids = {item.egress_id for item in evidence.egresses}
        if probed_egress_ids != configured_egress_ids:
            return None, (
                ProbeFailure(
                    exchange=exchange,
                    code="provider_contract",
                    message="egress reachability evidence is incomplete or unexpected",
                ),
            )
        expected_markets = {item.market for item in request.markets}
        market_evidence = {item.scope.market: item for item in evidence.markets}
        if set(market_evidence) - expected_markets:
            return None, (
                ProbeFailure(
                    exchange=exchange,
                    code="provider_contract",
                    message="provider returned an unrequested market",
                ),
            )

        failures: list[ProbeFailure] = []
        disabled_optional: list[str] = []
        gates = {item.feature_id: item for item in evidence.date_gates}
        expected_evidence = {
            item.feature_id for item in request.date_gates if item.requires_live_probe
        }
        if set(gates) != expected_evidence:
            return None, (
                ProbeFailure(
                    exchange=exchange,
                    code="provider_contract",
                    message="date-gate evidence does not match the request",
                ),
            )
        for requested_gate in request.date_gates:
            gate = gates.get(requested_gate.feature_id)
            archived_available = requested_gate.archived_available_at(
                evidence.public_time.exchange_time_ns
            )
            live_available = not requested_gate.requires_live_probe or (
                gate is not None and gate.available
            )
            available = archived_available and live_available
            if available:
                continue
            if requested_gate.required:
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="required_capability_unavailable",
                        message="required date-gated capability is unavailable",
                        feature_id=requested_gate.feature_id,
                    )
                )
            else:
                disabled_optional.append(requested_gate.feature_id)

        websocket_reachable = frozenset(
            item.egress_id for item in evidence.egresses if item.websocket_reachable
        )
        http_reachable = frozenset(
            item.egress_id for item in evidence.egresses if item.http_reachable
        )
        if not websocket_reachable:
            failures.append(
                ProbeFailure(
                    exchange=exchange,
                    code="websocket_unavailable",
                    message="no requested egress passed required WebSocket probes",
                )
            )
        drafts: dict[CatalogScope, _MarketDraft] = {}
        for scope in request.markets:
            item = market_evidence.get(scope.market)
            if item is None:
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        market=scope.market.value,
                        code="catalog_unavailable",
                        message="provider omitted the requested market catalog",
                    )
                )
                continue
            try:
                drafts[scope] = self._prepare_market(
                    bundle,
                    item,
                    websocket_reachable,
                    now_ns=observed_at_ns,
                )
            except FixedPairResolutionError as error:
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        market=scope.market.value,
                        code="fixed_resolution",
                        message=str(error),
                    )
                )
            except CapacityError as error:
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        market=scope.market.value,
                        code="capacity",
                        message=str(error),
                    )
                )
            except _MarketProbeError as error:
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        market=scope.market.value,
                        code=error.code,
                        message=str(error),
                    )
                )

        reports: dict[str, ProbeMarketReport] = {}
        if drafts:
            total_connections = sum(
                item.max_ws_connections
                for item in bundle.config.network.egress_pool
                if item.id in websocket_reachable
            )
            healthy_egresses = tuple(
                item
                for item in bundle.config.network.egress_pool
                if item.id in websocket_reachable
            )
            active_drafts = dict(drafts)
            rest_rejections: defaultdict[
                CatalogScope,
                dict[str, ProbeRestCapacityRejection],
            ] = defaultdict(dict)
            try:
                while active_drafts:
                    demands = tuple(
                        ScopedCapacityDemand(
                            scope=scope,
                            candidates=tuple(
                                CapacityCandidate.from_selection_entry(item)
                                for key, item in draft.selection.entries.items()
                                if key not in rest_rejections[scope]
                            ),
                            instruments_per_connection=(
                                draft.instruments_per_connection
                            ),
                            policies={
                                key: effective_scope(
                                    bundle.config,
                                    scope.exchange.value,
                                    scope.market.value,
                                    key,
                                ).selection.capacity_policy
                                for key in draft.selection.entries
                                if key not in rest_rejections[scope]
                            },
                        )
                        for scope, draft in sorted(
                            active_drafts.items(),
                            key=lambda item: item[0].market.value,
                        )
                    )
                    try:
                        exchange_admission = admit_exchange_capacity(
                            demands,
                            ws_connections=total_connections,
                            config_sha256=bundle.config_sha256,
                        )
                    except ScopedCapacityError as error:
                        if error.scope not in active_drafts:
                            raise
                        active_drafts.pop(error.scope)
                        rest_rejections.clear()
                        failures.append(
                            ProbeFailure(
                                exchange=exchange,
                                market=error.scope.market.value,
                                code="capacity",
                                message=str(error),
                            )
                        )
                        continue
                    reservations = self._reserve_connections(
                        drafts=active_drafts,
                        connections_by_scope=(exchange_admission.connections_by_scope),
                        egresses=healthy_egresses,
                    )
                    candidate_reports = {
                        scope.market.value: self._build_market_report(
                            draft,
                            admission=exchange_admission.admissions[scope],
                            rest_rejections=tuple(
                                rest_rejections[scope][key]
                                for key in sorted(rest_rejections[scope])
                            ),
                            reservations=reservations[scope],
                        )
                        for scope, draft in sorted(
                            active_drafts.items(),
                            key=lambda item: item[0].market.value,
                        )
                    }
                    try:
                        interval_allocation = self._allocate_intervals(
                            bundle=bundle,
                            drafts=active_drafts,
                            reports=candidate_reports,
                            endpoint_budgets=evidence.endpoint_budgets,
                            reachable=http_reachable,
                        )
                    except _RestCapacityReduction as reduction:
                        rest_rejections[reduction.scope][
                            reduction.rejection.instrument_key
                        ] = reduction.rejection
                        continue
                    except _IntervalAllocationError as error:
                        affected = tuple(
                            scope for scope in error.scopes if scope in active_drafts
                        )
                        if not affected:
                            raise
                        for scope in affected:
                            active_drafts.pop(scope, None)
                            failures.append(
                                ProbeFailure(
                                    exchange=exchange,
                                    market=scope.market.value,
                                    code=error.code,
                                    message=str(error),
                                )
                            )
                        rest_rejections.clear()
                        continue
                    reports = {
                        market_id: replace(
                            report,
                            intervals=interval_allocation.plans.get(report.scope, {}),
                            interval_cohorts=interval_allocation.cohorts.get(
                                report.scope, ()
                            ),
                        )
                        for market_id, report in candidate_reports.items()
                    }
                    break
            except CapacityError as error:
                reports.clear()
                failures.append(
                    ProbeFailure(
                        exchange=exchange,
                        code="capacity",
                        message=str(error),
                    )
                )

        return (
            ProbeExchangeReport(
                exchange=exchange,
                started_at_ns=request.observed_at_ns,
                completed_at_ns=observed_at_ns,
                public_time=evidence.public_time,
                egresses=evidence.egresses,
                market_evidence=evidence.markets,
                date_gate_requests=request.date_gates,
                date_gates=evidence.date_gates,
                endpoint_budgets=evidence.endpoint_budgets,
                disabled_optional_features=tuple(sorted(disabled_optional)),
                markets=reports,
            ),
            tuple(failures),
        )

    def _prepare_market(
        self,
        bundle: ConfigBundle,
        evidence: MarketProbeEvidence,
        reachable: frozenset[str],
        *,
        now_ns: int,
    ) -> _MarketDraft:
        scope = evidence.scope
        scope_config = effective_scope(
            bundle.config,
            scope.exchange.value,
            scope.market.value,
        )
        fixed = resolve_fixed_requests(
            scope_config.selection.fixed_pairs,
            evidence.catalog,
        )
        disabled_keys = frozenset(
            item.instrument_key
            for item in evidence.catalog.instruments
            if not effective_scope(
                bundle.config,
                scope.exchange.value,
                scope.market.value,
                item.instrument_key,
            ).enabled
        )
        disabled_fixed = tuple(sorted(fixed.instrument_keys & disabled_keys))
        if disabled_fixed:
            raise _MarketProbeError(
                "fixed_disabled",
                "fixed instruments are disabled by symbol configuration: "
                + ", ".join(disabled_fixed),
            )
        selection_catalog = replace(
            evidence.catalog,
            instruments=tuple(
                item
                for item in evidence.catalog.instruments
                if item.instrument_key not in disabled_keys
            ),
            turnover_covered_instrument_keys=tuple(
                key
                for key in evidence.catalog.turnover_covered_instrument_keys
                if key not in disabled_keys
            ),
        )
        selection = self._select_with_symbol_policies(
            bundle=bundle,
            catalog=selection_catalog,
            fixed=fixed,
            now_ns=now_ns,
        )
        capacity = calculate_egress_capacity(
            exchange=scope.exchange.value,
            egresses=bundle.config.network.egress_pool,
            reachable_egress_ids=reachable,
            subscriptions_per_connection=evidence.subscriptions_per_connection,
            subscriptions_per_instrument=evidence.subscriptions_per_instrument,
        )
        instruments_per_connection = (
            evidence.subscriptions_per_connection
            // evidence.subscriptions_per_instrument
        )
        if instruments_per_connection == 0:
            raise CapacityError(
                "one instrument exceeds the provider subscription limit per connection"
            )
        return _MarketDraft(
            evidence=evidence,
            scope_config=scope_config,
            fixed=fixed,
            selection=selection,
            capacity=capacity,
            instruments_per_connection=instruments_per_connection,
        )

    @staticmethod
    def _select_with_symbol_policies(
        *,
        bundle: ConfigBundle,
        catalog: CatalogView,
        fixed: ResolvedFixedSelection,
        now_ns: int,
    ) -> SelectionResult:
        scope = catalog.scope
        selections_by_policy: dict[str, SelectionResult] = {}
        entries = {}
        for instrument in catalog.instruments:
            selection_config = effective_scope(
                bundle.config,
                scope.exchange.value,
                scope.market.value,
                instrument.instrument_key,
            ).selection
            policy = SelectionPolicy(
                scope=scope,
                quote_assets=selection_config.quote_assets,
                top_n=selection_config.top_n,
                turnover_max_age_ns=selection_config.turnover_max_age_ns,
                new_listings_enabled=selection_config.new_listings.enabled,
                new_listing_capture_duration_ns=(
                    selection_config.new_listings.capture_duration_ns
                ),
                exit_grace_ns=selection_config.exit_grace_ns,
            )
            result = selections_by_policy.get(policy.policy_id)
            if result is None:
                result = select(
                    catalog,
                    fixed=fixed,
                    policy=policy,
                    previous=None,
                    now_ns=now_ns,
                )
                selections_by_policy[policy.policy_id] = result
            entry = result.entries.get(instrument.instrument_key)
            if entry is not None:
                entries[instrument.instrument_key] = entry

        policy_id = bundle.config_sha256
        next_state = SelectionState(
            scope=scope,
            catalog_revision=catalog.catalog_revision,
            turnover_revision=catalog.turnover_revision,
            policy_id=policy_id,
            revision=0,
            entries=entries,
        )
        deltas = tuple(
            SelectionDelta(
                instrument_key=instrument_key,
                previous=None,
                current=entry,
            )
            for instrument_key, entry in sorted(entries.items())
        )
        return SelectionResult(
            scope=scope,
            catalog_revision=catalog.catalog_revision,
            turnover_revision=catalog.turnover_revision,
            policy_id=policy_id,
            entries=entries,
            next_state=next_state,
            deltas=deltas,
        )

    @staticmethod
    def _reserve_connections(
        *,
        drafts: Mapping[CatalogScope, _MarketDraft],
        connections_by_scope: Mapping[CatalogScope, int],
        egresses: tuple[EgressConfig, ...],
    ) -> Mapping[CatalogScope, tuple[_ConnectionReservation, ...]]:
        by_id = {item.id: item for item in egresses}
        next_index = {item.id: 0 for item in egresses}
        reservations: dict[CatalogScope, tuple[_ConnectionReservation, ...]] = {}
        for scope in sorted(drafts, key=lambda item: item.market.value):
            reserved: defaultdict[str, list[int]] = defaultdict(list)
            for _ in range(connections_by_scope[scope]):
                egress_id = next(
                    (
                        item
                        for item in sorted(next_index)
                        if next_index[item] < by_id[item].max_ws_connections
                    ),
                    None,
                )
                if egress_id is None:
                    raise CapacityError(
                        "connection reservation exceeds healthy capacity"
                    )
                reserved[egress_id].append(next_index[egress_id])
                next_index[egress_id] += 1
            reservations[scope] = tuple(
                _ConnectionReservation(
                    egress=by_id[egress_id].model_copy(
                        update={"max_ws_connections": len(indices)}
                    ),
                    physical_indices=tuple(indices),
                )
                for egress_id, indices in sorted(reserved.items())
            )
        return MappingProxyType(reservations)

    @staticmethod
    def _build_market_report(
        draft: _MarketDraft,
        *,
        admission: CapacityAdmission,
        rest_rejections: tuple[ProbeRestCapacityRejection, ...],
        reservations: tuple[_ConnectionReservation, ...],
    ) -> ProbeMarketReport:
        egresses = tuple(item.egress for item in reservations)
        assignments: tuple[StickyAssignment, ...] = ()
        shards: tuple[EgressShard, ...] = ()
        if admission.admitted:
            assignments = assign_instruments(
                admission.admitted,
                exchange=draft.evidence.scope.exchange.value,
                market=draft.evidence.scope.market.value,
                channel="_probe",
                egresses=egresses,
                subscriptions_per_connection=draft.instruments_per_connection,
            )
            shards = pack_egress_shards(
                assignments,
                egresses=egresses,
                subscriptions_per_connection=draft.instruments_per_connection,
            )
        reservation_by_id = {item.egress.id: item for item in reservations}
        report_shards = tuple(
            ProbeShard(
                egress_id=item.egress_id,
                quota_group=reservation_by_id[item.egress_id].egress.quota_group,
                index=reservation_by_id[item.egress_id].physical_indices[item.index],
                instrument_keys=item.instrument_keys,
            )
            for item in shards
        )
        return ProbeMarketReport(
            scope=draft.evidence.scope,
            config_sha256=admission.config_sha256,
            catalog=draft.evidence.catalog,
            fixed=draft.fixed,
            selection=draft.selection,
            exchange_capacity_ceiling=draft.capacity,
            admission=admission,
            rest_rejections=rest_rejections,
            shards=report_shards,
            endpoint_work=draft.evidence.endpoint_work,
            interval_cohorts=(),
            intervals={},
        )

    @staticmethod
    def _rest_reduction_candidate(
        *,
        bundle: ConfigBundle,
        drafts: Mapping[CatalogScope, _MarketDraft],
        demands: tuple[_IntervalDemand, ...],
    ) -> tuple[CatalogScope, str] | None:
        candidates: dict[tuple[CatalogScope, str], SelectionEntry] = {}
        for demand in demands:
            draft = drafts[demand.scope]
            for instrument_key in demand.instrument_keys:
                entry = draft.selection.entries[instrument_key]
                capacity_policy = effective_scope(
                    bundle.config,
                    demand.scope.exchange.value,
                    demand.scope.market.value,
                    instrument_key,
                ).selection.capacity_policy
                if (
                    entry.admission_priority is AdmissionPriority.FIXED
                    or capacity_policy == "fail"
                ):
                    continue
                candidates[(demand.scope, instrument_key)] = entry
        if not candidates:
            return None
        return min(
            candidates,
            key=lambda item: _selection_eviction_order(item[0], candidates[item]),
        )

    @staticmethod
    def _reduce_rest_or_fail(
        *,
        bundle: ConfigBundle,
        drafts: Mapping[CatalogScope, _MarketDraft],
        endpoint: str,
        active: tuple[_IntervalDemand, ...],
        available_rate: Fraction,
        required_rate: Fraction,
        max_effective_ns: int,
        reason: Literal["max_effective_interval", "overload_policy", "zero_rate"],
        message: str,
        failure_demands: tuple[_IntervalDemand, ...] | None = None,
    ) -> Never:
        candidate = ProbeEngine._rest_reduction_candidate(
            bundle=bundle,
            drafts=drafts,
            demands=active,
        )
        if candidate is not None:
            scope, instrument_key = candidate
            demand = next(
                item
                for item in active
                if item.scope == scope and instrument_key in item.instrument_keys
            )
            raise _RestCapacityReduction(
                scope=scope,
                rejection=ProbeRestCapacityRejection(
                    instrument_key=instrument_key,
                    logical_endpoint=endpoint,
                    depth=demand.depth,
                    requested_interval_ns=demand.requested_ns,
                    cost=demand.cost,
                    jobs_per_instrument=demand.jobs_per_instrument,
                    available_rate_numerator=available_rate.numerator,
                    available_rate_denominator=available_rate.denominator,
                    required_rate_numerator=required_rate.numerator,
                    required_rate_denominator=required_rate.denominator,
                    max_effective_ns=max_effective_ns,
                    reason=reason,
                    config_sha256=bundle.config_sha256,
                ),
            )
        raise _IntervalAllocationError(
            "capacity",
            message,
            tuple(
                sorted(
                    {
                        item.scope
                        for item in (
                            active if failure_demands is None else failure_demands
                        )
                    },
                    key=lambda item: item.market.value,
                )
            ),
        )

    @staticmethod
    def _allocate_intervals(
        *,
        bundle: ConfigBundle,
        drafts: Mapping[CatalogScope, _MarketDraft],
        reports: Mapping[str, ProbeMarketReport],
        endpoint_budgets: tuple[EndpointBudgetProbe, ...],
        reachable: frozenset[str],
    ) -> _IntervalAllocation:
        report_by_scope = {item.scope: item for item in reports.values()}
        demands_by_endpoint: defaultdict[str, list[_IntervalDemand]] = defaultdict(list)
        for scope, draft in drafts.items():
            report = report_by_scope.get(scope)
            if report is None:
                continue
            work_cohorts: defaultdict[
                tuple[
                    str,
                    int | Literal["max_supported"] | None,
                    int,
                    str,
                    Decimal,
                    int,
                    int,
                ],
                list[str],
            ] = defaultdict(list)
            for work in draft.evidence.endpoint_work:
                if work.kind != "periodic_reference" or work.jobs_per_market == 0:
                    continue
                requested_interval_ns = (
                    draft.scope_config.selection.refresh_interval_ns
                    if work.logical_endpoint == "instruments"
                    else work.requested_interval_ns
                )
                if requested_interval_ns is None:  # pragma: no cover - model validates.
                    raise _IntervalAllocationError(
                        "endpoint_work_unavailable",
                        "periodic reference workload has no requested interval",
                        (scope,),
                    )
                work_cohorts[
                    (
                        work.logical_endpoint,
                        None,
                        requested_interval_ns,
                        "stretch_with_warning",
                        work.cost,
                        work.jobs_per_instrument,
                        work.jobs_per_market,
                    )
                ]
            for instrument_key in report.admission.admitted:
                books = effective_scope(
                    bundle.config,
                    scope.exchange.value,
                    scope.market.value,
                    instrument_key,
                ).books.deep_snapshot
                if books.enabled:
                    matching_work = tuple(
                        work
                        for work in draft.evidence.endpoint_work
                        if work.kind == "deep_snapshot"
                        and (work.depth == books.depth or work.depth == "max_supported")
                    )
                    if not matching_work:
                        raise _IntervalAllocationError(
                            "endpoint_work_unavailable",
                            "enabled deep snapshot has no matching provider workload "
                            f"for depth {books.depth}",
                            (scope,),
                        )
                    for work in matching_work:
                        work_cohorts[
                            (
                                work.logical_endpoint,
                                books.depth,
                                books.requested_interval_ns,
                                books.overload_policy,
                                work.cost,
                                work.jobs_per_instrument,
                                work.jobs_per_market,
                            )
                        ].append(instrument_key)
                for work in draft.evidence.endpoint_work:
                    if (
                        work.kind != "periodic_reference"
                        or work.jobs_per_instrument == 0
                    ):
                        continue
                    if work.requested_interval_ns is None:  # pragma: no cover
                        raise _IntervalAllocationError(
                            "endpoint_work_unavailable",
                            "periodic reference workload has no requested interval",
                            (scope,),
                        )
                    work_cohorts[
                        (
                            work.logical_endpoint,
                            None,
                            work.requested_interval_ns,
                            "stretch_with_warning",
                            work.cost,
                            work.jobs_per_instrument,
                            work.jobs_per_market,
                        )
                    ].append(instrument_key)
            for (
                endpoint,
                depth,
                requested_ns,
                policy,
                cost,
                jobs_per_instrument,
                jobs_per_market,
            ), instrument_keys in sorted(
                work_cohorts.items(),
                key=lambda item: (
                    item[0][0],
                    str(item[0][1]),
                    item[0][2:],
                ),
            ):
                normalized_keys = tuple(sorted(instrument_keys))
                demands_by_endpoint[endpoint].append(
                    _IntervalDemand(
                        scope=scope,
                        logical_endpoint=endpoint,
                        depth=depth,
                        instrument_keys=normalized_keys,
                        requested_ns=requested_ns,
                        policy=policy,
                        jobs=(
                            len(normalized_keys) * jobs_per_instrument + jobs_per_market
                        ),
                        jobs_per_instrument=jobs_per_instrument,
                        cost=cost,
                    )
                )

        egresses = tuple(
            item for item in bundle.config.network.egress_pool if item.id in reachable
        )
        quota_groups = tuple(sorted({item.quota_group for item in egresses}))
        budget_by_key = {
            (item.quota_group, item.logical_endpoint): item for item in endpoint_budgets
        }
        cohorts_by_scope: defaultdict[CatalogScope, list[ProbeIntervalCohort]] = (
            defaultdict(list)
        )
        maximum = bundle.config.network.scheduler.deep_snapshot_max_interval_ns
        for endpoint, demands in sorted(demands_by_endpoint.items()):
            active = tuple(item for item in demands if item.jobs)
            if active:
                missing = tuple(
                    group
                    for group in quota_groups
                    if (group, endpoint) not in budget_by_key
                )
                if missing:
                    scopes = tuple(
                        sorted(
                            {item.scope for item in active},
                            key=lambda item: item.market.value,
                        )
                    )
                    raise _IntervalAllocationError(
                        "endpoint_budget_unavailable",
                        "missing endpoint budget for "
                        + ", ".join(f"{group}/{endpoint}" for group in missing),
                        scopes,
                    )
                available = sum(
                    (
                        Fraction(
                            budget_by_key[(group, endpoint)].available_tokens_per_second
                        )
                        for group in quota_groups
                    ),
                    start=Fraction(0),
                )
                rates = {
                    item: Fraction(item.jobs)
                    * Fraction(item.cost)
                    * 1_000_000_000
                    / item.requested_ns
                    for item in active
                }
                required = sum(
                    rates.values(),
                    start=Fraction(0),
                )
                if available == 0:
                    ProbeEngine._reduce_rest_or_fail(
                        bundle=bundle,
                        drafts=drafts,
                        endpoint=endpoint,
                        active=active,
                        available_rate=available,
                        required_rate=required,
                        max_effective_ns=maximum,
                        reason="zero_rate",
                        message=f"available token rate is zero for {endpoint}",
                    )
                fail_demands = tuple(item for item in active if item.policy == "fail")
                flexible_demands = tuple(
                    item for item in active if item.policy != "fail"
                )
                fail_required = sum(
                    (rates[item] for item in fail_demands),
                    start=Fraction(0),
                )
                if fail_required > available:
                    ProbeEngine._reduce_rest_or_fail(
                        bundle=bundle,
                        drafts=drafts,
                        endpoint=endpoint,
                        active=fail_demands,
                        available_rate=available,
                        required_rate=required,
                        max_effective_ns=maximum,
                        reason="overload_policy",
                        message=f"endpoint {endpoint} cannot preserve fail-policy cadence",
                    )
                remaining = available - fail_required
                flexible_required = sum(
                    (rates[item] for item in flexible_demands),
                    start=Fraction(0),
                )
                if flexible_demands and remaining == 0:
                    ProbeEngine._reduce_rest_or_fail(
                        bundle=bundle,
                        drafts=drafts,
                        endpoint=endpoint,
                        active=flexible_demands,
                        available_rate=remaining,
                        required_rate=flexible_required,
                        max_effective_ns=maximum,
                        reason="zero_rate",
                        message=f"endpoint {endpoint} has no flexible workload budget",
                    )
                flexible_stretch = (
                    max(Fraction(1), flexible_required / remaining)
                    if flexible_demands
                    else Fraction(1)
                )
                stretches = {
                    item: (Fraction(1) if item.policy == "fail" else flexible_stretch)
                    for item in active
                }
                over_maximum = tuple(
                    item
                    for item in active
                    if (
                        scaled := Fraction(item.requested_ns) * stretches[item]
                    ).numerator
                    + scaled.denominator
                    - 1
                    > maximum * scaled.denominator
                )
                over_maximum_fail = tuple(
                    item for item in over_maximum if item.policy == "fail"
                )
                if over_maximum_fail:
                    ProbeEngine._reduce_rest_or_fail(
                        bundle=bundle,
                        drafts=drafts,
                        endpoint=endpoint,
                        active=over_maximum_fail,
                        available_rate=available,
                        required_rate=required,
                        max_effective_ns=maximum,
                        reason="max_effective_interval",
                        message=f"endpoint {endpoint} exceeds configured REST capacity",
                    )
                if over_maximum:
                    ProbeEngine._reduce_rest_or_fail(
                        bundle=bundle,
                        drafts=drafts,
                        endpoint=endpoint,
                        active=flexible_demands,
                        available_rate=available,
                        required_rate=required,
                        max_effective_ns=maximum,
                        reason="max_effective_interval",
                        message=f"endpoint {endpoint} exceeds configured REST capacity",
                        failure_demands=over_maximum,
                    )
            else:
                stretches = {}

            for demand in demands:
                stretch = stretches.get(demand, Fraction(1))
                scaled = Fraction(demand.requested_ns) * stretch
                effective = (
                    scaled.numerator + scaled.denominator - 1
                ) // scaled.denominator
                if effective > maximum:
                    raise _IntervalAllocationError(
                        "capacity",
                        f"endpoint {endpoint} exceeds max effective interval",
                        (demand.scope,),
                    )
                warning = (
                    None
                    if effective == demand.requested_ns
                    else IntervalWarning(
                        demand.requested_ns,
                        effective,
                        len(demand.instrument_keys),
                    )
                )
                cohort_plan = IntervalPlan(
                    requested_ns=demand.requested_ns,
                    effective_ns=effective,
                    warning=warning,
                )
                cohorts_by_scope[demand.scope].append(
                    ProbeIntervalCohort(
                        logical_endpoint=endpoint,
                        depth=demand.depth,
                        instrument_keys=demand.instrument_keys,
                        plan=cohort_plan,
                    )
                )

        normalized_cohorts = {
            scope: tuple(
                sorted(
                    scope_cohorts,
                    key=lambda item: (
                        item.logical_endpoint,
                        str(item.depth),
                        item.plan.requested_ns,
                        item.instrument_keys,
                    ),
                )
            )
            for scope, scope_cohorts in sorted(
                cohorts_by_scope.items(), key=lambda item: item[0].market.value
            )
        }
        plans: dict[CatalogScope, Mapping[str, IntervalPlan]] = {}
        for scope, scope_cohorts in normalized_cohorts.items():
            grouped: defaultdict[str, list[ProbeIntervalCohort]] = defaultdict(list)
            for cohort in scope_cohorts:
                grouped[cohort.logical_endpoint].append(cohort)
            scope_plans: dict[str, IntervalPlan] = {}
            for endpoint, endpoint_cohorts in sorted(grouped.items()):
                signatures = {
                    (item.plan.requested_ns, item.plan.effective_ns)
                    for item in endpoint_cohorts
                }
                if len(signatures) != 1:
                    continue
                requested, effective = next(iter(signatures))
                summary_instrument_keys = {
                    instrument_key
                    for item in endpoint_cohorts
                    for instrument_key in item.instrument_keys
                }
                has_warning = any(
                    item.plan.warning is not None for item in endpoint_cohorts
                )
                warning = (
                    None
                    if not has_warning
                    else IntervalWarning(
                        requested,
                        effective,
                        len(summary_instrument_keys),
                    )
                )
                scope_plans[endpoint] = IntervalPlan(requested, effective, warning)
            plans[scope] = MappingProxyType(scope_plans)

        return _IntervalAllocation(
            plans=MappingProxyType(plans),
            cohorts=MappingProxyType(normalized_cohorts),
        )


__all__ = [
    "DateGateProbe",
    "DateGateRequest",
    "EgressReachabilityProbe",
    "EndpointBudgetProbe",
    "EndpointWork",
    "ExchangeProbeEvidence",
    "MarketProbeEvidence",
    "ProbeEngine",
    "ProbeExchangeReport",
    "ProbeFailure",
    "ProbeIntervalCohort",
    "ProbeMarketReport",
    "ProbeProvider",
    "ProbeReport",
    "ProbeRequest",
    "ProbeRestCapacityRejection",
    "ProbeShard",
    "PublicTimeProbe",
    "TransportReachabilityProbe",
]
