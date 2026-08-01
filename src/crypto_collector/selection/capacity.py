from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Literal, cast

from crypto_collector.config.models import EgressConfig
from crypto_collector.scheduler.rest import CapacityError
from crypto_collector.selection.models import CatalogScope
from crypto_collector.selection.selector import (
    AdmissionPriority,
    SelectionEntry,
)

CapacityPolicy = Literal["degrade_low_priority_with_warning", "fail"]
AdmissionPolicy = Literal["degrade_low_priority_with_warning", "fail", "mixed"]
_MAX_INT64 = 2**63 - 1


class ScopedCapacityError(CapacityError):
    def __init__(self, scope: CatalogScope, message: str) -> None:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be CatalogScope")
        self.scope = scope
        super().__init__(message)


def _integer(value: object, *, field: str, minimum: int = 0) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field} must be {qualifier}")
    if value > _MAX_INT64:
        raise ValueError(f"{field} must fit a signed 64-bit integer")
    return value


def _nonempty(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _sha256(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("config_sha256 must be a lowercase SHA-256 digest")
    return value


def _capacity_policy(value: object) -> CapacityPolicy:
    if type(value) is not str or value not in {
        "degrade_low_priority_with_warning",
        "fail",
    }:
        raise ValueError("unsupported capacity policy")
    return cast(CapacityPolicy, value)


@dataclass(frozen=True, slots=True, init=False)
class CapacityCandidate:
    instrument_key: str
    priority: AdmissionPriority
    first_seen_ns: int
    top_n_rank: int | None

    def __init__(
        self,
        instrument_key: str,
        priority: AdmissionPriority,
        *,
        first_seen_ns: int,
        top_n_rank: int | None = None,
    ) -> None:
        key = _nonempty(instrument_key, field="instrument_key")
        if type(priority) is not AdmissionPriority:
            raise TypeError("priority must be AdmissionPriority")
        first_seen = _integer(first_seen_ns, field="first_seen_ns")
        rank = (
            None
            if top_n_rank is None
            else _integer(top_n_rank, field="top_n_rank", minimum=1)
        )
        if priority is AdmissionPriority.TOP_N and rank is None:
            raise ValueError("TOP_N candidate requires top_n_rank")
        if priority is not AdmissionPriority.TOP_N and rank is not None:
            raise ValueError("top_n_rank is valid only for TOP_N candidates")
        object.__setattr__(self, "instrument_key", key)
        object.__setattr__(self, "priority", priority)
        object.__setattr__(self, "first_seen_ns", first_seen)
        object.__setattr__(self, "top_n_rank", rank)

    @classmethod
    def from_selection_entry(cls, entry: SelectionEntry) -> CapacityCandidate:
        if type(entry) is not SelectionEntry:
            raise TypeError("entry must be SelectionEntry")
        return cls(
            entry.instrument_key,
            entry.admission_priority,
            first_seen_ns=entry.instrument.first_seen_ns,
            top_n_rank=(
                entry.top_n_rank
                if entry.admission_priority is AdmissionPriority.TOP_N
                else None
            ),
        )


@dataclass(frozen=True, slots=True)
class EgressCapacity:
    exchange: str
    healthy_egress_ids: tuple[str, ...]
    quota_groups: tuple[str, ...]
    ws_connections: int
    ws_subscription_slots: int
    instrument_slots: int
    http_concurrency: int
    subscriptions_per_connection: int
    subscriptions_per_instrument: int


@dataclass(frozen=True, slots=True)
class CapacityWarning:
    rejected: tuple[str, ...]
    required_slots: int
    available_slots: int
    config_sha256: str
    reason: str = "selection exceeds healthy transport capacity"


@dataclass(frozen=True, slots=True)
class CapacityAdmission:
    admitted: tuple[str, ...]
    rejected: tuple[str, ...]
    required_slots: int
    available_slots: int
    policy: AdmissionPolicy
    config_sha256: str
    warning: CapacityWarning | None


@dataclass(frozen=True, slots=True, init=False)
class ScopedCapacityDemand:
    scope: CatalogScope
    candidates: tuple[CapacityCandidate, ...]
    instruments_per_connection: int
    policies: Mapping[str, CapacityPolicy]

    def __init__(
        self,
        *,
        scope: CatalogScope,
        candidates: tuple[CapacityCandidate, ...],
        instruments_per_connection: int,
        policies: Mapping[str, CapacityPolicy],
    ) -> None:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be CatalogScope")
        if type(candidates) is not tuple or any(
            type(item) is not CapacityCandidate for item in candidates
        ):
            raise TypeError("candidates must be a tuple of CapacityCandidate")
        keys = tuple(item.instrument_key for item in candidates)
        if len(set(keys)) != len(keys):
            raise ValueError("candidate instrument keys must be unique within a scope")
        per_connection = _integer(
            instruments_per_connection,
            field="instruments_per_connection",
            minimum=1,
        )
        if not isinstance(policies, Mapping):
            raise TypeError("policies must be a mapping")
        normalized_policies: dict[str, CapacityPolicy] = {}
        for key, policy in policies.items():
            normalized_key = _nonempty(key, field="policy instrument key")
            normalized_policies[normalized_key] = _capacity_policy(policy)
        if set(normalized_policies) != set(keys):
            raise ValueError("policies must cover the exact candidate instrument keys")
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "candidates", candidates)
        object.__setattr__(self, "instruments_per_connection", per_connection)
        object.__setattr__(
            self,
            "policies",
            MappingProxyType(dict(sorted(normalized_policies.items()))),
        )


@dataclass(frozen=True, slots=True)
class ExchangeCapacityAdmission:
    connections_available: int
    connections_used: int
    connections_by_scope: Mapping[CatalogScope, int]
    admissions: Mapping[CatalogScope, CapacityAdmission]

    def __post_init__(self) -> None:
        available = _integer(
            self.connections_available,
            field="connections_available",
        )
        used = _integer(self.connections_used, field="connections_used")
        if used > available:
            raise ValueError("connections_used exceeds connections_available")
        if not isinstance(self.connections_by_scope, Mapping) or not isinstance(
            self.admissions, Mapping
        ):
            raise TypeError("exchange capacity results must be mappings")
        if set(self.connections_by_scope) != set(self.admissions):
            raise ValueError("connection and admission scopes must match")
        connections: dict[CatalogScope, int] = {}
        admissions: dict[CatalogScope, CapacityAdmission] = {}
        for scope in sorted(
            self.admissions,
            key=lambda item: (item.exchange.value, item.market.value),
        ):
            if type(scope) is not CatalogScope:
                raise TypeError("capacity result keys must be CatalogScope")
            connections[scope] = _integer(
                self.connections_by_scope[scope],
                field="scope connections",
            )
            admission = self.admissions[scope]
            if type(admission) is not CapacityAdmission:
                raise TypeError("admission values must be CapacityAdmission")
            admissions[scope] = admission
        if sum(connections.values()) != used:
            raise ValueError("scope connections must sum to connections_used")
        object.__setattr__(self, "connections_by_scope", MappingProxyType(connections))
        object.__setattr__(self, "admissions", MappingProxyType(admissions))


def calculate_egress_capacity(
    *,
    exchange: str,
    egresses: Iterable[EgressConfig],
    reachable_egress_ids: frozenset[str],
    subscriptions_per_connection: int,
    subscriptions_per_instrument: int,
) -> EgressCapacity:
    exchange_id = _nonempty(exchange, field="exchange")
    if type(reachable_egress_ids) is not frozenset or any(
        type(item) is not str or not item for item in reachable_egress_ids
    ):
        raise TypeError("reachable_egress_ids must be a frozenset of strings")
    per_connection = _integer(
        subscriptions_per_connection,
        field="subscriptions_per_connection",
        minimum=1,
    )
    per_instrument = _integer(
        subscriptions_per_instrument,
        field="subscriptions_per_instrument",
        minimum=1,
    )
    candidates = tuple(egresses)
    if any(type(item) is not EgressConfig for item in candidates):
        raise TypeError("egresses must contain EgressConfig values")
    by_id = {item.id: item for item in candidates}
    if len(by_id) != len(candidates):
        raise ValueError("egress IDs must be unique")
    unknown = tuple(sorted(reachable_egress_ids - by_id.keys()))
    if unknown:
        raise ValueError("unknown reachable egress IDs: " + ", ".join(unknown))
    healthy = tuple(by_id[item] for item in sorted(reachable_egress_ids))
    connections = sum(item.max_ws_connections for item in healthy)
    return EgressCapacity(
        exchange=exchange_id,
        healthy_egress_ids=tuple(item.id for item in healthy),
        quota_groups=tuple(sorted({item.quota_group for item in healthy})),
        ws_connections=connections,
        ws_subscription_slots=connections * per_connection,
        instrument_slots=sum(
            item.max_ws_connections * (per_connection // per_instrument)
            for item in healthy
        ),
        http_concurrency=sum(item.max_http_concurrency for item in healthy),
        subscriptions_per_connection=per_connection,
        subscriptions_per_instrument=per_instrument,
    )


def _admission_order(candidate: CapacityCandidate) -> tuple[int, int, str]:
    if candidate.priority is AdmissionPriority.FIXED:
        return (0, 0, candidate.instrument_key)
    if candidate.priority is AdmissionPriority.NEW_LISTING:
        return (1, candidate.first_seen_ns, candidate.instrument_key)
    assert candidate.top_n_rank is not None
    return (2, candidate.top_n_rank, candidate.instrument_key)


def _eviction_order(candidate: CapacityCandidate) -> tuple[int, int, str]:
    if candidate.priority is AdmissionPriority.TOP_N:
        assert candidate.top_n_rank is not None
        return (0, -candidate.top_n_rank, candidate.instrument_key)
    if candidate.priority is AdmissionPriority.NEW_LISTING:
        return (1, -candidate.first_seen_ns, candidate.instrument_key)
    return (2, 0, candidate.instrument_key)


def admit(
    candidates: Iterable[CapacityCandidate],
    *,
    slots: int,
    config_sha256: str,
    policy: CapacityPolicy = "degrade_low_priority_with_warning",
) -> CapacityAdmission:
    available = _integer(slots, field="slots")
    normalized_policy = _capacity_policy(policy)
    config_digest = _sha256(config_sha256)
    materialized = tuple(candidates)
    if any(type(item) is not CapacityCandidate for item in materialized):
        raise TypeError("candidates must contain CapacityCandidate values")
    keys = tuple(item.instrument_key for item in materialized)
    if len(set(keys)) != len(keys):
        raise ValueError("candidate instrument keys must be unique")
    fixed_count = sum(item.priority is AdmissionPriority.FIXED for item in materialized)
    if fixed_count > available:
        raise CapacityError("fixed pairs exceed available capacity")
    required = len(materialized)
    if required <= available:
        admitted = tuple(
            item.instrument_key for item in sorted(materialized, key=_admission_order)
        )
        return CapacityAdmission(
            admitted=admitted,
            rejected=(),
            required_slots=required,
            available_slots=available,
            policy=normalized_policy,
            config_sha256=config_digest,
            warning=None,
        )
    if normalized_policy == "fail":
        raise CapacityError(
            f"capacity shortfall: required {required}, available {available}"
        )

    removable = tuple(
        sorted(
            (
                item
                for item in materialized
                if item.priority is not AdmissionPriority.FIXED
            ),
            key=_eviction_order,
        )
    )
    rejected_candidates = removable[: required - available]
    rejected_keys = tuple(item.instrument_key for item in rejected_candidates)
    rejected_set = set(rejected_keys)
    admitted = tuple(
        item.instrument_key
        for item in sorted(materialized, key=_admission_order)
        if item.instrument_key not in rejected_set
    )
    warning = CapacityWarning(
        rejected=rejected_keys,
        required_slots=required,
        available_slots=available,
        config_sha256=config_digest,
    )
    return CapacityAdmission(
        admitted=admitted,
        rejected=rejected_keys,
        required_slots=required,
        available_slots=available,
        policy=normalized_policy,
        config_sha256=config_digest,
        warning=warning,
    )


def _scope_key(scope: CatalogScope) -> tuple[str, str]:
    return (scope.exchange.value, scope.market.value)


def _connection_chunk(
    demand: ScopedCapacityDemand,
    *,
    allocated_connections: int,
) -> tuple[CapacityCandidate, ...]:
    ordered = tuple(sorted(demand.candidates, key=_admission_order))
    start = allocated_connections * demand.instruments_per_connection
    return ordered[start : start + demand.instruments_per_connection]


def _best_connection_scope(
    options: tuple[tuple[ScopedCapacityDemand, tuple[CapacityCandidate, ...]], ...],
) -> CatalogScope:
    maximum_chunk = max(len(chunk) for _, chunk in options)
    sentinel = (3, _MAX_INT64 + 1, "")

    def key(
        option: tuple[ScopedCapacityDemand, tuple[CapacityCandidate, ...]],
    ) -> tuple[tuple[tuple[int, int, str], ...], tuple[str, str]]:
        demand, chunk = option
        candidate_keys = tuple(_admission_order(item) for item in chunk)
        padded = candidate_keys + (sentinel,) * (maximum_chunk - len(chunk))
        return (padded, _scope_key(demand.scope))

    return min(options, key=key)[0].scope


def admit_exchange_capacity(
    demands: Iterable[ScopedCapacityDemand],
    *,
    ws_connections: int,
    config_sha256: str,
) -> ExchangeCapacityAdmission:
    available_connections = _integer(ws_connections, field="ws_connections")
    digest = _sha256(config_sha256)
    materialized = tuple(demands)
    if any(type(item) is not ScopedCapacityDemand for item in materialized):
        raise TypeError("demands must contain ScopedCapacityDemand values")
    scopes = tuple(item.scope for item in materialized)
    if len(set(scopes)) != len(scopes):
        raise ValueError("capacity demand scopes must be unique")
    exchanges = {item.scope.exchange for item in materialized}
    if len(exchanges) > 1:
        raise ValueError("capacity demands must belong to one exchange")
    ordered = tuple(sorted(materialized, key=lambda item: _scope_key(item.scope)))

    allocations: dict[CatalogScope, int] = {}
    for demand in ordered:
        fixed_count = sum(
            item.priority is AdmissionPriority.FIXED for item in demand.candidates
        )
        allocations[demand.scope] = (
            fixed_count + demand.instruments_per_connection - 1
        ) // demand.instruments_per_connection
    if sum(allocations.values()) > available_connections:
        rejected_scope = max(
            (scope for scope, count in allocations.items() if count),
            key=_scope_key,
        )
        raise ScopedCapacityError(
            rejected_scope,
            "fixed pairs exceed available exchange connection capacity",
        )

    remaining = available_connections - sum(allocations.values())
    while remaining:
        options = tuple(
            (demand, chunk)
            for demand in ordered
            if (
                chunk := _connection_chunk(
                    demand,
                    allocated_connections=allocations[demand.scope],
                )
            )
        )
        if not options:
            break
        selected_scope = _best_connection_scope(options)
        allocations[selected_scope] += 1
        remaining -= 1

    admissions: dict[CatalogScope, CapacityAdmission] = {}
    for demand in ordered:
        allocated_slots = allocations[demand.scope] * demand.instruments_per_connection
        admission = admit(
            demand.candidates,
            slots=allocated_slots,
            config_sha256=digest,
            policy="degrade_low_priority_with_warning",
        )
        rejected_fail = tuple(
            key for key in admission.rejected if demand.policies[key] == "fail"
        )
        if rejected_fail:
            raise ScopedCapacityError(
                demand.scope,
                "capacity shortfall rejected fail-policy instruments in "
                f"{demand.scope.exchange.value}/{demand.scope.market.value}",
            )
        distinct_policies = set(demand.policies.values())
        report_policy: AdmissionPolicy = (
            next(iter(distinct_policies)) if len(distinct_policies) == 1 else "mixed"
        )
        admissions[demand.scope] = replace(admission, policy=report_policy)

    used = sum(allocations.values())
    return ExchangeCapacityAdmission(
        connections_available=available_connections,
        connections_used=used,
        connections_by_scope=allocations,
        admissions=admissions,
    )


__all__ = [
    "CapacityAdmission",
    "CapacityCandidate",
    "CapacityPolicy",
    "CapacityWarning",
    "EgressCapacity",
    "ExchangeCapacityAdmission",
    "ScopedCapacityDemand",
    "ScopedCapacityError",
    "admit",
    "admit_exchange_capacity",
    "calculate_egress_capacity",
]
