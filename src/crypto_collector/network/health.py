from __future__ import annotations

from dataclasses import dataclass, field
from decimal import Decimal

EgressHealthKey = tuple[str, str]


def _nonnegative(value: int, *, field_name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field_name} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class HealthSnapshot:
    unavailable: frozenset[EgressHealthKey] = field(default_factory=frozenset)
    probe_eligible: frozenset[EgressHealthKey] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.probe_eligible <= self.unavailable:
            raise ValueError("probe-eligible egresses must also be unavailable")

    def is_available(self, exchange: str, egress_id: str) -> bool:
        return (exchange, egress_id) not in self.unavailable

    def may_probe(self, exchange: str, egress_id: str) -> bool:
        return (exchange, egress_id) in self.probe_eligible


@dataclass(frozen=True, slots=True)
class QuotaProbeAdmission:
    exchange: str
    quota_group: str
    restriction_revision: int
    probe_after_monotonic_ns: int
    _store_identity: object = field(repr=False)

    def __post_init__(self) -> None:
        if not self.exchange or not self.quota_group:
            raise ValueError("quota probe admission keys must be non-empty")
        _nonnegative(self.restriction_revision, field_name="restriction_revision")
        _nonnegative(
            self.probe_after_monotonic_ns,
            field_name="probe monotonic deadline",
        )


@dataclass(frozen=True, slots=True)
class TransportProbeAdmission:
    exchange: str
    egress_id: str
    restriction_revision: int
    probe_after_monotonic_ns: int
    _store_identity: object = field(repr=False)

    def __post_init__(self) -> None:
        if not self.exchange or not self.egress_id:
            raise ValueError("transport probe admission keys must be non-empty")
        _nonnegative(self.restriction_revision, field_name="restriction_revision")
        _nonnegative(
            self.probe_after_monotonic_ns,
            field_name="probe monotonic deadline",
        )


@dataclass(frozen=True, slots=True)
class AdmittedHealth:
    probe_after_monotonic_ns: tuple[tuple[EgressHealthKey, int], ...] = ()
    quota_probe_admissions: tuple[QuotaProbeAdmission, ...] = ()
    transport_probe_admissions: tuple[TransportProbeAdmission, ...] = ()

    def __post_init__(self) -> None:
        keys: set[EgressHealthKey] = set()
        for key, deadline in self.probe_after_monotonic_ns:
            if not key[0] or not key[1]:
                raise ValueError("admitted health keys must be non-empty")
            if key in keys:
                raise ValueError("admitted health keys must be unique")
            keys.add(key)
            _nonnegative(deadline, field_name="probe monotonic deadline")
        quota_keys = [
            (admission.exchange, admission.quota_group)
            for admission in self.quota_probe_admissions
        ]
        if len(set(quota_keys)) != len(quota_keys):
            raise ValueError("quota probe admission keys must be unique")
        transport_keys = [
            (admission.exchange, admission.egress_id)
            for admission in self.transport_probe_admissions
        ]
        if len(set(transport_keys)) != len(transport_keys):
            raise ValueError("transport probe admission keys must be unique")

    def snapshot(self, *, now_monotonic_ns: int) -> HealthSnapshot:
        now_monotonic_ns = _nonnegative(now_monotonic_ns, field_name="now_monotonic_ns")
        unavailable = frozenset(key for key, _deadline in self.probe_after_monotonic_ns)
        probe_eligible = frozenset(
            key
            for key, deadline in self.probe_after_monotonic_ns
            if now_monotonic_ns >= deadline
        )
        return HealthSnapshot(
            unavailable=unavailable,
            probe_eligible=probe_eligible,
        )

    def quota_probe(
        self, *, exchange: str, quota_group: str
    ) -> QuotaProbeAdmission | None:
        return next(
            (
                admission
                for admission in self.quota_probe_admissions
                if admission.exchange == exchange
                and admission.quota_group == quota_group
            ),
            None,
        )

    def transport_probe(
        self, *, exchange: str, egress_id: str
    ) -> TransportProbeAdmission | None:
        return next(
            (
                admission
                for admission in self.transport_probe_admissions
                if admission.exchange == exchange and admission.egress_id == egress_id
            ),
            None,
        )


@dataclass(frozen=True, slots=True)
class QuotaState:
    exchange: str
    quota_group: str
    ban_until_unix_ns: int = 0
    cooldown_until_unix_ns: int = 0
    current_rate_multiplier: Decimal = Decimal(1)
    last_reason: str | None = None
    restriction_revision: int = 0

    @property
    def restriction_until_unix_ns(self) -> int:
        return max(self.ban_until_unix_ns, self.cooldown_until_unix_ns)

    @property
    def requires_probe(self) -> bool:
        return self.last_reason is not None


@dataclass(frozen=True, slots=True)
class EgressHealthState:
    exchange: str
    egress_id: str
    consecutive_transport_failures: int = 0
    cooldown_until_unix_ns: int = 0
    last_success_unix_ns: int | None = None
    last_latency_ns: int | None = None
    last_reason: str | None = None
    restriction_revision: int = 0

    @property
    def requires_probe(self) -> bool:
        return self.consecutive_transport_failures > 0
