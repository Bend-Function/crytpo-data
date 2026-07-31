from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from hashlib import sha256

from crypto_collector.network.health import HealthSnapshot
from crypto_collector.network.models import Egress


class NoAvailableEgressError(RuntimeError):
    pass


def _nonnegative_integer(value: int, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _positive_integer(value: int, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


def _validate_fixed_key_components(*, exchange: str, market: str, channel: str) -> None:
    if (
        not exchange
        or "/" in exchange
        or not market
        or "/" in market
        or not channel
        or "/" in channel
    ):
        raise ValueError("assignment key components are invalid")


@dataclass(frozen=True, slots=True)
class _AssignmentKey:
    exchange: str
    market: str
    instrument_key: str
    channel: str

    @classmethod
    def parse(cls, value: str) -> _AssignmentKey:
        try:
            exchange, market, remainder = value.split("/", 2)
            instrument_key, channel = remainder.rsplit("/", 1)
        except ValueError as error:
            raise ValueError(
                "assignment key must be exchange/market/instrument/channel"
            ) from error
        if not exchange or not market or not instrument_key or not channel:
            raise ValueError(
                "assignment key must be exchange/market/instrument/channel"
            )
        return cls(exchange, market, instrument_key, channel)

    @classmethod
    def from_parts(
        cls,
        *,
        exchange: str,
        market: str,
        instrument_key: str,
        channel: str,
    ) -> _AssignmentKey:
        _validate_fixed_key_components(
            exchange=exchange,
            market=market,
            channel=channel,
        )
        if not instrument_key:
            raise ValueError("assignment key components are invalid")
        return cls(exchange, market, instrument_key, channel)

    @property
    def canonical(self) -> str:
        return f"{self.exchange}/{self.market}/{self.instrument_key}/{self.channel}"


@dataclass(frozen=True, slots=True)
class StickyAssignment:
    key: str
    exchange: str
    market: str
    instrument_key: str
    channel: str
    egress_id: str
    quota_group: str
    generation: int

    def __post_init__(self) -> None:
        parsed = _AssignmentKey.parse(self.key)
        if (
            parsed.exchange != self.exchange
            or parsed.market != self.market
            or parsed.instrument_key != self.instrument_key
            or parsed.channel != self.channel
        ):
            raise ValueError("sticky assignment fields must match its canonical key")
        if not self.egress_id or not self.quota_group:
            raise ValueError("sticky assignment egress fields must be non-empty")
        _nonnegative_integer(self.generation, field="generation")

    @classmethod
    def create(
        cls,
        key: str,
        egress: Egress,
        *,
        generation: int = 0,
    ) -> StickyAssignment:
        parsed = _AssignmentKey.parse(key)
        generation = _nonnegative_integer(generation, field="generation")
        return cls(
            key=parsed.canonical,
            exchange=parsed.exchange,
            market=parsed.market,
            instrument_key=parsed.instrument_key,
            channel=parsed.channel,
            egress_id=egress.id,
            quota_group=egress.quota_group,
            generation=generation,
        )


@dataclass(frozen=True, slots=True)
class EgressShard:
    egress_id: str
    index: int
    assignments: tuple[StickyAssignment, ...]

    @property
    def instrument_keys(self) -> tuple[str, ...]:
        return tuple(item.instrument_key for item in self.assignments)


def _validated_egresses(egresses: Iterable[Egress]) -> tuple[Egress, ...]:
    candidates = tuple(egresses)
    if not candidates:
        raise NoAvailableEgressError("no egresses are configured")
    ids = [candidate.id for candidate in candidates]
    if len(set(ids)) != len(ids):
        raise ValueError("duplicate egress id")
    return tuple(sorted(candidates, key=lambda candidate: candidate.id))


def _score(key: str, egress_id: str) -> int:
    digest = sha256(f"{key}\0{egress_id}".encode()).digest()
    return int.from_bytes(digest, "big", signed=False)


def _ranked_healthy_egresses(
    key: _AssignmentKey,
    egresses: Iterable[Egress],
    health: HealthSnapshot,
) -> tuple[Egress, ...]:
    candidates = _validated_egresses(egresses)
    healthy = tuple(
        candidate
        for candidate in candidates
        if health.is_available(key.exchange, candidate.id)
    )
    return tuple(
        sorted(
            healthy,
            key=lambda candidate: (_score(key.canonical, candidate.id), candidate.id),
            reverse=True,
        )
    )


def choose_egress(
    key: str,
    egresses: Iterable[Egress],
    health: HealthSnapshot | None = None,
) -> Egress:
    parsed = _AssignmentKey.parse(key)
    ranked = _ranked_healthy_egresses(
        parsed,
        egresses,
        HealthSnapshot() if health is None else health,
    )
    if not ranked:
        raise NoAvailableEgressError(
            f"no healthy egress is available for exchange {parsed.exchange!r}"
        )
    return ranked[0]


def assign_instruments(
    instruments: Iterable[str],
    *,
    exchange: str,
    market: str,
    channel: str,
    egresses: Iterable[Egress],
    subscriptions_per_connection: int,
    health: HealthSnapshot | None = None,
    generation: int = 0,
) -> tuple[StickyAssignment, ...]:
    _validate_fixed_key_components(
        exchange=exchange,
        market=market,
        channel=channel,
    )
    subscriptions_per_connection = _positive_integer(
        subscriptions_per_connection,
        field="subscriptions_per_connection",
    )
    generation = _nonnegative_integer(generation, field="generation")
    instrument_keys = tuple(instruments)
    if any(not instrument for instrument in instrument_keys):
        raise ValueError("instrument keys must be non-empty")
    if len(set(instrument_keys)) != len(instrument_keys):
        raise ValueError("instrument keys must be unique")
    candidates = _validated_egresses(egresses)
    snapshot = HealthSnapshot() if health is None else health
    capacity = {
        candidate.id: candidate.max_ws_connections * subscriptions_per_connection
        for candidate in candidates
        if snapshot.is_available(exchange, candidate.id)
    }
    if len(instrument_keys) > sum(capacity.values()):
        raise NoAvailableEgressError(
            "instrument demand exceeds total healthy egress capacity"
        )

    used: defaultdict[str, int] = defaultdict(int)
    assignments: list[StickyAssignment] = []
    for instrument in sorted(instrument_keys):
        key = _AssignmentKey.from_parts(
            exchange=exchange,
            market=market,
            instrument_key=instrument,
            channel=channel,
        )
        ranked = _ranked_healthy_egresses(key, candidates, snapshot)
        selected = next(
            (
                candidate
                for candidate in ranked
                if used[candidate.id] < capacity[candidate.id]
            ),
            None,
        )
        if selected is None:
            raise NoAvailableEgressError(
                "instrument demand exceeds total healthy egress capacity"
            )
        used[selected.id] += 1
        assignments.append(
            StickyAssignment.create(
                key.canonical,
                selected,
                generation=generation,
            )
        )
    return tuple(assignments)


def pack_egress_shards(
    assignments: Iterable[StickyAssignment],
    *,
    egresses: Sequence[Egress],
    subscriptions_per_connection: int,
) -> tuple[EgressShard, ...]:
    subscriptions_per_connection = _positive_integer(
        subscriptions_per_connection,
        field="subscriptions_per_connection",
    )
    candidates = _validated_egresses(egresses)
    by_id = {candidate.id: candidate for candidate in candidates}
    materialized = tuple(assignments)
    cohorts = {
        (item.exchange, item.market, item.channel, item.generation)
        for item in materialized
    }
    if len(cohorts) > 1:
        raise ValueError("sharding requires one assignment cohort")
    grouped: defaultdict[str, list[StickyAssignment]] = defaultdict(list)
    seen_keys: set[str] = set()
    for assignment in materialized:
        if assignment.key in seen_keys:
            raise ValueError("assignment keys must be unique")
        seen_keys.add(assignment.key)
        if assignment.egress_id not in by_id:
            raise ValueError(
                f"assignment references unknown egress {assignment.egress_id!r}"
            )
        if assignment.quota_group != by_id[assignment.egress_id].quota_group:
            raise ValueError("assignment quota group does not match current egress")
        grouped[assignment.egress_id].append(assignment)

    shards: list[EgressShard] = []
    for egress_id in sorted(grouped):
        items = sorted(grouped[egress_id], key=lambda item: item.key)
        chunks = [
            tuple(items[offset : offset + subscriptions_per_connection])
            for offset in range(0, len(items), subscriptions_per_connection)
        ]
        if len(chunks) > by_id[egress_id].max_ws_connections:
            raise NoAvailableEgressError(
                f"assignments exceed egress {egress_id!r} shard capacity"
            )
        shards.extend(
            EgressShard(egress_id=egress_id, index=index, assignments=chunk)
            for index, chunk in enumerate(chunks)
        )
    return tuple(shards)
