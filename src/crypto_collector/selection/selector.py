from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import IntEnum, IntFlag
from types import MappingProxyType

from crypto_collector.selection.models import (
    CatalogInstrument,
    CatalogScope,
    CatalogView,
    ListingState,
    SelectionScope,
    Turnover,
)

_MAX_INT64 = 2**63 - 1
_SHA256_HEX_LENGTH = 64


def _integer(
    value: object,
    *,
    field: str,
    minimum: int = 0,
) -> int:
    if type(value) is not int:
        raise TypeError(f"{field} must be an integer")
    if value < minimum:
        qualifier = "positive" if minimum == 1 else "non-negative"
        raise ValueError(f"{field} must be {qualifier}")
    if value > _MAX_INT64:
        raise ValueError(f"{field} must fit a signed 64-bit integer")
    return value


def _optional_integer(
    value: object,
    *,
    field: str,
    minimum: int = 0,
) -> int | None:
    if value is None:
        return None
    return _integer(value, field=field, minimum=minimum)


def _scope(value: object, *, field: str = "scope") -> SelectionScope:
    if type(value) is not CatalogScope:
        raise TypeError(f"{field} must be SelectionScope")
    return value


def _sha256(value: object, *, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != _SHA256_HEX_LENGTH
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _selection_strings(
    value: object,
    *,
    field: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{field} must be a tuple")
    if not value and not allow_empty:
        raise ValueError(f"{field} must not be empty")
    normalized: list[str] = []
    identities: set[str] = set()
    for item in value:
        if type(item) is not str:
            raise TypeError(f"{field} entries must be strings")
        stripped = item.strip()
        if not stripped:
            raise ValueError(f"{field} entries must not be blank")
        identity = stripped.casefold()
        if identity in identities:
            raise ValueError(f"{field} entries must be unique under case-folding")
        identities.add(identity)
        normalized.append(stripped)
    return tuple(normalized)


class SelectionReason(IntFlag):
    FIXED = 1
    NEW_LISTING = 2
    TOP_N = 4
    TOP_N_GRACE = 8

    @property
    def fixed(self) -> bool:
        return bool(self & type(self).FIXED)

    @property
    def new_listing(self) -> bool:
        return bool(self & type(self).NEW_LISTING)

    @property
    def top_n(self) -> bool:
        return bool(self & type(self).TOP_N)

    @property
    def top_n_grace(self) -> bool:
        return bool(self & type(self).TOP_N_GRACE)


class AdmissionPriority(IntEnum):
    TOP_N = 1
    NEW_LISTING = 2
    FIXED = 3


@dataclass(frozen=True, slots=True, init=False)
class SelectionPolicy:
    scope: SelectionScope
    quote_assets: tuple[str, ...]
    top_n: int
    turnover_max_age_ns: int
    new_listings_enabled: bool
    new_listing_capture_duration_ns: int
    exit_grace_ns: int
    policy_id: str

    def __init__(
        self,
        *,
        scope: SelectionScope,
        quote_assets: tuple[str, ...],
        top_n: int,
        turnover_max_age_ns: int,
        new_listings_enabled: bool,
        new_listing_capture_duration_ns: int,
        exit_grace_ns: int,
    ) -> None:
        normalized_scope = _scope(scope)
        normalized_quotes = _selection_strings(
            quote_assets,
            field="quote_assets",
            allow_empty=False,
        )
        normalized_top_n = _integer(top_n, field="top_n")
        normalized_turnover_age = _integer(
            turnover_max_age_ns,
            field="turnover_max_age_ns",
            minimum=1,
        )
        if type(new_listings_enabled) is not bool:
            raise TypeError("new_listings_enabled must be a boolean")
        normalized_capture_duration = _integer(
            new_listing_capture_duration_ns,
            field="new_listing_capture_duration_ns",
            minimum=1,
        )
        normalized_exit_grace = _integer(
            exit_grace_ns,
            field="exit_grace_ns",
        )
        canonical = {
            "exit_grace_ns": normalized_exit_grace,
            "new_listing_capture_duration_ns": normalized_capture_duration,
            "new_listings_enabled": new_listings_enabled,
            "quote_assets": list(normalized_quotes),
            "top_n": normalized_top_n,
            "turnover_max_age_ns": normalized_turnover_age,
        }
        encoded = json.dumps(
            canonical,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        object.__setattr__(self, "scope", normalized_scope)
        object.__setattr__(self, "quote_assets", normalized_quotes)
        object.__setattr__(self, "top_n", normalized_top_n)
        object.__setattr__(self, "turnover_max_age_ns", normalized_turnover_age)
        object.__setattr__(self, "new_listings_enabled", new_listings_enabled)
        object.__setattr__(
            self,
            "new_listing_capture_duration_ns",
            normalized_capture_duration,
        )
        object.__setattr__(self, "exit_grace_ns", normalized_exit_grace)
        object.__setattr__(self, "policy_id", hashlib.sha256(encoded).hexdigest())


@dataclass(frozen=True, slots=True)
class ResolvedFixedSelection:
    scope: SelectionScope
    catalog_revision: int
    instrument_keys: frozenset[str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "scope", _scope(self.scope))
        object.__setattr__(
            self,
            "catalog_revision",
            _integer(
                self.catalog_revision,
                field="catalog_revision",
                minimum=1,
            ),
        )
        if type(self.instrument_keys) is not frozenset:
            raise TypeError("instrument_keys must be a frozenset")
        for key in self.instrument_keys:
            if type(key) is not str or not key:
                raise ValueError("instrument_keys must contain non-empty strings")


@dataclass(frozen=True, slots=True)
class SelectionEntry:
    instrument: CatalogInstrument
    reasons: SelectionReason
    top_n_rank: int | None
    top_exit_started_at_ns: int | None

    def __post_init__(self) -> None:
        if type(self.instrument) is not CatalogInstrument:
            raise TypeError("instrument must be CatalogInstrument")
        if type(self.reasons) is not SelectionReason:
            raise TypeError("reasons must be SelectionReason")
        known = (
            SelectionReason.FIXED
            | SelectionReason.NEW_LISTING
            | SelectionReason.TOP_N
            | SelectionReason.TOP_N_GRACE
        )
        if not self.reasons or int(self.reasons) & ~int(known):
            raise ValueError("reasons must contain only known selection reasons")
        if self.reasons.top_n and self.reasons.top_n_grace:
            raise ValueError("TOP_N and TOP_N_GRACE are mutually exclusive")
        rank = _optional_integer(
            self.top_n_rank,
            field="top_n_rank",
            minimum=1,
        )
        if self.reasons.top_n and rank is None:
            raise ValueError("TOP_N requires a quote-local rank")
        if not (self.reasons.top_n or self.reasons.top_n_grace) and rank is not None:
            raise ValueError("top_n_rank requires TOP_N or TOP_N_GRACE")
        exit_started = _optional_integer(
            self.top_exit_started_at_ns,
            field="top_exit_started_at_ns",
        )
        if self.reasons.top_n_grace != (exit_started is not None):
            raise ValueError(
                "top_exit_started_at_ns must exist exactly for TOP_N_GRACE"
            )
        object.__setattr__(self, "top_n_rank", rank)
        object.__setattr__(self, "top_exit_started_at_ns", exit_started)

    @property
    def instrument_key(self) -> str:
        return self.instrument.instrument_key

    @property
    def admission_priority(self) -> AdmissionPriority:
        if self.reasons.fixed:
            return AdmissionPriority.FIXED
        if self.reasons.new_listing:
            return AdmissionPriority.NEW_LISTING
        return AdmissionPriority.TOP_N


def _immutable_entries(
    value: object,
    *,
    scope: SelectionScope,
) -> Mapping[str, SelectionEntry]:
    if not isinstance(value, Mapping):
        raise TypeError("entries must be a mapping")
    normalized: dict[str, SelectionEntry] = {}
    for key, entry in value.items():
        if type(key) is not str or not key:
            raise ValueError("entry keys must be non-empty strings")
        if type(entry) is not SelectionEntry:
            raise TypeError("entry values must be SelectionEntry")
        if key != entry.instrument_key:
            raise ValueError("entry key must match its instrument_key")
        if entry.instrument.scope != scope:
            raise ValueError("entry instrument scope must match selection scope")
        normalized[key] = entry
    return MappingProxyType(dict(sorted(normalized.items())))


@dataclass(frozen=True, slots=True)
class SelectionState:
    scope: SelectionScope
    catalog_revision: int
    turnover_revision: int
    policy_id: str
    revision: int
    entries: Mapping[str, SelectionEntry]

    def __post_init__(self) -> None:
        normalized_scope = _scope(self.scope)
        object.__setattr__(self, "scope", normalized_scope)
        object.__setattr__(
            self,
            "catalog_revision",
            _integer(
                self.catalog_revision,
                field="catalog_revision",
                minimum=1,
            ),
        )
        object.__setattr__(
            self,
            "turnover_revision",
            _integer(self.turnover_revision, field="turnover_revision"),
        )
        object.__setattr__(
            self,
            "policy_id",
            _sha256(self.policy_id, field="policy_id"),
        )
        object.__setattr__(
            self,
            "revision",
            _integer(self.revision, field="revision"),
        )
        object.__setattr__(
            self,
            "entries",
            _immutable_entries(self.entries, scope=normalized_scope),
        )

    @property
    def selected(self) -> frozenset[str]:
        return frozenset(self.entries)

    @property
    def state_revision(self) -> int:
        return self.revision

    def entry(self, instrument_key: str) -> SelectionEntry:
        return self.entries[instrument_key]


@dataclass(frozen=True, slots=True)
class SelectionDelta:
    instrument_key: str
    previous: SelectionEntry | None
    current: SelectionEntry | None

    def __post_init__(self) -> None:
        if type(self.instrument_key) is not str or not self.instrument_key:
            raise ValueError("instrument_key must be a non-empty string")
        if self.previous is None and self.current is None:
            raise ValueError("selection delta requires a previous or current value")
        for value in (self.previous, self.current):
            if value is not None and value.instrument_key != self.instrument_key:
                raise ValueError("delta values must match instrument_key")


@dataclass(frozen=True, slots=True)
class SelectionResult:
    scope: SelectionScope
    catalog_revision: int
    turnover_revision: int
    policy_id: str
    entries: Mapping[str, SelectionEntry]
    next_state: SelectionState
    deltas: tuple[SelectionDelta, ...]

    def __post_init__(self) -> None:
        normalized_scope = _scope(self.scope)
        catalog_revision = _integer(
            self.catalog_revision,
            field="catalog_revision",
            minimum=1,
        )
        turnover_revision = _integer(
            self.turnover_revision,
            field="turnover_revision",
        )
        policy_id = _sha256(self.policy_id, field="policy_id")
        entries = _immutable_entries(self.entries, scope=normalized_scope)
        if type(self.next_state) is not SelectionState:
            raise TypeError("next_state must be SelectionState")
        if (
            self.next_state.scope != normalized_scope
            or self.next_state.catalog_revision != catalog_revision
            or self.next_state.turnover_revision != turnover_revision
            or self.next_state.policy_id != policy_id
            or self.next_state.entries != entries
        ):
            raise ValueError("next_state must describe this exact selection result")
        if type(self.deltas) is not tuple or any(
            type(item) is not SelectionDelta for item in self.deltas
        ):
            raise TypeError("deltas must be a tuple of SelectionDelta")
        delta_keys = tuple(item.instrument_key for item in self.deltas)
        if delta_keys != tuple(sorted(delta_keys)) or len(delta_keys) != len(
            set(delta_keys)
        ):
            raise ValueError("deltas must have unique instrument keys in sorted order")
        for delta in self.deltas:
            for value in (delta.previous, delta.current):
                if value is not None and value.instrument.scope != normalized_scope:
                    raise ValueError("delta entries must match result scope")
            if delta.current != entries.get(delta.instrument_key):
                raise ValueError("delta current value must match result entries")
        object.__setattr__(self, "scope", normalized_scope)
        object.__setattr__(self, "catalog_revision", catalog_revision)
        object.__setattr__(self, "turnover_revision", turnover_revision)
        object.__setattr__(self, "policy_id", policy_id)
        object.__setattr__(self, "entries", entries)

    @property
    def selected(self) -> frozenset[str]:
        return frozenset(self.entries)

    @property
    def delta(self) -> tuple[SelectionDelta, ...]:
        return self.deltas

    def entry(self, instrument_key: str) -> SelectionEntry:
        return self.entries[instrument_key]

    def reason(self, instrument_key: str) -> SelectionReason:
        return self.entry(instrument_key).reasons


def _validate_catalog(
    catalog: object,
) -> tuple[CatalogView, dict[str, CatalogInstrument]]:
    if type(catalog) is not CatalogView:
        raise TypeError("catalog must be CatalogView")
    scope = _scope(catalog.scope, field="catalog scope")
    catalog_revision = _integer(
        catalog.catalog_revision,
        field="catalog revision",
        minimum=1,
    )
    turnover_revision = _integer(
        catalog.turnover_revision,
        field="turnover revision",
    )
    _optional_integer(
        catalog.catalog_observed_at_ns,
        field="catalog observed_at_ns",
    )
    turnover_observed_at_ns = _optional_integer(
        catalog.turnover_observed_at_ns,
        field="turnover observed_at_ns",
    )
    turnover_catalog_revision = _optional_integer(
        catalog.turnover_catalog_revision,
        field="turnover catalog revision",
        minimum=1,
    )
    if turnover_revision == 0 and (
        turnover_observed_at_ns is not None
        or turnover_catalog_revision is not None
        or catalog.turnover_digest_sha256 is not None
    ):
        raise ValueError("empty turnover state must not carry provenance")
    if turnover_revision > 0 and (
        turnover_observed_at_ns is None
        or turnover_catalog_revision is None
        or catalog.turnover_digest_sha256 is None
    ):
        raise ValueError("turnover state requires complete provenance")
    if turnover_catalog_revision is not None and turnover_catalog_revision > (
        catalog_revision
    ):
        raise ValueError("turnover cannot be bound to a future catalog revision")
    if type(catalog.instruments) is not tuple:
        raise TypeError("catalog instruments must be a tuple")
    instruments: dict[str, CatalogInstrument] = {}
    for item in catalog.instruments:
        if type(item) is not CatalogInstrument:
            raise TypeError("catalog instruments must be CatalogInstrument")
        if item.scope != scope:
            raise ValueError("catalog instrument scope mismatch")
        if item.instrument_key in instruments:
            raise ValueError("catalog instrument keys must be unique")
        instruments[item.instrument_key] = item
    return catalog, instruments


def _validate_inputs(
    catalog: CatalogView,
    *,
    fixed: ResolvedFixedSelection,
    policy: SelectionPolicy,
    previous: SelectionState | None,
) -> None:
    if type(policy) is not SelectionPolicy:
        raise TypeError("policy must be SelectionPolicy")
    if type(fixed) is not ResolvedFixedSelection:
        raise TypeError("fixed must be ResolvedFixedSelection")
    if policy.scope != catalog.scope:
        raise ValueError("policy scope does not match catalog scope")
    if fixed.scope != catalog.scope:
        raise ValueError("fixed selection scope does not match catalog scope")
    if fixed.catalog_revision != catalog.catalog_revision:
        raise ValueError("fixed selection revision does not match catalog revision")
    if previous is None:
        return
    if type(previous) is not SelectionState:
        raise TypeError("previous must be SelectionState or None")
    if previous.scope != catalog.scope:
        raise ValueError("previous state scope does not match catalog scope")
    if previous.policy_id != policy.policy_id:
        raise ValueError("previous state policy does not match selection policy")
    if previous.catalog_revision > catalog.catalog_revision:
        raise ValueError("previous state catalog revision is from the future")
    if previous.turnover_revision > catalog.turnover_revision:
        raise ValueError("previous state turnover revision is from the future")


def _rank_top_n(
    catalog: CatalogView,
    instruments: Mapping[str, CatalogInstrument],
    *,
    policy: SelectionPolicy,
    now_ns: int,
) -> dict[str, int]:
    if (
        catalog.turnover_revision == 0
        or catalog.turnover_catalog_revision != catalog.catalog_revision
        or policy.top_n == 0
    ):
        return {}
    covered_instrument_keys = frozenset(catalog.turnover_covered_instrument_keys)
    ranks: dict[str, int] = {}
    for quote in policy.quote_assets:
        eligible: list[CatalogInstrument] = []
        for item in instruments.values():
            turnover = item.turnover
            if (
                not item.present
                or not item.tradable
                or item.instrument_key not in covered_instrument_keys
                or item.quote_asset != quote
                or type(turnover) is not Turnover
                or turnover.currency != quote
                or turnover.observed_at_ns is None
                or turnover.observed_at_ns > now_ns
                or now_ns - turnover.observed_at_ns > policy.turnover_max_age_ns
            ):
                continue
            eligible.append(item)
        eligible.sort(key=lambda item: item.instrument_key)
        eligible.sort(
            key=lambda item: item.turnover.value if item.turnover else 0,
            reverse=True,
        )
        for rank, item in enumerate(eligible[: policy.top_n], start=1):
            ranks[item.instrument_key] = rank
    return ranks


def _is_active_new_listing(
    item: CatalogInstrument,
    *,
    policy: SelectionPolicy,
    now_ns: int,
) -> bool:
    start = item.new_listing_started_at_ns
    return (
        policy.new_listings_enabled
        and item.present
        and item.tradable
        and item.quote_asset in policy.quote_assets
        and item.listing_state is ListingState.ACTIVE_NEW
        and item.new_listing_eligible
        and start is not None
        and start <= now_ns
        and now_ns - start < policy.new_listing_capture_duration_ns
    )


def select(
    catalog: CatalogView,
    *,
    fixed: ResolvedFixedSelection,
    policy: SelectionPolicy,
    previous: SelectionState | None,
    now_ns: int,
) -> SelectionResult:
    normalized_now = _integer(now_ns, field="now_ns")
    catalog, instruments = _validate_catalog(catalog)
    _validate_inputs(
        catalog,
        fixed=fixed,
        policy=policy,
        previous=previous,
    )

    for key in sorted(fixed.instrument_keys):
        item = instruments.get(key)
        if item is None:
            raise ValueError(f"fixed instrument {key!r} is not in catalog")
        if not item.present or not item.tradable:
            raise ValueError(f"fixed instrument {key!r} must be present and tradable")

    top_ranks = _rank_top_n(
        catalog,
        instruments,
        policy=policy,
        now_ns=normalized_now,
    )
    reasons: dict[str, SelectionReason] = {}
    ranks: dict[str, int | None] = {}
    grace_starts: dict[str, int | None] = {}

    for key in fixed.instrument_keys:
        reasons[key] = reasons.get(key, SelectionReason(0)) | SelectionReason.FIXED
    for key, item in instruments.items():
        if _is_active_new_listing(item, policy=policy, now_ns=normalized_now):
            reasons[key] = (
                reasons.get(key, SelectionReason(0)) | SelectionReason.NEW_LISTING
            )
    for key, rank in top_ranks.items():
        reasons[key] = reasons.get(key, SelectionReason(0)) | SelectionReason.TOP_N
        ranks[key] = rank
        grace_starts[key] = None

    previous_entries = {} if previous is None else previous.entries
    for old_entry in previous_entries.values():
        persisted_exit_started = old_entry.top_exit_started_at_ns
        if (
            old_entry.reasons.top_n_grace
            and persisted_exit_started is not None
            and normalized_now < persisted_exit_started
        ):
            raise ValueError("now_ns precedes a persisted top-exit grace deadline")
    for key, old_entry in previous_entries.items():
        if key in top_ranks:
            continue
        current = instruments.get(key)
        if (
            current is None
            or not current.present
            or not current.tradable
            or current.quote_asset not in policy.quote_assets
            or current.listing_generation != old_entry.instrument.listing_generation
        ):
            continue
        exit_started: int | None = None
        if old_entry.reasons.top_n:
            exit_started = normalized_now
        elif old_entry.reasons.top_n_grace:
            exit_started = old_entry.top_exit_started_at_ns
        if (
            exit_started is not None
            and exit_started <= normalized_now
            and normalized_now - exit_started < policy.exit_grace_ns
        ):
            reasons[key] = (
                reasons.get(key, SelectionReason(0)) | SelectionReason.TOP_N_GRACE
            )
            ranks[key] = old_entry.top_n_rank
            grace_starts[key] = exit_started

    entries = {
        key: SelectionEntry(
            instrument=instruments[key],
            reasons=reason,
            top_n_rank=ranks.get(key),
            top_exit_started_at_ns=grace_starts.get(key),
        )
        for key, reason in sorted(reasons.items())
    }
    immutable_entries = _immutable_entries(entries, scope=catalog.scope)
    next_state = SelectionState(
        scope=catalog.scope,
        catalog_revision=catalog.catalog_revision,
        turnover_revision=catalog.turnover_revision,
        policy_id=policy.policy_id,
        revision=0 if previous is None else previous.revision,
        entries=immutable_entries,
    )
    deltas = tuple(
        SelectionDelta(
            instrument_key=key,
            previous=previous_entries.get(key),
            current=immutable_entries.get(key),
        )
        for key in sorted(set(previous_entries) | set(immutable_entries))
        if previous_entries.get(key) != immutable_entries.get(key)
    )
    return SelectionResult(
        scope=catalog.scope,
        catalog_revision=catalog.catalog_revision,
        turnover_revision=catalog.turnover_revision,
        policy_id=policy.policy_id,
        entries=immutable_entries,
        next_state=next_state,
        deltas=deltas,
    )
