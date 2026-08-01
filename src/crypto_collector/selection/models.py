from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from itertools import pairwise
from types import MappingProxyType
from typing import TypeAlias, TypeVar, cast

from crypto_collector.domain.json_codec import JsonPayload
from crypto_collector.domain.types import Exchange, Market

FrozenJsonPayload: TypeAlias = (
    bool
    | int
    | Decimal
    | str
    | None
    | tuple["FrozenJsonPayload", ...]
    | Mapping[str, "FrozenJsonPayload"]
)
_StrEnumT = TypeVar("_StrEnumT", bound=StrEnum)


def _nonempty_string(value: object, *, field: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _nonnegative_int(value: object, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    if value > 2**63 - 1:
        raise ValueError(f"{field} must fit a signed 64-bit integer")
    return value


def _optional_nonnegative_int(value: object, *, field: str) -> int | None:
    if value is None:
        return None
    return _nonnegative_int(value, field=field)


def _positive_int(value: object, *, field: str) -> int:
    normalized = _nonnegative_int(value, field=field)
    if normalized == 0:
        raise ValueError(f"{field} must be positive")
    return normalized


def _sha256_digest(value: object, *, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a lowercase SHA-256 hex digest")
    return value


def _nonempty_string_tuple(value: object, *, field: str) -> tuple[str, ...]:
    if type(value) is not tuple or not value:
        raise ValueError(f"{field} must be a non-empty tuple")
    normalized = tuple(_nonempty_string(item, field=f"{field} item") for item in value)
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{field} must not contain duplicates")
    return normalized


def _optional_nonempty_string(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    return _nonempty_string(value, field=field)


def _enum_member(
    value: object,
    enum_type: type[_StrEnumT],
    *,
    field: str,
) -> _StrEnumT:
    if isinstance(value, enum_type):
        return value
    if type(value) is not str:
        raise TypeError(f"{field} must be a {enum_type.__name__} or string")
    try:
        return enum_type(value)
    except ValueError as error:
        raise ValueError(f"unsupported {field}: {value!r}") from error


def _freeze_json(value: object) -> FrozenJsonPayload:
    if value is None or type(value) in {bool, int, str}:
        return cast(FrozenJsonPayload, value)
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError("lifecycle Decimal values must be finite")
        return value
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise ValueError("lifecycle object keys must be strings")
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    raise ValueError(f"lifecycle contains unsupported type {type(value).__name__}")


def mutable_json_copy(value: FrozenJsonPayload) -> JsonPayload:
    if isinstance(value, Mapping):
        return {key: mutable_json_copy(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [mutable_json_copy(item) for item in value]
    return value


def _wire_symbols(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping) or not value:
        raise ValueError("wire_symbols must be a non-empty mapping")
    normalized: dict[str, str] = {}
    for protocol, symbol in value.items():
        normalized[_nonempty_string(protocol, field="wire symbol protocol")] = (
            _nonempty_string(symbol, field="wire symbol")
        )
    return MappingProxyType(normalized)


class TradableAtSource(StrEnum):
    EXCHANGE = "exchange"
    EXCHANGE_CONTINUOUS = "exchange_continuous"
    EXCHANGE_LAUNCH = "exchange_launch"
    FIRST_TRADABLE_SEEN = "first_tradable_seen"

    @property
    def is_official(self) -> bool:
        return self is not TradableAtSource.FIRST_TRADABLE_SEEN


class ListingState(StrEnum):
    BASELINE = "baseline"
    PENDING = "pending"
    PENDING_OFFICIAL = "pending_official"
    RELIST_PENDING = "relist_pending"
    ACTIVE_NEW = "active_new"


class LifecyclePhase(StrEnum):
    UNKNOWN = "unknown"
    PREOPEN = "preopen"
    TRADABLE = "tradable"
    PAUSED = "paused"
    DELISTED = "delisted"


class TurnoverMethod(StrEnum):
    EXCHANGE_QUOTE_TURNOVER = "exchange_quote_turnover"
    BASE_VOLUME_X_REFERENCE_PRICE = "base_volume_x_reference_price"


@dataclass(frozen=True, slots=True, init=False)
class CatalogScope:
    exchange: Exchange
    market: Market

    def __init__(
        self,
        exchange: Exchange | str,
        market: Market | str,
    ) -> None:
        object.__setattr__(
            self,
            "exchange",
            _enum_member(exchange, Exchange, field="exchange"),
        )
        object.__setattr__(
            self,
            "market",
            _enum_member(market, Market, field="market"),
        )


SelectionScope = CatalogScope


@dataclass(frozen=True, slots=True, init=False)
class Turnover:
    value: Decimal
    method: TurnoverMethod
    currency: str
    observed_at_ns: int | None = None
    raw_reference: str | None = None

    def __init__(
        self,
        value: Decimal | int,
        method: TurnoverMethod | str,
        currency: str,
        observed_at_ns: int | None = None,
        raw_reference: str | None = None,
    ) -> None:
        if type(value) is int:
            normalized_value = Decimal(value)
        elif type(value) is Decimal:
            normalized_value = value
        else:
            raise TypeError("turnover value must be an int or Decimal")
        if not normalized_value.is_finite() or normalized_value < 0:
            raise ValueError("turnover value must be finite and non-negative")
        object.__setattr__(self, "value", normalized_value)
        object.__setattr__(
            self,
            "method",
            _enum_member(method, TurnoverMethod, field="turnover method"),
        )
        object.__setattr__(
            self,
            "currency",
            _nonempty_string(currency, field="turnover currency"),
        )
        normalized_observed_at_ns = _optional_nonnegative_int(
            observed_at_ns,
            field="turnover observed_at_ns",
        )
        if (normalized_observed_at_ns is None) != (raw_reference is None):
            raise ValueError(
                "turnover observed_at_ns and raw_reference must be provided together"
            )
        object.__setattr__(self, "observed_at_ns", normalized_observed_at_ns)
        if raw_reference is not None:
            object.__setattr__(
                self,
                "raw_reference",
                _nonempty_string(
                    raw_reference,
                    field="turnover raw_reference",
                ),
            )
        else:
            object.__setattr__(self, "raw_reference", None)


@dataclass(frozen=True, slots=True, init=False)
class InstrumentRecord:
    exchange: Exchange
    market: Market
    instrument_key: str
    canonical_pair: str
    wire_symbols: Mapping[str, str]
    base_asset: str
    quote_asset: str
    settlement_asset: str | None
    status: str
    lifecycle_phase: LifecyclePhase
    tradable: bool
    lifecycle: FrozenJsonPayload
    tradable_at_ns: int | None
    tradable_at_source: TradableAtSource | None
    turnover: Turnover | None
    raw_catalog_reference: str

    def __init__(
        self,
        exchange: Exchange | str,
        market: Market | str,
        instrument_key: str,
        canonical_pair: str,
        wire_symbols: Mapping[str, str],
        base_asset: str,
        quote_asset: str,
        settlement_asset: str | None,
        status: str,
        tradable: bool,
        lifecycle: object,
        tradable_at_ns: int | None,
        tradable_at_source: TradableAtSource | str | None,
        turnover: Turnover | None,
        raw_catalog_reference: str,
        lifecycle_phase: LifecyclePhase | str | None = None,
    ) -> None:
        object.__setattr__(
            self,
            "exchange",
            _enum_member(exchange, Exchange, field="exchange"),
        )
        object.__setattr__(
            self,
            "market",
            _enum_member(market, Market, field="market"),
        )
        object.__setattr__(
            self,
            "instrument_key",
            _nonempty_string(instrument_key, field="instrument_key"),
        )
        object.__setattr__(
            self,
            "canonical_pair",
            _nonempty_string(canonical_pair, field="canonical_pair"),
        )
        object.__setattr__(self, "wire_symbols", _wire_symbols(wire_symbols))
        object.__setattr__(
            self,
            "base_asset",
            _nonempty_string(base_asset, field="base_asset"),
        )
        normalized_quote_asset = _nonempty_string(
            quote_asset,
            field="quote_asset",
        )
        object.__setattr__(self, "quote_asset", normalized_quote_asset)
        if settlement_asset is not None:
            settlement_asset = _nonempty_string(
                settlement_asset,
                field="settlement_asset",
            )
        object.__setattr__(self, "settlement_asset", settlement_asset)
        object.__setattr__(
            self,
            "status",
            _nonempty_string(status, field="status"),
        )
        if type(tradable) is not bool:
            raise TypeError("tradable must be a boolean")
        object.__setattr__(self, "tradable", tradable)
        normalized_phase = (
            LifecyclePhase.TRADABLE
            if lifecycle_phase is None and tradable
            else LifecyclePhase.UNKNOWN
            if lifecycle_phase is None
            else _enum_member(
                lifecycle_phase,
                LifecyclePhase,
                field="lifecycle_phase",
            )
        )
        if (
            lifecycle_phase is not None
            and (normalized_phase is LifecyclePhase.TRADABLE) != tradable
        ):
            raise ValueError("tradable must agree with the canonical lifecycle_phase")
        object.__setattr__(self, "lifecycle_phase", normalized_phase)
        object.__setattr__(self, "lifecycle", _freeze_json(lifecycle))
        normalized_tradable_at_ns = _optional_nonnegative_int(
            tradable_at_ns,
            field="tradable_at_ns",
        )
        if (normalized_tradable_at_ns is None) != (tradable_at_source is None):
            raise ValueError(
                "tradable_at_ns and tradable_at_source must be provided together"
            )
        object.__setattr__(self, "tradable_at_ns", normalized_tradable_at_ns)
        normalized_source = (
            None
            if tradable_at_source is None
            else _enum_member(
                tradable_at_source,
                TradableAtSource,
                field="tradable_at_source",
            )
        )
        object.__setattr__(self, "tradable_at_source", normalized_source)
        if turnover is not None:
            if type(turnover) is not Turnover:
                raise TypeError("turnover must be Turnover or None")
            if turnover.currency != normalized_quote_asset:
                raise ValueError("turnover currency must match quote_asset")
        object.__setattr__(self, "turnover", turnover)
        object.__setattr__(
            self,
            "raw_catalog_reference",
            _nonempty_string(
                raw_catalog_reference,
                field="raw_catalog_reference",
            ),
        )

    @property
    def scope(self) -> CatalogScope:
        return CatalogScope(self.exchange, self.market)


@dataclass(frozen=True, slots=True, init=False)
class CatalogInstrument(InstrumentRecord):
    first_seen_ns: int
    last_seen_ns: int
    present: bool
    listing_state: ListingState
    first_tradable_seen_ns: int | None
    listing_generation: int
    last_terminal_seen_ns: int | None
    new_listing_started_at_ns: int | None
    new_listing_source: TradableAtSource | None
    new_listing_eligible: bool

    def __init__(
        self,
        exchange: Exchange | str,
        market: Market | str,
        instrument_key: str,
        canonical_pair: str,
        wire_symbols: Mapping[str, str],
        base_asset: str,
        quote_asset: str,
        settlement_asset: str | None,
        status: str,
        tradable: bool,
        lifecycle: object,
        tradable_at_ns: int | None,
        tradable_at_source: TradableAtSource | str | None,
        turnover: Turnover | None,
        raw_catalog_reference: str,
        first_seen_ns: int,
        last_seen_ns: int,
        present: bool,
        listing_state: ListingState | str,
        lifecycle_phase: LifecyclePhase | str | None = None,
        first_tradable_seen_ns: int | None = None,
        listing_generation: int = 0,
        last_terminal_seen_ns: int | None = None,
        new_listing_started_at_ns: int | None = None,
        new_listing_source: TradableAtSource | str | None = None,
        new_listing_eligible: bool = False,
    ) -> None:
        InstrumentRecord.__init__(
            self,
            exchange=exchange,
            market=market,
            instrument_key=instrument_key,
            canonical_pair=canonical_pair,
            wire_symbols=wire_symbols,
            base_asset=base_asset,
            quote_asset=quote_asset,
            settlement_asset=settlement_asset,
            status=status,
            tradable=tradable,
            lifecycle=lifecycle,
            tradable_at_ns=tradable_at_ns,
            tradable_at_source=tradable_at_source,
            turnover=turnover,
            raw_catalog_reference=raw_catalog_reference,
            lifecycle_phase=lifecycle_phase,
        )
        first_seen = _nonnegative_int(first_seen_ns, field="first_seen_ns")
        last_seen = _nonnegative_int(last_seen_ns, field="last_seen_ns")
        if last_seen < first_seen:
            raise ValueError("last_seen_ns must not be below first_seen_ns")
        if type(present) is not bool:
            raise TypeError("present must be a boolean")
        object.__setattr__(self, "first_seen_ns", first_seen)
        object.__setattr__(self, "last_seen_ns", last_seen)
        object.__setattr__(self, "present", present)
        normalized_listing_state = _enum_member(
            listing_state,
            ListingState,
            field="listing_state",
        )
        if self.tradable and normalized_listing_state in {
            ListingState.PENDING,
            ListingState.PENDING_OFFICIAL,
            ListingState.RELIST_PENDING,
        }:
            raise ValueError("pending listing states must be non-tradable")
        if (
            self.lifecycle_phase is LifecyclePhase.DELISTED
            and normalized_listing_state is not ListingState.RELIST_PENDING
        ):
            raise ValueError("delisted lifecycle requires relist-pending state")
        object.__setattr__(self, "listing_state", normalized_listing_state)
        first_tradable_seen = _optional_nonnegative_int(
            first_tradable_seen_ns,
            field="first_tradable_seen_ns",
        )
        if first_tradable_seen is not None and not (
            first_seen <= first_tradable_seen <= last_seen
        ):
            raise ValueError(
                "first_tradable_seen_ns must be between first_seen_ns and last_seen_ns"
            )
        object.__setattr__(self, "first_tradable_seen_ns", first_tradable_seen)
        object.__setattr__(
            self,
            "listing_generation",
            _nonnegative_int(
                listing_generation,
                field="listing_generation",
            ),
        )
        terminal_seen = _optional_nonnegative_int(
            last_terminal_seen_ns,
            field="last_terminal_seen_ns",
        )
        if terminal_seen is not None and not (first_seen <= terminal_seen <= last_seen):
            raise ValueError(
                "last_terminal_seen_ns must be between first_seen_ns and last_seen_ns"
            )
        if normalized_listing_state is ListingState.RELIST_PENDING:
            if terminal_seen is None:
                raise ValueError("relist-pending state requires terminal evidence")
        elif (
            terminal_seen is not None
            and normalized_listing_state is not ListingState.ACTIVE_NEW
        ):
            raise ValueError(
                "terminal evidence requires an active or relist-pending listing state"
            )
        if (
            self.lifecycle_phase is LifecyclePhase.DELISTED
            and terminal_seen != last_seen
        ):
            raise ValueError("delisted terminal evidence must equal last_seen_ns")
        object.__setattr__(self, "last_terminal_seen_ns", terminal_seen)
        started_at = _optional_nonnegative_int(
            new_listing_started_at_ns,
            field="new_listing_started_at_ns",
        )
        source = (
            None
            if new_listing_source is None
            else _enum_member(
                new_listing_source,
                TradableAtSource,
                field="new_listing_source",
            )
        )
        if (started_at is None) != (source is None):
            raise ValueError(
                "new_listing_started_at_ns and new_listing_source must be paired"
            )
        if type(new_listing_eligible) is not bool:
            raise TypeError("new_listing_eligible must be a boolean")
        if new_listing_eligible != (
            normalized_listing_state is ListingState.ACTIVE_NEW
        ):
            raise ValueError(
                "new-listing eligibility must agree with the active listing state"
            )
        if (
            started_at is not None
            and not new_listing_eligible
            and normalized_listing_state is not ListingState.RELIST_PENDING
        ):
            raise ValueError(
                "persisted episode history requires an active or relist-pending "
                "listing state"
            )
        if new_listing_eligible and started_at is None:
            raise ValueError("active listing state requires a persisted episode start")
        if (
            normalized_listing_state is ListingState.ACTIVE_NEW
            and terminal_seen is not None
            and (started_at is None or started_at <= terminal_seen)
        ):
            raise ValueError("relisting episode start must follow terminal evidence")
        if started_at is not None:
            if first_tradable_seen is None:
                raise ValueError(
                    "eligible listing episodes require first_tradable_seen_ns"
                )
            if started_at > first_tradable_seen:
                raise ValueError(
                    "listing episode start must not follow first_tradable_seen_ns"
                )
        if (
            source is TradableAtSource.FIRST_TRADABLE_SEEN
            and started_at != first_tradable_seen
        ):
            raise ValueError(
                "FIRST_TRADABLE_SEEN episodes must start at first_tradable_seen_ns"
            )
        object.__setattr__(self, "new_listing_started_at_ns", started_at)
        object.__setattr__(self, "new_listing_source", source)
        object.__setattr__(self, "new_listing_eligible", new_listing_eligible)


@dataclass(frozen=True, slots=True)
class AnnouncementHint:
    scope: CatalogScope
    hint_id: str
    announced_at_ns: int
    raw_reference: str
    candidate_instrument_key: str | None = None
    candidate_canonical_pair: str | None = None

    def __post_init__(self) -> None:
        if type(self.scope) is not CatalogScope:
            raise TypeError("scope must be CatalogScope")
        for field in ("hint_id", "raw_reference"):
            object.__setattr__(
                self,
                field,
                _nonempty_string(getattr(self, field), field=field),
            )
        if self.candidate_instrument_key is not None:
            object.__setattr__(
                self,
                "candidate_instrument_key",
                _nonempty_string(
                    self.candidate_instrument_key,
                    field="candidate_instrument_key",
                ),
            )
        if self.candidate_canonical_pair is not None:
            object.__setattr__(
                self,
                "candidate_canonical_pair",
                _nonempty_string(
                    self.candidate_canonical_pair,
                    field="candidate_canonical_pair",
                ),
            )
        if (
            self.candidate_instrument_key is None
            and self.candidate_canonical_pair is None
        ):
            raise ValueError("announcement hint requires a candidate")
        object.__setattr__(
            self,
            "announced_at_ns",
            _nonnegative_int(self.announced_at_ns, field="announced_at_ns"),
        )


@dataclass(frozen=True, slots=True)
class StoredAnnouncementHint(AnnouncementHint):
    confirmed_at_ns: int | None = None

    def __post_init__(self) -> None:
        super(StoredAnnouncementHint, self).__post_init__()
        confirmed = _optional_nonnegative_int(
            self.confirmed_at_ns,
            field="confirmed_at_ns",
        )
        if confirmed is not None and confirmed < self.announced_at_ns:
            raise ValueError("confirmed_at_ns must not precede announced_at_ns")
        object.__setattr__(self, "confirmed_at_ns", confirmed)


@dataclass(frozen=True, slots=True)
class CatalogSnapshot:
    scope: CatalogScope
    observed_at_ns: int | None
    revision: int
    digest_sha256: str | None
    complete: bool
    instruments: tuple[CatalogInstrument, ...]

    def __post_init__(self) -> None:
        if type(self.scope) is not CatalogScope:
            raise TypeError("scope must be CatalogScope")
        object.__setattr__(
            self,
            "observed_at_ns",
            _optional_nonnegative_int(
                self.observed_at_ns,
                field="observed_at_ns",
            ),
        )
        revision = _nonnegative_int(self.revision, field="revision")
        if (self.observed_at_ns is None) != (revision == 0):
            raise ValueError("empty catalog state must use revision zero")
        if self.digest_sha256 is not None:
            _sha256_digest(self.digest_sha256, field="digest_sha256")
        if (revision == 0) != (self.digest_sha256 is None):
            raise ValueError("catalog digest must exist exactly when revision exists")
        if type(self.complete) is not bool:
            raise TypeError("complete must be a boolean")
        if revision == 0 and self.complete:
            raise ValueError("revision-zero catalog state must be incomplete")
        if revision > 0 and not self.complete:
            raise ValueError("persisted catalog revisions must be complete")
        object.__setattr__(self, "revision", revision)
        if type(self.instruments) is not tuple or any(
            type(item) is not CatalogInstrument for item in self.instruments
        ):
            raise TypeError("instruments must be a tuple of CatalogInstrument")
        if revision == 0 and self.instruments:
            raise ValueError("revision-zero catalog state cannot contain instruments")
        keys: set[str] = set()
        for item in self.instruments:
            if item.scope != self.scope:
                raise ValueError("instrument scope does not match catalog scope")
            if item.instrument_key in keys:
                raise ValueError("catalog instrument keys must be unique")
            keys.add(item.instrument_key)


@dataclass(frozen=True, slots=True)
class CatalogDelta:
    kind: str
    instrument_key: str
    previous: CatalogInstrument | StoredAnnouncementHint | None
    current: CatalogInstrument | StoredAnnouncementHint

    def __post_init__(self) -> None:
        if self.kind not in {
            "added",
            "updated",
            "removed",
            "new_listing",
            "announcement_confirmed",
        }:
            raise ValueError("unsupported catalog delta kind")
        object.__setattr__(
            self,
            "instrument_key",
            _nonempty_string(self.instrument_key, field="instrument_key"),
        )
        previous = self.previous
        current = self.current
        if self.kind == "announcement_confirmed":
            if (
                type(previous) is not StoredAnnouncementHint
                or type(current) is not StoredAnnouncementHint
            ):
                raise TypeError(
                    "announcement delta values must be StoredAnnouncementHint"
                )
            if (
                current.candidate_instrument_key is not None
                and current.candidate_instrument_key != self.instrument_key
            ):
                raise ValueError(
                    "announcement key must match the explicit instrument candidate"
                )
            if previous.scope != current.scope or previous.hint_id != current.hint_id:
                raise ValueError("announcement delta values must share identity")
            if previous.confirmed_at_ns is not None or current.confirmed_at_ns is None:
                raise ValueError("announcement delta must record first confirmation")
            return

        if previous is not None and type(previous) is not CatalogInstrument:
            raise TypeError("previous must be CatalogInstrument or None")
        if type(current) is not CatalogInstrument:
            raise TypeError("current must be CatalogInstrument")
        if current.instrument_key != self.instrument_key:
            raise ValueError("current instrument key must match catalog delta")
        if previous is not None:
            if previous.instrument_key != self.instrument_key:
                raise ValueError("previous instrument key must match catalog delta")
            if previous.scope != current.scope:
                raise ValueError("catalog delta values must share one scope")
        if self.kind in {"updated", "removed"} and previous is None:
            raise ValueError(f"{self.kind} catalog delta requires a previous value")
        if (
            self.kind == "removed"
            and previous is not None
            and (not previous.present or current.present)
        ):
            raise ValueError("removed catalog delta must transition to non-present")

    @property
    def scope(self) -> CatalogScope:
        return self.current.scope

    @property
    def identity_key(self) -> str:
        if self.kind == "announcement_confirmed":
            return cast(StoredAnnouncementHint, self.current).hint_id
        return self.instrument_key


@dataclass(frozen=True, slots=True)
class CatalogChanges:
    scope: CatalogScope
    observed_at_ns: int
    is_initial_baseline: bool
    idempotent: bool
    added: tuple[CatalogInstrument, ...]
    updated: tuple[CatalogInstrument, ...]
    removed: tuple[CatalogInstrument, ...]
    new_listings: tuple[CatalogInstrument, ...]
    confirmed_announcement_hints: tuple[StoredAnnouncementHint, ...]
    revision: int = 0
    digest_sha256: str | None = None
    control_event_ids: tuple[str, ...] = ()
    deltas: tuple[CatalogDelta, ...] = ()

    def __post_init__(self) -> None:
        if type(self.scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        object.__setattr__(
            self,
            "observed_at_ns",
            _nonnegative_int(self.observed_at_ns, field="observed_at_ns"),
        )
        if type(self.is_initial_baseline) is not bool:
            raise TypeError("is_initial_baseline must be a boolean")
        if type(self.idempotent) is not bool:
            raise TypeError("idempotent must be a boolean")
        if self.is_initial_baseline and self.idempotent:
            raise ValueError("an initial baseline cannot be idempotent")
        object.__setattr__(
            self, "revision", _positive_int(self.revision, field="revision")
        )
        if self.digest_sha256 is None:
            raise ValueError("digest_sha256 is required")
        _sha256_digest(self.digest_sha256, field="digest_sha256")
        for field in ("added", "updated", "removed", "new_listings"):
            values = getattr(self, field)
            if type(values) is not tuple or any(
                type(item) is not CatalogInstrument for item in values
            ):
                raise TypeError(f"{field} must be a tuple of CatalogInstrument")
            if any(item.scope != self.scope for item in values):
                raise ValueError(f"{field} contains a cross-scope instrument")
        hints = self.confirmed_announcement_hints
        if type(hints) is not tuple or any(
            type(item) is not StoredAnnouncementHint for item in hints
        ):
            raise TypeError(
                "confirmed_announcement_hints must contain StoredAnnouncementHint"
            )
        if any(item.scope != self.scope for item in hints):
            raise ValueError("confirmed announcement hint scope mismatch")
        if type(self.deltas) is not tuple or any(
            type(item) is not CatalogDelta for item in self.deltas
        ):
            raise TypeError("deltas must be a tuple of CatalogDelta")
        if any(item.scope != self.scope for item in self.deltas):
            raise ValueError("catalog delta scope mismatch")
        identities = tuple((item.kind, item.identity_key) for item in self.deltas)
        if len(set(identities)) != len(identities):
            raise ValueError("catalog deltas must have unique kind/key identities")
        for field, kind in (
            ("added", "added"),
            ("updated", "updated"),
            ("removed", "removed"),
            ("new_listings", "new_listing"),
        ):
            if getattr(self, field) != tuple(
                cast(CatalogInstrument, item.current)
                for item in self.deltas
                if item.kind == kind
            ):
                raise ValueError(f"{field} must agree with catalog deltas")
        if hints != tuple(
            cast(StoredAnnouncementHint, item.current)
            for item in self.deltas
            if item.kind == "announcement_confirmed"
        ):
            raise ValueError(
                "confirmed_announcement_hints must agree with catalog deltas"
            )
        event_ids = self.control_event_ids
        if type(event_ids) is not tuple:
            raise TypeError("control_event_ids must be a tuple")
        normalized_ids = tuple(
            _sha256_digest(item, field="control event ID") for item in event_ids
        )
        if len(set(normalized_ids)) != len(normalized_ids):
            raise ValueError("control_event_ids must be unique")
        if self.idempotent and any(
            (
                self.added,
                self.updated,
                self.removed,
                self.new_listings,
                self.confirmed_announcement_hints,
                self.control_event_ids,
                self.deltas,
            )
        ):
            raise ValueError("idempotent catalog changes cannot contain deltas")

    @property
    def new_listing_episodes(self) -> tuple[CatalogInstrument, ...]:
        return self.new_listings


@dataclass(frozen=True, slots=True)
class SnapshotPage:
    raw_reference: str
    request_cursor: str | None
    next_cursor: str | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "raw_reference",
            _nonempty_string(self.raw_reference, field="page raw_reference"),
        )
        object.__setattr__(
            self,
            "request_cursor",
            _optional_nonempty_string(
                self.request_cursor,
                field="page request_cursor",
            ),
        )
        object.__setattr__(
            self,
            "next_cursor",
            _optional_nonempty_string(
                self.next_cursor,
                field="page next_cursor",
            ),
        )
        if self.request_cursor is not None and self.request_cursor == self.next_cursor:
            raise ValueError("a page cursor must advance")


def _complete_snapshot_pages(value: object) -> tuple[SnapshotPage, ...]:
    if type(value) is not tuple or not value:
        raise ValueError("pages must be a non-empty tuple")
    if any(type(item) is not SnapshotPage for item in value):
        raise TypeError("pages must contain SnapshotPage values")
    pages = cast(tuple[SnapshotPage, ...], value)
    if pages[0].request_cursor is not None:
        raise ValueError("the first snapshot page must use the initial cursor")
    for current, following in pairwise(pages):
        if current.next_cursor is None:
            raise ValueError("snapshot pages continue after a terminal page")
        if following.request_cursor != current.next_cursor:
            raise ValueError("snapshot page cursor chain is not contiguous")
    if pages[-1].next_cursor is not None:
        raise ValueError("snapshot pages lack terminal cursor evidence")
    references = tuple(item.raw_reference for item in pages)
    if len(set(references)) != len(references):
        raise ValueError("snapshot page raw references must be unique")
    request_cursors = tuple(
        item.request_cursor for item in pages if item.request_cursor is not None
    )
    if len(set(request_cursors)) != len(request_cursors):
        raise ValueError("snapshot request cursors must be unique")
    return pages


@dataclass(frozen=True, slots=True, init=False)
class CompleteCatalogSnapshot:
    scope: SelectionScope
    observed_at_ns: int
    snapshot_id: str
    pages: tuple[SnapshotPage, ...]
    reported_total_count: int | None
    authoritative_empty: bool
    instruments: tuple[InstrumentRecord, ...]

    def __init__(
        self,
        *,
        scope: SelectionScope,
        observed_at_ns: int,
        snapshot_id: str,
        pages: tuple[SnapshotPage, ...],
        reported_total_count: int | None,
        authoritative_empty: bool,
        instruments: tuple[InstrumentRecord, ...],
    ) -> None:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        observed_at = _nonnegative_int(
            observed_at_ns,
            field="observed_at_ns",
        )
        identity = _nonempty_string(snapshot_id, field="snapshot_id")
        normalized_pages = _complete_snapshot_pages(pages)
        reported = _optional_nonnegative_int(
            reported_total_count,
            field="reported_total_count",
        )
        if type(authoritative_empty) is not bool:
            raise TypeError("authoritative_empty must be a boolean")
        if type(instruments) is not tuple or any(
            type(item) is not InstrumentRecord for item in instruments
        ):
            raise TypeError("instruments must be a tuple of InstrumentRecord")
        keys: set[str] = set()
        for item in instruments:
            if item.scope != scope:
                raise ValueError("instrument scope does not match snapshot scope")
            if item.instrument_key in keys:
                raise ValueError("snapshot instrument keys must be unique")
            if item.turnover is not None:
                raise ValueError("catalog snapshots cannot carry turnover observations")
            keys.add(item.instrument_key)
        if reported is not None and reported != len(instruments):
            raise ValueError("reported_total_count must equal the instrument count")
        if not instruments and not authoritative_empty:
            raise ValueError(
                "empty catalog requires an explicit authoritative_empty fact"
            )
        if instruments and authoritative_empty:
            raise ValueError("authoritative_empty cannot accompany catalog instruments")
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "observed_at_ns", observed_at)
        object.__setattr__(self, "snapshot_id", identity)
        object.__setattr__(self, "pages", normalized_pages)
        object.__setattr__(self, "reported_total_count", reported)
        object.__setattr__(self, "authoritative_empty", authoritative_empty)
        object.__setattr__(self, "instruments", instruments)

    @property
    def page_raw_references(self) -> tuple[str, ...]:
        return tuple(item.raw_reference for item in self.pages)

    @property
    def page_count(self) -> int:
        return len(self.pages)


@dataclass(frozen=True, slots=True, init=False)
class TurnoverObservation:
    instrument_key: str
    value: Decimal
    method: TurnoverMethod
    currency: str
    raw_reference: str

    def __init__(
        self,
        *,
        instrument_key: str,
        value: Decimal | int,
        method: TurnoverMethod | str,
        currency: str,
        raw_reference: str,
    ) -> None:
        normalized = Turnover(value, method, currency)
        object.__setattr__(
            self,
            "instrument_key",
            _nonempty_string(instrument_key, field="instrument_key"),
        )
        object.__setattr__(self, "value", normalized.value)
        object.__setattr__(self, "method", normalized.method)
        object.__setattr__(self, "currency", normalized.currency)
        object.__setattr__(
            self,
            "raw_reference",
            _nonempty_string(raw_reference, field="raw_reference"),
        )


@dataclass(frozen=True, slots=True, init=False)
class CompleteTurnoverSnapshot:
    scope: SelectionScope
    catalog_revision: int
    observed_at_ns: int
    snapshot_id: str
    pages: tuple[SnapshotPage, ...]
    reported_total_count: int | None
    authoritative_empty: bool
    covered_instrument_keys: tuple[str, ...]
    observations: tuple[TurnoverObservation, ...]

    def __init__(
        self,
        *,
        scope: SelectionScope,
        catalog_revision: int,
        observed_at_ns: int,
        snapshot_id: str,
        pages: tuple[SnapshotPage, ...],
        reported_total_count: int | None,
        authoritative_empty: bool = False,
        covered_instrument_keys: tuple[str, ...],
        observations: tuple[TurnoverObservation, ...],
    ) -> None:
        if type(scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        revision = _nonnegative_int(
            catalog_revision,
            field="catalog_revision",
        )
        if revision == 0:
            raise ValueError("turnover snapshot requires a catalog revision")
        observed_at = _nonnegative_int(
            observed_at_ns,
            field="observed_at_ns",
        )
        identity = _nonempty_string(snapshot_id, field="snapshot_id")
        normalized_pages = _complete_snapshot_pages(pages)
        reported = _optional_nonnegative_int(
            reported_total_count,
            field="reported_total_count",
        )
        if type(authoritative_empty) is not bool:
            raise TypeError("authoritative_empty must be a boolean")
        if type(covered_instrument_keys) is not tuple:
            raise TypeError("covered_instrument_keys must be a tuple")
        covered = tuple(
            _nonempty_string(item, field="covered_instrument_keys")
            for item in covered_instrument_keys
        )
        if len(set(covered)) != len(covered):
            raise ValueError("covered_instrument_keys must be unique")
        if not covered and not authoritative_empty:
            raise ValueError(
                "empty turnover coverage requires an explicit authoritative_empty fact"
            )
        if covered and authoritative_empty:
            raise ValueError("authoritative_empty cannot accompany turnover coverage")
        if type(observations) is not tuple or any(
            type(item) is not TurnoverObservation for item in observations
        ):
            raise TypeError("observations must be a tuple of TurnoverObservation")
        observation_keys = tuple(item.instrument_key for item in observations)
        if len(set(observation_keys)) != len(observation_keys):
            raise ValueError("turnover observation keys must be unique")
        if not set(observation_keys).issubset(covered):
            raise ValueError(
                "turnover observations must belong to covered_instrument_keys"
            )
        if reported is not None and reported != len(covered):
            raise ValueError("reported_total_count must equal the coverage count")
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "catalog_revision", revision)
        object.__setattr__(self, "observed_at_ns", observed_at)
        object.__setattr__(self, "snapshot_id", identity)
        object.__setattr__(self, "pages", normalized_pages)
        object.__setattr__(self, "reported_total_count", reported)
        object.__setattr__(self, "authoritative_empty", authoritative_empty)
        object.__setattr__(self, "covered_instrument_keys", covered)
        object.__setattr__(self, "observations", observations)

    @property
    def page_raw_references(self) -> tuple[str, ...]:
        return tuple(item.raw_reference for item in self.pages)

    @property
    def page_count(self) -> int:
        return len(self.pages)


@dataclass(frozen=True, slots=True)
class CatalogView:
    scope: SelectionScope
    catalog_observed_at_ns: int | None
    catalog_revision: int
    catalog_digest_sha256: str | None
    catalog_snapshot_id: str | None
    catalog_page_raw_references: tuple[str, ...]
    turnover_observed_at_ns: int | None
    turnover_revision: int
    turnover_digest_sha256: str | None
    turnover_catalog_revision: int | None
    turnover_snapshot_id: str | None
    turnover_page_raw_references: tuple[str, ...]
    turnover_covered_instrument_keys: tuple[str, ...]
    instruments: tuple[CatalogInstrument, ...]

    def __post_init__(self) -> None:
        if type(self.scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        catalog_observed = _optional_nonnegative_int(
            self.catalog_observed_at_ns,
            field="catalog_observed_at_ns",
        )
        catalog_revision = _nonnegative_int(
            self.catalog_revision,
            field="catalog_revision",
        )
        if (catalog_revision == 0) != (catalog_observed is None):
            raise ValueError("empty catalog state must use revision zero")
        if (catalog_revision == 0) != (self.catalog_digest_sha256 is None):
            raise ValueError(
                "catalog digest must exist exactly with a catalog revision"
            )
        if self.catalog_digest_sha256 is not None:
            _sha256_digest(
                self.catalog_digest_sha256,
                field="catalog_digest_sha256",
            )
        if catalog_revision == 0:
            if self.catalog_snapshot_id is not None:
                raise ValueError("empty catalog state cannot carry a snapshot ID")
            if self.catalog_page_raw_references != ():
                raise ValueError("empty catalog state cannot carry page references")
        else:
            object.__setattr__(
                self,
                "catalog_snapshot_id",
                _nonempty_string(
                    self.catalog_snapshot_id,
                    field="catalog_snapshot_id",
                ),
            )
            object.__setattr__(
                self,
                "catalog_page_raw_references",
                _nonempty_string_tuple(
                    self.catalog_page_raw_references,
                    field="catalog_page_raw_references",
                ),
            )
        turnover_observed = _optional_nonnegative_int(
            self.turnover_observed_at_ns,
            field="turnover_observed_at_ns",
        )
        turnover_revision = _nonnegative_int(
            self.turnover_revision,
            field="turnover_revision",
        )
        turnover_catalog_revision = _optional_nonnegative_int(
            self.turnover_catalog_revision,
            field="turnover_catalog_revision",
        )
        turnover_empty = turnover_revision == 0
        if turnover_empty != (turnover_observed is None):
            raise ValueError(
                "turnover observation must exist exactly with its revision"
            )
        if turnover_empty != (self.turnover_digest_sha256 is None):
            raise ValueError("turnover digest must exist exactly with its revision")
        if turnover_empty != (turnover_catalog_revision is None):
            raise ValueError(
                "turnover catalog binding must exist exactly with its revision"
            )
        if self.turnover_digest_sha256 is not None:
            _sha256_digest(
                self.turnover_digest_sha256,
                field="turnover_digest_sha256",
            )
        if turnover_catalog_revision is not None:
            if turnover_catalog_revision == 0:
                raise ValueError("turnover_catalog_revision must be positive")
            if turnover_catalog_revision > catalog_revision:
                raise ValueError("turnover cannot bind a future catalog revision")
            if (
                turnover_catalog_revision == catalog_revision
                and catalog_observed is not None
                and turnover_observed is not None
                and turnover_observed < catalog_observed
            ):
                raise ValueError(
                    "turnover observation cannot predate its bound catalog observation"
                )
        if turnover_empty:
            if self.turnover_snapshot_id is not None:
                raise ValueError("empty turnover state cannot carry a snapshot ID")
            if self.turnover_page_raw_references != ():
                raise ValueError("empty turnover state cannot carry page references")
            if self.turnover_covered_instrument_keys != ():
                raise ValueError("empty turnover state cannot carry coverage")
        else:
            object.__setattr__(
                self,
                "turnover_snapshot_id",
                _nonempty_string(
                    self.turnover_snapshot_id,
                    field="turnover_snapshot_id",
                ),
            )
            object.__setattr__(
                self,
                "turnover_page_raw_references",
                _nonempty_string_tuple(
                    self.turnover_page_raw_references,
                    field="turnover_page_raw_references",
                ),
            )
            if type(self.turnover_covered_instrument_keys) is not tuple:
                raise TypeError("turnover_covered_instrument_keys must be a tuple")
            coverage = tuple(
                _nonempty_string(item, field="turnover covered instrument key")
                for item in self.turnover_covered_instrument_keys
            )
            if len(set(coverage)) != len(coverage):
                raise ValueError("turnover coverage must contain unique keys")
        if type(self.instruments) is not tuple or any(
            type(item) is not CatalogInstrument for item in self.instruments
        ):
            raise TypeError("instruments must be a tuple of CatalogInstrument")
        keys: set[str] = set()
        for item in self.instruments:
            if item.scope != self.scope:
                raise ValueError("instrument scope does not match catalog view scope")
            if item.instrument_key in keys:
                raise ValueError("catalog view instrument keys must be unique")
            if catalog_observed is not None:
                if item.present and item.last_seen_ns != catalog_observed:
                    raise ValueError(
                        "present instrument last_seen_ns must equal "
                        "catalog_observed_at_ns"
                    )
                if not item.present and item.last_seen_ns >= catalog_observed:
                    raise ValueError(
                        "missing instrument last_seen_ns must precede "
                        "catalog_observed_at_ns"
                    )
            keys.add(item.instrument_key)
        if catalog_revision == 0 and self.instruments:
            raise ValueError("empty catalog state cannot contain instruments")
        coverage_keys = frozenset(self.turnover_covered_instrument_keys)
        if not coverage_keys.issubset(keys):
            raise ValueError("turnover coverage must belong to catalog instruments")
        present_keys = frozenset(
            item.instrument_key for item in self.instruments if item.present
        )
        if turnover_catalog_revision == catalog_revision and not coverage_keys.issubset(
            present_keys
        ):
            raise ValueError(
                "turnover coverage bound to the current catalog must contain only "
                "present instruments"
            )
        for item in self.instruments:
            turnover = item.turnover
            if turnover_empty:
                if turnover is not None:
                    raise ValueError("turnover values require a turnover revision")
                continue
            if item.instrument_key not in coverage_keys:
                if turnover is not None:
                    raise ValueError(
                        "turnover outside the latest snapshot coverage is invalid"
                    )
                continue
            if turnover is not None and turnover.observed_at_ns != turnover_observed:
                raise ValueError(
                    "turnover observation must match the view observation header"
                )


@dataclass(frozen=True, slots=True)
class TurnoverChanges:
    scope: SelectionScope
    catalog_revision: int
    observed_at_ns: int
    revision: int
    idempotent: bool
    changed_instrument_keys: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        object.__setattr__(
            self,
            "catalog_revision",
            _positive_int(self.catalog_revision, field="catalog_revision"),
        )
        object.__setattr__(
            self,
            "observed_at_ns",
            _nonnegative_int(self.observed_at_ns, field="observed_at_ns"),
        )
        object.__setattr__(
            self, "revision", _positive_int(self.revision, field="revision")
        )
        if type(self.idempotent) is not bool:
            raise TypeError("idempotent must be a boolean")
        keys = self.changed_instrument_keys
        if type(keys) is not tuple:
            raise TypeError("changed_instrument_keys must be a tuple")
        normalized = tuple(
            _nonempty_string(item, field="changed instrument key") for item in keys
        )
        if normalized != tuple(sorted(normalized)) or len(set(normalized)) != len(
            normalized
        ):
            raise ValueError("changed_instrument_keys must be sorted and unique")
        if self.idempotent and normalized:
            raise ValueError("idempotent turnover changes cannot contain deltas")


@dataclass(frozen=True, slots=True)
class CatalogControlChange:
    event_id: str
    scope: SelectionScope
    catalog_revision: int
    kind: str
    instrument_key: str
    payload: FrozenJsonPayload

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "event_id",
            _sha256_digest(self.event_id, field="event_id"),
        )
        if type(self.scope) is not CatalogScope:
            raise TypeError("scope must be SelectionScope")
        object.__setattr__(
            self,
            "catalog_revision",
            _positive_int(self.catalog_revision, field="catalog_revision"),
        )
        object.__setattr__(self, "kind", _nonempty_string(self.kind, field="kind"))
        object.__setattr__(
            self,
            "instrument_key",
            _nonempty_string(self.instrument_key, field="instrument_key"),
        )
        object.__setattr__(self, "payload", _freeze_json(self.payload))
