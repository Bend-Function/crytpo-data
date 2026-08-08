from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation

from crypto_collector.domain.types import IntegrityMode
from crypto_collector.materializer.models import SourceLocator
from crypto_collector.materializer.windows import window_for

_MAX_SIGNED_INT64 = 2**63 - 1
_FIXED_NONNEGATIVE_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")


def _time(value: object, *, field_name: str) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must be a non-negative signed 64-bit integer")
    return value


def _sha(value: object, *, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True, slots=True, order=True)
class TimeRange:
    start_ns: int
    end_ns: int

    def __post_init__(self) -> None:
        start = _time(self.start_ns, field_name="start_ns")
        end = _time(self.end_ns, field_name="end_ns")
        if end <= start:
            raise ValueError("end_ns must exceed start_ns")


@dataclass(frozen=True, slots=True)
class BookImpactPlanner:
    revision_horizon_ns: int

    def __post_init__(self) -> None:
        if _time(self.revision_horizon_ns, field_name="revision_horizon_ns") == 0:
            raise ValueError("revision_horizon_ns must be positive")

    def affected_range(
        self,
        *,
        late_event_ns: int,
        authoritative_snapshot_times: Iterable[int],
        horizon_end_ns: int,
        interval_ns: int = 30_000_000_000,
    ) -> TimeRange:
        late = _time(late_event_ns, field_name="late_event_ns")
        horizon_end = _time(horizon_end_ns, field_name="horizon_end_ns")
        start = window_for(late, interval_ns).start_ns
        if horizon_end <= start:
            raise ValueError("horizon_end_ns must exceed the affected window start")
        hard_end = min(horizon_end, late + self.revision_horizon_ns)
        snapshot_values = tuple(
            _time(value, field_name="authoritative_snapshot_times")
            for value in authoritative_snapshot_times
        )
        snapshots = sorted({value for value in snapshot_values if value > late})
        end = min(snapshots[0], hard_end) if snapshots else hard_end
        if end <= start:
            raise ValueError("affected range must have positive duration")
        return TimeRange(start, end)


def source_prefix_digest(locators: Iterable[SourceLocator]) -> str:
    digest = hashlib.sha256()
    digest.update(b"crypto-collector-book-source-prefix-v1\0")
    seen: set[SourceLocator] = set()
    for locator in locators:
        if type(locator) is not SourceLocator:
            raise TypeError("locators must contain SourceLocator values")
        if locator in seen:
            raise ValueError("source prefix locators must be unique")
        seen.add(locator)
        manifest = locator.manifest_sha256.encode("ascii")
        index = str(locator.zero_based_record_index).encode("ascii")
        digest.update(len(manifest).to_bytes(4, "big"))
        digest.update(manifest)
        digest.update(len(index).to_bytes(4, "big"))
        digest.update(index)
    return digest.hexdigest()


@dataclass(frozen=True, slots=True)
class BookReplayCheckpoint:
    """Discardable replay acceleration; raw source identity remains authoritative."""

    source_locator: SourceLocator
    integrity_mode: IntegrityMode
    authoritative_ancestor: SourceLocator
    source_prefix_sha256: str
    bids: tuple[tuple[str, str], ...]
    asks: tuple[tuple[str, str], ...]
    sequence_id: int

    def __post_init__(self) -> None:
        if type(self.source_locator) is not SourceLocator:
            raise TypeError("source_locator must be SourceLocator")
        if type(self.integrity_mode) is not IntegrityMode:
            raise TypeError("integrity_mode must be IntegrityMode")
        if not self.integrity_mode.is_research_valid:
            raise ValueError("checkpoint must contain valid book state")
        if type(self.authoritative_ancestor) is not SourceLocator:
            raise TypeError("authoritative_ancestor must be SourceLocator")
        _sha(self.source_prefix_sha256, field_name="source_prefix_sha256")
        if type(self.sequence_id) is not int or self.sequence_id < 0:
            raise ValueError("sequence_id must be non-negative")
        if self.sequence_id > _MAX_SIGNED_INT64:
            raise ValueError("sequence_id must fit a signed 64-bit integer")
        self._validate_side(self.bids, side="bids", reverse=True)
        self._validate_side(self.asks, side="asks", reverse=False)

    @staticmethod
    def _validate_side(
        levels: tuple[tuple[str, str], ...],
        *,
        side: str,
        reverse: bool,
    ) -> None:
        if type(levels) is not tuple:
            raise TypeError(f"{side} must be a tuple")
        parsed: list[Decimal] = []
        for level in levels:
            if type(level) is not tuple or len(level) != 2:
                raise ValueError(f"{side} levels must be price/quantity pairs")
            for field_name, value in zip(("price", "quantity"), level, strict=True):
                if (
                    type(value) is not str
                    or _FIXED_NONNEGATIVE_DECIMAL.fullmatch(value) is None
                ):
                    raise ValueError(
                        f"{side} {field_name} must be a fixed-point decimal string"
                    )
                try:
                    decimal = Decimal(value)
                except InvalidOperation as error:
                    raise ValueError(f"invalid {side} {field_name}") from error
                if decimal <= 0:
                    raise ValueError(f"{side} {field_name} must be positive")
                if field_name == "price":
                    parsed.append(decimal)
        if parsed != sorted(parsed, reverse=reverse) or len(parsed) != len(set(parsed)):
            raise ValueError(f"{side} prices must be unique and canonically sorted")

    def matches_prefix(self, locators: Iterable[SourceLocator]) -> bool:
        values = tuple(locators)
        return (
            bool(values)
            and values[-1] == self.source_locator
            and source_prefix_digest(values) == self.source_prefix_sha256
        )


__all__ = [
    "BookImpactPlanner",
    "BookReplayCheckpoint",
    "TimeRange",
    "source_prefix_digest",
]
