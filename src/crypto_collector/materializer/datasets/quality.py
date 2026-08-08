from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from decimal import ROUND_HALF_EVEN, Context, Decimal, localcontext
from enum import StrEnum
from itertools import pairwise

from crypto_collector.domain.envelope import MARKET_SCOPED_STREAMS
from crypto_collector.domain.types import CoverageMode, Exchange, Market, Transport
from crypto_collector.materializer.models import (
    DiscoveredRawInput,
    SourceLocator,
    SourceRecord,
    TimedSourceRecord,
    TimeSource,
)
from crypto_collector.materializer.time_policy import EventTimePolicy
from crypto_collector.materializer.windows import Window, window_for

_MAX_SIGNED_INT64 = 2**63 - 1
_HOUR_NS = 3_600_000_000_000
_RATIO_PRECISION = 36
_RATIO_CONTEXT = Context(
    prec=_RATIO_PRECISION,
    rounding=ROUND_HALF_EVEN,
    Emin=-999_999,
    Emax=999_999,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[],
)


class ExpectationContractError(ValueError):
    pass


class QualityEventKind(StrEnum):
    GAP = "gap"
    RECONNECT = "reconnect"
    PARSE_ERROR = "parse_error"
    CHECKSUM_ERROR = "checksum_error"
    SEQUENCE_ERROR = "sequence_error"
    QUEUE_OVERFLOW = "queue_overflow"
    EGRESS_CHANGE = "egress_change"
    THROTTLE = "throttle"
    INTERVAL_STRETCH = "interval_stretch"


_MANIFEST_COUNTER_FIELDS = {
    QualityEventKind.GAP: "gap_count",
    QualityEventKind.RECONNECT: "reconnect_count",
    QualityEventKind.PARSE_ERROR: "parse_error_count",
    QualityEventKind.CHECKSUM_ERROR: "checksum_error_count",
    QualityEventKind.QUEUE_OVERFLOW: "queue_overflow_count",
}
_MANIFEST_KINDS = tuple(_MANIFEST_COUNTER_FIELDS)
_COVERAGE_PRECEDENCE = {
    CoverageMode.COMPLETE: 0,
    CoverageMode.LOSSY_WINDOW: 1,
    CoverageMode.UNKNOWN: 2,
}


def _nonempty(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a normalized non-empty string")
    return value


def _nonnegative_int64(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    if value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must fit a signed 64-bit integer")
    return value


def _signed_int64(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < -_MAX_SIGNED_INT64 or value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must fit a signed 64-bit integer")
    return value


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _sha256(value: object, *, field_name: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    assert isinstance(value, str)
    return value


def _ratio(numerator: int, denominator: int) -> Decimal:
    with localcontext(_RATIO_CONTEXT) as context:
        context.clear_flags()
        return context.divide(Decimal(numerator), Decimal(denominator))


@dataclass(frozen=True, slots=True)
class QualityStreamKey:
    exchange: Exchange
    market: Market | None
    instrument_key: str | None
    logical_stream: str

    def __post_init__(self) -> None:
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        if self.market is not None and type(self.market) is not Market:
            raise TypeError("market must be Market or None")
        if self.instrument_key is not None:
            _nonempty(self.instrument_key, field_name="instrument_key")
        _nonempty(self.logical_stream, field_name="logical_stream")

        if self.logical_stream == "_control":
            if self.market is not None or self.instrument_key is not None:
                raise ValueError("_control quality keys must be exchange scoped")
            return
        if self.market is None:
            raise ValueError("non-control quality keys require a market")
        if self.logical_stream in MARKET_SCOPED_STREAMS:
            if self.instrument_key is not None:
                raise ValueError("market-scoped quality keys cannot name an instrument")
        elif self.instrument_key is None:
            raise ValueError("instrument-scoped quality keys require an instrument")

    @property
    def sort_key(self) -> tuple[str, str, str, str]:
        return (
            self.exchange.value,
            "" if self.market is None else self.market.value,
            self.instrument_key or "",
            self.logical_stream,
        )


@dataclass(frozen=True, slots=True)
class ExpectedStream:
    key: QualityStreamKey
    shard_id: str
    coverage: CoverageMode

    def __post_init__(self) -> None:
        if type(self.key) is not QualityStreamKey:
            raise TypeError("key must be QualityStreamKey")
        _nonempty(self.shard_id, field_name="shard_id")
        if type(self.coverage) is not CoverageMode:
            raise TypeError("coverage must be CoverageMode")
        if self.key.logical_stream == "_control":
            if self.shard_id != "_control":
                raise ValueError("_control expectation must use the _control shard")
        elif self.shard_id == "_control":
            raise ValueError("non-control expectation cannot use the _control shard")

    @property
    def checkpoint_sort_key(self) -> tuple[str, str, str, str]:
        return (
            "" if self.key.market is None else self.key.market.value,
            self.key.instrument_key or "",
            self.key.logical_stream,
            self.shard_id,
        )


@dataclass(frozen=True, slots=True)
class SubscriptionExpectationCheckpoint:
    source: SourceRecord
    declared_start_ns: int
    declared_end_ns: int | None
    effective_start_ns: int | None
    start_time_source: TimeSource | None
    effective_end_ns: int | None
    end_time_source: TimeSource | None
    policy: EventTimePolicy
    config_sha256: str
    expectations: tuple[ExpectedStream, ...]

    def __post_init__(self) -> None:
        if type(self.source) is not SourceRecord:
            raise TypeError("source must be SourceRecord")
        declared_start_ns = _nonnegative_int64(
            self.declared_start_ns,
            field_name="declared_start_ns",
        )
        if self.declared_end_ns is not None:
            declared_end_ns = _nonnegative_int64(
                self.declared_end_ns,
                field_name="declared_end_ns",
            )
            if declared_end_ns < declared_start_ns:
                raise ValueError("declared end must not precede declared start")
        if type(self.policy) is not EventTimePolicy:
            raise TypeError("policy must be EventTimePolicy")
        config_sha256 = _sha256(self.config_sha256, field_name="config_sha256")
        envelope = self.source.envelope
        if not _expectation_source_is_valid(self.source):
            raise ValueError(
                "subscription expectation requires exchange-scoped internal control"
            )
        if envelope.config_sha256 != config_sha256:
            raise ValueError("checkpoint config SHA does not match its envelope")
        if type(self.expectations) is not tuple or not self.expectations:
            raise ValueError("expectations must be a non-empty tuple")
        if any(type(item) is not ExpectedStream for item in self.expectations):
            raise TypeError("expectations must contain ExpectedStream values")
        if any(
            item.key.exchange is not envelope.exchange for item in self.expectations
        ):
            raise ValueError("checkpoint expectation exchange mismatch")
        canonical = tuple(
            sorted(self.expectations, key=lambda item: item.checkpoint_sort_key)
        )
        if self.expectations != canonical:
            raise ValueError("checkpoint expectations must be canonically sorted")
        checkpoint_keys = tuple(
            (*item.key.sort_key, item.shard_id) for item in self.expectations
        )
        if len(checkpoint_keys) != len(set(checkpoint_keys)):
            raise ValueError("checkpoint expectations must be unique")
        projected_keys = tuple(item.key for item in self.expectations)
        if len(projected_keys) != len(set(projected_keys)):
            raise ValueError(
                "one logical expectation cannot be projected from multiple shards"
            )
        control_expectations = tuple(
            item for item in self.expectations if item.key.logical_stream == "_control"
        )
        if len(control_expectations) != 1 or (
            control_expectations[0].coverage is not CoverageMode.COMPLETE
        ):
            raise ValueError(
                "checkpoint requires one complete exchange-scoped control expectation"
            )

        try:
            payload_start, payload_end, payload_config, payload_expectations = (
                _parse_checkpoint_payload(self.source)
            )
        except ExpectationContractError as error:
            raise ValueError(str(error)) from error
        if (
            payload_start != declared_start_ns
            or payload_end != self.declared_end_ns
            or payload_config != config_sha256
            or payload_expectations != self.expectations
        ):
            raise ValueError("typed checkpoint does not match its source payload")

        received_at_ns = envelope.received_at_ns
        if payload_end is None:
            if self.effective_start_ns is None or self.start_time_source is None:
                raise ValueError("open checkpoint requires a chosen start")
            chosen_start = self.policy.choose(
                event_time_ns=declared_start_ns,
                received_at_ns=received_at_ns,
            )
            if (
                self.effective_start_ns != chosen_start.effective_event_time_ns
                or self.start_time_source is not chosen_start.time_source
            ):
                raise ValueError("open checkpoint start does not match its time policy")
            if self.effective_end_ns is not None or self.end_time_source is not None:
                raise ValueError("open checkpoint cannot carry a chosen end")
            return

        if self.effective_start_ns is not None or self.start_time_source is not None:
            raise ValueError("close checkpoint cannot choose its declared start token")
        if self.effective_end_ns is None or self.end_time_source is None:
            raise ValueError("close checkpoint requires a chosen end")
        chosen_end = self.policy.choose(
            event_time_ns=payload_end,
            received_at_ns=received_at_ns,
        )
        if (
            self.effective_end_ns != chosen_end.effective_event_time_ns
            or self.end_time_source is not chosen_end.time_source
        ):
            raise ValueError("close checkpoint end does not match its time policy")


def _expectation_source_is_valid(source: SourceRecord) -> bool:
    envelope = source.envelope
    return (
        envelope.logical_stream == "_control"
        and envelope.market is None
        and envelope.instrument_key is None
        and envelope.wire_symbol is None
        and envelope.native_channel is None
        and envelope.transport is Transport.INTERNAL
        and envelope.event_time_ns is None
        and envelope.event_time_source is None
        and envelope.integrity_mode is None
        and envelope.coverage is None
        and envelope.rest_metadata is None
        and envelope.connection_id is None
        and envelope.connection_generation is None
        and envelope.egress_id is None
    )


def _parse_expected_stream(
    raw: object,
    *,
    exchange: Exchange,
) -> ExpectedStream:
    if type(raw) is not dict or set(raw) != {
        "market",
        "instrument_key",
        "logical_stream",
        "shard_id",
        "coverage",
    }:
        raise ExpectationContractError(
            "expectation item must have the exact Plan04 fields"
        )
    try:
        market_raw = raw["market"]
        market = None if market_raw is None else Market(market_raw)
        coverage = CoverageMode(raw["coverage"])
        key = QualityStreamKey(
            exchange=exchange,
            market=market,
            instrument_key=raw["instrument_key"],
            logical_stream=raw["logical_stream"],
        )
        return ExpectedStream(
            key=key,
            shard_id=raw["shard_id"],
            coverage=coverage,
        )
    except (KeyError, TypeError, ValueError) as error:
        raise ExpectationContractError("invalid expectation item") from error


def _parse_checkpoint_payload(
    source: SourceRecord,
) -> tuple[int, int | None, str, tuple[ExpectedStream, ...]]:
    if not _expectation_source_is_valid(source):
        raise ExpectationContractError(
            "subscription expectation must use exchange-scoped internal control"
        )
    payload = source.envelope.payload
    if type(payload) is not dict or payload.get("kind") != "subscription_expectation":
        raise ExpectationContractError(
            "source payload is not a subscription_expectation"
        )
    allowed = {
        "kind",
        "effective_start_ns",
        "config_sha256",
        "expectations",
    }
    if "effective_end_ns" in payload:
        allowed.add("effective_end_ns")
    if set(payload) != allowed:
        raise ExpectationContractError(
            "subscription expectation has missing or extra fields"
        )
    raw_expectations = payload["expectations"]
    if type(raw_expectations) is not list or not raw_expectations:
        raise ExpectationContractError("expectations must be a non-empty JSON array")
    try:
        declared_start_ns = _nonnegative_int64(
            payload["effective_start_ns"],
            field_name="effective_start_ns",
        )
        declared_end_ns = (
            _nonnegative_int64(
                payload["effective_end_ns"],
                field_name="effective_end_ns",
            )
            if "effective_end_ns" in payload
            else None
        )
        if declared_end_ns is not None and declared_end_ns < declared_start_ns:
            raise ExpectationContractError(
                "effective end must not precede effective start"
            )
        config_sha256 = _sha256(
            payload["config_sha256"],
            field_name="config_sha256",
        )
        expectations = tuple(
            _parse_expected_stream(item, exchange=source.envelope.exchange)
            for item in raw_expectations
        )
    except ExpectationContractError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ExpectationContractError("invalid subscription expectation") from error
    return declared_start_ns, declared_end_ns, config_sha256, expectations


def decode_subscription_expectation(
    source: SourceRecord,
    *,
    policy: EventTimePolicy,
) -> SubscriptionExpectationCheckpoint | None:
    if type(source) is not SourceRecord:
        raise TypeError("source must be SourceRecord")
    if type(policy) is not EventTimePolicy:
        raise TypeError("policy must be EventTimePolicy")
    payload = source.envelope.payload
    if type(payload) is not dict or payload.get("kind") != "subscription_expectation":
        return None
    try:
        declared_start_ns, declared_end_ns, config_sha256, expectations = (
            _parse_checkpoint_payload(source)
        )
        received_at_ns = source.envelope.received_at_ns
        if declared_end_ns is None:
            chosen_start = policy.choose(
                event_time_ns=declared_start_ns,
                received_at_ns=received_at_ns,
            )
            effective_start_ns = chosen_start.effective_event_time_ns
            start_time_source = chosen_start.time_source
            effective_end_ns = None
            end_time_source = None
        else:
            chosen_end = policy.choose(
                event_time_ns=declared_end_ns,
                received_at_ns=received_at_ns,
            )
            effective_start_ns = None
            start_time_source = None
            effective_end_ns = chosen_end.effective_event_time_ns
            end_time_source = chosen_end.time_source
        return SubscriptionExpectationCheckpoint(
            source=source,
            declared_start_ns=declared_start_ns,
            declared_end_ns=declared_end_ns,
            effective_start_ns=effective_start_ns,
            start_time_source=start_time_source,
            effective_end_ns=effective_end_ns,
            end_time_source=end_time_source,
            policy=policy,
            config_sha256=config_sha256,
            expectations=expectations,
        )
    except ExpectationContractError:
        raise
    except (KeyError, TypeError, ValueError) as error:
        raise ExpectationContractError("invalid subscription expectation") from error


@dataclass(frozen=True, slots=True)
class ExpectationSegment:
    key: QualityStreamKey
    start_ns: int
    end_ns: int
    start_time_source: TimeSource | None
    end_time_source: TimeSource | None
    coverage: CoverageMode
    config_sha256: str
    shard_id: str
    lineage_manifest_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.key) is not QualityStreamKey:
            raise TypeError("key must be QualityStreamKey")
        if self.key.logical_stream == "_control":
            raise ValueError("control expectations are evidence, not quality segments")
        start_ns = _nonnegative_int64(self.start_ns, field_name="start_ns")
        end_ns = _nonnegative_int64(self.end_ns, field_name="end_ns")
        if end_ns <= start_ns:
            raise ValueError("expectation segment must have positive duration")
        if self.start_time_source is not None and (
            type(self.start_time_source) is not TimeSource
        ):
            raise TypeError("start_time_source must be TimeSource or None")
        if self.end_time_source is not None and (
            type(self.end_time_source) is not TimeSource
        ):
            raise TypeError("end_time_source must be TimeSource or None")
        if type(self.coverage) is not CoverageMode:
            raise TypeError("coverage must be CoverageMode")
        _sha256(self.config_sha256, field_name="config_sha256")
        _nonempty(self.shard_id, field_name="shard_id")
        _validate_lineage(self.lineage_manifest_sha256s)


@dataclass(frozen=True, slots=True)
class _CheckpointGroup:
    exchange: Exchange
    declared_start_ns: int
    start_ns: int
    start_time_source: TimeSource
    explicit_end_ns: int | None
    explicit_end_time_source: TimeSource | None
    config_sha256: str
    expectations: tuple[ExpectedStream, ...]
    lineage_manifest_sha256s: tuple[str, ...]


def _group_checkpoints(
    checkpoints: tuple[SubscriptionExpectationCheckpoint, ...],
) -> dict[Exchange, tuple[_CheckpointGroup, ...]]:
    sources: set[SourceLocator] = set()
    policies_by_config: dict[str, EventTimePolicy] = {}
    grouped: dict[tuple[Exchange, int], list[SubscriptionExpectationCheckpoint]] = {}
    for checkpoint in checkpoints:
        if type(checkpoint) is not SubscriptionExpectationCheckpoint:
            raise TypeError(
                "checkpoints must contain SubscriptionExpectationCheckpoint values"
            )
        if checkpoint.source.locator in sources:
            raise ExpectationContractError("checkpoint source locators must be unique")
        sources.add(checkpoint.source.locator)
        existing_policy = policies_by_config.get(checkpoint.config_sha256)
        if existing_policy is not None and existing_policy != checkpoint.policy:
            raise ExpectationContractError(
                "one checkpoint config SHA cannot use multiple time policy values"
            )
        policies_by_config[checkpoint.config_sha256] = checkpoint.policy
        key = (checkpoint.source.envelope.exchange, checkpoint.declared_start_ns)
        grouped.setdefault(key, []).append(checkpoint)

    by_exchange: dict[Exchange, list[_CheckpointGroup]] = {}
    for (exchange, declared_start_ns), members in grouped.items():
        opens = tuple(item for item in members if item.effective_end_ns is None)
        closes = tuple(item for item in members if item.effective_end_ns is not None)
        if not opens:
            raise ExpectationContractError(
                "checkpoint close has no exact declared-start open"
            )
        if len(opens) > 1:
            raise ExpectationContractError(
                "checkpoint declared token has multiple open records"
            )
        if len(closes) > 1:
            raise ExpectationContractError(
                "checkpoint declared token has multiple close records"
            )
        opened = opens[0]
        closed = closes[0] if closes else None
        if closed is not None and (
            closed.config_sha256 != opened.config_sha256
            or closed.expectations != opened.expectations
        ):
            raise ExpectationContractError(
                "checkpoint open and close state conflict for one declared token"
            )
        assert opened.effective_start_ns is not None
        assert opened.start_time_source is not None
        explicit_end_ns = None if closed is None else closed.effective_end_ns
        explicit_end_time_source = None if closed is None else closed.end_time_source
        if explicit_end_ns is not None and explicit_end_ns < opened.effective_start_ns:
            raise ExpectationContractError(
                "chosen checkpoint end precedes its chosen open start"
            )
        by_exchange.setdefault(exchange, []).append(
            _CheckpointGroup(
                exchange=exchange,
                declared_start_ns=declared_start_ns,
                start_ns=opened.effective_start_ns,
                start_time_source=opened.start_time_source,
                explicit_end_ns=explicit_end_ns,
                explicit_end_time_source=explicit_end_time_source,
                config_sha256=opened.config_sha256,
                expectations=opened.expectations,
                lineage_manifest_sha256s=tuple(
                    sorted({item.source.locator.manifest_sha256 for item in members})
                ),
            )
        )

    result: dict[Exchange, tuple[_CheckpointGroup, ...]] = {}
    for exchange, groups in by_exchange.items():
        ordered = tuple(sorted(groups, key=lambda item: item.start_ns))
        for previous, current in pairwise(ordered):
            if current.start_ns == previous.start_ns:
                raise ExpectationContractError(
                    "distinct checkpoints resolve to the same effective start"
                )
        result[exchange] = ordered
    return result


def build_expectation_segments(
    checkpoints: Iterable[SubscriptionExpectationCheckpoint],
    *,
    range_start_ns: int,
    range_end_ns: int,
) -> tuple[ExpectationSegment, ...]:
    range_start = _nonnegative_int64(range_start_ns, field_name="range_start_ns")
    range_end = _nonnegative_int64(range_end_ns, field_name="range_end_ns")
    if range_end <= range_start:
        raise ValueError("expectation range must have positive duration")
    grouped = _group_checkpoints(tuple(checkpoints))
    segments: list[ExpectationSegment] = []

    for groups in grouped.values():
        for index, group in enumerate(groups):
            next_group = groups[index + 1] if index + 1 < len(groups) else None
            next_start = None if next_group is None else next_group.start_ns
            if (
                group.explicit_end_ns is not None
                and next_start is not None
                and group.explicit_end_ns > next_start
            ):
                raise ExpectationContractError(
                    "explicit expectation end overlaps the next checkpoint"
                )
            semantic_end = (
                group.explicit_end_ns
                if group.explicit_end_ns is not None
                else next_start
                if next_start is not None
                else range_end
            )
            assert semantic_end is not None
            semantic_end_time_source = (
                group.explicit_end_time_source
                if group.explicit_end_ns is not None
                else next_group.start_time_source
                if next_group is not None
                else None
            )
            start_ns = max(group.start_ns, range_start)
            end_ns = min(semantic_end, range_end)
            if end_ns <= start_ns:
                continue

            lineage = set(group.lineage_manifest_sha256s)
            if (
                group.explicit_end_ns is None
                and next_group is not None
                and next_group.start_ns <= range_end
            ):
                lineage.update(next_group.lineage_manifest_sha256s)
            lineage_tuple = tuple(sorted(lineage))
            for expectation in group.expectations:
                if expectation.key.logical_stream == "_control":
                    continue
                segments.append(
                    ExpectationSegment(
                        key=expectation.key,
                        start_ns=start_ns,
                        end_ns=end_ns,
                        start_time_source=(
                            group.start_time_source
                            if start_ns == group.start_ns
                            else None
                        ),
                        end_time_source=(
                            semantic_end_time_source if end_ns == semantic_end else None
                        ),
                        coverage=expectation.coverage,
                        config_sha256=group.config_sha256,
                        shard_id=expectation.shard_id,
                        lineage_manifest_sha256s=lineage_tuple,
                    )
                )
    return tuple(
        sorted(
            segments,
            key=lambda item: (item.start_ns, item.end_ns, item.key.sort_key),
        )
    )


@dataclass(frozen=True, slots=True)
class QualityEvent:
    source: SourceRecord
    targets: tuple[QualityStreamKey, ...]
    event_id: str
    kind: QualityEventKind
    event_time_ns: int | None

    def __post_init__(self) -> None:
        if type(self.source) is not SourceRecord:
            raise TypeError("source must be SourceRecord")
        if type(self.targets) is not tuple or not self.targets:
            raise ValueError("targets must be a non-empty tuple")
        if any(type(target) is not QualityStreamKey for target in self.targets):
            raise TypeError("targets must contain QualityStreamKey values")
        canonical_targets = tuple(sorted(self.targets, key=lambda item: item.sort_key))
        if self.targets != canonical_targets or len(self.targets) != len(
            set(self.targets)
        ):
            raise ValueError("targets must be canonically sorted and unique")
        _nonempty(self.event_id, field_name="event_id")
        if type(self.kind) is not QualityEventKind:
            raise TypeError("kind must be QualityEventKind")
        if self.event_time_ns is not None:
            _nonnegative_int64(self.event_time_ns, field_name="event_time_ns")
        if not _expectation_source_is_valid(self.source):
            raise ValueError("quality events require exchange-scoped internal control")
        if any(
            self.source.envelope.exchange is not target.exchange
            for target in self.targets
        ):
            raise ValueError("quality event source exchange does not match its targets")


@dataclass(frozen=True, slots=True)
class LocatedQualityEventEvidence:
    event_id: str
    kind: QualityEventKind
    source_locator: SourceLocator
    source_received_at_ns: int
    event_time_ns: int | None
    targets: tuple[QualityStreamKey, ...]

    def __post_init__(self) -> None:
        _nonempty(self.event_id, field_name="event_id")
        if type(self.kind) is not QualityEventKind:
            raise TypeError("kind must be QualityEventKind")
        if type(self.source_locator) is not SourceLocator:
            raise TypeError("source_locator must be SourceLocator")
        _nonnegative_int64(
            self.source_received_at_ns,
            field_name="source_received_at_ns",
        )
        if self.event_time_ns is not None:
            _nonnegative_int64(self.event_time_ns, field_name="event_time_ns")
        if type(self.targets) is not tuple or not self.targets:
            raise ValueError("targets must be a non-empty tuple")
        if any(type(target) is not QualityStreamKey for target in self.targets):
            raise TypeError("targets must contain QualityStreamKey values")
        if self.targets != tuple(
            sorted(self.targets, key=lambda item: item.sort_key)
        ) or len(self.targets) != len(set(self.targets)):
            raise ValueError("targets must be canonically sorted and unique")


def _quality_event_evidence(event: QualityEvent) -> LocatedQualityEventEvidence:
    return LocatedQualityEventEvidence(
        event_id=event.event_id,
        kind=event.kind,
        source_locator=event.source.locator,
        source_received_at_ns=event.source.envelope.received_at_ns,
        event_time_ns=event.event_time_ns,
        targets=event.targets,
    )


@dataclass(frozen=True, slots=True)
class TimedQualityEvent:
    event: QualityEvent
    effective_event_time_ns: int
    time_source: TimeSource

    def __post_init__(self) -> None:
        if type(self.event) is not QualityEvent:
            raise TypeError("event must be QualityEvent")
        effective = _nonnegative_int64(
            self.effective_event_time_ns,
            field_name="effective_event_time_ns",
        )
        if type(self.time_source) is not TimeSource:
            raise TypeError("time_source must be TimeSource")
        event_time = self.event.event_time_ns
        received = _nonnegative_int64(
            self.event.source.envelope.received_at_ns,
            field_name="source received_at_ns",
        )
        if self.time_source is TimeSource.EVENT:
            consistent = event_time is not None and effective == event_time
        elif self.time_source is TimeSource.RECEIVE_MISSING:
            consistent = event_time is None and effective == received
        else:
            consistent = (
                event_time is not None
                and event_time != received
                and effective == received
            )
        if not consistent:
            raise ValueError(
                "time_source must match the quality event and effective event time"
            )


def apply_quality_event_time_policy(
    events: Iterable[QualityEvent],
    policy: EventTimePolicy,
) -> tuple[TimedQualityEvent, ...]:
    if type(policy) is not EventTimePolicy:
        raise TypeError("policy must be EventTimePolicy")
    timed: list[TimedQualityEvent] = []
    event_ids: set[str] = set()
    for event in tuple(events):
        if type(event) is not QualityEvent:
            raise TypeError("events must contain QualityEvent values")
        if event.event_id in event_ids:
            raise ValueError("quality event_id values must be globally unique")
        event_ids.add(event.event_id)
        chosen = policy.choose(
            event_time_ns=event.event_time_ns,
            received_at_ns=event.source.envelope.received_at_ns,
        )
        timed.append(
            TimedQualityEvent(
                event=event,
                effective_event_time_ns=chosen.effective_event_time_ns,
                time_source=chosen.time_source,
            )
        )
    return tuple(timed)


@dataclass(frozen=True, slots=True)
class QualityWindowRow:
    key: QualityStreamKey
    window: Window
    expected: bool
    expected_duration_ns: int
    coverage: CoverageMode | None
    input_count: int
    event_time_count: int
    receive_missing_count: int
    receive_outlier_count: int
    event_time_ratio: Decimal | None
    quality_event_count: int
    quality_event_event_time_count: int
    quality_event_receive_missing_count: int
    quality_event_receive_outlier_count: int
    latency_count: int
    latency_min_ns: int | None
    latency_max_ns: int | None
    last_event_age_ns: int | None
    gap_count: int
    reconnect_count: int
    parse_error_count: int
    checksum_error_count: int
    sequence_error_count: int
    queue_overflow_count: int
    egress_change_count: int
    throttle_count: int
    interval_stretch_count: int
    quality_complete: bool
    lineage_manifest_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.key) is not QualityStreamKey:
            raise TypeError("key must be QualityStreamKey")
        if type(self.window) is not Window:
            raise TypeError("window must be Window")
        if type(self.expected) is not bool:
            raise TypeError("expected must be bool")
        duration = _nonnegative_int64(
            self.expected_duration_ns,
            field_name="expected_duration_ns",
        )
        if duration > self.window.interval_ns:
            raise ValueError("expected duration cannot exceed the window")
        if self.expected is not (duration > 0):
            raise ValueError("expected must match positive expected duration")
        if self.expected:
            if type(self.coverage) is not CoverageMode:
                raise TypeError("expected rows require CoverageMode")
        elif self.coverage is not None:
            raise ValueError("unexpected rows cannot claim expectation coverage")
        count_fields = (
            "input_count",
            "event_time_count",
            "receive_missing_count",
            "receive_outlier_count",
            "quality_event_count",
            "quality_event_event_time_count",
            "quality_event_receive_missing_count",
            "quality_event_receive_outlier_count",
            "latency_count",
            *(f"{kind.value}_count" for kind in QualityEventKind),
        )
        for field_name in count_fields:
            _nonnegative_int64(getattr(self, field_name), field_name=field_name)
        if (
            self.event_time_count
            + self.receive_missing_count
            + self.receive_outlier_count
            != self.input_count
        ):
            raise ValueError("time-source counts must equal input_count")
        if self.latency_count != self.input_count:
            raise ValueError("latency_count must equal input_count")
        if (
            self.quality_event_event_time_count
            + self.quality_event_receive_missing_count
            + self.quality_event_receive_outlier_count
            != self.quality_event_count
        ):
            raise ValueError("quality event time-source counts must be conserved")
        if (
            sum(getattr(self, f"{kind.value}_count") for kind in QualityEventKind)
            != self.quality_event_count
        ):
            raise ValueError("quality event kind counts must equal quality_event_count")
        if self.input_count == 0:
            if (
                self.event_time_ratio is not None
                or self.latency_min_ns is not None
                or self.latency_max_ns is not None
                or self.last_event_age_ns is not None
            ):
                raise ValueError("empty input metrics must be null")
        else:
            if type(self.event_time_ratio) is not Decimal:
                raise TypeError("event_time_ratio must be Decimal")
            if self.event_time_ratio != _ratio(
                self.event_time_count,
                self.input_count,
            ):
                raise ValueError("event_time_ratio does not match its counts")
            if self.latency_min_ns is None or self.latency_max_ns is None:
                raise ValueError("non-empty rows require latency bounds")
            latency_min_ns = _signed_int64(
                self.latency_min_ns,
                field_name="latency_min_ns",
            )
            latency_max_ns = _signed_int64(
                self.latency_max_ns,
                field_name="latency_max_ns",
            )
            if latency_max_ns < latency_min_ns:
                raise ValueError("latency bounds are reversed")
            if self.last_event_age_ns is None:
                raise ValueError("non-empty rows require non-negative last event age")
            _nonnegative_int64(
                self.last_event_age_ns,
                field_name="last_event_age_ns",
            )
        if type(self.quality_complete) is not bool:
            raise TypeError("quality_complete must be bool")
        _validate_lineage(self.lineage_manifest_sha256s)


def _validate_lineage(lineage: tuple[str, ...]) -> None:
    if (
        type(lineage) is not tuple
        or not lineage
        or any(not _is_sha256(item) for item in lineage)
    ):
        raise ValueError("lineage must contain SHA-256 digests")
    if lineage != tuple(sorted(set(lineage))):
        raise ValueError("lineage SHA-256 values must be sorted and unique")


@dataclass(slots=True)
class _WindowAccumulator:
    key: QualityStreamKey
    window: Window
    expected_duration_ns: int = 0
    coverages: set[CoverageMode] = field(default_factory=set)
    input_count: int = 0
    time_source_counts: dict[TimeSource, int] = field(
        default_factory=lambda: {source: 0 for source in TimeSource}
    )
    latencies_ns: list[int] = field(default_factory=list)
    last_effective_event_time_ns: int | None = None
    event_counts: dict[QualityEventKind, int] = field(
        default_factory=lambda: {kind: 0 for kind in QualityEventKind}
    )
    quality_event_time_source_counts: dict[TimeSource, int] = field(
        default_factory=lambda: {source: 0 for source in TimeSource}
    )
    actual_manifest_sha256s: set[str] = field(default_factory=set)
    actual_received_at_ns_by_manifest: dict[str, set[int]] = field(default_factory=dict)
    quality_event_ids: set[str] = field(default_factory=set)
    quality_complete: bool = True
    lineage: set[str] = field(default_factory=set)


def _accumulator(
    accumulators: dict[tuple[QualityStreamKey, int], _WindowAccumulator],
    *,
    key: QualityStreamKey,
    window: Window,
) -> _WindowAccumulator:
    identity = (key, window.start_ns)
    existing = accumulators.get(identity)
    if existing is not None:
        return existing
    created = _WindowAccumulator(key=key, window=window)
    accumulators[identity] = created
    return created


def _validate_nonoverlapping_expectations(
    expectations: tuple[ExpectationSegment, ...],
) -> None:
    by_key: dict[QualityStreamKey, list[ExpectationSegment]] = {}
    for segment in expectations:
        if type(segment) is not ExpectationSegment:
            raise TypeError("expectations must contain ExpectationSegment values")
        by_key.setdefault(segment.key, []).append(segment)
    for segments in by_key.values():
        ordered = sorted(segments, key=lambda item: (item.start_ns, item.end_ns))
        for previous, current in pairwise(ordered):
            if current.start_ns < previous.end_ns:
                raise ExpectationContractError(
                    "expectation segments for one quality key overlap"
                )


def _coverage(coverages: set[CoverageMode]) -> CoverageMode | None:
    if not coverages:
        return None
    return max(coverages, key=_COVERAGE_PRECEDENCE.__getitem__)


def build_quality_windows(
    expectations: Iterable[ExpectationSegment],
    actual_records: Iterable[TimedSourceRecord],
    *,
    quality_events: Iterable[TimedQualityEvent] = (),
    reconciliations: Iterable[ManifestQualityReconciliation] = (),
    interval_ns: int,
) -> tuple[QualityWindowRow, ...]:
    interval = window_for(0, interval_ns).interval_ns
    expectation_values = tuple(expectations)
    _validate_nonoverlapping_expectations(expectation_values)
    accumulators: dict[tuple[QualityStreamKey, int], _WindowAccumulator] = {}

    for segment in expectation_values:
        cursor = window_for(segment.start_ns, interval).start_ns
        while cursor < segment.end_ns:
            window = window_for(cursor, interval)
            overlap_start = max(segment.start_ns, window.start_ns)
            overlap_end = min(segment.end_ns, window.end_ns)
            if overlap_start < overlap_end:
                item = _accumulator(accumulators, key=segment.key, window=window)
                item.expected_duration_ns += overlap_end - overlap_start
                item.coverages.add(segment.coverage)
                item.lineage.update(segment.lineage_manifest_sha256s)
            cursor = window.end_ns

    actual_values = tuple(actual_records)
    actual_locators: set[SourceLocator] = set()
    for timed in actual_values:
        if type(timed) is not TimedSourceRecord:
            raise TypeError("actual_records must contain TimedSourceRecord values")
        locator = timed.source.locator
        if locator in actual_locators:
            raise ValueError("actual source locators must be unique")
        actual_locators.add(locator)
        envelope = timed.source.envelope
        key = QualityStreamKey(
            exchange=envelope.exchange,
            market=envelope.market,
            instrument_key=envelope.instrument_key,
            logical_stream=envelope.logical_stream,
        )
        if key.logical_stream == "_control":
            raise ValueError("control records must be supplied as typed quality events")
        window = window_for(timed.effective_event_time_ns, interval)
        item = _accumulator(accumulators, key=key, window=window)
        item.input_count += 1
        item.time_source_counts[timed.time_source] += 1
        item.latencies_ns.append(
            envelope.received_at_ns - timed.effective_event_time_ns
        )
        item.last_effective_event_time_ns = max(
            timed.effective_event_time_ns,
            item.last_effective_event_time_ns
            if item.last_effective_event_time_ns is not None
            else timed.effective_event_time_ns,
        )
        item.lineage.add(locator.manifest_sha256)
        item.actual_manifest_sha256s.add(locator.manifest_sha256)
        item.actual_received_at_ns_by_manifest.setdefault(
            locator.manifest_sha256,
            set(),
        ).add(envelope.received_at_ns)

    quality_event_index: dict[str, QualityEvent] = {}
    for timed_event in tuple(quality_events):
        if type(timed_event) is not TimedQualityEvent:
            raise TypeError("quality_events must contain TimedQualityEvent values")
        event_id = timed_event.event.event_id
        if event_id in quality_event_index:
            raise ValueError("quality event_id values must be globally unique")
        quality_event_index[event_id] = timed_event.event
        window = window_for(timed_event.effective_event_time_ns, interval)
        for target in timed_event.event.targets:
            if target.logical_stream == "_control":
                raise ValueError("control cannot be a research quality target")
            item = _accumulator(
                accumulators,
                key=target,
                window=window,
            )
            item.event_counts[timed_event.event.kind] += 1
            item.quality_event_time_source_counts[timed_event.time_source] += 1
            item.quality_event_ids.add(event_id)
            item.lineage.add(timed_event.event.source.locator.manifest_sha256)

    reconciliation_values = tuple(reconciliations)
    reconciliations_by_sha: dict[str, ManifestQualityReconciliation] = {}
    control_reconciliation_shas: dict[tuple[QualityStreamKey, str], set[str]] = {}
    for reconciliation in reconciliation_values:
        if type(reconciliation) is not ManifestQualityReconciliation:
            raise TypeError(
                "reconciliations must contain ManifestQualityReconciliation values"
            )
        if reconciliation.manifest_sha256 in reconciliations_by_sha:
            raise ValueError("reconciliation manifest_sha256 values must be unique")
        reconciliations_by_sha[reconciliation.manifest_sha256] = reconciliation
        for evidence in reconciliation.located_control_events:
            event = quality_event_index.get(evidence.event_id)
            if event is None:
                raise ValueError("reconciliation locates an unknown quality event_id")
            if reconciliation.key not in event.targets:
                raise ValueError(
                    "reconciliation quality event does not include its target key"
                )
            if evidence != _quality_event_evidence(event):
                raise ValueError(
                    "reconciliation quality event evidence does not match input"
                )
            control_reconciliation_shas.setdefault(
                (reconciliation.key, evidence.event_id),
                set(),
            ).add(reconciliation.manifest_sha256)

    for item in accumulators.values():
        for manifest_sha256 in item.actual_manifest_sha256s:
            exact_reconciliation = reconciliations_by_sha.get(manifest_sha256)
            if (
                exact_reconciliation is None
                or exact_reconciliation.key != item.key
                or not exact_reconciliation.quality_complete
                or any(
                    not (
                        exact_reconciliation.hour_start_ns
                        <= received_at_ns
                        < exact_reconciliation.hour_end_ns
                    )
                    for received_at_ns in item.actual_received_at_ns_by_manifest[
                        manifest_sha256
                    ]
                )
            ):
                item.quality_complete = False
        for event_id in item.quality_event_ids:
            association_shas = control_reconciliation_shas.get(
                (item.key, event_id),
                set(),
            )
            if not association_shas or any(
                not reconciliations_by_sha[association_sha].quality_complete
                for association_sha in association_shas
            ):
                item.quality_complete = False
            item.lineage.update(association_shas)

    for reconciliation in reconciliation_values:
        for item in accumulators.values():
            if item.key != reconciliation.key or not (
                item.window.start_ns < reconciliation.hour_end_ns
                and reconciliation.hour_start_ns < item.window.end_ns
            ):
                continue
            item.quality_complete = (
                item.quality_complete and reconciliation.quality_complete
            )
            item.lineage.add(reconciliation.manifest_sha256)

    rows: list[QualityWindowRow] = []
    for item in accumulators.values():
        event_count = item.time_source_counts[TimeSource.EVENT]
        ratio = None if item.input_count == 0 else _ratio(event_count, item.input_count)
        last_age = (
            None
            if item.last_effective_event_time_ns is None
            else max(0, item.window.end_ns - item.last_effective_event_time_ns)
        )
        rows.append(
            QualityWindowRow(
                key=item.key,
                window=item.window,
                expected=item.expected_duration_ns > 0,
                expected_duration_ns=item.expected_duration_ns,
                coverage=_coverage(item.coverages),
                input_count=item.input_count,
                event_time_count=event_count,
                receive_missing_count=item.time_source_counts[
                    TimeSource.RECEIVE_MISSING
                ],
                receive_outlier_count=item.time_source_counts[
                    TimeSource.RECEIVE_OUTLIER
                ],
                event_time_ratio=ratio,
                quality_event_count=sum(item.quality_event_time_source_counts.values()),
                quality_event_event_time_count=item.quality_event_time_source_counts[
                    TimeSource.EVENT
                ],
                quality_event_receive_missing_count=(
                    item.quality_event_time_source_counts[TimeSource.RECEIVE_MISSING]
                ),
                quality_event_receive_outlier_count=(
                    item.quality_event_time_source_counts[TimeSource.RECEIVE_OUTLIER]
                ),
                latency_count=len(item.latencies_ns),
                latency_min_ns=(min(item.latencies_ns) if item.latencies_ns else None),
                latency_max_ns=(max(item.latencies_ns) if item.latencies_ns else None),
                last_event_age_ns=last_age,
                gap_count=item.event_counts[QualityEventKind.GAP],
                reconnect_count=item.event_counts[QualityEventKind.RECONNECT],
                parse_error_count=item.event_counts[QualityEventKind.PARSE_ERROR],
                checksum_error_count=item.event_counts[QualityEventKind.CHECKSUM_ERROR],
                sequence_error_count=item.event_counts[QualityEventKind.SEQUENCE_ERROR],
                queue_overflow_count=item.event_counts[QualityEventKind.QUEUE_OVERFLOW],
                egress_change_count=item.event_counts[QualityEventKind.EGRESS_CHANGE],
                throttle_count=item.event_counts[QualityEventKind.THROTTLE],
                interval_stretch_count=item.event_counts[
                    QualityEventKind.INTERVAL_STRETCH
                ],
                quality_complete=item.quality_complete,
                lineage_manifest_sha256s=tuple(sorted(item.lineage)),
            )
        )
    return tuple(sorted(rows, key=lambda row: (row.window.start_ns, row.key.sort_key)))


@dataclass(frozen=True, slots=True)
class ManifestQualityCount:
    kind: QualityEventKind
    manifest_total: int | None
    located_count: int
    unlocated_count: int | None

    def __post_init__(self) -> None:
        if type(self.kind) is not QualityEventKind:
            raise TypeError("kind must be QualityEventKind")
        if self.kind not in _MANIFEST_COUNTER_FIELDS:
            raise ValueError("kind has no RawManifestV1 quality counter")
        if self.manifest_total is not None:
            _nonnegative_int64(self.manifest_total, field_name="manifest_total")
        _nonnegative_int64(self.located_count, field_name="located_count")
        if self.unlocated_count is not None:
            _nonnegative_int64(self.unlocated_count, field_name="unlocated_count")
        if (self.manifest_total is None) != (self.unlocated_count is None):
            raise ValueError(
                "unlocated_count must be unavailable exactly when manifest_total is"
            )
        if self.manifest_total is not None and self.unlocated_count != max(
            self.manifest_total - self.located_count,
            0,
        ):
            raise ValueError("unlocated_count must equal max(total - located, 0)")


@dataclass(frozen=True, slots=True)
class ManifestQualityReconciliation:
    source: DiscoveredRawInput
    key: QualityStreamKey
    manifest_sha256: str
    hour_start_ns: int
    hour_end_ns: int
    counts: tuple[ManifestQualityCount, ...]
    located_control_event_ids: tuple[str, ...]
    located_control_events: tuple[LocatedQualityEventEvidence, ...]
    missing_control_event_ids: tuple[str, ...]
    quality_complete: bool
    diagnostics: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.source) is not DiscoveredRawInput:
            raise TypeError("source must be DiscoveredRawInput")
        if type(self.key) is not QualityStreamKey:
            raise TypeError("key must be QualityStreamKey")
        _sha256(self.manifest_sha256, field_name="manifest_sha256")
        if self.manifest_sha256 != self.source.manifest_sha256:
            raise ValueError("reconciliation manifest SHA must match its source")
        if self.key != _manifest_key(self.source):
            raise ValueError("reconciliation key must match its source manifest")
        start = _nonnegative_int64(self.hour_start_ns, field_name="hour_start_ns")
        end = _nonnegative_int64(self.hour_end_ns, field_name="hour_end_ns")
        if end - start != _HOUR_NS or start % _HOUR_NS:
            raise ValueError("manifest reconciliation must cover one UTC hour")
        expected_hour_start = (
            self.source.manifest.first_received_at_ns // _HOUR_NS * _HOUR_NS
        )
        if start != expected_hour_start:
            raise ValueError("reconciliation hour must match its source manifest")
        if type(self.counts) is not tuple or any(
            type(item) is not ManifestQualityCount for item in self.counts
        ):
            raise TypeError("counts must contain ManifestQualityCount values")
        if tuple(item.kind for item in self.counts) != _MANIFEST_KINDS:
            raise ValueError("manifest quality counts must use canonical kinds")
        for count in self.counts:
            manifest_total = getattr(
                self.source.manifest,
                _MANIFEST_COUNTER_FIELDS[count.kind],
            )
            if count.manifest_total != manifest_total:
                raise ValueError(
                    f"{count.kind.value} manifest_total does not match source manifest"
                )
        if type(self.located_control_event_ids) is not tuple or any(
            type(item) is not str or not item or item != item.strip()
            for item in self.located_control_event_ids
        ):
            raise ValueError("located control event IDs must be normalized strings")
        if self.located_control_event_ids != tuple(
            sorted(set(self.located_control_event_ids))
        ):
            raise ValueError("located control event IDs must be sorted and unique")
        if type(self.located_control_events) is not tuple or any(
            type(item) is not LocatedQualityEventEvidence
            for item in self.located_control_events
        ):
            raise TypeError(
                "located_control_events must contain LocatedQualityEventEvidence values"
            )
        canonical_located_events = tuple(
            sorted(self.located_control_events, key=lambda item: item.event_id)
        )
        if self.located_control_events != canonical_located_events or len(
            self.located_control_events
        ) != len({item.event_id for item in self.located_control_events}):
            raise ValueError("located control events must be sorted and unique")
        if self.located_control_event_ids != tuple(
            item.event_id for item in self.located_control_events
        ):
            raise ValueError(
                "located control event IDs must match located event evidence"
            )
        if any(self.key not in item.targets for item in self.located_control_events):
            raise ValueError("located control event evidence must include target key")
        for count in self.counts:
            evidence_count = sum(
                item.kind is count.kind for item in self.located_control_events
            )
            if count.located_count != evidence_count:
                raise ValueError(
                    f"{count.kind.value} located_count does not match event evidence"
                )
        if type(self.missing_control_event_ids) is not tuple or any(
            type(item) is not str or not item or item != item.strip()
            for item in self.missing_control_event_ids
        ):
            raise ValueError("missing control event IDs must be normalized strings")
        if self.missing_control_event_ids != tuple(
            sorted(set(self.missing_control_event_ids))
        ):
            raise ValueError("missing control event IDs must be sorted and unique")
        if set(self.located_control_event_ids) & set(self.missing_control_event_ids):
            raise ValueError("located and missing control event IDs must be disjoint")
        manifest_control_event_ids = self.source.manifest.control_event_ids or ()
        if (
            tuple(
                sorted(
                    (*self.located_control_event_ids, *self.missing_control_event_ids)
                )
            )
            != manifest_control_event_ids
        ):
            raise ValueError(
                "located and missing control event IDs must partition source manifest IDs"
            )
        if type(self.quality_complete) is not bool:
            raise TypeError("quality_complete must be bool")
        if type(self.diagnostics) is not tuple or any(
            type(item) is not str or not item or item != item.strip()
            for item in self.diagnostics
        ):
            raise ValueError("diagnostics must be normalized strings")
        if self.diagnostics != tuple(sorted(set(self.diagnostics))):
            raise ValueError("diagnostics must be sorted and unique")
        expected_complete = (
            not self.missing_control_event_ids
            and not self.diagnostics
            and all(
                item.manifest_total is not None
                and item.located_count <= item.manifest_total
                and item.unlocated_count == 0
                for item in self.counts
            )
        )
        if self.quality_complete is not expected_complete:
            raise ValueError("quality_complete does not match reconciliation evidence")


def _manifest_key(source: DiscoveredRawInput) -> QualityStreamKey:
    manifest = source.manifest
    return QualityStreamKey(
        exchange=manifest.exchange,
        market=manifest.market,
        instrument_key=manifest.instrument_key,
        logical_stream=manifest.logical_stream,
    )


def reconcile_manifest_quality(
    source: DiscoveredRawInput,
    events: Iterable[QualityEvent],
) -> ManifestQualityReconciliation:
    if type(source) is not DiscoveredRawInput:
        raise TypeError("source must be DiscoveredRawInput")
    event_index: dict[str, QualityEvent] = {}
    for event in tuple(events):
        if type(event) is not QualityEvent:
            raise TypeError("events must contain QualityEvent values")
        if event.event_id in event_index:
            raise ValueError("quality event_id values must be globally unique")
        event_index[event.event_id] = event

    manifest = source.manifest
    manifest_key = _manifest_key(source)
    referenced_ids = manifest.control_event_ids or ()
    missing_ids: list[str] = []
    located_ids: list[str] = []
    located_events: list[LocatedQualityEventEvidence] = []
    diagnostics: list[str] = []
    located = {kind: 0 for kind in _MANIFEST_KINDS}
    for event_id in referenced_ids:
        referenced_event = event_index.get(event_id)
        if referenced_event is None:
            missing_ids.append(event_id)
            diagnostics.append(f"missing_control_event:{event_id}")
            continue
        if manifest_key not in referenced_event.targets:
            missing_ids.append(event_id)
            diagnostics.append(f"control_target_mismatch:{event_id}")
            continue
        located_ids.append(event_id)
        located_events.append(_quality_event_evidence(referenced_event))
        if referenced_event.kind in located:
            located[referenced_event.kind] += 1

    counts: list[ManifestQualityCount] = []
    quality_complete = not missing_ids and not diagnostics
    for kind, field_name in _MANIFEST_COUNTER_FIELDS.items():
        total = getattr(manifest, field_name)
        located_count = located[kind]
        unlocated_count = None if total is None else max(total - located_count, 0)
        if total is None:
            diagnostics.append(f"manifest_total_unavailable:{kind.value}")
            quality_complete = False
        else:
            if located_count > total:
                diagnostics.append(
                    "located_exceeds_manifest_total:"
                    f"{kind.value}:{located_count}:{total}"
                )
                quality_complete = False
            if unlocated_count:
                diagnostics.append(
                    f"unlocated_manifest_total:{kind.value}:{unlocated_count}"
                )
                quality_complete = False
        counts.append(
            ManifestQualityCount(
                kind=kind,
                manifest_total=total,
                located_count=located_count,
                unlocated_count=unlocated_count,
            )
        )

    hour_start = manifest.first_received_at_ns // _HOUR_NS * _HOUR_NS
    return ManifestQualityReconciliation(
        source=source,
        key=manifest_key,
        manifest_sha256=source.manifest_sha256,
        hour_start_ns=hour_start,
        hour_end_ns=hour_start + _HOUR_NS,
        counts=tuple(counts),
        located_control_event_ids=tuple(sorted(located_ids)),
        located_control_events=tuple(
            sorted(located_events, key=lambda item: item.event_id)
        ),
        missing_control_event_ids=tuple(sorted(missing_ids)),
        quality_complete=quality_complete,
        diagnostics=tuple(sorted(set(diagnostics))),
    )


__all__ = [
    "ExpectationContractError",
    "ExpectationSegment",
    "ExpectedStream",
    "LocatedQualityEventEvidence",
    "ManifestQualityCount",
    "ManifestQualityReconciliation",
    "QualityEvent",
    "QualityEventKind",
    "QualityStreamKey",
    "QualityWindowRow",
    "SubscriptionExpectationCheckpoint",
    "TimedQualityEvent",
    "apply_quality_event_time_policy",
    "build_expectation_segments",
    "build_quality_windows",
    "decode_subscription_expectation",
    "reconcile_manifest_quality",
]
