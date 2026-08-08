from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    Inexact,
    Rounded,
    localcontext,
)

from crypto_collector.domain.types import Exchange, IntegrityMode
from crypto_collector.materializer.books.replay import (
    BookGapReason,
    BookScope,
    OkxBookReplayer,
    ReplayedBook,
    TimedBookRecord,
    apply_book_time_policy,
    is_okx_authoritative_snapshot,
)
from crypto_collector.materializer.datasets.quality import (
    QualityEventKind,
    QualityStreamKey,
    QualityWindowRow,
    TimedQualityEvent,
)
from crypto_collector.materializer.models import (
    DiscoveredRawInput,
    SourceLocator,
    SourceRecord,
)
from crypto_collector.materializer.ordering import canonical_replay_order
from crypto_collector.materializer.raw_reader import RawSourceReader
from crypto_collector.materializer.time_policy import EventTimePolicy
from crypto_collector.materializer.windows import Window

_RATIO_CONTEXT = Context(
    prec=36,
    rounding=ROUND_HALF_EVEN,
    Emin=-999_999,
    Emax=999_999,
    capitals=1,
    clamp=0,
    flags=[],
    traps=[],
)
_EXACT_CONTEXT = Context(
    prec=76,
    rounding=ROUND_HALF_EVEN,
    Emin=-999_999,
    Emax=999_999,
    capitals=1,
    clamp=0,
    traps=[Inexact, Rounded],
)
_CAUSAL_FAULT_KINDS = frozenset(
    {
        QualityEventKind.GAP,
        QualityEventKind.RECONNECT,
        QualityEventKind.CHECKSUM_ERROR,
        QualityEventKind.SEQUENCE_ERROR,
    }
)


def _divide(numerator: Decimal, denominator: Decimal) -> Decimal:
    if denominator == 0:
        return Decimal(0)
    with localcontext(_RATIO_CONTEXT) as context:
        context.clear_flags()
        return context.divide(numerator, denominator)


def _exact_operation(
    left: Decimal,
    right: Decimal,
    *,
    operation: str,
) -> Decimal:
    try:
        with localcontext(_EXACT_CONTEXT):
            if operation == "add":
                return left + right
            if operation == "subtract":
                return left - right
            if operation == "multiply":
                return left * right
    except DecimalException as error:
        raise ValueError("book feature arithmetic exceeds decimal(76,36)") from error
    raise AssertionError("unsupported exact decimal operation")


def _add(left: Decimal, right: Decimal) -> Decimal:
    return _exact_operation(left, right, operation="add")


def _subtract(left: Decimal, right: Decimal) -> Decimal:
    return _exact_operation(left, right, operation="subtract")


def _multiply(left: Decimal, right: Decimal) -> Decimal:
    return _exact_operation(left, right, operation="multiply")


def _sum(values: Iterable[Decimal]) -> Decimal:
    total = Decimal(0)
    for value in values:
        total = _add(total, value)
    return total


@dataclass(frozen=True, slots=True)
class BookDepthFeature:
    depth: int
    bid_quantity: Decimal | None
    ask_quantity: Decimal | None
    bid_notional: Decimal | None
    ask_notional: Decimal | None
    imbalance: Decimal | None

    def __post_init__(self) -> None:
        if type(self.depth) is not int or self.depth <= 0:
            raise ValueError("depth must be a positive integer")
        values = (
            self.bid_quantity,
            self.ask_quantity,
            self.bid_notional,
            self.ask_notional,
        )
        if all(value is None for value in values):
            if self.imbalance is not None:
                raise ValueError("invalid depth features cannot claim imbalance")
            return
        if any(value is None for value in values) or any(
            type(value) is not Decimal or not value.is_finite() or value < 0
            for value in values
            if value is not None
        ):
            raise ValueError(
                "depth quantities and notionals must be jointly null or finite decimals"
            )
        if self.imbalance is not None and (
            type(self.imbalance) is not Decimal
            or not self.imbalance.is_finite()
            or not Decimal(-1) <= self.imbalance <= Decimal(1)
        ):
            raise ValueError("imbalance must be a finite decimal in [-1, 1]")


@dataclass(frozen=True, slots=True)
class LiveBookFeatureRow:
    scope: BookScope
    window: Window
    quality: QualityWindowRow
    book_valid: bool
    integrity_mode: IntegrityMode
    gap_reason: BookGapReason | None
    authoritative_source_stream: str | None
    mid: Decimal | None
    spread: Decimal | None
    microprice: Decimal | None
    depths: tuple[BookDepthFeature, ...]
    update_count: int
    heartbeat_count: int
    sequence_reset_count: int
    stale_duration_ns: int | None
    valid_coverage_ratio: Decimal
    authoritative_ancestor: SourceLocator | None
    lineage_manifest_sha256s: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.scope) is not BookScope:
            raise TypeError("scope must be BookScope")
        if type(self.window) is not Window:
            raise TypeError("window must be Window")
        if type(self.quality) is not QualityWindowRow:
            raise TypeError("quality must be QualityWindowRow")
        if self.quality.key != self.scope.quality_key or self.quality.window != self.window:
            raise ValueError("quality row must exactly match book scope and window")
        if type(self.book_valid) is not bool:
            raise TypeError("book_valid must be bool")
        expected_integrity = (
            IntegrityMode.SEQUENCE_VERIFIED if self.book_valid else IntegrityMode.INVALID
        )
        if self.integrity_mode is not expected_integrity:
            raise ValueError("integrity mode must match OKX replay validity")
        if self.book_valid is (self.gap_reason is not None):
            raise ValueError("gap reason must be present exactly when the book is invalid")
        if self.depths != tuple(sorted(self.depths, key=lambda item: item.depth)):
            raise ValueError("depth features must be canonically sorted")
        if len({item.depth for item in self.depths}) != len(self.depths):
            raise ValueError("depth features must be unique")
        for count_name in ("update_count", "heartbeat_count", "sequence_reset_count"):
            count = getattr(self, count_name)
            if type(count) is not int or count < 0:
                raise ValueError(f"{count_name} must be non-negative")
        if self.stale_duration_ns is not None and (
            type(self.stale_duration_ns) is not int or self.stale_duration_ns < 0
        ):
            raise ValueError("stale_duration_ns must be non-negative")
        if (
            type(self.valid_coverage_ratio) is not Decimal
            or not Decimal(0) <= self.valid_coverage_ratio <= Decimal(1)
        ):
            raise ValueError("valid_coverage_ratio must be in [0, 1]")
        if self.lineage_manifest_sha256s != tuple(
            sorted(set(self.lineage_manifest_sha256s))
        ):
            raise ValueError("lineage manifests must be sorted and unique")
        if self.authoritative_ancestor is not None and (
            type(self.authoritative_ancestor) is not SourceLocator
        ):
            raise TypeError("authoritative_ancestor must be SourceLocator or None")

    @property
    def expected(self) -> bool:
        return self.quality.expected

    @property
    def quality_complete(self) -> bool:
        return self.quality.quality_complete

    def depth_at(self, depth: int) -> BookDepthFeature:
        for item in self.depths:
            if item.depth == depth:
                return item
        raise KeyError(depth)


def _scope_from_quality(key: QualityStreamKey) -> BookScope:
    if key.logical_stream != "book_live" or key.market is None or key.instrument_key is None:
        raise ValueError("scope must identify one book_live instrument")
    return BookScope(key.exchange, key.market, key.instrument_key)


def _infer_scope(
    records: tuple[SourceRecord, ...],
    explicit: QualityStreamKey | BookScope | None,
) -> BookScope:
    if explicit is not None:
        if type(explicit) is BookScope:
            result = explicit
        elif type(explicit) is QualityStreamKey:
            result = _scope_from_quality(explicit)
        else:
            raise TypeError("scope must be BookScope, QualityStreamKey, or None")
    elif records:
        envelope = records[0].envelope
        result = BookScope(
            envelope.exchange,
            envelope.market,  # type: ignore[arg-type]
            envelope.instrument_key,  # type: ignore[arg-type]
        )
    else:
        raise ValueError("empty book candidates require an explicit scope")
    if any(
        record.envelope.exchange is not result.exchange
        or record.envelope.market is not result.market
        or record.envelope.instrument_key != result.instrument_key
        for record in records
    ):
        raise ValueError("all book records must match the output scope")
    return result


def _quality_index(
    rows: Iterable[QualityWindowRow],
    *,
    scope: BookScope,
    windows: tuple[Window, ...],
) -> dict[Window, QualityWindowRow]:
    index: dict[Window, QualityWindowRow] = {}
    for row in rows:
        if type(row) is not QualityWindowRow:
            raise TypeError("quality_rows must contain QualityWindowRow values")
        if row.key != scope.quality_key:
            raise ValueError("quality row does not match the book scope")
        if row.window in index:
            raise ValueError("quality rows must be unique by window")
        index[row.window] = row
    if set(index) != set(windows):
        raise ValueError("quality row coverage must exactly match output windows")
    return index


def _depth_feature(
    replayed: ReplayedBook,
    depth: int,
) -> BookDepthFeature:
    if not replayed.book_valid:
        return BookDepthFeature(depth, None, None, None, None, None)
    bids = replayed.bids[:depth]
    asks = replayed.asks[:depth]
    bid_quantity = _sum(quantity for _, quantity in bids)
    ask_quantity = _sum(quantity for _, quantity in asks)
    bid_notional = _sum(_multiply(price, quantity) for price, quantity in bids)
    ask_notional = _sum(_multiply(price, quantity) for price, quantity in asks)
    total = _add(bid_quantity, ask_quantity)
    imbalance = (
        None if total == 0 else _divide(_subtract(bid_quantity, ask_quantity), total)
    )
    return BookDepthFeature(
        depth,
        bid_quantity,
        ask_quantity,
        bid_notional,
        ask_notional,
        imbalance,
    )


def _valid_coverage(replayed: ReplayedBook, window: Window) -> Decimal:
    transitions = sorted(
        enumerate(replayed.validity_transitions),
        key=lambda item: (item[1].effective_event_time_ns, item[0]),
    )
    valid = False
    cursor = window.start_ns
    duration = 0
    for _, transition in transitions:
        timestamp = transition.effective_event_time_ns
        if timestamp <= window.start_ns:
            valid = transition.book_valid
            continue
        if timestamp >= window.end_ns:
            break
        if valid:
            duration += timestamp - cursor
        cursor = timestamp
        valid = transition.book_valid
    if valid:
        duration += window.end_ns - cursor
    return _divide(Decimal(duration), Decimal(window.interval_ns))


def _end_features(
    replayed: ReplayedBook,
) -> tuple[Decimal | None, Decimal | None, Decimal | None]:
    if not replayed.book_valid or not replayed.bids or not replayed.asks:
        return None, None, None
    bid_price, bid_quantity = replayed.bids[0]
    ask_price, ask_quantity = replayed.asks[0]
    mid = _divide(_add(bid_price, ask_price), Decimal(2))
    spread = _subtract(ask_price, bid_price)
    total_quantity = _add(bid_quantity, ask_quantity)
    microprice = (
        None
        if total_quantity == 0
        else _divide(
            _add(
                _multiply(ask_price, bid_quantity),
                _multiply(bid_price, ask_quantity),
            ),
            total_quantity,
        )
    )
    return mid, spread, microprice


def build_live_book_features(
    records: Iterable[SourceRecord],
    *,
    policy: EventTimePolicy,
    windows: Iterable[Window],
    depths: Iterable[int],
    quality_rows: Iterable[QualityWindowRow],
    quality_events: Iterable[TimedQualityEvent] = (),
    scope: QualityStreamKey | BookScope | None = None,
) -> tuple[LiveBookFeatureRow, ...]:
    source_values = tuple(records)
    if any(type(record) is not SourceRecord for record in source_values):
        raise TypeError("records must contain SourceRecord values")
    output_windows = tuple(windows)
    if any(type(window) is not Window for window in output_windows):
        raise TypeError("windows must contain Window values")
    if output_windows != tuple(sorted(output_windows)) or len(output_windows) != len(
        set(output_windows)
    ):
        raise ValueError("windows must be sorted and unique")
    if output_windows and any(
        window.interval_ns != output_windows[0].interval_ns for window in output_windows
    ):
        raise ValueError("output windows must use one interval")
    depth_values = tuple(depths)
    if (
        any(type(depth) is not int or depth <= 0 for depth in depth_values)
        or depth_values != tuple(sorted(set(depth_values)))
    ):
        raise ValueError("depths must be sorted unique positive integers")
    output_scope = _infer_scope(source_values, scope)
    if output_scope.exchange is not Exchange.OKX:
        raise ValueError("Task 4 implements only frozen OKX book evidence")
    qualities = _quality_index(
        quality_rows,
        scope=output_scope,
        windows=output_windows,
    )
    timed = apply_book_time_policy(source_values, policy)
    fault_values = tuple(quality_events)
    if any(type(item) is not TimedQualityEvent for item in fault_values):
        raise TypeError("quality_events must contain TimedQualityEvent values")
    relevant_faults = tuple(
        item
        for item in fault_values
        if item.event.kind in _CAUSAL_FAULT_KINDS
        and output_scope.quality_key in item.event.targets
    )
    timed_by_locator = {item.source.locator: item for item in timed}
    faults_by_locator = {
        item.event.source.locator: item for item in relevant_faults
    }
    causal = canonical_replay_order(
        [item.source for item in timed]
        + [item.event.source for item in relevant_faults]
    )
    rows: list[LiveBookFeatureRow] = []
    for window in output_windows:
        prefix: list[TimedBookRecord] = []
        fault_prefix: list[TimedQualityEvent] = []
        for ordered in causal:
            locator = ordered.source.locator
            timed_item = timed_by_locator.get(locator)
            if timed_item is not None:
                effective_time_ns = timed_item.effective_event_time_ns
            else:
                fault_item = faults_by_locator[locator]
                effective_time_ns = fault_item.effective_event_time_ns
            if effective_time_ns >= window.end_ns:
                break
            if timed_item is not None:
                prefix.append(timed_item)
            else:
                fault_prefix.append(faults_by_locator[locator])
        replayed = OkxBookReplayer().replay(
            prefix,
            quality_events=fault_prefix,
            scope=output_scope,
        )
        mid, spread, microprice = _end_features(replayed)
        quality = qualities[window]
        lineage = set(replayed.lineage_manifest_sha256s)
        lineage.update(quality.lineage_manifest_sha256s)
        rows.append(
            LiveBookFeatureRow(
                scope=output_scope,
                window=window,
                quality=quality,
                book_valid=replayed.book_valid,
                integrity_mode=replayed.integrity_mode,
                gap_reason=replayed.gap_reason,
                authoritative_source_stream=replayed.authoritative_source_stream,
                mid=mid,
                spread=spread,
                microprice=microprice,
                depths=tuple(
                    _depth_feature(replayed, depth) for depth in depth_values
                ),
                update_count=sum(
                    window.start_ns <= value < window.end_ns
                    for value in replayed.accepted_update_times_ns
                ),
                heartbeat_count=sum(
                    window.start_ns <= value < window.end_ns
                    for value in replayed.heartbeat_times_ns
                ),
                sequence_reset_count=sum(
                    window.start_ns <= value < window.end_ns
                    for value in replayed.sequence_reset_times_ns
                ),
                stale_duration_ns=(
                    None
                    if not replayed.book_valid
                    or replayed.last_book_update_time_ns is None
                    else max(0, window.end_ns - replayed.last_book_update_time_ns)
                ),
                valid_coverage_ratio=_valid_coverage(replayed, window),
                authoritative_ancestor=replayed.authoritative_ancestor,
                lineage_manifest_sha256s=tuple(sorted(lineage)),
            )
        )
    return tuple(rows)


def select_hourly_live_records(
    records: Iterable[SourceRecord],
    *,
    policy: EventTimePolicy,
    hour_start_ns: int,
    hour_end_ns: int,
) -> tuple[SourceRecord, ...]:
    if type(hour_start_ns) is not int or type(hour_end_ns) is not int:
        raise TypeError("hour bounds must be integers")
    if hour_start_ns < 0 or hour_end_ns - hour_start_ns != 3_600_000_000_000:
        raise ValueError("hour bounds must describe one non-negative UTC hour")
    source_values = tuple(records)
    if any(type(record) is not SourceRecord for record in source_values):
        raise TypeError("records must contain SourceRecord values")
    live = tuple(
        record
        for record in source_values
        if record.envelope.logical_stream in {"book_live", "book_live_bootstrap"}
    )
    timed = apply_book_time_policy(live, policy)
    timed_by_locator = {item.source.locator: item for item in timed}
    causal = canonical_replay_order(item.source for item in timed)
    authority_index: int | None = None
    for index, ordered in enumerate(causal):
        item = timed_by_locator[ordered.source.locator]
        if (
            item.effective_event_time_ns < hour_start_ns
            and is_okx_authoritative_snapshot(item)
        ):
            authority_index = index
    selected: list[SourceRecord] = []
    for index, ordered in enumerate(causal):
        if authority_index is not None and index < authority_index:
            continue
        item = timed_by_locator[ordered.source.locator]
        if item.effective_event_time_ns >= hour_end_ns:
            break
        if authority_index is not None or item.effective_event_time_ns >= hour_start_ns:
            selected.append(item.source)
    return tuple(selected)


def read_live_book_records(
    inputs: Iterable[DiscoveredRawInput],
) -> tuple[SourceRecord, ...]:
    discovered = tuple(inputs)
    if any(type(item) is not DiscoveredRawInput for item in discovered):
        raise TypeError("inputs must contain DiscoveredRawInput values")
    if discovered != tuple(
        sorted(discovered, key=lambda item: item.manifest_sha256)
    ):
        raise ValueError("discovered inputs must use canonical manifest order")
    records: list[SourceRecord] = []
    for item in discovered:
        if item.manifest.logical_stream not in {"book_live", "book_live_bootstrap"}:
            continue
        with RawSourceReader(item) as reader:
            records.extend(reader)
            if not reader.validated_complete:
                raise RuntimeError("raw live-book source was not completely validated")
    return tuple(records)


def build_live_book_features_for_hour(
    inputs: Iterable[DiscoveredRawInput],
    *,
    policy: EventTimePolicy,
    hour_start_ns: int,
    interval_ns: int,
    depths: Iterable[int],
    quality_rows: Iterable[QualityWindowRow],
    quality_events: Iterable[TimedQualityEvent] = (),
    scope: QualityStreamKey | BookScope | None = None,
) -> tuple[LiveBookFeatureRow, ...]:
    hour_end_ns = hour_start_ns + 3_600_000_000_000
    selected = select_hourly_live_records(
        read_live_book_records(inputs),
        policy=policy,
        hour_start_ns=hour_start_ns,
        hour_end_ns=hour_end_ns,
    )
    windows = tuple(
        Window(start, start + interval_ns)
        for start in range(hour_start_ns, hour_end_ns, interval_ns)
    )
    return build_live_book_features(
        selected,
        policy=policy,
        windows=windows,
        depths=depths,
        quality_rows=quality_rows,
        quality_events=quality_events,
        scope=scope,
    )


__all__ = [
    "BookDepthFeature",
    "LiveBookFeatureRow",
    "build_live_book_features",
    "build_live_book_features_for_hour",
    "read_live_book_records",
    "select_hourly_live_records",
]
