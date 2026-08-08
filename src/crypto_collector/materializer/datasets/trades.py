from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    Inexact,
    InvalidOperation,
    Rounded,
    localcontext,
)
from enum import StrEnum
from itertools import pairwise
from typing import Any, Protocol

from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.materializer.models import (
    DerivedSourceLocator,
    SourceRecord,
    TimeSource,
)
from crypto_collector.materializer.time_policy import EventTimePolicy
from crypto_collector.materializer.windows import Window

_MAX_SIGNED_INT64 = 2**63 - 1
_INPUT_MAX_PRECISION = 38
_INPUT_MAX_SCALE = 18
_AGGREGATE_MAX_PRECISION = 76
_AGGREGATE_MAX_SCALE = 36
_VWAP_SCALE = 36
_FIXED_POSITIVE_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$")
_DIGITS = re.compile(r"^[0-9]+$")
_OKX_EXACT_TRADE_NAMESPACE = "okx_public_trade"
_OKX_AGGREGATED_TRADE_NAMESPACE = "okx_public_trade_aggregate"
_OKX_REST_TRADE_PATHS = frozenset(
    {"/api/v5/market/trades", "/api/v5/market/history-trades"}
)
_EXACT_DECIMAL_CONTEXT = Context(
    prec=_AGGREGATE_MAX_PRECISION,
    rounding=ROUND_HALF_EVEN,
    Emin=-999_999,
    Emax=999_999,
    capitals=1,
    clamp=0,
    traps=[Inexact, Rounded],
)


class AggressorSide(StrEnum):
    BUY = "buy"
    SELL = "sell"
    UNKNOWN = "unknown"


class TradeRepresentation(StrEnum):
    EXACT = "exact"
    AGGREGATED = "aggregated"


class DeduplicationMode(StrEnum):
    STABLE_ID = "stable_id"
    UNAVAILABLE = "unavailable"
    MIXED = "mixed"


class TradeNormalizer(Protocol):
    def normalize(self, source: SourceRecord) -> tuple[NormalizedTrade, ...]: ...


def _nonnegative_int64(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < 0 or value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must be a non-negative signed 64-bit integer")
    return value


def _positive_string(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    if not value:
        raise ValueError(f"{field_name} must be non-empty")
    return value


def _sha256(value: object, *, field_name: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


def _decimal_shape(value: Decimal) -> tuple[int, int]:
    if not value.is_finite():
        raise ValueError("Decimal value must be finite")
    _, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):
        raise TypeError("Decimal exponent must be an integer")
    precision = len(digits) + max(exponent, 0)
    scale = max(-exponent, 0)
    return precision, scale


def _validate_decimal(
    value: object,
    *,
    field_name: str,
    max_precision: int,
    max_scale: int,
    positive: bool,
) -> Decimal:
    if type(value) is not Decimal:
        raise TypeError(f"{field_name} must be Decimal")
    if not value.is_finite():
        raise ValueError(f"{field_name} must be finite")
    if positive and value <= 0:
        raise ValueError(f"{field_name} must be positive")
    precision, scale = _decimal_shape(value)
    integer_digits = 0 if value.is_zero() else max(value.adjusted() + 1, 0)
    if (
        precision > max_precision
        or scale > max_scale
        or integer_digits > max_precision - max_scale
    ):
        raise ValueError(
            f"{field_name} exceeds decimal({max_precision},{max_scale}) bounds"
        )
    return value


def _parse_input_decimal(value: object, *, field_name: str) -> Decimal:
    text = _positive_string(value, field_name=field_name)
    if _FIXED_POSITIVE_DECIMAL.fullmatch(text) is None:
        raise ValueError(f"{field_name} must be a fixed-point decimal string")
    try:
        parsed = Decimal(text)
    except InvalidOperation as error:
        raise ValueError(f"{field_name} is not a valid decimal") from error
    return _validate_decimal(
        parsed,
        field_name=field_name,
        max_precision=_INPUT_MAX_PRECISION,
        max_scale=_INPUT_MAX_SCALE,
        positive=True,
    )


def _exact_operation(
    left: Decimal,
    right: Decimal,
    *,
    operation: str,
    field_name: str,
) -> Decimal:
    try:
        with localcontext(_EXACT_DECIMAL_CONTEXT):
            if operation == "add":
                result = left + right
            elif operation == "multiply":
                result = left * right
            else:  # pragma: no cover - private call sites are closed over literals
                raise AssertionError("unsupported decimal operation")
    except DecimalException as error:
        raise ValueError(
            f"{field_name} exceeds exact decimal aggregation bounds"
        ) from error
    return _validate_decimal(
        result,
        field_name=field_name,
        max_precision=_AGGREGATE_MAX_PRECISION,
        max_scale=_AGGREGATE_MAX_SCALE,
        positive=False,
    )


def _exact_add(left: Decimal, right: Decimal, *, field_name: str) -> Decimal:
    return _exact_operation(left, right, operation="add", field_name=field_name)


def _exact_multiply(left: Decimal, right: Decimal, *, field_name: str) -> Decimal:
    return _exact_operation(left, right, operation="multiply", field_name=field_name)


def _decimal_fraction(value: Decimal) -> tuple[int, int]:
    sign, digits, exponent = value.as_tuple()
    if not isinstance(exponent, int):
        raise TypeError("Decimal exponent must be an integer")
    coefficient = 0
    for digit in digits:
        coefficient = coefficient * 10 + digit
    if sign:
        coefficient = -coefficient
    if exponent >= 0:
        return coefficient * 10**exponent, 1
    return coefficient, 10 ** (-exponent)


def _round_ratio_half_even(
    numerator: Decimal,
    denominator: Decimal,
    *,
    scale: int,
    field_name: str,
) -> Decimal:
    if denominator <= 0:
        raise ValueError(f"{field_name} denominator must be positive")
    numerator_coefficient, numerator_denominator = _decimal_fraction(numerator)
    denominator_coefficient, denominator_denominator = _decimal_fraction(denominator)
    scaled_numerator = numerator_coefficient * denominator_denominator * 10**scale
    scaled_denominator = numerator_denominator * denominator_coefficient
    quotient, remainder = divmod(abs(scaled_numerator), scaled_denominator)
    doubled_remainder = remainder * 2
    if doubled_remainder > scaled_denominator or (
        doubled_remainder == scaled_denominator and quotient % 2 == 1
    ):
        quotient += 1
    if scaled_numerator < 0:
        quotient = -quotient
    digits = tuple(int(character) for character in str(abs(quotient)))
    result = Decimal((1 if quotient < 0 else 0, digits, -scale))
    return _validate_decimal(
        result,
        field_name=field_name,
        max_precision=_AGGREGATE_MAX_PRECISION,
        max_scale=_AGGREGATE_MAX_SCALE,
        positive=False,
    )


def canonical_decimal(value: Decimal) -> str:
    _validate_decimal(
        value,
        field_name="value",
        max_precision=_AGGREGATE_MAX_PRECISION,
        max_scale=_AGGREGATE_MAX_SCALE,
        positive=False,
    )
    if value.is_zero():
        return "0"
    text = format(value, "f")
    if "." in text:
        text = text.rstrip("0").rstrip(".")
    return text


@dataclass(frozen=True, slots=True, order=True)
class TradeScope:
    exchange: Exchange
    market: Market
    instrument_key: str

    def __post_init__(self) -> None:
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        if type(self.market) is not Market:
            raise TypeError("market must be Market")
        _positive_string(self.instrument_key, field_name="instrument_key")


@dataclass(frozen=True, slots=True, order=True)
class CandidateCoverage:
    """Caller assertion that all dedup candidates in this time range were supplied."""

    start_ns: int
    end_ns: int

    def __post_init__(self) -> None:
        start = _nonnegative_int64(self.start_ns, field_name="start_ns")
        end = _nonnegative_int64(self.end_ns, field_name="end_ns")
        if end <= start:
            raise ValueError("candidate coverage end_ns must exceed start_ns")


@dataclass(frozen=True, slots=True)
class OkxLinearContractMetadata:
    source_manifest_sha256: str
    instrument_key: str
    valid_from_ns: int
    valid_to_ns: int | None
    base_asset: str
    quote_asset: str
    contract_type: str
    settle_currency: str
    contract_value: Decimal
    contract_value_currency: str
    contract_multiplier: Decimal

    def __post_init__(self) -> None:
        _sha256(
            self.source_manifest_sha256,
            field_name="source_manifest_sha256",
        )
        _positive_string(self.instrument_key, field_name="instrument_key")
        _nonnegative_int64(self.valid_from_ns, field_name="valid_from_ns")
        if self.valid_to_ns is not None:
            end = _nonnegative_int64(self.valid_to_ns, field_name="valid_to_ns")
            if end <= self.valid_from_ns:
                raise ValueError("metadata valid_to_ns must exceed valid_from_ns")
        for field_name in (
            "base_asset",
            "quote_asset",
            "contract_type",
            "settle_currency",
            "contract_value_currency",
        ):
            _positive_string(getattr(self, field_name), field_name=field_name)
        _validate_decimal(
            self.contract_value,
            field_name="contract_value",
            max_precision=_INPUT_MAX_PRECISION,
            max_scale=_INPUT_MAX_SCALE,
            positive=True,
        )
        _validate_decimal(
            self.contract_multiplier,
            field_name="contract_multiplier",
            max_precision=_INPUT_MAX_PRECISION,
            max_scale=_INPUT_MAX_SCALE,
            positive=True,
        )

    def applies_at(self, timestamp_ns: int) -> bool:
        return self.valid_from_ns <= timestamp_ns and (
            self.valid_to_ns is None or timestamp_ns < self.valid_to_ns
        )


@dataclass(frozen=True, slots=True)
class NormalizedTrade:
    source: SourceRecord
    locator: DerivedSourceLocator
    scope: TradeScope
    native_event_time_ns: int | None
    stable_trade_id: str | None
    trade_id_namespace: str | None
    price: Decimal
    base_quantity: Decimal
    quote_quantity: Decimal | None
    contract_quantity: Decimal | None
    aggressor_side: AggressorSide
    match_count: int
    representation: TradeRepresentation
    venue_source: str
    lineage_manifest_sha256s: tuple[str, ...]
    venue_sequence: int | None = None

    def __post_init__(self) -> None:
        if type(self.source) is not SourceRecord:
            raise TypeError("source must be SourceRecord")
        if type(self.locator) is not DerivedSourceLocator:
            raise TypeError("locator must be DerivedSourceLocator")
        if self.locator.source != self.source.locator:
            raise ValueError("derived locator must be a child of source locator")
        if type(self.scope) is not TradeScope:
            raise TypeError("scope must be TradeScope")
        envelope = self.source.envelope
        expected_scope = TradeScope(
            envelope.exchange,
            envelope.market,  # type: ignore[arg-type]
            envelope.instrument_key,  # type: ignore[arg-type]
        )
        if self.scope != expected_scope:
            raise ValueError("trade scope must match source envelope")
        if self.native_event_time_ns is not None:
            _nonnegative_int64(
                self.native_event_time_ns,
                field_name="native_event_time_ns",
            )
        if (self.stable_trade_id is None) != (self.trade_id_namespace is None):
            raise ValueError("stable trade ID and namespace must be paired")
        if self.stable_trade_id is not None:
            _positive_string(self.stable_trade_id, field_name="stable_trade_id")
            _positive_string(self.trade_id_namespace, field_name="trade_id_namespace")
        _validate_decimal(
            self.price,
            field_name="price",
            max_precision=_INPUT_MAX_PRECISION,
            max_scale=_INPUT_MAX_SCALE,
            positive=True,
        )
        _validate_decimal(
            self.base_quantity,
            field_name="base_quantity",
            max_precision=_AGGREGATE_MAX_PRECISION,
            max_scale=_AGGREGATE_MAX_SCALE,
            positive=True,
        )
        if self.quote_quantity is not None:
            _validate_decimal(
                self.quote_quantity,
                field_name="quote_quantity",
                max_precision=_AGGREGATE_MAX_PRECISION,
                max_scale=_AGGREGATE_MAX_SCALE,
                positive=True,
            )
        if self.contract_quantity is not None:
            _validate_decimal(
                self.contract_quantity,
                field_name="contract_quantity",
                max_precision=_INPUT_MAX_PRECISION,
                max_scale=_INPUT_MAX_SCALE,
                positive=True,
            )
        if type(self.aggressor_side) is not AggressorSide:
            raise TypeError("aggressor_side must be AggressorSide")
        if (
            type(self.match_count) is not int
            or self.match_count <= 0
            or self.match_count > _MAX_SIGNED_INT64
        ):
            raise ValueError("match_count must be a positive signed 64-bit integer")
        if type(self.representation) is not TradeRepresentation:
            raise TypeError("representation must be TradeRepresentation")
        if self.representation is TradeRepresentation.EXACT and self.match_count != 1:
            raise ValueError("exact trades must represent exactly one match")
        if self.representation is TradeRepresentation.AGGREGATED and (
            self.stable_trade_id is None
            or _DIGITS.fullmatch(self.stable_trade_id) is None
            or int(self.stable_trade_id) < self.match_count - 1
        ):
            raise ValueError(
                "aggregated trades require a valid numeric last trade ID range"
            )
        _positive_string(self.venue_source, field_name="venue_source")
        if not self.lineage_manifest_sha256s or self.lineage_manifest_sha256s != tuple(
            sorted(set(self.lineage_manifest_sha256s))
        ):
            raise ValueError("trade lineage manifests must be sorted and unique")
        for manifest_sha256 in self.lineage_manifest_sha256s:
            _sha256(manifest_sha256, field_name="lineage_manifest_sha256s")
        if self.source.locator.manifest_sha256 not in self.lineage_manifest_sha256s:
            raise ValueError("trade lineage must include its raw source manifest")
        if self.venue_sequence is not None:
            _nonnegative_int64(self.venue_sequence, field_name="venue_sequence")


@dataclass(frozen=True, slots=True)
class TimedTrade:
    trade: NormalizedTrade
    effective_event_time_ns: int
    time_source: TimeSource

    def __post_init__(self) -> None:
        if type(self.trade) is not NormalizedTrade:
            raise TypeError("trade must be NormalizedTrade")
        effective = _nonnegative_int64(
            self.effective_event_time_ns,
            field_name="effective_event_time_ns",
        )
        if type(self.time_source) is not TimeSource:
            raise TypeError("time_source must be TimeSource")
        native = self.trade.native_event_time_ns
        received = self.trade.source.envelope.received_at_ns
        if self.time_source is TimeSource.EVENT:
            consistent = native is not None and effective == native
        elif self.time_source is TimeSource.RECEIVE_MISSING:
            consistent = native is None and effective == received
        else:
            consistent = (
                native is not None and native != received and effective == received
            )
        if not consistent:
            raise ValueError("time source must match item and effective event time")

    @property
    def locator(self) -> DerivedSourceLocator:
        return self.trade.locator


@dataclass(frozen=True, slots=True)
class TradeCandidateSet:
    """Candidates spanning the caller-proven cross-window deduplication domain."""

    scope: TradeScope
    coverage: CandidateCoverage
    trades: tuple[TimedTrade, ...]

    def __post_init__(self) -> None:
        if type(self.scope) is not TradeScope:
            raise TypeError("scope must be TradeScope")
        if type(self.coverage) is not CandidateCoverage:
            raise TypeError("coverage must be CandidateCoverage")
        if any(type(trade) is not TimedTrade for trade in self.trades):
            raise TypeError("trades must contain TimedTrade values")
        if any(trade.trade.scope != self.scope for trade in self.trades):
            raise ValueError("all trade candidates must match candidate-set scope")
        if any(
            not self.coverage.start_ns
            <= trade.effective_event_time_ns
            < self.coverage.end_ns
            for trade in self.trades
        ):
            raise ValueError("all trade candidates must fall inside declared coverage")
        representations = {trade.trade.representation for trade in self.trades}
        if len(representations) > 1:
            raise ValueError(
                "exact and aggregated trade representations cannot be mixed"
            )
        locators = tuple(trade.locator for trade in self.trades)
        if len(locators) != len(set(locators)):
            raise ValueError(
                "trade candidates must have unique derived source locators"
            )
        if representations == {TradeRepresentation.AGGREGATED}:
            _reject_partial_aggregate_range_overlaps(self.trades)


@dataclass(frozen=True, slots=True)
class TradeBar:
    scope: TradeScope
    window: Window
    open: Decimal | None
    high: Decimal | None
    low: Decimal | None
    close: Decimal | None
    vwap: Decimal | None
    base_volume: Decimal
    quote_volume: Decimal
    buy_base_volume: Decimal
    sell_base_volume: Decimal
    unknown_base_volume: Decimal
    signed_base_volume: Decimal
    trade_count: int
    normalized_record_count: int
    aggregated_record_count: int
    duplicate_input_count: int
    duplicate_match_count: int
    first_effective_trade_time_ns: int | None
    last_effective_trade_time_ns: int | None
    event_time_count: int
    receive_missing_count: int
    receive_outlier_count: int
    event_time_ratio: Decimal | None
    deduplication_mode: DeduplicationMode | None
    lineage_manifest_sha256s: tuple[str, ...]
    first_source_locator: DerivedSourceLocator | None
    last_source_locator: DerivedSourceLocator | None

    def __post_init__(self) -> None:
        if type(self.scope) is not TradeScope:
            raise TypeError("scope must be TradeScope")
        if type(self.window) is not Window:
            raise TypeError("window must be Window")

        count_fields = (
            "trade_count",
            "normalized_record_count",
            "aggregated_record_count",
            "duplicate_input_count",
            "duplicate_match_count",
            "event_time_count",
            "receive_missing_count",
            "receive_outlier_count",
        )
        for field_name in count_fields:
            _nonnegative_int64(getattr(self, field_name), field_name=field_name)
        if self.aggregated_record_count not in (0, self.normalized_record_count):
            raise ValueError(
                "aggregated_record_count must be zero or normalized_record_count"
            )
        if self.trade_count < self.normalized_record_count:
            raise ValueError("trade_count cannot be less than normalized_record_count")
        if self.aggregated_record_count == 0 and (
            self.trade_count != self.normalized_record_count
        ):
            raise ValueError("exact trade_count must equal normalized_record_count")
        if self.duplicate_match_count < self.duplicate_input_count:
            raise ValueError(
                "duplicate_match_count cannot be less than duplicate_input_count"
            )
        if self.aggregated_record_count == 0 and (
            self.duplicate_match_count != self.duplicate_input_count
        ):
            raise ValueError(
                "exact duplicate match count must equal duplicate input count"
            )
        if (
            self.event_time_count
            + self.receive_missing_count
            + self.receive_outlier_count
            != self.normalized_record_count
        ):
            raise ValueError("time-source counts must equal normalized_record_count")

        volume_fields = (
            "base_volume",
            "quote_volume",
            "buy_base_volume",
            "sell_base_volume",
            "unknown_base_volume",
        )
        for field_name in volume_fields:
            value = _validate_decimal(
                getattr(self, field_name),
                field_name=field_name,
                max_precision=_AGGREGATE_MAX_PRECISION,
                max_scale=_AGGREGATE_MAX_SCALE,
                positive=False,
            )
            if value < 0:
                raise ValueError(f"{field_name} must be non-negative")
        _validate_decimal(
            self.signed_base_volume,
            field_name="signed_base_volume",
            max_precision=_AGGREGATE_MAX_PRECISION,
            max_scale=_AGGREGATE_MAX_SCALE,
            positive=False,
        )
        side_total = _exact_add(
            _exact_add(
                self.buy_base_volume,
                self.sell_base_volume,
                field_name="base_volume",
            ),
            self.unknown_base_volume,
            field_name="base_volume",
        )
        if self.base_volume != side_total:
            raise ValueError("base_volume must equal side-attributed volume")
        expected_signed = _exact_add(
            self.buy_base_volume,
            self.sell_base_volume.copy_negate(),
            field_name="signed_base_volume",
        )
        if self.signed_base_volume != expected_signed:
            raise ValueError("signed_base_volume must equal buy minus sell volume")

        if self.normalized_record_count == 0:
            self._validate_empty()
            return
        self._validate_nonempty()

    def _validate_empty(self) -> None:
        if any(
            value is not None
            for value in (self.open, self.high, self.low, self.close, self.vwap)
        ):
            raise ValueError("empty trade bars require null price fields")
        if any(
            value != 0
            for value in (
                self.base_volume,
                self.quote_volume,
                self.buy_base_volume,
                self.sell_base_volume,
                self.unknown_base_volume,
                self.signed_base_volume,
            )
        ):
            raise ValueError("empty trade bars require zero volumes")
        if any(
            value != 0
            for value in (
                self.trade_count,
                self.aggregated_record_count,
                self.duplicate_input_count,
                self.duplicate_match_count,
            )
        ):
            raise ValueError("empty trade bars require zero activity counts")
        if any(
            value is not None
            for value in (
                self.first_effective_trade_time_ns,
                self.last_effective_trade_time_ns,
                self.event_time_ratio,
                self.deduplication_mode,
                self.first_source_locator,
                self.last_source_locator,
            )
        ):
            raise ValueError("empty trade bars require null event metadata")
        if self.lineage_manifest_sha256s != ():
            raise ValueError("empty trade bars require empty lineage")

    def _validate_nonempty(self) -> None:
        prices = (self.open, self.high, self.low, self.close)
        if any(value is None for value in prices):
            raise ValueError("non-empty trade bars require OHLC prices")
        for field_name, value in zip(("open", "high", "low", "close"), prices):
            _validate_decimal(
                value,
                field_name=field_name,
                max_precision=_INPUT_MAX_PRECISION,
                max_scale=_INPUT_MAX_SCALE,
                positive=True,
            )
        assert self.open is not None
        assert self.high is not None
        assert self.low is not None
        assert self.close is not None
        if (
            not self.low
            <= min(self.open, self.close)
            <= max(self.open, self.close)
            <= self.high
        ):
            raise ValueError("OHLC price bounds are inconsistent")
        _validate_decimal(
            self.vwap,
            field_name="vwap",
            max_precision=_AGGREGATE_MAX_PRECISION,
            max_scale=_AGGREGATE_MAX_SCALE,
            positive=True,
        )
        if self.base_volume <= 0 or self.quote_volume <= 0:
            raise ValueError("non-empty trade bars require positive total volumes")
        expected_vwap = _round_ratio_half_even(
            self.quote_volume,
            self.base_volume,
            scale=_VWAP_SCALE,
            field_name="vwap",
        )
        if self.vwap != expected_vwap:
            raise ValueError("VWAP must match quote_volume / base_volume")
        if not self.low <= self.vwap <= self.high:
            raise ValueError("VWAP must fall inside the OHLC price range")

        if self.first_effective_trade_time_ns is None:
            raise ValueError("non-empty trade bars require first trade time")
        if self.last_effective_trade_time_ns is None:
            raise ValueError("non-empty trade bars require last trade time")
        first_time = _nonnegative_int64(
            self.first_effective_trade_time_ns,
            field_name="first_effective_trade_time_ns",
        )
        last_time = _nonnegative_int64(
            self.last_effective_trade_time_ns,
            field_name="last_effective_trade_time_ns",
        )
        if not (self.window.start_ns <= first_time <= last_time < self.window.end_ns):
            raise ValueError("trade times must be ordered inside the output window")

        if type(self.event_time_ratio) is not Decimal:
            raise TypeError("non-empty trade bars require Decimal event_time_ratio")
        expected_ratio = _round_ratio_half_even(
            Decimal(self.event_time_count),
            Decimal(self.normalized_record_count),
            scale=_VWAP_SCALE,
            field_name="event_time_ratio",
        )
        if self.event_time_ratio != expected_ratio:
            raise ValueError("event_time_ratio must match its counts")
        if type(self.deduplication_mode) is not DeduplicationMode:
            raise TypeError("non-empty trade bars require a deduplication mode")
        if (
            self.aggregated_record_count != 0
            and self.deduplication_mode is not DeduplicationMode.STABLE_ID
        ):
            raise ValueError("aggregated bars require stable-ID deduplication")
        if (
            self.deduplication_mode is DeduplicationMode.UNAVAILABLE
            and self.duplicate_input_count != 0
        ):
            raise ValueError("unavailable deduplication cannot report duplicates")

        if (
            type(self.lineage_manifest_sha256s) is not tuple
            or not self.lineage_manifest_sha256s
            or self.lineage_manifest_sha256s
            != tuple(sorted(set(self.lineage_manifest_sha256s)))
        ):
            raise ValueError("non-empty trade lineage must be sorted and unique")
        for manifest_sha256 in self.lineage_manifest_sha256s:
            _sha256(manifest_sha256, field_name="lineage_manifest_sha256s")
        if (
            type(self.first_source_locator) is not DerivedSourceLocator
            or type(self.last_source_locator) is not DerivedSourceLocator
        ):
            raise TypeError("non-empty trade bars require source locators")
        if (
            self.first_source_locator.source.manifest_sha256
            not in self.lineage_manifest_sha256s
            or self.last_source_locator.source.manifest_sha256
            not in self.lineage_manifest_sha256s
        ):
            raise ValueError("source locator manifests must be present in lineage")
        if self.normalized_record_count == 1:
            if len({self.open, self.high, self.low, self.close}) != 1:
                raise ValueError("single-record OHLC prices must be identical")
            if (
                first_time != last_time
                or self.first_source_locator != self.last_source_locator
            ):
                raise ValueError("single-record endpoints must be identical")
            if self.deduplication_mode is DeduplicationMode.MIXED:
                raise ValueError("single-record deduplication mode cannot be mixed")

    def to_canonical_dict(self) -> dict[str, Any]:
        decimal_fields = (
            "open",
            "high",
            "low",
            "close",
            "vwap",
            "base_volume",
            "quote_volume",
            "buy_base_volume",
            "sell_base_volume",
            "unknown_base_volume",
            "signed_base_volume",
            "event_time_ratio",
        )
        result: dict[str, Any] = {
            "exchange": self.scope.exchange.value,
            "market": self.scope.market.value,
            "instrument_key": self.scope.instrument_key,
            "window_start_ns": self.window.start_ns,
            "window_end_ns": self.window.end_ns,
        }
        for field_name in decimal_fields:
            value = getattr(self, field_name)
            result[field_name] = None if value is None else canonical_decimal(value)
        result.update(
            trade_count=self.trade_count,
            normalized_record_count=self.normalized_record_count,
            aggregated_record_count=self.aggregated_record_count,
            duplicate_input_count=self.duplicate_input_count,
            duplicate_match_count=self.duplicate_match_count,
            first_effective_trade_time_ns=self.first_effective_trade_time_ns,
            last_effective_trade_time_ns=self.last_effective_trade_time_ns,
            event_time_count=self.event_time_count,
            receive_missing_count=self.receive_missing_count,
            receive_outlier_count=self.receive_outlier_count,
            first_source_locator=_canonical_locator(self.first_source_locator),
            last_source_locator=_canonical_locator(self.last_source_locator),
            deduplication_mode=(
                None
                if self.deduplication_mode is None
                else self.deduplication_mode.value
            ),
            lineage_manifest_sha256s=list(self.lineage_manifest_sha256s),
        )
        return result


def _canonical_locator(
    locator: DerivedSourceLocator | None,
) -> dict[str, object] | None:
    if locator is None:
        return None
    return {
        "manifest_sha256": locator.source.manifest_sha256,
        "zero_based_record_index": locator.source.zero_based_record_index,
        "item_ordinal": locator.item_ordinal,
    }


def _mapping(value: object, *, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{field_name} must be an object")
    if any(type(key) is not str for key in value):
        raise TypeError(f"{field_name} keys must be strings")
    return value


def _list(value: object, *, field_name: str) -> list[object]:
    if type(value) is not list:
        raise TypeError(f"{field_name} must be an array")
    return value


def _okx_items(
    source: SourceRecord,
    *,
    aggregated_equivalence_verified: bool,
) -> tuple[list[object], bool]:
    envelope = source.envelope
    if envelope.exchange is not Exchange.OKX:
        raise ValueError("OKX normalizer requires an OKX source")
    if envelope.logical_stream != "trade":
        raise ValueError("OKX trade normalizer requires logical_stream=trade")
    if envelope.market not in (Market.SPOT, Market.PERPETUAL):
        raise ValueError("OKX trade source market must be spot or perpetual")
    instrument_key = _positive_string(
        envelope.instrument_key,
        field_name="envelope.instrument_key",
    )
    if envelope.wire_symbol != instrument_key:
        raise ValueError("OKX wire symbol must match instrument key")
    payload = _mapping(envelope.payload, field_name="payload")

    if envelope.transport is Transport.WEBSOCKET:
        channel = _positive_string(
            envelope.native_channel,
            field_name="native_channel",
        )
        if channel not in {"trades-all", "trades"}:
            raise ValueError("unsupported OKX trade WebSocket channel")
        aggregated = channel == "trades"
        if aggregated and not aggregated_equivalence_verified:
            raise ValueError(
                "aggregated OKX trades require verified exact-feed equivalence"
            )
        arg = _mapping(payload.get("arg"), field_name="payload.arg")
        if arg.get("channel") != channel:
            raise ValueError("OKX payload channel does not match envelope")
        if arg.get("instId") != instrument_key:
            raise ValueError("OKX payload instrument does not match envelope")
        items = _list(payload.get("data"), field_name="payload.data")
        if not aggregated and len(items) != 1:
            raise ValueError("OKX trades-all update must contain exactly one trade")
        if aggregated and not items:
            raise ValueError("OKX trades update must contain at least one trade")
        return items, aggregated

    if envelope.transport is Transport.REST:
        metadata = envelope.rest_metadata
        if metadata is None:
            raise ValueError("OKX REST trade source requires request metadata")
        if metadata.method != "GET" or metadata.path not in _OKX_REST_TRADE_PATHS:
            raise ValueError("unsupported OKX REST trade request")
        if envelope.native_channel != metadata.path:
            raise ValueError("OKX REST native channel must match request path")
        if not 200 <= metadata.status < 300:
            raise ValueError("OKX REST trade request was not successful")
        if metadata.params.get("instId") != instrument_key:
            raise ValueError("OKX REST request instrument does not match envelope")
        if payload.get("code") != "0" or type(payload.get("msg")) is not str:
            raise ValueError("OKX REST payload is not a successful response")
        return _list(payload.get("data"), field_name="payload.data"), False

    raise ValueError("OKX trade source must use REST or WebSocket transport")


def _parse_okx_timestamp(value: object) -> int:
    text = _positive_string(value, field_name="ts")
    if _DIGITS.fullmatch(text) is None:
        raise ValueError("ts must be a millisecond integer string")
    timestamp_ms = int(text)
    if timestamp_ms > _MAX_SIGNED_INT64 // 1_000_000:
        raise ValueError("ts nanoseconds must fit a signed 64-bit integer")
    return timestamp_ms * 1_000_000


def _okx_side(value: object) -> AggressorSide:
    text = _positive_string(value, field_name="side")
    if text == "buy":
        return AggressorSide.BUY
    if text == "sell":
        return AggressorSide.SELL
    return AggressorSide.UNKNOWN


def _select_okx_contract_metadata(
    metadata: Sequence[OkxLinearContractMetadata],
    *,
    instrument_key: str,
    native_event_time_ns: int,
) -> OkxLinearContractMetadata:
    matches = tuple(
        item
        for item in metadata
        if item.instrument_key == instrument_key
        and item.applies_at(native_event_time_ns)
    )
    if len(matches) != 1:
        raise ValueError(
            "exactly one effective OKX contract metadata record is required"
        )
    item = matches[0]
    if (
        item.contract_type != "linear"
        or item.instrument_key != f"{item.base_asset}-{item.quote_asset}-SWAP"
        or item.quote_asset != "USDT"
        or item.settle_currency != item.quote_asset
        or item.contract_value_currency != item.base_asset
        or item.contract_multiplier != Decimal(1)
    ):
        raise ValueError("OKX contract metadata does not prove linear USDT conversion")
    return item


def normalize_okx_trade_items(
    source: SourceRecord,
    *,
    contract_metadata: Sequence[OkxLinearContractMetadata] = (),
    aggregated_equivalence_verified: bool = False,
) -> tuple[NormalizedTrade, ...]:
    """Expand one OKX raw payload in native array order without choosing time."""

    if type(source) is not SourceRecord:
        raise TypeError("source must be SourceRecord")
    if type(aggregated_equivalence_verified) is not bool:
        raise TypeError("aggregated_equivalence_verified must be bool")
    items, aggregated = _okx_items(
        source,
        aggregated_equivalence_verified=aggregated_equivalence_verified,
    )
    envelope = source.envelope
    assert envelope.market is not None
    assert envelope.instrument_key is not None
    scope = TradeScope(envelope.exchange, envelope.market, envelope.instrument_key)
    normalized: list[NormalizedTrade] = []
    for item_ordinal, raw_item in enumerate(items):
        item = _mapping(raw_item, field_name=f"payload.data[{item_ordinal}]")
        if item.get("instId") != envelope.wire_symbol:
            raise ValueError("OKX trade item instrument does not match envelope")
        trade_id = _positive_string(item.get("tradeId"), field_name="tradeId")
        price = _parse_input_decimal(item.get("px"), field_name="px")
        raw_size = _parse_input_decimal(item.get("sz"), field_name="sz")
        native_time_ns = _parse_okx_timestamp(item.get("ts"))
        if (
            envelope.transport is Transport.WEBSOCKET
            and envelope.native_channel == "trades-all"
            and envelope.event_time_ns != native_time_ns
        ):
            raise ValueError(
                "OKX trades-all envelope event time must match its single item"
            )
        side = _okx_side(item.get("side"))
        venue_source = _positive_string(item.get("source"), field_name="source")

        if aggregated:
            count_text = _positive_string(item.get("count"), field_name="count")
            if (
                _DIGITS.fullmatch(count_text) is None
                or int(count_text) <= 0
                or int(count_text) > _MAX_SIGNED_INT64
            ):
                raise ValueError("count must be a positive integer string")
            match_count = int(count_text)
            sequence = item.get("seqId")
            if type(sequence) is not int or sequence < 0:
                raise ValueError("seqId must be a non-negative JSON integer")
            representation = TradeRepresentation.AGGREGATED
            namespace = _OKX_AGGREGATED_TRADE_NAMESPACE
        else:
            if "count" in item and item["count"] != "1":
                raise ValueError("exact OKX trade cannot carry count greater than one")
            match_count = 1
            sequence = None
            representation = TradeRepresentation.EXACT
            namespace = _OKX_EXACT_TRADE_NAMESPACE

        contract_quantity: Decimal | None = None
        lineage_manifest_sha256s = {source.locator.manifest_sha256}
        if envelope.market is Market.SPOT:
            base_quantity = raw_size
        else:
            effective_metadata = _select_okx_contract_metadata(
                contract_metadata,
                instrument_key=envelope.instrument_key,
                native_event_time_ns=native_time_ns,
            )
            contract_quantity = raw_size
            lineage_manifest_sha256s.add(effective_metadata.source_manifest_sha256)
            base_quantity = _exact_multiply(
                raw_size,
                effective_metadata.contract_value,
                field_name="base_quantity",
            )
        quote_quantity = _exact_multiply(
            base_quantity,
            price,
            field_name="quote_quantity",
        )
        normalized.append(
            NormalizedTrade(
                source=source,
                locator=DerivedSourceLocator(
                    source=source.locator,
                    item_ordinal=item_ordinal,
                ),
                scope=scope,
                native_event_time_ns=native_time_ns,
                stable_trade_id=trade_id,
                trade_id_namespace=namespace,
                price=price,
                base_quantity=base_quantity,
                quote_quantity=quote_quantity,
                contract_quantity=contract_quantity,
                aggressor_side=side,
                match_count=match_count,
                representation=representation,
                venue_source=venue_source,
                lineage_manifest_sha256s=tuple(sorted(lineage_manifest_sha256s)),
                venue_sequence=sequence,
            )
        )
    return tuple(normalized)


@dataclass(frozen=True, slots=True)
class OkxTradeNormalizer:
    contract_metadata: tuple[OkxLinearContractMetadata, ...] = ()
    aggregated_equivalence_verified: bool = False

    def __post_init__(self) -> None:
        if any(
            type(item) is not OkxLinearContractMetadata
            for item in self.contract_metadata
        ):
            raise TypeError(
                "contract_metadata must contain OkxLinearContractMetadata values"
            )
        if type(self.aggregated_equivalence_verified) is not bool:
            raise TypeError("aggregated_equivalence_verified must be bool")

    def normalize(self, source: SourceRecord) -> tuple[NormalizedTrade, ...]:
        return normalize_okx_trade_items(
            source,
            contract_metadata=self.contract_metadata,
            aggregated_equivalence_verified=self.aggregated_equivalence_verified,
        )


def apply_trade_time_policy(
    trades: Iterable[NormalizedTrade],
    *,
    policy: EventTimePolicy,
) -> tuple[TimedTrade, ...]:
    if type(policy) is not EventTimePolicy:
        raise TypeError("policy must be EventTimePolicy")
    timed: list[TimedTrade] = []
    for trade in trades:
        if type(trade) is not NormalizedTrade:
            raise TypeError("trades must contain NormalizedTrade values")
        chosen = policy.choose(
            event_time_ns=trade.native_event_time_ns,
            received_at_ns=trade.source.envelope.received_at_ns,
        )
        timed.append(
            TimedTrade(
                trade=trade,
                effective_event_time_ns=chosen.effective_event_time_ns,
                time_source=chosen.time_source,
            )
        )
    return tuple(timed)


def canonical_trade_sort_key(
    trade: TimedTrade,
) -> tuple[int, int, str, int, int]:
    if type(trade) is not TimedTrade:
        raise TypeError("trade must be TimedTrade")
    locator = trade.locator
    return (
        trade.effective_event_time_ns,
        trade.trade.source.envelope.received_at_ns,
        locator.source.manifest_sha256,
        locator.source.zero_based_record_index,
        locator.item_ordinal,
    )


def _reject_partial_aggregate_range_overlaps(
    trades: tuple[TimedTrade, ...],
) -> None:
    ranges: list[tuple[int, int, tuple[Exchange, Market, str, str, str]]] = []
    for trade in trades:
        normalized = trade.trade
        identity = _stable_identity(trade)
        assert normalized.stable_trade_id is not None
        last_trade_id = int(normalized.stable_trade_id)
        first_trade_id = last_trade_id - normalized.match_count + 1
        ranges.append((first_trade_id, last_trade_id, identity))
    for index, (first, last, identity) in enumerate(ranges):
        for other_first, other_last, other_identity in ranges[index + 1 :]:
            overlaps = max(first, other_first) <= min(last, other_last)
            if overlaps and identity != other_identity:
                raise ValueError("partially overlapping aggregated trade ID ranges")


def _stable_identity(trade: TimedTrade) -> tuple[Exchange, Market, str, str, str]:
    normalized = trade.trade
    assert normalized.trade_id_namespace is not None
    assert normalized.stable_trade_id is not None
    return (
        normalized.scope.exchange,
        normalized.scope.market,
        normalized.scope.instrument_key,
        normalized.trade_id_namespace,
        normalized.stable_trade_id,
    )


def _semantic_identity(trade: TimedTrade) -> tuple[object, ...]:
    normalized = trade.trade
    return (
        normalized.native_event_time_ns,
        normalized.price,
        normalized.base_quantity,
        normalized.quote_quantity,
        normalized.contract_quantity,
        normalized.aggressor_side,
        normalized.match_count,
        normalized.representation,
        normalized.venue_source,
    )


@dataclass(slots=True)
class _DeduplicatedTrades:
    accepted: list[TimedTrade]
    duplicate_input_count: dict[DerivedSourceLocator, int]
    duplicate_match_count: dict[DerivedSourceLocator, int]
    lineage: dict[DerivedSourceLocator, set[str]]


def _deduplicate(trades: tuple[TimedTrade, ...]) -> _DeduplicatedTrades:
    ordered = sorted(trades, key=canonical_trade_sort_key)
    accepted: list[TimedTrade] = []
    winners: dict[tuple[Exchange, Market, str, str, str], TimedTrade] = {}
    duplicate_input_count: dict[DerivedSourceLocator, int] = {}
    duplicate_match_count: dict[DerivedSourceLocator, int] = {}
    lineage: dict[DerivedSourceLocator, set[str]] = {}
    for trade in ordered:
        if trade.trade.stable_trade_id is None:
            accepted.append(trade)
            lineage[trade.locator] = set(trade.trade.lineage_manifest_sha256s)
            continue
        identity = _stable_identity(trade)
        winner = winners.get(identity)
        if winner is None:
            winners[identity] = trade
            accepted.append(trade)
            lineage[trade.locator] = set(trade.trade.lineage_manifest_sha256s)
            continue
        if _semantic_identity(winner) != _semantic_identity(trade):
            raise ValueError("conflicting stable trade identity")
        winner_locator = winner.locator
        duplicate_input_count[winner_locator] = (
            duplicate_input_count.get(winner_locator, 0) + 1
        )
        duplicate_match_count[winner_locator] = (
            duplicate_match_count.get(winner_locator, 0) + trade.trade.match_count
        )
        lineage[winner_locator].update(trade.trade.lineage_manifest_sha256s)
    return _DeduplicatedTrades(
        accepted=accepted,
        duplicate_input_count=duplicate_input_count,
        duplicate_match_count=duplicate_match_count,
        lineage=lineage,
    )


def _deduplication_mode(trades: Sequence[TimedTrade]) -> DeduplicationMode | None:
    if not trades:
        return None
    with_id = sum(trade.trade.stable_trade_id is not None for trade in trades)
    if with_id == len(trades):
        return DeduplicationMode.STABLE_ID
    if with_id == 0:
        return DeduplicationMode.UNAVAILABLE
    return DeduplicationMode.MIXED


def _zero() -> Decimal:
    return Decimal(0)


def _count_sum(values: Iterable[int], *, field_name: str) -> int:
    total = 0
    for value in values:
        if type(value) is not int or value < 0:
            raise ValueError(f"{field_name} inputs must be non-negative integers")
        total += value
        if total > _MAX_SIGNED_INT64:
            raise ValueError(f"{field_name} must fit a signed 64-bit integer")
    return total


def _sum_field(trades: Sequence[TimedTrade], field_name: str) -> Decimal:
    total = _zero()
    for trade in trades:
        value = getattr(trade.trade, field_name)
        assert isinstance(value, Decimal)
        total = _exact_add(total, value, field_name=field_name)
    return total


def _quote_for_trade(trade: TimedTrade) -> Decimal:
    quote_quantity = trade.trade.quote_quantity
    if quote_quantity is not None:
        return quote_quantity
    return _exact_multiply(
        trade.trade.price,
        trade.trade.base_quantity,
        field_name="quote_quantity",
    )


def _sum_quote(trades: Sequence[TimedTrade]) -> Decimal:
    total = _zero()
    for trade in trades:
        total = _exact_add(total, _quote_for_trade(trade), field_name="quote_quantity")
    return total


def _side_volume(
    trades: Sequence[TimedTrade],
    side: AggressorSide,
) -> Decimal:
    return _sum_field(
        [trade for trade in trades if trade.trade.aggressor_side is side],
        "base_quantity",
    )


def _canonical_windows(windows: Iterable[Window]) -> tuple[Window, ...]:
    values = tuple(windows)
    if any(type(window) is not Window for window in values):
        raise TypeError("windows must contain Window values")
    ordered = tuple(sorted(values))
    if values != ordered:
        raise ValueError("windows must be in ascending order")
    if len(values) != len(set(values)):
        raise ValueError("windows must be unique")
    if values:
        interval = values[0].interval_ns
        if any(window.interval_ns != interval for window in values):
            raise ValueError("all output windows must use one interval")
        if any(
            previous.end_ns > current.start_ns for previous, current in pairwise(values)
        ):
            raise ValueError("output windows must not overlap")
    return values


def _build_bar(
    *,
    scope: TradeScope,
    window: Window,
    trades: list[TimedTrade],
    deduplicated: _DeduplicatedTrades,
) -> TradeBar:
    if not trades:
        zero = _zero()
        return TradeBar(
            scope=scope,
            window=window,
            open=None,
            high=None,
            low=None,
            close=None,
            vwap=None,
            base_volume=zero,
            quote_volume=zero,
            buy_base_volume=zero,
            sell_base_volume=zero,
            unknown_base_volume=zero,
            signed_base_volume=zero,
            trade_count=0,
            normalized_record_count=0,
            aggregated_record_count=0,
            duplicate_input_count=0,
            duplicate_match_count=0,
            first_effective_trade_time_ns=None,
            last_effective_trade_time_ns=None,
            event_time_count=0,
            receive_missing_count=0,
            receive_outlier_count=0,
            event_time_ratio=None,
            deduplication_mode=None,
            lineage_manifest_sha256s=(),
            first_source_locator=None,
            last_source_locator=None,
        )

    base_volume = _sum_field(trades, "base_quantity")
    quote_volume = _sum_quote(trades)
    buy_volume = _side_volume(trades, AggressorSide.BUY)
    sell_volume = _side_volume(trades, AggressorSide.SELL)
    unknown_volume = _side_volume(trades, AggressorSide.UNKNOWN)
    signed_volume = _exact_add(
        buy_volume,
        sell_volume.copy_negate(),
        field_name="signed_base_volume",
    )
    prices = [trade.trade.price for trade in trades]
    event_count = sum(trade.time_source is TimeSource.EVENT for trade in trades)
    missing_count = sum(
        trade.time_source is TimeSource.RECEIVE_MISSING for trade in trades
    )
    outlier_count = sum(
        trade.time_source is TimeSource.RECEIVE_OUTLIER for trade in trades
    )
    lineage = {
        manifest_sha
        for trade in trades
        for manifest_sha in deduplicated.lineage[trade.locator]
    }
    return TradeBar(
        scope=scope,
        window=window,
        open=prices[0],
        high=max(prices),
        low=min(prices),
        close=prices[-1],
        vwap=_round_ratio_half_even(
            quote_volume,
            base_volume,
            scale=_VWAP_SCALE,
            field_name="vwap",
        ),
        base_volume=base_volume,
        quote_volume=quote_volume,
        buy_base_volume=buy_volume,
        sell_base_volume=sell_volume,
        unknown_base_volume=unknown_volume,
        signed_base_volume=signed_volume,
        trade_count=_count_sum(
            (trade.trade.match_count for trade in trades),
            field_name="trade_count",
        ),
        normalized_record_count=len(trades),
        aggregated_record_count=sum(
            trade.trade.representation is TradeRepresentation.AGGREGATED
            for trade in trades
        ),
        duplicate_input_count=_count_sum(
            (
                deduplicated.duplicate_input_count.get(trade.locator, 0)
                for trade in trades
            ),
            field_name="duplicate_input_count",
        ),
        duplicate_match_count=_count_sum(
            (
                deduplicated.duplicate_match_count.get(trade.locator, 0)
                for trade in trades
            ),
            field_name="duplicate_match_count",
        ),
        first_effective_trade_time_ns=trades[0].effective_event_time_ns,
        last_effective_trade_time_ns=trades[-1].effective_event_time_ns,
        event_time_count=event_count,
        receive_missing_count=missing_count,
        receive_outlier_count=outlier_count,
        event_time_ratio=_round_ratio_half_even(
            Decimal(event_count),
            Decimal(len(trades)),
            scale=_VWAP_SCALE,
            field_name="event_time_ratio",
        ),
        deduplication_mode=_deduplication_mode(trades),
        lineage_manifest_sha256s=tuple(sorted(lineage)),
        first_source_locator=trades[0].locator,
        last_source_locator=trades[-1].locator,
    )


def build_trade_bars(
    candidates: TradeCandidateSet,
    *,
    windows: Iterable[Window],
) -> tuple[TradeBar, ...]:
    """Deduplicate the complete declared candidate domain, then project windows."""

    if type(candidates) is not TradeCandidateSet:
        raise TypeError("candidates must be TradeCandidateSet")
    output_windows = _canonical_windows(windows)
    if any(
        window.start_ns < candidates.coverage.start_ns
        or window.end_ns > candidates.coverage.end_ns
        for window in output_windows
    ):
        raise ValueError("output windows must fall inside candidate coverage")
    deduplicated = _deduplicate(candidates.trades)
    accepted = deduplicated.accepted
    duplicate_winners = set(deduplicated.duplicate_input_count)
    if any(
        trade.locator in duplicate_winners
        and not any(
            window.start_ns <= trade.effective_event_time_ns < window.end_ns
            for window in output_windows
        )
        for trade in accepted
    ):
        raise ValueError("output must include winner windows with duplicate telemetry")
    return tuple(
        _build_bar(
            scope=candidates.scope,
            window=window,
            trades=[
                trade
                for trade in accepted
                if window.start_ns <= trade.effective_event_time_ns < window.end_ns
            ],
            deduplicated=deduplicated,
        )
        for window in output_windows
    )


__all__ = [
    "AggressorSide",
    "CandidateCoverage",
    "DeduplicationMode",
    "NormalizedTrade",
    "OkxLinearContractMetadata",
    "OkxTradeNormalizer",
    "TimedTrade",
    "TradeBar",
    "TradeCandidateSet",
    "TradeNormalizer",
    "TradeRepresentation",
    "TradeScope",
    "apply_trade_time_policy",
    "build_trade_bars",
    "canonical_decimal",
    "canonical_trade_sort_key",
    "normalize_okx_trade_items",
]
