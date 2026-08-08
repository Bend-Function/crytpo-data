from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import cast

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import JsonPayload, encode_json
from crypto_collector.exchanges.binance.errors import BinancePayloadError
from crypto_collector.selection import (
    CatalogScope,
    CompleteCatalogSnapshot,
    CompleteTurnoverSnapshot,
    InstrumentRecord,
    LifecyclePhase,
    SnapshotPage,
    TradableAtSource,
    TurnoverMethod,
    TurnoverObservation,
)

_MILLISECONDS_TO_NANOSECONDS = 1_000_000
_MAX_SIGNED_64 = 2**63 - 1
_SPOT_PHASES = {
    "TRADING": LifecyclePhase.TRADABLE,
    "END_OF_DAY": LifecyclePhase.PAUSED,
    "HALT": LifecyclePhase.PAUSED,
    "BREAK": LifecyclePhase.PAUSED,
    "CANCEL_ONLY": LifecyclePhase.PAUSED,
}
_FUTURES_PHASES = {
    "PENDING_TRADING": LifecyclePhase.PREOPEN,
    "TRADING": LifecyclePhase.TRADABLE,
    "PRE_DELIVERING": LifecyclePhase.PAUSED,
    "DELIVERING": LifecyclePhase.PAUSED,
    "PRE_SETTLE": LifecyclePhase.PAUSED,
    "SETTLING": LifecyclePhase.PAUSED,
    "TRADING_HALT": LifecyclePhase.PAUSED,
    "TRADING_CANCEL_ONLY": LifecyclePhase.PAUSED,
    "DELIVERED": LifecyclePhase.DELISTED,
    "CLOSE": LifecyclePhase.DELISTED,
}


@dataclass(frozen=True, slots=True)
class BinanceRateLimit:
    rate_limit_type: str
    interval: str
    interval_num: int
    limit: int

    def __post_init__(self) -> None:
        for field in ("rate_limit_type", "interval"):
            value = getattr(self, field)
            if type(value) is not str or not value:
                raise ValueError(f"{field} must be a non-empty string")
        for field in ("interval_num", "limit"):
            value = getattr(self, field)
            if type(value) is not int or value <= 0:
                raise ValueError(f"{field} must be a positive integer")


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BinancePayloadError(f"{field} must be a JSON object")
    return cast(Mapping[str, JsonPayload], value)


def _array(value: object, *, field: str) -> Sequence[JsonPayload]:
    if not isinstance(value, (list, tuple)):
        raise BinancePayloadError(f"{field} must be a JSON array")
    return cast(Sequence[JsonPayload], value)


def _required_string(item: Mapping[str, JsonPayload], field: str) -> str:
    value = item.get(field)
    if type(value) is not str or not value:
        raise BinancePayloadError(f"Binance {field} must be a non-empty string")
    return value


def _required_bool(item: Mapping[str, JsonPayload], field: str) -> bool:
    value = item.get(field)
    if type(value) is not bool:
        raise BinancePayloadError(f"Binance {field} must be a boolean")
    return value


def _positive_int(value: object, *, field: str) -> int:
    if type(value) is not int or value <= 0:
        raise BinancePayloadError(f"Binance {field} must be a positive integer")
    return value


def _observed_at(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SIGNED_64:
        raise ValueError("observed_at_ns must fit signed 64-bit nanoseconds")
    return value


def _optional_milliseconds(item: Mapping[str, JsonPayload], field: str) -> int | None:
    value = item.get(field)
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise BinancePayloadError(f"Binance {field} must be Unix epoch milliseconds")
    if value == 0:
        return None
    nanoseconds = value * _MILLISECONDS_TO_NANOSECONDS
    if nanoseconds > _MAX_SIGNED_64:
        raise BinancePayloadError(
            f"Binance {field} does not fit signed 64-bit nanoseconds"
        )
    return nanoseconds


def _raw_reference(payload: object, *, kind: str) -> str:
    try:
        digest = sha256(encode_json(payload)).hexdigest()
    except (TypeError, ValueError) as error:
        raise BinancePayloadError("Binance payload is not exact finite JSON") from error
    return f"binance:{kind}:sha256:{digest}"


def _snapshot_id(*, market: Market, kind: str, raw_reference: str) -> str:
    digest = sha256(
        f"binance\0{market.value}\0{kind}\0{raw_reference}".encode()
    ).hexdigest()
    return f"binance:{market.value}:{kind}:{digest}"


def parse_rate_limits(payload: object) -> tuple[BinanceRateLimit, ...]:
    envelope = _mapping(payload, field="Binance exchangeInfo response")
    values = _array(envelope.get("rateLimits"), field="Binance rateLimits")
    limits: list[BinanceRateLimit] = []
    identities: set[tuple[str, str, int]] = set()
    for index, value in enumerate(values):
        item = _mapping(value, field=f"Binance rateLimits[{index}]")
        rate_limit = BinanceRateLimit(
            rate_limit_type=_required_string(item, "rateLimitType"),
            interval=_required_string(item, "interval"),
            interval_num=_positive_int(item.get("intervalNum"), field="intervalNum"),
            limit=_positive_int(item.get("limit"), field="limit"),
        )
        identity = (
            rate_limit.rate_limit_type,
            rate_limit.interval,
            rate_limit.interval_num,
        )
        if identity in identities:
            raise BinancePayloadError("Binance rateLimits contains a duplicate scope")
        identities.add(identity)
        limits.append(rate_limit)
    return tuple(limits)


def _string_array(value: object, *, field: str) -> tuple[str, ...]:
    values = _array(value, field=field)
    normalized: list[str] = []
    for item in values:
        if type(item) is not str or not item:
            raise BinancePayloadError(f"{field} must contain non-empty strings")
        normalized.append(item)
    return tuple(normalized)


def _has_spot_permission(item: Mapping[str, JsonPayload]) -> bool:
    permissions_value = item.get("permissions")
    permission_sets_value = item.get("permissionSets")
    if permissions_value is None and permission_sets_value is None:
        raise BinancePayloadError(
            "Binance Spot row lacks permissions and permissionSets evidence"
        )
    permissions = (
        ()
        if permissions_value is None
        else _string_array(permissions_value, field="Binance permissions")
    )
    sets: list[tuple[str, ...]] = []
    if permission_sets_value is not None:
        for index, value in enumerate(
            _array(permission_sets_value, field="Binance permissionSets")
        ):
            sets.append(_string_array(value, field=f"Binance permissionSets[{index}]"))
    return "SPOT" in permissions or any("SPOT" in group for group in sets)


def _spot_record(
    item: Mapping[str, JsonPayload], *, raw_reference: str
) -> InstrumentRecord | None:
    if not _has_spot_permission(item):
        return None
    symbol = _required_string(item, "symbol")
    status = _required_string(item, "status")
    base = _required_string(item, "baseAsset")
    quote = _required_string(item, "quoteAsset")
    spot_allowed = _required_bool(item, "isSpotTradingAllowed")
    phase = _SPOT_PHASES.get(status, LifecyclePhase.UNKNOWN)
    tradable = status == "TRADING" and spot_allowed
    if phase is LifecyclePhase.TRADABLE and not tradable:
        phase = LifecyclePhase.PAUSED
    return InstrumentRecord(
        exchange=Exchange.BINANCE,
        market=Market.SPOT,
        instrument_key=symbol,
        canonical_pair=f"{base}/{quote}",
        wire_symbols={"rest": symbol, "websocket": symbol.lower()},
        base_asset=base,
        quote_asset=quote,
        settlement_asset=None,
        status=status,
        lifecycle_phase=phase,
        tradable=tradable,
        lifecycle=item,
        tradable_at_ns=None,
        tradable_at_source=None,
        turnover=None,
        raw_catalog_reference=raw_reference,
    )


def _usd_m_row_indicator(item: Mapping[str, JsonPayload]) -> bool:
    value = item.get("st")
    if value is None:
        return True
    if type(value) is not int or value not in {1, 2}:
        return False
    return value == 1


def _futures_record(
    item: Mapping[str, JsonPayload],
    *,
    raw_reference: str,
    settlement_asset: str,
) -> InstrumentRecord | None:
    contract_type = _required_string(item, "contractType")
    if contract_type != "PERPETUAL" or not _usd_m_row_indicator(item):
        return None
    margin_asset = _required_string(item, "marginAsset")
    quote = _required_string(item, "quoteAsset")
    if margin_asset != settlement_asset or quote != settlement_asset:
        return None
    symbol = _required_string(item, "symbol")
    status = _required_string(item, "status")
    base = _required_string(item, "baseAsset")
    pair = item.get("pair")
    if pair is not None and (type(pair) is not str or not pair):
        raise BinancePayloadError("Binance pair must be a non-empty string")
    phase = _FUTURES_PHASES.get(status, LifecyclePhase.UNKNOWN)
    tradable = status == "TRADING"
    onboard_at_ns = _optional_milliseconds(item, "onboardDate")
    wire_symbols = {"rest": symbol, "websocket": symbol.lower()}
    if type(pair) is str:
        wire_symbols["pair"] = pair
    return InstrumentRecord(
        exchange=Exchange.BINANCE,
        market=Market.PERPETUAL,
        instrument_key=symbol,
        canonical_pair=f"{base}/{quote}",
        wire_symbols=wire_symbols,
        base_asset=base,
        quote_asset=quote,
        settlement_asset=margin_asset,
        status=status,
        lifecycle_phase=phase,
        tradable=tradable,
        lifecycle=item,
        tradable_at_ns=onboard_at_ns,
        tradable_at_source=(
            None if onboard_at_ns is None else TradableAtSource.EXCHANGE_LAUNCH
        ),
        turnover=None,
        raw_catalog_reference=raw_reference,
    )


def parse_exchange_info(
    payload: object,
    market: Market,
    *,
    observed_at_ns: int,
    settlement_asset: str = "USDT",
) -> CompleteCatalogSnapshot:
    """Parse one complete Spot or USD-M exchangeInfo response."""

    if type(market) is not Market:
        raise TypeError("market must be Market")
    observed_at = _observed_at(observed_at_ns)
    if type(settlement_asset) is not str or not settlement_asset:
        raise ValueError("settlement_asset must be a non-empty string")
    envelope = _mapping(payload, field="Binance exchangeInfo response")
    if market is Market.PERPETUAL:
        futures_type = _required_string(envelope, "futuresType")
        if futures_type != "U_MARGINED":
            raise BinancePayloadError(
                "Binance Futures catalog is not proven U_MARGINED"
            )
    parse_rate_limits(envelope)
    rows = _array(envelope.get("symbols"), field="Binance symbols")
    raw_reference = _raw_reference(payload, kind=f"exchange-info-{market.value}")
    instruments: list[InstrumentRecord] = []
    for index, value in enumerate(rows):
        item = _mapping(value, field=f"Binance symbols[{index}]")
        record = (
            _spot_record(item, raw_reference=raw_reference)
            if market is Market.SPOT
            else _futures_record(
                item,
                raw_reference=raw_reference,
                settlement_asset=settlement_asset,
            )
        )
        if record is not None:
            instruments.append(record)
    ordered = tuple(sorted(instruments, key=lambda item: item.instrument_key))
    if len({item.instrument_key for item in ordered}) != len(ordered):
        raise BinancePayloadError("Binance catalog contains duplicate symbols")
    return CompleteCatalogSnapshot(
        scope=CatalogScope(Exchange.BINANCE, market),
        observed_at_ns=observed_at,
        snapshot_id=_snapshot_id(
            market=market,
            kind="catalog",
            raw_reference=raw_reference,
        ),
        pages=(SnapshotPage(raw_reference, None, None),),
        reported_total_count=None,
        authoritative_empty=not ordered,
        instruments=ordered,
    )


def instrument_by_key(
    catalog: CompleteCatalogSnapshot, instrument_key: str
) -> InstrumentRecord:
    for instrument in catalog.instruments:
        if instrument.instrument_key == instrument_key:
            return instrument
    raise KeyError(instrument_key)


def _quote_volume(item: Mapping[str, JsonPayload]) -> Decimal:
    value = item.get("quoteVolume")
    if type(value) is not str or not value:
        raise BinancePayloadError("Binance quoteVolume must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise BinancePayloadError(
            "Binance quoteVolume must be a decimal string"
        ) from error
    if not parsed.is_finite() or parsed < 0:
        raise BinancePayloadError("Binance quoteVolume must be finite and non-negative")
    return parsed


def parse_ticker_turnover(
    payload: object,
    *,
    market: Market,
    catalog: CompleteCatalogSnapshot,
    catalog_revision: int,
    observed_at_ns: int,
) -> CompleteTurnoverSnapshot:
    if type(market) is not Market:
        raise TypeError("market must be Market")
    if type(catalog) is not CompleteCatalogSnapshot:
        raise TypeError("catalog must be CompleteCatalogSnapshot")
    expected_scope = CatalogScope(Exchange.BINANCE, market)
    if catalog.scope != expected_scope:
        raise ValueError("catalog scope does not match Binance market")
    if type(catalog_revision) is not int or catalog_revision <= 0:
        raise ValueError("catalog_revision must be positive")
    observed_at = _observed_at(observed_at_ns)
    if observed_at < catalog.observed_at_ns:
        raise ValueError("turnover observation cannot precede its catalog")
    rows: Sequence[JsonPayload]
    if isinstance(payload, Mapping):
        rows = (cast(JsonPayload, payload),)
    else:
        rows = _array(payload, field="Binance ticker response")
    by_key = {item.instrument_key: item for item in catalog.instruments}
    raw_reference = _raw_reference(payload, kind=f"ticker-{market.value}")
    observations: list[TurnoverObservation] = []
    seen: set[str] = set()
    for index, value in enumerate(rows):
        item = _mapping(value, field=f"Binance ticker[{index}]")
        symbol = _required_string(item, "symbol")
        if symbol in seen:
            raise BinancePayloadError("Binance ticker response contains duplicates")
        seen.add(symbol)
        instrument = by_key.get(symbol)
        if instrument is None:
            continue
        observations.append(
            TurnoverObservation(
                instrument_key=symbol,
                value=_quote_volume(item),
                method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
                currency=instrument.quote_asset,
                raw_reference=raw_reference,
            )
        )
    covered = tuple(sorted(seen.intersection(by_key)))
    ordered = tuple(sorted(observations, key=lambda item: item.instrument_key))
    return CompleteTurnoverSnapshot(
        scope=expected_scope,
        catalog_revision=catalog_revision,
        observed_at_ns=observed_at,
        snapshot_id=_snapshot_id(
            market=market,
            kind="turnover",
            raw_reference=raw_reference,
        ),
        pages=(SnapshotPage(raw_reference, None, None),),
        reported_total_count=None,
        authoritative_empty=not covered,
        covered_instrument_keys=covered,
        observations=ordered,
    )


__all__ = [
    "BinanceRateLimit",
    "instrument_by_key",
    "parse_exchange_info",
    "parse_rate_limits",
    "parse_ticker_turnover",
]
