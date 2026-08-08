from __future__ import annotations

from collections.abc import Iterable, Mapping
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import cast

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import JsonPayload, encode_json
from crypto_collector.exchanges.bitget.errors import BitgetPayloadError
from crypto_collector.exchanges.bitget.rest import (
    INSTRUMENTS_PATH,
    TICKERS_PATH,
    BitgetRestRequest,
)
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
_TRADABLE_STATES = frozenset({"online"})
_SYMBOL_TYPES = frozenset({"crypto", "metal", "stock", "commodity"})
_FUTURES_TYPES = frozenset({"perpetual", "delivery"})
_REALITY_VALUES = frozenset({"yes", "no"})
_EXPECTED_CATEGORY = {
    Market.SPOT: "SPOT",
    Market.PERPETUAL: "USDT-FUTURES",
}
_PHASE_BY_STATE = {
    "listed": LifecyclePhase.PREOPEN,
    "online": LifecyclePhase.TRADABLE,
    "limit_open": LifecyclePhase.PAUSED,
    "limit_close": LifecyclePhase.PAUSED,
    # Bitget defines offline as either delisted or under maintenance.
    "offline": LifecyclePhase.UNKNOWN,
    "restrictedAPI": LifecyclePhase.PAUSED,
}


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BitgetPayloadError(f"{field} must be a JSON object")
    return cast(Mapping[str, JsonPayload], value)


def _success_data(payload: object) -> tuple[Mapping[str, JsonPayload], ...]:
    envelope = _mapping(payload, field="Bitget response")
    if envelope.get("code") != "00000":
        raise BitgetPayloadError(
            "Bitget parser requires a successful string code='00000' response"
        )
    data = envelope.get("data")
    if not isinstance(data, (list, tuple)):
        raise BitgetPayloadError("Bitget response data must be an array")
    return tuple(
        _mapping(item, field=f"Bitget response data[{index}]")
        for index, item in enumerate(data)
    )


def _required_string(item: Mapping[str, JsonPayload], field: str) -> str:
    value = item.get(field)
    if type(value) is not str or not value:
        raise BitgetPayloadError(f"Bitget {field} must be a non-empty string")
    return value


def _optional_milliseconds(item: Mapping[str, JsonPayload], field: str) -> int | None:
    value = item.get(field)
    if value is None or value == "" or value == "0":
        return None
    if type(value) is not str or not value.isascii() or not value.isdigit():
        raise BitgetPayloadError(f"Bitget {field} must be Unix milliseconds")
    normalized = value.lstrip("0") or "0"
    if normalized == "0":
        return None
    maximum_ms = str(_MAX_SIGNED_64 // _MILLISECONDS_TO_NANOSECONDS)
    if len(normalized) > len(maximum_ms) or (
        len(normalized) == len(maximum_ms) and normalized > maximum_ms
    ):
        raise BitgetPayloadError(
            f"Bitget {field} does not fit signed 64-bit nanoseconds"
        )
    nanoseconds = int(normalized) * _MILLISECONDS_TO_NANOSECONDS
    return nanoseconds


def _raw_reference(payload: object, *, kind: str) -> str:
    try:
        digest = sha256(encode_json(payload)).hexdigest()
    except (TypeError, ValueError) as error:
        raise BitgetPayloadError("Bitget payload is not exact finite JSON") from error
    return f"bitget:{kind}:sha256:{digest}"


def _snapshot_id(*, market: Market, kind: str, raw_reference: str) -> str:
    digest = sha256(
        f"bitget\0{market.value}\0{kind}\0{raw_reference}".encode()
    ).hexdigest()
    return f"bitget:{market.value}:{kind}:{digest}"


def _official_tradable_time(
    item: Mapping[str, JsonPayload],
) -> tuple[int | None, TradableAtSource | None]:
    launch_time = _optional_milliseconds(item, "launchTime")
    if launch_time is None:
        return None, None
    return launch_time, TradableAtSource.EXCHANGE_LAUNCH


def _required_enum(
    item: Mapping[str, JsonPayload],
    field: str,
    allowed: frozenset[str],
) -> str:
    value = item.get(field)
    if type(value) is not str or value not in allowed:
        raise BitgetPayloadError(
            f"Bitget {field} is missing or outside the documented enum"
        )
    return value


def _is_anonymous_crypto_instrument(
    item: Mapping[str, JsonPayload],
    *,
    market: Market,
) -> bool:
    if market is Market.PERPETUAL:
        futures_type = _required_enum(item, "type", _FUTURES_TYPES)
        if futures_type == "delivery":
            return False
    symbol_type = _required_enum(item, "symbolType", _SYMBOL_TYPES)
    if symbol_type != "crypto":
        return False
    if market is Market.SPOT:
        return _required_enum(item, "isReality", _REALITY_VALUES) == "no"
    # Reality is a Spot field and is absent from the documented futures shape.
    if "isReality" not in item:
        return True
    return _required_enum(item, "isReality", _REALITY_VALUES) == "no"


def _validate_complete_request(
    request: BitgetRestRequest,
    *,
    market: Market,
    path: str,
    logical_stream: str,
) -> None:
    if type(request) is not BitgetRestRequest:
        raise TypeError("request must be BitgetRestRequest")
    expected_params = {"category": _EXPECTED_CATEGORY[market]}
    if (
        request.path != path
        or request.logical_stream != logical_stream
        or dict(request.params) != expected_params
    ):
        raise ValueError("complete Bitget parser requires an unscoped category request")


def parse_instruments(
    payload: object,
    market: Market,
    *,
    request: BitgetRestRequest,
    observed_at_ns: int,
) -> CompleteCatalogSnapshot:
    """Parse one complete, unscoped UTA v3 category response."""

    if type(market) is not Market:
        raise TypeError("market must be Market")
    if type(observed_at_ns) is not int or not 0 <= observed_at_ns <= _MAX_SIGNED_64:
        raise ValueError("observed_at_ns must fit signed 64-bit nanoseconds")
    _validate_complete_request(
        request,
        market=market,
        path=INSTRUMENTS_PATH,
        logical_stream="instrument_catalog",
    )

    expected_category = _EXPECTED_CATEGORY[market]
    raw_reference = _raw_reference(payload, kind=f"instruments-{market.value}")
    instruments: list[InstrumentRecord] = []
    for item in _success_data(payload):
        if item.get("category") != expected_category:
            raise BitgetPayloadError(
                "Bitget instrument row does not match requested "
                f"{expected_category} category"
            )
        if not _is_anonymous_crypto_instrument(item, market=market):
            continue
        instrument_key = _required_string(item, "symbol")
        base = _required_string(item, "baseCoin")
        quote = _required_string(item, "quoteCoin")
        if market is Market.PERPETUAL and quote != "USDT":
            raise BitgetPayloadError(
                "Bitget USDT-FUTURES instrument must use USDT as quote asset"
            )
        status = _required_string(item, "status")
        tradable_at_ns, tradable_at_source = _official_tradable_time(item)
        instruments.append(
            InstrumentRecord(
                exchange=Exchange.BITGET,
                market=market,
                instrument_key=instrument_key,
                canonical_pair=f"{base}/{quote}",
                wire_symbols={
                    "rest": instrument_key,
                    "websocket": instrument_key,
                },
                base_asset=base,
                quote_asset=quote,
                settlement_asset="USDT" if market is Market.PERPETUAL else None,
                status=status,
                lifecycle_phase=_PHASE_BY_STATE.get(
                    status,
                    LifecyclePhase.UNKNOWN,
                ),
                tradable=status in _TRADABLE_STATES,
                lifecycle=item,
                tradable_at_ns=tradable_at_ns,
                tradable_at_source=tradable_at_source,
                turnover=None,
                raw_catalog_reference=raw_reference,
            )
        )

    ordered = tuple(sorted(instruments, key=lambda item: item.instrument_key))
    return CompleteCatalogSnapshot(
        scope=CatalogScope(Exchange.BITGET, market),
        observed_at_ns=observed_at_ns,
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


def _optional_decimal_string(
    item: Mapping[str, JsonPayload], field: str
) -> Decimal | None:
    value = item.get(field)
    if type(value) is not str or not value:
        return None
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return None
    if not parsed.is_finite() or parsed < 0:
        return None
    return parsed


def parse_tickers(
    payload: object,
    *,
    market: Market,
    request: BitgetRestRequest,
    catalog: CompleteCatalogSnapshot,
    catalog_revision: int,
    observed_at_ns: int,
) -> CompleteTurnoverSnapshot:
    """Build turnover from one complete, unscoped category ticker response."""

    if type(market) is not Market:
        raise TypeError("market must be Market")
    if type(catalog_revision) is not int or catalog_revision <= 0:
        raise ValueError("catalog_revision must be positive")
    if type(catalog) is not CompleteCatalogSnapshot:
        raise TypeError("catalog must be CompleteCatalogSnapshot")
    expected_scope = CatalogScope(Exchange.BITGET, market)
    if catalog.scope != expected_scope:
        raise ValueError("catalog scope does not match the requested Bitget market")
    if type(observed_at_ns) is not int or not 0 <= observed_at_ns <= _MAX_SIGNED_64:
        raise ValueError("observed_at_ns must fit signed 64-bit nanoseconds")
    if observed_at_ns < catalog.observed_at_ns:
        raise ValueError("turnover observation cannot precede its catalog")
    _validate_complete_request(
        request,
        market=market,
        path=TICKERS_PATH,
        logical_stream="ticker_catalog",
    )

    by_key = {
        item.instrument_key: item
        for item in catalog.instruments
        if item.exchange is Exchange.BITGET and item.market is market
    }
    expected_category = _EXPECTED_CATEGORY[market]
    raw_reference = _raw_reference(payload, kind=f"tickers-{market.value}")
    observations: list[TurnoverObservation] = []
    seen_instrument_keys: set[str] = set()
    covered = tuple(sorted(by_key))
    for item in _success_data(payload):
        if item.get("category") != expected_category:
            raise BitgetPayloadError("Bitget ticker row has the wrong category")
        instrument_key = _required_string(item, "symbol")
        if instrument_key in seen_instrument_keys:
            raise BitgetPayloadError("Bitget ticker response repeats a symbol")
        seen_instrument_keys.add(instrument_key)
        instrument = by_key.get(instrument_key)
        if instrument is None:
            continue
        turnover = _optional_decimal_string(item, "turnover24h")
        if turnover is None:
            continue
        observations.append(
            TurnoverObservation(
                instrument_key=instrument_key,
                value=turnover,
                method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
                currency=instrument.quote_asset,
                raw_reference=raw_reference,
            )
        )
    ordered = tuple(sorted(observations, key=lambda item: item.instrument_key))
    return CompleteTurnoverSnapshot(
        scope=expected_scope,
        catalog_revision=catalog_revision,
        observed_at_ns=observed_at_ns,
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


def instrument_by_key(
    catalog: CompleteCatalogSnapshot,
    instrument_key: str,
) -> InstrumentRecord:
    if type(catalog) is not CompleteCatalogSnapshot:
        raise TypeError("catalog must be CompleteCatalogSnapshot")
    for instrument in catalog.instruments:
        if instrument.instrument_key == instrument_key:
            return instrument
    raise KeyError(instrument_key)


def iter_raw_catalog_payloads(
    catalog: CompleteCatalogSnapshot,
) -> Iterable[Mapping[str, object]]:
    """Expose immutable lifecycle payloads for audit and fixture verification."""

    for instrument in catalog.instruments:
        if not isinstance(instrument.lifecycle, Mapping):
            raise BitgetPayloadError(
                "Bitget catalog lifecycle payload must be an object"
            )
        yield cast(Mapping[str, object], instrument.lifecycle)


__all__ = [
    "instrument_by_key",
    "iter_raw_catalog_payloads",
    "parse_instruments",
    "parse_tickers",
]
