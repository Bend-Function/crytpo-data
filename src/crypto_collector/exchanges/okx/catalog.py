from __future__ import annotations

from collections.abc import Iterable, Mapping
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import cast

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import JsonPayload, encode_json
from crypto_collector.exchanges.okx.errors import OkxPayloadError
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
_TRADABLE_STATES = frozenset({"live", "post_only"})
_EXPECTED_INST_TYPE = {
    Market.SPOT: "SPOT",
    Market.PERPETUAL: "SWAP",
}
_PHASE_BY_STATE = {
    "live": LifecyclePhase.TRADABLE,
    "post_only": LifecyclePhase.TRADABLE,
    "preopen": LifecyclePhase.PREOPEN,
    "suspend": LifecyclePhase.PAUSED,
    "rebase": LifecyclePhase.PAUSED,
    "settling": LifecyclePhase.DELISTED,
}


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise OkxPayloadError(f"{field} must be a JSON object")
    return cast(Mapping[str, JsonPayload], value)


def _success_data(payload: object) -> tuple[Mapping[str, JsonPayload], ...]:
    envelope = _mapping(payload, field="OKX response")
    code = envelope.get("code")
    if code != "0" and code != 0:
        raise OkxPayloadError("OKX parser requires a successful code=0 response")
    data = envelope.get("data")
    if not isinstance(data, (list, tuple)):
        raise OkxPayloadError("OKX response data must be an array")
    return tuple(
        _mapping(item, field=f"OKX response data[{index}]")
        for index, item in enumerate(data)
    )


def _required_string(item: Mapping[str, JsonPayload], field: str) -> str:
    value = item.get(field)
    if type(value) is not str or not value:
        raise OkxPayloadError(f"OKX {field} must be a non-empty string")
    return value


def _optional_string(item: Mapping[str, JsonPayload], field: str) -> str | None:
    value = item.get(field)
    if value is None or value == "":
        return None
    if type(value) is not str:
        raise OkxPayloadError(f"OKX {field} must be a string")
    return value


def _milliseconds(value: str | None, *, field: str) -> int | None:
    if value is None:
        return None
    if not value.isascii() or not value.isdigit():
        raise OkxPayloadError(f"OKX {field} must be milliseconds since Unix epoch")
    nanoseconds = int(value) * _MILLISECONDS_TO_NANOSECONDS
    if nanoseconds > _MAX_SIGNED_64:
        raise OkxPayloadError(f"OKX {field} does not fit signed 64-bit nanoseconds")
    return nanoseconds


def _raw_reference(payload: object, *, kind: str) -> str:
    try:
        digest = sha256(encode_json(payload)).hexdigest()
    except (TypeError, ValueError) as error:
        raise OkxPayloadError("OKX payload is not exact finite JSON") from error
    return f"okx:{kind}:sha256:{digest}"


def _snapshot_id(*, market: Market, kind: str, raw_reference: str) -> str:
    digest = sha256(
        f"okx\0{market.value}\0{kind}\0{raw_reference}".encode()
    ).hexdigest()
    return f"okx:{market.value}:{kind}:{digest}"


def _official_tradable_time(
    item: Mapping[str, JsonPayload],
) -> tuple[int | None, TradableAtSource | None]:
    for field in ("contTdSwTime", "preMktSwTime"):
        value = _milliseconds(_optional_string(item, field), field=field)
        if value is not None:
            return value, TradableAtSource.EXCHANGE_CONTINUOUS
    value = _milliseconds(_optional_string(item, "listTime"), field="listTime")
    if value is None:
        return None, None
    return value, TradableAtSource.EXCHANGE_LAUNCH


def _spot_identity(item: Mapping[str, JsonPayload]) -> tuple[str, str, None]:
    base = _required_string(item, "baseCcy")
    quote = _required_string(item, "quoteCcy")
    return base, quote, None


def _linear_swap_identity(
    item: Mapping[str, JsonPayload],
    *,
    settlement_asset: str,
) -> tuple[str, str, str] | None:
    if item.get("ctType") != "linear" or item.get("settleCcy") != settlement_asset:
        return None
    base = _required_string(item, "ctValCcy")
    return base, settlement_asset, settlement_asset


def parse_instruments(
    payload: object,
    market: Market,
    *,
    observed_at_ns: int,
    settlement_asset: str = "USDT",
) -> CompleteCatalogSnapshot:
    """Parse one complete OKX SPOT or linear-SWAP instrument response."""

    if type(market) is not Market:
        raise TypeError("market must be Market")
    if type(observed_at_ns) is not int or not 0 <= observed_at_ns <= _MAX_SIGNED_64:
        raise ValueError("observed_at_ns must fit signed 64-bit nanoseconds")
    if type(settlement_asset) is not str or not settlement_asset:
        raise ValueError("settlement_asset must be a non-empty string")

    expected_type = _EXPECTED_INST_TYPE[market]
    instruments: list[InstrumentRecord] = []
    raw_reference = _raw_reference(payload, kind=f"instruments-{market.value}")
    for item in _success_data(payload):
        if item.get("instType") != expected_type:
            raise OkxPayloadError(
                f"OKX instrument row does not match requested {expected_type} type"
            )
        instrument_key = _required_string(item, "instId")
        state = _required_string(item, "state")
        if market is Market.SPOT:
            base, quote, settlement = _spot_identity(item)
            wire_symbols = {
                "rest": instrument_key,
                "websocket": instrument_key,
            }
        else:
            identity = _linear_swap_identity(
                item,
                settlement_asset=settlement_asset,
            )
            if identity is None:
                continue
            base, quote, settlement = identity
            wire_symbols = {
                "rest": instrument_key,
                "websocket": instrument_key,
                "index": _required_string(item, "uly"),
                "instrument_family": _required_string(item, "instFamily"),
            }
        tradable_at_ns, tradable_at_source = _official_tradable_time(item)
        instruments.append(
            InstrumentRecord(
                exchange=Exchange.OKX,
                market=market,
                instrument_key=instrument_key,
                canonical_pair=f"{base}/{quote}",
                wire_symbols=wire_symbols,
                base_asset=base,
                quote_asset=quote,
                settlement_asset=settlement,
                status=state,
                lifecycle_phase=_PHASE_BY_STATE.get(
                    state,
                    LifecyclePhase.UNKNOWN,
                ),
                tradable=state in _TRADABLE_STATES,
                lifecycle=item,
                tradable_at_ns=tradable_at_ns,
                tradable_at_source=tradable_at_source,
                turnover=None,
                raw_catalog_reference=raw_reference,
            )
        )

    ordered = tuple(sorted(instruments, key=lambda item: item.instrument_key))
    return CompleteCatalogSnapshot(
        scope=CatalogScope(Exchange.OKX, market),
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
    item: Mapping[str, JsonPayload],
    field: str,
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
    catalog: CompleteCatalogSnapshot,
    catalog_revision: int,
    observed_at_ns: int,
) -> CompleteTurnoverSnapshot:
    """Build quote-currency turnover without treating SWAP contracts as volume."""

    if type(market) is not Market:
        raise TypeError("market must be Market")
    if type(catalog_revision) is not int or catalog_revision <= 0:
        raise ValueError("catalog_revision must be positive")
    if type(catalog) is not CompleteCatalogSnapshot:
        raise TypeError("catalog must be CompleteCatalogSnapshot")
    expected_scope = CatalogScope(Exchange.OKX, market)
    if catalog.scope != expected_scope:
        raise ValueError("catalog scope does not match the requested OKX market")
    if type(observed_at_ns) is not int or not 0 <= observed_at_ns <= _MAX_SIGNED_64:
        raise ValueError("observed_at_ns must fit signed 64-bit nanoseconds")
    if observed_at_ns < catalog.observed_at_ns:
        raise ValueError("turnover observation cannot precede its catalog")
    records = catalog.instruments
    by_key = {
        item.instrument_key: item
        for item in records
        if item.exchange is Exchange.OKX and item.market is market
    }
    rows = _success_data(payload)
    raw_reference = _raw_reference(payload, kind=f"tickers-{market.value}")
    observations: list[TurnoverObservation] = []
    covered = tuple(sorted(by_key))
    for item in rows:
        if item.get("instType") != _EXPECTED_INST_TYPE[market]:
            raise OkxPayloadError("OKX ticker row has the wrong instrument type")
        instrument_key = _required_string(item, "instId")
        instrument = by_key.get(instrument_key)
        if instrument is None:
            continue
        native_volume = _optional_decimal_string(item, "volCcy24h")
        if native_volume is None:
            continue
        if market is Market.SPOT:
            value = native_volume
            method = TurnoverMethod.EXCHANGE_QUOTE_TURNOVER
        else:
            reference_price = _optional_decimal_string(item, "last")
            if reference_price is None:
                continue
            value = native_volume * reference_price
            method = TurnoverMethod.BASE_VOLUME_X_REFERENCE_PRICE
        observations.append(
            TurnoverObservation(
                instrument_key=instrument_key,
                value=value,
                method=method,
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
    """Expose immutable lifecycle payloads for audit/test tooling."""

    for instrument in catalog.instruments:
        if not isinstance(instrument.lifecycle, Mapping):
            raise OkxPayloadError("OKX catalog lifecycle payload must be an object")
        yield cast(Mapping[str, object], instrument.lifecycle)


__all__ = [
    "instrument_by_key",
    "iter_raw_catalog_payloads",
    "parse_instruments",
    "parse_tickers",
]
