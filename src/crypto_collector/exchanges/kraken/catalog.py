from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import cast

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import JsonPayload, encode_json
from crypto_collector.exchanges.kraken.errors import KrakenPayloadError
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

_MAX_SIGNED_64 = 2**63 - 1
_SPOT_ASSET_ALIASES = {
    "XBT": "BTC",
    "XXBT": "BTC",
    "XDG": "DOGE",
    "XXDG": "DOGE",
    "XETH": "ETH",
    "ZUSD": "USD",
    "ZEUR": "EUR",
    "ZGBP": "GBP",
    "ZJPY": "JPY",
    "ZCAD": "CAD",
    "ZAUD": "AUD",
}
_SPOT_TRADABLE = frozenset({"online", "limit_only", "post_only", "reduce_only"})
_SPOT_PHASE = {
    "online": LifecyclePhase.TRADABLE,
    "limit_only": LifecyclePhase.TRADABLE,
    "post_only": LifecyclePhase.TRADABLE,
    "reduce_only": LifecyclePhase.TRADABLE,
    "cancel_only": LifecyclePhase.PAUSED,
    "maintenance": LifecyclePhase.PAUSED,
    "delisted": LifecyclePhase.DELISTED,
    "work_in_progress": LifecyclePhase.PREOPEN,
}
_PERPETUAL_PREFIXES = ("PF_", "PI_")
_NON_CRYPTO_FUTURES_CATEGORIES = frozenset(
    {"Commodities", "Forex", "Pre-IPO", "xStocks"}
)


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise KrakenPayloadError(f"{field} must be a JSON object")
    return cast(Mapping[str, JsonPayload], value)


def _sequence(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        raise KrakenPayloadError(f"{field} must be an array")
    return cast(Sequence[object], value)


def _required_string(item: Mapping[str, JsonPayload], field: str) -> str:
    value = item.get(field)
    if type(value) is not str or not value:
        raise KrakenPayloadError(f"Kraken {field} must be a non-empty string")
    return value


def _required_bool(item: Mapping[str, JsonPayload], field: str) -> bool:
    value = item.get(field)
    if type(value) is not bool:
        raise KrakenPayloadError(f"Kraken {field} must be a boolean")
    return value


def _raw_reference(payload: object, *, kind: str) -> str:
    try:
        digest = sha256(encode_json(payload)).hexdigest()
    except (TypeError, ValueError) as error:
        raise KrakenPayloadError("Kraken payload is not exact finite JSON") from error
    return f"kraken:{kind}:sha256:{digest}"


def _snapshot_id(*, market: Market, kind: str, raw_reference: str) -> str:
    digest = sha256(
        f"kraken\0{market.value}\0{kind}\0{raw_reference}".encode()
    ).hexdigest()
    return f"kraken:{market.value}:{kind}:{digest}"


def _observed(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SIGNED_64:
        raise ValueError("observed_at_ns must fit signed 64-bit nanoseconds")
    return value


def _canonical_spot_asset(value: str) -> str:
    return _SPOT_ASSET_ALIASES.get(value, value)


def _spot_identity(
    result_key: str,
    item: Mapping[str, JsonPayload],
) -> tuple[str, str, str, str, str]:
    ws_v1 = _required_string(item, "wsname")
    parts = ws_v1.split("/")
    if len(parts) != 2 or any(not part for part in parts):
        raise KrakenPayloadError("Kraken wsname must be BASE/QUOTE")
    base = _canonical_spot_asset(parts[0])
    quote = _canonical_spot_asset(parts[1])
    ws_v2 = f"{base}/{quote}"
    rest_altname = _required_string(item, "altname")
    return base, quote, ws_v1, ws_v2, rest_altname


def _spot_envelope(payload: object) -> Mapping[str, JsonPayload]:
    envelope = _mapping(payload, field="Kraken Spot response")
    errors = envelope.get("error")
    if errors != []:
        raise KrakenPayloadError("Kraken Spot catalog requires an empty error array")
    return _mapping(envelope.get("result"), field="Kraken Spot result")


def parse_spot_pairs(
    payload: object, *, observed_at_ns: int
) -> CompleteCatalogSnapshot:
    observed = _observed(observed_at_ns)
    result = _spot_envelope(payload)
    raw_reference = _raw_reference(payload, kind="spot-asset-pairs")
    instruments: list[InstrumentRecord] = []
    for result_key, value in result.items():
        item = _mapping(value, field=f"Kraken AssetPairs.{result_key}")
        base, quote, ws_v1, ws_v2, rest_altname = _spot_identity(result_key, item)
        status = _required_string(item, "status")
        instruments.append(
            InstrumentRecord(
                exchange=Exchange.KRAKEN,
                market=Market.SPOT,
                instrument_key=ws_v2,
                canonical_pair=ws_v2,
                wire_symbols={
                    "rest_query": ws_v2.replace("/", ""),
                    "rest_result": result_key,
                    "rest_altname": rest_altname,
                    "ws_v1": ws_v1,
                    "ws_v2": ws_v2,
                },
                base_asset=base,
                quote_asset=quote,
                settlement_asset=None,
                status=status,
                lifecycle_phase=_SPOT_PHASE.get(status, LifecyclePhase.UNKNOWN),
                tradable=status in _SPOT_TRADABLE,
                lifecycle=item,
                tradable_at_ns=None,
                tradable_at_source=None,
                turnover=None,
                raw_catalog_reference=raw_reference,
            )
        )
    ordered = tuple(sorted(instruments, key=lambda item: item.instrument_key))
    return CompleteCatalogSnapshot(
        scope=CatalogScope(Exchange.KRAKEN, Market.SPOT),
        observed_at_ns=observed,
        snapshot_id=_snapshot_id(
            market=Market.SPOT,
            kind="catalog",
            raw_reference=raw_reference,
        ),
        pages=(SnapshotPage(raw_reference, None, None),),
        reported_total_count=None,
        authoritative_empty=not ordered,
        instruments=ordered,
    )


def _rfc3339_ns(value: object, *, field: str) -> int | None:
    if value is None or value == "":
        return None
    if type(value) is not str:
        raise KrakenPayloadError(f"Kraken {field} must be an RFC3339 string")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise KrakenPayloadError(f"Kraken {field} must be an RFC3339 string") from error
    if parsed.tzinfo is None:
        raise KrakenPayloadError(f"Kraken {field} must include a timezone")
    normalized = parsed.astimezone(UTC)
    nanoseconds = int(normalized.timestamp()) * 1_000_000_000
    nanoseconds += normalized.microsecond * 1_000
    if not 0 <= nanoseconds <= _MAX_SIGNED_64:
        raise KrakenPayloadError(f"Kraken {field} overflows signed 64-bit nanoseconds")
    return nanoseconds


def _futures_rows(payload: object, *, field: str) -> Sequence[object]:
    envelope = _mapping(payload, field="Kraken Futures response")
    if envelope.get("result") != "success":
        raise KrakenPayloadError("Kraken Futures parser requires result=success")
    return _sequence(envelope.get(field), field=f"Kraken Futures {field}")


def _futures_ticker_rows(
    payload: object,
) -> Mapping[str, Mapping[str, JsonPayload]]:
    tickers: dict[str, Mapping[str, JsonPayload]] = {}
    for index, value in enumerate(_futures_rows(payload, field="tickers")):
        row = _mapping(value, field=f"Kraken Futures tickers[{index}]")
        symbol = _required_string(row, "symbol")
        if symbol in tickers:
            raise KrakenPayloadError("Kraken Futures ticker symbols must be unique")
        tickers[symbol] = row
    return tickers


def _futures_ticker_status(
    row: Mapping[str, JsonPayload],
) -> tuple[bool, bool]:
    suspended = row.get("suspended")
    post_only = row.get("postOnly")
    if type(suspended) is not bool or type(post_only) is not bool:
        raise KrakenPayloadError(
            "Kraken Futures ticker status requires suspended and postOnly booleans"
        )
    return suspended, post_only


def parse_futures_instruments(
    payload: object,
    *,
    tickers_payload: object,
    observed_at_ns: int,
) -> CompleteCatalogSnapshot:
    observed = _observed(observed_at_ns)
    instruments_reference = _raw_reference(payload, kind="futures-instruments")
    tickers_reference = _raw_reference(tickers_payload, kind="futures-tickers")
    raw_reference = (
        "kraken:futures-catalog:sources:"
        f"instruments-sha256={instruments_reference.rsplit(':', 1)[1]};"
        f"tickers-sha256={tickers_reference.rsplit(':', 1)[1]}"
    )
    tickers = _futures_ticker_rows(tickers_payload)
    instruments: list[InstrumentRecord] = []
    for index, value in enumerate(_futures_rows(payload, field="instruments")):
        item = _mapping(value, field=f"Kraken Futures instruments[{index}]")
        symbol = _required_string(item, "symbol")
        if not symbol.startswith(_PERPETUAL_PREFIXES):
            continue
        tradfi = _required_bool(item, "tradfi")
        category = item.get("category")
        if type(category) is not str:
            raise KrakenPayloadError("Kraken category must be a string")
        if tradfi or category in _NON_CRYPTO_FUTURES_CATEGORIES:
            continue
        base = _required_string(item, "base")
        quote = _required_string(item, "quote")
        _required_bool(item, "tradeable")
        expired = _required_bool(item, "isExpired")
        opening_ns = _rfc3339_ns(item.get("openingDate"), field="openingDate")
        ticker = tickers.get(symbol)
        ticker_status = None if ticker is None else _futures_ticker_status(ticker)
        if expired:
            status = "expired"
            phase = LifecyclePhase.DELISTED
            tradable = False
        elif opening_ns is not None and opening_ns > observed:
            status = "preopen"
            phase = LifecyclePhase.PREOPEN
            tradable = False
        elif ticker is None:
            raise KrakenPayloadError(
                "Kraken Futures full tickers lack an opened catalog instrument"
            )
        elif ticker_status is not None and ticker_status[0]:
            status = "suspended"
            phase = LifecyclePhase.PAUSED
            tradable = False
        elif ticker_status is not None and ticker_status[1]:
            status = "post_only"
            phase = LifecyclePhase.TRADABLE
            tradable = True
        else:
            status = "online"
            phase = LifecyclePhase.TRADABLE
            tradable = True
        lifecycle: dict[str, JsonPayload] = {
            "native_instrument": dict(item),
            "native_ticker_status": (
                None
                if ticker is None
                else {
                    "suspended": ticker["suspended"],
                    "postOnly": ticker["postOnly"],
                }
            ),
            "collector_evidence": {
                "instruments": instruments_reference,
                "tickers": tickers_reference,
            },
        }
        instruments.append(
            InstrumentRecord(
                exchange=Exchange.KRAKEN,
                market=Market.PERPETUAL,
                instrument_key=symbol,
                canonical_pair=f"{base}/{quote}",
                wire_symbols={
                    "rest": symbol,
                    "websocket": symbol,
                    "charts": symbol,
                },
                base_asset=base,
                quote_asset=quote,
                # The public instrument response does not declare settlement asset.
                settlement_asset=None,
                status=status,
                lifecycle_phase=phase,
                tradable=tradable,
                lifecycle=lifecycle,
                tradable_at_ns=opening_ns,
                tradable_at_source=(
                    TradableAtSource.EXCHANGE_LAUNCH if opening_ns is not None else None
                ),
                turnover=None,
                raw_catalog_reference=raw_reference,
            )
        )
    ordered = tuple(sorted(instruments, key=lambda item: item.instrument_key))
    return CompleteCatalogSnapshot(
        scope=CatalogScope(Exchange.KRAKEN, Market.PERPETUAL),
        observed_at_ns=observed,
        snapshot_id=_snapshot_id(
            market=Market.PERPETUAL,
            kind="catalog",
            raw_reference=raw_reference,
        ),
        pages=(SnapshotPage(raw_reference, None, None),),
        reported_total_count=None,
        authoritative_empty=not ordered,
        instruments=ordered,
    )


def _exact_decimal(value: object, *, field: str) -> Decimal | None:
    if value is None or value == "":
        return None
    if type(value) is int:
        parsed = Decimal(value)
    elif type(value) is str:
        try:
            parsed = Decimal(value)
        except InvalidOperation:
            return None
    elif type(value) is Decimal:
        parsed = value
    else:
        raise KrakenPayloadError(f"Kraken {field} must not pass through float")
    return parsed if parsed.is_finite() and parsed >= 0 else None


def _catalog_keys(
    catalog: CompleteCatalogSnapshot,
    *,
    market: Market,
) -> dict[str, InstrumentRecord]:
    if type(catalog) is not CompleteCatalogSnapshot:
        raise TypeError("catalog must be CompleteCatalogSnapshot")
    if catalog.scope != CatalogScope(Exchange.KRAKEN, market):
        raise ValueError("catalog scope does not match Kraken market")
    return {item.instrument_key: item for item in catalog.instruments}


def parse_spot_tickers(
    payload: object,
    *,
    catalog: CompleteCatalogSnapshot,
    catalog_revision: int,
    observed_at_ns: int,
) -> CompleteTurnoverSnapshot:
    if type(catalog_revision) is not int or catalog_revision <= 0:
        raise ValueError("catalog_revision must be positive")
    observed = _observed(observed_at_ns)
    if observed < catalog.observed_at_ns:
        raise ValueError("turnover observation cannot precede catalog")
    instruments = _catalog_keys(catalog, market=Market.SPOT)
    by_result = {item.wire_symbol("rest_result"): item for item in instruments.values()}
    result = _spot_envelope(payload)
    raw_reference = _raw_reference(payload, kind="spot-tickers")
    observations: list[TurnoverObservation] = []
    seen: set[str] = set()
    for result_key, value in result.items():
        instrument = by_result.get(result_key)
        if instrument is None:
            continue
        seen.add(instrument.instrument_key)
        row = _mapping(value, field=f"Kraken Spot ticker.{result_key}")
        volumes = _sequence(row.get("v"), field="ticker.v")
        vwaps = _sequence(row.get("p"), field="ticker.p")
        if len(volumes) < 2 or len(vwaps) < 2:
            continue
        base_volume = _exact_decimal(volumes[1], field="ticker.v[1]")
        vwap = _exact_decimal(vwaps[1], field="ticker.p[1]")
        if base_volume is None or vwap is None:
            continue
        observations.append(
            TurnoverObservation(
                instrument_key=instrument.instrument_key,
                value=base_volume * vwap,
                method=TurnoverMethod.BASE_VOLUME_X_REFERENCE_PRICE,
                currency=instrument.quote_asset,
                raw_reference=raw_reference,
            )
        )
    if seen != set(instruments):
        raise KrakenPayloadError(
            "Kraken Spot complete ticker response lacks catalog instruments"
        )
    ordered = tuple(sorted(observations, key=lambda item: item.instrument_key))
    covered = tuple(sorted(seen))
    return CompleteTurnoverSnapshot(
        scope=CatalogScope(Exchange.KRAKEN, Market.SPOT),
        catalog_revision=catalog_revision,
        observed_at_ns=observed,
        snapshot_id=_snapshot_id(
            market=Market.SPOT,
            kind="turnover",
            raw_reference=raw_reference,
        ),
        pages=(SnapshotPage(raw_reference, None, None),),
        reported_total_count=None,
        authoritative_empty=not covered,
        covered_instrument_keys=covered,
        observations=ordered,
    )


def parse_futures_tickers(
    payload: object,
    *,
    catalog: CompleteCatalogSnapshot,
    catalog_revision: int,
    observed_at_ns: int,
) -> CompleteTurnoverSnapshot:
    if type(catalog_revision) is not int or catalog_revision <= 0:
        raise ValueError("catalog_revision must be positive")
    observed = _observed(observed_at_ns)
    if observed < catalog.observed_at_ns:
        raise ValueError("turnover observation cannot precede catalog")
    instruments = _catalog_keys(catalog, market=Market.PERPETUAL)
    raw_reference = _raw_reference(payload, kind="futures-tickers")
    observations: list[TurnoverObservation] = []
    seen: set[str] = set()
    ticker_rows = _futures_ticker_rows(payload)
    for symbol, row in ticker_rows.items():
        instrument = instruments.get(symbol)
        if instrument is None:
            continue
        _futures_ticker_status(row)
        seen.add(symbol)
        quote_volume = _exact_decimal(row.get("volumeQuote"), field="volumeQuote")
        if quote_volume is None:
            continue
        observations.append(
            TurnoverObservation(
                instrument_key=symbol,
                value=quote_volume,
                method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
                currency=instrument.quote_asset,
                raw_reference=raw_reference,
            )
        )
    required = {
        key
        for key, instrument in instruments.items()
        if instrument.lifecycle_phase
        not in {LifecyclePhase.PREOPEN, LifecyclePhase.DELISTED}
    }
    if not required.issubset(seen):
        raise KrakenPayloadError(
            "Kraken Futures complete ticker response lacks opened catalog instruments"
        )
    ordered = tuple(sorted(observations, key=lambda item: item.instrument_key))
    covered = tuple(sorted(seen))
    return CompleteTurnoverSnapshot(
        scope=CatalogScope(Exchange.KRAKEN, Market.PERPETUAL),
        catalog_revision=catalog_revision,
        observed_at_ns=observed,
        snapshot_id=_snapshot_id(
            market=Market.PERPETUAL,
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
    if type(instrument_key) is not str or not instrument_key:
        raise ValueError("instrument_key must be a non-empty string")
    for instrument in catalog.instruments:
        if instrument.instrument_key == instrument_key:
            return instrument
    raise KeyError(instrument_key)


__all__ = [
    "instrument_by_key",
    "parse_futures_instruments",
    "parse_futures_tickers",
    "parse_spot_pairs",
    "parse_spot_tickers",
]
