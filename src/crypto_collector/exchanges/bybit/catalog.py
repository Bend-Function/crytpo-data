from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from typing import cast

from crypto_collector.domain import Exchange, Market
from crypto_collector.domain.json_codec import JsonPayload, encode_json
from crypto_collector.exchanges.bybit.errors import BybitPayloadError
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
_CATEGORY_BY_MARKET = {
    Market.SPOT: "spot",
    Market.PERPETUAL: "linear",
}
_PHASE_BY_STATUS = {
    "Trading": LifecyclePhase.TRADABLE,
    "PreLaunch": LifecyclePhase.PREOPEN,
}


def _mapping(value: object, *, field: str) -> Mapping[str, JsonPayload]:
    if not isinstance(value, Mapping) or any(type(key) is not str for key in value):
        raise BybitPayloadError(f"{field} must be a JSON object")
    return cast(Mapping[str, JsonPayload], value)


def _required_string(item: Mapping[str, JsonPayload], field: str) -> str:
    value = item.get(field)
    if type(value) is not str or not value:
        raise BybitPayloadError(f"Bybit {field} must be a non-empty string")
    return value


def _optional_string(item: Mapping[str, JsonPayload], field: str) -> str | None:
    value = item.get(field)
    if value is None or value == "":
        return None
    if type(value) is not str:
        raise BybitPayloadError(f"Bybit {field} must be a string")
    return value


def _milliseconds(value: str | None, *, field: str) -> int | None:
    if value is None:
        return None
    if not value.isascii() or not value.isdigit():
        raise BybitPayloadError(f"Bybit {field} must be milliseconds since Unix epoch")
    nanoseconds = int(value) * _MILLISECONDS_TO_NANOSECONDS
    if nanoseconds > _MAX_SIGNED_64:
        raise BybitPayloadError(f"Bybit {field} does not fit signed 64-bit nanoseconds")
    return nanoseconds


def _raw_reference(payload: object, *, kind: str) -> str:
    try:
        digest = sha256(encode_json(payload)).hexdigest()
    except (TypeError, ValueError) as error:
        raise BybitPayloadError("Bybit payload is not exact finite JSON") from error
    return f"bybit:{kind}:sha256:{digest}"


def _snapshot_id(
    *,
    market: Market,
    kind: str,
    raw_references: tuple[str, ...],
) -> str:
    digest = sha256(
        b"\0".join(
            (
                b"bybit",
                market.value.encode(),
                kind.encode(),
                *(reference.encode() for reference in raw_references),
            )
        )
    ).hexdigest()
    return f"bybit:{market.value}:{kind}:{digest}"


def _success_result(payload: object) -> Mapping[str, JsonPayload]:
    envelope = _mapping(payload, field="Bybit response")
    ret_code = envelope.get("retCode")
    if type(ret_code) is not int or ret_code != 0:
        raise BybitPayloadError("Bybit parser requires a successful integer retCode=0")
    if type(envelope.get("retMsg")) is not str:
        raise BybitPayloadError("Bybit response retMsg must be a string")
    return _mapping(envelope.get("result"), field="Bybit response result")


def _result_rows(
    result: Mapping[str, JsonPayload],
) -> tuple[Mapping[str, JsonPayload], ...]:
    rows = result.get("list")
    if not isinstance(rows, (list, tuple)):
        raise BybitPayloadError("Bybit response result.list must be an array")
    return tuple(
        _mapping(row, field=f"Bybit response result.list[{index}]")
        for index, row in enumerate(rows)
    )


def _next_cursor(
    result: Mapping[str, JsonPayload],
    *,
    market: Market,
) -> str | None:
    cursor = result.get("nextPageCursor")
    if market is Market.SPOT:
        if cursor is None or cursor == "":
            return None
        if type(cursor) is not str:
            raise BybitPayloadError(
                "Bybit Spot catalog nextPageCursor must be absent or an empty string"
            )
        raise BybitPayloadError("Bybit Spot catalog must not paginate")
    if type(cursor) is not str:
        raise BybitPayloadError("Bybit Linear catalog nextPageCursor must be a string")
    return cursor or None


@dataclass(frozen=True, slots=True)
class BybitCatalogPage:
    payload: object
    request_cursor: str | None = None

    def __post_init__(self) -> None:
        cursor = self.request_cursor
        if cursor is not None and (type(cursor) is not str or not cursor):
            raise ValueError("request_cursor must be a non-empty string or None")


@dataclass(frozen=True, slots=True)
class BybitCatalogChain:
    status: str | None
    pages: tuple[BybitCatalogPage, ...]

    def __post_init__(self) -> None:
        if self.status not in {None, "Trading", "PreLaunch"}:
            raise ValueError("catalog chain status must be Trading, PreLaunch, or None")
        if type(self.pages) is not tuple or not self.pages:
            raise ValueError("catalog chain pages must be a non-empty tuple")
        if any(type(page) is not BybitCatalogPage for page in self.pages):
            raise TypeError("catalog chain pages must contain BybitCatalogPage values")


@dataclass(frozen=True, slots=True)
class BybitCatalogPageEvidence:
    request_cursor: str | None
    next_cursor: str | None
    raw_reference: str


@dataclass(frozen=True, slots=True)
class BybitCatalogChainEvidence:
    status: str | None
    pages: tuple[BybitCatalogPageEvidence, ...]


@dataclass(frozen=True, slots=True)
class BybitCatalogTransition:
    instrument_key: str
    prelaunch_raw_reference: str
    trading_raw_reference: str


class BybitCatalogRaceError(BybitPayloadError):
    """Two independently fetched lifecycle chains overlapped and are not atomic."""

    def __init__(self, transitions: tuple[BybitCatalogTransition, ...]) -> None:
        if not transitions:
            raise ValueError("catalog race error requires transition evidence")
        self.transitions = transitions
        symbols = ", ".join(item.instrument_key for item in transitions)
        super().__init__(
            f"Bybit catalog status chains overlap for {symbols}; retry the full catalog round"
        )


@dataclass(frozen=True, slots=True)
class BybitCatalogParseResult:
    snapshot: CompleteCatalogSnapshot
    chains: tuple[BybitCatalogChainEvidence, ...]
    transitions: tuple[BybitCatalogTransition, ...]
    manifest_bytes: bytes
    manifest_sha256: str
    manifest_reference: str

    @property
    def manifest_payload(self) -> Mapping[str, JsonPayload]:
        from crypto_collector.domain.json_codec import decode_json

        payload = decode_json(self.manifest_bytes)
        return _mapping(payload, field="Bybit catalog manifest")


def _continuous_trading_time(
    item: Mapping[str, JsonPayload],
    *,
    pre_listing: bool,
) -> tuple[int | None, bool]:
    info_value = item.get("preListingInfo")
    if not pre_listing:
        if info_value is not None:
            raise BybitPayloadError(
                "Bybit preListingInfo must be null when isPreListing is false"
            )
        return None, False
    if info_value is None:
        raise BybitPayloadError(
            "Bybit preListingInfo must be an object when isPreListing is true"
        )
    info = _mapping(info_value, field="Bybit preListingInfo")
    current_phase = info.get("curAuctionPhase")
    if current_phase is not None and type(current_phase) is not str:
        raise BybitPayloadError("Bybit curAuctionPhase must be a string")
    skip_call_auction = info.get("skipCallAuction", False)
    if type(skip_call_auction) is not bool:
        raise BybitPayloadError("Bybit skipCallAuction must be a boolean")
    phases = info.get("phases")
    if not isinstance(phases, (list, tuple)):
        raise BybitPayloadError("Bybit preListingInfo.phases must be an array")
    continuous: int | None = None
    for index, phase_value in enumerate(phases):
        phase = _mapping(
            phase_value,
            field=f"Bybit preListingInfo.phases[{index}]",
        )
        name = _required_string(phase, "phase")
        start = _milliseconds(
            _required_string(phase, "startTime"),
            field="preListingInfo.phases[].startTime",
        )
        _milliseconds(
            _optional_string(phase, "endTime"),
            field="preListingInfo.phases[].endTime",
        )
        if name == "ContinuousTrading":
            if continuous is not None:
                raise BybitPayloadError(
                    "Bybit preListingInfo has duplicate ContinuousTrading phases"
                )
            continuous = start
    return continuous, skip_call_auction


def _official_tradable_time(
    item: Mapping[str, JsonPayload],
    *,
    status: str,
    observed_at_ns: int,
) -> tuple[int | None, TradableAtSource | None]:
    pre_listing = item.get("isPreListing")
    if type(pre_listing) is not bool:
        raise BybitPayloadError("Bybit isPreListing must be a boolean")
    continuous, skip_call_auction = _continuous_trading_time(
        item,
        pre_listing=pre_listing,
    )
    launch = _milliseconds(
        _required_string(item, "launchTime"),
        field="launchTime",
    )
    if status == "PreLaunch":
        if (
            not skip_call_auction
            and continuous is not None
            and continuous > observed_at_ns
        ):
            return continuous, TradableAtSource.EXCHANGE_CONTINUOUS
        if launch is not None and launch > observed_at_ns:
            return launch, TradableAtSource.EXCHANGE_LAUNCH
        return None, None
    if continuous is not None and not skip_call_auction:
        return continuous, TradableAtSource.EXCHANGE_CONTINUOUS
    if launch is not None:
        return launch, TradableAtSource.EXCHANGE_LAUNCH
    return None, None


def _validate_decimal_text(value: object, *, field: str) -> None:
    if type(value) is not str or not value:
        raise BybitPayloadError(f"Bybit {field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise BybitPayloadError(f"Bybit {field} must be a decimal string") from error
    if not parsed.is_finite():
        raise BybitPayloadError(f"Bybit {field} must be a finite decimal string")


def _validate_instrument_decimal_fields(item: Mapping[str, JsonPayload]) -> None:
    for field in ("priceScale", "upperFundingRate", "lowerFundingRate"):
        value = item.get(field)
        if value is not None:
            _validate_decimal_text(value, field=field)
    nested_fields = {
        "leverageFilter": ("minLeverage", "maxLeverage", "leverageStep"),
        "priceFilter": ("minPrice", "maxPrice", "tickSize"),
        "lotSizeFilter": (
            "maxOrderQty",
            "minOrderQty",
            "qtyStep",
            "postOnlyMaxOrderQty",
            "maxMktOrderQty",
            "minNotionalValue",
            "basePrecision",
            "quotePrecision",
            "maxOrderAmt",
            "minOrderAmt",
            "maxLimitOrderQty",
            "maxMarketOrderQty",
            "postOnlyMaxLimitOrderSize",
        ),
        "riskParameters": ("priceLimitRatioX", "priceLimitRatioY"),
    }
    for container_name, fields in nested_fields.items():
        container_value = item.get(container_name)
        if container_value is None:
            continue
        container = _mapping(container_value, field=f"Bybit {container_name}")
        for field in fields:
            value = container.get(field)
            if value is not None:
                _validate_decimal_text(value, field=f"{container_name}.{field}")


def _instrument(
    item: Mapping[str, JsonPayload],
    *,
    market: Market,
    raw_reference: str,
    settlement_asset: str,
    observed_at_ns: int,
) -> InstrumentRecord | None:
    symbol = _required_string(item, "symbol")
    status = _required_string(item, "status")
    base = _required_string(item, "baseCoin")
    quote = _required_string(item, "quoteCoin")
    if market is Market.PERPETUAL:
        contract_type = _required_string(item, "contractType")
        if contract_type != "LinearPerpetual":
            return None
        settlement = _required_string(item, "settleCoin")
        if quote != settlement_asset or settlement != settlement_asset:
            return None
    else:
        settlement = None
    _validate_instrument_decimal_fields(item)
    if market is Market.PERPETUAL:
        tradable_at_ns, tradable_at_source = _official_tradable_time(
            item,
            status=status,
            observed_at_ns=observed_at_ns,
        )
    else:
        tradable_at_ns, tradable_at_source = None, None
    phase = _PHASE_BY_STATUS.get(status, LifecyclePhase.UNKNOWN)
    return InstrumentRecord(
        exchange=Exchange.BYBIT,
        market=market,
        instrument_key=symbol,
        canonical_pair=f"{base}/{quote}",
        wire_symbols={
            "rest": symbol,
            "websocket": symbol,
            **({"index": symbol} if market is Market.PERPETUAL else {}),
        },
        base_asset=base,
        quote_asset=quote,
        settlement_asset=settlement,
        status=status,
        lifecycle_phase=phase,
        tradable=phase is LifecyclePhase.TRADABLE,
        lifecycle=item,
        tradable_at_ns=tradable_at_ns,
        tradable_at_source=tradable_at_source,
        turnover=None,
        raw_catalog_reference=raw_reference,
    )


def _validate_row_chain_status(row_status: str, chain_status: str | None) -> None:
    if chain_status == "Trading" and row_status == "PreLaunch":
        raise BybitPayloadError("Bybit Trading chain returned a PreLaunch instrument")
    if chain_status == "PreLaunch" and row_status == "Trading":
        raise BybitPayloadError("Bybit PreLaunch chain returned a Trading instrument")
    if chain_status is None and row_status == "PreLaunch":
        raise BybitPayloadError("Bybit Spot catalog returned a PreLaunch instrument")


def _parse_chain(
    chain: BybitCatalogChain,
    *,
    market: Market,
    settlement_asset: str,
    observed_at_ns: int,
) -> tuple[BybitCatalogChainEvidence, tuple[InstrumentRecord, ...]]:
    if chain.pages[0].request_cursor is not None:
        raise BybitPayloadError("Bybit catalog chain must start without a cursor")
    if market is Market.SPOT and len(chain.pages) != 1:
        raise BybitPayloadError("Bybit Spot catalog must contain exactly one page")

    expected_category = _CATEGORY_BY_MARKET[market]
    evidence: list[BybitCatalogPageEvidence] = []
    instruments: list[InstrumentRecord] = []
    seen_request_cursors: set[str] = set()
    seen_instruments: set[str] = set()
    expected_request_cursor: str | None = None
    chain_name = "spot" if chain.status is None else chain.status.casefold()
    for index, page in enumerate(chain.pages):
        if page.request_cursor != expected_request_cursor:
            raise BybitPayloadError("Bybit catalog cursor chain is not contiguous")
        if page.request_cursor is not None:
            if page.request_cursor in seen_request_cursors:
                raise BybitPayloadError("Bybit catalog request cursor repeats")
            seen_request_cursors.add(page.request_cursor)
        result = _success_result(page.payload)
        if result.get("category") != expected_category:
            raise BybitPayloadError(
                "Bybit catalog result category does not match market"
            )
        next_cursor = _next_cursor(result, market=market)
        if market is Market.SPOT and next_cursor is not None:
            raise BybitPayloadError("Bybit Spot catalog must not paginate")
        if next_cursor is not None and (
            next_cursor == page.request_cursor or next_cursor in seen_request_cursors
        ):
            raise BybitPayloadError("Bybit catalog response cursor does not advance")
        if index < len(chain.pages) - 1 and next_cursor is None:
            raise BybitPayloadError(
                "Bybit catalog pages continue after a terminal cursor"
            )
        if index == len(chain.pages) - 1 and next_cursor is not None:
            raise BybitPayloadError("Bybit catalog cursor chain is incomplete")

        raw_reference = _raw_reference(
            page.payload,
            kind=f"instruments-{market.value}-{chain_name}-page-{index + 1}",
        )
        evidence.append(
            BybitCatalogPageEvidence(
                request_cursor=page.request_cursor,
                next_cursor=next_cursor,
                raw_reference=raw_reference,
            )
        )
        for item in _result_rows(result):
            row_status = _required_string(item, "status")
            _validate_row_chain_status(row_status, chain.status)
            parsed = _instrument(
                item,
                market=market,
                raw_reference=raw_reference,
                settlement_asset=settlement_asset,
                observed_at_ns=observed_at_ns,
            )
            if parsed is None:
                continue
            if parsed.instrument_key in seen_instruments:
                raise BybitPayloadError(
                    "Bybit catalog chain contains a duplicate instrument"
                )
            seen_instruments.add(parsed.instrument_key)
            instruments.append(parsed)
        expected_request_cursor = next_cursor
    return (
        BybitCatalogChainEvidence(chain.status, tuple(evidence)),
        tuple(instruments),
    )


def _manifest_payload(
    *,
    market: Market,
    chains: tuple[BybitCatalogChainEvidence, ...],
) -> dict[str, JsonPayload]:
    return {
        "schema_version": 1,
        "exchange": "bybit",
        "market": market.value,
        "merge_policy": (
            "single_chain" if market is Market.SPOT else "reject_cross_chain_transition"
        ),
        "chains": [
            {
                "status": chain.status,
                "pages": [
                    {
                        "request_cursor": page.request_cursor,
                        "next_cursor": page.next_cursor,
                        "raw_reference": page.raw_reference,
                    }
                    for page in chain.pages
                ],
            }
            for chain in chains
        ],
    }


def parse_instrument_chains(
    chains: tuple[BybitCatalogChain, ...],
    market: Market,
    *,
    observed_at_ns: int,
    settlement_asset: str = "USDT",
) -> BybitCatalogParseResult:
    """Parse a Spot chain or both complete Linear lifecycle cursor chains."""

    if type(chains) is not tuple or not chains:
        raise ValueError("chains must be a non-empty tuple")
    if any(type(chain) is not BybitCatalogChain for chain in chains):
        raise TypeError("chains must contain BybitCatalogChain values")
    if type(market) is not Market:
        raise TypeError("market must be Market")
    if type(observed_at_ns) is not int or not 0 <= observed_at_ns <= _MAX_SIGNED_64:
        raise ValueError("observed_at_ns must fit signed 64-bit nanoseconds")
    if type(settlement_asset) is not str or not settlement_asset:
        raise ValueError("settlement_asset must be a non-empty string")

    by_status = {chain.status: chain for chain in chains}
    if len(by_status) != len(chains):
        raise BybitPayloadError("Bybit catalog chain statuses must be unique")
    canonical_inputs: tuple[BybitCatalogChain, ...]
    if market is Market.SPOT:
        if set(by_status) != {None}:
            raise BybitPayloadError("Bybit Spot catalog requires one unfiltered chain")
        canonical_inputs = (by_status[None],)
    else:
        if set(by_status) != {"Trading", "PreLaunch"}:
            raise BybitPayloadError(
                "Bybit Linear catalog requires Trading and PreLaunch chains"
            )
        canonical_inputs = (by_status["Trading"], by_status["PreLaunch"])

    parsed = tuple(
        _parse_chain(
            chain,
            market=market,
            settlement_asset=settlement_asset,
            observed_at_ns=observed_at_ns,
        )
        for chain in canonical_inputs
    )
    chain_evidence = tuple(item[0] for item in parsed)
    records_by_chain = {evidence.status: records for evidence, records in parsed}
    if market is Market.SPOT:
        winners = {record.instrument_key: record for record in records_by_chain[None]}
        transitions: tuple[BybitCatalogTransition, ...] = ()
    else:
        prelaunch = {
            record.instrument_key: record for record in records_by_chain["PreLaunch"]
        }
        trading = {
            record.instrument_key: record for record in records_by_chain["Trading"]
        }
        transitions = tuple(
            BybitCatalogTransition(
                instrument_key=key,
                prelaunch_raw_reference=prelaunch[key].raw_catalog_reference,
                trading_raw_reference=trading[key].raw_catalog_reference,
            )
            for key in sorted(prelaunch.keys() & trading.keys())
        )
        if transitions:
            raise BybitCatalogRaceError(transitions)
        winners = {**prelaunch, **trading}

    manifest_bytes = encode_json(
        _manifest_payload(market=market, chains=chain_evidence)
    )
    manifest_sha256 = sha256(manifest_bytes).hexdigest()
    manifest_reference = f"bybit:catalog-manifest:sha256:{manifest_sha256}"
    ordered = tuple(sorted(winners.values(), key=lambda item: item.instrument_key))
    try:
        snapshot = CompleteCatalogSnapshot(
            scope=CatalogScope(Exchange.BYBIT, market),
            observed_at_ns=observed_at_ns,
            snapshot_id=_snapshot_id(
                market=market,
                kind="catalog",
                raw_references=(manifest_reference,),
            ),
            pages=(SnapshotPage(manifest_reference, None, None),),
            reported_total_count=None,
            authoritative_empty=not ordered,
            instruments=ordered,
        )
    except ValueError as error:
        raise BybitPayloadError(f"invalid Bybit catalog snapshot: {error}") from error
    return BybitCatalogParseResult(
        snapshot=snapshot,
        chains=chain_evidence,
        transitions=transitions,
        manifest_bytes=manifest_bytes,
        manifest_sha256=manifest_sha256,
        manifest_reference=manifest_reference,
    )


def parse_instrument_pages(
    pages: tuple[BybitCatalogPage, ...],
    market: Market,
    *,
    observed_at_ns: int,
    settlement_asset: str = "USDT",
) -> CompleteCatalogSnapshot:
    """Convenience wrapper for the single non-paginated Spot catalog."""

    if market is not Market.SPOT:
        raise ValueError(
            "Bybit Linear catalog requires parse_instrument_chains with both statuses"
        )
    return parse_instrument_chains(
        (BybitCatalogChain(None, pages),),
        market,
        observed_at_ns=observed_at_ns,
        settlement_asset=settlement_asset,
    ).snapshot


def _decimal_string(
    item: Mapping[str, JsonPayload],
    field: str,
) -> Decimal | None:
    value = item.get(field)
    if value is None or value == "":
        return None
    if type(value) is not str:
        raise BybitPayloadError(f"Bybit {field} must be a decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise BybitPayloadError(f"Bybit {field} must be a decimal string") from error
    if not parsed.is_finite() or parsed < 0:
        raise BybitPayloadError(f"Bybit {field} must be finite and non-negative")
    return parsed


def parse_tickers(
    payload: object,
    *,
    market: Market,
    catalog: CompleteCatalogSnapshot,
    catalog_revision: int,
    observed_at_ns: int,
) -> CompleteTurnoverSnapshot:
    """Build comparable quote-currency turnover without filling sparse fields."""

    if type(market) is not Market:
        raise TypeError("market must be Market")
    if type(catalog) is not CompleteCatalogSnapshot:
        raise TypeError("catalog must be CompleteCatalogSnapshot")
    expected_scope = CatalogScope(Exchange.BYBIT, market)
    if catalog.scope != expected_scope:
        raise ValueError("catalog scope does not match the requested Bybit market")
    if type(catalog_revision) is not int or catalog_revision <= 0:
        raise ValueError("catalog_revision must be positive")
    if type(observed_at_ns) is not int or not 0 <= observed_at_ns <= _MAX_SIGNED_64:
        raise ValueError("observed_at_ns must fit signed 64-bit nanoseconds")
    if observed_at_ns < catalog.observed_at_ns:
        raise ValueError("turnover observation cannot precede its catalog")

    result = _success_result(payload)
    if result.get("category") != _CATEGORY_BY_MARKET[market]:
        raise BybitPayloadError("Bybit ticker result category does not match market")
    by_key = {item.instrument_key: item for item in catalog.instruments}
    raw_reference = _raw_reference(payload, kind=f"tickers-{market.value}")
    observations: list[TurnoverObservation] = []
    seen: set[str] = set()
    for row in _result_rows(result):
        symbol = _required_string(row, "symbol")
        if symbol in seen:
            raise BybitPayloadError("Bybit ticker response contains duplicate symbols")
        seen.add(symbol)
        instrument = by_key.get(symbol)
        if instrument is None:
            continue
        turnover = _decimal_string(row, "turnover24h")
        if turnover is None:
            continue
        observations.append(
            TurnoverObservation(
                instrument_key=symbol,
                value=turnover,
                method=TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
                currency=instrument.quote_asset,
                raw_reference=raw_reference,
            )
        )
    covered = tuple(sorted(by_key))
    return CompleteTurnoverSnapshot(
        scope=expected_scope,
        catalog_revision=catalog_revision,
        observed_at_ns=observed_at_ns,
        snapshot_id=_snapshot_id(
            market=market,
            kind="turnover",
            raw_references=(raw_reference,),
        ),
        pages=(SnapshotPage(raw_reference, None, None),),
        reported_total_count=None,
        authoritative_empty=not covered,
        covered_instrument_keys=covered,
        observations=tuple(
            sorted(observations, key=lambda observation: observation.instrument_key)
        ),
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
    for instrument in catalog.instruments:
        if not isinstance(instrument.lifecycle, Mapping):
            raise BybitPayloadError("Bybit catalog lifecycle payload must be an object")
        yield cast(Mapping[str, object], instrument.lifecycle)


__all__ = [
    "BybitCatalogChain",
    "BybitCatalogChainEvidence",
    "BybitCatalogPage",
    "BybitCatalogPageEvidence",
    "BybitCatalogParseResult",
    "BybitCatalogRaceError",
    "BybitCatalogTransition",
    "instrument_by_key",
    "iter_raw_catalog_payloads",
    "parse_instrument_chains",
    "parse_instrument_pages",
    "parse_tickers",
]
