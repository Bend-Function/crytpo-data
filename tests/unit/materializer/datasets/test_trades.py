from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from dataclasses import replace
from decimal import Decimal, getcontext, localcontext
from pathlib import Path
from typing import Any, cast

import pytest

from crypto_collector.domain.envelope import RawEnvelope, RestMetadata
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.materializer.datasets.trades import (
    AggressorSide,
    CandidateCoverage,
    DeduplicationMode,
    OkxLinearContractMetadata,
    OkxTradeNormalizer,
    TimedTrade,
    TradeCandidateSet,
    TradeRepresentation,
    TradeScope,
    apply_trade_time_policy,
    build_trade_bars,
    canonical_decimal,
    canonical_trade_sort_key,
    normalize_okx_trade_items,
)
from crypto_collector.materializer.models import (
    DerivedSourceLocator,
    SourceLocator,
    SourceRecord,
    TimeSource,
)
from crypto_collector.materializer.time_policy import EventTimePolicy
from crypto_collector.materializer.windows import Window

SECOND_NS = 1_000_000_000
BASE_NS = 1_800_000_000_000_000_000
BASE_MS = BASE_NS // 1_000_000
MANIFEST_A = "a" * 64
MANIFEST_B = "b" * 64
MANIFEST_C = "c" * 64
MAX_SIGNED_INT64 = 2**63 - 1
GOLDEN_ROOT = Path(__file__).parents[3] / "golden" / "materializer" / "trades"


def _item(
    *,
    trade_id: str = "100",
    price: str = "10.10",
    size: str = "2",
    side: str = "buy",
    timestamp_ms: int = BASE_MS + 1_000,
    source: str = "0",
) -> dict[str, object]:
    return {
        "instId": "BTC-USDT",
        "tradeId": trade_id,
        "px": price,
        "sz": size,
        "side": side,
        "source": source,
        "ts": str(timestamp_ms),
    }


def _rest_source(
    items: list[dict[str, object]],
    *,
    received_at_ns: int = BASE_NS + 2 * SECOND_NS,
    record_index: int = 0,
    manifest_sha256: str = MANIFEST_A,
    market: Market = Market.SPOT,
    instrument_key: str = "BTC-USDT",
    path: str = "/api/v5/market/trades",
) -> SourceRecord:
    envelope = RawEnvelope(
        schema_version=1,
        exchange=Exchange.OKX,
        market=market,
        instrument_key=instrument_key,
        wire_symbol=instrument_key,
        logical_stream="trade",
        native_channel=path,
        transport=Transport.REST,
        event_time_ns=None,
        event_time_source=None,
        integrity_mode=None,
        coverage=None,
        rest_metadata=RestMetadata(
            request_started_at_ns=received_at_ns - 2,
            request_ended_at_ns=received_at_ns - 1,
            method="GET",
            path=path,
            params={"instId": instrument_key},
            status=200,
            attempt=1,
            rate_limit_headers={},
        ),
        payload=cast(Any, {"code": "0", "msg": "", "data": items}),
        received_at_ns=received_at_ns,
        monotonic_ns=record_index + 1,
        worker_instance_id="worker-a",
        connection_id=None,
        connection_generation=None,
        writer_sequence=record_index + 1,
        egress_id="direct-primary",
        config_sha256="c" * 64,
    )
    return SourceRecord(
        envelope=envelope,
        locator=SourceLocator(
            manifest_sha256=manifest_sha256,
            zero_based_record_index=record_index,
        ),
    )


def _ws_source(
    items: list[dict[str, object]],
    *,
    channel: str = "trades-all",
    received_at_ns: int = BASE_NS + 2 * SECOND_NS,
    record_index: int = 0,
    manifest_sha256: str = MANIFEST_A,
) -> SourceRecord:
    envelope = RawEnvelope(
        schema_version=1,
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="trade",
        native_channel=channel,
        transport=Transport.WEBSOCKET,
        event_time_ns=BASE_NS + SECOND_NS,
        event_time_source="okx.ts",
        integrity_mode=None,
        coverage=None,
        rest_metadata=None,
        payload=cast(
            Any,
            {
                "arg": {"channel": channel, "instId": "BTC-USDT"},
                "data": items,
            },
        ),
        received_at_ns=received_at_ns,
        monotonic_ns=record_index + 1,
        worker_instance_id="worker-a",
        connection_id="connection-a",
        connection_generation=1,
        writer_sequence=record_index + 1,
        egress_id="direct-primary",
        config_sha256="c" * 64,
    )
    return SourceRecord(
        envelope=envelope,
        locator=SourceLocator(
            manifest_sha256=manifest_sha256,
            zero_based_record_index=record_index,
        ),
    )


def _policy(*, skew_ns: int = 60 * SECOND_NS) -> EventTimePolicy:
    return EventTimePolicy(
        max_past_skew_ns=skew_ns,
        max_future_skew_ns=skew_ns,
    )


def _timed(
    source: SourceRecord,
    *,
    contract_metadata: Sequence[OkxLinearContractMetadata] = (),
    aggregated_equivalence_verified: bool = False,
) -> tuple[TimedTrade, ...]:
    items = normalize_okx_trade_items(
        source,
        contract_metadata=contract_metadata,
        aggregated_equivalence_verified=aggregated_equivalence_verified,
    )
    return apply_trade_time_policy(items, policy=_policy())


def _candidate_set(
    trades: Iterable[TimedTrade],
    *,
    start_ns: int = BASE_NS - 30 * SECOND_NS,
) -> TradeCandidateSet:
    return TradeCandidateSet(
        scope=TradeScope(Exchange.OKX, Market.SPOT, "BTC-USDT"),
        coverage=CandidateCoverage(start_ns, BASE_NS + 90 * SECOND_NS),
        trades=tuple(trades),
    )


def _windows(interval_ns: int) -> tuple[Window, ...]:
    return tuple(
        Window(start_ns=start, end_ns=start + interval_ns)
        for start in range(BASE_NS, BASE_NS + 60 * SECOND_NS, interval_ns)
    )


def test_derived_source_locator_adds_stable_native_item_ordinal() -> None:
    source = SourceLocator(MANIFEST_A, 7)

    first = DerivedSourceLocator(source=source, item_ordinal=0)
    second = DerivedSourceLocator(source=source, item_ordinal=1)

    assert first < second
    with pytest.raises((TypeError, ValueError)):
        DerivedSourceLocator(source=source, item_ordinal=True)
    with pytest.raises(ValueError):
        DerivedSourceLocator(source=source, item_ordinal=-1)


def test_okx_rest_batch_preserves_wire_order_and_uses_each_item_time() -> None:
    source = _rest_source(
        [
            _item(trade_id="newer", timestamp_ms=BASE_MS + 40_000),
            _item(trade_id="older", timestamp_ms=BASE_MS + 10_000),
        ]
    )

    normalized = normalize_okx_trade_items(source)
    timed = apply_trade_time_policy(normalized, policy=_policy())

    assert [row.locator.item_ordinal for row in normalized] == [0, 1]
    assert [row.stable_trade_id for row in normalized] == ["newer", "older"]
    assert [row.native_event_time_ns for row in normalized] == [
        BASE_NS + 40 * SECOND_NS,
        BASE_NS + 10 * SECOND_NS,
    ]
    assert [row.effective_event_time_ns for row in timed] == [
        BASE_NS + 40 * SECOND_NS,
        BASE_NS + 10 * SECOND_NS,
    ]
    assert sorted(timed, key=canonical_trade_sort_key) == [timed[1], timed[0]]


def test_okx_normalizer_object_implements_pure_expand_stage() -> None:
    source = _rest_source([_item()])

    normalized = OkxTradeNormalizer().normalize(source)

    assert len(normalized) == 1
    assert normalized[0].native_event_time_ns == BASE_NS + SECOND_NS


def test_batch_child_outlier_falls_back_independently_to_envelope_receive() -> None:
    source = _rest_source(
        [
            _item(trade_id="near", timestamp_ms=BASE_MS + 1_000),
            _item(trade_id="old", timestamp_ms=BASE_MS - 100_000),
        ],
        received_at_ns=BASE_NS + 2 * SECOND_NS,
    )

    timed = apply_trade_time_policy(
        normalize_okx_trade_items(source),
        policy=_policy(skew_ns=5 * SECOND_NS),
    )

    assert timed[0].time_source is TimeSource.EVENT
    assert timed[0].effective_event_time_ns == BASE_NS + SECOND_NS
    assert timed[1].time_source is TimeSource.RECEIVE_OUTLIER
    assert timed[1].effective_event_time_ns == BASE_NS + 2 * SECOND_NS


def test_okx_trades_all_requires_exactly_one_item() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        normalize_okx_trade_items(_ws_source([]))
    with pytest.raises(ValueError, match="exactly one"):
        normalize_okx_trade_items(_ws_source([_item(), _item(trade_id="101")]))


def test_okx_trades_all_item_time_must_match_single_item_envelope_time() -> None:
    with pytest.raises(ValueError, match="envelope event time"):
        normalize_okx_trade_items(_ws_source([_item(timestamp_ms=BASE_MS + 2_000)]))


def test_okx_rest_empty_batch_and_unknown_extra_fields_are_supported() -> None:
    assert normalize_okx_trade_items(_rest_source([])) == ()
    item = {**_item(), "futureField": {"nested": True}}
    source = _rest_source([item])
    payload = cast(dict[str, Any], source.envelope.payload)
    envelope = source.envelope.model_copy(
        update={
            "payload": {
                **payload,
                "futureWrapperField": "ignored",
            }
        }
    )

    assert (
        len(
            normalize_okx_trade_items(
                SourceRecord(envelope=envelope, locator=source.locator)
            )
        )
        == 1
    )


def test_okx_trade_routing_and_rest_result_fail_closed() -> None:
    source = _rest_source([_item()])
    bad_result = source.envelope.model_copy(
        update={"payload": {"code": "50011", "msg": "throttled", "data": []}}
    )
    bad_instrument = source.envelope.model_copy(update={"wire_symbol": "ETH-USDT"})

    with pytest.raises(ValueError, match="successful"):
        normalize_okx_trade_items(
            SourceRecord(envelope=bad_result, locator=source.locator)
        )
    with pytest.raises(ValueError, match="wire symbol"):
        normalize_okx_trade_items(
            SourceRecord(envelope=bad_instrument, locator=source.locator)
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("px", 10.1),
        ("px", "NaN"),
        ("px", "0"),
        ("px", "1e1"),
        ("px", "1.0000000000000000001"),
        ("px", "100000000000000000000"),
        ("sz", 2),
        ("sz", "-1"),
        ("ts", 123),
        ("ts", "1.5"),
    ],
)
def test_okx_trade_numeric_schema_fails_closed(field: str, value: object) -> None:
    item = _item()
    item[field] = value

    with pytest.raises((TypeError, ValueError)):
        normalize_okx_trade_items(_rest_source([item]))


def test_okx_spot_uses_exact_decimal_base_and_quote_quantity() -> None:
    trade = normalize_okx_trade_items(
        _rest_source([_item(price="10.10", size="2.25")])
    )[0]

    assert trade.price == Decimal("10.10")
    assert trade.base_quantity == Decimal("2.25")
    assert trade.quote_quantity == Decimal("22.7250")
    assert trade.contract_quantity is None
    assert trade.aggressor_side is AggressorSide.BUY


def test_input_decimal_accepts_exact_decimal_38_18_integer_boundary() -> None:
    price = "99999999999999999999.999999999999999999"

    trade = normalize_okx_trade_items(
        _rest_source([_item(price=price, size="0.000000000000000001")])
    )[0]

    assert trade.price == Decimal(price)


def test_derived_decimal_rejects_more_than_40_integer_digits() -> None:
    timed = _timed(_rest_source([_item()]))[0]

    with pytest.raises(ValueError, match=r"decimal\(76,36\)"):
        replace(
            timed.trade,
            base_quantity=Decimal(10**40),
        )


def test_okx_linear_usdt_swap_converts_contracts_using_effective_metadata() -> None:
    source = _rest_source(
        [
            {
                **_item(price="50000", size="3"),
                "instId": "BTC-USDT-SWAP",
            }
        ],
        market=Market.PERPETUAL,
        instrument_key="BTC-USDT-SWAP",
    )
    metadata = OkxLinearContractMetadata(
        source_manifest_sha256=MANIFEST_C,
        instrument_key="BTC-USDT-SWAP",
        valid_from_ns=BASE_NS,
        valid_to_ns=BASE_NS + 60 * SECOND_NS,
        base_asset="BTC",
        quote_asset="USDT",
        contract_type="linear",
        settle_currency="USDT",
        contract_value=Decimal("0.01"),
        contract_value_currency="BTC",
        contract_multiplier=Decimal(1),
    )

    trade = normalize_okx_trade_items(source, contract_metadata=(metadata,))[0]

    assert trade.contract_quantity == Decimal(3)
    assert trade.base_quantity == Decimal("0.03")
    assert trade.quote_quantity == Decimal("1500.00")
    assert trade.lineage_manifest_sha256s == (MANIFEST_A, MANIFEST_C)


@pytest.mark.parametrize(
    "metadata_change",
    [
        {"contract_type": "inverse"},
        {"settle_currency": "USD"},
        {"contract_value_currency": "USDT"},
        {"contract_multiplier": Decimal(10)},
        {"base_asset": "ETH", "contract_value_currency": "ETH"},
        {"valid_from_ns": BASE_NS + 2 * SECOND_NS},
    ],
)
def test_okx_perpetual_rejects_unproven_quantity_conversion(
    metadata_change: dict[str, object],
) -> None:
    source = _rest_source(
        [
            {
                **_item(price="50000", size="3"),
                "instId": "BTC-USDT-SWAP",
            }
        ],
        market=Market.PERPETUAL,
        instrument_key="BTC-USDT-SWAP",
    )
    values: dict[str, object] = {
        "source_manifest_sha256": MANIFEST_C,
        "instrument_key": "BTC-USDT-SWAP",
        "valid_from_ns": BASE_NS,
        "valid_to_ns": BASE_NS + 60 * SECOND_NS,
        "base_asset": "BTC",
        "quote_asset": "USDT",
        "contract_type": "linear",
        "settle_currency": "USDT",
        "contract_value": Decimal("0.01"),
        "contract_value_currency": "BTC",
        "contract_multiplier": Decimal(1),
    }
    values.update(metadata_change)
    metadata = OkxLinearContractMetadata(**values)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="metadata"):
        normalize_okx_trade_items(source, contract_metadata=(metadata,))


def test_aggregated_match_count_must_fit_signed_int64() -> None:
    item = {
        **_item(trade_id=str(MAX_SIGNED_INT64)),
        "count": str(MAX_SIGNED_INT64 + 1),
        "seqId": 1,
    }

    with pytest.raises(ValueError, match="count"):
        normalize_okx_trade_items(
            _ws_source([item], channel="trades"),
            aggregated_equivalence_verified=True,
        )


def test_trade_bar_uses_decimal_aggressor_side_and_exact_vwap_rounding() -> None:
    source = _rest_source(
        [
            _item(trade_id="1", price="0.1", size="1", side="buy"),
            _item(trade_id="2", price="0.2", size="2", side="sell"),
        ]
    )
    bars = build_trade_bars(
        _candidate_set(_timed(source)),
        windows=_windows(30 * SECOND_NS),
    )

    first = bars[0]
    assert first.open == Decimal("0.1")
    assert first.high == Decimal("0.2")
    assert first.low == Decimal("0.1")
    assert first.close == Decimal("0.2")
    assert first.vwap == Decimal("0.166666666666666666666666666666666667")
    assert first.base_volume == Decimal(3)
    assert first.quote_volume == Decimal("0.5")
    assert first.buy_base_volume == Decimal(1)
    assert first.sell_base_volume == Decimal(2)
    assert first.unknown_base_volume == Decimal(0)
    assert first.signed_base_volume == Decimal(-1)
    assert first.trade_count == 2
    assert first.normalized_record_count == 2
    assert first.event_time_count == 2
    assert first.event_time_ratio == Decimal(1)


def test_missing_venue_quote_quantity_uses_exact_price_times_base() -> None:
    timed = _timed(_rest_source([_item(price="10.25", size="2")]))[0]
    without_quote = replace(
        timed,
        trade=replace(timed.trade, quote_quantity=None),
    )

    row = build_trade_bars(
        _candidate_set((without_quote,)),
        windows=_windows(30 * SECOND_NS),
    )[0]

    assert row.quote_volume == Decimal("20.50")
    assert row.vwap == Decimal("10.25")


def test_unknown_aggressor_side_is_separate_and_not_signed() -> None:
    trade = _timed(_rest_source([_item(side="auction", price="10", size="2")]))[0]

    row = build_trade_bars(
        _candidate_set((trade,)),
        windows=_windows(30 * SECOND_NS),
    )[0]

    assert trade.trade.aggressor_side is AggressorSide.UNKNOWN
    assert row.unknown_base_volume == Decimal(2)
    assert row.buy_base_volume == row.sell_base_volume == Decimal(0)
    assert row.signed_base_volume == Decimal(0)


def test_empty_trade_window_has_null_prices_and_zero_activity() -> None:
    bars = build_trade_bars(
        _candidate_set(()),
        windows=_windows(30 * SECOND_NS),
    )

    assert len(bars) == 2
    row = bars[0]
    assert row.open is row.high is row.low is row.close is row.vwap is None
    assert row.base_volume == row.quote_volume == Decimal(0)
    assert row.trade_count == row.normalized_record_count == 0
    assert row.event_time_ratio is None
    assert row.deduplication_mode is None
    assert row.lineage_manifest_sha256s == ()


def test_stable_trade_id_deduplicates_before_windowing_and_assigns_to_winner() -> None:
    item = _item(trade_id="venue-42", timestamp_ms=BASE_MS + 1_000)
    winner = _rest_source(
        [item],
        received_at_ns=BASE_NS + 2 * SECOND_NS,
        record_index=0,
        manifest_sha256=MANIFEST_A,
    )
    replay = _rest_source(
        [item],
        received_at_ns=BASE_NS + 40 * SECOND_NS,
        record_index=0,
        manifest_sha256=MANIFEST_B,
    )
    policy = _policy(skew_ns=0)
    timed = (
        *apply_trade_time_policy(normalize_okx_trade_items(winner), policy=policy),
        *apply_trade_time_policy(normalize_okx_trade_items(replay), policy=policy),
    )

    bars = build_trade_bars(
        _candidate_set(timed),
        windows=_windows(30 * SECOND_NS),
    )

    assert bars[0].trade_count == 1
    assert bars[0].duplicate_input_count == 1
    assert bars[0].lineage_manifest_sha256s == (MANIFEST_A, MANIFEST_B)
    assert bars[1].trade_count == 0
    assert bars[1].duplicate_input_count == 0


def test_output_subset_cannot_hide_cross_window_duplicate_telemetry() -> None:
    item = _item(trade_id="venue-42", timestamp_ms=BASE_MS + 1_000)
    winner = _rest_source(
        [item],
        received_at_ns=BASE_NS + 2 * SECOND_NS,
        manifest_sha256=MANIFEST_A,
    )
    replay = _rest_source(
        [item],
        received_at_ns=BASE_NS + 40 * SECOND_NS,
        manifest_sha256=MANIFEST_B,
    )
    policy = _policy(skew_ns=0)
    timed = (
        *apply_trade_time_policy(normalize_okx_trade_items(winner), policy=policy),
        *apply_trade_time_policy(normalize_okx_trade_items(replay), policy=policy),
    )

    with pytest.raises(ValueError, match="winner windows with duplicate telemetry"):
        build_trade_bars(
            _candidate_set(timed),
            windows=(_windows(30 * SECOND_NS)[1],),
        )


def test_trade_bar_validates_public_state_and_canonicalizes_audit_locators() -> None:
    row = build_trade_bars(
        _candidate_set(_timed(_rest_source([_item()]))),
        windows=(_windows(30 * SECOND_NS)[0],),
    )[0]
    assert row.last_source_locator is not None

    with pytest.raises(ValueError, match="trade_count"):
        replace(row, trade_count=-1)
    with pytest.raises(ValueError, match="time-source counts"):
        replace(row, event_time_count=0)
    with pytest.raises(ValueError, match="VWAP"):
        replace(row, vwap=Decimal(1))
    with pytest.raises(ValueError, match="price range"):
        replace(row, quote_volume=Decimal(1998), vwap=Decimal(999))
    with pytest.raises(ValueError, match="unavailable deduplication"):
        replace(
            row,
            duplicate_input_count=1,
            duplicate_match_count=1,
            deduplication_mode=DeduplicationMode.UNAVAILABLE,
        )
    with pytest.raises(ValueError, match="single-record OHLC"):
        replace(row, high=Decimal("10.2"))
    with pytest.raises(ValueError, match="single-record endpoints"):
        replace(
            row,
            last_source_locator=DerivedSourceLocator(
                source=row.last_source_locator.source,
                item_ordinal=1,
            ),
        )
    with pytest.raises(ValueError, match="single-record deduplication"):
        replace(row, deduplication_mode=DeduplicationMode.MIXED)

    canonical = row.to_canonical_dict()
    expected_locator = {
        "manifest_sha256": MANIFEST_A,
        "zero_based_record_index": 0,
        "item_ordinal": 0,
    }
    assert canonical["first_source_locator"] == expected_locator
    assert canonical["last_source_locator"] == expected_locator


def test_same_stable_id_with_conflicting_semantics_fails_closed() -> None:
    first = _timed(_rest_source([_item(trade_id="42", price="10")]))
    second = _timed(
        _rest_source(
            [_item(trade_id="42", price="11")],
            record_index=1,
            manifest_sha256=MANIFEST_B,
        )
    )

    with pytest.raises(ValueError, match="conflicting stable trade identity"):
        build_trade_bars(
            _candidate_set((*first, *second)),
            windows=_windows(30 * SECOND_NS),
        )


def test_missing_trade_id_is_not_heuristically_deduplicated() -> None:
    trade = _timed(_rest_source([_item()]))[0]
    unavailable = replace(
        trade,
        trade=replace(
            trade.trade,
            stable_trade_id=None,
            trade_id_namespace=None,
        ),
    )
    candidate_set = _candidate_set(
        (
            unavailable,
            replace(
                unavailable,
                trade=replace(
                    unavailable.trade,
                    locator=DerivedSourceLocator(
                        source=SourceLocator(MANIFEST_B, 0),
                        item_ordinal=0,
                    ),
                    source=_rest_source(
                        [_item()],
                        manifest_sha256=MANIFEST_B,
                    ),
                    lineage_manifest_sha256s=(MANIFEST_B,),
                ),
            ),
        )
    )

    row = build_trade_bars(candidate_set, windows=_windows(30 * SECOND_NS))[0]

    assert row.trade_count == 2
    assert row.duplicate_input_count == 0
    assert row.deduplication_mode is DeduplicationMode.UNAVAILABLE


def test_exact_and_aggregated_okx_representations_cannot_be_mixed() -> None:
    exact = _timed(_rest_source([_item(trade_id="42")]))[0]
    aggregated_item = {
        **_item(trade_id="43"),
        "count": "3",
        "seqId": 123,
    }
    aggregated = apply_trade_time_policy(
        normalize_okx_trade_items(
            _ws_source([aggregated_item], channel="trades"),
            aggregated_equivalence_verified=True,
        ),
        policy=_policy(),
    )[0]

    assert aggregated.trade.match_count == 3
    assert aggregated.trade.representation is TradeRepresentation.AGGREGATED
    with pytest.raises(ValueError, match="representations"):
        _candidate_set((exact, aggregated))


def test_aggregated_match_count_does_not_multiply_reported_quantity() -> None:
    aggregated_item = {
        **_item(trade_id="123", price="10", size="2", side="buy"),
        "count": "3",
        "seqId": 123,
    }
    trade = apply_trade_time_policy(
        normalize_okx_trade_items(
            _ws_source([aggregated_item], channel="trades"),
            aggregated_equivalence_verified=True,
        ),
        policy=_policy(),
    )[0]

    row = build_trade_bars(
        _candidate_set((trade,)),
        windows=_windows(30 * SECOND_NS),
    )[0]

    assert row.trade_count == 3
    assert row.normalized_record_count == 1
    assert row.aggregated_record_count == 1
    assert row.base_volume == Decimal(2)
    assert row.quote_volume == Decimal(20)
    with pytest.raises(ValueError, match="aggregated bars require stable-ID"):
        replace(row, deduplication_mode=DeduplicationMode.UNAVAILABLE)


def test_partially_overlapping_aggregated_trade_id_ranges_fail_closed() -> None:
    first_item = {
        **_item(trade_id="123", size="2"),
        "count": "3",
        "seqId": 123,
    }
    second_item = {
        **_item(trade_id="124", size="2"),
        "count": "3",
        "seqId": 124,
    }
    first = apply_trade_time_policy(
        normalize_okx_trade_items(
            _ws_source([first_item], channel="trades"),
            aggregated_equivalence_verified=True,
        ),
        policy=_policy(),
    )[0]
    second = apply_trade_time_policy(
        normalize_okx_trade_items(
            _ws_source(
                [second_item],
                channel="trades",
                record_index=1,
                manifest_sha256=MANIFEST_B,
            ),
            aggregated_equivalence_verified=True,
        ),
        policy=_policy(),
    )[0]

    with pytest.raises(ValueError, match="overlapping aggregated"):
        _candidate_set((first, second))


def test_aggregated_trade_count_sum_overflow_fails_closed() -> None:
    count = 2**62
    first_item = {
        **_item(trade_id=str(count - 1), size="1"),
        "count": str(count),
        "seqId": 1,
    }
    second_item = {
        **_item(trade_id=str(2 * count - 1), size="1"),
        "count": str(count),
        "seqId": 2,
    }
    first = apply_trade_time_policy(
        normalize_okx_trade_items(
            _ws_source([first_item], channel="trades"),
            aggregated_equivalence_verified=True,
        ),
        policy=_policy(),
    )[0]
    second = apply_trade_time_policy(
        normalize_okx_trade_items(
            _ws_source(
                [second_item],
                channel="trades",
                record_index=1,
                manifest_sha256=MANIFEST_B,
            ),
            aggregated_equivalence_verified=True,
        ),
        policy=_policy(),
    )[0]

    with pytest.raises(ValueError, match="trade_count"):
        build_trade_bars(
            _candidate_set((first, second)),
            windows=_windows(30 * SECOND_NS),
        )


def test_decimal_aggregation_is_independent_of_process_global_context() -> None:
    timed = _timed(
        _rest_source(
            [
                _item(trade_id="1", price="123456789.123456789", size="0.000000001"),
                _item(
                    trade_id="2",
                    price="0.000000001",
                    size="123456789.123456789",
                    side="sell",
                ),
            ]
        )
    )
    candidate_set = _candidate_set(timed)

    with localcontext() as context:
        context.prec = 6
        low_context = build_trade_bars(candidate_set, windows=_windows(30 * SECOND_NS))
    with localcontext() as context:
        context.prec = 50
        high_context = build_trade_bars(candidate_set, windows=_windows(30 * SECOND_NS))

    assert low_context == high_context
    assert getcontext().prec != 6


def test_decimal_aggregation_ignores_global_exponent_clamp_and_traps() -> None:
    source = _rest_source([_item(price="10.10", size="2")])

    with localcontext() as context:
        context.prec = 6
        context.Emax = 0
        context.Emin = -1
        context.clamp = 1
        for signal in context.traps:
            context.traps[signal] = True
        hostile = build_trade_bars(
            _candidate_set(_timed(source)),
            windows=_windows(30 * SECOND_NS),
        )

    with localcontext() as context:
        context.prec = 50
        context.Emax = 999_999
        context.Emin = -999_999
        context.clamp = 0
        for signal in context.traps:
            context.traps[signal] = False
        permissive = build_trade_bars(
            _candidate_set(_timed(source)),
            windows=_windows(30 * SECOND_NS),
        )

    assert hostile == permissive
    assert hostile[0].quote_volume == Decimal("20.20")


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (Decimal("10.1000"), "10.1"),
        (Decimal("0E-36"), "0"),
        (Decimal(100), "100"),
        (Decimal("0.000001"), "0.000001"),
    ],
)
def test_canonical_decimal_is_fixed_point(value: Decimal, expected: str) -> None:
    assert canonical_decimal(value) == expected


def test_trade_fixture_matches_30_second_and_one_minute_goldens() -> None:
    records: list[TimedTrade] = []
    next_record_index: dict[str, int] = {}
    with (GOLDEN_ROOT / "raw.jsonl").open(encoding="utf-8") as stream:
        for line in stream:
            fixture = json.loads(line)
            manifest_sha256 = fixture["manifest_sha256"]
            record_index = next_record_index.get(manifest_sha256, 0)
            next_record_index[manifest_sha256] = record_index + 1
            source = _rest_source(
                fixture["data"],
                received_at_ns=fixture["received_at_ns"],
                record_index=record_index,
                manifest_sha256=manifest_sha256,
            )
            records.extend(_timed(source))

    for interval_name, interval_ns in (("30s", 30 * SECOND_NS), ("1m", 60 * SECOND_NS)):
        bars = build_trade_bars(
            _candidate_set(records),
            windows=_windows(interval_ns),
        )
        actual = [bar.to_canonical_dict() for bar in bars]
        with (GOLDEN_ROOT / f"expected-{interval_name}.json").open(
            encoding="utf-8"
        ) as stream:
            expected = json.load(stream)
        assert actual == expected
