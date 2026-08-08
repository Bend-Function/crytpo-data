from __future__ import annotations

from decimal import ROUND_HALF_EVEN, Decimal, localcontext

from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.materializer.datasets.trades import (
    AggressorSide,
    CandidateCoverage,
    NormalizedTrade,
    TimedTrade,
    TradeCandidateSet,
    TradeRepresentation,
    TradeScope,
    build_trade_bars,
    canonical_trade_sort_key,
)
from crypto_collector.materializer.models import (
    DerivedSourceLocator,
    SourceLocator,
    SourceRecord,
    TimeSource,
)
from crypto_collector.materializer.windows import Window

SECOND_NS = 1_000_000_000
BASE_NS = 1_800_000_000_000_000_000
MANIFESTS = ("a" * 64, "b" * 64, "c" * 64, "d" * 64)
SCOPE = TradeScope(Exchange.OKX, Market.SPOT, "BTC-USDT")
WINDOWS = (
    Window(BASE_NS, BASE_NS + 30 * SECOND_NS),
    Window(BASE_NS + 30 * SECOND_NS, BASE_NS + 60 * SECOND_NS),
)
COVERAGE = CandidateCoverage(BASE_NS - 30 * SECOND_NS, BASE_NS + 90 * SECOND_NS)


def _trade(
    *,
    manifest_sha256: str,
    record_index: int,
    item_ordinal: int,
    event_offset_ns: int,
    received_offset_ns: int,
    trade_id: str,
    price: Decimal,
    quantity: Decimal = Decimal(1),
) -> TimedTrade:
    event_time_ns = BASE_NS + event_offset_ns
    received_at_ns = BASE_NS + received_offset_ns
    envelope = RawEnvelope(
        schema_version=1,
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="trade",
        native_channel="trades-all",
        transport=Transport.WEBSOCKET,
        event_time_ns=event_time_ns,
        event_time_source="okx.ts",
        integrity_mode=None,
        coverage=None,
        rest_metadata=None,
        payload={"fixture": trade_id},
        received_at_ns=received_at_ns,
        monotonic_ns=record_index + 1,
        worker_instance_id="worker-a",
        connection_id="connection-a",
        connection_generation=1,
        writer_sequence=record_index + 1,
        egress_id="direct-primary",
        config_sha256="e" * 64,
    )
    source = SourceRecord(
        envelope=envelope,
        locator=SourceLocator(manifest_sha256, record_index),
    )
    quote = price * quantity
    normalized = NormalizedTrade(
        source=source,
        locator=DerivedSourceLocator(source.locator, item_ordinal),
        scope=SCOPE,
        native_event_time_ns=event_time_ns,
        stable_trade_id=trade_id,
        trade_id_namespace="okx_public_trade",
        price=price,
        base_quantity=quantity,
        quote_quantity=quote,
        contract_quantity=None,
        aggressor_side=AggressorSide.BUY,
        match_count=1,
        representation=TradeRepresentation.EXACT,
        venue_source="0",
        lineage_manifest_sha256s=(manifest_sha256,),
    )
    return TimedTrade(normalized, event_time_ns, TimeSource.EVENT)


PERMUTATION_ROWS = (
    _trade(
        manifest_sha256=MANIFESTS[0],
        record_index=0,
        item_ordinal=0,
        event_offset_ns=1,
        received_offset_ns=10,
        trade_id="1",
        price=Decimal(10),
    ),
    _trade(
        manifest_sha256=MANIFESTS[1],
        record_index=0,
        item_ordinal=0,
        event_offset_ns=2,
        received_offset_ns=11,
        trade_id="2",
        price=Decimal(20),
    ),
    _trade(
        manifest_sha256=MANIFESTS[2],
        record_index=0,
        item_ordinal=0,
        event_offset_ns=2,
        received_offset_ns=12,
        trade_id="2",
        price=Decimal(20),
    ),
    _trade(
        manifest_sha256=MANIFESTS[3],
        record_index=0,
        item_ordinal=0,
        event_offset_ns=30 * SECOND_NS,
        received_offset_ns=30 * SECOND_NS + 1,
        trade_id="3",
        price=Decimal(30),
    ),
)
EXPECTED_PERMUTATION_BARS = build_trade_bars(
    TradeCandidateSet(SCOPE, COVERAGE, PERMUTATION_ROWS),
    windows=WINDOWS,
)


@given(rows=st.permutations(PERMUTATION_ROWS))
def test_trade_bars_are_independent_of_candidate_input_order(
    rows: list[TimedTrade],
) -> None:
    actual = build_trade_bars(
        TradeCandidateSet(SCOPE, COVERAGE, tuple(rows)),
        windows=WINDOWS,
    )

    assert actual == EXPECTED_PERMUTATION_BARS


def test_trade_tie_uses_native_item_ordinal_after_raw_locator() -> None:
    first = _trade(
        manifest_sha256=MANIFESTS[0],
        record_index=0,
        item_ordinal=0,
        event_offset_ns=1,
        received_offset_ns=2,
        trade_id="1",
        price=Decimal(10),
    )
    second = _trade(
        manifest_sha256=MANIFESTS[0],
        record_index=0,
        item_ordinal=1,
        event_offset_ns=1,
        received_offset_ns=2,
        trade_id="2",
        price=Decimal(20),
    )

    assert sorted((second, first), key=canonical_trade_sort_key) == [first, second]
    bar = build_trade_bars(
        TradeCandidateSet(SCOPE, COVERAGE, (second, first)),
        windows=WINDOWS[:1],
    )[0]
    assert bar.open == Decimal(10)
    assert bar.close == Decimal(20)


@given(
    first_price=st.integers(min_value=1, max_value=10**12),
    second_price=st.integers(min_value=1, max_value=10**12),
    first_quantity=st.integers(min_value=1, max_value=10**12),
    second_quantity=st.integers(min_value=1, max_value=10**12),
)
def test_vwap_matches_high_precision_half_even_oracle(
    first_price: int,
    second_price: int,
    first_quantity: int,
    second_quantity: int,
) -> None:
    first = _trade(
        manifest_sha256=MANIFESTS[0],
        record_index=0,
        item_ordinal=0,
        event_offset_ns=1,
        received_offset_ns=2,
        trade_id="1",
        price=Decimal(first_price),
        quantity=Decimal(first_quantity),
    )
    second = _trade(
        manifest_sha256=MANIFESTS[1],
        record_index=0,
        item_ordinal=0,
        event_offset_ns=2,
        received_offset_ns=3,
        trade_id="2",
        price=Decimal(second_price),
        quantity=Decimal(second_quantity),
    )
    bar = build_trade_bars(
        TradeCandidateSet(SCOPE, COVERAGE, (first, second)),
        windows=WINDOWS[:1],
    )[0]

    numerator = first_price * first_quantity + second_price * second_quantity
    denominator = first_quantity + second_quantity
    with localcontext() as context:
        context.prec = 100
        expected = (Decimal(numerator) / Decimal(denominator)).quantize(
            Decimal("1e-36"),
            rounding=ROUND_HALF_EVEN,
        )
    assert bar.vwap == expected


def test_half_open_trade_boundary_belongs_only_to_next_window() -> None:
    trade = _trade(
        manifest_sha256=MANIFESTS[0],
        record_index=0,
        item_ordinal=0,
        event_offset_ns=30 * SECOND_NS,
        received_offset_ns=30 * SECOND_NS + 1,
        trade_id="boundary",
        price=Decimal(10),
    )

    bars = build_trade_bars(
        TradeCandidateSet(SCOPE, COVERAGE, (trade,)),
        windows=WINDOWS,
    )

    assert [bar.trade_count for bar in bars] == [0, 1]
