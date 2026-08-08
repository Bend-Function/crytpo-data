from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from crypto_collector.domain import IntegrityMode
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.exchanges.kraken import (
    KrakenBookAction,
    KrakenBookLevel,
    KrakenBookParseError,
    KrakenFuturesBook,
    KrakenFuturesBookFrame,
    parse_futures_book_message,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "kraken"


def level(price: str, quantity: str) -> KrakenBookLevel:
    return KrakenBookLevel(Decimal(price), Decimal(quantity), price, quantity)


def frame(
    *,
    action: str = "update",
    sequence: int,
    bids: tuple[KrakenBookLevel, ...] = (),
    asks: tuple[KrakenBookLevel, ...] = (),
) -> KrakenFuturesBookFrame:
    return KrakenFuturesBookFrame(
        action=action,
        product_id="PF_XBTUSD",
        bids=bids,
        asks=asks,
        timestamp_ns=1_000_000,
        sequence_id=sequence,
    )


def seeded(*, sequence: int = 100) -> KrakenFuturesBook:
    state = KrakenFuturesBook(product_id="PF_XBTUSD")
    outcome = state.apply(
        frame(
            action="snapshot",
            sequence=sequence,
            bids=(level("10", "1"),),
            asks=(level("11", "1"),),
        )
    )
    assert outcome.action is KrakenBookAction.SNAPSHOT
    return state


def test_official_snapshot_parses_exact_decimal_without_float() -> None:
    payload = decode_json((_FIXTURES / "futures-book.json").read_bytes())
    parsed = parse_futures_book_message(payload)
    state = KrakenFuturesBook(product_id="PF_XBTUSD")

    outcome = state.apply(parsed)

    assert outcome.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert outcome.sequence_id == 326072249
    assert state.bids[0].price == Decimal("34892.5")
    assert type(state.bids[0].price) is Decimal


def test_non_contiguous_increase_remains_best_effort_not_a_gap() -> None:
    state = seeded(sequence=100)

    outcome = state.apply(frame(sequence=105, bids=(level("10", "2"),)))

    assert outcome.action is KrakenBookAction.APPLY
    assert outcome.integrity is IntegrityMode.BEST_EFFORT
    assert outcome.generation_valid
    assert state.sequence_id == 105


@pytest.mark.parametrize("sequence", [100, 99])
def test_duplicate_or_regression_invalidates_generation(sequence: int) -> None:
    state = seeded(sequence=100)

    outcome = state.apply(frame(sequence=sequence, bids=(level("10", "2"),)))

    assert outcome.action is KrakenBookAction.RECONNECT
    assert outcome.integrity is IntegrityMode.INVALID
    assert outcome.control_reason == "book_sequence_regression"
    assert state.sequence_id == 100
    assert state.bids[0].quantity == Decimal(1)


def test_invalid_generation_is_sticky_until_authoritative_snapshot() -> None:
    state = seeded(sequence=100)
    state.apply(frame(sequence=100))

    later = state.apply(frame(sequence=101, bids=(level("10", "2"),)))
    restored = state.apply(
        frame(
            action="snapshot",
            sequence=500,
            bids=(level("20", "1"),),
            asks=(level("21", "1"),),
        )
    )

    assert later.action is KrakenBookAction.RECONNECT
    assert later.control_reason == "book_generation_invalid"
    assert restored.action is KrakenBookAction.SNAPSHOT
    assert restored.integrity is IntegrityMode.SNAPSHOT_CHAIN
    assert state.sequence_id == 500


def test_zero_quantity_delta_deletes_one_native_side_level() -> None:
    state = seeded(sequence=100)

    outcome = state.apply(frame(sequence=101, asks=(level("11", "0"),)))

    assert outcome.integrity is IntegrityMode.BEST_EFFORT
    assert state.asks == ()


def test_crossing_delta_is_atomic_and_invalidates_generation() -> None:
    state = seeded(sequence=100)

    outcome = state.apply(frame(sequence=101, bids=(level("12", "1"),)))

    assert outcome.control_reason == "book_crossed"
    assert state.sequence_id == 100
    assert state.bids[0].price == Decimal(10)


def test_delta_before_snapshot_is_invalid() -> None:
    state = KrakenFuturesBook()

    outcome = state.apply(frame(sequence=1, bids=(level("10", "1"),)))

    assert outcome.action is KrakenBookAction.RECONNECT
    assert outcome.integrity is IntegrityMode.INVALID


def test_parser_rejects_float_object_values_even_though_wire_decoder_is_exact() -> None:
    message = {
        "feed": "book",
        "product_id": "PF_XBTUSD",
        "side": "buy",
        "seq": 1,
        "price": 10.1,
        "qty": 1,
        "timestamp": 1,
    }

    with pytest.raises(KrakenBookParseError, match="float"):
        parse_futures_book_message(message)
