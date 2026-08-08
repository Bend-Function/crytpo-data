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
    KrakenSpotBook,
    KrakenSpotBookFrame,
    kraken_spot_checksum_input,
    kraken_spot_crc32,
    parse_spot_book_message,
)

_FIXTURES = Path(__file__).resolve().parents[3] / "fixtures" / "exchanges" / "kraken"


def level(price: str, quantity: str) -> KrakenBookLevel:
    return KrakenBookLevel(
        Decimal(price),
        Decimal(quantity),
        price,
        quantity,
    )


def crc(
    asks: tuple[KrakenBookLevel, ...],
    bids: tuple[KrakenBookLevel, ...],
) -> int:
    return kraken_spot_crc32(
        kraken_spot_checksum_input(
            ((item.raw_price, item.raw_quantity) for item in asks[:10]),
            ((item.raw_price, item.raw_quantity) for item in bids[:10]),
        )
    )


def frame(
    *,
    action: str,
    bids: tuple[KrakenBookLevel, ...],
    asks: tuple[KrakenBookLevel, ...],
    checksum: int | None = None,
) -> KrakenSpotBookFrame:
    return KrakenSpotBookFrame(
        action=action,
        symbol="BTC/USDT",
        bids=bids,
        asks=asks,
        checksum=crc(asks, bids) if checksum is None else checksum,
        timestamp_ns=None,
    )


def seeded() -> KrakenSpotBook:
    state = KrakenSpotBook(depth=10, symbol="BTC/USDT")
    bids = (level("10.00000000", "1.00000000"),)
    asks = (level("11.00000000", "1.00000000"),)
    outcome = state.apply(frame(action="snapshot", bids=bids, asks=asks))
    assert outcome.action is KrakenBookAction.SNAPSHOT
    return state


def test_official_crc_fixture_is_verified_from_exact_decimal_strings() -> None:
    payload = decode_json((_FIXTURES / "spot-book.json").read_bytes())
    parsed = parse_spot_book_message(payload)
    state = KrakenSpotBook(depth=10, symbol="BTC/USD")

    outcome = state.apply(parsed[0])

    assert outcome.integrity is IntegrityMode.CHECKSUM_VERIFIED
    assert outcome.generation_valid
    assert state.verify_crc(3310070434)
    assert state.checksum_input().startswith("452852100000")
    assert all(type(item.price) is Decimal for item in (*state.bids, *state.asks))


def test_same_price_updates_apply_in_wire_order_before_one_final_trim() -> None:
    state = seeded()
    asks = (
        level("11.00000000", "2.00000000"),
        level("11.00000000", "0.00000000"),
        level("12.00000000", "1.25000000"),
    )
    expected_asks = (level("12.00000000", "1.25000000"),)
    expected_bids = state.bids
    update = frame(
        action="update",
        bids=(),
        asks=asks,
        checksum=crc(expected_asks, expected_bids),
    )

    outcome = state.apply(update)

    assert outcome.integrity is IntegrityMode.CHECKSUM_VERIFIED
    assert Decimal(11) not in {item.price for item in state.asks}
    assert state.asks == expected_asks


def test_snapshot_trims_to_subscription_depth_before_crc() -> None:
    bids = tuple(
        level(f"{price}.00000000", "1.00000000") for price in range(100, 89, -1)
    )
    asks = tuple(level(f"{price}.00000000", "1.00000000") for price in range(101, 112))
    state = KrakenSpotBook(depth=10, allow_crossed=True)
    trimmed_bids = bids[:10]
    trimmed_asks = asks[:10]

    outcome = state.apply(
        frame(
            action="snapshot",
            bids=bids,
            asks=asks,
            checksum=crc(trimmed_asks, trimmed_bids),
        )
    )

    assert outcome.generation_valid
    assert len(state.bids) == 10
    assert len(state.asks) == 10


def test_crc_mismatch_is_atomic_and_sticky_until_new_snapshot() -> None:
    state = seeded()
    original = state.bids
    proposed = (level("10.00000000", "2.00000000"),)
    bad = frame(action="update", bids=proposed, asks=(), checksum=0)

    mismatch = state.apply(bad)
    assert mismatch.action is KrakenBookAction.RECONNECT
    assert mismatch.control_reason == "book_checksum_mismatch"
    assert state.bids == original
    assert not state.generation_valid

    later = state.apply(
        frame(
            action="update",
            bids=proposed,
            asks=(),
            checksum=crc(state.asks, proposed),
        )
    )
    assert later.action is KrakenBookAction.RECONNECT
    assert state.bids == original
    assert not state.generation_valid

    restored = state.apply(
        frame(
            action="snapshot",
            bids=(level("20.00000000", "1.00000000"),),
            asks=(level("21.00000000", "1.00000000"),),
        )
    )

    assert restored.action is KrakenBookAction.SNAPSHOT
    assert state.generation_valid
    assert state.bids[0].price == Decimal(20)


def test_crossed_update_is_atomic_and_invalidates_generation() -> None:
    state = seeded()
    previous = state.bids
    crossed_bid = (level("12.00000000", "1.00000000"),)

    outcome = state.apply(
        frame(
            action="update",
            bids=crossed_bid,
            asks=(),
            checksum=crc(state.asks, crossed_bid),
        )
    )

    assert outcome.control_reason == "book_crossed"
    assert state.bids == previous
    assert not state.generation_valid


def test_parser_rejects_binary_float_before_checksum_state() -> None:
    payload = {
        "channel": "book",
        "type": "snapshot",
        "data": [
            {
                "symbol": "BTC/USDT",
                "bids": [{"price": 10.1, "qty": "1.0"}],
                "asks": [{"price": "11.0", "qty": "1.0"}],
                "checksum": 0,
            }
        ],
    }

    with pytest.raises(KrakenBookParseError, match="float"):
        parse_spot_book_message(payload)


def test_parser_preserves_fixed_scale_zero_from_exact_json_delete() -> None:
    payload = decode_json(
        b'{"channel":"book","type":"update","data":['
        b'{"symbol":"BTC/USD","bids":[],"asks":['
        b'{"price":65057.2,"qty":0.00000000}],"checksum":0}]}'
    )

    parsed = parse_spot_book_message(payload)

    assert parsed[0].asks[0].quantity == Decimal(0)
    assert parsed[0].asks[0].raw_price == "65057.2"
    assert parsed[0].asks[0].raw_quantity == "0.00000000"


def test_parser_preserves_nine_digit_rfc3339_timestamp_precision() -> None:
    payload = decode_json(
        b'{"channel":"book","type":"update","data":['
        b'{"symbol":"BTC/USD","bids":[],"asks":[],'
        b'"checksum":0,"timestamp":"2026-08-08T12:34:56.123456789Z"}]}'
    )

    parsed = parse_spot_book_message(payload)

    assert parsed[0].timestamp_ns == 1_786_192_496_123_456_789


def test_update_before_snapshot_is_invalid() -> None:
    state = KrakenSpotBook(depth=10)
    bids = (level("10", "1"),)

    outcome = state.apply(frame(action="update", bids=bids, asks=()))

    assert outcome.integrity is IntegrityMode.INVALID
    assert outcome.action is KrakenBookAction.RECONNECT
