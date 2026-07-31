import pytest
from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.domain.paths import decode_instrument_key, encode_instrument_key


@given(
    st.text(min_size=1).filter(
        lambda value: "\x00" not in value and value not in {".", ".."}
    )
)
def test_instrument_key_is_reversible_and_has_no_path_separator(
    instrument_key: str,
) -> None:
    key = encode_instrument_key(instrument_key)
    assert "/" not in key
    assert decode_instrument_key(key) == instrument_key


def test_kraken_symbol_is_percent_encoded() -> None:
    assert encode_instrument_key("BTC/USDT") == "BTC%2FUSDT"


def test_reserved_segment_cannot_collide() -> None:
    assert encode_instrument_key("_market") == "%5Fmarket"


@pytest.mark.parametrize("instrument_key", ["", ".", "..", "bad\x00key"])
def test_invalid_instrument_key_is_rejected(instrument_key: str) -> None:
    with pytest.raises(ValueError, match="path-safe"):
        encode_instrument_key(instrument_key)
