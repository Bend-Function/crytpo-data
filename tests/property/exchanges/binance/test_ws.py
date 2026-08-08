from __future__ import annotations

from string import ascii_letters, digits

from hypothesis import given
from hypothesis import strategies as st

from crypto_collector.domain import Market
from crypto_collector.exchanges.binance.ws import stream_spec


@given(
    st.text(
        alphabet=ascii_letters + digits + "_-",
        min_size=1,
        max_size=32,
    )
)
def test_composite_index_identity_determines_exact_wire_stream(
    index_symbol: str,
) -> None:
    spec = stream_spec(
        Market.PERPETUAL,
        "index_info",
        index_symbol=index_symbol,
    )

    assert spec.instrument_key is None
    assert spec.wire_symbol is None
    assert spec.index_symbol == index_symbol
    assert spec.identity_symbol == index_symbol
    assert spec.stream_name == f"{index_symbol.lower()}@compositeIndex"
