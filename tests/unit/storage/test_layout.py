from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.storage.layout import raw_partial_path


def make_envelope(**overrides: Any) -> RawEnvelope:
    values: dict[str, Any] = {
        "exchange": Exchange.KRAKEN,
        "market": Market.SPOT,
        "instrument_key": "BTC/USDT",
        "wire_symbol": "BTC/USDT",
        "logical_stream": "trade",
        "native_channel": "trade",
        "transport": Transport.WEBSOCKET,
        "event_time_ns": 0,
        "event_time_source": "exchange",
        "received_at_ns": 1_785_473_918_123_456_789,
        "monotonic_ns": 123,
        "worker_instance_id": "worker-1",
        "connection_id": "connection-1",
        "connection_generation": 1,
        "writer_sequence": 7,
        "egress_id": "direct-primary",
        "config_sha256": "a" * 64,
        "payload": {"price": "1.00"},
    }
    values.update(overrides)
    return RawEnvelope(**values)


def test_received_time_selects_the_utc_hour_partition(tmp_path: Path) -> None:
    envelope = make_envelope(event_time_ns=0, event_time_source="exchange")

    path = raw_partial_path(
        tmp_path,
        envelope,
        part_start_ns=1_785_470_400_000_000_000,
        sequence=0,
    )

    assert (
        path.relative_to(tmp_path)
        .as_posix()
        .startswith("raw/kraken/spot/BTC%2FUSDT/trade/2026/07/31/04/")
    )


def test_instrument_key_is_encoded_and_filename_is_deterministic(
    tmp_path: Path,
) -> None:
    path = raw_partial_path(
        tmp_path,
        make_envelope(instrument_key="BTC/USDT", wire_symbol="BTC/USDT"),
        part_start_ns=1_785_470_400_000_000_000,
        sequence=12,
    )

    relative = path.relative_to(tmp_path).as_posix()
    assert "/BTC%2FUSDT/" in relative
    assert path.name == "part-1785470400000000000-12.jsonl.zst.partial"


def test_exchange_control_and_market_scope_use_distinct_reserved_layouts(
    tmp_path: Path,
) -> None:
    exchange_control = make_envelope(
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        connection_id=None,
        connection_generation=None,
        egress_id=None,
        payload={"kind": "config_committed"},
    )
    market_status = make_envelope(
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="status",
        native_channel="status",
        payload={"state": "live"},
    )

    control_path = raw_partial_path(
        tmp_path,
        exchange_control,
        part_start_ns=1_785_470_400_000_000_000,
        sequence=0,
    )
    market_path = raw_partial_path(
        tmp_path,
        market_status,
        part_start_ns=1_785_470_400_000_000_000,
        sequence=0,
    )

    assert (
        control_path.relative_to(tmp_path)
        .as_posix()
        .startswith("raw/okx/_control/2026/07/31/04/")
    )
    assert (
        market_path.relative_to(tmp_path)
        .as_posix()
        .startswith("raw/okx/spot/_market/status/2026/07/31/04/")
    )


def test_insurance_fund_preserves_instrument_scope(tmp_path: Path) -> None:
    insurance = make_envelope(
        exchange=Exchange.OKX,
        market=Market.PERPETUAL,
        instrument_key="BTC-USDT-SWAP",
        wire_symbol="BTC-USDT-SWAP",
        logical_stream="insurance_fund",
        native_channel="/api/v5/public/insurance-fund",
        transport=Transport.REST,
        connection_id=None,
        connection_generation=None,
        payload={"data": [{"instFamily": "BTC-USDT"}]},
        rest_metadata={
            "request_started_at_ns": 1,
            "request_ended_at_ns": 2,
            "method": "GET",
            "path": "/api/v5/public/insurance-fund",
            "params": {"instType": "SWAP", "instFamily": "BTC-USDT"},
            "status": 200,
            "attempt": 1,
            "rate_limit_headers": {},
        },
    )

    path = raw_partial_path(
        tmp_path,
        insurance,
        part_start_ns=1_785_470_400_000_000_000,
        sequence=0,
    )

    assert (
        path.relative_to(tmp_path)
        .as_posix()
        .startswith(
            "raw/okx/perpetual/BTC-USDT-SWAP/insurance_fund/2026/07/31/04/"
        )
    )


def test_control_with_market_context_stays_in_exchange_control_namespace(
    tmp_path: Path,
) -> None:
    control = make_envelope(
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        connection_id=None,
        connection_generation=None,
        egress_id=None,
        payload={"kind": "market_capacity_warning"},
    )

    path = raw_partial_path(tmp_path, control, part_start_ns=1, sequence=0)

    assert path.relative_to(tmp_path).as_posix().startswith("raw/okx/_control/")


def test_reserved_instrument_name_cannot_collide_with_market_scope(
    tmp_path: Path,
) -> None:
    symbol_path = raw_partial_path(
        tmp_path,
        make_envelope(instrument_key="_market", wire_symbol="_market"),
        part_start_ns=1,
        sequence=0,
    )

    assert "/%5Fmarket/" in symbol_path.relative_to(tmp_path).as_posix()


@pytest.mark.parametrize("logical_stream", ["../escape", "nested/escape", "/escape"])
def test_path_traversal_in_stream_name_is_rejected(
    tmp_path: Path,
    logical_stream: str,
) -> None:
    envelope = make_envelope(logical_stream=logical_stream)

    with pytest.raises(ValueError, match="path-safe|traversal"):
        raw_partial_path(tmp_path, envelope, part_start_ns=1, sequence=0)


def test_encoded_malicious_instrument_key_remains_within_data_root(
    tmp_path: Path,
) -> None:
    path = raw_partial_path(
        tmp_path,
        make_envelope(instrument_key="../../BTC", wire_symbol="../../BTC"),
        part_start_ns=1,
        sequence=0,
    )

    assert path.is_relative_to(tmp_path.resolve())
    assert "%2F" in path.as_posix()


def test_existing_symlink_cannot_redirect_raw_path_outside_data_root(
    tmp_path: Path,
) -> None:
    data_root = tmp_path / "data"
    outside = tmp_path / "outside"
    data_root.mkdir()
    outside.mkdir()
    (data_root / "raw").symlink_to(outside, target_is_directory=True)

    with pytest.raises(ValueError, match="escaped data_root"):
        raw_partial_path(data_root, make_envelope(), part_start_ns=1, sequence=0)
