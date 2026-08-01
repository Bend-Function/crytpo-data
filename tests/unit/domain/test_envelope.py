from collections.abc import Callable
from decimal import Decimal
from typing import Any

import pytest
from pydantic import ValidationError

from crypto_collector.domain.envelope import (
    NativeEventDraft,
    RawEnvelope,
    RestMetadata,
    SourceContext,
)
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.domain.types import Exchange, Market, Transport


def make_rest_metadata() -> RestMetadata:
    return RestMetadata(
        request_started_at_ns=1,
        request_ended_at_ns=2,
        method="GET",
        path="/api/v5/market/tickers",
        params={"instType": "SPOT"},
        status=200,
        attempt=1,
        rate_limit_headers={},
        requested_interval_ns=30_000_000_000,
        effective_interval_ns=60_000_000_000,
    )


def make_native_event_draft(**overrides: Any) -> NativeEventDraft:
    values: dict[str, Any] = {
        "exchange": Exchange.OKX,
        "market": Market.SPOT,
        "instrument_key": "BTC-USDT",
        "wire_symbol": "BTC-USDT",
        "logical_stream": "book_live",
        "native_channel": "books",
        "transport": Transport.WEBSOCKET,
        "event_time_ns": None,
        "event_time_source": None,
        "integrity_mode": None,
        "coverage": None,
        "rest_metadata": None,
        "payload": {"arg": {"channel": "books"}, "ratio": Decimal("0.1")},
    }
    values.update(overrides)
    return NativeEventDraft(**values)


def make_envelope(**overrides: Any) -> RawEnvelope:
    values = make_native_event_draft().model_dump()
    values.update(
        {
            "received_at_ns": 1_785_473_918_123_456_789,
            "monotonic_ns": 123,
            "worker_instance_id": "worker-1",
            "connection_id": "connection-1",
            "connection_generation": 1,
            "writer_sequence": 7,
            "egress_id": "direct-primary",
            "config_sha256": "a" * 64,
        }
    )
    values.update(overrides)
    return RawEnvelope(**values)


def test_event_time_may_be_absent_but_receive_and_monotonic_time_are_required() -> None:
    row = make_envelope()

    assert row.event_time_ns is None
    assert isinstance(row.payload, dict)
    arg = row.payload["arg"]
    assert isinstance(arg, dict)
    assert arg["channel"] == "books"
    assert decode_json(encode_json(row.model_dump()))["payload"]["ratio"] == Decimal(
        "0.1"
    )


def test_routine_rest_has_null_connection_and_structured_metadata() -> None:
    row = make_envelope(
        transport=Transport.REST,
        logical_stream="ticker",
        native_channel="/api/v5/market/tickers",
        connection_id=None,
        connection_generation=None,
        rest_metadata=make_rest_metadata(),
    )

    assert row.connection_id is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"requested_interval_ns": None},
        {"effective_interval_ns": None},
        {
            "requested_interval_ns": 60_000_000_000,
            "effective_interval_ns": 30_000_000_000,
        },
    ],
)
def test_rest_interval_metadata_is_paired_and_never_below_requested(
    overrides: dict[str, int | None],
) -> None:
    values = make_rest_metadata().model_dump()
    values.update(overrides)

    with pytest.raises(ValidationError, match="interval"):
        RestMetadata(**values)


def test_symbol_data_rejects_missing_instrument_identity() -> None:
    with pytest.raises(ValidationError, match="instrument_key"):
        make_envelope(logical_stream="trade", instrument_key=None, wire_symbol=None)


def test_unknown_non_control_stream_defaults_to_symbol_scope() -> None:
    with pytest.raises(ValidationError, match="instrument_key"):
        make_native_event_draft(
            logical_stream="new_exchange_stream",
            instrument_key=None,
            wire_symbol=None,
        )


def test_declared_market_stream_may_omit_instrument_identity() -> None:
    draft = make_native_event_draft(
        logical_stream="instrument",
        native_channel="instruments",
        instrument_key=None,
        wire_symbol=None,
    )

    assert draft.instrument_key is None


def test_exchange_control_draft_uses_explicit_null_scope() -> None:
    draft = make_native_event_draft(
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        payload={"kind": "config_committed"},
    )

    assert draft.market is None
    assert SourceContext.internal().egress_id is None


@pytest.mark.parametrize(
    "bad", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")]
)
def test_payload_rejects_every_non_finite_decimal(bad: Decimal) -> None:
    with pytest.raises(ValidationError, match="finite"):
        make_envelope(payload={"bad": [bad]})


@pytest.mark.parametrize(
    "raw", [b'{"bad":NaN}', b'{"bad":Infinity}', b'{"bad":-Infinity}']
)
def test_decoder_rejects_non_json_numeric_constants(raw: bytes) -> None:
    with pytest.raises(ValueError, match="non-finite|constant"):
        decode_json(raw)


@pytest.mark.parametrize(
    "builder", [make_native_event_draft, make_envelope], ids=["draft", "envelope"]
)
@pytest.mark.parametrize(
    "bad_payload",
    [
        {"nested": [0.1]},
        {"nested": [b"bytes"]},
        {1: "non-string-key"},
    ],
)
def test_draft_and_envelope_share_recursive_json_domain_rejection(
    builder: Callable[..., NativeEventDraft | RawEnvelope],
    bad_payload: dict[Any, Any],
) -> None:
    with pytest.raises(ValidationError, match="payload|JSON"):
        builder(payload=bad_payload)


@pytest.mark.parametrize(
    ("source", "transport", "logical_stream"),
    [
        (SourceContext.internal(), Transport.WEBSOCKET, "trade"),
        (
            SourceContext(
                connection_id="connection-1",
                connection_generation=1,
                egress_id="direct-primary",
            ),
            Transport.REST,
            "ticker",
        ),
        (
            SourceContext(
                connection_id=None, connection_generation=None, egress_id=None
            ),
            Transport.REST,
            "ticker",
        ),
    ],
)
def test_source_context_rejects_invalid_transport_combinations(
    source: SourceContext,
    transport: Transport,
    logical_stream: str,
) -> None:
    with pytest.raises(ValueError, match="source context"):
        source.validate_for(transport=transport, logical_stream=logical_stream)


def test_rest_bootstrap_requires_connection_generation_and_egress() -> None:
    with pytest.raises(ValidationError, match="source context"):
        make_envelope(
            transport=Transport.REST,
            logical_stream="book_live_bootstrap",
            connection_id=None,
            connection_generation=None,
            rest_metadata=make_rest_metadata(),
        )


def test_rest_bootstrap_accepts_generation_scoped_source() -> None:
    row = make_envelope(
        transport=Transport.REST,
        logical_stream="book_live_bootstrap",
        native_channel="/api/v5/market/books",
        rest_metadata=make_rest_metadata(),
    )

    assert row.connection_generation == 1


def test_internal_control_envelope_requires_entirely_null_source() -> None:
    row = make_envelope(
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        connection_id=None,
        connection_generation=None,
        egress_id=None,
        payload={"kind": "recovery"},
    )

    assert row.egress_id is None


def test_config_hash_must_be_lowercase_sha256() -> None:
    with pytest.raises(ValidationError, match="config_sha256"):
        make_envelope(config_sha256="A" * 64)
