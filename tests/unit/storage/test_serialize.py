from __future__ import annotations

from dataclasses import FrozenInstanceError
from decimal import Decimal
from typing import Any

import pytest

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.domain.types import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    Transport,
)
from crypto_collector.storage.models import AcceptedRecord
from crypto_collector.storage.serialize import decode_envelope_jsonl, encode_envelope


def make_envelope(**overrides: Any) -> RawEnvelope:
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
        "received_at_ns": 1_785_473_918_123_456_789,
        "monotonic_ns": 123,
        "worker_instance_id": "worker-1",
        "connection_id": "connection-1",
        "connection_generation": 1,
        "writer_sequence": 7,
        "egress_id": "direct-primary",
        "config_sha256": "a" * 64,
        "payload": {"asks": [["1.00", "2.50"]], "flag": None},
    }
    values.update(overrides)
    return RawEnvelope(**values)


def test_raw_json_preserves_payload_shape_and_uses_one_newline() -> None:
    envelope = make_envelope(
        payload={"asks": [["1.00", "2.50"]], "note": "line one\nline two"}
    )

    encoded = encode_envelope(envelope)

    assert encoded.endswith(b"\n")
    assert encoded.count(b"\n") == 1
    assert decode_json(encoded)["payload"] == envelope.payload


def test_decimal_is_encoded_as_a_json_number_and_round_trips() -> None:
    envelope = make_envelope(payload={"ratio": Decimal("0.100")})

    encoded = encode_envelope(envelope)

    assert b'"ratio":0.100' in encoded
    assert b'"ratio":"0.100"' not in encoded
    assert decode_json(encoded)["payload"]["ratio"] == Decimal("0.100")


def test_public_decoder_preserves_decimal_payload_and_strict_enums() -> None:
    envelope = make_envelope(
        integrity_mode=IntegrityMode.SEQUENCE_VERIFIED,
        coverage=CoverageMode.COMPLETE,
        payload={"ratio": Decimal("0.100")},
    )

    decoded = decode_envelope_jsonl(encode_envelope(envelope))

    assert decoded == envelope
    assert decoded.exchange is Exchange.OKX
    assert decoded.market is Market.SPOT
    assert decoded.transport is Transport.WEBSOCKET
    assert decoded.integrity_mode is IntegrityMode.SEQUENCE_VERIFIED
    assert decoded.coverage is CoverageMode.COMPLETE
    assert decoded.payload["ratio"] == Decimal("0.100")


@pytest.mark.parametrize(
    "line",
    [
        b"{}",
        b"[]\n",
        b"{}\n{}\n",
    ],
    ids=["missing-newline", "not-object", "multiple-jsonl-rows"],
)
def test_public_decoder_rejects_non_single_jsonl_object(line: bytes) -> None:
    with pytest.raises(ValueError):
        decode_envelope_jsonl(line)


@pytest.mark.parametrize("bad", [0.1, b"bytes", object()])
def test_serialization_rejects_values_outside_the_json_domain(bad: object) -> None:
    envelope = make_envelope().model_copy(update={"payload": {"bad": bad}})

    with pytest.raises(ValueError, match="JSON|unsupported"):
        encode_envelope(envelope)


def test_serialization_rejects_binary_float_outside_payload() -> None:
    envelope = make_envelope().model_copy(update={"received_at_ns": 0.1})

    with pytest.raises(ValueError, match="received_at_ns|integer"):
        encode_envelope(envelope)


def test_serialization_rejects_float_that_pydantic_literal_would_coerce() -> None:
    envelope = make_envelope().model_copy(update={"schema_version": 1.0})

    with pytest.raises(ValueError, match="float|JSON"):
        encode_envelope(envelope)


def test_serialization_rejects_boolean_schema_version() -> None:
    envelope = make_envelope().model_copy(update={"schema_version": True})

    with pytest.raises(ValueError, match="schema_version|integer 1"):
        encode_envelope(envelope)


def test_accepted_record_uses_the_envelope_acceptance_clock() -> None:
    envelope = make_envelope(monotonic_ns=987_654_321)
    encoded = encode_envelope(envelope)

    record = AcceptedRecord(envelope=envelope, encoded_jsonl=encoded)

    assert record.accepted_monotonic_ns == 987_654_321
    assert not hasattr(record, "__dict__")
    with pytest.raises(FrozenInstanceError):
        record.encoded_jsonl = b"changed\n"  # type: ignore[misc]
