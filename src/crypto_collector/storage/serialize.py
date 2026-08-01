from enum import Enum

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.json_codec import (
    decode_json,
    encode_json,
    validate_json_payload,
)
from crypto_collector.domain.types import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    Transport,
)

_ENUM_FIELDS = ("exchange", "market", "transport", "integrity_mode", "coverage")
_ENUM_TYPES = {
    "exchange": Exchange,
    "market": Market,
    "transport": Transport,
    "integrity_mode": IntegrityMode,
    "coverage": CoverageMode,
}


def encode_envelope(envelope: RawEnvelope) -> bytes:
    wire = envelope.model_dump(mode="python", warnings=False)
    if type(wire.get("schema_version")) is not int or wire["schema_version"] != 1:
        raise ValueError(
            "schema_version must be the integer 1; binary float and bool are invalid"
        )
    json_domain_wire = wire.copy()
    for field in _ENUM_FIELDS:
        value = json_domain_wire.get(field)
        if isinstance(value, Enum):
            json_domain_wire[field] = value.value
    validate_json_payload(json_domain_wire)
    RawEnvelope.model_validate(wire)
    return encode_json(wire) + b"\n"


def decode_envelope_jsonl(line: bytes) -> RawEnvelope:
    if type(line) is not bytes:
        raise TypeError("raw envelope line must be bytes")
    if not line.endswith(b"\n"):
        raise ValueError("raw envelope line must end with newline")
    wire = decode_json(line[:-1])
    if type(wire) is not dict:
        raise ValueError("raw envelope line must contain one JSON object")
    for field, enum_type in _ENUM_TYPES.items():
        if wire.get(field) is not None:
            wire[field] = enum_type(wire[field])
    return RawEnvelope.model_validate(wire)


__all__ = ["decode_envelope_jsonl", "encode_envelope"]
