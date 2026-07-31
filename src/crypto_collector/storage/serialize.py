from enum import Enum

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.json_codec import encode_json, validate_json_payload

_ENUM_FIELDS = ("exchange", "market", "transport", "integrity_mode", "coverage")


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
