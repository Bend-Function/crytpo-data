from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any
from urllib.parse import urlsplit

_LEGACY_SCHEMA_VERSION = 1
_SCHEMA_VERSION = 2
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
_MAX_INT64 = (1 << 63) - 1
_MIN_INT64 = -(1 << 63)
_LEGACY_ENVELOPE_KEYS = frozenset(
    {
        "base_dir",
        "capability_registry_sha256",
        "config_path",
        "config_sha256",
        "schema_version",
        "source_document",
    }
)
_ENVELOPE_KEYS = _LEGACY_ENVELOPE_KEYS | {"document_sha256"}


class ReferenceDocumentError(ValueError):
    """Raised when a durable config document is not strict reference-only JSON."""


def _identifier(value: str) -> str:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]", "", separated.lower())


def _is_sensitive_key(key: str, *, parent_path: tuple[str, ...]) -> bool:
    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    tokens = tuple(
        token for token in re.split(r"[^a-z0-9]+", separated.lower()) if token
    )
    token_set = frozenset(tokens)
    if token_set & {
        "authorization",
        "credential",
        "credentials",
        "password",
        "passwd",
        "secret",
        "token",
    }:
        return True
    if any(
        left in token_set and "key" in token_set
        for left in ("access", "api", "private")
    ):
        return True
    key_identity = _identifier(key)
    parent_identities = {_identifier(component) for component in parent_path}
    if key_identity == "url" and "egresspool" in parent_identities:
        return True
    if "proxy" in token_set and "url" in token_set:
        return True
    return key_identity == "expected" and "mountguard" in parent_identities


def _is_secret_reference(value: str) -> bool:
    scheme, separator, target = value.partition(":")
    if separator != ":" or scheme not in {"env", "file"} or not target:
        return False
    return scheme == "env" or Path(target).is_absolute()


def _contains_url_credentials(value: str) -> bool:
    if "://" not in value and not value.startswith("//"):
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ReferenceDocumentError("URL-like value has invalid syntax") from None
    return (
        parsed.username is not None
        or parsed.password is not None
        or bool(parsed.query)
        or bool(parsed.fragment)
    )


def _path_text(path: tuple[str, ...]) -> str:
    return ".".join(path) if path else "$"


def _secret_reference_error(path: tuple[str, ...]) -> ReferenceDocumentError:
    return ReferenceDocumentError(
        f"{_path_text(path)}: secret must use env:NAME or file:/absolute/path"
    )


def _is_public_endpoint_path(path: tuple[str, ...]) -> bool:
    identities = tuple(_identifier(component) for component in path)
    return (
        bool(identities)
        and identities[0] == "sourcedocument"
        and (
            identities[-1] == "endpoint"
            or ("exchanges" in identities and "endpoints" in identities[:-1])
        )
    )


def _validate_public_endpoint(value: str, *, path: tuple[str, ...]) -> None:
    invalid = any(
        character.isspace()
        or ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or character == "\\"
        for character in value
    )
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except (UnicodeError, ValueError):
        invalid = True
        parsed = None
        port = None
    if parsed is not None:
        invalid = invalid or (
            parsed.scheme not in {"http", "https", "ws", "wss"}
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or bool(parsed.query)
            or bool(parsed.fragment)
            or "?" in value
            or "#" in value
            or "@" in parsed.netloc
            or "%" in parsed.netloc
            or parsed.netloc.endswith(":")
            or (port is not None and not 1 <= port <= 65_535)
        )
    if invalid:
        raise ReferenceDocumentError(
            f"{_path_text(path)} must be an unambiguous anonymous public endpoint"
        )


def _freeze_reference_value(
    value: object,
    *,
    path: tuple[str, ...],
    secret_context: bool = False,
) -> object:
    if value is None or type(value) is bool:
        if secret_context and value is not None:
            raise _secret_reference_error(path)
        return value
    if type(value) is str:
        text = str(value)
        if secret_context and not _is_secret_reference(text):
            raise _secret_reference_error(path)
        if _is_public_endpoint_path(path):
            _validate_public_endpoint(text, path=path)
        if not _is_secret_reference(text) and _contains_url_credentials(text):
            raise ReferenceDocumentError(
                f"{_path_text(path)} embeds credentials instead of a secret reference"
            )
        return text
    if type(value) is int:
        integer = int(value)
        if secret_context:
            raise _secret_reference_error(path)
        if not _MIN_INT64 <= integer <= _MAX_INT64:
            raise ReferenceDocumentError(f"{_path_text(path)} exceeds signed int64")
        return integer
    if type(value) is float:
        number = float(value)
        if secret_context:
            raise _secret_reference_error(path)
        if not math.isfinite(number):
            raise ReferenceDocumentError(f"{_path_text(path)} must be finite")
        return number
    if isinstance(value, Mapping):
        frozen: dict[str, object] = {}
        for raw_key, child in value.items():
            if type(raw_key) is not str or not raw_key:
                raise ReferenceDocumentError(
                    f"{_path_text(path)} object keys must be non-empty strings"
                )
            key = str(raw_key)
            if (
                path
                and path[0] == "payload"
                and key.casefold()
                in {"detail", "error", "exception", "message", "reason"}
            ):
                raise ReferenceDocumentError(
                    f"{_path_text(path + (key,))} must use a normalized *_code field"
                )
            if key in frozen:
                raise ReferenceDocumentError(
                    f"duplicate object key at {_path_text(path + (key,))}"
                )
            frozen[key] = _freeze_reference_value(
                child,
                path=path + (key,),
                secret_context=secret_context
                or _is_sensitive_key(key, parent_path=path),
            )
        return MappingProxyType(frozen)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return tuple(
            _freeze_reference_value(
                child,
                path=path + (f"[{index}]",),
                secret_context=secret_context,
            )
            for index, child in enumerate(value)
        )
    raise ReferenceDocumentError(
        f"{_path_text(path)} has unsupported value type {type(value).__name__}"
    )


def _thaw_reference_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _thaw_reference_value(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_thaw_reference_value(child) for child in value]
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            _thaw_reference_value(value),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:  # defensive: validation owns the API error
        raise ReferenceDocumentError("payload is not canonical JSON") from error


def _normalized_absolute_path(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value:
        raise ReferenceDocumentError(f"{field_name} must be a non-empty string")
    raw = str(value)
    if "\x00" in raw:
        raise ReferenceDocumentError(f"{field_name} could not be normalized")
    normalized = os.path.abspath(raw)
    if not Path(raw).is_absolute() or normalized != raw:
        raise ReferenceDocumentError(f"{field_name} must be a normalized absolute path")
    return raw


def _validate_sha256(value: object, *, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(str(value)) is None:
        raise ReferenceDocumentError(f"{field_name} must be a lowercase SHA-256 digest")
    return str(value)


def _reference_document_sha256(
    *,
    schema_version: int,
    config_sha256: str,
    capability_registry_sha256: str,
    config_path: str,
    base_dir: str,
    source_document: Mapping[str, object],
) -> str:
    unsigned = {
        "base_dir": base_dir,
        "capability_registry_sha256": capability_registry_sha256,
        "config_path": config_path,
        "config_sha256": config_sha256,
        "schema_version": schema_version,
        "source_document": source_document,
    }
    return hashlib.sha256(_canonical_json_bytes(unsigned)).hexdigest()


def freeze_reference_document(
    document: Mapping[str, object],
    *,
    enforce_size_limit: bool = False,
) -> Mapping[str, object]:
    """Validate and freeze a reference-only config document without reading secrets."""

    if not isinstance(document, Mapping):
        raise ReferenceDocumentError("source_document must be a JSON object")
    frozen = _freeze_reference_value(document, path=("source_document",))
    if not isinstance(frozen, Mapping):  # pragma: no cover - guarded above
        raise ReferenceDocumentError("source_document must be a JSON object")
    if enforce_size_limit and len(_canonical_json_bytes(frozen)) > _MAX_DOCUMENT_BYTES:
        raise ReferenceDocumentError("encoded payload exceeds 8 MiB")
    return frozen


def thaw_reference_document(document: Mapping[str, object]) -> dict[str, object]:
    """Return a mutable JSON-compatible copy of a frozen reference document."""

    thawed = _thaw_reference_value(document)
    if not isinstance(thawed, dict):  # pragma: no cover - validated by the freezer
        raise ReferenceDocumentError("source_document must be a JSON object")
    return thawed


@dataclass(frozen=True, slots=True)
class ReferenceConfigSnapshot:
    """Durable config input containing references, never resolved secret values."""

    config_sha256: str
    capability_registry_sha256: str
    config_path: str
    base_dir: str
    source_document: Mapping[str, object] = field(repr=False)
    document_sha256: str | None = field(default=None, repr=False)
    schema_version: int = _SCHEMA_VERSION
    _legacy_encoding: bytes | None = field(
        default=None,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != _SCHEMA_VERSION
        ):
            raise ReferenceDocumentError(f"schema_version must equal {_SCHEMA_VERSION}")
        object.__setattr__(
            self,
            "config_sha256",
            _validate_sha256(self.config_sha256, field_name="config_sha256"),
        )
        object.__setattr__(
            self,
            "capability_registry_sha256",
            _validate_sha256(
                self.capability_registry_sha256,
                field_name="capability_registry_sha256",
            ),
        )
        config_path = _normalized_absolute_path(
            self.config_path, field_name="config_path"
        )
        object.__setattr__(self, "config_path", config_path)
        base_dir = _normalized_absolute_path(self.base_dir, field_name="base_dir")
        object.__setattr__(self, "base_dir", base_dir)
        if Path(config_path).parent != Path(base_dir):
            raise ReferenceDocumentError("config_path must be directly inside base_dir")
        frozen = freeze_reference_document(self.source_document)
        object.__setattr__(self, "source_document", frozen)

        computed_digest = _reference_document_sha256(
            schema_version=self.schema_version,
            config_sha256=self.config_sha256,
            capability_registry_sha256=self.capability_registry_sha256,
            config_path=config_path,
            base_dir=base_dir,
            source_document=frozen,
        )
        if self.document_sha256 is not None:
            supplied_digest = _validate_sha256(
                self.document_sha256,
                field_name="document_sha256",
            )
            if not hmac.compare_digest(supplied_digest, computed_digest):
                raise ReferenceDocumentError(
                    "reference config document digest does not match its content"
                )
        object.__setattr__(self, "document_sha256", computed_digest)

    def __reduce__(self) -> tuple[object, tuple[bytes]]:
        return decode_reference_config, (encode_reference_config(self),)


def _encode_reference_payload_unbounded(payload: Mapping[str, object]) -> bytes:
    frozen = _freeze_reference_value(payload, path=("payload",))
    return _canonical_json_bytes(frozen)


def encode_reference_payload(payload: Mapping[str, object]) -> bytes:
    encoded = _encode_reference_payload_unbounded(payload)
    if len(encoded) > _MAX_DOCUMENT_BYTES:
        raise ReferenceDocumentError("encoded payload exceeds 8 MiB")
    return encoded


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ReferenceDocumentError(f"duplicate object key: {key}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ReferenceDocumentError(f"invalid JSON constant: {value}")


def decode_reference_payload(encoded: bytes) -> Mapping[str, object]:
    if type(encoded) is not bytes or not encoded:
        raise ReferenceDocumentError("encoded payload must be non-empty bytes")
    if len(encoded) > _MAX_DOCUMENT_BYTES:
        raise ReferenceDocumentError("encoded payload exceeds 8 MiB")
    try:
        loaded = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReferenceDocumentError(
            "encoded payload is not strict UTF-8 JSON"
        ) from error
    if not isinstance(loaded, Mapping):
        raise ReferenceDocumentError("encoded payload must contain a JSON object")
    frozen = _freeze_reference_value(loaded, path=("payload",))
    if not isinstance(frozen, Mapping):  # pragma: no cover - guarded above
        raise ReferenceDocumentError("encoded payload must contain a JSON object")
    return frozen


def _validated_reference_config(
    snapshot: ReferenceConfigSnapshot,
) -> ReferenceConfigSnapshot:
    if not isinstance(snapshot, ReferenceConfigSnapshot):
        raise TypeError("snapshot must be ReferenceConfigSnapshot")
    if snapshot.document_sha256 is None:
        raise ReferenceDocumentError("reference config document digest is missing")
    return ReferenceConfigSnapshot(
        schema_version=snapshot.schema_version,
        config_sha256=snapshot.config_sha256,
        capability_registry_sha256=snapshot.capability_registry_sha256,
        config_path=snapshot.config_path,
        base_dir=snapshot.base_dir,
        source_document=snapshot.source_document,
        document_sha256=snapshot.document_sha256,
    )


def _encode_validated_reference_config_unbounded(
    snapshot: ReferenceConfigSnapshot,
) -> bytes:
    return _encode_reference_payload_unbounded(
        {
            "base_dir": snapshot.base_dir,
            "capability_registry_sha256": snapshot.capability_registry_sha256,
            "config_path": snapshot.config_path,
            "config_sha256": snapshot.config_sha256,
            "document_sha256": snapshot.document_sha256,
            "schema_version": snapshot.schema_version,
            "source_document": snapshot.source_document,
        }
    )


def encode_reference_config(snapshot: ReferenceConfigSnapshot) -> bytes:
    validated = _validated_reference_config(snapshot)
    encoded = _encode_validated_reference_config_unbounded(validated)
    if len(encoded) <= _MAX_DOCUMENT_BYTES:
        return encoded

    legacy_encoding = snapshot._legacy_encoding
    if legacy_encoding is not None:
        try:
            legacy_snapshot, source_schema_version = (
                _decode_reference_config_with_schema(legacy_encoding)
            )
        except ValueError:
            pass
        else:
            if (
                source_schema_version == _LEGACY_SCHEMA_VERSION
                and legacy_snapshot == validated
            ):
                return legacy_encoding
    raise ReferenceDocumentError("encoded payload exceeds 8 MiB")


def _decode_reference_config_document(
    document: Mapping[str, object],
) -> tuple[ReferenceConfigSnapshot, int]:
    schema_version = document.get("schema_version")
    if type(schema_version) is not int:
        raise ReferenceDocumentError(
            "reference config schema_version must be an integer"
        )
    if schema_version == _LEGACY_SCHEMA_VERSION:
        if frozenset(document) != _LEGACY_ENVELOPE_KEYS:
            raise ReferenceDocumentError(
                "reference config envelope must contain exactly the version 1 fields"
            )
        document_sha256 = None
    elif schema_version == _SCHEMA_VERSION:
        if frozenset(document) != _ENVELOPE_KEYS:
            raise ReferenceDocumentError(
                "reference config envelope must contain exactly the version 2 fields"
            )
        document_sha256 = document["document_sha256"]
    else:
        raise ReferenceDocumentError(
            f"unsupported reference config schema_version {schema_version}"
        )
    source = document["source_document"]
    if not isinstance(source, Mapping):
        raise ReferenceDocumentError("source_document must be a JSON object")
    return (
        ReferenceConfigSnapshot(
            schema_version=_SCHEMA_VERSION,
            config_sha256=document["config_sha256"],  # type: ignore[arg-type]
            capability_registry_sha256=document["capability_registry_sha256"],  # type: ignore[arg-type]
            config_path=document["config_path"],  # type: ignore[arg-type]
            base_dir=document["base_dir"],  # type: ignore[arg-type]
            source_document=source,
            document_sha256=document_sha256,  # type: ignore[arg-type]
        ),
        schema_version,
    )


def _decode_reference_config_with_schema(
    encoded: bytes,
) -> tuple[ReferenceConfigSnapshot, int]:
    snapshot, source_schema_version = _decode_reference_config_document(
        decode_reference_payload(encoded)
    )
    if source_schema_version == _LEGACY_SCHEMA_VERSION:
        object.__setattr__(snapshot, "_legacy_encoding", encoded)
    return snapshot, source_schema_version


def decode_reference_config(encoded: bytes) -> ReferenceConfigSnapshot:
    snapshot, _ = _decode_reference_config_with_schema(encoded)
    return snapshot


def decode_stored_reference_config(
    encoded: bytes,
) -> tuple[ReferenceConfigSnapshot, bytes]:
    """Decode a stored snapshot and return its migration rewrite when one fits."""

    snapshot, _ = _decode_reference_config_with_schema(encoded)
    return snapshot, encode_reference_config(snapshot)


__all__ = [
    "ReferenceConfigSnapshot",
    "ReferenceDocumentError",
    "decode_reference_config",
    "decode_reference_payload",
    "decode_stored_reference_config",
    "encode_reference_config",
    "encode_reference_payload",
    "freeze_reference_document",
    "thaw_reference_document",
]
