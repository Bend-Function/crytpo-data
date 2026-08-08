from __future__ import annotations

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

_SCHEMA_VERSION = 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_DOCUMENT_BYTES = 8 * 1024 * 1024
_MAX_INT64 = (1 << 63) - 1
_MIN_INT64 = -(1 << 63)
_RESTART_REQUIRED_ROOTS = frozenset({"data_root", "process_model", "state_root"})
_ENVELOPE_KEYS = frozenset(
    {
        "base_dir",
        "capability_registry_sha256",
        "config_path",
        "config_sha256",
        "schema_version",
        "source_document",
    }
)


class ReferenceDocumentError(ValueError):
    """Raised when a durable config document is not strict reference-only JSON."""


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
    if key == "url" and "egress_pool" in parent_path:
        return True
    if "proxy" in token_set and "url" in token_set:
        return True
    return key == "expected" and "mount_guard" in parent_path


def _is_secret_reference(value: str) -> bool:
    scheme, separator, target = value.partition(":")
    if separator != ":" or scheme not in {"env", "file"} or not target:
        return False
    return scheme == "env" or Path(target).is_absolute()


def _contains_url_credentials(value: str) -> bool:
    if "://" not in value:
        return False
    try:
        parsed = urlsplit(value)
    except ValueError:
        raise ReferenceDocumentError("URL-like value has invalid syntax") from None
    return parsed.username is not None or parsed.password is not None


def _path_text(path: tuple[str, ...]) -> str:
    return ".".join(path) if path else "$"


def _freeze_reference_value(
    value: object,
    *,
    path: tuple[str, ...],
    secret_context: bool = False,
) -> object:
    if value is None or type(value) is bool:
        if secret_context and value is not None:
            raise ReferenceDocumentError(
                f"{_path_text(path)} must be an env: or file: reference"
            )
        return value
    if type(value) is str:
        text = str(value)
        if secret_context and not _is_secret_reference(text):
            raise ReferenceDocumentError(
                f"{_path_text(path)} must be an env: or file: reference"
            )
        if not _is_secret_reference(text) and _contains_url_credentials(text):
            raise ReferenceDocumentError(
                f"{_path_text(path)} embeds credentials instead of a secret reference"
            )
        return text
    if type(value) is int:
        integer = int(value)
        if secret_context:
            raise ReferenceDocumentError(
                f"{_path_text(path)} must be an env: or file: reference"
            )
        if not _MIN_INT64 <= integer <= _MAX_INT64:
            raise ReferenceDocumentError(f"{_path_text(path)} exceeds signed int64")
        return integer
    if type(value) is float:
        number = float(value)
        if secret_context:
            raise ReferenceDocumentError(
                f"{_path_text(path)} must be an env: or file: reference"
            )
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


def _normalized_absolute_path(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value:
        raise ReferenceDocumentError(f"{field_name} must be a non-empty string")
    raw = str(value)
    normalized = os.path.abspath(raw)
    if not Path(raw).is_absolute() or normalized != raw:
        raise ReferenceDocumentError(f"{field_name} must be a normalized absolute path")
    return raw


def _validate_sha256(value: object, *, field_name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(str(value)) is None:
        raise ReferenceDocumentError(f"{field_name} must be a lowercase SHA-256 digest")
    return str(value)


@dataclass(frozen=True, slots=True)
class ReferenceConfigSnapshot:
    """Durable config input containing references, never resolved secret values."""

    config_sha256: str
    capability_registry_sha256: str
    config_path: str
    base_dir: str
    source_document: Mapping[str, object] = field(repr=False)
    schema_version: int = _SCHEMA_VERSION

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
        object.__setattr__(
            self,
            "config_path",
            _normalized_absolute_path(self.config_path, field_name="config_path"),
        )
        object.__setattr__(
            self,
            "base_dir",
            _normalized_absolute_path(self.base_dir, field_name="base_dir"),
        )
        if not isinstance(self.source_document, Mapping):
            raise ReferenceDocumentError("source_document must be a JSON object")
        frozen = _freeze_reference_value(
            self.source_document, path=("source_document",)
        )
        if not isinstance(frozen, Mapping):  # pragma: no cover - guarded above
            raise ReferenceDocumentError("source_document must be a JSON object")
        object.__setattr__(self, "source_document", frozen)


def encode_reference_payload(payload: Mapping[str, object]) -> bytes:
    frozen = _freeze_reference_value(payload, path=("payload",))
    try:
        encoded = json.dumps(
            _thaw_reference_value(frozen),
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:  # defensive: validation owns the API error
        raise ReferenceDocumentError("payload is not canonical JSON") from error
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


def encode_reference_config(snapshot: ReferenceConfigSnapshot) -> bytes:
    if not isinstance(snapshot, ReferenceConfigSnapshot):
        raise TypeError("snapshot must be ReferenceConfigSnapshot")
    return encode_reference_payload(
        {
            "base_dir": snapshot.base_dir,
            "capability_registry_sha256": snapshot.capability_registry_sha256,
            "config_path": snapshot.config_path,
            "config_sha256": snapshot.config_sha256,
            "schema_version": snapshot.schema_version,
            "source_document": snapshot.source_document,
        }
    )


def decode_reference_config(encoded: bytes) -> ReferenceConfigSnapshot:
    document = decode_reference_payload(encoded)
    if frozenset(document) != _ENVELOPE_KEYS:
        raise ReferenceDocumentError(
            "reference config envelope must contain exactly the version 1 fields"
        )
    source = document["source_document"]
    if not isinstance(source, Mapping):
        raise ReferenceDocumentError("source_document must be a JSON object")
    return ReferenceConfigSnapshot(
        schema_version=document["schema_version"],  # type: ignore[arg-type]
        config_sha256=document["config_sha256"],  # type: ignore[arg-type]
        capability_registry_sha256=document["capability_registry_sha256"],  # type: ignore[arg-type]
        config_path=document["config_path"],  # type: ignore[arg-type]
        base_dir=document["base_dir"],  # type: ignore[arg-type]
        source_document=source,
    )


@dataclass(frozen=True, slots=True)
class ReloadDiff:
    changed_paths: tuple[str, ...]
    restart_required_keys: tuple[str, ...]

    @property
    def restart_required(self) -> bool:
        return bool(self.restart_required_keys)


def _join_path(parent: str, child: str) -> str:
    if child.startswith("["):
        return f"{parent}{child}"
    return child if not parent else f"{parent}.{child}"


def _collect_changed_paths(old: object, new: object, path: str) -> set[str]:
    if isinstance(old, Mapping) and isinstance(new, Mapping):
        changed: set[str] = set()
        keys = frozenset(old) | frozenset(new)
        for key in keys:
            child_path = _join_path(path, key)
            if key not in old or key not in new:
                changed.add(child_path)
            else:
                changed.update(_collect_changed_paths(old[key], new[key], child_path))
        return changed
    if isinstance(old, tuple) and isinstance(new, tuple):
        if len(old) != len(new):
            return {path}
        changed = set()
        for index, (old_child, new_child) in enumerate(zip(old, new, strict=True)):
            changed.update(
                _collect_changed_paths(
                    old_child,
                    new_child,
                    _join_path(path, f"[{index}]"),
                )
            )
        return changed
    return set() if type(old) is type(new) and old == new else {path}


def classify_reload(
    old: ReferenceConfigSnapshot,
    new: ReferenceConfigSnapshot,
) -> ReloadDiff:
    """Return a deterministic diff without resolving references or mutating snapshots."""

    if not isinstance(old, ReferenceConfigSnapshot) or not isinstance(
        new, ReferenceConfigSnapshot
    ):
        raise TypeError("old and new must be ReferenceConfigSnapshot")
    changed = _collect_changed_paths(old.source_document, new.source_document, "")
    if old.capability_registry_sha256 != new.capability_registry_sha256:
        changed.add("capability_registry_sha256")
    if old.config_path != new.config_path:
        changed.add("config_path")
    if old.base_dir != new.base_dir:
        changed.add("base_dir")
    changed_paths = tuple(sorted(changed))
    restart = tuple(
        sorted(
            {
                (
                    "process_model"
                    if path.rpartition(".")[2].partition("[")[0] == "process_model"
                    else path.partition(".")[0].partition("[")[0]
                )
                for path in changed_paths
                if (
                    path.partition(".")[0].partition("[")[0] in _RESTART_REQUIRED_ROOTS
                    or path.rpartition(".")[2].partition("[")[0] == "process_model"
                )
            }
        )
    )
    return ReloadDiff(
        changed_paths=changed_paths,
        restart_required_keys=restart,
    )


__all__ = [
    "ReferenceConfigSnapshot",
    "ReferenceDocumentError",
    "ReloadDiff",
    "classify_reload",
    "decode_reference_config",
    "decode_reference_payload",
    "encode_reference_config",
    "encode_reference_payload",
]
