import hashlib
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any

import simplejson  # type: ignore[import-untyped]
from pydantic import BaseModel

from crypto_collector.config.models import (
    CollectorConfig,
    validate_capability_registry_sha256,
)
from crypto_collector.config.primitives import SecretRef


def _canonicalize(value: object) -> Any:
    if isinstance(value, SecretRef):
        return value.fingerprint_value()
    if isinstance(value, BaseModel):
        return {
            name: _canonicalize(getattr(value, name))
            for name in sorted(type(value).model_fields)
        }
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, float):
        return Decimal(str(value))
    if value is None or type(value) in {bool, int, str, Decimal}:
        return value
    raise TypeError(f"unsupported canonical config value: {type(value).__name__}")


def config_sha256(
    config: CollectorConfig,
    *,
    capability_registry_sha256: str,
) -> str:
    registry_sha = validate_capability_registry_sha256(capability_registry_sha256)
    canonical = {
        "capability_registry_sha256": registry_sha,
        "config": _canonicalize(config),
    }
    encoded = simplejson.dumps(
        canonical,
        use_decimal=True,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
