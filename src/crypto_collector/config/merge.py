from collections.abc import Mapping
from copy import deepcopy
from typing import Any


def merge_layers(*layers: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for layer in layers:
        result = _merge(result, layer)
    return result


def _merge(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    merged = deepcopy(dict(left))
    for key, value in right.items():
        if isinstance(merged.get(key), Mapping) and isinstance(value, Mapping):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged
