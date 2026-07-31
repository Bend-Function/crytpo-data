from __future__ import annotations

import math
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.constructor import ConstructorError, DuplicateKeyError
from ruamel.yaml.error import YAMLError
from ruamel.yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

_MERGE_TAG = "tag:yaml.org,2002:merge"


class ConfigSyntaxError(ValueError):
    def __init__(self, path: Path, message: str) -> None:
        self.path = path
        self.detail = message
        super().__init__(f"{path}: {message}")


def _yaml() -> YAML:
    parser = YAML(typ="safe", pure=True)
    parser.allow_duplicate_keys = False
    return parser


def _yaml_error_detail(error: YAMLError) -> str:
    mark = getattr(error, "problem_mark", None)
    location = ""
    if mark is not None:
        location = f" at line {mark.line + 1}, column {mark.column + 1}"
    if isinstance(error, DuplicateKeyError):
        return f"duplicate YAML mapping key{location}"
    if isinstance(error, ConstructorError):
        return f"unsupported YAML tag or constructor{location}"
    return f"invalid YAML syntax{location}"


def _reject_merge_keys(node: Node, *, path: Path, seen: set[int]) -> None:
    identity = id(node)
    if identity in seen:
        return
    seen.add(identity)

    if isinstance(node, MappingNode):
        for key, value in node.value:
            if key.tag == _MERGE_TAG or (
                isinstance(key, ScalarNode) and key.value == "<<"
            ):
                raise ConfigSyntaxError(path, "YAML merge keys are not supported")
            _reject_merge_keys(key, path=path, seen=seen)
            _reject_merge_keys(value, path=path, seen=seen)
    elif isinstance(node, SequenceNode):
        for value in node.value:
            _reject_merge_keys(value, path=path, seen=seen)


def _reject_anchors(node: Node, *, path: Path, seen: set[int]) -> None:
    identity = id(node)
    if identity in seen:
        return
    seen.add(identity)
    if node.anchor is not None:
        raise ConfigSyntaxError(path, "YAML anchors and aliases are not supported")
    if isinstance(node, MappingNode):
        for key, value in node.value:
            _reject_anchors(key, path=path, seen=seen)
            _reject_anchors(value, path=path, seen=seen)
    elif isinstance(node, SequenceNode):
        for value in node.value:
            _reject_anchors(value, path=path, seen=seen)


def _plain_mapping(value: Mapping[object, object], *, path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in value.items():
        if type(key) is not str:
            raise ConfigSyntaxError(path, "all YAML mapping keys must be strings")
        result[key] = _plain_value(item, path=path)
    return result


def _plain_value(value: object, *, path: Path) -> Any:
    if isinstance(value, Mapping):
        return _plain_mapping(value, path=path)
    if isinstance(value, list):
        return [_plain_value(item, path=path) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ConfigSyntaxError(path, "floating-point YAML scalars must be finite")
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise ConfigSyntaxError(
        path, f"unsupported YAML scalar type: {type(value).__name__}"
    )


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    path = Path(path)
    text = path.read_text(encoding="utf-8")

    try:
        documents = list(_yaml().compose_all(text))
    except YAMLError as error:
        raise ConfigSyntaxError(path, _yaml_error_detail(error)) from error

    if len(documents) != 1:
        raise ConfigSyntaxError(path, "configuration must contain a single document")
    document = documents[0]
    if document is None or not isinstance(document, MappingNode):
        raise ConfigSyntaxError(path, "configuration root must be a mapping")
    _reject_merge_keys(document, path=path, seen=set())
    _reject_anchors(document, path=path, seen=set())

    try:
        loaded = _yaml().load(text)
    except YAMLError as error:
        raise ConfigSyntaxError(path, _yaml_error_detail(error)) from error
    if not isinstance(loaded, Mapping):
        raise ConfigSyntaxError(path, "configuration root must be a mapping")
    return _plain_mapping(loaded, path=path)


__all__ = ["ConfigSyntaxError", "load_yaml_mapping"]
