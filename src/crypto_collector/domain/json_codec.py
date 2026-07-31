from decimal import Decimal
from typing import TYPE_CHECKING, Annotated, Any, TypeAlias

import simplejson  # type: ignore[import-untyped]
from pydantic import PlainValidator
from typing_extensions import TypeAliasType

if TYPE_CHECKING:
    JsonPayload: TypeAlias = (
        bool
        | int
        | Decimal
        | str
        | None
        | list["JsonPayload"]
        | dict[str, "JsonPayload"]
    )
else:
    JsonPayload = TypeAliasType(
        "JsonPayload",
        bool
        | int
        | Decimal
        | str
        | None
        | list["JsonPayload"]
        | dict[str, "JsonPayload"],
    )


def _json_path(path: tuple[str | int, ...]) -> str:
    rendered = "$"
    for segment in path:
        if isinstance(segment, int):
            rendered += f"[{segment}]"
        else:
            rendered += f".{segment}"
    return rendered


def validate_json_payload(
    value: Any,
    path: tuple[str | int, ...] = (),
) -> JsonPayload:
    if value is None or type(value) in {bool, int, str}:
        return value
    if isinstance(value, Decimal):
        if not value.is_finite():
            raise ValueError(f"JSON Decimal at {_json_path(path)} must be finite")
        return value
    if isinstance(value, list):
        return [
            validate_json_payload(item, (*path, index))
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        validated: dict[str, JsonPayload] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ValueError(
                    f"JSON object key at {_json_path(path)} must be a string"
                )
            validated[key] = validate_json_payload(item, (*path, key))
        return validated
    raise ValueError(
        f"JSON value at {_json_path(path)} has unsupported type {type(value).__name__}"
    )


ValidatedJsonPayload: TypeAlias = Annotated[
    JsonPayload,
    PlainValidator(validate_json_payload),
]


def reject_non_finite_constant(token: str) -> None:
    raise ValueError(f"non-finite JSON constant is not allowed: {token}")


def decode_json(data: str | bytes) -> Any:
    return simplejson.loads(
        data,
        use_decimal=True,
        allow_nan=False,
        parse_constant=reject_non_finite_constant,
    )


def encode_json(value: Any) -> bytes:
    return simplejson.dumps(
        value,
        use_decimal=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=False,
    ).encode("utf-8")
