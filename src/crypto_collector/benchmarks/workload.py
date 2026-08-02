from __future__ import annotations

import errno
import math
import os
import re
import stat
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from hashlib import sha256
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal, Self, cast

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_serializer,
    field_validator,
    model_validator,
)
from ruamel.yaml import YAML
from ruamel.yaml.constructor import ConstructorError, DuplicateKeyError
from ruamel.yaml.error import YAMLError
from ruamel.yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode

RESEARCH_DEFAULT_V1_SHA256 = (
    "4a1594dc8e0b05c56465207218631b8c57f26b6a1918468c6d1121126a64f69b"
)

_MERGE_TAG = "tag:yaml.org,2002:merge"
_CANONICAL_DECIMAL = re.compile(r"(?:0|[1-9][0-9]*)(?:\.[0-9]+)?\Z")
_CANONICAL_EXCHANGES = ("binance", "okx", "bybit", "bitget", "kraken")
_CANONICAL_MARKETS = ("spot", "perpetual")
_CANONICAL_DERIVATIVE_STREAMS = ("funding", "open_interest")
_ORDINARY_STREAMS = (
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "candle_1m",
    "book_deep_snapshot",
)
_STREAM_GROUPS = (
    *_ORDINARY_STREAMS[:4],
    "derivative",
    *_ORDINARY_STREAMS[4:],
    "control",
)


def _tuple(value: object) -> object:
    if type(value) is list:
        return tuple(cast(list[object], value))
    return value


def _positive_decimal_string(value: object) -> Decimal:
    if type(value) is not str or _CANONICAL_DECIMAL.fullmatch(value) is None:
        raise ValueError("value must be a canonical positive decimal string")
    try:
        parsed = Decimal(value)
    except InvalidOperation as error:
        raise ValueError("value must be a finite positive decimal string") from error
    if not parsed.is_finite() or parsed <= 0:
        raise ValueError("value must be a finite positive decimal string")
    return parsed


def _fraction_decimal_string(value: object) -> Decimal:
    parsed = _positive_decimal_string(value)
    if parsed > 1:
        raise ValueError("fraction must be a decimal string in the interval (0, 1]")
    return parsed


PositiveInt = Annotated[int, Field(gt=0)]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveDecimal = Annotated[Decimal, BeforeValidator(_positive_decimal_string)]
FractionDecimal = Annotated[Decimal, BeforeValidator(_fraction_decimal_string)]
CanonicalName = Annotated[
    str,
    StringConstraints(min_length=1, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$"),
]
ExchangeName = Literal["binance", "okx", "bybit", "bitget", "kraken"]
MarketName = Literal["spot", "perpetual"]
DerivativeLogicalStream = Literal["funding", "open_interest"]
StreamGroupName = Literal[
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "derivative",
    "candle_1m",
    "book_deep_snapshot",
    "control",
]
LogicalStreamName = Literal[
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "funding",
    "open_interest",
    "candle_1m",
    "book_deep_snapshot",
    "_control",
]
StreamTransport = Literal["websocket", "rest", "internal"]
ExchangeTuple = Annotated[
    tuple[ExchangeName, ...],
    BeforeValidator(_tuple),
    Field(min_length=1),
]
MarketTuple = Annotated[
    tuple[MarketName, ...],
    BeforeValidator(_tuple),
    Field(min_length=1),
]
DerivativeLogicalStreamTuple = Annotated[
    tuple[DerivativeLogicalStream, ...],
    BeforeValidator(_tuple),
    Field(min_length=1),
]


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class _PayloadSizedStreamV1(_FrozenStrictModel):
    mean_records_per_second: PositiveDecimal
    burst_records_in_1s: PositiveInt
    payload_p50_bytes: PositiveInt
    payload_p95_bytes: PositiveInt
    payload_max_bytes: PositiveInt

    @model_validator(mode="after")
    def validate_payload_sizes(self) -> Self:
        if not (
            self.payload_p50_bytes <= self.payload_p95_bytes <= self.payload_max_bytes
        ):
            raise ValueError("payload sizes must be ordered p50 <= p95 <= max")
        return self


class _OrdinaryStreamV1(_PayloadSizedStreamV1):
    instances: PositiveInt


class _DerivativeStreamV1(_PayloadSizedStreamV1):
    instrument_instances: PositiveInt
    file_instances: PositiveInt
    markets: Annotated[
        tuple[Literal["perpetual"], ...],
        BeforeValidator(_tuple),
        Field(min_length=1),
    ]
    logical_streams_per_instrument: PositiveInt

    @field_validator("markets", mode="after")
    @classmethod
    def validate_unique_markets(
        cls,
        value: tuple[Literal["perpetual"], ...],
    ) -> tuple[Literal["perpetual"], ...]:
        if len(set(value)) != len(value):
            raise ValueError("derivative markets must be unique")
        return value


class _ControlStreamV1(_PayloadSizedStreamV1):
    instances: PositiveInt
    scope: Literal["exchange"]


StreamDefinitionV1 = _OrdinaryStreamV1 | _DerivativeStreamV1 | _ControlStreamV1


class _PayloadGenerationV1(_FrozenStrictModel):
    decimal_string_fraction: FractionDecimal
    repeated_key_fraction: FractionDecimal
    incompressible_fraction: FractionDecimal


class _QueueLimitsV1(_FrozenStrictModel):
    shard_max_records: PositiveInt
    shard_max_bytes: PositiveInt
    worker_max_bytes: PositiveInt
    control_reserve_records: PositiveInt
    control_reserve_bytes: PositiveInt

    @model_validator(mode="after")
    def validate_relationships(self) -> Self:
        if self.worker_max_bytes < self.shard_max_bytes:
            raise ValueError("worker queue bytes must cover at least one shard")
        if self.control_reserve_records > self.shard_max_records:
            raise ValueError("control reserve records exceed the shard limit")
        if self.control_reserve_bytes > self.shard_max_bytes:
            raise ValueError("control reserve bytes exceed the shard limit")
        if self.control_reserve_bytes >= self.worker_max_bytes:
            raise ValueError("control reserve bytes must be below worker queue bytes")
        return self


class _QualificationLimitsV1(_FrozenStrictModel):
    warmup_seconds: NonNegativeInt
    storage_health_sample_interval_seconds: PositiveInt
    storage_health_max_gap_seconds: PositiveInt
    max_rss_bytes: PositiveInt
    max_rss_slope_bytes_per_minute: NonNegativeInt
    max_open_fds: PositiveInt
    max_fd_growth_after_warmup: NonNegativeInt
    durability_lag_max_ns: PositiveInt

    @model_validator(mode="after")
    def validate_relationships(self) -> Self:
        if (
            self.storage_health_max_gap_seconds
            < self.storage_health_sample_interval_seconds
        ):
            raise ValueError(
                "storage health maximum gap must cover the sampling interval"
            )
        if self.max_fd_growth_after_warmup > self.max_open_fds:
            raise ValueError("post-warmup FD growth cannot exceed the FD limit")
        return self


_STREAM_MODELS: dict[str, type[_FrozenStrictModel]] = {
    **{name: _OrdinaryStreamV1 for name in _ORDINARY_STREAMS},
    "derivative": _DerivativeStreamV1,
    "control": _ControlStreamV1,
}


class GateWorkloadV1(_FrozenStrictModel):
    schema_version: Literal[1]
    name: CanonicalName
    generation_seed: NonNegativeInt
    exchanges: ExchangeTuple
    markets: MarketTuple
    symbols_per_market: PositiveInt
    derivative_logical_streams: DerivativeLogicalStreamTuple
    identity_algorithm: Literal["gate-identity-v1"]
    payload_algorithm: Literal["gate-payload-v1"]
    schedule_algorithm: Literal["gate-schedule-v2-full-second-burst"]
    stream_transports: Mapping[LogicalStreamName, StreamTransport]
    fixed_scope_file_count: PositiveInt
    scalable_file_count: PositiveInt
    active_file_count: PositiveInt
    streams: Mapping[StreamGroupName, StreamDefinitionV1]
    payload_generation: _PayloadGenerationV1
    queues: _QueueLimitsV1
    qualification: _QualificationLimitsV1

    @field_validator("schema_version", mode="before")
    @classmethod
    def validate_schema_version_type(cls, value: object) -> object:
        if type(value) is not int:
            raise ValueError("schema version must be the integer 1")
        return value

    @field_validator(
        "exchanges",
        "markets",
        "derivative_logical_streams",
        mode="after",
    )
    @classmethod
    def validate_unique_scope_names(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            raise ValueError("ordered workload scope names must be unique")
        return value

    @field_validator("streams", mode="before")
    @classmethod
    def validate_stream_shape(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        if any(type(name) is not str for name in value):
            raise ValueError("stream group names must be strings")
        names = tuple(cast(str, name) for name in value)
        if len(names) != len(_STREAM_GROUPS) or set(names) != set(_STREAM_GROUPS):
            raise ValueError("streams must contain exactly the version-one groups")
        return {
            name: _STREAM_MODELS[name].model_validate(value[name]) for name in names
        }

    @field_validator("stream_transports", mode="after")
    @classmethod
    def freeze_stream_transports(
        cls,
        value: Mapping[LogicalStreamName, StreamTransport],
    ) -> Mapping[LogicalStreamName, StreamTransport]:
        return MappingProxyType(dict(value))

    @field_validator("streams", mode="after")
    @classmethod
    def freeze_streams(
        cls,
        value: Mapping[StreamGroupName, StreamDefinitionV1],
    ) -> Mapping[StreamGroupName, StreamDefinitionV1]:
        return MappingProxyType(dict(value))

    @field_serializer("stream_transports")
    def serialize_stream_transports(
        self,
        value: Mapping[LogicalStreamName, StreamTransport],
    ) -> dict[LogicalStreamName, StreamTransport]:
        return dict(value)

    @field_serializer("streams")
    def serialize_streams(
        self,
        value: Mapping[StreamGroupName, StreamDefinitionV1],
    ) -> dict[StreamGroupName, StreamDefinitionV1]:
        return dict(value)

    @model_validator(mode="after")
    def validate_scope_and_cardinalities(self) -> Self:
        if self.exchanges != _CANONICAL_EXCHANGES:
            raise ValueError("exchanges must use the canonical version-one order")
        if self.markets != _CANONICAL_MARKETS:
            raise ValueError("markets must use the canonical version-one order")
        if self.derivative_logical_streams != _CANONICAL_DERIVATIVE_STREAMS:
            raise ValueError(
                "derivative logical streams must use the canonical version-one order"
            )

        expected_transports: dict[str, str] = {
            "trade": "websocket",
            "book_live": "websocket",
            "ticker": "websocket",
            "bbo": "websocket",
            "funding": "websocket",
            "open_interest": "websocket",
            "candle_1m": "websocket",
            "book_deep_snapshot": "rest",
            "_control": "internal",
        }
        if self.stream_transports != expected_transports:
            raise ValueError(
                "stream transports must match the version-one transport profile"
            )

        ordinary_instance_count = (
            len(self.exchanges) * len(self.markets) * self.symbols_per_market
        )
        ordinary_file_count = 0
        for name in _ORDINARY_STREAMS:
            stream = self.streams[cast(StreamGroupName, name)]
            if not isinstance(stream, _OrdinaryStreamV1):
                raise TypeError(f"{name} must use an ordinary stream definition")
            if stream.instances != ordinary_instance_count:
                raise ValueError(
                    f"{name} instances must equal exchanges * markets * symbols"
                )
            ordinary_file_count += stream.instances

        derivative = self.streams["derivative"]
        if not isinstance(derivative, _DerivativeStreamV1):
            raise TypeError("derivative must use a derivative stream definition")
        if tuple(derivative.markets) != ("perpetual",):
            raise ValueError("derivative markets must be exactly perpetual")
        expected_derivative_instruments = (
            len(self.exchanges) * len(derivative.markets) * self.symbols_per_market
        )
        if derivative.instrument_instances != expected_derivative_instruments:
            raise ValueError(
                "derivative instrument instances must match the declared scope"
            )
        if (
            derivative.instrument_instances * derivative.logical_streams_per_instrument
            != derivative.file_instances
        ):
            raise ValueError(
                "derivative instrument and logical-stream product must equal files"
            )
        if derivative.logical_streams_per_instrument != len(
            self.derivative_logical_streams
        ):
            raise ValueError(
                "derivative logical-stream count must match the declared names"
            )

        control = self.streams["control"]
        if not isinstance(control, _ControlStreamV1):
            raise TypeError("control must use a control stream definition")
        if control.instances != len(self.exchanges):
            raise ValueError("control instances must equal the exchange count")

        expected_fixed = control.instances
        if self.fixed_scope_file_count != expected_fixed:
            raise ValueError("fixed file count does not match control identities")
        expected_scalable = ordinary_file_count + derivative.file_instances
        if self.scalable_file_count != expected_scalable:
            raise ValueError("scalable file count does not match stream identities")
        if self.active_file_count != expected_fixed + expected_scalable:
            raise ValueError("active file count must equal fixed plus scalable files")
        return self


@dataclass(frozen=True, slots=True)
class LoadedWorkload:
    workload: GateWorkloadV1
    source_bytes: bytes
    sha256: str


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
                raise ValueError(f"{path}: YAML merge keys are not supported")
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
        raise ValueError(f"{path}: YAML anchors and aliases are not supported")
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
            raise ValueError(f"{path}: all YAML mapping keys must be strings")
        result[key] = _plain_value(item, path=path)
    return result


def _plain_value(value: object, *, path: Path) -> Any:
    if isinstance(value, Mapping):
        return _plain_mapping(value, path=path)
    if isinstance(value, list):
        return [_plain_value(item, path=path) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"{path}: floating-point YAML scalars must be finite")
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise ValueError(f"{path}: unsupported YAML scalar type: {type(value).__name__}")


def _parse_yaml_mapping(source_bytes: bytes, *, path: Path) -> dict[str, Any]:
    try:
        text = source_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: workload must be valid UTF-8") from error

    try:
        documents = list(_yaml().compose_all(text))
    except YAMLError as error:
        raise ValueError(f"{path}: {_yaml_error_detail(error)}") from error
    if len(documents) != 1:
        raise ValueError(f"{path}: workload must contain a single document")
    document = documents[0]
    if document is None or not isinstance(document, MappingNode):
        raise ValueError(f"{path}: workload root must be a mapping")
    _reject_merge_keys(document, path=path, seen=set())
    _reject_anchors(document, path=path, seen=set())

    try:
        loaded = _yaml().load(text)
    except YAMLError as error:
        raise ValueError(f"{path}: {_yaml_error_detail(error)}") from error
    if not isinstance(loaded, Mapping):
        raise TypeError(f"{path}: workload root must be a mapping")
    return _plain_mapping(loaded, path=path)


def _read_source_bytes(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise ValueError(f"{path}: workload must not be a symbolic link") from error
        raise ValueError(f"{path}: workload is not a readable regular file") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"{path}: workload must be a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        return b"".join(chunks)
    except OSError as error:
        raise ValueError(f"{path}: workload is not a readable regular file") from error
    finally:
        os.close(descriptor)


def load_workload(path: Path) -> LoadedWorkload:
    source_path = Path(path)
    source_bytes = _read_source_bytes(source_path)
    source_sha256 = sha256(source_bytes).hexdigest()
    workload = GateWorkloadV1.model_validate(
        _parse_yaml_mapping(source_bytes, path=source_path)
    )
    return LoadedWorkload(
        workload=workload,
        source_bytes=source_bytes,
        sha256=source_sha256,
    )


__all__ = [
    "RESEARCH_DEFAULT_V1_SHA256",
    "GateWorkloadV1",
    "LoadedWorkload",
    "load_workload",
]
