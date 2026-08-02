from __future__ import annotations

import heapq
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from decimal import Decimal
from functools import cached_property
from hashlib import sha256, shake_256
from typing import Annotated, Any, Literal, Self, cast

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    model_validator,
)

from crypto_collector.benchmarks.workload import LoadedWorkload
from crypto_collector.domain.envelope import (
    NativeEventDraft,
    RestMetadata,
    SourceContext,
)
from crypto_collector.domain.json_codec import JsonPayload, decode_json, encode_json
from crypto_collector.domain.types import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    Transport,
)

EVENT_ALGORITHM_V1: Literal["gate-event-v1"] = "gate-event-v1"
ONE_SECOND_NS = 1_000_000_000
MAX_LANE_OR_SYMBOL = 9_999
_PADDING_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
_PADDING_TRANSLATION = bytes(
    ord(_PADDING_ALPHABET[value & 0x3F]) for value in range(256)
)
_CONTROL_KIND = "writer_gate_control"
_CANONICAL_EXCHANGES = (
    Exchange.BINANCE,
    Exchange.OKX,
    Exchange.BYBIT,
    Exchange.BITGET,
    Exchange.KRAKEN,
)
_CANONICAL_MARKETS = (Market.SPOT, Market.PERPETUAL)
_STREAM_GROUPS = (
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "derivative",
    "candle_1m",
    "book_deep_snapshot",
    "control",
)

NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
StreamGroup = Literal[
    "trade",
    "book_live",
    "ticker",
    "bbo",
    "derivative",
    "candle_1m",
    "book_deep_snapshot",
    "control",
]
LogicalStream = Literal[
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


def _schema_version_one(value: object) -> Literal[1]:
    if type(value) is not int or value != 1:
        raise ValueError("schema version must be the integer one")
    return 1


SchemaVersion1 = Annotated[Literal[1], BeforeValidator(_schema_version_one)]


def _validate_identity_fields(
    *,
    identity_algorithm: str,
    stream_group: str,
    logical_stream: str,
    exchange: Exchange,
    market: Market | None,
    lane_index: int | None,
    symbol_index: int | None,
    instrument_key: str | None,
    canonical_identity: str,
) -> None:
    if stream_group == "control":
        if logical_stream != "_control":
            raise ValueError("control group must use the _control logical stream")
    elif stream_group == "derivative":
        if logical_stream not in {"funding", "open_interest"}:
            raise ValueError("derivative group has an invalid logical stream")
    elif logical_stream != stream_group:
        raise ValueError("ordinary group and logical stream must match")

    if logical_stream == "_control":
        if any(
            value is not None
            for value in (market, lane_index, symbol_index, instrument_key)
        ):
            raise ValueError("control identity must have no market or instrument")
        expected_identity = f"{identity_algorithm}:{exchange.value}:-:-:_control"
    else:
        if (
            market is None
            or lane_index is None
            or symbol_index is None
            or instrument_key is None
        ):
            raise ValueError("scalable identity requires market and instrument fields")
        if lane_index > MAX_LANE_OR_SYMBOL or symbol_index > MAX_LANE_OR_SYMBOL:
            raise ValueError("identity lane and symbol must fit four digits")
        expected_instrument = (
            f"GATE-{exchange.value.upper()}-{market.value.upper()}-"
            f"L{lane_index:04d}-S{symbol_index:04d}"
        )
        if instrument_key != expected_instrument:
            raise ValueError("instrument key does not match canonical identity fields")
        expected_identity = (
            f"{identity_algorithm}:{exchange.value}:{market.value}:"
            f"{expected_instrument}:{logical_stream}"
        )
    if canonical_identity != expected_identity:
        raise ValueError("canonical identity does not match its component fields")


class _FrozenStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class WorkloadPlanHeaderV1(_FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["workload_plan_header_v1"] = "workload_plan_header_v1"
    workload_sha256: Sha256
    workload_name: NonEmptyString
    generation_seed: NonNegativeInt
    identity_algorithm: Literal["gate-identity-v1"]
    event_algorithm: Literal["gate-event-v1"]
    payload_algorithm: Literal["gate-payload-v1"]
    schedule_algorithm: Literal["gate-schedule-v2-full-second-burst"]
    multiplier: PositiveInt
    duration_ns: PositiveInt
    duration_seconds: PositiveInt
    declared_file_identity_count: PositiveInt
    expected_touched_file_identity_count: PositiveInt
    expected_record_count: PositiveInt

    def canonical_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="json")) + b"\n"


class PlannedIdentityV1(_FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    stream_group: StreamGroup
    logical_stream: LogicalStream
    exchange: Exchange
    market: Market | None
    lane_index: NonNegativeInt | None
    symbol_index: NonNegativeInt | None
    instrument_key: NonEmptyString | None
    canonical_identity: NonEmptyString
    identity_index: NonNegativeInt
    allocated_event_count: NonNegativeInt

    @model_validator(mode="after")
    def validate_scope(self) -> Self:
        _validate_identity_fields(
            identity_algorithm="gate-identity-v1",
            stream_group=self.stream_group,
            logical_stream=self.logical_stream,
            exchange=self.exchange,
            market=self.market,
            lane_index=self.lane_index,
            symbol_index=self.symbol_index,
            instrument_key=self.instrument_key,
            canonical_identity=self.canonical_identity,
        )
        return self


class StreamPlanV1(_FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["workload_stream_plan_v1"] = "workload_stream_plan_v1"
    stream_group: StreamGroup
    logical_streams: tuple[LogicalStream, ...]
    transports: tuple[Transport, ...]
    exchanges: tuple[Exchange, ...]
    markets: tuple[Market, ...]
    symbols_per_market: PositiveInt
    generation_seed: NonNegativeInt
    identity_algorithm: Literal["gate-identity-v1"]
    event_algorithm: Literal["gate-event-v1"]
    payload_algorithm: Literal["gate-payload-v1"]
    schedule_algorithm: Literal["gate-schedule-v2-full-second-burst"]
    multiplier: PositiveInt
    duration_ns: PositiveInt
    base_instance_count: PositiveInt
    identity_count: PositiveInt
    mean_records_per_second: Decimal
    burst_records_in_1s: PositiveInt
    payload_p50_bytes: PositiveInt
    payload_p95_bytes: PositiveInt
    payload_max_bytes: PositiveInt
    decimal_string_fraction: Decimal
    repeated_key_fraction: Decimal
    incompressible_fraction: Decimal
    expected_record_count: PositiveInt
    expected_touched_file_identity_count: PositiveInt
    required_burst_count: PositiveInt
    scheduled_burst_count: PositiveInt
    burst_second: NonNegativeInt
    burst_start_ns: NonNegativeInt

    @model_validator(mode="after")
    def validate_contract(self) -> Self:
        if len(self.logical_streams) != len(self.transports):
            raise ValueError("logical streams and transports must be paired")
        if len(set(self.logical_streams)) != len(self.logical_streams):
            raise ValueError("logical streams must be unique")
        if self.duration_ns < 10 * ONE_SECOND_NS or self.duration_ns % ONE_SECOND_NS:
            raise ValueError(
                "stream duration must be integral and at least ten seconds"
            )
        if self.symbols_per_market - 1 > MAX_LANE_OR_SYMBOL:
            raise ValueError("stream symbol count exceeds four-digit identity grammar")
        if self.multiplier - 1 > MAX_LANE_OR_SYMBOL:
            raise ValueError("stream multiplier exceeds four-digit identity grammar")
        if (
            len(set(self.exchanges)) != len(self.exchanges)
            or tuple(sorted(self.exchanges, key=_CANONICAL_EXCHANGES.index))
            != self.exchanges
        ):
            raise ValueError("stream exchanges must use canonical relative order")

        expected_logical: tuple[str, ...]
        expected_transports: tuple[Transport, ...]
        if self.stream_group == "control":
            expected_logical = ("_control",)
            expected_transports = (Transport.INTERNAL,)
            expected_base = len(self.exchanges)
            expected_identity_count = expected_base
            if self.markets:
                raise ValueError("control stream must not declare markets")
        elif self.stream_group == "derivative":
            expected_logical = ("funding", "open_interest")
            expected_transports = (Transport.WEBSOCKET, Transport.WEBSOCKET)
            if self.markets != (Market.PERPETUAL,):
                raise ValueError("derivative stream must use perpetual market")
            expected_base = (
                len(self.exchanges)
                * len(self.markets)
                * self.symbols_per_market
                * len(expected_logical)
            )
            expected_identity_count = expected_base * self.multiplier
        else:
            expected_logical = (self.stream_group,)
            expected_transports = (
                Transport.REST
                if self.stream_group == "book_deep_snapshot"
                else Transport.WEBSOCKET,
            )
            if (
                not self.markets
                or len(set(self.markets)) != len(self.markets)
                or tuple(sorted(self.markets, key=_CANONICAL_MARKETS.index))
                != self.markets
            ):
                raise ValueError("ordinary markets must use canonical relative order")
            expected_base = (
                len(self.exchanges) * len(self.markets) * self.symbols_per_market
            )
            expected_identity_count = expected_base * self.multiplier
        if self.logical_streams != expected_logical:
            raise ValueError("logical streams do not match the stream group")
        if self.transports != expected_transports:
            raise ValueError("transports do not match the logical streams")
        if self.base_instance_count != expected_base:
            raise ValueError("base instance count does not match stream scope")
        if self.identity_count != expected_identity_count:
            raise ValueError("identity count does not match stream scope")
        expected_records = _ceil_records(
            base_instance_count=self.base_instance_count,
            mean_records_per_second=self.mean_records_per_second,
            multiplier=self.multiplier,
            duration_ns=self.duration_ns,
        )
        if self.expected_record_count != expected_records:
            raise ValueError("expected record count does not match stream inputs")
        if self.expected_touched_file_identity_count != min(
            self.expected_record_count, self.identity_count
        ):
            raise ValueError("touched identity count does not match allocation")
        if self.required_burst_count != (
            self.base_instance_count * self.burst_records_in_1s * self.multiplier
        ):
            raise ValueError("required burst count does not match workload inputs")
        if self.scheduled_burst_count != min(
            self.expected_record_count, self.required_burst_count
        ):
            raise ValueError("scheduled burst count does not match capped burst")
        if self.burst_start_ns != self.burst_second * ONE_SECOND_NS:
            raise ValueError("burst start does not match burst second")
        expected_burst_second = _burst_second(
            seed=self.generation_seed,
            stream_group=self.stream_group,
            duration_seconds=self.duration_ns // ONE_SECOND_NS,
        )
        if self.burst_second != expected_burst_second:
            raise ValueError("burst second does not match the schedule algorithm")
        if self.burst_second >= self.duration_ns // ONE_SECOND_NS - 1:
            raise ValueError("burst second must precede the drain second")
        if not (
            Decimal(0) < self.decimal_string_fraction <= Decimal(1)
            and Decimal(0) < self.repeated_key_fraction <= Decimal(1)
            and Decimal(0) < self.incompressible_fraction <= Decimal(1)
        ):
            raise ValueError("payload fractions must be in the interval (0, 1]")
        if not (
            self.payload_p50_bytes <= self.payload_p95_bytes <= self.payload_max_bytes
        ):
            raise ValueError("payload sizes must be ordered p50 <= p95 <= max")
        if (
            self.duration_ns >= 600 * ONE_SECOND_NS
            and self.expected_record_count < self.required_burst_count
        ):
            raise ValueError("qualification stream underdrives its required burst")
        return self

    def iter_identities(self) -> Iterator[PlannedIdentityV1]:
        yield from _iter_identities(self)

    @cached_property
    def expected_payload_byte_count(self) -> int:
        return sum(
            _payload_target_bytes(event_id, self)
            for event_id, _ in _iter_event_ids_and_ordinals(self)
        )

    def canonical_bytes(self) -> bytes:
        values = self.model_dump(mode="json")
        values["expected_payload_byte_count"] = self.expected_payload_byte_count
        return encode_json(values) + b"\n"


class PlannedEventV1(_FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    record_type: Literal["planned_event_v1"] = "planned_event_v1"
    identity_algorithm: Literal["gate-identity-v1"]
    event_algorithm: Literal["gate-event-v1"]
    payload_algorithm: Literal["gate-payload-v1"]
    schedule_algorithm: Literal["gate-schedule-v2-full-second-burst"]
    planned_event_id: Sha256
    stream_group: StreamGroup
    logical_stream: LogicalStream
    exchange: Exchange
    market: Market | None
    lane_index: NonNegativeInt | None
    symbol_index: NonNegativeInt | None
    instrument_key: NonEmptyString | None
    canonical_identity: NonEmptyString
    identity_index: NonNegativeInt
    local_sequence: NonNegativeInt
    transport: Transport
    due_offset_ns: NonNegativeInt
    deadline_offset_ns: PositiveInt
    payload_bytes: PositiveInt
    payload_sha256: Sha256
    payload_canonical_bytes: bytes = Field(exclude=True, repr=False)

    @model_validator(mode="after")
    def validate_event(self) -> Self:
        _validate_identity_fields(
            identity_algorithm=self.identity_algorithm,
            stream_group=self.stream_group,
            logical_stream=self.logical_stream,
            exchange=self.exchange,
            market=self.market,
            lane_index=self.lane_index,
            symbol_index=self.symbol_index,
            instrument_key=self.instrument_key,
            canonical_identity=self.canonical_identity,
        )
        expected_transport = (
            Transport.INTERNAL
            if self.logical_stream == "_control"
            else (
                Transport.REST
                if self.logical_stream == "book_deep_snapshot"
                else Transport.WEBSOCKET
            )
        )
        if self.transport is not expected_transport:
            raise ValueError("event transport does not match its logical stream")
        if self.deadline_offset_ns != self.due_offset_ns + ONE_SECOND_NS:
            raise ValueError("event deadline must be exactly one second after due time")
        if len(self.payload_canonical_bytes) != self.payload_bytes:
            raise ValueError("payload byte count does not match canonical payload")
        if sha256(self.payload_canonical_bytes).hexdigest() != self.payload_sha256:
            raise ValueError("payload SHA does not match canonical payload")
        try:
            payload = decode_json(self.payload_canonical_bytes)
        except (TypeError, ValueError) as error:
            raise ValueError("payload must be canonical JSON") from error
        if (
            not isinstance(payload, dict)
            or encode_json(payload) != self.payload_canonical_bytes
        ):
            raise ValueError("payload must use canonical JSON bytes")
        expected_prefix = (
            ("algorithm", self.payload_algorithm),
            ("event_id", self.planned_event_id),
            ("stream", self.logical_stream),
            ("identity", self.canonical_identity),
            ("local_sequence", self.local_sequence),
        )
        payload_items = tuple(payload.items())
        if payload_items[:5] != expected_prefix:
            raise ValueError("payload identity prefix does not match the event")
        if (
            not payload_items
            or payload_items[-1][0] != "padding"
            or not isinstance(payload_items[-1][1], str)
        ):
            raise ValueError("payload must end with string padding")
        if self.logical_stream == "_control":
            if payload_items[-3] != ("kind", _CONTROL_KIND):
                raise ValueError("control payload has invalid control kind")
            if payload_items[-2] != (
                "affected_markets",
                ["spot", "perpetual"],
            ):
                raise ValueError("control payload has invalid affected markets")
            value_items = payload_items[5:-3]
        else:
            value_items = payload_items[5:-1]
        if len(value_items) != 1 or not (
            value_items[0][0] == "value"
            or value_items[0][0] in {f"value_{index:02d}" for index in range(16)}
        ):
            raise ValueError("payload must contain one canonical value key")
        return self

    @property
    def payload(self) -> dict[str, JsonPayload]:
        decoded = decode_json(self.payload_canonical_bytes)
        if not isinstance(decoded, dict):
            raise TypeError("planned payload must decode to an object")
        return cast(dict[str, JsonPayload], decoded)

    def canonical_bytes(self) -> bytes:
        return encode_json(self.model_dump(mode="json")) + b"\n"


class WorkloadPlanV1(_FrozenStrictModel):
    schema_version: SchemaVersion1 = 1
    workload_sha256: Sha256
    workload_name: NonEmptyString
    generation_seed: NonNegativeInt
    identity_algorithm: Literal["gate-identity-v1"]
    event_algorithm: Literal["gate-event-v1"]
    payload_algorithm: Literal["gate-payload-v1"]
    schedule_algorithm: Literal["gate-schedule-v2-full-second-burst"]
    multiplier: PositiveInt
    duration_ns: PositiveInt
    duration_seconds: PositiveInt
    declared_file_identity_count: PositiveInt
    expected_touched_file_identity_count: PositiveInt
    expected_record_count: PositiveInt
    streams: tuple[StreamPlanV1, ...]

    @model_validator(mode="after")
    def validate_totals(self) -> Self:
        if self.duration_seconds * ONE_SECOND_NS != self.duration_ns:
            raise ValueError("plan duration seconds and nanoseconds disagree")
        if tuple(summary.stream_group for summary in self.streams) != _STREAM_GROUPS:
            raise ValueError("stream plans must use declared version-one order")
        if self.expected_record_count != sum(
            summary.expected_record_count for summary in self.streams
        ):
            raise ValueError("plan record count does not match stream summaries")
        if self.expected_touched_file_identity_count != sum(
            summary.expected_touched_file_identity_count for summary in self.streams
        ):
            raise ValueError("plan touched count does not match stream summaries")
        if self.declared_file_identity_count != sum(
            summary.identity_count for summary in self.streams
        ):
            raise ValueError("plan declared count does not match stream summaries")
        for summary in self.streams:
            if (
                summary.generation_seed != self.generation_seed
                or summary.identity_algorithm != self.identity_algorithm
                or summary.event_algorithm != self.event_algorithm
                or summary.payload_algorithm != self.payload_algorithm
                or summary.schedule_algorithm != self.schedule_algorithm
                or summary.multiplier != self.multiplier
                or summary.duration_ns != self.duration_ns
            ):
                raise ValueError("stream summary inputs disagree with plan header")
        return self

    def stream(self, stream_group: str) -> StreamPlanV1:
        if type(stream_group) is not str:
            raise TypeError("stream group must be a string")
        for summary in self.streams:
            if summary.stream_group == stream_group:
                return summary
        raise KeyError(stream_group)

    @cached_property
    def expected_payload_byte_count(self) -> int:
        return sum(summary.expected_payload_byte_count for summary in self.streams)

    @property
    def header(self) -> WorkloadPlanHeaderV1:
        return WorkloadPlanHeaderV1(
            workload_sha256=self.workload_sha256,
            workload_name=self.workload_name,
            generation_seed=self.generation_seed,
            identity_algorithm=self.identity_algorithm,
            event_algorithm=self.event_algorithm,
            payload_algorithm=self.payload_algorithm,
            schedule_algorithm=self.schedule_algorithm,
            multiplier=self.multiplier,
            duration_ns=self.duration_ns,
            duration_seconds=self.duration_seconds,
            declared_file_identity_count=self.declared_file_identity_count,
            expected_touched_file_identity_count=self.expected_touched_file_identity_count,
            expected_record_count=self.expected_record_count,
        )

    @cached_property
    def workload_plan_sha256(self) -> str:
        digest = sha256()
        digest.update(self.header.canonical_bytes())
        for summary in self.streams:
            digest.update(summary.canonical_bytes())
        for scheduled in _iter_plan_schedule(self):
            digest.update(_scheduled_event_canonical_bytes(scheduled))
        return digest.hexdigest()


def _exact_int(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    return value


def _stream_mapping(value: BaseModel) -> dict[str, Any]:
    return cast(dict[str, Any], value.model_dump(mode="python"))


def _stream_logical_names(stream_group: str, loaded: LoadedWorkload) -> tuple[str, ...]:
    if stream_group == "derivative":
        return tuple(loaded.workload.derivative_logical_streams)
    if stream_group == "control":
        return ("_control",)
    return (stream_group,)


def _stream_markets(
    stream_group: str, stream_data: Mapping[str, Any], loaded: LoadedWorkload
) -> tuple[str, ...]:
    if stream_group == "control":
        return ()
    if stream_group == "derivative":
        return cast(tuple[str, ...], stream_data["markets"])
    return tuple(loaded.workload.markets)


def _ceil_records(
    *,
    base_instance_count: int,
    mean_records_per_second: Decimal,
    multiplier: int,
    duration_ns: int,
) -> int:
    rate_numerator, rate_denominator = mean_records_per_second.as_integer_ratio()
    numerator = base_instance_count * multiplier * duration_ns * rate_numerator
    denominator = ONE_SECOND_NS * rate_denominator
    return -(-numerator // denominator)


def _burst_second(*, seed: int, stream_group: str, duration_seconds: int) -> int:
    digest = sha256(f"{seed}:{stream_group}".encode("ascii")).digest()
    return int.from_bytes(digest[:8], "big", signed=False) % (duration_seconds - 1)


def build_workload_plan(
    loaded: LoadedWorkload,
    *,
    multiplier: int,
    duration_ns: int,
) -> WorkloadPlanV1:
    if type(loaded) is not LoadedWorkload:
        raise TypeError("loaded must be LoadedWorkload")
    if sha256(loaded.source_bytes).hexdigest() != loaded.sha256:
        raise ValueError("loaded workload source SHA does not match its bytes")
    if type(multiplier) is not int:
        raise TypeError("multiplier must be an integer")
    if multiplier < 1:
        raise ValueError("multiplier must be at least one")
    if multiplier - 1 > MAX_LANE_OR_SYMBOL:
        raise ValueError("multiplier exceeds the four-digit identity lane limit")
    if type(duration_ns) is not int:
        raise TypeError("duration must be an integer number of nanoseconds")
    if duration_ns < 10 * ONE_SECOND_NS:
        raise ValueError("duration must be at least ten seconds")
    if duration_ns % ONE_SECOND_NS:
        raise ValueError("duration must be an integral number of seconds")
    if loaded.workload.symbols_per_market - 1 > MAX_LANE_OR_SYMBOL:
        raise ValueError("symbol count exceeds the four-digit identity symbol limit")

    duration_seconds = duration_ns // ONE_SECOND_NS
    workload = loaded.workload
    payload_data = cast(
        dict[str, Decimal], workload.payload_generation.model_dump(mode="python")
    )
    summaries: list[StreamPlanV1] = []
    for stream_group in _STREAM_GROUPS:
        stream_model = workload.streams[cast(Any, stream_group)]
        stream_data = _stream_mapping(stream_model)
        base_instance_count = _exact_int(
            stream_data.get("file_instances", stream_data.get("instances")),
            field_name=f"{stream_group}.base_instance_count",
        )
        mean_rate = cast(Decimal, stream_data["mean_records_per_second"])
        expected_count = _ceil_records(
            base_instance_count=base_instance_count,
            mean_records_per_second=mean_rate,
            multiplier=multiplier,
            duration_ns=duration_ns,
        )
        identity_count = (
            base_instance_count
            if stream_group == "control"
            else base_instance_count * multiplier
        )
        burst_records = _exact_int(
            stream_data["burst_records_in_1s"],
            field_name=f"{stream_group}.burst_records_in_1s",
        )
        required_burst = base_instance_count * burst_records * multiplier
        if duration_seconds >= 600 and expected_count < required_burst:
            raise ValueError(
                f"qualification duration underdrives {stream_group} required burst"
            )
        logical_names = _stream_logical_names(stream_group, loaded)
        transports = tuple(
            Transport(workload.stream_transports[cast(Any, name)])
            for name in logical_names
        )
        burst_second = _burst_second(
            seed=workload.generation_seed,
            stream_group=stream_group,
            duration_seconds=duration_seconds,
        )
        summaries.append(
            StreamPlanV1(
                stream_group=cast(StreamGroup, stream_group),
                logical_streams=cast(tuple[LogicalStream, ...], logical_names),
                transports=transports,
                exchanges=tuple(Exchange(value) for value in workload.exchanges),
                markets=tuple(
                    Market(value)
                    for value in _stream_markets(stream_group, stream_data, loaded)
                ),
                symbols_per_market=workload.symbols_per_market,
                generation_seed=workload.generation_seed,
                identity_algorithm=workload.identity_algorithm,
                event_algorithm=EVENT_ALGORITHM_V1,
                payload_algorithm=workload.payload_algorithm,
                schedule_algorithm=workload.schedule_algorithm,
                multiplier=multiplier,
                duration_ns=duration_ns,
                base_instance_count=base_instance_count,
                identity_count=identity_count,
                mean_records_per_second=mean_rate,
                burst_records_in_1s=burst_records,
                payload_p50_bytes=_exact_int(
                    stream_data["payload_p50_bytes"],
                    field_name=f"{stream_group}.payload_p50_bytes",
                ),
                payload_p95_bytes=_exact_int(
                    stream_data["payload_p95_bytes"],
                    field_name=f"{stream_group}.payload_p95_bytes",
                ),
                payload_max_bytes=_exact_int(
                    stream_data["payload_max_bytes"],
                    field_name=f"{stream_group}.payload_max_bytes",
                ),
                decimal_string_fraction=payload_data["decimal_string_fraction"],
                repeated_key_fraction=payload_data["repeated_key_fraction"],
                incompressible_fraction=payload_data["incompressible_fraction"],
                expected_record_count=expected_count,
                expected_touched_file_identity_count=min(
                    expected_count, identity_count
                ),
                required_burst_count=required_burst,
                scheduled_burst_count=min(expected_count, required_burst),
                burst_second=burst_second,
                burst_start_ns=burst_second * ONE_SECOND_NS,
            )
        )

    declared_count = workload.fixed_scope_file_count + (
        multiplier * workload.scalable_file_count
    )
    return WorkloadPlanV1(
        workload_sha256=loaded.sha256,
        workload_name=workload.name,
        generation_seed=workload.generation_seed,
        identity_algorithm=workload.identity_algorithm,
        event_algorithm=EVENT_ALGORITHM_V1,
        payload_algorithm=workload.payload_algorithm,
        schedule_algorithm=workload.schedule_algorithm,
        multiplier=multiplier,
        duration_ns=duration_ns,
        duration_seconds=duration_seconds,
        declared_file_identity_count=declared_count,
        expected_touched_file_identity_count=sum(
            summary.expected_touched_file_identity_count for summary in summaries
        ),
        expected_record_count=sum(
            summary.expected_record_count for summary in summaries
        ),
        streams=tuple(summaries),
    )


def _allocated_count(summary: StreamPlanV1, identity_index: int) -> int:
    quotient, remainder = divmod(summary.expected_record_count, summary.identity_count)
    return quotient + (1 if identity_index < remainder else 0)


@dataclass(frozen=True, slots=True)
class _IdentityFacts:
    stream_group: StreamGroup
    logical_stream: LogicalStream
    exchange: Exchange
    market: Market | None
    lane_index: int | None
    symbol_index: int | None
    instrument_key: str | None
    canonical_identity: str
    identity_index: int
    allocated_event_count: int


def _identity_facts_at(summary: StreamPlanV1, identity_index: int) -> _IdentityFacts:
    if not 0 <= identity_index < summary.identity_count:
        raise IndexError(identity_index)
    if summary.stream_group == "control":
        exchange = summary.exchanges[identity_index]
        return _IdentityFacts(
            stream_group=summary.stream_group,
            logical_stream="_control",
            exchange=exchange,
            market=None,
            lane_index=None,
            symbol_index=None,
            instrument_key=None,
            canonical_identity=(
                f"{summary.identity_algorithm}:{exchange.value}:-:-:_control"
            ),
            identity_index=identity_index,
            allocated_event_count=_allocated_count(summary, identity_index),
        )

    logical_count = len(summary.logical_streams)
    symbols = summary.symbols_per_market
    per_lane = symbols * logical_count
    per_market = summary.multiplier * per_lane
    per_exchange = len(summary.markets) * per_market
    exchange_index, remainder = divmod(identity_index, per_exchange)
    market_index, remainder = divmod(remainder, per_market)
    lane_index, remainder = divmod(remainder, per_lane)
    symbol_index, logical_index = divmod(remainder, logical_count)
    exchange = summary.exchanges[exchange_index]
    market = summary.markets[market_index]
    logical_stream = summary.logical_streams[logical_index]
    instrument_key = (
        f"GATE-{exchange.value.upper()}-{market.value.upper()}-"
        f"L{lane_index:04d}-S{symbol_index:04d}"
    )
    return _IdentityFacts(
        stream_group=summary.stream_group,
        logical_stream=logical_stream,
        exchange=exchange,
        market=market,
        lane_index=lane_index,
        symbol_index=symbol_index,
        instrument_key=instrument_key,
        canonical_identity=(
            f"{summary.identity_algorithm}:{exchange.value}:{market.value}:"
            f"{instrument_key}:{logical_stream}"
        ),
        identity_index=identity_index,
        allocated_event_count=_allocated_count(summary, identity_index),
    )


def _identity_at(summary: StreamPlanV1, identity_index: int) -> PlannedIdentityV1:
    facts = _identity_facts_at(summary, identity_index)
    return PlannedIdentityV1(
        stream_group=facts.stream_group,
        logical_stream=facts.logical_stream,
        exchange=facts.exchange,
        market=facts.market,
        lane_index=facts.lane_index,
        symbol_index=facts.symbol_index,
        instrument_key=facts.instrument_key,
        canonical_identity=facts.canonical_identity,
        identity_index=facts.identity_index,
        allocated_event_count=facts.allocated_event_count,
    )


def _iter_identities(summary: StreamPlanV1) -> Iterator[PlannedIdentityV1]:
    for identity_index in range(summary.identity_count):
        yield _identity_at(summary, identity_index)


def _ordinal_identity_facts_and_sequence(
    summary: StreamPlanV1,
    ordinal: int,
) -> tuple[_IdentityFacts, int]:
    if not 0 <= ordinal < summary.expected_record_count:
        raise IndexError(ordinal)
    quotient, remainder = divmod(summary.expected_record_count, summary.identity_count)
    longer_span = remainder * (quotient + 1)
    if ordinal < longer_span:
        identity_index, local_sequence = divmod(ordinal, quotient + 1)
    else:
        if quotient == 0:
            raise AssertionError("zero allocation cannot have a remainder ordinal")
        tail_ordinal = ordinal - longer_span
        tail_index, local_sequence = divmod(tail_ordinal, quotient)
        identity_index = remainder + tail_index
    return _identity_facts_at(summary, identity_index), local_sequence


def _planned_event_id(
    summary: StreamPlanV1,
    canonical_identity: str,
    local_sequence: int,
) -> str:
    record = (
        f"{summary.event_algorithm}:{summary.generation_seed}:{summary.stream_group}:"
        f"{canonical_identity}:{local_sequence}"
    )
    return sha256(record.encode("ascii")).hexdigest()


def _event_facts_at(
    summary: StreamPlanV1, ordinal: int
) -> tuple[str, _IdentityFacts, int]:
    identity, local_sequence = _ordinal_identity_facts_and_sequence(summary, ordinal)
    return (
        _planned_event_id(summary, identity.canonical_identity, local_sequence),
        identity,
        local_sequence,
    )


def _event_id_at(
    summary: StreamPlanV1, ordinal: int
) -> tuple[str, PlannedIdentityV1, int]:
    event_id, facts, local_sequence = _event_facts_at(summary, ordinal)
    return (
        event_id,
        _identity_at(summary, facts.identity_index),
        local_sequence,
    )


def _iter_event_ids_and_ordinals(summary: StreamPlanV1) -> Iterator[tuple[str, int]]:
    for ordinal in range(summary.expected_record_count):
        event_id, _, _ = _event_facts_at(summary, ordinal)
        yield event_id, ordinal


def _burst_quota_per_identity(summary: StreamPlanV1) -> int:
    multiplier = summary.multiplier if summary.stream_group == "control" else 1
    return summary.burst_records_in_1s * multiplier


def _identity_ordinal_start(summary: StreamPlanV1, identity_index: int) -> int:
    if not 0 <= identity_index <= summary.identity_count:
        raise IndexError(identity_index)
    quotient, remainder = divmod(summary.expected_record_count, summary.identity_count)
    return identity_index * quotient + min(identity_index, remainder)


def _exchange_identity_span(
    summary: StreamPlanV1, exchange: Exchange
) -> tuple[int, int]:
    exchange_index = summary.exchanges.index(exchange)
    per_exchange, remainder = divmod(summary.identity_count, len(summary.exchanges))
    if remainder:
        raise AssertionError("exchange identity spans must be equal and contiguous")
    identity_start = exchange_index * per_exchange
    return identity_start, identity_start + per_exchange


def _iter_burst_ordinals_for_identity_span(
    summary: StreamPlanV1,
    identity_start: int,
    identity_stop: int,
) -> Iterator[int]:
    ordinal_start = _identity_ordinal_start(summary, identity_start)
    quota = _burst_quota_per_identity(summary)
    for identity_index in range(identity_start, identity_stop):
        allocated_count = _allocated_count(summary, identity_index)
        selected_for_identity = min(allocated_count, quota)
        yield from range(ordinal_start, ordinal_start + selected_for_identity)
        ordinal_start += allocated_count


def _iter_burst_ordinals(summary: StreamPlanV1) -> Iterator[int]:
    selected_count = 0
    for ordinal in _iter_burst_ordinals_for_identity_span(
        summary, 0, summary.identity_count
    ):
        selected_count += 1
        yield ordinal
    if selected_count != summary.scheduled_burst_count:
        raise AssertionError("distributed burst count does not match stream plan")


def _smooth_count_before_identity(summary: StreamPlanV1, identity_index: int) -> int:
    if not 0 <= identity_index <= summary.identity_count:
        raise IndexError(identity_index)
    quotient, remainder = divmod(summary.expected_record_count, summary.identity_count)
    quota = _burst_quota_per_identity(summary)
    longer_identity_count = min(identity_index, remainder)
    shorter_identity_count = identity_index - longer_identity_count
    return longer_identity_count * max(
        quotient + 1 - quota, 0
    ) + shorter_identity_count * max(quotient - quota, 0)


def _iter_indexed_smooth_ordinals_for_identity_span(
    summary: StreamPlanV1,
    identity_start: int,
    identity_stop: int,
) -> Iterator[tuple[int, int]]:
    ordinal_start = _identity_ordinal_start(summary, identity_start)
    smooth_index = _smooth_count_before_identity(summary, identity_start)
    quota = _burst_quota_per_identity(summary)
    for identity_index in range(identity_start, identity_stop):
        allocated_count = _allocated_count(summary, identity_index)
        selected_for_identity = min(allocated_count, quota)
        for ordinal in range(
            ordinal_start + selected_for_identity,
            ordinal_start + allocated_count,
        ):
            yield smooth_index, ordinal
            smooth_index += 1
        ordinal_start += allocated_count


def _iter_smooth_ordinals(summary: StreamPlanV1) -> Iterator[int]:
    selected_count = 0
    for _, ordinal in _iter_indexed_smooth_ordinals_for_identity_span(
        summary, 0, summary.identity_count
    ):
        selected_count += 1
        yield ordinal
    expected_count = summary.expected_record_count - summary.scheduled_burst_count
    if selected_count != expected_count:
        raise AssertionError("smooth event count does not match stream plan")


def _selector_lane(event_id: str, selector_name: str) -> int:
    source = f"gate-payload-v1:{event_id}:{selector_name}".encode("ascii")
    return int.from_bytes(sha256(source).digest()[:8], "big", signed=False)


def _fraction_selected(event_id: str, selector_name: str, fraction: Decimal) -> bool:
    numerator, denominator = fraction.as_integer_ratio()
    threshold = numerator * (2**64) // denominator
    return _selector_lane(event_id, selector_name) < threshold


def _payload_target_bytes(event_id: str, summary: StreamPlanV1) -> int:
    percentile = _selector_lane(event_id, "size") % 100
    if percentile < 50:
        return summary.payload_p50_bytes
    if percentile < 95:
        return summary.payload_p95_bytes
    return summary.payload_max_bytes


def _payload_bytes(
    *,
    event_id: str,
    identity: _IdentityFacts,
    local_sequence: int,
    summary: StreamPlanV1,
) -> bytes:
    target_bytes = _payload_target_bytes(event_id, summary)
    decimal_layout = _fraction_selected(
        event_id, "decimal", summary.decimal_string_fraction
    )
    common_key = _fraction_selected(
        event_id, "common-key", summary.repeated_key_fraction
    )
    incompressible = _fraction_selected(
        event_id, "incompressible", summary.incompressible_fraction
    )
    whole = _selector_lane(event_id, "decimal-whole") % 100_000_000
    value: JsonPayload
    if decimal_layout:
        fraction = _selector_lane(event_id, "decimal-fraction") % 100_000_000
        value = f"{whole}.{fraction:08d}"
    else:
        value = whole
    value_key = (
        "value"
        if common_key
        else f"value_{_selector_lane(event_id, 'uncommon-key') % 16:02d}"
    )
    payload: dict[str, JsonPayload] = {
        "algorithm": summary.payload_algorithm,
        "event_id": event_id,
        "stream": identity.logical_stream,
        "identity": identity.canonical_identity,
        "local_sequence": local_sequence,
        value_key: value,
    }
    if identity.logical_stream == "_control":
        payload["kind"] = _CONTROL_KIND
        payload["affected_markets"] = ["spot", "perpetual"]
    payload["padding"] = ""
    base_bytes = encode_json(payload)
    padding_length = target_bytes - len(base_bytes)
    if padding_length < 0:
        raise ValueError(
            f"{summary.stream_group} payload target is below its canonical base size"
        )
    if incompressible:
        raw_padding = shake_256(f"gate-padding-v1:{event_id}".encode("ascii")).digest(
            padding_length
        )
        padding = raw_padding.translate(_PADDING_TRANSLATION)
    else:
        padding = b"A" * padding_length
    if not base_bytes.endswith(b'""}'):
        raise AssertionError("canonical payload padding suffix changed")
    encoded = base_bytes[:-2] + padding + b'"}'
    if len(encoded) != target_bytes:
        raise AssertionError("payload padding did not produce its exact target size")
    return encoded


@dataclass(frozen=True, slots=True)
class _ScheduledEvent:
    summary: StreamPlanV1
    ordinal: int
    due_offset_ns: int
    event_id: str


def _scheduled_event_values(
    scheduled: _ScheduledEvent,
) -> tuple[dict[str, Any], bytes]:
    summary = scheduled.summary
    ordinal = scheduled.ordinal
    computed_id, identity, local_sequence = _event_facts_at(summary, ordinal)
    if scheduled.event_id != computed_id:
        raise AssertionError("event ID changed between ordering and construction")
    payload = _payload_bytes(
        event_id=computed_id,
        identity=identity,
        local_sequence=local_sequence,
        summary=summary,
    )
    logical_index = summary.logical_streams.index(identity.logical_stream)
    values: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "planned_event_v1",
        "identity_algorithm": summary.identity_algorithm,
        "event_algorithm": summary.event_algorithm,
        "payload_algorithm": summary.payload_algorithm,
        "schedule_algorithm": summary.schedule_algorithm,
        "planned_event_id": computed_id,
        "stream_group": summary.stream_group,
        "logical_stream": identity.logical_stream,
        "exchange": identity.exchange,
        "market": identity.market,
        "lane_index": identity.lane_index,
        "symbol_index": identity.symbol_index,
        "instrument_key": identity.instrument_key,
        "canonical_identity": identity.canonical_identity,
        "identity_index": identity.identity_index,
        "local_sequence": local_sequence,
        "transport": summary.transports[logical_index],
        "due_offset_ns": scheduled.due_offset_ns,
        "deadline_offset_ns": scheduled.due_offset_ns + ONE_SECOND_NS,
        "payload_bytes": len(payload),
        "payload_sha256": sha256(payload).hexdigest(),
    }
    return values, payload


def _scheduled_event_canonical_bytes(scheduled: _ScheduledEvent) -> bytes:
    values, _ = _scheduled_event_values(scheduled)
    return encode_json(values) + b"\n"


def _build_event(scheduled: _ScheduledEvent) -> PlannedEventV1:
    values, payload = _scheduled_event_values(scheduled)
    values["payload_canonical_bytes"] = payload
    return PlannedEventV1.model_construct(**values)


def _iter_burst_schedule_for_identity_span(
    summary: StreamPlanV1,
    identity_start: int,
    identity_stop: int,
) -> Iterator[_ScheduledEvent]:
    burst_rows = [
        (_event_facts_at(summary, ordinal)[0], ordinal)
        for ordinal in _iter_burst_ordinals_for_identity_span(
            summary, identity_start, identity_stop
        )
    ]
    burst_rows.sort(key=lambda row: row[0])
    for event_id, ordinal in burst_rows:
        yield _ScheduledEvent(
            summary=summary,
            ordinal=ordinal,
            due_offset_ns=summary.burst_start_ns,
            event_id=event_id,
        )


def _iter_burst_schedule(summary: StreamPlanV1) -> Iterator[_ScheduledEvent]:
    yield from _iter_burst_schedule_for_identity_span(
        summary, 0, summary.identity_count
    )


def _iter_smooth_schedule_for_identity_span(
    summary: StreamPlanV1,
    identity_start: int,
    identity_stop: int,
) -> Iterator[_ScheduledEvent]:
    remaining_count = summary.expected_record_count - summary.scheduled_burst_count
    if remaining_count == 0:
        return
    schedulable_ns = summary.duration_ns - ONE_SECOND_NS
    outside_ns = schedulable_ns - ONE_SECOND_NS
    tie_group: list[tuple[str, int, int]] = []
    prior_due: int | None = None
    for index, ordinal in _iter_indexed_smooth_ordinals_for_identity_span(
        summary, identity_start, identity_stop
    ):
        compressed = index * outside_ns // remaining_count
        due_offset_ns = (
            compressed
            if compressed < summary.burst_start_ns
            else compressed + ONE_SECOND_NS
        )
        event_id, _, _ = _event_facts_at(summary, ordinal)
        if prior_due is not None and due_offset_ns != prior_due:
            tie_group.sort(key=lambda row: row[0])
            for grouped_id, grouped_ordinal, grouped_due in tie_group:
                yield _ScheduledEvent(
                    summary=summary,
                    ordinal=grouped_ordinal,
                    due_offset_ns=grouped_due,
                    event_id=grouped_id,
                )
            tie_group.clear()
        tie_group.append((event_id, ordinal, due_offset_ns))
        prior_due = due_offset_ns
    tie_group.sort(key=lambda row: row[0])
    for event_id, ordinal, due_offset_ns in tie_group:
        yield _ScheduledEvent(
            summary=summary,
            ordinal=ordinal,
            due_offset_ns=due_offset_ns,
            event_id=event_id,
        )


def _iter_smooth_schedule(summary: StreamPlanV1) -> Iterator[_ScheduledEvent]:
    yield from _iter_smooth_schedule_for_identity_span(
        summary, 0, summary.identity_count
    )


def _iter_stream_schedule_for_identity_span(
    summary: StreamPlanV1,
    identity_start: int,
    identity_stop: int,
) -> Iterator[_ScheduledEvent]:
    yield from heapq.merge(
        _iter_burst_schedule_for_identity_span(summary, identity_start, identity_stop),
        _iter_smooth_schedule_for_identity_span(summary, identity_start, identity_stop),
        key=lambda event: (event.due_offset_ns, event.event_id),
    )


def _iter_stream_schedule(summary: StreamPlanV1) -> Iterator[_ScheduledEvent]:
    yield from _iter_stream_schedule_for_identity_span(
        summary, 0, summary.identity_count
    )


def _iter_plan_schedule(plan: WorkloadPlanV1) -> Iterator[_ScheduledEvent]:
    yield from heapq.merge(
        *(_iter_stream_schedule(summary) for summary in plan.streams),
        key=lambda event: (event.due_offset_ns, event.event_id),
    )


def _iter_exchange_plan_schedule(
    plan: WorkloadPlanV1, exchange: Exchange
) -> Iterator[_ScheduledEvent]:
    schedules: list[Iterator[_ScheduledEvent]] = []
    for summary in plan.streams:
        identity_start, identity_stop = _exchange_identity_span(summary, exchange)
        schedules.append(
            _iter_stream_schedule_for_identity_span(
                summary, identity_start, identity_stop
            )
        )
    yield from heapq.merge(
        *schedules,
        key=lambda event: (event.due_offset_ns, event.event_id),
    )


def iter_plan_events(plan: WorkloadPlanV1) -> Iterator[PlannedEventV1]:
    if type(plan) is not WorkloadPlanV1:
        raise TypeError("plan must be WorkloadPlanV1")
    for scheduled in _iter_plan_schedule(plan):
        yield _build_event(scheduled)


def iter_exchange_plan_events(
    plan: WorkloadPlanV1, exchange: Exchange
) -> Iterator[PlannedEventV1]:
    if type(plan) is not WorkloadPlanV1:
        raise TypeError("plan must be WorkloadPlanV1")
    if type(exchange) is not Exchange:
        raise TypeError("exchange must be Exchange")
    if any(exchange not in summary.exchanges for summary in plan.streams):
        raise ValueError("exchange is absent from the plan")
    for scheduled in _iter_exchange_plan_schedule(plan, exchange):
        yield _build_event(scheduled)


def build_native_draft(
    event: PlannedEventV1,
    *,
    admission_started_utc_ns: int,
) -> tuple[NativeEventDraft, SourceContext, str]:
    """Build a production draft from an event emitted by ``iter_plan_events``.

    ``PlannedEventV1`` validates its standalone row structure. Algorithmic
    authenticity remains plan-bound and is established by exact oracle replay.
    """
    if type(event) is not PlannedEventV1:
        raise TypeError("event must be PlannedEventV1")
    if type(admission_started_utc_ns) is not int:
        raise TypeError("admission UTC anchor must be an integer")
    if admission_started_utc_ns < 0:
        raise ValueError("admission UTC anchor must be non-negative")

    is_control = event.logical_stream == "_control"
    event_time_ns = (
        None if is_control else admission_started_utc_ns + event.due_offset_ns
    )
    rest_metadata: RestMetadata | None = None
    if event.transport is Transport.INTERNAL:
        source = SourceContext.internal()
    elif event.transport is Transport.WEBSOCKET:
        if event.market is None:
            raise ValueError("WebSocket event requires a market")
        source = SourceContext(
            connection_id=(f"gate-ws-v1-{event.exchange.value}-{event.market.value}"),
            connection_generation=0,
            egress_id=f"gate-egress-v1-{event.exchange.value}",
        )
    else:
        if event.instrument_key is None or event_time_ns is None:
            raise ValueError("REST event requires instrument and event time")
        source = SourceContext(
            connection_id=None,
            connection_generation=None,
            egress_id=f"gate-egress-v1-{event.exchange.value}",
        )
        rest_metadata = RestMetadata(
            request_started_at_ns=event_time_ns,
            request_ended_at_ns=event_time_ns,
            method="GET",
            path="/gate/v1/book-deep-snapshot",
            params={"instrument": event.instrument_key},
            status=200,
            attempt=1,
            rate_limit_headers={},
            requested_interval_ns=None,
            effective_interval_ns=None,
        )

    integrity_mode: IntegrityMode | None = None
    coverage: CoverageMode | None = None
    if event.logical_stream == "book_live":
        integrity_mode = IntegrityMode.SEQUENCE_VERIFIED
        coverage = CoverageMode.COMPLETE
    elif event.logical_stream == "book_deep_snapshot":
        integrity_mode = IntegrityMode.SNAPSHOT_CHAIN
        coverage = CoverageMode.COMPLETE

    draft = NativeEventDraft(
        exchange=event.exchange,
        market=event.market,
        instrument_key=event.instrument_key,
        wire_symbol=event.instrument_key,
        logical_stream=event.logical_stream,
        native_channel=None if is_control else f"gate.v1.{event.logical_stream}",
        transport=event.transport,
        event_time_ns=event_time_ns,
        event_time_source=None if is_control else "gate_due_time",
        integrity_mode=integrity_mode,
        coverage=coverage,
        rest_metadata=rest_metadata,
        payload=event.payload,
    )
    draft.validate_source(source)
    return draft, source, event.logical_stream


__all__ = [
    "EVENT_ALGORITHM_V1",
    "PlannedEventV1",
    "PlannedIdentityV1",
    "StreamPlanV1",
    "WorkloadPlanHeaderV1",
    "WorkloadPlanV1",
    "build_native_draft",
    "build_workload_plan",
    "iter_exchange_plan_events",
    "iter_plan_events",
]
