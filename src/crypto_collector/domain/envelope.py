from __future__ import annotations

from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from crypto_collector.domain.json_codec import ValidatedJsonPayload
from crypto_collector.domain.types import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    Transport,
)

NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
NonNegativeInt = Annotated[int, Field(ge=0)]
PositiveInt = Annotated[int, Field(gt=0)]
ConfigSha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]

MARKET_SCOPED_STREAMS = frozenset({"instrument", "status", "insurance_fund"})
BOOK_STREAMS = frozenset({"book_deep_snapshot", "book_live", "book_live_bootstrap"})


class FrozenStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class RestMetadata(FrozenStrictModel):
    request_started_at_ns: NonNegativeInt
    request_ended_at_ns: NonNegativeInt
    method: NonEmptyString
    path: NonEmptyString
    params: dict[str, ValidatedJsonPayload]
    status: Annotated[int, Field(ge=0, le=599)]
    attempt: PositiveInt
    rate_limit_headers: dict[str, str]
    requested_interval_ns: PositiveInt | None = None
    effective_interval_ns: PositiveInt | None = None

    @model_validator(mode="after")
    def validate_request_times(self) -> Self:
        if self.request_ended_at_ns < self.request_started_at_ns:
            raise ValueError(
                "request_ended_at_ns must not precede request_started_at_ns"
            )
        return self


class SourceContext(FrozenStrictModel):
    connection_id: NonEmptyString | None
    connection_generation: NonNegativeInt | None
    egress_id: NonEmptyString | None

    @model_validator(mode="after")
    def validate_connection_pair(self) -> Self:
        if (self.connection_id is None) != (self.connection_generation is None):
            raise ValueError(
                "source context connection_id and connection_generation must be paired"
            )
        return self

    @classmethod
    def internal(cls) -> SourceContext:
        return cls(
            connection_id=None,
            connection_generation=None,
            egress_id=None,
        )

    def validate_for(self, *, transport: Transport, logical_stream: str) -> None:
        has_connection = self.connection_id is not None
        if transport is Transport.INTERNAL:
            if has_connection or self.egress_id is not None:
                raise ValueError("internal source context must be entirely null")
            return

        needs_connection = (
            transport is Transport.WEBSOCKET or logical_stream == "book_live_bootstrap"
        )
        if needs_connection:
            if not has_connection or self.egress_id is None:
                raise ValueError(
                    "WebSocket/bootstrap source context requires connection and egress"
                )
            return

        if has_connection or self.egress_id is None:
            raise ValueError(
                "routine REST source context requires only a non-null egress_id"
            )


class NativeEventDraft(FrozenStrictModel):
    exchange: Exchange
    market: Market | None
    instrument_key: NonEmptyString | None
    wire_symbol: NonEmptyString | None
    logical_stream: NonEmptyString
    native_channel: NonEmptyString | None
    transport: Transport
    event_time_ns: NonNegativeInt | None
    event_time_source: NonEmptyString | None
    integrity_mode: IntegrityMode | None = None
    coverage: CoverageMode | None = None
    rest_metadata: RestMetadata | None = None
    payload: ValidatedJsonPayload

    @model_validator(mode="after")
    def validate_scope_and_transport(self) -> Self:
        is_control = self.logical_stream == "_control"
        if self.market is None and not is_control:
            raise ValueError("market may be null only for exchange _control records")
        if (self.instrument_key is None) != (self.wire_symbol is None):
            raise ValueError("instrument_key and wire_symbol must be present together")
        if (
            not is_control
            and self.logical_stream not in MARKET_SCOPED_STREAMS
            and self.instrument_key is None
        ):
            raise ValueError(
                f"instrument_key and wire_symbol are required for {self.logical_stream}"
            )
        if self.native_channel is None and not is_control:
            raise ValueError("native_channel may be null only for _control records")
        if (self.event_time_ns is None) != (self.event_time_source is None):
            raise ValueError(
                "event_time_ns and event_time_source must be present together"
            )
        if self.transport is Transport.REST:
            if self.rest_metadata is None:
                raise ValueError("REST records require rest_metadata")
        elif self.rest_metadata is not None:
            raise ValueError("rest_metadata is valid only for REST records")
        if self.transport is Transport.INTERNAL and not is_control:
            raise ValueError("internal transport is reserved for _control records")
        if (
            self.logical_stream == "book_live_bootstrap"
            and self.transport is not Transport.REST
        ):
            raise ValueError("book_live_bootstrap must use REST transport")
        if self.integrity_mode is not None and self.logical_stream not in BOOK_STREAMS:
            raise ValueError("integrity_mode is valid only for book records")
        return self

    def validate_source(self, source: SourceContext) -> None:
        source.validate_for(
            transport=self.transport,
            logical_stream=self.logical_stream,
        )


class RawEnvelope(NativeEventDraft):
    schema_version: Literal[1] = 1
    received_at_ns: NonNegativeInt
    monotonic_ns: NonNegativeInt
    worker_instance_id: NonEmptyString
    connection_id: NonEmptyString | None
    connection_generation: NonNegativeInt | None
    writer_sequence: NonNegativeInt
    egress_id: NonEmptyString | None
    config_sha256: ConfigSha256

    @model_validator(mode="after")
    def validate_source_fields(self) -> Self:
        try:
            source = SourceContext(
                connection_id=self.connection_id,
                connection_generation=self.connection_generation,
                egress_id=self.egress_id,
            )
            self.validate_source(source)
        except ValueError as error:
            raise ValueError(f"invalid source context: {error}") from error
        return self
