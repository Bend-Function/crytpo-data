from __future__ import annotations

from datetime import date
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

REGISTRY_SCHEMA_VERSION = 1

ExchangeId = Literal["binance", "okx", "bybit", "bitget", "kraken"]
MarketId = Literal["spot", "perpetual"]
BootstrapKind = Literal["none", "rest_snapshot"]
SpecialDepth = Literal["full", "symbol_max_depth"]
BookDepth = Annotated[int, Field(gt=0, strict=True)] | SpecialDepth
RestDepth = Annotated[int, Field(gt=0, strict=True)] | Literal["full"]
UpdateIntervalMs = Annotated[int, Field(gt=0, strict=True)] | Literal["event_driven"]
NonEmptyString = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, strict=True),
]
PositiveInt = Annotated[int, Field(gt=0, strict=True)]


def _tuple_from_list(value: object) -> object:
    if isinstance(value, list):
        return tuple(value)
    return value


def _is_public_base_url(value: str, *, scheme: str) -> bool:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
    except ValueError:
        return False
    return (
        parsed.scheme == scheme
        and hostname is not None
        and parsed.username is None
        and parsed.password is None
        and not parsed.query
        and not parsed.fragment
    )


StringTuple = Annotated[
    tuple[NonEmptyString, ...],
    BeforeValidator(_tuple_from_list),
    Field(min_length=1),
]
DepthTuple = Annotated[
    tuple[BookDepth, ...],
    BeforeValidator(_tuple_from_list),
    Field(min_length=1),
]
MarketTuple = Annotated[
    tuple[MarketId, ...],
    BeforeValidator(_tuple_from_list),
    Field(min_length=1),
]


class FrozenStrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class WindowLimit(FrozenStrictModel):
    limit: PositiveInt
    window_seconds: PositiveInt
    scope: Literal["ip", "domain", "client", "connection"]


class ConnectionLimits(FrozenStrictModel):
    connection_attempts: WindowLimit | None = None
    concurrent_connections: PositiveInt | None = None
    client_messages_per_second: PositiveInt | None = None
    subscription_requests: WindowLimit | None = None
    subscriptions_per_connection: PositiveInt | None = None
    recommended_subscriptions_per_connection: PositiveInt | None = None
    subscription_payload_bytes: PositiveInt | None = None
    subscription_payload_characters: PositiveInt | None = None
    subscription_args_per_request: PositiveInt | None = None
    connection_lifetime_seconds: PositiveInt | None = None


class BookCapability(FrozenStrictModel):
    channel: NonEmptyString
    supported_depths: DepthTuple
    recommended_depth: BookDepth
    update_interval_ms: UpdateIntervalMs
    bootstrap: BootstrapKind
    max_rest_depth: RestDepth

    @model_validator(mode="after")
    def validate_recommended_depth(self) -> Self:
        if self.recommended_depth not in self.supported_depths:
            raise ValueError("recommended depth must be one of supported_depths")
        return self


class MarketCapability(FrozenStrictModel):
    market: MarketId
    rest_base_urls: StringTuple
    websocket_base_urls: StringTuple
    live_book: BookCapability
    connection_limits: ConnectionLimits = Field(default_factory=ConnectionLimits)

    @field_validator("rest_base_urls", mode="after")
    @classmethod
    def validate_rest_urls(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _is_public_base_url(item, scheme="https") for item in value):
            raise ValueError("public REST base URLs must be valid https URLs")
        return value

    @field_validator("websocket_base_urls", mode="after")
    @classmethod
    def validate_websocket_urls(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _is_public_base_url(item, scheme="wss") for item in value):
            raise ValueError("public WebSocket base URLs must be valid wss URLs")
        return value


class DateGatedFeature(FrozenStrictModel):
    id: NonEmptyString
    markets: MarketTuple
    available_from: NonEmptyString | None
    requires_live_probe: bool = True

    @field_validator("available_from", mode="after")
    @classmethod
    def validate_available_from(cls, value: str | None) -> str | None:
        if value is not None:
            try:
                date.fromisoformat(value)
            except ValueError as error:
                raise ValueError(
                    "available_from must be an ISO calendar date"
                ) from error
        return value


MarketCapabilityTuple = Annotated[
    tuple[MarketCapability, ...],
    BeforeValidator(_tuple_from_list),
    Field(min_length=1),
]
DateGatedFeatureTuple = Annotated[
    tuple[DateGatedFeature, ...],
    BeforeValidator(_tuple_from_list),
]


class ExchangeCapability(FrozenStrictModel):
    schema_version: Literal[1]
    exchange: ExchangeId
    anonymous_only: bool
    markets: MarketCapabilityTuple
    date_gated_features: DateGatedFeatureTuple = ()

    @model_validator(mode="after")
    def validate_and_normalize_collections(self) -> Self:
        market_ids = [market.market for market in self.markets]
        if len(set(market_ids)) != len(market_ids):
            raise ValueError("market IDs must be unique within an exchange record")
        feature_ids = [feature.id for feature in self.date_gated_features]
        if len(set(feature_ids)) != len(feature_ids):
            raise ValueError("date-gated feature IDs must be unique")
        supported_markets = set(market_ids)
        for feature in self.date_gated_features:
            unsupported = sorted(set(feature.markets) - supported_markets)
            if unsupported:
                raise ValueError(
                    f"date-gated feature {feature.id!r} references unsupported market: "
                    + ", ".join(unsupported)
                )

        ordered_markets = tuple(sorted(self.markets, key=lambda item: item.market))
        ordered_features = tuple(
            sorted(self.date_gated_features, key=lambda item: item.id)
        )
        if (
            ordered_markets != self.markets
            or ordered_features != self.date_gated_features
        ):
            return self.model_copy(
                update={
                    "markets": ordered_markets,
                    "date_gated_features": ordered_features,
                }
            )
        return self
