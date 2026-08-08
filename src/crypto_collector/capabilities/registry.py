from __future__ import annotations

import hashlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import Enum
from importlib import resources
from pathlib import Path
from typing import Any

import simplejson  # type: ignore[import-untyped]
from pydantic import BaseModel, ValidationError
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from crypto_collector.capabilities.models import (
    REGISTRY_SCHEMA_VERSION,
    BookCapability,
    ExchangeCapability,
    MarketCapability,
)
from crypto_collector.domain.types import Exchange, Market


class CapabilityError(ValueError):
    pass


_MAX_PUBLIC_DOCUMENT_BYTES = 8 * 1024 * 1024
_PUBLIC_DOCUMENT_KEYS = frozenset({"records", "schema_version"})


def _canonicalize(value: object) -> Any:
    if isinstance(value, BaseModel):
        return {
            name: _canonicalize(getattr(value, name))
            for name in sorted(type(value).model_fields)
        }
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _canonicalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, float):
        return Decimal(str(value))
    if value is None or type(value) in {bool, int, str, Decimal}:
        return value
    raise TypeError(f"unsupported canonical capability value: {type(value).__name__}")


def _mutable_json_value(value: object) -> object:
    if isinstance(value, Mapping):
        return {key: _mutable_json_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_mutable_json_value(item) for item in value]
    return value


def _public_document(records: tuple[ExchangeCapability, ...]) -> dict[str, object]:
    return {
        "schema_version": REGISTRY_SCHEMA_VERSION,
        "records": [record.model_dump(mode="json") for record in records],
    }


def _public_document_bytes(document: object) -> bytes:
    encoded: bytes | None
    try:
        canonical = _canonicalize(document)
        encoded = simplejson.dumps(
            canonical,
            use_decimal=True,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        encoded = None
    if encoded is None:
        raise CapabilityError("public capability registry document must be strict JSON")
    if len(encoded) > _MAX_PUBLIC_DOCUMENT_BYTES:
        raise CapabilityError("public capability registry document exceeds 8 MiB")
    return encoded


def _registry_sha256(records: tuple[ExchangeCapability, ...]) -> str:
    return hashlib.sha256(_public_document_bytes(_public_document(records))).hexdigest()


def _load_yaml_record(source: str, text: str) -> ExchangeCapability:
    yaml = YAML(typ="safe", pure=True)
    yaml.allow_duplicate_keys = False
    yaml.version = (1, 2)
    try:
        documents = list(yaml.load_all(text))
    except YAMLError as error:
        raise CapabilityError(f"invalid capability YAML {source}: {error}") from error
    if len(documents) != 1:
        raise CapabilityError(f"capability YAML {source} must contain one document")
    document = documents[0]
    if not isinstance(document, dict):
        raise CapabilityError(f"capability YAML {source} must contain a mapping")

    schema_version = document.get("schema_version")
    if type(schema_version) is not int:
        raise CapabilityError(
            f"registry schema version in {source} must be integer "
            f"{REGISTRY_SCHEMA_VERSION}"
        )
    if schema_version != REGISTRY_SCHEMA_VERSION:
        raise CapabilityError(
            f"unsupported registry schema version {schema_version} in {source}"
        )
    try:
        return ExchangeCapability.model_validate(document)
    except ValidationError as error:
        raise CapabilityError(f"invalid capability record {source}: {error}") from error


def _normalize_exchange(value: Exchange | str) -> str:
    return value.value if isinstance(value, Exchange) else value


def _normalize_market(value: Market | str) -> str:
    return value.value if isinstance(value, Market) else value


@dataclass(frozen=True, slots=True)
class CapabilityRegistry:
    records: tuple[ExchangeCapability, ...]
    sha256: str

    @classmethod
    def _from_records(
        cls, records: tuple[ExchangeCapability, ...]
    ) -> CapabilityRegistry:
        if not records:
            raise CapabilityError("capability registry contains no records")

        ordered = tuple(sorted(records, key=lambda record: record.exchange))
        duplicate_ids = sorted(
            {
                record.exchange
                for record in ordered
                if sum(item.exchange == record.exchange for item in ordered) > 1
            }
        )
        if duplicate_ids:
            raise CapabilityError(
                "duplicate exchange ID in capability registry: "
                + ", ".join(duplicate_ids)
            )
        return cls(
            records=ordered,
            sha256=_registry_sha256(ordered),
        )

    @classmethod
    def _from_sources(cls, sources: Iterable[tuple[str, str]]) -> CapabilityRegistry:
        records = tuple(_load_yaml_record(source, text) for source, text in sources)
        if not records:
            raise CapabilityError("capability registry contains no YAML records")
        return cls._from_records(records)

    @classmethod
    def from_public_document(cls, document: Mapping[str, object]) -> CapabilityRegistry:
        """Rebuild a registry from its canonical, public durable document."""

        encoded = _public_document_bytes(document)
        if not isinstance(document, Mapping):
            raise CapabilityError(
                "public capability registry document must be an object"
            )
        if frozenset(document) != _PUBLIC_DOCUMENT_KEYS:
            raise CapabilityError(
                "public capability registry document must contain exactly "
                "records and schema_version"
            )
        schema_version = document["schema_version"]
        if type(schema_version) is not int:
            raise CapabilityError(
                "public capability registry schema_version must be an integer"
            )
        if schema_version != REGISTRY_SCHEMA_VERSION:
            raise CapabilityError(
                "unsupported public capability registry schema_version"
            )
        raw_records = document["records"]
        if not isinstance(raw_records, Sequence) or isinstance(
            raw_records, (str, bytes, bytearray)
        ):
            raise CapabilityError("public capability registry records must be an array")

        records: list[ExchangeCapability] = []
        for raw_record in raw_records:
            if not isinstance(raw_record, Mapping):
                raise CapabilityError(
                    "public capability registry records must contain objects"
                )
            record: ExchangeCapability | None
            try:
                record = ExchangeCapability.model_validate(
                    _mutable_json_value(raw_record)
                )
            except ValidationError:
                record = None
            if record is None:
                raise CapabilityError("invalid public capability registry record")
            records.append(record)
        registry = cls._from_records(tuple(records))
        if encoded != _public_document_bytes(_public_document(registry.records)):
            raise CapabilityError(
                "public capability registry document is not canonical"
            )
        return registry

    def to_public_document(self) -> dict[str, object]:
        """Return the canonical public document bound by ``sha256``."""

        document = _public_document(self.records)
        digest = hashlib.sha256(_public_document_bytes(document)).hexdigest()
        if digest != self.sha256:
            raise CapabilityError("capability registry digest does not match records")
        return document

    @classmethod
    def from_directory(cls, path: str | Path) -> CapabilityRegistry:
        directory = Path(path)
        if not directory.is_dir():
            raise CapabilityError(f"capability directory does not exist: {directory}")
        sources = [
            (str(item), item.read_text(encoding="utf-8"))
            for item in sorted(directory.glob("*.yaml"))
            if item.is_file()
        ]
        return cls._from_sources(sources)

    @classmethod
    def load_builtin(cls) -> CapabilityRegistry:
        package = resources.files("crypto_collector.capabilities.data")
        sources = [
            (item.name, item.read_text(encoding="utf-8"))
            for item in sorted(package.iterdir(), key=lambda entry: entry.name)
            if item.name.endswith(".yaml") and item.is_file()
        ]
        registry = cls._from_sources(sources)
        expected = {exchange.value for exchange in Exchange}
        actual = {record.exchange for record in registry.records}
        if actual != expected:
            missing = sorted(expected - actual)
            unexpected = sorted(actual - expected)
            detail = []
            if missing:
                detail.append("missing " + ", ".join(missing))
            if unexpected:
                detail.append("unexpected " + ", ".join(unexpected))
            raise CapabilityError(
                "invalid built-in capability set: " + "; ".join(detail)
            )
        return registry

    def for_exchange(self, exchange: Exchange | str) -> ExchangeCapability:
        exchange_id = _normalize_exchange(exchange)
        for record in self.records:
            if record.exchange == exchange_id:
                return record
        raise CapabilityError(f"unsupported exchange: {exchange_id}")

    def for_market(
        self,
        exchange: Exchange | str,
        market: Market | str,
    ) -> MarketCapability:
        record = self.for_exchange(exchange)
        market_id = _normalize_market(market)
        for capability in record.markets:
            if capability.market == market_id:
                return capability
        raise CapabilityError(
            f"exchange {record.exchange} does not support market: {market_id}"
        )

    def validate_book(
        self,
        exchange: Exchange | str,
        market: Market | str,
        *,
        channel: str,
        depth: int | str,
    ) -> BookCapability:
        capability = self.for_market(exchange, market).live_book
        if channel != capability.channel:
            raise CapabilityError(
                f"supported live channel is {capability.channel!r}, got {channel!r}"
            )
        if type(depth) not in {int, str} or depth not in capability.supported_depths:
            supported = ", ".join(repr(item) for item in capability.supported_depths)
            raise CapabilityError(
                f"depth {depth!r} is not one of supported live depths: {supported}"
            )
        return capability
