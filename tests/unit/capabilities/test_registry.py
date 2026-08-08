from __future__ import annotations

import json
import pickle
from copy import deepcopy
from importlib import resources
from pathlib import Path

import pytest
from pydantic import ValidationError

from crypto_collector.capabilities.registry import (
    CapabilityError,
    CapabilityRegistry,
)
from crypto_collector.domain.types import Exchange, Market

_BLOCK_RECORD = """\
schema_version: 1
exchange: binance
anonymous_only: true
markets:
  - market: spot
    rest_base_urls:
      - https://data-api.binance.vision
    websocket_base_urls:
      - wss://data-stream.binance.vision:443
    live_book:
      channel: diff_depth
      supported_depths:
        - full
      recommended_depth: full
      update_interval_ms: 100
      bootstrap: rest_snapshot
      max_rest_depth: 5000
    connection_limits:
      subscriptions_per_connection: 1024
date_gated_features: []
"""

_FLOW_RECORD = """\
schema_version: 1
exchange: binance
anonymous_only: true
markets: [{market: spot, rest_base_urls: [https://data-api.binance.vision], websocket_base_urls: [wss://data-stream.binance.vision:443], live_book: {channel: diff_depth, supported_depths: [full], recommended_depth: full, update_interval_ms: 100, bootstrap: rest_snapshot, max_rest_depth: 5000}, connection_limits: {subscriptions_per_connection: 1024}}]
date_gated_features: []
"""


def _write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")


def test_builtin_registry_contains_the_five_supported_exchanges() -> None:
    registry = CapabilityRegistry.load_builtin()

    assert tuple(record.exchange for record in registry.records) == (
        "binance",
        "bitget",
        "bybit",
        "kraken",
        "okx",
    )
    assert len(registry.sha256) == 64
    assert all(record.anonymous_only for record in registry.records)


@pytest.mark.parametrize(
    (
        "exchange",
        "market",
        "channel",
        "recommended_depth",
        "update_interval_ms",
        "bootstrap",
        "max_rest_depth",
    ),
    [
        ("binance", "spot", "diff_depth", "full", 100, "rest_snapshot", 5000),
        (
            "binance",
            "perpetual",
            "diff_depth",
            "full",
            100,
            "rest_snapshot",
            1000,
        ),
        ("okx", "spot", "books", 400, 100, "none", 5000),
        ("okx", "perpetual", "books", 400, 100, "none", 5000),
        ("bybit", "spot", "orderbook", 200, 100, "none", 1000),
        ("bybit", "perpetual", "orderbook", 200, 100, "none", 1000),
        (
            "bitget",
            "spot",
            "books",
            "symbol_max_depth",
            50,
            "none",
            1000,
        ),
        (
            "bitget",
            "perpetual",
            "books",
            "symbol_max_depth",
            50,
            "none",
            1000,
        ),
        ("kraken", "spot", "book", 100, "event_driven", "none", 500),
        (
            "kraken",
            "perpetual",
            "book",
            "full",
            "event_driven",
            "none",
            "full",
        ),
    ],
)
def test_builtin_registry_encodes_approved_book_defaults(
    exchange: str,
    market: str,
    channel: str,
    recommended_depth: int | str,
    update_interval_ms: int | str,
    bootstrap: str,
    max_rest_depth: int | str,
) -> None:
    capability = CapabilityRegistry.load_builtin().for_market(exchange, market)

    assert capability.rest_base_urls
    assert capability.websocket_base_urls
    assert capability.live_book.channel == channel
    assert capability.live_book.recommended_depth == recommended_depth
    assert capability.live_book.update_interval_ms == update_interval_ms
    assert capability.live_book.bootstrap == bootstrap
    assert capability.live_book.max_rest_depth == max_rest_depth


def test_lookup_accepts_domain_enums_and_book_validation_returns_the_capability() -> (
    None
):
    registry = CapabilityRegistry.load_builtin()

    market = registry.for_market(Exchange.OKX, Market.SPOT)
    decision = registry.validate_book(
        Exchange.OKX,
        Market.SPOT,
        channel="books",
        depth=400,
    )

    assert decision is market.live_book


def test_unsupported_okx_anonymous_depth_is_rejected() -> None:
    registry = CapabilityRegistry.load_builtin()

    with pytest.raises(CapabilityError, match="supported live depths"):
        registry.validate_book("okx", "spot", channel="books", depth=500)


def test_unknown_exchange_market_and_channel_are_actionable_errors() -> None:
    registry = CapabilityRegistry.load_builtin()

    with pytest.raises(CapabilityError, match="unsupported exchange"):
        registry.for_exchange("unknown")
    with pytest.raises(CapabilityError, match="does not support market"):
        registry.for_market("binance", "options")
    with pytest.raises(CapabilityError, match="supported live channel"):
        registry.validate_book("okx", "spot", channel="books5", depth=400)


def test_date_gated_features_capture_known_release_constraints() -> None:
    registry = CapabilityRegistry.load_builtin()

    okx = registry.for_exchange("okx")
    bybit = registry.for_exchange("bybit")

    assert {feature.id for feature in okx.date_gated_features} >= {"books_rpi"}
    assert {feature.id for feature in bybit.date_gated_features} >= {
        "spot_full_order_book",
        "perpetual_full_order_book",
    }
    perpetual_full = next(
        feature
        for feature in bybit.date_gated_features
        if feature.id == "perpetual_full_order_book"
    )
    assert perpetual_full.available_from == "2026-08-11"
    assert perpetual_full.requires_live_probe is True


def test_kraken_spot_separates_standard_and_grouped_rest_books() -> None:
    capability = CapabilityRegistry.load_builtin().for_market("kraken", "spot")

    assert capability.live_book.max_rest_depth == 500
    assert tuple(
        (variant.id, variant.max_depth, variant.aggregated)
        for variant in capability.live_book.rest_book_variants
    ) == (("grouped_book", 1000, True),)


def test_connection_limit_scopes_and_recommendations_match_evidence() -> None:
    registry = CapabilityRegistry.load_builtin()

    kraken_futures = registry.for_market("kraken", "perpetual")
    subscription_requests = kraken_futures.connection_limits.subscription_requests
    assert subscription_requests is not None
    assert subscription_requests.scope == "connection"

    for market in ("spot", "perpetual"):
        bitget = registry.for_market("bitget", market)
        recommended = bitget.connection_limits.recommended_subscriptions_per_connection
        assert recommended is not None
        assert recommended < 50


def test_capability_digest_uses_validated_content_not_yaml_formatting(
    tmp_path: Path,
) -> None:
    block = tmp_path / "block"
    flow = tmp_path / "flow"
    block.mkdir()
    flow.mkdir()
    _write(block / "first.yaml", _BLOCK_RECORD)
    _write(flow / "renamed.yaml", _FLOW_RECORD)

    first = CapabilityRegistry.from_directory(block)
    second = CapabilityRegistry.from_directory(flow)

    assert first.records == second.records
    assert first.sha256 == second.sha256


def test_digest_changes_when_validated_semantics_change(tmp_path: Path) -> None:
    first_path = tmp_path / "first"
    second_path = tmp_path / "second"
    first_path.mkdir()
    second_path.mkdir()
    _write(first_path / "record.yaml", _BLOCK_RECORD)
    _write(
        second_path / "record.yaml",
        _BLOCK_RECORD.replace("update_interval_ms: 100", "update_interval_ms: 1000"),
    )

    assert (
        CapabilityRegistry.from_directory(first_path).sha256
        != CapabilityRegistry.from_directory(second_path).sha256
    )


def test_duplicate_exchange_ids_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path / "one.yaml", _BLOCK_RECORD)
    _write(tmp_path / "two.yaml", _FLOW_RECORD)

    with pytest.raises(CapabilityError, match="duplicate exchange ID.*binance"):
        CapabilityRegistry.from_directory(tmp_path)


def test_unsupported_registry_schema_is_rejected(tmp_path: Path) -> None:
    _write(
        tmp_path / "future.yaml",
        _BLOCK_RECORD.replace("schema_version: 1", "schema_version: 99"),
    )

    with pytest.raises(CapabilityError, match="unsupported registry schema version 99"):
        CapabilityRegistry.from_directory(tmp_path)


@pytest.mark.parametrize("invalid_version", ["true", "1.0", '"1"', "null"])
def test_registry_schema_version_requires_an_exact_integer(
    tmp_path: Path,
    invalid_version: str,
) -> None:
    _write(
        tmp_path / "invalid.yaml",
        _BLOCK_RECORD.replace(
            "schema_version: 1", f"schema_version: {invalid_version}"
        ),
    )

    with pytest.raises(CapabilityError, match="schema version.*integer"):
        CapabilityRegistry.from_directory(tmp_path)


def test_unknown_record_fields_are_rejected(tmp_path: Path) -> None:
    _write(tmp_path / "invalid.yaml", _BLOCK_RECORD + "unexpected: true\n")

    with pytest.raises(CapabilityError, match="unexpected"):
        CapabilityRegistry.from_directory(tmp_path)


def test_base_urls_require_a_secure_scheme_and_hostname(tmp_path: Path) -> None:
    _write(
        tmp_path / "invalid.yaml",
        _BLOCK_RECORD.replace(
            "https://data-api.binance.vision",
            "https://",
        ),
    )

    with pytest.raises(CapabilityError, match="valid https"):
        CapabilityRegistry.from_directory(tmp_path)


@pytest.mark.parametrize(
    "invalid_url",
    [
        "https://example.com:bad",
        "https://example.com:99999",
        "https://example.com:",
        "https://exa mple.com",
        "https://exa%20mple.com",
        "https://exa\x80mple.com",
        "https://exa\x9fmple.com",
        "https://example.com:\\bad",
    ],
)
def test_base_urls_reject_values_network_clients_cannot_parse(
    tmp_path: Path,
    invalid_url: str,
) -> None:
    _write(
        tmp_path / "invalid.yaml",
        _BLOCK_RECORD.replace(
            "https://data-api.binance.vision",
            json.dumps(invalid_url),
        ),
    )

    with pytest.raises(CapabilityError, match="valid https"):
        CapabilityRegistry.from_directory(tmp_path)


def test_date_gate_cannot_reference_an_unsupported_market(tmp_path: Path) -> None:
    _write(
        tmp_path / "invalid.yaml",
        _BLOCK_RECORD.replace(
            "date_gated_features: []",
            """\
date_gated_features:
  - id: future_perpetual_book
    markets: [perpetual]
    available_from: null
    requires_live_probe: true""",
        ),
    )

    with pytest.raises(CapabilityError, match="unsupported market.*perpetual"):
        CapabilityRegistry.from_directory(tmp_path)


def test_records_and_nested_models_are_frozen(tmp_path: Path) -> None:
    _write(tmp_path / "record.yaml", _BLOCK_RECORD)
    registry = CapabilityRegistry.from_directory(tmp_path)
    record = registry.records[0]

    assert isinstance(registry.records, tuple)
    assert isinstance(record.markets, tuple)
    with pytest.raises(ValidationError, match="frozen"):
        record.exchange = "okx"  # type: ignore[misc]


def test_registry_pickle_round_trip_preserves_lookup_and_digest() -> None:
    registry = CapabilityRegistry.load_builtin()

    restored = pickle.loads(pickle.dumps(registry))

    assert restored == registry
    assert restored.records == registry.records
    assert restored.sha256 == registry.sha256
    assert restored.for_market("okx", "spot") == registry.for_market("okx", "spot")


def test_public_registry_document_round_trip_is_canonical_and_digest_bound() -> None:
    registry = CapabilityRegistry.load_builtin()

    document = registry.to_public_document()
    restored = CapabilityRegistry.from_public_document(document)

    assert restored == registry
    assert restored.to_public_document() == document
    assert json.loads(json.dumps(document)) == document

    tampered = deepcopy(document)
    tampered["records"][0]["anonymous_only"] = False  # type: ignore[index]
    assert CapabilityRegistry.from_public_document(tampered).sha256 != registry.sha256


@pytest.mark.parametrize(
    "mutation",
    [
        {"schema_version": 99, "records": []},
        {"schema_version": 1, "records": [], "unexpected": True},
        {"schema_version": 1, "records": []},
    ],
)
def test_public_registry_document_rejects_unknown_or_noncanonical_schema(
    mutation: dict[str, object],
) -> None:
    with pytest.raises(CapabilityError):
        CapabilityRegistry.from_public_document(mutation)


def test_public_registry_document_has_an_independent_eight_mib_limit() -> None:
    oversized = {
        "schema_version": 1,
        "records": [],
        "padding": "x" * (8 * 1024 * 1024),
    }

    with pytest.raises(CapabilityError, match="exceeds 8 MiB"):
        CapabilityRegistry.from_public_document(oversized)


def test_builtin_yaml_records_are_package_resources() -> None:
    package = resources.files("crypto_collector.capabilities.data")

    assert {path.name for path in package.iterdir() if path.name.endswith(".yaml")} == {
        "binance.yaml",
        "bitget.yaml",
        "bybit.yaml",
        "kraken.yaml",
        "okx.yaml",
    }
