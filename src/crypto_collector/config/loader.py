from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from crypto_collector.capabilities.registry import CapabilityError, CapabilityRegistry
from crypto_collector.config.effective import effective_scope
from crypto_collector.config.fingerprint import config_sha256
from crypto_collector.config.merge import merge_layers
from crypto_collector.config.models import (
    CollectorConfig,
    ConfigSecretError,
    iter_secret_refs,
    validate_secret_snapshot,
)
from crypto_collector.config.primitives import SecretSnapshot
from crypto_collector.config.yaml import ConfigSyntaxError, load_yaml_mapping

_PROFILE_NAME = re.compile(r"^[a-z0-9][a-z0-9_-]*$")
_BUILTIN_DEFAULTS: dict[str, Any] = {"profile": "research-default"}


@dataclass(frozen=True, slots=True)
class ConfigBundle:
    config: CollectorConfig
    capabilities: CapabilityRegistry
    config_sha256: str


@dataclass(frozen=True, slots=True)
class ResolvedConfigBundle:
    bundle: ConfigBundle
    secrets: SecretSnapshot


def _root_path(path: Path) -> Path:
    candidate = Path(path)
    return candidate / "config.yaml" if candidate.is_dir() else candidate


def _optional_mapping(path: Path) -> dict[str, Any]:
    return load_yaml_mapping(path) if path.is_file() else {}


def _selected_profile(root: Mapping[str, Any], *, config_dir: Path) -> dict[str, Any]:
    selected = root.get("profile", _BUILTIN_DEFAULTS["profile"])
    if type(selected) is not str or _PROFILE_NAME.fullmatch(selected) is None:
        raise ConfigSyntaxError(
            config_dir.parent / "config.yaml",
            "profile must be a lowercase name containing letters, digits, '-' or '_'",
        )

    profile_path = config_dir / "profiles" / f"{selected}.yaml"
    if not profile_path.is_file():
        if "profile" in root:
            raise ConfigSyntaxError(
                profile_path, f"selected profile {selected!r} was not found"
            )
        return {}

    profile = load_yaml_mapping(profile_path)
    if "profile" in profile:
        raise ConfigSyntaxError(
            profile_path, "a profile file cannot select another profile"
        )
    return profile


def _merge_exchange_files(
    document: dict[str, Any], *, config_dir: Path
) -> dict[str, Any]:
    exchange_dir = config_dir / "exchanges"
    exchange_files = (
        sorted(exchange_dir.glob("*.yaml")) if exchange_dir.is_dir() else []
    )
    if not exchange_files:
        return document

    existing = document.get("exchanges", {})
    if not isinstance(existing, Mapping):
        return document
    exchanges = {str(key): value for key, value in existing.items()}
    for path in exchange_files:
        exchange_id = path.stem
        current = exchanges.get(exchange_id, {})
        if not isinstance(current, Mapping):
            current = {}
        exchanges[exchange_id] = merge_layers(current, load_yaml_mapping(path))
    return merge_layers(document, {"exchanges": exchanges})


def _validate_capability_scopes(
    config: CollectorConfig, registry: CapabilityRegistry
) -> None:
    known_exchanges = {record.exchange for record in registry.records}
    issues: set[str] = set()
    for exchange_id, exchange in sorted(config.exchanges.items()):
        if exchange_id not in known_exchanges:
            issues.add(f"unknown exchange: {exchange_id}")
            continue
        for market_id in sorted(exchange.markets):
            try:
                capability = registry.for_market(exchange_id, market_id)
            except CapabilityError as error:
                issues.add(str(error))
                continue

            configured_market = exchange.markets[market_id]
            for symbol in (None, *sorted(configured_market.symbols)):
                scope = effective_scope(config, exchange_id, market_id, symbol)
                requested_depth = scope.books.deep_snapshot.depth
                maximum_depth = capability.live_book.max_rest_depth
                if (
                    type(requested_depth) is int
                    and type(maximum_depth) is int
                    and requested_depth > maximum_depth
                ):
                    scope_name = f"{exchange_id}/{market_id}"
                    if symbol is not None:
                        scope_name += f"/{symbol}"
                    issues.add(
                        f"{scope_name} requests deep REST depth {requested_depth}; "
                        f"maximum deep REST depth is {maximum_depth}"
                    )
    if issues:
        raise CapabilityError("; ".join(sorted(issues)))


def load_config(path: Path) -> ConfigBundle:
    root_path = _root_path(Path(path))
    root = load_yaml_mapping(root_path)
    config_dir = root_path.parent / "config"
    network_path = config_dir / "network.yaml"
    profile = _selected_profile(root, config_dir=config_dir)

    has_network_fragment = network_path.is_file()
    network = _optional_mapping(network_path)
    if has_network_fragment and "network" in root:
        raise ConfigSyntaxError(
            network_path,
            "network.yaml exclusively owns the root network subtree",
        )
    root_layer = (
        merge_layers(root, {"network": network}) if has_network_fragment else dict(root)
    )
    merged = merge_layers(_BUILTIN_DEFAULTS, root_layer, profile)
    merged = _merge_exchange_files(merged, config_dir=config_dir)

    registry = CapabilityRegistry.load_builtin()
    config = CollectorConfig.model_validate(
        merged, context={"base_dir": root_path.parent}
    )
    _validate_capability_scopes(config, registry)
    digest = config_sha256(config, capability_registry_sha256=registry.sha256)
    return ConfigBundle(config=config, capabilities=registry, config_sha256=digest)


def resolve_bundle(bundle: ConfigBundle) -> ResolvedConfigBundle:
    try:
        secrets = SecretSnapshot.resolve_all(iter_secret_refs(bundle.config))
    except ValueError as error:
        detail = str(error).removeprefix("failed to resolve secrets: ")
        raise ConfigSecretError(detail) from error
    validate_secret_snapshot(bundle.config, secrets)
    return ResolvedConfigBundle(bundle=bundle, secrets=secrets)


def load_resolved_config(path: Path) -> ResolvedConfigBundle:
    return resolve_bundle(load_config(path))


__all__ = [
    "ConfigBundle",
    "ConfigSecretError",
    "ConfigSyntaxError",
    "ResolvedConfigBundle",
    "load_config",
    "load_resolved_config",
    "resolve_bundle",
]
