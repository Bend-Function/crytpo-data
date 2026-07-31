from __future__ import annotations

import json
from decimal import Decimal
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, ValidationError

from crypto_collector.capabilities.registry import CapabilityError
from crypto_collector.config.effective import effective_scope
from crypto_collector.config.loader import ConfigBundle
from crypto_collector.config.primitives import SecretRef


class ReportModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class LiveBookDecision(ReportModel):
    enabled: bool
    channel: str
    depth: int | str
    update_interval_ms: int | str
    bootstrap: str


class DeepSnapshotDecision(ReportModel):
    enabled: bool
    requested_depth: int | str
    maximum_supported_depth: int | str
    requested_interval_ns: int
    capacity_status: Literal["unresolved"] = "unresolved"


class MarketCapabilityDecision(ReportModel):
    enabled: bool
    rest_base_urls: tuple[str, ...]
    websocket_base_urls: tuple[str, ...]
    live_book: LiveBookDecision
    deep_snapshot: DeepSnapshotDecision


class DateGateDecision(ReportModel):
    feature: str
    markets: tuple[str, ...]
    available_from: str | None
    required: bool
    status: Literal["probe_unresolved"] = "probe_unresolved"


class ExchangeCapabilityDecision(ReportModel):
    enabled: bool
    anonymous_only: bool
    markets: dict[str, MarketCapabilityDecision]
    date_gated_features: tuple[DateGateDecision, ...]


class DynamicScope(ReportModel):
    exchange: str
    market: str
    top_n: int
    new_listings_enabled: bool
    capture_duration_ns: int


class DynamicSelectionReport(ReportModel):
    status: Literal["unresolved"] = "unresolved"
    scopes: tuple[DynamicScope, ...]
    requires_live_catalog: bool = True
    requires_live_turnover: bool = True


class FixedRequest(ReportModel):
    exchange: str
    market: str
    canonical_pair: str
    status: Literal["catalog_unresolved"] = "catalog_unresolved"


class StaticCapacityReport(ReportModel):
    status: Literal["partial"] = "partial"
    configured_exchange_count: int
    configured_market_count: int
    enabled_market_count: int
    configured_egress_count: int
    fixed_request_count: int
    dynamic_top_n_slots: int
    max_http_concurrency: int
    max_ws_connections: int
    live_capacity_status: Literal["unresolved"] = "unresolved"


class RequestedIntervalsReport(ReportModel):
    deep_snapshot_ns: dict[str, int]
    materializer_ns: tuple[int, ...]


class ConfigReport(ReportModel):
    schema_version: Literal[1] = 1
    config_sha256: str
    capability_registry_sha256: str
    profile: str
    data_root: str
    state_root: str
    runtime: dict[str, Any]
    selection: dict[str, Any]
    books: dict[str, Any]
    capability_policy: dict[str, Any]
    writer: dict[str, Any]
    ingress: dict[str, Any]
    disk: dict[str, Any]
    materializer: dict[str, Any]
    network: dict[str, Any]
    archive: dict[str, Any]
    local_cleanup: dict[str, Any]
    exchanges: dict[str, Any]
    capability_decisions: dict[str, ExchangeCapabilityDecision]
    dynamic_selection: DynamicSelectionReport
    fixed_requests: tuple[FixedRequest, ...]
    static_capacity: StaticCapacityReport
    requested_intervals: RequestedIntervalsReport
    warnings: tuple[str, ...]

    def to_json(self) -> str:
        return json.dumps(
            self.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )

    def to_text(self) -> str:
        lines = [
            "Configuration valid",
            f"Config SHA-256: {self.config_sha256}",
            f"Capability SHA-256: {self.capability_registry_sha256}",
            f"Profile: {self.profile}",
            f"Exchanges: {len(self.exchanges)}",
            f"Fixed requests: {len(self.fixed_requests)} (catalog_unresolved)",
            "Dynamic selection: unresolved",
            "Live capacity: unresolved",
            "Warnings:",
        ]
        lines.extend(f"- {warning}" for warning in self.warnings)
        return "\n".join(lines)


def _reference_value(value: object) -> Any:
    if isinstance(value, SecretRef):
        return value.fingerprint_value()
    if isinstance(value, BaseModel):
        fields = []
        for name, field in type(value).model_fields.items():
            output_name = field.alias or name
            fields.append((output_name, getattr(value, name)))
        return {name: _reference_value(item) for name, item in sorted(fields)}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {
            str(key): _reference_value(item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, (list, tuple)):
        return [_reference_value(item) for item in value]
    if isinstance(value, Decimal):
        return str(value)
    if value is None or type(value) in {bool, int, float, str}:
        return value
    raise TypeError(f"unsupported report value: {type(value).__name__}")


def build_config_report(bundle: ConfigBundle) -> ConfigReport:
    config = bundle.config
    reference = _reference_value(config)
    if not isinstance(reference, dict):
        raise TypeError("collector configuration did not produce a mapping")

    decisions: dict[str, ExchangeCapabilityDecision] = {}
    dynamic_scopes: list[DynamicScope] = []
    fixed_requests: list[FixedRequest] = []
    deep_intervals: dict[str, int] = {}
    configured_markets = 0
    enabled_markets = 0
    dynamic_top_n_slots = 0

    for exchange_id, exchange in sorted(config.exchanges.items()):
        capability = bundle.capabilities.for_exchange(exchange_id)
        markets: dict[str, MarketCapabilityDecision] = {}
        for market_id in sorted(exchange.markets):
            configured_markets += 1
            market_capability = bundle.capabilities.for_market(exchange_id, market_id)
            scope = effective_scope(config, exchange_id, market_id)
            enabled_markets += int(scope.enabled)
            deep_intervals[f"{exchange_id}/{market_id}"] = (
                scope.books.deep_snapshot.requested_interval_ns
            )
            markets[market_id] = MarketCapabilityDecision(
                enabled=scope.enabled,
                rest_base_urls=market_capability.rest_base_urls,
                websocket_base_urls=market_capability.websocket_base_urls,
                live_book=LiveBookDecision(
                    enabled=scope.enabled and scope.books.live.enabled,
                    channel=market_capability.live_book.channel,
                    depth=market_capability.live_book.recommended_depth,
                    update_interval_ms=market_capability.live_book.update_interval_ms,
                    bootstrap=market_capability.live_book.bootstrap,
                ),
                deep_snapshot=DeepSnapshotDecision(
                    enabled=scope.enabled and scope.books.deep_snapshot.enabled,
                    requested_depth=scope.books.deep_snapshot.depth,
                    maximum_supported_depth=market_capability.live_book.max_rest_depth,
                    requested_interval_ns=(
                        scope.books.deep_snapshot.requested_interval_ns
                    ),
                ),
            )
            if scope.enabled:
                dynamic_scopes.append(
                    DynamicScope(
                        exchange=exchange_id,
                        market=market_id,
                        top_n=scope.selection.top_n,
                        new_listings_enabled=scope.selection.new_listings.enabled,
                        capture_duration_ns=(
                            scope.selection.new_listings.capture_duration_ns
                        ),
                    )
                )
                dynamic_top_n_slots += scope.selection.top_n
                fixed_requests.extend(
                    FixedRequest(
                        exchange=exchange_id,
                        market=market_id,
                        canonical_pair=pair,
                    )
                    for pair in scope.selection.fixed_pairs
                )

        date_gates = tuple(
            DateGateDecision(
                feature=feature.id,
                markets=feature.markets,
                available_from=feature.available_from,
                required=config.capabilities.date_gated_default_required,
            )
            for feature in capability.date_gated_features
        )
        decisions[exchange_id] = ExchangeCapabilityDecision(
            enabled=exchange.enabled,
            anonymous_only=capability.anonymous_only,
            markets=markets,
            date_gated_features=date_gates,
        )

    fixed_requests.sort(
        key=lambda item: (item.exchange, item.market, item.canonical_pair)
    )
    dynamic_scopes.sort(key=lambda item: (item.exchange, item.market))
    egresses = config.network.egress_pool
    warnings = [
        "dynamic Top-N and new-listing selection is unresolved until config probe",
        "live endpoint budgets and schedulable intervals are unresolved until config probe",
    ]
    if fixed_requests:
        warnings.append(
            "fixed pairs remain catalog_unresolved until venue instruments are probed"
        )
    if any(decision.date_gated_features for decision in decisions.values()):
        warnings.append("date-gated capabilities require a live probe")
    quota_groups = [egress.quota_group for egress in egresses]
    if len(set(quota_groups)) < len(quota_groups):
        warnings.append(
            "multiple egress IDs share a quota_group and do not add independent venue budget"
        )

    return ConfigReport(
        config_sha256=bundle.config_sha256,
        capability_registry_sha256=bundle.capabilities.sha256,
        profile=config.profile,
        data_root=str(config.data_root),
        state_root=str(config.state_root),
        runtime=reference["runtime"],
        selection=reference["selection"],
        books=reference["books"],
        capability_policy=reference["capabilities"],
        writer=reference["writer"],
        ingress=reference["ingress"],
        disk=reference["disk"],
        materializer=reference["materializer"],
        network=reference["network"],
        archive=reference["archive"],
        local_cleanup=reference["local_cleanup"],
        exchanges=reference["exchanges"],
        capability_decisions=decisions,
        dynamic_selection=DynamicSelectionReport(scopes=tuple(dynamic_scopes)),
        fixed_requests=tuple(fixed_requests),
        static_capacity=StaticCapacityReport(
            configured_exchange_count=len(config.exchanges),
            configured_market_count=configured_markets,
            enabled_market_count=enabled_markets,
            configured_egress_count=len(egresses),
            fixed_request_count=len(fixed_requests),
            dynamic_top_n_slots=dynamic_top_n_slots,
            max_http_concurrency=sum(item.max_http_concurrency for item in egresses),
            max_ws_connections=sum(item.max_ws_connections for item in egresses),
        ),
        requested_intervals=RequestedIntervalsReport(
            deep_snapshot_ns=deep_intervals,
            materializer_ns=config.materializer.intervals_ns,
        ),
        warnings=tuple(sorted(warnings)),
    )


def format_validation_error(error: Exception) -> str:
    if isinstance(error, CapabilityError):
        return f"Unsupported capability: {error}"
    if isinstance(error, ValidationError):
        issues = []
        for issue in error.errors(include_input=False, include_url=False):
            location = ".".join(str(item) for item in issue["loc"])
            issues.append(f"{location}: {issue['msg']}" if location else issue["msg"])
        return "Invalid configuration: " + "; ".join(sorted(issues))
    return f"Invalid configuration: {error}"


__all__ = [
    "ConfigReport",
    "build_config_report",
    "format_validation_error",
]
