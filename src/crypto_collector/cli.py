from __future__ import annotations

import asyncio
import json
import math
from collections.abc import Mapping
from contextlib import AsyncExitStack
from dataclasses import fields, is_dataclass
from decimal import Decimal
from enum import Enum, IntFlag
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer

from crypto_collector.config.effective import effective_scope
from crypto_collector.config.loader import ResolvedConfigBundle, load_resolved_config
from crypto_collector.config.report import build_config_report, format_validation_error
from crypto_collector.domain import Exchange

if TYPE_CHECKING:
    from crypto_collector.config.probe_contracts import ProbeReport

app = typer.Typer(no_args_is_help=True)
config_app = typer.Typer(no_args_is_help=True)
app.add_typer(config_app, name="config")


@app.callback()
def main() -> None:
    pass


@config_app.command("check")
def check_config(
    path: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        resolved = load_resolved_config(path)
        report = build_config_report(resolved.bundle)
    except (OSError, ValueError) as error:
        typer.echo(format_validation_error(error))
        raise typer.Exit(2) from error
    typer.echo(report.to_json() if json_output else report.to_text())


def _exchange_has_enabled_market(
    resolved: ResolvedConfigBundle,
    exchange: Exchange,
) -> bool:
    exchange_config = resolved.bundle.config.exchanges.get(exchange.value)
    return exchange_config is not None and any(
        effective_scope(
            resolved.bundle.config,
            exchange.value,
            market_id,
        ).enabled
        for market_id in exchange_config.markets
    )


async def _run_config_probe(resolved: ResolvedConfigBundle) -> ProbeReport:
    from crypto_collector.config.probe_contracts import ProbeEngine
    from crypto_collector.domain.clock import SystemClock
    from crypto_collector.exchanges.registry import AdapterRegistry

    clock = SystemClock()
    registry = AdapterRegistry()
    async with AsyncExitStack() as stack:
        if _exchange_has_enabled_market(resolved, Exchange.OKX):
            from crypto_collector.exchanges.okx.probe import OkxProbeProvider
            from crypto_collector.network import build_clients

            clients = {
                egress.id: await stack.enter_async_context(
                    build_clients(egress, secrets=resolved.secrets)
                )
                for egress in resolved.bundle.config.network.egress_pool
            }
            exchange_config = resolved.bundle.config.exchanges[Exchange.OKX.value]
            registry.register_probe_provider(
                OkxProbeProvider(
                    transports={
                        egress_id: client.http for egress_id, client in clients.items()
                    },
                    websocket_transports={
                        egress_id: client.websocket
                        for egress_id, client in clients.items()
                    },
                    quota_groups={
                        egress.id: egress.quota_group
                        for egress in resolved.bundle.config.network.egress_pool
                    },
                    clock=clock,
                    rest_base_url=exchange_config.endpoints.get(
                        "rest", "https://openapi.okx.com"
                    ),
                    websocket_public_url=exchange_config.endpoints.get(
                        "websocket_public",
                        "wss://ws.okx.com:8443/ws/v5/public",
                    ),
                    websocket_business_url=exchange_config.endpoints.get(
                        "websocket_business",
                        "wss://ws.okx.com:8443/ws/v5/business",
                    ),
                )
            )
        return await ProbeEngine(clock=clock).run(
            resolved.bundle,
            providers=registry.probe_providers(),
        )


def _probe_json_value(value: object) -> Any:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("probe report contains a non-finite float")
        return value
    if isinstance(value, IntFlag):
        return [
            member.name.lower()
            for member in type(value)
            if member.value and member in value and member.name is not None
        ]
    if isinstance(value, Enum):
        return _probe_json_value(value.value)
    if type(value) is Decimal:
        if not value.is_finite():
            raise ValueError("probe report contains a non-finite Decimal")
        return str(value)
    if isinstance(value, Mapping):
        if any(type(key) is not str for key in value):
            raise TypeError("probe report mappings must use string keys")
        return {key: _probe_json_value(item) for key, item in sorted(value.items())}
    if isinstance(value, (tuple, list)):
        return [_probe_json_value(item) for item in value]
    if isinstance(value, (set, frozenset)):
        normalized = [_probe_json_value(item) for item in value]
        return sorted(
            normalized,
            key=lambda item: json.dumps(
                item,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ),
        )
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _probe_json_value(getattr(value, field.name))
            for field in fields(value)
        }
    raise TypeError(f"unsupported probe report value: {type(value).__name__}")


def _probe_report_document(report: ProbeReport) -> dict[str, Any]:
    document = _probe_json_value(report)
    if not isinstance(document, dict):
        raise TypeError("probe report must serialize as an object")
    return {"success": report.success, **document}


def _probe_report_json(report: ProbeReport) -> str:
    return json.dumps(
        _probe_report_document(report),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )


def _probe_report_text(report: ProbeReport) -> str:
    lines = [
        "Configuration probe succeeded"
        if report.success
        else "Configuration probe failed",
        f"Config SHA-256: {report.config_sha256}",
        f"Capability SHA-256: {report.capability_registry_sha256}",
        f"Observed at (ns): {report.observed_at_ns}",
        f"Exchanges resolved: {len(report.exchanges)}",
        f"Failures: {len(report.failures)}",
    ]
    lines.extend(
        "- "
        + "/".join(
            part
            for part in (
                failure.exchange.value,
                failure.market,
                failure.feature_id,
                failure.code,
            )
            if part is not None
        )
        + f": {failure.message}"
        for failure in report.failures
    )
    return "\n".join(lines)


@config_app.command("probe")
def probe_config(
    path: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        resolved = load_resolved_config(path)
    except (OSError, ValueError) as error:
        typer.echo(format_validation_error(error))
        raise typer.Exit(2) from error
    try:
        report = asyncio.run(_run_config_probe(resolved))
        rendered = (
            _probe_report_json(report) if json_output else _probe_report_text(report)
        )
    except ModuleNotFoundError as error:
        typer.echo(
            "Configuration probe unavailable: install the collector role dependencies"
        )
        raise typer.Exit(1) from error
    except Exception as error:
        typer.echo("Configuration probe failed: runtime setup or cleanup failed")
        raise typer.Exit(1) from error
    typer.echo(rendered)
    if not report.success:
        raise typer.Exit(1)
