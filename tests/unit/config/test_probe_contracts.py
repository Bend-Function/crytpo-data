from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
from decimal import Decimal

import pytest

import crypto_collector.config.probe_contracts as probe_contracts_module
from crypto_collector.capabilities.registry import CapabilityRegistry
from crypto_collector.config.loader import ConfigBundle
from crypto_collector.config.models import CollectorConfig
from crypto_collector.config.probe_contracts import (
    DateGateProbe,
    DateGateRequest,
    EgressReachabilityProbe,
    EndpointBudgetProbe,
    EndpointWork,
    ExchangeProbeEvidence,
    MarketProbeEvidence,
    ProbeEngine,
    ProbeFailure,
    ProbeReport,
    ProbeRequest,
    PublicTimeProbe,
    TransportReachabilityProbe,
)
from crypto_collector.domain.types import Exchange, Market
from crypto_collector.selection.models import (
    CatalogInstrument,
    CatalogScope,
    CatalogView,
    LifecyclePhase,
    ListingState,
    Turnover,
    TurnoverMethod,
)
from tests.unit.config.test_models import BASE


class FakeClock:
    def __init__(self, time_ns: int = 123) -> None:
        self.now = time_ns

    def time_ns(self) -> int:
        return self.now

    def monotonic_ns(self) -> int:
        return self.now


class FakeProvider:
    exchange = Exchange.OKX

    def __init__(self, evidence: ExchangeProbeEvidence) -> None:
        self.evidence = evidence
        self.requests: list[ProbeRequest] = []

    async def probe(self, request: ProbeRequest) -> ExchangeProbeEvidence:
        self.requests.append(request)
        return self.evidence


class AdvancingProvider(FakeProvider):
    def __init__(
        self,
        evidence: ExchangeProbeEvidence,
        *,
        clock: FakeClock,
        completed_at_ns: int,
    ) -> None:
        super().__init__(evidence)
        self.clock = clock
        self.completed_at_ns = completed_at_ns

    async def probe(self, request: ProbeRequest) -> ExchangeProbeEvidence:
        self.requests.append(request)
        self.clock.now = self.completed_at_ns
        return self.evidence


def test_egress_reachability_separates_http_and_websocket_health() -> None:
    legacy = EgressReachabilityProbe("legacy", True, 123, "raw/legacy")
    assert legacy.http_reachable is True
    assert legacy.websocket_reachable is True

    transports = (
        TransportReachabilityProbe(
            "websocket", "business", False, 123, "raw/ws-business"
        ),
        TransportReachabilityProbe("http", "public_rest", True, 123, "raw/http"),
        TransportReachabilityProbe("websocket", "public", True, 123, "raw/ws-public"),
    )
    separated = EgressReachabilityProbe(
        "separated",
        False,
        123,
        "raw/separated",
        transports,
    )

    assert separated.http_reachable is True
    assert separated.websocket_reachable is False
    assert [(item.transport, item.endpoint_role) for item in separated.transports] == [
        ("http", "public_rest"),
        ("websocket", "business"),
        ("websocket", "public"),
    ]
    with pytest.raises(ValueError, match="must equal all"):
        EgressReachabilityProbe(
            "invalid",
            True,
            123,
            "raw/invalid",
            transports,
        )


def instrument(
    key: str,
    turnover: str | None = None,
    *,
    market: str = "spot",
) -> CatalogInstrument:
    value = (
        None
        if turnover is None
        else Turnover(
            Decimal(turnover),
            TurnoverMethod.EXCHANGE_QUOTE_TURNOVER,
            "USDT",
            observed_at_ns=123,
            raw_reference=f"raw/turnover/{key}",
        )
    )
    return CatalogInstrument(
        exchange="okx",
        market=market,
        instrument_key=key,
        canonical_pair=f"{key.removesuffix('-USDT')}/USDT",
        wire_symbols={"rest": key},
        base_asset=key.removesuffix("-USDT"),
        quote_asset="USDT",
        settlement_asset=None,
        status="live",
        lifecycle_phase=LifecyclePhase.TRADABLE,
        tradable=True,
        lifecycle={"state": "live"},
        tradable_at_ns=None,
        tradable_at_source=None,
        turnover=value,
        raw_catalog_reference=f"raw/catalog/{key}",
        first_seen_ns=100,
        last_seen_ns=123,
        present=True,
        listing_state=ListingState.BASELINE,
    )


def catalog(
    *items: CatalogInstrument,
    market: str = "spot",
    observed_at_ns: int = 123,
) -> CatalogView:
    normalized = tuple(
        replace(item, last_seen_ns=observed_at_ns) if item.present else item
        for item in items
    )
    has_turnover = any(item.turnover is not None for item in normalized)
    return CatalogView(
        scope=CatalogScope("okx", market),
        catalog_observed_at_ns=observed_at_ns,
        catalog_revision=1,
        catalog_digest_sha256="a" * 64,
        catalog_snapshot_id="catalog-100",
        catalog_page_raw_references=("raw/catalog-100",),
        turnover_observed_at_ns=observed_at_ns if has_turnover else None,
        turnover_revision=1 if has_turnover else 0,
        turnover_digest_sha256="b" * 64 if has_turnover else None,
        turnover_catalog_revision=1 if has_turnover else None,
        turnover_snapshot_id="turnover-110" if has_turnover else None,
        turnover_page_raw_references=("raw/turnover-110",) if has_turnover else (),
        turnover_covered_instrument_keys=(
            tuple(item.instrument_key for item in normalized) if has_turnover else ()
        ),
        instruments=normalized,
    )


def bundle(
    tmp_path,
    *,
    top_n: int = 0,
    fixed_pairs: tuple[str, ...] = ("BTC/USDT",),
    egresses: list[dict[str, object]] | None = None,
    date_gates_required: bool = False,
    date_gate_features: dict[str, dict[str, object]] | None = None,
    markets: tuple[str, ...] = ("spot",),
    deep_enabled: bool = True,
    symbols: dict[str, dict[str, object]] | None = None,
    market_symbols: dict[str, dict[str, dict[str, object]]] | None = None,
) -> ConfigBundle:
    source = deepcopy(BASE)
    source["selection"] = {
        "quote_assets": ["USDT"],
        "fixed_pairs": list(fixed_pairs),
        "top_n": top_n,
        "new_listings": {"enabled": False},
    }
    source["books"] = {
        "deep_snapshot": {
            "enabled": deep_enabled,
            "requested_interval": "1s",
        }
    }
    source["network"]["egress_pool"] = egresses or [
        {
            "id": "direct",
            "type": "direct",
            "quota_group": "direct",
            "max_http_concurrency": 2,
            "max_ws_connections": 1,
        }
    ]
    source["capabilities"] = {
        "date_gated_default_required": date_gates_required,
        "date_gated_features": {"okx": date_gate_features or {}},
    }
    source["exchanges"] = {
        "okx": {
            "markets": {
                market: (
                    {"symbols": market_symbols[market]}
                    if market_symbols is not None and market in market_symbols
                    else {"symbols": symbols}
                    if market == "spot" and symbols
                    else {}
                )
                for market in markets
            }
        }
    }
    return ConfigBundle(
        config=CollectorConfig.model_validate(
            source,
            context={"base_dir": tmp_path},
        ),
        capabilities=CapabilityRegistry.load_builtin(),
        config_sha256="c" * 64,
    )


def evidence(
    market_catalog: CatalogView | tuple[CatalogView, ...],
    *,
    reachable: tuple[str, ...] = ("direct",),
    endpoint_work: tuple[EndpointWork, ...] | None = None,
    endpoint_budgets: tuple[EndpointBudgetProbe, ...] | None = None,
    date_gates: tuple[DateGateProbe, ...] = (),
    subscriptions_per_connection: int = 10,
    observed_at_ns: int = 123,
    exchange_time_ns: int = 120,
) -> ExchangeProbeEvidence:
    catalogs: tuple[CatalogView, ...]
    if isinstance(market_catalog, tuple):
        catalogs = market_catalog
    else:
        catalogs = (market_catalog,)
    work = (
        endpoint_work
        if endpoint_work is not None
        else (
            EndpointWork(
                "deep_snapshot",
                Decimal(1),
                jobs_per_instrument=1,
                observed_at_ns=observed_at_ns,
                raw_reference="raw/okx/work/deep-snapshot",
            ),
        )
    )
    budgets = (
        endpoint_budgets
        if endpoint_budgets is not None
        else tuple(
            EndpointBudgetProbe(
                item,
                "deep_snapshot",
                Decimal(100),
                observed_at_ns=observed_at_ns,
                raw_reference=f"raw/okx/rate-limit/{item}/deep",
            )
            for item in reachable
        )
    )
    return ExchangeProbeEvidence(
        exchange=Exchange.OKX,
        public_time=PublicTimeProbe(
            exchange_time_ns=exchange_time_ns,
            observed_at_ns=observed_at_ns,
            raw_reference="raw/okx/time",
        ),
        egresses=tuple(
            EgressReachabilityProbe(
                egress_id=item,
                reachable=True,
                observed_at_ns=observed_at_ns,
                raw_reference=f"raw/okx/reachability/{item}",
            )
            for item in reachable
        ),
        markets=tuple(
            MarketProbeEvidence(
                catalog=item,
                subscriptions_per_connection=subscriptions_per_connection,
                subscriptions_per_instrument=1,
                endpoint_work=work,
            )
            for item in catalogs
        ),
        endpoint_budgets=budgets,
        date_gates=date_gates,
    )


@pytest.mark.asyncio
async def test_probe_engine_is_provider_neutral_and_timestamped(tmp_path) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path),
        providers={"okx": provider},
    )

    assert result.observed_at_ns == 123
    assert result.config_sha256 == "c" * 64
    assert result.failures == ()
    fixed = result.exchanges["okx"].markets["spot"].fixed
    assert fixed.instrument_keys == frozenset({"BTC-USDT"})
    assert provider.requests == [
        ProbeRequest(
            exchange=Exchange.OKX,
            markets=(CatalogScope("okx", "spot"),),
            egress_ids=("direct",),
            initial_lookback_ns={(Market.SPOT, None): 259_200_000_000_000},
            config_sha256="c" * 64,
            observed_at_ns=123,
        )
    ]


def test_probe_request_freezes_and_validates_initial_lookback_policy() -> None:
    source = {
        (Market.SPOT, "BTC-USDT"): 3_600_000_000_000,
        (Market.SPOT, None): 259_200_000_000_000,
    }
    request = ProbeRequest(
        exchange=Exchange.OKX,
        markets=(CatalogScope("okx", "spot"),),
        egress_ids=("direct",),
        initial_lookback_ns=source,
        config_sha256="c" * 64,
        observed_at_ns=123,
    )

    source[(Market.SPOT, None)] = 0
    assert request.initial_lookback_for(Market.SPOT, "ETH-USDT") == (
        259_200_000_000_000
    )
    assert request.initial_lookback_for(Market.SPOT, "BTC-USDT") == (3_600_000_000_000)
    with pytest.raises(TypeError):
        request.initial_lookback_ns[(Market.SPOT, None)] = 0  # type: ignore[index]

    with pytest.raises(ValueError, match="market-level fallback"):
        ProbeRequest(
            exchange=Exchange.OKX,
            markets=(CatalogScope("okx", "spot"),),
            egress_ids=("direct",),
            initial_lookback_ns={(Market.SPOT, "BTC-USDT"): 1},
            config_sha256="c" * 64,
            observed_at_ns=123,
        )
    with pytest.raises(TypeError, match="value must be an integer"):
        ProbeRequest(
            exchange=Exchange.OKX,
            markets=(CatalogScope("okx", "spot"),),
            egress_ids=("direct",),
            initial_lookback_ns={(Market.SPOT, None): True},  # type: ignore[dict-item]
            config_sha256="c" * 64,
            observed_at_ns=123,
        )


@pytest.mark.asyncio
async def test_probe_request_resolves_market_and_symbol_lookbacks(tmp_path) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))
    configured = bundle(
        tmp_path,
        market_symbols={
            "spot": {
                "BTC-USDT": {"selection": {"new_listings": {"initial_lookback": "1h"}}}
            }
        },
    )

    await ProbeEngine(clock=FakeClock()).run(
        configured,
        providers={"okx": provider},
    )

    assert dict(provider.requests[0].initial_lookback_ns) == {
        (Market.SPOT, None): 259_200_000_000_000,
        (Market.SPOT, "BTC-USDT"): 3_600_000_000_000,
    }


@pytest.mark.asyncio
async def test_probe_reports_missing_provider_instead_of_omitting_exchange(
    tmp_path,
) -> None:
    result = await ProbeEngine(clock=FakeClock()).run(bundle(tmp_path), providers={})

    assert result.exchanges == {}
    assert [(item.exchange.value, item.code) for item in result.failures] == [
        ("okx", "provider_unavailable")
    ]


@pytest.mark.asyncio
async def test_fixed_resolution_failure_is_scope_local_and_reported(tmp_path) -> None:
    ambiguous = catalog(
        replace(instrument("BTC-USDT-A"), canonical_pair="BTC/USDT"),
        replace(instrument("BTC-USDT-B"), canonical_pair="BTC/USDT"),
    )
    provider = FakeProvider(evidence(ambiguous))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path), providers={"okx": provider}
    )

    assert result.exchanges["okx"].markets == {}
    assert [(item.market, item.code) for item in result.failures] == [
        ("spot", "fixed_resolution")
    ]


@pytest.mark.asyncio
async def test_probe_composes_selection_capacity_sharding_and_interval(
    tmp_path,
) -> None:
    market_catalog = catalog(
        instrument("BTC-USDT", "100"),
        instrument("ETH-USDT", "90"),
        instrument("ALT-USDT", "80"),
    )
    endpoint = EndpointWork(
        logical_endpoint="deep_snapshot",
        cost=Decimal(1),
        jobs_per_instrument=1,
        observed_at_ns=123,
        raw_reference="raw/okx/work/deep-snapshot",
    )
    budget_probe = EndpointBudgetProbe(
        quota_group="direct",
        logical_endpoint="deep_snapshot",
        available_tokens_per_second=Decimal(1),
        observed_at_ns=123,
        raw_reference="raw/okx/rate-limit/deep",
    )
    provider = FakeProvider(
        evidence(
            market_catalog,
            endpoint_work=(endpoint,),
            endpoint_budgets=(budget_probe,),
            subscriptions_per_connection=2,
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, top_n=3), providers={"okx": provider}
    )

    market = result.exchanges["okx"].markets["spot"]
    assert market.selection.selected == frozenset({"BTC-USDT", "ETH-USDT", "ALT-USDT"})
    assert market.admission.admitted == ("BTC-USDT", "ETH-USDT")
    assert market.admission.rejected == ("ALT-USDT",)
    assert [(item.egress_id, item.instrument_keys) for item in market.shards] == [
        ("direct", ("BTC-USDT", "ETH-USDT"))
    ]
    assert market.intervals["deep_snapshot"].requested_ns == 1_000_000_000
    assert market.intervals["deep_snapshot"].effective_ns == 2_000_000_000


@pytest.mark.asyncio
async def test_market_report_preserves_complete_catalog_evidence(tmp_path) -> None:
    market_catalog = catalog(
        instrument("BTC-USDT", "100"),
        instrument("ETH-USDT", "90"),
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, top_n=0),
        providers={"okx": FakeProvider(evidence(market_catalog))},
    )

    market = result.exchanges["okx"].markets["spot"]
    assert market.catalog == market_catalog
    assert tuple(item.instrument_key for item in market.catalog.instruments) == (
        "BTC-USDT",
        "ETH-USDT",
    )
    assert market.catalog.catalog_snapshot_id == "catalog-100"
    assert market.catalog.catalog_page_raw_references == ("raw/catalog-100",)
    assert market.catalog.turnover_snapshot_id == "turnover-110"
    assert market.catalog.turnover_page_raw_references == ("raw/turnover-110",)
    assert "ETH-USDT" not in market.selection.entries


@pytest.mark.asyncio
async def test_shared_quota_group_rate_is_not_multiplied_by_egress_count(
    tmp_path,
) -> None:
    egresses = [
        {
            "id": "a",
            "type": "direct",
            "quota_group": "shared-nat",
            "max_http_concurrency": 1,
            "max_ws_connections": 1,
        },
        {
            "id": "b",
            "type": "direct",
            "quota_group": "shared-nat",
            "max_http_concurrency": 1,
            "max_ws_connections": 1,
        },
    ]
    endpoint = EndpointWork(
        "deep_snapshot",
        Decimal(1),
        jobs_per_instrument=1,
        observed_at_ns=123,
        raw_reference="raw/okx/work/deep-snapshot",
    )
    rate = EndpointBudgetProbe(
        "shared-nat",
        "deep_snapshot",
        Decimal(1),
        observed_at_ns=123,
        raw_reference="raw/shared/rate",
    )
    provider = FakeProvider(
        evidence(
            catalog(instrument("BTC-USDT", "10"), instrument("ETH-USDT", "9")),
            reachable=("a", "b"),
            endpoint_work=(endpoint,),
            endpoint_budgets=(rate,),
            subscriptions_per_connection=1,
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, top_n=2, egresses=egresses),
        providers={"okx": provider},
    )

    interval = result.exchanges["okx"].markets["spot"].intervals["deep_snapshot"]
    assert interval.effective_ns == 2_000_000_000


@pytest.mark.asyncio
async def test_explicit_required_date_gate_failure_is_explicit(tmp_path) -> None:
    provider = FakeProvider(
        evidence(
            catalog(instrument("BTC-USDT")),
            date_gates=(
                DateGateProbe(
                    feature_id="books_rpi",
                    available=False,
                    observed_at_ns=123,
                    raw_reference="raw/okx/books-rpi",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            date_gate_features={"books_rpi": {"required": True}},
        ),
        providers={"okx": provider},
    )

    assert [(item.code, item.feature_id) for item in result.failures] == [
        ("required_capability_unavailable", "books_rpi")
    ]
    assert provider.requests[0].date_gates == (
        DateGateRequest(
            feature_id="books_rpi",
            markets=(Market.SPOT,),
            required=True,
            available_from="2026-07-28",
            requires_live_probe=True,
        ),
    )


@pytest.mark.asyncio
async def test_explicit_optional_date_gate_is_disabled_when_unavailable(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            catalog(instrument("BTC-USDT")),
            date_gates=(
                DateGateProbe(
                    feature_id="books_rpi",
                    available=False,
                    observed_at_ns=123,
                    raw_reference="raw/okx/books-rpi",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            date_gates_required=True,
            date_gate_features={"books_rpi": {"required": False}},
        ),
        providers={"okx": provider},
    )

    exchange = result.exchanges["okx"]
    assert result.failures == ()
    assert exchange.disabled_optional_features == ("books_rpi",)
    assert result.capability_registry_sha256 == bundle(tmp_path).capabilities.sha256
    assert provider.requests[0].date_gates == (
        DateGateRequest(
            feature_id="books_rpi",
            markets=(Market.SPOT,),
            required=False,
            available_from="2026-07-28",
            requires_live_probe=True,
        ),
    )
    assert exchange.date_gate_requests == provider.requests[0].date_gates


@pytest.mark.asyncio
async def test_unrequested_date_gate_is_not_probed_or_evaluated(tmp_path) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, date_gates_required=True),
        providers={"okx": provider},
    )

    assert result.failures == ()
    assert result.exchanges["okx"].disabled_optional_features == ()
    assert provider.requests[0].date_gates == ()


@pytest.mark.asyncio
async def test_missing_requested_date_gate_evidence_is_provider_contract_error(
    tmp_path,
) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, date_gate_features={"books_rpi": {}}),
        providers={"okx": provider},
    )

    assert result.exchanges == {}
    assert [(item.code, item.message) for item in result.failures] == [
        ("provider_contract", "date-gate evidence does not match the request")
    ]


@pytest.mark.asyncio
async def test_unrequested_date_gate_evidence_is_provider_contract_error(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            catalog(instrument("BTC-USDT")),
            date_gates=(
                DateGateProbe(
                    feature_id="books_rpi",
                    available=False,
                    observed_at_ns=123,
                    raw_reference="raw/okx/books-rpi",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path),
        providers={"okx": provider},
    )

    assert result.exchanges == {}
    assert [(item.code, item.message) for item in result.failures] == [
        ("provider_contract", "date-gate evidence does not match the request")
    ]


@pytest.mark.asyncio
async def test_date_gate_requires_archived_date_and_live_probe(tmp_path) -> None:
    release_ns = 1_785_196_800 * 1_000_000_000

    async def run(exchange_time_ns: int):
        provider = FakeProvider(
            evidence(
                catalog(instrument("BTC-USDT")),
                date_gates=(
                    DateGateProbe(
                        feature_id="books_rpi",
                        available=True,
                        observed_at_ns=123,
                        raw_reference="raw/okx/books-rpi",
                    ),
                ),
                exchange_time_ns=exchange_time_ns,
            )
        )
        return await ProbeEngine(clock=FakeClock()).run(
            bundle(tmp_path, date_gate_features={"books_rpi": {}}),
            providers={"okx": provider},
        )

    before = await run(release_ns - 1)
    at_release = await run(release_ns)

    assert before.failures == ()
    assert before.exchanges["okx"].disabled_optional_features == ("books_rpi",)
    assert at_release.failures == ()
    assert at_release.exchanges["okx"].disabled_optional_features == ()


@pytest.mark.asyncio
async def test_missing_endpoint_budget_fails_market_without_guessing(tmp_path) -> None:
    provider = FakeProvider(
        evidence(
            catalog(instrument("BTC-USDT")),
            endpoint_work=(
                EndpointWork(
                    "deep_snapshot",
                    Decimal(1),
                    jobs_per_instrument=1,
                    observed_at_ns=123,
                    raw_reference="raw/okx/work/deep-snapshot",
                ),
            ),
            endpoint_budgets=(),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path), providers={"okx": provider}
    )

    assert result.exchanges["okx"].markets == {}
    assert [(item.market, item.code) for item in result.failures] == [
        ("spot", "endpoint_budget_unavailable")
    ]


@pytest.mark.asyncio
async def test_selection_uses_probe_completion_time_for_fresh_turnover(
    tmp_path,
) -> None:
    clock = FakeClock(100)
    fresh = instrument("BTC-USDT", "10")
    assert fresh.turnover is not None
    fresh = replace(
        fresh,
        turnover=replace(fresh.turnover, observed_at_ns=110),
        last_seen_ns=110,
    )
    provider = AdvancingProvider(
        evidence(catalog(fresh, observed_at_ns=110), observed_at_ns=110),
        clock=clock,
        completed_at_ns=120,
    )

    result = await ProbeEngine(clock=clock).run(
        bundle(tmp_path, fixed_pairs=(), top_n=1),
        providers={"okx": provider},
    )

    assert result.observed_at_ns == 120
    assert result.started_at_ns == 100
    assert result.exchanges["okx"].started_at_ns == 100
    assert result.exchanges["okx"].completed_at_ns == 120
    assert result.exchanges["okx"].markets["spot"].selection.selected == frozenset(
        {"BTC-USDT"}
    )


@pytest.mark.asyncio
async def test_ws_connection_capacity_is_shared_across_markets(tmp_path) -> None:
    provider = FakeProvider(
        evidence(
            (
                catalog(instrument("BTC-USDT", "10")),
                catalog(
                    instrument("BTC-USDT", "10", market="perpetual"),
                    market="perpetual",
                ),
            ),
            subscriptions_per_connection=1,
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=(),
            top_n=1,
            markets=("spot", "perpetual"),
        ),
        providers={"okx": provider},
    )

    reports = result.exchanges["okx"].markets.values()
    assert result.failures == ()
    assert sum(len(item.shards) for item in reports) == 1
    assert sum(len(item.admission.admitted) for item in reports) == 1


@pytest.mark.asyncio
async def test_ws_fail_policy_failure_is_market_local_and_reallocates(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            (
                catalog(instrument("BTC-USDT", "10")),
                catalog(
                    instrument("BTC-USDT", "10", market="perpetual"),
                    market="perpetual",
                ),
            ),
            subscriptions_per_connection=1,
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=(),
            top_n=1,
            markets=("spot", "perpetual"),
            symbols={"BTC-USDT": {"selection": {"capacity_policy": "fail"}}},
        ),
        providers={"okx": provider},
    )

    assert [(item.market, item.code) for item in result.failures] == [
        ("spot", "capacity")
    ]
    exchange = result.exchanges["okx"]
    assert set(exchange.markets) == {"perpetual"}
    assert exchange.markets["perpetual"].admission.admitted == ("BTC-USDT",)


@pytest.mark.asyncio
async def test_fixed_ws_overload_is_market_local_and_reallocates(tmp_path) -> None:
    provider = FakeProvider(
        evidence(
            (
                catalog(instrument("BTC-USDT", "10")),
                catalog(
                    instrument("BTC-USDT", "10", market="perpetual"),
                    market="perpetual",
                ),
            ),
            subscriptions_per_connection=1,
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, markets=("spot", "perpetual")),
        providers={"okx": provider},
    )

    assert [(item.market, item.code) for item in result.failures] == [
        ("spot", "capacity")
    ]
    exchange = result.exchanges["okx"]
    assert tuple(exchange.markets) == ("perpetual",)
    assert exchange.markets["perpetual"].admission.admitted == ("BTC-USDT",)


@pytest.mark.asyncio
async def test_connection_reservation_does_not_materialize_configured_capacity(
    tmp_path,
    monkeypatch,
) -> None:
    real_range = range

    def bounded_range(*args):  # type: ignore[no-untyped-def]
        value = real_range(*args)
        if len(value) > 1_000:
            raise AssertionError("configured connection range was materialized")
        return value

    monkeypatch.setattr(
        probe_contracts_module,
        "range",
        bounded_range,
        raising=False,
    )
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            egresses=[
                {
                    "id": "direct",
                    "type": "direct",
                    "quota_group": "direct",
                    "max_http_concurrency": 2,
                    "max_ws_connections": 10**12,
                }
            ],
        ),
        providers={"okx": provider},
    )

    assert result.failures == ()
    assert result.exchanges["okx"].markets["spot"].shards[0].index == 0


@pytest.mark.asyncio
async def test_endpoint_rate_is_shared_across_market_workloads(tmp_path) -> None:
    rate = EndpointBudgetProbe(
        "direct",
        "deep_snapshot",
        Decimal(1),
        observed_at_ns=123,
        raw_reference="raw/direct/deep-rate",
    )
    provider = FakeProvider(
        evidence(
            (
                catalog(instrument("BTC-USDT", "10")),
                catalog(
                    instrument("BTC-USDT", "10", market="perpetual"),
                    market="perpetual",
                ),
            ),
            endpoint_budgets=(rate,),
            subscriptions_per_connection=1,
        )
    )
    egresses = [
        {
            "id": "direct",
            "type": "direct",
            "quota_group": "direct",
            "max_http_concurrency": 2,
            "max_ws_connections": 2,
        }
    ]

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=(),
            top_n=1,
            markets=("spot", "perpetual"),
            egresses=egresses,
        ),
        providers={"okx": provider},
    )

    assert result.failures == ()
    assert {
        report.intervals["deep_snapshot"].effective_ns
        for report in result.exchanges["okx"].markets.values()
    } == {2_000_000_000}


@pytest.mark.asyncio
async def test_deep_rest_capacity_is_independent_of_ws_assignment(tmp_path) -> None:
    egresses = [
        {
            "id": "a",
            "type": "direct",
            "quota_group": "zero",
            "max_http_concurrency": 1,
            "max_ws_connections": 1,
        },
        {
            "id": "b",
            "type": "direct",
            "quota_group": "fast",
            "max_http_concurrency": 1,
            "max_ws_connections": 1,
        },
    ]
    budgets = (
        EndpointBudgetProbe(
            "zero",
            "deep_snapshot",
            Decimal(0),
            observed_at_ns=123,
            raw_reference="raw/zero/deep-rate",
        ),
        EndpointBudgetProbe(
            "fast",
            "deep_snapshot",
            Decimal(10),
            observed_at_ns=123,
            raw_reference="raw/fast/deep-rate",
        ),
    )
    provider = FakeProvider(
        evidence(
            catalog(instrument("ETH-USDT")),
            reachable=("a", "b"),
            endpoint_budgets=budgets,
            subscriptions_per_connection=1,
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, fixed_pairs=("ETH/USDT",), egresses=egresses),
        providers={"okx": provider},
    )

    market = result.exchanges["okx"].markets["spot"]
    assert result.failures == ()
    assert market.intervals["deep_snapshot"].effective_ns == 1_000_000_000


@pytest.mark.asyncio
async def test_enabled_deep_snapshot_requires_provider_workload(tmp_path) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT")), endpoint_work=()))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path), providers={"okx": provider}
    )

    assert result.exchanges["okx"].markets == {}
    assert [(item.market, item.code) for item in result.failures] == [
        ("spot", "endpoint_work_unavailable")
    ]


@pytest.mark.asyncio
async def test_disabled_deep_snapshot_ignores_deep_work_and_budget(tmp_path) -> None:
    provider = FakeProvider(
        evidence(
            catalog(instrument("BTC-USDT")),
            endpoint_budgets=(),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, deep_enabled=False), providers={"okx": provider}
    )

    assert result.failures == ()
    assert result.exchanges["okx"].markets["spot"].intervals == {}


@pytest.mark.asyncio
async def test_probe_report_preserves_endpoint_evidence(tmp_path) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path), providers={"okx": provider}
    )

    exchange = result.exchanges["okx"]
    assert exchange.endpoint_budgets == provider.evidence.endpoint_budgets
    assert exchange.markets["spot"].endpoint_work == (
        provider.evidence.markets[0].endpoint_work
    )


@pytest.mark.asyncio
async def test_market_report_rejects_mismatched_provenance_and_shards(
    tmp_path,
) -> None:
    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path),
        providers={"okx": FakeProvider(evidence(catalog(instrument("BTC-USDT"))))},
    )
    market = result.exchanges["okx"].markets["spot"]

    with pytest.raises(ValueError, match="catalog revision"):
        replace(
            market,
            catalog=replace(market.catalog, catalog_revision=2),
        )
    mismatched_state = replace(market.selection.next_state, policy_id="d" * 64)
    mismatched_selection = replace(
        market.selection,
        policy_id="d" * 64,
        next_state=mismatched_state,
    )
    with pytest.raises(ValueError, match="selection config SHA"):
        replace(market, selection=mismatched_selection)
    with pytest.raises(ValueError, match="config SHA"):
        replace(
            market,
            admission=replace(market.admission, config_sha256="d" * 64),
        )
    with pytest.raises(ValueError, match="shards"):
        replace(market, shards=())


class ExplodingIdentityProvider:
    @property
    def exchange(self) -> Exchange:
        raise RuntimeError("secret provider detail")

    async def probe(self, request: ProbeRequest) -> ExchangeProbeEvidence:
        raise AssertionError("probe must not be called")


class ExplodingProviderRegistry(dict[str, FakeProvider]):
    def get(self, key: str, default=None):  # type: ignore[no-untyped-def]
        raise RuntimeError("registry secret")


class ExplodingProbeProvider:
    exchange = Exchange.OKX

    async def probe(self, request: ProbeRequest) -> ExchangeProbeEvidence:
        error_type = type("API_KEY_12345", (RuntimeError,), {})
        raise error_type("secret provider detail")


@pytest.mark.asyncio
async def test_provider_identity_failure_is_exchange_local_and_secret_safe(
    tmp_path,
) -> None:
    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path),
        providers={"okx": ExplodingIdentityProvider()},  # type: ignore[dict-item]
    )

    assert result.exchanges == {}
    assert [(item.code, item.message) for item in result.failures] == [
        ("provider_error", "provider contract inspection failed")
    ]
    assert "secret" not in result.failures[0].message


@pytest.mark.asyncio
async def test_provider_registry_failure_is_exchange_local_and_secret_safe(
    tmp_path,
) -> None:
    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path),
        providers=ExplodingProviderRegistry(),
    )

    assert result.exchanges == {}
    assert [(item.code, item.message) for item in result.failures] == [
        ("provider_error", "provider registry lookup failed")
    ]


@pytest.mark.asyncio
async def test_provider_probe_failure_does_not_expose_exception_type(tmp_path) -> None:
    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path),
        providers={"okx": ExplodingProbeProvider()},
    )

    assert result.exchanges == {}
    assert [(item.code, item.message) for item in result.failures] == [
        ("provider_error", "provider probe failed")
    ]


@pytest.mark.asyncio
async def test_probe_rejects_evidence_observed_outside_request_window(tmp_path) -> None:
    clock = FakeClock(100)
    provider = AdvancingProvider(
        evidence(catalog(instrument("BTC-USDT")), observed_at_ns=123),
        clock=clock,
        completed_at_ns=120,
    )

    result = await ProbeEngine(clock=clock).run(
        bundle(tmp_path), providers={"okx": provider}
    )

    assert result.exchanges == {}
    assert [(item.code, item.message) for item in result.failures] == [
        ("provider_contract", "provider evidence is outside the probe time window")
    ]


@pytest.mark.asyncio
async def test_probe_rejects_stale_endpoint_work_evidence(tmp_path) -> None:
    provider = FakeProvider(
        evidence(
            catalog(instrument("BTC-USDT")),
            endpoint_work=(
                EndpointWork(
                    "deep_snapshot",
                    Decimal(1),
                    jobs_per_instrument=1,
                    observed_at_ns=122,
                    raw_reference="raw/okx/work/stale",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path), providers={"okx": provider}
    )

    assert result.exchanges == {}
    assert [(item.code, item.message) for item in result.failures] == [
        ("provider_contract", "provider evidence is outside the probe time window")
    ]


def test_provider_evidence_collections_are_canonicalized() -> None:
    work_a = EndpointWork(
        "a",
        Decimal(1),
        jobs_per_instrument=1,
        observed_at_ns=123,
        raw_reference="raw/okx/work/a",
    )
    work_z = EndpointWork(
        "z",
        Decimal(1),
        jobs_per_instrument=1,
        observed_at_ns=123,
        raw_reference="raw/okx/work/z",
    )
    spot = MarketProbeEvidence(
        catalog=catalog(instrument("BTC-USDT")),
        subscriptions_per_connection=1,
        subscriptions_per_instrument=1,
        endpoint_work=(work_z, work_a),
    )
    perpetual = MarketProbeEvidence(
        catalog=catalog(instrument("BTC-USDT", market="perpetual"), market="perpetual"),
        subscriptions_per_connection=1,
        subscriptions_per_instrument=1,
        endpoint_work=(work_z, work_a),
    )
    value = ExchangeProbeEvidence(
        exchange=Exchange.OKX,
        public_time=PublicTimeProbe(120, 123, "raw/time"),
        egresses=(
            EgressReachabilityProbe("z", True, 123, "raw/z"),
            EgressReachabilityProbe("a", True, 123, "raw/a"),
        ),
        markets=(spot, perpetual),
        endpoint_budgets=(
            EndpointBudgetProbe(
                "z", "z", Decimal(1), observed_at_ns=123, raw_reference="raw/zz"
            ),
            EndpointBudgetProbe(
                "a", "a", Decimal(1), observed_at_ns=123, raw_reference="raw/aa"
            ),
        ),
        date_gates=(
            DateGateProbe("z", True, 123, "raw/gate-z"),
            DateGateProbe("a", True, 123, "raw/gate-a"),
        ),
    )

    assert [item.logical_endpoint for item in spot.endpoint_work] == ["a", "z"]
    assert [item.egress_id for item in value.egresses] == ["a", "z"]
    assert [item.scope.market.value for item in value.markets] == ["perpetual", "spot"]
    assert [
        (item.quota_group, item.logical_endpoint) for item in value.endpoint_budgets
    ] == [
        ("a", "a"),
        ("z", "z"),
    ]
    assert [item.feature_id for item in value.date_gates] == ["a", "z"]


@pytest.mark.asyncio
async def test_disabled_fixed_symbol_is_an_explicit_probe_failure(tmp_path) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, symbols={"BTC-USDT": {"enabled": False}}),
        providers={"okx": provider},
    )

    assert result.exchanges["okx"].markets == {}
    assert [(item.market, item.code) for item in result.failures] == [
        ("spot", "fixed_disabled")
    ]


@pytest.mark.asyncio
async def test_disabled_dynamic_symbol_is_removed_before_top_n_ranking(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            catalog(
                instrument("BTC-USDT", "100"),
                instrument("ETH-USDT", "90"),
            )
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=(),
            top_n=1,
            symbols={"BTC-USDT": {"enabled": False}},
        ),
        providers={"okx": provider},
    )

    assert result.failures == ()
    assert result.exchanges["okx"].markets["spot"].selection.selected == frozenset(
        {"ETH-USDT"}
    )


@pytest.mark.asyncio
async def test_symbol_deep_snapshot_interval_override_is_applied(tmp_path) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            symbols={
                "BTC-USDT": {"books": {"deep_snapshot": {"requested_interval": "2s"}}}
            },
        ),
        providers={"okx": provider},
    )

    interval = result.exchanges["okx"].markets["spot"].intervals["deep_snapshot"]
    assert interval.requested_ns == 2_000_000_000
    assert interval.effective_ns == 2_000_000_000


def test_probe_report_rejects_mutable_failure_aliases() -> None:
    failures: list[ProbeFailure] = []
    with pytest.raises(TypeError, match="failures must be a tuple"):
        ProbeReport(
            observed_at_ns=1,
            started_at_ns=1,
            config_sha256="a" * 64,
            capability_registry_sha256="b" * 64,
            exchanges={},
            failures=failures,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_symbol_selection_policy_controls_its_own_top_n_membership(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            catalog(
                instrument("BTC-USDT", "100"),
                instrument("ETH-USDT", "90"),
            )
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=(),
            top_n=2,
            symbols={"BTC-USDT": {"selection": {"top_n": 0}}},
        ),
        providers={"okx": provider},
    )

    assert result.failures == ()
    assert result.exchanges["okx"].markets["spot"].selection.selected == frozenset(
        {"ETH-USDT"}
    )


@pytest.mark.asyncio
async def test_symbol_interval_overrides_form_distinct_auditable_cohorts(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(catalog(instrument("BTC-USDT"), instrument("ETH-USDT")))
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=("BTC/USDT", "ETH/USDT"),
            symbols={
                "ETH-USDT": {"books": {"deep_snapshot": {"requested_interval": "2s"}}}
            },
        ),
        providers={"okx": provider},
    )

    cohorts = result.exchanges["okx"].markets["spot"].interval_cohorts
    assert [item.instrument_keys for item in cohorts] == [
        ("BTC-USDT",),
        ("ETH-USDT",),
    ]
    assert [item.plan.requested_ns for item in cohorts] == [
        1_000_000_000,
        2_000_000_000,
    ]
    assert "deep_snapshot" not in result.exchanges["okx"].markets["spot"].intervals


@pytest.mark.asyncio
async def test_deep_workload_must_match_effective_symbol_depth(tmp_path) -> None:
    provider = FakeProvider(evidence(catalog(instrument("BTC-USDT"))))

    supported = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            symbols={"BTC-USDT": {"books": {"deep_snapshot": {"depth": 1000}}}},
        ),
        providers={"okx": provider},
    )

    cohort = supported.exchanges["okx"].markets["spot"].interval_cohorts[0]
    assert cohort.depth == 1000
    assert cohort.instrument_keys == ("BTC-USDT",)

    wrong_depth_work = EndpointWork(
        "deep_snapshot",
        Decimal(1),
        jobs_per_instrument=1,
        depth=500,
        observed_at_ns=123,
        raw_reference="raw/okx/work/depth-500",
    )
    failed = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            symbols={"BTC-USDT": {"books": {"deep_snapshot": {"depth": 1000}}}},
        ),
        providers={
            "okx": FakeProvider(
                evidence(
                    catalog(instrument("BTC-USDT")),
                    endpoint_work=(wrong_depth_work,),
                )
            )
        },
    )

    assert [(item.market, item.code) for item in failed.failures] == [
        ("spot", "endpoint_work_unavailable")
    ]

    depth_work = EndpointWork(
        "deep_snapshot",
        Decimal(1),
        jobs_per_instrument=1,
        depth=1000,
        observed_at_ns=123,
        raw_reference="raw/okx/work/depth-1000",
    )
    succeeded = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            symbols={"BTC-USDT": {"books": {"deep_snapshot": {"depth": 1000}}}},
        ),
        providers={
            "okx": FakeProvider(
                evidence(catalog(instrument("BTC-USDT")), endpoint_work=(depth_work,))
            )
        },
    )

    cohort = succeeded.exchanges["okx"].markets["spot"].interval_cohorts[0]
    assert cohort.depth == 1000
    assert cohort.instrument_keys == ("BTC-USDT",)


@pytest.mark.asyncio
async def test_deep_workload_is_required_only_after_capacity_admission(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            catalog(
                instrument("BTC-USDT", "10"),
                instrument("ETH-USDT", "100"),
            ),
            subscriptions_per_connection=1,
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            top_n=1,
            symbols={"ETH-USDT": {"books": {"deep_snapshot": {"depth": 1000}}}},
        ),
        providers={"okx": provider},
    )

    market = result.exchanges["okx"].markets["spot"]
    assert result.failures == ()
    assert market.admission.admitted == ("BTC-USDT",)
    assert market.admission.rejected == ("ETH-USDT",)


@pytest.mark.asyncio
async def test_interval_failure_recomputes_unaffected_market_reports(tmp_path) -> None:
    base = evidence(
        (
            catalog(instrument("BTC-USDT", "10")),
            catalog(
                instrument("BTC-USDT", "10", market="perpetual"),
                market="perpetual",
            ),
        ),
        endpoint_budgets=(
            EndpointBudgetProbe(
                "direct",
                "z_good",
                Decimal(10),
                observed_at_ns=123,
                raw_reference="raw/direct/z-good",
            ),
        ),
    )
    provider = FakeProvider(
        replace(
            base,
            markets=(
                replace(
                    base.markets[1],
                    endpoint_work=(
                        EndpointWork(
                            "z_good",
                            Decimal(1),
                            jobs_per_instrument=1,
                            observed_at_ns=123,
                            raw_reference="raw/okx/work/z-good",
                        ),
                    ),
                ),
                replace(
                    base.markets[0],
                    endpoint_work=(
                        EndpointWork(
                            "a_missing",
                            Decimal(1),
                            jobs_per_instrument=1,
                            observed_at_ns=123,
                            raw_reference="raw/okx/work/a-missing",
                        ),
                    ),
                ),
            ),
        )
    )
    egresses = [
        {
            "id": "direct",
            "type": "direct",
            "quota_group": "direct",
            "max_http_concurrency": 2,
            "max_ws_connections": 1,
        }
    ]

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=(),
            top_n=1,
            markets=("spot", "perpetual"),
            egresses=egresses,
        ),
        providers={"okx": provider},
    )

    exchange = result.exchanges["okx"]
    assert [(item.market, item.code) for item in result.failures] == [
        ("perpetual", "endpoint_budget_unavailable")
    ]
    assert set(exchange.markets) == {"spot"}
    assert {item.scope.market for item in exchange.market_evidence} == {
        Market.SPOT,
        Market.PERPETUAL,
    }
    failed_evidence = next(
        item
        for item in exchange.market_evidence
        if item.scope.market is Market.PERPETUAL
    )
    assert failed_evidence.catalog.catalog_page_raw_references == ("raw/catalog-100",)
    assert failed_evidence.endpoint_work[0].logical_endpoint == "a_missing"
    assert exchange.markets["spot"].admission.admitted == ("BTC-USDT",)
    assert exchange.markets["spot"].intervals["z_good"].effective_ns == (1_000_000_000)


@pytest.mark.asyncio
async def test_market_failure_clears_stale_rest_rejections_before_recompute(
    tmp_path,
) -> None:
    base = evidence(
        (
            catalog(
                instrument("BTC-USDT", "10"),
                instrument("ETH-USDT", "100"),
            ),
            catalog(
                instrument("SOL-USDT", "100", market="perpetual"),
                market="perpetual",
            ),
        ),
        endpoint_budgets=(
            EndpointBudgetProbe(
                "direct",
                "a_shared",
                Decimal("0.0025"),
                observed_at_ns=123,
                raw_reference="raw/direct/a-shared",
            ),
        ),
    )
    by_market = {item.scope.market: item for item in base.markets}
    spot = replace(
        by_market[Market.SPOT],
        endpoint_work=(
            EndpointWork(
                "a_shared",
                Decimal(1),
                jobs_per_instrument=1,
                observed_at_ns=123,
                raw_reference="raw/okx/work/a-shared/spot",
            ),
        ),
    )
    perpetual = replace(
        by_market[Market.PERPETUAL],
        endpoint_work=(
            EndpointWork(
                "a_shared",
                Decimal(1),
                jobs_per_instrument=1,
                observed_at_ns=123,
                raw_reference="raw/okx/work/a-shared/perpetual",
            ),
            EndpointWork(
                "z_missing",
                Decimal(1),
                jobs_per_instrument=1,
                observed_at_ns=123,
                raw_reference="raw/okx/work/z-missing",
            ),
        ),
    )
    provider = FakeProvider(replace(base, markets=(spot, perpetual)))

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=(),
            top_n=2,
            markets=("spot", "perpetual"),
            egresses=[
                {
                    "id": "direct",
                    "type": "direct",
                    "quota_group": "direct",
                    "max_http_concurrency": 2,
                    "max_ws_connections": 2,
                }
            ],
            market_symbols={
                "spot": {
                    "BTC-USDT": {
                        "books": {"deep_snapshot": {"requested_interval": "800s"}}
                    },
                    "ETH-USDT": {
                        "books": {"deep_snapshot": {"requested_interval": "800s"}}
                    },
                },
                "perpetual": {"SOL-USDT": {"selection": {"capacity_policy": "fail"}}},
            },
        ),
        providers={"okx": provider},
    )

    assert [(item.market, item.code) for item in result.failures] == [
        ("perpetual", "endpoint_budget_unavailable")
    ]
    spot_report = result.exchanges["okx"].markets["spot"]
    assert spot_report.rest_rejections == ()
    assert spot_report.admission.admitted == ("ETH-USDT", "BTC-USDT")


@pytest.mark.asyncio
async def test_flexible_rejection_records_remaining_endpoint_rate(tmp_path) -> None:
    provider = FakeProvider(
        evidence(
            catalog(
                instrument("BTC-USDT", "10"),
                instrument("ETH-USDT", "100"),
            ),
            endpoint_budgets=(
                EndpointBudgetProbe(
                    "direct",
                    "deep_snapshot",
                    Decimal(1),
                    observed_at_ns=123,
                    raw_reference="raw/direct/deep-reserved",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            top_n=1,
            symbols={
                "BTC-USDT": {"books": {"deep_snapshot": {"overload_policy": "fail"}}}
            },
        ),
        providers={"okx": provider},
    )

    rejection = result.exchanges["okx"].markets["spot"].rest_rejections[0]
    assert rejection.reason == "zero_rate"
    assert (
        rejection.available_rate_numerator,
        rejection.available_rate_denominator,
    ) == (0, 1)
    assert (
        rejection.required_rate_numerator,
        rejection.required_rate_denominator,
    ) == (1, 1)


@pytest.mark.asyncio
async def test_rest_capacity_evicts_top_n_before_failing_fixed_workload(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            catalog(
                instrument("BTC-USDT", "10"),
                instrument("ETH-USDT", "100"),
            ),
            endpoint_budgets=(
                EndpointBudgetProbe(
                    "direct",
                    "deep_snapshot",
                    Decimal("0.00200000000000000001"),
                    observed_at_ns=123,
                    raw_reference="raw/direct/deep-slow",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(tmp_path, top_n=1),
        providers={"okx": provider},
    )

    market = result.exchanges["okx"].markets["spot"]
    assert result.failures == ()
    assert market.admission.admitted == ("BTC-USDT",)
    assert market.admission.rejected == ()
    rejection = market.rest_rejections[0]
    assert rejection.instrument_key == "ETH-USDT"
    assert rejection.logical_endpoint == "deep_snapshot"
    assert (
        rejection.available_rate_numerator,
        rejection.available_rate_denominator,
    ) == (
        200_000_000_000_000_001,
        100_000_000_000_000_000_000,
    )
    assert (rejection.required_rate_numerator, rejection.required_rate_denominator) == (
        2,
        1,
    )
    assert rejection.requested_interval_ns == 1_000_000_000
    assert rejection.max_effective_ns == 900_000_000_000
    assert rejection.config_sha256 == "c" * 64
    assert market.intervals["deep_snapshot"].effective_ns == 500_000_000_000
    assert market.intervals["deep_snapshot"].warning is not None


@pytest.mark.asyncio
async def test_fail_cadence_is_reserved_before_stretching_flexible_cohort(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            catalog(instrument("BTC-USDT"), instrument("ETH-USDT")),
            endpoint_budgets=(
                EndpointBudgetProbe(
                    "direct",
                    "deep_snapshot",
                    Decimal("1.5"),
                    observed_at_ns=123,
                    raw_reference="raw/direct/deep-mixed",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            fixed_pairs=("BTC/USDT", "ETH/USDT"),
            symbols={
                "BTC-USDT": {"books": {"deep_snapshot": {"overload_policy": "fail"}}}
            },
        ),
        providers={"okx": provider},
    )

    market = result.exchanges["okx"].markets["spot"]
    assert result.failures == ()
    assert market.rest_rejections == ()
    plans = {
        item.instrument_keys: item.plan.effective_ns for item in market.interval_cohorts
    }
    assert plans == {
        ("BTC-USDT",): 1_000_000_000,
        ("ETH-USDT",): 2_000_000_000,
    }


@pytest.mark.asyncio
async def test_rest_reduction_can_evict_competing_cohort_causing_max_breach(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            catalog(
                instrument("BTC-USDT", "10"),
                instrument("ETH-USDT", "100"),
            ),
            endpoint_budgets=(
                EndpointBudgetProbe(
                    "direct",
                    "deep_snapshot",
                    Decimal("0.8"),
                    observed_at_ns=123,
                    raw_reference="raw/direct/deep-competing",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            top_n=1,
            symbols={
                "BTC-USDT": {"books": {"deep_snapshot": {"requested_interval": "800s"}}}
            },
        ),
        providers={"okx": provider},
    )

    market = result.exchanges["okx"].markets["spot"]
    assert result.failures == ()
    assert market.admission.admitted == ("BTC-USDT",)
    assert [item.instrument_key for item in market.rest_rejections] == ["ETH-USDT"]
    assert market.interval_cohorts[0].plan.effective_ns == 800_000_000_000


@pytest.mark.asyncio
async def test_rest_max_failure_is_market_local_after_competitor_search(
    tmp_path,
) -> None:
    provider = FakeProvider(
        evidence(
            (
                catalog(instrument("BTC-USDT", "10")),
                catalog(
                    instrument("BTC-USDT", "10", market="perpetual"),
                    market="perpetual",
                ),
            ),
            endpoint_budgets=(
                EndpointBudgetProbe(
                    "direct",
                    "deep_snapshot",
                    Decimal("0.8"),
                    observed_at_ns=123,
                    raw_reference="raw/direct/deep-market-local",
                ),
            ),
        )
    )

    result = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            markets=("spot", "perpetual"),
            egresses=[
                {
                    "id": "direct",
                    "type": "direct",
                    "quota_group": "direct",
                    "max_http_concurrency": 2,
                    "max_ws_connections": 2,
                }
            ],
            symbols={
                "BTC-USDT": {"books": {"deep_snapshot": {"requested_interval": "800s"}}}
            },
        ),
        providers={"okx": provider},
    )

    assert [(item.market, item.code) for item in result.failures] == [
        ("spot", "capacity")
    ]
    exchange = result.exchanges["okx"]
    assert tuple(exchange.markets) == ("perpetual",)
    assert (
        exchange.markets["perpetual"].intervals["deep_snapshot"].effective_ns
        == 1_250_000_000
    )


def test_endpoint_work_rejects_unknown_kind_and_zero_jobs() -> None:
    with pytest.raises(ValueError, match="kind"):
        EndpointWork(
            "depth",
            Decimal(1),
            jobs_per_instrument=1,
            kind="reference",  # type: ignore[arg-type]
            observed_at_ns=123,
            raw_reference="raw/okx/work/invalid-kind",
        )
    with pytest.raises(ValueError, match="positive"):
        EndpointWork(
            "depth",
            Decimal(1),
            jobs_per_instrument=0,
            observed_at_ns=123,
            raw_reference="raw/okx/work/invalid-jobs",
        )
    with pytest.raises(ValueError, match="raw_reference"):
        EndpointWork(
            "depth",
            Decimal(1),
            jobs_per_instrument=1,
            observed_at_ns=123,
            raw_reference="",
        )


@pytest.mark.asyncio
async def test_periodic_reference_work_is_capacity_planned_and_stretched(
    tmp_path,
) -> None:
    periodic_work = (
        EndpointWork(
            "candles",
            Decimal(1),
            kind="periodic_reference",
            jobs_per_instrument=1,
            requested_interval_ns=1_000_000_000,
            observed_at_ns=123,
            raw_reference="raw/okx/work/candles",
        ),
        EndpointWork(
            "instruments",
            Decimal(1),
            kind="periodic_reference",
            jobs_per_instrument=0,
            jobs_per_market=1,
            requested_interval_ns=300_000_000_000,
            observed_at_ns=123,
            raw_reference="raw/okx/work/instruments",
        ),
    )
    budgets = tuple(
        EndpointBudgetProbe(
            "direct",
            endpoint,
            Decimal(rate),
            observed_at_ns=123,
            raw_reference=f"raw/okx/rate-limit/{endpoint}",
        )
        for endpoint, rate in (("candles", 1), ("instruments", 10))
    )
    provider = FakeProvider(
        evidence(
            catalog(
                instrument("BTC-USDT", "2"),
                instrument("ETH-USDT", "1"),
            ),
            endpoint_work=periodic_work,
            endpoint_budgets=budgets,
        )
    )

    report = await ProbeEngine(clock=FakeClock()).run(
        bundle(
            tmp_path,
            top_n=2,
            fixed_pairs=(),
            deep_enabled=False,
        ),
        providers={"okx": provider},
    )

    assert report.success is True
    market = report.exchanges["okx"].markets["spot"]
    assert market.intervals["candles"].requested_ns == 1_000_000_000
    assert market.intervals["candles"].effective_ns == 2_000_000_000
    assert market.intervals["candles"].warning is not None
    cohorts = {item.logical_endpoint: item for item in market.interval_cohorts}
    assert cohorts["candles"].depth is None
    assert cohorts["candles"].instrument_keys == ("BTC-USDT", "ETH-USDT")
    assert cohorts["instruments"].instrument_keys == ()


def test_date_gate_without_archived_date_has_no_date_constraint() -> None:
    request = DateGateRequest(
        feature_id="live_only",
        markets=(Market.SPOT,),
        required=False,
        available_from=None,
        requires_live_probe=True,
    )

    assert request.archived_available_at(0) is True
