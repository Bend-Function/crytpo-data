# Remaining Exchange Connectors Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Binance, Bybit, Bitget, and Kraken public Spot/perpetual adapters to the frozen OKX-tested contract without sharing venue-specific book assumptions.

**Architecture:** Each venue owns catalog, REST, WebSocket, error, and book modules plus exact-byte fixtures. The four venue tasks may execute in parallel because they modify separate packages; registry/conformance and live-matrix tasks run only after all four pass review.

**Tech Stack:** Python 3.11+, HTTPX, websockets, Decimal-aware JSON, pytest contract/protocol/integration fixtures, Hypothesis.

---

## Mandatory Evidence Preflight

Before Step 1 of each venue task, re-fetch every official URL listed in that venue's provenance index into temporary files, verify status/content type/non-empty venue markers, replace the corresponding archived files only after all downloads succeed, and update retrieval time plus SHA-256 values. The exact owned roots are `docs/exchanges/binance/`, `docs/exchanges/bybit/`, `docs/exchanges/bitget/`, and `docs/exchanges/kraken/`; each venue commit includes its refreshed index and referenced `sources/` files. Review endpoint, rate-limit, auth, channel, sequence/checksum, and changelog diffs. If an official contract changed, amend the design and affected tests before connector code. A missing/unverifiable source blocks that venue task but not independent venue tasks.

Run after each refresh: `shasum -a 256 docs/exchanges/<venue>/sources/*`

Expected: every digest matches that venue's updated provenance index; implementation fixtures cite one of those refreshed sources and its digest.

## Mandatory Book Property Gate

Each venue task creates and runs `tests/property/exchanges/<venue>/test_book.py` with Hypothesis. The venue-specific strategy must generate an authoritative snapshot, a non-empty legal update chain, legal reset/heartbeat forms where documented, and one minimally mutated sequence/checksum link. For every generated case assert: legal chains preserve the venue's declared integrity level; a true gap/checksum/regression makes the current connection generation invalid with the documented recovery action; no later ordinary delta can silently restore validity; only a new authoritative snapshot/reset starts valid state; Decimal/string book semantics never pass through binary float; and applying the same generated messages twice produces the same outcomes. Protocol examples alone do not satisfy this gate, and these property tests run in the normal offline suite rather than a quarantined fuzz job.

---

### Task 1: Binance Spot and USD-M Perpetual

**Files:**
- Modify: `docs/exchanges/binance/README.md`
- Modify: `docs/exchanges/binance/sources/`
- Create: `src/crypto_collector/exchanges/binance/__init__.py`
- Create: `src/crypto_collector/exchanges/binance/adapter.py`
- Create: `src/crypto_collector/exchanges/binance/catalog.py`
- Create: `src/crypto_collector/exchanges/binance/rest.py`
- Create: `src/crypto_collector/exchanges/binance/ws.py`
- Create: `src/crypto_collector/exchanges/binance/book.py`
- Create: `src/crypto_collector/exchanges/binance/errors.py`
- Create: `tests/fixtures/exchanges/binance/manifest.json`
- Create: `tests/fixtures/exchanges/binance/spot-exchange-info.json`
- Create: `tests/fixtures/exchanges/binance/futures-exchange-info.json`
- Create: `tests/fixtures/exchanges/binance/spot-depth.json`
- Create: `tests/fixtures/exchanges/binance/futures-depth.json`
- Create: `tests/fixtures/exchanges/binance/ws-session.json`
- Test: `tests/contract/exchanges/binance/test_catalog.py`
- Test: `tests/contract/exchanges/binance/test_rest.py`
- Test: `tests/protocol/exchanges/binance/test_book.py`
- Test: `tests/property/exchanges/binance/test_book.py`
- Test: `tests/integration/exchanges/test_binance_session.py`

- [ ] **Step 1: Write failing route, bootstrap, and continuity tests**

```python
def test_futures_routes_public_book_separately_from_market_streams() -> None:
    plan = BinanceAdapter().plan(futures_request("BTCUSDT"))
    assert plan.ws.first(stream="book_live").url_path.startswith("/public/")
    assert plan.ws.first(stream="trade").url_path.startswith("/market/")


def test_spot_bootstrap_accepts_covering_first_event() -> None:
    state = BinanceSpotBookBootstrap(snapshot_last_update_id=100)
    assert state.apply(diff(U=99, u=101)).integrity is BookIntegrity.SEQUENCE_VERIFIED
    assert state.apply(diff(U=102, u=103)).integrity is BookIntegrity.SEQUENCE_VERIFIED


def test_spot_gap_invalidates_generation() -> None:
    state = seeded_spot_book(last_u=101)
    outcome = state.apply(diff(U=103, u=104))
    assert outcome.integrity is BookIntegrity.INVALID
    assert outcome.action is BookAction.FETCH_BOOTSTRAP


def test_futures_requires_previous_u_link() -> None:
    state = seeded_futures_book(last_u=200)
    assert state.apply(diff(U=201, u=202, pu=200)).integrity is BookIntegrity.SEQUENCE_VERIFIED
    assert state.apply(diff(U=203, u=204, pu=199)).integrity is BookIntegrity.INVALID


def test_bootstrap_and_ws_share_generation_egress() -> None:
    plan = BinanceAdapter().plan(spot_request("BTCUSDT", assigned_egress="socks-a"))
    bootstrap = plan.rest.first(stream="book_live_bootstrap")
    websocket = plan.ws.first(stream="book_live")
    assert bootstrap.egress_id == websocket.egress_id == "socks-a"
    assert bootstrap.connection_generation == websocket.connection_generation
```

- [ ] **Step 2: Run and verify Binance modules are missing**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/binance tests/protocol/exchanges/binance tests/property/exchanges/binance tests/integration/exchanges/test_binance_session.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement Binance contracts from archived evidence**

Implement Spot `/api/v3` and USD-M `/fapi` public catalogs, ticker/BBO, trade, 1m candle, deep book, premium/mark/index/funding/OI/reference data, and public status/contract changes where available. Filter USD-M catalog by `PERPETUAL`, trading state, USDT settlement, and post-merger UM indicators rather than host alone. Futures WebSocket URLs always use explicit `/market` or `/public`; rotate Spot/Futures generations before their documented 24-hour limit.

Spot diff buffering/bootstrap follows `U/u`; Futures follows `U/u` bootstrap then `pu == previous u`. A bootstrap belongs only to its generation and sticky egress. Store Binance liquidation as `coverage="lossy_window"`. Feed endpoint weights and live `exchangeInfo.rateLimits` into the scheduler; Top-20 5000-level Spot snapshots at 30s must stretch because their depth weight alone exceeds the archived minute budget.

- [ ] **Step 4: Run Binance fixture and scripted-session tests**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/binance tests/protocol/exchanges/binance tests/property/exchanges/binance tests/integration/exchanges/test_binance_session.py -q`

Expected: PASS, including 429/418, `Retry-After`, 24-hour planned rotation, unknown catalog status, and bootstrap generation replacement.

- [ ] **Step 5: Commit**

```bash
git add docs/exchanges/binance src/crypto_collector/exchanges/binance tests/fixtures/exchanges/binance tests/contract/exchanges/binance tests/protocol/exchanges/binance tests/property/exchanges/binance tests/integration/exchanges/test_binance_session.py
git commit -m "feat: add binance public connector"
```

### Task 2: Bybit Spot and Linear Perpetual

**Files:**
- Modify: `docs/exchanges/bybit/README.md`
- Modify: `docs/exchanges/bybit/sources/`
- Create: `src/crypto_collector/exchanges/bybit/__init__.py`
- Create: `src/crypto_collector/exchanges/bybit/adapter.py`
- Create: `src/crypto_collector/exchanges/bybit/catalog.py`
- Create: `src/crypto_collector/exchanges/bybit/rest.py`
- Create: `src/crypto_collector/exchanges/bybit/ws.py`
- Create: `src/crypto_collector/exchanges/bybit/book.py`
- Create: `src/crypto_collector/exchanges/bybit/errors.py`
- Create: `tests/fixtures/exchanges/bybit/manifest.json`
- Create: `tests/fixtures/exchanges/bybit/spot-instruments.json`
- Create: `tests/fixtures/exchanges/bybit/linear-instruments.json`
- Create: `tests/fixtures/exchanges/bybit/standard-book.json`
- Create: `tests/fixtures/exchanges/bybit/full-book.json`
- Create: `tests/fixtures/exchanges/bybit/ticker.json`
- Test: `tests/contract/exchanges/bybit/test_catalog.py`
- Test: `tests/contract/exchanges/bybit/test_rest.py`
- Test: `tests/protocol/exchanges/bybit/test_book.py`
- Test: `tests/property/exchanges/bybit/test_book.py`
- Test: `tests/integration/exchanges/test_bybit_session.py`

- [ ] **Step 1: Write failing pagination, path, and depth-mode tests**

```python
def test_linear_catalog_follows_cursor_pagination(scripted_http) -> None:
    catalog = fetch_all_instruments(scripted_http, category="linear")
    assert scripted_http.request_cursors == [None, "page-2"]
    assert catalog.by_key("BTCUSDT").market is Market.PERPETUAL


def test_current_public_paths_are_case_sensitive() -> None:
    assert BybitEndpoints.PRICE_LIMIT == "/v5/market/price-limit"
    assert BybitEndpoints.ADL_ALERT == "/v5/market/adlAlert"


def test_standard_snapshot_and_delta_do_not_invent_u_plus_one_rule() -> None:
    state = BybitStandardBook()
    state.apply(standard_snapshot(u=100, seq=500))
    outcome = state.apply(standard_delta(u=150, seq=501))
    assert outcome.integrity is BookIntegrity.SNAPSHOT_CHAIN


def test_full_book_requires_date_gate_and_successful_live_probe() -> None:
    optional = plan_full_book(
        market="perpetual", date_gate=True, live_probe=False, required=False)
    assert optional.disabled_reason == "live_probe_failed"
    with pytest.raises(CapabilityError):
        plan_full_book(market="perpetual", date_gate=True, live_probe=False, required=True)
    assert plan_full_book(market="spot", date_gate=True, live_probe=True).requires_rest_bootstrap


def test_sparse_ticker_does_not_fill_absent_fields_with_zero() -> None:
    parsed = parse_ticker({"symbol": "BTCUSDT", "lastPrice": "1"})
    assert parsed.payload.get("openInterest") is None
    assert "openInterest" not in parsed.payload
```

- [ ] **Step 2: Run and verify Bybit modules are missing**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/bybit tests/protocol/exchanges/bybit tests/property/exchanges/bybit tests/integration/exchanges/test_bybit_session.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement standard depth by default and probe-gated full depth**

Implement `/v5/market` catalogs, tickers, recent trades, candles, standard/deep/full order books, mark/index/premium, funding, OI, price-limit, risk/ADL/insurance/index-component data, public system status, and `allLiquidation`. Follow cursor pagination. Standard Spot/linear depth 200 is the default and starts from its own WS snapshot; use documented snapshot/reset/update semantics without imposing `u+1` where the standard feed does not promise it.

Full book is a distinct date-gated channel, disabled and optional by default. Enable only for supported markets after both the archived date gate and live capability probe; a failed optional request is disabled with warning/control evidence, while `required: true` fails probe/start/reload. Buffer deltas and use its generation/egress-affine REST bootstrap. On the research date perpetual full book remains disabled. Never use full/deep REST to enlarge standard live depth. Preserve sparse derivative ticker fields exactly and classify JSON `retCode` even under HTTP 200.

- [ ] **Step 4: Run Bybit contract/protocol/session tests**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/bybit tests/protocol/exchanges/bybit tests/property/exchanges/bybit tests/integration/exchanges/test_bybit_session.py -q`

Expected: PASS, including reset snapshot, optional-field drift, `allLiquidation`, 429/business throttle, and disabled unsupported full perpetual depth.

- [ ] **Step 5: Commit**

```bash
git add docs/exchanges/bybit src/crypto_collector/exchanges/bybit tests/fixtures/exchanges/bybit tests/contract/exchanges/bybit tests/protocol/exchanges/bybit tests/property/exchanges/bybit tests/integration/exchanges/test_bybit_session.py
git commit -m "feat: add bybit public connector"
```

### Task 3: Bitget UTA v3 Spot and USDT Futures

**Files:**
- Modify: `docs/exchanges/bitget/index.md`
- Modify: `docs/exchanges/bitget/sources/`
- Create: `src/crypto_collector/exchanges/bitget/__init__.py`
- Create: `src/crypto_collector/exchanges/bitget/adapter.py`
- Create: `src/crypto_collector/exchanges/bitget/catalog.py`
- Create: `src/crypto_collector/exchanges/bitget/rest.py`
- Create: `src/crypto_collector/exchanges/bitget/ws.py`
- Create: `src/crypto_collector/exchanges/bitget/book.py`
- Create: `src/crypto_collector/exchanges/bitget/errors.py`
- Create: `tests/fixtures/exchanges/bitget/manifest.json`
- Create: `tests/fixtures/exchanges/bitget/spot-instruments.json`
- Create: `tests/fixtures/exchanges/bitget/futures-instruments.json`
- Create: `tests/fixtures/exchanges/bitget/book-snapshot.json`
- Create: `tests/fixtures/exchanges/bitget/book-first-update.json`
- Create: `tests/fixtures/exchanges/bitget/book-update.json`
- Test: `tests/contract/exchanges/bitget/test_catalog.py`
- Test: `tests/contract/exchanges/bitget/test_rest.py`
- Test: `tests/protocol/exchanges/bitget/test_book.py`
- Test: `tests/property/exchanges/bitget/test_book.py`
- Test: `tests/integration/exchanges/test_bitget_session.py`

- [ ] **Step 1: Write failing path, casing, heartbeat, and pseq tests**

```python
def test_uta_v3_instruments_path_and_categories_are_exact() -> None:
    assert BitgetEndpoints.INSTRUMENTS == "/api/v3/market/instruments"
    assert request_category(Market.SPOT) == "SPOT"
    assert request_category(Market.PERPETUAL) == "USDT-FUTURES"


def test_initial_snapshot_may_legitimately_have_pseq_zero() -> None:
    state = BitgetBook()
    outcome = state.apply(snapshot(seq=100, pseq=0, bids=[["10", "1"]]))
    assert outcome.integrity is BookIntegrity.SNAPSHOT_CHAIN


def test_first_update_must_overlap_snapshot_range() -> None:
    state = seeded_bitget_snapshot(seq=100)
    assert state.apply(update(pseq=99, seq=101)).integrity is BookIntegrity.SEQUENCE_VERIFIED
    assert seeded_bitget_snapshot(seq=100).apply(update(pseq=101, seq=102)).integrity is BookIntegrity.INVALID


def test_later_update_requires_pseq_chain_and_zero_means_reset() -> None:
    state = seeded_bitget_updates(last_seq=101)
    assert state.apply(update(pseq=101, seq=102)).integrity is BookIntegrity.SEQUENCE_VERIFIED
    assert state.apply(update(pseq=0, seq=1)).action is BookAction.RESUBSCRIBE


@pytest.mark.asyncio
async def test_literal_ping_requires_literal_pong(scripted_ws) -> None:
    connection = BitgetConnection(scripted_ws)
    await connection.send_heartbeat()
    assert scripted_ws.sent[-1] == "ping"
    scripted_ws.feed("pong")
    assert await connection.wait_for_pong(timeout=1)
```

- [ ] **Step 2: Run and verify Bitget modules are missing**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/bitget tests/protocol/exchanges/bitget tests/property/exchanges/bitget tests/integration/exchanges/test_bitget_session.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement UTA v3 without mixing Classic v2**

Implement UTA v3 catalog, tickers, trades/fills, candles, REST deep book, funding/OI/index components, liquidation history, and public WS ticker/trades/candles/books/liquidation. Preserve UTA category casing and JSON business codes. Use symbol `maxDepth` to validate live selection and a separate maximum-1000 REST deep snapshot.

For `books`, accept initial snapshot `pseq=0`; require first update overlap and later `pseq == previous seq`; only an update/reset in an established chain treats `pseq=0` as reset. The archived material does not prove zero-quantity deletion semantics, so raw collection and chain integrity proceed, but `book_live_features` capability remains disabled until an exact captured fixture and source/probe demonstrate deletion behavior. Do not hardcode a forced 24-hour connection lifetime that the versioned UTA evidence does not substantiate; support ordinary planned/admin reconnect independently.

- [ ] **Step 4: Run Bitget contract/protocol/session tests**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/bitget tests/protocol/exchanges/bitget tests/property/exchanges/bitget tests/integration/exchanges/test_bitget_session.py -q`

Expected: PASS, including 404 rejection of the obsolete instruments path, heartbeat timeout, schema additions, pseq reset, and incomplete liquidation coverage.

- [ ] **Step 5: Commit**

```bash
git add docs/exchanges/bitget src/crypto_collector/exchanges/bitget tests/fixtures/exchanges/bitget tests/contract/exchanges/bitget tests/protocol/exchanges/bitget tests/property/exchanges/bitget tests/integration/exchanges/test_bitget_session.py
git commit -m "feat: add bitget public connector"
```

### Task 4: Kraken Spot v2 and Futures

**Files:**
- Modify: `docs/exchanges/kraken/README.md`
- Modify: `docs/exchanges/kraken/sources/`
- Create: `src/crypto_collector/exchanges/kraken/__init__.py`
- Create: `src/crypto_collector/exchanges/kraken/adapter.py`
- Create: `src/crypto_collector/exchanges/kraken/catalog.py`
- Create: `src/crypto_collector/exchanges/kraken/rest.py`
- Create: `src/crypto_collector/exchanges/kraken/ws.py`
- Create: `src/crypto_collector/exchanges/kraken/book.py`
- Create: `src/crypto_collector/exchanges/kraken/checksum.py`
- Create: `src/crypto_collector/exchanges/kraken/errors.py`
- Create: `tests/fixtures/exchanges/kraken/manifest.json`
- Create: `tests/fixtures/exchanges/kraken/spot-pairs.json`
- Create: `tests/fixtures/exchanges/kraken/spot-book.json`
- Create: `tests/fixtures/exchanges/kraken/futures-instruments.json`
- Create: `tests/fixtures/exchanges/kraken/futures-book.json`
- Test: `tests/contract/exchanges/kraken/test_catalog.py`
- Test: `tests/contract/exchanges/kraken/test_rest.py`
- Test: `tests/protocol/exchanges/kraken/test_spot_book.py`
- Test: `tests/protocol/exchanges/kraken/test_futures_book.py`
- Test: `tests/property/exchanges/kraken/test_book.py`
- Test: `tests/integration/exchanges/test_kraken_session.py`

- [ ] **Step 1: Write failing alias, CRC, ordered-update, and best-effort tests**

```python
def test_catalog_maps_rest_and_ws_aliases_to_one_instrument_key() -> None:
    instrument = parse_spot_pair_fixture().by_key("BTC/USDT")
    assert instrument.wire_symbol("rest_query") == "BTCUSDT"
    assert instrument.wire_symbol("rest_result") == "XBTUSDT"
    assert instrument.wire_symbol("ws_v2") == "BTC/USDT"


def test_spot_crc_uses_decimal_strings_not_binary_float() -> None:
    book = KrakenSpotBook(depth=10)
    book.apply(snapshot_with_strings(price="0.10000000", qty="1.2300"))
    assert book.checksum_input().startswith("1")
    assert book.verify_crc(expected_crc(book.checksum_input()))


def test_repeated_price_updates_apply_in_message_order_then_trim() -> None:
    book = seeded_kraken_spot_book(depth=10)
    outcome = book.apply(update(asks=[{"price": "11", "qty": "2"},
                                      {"price": "11", "qty": "0"}]))
    assert Decimal("11") not in book.asks
    assert len(book.asks) <= 10
    assert outcome.integrity is BookIntegrity.CHECKSUM_VERIFIED


def test_futures_seq_regression_invalidates_but_gap_does_not_assume_plus_one() -> None:
    state = seeded_kraken_futures_book(seq=100)
    assert state.apply(futures_delta(seq=105)).integrity is BookIntegrity.BEST_EFFORT
    assert state.apply(futures_delta(seq=104)).integrity is BookIntegrity.INVALID
```

- [ ] **Step 2: Run and verify Kraken modules are missing**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/kraken tests/protocol/exchanges/kraken tests/property/exchanges/kraken tests/integration/exchanges/test_kraken_session.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement protocol-specific Spot and Futures clients**

Use Spot REST `/0/public/*`, Spot WS v2, Futures REST `/derivatives/api/v3`, Futures Charts, and Futures WS v1. Catalog mapping establishes stable `instrument_key`; every request/event keeps its actual `wire_symbol`. Spot supports catalog/status, ticker/BBO, trade batches, OHLC, and book. Futures supports instruments/status, ticker with mark/index/funding/OI, trade/liquidation types, book snapshot/delta, funding history, candles, and configured analytics.

Spot applies message updates in array order, trims to subscribed depth, constructs top-10 CRC input from original Decimal/string semantics, and invalidates on mismatch. Futures rejects duplicate/regressing sequences and reconnects on confirmed anomalies, but a non-`+1` increase remains `BEST_EFFORT` because the official contract does not promise contiguity. Exclude token-only Spot L3 and all private feeds.

- [ ] **Step 4: Run Kraken contract/protocol/session tests**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/kraken tests/protocol/exchanges/kraken tests/property/exchanges/kraken tests/integration/exchanges/test_kraken_session.py -q`

Expected: PASS, including batched trades, heartbeat/status, CRC mismatch recovery, mixed Futures field casing, and USD fixed-pair bypass.

- [ ] **Step 5: Commit**

```bash
git add docs/exchanges/kraken src/crypto_collector/exchanges/kraken tests/fixtures/exchanges/kraken tests/contract/exchanges/kraken tests/protocol/exchanges/kraken tests/property/exchanges/kraken tests/integration/exchanges/test_kraken_session.py
git commit -m "feat: add kraken public connector"
```

### Task 5: Registry and Shared Adapter Conformance

**Files:**
- Modify: `src/crypto_collector/exchanges/registry.py`
- Modify: `src/crypto_collector/capabilities/data/binance.yaml`
- Modify: `src/crypto_collector/capabilities/data/bybit.yaml`
- Modify: `src/crypto_collector/capabilities/data/bitget.yaml`
- Modify: `src/crypto_collector/capabilities/data/kraken.yaml`
- Create: `tests/contract/exchanges/test_all_connectors.py`
- Create: `tests/integration/exchanges/test_all_scripted_sessions.py`
- Modify: `tests/cli/test_config_probe.py`

- [ ] **Step 1: Write the failing five-adapter conformance matrix**

```python
@pytest.mark.parametrize("exchange", ["binance", "okx", "bybit", "bitget", "kraken"])
def test_registry_exposes_anonymous_adapter(exchange) -> None:
    adapter = ExchangeRegistry.builtin().get(exchange)
    assert adapter.exchange.value == exchange
    assert adapter.accepts_credentials is False


@pytest.mark.parametrize("exchange", ["binance", "okx", "bybit", "bitget", "kraken"])
@pytest.mark.network
@pytest.mark.asyncio
async def test_scripted_adapter_contract(exchange, scripted_exchange_server, tmp_path) -> None:
    result = await run_scripted_adapter(exchange, scripted_exchange_server[exchange], tmp_path)
    assert result.catalog_spot_count > 0
    assert result.catalog_perpetual_count > 0
    assert result.closed_manifest_count > 0
    assert result.unrecorded_gap_count == 0
    assert result.private_request_count == 0


@pytest.mark.parametrize("exchange", ["binance", "okx", "bybit", "bitget", "kraken"])
def test_adapter_plan_matches_declared_research_surface(exchange, resolved_config) -> None:
    adapter = ExchangeRegistry.builtin().get(exchange)
    plan = adapter.plan(request_for(exchange, resolved_config))
    assert plan.expected_logical_streams() == expected_streams_from_capability(exchange)


@pytest.mark.network
def test_config_probe_reports_all_five_providers(config_tree, scripted_exchange_server) -> None:
    point_all_exchange_endpoints_at(config_tree, scripted_exchange_server)
    result = CliRunner().invoke(app, ["config", "probe", str(config_tree), "--json"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert set(body["exchanges"]) == {"binance", "okx", "bybit", "bitget", "kraken"}
    assert all(item["selection"]["fixed"]["instrument_keys"]
               for item in body["exchanges"].values())
```

- [ ] **Step 2: Run and verify registry/conformance failures**

Run: `.venv/bin/python -m pytest tests/contract/exchanges/test_all_connectors.py tests/integration/exchanges/test_all_scripted_sessions.py tests/cli/test_config_probe.py -q`

Expected: FAIL until every adapter and capability record is registered.

- [ ] **Step 3: Freeze the reviewed adapter contract**

Register all five adapters and their `ProbeProvider` implementations without conditional import side effects. The `collector config probe` command now requires and exercises every enabled provider; no exchange can disappear from the report. Validate each capability YAML against the same Pydantic schema and compare the complete default stream/channel/depth/anonymous/date-gate decisions with adapter output. Conformance covers catalog, stable/wire identity, required streams, business error classification, added fields, malformed required routing fields, heartbeat, disconnect, queue overflow, gap control, sticky bootstrap where applicable, and clean shutdown.

No venue task may modify the shared contract after this point without updating all five conformance fixtures in the same commit.

- [ ] **Step 4: Run the complete offline connector suite**

Run: `.venv/bin/python -m pytest tests/contract/exchanges tests/protocol/exchanges tests/integration/exchanges tests/cli/test_config_probe.py -q`

Expected: PASS with external sockets disabled except local `network` fixtures.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/exchanges/registry.py src/crypto_collector/capabilities/data tests/contract/exchanges tests/integration/exchanges tests/cli/test_config_probe.py
git commit -m "feat: register five public exchange adapters"
```

### Task 6: Refactor and Run the Live/SOCKS Matrix

**Files:**
- Modify: `tests/smoke/test_binance_public_api.py`
- Modify: `tests/smoke/test_bybit_public_api.py`
- Modify: `tests/smoke/test_bitget_public_api.py`
- Modify: `tests/smoke/test_kraken_public_api.py`
- Create: `tests/smoke/test_connector_live_matrix.py`
- Create: `tests/smoke/test_connector_socks_live.py`
- Create: `.github/workflows/live-exchange-smoke.yml`
- Create: `docs/operations/evidence/five-exchange-live-check.md`

- [ ] **Step 1: Mark and route existing smoke tests through production builders/parsers**

```python
pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(os.getenv("RUN_LIVE_API_TESTS") != "1",
                       reason="set RUN_LIVE_API_TESTS=1 to contact exchanges"),
]


@pytest.mark.parametrize("exchange", ["binance", "okx", "bybit", "bitget", "kraken"])
@pytest.mark.asyncio
async def test_live_catalog_and_public_ws(exchange) -> None:
    adapter = ExchangeRegistry.builtin().get(exchange)
    result = await live_probe_adapter(adapter, fixed_probe_pair(exchange))
    assert result.spot_catalog_ok
    assert result.perpetual_catalog_ok
    assert result.ws_subscription_ack
    assert result.first_public_event_ok
```

Replace hardcoded smoke request construction with adapter request builders and pass live responses through production parsers. Stateful book probes require a snapshot plus at least one update; quiet liquidation channels require a successful ACK rather than fabricating a data event.

- [ ] **Step 2: Verify the entire live matrix skips offline**

Run: `.venv/bin/python -m pytest tests/smoke -q -m live`

Expected: every live case skips and pytest-socket reports no attempted external connection.

- [ ] **Step 3: Add explicit SOCKS matrix behavior**

```python
@pytest.mark.live
@pytest.mark.skipif(os.getenv("RUN_LIVE_API_TESTS") != "1",
                    reason="set RUN_LIVE_API_TESTS=1 to contact exchanges")
@pytest.mark.skipif(not os.getenv("LIVE_SOCKS_PROXY"), reason="LIVE_SOCKS_PROXY is not configured")
@pytest.mark.asyncio
async def test_one_rest_and_ws_generation_use_socks() -> None:
    result = await probe_through_socks(os.environ["LIVE_SOCKS_PROXY"], exchange="okx")
    assert result.rest_egress_id == "live-socks"
    assert result.ws_egress_id == "live-socks"
    assert result.proxy_value_not_logged
```

The SOCKS test has a deliberate double opt-in: both `RUN_LIVE_API_TESTS=1` and a non-empty `LIVE_SOCKS_PROXY` are required. Merely inheriting a proxy variable on a developer or CI host must never contact an exchange. No automatic regional fallback is allowed. A geographic block produces a specific failure/skip requiring an explicit regional host override.

- [ ] **Step 4: Run and record explicit public live tests**

Run: `RUN_LIVE_API_TESTS=1 .venv/bin/python -m pytest tests/smoke -q -m live`

Expected: all environmentally available public REST/WS cases pass; genuine protocol/parser failures fail. With a configured proxy, separately run `LIVE_SOCKS_PROXY='socks5h://...' RUN_LIVE_API_TESTS=1 .venv/bin/python -m pytest tests/smoke/test_connector_socks_live.py -q -m live`.

Record timestamp, source commit, endpoint regions, adapter/capability digests, pass/skip/failure counts, and exact environmental skips in `docs/operations/evidence/five-exchange-live-check.md` without credentials.

- [ ] **Step 5: Commit**

```bash
git add tests/smoke .github/workflows/live-exchange-smoke.yml docs/operations/evidence/five-exchange-live-check.md
git commit -m "test: verify five exchange connectors live"
```

- [ ] **Step 6: Run the repository-wide offline regression gate**

Run: `.venv/bin/python -m pytest -q -m "not live and not performance"`

Expected: PASS with all external sockets denied and all live cases skipped.
