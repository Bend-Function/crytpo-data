# Bybit public market data notes

This directory is a point-in-time archive and implementation note for the
anonymous Bybit V5 market-data APIs. It covers Spot and USDT perpetual data
needed by a file-only collector. It deliberately excludes account, wallet,
order-entry, and other authenticated APIs.

- Retrieved during: `2026-08-09T01:07:49+12:00` to `2026-08-09T01:37:12+12:00`
- Source policy: official Bybit API documentation only
- Local source format: complete HTML responses from the official Docusaurus site
- Integrity: SHA256 values are listed in the source inventory below
- Live probe symbol: `BTCUSDT`

The online documentation can change without notice. Treat this archive as the
contract used during design, and re-download it before implementing or changing
the connector.

## Base endpoints

Mainnet REST:

- `https://api.bybit.com`
- `https://api.bytick.com` (official alternative)

The archived rate-limit page spells the alternative domain as
`api.bybick.com`, which conflicts with `api.bytick.com` in Integration
Guidance. Do not derive an endpoint from that rate-limit spelling; this note
uses the Integration Guidance endpoint and preserves the discrepancy for
future review.

Mainnet public WebSocket:

- Spot: `wss://stream.bybit.com/v5/public/spot`
- USDT/USDC perpetual and USDT futures: `wss://stream.bybit.com/v5/public/linear`
- Inverse contracts: `wss://stream.bybit.com/v5/public/inverse`
- Platform status: `wss://stream.bybit.com/v5/public/misc/status`

Testnet uses `https://api-testnet.bybit.com` and
`wss://stream-testnet.bybit.com/v5/public/{spot,linear,inverse}`.

Bybit documents separate mainnet hosts for several registered-user regions.
The generic API rejects IP addresses in the US and Mainland China with HTTP
403. A deployment must make the REST and WebSocket hosts configurable rather
than silently falling back to an unrelated regional host.

For Argentina, the official guidance uses the generic `api.bybit.com` and
`stream.bybit.com` hosts but requires `x-site-id: ARG_BTL` on mainnet REST and
WebSocket requests. Treat this as an explicitly configured regional route:
the anonymous generic route must not send this header by default.

Public WebSocket topics do not require authentication. The REST market and
platform endpoints listed below are also usable without authentication.

## Recommended collection surface

### Core realtime channels

| Data | Topic | Spot | USDT perpetual | Documented frequency |
| --- | --- | --- | --- | --- |
| Trades | `publicTrade.{symbol}` | Yes | Yes | Realtime; up to 1024 trades in one Spot/Futures message |
| Ticker | `tickers.{symbol}` | Yes | Yes | Spot 50 ms; derivatives 100 ms |
| Order book | `orderbook.{depth}.{symbol}` | Yes | Yes | depth 1: 10 ms; 50: 20 ms; 200: 100 ms; 1000: 200 ms |
| RPI order book | `orderbook.rpi.{symbol}` | Yes | Yes | depth 50, 100 ms |
| Full order book | `orderbook.full.{symbol}` | Documented available; optional and probe-gated | Date-gated optional capability; not presumed live | 200 ms |
| Kline | `kline.{interval}.{symbol}` | Yes | Yes | 1 to 60 seconds |

Standard `orderbook.200.{symbol}` remains the default depth for both Spot and
USDT perpetual collection. Full depth is opt-in even after its capability
gates pass.

Ticker is especially useful for the selection and derivatives layers. Spot
ticker messages are snapshots. Derivatives ticker uses an initial snapshot and
subsequent deltas, and includes last/mark/index price, best bid/ask, 24-hour
volume and turnover, open interest, funding rate, and next funding time.

### Derivatives and platform channels

| Data | Topic | Frequency / behavior |
| --- | --- | --- |
| Complete liquidation feed | `allLiquidation.{symbol}` | 500 ms, contracts only |
| Insurance pool | `insurance.USDT`, `insurance.USDC`, `insurance.inverse` | 1 second when balances change; shared pools are not pushed |
| Order price limits | `priceLimit.{symbol}` | 300 ms |
| ADL risk | `adlAlert.USDT`, `adlAlert.USDC`, `adlAlert.inverse` | 1 second |
| Platform status | `system.status` on separate `.../public/misc/status` connection | Event driven; interruptions under 10 seconds may not be announced |

The old `liquidation.{symbol}` feed is deprecated and incomplete. Use
`allLiquidation.{symbol}`.

### Public REST support

The collector should use REST for discovery, independent deep snapshots,
slow-changing data, and full-book bootstrap/gap recovery:

- `/v5/market/instruments-info`: instrument catalog and contract lifecycle
- `/v5/market/tickers`: latest price, best bid/ask, and 24-hour volume/turnover
- `/v5/market/orderbook`: up to 1,000 levels per side, snapshot only
- `/v5/market/rpi_orderbook`: 50-level RPI-aware snapshot
- `/v5/market/full_orderbook`: up to 10,000 levels per side, full-book bootstrap
- `/v5/market/recent-trade`: recent public trades
- `/v5/market/kline`: trade-price OHLCV
- `/v5/market/mark-price-kline`, `/v5/market/index-price-kline`,
  `/v5/market/premium-index-price-kline`: derivatives reference-price history
- `/v5/market/funding/history`: funding-rate history
- `/v5/market/open-interest`: open-interest history
- `/v5/market/account-ratio`: long/short account ratio
- `/v5/market/insurance`, `/v5/market/risk-limit`,
  `/v5/market/price-limit`, `/v5/market/adlAlert`: risk context
- `/v5/market/index-price-components`: index composition
- `/v5/market/delivery-price`: delivery-futures history (outside the default
  Spot/perpetual scope)
- `/v5/market/historical-volatility`: Options-only historical volatility
  (outside the default Spot/perpetual scope)
- `/v5/announcements/index`: announcements, including new-listing metadata
- `/v5/system/status`: maintenance and incident records
- `/v5/market/time`: server clock

The standard `orderbook.200` feed is not REST-bootstrapped: it starts and
recovers only from its own WebSocket snapshot. The standard REST order-book
`u` is documented to correspond to the 1000-level WebSocket feed, not the
default 200-level feed. Do not use REST depth to enlarge, bridge, or repair a
standard live book. Only `orderbook.full` uses the documented REST/WS handoff.

For Top N selection, rank the configured quote-currency subset using
`turnover24h` rather than raw base-asset `volume24h`; turnover is comparable
within a common quote currency such as USDT.

## Order-book state and recovery

### Standard order book

`orderbook.1.*` is snapshot-only. If the best level does not change for three
seconds, Bybit sends another snapshot with the same update ID.

Depths 50, 200, and 1000 start with a snapshot and then send deltas:

- size `0`: delete the price level
- absent price with nonzero size: insert it
- existing price with nonzero size: replace its size
- any new `snapshot`: discard the local state and replace it completely
- `u == 1`: service reinitialization; replace local state with the snapshot
- after a disconnect or suspected gap: discard state, reconnect, and wait for a
  fresh snapshot before applying more deltas

The archived standard and full order-book specifications do not define a
checksum field or checksum procedure. The standard feed also does not promise
consecutive `u` values or define `seq` as a same-depth gap detector; it provides
snapshot-chain integrity only. On disconnect or suspected loss, discard it and
wait for a new WebSocket snapshot. The full feed separately documents its
consecutive-`u` and `seq` handoff rules. Do not invent or claim exchange
checksum validation.

The standard feed excludes Retail Price Improvement orders. The dedicated RPI
feed supplies separate non-RPI and RPI size fields at each price.

### Full order book

As of this evidence date (`2026-08-09`), the documentation marks full depth as
available for Spot. For linear/inverse, the scheduled testnet date
(`2026-08-04`) has passed, while the mainnet date (`2026-08-11`) remains in the
future. These schedule entries are not live evidence, and this refresh did not
probe either full-depth transport.

Freeze full depth as an optional capability. Spot requires a successful live
probe before enablement; linear/inverse require both the configured schedule
date to have passed and a successful live probe for the exact environment,
category, and symbol. Passing a date alone must not enable it, and standard
depth 200 remains the default after either gate succeeds.

The full stream is delta-only and has no initial WebSocket snapshot. Follow the
official synchronization sequence:

1. Subscribe and buffer deltas.
2. Discard a buffered delta whose `seq` decreases; restart buffering if `u` is
   discontinuous.
3. Fetch `/v5/market/full_orderbook`.
4. Discard buffered messages older than the snapshot and require matching
   `seq` and `u` at the handoff point; refetch if they cannot be aligned.
5. Install the REST snapshot, then apply the remaining buffered deltas.
6. In steady state require each new `u` to equal the previous `u + 1`.
7. On a `u` gap or `u == 1`, discard the book and repeat the entire
   synchronization procedure.

The official steady-state update procedure bases recovery on `u`. This
implementation additionally treats a decreasing steady-state `seq` as a local
fail-closed anomaly and resynchronizes; that extra check is a conservative
collector policy, not an exchange-mandated recovery rule.

Bound bootstrap buffering by frame count, encoded bytes, and elapsed time.
Exceeding any bound invalidates the partial generation and restarts the full
handoff; a stalled or unalignable REST snapshot must not grow memory without
limit.

`seq` is monotonic but is not required to be consecutive. `u` is consecutive
within a service session. A full-book `u == 1` can also mean restart, delisting,
auction transition, or a tick/lot configuration change; consult the REST
snapshot and instrument status rather than guessing.

## Instrument and new-listing discovery

Poll `/v5/market/instruments-info` separately by category.

- Spot has no pagination and currently returns `Trading` instruments only. Its
  documented Spot response does not include `launchTime`. Detect new Spot pairs
  by diffing complete catalog snapshots, then use announcements as an earlier
  hint where possible.
- Linear has more than 500 instruments. Fetch `status=Trading` and
  `status=PreLaunch` as two independent cursor chains, following each opaque
  `nextPageCursor` until empty. The default request returns only `Trading`.
  If one symbol appears in both independently fetched chains, reject the whole
  round as a transition race and retry rather than inventing a winner.
- Linear supports `status=PreLaunch` and returns `launchTime`, `isPreListing`,
  auction phases, and continuous-trading start times. These fields are the
  preferred timestamps for perpetual new-listing collection windows. Live
  payloads have also used `946684800000` phase timestamps as placeholders;
  when a future continuous-trading time cannot be proved, conservatively fall
  back to a future `launchTime` or leave the time unknown while preserving raw
  evidence.
- `/v5/announcements/index?locale=en-US` returns type, tags, publish time, title,
  and URL. Treat an announcement as a discovery trigger, then confirm the
  symbol and status against the instrument catalog before subscribing.
- Persist full catalog snapshots and `first_seen` time. On the first collector
  run, baseline existing Spot instruments instead of labeling every pair new.

## Limits, heartbeat, and connection policy

- HTTP: 600 requests per 5 seconds per IP by default across the documented API
  domains. Only a 403 body that explicitly says `access too frequent` proves
  the documented IP ban and requires stopping that egress for at least 10
  minutes; a generic 403 can represent a regional or request-policy failure.
- Inspect HTTP status and integer JSON `retCode` independently. HTTP 429 and
  business codes `10000`, `10006`, `10016`, and `429` are retryable according
  to their timeout/throttle meaning; parameter, route, and symbol codes
  `10001`, `10017`, and `10029` fail without a blind retry.
- Anonymous public REST responses may omit `X-Bapi-Limit*`; preserve those
  headers when present, but do not treat them as required public quota truth.
- WebSocket creation: no more than 500 connections per 5 minutes per domain;
  avoid repeated connect/disconnect loops.
- Market-data connections: no more than 1,000 per IP, counted separately for
  Spot, Linear, Inverse, and Options.
- One public connection has a 21,000-character aggregate `args` limit.
- Spot permits at most 10 arguments in each individual subscription request.
  Futures currently has no per-request argument-count limit, but the character
  limit still applies.
- Send the application-level JSON heartbeat `{"op":"ping"}` every 20 seconds,
  as recommended by Bybit. Reconnect immediately on disconnection with bounded
  exponential backoff and jitter.
- `max_active_time` is documented for private/order-entry connections, not as a
  public-stream tuning control.

## Anonymous boundary and exclusions

Include only public market, platform-status, instrument, announcement, and risk
reference data. Do not add API keys merely to increase convenience. Exclude:

- private WebSocket topics
- WebSocket order entry
- order, position, account, asset, wallet, and user endpoints
- institutional feeds that require login, entitlements, or API credentials

Standard public order books exclude RPI orders, but the separately documented
public RPI order book can be collected without authentication. Keep it as a
distinct channel because its size schema differs from the standard book.

## Deprecations and date-sensitive notes

- Old `liquidation` WebSocket topic: deprecated on 2025-02-20; use
  `allLiquidation` to avoid losing events.
- Instruments `innovation`: deprecated; use `symbolType`.
- Linear/inverse `postOnlyMaxOrderQty`: deprecated; use `maxOrderQty`.
- Several legacy Spot lot-size fields (`minOrderQty`, `maxOrderQty`,
  `maxOrderAmt`) are deprecated; retain raw payloads but do not build new logic
  on them.
- ADL alert `mb`: deprecated and documented to return an empty string.
- Spot full order book was documented as added on 2026-07-16, but remains an
  opt-in, probe-gated collector capability.
- The linear/inverse full-book testnet schedule date (2026-08-04) has passed
  without a live probe in this refresh. The mainnet schedule date (2026-08-11)
  is still future-dated relative to this archive. Neither schedule entry proves
  availability; use the date-plus-probe gate described above.
- The changelog may contain future-dated release notices. A future heading is
  not evidence that a production capability is already live.

## Live smoke test

Test file: `tests/smoke/test_bybit_public_api.py`

The test is opt-in so an ordinary offline test run does not make external API
calls. It sends no credentials and performs no trading action.

Command run from the repository root:

```bash
RUN_LIVE_API_TESTS=1 .venv/bin/pytest -q tests/smoke/test_bybit_public_api.py
```

Observed result on `2026-08-09` after the smoke test's file-level `live` marker
enabled the repository's explicit socket exception:

```text
..                                                                       [100%]
2 passed in 1.13s
```

Coverage:

- REST `GET /v5/market/orderbook?category=spot&symbol=BTCUSDT&limit=1`
- Spot WebSocket subscription `orderbook.1.BTCUSDT`, including a non-empty
  anonymous snapshot with positive `u` and `seq`

This proves reachability and the checked response shape from this host at that
time. It is not a load test and does not validate the scheduled perpetual
full-depth channel.

## Source inventory

Every item below was retrieved from the official Bybit documentation site at
the timestamp near the top of this file.

| Local file | Official URL | SHA256 |
| --- | --- | --- |
| `sources/announcements.html` | https://bybit-exchange.github.io/docs/v5/announcement | `d8c70052352e892e6e27bca5d5d3481bf07c355f11f4ccd6622bc31805996ad3` |
| `sources/error-codes.html` | https://bybit-exchange.github.io/docs/v5/error | `c32defbe316fcc19e2153e85bd8174c447d87d92fe845f558e72726363178121` |
| `sources/integration-guidance.html` | https://bybit-exchange.github.io/docs/v5/guide | `a146b4c5f9d27307db9181da22d0fceea1434a4367603e44d8257d1ca59bf20c` |
| `sources/rate-limit.html` | https://bybit-exchange.github.io/docs/v5/rate-limit | `9ac6046a5d955cc19cd9ac70759aaeebe52037479b2d630346e734e7d2412c09` |
| `sources/rest-adl-alert.html` | https://bybit-exchange.github.io/docs/v5/market/adl-alert | `2542ae420aff1cb46bc6cf9ab67196ed38026a43027d1b720b867a81071c5ba7` |
| `sources/rest-delivery-price.html` | https://bybit-exchange.github.io/docs/v5/market/delivery-price | `aa88a70298e2cd85577c733e03f8ba4094d37cc10e1230a713b2c62c9fd9a0a7` |
| `sources/rest-full-orderbook.html` | https://bybit-exchange.github.io/docs/v5/market/full-ob | `e49d7a733980c96e9be97b241234e84def40e170e40c66b650035fde6262abce` |
| `sources/rest-funding-rate-history.html` | https://bybit-exchange.github.io/docs/v5/market/history-fund-rate | `011454cb5a3f87e989be8bb81c9293bfb3ec7fb50e9f478be1e5bac7da0013bb` |
| `sources/rest-historical-volatility.html` | https://bybit-exchange.github.io/docs/v5/market/iv | `2186495fa8a3f94ce3e85d78547d01d4d186a19b0502503f61d4c0a87dbe600f` |
| `sources/rest-index-components.html` | https://bybit-exchange.github.io/docs/v5/market/index-components | `8ce1fd3e7ba22c4c504ee7aae52c1ea7b5f754ad739180918d7da106a117b7cd` |
| `sources/rest-index-price-kline.html` | https://bybit-exchange.github.io/docs/v5/market/index-kline | `843bd4e45e08a10f28a59f13b2c6f410b171a152fc17dc78b3cf4080c9baa7fe` |
| `sources/rest-instruments-info.html` | https://bybit-exchange.github.io/docs/v5/market/instrument | `9c406149ffda01275648f13ecc8ff14d0c1c47d6e1cec7cffa7e8158ec211e89` |
| `sources/rest-insurance-pool.html` | https://bybit-exchange.github.io/docs/v5/market/insurance | `7bbc9ad0aa2eb0451ed52256b3d50d818db9f1ec0e28e73172bc346638e24ba1` |
| `sources/rest-kline.html` | https://bybit-exchange.github.io/docs/v5/market/kline | `86b521c8d4cca2f9901cefc7cebc5e2ce969f7b5a1820547b732bfb3f7456816` |
| `sources/rest-long-short-ratio.html` | https://bybit-exchange.github.io/docs/v5/market/long-short-ratio | `2f17fb17a272cc4753428230552990f508ba3e02f487a6e966db621dedc2fb3e` |
| `sources/rest-mark-price-kline.html` | https://bybit-exchange.github.io/docs/v5/market/mark-kline | `9666391dfce5b2096ddd3abc4e7457907710dfcd9cd13b8fa98c7c50b05e4526` |
| `sources/rest-open-interest.html` | https://bybit-exchange.github.io/docs/v5/market/open-interest | `6fb8f50ad3aff414561ce3feccb6f8b0bad2fa38704d3d7852f1f61c25999f09` |
| `sources/rest-order-price-limit.html` | https://bybit-exchange.github.io/docs/v5/market/order-price-limit | `2eedaddd7ee0acd54c292c9dfbd2937914f906c936e7ba616e50c40b731c9364` |
| `sources/rest-orderbook.html` | https://bybit-exchange.github.io/docs/v5/market/orderbook | `1d25265f09c714ae07ca5d4dc66b1f4a99e7e863cd1ddcd3ba64e1e5097e8db1` |
| `sources/rest-premium-index-kline.html` | https://bybit-exchange.github.io/docs/v5/market/premium-index-kline | `b26eb2c0c433065fbe917ef869ebac293fcc9997cc30ec38db329791d1e79571` |
| `sources/rest-recent-trades.html` | https://bybit-exchange.github.io/docs/v5/market/recent-trade | `6064db478061400e46c41dd7f5481a60ec79829115d6443e658c703ecb22d794` |
| `sources/rest-risk-limit.html` | https://bybit-exchange.github.io/docs/v5/market/risk-limit | `1b8f752db5007d2f54554e8cad739e90e71175d521eb52ac05ae3c2e8a84d4e4` |
| `sources/rest-rpi-orderbook.html` | https://bybit-exchange.github.io/docs/v5/market/rpi-orderbook | `b48d15bdd259db9a0939002d0bac85a47b451e9348c89d71c099acbe99fb818c` |
| `sources/rest-server-time.html` | https://bybit-exchange.github.io/docs/v5/market/time | `d72a5c4c5fcd352a5908d16bae15fc92209b0859e4afe3b1bda36fa40b1453ae` |
| `sources/rest-tickers.html` | https://bybit-exchange.github.io/docs/v5/market/tickers | `260be428e16a709f59c8dd81cd5482e7274c0acc0f5faa3c9ce2a9dc3c9cd1cd` |
| `sources/system-status.html` | https://bybit-exchange.github.io/docs/v5/system-status | `8afdf7a3ccb8914f782748ede73ad0ce3b0d509d3a6d8d0203aff9fabd666fb0` |
| `sources/v5-changelog.html` | https://bybit-exchange.github.io/docs/changelog/v5 | `d8e2d59ef56c4665851e7019db3c7e239f15d7326daa424ad9fba78b644386bd` |
| `sources/ws-adl-alert.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/adl-alert | `7aa99d0392e8981353af94e6989479af2960775cc890ce0d50616fa8465c271b` |
| `sources/ws-all-liquidation.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/all-liquidation | `238de8e988da047e4573db932bbcdc5b836d3cbbd378eb1dd4f9b4c0a9c23ebe` |
| `sources/ws-connect.html` | https://bybit-exchange.github.io/docs/v5/ws/connect | `7ea48dbde7db55aaf44a66cf85f0f5370865e5acd2e5503aebe677419365c17a` |
| `sources/ws-full-orderbook.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/full-ob | `9795de21b134bc890cb7c2fa3cc270401184eacaa4748551395bf60be382183e` |
| `sources/ws-insurance-pool.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/insurance-pool | `b5330dbb03cfd6475c435da61d495037365640c344be4faa5b365f3b4864324e` |
| `sources/ws-kline.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/kline | `1ddade558fc9901277e0429a574eceff6033c2f6af6bc0fad80dc925d1f639a6` |
| `sources/ws-order-price-limit.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/order-price-limit | `f9d57ad31de121f251f7de7414662f9b82dd1d9507ee85ee3e13565784fc4d75` |
| `sources/ws-orderbook.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/orderbook | `9c806ce0622aa25ea8ce7697e76ace8e59a981fdc515be124c869789d5ab1f23` |
| `sources/ws-rpi-orderbook.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/orderbook-rpi | `fbc456011ad71bd3fcc64778630766656584798423e987ab0eaeea8d26d32ad1` |
| `sources/ws-system-status.html` | https://bybit-exchange.github.io/docs/v5/websocket/system/system-status | `5de3f721007aa06630450f359cedfaaa989b8b36377eac12d67e38bb4200f67e` |
| `sources/ws-ticker.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/ticker | `fd232177a5ae1fe1f464d3f9dc87da9541e9e66182afd682d52aa7a79de59aa2` |
| `sources/ws-trade.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/trade | `b5994ad3791afbd29ea3a4b041b05641b98c89a106a81bc0c721c13f385f1292` |
