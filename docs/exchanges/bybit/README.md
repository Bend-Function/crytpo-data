# Bybit public market data notes

This directory is a point-in-time archive and implementation note for the
anonymous Bybit V5 market-data APIs. It covers Spot and USDT perpetual data
needed by a file-only collector. It deliberately excludes account, wallet,
order-entry, and other authenticated APIs.

- Retrieved during: `2026-07-31T03:53:55Z` to `2026-07-31T04:01:43Z`
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
| Full order book | `orderbook.full.{symbol}` | Spot only now | Scheduled, not live yet | 200 ms |
| Kline | `kline.{interval}.{symbol}` | Yes | Yes | 1 to 60 seconds |

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

The collector should use REST for discovery, bootstrap, slow-changing data,
and gap recovery:

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
  `/v5/market/order-price-limit`, `/v5/market/adl-alert`: risk context
- `/v5/market/index-price-components`: index composition
- `/v5/market/delivery-price`: delivery-futures history (outside the default
  Spot/perpetual scope)
- `/v5/market/historical-volatility`: Options-only historical volatility
  (outside the default Spot/perpetual scope)
- `/v5/announcements/index`: announcements, including new-listing metadata
- `/v5/system/status`: maintenance and incident records
- `/v5/market/time`: server clock

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

The standard feed excludes Retail Price Improvement orders. The dedicated RPI
feed supplies separate non-RPI and RPI size fields at each price.

### Full order book

As of `2026-07-31`, full depth is live for Spot. The official release schedule
lists linear/inverse testnet for `2026-08-04` and mainnet for `2026-08-11`.
Do not enable full depth for perpetuals until the configured date has passed and
a capability probe succeeds.

The full stream is delta-only and has no initial WebSocket snapshot. Follow the
official synchronization sequence:

1. Subscribe and buffer deltas.
2. Reject decreasing `seq`; restart buffering if `u` is discontinuous.
3. Fetch `/v5/market/full_orderbook`.
4. Discard buffered messages older than the snapshot and require matching
   `seq` and `u` at the handoff point; refetch if they cannot be aligned.
5. Install the REST snapshot, then apply the remaining buffered deltas.
6. In steady state require each new `u` to equal the previous `u + 1`.
7. On a gap, decreasing sequence, or `u == 1`, discard the book and repeat the
   entire synchronization procedure.

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
- Linear has more than 500 instruments. Follow `nextPageCursor` until empty;
  never assume the default first page is complete.
- Linear supports `status=PreLaunch` and returns `launchTime`, `isPreListing`,
  auction phases, and continuous-trading start times. These fields are the
  preferred timestamps for perpetual new-listing collection windows.
- `/v5/announcements/index?locale=en-US` returns type, tags, publish time, title,
  and URL. Treat an announcement as a discovery trigger, then confirm the
  symbol and status against the instrument catalog before subscribing.
- Persist full catalog snapshots and `first_seen` time. On the first collector
  run, baseline existing Spot instruments instead of labeling every pair new.

## Limits, heartbeat, and connection policy

- HTTP: 600 requests per 5 seconds per IP by default across the documented API
  domains. A 403 for excessive access requires stopping requests for at least
  10 minutes.
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
- Spot full order book was added on 2026-07-16. Perpetual full order book is
  still future-scheduled relative to this archive date.
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

Observed result on `2026-07-31`:

```text
..                                                                       [100%]
2 passed in 1.15s
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
| `sources/announcements.html` | https://bybit-exchange.github.io/docs/v5/announcement | `e0a58047fe2c27734c5ec5e9b4e097bf1333604e45dcd00bdd9ca46f2cd70976` |
| `sources/integration-guidance.html` | https://bybit-exchange.github.io/docs/v5/guide | `ad0f6592307d4db39a797d8be0474b381d31b86a9292b377106d618edba8c2aa` |
| `sources/rate-limit.html` | https://bybit-exchange.github.io/docs/v5/rate-limit | `781d563d14f4ca754962b52e99d18e100ec67533e91756b7dc997af987b10d58` |
| `sources/rest-adl-alert.html` | https://bybit-exchange.github.io/docs/v5/market/adl-alert | `4e14c5532648d1037d3c81fd733b23260149347776ab53d0633dbe77297d3c29` |
| `sources/rest-delivery-price.html` | https://bybit-exchange.github.io/docs/v5/market/delivery-price | `da784f46f74200eceb3dc38110d1e80f9ec801f5456a55f4365a06b666f7e377` |
| `sources/rest-full-orderbook.html` | https://bybit-exchange.github.io/docs/v5/market/full-ob | `a7f66df4f71573f0cbdf43288349abd19a278237e44694ab4ed5d3802add6c42` |
| `sources/rest-funding-rate-history.html` | https://bybit-exchange.github.io/docs/v5/market/history-fund-rate | `0ca14d23eebd9b2071e098787973b9440e210d3bc3188e97e2d65d1b47cd0345` |
| `sources/rest-historical-volatility.html` | https://bybit-exchange.github.io/docs/v5/market/iv | `2faf2834e0b3dd08e926f358eb347c04b6ef625d2cd894f549f043bcf328cd71` |
| `sources/rest-index-components.html` | https://bybit-exchange.github.io/docs/v5/market/index-components | `96661e2b4bfb945452383c5ef5c25d101c83162b8ed1a2d6049d3254b7fa2420` |
| `sources/rest-index-price-kline.html` | https://bybit-exchange.github.io/docs/v5/market/index-kline | `0a5627af9c1f5a692bf0da129953da4b69da8f7ae8961feaec407cbfd21d76de` |
| `sources/rest-instruments-info.html` | https://bybit-exchange.github.io/docs/v5/market/instrument | `28048953d2291684b3964b199261681db9a10a99cba944b13f46866f700fe47e` |
| `sources/rest-insurance-pool.html` | https://bybit-exchange.github.io/docs/v5/market/insurance | `18a8929e69362b1fedfccfa8aa6f2728cad0a76662644f94ff6a37af90da2111` |
| `sources/rest-kline.html` | https://bybit-exchange.github.io/docs/v5/market/kline | `11640bbcdd67097db60cd3c40ec7abf2dd2b29af1fa53643f020c17f892adcb0` |
| `sources/rest-long-short-ratio.html` | https://bybit-exchange.github.io/docs/v5/market/long-short-ratio | `30c4f8a9ccc03f5619824e2d093f5b719b4893e49e0e940219a9b369916495d8` |
| `sources/rest-mark-price-kline.html` | https://bybit-exchange.github.io/docs/v5/market/mark-kline | `c26685027c96050370f028132a7e3dd348c8f6cb50f09b7309f9e4d4ea455861` |
| `sources/rest-open-interest.html` | https://bybit-exchange.github.io/docs/v5/market/open-interest | `da3e4a9bb0fb683eabcc82ccff730b835d0b912c7e8bf20c99261e1a3d3984e3` |
| `sources/rest-order-price-limit.html` | https://bybit-exchange.github.io/docs/v5/market/order-price-limit | `a6ae77a1362f72a7a81e07699b9e7e884666fac500660857ad764dc009f2e8e7` |
| `sources/rest-orderbook.html` | https://bybit-exchange.github.io/docs/v5/market/orderbook | `5b48a43cc0fe23537516c60190b44485eba5e39eb10b11d9f176877496c0093e` |
| `sources/rest-premium-index-kline.html` | https://bybit-exchange.github.io/docs/v5/market/premium-index-kline | `afe4c36e73df3aa933d7c46f6bbfdd2f708d31d49aa20ada2a0424e94b5678f5` |
| `sources/rest-recent-trades.html` | https://bybit-exchange.github.io/docs/v5/market/recent-trade | `977c6f2084a3a38a29633d50621130513cfc1214cdaf112516e559641b3559fa` |
| `sources/rest-risk-limit.html` | https://bybit-exchange.github.io/docs/v5/market/risk-limit | `e381d28f1fffc07ca6ea5e851e2fab635d18968a3aff97e9336d0b7780b3075a` |
| `sources/rest-rpi-orderbook.html` | https://bybit-exchange.github.io/docs/v5/market/rpi-orderbook | `5e70fd915628b38e25cc79b38efbb55a885dbd682ec687b261b3a6bd0ef459ca` |
| `sources/rest-server-time.html` | https://bybit-exchange.github.io/docs/v5/market/time | `58a95d9e330923f720969c2f9373c88a48c38d40392b75e86636a54ae6562601` |
| `sources/rest-tickers.html` | https://bybit-exchange.github.io/docs/v5/market/tickers | `f86a19117351f5866d863bb9571a6b4cbed0353cd49430e20a897133f05202dd` |
| `sources/system-status.html` | https://bybit-exchange.github.io/docs/v5/system-status | `0a5cb6f0038c7ce9cd9e9ec0b51f1cb4182b6f1bf7a09e2227dc8d29c372cd1d` |
| `sources/v5-changelog.html` | https://bybit-exchange.github.io/docs/changelog/v5 | `f436b0f0e9aba231608ebad2e6691d58db463c2b0e247c4af2c11dae7f999e9f` |
| `sources/ws-adl-alert.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/adl-alert | `89f786734974b9de8ea11ecc77ea5457b8c08aab22d161420b0938393828dcf1` |
| `sources/ws-all-liquidation.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/all-liquidation | `2ea2404c0a325024055b32249b25944022e45eba4cbd06b8c1aaf5c57b625c9e` |
| `sources/ws-connect.html` | https://bybit-exchange.github.io/docs/v5/ws/connect | `7cafb70e506ff5df5d6ca5ca3efe38ecf355d5a21668c2359e9a69ee8918fa94` |
| `sources/ws-full-orderbook.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/full-ob | `71a4568925bdabb45b6fa2d8b2b6b03c9bc9cdcfb1cc9e5a7d48efb48a06c321` |
| `sources/ws-insurance-pool.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/insurance-pool | `713b788acbd3460761077046c3b0bd4526e5f505a8152b4afb3844ee7cde883b` |
| `sources/ws-kline.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/kline | `7525265b51eeb4b8ed1ad745af1d819f2f5d21a1eb82cb89da570dbb5f618064` |
| `sources/ws-order-price-limit.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/order-price-limit | `8b498f38f866b48be4bf047893bb4b28673d693fdf9ffa48f3b7f710729d4873` |
| `sources/ws-orderbook.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/orderbook | `3e17523571c94465f1801e8a19bffc0cdf3de5c055424ab4414835f458bdfd15` |
| `sources/ws-rpi-orderbook.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/orderbook-rpi | `dc9dea5719fc4f9609f266e45cb61bad23f156a987cee010da67b230c7473836` |
| `sources/ws-system-status.html` | https://bybit-exchange.github.io/docs/v5/websocket/system/system-status | `2884ac5482fa80c5b4279b0f163d0ef228b4fcec2144520f656a1a8b852b36cf` |
| `sources/ws-ticker.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/ticker | `49a073353c6a1df679cfb49460cb9b7fcca4d46a516011a393beff90a69c1299` |
| `sources/ws-trade.html` | https://bybit-exchange.github.io/docs/v5/websocket/public/trade | `a140564e4a978b9c083181be91342ceb1b2d478ba4758116801aa4024961dec6` |
