# OKX V5 public market API notes

This directory is a point-in-time research bundle for the unauthenticated OKX
V5 market-data APIs used by this project. It covers spot and USDT-margined
perpetual data only; it is not an SDK reference and must not be used as a
substitute for checking the live OKX changelog.

## Source provenance

Retrieved at `2026-08-03T12:32:17Z` from OKX-operated domains.

| Local file | Official URL | SHA-256 |
| --- | --- | --- |
| [`sources/api-guide-en.html`](sources/api-guide-en.html) | <https://www.okx.com/docs-v5/en/> | `7b7fa15a91e0f3a86ca81b76aa6fc9d0d114e3dd0ffe98575c24dc4d34bf7331` |
| [`sources/changelog-en.html`](sources/changelog-en.html) | <https://www.okx.com/docs-v5/log_en/> | `a09a8c1fd241176196abec2e0fff1a560da77843194899e4718aafd9123d0295` |

Verify the downloaded originals with:

```bash
shasum -a 256 docs/exchanges/okx/sources/*.html
```

The saved files are complete HTML snapshots, so endpoint examples, response
field definitions, navigation anchors, and the historical changelog remain
available offline. Relevant anchors include:

- `#overview-websocket-connect`
- `#overview-production-trading-services`
- `#order-book-trading-market-data-get-tickers`
- `#order-book-trading-market-data-ws-order-book-channel`
- `#public-data-rest-api-get-instruments`
- `#public-data-websocket-instruments-channel`
- `#public-data-websocket-open-interest-channel`
- `#public-data-websocket-funding-rate-channel`
- `#public-data-websocket-liquidation-orders-channel`
- `#status-ws-status-channel`
- changelog `#2026-08-03`, `#2026-07-28`, and `#2026-06-23`

The 2026-08-03 changelog entry concerns authenticated affiliate endpoints and does
not alter this collector's anonymous market-data contract. The refreshed guide also
removes SWAP-only wording from some `rebase`/`post_only` instrument-state descriptions;
parsers therefore retain those states without assuming they are venue-type exclusive.

## Service endpoints and regional routing

Global production endpoints documented on the retrieval date:

| Service | Base URL |
| --- | --- |
| REST | `https://openapi.okx.com` |
| Public WebSocket | `wss://ws.okx.com:8443/ws/v5/public` |
| Business WebSocket | `wss://ws.okx.com:8443/ws/v5/business` |

The Business WebSocket name does not imply authentication: public candlestick
and unaggregated-trade channels on that path can be subscribed to without a
login. Private/account channels are out of scope.

OKX routes accounts by registration region. The guide says US/AU registrations
must use `us.okx.com` and EU registrations must use `eea.okx.com`, with their
corresponding regional WebSocket hosts. Do not silently fall back across
regions. The smoke test accepts `OKX_REST_BASE_URL` and
`OKX_WS_PUBLIC_URL` overrides so the operator can select the documented host
for the account/installation region.

## Anonymous REST coverage

No `OK-ACCESS-*` headers are required for these public calls. The following are
the main collection inputs for spot and perpetual research.

| Purpose | Request | Documented limit | Notes |
| --- | --- | --- | --- |
| Instrument catalog | `GET /api/v5/public/instruments` | 20 requests / 2 s, IP + instrument type | Query `instType=SPOT` and `instType=SWAP`; optionally filter `instId`. |
| All 24h tickers | `GET /api/v5/market/tickers` | 20 / 2 s, IP | Price, BBO, `vol24h`, `volCcy24h`; query by instrument type. |
| One 24h ticker | `GET /api/v5/market/ticker` | 20 / 2 s, IP | Useful for liveness, not primary high-rate capture. |
| Order-book snapshot | `GET /api/v5/market/books` | 40 / 2 s, IP | Server cache updates every 50 ms; depth up to the endpoint limit. |
| Full order-book snapshot | `GET /api/v5/market/books-full` | 10 / 2 s, IP | Up to 5,000 levels per side, refreshed once per second. |
| RPI consolidated book | `GET /api/v5/market/books-rpi` | See current endpoint section | Added 2026-07-28; up to 400 levels, server refresh 200 ms. |
| Recent trades | `GET /api/v5/market/trades` | 100 / 2 s, IP | Recent transactions only. |
| Trade history | `GET /api/v5/market/history-trades` | 20 / 2 s, IP | Paginated, most recent three months. |
| Recent candles | `GET /api/v5/market/candles` | 40 / 2 s, IP | Latest 1,440 entries. |
| Candle history | `GET /api/v5/market/history-candles` | 20 / 2 s, IP | Recent years; 1-second bars are limited to three months. |
| Funding rate / history | `GET /api/v5/public/funding-rate`, `.../funding-rate-history` | Each 10 / 2 s, IP + instrument | Current rate and up to three months of history. |
| Open interest | `GET /api/v5/public/open-interest` | 20 / 2 s, IP + instrument | Contract OI; preserve both contract and currency units. |
| Mark price | `GET /api/v5/public/mark-price` | 10 / 2 s, IP + instrument | Perpetual/futures reference price. |
| Index ticker | `GET /api/v5/market/index-tickers` | 20 / 2 s, IP | Underlying/index rather than tradeable contract. |
| Premium history | `GET /api/v5/public/premium-history` | 20 / 2 s, IP | Six months documented. |
| Security fund | `GET /api/v5/public/insurance-fund` | 10 / 2 s, IP | Risk context; some types are deprecated. |
| Server time | `GET /api/v5/public/time` | 10 / 2 s, IP | Use for clock-offset monitoring. |
| Platform status | `GET /api/v5/system/status` | 1 / 5 s | Planned upgrade events; short interruptions may be omitted. |

Rate limits are endpoint-specific, and anonymous REST limits are IP-based.
Treat an OKX error payload with code `50011` as throttling even if an upstream
HTTP layer returns a successful HTTP status.

Volume units must remain explicit in the raw data. For spot,
`vol24h` is base-currency quantity and `volCcy24h` is quote-currency quantity.
For derivatives, the guide defines `vol24h` in contracts and `volCcy24h` in
base currency. Convert derivative size using the instrument's `ctVal`,
`ctMult`, `ctValCcy`, and `ctType`, not a spot-size assumption.

## Anonymous WebSocket channels

### Common spot and perpetual channels

| Channel | Path | Push behavior | Collection note |
| --- | --- | --- | --- |
| `tickers` | public | Fastest 100 ms, only after trade or BBO change | Last/BBO/24h volume. |
| `trades` | public | On trades; one update can aggregate matches | `count` reports aggregated match count; this is not one row per match. |
| `trades-all` | business | On trades; one trade per update | Prefer when exact unaggregated public trades are required. |
| `candle<bar>` | business | Fastest one second | Exchange-provided bars; raw trades remain the primary source for custom bars. |
| `books` | public | Full 400-level snapshot, then 100 ms deltas | Best anonymous incremental organic book. |
| `books5` | public | Five-level snapshots, at most every 100 ms on change | No delta reconstruction required. |
| `bbo-tbt` | public | One-level snapshots, at most every 10 ms on change | Lowest-load top-of-book alternative. |
| `books-rpi` | public | Full 400-level snapshot, then 100 ms deltas | Added 2026-07-28; organic + RPI; different level schema. |
| `instruments` | public | Initial data plus changes to listings/state/parameters/times | Subscribe separately for `SPOT` and `SWAP`. |
| `status` | public | Initial latest change, then maintenance changes | Does not announce every sub-five-second interruption. |

The ordinary `books` family excludes RPI orders. `books-rpi` returns each level
as `[price, totalQty, nonRpiQty, count]`; ordinary books use
`[price, quantity, deprecatedField, count]`, where the deprecated field is
always `0`.

### Perpetual-specific public data

| Channel | Path | Push behavior | Notes |
| --- | --- | --- | --- |
| `open-interest` | public | Every 3 s when updated | Preserve OI unit fields and contract metadata. |
| `funding-rate` | public | Every 30-90 s | Includes current/next funding timing and rate fields. |
| `mark-price` | public | Every 200 ms on change; otherwise every 10 s | Contract mark price. |
| `index-tickers` | public | Every 100 ms on change; otherwise once per minute | Subscribe by index ID such as `BTC-USDT`. |
| `price-limit` | public | Every 200 ms on change | Maximum buy/minimum sell limits. |
| `mark-price-candle<bar>` | business | Fastest one second | Mark-price OHLCV series. |
| `index-candle<bar>` | business | Fastest one second | Index OHLCV series. |
| `liquidation-orders` | public | Event-driven | Explicitly documented as incomplete liquidation coverage. |
| `adl-warning` | public | Once per second only in warning/ADL state | No message in normal state. |

Do not interpret silence from `liquidation-orders` or `adl-warning` as zero
events/risk. The former is explicitly not the total liquidation population and
the latter is silent in normal state.

### Anonymous exclusions

- `books-l2-tbt` (400 levels, 10 ms) and `books50-l2-tbt` (50 levels,
  10 ms) require WebSocket identity verification and VIP4 or above. They are
  public-market data but are **not anonymous**, so this project must not select
  them under its no-key configuration.
- Account, positions, orders, balance, liquidation-warning for one's own
  account, and all trading operations require login and are out of scope.
- The demo endpoints and `x-simulated-trading` header are irrelevant to this
  read-only production collector.

## WebSocket limits, heartbeat, and lifetime

- Connection establishment is limited to 3 requests/s per IP.
- A connection may send at most 480 combined `subscribe`, `unsubscribe`, and
  `login` operations per hour.
- Subscription argument payloads must stay within the guide's 64 KiB limit.
- If no subscription is established or no data is pushed for more than 30 s,
  the connection can be closed. After less than 30 s of silence, send the text
  frame `ping` and require a text `pong`; reconnect when the response misses the
  same bounded deadline.
- The captured guide does not specify a fixed maximum connection lifetime.
  It does specify service-upgrade notice code `64008`, normally sent 60 s
  before closure. Open a replacement connection and resubscribe before retiring
  the old one.
- Keep connection IDs and subscribe/error/notice/ping/pong messages in a
  control stream. Reconnect with bounded exponential backoff plus jitter and
  rebuild every stateful book from a new snapshot.

The documented 30-connection-per-channel rule is described for named private
channels. It should not be treated as a general public-channel capacity promise;
shard large public subscriptions conservatively and observe live errors.

## Order-book reconstruction and gap recovery

For the anonymous incremental `books` stream:

1. Subscribe and wait for `action: snapshot`. Replace both sides completely,
   sort bids descending and asks ascending, and set `last_seq_id = seqId`.
2. For an `action: update`, interpret quantity `0` as deletion and a positive
   quantity as insert/replace at that price. Apply all changes atomically.
3. Under normal sequencing, require `update.prevSeqId == last_seq_id`, then set
   `last_seq_id = update.seqId`.
4. An empty update can be a heartbeat with `prevSeqId == seqId == last_seq_id`.
   It is valid and must not be classified as a gap.
5. A maintenance reset can have `prevSeqId == last_seq_id` but
   `seqId < prevSeqId`. Apply that update and continue from the lower new
   sequence; the decrease alone is not a gap.
6. Any other `prevSeqId != last_seq_id`, malformed update, crossed book outside
   documented pre-open behavior, or transport loss makes the local book
   untrusted. Stop publishing derived book state, reconnect/resubscribe, and
   wait for a fresh snapshot. Never patch a missing range with a REST snapshot
   while old WebSocket deltas continue.

As of the 2026-06-23 changelog, `checksum` in `books`, `books-l2-tbt`, and
`books50-l2-tbt` is fixed to `0` and **must not** be used for integrity checks.
Continuity uses `seqId/prevSeqId`. `books5` and `bbo-tbt` are snapshot channels
and do not carry checksum. `books-rpi` also has no checksum.

## Instrument discovery and new listings

Use a REST snapshot plus a live change stream:

1. Poll `GET /api/v5/public/instruments?instType=SPOT` and `instType=SWAP` for
   reconciliation and startup baseline.
2. Subscribe to `instruments` once per instrument type. It emits new pairs,
   status changes, suspension/delivery, `tickSz`/`minSz`/`maxMktSz` changes,
   and changes to `listTime` or `expTime`.
3. Key instruments by native `instId`. Filter the spot quote with `quoteCcy`
   and linear USDT swaps with `settleCcy`, `ctType`, and `instFamily`; do not
   infer type only from string suffixes.
4. Persist `listTime`, `contTdSwTime`, `preMktSwTime`, `openType`, `state`, and
   `ruleType`. For auction/pre-open listings, `listTime` can be the auction or
   pre-open start while `contTdSwTime` marks continuous trading.
5. Start the configurable new-listing capture window from the intended semantic
   time (listing/pre-open vs continuous trading), and record that choice. On a
   first run, use returned official timestamps when they fall in the configured
   lookback; otherwise baseline the catalog and detect later changes.

`state=preopen` normally transitions to `live` at `listTime`, but consumers
should still use the actual state event. A product approaching delisting may
disappear from the current open-instrument list, so retain historical catalog
records and reconcile state rather than deleting metadata.

## Current deprecations and migration risks

- **2026-06-23:** order-book checksum integrity was removed; use sequence IDs.
- **2026-07-28:** ELP was renamed to RPI. `books-rpi` supersedes `books-elp`;
  both names coexist only until the documented 2026-10-31 sunset. New code
  should use RPI names.
- `auctionEndTime` is deprecated; use `contTdSwTime`.
- Instrument `category` is deprecated. Futures `alias` is deprecated; use
  `expTime` rather than relying on calendar aliases.
- Security-fund `adl` and `platform_revenue` types are deprecated and return
  empty values; `regular_update` was removed.
- Regional base domains and channel entitlements can differ. Capture error
  events and the source host in every connection manifest.

## Live smoke test

The test is opt-in so routine offline test runs do not unexpectedly contact an
exchange. It performs only anonymous reads:

```bash
RUN_LIVE_API_TESTS=1 .venv/bin/pytest -q \
  tests/smoke/test_okx_public_api.py
```

For a regional installation:

```bash
OKX_REST_BASE_URL=https://REGIONAL_HOST \
OKX_WS_PUBLIC_URL=wss://REGIONAL_WS_HOST/ws/v5/public \
RUN_LIVE_API_TESTS=1 .venv/bin/pytest -q \
  tests/smoke/test_okx_public_api.py
```

The test checks public instrument metadata and ticker data for `BTC-USDT`
(spot) and `BTC-USDT-SWAP` (linear perpetual), then receives ticker data for
both subscriptions over one WebSocket connection. It sends no credentials and
has no write/trade path.
