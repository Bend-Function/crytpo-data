# Bitget public market API notes

检索与实测日期：2026-08-08。范围限定为无需 API key 的公开行情数据，优先使用 Bitget 推荐的 Unified Trading Account (UTA) v3 接口。本文不是交易接口说明。

原始官方页面保存在 [`sources/`](sources/)，URL、UTC 下载时间和 SHA256 见 [`sources/manifest.csv`](sources/manifest.csv)。HTML 是检索时点快照；实现前仍应检查 UTA changelog。

## Production endpoints

| Purpose | Endpoint | Authentication |
| --- | --- | --- |
| REST | `https://api.bitget.com` | 本文列出的 `/api/v3/market/*` 端点无需认证 |
| Public WebSocket | `wss://ws.bitget.com/v3/ws/public` | 无需登录 |
| Demo public WebSocket | `wss://wspap.bitget.com/v3/ws/public` | 仅用于 demo 环境，不用于生产采集 |

2026-08-08 刷新的 UTA guide 新增了需要向 BD/RM 申请的机构 Lo-La 域名。它们不属于默认匿名公共接入面，本项目仍只使用上表 common domain；guide 现在也明确 6,000 requests/IP/min 的总体限制适用于 common domain。

产品类型大小写不同，配置层不要直接复用：REST 使用 `SPOT`、`USDT-FUTURES`；v3 WebSocket 使用 `spot`、`usdt-futures`。Bitget 原生 symbol 为无分隔符大写形式，例如 `BTCUSDT`。

## Instrument and listing discovery

当前有效端点是：

```text
GET /api/v3/market/instruments?category=SPOT
GET /api/v3/market/instruments?category=USDT-FUTURES
```

`symbol` 可选，端点限速为 20 次/秒/IP。采集器可轮询完整列表并关注：

- `symbol`, `category`, `baseCoin`, `quoteCoin`, `type`
- `status`: `listed`, `online`, `limit_open`, `limit_close`, `offline`, `restrictedAPI`
- `launchTime`, `offTime`, `limitOpenTime`, `maintainTime`
- `deliveryStartTime`, `deliveryTime`, `deliveryPeriod`
- `fundInterval`, price/quantity precision and multiplier fields

新币发现建议以 `(category, symbol)` 目录快照差集为主，以 `launchTime` 辅助。`listed` 可作为尚未开放交易的预告，`online` 才表示正常交易。官方示例中 `launchTime` 可能为 `0` 或 `null`，因此不能只靠该字段；缺失时使用本地 `first_seen`。

### Confirmed documentation conflict

以下两份官方说明仍写着不存在的旧路径：

- UTA Best Practices: `GET /api/v3/public/instruments`
- Classic-to-UTA upgrade guide: `GET /api/v3/public/instruments`

但独立的 Get Instruments 页面、curl 示例和线上接口均使用 `/api/v3/market/instruments`。2026-07-31 匿名实测结果：

```text
GET /api/v3/public/instruments?... -> HTTP 404, code 40404, Request URL NOT FOUND
GET /api/v3/market/instruments?... -> HTTP 200, code 00000
```

实现必须使用 `/api/v3/market/instruments`，并为端点漂移保留冒烟测试。

## REST market data

| Data | Request path | Products | Useful fields / notes | Limit |
| --- | --- | --- | --- | --- |
| Instruments | `/api/v3/market/instruments` | Spot, futures | listing state, launch/delist time, precision, funding interval | 20/s/IP |
| Tickers | `/api/v3/market/tickers` | Spot, futures | last, bid/ask, base volume, quote turnover; futures also mark/index/funding/OI | 20/s/IP |
| Order book snapshot | `/api/v3/market/orderbook` | Spot, futures | asks/bids and match-engine `ts`; max requested depth 1000 | 20/s/IP |
| Recent public fills | `/api/v3/market/fills` | Spot, margin, futures | execution IDs, price, size, side, event `ts`, RPI flag; max 100 | 20/s/IP |
| Candles | `/api/v3/market/candles` | Spot, futures | market/mark/index/premium OHLCV; recent window | 20/s/IP |
| Historical candles | `/api/v3/market/history-candles` | Spot, futures | history older than 90 days, each request range at most 90 days | 20/s/IP |
| Open interest | `/api/v3/market/open-interest` | Futures | per-symbol OI and data `ts`; symbol is optional | 20/s/IP |
| Current funding | `/api/v3/market/current-fund-rate` | Futures | rate, 1/2/4/8h interval, next update, min/max rate | 20/s/IP |
| Funding history | `/api/v3/market/history-fund-rate` | Futures | rate and settlement timestamp; page-number cursor | 20/s/IP |
| Index components | `/api/v3/market/index-components` | Futures index | source exchange/pair, equivalent price, weight | 10/s/IP |
| Liquidation history | `/api/v3/market/liquidations` | Futures | delayed, only last 3 days, cursor pagination | 5/s/IP |

Ticker `turnover24h` is quote-currency turnover and is the appropriate field for per-market Top-N selection; `volume24h` is base-asset volume and is not directly comparable across symbols.

The category responses also contain stocks, metals, commodities, and Reality tokens. This collector includes only rows with `symbolType=crypto`; Spot additionally requires `isReality=no`. Known explicit non-target values are excluded. A missing or unknown scope discriminator rejects the complete snapshot instead of silently removing instruments or treating them as cryptocurrency. Bitget defines `offline` as either delisted or under maintenance, so it remains an unknown inactive lifecycle phase instead of being asserted as a delisting.

Candles support intervals `1m`, `3m`, `5m`, `15m`, `30m`, `1H`, `4H`, `6H`, `12H`, `1D`. Anonymous probes on 2026-08-08 accept `market` and `index` for Spot; USDT futures accepts `market`, `mark`, `index`, and `premium`. The recent-candle parameter table still says maximum 100, but the versioned UTA changelog records the 2025-11-28 increase to 1,000 and an anonymous `limit=1000` probe returns 1,000 rows. Use 1,000 for the recent endpoint and retain 100 for historical candles.

## WebSocket public channels

Subscription envelope:

```json
{
  "op": "subscribe",
  "args": [
    {"instType": "spot", "topic": "ticker", "symbol": "BTCUSDT"}
  ]
}
```

| Topic | Scope | Push behavior |
| --- | --- | --- |
| `ticker` | per symbol, spot/futures | event-driven; spot 200-300 ms, futures 300-400 ms |
| `publicTrade` | per symbol, spot/futures | real time; execution/correlation ID, price, size, side, trade time, RPI flag |
| `kline` | per symbol and interval | on trades, once/second; without trades, once per selected interval |
| `books1` | per symbol, spot/futures | one-level snapshot, documented v3 frequency 1 ms |
| `books5` | per symbol, spot/futures | five-level snapshot, 10 ms |
| `books50` | per symbol, spot/futures | 50-level snapshot, 20 ms |
| `books` | per symbol, spot/futures | full-depth snapshot followed by incremental updates, 50 ms |
| `liquidation` | per futures product type, all symbols | once/second; no symbol in subscription |

Futures `ticker` includes `indexPrice`, `markPrice`, `fundingRate`, `nextFundingTime`, and `openInterest`, so one channel provides the continuously changing derivative indicators. Dedicated REST endpoints remain useful for bootstrap, periodic reconciliation, and history.

The liquidation stream is lossy by design: each second contains only the largest long liquidation and largest short liquidation per symbol from the prior second, at most two records per symbol. It covers both UTA and Classic accounts, but it is not a complete liquidation tape. Store the raw event and label this limitation in downstream features.

## WebSocket connection rules

- Maximum 300 connection attempts per IP per 5 minutes and 100 concurrent connections per IP.
- Maximum 240 subscription requests per hour per connection and 1,000 channel subscriptions per connection.
- Bitget recommends fewer than 50 channels per connection for stability.
- Send the literal text `ping` every 30 seconds and expect literal `pong`; reconnect if pong is absent.
- Server disconnects a connection that sends no `ping` for 2 minutes.
- Maximum 10 client messages per second per connection, including ping, login, subscribe and unsubscribe messages.
- The versioned UTA evidence does not substantiate a fixed 24-hour connection lifetime, so the protocol layer does not force one. Ordinary planned/admin reconnect and resubscription remain supported independently.
- REST and WebSocket share rate-limit accounting; the UTA guide also states an overall 6,000 requests/IP/minute ceiling. Individual public REST endpoint limits still apply.

## Full order-book state machine

Use `books` when incremental full depth is required. `books1`, `books5`, and `books50` are independent snapshots and must not be applied as deltas.

1. On `action=snapshot`, replace local asks/bids and store snapshot `seq`.
2. For the first `action=update`, require snapshot `seq` to lie in the inclusive range `[update.pseq, update.seq]`.
3. For every later update, require `update.pseq == previous_update.seq` and a normally increasing `seq`.
4. Treat `pseq=0` as a possible server sequence reset. Discard the derived book and obtain a new snapshot.
5. On a gap, duplicate/out-of-order sequence, disconnect, parse failure, or subscription error, mark the book invalid; reconnect/resubscribe and wait for a new snapshot before publishing derived state.

`maxDepth` can vary by symbol and is documented in the range 0-1000 on the WebSocket depth push. The current UTA instruments response does not expose this field, so it must not be invented during catalog parsing; validate it from the actual `books` stream or a dedicated live probe. The v3 page documents no checksum field and does not explicitly define zero-quantity deletion semantics. Raw collection can preserve messages losslessly, but a later book materializer should validate deletion behavior against captured fixtures before relying on reconstructed state.

The REST order-book snapshot contains no sequence linkage to the WebSocket stream. Do not splice REST asks/bids into `books` updates; use the WebSocket's own initial snapshot for a consistent incremental state.

## Anonymous-only boundary

The tested public REST and v3 public WebSocket endpoints work without API key, signature, login, cookies, account access, or trading permissions. Exclude private account/order/position channels and every `/account/*` or `/trade/*` operation from this collector.

Reality/rToken order-book and fill APIs are whitelist-gated and are outside this anonymous crypto scope. RPI-specific public depth exists separately; the standard `Fills` and `publicTrade` records expose `isRPI`, so downstream analysis must decide whether to include those fills.

## Migration and schema risks

- UTA v3 is marked recommended; Classic v2 remains online and has different WS URLs, subscription keys and payload fields. Do not mix examples across versions.
- The instruments path conflict described above proves guide pages can lag endpoint pages.
- UTA changelog entries were still changing market schemas in July 2026; pin raw payloads and monitor the changelog.
- The former `/api-doc/common/changelog` URL now redirects to the UTA introduction page; it is not retained as changelog evidence and cannot support a 24-hour lifetime claim.
- Classic `books1` had a documented frequency change in January 2026. The UTA v3 depth page still states 1 ms; version-specific docs take precedence.
- Preserve unknown fields and the complete original payload. Do not fail collection when Bitget adds optional fields.
- Treat documented push intervals as targets, not delivery guarantees. Record local receive time and connection/gap events.

## Smoke test

The live test is opt-in so an ordinary offline test run does not contact Bitget:

```bash
RUN_LIVE_API_TESTS=1 .venv/bin/pytest -q tests/smoke/test_bitget_public_api.py
```

It verifies anonymous `BTCUSDT` instrument discovery for both `SPOT` and `USDT-FUTURES`, then connects to the UTA v3 public WebSocket, subscribes to the low-volume spot ticker channel, waits for the subscription acknowledgement and validates one data event before closing safely.
