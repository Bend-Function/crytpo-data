# Important WebSocket Change Notice — Base URL Split & Migration

## Background

Due to sustained heavy traffic, we have upgraded the WebSocket URL structure by introducing a
**root** plus dedicated entry points for **Public / Market / Private** traffic. This separation
improves stability, scalability, and operational isolation across different data types.

## What’s New

- **3 new WebSocket base URLs (Root + routed paths)**
  - Public (high-frequency public market data): `wss://fstream.binance.com/public`
  - Market (regular market data): `wss://fstream.binance.com/market`
  - Private (user data): `wss://fstream.binance.com/private`
- **Two access modes are supported**
  - `ws` mode: streams are composed in the URL path
  - `stream` mode: streams are passed via query (e.g., `?streams=`) — private uses
    `listenKey/events`
- **Combined streams remain supported**
- **Private supports listenKey + events subscription (multiple listenKeys and multiple events)**

## Examples

### Public / Market: combined subscriptions

- `ws` mode (path-based)
  - `wss://fstream.binance.com/public/ws/bnbusdt@depth/ethusdt@depth`
  - `wss://fstream.binance.com/market/ws/btcusdt@aggTrade/ethusdt@aggTrade`
- `stream` mode (query-based)
  - `wss://fstream.binance.com/market/stream?streams=bnbusdt@aggTrade/btcusdt@markPrice`
  - `wss://fstream.binance.com/public/stream?streams=btcusdt@depth/ethusdt@depth`

### Private: listenKey & events

- `ws` mode (listenKey + events)
  - `wss://fstream.binance.com/private/ws?listenKey=<listenKey1>&events=ORDER_TRADE_UPDATE/ACCOUNT_UPDATE`
- `stream` mode (multiple listenKeys + events)
  - `wss://fstream.binance.com/private/stream?listenKey=<listenKey1>&events=ORDER_TRADE_UPDATE&listenKey=<listenKey2>&events=ACCOUNT_UPDATE`

> JSON `SUBSCRIBE` is also supported; params may include market/public streams and listenKey event
> items.

## Endpoint & Stream Mapping (Excerpt)

### Public (high-frequency public data)

- Individual Symbol Book Ticker: `<symbol>@bookTicker`
- All Book Tickers: `!bookTicker`
- Partial Book Depth: `<symbol>@depth<levels>` (supports `@500ms` / `@100ms`)
- Diff. Book Depth: `<symbol>@depth` (supports `@500ms` / `@100ms`)

### Market (regular market data)

- Aggregate Trades: `<symbol>@aggTrade`
- Mark Price: `<symbol>@markPrice` or `<symbol>@markPrice@1s`
- Mark Price (All market): `!markPrice@arr` or `!markPrice@arr@1s`
- Kline/Candlestick: `<symbol>@kline_<interval>`
- Continuous Kline: `<pair>_<contractType>@continuousKline_<interval>`
- Mini Ticker: `<symbol>@miniTicker`; All: `!miniTicker@arr`
- Ticker: `<symbol>@ticker`; All: `!ticker@arr`
- Liquidations: `<symbol>@forceOrder`; All: `!forceOrder@arr`
- Composite Index: `<symbol>@compositeIndex`
- Contract Info: `!contractInfo`
- Multi-Assets Mode Asset Index: `!assetIndex@arr` or `<assetSymbol>@assetIndex`

## Compatibility & Migration Guidance

- **Legacy URLs will remain available until 2026-04-23**, after which they will be permanently
  decommissioned. Users are strongly encouraged to migrate to the new `/public`, `/market`,
  `/private` endpoints before this date.
- **After the upgrade, any connections not migrated will ONLY be able to receive data from
  `wss://fstream.binance.com/public`. Channels under `/market` and `/private` will stop pushing
  data.** For example, `wss://fstream.binance.com/ws/btcusdt@depth` will continue to work, but
  `wss://fstream.binance.com/ws/btcusdt@markPrice` will not.
- Recommended migration order:
  1. High-frequency order book & core public feeds → `/public`
  2. Regular market feeds (markPrice/kline/ticker, etc.) → `/market`
  3. User data feeds (listenKey-based) → `/private`
- Client / SDK recommendations:
  - Split connections by traffic type (separate public/market/private sessions) to reduce
    per-connection load and jitter.
  - For combined subscriptions, prefer `stream` mode (`?streams=`; private uses listenKey/events).

## Action Required

- Update your WebSocket configuration:
  - Switch base URLs to `/public`, `/market`, `/private`
  - Ensure each stream is subscribed via the correct endpoint category
- **Complete migration before 2026-04-23.** After this date, legacy URLs
  (`wss://fstream.binance.com/ws`, `wss://fstream.binance.com/stream`) will no longer be available.
