# Binance public market API notes

检索日期：**2026-07-31**。本文只覆盖 Binance Spot 与 USDⓈ-M linear perpetual 的公共市场数据，
不包含下单、账户、仓位或用户数据流。所有获取时间均为 UTC。

## 本地原始资料

Spot GitHub 资料固定在 `binance/binance-spot-api-docs@6b8372cad7cecbdf5dd88a3372eafff51988c5cf`；
Futures SDK 资料固定在 `binance/binance-connector-python@06d24c98db24248f26a1cf8bd403b62fa7e619fa`。
固定 commit 是为了让归档可复现；运行时契约仍应以最新官方文档和 `exchangeInfo` 为准。

| 本地文件 | 官方 URL | 获取时间 | SHA256 |
| --- | --- | --- | --- |
| [`spot-rest-public-market.md`](sources/spot-rest-public-market.md) | [official `rest-api.md`](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/rest-api.md) | 2026-07-31T04:05:56Z | `51c5375fc2e763d542301a9a6fc6f36a259f572c9cab5abc6c9fc4da85e62038` |
| [`spot-websocket-streams.md`](sources/spot-websocket-streams.md) | [official `web-socket-streams.md`](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/web-socket-streams.md) | 2026-07-31T04:05:56Z | `32bf73a0bed3b75e3ca981fdbaf48c53544bbdfb5944ef8ed1c4d7af9aceba0a` |
| [`spot-market-data-only.md`](sources/spot-market-data-only.md) | [official market-data-only FAQ](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/faqs/market_data_only.md) | 2026-07-31T04:05:56Z | `57d608507426215c43f11907c07ed693f02725840d9ee4d6630f134de402b6da` |
| [`spot-filters.md`](sources/spot-filters.md) | [official filters](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/filters.md) | 2026-07-31T04:05:56Z | `4b5a8f0f5d15bcf68fd7ac2059ba6c88da641c06fd7885e642330c5ac8124dd3` |
| [`spot-enums.md`](sources/spot-enums.md) | [official enums](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/enums.md) | 2026-07-31T04:05:56Z | `5708fe6fdea8013f6c8a8388074c8cef8482b2b69a09181e4b2b36e0c2b4ab4b` |
| [`futures-general-info.md`](sources/futures-general-info.md) | [official general info](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/general-info.md) | 2026-07-31T04:05:56Z | `9bbf9295ed57922ce1dc49a1e025400076cc0539329a2a820b3a93b253b255ff` |
| [`futures-common-definition.md`](sources/futures-common-definition.md) | [official common definitions](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/common-definition.md) | 2026-07-31T04:05:56Z | `52706283c94a7b6c80714aee009e4c9bf1b367979612903753e52bd935c878d1` |
| [`futures-rest-market-data-sdk.py`](sources/futures-rest-market-data-sdk.py) | [official generated market-data client](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/api/market_data_api.py) | 2026-07-31T04:05:56Z | `6a5f6f45fb80e73b1bf09c24ccbf7a45dbb1604fbad2e163847d3379a456cd05` |
| [`futures-ws-connect.md`](sources/futures-ws-connect.md) | [official connect rules](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/websocket-market-streams/Connect.md) | 2026-07-31T04:05:56Z | `912f2dad9da21b5c1801d73f052473b6a1d7136a43b2ff3e7a1c2cdc54abdde2` |
| [`futures-ws-migration.md`](sources/futures-ws-migration.md) | [official 2026 routed-URL migration notice](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/websocket-market-streams/Important-WebSocket-Change-Notice.md) | 2026-07-31T04:05:56Z | `7711169f43066cb169fa40d90193731630ffca43dc2c04a2c753a5814b596f5c` |
| [`futures-ws-subscriptions.md`](sources/futures-ws-subscriptions.md) | [official subscription protocol](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/websocket-market-streams/Live-Subscribing-Unsubscribing-to-streams.md) | 2026-07-31T04:05:56Z | `3aca01db3fa5d7d2f79f90236311d251555c15f8bc3833acc7ed38ab744ec418` |
| [`futures-orderbook-sync.md`](sources/futures-orderbook-sync.md) | [official local-book procedure](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/websocket-market-streams/How-to-manage-a-local-order-book-correctly.md) | 2026-07-31T04:05:56Z | `d6a94d17fb32450c67ad598c0f923bf9df12ecdc43ced4928798a9fa56d62622` |
| [`futures-ws-market-sdk.py`](sources/futures-ws-market-sdk.py) | [official routed `market` streams](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/websocket_streams/streams/market_api.py) | 2026-07-31T04:05:56Z | `6b0a7c5d68ab39b849f027b43a6d51fcc624cf1ce73ba9983dd25b6b2493b196` |
| [`futures-ws-public-sdk.py`](sources/futures-ws-public-sdk.py) | [official routed `public` streams](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/websocket_streams/streams/public_api.py) | 2026-07-31T04:05:56Z | `5ed435cc9201faddb3d074d8ac65277671b2fc110912dcf59b9ffd74ec40149d` |

`spot-rest-public-market.md` 是上游文件中通用 REST 规则、`exchangeInfo` 和所需行情端点的逐字节
节选；`futures-general-info.md` 是上游页面中 base URL、HTTP/IP 限流和安全类型的逐字节节选。
这样保留官方原文，同时不镜像同页的下单签名示例。其余文件是对应 URL 的完整响应。

## Base URL 与鉴权边界

| 市场 | REST | WebSocket 市场流 |
| --- | --- | --- |
| Spot | 纯行情优先 `https://data-api.binance.vision`；通用生产入口为 `https://api.binance.com`、`api-gcp.binance.com` 和 `api1` 至 `api4.binance.com`，后四个较快但稳定性较低 | `wss://stream.binance.com:9443` 或 `:443`；纯行情也可用 `wss://data-stream.binance.vision:443`。原始流 `/ws/<stream>`，组合流 `/stream?streams=<a>/<b>` |
| USDⓈ-M Futures | `https://fapi.binance.com` | 根为 `wss://fstream.binance.com`。订单簿/最优价使用 `/public`，常规行情使用 `/market`；原始流 `/<route>/ws/<stream>`，组合流 `/<route>/stream?streams=<a>/<b>` |

下列 REST 表中除明确标注者外均为安全类型 `NONE`，不需要 API key、签名、`timestamp` 或
`recvWindow`。WS 表只列公开市场流。Spot stream symbol 必须小写；Futures 同样应使用小写 stream name。

## REST 公共端点

### Spot

| 用途 | 端点 | 当前限制与语义 |
| --- | --- | --- |
| 标的发现 | `GET /api/v3/exchangeInfo` | 权重 20；支持 `symbol`、`symbols`、`permissions`、`symbolStatus`；返回状态、资产、过滤器和实时 `rateLimits` |
| 最近/历史成交 | `GET /api/v3/trades`、`GET /api/v3/historicalTrades` | 各权重 25；limit 默认 500、最大 1000；前者来自 Memory，后者来自 Database。`historicalTrades` 当前为 `NONE`，但不在 `data-api` 白名单，应走通用 API host |
| 聚合成交 | `GET /api/v3/aggTrades` | 权重 4；limit 默认 500、最大 1000；`fromId`、`startTime`、`endTime` 为 inclusive |
| K 线 | `GET /api/v3/klines` | 权重 2；limit 默认 500、最大 1000；支持 `1s` 到 `1M`；`timeZone` 只改变分桶边界，起止参数仍按 UTC |
| 深度快照 | `GET /api/v3/depth` | limit 默认 100、最大 5000；limit `1-100/101-500/501-1000/1001-5000` 的权重为 `5/25/50/250` |
| ticker | `GET /api/v3/ticker/24hr` | 单 symbol 或 1-20 symbols 权重 2；21-100 为 40；全市场或 101+ 为 80；24 小时滚动窗口，不是 UTC 自然日 |
| 最新价/最优价 | `GET /api/v3/ticker/price`、`GET /api/v3/ticker/bookTicker` | 单 symbol 权重 2；多 symbol 或全市场权重 4；返回中没有交易所事件时间 |

不要用 `pricePrecision` 或 `quantityPrecision` 推导下单步长；数据规范也应从
`exchangeInfo.filters` 的 `tickSize`/`stepSize` 读取。本文虽不下单，统一采用过滤器可避免精度
解释与交易所元数据脱节。

### USDⓈ-M perpetual

| 用途 | 端点 | 当前限制与语义 |
| --- | --- | --- |
| 标的发现 | `GET /fapi/v1/exchangeInfo` | 权重 1；返回合约类型、状态、资产、过滤器和实时 `rateLimits`。响应中的示例 `serverTime` 不保证当前，时钟同步用 `/fapi/v1/time` |
| 最近成交 | `GET /fapi/v1/trades` | 权重 5；limit 默认 500、最大 1000；不含保险基金和 ADL 成交 |
| 聚合成交 | `GET /fapi/v1/aggTrades` | 权重 20；limit 默认 500、最大 1000；时间区间小于 1 小时，不与 `fromId` 混用 |
| K 线 | `GET /fapi/v1/klines` | 最大 1500；limit `[1,100)/[100,500)/[500,1000]/>1000` 的权重为 `1/2/5/10` |
| 指数/标记/溢价 K 线 | `/fapi/v1/indexPriceKlines`、`markPriceKlines`、`premiumIndexKlines` | 与普通 K 线相同的 limit 权重阶梯；分别用 `pair` 或 `symbol` |
| 深度快照 | `GET /fapi/v1/depth` | limit `5,10,20,50/100/500/1000` 的权重为 `2/5/10/20`；不包含 RPI 订单 |
| ticker | `GET /fapi/v1/ticker/24hr` | 单 symbol 权重 1，全市场 40 |
| 最新价/最优价 | `GET /fapi/v2/ticker/price`、`GET /fapi/v1/ticker/bookTicker` | 单 symbol 权重 1/2，全市场 2/5；官方说明这两个响应的 `X-MBX-USED-WEIGHT-1M` 不准确 |
| 标记价、指数价、资金费率 | `GET /fapi/v1/premiumIndex` | 单 symbol 权重 1，全市场 10；同一响应含 `markPrice`、`indexPrice`、最近费率与下一结算时间 |
| 资金费率历史/配置 | `GET /fapi/v1/fundingRate`、`GET /fapi/v1/fundingInfo` | 共享每 IP 每 5 分钟 500 次专有限额；后者权重 0，只返回有调整的标的 |
| 当前/历史 OI | `GET /fapi/v1/openInterest`、`GET /futures/data/openInterestHist` | 当前值权重 1；历史值权重 0，但另有每 IP 每 5 分钟 1000 次限制，只保留最近一个月 |

所有 REST 权重按 IP 累计。读取 `X-MBX-USED-WEIGHT-*`，遇到 429 必须按 `Retry-After`
退避；继续请求会触发 418，重复封禁可从 2 分钟增长到 3 天。`exchangeInfo.rateLimits` 是
运行时权威值；检索日 Spot/Futures 分别发布了 6000/2400 `REQUEST_WEIGHT` 每分钟，但不要硬编码。

## WebSocket 公共频道

### Spot

| 数据 | stream | 推送频率 |
| --- | --- | --- |
| 聚合/逐笔成交 | `<symbol>@aggTrade`、`<symbol>@trade` | 实时 |
| K 线 | `<symbol>@kline_<interval>` | `1s` K 线每 1000ms，其他周期每 2000ms |
| 单标的 ticker | `<symbol>@miniTicker`、`<symbol>@ticker` | 1000ms，均为滚动 24 小时 |
| 最优买卖 | `<symbol>@bookTicker` | 实时 |
| 部分深度 | `<symbol>@depth5|10|20`，可加 `@100ms` | 默认 1000ms 或 100ms |
| 差量深度 | `<symbol>@depth`，可加 `@100ms` | 默认 1000ms 或 100ms |

`!miniTicker@arr` 只包含发生变化的标的，不能充当完整标的快照。旧全市场
`!ticker@arr` 和 `!bookTicker` 不应作为当前集成依赖。

### USDⓈ-M perpetual

| route | 数据 | stream | 推送频率 |
| --- | --- | --- | --- |
| `market` | 聚合成交 | `<symbol>@aggTrade` | 100ms |
| `market` | K 线 | `<symbol>@kline_<interval>` | 250ms（有更新时） |
| `market` | 单标的 ticker | `<symbol>@miniTicker`、`<symbol>@ticker` | 2000ms |
| `market` | 标记价/指数价/费率 | `<symbol>@markPrice` 或 `@markPrice@1s` | 默认 3s 或 1s；payload 含 index price 和下一 funding time |
| `market` | 指数构成 | `<symbol>@compositeIndex` | 1000ms |
| `market` | 强平快照 | `<symbol>@forceOrder`、`!forceOrder@arr` | 1000ms；每个标的每窗口只推最后一笔，不能当完整强平流水 |
| `market` | 合约变更 | `!contractInfo` | 实时；listing、settlement、bracket 更新 |
| `public` | 最优买卖 | `<symbol>@bookTicker` | 实时 |
| `public` | 部分深度 | `<symbol>@depth<5|10|20>`，可加 `@500ms`/`@100ms` | 默认 250ms、500ms 或 100ms |
| `public` | 差量深度 | `<symbol>@depth`，可加 `@500ms`/`@100ms` | 默认 250ms、500ms 或 100ms |

当前官方 USDⓈ-M 市场流没有 open-interest stream；OI 走 REST。Futures 的逐笔公共流为
`aggTrade`，而原始最近成交由 REST `/fapi/v1/trades` 提供。

## 连接生命周期与心跳

Spot 单连接最多 24 小时；服务端每 20 秒发送 Ping，1 分钟内必须返回带相同 payload 的
Pong。每连接每秒最多 5 条客户端入站消息（包括 Ping、Pong、订阅控制消息），最多 1024 个
streams；每 IP 每 5 分钟最多 300 次连接尝试。支持 `SUBSCRIBE`、`UNSUBSCRIBE`、
`LIST_SUBSCRIPTIONS`、`SET_PROPERTY`、`GET_PROPERTY`，组合流外层为
`{"stream":"...","data":...}`。收到 `serverShutdown` 应立即迁移连接。

Futures 同样在 24 小时处断开；服务端每 3 分钟 Ping，10 分钟未收到 Pong 会断开。每连接每秒
最多 10 条客户端入站消息，最多 1024 个 streams。客户端库应自动响应协议级 Ping，并在 24 小时
前主动轮换，使用带抖动的指数退避重连，重连后重新订阅和重建 order book。

## Order book 快照与增量

Spot：先连接 diff stream 并缓存事件，再取 limit 5000 的 REST 快照。若快照
`lastUpdateId < first U`，重取快照；丢弃所有 `u <= lastUpdateId` 的缓存事件，首个保留事件必须
覆盖快照 update ID。后续 `u < localId` 可忽略，`U > localId + 1` 表示 gap，必须丢弃本地簿并
从头重建。通常下一事件的 `U == previous u + 1`。

Futures：先缓存 `/public` diff stream，再取 limit 1000 的快照；丢弃 `u < lastUpdateId`，首个
事件需满足 `U <= lastUpdateId <= u`。进入实时阶段后，每个事件的 `pu` 必须等于前一事件的
`u`；否则从 REST 快照重新开始。两类市场的数量都是价位绝对值而非 delta：数量为零即删除，
删除不存在价位属于正常情况。Spot 快照每侧最多 5000 档，范围外价位在首次变化前状态未知。

Partial depth 与 `bookTicker` 都不能替代 snapshot + diff 的本地全簿流程。重连、超时、解析失败、
sequence gap 或切换 symbol metadata 版本都应触发恢复，而不是猜测缺失增量。

## 新币与交易对发现

Spot 没有专用 listing stream。定期轮询 `/api/v3/exchangeInfo`，按 `status`、`permissions` 和
`isSpotTradingAllowed` 过滤，再与已知 symbol 集合做差分；数组 ticker 只能作为成交后的提示，
不能保证预上市、完整集合或下架通知。解析状态时允许未知枚举，当前已包括 `CANCEL_ONLY`。

Futures 以 `/fapi/v1/exchangeInfo` 为基线，至少过滤 `contractType == PERPETUAL`、
`status == TRADING` 和期望的结算/报价资产；`PENDING_TRADING` 可用于预热但不能作为可交易标的。
再用 `!contractInfo` 降低发现延迟，任何事件后仍以新的 `exchangeInfo` 快照确认。

2026-06-30 CM-UM integration 后，部分 `/fapi` K 线和 `fstream`/`dstream` 全市场流可混合 UM 与
CM；新 payload 可能有 `st`（`1`=UM、`2`=CM）和 `ps`。因此不能只凭 host/path 判断 linear，
应使用 `st` 和 `exchangeInfo` 元数据双重过滤，共享限频池也要统一计数。

## 时间字段语义

| 接口/字段 | 语义 |
| --- | --- |
| Spot REST | JSON 时间默认 Unix 毫秒；`X-MBX-TIME-UNIT: MICROSECOND` 可请求微秒。`startTime`/`endTime` 可传毫秒或微秒 |
| Spot trade WS | `E` 是事件时间，`T` 是成交时间；逐笔的 `t` 是 trade ID，不是时间 |
| Spot kline | `k.t`/`k.T` 是分桶开/闭时间，`k.x` 表示是否闭合；即使使用 UTC+8 分桶，时间戳仍按 UTC Unix 解释 |
| Spot ticker | `E` 是事件时间，`O`/`C` 是滚动统计窗口边界；`bookTicker` 和 REST price/bookTicker 没有事件时间 |
| Futures REST | 所有时间戳为 Unix 毫秒；成交 `time`、aggTrade `T`、K 线 `[0]`/`[6]` 为开/闭时间 |
| Futures mark/funding/OI | `premiumIndex.time` 是快照时间，`nextFundingTime` 是下一结算点；历史费率 `fundingTime` 是结算事件；当前 OI 的 `time` 是快照时间，历史 OI 的 `timestamp` 是周期时间 |
| Futures WS | `E` 是事件时间，成交/强平内部 `T` 是成交时间；kline `k.t`/`k.T` 是开/闭时间；mark-price `T` 是下一 funding time |

客户端接收时间只能单独记为 ingestion time，不能覆盖或伪装成交易所 event/trade time。

## 明确排除与弃用风险

- 排除 Spot/Futures 下单、账户、仓位、listenKey/user-data stream、`/private` route 和 WebSocket
  API 交易请求。live smoke tests 只执行匿名 GET 与公共流订阅，不发送订单。
- Spot `/api/v3/historicalBlockTrades` 需要 API key，不属于本文匿名成交范围。
- Futures `/fapi/v1/historicalTrades` 是 `MARKET_DATA`，需要 `X-MBX-APIKEY`；
  `/fapi/v1/forceOrders` 是签名 `USER_DATA`。旧匿名 `/fapi/v1/allForceOrders` 已停止维护，当前
  没有匿名 REST 强平替代，使用有损的 `forceOrder` WS 快照。
- Spot `/api/v1` 行情端点已于 2026-03-25 退役；使用 `/api/v3`。旧 `data.binance.com` 已弃用，
  使用 `data-api.binance.vision`。
- Futures `/fapi/v1/ticker/price` 已标记弃用，使用 `/fapi/v2/ticker/price`。
- Futures 旧未路由 WS URL 的迁移截止日是 2026-04-23。当前 Connect 页仍描述未路由连接仅接收
  `public` 数据，而迁移公告称旧 URL 将下线；集成必须使用显式 `/public` 或 `/market`，不依赖
  这个冲突行为。
- OpenAPI/SDK 标称版本 `1.0.0` 不代表语义冻结。2026-07 的资金费率字段、历史保留期和 CM-UM
  合并仍在变化；解析器应容忍新增字段/枚举，并定期重抓官方文档、变更日志和运行时
  `exchangeInfo`。
