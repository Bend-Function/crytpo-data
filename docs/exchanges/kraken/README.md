# Kraken 公开市场 API 调研快照

- 范围：Kraken Spot + Kraken Derivatives/Futures，仅匿名公开市场数据。
- 抓取时间：截至 `2026-08-08T14:56:28Z`（live JSON 在同一调研时段内抓取）。
- 官方来源：仅 `docs.kraken.com`、`support.kraken.com`、`api.kraken.com`、`futures.kraken.com`。
- 本地 HTML 是官方页面的原始 HTTP 响应；页面引用的 CSS/JS/图片等外链资产没有继续镜像。

## 基址与协议

| 范围 | 基址 | 说明 |
| --- | --- | --- |
| Spot REST | `https://api.kraken.com/0` | 公开端点位于 `/public/*`。 |
| Spot WebSocket v2 | `wss://ws.kraken.com/v2` | 新采集器应使用 v2；v1 仍存在但不是新功能主线。 |
| Futures REST | `https://futures.kraken.com/derivatives/api/v3` | 合约、ticker、order book、成交与资金费率等。 |
| Futures Charts REST | `https://futures.kraken.com/api/charts/v1` | K 线与研究型分桶指标。 |
| Futures WebSocket | `wss://futures.kraken.com/ws/v1` | 这里的 `v1` 是当前 Futures WS 接口名，不等于 Spot 的 legacy v1。 |

## 建议采集矩阵

### Spot

| 数据 | REST | WebSocket v2 | 采集要点 |
| --- | --- | --- | --- |
| 产品目录 | `Assets`, `AssetPairs` | `instrument` | `instrument` 首次给全量 snapshot，之后给 update，适合检测新增/状态变化。 |
| Ticker/24h | `Ticker` | `ticker` | 包含 BBO、last、24h volume/VWAP/high/low/change；WS 默认由成交触发，也可配置 `event_trigger=bbo`。 |
| 成交 | `Trades`, `PostTrade` | `trade` | 逐次撮合事件；一个 WS 消息可以批量包含多笔成交。 |
| L2 order book | `Depth`, `GroupedBook`, `PreTrade` | `book` | WS 可选深度 `10/25/100/500/1000`，snapshot 后接增量并带 top-10 CRC32。 |
| K 线 | `OHLC` | `ohlc` | 原生最小周期为 1 分钟；30 秒必须由 trade 自行确定性聚合。WS 在成交时更新。 |
| Spread/BBO | `Spread` | `ticker(event_trigger=bbo)` | 适合价差、微价格和流动性研究。 |
| 系统状态 | `SystemStatus` | `status` | WS 连接成功及交易引擎状态变化时自动发送。 |

### Futures

| 数据 | REST | WebSocket | 采集要点 |
| --- | --- | --- | --- |
| 产品目录/状态 | `instruments`, `instruments/status` | 无独立目录流 | 轮询并 diff；字段包括 `openingDate`, `lastTradingTime`, `tradeable`, `isExpired`。 |
| Ticker/衍生指标 | `tickers` | `ticker` | WS 增量最多约每 1 秒发布一次；含 BBO、last、24h OHLC/volume、`volumeQuote`、`openInterest`、mark/index、premium、当前/预测 funding。 |
| 成交/清算 | `history` | `trade` | `type` 可区分 `fill`, `liquidation`, `termination`, `block`，可直接保留清算类事件。 |
| L2 order book | `orderbook` | `book` | WS 先发 `book_snapshot`，再发单价位 `book` delta，消息带 `seq`。 |
| 历史资金费率 | `historical-funding-rates` | ticker 提供当前/预测值 | 历史与实时应分别采集。 |
| K 线 | Charts `/{tick_type}/{symbol}/{resolution}` | 无专用 candle feed | `tick_type` 支持 `spot`, `mark`, `trade`；原生最小周期 1 分钟。 |
| 研究型分桶指标 | Charts `/analytics/{symbol}/{analytics_type}` | 无 | 可取 open interest、主动买卖差、成交量/笔数、清算量、波动率、多空比、CVD、top traders、orderbook/spread/liquidity/slippage、basis、funding 等。 |
| 心跳 | 无 | `heartbeat` | 可以显式订阅；另需客户端 ping 保活。 |

Futures Charts 已通过匿名 `open-interest` 实测。它能补足仅保存实时 ticker 时缺少的历史研究指标，但它是交易所预聚合数据，仍应与原始 trade/book 数据分层存储。

## 品种映射与新币发现

不要用字符串替换统一 Kraken 品种名，必须保存协议原生标识并维护目录映射：

- Spot REST 查询 `BTCUSDT` 时，结果 key/`altname` 是 `XBTUSDT`，`wsname` 是 Spot WS v1 风格的 `XBT/USDT`。
- Spot WS v2 使用 `BTC/USDT`；官方说明 v2 用 `BTC` 替代 `XBT`。
- Futures 主力 BTC 永续是 `PF_XBTUSD`，ticker 的 pair 是 `XBT:USD`，而当前 instruments 响应的 base 可能是 `BTC`。
- Futures WS ticker 字段命名混合 snake_case 与 camelCase，例如 `funding_rate`、`markPrice`、`openInterest`；raw 层不得改名。
- 当前 Futures `instruments` 还包含 `Forex`、`xStocks`、`Commodities` 和 `Pre-IPO` 类别；其中部分非加密合约的 `tradfi` 仍为 `false`。加密采集范围必须同时按原生 `category` 排除这些类别，不能只依赖 `tradfi` 或猜测 symbol 后缀。

默认只允许 USDT 报价时，Kraken Spot 的 `BTC/USDT` 可正常入选，但旗舰 Futures `PF_XBTUSD` 会被过滤。配置中应通过固定对绕过默认报价币过滤，或为 Kraken Futures 单独增加 `USD`。

新币/新合约发现建议：

- Spot：首次运行保存 `AssetPairs` 和 WS `instrument` 全量基线；之后以目录 update 和定时 REST diff 产生 `first_seen`。当前公开 schema 不提供可靠的 Spot 上市时间，因此首次基线不能反推历史上市时间。
- Futures：轮询 `instruments` 并 diff，同时使用 `openingDate` 判断是否落在可配置的新合约采集窗口内；用 `lastTradingTime`/`isExpired` 处理到期合约。
- 所有目录变化、状态变化和订阅集合变化都写入 control stream，不能只修改内存集合。

## Order book 拼接与恢复

### Spot WebSocket v2

1. 订阅时请求 snapshot；snapshot 到达前不接受该品种的增量状态。
2. 同一 update 可能对同一价位包含多次修改，必须按消息内顺序全部应用；`qty=0` 删除价位。
3. 每个 update 处理完后裁剪到订阅深度。落出深度的价位不会再收到 `qty=0`。
4. checksum 始终覆盖 asks 低到高的前 10 档，再接 bids 高到低的前 10 档。去掉小数点和前导零后拼接，计算无符号 CRC32。
5. 解析 price/qty 时必须用原始字符串或 `Decimal`，不能先转二进制浮点数再算 checksum。
6. L2 v2 消息没有公开 sequence number；CRC32 是主要完整性校验。checksum 不一致或连接重建时，立刻作废本地 book，记录 control 事件并重新订阅取得新 snapshot。

### Futures WebSocket

1. `book_snapshot` 给出全量 bids/asks 和 `seq`，随后 `book` delta 给出 `side/price/qty/seq`；`qty=0` 删除价位。
2. 官方页面把 `seq` 定义为订阅消息序号，但没有明确写出“每条消息必须严格 +1”，也没有 checksum 字段。因此应保存每个原始 `seq`，监控倒退、重复及不连续现象，并在任何确认的异常或重连后丢弃本地状态、等待新 snapshot。
3. 在没有额外实测确认前，不应把未写入官方契约的 `+1` 假设当成唯一丢包判据。

raw 采集器即使暂不重建 order book，也应记录 snapshot/delta、连接 ID、接收单调时钟和所有 gap/checksum/control 事件，供后处理确定性重放。

## 限流、心跳与连接生命周期

| 范围 | 官方信息 | 实现建议 |
| --- | --- | --- |
| Spot WS | 单 IP 约 150 次连接/重连尝试每滚动 10 分钟；超限会封 10 分钟。约 1 分钟无活动时服务端可关闭连接。 | 指数退避；维护/长停机后最多每 5 秒重连一次。使用 ping，并把自动 status/heartbeat 作为 liveness 信号。 |
| Spot heartbeat | 订阅任意频道后自动生成；没有其他频道更新时约每秒一次。 | 若超过可配置阈值没有任何消息，主动重连并重取 snapshot。 |
| Spot REST | 官方账户级 call counter 为 Starter 15、Intermediate/Pro 20，并按等级衰减；没有给匿名市场请求单独的稳定配额。 | 对 429、`EAPI:Rate limit exceeded`、`EService: Throttled` 自适应退避；对 `EService:Unavailable`、`EService:Busy` 和 `EGeneral:Internal error` 做临时故障 backoff。 |
| Futures REST | 公开端点 cost 为 0；`/derivatives` 受计费调用预算 500/10 秒约束。 | 即使公开请求不计 cost，也要限制并发、处理 429/5xx。 |
| Futures WS | 每客户端最多 100 个并发连接；每连接请求额度 100，每秒补充。 | 批量订阅、限制请求突发，不为每个 symbol 建独立连接。 |
| Futures liveness | 至少每 60 秒发送一次 ping；`heartbeat` feed 的具体发送周期未在当前页面量化。 | 建议约 30 秒主动 ping，并单独设置消息陈旧阈值。 |

Spot/Futures 当前文档都没有声明固定的强制连接寿命。采集器应按长期连接设计，但必须支持服务端关闭、维护、网络中断和无消息超时后的重连与重新订阅。

## 匿名边界与弃用信息

本项目匿名模式排除：

- Spot WS v2 `level3`：虽然列在 public channels 导航下，但订阅明确要求 API token；对应 REST `/private/Level3` 也要求认证。
- Spot 的 balances、executions、交易、资金、账户和私有历史端点。
- Futures 的 balances、fills、open orders/positions、account log、notifications 等 challenge 认证 feed，以及账户、订单、转账等私有 REST。
- 钱包、充值提现和任何会改变交易所状态的接口。

弃用/版本注意事项：

- Spot WS v2 是官方推荐的新集成版本；v1 当前仍维护，但后续增强以 v2 为主。
- Futures WS 的路径仍名为 `/ws/v1`，官方没有把它标为弃用。
- 2026-08-08 匿名负向订阅实测中，无效 Futures product 返回 `event: alert` 和 `message`，而不是文档示例中的 `event: error`；connector 将两者都作为原生订阅错误保留。
- Futures OpenAPI 标注 fee schedule 端点自 `2026-06-22` 起不再反映实际成交费率；这不影响本调研选择的匿名市场数据端点。
- 当前选用的匿名端点没有发现已公告的退役日期。订阅确认中的 `warnings` 仍应原样存储，以捕捉未来变更。

## 本地官方源文件

以下文件均在 `sources/`，SHA-256 对应本次下载内容。

| 文件 | 官方 URL | SHA-256 |
| --- | --- | --- |
| `futures-analytics-open-interest-live.json` | `https://futures.kraken.com/api/charts/v1/analytics/PF_XBTUSD/open-interest?since=1785466800&interval=300` | `138d05036c8b70c88eaaf58cc3505f96ed6a333b66af823cf90fa68b18ed29b8` |
| `futures-charts-rest-openapi.yaml` | `https://docs.kraken.com/openapi/futures-charts-rest.yaml` | `26f2888fb2d26edb472381c3b22ba903450106cb0d34744dc71102d4403b3415` |
| `futures-instruments-live.json` | `https://futures.kraken.com/derivatives/api/v3/instruments` | `da52e638cc5c6431212f55640128f974efb1b154720420d19ff896a54e152d41` |
| `futures-instruments-status-live.json` | `https://futures.kraken.com/derivatives/api/v3/instruments/status` | `26061faa1c2fb358992773405b58afb925e7b2154996cab46eaecbb80e264003` |
| `futures-introduction.html` | `https://docs.kraken.com/exchange/guides/futures/introduction` | `24a0c592e47a76e90d26e6b497aef5850587182b690f509f41f33a5290071cac` |
| `futures-rate-limits.html` | `https://docs.kraken.com/exchange/guides/futures/ratelimits` | `c3812f916f642236093a8cb6f2489481eec608082e3aa4a586d05e526daf4596` |
| `futures-rest-instruments.html` | `https://docs.kraken.com/api-reference/instrument-details/get-instruments` | `9aeb10854a717ba9f31c263c4950afc3811d5edd10632758bffcb499ff217a2b` |
| `futures-rest-market-analytics.html` | `https://docs.kraken.com/api-reference/analytics/market-analytics` | `72d99be2133d1b9ab6a05585f63297d4544212fee9d0a5cb5b4783ac584e5ea8` |
| `futures-rest-market-candles.html` | `https://docs.kraken.com/api-reference/candles/market-candles` | `c9fe03f15e5b88b9d84085c73c76884b7ac36fdf92dec468e68424d90e84a737` |
| `futures-rest-openapi.yaml` | `https://docs.kraken.com/openapi/futures-rest.yaml` | `ac060965738052420a9e2d3f2110d30ac13530578534c4491d537b4a0a17f25d` |
| `futures-ticker-pf_xbtusd.json` | `https://futures.kraken.com/derivatives/api/v3/tickers?symbol=PF_XBTUSD` | `6804669c3503872fe97eadd9d2c01d7c757de4491935845ec814dac1c4067a19` |
| `futures-tickers-live.json` | `https://futures.kraken.com/derivatives/api/v3/tickers` | `5acdd87856f53cce2ca9a6cf743530487007b15d423496072029ba2602da917c` |
| `futures-ws-book.html` | `https://docs.kraken.com/exchange/api-reference/futures-websocket/book` | `18d9e4d2189af4be9ca1326b00aa13771e3c2bc713e4be25960e582cc25d743d` |
| `futures-ws-guide.html` | `https://docs.kraken.com/exchange/guides/futures/websockets` | `9e68b93a2bfef453328a0e185dd804cb5a10cb6417f3e8400644ed907ee770d5` |
| `futures-ws-heartbeat.html` | `https://docs.kraken.com/exchange/api-reference/futures-websocket/heartbeat` | `1ec93f66d73bb6689c5e8c68dbf017cfd4f30a594d05ce9f61a3fde757b1941b` |
| `futures-ws-ticker.html` | `https://docs.kraken.com/exchange/api-reference/futures-websocket/ticker` | `25b7fd5f4aa697e4ce7ff87f2d5f89d7cb9b8c3b131031d82bdcdadb2e6f87a2` |
| `futures-ws-trade.html` | `https://docs.kraken.com/exchange/api-reference/futures-websocket/trade` | `504195cf92da93f143c8f73b3f723d9e43e2353770ebe6f8fbe98e3563f87367` |
| `spot-api-error-messages.html` | `https://support.kraken.com/hc/articles/360001491786-api-error-messages` | `f883ad512106d9e21b61b3e4202391da797c955b4e5f12a877f97aec70afe992` |
| `spot-assetpairs-btcusdt.json` | `https://api.kraken.com/0/public/AssetPairs?pair=BTCUSDT` | `e8d7bbde82050fade08fb26cb6949bff90ce1ed95dea4fc1b276c4d2dcfdca1e` |
| `spot-assetpairs-live.json` | `https://api.kraken.com/0/public/AssetPairs` | `2198a59e9a255153b69bf77d4a0e7b54f1db588cf047262404a1bdb924daab03` |
| `spot-rest-openapi.yaml` | `https://docs.kraken.com/openapi/spot-rest.yaml` | `7f5f7a8328843757adee3bb3b27840134b9edf1c3b282c20b11bae7f87c25a02` |
| `spot-rest-rate-limits.html` | `https://docs.kraken.com/exchange/guides/rest/ratelimits` | `4feb64d200903458f29b4522be7ed0338be47c3185470ef5af79d02a3dff9580` |
| `spot-ws-book-checksum-v2.html` | `https://docs.kraken.com/exchange/guides/websockets/book-checksum-v2` | `c0c9028c20c27bfd68e07c000a6c38a3b38b6f95b75ce14c48dcf873a43d32fd` |
| `spot-ws-introduction.html` | `https://docs.kraken.com/exchange/guides/websockets/introduction` | `0d6e86dc7973dd05cbda0a6cb620eabe69be3898c9a67b1acfd8074d219cbbdd` |
| `spot-ws-v2-book.html` | `https://docs.kraken.com/exchange/api-reference/spot-websocket-v2/book` | `3c93af27374d175a30e35252e29afc000acc2e977611d13889be5b4f958e5d0e` |
| `spot-ws-v2-heartbeat.html` | `https://docs.kraken.com/exchange/api-reference/spot-websocket-v2/heartbeat` | `7aaff9fddefdbc8f0419fd222b14d60fec05944f0166d3c6c2556050363f0f02` |
| `spot-ws-v2-instrument.html` | `https://docs.kraken.com/exchange/api-reference/spot-websocket-v2/instrument` | `a3d6d3efece0692276762960b8a348d8e87a3524920ceae384f8dd0bf9fcfe71` |
| `spot-ws-v2-level3.html` | `https://docs.kraken.com/exchange/api-reference/spot-websocket-v2/level3` | `d4d0d7c5d72cfbb172c7b76aaccf9120d2ea8c7f97c93e75646f04033a6b8882` |
| `spot-ws-v2-ohlc.html` | `https://docs.kraken.com/exchange/api-reference/spot-websocket-v2/ohlc` | `f8cd53405e0174d878b563e1619cda7fc95ca0ffc42e415034d4909555ae1986` |
| `spot-ws-v2-status.html` | `https://docs.kraken.com/exchange/api-reference/spot-websocket-v2/status` | `fd982ef8baaf0c9df7e5a51b1b52f578eeff91213b7cff0ea48a08fdc0419944` |
| `spot-ws-v2-ticker.html` | `https://docs.kraken.com/exchange/api-reference/spot-websocket-v2/ticker` | `8373d589ed96b6e09b299b97559a50c8185973fae5b6f8b3a191be7d91a19c3f` |
| `spot-ws-v2-trade.html` | `https://docs.kraken.com/exchange/api-reference/spot-websocket-v2/trade` | `91c9099ad0f3f315e9182b90e0108b186e37940d15b762758eb56b6d5f3d6990` |

## Smoke 测试

测试文件：`tests/smoke/test_kraken_public_api.py`

```bash
RUN_LIVE_API_TESTS=1 .venv/bin/pytest -q tests/smoke/test_kraken_public_api.py
```

本次结果：`5 passed in 6.51s`。覆盖：

- Spot REST `AssetPairs` 的 BTC/USDT 发现。
- Futures REST `instruments` 的 `PF_XBTUSD` 发现。
- Futures Charts REST open-interest 分桶数据。
- Spot WS v2 `book` 深度 10 snapshot 与 checksum。
- Futures WS `ticker` 的 BBO、mark/index 和 open interest。

当前从新西兰网络出口未观察到地域封锁或认证要求；这不代表其他司法辖区一定可用。测试默认跳过，只有设置 `RUN_LIVE_API_TESTS=1` 才访问公网。
