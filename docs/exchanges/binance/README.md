# Binance public market API notes

检索日期：**2026-08-08**。本文只覆盖 Binance Spot 与 USDⓈ-M linear perpetual 的公共市场数据，
不包含下单、账户、仓位或用户数据流。所有获取时间均为 UTC。

## 本地原始资料

Spot GitHub 资料固定在 `binance/binance-spot-api-docs@6b8372cad7cecbdf5dd88a3372eafff51988c5cf`；
Futures SDK 资料固定在 `binance/binance-connector-python@06d24c98db24248f26a1cf8bd403b62fa7e619fa`。
固定 commit 是为了让归档可复现；运行时契约仍应以最新官方文档和 `exchangeInfo` 为准。

| 本地文件 | 官方 URL | 获取时间 | SHA256 |
| --- | --- | --- | --- |
| [`spot-rest-public-market.md`](sources/spot-rest-public-market.md) | [official `rest-api.md`](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/rest-api.md) | 2026-08-08T13:09:01Z | `49ea6809243fc7fb426e07f2fe662097736c7bb405bd2da5eef637d715427999` |
| [`spot-websocket-streams.md`](sources/spot-websocket-streams.md) | [official `web-socket-streams.md`](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/web-socket-streams.md) | 2026-08-08T13:09:01Z | `32bf73a0bed3b75e3ca981fdbaf48c53544bbdfb5944ef8ed1c4d7af9aceba0a` |
| [`spot-market-data-only.md`](sources/spot-market-data-only.md) | [official market-data-only FAQ](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/faqs/market_data_only.md) | 2026-08-08T13:09:01Z | `57d608507426215c43f11907c07ed693f02725840d9ee4d6630f134de402b6da` |
| [`spot-filters.md`](sources/spot-filters.md) | [official filters](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/filters.md) | 2026-08-08T13:09:01Z | `4b5a8f0f5d15bcf68fd7ac2059ba6c88da641c06fd7885e642330c5ac8124dd3` |
| [`spot-enums.md`](sources/spot-enums.md) | [official enums](https://raw.githubusercontent.com/binance/binance-spot-api-docs/6b8372cad7cecbdf5dd88a3372eafff51988c5cf/enums.md) | 2026-08-08T13:09:01Z | `5708fe6fdea8013f6c8a8388074c8cef8482b2b69a09181e4b2b36e0c2b4ab4b` |
| [`futures-general-info.md`](sources/futures-general-info.md) | [official general info](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/general-info.md) | 2026-08-08T13:09:01Z | `b2e647582fb3ae4cae3a79d6f6f6030d0c03cf403d05176117b24094a083521b` |
| [`futures-common-definition.md`](sources/futures-common-definition.md) | [official common definitions](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/common-definition.md) | 2026-08-08T13:09:01Z | `52706283c94a7b6c80714aee009e4c9bf1b367979612903753e52bd935c878d1` |
| [`futures-rest-market-data-sdk.py`](sources/futures-rest-market-data-sdk.py) | [official generated market-data client](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/api/market_data_api.py) | 2026-08-08T13:09:01Z | `6a5f6f45fb80e73b1bf09c24ccbf7a45dbb1604fbad2e163847d3379a456cd05` |
| [`futures-rest-enums.py`](sources/futures-rest-enums.py) | [official generated REST enums](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/enums.py) | 2026-08-08T14:10:21Z | `e307fbf4aadf4acb0e9db73acd1d9bb38f9b5705e54ed9d3b40f3ef22485be18` |
| [`futures-rest-exchange-info-response.py`](sources/futures-rest-exchange-info-response.py) | [official exchange-info response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/exchange_information_response.py) | 2026-08-08T14:39:33Z | `84dc0e0acad0ffae737cca6d5cfdadc17f92d61b4eaedb1187641b9b212da51f` |
| [`futures-rest-exchange-symbol-response.py`](sources/futures-rest-exchange-symbol-response.py) | [official exchange symbol response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/exchange_information_response_symbols_inner.py) | 2026-08-08T14:39:33Z | `c05e619c68dff07893c8440c3d11f4969f74c2dac6909407839f66dc2e301559` |
| [`futures-rest-order-book-response.py`](sources/futures-rest-order-book-response.py) | [official order-book response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/order_book_response.py) | 2026-08-08T14:39:33Z | `7ed3baa92d05df003617be72f8a2ce6fbcd77352118eb6570bfb49a29915d1d3` |
| [`futures-rest-mark-price-response.py`](sources/futures-rest-mark-price-response.py) | [official single mark-price response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/mark_price_response1.py) | 2026-08-08T14:39:33Z | `7b17fb6d5d270ce8e3b8535eb1e4e1320e3e637dc377fb8323e8268bf267e1e4` |
| [`futures-rest-mark-price-batch-response.py`](sources/futures-rest-mark-price-batch-response.py) | [official batch mark-price row model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/mark_price_response2_inner.py) | 2026-08-08T14:39:33Z | `c37424ca8b7b0b91af081993930fd733f0c7ccb4f9e41f5d202977d34ca42c91` |
| [`futures-rest-funding-history-response.py`](sources/futures-rest-funding-history-response.py) | [official funding-history row model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/get_funding_rate_history_response_inner.py) | 2026-08-08T14:39:33Z | `b3aa5b35ad034d409f60616ef7bed10fe6b553c6ad6eb145fdb32806a9d459d4` |
| [`futures-rest-funding-info-response.py`](sources/futures-rest-funding-info-response.py) | [official funding-info row model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/get_funding_rate_info_response_inner.py) | 2026-08-08T14:39:33Z | `3fb9ccd8ca219d6f6c50f32e1e31141bdebf1231997429ed7339a9adba5c68ef` |
| [`futures-rest-open-interest-response.py`](sources/futures-rest-open-interest-response.py) | [official current-OI response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/open_interest_response.py) | 2026-08-08T14:39:33Z | `627bf3195140ada2f29c990380384a0da43ec9d9d29140e130fb3336044738cc` |
| [`futures-rest-open-interest-history-response.py`](sources/futures-rest-open-interest-history-response.py) | [official historical-OI row model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/open_interest_statistics_response_inner.py) | 2026-08-08T14:39:33Z | `cd5e75967a21f18f7a51aa84bd4ccfc2a5aba9b4dfa0cb7377db88cfb3862e94` |
| [`futures-rest-index-info-response.py`](sources/futures-rest-index-info-response.py) | [official composite-index response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/composite_index_symbol_information_response_inner.py) | 2026-08-08T14:39:33Z | `c806be5c33245a5324401a8c369ae6c1174561840daf69855dbab3493ce3d767` |
| [`futures-rest-index-info-asset-response.py`](sources/futures-rest-index-info-asset-response.py) | [official composite-index asset model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/composite_index_symbol_information_response_inner_base_asset_list_inner.py) | 2026-08-08T14:39:33Z | `215c11e86725bcc3c8a396c0b91efa9d02dfea210c72b116468098650307846c` |
| [`futures-rest-index-constituents-response.py`](sources/futures-rest-index-constituents-response.py) | [official index-constituents response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/query_index_price_constituents_response.py) | 2026-08-08T14:39:33Z | `039fd78c9f8e144249e22ea01fb871dade9ba88e22b598028dcbaebd74a22ea2` |
| [`futures-rest-index-constituent-response.py`](sources/futures-rest-index-constituent-response.py) | [official index constituent row model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/query_index_price_constituents_response_constituents_inner.py) | 2026-08-08T14:39:33Z | `67f54bffc360dc397e5a36cb072a1df7be65f257974941fb375d5a546dacb8c8` |
| [`futures-rest-insurance-response.py`](sources/futures-rest-insurance-response.py) | [official single insurance-fund response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/query_insurance_fund_balance_snapshot_response1.py) | 2026-08-08T14:39:33Z | `260072bf346685cd119d5f801f320732ad12175e3707b1c4880496e348bc317c` |
| [`futures-rest-insurance-asset-response.py`](sources/futures-rest-insurance-asset-response.py) | [official insurance-fund asset model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/query_insurance_fund_balance_snapshot_response1_assets_inner.py) | 2026-08-08T14:39:33Z | `3d932e2e5de594683d77abf8805f01631f3a30fee35ef555d5005450694fb808` |
| [`futures-rest-insurance-batch-response.py`](sources/futures-rest-insurance-batch-response.py) | [official batch insurance-fund row model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/query_insurance_fund_balance_snapshot_response2_inner.py) | 2026-08-08T14:39:33Z | `0c274113b660c39e9650a055d439de23658b080c9f8d682a8332194d34ae1ba7` |
| [`futures-rest-asset-index-response.py`](sources/futures-rest-asset-index-response.py) | [official single asset-index response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/asset_index_response1.py) | 2026-08-08T14:39:33Z | `09f27f411a75b5a5fbd8b4eb6bed1ffa817d3185c57f577af18374c6dc685d0d` |
| [`futures-rest-asset-index-batch-response.py`](sources/futures-rest-asset-index-batch-response.py) | [official batch asset-index row model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/asset_index_response2_inner.py) | 2026-08-08T14:39:33Z | `346704adb49e5c573fc1864a15c3a3958cc155f76928cdaeeba59e842d6dda33` |
| [`futures-rest-adl-risk-response.py`](sources/futures-rest-adl-risk-response.py) | [official ADL-risk response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/adl_risk_response1.py) | 2026-08-08T14:39:33Z | `66cb20127b8cc6918d5025671b6580a8f11401426f8e0a4edd8d471145bb5e31` |
| [`futures-rest-trading-schedule-response.py`](sources/futures-rest-trading-schedule-response.py) | [official trading-schedule response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/rest_api/models/trading_schedule_response.py) | 2026-08-08T14:39:33Z | `4a345ea497a1f066a245b3ada49aa0cbccd581f4d15860aa3e1e2ab8aa74e184` |
| [`futures-ws-connect.md`](sources/futures-ws-connect.md) | [official connect rules](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/websocket-market-streams/Connect.md) | 2026-08-08T13:09:01Z | `912f2dad9da21b5c1801d73f052473b6a1d7136a43b2ff3e7a1c2cdc54abdde2` |
| [`futures-ws-migration.md`](sources/futures-ws-migration.md) | [official 2026 routed-URL migration notice](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/websocket-market-streams/Important-WebSocket-Change-Notice.md) | 2026-08-08T13:09:01Z | `7711169f43066cb169fa40d90193731630ffca43dc2c04a2c753a5814b596f5c` |
| [`futures-ws-subscriptions.md`](sources/futures-ws-subscriptions.md) | [official subscription protocol](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/websocket-market-streams/Live-Subscribing-Unsubscribing-to-streams.md) | 2026-08-08T13:09:01Z | `3aca01db3fa5d7d2f79f90236311d251555c15f8bc3833acc7ed38ab744ec418` |
| [`futures-orderbook-sync.md`](sources/futures-orderbook-sync.md) | [official local-book procedure](https://developers.binance.com/en/docs/products/derivatives-trading-usds-futures/websocket-market-streams/How-to-manage-a-local-order-book-correctly.md) | 2026-08-08T13:09:01Z | `d6a94d17fb32450c67ad598c0f923bf9df12ecdc43ced4928798a9fa56d62622` |
| [`futures-ws-market-sdk.py`](sources/futures-ws-market-sdk.py) | [official routed `market` streams](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/websocket_streams/streams/market_api.py) | 2026-08-08T13:09:01Z | `6b0a7c5d68ab39b849f027b43a6d51fcc624cf1ce73ba9983dd25b6b2493b196` |
| [`futures-ws-public-sdk.py`](sources/futures-ws-public-sdk.py) | [official routed `public` streams](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/websocket_streams/streams/public_api.py) | 2026-08-08T13:09:01Z | `5ed435cc9201faddb3d074d8ac65277671b2fc110912dcf59b9ffd74ec40149d` |
| [`futures-ws-enums.py`](sources/futures-ws-enums.py) | [official generated WebSocket enums](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/websocket_streams/models/enums.py) | 2026-08-08T14:10:21Z | `2bd0c91ad680ff4c253f38a720675b5d557a5bc9eb8682c7c5fe1fb636ab0dfa` |
| [`futures-ws-index-info-response.py`](sources/futures-ws-index-info-response.py) | [official composite-index stream response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/websocket_streams/models/composite_index_symbol_information_streams_response.py) | 2026-08-08T14:39:33Z | `4719c366fc400f7fb9745e899eee383a09e7e58dbd150b49a09b38ab46a6257b` |
| [`futures-ws-kline-response.py`](sources/futures-ws-kline-response.py) | [official kline stream response model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/websocket_streams/models/kline_candlestick_streams_response.py) | 2026-08-08T14:39:33Z | `cd52762441aee88351d7bf6599f00ed2b6e4c57c71694f44c8fd98cbe0835804` |
| [`futures-ws-kline-payload.py`](sources/futures-ws-kline-payload.py) | [official nested kline payload model](https://raw.githubusercontent.com/binance/binance-connector-python/06d24c98db24248f26a1cf8bd403b62fa7e619fa/clients/derivatives_trading_usds_futures/src/binance_sdk_derivatives_trading_usds_futures/websocket_streams/models/kline_candlestick_streams_response_k.py) | 2026-08-08T14:39:33Z | `91e898b7cdabb5382bc006fd8d801c3600671f1b07562e6efd118d8aba1d034c` |

所有 `sources/` 文件都是对应官方 URL 在上表获取时间的完整响应。Spot REST 与 Futures general
info 全文包含鉴权和交易示例，但本项目的实现与测试只采用公共市场数据、限流及错误处理章节，
不会发送订单或携带账户凭据。

本轮强制证据刷新最初列出的 14 个 URL 全部返回可验证的官方 Markdown/Python 内容。此前已经
保存全文的 12 个文件 SHA-256 未变化；`spot-rest-public-market.md` 与
`futures-general-info.md` 从公共章节节选升级为官方完整响应，因此摘要变化不表示上游公共行情
契约发生变更。随后为解决 interval 与响应 shape 歧义，又从同一固定官方 commit 原子归档了 2 个
enum 文件和 23 个响应模型；所有补充 URL 同样成功返回非空 Python 源码。全文与模型补充暴露了
Spot reference price/execution rules，以及 Futures ADL risk、asset index、insurance balance 和
trading schedule 等匿名研究数据；纯协议层为这些端点保留了显式请求和响应契约。

`futures-common-definition.md` 当前列出 `1s` K 线，但同一官方 SDK 固定提交的 REST
`KlineCandlestickDataIntervalEnum` 与 WebSocket `KlineCandlestickStreamsIntervalEnum` 均从 `1m`
开始；2026-08-08 对 `/fapi/v1/klines?interval=1s` 的匿名探测也返回 `-1120 Invalid interval`。
因此 Futures 纯协议层暂时拒绝 `1s`，Spot 仍按官方 Spot 契约支持 `1s`。

固定 SDK commit 与当前线上响应存在可观测滞后。2026-08-08 UTC 的匿名只读探测确认：
`/fapi/v1/exchangeInfo` 顶层以 `futuresType="U_MARGINED"` 证明 USD-M 范围，symbol 行通常没有
`st`，并已有中文 symbol；`/fapi/v1/fundingInfo` 返回 742 行且每行带 `updateTime`；
`/fapi/v1/indexInfo` 返回 `SMALLUSDT` 等独立复合指数身份，而非合约目录中的 `BTCUSDT`；
`/fapi/v1/insuranceBalance?symbol=BTCUSDT` 返回覆盖多个合约的共享基金组。纯协议测试按这些线上
shape 增加了边界，同时保留原始 payload；生成模型仍用于固定字段类型证据，而不覆盖较新的 live
字段。Unicode Futures ticker 的百分号编码 stream URL 也完成匿名连接和响应 symbol 绑定验证。

## Base URL 与鉴权边界

| 市场 | REST | WebSocket 市场流 |
| --- | --- | --- |
| Spot | 纯行情优先 `https://data-api.binance.vision`；通用生产入口为 `https://api.binance.com`、`api-gcp.binance.com` 和 `api1` 至 `api4.binance.com`，后四个较快但稳定性较低 | `wss://stream.binance.com:9443` 或 `:443`；纯行情也可用 `wss://data-stream.binance.vision:443`。原始流 `/ws/<stream>`，组合流 `/stream?streams=<a>/<b>` |
| USDⓈ-M Futures | `https://fapi.binance.com` | 根为 `wss://fstream.binance.com`。订单簿/最优价使用 `/public`，常规行情使用 `/market`；原始流 `/<route>/ws/<stream>`，组合流 `/<route>/stream?streams=<a>/<b>` |

下列 REST 表中除明确标注者外均为安全类型 `NONE`，不需要 API key、签名、`timestamp` 或
`recvWindow`。WS 表只列公开市场流。Spot 与 Futures stream symbol 均须小写；若 symbol 含
非 ASCII 字符，订阅 JSON 保留原 symbol，组合流 URL 则对每个 stream component 做 UTF-8
百分号编码，并保留协议字符 `@_!` 与 stream 间的 `/` 分隔符。

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
| 平均价/参考价 | `GET /api/v3/avgPrice`、`GET /api/v3/referencePrice`、`GET /api/v3/referencePrice/calculation` | 单 symbol 权重均为 2；参考价不存在时返回业务错误 `-2043`，不能伪造为零 |
| 执行规则 | `GET /api/v3/executionRules` | 单 symbol 权重 2；多 symbol 每个 2、上限 40；无 selector 或按 `symbolStatus` 查询权重 40 |

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
| 资金费率历史/配置 | `GET /fapi/v1/fundingRate`、`GET /fapi/v1/fundingInfo` | 共享每 IP 每 5 分钟 500 次专有限额；后者权重 0。固定 SDK 描述为调整项，但当前 live 响应覆盖大量标的并为每行提供 `updateTime`，必须保留原始集合而非假定稀疏 |
| 当前/历史 OI | `GET /fapi/v1/openInterest`、`GET /futures/data/openInterestHist` | 当前值权重 1；历史值权重 0，但另有每 IP 每 5 分钟 1000 次限制，只保留最近一个月 |
| 指数构成/复合指数 | `GET /fapi/v1/constituents`、`GET /fapi/v1/indexInfo`、`GET /fapi/v1/assetIndex` | 构成权重 2；复合指数权重 1；asset index 单 symbol 1、全市场 10。`indexInfo.symbol` 是独立指数身份，`assetIndex.symbol` 是 BTCUSD 一类 asset pair，都不能冒充已选 perpetual contract |
| 风险与保险基金 | `GET /fapi/v1/symbolAdlRisk`、`GET /fapi/v1/insuranceBalance` | 权重均为 1；前者为约 30 分钟更新的 symbol 级 ADL 风险；后者一个基金组可覆盖多个 `symbols` 和多种 `assets`，按市场级共享快照保存，不能重复标成单个合约事件 |
| 交易时段 | `GET /fapi/v1/tradingSchedule` | 权重 5；用于 TradFi perpetual 的公开交易时段，不等同于全交易所系统状态 |

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
Spot 控制消息 `id` 可用 signed 64-bit integer、最长 36 位字母数字字符串或 `null`。

Futures 同样在 24 小时处断开；服务端每 3 分钟 Ping，10 分钟未收到 Pong 会断开。每连接每秒
最多 10 条客户端入站消息，最多 1024 个 streams。客户端库应自动响应协议级 Ping，并在 24 小时
前主动轮换，使用带抖动的指数退避重连，重连后重新订阅和重建 order book。Futures 控制消息
必须携带 unsigned integer `id`，不能复用 Spot 的字符串或 `null` 形式。

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

Futures 以 `/fapi/v1/exchangeInfo` 为基线，先要求顶层 `futuresType == U_MARGINED`，再过滤
`contractType == PERPETUAL`、`status == TRADING` 和期望的结算/报价资产；`PENDING_TRADING`
可用于预热但不能作为可交易标的。symbol 不能假设为 ASCII，新币选择与 stream URL 构造必须
保留 Unicode 身份。
再用 `!contractInfo` 降低发现延迟，任何事件后仍以新的 `exchangeInfo` 快照确认。

2026-06-30 CM-UM integration 后，部分 `/fapi` K 线和 `fstream`/`dstream` 全市场流可混合 UM 与
CM；新 payload 可能有 `st`（`1`=UM、`2`=CM）和 `ps`。因此不能只凭 host/path 判断 linear。
目录以顶层 `futuresType` 和合约元数据证明 USD-M；row/WS payload 若出现 `st` 则再做附加过滤，
但当前合法 `exchangeInfo` symbol 行缺少 `st`，不能把缺失误判为非 USD-M。共享限频池仍要统一计数。

## 时间字段语义

| 接口/字段 | 语义 |
| --- | --- |
| Spot REST | JSON 时间默认 Unix 毫秒；`X-MBX-TIME-UNIT: MICROSECOND` 可请求微秒。`startTime`/`endTime` 可传毫秒或微秒 |
| Spot trade WS | `E` 是事件时间，`T` 是成交时间；逐笔的 `t` 是 trade ID，不是时间 |
| Spot kline | `k.t`/`k.T` 是分桶开/闭时间，`k.x` 表示是否闭合；即使使用 UTC+8 分桶，时间戳仍按 UTC Unix 解释 |
| Spot ticker | `E` 是事件时间，`O`/`C` 是滚动统计窗口边界；`bookTicker` 和 REST price/bookTicker 没有事件时间 |
| Futures REST | 所有时间戳为 Unix 毫秒；成交 `time`、aggTrade `T`、K 线 `[0]`/`[6]` 为开/闭时间 |
| Futures mark/funding/OI | `premiumIndex.time` 是快照时间，`nextFundingTime` 是下一结算点；历史费率 `fundingTime` 是结算事件；当前 funding 配置的 `updateTime` 是行更新时间；当前 OI 的 `time` 是快照时间，历史 OI 的 `timestamp` 是周期时间 |
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
