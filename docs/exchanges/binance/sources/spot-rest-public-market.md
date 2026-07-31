# Public Rest API for Binance

## General API Information
* The following base endpoints are available. Please use whichever works best for your setup:
  * **https://api.binance.com**
  * **https://api-gcp.binance.com**
  * **https://api1.binance.com**
  * **https://api2.binance.com**
  * **https://api3.binance.com**
  * **https://api4.binance.com**
* The last 4 endpoints in the point above (`api1`-`api4`) should give better performance but have less stability.
* Responses are in JSON by default. To receive responses in SBE, refer to the [SBE FAQ](./faqs/sbe_faq.md) page.
* Data is returned in **chronological order**, unless noted otherwise.
  * Without `startTime` or `endTime`, returns the most recent items up to the limit.
  * With `startTime`, returns oldest items from `startTime` up to the limit.
  * With `endTime`, returns most recent items up to `endTime` and the limit.
  * With both, behaves like `startTime` but does not exceed `endTime`.
* All time and timestamp related fields in the JSON responses are in **milliseconds by default.** To receive the information in microseconds, please add the header `X-MBX-TIME-UNIT:MICROSECOND` or `X-MBX-TIME-UNIT:microsecond`.
* We support HMAC, RSA, and Ed25519 keys. For more information, please see [API Key types](faqs/api_key_types.md).
* Timestamp parameters (e.g. `startTime`, `endTime`, `timestamp`) can be passed in milliseconds or microseconds.
* For APIs that only send public market data, please use the base endpoint **https://data-api.binance.vision**. Please refer to [Market Data Only](./faqs/market_data_only.md) page.
* If there are enums or terms you want clarification on, please see the [SPOT Glossary](faqs/spot_glossary.md) for more information.
* APIs have a timeout of 10 seconds when processing a request. If a response from the Matching Engine takes longer than this, the API responds with "Timeout waiting for response from backend server. Send status unknown; execution status unknown." [(-1007 TIMEOUT)](errors.md#-1007-timeout)
  * This does not always mean that the request failed in the Matching Engine.
  * If the status of the request has not appeared in [User Data Stream](user-data-stream.md), please perform an API query for its status.
* **Please avoid SQL keywords in requests** as they may trigger a security block by a WAF (Web Application Firewall) rule. See https://www.binance.com/en/support/faq/detail/360004492232 for more details.
* If your request contains a symbol name containing non-ASCII characters, then the response may contain non-ASCII characters encoded in UTF-8.
* Some endpoints may return asset and/or symbol names containing non-ASCII characters encoded in UTF-8 even if the request did not contain non-ASCII characters.

## HTTP Return Codes

* HTTP `4XX` return codes are used for malformed requests; the issue is on the sender's side.
* HTTP `403` return code is used when a WAF (Web Application Firewall) rule has been violated. This can indicate a rate limit violation or a security block. See https://www.binance.com/en/support/faq/detail/360004492232 for more details.
* HTTP `409` return code is used when a cancelReplace order partially succeeds. (i.e. if the cancellation of the order fails but the new order placement succeeds.)
* HTTP `429` return code is used when breaking a request rate limit.
* HTTP `418` return code is used when an IP has been auto-banned for continuing to send requests after receiving `429` codes.
* HTTP `5XX` return codes are used for internal errors; the issue is on Binance's side.
  It is important to **NOT** treat this as a failure operation; the execution status is
  **UNKNOWN** and could have been a success.


## Error Codes
* Any endpoint can return an ERROR

Sample Payload below:
```javascript
{
    "code": -1121,
    "msg": "Invalid symbol."
}
```
* Specific error codes and messages are defined in [Errors Codes](./errors.md).

## General Information on Endpoints
* For `GET` endpoints, parameters must be sent as a `query string`.
* For `POST`, `PUT`, and `DELETE` endpoints, the parameters may be sent as a
  `query string` or in the `request body` with content type
  `application/x-www-form-urlencoded`. You may mix parameters between both the
  `query string` and `request body` if you wish to do so.
* Parameters may be sent in any order.
* If a parameter sent in both the `query string` and `request body`, the
  `query string` parameter will be used.

## LIMITS

### General Info on Limits
* The following `intervalLetter` values for headers:
    * SECOND => S
    * MINUTE => M
    * HOUR => H
    * DAY => D
* `intervalNum` describes the amount of the interval. For example, `intervalNum` 5 with `intervalLetter` M means "Every 5 minutes".
* The `/api/v3/exchangeInfo` `rateLimits` array contains objects related to the exchange's `RAW_REQUESTS`, `REQUEST_WEIGHT`, and `ORDERS` rate limits. These are further defined in the `ENUM definitions` section under `Rate limiters (rateLimitType)`.
* Requests fail with HTTP status code 429 when you exceed the request rate limit.

### IP Limits
* Every request will contain `X-MBX-USED-WEIGHT-(intervalNum)(intervalLetter)` in the response headers which has the current used weight for the IP for all request rate limiters defined.
* Each route has a `weight` which determines for the number of requests each endpoint counts for. Heavier endpoints and endpoints that do operations on multiple symbols will have a heavier `weight`.
* When a 429 is received, it's your obligation as an API to back off and not spam the API.
* **Repeatedly violating rate limits and/or failing to back off after receiving 429s will result in an automated IP ban (HTTP status 418).**
* IP bans are tracked and **scale in duration** for repeat offenders, **from 2 minutes to 3 days**.
* A `Retry-After` header is sent with a 418 or 429 responses and will give the **number of seconds** required to wait, in the case of a 429, to prevent a ban, or, in the case of a 418, until the ban is over.
* **The limits on the API are based on the IPs, not the API keys.**

## Data Sources
* The API system is asynchronous, so some delay in the response is normal and expected.
* Each endpoint has a data source indicating where the data is being retrieved, and thus which endpoints have the most up-to-date response.

These are the three sources, ordered by least to most potential for delays in data updates.

  * **Matching Engine** - the data is from the Matching Engine
  * **Memory** - the data is from a server's local or external memory
  * **Database** - the data is taken directly from a database

Some endpoints can have more than 1 data source. (e.g. Memory => Database)
This means that the endpoint will check the first Data Source, and if it cannot find the value it's looking for it will check the next one.

### Exchange information
```
GET /api/v3/exchangeInfo
```
Current exchange trading rules and symbol information

**Weight:**
20

**Parameters:**

Name | Type | Mandatory | Description
------------ | ------------ | ------------ | ------------
symbol |STRING| No| Example: curl -X GET "https://api.binance.com/api/v3/exchangeInfo?symbol=BNBBTC"
symbols |ARRAY OF STRING|No| Examples: curl -X GET "https://api.binance.com/api/v3/exchangeInfo?symbols=%5B%22BNBBTC%22,%22BTCUSDT%22%5D" <br/> or <br/> curl -g -X  GET 'https://api.binance.com/api/v3/exchangeInfo?symbols=["BTCUSDT","BNBBTC"]'
permissions |ENUM|No|Examples: curl -X GET "https://api.binance.com/api/v3/exchangeInfo?permissions=SPOT" <br/> or <br/> curl -X GET "https://api.binance.com/api/v3/exchangeInfo?permissions=%5B%22MARGIN%22%2C%22LEVERAGED%22%5D" <br/> or <br/> curl -g -X GET 'https://api.binance.com/api/v3/exchangeInfo?permissions=["MARGIN","LEVERAGED"]' |
showPermissionSets|BOOLEAN|No|Controls whether the content of the `permissionSets` field is populated or not. Defaults to `true`
symbolStatus|ENUM|No|Filters for symbols that have this `tradingStatus`. Valid values: `TRADING`, `HALT`, `BREAK` <br> Cannot be used in combination with `symbols` or `symbol`.|

**Notes:**
* If the value provided to `symbol` or `symbols` do not exist, the endpoint will throw an error saying the symbol is invalid.
* All parameters are optional.
* `permissions` can support single or multiple values (e.g. `SPOT`, `["MARGIN","LEVERAGED"]`). This cannot be used in combination with `symbol` or `symbols`.
* If `permissions` parameter not provided, all symbols that have either `SPOT`, `MARGIN`, or `LEVERAGED` permission will be exposed.
  * To display symbols with any permission you need to specify them explicitly in `permissions`: (e.g. `["SPOT","MARGIN",...]`.). See [Account and Symbol Permissions](enums.md#account-and-symbol-permissions) for the full list.

<a id="examples-of-symbol-permissions-interpretation-from-the-response"></a>

**Examples of Symbol Permissions Interpretation from the Response:**

* `[["A","B"]]` means you may place an order if your account has either permission "A" **or** permission "B".
* `[["A"],["B"]]` means you can place an order if your account has permission "A" **and** permission "B".
* `[["A"],["B","C"]]` means you can place an order if your account has permission "A" **and** permission "B" or permission "C". (Inclusive or is applied here, not exclusive or, so your account may have both permission "B" and permission "C".)

**Data Source:**
Memory

**Response:**
```javascript
{
    "timezone": "UTC",
    "serverTime": 1565246363776,
    "rateLimits": [
        {
            // These are defined in the `ENUM definitions` section under `Rate Limiters (rateLimitType)`.
            // All limits are optional
        }
    ],
    "exchangeFilters": [
        // These are the defined filters in the `Filters` section.
        // All filters are optional.
    ],
    "symbols": [
        {
            "symbol": "ETHBTC",
            "status": "TRADING",
            "baseAsset": "ETH",
            "baseAssetPrecision": 8,
            "quoteAsset": "BTC",
            "quotePrecision": 8,     // will be removed in future api versions (v4+)
            "quoteAssetPrecision": 8,
            "baseCommissionPrecision": 8,
            "quoteCommissionPrecision": 8,
            "orderTypes": [
                "LIMIT",
                "LIMIT_MAKER",
                "MARKET",
                "STOP_LOSS",
                "STOP_LOSS_LIMIT",
                "TAKE_PROFIT",
                "TAKE_PROFIT_LIMIT"
            ],
            "icebergAllowed": true,
            "ocoAllowed": true,
            "otoAllowed": true,
            "opoAllowed": true,
            "quoteOrderQtyMarketAllowed": true,
            "allowTrailingStop": false,
            "cancelReplaceAllowed": false,
            "amendAllowed": false,
            "pegInstructionsAllowed": true,
            "isSpotTradingAllowed": true,
            "isMarginTradingAllowed": true,
            "filters": [
                // These are defined in the Filters section.
                // All filters are optional
            ],
            "permissions": [],
            "permissionSets": [["SPOT", "MARGIN"]],
            "defaultSelfTradePreventionMode": "NONE",
            "allowedSelfTradePreventionModes": ["NONE"]
        }
    ],
    // Optional field. Present only when SOR is available.
    // https://github.com/binance/binance-spot-api-docs/blob/master/faqs/sor_faq.md
    "sors": [
        {
            "baseAsset": "BTC",
            "symbols": ["BTCUSDT", "BTCUSDC"]
        }
    ]
}
```

## Market Data endpoints
### Order book
```
GET /api/v3/depth
```

**Weight:**
Adjusted based on the limit:

|Limit|Request Weight
------|-------
1-100|  5
101-500| 25
501-1000| 50
1001-5000| 250

**Parameters:**

Name | Type | Mandatory | Description
------------ | ------------ | ------------ | ------------
symbol | STRING | YES |
limit | INT | NO | Default: 100; Maximum: 5000. <br/> If limit > 5000, only 5000 entries will be returned.
symbolStatus|ENUM|NO|Filters for symbols that have this `tradingStatus`. <br/>A status mismatch returns error `-1220 SYMBOL_DOES_NOT_MATCH_STATUS`.<br/> Valid values: `TRADING`, `HALT`, `BREAK`

**Data Source:**
Memory

**Response:**
```javascript
{
    "lastUpdateId": 1027024,
    "bids": [
        [
            "4.00000000",      // PRICE
            "431.00000000"     // QTY
        ]
    ],
    "asks": [["4.00000200", "12.00000000"]]
}
```


### Recent trades list
```
GET /api/v3/trades
```
Get recent trades.

**Weight:**
25

**Parameters:**

Name | Type | Mandatory | Description
------------ | ------------ | ------------ | ------------
symbol | STRING | YES |
limit | INT | NO | Default: 500; Maximum: 1000.

**Data Source:**
Memory

**Response:**
```javascript
[
    {
        "id": 28457,
        "price": "4.00000100",
        "qty": "12.00000000",
        "quoteQty": "48.000012",
        "time": 1499865549590,
        "isBuyerMaker": true,
        "isBestMatch": true
    }
]
```

### Compressed/Aggregate trades list
```
GET /api/v3/aggTrades
```
Get compressed, aggregate trades. Trades that fill at the time, from the same taker order, with the same price will have the quantity aggregated.

**Weight:**
4

**Parameters:**

Name | Type | Mandatory | Description
------------ | ------------ | ------------ | ------------
symbol | STRING | YES |
fromId | LONG | NO | ID to get aggregate trades from INCLUSIVE.
startTime | LONG | NO | Timestamp in ms to get aggregate trades from INCLUSIVE.
endTime | LONG | NO | Timestamp in ms to get aggregate trades until INCLUSIVE.
limit | INT | NO | Default: 500; Maximum: 1000.

* If fromId, startTime, and endTime are not sent, the most recent aggregate trades will be returned.

**Data Source:**
Database

**Response:**
```javascript
[
    {
        "a": 26129,             // Aggregate tradeId
        "p": "0.01633102",      // Price
        "q": "4.70443515",      // Quantity
        "f": 27781,             // First tradeId
        "l": 27781,             // Last tradeId
        "T": 1498793709153,     // Timestamp
        "m": true,              // Was the buyer the maker?
        "M": true               // Was the trade the best price match?
    }
]
```
<a id="klines"></a>
### Kline/Candlestick data
```
GET /api/v3/klines
```
Kline/candlestick bars for a symbol.
Klines are uniquely identified by their open time.

**Weight:**
2

**Parameters:**

Name | Type | Mandatory | Description
------------ | ------------ | ------------ | ------------
symbol | STRING | YES |
interval | ENUM | YES |
startTime | LONG | NO |
endTime | LONG | NO |
timeZone |STRING| NO| Default: 0 (UTC)
limit | INT | NO | Default: 500; Maximum: 1000.

<a id="kline-intervals"></a>
Supported kline intervals (case-sensitive):

Interval  | `interval` value
--------- | ----------------
seconds   | `1s`
minutes   | `1m`, `3m`, `5m`, `15m`, `30m`
hours     | `1h`, `2h`, `4h`, `6h`, `8h`, `12h`
days      | `1d`, `3d`
weeks     | `1w`
months    | `1M`

**Notes:**

* If `startTime` and `endTime` are not sent, the most recent klines are returned.
* Supported values for `timeZone`:
  * Hours and minutes (e.g. `-1:00`, `05:45`)
  * Only hours (e.g. `0`, `8`, `4`)
  * Accepted range is strictly [-12:00 to +14:00] inclusive
* If `timeZone` provided, kline intervals are interpreted in that timezone instead of UTC.
* Note that `startTime` and `endTime` are always interpreted in UTC, regardless of `timeZone`.

**Data Source:**
Database

**Response:**
```javascript
[
    [
        1499040000000,         // Kline open time
        "0.01634790",          // Open price
        "0.80000000",          // High price
        "0.01575800",          // Low price
        "0.01577100",          // Close price
        "148976.11427815",     // Volume
        1499644799999,         // Kline Close time
        "2434.19055334",       // Quote asset volume
        308,                   // Number of trades
        "1756.87402397",       // Taker buy base asset volume
        "28.46694368",         // Taker buy quote asset volume
        "0"                    // Unused field, ignore.
    ]
]
```
<a id="uiKlines"></a>
### 24hr ticker price change statistics
```
GET /api/v3/ticker/24hr
```
24 hour rolling window price change statistics. **Careful** when accessing this with no symbol.

**Weight:**

<table>
<thead>
    <tr>
        <th>Parameter</th>
        <th>Symbols Provided</th>
        <th>Weight</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td rowspan="2">symbol</td>
        <td>1</td>
        <td>2</td>
    </tr>
    <tr>
        <td>symbol parameter is omitted</td>
        <td>80</td>
    </tr>
    <tr>
        <td rowspan="4">symbols</td>
        <td>1-20</td>
        <td>2</td>
    </tr>
    <tr>
        <td>21-100</td>
        <td>40</td>
    </tr>
    <tr>
        <td>101 or more</td>
        <td>80</td>
    </tr>
    <tr>
        <td>symbols parameter is omitted</td>
        <td>80</td>
    </tr>
</tbody>
</table>

**Parameters:**

<table>
<thead>
    <tr>
        <th>Name</th>
        <th>Type</th>
        <th>Mandatory</th>
        <th>Description</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td>symbol</td>
        <td>STRING</td>
        <td>NO</td>
        <td rowspan="2">Parameter symbol and symbols cannot be used in combination. <br/> If neither parameter is sent, tickers for all symbols will be returned in an array. <br/><br/>
         Examples of accepted format for the symbols parameter:
         ["BTCUSDT","BNBUSDT"] <br/>
         or <br/>
         %5B%22BTCUSDT%22,%22BNBUSDT%22%5D
        </td>
     </tr>
     <tr>
        <td>symbols</td>
        <td>STRING</td>
        <td>NO</td>
     </tr>
     <tr>
        <td>type</td>
        <td>ENUM</td>
        <td>NO</td>
        <td>Supported values: <tt>FULL</tt> or <tt>MINI</tt>. <br/>If none provided, the default is <tt>FULL</tt> </td>
     </tr>
     <tr>
        <td>symbolStatus</td>
        <td>ENUM</td>
        <td>NO</td>
        <td>Filters for symbols that have this <code>tradingStatus</code>.<br>For a single symbol, a status mismatch returns error <code>-1220 SYMBOL_DOES_NOT_MATCH_STATUS</code>. <br>For multiple or all symbols, non-matching ones are simply excluded from the response.<br>Valid values: <code>TRADING</code>, <code>HALT</code>, <code>BREAK</code> </td>
     </tr>
</tbody>
</table>

**Data Source:**
Memory

**Response - FULL:**
```javascript
{
    "symbol": "BNBBTC",
    "priceChange": "-94.99999800",
    "priceChangePercent": "-95.960",
    "weightedAvgPrice": "0.29628482",
    "prevClosePrice": "0.10002000",
    "lastPrice": "4.00000200",
    "lastQty": "200.00000000",
    "bidPrice": "4.00000000",
    "bidQty": "100.00000000",
    "askPrice": "4.00000200",
    "askQty": "100.00000000",
    "openPrice": "99.00000000",
    "highPrice": "100.00000000",
    "lowPrice": "0.10000000",
    "volume": "8913.30000000",
    "quoteVolume": "15.30000000",
    "openTime": 1499783499040,
    "closeTime": 1499869899040,
    "firstId": 28385,     // First tradeId
    "lastId": 28460,      // Last tradeId
    "count": 76           // Trade count
}
```
OR
```javascript
[
    {
        "symbol": "BNBBTC",
        "priceChange": "-94.99999800",
        "priceChangePercent": "-95.960",
        "weightedAvgPrice": "0.29628482",
        "prevClosePrice": "0.10002000",
        "lastPrice": "4.00000200",
        "lastQty": "200.00000000",
        "bidPrice": "4.00000000",
        "bidQty": "100.00000000",
        "askPrice": "4.00000200",
        "askQty": "100.00000000",
        "openPrice": "99.00000000",
        "highPrice": "100.00000000",
        "lowPrice": "0.10000000",
        "volume": "8913.30000000",
        "quoteVolume": "15.30000000",
        "openTime": 1499783499040,
        "closeTime": 1499869899040,
        "firstId": 28385,     // First tradeId
        "lastId": 28460,      // Last tradeId
        "count": 76           // Trade count
    }
]
```

**Response - MINI:**

```javascript
{
    "symbol": "BNBBTC",               // Symbol Name
    "openPrice": "99.00000000",       // Opening price of the Interval
    "highPrice": "100.00000000",      // Highest price in the interval
    "lowPrice": "0.10000000",         // Lowest  price in the interval
    "lastPrice": "4.00000200",        // Closing price of the interval
    "volume": "8913.30000000",        // Total trade volume (in base asset)
    "quoteVolume": "15.30000000",     // Total trade volume (in quote asset)
    "openTime": 1499783499040,        // Start of the ticker interval
    "closeTime": 1499869899040,       // End of the ticker interval
    "firstId": 28385,                 // First tradeId considered
    "lastId": 28460,                  // Last tradeId considered
    "count": 76                       // Total trade count
}
```

OR

```javascript
[
    {
        "symbol": "BNBBTC",
        "openPrice": "99.00000000",
        "highPrice": "100.00000000",
        "lowPrice": "0.10000000",
        "lastPrice": "4.00000200",
        "volume": "8913.30000000",
        "quoteVolume": "15.30000000",
        "openTime": 1499783499040,
        "closeTime": 1499869899040,
        "firstId": 28385,
        "lastId": 28460,
        "count": 76
    },
    {
        "symbol": "LTCBTC",
        "openPrice": "0.07000000",
        "highPrice": "0.07000000",
        "lowPrice": "0.07000000",
        "lastPrice": "0.07000000",
        "volume": "11.00000000",
        "quoteVolume": "0.77000000",
        "openTime": 1656908192899,
        "closeTime": 1656994592899,
        "firstId": 0,
        "lastId": 10,
        "count": 11
    }
]
```


### Symbol price ticker
```
GET /api/v3/ticker/price
```
Latest price for a symbol or symbols.

**Weight:**

<table>
<thead>
    <tr>
        <th>Parameter</th>
        <th>Symbols Provided</th>
        <th>Weight</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td rowspan="2">symbol</td>
        <td>1</td>
        <td>2</td>
    </tr>
    <tr>
        <td>symbol parameter is omitted</td>
        <td>4</td>
    </tr>
    <tr>
        <td>symbols</td>
        <td>Any</td>
        <td>4</td>
    </tr>
</tbody>
</table>

**Parameters:**

<table>
<thead>
    <tr>
      <th>Name</th>
      <th>Type</th>
      <th>Mandatory</th>
      <th>Description</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td>symbol</td>
        <td>STRING</td>
        <td>NO</td>
        <td rowspan="2"> Parameter symbol and symbols cannot be used in combination. <br/> If neither parameter is sent, prices for all symbols will be returned in an array. <br/><br/>
        Examples of accepted format for the symbols parameter:
         ["BTCUSDT","BNBUSDT"] <br/>
         or <br/>
         %5B%22BTCUSDT%22,%22BNBUSDT%22%5D</td>
    </tr>
    <tr>
        <td>symbols</td>
        <td>STRING</td>
        <td>NO</td>
    </tr>
    <tr>
        <td>symbolStatus</td>
        <td>ENUM</td>
        <td>NO</td>
        <td>Filters for symbols that have this <code>tradingStatus</code>.<br>For a single symbol, a status mismatch returns error <code>-1220 SYMBOL_DOES_NOT_MATCH_STATUS</code>. <br>For multiple or all symbols, non-matching ones are simply excluded from the response.<br>Valid values: <code>TRADING</code>, <code>HALT</code>, <code>BREAK</code> </td>
    </tr>
</tbody>
</table>


**Data Source:**
Memory

**Response:**
```javascript
{
    "symbol": "LTCBTC",
    "price": "4.00000200"
}
```
OR
```javascript
[
    {
        "symbol": "LTCBTC",
        "price": "4.00000200"
    },
    {
        "symbol": "ETHBTC",
        "price": "0.07946600"
    }
]
```

### Symbol order book ticker
```
GET /api/v3/ticker/bookTicker
```
Best price/qty on the order book for a symbol or symbols.

**Weight:**

<table>
<thead>
    <tr>
        <th>Parameter</th>
        <th>Symbols Provided</th>
        <th>Weight</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td rowspan="2">symbol</td>
        <td>1</td>
        <td>2</td>
    </tr>
    <tr>
        <td>symbol parameter is omitted</td>
        <td>4</td>
    </tr>
    <tr>
        <td>symbols</td>
        <td>Any</td>
        <td>4</td>
    </tr>
</tbody>
</table>

**Parameters:**

<table>
<thead>
    <tr>
      <th>Name</th>
      <th>Type</th>
      <th>Mandatory</th>
      <th>Description</th>
    </tr>
</thead>
<tbody>
    <tr>
        <td>symbol</td>
        <td>STRING</td>
        <td>NO</td>
        <td rowspan="2"> Parameter symbol and symbols cannot be used in combination. <br/> If neither parameter is sent, bookTickers for all symbols will be returned in an array.
         <br/><br/>
        Examples of accepted format for the symbols parameter:
         ["BTCUSDT","BNBUSDT"] <br/>
         or <br/>
         %5B%22BTCUSDT%22,%22BNBUSDT%22%5D</td>
    </tr>
    <tr>
        <td>symbols</td>
        <td>STRING</td>
        <td>NO</td>
    </tr>
    <tr>
        <td>symbolStatus</td>
        <td>ENUM</td>
        <td>NO</td>
        <td>Filters for symbols that have this <code>tradingStatus</code>.<br>For a single symbol, a status mismatch returns error <code>-1220 SYMBOL_DOES_NOT_MATCH_STATUS</code>. <br>For multiple or all symbols, non-matching ones are simply excluded from the response.<br>Valid values: <code>TRADING</code>, <code>HALT</code>, <code>BREAK</code> </td>
    </tr>
</tbody>
</table>


**Data Source:**
Memory

**Response:**
```javascript
{
    "symbol": "LTCBTC",
    "bidPrice": "4.00000000",
    "bidQty": "431.00000000",
    "askPrice": "4.00000200",
    "askQty": "9.00000000"
}
```
OR
```javascript
[
    {
        "symbol": "LTCBTC",
        "bidPrice": "4.00000000",
        "bidQty": "431.00000000",
        "askPrice": "4.00000200",
        "askQty": "9.00000000"
    },
    {
        "symbol": "ETHBTC",
        "bidPrice": "0.07946700",
        "bidQty": "9.00000000",
        "askPrice": "100000.00000000",
        "askQty": "1000.00000000"
    }
]
```

