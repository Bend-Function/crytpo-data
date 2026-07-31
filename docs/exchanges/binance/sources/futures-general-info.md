# General Info

## General API Information

- Some endpoints will require an API Key. Please refer to
  [this page](https://www.binance.com/en/support/articles/360002502072)
- The base endpoint is: **https://fapi.binance.com**
- All endpoints return either a JSON object or array.
- Data is returned in **ascending** order. Oldest first, newest last.
- All time and timestamp related fields are in milliseconds.
- All data types adopt definition in JAVA.

### Testnet API Information

- Most of the endpoints can be used in the testnet platform.
- The REST base url for **testnet** is "https://demo-fapi.binance.com"
- The Websocket base url for **testnet** is "wss://demo-fstream.binance.com"

---

## General Information on Endpoints

- For `GET` endpoints, parameters must be sent as a `query string`.
- For `POST`, `PUT`, and `DELETE` endpoints, the parameters may be sent as a `query string` or in
  the `request body` with content type `application/x-www-form-urlencoded`. You may mix parameters
  between both the `query string` and `request body` if you wish to do so.
- Parameters may be sent in any order.
- If a parameter sent in both the `query string` and `request body`, the `query string` parameter
  will be used.

### HTTP Return Codes

- HTTP `4XX` return codes are used for for malformed requests; the issue is on the sender's side.
- HTTP `403` return code is used when the WAF Limit (Web Application Firewall) has been violated.
- HTTP `408` return code is used when a timeout has occurred while waiting for a response from the
  backend server.
- HTTP `429` return code is used when breaking a request rate limit.
- HTTP `418` return code is used when an IP has been auto-banned for continuing to send requests
  after receiving `429` codes.
- HTTP `5XX` return codes are used for internal errors; the issue is on Binance's side.
  1. If there is an error message **"Request occur unknown error."**, please retry later.
- HTTP `503` return code is used when:
  1. If there is an error message **"Unknown error, please check your request or try again later."**
     returned in the response, the API successfully sent the request but not get a response within
     the timeout period.  
     It is important to **NOT** treat this as a failure operation; the execution status is
     **UNKNOWN** and could have been a success;
  2. If there is an error message **"Service Unavailable."** returned in the response, it means this
     is a failure API operation and the service might be unavailable at the moment, you need to
     retry later.
  3. If there is an error message **"Internal error; unable to process your request. Please try
     again."** returned in the response, it means this is a failure API operation and you can resend
     your request if you need.
  4. If the response contains the error message **"Request throttled by system-level protection.
     Reduce-only/close-position orders are exempt. Please try again." (-1008)**, This indicates the
     node has exceeded its maximum concurrency and is temporarily throttled. Close-position,
     reduce-only, and cancel orders are exempt and will not receive this error.

## LIMITS

- The `/fapi/v1/exchangeInfo` `rateLimits` array contains objects related to the exchange's
  `RAW_REQUEST`, `REQUEST_WEIGHT`, and `ORDER` rate limits. These are further defined in the
  `ENUM definitions` section under `Rate limiters (rateLimitType)`.
- A `429` will be returned when either rate limit is violated.

<aside class="notice">
Binance has the right to further tighten the rate limits on users with intent to attack.
</aside>

### IP Limits

- Every request will contain `X-MBX-USED-WEIGHT-(intervalNum)(intervalLetter)` in the response
  headers which has the current used weight for the IP for all request rate limiters defined.
- Each route has a `weight` which determines for the number of requests each endpoint counts for.
  Heavier endpoints and endpoints that do operations on multiple symbols will have a heavier
  `weight`.
- When a 429 is received, it's your obligation as an API to back off and not spam the API.
- **Repeatedly violating rate limits and/or failing to back off after receiving 429s will result in
  an automated IP ban (HTTP status 418).**
- IP bans are tracked and **scale in duration** for repeat offenders, **from 2 minutes to 3 days**.
- **The limits on the API are based on the IPs, not the API keys.**

<aside class="notice">
It is strongly recommended to use websocket stream for getting data as much as possible, which can not only ensure the timeliness of the message, but also reduce the access restriction pressure caused by the request.
</aside>

## Endpoint Security Type

- Each endpoint has a security type that determines the how you will interact with it.
- API-keys are passed into the Rest API via the `X-MBX-APIKEY` header.
- API-keys and secret-keys **are case sensitive**.
- API-keys can be configured to only access certain types of secure endpoints. For example, one
  API-key could be used for TRADE only, while another API-key can access everything except for TRADE
  routes.
- By default, API-keys can access all secure routes.

| Security Type | Description                                              |
| ------------- | -------------------------------------------------------- |
| NONE          | Endpoint can be accessed freely.                         |
| TRADE         | Endpoint requires sending a valid API-Key and signature. |
| USER_DATA     | Endpoint requires sending a valid API-Key and signature. |
| USER_STREAM   | Endpoint requires sending a valid API-Key.               |
| MARKET_DATA   | Endpoint requires sending a valid API-Key.               |

- `TRADE` and `USER_DATA` endpoints are `SIGNED` endpoints.

