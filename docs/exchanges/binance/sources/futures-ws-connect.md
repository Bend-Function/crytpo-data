
# Websocket Market Streams

- The connection method for Websocket is：
  - Base Url: **wss://fstream.binance.com**
  - Three routed endpoints are available based on data type:
    - **Public** (high-frequency public market data): `wss://fstream.binance.com/public`
    - **Market** (regular market data): `wss://fstream.binance.com/market`
    - **Private** (user data): `wss://fstream.binance.com/private`
  - Two access modes are supported:
    - `ws` mode: streams are composed in the URL path — **/ws/&lt;streamName&gt;**
    - `stream` mode: streams are passed via query parameters —
      **/stream?streams=&lt;streamName1&gt;/&lt;streamName2&gt;/&lt;streamName3&gt;**
  - Examples:
    - `wss://fstream.binance.com/market/ws/bnbusdt@aggTrade`
    - `wss://fstream.binance.com/public/ws/bnbusdt@depth/ethusdt@depth`
    - `wss://fstream.binance.com/market/stream?streams=bnbusdt@aggTrade/btcusdt@markPrice`

> **Important:** Connections that do not include a routed path (`/public`, `/market`, or `/private`)
> will only receive data from the **Public** endpoint. Streams belonging to `/market` or `/private`
> will not push data on unrouted connections. For example,
> `wss://fstream.binance.com/ws/btcusdt@depth` will continue to work (since `@depth` belongs to
> `/public`), but `wss://fstream.binance.com/ws/btcusdt@markPrice` will not (since `@markPrice`
> belongs to `/market`). See [Important WebSocket Change Notice](Important-WebSocket-Change-Notice)
> for the full stream-to-endpoint mapping and migration details.

- Combined stream events are wrapped as follows:
  **{"stream":"&lt;streamName&gt;","data":&lt;rawPayload&gt;}**
- All symbols for streams are **lowercase**
- A single connection is only valid for 24 hours; expect to be disconnected at the 24 hour mark
- The websocket server will send a `ping frame` every 3 minutes. If the websocket server does not
  receive a `pong frame` back from the connection within a 10 minute period, the connection will be
  disconnected. Unsolicited `pong frames` are allowed(the client can send pong frames at a frequency
  higher than every 15 minutes to maintain the connection).
- WebSocket connections have a limit of 10 incoming messages per second.
- A connection that goes beyond the limit will be disconnected; IPs that are repeatedly disconnected
  may be banned.
- A single connection can listen to a maximum of **1024** streams.
- Considering the possible data latency from RESTful endpoints during an extremely volatile market,
  it is highly recommended to get the order status, position, etc from the Websocket user data
  stream.
