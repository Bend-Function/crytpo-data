# Exchange public API research bundle

This directory contains point-in-time snapshots and implementation notes for
anonymous public market-data APIs. The research date is 2026-07-31. Private
account, wallet, order-entry, and authenticated data are intentionally out of
scope.

| Exchange | Local notes | Archived official sources | Live smoke test |
| --- | --- | ---: | --- |
| Binance | [`binance/README.md`](binance/README.md) | 14 | `tests/smoke/test_binance_public_api.py` |
| OKX | [`okx/README.md`](okx/README.md) | 2 | `tests/smoke/test_okx_public_api.py` |
| Bybit | [`bybit/README.md`](bybit/README.md) | 39 | `tests/smoke/test_bybit_public_api.py` |
| Bitget | [`bitget/index.md`](bitget/index.md) | 22 plus checksum manifest | `tests/smoke/test_bitget_public_api.py` |
| Kraken | [`kraken/README.md`](kraken/README.md) | 28 | `tests/smoke/test_kraken_public_api.py` |

Each exchange note records source URLs, retrieval time, SHA-256 values, REST
and WebSocket endpoints, public channel coverage, rate and connection limits,
heartbeat behavior, order-book reconstruction rules, instrument/listing
discovery, known schema or documentation conflicts, and anonymous exclusions.

## Test environment

The local environment uses Python 3.11. Recreate it from the repository root:

```bash
python3.11 -m venv .venv
.venv/bin/python -m pip install --require-hashes -r requirements/dev.lock
```

Smoke tests are opt-in because they contact live exchange endpoints. Run all
five exchanges with:

```bash
RUN_LIVE_API_TESTS=1 .venv/bin/pytest --force-enable-socket -q tests/smoke
```

Without `RUN_LIVE_API_TESTS=1`, the suite must skip every network test. The
tests perform anonymous GET requests and public WebSocket subscriptions only;
they contain no credentials and cannot place orders.

## Important cross-exchange differences

- Preserve native symbols and payloads. Kraken alone uses several BTC names
  (`BTC/USDT`, `XBTUSDT`, and `PF_XBTUSD`), and its Futures ticker mixes
  snake_case with camelCase fields.
- A default USDT quote filter needs a fixed-pair bypass or exchange-specific
  override for Kraken's USD-margined perpetuals.
- Public liquidation streams are not uniformly complete. Binance and Bitget
  publish lossy windowed selections; OKX explicitly documents incomplete
  coverage; do not label these streams as a complete liquidation tape.
- The strongest anonymous order-book integrity mechanism varies: Binance uses
  update IDs, OKX and Bitget use sequence linkage, Bybit uses update/sequence
  rules, Kraken Spot uses a top-10 CRC32 checksum, and Kraken Futures documents
  a sequence field without promising strict `+1` continuity.
- Treat the archived docs as a versioned design input, not a permanent API
  contract. Re-download official sources and re-run the live tests before
  implementing or changing a connector.
