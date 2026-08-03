from __future__ import annotations

from crypto_collector.domain import Exchange


def assert_adapter_identity(adapter: object, exchange: Exchange) -> None:
    assert getattr(adapter, "exchange", None) is exchange
    for method in ("probe", "fetch_catalog", "plan", "run"):
        assert callable(getattr(adapter, method, None)), method
