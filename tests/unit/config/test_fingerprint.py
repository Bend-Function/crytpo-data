from crypto_collector.config.fingerprint import config_sha256
from crypto_collector.config.models import CollectorConfig
from tests.unit.config.test_models import BASE


def test_fingerprint_is_canonical_and_secret_value_independent(monkeypatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:first@127.0.0.1:1080")
    config = CollectorConfig.model_validate(BASE)
    first = config_sha256(config, capability_registry_sha256="c" * 64)
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:second@127.0.0.1:1080")

    assert config_sha256(config, capability_registry_sha256="c" * 64) == first
    assert config_sha256(config, capability_registry_sha256="d" * 64) != first


def test_fingerprint_ignores_materializer_interval_order() -> None:
    first = CollectorConfig.model_validate(
        BASE | {"materializer": {"intervals": ["30s", "1m", "5m"]}}
    )
    second = CollectorConfig.model_validate(
        BASE | {"materializer": {"intervals": ["5m", "30s", "1m"]}}
    )

    assert config_sha256(first, capability_registry_sha256="c" * 64) == config_sha256(
        second,
        capability_registry_sha256="c" * 64,
    )


def test_fingerprint_includes_materializer_event_time_policy() -> None:
    baseline = CollectorConfig.model_validate(BASE)
    changed_past = CollectorConfig.model_validate(
        BASE | {"materializer": {"max_past_skew": "8d"}}
    )
    changed_future = CollectorConfig.model_validate(
        BASE | {"materializer": {"max_future_skew": "6m"}}
    )
    baseline_sha = config_sha256(
        baseline,
        capability_registry_sha256="c" * 64,
    )

    assert (
        config_sha256(changed_past, capability_registry_sha256="c" * 64) != baseline_sha
    )
    assert (
        config_sha256(changed_future, capability_registry_sha256="c" * 64)
        != baseline_sha
    )
