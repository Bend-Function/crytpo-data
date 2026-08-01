from __future__ import annotations

import pickle
from pathlib import Path

import pytest

from crypto_collector.capabilities.registry import CapabilityError
from crypto_collector.config.fingerprint import config_sha256
from crypto_collector.config.loader import (
    ConfigSecretError,
    load_config,
    load_resolved_config,
)
from crypto_collector.config.primitives import SecretRef
from crypto_collector.config.yaml import ConfigSyntaxError, load_yaml_mapping


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


@pytest.fixture
def config_tree(tmp_path: Path) -> Path:
    _write(
        tmp_path / "config.yaml",
        """\
profile: test
data_root: ./data
state_root: ./state
selection:
  top_n: 20
exchanges:
  binance:
    selection:
      top_n: 18
    markets:
      spot:
        selection:
          top_n: 17
""",
    )
    _write(
        tmp_path / "config" / "network.yaml",
        """\
egress_pool:
  - id: direct
    type: direct
""",
    )
    _write(
        tmp_path / "config" / "profiles" / "test.yaml",
        """\
selection:
  top_n: 10
exchanges:
  binance:
    selection:
      top_n: 8
    markets:
      spot:
        selection:
          top_n: 7
""",
    )
    _write(
        tmp_path / "config" / "exchanges" / "binance.yaml",
        """\
selection:
  top_n: 5
markets:
  spot:
    selection:
      top_n: 2
    symbols:
      BTCUSDT:
        selection:
          top_n: 1
""",
    )
    return tmp_path


def test_loader_applies_documented_precedence(config_tree: Path) -> None:
    loaded = load_config(config_tree / "config.yaml")

    assert loaded.config.selection.top_n == 10
    exchange = loaded.config.exchanges["binance"]
    assert exchange.selection.top_n == 5
    assert exchange.markets["spot"].selection.top_n == 2
    assert exchange.markets["spot"].symbols["BTCUSDT"].selection.top_n == 1


def test_loader_accepts_config_directory_and_resolves_paths_from_root(
    config_tree: Path,
) -> None:
    loaded = load_config(config_tree)

    assert loaded.config.data_root == (config_tree / "data").resolve()
    assert loaded.config.state_root == (config_tree / "state").resolve()


def test_loader_reads_network_fragment_as_root_network_subtree(
    config_tree: Path,
) -> None:
    loaded = load_config(config_tree / "config.yaml")

    assert loaded.config.network.egress_pool[0].id == "direct"


def test_loader_rejects_unknown_explicit_date_gated_feature(
    config_tree: Path,
) -> None:
    root = config_tree / "config.yaml"
    root.write_text(
        root.read_text(encoding="utf-8")
        + """\
capabilities:
  date_gated_features:
    okx:
      unknown_feature: {}
""",
        encoding="utf-8",
    )

    with pytest.raises(
        CapabilityError,
        match="unknown date-gated capability: okx/unknown_feature",
    ):
        load_config(root)


def test_loader_rejects_enabled_date_gate_without_applicable_market(
    config_tree: Path,
) -> None:
    root = config_tree / "config.yaml"
    root.write_text(
        root.read_text(encoding="utf-8")
        + """\
capabilities:
  date_gated_features:
    okx:
      books_rpi: {}
""",
        encoding="utf-8",
    )

    with pytest.raises(
        CapabilityError,
        match="date-gated capability has no configured applicable market: okx/books_rpi",
    ):
        load_config(root)


def test_root_network_key_conflicts_with_named_fragment(config_tree: Path) -> None:
    root = config_tree / "config.yaml"
    root.write_text(
        root.read_text(encoding="utf-8") + "network: {}\n", encoding="utf-8"
    )

    with pytest.raises(ConfigSyntaxError, match="network.yaml"):
        load_config(root)


def test_profile_can_explicitly_override_root_network_fragment(
    config_tree: Path,
) -> None:
    profile = config_tree / "config" / "profiles" / "test.yaml"
    profile.write_text(
        profile.read_text(encoding="utf-8")
        + """\
network:
  egress_pool:
    - id: profile-direct
      type: direct
""",
        encoding="utf-8",
    )

    loaded = load_config(config_tree)

    assert loaded.config.network.egress_pool[0].id == "profile-direct"


def test_load_config_does_not_resolve_secret_values(
    config_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        config_tree / "config" / "network.yaml",
        """\
egress_pool:
  - id: socks
    type: socks5h
    url: env:SOCKS_URL
""",
    )

    def fail_if_resolved(self: SecretRef) -> str:
        raise AssertionError(f"unexpected secret read: {self.fingerprint_value()}")

    monkeypatch.setattr(SecretRef, "_resolve_once", fail_if_resolved)
    loaded = load_config(config_tree)

    assert loaded.config.network.egress_pool[0].url == SecretRef.parse("env:SOCKS_URL")


def test_resolved_loader_aggregates_missing_secret_references(
    config_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        config_tree / "config" / "network.yaml",
        """\
egress_pool:
  - id: first
    type: socks5h
    url: env:FIRST_SOCKS_URL
  - id: second
    type: socks5
    url: env:SECOND_SOCKS_URL
""",
    )
    monkeypatch.delenv("FIRST_SOCKS_URL", raising=False)
    monkeypatch.delenv("SECOND_SOCKS_URL", raising=False)

    with pytest.raises(ConfigSecretError) as captured:
        load_resolved_config(config_tree)

    message = str(captured.value)
    assert "FIRST_SOCKS_URL" in message
    assert "SECOND_SOCKS_URL" in message


def test_resolved_loader_rejects_unsafe_file_secret(
    config_tree: Path, tmp_path: Path
) -> None:
    secret = tmp_path / "proxy-url"
    secret.write_text("socks5h://127.0.0.1:1080", encoding="utf-8")
    secret.chmod(0o622)
    _write(
        config_tree / "config" / "network.yaml",
        f"""\
egress_pool:
  - id: socks
    type: socks5h
    url: file:{secret}
""",
    )

    with pytest.raises(ConfigSecretError, match="permissions"):
        load_resolved_config(config_tree)


def test_resolved_loader_validates_proxy_scheme(
    config_tree: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _write(
        config_tree / "config" / "network.yaml",
        """\
egress_pool:
  - id: socks
    type: socks5h
    url: env:SOCKS_URL
""",
    )
    monkeypatch.setenv("SOCKS_URL", "socks5://127.0.0.1:1080")

    with pytest.raises(ConfigSecretError, match="socks5h"):
        load_resolved_config(config_tree)


def test_capability_digest_participates_in_config_fingerprint(
    config_tree: Path,
) -> None:
    loaded = load_config(config_tree)

    assert loaded.config_sha256 == config_sha256(
        loaded.config,
        capability_registry_sha256=loaded.capabilities.sha256,
    )


def test_loader_rejects_deep_snapshot_beyond_capability(config_tree: Path) -> None:
    _write(
        config_tree / "config" / "exchanges" / "okx.yaml",
        """\
markets:
  spot:
    books:
      deep_snapshot:
        depth: 5001
""",
    )

    with pytest.raises(CapabilityError, match="maximum deep REST depth.*5000"):
        load_config(config_tree)


def test_committed_config_loads_with_five_exchanges_and_no_secrets() -> None:
    repository = Path(__file__).parents[3]

    resolved = load_resolved_config(repository / "config.yaml")

    assert set(resolved.bundle.config.exchanges) == {
        "binance",
        "bitget",
        "bybit",
        "kraken",
        "okx",
    }
    assert resolved.bundle.config.network.egress_pool[0].type == "direct"
    assert repr(resolved.secrets) == "SecretSnapshot()"


def test_reference_only_bundle_can_cross_a_process_boundary(config_tree: Path) -> None:
    bundle = load_config(config_tree)

    restored = pickle.loads(pickle.dumps(bundle))

    assert restored == bundle
    assert restored.config_sha256 == bundle.config_sha256


@pytest.mark.parametrize(
    ("name", "body", "message"),
    [
        (
            "duplicate.yaml",
            "data_root: ./first\ndata_root: ./second\n",
            "duplicate",
        ),
        (
            "merge.yaml",
            "base: &base {top_n: 20}\nselection: {<<: *base}\n",
            "merge key",
        ),
        (
            "multiple.yaml",
            "data_root: ./data\n---\nstate_root: ./state\n",
            "single document",
        ),
        ("sequence.yaml", "- one\n- two\n", "mapping"),
        ("unsafe.yaml", "value: !python/object:example {}\n", "tag|construct"),
        ("alias.yaml", "one: &shared [1, 2]\ntwo: *shared\n", "anchor|alias"),
        ("binary.yaml", "value: !!binary SGVsbG8=\n", "scalar"),
        ("infinite.yaml", "value: .inf\n", "finite"),
    ],
)
def test_yaml_safety_rejections(
    tmp_path: Path, name: str, body: str, message: str
) -> None:
    path = tmp_path / name
    path.write_text(body, encoding="utf-8")

    with pytest.raises(ConfigSyntaxError, match=message):
        load_yaml_mapping(path)


def test_duplicate_key_error_does_not_echo_scalar_values(tmp_path: Path) -> None:
    path = tmp_path / "duplicate-secret.yaml"
    path.write_text(
        "url: socks5h://user:first-secret@127.0.0.1\n"
        "url: socks5h://user:second-secret@127.0.0.1\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigSyntaxError) as captured:
        load_yaml_mapping(path)

    message = str(captured.value)
    assert "duplicate" in message
    assert "first-secret" not in message
    assert "second-secret" not in message
