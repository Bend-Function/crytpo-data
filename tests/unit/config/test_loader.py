from __future__ import annotations

import json
import pickle
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

from crypto_collector.capabilities.registry import CapabilityError, CapabilityRegistry
from crypto_collector.config.fingerprint import config_sha256
from crypto_collector.config.loader import (
    ConfigSecretError,
    load_config,
    load_reference_config,
    load_resolved_config,
    rehydrate_bundle,
)
from crypto_collector.config.primitives import SecretRef
from crypto_collector.config.yaml import ConfigSyntaxError, load_yaml_mapping
from crypto_collector.runtime.reload import (
    ReferenceConfigSnapshot,
    ReferenceDocumentError,
    classify_reload,
    decode_reference_config,
    encode_reference_config,
)


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


def test_reference_snapshot_freezes_the_actual_merged_document(
    config_tree: Path,
) -> None:
    snapshot = load_reference_config(config_tree)
    original = rehydrate_bundle(snapshot)

    assert snapshot.config_path == str((config_tree / "config.yaml").resolve())
    assert snapshot.base_dir == str(config_tree.resolve())
    assert snapshot.source_document["data_root"] == str(
        (config_tree / "data").resolve()
    )
    assert snapshot.source_document["state_root"] == str(
        (config_tree / "state").resolve()
    )
    assert snapshot.source_document["selection"] == {"top_n": 10}
    exchanges = snapshot.source_document["exchanges"]
    assert isinstance(exchanges, Mapping)
    binance = exchanges["binance"]
    assert isinstance(binance, Mapping)
    assert binance["selection"] == {"top_n": 5}

    (config_tree / "config.yaml").unlink()
    (config_tree / "config" / "network.yaml").write_text(
        "this: [is: no longer valid\n", encoding="utf-8"
    )
    (config_tree / "config" / "profiles" / "test.yaml").unlink()
    (config_tree / "config" / "exchanges" / "binance.yaml").unlink()

    assert rehydrate_bundle(snapshot) == original


def test_v3_snapshot_rehydrates_after_builtin_registry_changes(
    config_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = load_reference_config(config_tree)
    expected = rehydrate_bundle(snapshot)

    assert snapshot.schema_version == 3
    assert snapshot.capability_registry_document is not None

    def fail_if_builtin_is_read(cls: type[CapabilityRegistry]) -> CapabilityRegistry:
        raise AssertionError("v3 rehydrate read the current binary registry")

    monkeypatch.setattr(
        CapabilityRegistry,
        "load_builtin",
        classmethod(fail_if_builtin_is_read),
    )

    assert rehydrate_bundle(snapshot) == expected


def test_legacy_v2_snapshot_keeps_builtin_registry_fail_closed_semantics(
    config_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    current = load_reference_config(config_tree)
    legacy = ReferenceConfigSnapshot(
        schema_version=2,
        config_sha256=current.config_sha256,
        capability_registry_sha256=current.capability_registry_sha256,
        config_path=current.config_path,
        base_dir=current.base_dir,
        source_document=current.source_document,
    )
    builtin = CapabilityRegistry.load_builtin()
    mutated = CapabilityRegistry(records=builtin.records, sha256="0" * 64)
    monkeypatch.setattr(
        CapabilityRegistry,
        "load_builtin",
        classmethod(lambda cls: mutated),
    )

    with pytest.raises(ReferenceDocumentError, match="built-in registry"):
        rehydrate_bundle(legacy)

    assert legacy.capability_registry_document is None


def test_reference_snapshot_freezes_symlinked_model_paths(
    config_tree: Path,
) -> None:
    first_data = config_tree / "first-data"
    second_data = config_tree / "second-data"
    first_archive = config_tree / "first-archive"
    second_archive = config_tree / "second-archive"
    first_mount = config_tree / "first-mount"
    second_mount = config_tree / "second-mount"
    for directory in (
        first_data,
        second_data,
        first_archive,
        second_archive,
        first_mount,
        second_mount,
    ):
        directory.mkdir()

    data_link = config_tree / "data-link"
    archive_link = config_tree / "archive-link"
    mount_link = config_tree / "mount-link"
    data_link.symlink_to(first_data, target_is_directory=True)
    archive_link.symlink_to(first_archive, target_is_directory=True)
    mount_link.symlink_to(first_mount, target_is_directory=True)

    root = config_tree / "config.yaml"
    root.write_text(
        root.read_text(encoding="utf-8").replace(
            "data_root: ./data",
            "data_root: ./data-link/records",
        )
        + """\
archive:
  targets:
    - id: mounted
      type: filesystem
      root: ./archive-link/objects
      mount_guard:
        path: ./mount-link/identity
        expected: env:MOUNT_ID
""",
        encoding="utf-8",
    )

    snapshot = load_reference_config(config_tree)
    original = rehydrate_bundle(snapshot)
    archive = snapshot.source_document["archive"]
    assert isinstance(archive, Mapping)
    targets = archive["targets"]
    assert isinstance(targets, tuple)
    target = targets[0]
    assert isinstance(target, Mapping)
    guard = target["mount_guard"]
    assert isinstance(guard, Mapping)
    assert snapshot.source_document["data_root"] == str(first_data / "records")
    assert target["root"] == str(first_archive / "objects")
    assert guard["path"] == str(first_mount / "identity")

    for link, replacement in (
        (data_link, second_data),
        (archive_link, second_archive),
        (mount_link, second_mount),
    ):
        link.unlink()
        link.symlink_to(replacement, target_is_directory=True)

    assert rehydrate_bundle(snapshot) == original


def test_reload_diff_classifies_relative_roots_after_base_directory_move(
    tmp_path: Path,
) -> None:
    snapshots: list[ReferenceConfigSnapshot] = []
    for name in ("first", "second"):
        tree = tmp_path / name
        _write(
            tree / "config.yaml",
            "data_root: ./data\nstate_root: ./state\n",
        )
        _write(
            tree / "config" / "network.yaml",
            "egress_pool:\n  - id: direct\n    type: direct\n",
        )
        snapshots.append(load_reference_config(tree))

    diff = classify_reload(snapshots[0], snapshots[1])

    assert set(diff.changed_paths) >= {
        "base_dir",
        "config_path",
        "data_root",
        "state_root",
    }
    assert diff.restart_required_keys == ("data_root", "state_root")


def test_reference_loader_redacts_symlink_loop_path(config_tree: Path) -> None:
    canary = "path-plaintext-canary"
    loop = config_tree / canary
    loop.symlink_to(loop.name)
    root = config_tree / "config.yaml"
    root.write_text(
        root.read_text(encoding="utf-8").replace(
            "data_root: ./data",
            f"data_root: ./{canary}/records",
        ),
        encoding="utf-8",
    )

    with pytest.raises(ReferenceDocumentError) as captured:
        load_reference_config(config_tree)

    assert canary not in str(captured.value)


def test_reference_snapshot_binds_every_durable_input(config_tree: Path) -> None:
    snapshot = load_reference_config(config_tree)
    assert snapshot.document_sha256 is not None
    assert decode_reference_config(encode_reference_config(snapshot)) == snapshot
    assert pickle.loads(pickle.dumps(snapshot)) == snapshot

    document = json.loads(encode_reference_config(snapshot))
    document["source_document"]["selection"]["top_n"] = 11
    with pytest.raises(ReferenceDocumentError, match="document digest"):
        decode_reference_config(
            json.dumps(document, separators=(",", ":")).encode("utf-8")
        )

    with pytest.raises(ReferenceDocumentError, match="document digest"):
        replace(snapshot, config_path=str(config_tree / "alternate.yaml"))
    with pytest.raises(ReferenceDocumentError, match="document digest|base_dir"):
        replace(snapshot, base_dir=str((config_tree / "other").resolve()))
    with pytest.raises(ReferenceDocumentError, match="document digest"):
        replace(
            snapshot, source_document={**snapshot.source_document, "profile": "other"}
        )


def test_rehydrate_rejects_config_and_capability_digest_mutations(
    config_tree: Path,
) -> None:
    snapshot = load_reference_config(config_tree)

    forged_config = ReferenceConfigSnapshot(
        config_sha256="0" * 64,
        capability_registry_sha256=snapshot.capability_registry_sha256,
        config_path=snapshot.config_path,
        base_dir=snapshot.base_dir,
        source_document=snapshot.source_document,
    )
    with pytest.raises(ReferenceDocumentError, match="config digest"):
        rehydrate_bundle(forged_config)

    forged_capability = ReferenceConfigSnapshot(
        config_sha256=snapshot.config_sha256,
        capability_registry_sha256="0" * 64,
        config_path=snapshot.config_path,
        base_dir=snapshot.base_dir,
        source_document=snapshot.source_document,
    )
    with pytest.raises(ReferenceDocumentError, match="capability registry digest"):
        rehydrate_bundle(forged_capability)


def test_reference_snapshot_never_resolves_or_serializes_secret_values(
    config_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
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
    canary = "socks5h://user:plaintext-canary@127.0.0.1:1080"
    monkeypatch.setenv("SOCKS_URL", canary)

    def fail_if_resolved(self: SecretRef) -> str:
        raise AssertionError(f"unexpected secret read: {self.fingerprint_value()}")

    monkeypatch.setattr(SecretRef, "_resolve_once", fail_if_resolved)
    snapshot = load_reference_config(config_tree)
    encoded = encode_reference_config(snapshot)

    assert b"env:SOCKS_URL" in encoded
    assert canary.encode("utf-8") not in encoded
    assert rehydrate_bundle(snapshot).config.network.egress_pool[0].url == (
        SecretRef.parse("env:SOCKS_URL")
    )


def test_reference_loader_rejects_plaintext_secret_without_echoing_it(
    config_tree: Path,
) -> None:
    canary = "plaintext-canary"
    _write(
        config_tree / "config" / "network.yaml",
        f"""\
egress_pool:
  - id: socks
    type: socks5h
    url: socks5h://user:{canary}@127.0.0.1:1080
""",
    )

    with pytest.raises(ReferenceDocumentError) as captured:
        load_reference_config(config_tree)

    assert canary not in str(captured.value)


@pytest.mark.parametrize(
    "endpoint",
    [
        "//user:plaintext-canary@example.test",
        "https://example.test?api_key=plaintext-canary",
        "https://example.test/#plaintext-canary",
    ],
)
def test_reference_loader_rejects_unsafe_endpoint_without_echoing_it(
    config_tree: Path,
    endpoint: str,
) -> None:
    canary = "plaintext-canary"
    _write(
        config_tree / "config" / "exchanges" / "okx.yaml",
        f"""\
endpoints:
  rest: {endpoint}
markets:
  spot: {{}}
""",
    )

    with pytest.raises(ReferenceDocumentError, match="public endpoint") as captured:
        load_reference_config(config_tree)

    assert canary not in str(captured.value)


def test_reference_snapshot_allows_pathful_websocket_overrides(
    config_tree: Path,
) -> None:
    endpoints = {
        "ws_public": "wss://ws.okx.com:8443/ws/v5/public",
        "ws_business": "wss://ws.okx.com:8443/ws/v5/business",
    }
    _write(
        config_tree / "config" / "exchanges" / "okx.yaml",
        """\
endpoints:
  ws_public: wss://ws.okx.com:8443/ws/v5/public
  ws_business: wss://ws.okx.com:8443/ws/v5/business
markets:
  spot: {}
""",
    )

    snapshot = load_reference_config(config_tree)
    rebuilt = rehydrate_bundle(snapshot)

    exchange = snapshot.source_document["exchanges"]
    assert isinstance(exchange, Mapping)
    okx = exchange["okx"]
    assert isinstance(okx, Mapping)
    assert okx["endpoints"] == endpoints
    assert rebuilt.config.exchanges["okx"].endpoints == endpoints


def test_reference_loader_rejects_oversized_snapshot_before_return(
    config_tree: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import crypto_collector.config.reference as reference_contract

    monkeypatch.setattr(reference_contract, "_MAX_DOCUMENT_BYTES", 256)

    with pytest.raises(ReferenceDocumentError, match="exceeds 8 MiB"):
        load_reference_config(config_tree)


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
