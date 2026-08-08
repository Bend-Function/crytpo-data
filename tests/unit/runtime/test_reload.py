from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest

from crypto_collector.capabilities.registry import CapabilityRegistry
from crypto_collector.runtime.reload import (
    ReferenceConfigSnapshot,
    ReferenceDocumentError,
    classify_reload,
    decode_reference_config,
    decode_reference_payload,
    encode_reference_config,
    encode_reference_payload,
)


def _snapshot(
    tmp_path: Path,
    source_document: dict[str, object],
    *,
    config_sha256: str = "a" * 64,
    capability_registry_sha256: str = "b" * 64,
) -> ReferenceConfigSnapshot:
    return ReferenceConfigSnapshot(
        config_sha256=config_sha256,
        capability_registry_sha256=capability_registry_sha256,
        config_path=str(tmp_path / "collector.yaml"),
        base_dir=str(tmp_path),
        source_document=source_document,
    )


def test_reference_config_codec_is_canonical_and_immutable(tmp_path: Path) -> None:
    first = _snapshot(
        tmp_path,
        {
            "network": {
                "egress_pool": [{"id": "proxy-a", "url": "env:COLLECTOR_PROXY_A"}]
            },
            "data_root": str(tmp_path / "data"),
        },
    )
    second = _snapshot(
        tmp_path,
        {
            "data_root": str(tmp_path / "data"),
            "network": {
                "egress_pool": [{"url": "env:COLLECTOR_PROXY_A", "id": "proxy-a"}]
            },
        },
    )

    encoded = encode_reference_config(first)
    assert encoded == encode_reference_config(second)
    assert encoded.endswith(b"}")
    assert b"COLLECTOR_PROXY_A" in encoded
    assert decode_reference_config(encoded) == first

    with pytest.raises(TypeError):
        first.source_document["data_root"] = "/tmp/other"  # type: ignore[index]


def test_generic_audit_payload_endpoint_is_not_treated_as_config_uri() -> None:
    encoded = encode_reference_payload({"endpoint": "logical-endpoint"})

    assert decode_reference_payload(encoded)["endpoint"] == "logical-endpoint"


@pytest.mark.parametrize(
    "source_document",
    [
        {"password": "plaintext"},
        {"credential": "plaintext"},
        {"clientSecret": "plaintext"},
        {"apiKey": "plaintext"},
        {"archive": {"access_key_id": "plaintext"}},
        {"archive": {"access_key_secret": "plaintext"}},
        {"archive": {"security_token": "plaintext"}},
        {"archive": {"secret_access_key": "plaintext"}},
        {"archive": {"session_token": "plaintext"}},
        {
            "network": {
                "egress_pool": [{"id": "proxy-a", "url": "socks5://127.0.0.1:1080"}]
            }
        },
        {"archive": {"targets": [{"mount_guard": {"expected": "literal"}}]}},
        {"Archive": {"Targets": [{"MountGuard": {"Expected": "literal"}}]}},
        {"Network": {"EgressPool": [{"Url": "literal"}]}},
        {"proxy": {"url": "socks5://alice:plaintext@127.0.0.1:1080"}},
        {"ratio": float("nan")},
        {"bad": object()},
    ],
)
def test_reference_config_rejects_non_reference_secrets_and_non_json_values(
    tmp_path: Path, source_document: dict[str, object]
) -> None:
    with pytest.raises(ReferenceDocumentError):
        _snapshot(tmp_path, source_document)


def test_all_config_secret_reference_locations_accept_references_only(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(
        tmp_path,
        {
            "network": {
                "egress_pool": [{"id": "proxy-a", "url": "env:COLLECTOR_PROXY_A"}]
            },
            "archive": {
                "targets": [
                    {
                        "credentials": {
                            "access_key_id": "env:ALIYUN_ACCESS_KEY_ID",
                            "access_key_secret": "file:/run/secrets/aliyun-secret",
                            "security_token": "env:ALIYUN_SECURITY_TOKEN",
                        }
                    },
                    {
                        "credentials": {
                            "access_key_id": "env:S3_ACCESS_KEY_ID",
                            "secret_access_key": "file:/run/secrets/s3-secret",
                            "session_token": "env:S3_SESSION_TOKEN",
                        }
                    },
                    {"mount_guard": {"expected": "file:/run/secrets/mount-sentinel"}},
                ]
            },
        },
    )

    assert decode_reference_config(encode_reference_config(snapshot)) == snapshot


def test_reference_config_decoder_rejects_duplicate_and_unknown_fields(
    tmp_path: Path,
) -> None:
    encoded = encode_reference_config(_snapshot(tmp_path, {"enabled": True}))
    document = json.loads(encoded)
    document["unexpected"] = True

    with pytest.raises(ReferenceDocumentError, match="exactly"):
        decode_reference_config(
            json.dumps(document, separators=(",", ":")).encode("utf-8")
        )

    duplicate = encoded[:-1] + b',"schema_version":1}'
    with pytest.raises(ReferenceDocumentError, match="duplicate"):
        decode_reference_config(duplicate)


def test_reference_config_decoder_migrates_legacy_version_one(
    tmp_path: Path,
) -> None:
    encoded = encode_reference_config(_snapshot(tmp_path, {"enabled": True}))
    legacy = json.loads(encoded)
    legacy["schema_version"] = 1
    del legacy["document_sha256"]

    migrated = decode_reference_config(
        json.dumps(legacy, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )

    assert migrated.schema_version == 2
    assert migrated.document_sha256 is not None
    assert b'"schema_version":2' in encode_reference_config(migrated)


def test_v3_reference_config_binds_the_public_capability_document(
    tmp_path: Path,
) -> None:
    registry = CapabilityRegistry.load_builtin()
    document = registry.to_public_document()
    snapshot = ReferenceConfigSnapshot(
        schema_version=3,
        config_sha256="a" * 64,
        capability_registry_sha256=registry.sha256,
        capability_registry_document=document,
        config_path=str(tmp_path / "collector.yaml"),
        base_dir=str(tmp_path),
        source_document={"enabled": True},
    )

    restored = decode_reference_config(encode_reference_config(snapshot))

    assert restored == snapshot
    assert restored.capability_registry_document is not None
    assert (
        CapabilityRegistry.from_public_document(restored.capability_registry_document)
        == registry
    )

    tampered = deepcopy(document)
    tampered["records"][0]["anonymous_only"] = False  # type: ignore[index]
    with pytest.raises(ReferenceDocumentError, match="capability registry digest"):
        ReferenceConfigSnapshot(
            schema_version=3,
            config_sha256="a" * 64,
            capability_registry_sha256=registry.sha256,
            capability_registry_document=tampered,
            config_path=str(tmp_path / "collector.yaml"),
            base_dir=str(tmp_path),
            source_document={"enabled": True},
        )


def test_v3_reference_config_rejects_unknown_registry_schema_without_canary(
    tmp_path: Path,
) -> None:
    registry = CapabilityRegistry.load_builtin()
    unknown_schema = deepcopy(registry.to_public_document())
    unknown_schema["schema_version"] = 99

    with pytest.raises(ReferenceDocumentError, match="capability registry"):
        ReferenceConfigSnapshot(
            schema_version=3,
            config_sha256="a" * 64,
            capability_registry_sha256=registry.sha256,
            capability_registry_document=unknown_schema,
            config_path=str(tmp_path / "collector.yaml"),
            base_dir=str(tmp_path),
            source_document={"enabled": True},
        )

    canary = "registry-plaintext-secret-canary"
    secret_document = deepcopy(registry.to_public_document())
    secret_document["records"][0]["api_key"] = canary  # type: ignore[index]
    with pytest.raises(ReferenceDocumentError) as captured:
        ReferenceConfigSnapshot(
            schema_version=3,
            config_sha256="a" * 64,
            capability_registry_sha256=registry.sha256,
            capability_registry_document=secret_document,
            config_path=str(tmp_path / "collector.yaml"),
            base_dir=str(tmp_path),
            source_document={"enabled": True},
        )
    assert canary not in str(captured.value)

    invalid_record = deepcopy(registry.to_public_document())
    invalid_record["records"][0]["anonymous_only"] = canary  # type: ignore[index]
    with pytest.raises(ReferenceDocumentError) as graph_capture:
        ReferenceConfigSnapshot(
            schema_version=3,
            config_sha256="a" * 64,
            capability_registry_sha256=registry.sha256,
            capability_registry_document=invalid_record,
            config_path=str(tmp_path / "collector.yaml"),
            base_dir=str(tmp_path),
            source_document={"enabled": True},
        )

    pending: list[BaseException] = [graph_capture.value]
    diagnostics: list[str] = []
    seen: set[int] = set()
    while pending:
        error = pending.pop()
        if id(error) in seen:
            continue
        seen.add(id(error))
        diagnostics.extend((str(error), repr(error), repr(error.args)))
        if error.__cause__ is not None:
            pending.append(error.__cause__)
        if error.__context__ is not None:
            pending.append(error.__context__)
    assert graph_capture.value.__cause__ is None
    assert graph_capture.value.__context__ is None
    assert canary not in "\n".join(diagnostics)


def test_reference_config_rejects_future_schema_and_noncanonical_paths(
    tmp_path: Path,
) -> None:
    with pytest.raises(ReferenceDocumentError, match="schema_version"):
        ReferenceConfigSnapshot(
            schema_version=4,
            config_sha256="a" * 64,
            capability_registry_sha256="b" * 64,
            config_path=str(tmp_path / "collector.yaml"),
            base_dir=str(tmp_path),
            source_document={"enabled": True},
        )

    with pytest.raises(ReferenceDocumentError, match="normalized absolute path"):
        ReferenceConfigSnapshot(
            config_sha256="a" * 64,
            capability_registry_sha256="b" * 64,
            config_path=str(tmp_path / "nested" / ".." / "collector.yaml"),
            base_dir=str(tmp_path),
            source_document={"enabled": True},
        )

    with pytest.raises(ReferenceDocumentError, match="directly inside"):
        ReferenceConfigSnapshot(
            config_sha256="a" * 64,
            capability_registry_sha256="b" * 64,
            config_path=str(tmp_path / "nested" / "collector.yaml"),
            base_dir=str(tmp_path),
            source_document={"enabled": True},
        )


def test_reference_codec_rejects_oversized_documents_before_persistence(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path, {"padding": "x" * (8 * 1024 * 1024)})

    with pytest.raises(ReferenceDocumentError, match="exceeds 8 MiB"):
        encode_reference_config(snapshot)


def test_reference_encoder_revalidates_a_force_mutated_snapshot(
    tmp_path: Path,
) -> None:
    snapshot = _snapshot(tmp_path, {"enabled": True})
    canary = "plaintext-canary"
    object.__setattr__(snapshot, "source_document", {"password": canary})

    with pytest.raises(ReferenceDocumentError) as captured:
        encode_reference_config(snapshot)

    assert canary not in str(captured.value)


def test_case_variant_sensitive_paths_reject_without_echoing_canary(
    tmp_path: Path,
) -> None:
    canary = "plaintext-canary"

    with pytest.raises(ReferenceDocumentError) as captured:
        _snapshot(
            tmp_path,
            {"Archive": {"Targets": [{"MountGuard": {"Expected": canary}}]}},
        )

    assert canary not in str(captured.value)


def test_malformed_url_error_never_echoes_the_input_secret(tmp_path: Path) -> None:
    canary = "plaintext-canary"
    malformed = f"https://user:{canary}@example.test／path"

    with pytest.raises(ReferenceDocumentError) as captured:
        _snapshot(tmp_path, {"endpoint": malformed})

    assert canary not in str(captured.value)


def test_reload_diff_is_pure_deterministic_and_classifies_restart_roots(
    tmp_path: Path,
) -> None:
    old = _snapshot(
        tmp_path,
        {
            "data_root": str(tmp_path / "data-a"),
            "state_root": str(tmp_path / "state-a"),
            "selection": {"fixed_pairs": ["BTC-USDT"]},
            "network": {"retry": {"max_attempts": 3}},
        },
    )
    new = _snapshot(
        tmp_path,
        {
            "data_root": str(tmp_path / "data-b"),
            "state_root": str(tmp_path / "state-b"),
            "selection": {"fixed_pairs": ["BTC-USDT", "ETH-USDT"]},
            "network": {"retry": {"max_attempts": 5}},
        },
        config_sha256="c" * 64,
    )

    diff = classify_reload(old, new)

    assert diff.changed_paths == (
        "data_root",
        "network.retry.max_attempts",
        "selection.fixed_pairs",
        "state_root",
    )
    assert diff.restart_required_keys == ("data_root", "state_root")
    assert diff.restart_required is True
    assert old.source_document["data_root"] == str(tmp_path / "data-a")


def test_capability_hash_and_process_model_changes_are_reported(tmp_path: Path) -> None:
    old = _snapshot(tmp_path, {"runtime": {"process_model": "one-per-exchange"}})
    new = _snapshot(
        tmp_path,
        {"runtime": {"process_model": "single-process"}},
        config_sha256="c" * 64,
        capability_registry_sha256="d" * 64,
    )

    diff = classify_reload(old, new)

    assert diff.changed_paths == (
        "capability_registry_sha256",
        "runtime.process_model",
    )
    assert diff.restart_required_keys == ("process_model",)


def test_reload_diff_is_unchanged_by_equivalent_v3_registry_documents(
    tmp_path: Path,
) -> None:
    registry = CapabilityRegistry.load_builtin()
    common = {
        "schema_version": 3,
        "capability_registry_sha256": registry.sha256,
        "capability_registry_document": registry.to_public_document(),
        "config_path": str(tmp_path / "collector.yaml"),
        "base_dir": str(tmp_path),
    }
    old = ReferenceConfigSnapshot(
        config_sha256="a" * 64,
        source_document={"selection": {"top_n": 10}},
        **common,  # type: ignore[arg-type]
    )
    new = ReferenceConfigSnapshot(
        config_sha256="b" * 64,
        source_document={"selection": {"top_n": 11}},
        **common,  # type: ignore[arg-type]
    )
    legacy = ReferenceConfigSnapshot(
        schema_version=2,
        config_sha256=old.config_sha256,
        capability_registry_sha256=registry.sha256,
        config_path=old.config_path,
        base_dir=old.base_dir,
        source_document=old.source_document,
    )

    assert classify_reload(legacy, old).changed_paths == ()
    assert classify_reload(old, new).changed_paths == ("selection.top_n",)
