import pickle
from dataclasses import asdict
from typing import Any, cast

import pytest

from crypto_collector.config.primitives import (
    SecretRef,
    SecretSnapshot,
    parse_duration_ns,
    parse_size_bytes,
)


def test_duration_and_size_use_explicit_units() -> None:
    assert parse_duration_ns("500ms") == 500_000_000
    assert parse_duration_ns("72h") == 259_200_000_000_000
    assert parse_size_bytes("1GiB") == 1_073_741_824


@pytest.mark.parametrize("value", ["1", "1.5s", "-1s", "1M", " 1s"])
def test_invalid_duration_is_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        parse_duration_ns(value)


@pytest.mark.parametrize("value", ["1", "1GB", "1.5MiB", "-1B", "01KiB"])
def test_invalid_size_is_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        parse_size_bytes(value)


def test_secret_repr_never_contains_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:password@127.0.0.1:1080")
    ref = SecretRef.parse("env:SOCKS_URL")
    snapshot = SecretSnapshot.resolve_all([ref])
    value = snapshot.value_for(ref)

    assert value.reveal().startswith("socks5h://")
    assert "password" not in repr(ref)
    assert "password" not in repr(snapshot)
    assert "password" not in repr(value)
    assert ref.fingerprint_value() == "env:SOCKS_URL"


def test_file_secret_is_regular_small_restricted_and_removes_one_newline(
    tmp_path,
) -> None:
    secret = tmp_path / "archive-key"
    secret.write_text("value\n", encoding="utf-8")
    secret.chmod(0o600)
    ref = SecretRef.parse(f"file:{secret}")

    assert SecretSnapshot.resolve_all([ref]).value_for(ref).reveal() == "value"
    assert ref.fingerprint_value() == f"file:{secret}"


def test_group_writable_file_secret_is_rejected(tmp_path) -> None:
    secret = tmp_path / "unsafe"
    secret.write_text("value", encoding="utf-8")
    secret.chmod(0o620)

    with pytest.raises(ValueError, match="permissions"):
        SecretSnapshot.resolve_all([SecretRef.parse(f"file:{secret}")])


def test_file_secret_symlink_is_rejected(tmp_path) -> None:
    target = tmp_path / "target"
    target.write_text("value", encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "link"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="resolve|symbolic|symlink"):
        SecretSnapshot.resolve_all([SecretRef.parse(f"file:{link}")])


def test_snapshot_resolves_each_distinct_reference_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONE", "value")
    ref = SecretRef.parse("env:ONE")
    calls = 0
    original = SecretRef._resolve_once

    def counting_resolve(item: SecretRef) -> str:
        nonlocal calls
        calls += 1
        return original(item)

    monkeypatch.setattr(SecretRef, "_resolve_once", counting_resolve)

    snapshot = SecretSnapshot.resolve_all([ref, ref])

    assert snapshot.value_for(ref).reveal() == "value"
    assert calls == 1


def test_secret_failures_are_aggregated_without_resolved_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PRESENT", "must-not-leak")

    with pytest.raises(ValueError, match="MISSING_ONE.*MISSING_TWO") as captured:
        SecretSnapshot.resolve_all(
            [
                SecretRef.parse("env:PRESENT"),
                SecretRef.parse("env:MISSING_ONE"),
                SecretRef.parse("env:MISSING_TWO"),
            ]
        )

    assert "must-not-leak" not in str(captured.value)


def test_secret_values_and_snapshots_cannot_be_pickled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONE", "value")
    ref = SecretRef.parse("env:ONE")
    snapshot = SecretSnapshot.resolve_all([ref])

    with pytest.raises(TypeError, match="secret"):
        pickle.dumps(snapshot.value_for(ref))
    with pytest.raises(TypeError, match="secret"):
        pickle.dumps(snapshot)


def test_secret_value_rejects_dataclass_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ONE", "must-not-leak")
    ref = SecretRef.parse("env:ONE")
    value = SecretSnapshot.resolve_all([ref]).value_for(ref)

    with pytest.raises(TypeError):
        asdict(cast(Any, value))
