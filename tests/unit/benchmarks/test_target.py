from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import crypto_collector.benchmarks.target as target_module
from crypto_collector.benchmarks.contracts import (
    GateRootProbeV1,
    GateTargetReprobeV1,
    GateTargetV1,
)
from crypto_collector.benchmarks.target import (
    GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES,
    declare_target,
    load_target_declaration,
    reprobe_target,
)
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.storage.errors import PublicationConflict
from crypto_collector.storage.raw_writer import NoReplaceCapability

_TARGET_FIELDS = (
    "schema_version",
    "record_type",
    "target_id",
    "data_root",
    "state_root",
    "deployment_purpose",
    "created_at_unix_ns",
    "sha256",
)
_ROOT_FIELDS = (
    "schema_version",
    "record_type",
    "root",
    "storage_device",
    "filesystem",
    "mount_point",
    "mount_options",
    "minimum_available_bytes",
    "observed_available_bytes",
    "no_replace_capability",
    "same_parent_publication_only",
    "file_sync_supported",
    "directory_sync_supported",
)
_REPROBE_FIELDS = (
    "schema_version",
    "record_type",
    "target_id",
    "expected_target_id",
    "declaration_sha256",
    "probed_at_unix_ns",
    "data_root",
    "state_root",
    "shared_mount",
    "shared_required_available_bytes",
    "shared_observed_available_bytes",
    "target_id_matches",
    "declaration_facts_match",
    "available_space_valid",
    "reprobe_valid",
    "sha256",
)


def _device(path: Path) -> str:
    value = path.stat().st_dev
    return f"{os.major(value)}:{os.minor(value)}"


def _mountinfo(*roots: Path, mount_point: str | None = None) -> bytes:
    lines = []
    for index, root in enumerate(roots, start=10):
        device = _device(root)
        selected_mount = root.as_posix() if mount_point is None else mount_point
        lines.append(
            f"{index} 1 {device} / {selected_mount} rw,nosuid shared:1 - "
            "ext4 /dev/test rw,noatime"
        )
    return ("\n".join(lines) + "\n").encode("ascii")


def _patch_linux(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mountinfo: bytes,
    available_bytes: int = 300 * 1024**3,
) -> None:
    monkeypatch.setattr(target_module, "_is_linux", lambda: True)
    monkeypatch.setattr(target_module, "_read_mountinfo_bytes", lambda: mountinfo)
    monkeypatch.setattr(
        target_module,
        "_available_bytes",
        lambda _path: available_bytes,
    )
    monkeypatch.setattr(
        target_module, "_now_unix_ns", lambda: 1_800_000_000_000_000_000
    )


def _self_hash(values: dict[str, Any]) -> str:
    return hashlib.sha256(encode_json(values) + b"\n").hexdigest()


def _root_values(root_path: Path, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": 1,
        "record_type": "gate_root_probe_v1",
        "root": root_path.as_posix(),
        "storage_device": _device(root_path),
        "filesystem": "ext4",
        "mount_point": root_path.as_posix(),
        "mount_options": ("mount:nosuid", "mount:rw", "super:noatime", "super:rw"),
        "minimum_available_bytes": GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES,
        "observed_available_bytes": 300 * 1024**3,
        "no_replace_capability": NoReplaceCapability.HARDLINK,
        "same_parent_publication_only": True,
        "file_sync_supported": True,
        "directory_sync_supported": True,
    }
    values.update(overrides)
    return values


def _target_values(
    data_root: Path, state_root: Path, **overrides: object
) -> dict[str, object]:
    unsigned: dict[str, object] = {
        "schema_version": 1,
        "record_type": "gate_target_v1",
        "target_id": "target-a",
        "data_root": _root_values(data_root),
        "state_root": _root_values(state_root),
        "deployment_purpose": "raw-writer-gate-b",
        "created_at_unix_ns": 1_800_000_000_000_000_000,
    }
    unsigned.update(overrides)
    return {**unsigned, "sha256": _self_hash(unsigned)}


def test_target_contract_field_order_is_frozen() -> None:
    assert tuple(GateRootProbeV1.model_fields) == _ROOT_FIELDS
    assert tuple(GateTargetV1.model_fields) == _TARGET_FIELDS
    assert tuple(GateTargetReprobeV1.model_fields) == _REPROBE_FIELDS


@pytest.mark.parametrize("value", [True, 1.0, "1", 0, 2])
def test_target_schema_versions_are_strict(value: object, tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    data_root.mkdir()
    state_root.mkdir()
    values = _root_values(data_root, schema_version=value)
    with pytest.raises(ValidationError):
        GateRootProbeV1.model_validate(values)


@pytest.mark.parametrize(
    "field,value",
    [
        ("root", "/"),
        ("root", "relative"),
        ("root", "/data/../state"),
        ("storage_device", "1"),
        ("storage_device", "01:2"),
        ("mount_point", "relative"),
        ("mount_options", ("super:rw", "mount:rw")),
        ("mount_options", ("mount:rw", "mount:rw")),
        ("mount_options", ("optional:shared",)),
        ("minimum_available_bytes", GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES - 1),
        ("no_replace_capability", NoReplaceCapability.RENAMEAT2_NOREPLACE),
        ("same_parent_publication_only", False),
        ("file_sync_supported", False),
        ("directory_sync_supported", False),
    ],
)
def test_root_contract_rejects_noncanonical_facts(
    field: str,
    value: object,
    tmp_path: Path,
) -> None:
    root = tmp_path / "data"
    root.mkdir()
    with pytest.raises(ValidationError):
        GateRootProbeV1.model_validate(_root_values(root, **{field: value}))


def test_target_self_hash_rejects_tampering(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    data_root.mkdir()
    state_root.mkdir()
    values = _target_values(data_root, state_root)
    target = GateTargetV1.model_validate(values)

    assert (
        target.canonical_bytes() == encode_json(target.model_dump(mode="json")) + b"\n"
    )
    with pytest.raises(ValidationError, match="SHA-256"):
        GateTargetV1.model_validate({**values, "target_id": "target-b"})


def test_absolute_target_paths_preserve_valid_posix_backslashes(tmp_path: Path) -> None:
    root = tmp_path / "data"
    root.mkdir()
    model = GateRootProbeV1.model_validate(
        _root_values(root, mount_point="/mounted/back\\slash")
    )

    assert model.mount_point == "/mounted/back\\slash"


@pytest.mark.parametrize("target_id", ["", " target", "target/path", True])
def test_declaration_rejects_target_id_before_probing(
    target_id: object,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    state_root = (tmp_path / "state").resolve()
    data_root.mkdir()
    state_root.mkdir()
    probe_called = False

    def unexpected_probe(*_args: object, **_kwargs: object) -> GateRootProbeV1:
        nonlocal probe_called
        probe_called = True
        raise AssertionError("probe must not run")

    monkeypatch.setattr(target_module, "_probe_root", unexpected_probe)
    with pytest.raises((TypeError, ValueError)):
        declare_target(
            target_id=cast(str, target_id),
            data_root=data_root,
            state_root=state_root,
            output=tmp_path / "target.json",
        )
    assert probe_called is False


def test_target_requires_distinct_roots_and_shared_floor(tmp_path: Path) -> None:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    data_root.mkdir()
    state_root.mkdir()

    with pytest.raises(ValidationError, match="distinct"):
        GateTargetV1.model_validate(_target_values(data_root, data_root))

    state = _root_values(
        state_root,
        storage_device=_device(data_root),
        mount_point=data_root.as_posix(),
        observed_available_bytes=199 * 1024**3,
    )
    data = _root_values(data_root, observed_available_bytes=199 * 1024**3)
    unsigned = _target_values(data_root, state_root)
    unsigned.update(data_root=data, state_root=state)
    unsigned["sha256"] = _self_hash(
        {key: value for key, value in unsigned.items() if key != "sha256"}
    )
    with pytest.raises(ValidationError, match="shared"):
        GateTargetV1.model_validate(unsigned)


def test_mountinfo_decodes_escapes_and_selects_longest_component_match() -> None:
    mountinfo = (
        b"1 0 8:1 / / rw - ext4 /dev/root rw\n"
        b"2 1 8:2 / /srv/data rw,nodev shared:2 - xfs /dev/data rw,noatime\n"
        b"3 2 8:3 / /srv/data/set\\040a rw,nosuid - ext4 /dev/space rw,relatime\n"
        b"4 2 8:4 / /srv/data/set\\011tab rw - ext4 /dev/tab rw\n"
        b"5 2 8:5 / /srv/data/set\\134slash rw - ext4 /dev/backslash rw\n"
    )
    entries = target_module._parse_mountinfo(mountinfo)

    selected = target_module._select_mount(entries, "/srv/data/set a/child")
    assert selected.storage_device == "8:3"
    assert selected.mount_point == "/srv/data/set a"
    assert selected.mount_options == (
        "mount:nosuid",
        "mount:rw",
        "super:relatime",
        "super:rw",
    )
    assert target_module._select_mount(entries, "/srv/database").mount_point == "/"
    assert entries[3].mount_point == "/srv/data/set\ttab"
    assert entries[4].mount_point == "/srv/data/set\\slash"


@pytest.mark.parametrize(
    "source",
    [
        b"",
        b"1 2 8:1 / / rw ext4 /dev/root rw\n",
        b"1 2 08:1 / / rw - ext4 /dev/root rw\n",
        b"1 2 8:1 / relative rw - ext4 /dev/root rw\n",
        b"1 2 8:1 / /bad\\041escape rw - ext4 /dev/root rw\n",
        b"1 2 8:1 / / rw - ext4 /dev/root rw trailing\n",
        b"01 2 8:1 / / rw - ext4 /dev/root rw\n",
    ],
)
def test_mountinfo_rejects_malformed_input(source: bytes) -> None:
    with pytest.raises(ValueError, match="mountinfo"):
        target_module._parse_mountinfo(source)


def test_declare_target_probes_publishes_and_loads_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    state_root = (tmp_path / "state").resolve()
    evidence_root = (tmp_path / "evidence").resolve()
    data_root.mkdir()
    state_root.mkdir()
    evidence_root.mkdir()
    _patch_linux(monkeypatch, mountinfo=_mountinfo(data_root, state_root))
    output = evidence_root / "target.json"

    target = declare_target(
        target_id="target-a",
        data_root=data_root,
        state_root=state_root,
        output=output,
    )

    assert target == load_target_declaration(output)
    assert output.read_bytes() == target.canonical_bytes()
    assert target.data_root.no_replace_capability is NoReplaceCapability.HARDLINK
    assert target.state_root.no_replace_capability is NoReplaceCapability.HARDLINK
    assert not tuple(data_root.glob(".writer-gate-probe-*"))
    assert not tuple(state_root.glob(".writer-gate-probe-*"))
    with pytest.raises(PublicationConflict):
        declare_target(
            target_id="target-a",
            data_root=data_root,
            state_root=state_root,
            output=output,
        )
    assert output.read_bytes() == target.canonical_bytes()


def test_declare_target_rejects_non_linux_symlink_and_low_space(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    state_root = (tmp_path / "state").resolve()
    data_root.mkdir()
    state_root.mkdir()
    output = tmp_path / "target.json"
    monkeypatch.setattr(target_module, "_is_linux", lambda: False)
    with pytest.raises(OSError, match="Linux"):
        declare_target(
            target_id="target-a",
            data_root=data_root,
            state_root=state_root,
            output=output,
        )

    linked = tmp_path / "linked"
    linked.symlink_to(data_root, target_is_directory=True)
    _patch_linux(monkeypatch, mountinfo=_mountinfo(data_root, state_root))
    with pytest.raises(ValueError, match="symlink|real"):
        declare_target(
            target_id="target-a",
            data_root=linked,
            state_root=state_root,
            output=output,
        )

    _patch_linux(
        monkeypatch,
        mountinfo=_mountinfo(data_root, state_root),
        available_bytes=GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES - 1,
    )
    with pytest.raises(ValueError, match="available"):
        declare_target(
            target_id="target-a",
            data_root=data_root,
            state_root=state_root,
            output=output,
        )


def test_reprobe_records_mismatch_without_trusting_a_boolean(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    state_root = (tmp_path / "state").resolve()
    evidence_root = (tmp_path / "evidence").resolve()
    data_root.mkdir()
    state_root.mkdir()
    evidence_root.mkdir()
    _patch_linux(monkeypatch, mountinfo=_mountinfo(data_root, state_root))
    target = declare_target(
        target_id="target-a",
        data_root=data_root,
        state_root=state_root,
        output=evidence_root / "target.json",
    )

    passing = reprobe_target(target, expected_target_id="target-a")
    assert passing.target_id_matches is True
    assert passing.declaration_facts_match is True
    assert passing.available_space_valid is True
    assert passing.reprobe_valid is True

    monkeypatch.setattr(
        target_module,
        "_available_bytes",
        lambda _path: GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES - 1,
    )
    failing = reprobe_target(target, expected_target_id="target-b")
    assert failing.target_id_matches is False
    assert failing.available_space_valid is False
    assert failing.reprobe_valid is False
    assert failing.sha256 != passing.sha256

    changed_mountinfo = _mountinfo(data_root, state_root).replace(b"ext4", b"xfs")
    _patch_linux(monkeypatch, mountinfo=changed_mountinfo)
    changed = reprobe_target(target, expected_target_id="target-a")
    assert changed.target_id_matches is True
    assert changed.declaration_facts_match is False
    assert changed.available_space_valid is True
    assert changed.reprobe_valid is False


def test_shared_mount_requires_one_combined_floor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root = (tmp_path / "data").resolve()
    state_root = (tmp_path / "state").resolve()
    evidence_root = (tmp_path / "evidence").resolve()
    data_root.mkdir()
    state_root.mkdir()
    evidence_root.mkdir()
    shared_mountinfo = _mountinfo(
        data_root, state_root, mount_point=tmp_path.as_posix()
    )
    _patch_linux(monkeypatch, mountinfo=shared_mountinfo)
    target = declare_target(
        target_id="target-a",
        data_root=data_root,
        state_root=state_root,
        output=evidence_root / "target.json",
    )
    reprobe = reprobe_target(target, expected_target_id="target-a")

    assert reprobe.shared_mount is True
    assert reprobe.shared_required_available_bytes == 200 * 1024**3
    assert reprobe.shared_observed_available_bytes == 300 * 1024**3
    assert reprobe.reprobe_valid is True

    monkeypatch.setattr(
        target_module,
        "_available_bytes",
        lambda _path: 150 * 1024**3,
    )
    low_shared = reprobe_target(target, expected_target_id="target-a")
    assert low_shared.data_root.observed_available_bytes >= 100 * 1024**3
    assert low_shared.state_root.observed_available_bytes >= 100 * 1024**3
    assert low_shared.available_space_valid is False
    assert low_shared.reprobe_valid is False


def test_probe_cleanup_syncs_root_after_capability_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = (tmp_path / "data").resolve()
    root.mkdir()
    sync_calls: list[Path] = []
    real_sync = target_module.fsync_directory

    def recording_sync(path: Path) -> None:
        sync_calls.append(path)
        real_sync(path)

    def failed_publish(*_args: object, **_kwargs: object) -> None:
        raise OSError("injected hard-link failure")

    monkeypatch.setattr(target_module, "fsync_directory", recording_sync)
    monkeypatch.setattr(target_module, "publish_no_replace", failed_publish)

    with pytest.raises(OSError, match="injected"):
        target_module._probe_publication_capabilities(root)

    assert sync_calls[-1] == root
    assert not tuple(root.iterdir())
