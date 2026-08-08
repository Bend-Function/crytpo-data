from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from crypto_collector.config.reference import (
    ReferenceConfigSnapshot,
    ReferenceDocumentError,
    decode_reference_config,
    decode_reference_payload,
    encode_reference_config,
    encode_reference_payload,
    freeze_reference_document,
    thaw_reference_document,
)

_RESTART_REQUIRED_ROOTS = frozenset({"data_root", "process_model", "state_root"})


@dataclass(frozen=True, slots=True)
class ReloadDiff:
    changed_paths: tuple[str, ...]
    restart_required_keys: tuple[str, ...]

    @property
    def restart_required(self) -> bool:
        return bool(self.restart_required_keys)


def _join_path(parent: str, child: str) -> str:
    if child.startswith("["):
        return f"{parent}{child}"
    return child if not parent else f"{parent}.{child}"


def _collect_changed_paths(old: object, new: object, path: str) -> set[str]:
    if isinstance(old, Mapping) and isinstance(new, Mapping):
        changed: set[str] = set()
        keys = frozenset(old) | frozenset(new)
        for key in keys:
            child_path = _join_path(path, key)
            if key not in old or key not in new:
                changed.add(child_path)
            else:
                changed.update(_collect_changed_paths(old[key], new[key], child_path))
        return changed
    if isinstance(old, tuple) and isinstance(new, tuple):
        if len(old) != len(new):
            return {path}
        changed = set()
        for index, (old_child, new_child) in enumerate(zip(old, new, strict=True)):
            changed.update(
                _collect_changed_paths(
                    old_child,
                    new_child,
                    _join_path(path, f"[{index}]"),
                )
            )
        return changed
    return set() if type(old) is type(new) and old == new else {path}


def classify_reload(
    old: ReferenceConfigSnapshot,
    new: ReferenceConfigSnapshot,
) -> ReloadDiff:
    """Return a deterministic diff without resolving references or mutating snapshots."""

    if not isinstance(old, ReferenceConfigSnapshot) or not isinstance(
        new, ReferenceConfigSnapshot
    ):
        raise TypeError("old and new must be ReferenceConfigSnapshot")
    changed = _collect_changed_paths(old.source_document, new.source_document, "")
    if old.capability_registry_sha256 != new.capability_registry_sha256:
        changed.add("capability_registry_sha256")
    if old.config_path != new.config_path:
        changed.add("config_path")
    if old.base_dir != new.base_dir:
        changed.add("base_dir")
    changed_paths = tuple(sorted(changed))
    restart = tuple(
        sorted(
            {
                (
                    "process_model"
                    if path.rpartition(".")[2].partition("[")[0] == "process_model"
                    else path.partition(".")[0].partition("[")[0]
                )
                for path in changed_paths
                if (
                    path.partition(".")[0].partition("[")[0] in _RESTART_REQUIRED_ROOTS
                    or path.rpartition(".")[2].partition("[")[0] == "process_model"
                )
            }
        )
    )
    return ReloadDiff(
        changed_paths=changed_paths,
        restart_required_keys=restart,
    )


__all__ = [
    "ReferenceConfigSnapshot",
    "ReferenceDocumentError",
    "ReloadDiff",
    "classify_reload",
    "decode_reference_config",
    "decode_reference_payload",
    "encode_reference_config",
    "encode_reference_payload",
    "freeze_reference_document",
    "thaw_reference_document",
]
