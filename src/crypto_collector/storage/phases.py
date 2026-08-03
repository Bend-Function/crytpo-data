from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol


class StoragePhaseHook(Protocol):
    def __call__(self, phase: str) -> None: ...


def notify_storage_phase(hook: StoragePhaseHook | None, phase: str) -> None:
    if hook is not None:
        hook(phase)


def project_storage_phase_hook(
    hook: StoragePhaseHook | None,
    mapping: Mapping[str, str],
    *,
    passthrough: bool = False,
) -> StoragePhaseHook | None:
    if hook is None:
        return None
    if not callable(hook):
        raise TypeError("hook must be callable or None")
    if not isinstance(mapping, Mapping) or any(
        type(source) is not str or not source or type(target) is not str or not target
        for source, target in mapping.items()
    ):
        raise ValueError("phase mapping must contain nonempty string pairs")
    if type(passthrough) is not bool:
        raise TypeError("passthrough must be bool")
    frozen_mapping = dict(mapping)

    def projected(phase: str) -> None:
        if passthrough:
            hook(phase)
        target = frozen_mapping.get(phase)
        if target is not None:
            hook(target)

    return projected


__all__ = [
    "StoragePhaseHook",
    "notify_storage_phase",
    "project_storage_phase_hook",
]
