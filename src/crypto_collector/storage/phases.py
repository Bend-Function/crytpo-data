from __future__ import annotations

from typing import Protocol


class StoragePhaseHook(Protocol):
    def __call__(self, phase: str) -> None: ...


def notify_storage_phase(hook: StoragePhaseHook | None, phase: str) -> None:
    if hook is not None:
        hook(phase)


__all__ = ["StoragePhaseHook", "notify_storage_phase"]
