from __future__ import annotations

from dataclasses import dataclass

from crypto_collector.domain import Exchange
from crypto_collector.runtime.state import WorkerState


@dataclass(frozen=True, slots=True)
class WorkerStatus:
    exchange: Exchange
    worker_instance_id: str
    state: WorkerState
    config_sha256: str
    gap_count: int
    last_failure: str | None
    exit_code: int | None

    def __post_init__(self) -> None:
        if type(self.exchange) is not Exchange:
            raise TypeError("exchange must be Exchange")
        if type(self.worker_instance_id) is not str or not self.worker_instance_id:
            raise ValueError("worker_instance_id must be a non-empty string")
        if type(self.state) is not WorkerState:
            raise TypeError("state must be WorkerState")
        if (
            type(self.config_sha256) is not str
            or len(self.config_sha256) != 64
            or any(
                character not in "0123456789abcdef" for character in self.config_sha256
            )
        ):
            raise ValueError("config_sha256 must be a lowercase SHA-256 digest")
        if type(self.gap_count) is not int or self.gap_count < 0:
            raise ValueError("gap_count must be a non-negative integer")
        if self.last_failure is not None and (
            type(self.last_failure) is not str or not self.last_failure
        ):
            raise ValueError("last_failure must be a non-empty string or None")
        if self.exit_code is not None and type(self.exit_code) is not int:
            raise TypeError("exit_code must be an integer or None")


@dataclass(frozen=True, slots=True)
class FatalWriterSignal:
    reason: str

    def __post_init__(self) -> None:
        if type(self.reason) is not str or not self.reason:
            raise ValueError("fatal writer reason must be a non-empty string")
