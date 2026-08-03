from pathlib import Path


class PublicationConflict(RuntimeError):
    def __init__(self, source: Path, destination: Path, message: str) -> None:
        self.source = source
        self.destination = destination
        super().__init__(message)


class RecoveryBlocked(RuntimeError):
    """Startup recovery could not establish a safe state before admission."""


class SourceUnavailable(RuntimeError):
    """A manifest's immutable source is not locally available."""


__all__ = [
    "PublicationConflict",
    "RecoveryBlocked",
    "SourceUnavailable",
]
