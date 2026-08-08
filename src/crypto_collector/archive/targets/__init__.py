"""Archive provider target contracts."""

from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    ArchiveTarget,
    MultipartJournal,
    MultipartJournalFactory,
    PutResult,
    ReceiptLastCommit,
    ResumeState,
    TargetClosed,
    TargetProbe,
    TargetUnavailable,
    TargetVerificationError,
    UnsafeObjectKey,
    VerifyResult,
    publish_receipt_last,
)
from crypto_collector.archive.targets.filesystem import (
    FilesystemNoReplaceCapability,
    FilesystemTarget,
)

__all__ = [
    "ArchiveObjectSource",
    "ArchiveTarget",
    "FilesystemNoReplaceCapability",
    "FilesystemTarget",
    "MultipartJournal",
    "MultipartJournalFactory",
    "PutResult",
    "ReceiptLastCommit",
    "ResumeState",
    "TargetClosed",
    "TargetProbe",
    "TargetUnavailable",
    "TargetVerificationError",
    "UnsafeObjectKey",
    "VerifyResult",
    "publish_receipt_last",
]
