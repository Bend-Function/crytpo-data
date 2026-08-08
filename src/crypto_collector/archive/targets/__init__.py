"""Archive provider target contracts."""

from crypto_collector.archive.targets.base import (
    ArchiveObjectSource,
    ArchiveTarget,
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

__all__ = [
    "ArchiveObjectSource",
    "ArchiveTarget",
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
