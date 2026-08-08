from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.storage.manifest import (
    LoadedRawManifest,
    RawManifestV1,
    lease_path_for_data,
)


def _is_sha256(value: str) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


@dataclass(frozen=True, slots=True, order=True)
class SourceLocator:
    manifest_sha256: str
    zero_based_record_index: int

    def __post_init__(self) -> None:
        if not _is_sha256(self.manifest_sha256):
            raise ValueError("manifest_sha256 must be a lowercase SHA-256 digest")
        if (
            type(self.zero_based_record_index) is not int
            or self.zero_based_record_index < 0
        ):
            raise ValueError("zero_based_record_index must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class SourceRecord:
    envelope: RawEnvelope
    locator: SourceLocator

    def __post_init__(self) -> None:
        if type(self.envelope) is not RawEnvelope:
            raise TypeError("envelope must be RawEnvelope")
        if type(self.locator) is not SourceLocator:
            raise TypeError("locator must be SourceLocator")


@dataclass(frozen=True, slots=True)
class TimedSourceRecord:
    source: SourceRecord
    effective_event_time_ns: int

    def __post_init__(self) -> None:
        if type(self.source) is not SourceRecord:
            raise TypeError("source must be SourceRecord")
        if (
            type(self.effective_event_time_ns) is not int
            or self.effective_event_time_ns < 0
        ):
            raise ValueError("effective_event_time_ns must be a non-negative integer")


@dataclass(frozen=True, slots=True, order=True)
class ConnectionGenerationScope:
    worker_instance_id: str
    connection_id: str
    connection_generation: int

    def __post_init__(self) -> None:
        if type(self.worker_instance_id) is not str or not self.worker_instance_id:
            raise ValueError("worker_instance_id must be non-empty")
        if type(self.connection_id) is not str or not self.connection_id:
            raise ValueError("connection_id must be non-empty")
        if (
            type(self.connection_generation) is not int
            or self.connection_generation < 0
        ):
            raise ValueError("connection_generation must be a non-negative integer")


@dataclass(frozen=True, slots=True)
class ReplayOrderedRecord:
    source: SourceRecord
    worker_run_ordinal: int
    starts_worker_run: bool
    invalidates_inherited_generation: bool
    connection_generation_scope: ConnectionGenerationScope | None

    def __post_init__(self) -> None:
        if type(self.source) is not SourceRecord:
            raise TypeError("source must be SourceRecord")
        if type(self.worker_run_ordinal) is not int or self.worker_run_ordinal < 0:
            raise ValueError("worker_run_ordinal must be a non-negative integer")
        if type(self.starts_worker_run) is not bool:
            raise TypeError("starts_worker_run must be bool")
        if type(self.invalidates_inherited_generation) is not bool:
            raise TypeError("invalidates_inherited_generation must be bool")
        expected_invalidation = self.starts_worker_run and self.worker_run_ordinal > 0
        if self.invalidates_inherited_generation is not expected_invalidation:
            raise ValueError(
                "inherited generation invalidation must mark later worker runs"
            )

        envelope = self.source.envelope
        if envelope.connection_id is None:
            expected_scope = None
        else:
            assert envelope.connection_generation is not None
            expected_scope = ConnectionGenerationScope(
                worker_instance_id=envelope.worker_instance_id,
                connection_id=envelope.connection_id,
                connection_generation=envelope.connection_generation,
            )
        if self.connection_generation_scope != expected_scope:
            raise ValueError(
                "connection_generation_scope must match the source envelope"
            )


@dataclass(frozen=True, slots=True)
class DiscoveredRawInput:
    data_root: Path
    manifest_path: Path
    data_path: Path
    lease_path: Path
    manifest_sha256: str
    manifest: RawManifestV1

    def __post_init__(self) -> None:
        for field_name in ("data_root", "manifest_path", "data_path", "lease_path"):
            value = getattr(self, field_name)
            if not isinstance(value, Path) or not value.is_absolute():
                raise ValueError(f"{field_name} must be an absolute Path")
        if type(self.manifest) is not RawManifestV1:
            raise TypeError("manifest must be RawManifestV1")
        if not _is_sha256(self.manifest_sha256):
            raise ValueError("manifest_sha256 must be a lowercase SHA-256 digest")
        if hashlib.sha256(self.manifest.canonical_bytes()).hexdigest() != (
            self.manifest_sha256
        ):
            raise ValueError("manifest_sha256 does not match canonical manifest bytes")

        expected_manifest = self.data_root / self.manifest.manifest_relative_path
        expected_data = self.data_root / self.manifest.data_relative_path
        if self.manifest_path != expected_manifest:
            raise ValueError("manifest_path does not match the manifest identity")
        if self.data_path != expected_data:
            raise ValueError("data_path does not match the manifest identity")
        if self.lease_path != lease_path_for_data(expected_data):
            raise ValueError("lease_path does not match the data identity")

    @classmethod
    def from_loaded(
        cls,
        *,
        data_root: Path,
        loaded: LoadedRawManifest,
    ) -> DiscoveredRawInput:
        if type(loaded) is not LoadedRawManifest:
            raise TypeError("loaded must be LoadedRawManifest")
        data_path = data_root / loaded.manifest.data_relative_path
        return cls(
            data_root=data_root,
            manifest_path=loaded.path,
            data_path=data_path,
            lease_path=lease_path_for_data(data_path),
            manifest_sha256=loaded.sha256,
            manifest=loaded.manifest,
        )


class DiscoveryIssueCode(StrEnum):
    CLEANUP_PROOF_INVALID = "cleanup_proof_invalid"
    INVALID_MANIFEST = "invalid_manifest"
    UNSUPPORTED_MANIFEST_SCHEMA = "unsupported_manifest_schema"
    SOURCE_BUSY = "source_busy"
    SOURCE_CLEANED = "source_cleaned"
    SOURCE_UNAVAILABLE = "source_unavailable"
    SOURCE_MISMATCH = "source_mismatch"
    FILESYSTEM_ERROR = "filesystem_error"
    SYMLINK_SKIPPED = "symlink_skipped"


@dataclass(frozen=True, slots=True)
class DiscoveryDiagnostic:
    code: DiscoveryIssueCode
    path: Path
    message: str

    def __post_init__(self) -> None:
        if type(self.code) is not DiscoveryIssueCode:
            raise TypeError("code must be DiscoveryIssueCode")
        if not isinstance(self.path, Path) or not self.path.is_absolute():
            raise ValueError("diagnostic path must be an absolute Path")
        if type(self.message) is not str or not self.message:
            raise ValueError("diagnostic message must be non-empty")


@dataclass(frozen=True, slots=True)
class DiscoveryReport:
    inputs: tuple[DiscoveredRawInput, ...]
    diagnostics: tuple[DiscoveryDiagnostic, ...]
    scanned_manifest_count: int

    def __post_init__(self) -> None:
        if any(type(item) is not DiscoveredRawInput for item in self.inputs):
            raise TypeError("inputs must contain DiscoveredRawInput values")
        if any(type(item) is not DiscoveryDiagnostic for item in self.diagnostics):
            raise TypeError("diagnostics must contain DiscoveryDiagnostic values")
        if (
            type(self.scanned_manifest_count) is not int
            or self.scanned_manifest_count < 0
        ):
            raise ValueError("scanned_manifest_count must be a non-negative integer")
        expected_inputs = tuple(
            sorted(
                self.inputs,
                key=lambda item: (
                    item.manifest_sha256,
                    item.manifest_path.as_posix(),
                ),
            )
        )
        if self.inputs != expected_inputs:
            raise ValueError("inputs must be in canonical manifest-SHA order")
        manifest_paths = tuple(item.manifest_path for item in self.inputs)
        if len(manifest_paths) != len(set(manifest_paths)):
            raise ValueError("inputs must have unique manifest paths")
        manifest_sha256s = tuple(item.manifest_sha256 for item in self.inputs)
        if len(manifest_sha256s) != len(set(manifest_sha256s)):
            raise ValueError("inputs must have unique manifest SHA-256 identities")
        expected_diagnostics = tuple(
            sorted(
                self.diagnostics,
                key=lambda item: (item.path.as_posix(), item.code.value, item.message),
            )
        )
        if self.diagnostics != expected_diagnostics:
            raise ValueError("diagnostics must be in canonical path/code order")
        if len(self.inputs) > self.scanned_manifest_count:
            raise ValueError("valid inputs cannot exceed scanned manifests")

    def __iter__(self) -> Iterator[DiscoveredRawInput]:
        return iter(self.inputs)

    def __len__(self) -> int:
        return len(self.inputs)


__all__ = [
    "ConnectionGenerationScope",
    "DiscoveredRawInput",
    "DiscoveryDiagnostic",
    "DiscoveryIssueCode",
    "DiscoveryReport",
    "ReplayOrderedRecord",
    "SourceLocator",
    "SourceRecord",
    "TimedSourceRecord",
]
