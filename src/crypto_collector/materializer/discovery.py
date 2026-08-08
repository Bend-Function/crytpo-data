from __future__ import annotations

import os
import stat
from pathlib import Path

from crypto_collector.materializer.models import (
    DiscoveredRawInput,
    DiscoveryDiagnostic,
    DiscoveryIssueCode,
    DiscoveryReport,
)
from crypto_collector.storage.lease import SourceLease, SourceLeaseBusy
from crypto_collector.storage.manifest import (
    CleanupProofEvidenceV1,
    LoadedRawManifest,
    LocalSourceValidation,
    ManifestValidationError,
    SourceDisposition,
    SourceDispositionResolver,
    UnsupportedManifestSchema,
    lease_path_for_data,
    load_raw_manifest,
    validate_local_source,
)


class _NoCleanupProofResolver:
    def resolve_missing(
        self,
        *,
        loaded: LoadedRawManifest,
        data_path: Path,
        expected_data_sha256: str,
        expected_proof: CleanupProofEvidenceV1 | None = None,
    ) -> None:
        return None


class _TrackingSourceDispositionResolver:
    def __init__(self, delegate: SourceDispositionResolver) -> None:
        self.delegate = delegate
        self.entered = False
        self.returned = False

    def resolve_missing(
        self,
        *,
        loaded: LoadedRawManifest,
        data_path: Path,
        expected_data_sha256: str,
        expected_proof: CleanupProofEvidenceV1 | None = None,
    ) -> CleanupProofEvidenceV1 | None:
        self.entered = True
        result = self.delegate.resolve_missing(
            loaded=loaded,
            data_path=data_path,
            expected_data_sha256=expected_data_sha256,
            expected_proof=expected_proof,
        )
        self.returned = True
        return result


def _absolute_data_root(data_root: Path) -> Path:
    if not isinstance(data_root, Path):
        raise TypeError("data_root must be Path")
    absolute = Path(os.path.abspath(os.fspath(data_root)))
    current = Path(absolute.anchor)
    observed = os.lstat(current)
    for segment in absolute.parts[1:]:
        current /= segment
        observed = os.lstat(current)
        if stat.S_ISLNK(observed.st_mode):
            raise ValueError("data_root path must not contain a symlink component")
    if not stat.S_ISDIR(observed.st_mode):
        raise NotADirectoryError(absolute)
    return absolute


def _diagnostic(
    code: DiscoveryIssueCode,
    path: Path,
    message: str,
) -> DiscoveryDiagnostic:
    return DiscoveryDiagnostic(code=code, path=path, message=message)


def _manifest_candidates(
    data_root: Path,
) -> tuple[tuple[Path, ...], tuple[DiscoveryDiagnostic, ...]]:
    raw_root = data_root / "raw"
    try:
        observed = os.lstat(raw_root)
    except FileNotFoundError:
        return (), ()
    if stat.S_ISLNK(observed.st_mode):
        return (
            (),
            (
                _diagnostic(
                    DiscoveryIssueCode.SYMLINK_SKIPPED,
                    raw_root,
                    "raw discovery root is a symlink",
                ),
            ),
        )
    if not stat.S_ISDIR(observed.st_mode):
        return (
            (),
            (
                _diagnostic(
                    DiscoveryIssueCode.FILESYSTEM_ERROR,
                    raw_root,
                    "raw discovery root is not a directory",
                ),
            ),
        )

    candidates: list[Path] = []
    diagnostics: list[DiscoveryDiagnostic] = []

    def on_error(error: OSError) -> None:
        failed_path = Path(error.filename) if error.filename else raw_root
        diagnostics.append(
            _diagnostic(
                DiscoveryIssueCode.FILESYSTEM_ERROR,
                Path(os.path.abspath(os.fspath(failed_path))),
                f"cannot scan raw discovery path: {type(error).__name__}",
            )
        )

    for current, directories, files in os.walk(
        raw_root,
        topdown=True,
        onerror=on_error,
        followlinks=False,
    ):
        current_path = Path(current)
        directories.sort()
        retained_directories: list[str] = []
        for name in directories:
            candidate = current_path / name
            try:
                child = os.lstat(candidate)
            except OSError as error:
                diagnostics.append(
                    _diagnostic(
                        DiscoveryIssueCode.FILESYSTEM_ERROR,
                        candidate,
                        f"cannot inspect discovery directory: {type(error).__name__}",
                    )
                )
                continue
            if stat.S_ISLNK(child.st_mode):
                diagnostics.append(
                    _diagnostic(
                        DiscoveryIssueCode.SYMLINK_SKIPPED,
                        candidate,
                        "symlinked discovery directory was not traversed",
                    )
                )
                continue
            retained_directories.append(name)
        directories[:] = retained_directories
        candidates.extend(
            current_path / name
            for name in sorted(files)
            if name.endswith(".manifest.json")
        )
    return tuple(candidates), tuple(diagnostics)


def _validate_candidate(
    manifest_path: Path,
    *,
    data_root: Path,
    resolver: SourceDispositionResolver,
) -> tuple[DiscoveredRawInput | None, DiscoveryDiagnostic | None]:
    stage = "manifest"
    tracking_resolver: _TrackingSourceDispositionResolver | None = None
    try:
        loaded = load_raw_manifest(manifest_path)
        stage = "source"
        data_path = data_root / loaded.manifest.data_relative_path
        tracking_resolver = _TrackingSourceDispositionResolver(resolver)
        with SourceLease.shared(
            lease_path_for_data(data_path),
            blocking=False,
        ) as lease:
            validation: LocalSourceValidation = validate_local_source(
                loaded,
                data_root=data_root,
                resolver=tracking_resolver,
                lease=lease,
            )
        if validation.disposition is not SourceDisposition.PRESENT_VERIFIED:
            if validation.disposition in {
                SourceDisposition.CLEANUP_INTENT,
                SourceDisposition.CLEANUP_TOMBSTONE,
            }:
                return None, _diagnostic(
                    DiscoveryIssueCode.SOURCE_CLEANED,
                    manifest_path,
                    "raw source has a validated cleanup disposition: "
                    + validation.disposition.value,
                )
            return None, _diagnostic(
                DiscoveryIssueCode.SOURCE_UNAVAILABLE,
                manifest_path,
                "raw source is missing without a validated cleanup proof",
            )
        return (
            DiscoveredRawInput.from_loaded(data_root=data_root, loaded=loaded),
            None,
        )
    except UnsupportedManifestSchema:
        if stage != "manifest":
            raise
        return None, _diagnostic(
            DiscoveryIssueCode.UNSUPPORTED_MANIFEST_SCHEMA,
            manifest_path,
            "raw manifest schema is unsupported",
        )
    except SourceLeaseBusy:
        if tracking_resolver is not None and tracking_resolver.entered:
            raise
        return None, _diagnostic(
            DiscoveryIssueCode.SOURCE_BUSY,
            manifest_path,
            "raw source lease is held exclusively",
        )
    except ManifestValidationError as error:
        if (
            tracking_resolver is not None
            and tracking_resolver.entered
            and not tracking_resolver.returned
        ):
            raise
        if tracking_resolver is not None and tracking_resolver.returned:
            return None, _diagnostic(
                DiscoveryIssueCode.CLEANUP_PROOF_INVALID,
                manifest_path,
                f"cleanup proof validation failed: {type(error).__name__}",
            )
        code = (
            DiscoveryIssueCode.INVALID_MANIFEST
            if stage == "manifest"
            else DiscoveryIssueCode.SOURCE_MISMATCH
        )
        return None, _diagnostic(code, manifest_path, str(error))
    except ValueError as error:
        if tracking_resolver is not None and tracking_resolver.returned:
            return None, _diagnostic(
                DiscoveryIssueCode.CLEANUP_PROOF_INVALID,
                manifest_path,
                f"cleanup proof validation failed: {type(error).__name__}",
            )
        raise
    except OSError as error:
        return None, _diagnostic(
            DiscoveryIssueCode.FILESYSTEM_ERROR,
            manifest_path,
            f"raw {stage} filesystem validation failed: {type(error).__name__}",
        )


def discover_raw_inputs(
    data_root: Path,
    *,
    source_disposition_resolver: SourceDispositionResolver | None = None,
) -> DiscoveryReport:
    root = _absolute_data_root(data_root)
    resolver = (
        _NoCleanupProofResolver()
        if source_disposition_resolver is None
        else source_disposition_resolver
    )
    candidates, scan_diagnostics = _manifest_candidates(root)
    inputs: list[DiscoveredRawInput] = []
    diagnostics = list(scan_diagnostics)
    for manifest_path in candidates:
        source, diagnostic = _validate_candidate(
            manifest_path,
            data_root=root,
            resolver=resolver,
        )
        if source is not None:
            inputs.append(source)
        if diagnostic is not None:
            diagnostics.append(diagnostic)

    return DiscoveryReport(
        inputs=tuple(
            sorted(
                inputs,
                key=lambda item: (
                    item.manifest_sha256,
                    item.manifest_path.as_posix(),
                ),
            )
        ),
        diagnostics=tuple(
            sorted(
                diagnostics,
                key=lambda item: (item.path.as_posix(), item.code.value, item.message),
            )
        ),
        scanned_manifest_count=len(candidates),
    )


__all__ = ["discover_raw_inputs"]
