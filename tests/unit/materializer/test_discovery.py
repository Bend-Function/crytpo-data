from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import zstandard

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.paths import encode_instrument_key
from crypto_collector.domain.types import CloseReason, Exchange, Market, Transport
from crypto_collector.materializer import (
    DiscoveryIssueCode,
    DiscoveryReport,
    RawManifestReader,
    RawSourceReader,
    discover_raw_inputs,
)
from crypto_collector.storage import RawManifestReader as StorageRawManifestReader
from crypto_collector.storage.lease import SourceLease, SourceLeaseBusy
from crypto_collector.storage.manifest import (
    CleanupProofEvidenceV1,
    CleanupProofKind,
    LoadedRawManifest,
    ManifestValidationError,
    RawManifestV1,
    UnsupportedManifestSchema,
    lease_path_for_data,
    manifest_path_for_data,
)
from crypto_collector.storage.serialize import encode_envelope

RECEIVED_AT_NS = (
    int(datetime(2026, 7, 31, 0, 0, 1, tzinfo=UTC).timestamp()) * 1_000_000_000
)
PROOF_ERROR_CANARY = "credential-canary-must-not-leak"


@dataclass(frozen=True, slots=True)
class RawPart:
    manifest_path: Path
    data_path: Path
    manifest: RawManifestV1
    rows: tuple[RawEnvelope, ...]


def _envelope(
    instrument_key: str,
    *,
    writer_sequence: int,
    received_at_ns: int,
) -> RawEnvelope:
    return RawEnvelope(
        schema_version=1,
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key=instrument_key,
        wire_symbol=instrument_key,
        logical_stream="trade",
        native_channel="trades",
        transport=Transport.WEBSOCKET,
        event_time_ns=received_at_ns - 1,
        event_time_source="venue",
        integrity_mode=None,
        coverage=None,
        rest_metadata=None,
        payload={"trade_id": f"trade-{writer_sequence}"},
        received_at_ns=received_at_ns,
        monotonic_ns=100 + writer_sequence,
        worker_instance_id="worker-1",
        connection_id="connection-1",
        connection_generation=1,
        writer_sequence=writer_sequence,
        egress_id="direct-primary",
        config_sha256="a" * 64,
    )


def _write_part(
    data_root: Path,
    instrument_key: str,
    *,
    part_sequence: int = 0,
    row_count: int = 1,
    concatenate_frames: bool = False,
    encoded_override: bytes | None = None,
    manifest_overrides: dict[str, Any] | None = None,
) -> RawPart:
    rows = tuple(
        _envelope(
            instrument_key,
            writer_sequence=10 + index,
            received_at_ns=RECEIVED_AT_NS + index,
        )
        for index in range(row_count)
    )
    compressor = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    )
    if encoded_override is not None:
        encoded = encoded_override
    elif concatenate_frames:
        encoded = b"".join(compressor.compress(encode_envelope(row)) for row in rows)
    else:
        encoded = compressor.compress(b"".join(encode_envelope(row) for row in rows))

    identity_segment = encode_instrument_key(instrument_key)
    data_relative_path = (
        "raw/okx/spot/"
        f"{identity_segment}/trade/2026/07/31/00/"
        f"part-{RECEIVED_AT_NS}-{part_sequence}.jsonl.zst"
    )
    manifest_relative_path = manifest_path_for_data(data_relative_path).as_posix()
    values: dict[str, Any] = {
        "schema_version": 1,
        "exchange": Exchange.OKX,
        "market": Market.SPOT,
        "instrument_key": instrument_key,
        "logical_stream": "trade",
        "wire_symbols": (instrument_key,),
        "data_relative_path": data_relative_path,
        "manifest_relative_path": manifest_relative_path,
        "file_size_bytes": len(encoded),
        "file_sha256": hashlib.sha256(encoded).hexdigest(),
        "zstd_level": 3,
        "zstd_write_checksum": True,
        "zstd_write_content_size": True,
        "max_plain_frame_bytes": 1_048_576,
        "record_count": len(rows),
        "first_received_at_ns": rows[0].received_at_ns,
        "last_received_at_ns": rows[-1].received_at_ns,
        "first_event_time_ns": rows[0].event_time_ns,
        "last_event_time_ns": rows[-1].event_time_ns,
        "worker_instance_id": "worker-1",
        "connection_generations": (1,),
        "writer_sequence_first": rows[0].writer_sequence,
        "writer_sequence_last": rows[-1].writer_sequence,
        "config_sha256": "a" * 64,
        "egress_ids": ("direct-primary",),
        "requested_intervals_ns": (),
        "effective_intervals_ns": (),
        "gap_count": 0,
        "reconnect_count": 0,
        "parse_error_count": 0,
        "checksum_error_count": 0,
        "queue_overflow_count": 0,
        "control_event_ids": (),
        "durability_measurement": "measured",
        "durability_sample_count": len(rows),
        "durability_lag_p50_ns": 1,
        "durability_lag_p95_ns": 1,
        "durability_lag_p99_ns": 1,
        "durability_lag_max_ns": 1,
        "sync_count": 1,
        "sync_duration_total_ns": 1,
        "sync_duration_max_ns": 1,
        "slo_breach_count": 0,
        "write_failure_count": 0,
        "sync_failure_count": 0,
        "close_reason": CloseReason.SHUTDOWN,
        "created_at_ns": RECEIVED_AT_NS - 10,
        "closed_at_ns": RECEIVED_AT_NS + 10,
        "recovery_transaction_id": None,
        "recovery_source_state": None,
        "recovery_source_relative_path": None,
        "recovery_source_bytes": None,
        "recovery_source_sha256": None,
        "recovery_control_event_id": None,
        "recovered_frame_count": None,
        "recovered_record_count": None,
        "recovered_bytes": None,
        "recovered_sha256": None,
        "quarantined_suffix_relative_path": None,
        "quarantined_suffix_bytes": None,
        "quarantined_suffix_sha256": None,
        "unavailable_fields": (),
    }
    if manifest_overrides is not None:
        values.update(manifest_overrides)
    manifest = RawManifestV1.model_validate(values)
    data_path = data_root / data_relative_path
    manifest_path = data_root / manifest_relative_path
    data_path.parent.mkdir(parents=True, exist_ok=True)
    data_path.write_bytes(encoded)
    manifest_path.write_bytes(manifest.canonical_bytes())
    return RawPart(
        manifest_path=manifest_path,
        data_path=data_path,
        manifest=manifest,
        rows=rows,
    )


def test_discovery_returns_only_verified_closed_inputs_with_diagnostics(
    tmp_path: Path,
) -> None:
    first = _write_part(tmp_path, "BTC-USDT", part_sequence=5)
    second = _write_part(tmp_path, "ETH-USDT", part_sequence=1)
    corrupt = _write_part(tmp_path, "SOL-USDT", part_sequence=2)
    corrupt.data_path.write_bytes(corrupt.data_path.read_bytes() + b"corrupt")

    invalid = tmp_path / "raw/invalid.manifest.json"
    invalid.parent.mkdir(parents=True, exist_ok=True)
    invalid.write_bytes(b"{}\n")
    unsupported = tmp_path / "raw/unsupported.manifest.json"
    unsupported.write_bytes(b'{"schema_version":2}\n')
    (tmp_path / "raw/unclosed.jsonl.zst.partial").write_bytes(b"partial")
    (tmp_path / "raw/orphan.jsonl.zst").write_bytes(b"closed-without-manifest")

    report = discover_raw_inputs(tmp_path)

    assert report.scanned_manifest_count == 5
    assert {item.manifest_path for item in report} == {
        first.manifest_path,
        second.manifest_path,
    }
    assert [item.manifest_sha256 for item in report] == sorted(
        item.manifest_sha256 for item in report
    )
    assert {item.code for item in report.diagnostics} == {
        DiscoveryIssueCode.INVALID_MANIFEST,
        DiscoveryIssueCode.UNSUPPORTED_MANIFEST_SCHEMA,
        DiscoveryIssueCode.SOURCE_MISMATCH,
    }


def test_missing_source_is_fail_closed_and_not_silently_empty(tmp_path: Path) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    source.data_path.unlink()

    report = discover_raw_inputs(tmp_path)

    assert not report.inputs
    assert report.scanned_manifest_count == 1
    assert [(item.code, item.path) for item in report.diagnostics] == [
        (DiscoveryIssueCode.SOURCE_UNAVAILABLE, source.manifest_path)
    ]


class _TombstoneResolver:
    def resolve_missing(
        self,
        *,
        loaded: LoadedRawManifest,
        data_path: Path,
        expected_data_sha256: str,
        expected_proof: CleanupProofEvidenceV1 | None = None,
    ) -> CleanupProofEvidenceV1:
        assert data_path.name.endswith(".jsonl.zst")
        assert expected_data_sha256 == loaded.manifest.file_sha256
        assert expected_proof is None
        manifest = loaded.manifest
        return CleanupProofEvidenceV1(
            schema_version=1,
            kind=CleanupProofKind.FINAL_TOMBSTONE,
            proof_relative_path="archive/tombstones/source.json",
            proof_size_bytes=10,
            proof_sha256="f" * 64,
            source_manifest_relative_path=manifest.manifest_relative_path,
            source_manifest_sha256=loaded.sha256,
            source_data_relative_path=manifest.data_relative_path,
            source_data_size_bytes=manifest.file_size_bytes,
            source_data_sha256=manifest.file_sha256,
        )


class _InvalidProofResolver:
    def resolve_missing(self, **_kwargs: object) -> None:
        raise ValueError(PROOF_ERROR_CANARY)


class _ManifestProgrammingErrorResolver:
    def resolve_missing(self, **_kwargs: object) -> None:
        raise ManifestValidationError(PROOF_ERROR_CANARY)


class _UnsupportedSchemaProgrammingErrorResolver:
    def resolve_missing(self, **_kwargs: object) -> None:
        raise UnsupportedManifestSchema(PROOF_ERROR_CANARY)


class _LeaseBusyProgrammingErrorResolver:
    def resolve_missing(self, **_kwargs: object) -> None:
        raise SourceLeaseBusy(Path("/resolver-owned.lease"))


class _MismatchedProofResolver(_TombstoneResolver):
    def resolve_missing(
        self,
        *,
        loaded: LoadedRawManifest,
        data_path: Path,
        expected_data_sha256: str,
        expected_proof: CleanupProofEvidenceV1 | None = None,
    ) -> CleanupProofEvidenceV1:
        evidence = super().resolve_missing(
            loaded=loaded,
            data_path=data_path,
            expected_data_sha256=expected_data_sha256,
            expected_proof=expected_proof,
        )
        return evidence.model_copy(update={"source_data_sha256": "0" * 64})


class _ProgrammingErrorResolver:
    def resolve_missing(self, **_kwargs: object) -> None:
        raise TypeError("injected resolver programming error")


def test_validated_cleanup_disposition_is_diagnosed_and_not_discovered(
    tmp_path: Path,
) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    source.data_path.unlink()

    report = discover_raw_inputs(
        tmp_path,
        source_disposition_resolver=_TombstoneResolver(),
    )

    assert not report.inputs
    assert [(item.code, item.path) for item in report.diagnostics] == [
        (DiscoveryIssueCode.SOURCE_CLEANED, source.manifest_path)
    ]


def test_cleanup_resolver_value_error_is_not_swallowed(tmp_path: Path) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    source.data_path.unlink()

    with pytest.raises(ValueError, match=PROOF_ERROR_CANARY):
        discover_raw_inputs(
            tmp_path,
            source_disposition_resolver=_InvalidProofResolver(),
        )


def test_cleanup_resolver_manifest_error_is_not_misclassified(tmp_path: Path) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    source.data_path.unlink()

    with pytest.raises(ManifestValidationError, match=PROOF_ERROR_CANARY):
        discover_raw_inputs(
            tmp_path,
            source_disposition_resolver=_ManifestProgrammingErrorResolver(),
        )


def test_cleanup_resolver_schema_error_is_not_misclassified(tmp_path: Path) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    source.data_path.unlink()

    with pytest.raises(UnsupportedManifestSchema, match=PROOF_ERROR_CANARY):
        discover_raw_inputs(
            tmp_path,
            source_disposition_resolver=(_UnsupportedSchemaProgrammingErrorResolver()),
        )


def test_cleanup_resolver_lease_error_is_not_misclassified(tmp_path: Path) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    source.data_path.unlink()

    with pytest.raises(SourceLeaseBusy) as raised:
        discover_raw_inputs(
            tmp_path,
            source_disposition_resolver=_LeaseBusyProgrammingErrorResolver(),
        )

    assert raised.value.lease_path == Path("/resolver-owned.lease")


def test_mismatched_cleanup_proof_is_not_misclassified_as_data_corruption(
    tmp_path: Path,
) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    source.data_path.unlink()

    report = discover_raw_inputs(
        tmp_path,
        source_disposition_resolver=_MismatchedProofResolver(),
    )

    assert [item.code for item in report.diagnostics] == [
        DiscoveryIssueCode.CLEANUP_PROOF_INVALID
    ]
    assert report.diagnostics[0].message == (
        "cleanup proof validation failed: ManifestValidationError"
    )


def test_cleanup_resolver_programming_error_is_not_swallowed(tmp_path: Path) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    source.data_path.unlink()

    with pytest.raises(TypeError, match="resolver programming error"):
        discover_raw_inputs(
            tmp_path,
            source_disposition_resolver=_ProgrammingErrorResolver(),
        )


def test_exclusive_source_lease_yields_busy_diagnostic_without_blocking(
    tmp_path: Path,
) -> None:
    source = _write_part(tmp_path, "BTC-USDT")
    lease_path = lease_path_for_data(source.data_path)

    with SourceLease.exclusive(lease_path):
        report = discover_raw_inputs(tmp_path)

    assert not report.inputs
    assert [item.code for item in report.diagnostics] == [
        DiscoveryIssueCode.SOURCE_BUSY
    ]


def test_discovery_report_rejects_duplicate_manifest_paths(tmp_path: Path) -> None:
    _write_part(tmp_path, "BTC-USDT")
    source = discover_raw_inputs(tmp_path).inputs[0]

    with pytest.raises(ValueError, match="unique manifest paths"):
        DiscoveryReport(
            inputs=(source, source),
            diagnostics=(),
            scanned_manifest_count=2,
        )


def test_discovery_report_rejects_duplicate_manifest_sha256_identities(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    _write_part(first_root, "BTC-USDT")
    _write_part(second_root, "BTC-USDT")
    first = discover_raw_inputs(first_root).inputs[0]
    second = discover_raw_inputs(second_root).inputs[0]
    assert first.manifest_path != second.manifest_path
    assert first.manifest_sha256 == second.manifest_sha256

    with pytest.raises(ValueError, match="unique manifest SHA-256"):
        DiscoveryReport(
            inputs=tuple(sorted((first, second), key=lambda item: item.manifest_path)),
            diagnostics=(),
            scanned_manifest_count=2,
        )


def test_reader_reuses_storage_contract_and_assigns_physical_source_locators(
    tmp_path: Path,
) -> None:
    part = _write_part(
        tmp_path,
        "BTC-USDT",
        row_count=2,
        concatenate_frames=True,
    )
    source = discover_raw_inputs(tmp_path).inputs[0]

    assert RawManifestReader is StorageRawManifestReader
    with RawSourceReader(source) as reader:
        with pytest.raises(SourceLeaseBusy):
            SourceLease.exclusive(source.lease_path, blocking=False)
        records = list(reader)
        assert reader.validated_complete
        assert reader.records_read == 2

    assert [record.envelope for record in records] == list(part.rows)
    assert [record.locator.manifest_sha256 for record in records] == [
        source.manifest_sha256,
        source.manifest_sha256,
    ]
    assert [record.locator.zero_based_record_index for record in records] == [0, 1]
    with SourceLease.exclusive(source.lease_path, blocking=False):
        pass


def test_reader_revalidates_manifest_identity_after_discovery(tmp_path: Path) -> None:
    part = _write_part(tmp_path, "BTC-USDT")
    source = discover_raw_inputs(tmp_path).inputs[0]
    replacement = RawManifestV1.model_validate(
        {
            **part.manifest.model_dump(mode="python"),
            "closed_at_ns": part.manifest.closed_at_ns + 1,
        }
    )
    replacement_path = part.manifest_path.with_name("replacement.manifest.json")
    replacement_path.write_bytes(replacement.canonical_bytes())
    os.replace(replacement_path, part.manifest_path)
    reader = RawSourceReader(source)

    with (
        pytest.raises(ManifestValidationError, match="expected source identity"),
        reader,
    ):
        pass
    assert reader.records_read == 0
    assert not reader.validated_complete
    with SourceLease.exclusive(source.lease_path, blocking=False):
        pass


def test_discovery_does_not_traverse_symlinked_raw_subtrees(tmp_path: Path) -> None:
    external_root = tmp_path / "external"
    external = _write_part(external_root, "BTC-USDT")
    data_root = tmp_path / "data"
    raw_root = data_root / "raw"
    raw_root.mkdir(parents=True)
    linked = raw_root / "linked"
    linked.symlink_to(external.manifest_path.parent, target_is_directory=True)

    report = discover_raw_inputs(data_root)

    assert not report.inputs
    assert [(item.code, item.path) for item in report.diagnostics] == [
        (DiscoveryIssueCode.SYMLINK_SKIPPED, linked)
    ]


def test_reader_rejects_invalid_raw_envelope_even_when_data_sha_matches(
    tmp_path: Path,
) -> None:
    compressor = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    )
    part = _write_part(
        tmp_path,
        "BTC-USDT",
        encoded_override=compressor.compress(b"{}\n"),
    )
    report = discover_raw_inputs(tmp_path)
    assert len(report.inputs) == 1

    with (
        pytest.raises(ManifestValidationError, match="rows are invalid"),
        RawSourceReader(report.inputs[0]) as reader,
    ):
        list(reader)

    with SourceLease.exclusive(lease_path_for_data(part.data_path), blocking=False):
        pass


def test_empty_existing_root_is_distinct_from_invalid_sources(tmp_path: Path) -> None:
    report = discover_raw_inputs(tmp_path)

    assert report.scanned_manifest_count == 0
    assert report.inputs == ()
    assert report.diagnostics == ()


def test_missing_data_root_raises_instead_of_reporting_an_empty_scan(
    tmp_path: Path,
) -> None:
    with pytest.raises(FileNotFoundError):
        discover_raw_inputs(tmp_path / "missing")


def test_data_root_rejects_a_symlinked_ancestor_component(tmp_path: Path) -> None:
    real_parent = tmp_path / "real-parent"
    data_root = real_parent / "data"
    data_root.mkdir(parents=True)
    alias = tmp_path / "alias-parent"
    alias.symlink_to(real_parent, target_is_directory=True)

    with pytest.raises(ValueError, match="symlink component"):
        discover_raw_inputs(alias / "data")
