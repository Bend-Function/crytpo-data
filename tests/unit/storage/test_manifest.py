from __future__ import annotations

import errno
import hashlib
import os
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

import pytest
import zstandard
from pydantic import ValidationError

import crypto_collector.storage.manifest as manifest_module
from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.json_codec import decode_json
from crypto_collector.domain.types import CloseReason, Exchange, Market, Transport
from crypto_collector.storage.lease import SourceLease, SourceLeaseBusy
from crypto_collector.storage.manifest import (
    RECOVERY_UNAVAILABLE_FIELDS,
    CleanupProofEvidenceV1,
    CleanupProofKind,
    LoadedRawManifest,
    ManifestValidationError,
    RawManifestReader,
    RawManifestV1,
    RecoverySourceState,
    SourceDisposition,
    SourceUnavailable,
    UnsupportedManifestSchema,
    lease_path_for_data,
    load_raw_manifest,
    manifest_path_for_data,
    validate_local_source,
)
from crypto_collector.storage.serialize import encode_envelope


def _ns(value: datetime) -> int:
    return int(value.timestamp()) * 1_000_000_000


FIRST_RECEIVED_NS = _ns(datetime(2026, 7, 31, 0, 0, 1, tzinfo=UTC))
LAST_RECEIVED_NS = FIRST_RECEIVED_NS + 10
DATA_RELATIVE_PATH = (
    "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/part-1785456000000000000-0.jsonl.zst"
)
MANIFEST_RELATIVE_PATH = (
    DATA_RELATIVE_PATH.removesuffix(".jsonl.zst") + ".manifest.json"
)


def normal_manifest_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": 1,
        "exchange": Exchange.OKX,
        "market": Market.SPOT,
        "instrument_key": "BTC-USDT",
        "logical_stream": "trade",
        "wire_symbols": ("BTC-USDT",),
        "data_relative_path": DATA_RELATIVE_PATH,
        "manifest_relative_path": MANIFEST_RELATIVE_PATH,
        "file_size_bytes": 100,
        "file_sha256": "a" * 64,
        "zstd_level": 3,
        "zstd_write_checksum": True,
        "zstd_write_content_size": True,
        "max_plain_frame_bytes": 1_048_576,
        "record_count": 2,
        "first_received_at_ns": FIRST_RECEIVED_NS,
        "last_received_at_ns": LAST_RECEIVED_NS,
        "first_event_time_ns": FIRST_RECEIVED_NS - 2,
        "last_event_time_ns": LAST_RECEIVED_NS - 2,
        "worker_instance_id": "worker-1",
        "connection_generations": (1,),
        "writer_sequence_first": 7,
        "writer_sequence_last": 8,
        "config_sha256": "b" * 64,
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
        "durability_sample_count": 2,
        "durability_lag_p50_ns": 100_000,
        "durability_lag_p95_ns": 250_000,
        "durability_lag_p99_ns": 250_000,
        "durability_lag_max_ns": 200_000,
        "sync_count": 1,
        "sync_duration_total_ns": 50_000,
        "sync_duration_max_ns": 50_000,
        "slo_breach_count": 0,
        "write_failure_count": 0,
        "sync_failure_count": 0,
        "close_reason": CloseReason.SHUTDOWN,
        "created_at_ns": FIRST_RECEIVED_NS - 1,
        "closed_at_ns": LAST_RECEIVED_NS + 1,
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
    values.update(overrides)
    return values


def recovery_manifest_values(**overrides: object) -> dict[str, object]:
    source_path = DATA_RELATIVE_PATH + ".partial"
    values = normal_manifest_values(
        file_size_bytes=100,
        zstd_level=None,
        max_plain_frame_bytes=None,
        gap_count=None,
        reconnect_count=None,
        parse_error_count=None,
        checksum_error_count=None,
        queue_overflow_count=None,
        control_event_ids=None,
        durability_measurement="unavailable_after_crash",
        durability_sample_count=None,
        durability_lag_p50_ns=None,
        durability_lag_p95_ns=None,
        durability_lag_p99_ns=None,
        durability_lag_max_ns=None,
        sync_count=None,
        sync_duration_total_ns=None,
        sync_duration_max_ns=None,
        slo_breach_count=None,
        write_failure_count=None,
        sync_failure_count=None,
        close_reason=CloseReason.RECOVERY,
        created_at_ns=None,
        recovery_transaction_id="123e4567-e89b-42d3-a456-426614174000",
        recovery_source_state=RecoverySourceState.PARTIAL_TRUNCATED,
        recovery_source_relative_path=source_path,
        recovery_source_bytes=120,
        recovery_source_sha256="c" * 64,
        recovery_control_event_id=(
            "raw-recovery-lineage:v1:123e4567-e89b-42d3-a456-426614174000"
        ),
        recovered_frame_count=1,
        recovered_record_count=2,
        recovered_bytes=100,
        recovered_sha256="a" * 64,
        quarantined_suffix_relative_path=(
            "quarantine/okx/123e4567-e89b-42d3-a456-426614174000/suffix.bin"
        ),
        quarantined_suffix_bytes=20,
        quarantined_suffix_sha256="d" * 64,
        unavailable_fields=RECOVERY_UNAVAILABLE_FIELDS,
    )
    values.update(overrides)
    return values


def owned_control_manifest_values(**overrides: object) -> dict[str, object]:
    control_data = "raw/okx/_control/2026/07/31/00/part-1785456000000000000-0.jsonl.zst"
    values = recovery_manifest_values(
        market=None,
        instrument_key=None,
        logical_stream="_control",
        wire_symbols=(),
        data_relative_path=control_data,
        manifest_relative_path=manifest_path_for_data(control_data).as_posix(),
        record_count=1,
        writer_sequence_last=7,
        recovery_source_state=RecoverySourceState.OWNED_CONTROL_CARRIER,
        recovery_source_relative_path=control_data + ".partial",
        recovery_source_bytes=100,
        recovery_source_sha256="a" * 64,
        recovered_frame_count=1,
        recovered_record_count=1,
        quarantined_suffix_relative_path=None,
        quarantined_suffix_bytes=None,
        quarantined_suffix_sha256=None,
    )
    values.update(overrides)
    return values


def test_normal_manifest_canonical_bytes_and_loader_do_not_require_data(
    tmp_path: Path,
) -> None:
    manifest = RawManifestV1.model_validate(normal_manifest_values())
    encoded = manifest.canonical_bytes()
    manifest_path = tmp_path / "part.manifest.json"
    manifest_path.write_bytes(encoded)

    loaded = load_raw_manifest(manifest_path)

    assert isinstance(loaded, LoadedRawManifest)
    assert loaded.path == manifest_path
    assert loaded.manifest == manifest
    assert loaded.canonical_bytes == encoded
    assert loaded.sha256 == hashlib.sha256(encoded).hexdigest()
    assert encoded.endswith(b"\n")
    assert encoded.count(b"\n") == 1
    assert list(decode_json(encoded)) == list(RawManifestV1.model_fields)
    assert not (tmp_path / "part.jsonl.zst").exists()


def test_recovery_control_manifest_uses_normal_measured_schema() -> None:
    manifest = RawManifestV1.model_validate(
        normal_manifest_values(close_reason=CloseReason.RECOVERY_CONTROL)
    )

    assert manifest.close_reason is CloseReason.RECOVERY_CONTROL
    assert manifest.durability_measurement == "measured"
    assert manifest.recovery_transaction_id is None


@pytest.mark.parametrize("schema_version", [2, 0, True, 1.0, "1"])
def test_manifest_schema_version_is_independent_and_strict(
    schema_version: object,
) -> None:
    with pytest.raises(UnsupportedManifestSchema):
        RawManifestV1.model_validate(
            normal_manifest_values(schema_version=schema_version)
        )


@pytest.mark.parametrize(
    "overrides",
    [
        {"record_count": 0},
        {"durability_sample_count": 1},
        {"zstd_level": None},
        {"gap_count": None},
        {"created_at_ns": None},
        {"recovery_transaction_id": "123e4567-e89b-42d3-a456-426614174000"},
        {"unavailable_fields": ("gap_count",)},
        {"durability_lag_p50_ns": 300_000},
    ],
)
def test_normal_manifest_rejects_incomplete_or_inconsistent_facts(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        RawManifestV1.model_validate(normal_manifest_values(**overrides))


def test_manifest_preserves_reverse_wall_event_times_and_sequence_gaps() -> None:
    manifest = RawManifestV1.model_validate(
        normal_manifest_values(
            first_received_at_ns=FIRST_RECEIVED_NS + 10,
            last_received_at_ns=FIRST_RECEIVED_NS + 5,
            first_event_time_ns=FIRST_RECEIVED_NS + 20,
            last_event_time_ns=FIRST_RECEIVED_NS + 1,
            writer_sequence_last=12,
        )
    )

    assert manifest.last_received_at_ns < manifest.first_received_at_ns
    assert manifest.last_event_time_ns is not None
    assert manifest.first_event_time_ns is not None
    assert manifest.last_event_time_ns < manifest.first_event_time_ns
    assert manifest.writer_sequence_last == 12


@pytest.mark.parametrize(
    "field,value",
    [
        ("wire_symbols", ("ETH-USDT", "BTC-USDT")),
        ("connection_generations", (2, 1)),
        ("egress_ids", ("proxy-b", "proxy-a")),
        ("requested_intervals_ns", (2, 1)),
        ("effective_intervals_ns", (2, 1)),
        ("control_event_ids", ("gap:2", "gap:1")),
    ],
)
def test_manifest_tuple_facts_must_be_sorted_and_unique(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValidationError, match="sorted"):
        RawManifestV1.model_validate(normal_manifest_values(**{field: value}))


@pytest.mark.parametrize(
    "overrides",
    [
        {"data_relative_path": DATA_RELATIVE_PATH.replace("raw/okx", "raw/bybit")},
        {"data_relative_path": DATA_RELATIVE_PATH.replace("/00/", "/01/")},
        {"data_relative_path": DATA_RELATIVE_PATH + ".partial"},
        {"manifest_relative_path": MANIFEST_RELATIVE_PATH.replace("part-", "other-")},
        {"logical_stream": "book_live"},
        {"market": Market.PERPETUAL},
    ],
)
def test_manifest_identity_and_hour_must_match_canonical_paths(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError, match="path|layout|hour"):
        RawManifestV1.model_validate(normal_manifest_values(**overrides))


def test_manifest_rejects_noncanonical_part_numbers() -> None:
    data_path = DATA_RELATIVE_PATH.replace(
        "part-1785456000000000000-0", "part-01785456000000000000-00"
    )

    with pytest.raises(ValidationError, match="path|layout"):
        RawManifestV1.model_validate(
            normal_manifest_values(
                data_relative_path=data_path,
                manifest_relative_path=manifest_path_for_data(data_path).as_posix(),
            )
        )


def test_recovery_manifest_requires_exact_reconstructed_and_unavailable_facts() -> None:
    manifest = RawManifestV1.model_validate(recovery_manifest_values())
    assert manifest.close_reason is CloseReason.RECOVERY
    assert manifest.unavailable_fields == RECOVERY_UNAVAILABLE_FIELDS

    for overrides in (
        {"gap_count": 0},
        {"durability_sample_count": 2},
        {"recovered_bytes": 99},
        {"recovered_sha256": "e" * 64},
        {"quarantined_suffix_bytes": 21},
        {"unavailable_fields": RECOVERY_UNAVAILABLE_FIELDS[:-1]},
        {"recovery_transaction_id": "NOT-A-UUID"},
        {"recovery_control_event_id": "recovery:wrong-prefix"},
    ):
        with pytest.raises(ValidationError):
            RawManifestV1.model_validate(recovery_manifest_values(**overrides))


def test_recovery_manifest_cannot_use_recovery_control_close_reason() -> None:
    with pytest.raises(ValidationError):
        RawManifestV1.model_validate(
            recovery_manifest_values(close_reason=CloseReason.RECOVERY_CONTROL)
        )


def test_owned_control_recovery_keeps_created_at_unavailable() -> None:
    manifest = RawManifestV1.model_validate(owned_control_manifest_values())
    assert manifest.created_at_ns is None
    assert manifest.unavailable_fields == RECOVERY_UNAVAILABLE_FIELDS

    with pytest.raises(ValidationError):
        RawManifestV1.model_validate(owned_control_manifest_values(created_at_ns=1))


@pytest.mark.parametrize(
    "overrides",
    [
        {"recovery_source_state": RecoverySourceState.PARTIAL_COMPLETE},
        {
            "recovery_source_state": RecoverySourceState.PARTIAL_TRUNCATED,
            "recovery_source_bytes": 100,
            "recovery_source_sha256": "a" * 64,
            "quarantined_suffix_relative_path": None,
            "quarantined_suffix_bytes": None,
            "quarantined_suffix_sha256": None,
        },
        {
            "recovery_source_state": RecoverySourceState.ORPHAN_CLOSED_DATA,
            "quarantined_suffix_relative_path": None,
            "quarantined_suffix_bytes": None,
            "quarantined_suffix_sha256": None,
        },
        {
            "recovery_source_state": RecoverySourceState.OWNED_CONTROL_CARRIER,
            "recovery_source_bytes": 100,
            "recovery_source_sha256": "a" * 64,
            "quarantined_suffix_relative_path": None,
            "quarantined_suffix_bytes": None,
            "quarantined_suffix_sha256": None,
        },
        {"recovered_frame_count": 3},
    ],
)
def test_recovery_source_states_are_mutually_consistent(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        RawManifestV1.model_validate(recovery_manifest_values(**overrides))


def test_owned_control_recovery_requires_one_control_row_and_frame() -> None:
    manifest = RawManifestV1.model_validate(owned_control_manifest_values())

    assert manifest.recovered_frame_count == manifest.record_count == 1


@pytest.mark.parametrize(
    ("builder", "suffix"),
    [
        (manifest_path_for_data, ".manifest.json"),
        (lease_path_for_data, ".lease"),
    ],
)
def test_sibling_path_builders_replace_the_complete_data_suffix(
    builder: object,
    suffix: str,
) -> None:
    data_path = Path("/data") / DATA_RELATIVE_PATH
    result = builder(data_path)  # type: ignore[operator]
    assert result.parent == data_path.parent
    assert result.name == data_path.name.removesuffix(".jsonl.zst") + suffix


@pytest.mark.parametrize(
    "path",
    [
        Path("part.jsonl.zst.partial"),
        Path("part.zst"),
        Path(".jsonl.zst"),
        Path("part.manifest.json"),
    ],
)
def test_sibling_path_builders_reject_nonfinal_data_names(path: Path) -> None:
    with pytest.raises(ValueError, match="complete .jsonl.zst"):
        manifest_path_for_data(path)
    with pytest.raises(ValueError, match="complete .jsonl.zst"):
        lease_path_for_data(path)


def test_loader_rejects_noncanonical_bytes_and_structural_errors(
    tmp_path: Path,
) -> None:
    manifest = RawManifestV1.model_validate(normal_manifest_values())
    canonical = manifest.canonical_bytes()

    for index, payload in enumerate(
        (
            canonical.removesuffix(b"\n"),
            canonical + b"\n",
            b" " + canonical,
            canonical.replace(b'"record_count":2', b'"record_count":true'),
        )
    ):
        path = tmp_path / f"bad-{index}.manifest.json"
        path.write_bytes(payload)
        with pytest.raises(ManifestValidationError):
            load_raw_manifest(path)


def test_loader_wraps_unrepresentable_utc_timestamp(tmp_path: Path) -> None:
    canonical = RawManifestV1.model_validate(normal_manifest_values()).canonical_bytes()
    payload = canonical.replace(
        str(FIRST_RECEIVED_NS).encode(),
        b"1000000000000000000000000000000",
    )
    path = tmp_path / "overflow.manifest.json"
    path.write_bytes(payload)

    with pytest.raises(ManifestValidationError):
        load_raw_manifest(path)


def _write_readable_part(
    tmp_path: Path,
) -> tuple[Path, Path, RawEnvelope, RawManifestV1]:
    data_root = tmp_path / "data"
    data_path = data_root / DATA_RELATIVE_PATH
    data_path.parent.mkdir(parents=True)
    envelope = RawEnvelope(
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="trade",
        native_channel="trades",
        transport=Transport.WEBSOCKET,
        event_time_ns=None,
        event_time_source=None,
        received_at_ns=FIRST_RECEIVED_NS,
        monotonic_ns=123,
        worker_instance_id="worker-1",
        connection_id="connection-1",
        connection_generation=1,
        writer_sequence=7,
        egress_id="direct-primary",
        config_sha256="b" * 64,
        payload={"price": Decimal("1.250")},
    )
    frame = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    ).compress(encode_envelope(envelope))
    data_path.write_bytes(frame)
    manifest = RawManifestV1.model_validate(
        normal_manifest_values(
            file_size_bytes=len(frame),
            file_sha256=hashlib.sha256(frame).hexdigest(),
            record_count=1,
            first_received_at_ns=FIRST_RECEIVED_NS,
            last_received_at_ns=FIRST_RECEIVED_NS,
            first_event_time_ns=None,
            last_event_time_ns=None,
            writer_sequence_first=7,
            writer_sequence_last=7,
            durability_sample_count=1,
        )
    )
    manifest_path = data_root / MANIFEST_RELATIVE_PATH
    manifest_path.write_bytes(manifest.canonical_bytes())
    return data_root, manifest_path, envelope, manifest


def test_local_source_validation_requires_the_exact_held_lease(
    tmp_path: Path,
) -> None:
    data_root, manifest_path, _envelope, manifest = _write_readable_part(tmp_path)
    loaded = load_raw_manifest(manifest_path)
    expected_lease_path = lease_path_for_data(data_root / manifest.data_relative_path)

    with SourceLease.shared(expected_lease_path) as lease:
        result = validate_local_source(
            loaded,
            data_root=data_root,
            resolver=_MissingResolver(None),
            lease=lease,
        )
    assert result.disposition is SourceDisposition.PRESENT_VERIFIED
    assert result.cleanup_proof is None

    with (
        SourceLease.shared(tmp_path / "different.lease") as wrong_lease,
        pytest.raises(ManifestValidationError, match="lease"),
    ):
        validate_local_source(
            loaded,
            data_root=data_root,
            resolver=_MissingResolver(None),
            lease=wrong_lease,
        )


def test_local_source_validation_rejects_data_hash_mismatch(tmp_path: Path) -> None:
    data_root, manifest_path, _envelope, manifest = _write_readable_part(tmp_path)
    data_path = data_root / manifest.data_relative_path
    data_path.write_bytes(data_path.read_bytes() + b"corrupt")

    with (
        SourceLease.shared(lease_path_for_data(data_path)) as lease,
        pytest.raises(ManifestValidationError, match="size|SHA-256"),
    ):
        validate_local_source(
            load_raw_manifest(manifest_path),
            data_root=data_root,
            resolver=_MissingResolver(None),
            lease=lease,
        )


class _MissingResolver:
    def __init__(self, evidence: CleanupProofEvidenceV1 | None) -> None:
        self.evidence = evidence
        self.calls: list[dict[str, Any]] = []

    def resolve_missing(self, **kwargs: Any) -> CleanupProofEvidenceV1 | None:
        self.calls.append(kwargs)
        return self.evidence


def _cleanup_evidence(
    loaded: LoadedRawManifest,
    *,
    kind: CleanupProofKind = CleanupProofKind.FINAL_TOMBSTONE,
) -> CleanupProofEvidenceV1:
    manifest = loaded.manifest
    return CleanupProofEvidenceV1(
        schema_version=1,
        kind=kind,
        proof_relative_path="cleanup/okx/proof.json",
        proof_size_bytes=10,
        proof_sha256="d" * 64,
        source_manifest_relative_path=manifest.manifest_relative_path,
        source_manifest_sha256=loaded.sha256,
        source_data_relative_path=manifest.data_relative_path,
        source_data_size_bytes=manifest.file_size_bytes,
        source_data_sha256=manifest.file_sha256,
    )


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        (CleanupProofKind.DURABLE_INTENT, SourceDisposition.CLEANUP_INTENT),
        (CleanupProofKind.FINAL_TOMBSTONE, SourceDisposition.CLEANUP_TOMBSTONE),
    ],
)
def test_missing_source_maps_only_exact_cleanup_evidence(
    tmp_path: Path,
    kind: CleanupProofKind,
    expected: SourceDisposition,
) -> None:
    data_root, manifest_path, _envelope, manifest = _write_readable_part(tmp_path)
    (data_root / manifest.data_relative_path).unlink()
    loaded = load_raw_manifest(manifest_path)
    evidence = _cleanup_evidence(loaded, kind=kind)

    with SourceLease.shared(
        lease_path_for_data(data_root / manifest.data_relative_path)
    ) as lease:
        result = validate_local_source(
            loaded,
            data_root=data_root,
            resolver=_MissingResolver(evidence),
            lease=lease,
            expected_cleanup_proof=evidence,
        )

    assert result.disposition is expected
    assert result.cleanup_proof == evidence


def test_missing_source_without_proof_is_unexplained(tmp_path: Path) -> None:
    data_root, manifest_path, _envelope, manifest = _write_readable_part(tmp_path)
    (data_root / manifest.data_relative_path).unlink()
    loaded = load_raw_manifest(manifest_path)

    with SourceLease.shared(
        lease_path_for_data(data_root / manifest.data_relative_path)
    ) as lease:
        result = validate_local_source(
            loaded,
            data_root=data_root,
            resolver=_MissingResolver(None),
            lease=lease,
        )

    assert result.disposition is SourceDisposition.MISSING_UNEXPLAINED
    assert result.cleanup_proof is None


def test_raw_manifest_reader_streams_rows_while_holding_shared_lease(
    tmp_path: Path,
) -> None:
    data_root, manifest_path, envelope, manifest = _write_readable_part(tmp_path)
    lease_path = lease_path_for_data(data_root / manifest.data_relative_path)

    with RawManifestReader(manifest_path) as reader:
        with pytest.raises(SourceLeaseBusy):
            SourceLease.exclusive(lease_path, blocking=False)
        assert list(reader) == [envelope]

    with SourceLease.exclusive(lease_path, blocking=False):
        pass


def _track_data_file_opens(
    monkeypatch: pytest.MonkeyPatch,
    data_path: Path,
) -> list[int]:
    original = manifest_module._open_regular_no_follow
    opened: list[int] = []

    def tracked(path: Path) -> tuple[int, Path]:
        fd, absolute = original(path)
        if absolute == data_path:
            opened.append(fd)
        return fd, absolute

    monkeypatch.setattr(manifest_module, "_open_regular_no_follow", tracked)
    return opened


def _assert_fd_is_closed(fd: int) -> None:
    with pytest.raises(OSError) as captured:
        os.fstat(fd)
    assert captured.value.errno == errno.EBADF


@pytest.mark.parametrize("failure_point", ["hash", "fdopen", "zstd_reader"])
def test_raw_manifest_reader_enter_failure_closes_fd_and_releases_lease(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    data_root, manifest_path, _envelope, manifest = _write_readable_part(tmp_path)
    data_path = data_root / manifest.data_relative_path
    lease_path = lease_path_for_data(data_path)
    opened = _track_data_file_opens(monkeypatch, data_path)
    retained_data_files: list[Any] = []

    if failure_point == "hash":
        original_hash = manifest_module._hash_fd
        hash_calls = 0

        def fail_second_hash(fd: int) -> tuple[int, str]:
            nonlocal hash_calls
            hash_calls += 1
            if hash_calls == 2:
                raise RuntimeError("injected hash failure")
            return original_hash(fd)

        monkeypatch.setattr(manifest_module, "_hash_fd", fail_second_hash)
    elif failure_point == "fdopen":

        def fail_fdopen(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("injected fdopen failure")

        monkeypatch.setattr(manifest_module.os, "fdopen", fail_fdopen)
    else:
        original_fdopen = manifest_module.os.fdopen

        def retain_fdopen(*args: Any, **kwargs: Any) -> Any:
            data_file = original_fdopen(*args, **kwargs)
            retained_data_files.append(data_file)
            return data_file

        class FailingDecompressor:
            def stream_reader(self, *_args: object, **_kwargs: object) -> None:
                raise RuntimeError("injected zstd_reader failure")

        monkeypatch.setattr(
            manifest_module.zstandard,
            "ZstdDecompressor",
            FailingDecompressor,
        )
        monkeypatch.setattr(manifest_module.os, "fdopen", retain_fdopen)

    with pytest.raises(RuntimeError, match="injected"):
        RawManifestReader(manifest_path).__enter__()

    assert len(opened) == 2
    _assert_fd_is_closed(opened[-1])
    assert not retained_data_files or retained_data_files[0].closed
    with SourceLease.exclusive(lease_path, blocking=False):
        pass


def test_raw_manifest_reader_buffer_initialization_failure_closes_zstd_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data_root, manifest_path, _envelope, manifest = _write_readable_part(tmp_path)
    data_path = data_root / manifest.data_relative_path
    lease_path = lease_path_for_data(data_path)
    opened = _track_data_file_opens(monkeypatch, data_path)
    retained_data_files: list[Any] = []
    original_fdopen = manifest_module.os.fdopen

    def retain_fdopen(*args: Any, **kwargs: Any) -> Any:
        data_file = original_fdopen(*args, **kwargs)
        retained_data_files.append(data_file)
        return data_file

    class TrackingZstdReader:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    zstd_reader = TrackingZstdReader()

    class TrackingDecompressor:
        def stream_reader(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> TrackingZstdReader:
            return zstd_reader

    def fail_buffered_reader(_raw: object) -> None:
        raise RuntimeError("injected buffered reader failure")

    monkeypatch.setattr(
        manifest_module.zstandard,
        "ZstdDecompressor",
        TrackingDecompressor,
    )
    monkeypatch.setattr(manifest_module.os, "fdopen", retain_fdopen)
    monkeypatch.setattr(manifest_module.io, "BufferedReader", fail_buffered_reader)

    with pytest.raises(RuntimeError, match="injected"):
        RawManifestReader(manifest_path).__enter__()

    assert zstd_reader.closed
    assert retained_data_files[0].closed
    assert len(opened) == 2
    _assert_fd_is_closed(opened[-1])
    with SourceLease.exclusive(lease_path, blocking=False):
        pass


def test_raw_manifest_reader_reports_missing_data_as_unavailable(
    tmp_path: Path,
) -> None:
    data_root, manifest_path, _envelope, manifest = _write_readable_part(tmp_path)
    (data_root / manifest.data_relative_path).unlink()

    with pytest.raises(SourceUnavailable), RawManifestReader(manifest_path):
        pass


def test_raw_manifest_reader_rejects_manifest_at_wrong_root(tmp_path: Path) -> None:
    _data_root, manifest_path, _envelope, _manifest = _write_readable_part(tmp_path)
    displaced = tmp_path / "displaced.manifest.json"
    displaced.write_bytes(manifest_path.read_bytes())

    with (
        pytest.raises(ManifestValidationError, match="path"),
        RawManifestReader(displaced),
    ):
        pass


def test_source_reader_contract_is_exported_from_storage_package() -> None:
    from crypto_collector import storage

    assert storage.CleanupProofEvidenceV1 is CleanupProofEvidenceV1
    assert storage.RawManifestReader is RawManifestReader
    assert storage.SourceDisposition is SourceDisposition
    assert storage.SourceLease is SourceLease
    assert storage.decode_envelope_jsonl.__name__ == "decode_envelope_jsonl"
    assert storage.validate_local_source is validate_local_source
