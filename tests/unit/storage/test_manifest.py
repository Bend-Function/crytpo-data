from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from crypto_collector.domain.json_codec import decode_json
from crypto_collector.domain.types import CloseReason, Exchange, Market
from crypto_collector.storage.manifest import (
    RECOVERY_UNAVAILABLE_FIELDS,
    LoadedRawManifest,
    ManifestValidationError,
    RawManifestV1,
    RecoverySourceState,
    UnsupportedManifestSchema,
    lease_path_for_data,
    load_raw_manifest,
    manifest_path_for_data,
)


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
