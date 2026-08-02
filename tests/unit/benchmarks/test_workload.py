from __future__ import annotations

from copy import deepcopy
from dataclasses import FrozenInstanceError
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from crypto_collector.benchmarks.workload import (
    RESEARCH_DEFAULT_V1_SHA256,
    GateWorkloadV1,
    load_workload,
)

WORKLOAD = Path("benchmarks/workloads/research-default-v1.yaml")


def _workload_data() -> dict[str, Any]:
    return cast(
        dict[str, Any],
        deepcopy(load_workload(WORKLOAD).workload.model_dump(mode="json")),
    )


def _stream(data: dict[str, Any], name: str) -> dict[str, Any]:
    return cast(dict[str, Any], data["streams"][name])


def _write_bytes(path: Path, source: bytes) -> Path:
    path.write_bytes(source)
    return path


def test_research_default_v1_freezes_scope_algorithms_and_source_bytes() -> None:
    loaded = load_workload(WORKLOAD)
    source_bytes = WORKLOAD.read_bytes()

    assert loaded.source_bytes == source_bytes
    assert loaded.sha256 == sha256(source_bytes).hexdigest()
    assert loaded.sha256 == RESEARCH_DEFAULT_V1_SHA256
    assert loaded.workload.exchanges == (
        "binance",
        "okx",
        "bybit",
        "bitget",
        "kraken",
    )
    assert loaded.workload.markets == ("spot", "perpetual")
    assert loaded.workload.derivative_logical_streams == (
        "funding",
        "open_interest",
    )
    assert loaded.workload.identity_algorithm == "gate-identity-v1"
    assert loaded.workload.payload_algorithm == "gate-payload-v1"
    assert (
        loaded.workload.schedule_algorithm
        == "gate-schedule-v2-full-second-burst"
    )
    assert loaded.workload.streams["trade"].mean_records_per_second == Decimal(50)
    assert loaded.workload.fixed_scope_file_count == 5
    assert loaded.workload.scalable_file_count == 1_750
    assert loaded.workload.active_file_count == 1_755


def test_loaded_workload_and_models_are_frozen_and_loaded_workload_uses_slots() -> None:
    loaded = load_workload(WORKLOAD)

    with pytest.raises(FrozenInstanceError):
        loaded.sha256 = "0" * 64
    with pytest.raises(ValidationError):
        loaded.workload.generation_seed = 1
    assert not hasattr(loaded, "__dict__")


@pytest.mark.parametrize("value", [1.0, True, "1.0", {"unexpected": 1}])
def test_workload_rejects_noncanonical_schema_version(value: object) -> None:
    data = _workload_data()
    data["schema_version"] = value

    with pytest.raises((TypeError, ValidationError, ValueError)):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("exchanges", ["binance", "binance"]),
        ("markets", ["spot", "spot"]),
        ("derivative_logical_streams", ["funding", "funding"]),
    ],
)
def test_workload_rejects_duplicate_scope_names(
    field: str,
    value: list[str],
) -> None:
    data = _workload_data()
    data[field] = value

    with pytest.raises(ValidationError, match="unique"):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize("value", [1, 1.0, True, Decimal(1)])
def test_workload_rejects_non_string_rates(value: object) -> None:
    data = _workload_data()
    _stream(data, "trade")["mean_records_per_second"] = value

    with pytest.raises(ValidationError, match="decimal string"):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize(
    "value",
    ["NaN", "Infinity", "-1", "0", "+1", "01", ".5", "1.", "1e1", " 1"],
)
def test_workload_rejects_noncanonical_or_nonpositive_rates(value: str) -> None:
    data = _workload_data()
    _stream(data, "trade")["mean_records_per_second"] = value

    with pytest.raises(ValidationError, match="decimal string"):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize("value", [1, 1.0, True, Decimal("0.5")])
def test_workload_rejects_non_string_payload_fractions(value: object) -> None:
    data = _workload_data()
    data["payload_generation"]["decimal_string_fraction"] = value

    with pytest.raises(ValidationError, match="decimal string"):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize(
    "value",
    [
        "NaN",
        "Infinity",
        "-0.1",
        "0",
        "1.1",
        "+0.5",
        "00.5",
        ".5",
        "0.5e0",
        " 0.5",
    ],
)
def test_workload_rejects_invalid_payload_fractions(value: str) -> None:
    data = _workload_data()
    data["payload_generation"]["incompressible_fraction"] = value

    with pytest.raises(ValidationError, match="decimal string"):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize(
    ("stream", "transport"),
    [
        ("trade", "udp"),
        ("trade", "rest"),
        ("book_deep_snapshot", "websocket"),
        ("_control", "rest"),
    ],
)
def test_workload_rejects_unknown_or_mismatched_transports(
    stream: str,
    transport: str,
) -> None:
    data = _workload_data()
    data["stream_transports"][stream] = transport

    with pytest.raises(ValidationError, match="transport"):
        GateWorkloadV1.model_validate(data)


def test_workload_rejects_missing_or_extra_transport_keys() -> None:
    missing = _workload_data()
    del missing["stream_transports"]["ticker"]
    with pytest.raises(ValidationError, match="transport"):
        GateWorkloadV1.model_validate(missing)

    extra = _workload_data()
    extra["stream_transports"]["unknown"] = "websocket"
    with pytest.raises(ValidationError, match="transport"):
        GateWorkloadV1.model_validate(extra)


def test_workload_rejects_derivative_file_product_mismatch() -> None:
    data = _workload_data()
    _stream(data, "derivative")["logical_streams_per_instrument"] = 3

    with pytest.raises(ValidationError, match="derivative"):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("fixed_scope_file_count", 4),
        ("scalable_file_count", 1_749),
        ("active_file_count", 1_754),
    ],
)
def test_workload_rejects_declared_cardinality_mismatch(
    field: str,
    value: int,
) -> None:
    data = _workload_data()
    data[field] = value

    with pytest.raises(ValidationError, match="file count"):
        GateWorkloadV1.model_validate(data)


def test_workload_rejects_stream_scope_cardinality_mismatch() -> None:
    data = _workload_data()
    _stream(data, "trade")["instances"] = 249
    data["scalable_file_count"] = 1_749
    data["active_file_count"] = 1_754

    with pytest.raises(ValidationError, match="trade instances"):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("generation_seed",), True),
        (("symbols_per_market",), True),
        (("streams", "trade", "instances"), True),
        (("queues", "shard_max_records"), True),
        (("qualification", "warmup_seconds"), True),
    ],
)
def test_workload_rejects_booleans_as_integers(
    path: tuple[str, ...],
    value: object,
) -> None:
    data = _workload_data()
    target: dict[str, Any] = data
    for component in path[:-1]:
        target = cast(dict[str, Any], target[component])
    target[path[-1]] = value

    with pytest.raises(ValidationError):
        GateWorkloadV1.model_validate(data)


@pytest.mark.parametrize(
    "path",
    [
        (),
        ("streams", "trade"),
        ("payload_generation",),
        ("queues",),
        ("qualification",),
    ],
)
def test_workload_rejects_extra_fields(path: tuple[str, ...]) -> None:
    data = _workload_data()
    target: dict[str, Any] = data
    for component in path:
        target = cast(dict[str, Any], target[component])
    target["unexpected"] = 1

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        GateWorkloadV1.model_validate(data)


def test_load_workload_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    path = _write_bytes(
        tmp_path / "duplicate.yaml",
        b"schema_version: 1\nschema_version: 1\n",
    )

    with pytest.raises(ValueError, match="duplicate YAML mapping key"):
        load_workload(path)


def test_load_workload_rejects_multiple_yaml_documents(tmp_path: Path) -> None:
    path = _write_bytes(
        tmp_path / "multiple.yaml",
        b"schema_version: 1\n---\nschema_version: 1\n",
    )

    with pytest.raises(ValueError, match="single document"):
        load_workload(path)


@pytest.mark.parametrize("source", [b"- one\n- two\n", b"null\n"])
def test_load_workload_rejects_non_mapping_roots(
    tmp_path: Path,
    source: bytes,
) -> None:
    path = _write_bytes(tmp_path / "non-mapping.yaml", source)

    with pytest.raises(ValueError, match="root must be a mapping"):
        load_workload(path)


def test_load_workload_rejects_invalid_utf8(tmp_path: Path) -> None:
    path = _write_bytes(tmp_path / "invalid.yaml", b"schema_version: \xff\n")

    with pytest.raises(ValueError, match="UTF-8"):
        load_workload(path)


def test_load_workload_rejects_symlinks(tmp_path: Path) -> None:
    target = _write_bytes(tmp_path / "target.yaml", WORKLOAD.read_bytes())
    link = tmp_path / "link.yaml"
    link.symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        load_workload(link)


def test_load_workload_rejects_non_regular_files(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="regular file"):
        load_workload(tmp_path)
