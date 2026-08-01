from __future__ import annotations

import hashlib
import json
import os
import select
import signal
import subprocess
import sys
from pathlib import Path

import pytest

from crypto_collector.storage.manifest import RawManifestV1, load_raw_manifest

_HELPER = Path(__file__).parents[2] / "helpers/writer_crash_child.py"
_PART_RELATIVE_PATH = Path(
    "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/"
    "part-1785456000000000000-0.jsonl.zst.partial"
)


def _kill_at(
    root: Path,
    *,
    mode: str,
    phase: str,
    extra_args: tuple[str, ...] = (),
) -> None:
    read_fd, write_fd = os.pipe()
    process = subprocess.Popen(
        [
            sys.executable,
            os.fspath(_HELPER),
            mode,
            os.fspath(root),
            "--phase",
            phase,
            "--pipe-fd",
            str(write_fd),
            *extra_args,
        ],
        pass_fds=(write_fd,),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    os.close(write_fd)
    try:
        readable, _, _ = select.select((read_fd,), (), (), 10)
        if not readable:
            process.kill()
            stdout, stderr = process.communicate(timeout=10)
            pytest.fail(
                f"child did not reach {phase}: stdout={stdout!r}, stderr={stderr!r}"
            )
        marker = os.read(read_fd, 4096).decode("ascii").strip()
        if marker != phase:
            if process.poll() is None:
                process.kill()
            stdout, stderr = process.communicate(timeout=10)
            pytest.fail(
                f"child exited before {phase}: marker={marker!r}, "
                f"stdout={stdout!r}, stderr={stderr!r}"
            )
        process.send_signal(signal.SIGKILL)
        process.wait(timeout=10)
    finally:
        os.close(read_fd)
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    assert process.returncode == -signal.SIGKILL


def _kill_allocation_at(root: Path, phase: str) -> Path:
    _kill_at(root, mode="allocation", phase=phase)
    return root / "data" / _PART_RELATIVE_PATH


def _recover_in_fresh_process(root: Path) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, os.fspath(_HELPER), "recover", os.fspath(root)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def _assert_one_converged_trade(
    root: Path,
    *,
    expected_quarantine_count: int = 0,
) -> dict[str, object]:
    first = _recover_in_fresh_process(root)
    trade_manifests = [
        item for item in first["manifests"] if item["logical_stream"] == "trade"
    ]
    assert len(trade_manifests) == 1
    trade = trade_manifests[0]
    assert trade["record_count"] == 1
    assert trade["data_size_bytes"] == trade["manifest_file_size_bytes"]
    assert trade["data_sha256"] == trade["manifest_file_sha256"]
    trade_data = [
        item
        for item in first["closed_data"]
        if "/trade/" in f"/{item['relative_path']}"
    ]
    assert len(trade_data) == 1
    assert trade_data[0]["relative_path"] == trade["data_relative_path"]
    assert trade_data[0]["sha256"] == trade["data_sha256"]
    assert trade_data[0]["envelopes"] == [
        {
            "exchange": "okx",
            "logical_stream": "trade",
            "writer_sequence": 0,
            "payload": {"price": "100", "quantity": "1"},
        }
    ]
    assert (
        sum(
            item["data_relative_path"] == trade["data_relative_path"]
            for item in first["manifests"]
        )
        == 1
    )
    assert len(first["quarantine"]) == expected_quarantine_count
    assert not [path for path in first["partial_paths"] if "/trade/" in f"/{path}"]
    assert [item["transaction_id"] for item in first["fact_chains"]] == first[
        "transaction_ids"
    ]
    assert len({item["source_relative_path"] for item in first["fact_chains"]}) == len(
        first["fact_chains"]
    )
    for chain in first["fact_chains"]:
        assert [fact["kind"] for fact in chain["facts"]] == [
            "intent",
            "artifacts_durable",
            "source_settled",
            "control_ownership",
            "control_durable",
            "complete",
        ]

    second = _recover_in_fresh_process(root)
    assert second == first
    return first


@pytest.mark.parametrize(
    "phase",
    ("partial_create_before_parent_fsync", "partial_parent_fsync"),
)
def test_sigkill_around_allocation_parent_fsync_recovers_zero_byte_partial(
    tmp_path: Path,
    phase: str,
) -> None:
    partial_path = _kill_allocation_at(tmp_path, phase)
    assert partial_path.exists()
    assert partial_path.stat().st_size == 0

    first = _recover_in_fresh_process(tmp_path)
    assert len(first["outcomes"]) == 1
    outcome = first["outcomes"][0]
    assert outcome["source_disposition"] == "moved_to_quarantine"
    assert outcome["recovered_relative_path"] is None
    assert outcome["source_sha256"] == hashlib.sha256(b"").hexdigest()
    quarantine = tmp_path / "data" / outcome["quarantined_relative_path"]
    assert quarantine.read_bytes() == b""
    assert not partial_path.exists()
    assert len(first["transaction_ids"]) == 1

    second = _recover_in_fresh_process(tmp_path)
    assert second == first


@pytest.mark.parametrize(
    "phase",
    (
        "after_frame_write",
        "after_data_sync",
        "after_data_publish",
        "after_manifest_temp_sync",
        "after_manifest_publish",
    ),
)
def test_sigkill_at_close_phase_converges_to_one_visible_outcome(
    tmp_path: Path,
    phase: str,
) -> None:
    _kill_at(tmp_path, mode="writer-close", phase=phase)
    _assert_one_converged_trade(tmp_path)


@pytest.mark.parametrize(
    "phase",
    (
        "after_link",
        "after_destination_directory_fsync",
        "after_source_unlink",
    ),
)
def test_sigkill_during_hardlink_publication_converges_to_one_closed_identity(
    tmp_path: Path,
    phase: str,
) -> None:
    _kill_at(tmp_path, mode="writer-close", phase=phase)
    _assert_one_converged_trade(tmp_path)


def test_recovery_blocks_conflicting_final_and_manifest_temporary(
    tmp_path: Path,
) -> None:
    _kill_at(tmp_path, mode="writer-close", phase="after_manifest_temp_sync")
    temporary = next((tmp_path / "data").rglob("*.manifest.json.partial"))
    loaded = load_raw_manifest(temporary)
    values = loaded.manifest.model_dump(mode="python")
    values["closed_at_ns"] = loaded.manifest.closed_at_ns + 1
    conflicting = RawManifestV1.model_validate(values)
    final = temporary.with_name(temporary.name.removesuffix(".partial"))
    final.write_bytes(conflicting.canonical_bytes())

    completed = subprocess.run(
        [sys.executable, os.fspath(_HELPER), "recover", os.fspath(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "temporary conflicts with the final manifest" in completed.stderr
    assert temporary.exists()
    assert final.exists()


@pytest.mark.parametrize(
    "phase",
    tuple(
        f"{prefix}_{suffix}"
        for prefix in (
            "intent",
            "artifacts",
            "source_settled",
            "control_ownership",
            "control_durable",
            "complete",
        )
        for suffix in (
            "temp_create",
            "temp_parent_fsync",
            "file_fsync",
            "rename",
            "parent_fsync",
        )
    ),
)
def test_sigkill_at_recovery_fact_edge_replays_exactly_once(
    tmp_path: Path,
    phase: str,
) -> None:
    _kill_at(tmp_path, mode="recovery-edge", phase=phase)
    report = _assert_one_converged_trade(tmp_path)

    assert len(report["outcomes"]) == 1
    assert report["outcomes"][0]["source_disposition"] == "removed"
    assert len(report["transaction_ids"]) == 1


@pytest.mark.parametrize(
    "phase",
    (
        "recovery_root_mkdir",
        "recovery_root_parent_fsync",
        "exchange_journal_mkdir",
        "exchange_journal_parent_fsync",
        "transaction_mkdir",
        "transaction_parent_fsync",
    ),
)
def test_sigkill_at_recovery_directory_edge_replays_exactly_once(
    tmp_path: Path,
    phase: str,
) -> None:
    _kill_at(tmp_path, mode="recovery-edge", phase=phase)
    report = _assert_one_converged_trade(tmp_path)

    assert len(report["outcomes"]) == 1
    assert len(report["transaction_ids"]) == 1


@pytest.mark.parametrize(
    "phase",
    (
        "recovered_data_temp_create",
        "recovered_data_temp_parent_fsync",
        "recovered_data_file_fsync",
        "recovered_data_publish",
        "recovered_data_parent_fsync",
        "retained_data_parent_fsync",
        "recovery_manifest_temp_create",
        "recovery_manifest_temp_parent_fsync",
        "recovery_manifest_file_fsync",
        "recovery_manifest_publish",
        "recovery_manifest_parent_fsync",
        "quarantine_temp_create",
        "quarantine_temp_parent_fsync",
        "quarantine_file_fsync",
        "quarantine_publish",
        "quarantine_parent_fsync",
    ),
)
def test_sigkill_at_recovery_artifact_edge_replays_exactly_once(
    tmp_path: Path,
    phase: str,
) -> None:
    _kill_at(tmp_path, mode="recovery-edge", phase=phase)
    report = _assert_one_converged_trade(
        tmp_path,
        expected_quarantine_count=int(phase.startswith("quarantine_")),
    )

    assert len(report["outcomes"]) == 1
    expected_disposition = (
        "retained" if phase == "retained_data_parent_fsync" else "removed"
    )
    assert report["outcomes"][0]["source_disposition"] == expected_disposition
    assert len(report["transaction_ids"]) == 1


@pytest.mark.parametrize(
    "phase",
    ("source_settlement_mutation", "source_settlement_parent_fsync"),
)
def test_sigkill_at_source_settlement_edge_replays_exactly_once(
    tmp_path: Path,
    phase: str,
) -> None:
    _kill_at(tmp_path, mode="recovery-edge", phase=phase)
    report = _assert_one_converged_trade(tmp_path)

    assert len(report["outcomes"]) == 1
    assert report["outcomes"][0]["source_disposition"] == "removed"
    assert len(report["transaction_ids"]) == 1


@pytest.mark.parametrize(
    "phase",
    (
        "owned_control_partial_create",
        "owned_control_partial_parent_fsync",
        "owned_control_frame_write",
        "recovery_control_sync",
        "owned_control_data_publish",
        "owned_control_data_parent_fsync",
        "owned_control_normal_manifest_publish",
        "owned_control_normal_manifest_parent_fsync",
    ),
)
def test_sigkill_at_owned_control_edge_replays_exactly_once(
    tmp_path: Path,
    phase: str,
) -> None:
    replay_only = {
        "owned_control_partial_create",
        "owned_control_partial_parent_fsync",
        "owned_control_frame_write",
        "recovery_control_sync",
        "owned_control_data_publish",
        "owned_control_data_parent_fsync",
    }
    if phase in replay_only:
        _kill_at(
            tmp_path,
            mode="recovery-edge",
            phase="control_ownership_parent_fsync",
        )
        _kill_at(tmp_path, mode="replay-edge", phase=phase)
    else:
        _kill_at(tmp_path, mode="recovery-edge", phase=phase)
    report = _assert_one_converged_trade(tmp_path)

    assert len(report["outcomes"]) == 1
    assert len(report["transaction_ids"]) == 1
    control_manifests = [
        item for item in report["manifests"] if item["logical_stream"] == "_control"
    ]
    assert len(control_manifests) == 1
    control = control_manifests[0]
    if phase.startswith("owned_control_normal_manifest_"):
        assert control["close_reason"] == "recovery_control"
        assert control["recovery_transaction_id"] is None
        assert control["recovery_source_state"] is None
    else:
        assert control["close_reason"] == "recovery"
        assert control["recovery_transaction_id"] == report["transaction_ids"][0]
        assert control["recovery_source_state"] == "owned_control_carrier"


@pytest.mark.parametrize(
    "phase",
    (
        "owned_control_recovery_manifest_publish",
        "owned_control_recovery_manifest_parent_fsync",
    ),
)
def test_sigkill_at_owned_control_recovery_manifest_edge_replays_exactly_once(
    tmp_path: Path,
    phase: str,
) -> None:
    _kill_at(
        tmp_path,
        mode="recovery-edge",
        phase="owned_control_data_parent_fsync",
    )
    _kill_at(tmp_path, mode="replay-edge", phase=phase)
    report = _assert_one_converged_trade(tmp_path)

    assert len(report["outcomes"]) == 1
    assert len(report["transaction_ids"]) == 1


def test_retained_orphan_survives_writer_crash_then_recovery_crash(
    tmp_path: Path,
) -> None:
    _kill_at(tmp_path, mode="writer-close", phase="after_source_unlink")
    closed = next(
        path
        for path in (tmp_path / "data").rglob("*.jsonl.zst")
        if "/trade/" in f"/{path.relative_to(tmp_path / 'data').as_posix()}"
    )
    original_sha256 = hashlib.sha256(closed.read_bytes()).hexdigest()

    _kill_at(tmp_path, mode="replay-edge", phase="retained_data_parent_fsync")
    report = _assert_one_converged_trade(tmp_path)

    assert len(report["outcomes"]) == 1
    assert report["outcomes"][0]["source_disposition"] == "retained"
    trade_manifest = next(
        item for item in report["manifests"] if item["logical_stream"] == "trade"
    )
    assert (
        trade_manifest["data_relative_path"]
        == closed.relative_to(tmp_path / "data").as_posix()
    )
    assert trade_manifest["data_sha256"] == original_sha256
    assert len(report["transaction_ids"]) == 1


def test_owned_control_nonprefix_blocks_without_a_second_transaction(
    tmp_path: Path,
) -> None:
    _kill_at(
        tmp_path,
        mode="recovery-edge",
        phase="control_ownership_parent_fsync",
    )
    _kill_at(
        tmp_path,
        mode="replay-edge",
        phase="owned_control_partial_parent_fsync",
    )
    control_partial = next(
        path
        for path in (tmp_path / "data").rglob("*.partial")
        if "/_control/" in f"/{path.relative_to(tmp_path / 'data').as_posix()}"
    )
    control_partial.write_bytes(b"not-the-owned-control-frame")

    completed = subprocess.run(
        [sys.executable, os.fspath(_HELPER), "recover", os.fspath(tmp_path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode != 0
    assert "owned control carrier" in completed.stderr
    transaction_root = tmp_path / "state/raw-recovery/okx"
    assert len([path for path in transaction_root.iterdir() if path.is_dir()]) == 1


@pytest.mark.parametrize("fraction", (0.0, 0.5, 1.0))
def test_owned_control_carrier_prefix_resumes_in_a_fresh_process(
    tmp_path: Path,
    fraction: float,
) -> None:
    _kill_at(
        tmp_path,
        mode="recovery-edge",
        phase="owned_control_partial_create",
    )
    _kill_at(
        tmp_path,
        mode="owned-prefix",
        phase="owned_control_prefix_seeded",
        extra_args=("--fraction", str(fraction)),
    )

    report = _assert_one_converged_trade(tmp_path)

    assert len(report["outcomes"]) == 1
    assert len(report["transaction_ids"]) == 1
    control_manifest = next(
        item for item in report["manifests"] if item["logical_stream"] == "_control"
    )
    assert control_manifest["recovery_source_state"] == "owned_control_carrier"
    assert not [path for path in report["partial_paths"] if "/_control/" in f"/{path}"]
