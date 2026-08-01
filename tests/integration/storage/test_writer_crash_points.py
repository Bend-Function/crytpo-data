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


def _kill_at(root: Path, *, mode: str, phase: str) -> None:
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


def _assert_one_converged_trade(root: Path) -> None:
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
    assert first["quarantine"] == []
    assert not [path for path in first["partial_paths"] if "/trade/" in f"/{path}"]

    second = _recover_in_fresh_process(root)
    assert second == first


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
