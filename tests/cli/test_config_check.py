from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from crypto_collector.cli import app


def _write(path: Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")


def _config_tree(tmp_path: Path, *, socks: bool = True) -> Path:
    _write(
        tmp_path / "config.yaml",
        """\
data_root: ./data
state_root: ./state
selection:
  fixed_pairs: [BTC/USDT]
  top_n: 3
exchanges:
  okx:
    markets:
      spot: {}
""",
    )
    proxy = (
        """
  - id: socks
    type: socks5h
    quota_group: proxy-nat
    url: env:SOCKS_URL
"""
        if socks
        else ""
    )
    _write(
        tmp_path / "config" / "network.yaml",
        """\
egress_pool:
  - id: direct
    type: direct
"""
        + proxy,
    )
    return tmp_path


def test_config_check_json_is_stable_and_redacted(tmp_path: Path, monkeypatch) -> None:
    config_tree = _config_tree(tmp_path)
    monkeypatch.setenv(
        "SOCKS_URL", "socks5h://research-user:highly-secret@127.0.0.1:1080"
    )
    runner = CliRunner()

    first = runner.invoke(app, ["config", "check", str(config_tree), "--json"])
    second = runner.invoke(app, ["config", "check", str(config_tree), "--json"])

    assert first.exit_code == 0, first.output
    assert first.stdout == second.stdout
    body = json.loads(first.stdout)
    assert len(body["config_sha256"]) == 64
    assert body["network"]["egress_pool"][1]["url"] == "env:SOCKS_URL"
    assert body["dynamic_selection"]["status"] == "unresolved"
    assert body["fixed_requests"][0]["status"] == "catalog_unresolved"
    assert "highly-secret" not in first.stdout
    assert "effective_interval" not in first.stdout


def test_config_check_reports_static_capacity_without_live_claims(
    tmp_path: Path, monkeypatch
) -> None:
    config_tree = _config_tree(tmp_path)
    monkeypatch.setenv("SOCKS_URL", "socks5h://127.0.0.1:1080")

    result = CliRunner().invoke(app, ["config", "check", str(config_tree), "--json"])

    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    assert body["static_capacity"]["status"] == "partial"
    assert body["static_capacity"]["configured_egress_count"] == 2
    assert body["static_capacity"]["live_capacity_status"] == "unresolved"
    assert body["requested_intervals"]["deep_snapshot_ns"]["okx/spot"] > 0
    assert body["capability_decisions"]["okx"]["date_gated_features"] == []


def test_config_check_reports_only_explicit_date_gated_features(tmp_path: Path) -> None:
    config_tree = _config_tree(tmp_path, socks=False)
    root = config_tree / "config.yaml"
    root.write_text(
        root.read_text(encoding="utf-8")
        + """\
capabilities:
  date_gated_features:
    okx:
      books_rpi:
        required: true
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["config", "check", str(config_tree), "--json"])

    assert result.exit_code == 0, result.output
    decisions = json.loads(result.stdout)["capability_decisions"]["okx"]
    assert decisions["date_gated_features"] == [
        {
            "available_from": "2026-07-28",
            "feature": "books_rpi",
            "markets": ["spot", "perpetual"],
            "required": True,
            "status": "probe_unresolved",
        }
    ]


def test_disabled_market_disables_nested_collection_decisions(tmp_path: Path) -> None:
    config_tree = _config_tree(tmp_path, socks=False)
    root = config_tree / "config.yaml"
    root.write_text(
        root.read_text(encoding="utf-8").replace(
            "spot: {}", "spot:\n        enabled: false"
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["config", "check", str(config_tree), "--json"])

    assert result.exit_code == 0, result.output
    body = json.loads(result.stdout)
    market = body["capability_decisions"]["okx"]["markets"]["spot"]
    assert market["enabled"] is False
    assert market["live_book"]["enabled"] is False
    assert market["deep_snapshot"]["enabled"] is False
    assert body["static_capacity"]["configured_market_count"] == 1
    assert body["static_capacity"]["enabled_market_count"] == 0


def test_config_check_human_output_keeps_warnings_nonfatal(
    tmp_path: Path,
) -> None:
    config_tree = _config_tree(tmp_path, socks=False)

    result = CliRunner().invoke(app, ["config", "check", str(config_tree)])

    assert result.exit_code == 0, result.output
    assert "Configuration valid" in result.stdout
    assert "Warnings" in result.stdout
    assert "unresolved" in result.stdout


def test_config_check_fails_before_network_or_file_creation(tmp_path: Path) -> None:
    config_tree = _config_tree(tmp_path, socks=False)
    _write(
        config_tree / "config" / "exchanges" / "okx.yaml",
        """\
markets:
  spot:
    books:
      deep_snapshot:
        depth: 5001
""",
    )

    result = CliRunner().invoke(app, ["config", "check", str(config_tree), "--json"])

    assert result.exit_code == 2
    assert "unsupported" in result.stdout.lower()
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "state").exists()


def test_invalid_literal_secret_is_not_echoed(tmp_path: Path) -> None:
    config_tree = _config_tree(tmp_path)
    network = config_tree / "config" / "network.yaml"
    network.write_text(
        network.read_text(encoding="utf-8").replace(
            "env:SOCKS_URL",
            "socks5h://user:plaintext-must-not-leak@127.0.0.1:1080",
        ),
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["config", "check", str(config_tree), "--json"])

    assert result.exit_code == 2
    assert "secret must use env:NAME or file:/absolute/path" in result.stdout
    assert "plaintext-must-not-leak" not in result.stdout


def test_archive_endpoint_credentials_are_rejected_without_echo(tmp_path: Path) -> None:
    config_tree = _config_tree(tmp_path, socks=False)
    canary = "archive-endpoint-plaintext-canary"
    root = config_tree / "config.yaml"
    root.write_text(
        root.read_text(encoding="utf-8")
        + f"""\
archive:
  targets:
    - id: s3-primary
      type: s3
      bucket: market-data
      endpoint: https://user:{canary}@example.test
      credentials:
        access_key_id: env:S3_ACCESS_KEY_ID
        secret_access_key: env:S3_SECRET_ACCESS_KEY
""",
        encoding="utf-8",
    )

    result = CliRunner().invoke(app, ["config", "check", str(config_tree), "--json"])

    assert result.exit_code == 2
    assert "archive endpoint" in result.stdout
    assert canary not in result.stdout
    assert not (tmp_path / "data").exists()
    assert not (tmp_path / "state").exists()


def test_committed_config_check_reports_all_five_exchanges() -> None:
    repository = Path(__file__).parents[2]

    result = CliRunner().invoke(
        app, ["config", "check", str(repository / "config.yaml"), "--json"]
    )

    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)["exchanges"]) == 5
