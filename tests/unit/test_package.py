from typer.testing import CliRunner

from crypto_collector import __version__
from crypto_collector.cli import app


def test_package_exposes_version() -> None:
    assert __version__ == "0.1.0"


def test_cli_help_runs() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
