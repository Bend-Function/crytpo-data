from pathlib import Path

import typer

from crypto_collector.config.loader import load_resolved_config
from crypto_collector.config.report import build_config_report, format_validation_error

app = typer.Typer(no_args_is_help=True)
config_app = typer.Typer(no_args_is_help=True)
app.add_typer(config_app, name="config")


@app.callback()
def main() -> None:
    pass


@config_app.command("check")
def check_config(
    path: Path,
    json_output: bool = typer.Option(False, "--json"),
) -> None:
    try:
        resolved = load_resolved_config(path)
        report = build_config_report(resolved.bundle)
    except (OSError, ValueError) as error:
        typer.echo(format_validation_error(error))
        raise typer.Exit(2) from error
    typer.echo(report.to_json() if json_output else report.to_text())
