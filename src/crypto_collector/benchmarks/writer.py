from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from crypto_collector.benchmarks.contracts import GateRunIndexV1
from crypto_collector.benchmarks.provenance import (
    ProvenanceValidationError,
    SubprocessArchiveProviderPort,
    SubprocessDockerPort,
    SubprocessGitPort,
    build_disclosure,
    load_acceptance_receipt,
    load_build_provenance,
    publish_disclosure,
    validate_provenance,
)
from crypto_collector.benchmarks.runner import (
    QualificationClaims,
    RunnerPreflightError,
    RunRequest,
    WriterGateRunError,
    parse_gate_duration,
    run_writer_gate,
)
from crypto_collector.benchmarks.runtime_verifier import (
    RuntimeEvidenceValidationError,
    validate_runtime_evidence,
)
from crypto_collector.benchmarks.target import declare_target, reprobe_target

app = typer.Typer(
    add_completion=False,
    invoke_without_command=True,
    no_args_is_help=True,
)


def _absolute(path: Path) -> Path:
    return path if path.is_absolute() else (Path.cwd() / path).resolve(strict=False)


def _build_claims(
    *,
    functional_only: bool,
    target_declaration: Path | None,
    expected_target_id: str | None,
    expected_image_id: str | None,
    build_provenance: Path,
) -> QualificationClaims | None:
    supplied = (target_declaration, expected_target_id, expected_image_id)
    if functional_only:
        if any(value is not None for value in supplied):
            raise RunnerPreflightError(
                "functional mode forbids target and image options"
            )
        return None
    if any(value is None for value in supplied):
        raise RunnerPreflightError(
            "qualification requires target declaration, target ID, and image ID"
        )
    runtime_image_id = os.environ.get("COLLECTOR_RUNTIME_IMAGE_ID")
    if runtime_image_id is None:
        raise RunnerPreflightError("qualification requires COLLECTOR_RUNTIME_IMAGE_ID")
    provenance_path = _absolute(build_provenance)
    try:
        provenance = load_build_provenance(provenance_path)
    except (OSError, TypeError, ValueError, ProvenanceValidationError) as error:
        raise RunnerPreflightError("build provenance document is invalid") from error

    assert target_declaration is not None
    assert expected_target_id is not None
    assert expected_image_id is not None
    return QualificationClaims(
        target_declaration_path=_absolute(target_declaration),
        expected_target_id=expected_target_id,
        expected_image_id=expected_image_id,
        runtime_image_id=runtime_image_id,
        implementation_source_commit=provenance.implementation_source_commit,
        collector_wheel_sha256=provenance.collector_wheel_sha256,
        requirements_lock_sha256=provenance.requirements_lock_sha256,
        dockerfile_sha256=provenance.dockerfile_sha256,
    )


def _launch_fresh_runtime_verifier(
    run_index_path: Path,
    *,
    expected_target_id: str | None,
) -> None:
    command = [
        sys.executable,
        "-m",
        "crypto_collector.benchmarks.writer",
        "validate-runtime",
        "--run-index",
        os.fspath(run_index_path),
    ]
    if expected_target_id is not None:
        command.extend(("--expected-target-id", expected_target_id))
    completed = subprocess.run(command, check=False)
    if completed.returncode != 0:
        raise WriterGateRunError("fresh runtime verifier rejected the candidate")


def _execute_run(
    *,
    workload: Path,
    multiplier: int,
    duration: str,
    evidence_root: Path,
    report: Path,
    functional_only: bool,
    data_root: Path | None,
    state_root: Path | None,
    target_declaration: Path | None,
    expected_target_id: str | None,
    expected_image_id: str | None,
    build_provenance: Path,
) -> None:
    claims = _build_claims(
        functional_only=functional_only,
        target_declaration=target_declaration,
        expected_target_id=expected_target_id,
        expected_image_id=expected_image_id,
        build_provenance=build_provenance,
    )
    result = run_writer_gate(
        RunRequest(
            workload_path=_absolute(workload),
            multiplier=multiplier,
            duration_ns=parse_gate_duration(duration),
            evidence_root=_absolute(evidence_root),
            report_path=_absolute(report),
            functional_only=functional_only,
            data_root=None if data_root is None else _absolute(data_root),
            state_root=None if state_root is None else _absolute(state_root),
            qualification=claims,
        )
    )
    _launch_fresh_runtime_verifier(
        result.run_index_path,
        expected_target_id=None if claims is None else claims.expected_target_id,
    )
    typer.echo(result.candidate_report.canonical_bytes().decode("utf-8").rstrip())


WorkloadOption = Annotated[Path | None, typer.Option("--workload")]
MultiplierOption = Annotated[int | None, typer.Option("--multiplier")]
DurationOption = Annotated[str | None, typer.Option("--duration")]
EvidenceRootOption = Annotated[Path | None, typer.Option("--evidence-root")]
ReportOption = Annotated[Path | None, typer.Option("--report")]
FunctionalOption = Annotated[bool, typer.Option("--functional-only")]
DataRootOption = Annotated[Path | None, typer.Option("--data-root")]
StateRootOption = Annotated[Path | None, typer.Option("--state-root")]
TargetDeclarationOption = Annotated[
    Path | None,
    typer.Option("--target-declaration"),
]
ExpectedTargetOption = Annotated[str | None, typer.Option("--expected-target-id")]
ExpectedImageOption = Annotated[str | None, typer.Option("--expected-image-id")]
BuildProvenanceOption = Annotated[
    Path,
    typer.Option("--build-provenance"),
]


def _required_default_options(
    workload: Path | None,
    multiplier: int | None,
    duration: str | None,
    evidence_root: Path | None,
    report: Path | None,
) -> tuple[Path, int, str, Path, Path]:
    values = (workload, multiplier, duration, evidence_root, report)
    if any(value is None for value in values):
        raise RunnerPreflightError(
            "run requires workload, multiplier, duration, evidence root, and report"
        )
    assert workload is not None
    assert multiplier is not None
    assert duration is not None
    assert evidence_root is not None
    assert report is not None
    return workload, multiplier, duration, evidence_root, report


@app.callback(invoke_without_command=True)
def main(
    context: typer.Context,
    workload: WorkloadOption = None,
    multiplier: MultiplierOption = None,
    duration: DurationOption = None,
    evidence_root: EvidenceRootOption = None,
    report: ReportOption = None,
    functional_only: FunctionalOption = False,
    data_root: DataRootOption = None,
    state_root: StateRootOption = None,
    target_declaration: TargetDeclarationOption = None,
    expected_target_id: ExpectedTargetOption = None,
    expected_image_id: ExpectedImageOption = None,
    build_provenance: BuildProvenanceOption = Path("/app/build-provenance-v1.json"),
) -> None:
    if context.invoked_subcommand is not None:
        return
    try:
        required = _required_default_options(
            workload,
            multiplier,
            duration,
            evidence_root,
            report,
        )
        _execute_run(
            workload=required[0],
            multiplier=required[1],
            duration=required[2],
            evidence_root=required[3],
            report=required[4],
            functional_only=functional_only,
            data_root=data_root,
            state_root=state_root,
            target_declaration=target_declaration,
            expected_target_id=expected_target_id,
            expected_image_id=expected_image_id,
            build_provenance=build_provenance,
        )
    except RunnerPreflightError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(2) from error
    except (OSError, ValueError, WriterGateRunError) as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error


@app.command("run")
def run_command(
    workload: Annotated[Path, typer.Option("--workload")],
    multiplier: Annotated[int, typer.Option("--multiplier")],
    duration: Annotated[str, typer.Option("--duration")],
    evidence_root: Annotated[Path, typer.Option("--evidence-root")],
    report: Annotated[Path, typer.Option("--report")],
    functional_only: FunctionalOption = False,
    data_root: DataRootOption = None,
    state_root: StateRootOption = None,
    target_declaration: TargetDeclarationOption = None,
    expected_target_id: ExpectedTargetOption = None,
    expected_image_id: ExpectedImageOption = None,
    build_provenance: BuildProvenanceOption = Path("/app/build-provenance-v1.json"),
) -> None:
    try:
        _execute_run(
            workload=workload,
            multiplier=multiplier,
            duration=duration,
            evidence_root=evidence_root,
            report=report,
            functional_only=functional_only,
            data_root=data_root,
            state_root=state_root,
            target_declaration=target_declaration,
            expected_target_id=expected_target_id,
            expected_image_id=expected_image_id,
            build_provenance=build_provenance,
        )
    except RunnerPreflightError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(2) from error
    except (OSError, ValueError, WriterGateRunError) as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error


@app.command("validate-runtime")
def validate_runtime_command(
    run_index: Annotated[Path, typer.Option("--run-index")],
    expected_target_id: ExpectedTargetOption = None,
) -> None:
    path = _absolute(run_index)
    try:
        source = path.read_bytes()
        index = GateRunIndexV1.model_validate_json(source, strict=True)
        if index.canonical_bytes() != source:
            raise RuntimeEvidenceValidationError("run index is not canonical")
        if index.mode == "functional":
            if expected_target_id is not None:
                raise RuntimeEvidenceValidationError(
                    "functional verification forbids an expected target ID"
                )
            target_probe = None
        else:
            if (
                expected_target_id is None
                or expected_target_id != index.expected_target_id
            ):
                raise RuntimeEvidenceValidationError(
                    "qualification expected target ID does not match"
                )
            target_probe = reprobe_target
        receipt = validate_runtime_evidence(path, target_probe=target_probe)
    except (OSError, ValueError, RuntimeEvidenceValidationError) as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error
    typer.echo(receipt.canonical_bytes().decode("utf-8").rstrip())
    if not receipt.runtime_evidence_valid:
        raise typer.Exit(1)


@app.command("declare-target")
def declare_target_command(
    target_id: Annotated[str, typer.Option("--target-id")],
    data_root: Annotated[Path, typer.Option("--data-root")],
    state_root: Annotated[Path, typer.Option("--state-root")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    try:
        declaration = declare_target(
            target_id=target_id,
            data_root=_absolute(data_root),
            state_root=_absolute(state_root),
            output=_absolute(output),
        )
    except (OSError, ValueError) as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error
    typer.echo(declaration.canonical_bytes().decode("utf-8").rstrip())


@app.command("validate-provenance")
def validate_provenance_command(
    source_commit: Annotated[str, typer.Option("--source-commit")],
    runtime_index: Annotated[Path, typer.Option("--runtime-index")],
    archive_attestation: Annotated[Path, typer.Option("--archive-attestation")],
    writer_container: Annotated[str, typer.Option("--writer-container")],
    verifier_container: Annotated[str, typer.Option("--verifier-container")],
    repository: Annotated[Path, typer.Option("--repository")] = Path("."),
) -> None:
    repository_path = _absolute(repository)
    try:
        acceptance = validate_provenance(
            source_commit=source_commit,
            runtime_index=_absolute(runtime_index),
            archive_attestation=_absolute(archive_attestation),
            writer_container=writer_container,
            verifier_container=verifier_container,
            docker=SubprocessDockerPort(repository_path),
            git=SubprocessGitPort(repository_path),
            archive_provider=SubprocessArchiveProviderPort(repository_path),
        )
    except (OSError, TypeError, ValueError, ProvenanceValidationError) as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error
    typer.echo(acceptance.canonical_bytes().decode("utf-8").rstrip())


@app.command("build-disclosure")
def build_disclosure_command(
    acceptance: Annotated[Path, typer.Option("--acceptance")],
    output: Annotated[Path, typer.Option("--output")],
) -> None:
    try:
        receipt = load_acceptance_receipt(_absolute(acceptance))
        disclosure = build_disclosure(receipt)
        publish_disclosure(_absolute(output), disclosure)
    except (OSError, TypeError, ValueError, ProvenanceValidationError) as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(1) from error
    typer.echo(disclosure.canonical_bytes().decode("utf-8").rstrip())


def entrypoint() -> Any:
    return app()


if __name__ == "__main__":
    entrypoint()
