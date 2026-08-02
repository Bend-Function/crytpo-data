from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from crypto_collector.benchmarks import runtime_verifier
from crypto_collector.benchmarks.runtime_verifier import (
    RuntimeEvidenceValidationError,
    validate_runtime_evidence,
)
from tests.support.writer_gate_evidence import write_passing_micro_evidence
from tests.support.writer_gate_mutations import (
    RUNTIME_EVIDENCE_MUTATIONS,
    RuntimeEvidenceMutation,
)


@pytest.mark.parametrize("mutation_name", ("workload_hash", "workload_plan_hash"))
def test_resigned_plan_mutation_reaches_independent_trace_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutation_name: str,
) -> None:
    mutation = next(
        item for item in RUNTIME_EVIDENCE_MUTATIONS if item.name == mutation_name
    )
    evidence = write_passing_micro_evidence(tmp_path / mutation_name)
    mutation.apply(evidence)
    original = runtime_verifier._validate_trace
    reached_trace_validation = False

    def observe_trace_validation(*args: Any, **kwargs: Any) -> Any:
        nonlocal reached_trace_validation
        reached_trace_validation = True
        return original(*args, **kwargs)

    monkeypatch.setattr(
        runtime_verifier,
        "_validate_trace",
        observe_trace_validation,
    )

    receipt = validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )

    assert reached_trace_validation is True
    assert receipt.failure_codes == ("evidence_integrity_invalid",)


@pytest.mark.parametrize("root_name", ("data_root", "state_root"))
def test_runtime_verifier_rejects_untrusted_root_without_outputs(
    tmp_path: Path,
    root_name: str,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "untrusted-root")
    root = getattr(evidence, root_name)
    backing = evidence.root / f"{root.name}-backing"
    root.rename(backing)
    root.symlink_to(backing, target_is_directory=True)

    with pytest.raises(
        RuntimeEvidenceValidationError, match=root_name.replace("_", " ")
    ):
        validate_runtime_evidence(
            evidence.run_index_path,
            target_probe=None,
        )

    assert not (evidence.root / "runtime-receipt.json").exists()
    assert not (evidence.root / "runtime-index.json").exists()


@pytest.mark.parametrize("link_kind", ("run_index", "evidence_root"))
def test_runtime_verifier_rejects_symlinked_entrypoint_without_outputs(
    tmp_path: Path,
    link_kind: str,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    if link_kind == "run_index":
        backing = evidence.root / "run-index.backing.json"
        evidence.run_index_path.rename(backing)
        evidence.run_index_path.symlink_to(backing)
        entrypoint = evidence.run_index_path
    else:
        alias = tmp_path / "evidence-alias"
        alias.symlink_to(evidence.root, target_is_directory=True)
        entrypoint = alias / "run-index.json"

    with pytest.raises(RuntimeEvidenceValidationError, match="symbolic links"):
        validate_runtime_evidence(entrypoint, target_probe=None)

    assert not (evidence.root / "runtime-receipt.json").exists()
    assert not (evidence.root / "runtime-index.json").exists()


def test_runtime_verifier_rejects_symlinked_referenced_leaf(
    tmp_path: Path,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / "evidence")
    candidate_path = evidence.root / evidence.run_index.candidate_report.relative_path
    backing = candidate_path.with_name(f"{candidate_path.name}.backing")
    candidate_path.rename(backing)
    candidate_path.symlink_to(backing)

    receipt = validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )

    assert receipt.failure_codes == ("evidence_integrity_invalid",)
    assert receipt.runtime_evidence_valid is False
    assert (evidence.root / "runtime-receipt.json").is_file()
    assert (evidence.root / "runtime-index.json").is_file()


@pytest.mark.parametrize(
    "mutation",
    RUNTIME_EVIDENCE_MUTATIONS,
    ids=str,
)
def test_runtime_verifier_rejects_primary_fact_mutation(
    tmp_path: Path,
    mutation: RuntimeEvidenceMutation,
) -> None:
    evidence = write_passing_micro_evidence(tmp_path / mutation.name)
    mutation.apply(evidence)

    receipt = validate_runtime_evidence(
        evidence.run_index_path,
        target_probe=None,
    )

    assert receipt.runtime_evidence_valid is False
    assert receipt.qualification_runtime_accepted is False
    assert receipt.failure_codes == mutation.expected_failure_codes
    assert (evidence.root / "runtime-receipt.json").read_bytes() == (
        receipt.canonical_bytes()
    )
    assert (evidence.root / "runtime-index.json").is_file()
