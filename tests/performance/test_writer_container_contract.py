from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = ROOT / "Dockerfile"
DOCKERIGNORE = ROOT / ".dockerignore"
RUNBOOK = ROOT / "docs/operations/writer-benchmark.md"
SHA256 = r"sha256:[0-9a-f]{64}"
BUILD_ARGUMENTS = (
    "COLLECTOR_SOURCE_COMMIT",
    "SOURCE_DATE_EPOCH",
    "COLLECTOR_WHEEL_SHA256",
    "REQUIREMENTS_LOCK_SHA256",
    "BUILD_REQUIREMENTS_LOCK_SHA256",
    "DOCKERFILE_SHA256",
    "WORKLOAD_SHA256",
    "BASE_IMAGE_DIGEST",
    "DOCKER_ENGINE_VERSION",
    "DOCKER_BUILDX_VERSION",
    "BUILDKIT_VERSION",
    "DOCKERFILE_FRONTEND",
    "BUILD_PROVENANCE_SHA256",
)
PROVENANCE_FIELDS = (
    "schema_version",
    "record_type",
    "implementation_source_commit",
    "source_date_epoch",
    "platform",
    "base_image_digest",
    "docker_engine_version",
    "docker_buildx_version",
    "buildkit_version",
    "dockerfile_frontend",
    "collector_wheel_sha256",
    "requirements_lock_sha256",
    "build_requirements_lock_sha256",
    "dockerfile_sha256",
    "workload_sha256",
    "provenance_enabled",
    "sbom_enabled",
    "runtime_user",
    "sha256",
)
OCI_LABELS = (
    "org.opencontainers.image.revision",
    "org.opencontainers.image.base.digest",
    "io.crypto-collector.source-date-epoch",
    "io.crypto-collector.collector-wheel-sha256",
    "io.crypto-collector.requirements-lock-sha256",
    "io.crypto-collector.build-requirements-lock-sha256",
    "io.crypto-collector.dockerfile-sha256",
    "io.crypto-collector.workload-sha256",
    "io.crypto-collector.build-provenance-sha256",
    "io.crypto-collector.platform",
    "io.crypto-collector.runtime-user",
    "io.crypto-collector.docker-engine-version",
    "io.crypto-collector.docker-buildx-version",
    "io.crypto-collector.buildkit-version",
    "io.crypto-collector.dockerfile-frontend",
    "io.crypto-collector.provenance",
    "io.crypto-collector.sbom",
)


def _read_required(path: Path) -> str:
    assert path.is_file(), (
        f"required contract file is missing: {path.relative_to(ROOT)}"
    )
    return path.read_text(encoding="utf-8")


def _ordered_offsets(document: str, markers: tuple[str, ...]) -> list[int]:
    offsets = [document.find(marker) for marker in markers]
    assert all(offset >= 0 for offset in offsets), dict(
        zip(markers, offsets, strict=True)
    )
    return offsets


def test_collector_image_pins_linux_python_and_the_dockerfile_frontend() -> None:
    dockerfile = _read_required(DOCKERFILE)
    first_line = dockerfile.splitlines()[0]

    assert re.fullmatch(
        rf"# syntax=docker/dockerfile:1\.18@{SHA256}",
        first_line,
    )
    from_lines = [line for line in dockerfile.splitlines() if line.startswith("FROM ")]
    assert from_lines
    assert all(
        re.fullmatch(
            rf"FROM --platform=linux/amd64 "
            rf"python:3\.11\.13-slim-bookworm@{SHA256} AS [a-z0-9-]+",
            line,
        )
        for line in from_lines
    )
    assert any(line.endswith(" AS wheel-builder") for line in from_lines)
    assert any(line.endswith(" AS collector") for line in from_lines)


def test_collector_image_uses_only_hash_locked_build_and_runtime_inputs() -> None:
    dockerfile = _read_required(DOCKERFILE)

    for argument in BUILD_ARGUMENTS:
        assert f"ARG {argument}" in dockerfile
    assert "COPY requirements/build.lock" in dockerfile
    assert "COPY requirements/collector.lock" in dockerfile
    assert dockerfile.count("--require-hashes") >= 2
    assert dockerfile.count("--no-compile") >= 3
    assert "--no-build-isolation" in dockerfile
    assert "SOURCE_DATE_EPOCH" in dockerfile
    assert "COLLECTOR_SOURCE_COMMIT" in dockerfile
    assert "requirements/archiver.lock" not in dockerfile
    assert "requirements/materializer.lock" not in dockerfile
    for forbidden_dependency in ("boto3", "oss2", "pyarrow"):
        assert forbidden_dependency not in dockerfile.lower()


def test_collector_image_preserves_the_wheel_filename_for_pip() -> None:
    dockerfile = _read_required(DOCKERFILE)

    assert "COPY --from=wheel-builder /wheel/*.whl /tmp/wheel/" in dockerfile
    assert "/tmp/collector.whl" not in dockerfile
    assert "python -m pip install --no-compile --no-deps /tmp/wheel/*.whl" in dockerfile


def test_collector_image_removes_unlocked_packaging_tools_from_runtime() -> None:
    dockerfile = _read_required(DOCKERFILE)

    assert "python -m pip uninstall --yes pip setuptools wheel" in dockerfile


def test_collector_image_freezes_provenance_workload_user_and_cli() -> None:
    dockerfile = _read_required(DOCKERFILE)

    assert "/app/build-provenance-v1.json" in dockerfile
    assert re.search(
        r"chmod\s+0?444\s+/app/build-provenance-v1\.json",
        dockerfile,
    )
    assert "research-default-v1.yaml" in dockerfile
    assert "research-default-v1.golden.json" in dockerfile
    assert "/app/benchmarks/workloads/" in dockerfile
    assert re.search(r"chmod\s+-R\s+a-w\s+/app/benchmarks/workloads", dockerfile)
    provenance = re.search(
        r"(?ms)^provenance = \{\n(?P<body>.*?)^\}\n",
        dockerfile,
    )
    assert provenance is not None
    unsigned_keys = tuple(
        re.findall(r'(?m)^\s{4}"([a-z0-9_]+)":', provenance.group("body"))
    )
    assert unsigned_keys == PROVENANCE_FIELDS[:-1]
    assert '"record_type": "gate_build_provenance_v1"' in dockerfile
    assert 'provenance["sha256"]' in dockerfile
    for label in OCI_LABELS:
        assert label in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert (
        'ENTRYPOINT ["python", "-m", "crypto_collector.benchmarks.writer"]'
        in dockerfile
    )
    assert 'CMD ["--help"]' in dockerfile


def test_expected_structured_image_inspect_contract_is_explicit() -> None:
    dockerfile = _read_required(DOCKERFILE)
    expected_inspect = {
        "Os": "linux",
        "Architecture": "amd64",
        "Config": {
            "User": "65532:65532",
            "Entrypoint": ["python", "-m", "crypto_collector.benchmarks.writer"],
            "Cmd": ["--help"],
            "Labels": set(OCI_LABELS),
        },
    }

    assert (
        f"--platform={expected_inspect['Os']}/{expected_inspect['Architecture']}"
        in (dockerfile)
    )
    assert f"USER {expected_inspect['Config']['User']}" in dockerfile
    assert (
        'ENTRYPOINT ["python", "-m", "crypto_collector.benchmarks.writer"]'
        in dockerfile
    )
    assert 'CMD ["--help"]' in dockerfile
    assert all(label in dockerfile for label in expected_inspect["Config"]["Labels"])


def test_docker_context_excludes_local_state_and_unrelated_roles() -> None:
    dockerignore = _read_required(DOCKERIGNORE)
    patterns = {
        line.strip()
        for line in dockerignore.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    for required_pattern in (
        ".git",
        ".worktrees",
        ".venv",
        "**/__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "data",
        "state",
        "evidence",
        "*.env",
        "*.pem",
        "requirements/archiver.lock",
        "requirements/build.in",
        "requirements/dev.lock",
        "requirements/materializer.lock",
    ):
        assert required_pattern in patterns
    for required_input in (
        "pyproject.toml",
        "requirements/build.lock",
        "requirements/collector.lock",
        "benchmarks/workloads/research-default-v1.yaml",
        "benchmarks/workloads/research-default-v1.golden.json",
    ):
        assert required_input not in patterns


def test_reproduction_script_refuses_macos_before_repository_commands(
    tmp_path: Path,
) -> None:
    script = ROOT / "scripts/reproduce-writer-image.sh"
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    marker = tmp_path / "git-was-called"
    uname = fake_bin / "uname"
    uname.write_text("#!/bin/sh\nprintf '%s\\n' Darwin\n", encoding="utf-8")
    uname.chmod(0o755)
    git = fake_bin / "git"
    git.write_text(
        "#!/bin/sh\nprintf '%s\\n' called > \"$REPRO_TEST_MARKER\"\nexit 97\n",
        encoding="utf-8",
    )
    git.chmod(0o755)
    environment = dict(os.environ)
    environment["PATH"] = f"{fake_bin}{os.pathsep}{environment['PATH']}"
    environment["REPRO_TEST_MARKER"] = marker.as_posix()

    completed = subprocess.run(
        ("bash", script.as_posix(), "--source-commit", "a" * 40),
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=10,
    )

    assert completed.returncode == 1
    assert "disposable Linux host" in completed.stderr
    assert not marker.exists()


def test_runbook_disables_bytecode_and_preflights_ignored_build_inputs() -> None:
    runbook = _read_required(RUNBOOK)
    implementation = runbook.index("## 1. Implementation Gate")
    first_python = runbook.index(".venv/bin/python", implementation)
    bytecode_guard = runbook.index("export PYTHONDONTWRITEBYTECODE=1")

    assert bytecode_guard < first_python
    assert "git ls-files --others --ignored --exclude-standard" in runbook
    assert "__pycache__" in runbook
    assert "*.pyc" in runbook
    assert 'test -f "$ignored_path"' in runbook
    assert 'test ! -L "$ignored_path"' in runbook


@pytest.mark.parametrize(
    "marker",
    (
        "IMPLEMENTATION_PASS",
        "DOCKER_REPRODUCIBILITY_PASS",
        "TARGET_PENDING",
        "RUNTIME_FAILURE",
        "PROVENANCE_FAILURE",
        "IMMUTABLE_ARCHIVE_FAILURE",
        "EVIDENCE_ACCEPTED",
    ),
)
def test_runbook_distinguishes_every_gate_state(marker: str) -> None:
    runbook = _read_required(RUNBOOK)
    assert f"`{marker}`" in runbook


def test_runbook_freezes_the_evidence_command_order() -> None:
    runbook = _read_required(RUNBOOK)
    offsets = _ordered_offsets(
        runbook,
        (
            "## 2. Reproduce The Collector Image",
            "## 3. Declare The Target",
            "## 4. Run The Qualification Writer",
            "## 5. Verify Runtime In A Fresh Container",
            "## 6. Build The Private File Inventory",
            "## 7. Archive Private Immutable Evidence",
            "## 8. Validate Host Provenance",
            "## 9. Build The Public Disclosure",
        ),
    )

    assert offsets == sorted(offsets)
    for command_marker in (
        "scripts/reproduce-writer-image.sh",
        "declare-target",
        "crypto-writer-gate-b",
        "validate-runtime",
        "build-inventory",
        "S3 Object Lock",
        "validate-provenance",
        "build-disclosure",
    ):
        assert command_marker in runbook


def test_runbook_requires_the_archive_modes_accepted_by_the_contract() -> None:
    runbook = _read_required(RUNBOOK)

    assert "S3 Object Lock in COMPLIANCE mode" in runbook
    assert "GOVERNANCE" not in runbook
    assert "OSS WORM/version retention" in runbook


def test_runbook_retains_containers_until_host_provenance_inspection() -> None:
    runbook = _read_required(RUNBOOK)

    assert "--name crypto-writer-gate-b" in runbook
    assert "--name crypto-writer-gate-b-runtime-verifier" in runbook
    assert "\n  --rm" not in runbook
    assert "docker run --rm" not in runbook
    inspection = runbook.index("docker container inspect")
    cleanup = runbook.index("docker container rm")
    assert inspection < cleanup


def test_runbook_hard_limits_writer_memory_and_proves_the_retained_config() -> None:
    runbook = _read_required(RUNBOOK)
    writer_section = runbook.split("## 4. Run The Qualification Writer", maxsplit=1)[
        1
    ].split("## 5. Verify Runtime In A Fresh Container", maxsplit=1)[0]

    assert writer_section.count("--memory 4g") == 1
    assert writer_section.count("--memory-swap 4g") == 1
    assert "{{.HostConfig.Memory}}" in writer_section
    assert "{{.HostConfig.MemorySwap}}" in writer_section
    assert "4294967296" in writer_section
    assert "{{.State.OOMKilled}}" in writer_section
    assert '"false"' in writer_section


def test_runbook_keeps_host_paths_stable_and_output_roots_disjoint() -> None:
    runbook = _read_required(RUNBOOK)

    assert 'COLLECTOR_GATE_TARGET_HOST="/declared/target"' in runbook
    assert 'COLLECTOR_GATE_EVIDENCE_HOST="/declared/target/evidence/' in runbook
    assert (
        runbook.count(
            '--mount "type=bind,src=$COLLECTOR_GATE_TARGET_HOST,'
            'dst=$COLLECTOR_GATE_TARGET_HOST"'
        )
        >= 3
    )
    assert '--data-root "$COLLECTOR_GATE_DATA_HOST"' in runbook
    assert '--state-root "$COLLECTOR_GATE_STATE_HOST"' in runbook
    assert '--evidence-root "$COLLECTOR_GATE_EVIDENCE_HOST"' in runbook
    assert '--report "$COLLECTOR_GATE_REPORT_HOST/writer-durability.json"' in runbook
    assert "--report /state/" not in runbook
    assert '--run-index "$COLLECTOR_GATE_EVIDENCE_HOST/run-index.json"' in runbook
    assert "dst=/data,readonly" not in runbook
    assert "dst=/state,readonly" not in runbook
    assert re.search(r"declared data, state, and evidence\s+roots", runbook)


def test_runbook_preserves_private_originals_and_requires_immutable_archive() -> None:
    runbook = _read_required(RUNBOOK)
    lowered = runbook.lower()

    assert "oss worm" in lowered
    assert "webdav" in lowered
    assert "webdav-only" in lowered
    assert "not qualification evidence" in lowered
    assert "canonical originals" in lowered
    assert "never redact" in lowered
    assert "private immutable evidence" in lowered
    assert "public disclosure" in lowered
    assert re.search(r"authorized\s+operators", lowered)


def test_runbook_contains_no_example_secret_values() -> None:
    runbook = _read_required(RUNBOOK)

    assert "AKIA" not in runbook
    assert not re.search(
        r"(?im)^(?:AWS_SECRET_ACCESS_KEY|ALIYUN_ACCESS_KEY_SECRET|PASSWORD)="
        r"[^<$\s][^\s]*$",
        runbook,
    )


def test_runbook_uses_the_supported_provenance_cli_and_receipt_paths() -> None:
    runbook = _read_required(RUNBOOK)
    provenance_command = runbook.split("validate-provenance", maxsplit=1)[1].split(
        "```", maxsplit=1
    )[0]

    assert "--output" not in provenance_command
    assert (
        '--runtime-index "$COLLECTOR_GATE_EVIDENCE_HOST/runtime-index.json"'
        in provenance_command
    )
    assert 'COLLECTOR_GATE_PRIVATE_HOST="/operator/private/' in runbook
    assert '"$COLLECTOR_GATE_PRIVATE_HOST/acceptance-receipt.json"' in runbook
    assert "gate-acceptance-receipt-v1.json" not in runbook
