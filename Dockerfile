# syntax=docker/dockerfile:1.18@sha256:dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf

FROM --platform=linux/amd64 python:3.11.13-slim-bookworm@sha256:cec9aa7aa96eea4fa036e9b82be1e6b325f2e3707f462d885868df51ec0a4b47 AS wheel-builder

ARG SOURCE_DATE_EPOCH
ARG COLLECTOR_WHEEL_SHA256
ARG BUILD_REQUIREMENTS_LOCK_SHA256

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_NO_INPUT=1 \
    PIP_ROOT_USER_ACTION=ignore \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /build

COPY requirements/build.lock /tmp/requirements/build.lock
RUN printf '%s  %s\n' \
      "$BUILD_REQUIREMENTS_LOCK_SHA256" /tmp/requirements/build.lock \
      | sha256sum --check --strict - \
    && python -m pip install \
      --no-compile --no-deps --require-hashes -r /tmp/requirements/build.lock \
    && rm -rf /root/.cache /tmp/requirements

COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel \
      --no-deps --no-build-isolation --wheel-dir /wheel . \
    && test "$(find /wheel -maxdepth 1 -type f -name '*.whl' | wc -l)" = "1" \
    && printf '%s  %s\n' "$COLLECTOR_WHEEL_SHA256" /wheel/*.whl \
      | sha256sum --check --strict - \
    && rm -rf /root/.cache


FROM --platform=linux/amd64 python:3.11.13-slim-bookworm@sha256:cec9aa7aa96eea4fa036e9b82be1e6b325f2e3707f462d885868df51ec0a4b47 AS collector

ARG COLLECTOR_SOURCE_COMMIT
ARG SOURCE_DATE_EPOCH
ARG COLLECTOR_WHEEL_SHA256
ARG REQUIREMENTS_LOCK_SHA256
ARG BUILD_REQUIREMENTS_LOCK_SHA256
ARG DOCKERFILE_SHA256
ARG WORKLOAD_SHA256
ARG BASE_IMAGE_DIGEST
ARG DOCKER_ENGINE_VERSION
ARG DOCKER_BUILDX_VERSION
ARG BUILDKIT_VERSION
ARG DOCKERFILE_FRONTEND
ARG BUILD_PROVENANCE_SHA256

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONHASHSEED=0 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_NO_INPUT=1 \
    PIP_ROOT_USER_ACTION=ignore \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /app

COPY requirements/collector.lock /tmp/requirements/collector.lock
RUN printf '%s  %s\n' \
      "$REQUIREMENTS_LOCK_SHA256" /tmp/requirements/collector.lock \
      | sha256sum --check --strict - \
    && python -m pip install \
      --no-compile --no-deps --only-binary=:all: --require-hashes \
      -r /tmp/requirements/collector.lock \
    && rm -rf /root/.cache /tmp/requirements

COPY --from=wheel-builder /wheel/*.whl /tmp/wheel/
RUN printf '%s  %s\n' "$COLLECTOR_WHEEL_SHA256" /tmp/wheel/*.whl \
      | sha256sum --check --strict - \
    && python -m pip install --no-compile --no-deps /tmp/wheel/*.whl \
    && python -m pip uninstall --yes pip setuptools wheel \
    && rm -rf /root/.cache /tmp/wheel

COPY benchmarks/workloads/research-default-v1.yaml \
  /app/benchmarks/workloads/research-default-v1.yaml
COPY benchmarks/workloads/research-default-v1.golden.json \
  /app/benchmarks/workloads/research-default-v1.golden.json
RUN printf '%s  %s\n' \
      "$WORKLOAD_SHA256" \
      /app/benchmarks/workloads/research-default-v1.yaml \
      | sha256sum --check --strict - \
    && chmod -R a-w /app/benchmarks/workloads

RUN <<'SHELL'
python - \
  "$COLLECTOR_SOURCE_COMMIT" \
  "$SOURCE_DATE_EPOCH" \
  "$BASE_IMAGE_DIGEST" \
  "$DOCKER_ENGINE_VERSION" \
  "$DOCKER_BUILDX_VERSION" \
  "$BUILDKIT_VERSION" \
  "$DOCKERFILE_FRONTEND" \
  "$COLLECTOR_WHEEL_SHA256" \
  "$REQUIREMENTS_LOCK_SHA256" \
  "$BUILD_REQUIREMENTS_LOCK_SHA256" \
  "$DOCKERFILE_SHA256" \
  "$WORKLOAD_SHA256" \
  "$BUILD_PROVENANCE_SHA256" <<'PYTHON'
import hashlib
import json
import re
import sys
from pathlib import Path


(
    source_commit,
    source_date_epoch_source,
    base_image_digest,
    docker_engine_version,
    docker_buildx_version,
    buildkit_version,
    dockerfile_frontend,
    collector_wheel_sha256,
    requirements_lock_sha256,
    build_requirements_lock_sha256,
    dockerfile_sha256,
    workload_sha256,
    expected_document_sha256,
) = sys.argv[1:]

sha256 = re.compile(r"[0-9a-f]{64}").fullmatch
if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
    raise SystemExit("COLLECTOR_SOURCE_COMMIT must be a full Git SHA-1")
try:
    source_date_epoch = int(source_date_epoch_source)
except ValueError as error:
    raise SystemExit("SOURCE_DATE_EPOCH must be an integer") from error
if source_date_epoch < 0:
    raise SystemExit("SOURCE_DATE_EPOCH must be nonnegative")
for name, value in (
    ("COLLECTOR_WHEEL_SHA256", collector_wheel_sha256),
    ("REQUIREMENTS_LOCK_SHA256", requirements_lock_sha256),
    ("BUILD_REQUIREMENTS_LOCK_SHA256", build_requirements_lock_sha256),
    ("DOCKERFILE_SHA256", dockerfile_sha256),
    ("WORKLOAD_SHA256", workload_sha256),
    ("BUILD_PROVENANCE_SHA256", expected_document_sha256),
):
    if sha256(value) is None:
        raise SystemExit(f"{name} must be a lowercase SHA-256")
if base_image_digest != (
    "sha256:cec9aa7aa96eea4fa036e9b82be1e6b325f2e3707f462d885868df51ec0a4b47"
):
    raise SystemExit("BASE_IMAGE_DIGEST does not match the Dockerfile base")
if dockerfile_frontend != (
    "docker/dockerfile:1.18@sha256:"
    "dabfc0969b935b2080555ace70ee69a5261af8a8f1b4df97b9e7fbcf6722eddf"
):
    raise SystemExit("DOCKERFILE_FRONTEND does not match the syntax directive")
for name, value in (
    ("DOCKER_ENGINE_VERSION", docker_engine_version),
    ("DOCKER_BUILDX_VERSION", docker_buildx_version),
    ("BUILDKIT_VERSION", buildkit_version),
):
    if not value or any(character.isspace() for character in value):
        raise SystemExit(f"{name} must be one nonempty token")

provenance = {
    "schema_version": 1,
    "record_type": "gate_build_provenance_v1",
    "implementation_source_commit": source_commit,
    "source_date_epoch": source_date_epoch,
    "platform": "linux/amd64",
    "base_image_digest": base_image_digest,
    "docker_engine_version": docker_engine_version,
    "docker_buildx_version": docker_buildx_version,
    "buildkit_version": buildkit_version,
    "dockerfile_frontend": dockerfile_frontend,
    "collector_wheel_sha256": collector_wheel_sha256,
    "requirements_lock_sha256": requirements_lock_sha256,
    "build_requirements_lock_sha256": build_requirements_lock_sha256,
    "dockerfile_sha256": dockerfile_sha256,
    "workload_sha256": workload_sha256,
    "provenance_enabled": False,
    "sbom_enabled": False,
    "runtime_user": "65532:65532",
}
unsigned = json.dumps(
    provenance,
    ensure_ascii=False,
    allow_nan=False,
    separators=(",", ":"),
).encode("utf-8") + b"\n"
provenance["sha256"] = hashlib.sha256(unsigned).hexdigest()
document = json.dumps(
    provenance,
    ensure_ascii=False,
    allow_nan=False,
    separators=(",", ":"),
).encode("utf-8") + b"\n"
if hashlib.sha256(document).hexdigest() != expected_document_sha256:
    raise SystemExit("BUILD_PROVENANCE_SHA256 does not match canonical document")
Path("/app/build-provenance-v1.json").write_bytes(document)
PYTHON
chmod 0444 /app/build-provenance-v1.json
SHELL

LABEL org.opencontainers.image.revision="${COLLECTOR_SOURCE_COMMIT}" \
      org.opencontainers.image.base.digest="${BASE_IMAGE_DIGEST}" \
      io.crypto-collector.source-date-epoch="${SOURCE_DATE_EPOCH}" \
      io.crypto-collector.collector-wheel-sha256="${COLLECTOR_WHEEL_SHA256}" \
      io.crypto-collector.requirements-lock-sha256="${REQUIREMENTS_LOCK_SHA256}" \
      io.crypto-collector.build-requirements-lock-sha256="${BUILD_REQUIREMENTS_LOCK_SHA256}" \
      io.crypto-collector.dockerfile-sha256="${DOCKERFILE_SHA256}" \
      io.crypto-collector.workload-sha256="${WORKLOAD_SHA256}" \
      io.crypto-collector.build-provenance-sha256="${BUILD_PROVENANCE_SHA256}" \
      io.crypto-collector.platform="linux/amd64" \
      io.crypto-collector.runtime-user="65532:65532" \
      io.crypto-collector.docker-engine-version="${DOCKER_ENGINE_VERSION}" \
      io.crypto-collector.docker-buildx-version="${DOCKER_BUILDX_VERSION}" \
      io.crypto-collector.buildkit-version="${BUILDKIT_VERSION}" \
      io.crypto-collector.dockerfile-frontend="${DOCKERFILE_FRONTEND}" \
      io.crypto-collector.provenance="false" \
      io.crypto-collector.sbom="false"

USER 65532:65532
ENTRYPOINT ["python", "-m", "crypto_collector.benchmarks.writer"]
CMD ["--help"]
