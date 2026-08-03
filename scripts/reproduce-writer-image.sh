#!/usr/bin/env bash
set -euo pipefail

[ "$(uname -s)" = Linux ] || {
  printf '%s\n' 'image reproduction requires a disposable Linux host; refusing this host' >&2
  exit 1
}

usage() {
  printf '%s\n' \
    'usage: reproduce-writer-image.sh COMMIT' \
    '   or: reproduce-writer-image.sh --source-commit COMMIT --source-date-epoch EPOCH' >&2
  exit 2
}

source_commit=''
requested_epoch=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source-commit)
      [ "$#" -ge 2 ] || usage
      source_commit=$2
      shift 2
      ;;
    --source-date-epoch)
      [ "$#" -ge 2 ] || usage
      requested_epoch=$2
      shift 2
      ;;
    -*)
      usage
      ;;
    *)
      [ -z "$source_commit" ] || usage
      source_commit=$1
      shift
      ;;
  esac
done
[ -n "$source_commit" ] || usage

repository=$(git rev-parse --show-toplevel)
cd "$repository"
resolved_commit=$(git rev-parse --verify "${source_commit}^{commit}")
[ "$resolved_commit" = "$source_commit" ] || {
  printf '%s\n' 'source commit must be one exact full commit ID' >&2
  exit 1
}
head_commit=$(git rev-parse --verify HEAD)
[ "$head_commit" = "$source_commit" ] || {
  printf '%s\n' 'checkout HEAD differs from the source commit' >&2
  exit 1
}
[ -z "$(git status --porcelain=v2 --untracked-files=all)" ] || {
  printf '%s\n' 'source checkout must be clean' >&2
  exit 1
}
source_date_epoch=$(git show -s --format=%ct "$source_commit")
if [ -n "$requested_epoch" ] && [ "$requested_epoch" != "$source_date_epoch" ]; then
  printf '%s\n' 'requested SOURCE_DATE_EPOCH differs from the commit timestamp' >&2
  exit 1
fi

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/writer-image-repro.XXXXXX")
tag_one="crypto-collector:writer-gate-repro-1-$$"
tag_two="crypto-collector:writer-gate-repro-2-$$"
container_one="crypto-writer-image-inspect-1-$$"
container_two="crypto-writer-image-inspect-2-$$"
builder_name="crypto-writer-repro-builder-$$"
builder_created=false
buildkit_image='moby/buildkit:v0.24.0@sha256:8c2ce26a3722e0cf4514fad4cfcd0e0f0f16214219ca7b73f3e1fcef74640ac4'
expected_buildkit_version='v0.24.0'

cleanup() {
  cleanup_status=$?
  trap - EXIT INT TERM
  docker container rm "$container_one" "$container_two" >/dev/null 2>&1 || true
  docker image rm "$tag_one" "$tag_two" >/dev/null 2>&1 || true
  if [ "$builder_created" = true ]; then
    docker buildx rm "$builder_name" >/dev/null 2>&1 || true
  fi
  case "$temporary_root" in
    "${TMPDIR:-/tmp}"/writer-image-repro.*)
      rm -rf "$temporary_root"
      ;;
    *)
      printf '%s\n' 'refusing to remove an unexpected temporary root' >&2
      cleanup_status=1
      ;;
  esac
  exit "$cleanup_status"
}
trap cleanup EXIT INT TERM

hash_file() {
  python3 - "$1" <<'PYTHON'
import hashlib
import sys
from pathlib import Path

print(hashlib.sha256(Path(sys.argv[1]).read_bytes()).hexdigest())
PYTHON
}

for ordinal in 1 2; do
  archive="$temporary_root/source-${ordinal}.tar"
  context="$temporary_root/context-${ordinal}"
  mkdir -p "$context"
  git archive --format=tar --output="$archive" "$source_commit"
  tar -xf "$archive" -C "$context"
done
source_archive_one_sha256=$(hash_file "$temporary_root/source-1.tar")
source_archive_two_sha256=$(hash_file "$temporary_root/source-2.tar")
[ "$source_archive_one_sha256" = "$source_archive_two_sha256" ] || {
  printf '%s\n' 'git archive contexts differ' >&2
  exit 1
}

python3 -m venv "$temporary_root/build-venv"
PIP_DISABLE_PIP_VERSION_CHECK=1 \
  "$temporary_root/build-venv/bin/python" -m pip install \
  --no-compile --require-hashes -r "$temporary_root/context-1/requirements/build.lock" \
  >&2
for ordinal in 1 2; do
  mkdir -p "$temporary_root/wheel-${ordinal}"
  SOURCE_DATE_EPOCH="$source_date_epoch" \
    "$temporary_root/build-venv/bin/python" -m pip wheel \
    --no-deps --no-build-isolation \
    --wheel-dir "$temporary_root/wheel-${ordinal}" \
    "$temporary_root/context-${ordinal}" >&2
  [ "$(find "$temporary_root/wheel-${ordinal}" -type f -name '*.whl' | wc -l | tr -d ' ')" = 1 ] || {
    printf '%s\n' 'wheel build did not produce exactly one wheel' >&2
    exit 1
  }
done
wheel_one=$(find "$temporary_root/wheel-1" -type f -name '*.whl')
wheel_two=$(find "$temporary_root/wheel-2" -type f -name '*.whl')
collector_wheel_sha256=$(hash_file "$wheel_one")
[ "$collector_wheel_sha256" = "$(hash_file "$wheel_two")" ] || {
  printf '%s\n' 'reproduced wheel hashes differ' >&2
  exit 1
}

requirements_lock_sha256=$(hash_file "$temporary_root/context-1/requirements/collector.lock")
build_requirements_lock_sha256=$(hash_file "$temporary_root/context-1/requirements/build.lock")
dockerfile_sha256=$(hash_file "$temporary_root/context-1/Dockerfile")
workload_sha256=$(hash_file "$temporary_root/context-1/benchmarks/workloads/research-default-v1.yaml")
dockerfile_frontend=$(sed -n '1s/^# syntax=//p' "$temporary_root/context-1/Dockerfile")
base_image_digest=$(sed -n 's/^FROM .*python:3\.11\.13-slim-bookworm@\(sha256:[0-9a-f]*\).*/\1/p' \
  "$temporary_root/context-1/Dockerfile" | head -n 1)
docker_engine_version=$(docker version --format '{{.Server.Version}}')
docker_buildx_version=$(docker buildx version | awk 'NR == 1 {print $2; exit}')
[ -n "$docker_engine_version" ] && [ -n "$docker_buildx_version" ] || {
  printf '%s\n' 'Docker Engine or Buildx version could not be observed' >&2
  exit 1
}
builder_created=true
docker buildx create \
  --name "$builder_name" \
  --driver docker-container \
  --driver-opt "image=$buildkit_image" \
  --bootstrap >/dev/null
builder_inspect=$(docker buildx inspect "$builder_name" --bootstrap)
builder_driver=$(printf '%s\n' "$builder_inspect" | awk '$1 == "Driver:" {print $2; exit}')
buildkit_version=$(printf '%s\n' "$builder_inspect" | awk '$1 == "BuildKit:" {print $2; exit}')
[ "$builder_driver" = docker-container ] || {
  printf '%s\n' 'reproduction builder is not docker-container' >&2
  exit 1
}
[ "$buildkit_version" = "$expected_buildkit_version" ] || {
  printf '%s\n' 'reproduction builder has the wrong BuildKit daemon version' >&2
  exit 1
}

python3 - \
  "$source_commit" "$source_date_epoch" "$base_image_digest" \
  "$docker_engine_version" "$docker_buildx_version" \
  "$buildkit_version" "$dockerfile_frontend" "$collector_wheel_sha256" \
  "$requirements_lock_sha256" "$build_requirements_lock_sha256" \
  "$dockerfile_sha256" "$workload_sha256" \
  > "$temporary_root/build-provenance-v1.json" <<'PYTHON'
import hashlib
import json
import sys

(
    source_commit,
    source_date_epoch,
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
) = sys.argv[1:]
provenance = {
    "schema_version": 1,
    "record_type": "gate_build_provenance_v1",
    "implementation_source_commit": source_commit,
    "source_date_epoch": int(source_date_epoch),
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
sys.stdout.buffer.write(document)
PYTHON
build_provenance_sha256=$(hash_file "$temporary_root/build-provenance-v1.json")

for ordinal in 1 2; do
  if [ "$ordinal" = 1 ]; then
    image_tag=$tag_one
  else
    image_tag=$tag_two
  fi
  docker buildx build \
    --builder "$builder_name" \
    --load \
    --no-cache \
    --platform linux/amd64 \
    --provenance=false \
    --sbom=false \
    --target collector \
    --tag "$image_tag" \
    --build-arg "COLLECTOR_SOURCE_COMMIT=$source_commit" \
    --build-arg "SOURCE_DATE_EPOCH=$source_date_epoch" \
    --build-arg "COLLECTOR_WHEEL_SHA256=$collector_wheel_sha256" \
    --build-arg "REQUIREMENTS_LOCK_SHA256=$requirements_lock_sha256" \
    --build-arg "BUILD_REQUIREMENTS_LOCK_SHA256=$build_requirements_lock_sha256" \
    --build-arg "DOCKERFILE_SHA256=$dockerfile_sha256" \
    --build-arg "WORKLOAD_SHA256=$workload_sha256" \
    --build-arg "BASE_IMAGE_DIGEST=$base_image_digest" \
    --build-arg "DOCKER_ENGINE_VERSION=$docker_engine_version" \
    --build-arg "DOCKER_BUILDX_VERSION=$docker_buildx_version" \
    --build-arg "BUILDKIT_VERSION=$buildkit_version" \
    --build-arg "DOCKERFILE_FRONTEND=$dockerfile_frontend" \
    --build-arg "BUILD_PROVENANCE_SHA256=$build_provenance_sha256" \
    "$temporary_root/context-${ordinal}" >&2
  docker image inspect "$image_tag" > "$temporary_root/image-${ordinal}.json"
  if [ "$ordinal" = 1 ]; then
    inspect_container=$container_one
  else
    inspect_container=$container_two
  fi
  docker container create --name "$inspect_container" "$image_tag" --help \
    > "$temporary_root/container-${ordinal}.id"
  docker container inspect "$inspect_container" \
    > "$temporary_root/container-${ordinal}.json"
  docker container export --output="$temporary_root/rootfs-${ordinal}.tar" \
    "$inspect_container"
done

python3 - \
  "$source_commit" "$source_date_epoch" \
  "$source_archive_one_sha256" "$source_archive_two_sha256" \
  "$base_image_digest" "$docker_engine_version" "$docker_buildx_version" \
  "$buildkit_version" "$dockerfile_frontend" \
  "$requirements_lock_sha256" "$build_requirements_lock_sha256" \
  "$dockerfile_sha256" "$workload_sha256" \
  "$temporary_root/context-1/requirements/collector.lock" \
  "$temporary_root/context-1/requirements/build.lock" \
  "$temporary_root/image-1.json" "$temporary_root/image-2.json" \
  "$temporary_root/container-1.json" "$temporary_root/container-2.json" \
  "$temporary_root/rootfs-1.tar" "$temporary_root/rootfs-2.tar" \
  > "$temporary_root/reproduction-transcript.json" <<'PYTHON'
import hashlib
import json
import re
import sys
import tarfile
from email.parser import BytesParser
from pathlib import Path

(
    source_commit,
    source_date_epoch,
    source_archive_one_sha256,
    source_archive_two_sha256,
    base_image_digest,
    docker_engine_version,
    docker_buildx_version,
    buildkit_version,
    dockerfile_frontend,
    requirements_lock_sha256,
    build_requirements_lock_sha256,
    dockerfile_sha256,
    workload_sha256,
    runtime_lock_path,
    build_lock_path,
    image_one_path,
    image_two_path,
    container_one_path,
    container_two_path,
    rootfs_one_path,
    rootfs_two_path,
) = sys.argv[1:]


def load_one(path: str) -> dict[str, object]:
    decoded = json.loads(Path(path).read_bytes())
    if not isinstance(decoded, list) or len(decoded) != 1 or not isinstance(decoded[0], dict):
        raise SystemExit(f"inspect output is malformed: {path}")
    return decoded[0]


def rootfs_facts(path: str) -> dict[str, object]:
    with tarfile.open(path, mode="r:") as archive:
        provenance_member = archive.getmember("app/build-provenance-v1.json")
        provenance_file = archive.extractfile(provenance_member)
        workload_file = archive.extractfile(
            "app/benchmarks/workloads/research-default-v1.yaml"
        )
        if provenance_file is None or workload_file is None:
            raise SystemExit("image export is missing required immutable files")
        provenance_source = provenance_file.read()
        workload_source = workload_file.read()
        provenance = json.loads(provenance_source)
        distributions: list[str] = []
        for member in archive.getmembers():
            if not member.isfile() or not member.name.endswith(".dist-info/METADATA"):
                continue
            metadata_file = archive.extractfile(member)
            if metadata_file is None:
                raise SystemExit("cannot read installed distribution metadata")
            metadata = BytesParser().parsebytes(metadata_file.read())
            name = metadata.get("Name")
            version = metadata.get("Version")
            if not name or not version:
                raise SystemExit("installed distribution metadata is incomplete")
            distributions.append(f"{name}=={version}")
    return {
        "build_provenance": provenance,
        "build_provenance_content_sha256": hashlib.sha256(
            provenance_source
        ).hexdigest(),
        "build_provenance_mode": f"{provenance_member.mode:04o}",
        "workload_sha256": hashlib.sha256(workload_source).hexdigest(),
        "installed_distributions": tuple(sorted(distributions)),
    }


def lock_requirements(path: str) -> tuple[str, ...]:
    requirements: list[str] = []
    pattern = re.compile(
        r"^([A-Za-z0-9][A-Za-z0-9._-]*)"
        r"(?:\[[A-Za-z0-9_,.-]+\])?==([^ \\\\]+)"
    )
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        match = pattern.match(line)
        if match is not None:
            requirements.append(f"{match.group(1)}=={match.group(2)}")
    if not requirements:
        raise SystemExit(f"lock contains no exact requirements: {path}")
    return tuple(sorted(requirements))


runtime_lock_requirements = lock_requirements(runtime_lock_path)
build_lock_requirements = lock_requirements(build_lock_path)

builds: list[dict[str, object]] = []
for source_context_sha256, image_path, container_path, rootfs_path in (
    (
        source_archive_one_sha256,
        image_one_path,
        container_one_path,
        rootfs_one_path,
    ),
    (
        source_archive_two_sha256,
        image_two_path,
        container_two_path,
        rootfs_two_path,
    ),
):
    image = load_one(image_path)
    container = load_one(container_path)
    config = image.get("Config")
    if not isinstance(config, dict) or not isinstance(config.get("Labels"), dict):
        raise SystemExit("image inspect lacks config labels")
    if image.get("Os") != "linux" or image.get("Architecture") != "amd64":
        raise SystemExit("image inspect reports the wrong target platform")
    if config.get("User") != "65532:65532":
        raise SystemExit("image inspect reports the wrong numeric user")
    if config.get("Entrypoint") != [
        "python",
        "-m",
        "crypto_collector.benchmarks.writer",
    ]:
        raise SystemExit("image inspect reports the wrong entrypoint")
    if config.get("Cmd") != ["--help"]:
        raise SystemExit("image inspect reports the wrong default command")
    if container.get("Image") != image.get("Id"):
        raise SystemExit("inspection container does not bind the image ID")
    rootfs = rootfs_facts(rootfs_path)
    provenance = rootfs["build_provenance"]
    if not isinstance(provenance, dict):
        raise SystemExit("build provenance is not an object")
    builds.append(
        {
            "source_context_sha256": source_context_sha256,
            "collector_wheel_sha256": provenance["collector_wheel_sha256"],
            "image_id": image.get("Id"),
            "labels": config["Labels"],
            "build_provenance": provenance,
            "build_provenance_content_sha256": rootfs[
                "build_provenance_content_sha256"
            ],
            "build_provenance_mode": rootfs["build_provenance_mode"],
            "workload_sha256": rootfs["workload_sha256"],
            "runtime_user": config.get("User"),
            "installed_distributions": rootfs["installed_distributions"],
        }
    )

transcript = {
    "source_commit": source_commit,
    "source_date_epoch": int(source_date_epoch),
    "platform": "linux/amd64",
    "base_image_digest": base_image_digest,
    "docker_engine_version": docker_engine_version,
    "docker_buildx_version": docker_buildx_version,
    "buildkit_version": buildkit_version,
    "dockerfile_frontend": dockerfile_frontend,
    "provenance_enabled": False,
    "sbom_enabled": False,
    "requirements_lock_sha256": requirements_lock_sha256,
    "build_requirements_lock_sha256": build_requirements_lock_sha256,
    "dockerfile_sha256": dockerfile_sha256,
    "workload_sha256": workload_sha256,
    "runtime_lock_requirements": runtime_lock_requirements,
    "build_lock_requirements": build_lock_requirements,
    "builds": tuple(builds),
}
sys.stdout.write(
    json.dumps(
        transcript,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    )
    + "\n"
)
PYTHON

image_one_id=$(docker image inspect --format '{{.Id}}' "$tag_one")
image_two_id=$(docker image inspect --format '{{.Id}}' "$tag_two")
[ "$image_one_id" = "$image_two_id" ] || {
  printf '%s\n' 'reproduced image IDs differ' >&2
  exit 1
}
docker image tag "$image_one_id" crypto-collector:writer-gate-b
cat "$temporary_root/reproduction-transcript.json"
