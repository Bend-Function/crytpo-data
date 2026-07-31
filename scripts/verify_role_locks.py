from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
import venv
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "requirements"
SUBPROCESS_TIMEOUT_SECONDS = 1_800

BASE_ENVIRONMENT_VARIABLES = (
    "COMSPEC",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "TEMP",
    "TMP",
    "TMPDIR",
    "WINDIR",
)
PACKAGE_INDEX_ENVIRONMENT_VARIABLES = (
    "ALL_PROXY",
    "CURL_CA_BUNDLE",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "PIP_CERT",
    "PIP_CLIENT_CERT",
    "PIP_EXTRA_INDEX_URL",
    "PIP_INDEX_URL",
    "PIP_PROXY",
    "PIP_TRUSTED_HOST",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_DIR",
    "SSL_CERT_FILE",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


@dataclass(frozen=True)
class Role:
    lock: str
    required_modules: tuple[str, ...]
    forbidden_modules: tuple[str, ...] = ()


COLLECTOR_MODULES = ("httpx", "socksio", "python_socks", "websockets")
ARCHIVE_MODULES = ("boto3", "oss2")
ENTRY_MODULES = {
    "collector": ("crypto_collector.runtime.worker",),
    "materializer": ("crypto_collector.materializer.service",),
    "archiver": ("crypto_collector.archive.service",),
}

ROLES = {
    "collector": Role(
        lock="collector.lock",
        required_modules=COLLECTOR_MODULES,
        forbidden_modules=("pyarrow", *ARCHIVE_MODULES),
    ),
    "materializer": Role(
        lock="materializer.lock",
        required_modules=("pyarrow",),
        forbidden_modules=(*COLLECTOR_MODULES, *ARCHIVE_MODULES),
    ),
    "archiver": Role(
        lock="archiver.lock",
        required_modules=ARCHIVE_MODULES,
        forbidden_modules=(*COLLECTOR_MODULES, "pyarrow"),
    ),
    "dev": Role(
        lock="dev.lock",
        required_modules=(
            *COLLECTOR_MODULES,
            "pyarrow",
            *ARCHIVE_MODULES,
            "pytest",
            "hypothesis",
        ),
    ),
}

IMPORT_PROBE = """
import importlib
import importlib.util
import json
import sys
from pathlib import Path

import crypto_collector
from crypto_collector import __version__
from crypto_collector.cli import app

venv_root = Path(sys.prefix).resolve()
package_path = Path(crypto_collector.__file__).resolve()
if not package_path.is_relative_to(venv_root):
    raise RuntimeError(f"package imported outside role venv: {package_path}")
if __version__ != "0.1.0":
    raise RuntimeError(f"unexpected package version: {__version__}")
if app is None:
    raise RuntimeError("CLI app did not import")

for module_name in json.loads(sys.argv[1]):
    importlib.import_module(module_name)

for module_name in json.loads(sys.argv[2]):
    if importlib.util.find_spec(module_name) is not None:
        raise RuntimeError(f"forbidden module is installed: {module_name}")
"""


def parse_required_entries(arguments: Sequence[str] | None = None) -> frozenset[str]:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--require-entry",
        action="append",
        choices=tuple(ENTRY_MODULES),
        default=[],
        dest="required_entries",
    )
    namespace = parser.parse_args(arguments)
    return frozenset(namespace.required_entries)


def required_modules_for_role(
    name: str,
    role: Role,
    required_entries: frozenset[str],
) -> tuple[str, ...]:
    if name not in required_entries:
        return role.required_modules
    return (*role.required_modules, *ENTRY_MODULES[name])


def _python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _clean_environment(*, allow_package_index: bool = False) -> dict[str, str]:
    allowed_variables: tuple[str, ...] = BASE_ENVIRONMENT_VARIABLES
    if allow_package_index:
        allowed_variables += PACKAGE_INDEX_ENVIRONMENT_VARIABLES
    environment = {
        name: os.environ[name] for name in allowed_variables if name in os.environ
    }
    environment.setdefault("PATH", os.defpath)
    environment["PIP_CONFIG_FILE"] = os.devnull
    environment["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    environment["PIP_NO_CACHE_DIR"] = "1"
    environment["PIP_NO_INPUT"] = "1"
    return environment


def _safe_output(output: str) -> str:
    sanitized = re.sub(r"https?://[^\s]+", "<redacted-url>", output)
    for name, value in os.environ.items():
        if value and any(
            word in name.upper()
            for word in (
                "ACCESS_KEY",
                "API_KEY",
                "AUTH",
                "CREDENTIAL",
                "PASSWORD",
                "PASSWD",
                "PRIVATE_KEY",
                "SECRET",
                "TOKEN",
            )
        ):
            sanitized = sanitized.replace(value, "<redacted-secret>")
    return sanitized


def _run(
    label: str,
    command: list[str],
    *,
    allow_package_index: bool = False,
    cwd: Path = ROOT,
) -> None:
    print(f"[verify] {label}", flush=True)
    result = subprocess.run(
        command,
        cwd=cwd,
        env=_clean_environment(allow_package_index=allow_package_index),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=False,
        timeout=SUBPROCESS_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        output = _safe_output(result.stdout)
        raise RuntimeError(
            f"{label} failed with exit code {result.returncode}:\n{output}"
        )


def _create_venv(venv_dir: Path) -> Path:
    venv.EnvBuilder(
        with_pip=True,
        system_site_packages=False,
    ).create(venv_dir)
    return _python(venv_dir)


def _install_lock(python: Path, lock: Path, label: str, *, cwd: Path) -> None:
    _run(
        label,
        [
            str(python),
            "-I",
            "-m",
            "pip",
            "install",
            "--require-hashes",
            "-r",
            str(lock),
        ],
        allow_package_index=True,
        cwd=cwd,
    )


def _build_wheel(build_root: Path) -> Path:
    build_python = _create_venv(build_root / "venv")
    _install_lock(
        build_python,
        REQUIREMENTS / "dev.lock",
        "install dev lock in clean build venv",
        cwd=build_root,
    )

    wheel_dir = build_root / "wheel"
    wheel_dir.mkdir()
    _run(
        "build project wheel",
        [
            str(build_python),
            "-I",
            "-m",
            "pip",
            "wheel",
            "--no-deps",
            "--no-build-isolation",
            "--wheel-dir",
            str(wheel_dir),
            str(ROOT),
        ],
        cwd=build_root,
    )

    wheels = list(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise RuntimeError(f"expected exactly one wheel, found {len(wheels)}")
    return wheels[0]


def _verify_role(
    name: str,
    role: Role,
    wheel: Path,
    required_entries: frozenset[str],
) -> None:
    with tempfile.TemporaryDirectory(prefix=f"crypto-{name}-") as temporary:
        role_root = Path(temporary)
        role_python = _create_venv(role_root / "venv")
        _install_lock(
            role_python,
            REQUIREMENTS / role.lock,
            f"install {name} lock in clean venv",
            cwd=role_root,
        )
        _run(
            f"install project wheel for {name}",
            [
                str(role_python),
                "-I",
                "-m",
                "pip",
                "install",
                "--no-deps",
                str(wheel),
            ],
            cwd=role_root,
        )
        _run(
            f"check {name} dependencies",
            [str(role_python), "-I", "-m", "pip", "check"],
            cwd=role_root,
        )
        _run(
            f"probe {name} imports and isolation",
            [
                str(role_python),
                "-I",
                "-c",
                IMPORT_PROBE,
                json.dumps(required_modules_for_role(name, role, required_entries)),
                json.dumps(role.forbidden_modules),
            ],
            cwd=role_root,
        )


def main(arguments: Sequence[str] | None = None) -> None:
    required_entries = parse_required_entries(arguments)
    for role in ROLES.values():
        lock = REQUIREMENTS / role.lock
        if not lock.is_file():
            raise RuntimeError(f"missing role lock: {lock.relative_to(ROOT)}")

    with tempfile.TemporaryDirectory(prefix="crypto-lock-build-") as temporary:
        wheel = _build_wheel(Path(temporary))
        for name, role in ROLES.items():
            _verify_role(name, role, wheel, required_entries)

    print("[verify] all role locks passed", flush=True)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"[verify] ERROR: {error}", file=sys.stderr)
        raise SystemExit(1) from error
