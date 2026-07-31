# Collector Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Create the installable Python package, stable domain types, strict layered configuration, capability registry, and configuration-check CLI required by every later subsystem.

**Architecture:** Domain contracts are dependency-light frozen dataclasses and enums. Pydantic validates user configuration with unknown-key rejection, while immutable built-in capability YAML constrains what each adapter may request.

**Tech Stack:** Python 3.11+, hatchling, Pydantic 2, ruamel.yaml, simplejson with Decimal, Typer, pytest, Hypothesis, pip-tools.

---

### Task 1: Package and Offline Test Harness

**Files:**
- Create: `pyproject.toml`
- Create: `requirements/collector.lock`
- Create: `requirements/materializer.lock`
- Create: `requirements/archiver.lock`
- Create: `requirements/dev.lock`
- Create: `scripts/verify_role_locks.py`
- Create: `src/crypto_collector/__init__.py`
- Create: `src/crypto_collector/__main__.py`
- Create: `src/crypto_collector/cli.py`
- Create: `tests/unit/test_package.py`
- Create: `tests/conftest.py`
- Modify: `.gitignore`
- Delete: `requirements-smoke.txt`
- Modify: `README.md`

- [ ] **Step 1: Write the failing import and CLI tests**

```python
# tests/unit/test_package.py
from crypto_collector import __version__
from crypto_collector.cli import app
from typer.testing import CliRunner


def test_package_exposes_version() -> None:
    assert __version__ == "0.1.0"


def test_cli_help_runs() -> None:
    result = CliRunner().invoke(app, ["--help"])
    assert result.exit_code == 0
```

- [ ] **Step 2: Run the test and verify collection fails**

Run: `.venv/bin/python -m pytest tests/unit/test_package.py -q`

Expected: FAIL during collection with `ModuleNotFoundError: No module named 'crypto_collector'`.

- [ ] **Step 3: Add the package metadata and minimal module**

```toml
# pyproject.toml
[build-system]
requires = ["hatchling>=1.27,<2"]
build-backend = "hatchling.build"

[project]
name = "crypto-market-data-collector"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = [
  "prometheus-client>=0.22,<1",
  "pydantic>=2.11,<3",
  "ruamel.yaml>=0.18,<0.19",
  "simplejson>=3.20,<4",
  "typer>=0.16,<1",
  "zstandard>=0.23,<1",
]

[project.optional-dependencies]
collector = [
  "httpx[socks]>=0.28,<1",
  "python-socks[asyncio]>=2.7,<3",
  "websockets>=17,<18",
]
materializer = ["pyarrow>=18,<24"]
archive = ["boto3>=1.39,<2", "oss2>=2.19,<3"]
dev = [
  "hatchling>=1.27,<2",
  "hypothesis>=6.130,<7",
  "moto[s3,server]>=5,<6",
  "pip-tools>=7.4,<8",
  "pytest>=9,<10",
  "pytest-asyncio>=1,<2",
  "pytest-socket>=0.7,<1",
  "respx>=0.22,<1",
  "ruff>=0.12,<1",
  "mypy>=1.17,<2",
]

[project.scripts]
collector = "crypto_collector.cli:app"

[tool.hatch.build.targets.wheel]
packages = ["src/crypto_collector"]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = [
  "live: opt-in test that contacts a public external service",
  "network: test that uses a local network fixture",
  "performance: target-host performance acceptance test",
]
asyncio_mode = "auto"
addopts = "--disable-socket --allow-unix-socket"
```

```python
# src/crypto_collector/__init__.py
__version__ = "0.1.0"
```

```python
# src/crypto_collector/__main__.py
from crypto_collector.cli import app

app()
```

```python
# src/crypto_collector/cli.py
import typer

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main() -> None:
    pass
```

```python
# tests/conftest.py
import pytest


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(pytest.mark.enable_socket)
        elif item.get_closest_marker("network"):
            item.add_marker(pytest.mark.allow_hosts(["127.0.0.1", "::1"]))
```

All local HTTP, WebSocket, and SOCKS fixtures are function-scoped and bind literal loopback addresses. The `network` marker never enables arbitrary hosts; only `live` tests, which remain environment-gated, receive unrestricted sockets.

Generate four genuinely role-specific locks and install the development set. Runtime modules import role extras lazily so materializer/archiver startup does not require collector network packages, collector does not require PyArrow/provider SDKs, and materializer does not require archive SDKs. Only `requirements/materializer.lock` contributes the dependency-lock SHA to materialization identity; test/provider SDK churn must not change that identity.

```bash
.venv/bin/python -m pip install "pip-tools>=7.4,<8"
mkdir -p requirements
.venv/bin/pip-compile --extra collector --generate-hashes --output-file requirements/collector.lock pyproject.toml
.venv/bin/pip-compile --extra materializer --generate-hashes --output-file requirements/materializer.lock pyproject.toml
.venv/bin/pip-compile --extra archive --generate-hashes --output-file requirements/archiver.lock pyproject.toml
.venv/bin/pip-compile --extra archive --extra collector --extra dev --extra materializer --generate-hashes --output-file requirements/dev.lock pyproject.toml
.venv/bin/python -m pip install --dry-run --require-hashes -r requirements/collector.lock
.venv/bin/python -m pip install --dry-run --require-hashes -r requirements/materializer.lock
.venv/bin/python -m pip install --dry-run --require-hashes -r requirements/archiver.lock
.venv/bin/python -m pip install --dry-run --require-hashes -r requirements/dev.lock
.venv/bin/python -m pip install -r requirements/dev.lock
.venv/bin/python -m pip install -e . --no-deps
.venv/bin/python scripts/verify_role_locks.py
```

`scripts/verify_role_locks.py` must not inspect or reuse the active environment's site-packages. It first creates a clean build venv, installs `requirements/dev.lock` with hashes, and builds one wheel with `pip wheel --no-deps --no-build-isolation`; `hatchling` is therefore itself locked. For each of `collector`, `materializer`, `archiver`, and `dev`, it then creates a separate `TemporaryDirectory`, creates a new venv with `system_site_packages=False`, installs that role's lock with `--require-hashes`, installs that exact wheel with `--no-deps`, runs `pip check`, and launches a subprocess import probe. The collector probe requires HTTPX/SOCKS/websockets and asserts PyArrow/Boto3/OSS2 are absent; materializer requires PyArrow and asserts collector/archive extras are absent; archiver requires Boto3/OSS2 and asserts PyArrow/collector extras are absent; dev requires every extra plus pytest/Hypothesis. At this foundation stage all four import the base package and CLI; later role plans rerun the same verifier with their newly available entry-module probes enabled. Any install, hash, build, dependency, forbidden-package, or import failure fails the task. A dry run in the existing `.venv` is useful diagnostics but does not satisfy this clean-environment gate.

- [ ] **Step 4: Run the package test and the existing smoke suite offline**

Run: `.venv/bin/python -m pytest tests/unit/test_package.py tests/smoke -q`

Expected: `2 passed, 17 skipped`.

- [ ] **Step 5: Document the locked install and commit**

Update `README.md` with the four install commands above and retain the explicit live-test opt-in. Add `data/`, `dist/`, `.coverage`, and `*.egg-info/` to `.gitignore`.

```bash
git add pyproject.toml requirements scripts/verify_role_locks.py src/crypto_collector tests/unit/test_package.py tests/conftest.py .gitignore README.md requirements-smoke.txt
git commit -m "build: initialize collector package"
```

### Task 2: Domain Types, Clock, and Instrument Key Paths

**Files:**
- Create: `src/crypto_collector/domain/__init__.py`
- Create: `src/crypto_collector/domain/types.py`
- Create: `src/crypto_collector/domain/clock.py`
- Create: `src/crypto_collector/domain/envelope.py`
- Create: `src/crypto_collector/domain/json_codec.py`
- Create: `src/crypto_collector/domain/paths.py`
- Test: `tests/unit/domain/test_envelope.py`
- Test: `tests/unit/domain/test_paths.py`

- [ ] **Step 1: Write failing contract tests**

```python
# tests/unit/domain/test_paths.py
from hypothesis import given, strategies as st

from crypto_collector.domain.paths import decode_instrument_key, encode_instrument_key


@given(st.text(min_size=1).filter(lambda value: "\x00" not in value and value not in {".", ".."}))
def test_instrument_key_is_reversible_and_has_no_path_separator(instrument_key: str) -> None:
    key = encode_instrument_key(instrument_key)
    assert "/" not in key
    assert decode_instrument_key(key) == instrument_key


def test_kraken_symbol_is_percent_encoded() -> None:
    assert encode_instrument_key("BTC/USDT") == "BTC%2FUSDT"


def test_reserved_segment_cannot_collide() -> None:
    assert encode_instrument_key("_market") == "%5Fmarket"
```

```python
# tests/unit/domain/test_envelope.py
from decimal import Decimal

import pytest
from pydantic import ValidationError

from crypto_collector.domain.envelope import NativeEventDraft, RawEnvelope, RestMetadata, SourceContext
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.domain.types import Exchange, Market, Transport


def test_event_time_may_be_absent_but_receive_and_monotonic_time_are_required() -> None:
    row = RawEnvelope(
        exchange=Exchange.OKX,
        market=Market.SPOT,
        instrument_key="BTC-USDT",
        wire_symbol="BTC-USDT",
        logical_stream="book_live",
        native_channel="books",
        transport=Transport.WEBSOCKET,
        event_time_ns=None,
        event_time_source=None,
        received_at_ns=1_785_473_918_123_456_789,
        monotonic_ns=123,
        worker_instance_id="worker-1",
        connection_id="connection-1",
        connection_generation=1,
        writer_sequence=7,
        egress_id="direct-primary",
        config_sha256="a" * 64,
        payload={"arg": {"channel": "books"}, "ratio": Decimal("0.1")},
    )
    assert row.event_time_ns is None
    assert row.payload["arg"]["channel"] == "books"
    assert decode_json(encode_json(row.model_dump()))["payload"]["ratio"] == Decimal("0.1")


def test_routine_rest_has_null_connection_and_structured_metadata() -> None:
    row = make_envelope(
        transport=Transport.REST,
        connection_id=None,
        connection_generation=None,
        rest_metadata=RestMetadata(
            request_started_at_ns=1,
            request_ended_at_ns=2,
            method="GET",
            path="/api/v5/market/tickers",
            params={"instType": "SPOT"},
            status=200,
            attempt=1,
            rate_limit_headers={},
            requested_interval_ns=30_000_000_000,
            effective_interval_ns=60_000_000_000,
        ),
    )
    assert row.connection_id is None


def test_symbol_data_rejects_missing_instrument_identity() -> None:
    with pytest.raises(ValidationError, match="instrument_key"):
        make_envelope(logical_stream="trade", instrument_key=None, wire_symbol=None)


def test_exchange_control_draft_uses_explicit_null_scope() -> None:
    draft = NativeEventDraft(
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        event_time_ns=None,
        event_time_source=None,
        payload={"kind": "config_committed"},
    )
    assert draft.market is None
    assert SourceContext.internal().egress_id is None


@pytest.mark.parametrize("bad", [Decimal("NaN"), Decimal("Infinity"), Decimal("-Infinity")])
def test_payload_rejects_every_non_finite_decimal(bad) -> None:
    with pytest.raises(ValidationError, match="finite"):
        make_envelope(payload={"bad": [bad]})


@pytest.mark.parametrize("raw", [b'{"bad":NaN}', b'{"bad":Infinity}', b'{"bad":-Infinity}'])
def test_decoder_rejects_non_json_numeric_constants(raw) -> None:
    with pytest.raises(ValueError, match="non-finite|constant"):
        decode_json(raw)


@pytest.mark.parametrize("builder", [make_native_event_draft, make_envelope])
@pytest.mark.parametrize("bad_payload", [
    {"nested": [0.1]},
    {"nested": [b"bytes"]},
    {1: "non-string-key"},
])
def test_draft_and_envelope_share_recursive_json_domain_rejection(builder, bad_payload) -> None:
    with pytest.raises(ValidationError, match="payload|JSON"):
        builder(payload=bad_payload)
```

- [ ] **Step 2: Run the tests and verify imports fail**

Run: `.venv/bin/python -m pytest tests/unit/domain -q`

Expected: FAIL with missing `crypto_collector.domain` modules.

- [ ] **Step 3: Implement the frozen contracts**

```python
# src/crypto_collector/domain/types.py
from enum import StrEnum


class Exchange(StrEnum):
    BINANCE = "binance"
    OKX = "okx"
    BYBIT = "bybit"
    BITGET = "bitget"
    KRAKEN = "kraken"


class Market(StrEnum):
    SPOT = "spot"
    PERPETUAL = "perpetual"


class Transport(StrEnum):
    REST = "rest"
    WEBSOCKET = "websocket"
    INTERNAL = "internal"


class IntegrityMode(StrEnum):
    SEQUENCE_VERIFIED = "sequence_verified"
    CHECKSUM_VERIFIED = "checksum_verified"
    SNAPSHOT_CHAIN = "snapshot_chain"
    BEST_EFFORT = "best_effort"
    INVALID = "invalid"

    @property
    def is_research_valid(self) -> bool:
        return self is not IntegrityMode.INVALID


class CoverageMode(StrEnum):
    COMPLETE = "complete"
    LOSSY_WINDOW = "lossy_window"
    UNKNOWN = "unknown"


class CloseReason(StrEnum):
    ROTATE_TIME = "rotate_time"
    ROTATE_SIZE = "rotate_size"
    CONFIG_RELOAD = "config_reload"
    SHUTDOWN = "shutdown"
    RECOVERY = "recovery"
```

```python
# src/crypto_collector/domain/clock.py
import time
from typing import Protocol


class Clock(Protocol):
    def time_ns(self) -> int: ...
    def monotonic_ns(self) -> int: ...


class SystemClock:
    def time_ns(self) -> int:
        return time.time_ns()

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()
```

```python
# src/crypto_collector/domain/paths.py
from urllib.parse import unquote

_SAFE = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.~")


def encode_instrument_key(instrument_key: str) -> str:
    if not instrument_key or instrument_key in {".", ".."} or "\x00" in instrument_key:
        raise ValueError("instrument key is not path-safe")
    return "".join(chr(byte) if byte in _SAFE else f"%{byte:02X}"
                   for byte in instrument_key.encode("utf-8"))


def decode_instrument_key(encoded: str) -> str:
    return unquote(encoded, encoding="utf-8", errors="strict")
```

Implement `RestMetadata`, `NativeEventDraft`, and `RawEnvelope` as frozen strict Pydantic models with `extra="forbid"`; `RawEnvelope` has `schema_version: Literal[1] = 1`. `NativeEventDraft` is the canonical connector-to-storage type and contains every exchange/native field through `payload`, but none of `received_at_ns`, `monotonic_ns`, `worker_instance_id`, connection identity, `writer_sequence`, `egress_id`, or `config_sha256`. Follow the spec's nullability rules for market/instrument/wire/native-channel: symbol streams require stable `instrument_key` plus exact `wire_symbol`; `_market` may omit instrument/wire; exchange `_control` may also omit market/native channel. REST drafts require `RestMetadata`; internal control/recovery uses `Transport.INTERNAL`. Top-level optional `integrity_mode` and `coverage` use the domain enums rather than modifying native payload. `RestMetadata` contains request wall-clock start/end, method, redacted path/params, status, attempt, rate-limit headers, and optional requested/effective interval nanoseconds.

Also define frozen `SourceContext(connection_id: str | None, connection_generation: int | None, egress_id: str | None)`. Its validators enforce that WebSocket data has all three values; `book_live_bootstrap` has all three even though transport is REST; ordinary external REST has only `egress_id`; and pure internal controls use `SourceContext.internal()` with all three null. Plan 02's `RawIngress.try_accept(draft, source=source, shard=shard)` receives the canonical draft/source plus the runtime plan's storage shard ID, owns the worker/config identity, and is the only component that stamps acceptance times and sequence into the final envelope.

Define one canonical `validate_json_payload(value, path=()) -> JsonPayload` recursion in `json_codec.py`; both `NativeEventDraft.payload` and `RawEnvelope.payload` invoke that same function through the same annotated Pydantic field type. It permits `Decimal` but rejects float, bytes, non-string object keys, NaN, and infinity at every nesting level with a path-aware error. Neither model may maintain a second validator. Validators also require non-negative generation/sequence/timestamps and a lowercase 64-character hexadecimal config hash.

```python
# src/crypto_collector/domain/json_codec.py
from decimal import Decimal
from typing import Any, TypeAlias

import simplejson

JsonPayload: TypeAlias = (
    bool | int | Decimal | str | None | list["JsonPayload"] | dict[str, "JsonPayload"]
)


def decode_json(data: str | bytes) -> Any:
    return simplejson.loads(data, use_decimal=True, allow_nan=False,
                            parse_constant=reject_non_finite_constant)


def encode_json(value: Any) -> bytes:
    return simplejson.dumps(value, use_decimal=True, ensure_ascii=False,
                            allow_nan=False, separators=(",", ":"),
                            sort_keys=False).encode("utf-8")
```

`reject_non_finite_constant` always raises `ValueError` naming the rejected token. The recursive payload validator calls `Decimal.is_finite()` at every nesting level before encoding, so Decimal NaN/infinities cannot rely on encoder-version behavior.

- [ ] **Step 4: Run the domain tests**

Run: `.venv/bin/python -m pytest tests/unit/domain -q`

Expected: PASS.

- [ ] **Step 5: Commit the stable domain API**

```bash
git add src/crypto_collector/domain tests/unit/domain
git commit -m "feat: define raw domain contracts"
```

### Task 3: Strict Durations, Secret References, and Layer Merge

**Files:**
- Create: `src/crypto_collector/config/__init__.py`
- Create: `src/crypto_collector/config/primitives.py`
- Create: `src/crypto_collector/config/merge.py`
- Test: `tests/unit/config/test_primitives.py`
- Test: `tests/unit/config/test_merge.py`

- [ ] **Step 1: Write failing parsing and merge tests**

```python
# tests/unit/config/test_primitives.py
import pytest

from crypto_collector.config.primitives import SecretRef, SecretSnapshot, parse_duration_ns, parse_size_bytes


def test_duration_and_size_use_explicit_units() -> None:
    assert parse_duration_ns("500ms") == 500_000_000
    assert parse_duration_ns("72h") == 259_200_000_000_000
    assert parse_size_bytes("1GiB") == 1_073_741_824


@pytest.mark.parametrize("value", ["1", "1.5s", "-1s", "1M", " 1s"])
def test_invalid_duration_is_rejected(value: str) -> None:
    with pytest.raises(ValueError):
        parse_duration_ns(value)


def test_secret_repr_never_contains_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:password@127.0.0.1:1080")
    ref = SecretRef.parse("env:SOCKS_URL")
    snapshot = SecretSnapshot.resolve_all([ref])
    assert snapshot.value_for(ref).reveal().startswith("socks5h://")
    assert "password" not in repr(ref)
    assert "password" not in repr(snapshot)
    assert "password" not in repr(snapshot.value_for(ref))
    assert ref.fingerprint_value() == "env:SOCKS_URL"


def test_file_secret_is_regular_small_restricted_and_removes_one_newline(tmp_path) -> None:
    secret = tmp_path / "archive-key"
    secret.write_text("value\n", encoding="utf-8")
    secret.chmod(0o600)
    ref = SecretRef.parse(f"file:{secret}")
    assert SecretSnapshot.resolve_all([ref]).value_for(ref).reveal() == "value"
    assert ref.fingerprint_value() == f"file:{secret}"


def test_group_writable_file_secret_is_rejected(tmp_path) -> None:
    secret = tmp_path / "unsafe"
    secret.write_text("value", encoding="utf-8")
    secret.chmod(0o620)
    with pytest.raises(ValueError, match="permissions"):
        SecretSnapshot.resolve_all([SecretRef.parse(f"file:{secret}")])
```

```python
# tests/unit/config/test_merge.py
from crypto_collector.config.merge import merge_layers


def test_mappings_recurse_scalars_override_and_lists_replace() -> None:
    result = merge_layers(
        {"selection": {"top_n": 20, "quote_assets": ["USDT"]}},
        {"selection": {"top_n": 5, "quote_assets": ["USD", "USDT"]}},
    )
    assert result == {"selection": {"top_n": 5, "quote_assets": ["USD", "USDT"]}}
```

- [ ] **Step 2: Run and confirm missing modules fail**

Run: `.venv/bin/python -m pytest tests/unit/config/test_primitives.py tests/unit/config/test_merge.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement exact parsers and merge behavior**

```python
# src/crypto_collector/config/primitives.py
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

_DURATION = re.compile(r"^(0|[1-9][0-9]*)(ms|s|m|h|d)$")
_DURATION_SCALE = {"ms": 1_000_000, "s": 1_000_000_000, "m": 60_000_000_000,
                   "h": 3_600_000_000_000, "d": 86_400_000_000_000}
_SIZE = re.compile(r"^(0|[1-9][0-9]*)(B|KiB|MiB|GiB)$")
_SIZE_SCALE = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}


def parse_duration_ns(value: str) -> int:
    match = _DURATION.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid duration: {value!r}")
    return int(match.group(1)) * _DURATION_SCALE[match.group(2)]


def parse_size_bytes(value: str) -> int:
    match = _SIZE.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid size: {value!r}")
    return int(match.group(1)) * _SIZE_SCALE[match.group(2)]


@dataclass(frozen=True, slots=True)
class SecretRef:
    scheme: str
    target: str

    @classmethod
    def parse(cls, value: str) -> "SecretRef":
        scheme, separator, target = value.partition(":")
        if separator != ":" or scheme not in {"env", "file"} or not target:
            raise ValueError("secret must use env:NAME or file:/absolute/path")
        if scheme == "file" and not Path(target).is_absolute():
            raise ValueError("file secret path must be absolute")
        return cls(scheme, target)

    def _resolve_once(self) -> str:
        if self.scheme == "env":
            try:
                return os.environ[self.target]
            except KeyError as error:
                raise ValueError(f"missing environment variable: {self.target}") from error
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(self.target, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("file secret must be a regular file")
            if info.st_size > 65_536:
                raise ValueError("file secret exceeds 64KiB")
            if info.st_mode & 0o022:
                raise ValueError("file secret has unsafe permissions")
            chunks: list[bytes] = []
            remaining = 65_537
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > 65_536:
                raise ValueError("file secret exceeds 64KiB")
        finally:
            os.close(fd)
        value = raw.decode("utf-8", errors="strict")
        return value[:-1] if value.endswith("\n") else value

    def fingerprint_value(self) -> str:
        return f"{self.scheme}:{self.target}"

    def __repr__(self) -> str:
        return f"SecretRef({self.fingerprint_value()!r})"
```

Add `SecretValue` as a frozen `repr=False` wrapper whose only plaintext accessor is `reveal()`, and `SecretSnapshot` as a frozen `repr=False` mapping from `SecretRef` to `SecretValue`. `SecretSnapshot.resolve_all(refs)` deduplicates references and calls `_resolve_once()` exactly once per distinct reference, aggregates failures without values, and exposes only `value_for(ref)`. Its explicit `__repr__` lists reference names and prints every value as `***`; serialization/pickling is rejected so plaintext cannot accidentally cross the supervisor IPC boundary.

```python
# src/crypto_collector/config/merge.py
from collections.abc import Mapping
from copy import deepcopy
from typing import Any


def merge_layers(*layers: Mapping[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for layer in layers:
        result = _merge(result, layer)
    return result


def _merge(left: Mapping[str, Any], right: Mapping[str, Any]) -> dict[str, Any]:
    merged = deepcopy(dict(left))
    for key, value in right.items():
        if isinstance(merged.get(key), Mapping) and isinstance(value, Mapping):
            merged[key] = _merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged
```

- [ ] **Step 4: Run config primitive tests**

Run: `.venv/bin/python -m pytest tests/unit/config/test_primitives.py tests/unit/config/test_merge.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/config tests/unit/config
git commit -m "feat: add strict config primitives"
```

### Task 4: Full Configuration Model and Fingerprint

**Files:**
- Create: `src/crypto_collector/config/models.py`
- Create: `src/crypto_collector/config/fingerprint.py`
- Test: `tests/unit/config/test_models.py`
- Test: `tests/unit/config/test_fingerprint.py`

- [ ] **Step 1: Write failing validation tests for critical invariants**

```python
# tests/unit/config/test_models.py
import pytest
from pydantic import ValidationError

from crypto_collector.config.models import (
    CollectorConfig,
    ConfigSecretError,
    iter_secret_refs,
    validate_secret_snapshot,
)
from crypto_collector.config.primitives import SecretSnapshot


BASE = {
    "data_root": "./data",
    "state_root": "./state",
    "writer": {
        "flush_interval": "500ms",
        "durability_slo": "1s",
        "durability_critical": "5s",
        "max_sync_concurrency": 8,
        "rotate_interval": "1h",
        "max_compressed_size": "1GiB",
    },
    "selection": {"quote_assets": ["USDT"], "fixed_pairs": ["BTC/USDT"], "top_n": 20},
    "ingress": {
        "shard_max_records": 10_000,
        "shard_max_bytes": "64MiB",
        "worker_max_bytes": "512MiB",
        "high_water_ratio": 0.80,
        "control_reserve_records": 1_024,
        "control_reserve_bytes": "8MiB",
    },
    "network": {
        "egress_pool": [
            {"id": "direct", "type": "direct", "quota_group": "direct"},
            {"id": "socks", "type": "socks5h", "quota_group": "proxy-nat",
             "url": "env:SOCKS_URL"},
        ]
    },
}


def test_flush_interval_must_leave_half_the_slo_as_budget() -> None:
    invalid = BASE | {"writer": BASE["writer"] | {"flush_interval": "750ms"}}
    with pytest.raises(ValidationError, match="flush_interval"):
        CollectorConfig.model_validate(invalid)


def test_unknown_key_is_rejected() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        CollectorConfig.model_validate(BASE | {"typo_key": True})


def test_scalar_types_are_not_coerced() -> None:
    invalid = BASE | {"selection": BASE["selection"] | {"top_n": "20"}}
    with pytest.raises(ValidationError, match="int_type"):
        CollectorConfig.model_validate(invalid)


def test_runtime_safety_defaults_are_explicit() -> None:
    config = CollectorConfig.model_validate(BASE)
    runtime = config.runtime
    assert runtime.admin_timeout_ns == 10_000_000_000
    assert runtime.reload_prepare_timeout_ns == 15_000_000_000
    assert runtime.shutdown_deadline_ns == 30_000_000_000
    assert runtime.worker_restart.max_attempts == 10
    assert config.network.retry.rest_max_attempts == 5
    assert config.network.scheduler.deep_snapshot_max_interval_ns == 900_000_000_000


def test_materializer_intervals_fit_hourly_revision_partitions() -> None:
    invalid = BASE | {"materializer": {"intervals": ["7m"]}}
    with pytest.raises(ValidationError, match="UTC hour"):
        CollectorConfig.model_validate(invalid)


def test_socks_type_must_match_resolved_url_scheme(monkeypatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5://127.0.0.1:1080")
    config = CollectorConfig.model_validate(BASE)
    secrets = SecretSnapshot.resolve_all(iter_secret_refs(config))
    with pytest.raises(ConfigSecretError, match="socks5h"):
        validate_secret_snapshot(config, secrets)
```

```python
# tests/unit/config/test_fingerprint.py
from crypto_collector.config.fingerprint import config_sha256
from crypto_collector.config.models import CollectorConfig
from tests.unit.config.test_models import BASE


def test_fingerprint_is_canonical_and_secret_value_independent(monkeypatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:first@127.0.0.1:1080")
    config = CollectorConfig.model_validate(BASE)
    first = config_sha256(config, capability_registry_sha256="c" * 64)
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:second@127.0.0.1:1080")
    assert config_sha256(config, capability_registry_sha256="c" * 64) == first
    assert config_sha256(config, capability_registry_sha256="d" * 64) != first
```

- [ ] **Step 2: Run and verify the model is absent**

Run: `.venv/bin/python -m pytest tests/unit/config/test_models.py tests/unit/config/test_fingerprint.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement frozen, extra-forbid models**

Create `StrictModel` with `ConfigDict(extra="forbid", frozen=True, strict=True)`. Define typed models for runtime/restart, network retry/scheduler, capability/date-gate policy, selection, books, writer, disk, egress, materializer, archive targets, cleanup, exchange/market/symbol overrides, and root configuration. Runtime defaults are admin timeout 10s, reload prepare timeout 15s, shutdown deadline 30s, and worker full-jitter restart policy 1s base/60s cap/10 attempts per 10m/10m healthy reset. Network defaults are five REST attempts, 250ms/30s REST backoff, 60s WS reconnect cap, 15m deep maximum, 20% recovery step, and three healthy refreshes. Date-gated features default optional and expose explicit `required: bool`. Convert duration and byte-size strings to integer nanoseconds/bytes before validation. Root validation must enforce:

```python
if writer.flush_interval_ns * 2 > writer.durability_slo_ns:
    raise ValueError("writer.flush_interval must be <= durability_slo / 2")
if not 0 < disk.critical_free_ratio < disk.warning_free_ratio < disk.recovery_free_ratio < 1:
    raise ValueError("disk thresholds must satisfy critical < warning < recovery")
if len({egress.id for egress in network.egress_pool}) != len(network.egress_pool):
    raise ValueError("egress IDs must be unique")
if ingress.worker_max_bytes < ingress.shard_max_bytes:
    raise ValueError("worker ingress bytes must cover at least one shard")
if ingress.control_reserve_bytes >= ingress.worker_max_bytes:
    raise ValueError("control reserve must be smaller than worker ingress limit")
if len(set(materializer.intervals_ns)) != len(materializer.intervals_ns) or any(
    interval < seconds(30) or interval > hours(1) or hours(1) % interval
    for interval in materializer.intervals_ns
):
    raise ValueError("materializer intervals must be unique 30s..1h divisors of one UTC hour")
```

Canonicalize valid materializer intervals into an ascending tuple before fingerprinting and reporting so user ordering does not create a different semantic configuration.

Direct egresses reject a URL. SOCKS egresses require one `SecretRef`; after resolving it, validation requires the URL scheme to match the configured `socks5` or `socks5h` type exactly. Never infer or rewrite the type from a secret value.

Canonicalize with sorted-key Decimal-aware JSON over `model_dump(mode="python")`, replacing every `SecretRef` by its `env:NAME` or `file:/absolute/path` reference. `config_sha256(config, *, capability_registry_sha256: str)` takes the registry digest explicitly, includes it with normalized durations/bytes/paths, and returns `hashlib.sha256(bytes).hexdigest()`. Task 4 tests it with a fixture digest; Task 5 is the first code allowed to load the packaged registry and pass its real digest. Resolve filesystem paths without creating them and reject an archive filesystem root equal to or nested inside `data_root`.

- [ ] **Step 4: Run model and fingerprint tests**

Run: `.venv/bin/python -m pytest tests/unit/config -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/crypto_collector/config tests/unit/config
git commit -m "feat: validate collector configuration"
```

### Task 5: Layered Loader and Immutable Capability Registry

**Files:**
- Create: `src/crypto_collector/config/loader.py`
- Create: `src/crypto_collector/config/yaml.py`
- Create: `src/crypto_collector/capabilities/models.py`
- Create: `src/crypto_collector/capabilities/registry.py`
- Create: `src/crypto_collector/capabilities/data/binance.yaml`
- Create: `src/crypto_collector/capabilities/data/okx.yaml`
- Create: `src/crypto_collector/capabilities/data/bybit.yaml`
- Create: `src/crypto_collector/capabilities/data/bitget.yaml`
- Create: `src/crypto_collector/capabilities/data/kraken.yaml`
- Create: `config.yaml`
- Create: `config/network.yaml`
- Create: `config/examples/network-with-socks.yaml`
- Create: `config/profiles/research-default.yaml`
- Create: `config/profiles/low-bandwidth.yaml`
- Create: `config/exchanges/binance.yaml`
- Create: `config/exchanges/okx.yaml`
- Create: `config/exchanges/bybit.yaml`
- Create: `config/exchanges/bitget.yaml`
- Create: `config/exchanges/kraken.yaml`
- Test: `tests/unit/config/test_loader.py`
- Test: `tests/unit/capabilities/test_registry.py`

- [ ] **Step 1: Write failing precedence and capability tests**

```python
def test_loader_applies_documented_precedence(tmp_path) -> None:
    write_config_tree(tmp_path, root_top_n=20, profile_top_n=10, exchange_top_n=5, market_top_n=2)
    loaded = load_config(tmp_path / "config.yaml")
    assert loaded.config.exchanges["binance"].markets["spot"].selection.top_n == 2


def test_unsupported_okx_anonymous_depth_is_rejected() -> None:
    registry = CapabilityRegistry.load_builtin()
    with pytest.raises(CapabilityError, match="supported live depths"):
        registry.validate_book("okx", "spot", channel="books", depth=500)


def test_duplicate_yaml_key_is_rejected(tmp_path) -> None:
    path = tmp_path / "config.yaml"
    path.write_text("data_root: ./first\ndata_root: ./second\n", encoding="utf-8")
    with pytest.raises(ConfigSyntaxError, match="duplicate"):
        load_config(path)


def test_yaml_merge_key_is_rejected(tmp_path) -> None:
    merge_key = tmp_path / "merge.yaml"
    merge_key.write_text("base: &base {top_n: 20}\nselection: {<<: *base}\n", encoding="utf-8")
    with pytest.raises(ConfigSyntaxError, match="merge key"):
        load_yaml_mapping(merge_key)


def test_multiple_yaml_documents_are_rejected(tmp_path) -> None:
    multiple = tmp_path / "multiple.yaml"
    multiple.write_text("data_root: ./data\n---\nstate_root: ./state\n", encoding="utf-8")
    with pytest.raises(ConfigSyntaxError, match="multiple documents|single document"):
        load_yaml_mapping(multiple)


def test_loader_resolves_every_secret_reference_and_rejects_missing(monkeypatch, config_tree) -> None:
    point_proxy_at(config_tree, "env:SOCKS_URL")
    monkeypatch.delenv("SOCKS_URL", raising=False)
    with pytest.raises(ConfigSecretError, match="SOCKS_URL"):
        load_resolved_config(config_tree / "config.yaml")


def test_loader_rejects_unsafe_file_secret(config_tree, tmp_path) -> None:
    secret = tmp_path / "proxy-url"
    secret.write_text("socks5h://127.0.0.1:1080", encoding="utf-8")
    secret.chmod(0o622)
    point_proxy_at(config_tree, f"file:{secret}")
    with pytest.raises(ConfigSecretError, match="permissions"):
        load_resolved_config(config_tree / "config.yaml")


def test_loader_reads_network_fragment_as_root_network_subtree(config_tree) -> None:
    loaded = load_config(config_tree / "config.yaml")
    assert loaded.config.network.egress_pool[0].id == "direct"


def test_root_network_key_conflicts_with_named_fragment(config_tree) -> None:
    add_root_network_key(config_tree / "config.yaml")
    with pytest.raises(ConfigSyntaxError, match="network.yaml"):
        load_config(config_tree / "config.yaml")


def test_capability_digest_participates_in_config_fingerprint(config_tree) -> None:
    loaded = load_config(config_tree / "config.yaml")
    assert loaded.config_sha256 == config_sha256(
        loaded.config,
        capability_registry_sha256=loaded.capabilities.sha256,
    )


def test_capability_digest_uses_validated_content_not_yaml_formatting(tmp_path) -> None:
    first = CapabilityRegistry.from_directory(copy_capabilities(tmp_path, formatting="block"))
    second = CapabilityRegistry.from_directory(copy_capabilities(tmp_path, formatting="flow"))
    assert first.records == second.records
    assert first.sha256 == second.sha256
```

- [ ] **Step 2: Run and confirm missing loader/registry errors**

Run: `.venv/bin/python -m pytest tests/unit/config/test_loader.py tests/unit/capabilities/test_registry.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement the loader and five capability records**

The loader uses `ruamel.yaml.YAML(typ="safe", pure=True)` with `allow_duplicate_keys = False`. It rejects unsafe tags, YAML merge keys, multiple documents, and non-mapping roots before Pydantic validation. `config/network.yaml` exclusively owns the root `network` subtree; if that file exists, a `network` key in `config.yaml` is an error instead of an undocumented winner. It then merges this exact order:

```python
merged = merge_layers(
    builtin_defaults,
    merge_layers(root_document, {"network": network_document}),
    selected_profile_document,
    exchange_document,
    market_override,
    symbol_override,
)
```

Load the packaged capability registry before computing the fingerprint. Freeze these exact APIs: `load_config(path) -> ConfigBundle(config, capabilities, config_sha256)` performs syntax/layer/model/capability validation without reading secret values; `resolve_bundle(bundle) -> ResolvedConfigBundle(bundle, secrets)` resolves and validates one process-local snapshot; `load_resolved_config(path)` composes those two for CLI callers. Missing env variables, file `lstat`/read/UTF-8 errors, non-regular files, files above 64KiB, unsafe permissions, and proxy scheme/type mismatches become aggregate `ConfigSecretError` issues. Neither resolved values nor value-derived hashes enter `CollectorConfig`, reports, exceptions, IPC, or the config fingerprint.

`config check` calls `load_resolved_config`, reports only `resolved.bundle`, and then discards the snapshot. `config probe` resolves once and passes that same snapshot to every client factory. For `run`/reload, the supervisor calls `load_config` and sends only the validated reference-bearing `ConfigBundle`; each exchange worker calls `resolve_bundle` once during prepare, validates schemes against those exact values, constructs every client from that same snapshot, and only then ACKs. Reload always creates a fresh worker-local snapshot even when the semantic config SHA is unchanged; the old snapshot survives only until old clients close. This prevents a second environment/file read from selecting a value different from the one validated and prevents plaintext secret bytes from crossing process boundaries.

Each built-in capability record must include public REST/WS base URLs, Spot/perpetual support, recommended live book channel/depth/frequency, maximum deep REST depth, bootstrap kind (`none`, `rest_snapshot`), anonymous-only flag, documented connection/subscription limits, and date-gated features. Encode the approved defaults: Binance diff + 5000/1000 deep; OKX books 400 + 5000 deep; Bybit standard 200 + 1000 deep; Bitget books + symbol `maxDepth` and 1000 deep; Kraken Spot 100/Futures full + 500/1000/Futures full REST. For Kraken Spot, `max_rest_depth: 500` is the ordinary `/public/Depth` contract; preserve `GroupedBook` depth 1000 as a separate aggregated REST-book variant and never treat it as an interchangeable bootstrap snapshot.

Compute `CapabilityRegistry.sha256` from canonical Decimal-aware JSON of the five validated records sorted by exchange ID, including the registry schema version; filenames, package paths, YAML formatting, and mtimes do not participate. Reject duplicate exchange IDs and unsupported registry schema versions. The config fingerprint consumes this digest exactly once.

The committed runnable `config/network.yaml` enables one direct egress only, so `collector config check config.yaml` succeeds in a fresh environment. Put the fully annotated direct + SOCKS5h/quota-group pattern in `config/examples/network-with-socks.yaml`; copying/enabling that example intentionally makes the referenced secret mandatory. Never ship a fake proxy credential or silently disable an enabled egress with a missing secret.

- [ ] **Step 4: Run the loader and registry tests**

Run: `.venv/bin/python -m pytest tests/unit/config/test_loader.py tests/unit/capabilities/test_registry.py -q`

Expected: PASS.

- [ ] **Step 5: Commit configuration resources**

```bash
git add src/crypto_collector/config src/crypto_collector/capabilities config.yaml config tests/unit/config tests/unit/capabilities
git commit -m "feat: resolve layered capability-aware config"
```

### Task 6: `collector config check`

**Files:**
- Create: `src/crypto_collector/cli.py`
- Create: `src/crypto_collector/config/report.py`
- Test: `tests/cli/test_config_check.py`

- [ ] **Step 1: Write failing CLI tests**

```python
import json

from typer.testing import CliRunner

from crypto_collector.cli import app


def test_config_check_json_is_stable_and_redacted(config_tree, monkeypatch) -> None:
    monkeypatch.setenv("SOCKS_URL", "socks5h://user:password@127.0.0.1:1080")
    result = CliRunner().invoke(app, ["config", "check", str(config_tree), "--json"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert len(body["config_sha256"]) == 64
    assert body["network"]["egress_pool"][1]["url"] == "env:SOCKS_URL"
    assert body["dynamic_selection"]["status"] == "unresolved"
    assert "password" not in result.stdout


def test_config_check_fails_before_network_or_file_creation(invalid_config_tree) -> None:
    result = CliRunner().invoke(app, ["config", "check", str(invalid_config_tree)])
    assert result.exit_code == 2
    assert "unsupported" in result.stdout.lower()
```

- [ ] **Step 2: Run and verify the CLI import fails**

Run: `.venv/bin/python -m pytest tests/cli/test_config_check.py -q`

Expected: FAIL during import.

- [ ] **Step 3: Implement deterministic human and JSON reports**

Create a Typer application with `config check CONFIG_PATH [--json]`. The report must contain the config SHA, redacted reference-only configuration, capability decisions, unresolved live probes and dynamic Top-N/new-listing selection, configured fixed requests labelled `catalog_unresolved`, static capacity estimates, requested intervals, and warnings. Validation errors exit `2`; valid warnings retain exit `0`. Do not instantiate network clients, claim that a canonical pair has resolved to a venue instrument, claim an effective interval from live capacity, or create `data_root` during this command. Plan 03 defines the probe contract; Plans 04-05 wire the explicitly online `config probe` command as venue providers become available.

```python
@config_app.command("check")
def check_config(path: Path, json_output: bool = typer.Option(False, "--json")) -> None:
    try:
        resolved = load_resolved_config(path)
        report = build_config_report(resolved.bundle)
    except (OSError, ValueError, ValidationError, CapabilityError) as error:
        typer.echo(format_validation_error(error))
        raise typer.Exit(2) from error
    typer.echo(report.model_dump_json(indent=2) if json_output else report.to_text())
```

- [ ] **Step 4: Run the CLI tests and invoke the sample config**

Run: `.venv/bin/python -m pytest tests/cli/test_config_check.py -q`

Expected: PASS.

Run: `.venv/bin/collector config check config.yaml --json`

Expected: exit `0`, valid JSON, five exchange entries, and no resolved secret values.

- [ ] **Step 5: Run the foundation suite and commit**

Run: `.venv/bin/python -m pytest -q -m "not live and not performance"`

Expected: all foundation tests pass and the 17 public live smoke cases skip.

```bash
git add src/crypto_collector/cli.py src/crypto_collector/config/report.py tests/cli
git commit -m "feat: add configuration check command"
```
