from __future__ import annotations

import os
import re
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import NoReturn, SupportsIndex

_DURATION = re.compile(r"^(0|[1-9][0-9]*)(ms|s|m|h|d)$")
_DURATION_SCALE = {
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60_000_000_000,
    "h": 3_600_000_000_000,
    "d": 86_400_000_000_000,
}
_SIZE = re.compile(r"^(0|[1-9][0-9]*)(B|KiB|MiB|GiB)$")
_SIZE_SCALE = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
_MAX_SECRET_BYTES = 65_536


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


def _reject_pickle() -> NoReturn:
    raise TypeError("secret containers cannot be serialized or pickled")


@dataclass(frozen=True, slots=True)
class SecretRef:
    scheme: str
    target: str

    @classmethod
    def parse(cls, value: str) -> SecretRef:
        scheme, separator, target = value.partition(":")
        if separator != ":" or scheme not in {"env", "file"} or not target:
            raise ValueError("secret must use env:NAME or file:/absolute/path")
        if scheme == "file" and not Path(target).is_absolute():
            raise ValueError("file secret path must be absolute")
        return cls(scheme=scheme, target=target)

    def _resolve_once(self) -> str:
        if self.scheme == "env":
            try:
                return os.environ[self.target]
            except KeyError as error:
                raise ValueError(
                    f"missing environment variable: {self.target}"
                ) from error

        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.target, flags)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("file secret must be a regular file")
            if info.st_size > _MAX_SECRET_BYTES:
                raise ValueError("file secret exceeds 64KiB")
            if info.st_mode & 0o022:
                raise ValueError("file secret has unsafe permissions")

            chunks: list[bytes] = []
            remaining = _MAX_SECRET_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_SECRET_BYTES:
                raise ValueError("file secret exceeds 64KiB")
        finally:
            os.close(fd)

        try:
            value = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise ValueError("file secret must contain valid UTF-8") from error
        return value.removesuffix("\n")

    def fingerprint_value(self) -> str:
        return f"{self.scheme}:{self.target}"

    def __repr__(self) -> str:
        return f"SecretRef({self.fingerprint_value()!r})"


class SecretValue:
    __slots__ = ("_plaintext",)

    _plaintext: str

    def __init__(self, plaintext: str) -> None:
        object.__setattr__(self, "_plaintext", plaintext)

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del name, value
        raise AttributeError("SecretValue is immutable")

    def reveal(self) -> str:
        return self._plaintext

    def __repr__(self) -> str:
        return "SecretValue(***)"

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        _reject_pickle()


class SecretSnapshot:
    __slots__ = ("_values",)

    _values: Mapping[SecretRef, SecretValue]

    def __init__(self, values: Mapping[SecretRef, SecretValue]) -> None:
        object.__setattr__(self, "_values", MappingProxyType(dict(values)))

    def __setattr__(self, name: str, value: object) -> NoReturn:
        del name, value
        raise AttributeError("SecretSnapshot is immutable")

    @classmethod
    def resolve_all(cls, refs: Iterable[SecretRef]) -> SecretSnapshot:
        distinct = sorted(set(refs), key=SecretRef.fingerprint_value)
        resolved: dict[SecretRef, SecretValue] = {}
        failures: list[str] = []

        for ref in distinct:
            try:
                resolved[ref] = SecretValue(ref._resolve_once())
            except (OSError, ValueError) as error:
                failures.append(
                    f"{ref.fingerprint_value()}: could not resolve ({error})"
                )

        if failures:
            raise ValueError("failed to resolve secrets: " + "; ".join(failures))
        return cls(resolved)

    def value_for(self, ref: SecretRef) -> SecretValue:
        try:
            return self._values[ref]
        except KeyError as error:
            raise ValueError(
                f"secret was not captured in snapshot: {ref.fingerprint_value()}"
            ) from error

    def __repr__(self) -> str:
        entries = ", ".join(
            f"{ref.fingerprint_value()}=***"
            for ref in sorted(self._values, key=SecretRef.fingerprint_value)
        )
        return f"SecretSnapshot({entries})"

    def __reduce_ex__(self, protocol: SupportsIndex) -> NoReturn:
        del protocol
        _reject_pickle()
