from __future__ import annotations

import hashlib
import os
import re
import stat
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from crypto_collector.benchmarks.contracts import (
    GateRootProbeV1,
    GateTargetReprobeV1,
    GateTargetV1,
)
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.storage.errors import PublicationConflict
from crypto_collector.storage.raw_writer import (
    NoReplaceCapability,
    fsync_directory,
    open_readonly_nofollow,
    publish_no_replace,
)

GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES: Literal[107374182400] = 107374182400
_MAX_TARGET_DOCUMENT_BYTES = 1024 * 1024
_DEVICE = re.compile(r"(?:0|[1-9][0-9]*):(?:0|[1-9][0-9]*)\Z")
_TARGET_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_MOUNTINFO_ESCAPES = {
    b"011": b"\t",
    b"012": b"\n",
    b"040": b" ",
    b"134": b"\\",
}


@dataclass(frozen=True, slots=True)
class _MountInfoEntry:
    storage_device: str
    filesystem: str
    mount_point: str
    mount_options: tuple[str, ...]


def _is_linux() -> bool:
    return sys.platform.startswith("linux")


def _now_unix_ns() -> int:
    return time.time_ns()


def _read_mountinfo_bytes() -> bytes:
    path = Path("/proc/self/mountinfo")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("/proc/self/mountinfo must be a regular proc file")
        chunks: list[bytes] = []
        total = 0
        while chunk := os.read(fd, 64 * 1024):
            total += len(chunk)
            if total > 16 * 1024 * 1024:
                raise ValueError("mountinfo exceeds its reader bound")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _decode_mountinfo_field(value: bytes) -> str:
    decoded = bytearray()
    index = 0
    while index < len(value):
        if value[index : index + 1] != b"\\":
            decoded.append(value[index])
            index += 1
            continue
        token = value[index + 1 : index + 4]
        replacement = _MOUNTINFO_ESCAPES.get(token)
        if replacement is None:
            raise ValueError("mountinfo contains an unsupported escape")
        decoded.extend(replacement)
        index += 4
    try:
        return decoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("mountinfo fields must be valid UTF-8") from error


def _normalize_absolute_path_text(value: str, *, field_name: str) -> str:
    if type(value) is not str or not value.startswith("/") or "\x00" in value:
        raise ValueError(f"mountinfo {field_name} must be an absolute path")
    if value != "/" and (
        value.endswith("/")
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        raise ValueError(f"mountinfo {field_name} must be normalized")
    return value


def _parse_options(mount_options: bytes, super_options: bytes) -> tuple[str, ...]:
    values: set[str] = set()
    for prefix, source in (("mount:", mount_options), ("super:", super_options)):
        for raw_option in source.split(b","):
            if not raw_option:
                raise ValueError("mountinfo contains an empty mount option")
            option = _decode_mountinfo_field(raw_option)
            if not option or option != option.strip():
                raise ValueError("mountinfo contains an invalid mount option")
            values.add(prefix + option)
    return tuple(sorted(values))


def _parse_mountinfo(source: bytes) -> tuple[_MountInfoEntry, ...]:
    if type(source) is not bytes or not source:
        raise ValueError("mountinfo input must be nonempty bytes")
    entries: list[_MountInfoEntry] = []
    for raw_line in source.splitlines():
        if not raw_line:
            raise ValueError("mountinfo contains an empty line")
        fields = raw_line.split(b" ")
        if any(not field for field in fields):
            raise ValueError("mountinfo contains an empty field")
        if b"-" not in fields:
            raise ValueError("mountinfo line lacks its separator")
        separator = fields.index(b"-")
        if separator < 6 or len(fields) - separator - 1 != 3:
            raise ValueError("mountinfo line has an invalid field count")
        for index in (0, 1):
            if not fields[index].isdigit() or (
                fields[index] != b"0" and fields[index].startswith(b"0")
            ):
                raise ValueError("mountinfo IDs must be canonical integers")
        device = _decode_mountinfo_field(fields[2])
        if _DEVICE.fullmatch(device) is None:
            raise ValueError("mountinfo storage device is not canonical")
        _normalize_absolute_path_text(
            _decode_mountinfo_field(fields[3]),
            field_name="mount root",
        )
        mount_point = _normalize_absolute_path_text(
            _decode_mountinfo_field(fields[4]),
            field_name="mount point",
        )
        filesystem = _decode_mountinfo_field(fields[separator + 1])
        if not filesystem or filesystem != filesystem.strip():
            raise ValueError("mountinfo filesystem is invalid")
        entries.append(
            _MountInfoEntry(
                storage_device=device,
                filesystem=filesystem,
                mount_point=mount_point,
                mount_options=_parse_options(
                    fields[5],
                    fields[separator + 3],
                ),
            )
        )
    if not entries:
        raise ValueError("mountinfo contains no entries")
    return tuple(entries)


def _select_mount(
    entries: tuple[_MountInfoEntry, ...],
    root: str,
) -> _MountInfoEntry:
    normalized = _normalize_absolute_path_text(root, field_name="lookup path")
    candidates = tuple(
        entry
        for entry in entries
        if entry.mount_point == "/"
        or normalized == entry.mount_point
        or normalized.startswith(entry.mount_point + "/")
    )
    if not candidates:
        raise ValueError("mountinfo has no component-boundary match for root")
    maximum_length = max(len(entry.mount_point) for entry in candidates)
    longest = tuple(
        entry for entry in candidates if len(entry.mount_point) == maximum_length
    )
    first = longest[0]
    if any(entry != first for entry in longest[1:]):
        raise ValueError("mountinfo has ambiguous longest matches for root")
    return first


def _validate_real_directory(value: Path, *, field_name: str) -> Path:
    if not isinstance(value, Path):
        raise TypeError(f"{field_name} must be Path")
    if not value.is_absolute() or value == Path(value.anchor):
        raise ValueError(f"{field_name} must be an absolute non-root directory")
    if any(part in {"", ".", ".."} for part in value.parts[1:]):
        raise ValueError(f"{field_name} must be lexically normalized")
    try:
        resolved = value.resolve(strict=True)
    except OSError as error:
        raise ValueError(f"{field_name} must be an existing real directory") from error
    if resolved != value or not value.is_dir():
        raise ValueError(f"{field_name} must be a symlink-free real directory")
    return value


def _validate_target_id(value: str, *, field_name: str) -> str:
    if type(value) is not str or _TARGET_ID.fullmatch(value) is None:
        raise ValueError(f"{field_name} must be a canonical target identifier")
    return value


def _available_bytes(path: Path) -> int:
    result = os.statvfs(path)
    available = result.f_bavail * result.f_frsize
    if type(available) is not int or available < 0:
        raise ValueError("statvfs returned invalid available bytes")
    return available


def _write_all(fd: int, data: bytes) -> None:
    offset = 0
    while offset < len(data):
        written = os.write(fd, data[offset:])
        if written <= 0:
            raise OSError("probe file write made no progress")
        offset += written


def _create_probe_file(path: Path, data: bytes) -> None:
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    fd = os.open(path, flags, 0o600)
    primary_error: BaseException | None = None
    try:
        _write_all(fd, data)
        os.fsync(fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            os.close(fd)
        except BaseException as error:
            if primary_error is None:
                raise
            primary_error.add_note(f"probe file close also failed: {error!r}")


def _probe_publication_capabilities(root: Path) -> None:
    token = uuid.uuid4().hex
    source = root / f".writer-gate-probe-{token}.partial"
    destination = root / f".writer-gate-probe-{token}.published"
    collision = root / f".writer-gate-probe-{token}.collision"
    paths = (source, destination, collision)
    primary_error: BaseException | None = None
    try:
        _create_probe_file(source, b"writer-gate-hardlink-probe-v1\n")
        fsync_directory(root)
        source_fd = open_readonly_nofollow(source)
        try:
            publish_no_replace(
                source,
                destination,
                capability=NoReplaceCapability.HARDLINK,
                expected_source_fd=source_fd,
            )
        finally:
            os.close(source_fd)
        destination_fd = open_readonly_nofollow(destination)
        try:
            if os.read(destination_fd, 64) != b"writer-gate-hardlink-probe-v1\n":
                raise OSError("published probe bytes changed")
        finally:
            os.close(destination_fd)

        _create_probe_file(collision, b"writer-gate-collision-probe-v1\n")
        collision_fd = open_readonly_nofollow(collision)
        try:
            with_publication_conflict = False
            try:
                publish_no_replace(
                    collision,
                    destination,
                    capability=NoReplaceCapability.HARDLINK,
                    expected_source_fd=collision_fd,
                )
            except PublicationConflict:
                with_publication_conflict = True
            if not with_publication_conflict:
                raise OSError("hard-link publication replaced an existing destination")
        finally:
            os.close(collision_fd)
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_errors: list[BaseException] = []
        for path in paths:
            try:
                path.unlink(missing_ok=True)
            except BaseException as error:  # noqa: BLE001 - attempt every cleanup
                cleanup_errors.append(error)
        try:
            fsync_directory(root)
        except BaseException as error:  # noqa: BLE001 - cleanup sync is mandatory
            cleanup_errors.append(error)
        if primary_error is not None:
            if cleanup_errors:
                primary_error.add_note(
                    "target probe cleanup also failed: "
                    + ", ".join(type(error).__name__ for error in cleanup_errors)
                )
        elif cleanup_errors:
            raise cleanup_errors[0]


def _probe_root(
    root: Path,
    mount_entries: tuple[_MountInfoEntry, ...],
) -> GateRootProbeV1:
    selected = _select_mount(mount_entries, root.as_posix())
    metadata = root.stat()
    observed_device = f"{os.major(metadata.st_dev)}:{os.minor(metadata.st_dev)}"
    if observed_device != selected.storage_device:
        raise ValueError("root device does not match its selected mountinfo entry")
    _probe_publication_capabilities(root)
    return GateRootProbeV1(
        root=root.as_posix(),
        storage_device=selected.storage_device,
        filesystem=selected.filesystem,
        mount_point=selected.mount_point,
        mount_options=selected.mount_options,
        minimum_available_bytes=GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES,
        observed_available_bytes=_available_bytes(root),
        no_replace_capability=NoReplaceCapability.HARDLINK,
        same_parent_publication_only=True,
        file_sync_supported=True,
        directory_sync_supported=True,
    )


def _document_sha256(unsigned: dict[str, Any]) -> str:
    return hashlib.sha256(encode_json(unsigned) + b"\n").hexdigest()


def _target_document(
    *,
    target_id: str,
    data_root: GateRootProbeV1,
    state_root: GateRootProbeV1,
    created_at_unix_ns: int,
) -> GateTargetV1:
    unsigned: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "gate_target_v1",
        "target_id": target_id,
        "data_root": data_root.model_dump(mode="json"),
        "state_root": state_root.model_dump(mode="json"),
        "deployment_purpose": "raw-writer-gate-b",
        "created_at_unix_ns": created_at_unix_ns,
    }
    return GateTargetV1(
        target_id=target_id,
        data_root=data_root,
        state_root=state_root,
        created_at_unix_ns=created_at_unix_ns,
        sha256=_document_sha256(unsigned),
    )


def _reprobe_document(
    *,
    declaration: GateTargetV1,
    expected_target_id: str,
    data_root: GateRootProbeV1,
    state_root: GateRootProbeV1,
    probed_at_unix_ns: int,
) -> GateTargetReprobeV1:
    shared_mount = (
        data_root.storage_device == state_root.storage_device
        and data_root.mount_point == state_root.mount_point
    )
    shared_required = (
        data_root.minimum_available_bytes + state_root.minimum_available_bytes
        if shared_mount
        else None
    )
    shared_observed = (
        min(data_root.observed_available_bytes, state_root.observed_available_bytes)
        if shared_mount
        else None
    )
    immutable_fields = (
        "root",
        "storage_device",
        "filesystem",
        "mount_point",
        "mount_options",
        "minimum_available_bytes",
        "no_replace_capability",
        "same_parent_publication_only",
        "file_sync_supported",
        "directory_sync_supported",
    )

    def projection(root: GateRootProbeV1) -> tuple[object, ...]:
        return tuple(getattr(root, field) for field in immutable_fields)

    facts_match = projection(data_root) == projection(
        declaration.data_root
    ) and projection(state_root) == projection(declaration.state_root)
    individual_space_valid = all(
        root.observed_available_bytes >= root.minimum_available_bytes
        for root in (data_root, state_root)
    )
    shared_space_valid = not shared_mount or (
        shared_required is not None
        and shared_observed is not None
        and shared_observed >= shared_required
    )
    available_space_valid = individual_space_valid and shared_space_valid
    target_id_matches = declaration.target_id == expected_target_id
    unsigned: dict[str, Any] = {
        "schema_version": 1,
        "record_type": "gate_target_reprobe_v1",
        "target_id": declaration.target_id,
        "expected_target_id": expected_target_id,
        "declaration_sha256": declaration.sha256,
        "probed_at_unix_ns": probed_at_unix_ns,
        "data_root": data_root.model_dump(mode="json"),
        "state_root": state_root.model_dump(mode="json"),
        "shared_mount": shared_mount,
        "shared_required_available_bytes": shared_required,
        "shared_observed_available_bytes": shared_observed,
        "target_id_matches": target_id_matches,
        "declaration_facts_match": facts_match,
        "available_space_valid": available_space_valid,
        "reprobe_valid": (target_id_matches and facts_match and available_space_valid),
    }
    return GateTargetReprobeV1(
        target_id=declaration.target_id,
        expected_target_id=expected_target_id,
        declaration_sha256=declaration.sha256,
        probed_at_unix_ns=probed_at_unix_ns,
        data_root=data_root,
        state_root=state_root,
        shared_mount=shared_mount,
        shared_required_available_bytes=shared_required,
        shared_observed_available_bytes=shared_observed,
        target_id_matches=target_id_matches,
        declaration_facts_match=facts_match,
        available_space_valid=available_space_valid,
        reprobe_valid=(target_id_matches and facts_match and available_space_valid),
        sha256=_document_sha256(unsigned),
    )


def _publish_document(output: Path, content: bytes) -> None:
    if not isinstance(output, Path):
        raise TypeError("target output must be Path")
    if not output.is_absolute() or output == Path(output.anchor):
        raise ValueError("target output must be an absolute file path")
    parent = _validate_real_directory(output.parent, field_name="target output parent")
    temporary = parent / f".{output.name}.partial.{uuid.uuid4().hex}"
    _create_probe_file(temporary, content)
    fsync_directory(parent)
    source_fd = open_readonly_nofollow(temporary)
    primary_error: BaseException | None = None
    try:
        publish_no_replace(
            temporary,
            output,
            capability=NoReplaceCapability.HARDLINK,
            expected_source_fd=source_fd,
        )
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            os.close(source_fd)
        except BaseException as error:
            if primary_error is None:
                raise
            primary_error.add_note(
                f"target publication fd close also failed: {error!r}"
            )


def load_target_declaration(path: Path) -> GateTargetV1:
    if not isinstance(path, Path):
        raise TypeError("target declaration path must be Path")
    fd = open_readonly_nofollow(path)
    try:
        size = os.fstat(fd).st_size
        if size <= 0 or size > _MAX_TARGET_DOCUMENT_BYTES:
            raise ValueError("target declaration size is outside its bound")
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = os.read(fd, min(remaining, 64 * 1024))
            if not chunk:
                raise ValueError("target declaration ended before its stated size")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise ValueError("target declaration changed while it was read")
    finally:
        os.close(fd)
    source = b"".join(chunks)
    try:
        declaration = GateTargetV1.model_validate_json(source)
    except (ValidationError, ValueError) as error:
        raise ValueError("target declaration structure is invalid") from error
    if source != declaration.canonical_bytes():
        raise ValueError("target declaration bytes are not canonical")
    return declaration


def declare_target(
    *,
    target_id: str,
    data_root: Path,
    state_root: Path,
    output: Path,
) -> GateTargetV1:
    target_id = _validate_target_id(target_id, field_name="target ID")
    if not _is_linux():
        raise OSError("writer Gate B target declaration requires Linux")
    data = _validate_real_directory(data_root, field_name="data root")
    state = _validate_real_directory(state_root, field_name="state root")
    if data == state:
        raise ValueError("data and state roots must be distinct")
    entries = _parse_mountinfo(_read_mountinfo_bytes())
    target = _target_document(
        target_id=target_id,
        data_root=_probe_root(data, entries),
        state_root=_probe_root(state, entries),
        created_at_unix_ns=_now_unix_ns(),
    )
    _publish_document(output, target.canonical_bytes())
    return target


def reprobe_target(
    declaration: GateTargetV1,
    *,
    expected_target_id: str,
) -> GateTargetReprobeV1:
    if type(declaration) is not GateTargetV1:
        raise TypeError("declaration must be GateTargetV1")
    expected_target_id = _validate_target_id(
        expected_target_id,
        field_name="expected target ID",
    )
    if not _is_linux():
        raise OSError("writer Gate B target re-probe requires Linux")
    data = _validate_real_directory(
        Path(declaration.data_root.root),
        field_name="data root",
    )
    state = _validate_real_directory(
        Path(declaration.state_root.root),
        field_name="state root",
    )
    entries = _parse_mountinfo(_read_mountinfo_bytes())
    return _reprobe_document(
        declaration=declaration,
        expected_target_id=expected_target_id,
        data_root=_probe_root(data, entries),
        state_root=_probe_root(state, entries),
        probed_at_unix_ns=_now_unix_ns(),
    )


__all__ = [
    "GATE_B_ROOT_MINIMUM_AVAILABLE_BYTES",
    "declare_target",
    "load_target_declaration",
    "reprobe_target",
]
