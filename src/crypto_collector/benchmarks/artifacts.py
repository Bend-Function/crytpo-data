from __future__ import annotations

import hashlib
import heapq
import os
import sqlite3
import uuid
from collections.abc import Iterable, Iterator, Sequence
from pathlib import Path
from typing import BinaryIO, Protocol, Self, TypeVar, cast

import zstandard
from pydantic import BaseModel, ValidationError

from crypto_collector.benchmarks.contracts import (
    CANONICAL_EXCHANGES,
    GateAdmissionTraceSetV1,
    GateAdmissionTraceV1,
    GateArtifactRefV1,
    GateExchangeArtifactPartitionV1,
)
from crypto_collector.domain.json_codec import encode_json
from crypto_collector.storage.raw_writer import (
    NoReplaceCapability,
    open_readonly_nofollow,
    publish_no_replace,
    size_and_sha256_fd,
)

RowT = TypeVar("RowT", bound=BaseModel)
_IO_CHUNK_BYTES = 64 * 1024


class _CompressionWriter(Protocol):
    def write(self, data: bytes) -> int: ...

    def close(self) -> None: ...


class _Closeable(Protocol):
    def close(self) -> None: ...


class ArtifactValidationError(ValueError):
    pass


class StreamingJsonlZstdWriter:
    """Incrementally publish one canonical model stream without replacement."""

    def __init__(
        self,
        root: Path,
        relative_path: str,
        *,
        zstd_level: int,
    ) -> None:
        self._root = _validate_root(root)
        self._relative_path = _validate_relative_path(relative_path)
        self._level = _strict_positive_int(zstd_level, field_name="zstd_level")
        if self._level > 22:
            raise ValueError("zstd_level must not exceed 22")
        self._destination = _artifact_path(self._root, self._relative_path)
        self._partial = self._destination.with_name(self._destination.name + ".partial")
        self._parent_fd = _open_or_create_parent_directories(
            self._root,
            self._relative_path,
        )
        self._raw_file: BinaryIO | None = None
        self._writer: _CompressionWriter | None = None
        self._closed = False
        self._content_digest = hashlib.sha256()
        self._content_size = 0
        self._row_count = 0
        self._row_model_type: type[BaseModel] | None = None
        self._artifact_ref: GateArtifactRefV1 | None = None
        fd = -1
        try:
            flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
            for flag_name in ("O_NOFOLLOW", "O_CLOEXEC"):
                flag = getattr(os, flag_name, None)
                if type(flag) is not int or flag == 0:
                    raise OSError(f"required open flag {flag_name} is unavailable")
                flags |= flag
            fd = os.open(
                self._partial.name,
                flags,
                0o640,
                dir_fd=self._parent_fd,
            )
            os.fsync(self._parent_fd)
            self._raw_file = os.fdopen(fd, "wb", buffering=0, closefd=True)
            fd = -1
            compressor = zstandard.ZstdCompressor(
                level=self._level,
                write_checksum=True,
                write_content_size=False,
            )
            self._writer = cast(
                _CompressionWriter,
                compressor.stream_writer(self._raw_file, closefd=False),
            )
        except BaseException:
            if fd >= 0:
                os.close(fd)
            if self._raw_file is not None:
                self._raw_file.close()
            os.close(self._parent_fd)
            self._closed = True
            raise

    def _write_chunk(
        self,
        chunk: bytes,
        model_type: type[BaseModel],
        *,
        row_count: int,
    ) -> None:
        if self._closed or self._writer is None:
            raise RuntimeError("artifact writer is closed")
        if self._row_model_type is None:
            self._row_model_type = model_type
        elif model_type is not self._row_model_type:
            raise TypeError("artifact rows must all use one exact model type")
        written = self._writer.write(chunk)
        if written != len(chunk):
            raise OSError("zstd artifact writer accepted a partial chunk")
        self._content_digest.update(chunk)
        self._content_size += len(chunk)
        self._row_count += row_count

    def _write_line(self, line: bytes, model_type: type[BaseModel]) -> None:
        self._write_chunk(line, model_type, row_count=1)

    def write(self, row: BaseModel) -> None:
        self._write_line(_canonical_row_bytes(row), type(row))

    def write_trusted_line(
        self,
        line: bytes,
        model_type: type[BaseModel],
    ) -> None:
        """Write caller-validated canonical JSONL bytes without re-encoding."""
        _validate_model_type(model_type)
        if type(line) is not bytes or not line.endswith(b"\n") or b"\n" in line[:-1]:
            raise ValueError("trusted artifact line must be one newline-terminated row")
        self._write_line(line, model_type)

    def write_trusted_lines(
        self,
        chunk: bytes,
        model_type: type[BaseModel],
        *,
        row_count: int,
    ) -> None:
        """Write caller-validated canonical JSONL rows as one bounded chunk."""
        _validate_model_type(model_type)
        count = _strict_positive_int(row_count, field_name="row_count")
        if (
            type(chunk) is not bytes
            or not chunk.endswith(b"\n")
            or chunk.startswith(b"\n")
            or b"\n\n" in chunk
            or chunk.count(b"\n") != count
        ):
            raise ValueError("trusted artifact chunk must match its declared row count")
        self._write_chunk(chunk, model_type, row_count=count)

    def abort(self, primary_error: BaseException | None = None) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            _close_partial_writer(self._writer, self._raw_file, primary_error)
        finally:
            self._writer = None
            self._raw_file = None
            os.close(self._parent_fd)

    def close(self) -> GateArtifactRefV1:
        if self._closed:
            raise RuntimeError("artifact writer is closed")
        self.abort()
        verification_fd = open_readonly_nofollow(self._partial)
        publication_error: BaseException | None = None
        try:
            compressed_size, compressed_sha256 = size_and_sha256_fd(verification_fd)
            publish_no_replace(
                self._partial,
                self._destination,
                capability=NoReplaceCapability.HARDLINK,
                expected_source_fd=verification_fd,
            )
        except BaseException as error:
            publication_error = error
            raise
        finally:
            _close_fd_after(
                verification_fd,
                publication_error,
                description="artifact publication verification",
            )
        self._artifact_ref = GateArtifactRefV1(
            relative_path=self._relative_path,
            row_count=self._row_count,
            content_size_bytes=self._content_size,
            content_sha256=self._content_digest.hexdigest(),
            compressed_size_bytes=compressed_size,
            compressed_sha256=compressed_sha256,
        )
        return self._artifact_ref

    @property
    def artifact_ref(self) -> GateArtifactRefV1:
        if self._artifact_ref is None:
            raise RuntimeError("artifact has not been published")
        return self._artifact_ref

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        error_type: type[BaseException] | None,
        error: BaseException | None,
        traceback: object,
    ) -> None:
        del error_type, traceback
        if error is not None:
            self.abort(error)
        else:
            self.close()


def _strict_positive_int(value: int, *, field_name: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _validate_root(root: Path) -> Path:
    if not isinstance(root, Path):
        raise TypeError("artifact root must be Path")
    if not root.is_absolute() or root == Path(root.anchor):
        raise ValueError("artifact root must be a normalized absolute directory")
    try:
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise ValueError("artifact root must exist") from error
    if resolved != root or not root.is_dir():
        raise ValueError("artifact root must be a normalized non-symlink directory")
    return root


def _validate_relative_path(relative_path: str) -> str:
    if type(relative_path) is not str:
        raise TypeError("artifact relative path must be str")
    if (
        not relative_path
        or "\x00" in relative_path
        or "\\" in relative_path
        or relative_path.startswith("/")
        or any(part in {"", ".", ".."} for part in relative_path.split("/"))
    ):
        raise ValueError("artifact path must be normalized POSIX relative")
    if not relative_path.endswith(".jsonl.zst"):
        raise ValueError("artifact path must end with .jsonl.zst")
    return relative_path


def _artifact_path(root: Path, relative_path: str) -> Path:
    candidate = root.joinpath(*relative_path.split("/"))
    if not candidate.is_relative_to(root):
        raise ValueError("artifact path escaped its root")
    return candidate


def _directory_flags() -> int:
    flags = os.O_RDONLY
    for flag_name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC"):
        flag = getattr(os, flag_name, None)
        if type(flag) is not int or flag == 0:
            raise OSError(f"required open flag {flag_name} is unavailable")
        flags |= flag
    return flags


def _open_or_create_parent_directories(root: Path, relative_path: str) -> int:
    parts = relative_path.split("/")[:-1]
    current_fd = os.open(root, _directory_flags())
    try:
        for part in parts:
            try:
                os.mkdir(part, 0o750, dir_fd=current_fd)
                os.fsync(current_fd)
            except FileExistsError:
                pass
            try:
                child_fd = os.open(part, _directory_flags(), dir_fd=current_fd)
            except OSError as error:
                raise ValueError(
                    "artifact parent path must contain only real directories"
                ) from error
            os.close(current_fd)
            current_fd = child_fd
        return current_fd
    except BaseException:
        os.close(current_fd)
        raise


def _validate_model_type(model_type: type[BaseModel]) -> None:
    if not isinstance(model_type, type) or not issubclass(model_type, BaseModel):
        raise TypeError("artifact model type must be a Pydantic model class")
    config = model_type.model_config
    if not (
        config.get("frozen") is True
        and config.get("strict") is True
        and config.get("extra") == "forbid"
    ):
        raise TypeError("artifact model type must be frozen, strict, and extra-forbid")


def _canonical_row_bytes(row: BaseModel) -> bytes:
    _validate_model_type(type(row))
    canonical_method = getattr(row, "canonical_bytes", None)
    if not callable(canonical_method):
        raise TypeError("artifact rows must expose canonical_bytes()")
    encoded = canonical_method()
    expected = encode_json(row.model_dump(mode="json")) + b"\n"
    if type(encoded) is not bytes or encoded != expected:
        raise TypeError("artifact row canonical bytes do not match its model fields")
    return encoded


def _close_fd_after(
    fd: int, primary_error: BaseException | None, *, description: str
) -> None:
    try:
        os.close(fd)
    except BaseException as error:
        if primary_error is None:
            raise
        primary_error.add_note(f"{description} fd close also failed: {error!r}")


def _close_resources_after(
    resources: tuple[_Closeable, ...], primary_error: BaseException | None
) -> None:
    close_errors: list[BaseException] = []
    for resource in resources:
        try:
            resource.close()
        except BaseException as error:  # noqa: BLE001 - close every resource
            close_errors.append(error)
    if primary_error is not None:
        if close_errors:
            primary_error.add_note(
                "artifact reader cleanup also failed: "
                + ", ".join(type(error).__name__ for error in close_errors)
            )
        return
    if close_errors:
        raise close_errors[0]


def _close_partial_writer(
    writer: _CompressionWriter | None,
    raw_file: BinaryIO | None,
    primary_error: BaseException | None,
) -> None:
    cleanup_errors: list[BaseException] = []
    if writer is not None:
        try:
            writer.close()
        except BaseException as error:  # noqa: BLE001 - preserve all partial evidence
            cleanup_errors.append(error)
    if raw_file is not None:
        try:
            raw_file.flush()
            os.fsync(raw_file.fileno())
        except BaseException as error:  # noqa: BLE001 - preserve the primary failure
            cleanup_errors.append(error)
        try:
            raw_file.close()
        except BaseException as error:  # noqa: BLE001 - retain the partial path
            cleanup_errors.append(error)
    if primary_error is not None:
        if cleanup_errors:
            primary_error.add_note(
                "partial artifact cleanup also failed: "
                + ", ".join(type(error).__name__ for error in cleanup_errors)
            )
        return
    if cleanup_errors:
        raise cleanup_errors[0]


def write_jsonl_zstd(
    root: Path,
    relative_path: str,
    rows: Iterable[RowT],
    *,
    zstd_level: int,
) -> GateArtifactRefV1:
    artifact_root = _validate_root(root)
    normalized_path = _validate_relative_path(relative_path)
    level = _strict_positive_int(zstd_level, field_name="zstd_level")
    if level > 22:
        raise ValueError("zstd_level must not exceed 22")
    try:
        iterator = iter(rows)
    except TypeError as error:
        raise TypeError("artifact rows must be iterable") from error

    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    for flag_name in ("O_NOFOLLOW", "O_CLOEXEC"):
        flag = getattr(os, flag_name, None)
        if type(flag) is not int or flag == 0:
            raise OSError(f"required open flag {flag_name} is unavailable")
        flags |= flag
    destination = _artifact_path(artifact_root, normalized_path)
    parent_fd = _open_or_create_parent_directories(artifact_root, normalized_path)
    partial = destination.with_name(destination.name + ".partial")
    fd = -1
    try:
        fd = os.open(partial.name, flags, 0o640, dir_fd=parent_fd)
        # The temporary name is durable even when row generation fails.
        os.fsync(parent_fd)
    except BaseException:
        if fd >= 0:
            os.close(fd)
        os.close(parent_fd)
        raise

    content_digest = hashlib.sha256()
    content_size = 0
    row_count = 0
    row_model_type: type[BaseModel] | None = None
    raw_file: BinaryIO | None = None
    writer: _CompressionWriter | None = None
    primary_error: BaseException | None = None
    try:
        raw_file = os.fdopen(fd, "wb", buffering=0, closefd=True)
        fd = -1
        compressor = zstandard.ZstdCompressor(
            level=level,
            write_checksum=True,
            write_content_size=False,
        )
        writer = cast(
            _CompressionWriter,
            compressor.stream_writer(raw_file, closefd=False),
        )
        for row in iterator:
            if row_model_type is None:
                row_model_type = type(row)
            elif type(row) is not row_model_type:
                raise TypeError("artifact rows must all use one exact model type")
            line = _canonical_row_bytes(row)
            written = writer.write(line)
            if written != len(line):
                raise OSError("zstd artifact writer accepted a partial row")
            content_digest.update(line)
            content_size += len(line)
            row_count += 1
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            if fd >= 0:
                try:
                    os.close(fd)
                except BaseException as error:
                    if primary_error is None:
                        raise
                    primary_error.add_note(
                        f"partial artifact fd close failed: {error!r}"
                    )
            _close_partial_writer(writer, raw_file, primary_error)
        finally:
            os.close(parent_fd)

    verification_fd = open_readonly_nofollow(partial)
    publication_error: BaseException | None = None
    try:
        compressed_size, compressed_sha256 = size_and_sha256_fd(verification_fd)
        publish_no_replace(
            partial,
            destination,
            capability=NoReplaceCapability.HARDLINK,
            expected_source_fd=verification_fd,
        )
    except BaseException as error:
        publication_error = error
        raise
    finally:
        _close_fd_after(
            verification_fd,
            publication_error,
            description="artifact publication verification",
        )

    return GateArtifactRefV1(
        relative_path=normalized_path,
        row_count=row_count,
        content_size_bytes=content_size,
        content_sha256=content_digest.hexdigest(),
        compressed_size_bytes=compressed_size,
        compressed_sha256=compressed_sha256,
    )


def _iter_zstd_plain_chunks(fd: int, compressed_size: int) -> Iterator[bytes]:
    if os.fstat(fd).st_size != compressed_size:
        raise ArtifactValidationError(
            "compressed artifact size changed before decoding"
        )
    source = os.fdopen(os.dup(fd), "rb", closefd=True)
    reader = zstandard.ZstdDecompressor().stream_reader(
        source,
        read_across_frames=True,
        closefd=False,
    )
    primary_error: BaseException | None = None
    try:
        while True:
            chunk = reader.read(_IO_CHUNK_BYTES)
            if not chunk:
                break
            yield chunk
    except (OSError, zstandard.ZstdError) as error:
        validation_error = ArtifactValidationError(
            "artifact contains malformed or trailing zstd bytes"
        )
        primary_error = validation_error
        raise validation_error from error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _close_resources_after((reader, source), primary_error)


def _validate_reader_bound(value: int, *, field_name: str) -> int:
    return _strict_positive_int(value, field_name=field_name)


def iter_jsonl_zstd(
    root: Path,
    artifact: GateArtifactRefV1,
    model_type: type[RowT],
    *,
    max_rows: int,
    max_content_bytes: int,
    max_line_bytes: int,
) -> Iterator[RowT]:
    artifact_root = _validate_root(root)
    if type(artifact) is not GateArtifactRefV1:
        raise TypeError("artifact must be GateArtifactRefV1")
    _validate_model_type(model_type)
    row_limit = _validate_reader_bound(max_rows, field_name="max_rows")
    content_limit = _validate_reader_bound(
        max_content_bytes, field_name="max_content_bytes"
    )
    line_limit = _validate_reader_bound(max_line_bytes, field_name="max_line_bytes")
    source_path = _artifact_path(artifact_root, artifact.relative_path)
    fd = open_readonly_nofollow(source_path)
    primary_error: BaseException | None = None
    try:
        compressed_size, compressed_sha256 = size_and_sha256_fd(fd)
        if compressed_size != artifact.compressed_size_bytes:
            raise ArtifactValidationError(
                "artifact compressed size does not match its ref"
            )
        if compressed_sha256 != artifact.compressed_sha256:
            raise ArtifactValidationError(
                "artifact compressed SHA does not match its ref"
            )
        if artifact.row_count > row_limit:
            raise ArtifactValidationError("artifact exceeds the caller row bound")
        if artifact.content_size_bytes > content_limit:
            raise ArtifactValidationError(
                "artifact exceeds the caller content byte bound"
            )

        content_digest = hashlib.sha256()
        content_size = 0
        row_count = 0
        pending = bytearray()
        for chunk in _iter_zstd_plain_chunks(fd, compressed_size):
            content_size += len(chunk)
            if content_size > content_limit:
                raise ArtifactValidationError(
                    "artifact exceeds the caller content byte bound"
                )
            content_digest.update(chunk)
            pending.extend(chunk)
            while True:
                newline_index = pending.find(b"\n")
                if newline_index < 0:
                    break
                line_size = newline_index + 1
                if line_size > line_limit:
                    raise ArtifactValidationError(
                        "artifact exceeds the caller line byte bound"
                    )
                line = bytes(pending[:line_size])
                del pending[:line_size]
                row_count += 1
                if row_count > row_limit:
                    raise ArtifactValidationError(
                        "artifact exceeds the caller row bound"
                    )
                try:
                    row = model_type.model_validate_json(line[:-1], strict=True)
                except (TypeError, ValueError, ValidationError) as error:
                    raise ArtifactValidationError(
                        "artifact row does not match its model"
                    ) from error
                if _canonical_row_bytes(row) != line:
                    raise ArtifactValidationError("artifact row is not canonical JSONL")
                yield row
            if len(pending) > line_limit:
                raise ArtifactValidationError(
                    "artifact exceeds the caller line byte bound"
                )
        if pending:
            raise ArtifactValidationError("artifact is missing its final newline")
        if row_count != artifact.row_count:
            raise ArtifactValidationError("artifact row count does not match its ref")
        if content_size != artifact.content_size_bytes:
            raise ArtifactValidationError(
                "artifact content size does not match its ref"
            )
        if content_digest.hexdigest() != artifact.content_sha256:
            raise ArtifactValidationError("artifact content SHA does not match its ref")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        _close_fd_after(fd, primary_error, description="artifact reader")


def _validated_partitions(
    partitions: Sequence[GateExchangeArtifactPartitionV1],
) -> tuple[GateExchangeArtifactPartitionV1, ...]:
    if isinstance(partitions, (str, bytes)) or not isinstance(partitions, Sequence):
        raise TypeError("trace partitions must be a sequence")
    frozen = tuple(partitions)
    if any(
        type(partition) is not GateExchangeArtifactPartitionV1 for partition in frozen
    ):
        raise TypeError("trace partitions must contain partition models")
    if tuple(partition.exchange for partition in frozen) != CANONICAL_EXCHANGES:
        raise ValueError("trace partitions must use all exchanges in canonical order")
    paths = tuple(partition.artifact.relative_path for partition in frozen)
    if len(paths) != len(set(paths)):
        raise ValueError("trace partition artifact paths must be unique")
    return frozen


def _iter_partition_rows(
    root: Path,
    partition: GateExchangeArtifactPartitionV1,
    *,
    max_rows: int,
    max_content_bytes: int,
    max_line_bytes: int,
) -> Iterator[GateAdmissionTraceV1]:
    prior_key: tuple[int, str] | None = None
    for row in iter_jsonl_zstd(
        root,
        partition.artifact,
        GateAdmissionTraceV1,
        max_rows=max_rows,
        max_content_bytes=max_content_bytes,
        max_line_bytes=max_line_bytes,
    ):
        if row.exchange is not partition.exchange:
            raise ArtifactValidationError(
                "trace row does not match its partition exchange"
            )
        key = (row.due_monotonic_ns, row.planned_event_id)
        if prior_key is not None and key <= prior_key:
            raise ArtifactValidationError("trace partition is not internally sorted")
        prior_key = key
        yield row


def _collision_database(root: Path) -> tuple[sqlite3.Connection, Path]:
    path = root / f".gate-trace-merge-{uuid.uuid4().hex}.sqlite.partial"
    connection = sqlite3.connect(path)
    try:
        connection.execute("PRAGMA journal_mode=OFF")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("PRAGMA cache_size=-8192")
        connection.execute(
            "CREATE TABLE seen (planned_event_id TEXT PRIMARY KEY) WITHOUT ROWID"
        )
        connection.execute("BEGIN")
    except BaseException:
        connection.close()
        path.unlink(missing_ok=True)
        raise
    return connection, path


def iter_merged_trace_partitions(
    root: Path,
    partitions: Sequence[GateExchangeArtifactPartitionV1],
    *,
    max_rows: int,
    max_content_bytes: int,
    max_line_bytes: int,
) -> Iterator[GateAdmissionTraceV1]:
    artifact_root = _validate_root(root)
    frozen = _validated_partitions(partitions)
    row_limit = _validate_reader_bound(max_rows, field_name="max_rows")
    content_limit = _validate_reader_bound(
        max_content_bytes, field_name="max_content_bytes"
    )
    line_limit = _validate_reader_bound(max_line_bytes, field_name="max_line_bytes")
    if sum(partition.artifact.row_count for partition in frozen) > row_limit:
        raise ArtifactValidationError("merged trace exceeds the caller row bound")
    if (
        sum(partition.artifact.content_size_bytes for partition in frozen)
        > content_limit
    ):
        raise ArtifactValidationError(
            "merged trace exceeds the caller content byte bound"
        )

    readers = tuple(
        _iter_partition_rows(
            artifact_root,
            partition,
            max_rows=row_limit,
            max_content_bytes=content_limit,
            max_line_bytes=line_limit,
        )
        for partition in frozen
    )
    connection, scratch_path = _collision_database(artifact_root)
    row_count = 0
    content_size = 0
    primary_error: BaseException | None = None
    try:
        for row in heapq.merge(
            *readers,
            key=lambda item: (item.due_monotonic_ns, item.planned_event_id),
        ):
            try:
                connection.execute(
                    "INSERT INTO seen (planned_event_id) VALUES (?)",
                    (row.planned_event_id,),
                )
            except sqlite3.IntegrityError as error:
                raise ArtifactValidationError("planned event ID collision") from error
            row_count += 1
            content_size += len(_canonical_row_bytes(row))
            if row_count > row_limit:
                raise ArtifactValidationError(
                    "merged trace exceeds the caller row bound"
                )
            if content_size > content_limit:
                raise ArtifactValidationError(
                    "merged trace exceeds the caller content byte bound"
                )
            yield row
        expected_rows = sum(partition.artifact.row_count for partition in frozen)
        expected_bytes = sum(
            partition.artifact.content_size_bytes for partition in frozen
        )
        if row_count != expected_rows or content_size != expected_bytes:
            raise ArtifactValidationError(
                "merged trace facts disagree with its partitions"
            )
        connection.commit()
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            connection.close()
        except BaseException as error:
            if primary_error is None:
                raise
            primary_error.add_note(f"collision database close also failed: {error!r}")
        for candidate in (scratch_path, Path(f"{scratch_path}-journal")):
            try:
                candidate.unlink(missing_ok=True)
            except OSError as error:
                if primary_error is None:
                    raise
                primary_error.add_note(
                    f"collision scratch cleanup also failed: {error!r}"
                )


def build_admission_trace_set(
    root: Path,
    partitions: Sequence[GateExchangeArtifactPartitionV1],
    *,
    max_rows: int,
    max_content_bytes: int,
    max_line_bytes: int,
) -> GateAdmissionTraceSetV1:
    frozen = _validated_partitions(partitions)
    digest = hashlib.sha256()
    row_count = 0
    content_size = 0
    for row in iter_merged_trace_partitions(
        root,
        frozen,
        max_rows=max_rows,
        max_content_bytes=max_content_bytes,
        max_line_bytes=max_line_bytes,
    ):
        line = _canonical_row_bytes(row)
        digest.update(line)
        row_count += 1
        content_size += len(line)
    return GateAdmissionTraceSetV1(
        partitions=frozen,
        merged_row_count=row_count,
        merged_content_size_bytes=content_size,
        merged_content_sha256=digest.hexdigest(),
    )


__all__ = [
    "ArtifactValidationError",
    "StreamingJsonlZstdWriter",
    "build_admission_trace_set",
    "iter_jsonl_zstd",
    "iter_merged_trace_partitions",
    "write_jsonl_zstd",
]
