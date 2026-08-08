from __future__ import annotations

from collections.abc import Iterator
from typing import Self

from crypto_collector.materializer.models import (
    DiscoveredRawInput,
    SourceLocator,
    SourceRecord,
)
from crypto_collector.storage.manifest import (
    RawManifestReader as _StorageRawManifestReader,
)

RawManifestReader = _StorageRawManifestReader


class RawSourceReader:
    def __init__(self, source: DiscoveredRawInput) -> None:
        if type(source) is not DiscoveredRawInput:
            raise TypeError("source must be DiscoveredRawInput")
        self.source = source
        self._reader: _StorageRawManifestReader | None = None
        self._record_index = 0
        self._validated_complete = False

    @property
    def records_read(self) -> int:
        return self._record_index

    @property
    def validated_complete(self) -> bool:
        return self._validated_complete

    def __enter__(self) -> Self:
        if self._reader is not None:
            raise RuntimeError("raw source reader is already entered")
        reader = _StorageRawManifestReader(
            self.source.manifest_path,
            expected_manifest_sha256=self.source.manifest_sha256,
        )
        reader.__enter__()
        self._reader = reader
        self._record_index = 0
        self._validated_complete = False
        return self

    def __iter__(self) -> Iterator[SourceRecord]:
        if self._reader is None:
            raise RuntimeError("raw source reader is not entered")
        return self

    def __next__(self) -> SourceRecord:
        reader = self._reader
        if reader is None:
            raise RuntimeError("raw source reader is not entered")
        try:
            envelope = next(reader)
        except StopIteration:
            self._validated_complete = True
            raise
        locator = SourceLocator(
            manifest_sha256=self.source.manifest_sha256,
            zero_based_record_index=self._record_index,
        )
        self._record_index += 1
        return SourceRecord(envelope=envelope, locator=locator)

    def __exit__(self, *exc: object) -> None:
        reader = self._reader
        self._reader = None
        if reader is not None:
            reader.__exit__(*exc)


__all__ = ["RawManifestReader", "RawSourceReader"]
