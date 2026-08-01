from crypto_collector import storage
from crypto_collector.storage.errors import (
    PublicationConflict,
    RecoveryBlocked,
    SourceUnavailable,
)
from crypto_collector.storage.manifest import (
    SourceUnavailable as ManifestSourceUnavailable,
)
from crypto_collector.storage.raw_writer import (
    PublicationConflict as RawWriterPublicationConflict,
)


def test_public_storage_exceptions_share_canonical_class_objects() -> None:
    assert storage.PublicationConflict is PublicationConflict
    assert RawWriterPublicationConflict is PublicationConflict
    assert storage.RecoveryBlocked is RecoveryBlocked
    assert storage.SourceUnavailable is SourceUnavailable
    assert ManifestSourceUnavailable is SourceUnavailable
