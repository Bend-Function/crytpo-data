from __future__ import annotations

import hashlib
import json

import pytest

import crypto_collector.archive.receipt as receipt_module
from crypto_collector.archive.keys import data_key
from crypto_collector.archive.models import (
    ArchiveJobKey,
    SourceArtifact,
    canonical_json_bytes,
)
from crypto_collector.archive.policy import freeze_policy
from crypto_collector.archive.receipt import (
    ArchiveReceiptV1,
    ProviderChecksumV1,
    ReceiptValidationError,
    validate_receipt,
)
from crypto_collector.config.models import ArchiveConfig


def policy():
    return freeze_policy(
        config=ArchiveConfig.model_validate(
            {
                "targets": [
                    {
                        "id": "s3-primary",
                        "type": "s3",
                        "required": True,
                        "bucket": "archive",
                        "endpoint": "https://s3.example.test",
                        "credentials": {
                            "access_key_id": "env:S3_ACCESS_KEY",
                            "secret_access_key": "env:S3_SECRET_KEY",
                        },
                        "compression": {
                            "enabled": True,
                            "mode": "zstd",
                            "level": 3,
                            "min_size": "1B",
                        },
                    }
                ]
            }
        )
    )


def artifact() -> SourceArtifact:
    return SourceArtifact(
        relative_path="raw/okx/spot/BTC-USDT/trades/part.json",
        size_bytes=2048,
        sha256="a" * 64,
        artifact_role="raw_data",
    )


def job_key() -> ArchiveJobKey:
    frozen = policy()
    source = artifact()
    return ArchiveJobKey(
        source_manifest_sha256="c" * 64,
        artifact_role=source.artifact_role,
        artifact_sha256=source.sha256,
        target_id="s3-primary",
        policy_sha256=frozen.policy_sha256,
    )


def valid_receipt() -> ArchiveReceiptV1:
    frozen = policy()
    source = artifact()
    target = frozen.target("s3-primary")
    compression = target.compression
    return ArchiveReceiptV1.with_computed_hash(
        job_key=job_key(),
        source_path=source.relative_path,
        source_size_bytes=source.size_bytes,
        stored_key=data_key(source, frozen, target_id=target.target_id),
        stored_size_bytes=1024,
        stored_sha256="b" * 64,
        transform_kind="zstd-v1",
        codec="zstd",
        codec_level=compression.level,
        codec_policy_version=compression.codec_policy_version,
        codec_tool=compression.codec_tool,
        codec_version=compression.codec_tool_version,
        transform_profile=compression.transform_profile,
        transform_implementation_sha256=(compression.transform_implementation_sha256),
        provider_checksum=ProviderChecksumV1(
            algorithm="sha256",
            checksum_type="full_object",
            value="b" * 64,
        ),
        verification_level=target.verification_level,
        verification_method="provider_full_object_sha256",
        verified_at_ns=123,
    )


def _rehash(document: dict[str, object]) -> bytes:
    unhashed = {
        key: value for key, value in document.items() if key != "receipt_sha256"
    }
    document["receipt_sha256"] = hashlib.sha256(
        canonical_json_bytes(unhashed)
    ).hexdigest()
    return canonical_json_bytes(document) + b"\n"


def test_receipt_is_canonical_self_hashed_and_job_bound() -> None:
    receipt = valid_receipt()
    source = receipt.to_canonical_json()
    validated = validate_receipt(
        source,
        expected_job_key=job_key(),
        expected_artifact=artifact(),
        expected_policy=policy(),
        expected_stored_key=receipt.stored_key,
        expected_stored_size_bytes=receipt.stored_size_bytes,
        expected_stored_sha256=receipt.stored_sha256,
    )

    assert source.endswith(b"\n")
    assert validated == receipt
    assert validated.job_key == job_key()
    assert validated.commit_marker is True
    assert json.loads(source)["receipt_sha256"] == receipt.receipt_sha256


@pytest.mark.parametrize(
    ("field", "tampered"),
    [
        ("source_sha256", "f" * 64),
        ("stored_size_bytes", 1025),
        ("receipt_sha256", "0" * 64),
    ],
)
def test_receipt_rejects_tampered_field_or_hash(field: str, tampered: object) -> None:
    document = json.loads(valid_receipt().to_canonical_json())
    document[field] = tampered

    with pytest.raises(ReceiptValidationError):
        validate_receipt(canonical_json_bytes(document) + b"\n")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("artifact_role", "other_role"),
        ("source_sha256", "f" * 64),
        ("target_id", "other-target"),
        ("policy_sha256", "e" * 64),
    ],
)
def test_rehashed_receipt_still_must_match_expected_job_key(
    field: str,
    value: object,
) -> None:
    document = json.loads(valid_receipt().to_canonical_json())
    document[field] = value

    with pytest.raises(ReceiptValidationError, match="job key"):
        validate_receipt(
            _rehash(document),
            expected_job_key=job_key(),
            expected_artifact=artifact(),
            expected_policy=policy(),
            expected_stored_key=valid_receipt().stored_key,
            expected_stored_size_bytes=valid_receipt().stored_size_bytes,
            expected_stored_sha256=valid_receipt().stored_sha256,
        )


def test_receipt_rejects_forged_expected_job_key_without_echo() -> None:
    canary = "../../plaintext-secret-canary"
    forged = job_key().model_copy(update={"target_id": canary})

    with pytest.raises(
        ReceiptValidationError, match="expected archive job key"
    ) as caught:
        validate_receipt(
            valid_receipt().to_canonical_json(),
            expected_job_key=forged,
            expected_artifact=artifact(),
            expected_policy=policy(),
            expected_stored_key=valid_receipt().stored_key,
            expected_stored_size_bytes=valid_receipt().stored_size_bytes,
            expected_stored_sha256=valid_receipt().stored_sha256,
        )

    assert canary not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_receipt_uses_constant_time_hash_comparison(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    original = receipt_module.hmac.compare_digest

    def recording_compare(first: str, second: str) -> bool:
        calls.append((first, second))
        return original(first, second)

    monkeypatch.setattr(receipt_module.hmac, "compare_digest", recording_compare)
    receipt = validate_receipt(valid_receipt().to_canonical_json())

    assert calls
    assert calls[-1] == (receipt.receipt_sha256, receipt.receipt_sha256)


def test_receipt_rejects_noncanonical_missing_and_extra_secret_fields() -> None:
    receipt = valid_receipt()
    document = json.loads(receipt.to_canonical_json())
    del document["target_id"]
    with pytest.raises(ReceiptValidationError):
        validate_receipt(_rehash(document))

    canary = "plaintext-secret-canary"
    document = json.loads(receipt.to_canonical_json())
    document["secret_access_key"] = canary
    with pytest.raises(ReceiptValidationError) as captured:
        validate_receipt(_rehash(document))
    assert canary not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None

    pretty = (
        json.dumps(
            json.loads(receipt.to_canonical_json()),
            indent=2,
        ).encode()
        + b"\n"
    )
    with pytest.raises(ReceiptValidationError, match="canonical"):
        validate_receipt(pretty)
    with pytest.raises(ReceiptValidationError, match="canonical"):
        validate_receipt(receipt.to_canonical_json().removesuffix(b"\n"))


def test_receipt_schema_cannot_serialize_credentials(monkeypatch) -> None:
    monkeypatch.setenv("S3_SECRET_KEY", "runtime-secret-canary")
    source = valid_receipt().to_canonical_json()

    assert b"runtime-secret-canary" not in source
    assert b"env:S3_SECRET_KEY" not in source
    assert b"credential" not in source


@pytest.mark.parametrize(
    "provider_checksum",
    [
        {
            "algorithm": "sha256",
            "checksum_type": "full_object",
            "value": "b" * 64,
            "access_key": "plaintext-secret",
        },
        {
            "algorithm": "sha256",
            "checksum_type": "full_object",
            "value": "not-a-sha256",
        },
    ],
)
def test_provider_checksum_is_strict_evidence_only(
    provider_checksum: dict[str, object],
) -> None:
    document = json.loads(valid_receipt().to_canonical_json())
    document["provider_checksum"] = provider_checksum

    with pytest.raises(ReceiptValidationError):
        validate_receipt(_rehash(document))


def test_receipt_rejects_wrong_stored_key_even_with_valid_hash() -> None:
    document = json.loads(valid_receipt().to_canonical_json())
    document["stored_key"] = "_archive/v1/policy=" + "d" * 64 + "/wrong"

    with pytest.raises(ReceiptValidationError, match="stored key"):
        validate_receipt(
            _rehash(document),
            expected_stored_key=valid_receipt().stored_key,
        )


def test_receipt_compares_unicode_stored_key_as_utf8_bytes() -> None:
    receipt = valid_receipt()
    document = json.loads(receipt.to_canonical_json())
    document["stored_key"] = "归档/object"
    source = _rehash(document)

    assert (
        validate_receipt(
            source,
            expected_stored_key="归档/object",
        ).stored_key
        == "归档/object"
    )


@pytest.mark.parametrize(
    "mutation",
    ("passthrough_identity", "zstd_fingerprint", "reserved_source_path"),
)
def test_receipt_rejects_self_hashed_internal_semantic_contradictions(
    mutation: str,
) -> None:
    document = json.loads(valid_receipt().to_canonical_json())
    if mutation == "passthrough_identity":
        document.update(
            {
                "transform_kind": "passthrough",
                "codec": "passthrough",
                "codec_level": None,
                "codec_policy_version": None,
                "codec_tool": None,
                "codec_version": None,
                "transform_profile": None,
                "transform_implementation_sha256": None,
            }
        )
    elif mutation == "zstd_fingerprint":
        document["transform_implementation_sha256"] = "f" * 64
    else:
        document["source_path"] = "_receipts/other.json"

    with pytest.raises(ReceiptValidationError):
        validate_receipt(_rehash(document))


@pytest.mark.parametrize(
    "mutation",
    ("source_path", "source_size", "transform_policy"),
)
def test_job_bound_receipt_requires_exact_artifact_and_policy_semantics(
    mutation: str,
) -> None:
    receipt = valid_receipt()
    document = json.loads(receipt.to_canonical_json())
    if mutation == "source_path":
        document["source_path"] = "raw/other.json"
    elif mutation == "source_size":
        document["source_size_bytes"] = artifact().size_bytes + 1
    else:
        document.update(
            {
                "stored_size_bytes": artifact().size_bytes,
                "stored_sha256": artifact().sha256,
                "transform_kind": "passthrough",
                "codec": "passthrough",
                "codec_level": None,
                "codec_policy_version": None,
                "codec_tool": None,
                "codec_version": None,
                "transform_profile": None,
                "transform_implementation_sha256": None,
                "provider_checksum": None,
                "verification_method": "readback_sha256",
            }
        )

    with pytest.raises(ReceiptValidationError, match="binding"):
        validate_receipt(
            _rehash(document),
            expected_job_key=job_key(),
            expected_artifact=artifact(),
            expected_policy=policy(),
            expected_stored_key=receipt.stored_key,
            expected_stored_size_bytes=int(document["stored_size_bytes"]),
            expected_stored_sha256=str(document["stored_sha256"]),
        )
