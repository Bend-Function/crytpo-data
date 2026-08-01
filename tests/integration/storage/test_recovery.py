from __future__ import annotations

import base64
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest
import zstandard

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.json_codec import decode_json, encode_json
from crypto_collector.domain.types import CloseReason, Exchange, Market, Transport
from crypto_collector.storage.durability import (
    PosixSyncBackend,
    RecoveryAccountingMode,
    RecoveryDurabilityCoordinator,
    StorageIoLimiter,
    discard_file_sync_completion,
)
from crypto_collector.storage.errors import RecoveryBlocked
from crypto_collector.storage.manifest import (
    RECOVERY_UNAVAILABLE_FIELDS,
    CleanupProofEvidenceV1,
    CleanupProofKind,
    RawManifestV1,
    RecoverySourceState,
    manifest_path_for_data,
)
from crypto_collector.storage.models import (
    AcceptedRecord,
    AcceptedRecordIdentityV1,
    StorageControlAssociationV1,
    StorageControlTargetV1,
)
from crypto_collector.storage.recovery import (
    RECOVERY_GENERATION_NAMESPACE,
    PendingRecoveryControl,
    PosixRecoveryBackend,
    RecoveryArtifactsDurableV1,
    RecoveryCompleteV1,
    RecoveryContext,
    RecoveryControlAdmission,
    RecoveryControlDurableV1,
    RecoveryControlOwnershipV1,
    RecoveryControlPayloadV1,
    RecoveryControlReceipt,
    RecoveryIntentV1,
    RecoveryOutcome,
    RecoverySourceDisposition,
    RecoverySourceSettledV1,
    _pending_from_intent,
    _plan_streaming_recovery_source,
    _recovery_manifest,
    _RecoveryJournal,
    _scan_recovery_chunks,
    bad_tail_quarantine_relative_path,
    load_recovery_chain,
    load_recovery_fact,
    plan_recovery_source,
    recovery_generation_id,
    scan_recovery_frames,
    whole_source_quarantine_relative_path,
)
from crypto_collector.storage.serialize import encode_envelope
from crypto_collector.storage.stats import CumulativeDurabilityHistogram

TRANSACTION_ID = "123e4567-e89b-42d3-a456-426614174000"
SOURCE_RELATIVE_PATH = (
    "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/"
    "part-1785456000000000000-0.jsonl.zst.partial"
)
RECOVERED_RELATIVE_PATH = (
    "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/part-1785456000000000000-1.jsonl.zst"
)


def valid_intent_values(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "schema_version": 1,
        "fact_kind": "intent",
        "transaction_id": TRANSACTION_ID,
        "created_at_ns": 1_785_456_000_000_000_000,
        "predecessor_sha256": None,
        "source_state": RecoverySourceState.PARTIAL_TRUNCATED,
        "source_relative_path": SOURCE_RELATIVE_PATH,
        "source_size_bytes": 100,
        "source_sha256": "a" * 64,
        "planned_source_disposition": RecoverySourceDisposition.REMOVED,
        "planned_data_generation_id": recovery_generation_id(RECOVERED_RELATIVE_PATH),
        "planned_data_relative_path": RECOVERED_RELATIVE_PATH,
        "planned_data_size_bytes": 80,
        "planned_data_sha256": "b" * 64,
        "planned_manifest_relative_path": manifest_path_for_data(
            RECOVERED_RELATIVE_PATH
        ).as_posix(),
        "planned_manifest_size_bytes": 1_000,
        "planned_manifest_sha256": "c" * 64,
        "planned_quarantine_relative_path": bad_tail_quarantine_relative_path(
            SOURCE_RELATIVE_PATH
        ),
        "planned_quarantine_size_bytes": 20,
        "planned_quarantine_sha256": "d" * 64,
        "cleanup_proof_kind": None,
        "cleanup_proof_relative_path": None,
        "cleanup_proof_size_bytes": None,
        "cleanup_proof_sha256": None,
        "recovery_control_event_id": f"raw-recovery-lineage:v1:{TRANSACTION_ID}",
    }
    values.update(overrides)
    return values


def artifacts_for(
    intent: RecoveryIntentV1,
    **overrides: object,
) -> RecoveryArtifactsDurableV1:
    values: dict[str, object] = {
        "schema_version": 1,
        "fact_kind": "artifacts_durable",
        "transaction_id": intent.transaction_id,
        "created_at_ns": intent.created_at_ns + 1,
        "predecessor_sha256": intent.fact_sha256,
        "data_generation_id": intent.planned_data_generation_id,
        "data_relative_path": intent.planned_data_relative_path,
        "data_size_bytes": intent.planned_data_size_bytes,
        "data_sha256": intent.planned_data_sha256,
        "manifest_relative_path": intent.planned_manifest_relative_path,
        "manifest_size_bytes": intent.planned_manifest_size_bytes,
        "manifest_sha256": intent.planned_manifest_sha256,
        "quarantine_relative_path": intent.planned_quarantine_relative_path,
        "quarantine_size_bytes": intent.planned_quarantine_size_bytes,
        "quarantine_sha256": intent.planned_quarantine_sha256,
    }
    values.update(overrides)
    return RecoveryArtifactsDurableV1.create(**values)


def settled_for(
    intent: RecoveryIntentV1,
    artifacts: RecoveryArtifactsDurableV1,
    **overrides: object,
) -> RecoverySourceSettledV1:
    values: dict[str, object] = {
        "schema_version": 1,
        "fact_kind": "source_settled",
        "transaction_id": intent.transaction_id,
        "created_at_ns": artifacts.created_at_ns + 1,
        "predecessor_sha256": artifacts.fact_sha256,
        "source_relative_path": intent.source_relative_path,
        "source_disposition": intent.planned_source_disposition,
        "settled_relative_path": None,
        "settled_size_bytes": None,
        "settled_sha256": None,
    }
    values.update(overrides)
    return RecoverySourceSettledV1.create(**values)


def test_recovery_generation_is_uuid5_of_exact_canonical_data_path() -> None:
    expected = str(uuid.uuid5(RECOVERY_GENERATION_NAMESPACE, RECOVERED_RELATIVE_PATH))

    assert recovery_generation_id(RECOVERED_RELATIVE_PATH) == expected
    assert recovery_generation_id(RECOVERED_RELATIVE_PATH) == expected

    with pytest.raises(ValueError, match="final|normalized"):
        recovery_generation_id(RECOVERED_RELATIVE_PATH + ".partial")
    with pytest.raises(ValueError, match="source path"):
        recovery_generation_id("junk/part-1-2.jsonl.zst")
    with pytest.raises(ValueError, match="hour"):
        recovery_generation_id(
            "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/part-1-2.jsonl.zst"
        )


def test_quarantine_paths_are_deterministic_and_branch_specific() -> None:
    assert bad_tail_quarantine_relative_path(SOURCE_RELATIVE_PATH) == (
        f"quarantine/{SOURCE_RELATIVE_PATH}.bad-tail"
    )
    assert whole_source_quarantine_relative_path(SOURCE_RELATIVE_PATH) == (
        f"quarantine/{SOURCE_RELATIVE_PATH}.whole"
    )


def test_intent_fact_hash_and_bytes_are_canonical(tmp_path: Path) -> None:
    intent = RecoveryIntentV1.create(**valid_intent_values())
    expected_payload = intent.model_dump(
        mode="python",
        exclude={"fact_sha256"},
    )

    assert intent.hash_payload_bytes() == (encode_json(expected_payload) + b"\n")
    assert intent.fact_sha256 == hashlib.sha256(intent.hash_payload_bytes()).hexdigest()
    assert intent.canonical_fact_bytes().endswith(b"\n")
    assert list(decode_json(intent.canonical_fact_bytes())) == list(
        RecoveryIntentV1.model_fields
    )

    path = tmp_path / "intent.json"
    path.write_bytes(intent.canonical_fact_bytes())
    assert load_recovery_fact(path, RecoveryIntentV1) == intent


@pytest.mark.parametrize("schema_version", [True, 1.0, "1", 0, 2])
def test_intent_rejects_non_exact_schema_version(schema_version: object) -> None:
    with pytest.raises(ValueError):
        RecoveryIntentV1.create(**valid_intent_values(schema_version=schema_version))


def test_intent_rejects_generation_path_mismatch_and_partial_group() -> None:
    for overrides in (
        {"planned_data_generation_id": str(uuid.uuid4())},
        {"planned_data_sha256": None},
        {"planned_manifest_size_bytes": None},
        {"planned_quarantine_size_bytes": 0},
        {"planned_quarantine_relative_path": "quarantine/wrong.bad-tail"},
    ):
        with pytest.raises(ValueError):
            RecoveryIntentV1.create(**valid_intent_values(**overrides))


def test_intent_rejects_unbound_source_and_incomplete_byte_accounting() -> None:
    invalid_source = "misc/evil.jsonl.zst.partial"
    with pytest.raises(ValueError, match="source path"):
        RecoveryIntentV1.create(
            **valid_intent_values(
                source_relative_path=invalid_source,
                planned_source_disposition=(
                    RecoverySourceDisposition.MOVED_TO_QUARANTINE
                ),
                planned_data_generation_id=None,
                planned_data_relative_path=None,
                planned_data_size_bytes=None,
                planned_data_sha256=None,
                planned_manifest_relative_path=None,
                planned_manifest_size_bytes=None,
                planned_manifest_sha256=None,
                planned_quarantine_relative_path=(
                    whole_source_quarantine_relative_path(invalid_source)
                ),
                planned_quarantine_size_bytes=100,
                planned_quarantine_sha256="a" * 64,
            )
        )

    with pytest.raises(ValueError, match="cover|size"):
        RecoveryIntentV1.create(
            **valid_intent_values(
                planned_data_size_bytes=1,
                planned_quarantine_size_bytes=1,
            )
        )

    with pytest.raises(ValueError, match="complete|source"):
        RecoveryIntentV1.create(
            **valid_intent_values(
                source_state=RecoverySourceState.PARTIAL_COMPLETE,
                planned_data_size_bytes=99,
                planned_data_sha256="b" * 64,
                planned_quarantine_relative_path=None,
                planned_quarantine_size_bytes=None,
                planned_quarantine_sha256=None,
            )
        )


def test_whole_quarantine_intent_has_no_recovered_artifact_group() -> None:
    intent = RecoveryIntentV1.create(
        **valid_intent_values(
            planned_source_disposition=RecoverySourceDisposition.MOVED_TO_QUARANTINE,
            planned_data_generation_id=None,
            planned_data_relative_path=None,
            planned_data_size_bytes=None,
            planned_data_sha256=None,
            planned_manifest_relative_path=None,
            planned_manifest_size_bytes=None,
            planned_manifest_sha256=None,
            planned_quarantine_relative_path=whole_source_quarantine_relative_path(
                SOURCE_RELATIVE_PATH
            ),
            planned_quarantine_size_bytes=100,
            planned_quarantine_sha256="a" * 64,
        )
    )

    assert (
        intent.planned_source_disposition
        is RecoverySourceDisposition.MOVED_TO_QUARANTINE
    )
    assert intent.planned_data_relative_path is None


def test_cleanup_intent_requires_exact_proof_group_and_existing_manifest() -> None:
    source_data = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    intent = RecoveryIntentV1.create(
        **valid_intent_values(
            source_state=RecoverySourceState.CLEANUP_INTENT,
            source_relative_path=source_data,
            source_size_bytes=80,
            source_sha256="b" * 64,
            planned_source_disposition=(RecoverySourceDisposition.LEGITIMATELY_MISSING),
            planned_data_generation_id=None,
            planned_data_relative_path=None,
            planned_data_size_bytes=None,
            planned_data_sha256=None,
            planned_manifest_relative_path=manifest_path_for_data(
                source_data
            ).as_posix(),
            planned_manifest_size_bytes=1_000,
            planned_manifest_sha256="c" * 64,
            planned_quarantine_relative_path=None,
            planned_quarantine_size_bytes=None,
            planned_quarantine_sha256=None,
            cleanup_proof_kind=CleanupProofKind.DURABLE_INTENT,
            cleanup_proof_relative_path="cleanup/okx/intent.json",
            cleanup_proof_size_bytes=200,
            cleanup_proof_sha256="e" * 64,
        )
    )

    assert intent.cleanup_proof_kind is CleanupProofKind.DURABLE_INTENT


def test_publication_coexistence_requires_full_source_replacement() -> None:
    with pytest.raises(ValueError, match="preserve|source"):
        RecoveryIntentV1.create(
            **valid_intent_values(
                source_state=RecoverySourceState.PUBLICATION_COEXISTENCE,
                planned_data_size_bytes=80,
                planned_data_sha256="b" * 64,
                planned_quarantine_relative_path=None,
                planned_quarantine_size_bytes=None,
                planned_quarantine_sha256=None,
            )
        )


def test_control_payload_freezes_exact_context_and_json_arrays() -> None:
    payload = RecoveryControlPayloadV1(
        schema_version=1,
        recovery_control_event_id=f"raw-recovery-lineage:v1:{TRANSACTION_ID}",
        transaction_id=TRANSACTION_ID,
        source_state=RecoverySourceState.PARTIAL_TRUNCATED,
        source_disposition=RecoverySourceDisposition.REMOVED,
        source_market=Market.SPOT,
        source_instrument_key="BTC-USDT",
        source_logical_stream="trade",
        source_relative_path=SOURCE_RELATIVE_PATH,
        source_sha256="a" * 64,
        recovered_generation_id=recovery_generation_id(RECOVERED_RELATIVE_PATH),
        recovered_relative_path=RECOVERED_RELATIVE_PATH,
        recovered_sha256="b" * 64,
        quarantined_relative_path=bad_tail_quarantine_relative_path(
            SOURCE_RELATIVE_PATH
        ),
        quarantined_sha256="d" * 64,
        informational_only=False,
        affected_markets=(Market.SPOT,),
    )

    wire = payload.model_dump(mode="json")
    assert wire["kind"] == "recovery_reconciled"
    assert wire["affected_markets"] == ["spot"]
    assert "storage_association" not in wire

    invalid = payload.model_dump(mode="python")
    invalid["affected_markets"] = ()
    with pytest.raises(ValueError):
        RecoveryControlPayloadV1.model_validate(invalid)


def valid_control_ownership_values(**overrides: object) -> dict[str, object]:
    intent = RecoveryIntentV1.create(**valid_intent_values())
    payload = RecoveryControlPayloadV1(
        schema_version=1,
        recovery_control_event_id=intent.recovery_control_event_id,
        transaction_id=intent.transaction_id,
        source_state=intent.source_state,
        source_disposition=intent.planned_source_disposition,
        source_market=Market.SPOT,
        source_instrument_key="BTC-USDT",
        source_logical_stream="trade",
        source_relative_path=intent.source_relative_path,
        source_sha256=intent.source_sha256,
        recovered_generation_id=intent.planned_data_generation_id,
        recovered_relative_path=intent.planned_data_relative_path,
        recovered_sha256=intent.planned_data_sha256,
        quarantined_relative_path=intent.planned_quarantine_relative_path,
        quarantined_sha256=intent.planned_quarantine_sha256,
        informational_only=False,
        affected_markets=(Market.SPOT,),
    )
    envelope = RawEnvelope(
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        event_time_ns=None,
        event_time_source=None,
        received_at_ns=1_785_456_001_000_000_000,
        monotonic_ns=20,
        worker_instance_id="worker-1",
        connection_id=None,
        connection_generation=None,
        writer_sequence=9,
        egress_id=None,
        config_sha256="f" * 64,
        payload=payload.model_dump(mode="json"),
    )
    encoded = encode_envelope(envelope)
    frame = _frame(envelope)
    data_relative_path = (
        "raw/okx/_control/2026/07/31/00/part-1785456000000000000-0.jsonl.zst"
    )
    source_relative_path = data_relative_path + ".partial"
    scan = scan_recovery_frames(frame, source_relative_path)
    created_at_ns = 1_785_456_100_000_000_000
    manifest = _recovery_manifest(
        scan=scan,
        source=frame,
        source_relative_path=source_relative_path,
        source_state=RecoverySourceState.OWNED_CONTROL_CARRIER,
        transaction_id=TRANSACTION_ID,
        created_at_ns=created_at_ns,
        data_relative_path=data_relative_path,
        data=frame,
        quarantine_relative_path=None,
        quarantine=None,
    )
    identity = AcceptedRecordIdentityV1(
        schema_version=1,
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        logical_stream="_control",
        worker_instance_id="worker-1",
        writer_sequence=9,
        acceptance_ordinal=4,
        config_sha256="f" * 64,
        config_generation=3,
    )
    association = StorageControlAssociationV1(
        schema_version=1,
        control_kind="recovery_reconciled",
        control_event_id=intent.recovery_control_event_id,
        targets=(
            StorageControlTargetV1(
                generation_id=intent.planned_data_generation_id,
                data_relative_path=intent.planned_data_relative_path,
            ),
        ),
        acceptance_ordinal=identity.acceptance_ordinal,
        config_generation=identity.config_generation,
    )
    values: dict[str, object] = {
        "schema_version": 1,
        "fact_kind": "control_ownership",
        "transaction_id": TRANSACTION_ID,
        "created_at_ns": created_at_ns,
        "predecessor_sha256": "a" * 64,
        "recovery_control_event_id": intent.recovery_control_event_id,
        "control_record_identity": identity,
        "control_envelope": envelope,
        "control_encoded_sha256": hashlib.sha256(encoded).hexdigest(),
        "control_frame_base64": base64.b64encode(frame).decode("ascii"),
        "control_frame_size_bytes": len(frame),
        "control_frame_sha256": hashlib.sha256(frame).hexdigest(),
        "control_recovery_manifest_base64": base64.b64encode(
            manifest.canonical_bytes()
        ).decode("ascii"),
        "control_recovery_manifest_size_bytes": len(manifest.canonical_bytes()),
        "control_recovery_manifest_sha256": hashlib.sha256(
            manifest.canonical_bytes()
        ).hexdigest(),
        "control_generation_id": "control-generation-1",
        "control_data_relative_path": data_relative_path,
        "control_manifest_relative_path": manifest_path_for_data(
            data_relative_path
        ).as_posix(),
        "control_association": association,
        "zstd_level": 3,
        "max_plain_frame_bytes": 1_048_576,
    }
    values.update(overrides)
    return values


def test_control_ownership_rejects_network_control_envelope() -> None:
    values = valid_control_ownership_values()
    original = cast(RawEnvelope, values["control_envelope"])
    envelope = original.model_copy(
        update={
            "native_channel": "control",
            "transport": Transport.WEBSOCKET,
            "connection_id": "connection-1",
            "connection_generation": 1,
            "egress_id": "egress-1",
        }
    )
    encoded = encode_envelope(envelope)
    frame = _frame(envelope)
    data_relative_path = cast(str, values["control_data_relative_path"])
    manifest = _recovery_manifest(
        scan=scan_recovery_frames(frame, data_relative_path + ".partial"),
        source=frame,
        source_relative_path=data_relative_path + ".partial",
        source_state=RecoverySourceState.OWNED_CONTROL_CARRIER,
        transaction_id=TRANSACTION_ID,
        created_at_ns=cast(int, values["created_at_ns"]),
        data_relative_path=data_relative_path,
        data=frame,
        quarantine_relative_path=None,
        quarantine=None,
    )
    manifest_bytes = manifest.canonical_bytes()
    values.update(
        {
            "control_envelope": envelope,
            "control_encoded_sha256": hashlib.sha256(encoded).hexdigest(),
            "control_frame_base64": base64.b64encode(frame).decode("ascii"),
            "control_frame_size_bytes": len(frame),
            "control_frame_sha256": hashlib.sha256(frame).hexdigest(),
            "control_recovery_manifest_base64": base64.b64encode(manifest_bytes).decode(
                "ascii"
            ),
            "control_recovery_manifest_size_bytes": len(manifest_bytes),
            "control_recovery_manifest_sha256": hashlib.sha256(
                manifest_bytes
            ).hexdigest(),
        }
    )

    with pytest.raises(ValueError, match="internal|scope|source context"):
        RecoveryControlOwnershipV1.create(**values)


@pytest.mark.parametrize(
    "overrides",
    [
        {"control_encoded_sha256": "0" * 64},
        {"control_frame_size_bytes": 1},
        {"control_frame_base64": "not canonical base64"},
        {"control_recovery_manifest_sha256": "0" * 64},
    ],
)
def test_control_ownership_validates_all_embedded_bytes(
    overrides: dict[str, object],
) -> None:
    assert RecoveryControlOwnershipV1.create(**valid_control_ownership_values())
    with pytest.raises(ValueError):
        RecoveryControlOwnershipV1.create(**valid_control_ownership_values(**overrides))


def test_complete_chain_binds_control_and_outcome_to_original_intent(
    tmp_path: Path,
) -> None:
    intent = RecoveryIntentV1.create(**valid_intent_values())
    artifacts = artifacts_for(intent)
    settled = settled_for(intent, artifacts)
    ownership = RecoveryControlOwnershipV1.create(
        **valid_control_ownership_values(
            predecessor_sha256=settled.fact_sha256,
        )
    )
    durable = RecoveryControlDurableV1.create(
        schema_version=1,
        fact_kind="control_durable",
        transaction_id=intent.transaction_id,
        created_at_ns=ownership.created_at_ns + 1,
        predecessor_sha256=ownership.fact_sha256,
        recovery_control_event_id=ownership.recovery_control_event_id,
        control_record_identity=ownership.control_record_identity,
        control_generation_id=ownership.control_generation_id,
        control_data_relative_path=ownership.control_data_relative_path,
        control_encoded_sha256=ownership.control_encoded_sha256,
        durable_at_monotonic_ns=50,
    )
    outcome = RecoveryOutcome(
        transaction_id=intent.transaction_id,
        recovery_control_event_id=intent.recovery_control_event_id,
        source_state=intent.source_state,
        source_disposition=intent.planned_source_disposition,
        source_relative_path=intent.source_relative_path,
        source_sha256=intent.source_sha256,
        recovered_generation_id=intent.planned_data_generation_id,
        recovered_relative_path=intent.planned_data_relative_path,
        recovered_sha256=intent.planned_data_sha256,
        quarantined_relative_path=intent.planned_quarantine_relative_path,
        quarantined_sha256=intent.planned_quarantine_sha256,
        informational_only=False,
    )
    outcome_sha256 = hashlib.sha256(encode_json(asdict(outcome)) + b"\n").hexdigest()
    complete = RecoveryCompleteV1.create(
        schema_version=1,
        fact_kind="complete",
        transaction_id=intent.transaction_id,
        created_at_ns=durable.created_at_ns + 1,
        predecessor_sha256=durable.fact_sha256,
        recovery_control_event_id=intent.recovery_control_event_id,
        source_state=intent.source_state,
        source_disposition=intent.planned_source_disposition,
        outcome_sha256=outcome_sha256,
    )
    transaction_root = tmp_path / intent.transaction_id
    transaction_root.mkdir()
    for fact in (intent, artifacts, settled, ownership, durable, complete):
        (transaction_root / fact._filename).write_bytes(fact.canonical_fact_bytes())

    assert load_recovery_chain(transaction_root) == (
        intent,
        artifacts,
        settled,
        ownership,
        durable,
        complete,
    )

    conflicting = RecoveryCompleteV1.create(
        **{
            **complete.model_dump(mode="python", exclude={"fact_sha256"}),
            "outcome_sha256": "0" * 64,
        }
    )
    (transaction_root / "complete.json").write_bytes(conflicting.canonical_fact_bytes())
    with pytest.raises(RecoveryBlocked, match="outcome"):
        load_recovery_chain(transaction_root)


def test_fact_loader_rejects_tampering_noncanonical_bytes_and_symlink(
    tmp_path: Path,
) -> None:
    intent = RecoveryIntentV1.create(**valid_intent_values())
    canonical = intent.canonical_fact_bytes()

    for index, source in enumerate((canonical + b"\n", b" " + canonical)):
        fact_root = tmp_path / f"bad-{index}"
        fact_root.mkdir()
        path = fact_root / "intent.json"
        path.write_bytes(source)
        with pytest.raises(RecoveryBlocked):
            load_recovery_fact(path, RecoveryIntentV1)

    tampered_root = tmp_path / "tampered"
    tampered_root.mkdir()
    tampered = tampered_root / "intent.json"
    tampered.write_bytes(
        canonical.replace(b'"source_size_bytes":100', b'"source_size_bytes":101')
    )
    with pytest.raises(RecoveryBlocked, match="hash|canonical"):
        load_recovery_fact(tampered, RecoveryIntentV1)

    target_root = tmp_path / "target"
    target_root.mkdir()
    target = target_root / "intent.json"
    target.write_bytes(canonical)
    symlink_root = tmp_path / "symlink"
    symlink_root.mkdir()
    symlink = symlink_root / "intent.json"
    symlink.symlink_to(target)
    with pytest.raises(RecoveryBlocked):
        load_recovery_fact(symlink, RecoveryIntentV1)


def test_chain_loader_rejects_unknown_entries_and_missing_predecessor(
    tmp_path: Path,
) -> None:
    transaction_root = tmp_path / TRANSACTION_ID
    transaction_root.mkdir()
    intent = RecoveryIntentV1.create(**valid_intent_values())
    (transaction_root / "intent.json").write_bytes(intent.canonical_fact_bytes())

    assert load_recovery_chain(transaction_root) == (intent,)

    (transaction_root / "unknown.json").write_bytes(b"{}\n")
    with pytest.raises(RecoveryBlocked, match="unknown"):
        load_recovery_chain(transaction_root)


def test_chain_loader_rejects_hash_valid_fact_that_disagrees_with_intent(
    tmp_path: Path,
) -> None:
    transaction_root = tmp_path / TRANSACTION_ID
    transaction_root.mkdir()
    intent = RecoveryIntentV1.create(**valid_intent_values())
    conflicting = artifacts_for(intent, data_sha256="e" * 64)
    (transaction_root / "intent.json").write_bytes(intent.canonical_fact_bytes())
    (transaction_root / "artifacts-durable.json").write_bytes(
        conflicting.canonical_fact_bytes()
    )

    with pytest.raises(RecoveryBlocked, match="intent"):
        load_recovery_chain(transaction_root)


def test_recovery_journal_publishes_and_replays_exact_intent(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    journal = _RecoveryJournal(state_root=state_root, exchange=Exchange.OKX)
    intent = RecoveryIntentV1.create(**valid_intent_values())

    first = journal.publish(intent)
    fact_path = journal.transaction_root(TRANSACTION_ID) / "intent.json"
    first_inode = fact_path.stat().st_ino
    repeated = journal.publish(intent)

    assert first == intent
    assert repeated == intent
    assert fact_path.read_bytes() == intent.canonical_fact_bytes()
    assert fact_path.stat().st_ino == first_inode
    assert journal.load_chain(TRANSACTION_ID) == (intent,)


def test_recovery_journal_cleans_known_temp_before_republishing(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    journal = _RecoveryJournal(state_root=state_root, exchange=Exchange.OKX)
    transaction_root = journal.ensure_transaction(TRANSACTION_ID)
    temporary = transaction_root / f".intent.json.tmp-{TRANSACTION_ID}"
    temporary.write_bytes(b"incomplete")
    intent = RecoveryIntentV1.create(**valid_intent_values())

    journal.publish(intent)

    assert not temporary.exists()
    assert (transaction_root / "intent.json").read_bytes() == (
        intent.canonical_fact_bytes()
    )


def test_recovery_journal_blocks_fact_collision_and_unknown_entry(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    journal = _RecoveryJournal(state_root=state_root, exchange=Exchange.OKX)
    intent = RecoveryIntentV1.create(**valid_intent_values())
    journal.publish(intent)

    conflicting = RecoveryIntentV1.create(
        **valid_intent_values(created_at_ns=intent.created_at_ns + 1)
    )
    with pytest.raises(RecoveryBlocked, match="conflict"):
        journal.publish(conflicting)

    transaction_root = journal.transaction_root(TRANSACTION_ID)
    (transaction_root / "operator-note").write_bytes(b"unknown")
    with pytest.raises(RecoveryBlocked, match="unknown"):
        journal.load_chain(TRANSACTION_ID)


def test_recovery_journal_refuses_semantically_conflicting_next_fact(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    journal = _RecoveryJournal(state_root=state_root, exchange=Exchange.OKX)
    intent = RecoveryIntentV1.create(**valid_intent_values())
    journal.publish(intent)

    with pytest.raises(RecoveryBlocked, match="intent"):
        journal.publish(artifacts_for(intent, data_sha256="e" * 64))

    assert not (
        journal.transaction_root(TRANSACTION_ID) / "artifacts-durable.json"
    ).exists()


def test_recovery_journal_rejects_symlinked_fact_temp(tmp_path: Path) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    journal = _RecoveryJournal(state_root=state_root, exchange=Exchange.OKX)
    transaction_root = journal.ensure_transaction(TRANSACTION_ID)
    target = tmp_path / "outside"
    target.write_bytes(b"outside")
    temporary = transaction_root / f".intent.json.tmp-{TRANSACTION_ID}"
    temporary.symlink_to(target)

    with pytest.raises(RecoveryBlocked, match="temporary"):
        journal.publish(RecoveryIntentV1.create(**valid_intent_values()))


def test_recovery_journal_lists_transactions_and_removes_empty_allocation(
    tmp_path: Path,
) -> None:
    state_root = tmp_path / "state"
    state_root.mkdir()
    journal = _RecoveryJournal(state_root=state_root, exchange=Exchange.OKX)
    empty = journal.ensure_transaction(TRANSACTION_ID)

    assert journal.transaction_ids() == ()
    assert not empty.exists()

    intent = RecoveryIntentV1.create(**valid_intent_values())
    journal.publish(intent)
    assert journal.transaction_ids() == (TRANSACTION_ID,)


class _TestClock:
    def __init__(self) -> None:
        self.wall = 1_785_456_200_000_000_000
        self.monotonic = 100

    def time_ns(self) -> int:
        self.wall += 1
        return self.wall

    def monotonic_ns(self) -> int:
        self.monotonic += 1
        return self.monotonic


class _NoCleanupResolver:
    def resolve_missing(self, **_values: object) -> None:
        return None


class _CleanupResolver:
    def __init__(self, evidence: CleanupProofEvidenceV1) -> None:
        self.evidence = evidence
        self.calls: list[dict[str, object]] = []

    def resolve_missing(self, **values: object) -> CleanupProofEvidenceV1:
        self.calls.append(values)
        return self.evidence


def _recovery_context(
    *,
    tmp_path: Path,
    executor: ThreadPoolExecutor,
) -> RecoveryContext:
    data_root = tmp_path / "data"
    state_root = tmp_path / "state"
    data_root.mkdir(exist_ok=True)
    state_root.mkdir(exist_ok=True)
    clock = _TestClock()
    limiter = StorageIoLimiter(max_concurrency=2)
    coordinator = RecoveryDurabilityCoordinator(
        accounting_mode=RecoveryAccountingMode.UNMEASURED,
        clock=clock,
        sync_backend=PosixSyncBackend(),
        io_limiter=limiter,
        storage_executor=executor,
        completion_sink=discard_file_sync_completion,
    )
    return RecoveryContext(
        data_root=data_root,
        state_root=state_root,
        exchange=Exchange.OKX,
        worker_instance_id="worker-recovery",
        config_sha256="f" * 64,
        config_generation=1,
        clock=clock,
        io_limiter=limiter,
        recovery_coordinator=coordinator,
        storage_executor=executor,
        source_disposition_resolver=_NoCleanupResolver(),
    )


def _admission_for_pending(
    pending: PendingRecoveryControl,
) -> RecoveryControlAdmission:
    pending_control = pending
    envelope = RawEnvelope(
        **pending_control.draft.model_dump(mode="python"),
        received_at_ns=1_785_456_001_000_000_000,
        monotonic_ns=20,
        worker_instance_id="worker-1",
        connection_id=None,
        connection_generation=None,
        writer_sequence=9,
        egress_id=None,
        config_sha256="f" * 64,
    )
    record = AcceptedRecord(envelope=envelope, encoded_jsonl=encode_envelope(envelope))
    identity = AcceptedRecordIdentityV1(
        schema_version=1,
        exchange=envelope.exchange,
        market=None,
        instrument_key=None,
        logical_stream="_control",
        worker_instance_id=envelope.worker_instance_id,
        writer_sequence=envelope.writer_sequence,
        acceptance_ordinal=4,
        config_sha256=envelope.config_sha256,
        config_generation=1,
    )
    association = (
        None
        if pending_control.target is None
        else StorageControlAssociationV1(
            schema_version=1,
            control_kind="recovery_reconciled",
            control_event_id=pending_control.recovery_control_event_id,
            targets=(pending_control.target,),
            acceptance_ordinal=identity.acceptance_ordinal,
            config_generation=identity.config_generation,
        )
    )
    frame = _frame(envelope)
    data_relative_path = (
        "raw/okx/_control/2026/07/31/00/part-1785456000000000000-0.jsonl.zst"
    )
    return RecoveryControlAdmission(
        transaction_id=pending_control.transaction_id,
        recovery_control_event_id=pending_control.recovery_control_event_id,
        control_record=record,
        control_record_identity=identity,
        control_generation_id="control-generation-1",
        control_data_relative_path=data_relative_path,
        control_manifest_relative_path=manifest_path_for_data(
            data_relative_path
        ).as_posix(),
        association=association,
        control_frame_bytes=frame,
        zstd_level=3,
        max_plain_frame_bytes=1_048_576,
    )


async def _bind_owned_control_transaction(
    context: RecoveryContext,
) -> tuple[
    PosixRecoveryBackend,
    _RecoveryJournal,
    PendingRecoveryControl,
    RecoveryControlAdmission,
    RecoveryControlOwnershipV1,
]:
    source = b"not-zstd"
    plan = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    intent = plan.intent
    artifacts = artifacts_for(intent)
    settled = settled_for(
        intent,
        artifacts,
        settled_relative_path=intent.planned_quarantine_relative_path,
        settled_size_bytes=intent.planned_quarantine_size_bytes,
        settled_sha256=intent.planned_quarantine_sha256,
    )
    quarantine_path = context.data_root / cast(
        str,
        intent.planned_quarantine_relative_path,
    )
    quarantine_path.parent.mkdir(parents=True)
    quarantine_path.write_bytes(source)
    journal = _RecoveryJournal(
        state_root=context.state_root,
        exchange=context.exchange,
    )
    for fact in (intent, artifacts, settled):
        journal.publish(fact)
    pending = _pending_from_intent(intent)
    admission = _admission_for_pending(pending)
    backend = PosixRecoveryBackend()
    await backend.bind_control_ownership(
        context,
        pending=pending,
        admission=admission,
    )
    ownership = cast(
        RecoveryControlOwnershipV1,
        journal.load_chain(TRANSACTION_ID)[3],
    )
    return backend, journal, pending, admission, ownership


def _normal_owned_control_manifest(
    ownership: RecoveryControlOwnershipV1,
) -> RawManifestV1:
    envelope = ownership.control_envelope
    histogram = CumulativeDurabilityHistogram()
    histogram.add(5)
    durability = histogram.snapshot()
    return RawManifestV1(
        schema_version=1,
        exchange=envelope.exchange,
        market=None,
        instrument_key=None,
        logical_stream="_control",
        wire_symbols=(),
        data_relative_path=ownership.control_data_relative_path,
        manifest_relative_path=ownership.control_manifest_relative_path,
        file_size_bytes=ownership.control_frame_size_bytes,
        file_sha256=ownership.control_frame_sha256,
        zstd_level=ownership.zstd_level,
        zstd_write_checksum=True,
        zstd_write_content_size=True,
        max_plain_frame_bytes=ownership.max_plain_frame_bytes,
        record_count=1,
        first_received_at_ns=envelope.received_at_ns,
        last_received_at_ns=envelope.received_at_ns,
        first_event_time_ns=envelope.event_time_ns,
        last_event_time_ns=envelope.event_time_ns,
        worker_instance_id=envelope.worker_instance_id,
        connection_generations=(
            ()
            if envelope.connection_generation is None
            else (envelope.connection_generation,)
        ),
        writer_sequence_first=envelope.writer_sequence,
        writer_sequence_last=envelope.writer_sequence,
        config_sha256=envelope.config_sha256,
        egress_ids=() if envelope.egress_id is None else (envelope.egress_id,),
        requested_intervals_ns=(),
        effective_intervals_ns=(),
        gap_count=0,
        reconnect_count=0,
        parse_error_count=0,
        checksum_error_count=0,
        queue_overflow_count=0,
        control_event_ids=(),
        durability_measurement="measured",
        durability_sample_count=1,
        durability_lag_p50_ns=durability.lag_p50_ns,
        durability_lag_p95_ns=durability.lag_p95_ns,
        durability_lag_p99_ns=durability.lag_p99_ns,
        durability_lag_max_ns=durability.lag_max_ns,
        sync_count=2,
        sync_duration_total_ns=4,
        sync_duration_max_ns=3,
        slo_breach_count=0,
        write_failure_count=0,
        sync_failure_count=0,
        close_reason=CloseReason.RECOVERY_CONTROL,
        created_at_ns=ownership.created_at_ns + 1,
        closed_at_ns=ownership.created_at_ns + 2,
        recovery_transaction_id=None,
        recovery_source_state=None,
        recovery_source_relative_path=None,
        recovery_source_bytes=None,
        recovery_source_sha256=None,
        recovery_control_event_id=None,
        recovered_frame_count=None,
        recovered_record_count=None,
        recovered_bytes=None,
        recovered_sha256=None,
        quarantined_suffix_relative_path=None,
        quarantined_suffix_bytes=None,
        quarantined_suffix_sha256=None,
        unavailable_fields=(),
    )


def _durable_for_ownership(
    ownership: RecoveryControlOwnershipV1,
) -> RecoveryControlDurableV1:
    return RecoveryControlDurableV1.create(
        schema_version=1,
        fact_kind="control_durable",
        transaction_id=ownership.transaction_id,
        created_at_ns=ownership.created_at_ns + 1,
        predecessor_sha256=ownership.fact_sha256,
        recovery_control_event_id=ownership.recovery_control_event_id,
        control_record_identity=ownership.control_record_identity,
        control_generation_id=ownership.control_generation_id,
        control_data_relative_path=ownership.control_data_relative_path,
        control_encoded_sha256=ownership.control_encoded_sha256,
        durable_at_monotonic_ns=50,
    )


@pytest.mark.asyncio
async def test_posix_backend_replays_source_settled_as_one_pending_control(
    tmp_path: Path,
) -> None:
    source = b"not-zstd"
    plan = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    intent = plan.intent
    artifacts = artifacts_for(intent)
    settled = settled_for(
        intent,
        artifacts,
        settled_relative_path=intent.planned_quarantine_relative_path,
        settled_size_bytes=intent.planned_quarantine_size_bytes,
        settled_sha256=intent.planned_quarantine_sha256,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        quarantine = context.data_root / cast(
            str, intent.planned_quarantine_relative_path
        )
        quarantine.parent.mkdir(parents=True)
        quarantine.write_bytes(source)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        for fact in (intent, artifacts, settled):
            journal.publish(fact)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

    assert reconciliation.completed_outcomes == ()
    assert len(reconciliation.pending_controls) == 1
    pending = reconciliation.pending_controls[0]
    assert pending.transaction_id == TRANSACTION_ID
    assert pending.source_disposition is RecoverySourceDisposition.MOVED_TO_QUARANTINE
    assert pending.target is None
    assert pending.draft.payload["source_sha256"] == intent.source_sha256


@pytest.mark.asyncio
async def test_bind_control_ownership_publishes_fact_before_carrier_io(
    tmp_path: Path,
) -> None:
    intent = RecoveryIntentV1.create(**valid_intent_values())
    artifacts = artifacts_for(intent)
    settled = settled_for(intent, artifacts)
    ownership_values = valid_control_ownership_values(
        predecessor_sha256=settled.fact_sha256
    )
    envelope = cast(RawEnvelope, ownership_values["control_envelope"])
    identity = cast(
        AcceptedRecordIdentityV1,
        ownership_values["control_record_identity"],
    )
    admission = RecoveryControlAdmission(
        transaction_id=intent.transaction_id,
        recovery_control_event_id=intent.recovery_control_event_id,
        control_record=AcceptedRecord(
            envelope=envelope,
            encoded_jsonl=encode_envelope(envelope),
        ),
        control_record_identity=identity,
        control_generation_id=cast(str, ownership_values["control_generation_id"]),
        control_data_relative_path=cast(
            str, ownership_values["control_data_relative_path"]
        ),
        control_manifest_relative_path=cast(
            str, ownership_values["control_manifest_relative_path"]
        ),
        association=cast(
            StorageControlAssociationV1,
            ownership_values["control_association"],
        ),
        control_frame_bytes=base64.b64decode(
            cast(str, ownership_values["control_frame_base64"])
        ),
        zstd_level=cast(int, ownership_values["zstd_level"]),
        max_plain_frame_bytes=cast(int, ownership_values["max_plain_frame_bytes"]),
    )
    pending = _pending_from_intent(intent)
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        for fact in (intent, artifacts, settled):
            journal.publish(fact)

        backend = PosixRecoveryBackend()
        await backend.bind_control_ownership(
            context,
            pending=pending,
            admission=admission,
        )
        await backend.bind_control_ownership(
            context,
            pending=pending,
            admission=admission,
        )
        chain = journal.load_chain(intent.transaction_id)

    assert len(chain) == 4
    ownership = cast(RecoveryControlOwnershipV1, chain[-1])
    assert (
        ownership.control_frame_sha256
        == hashlib.sha256(admission.control_frame_bytes).hexdigest()
    )
    assert not (
        context.data_root / (admission.control_data_relative_path + ".partial")
    ).exists()
    assert not (context.data_root / admission.control_data_relative_path).exists()


@pytest.mark.asyncio
async def test_posix_backend_replays_owned_control_with_absent_carrier(
    tmp_path: Path,
) -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        (
            _backend,
            journal,
            _pending,
            admission,
            ownership,
        ) = await _bind_owned_control_transaction(context)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert reconciliation.pending_controls == ()
        assert len(reconciliation.completed_outcomes) == 1
        assert len(journal.load_chain(TRANSACTION_ID)) == 6
        carrier_data = context.data_root / admission.control_data_relative_path
        carrier_manifest = context.data_root / admission.control_manifest_relative_path
        assert carrier_data.read_bytes() == admission.control_frame_bytes
        assert carrier_manifest.read_bytes() == base64.b64decode(
            ownership.control_recovery_manifest_base64
        )
        assert not carrier_data.with_name(carrier_data.name + ".partial").exists()


@pytest.mark.parametrize("carrier_state", ["prefix_partial", "exact_final"])
@pytest.mark.asyncio
async def test_posix_backend_resumes_owned_control_carrier_without_readmission(
    tmp_path: Path,
    carrier_state: str,
) -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        (
            _backend,
            journal,
            _pending,
            admission,
            ownership,
        ) = await _bind_owned_control_transaction(context)
        carrier_data = context.data_root / admission.control_data_relative_path
        carrier_data.parent.mkdir(parents=True, exist_ok=True)
        if carrier_state == "prefix_partial":
            carrier_data.with_name(carrier_data.name + ".partial").write_bytes(
                admission.control_frame_bytes[: len(admission.control_frame_bytes) // 2]
            )
        else:
            carrier_data.write_bytes(admission.control_frame_bytes)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert reconciliation.pending_controls == ()
        assert len(reconciliation.completed_outcomes) == 1
        assert journal.transaction_ids() == (TRANSACTION_ID,)
        assert len(journal.load_chain(TRANSACTION_ID)) == 6
        assert carrier_data.read_bytes() == admission.control_frame_bytes
        assert (
            context.data_root / admission.control_manifest_relative_path
        ).read_bytes() == base64.b64decode(ownership.control_recovery_manifest_base64)
        assert not carrier_data.with_name(carrier_data.name + ".partial").exists()


@pytest.mark.asyncio
async def test_posix_backend_preserves_exact_normal_owned_control_manifest(
    tmp_path: Path,
) -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        (
            _backend,
            journal,
            _pending,
            admission,
            ownership,
        ) = await _bind_owned_control_transaction(context)
        carrier_data = context.data_root / admission.control_data_relative_path
        carrier_manifest = context.data_root / admission.control_manifest_relative_path
        carrier_data.parent.mkdir(parents=True, exist_ok=True)
        carrier_data.write_bytes(admission.control_frame_bytes)
        normal_manifest_bytes = _normal_owned_control_manifest(
            ownership
        ).canonical_bytes()
        carrier_manifest.write_bytes(normal_manifest_bytes)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert len(reconciliation.completed_outcomes) == 1
        assert len(journal.load_chain(TRANSACTION_ID)) == 6
        assert carrier_manifest.read_bytes() == normal_manifest_bytes


@pytest.mark.asyncio
async def test_posix_backend_blocks_control_durable_without_its_carrier(
    tmp_path: Path,
) -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        (
            _backend,
            journal,
            _pending,
            _admission,
            ownership,
        ) = await _bind_owned_control_transaction(context)
        journal.publish(_durable_for_ownership(ownership))

        with pytest.raises(RecoveryBlocked, match="carrier|artifact"):
            await PosixRecoveryBackend().reconcile(context)

        assert len(journal.load_chain(TRANSACTION_ID)) == 5


@pytest.mark.asyncio
async def test_acknowledge_control_durable_closes_chain_idempotently(
    tmp_path: Path,
) -> None:
    frame = _frame(_envelope(1))
    source = frame + b"truncated"
    plan = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    assert plan.recovered_data_bytes is not None
    assert plan.quarantine_bytes is not None
    assert plan.manifest_bytes is not None
    intent = plan.intent
    artifacts = artifacts_for(intent)
    settled = settled_for(intent, artifacts)
    pending = _pending_from_intent(intent)
    admission = _admission_for_pending(pending)

    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        for relative_path, payload in (
            (intent.planned_data_relative_path, plan.recovered_data_bytes),
            (intent.planned_manifest_relative_path, plan.manifest_bytes),
            (intent.planned_quarantine_relative_path, plan.quarantine_bytes),
        ):
            assert relative_path is not None
            artifact_path = context.data_root / relative_path
            artifact_path.parent.mkdir(parents=True, exist_ok=True)
            artifact_path.write_bytes(payload)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        for fact in (intent, artifacts, settled):
            journal.publish(fact)
        backend = PosixRecoveryBackend()
        await backend.bind_control_ownership(
            context,
            pending=pending,
            admission=admission,
        )
        ownership = cast(
            RecoveryControlOwnershipV1,
            journal.load_chain(intent.transaction_id)[-1],
        )
        carrier_data = context.data_root / admission.control_data_relative_path
        carrier_manifest = context.data_root / admission.control_manifest_relative_path
        carrier_data.parent.mkdir(parents=True, exist_ok=True)
        carrier_data.write_bytes(admission.control_frame_bytes)
        carrier_manifest.write_bytes(
            base64.b64decode(ownership.control_recovery_manifest_base64)
        )
        receipt = RecoveryControlReceipt(
            transaction_id=intent.transaction_id,
            recovery_control_event_id=intent.recovery_control_event_id,
            control_record_identity=admission.control_record_identity,
            control_generation_id=admission.control_generation_id,
            control_data_relative_path=admission.control_data_relative_path,
            control_encoded_sha256=hashlib.sha256(
                admission.control_record.encoded_jsonl
            ).hexdigest(),
            durable_at_monotonic_ns=50,
        )

        outcome = await backend.acknowledge_control_durable(
            context,
            pending=pending,
            receipt=receipt,
        )
        repeated = await backend.acknowledge_control_durable(
            context,
            pending=pending,
            receipt=receipt,
        )
        replay = await backend.reconcile(context)

    assert repeated == outcome
    assert replay.completed_outcomes == (outcome,)
    assert replay.pending_controls == ()
    assert len(journal.load_chain(intent.transaction_id)) == 6


@pytest.mark.asyncio
async def test_posix_backend_discovers_and_settles_unbound_truncated_partial(
    tmp_path: Path,
) -> None:
    valid = _frame(_envelope(1))
    tail = _frame(_envelope(2))[:-5]
    source = valid + tail
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)
        backend = PosixRecoveryBackend()

        first = await backend.reconcile(context)
        second = await backend.reconcile(context)

        assert len(first.pending_controls) == 1
        assert second.pending_controls == first.pending_controls
        pending = first.pending_controls[0]
        target = pending.target
        assert target is not None
        recovered_path = context.data_root / target.data_relative_path
        manifest_path = context.data_root / manifest_path_for_data(
            target.data_relative_path
        )
        quarantine_path = context.data_root / bad_tail_quarantine_relative_path(
            SOURCE_RELATIVE_PATH
        )
        assert recovered_path.read_bytes() == valid
        assert quarantine_path.read_bytes() == tail
        assert manifest_path.exists()
        assert not source_path.exists()
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        chain = journal.load_chain(pending.transaction_id)

    assert len(chain) == 3
    assert (
        cast(RecoveryIntentV1, chain[0]).source_sha256
        == hashlib.sha256(source).hexdigest()
    )


@pytest.mark.asyncio
async def test_posix_backend_quarantines_empty_partial_as_zero_byte_artifact(
    tmp_path: Path,
) -> None:
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(b"")

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        pending = reconciliation.pending_controls[0]
        assert pending.target is None
        quarantine = context.data_root / whole_source_quarantine_relative_path(
            SOURCE_RELATIVE_PATH
        )
        assert quarantine.is_file()
        assert quarantine.read_bytes() == b""
        assert not source_path.exists()


@pytest.mark.asyncio
async def test_posix_backend_retains_valid_closed_orphan_and_adds_manifest(
    tmp_path: Path,
) -> None:
    closed_relative_path = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    source = _frame(_envelope(1))
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / closed_relative_path
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        pending = reconciliation.pending_controls[0]
        assert pending.source_disposition is RecoverySourceDisposition.RETAINED
        assert pending.target is not None
        assert pending.target.data_relative_path == closed_relative_path
        assert source_path.read_bytes() == source
        assert (
            context.data_root / manifest_path_for_data(closed_relative_path)
        ).is_file()


@pytest.mark.asyncio
async def test_posix_backend_wholly_quarantines_invalid_closed_orphan(
    tmp_path: Path,
) -> None:
    closed_relative_path = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    source = b"invalid-closed-zstd"
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / closed_relative_path
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        pending = reconciliation.pending_controls[0]
        assert pending.source_disposition is (
            RecoverySourceDisposition.MOVED_TO_QUARANTINE
        )
        quarantine = context.data_root / whole_source_quarantine_relative_path(
            closed_relative_path
        )
        assert quarantine.read_bytes() == source
        assert not source_path.exists()
        assert not (
            context.data_root / manifest_path_for_data(closed_relative_path)
        ).exists()


@pytest.mark.asyncio
async def test_posix_backend_reconciles_same_inode_publication_coexistence_once(
    tmp_path: Path,
) -> None:
    source = _frame(_envelope(1))
    final_relative_path = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        partial_path = context.data_root / SOURCE_RELATIVE_PATH
        final_path = context.data_root / final_relative_path
        partial_path.parent.mkdir(parents=True)
        partial_path.write_bytes(source)
        final_path.hardlink_to(partial_path)

        first = await PosixRecoveryBackend().reconcile(context)
        second = await PosixRecoveryBackend().reconcile(context)

        assert len(first.pending_controls) == 1
        assert second.pending_controls == first.pending_controls
        pending = first.pending_controls[0]
        assert pending.source_state is RecoverySourceState.PUBLICATION_COEXISTENCE
        assert pending.target is not None
        assert pending.target.data_relative_path == final_relative_path
        assert final_path.read_bytes() == source
        assert not partial_path.exists()
        assert (
            context.data_root / manifest_path_for_data(final_relative_path)
        ).is_file()
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        assert journal.transaction_ids() == (pending.transaction_id,)


@pytest.mark.asyncio
async def test_posix_backend_resumes_intent_only_transaction_exactly(
    tmp_path: Path,
) -> None:
    valid = _frame(_envelope(1))
    tail = b"truncated"
    source = valid + tail
    frozen = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        journal.publish(frozen.intent)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert reconciliation.pending_controls[0].transaction_id == TRANSACTION_ID
        chain = journal.load_chain(TRANSACTION_ID)
        assert len(chain) == 3
        assert chain[0] == frozen.intent
        assert not source_path.exists()
        assert (
            context.data_root / cast(str, frozen.intent.planned_data_relative_path)
        ).read_bytes() == valid
        assert (
            context.data_root
            / cast(str, frozen.intent.planned_quarantine_relative_path)
        ).read_bytes() == tail


@pytest.mark.asyncio
async def test_posix_backend_finishes_same_inode_recovered_publication(
    tmp_path: Path,
) -> None:
    valid = _frame(_envelope(1))
    source = valid + b"truncated"
    frozen = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)
        recovered_path = context.data_root / cast(
            str,
            frozen.intent.planned_data_relative_path,
        )
        recovered_path.write_bytes(valid)
        recovered_partial = recovered_path.with_name(recovered_path.name + ".partial")
        recovered_partial.hardlink_to(recovered_path)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        journal.publish(frozen.intent)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert reconciliation.pending_controls[0].transaction_id == TRANSACTION_ID
        assert recovered_path.read_bytes() == valid
        assert not recovered_partial.exists()
        assert not source_path.exists()


@pytest.mark.asyncio
async def test_posix_backend_blocks_different_inode_recovered_publication(
    tmp_path: Path,
) -> None:
    valid = _frame(_envelope(1))
    source = valid + b"truncated"
    frozen = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)
        recovered_path = context.data_root / cast(
            str,
            frozen.intent.planned_data_relative_path,
        )
        recovered_path.write_bytes(valid)
        recovered_partial = recovered_path.with_name(recovered_path.name + ".partial")
        recovered_partial.write_bytes(valid)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        journal.publish(frozen.intent)

        with pytest.raises(RecoveryBlocked, match="temporary|conflict"):
            await PosixRecoveryBackend().reconcile(context)

        assert source_path.read_bytes() == source
        assert len(journal.load_chain(TRANSACTION_ID)) == 1


@pytest.mark.asyncio
async def test_posix_backend_resumes_exact_prefix_recovered_partial(
    tmp_path: Path,
) -> None:
    valid = _frame(_envelope(1))
    source = valid + b"truncated"
    frozen = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)
        recovered_path = context.data_root / cast(
            str,
            frozen.intent.planned_data_relative_path,
        )
        recovered_partial = recovered_path.with_name(recovered_path.name + ".partial")
        recovered_partial.write_bytes(valid[: len(valid) // 2])
        original_inode = recovered_partial.stat().st_ino
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        journal.publish(frozen.intent)

        await PosixRecoveryBackend().reconcile(context)

        assert recovered_path.read_bytes() == valid
        assert recovered_path.stat().st_ino == original_inode
        assert not recovered_partial.exists()


@pytest.mark.parametrize("source_already_removed", [False, True])
@pytest.mark.asyncio
async def test_posix_backend_resumes_artifacts_durable_transaction_exactly(
    tmp_path: Path,
    source_already_removed: bool,
) -> None:
    valid = _frame(_envelope(1))
    tail = b"truncated"
    source = valid + tail
    frozen = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)
        data_path = context.data_root / cast(
            str,
            frozen.intent.planned_data_relative_path,
        )
        manifest_path = context.data_root / cast(
            str,
            frozen.intent.planned_manifest_relative_path,
        )
        quarantine_path = context.data_root / cast(
            str,
            frozen.intent.planned_quarantine_relative_path,
        )
        data_path.write_bytes(cast(bytes, frozen.recovered_data_bytes))
        manifest_path.write_bytes(cast(bytes, frozen.manifest_bytes))
        quarantine_path.parent.mkdir(parents=True)
        quarantine_path.write_bytes(cast(bytes, frozen.quarantine_bytes))
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        artifacts = artifacts_for(frozen.intent)
        journal.publish(frozen.intent)
        journal.publish(artifacts)
        if source_already_removed:
            source_path.unlink()

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert reconciliation.pending_controls[0].transaction_id == TRANSACTION_ID
        chain = journal.load_chain(TRANSACTION_ID)
        assert chain[:2] == (frozen.intent, artifacts)
        assert len(chain) == 3
        assert not source_path.exists()
        assert data_path.read_bytes() == valid
        assert quarantine_path.read_bytes() == tail


@pytest.mark.parametrize("chain_length", [1, 2, 3])
@pytest.mark.asyncio
async def test_posix_backend_revalidates_frozen_cleanup_proof(
    tmp_path: Path,
    chain_length: int,
) -> None:
    source_relative_path = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    source = _frame(_envelope(1))
    source_manifest = _recovery_manifest(
        scan=scan_recovery_frames(source, source_relative_path),
        source=source,
        source_relative_path=source_relative_path,
        source_state=RecoverySourceState.ORPHAN_CLOSED_DATA,
        transaction_id="223e4567-e89b-42d3-a456-426614174000",
        created_at_ns=1_785_456_050_000_000_000,
        data_relative_path=source_relative_path,
        data=source,
        quarantine_relative_path=None,
        quarantine=None,
    )
    source_manifest_bytes = source_manifest.canonical_bytes()
    source_manifest_sha256 = hashlib.sha256(source_manifest_bytes).hexdigest()
    evidence = CleanupProofEvidenceV1(
        schema_version=1,
        kind=CleanupProofKind.DURABLE_INTENT,
        proof_relative_path="cleanup/okx/intent.json",
        proof_size_bytes=200,
        proof_sha256="e" * 64,
        source_manifest_relative_path=source_manifest.manifest_relative_path,
        source_manifest_sha256=source_manifest_sha256,
        source_data_relative_path=source_relative_path,
        source_data_size_bytes=len(source),
        source_data_sha256=hashlib.sha256(source).hexdigest(),
    )
    intent = RecoveryIntentV1.create(
        **valid_intent_values(
            source_state=RecoverySourceState.CLEANUP_INTENT,
            source_relative_path=source_relative_path,
            source_size_bytes=len(source),
            source_sha256=hashlib.sha256(source).hexdigest(),
            planned_source_disposition=(RecoverySourceDisposition.LEGITIMATELY_MISSING),
            planned_data_generation_id=None,
            planned_data_relative_path=None,
            planned_data_size_bytes=None,
            planned_data_sha256=None,
            planned_manifest_relative_path=source_manifest.manifest_relative_path,
            planned_manifest_size_bytes=len(source_manifest_bytes),
            planned_manifest_sha256=source_manifest_sha256,
            planned_quarantine_relative_path=None,
            planned_quarantine_size_bytes=None,
            planned_quarantine_sha256=None,
            cleanup_proof_kind=evidence.kind,
            cleanup_proof_relative_path=evidence.proof_relative_path,
            cleanup_proof_size_bytes=evidence.proof_size_bytes,
            cleanup_proof_sha256=evidence.proof_sha256,
        )
    )
    artifacts = artifacts_for(intent)
    settled = settled_for(intent, artifacts)
    resolver = _CleanupResolver(evidence)
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        object.__setattr__(context, "source_disposition_resolver", resolver)
        manifest_path = context.data_root / source_manifest.manifest_relative_path
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(source_manifest_bytes)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        for fact in (intent, artifacts, settled)[:chain_length]:
            journal.publish(fact)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert reconciliation.pending_controls[0].transaction_id == TRANSACTION_ID
        assert len(journal.load_chain(TRANSACTION_ID)) == 3
        assert resolver.calls
        assert all(call["expected_proof"] == evidence for call in resolver.calls)


@pytest.mark.asyncio
async def test_posix_backend_discovers_manifest_only_cleanup_source(
    tmp_path: Path,
) -> None:
    source_relative_path = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    source = _frame(_envelope(1))
    manifest = _recovery_manifest(
        scan=scan_recovery_frames(source, source_relative_path),
        source=source,
        source_relative_path=source_relative_path,
        source_state=RecoverySourceState.ORPHAN_CLOSED_DATA,
        transaction_id="223e4567-e89b-42d3-a456-426614174000",
        created_at_ns=1_785_456_050_000_000_000,
        data_relative_path=source_relative_path,
        data=source,
        quarantine_relative_path=None,
        quarantine=None,
    )
    manifest_bytes = manifest.canonical_bytes()
    evidence = CleanupProofEvidenceV1(
        schema_version=1,
        kind=CleanupProofKind.FINAL_TOMBSTONE,
        proof_relative_path="cleanup/okx/tombstone.json",
        proof_size_bytes=200,
        proof_sha256="e" * 64,
        source_manifest_relative_path=manifest.manifest_relative_path,
        source_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        source_data_relative_path=source_relative_path,
        source_data_size_bytes=len(source),
        source_data_sha256=hashlib.sha256(source).hexdigest(),
    )
    resolver = _CleanupResolver(evidence)
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        object.__setattr__(context, "source_disposition_resolver", resolver)
        manifest_path = context.data_root / manifest.manifest_relative_path
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(manifest_bytes)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert len(reconciliation.pending_controls) == 1
        pending = reconciliation.pending_controls[0]
        assert pending.source_state is RecoverySourceState.CLEANUP_TOMBSTONE
        assert pending.source_disposition is (
            RecoverySourceDisposition.LEGITIMATELY_MISSING
        )
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        assert len(journal.load_chain(pending.transaction_id)) == 3
        assert resolver.calls


@pytest.mark.asyncio
async def test_posix_backend_blocks_unexplained_manifest_only_source_loss(
    tmp_path: Path,
) -> None:
    source_relative_path = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    source = _frame(_envelope(1))
    manifest = _recovery_manifest(
        scan=scan_recovery_frames(source, source_relative_path),
        source=source,
        source_relative_path=source_relative_path,
        source_state=RecoverySourceState.ORPHAN_CLOSED_DATA,
        transaction_id="223e4567-e89b-42d3-a456-426614174000",
        created_at_ns=1_785_456_050_000_000_000,
        data_relative_path=source_relative_path,
        data=source,
        quarantine_relative_path=None,
        quarantine=None,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        manifest_path = context.data_root / manifest.manifest_relative_path
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(manifest.canonical_bytes())

        with pytest.raises(RecoveryBlocked, match="unexplained"):
            await PosixRecoveryBackend().reconcile(context)


@pytest.mark.asyncio
async def test_posix_backend_accepts_proven_cleanup_of_recovered_data(
    tmp_path: Path,
) -> None:
    valid = _frame(_envelope(1))
    source = valid + b"truncated"
    plan = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    assert plan.manifest is not None
    assert plan.manifest_bytes is not None
    assert plan.quarantine_bytes is not None
    intent = plan.intent
    artifacts = artifacts_for(intent)
    settled = settled_for(intent, artifacts)
    evidence = CleanupProofEvidenceV1(
        schema_version=1,
        kind=CleanupProofKind.FINAL_TOMBSTONE,
        proof_relative_path="cleanup/okx/recovered-tombstone.json",
        proof_size_bytes=200,
        proof_sha256="e" * 64,
        source_manifest_relative_path=cast(
            str,
            intent.planned_manifest_relative_path,
        ),
        source_manifest_sha256=cast(str, intent.planned_manifest_sha256),
        source_data_relative_path=cast(str, intent.planned_data_relative_path),
        source_data_size_bytes=cast(int, intent.planned_data_size_bytes),
        source_data_sha256=cast(str, intent.planned_data_sha256),
    )
    resolver = _CleanupResolver(evidence)
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        object.__setattr__(context, "source_disposition_resolver", resolver)
        manifest_path = context.data_root / cast(
            str,
            intent.planned_manifest_relative_path,
        )
        quarantine_path = context.data_root / cast(
            str,
            intent.planned_quarantine_relative_path,
        )
        manifest_path.parent.mkdir(parents=True)
        manifest_path.write_bytes(plan.manifest_bytes)
        quarantine_path.parent.mkdir(parents=True, exist_ok=True)
        quarantine_path.write_bytes(plan.quarantine_bytes)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        for fact in (intent, artifacts, settled):
            journal.publish(fact)

        reconciliation = await PosixRecoveryBackend().reconcile(context)

        assert reconciliation.pending_controls[0].transaction_id == TRANSACTION_ID
        assert resolver.calls


@pytest.mark.asyncio
async def test_posix_backend_blocks_duplicate_source_owners_before_mutation(
    tmp_path: Path,
) -> None:
    source = _frame(_envelope(1)) + b"truncated"
    plans = (
        plan_recovery_source(
            source_relative_path=SOURCE_RELATIVE_PATH,
            source=source,
            transaction_id=TRANSACTION_ID,
            created_at_ns=1_785_456_100_000_000_000,
            next_part_sequence=10,
        ),
        plan_recovery_source(
            source_relative_path=SOURCE_RELATIVE_PATH,
            source=source,
            transaction_id="323e4567-e89b-42d3-a456-426614174000",
            created_at_ns=1_785_456_100_000_000_001,
            next_part_sequence=11,
        ),
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        context = _recovery_context(tmp_path=tmp_path, executor=executor)
        source_path = context.data_root / SOURCE_RELATIVE_PATH
        source_path.parent.mkdir(parents=True)
        source_path.write_bytes(source)
        journal = _RecoveryJournal(
            state_root=context.state_root,
            exchange=context.exchange,
        )
        for plan in plans:
            for relative_path, payload in (
                (plan.intent.planned_data_relative_path, plan.recovered_data_bytes),
                (plan.intent.planned_manifest_relative_path, plan.manifest_bytes),
                (
                    plan.intent.planned_quarantine_relative_path,
                    plan.quarantine_bytes,
                ),
            ):
                assert relative_path is not None
                assert payload is not None
                artifact_path = context.data_root / relative_path
                artifact_path.parent.mkdir(parents=True, exist_ok=True)
                if artifact_path.exists():
                    assert artifact_path.read_bytes() == payload
                else:
                    artifact_path.write_bytes(payload)
            journal.publish(plan.intent)
            journal.publish(artifacts_for(plan.intent))

        with pytest.raises(RecoveryBlocked, match="owner|overlap|source"):
            await PosixRecoveryBackend().reconcile(context)

        assert source_path.read_bytes() == source
        assert all(
            len(journal.load_chain(plan.intent.transaction_id)) == 2 for plan in plans
        )


def _envelope(sequence: int, **overrides: Any) -> RawEnvelope:
    values: dict[str, Any] = {
        "exchange": Exchange.OKX,
        "market": Market.SPOT,
        "instrument_key": "BTC-USDT",
        "wire_symbol": "BTC-USDT",
        "logical_stream": "trade",
        "native_channel": "trades",
        "transport": Transport.WEBSOCKET,
        "event_time_ns": None,
        "event_time_source": None,
        "received_at_ns": 1_785_456_001_000_000_000 + sequence,
        "monotonic_ns": 10 + sequence,
        "worker_instance_id": "worker-1",
        "connection_id": "connection-1",
        "connection_generation": 1,
        "writer_sequence": sequence,
        "egress_id": "direct-primary",
        "config_sha256": "f" * 64,
        "payload": {"price": Decimal("1.250")},
    }
    values.update(overrides)
    return RawEnvelope(**values)


def _frame(*rows: RawEnvelope, checksum: bool = True) -> bytes:
    return zstandard.ZstdCompressor(
        level=3,
        write_checksum=checksum,
        write_content_size=True,
    ).compress(b"".join(encode_envelope(row) for row in rows))


def test_frame_scanner_withholds_truncated_frame_and_every_later_byte() -> None:
    first = _frame(_envelope(1))
    second = _frame(_envelope(2))
    third = _frame(_envelope(3))
    source = first + second + third[:-4]

    scanned = scan_recovery_frames(source, SOURCE_RELATIVE_PATH)

    assert scanned.valid_prefix_size_bytes == len(first) + len(second)
    assert scanned.invalid_suffix_size_bytes == len(third) - 4
    assert scanned.record_count == 2
    assert [
        row.writer_sequence for frame in scanned.frames for row in frame.envelopes
    ] == [1, 2]


def test_frame_scanner_rejects_bad_checksum_and_later_valid_frame() -> None:
    first = _frame(_envelope(1))
    corrupted = bytearray(_frame(_envelope(2)))
    corrupted[-1] ^= 0xFF
    later = _frame(_envelope(3))
    source = first + bytes(corrupted) + later

    scanned = scan_recovery_frames(source, SOURCE_RELATIVE_PATH)

    assert scanned.valid_prefix_size_bytes == len(first)
    assert scanned.invalid_suffix_size_bytes == len(corrupted) + len(later)
    assert scanned.record_count == 1


@pytest.mark.parametrize(
    "invalid_frame",
    [
        _frame(_envelope(2, instrument_key="ETH-USDT", wire_symbol="ETH-USDT")),
        _frame(_envelope(1)),
        _frame(_envelope(2, received_at_ns=1_785_459_601_000_000_000)),
        _frame(_envelope(2), checksum=False),
    ],
    ids=["cross-identity", "duplicate-sequence", "cross-hour", "missing-checksum"],
)
def test_frame_scanner_stops_before_first_identity_or_codec_violation(
    invalid_frame: bytes,
) -> None:
    first = _frame(_envelope(1))
    later = _frame(_envelope(3))

    scanned = scan_recovery_frames(
        first + invalid_frame + later,
        SOURCE_RELATIVE_PATH,
    )

    assert scanned.valid_prefix_size_bytes == len(first)
    assert scanned.record_count == 1


@pytest.mark.parametrize("source", [b"", b"not-zstd"])
def test_frame_scanner_reports_zero_valid_frames(source: bytes) -> None:
    scanned = scan_recovery_frames(source, SOURCE_RELATIVE_PATH)

    assert scanned.valid_prefix_size_bytes == 0
    assert scanned.invalid_suffix_size_bytes == len(source)
    assert scanned.frames == ()


def test_streaming_scanner_reduces_rows_to_bounded_manifest_facts() -> None:
    first = _frame(_envelope(1))
    second = _frame(_envelope(2))
    source = first + second

    scanned = _scan_recovery_chunks(
        (source[index : index + 1] for index in range(len(source))),
        SOURCE_RELATIVE_PATH,
    )

    assert scanned.source_size_bytes == len(source)
    assert scanned.source_sha256 == hashlib.sha256(source).hexdigest()
    assert scanned.valid_prefix_size_bytes == len(source)
    assert scanned.valid_prefix_sha256 == hashlib.sha256(source).hexdigest()
    assert scanned.invalid_suffix_size_bytes == 0
    assert scanned.invalid_suffix_sha256 is None
    assert scanned.frame_count == 2
    assert scanned.row_facts is not None
    assert scanned.row_facts.record_count == 2
    assert scanned.row_facts.writer_sequence_first == 1
    assert scanned.row_facts.writer_sequence_last == 2
    assert not hasattr(scanned, "envelopes")


def test_streaming_scanner_hashes_corrupt_frame_and_later_bytes_as_suffix() -> None:
    first = _frame(_envelope(1))
    corrupted = bytearray(_frame(_envelope(2)))
    corrupted[-1] ^= 0xFF
    later = _frame(_envelope(3))
    suffix = bytes(corrupted) + later

    scanned = _scan_recovery_chunks(
        (first, bytes(corrupted[:3]), bytes(corrupted[3:]), later),
        SOURCE_RELATIVE_PATH,
    )

    assert scanned.valid_prefix_size_bytes == len(first)
    assert scanned.valid_prefix_sha256 == hashlib.sha256(first).hexdigest()
    assert scanned.invalid_suffix_size_bytes == len(suffix)
    assert scanned.invalid_suffix_sha256 == hashlib.sha256(suffix).hexdigest()
    assert scanned.frame_count == 1
    assert scanned.row_facts is not None
    assert scanned.row_facts.record_count == 1


def test_truncated_partial_plan_freezes_prefix_manifest_and_bad_tail() -> None:
    first = _frame(_envelope(1))
    second = _frame(_envelope(2))
    truncated = _frame(_envelope(3))[:-4]
    source = first + second + truncated

    plan = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )

    assert plan.intent.source_state is RecoverySourceState.PARTIAL_TRUNCATED
    assert plan.intent.planned_source_disposition is RecoverySourceDisposition.REMOVED
    assert plan.recovered_data_bytes == first + second
    assert plan.quarantine_bytes == truncated
    assert plan.manifest is not None
    assert plan.manifest.close_reason.value == "recovery"
    assert plan.manifest.record_count == 2
    assert plan.manifest.recovered_frame_count == 2
    assert plan.manifest.unavailable_fields == RECOVERY_UNAVAILABLE_FIELDS
    assert plan.manifest.file_sha256 == hashlib.sha256(first + second).hexdigest()
    assert plan.manifest.quarantined_suffix_bytes == len(truncated)
    assert plan.manifest.canonical_bytes() == plan.manifest_bytes

    with pytest.raises(ValueError, match="recovered data"):
        type(plan)(
            intent=plan.intent,
            manifest=plan.manifest,
            recovered_data_bytes=b"substituted",
            quarantine_bytes=plan.quarantine_bytes,
        )
    with pytest.raises(ValueError, match="quarantine"):
        type(plan)(
            intent=plan.intent,
            manifest=plan.manifest,
            recovered_data_bytes=plan.recovered_data_bytes,
            quarantine_bytes=b"substituted",
        )


def test_streaming_plan_matches_legacy_fixture_without_retaining_source_bytes() -> None:
    first = _frame(_envelope(1))
    second = _frame(_envelope(2))
    truncated = _frame(_envelope(3))[:-4]
    source = first + second + truncated
    scanned = _scan_recovery_chunks(
        (source[index : index + 7] for index in range(0, len(source), 7)),
        SOURCE_RELATIVE_PATH,
    )

    streaming = _plan_streaming_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        scan=scanned,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )
    legacy = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )

    assert streaming.intent == legacy.intent
    assert streaming.manifest == legacy.manifest
    assert streaming.recovered_range is not None
    assert streaming.recovered_range.start_offset == 0
    assert streaming.recovered_range.size_bytes == len(first) + len(second)
    assert streaming.quarantine_range is not None
    assert streaming.quarantine_range.start_offset == len(first) + len(second)
    assert streaming.quarantine_range.size_bytes == len(truncated)
    assert not hasattr(streaming, "recovered_data_bytes")


def test_complete_partial_plan_allocates_distinct_recovery_generation() -> None:
    source = _frame(_envelope(1))

    plan = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )

    assert plan.intent.source_state is RecoverySourceState.PARTIAL_COMPLETE
    assert plan.quarantine_bytes is None
    assert plan.intent.planned_data_relative_path != SOURCE_RELATIVE_PATH.removesuffix(
        ".partial"
    )
    assert plan.intent.planned_data_generation_id == recovery_generation_id(
        plan.intent.planned_data_relative_path
    )


@pytest.mark.parametrize("source", [b"", b"not-zstd"])
def test_zero_prefix_partial_plan_quarantines_whole_source(source: bytes) -> None:
    plan = plan_recovery_source(
        source_relative_path=SOURCE_RELATIVE_PATH,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )

    assert (
        plan.intent.planned_source_disposition
        is RecoverySourceDisposition.MOVED_TO_QUARANTINE
    )
    assert plan.recovered_data_bytes is None
    assert plan.manifest is None
    assert plan.manifest_bytes is None
    assert plan.quarantine_bytes == source


def test_valid_closed_orphan_is_retained_and_gets_manifest() -> None:
    closed_path = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    source = _frame(_envelope(1))

    plan = plan_recovery_source(
        source_relative_path=closed_path,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )

    assert plan.intent.source_state is RecoverySourceState.ORPHAN_CLOSED_DATA
    assert plan.intent.planned_source_disposition is RecoverySourceDisposition.RETAINED
    assert plan.intent.planned_data_relative_path == closed_path
    assert plan.recovered_data_bytes is None
    assert isinstance(plan.manifest, RawManifestV1)
    assert plan.quarantine_bytes is None


def test_invalid_closed_orphan_is_wholly_quarantined_without_prefix_salvage() -> None:
    closed_path = SOURCE_RELATIVE_PATH.removesuffix(".partial")
    first = _frame(_envelope(1))
    corrupt = _frame(_envelope(2))[:-4]
    source = first + corrupt

    plan = plan_recovery_source(
        source_relative_path=closed_path,
        source=source,
        transaction_id=TRANSACTION_ID,
        created_at_ns=1_785_456_100_000_000_000,
        next_part_sequence=10,
    )

    assert (
        plan.intent.planned_source_disposition
        is RecoverySourceDisposition.MOVED_TO_QUARANTINE
    )
    assert plan.recovered_data_bytes is None
    assert plan.manifest is None
    assert plan.quarantine_bytes == source
