from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path
from typing import get_type_hints

import pytest
import zstandard

import crypto_collector.storage.recovery as recovery_module
from crypto_collector.domain.envelope import NativeEventDraft, RawEnvelope
from crypto_collector.domain.types import Exchange, Market, Transport
from crypto_collector.storage.durability import (
    RecoveryDurabilityCoordinator,
    StorageIoLimiter,
)
from crypto_collector.storage.manifest import (
    RecoverySourceState,
    manifest_path_for_data,
)
from crypto_collector.storage.models import (
    AcceptedRecord,
    AcceptedRecordIdentityV1,
    CanonicalUuid,
    NonEmptyString,
    NormalizedDataRelativePath,
    Sha256,
    StorageControlAssociationV1,
    StorageControlTargetV1,
)
from crypto_collector.storage.recovery import (
    NonNegativeInt,
    PendingRecoveryControl,
    PositiveInt,
    RecoveryControlAdmission,
    RecoveryControlPayloadV1,
    RecoveryControlReceipt,
    RecoveryOutcome,
    RecoveryReconciliation,
    RecoverySourceDisposition,
    bad_tail_quarantine_relative_path,
    recovery_generation_id,
)
from crypto_collector.storage.serialize import encode_envelope

_TRANSACTION_A = "123e4567-e89b-42d3-a456-426614174000"
_TRANSACTION_B = "123e4567-e89b-42d3-a456-426614174001"
_TRANSACTION_C = "123e4567-e89b-42d3-a456-426614174002"
_SOURCE_RELATIVE_PATH = (
    "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/"
    "part-1785456000000000000-0.jsonl.zst.partial"
)
_RECOVERED_RELATIVE_PATH = (
    "raw/okx/spot/BTC-USDT/trade/2026/07/31/00/part-1785456000000000000-1.jsonl.zst"
)
_CONTROL_DATA_RELATIVE_PATH = (
    "raw/okx/_control/2026/07/31/00/part-1785456000000000000-0.jsonl.zst"
)
_CONTROL_MANIFEST_RELATIVE_PATH = manifest_path_for_data(
    _CONTROL_DATA_RELATIVE_PATH
).as_posix()


def _event_id(transaction_id: str) -> str:
    return f"raw-recovery-lineage:v1:{transaction_id}"


def _outcome_values(transaction_id: str = _TRANSACTION_A) -> dict[str, object]:
    return {
        "transaction_id": transaction_id,
        "recovery_control_event_id": _event_id(transaction_id),
        "source_state": RecoverySourceState.PARTIAL_TRUNCATED,
        "source_disposition": RecoverySourceDisposition.REMOVED,
        "source_relative_path": _SOURCE_RELATIVE_PATH,
        "source_sha256": "a" * 64,
        "recovered_generation_id": recovery_generation_id(_RECOVERED_RELATIVE_PATH),
        "recovered_relative_path": _RECOVERED_RELATIVE_PATH,
        "recovered_sha256": "b" * 64,
        "quarantined_relative_path": bad_tail_quarantine_relative_path(
            _SOURCE_RELATIVE_PATH
        ),
        "quarantined_sha256": "c" * 64,
        "informational_only": False,
    }


def _outcome(transaction_id: str = _TRANSACTION_A) -> RecoveryOutcome:
    return RecoveryOutcome(**_outcome_values(transaction_id))  # type: ignore[arg-type]


def _payload(transaction_id: str = _TRANSACTION_A) -> RecoveryControlPayloadV1:
    values = _outcome_values(transaction_id)
    return RecoveryControlPayloadV1(
        recovery_control_event_id=values["recovery_control_event_id"],
        transaction_id=values["transaction_id"],
        source_state=values["source_state"],
        source_disposition=values["source_disposition"],
        source_market=Market.SPOT,
        source_instrument_key="BTC-USDT",
        source_logical_stream="trade",
        source_relative_path=values["source_relative_path"],
        source_sha256=values["source_sha256"],
        recovered_generation_id=values["recovered_generation_id"],
        recovered_relative_path=values["recovered_relative_path"],
        recovered_sha256=values["recovered_sha256"],
        quarantined_relative_path=values["quarantined_relative_path"],
        quarantined_sha256=values["quarantined_sha256"],
        informational_only=values["informational_only"],
        affected_markets=(Market.SPOT,),
    )  # type: ignore[arg-type]


def _draft(transaction_id: str = _TRANSACTION_A) -> NativeEventDraft:
    return NativeEventDraft(
        exchange=Exchange.OKX,
        market=None,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="_control",
        native_channel=None,
        transport=Transport.INTERNAL,
        event_time_ns=None,
        event_time_source=None,
        payload=_payload(transaction_id).model_dump(mode="json"),
    )


def _target() -> StorageControlTargetV1:
    return StorageControlTargetV1(
        generation_id=recovery_generation_id(_RECOVERED_RELATIVE_PATH),
        data_relative_path=_RECOVERED_RELATIVE_PATH,
    )


def _pending(transaction_id: str = _TRANSACTION_A) -> PendingRecoveryControl:
    return PendingRecoveryControl(
        transaction_id=transaction_id,
        recovery_control_event_id=_event_id(transaction_id),
        source_state=RecoverySourceState.PARTIAL_TRUNCATED,
        source_disposition=RecoverySourceDisposition.REMOVED,
        draft=_draft(transaction_id),
        target=_target(),
    )


def _control_record(
    transaction_id: str = _TRANSACTION_A,
) -> tuple[AcceptedRecord, AcceptedRecordIdentityV1]:
    draft = _draft(transaction_id)
    envelope = RawEnvelope(
        **draft.model_dump(mode="python"),
        received_at_ns=1_785_456_001_000_000_000,
        monotonic_ns=20,
        worker_instance_id="worker-1",
        connection_id=None,
        connection_generation=None,
        writer_sequence=9,
        egress_id=None,
        config_sha256="d" * 64,
    )
    record = AcceptedRecord(
        envelope=envelope,
        encoded_jsonl=encode_envelope(envelope),
    )
    identity = AcceptedRecordIdentityV1(
        exchange=envelope.exchange,
        market=envelope.market,
        instrument_key=envelope.instrument_key,
        logical_stream=envelope.logical_stream,
        worker_instance_id=envelope.worker_instance_id,
        writer_sequence=envelope.writer_sequence,
        acceptance_ordinal=4,
        config_sha256=envelope.config_sha256,
        config_generation=3,
    )
    return record, identity


def _admission(transaction_id: str = _TRANSACTION_A) -> RecoveryControlAdmission:
    record, identity = _control_record(transaction_id)
    association = StorageControlAssociationV1(
        control_kind="recovery_reconciled",
        control_event_id=_event_id(transaction_id),
        targets=(_target(),),
        acceptance_ordinal=identity.acceptance_ordinal,
        config_generation=identity.config_generation,
    )
    frame = zstandard.ZstdCompressor(
        level=3,
        write_checksum=True,
        write_content_size=True,
    ).compress(record.encoded_jsonl)
    return RecoveryControlAdmission(
        transaction_id=transaction_id,
        recovery_control_event_id=_event_id(transaction_id),
        control_record=record,
        control_record_identity=identity,
        control_generation_id="control-generation-1",
        control_data_relative_path=_CONTROL_DATA_RELATIVE_PATH,
        control_manifest_relative_path=_CONTROL_MANIFEST_RELATIVE_PATH,
        association=association,
        control_frame_bytes=frame,
        zstd_level=3,
        max_plain_frame_bytes=1_048_576,
    )


def _receipt(transaction_id: str = _TRANSACTION_A) -> RecoveryControlReceipt:
    record, identity = _control_record(transaction_id)
    return RecoveryControlReceipt(
        transaction_id=transaction_id,
        recovery_control_event_id=_event_id(transaction_id),
        control_record_identity=identity,
        control_generation_id="control-generation-1",
        control_data_relative_path=_CONTROL_DATA_RELATIVE_PATH,
        control_encoded_sha256=hashlib.sha256(record.encoded_jsonl).hexdigest(),
        durable_at_monotonic_ns=30,
    )


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("transaction_id", "not-a-uuid"),
        ("recovery_control_event_id", "wrong-event"),
        ("source_state", "partial_truncated"),
        ("source_state", RecoverySourceState.ORPHAN_CLOSED_DATA),
        ("source_disposition", "removed"),
        ("source_relative_path", "not/a/raw/source"),
        ("source_sha256", "A" * 64),
        ("recovered_generation_id", "wrong-generation"),
        ("recovered_sha256", None),
        ("quarantined_sha256", None),
        ("informational_only", 0),
        ("informational_only", True),
    ],
)
def test_recovery_outcome_rejects_invalid_runtime_values(
    field_name: str,
    value: object,
) -> None:
    values = _outcome_values()
    values[field_name] = value

    with pytest.raises((TypeError, ValueError)):
        RecoveryOutcome(**values)  # type: ignore[arg-type]


def test_pending_control_binds_exact_payload_and_target() -> None:
    assert _pending().target == _target()

    with pytest.raises((TypeError, ValueError)):
        replace(_pending(), draft=_draft(_TRANSACTION_B))
    with pytest.raises((TypeError, ValueError)):
        replace(_pending(), target=None)
    with pytest.raises((TypeError, ValueError)):
        replace(_pending(), draft=object())  # type: ignore[arg-type]
    with pytest.raises((TypeError, ValueError)):
        replace(_pending(), source_state="partial_truncated")  # type: ignore[arg-type]


def test_informational_outcome_and_pending_control_have_no_artifact_target() -> None:
    source_path = _SOURCE_RELATIVE_PATH.removesuffix(".partial")
    outcome = RecoveryOutcome(
        transaction_id=_TRANSACTION_A,
        recovery_control_event_id=_event_id(_TRANSACTION_A),
        source_state=RecoverySourceState.CLEANUP_INTENT,
        source_disposition=RecoverySourceDisposition.LEGITIMATELY_MISSING,
        source_relative_path=source_path,
        source_sha256="a" * 64,
        recovered_generation_id=None,
        recovered_relative_path=None,
        recovered_sha256=None,
        quarantined_relative_path=None,
        quarantined_sha256=None,
        informational_only=True,
    )
    payload = RecoveryControlPayloadV1(
        recovery_control_event_id=outcome.recovery_control_event_id,
        transaction_id=outcome.transaction_id,
        source_state=outcome.source_state,
        source_disposition=outcome.source_disposition,
        source_market=Market.SPOT,
        source_instrument_key="BTC-USDT",
        source_logical_stream="trade",
        source_relative_path=outcome.source_relative_path,
        source_sha256=outcome.source_sha256,
        recovered_generation_id=None,
        recovered_relative_path=None,
        recovered_sha256=None,
        quarantined_relative_path=None,
        quarantined_sha256=None,
        informational_only=True,
        affected_markets=(Market.SPOT,),
    )
    draft = _draft().model_copy(update={"payload": payload.model_dump(mode="json")})
    pending = PendingRecoveryControl(
        transaction_id=outcome.transaction_id,
        recovery_control_event_id=outcome.recovery_control_event_id,
        source_state=outcome.source_state,
        source_disposition=outcome.source_disposition,
        draft=draft,
        target=None,
    )

    assert pending.target is None


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("recovery_control_event_id", "wrong-event"),
        ("control_generation_id", ""),
        ("control_manifest_relative_path", "raw/okx/wrong.manifest.json"),
        ("association", None),
        ("control_frame_bytes", b"not-zstd"),
        ("zstd_level", True),
        ("zstd_level", 0),
        ("zstd_level", 23),
        ("max_plain_frame_bytes", True),
        ("max_plain_frame_bytes", 0),
    ],
)
def test_control_admission_rejects_unbound_or_invalid_values(
    field_name: str,
    value: object,
) -> None:
    admission = _admission()

    with pytest.raises((TypeError, ValueError)):
        replace(admission, **{field_name: value})


def test_control_admission_rejects_record_and_identity_disagreement() -> None:
    admission = _admission()
    wrong_record = AcceptedRecord(
        envelope=admission.control_record.envelope,
        encoded_jsonl=b"{}\n",
    )
    wrong_identity = admission.control_record_identity.model_copy(
        update={"writer_sequence": 10}
    )

    with pytest.raises((TypeError, ValueError)):
        replace(admission, control_record=wrong_record)
    with pytest.raises((TypeError, ValueError)):
        replace(admission, control_record_identity=wrong_identity)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("transaction_id", "not-a-uuid"),
        ("recovery_control_event_id", "wrong-event"),
        ("control_record_identity", object()),
        ("control_generation_id", ""),
        ("control_data_relative_path", _RECOVERED_RELATIVE_PATH),
        ("control_encoded_sha256", "A" * 64),
        ("durable_at_monotonic_ns", True),
        ("durable_at_monotonic_ns", -1),
    ],
)
def test_control_receipt_rejects_invalid_runtime_values(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises((TypeError, ValueError)):
        replace(_receipt(), **{field_name: value})


def test_reconciliation_requires_ordered_unique_disjoint_tuples() -> None:
    completed_a = _outcome(_TRANSACTION_A)
    completed_c = _outcome(_TRANSACTION_C)
    pending_b = _pending(_TRANSACTION_B)
    reconciliation = RecoveryReconciliation(
        completed_outcomes=(completed_a,),
        pending_controls=(pending_b,),
    )
    assert reconciliation.completed_outcomes == (completed_a,)
    assert RecoveryReconciliation((), ()) == RecoveryReconciliation((), ())

    invalid_values = (
        {"completed_outcomes": [completed_a]},
        {"completed_outcomes": (object(),)},
        {"completed_outcomes": (completed_c, completed_a)},
        {"completed_outcomes": (completed_a, completed_a)},
        {"pending_controls": (_pending(_TRANSACTION_C), pending_b)},
        {
            "completed_outcomes": (completed_a,),
            "pending_controls": (_pending(_TRANSACTION_A),),
        },
    )
    for overrides in invalid_values:
        values: dict[str, object] = {
            "completed_outcomes": reconciliation.completed_outcomes,
            "pending_controls": reconciliation.pending_controls,
        }
        values.update(overrides)
        with pytest.raises((TypeError, ValueError)):
            RecoveryReconciliation(**values)  # type: ignore[arg-type]


class _Clock:
    def time_ns(self) -> int:
        return 1

    def monotonic_ns(self) -> int:
        return 2


class _SourceDispositionResolver:
    def resolve_missing(self, **_values: object) -> None:
        return None


def test_recovery_context_validates_dependencies_and_backend_signatures(
    tmp_path: Path,
) -> None:
    context_type = getattr(recovery_module, "RecoveryContext", None)
    assert context_type is not None
    coordinator = object.__new__(RecoveryDurabilityCoordinator)

    with ThreadPoolExecutor(max_workers=1) as executor:
        values = {
            "data_root": tmp_path / "data",
            "state_root": tmp_path / "state",
            "exchange": Exchange.OKX,
            "worker_instance_id": "worker-1",
            "config_sha256": "d" * 64,
            "config_generation": 3,
            "clock": _Clock(),
            "io_limiter": StorageIoLimiter(max_concurrency=1),
            "recovery_coordinator": coordinator,
            "storage_executor": executor,
            "source_disposition_resolver": _SourceDispositionResolver(),
        }
        context = context_type(**values)
        assert context.exchange is Exchange.OKX

        invalid_values = (
            {"data_root": "data"},
            {"exchange": "okx"},
            {"worker_instance_id": ""},
            {"config_sha256": "D" * 64},
            {"config_generation": True},
            {"clock": object()},
            {"io_limiter": object()},
            {"recovery_coordinator": object()},
            {"storage_executor": object()},
            {"source_disposition_resolver": object()},
        )
        for overrides in invalid_values:
            with pytest.raises((TypeError, ValueError)):
                context_type(**(values | overrides))

    assert "RecoveryContext" in recovery_module.__all__
    backend_methods = (
        recovery_module.RecoveryBackend.reconcile,
        recovery_module.RecoveryBackend.bind_control_ownership,
        recovery_module.RecoveryBackend.acknowledge_control_durable,
    )
    for method in backend_methods:
        assert get_type_hints(method)["context"] is context_type


def test_public_recovery_dataclasses_expose_the_planned_annotated_types() -> None:
    expected_annotations = {
        RecoveryOutcome: {
            "transaction_id": CanonicalUuid,
            "recovery_control_event_id": NonEmptyString,
            "source_relative_path": NormalizedDataRelativePath,
            "source_sha256": Sha256,
            "recovered_generation_id": NonEmptyString | None,
            "recovered_relative_path": NormalizedDataRelativePath | None,
            "recovered_sha256": Sha256 | None,
            "quarantined_relative_path": NormalizedDataRelativePath | None,
            "quarantined_sha256": Sha256 | None,
        },
        PendingRecoveryControl: {
            "transaction_id": CanonicalUuid,
            "recovery_control_event_id": NonEmptyString,
        },
        RecoveryControlAdmission: {
            "transaction_id": CanonicalUuid,
            "recovery_control_event_id": NonEmptyString,
            "control_generation_id": NonEmptyString,
            "control_data_relative_path": NormalizedDataRelativePath,
            "control_manifest_relative_path": NormalizedDataRelativePath,
            "max_plain_frame_bytes": PositiveInt,
        },
        RecoveryControlReceipt: {
            "transaction_id": CanonicalUuid,
            "recovery_control_event_id": NonEmptyString,
            "control_generation_id": NonEmptyString,
            "control_data_relative_path": NormalizedDataRelativePath,
            "control_encoded_sha256": Sha256,
            "durable_at_monotonic_ns": NonNegativeInt,
        },
    }
    for model, expected in expected_annotations.items():
        annotations = get_type_hints(model, include_extras=True)
        for field_name, annotation in expected.items():
            assert annotations[field_name] == annotation


def test_exact_public_recovery_contract_values_are_accepted() -> None:
    assert _outcome().transaction_id == _TRANSACTION_A
    assert _pending().draft.logical_stream == "_control"
    assert _admission().control_record.envelope.logical_stream == "_control"
    assert _receipt().durable_at_monotonic_ns == 30
