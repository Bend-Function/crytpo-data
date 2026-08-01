from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from decimal import ROUND_CEILING, Decimal

from crypto_collector.config.models import IngressConfig
from crypto_collector.domain.clock import Clock
from crypto_collector.domain.envelope import (
    NativeEventDraft,
    RawEnvelope,
    SourceContext,
)
from crypto_collector.domain.paths import encode_instrument_key
from crypto_collector.domain.types import Market
from crypto_collector.storage.models import (
    AcceptedRecord,
    AcceptedRecordIdentityV1,
    AdmissionContractError,
    CapacityClass,
    EnqueueResult,
    EnqueueStatus,
    StorageControlAssociationV1,
    StorageLogicalTargetV1,
    StorageScopeError,
    ValidatedControlDraft,
    validate_control_draft,
)
from crypto_collector.storage.serialize import encode_envelope

_MAX_SIGNED_INT64 = 2**63 - 1
ControlAssociationResolver = Callable[
    [ValidatedControlDraft, AcceptedRecordIdentityV1],
    StorageControlAssociationV1 | None,
]


def _integer(value: object, *, field_name: str) -> int:
    if type(value) is not int:
        raise TypeError(f"{field_name} must be an integer")
    if value < 0:
        raise ValueError(f"{field_name} must be non-negative")
    if value > _MAX_SIGNED_INT64:
        raise ValueError(f"{field_name} must fit a signed 64-bit integer")
    return value


def _nonempty(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value or value != value.strip():
        raise ValueError(f"{field_name} must be a normalized nonempty string")
    return value


def _sha256(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("config_sha256 must be 64 lowercase hexadecimal characters")
    return value


class SourceContextError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ResidentBudgetSnapshot:
    resident_record_count: int
    resident_bytes: int
    normal_resident_records: int
    normal_resident_bytes: int
    control_resident_records: int
    control_resident_bytes: int


@dataclass(frozen=True, slots=True)
class _ResidentCharge:
    capacity_class: CapacityClass
    charge_bytes: int


class ResidentBudget:
    def __init__(self, *, worker_max_bytes: int, control_reserve_bytes: int) -> None:
        maximum = _integer(worker_max_bytes, field_name="worker_max_bytes")
        reserve = _integer(
            control_reserve_bytes,
            field_name="control_reserve_bytes",
        )
        if maximum == 0:
            raise ValueError("worker_max_bytes must be positive")
        if reserve == 0 or reserve >= maximum:
            raise ValueError(
                "control_reserve_bytes must be positive and below worker_max_bytes"
            )
        self._worker_max_bytes = maximum
        self._control_reserve_bytes = reserve
        self._charges: dict[tuple[str, int], _ResidentCharge] = {}
        self._normal_resident_records = 0
        self._normal_resident_bytes = 0
        self._control_resident_records = 0
        self._control_resident_bytes = 0

    @classmethod
    def from_config(cls, config: IngressConfig) -> ResidentBudget:
        if type(config) is not IngressConfig:
            raise TypeError("config must be IngressConfig")
        return cls(
            worker_max_bytes=config.worker_max_bytes,
            control_reserve_bytes=config.control_reserve_bytes,
        )

    @property
    def worker_max_bytes(self) -> int:
        return self._worker_max_bytes

    @property
    def control_reserve_bytes(self) -> int:
        return self._control_reserve_bytes

    @property
    def normal_capacity_bytes(self) -> int:
        return self._worker_max_bytes - self._control_reserve_bytes

    @property
    def resident_record_count(self) -> int:
        return self._normal_resident_records + self._control_resident_records

    @property
    def resident_bytes(self) -> int:
        return self._normal_resident_bytes + self._control_resident_bytes

    @property
    def normal_resident_records(self) -> int:
        return self._normal_resident_records

    @property
    def normal_resident_bytes(self) -> int:
        return self._normal_resident_bytes

    @property
    def control_resident_records(self) -> int:
        return self._control_resident_records

    @property
    def control_resident_bytes(self) -> int:
        return self._control_resident_bytes

    def matches_config(self, config: IngressConfig) -> bool:
        if type(config) is not IngressConfig:
            raise TypeError("config must be IngressConfig")
        return (
            self._worker_max_bytes == config.worker_max_bytes
            and self._control_reserve_bytes == config.control_reserve_bytes
        )

    def fits(self, capacity_class: CapacityClass, charge_bytes: int) -> bool:
        if type(capacity_class) is not CapacityClass:
            raise TypeError("capacity_class must be CapacityClass")
        charge = _integer(charge_bytes, field_name="charge_bytes")
        if charge == 0:
            raise ValueError("charge_bytes must be positive")
        if self.resident_bytes + charge > self._worker_max_bytes:
            return False
        if capacity_class is CapacityClass.NORMAL:
            return self._normal_resident_bytes + charge <= self.normal_capacity_bytes
        return True

    @staticmethod
    def _charge_key(identity: AcceptedRecordIdentityV1) -> tuple[str, int]:
        if type(identity) is not AcceptedRecordIdentityV1:
            raise TypeError("identity must be AcceptedRecordIdentityV1")
        return identity.worker_instance_id, identity.acceptance_ordinal

    def reserve(
        self,
        identity: AcceptedRecordIdentityV1,
        *,
        capacity_class: CapacityClass,
        charge_bytes: int,
    ) -> None:
        key = self._charge_key(identity)
        if key in self._charges:
            raise ValueError("duplicate resident charge identity")
        charge = _integer(charge_bytes, field_name="charge_bytes")
        if not self.fits(capacity_class, charge):
            raise ValueError("resident charge exceeds its capacity")
        self._charges[key] = _ResidentCharge(capacity_class, charge)
        if capacity_class is CapacityClass.NORMAL:
            self._normal_resident_records += 1
            self._normal_resident_bytes += charge
        else:
            self._control_resident_records += 1
            self._control_resident_bytes += charge

    def charge_bytes(self, identity: AcceptedRecordIdentityV1) -> int:
        key = self._charge_key(identity)
        try:
            return self._charges[key].charge_bytes
        except KeyError as error:
            raise KeyError("unknown resident charge identity") from error

    def release(self, identity: AcceptedRecordIdentityV1) -> None:
        key = self._charge_key(identity)
        try:
            charge = self._charges.pop(key)
        except KeyError as error:
            raise KeyError("unknown resident charge identity") from error
        if charge.capacity_class is CapacityClass.NORMAL:
            self._normal_resident_records -= 1
            self._normal_resident_bytes -= charge.charge_bytes
        else:
            self._control_resident_records -= 1
            self._control_resident_bytes -= charge.charge_bytes

    def snapshot(self) -> ResidentBudgetSnapshot:
        return ResidentBudgetSnapshot(
            resident_record_count=self.resident_record_count,
            resident_bytes=self.resident_bytes,
            normal_resident_records=self._normal_resident_records,
            normal_resident_bytes=self._normal_resident_bytes,
            control_resident_records=self._control_resident_records,
            control_resident_bytes=self._control_resident_bytes,
        )


@dataclass(frozen=True, slots=True)
class RawIngressSnapshot:
    accepting: bool
    accepted_count: int
    acceptance_ordinal_next: int
    pending_control_association_count: int
    enqueue_high_water_count: int
    normal_overflow_count: int
    control_overflow_count: int
    queues: tuple[tuple[str, int, int], ...]
    next_sequences: tuple[tuple[str, str, str, int], ...]
    resident_budget: ResidentBudgetSnapshot


_SequenceKey = tuple[Market | None, str | None, str]


class RawIngress:
    def __init__(
        self,
        *,
        config: IngressConfig,
        worker_instance_id: str,
        config_sha256: str,
        config_generation: int,
        resident_budget: ResidentBudget,
        clock: Clock,
        control_association_resolver: ControlAssociationResolver | None = None,
    ) -> None:
        if type(config) is not IngressConfig:
            raise TypeError("config must be IngressConfig")
        if type(resident_budget) is not ResidentBudget:
            raise TypeError("resident_budget must be ResidentBudget")
        if not resident_budget.matches_config(config):
            raise ValueError("resident budget must match ingress config")
        if not callable(getattr(clock, "time_ns", None)) or not callable(
            getattr(clock, "monotonic_ns", None)
        ):
            raise TypeError("clock must implement time_ns and monotonic_ns")
        if control_association_resolver is not None and not callable(
            control_association_resolver
        ):
            raise TypeError("control_association_resolver must be callable or None")
        self._config = config
        self._worker_instance_id = _nonempty(
            worker_instance_id,
            field_name="worker_instance_id",
        )
        self._config_sha256 = _sha256(config_sha256)
        self._config_generation = _integer(
            config_generation,
            field_name="config_generation",
        )
        self._resident_budget = resident_budget
        self._clock = clock
        self._control_association_resolver = control_association_resolver
        self._queues: dict[str, asyncio.Queue[EnqueueResult]] = {}
        self._queued_bytes: dict[str, int] = {}
        self._next_sequences: dict[_SequenceKey, int] = {}
        self._next_acceptance_ordinal = 0
        self._pending_control_associations: dict[
            AcceptedRecordIdentityV1,
            StorageControlAssociationV1,
        ] = {}
        self._accepted_count = 0
        self._enqueue_high_water_count = 0
        self._normal_overflow_count = 0
        self._control_overflow_count = 0
        self._superseded = False
        threshold = (
            Decimal(config.worker_max_bytes) * Decimal(str(config.high_water_ratio))
        ).to_integral_value(rounding=ROUND_CEILING)
        self._high_water_bytes = int(threshold)

    @property
    def accepted_count(self) -> int:
        return self._accepted_count

    @property
    def config_generation(self) -> int:
        return self._config_generation

    @property
    def config_sha256(self) -> str:
        return self._config_sha256

    def replacement_for_config(
        self,
        *,
        config_sha256: str,
        config_generation: int,
    ) -> RawIngress:
        next_sha256 = _sha256(config_sha256)
        next_generation = _integer(
            config_generation,
            field_name="config_generation",
        )
        if next_generation <= self._config_generation:
            raise ValueError("config_generation must be strictly greater")
        if self._superseded:
            raise AdmissionContractError("ingress has already been superseded")
        if (
            any(not queue.empty() for queue in self._queues.values())
            or any(self._queued_bytes.values())
            or self._resident_budget.resident_record_count != 0
            or self._pending_control_associations
        ):
            raise AdmissionContractError(
                "config replacement requires a quiescent ingress"
            )

        replacement = RawIngress(
            config=self._config,
            worker_instance_id=self._worker_instance_id,
            config_sha256=next_sha256,
            config_generation=next_generation,
            resident_budget=self._resident_budget,
            clock=self._clock,
            control_association_resolver=self._control_association_resolver,
        )
        replacement._next_sequences = dict(self._next_sequences)
        replacement._next_acceptance_ordinal = self._next_acceptance_ordinal
        replacement._accepted_count = self._accepted_count
        replacement._enqueue_high_water_count = self._enqueue_high_water_count
        replacement._normal_overflow_count = self._normal_overflow_count
        replacement._control_overflow_count = self._control_overflow_count
        self._superseded = True
        return replacement

    @staticmethod
    def _sequence_key(draft: NativeEventDraft) -> _SequenceKey:
        return draft.market, draft.instrument_key, draft.logical_stream

    @staticmethod
    def _classify(
        draft: NativeEventDraft,
    ) -> tuple[CapacityClass, ValidatedControlDraft | None]:
        if draft.logical_stream == "_control":
            return CapacityClass.CONTROL, validate_control_draft(draft)
        return CapacityClass.NORMAL, None

    def _resolve_control_association(
        self,
        control: ValidatedControlDraft | None,
        identity: AcceptedRecordIdentityV1,
    ) -> StorageControlAssociationV1 | None:
        if control is None:
            return None
        resolver = self._control_association_resolver
        if resolver is None:
            if control.association_request is not None:
                raise AdmissionContractError(
                    "storage association request requires an association resolver"
                )
            return None
        association = resolver(control, identity)
        if association is None:
            if control.association_request is not None:
                raise AdmissionContractError(
                    "association resolver did not resolve every requested target"
                )
            return None
        if type(association) is not StorageControlAssociationV1:
            raise TypeError(
                "control association resolver must return "
                "StorageControlAssociationV1 or None"
            )
        if (
            association.control_kind != control.control_kind
            or association.acceptance_ordinal != identity.acceptance_ordinal
            or association.config_generation != identity.config_generation
        ):
            raise AdmissionContractError(
                "resolved control association does not match its candidate identity"
            )
        request = control.association_request
        if (
            request is not None
            and association.control_event_id != request.control_event_id
        ):
            raise AdmissionContractError(
                "resolved control association event ID does not match its request"
            )
        if request is not None and len(association.targets) != len(
            request.target_logical_identities
        ):
            raise AdmissionContractError(
                "resolved control association must cover every requested target"
            )
        if request is not None:
            expected_prefixes = tuple(
                sorted(
                    self._logical_target_path_prefix(identity.exchange.value, target)
                    for target in request.target_logical_identities
                )
            )
            observed_prefixes = tuple(
                sorted(
                    self._association_path_prefix(target.data_relative_path)
                    for target in association.targets
                )
            )
            if observed_prefixes != expected_prefixes:
                raise AdmissionContractError(
                    "resolved control association does not match requested logical "
                    "targets"
                )
        return association

    @staticmethod
    def _logical_target_path_prefix(
        exchange: str,
        target: StorageLogicalTargetV1,
    ) -> tuple[str, ...]:
        market = target.market
        instrument_key = target.instrument_key
        logical_stream = target.logical_stream
        if logical_stream == "_control":
            return "raw", exchange, "_control"
        assert market is not None
        scope = (
            "_market"
            if instrument_key is None
            else encode_instrument_key(instrument_key)
        )
        return "raw", exchange, market.value, scope, logical_stream

    @staticmethod
    def _association_path_prefix(data_relative_path: str) -> tuple[str, ...]:
        parts = tuple(data_relative_path.split("/"))
        if len(parts) >= 3 and parts[2] == "_control":
            return parts[:3]
        return parts[:5]

    @staticmethod
    def _validate_shard(shard: object) -> str:
        return _nonempty(shard, field_name="shard")

    @staticmethod
    def _validate_class_shard(
        capacity_class: CapacityClass,
        shard: str,
    ) -> None:
        if capacity_class is CapacityClass.CONTROL:
            if shard != "_control":
                raise AdmissionContractError(
                    "control capacity requires the _control shard"
                )
        elif shard == "_control":
            raise AdmissionContractError(
                "normal capacity cannot use the _control shard"
            )

    @staticmethod
    def _validate_source(draft: NativeEventDraft, source: SourceContext) -> None:
        if type(source) is not SourceContext:
            raise TypeError("source must be SourceContext")
        try:
            draft.validate_source(source)
        except ValueError as error:
            raise SourceContextError(
                "draft and source context are incompatible"
            ) from error

    def _overflow(self, capacity_class: CapacityClass) -> EnqueueResult:
        if capacity_class is CapacityClass.CONTROL:
            self._control_overflow_count += 1
            status = EnqueueStatus.CONTROL_OVERFLOW
        else:
            self._normal_overflow_count += 1
            status = EnqueueStatus.OVERFLOW
        return EnqueueResult(status=status, record=None, record_identity=None)

    def _build_candidate(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        writer_sequence: int,
        acceptance_ordinal: int,
    ) -> tuple[AcceptedRecord, AcceptedRecordIdentityV1]:
        envelope_values = draft.model_dump(mode="python", warnings=False)
        envelope_values.update(
            {
                "received_at_ns": _integer(
                    self._clock.time_ns(),
                    field_name="clock.time_ns()",
                ),
                "monotonic_ns": _integer(
                    self._clock.monotonic_ns(),
                    field_name="clock.monotonic_ns()",
                ),
                "worker_instance_id": self._worker_instance_id,
                "connection_id": source.connection_id,
                "connection_generation": source.connection_generation,
                "writer_sequence": writer_sequence,
                "egress_id": source.egress_id,
                "config_sha256": self._config_sha256,
            }
        )
        envelope = RawEnvelope.model_validate(envelope_values)
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
            acceptance_ordinal=acceptance_ordinal,
            config_sha256=envelope.config_sha256,
            config_generation=self._config_generation,
        )
        return record, identity

    def try_accept(
        self,
        draft: NativeEventDraft,
        *,
        source: SourceContext,
        shard: str,
    ) -> EnqueueResult:
        if type(draft) is not NativeEventDraft:
            raise TypeError("draft must be NativeEventDraft")
        if self._superseded:
            return EnqueueResult(
                status=EnqueueStatus.NOT_ACCEPTING,
                record=None,
                record_identity=None,
            )
        normalized_shard = self._validate_shard(shard)
        capacity_class, validated_control = self._classify(draft)
        self._validate_class_shard(capacity_class, normalized_shard)
        self._validate_source(draft, source)

        sequence_key = self._sequence_key(draft)
        writer_sequence = self._next_sequences.get(sequence_key, 0)
        acceptance_ordinal = self._next_acceptance_ordinal
        record, identity = self._build_candidate(
            draft,
            source=source,
            writer_sequence=writer_sequence,
            acceptance_ordinal=acceptance_ordinal,
        )
        association = self._resolve_control_association(validated_control, identity)
        association_bytes = (
            b"" if association is None else association.canonical_bytes()
        )
        charge_bytes = len(record.encoded_jsonl) + len(association_bytes)
        queue = self._queues.get(normalized_shard)
        queue_size = 0 if queue is None else queue.qsize()
        queued_bytes = self._queued_bytes.get(normalized_shard, 0)
        if (
            queue_size >= self._config.shard_max_records
            or queued_bytes + charge_bytes > self._config.shard_max_bytes
            or not self._resident_budget.fits(capacity_class, charge_bytes)
        ):
            return self._overflow(capacity_class)

        self._resident_budget.reserve(
            identity,
            capacity_class=capacity_class,
            charge_bytes=charge_bytes,
        )
        created_queue = queue is None
        try:
            status = (
                EnqueueStatus.ACCEPTED_HIGH_WATER
                if self._resident_budget.resident_bytes >= self._high_water_bytes
                else EnqueueStatus.ACCEPTED
            )
            result = EnqueueResult(
                status=status,
                record=record,
                record_identity=identity,
            )
            if created_queue:
                queue = asyncio.Queue(maxsize=self._config.shard_max_records)
                self._queues[normalized_shard] = queue
            assert queue is not None
            queue.put_nowait(result)
        except BaseException as error:
            self._resident_budget.release(identity)
            if (
                created_queue
                and queue is not None
                and self._queues.get(normalized_shard) is queue
                and queue.empty()
            ):
                del self._queues[normalized_shard]
            if isinstance(error, asyncio.QueueFull):
                return self._overflow(capacity_class)
            raise

        if association is not None:
            self._pending_control_associations[identity] = association
        self._queued_bytes[normalized_shard] = queued_bytes + charge_bytes
        self._next_sequences[sequence_key] = writer_sequence + 1
        self._next_acceptance_ordinal = acceptance_ordinal + 1
        self._accepted_count += 1
        if status is EnqueueStatus.ACCEPTED_HIGH_WATER:
            self._enqueue_high_water_count += 1
        return result

    def take_control_association(
        self,
        identity: AcceptedRecordIdentityV1,
    ) -> StorageControlAssociationV1 | None:
        if type(identity) is not AcceptedRecordIdentityV1:
            raise TypeError("identity must be AcceptedRecordIdentityV1")
        return self._pending_control_associations.pop(identity, None)

    def drain_one(self, shard: str) -> EnqueueResult | None:
        normalized_shard = self._validate_shard(shard)
        queue = self._queues.get(normalized_shard)
        if queue is None:
            return None
        try:
            result = queue.get_nowait()
        except asyncio.QueueEmpty:
            return None
        queue.task_done()
        assert result.record is not None
        assert result.record_identity is not None
        charge_bytes = self._resident_budget.charge_bytes(result.record_identity)
        remaining = self._queued_bytes[normalized_shard] - charge_bytes
        if remaining < 0:
            raise AssertionError("ingress queued byte accounting underflow")
        self._queued_bytes[normalized_shard] = remaining
        return result

    def queued_records(self, shard: str) -> int:
        normalized_shard = self._validate_shard(shard)
        queue = self._queues.get(normalized_shard)
        return 0 if queue is None else queue.qsize()

    def queued_bytes(self, shard: str) -> int:
        return self._queued_bytes.get(self._validate_shard(shard), 0)

    def nonempty_shards(self) -> tuple[str, ...]:
        return tuple(
            sorted(shard for shard, queue in self._queues.items() if not queue.empty())
        )

    def snapshot_for_test(self) -> RawIngressSnapshot:
        sequence_rows = tuple(
            sorted(
                (
                    "" if market is None else market.value,
                    "" if instrument is None else instrument,
                    logical_stream,
                    sequence,
                )
                for (market, instrument, logical_stream), sequence in (
                    self._next_sequences.items()
                )
            )
        )
        queue_rows = tuple(
            sorted(
                (
                    shard,
                    queue.qsize(),
                    self._queued_bytes.get(shard, 0),
                )
                for shard, queue in self._queues.items()
            )
        )
        return RawIngressSnapshot(
            accepting=not self._superseded,
            accepted_count=self._accepted_count,
            acceptance_ordinal_next=self._next_acceptance_ordinal,
            pending_control_association_count=len(self._pending_control_associations),
            enqueue_high_water_count=self._enqueue_high_water_count,
            normal_overflow_count=self._normal_overflow_count,
            control_overflow_count=self._control_overflow_count,
            queues=queue_rows,
            next_sequences=sequence_rows,
            resident_budget=self._resident_budget.snapshot(),
        )


__all__ = [
    "AdmissionContractError",
    "CapacityClass",
    "ControlAssociationResolver",
    "RawIngress",
    "RawIngressSnapshot",
    "ResidentBudget",
    "ResidentBudgetSnapshot",
    "SourceContextError",
    "StorageScopeError",
]
