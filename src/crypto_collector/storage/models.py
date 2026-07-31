from dataclasses import dataclass

from crypto_collector.domain.envelope import RawEnvelope


@dataclass(frozen=True, slots=True)
class AcceptedRecord:
    envelope: RawEnvelope
    encoded_jsonl: bytes

    @property
    def accepted_monotonic_ns(self) -> int:
        return self.envelope.monotonic_ns
