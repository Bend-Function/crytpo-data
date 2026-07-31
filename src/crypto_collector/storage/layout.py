from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from crypto_collector.domain.envelope import RawEnvelope
from crypto_collector.domain.paths import encode_instrument_key

_NS_PER_SECOND = 1_000_000_000


def _non_negative_int(value: int, *, name: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{name} must be a non-negative integer")
    return value


def _path_segment(value: str, *, name: str) -> str:
    if value in {".", ".."} or "\x00" in value or "/" in value or "\\" in value:
        raise ValueError(f"{name} must be a path-safe segment without traversal")
    return value


def _scope_segments(envelope: RawEnvelope) -> tuple[str, ...]:
    exchange = envelope.exchange.value
    if envelope.logical_stream == "_control":
        return ("raw", exchange, "_control")
    if envelope.market is None:
        raise ValueError("non-control storage records require a market")

    market = envelope.market.value
    stream = _path_segment(envelope.logical_stream, name="logical_stream")
    if envelope.instrument_key is None:
        return ("raw", exchange, market, "_market", stream)

    instrument = encode_instrument_key(envelope.instrument_key)
    return ("raw", exchange, market, instrument, stream)


def raw_partial_path(
    data_root: str | Path,
    envelope: RawEnvelope,
    part_start_ns: int,
    sequence: int,
) -> Path:
    start = _non_negative_int(part_start_ns, name="part_start_ns")
    part_sequence = _non_negative_int(sequence, name="sequence")
    received_seconds = envelope.received_at_ns // _NS_PER_SECOND
    received_at = datetime.fromtimestamp(received_seconds, tz=UTC)
    partition = (
        f"{received_at.year:04d}",
        f"{received_at.month:02d}",
        f"{received_at.day:02d}",
        f"{received_at.hour:02d}",
    )
    filename = f"part-{start}-{part_sequence}.jsonl.zst.partial"

    root = Path(data_root).expanduser().resolve()
    candidate = root.joinpath(
        *_scope_segments(envelope), *partition, filename
    ).resolve()
    if not candidate.is_relative_to(root):
        raise ValueError("raw storage path traversal escaped data_root")
    return candidate
