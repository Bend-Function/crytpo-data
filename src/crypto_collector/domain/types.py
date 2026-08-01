from enum import StrEnum


class Exchange(StrEnum):
    BINANCE = "binance"
    OKX = "okx"
    BYBIT = "bybit"
    BITGET = "bitget"
    KRAKEN = "kraken"


class Market(StrEnum):
    SPOT = "spot"
    PERPETUAL = "perpetual"


class Transport(StrEnum):
    REST = "rest"
    WEBSOCKET = "websocket"
    INTERNAL = "internal"


class IntegrityMode(StrEnum):
    SEQUENCE_VERIFIED = "sequence_verified"
    CHECKSUM_VERIFIED = "checksum_verified"
    SNAPSHOT_CHAIN = "snapshot_chain"
    BEST_EFFORT = "best_effort"
    INVALID = "invalid"

    @property
    def is_research_valid(self) -> bool:
        return self is not IntegrityMode.INVALID


class CoverageMode(StrEnum):
    COMPLETE = "complete"
    LOSSY_WINDOW = "lossy_window"
    UNKNOWN = "unknown"


class CloseReason(StrEnum):
    ROTATE_TIME = "rotate_time"
    ROTATE_SIZE = "rotate_size"
    CONFIG_RELOAD = "config_reload"
    SHUTDOWN = "shutdown"
    RECOVERY = "recovery"
    RECOVERY_CONTROL = "recovery_control"
