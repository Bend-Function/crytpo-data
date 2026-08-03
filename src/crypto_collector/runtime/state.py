from enum import StrEnum


class WorkerState(StrEnum):
    STARTING = "starting"
    RUNNING = "running"
    DEGRADED = "degraded"
    PAUSED_WRITER = "paused_writer"
    PAUSED_LOW_DISK = "paused_low_disk"
    STOPPING = "stopping"
    STOPPED = "stopped"
