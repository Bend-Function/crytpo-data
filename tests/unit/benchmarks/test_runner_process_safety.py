from __future__ import annotations

import pytest

from crypto_collector.benchmarks import runner


class _AbortEvent:
    def __init__(self) -> None:
        self.requested = False

    def is_set(self) -> bool:
        return self.requested

    def set(self) -> None:
        self.requested = True


class _Process:
    def __init__(self, name: str, *, start_error: bool = False) -> None:
        self.name = name
        self.pid = 100
        self.start_error = start_error
        self.started = False
        self.alive = False
        self.terminated = False
        self.killed = False
        self.join_count = 0

    def start(self) -> None:
        if self.start_error:
            raise OSError("injected start failure")
        self.started = True
        self.alive = True

    def is_alive(self) -> bool:
        return self.alive

    def terminate(self) -> None:
        self.terminated = True
        self.alive = False

    def kill(self) -> None:
        self.killed = True
        self.alive = False

    def join(self, timeout: float) -> None:
        assert timeout >= 0
        self.join_count += 1


class _IdleConnection:
    def __init__(self) -> None:
        self.recv_called = False

    def poll(self, timeout: float) -> bool:
        assert timeout == 0
        return False

    def recv(self) -> object:
        self.recv_called = True
        raise AssertionError("aborted command wait called recv")


@pytest.mark.asyncio
async def test_child_command_wait_observes_global_abort_without_blocking_recv() -> None:
    event = _AbortEvent()
    event.set()
    connection = _IdleConnection()

    with pytest.raises(runner.WriterGateRunError, match="aborted"):
        await runner._receive_child_command(  # type: ignore[attr-defined]
            connection,  # type: ignore[arg-type]
            abort_event=event,
            timeout_seconds=60,
            expected_kind="start",
        )

    assert connection.recv_called is False


def test_partial_process_start_aborts_every_process_that_started() -> None:
    event = _AbortEvent()
    first = _Process("first")
    failing = _Process("failing", start_error=True)
    never_started = _Process("never-started")

    with pytest.raises(OSError, match="injected start failure"):
        runner._start_processes(  # type: ignore[attr-defined]
            (first, failing, never_started),
            event,
        )

    assert event.is_set()
    assert first.started and first.terminated and first.join_count == 1
    assert not failing.started
    assert not never_started.started


def test_abort_processes_continues_after_one_signal_failure() -> None:
    class _SignalFailureProcess(_Process):
        def terminate(self) -> None:
            self.terminated = True
            raise OSError("injected terminate failure")

    failing = _SignalFailureProcess("failing")
    healthy = _Process("healthy")
    failing.started = failing.alive = True
    healthy.started = healthy.alive = True

    errors = runner._abort_processes(  # type: ignore[attr-defined]
        (failing, healthy)
    )

    assert any(error.startswith("terminate:failing") for error in errors)
    assert failing.killed
    assert healthy.terminated
    assert not failing.alive and not healthy.alive


def test_runner_cleanup_attempts_every_resource_after_one_failure() -> None:
    class _Database:
        def close(self) -> None:
            raise OSError("injected database close failure")

    class _Closeable:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class _Queue(_Closeable):
        def __init__(self) -> None:
            super().__init__()
            self.joined = False

        def join_thread(self) -> None:
            self.joined = True

    parent = _Closeable()
    child = _Closeable()
    status_queue = _Queue()

    errors = runner._close_runner_resources(  # type: ignore[attr-defined]
        join_database=_Database(),  # type: ignore[arg-type]
        parent_commands=(parent,),  # type: ignore[arg-type]
        child_connections=(child,),  # type: ignore[arg-type]
        result_queue=status_queue,
    )

    assert len(errors) == 1
    assert parent.closed and child.closed
    assert status_queue.closed and status_queue.joined
