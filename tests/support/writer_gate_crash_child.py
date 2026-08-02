from __future__ import annotations

import os
import signal
import sys
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Any, NoReturn
from unittest.mock import patch

from crypto_collector.benchmarks import runtime_verifier
from crypto_collector.benchmarks.contracts import (
    GateResourceSamplingRoundV1,
    GateSamplingRoundV1,
    GateStorageHealthSampleV1,
)

CRASH_RETURN_CODE = -signal.SIGKILL


def _crash() -> NoReturn:
    os.kill(os.getpid(), signal.SIGKILL)
    os._exit(128 + signal.SIGKILL)


def _patch_after(stack: ExitStack, function_name: str) -> None:
    original = getattr(runtime_verifier, function_name)

    def crash_after(*args: object, **kwargs: object) -> NoReturn:
        original(*args, **kwargs)
        _crash()

    stack.enter_context(patch.object(runtime_verifier, function_name, crash_after))


def _patch_mid_trace(stack: ExitStack) -> None:
    original = runtime_verifier.iter_plan_events

    def interrupted(plan: Any) -> Iterator[Any]:
        for index, event in enumerate(original(plan)):
            yield event
            if index == 0:
                _crash()

    stack.enter_context(patch.object(runtime_verifier, "iter_plan_events", interrupted))


def _patch_mid_worker_samples(stack: ExitStack) -> None:
    original = runtime_verifier.iter_jsonl_zstd

    def interrupted(*args: Any, **kwargs: Any) -> Iterator[Any]:
        rows = original(*args, **kwargs)
        if len(args) >= 3 and args[2] is GateSamplingRoundV1:
            for index, row in enumerate(rows):
                yield row
                if index == 0:
                    _crash()
            return
        yield from rows

    stack.enter_context(patch.object(runtime_verifier, "iter_jsonl_zstd", interrupted))


def _patch_mid_raw(stack: ExitStack) -> None:
    original = runtime_verifier._iter_bounded_raw_rows

    def interrupted(*args: Any, **kwargs: Any) -> Iterator[Any]:
        for index, row in enumerate(original(*args, **kwargs)):
            yield row
            if index == 0:
                _crash()

    stack.enter_context(
        patch.object(runtime_verifier, "_iter_bounded_raw_rows", interrupted)
    )


def _patch_after_artifact(
    stack: ExitStack,
    model_type: type[object],
) -> None:
    original = runtime_verifier._artifact_rows

    def interrupted(*args: Any, **kwargs: Any) -> Iterator[Any]:
        yield from original(*args, **kwargs)
        if len(args) >= 3 and args[2] is model_type:
            _crash()

    stack.enter_context(patch.object(runtime_verifier, "_artifact_rows", interrupted))


def _patch_after_first_call(stack: ExitStack, function_name: str) -> None:
    original = getattr(runtime_verifier, function_name)
    completed = False

    def interrupted(*args: object, **kwargs: object) -> Any:
        nonlocal completed
        result = original(*args, **kwargs)
        if not completed:
            completed = True
            _crash()
        return result

    stack.enter_context(patch.object(runtime_verifier, function_name, interrupted))


def _patch_after_partial_sync(stack: ExitStack, final_name: str) -> None:
    original = runtime_verifier.publish_no_replace

    def crash_before_link(
        source: Path,
        destination: Path,
        **kwargs: Any,
    ) -> Any:
        if destination.name == final_name:
            _crash()
        return original(source, destination, **kwargs)

    stack.enter_context(
        patch.object(runtime_verifier, "publish_no_replace", crash_before_link)
    )


def _patch_after_receipt(stack: ExitStack) -> None:
    def crash_before_index(*args: object, **kwargs: object) -> NoReturn:
        _crash()

    stack.enter_context(
        patch.object(runtime_verifier, "_publish_runtime_index", crash_before_index)
    )


def _install_crash_phase(stack: ExitStack, phase: str) -> None:
    after_boundaries = {
        "after_primary_documents": "_load_primary_documents",
        "after_trace": "_validate_trace",
        "after_bucket": "_validate_bucket_artifact",
        "after_samples": "_validate_sample_artifacts",
        "after_raw": "_validate_raw_evidence",
    }
    if phase in after_boundaries:
        _patch_after(stack, after_boundaries[phase])
    elif phase == "mid_trace":
        _patch_mid_trace(stack)
    elif phase == "mid_worker_samples":
        _patch_mid_worker_samples(stack)
    elif phase == "after_worker_samples":
        _patch_after_artifact(stack, GateSamplingRoundV1)
    elif phase == "after_resource_samples":
        _patch_after_artifact(stack, GateResourceSamplingRoundV1)
    elif phase == "after_health_samples":
        _patch_after_artifact(stack, GateStorageHealthSampleV1)
    elif phase == "after_first_manifest":
        _patch_after_first_call(stack, "_load_bounded_raw_manifest")
    elif phase == "after_first_raw_part":
        _patch_after_first_call(stack, "_validate_raw_manifest_rows")
    elif phase == "mid_raw":
        _patch_mid_raw(stack)
    elif phase == "after_partial_sync":
        _patch_after_partial_sync(stack, "runtime-receipt.json")
    elif phase == "after_receipt":
        _patch_after_receipt(stack)
    elif phase == "after_index_partial_sync":
        _patch_after_partial_sync(stack, "runtime-index.json")
    elif phase == "after_index":
        _patch_after(stack, "_publish_runtime_index")
    elif phase != "none":
        raise ValueError(f"unknown crash phase: {phase}")


def main(arguments: list[str]) -> int:
    if len(arguments) != 2:
        raise ValueError("usage: writer_gate_crash_child.py RUN_INDEX PHASE")
    run_index_path = Path(arguments[0])
    with ExitStack() as stack:
        _install_crash_phase(stack, arguments[1])
        runtime_verifier.validate_runtime_evidence(
            run_index_path,
            target_probe=None,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
