from __future__ import annotations

import asyncio
import random
from collections import defaultdict
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from dataclasses import field as dataclass_field
from enum import Enum
from hashlib import sha256
from typing import Any, TypeVar, cast
from uuid import uuid4

from httpx import Response
from websockets.exceptions import WebSocketException

from crypto_collector.domain import (
    CoverageMode,
    Exchange,
    IntegrityMode,
    Market,
    NativeEventDraft,
    SourceContext,
    Transport,
)
from crypto_collector.domain.json_codec import JsonPayload
from crypto_collector.exchanges.contracts import (
    AdapterPlan,
    AdapterRuntime,
    EventSink,
    NetworkAdmissionExpired,
    NetworkAdmissionLease,
    NetworkAdmissionPort,
    NetworkAdmissionReleaseDisposition,
    NetworkAdmissionReleaseError,
    PublicQueryValue,
    RestPlanItem,
    WebSocketSubscription,
)
from crypto_collector.exchanges.okx.book import OkxBookParseError, OkxBookState
from crypto_collector.exchanges.okx.catalog import parse_instruments
from crypto_collector.exchanges.okx.errors import (
    OkxPayloadError,
    OkxResponseError,
    okx_response_body_evidence,
)
from crypto_collector.exchanges.okx.rest import (
    OkxRestCapture,
    OkxRestRequest,
    candles_request,
    capture_okx_response,
    deep_book_request,
    derivative_reference_request,
    instruments_request,
    okx_rate_limit_headers,
    parse_candles,
    parse_deep_book,
    parse_derivative_reference,
)
from crypto_collector.exchanges.okx.ws import (
    OkxWsMessage,
    OkxWsMessageKind,
    OkxWsReconnectPolicy,
    OkxWsReconnectReason,
    OkxWsSession,
    OkxWsSessionAction,
    parse_incremental_book_frames,
    subscription_argument,
)
from crypto_collector.network import (
    RetryAction,
    RetryClassification,
    RetryDecision,
    RetryPolicy,
    retry_policy,
)
from crypto_collector.scheduler import (
    CapacityError,
    RestBudgetRoute,
    RestDispatch,
    RestJob,
    StableCadence,
    SubmitResult,
)
from crypto_collector.selection import (
    CompleteCatalogSnapshot,
    InstrumentRecord,
    LifecyclePhase,
)
from crypto_collector.storage import EnqueueStatus

_NANOSECONDS_PER_SECOND = 1_000_000_000
_HTTP_TIMEOUT_SECONDS = 10.0
_CATALOG_DEADLINE_NS = 30_000_000_000
_MAX_SIGNED_64 = 2**63 - 1
_NETWORK_ADMISSION_RELEASE_FAILURE_NOTE = "network admission release also failed"
_SINK_FAILURE_NOTE = "OKX event sink failure"
_COMMITTED_SUBMIT_RESULTS = frozenset(
    {
        SubmitResult.ENQUEUED,
        SubmitResult.IDEMPOTENT,
        SubmitResult.REPLACED,
        SubmitResult.EVICTED_AND_ENQUEUED,
    }
)

_T = TypeVar("_T")
_WsGroupKey = tuple[Market, str, str, str, str]
_OKX_WS_CHANNELS_BY_STREAM = {
    "instrument": frozenset({"instruments"}),
    "status": frozenset({"status"}),
    "liquidation": frozenset({"liquidation-orders"}),
    "book_live": frozenset({"books", "books-rpi"}),
    "trade": frozenset({"trades-all"}),
    "ticker": frozenset({"tickers"}),
    "bbo": frozenset({"bbo-tbt"}),
    "mark_price": frozenset({"mark-price"}),
    "index_ticker": frozenset({"index-tickers"}),
    "funding_rate": frozenset({"funding-rate"}),
    "open_interest": frozenset({"open-interest"}),
    "price_limit": frozenset({"price-limit"}),
}
_OKX_REST_LOGICAL_ENDPOINTS = {
    "book_deep_snapshot": "books-full",
    "candle_1m": "candles",
    "premium": "premium-history",
    "insurance_fund": "insurance-fund",
    "instrument": "instruments",
}
_OKX_DERIVATIVE_STREAMS = frozenset(
    {
        "liquidation",
        "mark_price",
        "index_ticker",
        "funding_rate",
        "open_interest",
        "price_limit",
        "premium",
        "insurance_fund",
    }
)


class OkxExecutionError(RuntimeError):
    pass


class _WsGenerationError(OkxExecutionError):
    pass


class _SinkRejectedError(OkxExecutionError):
    pass


class _NoHealthyRestRoute(OkxExecutionError):
    pass


class _DeadlineElapsed(TimeoutError):
    pass


class _ResponseContractError(OkxExecutionError):
    pass


class _StopTokenContractError(OkxExecutionError):
    pass


def _clock_ns(clock: object, method: str) -> int:
    value = getattr(clock, method)()
    if type(value) is not int or not 0 <= value <= _MAX_SIGNED_64:
        raise ValueError(f"clock.{method}() must return a signed 64-bit nanosecond")
    return value


def _monotonic_ns(runtime: AdapterRuntime) -> int:
    return _clock_ns(runtime.clock, "monotonic_ns")


def _wall_time_ns(runtime: AdapterRuntime) -> int:
    return _clock_ns(runtime.clock, "time_ns")


class _ValidatedClock:
    __slots__ = ("_clock",)

    def __init__(self, clock: object) -> None:
        self._clock = clock

    def time_ns(self) -> int:
        return _clock_ns(self._clock, "time_ns")

    def monotonic_ns(self) -> int:
        return _clock_ns(self._clock, "monotonic_ns")


def _stop_is_set(stop: object) -> bool:
    value = cast(Any, stop).is_set()
    if type(value) is not bool:
        raise TypeError("stop.is_set() must return bool")
    return value


def _validate_harvested_stop_waiter(
    task: asyncio.Task[None] | None,
    stop: object,
) -> None:
    if task is None or not task.done() or task.cancelled():
        return
    if task.exception() is not None:
        return
    if not _stop_is_set(stop):
        raise _StopTokenContractError("stop wait returned before the token was set")


class _CombinedStopToken:
    def __init__(self, external: object, internal: asyncio.Event) -> None:
        self._external = external
        self._internal = internal

    def is_set(self) -> bool:
        return _stop_is_set(self._external) or self._internal.is_set()

    async def wait(self) -> None:
        if self.is_set():
            return
        tasks: list[asyncio.Task[object]] = []
        external_task: asyncio.Task[None] | None = None
        try:
            external_task = _create_owned_task(
                self._external.wait(),  # type: ignore[attr-defined]
                tasks,
            )
            _create_owned_task(self._internal.wait(), tasks)
            await asyncio.wait(tuple(tasks), return_when=asyncio.FIRST_COMPLETED)
        finally:
            cleanup_error: BaseException | None = None
            try:
                cleanup_errors = await _cancel_and_collect(tasks)
            except BaseException as error:  # noqa: BLE001 - owned task harvest.
                cleanup_errors = ()
                cleanup_error = error
            _validate_harvested_stop_waiter(external_task, self._external)
            if cleanup_error is not None:
                raise cleanup_error
            if cleanup_errors:
                raise cleanup_errors[0]
        if not self.is_set():
            raise _StopTokenContractError("stop wait returned before the token was set")


def _stable_seed(*parts: str) -> int:
    digest = sha256("\0".join(parts).encode("utf-8")).digest()
    return int.from_bytes(digest[:16], "big")


def _full_url(endpoint: str, path: str) -> str:
    return endpoint.rstrip("/") + path


def _create_owned_task(
    coroutine: Coroutine[Any, Any, _T],
    owned: list[asyncio.Task[object]],
) -> asyncio.Task[_T]:
    try:
        task = asyncio.create_task(coroutine)
    except BaseException:
        coroutine.close()
        raise
    owned.append(cast(asyncio.Task[object], task))
    return task


async def _cancel_and_collect(
    tasks: Sequence[asyncio.Task[object]],
) -> tuple[BaseException, ...]:
    if not tasks:
        return ()
    for task in tasks:
        if not task.done():
            task.cancel()
    settlement = asyncio.gather(*tasks, return_exceptions=True)
    cancellation: asyncio.CancelledError | None = None
    while not settlement.done():
        try:
            await asyncio.shield(settlement)
        except asyncio.CancelledError as error:
            if cancellation is None:
                cancellation = error
    results = settlement.result()
    release_failed = any(
        bool(getattr(task, "_okx_network_admission_release_failed", False))
        for task in tasks
    )
    if cancellation is not None:
        if release_failed:
            cancellation.add_note(_NETWORK_ADMISSION_RELEASE_FAILURE_NOTE)
        raise cancellation
    errors = tuple(
        result
        for result in results
        if isinstance(result, BaseException)
        and not isinstance(result, asyncio.CancelledError)
    )
    if release_failed:
        return (
            *errors,
            NetworkAdmissionReleaseError("network admission release failed"),
        )
    return errors


async def _cancel_and_join(tasks: Sequence[asyncio.Task[object]]) -> None:
    errors = await _cancel_and_collect(tasks)
    if errors:
        raise errors[0]


async def _await_or_stop(
    awaitable: Awaitable[_T],
    runtime: AdapterRuntime,
) -> _T | None:
    async def resolve() -> _T:
        return await awaitable

    try:
        already_stopped = _stop_is_set(runtime.stop)
    except BaseException:
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise
    if already_stopped:
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        return None
    tasks: list[asyncio.Task[object]] = []
    operation_owned = False
    primary_error: BaseException | None = None
    stopped: asyncio.Task[None] | None = None
    try:
        stopped = _create_owned_task(runtime.stop.wait(), tasks)
        operation = _create_owned_task(resolve(), tasks)
        operation_owned = True
        done, _pending = await asyncio.wait(
            tuple(tasks),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stopped in done:
            try:
                await stopped
            except asyncio.CancelledError:
                if not _stop_is_set(runtime.stop):
                    raise _StopTokenContractError(
                        "stop wait was cancelled before the token was set"
                    ) from None
                raise
            if not _stop_is_set(runtime.stop):
                raise _StopTokenContractError(
                    "stop wait returned before the token was set"
                )
        if operation in done:
            return await operation
        if stopped in done:
            return None
        if _stop_is_set(runtime.stop):
            return None
        raise RuntimeError("OKX stop-aware wait ended without a completed task")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if not operation_owned and asyncio.iscoroutine(awaitable):
            awaitable.close()
        cleanup_failure: BaseException | None = None
        try:
            cleanup_errors = await _cancel_and_collect(tasks)
        except BaseException as error:  # noqa: BLE001 - owned task harvest.
            cleanup_errors = ()
            cleanup_failure = error
        try:
            _validate_harvested_stop_waiter(stopped, runtime.stop)
        except BaseException:
            if primary_error is None or isinstance(
                primary_error, asyncio.CancelledError
            ):
                raise
            primary_error.add_note("OKX stop waiter contract also failed")
        cleanup_error = next(
            (error for error in cleanup_errors if error is not primary_error),
            cleanup_failure,
        )
        if cleanup_error is not None:
            if primary_error is None:
                raise cleanup_error
            primary_error.add_note("OKX stop-aware task cleanup also failed")


async def _await_or_stop_until(
    awaitable: Awaitable[_T],
    runtime: AdapterRuntime,
    *,
    deadline_ns: int,
) -> _T | None:
    async def resolve() -> _T:
        return await awaitable

    try:
        if _stop_is_set(runtime.stop):
            if asyncio.iscoroutine(awaitable):
                awaitable.close()
            return None
        now_ns = _monotonic_ns(runtime)
    except BaseException:
        if asyncio.iscoroutine(awaitable):
            awaitable.close()
        raise
    timeout_seconds = max(0, deadline_ns - now_ns + 1) / _NANOSECONDS_PER_SECOND
    tasks: list[asyncio.Task[object]] = []
    operation_owned = False
    primary_error: BaseException | None = None
    stopped: asyncio.Task[None] | None = None
    try:
        stopped = _create_owned_task(runtime.stop.wait(), tasks)
        operation = _create_owned_task(resolve(), tasks)
        operation_owned = True
        _create_owned_task(asyncio.sleep(timeout_seconds), tasks)
        done, _pending = await asyncio.wait(
            tuple(tasks),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if stopped in done:
            try:
                await stopped
            except asyncio.CancelledError:
                if not _stop_is_set(runtime.stop):
                    raise _StopTokenContractError(
                        "stop wait was cancelled before the token was set"
                    ) from None
                raise
            if not _stop_is_set(runtime.stop):
                raise _StopTokenContractError(
                    "stop wait returned before the token was set"
                )
        if operation in done:
            return await operation
        if stopped in done:
            return None
        if _stop_is_set(runtime.stop):
            return None
        raise _DeadlineElapsed("OKX REST scheduler wait exceeded its deadline")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        if not operation_owned and asyncio.iscoroutine(awaitable):
            awaitable.close()
        cleanup_failure: BaseException | None = None
        try:
            cleanup_errors = await _cancel_and_collect(tasks)
        except BaseException as error:  # noqa: BLE001 - owned task harvest.
            cleanup_errors = ()
            cleanup_failure = error
        try:
            _validate_harvested_stop_waiter(stopped, runtime.stop)
        except BaseException:
            if primary_error is None or isinstance(
                primary_error, asyncio.CancelledError
            ):
                raise
            primary_error.add_note("OKX stop waiter contract also failed")
        cleanup_error = next(
            (error for error in cleanup_errors if error is not primary_error),
            cleanup_failure,
        )
        if cleanup_error is not None:
            if primary_error is None:
                raise cleanup_error
            primary_error.add_note("OKX deadline task cleanup also failed")


def _require_network_admission(runtime: AdapterRuntime) -> NetworkAdmissionPort:
    admission = runtime.network_admission
    if admission is None:
        raise RuntimeError("OKX planned network work requires network admission")
    return admission


async def _cancel_and_harvest_admission_waiters(
    waiters: Sequence[asyncio.Task[object]],
) -> tuple[list[object], asyncio.CancelledError | None]:
    for waiter in waiters:
        if not waiter.done():
            waiter.cancel()
    settlement = asyncio.gather(*waiters, return_exceptions=True)
    cancellation: asyncio.CancelledError | None = None
    while not settlement.done():
        try:
            await asyncio.shield(settlement)
        except asyncio.CancelledError as error:
            if cancellation is None:
                cancellation = error
    return settlement.result(), cancellation


async def _acquire_network_lease(
    *,
    runtime: AdapterRuntime,
    exchange: Exchange,
    transport: Transport,
    egress_id: str,
    quota_group: str,
    deadline_ns: int | None,
) -> NetworkAdmissionLease | None:
    admission = _require_network_admission(runtime)
    if _stop_is_set(runtime.stop):
        return None
    timeout_seconds: float | None = None
    if deadline_ns is not None:
        now_ns = _monotonic_ns(runtime)
        if now_ns > deadline_ns:
            raise NetworkAdmissionExpired("network admission deadline has expired")
        timeout_seconds = max(0, deadline_ns - now_ns + 1) / _NANOSECONDS_PER_SECOND
    operation: asyncio.Task[NetworkAdmissionLease] | None = None
    stopped: asyncio.Task[None] | None = None
    timeout: asyncio.Task[None] | None = None
    waiters: list[asyncio.Task[object]] = []
    timed_out = False
    operation_completed = False
    initially_stopped = False
    cancelled: asyncio.CancelledError | None = None
    setup_error: BaseException | None = None
    try:
        stopped = _create_owned_task(runtime.stop.wait(), waiters)
        operation = _create_owned_task(
            admission.acquire(  # type: ignore[attr-defined]
                exchange=exchange,
                transport=transport,
                egress_id=egress_id,
                quota_group=quota_group,
                deadline_monotonic_ns=deadline_ns,
            ),
            waiters,
        )
        if timeout_seconds is not None:
            timeout = _create_owned_task(asyncio.sleep(timeout_seconds), waiters)
        done, _pending = await asyncio.wait(
            tuple(waiters),
            return_when=asyncio.FIRST_COMPLETED,
        )
        if operation in done:
            operation_completed = True
        else:
            timed_out = timeout is not None and timeout in done
        initially_stopped = stopped in done
    except asyncio.CancelledError as error:
        cancelled = error
    except BaseException as error:  # noqa: BLE001 - task setup is an ownership edge.
        setup_error = error
    results, cleanup_cancellation = await _cancel_and_harvest_admission_waiters(waiters)
    if cancelled is None:
        cancelled = cleanup_cancellation

    result_by_task = dict(zip(waiters, results, strict=True))
    operation_result = result_by_task.get(operation) if operation is not None else None
    cleanup_candidate = (
        operation_result
        if isinstance(operation_result, NetworkAdmissionLease)
        else None
    )
    lease = (
        operation_result if type(operation_result) is NetworkAdmissionLease else None
    )
    stop_contract_error: BaseException | None = None
    try:
        _validate_harvested_stop_waiter(stopped, runtime.stop)
    except BaseException as error:  # noqa: BLE001 - validate an untrusted stop port.
        stop_contract_error = error
    if (
        stop_contract_error is None
        and initially_stopped
        and stopped is not None
        and isinstance(
            result_by_task.get(cast(asyncio.Task[object], stopped)),
            asyncio.CancelledError,
        )
    ):
        try:
            if not _stop_is_set(runtime.stop):
                raise _StopTokenContractError(
                    "stop wait was cancelled before the token was set"
                )
        except BaseException as error:  # noqa: BLE001 - validate an untrusted stop port.
            stop_contract_error = error
    if isinstance(operation_result, BaseException) and not isinstance(
        operation_result,
        asyncio.CancelledError,
    ):
        raise operation_result
    if setup_error is not None:
        if cleanup_candidate is not None:
            await _close_preserving(cleanup_candidate, setup_error)
        raise setup_error
    if stop_contract_error is not None:
        if cleanup_candidate is not None:
            await _close_preserving(cleanup_candidate, stop_contract_error)
        raise stop_contract_error
    if cancelled is not None:
        if cleanup_candidate is not None:
            await _close_preserving(cleanup_candidate, cancelled)
        raise cancelled
    waiter_error = next(
        (
            cast(BaseException, result_by_task[waiter])
            for waiter in (stopped, timeout)
            if waiter is not None
            and isinstance(result_by_task.get(waiter), BaseException)
            and not isinstance(result_by_task[waiter], asyncio.CancelledError)
        ),
        None,
    )
    if waiter_error is not None:
        if cleanup_candidate is not None:
            await _close_preserving(cleanup_candidate, waiter_error)
        raise waiter_error
    if operation_completed and lease is None:
        if cleanup_candidate is not None:
            invalid_lease_error = TypeError(
                "network admission acquire() must return NetworkAdmissionLease"
            )
            await _fail_closed_preserving(cleanup_candidate, invalid_lease_error)
            raise invalid_lease_error
        raise TypeError("network admission acquire() must return NetworkAdmissionLease")
    try:
        stopped_now = _stop_is_set(runtime.stop)
    except BaseException as error:
        if cleanup_candidate is not None:
            await _close_preserving(cleanup_candidate, error)
        raise
    if stopped_now:
        if cleanup_candidate is not None:
            await _close_network_lease(cleanup_candidate)
        return None
    if not operation_completed:
        if timed_out:
            admission_expired = NetworkAdmissionExpired(
                "network admission deadline has expired"
            )
            if cleanup_candidate is not None:
                await _close_preserving(cleanup_candidate, admission_expired)
            raise admission_expired
        if cleanup_candidate is not None:
            await _close_network_lease(cleanup_candidate)
        return None
    assert lease is not None
    expected = (exchange, transport, egress_id, quota_group)
    try:
        actual = (
            lease.exchange,
            lease.transport,
            lease.egress_id,
            lease.quota_group,
        )
        if actual != expected:
            route_error = RuntimeError(
                "network admission lease changed the planned route"
            )
            await _fail_closed_preserving(lease, route_error)
            raise route_error
        if deadline_ns is not None:
            try:
                admitted_at_ns = _monotonic_ns(runtime)
            except BaseException as error:
                await _fail_closed_preserving(lease, error)
                raise
            if admitted_at_ns > deadline_ns:
                raise NetworkAdmissionExpired(
                    "network admission completed after its deadline"
                )
    except BaseException as error:
        if lease.release_disposition is None:
            await _close_preserving(lease, error)
        raise
    return lease


async def _close_network_lease(lease: NetworkAdmissionLease) -> None:
    try:
        await NetworkAdmissionLease.aclose(lease)
    except asyncio.CancelledError as error:
        _mark_release_failed_cancellation(error)
        raise


async def _fail_closed_network_lease(lease: NetworkAdmissionLease) -> None:
    try:
        await NetworkAdmissionLease.fail_closed(lease)
    except asyncio.CancelledError as error:
        _mark_release_failed_cancellation(error)
        raise


def _mark_release_failed_cancellation(error: asyncio.CancelledError) -> None:
    if _NETWORK_ADMISSION_RELEASE_FAILURE_NOTE not in getattr(error, "__notes__", ()):
        return
    task = asyncio.current_task()
    if task is not None:
        cast(Any, task)._okx_network_admission_release_failed = True


async def _release_preserving(
    lease: NetworkAdmissionLease,
    error: BaseException,
    disposition: NetworkAdmissionReleaseDisposition,
) -> _ReleasePreservation:
    try:
        if disposition is NetworkAdmissionReleaseDisposition.FAIL_CLOSED:
            await _fail_closed_network_lease(lease)
        else:
            await _close_network_lease(lease)
    except asyncio.CancelledError as cancellation:
        release_failed = _NETWORK_ADMISSION_RELEASE_FAILURE_NOTE in getattr(
            cancellation, "__notes__", ()
        )
        if release_failed:
            error.add_note(_NETWORK_ADMISSION_RELEASE_FAILURE_NOTE)
            _mark_release_failed_cancellation(cancellation)
        error.add_note("network admission cleanup cancellation also observed")
        cancellation.__cause__ = None
        cancellation.__context__ = None
        cancellation.__suppress_context__ = True
        cancellation.__traceback__ = None
        return _ReleasePreservation(not release_failed, cancellation)
    except BaseException:  # noqa: BLE001 - preserve the primary failure.
        error.add_note(_NETWORK_ADMISSION_RELEASE_FAILURE_NOTE)
        task = asyncio.current_task()
        if task is not None:
            cast(Any, task)._okx_network_admission_release_failed = True
        return _ReleasePreservation(False)
    return _ReleasePreservation(True)


@dataclass(frozen=True, slots=True)
class _ReleasePreservation:
    released: bool
    cancellation: asyncio.CancelledError | None = None


async def _close_preserving(
    lease: NetworkAdmissionLease,
    error: BaseException,
) -> _ReleasePreservation:
    return await _release_preserving(
        lease,
        error,
        NetworkAdmissionReleaseDisposition.NORMAL,
    )


async def _fail_closed_preserving(
    lease: NetworkAdmissionLease,
    error: BaseException,
) -> _ReleasePreservation:
    return await _release_preserving(
        lease,
        error,
        NetworkAdmissionReleaseDisposition.FAIL_CLOSED,
    )


def _instrument_index(
    plan: AdapterPlan,
) -> Mapping[tuple[Market, str], InstrumentRecord]:
    return {
        (instrument.market, instrument.instrument_key): instrument
        for instrument in plan.instruments
    }


def _expected_rest_request(
    item: RestPlanItem,
    instruments: Mapping[tuple[Market, str], InstrumentRecord],
) -> OkxRestRequest:
    if item.logical_stream == "instrument":
        if item.instrument_key is not None or item.wire_symbol is not None:
            raise ValueError("OKX instrument catalog must be market-scoped")
        return instruments_request(item.market)
    if item.instrument_key is None or item.wire_symbol is None:
        raise ValueError("OKX routine REST streams must be instrument-scoped")
    try:
        instrument = instruments[(item.market, item.instrument_key)]
    except KeyError:
        raise ValueError(
            "OKX REST item is outside the frozen instrument index"
        ) from None
    if item.wire_symbol != instrument.wire_symbol("rest"):
        raise ValueError("OKX REST item wire symbol does not match plan instrument")
    if item.logical_stream == "book_deep_snapshot":
        depth = item.params.get("sz")
        if type(depth) is not int:
            raise ValueError("OKX deep book plan depth must be a canonical integer")
        return deep_book_request(instrument, depth=depth)
    if item.logical_stream == "candle_1m":
        return candles_request(instrument, bar="1m", limit=2)
    if item.logical_stream in {"premium", "insurance_fund"}:
        return derivative_reference_request(item.logical_stream, instrument)
    raise ValueError("OKX REST logical stream is not executable")


def _validate_okx_plan_identity(plan: AdapterPlan) -> None:
    ws_identities = [
        (item.market, item.instrument_key, item.logical_stream) for item in plan.ws
    ]
    rest_identities = [
        (item.market, item.instrument_key, item.logical_stream) for item in plan.rest
    ]
    catalog_markets = [item.market for item in plan.catalog]
    if len(set(ws_identities)) != len(ws_identities):
        raise ValueError("OKX WebSocket work identity must be unique")
    if len(set(rest_identities)) != len(rest_identities):
        raise ValueError("OKX REST work identity must be unique")
    if len(set(catalog_markets)) != len(catalog_markets):
        raise ValueError("OKX catalog market must be unique")
    instruments = _instrument_index(plan)
    claimed_aliases: dict[tuple[Market, str, str], str] = {}

    def claim_alias(
        *,
        market: Market,
        namespace: str,
        wire_symbol: str,
        instrument_key: str,
    ) -> None:
        owner = claimed_aliases.setdefault(
            (market, namespace, wire_symbol),
            instrument_key,
        )
        if owner != instrument_key:
            raise ValueError("OKX wire aliases must map to one plan instrument")

    for ws_item in plan.ws:
        if (
            ws_item.logical_stream in _OKX_DERIVATIVE_STREAMS
            and ws_item.market is not Market.PERPETUAL
        ):
            raise ValueError(
                "OKX derivative WebSocket stream requires perpetual market"
            )
        allowed_channels = _OKX_WS_CHANNELS_BY_STREAM.get(ws_item.logical_stream)
        if allowed_channels is None or ws_item.channel not in allowed_channels:
            raise ValueError("OKX WebSocket stream and channel do not match")
        if (
            ws_item.channel == "books-rpi"
            and "books_rpi" in plan.disabled_optional_features
        ):
            raise ValueError("OKX books-rpi is disabled by the frozen adapter plan")
        if ws_item.instrument_key is None:
            if ws_item.logical_stream not in {"instrument", "status", "liquidation"}:
                raise ValueError("OKX WebSocket stream requires an instrument")
        else:
            try:
                instrument = instruments[(ws_item.market, ws_item.instrument_key)]
            except KeyError:
                raise ValueError(
                    "OKX WebSocket item is outside the frozen instrument index"
                ) from None
            alias = "index" if ws_item.logical_stream == "index_ticker" else "websocket"
            if ws_item.wire_symbol != instrument.wire_symbol(alias):
                raise ValueError(
                    "OKX WebSocket wire symbol does not match plan instrument"
                )
            claim_alias(
                market=ws_item.market,
                namespace=alias,
                wire_symbol=cast(str, ws_item.wire_symbol),
                instrument_key=ws_item.instrument_key,
            )
    if any(
        item.logical_stream
        not in {
            "book_deep_snapshot",
            "candle_1m",
            "premium",
            "insurance_fund",
        }
        for item in plan.rest
    ):
        raise ValueError("OKX routine REST plan contains a non-routine stream")
    if any(item.logical_stream != "instrument" for item in plan.catalog):
        raise ValueError("OKX catalog plan contains a non-catalog stream")
    for rest_item in (*plan.rest, *plan.catalog):
        if (
            rest_item.logical_stream in _OKX_DERIVATIVE_STREAMS
            and rest_item.market is not Market.PERPETUAL
        ):
            raise ValueError("OKX derivative REST stream requires perpetual market")
        expected_endpoint = _OKX_REST_LOGICAL_ENDPOINTS.get(rest_item.logical_stream)
        if expected_endpoint is None or rest_item.logical_endpoint != expected_endpoint:
            raise ValueError("OKX REST stream and logical endpoint do not match")
        request = _request_for_item(rest_item)
        expected_request = _expected_rest_request(rest_item, instruments)
        if request != expected_request:
            raise ValueError("OKX REST stream, path, and parameters do not match")
        if rest_item.instrument_key is not None:
            claim_alias(
                market=rest_item.market,
                namespace="rest",
                wire_symbol=cast(str, rest_item.wire_symbol),
                instrument_key=rest_item.instrument_key,
            )
            family = expected_request.params.get("instFamily")
            if type(family) is str:
                claim_alias(
                    market=rest_item.market,
                    namespace="instrument_family",
                    wire_symbol=family,
                    instrument_key=rest_item.instrument_key,
                )
    expected_expectations: set[tuple[Market | None, str | None, str, str]] = {
        (
            ws_item.market,
            ws_item.instrument_key,
            ws_item.logical_stream,
            ws_item.shard_id,
        )
        for ws_item in plan.ws
    } | {
        (
            rest_item.market,
            rest_item.instrument_key,
            rest_item.logical_stream,
            rest_item.shard_id,
        )
        for rest_item in (*plan.rest, *plan.catalog)
    }
    stream_shards: dict[tuple[Market, str | None, str], str] = {}
    for ws_item in plan.ws:
        identity = (
            ws_item.market,
            ws_item.instrument_key,
            ws_item.logical_stream,
        )
        previous = stream_shards.setdefault(identity, ws_item.shard_id)
        if previous != ws_item.shard_id:
            raise ValueError("OKX logical stream is split across multiple shards")
    for rest_item in (*plan.rest, *plan.catalog):
        identity = (
            rest_item.market,
            rest_item.instrument_key,
            rest_item.logical_stream,
        )
        previous = stream_shards.setdefault(identity, rest_item.shard_id)
        if previous != rest_item.shard_id:
            raise ValueError("OKX logical stream is split across multiple shards")
    expected_expectations.add((None, None, "_control", "_control"))
    if {item.key for item in plan.expectations} != expected_expectations:
        raise ValueError("OKX stream expectations do not exactly match plan work")
    for expectation in plan.expectations:
        expected_coverage = (
            CoverageMode.UNKNOWN
            if expectation.logical_stream == "status"
            else CoverageMode.LOSSY_WINDOW
            if expectation.logical_stream == "liquidation"
            else CoverageMode.COMPLETE
        )
        if expectation.coverage is not expected_coverage:
            raise ValueError("OKX stream expectation coverage does not match")
    catalog_by_market = {item.market: item for item in plan.catalog}
    instrument_ws_by_market = {
        item.market for item in plan.ws if item.logical_stream == "instrument"
    }
    if set(catalog_by_market) != instrument_ws_by_market:
        raise ValueError(
            "OKX catalog and instrument WebSocket markets must match exactly"
        )
    for item in plan.ws:
        catalog = catalog_by_market.get(item.market)
        if catalog is None or item.instrument_key is not None:
            continue
        if (
            item.egress_id,
            item.quota_group,
            item.shard_id,
        ) != (
            catalog.egress_id,
            catalog.quota_group,
            catalog.shard_id,
        ):
            raise ValueError(
                "OKX catalog and market WebSocket routes must match exactly"
            )


def _request_for_item(item: RestPlanItem) -> OkxRestRequest:
    params: dict[str, PublicQueryValue] = {}
    for name, value in item.params.items():
        if isinstance(value, Sequence) and not isinstance(
            value, (str, bytes, bytearray)
        ):
            raise TypeError("OKX REST execution requires scalar query parameters")
        params[name] = cast(PublicQueryValue, value)
    return OkxRestRequest(
        path=item.path,
        params=params,
        logical_stream=item.logical_stream,
    )


def _retry_classification(error: OkxResponseError) -> RetryClassification:
    return RetryClassification(
        action=error.retry_action,
        retry_after=error.retry_after,
        reason=f"okx_{error.exchange_code}",
    )


def _apply_retry_effect(
    runtime: AdapterRuntime,
    *,
    dispatch: RestDispatch,
    decision: RetryDecision,
) -> None:
    if type(decision) is not RetryDecision:
        raise TypeError("decision must be RetryDecision")
    if decision.action not in {RetryAction.THROTTLE, RetryAction.BAN}:
        return
    effects = runtime.retry_effects
    if effects is None:
        raise RuntimeError("classified OKX throttle/ban requires retry effects")
    effects.apply(dispatch, decision)


def _record_transport_failure(
    runtime: AdapterRuntime,
    *,
    transport: Transport,
    egress_id: str,
    reason: str,
) -> None:
    health = runtime.transport_health
    if health is None:
        return
    health.record_transport_failure(
        exchange=Exchange.OKX,
        transport=transport,
        egress_id=egress_id,
        reason=reason,
    )


def _rest_control(
    *,
    kind: str,
    item: RestPlanItem,
    attempt: int,
    reason: str,
    payload: JsonPayload | None = None,
    capture: OkxRestCapture | None = None,
    dispatch: RestDispatch | None = None,
    request_started_at_ns: int | None = None,
    request_ended_at_ns: int | None = None,
    status: int | None = None,
    rate_limit_headers: Mapping[str, str] | None = None,
    evidence_complete: bool | None = None,
    failure_type: str | None = None,
    error_type: str | None = None,
    body_unavailable: bool = False,
    planned_egress_id: str | None = None,
    sticky_egress_id: str | None = None,
    scheduled_ns: int | None = None,
    deadline_ns: int | None = None,
    blocked_by_scheduled_ns: int | None = None,
    blocked_by_attempt: int | None = None,
) -> tuple[NativeEventDraft, SourceContext]:
    if request_ended_at_ns is not None and request_started_at_ns is None:
        raise ValueError("REST end evidence requires a request start timestamp")
    if capture is not None and request_started_at_ns is not None:
        raise ValueError("captured REST evidence already contains request timestamps")
    body: dict[str, JsonPayload] = {
        "kind": kind,
        "origin_transport": "rest",
        "market": item.market.value,
        "instrument_key": item.instrument_key,
        "logical_stream": item.logical_stream,
        "attempt": attempt,
        "reason": reason,
        "egress_id": (
            capture.source.egress_id
            if capture is not None
            else dispatch.route.egress_id
            if dispatch is not None and request_started_at_ns is not None
            else None
        ),
        "candidate_egress_ids": [route.egress_id for route in item.routes],
        "planned_egress_id": (
            planned_egress_id
            if planned_egress_id is not None
            else dispatch.route.egress_id
            if dispatch is not None
            else None
        ),
        "sticky_egress_id": sticky_egress_id,
        "scheduled_monotonic_ns": (
            dispatch.job.scheduled_ns if dispatch is not None else scheduled_ns
        ),
        "deadline_monotonic_ns": (
            dispatch.job.deadline_ns if dispatch is not None else deadline_ns
        ),
        "dispatched": capture is not None or request_started_at_ns is not None,
        "method": "GET",
        "path": item.path,
        "params": cast(JsonPayload, dict(item.params)),
    }
    if blocked_by_scheduled_ns is not None:
        body["blocked_by_scheduled_monotonic_ns"] = blocked_by_scheduled_ns
    if blocked_by_attempt is not None:
        body["blocked_by_attempt"] = blocked_by_attempt
    if evidence_complete is not None:
        body["evidence_complete"] = evidence_complete
    if failure_type is not None:
        body["failure_type"] = failure_type
    if error_type is not None:
        body["error_type"] = error_type
    if body_unavailable:
        body["body_unavailable"] = True
    if payload is not None:
        body["response"] = payload
    if capture is not None:
        metadata = capture.rest_metadata
        body["rest_metadata"] = cast(
            JsonPayload,
            metadata.model_dump(mode="json"),
        )
        body.update(
            request_started_at_ns=metadata.request_started_at_ns,
            request_ended_at_ns=metadata.request_ended_at_ns,
            status=metadata.status,
            rate_limit_headers=cast(JsonPayload, dict(metadata.rate_limit_headers)),
            requested_interval_ns=metadata.requested_interval_ns,
            effective_interval_ns=metadata.effective_interval_ns,
        )
    elif request_started_at_ns is not None:
        interval = None if dispatch is None else dispatch.job.interval
        body.update(
            request_started_at_ns=request_started_at_ns,
            request_ended_at_ns=request_ended_at_ns,
            status=status,
            rate_limit_headers=cast(
                JsonPayload,
                {} if rate_limit_headers is None else dict(rate_limit_headers),
            ),
            response=payload,
            requested_interval_ns=(
                None if interval is None else interval.requested_interval_ns
            ),
            effective_interval_ns=(
                None if interval is None else interval.effective_interval_ns
            ),
            rest_metadata=None,
        )
    return (
        NativeEventDraft(
            exchange=Exchange.OKX,
            market=None,
            instrument_key=None,
            wire_symbol=None,
            logical_stream="_control",
            native_channel=None,
            transport=Transport.INTERNAL,
            event_time_ns=None,
            event_time_source=None,
            payload=body,
        ),
        SourceContext.internal(),
    )


def _response_error_control(
    *,
    kind: str,
    item: RestPlanItem,
    attempt: int,
    error: OkxResponseError,
) -> tuple[NativeEventDraft, SourceContext]:
    metadata = error.rest_metadata
    source = error.source
    if metadata is None or source is None:
        raise ValueError("classified OKX response error lacks request evidence")
    body: dict[str, JsonPayload] = {
        "kind": kind,
        "origin_transport": "rest",
        "market": item.market.value,
        "instrument_key": item.instrument_key,
        "logical_stream": item.logical_stream,
        "attempt": attempt,
        "reason": f"okx_{error.exchange_code}",
        "http_status": error.http_status,
        "exchange_code": error.exchange_code,
        "exchange_message": error.exchange_message,
        "response": error.raw_payload,
        "egress_id": source.egress_id,
        "method": metadata.method,
        "path": metadata.path,
        "params": cast(JsonPayload, dict(metadata.params)),
        "request_started_at_ns": metadata.request_started_at_ns,
        "request_ended_at_ns": metadata.request_ended_at_ns,
        "status": metadata.status,
        "rate_limit_headers": cast(
            JsonPayload,
            dict(metadata.rate_limit_headers),
        ),
        "requested_interval_ns": metadata.requested_interval_ns,
        "effective_interval_ns": metadata.effective_interval_ns,
        "rest_metadata": cast(JsonPayload, metadata.model_dump(mode="json")),
    }
    return (
        NativeEventDraft(
            exchange=Exchange.OKX,
            market=None,
            instrument_key=None,
            wire_symbol=None,
            logical_stream="_control",
            native_channel=None,
            transport=Transport.INTERNAL,
            event_time_ns=None,
            event_time_source=None,
            payload=body,
        ),
        SourceContext.internal(),
    )


def _emit_control(
    sink: EventSink,
    draft_and_source: tuple[NativeEventDraft, SourceContext],
) -> None:
    draft, source = draft_and_source
    _emit_checked(
        sink,
        draft,
        source=source,
        shard="_control",
        allow_market_overflow=False,
    )


def _emit_checked(
    sink: EventSink,
    draft: NativeEventDraft,
    *,
    source: SourceContext,
    shard: str,
    allow_market_overflow: bool,
) -> bool:
    rejection_error: _SinkRejectedError | None = None
    try:
        result = sink.try_emit(draft, source=source, shard=shard)
        if result.accepted:
            return True
        status = result.status
        if status is EnqueueStatus.OVERFLOW and allow_market_overflow:
            return False
        rejection_error = _SinkRejectedError(
            f"event sink rejected OKX event: {status.value}"
        )
    except BaseException as sink_error:
        sink_error.add_note(_SINK_FAILURE_NOTE)
        raise
    assert rejection_error is not None
    rejection_error.add_note(_SINK_FAILURE_NOTE)
    raise rejection_error


def _parse_rest_capture(
    capture: OkxRestCapture,
    *,
    item: RestPlanItem,
    instrument: InstrumentRecord,
) -> NativeEventDraft:
    if item.logical_stream == "book_deep_snapshot":
        return parse_deep_book(capture, instrument=instrument)
    if item.logical_stream == "candle_1m":
        return parse_candles(capture, instrument=instrument)
    if item.logical_stream in {"premium", "insurance_fund"}:
        return parse_derivative_reference(capture, instrument=instrument)
    raise ValueError(f"unsupported OKX REST execution stream {item.logical_stream!r}")


async def _submit_rest_occurrence(
    *,
    item: RestPlanItem,
    runtime: AdapterRuntime,
    scheduled_ns: int,
    ready_ns: int,
    deadline_ns: int,
    attempt: int,
    sticky_route: RestBudgetRoute | None = None,
) -> _SubmitOutcome:
    job = item.materialize(
        ready_monotonic_ns=ready_ns,
        scheduled_ns=scheduled_ns,
        attempt=attempt,
        deadline_ns=deadline_ns,
    )
    if sticky_route is not None:
        if sticky_route not in item.routes:
            raise ValueError("sticky REST route must belong to the plan item")
        job = replace(job, routes=(sticky_route,))
    elif runtime.transport_health is not None:
        routes: list[RestBudgetRoute] = []
        for route in item.routes:
            available = runtime.transport_health.is_egress_available(
                exchange=item.exchange,
                egress_id=route.egress_id,
            )
            if type(available) is not bool:
                raise TypeError("transport health availability must be a bool")
            if available:
                routes.append(route)
        if not routes:
            raise _NoHealthyRestRoute(
                f"no healthy REST egress is available for {item.id!r}"
            )
        job = replace(job, routes=tuple(routes))
    result = await _submit_until(
        job=job,
        runtime=runtime,
        deadline_ns=deadline_ns,
    )
    if result.result is None:
        if result.deferred_error is not None:
            raise result.deferred_error
        raise asyncio.CancelledError
    if (
        result.deferred_error is not None
        and result.result not in _COMMITTED_SUBMIT_RESULTS
    ):
        raise result.deferred_error
    return result


@dataclass(frozen=True, slots=True)
class _SubmitOutcome:
    result: SubmitResult | None
    deferred_error: BaseException | None = None


class _SubmitOperationSignal(Enum):
    STOPPED = "stopped"


async def _submit_until(
    *,
    job: RestJob,
    runtime: AdapterRuntime,
    deadline_ns: int,
) -> _SubmitOutcome:
    if _stop_is_set(runtime.stop):
        return _SubmitOutcome(None)
    now_ns = _monotonic_ns(runtime)
    if now_ns > deadline_ns:
        return _SubmitOutcome(SubmitResult.EXPIRED)
    timeout_seconds = max(0, deadline_ns - now_ns + 1) / _NANOSECONDS_PER_SECOND

    async def submit_once() -> SubmitResult | _SubmitOperationSignal:
        if _stop_is_set(runtime.stop):
            return _SubmitOperationSignal.STOPPED
        if _monotonic_ns(runtime) > deadline_ns:
            return SubmitResult.EXPIRED
        result = await runtime.scheduler.submit(job)
        if type(result) is not SubmitResult:
            raise TypeError("REST scheduler submit() must return SubmitResult")
        return result

    waiters: list[asyncio.Task[object]] = []
    operation: asyncio.Task[SubmitResult | _SubmitOperationSignal] | None = None
    stopped: asyncio.Task[None] | None = None
    timeout: asyncio.Task[None] | None = None
    setup_error: BaseException | None = None
    cancellation: asyncio.CancelledError | None = None
    initially_timed_out = False
    initially_stopped = False
    try:
        stopped = _create_owned_task(runtime.stop.wait(), waiters)
        operation = _create_owned_task(submit_once(), waiters)
        timeout = _create_owned_task(asyncio.sleep(timeout_seconds), waiters)
        done, _pending = await asyncio.wait(
            tuple(waiters),
            return_when=asyncio.FIRST_COMPLETED,
        )
        initially_timed_out = timeout in done
        initially_stopped = stopped in done
    except asyncio.CancelledError as error:
        cancellation = error
    except BaseException as error:  # noqa: BLE001 - task setup is an ownership edge.
        setup_error = error

    results, cleanup_cancellation = await _cancel_and_harvest_admission_waiters(waiters)
    if cancellation is None:
        cancellation = cleanup_cancellation
    result_by_task = dict(zip(waiters, results, strict=True))
    operation_result = result_by_task.get(operation) if operation is not None else None

    stop_contract_error: BaseException | None = None
    try:
        _validate_harvested_stop_waiter(stopped, runtime.stop)
    except BaseException as error:  # noqa: BLE001 - validate an untrusted stop port.
        stop_contract_error = error
    if (
        stop_contract_error is None
        and initially_stopped
        and stopped is not None
        and isinstance(
            result_by_task.get(cast(asyncio.Task[object], stopped)),
            asyncio.CancelledError,
        )
    ):
        try:
            if not _stop_is_set(runtime.stop):
                raise _StopTokenContractError(
                    "stop wait was cancelled before the token was set"
                )
        except BaseException as error:  # noqa: BLE001 - validate an untrusted stop port.
            stop_contract_error = error

    waiter_error = next(
        (
            cast(BaseException, result_by_task[waiter])
            for waiter in (stopped, timeout)
            if waiter is not None
            and isinstance(result_by_task.get(waiter), BaseException)
            and not isinstance(result_by_task[waiter], asyncio.CancelledError)
        ),
        stop_contract_error,
    )
    if type(operation_result) is SubmitResult:
        deferred_error = (
            setup_error
            if setup_error is not None
            else waiter_error
            if waiter_error is not None
            else cancellation
        )
        return _SubmitOutcome(
            operation_result,
            cast(BaseException | None, deferred_error),
        )
    if isinstance(operation_result, BaseException) and not isinstance(
        operation_result,
        asyncio.CancelledError,
    ):
        raise operation_result
    if setup_error is not None:
        raise setup_error
    if waiter_error is not None:
        raise waiter_error
    if cancellation is not None:
        raise cancellation
    if operation_result is _SubmitOperationSignal.STOPPED:
        return _SubmitOutcome(None)
    if initially_stopped:
        if not _stop_is_set(runtime.stop):
            raise _StopTokenContractError("stop wait returned before the token was set")
        return _SubmitOutcome(None)
    if initially_timed_out:
        return _SubmitOutcome(SubmitResult.EXPIRED)
    raise RuntimeError("OKX REST submission ended without a result")


@dataclass(slots=True)
class _PendingCatalogRequest:
    item: RestPlanItem
    future: asyncio.Future[CompleteCatalogSnapshot]
    scheduled_ns: int
    deadline_ns: int
    policy: RetryPolicy
    phase: _RestOccurrencePhase
    submission_handoff: asyncio.Event
    current_attempt: int = 1
    sticky_egress_id: str | None = None
    submission: asyncio.Task[None] | None = None
    watchdog: asyncio.Task[None] | None = None
    terminal_handoff_error: BaseException | None = None


class _RestOccurrencePhase(str, Enum):
    QUEUED = "queued"
    IN_FLIGHT = "in_flight"


class OkxCatalogController:
    """Bridge active catalog calls into the run loop's sole REST consumer."""

    def __init__(
        self,
        *,
        plan: AdapterPlan,
        runtime: AdapterRuntime,
        sink: EventSink,
    ) -> None:
        if type(plan) is not AdapterPlan or plan.exchange is not Exchange.OKX:
            raise ValueError("catalog controller requires an OKX plan")
        if type(runtime) is not AdapterRuntime:
            raise TypeError("runtime must be AdapterRuntime")
        if not callable(getattr(sink, "try_emit", None)):
            raise TypeError("catalog controller sink must provide try_emit()")
        self._plan = plan
        self._runtime = runtime
        self._sink = sink
        self._items = {item.market: item for item in plan.catalog}
        if len(self._items) != len(plan.catalog):
            raise ValueError("OKX plan must have at most one catalog item per market")
        for item in plan.catalog:
            if item.logical_stream != "instrument" or item.interval_plan is not None:
                raise ValueError(
                    "catalog controller requires one-shot instrument plan items"
                )
            self._validate_expectation(item)
        self._pending: dict[str, _PendingCatalogRequest] = {}
        self._submissions: set[asyncio.Task[None]] = set()
        self._watchdogs: set[asyncio.Task[None]] = set()
        self._fatal_error: BaseException | None = None
        self._fatal_is_sink = False
        self._fatal_ready = asyncio.Event()
        self._closed = False
        self._lock = asyncio.Lock()

    def owns_runtime(self, runtime: AdapterRuntime) -> bool:
        return runtime is self._runtime

    def pending(self, item_id: str) -> _PendingCatalogRequest | None:
        return self._pending.get(item_id)

    async def wait_fatal(self) -> None:
        await self._fatal_ready.wait()
        error = self._fatal_error
        if error is None:  # pragma: no cover - event and error are set together.
            raise RuntimeError("OKX catalog fatal signal has no error")
        raise error

    def _publish_fatal(
        self, error: BaseException, *, sink_failure: bool = False
    ) -> None:
        if self._fatal_error is None or (sink_failure and not self._fatal_is_sink):
            self._fatal_error = error
            self._fatal_is_sink = sink_failure
            self._fatal_ready.set()

    def fatal_error(self) -> BaseException | None:
        return self._fatal_error

    def fatal_is_sink_failure(self) -> bool:
        return self._fatal_is_sink

    def _start_watchdog(self, pending: _PendingCatalogRequest) -> None:
        coroutine = self._watch_deadline_owned(pending)
        try:
            watchdog = asyncio.create_task(coroutine)
        except BaseException:
            coroutine.close()
            raise
        pending.watchdog = watchdog
        self._watchdogs.add(watchdog)
        watchdog.add_done_callback(self._watchdog_finished)

    def _watchdog_finished(self, watchdog: asyncio.Task[None]) -> None:
        self._watchdogs.discard(watchdog)
        try:
            watchdog.exception()
        except asyncio.CancelledError:
            pass

    def _submission_finished(self, submission: asyncio.Task[None]) -> None:
        self._submissions.discard(submission)
        try:
            submission.exception()
        except asyncio.CancelledError:
            pass

    async def _watch_deadline_owned(
        self,
        pending: _PendingCatalogRequest,
    ) -> None:
        try:
            await self._watch_deadline(pending)
        except asyncio.CancelledError:
            raise
        except BaseException as error:  # noqa: BLE001 - fatal worker evidence.
            self.finish_error(pending, error)
            self._publish_fatal(error)

    def _validate_expectation(self, item: RestPlanItem) -> None:
        expected = (item.market, None, "instrument", item.shard_id)
        if not any(
            expectation.key == expected for expectation in self._plan.expectations
        ):
            raise ValueError(
                "active catalog refresh requires its exact instrument expectation"
            )

    async def _run_submission(self, pending: _PendingCatalogRequest) -> None:
        item = pending.item
        try:
            submission_outcome = await _submit_rest_occurrence(
                item=item,
                runtime=self._runtime,
                scheduled_ns=pending.scheduled_ns,
                ready_ns=pending.scheduled_ns,
                deadline_ns=pending.deadline_ns,
                attempt=1,
            )
        except asyncio.CancelledError:
            raise
        except BaseException as error:  # noqa: BLE001 - settle caller evidence.
            self._finish_submission_error(pending, error)
            return

        result = submission_outcome.result
        assert result is not None
        if result not in _COMMITTED_SUBMIT_RESULTS:
            submission_error: BaseException = (
                TimeoutError("OKX catalog request expired before admission")
                if result is SubmitResult.EXPIRED
                else RuntimeError(f"OKX catalog submission failed with {result.value}")
            )
            self._retire(pending)
            try:
                _emit_schedule_control(
                    self._sink,
                    item=item,
                    kind="rest_terminal",
                    reason=f"catalog_submission_{result.value}",
                    scheduled_ns=pending.scheduled_ns,
                    deadline_ns=pending.deadline_ns,
                )
            except BaseException as sink_error:  # noqa: BLE001 - fatal sink.
                self._publish_fatal(sink_error, sink_failure=True)
                submission_error.add_note("catalog terminal emission also failed")
            if not pending.future.done():
                pending.future.set_exception(submission_error)
            return

        # submit() has an atomic commit/return contract. Do not introduce an
        # await between its accepted result and transferring ownership here.
        pending.submission = None
        deferred_error = submission_outcome.deferred_error
        if deferred_error is not None:
            if isinstance(deferred_error, asyncio.CancelledError):
                raise deferred_error
            if self._pending.get(item.id) is pending:
                self.mark_terminal_handoff(pending, deferred_error)
            else:
                pending.terminal_handoff_error = deferred_error
                pending.submission_handoff.set()
                if not pending.future.done():
                    pending.future.set_exception(deferred_error)
                self._publish_fatal(deferred_error)
            raise deferred_error
        if self._closed or self._pending.get(item.id) is not pending:
            if not pending.future.done():
                pending.future.cancel()
            return
        pending.submission_handoff.set()

    def _finish_submission_error(
        self,
        pending: _PendingCatalogRequest,
        error: BaseException,
    ) -> None:
        pending.submission_handoff.set()
        self._retire(pending)
        recoverable = isinstance(error, (CapacityError, _NoHealthyRestRoute))
        fatal_error: BaseException | None = None if recoverable else error
        try:
            _emit_schedule_control(
                self._sink,
                item=pending.item,
                kind="rest_terminal",
                reason=f"catalog_submission_{type(error).__name__}",
                scheduled_ns=pending.scheduled_ns,
                deadline_ns=pending.deadline_ns,
            )
        except BaseException as sink_error:  # noqa: BLE001 - fatal sink.
            fatal_error = sink_error
            error.add_note("catalog terminal emission also failed")
        if fatal_error is not None:
            self._publish_fatal(
                fatal_error,
                sink_failure=fatal_error is not error,
            )
        if not pending.future.done():
            pending.future.set_exception(error)

    async def request(self, market: Market) -> CompleteCatalogSnapshot:
        if type(market) is not Market:
            raise TypeError("catalog market must be Market")
        try:
            item = self._items[market]
        except KeyError:
            raise LookupError(
                f"OKX plan has no frozen {market.value} catalog route"
            ) from None
        loop = asyncio.get_running_loop()
        scheduled_ns = _monotonic_ns(self._runtime)
        deadline_ns = min(_MAX_SIGNED_64, scheduled_ns + _CATALOG_DEADLINE_NS)
        future: asyncio.Future[CompleteCatalogSnapshot] = loop.create_future()
        pending = _PendingCatalogRequest(
            item=item,
            future=future,
            scheduled_ns=scheduled_ns,
            deadline_ns=deadline_ns,
            policy=retry_policy(
                clock=_ValidatedClock(self._runtime.clock),
                rng=random.Random(
                    _stable_seed(
                        "catalog",
                        item.market.value,
                        item.egress_id,
                        item.shard_id,
                    )
                ),
                max_attempts=self._runtime.retry.rest_max_attempts,
                base_ns=self._runtime.retry.base_backoff_ns,
                cap_ns=self._runtime.retry.max_backoff_ns,
            ),
            phase=_RestOccurrencePhase.QUEUED,
            submission_handoff=asyncio.Event(),
        )
        async with self._lock:
            if self._closed:
                raise RuntimeError("OKX catalog controller is closed")
            if item.id in self._pending:
                raise RuntimeError(
                    f"OKX {item.market.value} catalog refresh is already pending"
                )
            self._pending[item.id] = pending
            submission_coroutine = self._run_submission(pending)
            try:
                submission = asyncio.create_task(submission_coroutine)
            except BaseException as error:
                submission_coroutine.close()
                self._pending.pop(item.id, None)
                future.cancel()
                self._publish_fatal(error)
                raise
            pending.submission = submission
            self._submissions.add(submission)
            submission.add_done_callback(self._submission_finished)
            try:
                self._start_watchdog(pending)
            except BaseException as error:
                submission.cancel()
                self._pending.pop(item.id, None)
                future.cancel()
                self._publish_fatal(error)
                raise
        try:
            return await asyncio.shield(future)
        except asyncio.CancelledError:
            future.cancel()
            raise

    async def _watch_deadline(self, pending: _PendingCatalogRequest) -> None:
        while not _stop_is_set(self._runtime.stop):
            if pending.phase is not _RestOccurrencePhase.QUEUED:
                return
            now_ns = _monotonic_ns(self._runtime)
            if now_ns > pending.deadline_ns:
                submission = pending.submission
                pending.submission = None
                if (
                    submission is not None
                    and submission is not asyncio.current_task()
                    and not submission.done()
                ):
                    errors = await _cancel_and_collect(
                        (cast(asyncio.Task[object], submission),)
                    )
                    if errors:
                        raise errors[0]
                try:
                    _emit_schedule_control(
                        self._sink,
                        item=pending.item,
                        kind="rest_terminal",
                        reason="catalog_queue_deadline_expired",
                        attempt=pending.current_attempt,
                        planned_egress_id=pending.sticky_egress_id,
                        sticky_egress_id=pending.sticky_egress_id,
                        scheduled_ns=pending.scheduled_ns,
                        deadline_ns=pending.deadline_ns,
                    )
                except BaseException as sink_error:  # noqa: BLE001 - fatal sink.
                    self.finish_error(pending, sink_error)
                    self._publish_fatal(sink_error, sink_failure=True)
                    return
                self.finish_error(
                    pending,
                    TimeoutError("OKX catalog request exceeded its deadline"),
                )
                return
            delay_seconds = (pending.deadline_ns - now_ns + 1) / _NANOSECONDS_PER_SECOND
            await _await_or_stop(asyncio.sleep(delay_seconds), self._runtime)
            if _stop_is_set(self._runtime.stop):
                return

    def mark_in_flight(self, pending: _PendingCatalogRequest) -> None:
        if self._pending.get(pending.item.id) is not pending:
            raise RuntimeError("OKX catalog dispatch is no longer pending")
        if pending.terminal_handoff_error is not None:
            raise pending.terminal_handoff_error
        if pending.phase is not _RestOccurrencePhase.QUEUED:
            raise RuntimeError("OKX catalog dispatch was not queued")
        pending.phase = _RestOccurrencePhase.IN_FLIGHT
        watchdog = pending.watchdog
        pending.watchdog = None
        if watchdog is not None and not watchdog.done():
            watchdog.cancel()

    def mark_queued(
        self,
        pending: _PendingCatalogRequest,
        *,
        attempt: int,
        sticky_egress_id: str,
    ) -> None:
        if self._pending.get(pending.item.id) is not pending:
            raise RuntimeError("OKX catalog retry is no longer pending")
        if pending.phase is not _RestOccurrencePhase.IN_FLIGHT:
            raise RuntimeError("OKX catalog retry must follow an in-flight attempt")
        pending.phase = _RestOccurrencePhase.QUEUED
        pending.terminal_handoff_error = None
        pending.current_attempt = attempt
        pending.sticky_egress_id = sticky_egress_id
        try:
            self._start_watchdog(pending)
        except BaseException as error:
            self.finish_error(pending, error)
            self._publish_fatal(error)
            raise

    def mark_terminal_handoff(
        self,
        pending: _PendingCatalogRequest,
        error: BaseException,
    ) -> None:
        if self._pending.get(pending.item.id) is not pending:
            raise RuntimeError("OKX catalog handoff is no longer pending")
        pending.terminal_handoff_error = error
        pending.submission_handoff.set()
        watchdog = pending.watchdog
        pending.watchdog = None
        if watchdog is not None and not watchdog.done():
            watchdog.cancel()
        if not pending.future.done():
            pending.future.set_exception(error)
        self._publish_fatal(error)

    async def wait_submission_handoff(
        self,
        pending: _PendingCatalogRequest,
        runtime: AdapterRuntime,
    ) -> None:
        if not pending.submission_handoff.is_set():
            completed = await _await_or_stop(pending.submission_handoff.wait(), runtime)
            if completed is None:
                raise asyncio.CancelledError
        if pending.terminal_handoff_error is not None:
            raise pending.terminal_handoff_error

    def _retire(self, pending: _PendingCatalogRequest) -> None:
        if self._pending.get(pending.item.id) is pending:
            del self._pending[pending.item.id]
        watchdog = pending.watchdog
        if (
            watchdog is not None
            and watchdog is not asyncio.current_task()
            and not watchdog.done()
        ):
            watchdog.cancel()

    def finish_success(
        self,
        pending: _PendingCatalogRequest,
        snapshot: CompleteCatalogSnapshot,
    ) -> None:
        self._retire(pending)
        if not pending.future.done():
            pending.future.set_result(snapshot)

    def finish_error(
        self,
        pending: _PendingCatalogRequest,
        error: BaseException,
    ) -> None:
        self._retire(pending)
        if not pending.future.done():
            pending.future.set_exception(error)

    async def close(self) -> None:
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            pending = tuple(self._pending.values())
        submissions = tuple(self._submissions)
        watchdogs = tuple(self._watchdogs)
        owned = tuple(
            cast(asyncio.Task[object], task) for task in (*submissions, *watchdogs)
        )
        try:
            if owned:
                errors = await _cancel_and_collect(owned)
                if errors:
                    raise errors[0]
        finally:
            self._submissions.difference_update(submissions)
            self._watchdogs.difference_update(watchdogs)
            for request in pending:
                request.submission_handoff.set()
                self._retire(request)
                request.submission = None
                request.watchdog = None
                if not request.future.done():
                    request.future.cancel()


@dataclass(frozen=True, slots=True)
class _RestAttemptResult:
    capture: OkxRestCapture | None
    response_error: OkxResponseError | None
    transport_error: Exception | None
    request_started_at_ns: int
    request_ended_at_ns: int
    lease: NetworkAdmissionLease
    failure_evidence: _RestFailureEvidence | None = None


@dataclass(frozen=True, slots=True)
class _RestFailureEvidence:
    response: JsonPayload | None
    status: int | None
    rate_limit_headers: Mapping[str, str]
    request_started_at_ns: int
    request_ended_at_ns: int | None
    transport_error_type: str | None = None
    body_unavailable: bool = False


def _rest_failure_control(
    *,
    item: RestPlanItem,
    dispatch: RestDispatch,
    evidence: _RestFailureEvidence,
    error: BaseException,
    reason: str,
) -> tuple[NativeEventDraft, SourceContext]:
    return _rest_control(
        kind="rest_terminal",
        item=item,
        attempt=dispatch.job.attempt,
        reason=reason,
        payload=evidence.response,
        dispatch=dispatch,
        request_started_at_ns=evidence.request_started_at_ns,
        request_ended_at_ns=None,
        status=evidence.status,
        rate_limit_headers=evidence.rate_limit_headers,
        evidence_complete=False,
        failure_type=type(error).__name__,
        error_type=evidence.transport_error_type,
        body_unavailable=evidence.body_unavailable,
    )


def _emit_rest_failure_evidence(
    *,
    sink: EventSink | None,
    item: RestPlanItem,
    dispatch: RestDispatch,
    evidence: _RestFailureEvidence,
    error: BaseException,
    reason: str,
) -> None:
    if sink is None:
        return
    _emit_control(
        sink,
        _rest_failure_control(
            item=item,
            dispatch=dispatch,
            evidence=evidence,
            error=error,
            reason=reason,
        ),
    )


async def _record_rest_failure_and_fail_closed(
    *,
    sink: EventSink | None,
    item: RestPlanItem,
    dispatch: RestDispatch,
    evidence: _RestFailureEvidence,
    lease: NetworkAdmissionLease,
    error: BaseException,
    reason: str,
) -> None:
    try:
        _emit_rest_failure_evidence(
            sink=sink,
            item=item,
            dispatch=dispatch,
            evidence=evidence,
            error=error,
            reason=reason,
        )
    except BaseException as sink_error:
        await _fail_closed_preserving(lease, sink_error)
        raise
    await _fail_closed_preserving(lease, error)


async def _capture_rest_attempt(
    *,
    item: RestPlanItem,
    dispatch: RestDispatch,
    runtime: AdapterRuntime,
    sink: EventSink | None = None,
) -> _RestAttemptResult:
    request = _request_for_item(item)
    transport = runtime.transport_for(dispatch.route.egress_id).http
    deadline_ns = dispatch.job.deadline_ns
    if deadline_ns is None:
        raise RuntimeError("OKX REST dispatch requires a deadline")
    lease = await _acquire_network_lease(
        runtime=runtime,
        exchange=item.exchange,
        transport=Transport.REST,
        egress_id=dispatch.route.egress_id,
        quota_group=dispatch.route.budget_key[1],
        deadline_ns=deadline_ns,
    )
    if lease is None:
        raise asyncio.CancelledError
    handed_off = False
    started_at_ns: int | None = None
    response_evidence: _RestFailureEvidence | None = None

    async def request_once() -> Response:
        nonlocal response_evidence, started_at_ns
        try:
            if _stop_is_set(runtime.stop):
                raise asyncio.CancelledError
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            await _close_preserving(lease, error)
            raise
        try:
            started_at_ns = _wall_time_ns(runtime)
        except BaseException as error:
            await _fail_closed_preserving(lease, error)
            raise
        try:
            if _stop_is_set(runtime.stop):
                raise asyncio.CancelledError
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            await _close_preserving(lease, error)
            raise
        try:
            started_monotonic_ns = _monotonic_ns(runtime)
        except BaseException as error:
            await _fail_closed_preserving(lease, error)
            raise
        if started_monotonic_ns > deadline_ns:
            raise NetworkAdmissionExpired(
                "network admission deadline expired before HTTP started"
            )
        response = await transport.get(
            _full_url(item.endpoint, request.path),
            params=request.params,
            timeout=_HTTP_TIMEOUT_SECONDS,
        )
        snapshot_failed = False
        try:
            status = response.status_code
        except BaseException:  # noqa: BLE001 - snapshot an untrusted response port.
            status = None
            snapshot_failed = True
        else:
            if type(status) is not int or not 100 <= status <= 599:
                status = None
                snapshot_failed = True
        try:
            rate_headers = okx_rate_limit_headers(response.headers)
        except BaseException:  # noqa: BLE001 - snapshot an untrusted response port.
            rate_headers = {}
            snapshot_failed = True
        response_evidence = _RestFailureEvidence(
            response=None,
            status=status,
            rate_limit_headers=rate_headers,
            request_started_at_ns=started_at_ns,
            request_ended_at_ns=None,
            body_unavailable=True,
        )
        try:
            exact_body = okx_response_body_evidence(response)
        except BaseException:  # noqa: BLE001 - snapshot an untrusted response port.
            snapshot_failed = True
        else:
            response_evidence = replace(
                response_evidence,
                response=exact_body,
                body_unavailable=False,
            )
        if snapshot_failed:
            del response
            raise _ResponseContractError(
                "OKX HTTP transport returned unreadable response evidence"
            ) from None
        return response

    try:
        try:
            response = await _await_or_stop(
                request_once(),
                runtime,
            )
            if response is None:
                raise asyncio.CancelledError
        except NetworkAdmissionExpired:
            raise
        except asyncio.CancelledError as error:
            if response_evidence is not None:
                await _record_rest_failure_and_fail_closed(
                    sink=sink,
                    item=item,
                    dispatch=dispatch,
                    evidence=response_evidence,
                    lease=lease,
                    error=error,
                    reason="response_processing_cancelled",
                )
            raise
        except Exception as error:
            if lease.release_disposition is not None:
                raise
            if response_evidence is not None:
                await _record_rest_failure_and_fail_closed(
                    sink=sink,
                    item=item,
                    dispatch=dispatch,
                    evidence=response_evidence,
                    lease=lease,
                    error=error,
                    reason=(
                        "response_contract_failed"
                        if isinstance(error, _ResponseContractError)
                        else "response_wait_cleanup_failed"
                    ),
                )
                raise
            if started_at_ns is None:  # pragma: no cover - request_once sets first.
                raise RuntimeError("OKX REST transport failed before start evidence")
            ended_at_ns: int | None = None
            try:
                ended_at_ns = _wall_time_ns(runtime)
                if ended_at_ns < started_at_ns:
                    ended_at_ns = None
                    raise RuntimeError("OKX REST response ended before it started")
                _record_transport_failure(
                    runtime,
                    transport=Transport.REST,
                    egress_id=dispatch.route.egress_id,
                    reason=type(error).__name__,
                )
            except BaseException as persistence_error:
                await _record_rest_failure_and_fail_closed(
                    sink=sink,
                    item=item,
                    dispatch=dispatch,
                    evidence=_RestFailureEvidence(
                        response=None,
                        status=None,
                        rate_limit_headers={},
                        request_started_at_ns=started_at_ns,
                        request_ended_at_ns=ended_at_ns,
                        transport_error_type=type(error).__name__,
                    ),
                    lease=lease,
                    error=persistence_error,
                    reason="transport_failure_persistence_failed",
                )
                raise
            assert ended_at_ns is not None
            handed_off = True
            return _RestAttemptResult(
                None,
                None,
                error,
                started_at_ns,
                ended_at_ns,
                lease,
                _RestFailureEvidence(
                    response=None,
                    status=None,
                    rate_limit_headers={},
                    request_started_at_ns=started_at_ns,
                    request_ended_at_ns=ended_at_ns,
                    transport_error_type=type(error).__name__,
                ),
            )
        if response_evidence is None:  # pragma: no cover - request_once snapshots it.
            raise RuntimeError("OKX REST response has no exact body evidence")
        try:
            ended_at_ns = _wall_time_ns(runtime)
        except BaseException as error:
            await _record_rest_failure_and_fail_closed(
                sink=sink,
                item=item,
                dispatch=dispatch,
                evidence=response_evidence,
                lease=lease,
                error=error,
                reason="response_end_evidence_failed",
            )
            raise
        if started_at_ns is None:  # pragma: no cover - request_once sets first.
            raise RuntimeError("OKX REST response has no start evidence")
        if ended_at_ns < started_at_ns:
            clock_order_error = RuntimeError(
                "OKX REST response ended before it started"
            )
            await _record_rest_failure_and_fail_closed(
                sink=sink,
                item=item,
                dispatch=dispatch,
                evidence=response_evidence,
                lease=lease,
                error=clock_order_error,
                reason="response_end_evidence_failed",
            )
            raise clock_order_error
        try:
            capture = capture_okx_response(
                response,
                dispatch=dispatch,
                request=request,
                request_started_at_ns=started_at_ns,
                request_ended_at_ns=ended_at_ns,
            )
        except OkxResponseError as error:
            handed_off = True
            return _RestAttemptResult(
                None,
                error,
                None,
                started_at_ns,
                ended_at_ns,
                lease,
                replace(response_evidence, request_ended_at_ns=ended_at_ns),
            )
        except BaseException as error:
            await _record_rest_failure_and_fail_closed(
                sink=sink,
                item=item,
                dispatch=dispatch,
                evidence=replace(
                    response_evidence,
                    request_ended_at_ns=ended_at_ns,
                ),
                lease=lease,
                error=error,
                reason="response_capture_failed",
            )
            raise
        handed_off = True
        return _RestAttemptResult(
            capture,
            None,
            None,
            started_at_ns,
            ended_at_ns,
            lease,
            replace(response_evidence, request_ended_at_ns=ended_at_ns),
        )
    except BaseException as error:
        if not handed_off and lease.release_disposition is None:
            await _close_preserving(lease, error)
        raise


def _bounded_retry_decision(
    policy: RetryPolicy,
    *,
    attempt: int,
    now_ns: int,
    deadline_ns: int,
    classification: RetryClassification,
) -> RetryDecision:
    decision = policy.decide(
        attempt=attempt,
        now_ns=min(now_ns, deadline_ns),
        deadline_ns=deadline_ns,
        classification=classification,
    )
    if now_ns > deadline_ns and decision.retry:
        return replace(decision, retry=False, reason="deadline_exceeded")
    return decision


@dataclass(frozen=True, slots=True)
class _RestRetryOutcome:
    response_error: OkxResponseError | None
    transport_error: Exception | None
    classification: RetryClassification
    now_ns: int
    decision: RetryDecision


async def _classify_rest_retry_and_release(
    *,
    attempt_result: _RestAttemptResult,
    policy: RetryPolicy,
    dispatch: RestDispatch,
    runtime: AdapterRuntime,
    deadline_ns: int,
    sink: EventSink | None = None,
    item: RestPlanItem | None = None,
) -> _RestRetryOutcome:
    lease = attempt_result.lease
    try:
        response_error = attempt_result.response_error
        transport_error = attempt_result.transport_error
        classification = (
            _retry_classification(response_error)
            if response_error is not None
            else RetryClassification(
                RetryAction.BACKOFF,
                None,
                "transport_error"
                if transport_error is None
                else type(transport_error).__name__,
            )
        )
        now_ns = _monotonic_ns(runtime)
        decision = _bounded_retry_decision(
            policy,
            attempt=dispatch.job.attempt,
            now_ns=now_ns,
            deadline_ns=deadline_ns,
            classification=classification,
        )
        _apply_retry_effect(runtime, dispatch=dispatch, decision=decision)
        outcome = _RestRetryOutcome(
            response_error=response_error,
            transport_error=transport_error,
            classification=classification,
            now_ns=now_ns,
            decision=decision,
        )
    except BaseException as transaction_error:
        if sink is not None:
            if item is None:  # pragma: no cover - internal call contract.
                raise RuntimeError("REST failure evidence requires a plan item")
            evidence = attempt_result.failure_evidence
            if evidence is None:  # pragma: no cover - capture always supplies it.
                raise RuntimeError("REST attempt lacks failure evidence")
            await _record_rest_failure_and_fail_closed(
                sink=sink,
                item=item,
                dispatch=dispatch,
                evidence=evidence,
                lease=lease,
                error=transaction_error,
                reason="retry_transaction_failed",
            )
        else:
            await _fail_closed_preserving(lease, transaction_error)
        raise
    return outcome


def _catalog_raw_draft(
    capture: OkxRestCapture,
    *,
    item: RestPlanItem,
) -> NativeEventDraft:
    return NativeEventDraft(
        exchange=Exchange.OKX,
        market=item.market,
        instrument_key=None,
        wire_symbol=None,
        logical_stream="instrument",
        native_channel=item.path,
        transport=Transport.REST,
        event_time_ns=None,
        event_time_source=None,
        coverage=CoverageMode.COMPLETE,
        rest_metadata=capture.rest_metadata,
        payload=dict(capture.payload),
    )


async def _handle_catalog_dispatch(
    *,
    pending: _PendingCatalogRequest,
    dispatch: RestDispatch,
    controller: OkxCatalogController,
    runtime: AdapterRuntime,
    sink: EventSink,
) -> None:
    item = pending.item
    await controller.wait_submission_handoff(pending, runtime)
    if (
        dispatch.route not in item.routes
        or dispatch.route.budget_key[0] != item.exchange.value
        or dispatch.route.budget_key[2] != item.logical_endpoint
        or dispatch.job.attempt < 1
        or dispatch.job.deadline_ns != pending.deadline_ns
    ):
        raise RuntimeError("OKX scheduler violated catalog route evidence")
    try:
        attempt = await _capture_rest_attempt(
            item=item,
            dispatch=dispatch,
            runtime=runtime,
            sink=sink,
        )
    except NetworkAdmissionExpired as error:
        _emit_control(
            sink,
            _rest_control(
                kind="rest_terminal",
                item=item,
                attempt=dispatch.job.attempt,
                reason="network_admission_expired",
                dispatch=dispatch,
            ),
        )
        controller.finish_error(pending, error)
        return
    if attempt.capture is not None:
        capture = attempt.capture
        try:
            _emit_checked(
                sink,
                _catalog_raw_draft(capture, item=item),
                source=capture.source,
                shard=item.shard_id,
                allow_market_overflow=False,
            )
        except BaseException as error:
            await _close_preserving(attempt.lease, error)
            controller.finish_error(pending, error)
            controller._publish_fatal(error, sink_failure=True)
            raise
        parse_failure: tuple[BaseException, _ReleasePreservation] | None = None
        try:
            snapshot = parse_instruments(
                capture.payload,
                item.market,
                observed_at_ns=capture.rest_metadata.request_ended_at_ns,
            )
        except (OkxPayloadError, ValueError) as error:
            try:
                _emit_control(
                    sink,
                    _rest_control(
                        kind="rest_terminal",
                        item=item,
                        attempt=dispatch.job.attempt,
                        reason=type(error).__name__,
                        payload=cast(JsonPayload, dict(capture.payload)),
                        capture=capture,
                    ),
                )
            except BaseException as sink_error:
                await _close_preserving(attempt.lease, sink_error)
                controller.finish_error(pending, sink_error)
                raise
            preservation = await _close_preserving(attempt.lease, error)
            controller.finish_error(pending, error)
            parse_failure = (error, preservation)
        else:
            try:
                await _close_network_lease(attempt.lease)
            except BaseException as error:
                controller.finish_error(pending, error)
                raise
            controller.finish_success(pending, snapshot)
        if parse_failure is not None:
            parse_error, preservation = parse_failure
            if preservation.cancellation is not None:
                raise preservation.cancellation from None
            if not preservation.released:
                raise parse_error from None
        return

    outcome = await _classify_rest_retry_and_release(
        attempt_result=attempt,
        policy=pending.policy,
        dispatch=dispatch,
        runtime=runtime,
        deadline_ns=pending.deadline_ns,
        sink=sink,
        item=item,
    )
    response_error = outcome.response_error
    transport_error = outcome.transport_error
    classification = outcome.classification
    now_ns = outcome.now_ns
    decision = outcome.decision
    kind = "rest_retry" if decision.retry else "rest_terminal"
    try:
        if response_error is not None:
            _emit_control(
                sink,
                _response_error_control(
                    kind=kind,
                    item=item,
                    attempt=dispatch.job.attempt,
                    error=response_error,
                ),
            )
        else:
            _emit_control(
                sink,
                _rest_control(
                    kind=kind,
                    item=item,
                    attempt=dispatch.job.attempt,
                    reason=classification.reason,
                    dispatch=dispatch,
                    request_started_at_ns=attempt.request_started_at_ns,
                    request_ended_at_ns=attempt.request_ended_at_ns,
                    evidence_complete=True,
                    error_type=(
                        None
                        if transport_error is None
                        else type(transport_error).__name__
                    ),
                ),
            )
    except BaseException as error:
        await _close_preserving(attempt.lease, error)
        controller.finish_error(pending, error)
        raise
    try:
        await _close_network_lease(attempt.lease)
    except BaseException as error:
        controller.finish_error(pending, error)
        raise
    if not decision.retry:
        controller.finish_error(
            pending,
            response_error
            or transport_error
            or RuntimeError("OKX catalog retry reached terminal state"),
        )
        return
    try:
        submission_outcome = await _submit_rest_occurrence(
            item=item,
            runtime=runtime,
            scheduled_ns=dispatch.job.scheduled_ns,
            ready_ns=now_ns + decision.delay_ns,
            deadline_ns=pending.deadline_ns,
            attempt=dispatch.job.attempt + 1,
            sticky_route=dispatch.route,
        )
    except CapacityError:
        submission_outcome = _SubmitOutcome(None)
    result = submission_outcome.result
    if result not in _COMMITTED_SUBMIT_RESULTS:
        submission_error = (
            TimeoutError("OKX catalog retry expired before admission")
            if result is SubmitResult.EXPIRED
            else RuntimeError(
                "OKX catalog retry submission failed with "
                f"{result.value if result is not None else 'capacity_exhausted'}"
            )
        )
        _emit_control(
            sink,
            _rest_control(
                kind="rest_terminal",
                item=item,
                attempt=dispatch.job.attempt + 1,
                reason=(
                    "retry_submission_expired"
                    if result is SubmitResult.EXPIRED
                    else "retry_submission_capacity_exhausted"
                    if result is None
                    else f"retry_submission_{result.value}"
                ),
                dispatch=dispatch,
                planned_egress_id=dispatch.route.egress_id,
                sticky_egress_id=dispatch.route.egress_id,
            ),
        )
        controller.finish_error(pending, submission_error)
        return
    controller.mark_queued(
        pending,
        attempt=dispatch.job.attempt + 1,
        sticky_egress_id=dispatch.route.egress_id,
    )
    if submission_outcome.deferred_error is not None:
        raise submission_outcome.deferred_error


@dataclass(slots=True)
class _RoutineRestState:
    item: RestPlanItem
    cadence: StableCadence
    active_scheduled_ns: int | None = None
    active_deadline_ns: int | None = None
    active_attempt: int = 0
    phase: _RestOccurrencePhase | None = None
    terminal_handoff_error: BaseException | None = None
    submission_handoff: asyncio.Event | None = None
    initial_submission_handoff: asyncio.Event = dataclass_field(
        default_factory=asyncio.Event
    )

    def activate(
        self,
        *,
        scheduled_ns: int,
        deadline_ns: int,
        attempt: int,
        submission_pending: bool = False,
    ) -> None:
        self.active_scheduled_ns = scheduled_ns
        self.active_deadline_ns = deadline_ns
        self.active_attempt = attempt
        self.phase = _RestOccurrencePhase.QUEUED
        self.terminal_handoff_error = None
        self.submission_handoff = asyncio.Event()
        if not submission_pending:
            self.submission_handoff.set()

    def finish_submission_handoff(self, error: BaseException | None) -> None:
        self.terminal_handoff_error = error
        if self.submission_handoff is None:
            self.submission_handoff = asyncio.Event()
        self.submission_handoff.set()

    async def wait_submission_handoff(self, runtime: AdapterRuntime) -> None:
        handoff = self.submission_handoff
        if handoff is not None and not handoff.is_set():
            completed = await _await_or_stop(handoff.wait(), runtime)
            if completed is None:
                raise asyncio.CancelledError
        if self.terminal_handoff_error is not None:
            raise self.terminal_handoff_error

    def mark_in_flight(self, *, scheduled_ns: int, attempt: int) -> None:
        if self.terminal_handoff_error is not None:
            raise self.terminal_handoff_error
        if (
            self.active_scheduled_ns != scheduled_ns
            or self.active_attempt != attempt
            or self.phase is not _RestOccurrencePhase.QUEUED
        ):
            raise RuntimeError("OKX REST dispatch does not match queued occurrence")
        self.phase = _RestOccurrencePhase.IN_FLIGHT

    def clear(self, *, scheduled_ns: int) -> None:
        if self.active_scheduled_ns == scheduled_ns:
            self.active_scheduled_ns = None
            self.active_deadline_ns = None
            self.active_attempt = 0
            self.phase = None
            self.terminal_handoff_error = None
            handoff = self.submission_handoff
            self.submission_handoff = None
            if handoff is not None:
                handoff.set()


async def _sleep_until(
    runtime: AdapterRuntime,
    target_ns: int,
) -> bool:
    while not _stop_is_set(runtime.stop):
        now_ns = _monotonic_ns(runtime)
        if now_ns >= target_ns:
            return True
        await _await_or_stop(
            asyncio.sleep((target_ns - now_ns) / _NANOSECONDS_PER_SECOND),
            runtime,
        )
    return False


def _emit_schedule_control(
    sink: EventSink,
    *,
    item: RestPlanItem,
    kind: str,
    reason: str,
    attempt: int = 1,
    planned_egress_id: str | None = None,
    sticky_egress_id: str | None = None,
    scheduled_ns: int | None = None,
    deadline_ns: int | None = None,
    blocked_by_scheduled_ns: int | None = None,
    blocked_by_attempt: int | None = None,
) -> None:
    _emit_control(
        sink,
        _rest_control(
            kind=kind,
            item=item,
            attempt=attempt,
            reason=reason,
            planned_egress_id=planned_egress_id,
            sticky_egress_id=sticky_egress_id,
            scheduled_ns=scheduled_ns,
            deadline_ns=deadline_ns,
            blocked_by_scheduled_ns=blocked_by_scheduled_ns,
            blocked_by_attempt=blocked_by_attempt,
        ),
    )


async def _run_rest_cadence(
    *,
    state: _RoutineRestState,
    runtime: AdapterRuntime,
    sink: EventSink,
) -> None:
    item = state.item
    interval = item.interval_plan
    if interval is None:
        raise ValueError("routine OKX REST plan items require an interval")
    scheduled_ns = state.cadence.anchor_monotonic_ns + state.cadence.phase_ns
    while not _stop_is_set(runtime.stop):
        now_ns = _monotonic_ns(runtime)
        active_deadline_ns = state.active_deadline_ns
        if state.active_scheduled_ns is not None and active_deadline_ns is not None:
            if state.phase is _RestOccurrencePhase.IN_FLIGHT:
                skipped_deadline_ns = min(
                    _MAX_SIGNED_64,
                    scheduled_ns + interval.effective_ns,
                )
                _emit_schedule_control(
                    sink,
                    item=item,
                    kind="rest_cadence_skipped",
                    reason="in_flight",
                    scheduled_ns=scheduled_ns,
                    deadline_ns=skipped_deadline_ns,
                    blocked_by_scheduled_ns=state.active_scheduled_ns,
                    blocked_by_attempt=max(1, state.active_attempt),
                )
            elif now_ns <= active_deadline_ns:
                skipped_deadline_ns = min(
                    _MAX_SIGNED_64,
                    scheduled_ns + interval.effective_ns,
                )
                _emit_schedule_control(
                    sink,
                    item=item,
                    kind="rest_cadence_skipped",
                    reason="active_occurrence",
                    scheduled_ns=scheduled_ns,
                    deadline_ns=skipped_deadline_ns,
                    blocked_by_scheduled_ns=state.active_scheduled_ns,
                    blocked_by_attempt=max(1, state.active_attempt),
                )
            else:
                _emit_schedule_control(
                    sink,
                    item=item,
                    kind="rest_occurrence_expired",
                    reason="scheduler_expired_or_evicted",
                    attempt=max(1, state.active_attempt),
                    scheduled_ns=state.active_scheduled_ns,
                    deadline_ns=active_deadline_ns,
                )
                state.active_scheduled_ns = None
                state.active_deadline_ns = None
                state.active_attempt = 0
                state.phase = None

        if state.active_scheduled_ns is None:
            deadline_ns = min(
                _MAX_SIGNED_64,
                scheduled_ns + interval.effective_ns,
            )
            state.activate(
                scheduled_ns=scheduled_ns,
                deadline_ns=deadline_ns,
                attempt=1,
                submission_pending=True,
            )
            try:
                submission_outcome = await _submit_rest_occurrence(
                    item=item,
                    runtime=runtime,
                    scheduled_ns=scheduled_ns,
                    ready_ns=scheduled_ns,
                    deadline_ns=deadline_ns,
                    attempt=1,
                )
            except (CapacityError, _NoHealthyRestRoute) as error:
                state.clear(scheduled_ns=scheduled_ns)
                _emit_schedule_control(
                    sink,
                    item=item,
                    kind="rest_schedule_rejected",
                    reason=(
                        "capacity_exhausted"
                        if isinstance(error, CapacityError)
                        else "no_healthy_egress"
                    ),
                    scheduled_ns=scheduled_ns,
                    deadline_ns=deadline_ns,
                )
            except BaseException:
                state.clear(scheduled_ns=scheduled_ns)
                raise
            else:
                result = submission_outcome.result
                assert result is not None
                if result in _COMMITTED_SUBMIT_RESULTS:
                    state.finish_submission_handoff(submission_outcome.deferred_error)
                    if submission_outcome.deferred_error is not None:
                        raise submission_outcome.deferred_error
                    if result in {
                        SubmitResult.REPLACED,
                        SubmitResult.EVICTED_AND_ENQUEUED,
                    }:
                        _emit_schedule_control(
                            sink,
                            item=item,
                            kind="rest_schedule_warning",
                            reason=result.value,
                            scheduled_ns=scheduled_ns,
                            deadline_ns=deadline_ns,
                        )
                elif result in {
                    SubmitResult.EXPIRED,
                    SubmitResult.STALE_IGNORED,
                }:
                    state.clear(scheduled_ns=scheduled_ns)
                    _emit_schedule_control(
                        sink,
                        item=item,
                        kind="rest_schedule_rejected",
                        reason=result.value,
                        scheduled_ns=scheduled_ns,
                        deadline_ns=deadline_ns,
                    )
                else:  # pragma: no cover - exhaustive for forward enum changes.
                    raise RuntimeError(
                        f"OKX REST cadence submission failed with {result.value}"
                    )

        state.initial_submission_handoff.set()
        next_target_ns = min(_MAX_SIGNED_64, scheduled_ns + interval.effective_ns)
        if not await _sleep_until(runtime, next_target_ns):
            return
        now_ns = _monotonic_ns(runtime)
        latest_due_ns = state.cadence.latest_due_ns(now_ns)
        scheduled_ns = max(
            next_target_ns,
            latest_due_ns if latest_due_ns is not None else next_target_ns,
        )


@dataclass(frozen=True, slots=True)
class _ClaimedRestDispatch:
    dispatch: RestDispatch
    pending_catalog: _PendingCatalogRequest | None
    routine_state: _RoutineRestState | None


async def _next_rest_dispatch(
    runtime: AdapterRuntime,
    producers: Sequence[asyncio.Task[None]],
    *,
    states: Mapping[str, _RoutineRestState],
    catalog_controller: OkxCatalogController | None,
) -> _ClaimedRestDispatch | None:
    if _stop_is_set(runtime.stop):
        return None

    async def next_and_claim() -> _ClaimedRestDispatch:
        dispatch = await runtime.scheduler.next_ready()
        plan_item_id = dispatch.job.control_context.get("plan_item_id")
        if type(plan_item_id) is not str:
            raise RuntimeError("OKX scheduler returned an unowned REST item")
        pending_catalog = (
            None
            if catalog_controller is None
            else catalog_controller.pending(plan_item_id)
        )
        if pending_catalog is not None:
            assert catalog_controller is not None
            catalog_controller.mark_in_flight(pending_catalog)
            return _ClaimedRestDispatch(dispatch, pending_catalog, None)
        try:
            state = states[plan_item_id]
        except KeyError:
            raise RuntimeError("OKX scheduler returned an unknown plan item") from None
        state.mark_in_flight(
            scheduled_ns=dispatch.job.scheduled_ns,
            attempt=dispatch.job.attempt,
        )
        return _ClaimedRestDispatch(dispatch, None, state)

    owned: list[asyncio.Task[object]] = []
    primary_error: BaseException | None = None
    stopped: asyncio.Task[None] | None = None
    try:
        stopped = _create_owned_task(runtime.stop.wait(), owned)
        operation = _create_owned_task(next_and_claim(), owned)
        waiters = (
            *owned,
            *(cast(asyncio.Task[object], task) for task in producers),
        )
        done, _pending = await asyncio.wait(
            waiters,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for producer in producers:
            if producer not in done:
                continue
            await producer
            if not _stop_is_set(runtime.stop):
                raise RuntimeError("OKX REST cadence producer ended unexpectedly")
        if operation in done:
            return await operation
        if stopped in done:
            try:
                await stopped
            except asyncio.CancelledError:
                if not _stop_is_set(runtime.stop):
                    raise _StopTokenContractError(
                        "stop wait was cancelled before the token was set"
                    ) from None
                raise
            if not _stop_is_set(runtime.stop):
                raise _StopTokenContractError(
                    "stop wait returned before the token was set"
                )
            return None
        if _stop_is_set(runtime.stop):
            return None
        raise RuntimeError("OKX REST wait ended without a dispatch")
    except BaseException as error:
        primary_error = error
        raise
    finally:
        cleanup_failure: BaseException | None = None
        try:
            cleanup_errors = await _cancel_and_collect(owned)
        except BaseException as error:  # noqa: BLE001 - owned task harvest.
            cleanup_errors = ()
            cleanup_failure = error
        try:
            _validate_harvested_stop_waiter(stopped, runtime.stop)
        except BaseException:
            if primary_error is None or isinstance(
                primary_error, asyncio.CancelledError
            ):
                raise
            primary_error.add_note("OKX stop waiter contract also failed")
        if cleanup_failure is not None:
            if primary_error is None:
                raise cleanup_failure
            primary_error.add_note("OKX REST waiter cleanup also failed")
        if cleanup_errors:
            if primary_error is None:
                raise cleanup_errors[0]
            primary_error.add_note("OKX REST waiter cleanup also failed")


async def _run_rest(
    plan: AdapterPlan,
    runtime: AdapterRuntime,
    sink: EventSink,
    *,
    catalog_controller: OkxCatalogController | None,
) -> None:
    instruments = _instrument_index(plan)
    policies = {
        item.id: retry_policy(
            clock=_ValidatedClock(runtime.clock),
            rng=random.Random(
                _stable_seed("rest", item.id, item.egress_id, item.shard_id)
            ),
            max_attempts=runtime.retry.rest_max_attempts,
            base_ns=runtime.retry.base_backoff_ns,
            cap_ns=runtime.retry.max_backoff_ns,
        )
        for item in plan.rest
    }
    anchor_ns = _monotonic_ns(runtime)
    states: dict[str, _RoutineRestState] = {}
    for item in plan.rest:
        interval = item.interval_plan
        if interval is None:
            raise ValueError("routine OKX REST plan items require an interval")
        states[item.id] = _RoutineRestState(
            item=item,
            cadence=StableCadence(
                anchor_monotonic_ns=anchor_ns,
                interval_ns=interval.effective_ns,
                phase_key=item.id,
            ),
        )
    owned_producers: list[asyncio.Task[object]] = []
    producers: tuple[asyncio.Task[None], ...] = ()
    primary_error: BaseException | None = None
    try:
        created_producers: list[asyncio.Task[None]] = []
        producer_finished = asyncio.Event()
        for state in states.values():
            producer = _create_owned_task(
                _run_rest_cadence(state=state, runtime=runtime, sink=sink),
                owned_producers,
            )

            def mark_producer_finished(
                _task: asyncio.Task[None],
                state_: _RoutineRestState = state,
            ) -> None:
                state_.initial_submission_handoff.set()
                producer_finished.set()

            producer.add_done_callback(mark_producer_finished)
            created_producers.append(producer)
        producers = tuple(created_producers)

        async def wait_initial_submissions() -> bool:
            async def wait_all_handoffs() -> None:
                await asyncio.gather(
                    *(
                        state.initial_submission_handoff.wait()
                        for state in states.values()
                    )
                )

            startup_tasks: list[asyncio.Task[object]] = []
            startup_error: BaseException | None = None
            try:
                all_handoffs = _create_owned_task(wait_all_handoffs(), startup_tasks)
                any_producer_finished = _create_owned_task(
                    producer_finished.wait(), startup_tasks
                )
                done, _pending = await asyncio.wait(
                    tuple(startup_tasks),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if any_producer_finished in done:
                    for producer in producers:
                        if producer.done():
                            await producer
                    if not _stop_is_set(runtime.stop):
                        raise RuntimeError(
                            "OKX REST cadence producer ended during startup"
                        )
                    return False
                await all_handoffs
                return True
            except BaseException as error:
                startup_error = error
                raise
            finally:
                try:
                    await _cancel_and_join(startup_tasks)
                except BaseException:
                    if startup_error is None:
                        raise
                    startup_error.add_note(
                        "OKX REST startup barrier cleanup also failed"
                    )

        if states:
            completed = await _await_or_stop(wait_initial_submissions(), runtime)
            if completed is None:
                return
            for producer in producers:
                if producer.done():
                    await producer
            if _stop_is_set(runtime.stop):
                return
        while not _stop_is_set(runtime.stop):
            claimed = await _next_rest_dispatch(
                runtime,
                producers,
                states=states,
                catalog_controller=catalog_controller,
            )
            if claimed is None:
                return
            dispatch = claimed.dispatch
            pending_catalog = claimed.pending_catalog
            if pending_catalog is not None:
                assert catalog_controller is not None
                try:
                    await _handle_catalog_dispatch(
                        pending=pending_catalog,
                        dispatch=dispatch,
                        controller=catalog_controller,
                        runtime=runtime,
                        sink=sink,
                    )
                except BaseException as error:
                    handoff_pending_cancellation = (
                        isinstance(error, asyncio.CancelledError)
                        and not pending_catalog.submission_handoff.is_set()
                    )
                    if (
                        not handoff_pending_cancellation
                        and pending_catalog.terminal_handoff_error is not error
                    ):
                        catalog_controller.finish_error(pending_catalog, error)
                    if not isinstance(error, asyncio.CancelledError):
                        catalog_controller._publish_fatal(
                            error,
                            sink_failure=_SINK_FAILURE_NOTE
                            in getattr(error, "__notes__", ()),
                        )
                    raise
                continue
            claimed_state = claimed.routine_state
            if claimed_state is None:  # pragma: no cover - variants are exhaustive.
                raise RuntimeError("OKX REST dispatch has no claimed owner")
            await claimed_state.wait_submission_handoff(runtime)
            item = claimed_state.item
            if (
                dispatch.route not in item.routes
                or dispatch.route.budget_key[0] != item.exchange.value
                or dispatch.route.budget_key[2] != item.logical_endpoint
                or dispatch.job.attempt < 1
                or dispatch.job.deadline_ns is None
            ):
                raise RuntimeError("OKX scheduler violated REST route evidence")
            try:
                instrument = instruments[(item.market, cast(str, item.instrument_key))]
            except KeyError:
                raise RuntimeError("OKX REST item has no plan instrument") from None
            try:
                attempt = await _capture_rest_attempt(
                    item=item,
                    dispatch=dispatch,
                    runtime=runtime,
                    sink=sink,
                )
            except NetworkAdmissionExpired:
                _emit_control(
                    sink,
                    _rest_control(
                        kind="rest_terminal",
                        item=item,
                        attempt=dispatch.job.attempt,
                        reason="network_admission_expired",
                        dispatch=dispatch,
                    ),
                )
                claimed_state.clear(scheduled_ns=dispatch.job.scheduled_ns)
                continue
            capture = attempt.capture
            if capture is not None:
                parse_failure: tuple[BaseException, _ReleasePreservation] | None = None
                try:
                    draft = _parse_rest_capture(
                        capture,
                        item=item,
                        instrument=instrument,
                    )
                except (OkxPayloadError, ValueError) as error:
                    try:
                        _emit_control(
                            sink,
                            _rest_control(
                                kind="rest_terminal",
                                item=item,
                                attempt=dispatch.job.attempt,
                                reason=type(error).__name__,
                                payload=cast(JsonPayload, dict(capture.payload)),
                                capture=capture,
                            ),
                        )
                    except BaseException as sink_error:
                        await _close_preserving(attempt.lease, sink_error)
                        raise
                    preservation = await _close_preserving(attempt.lease, error)
                    parse_failure = (error, preservation)
                else:
                    try:
                        _emit_checked(
                            sink,
                            draft,
                            source=capture.source,
                            shard=item.shard_id,
                            allow_market_overflow=True,
                        )
                    except BaseException as error:
                        await _close_preserving(attempt.lease, error)
                        raise
                    await _close_network_lease(attempt.lease)
                    claimed_state.clear(scheduled_ns=dispatch.job.scheduled_ns)
                if parse_failure is not None:
                    parse_error, preservation = parse_failure
                    claimed_state.clear(scheduled_ns=dispatch.job.scheduled_ns)
                    if preservation.cancellation is not None:
                        raise preservation.cancellation from None
                    if not preservation.released:
                        raise parse_error from None
                continue

            deadline_ns = dispatch.job.deadline_ns
            outcome = await _classify_rest_retry_and_release(
                attempt_result=attempt,
                policy=policies[item.id],
                dispatch=dispatch,
                runtime=runtime,
                deadline_ns=deadline_ns,
                sink=sink,
                item=item,
            )
            response_error = outcome.response_error
            transport_error = outcome.transport_error
            now_ns = outcome.now_ns
            decision = outcome.decision
            kind = "rest_retry" if decision.retry else "rest_terminal"
            try:
                if response_error is not None:
                    _emit_control(
                        sink,
                        _response_error_control(
                            kind=kind,
                            item=item,
                            attempt=dispatch.job.attempt,
                            error=response_error,
                        ),
                    )
                else:
                    _emit_control(
                        sink,
                        _rest_control(
                            kind=kind,
                            item=item,
                            attempt=dispatch.job.attempt,
                            reason=decision.reason,
                            dispatch=dispatch,
                            request_started_at_ns=attempt.request_started_at_ns,
                            request_ended_at_ns=attempt.request_ended_at_ns,
                            evidence_complete=True,
                            error_type=(
                                None
                                if transport_error is None
                                else type(transport_error).__name__
                            ),
                        ),
                    )
            except BaseException as error:
                await _close_preserving(attempt.lease, error)
                raise
            await _close_network_lease(attempt.lease)
            if not decision.retry:
                claimed_state.clear(scheduled_ns=dispatch.job.scheduled_ns)
                continue
            try:
                submission_outcome = await _submit_rest_occurrence(
                    item=item,
                    runtime=runtime,
                    scheduled_ns=dispatch.job.scheduled_ns,
                    ready_ns=now_ns + decision.delay_ns,
                    deadline_ns=deadline_ns,
                    attempt=dispatch.job.attempt + 1,
                    sticky_route=dispatch.route,
                )
            except CapacityError:
                result = None
                reason = "capacity_exhausted"
            else:
                result = submission_outcome.result
                assert result is not None
                reason = result.value
            if result not in _COMMITTED_SUBMIT_RESULTS:
                _emit_schedule_control(
                    sink,
                    item=item,
                    kind="rest_terminal",
                    reason=f"retry_submission_{reason}",
                    attempt=dispatch.job.attempt + 1,
                    planned_egress_id=dispatch.route.egress_id,
                    sticky_egress_id=dispatch.route.egress_id,
                    scheduled_ns=dispatch.job.scheduled_ns,
                    deadline_ns=deadline_ns,
                )
                claimed_state.clear(scheduled_ns=dispatch.job.scheduled_ns)
                continue
            claimed_state.activate(
                scheduled_ns=dispatch.job.scheduled_ns,
                deadline_ns=deadline_ns,
                attempt=dispatch.job.attempt + 1,
            )
            if submission_outcome.deferred_error is not None:
                claimed_state.finish_submission_handoff(
                    submission_outcome.deferred_error
                )
                raise submission_outcome.deferred_error
    except BaseException as error:
        primary_error = error
        raise
    finally:
        try:
            await _cancel_and_join(owned_producers)
        except BaseException as cleanup_error:
            if primary_error is None or isinstance(
                primary_error, asyncio.CancelledError
            ):
                raise
            if cleanup_error is not primary_error:
                if _SINK_FAILURE_NOTE in getattr(cleanup_error, "__notes__", ()) and (
                    _SINK_FAILURE_NOTE not in getattr(primary_error, "__notes__", ())
                ):
                    raise
                primary_error.add_note("OKX REST producer cleanup also failed")


def _group_websocket_items(
    subscriptions: Sequence[WebSocketSubscription],
) -> tuple[tuple[_WsGroupKey, tuple[WebSocketSubscription, ...]], ...]:
    grouped: dict[_WsGroupKey, list[WebSocketSubscription]] = defaultdict(list)
    for item in subscriptions:
        grouped[
            (
                item.market,
                item.endpoint,
                item.egress_id,
                item.quota_group,
                item.shard_id,
            )
        ].append(item)
    return tuple(
        (
            key,
            tuple(sorted(items, key=lambda item: item.id)),
        )
        for key, items in sorted(
            grouped.items(),
            key=lambda pair: (
                pair[0][0].value,
                pair[0][1],
                pair[0][2],
                pair[0][3],
                pair[0][4],
            ),
        )
    )


def _matching_subscription(
    subscriptions: Sequence[WebSocketSubscription],
    message: OkxWsMessage,
) -> WebSocketSubscription:
    argument = message.argument
    if argument is None:
        raise _WsGenerationError("OKX data frame has no subscription argument")
    matches: list[tuple[int, WebSocketSubscription]] = []
    for item in subscriptions:
        expected = subscription_argument(item)
        if all(argument.get(name) == value for name, value in expected.items()):
            matches.append((len(expected), item))
    if not matches:
        raise _WsGenerationError("OKX data frame does not match a planned subscription")
    specificity = max(size for size, _item in matches)
    selected = [item for size, item in matches if size == specificity]
    if len(selected) != 1:
        raise _WsGenerationError("OKX data frame ambiguously matches subscriptions")
    return selected[0]


def _timestamp_ns(value: object) -> int | None:
    if type(value) is not str or not value.isascii() or not value.isdigit():
        return None
    milliseconds = int(value)
    if milliseconds > _MAX_SIGNED_64 // 1_000_000:
        return None
    return milliseconds * 1_000_000


def _message_timestamp(message: OkxWsMessage) -> int | None:
    payload = message.payload
    if payload is None:
        return None
    data = payload.get("data")
    if not isinstance(data, list) or not data:
        return None
    timestamps: set[int] = set()
    for row in data:
        if not isinstance(row, Mapping):
            return None
        timestamp = _timestamp_ns(row.get("ts"))
        if timestamp is None:
            return None
        timestamps.add(timestamp)
    return next(iter(timestamps)) if len(timestamps) == 1 else None


def _validate_data_identity(
    item: WebSocketSubscription,
    message: OkxWsMessage,
) -> None:
    expected = item.wire_symbol
    if expected is None:
        return
    payload = message.payload
    if payload is None:
        raise _WsGenerationError("OKX data message has no payload")
    data = payload.get("data")
    if not isinstance(data, list):
        raise _WsGenerationError("OKX data message requires a data array")
    for row in data:
        if not isinstance(row, Mapping):
            raise _WsGenerationError("OKX data rows must be objects")
        returned = row.get("instId")
        if returned is not None and returned != expected:
            raise _WsGenerationError("OKX data row instrument does not match its route")


def _ws_source(
    *,
    generation: int,
    egress_id: str,
    local_connection_id: str,
) -> SourceContext:
    return SourceContext(
        connection_id=local_connection_id,
        connection_generation=generation,
        egress_id=egress_id,
    )


def _ws_control_draft(
    *,
    kind: str,
    market: Market,
    connection_id: str,
    generation: int,
    egress_id: str,
    reason: str | None = None,
    frame: JsonPayload | None = None,
    error_type: str | None = None,
    server_connection_id: str | None = None,
    raw_binary_base64: str | None = None,
    raw_binary_length: int | None = None,
) -> NativeEventDraft:
    payload: dict[str, JsonPayload] = {
        "kind": kind,
        "origin_transport": "websocket",
        "market": market.value,
        "connection_id": connection_id,
        "connection_generation": generation,
        "egress_id": egress_id,
    }
    if reason is not None:
        payload["reason"] = reason
    if frame is not None:
        payload["frame"] = frame
    if error_type is not None:
        payload["error_type"] = error_type
    if server_connection_id is not None:
        payload["server_connection_id"] = server_connection_id
    if raw_binary_base64 is not None:
        payload["frame_encoding"] = "base64"
        payload["frame_base64"] = raw_binary_base64
        payload["frame_byte_length"] = raw_binary_length
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
        payload=payload,
    )


def _book_gap_draft(
    *,
    market: Market,
    instrument_key: str,
    connection_id: str,
    generation: int,
    egress_id: str,
    reason: str,
) -> NativeEventDraft:
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
        payload={
            "kind": "book_gap",
            "origin_transport": "websocket",
            "reason": reason,
            "market": market.value,
            "instrument_key": instrument_key,
            "connection_id": connection_id,
            "connection_generation": generation,
            "egress_id": egress_id,
        },
    )


def _book_sequence_reset_draft(
    *,
    market: Market,
    instrument_key: str,
    connection_id: str,
    generation: int,
    egress_id: str,
) -> NativeEventDraft:
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
        payload={
            "kind": "book_sequence_reset",
            "origin_transport": "websocket",
            "reason": "maintenance_sequence_reset",
            "market": market.value,
            "instrument_key": instrument_key,
            "connection_id": connection_id,
            "connection_generation": generation,
            "egress_id": egress_id,
        },
    )


def _data_draft(
    *,
    item: WebSocketSubscription,
    message: OkxWsMessage,
) -> NativeEventDraft:
    if message.payload is None:
        raise ValueError("OKX data message has no payload")
    _validate_data_identity(item, message)
    event_time_ns = (
        None if item.logical_stream == "liquidation" else _message_timestamp(message)
    )
    return NativeEventDraft(
        exchange=Exchange.OKX,
        market=item.market,
        instrument_key=item.instrument_key,
        wire_symbol=item.wire_symbol,
        logical_stream=item.logical_stream,
        native_channel=item.channel,
        transport=Transport.WEBSOCKET,
        event_time_ns=event_time_ns,
        event_time_source=None if event_time_ns is None else "okx.data[].ts",
        coverage=(
            CoverageMode.LOSSY_WINDOW
            if item.logical_stream == "liquidation"
            else CoverageMode.UNKNOWN
            if item.logical_stream == "status"
            else None
        ),
        payload=dict(message.payload),
    )


def _handle_book_message(
    *,
    item: WebSocketSubscription,
    message: OkxWsMessage,
    state: OkxBookState,
    source: SourceContext,
    sink: EventSink,
) -> bool:
    if message.payload is None:
        raise ValueError("OKX book message has no payload")
    _validate_data_identity(item, message)
    reason: str | None = None
    integrity = IntegrityMode.SEQUENCE_VERIFIED
    event_time_ns = _message_timestamp(message)
    try:
        frames = parse_incremental_book_frames(message)
    except OkxBookParseError:
        frames = ()
        reason = "book_parse_error"
        integrity = IntegrityMode.INVALID
    for frame in frames:
        outcome = state.apply(frame)
        if outcome.integrity is IntegrityMode.INVALID:
            integrity = IntegrityMode.INVALID
            reason = outcome.control_reason or "book_generation_invalid"
            break
        if outcome.control_reason is not None:
            reason = outcome.control_reason

    draft = NativeEventDraft(
        exchange=Exchange.OKX,
        market=item.market,
        instrument_key=item.instrument_key,
        wire_symbol=item.wire_symbol,
        logical_stream=item.logical_stream,
        native_channel=item.channel,
        transport=Transport.WEBSOCKET,
        event_time_ns=event_time_ns,
        event_time_source=None if event_time_ns is None else "okx.data[].ts",
        integrity_mode=integrity,
        coverage=CoverageMode.COMPLETE,
        payload=dict(message.payload),
    )
    # The invalid native frame is durable before its control record requests a
    # new generation.
    accepted = _emit_checked(
        sink,
        draft,
        source=source,
        shard=item.shard_id,
        allow_market_overflow=True,
    )
    if not accepted:
        return True
    if reason is None:
        return False
    if item.instrument_key is None:
        raise ValueError("OKX book subscription must be instrument-scoped")
    control = (
        _book_gap_draft(
            market=item.market,
            instrument_key=item.instrument_key,
            connection_id=cast(str, source.connection_id),
            generation=cast(int, source.connection_generation),
            egress_id=cast(str, source.egress_id),
            reason=reason,
        )
        if integrity is IntegrityMode.INVALID
        else _book_sequence_reset_draft(
            market=item.market,
            instrument_key=item.instrument_key,
            connection_id=cast(str, source.connection_id),
            generation=cast(int, source.connection_generation),
            egress_id=cast(str, source.egress_id),
        )
    )
    _emit_checked(
        sink,
        control,
        source=SourceContext.internal(),
        shard="_control",
        allow_market_overflow=False,
    )
    return integrity is IntegrityMode.INVALID


def _emit_session_control(
    *,
    sink: EventSink,
    source: SourceContext,
    market: Market,
    generation: int,
    kind: str,
    reason: str | None = None,
    frame: JsonPayload | None = None,
    error_type: str | None = None,
    server_connection_id: str | None = None,
    raw_binary_base64: str | None = None,
    raw_binary_length: int | None = None,
) -> None:
    _emit_checked(
        sink,
        _ws_control_draft(
            kind=kind,
            market=market,
            connection_id=cast(str, source.connection_id),
            generation=generation,
            egress_id=cast(str, source.egress_id),
            reason=reason,
            frame=frame,
            error_type=error_type,
            server_connection_id=server_connection_id,
            raw_binary_base64=raw_binary_base64,
            raw_binary_length=raw_binary_length,
        ),
        source=SourceContext.internal(),
        shard="_control",
        allow_market_overflow=False,
    )


@asynccontextmanager
async def _leased_ws_session(
    session: OkxWsSession,
    lease: NetworkAdmissionLease,
    *,
    runtime: AdapterRuntime,
    egress_id: str,
    on_transport_failure: Callable[[BaseException], Awaitable[None]] | None = None,
):
    body_error: BaseException | None = None
    try:
        try:
            async with session:
                yield
        except (OSError, TimeoutError, WebSocketException) as error:
            if (
                lease.release_disposition
                is NetworkAdmissionReleaseDisposition.FAIL_CLOSED
            ):
                raise
            if on_transport_failure is not None:
                await on_transport_failure(error)
            else:
                try:
                    _record_transport_failure(
                        runtime,
                        transport=Transport.WEBSOCKET,
                        egress_id=egress_id,
                        reason=type(error).__name__,
                    )
                except BaseException as health_error:
                    await _fail_closed_preserving(lease, health_error)
                    raise
            raise
    except BaseException as error:
        body_error = error
        raise
    finally:
        if lease.release_disposition is None:
            if body_error is None:
                await _close_network_lease(lease)
            else:
                await _close_preserving(lease, body_error)


async def _run_ws_group(
    *,
    key: _WsGroupKey,
    subscriptions: tuple[WebSocketSubscription, ...],
    plan: AdapterPlan,
    runtime: AdapterRuntime,
    sink: EventSink,
) -> None:
    market, endpoint, egress_id, quota_group, shard_id = key
    instruments = _instrument_index(plan)
    reconnect_policy = OkxWsReconnectPolicy(
        base_ns=runtime.retry.base_backoff_ns,
        cap_ns=runtime.retry.ws_reconnect_max_backoff_ns,
    )
    rng = random.Random(_stable_seed("ws", market.value, endpoint, egress_id, shard_id))
    generation = 0
    reconnect_attempt = 0
    previous_egress_id: str | None = None
    group_identity = sha256(f"{endpoint}\0{egress_id}".encode()).hexdigest()[:12]

    while not _stop_is_set(runtime.stop):
        generation += 1
        health = runtime.transport_health
        generation_egress_id = (
            egress_id
            if health is None
            else health.choose_websocket_egress(
                exchange=Exchange.OKX,
                market=market,
                endpoint=endpoint,
                preferred_egress_id=egress_id,
                previous_egress_id=previous_egress_id,
            )
        )
        if type(generation_egress_id) is not str or not generation_egress_id:
            raise TypeError(
                "transport health must return a non-empty websocket egress ID"
            )
        try:
            generation_quota_group = plan.egress_quota_groups[generation_egress_id]
        except KeyError:
            raise RuntimeError(
                "websocket fallback egress is outside the frozen adapter plan"
            ) from None
        if generation_egress_id == egress_id and generation_quota_group != quota_group:
            raise RuntimeError("websocket group quota changed after planning")
        transport = runtime.transport_for(generation_egress_id).websocket
        previous_egress_id = generation_egress_id
        local_connection_id = (
            f"okx-{market.value}-{subscriptions[0].shard_id}-"
            f"{group_identity}-{generation}-{uuid4().hex}"
        )
        session = OkxWsSession(
            transport,
            subscriptions,
            request_id=f"g{generation}",
        )
        book_states = {
            cast(str, item.instrument_key): OkxBookState(
                allow_crossed=(
                    instruments[
                        (item.market, cast(str, item.instrument_key))
                    ].lifecycle_phase
                    is LifecyclePhase.PREOPEN
                )
            )
            for item in subscriptions
            if item.logical_stream == "book_live"
        }
        reconnect_reason = "transport_error"
        made_progress = False
        lease = await _acquire_network_lease(
            runtime=runtime,
            exchange=Exchange.OKX,
            transport=Transport.WEBSOCKET,
            egress_id=generation_egress_id,
            quota_group=generation_quota_group,
            deadline_ns=None,
        )
        if lease is None:
            return
        generation_lease: NetworkAdmissionLease = lease

        async def record_transport_failure(
            error: BaseException,
            generation_: int = generation,
            generation_egress_id_: str = generation_egress_id,
            local_connection_id_: str = local_connection_id,
            lease_: NetworkAdmissionLease = generation_lease,
        ) -> None:
            source = _ws_source(
                generation=generation_,
                egress_id=generation_egress_id_,
                local_connection_id=local_connection_id_,
            )
            try:
                _emit_session_control(
                    sink=sink,
                    source=source,
                    market=market,
                    generation=generation_,
                    kind="ws_reconnect",
                    reason="transport_error",
                    error_type=type(error).__name__,
                )
            except BaseException as sink_error:
                await _fail_closed_preserving(lease_, sink_error)
                raise
            try:
                _record_transport_failure(
                    runtime,
                    transport=Transport.WEBSOCKET,
                    egress_id=generation_egress_id_,
                    reason=type(error).__name__,
                )
            except BaseException as health_error:
                await _fail_closed_preserving(lease_, health_error)
                raise

        try:
            async with _leased_ws_session(
                session,
                lease,
                runtime=runtime,
                egress_id=generation_egress_id,
                on_transport_failure=record_transport_failure,
            ):
                while not _stop_is_set(runtime.stop):
                    event = await _await_or_stop(session.receive(), runtime)
                    if event is None:
                        return
                    source = _ws_source(
                        generation=generation,
                        egress_id=generation_egress_id,
                        local_connection_id=local_connection_id,
                    )
                    if event.action is OkxWsSessionAction.PING_SENT:
                        _emit_session_control(
                            sink=sink,
                            source=source,
                            market=market,
                            generation=generation,
                            kind="ws_ping_sent",
                        )
                        continue
                    if event.action is OkxWsSessionAction.RECONNECT:
                        if event.reconnect_reason is None:
                            raise RuntimeError(
                                "OKX reconnect event lacks a reconnect reason"
                            )
                        reconnect_reason = event.reconnect_reason.value
                        error_type = event.error_type or event.reconnect_reason.name
                        frame = (
                            cast(JsonPayload, event.message.payload)
                            if event.message is not None
                            else event.raw_text
                        )
                        try:
                            _emit_session_control(
                                sink=sink,
                                source=source,
                                market=market,
                                generation=generation,
                                kind="ws_reconnect",
                                reason=reconnect_reason,
                                frame=frame,
                                error_type=error_type,
                                raw_binary_base64=event.raw_binary_base64,
                                raw_binary_length=event.raw_binary_length,
                            )
                        except BaseException as sink_error:
                            await _fail_closed_preserving(lease, sink_error)
                            raise
                        if event.reconnect_reason in {
                            OkxWsReconnectReason.TRANSPORT_ERROR,
                            OkxWsReconnectReason.PONG_TIMEOUT,
                            OkxWsReconnectReason.SUBSCRIPTION_TIMEOUT,
                        }:
                            try:
                                _record_transport_failure(
                                    runtime,
                                    transport=Transport.WEBSOCKET,
                                    egress_id=generation_egress_id,
                                    reason=error_type,
                                )
                            except BaseException as health_error:
                                await _fail_closed_preserving(lease, health_error)
                                raise
                        break

                    message = event.message
                    if message is None:  # pragma: no cover - session event validates.
                        raise RuntimeError("OKX session message event has no message")
                    if message.kind is OkxWsMessageKind.DATA:
                        try:
                            item = _matching_subscription(subscriptions, message)
                            if item.logical_stream == "book_live":
                                if item.instrument_key is None:
                                    raise ValueError(
                                        "OKX book subscription lacks an instrument"
                                    )
                                state = book_states[item.instrument_key]
                                reconnect = _handle_book_message(
                                    item=item,
                                    message=message,
                                    state=state,
                                    source=source,
                                    sink=sink,
                                )
                            else:
                                accepted = _emit_checked(
                                    sink,
                                    _data_draft(item=item, message=message),
                                    source=source,
                                    shard=item.shard_id,
                                    allow_market_overflow=True,
                                )
                                reconnect = not accepted
                        except _WsGenerationError as error:
                            _emit_session_control(
                                sink=sink,
                                source=source,
                                market=market,
                                generation=generation,
                                kind="ws_reconnect",
                                reason=type(error).__name__,
                                frame=cast(JsonPayload, message.payload),
                            )
                            reconnect = True
                        if reconnect:
                            reconnect_reason = "market_overflow_or_invalid_frame"
                            break
                        made_progress = True
                        continue

                    kind = {
                        OkxWsMessageKind.PONG: "ws_pong",
                        OkxWsMessageKind.SUBSCRIBE_ACK: "ws_subscribe_ack",
                        OkxWsMessageKind.UNSUBSCRIBE_ACK: "ws_unsubscribe_ack",
                        OkxWsMessageKind.ERROR: "ws_error",
                        OkxWsMessageKind.NOTICE: "ws_notice",
                    }[message.kind]
                    _emit_session_control(
                        sink=sink,
                        source=source,
                        market=market,
                        generation=generation,
                        kind=kind,
                        frame=(
                            cast(JsonPayload, message.payload)
                            if message.payload is not None
                            else message.raw_text
                        ),
                        server_connection_id=(
                            message.connection_id
                            if message.kind is OkxWsMessageKind.SUBSCRIBE_ACK
                            else None
                        ),
                    )
                if _stop_is_set(runtime.stop):
                    return
        except asyncio.CancelledError:
            raise
        except (OSError, TimeoutError, WebSocketException):
            if (
                lease.release_disposition
                is NetworkAdmissionReleaseDisposition.FAIL_CLOSED
            ):
                raise
            reconnect_reason = "transport_error"
        if made_progress:
            reconnect_attempt = 0
        delay_ns = reconnect_policy.delay_ns(reconnect_attempt, rng=rng)
        reconnect_attempt += 1
        if delay_ns:
            await _await_or_stop(
                asyncio.sleep(delay_ns / _NANOSECONDS_PER_SECOND),
                runtime,
            )
            if _stop_is_set(runtime.stop):
                return


def _preflight_okx_plan(
    *,
    plan: AdapterPlan,
    runtime: AdapterRuntime,
    groups: tuple[tuple[_WsGroupKey, tuple[WebSocketSubscription, ...]], ...],
) -> None:
    _validate_okx_plan_identity(plan)
    if plan.ws or plan.rest or plan.catalog:
        _require_network_admission(runtime)
    if (plan.rest or plan.catalog) and runtime.retry_effects is None:
        raise RuntimeError("OKX REST work requires retry effects")
    for egress_id in plan.egress_quota_groups:
        runtime.transport_for(egress_id)
    for item in (*plan.rest, *plan.catalog):
        if item in plan.rest and item.interval_plan is None:
            raise ValueError("routine OKX REST plan items require an interval")
        if item in plan.catalog and (
            item.interval_plan is not None
            or item.logical_stream != "instrument"
            or item.instrument_key is not None
            or item.wire_symbol is not None
        ):
            raise ValueError(
                "OKX catalog items must be one-shot market-scoped instruments"
            )
        _request_for_item(item)
        for route in item.routes:
            runtime.transport_for(route.egress_id)
    for key, subscriptions in groups:
        market, endpoint, egress_id, quota_group, shard_id = key
        if plan.egress_quota_groups.get(egress_id) != quota_group:
            raise RuntimeError("websocket group has no frozen egress quota mapping")
        if any(
            (
                item.market,
                item.endpoint,
                item.egress_id,
                item.quota_group,
                item.shard_id,
            )
            != (market, endpoint, egress_id, quota_group, shard_id)
            for item in subscriptions
        ):
            raise RuntimeError("websocket group route identity is inconsistent")
        transport = runtime.transport_for(egress_id).websocket
        OkxWsSession(transport, subscriptions, request_id="preflight")


async def run_okx_plan(
    plan: AdapterPlan,
    runtime: AdapterRuntime,
    sink: EventSink,
    *,
    catalog_controller: OkxCatalogController | None = None,
) -> None:
    if type(plan) is not AdapterPlan or plan.exchange is not Exchange.OKX:
        raise ValueError("OKX execution requires an OKX adapter plan")
    if type(runtime) is not AdapterRuntime:
        raise TypeError("runtime must be AdapterRuntime")
    if not callable(getattr(sink, "try_emit", None)):
        raise TypeError("sink must provide try_emit()")
    if catalog_controller is not None and not catalog_controller.owns_runtime(runtime):
        raise ValueError("catalog controller must own the execution runtime")

    groups = _group_websocket_items(plan.ws)
    _preflight_okx_plan(plan=plan, runtime=runtime, groups=groups)
    internal_stop = asyncio.Event()
    execution_runtime = replace(
        runtime,
        stop=_CombinedStopToken(runtime.stop, internal_stop),
    )
    children: list[asyncio.Task[None]] = []
    owned: list[asyncio.Task[object]] = []
    stop_task: asyncio.Task[None] | None = None
    body_error: BaseException | None = None
    cleanup_errors: tuple[BaseException, ...] = ()
    try:
        for key, subscriptions in groups:
            children.append(
                _create_owned_task(
                    _run_ws_group(
                        key=key,
                        subscriptions=subscriptions,
                        plan=plan,
                        runtime=execution_runtime,
                        sink=sink,
                    ),
                    owned,
                )
            )
        if plan.rest or plan.catalog or catalog_controller is not None:
            children.append(
                _create_owned_task(
                    _run_rest(
                        plan,
                        execution_runtime,
                        sink,
                        catalog_controller=catalog_controller,
                    ),
                    owned,
                )
            )
        if catalog_controller is not None:
            children.append(_create_owned_task(catalog_controller.wait_fatal(), owned))
        stop_task = _create_owned_task(execution_runtime.stop.wait(), owned)
        if not children:
            try:
                await stop_task
            except asyncio.CancelledError:
                if not _stop_is_set(execution_runtime.stop):
                    raise _StopTokenContractError(
                        "stop wait was cancelled before the token was set"
                    ) from None
                raise
            if not _stop_is_set(execution_runtime.stop):
                raise _StopTokenContractError(
                    "stop wait returned before the token was set"
                )
        else:
            done, _pending = await asyncio.wait(
                (*children, stop_task),
                return_when=asyncio.FIRST_COMPLETED,
            )
            completed_errors: list[BaseException] = []
            completed_children = 0
            for task in children:
                if task not in done:
                    continue
                completed_children += 1
                if task.cancelled():
                    if not _stop_is_set(runtime.stop):
                        completed_errors.append(asyncio.CancelledError())
                    continue
                error = task.exception()
                if error is not None:
                    completed_errors.append(error)
            if completed_errors:
                raise completed_errors[0]
            if completed_children and not _stop_is_set(execution_runtime.stop):
                raise RuntimeError("OKX execution task ended unexpectedly")
            if stop_task in done:
                try:
                    await stop_task
                except asyncio.CancelledError:
                    if not _stop_is_set(execution_runtime.stop):
                        raise _StopTokenContractError(
                            "stop wait was cancelled before the token was set"
                        ) from None
                    raise
                if not _stop_is_set(execution_runtime.stop):
                    raise _StopTokenContractError(
                        "stop wait returned before the token was set"
                    )
    except asyncio.CancelledError as error:
        body_error = error
    except Exception as error:  # noqa: BLE001 - child tasks surface adapter failures.
        body_error = error
    finally:
        internal_stop.set()

        async def cleanup() -> tuple[BaseException, ...]:
            errors: list[BaseException] = []
            try:
                errors.extend(await _cancel_and_collect(owned))
            except BaseException as error:  # noqa: BLE001 - owned task harvest.
                errors.append(error)
            try:
                _validate_harvested_stop_waiter(stop_task, execution_runtime.stop)
            except BaseException as error:  # noqa: BLE001 - validate stop port.
                errors.append(error)
            if catalog_controller is not None:
                try:
                    await catalog_controller.close()
                except BaseException as error:  # noqa: BLE001 - cleanup evidence.
                    errors.append(error)
                fatal_error = catalog_controller.fatal_error()
                if fatal_error is not None and all(
                    error is not fatal_error for error in errors
                ):
                    errors.append(fatal_error)
            return tuple(errors)

        cleanup_coroutine = cleanup()
        try:
            cleanup_task = asyncio.create_task(cleanup_coroutine)
        except BaseException as setup_error:  # noqa: BLE001 - task factory boundary.
            cleanup_coroutine.close()
            try:
                cleanup_errors = await cleanup()
            except BaseException as cleanup_error:  # noqa: BLE001
                cleanup_errors = (cleanup_error,)
            if body_error is None:
                body_error = setup_error
            else:
                body_error.add_note("OKX cleanup task setup also failed")
        else:
            cleanup_cancellation: asyncio.CancelledError | None = None
            while not cleanup_task.done():
                try:
                    await asyncio.shield(cleanup_task)
                except asyncio.CancelledError as error:
                    if cleanup_cancellation is None:
                        cleanup_cancellation = error
            cleanup_errors = cleanup_task.result()
            if body_error is None and cleanup_cancellation is not None:
                body_error = cleanup_cancellation
    controller_fatal_error = (
        None if catalog_controller is None else catalog_controller.fatal_error()
    )
    controller_sink_error = (
        controller_fatal_error
        if catalog_controller is not None and catalog_controller.fatal_is_sink_failure()
        else None
    )
    sink_error = (
        controller_sink_error
        if controller_sink_error is not None
        else next(
            (
                error
                for error in cleanup_errors
                if isinstance(error, _SinkRejectedError)
                or _SINK_FAILURE_NOTE in getattr(error, "__notes__", ())
            ),
            None,
        )
    )
    stop_contract_error = next(
        (
            error
            for error in cleanup_errors
            if isinstance(error, _StopTokenContractError)
        ),
        None,
    )
    if stop_contract_error is not None:
        primary_for_stop_note = sink_error
        if primary_for_stop_note is None and isinstance(
            body_error, asyncio.CancelledError
        ):
            primary_for_stop_note = controller_fatal_error
        if primary_for_stop_note is None:
            primary_for_stop_note = body_error
        if primary_for_stop_note is not None:
            primary_for_stop_note.add_note("stop token contract also failed")
            cleanup_errors = tuple(
                error for error in cleanup_errors if error is not stop_contract_error
            )
    release_cleanup_failed = any(
        isinstance(error, NetworkAdmissionReleaseError)
        or (
            isinstance(error, asyncio.CancelledError)
            and _NETWORK_ADMISSION_RELEASE_FAILURE_NOTE
            in getattr(error, "__notes__", ())
        )
        for error in cleanup_errors
    )
    if body_error is not None and release_cleanup_failed:
        if _NETWORK_ADMISSION_RELEASE_FAILURE_NOTE not in getattr(
            body_error, "__notes__", ()
        ):
            body_error.add_note(_NETWORK_ADMISSION_RELEASE_FAILURE_NOTE)
        cleanup_errors = tuple(
            error
            for error in cleanup_errors
            if not isinstance(error, NetworkAdmissionReleaseError)
            and not (
                isinstance(error, asyncio.CancelledError)
                and _NETWORK_ADMISSION_RELEASE_FAILURE_NOTE
                in getattr(error, "__notes__", ())
            )
        )
    if sink_error is not None:
        raise sink_error
    if (
        isinstance(body_error, asyncio.CancelledError)
        and controller_fatal_error is not None
    ):
        raise controller_fatal_error
    if body_error is not None:
        raise body_error
    if cleanup_errors:
        raise cleanup_errors[0]


async def _fetch_okx_catalog_once(
    *,
    runtime: AdapterRuntime,
    market: Market,
    item: RestPlanItem,
) -> CompleteCatalogSnapshot:
    if type(runtime) is not AdapterRuntime:
        raise TypeError("runtime must be AdapterRuntime")
    if type(market) is not Market or item.market is not market:
        raise ValueError("catalog item must match the requested market")
    if item.logical_stream != "instrument" or item.interval_plan is not None:
        raise ValueError("catalog item must be a one-shot instrument request")
    _require_network_admission(runtime)
    if runtime.retry_effects is None:
        raise RuntimeError("OKX catalog work requires retry effects")
    _request_for_item(item)
    for route in item.routes:
        runtime.transport_for(route.egress_id)
    scheduled_ns = _monotonic_ns(runtime)
    deadline_ns = min(_MAX_SIGNED_64, scheduled_ns + _CATALOG_DEADLINE_NS)
    policy = retry_policy(
        clock=_ValidatedClock(runtime.clock),
        rng=random.Random(
            _stable_seed("catalog", market.value, item.egress_id, item.shard_id)
        ),
        max_attempts=runtime.retry.rest_max_attempts,
        base_ns=runtime.retry.base_backoff_ns,
        cap_ns=runtime.retry.max_backoff_ns,
    )
    attempt = 1
    ready_ns = scheduled_ns
    sticky_route: RestBudgetRoute | None = None
    while True:
        submission_outcome = await _submit_rest_occurrence(
            item=item,
            runtime=runtime,
            scheduled_ns=scheduled_ns,
            ready_ns=ready_ns,
            deadline_ns=deadline_ns,
            attempt=attempt,
            sticky_route=sticky_route,
        )
        result = submission_outcome.result
        assert result is not None
        if result not in _COMMITTED_SUBMIT_RESULTS:
            if result is SubmitResult.EXPIRED:
                raise TimeoutError("OKX catalog expired before admission")
            raise RuntimeError(f"OKX catalog submission failed with {result.value}")
        if submission_outcome.deferred_error is not None:
            raise submission_outcome.deferred_error
        dispatch = await _await_or_stop_until(
            runtime.scheduler.next_ready(),
            runtime,
            deadline_ns=deadline_ns,
        )
        if dispatch is None:
            raise asyncio.CancelledError
        if dispatch.job.control_context.get("plan_item_id") != item.id:
            raise RuntimeError("OKX catalog received another scheduler dispatch")
        if (
            dispatch.route not in item.routes
            or dispatch.route.budget_key[0] != item.exchange.value
            or dispatch.route.budget_key[2] != item.logical_endpoint
            or dispatch.job.deadline_ns != deadline_ns
            or (sticky_route is not None and dispatch.route != sticky_route)
        ):
            raise RuntimeError("OKX catalog scheduler changed its retry egress")
        sticky_route = dispatch.route
        attempt_result = await _capture_rest_attempt(
            item=item,
            dispatch=dispatch,
            runtime=runtime,
        )
        capture = attempt_result.capture
        if capture is not None:
            try:
                snapshot = parse_instruments(
                    capture.payload,
                    market,
                    observed_at_ns=capture.rest_metadata.request_ended_at_ns,
                )
            except BaseException as error:
                await _close_preserving(attempt_result.lease, error)
                raise
            await _close_network_lease(attempt_result.lease)
            return snapshot
        outcome = await _classify_rest_retry_and_release(
            attempt_result=attempt_result,
            policy=policy,
            dispatch=dispatch,
            runtime=runtime,
            deadline_ns=deadline_ns,
        )
        response_error = outcome.response_error
        transport_error = outcome.transport_error
        now_ns = outcome.now_ns
        decision = outcome.decision
        if not decision.retry:
            terminal_error = (
                response_error
                or transport_error
                or RuntimeError("OKX catalog retry policy reached terminal state")
            )
            await _close_preserving(attempt_result.lease, terminal_error)
            raise terminal_error
        await _close_network_lease(attempt_result.lease)
        attempt += 1
        ready_ns = now_ns + decision.delay_ns


async def fetch_okx_catalog(
    *,
    runtime: AdapterRuntime,
    market: Market,
    item: RestPlanItem,
) -> CompleteCatalogSnapshot:
    if type(runtime) is not AdapterRuntime:
        raise TypeError("runtime must be AdapterRuntime")
    runtime.ensure_run_not_claimed()
    try:
        return await _fetch_okx_catalog_once(
            runtime=runtime,
            market=market,
            item=item,
        )
    except BaseException:
        runtime.poison()
        raise


__all__ = ["fetch_okx_catalog", "run_okx_plan"]
