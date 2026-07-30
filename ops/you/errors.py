"""Turning You.com SDK failures into typed, sanitized provider errors.

Two rules shape this module.

A programming error is never disguised as a provider outage. TypeError,
AttributeError and friends propagate untouched, so a bug in our own code surfaces in
tests and monitoring instead of being reported as "You.com is unavailable" and
silently degrading a hundred runs to the verified baseline.

Nothing from the provider's message text is ever surfaced. The mapping produces a
reason code derived from the exception TYPE and, for HTTP errors, the status class
only. Provider prose can contain the query or fragments of fetched pages, so it is
never propagated into a reason code, a log line or run state.

Retries are configured once, deliberately: the SDK auto-retries by default, so a
single explicit bounded RetryConfig keeps behavior deterministic (429/5xx plus
connection errors, bounded elapsed time) rather than stacking a second retry layer
on top of the SDK's own.
"""

from __future__ import annotations

import asyncio
import importlib
from typing import Any, Literal

import httpx


# --------------------------------------------------------------------------
# Sanitized provider-error mapping + one bounded SDK retry layer
# --------------------------------------------------------------------------
class YouProviderError(RuntimeError):
    """A sanitized You.com failure. Never carries provider payload or the API key."""

    def __init__(self, *, capability: str, reason_code: str) -> None:
        self.capability = capability
        self.reason_code = reason_code
        super().__init__(f"{capability} failed: {reason_code}")


# Signals the INTEGRATION is broken (wrong kwarg, renamed module, bad attribute)
# rather than a provider/network failure. These are never mapped to a provider
# reason code, never retried, and never degraded to the baseline — they must
# reach monitoring/tests. (Section 12.)
_PROGRAMMING_ERRORS: tuple[type[Exception], ...] = (
    TypeError,
    AttributeError,
    NameError,
    ImportError,
    ModuleNotFoundError,
)


# Transient transport failures worth surfacing as a sanitized transient reason.
# (PoolTimeout is deliberately excluded — it signals local resource pressure.)
_TRANSIENT_TRANSPORT: tuple[type[Exception], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.WriteTimeout,
    httpx.RemoteProtocolError,
)


_TIMEOUT_AND_TRANSPORT: tuple[type[Exception], ...] = (TimeoutError, *_TRANSIENT_TRANSPORT)


def map_you_error(
    exc: Exception, *, capability: Literal["you_search", "you_contents", "you_research"]
) -> str:
    """Map a You.com provider exception to a stable, sanitized reason code.

    Reads only ``exc.status_code`` (the one stable attribute every ``YouError``
    exposes). ``.message``/``.body``/``.headers`` and the raw exception text are
    never read for logging or user-facing output.
    """

    if isinstance(exc, TimeoutError):
        return f"{capability}_timeout"
    status = getattr(exc, "status_code", None)
    if status == 400:
        return f"{capability}_invalid_request"
    if status == 401:
        return f"{capability}_unauthorized"
    if status == 402:
        return f"{capability}_credit_exhausted"
    if status == 403:
        return f"{capability}_forbidden"
    if status == 404:
        return f"{capability}_not_found"
    if status == 422:
        return (
            f"{capability}_invalid_schema"
            if capability == "you_research"
            else f"{capability}_invalid_request"
        )
    if status == 429:
        return f"{capability}_rate_limited"
    if isinstance(exc, _TRANSIENT_TRANSPORT):
        return f"{capability}_timeout"
    return f"{capability}_failed"


def _bounded_retry_config() -> object:
    """One explicit, bounded RetryConfig — the SDK's retry layer, made deterministic.

    Only 429 and selected transient 5xx (plus connection errors) retry, with a
    bounded total elapsed time. Client 4xx (400/401/402/403/404/422) are NOT in
    the override set, so they never retry. This is the ONLY retry layer; no
    custom retry loop wraps the SDK call.
    """

    retries = importlib.import_module("youdotcom.utils.retries")
    return retries.RetryConfig(
        strategy="backoff",
        backoff=retries.BackoffStrategy(
            initial_interval=500,
            max_interval=8_000,
            exponent=1.5,
            max_elapsed_time=20_000,
            jitter_ms=250,
        ),
        retry_connection_errors=True,
        status_codes_override=["429", "500", "502", "503", "504"],
    )


def _you_error_types() -> tuple[type[BaseException], ...]:
    """The installed SDK's provider error base class, if it can be imported.

    Imported lazily and tolerantly: this module is importable (and unit-testable)
    without the You.com SDK present.
    """

    try:
        errors = importlib.import_module("youdotcom.errors")
    except Exception:
        return ()
    base = getattr(errors, "YouError", None)
    if isinstance(base, type) and issubclass(base, BaseException):
        return (base,)
    return ()


def _is_provider_failure(exc: BaseException) -> bool:
    """Whether an exception is an EXPECTED provider failure worth sanitizing.

    Either an SDK ``YouError`` or something carrying its one stable attribute, an
    integer ``status_code``. A programming error (``TypeError``, ``NameError``,
    ``AttributeError``), an ``AssertionError``, or a Pydantic contract error has
    no ``status_code`` and therefore is NOT a provider failure — it must surface.
    """

    if isinstance(exc, _you_error_types()):
        return True
    return isinstance(getattr(exc, "status_code", None), int)


async def _guard_call(
    capability: Literal["you_search", "you_contents", "you_research"],
    factory: Any,
    *,
    timeout_seconds: float,
) -> Any:
    """Run one provider coroutine with an outer timeout and sanitized mapping.

    ``factory`` must itself open and close the ``You`` client via ``async with``
    so the client is torn down even on timeout/cancellation. Only timeouts,
    transport failures, and real provider errors become a
    :class:`YouProviderError`; everything else (broken integration, contract
    drift, assertion failures) propagates so it is visible to tests/monitoring
    instead of being reported as a provider outage.
    """

    try:
        return await asyncio.wait_for(factory(), timeout=timeout_seconds)
    except _PROGRAMMING_ERRORS:
        raise
    except _TIMEOUT_AND_TRANSPORT as exc:
        raise YouProviderError(
            capability=capability, reason_code=map_you_error(exc, capability=capability)
        ) from None
    except Exception as exc:
        # Deliberately NOT a catch-all: an unknown exception is re-raised.
        if not _is_provider_failure(exc):
            raise
        raise YouProviderError(
            capability=capability, reason_code=map_you_error(exc, capability=capability)
        ) from None
