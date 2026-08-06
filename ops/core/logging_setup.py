"""One redaction-covered stdout handler, and the run correlation on every line.

Production emitted four log lines in six days, none carrying a run id. Nothing
was broken: nothing had ever configured logging. ``install_redacting_filter``
was called on five loggers at api/app.py and browser_service/main.py, but a
filter is not a sink -- no handler was ever attached and the root logger kept
its default WARNING level, so every ``LOGGER.info`` in the codebase formatted
nothing and went nowhere. When a run failed there was no line to read.

Two things have to be true for a log line to be both useful and safe:

* It must reach a handler at all. ``configure_logging`` attaches exactly one
  StreamHandler to the root logger, so every ``composio_ops.*`` logger reaches
  it by propagation without needing its own sink.
* The redaction must live on the HANDLER, not only on the loggers. A filter
  attached to a logger runs only for records logged *directly* to that logger;
  CPython does not consult it for records that arrive by propagation from a
  child. A filter on the handler is consulted for every record the handler
  emits, whatever logger it came from. That distinction is the whole reason the
  fourteen ``composio_ops.*`` loggers have no coverage today, and it is why the
  filter here is attached before the handler joins the root logger.

Correlation is a ContextVar rather than a parameter. The alternative is
threading a run id through every call site in the browser and onboarding paths,
which is precisely the code that logs least today.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
from collections.abc import Generator
from contextvars import ContextVar
from typing import Final, TextIO

from ops.core.redaction import RedactingFilter, install_redacting_filter

HANDLER_NAME: Final = "composio_ops_stdout"

# DEBUG is deliberately not reachable by setting OPS_LOG_LEVEL alone. Debug
# records in the browser paths carry page text and action arguments, and no
# text-level scrubber can be trusted with a rendered signup form. Turning it on
# takes two variables, one of which is never set in production.
_LEVELS: Final[dict[str, int]] = {
    "CRITICAL": logging.CRITICAL,
    "ERROR": logging.ERROR,
    "WARNING": logging.WARNING,
    "INFO": logging.INFO,
}

_run_id: ContextVar[str | None] = ContextVar("composio_ops_run_id", default=None)


def current_run_id() -> str | None:
    """Return the run this task is executing, if it was bound."""

    return _run_id.get()


@contextlib.contextmanager
def run_context(run_id: str | None) -> Generator[None]:
    """Bind ``run_id`` onto every log record emitted inside this block.

    ContextVars follow ``asyncio`` task boundaries, so a background task started
    inside the block inherits the binding and a sibling run never sees it.
    """

    token = _run_id.set(run_id)
    try:
        yield
    finally:
        _run_id.reset(token)


class RunContextFilter(logging.Filter):
    """Stamp the ambient run id onto records that do not already carry one."""

    def filter(self, record: logging.LogRecord) -> bool:
        if getattr(record, "run_id", None) is None:
            record.run_id = _run_id.get()
        return True


class _RunFormatter(logging.Formatter):
    """Render the run id inline so ``grep run_abc123`` finds every line."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        run_id = getattr(record, "run_id", None)
        return f"{rendered} run_id={run_id}" if run_id else rendered


class _QuietStreamHandler(logging.StreamHandler):  # type: ignore[type-arg]
    """A handler whose failure path cannot print the unredacted record.

    ``logging.Handler.handleError`` writes ``repr(record.msg)`` and the raw
    ``record.args`` to stderr. Those are the pre-redaction values: a formatting
    mistake anywhere would hand the original credential straight to the very
    stream this module exists to protect.
    """

    def handleError(self, record: logging.LogRecord) -> None:
        try:
            sys.stderr.write(f"[logging] suppressed handler error for {record.name}\n")
        except Exception:  # pragma: no cover - stderr itself is gone
            pass


def _resolve_level(source: os._Environ[str] | dict[str, str]) -> int:
    raw = str(source.get("OPS_LOG_LEVEL", "") or "").strip().upper()
    if raw == "DEBUG" and str(source.get("OPS_ALLOW_DEBUG_LOGGING", "")).strip() == "true":
        return logging.DEBUG
    # An unrecognised value must not crash startup and must not silently mean
    # "log nothing"; INFO is the level this deployment is expected to run at.
    return _LEVELS.get(raw, logging.INFO)


def configure_logging(
    *,
    stream: TextIO | None = None,
    source: os._Environ[str] | dict[str, str] | None = None,
) -> logging.Handler:
    """Install the single redaction-covered stdout handler. Idempotent.

    Returns the handler, whether it was created now or on an earlier call, so a
    second invocation under a uvicorn reload cannot double up sinks.
    """

    environment = os.environ if source is None else source
    root = logging.getLogger()

    existing = next((item for item in root.handlers if item.name == HANDLER_NAME), None)
    if existing is not None:
        root.setLevel(_resolve_level(environment))
        return existing

    handler = _QuietStreamHandler(stream or sys.stdout)
    handler.name = HANDLER_NAME
    handler.setFormatter(_RunFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    # Order matters. Both filters go on the handler BEFORE it is attached, so
    # there is no window in which the handler is live and unfiltered, and so the
    # run id is stamped on records that reached the handler by propagation.
    handler.addFilter(RunContextFilter())
    handler.addFilter(RedactingFilter())
    root.addHandler(handler)
    install_redacting_filter(root)
    root.setLevel(_resolve_level(environment))

    # Fail closed. A handler on the root logger that is missing its redactor
    # would broadcast every credential the application holds, so refuse to run
    # rather than serve traffic in that state.
    if not any(isinstance(item, RedactingFilter) for item in handler.filters):
        root.removeHandler(handler)
        raise RuntimeError("refusing to log: the stdout handler lost its redacting filter")
    return handler


__all__ = [
    "HANDLER_NAME",
    "RunContextFilter",
    "configure_logging",
    "current_run_id",
    "run_context",
]
