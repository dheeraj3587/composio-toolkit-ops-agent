"""Structured, secret-safe logging for the frontend <-> Browser Use link.

The live browser onboarding path crosses several boundaries that used to fail
silently: the frontend run-creation/resume request, the synchronous workflow
dispatch, the Browser Use session creation and ``run`` call, the signed live-URL
derivation, and the live-view endpoint the frontend polls. When any hop fails,
this module leaves a single, greppable, correlated trail in stdout (captured by
``docker logs``) so the failing stage is obvious.

Safety: this logger never emits secret material. Signed live URLs, CDP URLs, and
credentials are reduced to a host or a boolean presence flag before logging, and
the shared :class:`ops.redaction.RedactingFilter` is attached as a second line of
defence that scrubs any secret-looking substring from every record.

Every event is a one-line JSON object prefixed with ``blink`` so it can be found
with ``docker logs ... | grep blink`` and parsed by eye or by tools.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from collections.abc import Iterable, Mapping
from urllib.parse import urlsplit

from ops.redaction import install_redacting_filter

_LOGGER_NAME = "composio_ops.browser_link"
_MESSAGE_PREFIX = "blink"
_configured = False


def _configure() -> logging.Logger:
    """Return the dedicated link logger, configuring stdout output once.

    Application loggers here propagate to a root logger that has no INFO handler
    under uvicorn, so INFO events would be dropped. This attaches an explicit
    stdout handler at the configured level (default INFO) and disables
    propagation to avoid duplicate emission through the root "last resort"
    handler.
    """

    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    if _configured:
        return logger

    level_name = os.environ.get("BROWSER_LINK_LOG_LEVEL", "INFO").strip().upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))

    if not any(isinstance(handler, logging.StreamHandler) for handler in logger.handlers):
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
        logger.addHandler(handler)

    logger.propagate = False
    # Reuse the shared redactor so no secret substring can survive in a record.
    install_redacting_filter(logger)
    _configured = True
    return logger


_LOGGER = _configure()


def url_host(url: object) -> str | None:
    """Return only the host of a URL, dropping any path/query that could carry a token."""

    if not isinstance(url, str) or not url:
        return None
    try:
        return urlsplit(url).hostname
    except Exception:
        return None


def field_keys(mapping: Mapping[str, object] | Iterable[str] | None) -> list[str]:
    """Return sorted key names only (never values) from a credential mapping."""

    if mapping is None:
        return []
    try:
        keys = list(mapping.keys()) if isinstance(mapping, Mapping) else list(mapping)
    except Exception:
        return []
    return sorted(str(key) for key in keys)


def log_event(event: str, *, level: int = logging.INFO, **fields: object) -> None:
    """Emit one structured JSON line for a link-lifecycle event.

    ``None`` fields are dropped to keep lines compact. Values are serialized with
    ``default=str`` and then pass through the redaction filter attached to the
    logger, so any secret-looking content is masked before it reaches stdout.
    """

    payload: dict[str, object] = {"event": event}
    for key, value in fields.items():
        if value is not None:
            payload[key] = value
    try:
        rendered = json.dumps(payload, default=str, sort_keys=True)
    except Exception:
        rendered = json.dumps({"event": event, "render_error": True})
    _LOGGER.log(level, "%s %s", _MESSAGE_PREFIX, rendered)


__all__ = ["field_keys", "log_event", "url_host"]
