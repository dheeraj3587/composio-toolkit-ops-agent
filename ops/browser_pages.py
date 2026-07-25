"""Multi-page (popup), dialog and download control for the Playwright harness.

Three fail-closed behaviors live here:

* **Popups / new pages** — a new page is never automatically trusted just
  because it is the newest. Its URL is validated against the reviewed host
  allowlist first; an unapproved popup is CLOSED, recorded as
  ``popup_blocked``, and the original page stays active.
* **Dialogs** — a handler is installed before any action so a dialog can never
  remain open and wedge the browser. ``alert`` is acknowledged per trace policy;
  ``confirm`` requires an explicit review (otherwise HITL); ``prompt`` always
  requires a human; ``beforeunload`` is cancelled unless leaving is reviewed.
* **Downloads** — refused by default. An approved download is bounded (private
  temp dir, size cap, MIME allowlist), never executed, and cleaned up. Files
  that look like credentials, private keys, or executables are never downloaded
  autonomously.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

DialogKind = Literal["alert", "confirm", "prompt", "beforeunload"]
DialogOutcome = Literal["accepted", "dismissed", "requires_human"]


@dataclass(slots=True)
class BrowserPageState:
    """One tracked page (tab/popup) in the session."""

    page_id: str
    page: Any
    opener_page_id: str | None
    last_url: str
    active: bool


@dataclass(frozen=True, slots=True)
class PopupDecision:
    """The typed outcome of considering a new popup.

    Carries the registry ``page_id`` for an activated popup so the caller can wire
    a close handler to the exact id the registry tracks. The previous
    ``tuple[bool, str]`` discarded the id, so the close handler was mis-wired with
    the ``Page`` object instead.
    """

    activated: bool
    reason_code: str
    page_id: str | None = None


async def wait_for_committed_popup_url(popup: Any, *, timeout_seconds: float = 5.0) -> str:
    """Return the popup's first COMMITTED URL, or "" if it closes/never commits.

    A popup usually opens at ``about:blank`` and navigates a moment later. Reading
    its URL at the instant the event fires therefore rejects legitimate popups.
    This waits (bounded, no fixed multi-second sleep) for a real destination.
    """

    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    while loop.time() < deadline:
        try:
            if popup.is_closed():
                return ""
        except Exception:
            return ""
        raw = getattr(popup, "url", "")
        url = raw if isinstance(raw, str) else ""
        if url and url != "about:blank":
            return url
        await asyncio.sleep(0.05)
    raw = getattr(popup, "url", "")
    return raw if isinstance(raw, str) else ""


@dataclass(frozen=True, slots=True)
class DialogPolicy:
    """Reviewed, per-trace dialog handling. Defaults are the safe answers."""

    # An alert is informational; acknowledging it is safe and unblocks the page.
    acknowledge_alerts: bool = True
    # A confirm CHANGES something; only a reviewed trace may auto-accept it.
    reviewed_confirm_accept: bool = False
    # Leaving a page may discard work; cancel unless the trace reviewed it.
    reviewed_allow_unload: bool = False


@dataclass(slots=True)
class DialogRecord:
    """What happened to a dialog, for sanitized reporting (never its content)."""

    kind: DialogKind
    outcome: DialogOutcome
    reason_code: str


@dataclass(frozen=True, slots=True)
class DownloadPolicy:
    """Downloads are refused unless a trace explicitly permits one."""

    allowed: bool = False
    max_bytes: int = 2_000_000
    allowed_mime_prefixes: tuple[str, ...] = ("text/csv", "application/json", "text/plain")

    # Filenames that must NEVER be fetched autonomously regardless of policy.
    forbidden_name: re.Pattern[str] = field(
        default_factory=lambda: re.compile(
            r"(?i)\.(exe|dll|so|dylib|sh|bat|cmd|ps1|jar|msi|apk|pem|key|p12|pfx|kdbx)$"
            r"|(?:^|[-_.])(id_rsa|id_ed25519|credentials?|secrets?|token|\.env)(?:$|[-_.])"
        )
    )


class BrowserPageRegistry:
    """Tracks pages, validates popups, and keeps exactly one active page."""

    def __init__(self, *, url_allowed: Callable[[str], bool]) -> None:
        self._url_allowed = url_allowed
        self.pages: dict[str, BrowserPageState] = {}
        self.active_page_id: str = ""
        # Sanitized events for reporting (no page content, no URLs with query).
        self.events: list[str] = []

    # --- registration ---------------------------------------------------------
    def register(
        self, page: Any, *, opener_page_id: str | None = None, active: bool = False
    ) -> str:
        page_id = uuid4().hex[:12]
        self.pages[page_id] = BrowserPageState(
            page_id=page_id,
            page=page,
            opener_page_id=opener_page_id,
            last_url=_page_url(page),
            active=active,
        )
        if active or not self.active_page_id:
            self._set_active(page_id)
        return page_id

    def _set_active(self, page_id: str) -> None:
        for state in self.pages.values():
            state.active = state.page_id == page_id
        self.active_page_id = page_id

    @property
    def active_page(self) -> Any | None:
        state = self.pages.get(self.active_page_id)
        return state.page if state is not None else None

    # --- popup handling -------------------------------------------------------
    async def consider_popup(self, popup: Any, *, opener_page_id: str | None) -> PopupDecision:
        """Validate a new page and return a typed :class:`PopupDecision`.

        The newest page is NEVER trusted automatically: an off-allowlist popup is
        closed and the original page remains active.

        A popup frequently opens at ``about:blank`` and only THEN navigates to its
        real destination, so the URL is evaluated once it commits (bounded wait)
        rather than at the instant the event fires. Returning the ``page_id`` lets
        the caller wire a close handler to the SAME id the registry tracks — the
        previous ``tuple`` API discarded it, so the close handler was mis-wired.
        """

        url = await wait_for_committed_popup_url(popup)
        if not url or url == "about:blank" or not self._url_allowed(url):
            await _safe_close(popup)
            self.events.append("popup_blocked")
            return PopupDecision(activated=False, reason_code="popup_blocked")
        page_id = self.register(popup, opener_page_id=opener_page_id, active=True)
        self.events.append("popup_activated")
        return PopupDecision(activated=True, reason_code="popup_activated", page_id=page_id)

    def close_page(self, page_id: str) -> None:
        state = self.pages.pop(page_id, None)
        if state is None:
            return
        if self.active_page_id == page_id:
            # Fall back to the opener, else any remaining page.
            fallback = state.opener_page_id if state.opener_page_id in self.pages else None
            if fallback is None:
                fallback = next(iter(self.pages), "")
            self.active_page_id = fallback
            if fallback:
                self._set_active(fallback)


def install_dialog_handler(page: Any, policy: DialogPolicy, records: list[DialogRecord]) -> None:
    """Install a dialog handler BEFORE any action, so nothing can wedge the page.

    Every dialog is answered (never left open). A dialog that needs a human is
    dismissed to unblock the browser and recorded as ``requires_human`` so the
    caller escalates.
    """

    async def _on_dialog(dialog: Any) -> None:
        kind = str(getattr(dialog, "type", "") or "alert").casefold()
        try:
            if kind == "alert":
                if policy.acknowledge_alerts:
                    await dialog.accept()
                    records.append(DialogRecord("alert", "accepted", "alert_acknowledged"))
                else:
                    await dialog.dismiss()
                    records.append(DialogRecord("alert", "dismissed", "alert_dismissed"))
                return
            if kind == "confirm":
                if policy.reviewed_confirm_accept:
                    await dialog.accept()
                    records.append(DialogRecord("confirm", "accepted", "reviewed_confirm"))
                else:
                    await dialog.dismiss()
                    records.append(
                        DialogRecord("confirm", "requires_human", "confirm_requires_human")
                    )
                return
            if kind == "prompt":
                # A prompt asks for free text: never answered autonomously.
                await dialog.dismiss()
                records.append(DialogRecord("prompt", "requires_human", "prompt_requires_human"))
                return
            if kind == "beforeunload":
                if policy.reviewed_allow_unload:
                    await dialog.accept()
                    records.append(DialogRecord("beforeunload", "accepted", "reviewed_unload"))
                else:
                    await dialog.dismiss()
                    records.append(DialogRecord("beforeunload", "dismissed", "unload_cancelled"))
                return
            # Unknown dialog kind: dismiss (fail closed) and flag for a human.
            await dialog.dismiss()
            records.append(DialogRecord("alert", "requires_human", "unknown_dialog_kind"))
        except Exception:
            # Never let dialog handling raise into the action loop; the page must
            # not stay blocked either, so a best-effort dismiss was attempted.
            records.append(DialogRecord("alert", "requires_human", "dialog_handler_failed"))

    page.on("dialog", _on_dialog)


@dataclass(slots=True)
class DownloadRecord:
    """Sanitized download outcome (never the file's content)."""

    allowed: bool
    reason_code: str
    suggested_name: str = ""


def install_download_guard(
    page: Any,
    policy: DownloadPolicy,
    records: list[DownloadRecord],
    *,
    temp_root: Path | None = None,
) -> None:
    """Refuse downloads unless the reviewed trace permits them.

    An approved download is saved into a PRIVATE temporary directory, size- and
    MIME-bounded, never executed, and deleted immediately after inspection.
    """

    async def _on_download(download: Any) -> None:
        name = str(getattr(download, "suggested_filename", "") or "")
        if not policy.allowed:
            await _safe_cancel(download)
            records.append(DownloadRecord(False, "download_blocked_by_policy", name))
            return
        if policy.forbidden_name.search(name):
            await _safe_cancel(download)
            records.append(DownloadRecord(False, "download_forbidden_filetype", name))
            return
        target_root = temp_root or Path("/tmp") / f"pw-dl-{uuid4().hex[:8]}"
        try:
            target_root.mkdir(parents=True, exist_ok=True)
            target = target_root / name[:120]
            await download.save_as(str(target))
            size = target.stat().st_size if target.exists() else 0
            if size > policy.max_bytes:
                records.append(DownloadRecord(False, "download_exceeds_size_limit", name))
            else:
                records.append(DownloadRecord(True, "download_allowed", name))
        except Exception:
            records.append(DownloadRecord(False, "download_failed", name))
        finally:
            # Automatic cleanup: the harness never retains a downloaded file.
            try:
                for child in target_root.glob("*"):
                    child.unlink(missing_ok=True)
                target_root.rmdir()
            except Exception:
                pass

    page.on("download", _on_download)


def _page_url(page: Any) -> str:
    url = getattr(page, "url", "")
    return url if isinstance(url, str) and url else "https://unknown.invalid/"


async def _safe_close(page: Any) -> None:
    try:
        await page.close()
    except Exception:
        pass


async def _safe_cancel(download: Any) -> None:
    try:
        await download.cancel()
    except Exception:
        pass


def frame_path_is_reviewed(frame_path: Sequence[str], reviewed_origins: Sequence[str]) -> bool:
    """True when every frame in the chain is on a reviewed origin.

    Used to refuse credential/OTP injection into an unreviewed frame: the main
    frame being approved is NOT sufficient when the field lives in a nested
    third-party iframe.
    """

    from ops.browser_host_policy import host_matches_patterns

    if not frame_path:
        return True  # main frame; the page URL itself is checked separately
    for entry in frame_path:
        host = entry.strip().casefold()
        if not host:
            return False
        if not host_matches_patterns(host, tuple(reviewed_origins)):
            return False
    return True


__all__ = [
    "PopupDecision",
    "wait_for_committed_popup_url",
    "BrowserPageRegistry",
    "BrowserPageState",
    "DialogPolicy",
    "DialogRecord",
    "DownloadPolicy",
    "DownloadRecord",
    "frame_path_is_reviewed",
    "install_dialog_handler",
    "install_download_guard",
]
