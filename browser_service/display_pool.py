"""Per-session X display slots for interactive HITL.

Why this exists: interactive remote control used to be capped at ONE session
(``PLAYWRIGHT_MAX_SESSIONS=1``) because the container ran a single Xvfb on ``:99``
with a single x11vnc on ``5900``. That cap was not a memory limit — it was the
only thing preventing a cross-session leak. x11vnc serves a WHOLE display, so two
headful Chromium processes sharing ``:99`` means a grant scoped to session A
streams a desktop that also contains session B's window (and B's login or
credential page). All of the per-session authorization in
``browser_service.novnc.authorize_live_view`` would be decorative at the display
layer.

The fix is to make a display an OWNED, LEASED resource rather than a global one:

* slot ``i`` is display ``:(display_base + i)`` with control x11vnc on
  ``vnc_port_base + i`` and server-enforced read-only x11vnc on
  ``view_vnc_port_base + i``,
* a session leases exactly one slot for its whole lifetime,
* that session's Chromium launches with that slot's ``DISPLAY``, so the slot's
  desktop contains that session's browser and nothing else,
* the noVNC relay connects to the LEASED slot's port, so a grant can only ever
  reach the desktop belonging to its own session.

Isolation therefore holds by construction: one session per display, one display
per session. The pool is deliberately fail-closed — a session that cannot get a
slot does not fall back to sharing one.

The pool is synchronous and lock-guarded because it is touched from several
application threads (request handlers and the janitor's close path), matching
``SessionManager``'s own locking discipline.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

# Hard ceiling on concurrent display stacks. Each slot is an Xvfb + fluxbox +
# x11vnc trio plus a headful Chromium, so this is a resource guard, not a policy.
MAX_DISPLAY_SLOTS = 10


class DisplayUnavailable(RuntimeError):
    """No display slot is free. Carries a reason code, never a display address."""

    def __init__(self, reason_code: str = "display_slot_exhausted") -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class DisplaySlot:
    """One X display and the x11vnc port serving it.

    ``vnc_port`` is always reached over container loopback; it is never published
    and never derived from a caller-supplied value.
    """

    index: int
    display_num: int
    vnc_port: int
    view_vnc_port: int

    @property
    def display(self) -> str:
        """The ``DISPLAY`` value Chromium must be launched with (e.g. ``:99``)."""

        return f":{self.display_num}"


class DisplayPool:
    """Leases one display slot per session, releasing each exactly once.

    A pool with ``slots=0`` is INERT: ``acquire`` returns ``None`` rather than
    raising. That is the headless deployment, where no display exists and none is
    needed, so the caller does not have to special-case the feature flag.
    """

    def __init__(
        self,
        *,
        slots: int,
        display_base: int = 99,
        vnc_port_base: int = 5_900,
        view_vnc_port_base: int = 5_910,
    ) -> None:
        if slots < 0:
            raise ValueError("display slot count cannot be negative")
        if slots > MAX_DISPLAY_SLOTS:
            raise ValueError(f"at most {MAX_DISPLAY_SLOTS} display slots are supported")
        self._lock = threading.Lock()
        self._all: tuple[DisplaySlot, ...] = tuple(
            DisplaySlot(
                index=index,
                display_num=display_base + index,
                vnc_port=vnc_port_base + index,
                view_vnc_port=view_vnc_port_base + index,
            )
            for index in range(slots)
        )
        # Indexes still free. A set (not a counter) so a released slot is
        # identifiable and a double release cannot inflate capacity.
        self._free: set[int] = {slot.index for slot in self._all}

    @property
    def enabled(self) -> bool:
        """False for a headless deployment that owns no displays."""

        return bool(self._all)

    @property
    def total(self) -> int:
        return len(self._all)

    @property
    def in_use(self) -> int:
        with self._lock:
            return len(self._all) - len(self._free)

    def slots(self) -> tuple[DisplaySlot, ...]:
        """Every configured slot, used to render the entrypoint's display stack."""

        return self._all

    def acquire(self) -> DisplaySlot | None:
        """Lease a free slot, or ``None`` when the pool is inert (headless).

        Raises ``DisplayUnavailable`` when displays EXIST but all are leased —
        that is a real refusal, distinct from "this deployment has no displays".
        """

        with self._lock:
            if not self._all:
                return None
            if not self._free:
                raise DisplayUnavailable()
            index = min(self._free)
            self._free.discard(index)
            return self._all[index]

    def release(self, slot: DisplaySlot | None) -> None:
        """Return a slot to the pool. Idempotent, so a retried close is safe."""

        if slot is None:
            return
        with self._lock:
            if 0 <= slot.index < len(self._all):
                self._free.add(slot.index)


__all__ = [
    "MAX_DISPLAY_SLOTS",
    "DisplayPool",
    "DisplaySlot",
    "DisplayUnavailable",
]
