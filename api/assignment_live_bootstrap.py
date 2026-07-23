"""Small bootstrap that installs the assignment live-evidence adapters."""

from __future__ import annotations

from api.assignment_live_evidence import install_assignment_live_evidence


def install_assignment_live_bootstrap() -> None:
    """Install assignment live-evidence adapters before API startup."""

    install_assignment_live_evidence()


__all__ = ["install_assignment_live_bootstrap"]
