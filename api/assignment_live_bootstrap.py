"""Small bootstrap that installs the assignment live-evidence adapters."""

from __future__ import annotations

from typing import Any, cast

import api.assignment_live_evidence as live_evidence
from ops.browser_host_policy import evaluate_navigation


def install_assignment_live_bootstrap() -> None:
    """Bind the reviewed navigation evaluator and install assignment adapters."""

    browser_module = cast(Any, live_evidence.browser_worker_module)
    browser_module.evaluate_navigation = evaluate_navigation
    live_evidence.install_assignment_live_evidence()


__all__ = ["install_assignment_live_bootstrap"]
