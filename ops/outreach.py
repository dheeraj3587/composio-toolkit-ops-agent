"""Provider-neutral outreach drafting boundary."""

from __future__ import annotations

from dataclasses import dataclass

from ops.graph import PhaseUnavailableError
from ops.models import CompanyProfile, OperationalResearch


@dataclass(frozen=True, slots=True)
class OutreachDraft:
    subject: str
    body: str


def correlation_subject(*, app_name: str, run_id: str) -> str:
    """Build the plan's deterministic, non-secret email-thread subject."""

    short_run_id = run_id.replace("-", "")[:8]
    return f"[API Access Request][run:{short_run_id}] {app_name} × Composio"


class OutreachComposer:
    async def compose(
        self,
        *,
        company: CompanyProfile,
        research: OperationalResearch,
        recipient: str,
        requested_scopes: tuple[str, ...],
    ) -> OutreachDraft:
        del company, research, recipient, requested_scopes
        raise PhaseUnavailableError(phase=4, capability="provider outreach drafting")
