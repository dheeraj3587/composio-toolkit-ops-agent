"""Typed boundary for classification of already-sanitized email threads."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from ops.gmail_worker import SanitizedGmailThread
from ops.graph import PhaseUnavailableError
from ops.models import CompanyProfile

ReplyClass = Literal[
    "no_reply",
    "more_information_required",
    "meeting_requested",
    "approved_setup_required",
    "credentials_received",
    "rejected",
    "automated_response",
    "unclear",
]


@dataclass(frozen=True, slots=True)
class ReplyClassification:
    classification: ReplyClass
    explicit_questions: tuple[str, ...]
    official_setup_urls: tuple[str, ...]
    stated_reason: str | None
    required_next_action: str | None
    start_browser_onboarding: bool


class ReplyClassifier:
    async def classify(
        self,
        *,
        app_name: str,
        sanitized_thread: SanitizedGmailThread,
        company: CompanyProfile,
    ) -> ReplyClassification:
        del app_name, sanitized_thread, company
        raise PhaseUnavailableError(phase=4, capability="sanitized reply classification")
