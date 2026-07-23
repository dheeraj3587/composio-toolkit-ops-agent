"""Typed boundary for classification of already-sanitized email threads.

The classifier is deterministic and offline: it inspects the already-sanitized
thread (secrets are replaced with ``[REDACTED_SECRET:...]`` placeholders before
this runs) and maps the latest inbound reply to a bounded reply class. It never
sees or reconstructs secret values.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from ops.gmail_worker import SanitizedGmailThread
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

_URL = re.compile(r"https://[^\s<>()\"']+")


@dataclass(frozen=True, slots=True)
class ReplyClassification:
    classification: ReplyClass
    explicit_questions: tuple[str, ...]
    official_setup_urls: tuple[str, ...]
    stated_reason: str | None
    required_next_action: str | None
    start_browser_onboarding: bool


def _latest_inbound_body(thread: SanitizedGmailThread) -> str | None:
    """Return the body of the latest message that is not our own outreach.

    We cannot always tell sender identity from a sanitized thread, so a thread
    with a single message is treated as our own outreach (no reply yet); with
    two or more messages the last one is the provider reply.
    """

    if len(thread.messages) < 2:
        return None
    body = thread.messages[-1].sanitized_body or ""
    # Keep only the new reply text, dropping the quoted original ("On ... wrote:"
    # and lines beginning with ">") so classification reflects what the provider
    # actually wrote, not our own quoted outreach.
    body = re.split(r"(?im)^\s*On .*wrote:\s*$", body)[0]
    lines = [line for line in body.splitlines() if not line.lstrip().startswith(">")]
    return "\n".join(lines).strip()


def _questions(body: str) -> tuple[str, ...]:
    lines = [line.strip() for line in re.split(r"[\r\n]+", body) if "?" in line]
    return tuple(line[:300] for line in lines[:10])


class ReplyClassifier:
    """Deterministic, offline reply classifier over sanitized threads."""

    async def classify(
        self,
        *,
        app_name: str,
        sanitized_thread: SanitizedGmailThread,
        company: CompanyProfile | None = None,
    ) -> ReplyClassification:
        del app_name, company
        body = _latest_inbound_body(sanitized_thread)
        if body is None:
            return ReplyClassification(
                classification="no_reply",
                explicit_questions=(),
                official_setup_urls=(),
                stated_reason=None,
                required_next_action="Wait for the provider to reply.",
                start_browser_onboarding=False,
            )
        lowered = body.casefold()
        urls = tuple(dict.fromkeys(_URL.findall(body)))[:10]
        questions = _questions(body)

        def has(*needles: str) -> bool:
            return any(needle in lowered for needle in needles)

        # Order matters: strongest signals first.
        if sanitized_thread.credential_refs or has(
            "[redacted_secret", "api key:", "client secret", "here is your key", "your token"
        ):
            classification: ReplyClass = "credentials_received"
            action = "Store the received credential references and validate."
            start_browser = False
        elif has("out of office", "auto-reply", "automatic reply", "do not reply", "no-reply"):
            classification = "automated_response"
            action = "Ignore the automated response and keep waiting."
            start_browser = False
        elif has(
            "reject",
            "denied",
            "declined",
            "not able to",
            "cannot provide",
            "not eligible",
            "not interested",
            "no thanks",
            "nope",
            "we cannot",
            "won't be able",
        ):
            classification = "rejected"
            action = "Access was declined; mark the run blocked."
            start_browser = False
        elif (
            has("approved", "granted", "you can now", "proceed to", "create your app", "go ahead")
            and urls
        ):
            classification = "approved_setup_required"
            action = "Follow the official setup link via the browser flow."
            start_browser = True
        elif has("meeting", "schedule a call", "book a call", "calendar", "hop on a call"):
            classification = "meeting_requested"
            action = "Offer availability from the configured company profile."
            start_browser = False
        elif questions or has(
            "could you",
            "please provide",
            "please share",
            "clarify",
            "more information",
            "let us know",
            "what is",
            "which",
            "how many",
        ):
            classification = "more_information_required"
            action = "Answer the provider's questions using configured company facts."
            start_browser = False
        else:
            classification = "unclear"
            action = "Reply could not be classified; retry once then request manual review."
            start_browser = False

        return ReplyClassification(
            classification=classification,
            explicit_questions=questions,
            official_setup_urls=urls,
            stated_reason=body[:500] if classification == "rejected" else None,
            required_next_action=action,
            start_browser_onboarding=start_browser,
        )


__all__ = ["ReplyClass", "ReplyClassification", "ReplyClassifier"]
