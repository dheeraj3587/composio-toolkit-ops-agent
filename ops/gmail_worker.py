"""Typed Composio Gmail boundary with a locked least-privilege tool allowlist."""

from __future__ import annotations

from dataclasses import dataclass

from ops.graph import PhaseUnavailableError

GMAIL_TOOL_ALLOWLIST: tuple[str, ...] = (
    "GMAIL_SEND_EMAIL",
    "GMAIL_CREATE_EMAIL_DRAFT",
    "GMAIL_SEND_DRAFT",
    "GMAIL_FETCH_EMAILS",
    "GMAIL_FETCH_MESSAGE_BY_THREAD_ID",
    "GMAIL_LIST_THREADS",
    "GMAIL_REPLY_TO_THREAD",
    "GMAIL_GET_PROFILE",
)


@dataclass(frozen=True, slots=True)
class GmailSendResult:
    session_id: str
    thread_id: str
    message_id: str
    intended_recipient: str
    actual_recipient: str


@dataclass(frozen=True, slots=True)
class SanitizedGmailMessage:
    message_id: str
    sender: str
    recipients: tuple[str, ...]
    sent_at: str
    sanitized_subject: str
    sanitized_body: str


@dataclass(frozen=True, slots=True)
class SanitizedGmailThread:
    thread_id: str
    messages: tuple[SanitizedGmailMessage, ...]


class GmailWorker:
    """Future Composio adapter; no SDK object is created in Phase 0/1."""

    async def ensure_connected(self) -> str:
        raise PhaseUnavailableError(phase=4, capability="Composio Gmail connection")

    async def send_outreach(
        self,
        recipient: str,
        subject: str,
        body: str,
        idempotency_key: str,
    ) -> GmailSendResult:
        del recipient, subject, body, idempotency_key
        raise PhaseUnavailableError(phase=4, capability="Composio Gmail outreach")

    async def fetch_thread(self, thread_id: str) -> SanitizedGmailThread:
        del thread_id
        raise PhaseUnavailableError(phase=4, capability="Composio Gmail thread fetch")

    async def reply(self, thread_id: str, body: str, idempotency_key: str) -> GmailSendResult:
        del thread_id, body, idempotency_key
        raise PhaseUnavailableError(phase=4, capability="Composio Gmail thread reply")
