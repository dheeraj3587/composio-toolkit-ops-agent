"""The sanitized shapes the Gmail boundary is allowed to hand back.

Nothing that leaves the Gmail boundary carries raw provider payloads. A thread becomes
sanitized messages plus ``vault://`` references for any secret found in the body, and a
send becomes a receipt of identifiers. That is what lets an outreach thread be stored
in the ledger, shown in a timeline and replayed without ever persisting message
content that might contain a credential.

The receipt pair matters for idempotency: a send is recorded as a small set of
identifiers and can be reconstructed from that record, so a retried outreach resolves
to the existing thread instead of emailing a vendor twice. In a hundred-app batch that
is the difference between one message per vendor and a duplicate storm.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


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
    credential_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class InboxSearchResult:
    """A sanitized, non-vaulted summary of one inbox message for general reads."""

    message_id: str
    thread_id: str
    sender: str
    sanitized_subject: str
    sanitized_preview: str
    sent_at: str
    has_attachments: bool


def _send_result_receipt(result: GmailSendResult) -> dict[str, str]:
    return {
        "session_id": result.session_id,
        "thread_id": result.thread_id,
        "message_id": result.message_id,
        "intended_recipient": result.intended_recipient,
        "actual_recipient": result.actual_recipient,
    }


def _send_result_from_receipt(receipt: Mapping[str, str]) -> GmailSendResult:
    required = {
        "session_id",
        "thread_id",
        "message_id",
        "intended_recipient",
        "actual_recipient",
    }
    if set(receipt) != required:
        raise RuntimeError("stored Gmail effect receipt is invalid")
    return GmailSendResult(**receipt)
