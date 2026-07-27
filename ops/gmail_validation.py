"""Validating what we are about to send, before a real vendor mailbox is touched.

These checks run on OUR side of the boundary. An outreach that would be malformed is
rejected locally rather than handed to the provider, because a rejected send still
consumes an idempotency slot and, worse, a partially-valid one could reach a real vendor
with a broken subject or an unintended recipient.

Identifiers and addresses are matched against strict patterns and returned normalized,
so the same logical recipient always produces the same value and cannot silently create
a second thread for one vendor across a hundred-app batch.
"""

from __future__ import annotations


def _validate_email(value: str) -> str:
    if not value or len(value) > 320 or "\n" in value or "\r" in value or value.count("@") != 1:
        raise ValueError("a single safe email address is required")
    local, domain = value.rsplit("@", 1)
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise ValueError("a single safe email address is required")
    return value


def _validate_identifier(value: str, name: str) -> str:
    if not value or len(value) > 1_000 or any(character in value for character in "\r\n\x00"):
        raise ValueError(f"{name} is invalid")
    return value


def _validate_message(subject: str, body: str) -> None:
    if not subject or len(subject) > 998 or "\r" in subject or "\n" in subject:
        raise ValueError("email subject is invalid")
    if not body or len(body) > 100_000 or "\x00" in body:
        raise ValueError("email body is invalid")
