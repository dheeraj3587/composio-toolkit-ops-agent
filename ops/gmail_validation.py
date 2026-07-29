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

import re
from email import policy
from email.parser import Parser

_EMAIL_LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")
_EMAIL_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)


def _validate_email(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 320
        or any(character.isspace() or character == "\x00" for character in value)
        or value.count("@") != 1
    ):
        raise ValueError("a single safe email address is required")
    local, domain = value.rsplit("@", 1)
    if (
        _EMAIL_LOCAL_RE.fullmatch(local) is None
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or _EMAIL_DOMAIN_RE.fullmatch(domain) is None
    ):
        raise ValueError("a single safe email address is required")
    return f"{local}@{domain.casefold()}"


def parse_mailbox_address(value: str) -> str | None:
    """Return one canonical RFC mailbox address, or ``None``.

    Display names are accepted, but groups, multiple addresses, malformed
    headers and header-injection characters are rejected. Callers compare the
    returned mailbox, never the untrusted display string, so a sender such as
    ``"trusted@example.test" <attacker@example.test>`` cannot pass by substring.
    """

    if (
        not isinstance(value, str)
        or not value
        or len(value) > 998
        or any(character in value for character in "\r\n\x00")
    ):
        return None
    try:
        message = Parser(policy=policy.default).parsestr(f"From: {value}\n\n")
        header = message["From"]
        if header is None or header.defects or len(header.addresses) != 1:
            return None
        # An RFC group is not a single mailbox even when it contains one address.
        if any(group.display_name is not None for group in header.groups):
            return None
        raw_address = header.addresses[0].addr_spec
        if not isinstance(raw_address, str):
            return None
        address = _validate_email(raw_address)
    except (AttributeError, IndexError, TypeError, ValueError):
        return None
    return address


def _validate_identifier(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 1_000
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise ValueError(f"{name} is invalid")
    return value


def _validate_message(subject: str, body: str) -> None:
    if not subject or len(subject) > 998 or "\r" in subject or "\n" in subject:
        raise ValueError("email subject is invalid")
    if not body or len(body) > 100_000 or "\x00" in body:
        raise ValueError("email body is invalid")
