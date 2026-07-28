"""Explicit, deterministic outreach boundary for reviewed gated app recipes.

Constructing :class:`GatedRoute` performs validation and builds an in-memory
plain-text message, but it has no side effects.  A caller must separately invoke
``send_outreach`` with its already-persisted effect identity.  The Gmail worker
remains the sole authority for recipient overrides and the live-vendor-email gate.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Literal

from ops.app_recipes import AppRecipe, OutreachSpec
from ops.gmail_worker import GmailWorker
from ops.models import OperationsRequest
from ops.redaction import redact_text

_MAX_EFFECT_IDENTITY_LENGTH = 500
_MAX_IDENTIFIER_LENGTH = 1_000


class GatedRoutePolicyError(ValueError):
    """A gated recipe or caller-supplied effect identity is not safe to execute."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"gated outreach is unavailable: {reason_code}")


@dataclass(frozen=True, slots=True)
class GatedOutreachTarget:
    """Reviewed, non-secret routing metadata exposed before an explicit send."""

    app_slug: str
    intended_recipient: str
    template_id: str
    sending_policy: Literal["controlled_sink_only"] = "controlled_sink_only"


@dataclass(frozen=True, slots=True)
class GatedOutreachReceipt:
    """Identifier-only projection of a completed Gmail outreach side effect."""

    session_id: str
    thread_id: str
    message_id: str
    intended_recipient: str
    actual_recipient: str


class GatedRoute:
    """Prepare one reviewed gated outreach and send it only on explicit request."""

    __slots__ = ("_body", "_gmail", "_recipient", "_subject", "_target")

    def __init__(
        self,
        *,
        recipe: AppRecipe,
        request: OperationsRequest,
        gmail: GmailWorker,
    ) -> None:
        outreach = _verified_outreach(recipe, request)
        recipient = _validate_email(outreach.contact_email or "")
        subject, body = _deterministic_message(recipe, request, outreach.approval_reason)

        self._gmail = gmail
        self._recipient = recipient
        self._subject = subject
        self._body = body
        self._target = GatedOutreachTarget(
            app_slug=recipe.app_slug,
            intended_recipient=recipient,
            template_id=_validate_public_identifier(outreach.template_id, "template_id"),
        )

    @property
    def target(self) -> GatedOutreachTarget:
        """Return reviewed routing metadata without exposing message content."""

        return self._target

    async def send_outreach(self, *, effect_identity: str) -> GatedOutreachReceipt:
        """Perform the single explicit side effect using the caller's identity verbatim.

        No recipient override is accepted here.  The reviewed recipe contact is
        always passed as the intended recipient, leaving ``GmailWorker`` to apply
        its configured controlled recipient or reject the call through its
        ``ALLOW_LIVE_VENDOR_EMAIL`` policy.
        """

        safe_effect_identity = _validate_effect_identity(effect_identity)
        sent = await self._gmail.send_outreach(
            self._recipient,
            self._subject,
            self._body,
            safe_effect_identity,
        )
        receipt = GatedOutreachReceipt(
            session_id=_validate_identifier(sent.session_id, "session_id"),
            thread_id=_validate_identifier(sent.thread_id, "thread_id"),
            message_id=_validate_identifier(sent.message_id, "message_id"),
            intended_recipient=_validate_email(sent.intended_recipient),
            actual_recipient=_validate_email(sent.actual_recipient),
        )
        if receipt.intended_recipient != self._recipient:
            raise GatedRoutePolicyError("gmail_receipt_recipient_mismatch")
        return receipt


def _verified_outreach(recipe: AppRecipe, request: OperationsRequest) -> OutreachSpec:
    if recipe.route_kind != "gated":
        raise GatedRoutePolicyError("route_kind_not_gated")
    if _lookup_key(request.app_name) not in {
        _lookup_key(recipe.app_name),
        _lookup_key(recipe.app_slug),
    }:
        raise GatedRoutePolicyError("request_recipe_mismatch")
    if recipe.readiness_tier != "outreach_ready":
        raise GatedRoutePolicyError("outreach_contact_not_verified")
    if not recipe.evidence_verified_at or not recipe.evidence_urls:
        raise GatedRoutePolicyError("outreach_evidence_missing")

    outreach = recipe.outreach
    if outreach is None or outreach.contact_email is None:
        raise GatedRoutePolicyError("verified_contact_email_missing")
    if outreach.sending_policy != "controlled_sink_only":
        raise GatedRoutePolicyError("sending_policy_not_controlled_sink_only")
    return outreach


def _deterministic_message(
    recipe: AppRecipe,
    request: OperationsRequest,
    approval_reason: str,
) -> tuple[str, str]:
    app_name = _public_line(recipe.app_name)
    app_slug = _public_line(recipe.app_slug)
    company_name = _public_line(request.company.legal_name)
    company_website = _public_line(request.company.website)
    use_case = _public_line(request.company.use_case)
    access_context = _public_line(approval_reason)

    subject = f"API access request for {app_name} [{app_slug}]"
    body = (
        "Hello,\n\n"
        f"{company_name} ({company_website}) is requesting reviewed developer and "
        f"production API access for {app_name}.\n\n"
        f"Use case: {use_case}\n\n"
        f"Access context: {access_context}\n\n"
        "Please confirm:\n"
        "- the application and approval steps, including the expected timeline\n"
        "- the scopes or permissions available for this integration\n"
        "- whether a sandbox or test environment is available\n"
        "- the production credential issuance and rotation process\n\n"
        f"Thank you,\n{company_name}"
    )
    return subject, body


def _lookup_key(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _public_line(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).replace("\x00", " ")
    return " ".join(redact_text(normalized).split())


def _validate_effect_identity(value: str) -> str:
    if (
        not value
        or len(value) > _MAX_EFFECT_IDENTITY_LENGTH
        or any(character in value for character in "\r\n\x00")
    ):
        raise GatedRoutePolicyError("effect_identity_invalid")
    return value


def _validate_identifier(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_IDENTIFIER_LENGTH
        or any(character in value for character in "\r\n\x00")
    ):
        raise GatedRoutePolicyError(f"gmail_{name}_invalid")
    return value


def _validate_public_identifier(value: str, name: str) -> str:
    if (
        not value
        or len(value) > _MAX_IDENTIFIER_LENGTH
        or any(character in value for character in "\r\n\x00")
        or redact_text(value) != value
    ):
        raise GatedRoutePolicyError(f"outreach_{name}_invalid")
    return value


def _validate_email(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 320
        or any(character.isspace() or character == "\x00" for character in value)
        or value.count("@") != 1
    ):
        raise GatedRoutePolicyError("outreach_email_invalid")
    local, domain = value.rsplit("@", 1)
    if not local or "." not in domain or domain.startswith(".") or domain.endswith("."):
        raise GatedRoutePolicyError("outreach_email_invalid")
    return value


__all__ = [
    "GatedOutreachReceipt",
    "GatedOutreachTarget",
    "GatedRoute",
    "GatedRoutePolicyError",
]
