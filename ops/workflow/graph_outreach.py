"""Composing the single controlled outreach message sent to a vendor.

Exactly one message per gated app is the whole design constraint. The body is built from
the company profile and the app's verified research only, so it states real facts about
who is asking and what for; nothing is invented about the integration, and no credential
or vault reference is ever interpolated.

The wording is deliberately specific about what is being requested (documented developer
access and the credential issuance path) because a vague message produces a vague reply,
and every extra round trip costs a real human on the vendor side. Across a hundred gated
apps that restraint is what keeps this from looking like bulk mail.
"""

from __future__ import annotations

from ops.core.models import OperationalResearch, OperationsRequest


def _outreach_message(
    request: OperationsRequest,
    research: OperationalResearch,
) -> tuple[str, str]:
    """Build a deterministic outreach from sanitized company and research fields.

    The message contains only non-secret operational facts: provider/app name,
    company legal name and website, a bounded use-case summary, and explicit
    requests for developer access, scopes, approval steps, sandbox availability,
    and the credentials process. It never contains secrets, tokens, vault
    values, browser URLs, prompts, or checkpoint data.
    """

    try:
        from ops.core.config import Settings
        from ops.email.ai import build_email_assistant

        assistant = build_email_assistant(Settings.from_env())
        if assistant is not None:
            draft = assistant.compose_outreach(
                app_name=research.app_name,
                company=request.company,
                research=research,
            )
            if draft.subject and draft.body:
                return draft.subject, draft.body
    except Exception:
        pass
    short_id = research.app_slug[:40]
    subject = f"API access request for {research.app_name} [{short_id}]"
    scopes = (
        ", ".join(scope.name for scope in research.scopes) or "the documented integration scopes"
    )
    use_case = request.company.use_case[:500]
    body = (
        "Hello,\n\n"
        f"{request.company.legal_name} ({request.company.website}) is requesting developer "
        f"and production API access for {research.app_name}.\n\n"
        f"Use case: {use_case}\n\n"
        "To proceed with the integration, we would appreciate confirmation of:\n"
        f"- the developer/API access request process for {research.app_name}\n"
        f"- the required OAuth scopes or permissions ({scopes})\n"
        "- any approval or review steps and their expected timeline\n"
        "- whether a sandbox or test environment is available\n"
        "- the credential issuance process for production access\n\n"
        f"Thank you,\n{request.company.legal_name}"
    )
    return subject, body
