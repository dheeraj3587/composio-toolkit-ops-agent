"""The run's approved non-secret values, and which of them each phase may type.

Two facts live here because exactly two components need both of them and neither
should own the other's copy.

**The values.** ``ops.browser.setup_values.browser_setup_values`` builds the run's
immutable, non-secret value map out of the accepted request. The canonical runtime
already did this for the recipe path (``ops/workflow/canonical_runtime.py``); the
onboarding driver's path had no equivalent, so its browser sessions were started
with no ``setup_fields`` at all and every phase goal carried
``allow_value_refs=()``.

**The consequence of that, stated plainly.** ``ops/browser/candidates.py`` iterates
``allow_value_refs`` to build ``fill`` and ``select_option`` candidates. An empty
sequence means zero of both, so the driver's entire live action alphabet was
``click | press(Enter) | goto`` — the agent could not put a single character into a
form on any app. Wiring these two functions is what gives it hands.

**Why the reference set is per phase and not "everything approved".** The
allow-list is a ceiling, not a menu, and the same rule ``_reviewed_urls`` keeps for
navigation applies to typing: a login page has no business being offered the
credential's name, and the credential surface has no business being offered the
company's use case. Narrowing per phase also keeps the cross product in
``generate_candidates`` small enough that ``goto`` and ``press`` candidates still
fit inside the same bounded set.

**Secrets are not here and cannot be.** Every reference below is one of the
non-secret keys ``browser_setup_values`` validates, and the DLP check inside it
refuses anything that looks like secret material. Email addresses, passwords and
one-time codes reach a page through the three-hop secret broker, never through a
model-selected ``fill``.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence

from ops.browser.setup_values import browser_setup_values
from ops.onboarding.phase import OnboardingPhase

LOGGER = logging.getLogger(__name__)

# Phase -> the approved references that phase may type, in preference order.
#
# Order is load-bearing: ``generate_candidates`` walks references innermost and
# stops at its per-kind bound, so the first entry is the one a page with a single
# text input is most likely to be offered. Each list is the answer to "what is
# this phase's declared purpose asking a human to type?" and nothing wider.
#
# The four phases mapped to an empty tuple are empty on purpose rather than by
# omission:
#   ``route_selected_login`` — the identity is a vaulted pair injected by the
#       broker; a model-selected fill here would be the agent typing over a
#       credential it is not allowed to see.
#   ``email_verification``  — the only value that phase supplies is the one-time
#       code, which is likewise broker-injected.
#   ``authenticated``       — a pure navigation phase; its postcondition is
#       reaching the developer console, and nothing on the way is a form.
# A phase absent from this mapping types nothing, which is the safe default for
# any phase added later without a reviewed answer to the question above.
PHASE_VALUE_REFS: Mapping[OnboardingPhase, tuple[str, ...]] = {
    "signup": (
        "company_name",
        "company_website",
        "organization_name",
        "account_name",
        "team_name",
        "use_case",
    ),
    "route_selected_login": (),
    "email_verification": (),
    "authenticated": (),
    "developer_app": (
        "application_name",
        "callback_url",
        "company_website",
    ),
    "credential_generation": (
        "credential_name",
        "permission_profile",
        "expiration",
        "region",
    ),
}


def run_setup_values(record: Mapping[str, object] | None, *, app_slug: str) -> dict[str, str]:
    """The run's approved non-secret value map, read from its own accepted request.

    PRE:  ``record`` is a ledger run row (or ``None``); ``app_slug`` is the run's
          app, used only to derive the two default names.
    POST: every key is one of ``APPROVED_BROWSER_VALUE_REFS`` and every value has
          passed the same validation, length bound and DLP check the API applied
          when the request was accepted — this re-derives from the stored request
          rather than trusting a projection of it.

    A row with no readable request yields ``{}`` rather than raising. The caller is
    either seeding a browser session or building a phase goal, and both degrade
    correctly to "this run types nothing", which is exactly where the driver stood
    before this module existed. Failing the run instead would turn one unparseable
    historical row into a dead phase.
    """

    if not record:
        return {}
    payload = record.get("request")
    if not isinstance(payload, Mapping):
        return {}
    # Imported here, not at module scope: ``ops.core.models`` imports
    # ``ops.browser.setup_values`` at import time, and this module is pulled into
    # the composition root. Keeping the request model local to the one function
    # that parses it leaves the import graph acyclic without a TYPE_CHECKING dance.
    from ops.core.models import OperationsRequest

    try:
        request = OperationsRequest.model_validate(dict(payload))
    except Exception:
        LOGGER.warning(
            "run %s has no parseable request to derive setup values from", record.get("run_id")
        )
        return {}
    company = request.company
    try:
        return browser_setup_values(
            request.provider_setup,
            company_name=company.legal_name,
            company_website=company.website,
            use_case=company.use_case,
            expected_volume=company.expected_volume,
            callback_urls=company.callback_urls,
            app_slug=app_slug or request.app_name,
        )
    except ValueError:
        # An accepted request whose values no longer validate is a policy change
        # since acceptance, not a run outcome. Typed nothing beats typing a value
        # the current rules refuse.
        LOGGER.warning("run %s setup values are no longer approvable", record.get("run_id"))
        return {}


def phase_value_refs(
    phase: OnboardingPhase, values: Mapping[str, str] | Sequence[str] | None
) -> tuple[str, ...]:
    """The references ``phase`` may fill, narrowed to the ones this run has a value for.

    The intersection is the point. A reference the run carries no value for would
    become a candidate the browser service refuses at execution time
    (``_approved_or_raise``), spending an iteration and a model call to learn that
    the value was never seeded — and on a loop with a bounded no-progress counter,
    a few of those are the difference between reaching the credential and pausing
    for a human.
    """

    declared = PHASE_VALUE_REFS.get(phase, ())
    if not declared or not values:
        return ()
    available = set(values)
    return tuple(ref for ref in declared if ref in available)


__all__ = ["PHASE_VALUE_REFS", "phase_value_refs", "run_setup_values"]
