"""The browser seam: ``LoopSession`` over in-process Playwright.

This is the layer the onboarding action loop was written against and that no
deployment had. The loop owns every decision — which candidates exist, which one
the model may pick, what counts as progress, when a budget is spent — and this
module owns nothing but the two verbs that touch a page:

* :meth:`PlaywrightLoopSession.observe` — one bounded, secret-free page reading.
* :meth:`PlaywrightLoopSession.act` — execute exactly one policy-generated
  candidate.

Three properties are deliberate, because each one is a way this could have gone
wrong:

**The loop keeps its projection.** ``observe`` returns RAW per-element mappings,
never ``SnapshotElement``s, so ``build_snapshot`` — the thing that strips
secret-ish values — always runs inside the loop and a session cannot skip it.

**A human gate wins over any status this module could infer.**
``detect_human_gate`` is consulted first and its verdict is returned unchanged. A
captcha, an OTP field, a billing prompt or a passkey challenge therefore reaches
the loop as ``human_action_required`` with a typed ``human_action_type``, which is
what makes the loop hand it to a person instead of clicking through it.

**Authentication is never inferred from absence.** ``ops.playwright.worker`` states
the rule for the deterministic login path — "authentication is proven by the
reviewed checkpoint predicate, never by the absence of login fields" — and it
holds here too. A page is only reported as a credential or console surface when its
URL matches a surface the run's committed plan or profile already named.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, cast
from urllib.parse import urlsplit

from pydantic import SecretStr

from ops.browser.candidates import ActionCandidate
from ops.browser.decider import SnapshotElement
from ops.browser.host_policy import BrowserAllowedHosts, evaluate_navigation
from ops.browser.worker import BrowserObservation, BrowserSessionContext
from ops.onboarding.action_loop import LoopObservation
from ops.playwright.actions import ActionExecutionResult
from ops.playwright.gates import detect_human_gate
from ops.playwright.page_inspection import PageInspection


class PageWorker(Protocol):
    """The worker verbs this seam needs, and nothing else.

    Narrow on purpose: there is no start, stop or storage-state verb here, so a
    ``LoopSession`` cannot end a session or export state. Satisfied structurally by
    ``PlaywrightBrowserWorker``.

    ``read_pattern_matched_values_for`` is the one verb that returns secret material,
    and it is NOT a vault verb: it reads the page and returns candidates, it cannot
    persist anything. The write still goes through
    ``ops.credentials.capture_boundary``, which re-applies the checked-in pattern.
    """

    async def inspect_page_for(self, context: BrowserSessionContext) -> PageInspection:
        """One bounded, secret-free inspection of the session's current page."""

    async def execute_candidate_for(
        self,
        context: BrowserSessionContext,
        candidate: ActionCandidate,
        inspection: PageInspection,
    ) -> ActionExecutionResult:
        """Execute exactly one candidate against the live page."""

    async def fill_secret_for(
        self,
        context: BrowserSessionContext,
        *,
        element_index: int,
        inspection: PageInspection,
        resolve: Callable[[], str],
    ) -> None:
        """Fill one resolved element from a value produced once by ``resolve``."""

    async def click_element_for(
        self,
        context: BrowserSessionContext,
        *,
        element_index: int,
        inspection: PageInspection,
    ) -> None:
        """Click one element the caller resolved from a bounded inspection."""

    async def navigate_resolved_for(
        self,
        context: BrowserSessionContext,
        *,
        resolve: Callable[[], str],
    ) -> None:
        """Navigate to one URL produced once by ``resolve``. Caller checks policy."""

    async def read_pattern_matched_values_for(
        self,
        context: BrowserSessionContext,
        *,
        element_indexes: Sequence[int],
        inspection: PageInspection,
        value_pattern: str,
    ) -> tuple[str, ...]:
        """Read the nominated elements, returning only whole-string pattern matches."""


class GrantedSecretConsumer(Protocol):
    """Redeems one grant for one reference. THE transport boundary for a secret.

    Where the plaintext materialises is a property of the TRANSPORT, not of this
    port. On the production RPC path the implementation is the browser container's
    broker client, so the value appears inside that container and this process only
    ever holds ``(reference, kind, grant)`` — which is exactly what
    ``SignupSecretFill`` documents as safe to hold and log by id. On the local
    in-process path (``PLAYWRIGHT_IN_PROCESS_SANDBOX=true``) there is no second
    process by definition, so the value necessarily appears here.

    IN-PROCESS EXCEPTION — read before copying this pattern. The callers below
    confine the returned value to a SINGLE expression handed straight to Playwright:
    never bound to a name, stored, logged, or returned. That confinement is the whole
    mitigation locally, and it mirrors the approved-value fill the reviewed candidate
    path already performs in ``ops/playwright/worker.py``
    (``locator.fill(_approved_or_raise(), ...)``). It is NOT the enforcing mechanism
    and must not be treated as sufficient on the RPC path, where the process
    boundary enforces the guarantee. Do not lift this into ``browser_service/``.
    """

    def consume(self, *, reference: str, kind: str, grant: str) -> str:
        """Redeem exactly one grant for one reference.

        ONE GRANT, ONE USE: the vault deletes the transient row on success, so a
        second call with the same grant must fail. A failed fill is retried with a
        FRESH reservation, never by re-presenting a spent grant — that is also what
        keeps the effect ledger's accounting honest.
        """


# A credential surface is only reported when the page also renders something that
# looks credential-bearing, so a bare URL match cannot satisfy ``credential_visible``.
_MAX_CREDENTIAL_LABELS = 12

# Stand-in title for a page that has none yet (a fresh ``about:blank`` before the
# first navigation). A fixed label, so it can carry no page content.
_UNTITLED_PAGE = "Untitled page"

# Element types a one-time code may be typed into. A provider renders an OTP field
# as a plain text or number input far more often than as a password field, and
# ``tel`` is common on mobile-first forms.
_OTP_FIELD_TYPES: tuple[str, ...] = ("text", "tel", "number", "password")


def _first_fillable_index(inspection: PageInspection, *, kinds: Sequence[str]) -> int | None:
    """The index of the first visible, enabled element of one of ``kinds``.

    Chosen from the bounded inspection in the caller's stated preference order, so a
    secret fill never needs a selector string and never guesses at a hidden control.
    ``None`` means the field is not on this page, which the caller reports as a
    retryable staleness rather than as a policy refusal.
    """

    for kind in kinds:
        for element in inspection.elements:
            if element.element_type == kind and element.visible and element.enabled:
                return element.index
    return None


def raw_element(element: SnapshotElement) -> dict[str, object]:
    """Project one ``SnapshotElement`` back into the raw shape ``build_snapshot`` reads.

    The inspection layer already produced a bounded, secret-free snapshot; the loop
    wants the raw form so that IT performs the projection. Every field
    ``build_snapshot`` consults is carried across, which is what keeps the
    round-trip lossless — a dropped ``visible``/``enabled`` would silently turn an
    un-actionable element into an actionable one.
    """

    return {
        "role": element.role,
        "name": element.name,
        "type": element.element_type,
        "value_present": element.has_value,
        "visible": element.visible,
        "enabled": element.enabled,
        "checked": element.checked,
        "selected": element.selected,
        "expanded": element.expanded,
        "frame_path": list(element.frame_path),
        "href_path": element.href_path,
        "test_id": element.test_id,
        "nearby_heading": element.nearby_heading,
        "selected_label": element.selected_label,
    }


def _surface_key(url: str) -> tuple[str, str]:
    """``(host, path)`` folded the way a planned surface is, for comparison only."""

    parsed = urlsplit(url)
    path = parsed.path or "/"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return (parsed.hostname or "").casefold(), path.casefold()


def _credential_labels(inspection: PageInspection) -> tuple[str, ...]:
    """The accessible names of credential-bearing controls on this page.

    Names only — ``SnapshotElement`` carries no values, and ``secretish`` is the
    inspection layer's own classification, so nothing here reads a secret to decide
    that a secret is present.
    """

    labels = [element.name for element in inspection.elements if element.secretish and element.name]
    return tuple(dict.fromkeys(labels))[:_MAX_CREDENTIAL_LABELS]


@dataclass(frozen=True, slots=True)
class SurfaceExpectations:
    """The reviewed surfaces this run may recognise, and nothing inferred.

    Both come from facts the run already committed to: ``credential_surface`` is the
    plan's own credential surface (the same one route adherence compares against),
    and ``console_urls`` are the committed profile's developer-portal URLs. With
    neither supplied, ``observe`` reports ``navigating`` and the loop advances only
    on a gate, a developer-application id, or its own budget — it never concludes
    "authenticated" on its own.
    """

    credential_surface: tuple[str, str] | None = None
    console_urls: tuple[tuple[str, str], ...] = ()

    @classmethod
    def build(
        cls,
        *,
        credential_url: str | None = None,
        console_urls: Sequence[str] = (),
    ) -> SurfaceExpectations:
        return cls(
            credential_surface=_surface_key(credential_url) if credential_url else None,
            console_urls=tuple(dict.fromkeys(_surface_key(url) for url in console_urls if url)),
        )


class BrowserActionFailed(RuntimeError):
    """One candidate did not execute. Retryable: the loop re-observes and replans.

    Raised for ``stale`` (the DOM moved between planning and acting), ``failed`` (a
    typed action error) and ``blocked`` (the executor's own navigation check refused
    it). The loop's transient-error handler counts these against the no-progress
    budget and applies backoff, so a page that keeps refusing ends as
    ``loop_no_progress_budget_exhausted`` rather than as an unhandled exception.
    """

    def __init__(self, status: str, reason_code: str | None) -> None:
        self.status = status
        self.reason_code = reason_code
        super().__init__(f"browser action {status}: {reason_code or 'unspecified'}")


class PlaywrightLoopSession:
    """``LoopSession`` bound to one in-process Playwright session."""

    def __init__(
        self,
        worker: PageWorker,
        context: BrowserSessionContext,
        *,
        expectations: SurfaceExpectations | None = None,
        secrets: GrantedSecretConsumer | None = None,
        allowed_hosts: BrowserAllowedHosts | None = None,
    ) -> None:
        self._worker = worker
        self._context = context
        self._expectations = expectations or SurfaceExpectations()
        # Both optional and both fail CLOSED when absent: a deployment that has not
        # wired the grant path cannot fill a secret, and one with no allow-list
        # cannot open a verification link. Neither degrades to a weaker check.
        self._secrets = secrets
        self._allowed_hosts = allowed_hosts
        # ``act`` receives only a candidate, but the executor needs the inspection
        # the candidate was generated against so it can re-confirm the URL and DOM
        # generation before touching anything. The loop always observes before it
        # acts, so caching the last inspection here is what preserves that
        # time-of-check-to-time-of-use protection rather than weakening it.
        self._last_inspection: PageInspection | None = None

    @property
    def session_id(self) -> str:
        """The bound session id, which this class can read and never change."""

        return self._context.session_id

    async def observe(self) -> LoopObservation:
        """One page reading, projected into the loop's own observation shape."""

        inspection = await self._worker.inspect_page_for(self._context)
        self._last_inspection = inspection
        return LoopObservation(
            observation=self._observation(inspection),
            raw_elements=tuple(raw_element(element) for element in inspection.elements),
        )

    async def click_index(self, *, element_index: int, inspection: PageInspection) -> None:
        """Click one element the caller already resolved from a bounded inspection.

        For a phase handler that owns its own submission ordering rather than going
        through the action loop — signup is the case: its single-submit guarantee
        comes from the effect ledger, so the click must happen inside the handler's
        reserved operation rather than as a model-chosen candidate.

        The element is addressed by index from an inspection the caller holds, so no
        selector string crosses, and the executor's own staleness re-validation still
        applies underneath.
        """

        await self._worker.click_element_for(
            self._context, element_index=element_index, inspection=inspection
        )
        # The page has moved; a later act() must re-observe rather than reuse this.
        self._last_inspection = None

    async def inspect(self) -> PageInspection:
        """One bounded, secret-free inspection, without the loop's projection.

        ``observe`` is the loop's verb and returns a ``LoopObservation``; this
        returns the inspection itself, which is what a phase handler needs when it
        must evaluate a reviewed postcondition predicate against the page rather
        than classify it into a loop status. Same DLP and bounding rules — this is
        the same call ``observe`` makes, without the projection step.
        """

        inspection = await self._worker.inspect_page_for(self._context)
        self._last_inspection = inspection
        return inspection

    async def act(self, candidate: ActionCandidate) -> None:
        """Execute one candidate, or raise so the loop retries and replans."""

        inspection = self._last_inspection
        if inspection is None:
            # Acting without a current inspection would mean executing against a
            # page nobody looked at, and would defeat the executor's staleness
            # check. Retryable: the loop observes at the top of every iteration.
            raise BrowserActionFailed("stale", "no_current_inspection")
        result = await self._worker.execute_candidate_for(self._context, candidate, inspection)
        if result.status != "executed":
            raise BrowserActionFailed(result.status, result.reason_code)
        # The page has moved; the cached inspection describes the page before the
        # action. Dropping it here means a second act() cannot reuse a stale one.
        self._last_inspection = None

    async def fill_from_grant(
        self, *, kinds: Sequence[str], reference: str, kind: str, grant: str
    ) -> None:
        """Fill one field by redeeming one grant. Value-free in and value-free out.

        ``kinds`` is the ordered set of element types this field may target
        (``("password",)`` for a password, ``("email", "text")`` for an address), so
        the target is chosen from the bounded inspection rather than from a selector
        string. The first visible, enabled match wins; nothing is guessed.

        ONE GRANT, ONE USE — see :class:`GrantedSecretConsumer`. A failed fill needs
        a fresh reservation; re-presenting this grant would fail the vault's
        single-consume check and desynchronise the effect ledger.
        """

        consumer = self._secrets
        if consumer is None:
            raise BrowserActionFailed("blocked", "secret_consumer_unavailable")
        inspection = self._last_inspection or await self._worker.inspect_page_for(self._context)
        self._last_inspection = inspection
        index = _first_fillable_index(inspection, kinds=kinds)
        if index is None:
            raise BrowserActionFailed("stale", "target_not_found")
        # The value is produced inside the worker call and consumed by one
        # expression there; nothing here ever holds it.
        await self._worker.fill_secret_for(
            self._context,
            element_index=index,
            inspection=inspection,
            resolve=lambda: consumer.consume(reference=reference, kind=kind, grant=grant),
        )
        # The page has moved; a later act() must re-observe rather than reuse this.
        self._last_inspection = None

    async def inject_one_time_code(self, *, reference: str, kind: str, grant: str) -> None:
        """``VerificationSession.inject_one_time_code``: one code, one grant.

        POST: the code is resolved through the grant path only, and no value crosses
        this call in either direction.
        """

        await self.fill_from_grant(
            kinds=_OTP_FIELD_TYPES, reference=reference, kind=kind, grant=grant
        )

    async def navigate_verification_link(self, link: SecretStr) -> None:
        """Open one resolved verification link on THIS session.

        The allow-list check is performed HERE, explicitly. ``VerificationBinding``
        states that the caller checks the host (via ``is_safe_verification_link``),
        and this is that check at the point of use: a magic link is NOT a
        model-chosen candidate, so it never passes through the action loop's
        per-candidate navigation guard, whose ``NAVIGATION_ACTIONS`` covers
        candidates only. Routing a provider-issued URL through the candidate path
        purely to inherit that guard would misrepresent it as a planned action, so
        the check is stated rather than borrowed.

        POST: the value is used once and never returned, logged, or persisted. The
        session is unchanged — this navigates the bound page, it does not replace it.
        """

        allowed = self._allowed_hosts
        if allowed is None:
            raise BrowserActionFailed("blocked", "verification_allow_list_unavailable")
        if not evaluate_navigation(link.get_secret_value(), allowed).allowed:
            raise BrowserActionFailed("blocked", "browser_host_not_in_app_policy")
        await self._worker.navigate_resolved_for(self._context, resolve=link.get_secret_value)
        self._last_inspection = None

    async def navigate_to(self, url: str) -> None:
        """Open one NON-SECRET, caller-supplied URL on this session.

        For a phase handler that owns its own ordering and therefore never gets a
        ``goto`` candidate from the loop — signup is the case: its single-submit
        guarantee comes from the effect ledger, so the page it submits must be reached
        inside the handler's reserved operation rather than by a model-chosen action.

        The allow-list is checked HERE, explicitly, for the same reason
        ``navigate_verification_link`` states it: this is not a candidate, so it never
        passes the action loop's per-candidate navigation guard. Absent allow-list
        fails closed.

        ``url`` is a committed-profile URL (``profile.signup_url``), never page text,
        so nothing the untrusted page said can steer this.
        """

        allowed = self._allowed_hosts
        if allowed is None:
            raise BrowserActionFailed("blocked", "navigation_allow_list_unavailable")
        if not evaluate_navigation(url, allowed).allowed:
            raise BrowserActionFailed("blocked", "browser_host_not_in_app_policy")
        await self._worker.navigate_resolved_for(self._context, resolve=lambda: url)
        self._last_inspection = None

    async def read_pattern_matched(
        self, *, element_indexes: Sequence[int], inspection: PageInspection, value_pattern: str
    ) -> tuple[str, ...]:
        """Read candidate credential values off the page, filtered by ``value_pattern``.

        THE ONE VERB ON THIS CLASS THAT RETURNS SECRET MATERIAL, and it is here rather
        than on the caller because the bound ``BrowserSessionContext`` is private: every
        other verb reaches the worker through this seam, and the credential read is not
        the place to make an exception by exposing the context.

        Every returned value is a whole-string match for ``value_pattern`` — the read is
        broad in WHICH elements it looks at (the caller nominates indexes from a bounded
        inspection, no selector strings) and strict in what it accepts from each.

        The caller must treat the result as secret and must offer it to
        ``ops.credentials.capture_boundary.capture_validated_credential``, which
        re-applies the same checked-in pattern before anything is written. This filter
        is a convenience to narrow candidates; it is NOT the authorization.
        """

        return await self._worker.read_pattern_matched_values_for(
            self._context,
            element_indexes=element_indexes,
            inspection=inspection,
            value_pattern=value_pattern,
        )

    def _observation(self, inspection: PageInspection) -> BrowserObservation:
        return classify_inspection(inspection, expectations=self._expectations)


class SessionStarter(Protocol):
    """The one verb the factory needs to obtain a browser session for a run."""

    async def start(
        self,
        profile_id: str | None,
        *,
        recipe: object | None = ...,
        app_slug: str = ...,
        account_ref: str | None = ...,
        use_storage_state: bool = ...,
    ) -> BrowserSessionContext:
        """Open one browser session bound to this run."""


class PlaywrightLoopSessions:
    """``LoopSessionFactory``: one browser session per run, reused across phases.

    Reuse is a requirement, not an optimisation. Email verification must continue on
    the session that submitted signup (``ops.onboarding.driver`` states it as
    "continue on the same ``Browser_Session_ID`` and submit the login form 0
    additional times"), so a factory that opened a fresh session per phase would log
    the run out between signup and verification and break the flow it was meant to
    drive.

    The lease is accepted and deliberately unused for binding: this deployment runs
    onboarding workers on one host, so the session registry is process-local and the
    driver's lease already serialises phases for a run. A multi-host deployment would
    reattach here under the lease's ownership proof.
    """

    def __init__(
        self,
        worker: PageWorker,
        *,
        app_slug: str = "",
        expectations: SurfaceExpectations | None = None,
        account_ref: str | None = None,
        starter: SessionStarter | None = None,
        secrets: GrantedSecretConsumer | None = None,
        allowed_hosts: BrowserAllowedHosts | None = None,
    ) -> None:
        self._worker = worker
        self._app_slug = app_slug
        self._expectations = expectations or SurfaceExpectations()
        self._account_ref = account_ref
        # Handed to every session this factory opens, so the run's signup fill and
        # its later verification injection go through the same grant path and the
        # same allow-list. Absent means those verbs fail closed.
        self._secrets = secrets
        self._allowed_hosts = allowed_hosts
        # The worker satisfies both protocols; ``starter`` exists so a caller can
        # supply a session that is already open rather than starting a new one.
        self._starter = starter
        self._sessions: dict[str, PlaywrightLoopSession] = {}

    async def session_for(self, *, run_id: str, phase: str, lease: object) -> PlaywrightLoopSession:
        """The run's bound session, opening one on first use."""

        del phase, lease
        existing = self._sessions.get(run_id)
        if existing is not None:
            return existing
        starter = self._starter
        if starter is None:
            # Structural: the worker has ``start``; the narrow PageWorker protocol
            # deliberately does not name it, so it is resolved here rather than
            # widening what a LoopSession can reach.
            starter = cast("SessionStarter", self._worker)
        context = await starter.start(
            run_id,
            app_slug=self._app_slug,
            account_ref=self._account_ref,
            use_storage_state=False,
        )
        session = PlaywrightLoopSession(
            self._worker,
            context,
            expectations=self._expectations,
            secrets=self._secrets,
            allowed_hosts=self._allowed_hosts,
        )
        self._sessions[run_id] = session
        return session


def expectations_for(
    profile: object | None,
    *,
    credential_url: str | None = None,
) -> SurfaceExpectations:
    """Build the reviewed surface expectations from a committed profile.

    Only URLs the profile already corroborated are used, so this cannot widen what
    the run may recognise as a console or credential page.
    """

    console: list[str] = []
    for attribute in ("developer_portal_url", "developer_docs_url"):
        value = getattr(profile, attribute, None)
        if isinstance(value, str) and value:
            console.append(value)
    return SurfaceExpectations.build(credential_url=credential_url, console_urls=console)


def _observed_title(inspection: PageInspection) -> str:
    """The page title an observation carries, never empty.

    A page that has not navigated yet has no title, and ``about:blank`` is an
    ADMITTED observation URL — ``sanitize_browser_url`` returns it unchanged in the
    same ``BrowserObservation.__post_init__`` that requires a non-empty title. The
    loop's FIRST ``observe`` runs before any navigation, so without a fallback that
    tick raises ``browser page title is invalid`` instead of reporting
    ``navigating``, and no run can ever reach its first action.

    Same convention as ``ops/playwright/worker.py`` (``"Reviewed public entry"``,
    ``"Credential page"``) and ``ops/playwright/gates.py``
    (``"Human action required"``): substitute a fixed, value-free label rather than
    relaxing the invariant. The label is a constant, so it carries no page content.
    """

    return inspection.title or _UNTITLED_PAGE


def classify_inspection(
    inspection: PageInspection,
    *,
    expectations: SurfaceExpectations | None = None,
) -> BrowserObservation:
    """Classify one inspection, preferring a human gate over any other reading.

    A module-level function rather than a method because BOTH transports must
    classify a page identically: the in-process session calls it directly, and the
    browser service's ``observe`` endpoint calls it while holding an inspection but
    no session object. One implementation means the two cannot drift about whether a
    page is a captcha.
    """

    gate = detect_human_gate(inspection)
    if gate is not None:
        # A structural human gate is the whole answer. Returned unchanged so the
        # typed ``human_action_type`` reaches the loop, which routes captcha, phone
        # OTP, passkey and billing to a person by policy.
        return gate

    surfaces = expectations or SurfaceExpectations()
    labels = _credential_labels(inspection)
    here = _surface_key(inspection.url)
    if surfaces.credential_surface is not None and here == surfaces.credential_surface and labels:
        # The reviewed credential surface. Labels are required as well, so a
        # redirect that merely lands on the right path cannot claim a credential is
        # on screen.
        return BrowserObservation(
            status="credential_page_ready",
            current_url=inspection.url,
            page_title=_observed_title(inspection),
            credential_field_labels=labels,
        )
    if here in surfaces.console_urls:
        return BrowserObservation(
            status="developer_console_ready",
            current_url=inspection.url,
            page_title=_observed_title(inspection),
            credential_field_labels=labels,
        )
    # Nothing reviewed matched. "Still moving" is the honest reading: the loop proves
    # progress from its goal's postconditions, not from this module's optimism.
    return BrowserObservation(
        status="navigating",
        current_url=inspection.url,
        page_title=_observed_title(inspection),
        credential_field_labels=labels,
    )


def loop_observation_from(
    inspection: PageInspection,
    *,
    expectations: SurfaceExpectations | None = None,
) -> LoopObservation:
    """A gate-aware loop observation for a caller that already holds an inspection."""

    return LoopObservation(
        observation=classify_inspection(inspection, expectations=expectations),
        raw_elements=tuple(raw_element(element) for element in inspection.elements),
    )


def observation_payload(observation: BrowserObservation) -> dict[str, object]:
    """The wire form of an observation: closed fields, no page text beyond a title."""

    return {
        "status": observation.status,
        "current_url": observation.current_url,
        "page_title": observation.page_title,
        "developer_app_id": observation.developer_app_id,
        "human_action_type": observation.human_action_type,
        "human_instruction": observation.human_instruction,
        "credential_field_labels": list(observation.credential_field_labels),
        "reason_code": observation.reason_code,
    }


def observation_from_payload(payload: Mapping[str, object]) -> BrowserObservation:
    """Rebuild an observation from its wire form, dropping anything undeclared."""

    def _text(key: str) -> str:
        value = payload.get(key)
        return value if isinstance(value, str) else ""

    def _optional(key: str) -> str | None:
        value = payload.get(key)
        return value if isinstance(value, str) and value else None

    labels = payload.get("credential_field_labels")
    return BrowserObservation(
        status=_text("status") or "navigating",  # type: ignore[arg-type]
        current_url=_text("current_url"),
        page_title=_text("page_title"),
        developer_app_id=_optional("developer_app_id"),
        human_action_type=_optional("human_action_type"),  # type: ignore[arg-type]
        human_instruction=_optional("human_instruction"),
        credential_field_labels=(
            tuple(str(item) for item in labels if isinstance(item, str))
            if isinstance(labels, (list, tuple))
            else ()
        ),
        reason_code=_optional("reason_code"),
    )


__all__ = [
    "BrowserActionFailed",
    "PageWorker",
    "PlaywrightLoopSession",
    "PlaywrightLoopSessions",
    "SessionStarter",
    "SurfaceExpectations",
    "classify_inspection",
    "expectations_for",
    "loop_observation_from",
    "observation_from_payload",
    "observation_payload",
    "raw_element",
]
