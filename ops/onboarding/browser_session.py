"""The one onboarding port that had no implementation: the browser itself.

``build_onboarding_ports`` binds every durable store, the model chain, the mailbox
and the vault — and deliberately does *not* bind ``sessions``, because "the
component that owns a bound browser session owns its lifecycle"
(``ops.onboarding.composition``'s module docstring). That was a correct boundary
and it left a real hole: no :class:`~ops.onboarding.driver.LoopSessionFactory`
existed anywhere outside test fakes, which is the literal reason
``api/app.py`` refused ``onboarding: true`` with ``onboarding_driver_not_wired``.
This module is that implementation, over the out-of-process browser service.

**Why the service client and not the in-process worker.** ``ops.playwright.worker``
drives a closed loop inside this process: inspect, call a model, act, repeat. The
action loop needs the opposite shape — look once, think here, do exactly one
thing — and ``BrowserServiceClient.observe_session`` / ``act_on_session`` are the
single-step pair that exists for precisely that. It also puts Chromium in its own
container, so a phase that crashes the API does not take the session with it and
a resumed run reattaches to the same one.

**Confinement is the profile's, and it is confirmed rather than assumed.** The
session is started with the allow-list derived from the run's committed provider
profile, and :meth:`BrowserServiceClient.start` refuses the session outright when
the service does not echo the same pattern set back. So the host policy the loop
re-checks in this process and the one the container enforces are the same list,
attributable to the same profile digest.

**No new human gate.** Everything that can fail here fails the way the loop
already understands: an unreachable service becomes a ``failed`` action outcome,
a refused act becomes ``blocked``, a page that moved becomes ``stale``. The only
exception is :meth:`observe`, which raises — an observation that did not happen is
not an observation, and the loop's own ``Q8`` turns that into a classified phase
outcome rather than a prompt.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Protocol, cast

from ops.browser.candidates import ActionCandidate
from ops.browser.decider import build_snapshot
from ops.browser.host_policy import BrowserAllowedHosts
from ops.browser.worker import BrowserObservation
from ops.onboarding.action_loop import LoopObservation, LoopSession
from ops.onboarding.lease import Lease
from ops.onboarding.phase import OnboardingPhase
from ops.onboarding.setup_refs import run_setup_values
from ops.playwright.actions import ActionExecutionResult, ActionReasonCode
from ops.playwright.gates import detect_human_gate
from ops.playwright.page_inspection import PageInspection
from ops.providers.errors import ProviderOperationError
from ops.providers.profile import ProviderProfile

LOGGER = logging.getLogger("composio_ops.onboarding_browser_session")

# What a page with no title is called. ``BrowserObservation`` refuses an empty
# title outright, and a titleless page is an ordinary thing on a provider console
# mid-navigation — failing the observation over it would end a phase that is
# working.
UNTITLED_PAGE = "(untitled)"

# The observation status a mid-phase reading carries when nothing stronger can be
# proven. It asserts nothing about whether the console is ready or the credential
# is visible.
NAVIGATING: Final = "navigating"

# --- what a single-step reading can honestly prove ---------------------------
# Every ``PHASE_POSTCONDITIONS`` predicate in ``ops.onboarding.action_loop`` reads
# ``status``/``reason_code``/``credential_field_labels``, and this session used to
# return ``NAVIGATING`` with none of them on every iteration. The result was not a
# conservative loop, it was an unsatisfiable one: no phase driven through this
# port could EVER report its postcondition met, so every one of them burned
# ``MAX_NO_PROGRESS`` and returned ``loop_no_progress_budget_exhausted``. That is
# the mechanism behind "the agent does nothing".
#
# So this classifies, using only what the trace loop uses for the same call:
# the reviewed recipe's success predicate (``ops.playwright.predicates``), the
# structural credential-bearing test, and code-authored control-name markers.
# Page PROSE never proves anything here — the needles below are matched against
# accessible names of interactive controls, which the page cannot rename into a
# claim without also rendering that control.

# An authenticated console has a way OUT of the account. A marketing page does
# not. This is the one marker that survives every provider's layout.
_SIGNED_IN_CONTROLS: Final[tuple[str, ...]] = (
    "log out",
    "logout",
    "sign out",
    "signout",
    "log off",
    "account settings",
    "my account",
)

# Post-submit signup acknowledgements. Matched against the page's own visible
# text because a "check your inbox" interstitial has no controls at all — the
# only phase that reads this is ``signup``, whose real proof (the mailbox) is
# checked separately by the verification phase that follows it.
_SIGNUP_ACKNOWLEDGED: Final[tuple[str, ...]] = (
    "verify your email",
    "verify your account",
    "confirm your email",
    "check your inbox",
    "check your email",
    "verification email",
    "confirmation email",
)


def _reviewed_success(inspection: PageInspection, recipe: Mapping[str, object] | None) -> bool:
    """True when the caller-bound recipe's own success predicate holds here.

    The SAME authority ``ops.playwright.worker`` uses at the equivalent point: a
    predicate with no positive condition proves nothing (``predicate_satisfied``
    returns False), so an app with an empty ``success`` block cannot be talked
    into a credential surface by this path. Any failure to rebuild the recipe is
    "not proven", never an exception — a malformed snapshot must not end a phase.
    """

    if recipe is None:
        return False
    try:
        from ops.playwright.predicates import predicate_satisfied
        from ops.recipes.app_recipes import AppRecipe, recipe_to_browser_trace

        trace = recipe_to_browser_trace(AppRecipe.model_validate(dict(recipe)))
    except Exception:  # noqa: BLE001 - an unusable snapshot proves nothing.
        return False
    if trace is None:
        return False
    return trace.success.has_positive_condition() and predicate_satisfied(trace.success, inspection)


def _credential_labels(inspection: PageInspection) -> tuple[str, ...]:
    """The already-sanitized names of the credential-shaped fields on this page.

    Names only. ``ops.playwright.page_inspection`` rewrites a credential-describing
    accessible name into a semantic placeholder at the source and redacts
    token-shaped text, so nothing here can carry a secret value. Bounded to the 20
    ``BrowserObservation`` accepts.
    """

    labels: list[str] = []
    for element in inspection.elements:
        if not element.secretish or not element.name:
            continue
        if element.name not in labels:
            labels.append(element.name)
        if len(labels) == 20:
            break
    return tuple(labels)


def classify_observation(
    inspection: PageInspection, *, recipe: Mapping[str, object] | None
) -> BrowserObservation:
    """One page reading, classified into the statuses the loop's postconditions read.

    Ordered most-authoritative first, and every branch fails closed to
    ``NAVIGATING`` — which is what this function returned unconditionally before,
    so nothing it cannot prove is any weaker than it was.
    """

    gate = detect_human_gate(inspection)
    if gate is not None:
        return gate

    title = inspection.title or UNTITLED_PAGE
    labels = _credential_labels(inspection)
    proven = _reviewed_success(inspection, recipe)
    if proven or labels:
        # Structurally credential-bearing, whether or not a reviewed predicate
        # named it. This does NOT authorize capture: capture goes through
        # ``arm_credential_surface``, which is the service's own proof and refuses
        # without a recipe. It authorizes the LOOP to stop driving a page that is
        # already showing the credential fields.
        return BrowserObservation(
            status="credential_page_ready",
            current_url=inspection.url,
            page_title=title,
            credential_field_labels=labels,
            non_secret_notes=(
                "Verified the reviewed success predicate."
                if proven
                else "Credential-shaped fields are present.",
            ),
        )

    names = tuple(name.casefold() for name in inspection.accessible_names())
    if any(needle in name for needle in _SIGNED_IN_CONTROLS for name in names):
        return BrowserObservation(
            status="developer_console_ready",
            current_url=inspection.url,
            page_title=title,
            non_secret_notes=("An account sign-out control is present.",),
        )

    text = inspection.visible_text.casefold()
    if any(needle in text for needle in _SIGNUP_ACKNOWLEDGED):
        return BrowserObservation(
            status=NAVIGATING,
            current_url=inspection.url,
            page_title=title,
            reason_code="signup_submitted",
        )

    return BrowserObservation(status=NAVIGATING, current_url=inspection.url, page_title=title)


class RemoteObservationLike(Protocol):
    """The observe half of the browser service, as the narrow port used here."""

    url: str
    title: str
    visible_text: str
    generation: int
    fingerprint: str
    raw_elements: tuple[Mapping[str, object], ...]


class RemoteActionOutcomeLike(Protocol):
    """The act half's typed answer, including "the request never arrived"."""

    status: str
    candidate_id: str
    before_url: str
    after_url: str
    before_generation: int
    after_generation: int
    reason_code: str | None
    expected_selected_label: str | None
    reached_service: bool


class RemoteCredentialSurfaceLike(Protocol):
    """Whether capture may run on this page, and whether a human may watch."""

    armed: bool
    live_view_allowed: bool
    reason_code: str
    reached_service: bool


class BrowserSessionService(Protocol):
    """Exactly the five verbs a driven onboarding session needs, and no others.

    Structurally satisfied by
    :class:`~ops.browser.service_client.BrowserServiceClient`. Declared as a port
    rather than imported as the class for the usual two reasons — a fake can drive
    the whole phase machine without a container, and nothing here can reach the
    client's wider surface (``navigate_onboarding`` would start a second closed
    loop inside the container and undo the single-step contract this module
    exists to provide).
    """

    async def start(
        self,
        profile_id: str | None,
        *,
        app_slug: str = ...,
        account_ref: str | None = ...,
        secret_scope: str | None = ...,
        use_storage_state: bool = ...,
        allowed_hosts: BrowserAllowedHosts | None = ...,
        run_id: str | None = ...,
        setup_fields: Mapping[str, str] | None = ...,
    ) -> Any:
        """Start one confined session and return its sanitized context."""

    async def session_status(self, session_id: str, *, capability_scope: str) -> tuple[bool, str]:
        """``(exists, reason_code)`` straight from the service, never inferred."""

    async def observe_session(
        self, session_id: str, *, capability_scope: str
    ) -> RemoteObservationLike:
        """Read the remote page once, taking no action."""

    async def act_on_session(
        self,
        session_id: str,
        *,
        candidate: Mapping[str, object],
        observed_url: str,
        observed_generation: int,
        capability_scope: str,
    ) -> RemoteActionOutcomeLike:
        """Execute ONE candidate against the observation that planned it."""

    async def arm_credential_surface(
        self, session_id: str, *, recipe: Mapping[str, object] | None, capability_scope: str
    ) -> RemoteCredentialSurfaceLike:
        """Ask the service to prove this page is the credential surface."""

    async def auto_capture_credentials(
        self,
        handle: str,
        app_slug: str,
        secret_store: object | None = ...,
        *,
        capability_scope: str,
        broker_grants: Mapping[str, str] | None = ...,
        broker_grant: str | None = ...,
    ) -> dict[str, str] | None:
        """Capture into the service's vault and return references only."""


class SessionBindingLedger(Protocol):
    """Where the run's bound session id is read from and written back to.

    One read and one write of the run's own row. The id has to be durable rather
    than held in this factory, because a CAPTCHA pause records the bound session
    (Requirement 11.4) and a worker that picks the run up afterwards must reattach
    to that session and not open a second one against the same account.
    """

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        """The run's record, or ``None`` when the run does not exist."""

    def update_run(self, run_id: str, **changes: object) -> dict[str, Any]:
        """Update the declared mutable run columns."""


class RunProfileReader(Protocol):
    """The run's committed provider profile — the authority for confinement."""

    def get_for_run(self, *, run_id: str) -> ProviderProfile | None:
        """The profile the run's phase history attributes it to."""


@dataclass(slots=True)
class ServiceLoopSession:
    """One run's bound session, seen through the loop's and the capture's ports.

    Mutable in exactly one respect: it remembers the last observation's URL and
    DOM generation. That is not a cache — it is the statement of *what this plan
    was made against*, which :meth:`act` quotes back so the service can answer
    ``stale`` rather than acting on a page that moved. Dropping it would leave the
    service comparing a fresh reading against itself, which passes every time.
    """

    service: BrowserSessionService
    run_id: str
    session_id: str
    app_slug: str
    # The reviewed recipe the credential surface is PROVEN against by the service.
    # ``None`` is honest for an app with no reviewed recipe: the service then
    # refuses to arm rather than arming against a predicate nobody wrote.
    recipe_snapshot: Mapping[str, object] | None = None
    _observed_url: str = ""
    _observed_generation: int = 0

    async def observe(self) -> LoopObservation:
        """One reading of the page, projected exactly as a local one would be.

        The raw element mappings are handed on unprojected: ``run_action_loop``
        runs them through ``build_snapshot`` itself, and a session that projected
        them early would be a session that could skip the projection. They are
        projected *here* too, but only to classify a structural human gate — that
        copy never leaves this method.
        """

        remote = await self.service.observe_session(self.session_id, capability_scope=self.run_id)
        self._observed_url = remote.url
        self._observed_generation = remote.generation
        raw = tuple(remote.raw_elements)
        # The same structural gate detection the trace loop uses, so a CAPTCHA or
        # a federated bounce reaches the loop as a typed ``human_action_type``
        # rather than as "the page has no useful candidates". Without it the phase
        # would burn its no-progress budget staring at a challenge widget and then
        # report a bound as spent instead of naming the gate.
        observation = classify_observation(
            PageInspection(
                url=remote.url,
                title=remote.title,
                visible_text=remote.visible_text,
                elements=build_snapshot(raw),
                locators=(),
                fingerprint=remote.fingerprint,
                generation=remote.generation,
            ),
            recipe=self.recipe_snapshot,
        )
        return LoopObservation(
            observation=observation,
            raw_elements=raw,
            page_text=remote.visible_text,
        )

    async def act(self, candidate: ActionCandidate) -> ActionExecutionResult:
        """Execute one already-validated candidate and report what happened.

        Never raises for a page outcome. The loop corrects itself differently for
        each of the four statuses, and an exception would collapse all of them
        into "the phase died" — which is the failure mode ``LoopSession.act``'s
        docstring says was the largest single reason the agent looked like it did
        nothing.
        """

        outcome = await self.service.act_on_session(
            self.session_id,
            candidate=_wire_candidate(candidate),
            observed_url=self._observed_url,
            observed_generation=self._observed_generation,
            capability_scope=self.run_id,
        )
        if not outcome.reached_service:
            # Nothing was attempted, so nothing about the page is known. Reported
            # as ``failed`` rather than ``blocked``: a denial that never happened
            # must not land in the run's durable denial facts, and ``failed`` is
            # the status whose correction — avoid this target, try a sibling — is
            # the right one for a transport that did not answer.
            LOGGER.warning(
                "onboarding run %s could not reach the browser service to act", self.run_id
            )
        status = outcome.status if outcome.status in _ACTION_STATUSES else "failed"
        return ActionExecutionResult(
            status=cast(Any, status),
            candidate_id=outcome.candidate_id or candidate.candidate_id,
            before_url=outcome.before_url or self._observed_url,
            after_url=outcome.after_url,
            before_generation=outcome.before_generation,
            after_generation=outcome.after_generation,
            reason_code=cast(ActionReasonCode | None, outcome.reason_code),
            expected_selected_label=outcome.expected_selected_label,
        )

    async def arm_credential_surface(self) -> bool:
        """Arm the pixel mask and revoke live grants, or report "not yet"."""

        surface = await self.service.arm_credential_surface(
            self.session_id,
            recipe=self.recipe_snapshot,
            capability_scope=self.run_id,
        )
        # Every unknown resolves to "not armed" inside the client already; this is
        # the same fail-closed reading restated at the boundary that gates capture.
        return bool(surface.armed and surface.reached_service)

    async def capture_credential(self, *, grant: str, kind: str) -> str:
        """Capture the rendered credential into the vault and return its reference.

        The value never enters this process: the service reads it inside the
        browser, writes it through its own broker boundary, and answers with the
        ``vault://`` reference the client has already validated for app and kind.
        A capture that produced no reference for ``kind`` raises, because a caller
        that continued on an empty string would record a credential it does not
        have.
        """

        refs = await self.service.auto_capture_credentials(
            self.session_id,
            self.app_slug,
            capability_scope=self.run_id,
            broker_grants={kind: grant},
        )
        reference = (refs or {}).get(kind, "")
        if not reference:
            raise ProviderOperationError(
                capability="browser service credential capture",
                reason_code="credential_not_captured",
            )
        return reference


_ACTION_STATUSES = frozenset({"executed", "stale", "blocked", "failed"})


def _wire_candidate(candidate: ActionCandidate) -> dict[str, object]:
    """Project a candidate onto the strict wire model the service accepts.

    Deliberately lossy in one direction: ``risk`` is not sent. The service sets it
    to ``requires_hitl`` on arrival because a candidate that crossed a process
    boundary carries no policy verdict of its own, and letting the sender assert
    its own risk level is exactly the thing the risk policy exists not to do. The
    verdict that matters was already applied in this process, twice, before the
    loop reached here.
    """

    identity = candidate.identity
    return {
        "candidate_id": candidate.candidate_id,
        "action": candidate.action,
        "semantic_target": candidate.semantic_target,
        "identity": None
        if identity is None
        else {
            "role": identity.role,
            "name": identity.name,
            "element_type": identity.element_type,
            "frame_path": list(identity.frame_path),
            "test_id": identity.test_id,
            "href_path": identity.href_path,
            "nearby_heading": identity.nearby_heading,
        },
        "value_ref": candidate.value_ref,
        "press_key": candidate.press_key,
        "url": candidate.url,
        "hint_index": candidate.hint_index,
    }


@dataclass(slots=True)
class ServiceLoopSessionFactory:
    """Bind (or reattach) the one browser session a run's phases are driven on.

    PRE:  the run has a committed provider profile — every session-bearing phase
          is entered after ``research``, and the allow-list is derived from it.
    POST: the returned session is confined to that profile's allow-list as the
          SERVICE confirmed it, and its id is durable on the run row before it is
          used, so a crash mid-phase leaves a session a later worker reattaches to
          rather than an orphan holding container capacity.

    One session per run for the whole walk, held in ``_bound``: the phases of a
    run are one continuous browsing session by design (sign in once, stay signed
    in through the developer console to the credential surface), and opening a
    session per phase would sign the run out between every boundary.
    """

    service: BrowserSessionService
    ledger: SessionBindingLedger
    profiles: RunProfileReader
    # Whether a reattached run reuses the persisted cookie jar for its account.
    # True is what makes ``authenticated -> developer_app -> credential_generation``
    # survive a worker restart without a second sign-in; a deployment that wants
    # every session cold sets it False and pays one login per resume.
    use_storage_state: bool = True
    _bound: dict[str, ServiceLoopSession] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def session_for(
        self, *, run_id: str, phase: OnboardingPhase, lease: Lease
    ) -> ServiceLoopSession:
        """The run's live session, reattached when one exists and startable once."""

        del phase  # one session serves every phase of the walk, by design
        del lease  # the driver already proved ownership; this port takes no second view
        async with self._lock:
            existing = self._bound.get(run_id)
            if existing is not None and await self._is_live(existing.session_id, run_id):
                return existing
            self._bound.pop(run_id, None)
            session = await self._bind(run_id)
            self._bound[run_id] = session
            return session

    def forget(self, run_id: str) -> None:
        """Drop this process's handle on a run's session (it is not released).

        Called when a worker is done driving a run. Deliberately *not* a release:
        the session belongs to the run, a paused run must keep the session holding
        its CAPTCHA (Requirement 11.4), and the service's own janitor plus
        ``reconcile_bound_sessions`` are what reclaim an abandoned one.
        """

        self._bound.pop(run_id, None)

    async def _is_live(self, session_id: str, run_id: str) -> bool:
        """Whether the SERVICE still reports this session, never inferred here."""

        try:
            exists, reason = await self.service.session_status(session_id, capability_scope=run_id)
        except Exception:
            # Unreachable is not "gone". Reported as not live so the caller binds a
            # fresh session rather than driving a session nobody confirmed.
            LOGGER.warning("onboarding run %s could not confirm its browser session", run_id)
            return False
        if not exists:
            LOGGER.info("onboarding run %s lost its browser session (%s)", run_id, reason)
        return bool(exists)

    async def _bind(self, run_id: str) -> ServiceLoopSession:
        """Reattach the run's recorded session, or start one under its profile."""

        record = self.ledger.get_run(run_id) or {}
        profile = self.profiles.get_for_run(run_id=run_id)
        if profile is None:
            # Raised rather than paused: every caller of this port is a phase the
            # driver only enters after ``research`` committed a digest, so an
            # absent profile is a broken profile store and not a run outcome.
            raise ProviderOperationError(
                capability="onboarding browser session",
                reason_code="profile_unavailable",
            )
        recipe = _recipe_snapshot(record)

        recorded = str(record.get("browser_session_id") or "")
        if recorded and await self._is_live(recorded, run_id):
            return ServiceLoopSession(
                service=self.service,
                run_id=run_id,
                session_id=recorded,
                app_slug=profile.app_slug,
                recipe_snapshot=recipe,
            )

        context = await self.service.start(
            None,
            app_slug=profile.app_slug,
            account_ref=str(record.get("browser_account_ref") or "") or None,
            secret_scope=run_id,
            run_id=run_id,
            use_storage_state=self.use_storage_state,
            # The confinement authority. ``start`` aborts the session when the
            # service does not echo this exact pattern set back, so an older or
            # misconfigured container cannot leave an unconfined session running.
            allowed_hosts=profile.allowed_hosts(),
            # The run's approved non-secret values, seeded at session creation.
            # The observe/act path never calls ``navigate_onboarding``, which is
            # the only other place the service learns them, so without this the
            # session's approved map holds one derived application name and every
            # ``fill`` the loop chose would be refused as an unapproved reference.
            # The same map is what ``ProfileGoals`` narrows each phase's
            # ``allow_value_refs`` against, so the two halves cannot disagree.
            setup_fields=run_setup_values(record, app_slug=profile.app_slug),
        )
        session_id = str(getattr(context, "session_id", "") or "")
        if not session_id:
            raise ProviderOperationError(
                capability="onboarding browser session",
                reason_code="session_id_missing",
            )
        # Durable BEFORE the session is driven: a crash after the first action with
        # no recorded id would leave a signed-in session nobody can reattach to and
        # nobody can attribute, which is how a run ends up creating two accounts.
        self.ledger.update_run(run_id, browser_session_id=session_id)
        return ServiceLoopSession(
            service=self.service,
            run_id=run_id,
            session_id=session_id,
            app_slug=profile.app_slug,
            recipe_snapshot=recipe,
        )


def _recipe_snapshot(record: Mapping[str, Any]) -> Mapping[str, object] | None:
    """The reviewed recipe the run was created against, if the row carries one."""

    snapshot = record.get("recipe_snapshot")
    return snapshot if isinstance(snapshot, Mapping) else None


def _session_conformance(session: ServiceLoopSession) -> LoopSession:
    """Typecheck-only proof that the session satisfies the action loop's port."""

    return session


__all__ = [
    "NAVIGATING",
    "UNTITLED_PAGE",
    "BrowserSessionService",
    "RunProfileReader",
    "ServiceLoopSession",
    "ServiceLoopSessionFactory",
    "SessionBindingLedger",
]
