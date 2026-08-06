"use client"

import {
  useActionState,
  useCallback,
  useEffect,
  useRef,
  useState,
  useTransition,
} from "react"
import { useFormStatus } from "react-dom"

import {
  openLiveView,
  refreshRunDetailAction,
  runOnboardingControlAction,
  runPhaseAction,
  type LiveViewState,
  type OnboardingControlState,
  type PhaseActionState,
} from "@/app/runs/[runId]/actions"
import {
  AdmissionDecisionForm,
  BrowserLoginForm,
  BrowserVerificationForm,
  CaptchaResumeForm,
  CredentialSubmitForm,
} from "@/components/browser-hitl-forms"
import { BrowserLiveSurface } from "@/components/browser-live-surface"
import type { PlaywrightRemoteViewHandle } from "@/components/playwright-remote-view"
import { Button } from "@/components/ui/button"
import { humanize } from "@/lib/format"
import type {
  BrowserUiState,
  OnboardingControlsView,
  OnboardingStateView,
} from "@/lib/types"

const initialLiveView: LiveViewState = {
  provider: null,
  mode: "unavailable",
  screenshotUrl: null,
  interactivePath: null,
  capturedAt: null,
  interactionAvailable: false,
  reasonCode: null,
  message: null,
  tone: "neutral",
}
const initialPhaseAction: PhaseActionState = { message: null, tone: "neutral" }
const initialControl: OnboardingControlState = { message: null, tone: "neutral", control: null }

function SubmitButton({ label, pendingLabel }: { label: string; pendingLabel: string }) {
  const { pending } = useFormStatus()
  return (
    <Button type="submit" variant="outline" size="sm" disabled={pending} className="rounded-md">
      {pending ? pendingLabel : label}
    </Button>
  )
}

/**
 * Provider-aware owner controls for the browser phase.
 *
 * Playwright supplies a continuous same-origin noVNC stream. The signed grant is
 * view-only while autonomous work runs and permits control only while the workflow
 * is paused for HITL. Mutation controls come only from backend-authoritative
 * capabilities. A run recorded on the retired cloud backend still renders as
 * history, but it has no live session, so it gets no viewer and no poll.
 */
export function HitlLiveControls({
  runId,
  browser,
  browserStateVersion,
  canResumeInteractive = false,
  fieldName = "api_token",
  fieldLabel = "API token",
  onboarding = null,
  controls = null,
}: {
  runId: string
  browser: BrowserUiState | null
  browserStateVersion: string
  canResumeInteractive?: boolean
  fieldName?: string
  fieldLabel?: string
  // Present only for an onboarding run. When they are present, the only decision
  // surface beside the live browser is the CAPTCHA prompt, and its buttons come
  // from the projected controls rather than from the run status.
  onboarding?: OnboardingStateView | null
  controls?: OnboardingControlsView | null
}) {
  const [liveState, setLiveState] = useState<LiveViewState>(initialLiveView)
  const [resumeState, resumeAction] = useActionState(runPhaseAction, initialPhaseAction)
  const [livePending, startLiveTransition] = useTransition()
  const liveRequestInFlight = useRef<number | null>(null)
  const liveRequestSequence = useRef(0)
  const remoteGrantIdentity = useRef<string | null>(null)
  const remoteViewRef = useRef<PlaywrightRemoteViewHandle>(null)
  const isPlaywright = browser?.provider === "playwright"
  const isInteractiveHitl =
    isPlaywright &&
    browser?.lifecycle === "waiting_for_hitl" &&
    browser.interaction_available
  const isPlaywrightRemote =
    isPlaywright &&
    browser?.live_view_available === true &&
    browser.live_view_mode === "interactive_remote"

  const requestLiveView = useCallback(() => {
    if (liveRequestInFlight.current !== null) return

    const requestSequence = ++liveRequestSequence.current
    liveRequestInFlight.current = requestSequence
    const formData = new FormData()
    formData.set("run_id", runId)

    startLiveTransition(async () => {
      try {
        const result = await openLiveView(initialLiveView, formData)
        if (requestSequence === liveRequestSequence.current) setLiveState(result)
      } catch {
        if (requestSequence === liveRequestSequence.current) {
          setLiveState({
            ...initialLiveView,
            message: "The live browser view could not be retrieved.",
            tone: "error",
          })
        }
      } finally {
        if (liveRequestInFlight.current === requestSequence) {
          liveRequestInFlight.current = null
        }
      }
    })
  }, [runId, startLiveTransition])

  useEffect(() => {
    if (isPlaywrightRemote) {
      // Attach once per capability generation. The transition from autonomous
      // view to HITL control deliberately requests a fresh signed token; ordinary
      // page refreshes must not churn a healthy RFB connection.
      const identity = `${runId}:${isInteractiveHitl ? "control" : "view"}`
      if (remoteGrantIdentity.current !== identity) {
        remoteViewRef.current?.disconnect()
        remoteGrantIdentity.current = identity
        requestLiveView()
      }
      return
    }

    remoteGrantIdentity.current = null
    requestLiveView()

    // Interactive noVNC stays connected after the first grant, and a run recorded
    // on the retired cloud backend has no session at all. Poll only read-only
    // Playwright frames, while the autonomous loop is active.
    if (!isPlaywright) return

    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") requestLiveView()
    }, 3_000)

    return () => window.clearInterval(timer)
  }, [
    browserStateVersion,
    isInteractiveHitl,
    isPlaywright,
    isPlaywrightRemote,
    requestLiveView,
    resumeState.interactiveStateVersion,
    runId,
  ])

  // The phase poll is deliberately separate from the live-view effect above,
  // which returns early in `interactive_remote` mode — the mode a CAPTCHA pause
  // uses. It revalidates the route only: no grant is requested and the RFB
  // connection is untouched, so an autonomous takeover appears without a reload.
  useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        void refreshRunDetailAction(runId).catch(() => undefined)
      }
    }, 5_000)

    return () => window.clearInterval(timer)
  }, [runId])

  function disconnectBeforeResume() {
    remoteViewRef.current?.disconnect()
    // The next backend state version represents a new HITL generation on the
    // same run and therefore needs a fresh, short-lived WebSocket grant.
    remoteGrantIdentity.current = null
    liveRequestSequence.current += 1
    liveRequestInFlight.current = null
    setLiveState({
      ...initialLiveView,
      provider: "playwright",
      message: "Remote control disconnected. Resuming the Playwright session…",
    })
  }

  return (
    <div className="space-y-4 border-t border-border pt-4">
      <BrowserLiveSurface
        liveState={liveState}
        isPlaywright={isPlaywright}
        isInteractiveHitl={isInteractiveHitl}
        livePending={livePending}
        onRequestLiveView={requestLiveView}
        remoteViewRef={remoteViewRef}
      />

      {/*
        An onboarding run has exactly two decision surfaces (Requirement 18.4).
        The admission prompt lives in the onboarding console; the one that belongs
        beside the live browser is the CAPTCHA prompt, so every legacy prompt is
        withheld here rather than added as a third surface.
      */}
      {controls ? (
        <div className="border-t border-border pt-4">
          {onboarding?.phase === "captcha_paused" ? (
            <CaptchaResumeForm
              runId={runId}
              canResume={controls.can_resume}
              canCancel={controls.can_cancel}
              withheldReason={controls.resume_withheld_reason ?? null}
              onResumeSubmit={isInteractiveHitl ? disconnectBeforeResume : undefined}
            />
          ) : (
            <p className="text-2xs text-muted-foreground">
              The agent is driving this session. Operator controls for this run come from the
              onboarding console above, and no credential is ever typed on this page.
            </p>
          )}
        </div>
      ) : (
        <LegacyBrowserSurfaces
          runId={runId}
          browser={browser}
          canResumeInteractive={canResumeInteractive}
          isInteractiveHitl={isInteractiveHitl}
          fieldName={fieldName}
          fieldLabel={fieldLabel}
          resumeAction={resumeAction}
          resumeState={resumeState}
          onResumeSubmit={disconnectBeforeResume}
        />
      )}
    </div>
  )
}

/**
 * The pre-onboarding browser surfaces, unchanged.
 *
 * A legacy run projects no onboarding controls, so it keeps deriving these
 * surfaces from `BrowserUiState` exactly as before.
 */
function LegacyBrowserSurfaces({
  runId,
  browser,
  canResumeInteractive,
  isInteractiveHitl,
  fieldName,
  fieldLabel,
  resumeAction,
  resumeState,
  onResumeSubmit,
}: {
  runId: string
  browser: BrowserUiState | null
  canResumeInteractive: boolean
  isInteractiveHitl: boolean
  fieldName: string
  fieldLabel: string
  resumeAction: (payload: FormData) => void
  resumeState: PhaseActionState
  onResumeSubmit: () => void
}) {
  return (
    <>
      {canResumeInteractive && isInteractiveHitl ? (
        <form
          action={resumeAction}
          onSubmit={onResumeSubmit}
          className="space-y-2 border-t border-border pt-4"
        >
          <input type="hidden" name="run_id" value={runId} />
          <input type="hidden" name="action" value="resume" />
          <p className="text-2xs text-muted-foreground">
            Finish the human-only step in the remote browser, then disconnect control and resume the
            same Playwright session.
          </p>
          <SubmitButton label="Disconnect and resume" pendingLabel="Resuming…" />
          {resumeState.message ? (
            <p
              className={resumeState.tone === "error" ? "text-xs text-destructive" : "text-xs text-muted-foreground"}
              role={resumeState.tone === "error" ? "alert" : "status"}
            >
              {resumeState.message}
            </p>
          ) : null}
        </form>
      ) : null}

      {browser?.can_submit_login ? <BrowserLoginForm runId={runId} /> : null}

      {browser?.can_submit_otp ? <BrowserVerificationForm runId={runId} /> : null}

      {browser?.can_submit_credential ? (
        <CredentialSubmitForm
          runId={runId}
          fieldName={fieldName}
          fieldLabel={fieldLabel}
        />
      ) : browser?.credential_page_verified ? (
        <p className="border-t border-border pt-4 text-2xs text-muted-foreground">
          The credential page is verified, but manual submission is disabled by the owner-action policy.
        </p>
      ) : (
        <p className="border-t border-border pt-4 text-2xs text-muted-foreground">
          Credential submission unlocks only after the backend verifies the official credential-management page.
        </p>
      )}
    </>
  )
}

/**
 * The backend-projected operator control strip (Requirements 18.4, 18.6).
 *
 * Every button here exists because `OnboardingControlsView` says it is legal —
 * nothing is inferred from the run status. The admission prompt is one of the two
 * decision surfaces the console may render; pause, resume, cancel, reset, and the
 * step retry are controls, not prompts. Resume during a CAPTCHA pause belongs to
 * the CAPTCHA prompt beside the live browser, so it is not duplicated here.
 */
export function OnboardingControlBar({
  runId,
  state,
  controls,
  providerName,
}: {
  runId: string
  state: OnboardingStateView
  controls: OnboardingControlsView
  providerName?: string | null
}) {
  const [controlState, controlAction] = useActionState(runOnboardingControlAction, initialControl)
  const captchaPaused = state.phase === "captcha_paused"
  const simpleControls = [
    { control: "pause", available: controls.can_pause, label: "Pause at next boundary", pending: "Pausing…" },
    {
      control: "resume",
      // A CAPTCHA pause is resumed from its own prompt beside the live browser.
      available: controls.can_resume && !captchaPaused,
      label: "Resume the run",
      pending: "Resuming…",
    },
    { control: "cancel", available: controls.can_cancel, label: "Cancel the run", pending: "Cancelling…" },
  ].filter((item) => item.available)
  const nothingAvailable =
    simpleControls.length === 0 &&
    !controls.can_decide_admission &&
    !controls.can_retry_step &&
    !controls.can_reset

  return (
    <div className="panel rounded-md p-5" data-testid="onboarding-control-bar">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="eyebrow">Backend-projected capability</p>
          <h3 className="mt-1 text-lg font-semibold">Operator controls</h3>
        </div>
        <p className="font-mono text-2xs uppercase tracking-[0.1em] text-muted-foreground">
          Control reason · {humanize(controls.reason_code)}
        </p>
      </div>
      <p className="mt-2 text-xs leading-5 text-muted-foreground">
        Each control below is one the backend reports as legal for {humanize(state.phase)}. A control
        the backend withholds is absent rather than shown and then refused.
      </p>

      <div className="mt-5 space-y-4 border-t border-border pt-4">
        {controls.can_decide_admission ? (
          <AdmissionDecisionForm
            runId={runId}
            profileDigest={state.profile_digest}
            providerName={providerName}
          />
        ) : null}

        {simpleControls.length || controls.can_retry_step ? (
          <div className="flex flex-wrap gap-2">
            {simpleControls.map((item) => (
              <form key={item.control} action={controlAction}>
                <input type="hidden" name="run_id" value={runId} />
                <input type="hidden" name="control" value={item.control} />
                <SubmitButton label={item.label} pendingLabel={item.pending} />
              </form>
            ))}
            {controls.can_retry_step ? (
              <form action={controlAction}>
                <input type="hidden" name="run_id" value={runId} />
                <input type="hidden" name="control" value="retry-step" />
                {/* Optimistic check, not a choice of step: the backend refuses a
                    phase the run is not standing in. */}
                <input type="hidden" name="expected_phase" value={state.phase} />
                <SubmitButton
                  label={`Retry ${humanize(controls.retryable_step ?? state.phase).toLowerCase()}`}
                  pendingLabel="Retrying…"
                />
              </form>
            ) : null}
          </div>
        ) : null}

        {controls.can_reset ? (
          <form action={controlAction} className="space-y-2 border-t border-border pt-4">
            <input type="hidden" name="run_id" value={runId} />
            <input type="hidden" name="control" value="reset" />
            <label htmlFor={`reset-confirm-${runId}`} className="flex items-center gap-2 text-xs">
              <input
                id={`reset-confirm-${runId}`}
                type="checkbox"
                name="confirm"
                value="true"
              />
              Confirm restart from research. Workflow state is cleared; stored credentials are kept.
            </label>
            <SubmitButton label="Reset this run" pendingLabel="Resetting…" />
          </form>
        ) : null}

        {nothingAvailable ? (
          <p className="text-xs leading-5 text-muted-foreground">
            The backend authorizes no operator control in this phase.
          </p>
        ) : null}

        {controlState.message ? (
          <p
            className={controlState.tone === "error" ? "text-xs text-destructive" : "text-xs text-muted-foreground"}
            role={controlState.tone === "error" ? "alert" : "status"}
          >
            {controlState.message}
          </p>
        ) : null}
      </div>
    </div>
  )
}
