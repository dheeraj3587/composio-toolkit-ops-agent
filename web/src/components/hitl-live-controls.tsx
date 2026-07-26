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
  runPhaseAction,
  type LiveViewState,
  type PhaseActionState,
} from "@/app/runs/[runId]/actions"
import {
  BrowserLoginForm,
  CredentialSubmitForm,
} from "@/components/browser-hitl-forms"
import { BrowserLiveSurface } from "@/components/browser-live-surface"
import type { PlaywrightRemoteViewHandle } from "@/components/playwright-remote-view"
import { Button } from "@/components/ui/button"
import type { BrowserUiState } from "@/lib/types"

const initialLiveView: LiveViewState = {
  provider: null,
  mode: "unavailable",
  liveUrl: null,
  screenshotUrl: null,
  interactivePath: null,
  capturedAt: null,
  interactionAvailable: false,
  message: null,
  tone: "neutral",
}
const initialPhaseAction: PhaseActionState = { message: null, tone: "neutral" }

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
 * Browser Use supplies an interactive hosted iframe. Playwright supplies masked
 * screenshots while autonomous work is running and same-origin noVNC control
 * only while the workflow is paused for HITL. Mutation controls are rendered
 * only from the backend-authoritative BrowserUiState booleans.
 */
export function HitlLiveControls({
  runId,
  browser,
  browserStateVersion,
  canResumeInteractive = false,
  fieldName = "api_token",
  fieldLabel = "API token",
}: {
  runId: string
  browser: BrowserUiState | null
  browserStateVersion: string
  canResumeInteractive?: boolean
  fieldName?: string
  fieldLabel?: string
}) {
  const [liveState, setLiveState] = useState<LiveViewState>(initialLiveView)
  const [resumeState, resumeAction] = useActionState(runPhaseAction, initialPhaseAction)
  const [livePending, startLiveTransition] = useTransition()
  const liveRequestInFlight = useRef<number | null>(null)
  const liveRequestSequence = useRef(0)
  const interactiveRunWithGrant = useRef<string | null>(null)
  const remoteViewRef = useRef<PlaywrightRemoteViewHandle>(null)
  const isPlaywright = browser?.provider === "playwright"
  const isInteractiveHitl =
    isPlaywright &&
    browser?.lifecycle === "waiting_for_hitl" &&
    browser.interaction_available

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
    if (isInteractiveHitl) {
      // Attach once when this run enters HITL. A timestamp refresh while the
      // operator is connected must not mint a token or replace the RFB session.
      if (interactiveRunWithGrant.current !== runId) {
        interactiveRunWithGrant.current = runId
        requestLiveView()
      }
      return
    }

    interactiveRunWithGrant.current = null
    requestLiveView()

    // Browser Use and interactive noVNC remain connected after the first grant.
    // Poll only read-only Playwright frames while the autonomous loop is active.
    if (!isPlaywright) return

    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") requestLiveView()
    }, 3_000)

    return () => window.clearInterval(timer)
  }, [
    browserStateVersion,
    isInteractiveHitl,
    isPlaywright,
    requestLiveView,
    resumeState.interactiveStateVersion,
    runId,
  ])

  function disconnectBeforeResume() {
    remoteViewRef.current?.disconnect()
    // The next backend state version represents a new HITL generation on the
    // same run and therefore needs a fresh, short-lived WebSocket grant.
    interactiveRunWithGrant.current = null
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

      {canResumeInteractive && isInteractiveHitl ? (
        <form
          action={resumeAction}
          onSubmit={disconnectBeforeResume}
          className="space-y-2 border-t border-border pt-4"
        >
          <input type="hidden" name="run_id" value={runId} />
          <input type="hidden" name="action" value="resume" />
          <p className="text-[10px] leading-4 text-muted-foreground">
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

      {browser?.can_submit_credential ? (
        <CredentialSubmitForm
          runId={runId}
          fieldName={fieldName}
          fieldLabel={fieldLabel}
        />
      ) : browser?.credential_page_verified ? (
        <p className="border-t border-border pt-4 text-[10px] leading-4 text-muted-foreground">
          The credential page is verified, but manual submission is disabled by the owner-action policy.
        </p>
      ) : (
        <p className="border-t border-border pt-4 text-[10px] leading-4 text-muted-foreground">
          Credential submission unlocks only after the backend verifies the official credential-management page.
        </p>
      )}
    </div>
  )
}
