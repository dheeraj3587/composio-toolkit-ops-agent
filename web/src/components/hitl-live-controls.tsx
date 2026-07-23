"use client"

import { useActionState } from "react"
import { useFormStatus } from "react-dom"
import { ExternalLink, KeyRound, MonitorPlay } from "lucide-react"

import {
  openLiveView,
  submitCredentialAction,
  type CredentialSubmitState,
  type LiveViewState,
} from "@/app/runs/[runId]/actions"
import { Button } from "@/components/ui/button"

const initialLiveView: LiveViewState = { liveUrl: null, message: null, tone: "neutral" }
const initialSubmit: CredentialSubmitState = { message: null, tone: "neutral", status: null }

const FIELD_CLASS =
  "w-full rounded-none border border-border bg-card px-3 py-2 text-xs focus-visible:outline focus-visible:outline-2 focus-visible:outline-violet-600"

function SubmitButton({ label, pendingLabel }: { label: string; pendingLabel: string }) {
  const { pending } = useFormStatus()
  return (
    <Button type="submit" variant="outline" size="sm" disabled={pending} className="rounded-none">
      {pending ? pendingLabel : label}
    </Button>
  )
}

/**
 * Owner-only HITL controls. The live-view URL is fetched on demand from the
 * loopback API and rendered as a click-through link; it is never persisted in
 * the browser. The credential value is posted directly to the loopback
 * submission endpoint and never stored client-side.
 */
export function HitlLiveControls({
  runId,
  fieldName = "api_token",
  fieldLabel = "API token",
}: {
  runId: string
  fieldName?: string
  fieldLabel?: string
}) {
  const [liveState, liveAction] = useActionState(openLiveView, initialLiveView)
  const [submitState, submitFormAction] = useActionState(submitCredentialAction, initialSubmit)

  return (
    <div className="space-y-4 border-t border-border pt-4">
      <div className="space-y-2">
        <form action={liveAction} className="space-y-2">
          <input type="hidden" name="run_id" value={runId} />
          <SubmitButton label="Get live browser link" pendingLabel="Requesting…" />
        </form>
        {liveState.liveUrl ? (
          <Button asChild size="sm" className="rounded-none">
            <a href={liveState.liveUrl} target="_blank" rel="noopener noreferrer">
              <MonitorPlay className="size-3.5" aria-hidden="true" /> Open live session
              <ExternalLink className="size-3" aria-hidden="true" />
            </a>
          </Button>
        ) : null}
        {liveState.message ? (
          <p
            className={liveState.tone === "error" ? "text-xs text-destructive" : "text-xs text-muted-foreground"}
            aria-live="polite"
          >
            {liveState.message}
          </p>
        ) : null}
      </div>

      <form
        action={submitFormAction}
        onSubmit={(event) => {
          // Clear the raw token from the DOM immediately after it is handed to
          // the server action; it is never kept in React state or storage.
          const form = event.currentTarget
          queueMicrotask(() => {
            const field = form.elements.namedItem("credential_value")
            if (field instanceof HTMLInputElement) field.value = ""
          })
        }}
        className="space-y-2"
      >
        <input type="hidden" name="run_id" value={runId} />
        <input type="hidden" name="field_name" value={fieldName} />

        <p className="data-label">Owner context (required by the API contract)</p>
        <div className="grid gap-2 sm:grid-cols-2">
          <input name="legal_name" required placeholder="Company legal name" autoComplete="off" className={FIELD_CLASS} aria-label="Company legal name" />
          <input name="website" required placeholder="https://company.example" autoComplete="off" className={FIELD_CLASS} aria-label="Company website" />
          <input name="work_email_ref" required placeholder="vault://company/work_email/..." autoComplete="off" spellCheck={false} className={FIELD_CLASS} aria-label="Work email vault reference" />
          <input name="callback_urls" placeholder="OAuth callback URLs (comma-separated)" autoComplete="off" className={FIELD_CLASS} aria-label="OAuth callback URLs" />
        </div>
        <input name="use_case" required placeholder="Integration use case" autoComplete="off" className={FIELD_CLASS} aria-label="Integration use case" />

        <label htmlFor={`credential-${runId}`} className="flex items-center gap-1.5 data-label">
          <KeyRound className="size-3 text-violet-600" aria-hidden="true" />
          {fieldLabel}
        </label>
        <input
          id={`credential-${runId}`}
          name="credential_value"
          type="password"
          autoComplete="off"
          spellCheck={false}
          required
          className={`${FIELD_CLASS} font-mono`}
          placeholder="Paste the token once; it is encrypted immediately"
        />
        <p className="text-[10px] leading-4 text-muted-foreground">
          The value is written straight to the encrypted vault. Only a vault:// reference is stored;
          the raw token never enters run state, logs, or this page.
        </p>
        <SubmitButton label="Submit credential securely" pendingLabel="Submitting…" />
        {submitState.message ? (
          <p
            className={submitState.tone === "error" ? "text-xs text-destructive" : "text-xs text-emerald-700"}
            aria-live="polite"
          >
            {submitState.message}
          </p>
        ) : null}
      </form>
    </div>
  )
}
