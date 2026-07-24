"use client"

import { useActionState, useEffect, useRef } from "react"
import { useFormStatus } from "react-dom"
import { ExternalLink, KeyRound, LogIn, MonitorPlay } from "lucide-react"

import {
  openLiveView,
  submitBrowserLoginAction,
  submitCredentialAction,
  type BrowserLoginState,
  type CredentialSubmitState,
  type LiveViewState,
} from "@/app/runs/[runId]/actions"
import { Button } from "@/components/ui/button"

const initialLiveView: LiveViewState = { liveUrl: null, message: null, tone: "neutral" }
const initialSubmit: CredentialSubmitState = { message: null, tone: "neutral", status: null }
const initialLogin: BrowserLoginState = { message: null, tone: "neutral" }

const FIELD_CLASS =
  "h-10 w-full rounded-md border border-input bg-card px-3 py-2 text-xs shadow-[0_1px_1px_rgba(15,16,20,0.02)] transition-[border-color,box-shadow] focus-visible:border-ring focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/20"

function SubmitButton({ label, pendingLabel }: { label: string; pendingLabel: string }) {
  const { pending } = useFormStatus()
  return (
    <Button type="submit" variant="outline" size="sm" disabled={pending} className="rounded-md">
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
  const [loginState, loginAction] = useActionState(submitBrowserLoginAction, initialLogin)
  const [submitState, submitFormAction] = useActionState(submitCredentialAction, initialSubmit)
  const liveFormRef = useRef<HTMLFormElement>(null)

  // Auto-load the live browser feed on mount and refresh it periodically so the
  // embedded viewer stays connected. The signed URL lives only in ephemeral
  // action state; it is never persisted client-side.
  useEffect(() => {
    liveFormRef.current?.requestSubmit()
    const timer = setInterval(() => liveFormRef.current?.requestSubmit(), 45_000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div className="space-y-4 border-t border-border pt-4">
      <div className="space-y-2">
        <div className="flex items-center justify-between gap-2">
          <p className="flex items-center gap-1.5 data-label">
            <MonitorPlay className="size-3 text-brand-600" aria-hidden="true" />
            Live browser — interact here (enter CAPTCHA / OTP in the frame)
          </p>
          <form action={liveAction} ref={liveFormRef}>
            <input type="hidden" name="run_id" value={runId} />
            <SubmitButton label="Reconnect" pendingLabel="Connecting…" />
          </form>
        </div>
        {liveState.liveUrl ? (
          <div className="space-y-2">
            <iframe
              src={liveState.liveUrl}
              title="Live browser session"
              className="h-[560px] w-full rounded-lg border border-border bg-black"
              allow="clipboard-read; clipboard-write"
            />
            <Button asChild variant="outline" size="sm" className="rounded-md">
              <a href={liveState.liveUrl} target="_blank" rel="noopener noreferrer">
                <MonitorPlay className="size-3.5" aria-hidden="true" /> Open in a new tab
                <ExternalLink className="size-3" aria-hidden="true" />
              </a>
            </Button>
          </div>
        ) : (
          <div className="grid h-[560px] w-full place-items-center rounded-none border border-dashed border-border bg-muted/30 text-xs text-muted-foreground">
            {liveState.tone === "error"
              ? (liveState.message ?? "No live browser session is available.")
              : "Connecting to the live browser session…"}
          </div>
        )}
        {liveState.liveUrl && liveState.message ? (
          <p
            className={liveState.tone === "error" ? "text-xs text-destructive" : "text-xs text-muted-foreground"}
            aria-live="polite"
          >
            {liveState.message}
          </p>
        ) : null}
      </div>

      <form
        action={loginAction}
        onSubmit={(event) => {
          // Hand the raw sign-in values to the server action, then clear them
          // from the DOM. They are injected into Browser Use as secure
          // placeholders for a single resume and are never persisted.
          const form = event.currentTarget
          queueMicrotask(() => {
            for (const name of ["login_email", "login_password"]) {
              const field = form.elements.namedItem(name)
              if (field instanceof HTMLInputElement) field.value = ""
            }
          })
        }}
        className="space-y-2 border-t border-border pt-4"
      >
        <input type="hidden" name="run_id" value={runId} />
        <label className="flex items-center gap-1.5 data-label">
          <LogIn className="size-3 text-brand-600" aria-hidden="true" />
          Sign the agent in autonomously
        </label>
        <p className="text-[10px] leading-4 text-muted-foreground">
          Provide the account sign-in credentials once. The agent types them into the app&apos;s own
          login form via secure placeholders it can never read, then continues on its own. You do
          not drive the browser. CAPTCHA, OTP/2FA, passkeys, billing, and legal consent still pause
          for you.
        </p>
        <div className="grid gap-2 sm:grid-cols-2">
          <input
            name="login_email"
            required
            placeholder="Account email or username"
            autoComplete="off"
            spellCheck={false}
            className={FIELD_CLASS}
            aria-label="Account email or username"
          />
          <input
            name="login_password"
            type="password"
            required
            placeholder="Account password"
            autoComplete="off"
            spellCheck={false}
            className={`${FIELD_CLASS} font-mono`}
            aria-label="Account password"
          />
        </div>
        <SubmitButton label="Sign in and continue" pendingLabel="Signing in…" />
        {loginState.message ? (
          <p
            className={loginState.tone === "error" ? "text-xs text-destructive" : "text-xs text-emerald-700"}
            aria-live="polite"
          >
            {loginState.message}
          </p>
        ) : null}
      </form>

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
          <KeyRound className="size-3 text-brand-600" aria-hidden="true" />
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
