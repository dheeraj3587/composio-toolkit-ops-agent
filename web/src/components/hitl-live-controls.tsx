"use client"

import Image from "next/image"
import { useActionState, useEffect, useRef } from "react"
import { useFormStatus } from "react-dom"
import { ExternalLink, KeyRound, LogIn, MonitorPlay, RefreshCw } from "lucide-react"

import {
  openLiveView,
  submitBrowserLoginAction,
  submitCredentialAction,
  type BrowserLoginState,
  type CredentialSubmitState,
  type LiveViewState,
} from "@/app/runs/[runId]/actions"
import { Button } from "@/components/ui/button"
import type { BrowserUiState } from "@/lib/types"

const initialLiveView: LiveViewState = {
  provider: null,
  mode: "unavailable",
  liveUrl: null,
  screenshotUrl: null,
  capturedAt: null,
  interactionAvailable: false,
  message: null,
  tone: "neutral",
}
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
 * Provider-aware owner controls for the browser phase.
 *
 * Browser Use supplies an interactive hosted iframe. Playwright supplies masked,
 * read-only screenshots through the same-origin Next proxy. Mutation controls are
 * rendered only from the backend-authoritative BrowserUiState booleans.
 */
export function HitlLiveControls({
  runId,
  browser,
  fieldName = "api_token",
  fieldLabel = "API token",
}: {
  runId: string
  browser: BrowserUiState | null
  fieldName?: string
  fieldLabel?: string
}) {
  const [liveState, liveAction] = useActionState(openLiveView, initialLiveView)
  const [loginState, loginAction] = useActionState(submitBrowserLoginAction, initialLogin)
  const [submitState, submitFormAction] = useActionState(submitCredentialAction, initialSubmit)
  const liveFormRef = useRef<HTMLFormElement>(null)
  const isPlaywright = browser?.provider === "playwright"

  useEffect(() => {
    liveFormRef.current?.requestSubmit()

    // A hosted Browser Use URL stays connected after the first load. Playwright
    // has no stream, so refresh only its read-only frame while the page is visible.
    if (!isPlaywright) return

    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") {
        liveFormRef.current?.requestSubmit()
      }
    }, 3_000)

    return () => window.clearInterval(timer)
  }, [isPlaywright])

  const providerLabel =
    (liveState.provider ?? browser?.provider) === "playwright"
      ? "Playwright browser"
      : "Browser Use session"

  return (
    <div className="space-y-4 border-t border-border pt-4">
      <div className="space-y-2">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <p className="flex items-center gap-1.5 data-label">
              <MonitorPlay className="size-3 text-brand-600" aria-hidden="true" />
              {providerLabel}
            </p>
            <p className="mt-1 text-[10px] leading-4 text-muted-foreground">
              {isPlaywright
                ? "Read-only masked frames from the isolated Chromium service."
                : "Interactive hosted browser session."}
            </p>
          </div>
          <form action={liveAction} ref={liveFormRef}>
            <input type="hidden" name="run_id" value={runId} />
            <SubmitButton
              label={isPlaywright ? "Refresh frame" : "Reconnect"}
              pendingLabel={isPlaywright ? "Refreshing…" : "Connecting…"}
            />
          </form>
        </div>

        {liveState.mode === "hosted_url" && liveState.liveUrl ? (
          <div className="space-y-2">
            <iframe
              src={liveState.liveUrl}
              title="Interactive Browser Use session"
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
        ) : liveState.mode === "screenshot" && liveState.screenshotUrl ? (
          <div className="space-y-2">
            <div className="relative aspect-video min-h-[320px] overflow-hidden rounded-lg border border-border bg-black">
              <Image
                unoptimized
                src={liveState.screenshotUrl}
                alt="Latest masked Playwright browser screenshot"
                width={1600}
                height={900}
                className="h-full w-full object-contain"
              />
            </div>
            <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] leading-4 text-muted-foreground">
              <span className="inline-flex items-center gap-1.5">
                <RefreshCw className="size-3" aria-hidden="true" />
                Read-only screenshot — you cannot click inside this view.
              </span>
              {liveState.capturedAt ? <span>Captured {liveState.capturedAt}</span> : null}
            </div>
          </div>
        ) : (
          <div className="grid min-h-[240px] w-full place-items-center rounded-lg border border-dashed border-border bg-muted/30 px-6 text-center text-xs text-muted-foreground">
            {liveState.tone === "error"
              ? (liveState.message ?? "No live browser session is available.")
              : "Connecting to the browser session…"}
          </div>
        )}

        {liveState.message && liveState.mode !== "unavailable" ? (
          <p
            className={liveState.tone === "error" ? "text-xs text-destructive" : "text-xs text-muted-foreground"}
            role={liveState.tone === "error" ? "alert" : "status"}
          >
            {liveState.message}
          </p>
        ) : null}
      </div>

      {browser?.can_submit_login ? (
        <form
          action={loginAction}
          onSubmit={(event) => {
            // Hand the raw sign-in values to the server action, then clear them
            // from the DOM. They are consumed by the selected provider's transient
            // secret boundary for this resume and are never persisted.
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
            Continue with account credentials
          </label>
          <p className="text-[10px] leading-4 text-muted-foreground">
            The backend requested a login resume. These values pass through the selected provider&apos;s
            one-time secret boundary and never enter model prompts or durable run state.
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
              role={loginState.tone === "error" ? "alert" : "status"}
            >
              {loginState.message}
            </p>
          ) : null}
        </form>
      ) : null}

      {browser?.can_submit_credential ? (
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
          className="space-y-2 border-t border-border pt-4"
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
              role={submitState.tone === "error" ? "alert" : "status"}
            >
              {submitState.message}
            </p>
          ) : null}
        </form>
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
