"use client"

import { useActionState, useState } from "react"
import { useFormStatus } from "react-dom"
import { KeyRound, LogIn, MailCheck, ShieldQuestion, UserPlus } from "lucide-react"

import {
  decideAdmissionAction,
  runOnboardingControlAction,
  submitBrowserLoginAction,
  submitBrowserVerificationAction,
  submitCredentialAction,
  type AdmissionDecisionState,
  type BrowserLoginState,
  type BrowserVerificationState,
  type CredentialSubmitState,
  type OnboardingControlState,
} from "@/app/runs/[runId]/actions"
import { Button } from "@/components/ui/button"
import { humanize } from "@/lib/format"

const initialSubmit: CredentialSubmitState = { message: null, tone: "neutral", status: null }
const initialLogin: BrowserLoginState = { message: null, tone: "neutral" }
const initialVerification: BrowserVerificationState = { message: null, tone: "neutral" }
const initialAdmission: AdmissionDecisionState = { message: null, tone: "neutral", route: null }
const initialControl: OnboardingControlState = { message: null, tone: "neutral", control: null }

const FIELD_CLASS =
  "h-10 w-full rounded-md border border-input bg-card px-3 py-2 text-xs shadow-[0_1px_1px_rgba(15,16,20,0.02)] transition-[border-color,box-shadow] focus-visible:border-ring focus-visible:outline-none focus-visible:ring-3 focus-visible:ring-ring/20"

function FormSubmitButton({ label, pendingLabel }: { label: string; pendingLabel: string }) {
  const { pending } = useFormStatus()
  return (
    <Button type="submit" variant="outline" size="sm" disabled={pending} className="rounded-md">
      {pending ? pendingLabel : label}
    </Button>
  )
}

function ActionMessage({
  message,
  tone,
}: {
  message: string | null
  tone: "neutral" | "error"
}) {
  if (!message) return null
  return (
    <p
      className={tone === "error" ? "text-xs text-destructive" : "text-xs text-muted-foreground"}
      role={tone === "error" ? "alert" : "status"}
    >
      {message}
    </p>
  )
}

/**
 * Decision surface 1 of 2: the admission prompt (Requirements 18.4, 18.6).
 *
 * Creating an account on a provider is the one judgement this feature refuses to
 * make on its own, so it is asked once, here. The committed profile digest travels
 * with the answer: the operator decides about the profile they were shown, and the
 * backend refuses a decision that names any other profile.
 *
 * Rendered only while the backend projects `can_decide_admission`.
 */
export function AdmissionDecisionForm({
  runId,
  profileDigest,
  providerName,
}: {
  runId: string
  profileDigest: string
  providerName?: string | null
}) {
  const [decisionState, decisionAction] = useActionState(decideAdmissionAction, initialAdmission)
  const subject = providerName?.trim() || "this provider"

  return (
    <div className="space-y-3" data-testid="admission-prompt">
      <p className="flex items-center gap-1.5 data-label">
        <UserPlus className="size-3 text-brand-600" aria-hidden="true" />
        Admission decision
      </p>
      <p className="text-[12px] leading-4 text-muted-foreground">
        No credential for {subject} is in the vault. Creating an account is the one decision the
        agent never makes for you. Approving it lets the agent sign up on the provider&apos;s own
        site; cancelling ends the run without creating anything.
      </p>
      <div className="flex flex-wrap gap-2">
        {(
          [
            { decision: "create_account", label: "Create an account", pending: "Recording…" },
            { decision: "cancel", label: "Cancel this run", pending: "Cancelling…" },
          ] as const
        ).map((choice) => (
          // Both forms share one action state, so the recorded outcome is
          // reported once no matter which answer the operator gives.
          <form key={choice.decision} action={decisionAction}>
            <input type="hidden" name="run_id" value={runId} />
            <input type="hidden" name="profile_digest" value={profileDigest} />
            <input type="hidden" name="decision" value={choice.decision} />
            <FormSubmitButton label={choice.label} pendingLabel={choice.pending} />
          </form>
        ))}
      </div>
      <p className="font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
        Profile digest · {profileDigest.slice(0, 12)}
      </p>
      <ActionMessage message={decisionState.message} tone={decisionState.tone} />
    </div>
  )
}

/**
 * Decision surface 2 of 2: the CAPTCHA prompt (Requirements 18.4, 18.6).
 *
 * A human-only challenge is on screen. The operator solves it in the live browser
 * and hands the same session back, or cancels the run. Both buttons appear only
 * when the backend projects the matching capability.
 */
export function CaptchaResumeForm({
  runId,
  canResume,
  canCancel,
  withheldReason = null,
  onResumeSubmit,
}: {
  runId: string
  canResume: boolean
  canCancel: boolean
  // The backend's closed reason code for an absent resume control, rendered in
  // place of the button so a paused page always says why.
  withheldReason?: string | null
  // Interactive sessions hand remote control back before the resume request, so
  // the caller can drop its noVNC connection first.
  onResumeSubmit?: () => void
}) {
  const [controlState, controlAction] = useActionState(runOnboardingControlAction, initialControl)

  return (
    <div className="space-y-3" data-testid="captcha-prompt">
      <p className="flex items-center gap-1.5 data-label">
        <ShieldQuestion className="size-3 text-brand-600" aria-hidden="true" />
        Human verification required
      </p>
      <p className="text-[12px] leading-4 text-muted-foreground">
        The provider is showing a challenge only a person may complete. Solve it in the live browser
        above, then hand the same session back to the agent. Nothing you type there is read by the
        agent or stored on the run.
      </p>
      <div className="flex flex-wrap gap-2">
        {canResume ? (
          <form action={controlAction} onSubmit={onResumeSubmit}>
            <input type="hidden" name="run_id" value={runId} />
            <input type="hidden" name="control" value="resume" />
            <FormSubmitButton label="I solved it, continue" pendingLabel="Resuming…" />
          </form>
        ) : (
          <p
            className="text-[12px] leading-4 text-muted-foreground"
            data-testid="resume-withheld-reason"
          >
            Handing this session back is withheld · {humanize(withheldReason)}
          </p>
        )}
        {canCancel ? (
          <form action={controlAction}>
            <input type="hidden" name="run_id" value={runId} />
            <input type="hidden" name="control" value="cancel" />
            <FormSubmitButton label="Cancel this run" pendingLabel="Cancelling…" />
          </form>
        ) : null}
      </div>
      <ActionMessage message={controlState.message} tone={controlState.tone} />
    </div>
  )
}

export function BrowserLoginForm({ runId }: { runId: string }) {
  const [loginState, loginAction] = useActionState(submitBrowserLoginAction, initialLogin)

  return (
    <form
      action={loginAction}
      onSubmit={(event) => {
        // The values are consumed by the provider's transient secret boundary.
        // Clear them from the DOM as soon as the server action owns the submission.
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
      <p className="flex items-center gap-1.5 data-label">
        <LogIn className="size-3 text-brand-600" aria-hidden="true" />
        Continue with account credentials
      </p>
      <p className="text-[12px] leading-4 text-muted-foreground">
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
      <FormSubmitButton label="Sign in and continue" pendingLabel="Signing in…" />
      {loginState.message ? (
        <p
          className={loginState.tone === "error" ? "text-xs text-destructive" : "text-xs text-emerald-700 dark:text-emerald-300"}
          role={loginState.tone === "error" ? "alert" : "status"}
        >
          {loginState.message}
        </p>
      ) : null}
    </form>
  )
}

export function BrowserVerificationForm({ runId }: { runId: string }) {
  const [method, setMethod] = useState<"code" | "url">("code")
  const [verificationState, verificationAction] = useActionState(
    submitBrowserVerificationAction,
    initialVerification,
  )

  return (
    <form
      action={verificationAction}
      onSubmit={(event) => {
        // React captures FormData before the action dispatch. Remove the
        // one-time value from the DOM immediately after that handoff.
        const form = event.currentTarget
        queueMicrotask(() => {
          for (const name of ["verification_code", "verification_url"]) {
            const field = form.elements.namedItem(name)
            if (field instanceof HTMLInputElement) field.value = ""
          }
        })
      }}
      className="space-y-3 border-t border-border pt-4"
    >
      <input type="hidden" name="run_id" value={runId} />
      <div>
        <p className="flex items-center gap-1.5 data-label">
          <MailCheck className="size-3 text-brand-600" aria-hidden="true" />
          Manual email verification fallback
        </p>
        <p className="mt-1 text-[12px] leading-4 text-muted-foreground">
          Gmail checking remains primary. Use this only when the automatic inbox path cannot
          resolve the provider message; the value is consumed once and is not retained.
        </p>
      </div>
      <fieldset className="flex flex-wrap gap-4">
        <legend className="sr-only">Verification value type</legend>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="radio"
            name="verification_method"
            value="code"
            checked={method === "code"}
            onChange={() => setMethod("code")}
          />
          One-time code
        </label>
        <label className="flex items-center gap-2 text-xs">
          <input
            type="radio"
            name="verification_method"
            value="url"
            checked={method === "url"}
            onChange={() => setMethod("url")}
          />
          Magic link
        </label>
      </fieldset>
      {method === "code" ? (
        <input
          name="verification_code"
          required
          minLength={4}
          maxLength={10}
          placeholder="Verification code"
          autoComplete="one-time-code"
          spellCheck={false}
          className={`${FIELD_CLASS} max-w-sm font-mono`}
          aria-label="Verification code"
        />
      ) : (
        <input
          name="verification_url"
          type="url"
          required
          maxLength={2_048}
          placeholder="https://provider.example/verify/…"
          autoComplete="off"
          spellCheck={false}
          className={FIELD_CLASS}
          aria-label="Verification magic link"
        />
      )}
      <FormSubmitButton
        label="Submit verification once"
        pendingLabel="Submitting verification…"
      />
      {verificationState.message ? (
        <p
          className={
            verificationState.tone === "error"
              ? "text-xs text-destructive"
              : "text-xs text-emerald-700 dark:text-emerald-300"
          }
          role={verificationState.tone === "error" ? "alert" : "status"}
        >
          {verificationState.message}
        </p>
      ) : null}
    </form>
  )
}

export function CredentialSubmitForm({
  runId,
  fieldName,
  fieldLabel,
}: {
  runId: string
  fieldName: string
  fieldLabel: string
}) {
  const [submitState, submitFormAction] = useActionState(submitCredentialAction, initialSubmit)

  return (
    <form
      action={submitFormAction}
      onSubmit={(event) => {
        // The vault consumes the token directly; clear its DOM value immediately.
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
      <p className="text-[12px] leading-4 text-muted-foreground">
        The value is written straight to the encrypted vault. Only a vault:// reference is stored;
        the raw token never enters run state, logs, or this page.
      </p>
      <FormSubmitButton label="Submit credential securely" pendingLabel="Submitting…" />
      {submitState.message ? (
        <p
          className={submitState.tone === "error" ? "text-xs text-destructive" : "text-xs text-emerald-700 dark:text-emerald-300"}
          role={submitState.tone === "error" ? "alert" : "status"}
        >
          {submitState.message}
        </p>
      ) : null}
    </form>
  )
}
