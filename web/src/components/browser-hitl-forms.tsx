"use client"

import { useActionState, useState } from "react"
import { useFormStatus } from "react-dom"
import { KeyRound, LogIn, MailCheck } from "lucide-react"

import {
  submitBrowserLoginAction,
  submitBrowserVerificationAction,
  submitCredentialAction,
  type BrowserLoginState,
  type BrowserVerificationState,
  type CredentialSubmitState,
} from "@/app/runs/[runId]/actions"
import { Button } from "@/components/ui/button"

const initialSubmit: CredentialSubmitState = { message: null, tone: "neutral", status: null }
const initialLogin: BrowserLoginState = { message: null, tone: "neutral" }
const initialVerification: BrowserVerificationState = { message: null, tone: "neutral" }

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
      <FormSubmitButton label="Sign in and continue" pendingLabel="Signing in…" />
      {loginState.message ? (
        <p
          className={loginState.tone === "error" ? "text-xs text-destructive" : "text-xs text-emerald-700"}
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
        <p className="mt-1 text-[10px] leading-4 text-muted-foreground">
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
              : "text-xs text-emerald-700"
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
      <p className="text-[10px] leading-4 text-muted-foreground">
        The value is written straight to the encrypted vault. Only a vault:// reference is stored;
        the raw token never enters run state, logs, or this page.
      </p>
      <FormSubmitButton label="Submit credential securely" pendingLabel="Submitting…" />
      {submitState.message ? (
        <p
          className={submitState.tone === "error" ? "text-xs text-destructive" : "text-xs text-emerald-700"}
          role={submitState.tone === "error" ? "alert" : "status"}
        >
          {submitState.message}
        </p>
      ) : null}
    </form>
  )
}
