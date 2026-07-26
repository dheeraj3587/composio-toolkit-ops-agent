"use client"

import { useActionState } from "react"
import { useFormStatus } from "react-dom"
import { KeyRound, LogIn } from "lucide-react"

import {
  submitBrowserLoginAction,
  submitCredentialAction,
  type BrowserLoginState,
  type CredentialSubmitState,
} from "@/app/runs/[runId]/actions"
import { Button } from "@/components/ui/button"

const initialSubmit: CredentialSubmitState = { message: null, tone: "neutral", status: null }
const initialLogin: BrowserLoginState = { message: null, tone: "neutral" }

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
