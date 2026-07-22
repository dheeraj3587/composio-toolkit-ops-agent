"use client"

import { useActionState } from "react"
import { useFormStatus } from "react-dom"
import { ArrowRight, LockKeyhole, ShieldCheck } from "lucide-react"

import { createRunAction, type CreateRunFormState } from "@/app/runs/new/actions"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"

const initialCreateRunState: CreateRunFormState = {
  error: null,
  fields: [],
  idempotencyKey: null,
  requestFingerprint: null,
}

function SubmitButton() {
  const { pending } = useFormStatus()
  return (
    <Button
      type="submit"
      size="lg"
      disabled={pending}
      className="h-11 rounded-none bg-rust px-6 text-paper hover:bg-rust/90"
    >
      {pending ? "Writing ledger entry…" : "Create dry run"}
      <ArrowRight aria-hidden="true" />
    </Button>
  )
}

export function NewRunForm() {
  const [state, formAction] = useActionState(createRunAction, initialCreateRunState)
  const invalid = new Set(state.fields)

  return (
    <form action={formAction} className="border border-ink/30 bg-card/55">
      <div className="flex flex-col gap-4 border-b border-ink/20 px-5 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-7">
        <div>
          <p className="eyebrow">Request / OperationsRequest</p>
          <h2 className="mt-2 font-heading text-3xl">Define the operating envelope</h2>
        </div>
        <Badge variant="outline" className="w-fit rounded-none border-viridian/40 bg-viridian/5 text-viridian">
          <ShieldCheck aria-hidden="true" /> Local dry-run only
        </Badge>
      </div>

      <div className="grid gap-8 px-5 py-7 sm:px-7 lg:grid-cols-[1fr_1px_1fr]">
        <fieldset className="space-y-5">
          <legend className="mb-5 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
            01 · Target and policy
          </legend>
          <Field label="Application name" htmlFor="app_name" error={invalid.has("app_name")}>
            <Input id="app_name" name="app_name" required maxLength={120} placeholder="e.g. HubSpot" aria-invalid={invalid.has("app_name")} />
          </Field>
          <Field label="Scope policy" htmlFor="requested_scope_policy">
            <Select name="requested_scope_policy" defaultValue="maximum">
              <SelectTrigger id="requested_scope_policy" className="w-full rounded-none bg-paper/45">
                <SelectValue placeholder="Choose policy" />
              </SelectTrigger>
              <SelectContent className="rounded-none">
                <SelectItem value="minimum">Minimum — essential scopes</SelectItem>
                <SelectItem value="recommended">Recommended — balanced</SelectItem>
                <SelectItem value="maximum">Maximum — broad integration</SelectItem>
              </SelectContent>
            </Select>
          </Field>
          <Field label="OAuth callback URLs" htmlFor="callback_urls" error={invalid.has("callback_urls")} hint="One URL per line. Leave blank when not applicable.">
            <Textarea id="callback_urls" name="callback_urls" rows={4} placeholder="https://integrator.example.com/oauth/callback" aria-invalid={invalid.has("callback_urls")} />
          </Field>
          <Field label="Controlled outreach override" htmlFor="outreach_recipient_override" hint="Optional. Development email remains blocked unless backend policy also permits it.">
            <Input id="outreach_recipient_override" name="outreach_recipient_override" type="email" maxLength={320} placeholder="controlled-inbox@example.com" />
          </Field>
        </fieldset>

        <Separator orientation="vertical" className="hidden h-full bg-ink/20 lg:block" />

        <fieldset className="space-y-5">
          <legend className="mb-5 font-mono text-[10px] uppercase tracking-[0.16em] text-muted-foreground">
            02 · Company profile
          </legend>
          <Field label="Legal name" htmlFor="legal_name" error={invalid.has("legal_name")}>
            <Input id="legal_name" name="legal_name" required maxLength={180} placeholder="Example Labs, Inc." aria-invalid={invalid.has("legal_name")} />
          </Field>
          <Field label="Company website" htmlFor="website" error={invalid.has("website")}>
            <Input id="website" name="website" required type="url" placeholder="https://example.com" aria-invalid={invalid.has("website")} />
          </Field>
          <Field label="Work email vault reference" htmlFor="work_email_ref" error={invalid.has("work_email_ref")} hint="The UI accepts a vault reference, never a raw company email credential.">
            <div className="relative">
              <LockKeyhole className="pointer-events-none absolute left-3 top-2.5 size-4 text-viridian" aria-hidden="true" />
              <Input id="work_email_ref" name="work_email_ref" required className="pl-10 font-mono text-xs" placeholder="vault://company/work_email/profile_1" aria-invalid={invalid.has("work_email_ref")} autoComplete="off" />
            </div>
          </Field>
          <Field label="Integration use case" htmlFor="use_case" error={invalid.has("use_case")}>
            <Textarea id="use_case" name="use_case" required rows={5} maxLength={2000} placeholder="Describe the customer-authorized workflow and why API access is needed." aria-invalid={invalid.has("use_case")} />
          </Field>
          <Field label="Expected volume" htmlFor="expected_volume" hint="Optional; use an honest range rather than an invented forecast.">
            <Input id="expected_volume" name="expected_volume" maxLength={180} placeholder="e.g. 1,000 authorized requests / month" />
          </Field>
        </fieldset>
      </div>

      <div className="border-t border-ink/20 px-5 py-5 sm:px-7">
        {state.error ? (
          <Alert variant="destructive" className="mb-5 rounded-none" aria-live="polite">
            <AlertTitle>Run not created</AlertTitle>
            <AlertDescription>{state.error}</AlertDescription>
          </Alert>
        ) : null}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <p className="max-w-xl text-xs leading-5 text-muted-foreground">
            Submission writes a local backend record. Research, browser, Gmail, and vendor contact remain unavailable until their backend phases report otherwise.
          </p>
          <SubmitButton />
        </div>
      </div>
    </form>
  )
}

function Field({
  label,
  htmlFor,
  hint,
  error = false,
  children,
}: {
  label: string
  htmlFor: string
  hint?: string
  error?: boolean
  children: React.ReactNode
}) {
  return (
    <div className="space-y-2">
      <label htmlFor={htmlFor} className="flex items-center justify-between gap-3 text-sm font-medium">
        {label}
        {error ? <span className="font-mono text-[9px] uppercase text-destructive">Review</span> : null}
      </label>
      {children}
      {hint ? <p className="text-xs leading-5 text-muted-foreground">{hint}</p> : null}
    </div>
  )
}
