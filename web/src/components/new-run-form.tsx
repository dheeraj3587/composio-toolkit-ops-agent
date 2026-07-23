"use client"

import { useActionState, useEffect, useTransition } from "react"
import { zodResolver } from "@hookform/resolvers/zod"
import { Controller, useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
import { ArrowRight, Check, LockKeyhole, ShieldCheck } from "lucide-react"

import { createRunAction, type CreateRunFormState } from "@/app/runs/new/actions"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Separator } from "@/components/ui/separator"
import { Textarea } from "@/components/ui/textarea"

const vaultReference = /^vault:\/\/[a-z0-9-]+\/[a-z0-9_-]+\/[A-Za-z0-9_-]+$/
const safeUrl = z.url({ protocol: /^https?$/ })

const runFormSchema = z.object({
  app_name: z.string().trim().min(2, "Enter an application name.").max(120),
  requested_scope_policy: z.enum(["minimum", "recommended", "maximum"]),
  execution_mode: z.enum(["plan_only", "execute_when_configured"]),
  callback_urls: z.string().max(2_000).refine((value) => {
    const urls = value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
    return urls.length <= 10 && urls.every((url) => safeUrl.safeParse(url).success)
  }, "Use one valid HTTP(S) URL per line."),
  outreach_recipient_override: z.union([z.literal(""), z.email().max(320)]),
  legal_name: z.string().trim().min(2, "Enter the legal company name.").max(180),
  website: safeUrl,
  work_email_ref: z.string().regex(vaultReference, "Use an exact vault:// reference."),
  use_case: z.string().trim().min(12, "Describe the authorized workflow in at least 12 characters.").max(2_000),
  expected_volume: z.string().max(180),
})

type RunFormValues = z.input<typeof runFormSchema>

const initialCreateRunState: CreateRunFormState = {
  error: null,
  fields: [],
  idempotencyKey: null,
  requestFingerprint: null,
}

export function NewRunForm({ defaultAppName = "" }: { defaultAppName?: string }) {
  const [state, formAction] = useActionState(createRunAction, initialCreateRunState)
  const [pending, startTransition] = useTransition()
  const {
    register,
    control,
    handleSubmit,
    watch,
    formState: { errors },
  } = useForm<RunFormValues>({
    resolver: zodResolver(runFormSchema),
    mode: "onBlur",
    defaultValues: {
      app_name: defaultAppName,
      requested_scope_policy: "maximum",
      execution_mode: "plan_only",
      callback_urls: "",
      outreach_recipient_override: "",
      legal_name: "",
      website: "",
      work_email_ref: "",
      use_case: "",
      expected_volume: "",
    },
  })
  const executionMode = watch("execution_mode")

  useEffect(() => {
    if (state.error) toast.error("Run not created", { description: state.error })
  }, [state.error])

  const submit = (values: RunFormValues) => {
    // Build the payload from the validated values rather than the DOM event:
    // react-hook-form validates asynchronously, so the submit event's
    // currentTarget is already null by the time this runs.
    const data = new FormData()
    data.set("app_name", values.app_name)
    data.set("requested_scope_policy", values.requested_scope_policy)
    data.set("execution_mode", values.execution_mode)
    data.set("callback_urls", values.callback_urls)
    data.set("outreach_recipient_override", values.outreach_recipient_override)
    data.set("legal_name", values.legal_name)
    data.set("website", values.website)
    data.set("work_email_ref", values.work_email_ref)
    data.set("use_case", values.use_case)
    data.set("expected_volume", values.expected_volume)
    startTransition(() => formAction(data))
  }

  const serverInvalid = new Set(state.fields)
  const invalid = (name: keyof RunFormValues) => Boolean(errors[name]) || serverInvalid.has(name)

  return (
    <form onSubmit={handleSubmit(submit)} noValidate className="panel overflow-hidden rounded-md">
      <div className="flex flex-col gap-4 border-b border-border bg-white px-5 py-5 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <div>
          <p className="eyebrow">OperationsRequest</p>
          <h2 className="mt-1 text-lg font-semibold">Define the operating envelope</h2>
        </div>
        <Badge variant="outline" className="w-fit rounded-md border-violet-300 bg-violet-50 text-violet-800">
          <ShieldCheck aria-hidden="true" /> Backend-gated execution
        </Badge>
      </div>

      <div className="grid gap-8 px-5 py-7 sm:px-6 xl:grid-cols-[1fr_1px_1fr]">
        <fieldset className="space-y-5">
          <legend className="mb-5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            01 · Target and policy
          </legend>
          <Field label="Application name" htmlFor="app_name" error={fieldError(errors.app_name?.message, serverInvalid.has("app_name"))}>
            <Input id="app_name" maxLength={120} placeholder="e.g. HubSpot" aria-invalid={invalid("app_name")} {...register("app_name")} />
          </Field>
          <Field label="Scope policy" htmlFor="requested_scope_policy" hint="The backend still limits scopes to evidence-backed provider requirements.">
            <Controller
              name="requested_scope_policy"
              control={control}
              render={({ field }) => (
                <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger id="requested_scope_policy" className="w-full rounded-md bg-white">
                    <SelectValue placeholder="Choose policy" />
                  </SelectTrigger>
                  <SelectContent className="rounded-md">
                    <SelectItem value="minimum">Minimum — essential scopes</SelectItem>
                    <SelectItem value="recommended">Recommended — balanced</SelectItem>
                    <SelectItem value="maximum">Maximum — evidence-backed breadth</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
          </Field>
          <Field
            label="Execution mode"
            htmlFor="execution_mode"
            hint={executionMode === "plan_only"
              ? "Plan only — no provider side effects are authorized."
              : "Execution remains subject to backend policy, configuration, and human gates."}
          >
            <Controller
              name="execution_mode"
              control={control}
              render={({ field }) => (
                <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                  <SelectTrigger id="execution_mode" className="w-full rounded-md bg-white">
                    <SelectValue placeholder="Choose execution mode" />
                  </SelectTrigger>
                  <SelectContent className="rounded-md">
                    <SelectItem value="plan_only">Plan only</SelectItem>
                    <SelectItem value="execute_when_configured">Execute when configured</SelectItem>
                  </SelectContent>
                </Select>
              )}
            />
          </Field>
          <Field label="OAuth callback URLs" htmlFor="callback_urls" error={fieldError(errors.callback_urls?.message, serverInvalid.has("callback_urls"))} hint="Optional. One HTTP(S) URL per line; token-bearing URLs are rejected by the backend.">
            <Textarea id="callback_urls" rows={4} placeholder="https://integrator.example.com/oauth/callback" aria-invalid={invalid("callback_urls")} {...register("callback_urls")} />
          </Field>
          <Field label="Controlled outreach override" htmlFor="outreach_recipient_override" error={errors.outreach_recipient_override?.message} hint="Optional. Sending remains blocked unless backend policy and provider configuration both permit it.">
            <Input id="outreach_recipient_override" type="email" maxLength={320} placeholder="controlled-inbox@example.com" aria-invalid={invalid("outreach_recipient_override")} {...register("outreach_recipient_override")} />
          </Field>
        </fieldset>

        <Separator orientation="vertical" className="hidden h-full bg-border xl:block" />

        <fieldset className="space-y-5">
          <legend className="mb-5 font-mono text-[10px] font-semibold uppercase tracking-[0.14em] text-muted-foreground">
            02 · Company profile
          </legend>
          <Field label="Legal name" htmlFor="legal_name" error={fieldError(errors.legal_name?.message, serverInvalid.has("legal_name"))}>
            <Input id="legal_name" maxLength={180} placeholder="Example Labs, Inc." aria-invalid={invalid("legal_name")} {...register("legal_name")} />
          </Field>
          <Field label="Company website" htmlFor="website" error={fieldError(errors.website?.message, serverInvalid.has("website"))}>
            <Input id="website" type="url" placeholder="https://example.com" aria-invalid={invalid("website")} {...register("website")} />
          </Field>
          <Field label="Work email profile reference" htmlFor="work_email_ref" error={fieldError(errors.work_email_ref?.message, serverInvalid.has("work_email_ref"))} hint="An opaque profile reference only. Never enter a password, token, key, cookie, or client secret.">
            <div className="relative">
              <LockKeyhole className="pointer-events-none absolute left-3 top-2.5 size-4 text-violet-500" aria-hidden="true" />
              <Input id="work_email_ref" className="pl-10 font-mono text-xs" placeholder="vault://company/work_email/profile_1" aria-invalid={invalid("work_email_ref")} autoComplete="off" spellCheck={false} {...register("work_email_ref")} />
            </div>
          </Field>
          <Field label="Integration use case" htmlFor="use_case" error={fieldError(errors.use_case?.message, serverInvalid.has("use_case"))}>
            <Textarea id="use_case" rows={5} maxLength={2000} placeholder="Describe the customer-authorized workflow and why provider access is needed." aria-invalid={invalid("use_case")} {...register("use_case")} />
          </Field>
          <Field label="Expected volume" htmlFor="expected_volume" error={errors.expected_volume?.message} hint="Optional; use an honest range rather than an invented forecast.">
            <Input id="expected_volume" maxLength={180} placeholder="e.g. 1,000 authorized requests / month" aria-invalid={invalid("expected_volume")} {...register("expected_volume")} />
          </Field>
        </fieldset>
      </div>

      <div className="border-t border-border bg-muted/30 px-5 py-5 sm:px-6">
        {state.error ? (
          <Alert variant="destructive" className="mb-5 rounded-md" aria-live="polite">
            <AlertTitle>Run not created</AlertTitle>
            <AlertDescription>{state.error}</AlertDescription>
          </Alert>
        ) : null}
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <p className="flex max-w-2xl items-start gap-2 text-xs leading-5 text-muted-foreground">
            <Check className="mt-0.5 size-3.5 shrink-0 text-emerald-600" aria-hidden="true" />
            {executionMode === "plan_only"
              ? "Plan-only mode keeps external actions disabled."
              : "Execution can proceed only when backend policy and provider configuration permit each action."}
          </p>
          <Button type="submit" size="lg" disabled={pending} className="h-10 rounded-md px-5">
            {pending ? "Creating run…" : "Create operations run"}
            <ArrowRight aria-hidden="true" />
          </Button>
        </div>
      </div>
    </form>
  )
}

function fieldError(message: string | undefined, serverInvalid: boolean): string | undefined {
  return message ?? (serverInvalid ? "The backend rejected this field." : undefined)
}

function Field({
  label,
  htmlFor,
  hint,
  error,
  children,
}: {
  label: string
  htmlFor: string
  hint?: string
  error?: string
  children: React.ReactNode
}) {
  const messageId = `${htmlFor}-message`
  return (
    <div className="space-y-2">
      <label htmlFor={htmlFor} className="flex items-center justify-between gap-3 text-sm font-medium">
        {label}
        {error ? <span className="font-mono text-[9px] uppercase text-destructive">Review</span> : null}
      </label>
      {children}
      <p id={messageId} className={error ? "text-xs leading-5 text-destructive" : "text-xs leading-5 text-muted-foreground"}>
        {error ?? hint ?? "\u00a0"}
      </p>
    </div>
  )
}
