"use client"

import { useActionState, useEffect, useRef, useTransition } from "react"
import { zodResolver } from "@hookform/resolvers/zod"
import { Controller, useForm } from "react-hook-form"
import { z } from "zod"
import { ArrowRight, Check, ChevronDown, KeyRound, LockKeyhole, MailCheck, UserPlus } from "lucide-react"

import { createRunAction, type CreateRunFormState } from "@/app/runs/new/actions"
import { AppNameField } from "@/components/app-name-field"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { BrowserEngineField, browserProviderIsSelectable } from "@/components/browser-engine-field"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import { useAppCapabilities, useAppCatalog } from "@/lib/app-catalog"
import type { BrowserProvider, ProviderStatus } from "@/lib/types"

const safeUrl = z.url({ protocol: /^https$/ })

const runFormSchema = z
  .object({
    app_name: z.string().trim().min(2, "Choose an application.").max(120),
    account_mode: z.enum(["existing_account", "create_account"]),
    legal_name: z.string().trim().min(2, "Enter the company name.").max(180),
    website: safeUrl,
    use_case: z.string().trim().min(12, "Tell us briefly how this integration will be used.").max(2_000),
    expected_volume: z.string().max(180),
    app_login_email: z.string().max(320),
    app_login_password: z.string().max(512),
    requested_scope_policy: z.enum(["minimum", "recommended", "maximum"]),
    execution_mode: z.enum(["plan_only", "execute_when_configured"]),
    browser_provider: z.enum(["playwright", "browser_use"], { error: "Choose an available browser." }),
    credential_creation_policy: z.enum(["reuse_only", "create_if_missing"]),
    callback_urls: z.string().max(2_000).refine((value) => {
      const urls = value.split(/[\n,]/).map((item) => item.trim()).filter(Boolean)
      return urls.length <= 10 && urls.every((url) => safeUrl.safeParse(url).success)
    }, "Use one valid HTTPS URL per line."),
  })
  .superRefine((values, context) => {
    if (
      values.account_mode === "existing_account" &&
      Boolean(values.app_login_email) !== Boolean(values.app_login_password)
    ) {
      context.addIssue({
        code: "custom",
        path: ["app_login_password"],
        message: "Enter both the account email and password, or leave both empty.",
      })
    }
  })

type RunFormValues = z.input<typeof runFormSchema>

const initialCreateRunState: CreateRunFormState = {
  error: null,
  fields: [],
  idempotencyKey: null,
  requestFingerprint: null,
}

const advancedFieldNames = [
  "browser_provider",
  "requested_scope_policy",
  "credential_creation_policy",
  "execution_mode",
  "callback_urls",
] as const satisfies readonly (keyof RunFormValues)[]

export function NewRunForm({
  defaultAppName = "",
  providerStates,
}: {
  defaultAppName?: string
  providerStates: ProviderStatus[]
}) {
  const defaultProvider: BrowserProvider | undefined = browserProviderIsSelectable(providerStates, "playwright")
    ? "playwright"
    : browserProviderIsSelectable(providerStates, "browser_use")
      ? "browser_use"
      : undefined
  const [state, formAction] = useActionState(createRunAction, initialCreateRunState)
  const [pending, startTransition] = useTransition()
  const advancedDetailsRef = useRef<HTMLDetailsElement>(null)
  const {
    register,
    control,
    handleSubmit,
    watch,
    resetField,
    setError,
    setValue,
    formState: { errors },
  } = useForm<RunFormValues>({
    resolver: zodResolver(runFormSchema),
    mode: "onBlur",
    defaultValues: {
      app_name: defaultAppName,
      account_mode: "existing_account",
      legal_name: "",
      website: "",
      use_case: "",
      expected_volume: "",
      app_login_email: "",
      app_login_password: "",
      requested_scope_policy: "recommended",
      execution_mode: "execute_when_configured",
      browser_provider: defaultProvider,
      credential_creation_policy: "create_if_missing",
      callback_urls: "",
    },
  })
  const serverInvalid = new Set(state.fields)
  const invalid = (name: keyof RunFormValues) => Boolean(errors[name]) || serverInvalid.has(name)
  const firstAdvancedError = advancedFieldNames.find((name) => invalid(name))
  // eslint-disable-next-line react-hooks/incompatible-library
  const accountMode = watch("account_mode")
  const executionMode = watch("execution_mode")
  const browserProvider = watch("browser_provider")
  const appName = watch("app_name")
  const catalog = useAppCatalog()
  const selectedApp = catalog.data?.items.find((app) => app.app_name === appName)
  const appCapabilities = useAppCapabilities(selectedApp?.app_slug)
  const gmail = gmailSignupReadiness(providerStates)
  const createAccountUnavailable = accountCreationUnavailableReason({
    appName,
    selectedAppName: selectedApp?.app_name,
    capabilitiesPending: Boolean(selectedApp) && appCapabilities.isPending,
    capabilitiesUnavailable: Boolean(selectedApp) && appCapabilities.isError,
    accountCreationSupported: appCapabilities.data?.account_creation_supported ?? false,
    gmail,
  })

  useEffect(() => {
    if (accountMode === "create_account") {
      resetField("app_login_email")
      resetField("app_login_password")
    }
  }, [accountMode, resetField])

  useEffect(() => {
    if (accountMode === "create_account" && createAccountUnavailable) {
      setValue("account_mode", "existing_account", { shouldDirty: true, shouldValidate: true })
    }
  }, [accountMode, createAccountUnavailable, setValue])

  useEffect(() => {
    if (!firstAdvancedError) return
    const details = advancedDetailsRef.current
    if (details) details.open = true
    queueMicrotask(() => document.getElementById(firstAdvancedError)?.focus())
  }, [firstAdvancedError])

  const submit = (values: RunFormValues) => {
    if (!selectedApp) {
      setError("app_name", { type: "validate", message: "Choose an application from the reviewed catalog." })
      return
    }
    const data = new FormData()
    for (const [key, value] of Object.entries(values)) {
      if (key === "app_login_password") continue
      data.set(key, String(value ?? ""))
    }
    // Preserve password whitespace exactly; it is never trimmed client-side.
    data.set("app_login_password", values.app_login_password)
    startTransition(() => formAction(data))
    // FormData owns an independent copy at this point. Remove the raw password
    // from React Hook Form and the DOM even when the server rejects the request.
    queueMicrotask(() => resetField("app_login_password", { defaultValue: "" }))
  }

  return (
    <form onSubmit={handleSubmit(submit)} noValidate className="space-y-5">
      <div className="panel overflow-hidden">
        <section aria-labelledby="target-account-heading">
          <div className="border-b border-border px-5 py-5 sm:px-7">
            <p className="eyebrow">01 · Target and account</p>
            <h2 id="target-account-heading" className="mt-1 text-xl font-medium">Choose where the run starts</h2>
            <p className="mt-2 text-sm text-muted-foreground">Select a reviewed app and the account path to use.</p>
          </div>

          <div className="grid gap-7 px-5 py-6 sm:px-7 xl:grid-cols-[0.8fr_1.2fr]">
            <Field label="Application" htmlFor="app_name" error={fieldError(errors.app_name?.message, serverInvalid.has("app_name"))}>
              {(a11y) => (
                <AppNameField
                  control={control}
                  invalid={invalid("app_name")}
                  describedBy={a11y["aria-describedby"]}
                  errorMessage={a11y["aria-errormessage"]}
                  required={a11y["aria-required"]}
                />
              )}
            </Field>

            <fieldset className="space-y-2" aria-required="true">
              <legend className="text-sm font-medium">Account setup</legend>
              <Controller
                name="account_mode"
                control={control}
                render={({ field }) => (
                  <div className="grid gap-2 sm:grid-cols-2">
                    <AccountChoice
                      name={field.name}
                      value="existing_account"
                      selected={field.value === "existing_account"}
                      onSelect={() => field.onChange("existing_account")}
                      onBlur={field.onBlur}
                      icon={KeyRound}
                      title="I have an account"
                      description="Use a reviewed connection or sign-in route."
                    />
                    <AccountChoice
                      name={field.name}
                      value="create_account"
                      selected={field.value === "create_account"}
                      onSelect={() => field.onChange("create_account")}
                      onBlur={field.onBlur}
                      disabled={Boolean(createAccountUnavailable)}
                      describedBy="account-creation-readiness"
                      icon={UserPlus}
                      title="Create a new account"
                      description={createAccountUnavailable ? "Requires a reviewed signup route and ready inbox." : "Sign up and verify the work email in one session."}
                    />
                  </div>
                )}
              />
              <p
                id="account-creation-readiness"
                className={`text-xs leading-5 ${createAccountUnavailable ? "text-amber-300" : "text-emerald-300"}`}
                aria-live="polite"
              >
                {createAccountUnavailable ?? "Verified signup route and connected work inbox are ready."}
              </p>
            </fieldset>
          </div>

          {accountMode === "existing_account" ? (
            <div className="border-t border-border bg-field/45 px-5 py-5 sm:px-7">
              <div className="mb-4 flex items-start gap-2.5">
                <LockKeyhole className="mt-0.5 size-4 shrink-0 text-brand-300" aria-hidden="true" />
                <div>
                  <h3 className="text-sm font-medium">Existing account sign-in</h3>
                  <p className="mt-1 text-xs leading-5 text-muted-foreground">
                    Leave both fields empty for OAuth. For browser sign-in, provide both values; they are used once.
                  </p>
                </div>
              </div>
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="Account email or username" optional htmlFor="app_login_email" error={fieldError(errors.app_login_email?.message, serverInvalid.has("app_login_email"))}>
                  {(a11y) => (
                    <Input id="app_login_email" autoComplete="off" spellCheck={false} placeholder="you@company.com" aria-invalid={invalid("app_login_email")} {...a11y} {...register("app_login_email")} />
                  )}
                </Field>
                <Field label="Account password" optional htmlFor="app_login_password" error={fieldError(errors.app_login_password?.message, serverInvalid.has("app_login_password"))}>
                  {(a11y) => (
                    <Input id="app_login_password" type="password" autoComplete="off" spellCheck={false} placeholder="Used once for sign-in" aria-invalid={invalid("app_login_password")} {...a11y} {...register("app_login_password")} />
                  )}
                </Field>
              </div>
            </div>
          ) : (
            <div className="flex gap-3 border-t border-emerald-400/20 bg-emerald-400/[0.06] px-5 py-5 sm:px-7">
              <MailCheck className="mt-0.5 size-4 shrink-0 text-emerald-300" aria-hidden="true" />
              <div>
                <h3 className="text-sm font-medium text-emerald-950">Connected signup inbox ready</h3>
                <p className="mt-1 text-xs leading-5 text-emerald-800">
                  CAPTCHA, MFA, billing, or legal consent pauses the run for your input.
                </p>
              </div>
            </div>
          )}
        </section>

        <section className="border-t border-border" aria-labelledby="company-heading">
          <div className="border-b border-border px-5 py-5 sm:px-7">
            <p className="eyebrow">02 · Company details</p>
            <h2 id="company-heading" className="mt-1 text-xl font-medium">Provide operating context</h2>
            <p className="mt-2 text-sm text-muted-foreground">Used only for approved signup and onboarding fields.</p>
          </div>
          <div className="grid gap-5 px-5 py-6 sm:grid-cols-2 sm:px-7">
            <Field label="Company name" htmlFor="legal_name" error={fieldError(errors.legal_name?.message, serverInvalid.has("legal_name"))}>
              {(a11y) => <Input id="legal_name" maxLength={180} placeholder="Example Labs Ltd." aria-invalid={invalid("legal_name")} {...a11y} {...register("legal_name")} />}
            </Field>
            <Field label="Company website" htmlFor="website" error={fieldError(errors.website?.message, serverInvalid.has("website"))}>
              {(a11y) => <Input id="website" type="url" placeholder="https://example.com" aria-invalid={invalid("website")} {...a11y} {...register("website")} />}
            </Field>
            <div className="sm:col-span-2">
              <Field label="What will this integration do?" htmlFor="use_case" error={fieldError(errors.use_case?.message, serverInvalid.has("use_case"))}>
                {(a11y) => (
                  <Textarea id="use_case" rows={4} maxLength={2_000} placeholder="For example: sync authorized support tickets into our internal workspace." aria-invalid={invalid("use_case")} {...a11y} {...register("use_case")} />
                )}
              </Field>
            </div>
            <Field label="Expected monthly usage" optional htmlFor="expected_volume" error={errors.expected_volume?.message}>
              {(a11y) => <Input id="expected_volume" maxLength={180} placeholder="About 1,000 requests per month" aria-invalid={invalid("expected_volume")} {...a11y} {...register("expected_volume")} />}
            </Field>
          </div>
        </section>

        <details ref={advancedDetailsRef} className="group border-t border-border">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-5 transition-colors hover:bg-secondary/45 sm:px-7">
            <div>
              <p className="eyebrow">03 · Advanced</p>
              <h2 className="mt-1 text-base font-medium">Advanced settings</h2>
              <p className="mt-1 text-xs text-muted-foreground">Browser engine, access policy, credentials, callbacks, and run mode.</p>
              {firstAdvancedError ? <p className="mt-2 text-xs font-medium text-destructive" role="alert">Review the highlighted advanced setting.</p> : null}
            </div>
            <ChevronDown className="size-4 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden="true" />
          </summary>
          <div className="grid gap-6 border-t border-border bg-field/30 px-5 py-6 sm:px-7 xl:grid-cols-2">
            <div className="xl:col-span-2">
              <BrowserEngineField control={control} providerStates={providerStates} error={errors.browser_provider} serverInvalid={serverInvalid.has("browser_provider")} />
            </div>
            <Field label="Access level" htmlFor="requested_scope_policy" error={fieldError(errors.requested_scope_policy?.message, serverInvalid.has("requested_scope_policy"))}>
              {(a11y) => (
                <Controller
                  name="requested_scope_policy"
                  control={control}
                  render={({ field }) => (
                    <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                      <SelectTrigger id="requested_scope_policy" className="w-full" aria-invalid={invalid("requested_scope_policy")} {...a11y}><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="minimum">Minimum — essentials only</SelectItem>
                        <SelectItem value="recommended">Recommended — balanced</SelectItem>
                        <SelectItem value="maximum">Maximum — all approved scopes</SelectItem>
                      </SelectContent>
                    </Select>
                  )}
                />
              )}
            </Field>
            <Field label="Credential handling" htmlFor="credential_creation_policy" error={fieldError(errors.credential_creation_policy?.message, serverInvalid.has("credential_creation_policy"))}>
              {(a11y) => (
                <Controller
                  name="credential_creation_policy"
                  control={control}
                  render={({ field }) => (
                    <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                      <SelectTrigger id="credential_creation_policy" className="w-full" aria-invalid={invalid("credential_creation_policy")} {...a11y}><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="create_if_missing">Use existing, or create if missing</SelectItem>
                        <SelectItem value="reuse_only">Only use an existing credential</SelectItem>
                      </SelectContent>
                    </Select>
                  )}
                />
              )}
            </Field>
            <Field
              label="Run mode"
              htmlFor="execution_mode"
              hint={executionMode === "plan_only" ? "Creates a plan without opening websites." : "Runs approved live browser and provider actions."}
              error={fieldError(errors.execution_mode?.message, serverInvalid.has("execution_mode"))}
            >
              {(a11y) => (
                <Controller
                  name="execution_mode"
                  control={control}
                  render={({ field }) => (
                    <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                      <SelectTrigger id="execution_mode" className="w-full" aria-invalid={invalid("execution_mode")} {...a11y}><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="execute_when_configured">Run the agent</SelectItem>
                        <SelectItem value="plan_only">Plan only</SelectItem>
                      </SelectContent>
                    </Select>
                  )}
                />
              )}
            </Field>
            <Field label="OAuth callback URLs" optional htmlFor="callback_urls" error={fieldError(errors.callback_urls?.message, serverInvalid.has("callback_urls"))} hint="One HTTPS URL per line.">
              {(a11y) => <Textarea id="callback_urls" rows={3} placeholder="https://app.example.com/oauth/callback" aria-invalid={invalid("callback_urls")} {...a11y} {...register("callback_urls")} />}
            </Field>
          </div>
        </details>
      </div>

      {state.error ? (
        <Alert variant="destructive" aria-live="polite">
          <AlertTitle>Run not created</AlertTitle>
          <AlertDescription>{state.error}</AlertDescription>
        </Alert>
      ) : null}

      <div className="panel flex flex-col gap-4 p-4 sm:flex-row sm:items-center sm:justify-between">
        <div className="max-w-2xl space-y-2">
          <p className="flex items-start gap-2 text-xs leading-5 text-muted-foreground">
            <Check className="mt-0.5 size-4 shrink-0 text-emerald-400" aria-hidden="true" />
            The app-specific vault destination is created automatically. You never need to enter a vault address.
          </p>
          <p className="text-xs leading-5">
            <span className="font-medium text-foreground">
              {browserProvider === "browser_use"
                ? "Managed cloud · Browser Use"
                : browserProvider === "playwright"
                  ? "Self-hosted · Playwright"
                  : "Browser runtime not selected"}
            </span>
            <span className="text-muted-foreground">
              {executionMode === "plan_only"
                ? " Plan-only mode will not start a browser. Any supplied sign-in values still travel through the server request and are never displayed in this workspace."
                : browserProvider === "browser_use"
                  ? " Browser Use will host this browser session and receive any one-time sign-in values used by the run."
                  : browserProvider === "playwright"
                    ? " The self-hosted Playwright runtime will handle this browser session and any one-time sign-in values."
                    : " Open Advanced settings and choose an available runtime before starting."}
            </span>
          </p>
        </div>
        <Button type="submit" size="lg" disabled={pending} className="h-10 px-5">
          {pending ? "Starting agent…" : executionMode === "plan_only" ? "Create plan" : "Start agent"}
          <ArrowRight aria-hidden="true" />
        </Button>
      </div>
    </form>
  )
}

function AccountChoice({
  name,
  value,
  selected,
  onSelect,
  onBlur,
  disabled = false,
  describedBy,
  icon: Icon,
  title,
  description,
}: {
  name: string
  value: "existing_account" | "create_account"
  selected: boolean
  onSelect: () => void
  onBlur: () => void
  disabled?: boolean
  describedBy?: string
  icon: typeof KeyRound
  title: string
  description: string
}) {
  return (
    <label
      className={`relative rounded-lg border p-3.5 text-left transition-colors ${selected ? "border-brand-400/60 bg-brand-50" : "border-border bg-field"} ${disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer hover:border-[#484848]"}`}
    >
      <input type="radio" name={name} value={value} checked={selected} disabled={disabled} required aria-describedby={describedBy} onBlur={onBlur} onChange={onSelect} className="peer sr-only" />
      <span className="flex items-start justify-between gap-3 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-4 peer-focus-visible:outline-ring">
        <Icon className={`size-4 ${selected ? "text-brand-300" : "text-muted-foreground"}`} aria-hidden="true" />
        <span className={`mt-0.5 size-3.5 rounded-full border ${selected ? "border-[4px] border-brand-400" : "border-muted-foreground/40"}`} aria-hidden="true" />
      </span>
      <span className="mt-3 block text-sm font-medium">{title}</span>
      <span className="mt-1 block text-xs leading-5 text-muted-foreground">{description}</span>
    </label>
  )
}

interface GmailSignupReadiness {
  ready: boolean
  detail: string
}

function gmailSignupReadiness(providerStates: ProviderStatus[]): GmailSignupReadiness {
  const state = providerStates.find((candidate) => candidate.provider === "gmail")
  if (!state) return { ready: false, detail: "Signup email readiness could not be verified." }
  if (state.status !== "ready") return { ready: false, detail: state.detail }
  return { ready: true, detail: state.detail }
}

function accountCreationUnavailableReason({
  appName,
  selectedAppName,
  capabilitiesPending,
  capabilitiesUnavailable,
  accountCreationSupported,
  gmail,
}: {
  appName: string
  selectedAppName?: string
  capabilitiesPending: boolean
  capabilitiesUnavailable: boolean
  accountCreationSupported: boolean
  gmail: GmailSignupReadiness
}): string | null {
  if (!appName.trim()) return "Choose an application to check whether signup is supported."
  if (!selectedAppName) return "Account creation is available only for apps in the verified catalog."
  if (capabilitiesPending) return `Checking the reviewed signup route for ${selectedAppName}…`
  if (capabilitiesUnavailable) return `Signup capability for ${selectedAppName} could not be verified.`
  if (!accountCreationSupported) return `${selectedAppName} does not have a reviewed signup route in this deployment.`
  if (!gmail.ready) return gmail.detail
  return null
}

function fieldError(message: string | undefined, serverInvalid: boolean): string | undefined {
  return message ?? (serverInvalid ? "The server rejected this field." : undefined)
}

function Field({
  label,
  htmlFor,
  optional = false,
  hint,
  error,
  children,
}: {
  label: string
  htmlFor: string
  optional?: boolean
  hint?: string
  error?: string
  children: (a11y: {
    "aria-describedby"?: string
    "aria-errormessage"?: string
    "aria-required": boolean
  }) => React.ReactNode
}) {
  const messageId = `${htmlFor}-message`
  const hasVisibleMessage = Boolean(error || hint)
  const hasDescription = hasVisibleMessage || optional
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-baseline gap-1">
          <label htmlFor={htmlFor} className="text-sm font-medium">{label}</label>
          {optional ? <span className="optional-label" aria-hidden="true">(optional)</span> : null}
        </div>
        {error ? <span className="font-mono text-[9px] uppercase text-destructive">Review</span> : null}
      </div>
      {children({
        "aria-describedby": hasDescription ? messageId : undefined,
        "aria-errormessage": error ? messageId : undefined,
        "aria-required": !optional,
      })}
      {hasDescription ? (
        <p
          id={messageId}
          className={error ? "text-xs leading-5 text-destructive" : hasVisibleMessage ? "text-xs leading-5 text-muted-foreground" : "sr-only"}
          role={error ? "alert" : undefined}
        >
          {optional ? <span className={hasVisibleMessage ? "sr-only" : undefined}>Optional. </span> : null}
          {error ?? hint}
        </p>
      ) : null}
    </div>
  )
}
