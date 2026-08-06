"use client"

import { useActionState, useEffect, useRef, useTransition } from "react"
import { zodResolver } from "@hookform/resolvers/zod"
import { Controller, useForm } from "react-hook-form"
import { toast } from "sonner"
import { z } from "zod"
import {
  ArrowRight,
  Check,
  ChevronDown,
  KeyRound,
  LockKeyhole,
  MailCheck,
  UserPlus,
} from "lucide-react"

import { createRunAction, type CreateRunFormState } from "@/app/runs/new/actions"
import { AppNameField } from "@/components/app-name-field"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { BrowserEngineField, browserProviderIsSelectable } from "@/components/browser-engine-field"
import { ModelPickerField } from "@/components/model-picker-field"
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
    browser_provider: z.enum(["playwright", "browser_use"], {
      error: "Choose an available browser.",
    }),
    credential_creation_policy: z.enum(["reuse_only", "create_if_missing"]),
    // A per-run model pin. Empty means "use the deployment's chain"; the
    // backend is the authority on whether a named model is serviceable.
    decision_model: z.string().max(120),
    decision_effort: z.enum(["", "instant", "low", "medium", "high"]),
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
      decision_model: "",
      decision_effort: "",
      callback_urls: "",
    },
  })
  const serverInvalid = new Set(state.fields)
  const invalid = (name: keyof RunFormValues) => Boolean(errors[name]) || serverInvalid.has(name)
  const firstAdvancedError = advancedFieldNames.find((name) => invalid(name))
  // eslint-disable-next-line react-hooks/incompatible-library
  const accountMode = watch("account_mode")
  const executionMode = watch("execution_mode")
  const appName = watch("app_name")
  const decisionEffort = watch("decision_effort")
  const catalog = useAppCatalog()
  const selectedApp = catalog.data?.items.find((app) => app.app_name === appName)
  const appCapabilities = useAppCapabilities(selectedApp?.app_slug)
  const gmail = gmailSignupReadiness(providerStates)
  const createAccountUnavailable = accountCreationUnavailableReason({
    appName,
    selectedAppName: selectedApp?.app_name,
    capabilitiesPending: Boolean(selectedApp) && appCapabilities.isPending,
    capabilitiesUnavailable: Boolean(selectedApp) && appCapabilities.isError,
    accountCreationSupported:
      appCapabilities.data?.account_creation_supported ?? false,
    gmail,
  })
  // Shown only when the toggle is actually usable. A route the agent will
  // research at run time is not a reviewed route, so it says so plainly rather
  // than borrowing the reviewed wording — but that is not a reason to disable
  // the control.
  const signupSource = appCapabilities.data?.signup_source
  const signupResearchCaveat =
    createAccountUnavailable || signupSource !== "runtime_research"
      ? null
      : researchedSignupCaveat(selectedApp?.app_name ?? appName)

  useEffect(() => {
    if (state.error) toast.error("Run not created", { description: state.error })
  }, [state.error])

  useEffect(() => {
    if (accountMode === "create_account") {
      resetField("app_login_email")
      resetField("app_login_password")
    }
  }, [accountMode, resetField])

  useEffect(() => {
    if (accountMode === "create_account" && createAccountUnavailable) {
      setValue("account_mode", "existing_account", {
        shouldDirty: true,
        shouldValidate: true,
      })
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
      setError("app_name", {
        type: "validate",
        message: "Choose an application from the reviewed catalog.",
      })
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
    <form onSubmit={handleSubmit(submit)} noValidate className="space-y-6">
      <section className="panel overflow-hidden rounded-2xl">
        <div className="border-b border-border bg-gradient-to-r from-card to-brand-50/50 px-5 py-5 sm:px-7">
          <p className="eyebrow">Step 1</p>
          <h2 className="mt-1 text-xl font-medium">Choose the app and account</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            Tell the agent where to work and whether it should sign in or create a new account.
          </p>
        </div>

        <div className="grid gap-7 px-5 py-7 sm:px-7 xl:grid-cols-[0.9fr_1.1fr]">
          <Field
            label="Application"
            htmlFor="app_name"
            error={fieldError(errors.app_name?.message, serverInvalid.has("app_name"))}
          >
            {(a11y) => (
              <AppNameField
                control={control}
                invalid={invalid("app_name")}
                describedBy={a11y["aria-describedby"]}
                errorMessage={a11y["aria-errormessage"]}
              />
            )}
          </Field>

          <fieldset className="space-y-2">
            <legend className="text-sm font-medium">Account setup</legend>
            <Controller
              name="account_mode"
              control={control}
              render={({ field }) => (
                <div className="grid gap-3 sm:grid-cols-2">
                  <AccountChoice
                    name={field.name}
                    value="existing_account"
                    selected={field.value === "existing_account"}
                    onSelect={() => field.onChange("existing_account")}
                    onBlur={field.onBlur}
                    icon={KeyRound}
                    title="I have an account"
                    description="Use the app's reviewed connection, sign-in, or owner-submit route."
                  />
                  <AccountChoice
                    name={field.name}
                    value="create_account"
                    selected={field.value === "create_account"}
                    onSelect={() => field.onChange("create_account")}
                    onBlur={field.onBlur}
                    disabled={Boolean(createAccountUnavailable)}
                    describedBy={
                      signupResearchCaveat
                        ? "account-creation-readiness account-creation-research-caveat"
                        : "account-creation-readiness"
                    }
                    icon={UserPlus}
                    title="Create a new account"
                    description={
                      createAccountUnavailable
                        ? "Available only when a reviewed signup route and connected verification inbox are ready."
                        : "Sign up, verify the work email, and finish setup in the same browser session."
                    }
                  />
                </div>
              )}
            />
            <p
              id="account-creation-readiness"
              className={`text-xs leading-5 ${
                createAccountUnavailable ? "text-amber-800 dark:text-amber-300" : "text-emerald-700 dark:text-emerald-300"
              }`}
              aria-live="polite"
            >
              {createAccountUnavailable ?? "Verified signup route and connected work inbox are ready."}
            </p>
            {signupResearchCaveat ? (
              <p
                id="account-creation-research-caveat"
                className="text-xs leading-5 text-amber-800 dark:text-amber-300"
                aria-live="polite"
              >
                {signupResearchCaveat.detail}{" "}
                {signupResearchCaveat.evidenceUrl ? (
                  <a
                    className="underline underline-offset-2"
                    href={signupResearchCaveat.evidenceUrl}
                    target="_blank"
                    rel="noreferrer noopener"
                  >
                    Open the source page
                  </a>
                ) : null}
              </p>
            ) : null}
          </fieldset>
        </div>

        <div className="border-t border-border bg-card px-5 py-6 sm:px-7">
          <BrowserEngineField
            control={control}
            providerStates={providerStates}
            error={errors.browser_provider}
            serverInvalid={serverInvalid.has("browser_provider")}
          />
          <div className="mt-6 border-t border-border pt-6">
            <Controller
              control={control}
              name="decision_model"
              render={({ field }) => (
                <ModelPickerField
                  value={{
                    modelId: field.value || null,
                    effort: decisionEffort || null,
                  }}
                  onChange={(next) => {
                    field.onChange(next.modelId ?? "")
                    setValue("decision_effort", next.effort ?? "", {
                      shouldDirty: true,
                    })
                  }}
                />
              )}
            />
          </div>
        </div>

        {accountMode === "existing_account" ? (
          <div className="border-t border-border bg-muted/25 px-5 py-6 sm:px-7">
            <div className="mb-4 flex items-start gap-3">
              <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-card text-brand-700 shadow-sm">
                <LockKeyhole className="size-4" aria-hidden="true" />
              </span>
              <div>
                <h3 className="text-sm font-medium">Existing account sign-in</h3>
                <p className="mt-1 text-xs leading-5 text-muted-foreground">
                  Optional for OAuth apps. For browser sign-in, both values are used once and never saved in the run record.
                </p>
              </div>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Account email or username" htmlFor="app_login_email" error={errors.app_login_email?.message}>
                {(a11y) => (
                  <Input
                    id="app_login_email"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="you@company.com"
                    aria-invalid={invalid("app_login_email")}
                    {...a11y}
                    {...register("app_login_email")}
                  />
                )}
              </Field>
              <Field label="Account password" htmlFor="app_login_password" error={errors.app_login_password?.message}>
                {(a11y) => (
                  <Input
                    id="app_login_password"
                    type="password"
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="Used once for sign-in"
                    aria-invalid={invalid("app_login_password")}
                    {...a11y}
                    {...register("app_login_password")}
                  />
                )}
              </Field>
            </div>
          </div>
        ) : (
          <div className="flex gap-3 border-t border-brand-200 bg-brand-50/70 px-5 py-5 text-brand-950 sm:px-7">
            <MailCheck className="mt-0.5 size-5 shrink-0 text-brand-600" aria-hidden="true" />
            <div>
              <h3 className="text-sm font-medium">Connected signup inbox ready</h3>
              <p className="mt-1 text-xs leading-5 text-brand-950/70">
                The agent uses the verified server-side work inbox, waits for the matching verification message,
                and continues in the same browser session. CAPTCHA, MFA, billing, or legal consent will pause for you.
              </p>
            </div>
          </div>
        )}
      </section>

      <section className="panel overflow-hidden rounded-2xl">
        <div className="border-b border-border px-5 py-5 sm:px-7">
          <p className="eyebrow">Step 2</p>
          <h2 className="mt-1 text-xl font-medium">Company details</h2>
          <p className="mt-2 text-sm text-muted-foreground">
            These values help the agent complete approved signup and onboarding fields.
          </p>
        </div>
        <div className="grid gap-5 px-5 py-7 sm:grid-cols-2 sm:px-7">
          <Field label="Company name" htmlFor="legal_name" error={fieldError(errors.legal_name?.message, serverInvalid.has("legal_name"))}>
            {(a11y) => (
              <Input id="legal_name" maxLength={180} placeholder="Example Labs Ltd." aria-invalid={invalid("legal_name")} {...a11y} {...register("legal_name")} />
            )}
          </Field>
          <Field label="Company website" htmlFor="website" error={fieldError(errors.website?.message, serverInvalid.has("website"))}>
            {(a11y) => (
              <Input id="website" type="url" placeholder="https://example.com" aria-invalid={invalid("website")} {...a11y} {...register("website")} />
            )}
          </Field>
          <div className="sm:col-span-2">
            <Field label="What will this integration do?" htmlFor="use_case" error={fieldError(errors.use_case?.message, serverInvalid.has("use_case"))}>
              {(a11y) => (
                <Textarea
                  id="use_case"
                  rows={4}
                  maxLength={2_000}
                  placeholder="For example: sync authorized customer support tickets into our internal workspace."
                  aria-invalid={invalid("use_case")}
                  {...a11y}
                  {...register("use_case")}
                />
              )}
            </Field>
          </div>
          <Field label="Expected monthly usage" htmlFor="expected_volume" error={errors.expected_volume?.message} hint="Optional">
            {(a11y) => (
              <Input id="expected_volume" maxLength={180} placeholder="About 1,000 requests per month" aria-invalid={invalid("expected_volume")} {...a11y} {...register("expected_volume")} />
            )}
          </Field>
        </div>
      </section>

      <details ref={advancedDetailsRef} className="panel group overflow-hidden rounded-2xl">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-5 py-5 sm:px-7">
          <div>
            <p className="eyebrow">Optional</p>
            <h2 className="mt-1 text-base font-medium">Advanced settings</h2>
            <p className="mt-1 text-xs text-muted-foreground">Scope policy, callback URLs, and execution mode.</p>
            {firstAdvancedError ? (
              <p className="mt-2 text-xs font-medium text-destructive" role="alert">
                Review the highlighted advanced setting.
              </p>
            ) : null}
          </div>
          <ChevronDown className="size-5 text-muted-foreground transition-transform group-open:rotate-180" aria-hidden="true" />
        </summary>
        <div className="grid gap-6 border-t border-border px-5 py-7 sm:px-7 xl:grid-cols-2">
          <Field
            label="Access level"
            htmlFor="requested_scope_policy"
            error={fieldError(
              errors.requested_scope_policy?.message,
              serverInvalid.has("requested_scope_policy"),
            )}
          >
            {(a11y) => (
              <Controller
                name="requested_scope_policy"
                control={control}
                render={({ field }) => (
                  <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                    <SelectTrigger
                      id="requested_scope_policy"
                      className="w-full bg-card"
                      aria-invalid={invalid("requested_scope_policy")}
                      {...a11y}
                    >
                      <SelectValue />
                    </SelectTrigger>
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
          <Field
            label="Credential handling"
            htmlFor="credential_creation_policy"
            error={fieldError(
              errors.credential_creation_policy?.message,
              serverInvalid.has("credential_creation_policy"),
            )}
          >
            {(a11y) => (
              <Controller
                name="credential_creation_policy"
                control={control}
                render={({ field }) => (
                  <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                    <SelectTrigger
                      id="credential_creation_policy"
                      className="w-full bg-card"
                      aria-invalid={invalid("credential_creation_policy")}
                      {...a11y}
                    >
                      <SelectValue />
                    </SelectTrigger>
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
            error={fieldError(
              errors.execution_mode?.message,
              serverInvalid.has("execution_mode"),
            )}
          >
            {(a11y) => (
              <Controller
                name="execution_mode"
                control={control}
                render={({ field }) => (
                  <Select name={field.name} value={field.value} onValueChange={field.onChange}>
                    <SelectTrigger
                      id="execution_mode"
                      className="w-full bg-card"
                      aria-invalid={invalid("execution_mode")}
                      {...a11y}
                    >
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="execute_when_configured">Run the agent</SelectItem>
                      <SelectItem value="plan_only">Plan only</SelectItem>
                    </SelectContent>
                  </Select>
                )}
              />
            )}
          </Field>
          <Field label="OAuth callback URLs" htmlFor="callback_urls" error={fieldError(errors.callback_urls?.message, serverInvalid.has("callback_urls"))} hint="Optional · one URL per line">
            {(a11y) => (
              <Textarea id="callback_urls" rows={3} placeholder="https://app.example.com/oauth/callback" aria-invalid={invalid("callback_urls")} {...a11y} {...register("callback_urls")} />
            )}
          </Field>
        </div>
      </details>

      {state.error ? (
        <Alert variant="destructive" className="rounded-xl" aria-live="polite">
          <AlertTitle>Run not created</AlertTitle>
          <AlertDescription>{state.error}</AlertDescription>
        </Alert>
      ) : null}

      <div className="sticky bottom-4 z-20 flex flex-col gap-4 rounded-2xl border border-border bg-card/90 p-4 shadow-[0_20px_60px_rgba(0,0,0,0.28)] backdrop-blur-xl sm:flex-row sm:items-center sm:justify-between">
        <p className="flex max-w-2xl items-start gap-2 text-xs leading-5 text-muted-foreground">
          <Check className="mt-0.5 size-4 shrink-0 text-emerald-600 dark:text-emerald-300" aria-hidden="true" />
          The app-specific vault destination is created automatically. You never need to enter a vault address.
        </p>
        <Button type="submit" size="lg" disabled={pending} className="h-11 rounded-xl px-6">
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
      className={`relative rounded-xl border p-4 text-left transition ${
        selected
          ? "border-brand-500 bg-brand-50 shadow-[0_0_0_1px_var(--color-brand-500)]"
          : "border-border bg-card"
      } ${
        disabled
          ? "cursor-not-allowed opacity-55"
          : "cursor-pointer hover:border-brand-300"
      }`}
    >
      <input
        type="radio"
        name={name}
        value={value}
        checked={selected}
        disabled={disabled}
        aria-describedby={describedBy}
        onBlur={onBlur}
        onChange={onSelect}
        className="peer sr-only"
      />
      <span className="flex items-start justify-between gap-3 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-4 peer-focus-visible:outline-brand-600">
        <span className={`grid size-9 place-items-center rounded-xl ${selected ? "bg-brand-500 text-rail" : "bg-secondary text-muted-foreground"}`}>
          <Icon className="size-4" aria-hidden="true" />
        </span>
        <span
          className={`mt-1 size-4 rounded-full border ${selected ? "border-[5px] border-brand-600" : "border-muted-foreground/40"}`}
          aria-hidden="true"
        />
      </span>
      <span className="mt-4 block text-sm font-medium">{title}</span>
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
  if (!state) {
    return {
      ready: false,
      detail: "Signup email readiness could not be verified.",
    }
  }
  if (state.status !== "ready") {
    return { ready: false, detail: state.detail }
  }
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
  if (!accountCreationSupported) {
    return `${selectedAppName} does not have a reviewed signup route in this deployment.`
  }
  if (!gmail.ready) return gmail.detail
  return null
}

/**
 * The caveat shown when no reviewed signup route exists and the agent will
 * research one from the app's own site at run time. There is nothing to link
 * yet — the route does not exist until the run researches it.
 *
 * The copy says "may not find one" rather than promising a route, because the
 * research is bounded to the app's reviewed navigation hosts and legitimately
 * comes back empty for apps whose registration lives on a host outside them.
 * When it does, the run is refused and nothing is created — so promising the
 * route here left that refusal looking like a malfunction.
 */
function researchedSignupCaveat(appName: string): {
  detail: string
  evidenceUrl: string | null
} {
  return {
    detail: `The signup route for ${appName} has not been reviewed by a human. When you start the run, the agent looks for one on ${appName}'s own reviewed site and shows each page it reads on the run timeline. If it finds no signup form there, the run is refused and nothing is created — a route is never guessed.`,
    evidenceUrl: null,
  }
}

function fieldError(message: string | undefined, serverInvalid: boolean): string | undefined {
  return message ?? (serverInvalid ? "The server rejected this field." : undefined)
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
  children: (a11y: {
    "aria-describedby"?: string
    "aria-errormessage"?: string
  }) => React.ReactNode
}) {
  const messageId = `${htmlFor}-message`
  const hasMessage = Boolean(error || hint)
  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <label htmlFor={htmlFor} className="text-sm font-medium">{label}</label>
        {error ? <span className="font-mono text-[11px] uppercase text-destructive">Review</span> : null}
      </div>
      {children({
        "aria-describedby": hasMessage ? messageId : undefined,
        "aria-errormessage": error ? messageId : undefined,
      })}
      {hasMessage ? (
        <p
          id={messageId}
          className={error ? "text-xs leading-5 text-destructive" : "text-xs leading-5 text-muted-foreground"}
          role={error ? "alert" : undefined}
        >
          {error ?? hint}
        </p>
      ) : null}
    </div>
  )
}
