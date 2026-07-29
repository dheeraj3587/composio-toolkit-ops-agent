"use client"

import { Controller, type Control, type FieldError, type Path } from "react-hook-form"
import { CloudCog, PanelsTopLeft } from "lucide-react"

import type { BrowserProvider, ProviderStatus } from "@/lib/types"

type BrowserEngineValues = {
  browser_provider: BrowserProvider
}

const selectableProviderStatuses = new Set(["configured", "configured_not_verified", "ready"])

export function browserProviderIsSelectable(
  providerStates: ProviderStatus[],
  provider: BrowserProvider,
): boolean {
  const state = providerStates.find((candidate) => candidate.provider === provider)
  return Boolean(state && selectableProviderStatuses.has(state.status))
}

export function BrowserEngineField<TValues extends BrowserEngineValues>({
  control,
  providerStates,
  error,
  serverInvalid,
}: {
  control: Control<TValues>
  providerStates: ProviderStatus[]
  error?: FieldError
  serverInvalid: boolean
}) {
  const invalid = Boolean(error) || serverInvalid
  const providerState = (provider: BrowserProvider) =>
    providerStates.find((state) => state.provider === provider)

  return (
    <fieldset
      className="space-y-2"
      aria-describedby="browser-provider-message"
      aria-errormessage={invalid ? "browser-provider-message" : undefined}
      aria-invalid={invalid}
    >
      <legend className="flex w-full items-center justify-between gap-3 text-sm font-medium">
        Browser engine
        {invalid ? <span className="font-mono text-[9px] uppercase text-destructive">Review</span> : null}
      </legend>
      <Controller
        name={"browser_provider" as Path<TValues>}
        control={control}
        render={({ field }) => (
          <div className="grid gap-3 sm:grid-cols-2">
            {([
              {
                value: "playwright" as const,
                title: "Playwright",
                eyebrow: "Self-hosted",
                description: "Policy-bounded Chromium with masked screenshot HITL.",
                icon: PanelsTopLeft,
              },
              {
                value: "browser_use" as const,
                title: "Browser Use",
                eyebrow: "Managed cloud",
                description: "Hosted browser agent with an interactive live session.",
                icon: CloudCog,
              },
            ]).map((option) => {
              const state = providerState(option.value)
              const selectable = browserProviderIsSelectable(providerStates, option.value)
              const selected = field.value === option.value
              const Icon = option.icon
              return (
                <label
                  key={option.value}
                  className={`group relative rounded-lg border p-4 outline-none transition-[border-color,box-shadow,background-color] ${
                    selected
                      ? "border-brand-500 bg-brand-50/80 shadow-[0_0_0_1px_var(--color-brand-500)]"
                      : "border-border bg-white"
                  } ${selectable ? "cursor-pointer hover:border-brand-300" : "cursor-not-allowed opacity-60"}`}
                >
                  <input
                    type="radio"
                    name={field.name}
                    value={option.value}
                    checked={selected}
                    disabled={!selectable}
                    onBlur={field.onBlur}
                    onChange={() => field.onChange(option.value)}
                    className="peer sr-only"
                  />
                  <span className="flex items-start justify-between gap-3 peer-focus-visible:outline peer-focus-visible:outline-2 peer-focus-visible:outline-offset-4 peer-focus-visible:outline-brand-600">
                    <span className="grid size-8 place-items-center rounded-md border border-border bg-white text-brand-700">
                      <Icon className="size-4" aria-hidden="true" />
                    </span>
                    <span
                      className={`mt-1 size-3.5 rounded-full border ${selected ? "border-[4px] border-brand-600" : "border-muted-foreground/40"}`}
                      aria-hidden="true"
                    />
                  </span>
                  <span className="mt-4 block font-mono text-[9px] uppercase tracking-[0.13em] text-muted-foreground">
                    {option.eyebrow}
                  </span>
                  <span className="mt-1 block text-sm font-semibold">{option.title}</span>
                  <span className="mt-1 block text-[11px] leading-5 text-muted-foreground">
                    {option.description}
                  </span>
                  {!selectable ? (
                    <span className="mt-3 block border-t border-border pt-3 text-[10px] leading-4 text-amber-800">
                      {state?.detail ?? "Provider readiness could not be confirmed."}
                    </span>
                  ) : null}
                </label>
              )
            })}
          </div>
        )}
      />
      <p
        id="browser-provider-message"
        className={invalid ? "text-xs leading-5 text-destructive" : "text-xs leading-5 text-muted-foreground"}
      >
        {error?.message
          ?? (serverInvalid ? "The backend rejected this field." : undefined)
          ?? "The selected engine is frozen for this run; retries and resumes never switch providers."}
      </p>
    </fieldset>
  )
}
