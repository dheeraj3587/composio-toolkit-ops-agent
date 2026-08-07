"use client"

import { useActionState, useDeferredValue, useMemo, useState, type ReactNode } from "react"
import Link from "next/link"
import { ArrowRight, Boxes, CheckCircle2, Search, ShieldAlert, XCircle } from "lucide-react"

import {
  createRunBatchAction,
  type CreateRunBatchFormState,
} from "@/app/runs/new/actions"
import { StatusBadge } from "@/components/status-badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Textarea } from "@/components/ui/textarea"
import { groupAppsByReadinessTier, matchesAppQuery, useAppCatalog } from "@/lib/app-catalog"
import { humanize } from "@/lib/format"
import type { AppSearchItem, BatchRunResult } from "@/lib/types"

// The batch route's own bound (api/models.py::CreateRunBatchRequest.app_names).
const MAX_BATCH_APPS = 50

const initialBatchState: CreateRunBatchFormState = {
  error: null,
  fields: [],
  batch: null,
  idempotencyKey: null,
  requestFingerprint: null,
}

/**
 * Why one app was refused, in the operator's words.
 *
 * The batch route answers 201 with a per-app outcome, so these are data on a
 * successful response rather than errors. Codes are matched exactly and an
 * unrecognized one falls through to the API's own short `detail`, so a new
 * backend code can never render as a raw token.
 */
const BATCH_REFUSALS: Record<string, string> = {
  app_not_found: "This app is not in the reviewed catalog, so there is no recipe to run against.",
  invalid_request: "The shared settings are not valid for this app.",
  idempotency_conflict:
    "A run for this app was already started from a different request. Reload and check the ledger before retrying.",
  gmail_signup_address_not_configured:
    "Creating an account needs a verified work inbox to receive the confirmation email, and none is configured for this deployment.",
  gmail_signup_preflight_failed:
    "The work inbox did not answer its readiness check. Check the inbox on the system health page and try again.",
  playwright_configuration_required:
    "The self-hosted browser engine is not configured in this deployment, so no browser run can start.",
}

function refusalSentence(result: BatchRunResult): string {
  const known = result.reason_code ? BATCH_REFUSALS[result.reason_code] : null
  if (known) return known
  if (result.detail) return result.detail
  return "The backend refused this app and gave no reason code."
}

/**
 * The verified catalog, browsable without knowing an app's name, and selectable
 * in bulk.
 *
 * This used to be a search box that showed nothing until two characters were
 * typed, so an operator who did not know the exact spelling — or did not know
 * which apps exist at all — had no way in. The full catalog is now listed up
 * front and the input only narrows it, which is filtering rather than guessing.
 *
 * Selection is held here rather than in the checkboxes themselves: the filter
 * unmounts the cards it hides, and a checkbox that unmounts stops posting, so a
 * narrowed filter would silently shrink the batch. Every selected name is posted
 * from a hidden input that lives outside the filtered list.
 */
export function AppSearch() {
  const [query, setQuery] = useState("")
  const deferredQuery = useDeferredValue(query.trim())
  const [selected, setSelected] = useState<string[]>([])
  const [state, formAction, pending] = useActionState(createRunBatchAction, initialBatchState)
  const catalog = useAppCatalog()

  const groups = useMemo(() => {
    const items = catalog.data?.items ?? []
    return groupAppsByReadinessTier(items.filter((app) => matchesAppQuery(app, deferredQuery)))
  }, [catalog.data, deferredQuery])

  const selectedSet = useMemo(() => new Set(selected), [selected])
  const matchCount = groups.reduce((total, [, apps]) => total + apps.length, 0)
  const totalCount = catalog.data?.total ?? 0
  const overLimit = selected.length > MAX_BATCH_APPS
  const invalidField = new Set(state.fields)

  function toggle(appName: string) {
    setSelected((current) =>
      current.includes(appName)
        ? current.filter((name) => name !== appName)
        : [...current, appName],
    )
  }

  function selectGroup(apps: AppSearchItem[]) {
    setSelected((current) => {
      const names = apps.map((app) => app.app_name)
      const everyOneSelected = names.every((name) => current.includes(name))
      return everyOneSelected
        ? current.filter((name) => !names.includes(name))
        : [...current, ...names.filter((name) => !current.includes(name))]
    })
  }

  return (
    <section id="app-catalog" className="panel overflow-hidden" aria-labelledby="app-catalog-title">
      <div className="grid border-b border-border lg:grid-cols-[0.7fr_1.3fr]">
        <div className="border-b border-border p-5 lg:border-b-0 lg:border-r lg:p-6">
          <p className="eyebrow">Verified catalog</p>
          <h2 id="app-catalog-title" className="mt-2 text-xl font-semibold tracking-[-0.02em]">
            Choose apps to onboard
          </h2>
          <p className="mt-2 max-w-md text-sm leading-6 text-muted-foreground">
            These are the apps this deployment knows how to set up. Open one to read what the
            agent found about it, use <span className="font-medium text-foreground">Run</span> to
            start a single integration, or tick several and onboard them together. Every entry is
            a backend record, not a suggestion.
          </p>
        </div>
        <div className="p-5 lg:p-6">
          <label htmlFor="app-search" className="data-label">Filter the catalog</label>
          <div className="relative mt-2">
            <Search
              className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground"
              aria-hidden="true"
            />
            <Input
              id="app-search"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value.slice(0, 120))}
              placeholder="Filter by name, slug, or category — optional"
              className="h-11 rounded-md bg-card pl-10"
              autoComplete="off"
            />
          </div>
          <p className="mt-2 text-xs text-muted-foreground" aria-live="polite">
            {catalog.isPending
              ? "Loading the verified catalog…"
              : catalog.isError
                ? "The catalog could not be loaded."
                : deferredQuery.length > 0
                  ? `${matchCount} of ${totalCount} verified apps match.`
                  : `${totalCount} verified apps available.`}
          </p>
        </div>
      </div>

      <form action={formAction}>
        {/* Posted outside the filtered list on purpose: a selected app that the
            filter has hidden must still be part of the batch. */}
        {selected.map((appName) => (
          <input key={appName} type="hidden" name="app_names" value={appName} />
        ))}

        <div className="min-h-48 p-5 lg:p-6" aria-live="polite">
          {catalog.isPending ? (
            <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-label="Loading app catalog">
              {[0, 1, 2, 3, 4, 5].map((item) => (
                <Skeleton key={item} className="h-32 rounded-md" />
              ))}
            </div>
          ) : catalog.isError ? (
            <CatalogMessage
              icon={ShieldAlert}
              title="Catalog unavailable"
              copy="The backend could not return verified app records. No placeholder results are shown."
            />
          ) : totalCount === 0 ? (
            <CatalogMessage
              icon={Boxes}
              title="No verified apps"
              copy="The verified snapshot returned no records."
            />
          ) : matchCount === 0 ? (
            <CatalogMessage
              icon={Search}
              title="No verified match"
              copy={`No reviewed app matched “${deferredQuery}”. Clear the filter to browse the supported catalog.`}
            />
          ) : (
            <div className="space-y-6">
              {groups.map(([tier, apps]) => (
                <div key={tier}>
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <h3 className="data-label">
                      {tier === "unknown" ? "Readiness not reported" : humanize(tier)} · {apps.length}
                    </h3>
                    <button
                      type="button"
                      onClick={() => selectGroup(apps)}
                      className="rounded-md px-1 text-2xs font-medium text-muted-foreground underline-offset-2 hover:text-foreground hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-500"
                    >
                      {apps.every((app) => selectedSet.has(app.app_name))
                        ? "Deselect group"
                        : "Select group"}
                      <span className="sr-only"> {humanize(tier)}</span>
                    </button>
                  </div>
                  <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                    {apps.map((app) => (
                      <AppCard
                        key={app.app_slug}
                        app={app}
                        selected={selectedSet.has(app.app_name)}
                        onToggle={() => toggle(app.app_name)}
                      />
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <BatchPanel
          selected={selected}
          onClear={() => setSelected([])}
          overLimit={overLimit}
          pending={pending}
          state={state}
          invalidField={invalidField}
        />
      </form>

      {state.batch ? (
        <BatchResults
          results={state.batch.results}
          requested={state.batch.requested}
          created={state.batch.created}
          rejected={state.batch.rejected}
        />
      ) : null}
    </section>
  )
}

/**
 * The shared configuration one batch is created under, plus the submit.
 *
 * These are the fields `CreateRunBatchRequest` requires and nothing more. There
 * is no password and no provider hint here because the batch model accepts
 * neither: one vendor's secret must not be applied to fifty vendors, and a
 * pointer at one provider's docs is meaningless shared across a selection.
 */
function BatchPanel({
  selected,
  onClear,
  overLimit,
  pending,
  state,
  invalidField,
}: {
  selected: string[]
  onClear: () => void
  overLimit: boolean
  pending: boolean
  state: CreateRunBatchFormState
  invalidField: Set<string>
}) {
  const none = selected.length === 0

  return (
    <div className="border-t border-border bg-muted/30 p-5 lg:p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-sm font-semibold" aria-live="polite">
            {none
              ? "No apps selected"
              : `${selected.length} app${selected.length === 1 ? "" : "s"} selected`}
          </p>
          <p className="mt-1 text-xs text-muted-foreground">
            {none
              ? "Tick apps above to start them together under one configuration."
              : selected.slice(0, 6).join(", ") +
                (selected.length > 6 ? ` and ${selected.length - 6} more` : "")}
          </p>
        </div>
        <Button
          type="button"
          variant="ghost"
          size="sm"
          onClick={onClear}
          disabled={none}
          className="rounded-md"
        >
          Clear selection
        </Button>
      </div>

      {overLimit ? (
        <p className="mt-3 text-xs font-medium text-red-700 dark:text-red-300">
          A batch is capped at {MAX_BATCH_APPS} apps. Deselect {selected.length - MAX_BATCH_APPS} to
          continue.
        </p>
      ) : null}

      {/* `open` is set once and never driven from state: React only rewrites the
          attribute when the prop changes, so a state-bound value would reopen
          the panel under the operator every time the selection changed. */}
      <details className="mt-4 rounded-md border border-border bg-card p-4" open>
        <summary className="cursor-pointer text-sm font-medium">
          Shared settings for every selected app
        </summary>
        <div className="mt-4 grid gap-4 sm:grid-cols-2">
          <BatchField label="Company name" htmlFor="batch_legal_name" invalid={invalidField.has("legal_name")}>
            <Input
              id="batch_legal_name"
              name="legal_name"
              maxLength={180}
              placeholder="Example Labs Ltd."
              aria-invalid={invalidField.has("legal_name")}
            />
          </BatchField>
          <BatchField label="Company website" htmlFor="batch_website" invalid={invalidField.has("website")}>
            <Input
              id="batch_website"
              name="website"
              type="url"
              placeholder="https://example.com"
              aria-invalid={invalidField.has("website")}
            />
          </BatchField>
          <div className="sm:col-span-2">
            <BatchField
              label="What will these integrations do?"
              htmlFor="batch_use_case"
              invalid={invalidField.has("use_case")}
            >
              <Textarea
                id="batch_use_case"
                name="use_case"
                rows={2}
                maxLength={2_000}
                placeholder="Sync customer records into our support desk."
                aria-invalid={invalidField.has("use_case")}
              />
            </BatchField>
          </div>
          <BatchField label="Account" htmlFor="batch_account_mode">
            <select
              id="batch_account_mode"
              name="account_mode"
              defaultValue="existing_account"
              className="h-9 w-full rounded-md border border-border bg-card px-2 text-sm"
            >
              <option value="existing_account">I already have accounts</option>
              <option value="create_account">Create accounts for me</option>
            </select>
          </BatchField>
          <BatchField label="Execution" htmlFor="batch_execution_mode">
            <select
              id="batch_execution_mode"
              name="execution_mode"
              defaultValue="execute_when_configured"
              className="h-9 w-full rounded-md border border-border bg-card px-2 text-sm"
            >
              <option value="plan_only">Plan only — no websites are opened</option>
              <option value="execute_when_configured">Run approved live actions</option>
            </select>
          </BatchField>
          <BatchField label="Scopes" htmlFor="batch_scope_policy">
            <select
              id="batch_scope_policy"
              name="requested_scope_policy"
              defaultValue="recommended"
              className="h-9 w-full rounded-md border border-border bg-card px-2 text-sm"
            >
              <option value="minimum">Minimum</option>
              <option value="recommended">Recommended</option>
              <option value="maximum">Maximum</option>
            </select>
          </BatchField>
          <div className="flex items-end">
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                name="onboarding"
                defaultChecked
                className="size-4 rounded border-border accent-brand-500"
              />
              Use the autonomous onboarding driver
            </label>
          </div>
          {/* Frozen, not chosen: the self-hosted engine is the only backend a new
              run may name, and the creation policy is what makes an unattended
              run able to click Create. Posted so the request is explicit. */}
          <input type="hidden" name="browser_provider" value="playwright" />
          <input type="hidden" name="credential_creation_policy" value="create_if_missing" />
        </div>
      </details>

      {state.error ? (
        <p
          role="alert"
          className="mt-4 rounded-md border border-red-300 bg-red-50 p-3 text-xs leading-5 text-red-800 dark:border-red-500/35 dark:bg-red-500/12 dark:text-red-200"
        >
          {state.error}
        </p>
      ) : null}

      <div className="mt-4 flex items-center gap-3">
        <Button type="submit" disabled={none || overLimit || pending} className="rounded-md">
          {pending
            ? "Starting…"
            : none
              ? "Onboard selected"
              : `Onboard ${selected.length} selected`}
          <ArrowRight aria-hidden="true" />
        </Button>
        <p className="text-xs text-muted-foreground">
          One run is created per app. Each is a normal run and appears in the ledger.
        </p>
      </div>
    </div>
  )
}

function BatchField({
  label,
  htmlFor,
  invalid = false,
  children,
}: {
  label: string
  htmlFor: string
  invalid?: boolean
  children: ReactNode
}) {
  return (
    <div>
      <label htmlFor={htmlFor} className="data-label">
        {label}
      </label>
      <div className="mt-1.5">{children}</div>
      {invalid ? (
        <p className="mt-1 text-2xs text-red-700 dark:text-red-300">This value is required.</p>
      ) : null}
    </div>
  )
}

/**
 * The per-app outcome of one batch.
 *
 * A partial success is the normal case and is never collapsed into a single
 * message: every created run is linked by id, and every rejection carries the
 * app it refers to and why. Reading only "some runs failed" would leave the
 * operator unable to tell which forty-nine worked.
 */
function BatchResults({
  results,
  requested,
  created,
  rejected,
}: {
  results: BatchRunResult[]
  requested: number
  created: number
  rejected: number
}) {
  return (
    <div className="border-t border-border p-5 lg:p-6" aria-live="polite">
      <p className="eyebrow">Batch result</p>
      <h3 className="mt-2 text-sm font-semibold">
        {created} of {requested} started
        {rejected > 0 ? ` · ${rejected} refused` : ""}
      </h3>
      <ul className="mt-3 divide-y divide-border overflow-hidden rounded-md border border-border">
        {results.map((result) => (
          <li
            key={result.app_name}
            className="flex flex-wrap items-start justify-between gap-3 bg-card px-4 py-3"
          >
            <div className="min-w-0">
              <p className="flex items-center gap-2 text-sm font-medium">
                {result.status === "created" ? (
                  <CheckCircle2 className="size-4 text-emerald-600" aria-hidden="true" />
                ) : (
                  <XCircle className="size-4 text-red-600" aria-hidden="true" />
                )}
                {result.app_name}
              </p>
              {result.status === "rejected" ? (
                <p className="mt-1 max-w-text text-xs leading-5 text-muted-foreground">
                  {refusalSentence(result)}
                </p>
              ) : null}
            </div>
            {result.status === "created" && result.run_id ? (
              <Link
                href={`/runs/${encodeURIComponent(result.run_id)}`}
                className="inline-flex shrink-0 items-center gap-1 rounded-md border border-border px-2 py-1 font-mono text-2xs hover:border-brand-300 hover:bg-brand-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-500"
              >
                {result.run_id.slice(0, 12)}…
                <ArrowRight className="size-3.5" aria-hidden="true" />
              </Link>
            ) : (
              <span className="shrink-0 text-2xs font-medium uppercase tracking-[0.12em] text-muted-foreground">
                Not started
              </span>
            )}
          </li>
        ))}
      </ul>
    </div>
  )
}

/**
 * One catalog entry with two distinct destinations and a selection control.
 *
 * The card surface still opens the evidence profile, and every app still carries
 * an explicit "Run" action for a single integration. The checkbox sits above the
 * overlay link so ticking an app never navigates away from the selection being
 * built.
 */
function AppCard({
  app,
  selected,
  onToggle,
}: {
  app: AppSearchItem
  selected: boolean
  onToggle: () => void
}) {
  const checkboxId = `select-${app.app_slug}`
  return (
    <div
      data-selected={selected || undefined}
      className="group relative flex min-h-32 flex-col justify-between rounded-md border border-border bg-card p-4 transition-colors focus-within:border-brand-300 hover:border-brand-300 hover:bg-brand-50/35 data-[selected]:border-brand-400 data-[selected]:bg-brand-50/60"
    >
      <Link
        href={`/apps/${encodeURIComponent(app.app_slug)}`}
        className="absolute inset-0 z-0 rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-500"
      >
        <span className="sr-only">Inspect {app.app_name} evidence</span>
      </Link>
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-start gap-2.5">
          <input
            id={checkboxId}
            type="checkbox"
            checked={selected}
            onChange={onToggle}
            className="relative z-10 mt-0.5 size-4 shrink-0 cursor-pointer rounded border-border accent-brand-500"
          />
          {/* The visible name stays part of the card's overlay link — ticking is
              the checkbox's job, and making the title toggle selection would
              take away the only way to open the app's evidence profile. */}
          <label htmlFor={checkboxId} className="sr-only">
            Select {app.app_name} for bulk onboarding
          </label>
          <div className="pointer-events-none">
            <p className="text-sm font-semibold">{app.app_name}</p>
            <p className="mt-1 font-mono text-2xs uppercase tracking-[0.12em] text-muted-foreground">
              {app.app_slug}
            </p>
          </div>
        </div>
        <div className="pointer-events-none">
          <StatusBadge status={app.access_route ?? "unknown"} />
        </div>
      </div>
      <div className="flex items-end justify-between gap-3 text-xs text-muted-foreground">
        <span className="pointer-events-none">
          {app.api_type ? humanize(app.api_type) : "API type not reported"}
        </span>
        <Link
          href={`/runs/new?app=${encodeURIComponent(app.app_name)}`}
          className="relative z-10 inline-flex items-center gap-1 rounded-md border border-border bg-card px-2 py-1 text-2xs font-medium text-foreground transition-colors hover:border-brand-300 hover:bg-brand-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-500"
        >
          Run<span className="sr-only"> {app.app_name}</span>
          <ArrowRight className="size-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
        </Link>
      </div>
    </div>
  )
}

function CatalogMessage({
  icon: Icon,
  title,
  copy,
}: {
  icon: typeof Boxes
  title: string
  copy: string
}) {
  return (
    <div className="grid min-h-36 place-items-center text-center">
      <div>
        <Icon className="mx-auto size-5 text-muted-foreground" aria-hidden="true" />
        <p className="mt-3 text-sm font-medium">{title}</p>
        <p className="mt-1 text-xs leading-5 text-muted-foreground">{copy}</p>
      </div>
    </div>
  )
}
