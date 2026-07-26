"use client"

import { useDeferredValue, useMemo, useState } from "react"
import Link from "next/link"
import { ArrowRight, Boxes, Search, ShieldAlert } from "lucide-react"

import { StatusBadge } from "@/components/status-badge"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { groupAppsByCategory, matchesAppQuery, useAppCatalog } from "@/lib/app-catalog"
import { humanize } from "@/lib/format"
import type { AppSearchItem } from "@/lib/types"

/**
 * The verified catalog, browsable without knowing an app's name.
 *
 * This used to be a search box that showed nothing until two characters were
 * typed, so an operator who did not know the exact spelling — or did not know
 * which apps exist at all — had no way in. The full catalog is now listed up
 * front and the input only narrows it, which is filtering rather than guessing.
 */
export function AppSearch() {
  const [query, setQuery] = useState("")
  const deferredQuery = useDeferredValue(query.trim())
  const catalog = useAppCatalog()

  const groups = useMemo(() => {
    const items = catalog.data?.items ?? []
    return groupAppsByCategory(items.filter((app) => matchesAppQuery(app, deferredQuery)))
  }, [catalog.data, deferredQuery])

  const matchCount = groups.reduce((total, [, apps]) => total + apps.length, 0)
  const totalCount = catalog.data?.total ?? 0

  return (
    <section id="app-catalog" className="panel overflow-hidden" aria-labelledby="app-catalog-title">
      <div className="grid border-b border-border lg:grid-cols-[0.7fr_1.3fr]">
        <div className="border-b border-border p-5 lg:border-b-0 lg:border-r lg:p-6">
          <p className="eyebrow">Verified catalog</p>
          <h2 id="app-catalog-title" className="mt-2 text-xl font-semibold tracking-[-0.02em]">
            Choose an app to inspect
          </h2>
          <p className="mt-2 max-w-md text-sm leading-6 text-muted-foreground">
            Every app in the immutable P1 snapshot is listed below. Pick one to read its evidence
            before opening a run. These are backend records, not generated suggestions.
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
              className="h-11 rounded-md bg-white pl-10"
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
            copy={`No P1 record matched “${deferredQuery}”. Clear the filter to browse every app, or create a run for bounded enrichment.`}
          />
        ) : (
          <div className="space-y-6">
            {groups.map(([category, apps]) => (
              <div key={category}>
                <h3 className="data-label">{category}</h3>
                <div className="mt-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                  {apps.map((app) => (
                    <AppCard key={app.app_slug} app={app} />
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </section>
  )
}

function AppCard({ app }: { app: AppSearchItem }) {
  return (
    <Link
      href={`/apps/${encodeURIComponent(app.app_slug)}`}
      className="group flex min-h-32 flex-col justify-between rounded-md border border-border bg-white p-4 transition-colors hover:border-brand-300 hover:bg-brand-50/35"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold">{app.app_name}</p>
          <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.12em] text-muted-foreground">
            {app.app_slug}
          </p>
        </div>
        <StatusBadge status={app.access_route ?? "unknown"} />
      </div>
      <div className="flex items-end justify-between gap-3 text-xs text-muted-foreground">
        <span>{app.api_type ? humanize(app.api_type) : "API type not reported"}</span>
        <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
      </div>
    </Link>
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
