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
    <section id="app-catalog" className="panel scroll-mt-6 overflow-hidden" aria-labelledby="app-catalog-title">
      <div className="grid border-b border-border lg:grid-cols-[1fr_1.1fr] lg:items-end">
        <div className="border-b border-border p-5 lg:border-b-0 lg:border-r">
          <p className="eyebrow">Verified catalog</p>
          <h2 id="app-catalog-title" className="mt-1 text-xl font-medium tracking-[-0.02em]">
            Supported apps
          </h2>
          <p className="mt-2 max-w-lg text-sm leading-6 text-muted-foreground">
            Inspect reviewed app evidence or start a prefilled integration.
          </p>
        </div>
        <div className="p-5">
          <label htmlFor="app-search" className="text-sm font-medium">
            Filter apps <span className="optional-label">(optional)</span>
          </label>
          <div className="relative mt-2">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              id="app-search"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value.slice(0, 120))}
              placeholder="Name, slug, or category"
              className="pl-10"
              autoComplete="off"
            />
          </div>
          <p className="mt-2 text-xs text-muted-foreground" aria-live="polite">
            {catalog.isPending
              ? "Loading verified apps…"
              : catalog.isError
                ? "The catalog could not be loaded."
                : deferredQuery.length > 0
                  ? `${matchCount} of ${totalCount} apps match.`
                  : `${totalCount} verified apps available.`}
          </p>
        </div>
      </div>

      <div className="min-h-40 p-5" aria-live="polite">
        {catalog.isPending ? (
          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-3" aria-label="Loading app catalog">
            {[0, 1, 2, 3, 4, 5].map((item) => <Skeleton key={item} className="h-24" />)}
          </div>
        ) : catalog.isError ? (
          <CatalogMessage icon={ShieldAlert} title="Catalog unavailable" copy="No placeholder results are shown." />
        ) : totalCount === 0 ? (
          <CatalogMessage icon={Boxes} title="No verified apps" copy="The verified snapshot returned no records." />
        ) : matchCount === 0 ? (
          <CatalogMessage icon={Search} title="No verified match" copy={`No reviewed app matched “${deferredQuery}”.`} />
        ) : (
          <div className="space-y-5">
            {groups.map(([category, apps]) => (
              <div key={category}>
                <h3 className="data-label">{category}</h3>
                <div className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                  {apps.map((app) => <AppCard key={app.app_slug} app={app} />)}
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
    <div className="group relative flex min-h-24 flex-col justify-between rounded-md border border-border bg-field p-3.5 transition-colors focus-within:border-brand-400/60 hover:border-[#454545] hover:bg-secondary/45">
      <Link
        href={`/apps/${encodeURIComponent(app.app_slug)}`}
        className="absolute inset-0 z-0 rounded-md focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
      >
        <span className="sr-only">Inspect {app.app_name} evidence</span>
      </Link>
      <div className="pointer-events-none flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-medium">{app.app_name}</p>
          <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.1em] text-muted-foreground">{app.app_slug}</p>
        </div>
        <StatusBadge status={app.access_route ?? "unknown"} />
      </div>
      <div className="mt-4 flex items-end justify-between gap-3 text-xs text-muted-foreground">
        <span className="pointer-events-none">{app.api_type ? humanize(app.api_type) : "API not reported"}</span>
        <Link
          href={`/runs/new?app=${encodeURIComponent(app.app_name)}`}
          className="relative z-10 inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium text-brand-300 hover:bg-brand-50 hover:text-brand-200 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring"
        >
          Run<span className="sr-only"> {app.app_name}</span>
          <ArrowRight className="size-3.5" aria-hidden="true" />
        </Link>
      </div>
    </div>
  )
}

function CatalogMessage({ icon: Icon, title, copy }: { icon: typeof Boxes; title: string; copy: string }) {
  return (
    <div className="grid min-h-32 place-items-center text-center">
      <div>
        <Icon className="mx-auto size-5 text-muted-foreground" aria-hidden="true" />
        <p className="mt-3 text-sm font-medium">{title}</p>
        <p className="mt-1 text-xs leading-5 text-muted-foreground">{copy}</p>
      </div>
    </div>
  )
}
