"use client"

import { useDeferredValue, useState } from "react"
import Link from "next/link"
import { useQuery } from "@tanstack/react-query"
import { ArrowRight, Boxes, Search, ShieldAlert } from "lucide-react"

import { StatusBadge } from "@/components/status-badge"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { humanize } from "@/lib/format"
import type { AppSearchResponse } from "@/lib/types"

async function findApps(query: string): Promise<AppSearchResponse> {
  const response = await fetch(`/api/ops/apps/search?q=${encodeURIComponent(query)}`, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  })
  if (!response.ok) throw new Error("catalog_unavailable")
  return response.json() as Promise<AppSearchResponse>
}

export function AppSearch() {
  const [query, setQuery] = useState("")
  const deferredQuery = useDeferredValue(query.trim())
  const enabled = deferredQuery.length >= 2
  const result = useQuery({
    queryKey: ["app-search", deferredQuery],
    queryFn: () => findApps(deferredQuery),
    enabled,
  })

  return (
    <section id="app-catalog" className="panel overflow-hidden" aria-labelledby="app-catalog-title">
      <div className="grid border-b border-border lg:grid-cols-[0.7fr_1.3fr]">
        <div className="border-b border-border p-5 lg:border-b-0 lg:border-r lg:p-6">
          <p className="eyebrow">Verified catalog</p>
          <h2 id="app-catalog-title" className="mt-2 text-xl font-semibold tracking-[-0.02em]">
            Inspect P1 app evidence
          </h2>
          <p className="mt-2 max-w-md text-sm leading-6 text-muted-foreground">
            Search the immutable snapshot before opening an operations run. Results are backend records, not generated suggestions.
          </p>
        </div>
        <div className="p-5 lg:p-6">
          <label htmlFor="app-search" className="data-label">Application name</label>
          <div className="relative mt-2">
            <Search className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              id="app-search"
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value.slice(0, 120))}
              placeholder="Search Slack, HubSpot, Linear…"
              className="h-11 rounded-md bg-white pl-10"
              autoComplete="off"
            />
          </div>
        </div>
      </div>

      <div className="min-h-48 p-5 lg:p-6" aria-live="polite">
        {!enabled ? (
          <CatalogMessage icon={Boxes} title="Search the verified catalog" copy="Enter at least two characters to query the P1 snapshot." />
        ) : result.isPending ? (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3" aria-label="Loading app results">
            {[0, 1, 2].map((item) => <Skeleton key={item} className="h-32 rounded-md" />)}
          </div>
        ) : result.isError ? (
          <CatalogMessage icon={ShieldAlert} title="Catalog unavailable" copy="The backend could not return verified app records. No placeholder results are shown." />
        ) : result.data.items.length === 0 ? (
          <CatalogMessage icon={Search} title="No verified match" copy={`No P1 record matched “${deferredQuery}”. You can still create a run for bounded enrichment.`} />
        ) : (
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {result.data.items.map((app) => (
              <Link
                key={app.app_slug}
                href={`/apps/${encodeURIComponent(app.app_slug)}`}
                className="group flex min-h-32 flex-col justify-between rounded-md border border-border bg-white p-4 transition-colors hover:border-brand-300 hover:bg-brand-50/35"
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold">{app.app_name}</p>
                    <p className="mt-1 font-mono text-[9px] uppercase tracking-[0.12em] text-muted-foreground">{app.app_slug}</p>
                  </div>
                  <StatusBadge status={app.access_route ?? "unknown"} />
                </div>
                <div className="flex items-end justify-between gap-3 text-xs text-muted-foreground">
                  <span>{app.api_type ? humanize(app.api_type) : "API type not reported"}</span>
                  <ArrowRight className="size-4 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </section>
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
