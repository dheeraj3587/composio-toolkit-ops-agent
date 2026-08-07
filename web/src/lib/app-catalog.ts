"use client"

import { useQuery } from "@tanstack/react-query"

import type {
  AppCapabilitiesResponse,
  AppCatalogResponse,
  AppSearchItem,
} from "@/lib/types"

/**
 * The verified catalog, fetched once and shared by every selector.
 *
 * Both the dashboard catalog card and the run form need the same list, and both
 * previously required the operator to already know an app's name. One query key
 * means the list is fetched once per session rather than per surface.
 */
export async function fetchAppCatalog(): Promise<AppCatalogResponse> {
  const response = await fetch("/api/ops/apps", {
    headers: { Accept: "application/json" },
    cache: "no-store",
  })
  if (!response.ok) throw new Error("catalog_unavailable")
  return response.json() as Promise<AppCatalogResponse>
}

export function useAppCatalog() {
  return useQuery({
    queryKey: ["app-catalog"],
    queryFn: fetchAppCatalog,
    // The snapshot is immutable for the life of a deployment, so refetching it
    // on every mount would be pure noise.
    staleTime: 10 * 60 * 1000,
  })
}

export async function fetchAppCapabilities(appSlug: string): Promise<AppCapabilitiesResponse> {
  const response = await fetch(
    `/api/ops/apps/${encodeURIComponent(appSlug)}/capabilities`,
    {
      headers: { Accept: "application/json" },
      cache: "no-store",
    },
  )
  if (!response.ok) throw new Error("app_capabilities_unavailable")
  return response.json() as Promise<AppCapabilitiesResponse>
}

export function useAppCapabilities(appSlug?: string) {
  return useQuery({
    queryKey: ["app-capabilities", appSlug],
    queryFn: () => fetchAppCapabilities(appSlug!),
    enabled: Boolean(appSlug),
    staleTime: 10 * 60 * 1_000,
  })
}

/** Case- and separator-insensitive match across the fields an operator can see. */
export function matchesAppQuery(app: AppSearchItem, query: string): boolean {
  const needle = query.trim().toLowerCase()
  if (needle.length === 0) return true
  const haystack = [app.app_name, app.app_slug, app.category ?? "", app.api_type ?? ""]
    .join(" ")
    .toLowerCase()
  return haystack.includes(needle)
}

/**
 * The order the readiness groups are shown in, most autonomous first.
 *
 * `readiness_tier` is the recipe's own claim about how far the agent gets
 * unattended, which is what an operator choosing a batch is actually sorting on
 * — and a different question from `access_route`, which says how the credential
 * is obtained. Apps the agent can finish alone come first; the tiers that end at
 * a person (owner submission, then outreach) come last.
 *
 * "unknown" is last and is a real bucket: the field is nullable server-side and
 * absent from an older API, and an app with no tier must still be selectable
 * rather than silently dropped from the list.
 */
const READINESS_TIER_ORDER = [
  "browser_ready",
  "managed_auth_ready",
  "owner_submit_ready",
  "outreach_ready",
  "outreach_review_required",
  "unknown",
] as const

/**
 * Group apps by how far the agent gets unattended, so a bulk selection is made
 * with the cost of each group visible rather than as one undifferentiated list.
 */
export function groupAppsByReadinessTier(apps: AppSearchItem[]): [string, AppSearchItem[]][] {
  const groups = new Map<string, AppSearchItem[]>()
  for (const app of apps) {
    const key = app.readiness_tier ?? "unknown"
    const bucket = groups.get(key)
    if (bucket) bucket.push(app)
    else groups.set(key, [app])
  }
  const rank = (key: string) => {
    const index = READINESS_TIER_ORDER.indexOf(key as (typeof READINESS_TIER_ORDER)[number])
    return index === -1 ? READINESS_TIER_ORDER.length : index
  }
  return [...groups.entries()].sort(([left], [right]) => rank(left) - rank(right) || left.localeCompare(right))
}

/** Group apps by category so a long list stays scannable. */
export function groupAppsByCategory(apps: AppSearchItem[]): [string, AppSearchItem[]][] {
  const groups = new Map<string, AppSearchItem[]>()
  for (const app of apps) {
    const key = app.category?.trim() || "Uncategorized"
    const bucket = groups.get(key)
    if (bucket) bucket.push(app)
    else groups.set(key, [app])
  }
  return [...groups.entries()].sort(([left], [right]) => left.localeCompare(right))
}
