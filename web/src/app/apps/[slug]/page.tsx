import type { Metadata } from "next"
import Link from "next/link"
import { notFound } from "next/navigation"
import { connection } from "next/server"
import { ArrowLeft, ArrowRight, Boxes, FileCheck2, Gauge, Route } from "lucide-react"

import { ProvenanceCard } from "@/components/provenance-card"
import { ResearchPanel } from "@/components/run-detail-panels"
import { StatusBadge } from "@/components/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { ApiError, getAppResearch } from "@/lib/api"
import { humanize } from "@/lib/format"

export const metadata: Metadata = { title: "App research" }

export default async function AppResearchPage({ params }: { params: Promise<{ slug: string }> }) {
  await connection()
  const { slug } = await params
  if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(slug)) notFound()

  let result
  try {
    result = await getAppResearch(slug)
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound()
    return <ResearchUnavailable {...researchErrorCopy(error)} />
  }

  const { app, research } = result

  return (
    <div className="page-enter space-y-7">
      <Button asChild variant="ghost" size="sm" className="-ml-2 font-mono text-[10px] uppercase tracking-[0.1em]">
        <Link href="/#app-catalog"><ArrowLeft aria-hidden="true" /> App catalog</Link>
      </Button>

      <header className="flex flex-col gap-5 border-b border-border pb-7 lg:flex-row lg:items-end lg:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className="eyebrow">Verified app profile</p>
            <StatusBadge status={app.verification_status} />
          </div>
          <h1 className="mt-3 text-3xl font-semibold tracking-[-0.035em] sm:text-4xl">{app.app_name}</h1>
          <p className="mt-2 font-mono text-[10px] uppercase tracking-[0.12em] text-muted-foreground">{app.app_slug}</p>
        </div>
        <Button asChild className="w-fit rounded-md">
          <Link href={`/runs/new?app=${encodeURIComponent(app.app_name)}`}>Create run <ArrowRight aria-hidden="true" /></Link>
        </Button>
      </header>

      <section className="grid overflow-hidden rounded-md border border-border bg-border sm:grid-cols-2 xl:grid-cols-4" aria-label="App evidence summary">
        <Summary icon={Boxes} label="Category" value={app.category ?? "Not reported"} />
        <Summary icon={Route} label="Access route" value={humanize(app.access_route)} />
        <Summary icon={Gauge} label="Buildability" value={humanize(app.buildability)} />
        <Summary icon={FileCheck2} label="Research confidence" value={app.confidence == null ? "Not reported" : `${Math.round(app.confidence * 100)}%`} />
      </section>

      <Alert className="rounded-md border-violet-200 bg-violet-50/60">
        <FileCheck2 className="text-violet-600" aria-hidden="true" />
        <AlertTitle>Evidence-derived, not routing authority</AlertTitle>
        <AlertDescription>
          This profile reflects the verified P1 snapshot and operational enrichment. A run’s deterministic router remains the final authority.
        </AlertDescription>
      </Alert>

      <section className="grid gap-5 xl:grid-cols-[1.3fr_0.7fr]">
        <ResearchPanel research={research} />
        <ProvenanceCard snapshot={result.provenance ?? null} />
      </section>

      {research.auth_methods.length ? (
        <section className="panel rounded-md p-5">
          <p className="data-label">Authentication surface</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {research.auth_methods.map((method) => <Badge key={method} variant="outline" className="rounded-md">{method}</Badge>)}
          </div>
          <p className="mt-4 text-xs leading-5 text-muted-foreground">Authentication methods are evidence labels. No credential values are loaded or displayed on this page.</p>
        </section>
      ) : null}
    </div>
  )
}

function Summary({ icon: Icon, label, value }: { icon: typeof Boxes; label: string; value: string }) {
  return (
    <div className="bg-card p-5 [&:not(:last-child)]:border-b [&:not(:last-child)]:border-border sm:[&:not(:last-child)]:border-b-0 sm:[&:not(:last-child)]:border-r">
      <span className="flex items-center gap-2 data-label"><Icon className="size-3.5 text-violet-500" aria-hidden="true" />{label}</span>
      <p className="mt-4 text-sm font-medium">{value}</p>
    </div>
  )
}

function researchErrorCopy(error: unknown): {
  copy: string
  title: string
} {
  if (error instanceof ApiError && error.code === "INVALID_API_RESPONSE") {
    return {
      title: "Response contract mismatch",
      copy: "The backend returned a sanitized payload that does not match the frontend contract. No synthetic app details are shown.",
    }
  }

  if (error instanceof ApiError && error.status === 503) {
    return {
      title: "Backend unavailable",
      copy: "The operations API is unreachable or not configured for this deployment. No synthetic app details are shown.",
    }
  }

  return {
    title: "The backend could not return verified research.",
    copy: "No synthetic app details are shown. Confirm the API is running and try again.",
  }
}

function ResearchUnavailable({ copy, title }: { copy: string; title: string }) {
  return (
    <div className="mx-auto grid min-h-[65vh] max-w-xl place-items-center text-center">
      <div>
        <Boxes className="mx-auto size-6 text-muted-foreground" aria-hidden="true" />
        <p className="eyebrow mt-4">App profile unavailable</p>
        <h1 className="mt-2 text-2xl font-semibold">{title}</h1>
        <p className="mt-3 text-sm leading-6 text-muted-foreground">{copy}</p>
        <Button asChild variant="outline" className="mt-6 rounded-md"><Link href="/"><ArrowLeft aria-hidden="true" /> Overview</Link></Button>
      </div>
    </div>
  )
}
