import Link from "next/link"
import { ArrowUpRight, CircleDotDashed } from "lucide-react"

import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-svh">
      <a
        href="#main-content"
        className="sr-only z-50 bg-primary px-4 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:left-3 focus:top-3"
      >
        Skip to content
      </a>
      <header className="site-header border-b border-ink/20">
        <div className="mx-auto flex min-h-16 max-w-[1480px] items-center justify-between gap-4 px-4 sm:px-7 lg:px-10">
          <Link href="/" className="group flex items-center gap-3" aria-label="Ops ledger home">
            <span className="grid size-9 place-items-center border border-ink bg-ink font-mono text-[10px] font-semibold tracking-[0.18em] text-paper transition-transform group-hover:-translate-y-0.5 motion-reduce:transform-none">
              C/O
            </span>
            <span className="hidden sm:block">
              <span className="block font-mono text-[10px] uppercase tracking-[0.2em] text-muted-foreground">
                Composio
              </span>
              <span className="block font-heading text-lg leading-none">Operations ledger</span>
            </span>
          </Link>

          <nav className="flex items-center gap-2" aria-label="Primary navigation">
            <Badge
              variant="outline"
              className="hidden rounded-none border-viridian/40 bg-viridian/5 font-mono text-[10px] uppercase tracking-[0.14em] text-viridian md:inline-flex"
            >
              <CircleDotDashed aria-hidden="true" /> Phase 2
            </Badge>
            <Button asChild variant="ghost" className="rounded-none font-mono text-xs uppercase">
              <Link href="/">Runs</Link>
            </Button>
            <Button asChild className="rounded-none bg-rust px-4 text-paper hover:bg-rust/90">
              <Link href="/runs/new">
                New run <ArrowUpRight aria-hidden="true" />
              </Link>
            </Button>
          </nav>
        </div>
      </header>

      <main id="main-content" className="mx-auto max-w-[1480px] px-4 py-8 sm:px-7 sm:py-12 lg:px-10">
        {children}
      </main>

      <footer className="mt-16 border-t border-ink/20">
        <div className="mx-auto flex max-w-[1480px] flex-col gap-2 px-4 py-6 font-mono text-[10px] uppercase tracking-[0.14em] text-muted-foreground sm:flex-row sm:items-center sm:justify-between sm:px-7 lg:px-10">
          <p>Private P2 operations surface</p>
          <p>References, never raw secrets · External actions off by default</p>
        </div>
      </footer>
    </div>
  )
}
