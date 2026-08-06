"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { Activity, Boxes, LayoutDashboard, LogOut, Plus, ShieldCheck, Smartphone } from "lucide-react"

import { signOutAction } from "@/app/login/actions"
import { NavLink } from "@/components/nav-link"

const navigation = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/runs/new", label: "New integration", icon: Plus },
  { href: "/#app-catalog", label: "Apps", icon: Boxes },
  { href: "/system", label: "System health", icon: Activity },
  { href: "/security/authenticator", label: "Authenticator", icon: Smartphone },
] as const

export function AppShell({
  children,
  demoMode,
}: {
  children: React.ReactNode
  demoMode: boolean
}) {
  const pathname = usePathname()
  if (pathname === "/login") return children

  const topOffset = demoMode ? "top-8" : "top-0"
  const pagePadding = demoMode ? "pt-8" : ""

  return (
    <div className={`min-h-svh bg-background ${pagePadding}`}>
      <a
        href="#main-content"
        className="sr-only z-[80] bg-primary px-4 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:left-3 focus:top-10"
      >
        Skip to content
      </a>

      <aside
        className={`fixed bottom-0 left-0 ${topOffset} z-50 hidden w-64 flex-col border-r border-white/10 bg-rail text-white lg:flex`}
        aria-label="Application navigation"
      >
        <div className="flex h-20 items-center border-b border-white/10 px-6">
          <Link href="/" className="group flex items-center gap-3" aria-label="Composio Operations home">
            <span className="grid size-9 place-items-center rounded-md border border-brand-dev bg-brand-dev font-mono text-[10px] font-semibold tracking-[0.16em] text-rail transition-colors group-hover:border-brand-400 group-hover:bg-brand-dev/80">
              C/O
            </span>
            <span>
              <span className="block text-sm font-semibold leading-none">Composio</span>
              <span className="mt-1 block font-mono text-[9px] uppercase tracking-[0.16em] text-white/45">
                Operations
              </span>
            </span>
          </Link>
        </div>

        <nav className="flex-1 space-y-1 px-3 py-6" aria-label="Primary navigation">
          <p className="px-3 pb-2 font-mono text-[9px] font-medium uppercase tracking-[0.18em] text-white/35">
            Control plane
          </p>
          {navigation.map((item) => (
            <NavLink key={item.href} {...item} />
          ))}
        </nav>

        <div className="m-3 rounded-xl border border-white/10 bg-white/[0.035] p-4">
          <div className="flex items-center gap-2 text-xs font-medium text-white/85">
            <ShieldCheck className="size-4 text-brand-300" aria-hidden="true" />
            Secure boundary
          </div>
          <p className="mt-2 text-[11px] leading-5 text-white/45">
            Account and API secrets stay inside the encrypted credential boundary.
          </p>
          <div className="mt-4 flex items-center gap-2 font-mono text-[9px] uppercase tracking-[0.12em] text-emerald-300">
            <span className="size-1.5 rounded-full bg-emerald-400" />
            Secrets protected
          </div>
        </div>

        <div className="flex items-center justify-between border-t border-white/10 px-5 py-3">
          <span className="font-mono text-[9px] uppercase tracking-[0.14em] text-white/35">
            Private workspace
          </span>
          <form action={signOutAction}>
            <button
              type="submit"
              className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1.5 text-[10px] font-medium text-white/50 hover:bg-white/10 hover:text-white"
              title="Sign out"
            >
              <LogOut className="size-3.5" aria-hidden="true" />
              Sign out
            </button>
          </form>
        </div>
      </aside>

      <header
        className={`fixed inset-x-0 ${topOffset} z-40 flex h-16 items-center justify-between border-b border-border bg-background/95 px-4 backdrop-blur-sm lg:hidden`}
      >
        <Link href="/" className="flex items-center gap-2 text-sm font-semibold" aria-label="Composio Operations home">
          <span className="grid size-8 place-items-center rounded-md bg-rail font-mono text-[9px] tracking-[0.14em] text-white">C/O</span>
          Operations
        </Link>
        <div className="flex items-center gap-1">
          <NavLink href="/" label="Runs" icon={LayoutDashboard} compact />
          <NavLink href="/system" label="System" icon={Activity} compact />
          <Link
            href="/runs/new"
            className="ml-1 inline-flex h-9 items-center gap-1.5 rounded-md bg-primary px-3 text-xs font-semibold text-primary-foreground"
          >
            <Plus className="size-3.5" aria-hidden="true" /> New
          </Link>
          <form action={signOutAction}>
            <button
              type="submit"
              className="ml-1 grid size-9 place-items-center rounded-md text-muted-foreground hover:bg-secondary hover:text-foreground"
              aria-label="Sign out"
            >
              <LogOut className="size-4" aria-hidden="true" />
            </button>
          </form>
        </div>
      </header>

      <div className="lg:pl-64">
        <main id="main-content" className="mx-auto min-h-svh max-w-[1336px] px-5 pb-16 pt-24 sm:px-8 lg:px-10 lg:pt-10 xl:px-12">
          {children}
        </main>
        <footer className="border-t border-border px-4 py-5 sm:px-7 lg:px-9 xl:px-12">
          <div className="mx-auto flex max-w-[1240px] flex-col gap-2 font-mono text-[9px] uppercase tracking-[0.13em] text-muted-foreground sm:flex-row sm:items-center sm:justify-between">
            <p className="flex items-center gap-2"><ShieldCheck className="size-3" aria-hidden="true" /> Private operations surface</p>
            <p>Live provider state · secrets never displayed</p>
          </div>
        </footer>
      </div>
    </div>
  )
}
