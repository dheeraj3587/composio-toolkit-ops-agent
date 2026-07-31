"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import type { LucideIcon } from "lucide-react"

import { cn } from "@/lib/utils"

export function NavLink({
  href,
  label,
  icon: Icon,
  compact = false,
}: {
  href: string
  label: string
  icon: LucideIcon
  compact?: boolean
}) {
  const pathname = usePathname()
  const route = href.split("#")[0]
  const anchorOnly = href.includes("#")
  const active = !anchorOnly && (route === "/" ? pathname === "/" : pathname === route || pathname.startsWith(`${route}/`))

  return (
    <Link
      href={href}
      aria-current={active ? "page" : undefined}
      aria-label={compact ? label : undefined}
      className={cn(
        "group flex items-center gap-3 rounded-md text-sm transition-colors",
        compact
          ? "size-9 justify-center text-muted-foreground hover:bg-secondary hover:text-foreground"
          : "min-h-9 px-3 text-muted-foreground hover:bg-secondary/65 hover:text-foreground",
        active && !compact && "bg-secondary text-foreground shadow-[inset_2px_0_0_#0007cd]",
        active && compact && "bg-secondary text-foreground",
      )}
    >
      <Icon className={cn("size-4", active ? "text-brand-300" : "")} aria-hidden="true" />
      {compact ? <span className="sr-only">{label}</span> : <span>{label}</span>}
    </Link>
  )
}
