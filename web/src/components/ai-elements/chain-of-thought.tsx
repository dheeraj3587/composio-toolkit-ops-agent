"use client"

/**
 * Chain of thought — the agent's reasoning, as an instrument trace.
 *
 * Hand-built against this repo's own stack (`radix-ui` unified import,
 * `class-variance-authority`, `cn`) rather than installed from the taki-ui
 * registry. The registry install pulled four dependencies this repo does not
 * use — `react-aria-components` (a second primitive stack alongside Radix),
 * `tailwind-variants` (a second variant system alongside CVA), `motion`, and
 * `streamdown` — asked to overwrite `src/lib/utils.ts`, and delivered no
 * component. The public API here is identical to the documented one, so call
 * sites are unchanged.
 *
 * Status is carried by FORM, not colour: this console is monochrome, and shape
 * is also the accessible answer (never colour alone). Solid = complete, ring =
 * active, hairline = pending, dashed = paused or gated.
 *
 * Motion is CSS-only and keyed on stable identity by the caller. The run detail
 * page re-renders every 4s (`run-progress.tsx`), so entry animation driven by
 * mount order would replay on every poll and strobe.
 */

import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { ChevronRight } from "lucide-react"
import type { LucideIcon } from "lucide-react"

import { cn } from "@/lib/utils"

type StepStatus = "complete" | "active" | "pending" | "halted"

const ChainOfThoughtContext = React.createContext<{ open: boolean }>({ open: true })

/* -------------------------------------------------------------------------- */

function ChainOfThought({
  open,
  defaultOpen = true,
  onOpenChange,
  className,
  children,
  ...props
}: React.ComponentProps<"div"> & {
  open?: boolean
  defaultOpen?: boolean
  onOpenChange?: (open: boolean) => void
}) {
  const [uncontrolled, setUncontrolled] = React.useState(defaultOpen)
  const isControlled = open !== undefined
  const isOpen = isControlled ? open : uncontrolled

  const toggle = React.useCallback(() => {
    const next = !isOpen
    if (!isControlled) setUncontrolled(next)
    onOpenChange?.(next)
  }, [isOpen, isControlled, onOpenChange])

  return (
    <ChainOfThoughtContext.Provider value={{ open: isOpen }}>
      <div
        data-slot="chain-of-thought"
        data-state={isOpen ? "open" : "closed"}
        className={cn("group/cot flex w-full flex-col gap-3", className)}
        {...props}
      >
        {React.Children.map(children, (child) =>
          React.isValidElement(child) && child.type === ChainOfThoughtHeader
            ? React.cloneElement(child as React.ReactElement<HeaderProps>, { onToggle: toggle })
            : child,
        )}
      </div>
    </ChainOfThoughtContext.Provider>
  )
}

/* -------------------------------------------------------------------------- */

type HeaderProps = React.ComponentProps<"button"> & { onToggle?: () => void }

function ChainOfThoughtHeader({ className, children, onToggle, ...props }: HeaderProps) {
  const { open } = React.useContext(ChainOfThoughtContext)

  return (
    <button
      type="button"
      data-slot="chain-of-thought-header"
      aria-expanded={open}
      onClick={onToggle}
      className={cn(
        "group/cot-header flex w-full items-center gap-2 rounded-md text-left",
        "font-mono text-[11px] tracking-[0.06em] text-muted-foreground uppercase",
        "transition-colors hover:text-foreground",
        "focus-visible:ring-2 focus-visible:ring-ring/40 focus-visible:outline-none",
        className,
      )}
      {...props}
    >
      <ChevronRight
        aria-hidden
        className={cn(
          "size-3 shrink-0 transition-transform duration-160",
          open && "rotate-90",
        )}
      />
      <span className="truncate">{children ?? "Chain of thought"}</span>
      <span aria-hidden className="ml-1 h-px flex-1 bg-border" />
    </button>
  )
}

/* -------------------------------------------------------------------------- */

function ChainOfThoughtContent({ className, children, ...props }: React.ComponentProps<"div">) {
  const { open } = React.useContext(ChainOfThoughtContext)
  if (!open) return null

  return (
    <div
      data-slot="chain-of-thought-content"
      className={cn(
        // The spine. One hairline down the whole trace; each step hangs off it.
        "relative flex flex-col gap-0 pl-[9px]",
        "before:absolute before:top-1 before:bottom-1 before:left-0 before:w-px before:bg-border",
        className,
      )}
      {...props}
    >
      {children}
    </div>
  )
}

/* -------------------------------------------------------------------------- */

const stepMarker = cva(
  "absolute top-[7px] left-[-13px] size-[7px] shrink-0 rounded-full transition-colors",
  {
    variants: {
      status: {
        // Solid: this step is done.
        complete: "bg-foreground",
        // Ring + travelling highlight: this is where the agent is now.
        active: "bg-background ring-[1.5px] ring-foreground cot-marker-live",
        // Hairline: not reached.
        pending: "bg-background ring-1 ring-border",
        // Dashed square: stopped for a person.
        halted: "rounded-[1px] bg-background ring-1 ring-dashed ring-muted-foreground",
      },
    },
    defaultVariants: { status: "pending" },
  },
)

function ChainOfThoughtStep({
  icon: Icon,
  label,
  status = "pending",
  description,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<"div">, "children"> &
  VariantProps<typeof stepMarker> & {
    icon?: LucideIcon
    label?: React.ReactNode
    description?: React.ReactNode
    children?: React.ReactNode
  }) {
  return (
    <div
      data-slot="chain-of-thought-step"
      data-status={status}
      className={cn("relative flex flex-col gap-1.5 pb-4 pl-4 last:pb-1", className)}
      {...props}
    >
      <span aria-hidden className={cn(stepMarker({ status }))} />

      <div className="flex min-w-0 items-baseline gap-2">
        {Icon ? (
          <Icon
            aria-hidden
            className={cn(
              "size-3 shrink-0 translate-y-[2px]",
              status === "pending" ? "text-muted-foreground" : "text-foreground",
            )}
          />
        ) : null}
        <span
          className={cn(
            "min-w-0 text-sm leading-snug",
            status === "pending" ? "text-muted-foreground" : "text-foreground",
          )}
        >
          {label}
        </span>
      </div>

      {description ? (
        <span className="font-mono text-[11px] tracking-[0.06em] text-muted-foreground">
          {description}
        </span>
      ) : null}

      {children}
    </div>
  )
}

/* -------------------------------------------------------------------------- */

function ChainOfThoughtSearchResults({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="chain-of-thought-search-results"
      className={cn("flex flex-wrap items-center gap-1", className)}
      {...props}
    />
  )
}

function ChainOfThoughtSearchResult({ className, ...props }: React.ComponentProps<"span">) {
  return (
    <span
      data-slot="chain-of-thought-search-result"
      className={cn(
        "inline-flex h-5 items-center rounded-[3px] border border-border bg-secondary px-1.5",
        "font-mono text-[10px] tracking-[0.06em] text-muted-foreground",
        className,
      )}
      {...props}
    />
  )
}

/* -------------------------------------------------------------------------- */

function ChainOfThoughtImage({
  caption,
  className,
  children,
  ...props
}: React.ComponentProps<"figure"> & { caption?: React.ReactNode }) {
  return (
    <figure
      data-slot="chain-of-thought-image"
      className={cn("flex flex-col gap-1.5", className)}
      {...props}
    >
      <div className="overflow-hidden rounded-md border border-border bg-secondary">{children}</div>
      {caption ? (
        <figcaption className="font-mono text-[10px] tracking-[0.06em] text-muted-foreground">
          {caption}
        </figcaption>
      ) : null}
    </figure>
  )
}

export {
  ChainOfThought,
  ChainOfThoughtContent,
  ChainOfThoughtHeader,
  ChainOfThoughtImage,
  ChainOfThoughtSearchResult,
  ChainOfThoughtSearchResults,
  ChainOfThoughtStep,
  type StepStatus,
}
