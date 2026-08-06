"use client"

import { useActionState } from "react"
import { useFormStatus } from "react-dom"
import { ArrowDown, Cable, CircleOff, ExternalLink, RefreshCcw } from "lucide-react"

import {
  runManagedConnectionAction,
  type ManagedConnectionActionState,
} from "@/app/runs/[runId]/actions"
import { PhaseActionForm } from "@/components/phase-action-form"
import { StatusBadge } from "@/components/status-badge"
import { Button } from "@/components/ui/button"
import { humanize } from "@/lib/format"
import type { PrimaryAction } from "@/lib/types"

const initialManagedState: ManagedConnectionActionState = {
  message: null,
  tone: "neutral",
  state: null,
}

const actionCopy: Record<PrimaryAction["kind"], { title: string; detail: string }> = {
  connect_account: {
    title: "Connect managed account",
    detail: "Open the provider authorization screen. Completion is accepted only after Composio reports an active account.",
  },
  poll_connection: {
    title: "Check managed connection",
    detail: "Refresh the stored connection request after completing authorization with the provider.",
  },
  open_browser: {
    title: "Open Playwright session",
    detail: "Watch the existing isolated browser session. Control remains locked until the backend grants HITL takeover.",
  },
  submit_credentials: {
    title: "Submit credential to vault",
    detail: "Use the owner-only encrypted submission surface. Raw credential values are never returned by this page.",
  },
  review_outreach: {
    title: "Review gated outreach",
    detail: "Review the verified contact route and controlled-send policy before any message is authorized.",
  },
  poll_reply: {
    title: "Check controlled inbox",
    detail: "Poll the existing outreach boundary for a classified provider reply without starting a browser.",
  },
  none: {
    title: "No action available",
    detail: "This run is complete, blocked, or retained through the read-only legacy adapter.",
  },
}

const actionTargets: Partial<Record<PrimaryAction["kind"], string>> = {
  open_browser: "#browser-session",
  submit_credentials: "#credential-submission",
  review_outreach: "#outreach-review",
}

export function CanonicalPrimaryAction({
  runId,
  action,
}: {
  runId: string
  action: PrimaryAction
}) {
  const copy = actionCopy[action.kind]

  return (
    <section className="panel overflow-hidden rounded-md" aria-labelledby="canonical-next-action">
      <div className="grid gap-5 p-5 md:grid-cols-[minmax(0,1fr)_auto] md:items-center">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <p className="eyebrow">Backend-authorized next step</p>
            <StatusBadge status={action.enabled ? "available" : "not_available"} />
          </div>
          <h2 id="canonical-next-action" className="mt-2 text-lg font-semibold">
            {copy.title}
          </h2>
          <p className="mt-2 max-w-text text-xs leading-5 text-muted-foreground">
            {copy.detail}
          </p>
          <p className="mt-3 font-mono text-2xs uppercase tracking-[0.1em] text-muted-foreground">
            Reason · {humanize(action.reason_code)}
          </p>
        </div>
        <div className="md:min-w-52 md:justify-self-end">
          <PrimaryActionControl runId={runId} action={action} />
        </div>
      </div>
    </section>
  )
}

function PrimaryActionControl({ runId, action }: { runId: string; action: PrimaryAction }) {
  if (action.kind === "connect_account" || action.kind === "poll_connection") {
    return (
      <ManagedConnectionForm
        runId={runId}
        operation={action.kind === "connect_account" ? "connect" : "poll"}
        enabled={action.enabled}
      />
    )
  }

  if (action.kind === "poll_reply") {
    return action.enabled ? (
      <PhaseActionForm runId={runId} action="poll-email" label="Check controlled inbox" />
    ) : (
      <DisabledAction label="Check controlled inbox" />
    )
  }

  const target = actionTargets[action.kind]
  if (target) {
    return action.enabled ? (
      <Button asChild size="sm" className="w-full rounded-none md:w-auto">
        <a href={target}>
          {action.kind === "review_outreach" ? (
            <ExternalLink aria-hidden="true" />
          ) : (
            <ArrowDown aria-hidden="true" />
          )}
          {actionCopy[action.kind].title}
        </a>
      </Button>
    ) : (
      <DisabledAction label={actionCopy[action.kind].title} />
    )
  }

  return <DisabledAction label="No action available" icon="off" />
}

function ManagedConnectionForm({
  runId,
  operation,
  enabled,
}: {
  runId: string
  operation: "connect" | "poll"
  enabled: boolean
}) {
  const [state, formAction] = useActionState(runManagedConnectionAction, initialManagedState)
  const label = operation === "connect" ? "Connect account" : "Check connection"

  return (
    <form action={formAction} className="space-y-2">
      <input type="hidden" name="run_id" value={runId} />
      <input type="hidden" name="managed_action" value={operation} />
      <ManagedSubmitButton label={label} enabled={enabled} operation={operation} />
      {state.message ? (
        <p
          className={state.tone === "error" ? "max-w-xs text-xs text-destructive" : "max-w-xs text-xs text-muted-foreground"}
          aria-live="polite"
        >
          {state.message}
        </p>
      ) : null}
    </form>
  )
}

function ManagedSubmitButton({
  label,
  enabled,
  operation,
}: {
  label: string
  enabled: boolean
  operation: "connect" | "poll"
}) {
  const { pending } = useFormStatus()
  const Icon = operation === "connect" ? Cable : RefreshCcw
  return (
    <Button type="submit" size="sm" disabled={!enabled || pending} className="w-full rounded-none md:w-auto">
      <Icon
        className={pending && operation === "poll" ? "animate-spin motion-reduce:animate-none" : ""}
        aria-hidden="true"
      />
      {pending ? "Requesting…" : label}
    </Button>
  )
}

function DisabledAction({ label, icon }: { label: string; icon?: "off" }) {
  const Icon = icon === "off" ? CircleOff : Cable
  return (
    <Button type="button" size="sm" variant="outline" disabled className="w-full rounded-none md:w-auto">
      <Icon aria-hidden="true" />
      {label}
    </Button>
  )
}
