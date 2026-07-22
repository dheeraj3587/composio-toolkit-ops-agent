"use client"

import { useActionState } from "react"
import { useFormStatus } from "react-dom"
import { RefreshCcw } from "lucide-react"

import { runPhaseAction, type PhaseActionState } from "@/app/runs/[runId]/actions"
import { Button } from "@/components/ui/button"
import type { RunPhaseAction } from "@/lib/types"

const initialPhaseActionState: PhaseActionState = {
  message: null,
  tone: "neutral",
}

function ActionButton({ label }: { label: string }) {
  const { pending } = useFormStatus()
  return (
    <Button type="submit" variant="outline" size="sm" disabled={pending} className="rounded-none">
      <RefreshCcw className={pending ? "animate-spin motion-reduce:animate-none" : ""} aria-hidden="true" />
      {pending ? "Requesting…" : label}
    </Button>
  )
}

export function PhaseActionForm({
  runId,
  action,
  label,
}: {
  runId: string
  action: RunPhaseAction
  label: string
}) {
  const [state, formAction] = useActionState(runPhaseAction, initialPhaseActionState)
  return (
    <form action={formAction} className="space-y-2">
      <input type="hidden" name="run_id" value={runId} />
      <input type="hidden" name="action" value={action} />
      <ActionButton label={label} />
      {state.message ? (
        <p className={state.tone === "error" ? "text-xs text-destructive" : "text-xs text-muted-foreground"} aria-live="polite">
          {state.message}
        </p>
      ) : null}
    </form>
  )
}
