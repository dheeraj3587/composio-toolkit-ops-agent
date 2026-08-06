import { Badge } from "@/components/ui/badge"
import { humanize } from "@/lib/format"
import { cn } from "@/lib/utils"

// ---------------------------------------------------------------------------
// Status vocabulary.
//
// The backend speaks many statuses across four unrelated axes -- run outcome,
// provider configuration, runtime policy, verification -- and the badge used to
// give nearly every one its own hue. Nine colours cannot be told apart at a
// glance, so the colour stopped carrying information and started competing with
// it.
//
// There are five tones here and they answer one question: what does this mean
// for the person reading it?
//
//   ok        Done, and correct. Nothing to do.
//   busy      Working right now. Nothing to do but wait.
//   attention Stopped, and it needs a person. This is the only colour that asks.
//   problem   It ended badly.
//   idle      Off, absent, or not reported. Deliberately quiet.
//
// Two statuses may share a tone; they never share a label, and every badge
// carries a plain-language title. Distinct meanings are separated by words,
// which are unambiguous, rather than by hue, which is not.
// ---------------------------------------------------------------------------

type Tone = "ok" | "busy" | "attention" | "problem" | "idle"

const TONE_CLASS: Record<Tone, string> = {
  ok: "border-emerald-300 bg-emerald-50 text-emerald-800 dark:border-emerald-500/35 dark:bg-emerald-500/12 dark:text-emerald-300",
  busy: "border-blue-300 bg-blue-50 text-blue-800 dark:border-blue-500/35 dark:bg-blue-500/12 dark:text-blue-300",
  attention:
    "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-500/35 dark:bg-amber-500/12 dark:text-amber-300",
  problem:
    "border-red-300 bg-red-50 text-red-800 dark:border-red-500/35 dark:bg-red-500/12 dark:text-red-300",
  idle: "border-slate-300 bg-slate-50 text-slate-600 dark:border-border dark:bg-muted dark:text-muted-foreground",
}

// Done and correct.
const ok = new Set([
  "credentials_ready",
  "completed",
  "complete",
  "ready",
  "configured",
  "healthy",
  "pass",
  "self_serve",
  "managed_auth_ready",
  "browser_ready",
  "owner_submit_ready",
  "outreach_ready",
  "verified",
])
// Ended badly.
const problem = new Set(["blocked", "failed", "fail"])
// Working, or waiting on something that is not you.
const busy = new Set([
  "researching",
  "route_selected",
  "browser_running",
  "running",
  "validating_credentials",
  "waiting_for_reply",
  "outreach_sent",
  "configured_not_verified",
])
// Stopped for a person.
const attention = new Set([
  "waiting_for_hitl",
  "waiting",
  "configuration_required",
  "connection_required",
  "approval_required",
  "not_configured",
  "outreach_review_required",
  "gated",
  "partner_gated",
  "managed_auth",
  "hybrid",
  "playwright",
])
// Off, absent, or not reported.
const idle = new Set([
  "unknown",
  "not_reported",
  "unavailable",
  "not_available",
  "not_started",
  "not_attempted",
  "disabled",
  "policy_unavailable",
])

function tone(status: string): Tone {
  if (ok.has(status)) return "ok"
  if (problem.has(status)) return "problem"
  if (attention.has(status)) return "attention"
  if (busy.has(status)) return "busy"
  if (idle.has(status)) return "idle"
  return "idle"
}

// What the status means, in the words an operator would use. Shown as the
// badge's title so the vocabulary never has to be learned from colour alone.
const MEANING: Record<string, string> = {
  configured_not_verified: "Set up, but not yet proven to work by a live check.",
  not_configured: "Missing configuration. This cannot run until it is set.",
  configuration_required: "Something must be configured before this run continues.",
  connection_required: "An account must be connected before this run continues.",
  waiting_for_hitl: "Paused: the website needs a person to act.",
  waiting_for_reply: "Waiting on an email reply. No action needed from you.",
  outreach_sent: "An email went out. Waiting on the reply.",
  disabled: "Turned off by policy. Not a fault.",
  ready: "Checked and working.",
  verified: "Checked and working.",
  pass: "This check passed.",
  fail: "This check did not pass.",
  failed: "This run ended without credentials.",
  blocked: "This run cannot continue on its own.",
  unavailable: "No answer from the backend. Nothing is assumed.",
  not_reported: "The backend did not report this. Nothing is assumed.",
}

// Statuses whose internal name is not English. The wire value is unchanged and
// still reaches the title; only the word on screen is the operator's word.
const LABEL: Record<string, string> = {
  waiting_for_hitl: "Needs you",
  configured_not_verified: "Not yet checked",
  configuration_required: "Needs setup",
  connection_required: "Needs connecting",
  outreach_review_required: "Needs review",
  managed_auth: "Connect account",
  partner_gated: "Partner approval",
  self_serve: "Self serve",
  credentials_ready: "Credentials ready",
  not_reported: "Not reported",
}

export function StatusBadge({ status, className }: { status?: string | null; className?: string }) {
  const value = status ?? "not_reported"
  return (
    <Badge
      variant="outline"
      title={MEANING[value]}
      className={cn(
        "max-w-full rounded-md px-2 py-1 font-mono text-[11px] uppercase tracking-[0.1em]",
        TONE_CLASS[tone(value)],
        className,
      )}
    >
      <span className="size-1.5 shrink-0 rounded-full bg-current" aria-hidden="true" />
      {LABEL[value] ?? humanize(value)}
    </Badge>
  )
}
