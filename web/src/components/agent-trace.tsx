"use client"

import { CircleSlash, Cpu, Eye, Hand, ListChecks, PlayCircle, ShieldCheck } from "lucide-react"
import type { LucideIcon } from "lucide-react"

import {
  ChainOfThought,
  ChainOfThoughtContent,
  ChainOfThoughtHeader,
  ChainOfThoughtSearchResult,
  ChainOfThoughtSearchResults,
  ChainOfThoughtStep,
} from "@/components/ai-elements/chain-of-thought"
import { humanize, relativeTimestamp } from "@/lib/format"
import type {
  DecisionAttempt,
  LoopStage,
  PhaseBoundary,
  ResearchFactGroup,
  RunProgressEvent,
} from "@/lib/types"
import { cn } from "@/lib/utils"

/**
 * The agent's reasoning, read from what the backend already records.
 *
 * This renders STRUCTURED reasoning, not model prose, and that is a constraint
 * rather than a shortcut. `ops/core/storage.py` states that the telemetry tables
 * have "no column a prompt, a page projection, or a URL could be written into",
 * and `api/models.py` states that the absence of any free-text field is what
 * makes "no prompts, no reasoning traces" structurally true rather than
 * review-enforced. So every label here is composed from a closed vocabulary:
 * phase names, typed reason codes, loop stages, providers, durations.
 *
 * Two sources:
 *
 *   phase boundaries  from `timeline.boundaries` — the densest reasoning trail
 *                     there is: `from_phase → to_phase` plus the reason code
 *                     that explains the move (`candidate_gate_model_declined`,
 *                     `step_retried`, `operator_approved_signup`).
 *   loop iterations   from `timeline.progress`, parsed by `api-schemas.ts` and
 *                     then dropped on the floor at the page boundary.
 *
 * Duration is drawn as WIDTH, so a slow decide step is visibly wide and the
 * millisecond number earns its place instead of sitting in a label.
 *
 * A CLIENT component, deliberately. `PHASE_ICON` resolves to Lucide component
 * functions, and functions cannot cross the RSC boundary — as a server component
 * this threw "Functions cannot be passed directly to Client Components" for every
 * node, the run page's Suspense boundaries never resolved, and the whole page sat
 * on skeletons. jsdom tests render client-side and so cannot catch that; the
 * server log is what surfaced it. Every prop here is serializable data, so the
 * page still fetches on the server and only rendering happens on the client.
 */

const STAGE_ORDER: readonly LoopStage[] = [
  "observe",
  "candidates",
  "decide",
  "act",
  "verify",
  "gate",
] as const

/** What each loop stage means, in the operator's terms rather than the code's. */
const STAGE_LABEL: Record<LoopStage, string> = {
  observe: "Read the page",
  candidates: "Generated the options policy allows",
  decide: "Chose one option",
  act: "Performed it",
  verify: "Checked what changed",
  gate: "Handed to a person",
  exhausted: "Spent its budget",
}

const PHASE_ICON: Record<string, LucideIcon> = {
  research: Eye,
  vault_check: ShieldCheck,
  awaiting_admission: Hand,
  route_selected_signup: ListChecks,
  route_selected_login: ListChecks,
  signup: PlayCircle,
  email_verification: Eye,
  authenticated: ShieldCheck,
  developer_app: Cpu,
  credential_generation: Cpu,
  vault_storage: ShieldCheck,
  credential_validation: ShieldCheck,
  paused: Hand,
  captcha_paused: Hand,
  blocked: CircleSlash,
  cancelled: CircleSlash,
  completed: ShieldCheck,
}

/** Phases that mean the run is over, one way or another. */
const TERMINAL = new Set(["completed", "blocked", "cancelled"])
/** Phases that mean the agent stopped and is waiting for a person. */
const HELD = new Set(["paused", "captcha_paused", "awaiting_admission"])

type Node = {
  key: string
  phase: string
  from?: string
  reasonCode: string
  attempt: number
  at: string
  status: "complete" | "active" | "halted"
}

/**
 * The spine, oldest first.
 *
 * Read from `timeline.boundaries` — the committed phase history — rather than
 * mined out of `timeline.items`. That distinction is load-bearing: audit events
 * carry no phase at all (every one of them has `correlation: null` in practice),
 * so an implementation that filtered `items` for a phase would render an empty
 * trace on a real run. The boundary rows are the driver's own record of what it
 * decided.
 *
 * Arrives ordered by `sequence`; sorted here anyway so the view does not depend
 * on transport order.
 */
function spine(boundaries: readonly PhaseBoundary[]): Node[] {
  const nodes: Node[] = boundaries
    .slice()
    .sort((a, b) => a.sequence - b.sequence)
    .map((boundary) => ({
      key: String(boundary.sequence),
      phase: boundary.to_phase,
      from: boundary.from_phase ?? undefined,
      reasonCode: boundary.reason_code,
      attempt: boundary.attempt,
      at: boundary.committed_at,
      status: "complete" as const,
    }))

  const last = nodes.at(-1)
  if (last) {
    last.status = TERMINAL.has(last.phase)
      ? "complete"
      : HELD.has(last.phase)
        ? "halted"
        : "active"
  }
  return nodes
}

/**
 * Loop iterations belonging to ONE visit to a phase, oldest first, grouped by step.
 *
 * Matching on phase name alone is wrong once a run re-enters a phase: a retry
 * produces two `signup` boundaries, and every `signup` iteration would then be
 * drawn under both of them — the same work reported twice, which reads as more
 * progress than the agent made. So an iteration is attributed to the visit whose
 * window contains it: at or after this boundary, and before the next one.
 */
function iterations(
  progress: readonly RunProgressEvent[],
  phase: string,
  from: string,
  until: string | undefined,
): { step: number; events: RunProgressEvent[] }[] {
  const forPhase = progress
    .filter(
      (event) =>
        event.onboarding_phase === phase &&
        event.recorded_at >= from &&
        (until === undefined || event.recorded_at < until),
    )
    .slice()
    .sort((a, b) => a.recorded_at.localeCompare(b.recorded_at))

  const steps = new Map<number, RunProgressEvent[]>()
  for (const event of forPhase) {
    const bucket = steps.get(event.step_index)
    if (bucket) bucket.push(event)
    else steps.set(event.step_index, [event])
  }
  return [...steps.entries()]
    .sort(([a], [b]) => a - b)
    .map(([step, events]) => ({ step, events }))
}

/**
 * Model attempts belonging to ONE visit to a phase, oldest first.
 *
 * Same time-window attribution as `iterations` above, and for the same reason —
 * see that comment. These rows carry no correlation id at all (the table has no
 * such column), so a window is the only attribution available.
 */
function attemptsFor(
  attempts: readonly DecisionAttempt[],
  phase: string,
  from: string,
  until: string | undefined,
): DecisionAttempt[] {
  return attempts
    .filter(
      (attempt) =>
        attempt.onboarding_phase === phase &&
        attempt.recorded_at >= from &&
        (until === undefined || attempt.recorded_at < until),
    )
    .slice()
    .sort((a, b) => a.recorded_at.localeCompare(b.recorded_at))
}

/**
 * One research refusal, in the operator's words rather than the vocabulary's.
 *
 * Composed client-side from closed values — that is the whole reason this can be
 * shown at all. `kind` is an enum, `field` is a `ProfileField`, the corroboration
 * numbers are bounded ints. Nothing here is a string the backend stored.
 */
function factLine(group: ResearchFactGroup): string {
  const parts = [humanize(group.kind)]
  if (group.field) parts.push(group.field)
  if (group.adapter) parts.push(group.adapter)
  if (group.count !== null && group.count !== undefined) parts.push(`${group.count} URLs`)
  if (
    group.corroborations !== null &&
    group.corroborations !== undefined &&
    group.corroborations_required !== null &&
    group.corroborations_required !== undefined
  ) {
    parts.push(`${group.corroborations} of ${group.corroborations_required} sources`)
  }
  return parts.join(" · ")
}

function ResearchRefusals({ groups }: { groups: readonly ResearchFactGroup[] }) {
  return (
    <div className="flex flex-col gap-1.5 rounded-md border border-border bg-secondary/40 p-2.5">
      <span className="font-mono text-[10px] tracking-[0.06em] text-muted-foreground">
        Refused to believe
      </span>
      <ul className="flex flex-col gap-1">
        {groups.map((group) => (
          <li
            key={`${group.kind}-${group.field ?? group.adapter ?? group.count ?? ""}`}
            className="flex items-baseline justify-between gap-3"
          >
            <span className="font-mono text-[10px] leading-4 tracking-[0.06em] text-foreground">
              {factLine(group)}
            </span>
            {group.occurrences > 1 ? (
              <span className="shrink-0 font-mono text-[10px] tabular-nums text-muted-foreground">
                ×{group.occurrences}
              </span>
            ) : null}
          </li>
        ))}
      </ul>
    </div>
  )
}

/** Widest bar in the trace, so every bar is scaled against one denominator. */
function widthFor(elapsedMs: number, slowestMs: number): string {
  if (slowestMs <= 0) return "6%"
  const ratio = Math.sqrt(Math.max(elapsedMs, 1) / slowestMs)
  return `${Math.max(6, Math.min(100, Math.round(ratio * 100)))}%`
}

function StageTrack({
  events,
  step,
  slowestMs,
}: {
  events: readonly RunProgressEvent[]
  step: number
  slowestMs: number
}) {
  const reached = new Map(events.map((event) => [event.stage, event]))
  const lastStage = events.at(-1)?.stage

  return (
    <div className="flex flex-col gap-1.5 rounded-md border border-border bg-secondary/40 p-2.5">
      <span className="font-mono text-[10px] tracking-[0.06em] text-muted-foreground">
        Step {step}
      </span>
      <ol className="flex flex-col gap-1">
        {STAGE_ORDER.map((stage) => {
          const event = reached.get(stage)
          const live = stage === lastStage
          return (
            <li key={stage} className="grid grid-cols-[7rem_1fr_3.5rem] items-center gap-2">
              <span
                className={cn(
                  "truncate font-mono text-[10px] tracking-[0.06em]",
                  event ? "text-foreground" : "text-muted-foreground/50",
                )}
              >
                {stage}
              </span>
              <span className="flex h-[3px] items-center">
                {event ? (
                  <span
                    className="stage-bar"
                    data-live={live ? "true" : "false"}
                    style={{ width: widthFor(event.elapsed_ms, slowestMs) }}
                  />
                ) : (
                  <span aria-hidden className="h-px w-full bg-border/60" />
                )}
              </span>
              <span
                className={cn(
                  "text-right font-mono text-[10px] tabular-nums",
                  event ? "text-muted-foreground" : "text-muted-foreground/40",
                )}
              >
                {event ? `${event.elapsed_ms}ms` : "—"}
              </span>
            </li>
          )
        })}
      </ol>
      {lastStage ? (
        <span className="font-mono text-[10px] tracking-[0.06em] text-muted-foreground">
          {STAGE_LABEL[lastStage]}
        </span>
      ) : null}
    </div>
  )
}

/**
 * Which model was asked, and what it cost.
 *
 * Deliberately the same grid and the same `slowestMs` denominator as `StageTrack`,
 * so a 900ms model call and a 900ms loop stage draw the same width — the operator
 * is comparing where the time went, and two scales would make that a lie.
 *
 * `outcome` is shown only when it is not `usable`: a working provider needs no
 * word, and a failing one is then the only text in the block.
 */
function ProviderTrack({
  attempts,
  slowestMs,
}: {
  attempts: readonly DecisionAttempt[]
  slowestMs: number
}) {
  const purpose = attempts[0]?.purpose ?? "action"

  return (
    <div className="flex flex-col gap-1.5 rounded-md border border-border bg-secondary/40 p-2.5">
      <span className="font-mono text-[10px] tracking-[0.06em] text-muted-foreground">
        {purpose === "plan" ? "Planner model" : "Model"}
      </span>
      <ol className="flex flex-col gap-1">
        {attempts.map((attempt, index) => (
          <li
            key={`${attempt.recorded_at}-${attempt.provider}-${index}`}
            className="grid grid-cols-[7rem_1fr_3.5rem] items-center gap-2"
          >
            <span className="truncate font-mono text-[10px] tracking-[0.06em] text-foreground">
              {attempt.provider}
            </span>
            <span className="flex h-[3px] items-center">
              <span
                className="stage-bar"
                data-live={attempt.outcome === "usable" ? "true" : "false"}
                style={{ width: widthFor(attempt.latency_ms, slowestMs) }}
              />
            </span>
            <span className="text-right font-mono text-[10px] tabular-nums text-muted-foreground">
              {attempt.latency_ms}ms
            </span>
            {attempt.outcome === "usable" ? null : (
              <span className="col-span-3 font-mono text-[10px] tracking-[0.06em] text-muted-foreground">
                {attempt.outcome}
              </span>
            )}
          </li>
        ))}
      </ol>
    </div>
  )
}

export function AgentTrace({
  boundaries,
  progress,
  attempts = [],
  research = [],
  className,
}: {
  boundaries: readonly PhaseBoundary[]
  progress: readonly RunProgressEvent[]
  attempts?: readonly DecisionAttempt[]
  research?: readonly ResearchFactGroup[]
  className?: string
}) {
  const nodes = spine(boundaries)
  if (nodes.length === 0) return null

  // One denominator across the whole trace, so bar widths are comparable between
  // phases rather than only within one — and shared with the model attempts, so a
  // slow provider and a slow loop stage are visibly the same size.
  const slowestMs = Math.max(
    progress.reduce((max, event) => Math.max(max, event.elapsed_ms), 0),
    attempts.reduce((max, attempt) => Math.max(max, attempt.latency_ms), 0),
  )

  // Where the research refusals hang. See the comment at the use site below.
  const leavesResearch = nodes.findIndex((node) => node.from === "research")
  const researchNodeIndex = leavesResearch === -1 ? 0 : leavesResearch

  return (
    <ChainOfThought defaultOpen className={className}>
      <ChainOfThoughtHeader>
        Chain of thought · {nodes.length} {nodes.length === 1 ? "decision" : "decisions"}
      </ChainOfThoughtHeader>
      <ChainOfThoughtContent>
        {nodes.map((node, index) => {
          const until = nodes[index + 1]?.at
          const steps = iterations(progress, node.phase, node.at, until)
          const asked = attemptsFor(attempts, node.phase, node.at, until)
          // Research facts belong to the phase they were gathered in, but no
          // boundary ever ENTERS `research` — the driver commits
          // `research -> vault_check` only after research finishes. So they hang
          // off the node that leaves it, falling back to the first node on a run
          // whose trace starts later.
          const refusals = index === researchNodeIndex ? research : []
          return (
            <ChainOfThoughtStep
              key={node.key}
              icon={PHASE_ICON[node.phase] ?? Cpu}
              status={node.status}
              label={
                node.from ? (
                  <span className="flex flex-wrap items-baseline gap-1.5">
                    <span className="text-muted-foreground">{humanize(node.from)}</span>
                    <span aria-hidden className="text-muted-foreground/60">
                      →
                    </span>
                    <span>{humanize(node.phase)}</span>
                  </span>
                ) : (
                  humanize(node.phase)
                )
              }
              description={[
                node.reasonCode,
                node.attempt > 0 ? `attempt ${node.attempt}` : null,
                relativeTimestamp(node.at),
              ]
                .filter(Boolean)
                .join(" · ")}
              // Staggered by POSITION IN THE TRACE, not by mount order: the run
              // page calls `router.refresh()` every 4s, and a mount-keyed
              // animation would replay on every poll and strobe the page.
              className="trace-node"
              style={{ animationDelay: `${Math.min(index, 12) * 18}ms` }}
            >
              {steps.length > 0 || asked.length > 0 || refusals.length > 0 ? (
                <div className="mt-1 flex flex-col gap-1.5">
                  {steps.map(({ step, events }) => (
                    <StageTrack key={step} step={step} events={events} slowestMs={slowestMs} />
                  ))}
                  {asked.length > 0 ? (
                    <ProviderTrack attempts={asked} slowestMs={slowestMs} />
                  ) : null}
                  {refusals.length > 0 ? <ResearchRefusals groups={refusals} /> : null}
                </div>
              ) : null}
            </ChainOfThoughtStep>
          )
        })}
      </ChainOfThoughtContent>
    </ChainOfThought>
  )
}

export function AgentTraceLegend() {
  return (
    <ChainOfThoughtSearchResults>
      {STAGE_ORDER.map((stage) => (
        <ChainOfThoughtSearchResult key={stage}>{stage}</ChainOfThoughtSearchResult>
      ))}
    </ChainOfThoughtSearchResults>
  )
}
