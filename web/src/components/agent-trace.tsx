"use client"

import { useMemo } from "react"

import {
  ChainOfThought,
  ChainOfThoughtContent,
  ChainOfThoughtHeader,
  ChainOfThoughtStep,
} from "@/components/chain-of-thought/chain-of-thought"
import type { ChainOfThoughtStepStatus } from "@/components/chain-of-thought/chain-of-thought"
import {
  InlineCitation,
  InlineCitationCard,
  InlineCitationCardBody,
  InlineCitationCardTrigger,
  InlineCitationSource,
} from "@/components/inline-citation/inline-citation"
import {
  Reasoning,
  ReasoningContent,
  ReasoningTrigger,
} from "@/components/reasoning/reasoning"
import { ToolCallChip } from "@/components/tool-call-chip/tool-call-chip"
import type { ToolCallState } from "@/components/tool-call-chip/tool-call-chip"
import { formatTimestamp, humanize, relativeTimestamp } from "@/lib/format"
import type {
  LoopStage,
  RunCitation,
  RunDecision,
  RunProgressEvent,
} from "@/lib/types"

/**
 * The agent's reasoning trace for one run.
 *
 * Two durable, independently written record sets are zipped on `step_index`:
 * `progress` (which stage the loop reached and how long it took) and
 * `decisions` (what the model chose and why). The loop writes exactly one
 * progress row per iteration, so the join is one-to-one; a step present in
 * only one set still renders from what exists rather than being dropped.
 *
 * Nothing here is derived, inferred, or filled in. A decision without a reason
 * says the reason was withheld. A run with no citations shows no sources.
 */

const STAGE_STATE: Record<LoopStage, ToolCallState> = {
  observe: "done",
  candidates: "done",
  decide: "done",
  act: "running",
  verify: "done",
  gate: "done",
  exhausted: "error",
}

const DECISION_LABEL: Record<RunDecision["decision"], string> = {
  select_candidate: "Chose an element to act on",
  report_hitl: "Handed off to a human",
  report_blocked: "Reported the route blocked",
  rejected: "Rejected the model's choice",
}

interface TraceStep {
  stepIndex: number
  phase: string
  stage: LoopStage | null
  elapsedMs: number | null
  decision: RunDecision | null
  recordedAt: string
}

interface TracePhase {
  phase: string
  steps: TraceStep[]
}

/** Group consecutive steps by onboarding phase, preserving loop order. */
function buildPhases(
  progress: RunProgressEvent[],
  decisions: RunDecision[],
): TracePhase[] {
  const byStep = new Map<number, RunDecision>()
  for (const decision of decisions) byStep.set(decision.step_index, decision)

  const steps: TraceStep[] = progress.map((event) => ({
    stepIndex: event.step_index,
    phase: event.onboarding_phase,
    stage: event.stage,
    elapsedMs: event.elapsed_ms,
    decision: byStep.get(event.step_index) ?? null,
    recordedAt: event.recorded_at,
  }))

  // A decision whose progress row is missing (a partially written iteration)
  // is still the agent's reasoning and must not vanish from the trace.
  const seen = new Set(progress.map((event) => event.step_index))
  for (const decision of decisions) {
    if (seen.has(decision.step_index)) continue
    steps.push({
      stepIndex: decision.step_index,
      phase: decision.onboarding_phase,
      stage: null,
      elapsedMs: null,
      decision,
      recordedAt: decision.recorded_at,
    })
  }
  steps.sort((left, right) => left.stepIndex - right.stepIndex)

  const grouped: TracePhase[] = []
  for (const step of steps) {
    const current = grouped.at(-1)
    if (current && current.phase === step.phase) current.steps.push(step)
    else grouped.push({ phase: step.phase, steps: [step] })
  }
  return grouped
}

function stepStatus(step: TraceStep, isLast: boolean): ChainOfThoughtStepStatus {
  if (step.stage === "exhausted") return "complete"
  if (isLast && step.stage === "act") return "active"
  return "complete"
}

export function AgentTrace({
  progress,
  decisions,
  citations,
  decisionModel,
  decisionEffort,
}: {
  progress: RunProgressEvent[]
  decisions: RunDecision[]
  citations: RunCitation[]
  decisionModel?: string | null
  decisionEffort?: string | null
}) {
  const phases = useMemo(
    () => buildPhases(progress, decisions),
    [progress, decisions],
  )

  if (!phases.length && !citations.length) return null

  const lastStepIndex = phases.at(-1)?.steps.at(-1)?.stepIndex ?? -1

  return (
    <section aria-labelledby="agent-trace">
      <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="eyebrow">Live agent reasoning</p>
          <h2 id="agent-trace" className="mt-1 text-xl font-semibold">
            Chain of thought
          </h2>
        </div>
        {decisionModel ? (
          <p className="font-mono text-2xs uppercase tracking-[0.1em] text-muted-foreground">
            {decisionModel}
            {decisionEffort ? ` · effort ${decisionEffort}` : null}
          </p>
        ) : null}
      </div>

      <div className="panel space-y-6 rounded-md px-5 py-5">
        {phases.length ? (
          phases.map((group, index) => (
            <div key={`${group.phase}-${group.steps[0]?.stepIndex ?? index}`}>
              <p className="data-label mb-2">{humanize(group.phase)}</p>
              <ChainOfThought defaultOpen>
                <ChainOfThoughtHeader>
                  <span>
                    {group.steps.length} step
                    {group.steps.length === 1 ? "" : "s"}
                  </span>
                </ChainOfThoughtHeader>
                <ChainOfThoughtContent>
                  {group.steps.map((step) => (
                    <TraceStepView
                      key={step.stepIndex}
                      step={step}
                      isLast={step.stepIndex === lastStepIndex}
                    />
                  ))}
                </ChainOfThoughtContent>
              </ChainOfThought>
            </div>
          ))
        ) : (
          <p className="text-xs leading-5 text-muted-foreground">
            No loop decisions were recorded for this run.
          </p>
        )}

        {citations.length ? <TraceSources citations={citations} /> : null}
      </div>
    </section>
  )
}

function TraceStepView({ step, isLast }: { step: TraceStep; isLast: boolean }) {
  const decision = step.decision
  const label = decision
    ? DECISION_LABEL[decision.decision]
    : `Loop stage · ${humanize(step.stage ?? "unknown")}`

  const seconds =
    step.elapsedMs === null ? null : Math.max(0, Math.round(step.elapsedMs / 1000))

  return (
    <ChainOfThoughtStep
      label={label}
      status={stepStatus(step, isLast)}
      description={
        <span>
          Step {step.stepIndex}
          {step.stage ? ` · ${humanize(step.stage)}` : ""}
          {seconds === null ? "" : ` · ${seconds}s`}
          {" · "}
          <time dateTime={step.recordedAt} title={formatTimestamp(step.recordedAt)}>
            {relativeTimestamp(step.recordedAt)}
          </time>
        </span>
      }
    >
      {decision?.action ? (
        <div className="pt-1">
          <ToolCallChip
            name={decision.action}
            detail={decision.target_host ?? decision.candidate_label ?? undefined}
            state={
              decision.decision === "select_candidate"
                ? (STAGE_STATE[step.stage ?? "decide"] ?? "done")
                : decision.decision === "rejected"
                  ? "error"
                  : "done"
            }
          />
        </div>
      ) : null}

      {decision?.candidate_label && !decision.action ? (
        <p className="pt-1 font-mono text-2xs text-muted-foreground/70">
          {decision.candidate_label}
        </p>
      ) : null}

      {decision?.reason_code ? (
        <p className="pt-1 font-mono text-2xs uppercase tracking-[0.1em] text-muted-foreground/60">
          {humanize(decision.reason_code)}
        </p>
      ) : null}

      {decision ? <DecisionReason decision={decision} /> : null}
    </ChainOfThoughtStep>
  )
}

/**
 * The model's own words about the step.
 *
 * Two things are non-negotiable here. The text is rendered by
 * `ReasoningContent`, which is a plain `<p>` — never markdown, so it cannot
 * introduce a link, an image, or embedded HTML. And it is labelled
 * model-authored and unverified, because it is prose about a live third-party
 * page that nothing has checked.
 */
function DecisionReason({ decision }: { decision: RunDecision }) {
  if (decision.reason_withheld) {
    return (
      <p className="pt-1 text-xs leading-5 text-muted-foreground/70">
        Reasoning withheld — the text did not pass the secret-material screen.
      </p>
    )
  }

  if (!decision.reason) return null

  return (
    <Reasoning className="mt-1.5">
      <ReasoningTrigger>
        <span>Reasoning · model-authored · unverified</span>
      </ReasoningTrigger>
      {/* Kept mounted so the trace stays findable with the browser's own
          find-in-page even while the fold is closed. */}
      <ReasoningContent keepMounted>{decision.reason}</ReasoningContent>
    </Reasoning>
  )
}

/** Every source the run recorded, deduplicated by the backend, grouped by kind. */
function TraceSources({ citations }: { citations: RunCitation[] }) {
  const byKind = new Map<string, RunCitation[]>()
  for (const citation of citations) {
    const bucket = byKind.get(citation.kind)
    if (bucket) bucket.push(citation)
    else byKind.set(citation.kind, [citation])
  }

  return (
    <div className="border-t border-border pt-4">
      <p className="data-label mb-2">Sources · {citations.length}</p>
      <div className="flex flex-wrap items-center gap-x-1 gap-y-2">
        {[...byKind.entries()].map(([kind, group]) => (
          <InlineCitation key={kind}>
            <span className="text-xs text-muted-foreground">{humanize(kind)}</span>
            <InlineCitationCard>
              <InlineCitationCardTrigger
                sources={group.map((citation) => citation.url)}
              />
              <InlineCitationCardBody>
                {group.map((citation) => (
                  <InlineCitationSource
                    key={citation.url}
                    title={humanize(citation.kind)}
                    url={citation.url}
                    description={
                      citation.source_url
                        ? `Recorded from ${citation.source_url}`
                        : undefined
                    }
                  />
                ))}
              </InlineCitationCardBody>
            </InlineCitationCard>
          </InlineCitation>
        ))}
      </div>
    </div>
  )
}
