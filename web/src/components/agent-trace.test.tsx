import { render, screen } from "@testing-library/react"
import { axe } from "jest-axe"

import { AgentTrace } from "@/components/agent-trace"
import type {
  DecisionAttempt,
  DecisionOutcome,
  LoopStage,
  OnboardingPhase,
  PhaseBoundary,
  RunProgressEvent,
} from "@/lib/types"

/**
 * The trace is built from data the run page already fetched, so these tests use
 * the real shapes rather than a bespoke fixture type. The rows mirror the live
 * DB: a signup run that reached a gate, was declined by the model, and retried.
 */

function boundary(
  sequence: number,
  from: OnboardingPhase | null,
  to: OnboardingPhase,
  reasonCode: string,
  attempt = 0,
): PhaseBoundary {
  return {
    sequence,
    from_phase: from,
    to_phase: to,
    reason_code: reasonCode,
    attempt,
    profile_digest: "086dd1bc",
    committed_at: `2026-08-02T05:0${sequence}:00.000Z`,
  }
}

function attempt(
  provider: string,
  latencyMs: number,
  outcome: DecisionOutcome = "usable",
  recordedAt = "2026-08-02T05:01:30.000Z",
  phase: OnboardingPhase = "signup",
): DecisionAttempt {
  return {
    purpose: "action",
    provider,
    outcome,
    latency_ms: latencyMs,
    onboarding_phase: phase,
    recorded_at: recordedAt,
  }
}

function step(stage: LoopStage, elapsedMs: number, stepIndex = 1): RunProgressEvent {
  return {
    step_index: stepIndex,
    stage,
    elapsed_ms: elapsedMs,
    onboarding_phase: "signup",
    recorded_at: `2026-08-02T05:04:1${elapsedMs % 10}.000Z`,
  }
}

describe("AgentTrace", () => {
  it("renders nothing when the run has committed no phase boundaries", () => {
    const { container } = render(<AgentTrace boundaries={[]} progress={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it("shows each phase transition with the reason code that explains it", () => {
    render(
      <AgentTrace
        boundaries={[
          boundary(1, "research", "vault_check", "profile_corroborated"),
          boundary(2, "vault_check", "awaiting_admission", "signup_authorization_required"),
          boundary(3, "route_selected_signup", "signup", "operator_approved_signup"),
        ]}
        progress={[]}
      />,
    )

    // The reason code is the agent's own account of why it moved, so it is shown
    // verbatim rather than prettified.
    expect(screen.getByText(/profile_corroborated/)).toBeInTheDocument()
    expect(screen.getByText(/signup_authorization_required/)).toBeInTheDocument()
    expect(screen.getByText("Signup")).toBeInTheDocument()
  })

  it("shows both sides of the transition, not just where the run landed", () => {
    render(
      <AgentTrace
        boundaries={[boundary(1, "route_selected_signup", "signup", "operator_approved_signup")]}
        progress={[]}
      />,
    )

    expect(screen.getByText("Route Selected Signup")).toBeInTheDocument()
    expect(screen.getByText("Signup")).toBeInTheDocument()
  })

  it("marks the newest boundary active and the earlier ones complete", () => {
    render(
      <AgentTrace
        boundaries={[
          boundary(1, "research", "vault_check", "profile_corroborated"),
          boundary(2, "route_selected_signup", "signup", "entered"),
        ]}
        progress={[]}
      />,
    )

    const steps = document.querySelectorAll("[data-slot='chain-of-thought-step']")
    expect(steps).toHaveLength(2)
    expect(steps[0]).toHaveAttribute("data-status", "complete")
    expect(steps[1]).toHaveAttribute("data-status", "active")
  })

  it("marks a paused run as halted rather than active, since it awaits a person", () => {
    render(
      <AgentTrace
        boundaries={[
          boundary(1, "route_selected_signup", "signup", "entered"),
          boundary(2, "signup", "paused", "candidate_gate_model_declined"),
        ]}
        progress={[]}
      />,
    )

    const steps = document.querySelectorAll("[data-slot='chain-of-thought-step']")
    expect(steps[steps.length - 1]).toHaveAttribute("data-status", "halted")
  })

  it("renders loop stages with duration as bar width, widest for the slowest step", () => {
    render(
      <AgentTrace
        boundaries={[boundary(1, "route_selected_signup", "signup", "entered")]}
        progress={[step("observe", 4), step("decide", 884), step("gate", 897)]}
      />,
    )

    expect(screen.getByText("4ms")).toBeInTheDocument()
    expect(screen.getByText("884ms")).toBeInTheDocument()

    const bars = document.querySelectorAll(".stage-bar")
    expect(bars.length).toBe(3)
    // The 4ms observe must be visibly narrower than the 897ms gate.
    const first = (bars[0] as HTMLElement).style.width
    const last = (bars[bars.length - 1] as HTMLElement).style.width
    expect(Number.parseInt(first, 10)).toBeLessThan(Number.parseInt(last, 10))
  })

  it("attributes an iteration to the one visit that contains it, not every visit", () => {
    // A retried run enters `signup` twice. Matching on phase name alone drew the
    // same iteration under both boundaries, reporting work the agent did once as
    // if it had happened twice.
    const first = boundary(1, "route_selected_signup", "signup", "entered")
    const paused = boundary(2, "signup", "paused", "candidate_gate_model_declined")
    const retried = boundary(3, "paused", "signup", "step_retried", 1)

    render(
      <AgentTrace
        boundaries={[first, paused, retried]}
        progress={[
          { ...step("observe", 12), recorded_at: "2026-08-02T05:01:30.000Z" },
          { ...step("decide", 640), recorded_at: "2026-08-02T05:03:30.000Z" },
        ]}
      />,
    )

    const steps = document.querySelectorAll("[data-slot='chain-of-thought-step']")
    // The 05:01:30 observe falls inside the first visit (05:01 → 05:02); the
    // 05:03:30 decide falls inside the retry (05:03 → now). One bar each.
    expect(steps[0]?.textContent).toContain("12ms")
    expect(steps[0]?.textContent).not.toContain("640ms")
    expect(steps[2]?.textContent).toContain("640ms")
    expect(steps[2]?.textContent).not.toContain("12ms")
    expect(document.querySelectorAll(".stage-bar")).toHaveLength(2)
  })

  it("shows stages the run never reached as unreached rather than omitting them", () => {
    render(
      <AgentTrace
        boundaries={[boundary(1, "route_selected_signup", "signup", "entered")]}
        progress={[step("observe", 4)]}
      />,
    )

    // `act` never happened; the rail still lists it so the gap is visible.
    expect(screen.getByText("act")).toBeInTheDocument()
    expect(screen.getAllByText("—").length).toBeGreaterThan(0)
  })

  it("keeps every committed boundary, including a re-entry of the same phase", () => {
    // The backend commits one row per transition it actually took, so a repeat of
    // a phase is a real second attempt rather than a duplicate to collapse.
    // Dropping it would hide the retry the operator most needs to see.
    render(
      <AgentTrace
        boundaries={[
          boundary(1, "route_selected_signup", "signup", "entered"),
          boundary(2, "signup", "paused", "candidate_gate_model_declined"),
          boundary(3, "paused", "signup", "step_retried", 1),
        ]}
        progress={[]}
      />,
    )

    expect(document.querySelectorAll("[data-slot='chain-of-thought-step']")).toHaveLength(3)
    expect(screen.getByText(/attempt 1/)).toBeInTheDocument()
  })

  it("orders the spine by sequence, not by the order the transport supplied", () => {
    render(
      <AgentTrace
        boundaries={[
          boundary(3, "route_selected_signup", "signup", "entered"),
          boundary(1, null, "research", "profile_corroborated"),
        ]}
        progress={[]}
      />,
    )

    const labels = [...document.querySelectorAll("[data-slot='chain-of-thought-step']")].map(
      (node) => node.textContent ?? "",
    )
    expect(labels[0]).toContain("Research")
    expect(labels[1]).toContain("Signup")
  })

  it("renders the run's first boundary, which has no prior phase", () => {
    render(
      <AgentTrace boundaries={[boundary(1, null, "research", "run_created")]} progress={[]} />,
    )

    const steps = document.querySelectorAll("[data-slot='chain-of-thought-step']")
    expect(steps).toHaveLength(1)
    expect(steps[0]?.textContent).toContain("Research")
    // No phantom arrow when there is nothing to transition from.
    expect(steps[0]?.textContent).not.toContain("→")
  })

  it("shows which model was asked and what it cost", () => {
    render(
      <AgentTrace
        boundaries={[boundary(1, "route_selected_signup", "signup", "entered")]}
        progress={[]}
        attempts={[attempt("groq", 884)]}
      />,
    )

    expect(screen.getByText("groq")).toBeInTheDocument()
    expect(screen.getByText("884ms")).toBeInTheDocument()
  })

  it("names a failing provider's outcome and stays silent on a working one", () => {
    render(
      <AgentTrace
        boundaries={[boundary(1, "route_selected_signup", "signup", "entered")]}
        progress={[]}
        attempts={[
          attempt("mercury", 84, "rate_limited"),
          attempt("groq", 884, "usable", "2026-08-02T05:01:31.000Z"),
        ]}
      />,
    )

    // A degraded provider is the only text; a usable one needs no word.
    expect(screen.getByText("rate_limited")).toBeInTheDocument()
    expect(screen.queryByText("usable")).not.toBeInTheDocument()
  })

  it("attributes an attempt to the visit that contains it, not every visit", () => {
    render(
      <AgentTrace
        boundaries={[
          boundary(1, "route_selected_signup", "signup", "entered"),
          boundary(2, "signup", "paused", "candidate_gate_model_declined"),
          boundary(3, "paused", "signup", "step_retried", 1),
        ]}
        progress={[]}
        attempts={[
          attempt("groq", 712, "usable", "2026-08-02T05:01:30.000Z"),
          attempt("mercury", 96, "usable", "2026-08-02T05:03:30.000Z"),
        ]}
      />,
    )

    const steps = document.querySelectorAll("[data-slot='chain-of-thought-step']")
    expect(steps[0]?.textContent).toContain("712ms")
    expect(steps[0]?.textContent).not.toContain("96ms")
    expect(steps[2]?.textContent).toContain("96ms")
    expect(steps[2]?.textContent).not.toContain("712ms")
  })

  it("labels a planner attempt distinctly from an action-loop one", () => {
    render(
      <AgentTrace
        boundaries={[boundary(1, null, "research", "run_created")]}
        progress={[]}
        attempts={[
          {
            ...attempt("groq", 640, "usable", "2026-08-02T05:01:30.000Z", "research"),
            purpose: "plan",
          },
        ]}
      />,
    )

    expect(screen.getByText("Planner model")).toBeInTheDocument()
  })

  it("shows what research refused to believe, with its repetition count", () => {
    render(
      <AgentTrace
        boundaries={[boundary(1, "research", "vault_check", "profile_corroborated")]}
        progress={[]}
        research={[
          {
            kind: "field_uncorroborated",
            field: "signup_url",
            corroborations: 1,
            corroborations_required: 2,
            occurrences: 45,
            first_at: "2026-08-02T05:03:50.000000Z",
            last_at: "2026-08-02T05:03:51.000000Z",
          },
        ]}
      />,
    )

    expect(screen.getByText(/Field Uncorroborated/)).toBeInTheDocument()
    expect(screen.getByText(/signup_url/)).toBeInTheDocument()
    expect(screen.getByText(/1 of 2 sources/)).toBeInTheDocument()
    expect(screen.getByText("×45")).toBeInTheDocument()
  })

  it("names nothing beyond the kind when the backend withheld a subject", () => {
    // `url_excluded` carries an observed URL, so the backend projects only its
    // kind. The interface must read as complete rather than broken.
    render(
      <AgentTrace
        boundaries={[boundary(1, "research", "vault_check", "profile_corroborated")]}
        progress={[]}
        research={[
          {
            kind: "url_excluded",
            occurrences: 1,
            first_at: "2026-08-02T05:03:50.000000Z",
            last_at: "2026-08-02T05:03:50.000000Z",
          },
        ]}
      />,
    )

    expect(screen.getByText("Url Excluded")).toBeInTheDocument()
    expect(screen.queryByText("×1")).not.toBeInTheDocument()
  })

  it("hangs refusals on the node that leaves research, since none enters it", () => {
    render(
      <AgentTrace
        boundaries={[
          boundary(1, "research", "vault_check", "profile_corroborated"),
          boundary(2, "vault_check", "signup", "operator_approved_signup"),
        ]}
        progress={[]}
        research={[
          {
            kind: "candidate_urls_capped",
            count: 9,
            occurrences: 1,
            first_at: "2026-08-02T05:03:45.000000Z",
            last_at: "2026-08-02T05:03:45.000000Z",
          },
        ]}
      />,
    )

    const steps = document.querySelectorAll("[data-slot='chain-of-thought-step']")
    expect(steps[0]?.textContent).toContain("Refused to believe")
    expect(steps[1]?.textContent).not.toContain("Refused to believe")
  })

  it("is accessible", async () => {
    const { container } = render(
      <AgentTrace
        boundaries={[
          boundary(1, null, "research", "profile_corroborated"),
          boundary(2, "route_selected_signup", "signup", "entered"),
        ]}
        progress={[step("observe", 4), step("decide", 884)]}
      />,
    )
    expect(await axe(container)).toHaveNoViolations()
  })
})
