import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

import type { OnboardingControlsView, OnboardingStateView } from "@/lib/types"

const mocks = vi.hoisted(() => ({
  decideAdmissionAction: vi.fn(),
  runOnboardingControlAction: vi.fn(),
}))

vi.mock("@/app/runs/[runId]/actions", () => ({
  decideAdmissionAction: mocks.decideAdmissionAction,
  runOnboardingControlAction: mocks.runOnboardingControlAction,
  openLiveView: vi.fn(),
  runPhaseAction: vi.fn(),
  submitBrowserLoginAction: vi.fn(),
  submitBrowserVerificationAction: vi.fn(),
  submitCredentialAction: vi.fn(),
}))

import { OnboardingControlBar } from "@/components/hitl-live-controls"

const RUN_ID = "run_22222222222222222222222222222222"
const DIGEST = "a".repeat(64)

const admissionState: OnboardingStateView = {
  phase: "awaiting_admission",
  phase_at_pause: null,
  profile_digest: DIGEST,
  reason_code: "admission_required",
  goal: "Decide how to authenticate",
  step: "Waiting for an admission decision",
  latest_decision: "No credential found in the vault",
  attempt: 0,
  admission_prompts: 1,
  captcha_prompts: 0,
  correlation_id: "corr_1",
}

// Only admission and pause are projected: reset and the step retry must not be
// rendered, because availability comes from these flags and never from status.
const admissionControls: OnboardingControlsView = {
  can_decide_admission: true,
  can_pause: true,
  can_resume: false,
  can_cancel: false,
  can_reset: false,
  can_retry_step: false,
  retryable_step: null,
  reason_code: "admission_required",
}

describe("OnboardingControlBar", () => {
  beforeEach(() => {
    mocks.decideAdmissionAction.mockReset()
    mocks.runOnboardingControlAction.mockReset()
    mocks.decideAdmissionAction.mockResolvedValue({
      message: "Decision recorded. The agent will create an account on the provider.",
      tone: "neutral",
      route: "signup",
    })
    mocks.runOnboardingControlAction.mockResolvedValue({
      message: "Pausing after Signup. The browser session stays open.",
      tone: "neutral",
      control: "pause",
    })
  })

  it("renders only the projected controls and submits the admission decision with its profile digest", async () => {
    const user = userEvent.setup()
    render(
      <OnboardingControlBar
        runId={RUN_ID}
        state={admissionState}
        controls={admissionControls}
        providerName="Acme"
      />,
    )

    expect(screen.getByTestId("admission-prompt")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Pause at next boundary" })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Reset this run" })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /^Retry/ })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Resume the run" })).not.toBeInTheDocument()

    await user.click(screen.getByRole("button", { name: "Create an account" }))

    await waitFor(() => expect(mocks.decideAdmissionAction).toHaveBeenCalledOnce())
    const submitted = mocks.decideAdmissionAction.mock.calls[0]?.[1] as FormData
    expect(submitted.get("decision")).toBe("create_account")
    expect(submitted.get("profile_digest")).toBe(DIGEST)
    expect(submitted.get("run_id")).toBe(RUN_ID)
    expect(
      await screen.findByText(/Decision recorded\. The agent will create an account/),
    ).toBeInTheDocument()
  })
})
