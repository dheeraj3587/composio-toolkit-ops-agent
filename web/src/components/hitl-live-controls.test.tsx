import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

import type { BrowserUiState } from "@/lib/types"

const mocks = vi.hoisted(() => ({
  openLiveView: vi.fn(),
  runPhaseAction: vi.fn(),
  submitBrowserLoginAction: vi.fn(),
  submitCredentialAction: vi.fn(),
  order: [] as string[],
}))

vi.mock("@/app/runs/[runId]/actions", () => ({
  openLiveView: mocks.openLiveView,
  runPhaseAction: mocks.runPhaseAction,
  submitBrowserLoginAction: mocks.submitBrowserLoginAction,
  submitCredentialAction: mocks.submitCredentialAction,
}))

vi.mock("@/components/playwright-remote-view", async () => {
  const React = await import("react")

  return {
    PlaywrightRemoteView: React.forwardRef<
      { disconnect: () => void },
      { interactivePath: string; controlAllowed: boolean; onReconnect: () => void }
    >(function MockRemoteView({ interactivePath, onReconnect, controlAllowed }, ref) {
      React.useImperativeHandle(ref, () => ({
        disconnect() {
          mocks.order.push("disconnect")
        },
      }))

      return (
        <div
          aria-label={
            controlAllowed
              ? "mock controlled playwright browser"
              : "mock view-only playwright browser"
          }
        >
          <span>{interactivePath.split("?")[0]}</span>
          <button type="button" onClick={onReconnect}>Reconnect remote</button>
        </div>
      )
    }),
  }
})

import { HitlLiveControls } from "@/components/hitl-live-controls"

const RUN_ID = "run_11111111111111111111111111111111"
const INTERACTIVE_PATH =
  "/internal/browser/live-view/novnc?session=pw_session_1&token=signed-grant"

const waitingBrowser: BrowserUiState = {
  provider: "playwright",
  lifecycle: "waiting_for_hitl",
  live_view_mode: "interactive_remote",
  live_view_available: true,
  interaction_available: true,
  screenshot_available: true,
  credential_page_verified: false,
  can_submit_login: false,
  can_submit_otp: false,
  can_resume: true,
  can_submit_credential: false,
  reason_code: "captcha_detected",
}

describe("HitlLiveControls interactive lifecycle", () => {
  beforeEach(() => {
    mocks.openLiveView.mockReset()
    mocks.runPhaseAction.mockReset()
    mocks.submitBrowserLoginAction.mockReset()
    mocks.submitCredentialAction.mockReset()
    mocks.order.splice(0)
    mocks.openLiveView.mockResolvedValue({
      provider: "playwright",
      mode: "interactive_remote",
      liveUrl: null,
      screenshotUrl: null,
      interactivePath: INTERACTIVE_PATH,
      capturedAt: null,
      interactionAvailable: true,
      message: "Interactive Playwright session ready.",
      tone: "neutral",
    })
    mocks.runPhaseAction.mockImplementation(async () => {
      mocks.order.push("resume")
      return { message: "Backend accepted the action.", tone: "neutral" }
    })
  })

  it("renders remote control only for an interactive Playwright HITL capability", async () => {
    const { rerender } = render(
      <HitlLiveControls
        runId={RUN_ID}
        browser={waitingBrowser}
        browserStateVersion="v1"
        canResumeInteractive
      />,
    )

    expect(await screen.findByLabelText(/mock controlled playwright browser/i)).toBeInTheDocument()
    expect(document.body.textContent).not.toContain("browser-worker")

    mocks.openLiveView.mockResolvedValue({
      provider: "playwright",
      mode: "interactive_remote",
      liveUrl: null,
      screenshotUrl: null,
      interactivePath: INTERACTIVE_PATH.replace("signed-grant", "signed-view-grant"),
      capturedAt: null,
      interactionAvailable: false,
      message: "Live Playwright session ready in view-only mode.",
      tone: "neutral",
    })
    rerender(
      <HitlLiveControls
        runId={RUN_ID}
        browser={{ ...waitingBrowser, lifecycle: "running", interaction_available: false }}
        browserStateVersion="v2"
      />,
    )
    expect(await screen.findByLabelText(/mock view-only playwright browser/i)).toBeInTheDocument()

    rerender(
      <HitlLiveControls
        runId={RUN_ID}
        browser={{ ...waitingBrowser, interaction_available: false }}
        browserStateVersion="v3"
      />,
    )
    expect(await screen.findByLabelText(/mock view-only playwright browser/i)).toBeInTheDocument()
  })

  it("requests a fresh grant only after the operator asks to reconnect", async () => {
    const user = userEvent.setup()
    const { rerender } = render(
      <HitlLiveControls
        runId={RUN_ID}
        browser={waitingBrowser}
        browserStateVersion="v1"
        canResumeInteractive
      />,
    )

    await screen.findByLabelText(/mock controlled playwright browser/i)
    expect(mocks.openLiveView).toHaveBeenCalledOnce()

    rerender(
      <HitlLiveControls
        runId={RUN_ID}
        browser={waitingBrowser}
        browserStateVersion="v2"
        canResumeInteractive
      />,
    )
    await Promise.resolve()
    expect(mocks.openLiveView).toHaveBeenCalledOnce()

    await user.click(screen.getByRole("button", { name: "Reconnect remote" }))
    await waitFor(() => expect(mocks.openLiveView).toHaveBeenCalledTimes(2))
  })

  it("disconnects and clears the grant before submitting Resume", async () => {
    const user = userEvent.setup()
    render(
      <HitlLiveControls
        runId={RUN_ID}
        browser={waitingBrowser}
        browserStateVersion="v1"
        canResumeInteractive
      />,
    )

    await screen.findByLabelText(/mock controlled playwright browser/i)
    await user.click(screen.getByRole("button", { name: /disconnect and resume/i }))

    await waitFor(() => expect(mocks.runPhaseAction).toHaveBeenCalledOnce())
    expect(mocks.order).toEqual(["disconnect", "resume"])
    expect(screen.queryByLabelText(/mock controlled playwright browser/i)).not.toBeInTheDocument()
    expect(document.body.textContent).not.toContain("signed-grant")
  })
})
