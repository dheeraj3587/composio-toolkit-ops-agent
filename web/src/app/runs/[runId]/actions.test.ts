import { beforeEach, describe, expect, it, vi } from "vitest"

const mocks = vi.hoisted(() => ({
  getLiveView: vi.fn(),
  revalidatePath: vi.fn(),
}))

vi.mock("server-only", () => ({}))
vi.mock("next/cache", () => ({ revalidatePath: mocks.revalidatePath }))
vi.mock("@/lib/api", () => {
  class ApiError extends Error {
    constructor(
      public readonly status: number,
      public readonly code: string,
    ) {
      super("API error")
    }
  }

  return {
    ApiError,
    PhaseConflictError: class PhaseConflictError extends ApiError {},
    getLiveView: mocks.getLiveView,
    performPhaseAction: vi.fn(),
    resumeWithBrowserLogin: vi.fn(),
    submitCredentials: vi.fn(),
  }
})

import { openLiveView, type LiveViewState } from "@/app/runs/[runId]/actions"

const RUN_ID = "run_11111111111111111111111111111111"
const initialState: LiveViewState = {
  provider: null,
  mode: "unavailable",
  liveUrl: null,
  screenshotUrl: null,
  interactivePath: null,
  capturedAt: null,
  interactionAvailable: false,
  message: null,
  tone: "neutral",
}

function runForm(): FormData {
  const form = new FormData()
  form.set("run_id", RUN_ID)
  return form
}

describe("openLiveView", () => {
  beforeEach(() => mocks.getLiveView.mockReset())

  it("returns only a same-origin path for an interactive Playwright grant", async () => {
    mocks.getLiveView.mockResolvedValue({
      run_id: RUN_ID,
      provider: "playwright",
      available: true,
      mode: "interactive_remote",
      live_url: null,
      screenshot_url: null,
      interactive_url:
        "http://browser-worker:8081/internal/browser/live-view/novnc?token=signed-grant&session=pw_session_1",
      captured_at: null,
      interaction_available: true,
      reason_code: "interactive_hitl_available",
    })

    const result = await openLiveView(initialState, runForm())

    expect(result).toMatchObject({
      provider: "playwright",
      mode: "interactive_remote",
      liveUrl: null,
      screenshotUrl: null,
      interactivePath:
        "/internal/browser/live-view/novnc?session=pw_session_1&token=signed-grant",
      interactionAvailable: true,
    })
    expect(JSON.stringify(result)).not.toContain("browser-worker")
  })

  it("fails closed and clears an old grant when the private URL drifts", async () => {
    mocks.getLiveView.mockResolvedValue({
      run_id: RUN_ID,
      provider: "playwright",
      available: true,
      mode: "interactive_remote",
      interactive_url:
        "http://browser-worker:8081/internal/browser/live-view/novnc?session=pw_session_1&token=signed-grant&extra=1",
      interaction_available: true,
    })

    const result = await openLiveView(
      {
        ...initialState,
        provider: "playwright",
        mode: "interactive_remote",
        interactivePath: "/internal/browser/live-view/novnc?session=old&token=old",
        interactionAvailable: true,
      },
      runForm(),
    )

    expect(result.mode).toBe("unavailable")
    expect(result.interactivePath).toBeNull()
    expect(result.message).toBe("The live browser view could not be retrieved.")
  })
})
