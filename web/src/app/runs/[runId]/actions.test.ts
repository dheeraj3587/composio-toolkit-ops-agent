import { beforeEach, describe, expect, it, vi } from "vitest"

const mocks = vi.hoisted(() => ({
  connectManagedRun: vi.fn(),
  getLiveView: vi.fn(),
  pollManagedConnection: vi.fn(),
  resumeWithBrowserVerification: vi.fn(),
  redirect: vi.fn(),
  revalidatePath: vi.fn(),
}))

vi.mock("server-only", () => ({}))
vi.mock("next/cache", () => ({ revalidatePath: mocks.revalidatePath }))
vi.mock("next/navigation", () => ({ redirect: mocks.redirect }))
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
    connectManagedRun: mocks.connectManagedRun,
    getLiveView: mocks.getLiveView,
    pollManagedConnection: mocks.pollManagedConnection,
    performPhaseAction: vi.fn(),
    resumeWithBrowserLogin: vi.fn(),
    resumeWithBrowserVerification: mocks.resumeWithBrowserVerification,
    submitCredentials: vi.fn(),
  }
})

import {
  openLiveView,
  runManagedConnectionAction,
  submitBrowserVerificationAction,
  type BrowserVerificationState,
  type LiveViewState,
  type ManagedConnectionActionState,
} from "@/app/runs/[runId]/actions"

const RUN_ID = "run_11111111111111111111111111111111"
const initialState: LiveViewState = {
  provider: null,
  mode: "unavailable",
  liveUrl: null,
  screenshotUrl: null,
  interactivePath: null,
  capturedAt: null,
  interactionAvailable: false,
  reasonCode: null,
  message: null,
  tone: "neutral",
}

function runForm(): FormData {
  const form = new FormData()
  form.set("run_id", RUN_ID)
  return form
}

const initialManagedState: ManagedConnectionActionState = {
  message: null,
  tone: "neutral",
  state: null,
}

const initialVerificationState: BrowserVerificationState = {
  message: null,
  tone: "neutral",
}

function managedForm(operation: "connect" | "poll"): FormData {
  const form = runForm()
  form.set("managed_action", operation)
  return form
}

describe("managed connection actions", () => {
  beforeEach(() => {
    mocks.connectManagedRun.mockReset()
    mocks.pollManagedConnection.mockReset()
    mocks.redirect.mockReset()
    mocks.revalidatePath.mockReset()
  })

  it("starts managed auth and immediately redirects to the ephemeral provider URL", async () => {
    mocks.connectManagedRun.mockResolvedValue({
      run: { run_id: RUN_ID },
      connection_request_id: "conn_123",
      state: "pending",
      redirect_url: "https://accounts.example.com/oauth/authorize?state=opaque",
      replayed: false,
    })

    await runManagedConnectionAction(initialManagedState, managedForm("connect"))

    expect(mocks.connectManagedRun).toHaveBeenCalledWith(RUN_ID)
    expect(mocks.revalidatePath).toHaveBeenCalledWith(`/runs/${RUN_ID}`)
    expect(mocks.redirect).toHaveBeenCalledWith(
      "https://accounts.example.com/oauth/authorize?state=opaque",
    )
  })

  it("polls only the existing request and reports active state", async () => {
    mocks.pollManagedConnection.mockResolvedValue({
      run: { run_id: RUN_ID },
      connection_request_id: "conn_123",
      state: "active",
      redirect_url: null,
      replayed: false,
    })

    const result = await runManagedConnectionAction(initialManagedState, managedForm("poll"))

    expect(mocks.pollManagedConnection).toHaveBeenCalledWith(RUN_ID)
    expect(mocks.connectManagedRun).not.toHaveBeenCalled()
    expect(result).toMatchObject({ state: "active", tone: "neutral" })
    expect(mocks.redirect).not.toHaveBeenCalled()
  })

  it("rejects an invalid run before calling either managed endpoint", async () => {
    const form = managedForm("connect")
    form.set("run_id", "../../other-run")

    const result = await runManagedConnectionAction(initialManagedState, form)

    expect(result.tone).toBe("error")
    expect(mocks.connectManagedRun).not.toHaveBeenCalled()
    expect(mocks.pollManagedConnection).not.toHaveBeenCalled()
  })
})

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

describe("manual browser verification", () => {
  beforeEach(() => {
    mocks.resumeWithBrowserVerification.mockReset()
    mocks.revalidatePath.mockReset()
    mocks.resumeWithBrowserVerification.mockResolvedValue({
      run_id: RUN_ID,
      action: "resume",
      status: "accepted",
      detail: "Never render the submitted value 123456.",
    })
  })

  it("normalizes and submits exactly one verification code", async () => {
    const form = runForm()
    form.set("verification_code", "12 34-56")

    const result = await submitBrowserVerificationAction(initialVerificationState, form)

    expect(mocks.resumeWithBrowserVerification).toHaveBeenCalledWith(
      RUN_ID,
      { code: "123456" },
    )
    expect(result.tone).toBe("neutral")
    expect(JSON.stringify(result)).not.toContain("123456")
  })

  it("submits an HTTPS magic link but rejects mixed secret sources", async () => {
    const linkForm = runForm()
    linkForm.set("verification_url", "https://provider.example/verify?token=opaque")

    await submitBrowserVerificationAction(initialVerificationState, linkForm)
    expect(mocks.resumeWithBrowserVerification).toHaveBeenLastCalledWith(
      RUN_ID,
      { url: "https://provider.example/verify?token=opaque" },
    )

    const mixed = runForm()
    mixed.set("verification_code", "123456")
    mixed.set("verification_url", "https://provider.example/verify?token=opaque")
    const result = await submitBrowserVerificationAction(initialVerificationState, mixed)
    expect(result.tone).toBe("error")
    expect(mocks.resumeWithBrowserVerification).toHaveBeenCalledTimes(1)
  })
})
