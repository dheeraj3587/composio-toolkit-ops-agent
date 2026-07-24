import { beforeEach, describe, expect, it, vi } from "vitest"

const mocks = vi.hoisted(() => ({
  createRun: vi.fn(),
  redirect: vi.fn(),
}))

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {
    constructor(public readonly status: number) {
      super("API error")
    }
  },
  createRun: mocks.createRun,
}))

vi.mock("next/navigation", () => ({
  redirect: mocks.redirect,
}))

import { createRunAction, type CreateRunFormState } from "@/app/runs/new/actions"

const initialState: CreateRunFormState = {
  error: null,
  fields: [],
  idempotencyKey: null,
  requestFingerprint: null,
}

function validForm(executionMode: string): FormData {
  const form = new FormData()
  form.set("app_name", "Linear")
  form.set("legal_name", "Example Labs, Inc.")
  form.set("website", "https://example.com")
  form.set("work_email_ref", "vault://company/work_email/profile_1")
  form.set("use_case", "Synchronize authorized customer issues.")
  form.set("expected_volume", "1,000 requests per month")
  form.set("callback_urls", "https://example.com/oauth/callback")
  form.set("outreach_recipient_override", "")
  form.set("requested_scope_policy", "minimum")
  form.set("execution_mode", executionMode)
  return form
}

describe("createRunAction", () => {
  beforeEach(() => {
    mocks.createRun.mockReset()
    mocks.redirect.mockReset()
    mocks.createRun.mockResolvedValue({ run: { run_id: "run_frontend_123" } })
    mocks.redirect.mockImplementation(() => {
      throw new Error("NEXT_REDIRECT")
    })
  })

  it("submits the selected execution mode without the legacy dry-run alias", async () => {
    await expect(createRunAction(initialState, validForm("execute_when_configured"))).rejects.toThrow("NEXT_REDIRECT")

    expect(mocks.createRun).toHaveBeenCalledOnce()
    const request = mocks.createRun.mock.calls[0]?.[0]
    expect(request).toMatchObject({
      app_name: "Linear",
      execution_mode: "execute_when_configured",
      company: {
        legal_name: "Example Labs, Inc.",
        website: "https://example.com",
        use_case: "Synchronize authorized customer issues.",
      },
    })
    expect(request).not.toHaveProperty("dry_run")
  })

  it("falls back to execute-when-configured when the submitted mode is not supported", async () => {
    await expect(createRunAction(initialState, validForm("unbounded_execution"))).rejects.toThrow("NEXT_REDIRECT")

    expect(mocks.createRun.mock.calls[0]?.[0]).toMatchObject({ execution_mode: "execute_when_configured" })
  })
})
