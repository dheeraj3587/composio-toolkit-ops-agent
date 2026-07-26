import { describe, expect, it, vi } from "vitest"

vi.mock("server-only", () => ({}))

import { ApiError } from "@/lib/api"
import { sameOriginInteractivePath } from "@/lib/live-view-grant"

describe("sameOriginInteractivePath", () => {
  it("converts the exact internal grant into a relative same-origin path", () => {
    expect(
      sameOriginInteractivePath(
        "http://browser-worker:8081/internal/browser/live-view/novnc?token=signed%2Bgrant&session=pw_session_1",
      ),
    ).toBe(
      "/internal/browser/live-view/novnc?session=pw_session_1&token=signed%2Bgrant",
    )
  })

  it.each([
    "https://browser-worker:8081/internal/browser/live-view/novnc?session=pw_1&token=t",
    "http://browser-worker/internal/browser/live-view/novnc?session=pw_1&token=t",
    "http://browser-worker:8081/vnc.html?session=pw_1&token=t",
    "http://127.0.0.1:8081/internal/browser/live-view/novnc?session=pw_1&token=t",
    "http://browser-worker:8081/internal/browser/live-view/novnc?session=pw_1&token=t&extra=1",
    "http://browser-worker:8081/internal/browser/live-view/novnc?session=pw%2F1&token=t",
    "http://browser-worker:8081/internal/browser/live-view/novnc?session=pw_1&token=t%0Ainjected",
  ])("fails closed for an unreviewed grant shape", (value) => {
    expect(() => sameOriginInteractivePath(value)).toThrow(ApiError)

    try {
      sameOriginInteractivePath(value)
    } catch (error) {
      expect(error).toMatchObject({ status: 502, code: "INVALID_INTERACTIVE_GRANT" })
      expect(String(error)).not.toContain(value)
    }
  })
})
