import { render, screen } from "@testing-library/react"
import { createRef } from "react"
import { describe, expect, it, vi } from "vitest"

import type { LiveViewState } from "@/app/runs/[runId]/actions"
import type { PlaywrightRemoteViewHandle } from "@/components/playwright-remote-view"
import { SECRET_CAPTURE_BOUNDARY } from "@/lib/live-view"

// The noVNC surface is exercised by its own test; this file is about which panel
// the live-view grant selects.
vi.mock("@/components/playwright-remote-view", () => ({
  PlaywrightRemoteView: () => null,
}))

import { BrowserLiveSurface } from "@/components/browser-live-surface"

const SCREENSHOT_PATH =
  "/api/control/runs/run_33333333333333333333333333333333/live-view/screenshot?v=1717"

const unavailableEmbed: LiveViewState = {
  provider: "playwright",
  mode: "unavailable",
  screenshotUrl: SCREENSHOT_PATH,
  interactivePath: null,
  capturedAt: "2025-01-01T00:00:00Z",
  interactionAvailable: false,
  reasonCode: "no_active_browser_session",
  message: "No live browser embed is available for this run.",
  tone: "error",
}

describe("BrowserLiveSurface", () => {
  it("falls back to the masked frame for an unavailable embed and shows no frame at the capture boundary", () => {
    const remoteViewRef = createRef<PlaywrightRemoteViewHandle>()
    const surface = (liveState: LiveViewState) => (
      <BrowserLiveSurface
        liveState={liveState}
        isPlaywright
        isInteractiveHitl={false}
        livePending={false}
        onRequestLiveView={vi.fn()}
        remoteViewRef={remoteViewRef}
      />
    )

    // Requirement 18.3: an unavailable embed degrades to the masked screenshot.
    const { rerender } = render(surface(unavailableEmbed))

    const frame = screen.getByAltText(/masked browser screenshot/i)
    expect(frame).toHaveAttribute("src", expect.stringContaining("/live-view/screenshot"))
    expect(screen.queryByTestId("live-view-empty-panel")).not.toBeInTheDocument()

    // Requirement 18.8: the capture boundary closes the view rather than masking
    // it, so no frame of a credential surface may render.
    rerender(
      surface({
        ...unavailableEmbed,
        screenshotUrl: null,
        reasonCode: SECRET_CAPTURE_BOUNDARY,
        message: "The live view is closed while this run is on a credential surface.",
      }),
    )

    expect(screen.getByTestId("live-view-capture-boundary")).toBeInTheDocument()
    expect(screen.queryByRole("img")).not.toBeInTheDocument()
  })
})
