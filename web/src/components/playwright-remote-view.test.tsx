import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

const rfbMocks = vi.hoisted(() => ({
  instances: [] as Array<{
    target: HTMLElement
    url: string
    disconnect: ReturnType<typeof vi.fn>
    listeners: Map<string, () => void>
    scaleViewport: boolean
    resizeSession: boolean
    viewOnly: boolean
  }>,
}))

vi.mock("@novnc/novnc", () => ({
  default: class MockRfb {
    target: HTMLElement
    url: string
    disconnect = vi.fn()
    listeners = new Map<string, () => void>()
    scaleViewport = false
    resizeSession = true
    viewOnly = true

    constructor(target: HTMLElement, url: string) {
      this.target = target
      this.url = url
      rfbMocks.instances.push(this)
    }

    addEventListener(event: string, callback: () => void) {
      this.listeners.set(event, callback)
    }

    removeEventListener(event: string) {
      this.listeners.delete(event)
    }
  },
}))

import { PlaywrightRemoteView } from "@/components/playwright-remote-view"

const INTERACTIVE_PATH =
  "/internal/browser/live-view/novnc?session=pw_session_1&token=signed-grant"

describe("PlaywrightRemoteView", () => {
  beforeEach(() => rfbMocks.instances.splice(0))

  it("connects noVNC to the same origin without putting the grant in the DOM", async () => {
    const { unmount } = render(
      <PlaywrightRemoteView interactivePath={INTERACTIVE_PATH} onReconnect={vi.fn()} />,
    )

    await waitFor(() => expect(rfbMocks.instances).toHaveLength(1))
    const rfb = rfbMocks.instances[0]

    expect(rfb?.url).toBe(`ws://${window.location.host}${INTERACTIVE_PATH}`)
    expect(rfb?.scaleViewport).toBe(true)
    expect(rfb?.resizeSession).toBe(false)
    expect(rfb?.viewOnly).toBe(false)
    expect(screen.getByLabelText(/remote chromium desktop/i).outerHTML).not.toContain(
      "signed-grant",
    )

    rfb?.listeners.get("connect")?.()
    expect(await screen.findByText(/browser connection · connected/i)).toBeInTheDocument()

    unmount()
    expect(rfb?.disconnect).toHaveBeenCalledOnce()
  })

  it("never reconnects automatically after a disconnect", async () => {
    const user = userEvent.setup()
    const onReconnect = vi.fn()
    render(
      <PlaywrightRemoteView interactivePath={INTERACTIVE_PATH} onReconnect={onReconnect} />,
    )

    await waitFor(() => expect(rfbMocks.instances).toHaveLength(1))
    rfbMocks.instances[0]?.listeners.get("disconnect")?.()

    const reconnect = await screen.findByRole("button", {
      name: /request fresh connection/i,
    })
    expect(onReconnect).not.toHaveBeenCalled()
    expect(rfbMocks.instances).toHaveLength(1)

    await user.click(reconnect)
    expect(onReconnect).toHaveBeenCalledOnce()
    expect(rfbMocks.instances).toHaveLength(1)
  })

  it("fails closed before noVNC sees a cross-origin path", async () => {
    render(
      <PlaywrightRemoteView
        interactivePath="https://browser-worker:8081/internal/browser/live-view/novnc?session=pw_1&token=t"
        onReconnect={vi.fn()}
      />,
    )

    expect(await screen.findByText(/browser connection · failed/i)).toBeInTheDocument()
    expect(rfbMocks.instances).toHaveLength(0)
  })
})
