import { render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { beforeEach, describe, expect, it, vi } from "vitest"

const rfbMocks = vi.hoisted(() => ({
  instances: [] as Array<{
    target: HTMLElement
    url: string
    disconnect: ReturnType<typeof vi.fn>
    clipboardPasteFrom: ReturnType<typeof vi.fn>
    sendKey: ReturnType<typeof vi.fn>
    listeners: Map<string, (event?: unknown) => void>
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
    clipboardPasteFrom = vi.fn()
    sendKey = vi.fn()
    listeners = new Map<string, (event?: unknown) => void>()
    scaleViewport = false
    resizeSession = true
    viewOnly = true

    constructor(target: HTMLElement, url: string) {
      this.target = target
      this.url = url
      rfbMocks.instances.push(this)
    }

    addEventListener(event: string, callback: (event?: unknown) => void) {
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
      <PlaywrightRemoteView
        interactivePath={INTERACTIVE_PATH}
        controlAllowed
        onReconnect={vi.fn()}
      />,
    )

    await waitFor(() => expect(rfbMocks.instances).toHaveLength(1))
    const rfb = rfbMocks.instances[0]

    expect(rfb?.url).toBe(`ws://${window.location.host}${INTERACTIVE_PATH}`)
    expect(rfb?.scaleViewport).toBe(true)
    expect(rfb?.resizeSession).toBe(false)
    expect(rfb?.viewOnly).toBe(false)
    const remoteDesktop = screen.getByLabelText(/remote chromium desktop/i)
    expect(remoteDesktop.outerHTML).not.toContain("signed-grant")
    // noVNC sizes its internal screen to 100% of this host. A minimum height is
    // not a definite percentage basis, so its ResizeObserver can autoscale the
    // canvas to zero after the first visible frame while RFB stays connected.
    expect(remoteDesktop).toHaveClass(
      "relative",
      "h-[420px]",
      "sm:h-[560px]",
      "xl:h-[640px]",
    )
    expect(remoteDesktop.className).not.toContain("min-h-")

    rfb?.listeners.get("connect")?.()
    expect(await screen.findByText(/browser connection · connected/i)).toBeInTheDocument()

    unmount()
    expect(rfb?.disconnect).toHaveBeenCalledOnce()
  })

  it("never reconnects automatically after a disconnect", async () => {
    const user = userEvent.setup()
    const onReconnect = vi.fn()
    render(
      <PlaywrightRemoteView
        interactivePath={INTERACTIVE_PATH}
        controlAllowed
        onReconnect={onReconnect}
      />,
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

  it("pastes typed text into the remote session and clears it from the DOM", async () => {
    const user = userEvent.setup()
    render(
      <PlaywrightRemoteView
        interactivePath={INTERACTIVE_PATH}
        controlAllowed
        onReconnect={vi.fn()}
      />,
    )

    await waitFor(() => expect(rfbMocks.instances).toHaveLength(1))
    const rfb = rfbMocks.instances[0]
    rfb?.listeners.get("connect")?.()

    const field = await screen.findByLabelText(/send text into the remote browser/i)
    await user.type(field, "hello-remote")
    await user.click(screen.getByRole("button", { name: /^send text$/i }))

    expect(rfb?.clipboardPasteFrom).toHaveBeenCalledWith("hello-remote")
    // Setting the clipboard alone cannot fill a field, so the paste chord must
    // actually be synthesized inside the session.
    expect(rfb?.sendKey).toHaveBeenCalled()
    expect((field as HTMLInputElement).value).toBe("")
  })

  it("surfaces text copied inside the remote browser", async () => {
    render(
      <PlaywrightRemoteView
        interactivePath={INTERACTIVE_PATH}
        controlAllowed
        onReconnect={vi.fn()}
      />,
    )

    await waitFor(() => expect(rfbMocks.instances).toHaveLength(1))
    const rfb = rfbMocks.instances[0]
    rfb?.listeners.get("connect")?.()
    rfb?.listeners.get("clipboard")?.({ detail: { text: "copied-from-remote" } })

    const mirrored = await screen.findByLabelText(/copied inside the remote browser/i)
    await waitFor(() => expect((mirrored as HTMLTextAreaElement).value).toBe("copied-from-remote"))
  })

  it("fails closed before noVNC sees a cross-origin path", async () => {
    render(
      <PlaywrightRemoteView
        interactivePath="https://browser-worker:8081/internal/browser/live-view/novnc?session=pw_1&token=t"
        controlAllowed={false}
        onReconnect={vi.fn()}
      />,
    )

    expect(await screen.findByText(/browser connection · failed/i)).toBeInTheDocument()
    expect(rfbMocks.instances).toHaveLength(0)
  })

  it("keeps an autonomous stream view-only and hides input affordances", async () => {
    render(
      <PlaywrightRemoteView
        interactivePath={INTERACTIVE_PATH}
        controlAllowed={false}
        onReconnect={vi.fn()}
      />,
    )

    await waitFor(() => expect(rfbMocks.instances).toHaveLength(1))
    expect(rfbMocks.instances[0]?.viewOnly).toBe(true)
    expect(screen.getByLabelText(/remote chromium desktop; view only/i)).toBeInTheDocument()
    expect(screen.queryByLabelText(/send text into the remote browser/i)).not.toBeInTheDocument()
    expect(screen.getByText(/controls unlock only at a human handoff/i)).toBeInTheDocument()
  })
})
