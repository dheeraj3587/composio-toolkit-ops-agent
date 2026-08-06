"use client"

import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from "react"
import { MonitorDot, RefreshCcw } from "lucide-react"

import { Button } from "@/components/ui/button"

const INTERACTIVE_ENDPOINT = "/internal/browser/live-view/novnc"

type ConnectionState = "connecting" | "connected" | "disconnected" | "failed"

interface RfbClipboardPayload extends Event {
  detail: { text: string }
}

interface RfbConnection {
  disconnect: () => void
  scaleViewport: boolean
  resizeSession: boolean
  viewOnly: boolean
  /** Sets the REMOTE clipboard (RFB ClientCutText). */
  clipboardPasteFrom: (text: string) => void
  /** Synthesizes a key event inside the remote session. */
  sendKey: (keysym: number, code: string, down?: boolean) => void
  addEventListener: {
    (event: "connect" | "disconnect", callback: () => void): void
    (event: "clipboard", callback: (event: RfbClipboardPayload) => void): void
  }
  removeEventListener: {
    (event: "connect" | "disconnect", callback: () => void): void
    (event: "clipboard", callback: (event: RfbClipboardPayload) => void): void
  }
}

/** Keysyms for the synthetic paste chord sent after the remote clipboard is set. */
const CONTROL_LEFT_KEYSYM = 0xffe3
const LOWERCASE_V_KEYSYM = 0x76

export interface PlaywrightRemoteViewHandle {
  disconnect: () => void
}

interface PlaywrightRemoteViewProps {
  interactivePath: string
  controlAllowed: boolean
  onReconnect: () => void
}

function sameOriginSocketUrl(interactivePath: string): string {
  const parsed = new URL(interactivePath, window.location.origin)
  const keys = [...parsed.searchParams.keys()]
  const session = parsed.searchParams.get("session")
  const token = parsed.searchParams.get("token")

  if (
    parsed.origin !== window.location.origin ||
    parsed.pathname !== INTERACTIVE_ENDPOINT ||
    parsed.hash !== "" ||
    keys.length !== 2 ||
    new Set(keys).size !== 2 ||
    !keys.includes("session") ||
    !keys.includes("token") ||
    session === null ||
    !/^[A-Za-z0-9_-]{1,180}$/.test(session) ||
    token === null ||
    token.length === 0 ||
    token.length > 2_048 ||
    /[\u0000-\u001f\u007f]/.test(token)
  ) {
    throw new Error("Invalid same-origin interactive path")
  }

  parsed.protocol = window.location.protocol === "https:" ? "wss:" : "ws:"
  return parsed.toString()
}

/**
 * An in-memory noVNC client for the currently paused Playwright session.
 *
 * The signed path is used only to construct this connection. It is never
 * persisted, logged, or copied into an element attribute.
 */
export const PlaywrightRemoteView = forwardRef<
  PlaywrightRemoteViewHandle,
  PlaywrightRemoteViewProps
>(function PlaywrightRemoteView({ interactivePath, controlAllowed, onReconnect }, ref) {
  const targetRef = useRef<HTMLDivElement>(null)
  const rfbRef = useRef<RfbConnection | null>(null)
  const [state, setState] = useState<ConnectionState>("connecting")
  // Text the REMOTE browser copied, mirrored here so the operator can take it
  // out of the session. Held in component state only: never persisted, never
  // sent to the API, never logged.
  const [remoteClipboard, setRemoteClipboard] = useState("")
  const [outgoingText, setOutgoingText] = useState("")
  const [clipboardNotice, setClipboardNotice] = useState("")

  useImperativeHandle(
    ref,
    () => ({
      disconnect() {
        try {
          rfbRef.current?.disconnect()
        } catch {
          // A failed best-effort disconnect must not trap the operator in HITL.
        }
        rfbRef.current = null
      },
    }),
    [],
  )

  useEffect(() => {
    let disposed = false
    const target = targetRef.current
    let rfb: RfbConnection | null = null
    const handleConnect = () => {
      if (!disposed) setState("connected")
    }
    const handleDisconnect = () => {
      if (!disposed) {
        rfbRef.current = null
        setState("disconnected")
      }
    }
    // The relay is byte-transparent, so RFB ServerCutText already arrives; it was
    // simply never read. Mirroring it here is what makes "copy out of the remote
    // browser" work at all.
    const handleClipboard = (event: RfbClipboardPayload) => {
      if (disposed) return
      const text = event?.detail?.text
      if (typeof text === "string") setRemoteClipboard(text)
    }

    if (!target) return
    const connectionTarget: HTMLElement = target

    async function connect() {
      try {
        const noVncModule = await import("@novnc/novnc")
        if (disposed) return

        rfb = new noVncModule.default(connectionTarget, sameOriginSocketUrl(interactivePath))
        rfbRef.current = rfb
        rfb.scaleViewport = true
        rfb.resizeSession = false
        // UX mirrors the signed server capability. Security does not depend on
        // this flag: view grants terminate at x11vnc's -viewonly listener.
        rfb.viewOnly = !controlAllowed

        rfb.addEventListener("connect", handleConnect)
        rfb.addEventListener("disconnect", handleDisconnect)
        if (controlAllowed) rfb.addEventListener("clipboard", handleClipboard)
      } catch {
        if (!disposed) setState("failed")
      }
    }

    void connect()

    return () => {
      disposed = true
      const shouldDisconnect = rfbRef.current === rfb
      rfbRef.current = null
      try {
        rfb?.removeEventListener("connect", handleConnect)
        rfb?.removeEventListener("disconnect", handleDisconnect)
        if (controlAllowed) rfb?.removeEventListener("clipboard", handleClipboard)
        if (shouldDisconnect) rfb?.disconnect()
      } catch {
        // Cleanup must not break unmounting or a resume submission.
      }
      target.replaceChildren()
    }
  }, [controlAllowed, interactivePath])

  /**
   * Put text on the REMOTE clipboard and press Ctrl+V inside the session.
   *
   * Setting the clipboard alone is not enough to fill a field, and the browser
   * running this UI cannot forward a native paste into the canvas, so the chord
   * is synthesized on the RFB connection right after the cut-text message.
   */
  const sendTextToRemote = (text: string): boolean => {
    const rfb = rfbRef.current
    if (rfb === null || text.length === 0) return false
    try {
      rfb.clipboardPasteFrom(text)
      if (typeof rfb.sendKey === "function") {
        rfb.sendKey(CONTROL_LEFT_KEYSYM, "ControlLeft", true)
        rfb.sendKey(LOWERCASE_V_KEYSYM, "KeyV", true)
        rfb.sendKey(LOWERCASE_V_KEYSYM, "KeyV", false)
        rfb.sendKey(CONTROL_LEFT_KEYSYM, "ControlLeft", false)
      }
      return true
    } catch {
      return false
    }
  }

  const handleSendText = () => {
    const text = outgoingText
    if (text.length === 0) {
      setClipboardNotice("Enter text to send first.")
      return
    }
    if (!sendTextToRemote(text)) {
      setClipboardNotice("The remote session is not connected.")
      return
    }
    // The value is dropped immediately so typed text is not left in the DOM.
    setOutgoingText("")
    setClipboardNotice("Sent to the remote browser and pasted at the cursor.")
  }

  const handlePasteFromLocalClipboard = async () => {
    try {
      const text = await navigator.clipboard.readText()
      if (!sendTextToRemote(text)) {
        setClipboardNotice("Nothing to paste, or the session is not connected.")
        return
      }
      setClipboardNotice("Your clipboard was pasted into the remote browser.")
    } catch {
      // Clipboard read needs a user gesture and permission; the text box is the
      // guaranteed fallback rather than a dead end.
      setClipboardNotice("Clipboard permission was refused. Use the text box instead.")
    }
  }

  const handleCopyRemoteClipboard = async () => {
    if (remoteClipboard.length === 0) return
    try {
      await navigator.clipboard.writeText(remoteClipboard)
      setClipboardNotice("Copied the remote selection to your clipboard.")
    } catch {
      setClipboardNotice("Copy was refused. Select the text above and copy manually.")
    }
  }

  return (
    <section
      aria-label="Interactive Playwright browser"
      className="overflow-hidden rounded-lg border border-border bg-black shadow-[0_12px_36px_rgba(0,0,0,0.16)]"
    >
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-zinc-950 px-3 py-2.5 text-zinc-100">
        <div className="flex items-center gap-2">
          <span
            className={
              state === "connected"
                ? "size-2 rounded-full bg-emerald-400 shadow-[0_0_0_3px_rgba(52,211,153,0.14)]"
                : state === "connecting"
                  ? "size-2 animate-pulse rounded-full bg-amber-300 motion-reduce:animate-none"
                  : "size-2 rounded-full bg-zinc-500"
            }
            aria-hidden="true"
          />
          <MonitorDot className="size-3.5 text-zinc-400" aria-hidden="true" />
          <p role="status" aria-live="polite" className="font-mono text-2xs uppercase tracking-[0.1em]">
            Browser connection · {state}
          </p>
        </div>

        {state === "disconnected" || state === "failed" ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onReconnect}
            className="border-zinc-700 bg-zinc-900 text-zinc-100 hover:bg-zinc-800 hover:text-white"
          >
            <RefreshCcw aria-hidden="true" />
            Request fresh connection
          </Button>
        ) : null}
      </header>

      <div
        ref={targetRef}
        tabIndex={0}
        aria-label={
          controlAllowed
            ? "Remote Chromium desktop; mouse and keyboard controls are active"
            : "Remote Chromium desktop; view only"
        }
        className="relative h-[420px] w-full overflow-hidden bg-black outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-500 sm:h-[560px] xl:h-[640px]"
      />

      {controlAllowed ? (
      <div className="space-y-3 border-t border-white/10 bg-zinc-950 px-3 py-3 text-zinc-100">
        <div className="flex flex-wrap items-end gap-2">
          <div className="min-w-[220px] flex-1">
            <label
              htmlFor="remote-clipboard-out"
              className="mb-1 block font-mono text-2xs uppercase tracking-[0.1em] text-zinc-400"
            >
              Send text into the remote browser
            </label>
            <input
              id="remote-clipboard-out"
              type="text"
              value={outgoingText}
              onChange={(event) => setOutgoingText(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Enter") {
                  event.preventDefault()
                  handleSendText()
                }
              }}
              autoComplete="off"
              spellCheck={false}
              placeholder="Click the target field in the page first, then send"
              className="w-full rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1.5 text-sm text-zinc-100 placeholder:text-zinc-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            />
          </div>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={handleSendText}
            disabled={state !== "connected"}
            className="border-zinc-700 bg-zinc-900 text-zinc-100 hover:bg-zinc-800 hover:text-white"
          >
            Send text
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => void handlePasteFromLocalClipboard()}
            disabled={state !== "connected"}
            className="border-zinc-700 bg-zinc-900 text-zinc-100 hover:bg-zinc-800 hover:text-white"
          >
            Paste my clipboard
          </Button>
        </div>

        <div>
          <label
            htmlFor="remote-clipboard-in"
            className="mb-1 block font-mono text-2xs uppercase tracking-[0.1em] text-zinc-400"
          >
            Copied inside the remote browser
          </label>
          <div className="flex flex-wrap items-start gap-2">
            <textarea
              id="remote-clipboard-in"
              readOnly
              rows={2}
              value={remoteClipboard}
              placeholder="Copy inside the remote page; the text appears here"
              className="min-w-[220px] flex-1 resize-y rounded-md border border-zinc-700 bg-zinc-900 px-2 py-1.5 font-mono text-xs text-zinc-100 placeholder:text-zinc-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-500"
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => void handleCopyRemoteClipboard()}
              disabled={remoteClipboard.length === 0}
              className="border-zinc-700 bg-zinc-900 text-zinc-100 hover:bg-zinc-800 hover:text-white"
            >
              Copy out
            </Button>
          </div>
        </div>

        <p role="status" aria-live="polite" className="text-2xs text-zinc-400">
          {clipboardNotice}
        </p>
      </div>
      ) : (
        <p className="border-t border-white/10 bg-zinc-950 px-3 py-3 text-2xs text-zinc-400">
          Live view is read-only while the agent is working. Controls unlock only at a human handoff.
        </p>
      )}
    </section>
  )
})
