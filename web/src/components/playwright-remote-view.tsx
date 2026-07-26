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

interface RfbConnection {
  disconnect: () => void
  scaleViewport: boolean
  resizeSession: boolean
  viewOnly: boolean
  addEventListener: (event: "connect" | "disconnect", callback: () => void) => void
  removeEventListener: (event: "connect" | "disconnect", callback: () => void) => void
}

export interface PlaywrightRemoteViewHandle {
  disconnect: () => void
}

interface PlaywrightRemoteViewProps {
  interactivePath: string
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
>(function PlaywrightRemoteView({ interactivePath, onReconnect }, ref) {
  const targetRef = useRef<HTMLDivElement>(null)
  const rfbRef = useRef<RfbConnection | null>(null)
  const [state, setState] = useState<ConnectionState>("connecting")

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
        rfb.viewOnly = false

        rfb.addEventListener("connect", handleConnect)
        rfb.addEventListener("disconnect", handleDisconnect)
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
        if (shouldDisconnect) rfb?.disconnect()
      } catch {
        // Cleanup must not break unmounting or a resume submission.
      }
      target.replaceChildren()
    }
  }, [interactivePath])

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
          <p role="status" aria-live="polite" className="font-mono text-[10px] uppercase tracking-[0.1em]">
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
        aria-label="Remote Chromium desktop; mouse and keyboard controls are active"
        className="min-h-[420px] w-full overflow-hidden bg-black outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-500 sm:min-h-[560px] xl:min-h-[640px]"
      />
    </section>
  )
})
