"use client"

import Image from "next/image"
import type { RefObject } from "react"
import { ExternalLink, MonitorPlay, RefreshCw } from "lucide-react"

import type { LiveViewState } from "@/app/runs/[runId]/actions"
import {
  PlaywrightRemoteView,
  type PlaywrightRemoteViewHandle,
} from "@/components/playwright-remote-view"
import { Button } from "@/components/ui/button"

// Browser Use's signed viewer is a cross-origin application and requires its
// own origin plus scripts to keep the interactive session authenticated. It
// cannot become same-origin with this control plane, so the paired grants do
// not let it remove the parent-owned sandbox. Downloads, top navigation,
// presentation and storage-access escalation remain intentionally absent.
const BROWSER_USE_IFRAME_SANDBOX =
  "allow-forms allow-modals allow-popups allow-popups-to-escape-sandbox allow-same-origin allow-scripts"

export function BrowserLiveSurface({
  liveState,
  isPlaywright,
  isInteractiveHitl,
  livePending,
  onRequestLiveView,
  remoteViewRef,
}: {
  liveState: LiveViewState
  isPlaywright: boolean
  isInteractiveHitl: boolean
  livePending: boolean
  onRequestLiveView: () => void
  remoteViewRef: RefObject<PlaywrightRemoteViewHandle | null>
}) {
  const interactiveViewVisible =
    isInteractiveHitl &&
    liveState.mode === "interactive_remote" &&
    liveState.interactionAvailable &&
    liveState.interactivePath !== null
  const providerLabel =
    (liveState.provider ?? (isPlaywright ? "playwright" : "browser_use")) === "playwright"
      ? "Playwright browser"
      : "Browser Use session"

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <p className="flex items-center gap-1.5 data-label">
            <MonitorPlay className="size-3 text-brand-600" aria-hidden="true" />
            {providerLabel}
          </p>
          <p className="mt-1 text-[10px] leading-4 text-muted-foreground">
            {isPlaywright
              ? isInteractiveHitl
                ? "Automation is paused. Mouse and keyboard input stay in this isolated session."
                : "Read-only masked frames from the isolated Chromium service."
              : "Interactive hosted browser session."}
          </p>
        </div>
        {!interactiveViewVisible ? (
          <Button
            type="button"
            variant="outline"
            size="sm"
            disabled={livePending}
            onClick={onRequestLiveView}
            className="rounded-md"
          >
            <RefreshCw className={livePending ? "animate-spin motion-reduce:animate-none" : ""} aria-hidden="true" />
            {livePending
              ? "Connecting…"
              : isPlaywright && !isInteractiveHitl
                ? "Refresh frame"
                : "Request connection"}
          </Button>
        ) : null}
      </div>

      {liveState.mode === "hosted_url" && liveState.liveUrl ? (
        <div className="space-y-2">
          <iframe
            src={liveState.liveUrl}
            title="Interactive Browser Use session"
            className="h-[560px] w-full rounded-lg border border-border bg-black"
            allow="clipboard-read; clipboard-write"
            sandbox={BROWSER_USE_IFRAME_SANDBOX}
          />
          <Button asChild variant="outline" size="sm" className="rounded-md">
            <a href={liveState.liveUrl} target="_blank" rel="noopener noreferrer">
              <MonitorPlay className="size-3.5" aria-hidden="true" /> Open in a new tab
              <ExternalLink className="size-3" aria-hidden="true" />
            </a>
          </Button>
        </div>
      ) : interactiveViewVisible && liveState.interactivePath ? (
        <PlaywrightRemoteView
          key={liveState.interactivePath}
          ref={remoteViewRef}
          interactivePath={liveState.interactivePath}
          onReconnect={onRequestLiveView}
        />
      ) : liveState.mode === "screenshot" && liveState.screenshotUrl ? (
        <div className="space-y-2">
          <div className="relative aspect-video min-h-[320px] overflow-hidden rounded-lg border border-border bg-black">
            <Image
              unoptimized
              src={liveState.screenshotUrl}
              alt="Latest masked Playwright browser screenshot"
              width={1600}
              height={900}
              className="h-full w-full object-contain"
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 text-[10px] leading-4 text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <RefreshCw className="size-3" aria-hidden="true" />
              Read-only screenshot — you cannot click inside this view.
            </span>
            {liveState.capturedAt ? <span>Captured {liveState.capturedAt}</span> : null}
          </div>
        </div>
      ) : (
        <div className="grid min-h-[240px] w-full place-items-center rounded-lg border border-dashed border-border bg-muted/30 px-6 text-center text-xs text-muted-foreground">
          {liveState.tone === "error"
            ? (liveState.message ?? "No live browser session is available.")
            : "Connecting to the browser session…"}
        </div>
      )}

      {liveState.message && liveState.mode !== "unavailable" ? (
        <p
          className={liveState.tone === "error" ? "text-xs text-destructive" : "text-xs text-muted-foreground"}
          role={liveState.tone === "error" ? "alert" : "status"}
        >
          {liveState.message}
        </p>
      ) : null}
    </div>
  )
}
