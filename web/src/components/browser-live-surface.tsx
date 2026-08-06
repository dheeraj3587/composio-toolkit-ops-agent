"use client"

import Image from "next/image"
import { useState, type RefObject } from "react"
import { ExternalLink, MonitorPlay, RefreshCw, ShieldCheck } from "lucide-react"

import type { LiveViewState } from "@/app/runs/[runId]/actions"
import {
  PlaywrightRemoteView,
  type PlaywrightRemoteViewHandle,
} from "@/components/playwright-remote-view"
import { Button } from "@/components/ui/button"
import { SECRET_CAPTURE_BOUNDARY } from "@/lib/live-view"

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
  // Requirement 18.3: a masked frame that cannot load must not leave a broken
  // image behind. Tracking the URL that failed lets a newer frame try again
  // without an effect resetting the flag.
  const [failedFrameUrl, setFailedFrameUrl] = useState<string | null>(null)
  const interactiveViewVisible =
    isPlaywright &&
    liveState.mode === "interactive_remote" &&
    liveState.interactivePath !== null
  const hostedEmbedVisible = liveState.mode === "hosted_url" && liveState.liveUrl !== null
  // Requirement 18.8: the capture boundary closes the view. This is the one
  // unavailable state that must never degrade to a frame.
  const captureBoundaryClosed = liveState.reasonCode === SECRET_CAPTURE_BOUNDARY
  // Requirement 18.3: whenever no embed is renderable, the masked screenshot is
  // the fallback view — including while the grant reports the embed unavailable.
  const maskedFrameVisible =
    !captureBoundaryClosed &&
    !hostedEmbedVisible &&
    !interactiveViewVisible &&
    liveState.screenshotUrl !== null &&
    liveState.screenshotUrl !== failedFrameUrl
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
          <p className="mt-1 text-[12px] leading-4 text-muted-foreground">
            {isPlaywright
              ? isInteractiveHitl
                ? "Automation is paused. Mouse and keyboard input stay in this isolated session."
                : "Read-only live stream from the isolated Chromium service."
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

      {captureBoundaryClosed ? (
        <div
          data-testid="live-view-capture-boundary"
          role="status"
          className="grid min-h-[240px] w-full place-items-center rounded-lg border border-dashed border-border bg-muted/30 px-6 text-center text-xs text-muted-foreground"
        >
          <p className="max-w-sm">
            <ShieldCheck className="mx-auto mb-2 size-4 text-brand-600" aria-hidden="true" />
            The live view is closed while this run is on a credential surface. No frame of that page
            is captured or shown — not even a masked one.
          </p>
        </div>
      ) : hostedEmbedVisible && liveState.liveUrl ? (
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
          controlAllowed={liveState.interactionAvailable}
          onReconnect={onRequestLiveView}
        />
      ) : maskedFrameVisible && liveState.screenshotUrl ? (
        <div className="space-y-2" data-testid="live-view-masked-frame">
          <div className="relative aspect-video min-h-[320px] overflow-hidden rounded-lg border border-border bg-black">
            <Image
              unoptimized
              src={liveState.screenshotUrl}
              alt={
                liveState.mode === "unavailable"
                  ? "Latest masked browser screenshot, shown because the live embed is unavailable"
                  : "Latest masked Playwright browser screenshot"
              }
              width={1600}
              height={900}
              className="h-full w-full object-contain"
              onError={() => setFailedFrameUrl(liveState.screenshotUrl)}
            />
          </div>
          <div className="flex flex-wrap items-center justify-between gap-2 text-[12px] leading-4 text-muted-foreground">
            <span className="inline-flex items-center gap-1.5">
              <RefreshCw className="size-3" aria-hidden="true" />
              {liveState.mode === "unavailable"
                ? "The live embed is unavailable, so this masked frame is the fallback view."
                : "Read-only screenshot — you cannot click inside this view."}
            </span>
            {liveState.capturedAt ? <span>Captured {liveState.capturedAt}</span> : null}
          </div>
        </div>
      ) : (
        <div
          data-testid="live-view-empty-panel"
          className="grid min-h-[240px] w-full place-items-center rounded-lg border border-dashed border-border bg-muted/30 px-6 text-center text-xs text-muted-foreground"
        >
          {liveState.screenshotUrl !== null && liveState.screenshotUrl === failedFrameUrl
            ? "No live browser embed is available, and no masked frame has been captured for this run yet."
            : liveState.tone === "error"
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
