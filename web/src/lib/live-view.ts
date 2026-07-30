/**
 * Shared live-view vocabulary for the server action and the client panel.
 *
 * The live-view grant's lifecycle is owned by the `autonomous-live-browser-console`
 * spec; this module only names the parts the operator console has to react to, so
 * the reason code is not duplicated as a literal on both sides of the boundary.
 */

/**
 * The one unavailable reason that must NOT degrade to a masked frame.
 *
 * Requirement 18.8: once a run enters the secret capture boundary the backend
 * closes the live view instead of masking it, so the console requests no frame
 * of a credential surface and renders none.
 */
export const SECRET_CAPTURE_BOUNDARY = "secret_capture_boundary_entered"  // pragma: allowlist secret

/** Same-origin masked-frame path. The private API origin is never exposed. */
export function maskedScreenshotPath(runId: string, version: string): string {
  return (
    `/api/control/runs/${encodeURIComponent(runId)}/live-view/screenshot` +
    `?v=${encodeURIComponent(version)}`
  )
}
