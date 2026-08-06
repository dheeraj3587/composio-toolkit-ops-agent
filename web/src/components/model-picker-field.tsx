"use client"

import { useEffect, useState } from "react"

import { ThinkingModelSelect } from "@/components/thinking-model-select/thinking-model-select"
import type { ThinkingEffort } from "@/components/thinking-select/thinking-select"
import type { ModelCatalogResponse, ModelOption } from "@/lib/types"

const EFFORTS: ThinkingEffort[] = ["instant", "low", "medium", "high"]

const isEffort = (value: string | null | undefined): value is ThinkingEffort =>
  typeof value === "string" && (EFFORTS as string[]).includes(value)

export interface ModelPickerValue {
  /** `<provider>:<model>`, or null to run on the deployment's default chain. */
  modelId: string | null
  effort: ThinkingEffort | null
}

/**
 * Pins one run to one decision model.
 *
 * The catalog is the backend's answer, not this component's: it lists only
 * providers whose key is configured, so a model can never be offered that the
 * inference chain would fail to build. When the catalog cannot be read the
 * field says so and the run proceeds on the deployment default — a preference
 * must never be able to block a run.
 */
export function ModelPickerField({
  value,
  onChange,
  disabled = false,
}: {
  value: ModelPickerValue
  onChange: (next: ModelPickerValue) => void
  disabled?: boolean
}) {
  const [catalog, setCatalog] = useState<ModelCatalogResponse | null>(null)
  const [failed, setFailed] = useState(false)

  useEffect(() => {
    let cancelled = false
    fetch("/api/ops/models", { cache: "no-store" })
      .then((response) => (response.ok ? response.json() : Promise.reject()))
      .then((body: ModelCatalogResponse) => {
        if (!cancelled) setCatalog(body)
      })
      .catch(() => {
        if (!cancelled) setFailed(true)
      })
    return () => {
      cancelled = true
    }
  }, [])

  const models = catalog?.models ?? []
  const selected = models.find((option) => option.id === value.modelId) ?? null
  const supportsEffort = selected?.supports_effort ?? false

  return (
    <fieldset className="space-y-2" disabled={disabled}>
      <legend className="data-label">Decision model</legend>
      <p className="text-xs leading-5 text-muted-foreground">
        The model that reads each page and chooses the next action. Only
        providers with a configured key are listed. Leave it unset to use the
        deployment&apos;s own chain.
      </p>

      {failed ? (
        <p className="text-xs leading-5 text-muted-foreground">
          The model catalog could not be read. This run will use the
          deployment&apos;s default chain.
        </p>
      ) : !catalog ? (
        <p className="text-xs leading-5 text-muted-foreground">
          Reading the configured providers…
        </p>
      ) : !models.length ? (
        <p className="text-xs leading-5 text-muted-foreground">
          No provider key is configured, so no model can be pinned. This run
          will use the deployment&apos;s default chain.
        </p>
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          <ThinkingModelSelect
            models={models.map(toAiModel)}
            value={value.modelId ?? undefined}
            effort={value.effort ?? defaultEffort(catalog, selected)}
            onValueChange={(modelId) => {
              const next = models.find((option) => option.id === modelId) ?? null
              onChange({
                modelId,
                // Effort is only carried for models that really honour it; the
                // rest report it unsupported and the backend rejects it.
                effort: next?.supports_effort
                  ? (value.effort ?? defaultEffort(catalog, next))
                  : null,
              })
            }}
            onEffortChange={(effort) => {
              if (!supportsEffort) return
              onChange({ modelId: value.modelId, effort })
            }}
            placeholder="Deployment default"
            size="md"
          />
          {value.modelId ? (
            <button
              type="button"
              className="text-xs text-muted-foreground underline underline-offset-2 hover:text-foreground"
              onClick={() => onChange({ modelId: null, effort: null })}
            >
              Use deployment default
            </button>
          ) : null}
          {selected && !supportsEffort ? (
            <p className="text-xs text-muted-foreground">
              This model does not expose a reasoning effort dial.
            </p>
          ) : null}
        </div>
      )}
    </fieldset>
  )
}

/**
 * What the dial reads before the operator touches it.
 *
 * This used to take `effort_values[0]` — the *lowest* level the model accepts,
 * "instant" on Mercury. The form submits whatever the dial shows, so leaving it
 * alone silently ran at the floor while the backend's own no-preference answer
 * (`default_effort_for`) was the deployment default. The catalog's answer comes
 * first now, and the fallback is the highest level the model takes rather than
 * the lowest, so an unread catalog cannot quietly downgrade a run either.
 */
function defaultEffort(
  catalog: ModelCatalogResponse,
  option: ModelOption | null,
): ThinkingEffort {
  const accepted = option?.effort_values ?? []
  const deploymentDefault = catalog.default_effort
  if (
    isEffort(deploymentDefault) &&
    (!accepted.length || accepted.includes(deploymentDefault))
  ) {
    return deploymentDefault
  }
  const highest = accepted[accepted.length - 1]
  return isEffort(highest) ? highest : "high"
}

/** Map a catalog entry onto the shape `ModelSelect` renders. */
function toAiModel(option: ModelOption) {
  return {
    id: option.id,
    name: option.label,
    provider: option.provider,
    reasoning: option.supports_effort,
    tag: option.is_default ? "default" : undefined,
  }
}
