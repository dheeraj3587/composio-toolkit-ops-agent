import type { PhaseCollection, PhaseState } from "@/lib/types"

export function phaseMap(collection: PhaseCollection): Map<string, PhaseState> {
  const result = new Map<string, PhaseState>()
  if (Array.isArray(collection)) {
    for (const phase of collection) {
      if (phase.key) result.set(phase.key, phase)
    }
  } else if (collection && typeof collection === "object") {
    for (const [key, phase] of Object.entries(collection)) {
      result.set(key, typeof phase === "string" ? { key, status: phase } : { key, ...(phase ?? {}) })
    }
  }
  return result
}
