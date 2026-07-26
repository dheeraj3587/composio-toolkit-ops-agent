"use client"

import { useMemo, useState } from "react"
import type { Control, FieldValues, Path } from "react-hook-form"
import { Controller } from "react-hook-form"

import { Input } from "@/components/ui/input"
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { groupAppsByCategory, useAppCatalog } from "@/lib/app-catalog"

/** Sentinel for "not in the verified catalog", which reveals the free-text input. */
export const OTHER_APP_VALUE = "__other__"

/**
 * Pick the run's target app from the verified catalog.
 *
 * A free-text box required the operator to already know the app's exact name,
 * which is unusable when they do not know what the snapshot contains. The
 * selector lists every verified app grouped by category; the text input remains
 * available behind an explicit "Not listed" choice because the backend still
 * supports one bounded enrichment probe for an app outside the snapshot.
 */
export function AppNameField<TValues extends FieldValues>({
  control,
  invalid,
  describedBy,
}: {
  // Generic over the parent form's values (rather than `any`) so the field stays
  // type-checked against whatever schema owns app_name.
  control: Control<TValues>
  invalid?: boolean
  describedBy?: string
}) {
  const catalog = useAppCatalog()
  const groups = useMemo(() => groupAppsByCategory(catalog.data?.items ?? []), [catalog.data])
  const knownNames = useMemo(
    () => new Set((catalog.data?.items ?? []).map((app) => app.app_name)),
    [catalog.data],
  )
  const [manual, setManual] = useState(false)

  return (
    <Controller
      name={"app_name" as Path<TValues>}
      control={control}
      render={({ field }) => {
        const current = typeof field.value === "string" ? field.value : ""
        // An unrecognised prefill (for example ?app=Something) must not silently
        // look like "nothing selected", so it opens the manual input instead.
        const unlisted = current.length > 0 && !knownNames.has(current)
        const showManual = manual || (unlisted && !catalog.isPending)
        const selectValue = showManual ? OTHER_APP_VALUE : current

        return (
          <div className="space-y-2">
            <Select
              name="app_name_select"
              value={selectValue}
              onValueChange={(value) => {
                if (value === OTHER_APP_VALUE) {
                  setManual(true)
                  field.onChange("")
                  return
                }
                setManual(false)
                field.onChange(value)
              }}
            >
              <SelectTrigger
                id="app_name"
                className="w-full rounded-md bg-white"
                aria-invalid={invalid}
                aria-describedby={describedBy}
                disabled={catalog.isPending}
              >
                <SelectValue
                  placeholder={
                    catalog.isPending
                      ? "Loading the verified catalog…"
                      : catalog.isError
                        ? "Catalog unavailable — enter a name below"
                        : "Select an application"
                  }
                />
              </SelectTrigger>
              <SelectContent className="max-h-72 rounded-md">
                {groups.map(([category, apps]) => (
                  <SelectGroup key={category}>
                    <SelectLabel>{category}</SelectLabel>
                    {apps.map((app) => (
                      <SelectItem key={app.app_slug} value={app.app_name}>
                        {app.app_name}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                ))}
                <SelectGroup>
                  <SelectLabel>Not in the catalog</SelectLabel>
                  <SelectItem value={OTHER_APP_VALUE}>Other — type a name</SelectItem>
                </SelectGroup>
              </SelectContent>
            </Select>

            {showManual || catalog.isError ? (
              <Input
                id="app_name_manual"
                maxLength={120}
                placeholder="e.g. Pipedrive"
                aria-label="Application name"
                aria-invalid={invalid}
                autoComplete="off"
                value={current}
                onChange={(event) => field.onChange(event.target.value.slice(0, 120))}
                onBlur={field.onBlur}
              />
            ) : null}

            {/* The server action reads app_name from the submitted FormData; the
                form builds that payload itself, so this mirror keeps a native
                submit (and browser autofill) consistent with the controlled value. */}
            <input type="hidden" name="app_name" value={current} />
          </div>
        )
      }}
    />
  )
}
