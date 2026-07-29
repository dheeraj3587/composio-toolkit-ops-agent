"use client"

import { useMemo } from "react"
import type { Control, FieldValues, Path } from "react-hook-form"
import { Controller } from "react-hook-form"

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

/**
 * Pick the run's target app from the verified catalog.
 *
 * A free-text box required the operator to already know the app's exact name,
 * which is unusable when they do not know what the snapshot contains. The
 * selector lists every reviewed app grouped by category and deliberately has no
 * "other" escape hatch: canonical production runs are recipe-bound, so accepting
 * an unknown name here would only fail later and imply unsupported automation.
 */
export function AppNameField<TValues extends FieldValues>({
  control,
  invalid,
  describedBy,
  errorMessage,
}: {
  // Generic over the parent form's values (rather than `any`) so the field stays
  // type-checked against whatever schema owns app_name.
  control: Control<TValues>
  invalid?: boolean
  describedBy?: string
  errorMessage?: string
}) {
  const catalog = useAppCatalog()
  const groups = useMemo(() => groupAppsByCategory(catalog.data?.items ?? []), [catalog.data])
  const knownNames = useMemo(
    () => new Set((catalog.data?.items ?? []).map((app) => app.app_name)),
    [catalog.data],
  )

  return (
    <Controller
      name={"app_name" as Path<TValues>}
      control={control}
      render={({ field }) => {
        const current = typeof field.value === "string" ? field.value : ""
        const selectValue = knownNames.has(current) ? current : ""

        return (
          <div className="space-y-2">
            <Select
              name="app_name_select"
              value={selectValue}
              onValueChange={field.onChange}
            >
              <SelectTrigger
                id="app_name"
                className="w-full rounded-md bg-white"
                aria-invalid={invalid}
                aria-describedby={describedBy}
                aria-errormessage={errorMessage}
                disabled={catalog.isPending}
              >
                <SelectValue
                  placeholder={
                    catalog.isPending
                      ? "Loading the verified catalog…"
                      : catalog.isError
                        ? "Verified catalog unavailable"
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
              </SelectContent>
            </Select>

            {catalog.isError ? (
              <p className="text-xs text-destructive" role="alert">
                The reviewed app catalog is unavailable. No run can be started safely.
              </p>
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
