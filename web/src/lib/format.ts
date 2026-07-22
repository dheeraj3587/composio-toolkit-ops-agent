const utcTimestamp = new Intl.DateTimeFormat("en-GB", {
  day: "2-digit",
  month: "short",
  year: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
  timeZone: "UTC",
})

export function formatTimestamp(value: string): string {
  const date = new Date(value)
  return isValid(date) ? utcTimestamp.format(date) : "Time unavailable"
}

export function relativeTimestamp(value: string): string {
  const date = new Date(value)
  return isValid(date) ? formatDistanceToNowStrict(date, { addSuffix: true }) : "Time unavailable"
}

export function humanize(value: string | null | undefined): string {
  if (!value) return "Not reported"
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase())
}
import { formatDistanceToNowStrict, isValid } from "date-fns"
