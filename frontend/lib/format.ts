// Shared display formatters. Display zones do not change stored timestamps or durations.

/** Shown for a value the backend did not report. Pair with sr-only text where context is unclear. */
export const MISSING = "\u2014"

const NBSP = "\u00a0"
const oneDecimal = new Intl.NumberFormat("en-US", { maximumFractionDigits: 1 })

function isReported(value: number | null | undefined): value is number {
  return value != null && Number.isFinite(value) && value >= 0
}

// Units ascend; use the first whose rounded value stays below 1000, so
// 999.94 Mbps stays "999.9 Mbps" while 999.95 Mbps becomes "1 Gbps".
function scaled(value: number, units: readonly (readonly [number, string])[]): string {
  for (const [index, [divisor, unit]] of units.entries()) {
    const rounded = Math.round((value / divisor) * 10) / 10

    if (rounded < 1000 || index === units.length - 1) return `${oneDecimal.format(rounded)}${unit}`
  }

  return MISSING
}

const BPS_UNITS = [[1, `${NBSP}bps`], [1e3, `${NBSP}Kbps`], [1e6, `${NBSP}Mbps`], [1e9, `${NBSP}Gbps`], [1e12, `${NBSP}Tbps`]] as const
const PPS_UNITS = [[1, `${NBSP}pps`], [1e3, `K${NBSP}pps`], [1e6, `M${NBSP}pps`], [1e9, `G${NBSP}pps`]] as const

export function formatBps(bps: number | null | undefined): string {
  return isReported(bps) ? scaled(bps, BPS_UNITS) : MISSING
}

export function formatPps(pps: number | null | undefined): string {
  return isReported(pps) ? scaled(pps, PPS_UNITS) : MISSING
}

// JavaScriptCore lists UTC in supportedValuesOf; V8 does not. Keep exactly one, first.
export const DISPLAY_TIME_ZONES = ["UTC", ...Intl.supportedValuesOf("timeZone").filter(zone => zone !== "UTC")]
const supportedTimeZones = new Set(DISPLAY_TIME_ZONES)
const dateFormatters = new Map<string, Intl.DateTimeFormat>()

export function isDisplayTimeZone(value: string | null): value is string {
  return value !== null && supportedTimeZones.has(value)
}

function dateParts(date: Date, timeZone: string) {
  if (!isDisplayTimeZone(timeZone)) throw new RangeError("Unsupported display timezone")
  let formatter = dateFormatters.get(timeZone)

  if (!formatter) {
    formatter = new Intl.DateTimeFormat("en-US", {
      timeZone,
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hourCycle: "h23",
      timeZoneName: "longOffset",
    })
    dateFormatters.set(timeZone, formatter)
  }

  return Object.fromEntries(formatter.formatToParts(date).map(p => [p.type, p.value]))
}

function offsetLabel(parts: Record<string, string>): string {
  const offset = parts.timeZoneName.replace("GMT", "UTC")

  return offset === "UTC+00:00" ? "UTC" : offset
}

/** Absolute display time with an unambiguous UTC offset, including during repeated DST hours. */
export function formatTimestamp(value: string | number | Date, timeZone = "UTC", now: number = Date.now()): string {
  const date = new Date(value)

  if (!Number.isFinite(date.getTime())) return MISSING
  const part = dateParts(date, timeZone)
  const current = new Date(now)
  const sameYear = Number.isFinite(current.getTime()) && part.year === dateParts(current, timeZone).year
  const year = sameYear ? "" : ` ${part.year}`

  return `${part.day} ${part.month}${year} ${part.hour}:${part.minute}:${part.second} ${offsetLabel(part)}`
}

/** Chart ticks retain the offset outside UTC so repeated local hours remain distinct. */
export function formatTimestampTick(value: string | number | Date, timeZone = "UTC", withDate = false): string {
  const date = new Date(value)

  if (!Number.isFinite(date.getTime())) return MISSING
  const part = dateParts(date, timeZone)
  const time = `${part.hour}:${part.minute}${timeZone === "UTC" ? "" : ` ${offsetLabel(part)}`}`

  return withDate ? `${part.day} ${part.month} ${time}` : time
}

export function formatClock(value: number, timeZone = "UTC"): string {
  const date = new Date(value)

  if (!Number.isFinite(date.getTime())) return MISSING
  const part = dateParts(date, timeZone)

  return `${part.hour}:${part.minute}:${part.second} ${offsetLabel(part)}`
}

/** Calendar-day identity in the selected zone; does not change chart bucket instants. */
export function displayDateKey(value: string | number | Date, timeZone = "UTC"): string {
  const date = new Date(value)

  if (!Number.isFinite(date.getTime())) return MISSING
  const part = dateParts(date, timeZone)

  return `${part.year}-${part.month}-${part.day}`
}

function compactDuration(ms: number): string {
  const seconds = Math.floor(ms / 1000)

  if (seconds < 60) return `${seconds}s`
  const minutes = Math.floor(seconds / 60)

  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)

  if (hours < 24) return `${hours}h`

  return `${Math.floor(hours / 24)}d`
}

/** Relative time, e.g. "3m ago" or "in 26m". Pair with an absolute display time. */
export function formatRelative(value: string | number | Date, now: number = Date.now()): string {
  const time = new Date(value).getTime()

  if (!Number.isFinite(time)) return MISSING
  const diff = now - time

  return diff >= 0 ? `${compactDuration(diff)} ago` : `in ${compactDuration(-diff)}`
}

/** Remaining lifetime of an expiring mitigation, e.g. "26m" or "1h 5m". */
export function formatTimeRemaining(expiresAt: string, now: number): string {
  const diff = Date.parse(expiresAt) - now

  if (!Number.isFinite(diff)) return "Unavailable"

  if (diff <= 0) return "Expiry due"
  const minutes = Math.floor(diff / 60_000)

  if (minutes === 0) return "<1m"

  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)

  if (hours < 24) return `${hours}h ${minutes % 60}m`

  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}
