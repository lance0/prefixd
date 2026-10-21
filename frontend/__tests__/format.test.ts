// @vitest-environment node

import { afterEach, describe, expect, it, vi } from "vitest"
import { MISSING, displayDateKey, formatBps, formatClock, formatPps, formatRelative, formatTimeRemaining, formatTimestamp, formatTimestampTick, isDisplayTimeZone } from "@/lib/format"

const nbsp = "\u00a0"

describe("formatBps", () => {
  it.each([
    [640_000_000, `640${nbsp}Mbps`],
    [5_000_000, `5${nbsp}Mbps`],
    [12_400_000_000, `12.4${nbsp}Gbps`],
    [12_449_999_999, `12.4${nbsp}Gbps`],
    [1_500, `1.5${nbsp}Kbps`],
    [999, `999${nbsp}bps`],
    [0, `0${nbsp}bps`],
    [2_500_000_000_000, `2.5${nbsp}Tbps`],
  ])("formats %d as %s", (bps, label) => {
    expect(formatBps(bps)).toBe(label)
  })

  it("moves to the next unit when rounding reaches it", () => {
    expect(formatBps(999_950_000)).toBe(`1${nbsp}Gbps`)
    expect(formatBps(999_940_000)).toBe(`999.9${nbsp}Mbps`)
  })

  it.each([null, undefined, Number.NaN, Number.POSITIVE_INFINITY, -1])("renders %s as an em dash", (bps) => {
    expect(formatBps(bps)).toBe(MISSING)
    expect(MISSING).toBe("\u2014")
  })
})

describe("formatPps", () => {
  it("uses compact suffixes and an em dash when missing", () => {
    expect(formatPps(3_100_000)).toBe(`3.1M${nbsp}pps`)
    expect(formatPps(220_000)).toBe(`220K${nbsp}pps`)
    expect(formatPps(512)).toBe(`512${nbsp}pps`)
    expect(formatPps(null)).toBe(MISSING)
  })
})

describe("formatTimestamp", () => {
  const now = Date.parse("2026-10-18T12:00:00Z")

  it("renders UTC in 24-hour time regardless of the host time zone", () => {
    expect(formatTimestamp("2026-10-18T16:49:58Z", "UTC", now)).toBe("18 Oct 16:49:58 UTC")
    expect(formatTimestamp("2026-10-18T12:49:58-04:00", "UTC", now)).toBe("18 Oct 16:49:58 UTC")
    expect(formatTimestamp("2026-01-02T00:05:09Z", "UTC", now)).toBe("02 Jan 00:05:09 UTC")
  })

  it("adds the year only outside the current UTC year", () => {
    expect(formatTimestamp("2025-12-31T23:59:59Z", "UTC", now)).toBe("31 Dec 2025 23:59:59 UTC")
  })

  it("renders an invalid timestamp as an em dash", () => {
    expect(formatTimestamp("not-a-date", "UTC", now)).toBe(MISSING)
  })
})

describe("formatRelative", () => {
  const now = Date.parse("2026-10-18T12:00:00Z")

  it.each([
    ["2026-10-18T11:59:15Z", "45s ago"],
    ["2026-10-18T11:57:00Z", "3m ago"],
    ["2026-10-18T09:00:00Z", "3h ago"],
    ["2026-10-16T12:00:00Z", "2d ago"],
    ["2026-10-18T12:26:00Z", "in 26m"],
  ])("formats %s as %s", (value, label) => {
    expect(formatRelative(value, now)).toBe(label)
  })

  it("renders an invalid timestamp as an em dash", () => {
    expect(formatRelative("bad", now)).toBe(MISSING)
  })
})

describe("formatTimeRemaining", () => {
  it("keeps the overview countdown contract", () => {
    const now = Date.parse("2026-10-18T12:00:00Z")
    expect(formatTimeRemaining("2026-10-18T13:05:00Z", now)).toBe("1h 5m")
    expect(formatTimeRemaining("2026-10-18T11:00:00Z", now)).toBe("Expiry due")
  })
})

describe("formatTimestampTick", () => {
  it("uses UTC hours, not the local zone", () => {
    expect(formatTimestampTick("2026-10-18T16:05:00Z")).toBe("16:05")
    expect(formatTimestampTick("2026-10-18T00:00:00+02:00")).toBe("22:00")
  })

  it("adds the UTC day for multi-day ranges and an em dash for bad input", () => {
    expect(formatTimestampTick("2026-10-17T23:30:00Z", "UTC", true)).toBe("17 Oct 23:30")
    expect(formatTimestampTick("not a date")).toBe(MISSING)
  })
})

describe("selected display timezone", () => {
  const zone = "America/New_York"
  const now = Date.parse("2026-10-18T12:00:00Z")

  it.each([
    ["2026-03-08T06:59:59Z", "08 Mar 01:59:59 UTC-05:00"],
    ["2026-03-08T07:00:00Z", "08 Mar 03:00:00 UTC-04:00"],
    ["2026-11-01T05:30:00Z", "01 Nov 01:30:00 UTC-04:00"],
    ["2026-11-01T06:30:00Z", "01 Nov 01:30:00 UTC-05:00"],
  ])("disambiguates DST for %s", (value, expected) => {
    expect(formatTimestamp(value, zone, now)).toBe(expected)
  })

  it("compares years in the selected zone at the year boundary", () => {
    const value = "2027-01-01T01:00:00Z"
    expect(formatTimestamp(value, zone, Date.parse("2027-01-01T02:00:00Z"))).toBe("31 Dec 20:00:00 UTC-05:00")
    expect(formatTimestamp(value, zone, Date.parse("2027-01-01T06:00:00Z"))).toBe("31 Dec 2026 20:00:00 UTC-05:00")
  })

  it("keeps half-hour offsets and the clock explicit", () => {
    expect(formatTimestamp("2026-01-01T00:00:00Z", "Australia/Adelaide", now)).toBe("01 Jan 10:30:00 UTC+10:30")
    expect(formatClock(Date.parse("2026-11-01T06:30:00Z"), zone)).toBe("01:30:00 UTC-05:00")
  })

  it("distinguishes repeated chart hours and detects days in the selected zone", () => {
    expect(formatTimestampTick("2026-11-01T05:30:00Z", zone)).toBe("01:30 UTC-04:00")
    expect(formatTimestampTick("2026-11-01T06:30:00Z", zone)).toBe("01:30 UTC-05:00")
    expect(formatTimestampTick("2027-01-01T01:00:00Z", zone, true)).toBe("31 Dec 20:00 UTC-05:00")
    const before = "2026-10-18T03:30:00Z"
    const after = "2026-10-18T04:30:00Z"
    expect(displayDateKey(before, "UTC")).toBe(displayDateKey(after, "UTC"))
    expect(displayDateKey(before, zone)).not.toBe(displayDateKey(after, zone))
  })

  it.each(["not/a-zone", "+05:00", "", null, "42"])("rejects unsupported preference %s", (value) => {
    expect(isDisplayTimeZone(value)).toBe(false)
  })

  it("does not change relative time, remaining lifetime or the original instant", () => {
    const value = "2026-10-18T13:05:00Z"
    const instant = Date.parse(value)
    expect(formatTimestamp(value, zone, now)).toBe("18 Oct 09:05:00 UTC-04:00")
    expect(formatRelative(value, now)).toBe("in 1h")
    expect(formatTimeRemaining(value, now)).toBe("1h 5m")
    expect(Date.parse(value)).toBe(instant)
  })
})

describe("DISPLAY_TIME_ZONES", () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.resetModules()
  })

  it("lists UTC once and first when the engine already includes it", async () => {
    vi.spyOn(Intl, "supportedValuesOf").mockReturnValue(["America/New_York", "UTC", "Europe/London"])
    vi.resetModules()
    const { DISPLAY_TIME_ZONES } = await import("@/lib/format")

    expect(DISPLAY_TIME_ZONES).toEqual(["UTC", "America/New_York", "Europe/London"])
  })
})
