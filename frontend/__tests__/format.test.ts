import { describe, expect, it } from "vitest"
import { MISSING, formatBps, formatPps, formatRelative, formatTimeRemaining, formatUtc } from "@/lib/format"

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

describe("formatUtc", () => {
  const now = Date.parse("2026-10-18T12:00:00Z")

  it("renders UTC in 24-hour time regardless of the host time zone", () => {
    expect(formatUtc("2026-10-18T16:49:58Z", now)).toBe("18 Oct 16:49:58 UTC")
    expect(formatUtc("2026-10-18T12:49:58-04:00", now)).toBe("18 Oct 16:49:58 UTC")
    expect(formatUtc("2026-01-02T00:05:09Z", now)).toBe("02 Jan 00:05:09 UTC")
  })

  it("adds the year only outside the current UTC year", () => {
    expect(formatUtc("2025-12-31T23:59:59Z", now)).toBe("31 Dec 2025 23:59:59 UTC")
  })

  it("renders an invalid timestamp as an em dash", () => {
    expect(formatUtc("not-a-date", now)).toBe(MISSING)
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
