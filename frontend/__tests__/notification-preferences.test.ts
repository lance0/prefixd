import { describe, expect, it } from "vitest"
import { shouldShowToast } from "@/components/websocket-provider"
import type { NotificationPreferences } from "@/lib/api"

describe("shouldShowToast", () => {
  it("shows all toasts when prefs is undefined", () => {
    expect(shouldShowToast("mitigation_created", undefined)).toBe(true)
    expect(shouldShowToast("mitigation_expired", undefined)).toBe(true)
    expect(shouldShowToast("resync_required", undefined)).toBe(true)
  })

  it("shows all toasts when prefs has no mutes and no quiet hours", () => {
    const prefs: NotificationPreferences = {
      muted_events: [],
      quiet_hours_start: null,
      quiet_hours_end: null,
    }

    expect(shouldShowToast("mitigation_created", prefs)).toBe(true)
    expect(shouldShowToast("mitigation_expired", prefs)).toBe(true)
  })

  it("suppresses muted event types", () => {
    const prefs: NotificationPreferences = {
      muted_events: ["mitigation.expired", "config.reloaded"],
      quiet_hours_start: null,
      quiet_hours_end: null,
    }

    expect(shouldShowToast("mitigation_expired", prefs)).toBe(false)
    expect(shouldShowToast("resync_required", prefs)).toBe(false)
    expect(shouldShowToast("mitigation_created", prefs)).toBe(true)
    expect(shouldShowToast("mitigation_updated", prefs)).toBe(true)
  })

  it("suppresses non-critical events during quiet hours", () => {
    const now = new Date().getUTCHours()

    const prefs: NotificationPreferences = {
      muted_events: [],
      quiet_hours_start: now,
      quiet_hours_end: (now + 2) % 24,
    }

    // Non-critical: suppressed
    expect(shouldShowToast("mitigation_withdrawn", prefs)).toBe(false)
    expect(shouldShowToast("mitigation_expired", prefs)).toBe(false)
    expect(shouldShowToast("resync_required", prefs)).toBe(false)
    // Critical: still shown
    expect(shouldShowToast("mitigation_created", prefs)).toBe(true)
    expect(shouldShowToast("mitigation_updated", prefs)).toBe(true)
  })

  it("shows non-critical events outside quiet hours", () => {
    const now = new Date().getUTCHours()
    // Set quiet hours to a window that doesn't include now
    const start = (now + 4) % 24
    const end = (now + 6) % 24

    const prefs: NotificationPreferences = {
      muted_events: [],
      quiet_hours_start: start,
      quiet_hours_end: end,
    }

    expect(shouldShowToast("mitigation_expired", prefs)).toBe(true)
    expect(shouldShowToast("mitigation_withdrawn", prefs)).toBe(true)
  })

  it("handles quiet hours wrapping midnight", () => {
    const now = new Date().getUTCHours()
    // Wrap: start > end means overnight (e.g. 22:00-06:00)
    // Set so 'now' is inside the wrap window
    const start = (now - 1 + 24) % 24
    const end = (now + 2) % 24

    const prefs: NotificationPreferences = {
      muted_events: [],
      quiet_hours_start: start,
      quiet_hours_end: end,
    }

    expect(shouldShowToast("mitigation_expired", prefs)).toBe(false)
    expect(shouldShowToast("mitigation_created", prefs)).toBe(true)
  })

  it("shows toast for unknown WS message types", () => {
    const prefs: NotificationPreferences = {
      muted_events: ["mitigation.created"],
      quiet_hours_start: null,
      quiet_hours_end: null,
    }

    expect(shouldShowToast("SomeUnknownType", prefs)).toBe(true)
  })

  it("muting takes precedence over quiet hours critical exception", () => {
    const now = new Date().getUTCHours()

    const prefs: NotificationPreferences = {
      muted_events: ["mitigation.created"],
      quiet_hours_start: now,
      quiet_hours_end: (now + 2) % 24,
    }

    // Created is critical (would survive quiet hours) but is explicitly muted
    expect(shouldShowToast("mitigation_created", prefs)).toBe(false)
  })
})
