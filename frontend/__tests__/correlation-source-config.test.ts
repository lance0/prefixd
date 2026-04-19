import { validateSourceConfig } from "@/components/dashboard/correlation/config-tab"
import type { SourceConfig } from "@/lib/api"

function base(overrides: Partial<SourceConfig> = {}): SourceConfig {
  return {
    weight: 1.0,
    type: "detector",
    confidence_mapping: {},
    ...overrides,
  }
}

describe("validateSourceConfig", () => {
  it("accepts a plain primary source with no mode field", () => {
    expect(validateSourceConfig("fastnetmon", base())).toEqual([])
  })

  it("accepts a source with mode=primary and no dims", () => {
    expect(
      validateSourceConfig("fastnetmon", base({ mode: "primary", match_dimensions: [] }))
    ).toEqual([])
  })

  it("rejects a primary source with match_dimensions", () => {
    const errs = validateSourceConfig(
      "fastnetmon",
      base({ mode: "primary", match_dimensions: ["pop"] })
    )
    expect(errs.some((e) => e.includes("match_dimensions is only valid"))).toBe(true)
  })

  it("rejects a corroborating source with no match_dimensions", () => {
    const errs = validateSourceConfig(
      "router-cpu",
      base({ mode: "corroborating", match_dimensions: [] })
    )
    expect(errs.some((e) => e.includes("at least one match_dimension"))).toBe(true)
  })

  it("accepts a corroborating source with one match_dimension", () => {
    expect(
      validateSourceConfig(
        "router-cpu",
        base({ mode: "corroborating", match_dimensions: ["pop"] })
      )
    ).toEqual([])
  })

  it("accepts a corroborating source with multiple dimensions", () => {
    expect(
      validateSourceConfig(
        "router-cpu",
        base({
          mode: "corroborating",
          match_dimensions: ["pop", "customer_id", "interface"],
        })
      )
    ).toEqual([])
  })

  it("rejects a blank name", () => {
    const errs = validateSourceConfig("   ", base())
    expect(errs).toContain("Source name is required")
  })

  it("rejects a negative weight", () => {
    const errs = validateSourceConfig("fastnetmon", base({ weight: -0.1 }))
    expect(errs.some((e) => e.includes("non-negative"))).toBe(true)
  })

  it("rejects NaN weight", () => {
    const errs = validateSourceConfig("fastnetmon", base({ weight: Number.NaN }))
    expect(errs.some((e) => e.includes("non-negative"))).toBe(true)
  })
})
