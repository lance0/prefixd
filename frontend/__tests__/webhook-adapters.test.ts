// @vitest-environment node

import { describe, it, expect } from "vitest"
import { validateAdapter } from "@/components/dashboard/correlation/webhook-adapters"
import type { WebhookAdapter } from "@/lib/api"

function base(): WebhookAdapter {
  return {
    name: "radware",
    description: "",
    enabled: true,
    auth: { type: "hmac", secret_env: "PREFIXD_WEBHOOK_RADWARE_SECRET", header: "X-Signature-SHA256", algorithm: "sha256" },
    root_path: null,
    fields: {
      victim_ip: "$.target.ip",
      vector: null,
      timestamp: null,
      bps: null,
      pps: null,
      confidence: null,
      source_id: null,
      top_dst_ports: null,
      action: null,
    },
    vector_map: {},
    default_vector: null,
    confidence_scale: null,
    source_id_prefix: null,
  }
}

describe("validateAdapter", () => {
  it("returns no errors for a valid adapter", () => {
    expect(validateAdapter(base(), [], true)).toEqual([])
  })

  it.each([
    ["Upper"],
    ["has space"],
    ["has/slash"],
    [""],
    ["a".repeat(65)],
    ["-leading-hyphen"],
    ["under_score"],
  ])("rejects invalid name %s", (bad) => {
    const adapter = { ...base(), name: bad }
    const errors = validateAdapter(adapter, [], true)
    expect(errors.some((e) => e.includes("name must match"))).toBe(true)
  })

  it("rejects duplicate name for new adapters", () => {
    const errors = validateAdapter(base(), ["radware"], true)
    expect(errors.some((e) => e.includes("already in use"))).toBe(true)
  })

  it("allows same name when editing existing adapter (isNew=false)", () => {
    const errors = validateAdapter(base(), ["radware"], false)
    expect(errors).toEqual([])
  })

  it("requires fields.victim_ip", () => {
    const adapter = { ...base(), fields: { ...base().fields, victim_ip: "" } }
    const errors = validateAdapter(adapter, [], true)
    expect(errors).toContain("fields.victim_ip is required")
  })

  it("requires auth.secret_env when auth type is hmac", () => {
    const adapter = base()
    adapter.auth = { type: "hmac", secret_env: "", header: "X-Signature-SHA256", algorithm: "sha256" }
    const errors = validateAdapter(adapter, [], true)
    expect(errors).toContain("auth.secret_env is required for HMAC")
  })

  it.each(["PATH", "RADWARE_WEBHOOK_SECRET", "prefixd_webhook_lower"])("refuses secret_env %s outside the PREFIXD_WEBHOOK_ namespace", (name) => {
    const adapter = base()
    adapter.auth = { type: "hmac", secret_env: name, header: "X-Signature-SHA256", algorithm: "sha256" }
    expect(validateAdapter(adapter, [], true)).toContain("auth.secret_env must start with PREFIXD_WEBHOOK_")
  })

  it("requires fields.source_id when an HMAC adapter maps fields.action", () => {
    const adapter = { ...base(), fields: { ...base().fields, action: "$.action" } }
    expect(validateAdapter(adapter, [], true).some((e) => e.startsWith("fields.source_id is required"))).toBe(true)
    expect(validateAdapter({ ...adapter, fields: { ...adapter.fields, source_id: "$.id" } }, [], true)).toEqual([])
    expect(validateAdapter({ ...adapter, auth: { type: "bearer" as const } }, [], true)).toEqual([])
  })

  it("does not require secret_env when auth type is bearer", () => {
    const adapter = { ...base(), auth: { type: "bearer" as const } }
    const errors = validateAdapter(adapter, [], true)
    expect(errors).toEqual([])
  })

  it("does not require secret_env when auth type is none", () => {
    const adapter = { ...base(), auth: { type: "none" as const } }
    const errors = validateAdapter(adapter, [], true)
    expect(errors).toEqual([])
  })

  it("rejects confidence_scale <= 0", () => {
    const adapter = { ...base(), confidence_scale: 0 }
    const errors = validateAdapter(adapter, [], true)
    expect(errors).toContain("confidence_scale must be > 0")
  })

  it("allows null confidence_scale", () => {
    const adapter = { ...base(), confidence_scale: null }
    const errors = validateAdapter(adapter, [], true)
    expect(errors).toEqual([])
  })
})
