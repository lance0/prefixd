import { afterEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { PlaybookEditor } from "@/components/dashboard/playbook-editor"
import { PlaybookYamlEditor } from "@/components/dashboard/playbook-yaml-editor"
import type { ConfigPlaybook } from "@/lib/api"

// Shaped like GET /v1/config/playbooks: every optional field is present as null.
const fromApi = [
  {
    name: "udp_flood_police_first",
    match: { vector: "udp_flood", require_top_ports: false },
    correlation: null,
    steps: [
      { action: "police", rate_bps: 5000000, ttl_seconds: 1800, require_confidence_at_least: null, require_persistence_seconds: null },
      { action: "discard", rate_bps: null, ttl_seconds: 1800, require_confidence_at_least: 0.7, require_persistence_seconds: 120 },
    ],
  },
  {
    name: "syn_flood_police",
    match: { vector: "syn_flood", require_top_ports: false },
    correlation: { min_sources: 2, confidence_threshold: null, confidence_decay_half_life_seconds: null },
    steps: [{ action: "police", rate_bps: 10000000, ttl_seconds: 1800, require_confidence_at_least: null, require_persistence_seconds: null }],
  },
  // SAFETY: the fixture mirrors the API's null-for-absent JSON, which the optional-field type models as undefined.
] as unknown as ConfigPlaybook[]

afterEach(cleanup)

describe("playbook form editor", () => {
  it("is clean on load when the API sends null optional fields and a correlation key", () => {
    render(<PlaybookEditor playbooks={fromApi} onSave={vi.fn()} saving={false} />)
    expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: /Save all/ })).toBeDisabled()
    expect(screen.getByRole("button", { name: /Discard/ })).toBeDisabled()
  })

  it("marks a real edit dirty and saves without dropping correlation overrides", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<PlaybookEditor playbooks={fromApi} onSave={onSave} saving={false} />)
    fireEvent.click(screen.getByRole("button", { name: "Remove playbook udp_flood_police_first" }))
    expect(screen.getByText("Unsaved changes")).toBeInTheDocument()

    fireEvent.click(screen.getByRole("button", { name: /Save all/ }))
    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1))
    expect(onSave.mock.calls[0][0]).toEqual([fromApi[1]])
  })
})

describe("playbook YAML editor", () => {
  it("round-trips a correlation override and omits unset fields", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<PlaybookYamlEditor playbooks={fromApi} onSave={onSave} saving={false} />)
    const text = (screen.getByRole("textbox") as HTMLTextAreaElement).value
    expect(text).toContain("min_sources: 2")
    expect(text).not.toContain("confidence_threshold")
    expect(screen.queryByText("Unsaved changes")).not.toBeInTheDocument()

    fireEvent.change(screen.getByRole("textbox"), { target: { value: text.replace("ttl_seconds: 1800", "ttl_seconds: 900") } })
    fireEvent.click(screen.getByRole("button", { name: "Apply" }))
    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1))
    expect(onSave.mock.calls[0][0][1].correlation).toEqual({ min_sources: 2 })
  })
})
