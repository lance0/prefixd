import { afterEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { PlaybookYamlEditor } from "@/components/dashboard/playbook-yaml-editor"
import type { ConfigPlaybook } from "@/lib/api"

const playbooks: ConfigPlaybook[] = [{
  name: "udp-policy",
  match: { vector: "udp_flood", require_top_ports: true },
  steps: [
    { action: "police", rate_bps: 8000000, ttl_seconds: 120 },
    { action: "discard", ttl_seconds: 180, require_confidence_at_least: 0, require_persistence_seconds: 60 },
  ],
}]

afterEach(cleanup)

/** The YAML editor's textarea, checked rather than asserted. */
function yamlText(): string {
  const textbox = screen.getByRole("textbox")

  if (!(textbox instanceof HTMLTextAreaElement)) throw new Error("expected the YAML textarea")

  return textbox.value
}

function edit(text: string) {
  fireEvent.change(screen.getByRole("textbox"), { target: { value: text } })
}

describe("playbook YAML editing", () => {
  it("round-trips generated YAML and preserves zero confidence when applying an edit", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<PlaybookYamlEditor playbooks={playbooks} onSave={onSave} saving={false} />)
    const initial = yamlText()
    expect(initial).toContain("require_confidence_at_least: 0")
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled()

    edit(initial.replace("ttl_seconds: 120", "ttl_seconds: 121"))
    fireEvent.click(screen.getByRole("button", { name: "Apply" }))

    await waitFor(() => expect(onSave).toHaveBeenCalledWith([{
      ...playbooks[0],
      steps: [{ ...playbooks[0].steps[0], ttl_seconds: 121 }, playbooks[0].steps[1]],
    }]))
  })

  it.each([
    { label: "ASCII maximum", name: "a".repeat(128), valid: true },
    { label: "ASCII over maximum", name: "a".repeat(129), valid: false },
    { label: "two-byte maximum", name: "é".repeat(64), valid: true },
    { label: "two-byte over maximum", name: `${"é".repeat(64)}a`, valid: false },
    { label: "four-byte maximum", name: "\u{10400}".repeat(32), valid: true },
    { label: "four-byte over maximum", name: `${"\u{10400}".repeat(32)}a`, valid: false },
  ])("counts UTF-8 name bytes: $label", async ({ name, valid }) => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<PlaybookYamlEditor playbooks={playbooks} onSave={onSave} saving={false} />)
    const initial = yamlText()
    edit(initial.replace("udp-policy", name))
    const apply = screen.getByRole("button", { name: "Apply" })

    if (valid) {
      expect(apply).toBeEnabled()
      fireEvent.click(apply)
      await waitFor(() => expect(onSave).toHaveBeenCalledWith([{ ...playbooks[0], name }]))
    } else {
      expect(apply).toBeDisabled()
      expect(screen.getByText(/name exceeds 128 bytes/)).toBeVisible()
      fireEvent.click(apply)
      expect(onSave).not.toHaveBeenCalled()
    }
  })

  it("preserves merged action values before validation and submission", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined)
    render(<PlaybookYamlEditor playbooks={playbooks} onSave={onSave} saving={false} />)
    edit(`defaults: &defaults
  action: discard
playbooks:
  - name: merged-policy
    match:
      vector: udp_flood
    steps:
      - <<: *defaults
        ttl_seconds: 75
        rate_bps: 8000000
`)
    fireEvent.click(screen.getByRole("button", { name: "Apply" }))

    await waitFor(() => expect(onSave).toHaveBeenCalledWith([{
      name: "merged-policy",
      match: { vector: "udp_flood", require_top_ports: false },
      steps: [{ action: "discard", ttl_seconds: 75, rate_bps: 8000000 }],
    }]))
  })

  it.each([
    "",
    "playbooks: [",
    "playbooks: not-an-array",
    'playbooks: !!js/function "function () { return 1 }"',
  ])("blocks applying an empty, malformed or unsafe YAML draft: %j", (draft) => {
    const onSave = vi.fn()
    render(<PlaybookYamlEditor playbooks={playbooks} onSave={onSave} saving={false} />)
    edit(draft)

    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled()
    expect(screen.getByText(/YAML parse error:|top-level 'playbooks' array/)).toBeVisible()
    fireEvent.click(screen.getByRole("button", { name: "Apply" }))
    expect(onSave).not.toHaveBeenCalled()
  })

  it("names an unknown step action instead of submitting it", () => {
    const onSave = vi.fn()
    render(<PlaybookYamlEditor playbooks={playbooks} onSave={onSave} saving={false} />)
    edit(yamlText().replace("action: discard", "action: drop"))

    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled()
    expect(screen.getByText('Playbook "udp-policy" step 2: action must be one of police, discard')).toBeVisible()
    fireEvent.click(screen.getByRole("button", { name: "Apply" }))
    expect(onSave).not.toHaveBeenCalled()
  })
})
