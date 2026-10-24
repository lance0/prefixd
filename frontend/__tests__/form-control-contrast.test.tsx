import { readFileSync } from "node:fs"
import path from "node:path"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it } from "vitest"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Select, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"

// jsdom neither runs Tailwind nor resolves custom properties, so the check reads
// the theme tokens from globals.css and computes WCAG contrast directly.
const css = readFileSync(path.resolve(__dirname, "../app/globals.css"), "utf8")

function tokens(selector: string) {
  const block = css.match(new RegExp(`^${selector.replace(".", "\\.")} \\{([^}]*)\\}`, "m"))?.[1] ?? ""

  return Object.fromEntries(Array.from(block.matchAll(/--([\w-]+):\s*([^;]+);/g), ([, name, value]) => [name, value.trim()]))
}

/** Relative luminance of an `oklch(L C H)` token, via OKLab and linear sRGB. */
function luminance(value: string) {
  const [l, c, h] = value.match(/^oklch\(([\d.]+) ([\d.]+) ([\d.]+)\)$/)!.slice(1).map(Number)
  const a = c * Math.cos((h * Math.PI) / 180)
  const b = c * Math.sin((h * Math.PI) / 180)
  const [lc, mc, sc] = [l + 0.3963377774 * a + 0.2158037573 * b, l - 0.1055613458 * a - 0.0638541728 * b, l - 0.0894841775 * a - 1.291485548 * b].map((v) => v ** 3)

  const rgb = [
    4.0767416621 * lc - 3.3077115913 * mc + 0.2309699292 * sc,
    -1.2684380046 * lc + 2.6097574011 * mc - 0.3413193965 * sc,
    -0.0041960863 * lc - 0.7034186147 * mc + 1.707614701 * sc,
  ].map((v) => Math.min(1, Math.max(0, v)))

  return 0.2126 * rgb[0] + 0.7152 * rgb[1] + 0.0722 * rgb[2]
}

function contrast(x: string, y: string) {
  const [hi, lo] = [luminance(x), luminance(y)].sort((p, q) => q - p)

  return (hi + 0.05) / (lo + 0.05)
}

afterEach(cleanup)

describe("form control boundaries", () => {
  it.each([":root", ".dark"])("reach 3:1 against page, card, muted and dialog surfaces in %s", (theme) => {
    const t = tokens(theme)
    expect(t["input-border"]).toBeDefined()

    for (const surface of ["background", "card", "muted", "popover"]) {
      expect(contrast(t["input-border"], t[surface]), `${theme} input-border on ${surface}`).toBeGreaterThanOrEqual(3)
    }
  })

  it("is the boundary token every shared control uses", () => {
    render(
      <>
        <Input aria-label="input" />
        <Textarea aria-label="textarea" />
        <Checkbox aria-label="checkbox" />
        <Select>
          <SelectTrigger aria-label="select"><SelectValue /></SelectTrigger>
        </Select>
      </>,
    )

    for (const name of ["input", "textarea", "checkbox", "select"]) {
      const control = screen.getByLabelText(name)
      expect(control).toHaveClass("border-input-border")
      expect(control.className).not.toMatch(/(^|\s)border-input(\s|$)/)
    }
  })
})
