import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useTabParam } from "@/hooks/use-tab-param"

const nav = vi.hoisted(() => ({ params: new URLSearchParams() }))
vi.mock("next/navigation", () => ({
  usePathname: () => "/config",
  useSearchParams: () => nav.params,
}))

const TABS = ["settings", "playbooks", "alerting"] as const

function Harness() {
  const [tab, setTab] = useTabParam(TABS)
  return (
    <Tabs value={tab} onValueChange={setTab}>
      <TabsList>
        {TABS.map((t) => <TabsTrigger key={t} value={t}>{t}</TabsTrigger>)}
      </TabsList>
      {TABS.map((t) => <TabsContent key={t} value={t}>{t} panel</TabsContent>)}
    </Tabs>
  )
}

const replaceState = vi.spyOn(window.history, "replaceState")

beforeEach(() => { replaceState.mockClear() })
afterEach(cleanup)

describe("useTabParam", () => {
  it("opens the tab named in the URL", () => {
    nav.params = new URLSearchParams("tab=playbooks&ip=203.0.113.10")
    render(<Harness />)
    expect(screen.getByRole("tab", { name: "playbooks" })).toHaveAttribute("aria-selected", "true")
  })

  it("falls back to the first tab for a missing or unknown value", () => {
    nav.params = new URLSearchParams("tab=nope")
    render(<Harness />)
    expect(screen.getByRole("tab", { name: "settings" })).toHaveAttribute("aria-selected", "true")
  })

  it("writes the selection to the URL, keeps other params, and drops the default", () => {
    nav.params = new URLSearchParams("tab=playbooks&ip=203.0.113.10")
    render(<Harness />)
    // Radix tabs activate on mousedown (and on arrow-key focus).
    fireEvent.mouseDown(screen.getByRole("tab", { name: "alerting" }), { button: 0 })
    expect(replaceState).toHaveBeenLastCalledWith(null, "", "/config?tab=alerting&ip=203.0.113.10")
    fireEvent.mouseDown(screen.getByRole("tab", { name: "settings" }), { button: 0 })
    expect(replaceState).toHaveBeenLastCalledWith(null, "", "/config?ip=203.0.113.10")
  })
})
