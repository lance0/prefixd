import { Suspense } from "react"
import { act, fireEvent, render, screen, within } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"
import { DISPOSITION_LABEL, ExportEvidenceCard } from "@/components/dashboard/export-evidence"
import { TimeZoneProvider, TIME_ZONE_STORAGE_KEY, useTimeZone } from "@/components/time-zone-provider"
import type { BlackholeExportEvidence, Mitigation, PeerExport } from "@/lib/api"
import { json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const observedAt = "2026-10-20T12:00:00Z"

function peer(peer_address: string, disposition: PeerExport["disposition"], reason = "", explain_code = "", detail = ""): PeerExport {
  return { peer_address, disposition, reason, explain_code, detail, advertised_path_id: 0 }
}

function evidence(overrides: Partial<BlackholeExportEvidence>): BlackholeExportEvidence {
  return {
    status: "observed",
    historical: false,
    observed_at: observedAt,
    peers: [],
    not_established_peers: [],
    counts: { committed: 0, withheld: 0, pending: 0 },
    warning: null,
    error: null,
    ...overrides,
  }
}

const mixed = evidence({
  peers: [
    peer("192.0.2.10", "committed"),
    peer("192.0.2.11", "withheld", "export_policy", "policy_denied", "export policy \"rtbh-out\" denied this route"),
    peer("2001:db8::12", "pending", "not_yet_committed"),
  ],
  not_established_peers: [{ peer_address: "192.0.2.13", state: "active" }],
  counts: { committed: 1, withheld: 1, pending: 1 },
})

describe("export evidence card", () => {
  it("formats the retained observation in the selected display timezone", () => {
    function ChooseTimeZone() {
      const { setTimeZone } = useTimeZone()

      return <button onClick={() => setTimeZone("America/New_York")}>Choose New York</button>
    }

    const saved = localStorage.getItem(TIME_ZONE_STORAGE_KEY)

    try {
      localStorage.removeItem(TIME_ZONE_STORAGE_KEY)
      render(<TimeZoneProvider><ChooseTimeZone /><ExportEvidenceCard evidence={{ ...mixed, historical: true }} now={Date.parse("2026-10-21T12:00:00Z")} /></TimeZoneProvider>)
      expect(screen.getByText("20 Oct 12:00:00 UTC")).toHaveAttribute("dateTime", observedAt)
      fireEvent.click(screen.getByRole("button", { name: "Choose New York" }))
      expect(screen.getByText("20 Oct 08:00:00 UTC-04:00")).toHaveAttribute("dateTime", observedAt)
      expect(screen.getByText("Historical export evidence")).toHaveAttribute("data-tone", "neutral")
    } finally {
      if (saved === null) localStorage.removeItem(TIME_ZONE_STORAGE_KEY)
      else localStorage.setItem(TIME_ZONE_STORAGE_KEY, saved)
    }
  })

  it("keeps historical rows and time without a green current export claim", () => {
    render(<ExportEvidenceCard evidence={{ ...mixed, historical: true }} />)
    const card = screen.getByTestId("export-evidence")
    expect(within(card).getByText("Historical export evidence")).toHaveAttribute("data-tone", "neutral")
    expect(within(card).getByRole("status")).toHaveTextContent("Current export is unknown until a fresh complete read")
    expect(within(card).getAllByRole("row")).toHaveLength(4)
    expect(within(card).getByText("Committed")).toHaveAttribute("data-tone", "neutral")
    expect(within(card).getByText(/^20 Oct/)).toHaveAttribute("dateTime", observedAt)
    expect(within(card).queryByText(/^Committed to/)).not.toBeInTheDocument()
  })

  it("keeps a failed historical refresh and its warning distinct from a current denial", () => {
    render(<ExportEvidenceCard evidence={evidence({
      historical: true,
      status: "error",
      peers: [peer("192.0.2.11", "withheld", "export_policy")],
      counts: { committed: 0, withheld: 1, pending: 0 },
      warning: { reason: "export_policy", message: "Export policy denies it." },
      error: "speaker unavailable",
    })} />)
    const card = screen.getByTestId("export-evidence")
    expect(card).toHaveTextContent("At the retained observation, no Established peer had this blackhole")
    expect(card).toHaveTextContent("The last export read failed: speaker unavailable")
    expect(card).toHaveTextContent("Export is unknown, not empty")
    expect(card).not.toHaveTextContent("Export policy denies it.")
    expect(within(card).getByRole("table")).toHaveTextContent("192.0.2.11")
  })

  it("lists every Established peer with its disposition, reason and explain code, and peers without a session", () => {
    render(<ExportEvidenceCard evidence={mixed} />)
    const card = screen.getByTestId("export-evidence")
    expect(within(card).getByText("Committed to 1 of 3 Established peers")).toHaveAttribute("data-tone", "success")
    const rows = within(card).getAllByRole("row").slice(1)
    expect(rows.map((row) => row.textContent)).toEqual([
      "192.0.2.10Committed——",
      "192.0.2.11Withheldexport_policyexport policy \"rtbh-out\" denied this routepolicy_denied",
      "2001:db8::12Pendingnot_yet_committed—",
    ])
    expect(within(rows[1]).getByText("Withheld")).toHaveAttribute("data-tone", "danger")
    expect(within(rows[2]).getByText("Pending")).toHaveAttribute("data-tone", "warning")
    expect(card).toHaveTextContent("Configured, not Established (sent nothing): 192.0.2.13 (active)")
    expect(card).toHaveTextContent("router enforcement is not verified here")
    expect(within(card).getByText(/^20 Oct/)).toHaveAttribute("dateTime", observedAt)
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })

  it("never labels a committed export as installed or enforced", () => {
    render(<ExportEvidenceCard evidence={evidence({ peers: [peer("192.0.2.10", "committed")], counts: { committed: 1, withheld: 0, pending: 0 } })} />)
    const row = screen.getAllByRole("row")[1]
    expect(row.textContent).not.toMatch(/install|enforc/i)
    expect(screen.getByText(/^Committed to/).textContent).not.toMatch(/install|enforc/i)
    expect(Object.values(DISPOSITION_LABEL).map(({ label }) => label).join(" ")).not.toMatch(/install|enforc/i)
  })

  it("alerts when the blackhole is exported to no peer, with the reason", () => {
    render(<ExportEvidenceCard evidence={evidence({
      peers: [peer("192.0.2.11", "withheld", "export_policy", "policy_denied")],
      counts: { committed: 0, withheld: 1, pending: 0 },
      warning: { reason: "export_policy", message: "Export policy denies it toward every Established peer; check the speaker's export policy." },
    })} />)
    expect(screen.getByText("Exported to no peer")).toHaveAttribute("data-tone", "danger")
    const alert = screen.getByRole("alert")
    expect(alert).toHaveTextContent("so no router is sent it")
    expect(alert).toHaveTextContent("check the speaker's export policy")
    expect(alert).not.toHaveTextContent("RPKI-Invalid")
    expect(alert).toHaveTextContent("(export_policy)")
  })

  it("treats a failed read as unknown export, not an empty peer list", () => {
    render(<ExportEvidenceCard evidence={evidence({ status: "error", observed_at: observedAt, not_established_peers: null, error: "internal error: rustbgpd: ListPathExportDispositions RPC failed: Unavailable" })} />)
    expect(screen.getByText("Export unknown")).toHaveAttribute("data-tone", "danger")
    expect(screen.getByRole("alert")).toHaveTextContent("Export is unknown, not empty")
    expect(screen.queryByRole("table")).not.toBeInTheDocument()
    expect(screen.queryByText(/Exported to no peer|Committed to/)).not.toBeInTheDocument()
  })

  it("labels a warning kept through a failed read as the last complete read's", () => {
    render(<ExportEvidenceCard evidence={evidence({ status: "error", observed_at: observedAt, not_established_peers: null, error: "read failed", warning: { reason: "export_policy", message: "Export policy denies it." } })} />)
    expect(screen.getByText("Export unknown")).toHaveAttribute("data-tone", "danger")
    const [warning] = screen.getAllByRole("alert")
    expect(warning).toHaveTextContent("At the last complete read, no Established peer had this blackhole")
  })

  it.each([
    ["unsupported", "Not reported by this speaker", "neutral"],
    ["not_observed", "Not observed yet", "neutral"],
    ["no_local_route", "No local route on the speaker", "warning"],
  ] as const)("distinguishes %s", (status, label, tone) => {
    render(<ExportEvidenceCard evidence={evidence({ status, observed_at: null, not_established_peers: null })} />)
    expect(screen.getByText(label)).toHaveAttribute("data-tone", tone)
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })

  it.each(["observed", "error", "unsupported", "not_observed", "no_local_route"] as const)("shows FlowSpec %s without calling it a blackhole", (status) => {
    render(<ExportEvidenceCard kind="flowspec" evidence={evidence({
      status,
      peers: status === "observed" || status === "error" ? [peer("192.0.2.11", "withheld", "family_not_negotiated")] : [],
      warning: status === "observed" || status === "error" ? { reason: "family_not_negotiated", message: "No Established session negotiated its address family." } : null,
      error: status === "error" ? "speaker unavailable" : null,
    })} />)
    const card = screen.getByTestId("export-evidence")
    expect(card).not.toHaveTextContent("blackhole")
    expect(card).toHaveTextContent("router enforcement is not verified here")

    if (status === "observed" || status === "error" || status === "no_local_route") expect(card).toHaveTextContent("FlowSpec rule")

    if (status === "error") {
      expect(card).toHaveTextContent("Export is unknown, not empty")
      expect(within(card).getByText("Withheld")).toHaveAttribute("data-tone", "neutral")
      expect(card).toHaveTextContent("Export at observation")
    }
  })

  it("labels retained FlowSpec observations as historical", () => {
    render(<ExportEvidenceCard kind="flowspec" evidence={{ ...mixed, historical: true, warning: { reason: "not_selected", message: "Another rule is selected." } }} />)
    expect(screen.getByTestId("export-evidence")).toHaveTextContent("At the retained observation, no Established peer had this FlowSpec rule")
    expect(screen.getByText("Committed")).toHaveAttribute("data-tone", "neutral")
    expect(screen.getByRole("status")).toHaveTextContent("Current export is unknown")
  })

  it("says when sessions were not observed rather than implying every peer is Established", () => {
    render(<ExportEvidenceCard evidence={{ ...mixed, not_established_peers: null }} />)
    expect(screen.getByText(/Peer sessions were not observed/)).toBeInTheDocument()
  })
})

describe("mitigation detail", () => {
  it.each(["blackhole", "discard", "police"] as const)("puts export evidence first for an active %s", async (actionType) => {
    const createdAt = new Date(Date.now() - 60_000).toISOString()

    const blackhole: Mitigation = {
      mitigation_id: "00000000-0000-4000-8000-000000000077",
      scope_hash: "scope-blackhole",
      status: "active",
      customer_id: null,
      service_id: null,
      pop: "test-pop",
      victim_ip: "203.0.113.10",
      vector: "unknown",
      action_type: actionType,
      rate_bps: actionType === "police" ? 8_000_000 : null,
      dst_prefix: "203.0.113.10/32",
      protocol: null,
      dst_ports: [],
      created_at: createdAt,
      updated_at: createdAt,
      expires_at: new Date(Date.now() + 600_000).toISOString(),
      withdrawn_at: null,
      triggering_event_id: "event-1",
      last_event_id: "event-1",
      reason: "manual blackhole",
      acknowledged_at: null,
      acknowledged_by: null,
      origin_mode: "enforced",
      blackhole: actionType === "blackhole" ? { next_hop: "192.0.2.66", communities: ["65535:666"], large_communities: [] } : null,
      export_evidence: mixed,
    }

    controller.route("GET", "/v1/config/inventory", () => json({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: createdAt }))
    controller.route("GET", "/v1/mitigations", () => json({ mitigations: [blackhole], count: 1, next_cursor: null, has_more: false }))
    controller.route("GET", `/v1/mitigations/${blackhole.mitigation_id}`, () => json(blackhole))
    signIn(controller, "credentials", operatorResponse("operator"))
    await act(async () => {
      renderApp(
        <Suspense fallback={<p>Loading...</p>}>
          <MitigationDetailPage params={Promise.resolve({ id: blackhole.mitigation_id })} />
        </Suspense>,
        { url: `/mitigations/${blackhole.mitigation_id}` },
      )
    })
    const exportCard = await screen.findByTestId("export-evidence")

    if (actionType === "blackhole") {
      const routeCard = screen.getByTestId("blackhole-card")
      expect(exportCard.compareDocumentPosition(routeCard) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
    } else {
      expect(screen.queryByTestId("blackhole-card")).not.toBeInTheDocument()
    }
  })
})
