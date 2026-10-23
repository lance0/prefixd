import { describe, expect, it } from "vitest"
import { mitigationTargetHref, parseDestination } from "@/lib/destination"

describe("manual destination parsing", () => {
  it.each([
    ["203.0.113.10", "203.0.113.10/32"],
    ["203.0.112.0/22", "203.0.112.0/22"],
    ["2001:DB8:1234:0000::/48", "2001:db8:1234::/48"],
    ["2001:db8::1", "2001:db8::1/128"],
    ["::ffff:192.0.2.0/120", "::ffff:c000:200/120"],
    ["::/0", "::/0"],
    ["0.0.0.0/0", "0.0.0.0/0"],
  ])("preserves the exact scope of %s", (input, prefix) => {
    expect(parseDestination(input)).toMatchObject({ prefix, networkAligned: true })
  })

  it.each([
    ["203.0.113.10/22", "203.0.112.0/22"],
    ["2001:db8:1234::1/48", "2001:db8:1234::/48"],
    ["192.0.2.1/0", "0.0.0.0/0"],
  ])("identifies host bits in %s without silently widening it", (input, prefix) => {
    expect(parseDestination(input)).toMatchObject({ prefix, networkAligned: false })
  })

  it.each(["", "203.0.113.1/33", "2001:db8::/129", "1:2:3/64", "1::2::3/64", "1.2.3.999/24", "192.0.2.01", "192.0.2.0/", "192.0.2.0/-1", "192.0.2.0/24/0", "fe80::1%eth0/128"])("refuses invalid destination %s", input => {
    expect(parseDestination(input)).toBeNull()
  })

  it("keeps CIDRs on mitigation details and bare hosts on IP history", () => {
    expect(mitigationTargetHref({ victim_ip: "203.0.112.0/22", mitigation_id: "rule" })).toBe("/mitigations/rule")
    expect(mitigationTargetHref({ victim_ip: "203.0.113.10", mitigation_id: "rule" })).toBe("/ip-history?ip=203.0.113.10")
  })
})
