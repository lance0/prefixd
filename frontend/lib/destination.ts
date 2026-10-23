/** A parsed manual destination. The controller remains authoritative for admission. */
export interface Destination {
  prefix: string
  prefixLength: number
  maxLength: 32 | 128
  ipv6: boolean
  isCidr: boolean
  networkAligned: boolean
}

function ipv4Bytes(value: string): number[] | null {
  const parts = value.split(".")

  return parts.length === 4 && parts.every((part) => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255)
    ? parts.map(Number)
    : null
}

/** Parse an IP or conventional CIDR without silently accepting host bits. */
export function parseDestination(value: string): Destination | null {
  const [address, length, extra] = value.trim().split("/")
  const isCidr = length !== undefined

  if (extra !== undefined || (isCidr && !/^\d{1,3}$/.test(length))) return null
  let bytes = ipv4Bytes(address)
  let ipv6 = false

  if (!bytes) {
    if (!address.includes(":") || !/^[0-9a-fA-F:.]+$/.test(address)) return null

    try {
      // URL validates IPv6 syntax and converts embedded IPv4 into hex groups.
      const canonical = new URL(`http://[${address}]/`).hostname.slice(1, -1)
      const halves = canonical.split("::")
      const left = halves[0] ? halves[0].split(":") : []
      const right = halves[1] ? halves[1].split(":") : []
      const groups = halves.length === 1 ? left : [...left, ...Array(8 - left.length - right.length).fill("0"), ...right]

      if (groups.length !== 8) return null
      bytes = groups.flatMap((group) => [parseInt(group, 16) >> 8, parseInt(group, 16) & 255])
      ipv6 = true
    } catch {
      return null
    }
  }

  const maxLength = ipv6 ? 128 : 32
  const prefixLength = isCidr ? Number(length) : maxLength

  if (prefixLength > maxLength) return null

  const network = bytes.map((byte, index) => {
    const hostBits = Math.max(0, Math.min(8, (index + 1) * 8 - prefixLength))

    return byte & (255 << hostBits)
  })

  const networkAligned = bytes.every((byte, index) => byte === network[index])

  const networkAddress = ipv6
    ? new URL(`http://[${Array.from({ length: 8 }, (_, index) => ((network[index * 2] << 8) | network[index * 2 + 1]).toString(16)).join(":")}]/`).hostname.slice(1, -1)
    : network.join(".")

  return { prefix: `${networkAddress}/${prefixLength}`, prefixLength, maxLength, ipv6, isCidr, networkAligned }
}

/** Keep CIDRs on their mitigation details, never substitute a base-IP history. */
export function mitigationTargetHref(mitigation: { victim_ip: string; mitigation_id: string }): string {
  return mitigation.victim_ip.includes("/")
    ? `/mitigations/${mitigation.mitigation_id}`
    : `/ip-history?ip=${encodeURIComponent(mitigation.victim_ip)}`
}
