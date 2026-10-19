import type { FragmentMatch, PacketLengthRange } from "@/lib/api"

function protocolName(proto: number | null): string {
  if (proto === null) return ""

  switch (proto) {
    case 1: return "icmp"
    case 6: return "tcp"
    case 17: return "udp"
    case 58: return "icmpv6"
    default: return `${proto}`
  }
}

// Rule syntax for copy/paste, not display: keep plain ASCII and a fixed decimal.
function ruleRate(bps: number | null): string {
  if (!bps) return ""

  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`

  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`

  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`

  return `${bps} bps`
}

export interface FlowSpecFields {
  dst_prefix: string
  protocol: number | null
  dst_ports: number[]
  src_ports?: number[]
  fragment?: FragmentMatch | null
  packet_length?: PacketLengthRange | null
  action_type: string
  rate_bps: number | null
}

/** Readable match for operators, for example "UDP src 123, 389" or "UDP non-first fragments". */
export function describeMatch(fields: Omit<FlowSpecFields, "dst_prefix" | "rate_bps">): string {
  if (fields.action_type === "blackhole") return "all traffic"
  const proto = protocolName(fields.protocol).toUpperCase().replace("ICMPV6", "ICMPv6")
  const parts: string[] = []

  if (fields.src_ports?.length) parts.push(`src ${fields.src_ports.join(", ")}`)

  if (fields.dst_ports.length > 0) parts.push(`dst ${fields.dst_ports.join(", ")}`)

  if (fields.fragment === "non_first") parts.push("non-first fragments")

  if (fields.packet_length) parts.push(`length ${fields.packet_length.min}–${fields.packet_length.max} B`)

  if (parts.length === 0) return proto ? `all ${proto}` : "all traffic"

  return [proto, ...parts].filter(Boolean).join(" ")
}

export function formatFlowSpecRule(fields: FlowSpecFields): string {
  const parts: string[] = ["match destination", fields.dst_prefix]

  const proto = protocolName(fields.protocol)

  if (proto) {
    parts.push("protocol", proto)
  }

  if (fields.dst_ports.length > 0) {
    parts.push("destination-port", fields.dst_ports.join(","))
  }

  if (fields.src_ports?.length) {
    parts.push("source-port", fields.src_ports.join(","))
  }

  if (fields.packet_length) {
    parts.push("packet-length", `${fields.packet_length.min}-${fields.packet_length.max}`)
  }

  if (fields.fragment === "non_first") {
    parts.push("fragment is-fragment")
  }

  if (fields.action_type === "discard") {
    parts.push("then discard")
  } else {
    parts.push("then rate-limit", ruleRate(fields.rate_bps))
  }

  return parts.join(" ")
}

export function FlowSpecPreview(fields: FlowSpecFields) {
  const rule = formatFlowSpecRule(fields)

  return (
    <div className="px-4 py-3 bg-secondary/20 border-b border-border">
      <code className="break-words text-sm font-mono text-foreground">{rule}</code>
    </div>
  )
}
