function protocolName(proto: number | null): string {
  if (proto === null) return ""
  switch (proto) {
    case 1: return "icmp"
    case 6: return "tcp"
    case 17: return "udp"
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
  action_type: string
  rate_bps: number | null
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

  if (fields.action_type === "discard") {
    parts.push("then discard")
  } else {
    parts.push("then rate-limit", ruleRate(fields.rate_bps))
  }

  return parts.join(" ")
}

export function FlowSpecPreview({ dst_prefix, protocol, dst_ports, action_type, rate_bps }: FlowSpecFields) {
  const rule = formatFlowSpecRule({ dst_prefix, protocol, dst_ports, action_type, rate_bps })

  return (
    <div className="px-4 py-3 bg-secondary/20 border-b border-border">
      <code className="text-sm font-mono text-foreground">{rule}</code>
    </div>
  )
}
