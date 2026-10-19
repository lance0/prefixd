import { formatBps } from "@/lib/format"
import { StatusPill, Tag } from "./status-pill"

interface ActionBadgeProps {
  actionType: "police" | "discard" | "blackhole" | string
  rateBps?: number | null
}

/**
 * The enforced action. Discard drops all matching traffic and a blackhole drops all
 * traffic to the victim, so both carry the danger tone.
 */
export function ActionBadge({ actionType, rateBps }: ActionBadgeProps) {
  if (actionType === "discard" || actionType === "blackhole") return <StatusPill tone="danger">{actionType}</StatusPill>

  return (
    <Tag className="text-foreground tabular-nums">
      {actionType === "police" && rateBps ? `police ${formatBps(rateBps)}` : actionType}
    </Tag>
  )
}
