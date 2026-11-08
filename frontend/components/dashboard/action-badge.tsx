import { formatBps } from "@/lib/format"
import { StatusPill, Tag } from "./status-pill"

interface ActionBadgeProps {
  actionType: "police" | "discard" | "blackhole" | string
  rateBps?: number | null
  dscp?: number | null
}

/**
 * The enforced action. Discard drops all matching traffic and a blackhole drops all
 * traffic to the victim, so both carry the danger tone.
 */
export function ActionBadge({ actionType, rateBps, dscp }: ActionBadgeProps) {
  if (actionType === "discard" || actionType === "blackhole") return <StatusPill tone="danger">{actionType}</StatusPill>

  return (
    <Tag className="text-foreground tabular-nums">
      {actionType === "mark" ? `mark DSCP ${dscp ?? "unavailable"}` : actionType === "police" && rateBps ? `police ${formatBps(rateBps)}` : actionType}
    </Tag>
  )
}
