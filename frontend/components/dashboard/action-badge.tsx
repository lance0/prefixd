import { formatBps } from "@/lib/format"
import { StatusPill, Tag } from "./status-pill"

interface ActionBadgeProps {
  actionType: "police" | "discard" | string
  rateBps?: number | null
}

/** The enforced action. Discard drops all matching traffic, so it carries the danger tone. */
export function ActionBadge({ actionType, rateBps }: ActionBadgeProps) {
  if (actionType === "discard") return <StatusPill tone="danger">discard</StatusPill>

  return (
    <Tag className="text-foreground tabular-nums">
      {actionType === "police" && rateBps ? `police ${formatBps(rateBps)}` : actionType}
    </Tag>
  )
}
