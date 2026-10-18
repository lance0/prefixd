import { Bot, User } from "lucide-react"

interface ActorBadgeProps {
  type: "system" | "operator" | "detector"
  name: string
}

export function ActorBadge({ type, name }: ActorBadgeProps) {
  const Icon = type === "operator" ? User : Bot

  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <Icon className="size-3.5 shrink-0 text-muted-foreground" aria-hidden="true" />
      {name}
    </span>
  )
}
