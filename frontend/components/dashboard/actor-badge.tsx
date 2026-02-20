import { cn } from "@/lib/utils"
import { Bot, User } from "lucide-react"

interface ActorBadgeProps {
  type: "system" | "operator" | "detector"
  name: string
}

export function ActorBadge({ type, name }: ActorBadgeProps) {
  const isSystemLike = type === "system" || type === "detector"

  return (
    <div className="flex items-center gap-2">
      <span
        className={cn(
          "flex items-center justify-center h-5 w-5",
          isSystemLike ? "bg-secondary text-muted-foreground" : "bg-primary/10 text-primary",
        )}
      >
        {isSystemLike ? <Bot className="h-3 w-3" /> : <User className="h-3 w-3" />}
      </span>
      <span className="text-xs font-mono text-foreground">{name}</span>
    </div>
  )
}
