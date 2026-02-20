import { cn } from "@/lib/utils"

interface SourceBadgeProps {
  source: string
}

export function SourceBadge({ source }: SourceBadgeProps) {
  const isAuto = source === "fastnetmon"

  return (
    <span
      className={cn(
        "inline-flex items-center border px-2 py-0.5 text-[10px] font-mono uppercase tracking-wide",
        isAuto ? "border-primary/30 text-primary bg-primary/5" : "border-border text-muted-foreground bg-muted/50",
      )}
    >
      {source}
    </span>
  )
}
