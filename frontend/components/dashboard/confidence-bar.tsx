import { cn } from "@/lib/utils"
import { formatConfidence, isConfidence } from "@/lib/confidence"

interface ConfidenceBarProps {
  value?: number | null
}

export function ConfidenceBar({ value }: ConfidenceBarProps) {
  const label = formatConfidence(value)
  if (!isConfidence(value)) {
    return <span className="text-xs text-muted-foreground">{label}</span>
  }
  const percent = value * 100

  return (
    <div className="flex items-center gap-2">
      <div
        role="meter"
        aria-label="Confidence"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={percent}
        aria-valuetext={label}
        className="h-1 w-16 overflow-hidden rounded-sm bg-secondary"
      >
        <div
          className={cn("h-full", value >= 0.8 ? "bg-primary" : "bg-muted-foreground")}
          style={{ width: `${percent}%` }}
        />
      </div>
      <span className="text-xs text-muted-foreground tabular-nums">{label}</span>
    </div>
  )
}
