interface QuotaGaugeProps {
  title: string
  current: number
  max: number
  secondary?: {
    title: string
    current: number
    max: number
  }
}

export function QuotaGauge({ title, current, max, secondary }: QuotaGaugeProps) {
  const percentage = Math.min((current / max) * 100, 100)
  const secondaryPercentage = secondary ? Math.min((secondary.current / secondary.max) * 100, 100) : 0

  return (
    <div className="border border-border bg-card p-4">
      <div className="space-y-4">
        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono uppercase tracking-wide text-muted-foreground">{title}</span>
            <span className="text-xs font-mono text-foreground tabular-nums">
              {current}/{max} <span className="text-muted-foreground">({percentage.toFixed(0)}%)</span>
            </span>
          </div>
          <div className="h-1.5 bg-secondary overflow-hidden">
            <div className="h-full bg-primary transition-transform duration-500 origin-left" style={{ transform: `scaleX(${percentage / 100})` }} />
          </div>
        </div>
        {secondary && (
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs font-mono uppercase tracking-wide text-muted-foreground">{secondary.title}</span>
              <span className="text-xs font-mono text-foreground tabular-nums">
                {secondary.current}/{secondary.max}
              </span>
            </div>
            <div className="h-1 bg-secondary overflow-hidden">
              <div
                className="h-full bg-muted-foreground transition-transform duration-500 origin-left"
                style={{ transform: `scaleX(${secondaryPercentage / 100})` }}
              />
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
