"use client"

import { useMemo } from "react"
import { AreaChart, Area, XAxis, YAxis, CartesianGrid } from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart"
import { useTimeseries } from "@/hooks/use-api"

const chartConfig = {
  mitigations: {
    label: "Mitigations",
    color: "var(--color-chart-1)",
  },
  events: {
    label: "Events",
    color: "var(--color-chart-2)",
  },
}

function formatHour(bucket: string) {
  const d = new Date(bucket)
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", hour12: false })
}

export function MitigationActivityChart() {
  const { data: mitigationData } = useTimeseries("mitigations", "24h", "1h")
  const { data: eventData } = useTimeseries("events", "24h", "1h")

  const chartData = useMemo(() => {
    if (!mitigationData?.buckets) return []
    const eventMap = new Map<string, number>()
    for (const b of eventData?.buckets ?? []) {
      eventMap.set(b.bucket, b.count)
    }
    return mitigationData.buckets.map((b) => ({
      time: formatHour(b.bucket),
      mitigations: b.count,
      events: eventMap.get(b.bucket) ?? 0,
    }))
  }, [mitigationData, eventData])

  if (chartData.length === 0) {
    return (
      <div className="border border-border bg-card p-4">
        <h3 className="text-xs font-mono uppercase text-muted-foreground mb-3">
          Activity (24h)
        </h3>
        <div className="flex items-center justify-center h-32 text-muted-foreground text-xs">
          Loading...
        </div>
      </div>
    )
  }

  return (
    <div className="border border-border bg-card p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-mono uppercase text-muted-foreground">
          Activity (24h)
        </h3>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full" style={{ backgroundColor: "var(--color-chart-1)" }} />
            <span className="text-[10px] text-muted-foreground">Mitigations</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="size-2 rounded-full" style={{ backgroundColor: "var(--color-chart-2)" }} />
            <span className="text-[10px] text-muted-foreground">Events</span>
          </div>
        </div>
      </div>
      <ChartContainer config={chartConfig} className="h-[140px] w-full">
        <AreaChart data={chartData} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <defs>
            <linearGradient id="fillMitigations" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--color-chart-1)" stopOpacity={0.3} />
              <stop offset="95%" stopColor="var(--color-chart-1)" stopOpacity={0} />
            </linearGradient>
            <linearGradient id="fillEvents" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="var(--color-chart-2)" stopOpacity={0.2} />
              <stop offset="95%" stopColor="var(--color-chart-2)" stopOpacity={0} />
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
          <XAxis
            dataKey="time"
            tickLine={false}
            axisLine={false}
            tick={{ fontSize: 10 }}
            className="fill-muted-foreground"
            interval="preserveStartEnd"
          />
          <YAxis
            tickLine={false}
            axisLine={false}
            tick={{ fontSize: 10 }}
            className="fill-muted-foreground"
            allowDecimals={false}
          />
          <ChartTooltip content={<ChartTooltipContent />} />
          <Area
            type="monotone"
            dataKey="mitigations"
            stroke="var(--color-chart-1)"
            fill="url(#fillMitigations)"
            strokeWidth={1.5}
          />
          <Area
            type="monotone"
            dataKey="events"
            stroke="var(--color-chart-2)"
            fill="url(#fillEvents)"
            strokeWidth={1.5}
          />
        </AreaChart>
      </ChartContainer>
    </div>
  )
}
