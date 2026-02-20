"use client"

import Link from "next/link"
import { useMemo } from "react"
import { PieChart, Pie, Cell } from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart"
import type { Mitigation } from "@/lib/api"

interface VectorBreakdownChartProps {
  mitigations: Mitigation[]
}

const VECTOR_COLORS: Record<string, string> = {
  udp_flood: "var(--color-chart-1)",
  syn_flood: "var(--color-destructive)",
  ack_flood: "var(--color-chart-3)",
  icmp_flood: "var(--color-chart-2)",
  ntp_amplification: "var(--color-chart-4)",
  dns_amplification: "var(--color-chart-5)",
  unknown: "var(--color-muted-foreground)",
}

const VECTOR_LABELS: Record<string, string> = {
  udp_flood: "UDP Flood",
  syn_flood: "SYN Flood",
  ack_flood: "ACK Flood",
  icmp_flood: "ICMP Flood",
  ntp_amplification: "NTP Amp",
  dns_amplification: "DNS Amp",
  unknown: "Unknown",
}

export function VectorBreakdownChart({ mitigations }: VectorBreakdownChartProps) {
  const data = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const m of mitigations) {
      const vector = m.vector || "unknown"
      counts[vector] = (counts[vector] || 0) + 1
    }
    return Object.entries(counts).map(([vector, count]) => ({
      vector,
      label: VECTOR_LABELS[vector] || vector.replace(/_/g, " "),
      count,
      fill: VECTOR_COLORS[vector] || VECTOR_COLORS.unknown,
    }))
  }, [mitigations])

  const chartConfig = useMemo(() => {
    const config: Record<string, { label: string; color: string }> = {}
    for (const item of data) {
      config[item.vector] = {
        label: item.label,
        color: item.fill,
      }
    }
    return config
  }, [data])

  if (mitigations.length === 0) {
    return (
      <div className="border border-border bg-card p-4 h-full">
        <h3 className="text-xs font-mono uppercase text-muted-foreground mb-3 text-balance">
          Mitigations by Vector
        </h3>
        <div className="flex items-center justify-center h-32 text-muted-foreground text-xs">
          No active mitigations
        </div>
      </div>
    )
  }

  return (
    <div className="border border-border bg-card p-4 h-full">
      <h3 className="text-xs font-mono uppercase text-muted-foreground mb-3 text-balance">
        Mitigations by Vector
      </h3>
      <div className="flex items-center gap-4">
        <div className="size-28 flex-shrink-0">
          <ChartContainer config={chartConfig} className="size-full !aspect-square">
            <PieChart>
              <ChartTooltip content={<ChartTooltipContent nameKey="label" />} />
              <Pie
                data={data}
                dataKey="count"
                nameKey="label"
                cx="50%"
                cy="50%"
                innerRadius={28}
                outerRadius={48}
                strokeWidth={0}
              >
                {data.map((entry) => (
                  <Cell key={entry.vector} fill={entry.fill} />
                ))}
              </Pie>
            </PieChart>
          </ChartContainer>
        </div>
        <div className="flex-1 space-y-1.5">
          {data.map((item) => (
            <Link
              key={item.vector}
              href={`/mitigations?ip=${item.vector}`}
              className="flex items-center justify-between text-xs hover:bg-secondary/50 rounded px-1 -mx-1 py-0.5 transition-colors"
            >
              <div className="flex items-center gap-2">
                <span
                  className="size-2"
                  style={{ backgroundColor: item.fill }}
                />
                <span className="text-muted-foreground">{item.label}</span>
              </div>
              <span className="font-mono tabular-nums text-foreground">{item.count}</span>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
