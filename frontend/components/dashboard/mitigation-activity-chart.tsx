"use client"

import { useMemo, useState } from "react"
import Link from "next/link"
import { Skeleton } from "@/components/ui/skeleton"
import { AreaChart, Area, XAxis, YAxis, CartesianGrid } from "recharts"
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart"
import { EmptyState, ErrorState } from "@/components/dashboard/states"
import { useTimeseries } from "@/hooks/use-api"
import { formatUtc, formatUtcTick } from "@/lib/format"
import { cn } from "@/lib/utils"

const RANGE_OPTIONS = [
  { label: "1h", range: "1h", bucket: "5m" },
  { label: "6h", range: "6h", bucket: "30m" },
  { label: "24h", range: "24h", bucket: "1h" },
  { label: "7d", range: "7d", bucket: "6h" },
] as const

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

const TICK = { fontSize: 12 }

export function MitigationActivityChart() {
  const [rangeIdx, setRangeIdx] = useState(2) // default 24h
  const selectedRange = RANGE_OPTIONS[rangeIdx]
  const { data: mitigationData, error: mitigationError, mutate: retryMitigations } = useTimeseries("mitigations", selectedRange.range, selectedRange.bucket)
  const { data: eventData, error: eventError, mutate: retryEvents } = useTimeseries("events", selectedRange.range, selectedRange.bucket)

  const chartData = useMemo(() => {
    const bucketMap = new Map<string, { bucket: string; mitigations: number; events: number }>()

    for (const b of mitigationData?.buckets ?? []) {
      bucketMap.set(b.bucket, {
        bucket: b.bucket,
        mitigations: b.count,
        events: bucketMap.get(b.bucket)?.events ?? 0,
      })
    }

    for (const b of eventData?.buckets ?? []) {
      const existing = bucketMap.get(b.bucket)
      bucketMap.set(b.bucket, {
        bucket: b.bucket,
        mitigations: existing?.mitigations ?? 0,
        events: b.count,
      })
    }

    return Array.from(bucketMap.values())
      .sort((a, b) => new Date(a.bucket).getTime() - new Date(b.bucket).getTime())
  }, [mitigationData, eventData])

  const multiDay = selectedRange.range === "7d"

  const isLoading = !mitigationData || !eventData
  const hasError = Boolean(mitigationError || eventError)

  return (
    <section aria-label="Activity chart" className="min-w-0">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-sm font-semibold text-balance">Activity <span className="text-muted-foreground">({selectedRange.label})</span></h2>
        <div role="group" className="flex rounded-md bg-muted p-0.5" aria-label="Activity range">
          {RANGE_OPTIONS.map((opt, i) => (
            <button key={opt.label} onClick={() => setRangeIdx(i)} aria-pressed={i === rangeIdx}
              className={cn("min-h-8 rounded-sm px-2.5 text-xs tabular-nums", i === rangeIdx ? "bg-background text-foreground shadow-xs" : "text-muted-foreground hover:text-foreground")}>
              {opt.label}
            </button>
          ))}
        </div>
      </div>
      {hasError ? (
        <div className="rounded-md border bg-card">
          <ErrorState
            title="Unable to load activity chart"
            detail="Mitigation and event counts could not be refreshed. Active mitigations above are unaffected."
            onRetry={() => { void Promise.allSettled([retryMitigations(), retryEvents()]) }}
            retryLabel="Retry activity"
          />
        </div>
      ) : isLoading ? (
        <div role="status" aria-label="Loading activity" className="h-48 space-y-3"><Skeleton className="h-40 w-full" /><p className="text-muted-foreground">Loading activity…</p></div>
      ) : chartData.length === 0 ? (
        <div className="rounded-md border bg-card">
          <EmptyState
            title={`No activity in the last ${selectedRange.label}`}
            description="Events and mitigations will be charted here as detectors report attacks. Try a longer range."
            action={<Link href="/events" className="rounded-sm text-sm text-primary hover:underline">Review events</Link>}
          />
        </div>
      ) : (
        <>
          <div className="mb-3 flex gap-4 text-xs text-muted-foreground">
            <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-chart-1" />Mitigations</span>
            <span className="flex items-center gap-1.5"><span className="size-2 rounded-full bg-chart-2" />Events</span>
          </div>
          <ChartContainer config={chartConfig} className="h-40 w-full min-w-0">
            <AreaChart data={chartData} margin={{ top: 4, right: 12, bottom: 0, left: -16 }}>
              <CartesianGrid vertical={false} />
              <XAxis
                dataKey="bucket"
                tickLine={false}
                axisLine={false}
                tick={TICK}
                tickFormatter={(value: string) => formatUtcTick(value, multiDay)}
                interval="preserveStartEnd"
                minTickGap={16}
                padding={{ left: 8, right: 8 }}
              />
              <YAxis tickLine={false} axisLine={false} tick={TICK} allowDecimals={false} />
              <ChartTooltip
                isAnimationActive={false}
                content={<ChartTooltipContent labelFormatter={(value) => formatUtc(String(value))} />}
              />
              <Area type="monotone" dataKey="mitigations" stroke="var(--color-chart-1)" fill="var(--color-chart-1)" fillOpacity={0.08} strokeWidth={1.5} isAnimationActive={false} />
              <Area type="monotone" dataKey="events" stroke="var(--color-chart-2)" fill="var(--color-chart-2)" fillOpacity={0.04} strokeWidth={1.5} isAnimationActive={false} />
            </AreaChart>
          </ChartContainer>
        </>
      )}
    </section>
  )
}
