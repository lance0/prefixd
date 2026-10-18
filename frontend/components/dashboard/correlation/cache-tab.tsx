"use client"

import { formatConfidence } from "@/lib/confidence"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { useCachedCorroborators } from "@/hooks/use-api"
import { MISSING, formatRelative, formatUtc } from "@/lib/format"

function dimsLabel(s: {
  customer_id: string | null
  pop: string | null
  service_id: string | null
  interface: string | null
}): string {
  const parts: string[] = []
  if (s.customer_id) parts.push(`customer=${s.customer_id}`)
  if (s.pop) parts.push(`pop=${s.pop}`)
  if (s.service_id) parts.push(`service=${s.service_id}`)
  if (s.interface) parts.push(`iface=${s.interface}`)
  return parts.length > 0 ? parts.join(" ") : MISSING
}

export function CacheTab() {
  const { data, error, isLoading, mutate } = useCachedCorroborators({ limit: 200 })

  if (isLoading) {
    return <div className="rounded-md border bg-card"><LoadingRows label="Loading corroborator cache" /></div>
  }

  if (error) {
    return (
      <div className="rounded-md border bg-card">
        <ErrorState
          title="Unable to load the corroborator cache"
          detail="Cached signals could not be refreshed; the cache on the controller is unaffected. Retry to reload."
          onRetry={() => { void mutate() }}
        />
      </div>
    )
  }

  if (!data || data.total === 0) {
    return (
      <div className="rounded-md border bg-card">
        <EmptyState
          title="No corroborator signals cached"
          description="Cached signals appear here when a corroborating-only source posts before any matching primary event lands."
        />
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Cache size by source</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {data.by_source.map((b) => (
              <Badge key={b.source} variant="secondary">
                {b.source}: {b.count}
              </Badge>
            ))}
          </div>
          <p className="mt-3 text-xs text-muted-foreground text-pretty">
            Total cached, unattached, unexpired: {data.total}. Watch the
            <code className="mx-1 rounded-sm bg-muted px-1 font-mono">prefixd_corroborator_cache_size</code>
            gauge to alert on caches growing without bound.
          </p>
        </CardContent>
      </Card>

      <section aria-labelledby="cached-signals" className="overflow-hidden rounded-md border bg-card">
        <div className="border-b px-4 py-3">
          <h2 id="cached-signals" className="text-sm font-semibold">Cached signals</h2>
        </div>
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Source</TableHead>
              <TableHead>Vector</TableHead>
              <TableHead>Dimensions</TableHead>
              <TableHead className="text-right">Confidence</TableHead>
              <TableHead>Ingested</TableHead>
              <TableHead>Expires</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.signals.map((s) => (
              <TableRow key={s.signal_id}>
                <TableCell>{s.source}</TableCell>
                <TableCell className="text-muted-foreground">{s.vector ?? MISSING}</TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{dimsLabel(s)}</TableCell>
                <TableCell numeric>{formatConfidence(s.confidence)}</TableCell>
                <TableCell className="text-muted-foreground tabular-nums">
                  <time dateTime={s.ingested_at} title={formatUtc(s.ingested_at)}>{formatRelative(s.ingested_at)}</time>
                </TableCell>
                <TableCell className="text-muted-foreground tabular-nums">
                  <time dateTime={s.expires_at} className="text-foreground">{formatRelative(s.expires_at)}</time>
                  <span className="block whitespace-nowrap text-xs">{formatUtc(s.expires_at)}</span>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </section>
    </div>
  )
}
