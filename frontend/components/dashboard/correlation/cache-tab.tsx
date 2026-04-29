"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { Database, AlertCircle } from "lucide-react"
import { useCachedCorroborators } from "@/hooks/use-api"
import { formatDistanceToNow } from "date-fns"

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
  return parts.length > 0 ? parts.join(" ") : "—"
}

export function CacheTab() {
  const { data, error, isLoading } = useCachedCorroborators({ limit: 200 })

  if (isLoading) {
    return (
      <div className="space-y-3">
        <Skeleton className="h-24 w-full" />
        <Skeleton className="h-48 w-full" />
      </div>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-4 flex items-center gap-2 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <span className="text-sm font-mono">Failed to load corroborator cache</span>
        </CardContent>
      </Card>
    )
  }

  if (!data || data.total === 0) {
    return (
      <Card>
        <CardContent className="p-6 text-center">
          <Database className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
          <p className="text-sm font-mono text-muted-foreground">
            No corroborator signals are currently cached.
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            Cached signals appear here when a corroborating-only source posts before
            any matching primary event lands.
          </p>
        </CardContent>
      </Card>
    )
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-mono flex items-center gap-2">
            <Database className="h-4 w-4" />
            Cache size by source
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {data.by_source.map((b) => (
              <Badge
                key={b.source}
                variant="secondary"
                className="font-mono text-xs"
              >
                {b.source}: {b.count}
              </Badge>
            ))}
          </div>
          <p className="text-[11px] text-muted-foreground font-mono mt-3">
            Total cached, unattached, unexpired: {data.total}. Watch the
            <span className="mx-1 inline-block px-1 rounded bg-muted">prefixd_corroborator_cache_size</span>
            gauge to alert on caches growing without bound.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-mono">Cached signals</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-1.5 pr-3">Source</th>
                  <th className="text-left py-1.5 pr-3">Vector</th>
                  <th className="text-left py-1.5 pr-3">Dimensions</th>
                  <th className="text-left py-1.5 pr-3">Confidence</th>
                  <th className="text-left py-1.5 pr-3">Ingested</th>
                  <th className="text-left py-1.5">Expires</th>
                </tr>
              </thead>
              <tbody>
                {data.signals.map((s) => (
                  <tr key={s.signal_id} className="border-b last:border-0">
                    <td className="py-1.5 pr-3">{s.source}</td>
                    <td className="py-1.5 pr-3 text-muted-foreground">
                      {s.vector ?? "—"}
                    </td>
                    <td className="py-1.5 pr-3 text-muted-foreground">
                      {dimsLabel(s)}
                    </td>
                    <td className="py-1.5 pr-3">
                      {s.confidence != null ? s.confidence.toFixed(2) : "—"}
                    </td>
                    <td
                      className="py-1.5 pr-3 text-muted-foreground"
                      title={s.ingested_at}
                    >
                      {formatDistanceToNow(new Date(s.ingested_at), {
                        addSuffix: true,
                      })}
                    </td>
                    <td
                      className="py-1.5 text-muted-foreground"
                      title={s.expires_at}
                    >
                      {formatDistanceToNow(new Date(s.expires_at), {
                        addSuffix: true,
                      })}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
