"use client"

import { useEffect, useState } from "react"
import useSWR from "swr"
import useSWRInfinite from "swr/infinite"
import * as api from "@/lib/api"

const REFRESH_INTERVAL = 5000 // 5 seconds

export function useHealth() {
  return useSWR(
    "health",
    api.getHealth,
    {
      refreshInterval: REFRESH_INTERVAL,
      revalidateOnFocus: true,
    }
  )
}

// Client receipt time belongs to the SWR snapshot, never the public API schema.
export type HealthDetailSnapshot = api.HealthResponse & { receivedAt: number }

export async function fetchHealthDetailSnapshot(): Promise<HealthDetailSnapshot> {
  return { ...await api.getHealthDetail(), receivedAt: performance.now() }
}

export function healthReceiptAge(receivedAt: number | undefined, now: number): number | null {
  if (receivedAt === undefined) return null
  const age = now - receivedAt

  return Number.isFinite(age) && age >= 0 ? age : null
}

export function useHealthDetail() {
  const [now, setNow] = useState(() => performance.now())
  useEffect(() => {
    const timer = setInterval(() => setNow(performance.now()), REFRESH_INTERVAL)

    return () => clearInterval(timer)
  }, [])

  const query = useSWR(
    "health-detail",
    fetchHealthDetailSnapshot,
    {
      refreshInterval: REFRESH_INTERVAL,
      revalidateOnFocus: true,
    }
  )

  const receiptAge = healthReceiptAge(query.data?.receivedAt, Math.max(now, performance.now()))

  return { ...query, receiptAge, isStale: Boolean(query.data) && (receiptAge === null || receiptAge > 15000) }
}

export function useStats() {
  return useSWR(
    "stats",
    api.getStats,
    {
      refreshInterval: REFRESH_INTERVAL,
      revalidateOnFocus: true,
    }
  )
}

/** `null` fetches nothing, for a query that depends on data still loading. */
export function useMitigations(params?: Parameters<typeof api.getMitigations>[0] | null) {
  const key = params === null ? null : params ? ["mitigations", JSON.stringify(params)] : "mitigations"

  const fetcher = () => api.getMitigations(params ?? undefined)

  return useSWR(key, fetcher, {
    refreshInterval: REFRESH_INTERVAL,
    revalidateOnFocus: true,
  })
}

export function useMitigation(id: string | null) {
  const fetcher = () => api.getMitigation(id!)

  return useSWR(
    id ? ["mitigation", id] : null,
    fetcher,
    {
      refreshInterval: REFRESH_INTERVAL,
    }
  )
}

export function useSafelist() {
  return useSWR(
    "safelist",
    api.getSafelist,
    {
      refreshInterval: REFRESH_INTERVAL,
    }
  )
}

export function usePops() {
  return useSWR(
    "pops",
    api.getPops,
    {
      refreshInterval: 30000,
    }
  )
}

export function useEvents(params?: Parameters<typeof api.getEvents>[0]) {
  const key = params ? ["events", JSON.stringify(params)] : "events"
  
  const fetcher = () => api.getEvents(params)

  return useSWR(key, fetcher, {
    refreshInterval: REFRESH_INTERVAL,
    revalidateOnFocus: true,
  })
}

export function useAuditLog(params?: Parameters<typeof api.getAuditLog>[0]) {
  const key = params ? ["audit", JSON.stringify(params)] : "audit"
  
  const fetcher = () => api.getAuditLog(params)

  return useSWR(key, fetcher, {
    refreshInterval: REFRESH_INTERVAL,
    revalidateOnFocus: true,
  })
}

// Parallel fetch all dashboard data in one request (async-parallel pattern)
export function useDashboard() {
  return useSWR(
    "dashboard",
    api.getDashboardData,
    {
      refreshInterval: REFRESH_INTERVAL,
      revalidateOnFocus: true,
    }
  )
}

// Operator management (admin only)
export function useOperators() {
  return useSWR(
    "operators",
    api.getOperators,
    {
      refreshInterval: 0,
      revalidateOnFocus: true,
    }
  )
}

// Config endpoints (read-only, no auto-refresh)
export function useConfigSettings() {
  return useSWR(
    "config-settings",
    api.getConfigSettings,
    { refreshInterval: 0, revalidateOnFocus: true }
  )
}

export function useConfigInventory() {
  return useSWR(
    "config-inventory",
    api.getConfigInventory,
    { refreshInterval: 0, revalidateOnFocus: true }
  )
}

export function useConfigPlaybooks() {
  return useSWR(
    "config-playbooks",
    api.getConfigPlaybooks,
    { refreshInterval: 0, revalidateOnFocus: true }
  )
}

export function useTimeseries(metric?: string, range?: string, bucket?: string) {
  const key = ["timeseries", metric || "mitigations", range || "24h", bucket || "1h"]

  return useSWR(
    key,
    () => api.getTimeseries({ metric, range, bucket }),
    {
      refreshInterval: 30000,
      revalidateOnFocus: true,
    }
  )
}

export function useAlertingConfig() {
  return useSWR(
    "alerting-config",
    api.getAlertingConfig,
    { refreshInterval: 0, revalidateOnFocus: true }
  )
}

export function useIpHistory(ip: string | null) {
  return useSWR(
    ip ? ["ip-history", ip] : null,
    () => api.getIpHistory(ip!),
    {
      refreshInterval: 0,
      revalidateOnFocus: true,
    }
  )
}

export function useNotificationPreferences() {
  return useSWR(
    "notification-preferences",
    api.getNotificationPreferences,
    { refreshInterval: 0, revalidateOnFocus: true }
  )
}

// Signal Groups (Correlation Engine)

export function useSignalGroups(params?: {
  status?: string
  vector?: string
  limit?: number
  start?: string
  end?: string
}) {
  const key = params ? ["signal-groups", JSON.stringify(params)] : "signal-groups"

  const fetcher = () => api.getSignalGroups(params)

  return useSWR(key, fetcher, {
    refreshInterval: REFRESH_INTERVAL,
    revalidateOnFocus: true,
  })
}

export function useSignalGroupsPaginated(params?: {
  status?: string
  vector?: string
  limit?: number
  start?: string
  end?: string
}) {
  const limit = params?.limit ?? 25

  const getKey = (pageIndex: number, previousPageData: api.SignalGroupsResponse | null) => {
    if (previousPageData && !previousPageData.has_more) return null
    const cursor = previousPageData?.next_cursor ?? undefined

    return ["signal-groups-page", JSON.stringify({ ...params, limit, cursor })]
  }

  const fetcher = async (_key: string[]): Promise<api.SignalGroupsResponse> => {
        const parsedParams = JSON.parse(_key[1])

        return api.getSignalGroups(parsedParams)
      }

  return useSWRInfinite(getKey, fetcher, {
    refreshInterval: REFRESH_INTERVAL,
    revalidateAll: true,
    revalidateOnFocus: true,
  })
}

export function useSignalGroupDetail(id: string | null) {
  const fetcher = () => api.getSignalGroupDetail(id!)

  return useSWR(
    id ? ["signal-group", id] : null,
    fetcher,
    {
      refreshInterval: REFRESH_INTERVAL,
    }
  )
}

export function useSignalSources() {
  return useSWR(
    "signal-sources",
    api.getSignalSources,
    {
      refreshInterval: 30000,
      revalidateOnFocus: true,
    }
  )
}

export function useCorrelationConfig() {
  return useSWR(
    "correlation-config",
    api.getCorrelationConfig,
    {
      refreshInterval: 0,
      revalidateOnFocus: true,
    }
  )
}

export function useOpenSignalGroupCount() {
  const { data } = useSignalGroups({ status: "open", limit: 1 })

  return data?.count ?? 0
}

export function useCachedCorroborators(params: {
  source?: string
  limit?: number
} = {}) {
  const key = `cached-corroborators:${params.source ?? ""}:${params.limit ?? 100}`

  return useSWR(
    key,
    () => api.getCachedCorroborators(params),
    {
      refreshInterval: 30_000,
      revalidateOnFocus: true,
    },
  )
}
