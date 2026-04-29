"use client"

import useSWR from "swr"
import useSWRInfinite from "swr/infinite"
import * as api from "@/lib/api"
import * as mockData from "@/lib/mock-api-data"

const REFRESH_INTERVAL = 5000 // 5 seconds
const MOCK_MODE = process.env.NEXT_PUBLIC_MOCK_MODE === "true"

// Mock fetchers that return static data
const mockFetchers = {
  publicHealth: async () => mockData.mockPublicHealth,
  health: async () => mockData.mockHealth,
  stats: async () => mockData.mockStats,
  mitigations: async () => mockData.mockMitigations,
  mitigation: async (id: string) => mockData.mockMitigations.find(m => m.mitigation_id === id) || mockData.mockMitigations[0],
  safelist: async () => mockData.mockSafelist,
  pops: async () => mockData.mockPops,
  events: async () => mockData.mockEvents,
  auditLog: async () => mockData.mockAuditLog,
  dashboard: async () => ({
    health: mockData.mockHealth,
    stats: mockData.mockStats,
    mitigations: mockData.mockMitigations.filter(m => m.status === "active" || m.status === "escalated"),
  }),
}

export function useHealth() {
  return useSWR(
    "health",
    MOCK_MODE ? mockFetchers.publicHealth : api.getHealth,
    {
      refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
      revalidateOnFocus: !MOCK_MODE,
    }
  )
}

export function useHealthDetail() {
  return useSWR(
    "health-detail",
    MOCK_MODE ? mockFetchers.health : api.getHealthDetail,
    {
      refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
      revalidateOnFocus: !MOCK_MODE,
    }
  )
}

export function useStats() {
  return useSWR(
    "stats",
    MOCK_MODE ? mockFetchers.stats : api.getStats,
    {
      refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
      revalidateOnFocus: !MOCK_MODE,
    }
  )
}

export function useMitigations(params?: Parameters<typeof api.getMitigations>[0]) {
  const key = params ? ["mitigations", JSON.stringify(params)] : "mitigations"
  
  const fetcher = MOCK_MODE
    ? async (): Promise<api.MitigationsResponse> => {
        let result = mockData.mockMitigations
        if (params?.status) {
          result = result.filter(m => params.status!.includes(m.status))
        }
        if (params?.customer_id) {
          result = result.filter(m => m.customer_id === params.customer_id)
        }
        if (params?.limit) {
          result = result.slice(0, params.limit)
        }
        return { mitigations: result, count: result.length, next_cursor: null, has_more: false }
      }
    : () => api.getMitigations(params)

  return useSWR(key, fetcher, {
    refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
    revalidateOnFocus: !MOCK_MODE,
  })
}

export function useMitigation(id: string | null) {
  const fetcher = MOCK_MODE
    ? () => mockFetchers.mitigation(id!)
    : () => api.getMitigation(id!)

  return useSWR(
    id ? ["mitigation", id] : null,
    fetcher,
    {
      refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
    }
  )
}

export function useSafelist() {
  return useSWR(
    "safelist",
    MOCK_MODE ? mockFetchers.safelist : api.getSafelist,
    {
      refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
    }
  )
}

export function usePops() {
  return useSWR(
    "pops",
    MOCK_MODE ? mockFetchers.pops : api.getPops,
    {
      refreshInterval: MOCK_MODE ? 0 : 30000,
    }
  )
}

export function useEvents(params?: Parameters<typeof api.getEvents>[0]) {
  const key = params ? ["events", JSON.stringify(params)] : "events"
  
  const fetcher = MOCK_MODE
    ? async (): Promise<api.EventsResponse> => {
        let result = mockData.mockEvents
        if (params?.limit) {
          result = result.slice(0, params.limit)
        }
        return { events: result, count: result.length, next_cursor: null, has_more: false }
      }
    : () => api.getEvents(params)

  return useSWR(key, fetcher, {
    refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
    revalidateOnFocus: !MOCK_MODE,
  })
}

export function useAuditLog(params?: Parameters<typeof api.getAuditLog>[0]) {
  const key = params ? ["audit", JSON.stringify(params)] : "audit"
  
  const fetcher = MOCK_MODE
    ? async (): Promise<api.AuditResponse> => {
        let result = mockData.mockAuditLog
        if (params?.limit) {
          result = result.slice(0, params.limit)
        }
        return { entries: result, count: result.length, next_cursor: null, has_more: false }
      }
    : () => api.getAuditLog(params)

  return useSWR(key, fetcher, {
    refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
    revalidateOnFocus: !MOCK_MODE,
  })
}

// Parallel fetch all dashboard data in one request (async-parallel pattern)
export function useDashboard() {
  return useSWR(
    "dashboard",
    MOCK_MODE ? mockFetchers.dashboard : api.getDashboardData,
    {
      refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
      revalidateOnFocus: !MOCK_MODE,
    }
  )
}

// Operator management (admin only)
export function useOperators() {
  return useSWR(
    "operators",
    MOCK_MODE ? async () => [] : api.getOperators,
    {
      refreshInterval: 0,
      revalidateOnFocus: !MOCK_MODE,
    }
  )
}

// Config endpoints (read-only, no auto-refresh)
export function useConfigSettings() {
  return useSWR(
    "config-settings",
    MOCK_MODE ? async () => ({ settings: {}, loaded_at: "" }) : api.getConfigSettings,
    { refreshInterval: 0, revalidateOnFocus: !MOCK_MODE }
  )
}

export function useConfigInventory() {
  return useSWR(
    "config-inventory",
    MOCK_MODE ? async () => ({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: "" }) : api.getConfigInventory,
    { refreshInterval: 0, revalidateOnFocus: !MOCK_MODE }
  )
}

export function useConfigPlaybooks() {
  return useSWR(
    "config-playbooks",
    MOCK_MODE ? async () => ({ playbooks: [], total_playbooks: 0, loaded_at: "" }) : api.getConfigPlaybooks,
    { refreshInterval: 0, revalidateOnFocus: !MOCK_MODE }
  )
}

export function useTimeseries(metric?: string, range?: string, bucket?: string) {
  const key = ["timeseries", metric || "mitigations", range || "24h", bucket || "1h"]
  return useSWR(
    key,
    MOCK_MODE
      ? async () => ({ metric: metric || "mitigations", buckets: [] })
      : () => api.getTimeseries({ metric, range, bucket }),
    {
      refreshInterval: MOCK_MODE ? 0 : 30000,
      revalidateOnFocus: !MOCK_MODE,
    }
  )
}

export function useAlertingConfig() {
  return useSWR(
    "alerting-config",
    MOCK_MODE ? async () => ({ destinations: [], events: [] }) : api.getAlertingConfig,
    { refreshInterval: 0, revalidateOnFocus: !MOCK_MODE }
  )
}

export function useIpHistory(ip: string | null) {
  return useSWR(
    ip ? ["ip-history", ip] : null,
    MOCK_MODE
      ? async () => ({ ip: ip!, customer: null, service: null, events: [], mitigations: [] })
      : () => api.getIpHistory(ip!),
    {
      refreshInterval: 0,
      revalidateOnFocus: !MOCK_MODE,
    }
  )
}

export function useNotificationPreferences() {
  return useSWR(
    "notification-preferences",
    MOCK_MODE
      ? async () => ({ muted_events: [], quiet_hours_start: null, quiet_hours_end: null })
      : api.getNotificationPreferences,
    { refreshInterval: 0, revalidateOnFocus: !MOCK_MODE }
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

  const fetcher = MOCK_MODE
    ? async (): Promise<api.SignalGroupsResponse> => {
        let result = mockData.mockSignalGroups
        if (params?.status) {
          result = result.filter(g => g.status === params.status)
        }
        if (params?.vector) {
          result = result.filter(g => g.vector === params.vector)
        }
        return { groups: result, count: result.length, next_cursor: null, has_more: false }
      }
    : () => api.getSignalGroups(params)

  return useSWR(key, fetcher, {
    refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
    revalidateOnFocus: !MOCK_MODE,
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

  const fetcher = MOCK_MODE
    ? async (): Promise<api.SignalGroupsResponse> => {
        let result = mockData.mockSignalGroups
        if (params?.status) {
          result = result.filter(g => g.status === params.status)
        }
        if (params?.vector) {
          result = result.filter(g => g.vector === params.vector)
        }
        return { groups: result, count: result.length, next_cursor: null, has_more: false }
      }
    : async (_key: string[]): Promise<api.SignalGroupsResponse> => {
        const parsedParams = JSON.parse(_key[1])
        return api.getSignalGroups(parsedParams)
      }

  return useSWRInfinite(getKey, fetcher, {
    revalidateOnFocus: !MOCK_MODE,
  })
}

export function useSignalGroupDetail(id: string | null) {
  const fetcher = MOCK_MODE
    ? async () => {
        const group = mockData.mockSignalGroups.find(g => g.group_id === id)
        if (!group) throw new Error("Not found")
        return {
          ...group,
          events: mockData.mockSignalGroupEvents.filter(e => e.group_id === id),
        } as api.SignalGroupDetailResponse
      }
    : () => api.getSignalGroupDetail(id!)

  return useSWR(
    id ? ["signal-group", id] : null,
    fetcher,
    {
      refreshInterval: MOCK_MODE ? 0 : REFRESH_INTERVAL,
    }
  )
}

export function useSignalSources() {
  return useSWR(
    "signal-sources",
    MOCK_MODE ? async () => mockData.mockSignalSources : api.getSignalSources,
    {
      refreshInterval: MOCK_MODE ? 0 : 30000,
      revalidateOnFocus: !MOCK_MODE,
    }
  )
}

export function useCorrelationConfig() {
  return useSWR(
    "correlation-config",
    MOCK_MODE ? async () => mockData.mockCorrelationConfig : api.getCorrelationConfig,
    {
      refreshInterval: 0,
      revalidateOnFocus: !MOCK_MODE,
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
    MOCK_MODE
      ? async () => ({
          now: new Date().toISOString(),
          total: 0,
          by_source: [],
          signals: [],
        } as Awaited<ReturnType<typeof api.getCachedCorroborators>>)
      : () => api.getCachedCorroborators(params),
    {
      refreshInterval: 30_000,
      revalidateOnFocus: !MOCK_MODE,
    },
  )
}
