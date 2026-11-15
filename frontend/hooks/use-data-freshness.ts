"use client"

import { useEffect, useState, useSyncExternalStore } from "react"
import type { ConnectionState } from "@/hooks/use-websocket-types"
import { dataFreshness, getApiReceipt, subscribeApiReceipt, type DataFreshness } from "@/lib/freshness"

/** Freshness of on-screen data, re-evaluated every second so age and staleness never freeze. */
export function useDataFreshness(connection: ConnectionState): DataFreshness {
  const receipt = useSyncExternalStore(subscribeApiReceipt, getApiReceipt, getApiReceipt)
  const [startedAt] = useState(() => performance.now())
  const [now, setNow] = useState(startedAt)

  useEffect(() => {
    const timer = setInterval(() => setNow(performance.now()), 1000)

    return () => clearInterval(timer)
  }, [])

  return dataFreshness(connection, receipt, now, startedAt)
}
