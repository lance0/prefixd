"use client"

import { useCallback } from "react"
import { usePathname, useSearchParams } from "next/navigation"

/**
 * Keeps the selected tab in `?tab=` so links and refresh reopen it. The first tab is the
 * default and is left out of the URL; an unknown value falls back to it. Uses
 * history.replaceState, which Next.js syncs with useSearchParams, so switching tabs
 * neither refetches the route nor adds history entries.
 */
export function useTabParam<T extends string>(tabs: readonly T[]): [T, (tab: string) => void] {
  const searchParams = useSearchParams()
  const pathname = usePathname()
  const requested = searchParams.get("tab")
  const active = tabs.find((tab) => tab === requested) ?? tabs[0]

  const select = useCallback((tab: string) => {
    const params = new URLSearchParams(searchParams.toString())

    if (tab === tabs[0]) params.delete("tab")
    else params.set("tab", tab)
    const query = params.toString()
    window.history.replaceState(null, "", `${pathname}${query ? `?${query}` : ""}${window.location.hash}`)
  }, [pathname, searchParams, tabs])

  return [active, select]
}
