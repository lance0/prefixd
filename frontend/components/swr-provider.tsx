"use client"

import { SWRConfig } from "swr"

export function SWRProvider({ children }: { children: React.ReactNode }) {
  return (
    <SWRConfig
      value={{
        revalidateOnFocus: true,
        revalidateOnReconnect: true,
        dedupingInterval: 2000,
        errorRetryCount: 3,
        onErrorRetry: (error, _key, _config, revalidate, { retryCount }) => {
          // Don't retry on 401 -- session expired, let auth-expired event handle redirect
          if (error?.message?.includes("401")) return

          // Default retry with exponential backoff for other errors
          if (retryCount >= 3) return
          setTimeout(() => revalidate({ retryCount }), 5000 * 2 ** retryCount)
        },
        onError: (error) => {
          if (!error?.message?.includes("401")) {
            console.error("SWR Error:", error)
          }
        },
      }}
    >
      {children}
    </SWRConfig>
  )
}
