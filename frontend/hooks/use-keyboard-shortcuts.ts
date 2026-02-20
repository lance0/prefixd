"use client"

import { useEffect, useCallback, useRef } from "react"
import { useRouter } from "next/navigation"

interface KeyboardShortcutsOptions {
  onCommandPalette?: () => void
  onToggleSidebar?: () => void
  onToggleHelp?: () => void
}

export function useKeyboardShortcuts({ onCommandPalette, onToggleSidebar, onToggleHelp }: KeyboardShortcutsOptions = {}) {
  const router = useRouter()
  const gPressedRef = useRef(false)
  const gTimeoutRef = useRef<NodeJS.Timeout>()

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      // Ignore if typing in input/textarea
      const target = e.target as HTMLElement
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) {
        return
      }

      // Cmd/Ctrl + K for command palette
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault()
        onCommandPalette?.()
        return
      }

      // Cmd/Ctrl + B for sidebar toggle
      if ((e.metaKey || e.ctrlKey) && e.key === "b") {
        e.preventDefault()
        onToggleSidebar?.()
        return
      }

      if (e.key === "?" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault()
        onToggleHelp?.()
        return
      }

      // n for Mitigate Now
      if (e.key === "n" && !e.metaKey && !e.ctrlKey) {
        e.preventDefault()
        router.push("/mitigations?mitigate=true")
        return
      }

      // Two-key navigation: g + letter
      if (e.key === "g" && !e.metaKey && !e.ctrlKey) {
        gPressedRef.current = true
        clearTimeout(gTimeoutRef.current)
        gTimeoutRef.current = setTimeout(() => {
          gPressedRef.current = false
        }, 1000)
        return
      }

      if (gPressedRef.current) {
        gPressedRef.current = false
        clearTimeout(gTimeoutRef.current)

        switch (e.key) {
          case "o":
            e.preventDefault()
            router.push("/")
            break
          case "m":
            e.preventDefault()
            router.push("/mitigations")
            break
          case "e":
            e.preventDefault()
            router.push("/events")
            break
          case "a":
            e.preventDefault()
            router.push("/audit-log")
            break
          case "i":
            e.preventDefault()
            router.push("/inventory")
            break
          case "c":
            e.preventDefault()
            router.push("/config")
            break
          case "h":
            e.preventDefault()
            router.push("/ip-history")
            break
        }
      }
    },
    [router, onCommandPalette, onToggleSidebar, onToggleHelp],
  )

  useEffect(() => {
    window.addEventListener("keydown", handleKeyDown)
    return () => {
      window.removeEventListener("keydown", handleKeyDown)
      clearTimeout(gTimeoutRef.current)
    }
  }, [handleKeyDown])
}
