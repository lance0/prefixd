"use client"

import { useCallback, useState } from "react"
import { useRouter } from "next/navigation"
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command"
import { LayoutDashboard, Shield, ShieldAlert, Activity, FileText, Settings, Zap, Clock, XCircle, Database, FileCode, History } from "lucide-react"
import { useMitigations, useEvents } from "@/hooks/use-api"
import type { Mitigation } from "@/lib/api"

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const router = useRouter()
  const [search, setSearch] = useState("")
  
  const { data: mitigations } = useMitigations({ limit: 50 })
  const { data: events } = useEvents({ limit: 50 })

  const runCommand = useCallback(
    (command: () => void) => {
      onOpenChange(false)
      command()
    },
    [onOpenChange],
  )

  const filteredMitigations = (mitigations || [])
    .filter(
      (m) =>
        m.mitigation_id.toLowerCase().includes(search.toLowerCase()) ||
        m.victim_ip.includes(search) ||
        m.vector.toLowerCase().includes(search.toLowerCase()) ||
        (m.customer_id && m.customer_id.toLowerCase().includes(search.toLowerCase())),
    )
    .slice(0, 5)

  const filteredEvents = (events || [])
    .filter(
      (e) =>
        e.event_id.toLowerCase().includes(search.toLowerCase()) ||
        e.victim_ip.includes(search) ||
        e.vector.toLowerCase().includes(search.toLowerCase()),
    )
    .slice(0, 5)

  const getStatusIcon = (status: Mitigation["status"]) => {
    switch (status) {
      case "active":
        return <span className="h-1.5 w-1.5 bg-primary" />
      case "escalated":
        return <span className="h-1.5 w-1.5 bg-destructive" />
      case "expired":
        return <Clock className="h-3 w-3 text-muted-foreground" />
      case "withdrawn":
        return <XCircle className="h-3 w-3 text-muted-foreground" />
      default:
        return <span className="h-1.5 w-1.5 bg-muted-foreground" />
    }
  }

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <Command className="border border-border bg-popover shadow-2xl">
        <CommandInput
          placeholder="Search mitigations, events, pages..."
          value={search}
          onValueChange={setSearch}
          className="border-b border-border font-mono text-sm"
        />
        <CommandList className="max-h-[400px]">
          <CommandEmpty className="py-6 text-center text-xs font-mono text-muted-foreground">
            No results found.
          </CommandEmpty>

          <CommandGroup heading="Pages">
            <CommandItem onSelect={() => runCommand(() => router.push("/"))} className="font-mono text-xs">
              <LayoutDashboard className="mr-2 h-3 w-3 opacity-60" />
              <span>Overview</span>
              <CommandShortcut className="font-mono">g o</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/mitigations"))} className="font-mono text-xs">
              <Shield className="mr-2 h-3 w-3 opacity-60" />
              <span>Mitigations</span>
              <CommandShortcut className="font-mono">g m</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/events"))} className="font-mono text-xs">
              <Activity className="mr-2 h-3 w-3 opacity-60" />
              <span>Events</span>
              <CommandShortcut className="font-mono">g e</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/inventory"))} className="font-mono text-xs">
              <Database className="mr-2 h-3 w-3 opacity-60" />
              <span>Inventory</span>
              <CommandShortcut className="font-mono">g i</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/ip-history"))} className="font-mono text-xs">
              <History className="mr-2 h-3 w-3 opacity-60" />
              <span>IP History</span>
              <CommandShortcut className="font-mono">g h</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/audit-log"))} className="font-mono text-xs">
              <FileText className="mr-2 h-3 w-3 opacity-60" />
              <span>Audit Log</span>
              <CommandShortcut className="font-mono">g a</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/config"))} className="font-mono text-xs">
              <FileCode className="mr-2 h-3 w-3 opacity-60" />
              <span>Config</span>
              <CommandShortcut className="font-mono">g c</CommandShortcut>
            </CommandItem>
          </CommandGroup>

          {search.length > 0 && filteredMitigations.length > 0 && (
            <>
              <CommandSeparator />
              <CommandGroup heading="Mitigations">
                {filteredMitigations.map((m) => (
                  <CommandItem
                    key={m.mitigation_id}
                    onSelect={() => runCommand(() => router.push(`/mitigations/${m.mitigation_id}`))}
                    className="flex items-center gap-3 font-mono text-xs"
                  >
                    {getStatusIcon(m.status)}
                    <span>{m.victim_ip}</span>
                    <span className="text-muted-foreground">{m.vector.replace(/_/g, " ")}</span>
                    <span className="ml-auto text-muted-foreground">{m.customer_id || "N/A"}</span>
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          )}

          {search.length > 0 && filteredEvents.length > 0 && (
            <>
              <CommandSeparator />
              <CommandGroup heading="Events">
                {filteredEvents.map((e) => (
                  <CommandItem
                    key={e.event_id}
                    onSelect={() => runCommand(() => router.push(`/events?id=${e.event_id}`))}
                    className="flex items-center gap-3 font-mono text-xs"
                  >
                    <span className="h-1.5 w-1.5 bg-muted-foreground" />
                    <span>{e.victim_ip}</span>
                    <span className="text-muted-foreground">{e.vector.replace(/_/g, " ")}</span>
                    <span className="ml-auto text-muted-foreground tabular-nums">
                      {e.confidence ? `${Math.round(e.confidence * 100)}%` : "N/A"}
                    </span>
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          )}

          <CommandSeparator />
          <CommandGroup heading="Quick Actions">
            <CommandItem
              onSelect={() => runCommand(() => router.push("/mitigations?mitigate=true"))}
              className="font-mono text-xs"
            >
              <ShieldAlert className="mr-2 h-3 w-3 text-primary" />
              <span>Mitigate Now</span>
            </CommandItem>
            <CommandItem
              onSelect={() => runCommand(() => router.push("/mitigations?status=active"))}
              className="font-mono text-xs"
            >
              <Zap className="mr-2 h-3 w-3 text-primary" />
              <span>View Active Mitigations</span>
            </CommandItem>
            <CommandItem
              onSelect={() => runCommand(() => router.push("/mitigations?status=escalated"))}
              className="font-mono text-xs"
            >
              <span className="mr-2 h-1.5 w-1.5 bg-destructive" />
              <span>View Escalated Mitigations</span>
            </CommandItem>
          </CommandGroup>
        </CommandList>
        <div className="flex items-center justify-between border-t border-border px-3 py-2 text-[10px] font-mono text-muted-foreground">
          <div className="flex items-center gap-4">
            <span>
              <kbd className="kbd">↑↓</kbd> navigate
            </span>
            <span>
              <kbd className="kbd">↵</kbd> select
            </span>
            <span>
              <kbd className="kbd">esc</kbd> close
            </span>
          </div>
        </div>
      </Command>
    </CommandDialog>
  )
}
