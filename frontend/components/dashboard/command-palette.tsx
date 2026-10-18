"use client"

import { formatConfidence } from "@/lib/confidence"
import { MISSING } from "@/lib/format"
import { StatusPill, mitigationTone } from "@/components/dashboard/status-pill"
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
import { LayoutDashboard, Shield, ShieldAlert, Activity, FileText, Zap, Database, FileCode, History, Waypoints } from "lucide-react"
import { useMitigations, useEvents } from "@/hooks/use-api"

interface CommandPaletteProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function CommandPalette({ open, onOpenChange }: CommandPaletteProps) {
  const router = useRouter()
  const [search, setSearch] = useState("")
  
  const { data: mitigationsResp } = useMitigations({ limit: 50 })
  const { data: eventsResp } = useEvents({ limit: 50 })
  const mitigations = mitigationsResp?.mitigations
  const events = eventsResp?.events

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

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <Command className="border border-border bg-popover shadow-2xl">
        <CommandInput
          placeholder="Search mitigations, events, pages…"
          value={search}
          onValueChange={setSearch}
          className="border-b border-border text-sm"
        />
        <CommandList className="max-h-[400px]">
          <CommandEmpty className="py-6 text-center text-xs text-muted-foreground">
            No results found.
          </CommandEmpty>

          <CommandGroup heading="Pages">
            <CommandItem onSelect={() => runCommand(() => router.push("/"))} className="text-sm">
              <LayoutDashboard className="mr-2 h-3 w-3 opacity-60" />
              <span>Overview</span>
              <CommandShortcut className="font-mono">g o</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/mitigations"))} className="text-sm">
              <Shield className="mr-2 h-3 w-3 opacity-60" />
              <span>Mitigations</span>
              <CommandShortcut className="font-mono">g m</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/events"))} className="text-sm">
              <Activity className="mr-2 h-3 w-3 opacity-60" />
              <span>Events</span>
              <CommandShortcut className="font-mono">g e</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/correlation"))} className="text-sm">
              <Waypoints className="mr-2 h-3 w-3 opacity-60" />
              <span>Correlation</span>
              <CommandShortcut className="font-mono">g r</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/inventory"))} className="text-sm">
              <Database className="mr-2 h-3 w-3 opacity-60" />
              <span>Inventory</span>
              <CommandShortcut className="font-mono">g i</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/ip-history"))} className="text-sm">
              <History className="mr-2 h-3 w-3 opacity-60" />
              <span>IP History</span>
              <CommandShortcut className="font-mono">g h</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/audit-log"))} className="text-sm">
              <FileText className="mr-2 h-3 w-3 opacity-60" />
              <span>Audit log</span>
              <CommandShortcut className="font-mono">g a</CommandShortcut>
            </CommandItem>
            <CommandItem onSelect={() => runCommand(() => router.push("/config"))} className="text-sm">
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
                    className="flex items-center gap-3 text-sm"
                  >
                    <StatusPill tone={mitigationTone(m.status)}>{m.status}</StatusPill>
                    <span className="font-mono">{m.victim_ip}</span>
                    <span className="text-muted-foreground">{m.vector.replace(/_/g, " ")}</span>
                    <span className="ml-auto text-muted-foreground">{m.customer_id || MISSING}</span>
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
                    onSelect={() =>
                      runCommand(() => router.push(`/events?id=${encodeURIComponent(e.event_id)}`))
                    }
                    className="flex items-center gap-3 text-sm"
                  >
                    <span className="size-1.5 rounded-full bg-muted-foreground" aria-hidden="true" />
                    <span className="font-mono">{e.victim_ip}</span>
                    <span className="text-muted-foreground">{e.vector.replace(/_/g, " ")}</span>
                    <span className="ml-auto text-muted-foreground tabular-nums">
                      {formatConfidence(e.confidence)}
                    </span>
                  </CommandItem>
                ))}
              </CommandGroup>
            </>
          )}

          <CommandSeparator />
          <CommandGroup heading="Quick actions">
            <CommandItem
              onSelect={() => runCommand(() => router.push("/mitigations?mitigate=true"))}
              className="text-sm"
            >
              <ShieldAlert className="mr-2 h-3 w-3 text-muted-foreground" />
              <span>Mitigate now</span>
            </CommandItem>
            <CommandItem
              onSelect={() => runCommand(() => router.push("/mitigations?status=active"))}
              className="text-sm"
            >
              <Zap className="mr-2 h-3 w-3 text-muted-foreground" />
              <span>View active mitigations</span>
            </CommandItem>
          </CommandGroup>
        </CommandList>
        <div className="flex items-center justify-between border-t border-border px-3 py-2 text-xs text-muted-foreground">
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
