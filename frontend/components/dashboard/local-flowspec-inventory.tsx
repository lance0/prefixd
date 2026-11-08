"use client"

import { useSpeakerRoutes } from "@/hooks/use-api"
import type { SpeakerRoutesResponse } from "@/lib/api"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { describeMatch } from "./flowspec-preview"
import { EmptyState, ErrorState, LoadingRows } from "./states"
import { Tag } from "./status-pill"

const OBSERVATION_LABELS: Record<SpeakerRoutesResponse["observation_scope"], string> = {
  retained_local_flow_spec_intent: "Retained local FlowSpec intent",
  accepted_local_flow_spec_rib: "Accepted local FlowSpec RIB",
  adapter_local_flow_spec: "Adapter-local FlowSpec",
}

export function LocalFlowSpecInventory() {
  const { data, error, isValidating, mutate } = useSpeakerRoutes()
  const unsupported = error?.message.startsWith("API error 501:")

  return (
    <section aria-labelledby="local-flowspec-heading" className="overflow-hidden rounded-md border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
        <div className="space-y-1">
          <h2 id="local-flowspec-heading" className="text-sm font-semibold">Local FlowSpec routes</h2>
          <p className="text-xs text-muted-foreground">
            Direct speaker observation, including untracked rules. Excludes blackholes.
            This does not prove export, router receipt or enforcement.
          </p>
        </div>
        <Button variant="outline" size="sm" disabled={isValidating} onClick={() => { void mutate() }}>
          Refresh routes
        </Button>
      </div>
      {error ? (
        <ErrorState
          title={unsupported ? "Local FlowSpec observation unsupported" : "Unable to observe local FlowSpec routes"}
          detail={unsupported
            ? "This speaker cannot report its local FlowSpec inventory. Route state is unknown."
            : "The speaker inventory could not be refreshed. Route state is unknown; rules may still be present."}
          onRetry={() => { void mutate() }}
          retryLabel="Retry speaker observation"
        />
      ) : !data ? (
        <LoadingRows label="Loading local FlowSpec routes" />
      ) : (
        <>
          <div className="flex flex-wrap items-center gap-2 border-b px-4 py-2 text-xs">
            <Tag>{data.backend}</Tag>
            <span>{OBSERVATION_LABELS[data.observation_scope]}</span>
            <span className="text-muted-foreground tabular-nums">{data.routes.length} local {data.routes.length === 1 ? "route" : "routes"}</span>
          </div>
          {data.routes.length === 0 ? (
            <EmptyState title="No local FlowSpec routes observed" description="The speaker returned a complete empty FlowSpec inventory. Blackholes and router enforcement are not observed here." />
          ) : (
            <Table aria-label="Observed local FlowSpec routes">
              <TableHeader>
                <TableRow>
                  <TableHead>Destination</TableHead>
                  <TableHead>Routing scope</TableHead>
                  <TableHead>Match</TableHead>
                  <TableHead>Actions</TableHead>
                  <TableHead>Injection owner</TableHead>
                  <TableHead>Inspect</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.routes.map((rule) => (
                  <TableRow key={JSON.stringify(rule)}>
                    <TableCell className="font-mono">{rule.nlri.dst_prefix || "any"}</TableCell>
                    <TableCell className="max-w-72 whitespace-normal break-words font-mono text-xs">{rule.nlri.scope ? `VPN${rule.nlri.scope.family === "ipv4" ? "v4" : "v6"} · RD ${rule.nlri.scope.rd} · RT ${(rule.route_targets ?? []).join(", ")}` : "Global"}</TableCell>
                    <TableCell className="min-w-48 max-w-96 whitespace-normal break-words">
                      {describeMatch({ ...rule.nlri, action_type: rule.actions[0]?.action_type ?? "" })}
                    </TableCell>
                    <TableCell className="tabular-nums">
                      {rule.actions.length === 0 ? "No actions reported" : rule.actions.map((action, actionIndex) => (
                        <div key={actionIndex}>
                          {action.action_type}{action.action_type === "police" ? ` ${action.rate_bps === undefined ? "rate unavailable" : `${action.rate_bps.toLocaleString("en-US")} bps`}` : ""}
                        </div>
                      ))}
                    </TableCell>
                    <TableCell className="max-w-64 break-all font-mono text-xs">{rule.owner || "No injection owner"}</TableCell>
                    <TableCell>
                      <details>
                        <summary className="cursor-pointer rounded-sm whitespace-nowrap text-xs focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-ring">Full rule for {rule.nlri.dst_prefix || "any destination"}</summary>
                        <pre className="mt-2 max-w-md overflow-x-auto text-xs">{JSON.stringify(rule, null, 2)}</pre>
                      </details>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          <p className="border-t px-4 py-2 text-xs text-muted-foreground">
            Injection owner identifies the speaker injection only; it does not establish this controller's ownership or a lease deadline.
          </p>
        </>
      )}
    </section>
  )
}
