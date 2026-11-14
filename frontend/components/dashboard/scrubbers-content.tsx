"use client"

import { useRef, useState } from "react"
import useSWR from "swr"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { tcpFlagsLabel } from "@/components/dashboard/flowspec-preview"
import { WithdrawConfirmDialog } from "@/components/dashboard/withdraw-confirm-dialog"
import { usePermissions } from "@/hooks/use-permissions"
import { armScrubber, createDiversion, getDiversions, getScrubbers, previewDiversion, withdrawDiversion, type DiversionExportObservation, type DiversionMatch, type DiversionPreview, type DiversionRequest, type ScrubberDiversion, type ScrubberReturnLeg } from "@/lib/api"

export function ScrubbersContent() {
  const permissions = usePermissions()
  const profiles = useSWR("scrubber-profiles", getScrubbers, { refreshInterval: 5000 })
  const diversions = useSWR("scrubber-diversions", getDiversions, { refreshInterval: 5000 })
  const [profile, setProfile] = useState("")
  const [victim, setVictim] = useState("")
  const [source, setSource] = useState("")
  const [protocol, setProtocol] = useState("6")
  const [ports, setPorts] = useState("")
  const [sourcePorts, setSourcePorts] = useState("")
  const [ttl, setTtl] = useState("60")
  const [reason, setReason] = useState("")
  const [preview, setPreview] = useState<DiversionPreview | null>(null)
  const [request, setRequest] = useState<DiversionRequest | null>(null)
  const [requestScope, setRequestScope] = useState("global")
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const [error, setError] = useState("")
  const [withdrawTarget, setWithdrawTarget] = useState<ScrubberDiversion | null>(null)
  const [withdrawError, setWithdrawError] = useState("")
  const withdrawTrigger = useRef<HTMLButtonElement | null>(null)
  const heading = useRef<HTMLHeadingElement | null>(null)
  const editVersion = useRef(0)
  const invalidate = () => { editVersion.current += 1; setPreview(null); setRequest(null); setRequestScope("global"); setConfirmed(false); setMessage("") }

  async function action(work: () => Promise<void>) {
    setBusy(true); setError(""); setMessage("")

    try { await work(); await Promise.all([profiles.mutate(), diversions.mutate()]) }
    catch (error) { setError(error instanceof Error ? error.message : "The operation could not be confirmed.") }
    finally { setBusy(false) }
  }

  async function confirmWithdraw(reason: string) {
    if (!withdrawTarget) return false
    setBusy(true); setWithdrawError(""); setMessage("")

    try {
      await withdrawDiversion(withdrawTarget.id, reason)
      setMessage("Withdrawal requested. Victim exclusion remains until local absence is confirmed.")

      return true
    } catch (error) {
      setWithdrawError(error instanceof Error ? error.message : "The withdrawal could not be confirmed.")

      return false
    } finally {
      setBusy(false)
      // Refresh in the background: a stalled read must not hold the dialog's pending lock.
      // SWR records refresh failures in each hook's error state.
      void Promise.all([profiles.mutate(), diversions.mutate()]).catch(() => {})
    }
  }

  const selectedProfile = profiles.data?.configuration.find(config => config.id === profile)

  if (!permissions.isAdmin) return <p>Scrubber diversion requires an administrator.</p>

  return <div className="space-y-6 p-6">
    <div><h1 ref={heading} tabIndex={-1} className="text-2xl font-semibold outline-none">Scrubbers</h1><p className="text-sm text-muted-foreground">Manual traffic diversion through a configured scrubber. Withdrawal returns traffic to ordinary routing and may expose the victim to the attack again.</p></div>
    {(error || profiles.error || diversions.error) && <p role="alert" className="text-destructive">{error || "Scrubber observations could not be refreshed. Current state is unknown."}</p>}
    {message && <p role="status">{message}</p>}
    {profiles.data?.enabled === false && <p>Scrubber diversion is disabled. Enable qualified profiles in the controller configuration.</p>}
    {!profiles.data && !profiles.error && <p role="status">Loading scrubber profiles…</p>}
    {profiles.data?.configuration.map(config => {
      const state = profiles.error ? undefined : profiles.data?.profiles[config.id]

      return <Card key={config.id}><CardHeader><CardTitle>{config.id} <span className="text-sm font-normal text-muted-foreground">{config.revision}</span></CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          {config.redirect_route_target ? <p>Redirect to VRF RT {config.redirect_route_target}</p> : <p>Targets: {config.ipv4_target ?? "IPv4 unavailable"} · {config.ipv6_target ?? "IPv6 unavailable"}</p>}
          {config.scope && config.scope !== "global" ? <p>Routing scope: {config.scope}</p> : null}
          {config.return_leg ? <p>Return leg for TCP: {describeReturnLeg(config.return_leg)}</p> : <p>Inbound direction only</p>}
          <p>{state?.ready ? "Fresh readiness" : state?.readiness === "not_ready" ? "Not ready" : "Readiness unknown"} · {state?.armed ? "Armed" : "Unarmed"}</p>
          {state?.latch_reason && <p>{state.latch_reason}</p>}
          <Button variant="outline" disabled={busy || !profiles.data?.enabled || !state?.ready || state?.armed} onClick={() => action(async () => { await armScrubber(config.id, config.revision); setMessage(`Profile ${config.id} re-armed. New intent requires a separate confirmation.`) })}>Re-arm {config.id}</Button>
        </CardContent></Card>
    })}
    {profiles.data?.enabled && <Card><CardHeader><CardTitle>New diversion</CardTitle></CardHeader><CardContent>
      <form className="grid gap-4 sm:grid-cols-2" onChange={invalidate} onSubmit={event => {
        event.preventDefault()
        action(async () => {
          const parsePorts = (value: string) => value.trim() ? value.split(",").map(port => Number(port.trim())) : []
          const scope: DiversionRequest["scope"] = { dst_prefix: victim, protocol: protocol === "any" ? null : Number(protocol), dst_ports: parsePorts(ports) }

          if (source) scope.src_prefix = source

          if (sourcePorts) scope.src_ports = parsePorts(sourcePorts)

          const next: DiversionRequest = { profile, scope, ttl_seconds: Number(ttl), reason }
          const expectedScope = selectedProfile?.scope ?? "global"
          const version = editVersion.current
          const result = await previewDiversion(next, expectedScope)

          if (version !== editVersion.current) return
          setRequest(next); setRequestScope(expectedScope); setPreview(result); setConfirmed(false)
        })
      }}>
        <label className="space-y-1 text-sm">Profile<Select required value={profile} onValueChange={value => { invalidate(); setProfile(value) }}><SelectTrigger aria-label="Profile" className="w-full"><SelectValue placeholder="Select profile" /></SelectTrigger><SelectContent>{profiles.data.configuration.map(config => <SelectItem key={config.id} value={config.id}>{config.id}</SelectItem>)}</SelectContent></Select></label>
        {selectedProfile?.scope && selectedProfile.scope !== "global" ? <p className="text-sm">Requested routing scope: {selectedProfile.scope}</p> : null}
        {selectedProfile?.return_leg ? <p className="text-sm">A TCP diversion through this profile adds a return leg. Any-protocol and source-selected TCP requests are refused.</p> : null}
        <label className="space-y-1 text-sm">Victim host CIDR<Input required value={victim} onChange={event => setVictim(event.target.value)} placeholder="203.0.113.10/32" /></label>
        <label className="space-y-1 text-sm">Source prefix (optional)<Input value={source} onChange={event => setSource(event.target.value)} /></label>
        <label className="space-y-1 text-sm">Protocol<Select value={protocol} onValueChange={value => { invalidate(); setProtocol(value) }}><SelectTrigger aria-label="Protocol" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="6">TCP</SelectItem><SelectItem value="17">UDP</SelectItem><SelectItem value="any">Any</SelectItem></SelectContent></Select></label>
        <label className="space-y-1 text-sm">Destination ports (optional)<Input value={ports} onChange={event => setPorts(event.target.value)} placeholder="80, 443" /></label>
        <label className="space-y-1 text-sm">UDP source ports (optional)<Input value={sourcePorts} onChange={event => setSourcePorts(event.target.value)} /></label>
        <label className="space-y-1 text-sm">Lifetime in seconds<Input required type="number" min="5" max="3600" value={ttl} onChange={event => setTtl(event.target.value)} /></label>
        <label className="space-y-1 text-sm">Reason<Input required maxLength={1024} value={reason} onChange={event => setReason(event.target.value)} /></label>
        <Button type="submit" disabled={busy}>Preview diversion</Button>
      </form>
      {preview && <div className="mt-4 space-y-3 rounded-md border p-4">
        <p>{preview.candidate.dry_run ? "Simulation only" : "Proposed diversion"}: {preview.candidate.rule.nlri.dst_prefix} → {describeTarget(preview.candidate.rule)} via {preview.candidate.profile.id}@{preview.candidate.profile.revision}{preview.candidate.rule.nlri.scope ? ` · VPN${preview.candidate.rule.nlri.scope.family === "ipv4" ? "v4" : "v6"} RD ${preview.candidate.rule.nlri.scope.rd} · RT ${(preview.candidate.rule.route_targets ?? []).join(", ")}` : ""}</p>
        {requestScope !== "global" ? <p className="text-sm">Confirmed routing scope: {requestScope}</p> : null}
        <pre className="overflow-x-auto whitespace-pre-wrap text-xs">{JSON.stringify(preview.candidate.rule.nlri, null, 2)}</pre>
        {preview.candidate.return_rule && <div className="space-y-1">
          <p>Return leg: {describeNlri(preview.candidate.return_rule.nlri)} → {describeTarget(preview.candidate.return_rule)} · community {preview.candidate.return_rule.export_community} · peers {(preview.candidate.profile.return_leg?.router_peers ?? []).join(", ")}</p>
          <p className="text-sm text-muted-foreground">The return leg selects the victim&apos;s responses to any destination. Both legs are confirmed, added, renewed and withdrawn together.</p>
        </div>}
        <p className="text-sm text-muted-foreground">{preview.evidence}</p>
        <label className="flex items-center gap-2 text-sm"><Checkbox checked={confirmed} onCheckedChange={checked => setConfirmed(checked === true)} />{preview.candidate.return_rule ? "I confirm both legs' traffic matches and the scrubber target." : "I confirm this traffic match and scrubber target."}</label>
        <Button disabled={busy || !confirmed || !request || !preview.candidate.dry_run && (Boolean(profiles.error) || !profiles.data.profiles[request?.profile ?? ""]?.armed || !profiles.data.profiles[request?.profile ?? ""]?.ready)} onClick={() => action(async () => {
          if (!request) return
          const result = await createDiversion({ ...request, confirmation: preview.confirmation }, requestScope)
          invalidate(); setMessage(result.dry_run ? "Simulation recorded; no speaker mutation sent." : `Diversion intent recorded: ${result.status}. Router forwarding remains separately qualified.`)
        })}>{preview.candidate.dry_run ? "Record simulation" : "Create diversion"}</Button>
      </div>}
    </CardContent></Card>}
    <Card><CardHeader><CardTitle>Outstanding diversions</CardTitle></CardHeader><CardContent className="space-y-3">
      {diversions.data?.length === 0 && <p className="text-sm text-muted-foreground">No outstanding diversion intent.</p>}
      {diversions.data?.map(row => <div key={row.id} className="space-y-2 rounded-md border p-3 text-sm">
        <p>{row.rule.nlri.dst_prefix} → {describeTarget(row.rule)} · {row.profile.id}@{row.profile.revision}{row.rule.nlri.scope ? ` · VPN${row.rule.nlri.scope.family === "ipv4" ? "v4" : "v6"} RD ${row.rule.nlri.scope.rd} · RT ${(row.rule.route_targets ?? []).join(", ")}` : ""}</p>
        {row.return_rule && <p>Return leg: {describeNlri(row.return_rule.nlri)} → {describeTarget(row.return_rule)} · community {row.return_rule.export_community}</p>}
        <p>{row.status === "active" ? row.return_rule ? "Both legs observed locally" : "Local intent observed" : row.status} · Expires {row.expires_at}</p>
        {row.status === "withdrawing" && <p>Withdrawal stays pending until outstanding authorization has expired and local absence is confirmed{row.return_rule ? " for both legs" : ""}.</p>}
        <ExportEvidence label={row.return_rule ? "Inbound leg peer export" : "Peer export"} observation={row.export_observation} />
        {row.return_rule && <ExportEvidence label="Return leg peer export" observation={row.return_export_observation} />}
        {(row.withdrawal_reason || row.last_error) && <p>{row.withdrawal_reason || row.last_error}</p>}
        <Button variant="outline" disabled={busy || row.status === "withdrawing"} onClick={event => { withdrawTrigger.current = event.currentTarget; setWithdrawError(""); setWithdrawTarget(row) }}>Withdraw {row.rule.nlri.dst_prefix}</Button>
      </div>)}
      <p className="text-xs text-muted-foreground">Local observation and peer export do not prove router installation or scrubber forwarding.</p>
    </CardContent></Card>
    <WithdrawConfirmDialog
      open={!!withdrawTarget}
      onClose={() => { setWithdrawTarget(null); setWithdrawError("") }}
      title="Withdraw diversion"
      description={<>
        Request withdrawal of the diversion matching <span className="font-mono font-semibold">{withdrawTarget && describeMatch(withdrawTarget)}</span>{withdrawTarget?.return_rule ? <> and its return leg <span className="font-mono font-semibold">{describeNlri(withdrawTarget.return_rule.nlri)}</span></> : null} to scrubber target <span className="font-mono font-semibold">{withdrawTarget && describeTarget(withdrawTarget.rule)}</span> via profile <span className="font-mono">{withdrawTarget?.profile.id}@{withdrawTarget?.profile.revision}</span>.
        Withdrawal returns attack traffic to ordinary routing and may expose the victim to the attack again. No automatic discard, blackhole or fallback replaces it. The request and reason are recorded in the audit log.
      </>}
      reasonPlaceholder="e.g., Attack subsided"
      pendingStatus="Waiting for the controller to record the withdrawal..."
      onConfirm={confirmWithdraw}
      error={withdrawError}
      trigger={withdrawTrigger}
      fallback={heading}
    />
  </div>
}

function describeMatch({ rule: { nlri } }: ScrubberDiversion) {
  return describeNlri(nlri)
}

// A return leg has no destination component: it matches any destination.
function describeNlri(nlri: DiversionMatch) {
  const parts = [nlri.dst_prefix ? `dst ${nlri.dst_prefix}` : "destination any"]

  if (nlri.scope) parts.unshift(`VPN${nlri.scope.family === "ipv4" ? "v4" : "v6"} RD ${nlri.scope.rd}`)

  if (nlri.src_prefix) parts.push(`src ${nlri.src_prefix}`)
  parts.push(nlri.protocol === null ? "any protocol" : `protocol ${nlri.protocol}`)

  if (nlri.dst_ports.length) parts.push(`dst ports ${nlri.dst_ports.join(", ")}`)

  if (nlri.src_ports?.length) parts.push(`src ports ${nlri.src_ports.join(", ")}`)

  if (nlri.tcp_flags) parts.push(`flags ${tcpFlagsLabel(nlri.tcp_flags)}`)

  return parts.join(" · ")
}

function describeReturnLeg(leg: ScrubberReturnLeg) {
  return `peers ${leg.router_peers.join(", ")} · community ${leg.export_community} · ${leg.tcp_flags === "syn_ack" ? "SYN+ACK only" : "all TCP from the mirrored ports"}`
}

// Each leg keeps its own evidence; a failed read is historical, never empty.
function ExportEvidence({ label, observation }: { label: string; observation?: DiversionExportObservation | null }) {
  if (!observation) return null

  return <details><summary>{observation.error ? `Historical ${label.toLowerCase()} observation from ${observation.observed_at}; current export unknown (${observation.error})` : `${label} observed since ${observation.observed_at}`}</summary><ul className="mt-2 space-y-1">{observation.peers.map(peer => <li key={peer.peer_address}>{peer.peer_address}: {peer.disposition}{peer.reason ? ` (${peer.reason})` : ""}</li>)}</ul></details>
}

function describeTarget(rule: ScrubberDiversion["rule"]) {
  return rule.redirect_route_target ? `VRF RT ${rule.redirect_route_target}` : rule.target ?? "Target unavailable"
}
