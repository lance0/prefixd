"use client"

import { useEffect, useRef, useState, type ReactNode } from "react"
import useSWR from "swr"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { DISPOSITION_LABEL } from "@/components/dashboard/export-evidence"
import { Field, FieldList } from "@/components/dashboard/field"
import { FlowSpecPreview, tcpFlagsLabel } from "@/components/dashboard/flowspec-preview"
import { PageHeader } from "@/components/dashboard/page-header"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { StatusPill, Tag, type StatusTone } from "@/components/dashboard/status-pill"
import { WithdrawConfirmDialog } from "@/components/dashboard/withdraw-confirm-dialog"
import { useTimeFormat } from "@/components/time-zone-provider"
import { useDiversions } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import { armScrubber, createDiversion, getScrubbers, previewDiversion, withdrawDiversion, type DiversionExportObservation, type DiversionMatch, type DiversionPreview, type DiversionRequest, type DiversionRule, type ScrubberDiversion, type ScrubberProfiles, type ScrubberReturnLeg, type ScrubberState } from "@/lib/api"
import { parseDestination } from "@/lib/destination"
import { formatTimeRemaining } from "@/lib/format"

const DESCRIPTION = "Manual traffic diversion through a configured scrubber. Withdrawal returns traffic to ordinary routing and may expose the victim to the attack again."

interface DiversionForm { profile: string; victim: string; source: string; protocol: string; ports: string; sourcePorts: string; ttl: string; reason: string }

type FormErrors = Partial<Record<keyof DiversionForm, string>>

/** Comma-separated ports, or null when any entry is not a port. */
function parsePorts(input: string): number[] | null {
  if (!input.trim()) return []
  const ports = input.split(",").map(part => part.trim())

  return ports.every(port => /^\d{1,5}$/.test(port) && Number(port) <= 65535) ? ports.map(Number) : null
}

/** Mirrors the controller's diversion checks; the controller re-checks everything and stays authoritative. */
function validateDiversion(form: DiversionForm, profile?: ScrubberProfiles["configuration"][number]): FormErrors {
  const errors: FormErrors = {}
  const victim = parseDestination(form.victim)

  if (!form.profile) errors.profile = "Select a scrubber profile."

  if (!victim) errors.victim = "Enter a host CIDR, for example 203.0.113.10/32 or 2001:db8::10/128."
  else if (!victim.isCidr || victim.prefixLength !== victim.maxLength) errors.victim = `Diversion needs one host. Use ${form.victim.trim().split("/")[0]}/${victim.maxLength}.`

  if (form.source.trim()) {
    const source = parseDestination(form.source)

    if (!source?.isCidr) errors.source = "Enter an IPv4 or IPv6 network in CIDR notation."
    else if (!source.networkAligned) errors.source = `Host bits are set. Use ${source.prefix} to match that network.`
    else if (victim && source.ipv6 !== victim.ipv6) errors.source = "Source prefix must match the victim's address family."
  }

  if (profile?.return_leg && form.protocol === "any") errors.protocol = "This profile's return leg needs a protocol. Choose TCP or UDP."
  else if (profile?.return_leg && form.protocol === "6" && form.source.trim()) errors.source = "A TCP diversion through this profile cannot select a source prefix."

  if (parsePorts(form.ports) === null) errors.ports = "Comma-separated ports, 0-65535."

  if (form.protocol === "17" && parsePorts(form.sourcePorts) === null) errors.sourcePorts = "Comma-separated ports, 0-65535."

  if (!/^\d+$/.test(form.ttl.trim()) || Number(form.ttl) < 1 || Number(form.ttl) > 3600) errors.ttl = "Lifetime must be a whole number from 1 to 3600 seconds. The profile may allow less."

  if (!form.reason.trim()) errors.reason = "A reason is required for the audit log."
  else if (new TextEncoder().encode(form.reason).length > 1024) errors.reason = "Reason must be at most 1024 UTF-8 bytes."

  return errors
}

/** The request for a valid form. Source ports are a UDP-only FlowSpec component. */
function toRequest(form: DiversionForm): DiversionRequest {
  const scope: DiversionRequest["scope"] = { dst_prefix: form.victim.trim(), protocol: form.protocol === "any" ? null : Number(form.protocol), dst_ports: parsePorts(form.ports) ?? [] }

  if (form.source.trim()) scope.src_prefix = form.source.trim()

  const sourcePorts = form.protocol === "17" ? parsePorts(form.sourcePorts) ?? [] : []

  if (sourcePorts.length) scope.src_ports = sourcePorts

  return { profile: form.profile, scope, ttl_seconds: Number(form.ttl), reason: form.reason }
}

// Form order, so an invalid submit focuses the first field with an error.
const FIELD_ORDER: (keyof DiversionForm)[] = ["profile", "victim", "source", "protocol", "ports", "sourcePorts", "ttl", "reason"]

const EMPTY_FORM: DiversionForm = { profile: "", victim: "", source: "", protocol: "6", ports: "", sourcePorts: "", ttl: "60", reason: "" }

export function ScrubbersContent() {
  const permissions = usePermissions()
  const { formatTime } = useTimeFormat()
  const profiles = useSWR("scrubber-profiles", getScrubbers, { refreshInterval: 5000 })
  const diversions = useDiversions()
  const [form, setForm] = useState(EMPTY_FORM)
  const [touched, setTouched] = useState<Set<keyof DiversionForm>>(new Set())
  const [submitted, setSubmitted] = useState(false)
  const [preview, setPreview] = useState<DiversionPreview | null>(null)
  const [request, setRequest] = useState<DiversionRequest | null>(null)
  const [requestScope, setRequestScope] = useState("global")
  const [confirmed, setConfirmed] = useState(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const [error, setError] = useState("")
  const [withdrawTarget, setWithdrawTarget] = useState<ScrubberDiversion | null>(null)
  const [withdrawError, setWithdrawError] = useState("")
  const [now, setNow] = useState(() => Date.now())
  const withdrawTrigger = useRef<HTMLButtonElement | null>(null)
  const listTitle = useRef<HTMLDivElement | null>(null)
  const editVersion = useRef(0)

  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 15_000)

    return () => clearInterval(interval)
  }, [])

  const invalidate = () => { editVersion.current += 1; setPreview(null); setRequest(null); setRequestScope("global"); setConfirmed(false); setMessage("") }

  const update = (field: keyof DiversionForm, value: string) => {
    invalidate()
    setForm(previous => ({ ...previous, [field]: value }))
  }

  // Text fields show errors after blur, not on the first keystroke.
  const touch = (field: keyof DiversionForm) => setTouched(previous => new Set(previous).add(field))

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

  const selectedProfile = profiles.data?.configuration.find(config => config.id === form.profile)
  const errors = validateDiversion(form, selectedProfile)
  const shown = (field: keyof DiversionForm) => submitted || touched.has(field) ? errors[field] : undefined
  const describedBy = (field: keyof DiversionForm) => shown(field) ? `scrub-${field}-error` : undefined
  const fieldError = (field: keyof DiversionForm) => shown(field) ? <p id={`scrub-${field}-error`} className="text-xs text-destructive">{shown(field)}</p> : null

  if (!permissions.settled) return <div className="space-y-6"><PageHeader title="Scrubbers" description={DESCRIPTION} /><Card><LoadingRows label="Loading permissions" /></Card></div>

  // Every role reads diversions; the controller refuses mutations without the Admin role.
  const canMutate = permissions.isAdmin

  // Stale data after a failed refresh is unknown, not current.
  const staleRefresh = (profiles.error && profiles.data) || (diversions.error && diversions.data)

  return <div className="space-y-6">
    <PageHeader title="Scrubbers" description={DESCRIPTION} meta={canMutate ? null : <><Tag>Read-only</Tag><span className="text-muted-foreground">Re-arm, preview, creation and withdrawal require an administrator.</span></>} />
    {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
    {staleRefresh && <p role="alert" className="text-sm text-destructive">Scrubber observations could not be refreshed. Current state is unknown.</p>}
    {message && <p role="status" className="text-sm">{message}</p>}

    <section aria-label="Scrubber profiles" className="space-y-4">
      {!profiles.data && !profiles.error && <Card><LoadingRows label="Loading scrubber profiles" rows={2} /></Card>}
      {!profiles.data && profiles.error && <Card><ErrorState title="Unable to load scrubber profiles" detail="Profile readiness and arm state are unknown." onRetry={() => { void profiles.mutate() }} /></Card>}
      {profiles.data?.enabled === false && <Card><EmptyState title="Scrubber diversion is disabled." description="Enable qualified profiles in the controller configuration." /></Card>}
      {profiles.data?.configuration.map(config => {
        const state = profiles.error ? undefined : profiles.data?.profiles[config.id]

        return <Card key={config.id}>
          <CardHeader className="flex flex-wrap items-center justify-between gap-2">
            <CardTitle className="flex flex-wrap items-center gap-2"><span className="font-mono">{config.id}</span><Tag>{config.revision}</Tag></CardTitle>
            <div className="flex flex-wrap items-center gap-2"><ReadinessPill state={state} /><ArmPill state={state} /></div>
          </CardHeader>
          <CardContent className="space-y-4">
            <FieldList>
              <Field label="Target">{config.redirect_route_target ? <span className="font-mono">VRF RT {config.redirect_route_target}</span> : <span className="font-mono">{config.ipv4_target ?? "IPv4 unavailable"} · {config.ipv6_target ?? "IPv6 unavailable"}</span>}</Field>
              {config.scope && config.scope !== "global" ? <Field label="Routing scope"><span className="font-mono">{config.scope}</span></Field> : null}
              <Field label="Direction">{config.return_leg ? `Return leg for TCP: ${describeReturnLeg(config.return_leg)}` : "Inbound direction only"}</Field>
              {state?.observed_at ? <Field label="Readiness observed"><time dateTime={state.observed_at}>{formatTime(state.observed_at, now)}</time></Field> : null}
            </FieldList>
            {state?.latch_reason && <p className="text-sm text-muted-foreground">{state.latch_reason}</p>}
            {canMutate && <Button variant="outline" size="sm" disabled={busy || !profiles.data?.enabled || !state?.ready || state?.armed} onClick={() => action(async () => { await armScrubber(config.id, config.revision); setMessage(`Profile ${config.id} re-armed. New intent requires a separate confirmation.`) })}>Re-arm {config.id}</Button>}
          </CardContent>
        </Card>
      })}
    </section>

    {canMutate && profiles.data?.enabled && <Card><CardHeader><CardTitle>New diversion</CardTitle></CardHeader><CardContent>
      <form noValidate className="grid gap-4 sm:grid-cols-2" onSubmit={event => {
        event.preventDefault()
        setSubmitted(true)
        const invalid = FIELD_ORDER.find(field => errors[field])

        if (invalid) {
          document.getElementById(`scrub-${invalid}`)?.focus()

          return
        }

        action(async () => {
          const next = toRequest(form)
          const expectedScope = selectedProfile?.scope ?? "global"
          const version = editVersion.current
          const result = await previewDiversion(next, expectedScope)

          if (version !== editVersion.current) return
          setRequest(next); setRequestScope(expectedScope); setPreview(result); setConfirmed(false)
        })
      }}>
        <div className="space-y-1.5">
          <Label htmlFor="scrub-profile">Profile</Label>
          <Select value={form.profile} onValueChange={value => { update("profile", value); touch("profile") }}>
            <SelectTrigger id="scrub-profile" className="w-full" aria-required="true" aria-invalid={Boolean(shown("profile"))} aria-describedby={describedBy("profile")}><SelectValue placeholder="Select profile" /></SelectTrigger>
            <SelectContent>{profiles.data.configuration.map(config => <SelectItem key={config.id} value={config.id}>{config.id}</SelectItem>)}</SelectContent>
          </Select>
          {fieldError("profile")}
          {selectedProfile?.scope && selectedProfile.scope !== "global" ? <p className="text-xs text-muted-foreground">Requested routing scope: {selectedProfile.scope}</p> : null}
          {selectedProfile?.return_leg ? <p className="text-xs text-muted-foreground">A TCP diversion through this profile adds a return leg. Any-protocol and source-selected TCP requests are refused.</p> : null}
        </div>
        <TextField id="victim" label="Victim host CIDR" required placeholder="203.0.113.10/32" form={form} update={update} touch={touch} shown={shown} describedBy={describedBy} fieldError={fieldError} />
        <TextField id="source" label="Source prefix (optional)" form={form} update={update} touch={touch} shown={shown} describedBy={describedBy} fieldError={fieldError} />
        <div className="space-y-1.5">
          <Label htmlFor="scrub-protocol">Protocol</Label>
          <Select value={form.protocol} onValueChange={value => { update("protocol", value); touch("protocol") }}>
            <SelectTrigger id="scrub-protocol" className="w-full" aria-invalid={Boolean(shown("protocol"))} aria-describedby={describedBy("protocol")}><SelectValue /></SelectTrigger>
            <SelectContent><SelectItem value="6">TCP</SelectItem><SelectItem value="17">UDP</SelectItem><SelectItem value="any">Any</SelectItem></SelectContent>
          </Select>
          {fieldError("protocol")}
        </div>
        <TextField id="ports" label="Destination ports (optional)" placeholder="80, 443" form={form} update={update} touch={touch} shown={shown} describedBy={describedBy} fieldError={fieldError} />
        {form.protocol === "17" && <TextField id="sourcePorts" label="Source ports (optional)" placeholder="53, 123" form={form} update={update} touch={touch} shown={shown} describedBy={describedBy} fieldError={fieldError} />}
        <TextField id="ttl" label="Lifetime in seconds" required inputMode="numeric" form={form} update={update} touch={touch} shown={shown} describedBy={describedBy} fieldError={fieldError} />
        <TextField id="reason" label="Reason" required form={form} update={update} touch={touch} shown={shown} describedBy={describedBy} fieldError={fieldError} />
        <div className="sm:col-span-2"><Button type="submit" disabled={busy}>Preview diversion</Button></div>
      </form>
      {preview && <div className="mt-4 space-y-3 rounded-md border p-4 text-sm">
        <p>{preview.candidate.dry_run ? "Simulation only" : "Proposed diversion"}: <span className="font-mono">{describeRow(preview.candidate)}</span></p>
        {requestScope !== "global" ? <p>Confirmed routing scope: {requestScope}</p> : null}
        <RulePreview rule={preview.candidate.rule} scopeName={preview.candidate.profile.scope} />
        {preview.candidate.return_rule && <div className="space-y-2">
          <p>Return leg: {describeNlri(preview.candidate.return_rule.nlri)} → {describeTarget(preview.candidate.return_rule)} · community {preview.candidate.return_rule.export_community} · peers {(preview.candidate.profile.return_leg?.router_peers ?? []).join(", ")}</p>
          <RulePreview rule={preview.candidate.return_rule} scopeName={preview.candidate.profile.scope} />
          <p className="text-muted-foreground">The return leg selects the victim&apos;s responses to any destination. Both legs are confirmed, added, renewed and withdrawn together.</p>
        </div>}
        <p className="text-muted-foreground">{preview.evidence}</p>
        <div className="flex items-center gap-2">
          <Checkbox id="scrub-confirm" checked={confirmed} onCheckedChange={checked => setConfirmed(checked === true)} />
          <Label htmlFor="scrub-confirm" className="font-normal">{preview.candidate.return_rule ? "I confirm both legs' traffic matches and the scrubber target." : "I confirm this traffic match and scrubber target."}</Label>
        </div>
        <Button disabled={busy || !confirmed || !request || !preview.candidate.dry_run && (Boolean(profiles.error) || !profiles.data.profiles[request?.profile ?? ""]?.armed || !profiles.data.profiles[request?.profile ?? ""]?.ready)} onClick={() => action(async () => {
          if (!request) return
          const result = await createDiversion({ ...request, confirmation: preview.confirmation }, requestScope)
          invalidate(); setMessage(result.dry_run ? "Simulation recorded; no speaker mutation sent." : `Diversion intent recorded: ${result.status}. Router forwarding remains separately qualified.`)
        })}>{preview.candidate.dry_run ? "Record simulation" : "Create diversion"}</Button>
      </div>}
    </CardContent></Card>}

    <Card>
      <CardHeader><CardTitle ref={listTitle} tabIndex={-1} className="outline-none">Outstanding diversions</CardTitle></CardHeader>
      <CardContent className="space-y-3">
        {!diversions.data && !diversions.error && <LoadingRows label="Loading diversions" />}
        {!diversions.data && diversions.error && <ErrorState title="Unable to load diversions" detail="Outstanding diversion intent is unknown, not empty." onRetry={() => { void diversions.mutate() }} />}
        {diversions.data?.length === 0 && <EmptyState title="No outstanding diversion intent." />}
        {diversions.data?.map(row => {
          const expired = Date.parse(row.expires_at) <= now

          return <div key={row.id} id={`diversion-${row.id}`} className="scroll-mt-20 space-y-3 rounded-md border p-3 text-sm">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <p className="min-w-0 break-words font-mono">{describeRow(row)}</p>
              <DiversionStatusPill row={row} stale={Boolean(diversions.error)} />
            </div>
            {row.return_rule && <p>Return leg: {describeNlri(row.return_rule.nlri)} → {describeTarget(row.return_rule)} · community {row.return_rule.export_community}</p>}
            <p className="text-muted-foreground tabular-nums">
              {row.status === "active" ? `${diversions.error ? "At the last read: " : ""}${row.return_rule ? "Both legs observed locally" : "Local intent observed"}` : null}
              {row.status === "active" ? " · " : null}
              {expired
                ? <>Expired <time dateTime={row.expires_at}>{formatTime(row.expires_at, now)}</time></>
                : <>Expires in <span className="font-medium text-foreground">{formatTimeRemaining(row.expires_at, now)}</span> · <time dateTime={row.expires_at}>{formatTime(row.expires_at, now)}</time></>}
            </p>
            {row.status === "withdrawing" && <p>Withdrawal stays pending until outstanding authorization has expired and local absence is confirmed{row.return_rule ? " for both legs" : ""}.</p>}
            <ExportEvidence label={row.return_rule ? "Inbound leg peer export" : "Peer export"} observation={row.export_observation} now={now} refreshFailed={Boolean(diversions.error)} />
            {row.return_rule && <ExportEvidence label="Return leg peer export" observation={row.return_export_observation} now={now} refreshFailed={Boolean(diversions.error)} />}
            {(row.withdrawal_reason || row.last_error) && <p>{row.withdrawal_reason || row.last_error}</p>}
            {canMutate && <Button variant="outline" size="sm" disabled={busy || row.status === "withdrawing"} onClick={event => { withdrawTrigger.current = event.currentTarget; setWithdrawError(""); setWithdrawTarget(row) }}>Withdraw {row.rule.nlri.dst_prefix}</Button>}
          </div>
        })}
        <p className="text-xs text-muted-foreground">Local observation and peer export do not prove router installation or scrubber forwarding.</p>
      </CardContent>
    </Card>
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
      fallback={listTitle}
    />
  </div>
}

interface TextFieldProps {
  id: keyof DiversionForm
  label: string
  required?: boolean
  placeholder?: string
  inputMode?: "numeric"
  form: DiversionForm
  update: (field: keyof DiversionForm, value: string) => void
  touch: (field: keyof DiversionForm) => void
  shown: (field: keyof DiversionForm) => string | undefined
  describedBy: (field: keyof DiversionForm) => string | undefined
  fieldError: (field: keyof DiversionForm) => ReactNode
}

function TextField({ id, label, required, placeholder, inputMode, form, update, touch, shown, describedBy, fieldError }: TextFieldProps) {
  return <div className="space-y-1.5">
    <Label htmlFor={`scrub-${id}`}>{label}</Label>
    <Input id={`scrub-${id}`} required={required} placeholder={placeholder} inputMode={inputMode} value={form[id]} onChange={event => update(id, event.target.value)} onBlur={() => touch(id)} aria-invalid={Boolean(shown(id))} aria-describedby={describedBy(id)} className={id === "reason" ? undefined : "font-mono"} />
    {fieldError(id)}
  </div>
}

function ReadinessPill({ state }: { state?: ScrubberState }) {
  if (state?.ready) return <StatusPill tone="success">Fresh readiness</StatusPill>

  if (state?.readiness === "not_ready") return <StatusPill tone="danger">Not ready</StatusPill>

  return <StatusPill tone="neutral">Readiness unknown</StatusPill>
}

function ArmPill({ state }: { state?: ScrubberState }) {
  if (!state) return <StatusPill tone="neutral">Arm state unknown</StatusPill>

  return state.armed ? <StatusPill tone="success">Armed</StatusPill> : <StatusPill tone="warning">Unarmed</StatusPill>
}

const DIVERSION_STATUS: Record<ScrubberDiversion["status"], { label: string; tone: StatusTone }> = {
  active: { label: "Active", tone: "success" },
  pending: { label: "Pending", tone: "warning" },
  withdrawing: { label: "Withdrawing", tone: "warning" },
  withdrawn: { label: "Withdrawn", tone: "neutral" },
  simulated: { label: "Simulation", tone: "neutral" },
}

/** A row retained after a failed refresh keeps its last label but loses its status color. */
function DiversionStatusPill({ row, stale }: { row: ScrubberDiversion; stale: boolean }) {
  const status = DIVERSION_STATUS[row.status] ?? { label: row.status, tone: "neutral" }

  return <StatusPill tone={stale ? "neutral" : status.tone}>{status.label}</StatusPill>
}

/** One FlowSpec rule, rendered as the speaker-neutral rule text used elsewhere in the dashboard. */
function RulePreview({ rule, scopeName }: { rule: DiversionRule; scopeName?: string }) {
  const { nlri } = rule

  return <div className="overflow-hidden rounded-md border">
    <FlowSpecPreview
      dst_prefix={nlri.dst_prefix}
      vpn_scope={nlri.scope ? { name: scopeName ?? "", identity: nlri.scope, route_targets: rule.route_targets ?? [] } : null}
      src_prefix={nlri.src_prefix}
      protocol={nlri.protocol}
      dst_ports={nlri.dst_ports}
      src_ports={nlri.src_ports}
      tcp_flags={nlri.tcp_flags}
      action_type="redirect"
      redirect_target={describeTarget(rule)}
      rate_bps={null}
    />
  </div>
}

function describeRow(row: ScrubberDiversion) {
  const scope = row.rule.nlri.scope ? ` · VPN${row.rule.nlri.scope.family === "ipv4" ? "v4" : "v6"} RD ${row.rule.nlri.scope.rd} · RT ${(row.rule.route_targets ?? []).join(", ")}` : ""

  return `${row.rule.nlri.dst_prefix} → ${describeTarget(row.rule)} · ${row.profile.id}@${row.profile.revision}${scope}`
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

// Each leg keeps its own evidence; a failed read, or a failed refresh of the rows, is historical, never empty or current.
function ExportEvidence({ label, observation, now, refreshFailed }: { label: string; observation?: DiversionExportObservation | null; now: number; refreshFailed: boolean }) {
  const { formatTime } = useTimeFormat()

  if (!observation) return <div className="space-y-1"><p className="font-medium">{label}</p><p className="text-muted-foreground">Not observed yet.</p></div>
  const historical = Boolean(observation.error) || refreshFailed
  const observed = <time dateTime={observation.observed_at}>{formatTime(observation.observed_at, now)}</time>

  return <div className="space-y-2">
    <div className="flex flex-wrap items-center gap-2">
      <p className="font-medium">{label}</p>
      {historical ? <StatusPill tone="warning">Export unknown</StatusPill> : null}
    </div>
    {historical
      ? <p role="status" className="text-muted-foreground">Historical observation from {observed}. Current export is unknown: {observation.error || "the diversions refresh failed"}</p>
      : <p className="text-muted-foreground">Observed since {observed}</p>}
    {observation.peers.length === 0
      ? <p className="text-muted-foreground">{observation.error ? "No peers from a successful export observation are retained." : historical ? "The retained observation listed no peers." : "The last complete observation listed no peers."}</p>
      : <div className="overflow-x-auto rounded-md border">
        <Table aria-label={label}>
          <TableHeader><TableRow className="hover:bg-transparent"><TableHead>Peer</TableHead><TableHead>{historical ? "Export at observation" : "Export"}</TableHead><TableHead>Reason</TableHead></TableRow></TableHeader>
          <TableBody>
            {observation.peers.map(peer => {
              const disposition = DISPOSITION_LABEL[peer.disposition] ?? { label: peer.disposition, tone: "neutral" as const }

              return <TableRow key={peer.peer_address}>
                <TableCell className="font-mono">{peer.peer_address}</TableCell>
                <TableCell><StatusPill tone={historical ? "neutral" : disposition.tone}>{disposition.label}</StatusPill></TableCell>
                <TableCell className="font-mono">{peer.reason || "—"}</TableCell>
              </TableRow>
            })}
          </TableBody>
        </Table>
      </div>}
  </div>
}

function describeTarget(rule: DiversionRule) {
  return rule.redirect_route_target ? `VRF RT ${rule.redirect_route_target}` : rule.target ?? "Target unavailable"
}
