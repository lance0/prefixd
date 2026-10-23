"use client"

import { useState, type FormEvent } from "react"
import { useRouter } from "next/navigation"
import { RefreshCw, ShieldPlus } from "lucide-react"
import { toast } from "sonner"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useConfigSettings } from "@/hooks/use-api"
import { createMitigation, type CreateFlowSpecRequest, type JsonValue } from "@/lib/api"
import { parseDestination } from "@/lib/destination"
import { formatFlowSpecRule } from "./flowspec-preview"

const PROTOCOLS = ["udp", "tcp", "icmp", "icmpv6", "any"] as const
const DEFAULT_TTL_SECONDS = "300"

export interface RuleForm {
  victimIp: string
  protocol: string
  action: "discard" | "police"
  rateBps: string
  dstPorts: string
  srcPrefix: string
  srcPorts: string
  nonFirstFragments: boolean
  lengthMin: string
  lengthMax: string
  ttl: string
  reason: string
}

/** The guardrails this form checks before the controller does; absent settings skip the opt-ins. */
export interface RuleGuardrails {
  maxPorts: number
  dstPrefixMinlen?: number
  dstPrefixMaxlen?: number
  dstPrefixMinlenV6?: number
  dstPrefixMaxlenV6?: number
  allowSrcPrefixMatch?: boolean
  allowFragmentMatch?: boolean
  allowPacketLengthMatch?: boolean
}

export type RuleErrors = Partial<Record<keyof RuleForm, string>>

const EMPTY_FORM: RuleForm = {
  victimIp: "",
  protocol: "udp",
  action: "discard",
  rateBps: "",
  dstPorts: "",
  srcPrefix: "",
  srcPorts: "",
  nonFirstFragments: false,
  lengthMin: "",
  lengthMax: "",
  ttl: DEFAULT_TTL_SECONDS,
  reason: "",
}

function isIPv4(ip: string): boolean {
  const parts = ip.split(".")

  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
}

function isIPv6(ip: string): boolean {
  return ip.includes(":") && /^[0-9a-fA-F:.]+$/.test(ip)
}

/** Comma-separated u16 ports, or null when any entry is not one. */
function parsePorts(input: string): number[] | null {
  if (!input.trim()) return []
  const ports = input.split(",").map((part) => part.trim())

  return ports.every((port) => /^\d{1,5}$/.test(port) && Number(port) <= 65535) ? ports.map(Number) : null
}

function parseBound(input: string): number | null {
  return /^\d{1,5}$/.test(input.trim()) && Number(input) <= 65535 ? Number(input) : null
}

/**
 * Mirrors the controller's checks for a manual FlowSpec rule (ADR 028), naming the invariant
 * or guardrail each error comes from. The controller re-checks everything and stays authoritative.
 */
export function validateRule(form: RuleForm, guardrails: RuleGuardrails): RuleErrors {
  const errors: RuleErrors = {}
  const destination = parseDestination(form.victimIp)
  const v4 = destination !== null && !destination.ipv6
  const v6 = destination?.ipv6 === true

  if (!destination) {
    errors.victimIp = "Enter an IPv4 or IPv6 address, or a network in CIDR notation."
  } else if (!destination.networkAligned) {
    errors.victimIp = `Host bits are set. Use ${destination.prefix} if you intend to match that entire network.`
  } else {
    const min = v6 ? guardrails.dstPrefixMinlenV6 : guardrails.dstPrefixMinlen
    const max = v6 ? guardrails.dstPrefixMaxlenV6 : guardrails.dstPrefixMaxlen
    const key = v6 ? "dst_prefix_minlen_v6" : "dst_prefix_minlen"

    if (min !== undefined && destination.prefixLength < min) {
      errors.victimIp = `Destination is broader than allowed (guardrails.${key}=${min}).`
    } else if (max !== undefined && destination.prefixLength > max) {
      errors.victimIp = `Destination is narrower than allowed (guardrails.${v6 ? "dst_prefix_maxlen_v6" : "dst_prefix_maxlen"}=${max}).`
    }
  }

  const source = form.srcPrefix.trim()

  if (source) {
    const [address, length, extra] = source.split("/")
    const sourceV4 = isIPv4(address)
    let sourceV6 = false

    if (isIPv6(address)) {
      try {
        sourceV6 = new URL(`http://[${address}]/`).hostname.startsWith("[")
      } catch {
        sourceV6 = false
      }
    }

    if (extra !== undefined || !/^\d{1,3}$/.test(length ?? "") ||
      !(sourceV4 || sourceV6) || Number(length) > (sourceV6 ? 128 : 32)) {
      errors.srcPrefix = "Enter an IPv4 or IPv6 network in CIDR notation."
    } else if ((v4 && !sourceV4) || (v6 && !sourceV6)) {
      errors.srcPrefix = "Source prefix must match the destination's address family."
    } else if (guardrails.allowSrcPrefixMatch === false) {
      errors.srcPrefix = "Source prefix matching is off (guardrails.allow_src_prefix_match=false)."
    }
  }

  if ((form.protocol === "icmp" && v6) || (form.protocol === "icmpv6" && v4)) {
    errors.protocol = "Protocol does not match the destination's address family."
  }

  const rate = Number(form.rateBps)

  if (form.action === "police" && !(Number.isInteger(rate) && rate > 0)) {
    errors.rateBps = "Police needs a positive rate in bps."
  }

  const dstPorts = parsePorts(form.dstPorts)

  if (dstPorts === null) {
    errors.dstPorts = "Comma-separated ports, 0-65535."
  } else if (dstPorts.length > guardrails.maxPorts) {
    errors.dstPorts = `Too many ports: ${dstPorts.length} (guardrails.max_ports=${guardrails.maxPorts}).`
  }

  const srcPorts = parsePorts(form.srcPorts)
  const hasSrc = srcPorts !== null && srcPorts.length > 0
  const hasLength = form.lengthMin.trim() !== "" || form.lengthMax.trim() !== ""
  const narrowed = hasSrc || form.nonFirstFragments || hasLength

  if (srcPorts === null) {
    errors.srcPorts = "Comma-separated ports, 0-65535."
  } else if (new Set(srcPorts).size > guardrails.maxPorts) {
    errors.srcPorts = `Too many source ports: ${new Set(srcPorts).size} (guardrails.max_ports=${guardrails.maxPorts}).`
  }

  if (narrowed && form.protocol !== "udp") {
    errors.protocol = "Source ports, fragments and packet length require protocol UDP."
  }

  if (form.nonFirstFragments) {
    if (hasSrc) {
      errors.nonFirstFragments = "Source ports and fragment cannot share a rule: ports never match a non-first fragment."
    } else if (guardrails.allowFragmentMatch === false) {
      errors.nonFirstFragments = "Fragment matching is off (guardrails.allow_fragment_match=false)."
    }
  }

  if (hasLength) {
    const min = parseBound(form.lengthMin)
    const max = parseBound(form.lengthMax)
    const floor = v6 ? 48 : 28

    if (!hasSrc) {
      errors.lengthMin = "Packet length requires source ports."
    } else if (min === null || max === null || min <= floor || min > max) {
      errors.lengthMin = `Packet length needs min above ${floor} (IP plus UDP header) and min ≤ max ≤ 65535.`
    } else if (guardrails.allowPacketLengthMatch === false) {
      errors.lengthMin = "Packet length matching is off (guardrails.allow_packet_length_match=false)."
    }
  }

  const ttl = Number(form.ttl)

  if (!Number.isInteger(ttl) || ttl <= 0) errors.ttl = "TTL must be a positive whole number of seconds."

  if (!form.reason.trim()) errors.reason = "A reason is required for the audit log."

  return errors
}

/** The request body for a valid form; optional components are sent only when set. */
export function toRequest(form: RuleForm): CreateFlowSpecRequest {
  const request: CreateFlowSpecRequest = {
    victim_ip: form.victimIp.trim(),
    protocol: form.protocol,
    action: form.action,
    ttl_seconds: Number(form.ttl),
    reason: form.reason,
  }

  const dstPorts = parsePorts(form.dstPorts) ?? []
  const srcPorts = parsePorts(form.srcPorts) ?? []

  if (form.action === "police") request.rate_bps = Number(form.rateBps)

  if (dstPorts.length > 0) request.dst_ports = dstPorts

  if (form.srcPrefix.trim()) request.src_prefix = form.srcPrefix.trim()

  if (srcPorts.length > 0) request.src_ports = srcPorts

  if (form.nonFirstFragments) request.fragment = "non_first"

  if (form.lengthMin.trim() || form.lengthMax.trim()) {
    request.packet_length = { min: Number(form.lengthMin), max: Number(form.lengthMax) }
  }

  return request
}

function readGuardrails(settings: { [key: string]: JsonValue } | undefined): RuleGuardrails {
  const value = settings?.guardrails
  const loaded = value instanceof Object && !Array.isArray(value)
  const guardrails: { [key: string]: JsonValue } = loaded ? value : {}
  const maxPorts = Number(guardrails.max_ports)
  const flag = (key: string) => (guardrails[key] === true ? true : guardrails[key] === false ? false : undefined)

  const prefixBound = (key: string, maximum: 32 | 128, fallback?: number) => {
    const input = guardrails[key]
    const value = Number(input)

    return Number.isInteger(input) && value >= 0 && value <= maximum ? value : fallback
  }

  return {
    maxPorts: Number.isInteger(maxPorts) && maxPorts > 0 ? maxPorts : 5,
    dstPrefixMinlen: prefixBound("dst_prefix_minlen", 32),
    dstPrefixMaxlen: prefixBound("dst_prefix_maxlen", 32),
    dstPrefixMinlenV6: prefixBound("dst_prefix_minlen_v6", 128, loaded ? 128 : undefined),
    dstPrefixMaxlenV6: prefixBound("dst_prefix_maxlen_v6", 128, loaded ? 128 : undefined),
    allowSrcPrefixMatch: flag("allow_src_prefix_match"),
    allowFragmentMatch: flag("allow_fragment_match"),
    allowPacketLengthMatch: flag("allow_packet_length_match"),
  }
}

function previewProtocol(protocol: string): number | null {
  switch (protocol) {
    case "udp": return 17
    case "tcp": return 6
    case "icmp": return 1
    case "icmpv6": return 58
    default: return null
  }
}

interface FlowSpecRuleDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/**
 * Manual FlowSpec rule (POST /v1/mitigations), including the ADR 028 source-port, fragment
 * and packet-length matches. Errors appear once a field is edited or submission is attempted.
 */
export function FlowSpecRuleDialog({ open, onOpenChange }: FlowSpecRuleDialogProps) {
  const router = useRouter()
  const { data: settings } = useConfigSettings()
  const [form, setForm] = useState<RuleForm>(EMPTY_FORM)
  const [touched, setTouched] = useState<Set<keyof RuleForm>>(new Set())
  const [submitted, setSubmitted] = useState(false)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const errors = validateRule(form, readGuardrails(settings?.settings))
  const isValid = Object.keys(errors).length === 0
  const destination = parseDestination(form.victimIp)
  const request = toRequest(form)
  const matchValid = !Object.keys(errors).some((field) => field !== "reason" && field !== "ttl")

  const preview = destination?.networkAligned && matchValid ? formatFlowSpecRule({
    dst_prefix: destination.prefix,
    src_prefix: request.src_prefix ? parseDestination(request.src_prefix)?.prefix : undefined,
    protocol: previewProtocol(form.protocol),
    dst_ports: request.dst_ports ?? [],
    src_ports: request.src_ports,
    fragment: request.fragment,
    packet_length: request.packet_length,
    action_type: form.action,
    rate_bps: form.action === "police" ? Number(form.rateBps) : null,
  }) : null

  const shown = (field: keyof RuleForm) => (submitted || touched.has(field) ? errors[field] : undefined)

  const update = <K extends keyof RuleForm>(field: K, value: RuleForm[K]) => {
    setForm((prev) => ({ ...prev, [field]: value }))
    setTouched((prev) => new Set(prev).add(field))
  }

  const reset = () => {
    setForm(EMPTY_FORM)
    setTouched(new Set())
    setSubmitted(false)
    setError(null)
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    setSubmitted(true)

    if (!isValid || isSubmitting) return
    setIsSubmitting(true)
    setError(null)

    try {
      const mitigation = await createMitigation(toRequest(form))

      if (mitigation.announcement_outcome === "unconfirmed") {
        toast.warning("Rule intent saved; announcement unconfirmed", {
          description: "Intent is saved for reconciliation. Check speaker state and mitigation details.",
        })
      } else {
        toast.success("Rule created", { description: form.victimIp })
      }

      reset()
      onOpenChange(false)
      router.push(`/mitigations/${mitigation.mitigation_id}`)
    } catch (e) {
      // The controller's reason, verbatim: it names the guardrail that refused the rule.
      setError(e instanceof Error ? e.message : "Failed to create rule")
    } finally {
      setIsSubmitting(false)
    }
  }

  const fieldError = (field: keyof RuleForm, id: string) => {
    const message = shown(field)

    return message ? <p id={`${id}-error`} className="text-xs text-destructive">{message}</p> : null
  }

  const describedBy = (field: keyof RuleForm, id: string) => (shown(field) ? `${id}-error` : undefined)

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (isSubmitting) return
        onOpenChange(next)

        if (!next) reset()
      }}
    >
      <DialogContent className="max-h-[90dvh] overflow-y-auto bg-card sm:max-w-lg">
        <form onSubmit={handleSubmit} noValidate className="grid gap-4">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-sm">
              <ShieldPlus className="size-4 text-muted-foreground" aria-hidden="true" />
              Create FlowSpec rule
            </DialogTitle>
            <DialogDescription className="text-xs">
              Define the traffic to discard or police. The controller checks ownership, safelists
              and deployment guardrails before saving intent.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-1.5">
            <Label htmlFor="fs-ip">Destination IP or CIDR</Label>
            <Input
              id="fs-ip"
              placeholder="203.0.113.10 or 203.0.112.0/22"
              value={form.victimIp}
              onChange={(e) => update("victimIp", e.target.value)}
              aria-invalid={Boolean(shown("victimIp"))}
              aria-describedby={["fs-ip-help", describedBy("victimIp", "fs-ip")].filter(Boolean).join(" ")}
              className="h-9 font-mono"
              spellCheck={false}
              autoComplete="off"
            />
            <p id="fs-ip-help" className="text-xs text-muted-foreground">
              Subnets require explicitly relaxed prefix bounds and one configured customer prefix covering the entire range.
            </p>
            {fieldError("victimIp", "fs-ip")}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="fs-src-prefix">Source prefix (optional)</Label>
            <Input
              id="fs-src-prefix"
              placeholder="e.g. 198.51.100.0/24"
              value={form.srcPrefix}
              onChange={(e) => update("srcPrefix", e.target.value)}
              aria-invalid={Boolean(shown("srcPrefix"))}
              aria-describedby={["fs-src-prefix-help", describedBy("srcPrefix", "fs-src-prefix")].filter(Boolean).join(" ")}
              className="h-9 font-mono"
              spellCheck={false}
              autoComplete="off"
            />
            <p id="fs-src-prefix-help" className="text-xs text-muted-foreground">
              Limits which sources match this destination. Requires source prefix matching to be enabled.
            </p>
            {fieldError("srcPrefix", "fs-src-prefix")}
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div className="space-y-1.5">
              <Label htmlFor="fs-protocol">Protocol</Label>
              <Select value={form.protocol} onValueChange={(value) => update("protocol", value)}>
                <SelectTrigger id="fs-protocol" className="h-9" aria-describedby={describedBy("protocol", "fs-protocol")}>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PROTOCOLS.map((protocol) => (
                    <SelectItem key={protocol} value={protocol}>{protocol}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="fs-action">Action</Label>
              <Select value={form.action} onValueChange={(value) => { if (value === "discard" || value === "police") update("action", value) }}>
                <SelectTrigger id="fs-action" className="h-9">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="discard">discard</SelectItem>
                  <SelectItem value="police">police</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {form.action === "police" && (
              <div className="space-y-1.5">
                <Label htmlFor="fs-rate">Rate (bps)</Label>
                <Input
                  id="fs-rate"
                  inputMode="numeric"
                  value={form.rateBps}
                  onChange={(e) => update("rateBps", e.target.value)}
                  aria-invalid={Boolean(shown("rateBps"))}
                  aria-describedby={describedBy("rateBps", "fs-rate")}
                  className="h-9 font-mono tabular-nums"
                />
              </div>
            )}
          </div>
          {fieldError("protocol", "fs-protocol")}
          {fieldError("rateBps", "fs-rate")}

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label htmlFor="fs-dst">Destination ports</Label>
              <Input
                id="fs-dst"
                placeholder="any"
                value={form.dstPorts}
                onChange={(e) => update("dstPorts", e.target.value)}
                aria-invalid={Boolean(shown("dstPorts"))}
                aria-describedby={describedBy("dstPorts", "fs-dst")}
                className="h-9 font-mono"
              />
              {fieldError("dstPorts", "fs-dst")}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="fs-src">Source ports</Label>
              <Input
                id="fs-src"
                placeholder="e.g. 123, 389"
                value={form.srcPorts}
                onChange={(e) => update("srcPorts", e.target.value)}
                aria-invalid={Boolean(shown("srcPorts"))}
                aria-describedby={describedBy("srcPorts", "fs-src")}
                className="h-9 font-mono"
              />
              {fieldError("srcPorts", "fs-src")}
            </div>
          </div>

          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <Checkbox
                id="fs-fragment"
                checked={form.nonFirstFragments}
                onCheckedChange={(checked) => update("nonFirstFragments", checked === true)}
                aria-describedby={describedBy("nonFirstFragments", "fs-fragment")}
              />
              <Label htmlFor="fs-fragment">Match non-first fragments only</Label>
            </div>
            {fieldError("nonFirstFragments", "fs-fragment")}
          </div>

          <fieldset className="space-y-1.5">
            <legend className="text-sm font-medium">Packet length (bytes, with source ports)</legend>
            <div className="grid grid-cols-2 gap-3">
              <Input
                id="fs-length-min"
                aria-label="Minimum packet length"
                placeholder="min"
                inputMode="numeric"
                value={form.lengthMin}
                onChange={(e) => update("lengthMin", e.target.value)}
                aria-invalid={Boolean(shown("lengthMin"))}
                aria-describedby={describedBy("lengthMin", "fs-length")}
                className="h-9 font-mono tabular-nums"
              />
              <Input
                id="fs-length-max"
                aria-label="Maximum packet length"
                placeholder="max"
                inputMode="numeric"
                value={form.lengthMax}
                onChange={(e) => update("lengthMax", e.target.value)}
                aria-invalid={Boolean(shown("lengthMin"))}
                aria-describedby={describedBy("lengthMin", "fs-length")}
                className="h-9 font-mono tabular-nums"
              />
            </div>
            {fieldError("lengthMin", "fs-length")}
          </fieldset>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-[8rem_1fr]">
            <div className="space-y-1.5">
              <Label htmlFor="fs-ttl">TTL (seconds)</Label>
              <Input
                id="fs-ttl"
                inputMode="numeric"
                value={form.ttl}
                onChange={(e) => update("ttl", e.target.value)}
                aria-invalid={Boolean(shown("ttl"))}
                aria-describedby={describedBy("ttl", "fs-ttl")}
                className="h-9 font-mono tabular-nums"
              />
              {fieldError("ttl", "fs-ttl")}
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="fs-reason">Reason</Label>
              <Input
                id="fs-reason"
                placeholder="e.g., NTP reflection toward the victim"
                value={form.reason}
                onChange={(e) => update("reason", e.target.value)}
                aria-invalid={Boolean(shown("reason"))}
                aria-describedby={describedBy("reason", "fs-reason")}
                className="h-9"
              />
              {fieldError("reason", "fs-reason")}
            </div>
          </div>

          <section aria-labelledby="fs-preview-title" className="rounded-md border bg-muted/30 p-3">
            <h3 id="fs-preview-title" className="text-xs font-semibold">Rule preview</h3>
            <p className="mt-2 break-words font-mono text-xs" aria-live="polite">
              {preview ?? "Complete the match fields to preview the rule."}
            </p>
            <p className="mt-2 text-xs text-muted-foreground">
              {Number.isInteger(Number(form.ttl)) && Number(form.ttl) > 0
                ? `Requested lifetime: ${Number(form.ttl)} seconds. ` : "Set a valid TTL. "}
              {form.action === "police" ? "The rate applies to the matching flow, across the whole destination. " : ""}
              Router enforcement is unobserved. Expiry needs the running controller.
            </p>
          </section>

          {error && (
            <div role="alert" className="break-words rounded-md border border-destructive/50 bg-destructive/10 p-2 text-xs text-destructive">
              {error}
            </div>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" size="sm" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button type="submit" size="sm" disabled={isSubmitting}>
              {isSubmitting ? (
                <>
                  <RefreshCw className="size-3.5 animate-spin" aria-hidden="true" />
                  Submitting…
                </>
              ) : (
                "Create rule"
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
