"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { ArrowLeft, ShieldAlert, RefreshCw } from "lucide-react"
import { ingestEvent } from "@/lib/api"
import { usePermissions } from "@/hooks/use-permissions"
import { toast } from "sonner"

const VECTORS = [
  { value: "udp_flood", label: "UDP Flood" },
  { value: "syn_flood", label: "SYN Flood" },
  { value: "ack_flood", label: "ACK Flood" },
  { value: "icmp_flood", label: "ICMP Flood" },
  { value: "unknown", label: "Unknown" },
] as const

function isValidIPv4(ip: string): boolean {
  const parts = ip.split(".")
  if (parts.length !== 4) return false
  return parts.every((p) => {
    const n = Number(p)
    return /^\d{1,3}$/.test(p) && n >= 0 && n <= 255
  })
}

export default function CreateMitigationPage() {
  const router = useRouter()
  const permissions = usePermissions()

  const [victimIp, setVictimIp] = useState("")
  const [vector, setVector] = useState("")
  const [bps, setBps] = useState("")
  const [pps, setPps] = useState("")
  const [ports, setPorts] = useState("")
  const [confidence, setConfidence] = useState("1.0")
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const parsePorts = (input: string): number[] | null => {
    if (!input.trim()) return []
    const parts = input.split(",").map((s) => s.trim())
    const parsed = parts.map(Number)
    if (parsed.some((n) => isNaN(n) || n < 1 || n > 65535)) return null
    if (parsed.length > 8) return null
    return parsed
  }

  const isValid =
    isValidIPv4(victimIp) &&
    vector !== "" &&
    parsePorts(ports) !== null &&
    (!bps || !isNaN(Number(bps))) &&
    (!pps || !isNaN(Number(pps))) &&
    !isNaN(Number(confidence)) &&
    Number(confidence) >= 0 &&
    Number(confidence) <= 1

  const handleSubmit = async () => {
    if (!isValid) return
    setIsSubmitting(true)
    setError(null)

    try {
      const result = await ingestEvent({
        victim_ip: victimIp,
        vector,
        source: "dashboard",
        timestamp: new Date().toISOString(),
        bps: bps ? Number(bps) : null,
        pps: pps ? Number(pps) : null,
        top_dst_ports: parsePorts(ports) || undefined,
        confidence: confidence ? Number(confidence) : null,
        action: "ban",
      })

      if (result.mitigation_id) {
        toast.success("Mitigation created", {
          description: `${victimIp} — ${vector.replace(/_/g, " ")}`,
        })
        router.push(`/mitigations/${result.mitigation_id}`)
      } else {
        toast.info("Event accepted", {
          description: result.status,
        })
        router.push("/mitigations")
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : "Failed to submit event"
      setError(message)
      toast.error("Failed to create mitigation", { description: message })
    } finally {
      setIsSubmitting(false)
    }
  }

  if (!permissions.settled) {
    return (
      <DashboardLayout>
        <div className="flex h-[50vh] items-center justify-center">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </DashboardLayout>
    )
  }

  if (!permissions.canWithdraw) {
    return (
      <DashboardLayout>
        <div className="flex flex-col items-center justify-center h-[50vh] space-y-4">
          <ShieldAlert className="h-12 w-12 text-muted-foreground" />
          <h2 className="text-xl font-semibold">Insufficient Permissions</h2>
          <p className="text-muted-foreground">Only operators and admins can create mitigations.</p>
          <Button variant="outline" onClick={() => router.push("/mitigations")}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Mitigations
          </Button>
        </div>
      </DashboardLayout>
    )
  }

  return (
    <DashboardLayout>
      <div className="max-w-2xl space-y-6">
        <div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => router.back()}
            className="-ml-3 mb-2 text-muted-foreground"
          >
            <ArrowLeft className="mr-2 h-4 w-4" /> Back
          </Button>
          <h1 className="text-2xl font-bold tracking-tight">Mitigate Now</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Submit a manual attack event. The policy engine will evaluate playbooks, check guardrails, and announce a FlowSpec rule if appropriate.
          </p>
        </div>

        <Card className="border-border shadow-sm">
          <CardHeader>
            <CardTitle className="text-base">Attack Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-5">
            {/* Victim IP */}
            <div className="space-y-2">
              <Label htmlFor="victim-ip">
                Destination IP <span className="text-destructive">*</span>
              </Label>
              <Input
                id="victim-ip"
                placeholder="192.0.2.1"
                value={victimIp}
                onChange={(e) => setVictimIp(e.target.value)}
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Must be a single host IP. A /32 prefix will be applied automatically.
              </p>
              {victimIp && !isValidIPv4(victimIp) && (
                <p className="text-xs text-destructive">Invalid IPv4 address</p>
              )}
            </div>

            {/* Vector */}
            <div className="space-y-2">
              <Label htmlFor="vector">
                Attack Vector <span className="text-destructive">*</span>
              </Label>
              <Select value={vector} onValueChange={setVector}>
                <SelectTrigger id="vector">
                  <SelectValue placeholder="Select vector..." />
                </SelectTrigger>
                <SelectContent>
                  {VECTORS.map((v) => (
                    <SelectItem key={v.value} value={v.value}>
                      {v.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Traffic metrics row */}
            <div className="grid grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="bps">Traffic (bps)</Label>
                <Input
                  id="bps"
                  type="number"
                  placeholder="e.g. 1000000000"
                  value={bps}
                  onChange={(e) => setBps(e.target.value)}
                  className="font-mono"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="pps">Packets (pps)</Label>
                <Input
                  id="pps"
                  type="number"
                  placeholder="e.g. 500000"
                  value={pps}
                  onChange={(e) => setPps(e.target.value)}
                  className="font-mono"
                />
              </div>
            </div>

            {/* Destination Ports */}
            <div className="space-y-2">
              <Label htmlFor="ports">Destination Ports</Label>
              <Input
                id="ports"
                placeholder="e.g. 80, 443, 53"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Comma-separated, max 8 ports. Leave empty for all ports.
              </p>
              {ports && parsePorts(ports) === null && (
                <p className="text-xs text-destructive">
                  Invalid ports. Use comma-separated numbers 1-65535, max 8.
                </p>
              )}
            </div>

            {/* Confidence */}
            <div className="space-y-2">
              <Label htmlFor="confidence">
                Confidence ({confidence || "1.0"})
              </Label>
              <Input
                id="confidence"
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={confidence}
                onChange={(e) => setConfidence(e.target.value)}
                className="accent-primary"
              />
              <div className="flex justify-between text-[10px] text-muted-foreground font-mono">
                <span>0.0</span>
                <span>1.0</span>
              </div>
            </div>

            {error && (
              <div className="rounded-md bg-destructive/10 border border-destructive/50 p-3 text-sm text-destructive">
                {error}
              </div>
            )}

            <div className="flex items-center gap-3 pt-2">
              <Button
                onClick={handleSubmit}
                disabled={!isValid || isSubmitting}
                className="flex-1"
              >
                {isSubmitting ? (
                  <>
                    <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                    Submitting...
                  </>
                ) : (
                  <>
                    <ShieldAlert className="h-4 w-4 mr-2" />
                    Submit Mitigation Event
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={() => router.push("/mitigations")}
                disabled={isSubmitting}
              >
                Cancel
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  )
}
