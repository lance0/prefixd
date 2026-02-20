"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
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
import { ShieldAlert, RefreshCw } from "lucide-react"
import { ingestEvent } from "@/lib/api"
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

function parsePorts(input: string): number[] | null {
  if (!input.trim()) return []
  const parts = input.split(",").map((s) => s.trim())
  const parsed = parts.map(Number)
  if (parsed.some((n) => isNaN(n) || n < 1 || n > 65535)) return null
  if (parsed.length > 8) return null
  return parsed
}

interface MitigateNowDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function MitigateNowDialog({ open, onOpenChange }: MitigateNowDialogProps) {
  const router = useRouter()
  const [victimIp, setVictimIp] = useState("")
  const [vector, setVector] = useState("")
  const [bps, setBps] = useState("")
  const [pps, setPps] = useState("")
  const [ports, setPorts] = useState("")
  const [confidence, setConfidence] = useState("1.0")
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const isValid =
    isValidIPv4(victimIp) &&
    vector !== "" &&
    parsePorts(ports) !== null &&
    (!bps || !isNaN(Number(bps))) &&
    (!pps || !isNaN(Number(pps))) &&
    !isNaN(Number(confidence)) &&
    Number(confidence) >= 0 &&
    Number(confidence) <= 1

  const reset = () => {
    setVictimIp("")
    setVector("")
    setBps("")
    setPps("")
    setPorts("")
    setConfidence("1.0")
    setError(null)
  }

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
        reset()
        onOpenChange(false)
        router.push(`/mitigations/${result.mitigation_id}`)
      } else {
        toast.info("Event accepted", { description: result.status })
        reset()
        onOpenChange(false)
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : "Failed to submit event"
      setError(message)
      toast.error("Failed to create mitigation", { description: message })
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!isSubmitting) { onOpenChange(v); if (!v) reset() } }}>
      <DialogContent className="sm:max-w-lg bg-card border-border">
        <DialogHeader>
          <DialogTitle className="text-sm font-mono uppercase tracking-wide flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-primary" />
            Mitigate Now
          </DialogTitle>
          <DialogDescription className="text-xs text-muted-foreground">
            Submit a manual attack event. The policy engine will evaluate playbooks and announce a FlowSpec rule if appropriate.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label htmlFor="mn-ip" className="text-xs">
              Destination IP <span className="text-destructive">*</span>
            </Label>
            <Input
              id="mn-ip"
              placeholder="192.0.2.1"
              value={victimIp}
              onChange={(e) => setVictimIp(e.target.value)}
              className="font-mono h-9"
            />
            {victimIp && !isValidIPv4(victimIp) && (
              <p className="text-[10px] text-destructive">Invalid IPv4 address</p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="mn-vector" className="text-xs">
              Attack Vector <span className="text-destructive">*</span>
            </Label>
            <Select value={vector} onValueChange={setVector}>
              <SelectTrigger id="mn-vector" className="h-9">
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

          <div className="grid grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label htmlFor="mn-bps" className="text-xs">Traffic (bps)</Label>
              <Input
                id="mn-bps"
                type="number"
                placeholder="1000000000"
                value={bps}
                onChange={(e) => setBps(e.target.value)}
                className="font-mono h-9"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="mn-pps" className="text-xs">Packets (pps)</Label>
              <Input
                id="mn-pps"
                type="number"
                placeholder="500000"
                value={pps}
                onChange={(e) => setPps(e.target.value)}
                className="font-mono h-9"
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="mn-ports" className="text-xs">Destination Ports</Label>
            <Input
              id="mn-ports"
              placeholder="80, 443, 53"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
              className="font-mono h-9"
            />
            {ports && parsePorts(ports) === null && (
              <p className="text-[10px] text-destructive">
                Invalid ports. Comma-separated 1-65535, max 8.
              </p>
            )}
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="mn-confidence" className="text-xs">
              Confidence ({confidence})
            </Label>
            <Input
              id="mn-confidence"
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
            <div className="rounded-md bg-destructive/10 border border-destructive/50 p-2 text-xs text-destructive">
              {error}
            </div>
          )}
        </div>

        <div className="flex items-center gap-3 pt-2">
          <Button
            onClick={handleSubmit}
            disabled={!isValid || isSubmitting}
            className="flex-1"
            size="sm"
          >
            {isSubmitting ? (
              <>
                <RefreshCw className="h-3.5 w-3.5 mr-2 animate-spin" />
                Submitting...
              </>
            ) : (
              <>
                <ShieldAlert className="h-3.5 w-3.5 mr-2" />
                Submit
              </>
            )}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onOpenChange(false)}
            disabled={isSubmitting}
          >
            Cancel
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
