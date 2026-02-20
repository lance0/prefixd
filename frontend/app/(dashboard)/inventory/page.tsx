"use client"

import { useState, useMemo } from "react"
import Link from "next/link"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { useConfigInventory } from "@/hooks/use-api"
import { Search, Loader2, ChevronDown, ChevronRight, Users, Server, Globe } from "lucide-react"
import type { ConfigCustomer } from "@/lib/api"

function profileColor(profile: string): "default" | "secondary" | "destructive" {
  switch (profile) {
    case "strict": return "destructive"
    case "relaxed": return "secondary"
    default: return "default"
  }
}

function CustomerCard({ customer, defaultOpen }: { customer: ConfigCustomer; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  const totalAssets = customer.services.reduce((sum, s) => sum + s.assets.length, 0)

  return (
    <Card>
      <CardHeader className="pb-2 cursor-pointer" onClick={() => setOpen(!open)}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {open ? <ChevronDown className="h-3 w-3 text-muted-foreground" /> : <ChevronRight className="h-3 w-3 text-muted-foreground" />}
            <CardTitle className="text-sm font-mono">{customer.name}</CardTitle>
            <Badge variant={profileColor(customer.policy_profile)} className="text-[10px] font-mono">
              {customer.policy_profile}
            </Badge>
          </div>
          <div className="flex items-center gap-3 text-[10px] font-mono text-muted-foreground">
            <span>{customer.services.length} services</span>
            <span>{totalAssets} IPs</span>
          </div>
        </div>
        <div className="flex items-center gap-1.5 ml-5 mt-1">
          <Link href={`/mitigations?ip=${customer.customer_id}`} className="text-[10px] font-mono text-primary hover:underline">{customer.customer_id}</Link>
          <span className="text-[10px] text-muted-foreground">·</span>
          {customer.prefixes.map((p) => (
            <Badge key={p} variant="outline" className="text-[10px] font-mono px-1 py-0">
              {p}
            </Badge>
          ))}
        </div>
      </CardHeader>
      {open && (
        <CardContent className="pt-0 space-y-3">
          {customer.services.map((service) => (
            <div key={service.service_id} className="border border-border">
              <div className="flex items-center justify-between px-3 py-2 bg-secondary/30">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-medium">{service.name}</span>
                  <span className="text-[10px] font-mono text-muted-foreground">{service.service_id}</span>
                </div>
                {(service.allowed_ports.tcp?.length ?? 0) > 0 || (service.allowed_ports.udp?.length ?? 0) > 0 ? (
                  <div className="flex items-center gap-2 text-[10px] font-mono text-muted-foreground">
                    {service.allowed_ports.tcp?.length ? (
                      <span>TCP: {service.allowed_ports.tcp.join(", ")}</span>
                    ) : null}
                    {service.allowed_ports.udp?.length ? (
                      <span>UDP: {service.allowed_ports.udp.join(", ")}</span>
                    ) : null}
                  </div>
                ) : null}
              </div>
              {service.assets.length > 0 && (
                <div className="divide-y divide-border">
                  {service.assets.map((asset) => (
                    <div key={asset.ip} className="flex items-center justify-between px-3 py-1.5 text-xs font-mono">
                      <Link href={`/mitigations?ip=${asset.ip}`} className="text-primary hover:underline">{asset.ip}</Link>
                      {asset.role && (
                        <Badge variant="outline" className="text-[10px] font-mono px-1 py-0">
                          {asset.role}
                        </Badge>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </CardContent>
      )}
    </Card>
  )
}

export default function InventoryPage() {
  const { data, error } = useConfigInventory()
  const [search, setSearch] = useState("")

  const filtered = useMemo(() => {
    if (!data) return []
    if (!search.trim()) return data.customers
    const q = search.toLowerCase()
    return data.customers.filter((c) => {
      if (c.customer_id.toLowerCase().includes(q)) return true
      if (c.name.toLowerCase().includes(q)) return true
      if (c.policy_profile.toLowerCase().includes(q)) return true
      if (c.prefixes.some((p) => p.includes(q))) return true
      return c.services.some((s) => {
        if (s.name.toLowerCase().includes(q)) return true
        if (s.service_id.toLowerCase().includes(q)) return true
        if (s.allowed_ports.tcp?.some((p) => String(p).includes(q))) return true
        if (s.allowed_ports.udp?.some((p) => String(p).includes(q))) return true
        return s.assets.some((a) => a.ip.includes(q) || a.role?.toLowerCase().includes(q))
      })
    })
  }, [data, search])

  return (
    <DashboardLayout>
      <div className="flex-1 overflow-auto">
        <div className="p-4 sm:p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-lg font-mono font-medium">Inventory</h1>
              <p className="text-xs text-muted-foreground font-mono mt-0.5">
                Customer services and IP assets
              </p>
            </div>
            {data && (
              <div className="flex items-center gap-4 text-xs font-mono text-muted-foreground">
                <div className="flex items-center gap-1">
                  <Users className="h-3 w-3" />
                  {data.total_customers} customers
                </div>
                <div className="flex items-center gap-1">
                  <Server className="h-3 w-3" />
                  {data.total_services} services
                </div>
                <div className="flex items-center gap-1">
                  <Globe className="h-3 w-3" />
                  {data.total_assets} IPs
                </div>
              </div>
            )}
          </div>

          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder="Search customers, services, IPs..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 h-8 text-xs font-mono"
            />
          </div>

          {error ? (
            <Card>
              <CardContent className="p-4 text-sm text-destructive font-mono">
                Failed to load inventory: {error.message}
              </CardContent>
            </Card>
          ) : !data ? (
            <Card>
              <CardContent className="p-4 flex items-center gap-2 text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
                <span className="text-sm font-mono">Loading inventory...</span>
              </CardContent>
            </Card>
          ) : filtered.length === 0 ? (
            <Card>
              <CardContent className="p-4 text-sm text-muted-foreground font-mono">
                {search ? "No matches found" : "No customers in inventory"}
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {filtered.map((customer) => (
                <CustomerCard
                  key={customer.customer_id}
                  customer={customer}
                  defaultOpen={filtered.length <= 3}
                />
              ))}
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  )
}
