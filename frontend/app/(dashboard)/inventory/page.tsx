"use client"

import { useState, useMemo } from "react"
import Link from "next/link"
import { Input } from "@/components/ui/input"
import { useConfigInventory } from "@/hooks/use-api"
import { Search, ChevronDown, ChevronRight } from "lucide-react"
import type { ConfigCustomer } from "@/lib/api"
import { PageHeader } from "@/components/dashboard/page-header"
import { Tag } from "@/components/dashboard/status-pill"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"

function CustomerSection({ customer, defaultOpen }: { customer: ConfigCustomer; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  const totalAssets = customer.services.reduce((sum, s) => sum + s.assets.length, 0)
  const panelId = `customer-${customer.customer_id}`

  return (
    <section className="overflow-hidden rounded-md border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 px-4 py-3">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={() => setOpen(!open)}
          className="flex min-w-0 items-center gap-2 rounded-sm text-left"
        >
          {open ? <ChevronDown className="size-4 text-muted-foreground" aria-hidden="true" /> : <ChevronRight className="size-4 text-muted-foreground" aria-hidden="true" />}
          <h2 className="truncate text-sm font-semibold">{customer.name}</h2>
        </button>
        <div className="flex flex-wrap items-center gap-2 text-sm">
          <Tag>{customer.policy_profile}</Tag>
          <span className="text-muted-foreground tabular-nums">
            {customer.services.length} services · {totalAssets} IPs
          </span>
        </div>
        <div className="flex w-full flex-wrap items-center gap-2 pl-6 text-xs">
          <Link href={`/mitigations?ip=${customer.customer_id}`} className="rounded-sm font-mono text-muted-foreground hover:text-foreground hover:underline">
            {customer.customer_id}
          </Link>
          {customer.prefixes.map((p) => (
            <Tag key={p} className="font-mono">{p}</Tag>
          ))}
        </div>
      </div>
      {open && (
        <div id={panelId} className="space-y-3 border-t p-4">
          {customer.services.map((service) => (
            <div key={service.service_id} className="overflow-hidden rounded-md border">
              <div className="flex flex-wrap items-center justify-between gap-2 bg-muted/40 px-3 py-2 text-sm">
                <div className="flex items-center gap-2">
                  <span className="font-medium">{service.name}</span>
                  <span className="font-mono text-xs text-muted-foreground">{service.service_id}</span>
                </div>
                {(service.allowed_ports.tcp?.length ?? 0) > 0 || (service.allowed_ports.udp?.length ?? 0) > 0 ? (
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    {service.allowed_ports.tcp?.length ? (
                      <span>TCP <span className="font-mono text-foreground">{service.allowed_ports.tcp.join(", ")}</span></span>
                    ) : null}
                    {service.allowed_ports.udp?.length ? (
                      <span>UDP <span className="font-mono text-foreground">{service.allowed_ports.udp.join(", ")}</span></span>
                    ) : null}
                  </div>
                ) : null}
              </div>
              {service.assets.length > 0 && (
                <ul className="divide-y">
                  {service.assets.map((asset) => (
                    <li key={asset.ip} className="flex items-center justify-between px-3 py-1.5 text-sm">
                      <Link href={`/mitigations?ip=${asset.ip}`} className="rounded-sm font-mono hover:underline">{asset.ip}</Link>
                      {asset.role && <Tag>{asset.role}</Tag>}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
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
    <div className="space-y-6">
      <PageHeader
        title="Inventory"
        description="Customers, their services and the IP assets prefixd may protect."
        meta={data ? (
          <span className="text-muted-foreground tabular-nums">
            {data.total_customers} customers · {data.total_services} services · {data.total_assets} IPs
          </span>
        ) : undefined}
      />

      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
        <Input
          placeholder="Search customers, services, IPs…"
          aria-label="Search inventory"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="h-9 pl-9 text-base sm:text-sm"
          spellCheck={false}
          autoComplete="off"
        />
      </div>

      {error ? (
        <div className="rounded-md border bg-card">
          <ErrorState title="Unable to load inventory" detail={`${error.message}. Check the controller's inventory file and API connectivity.`} />
        </div>
      ) : !data ? (
        <div className="rounded-md border bg-card"><LoadingRows label="Loading inventory" /></div>
      ) : filtered.length === 0 ? (
        <div className="rounded-md border bg-card">
          {search
            ? <EmptyState title="No matches found" description="Nothing in the inventory matches this search." />
            : <EmptyState title="No customers in inventory" description="Add customers and their assets to the inventory file, then reload configuration." />}
        </div>
      ) : (
        <div className="space-y-3">
          {filtered.map((customer) => (
            <CustomerSection
              key={customer.customer_id}
              customer={customer}
              defaultOpen={filtered.length <= 3}
            />
          ))}
        </div>
      )}
    </div>
  )
}
