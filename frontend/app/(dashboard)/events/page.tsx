"use client"

import { Suspense } from "react"
import { useSearchParams } from "next/navigation"
import { EventsContentLive } from "@/components/dashboard/events-content-live"
import { PageHeader } from "@/components/dashboard/page-header"
import { LoadingRows } from "@/components/dashboard/states"

export default function EventsPage() {
  const searchParams = useSearchParams()
  const eventId = searchParams.get("id")

  return (
    <div className="space-y-6">
      <PageHeader title="Events" description="Attack signals received from detectors and operators, newest first." />
      <Suspense fallback={<div className="rounded-md border bg-card"><LoadingRows label="Loading events" rows={5} /></div>}>
        <EventsContentLive key={eventId ?? ""} initialEventId={eventId} />
      </Suspense>
    </div>
  )
}
