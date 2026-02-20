"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"

export default function CreateMitigationRedirect() {
  const router = useRouter()
  useEffect(() => {
    router.replace("/mitigations?mitigate=true")
  }, [router])
  return null
}
