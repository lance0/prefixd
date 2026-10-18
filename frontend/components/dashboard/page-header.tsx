import type { ReactNode } from "react"
import Link from "next/link"
import { ArrowLeft } from "lucide-react"

interface PageHeaderProps {
  title: ReactNode
  description?: ReactNode
  /** Parent page link for detail views. */
  back?: { href: string; label: string }
  /** Right-aligned page actions. */
  actions?: ReactNode
  /** Status and facts row under the title, e.g. on detail pages. */
  meta?: ReactNode
}

/** The single page title for every dashboard route. Pages render no outer padding of their own. */
export function PageHeader({ title, description, back, actions, meta }: PageHeaderProps) {
  return (
    <header className="space-y-3">
      {back ? (
        <Link href={back.href} className="inline-flex items-center gap-1.5 rounded-sm text-sm text-muted-foreground hover:text-foreground">
          <ArrowLeft className="size-4" aria-hidden="true" />
          {back.label}
        </Link>
      ) : null}
      <div className="flex flex-wrap items-start justify-between gap-x-6 gap-y-3">
        <div className="min-w-0 space-y-1">
          <h1 className="text-xl font-semibold text-balance">{title}</h1>
          {description ? <p className="text-sm text-muted-foreground text-pretty">{description}</p> : null}
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {meta ? <div className="flex flex-wrap items-center gap-2 text-sm">{meta}</div> : null}
    </header>
  )
}
