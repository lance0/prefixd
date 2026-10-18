import * as React from 'react'

import { cn } from '@/lib/utils'

// Presentational table styling only. Sorting, filtering and pagination stay in
// the page or data layer that composes these elements.

function Table({ className, ...props }: React.ComponentProps<'table'>) {
  return (
    <div data-slot="table-container" className="relative w-full overflow-x-auto">
      <table data-slot="table" className={cn('w-full caption-bottom text-left text-sm', className)} {...props} />
    </div>
  )
}

function TableHeader({ className, ...props }: React.ComponentProps<'thead'>) {
  return <thead data-slot="table-header" className={cn('bg-muted/40 [&_tr]:border-b', className)} {...props} />
}

function TableBody({ className, ...props }: React.ComponentProps<'tbody'>) {
  return <tbody data-slot="table-body" className={cn('[&_tr:last-child]:border-0', className)} {...props} />
}

function TableRow({ className, ...props }: React.ComponentProps<'tr'>) {
  return <tr data-slot="table-row" className={cn('border-b hover:bg-muted/40 data-[state=selected]:bg-muted', className)} {...props} />
}

function TableHead({ className, ...props }: React.ComponentProps<'th'>) {
  return (
    <th
      data-slot="table-head"
      scope="col"
      className={cn('h-9 px-3 text-xs font-medium whitespace-nowrap text-muted-foreground', className)}
      {...props}
    />
  )
}

/** Use `numeric` cells for counts, rates and percentages. */
function TableCell({ className, numeric, ...props }: React.ComponentProps<'td'> & { numeric?: boolean }) {
  return (
    <td
      data-slot="table-cell"
      className={cn('px-3 py-2 align-middle', numeric && 'text-right tabular-nums', className)}
      {...props}
    />
  )
}

function TableCaption({ className, ...props }: React.ComponentProps<'caption'>) {
  return <caption data-slot="table-caption" className={cn('mt-3 text-xs text-muted-foreground', className)} {...props} />
}

export { Table, TableHeader, TableBody, TableRow, TableHead, TableCell, TableCaption }
