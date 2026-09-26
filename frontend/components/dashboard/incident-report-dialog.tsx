"use client"

import { useState } from "react"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Copy, Download, FileText, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { copyText } from "@/lib/clipboard"

interface IncidentReportDialogProps {
  markdown: string | null
  filename: string
  open: boolean
  onOpenChange: (open: boolean) => void
  loading?: boolean
}

export function IncidentReportDialog({
  markdown,
  filename,
  open,
  onOpenChange,
  loading,
}: IncidentReportDialogProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    if (!markdown) return
    if (!(await copyText(markdown))) {
      toast.error("Copy failed — clipboard unavailable")
      return
    }
    setCopied(true)
    toast.success("Report copied to clipboard")
    setTimeout(() => setCopied(false), 2000)
  }

  const handleDownload = () => {
    if (!markdown) return
    const blob = new Blob([markdown], { type: "text/markdown;charset=utf-8;" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
    toast.success(`Downloaded ${filename}`)
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl max-h-[80vh] bg-card border-border">
        <DialogHeader>
          <DialogTitle className="text-sm font-mono uppercase tracking-wide flex items-center gap-2">
            <FileText className="h-4 w-4 text-primary" />
            Incident Report
          </DialogTitle>
          <DialogDescription className="text-xs text-muted-foreground">
            Markdown report for sharing in Slack, email, or Jira.
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : markdown ? (
          <>
            <div className="overflow-auto max-h-[50vh] rounded-md border border-border bg-muted/50 p-4">
              <pre className="text-xs font-mono whitespace-pre-wrap break-words text-foreground">
                {markdown}
              </pre>
            </div>
            <div className="flex items-center gap-3 pt-2">
              <Button onClick={handleCopy} variant="outline" size="sm" className="flex-1">
                <Copy className="h-3.5 w-3.5 mr-2" />
                {copied ? "Copied!" : "Copy to Clipboard"}
              </Button>
              <Button onClick={handleDownload} size="sm" className="flex-1">
                <Download className="h-3.5 w-3.5 mr-2" />
                Download .md
              </Button>
            </div>
          </>
        ) : (
          <div className="text-center py-12 text-sm text-muted-foreground">
            No report data available.
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}
