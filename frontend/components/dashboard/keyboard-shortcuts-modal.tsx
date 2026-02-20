"use client"

import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog"

interface KeyboardShortcutsModalProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

const shortcuts = [
  {
    category: "Navigation",
    items: [
      { keys: ["g", "o"], description: "Go to Overview" },
      { keys: ["g", "m"], description: "Go to Mitigations" },
      { keys: ["g", "e"], description: "Go to Events" },
      { keys: ["g", "i"], description: "Go to Inventory" },
      { keys: ["g", "h"], description: "Go to IP History" },
      { keys: ["g", "a"], description: "Go to Audit Log" },
      { keys: ["g", "c"], description: "Go to Config" },
    ],
  },
  {
    category: "Actions",
    items: [
      { keys: ["n"], description: "Mitigate Now" },
      { keys: ["⌘", "K"], description: "Open command palette" },
      { keys: ["⌘", "B"], description: "Toggle sidebar" },
      { keys: ["?"], description: "Toggle keyboard shortcuts" },
      { keys: ["Esc"], description: "Close modal / panel" },
    ],
  },
]

export function KeyboardShortcutsModal({ open, onOpenChange }: KeyboardShortcutsModalProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md bg-card border-border">
        <DialogHeader>
          <DialogTitle className="text-sm font-mono uppercase tracking-wide text-foreground">
            Keyboard Shortcuts
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-6 py-2">
          {shortcuts.map((section) => (
            <div key={section.category}>
              <h3 className="text-[10px] font-mono uppercase tracking-wider text-muted-foreground mb-3">
                {section.category}
              </h3>
              <div className="space-y-1">
                {section.items.map((shortcut) => (
                  <div
                    key={shortcut.description}
                    className="flex items-center justify-between py-1.5 border-b border-border/50 last:border-0"
                  >
                    <span className="text-xs font-mono text-foreground">{shortcut.description}</span>
                    <div className="flex items-center gap-1">
                      {shortcut.keys.map((key, i) => (
                        <span key={i} className="flex items-center">
                          <kbd className="kbd">{key}</kbd>
                          {i < shortcut.keys.length - 1 && (
                            <span className="text-muted-foreground mx-1 text-[10px] font-mono">then</span>
                          )}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="pt-2 border-t border-border">
          <p className="text-[10px] font-mono text-muted-foreground text-center">
            Press <kbd className="kbd">?</kbd> anytime to show this help
          </p>
        </div>
      </DialogContent>
    </Dialog>
  )
}
