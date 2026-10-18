'use client'

import * as React from 'react'
import * as RechartsPrimitive from 'recharts'

import { cn } from '@/lib/utils'

/** Per-series display settings, keyed by the series' dataKey. */
export type ChartConfig = {
  [k in string]: {
    label?: React.ReactNode
    color?: string
  }
}

type ChartContextProps = {
  config: ChartConfig
}

const ChartContext = React.createContext<ChartContextProps | null>(null)

function useChart() {
  const context = React.useContext(ChartContext)

  if (!context) {
    throw new Error('useChart must be used within a <ChartContainer />')
  }

  return context
}

function ChartContainer({
  id,
  className,
  children,
  config,
  ...props
}: React.ComponentProps<'div'> & {
  config: ChartConfig
  children: React.ComponentProps<
    typeof RechartsPrimitive.ResponsiveContainer
  >['children']
}) {
  const uniqueId = React.useId()
  const chartId = `chart-${id || uniqueId.replace(/:/g, '')}`

  // Recharts 3 sizes the chart inside a zero-size, overflow-visible div. Chromium can
  // paint that layer wider than the container (seen in beyond-viewport captures), so the
  // SVG spilled into the neighbouring column. A full-size, clipping box keeps it in its
  // cell; the outer container keeps min-width: 0, so the chart still shrinks on resize.
  const sizer = '[&_.recharts-responsive-container>div]:size-full! [&_.recharts-responsive-container>div]:overflow-hidden!'

  return (
    <ChartContext.Provider value={{ config }}>
      <div
        data-slot="chart"
        data-chart={chartId}
        className={cn(
          "[&_.recharts-cartesian-axis-tick_text]:fill-muted-foreground [&_.recharts-cartesian-grid_line[stroke='#ccc']]:stroke-border/50 [&_.recharts-curve.recharts-tooltip-cursor]:stroke-border [&_.recharts-polar-grid_[stroke='#ccc']]:stroke-border [&_.recharts-radial-bar-background-sector]:fill-muted [&_.recharts-rectangle.recharts-tooltip-cursor]:fill-muted [&_.recharts-reference-line_[stroke='#ccc']]:stroke-border flex aspect-video justify-center text-xs [&_.recharts-dot[stroke='#fff']]:stroke-transparent [&_.recharts-layer]:outline-hidden [&_.recharts-sector]:outline-hidden [&_.recharts-sector[stroke='#fff']]:stroke-transparent [&_.recharts-surface]:outline-hidden",
          sizer,
          className,
        )}
        {...props}
      >
        <ChartStyle id={chartId} config={config} />
        <RechartsPrimitive.ResponsiveContainer>
          {children}
        </RechartsPrimitive.ResponsiveContainer>
      </div>
    </ChartContext.Provider>
  )
}

/** Exposes each configured series colour as `--color-<key>` inside the chart. */
const ChartStyle = ({ id, config }: { id: string; config: ChartConfig }) => {
  const declarations = Object.entries(config).flatMap(([key, item]) =>
    item.color ? [`  --color-${key}: ${item.color};`] : [],
  )

  if (!declarations.length) {
    return null
  }

  return (
    <style
      dangerouslySetInnerHTML={{
        __html: `[data-chart=${id}] {\n${declarations.join('\n')}\n}`,
      }}
    />
  )
}

const ChartTooltip = RechartsPrimitive.Tooltip

type ChartTooltipContentProps =
  Partial<RechartsPrimitive.TooltipContentProps> &
  React.ComponentProps<'div'> & {
    hideLabel?: boolean
  }

function ChartTooltipContent({
  active,
  payload,
  className,
  hideLabel = false,
  label,
  labelFormatter,
  labelClassName,
  color,
}: ChartTooltipContentProps) {
  const { config } = useChart()

  if (!active || !payload?.length) {
    return null
  }

  const seriesKey = (item: RechartsPrimitive.TooltipPayloadEntry) => `${item.dataKey || item.name || 'value'}`

  const tooltipLabel = (() => {
    if (hideLabel) {
      return null
    }

    const value = label !== undefined
      ? config[label]?.label || label
      : config[seriesKey(payload[0])]?.label

    if (labelFormatter) {
      return (
        <div className={cn('font-medium', labelClassName)}>
          {labelFormatter(value, payload)}
        </div>
      )
    }

    if (!value) {
      return null
    }

    return <div className={cn('font-medium', labelClassName)}>{value}</div>
  })()

  return (
    <div
      className={cn(
        'border-border/50 bg-background grid min-w-[8rem] items-start gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs shadow-xl',
        className,
      )}
    >
      {tooltipLabel}
      <div className="grid gap-1.5">
        {payload.map((item, index) => {
          const itemConfig = config[seriesKey(item)]
          const indicatorColor = color || item.payload?.fill || item.color

          return (
            <div
              key={`${item.dataKey ?? item.name ?? index}`}
              className="flex w-full flex-wrap items-center gap-2"
            >
              <div
                className="h-2.5 w-2.5 shrink-0 rounded-[2px]"
                style={{ backgroundColor: indicatorColor }}
              />
              <div className="flex flex-1 items-center justify-between leading-none">
                <span className="text-muted-foreground">
                  {itemConfig?.label || item.name}
                </span>
                {item.value !== undefined && item.value !== null && (
                  <span className="text-foreground font-mono font-medium tabular-nums">
                    {item.value.toLocaleString()}
                  </span>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export {
  ChartContainer,
  ChartTooltip,
  ChartTooltipContent,
  ChartStyle,
}
