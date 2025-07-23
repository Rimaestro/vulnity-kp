import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const timelineVariants = cva(
  "relative space-y-4",
  {
    variants: {
      variant: {
        default: "border-l border-border ml-4 pl-6",
        compact: "border-l border-border ml-2 pl-4",
        minimal: "ml-0 pl-0",
      },
      size: {
        sm: "space-y-2",
        md: "space-y-4", 
        lg: "space-y-6",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "md",
    },
  }
)

interface ActivityTimelineProps 
  extends React.ComponentProps<"div">,
    VariantProps<typeof timelineVariants> {}

function ActivityTimeline({ 
  className, 
  variant, 
  size, 
  ...props 
}: ActivityTimelineProps) {
  return (
    <div
      data-slot="activity-timeline"
      className={cn(timelineVariants({ variant, size }), className)}
      {...props}
    />
  )
}

export { ActivityTimeline, timelineVariants }
export type { ActivityTimelineProps }
