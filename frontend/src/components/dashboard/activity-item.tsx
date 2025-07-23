import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"

const activityItemVariants = cva(
  "relative flex items-start space-x-3 pb-4 group",
  {
    variants: {
      variant: {
        default: "hover:bg-muted/50 rounded-lg p-2 -m-2 transition-colors",
        minimal: "",
        interactive: "hover:bg-accent/50 rounded-lg p-2 -m-2 transition-all duration-200 cursor-pointer",
      },
      status: {
        default: "before:bg-primary",
        success: "before:bg-green-500",
        warning: "before:bg-yellow-500", 
        error: "before:bg-red-500",
        info: "before:bg-blue-500",
      },
    },
    defaultVariants: {
      variant: "default",
      status: "default",
    },
  }
)

const activityDotVariants = cva(
  "absolute left-[-25px] top-2 h-2 w-2 rounded-full ring-4 ring-background",
  {
    variants: {
      status: {
        default: "bg-primary",
        success: "bg-green-500",
        warning: "bg-yellow-500",
        error: "bg-red-500", 
        info: "bg-blue-500",
      },
    },
    defaultVariants: {
      status: "default",
    },
  }
)

interface ActivityItemProps 
  extends React.ComponentProps<"div">,
    VariantProps<typeof activityItemVariants> {}

function ActivityItem({ 
  className, 
  variant, 
  status,
  children,
  ...props 
}: ActivityItemProps) {
  return (
    <div
      data-slot="activity-item"
      className={cn(activityItemVariants({ variant, status }), className)}
      {...props}
    >
      <div className={cn(activityDotVariants({ status }))} />
      {children}
    </div>
  )
}

function ActivityIcon({ 
  className, 
  children,
  ...props 
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="activity-icon"
      className={cn(
        "flex h-8 w-8 items-center justify-center rounded-full bg-background border border-border",
        "group-hover:border-primary/50 transition-colors",
        className
      )}
      {...props}
    >
      {children}
    </div>
  )
}

function ActivityContent({ 
  className, 
  ...props 
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="activity-content"
      className={cn("flex-1 min-w-0", className)}
      {...props}
    />
  )
}

function ActivityTitle({ 
  className, 
  ...props 
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="activity-title"
      className={cn("text-sm font-medium leading-none", className)}
      {...props}
    />
  )
}

function ActivityDescription({ 
  className, 
  ...props 
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="activity-description"
      className={cn("text-xs text-muted-foreground mt-1", className)}
      {...props}
    />
  )
}

function ActivityTime({ 
  className, 
  ...props 
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="activity-time"
      className={cn("text-xs text-muted-foreground mt-1", className)}
      {...props}
    />
  )
}

function ActivityActions({ 
  className, 
  ...props 
}: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="activity-actions"
      className={cn(
        "flex items-center space-x-1 opacity-0 group-hover:opacity-100 transition-opacity",
        className
      )}
      {...props}
    />
  )
}

export { 
  ActivityItem, 
  ActivityIcon,
  ActivityContent,
  ActivityTitle,
  ActivityDescription,
  ActivityTime,
  ActivityActions,
  activityItemVariants 
}
export type { ActivityItemProps }
