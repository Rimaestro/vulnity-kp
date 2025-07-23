import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import { cn } from "@/lib/utils"
import {
  Search,
  Shield,
  AlertTriangle,
  CheckCircle,
  FileText,
  Settings,
  User,
  Download,
  Upload,
  Zap,
  Clock,
  Eye,
  RefreshCw,
  X,
  Play,
  Pause,
  Square
} from "lucide-react"

const activityIconVariants = cva(
  "flex h-8 w-8 items-center justify-center rounded-full border transition-all duration-200",
  {
    variants: {
      variant: {
        default: "bg-background border-border group-hover:border-primary/50",
        filled: "border-transparent text-white",
        ghost: "border-transparent bg-transparent",
      },
      type: {
        scan: "bg-blue-50 border-blue-200 text-blue-600 dark:bg-blue-950 dark:border-blue-800 dark:text-blue-400",
        vulnerability: "bg-red-50 border-red-200 text-red-600 dark:bg-red-950 dark:border-red-800 dark:text-red-400",
        fix: "bg-green-50 border-green-200 text-green-600 dark:bg-green-950 dark:border-green-800 dark:text-green-400",
        report: "bg-purple-50 border-purple-200 text-purple-600 dark:bg-purple-950 dark:border-purple-800 dark:text-purple-400",
        system: "bg-gray-50 border-gray-200 text-gray-600 dark:bg-gray-950 dark:border-gray-800 dark:text-gray-400",
        user: "bg-orange-50 border-orange-200 text-orange-600 dark:bg-orange-950 dark:border-orange-800 dark:text-orange-400",
      },
    },
    defaultVariants: {
      variant: "default",
      type: "scan",
    },
  }
)

type ActivityType = 
  | "scan-started"
  | "scan-completed" 
  | "scan-failed"
  | "vulnerability-found"
  | "vulnerability-fixed"
  | "vulnerability-dismissed"
  | "report-generated"
  | "report-downloaded"
  | "settings-changed"
  | "user-login"
  | "user-logout"
  | "file-uploaded"
  | "file-downloaded"
  | "system-update"
  | "backup-created"

const activityIcons: Record<ActivityType, React.ComponentType<{ className?: string }>> = {
  "scan-started": Play,
  "scan-completed": CheckCircle,
  "scan-failed": X,
  "vulnerability-found": AlertTriangle,
  "vulnerability-fixed": CheckCircle,
  "vulnerability-dismissed": X,
  "report-generated": FileText,
  "report-downloaded": Download,
  "settings-changed": Settings,
  "user-login": User,
  "user-logout": User,
  "file-uploaded": Upload,
  "file-downloaded": Download,
  "system-update": RefreshCw,
  "backup-created": Shield,
}

const activityTypeMapping: Record<ActivityType, VariantProps<typeof activityIconVariants>["type"]> = {
  "scan-started": "scan",
  "scan-completed": "scan", 
  "scan-failed": "scan",
  "vulnerability-found": "vulnerability",
  "vulnerability-fixed": "fix",
  "vulnerability-dismissed": "vulnerability",
  "report-generated": "report",
  "report-downloaded": "report",
  "settings-changed": "system",
  "user-login": "user",
  "user-logout": "user",
  "file-uploaded": "system",
  "file-downloaded": "system",
  "system-update": "system",
  "backup-created": "system",
}

interface ActivityIconProps 
  extends Omit<React.ComponentProps<"div">, "type">,
    VariantProps<typeof activityIconVariants> {
  activityType?: ActivityType
  icon?: React.ComponentType<{ className?: string }>
}

function ActivityIcon({ 
  className, 
  variant,
  type,
  activityType,
  icon: CustomIcon,
  ...props 
}: ActivityIconProps) {
  // Determine the icon to use
  const IconComponent = CustomIcon || (activityType ? activityIcons[activityType] : Search)
  
  // Determine the type variant based on activity type
  const typeVariant = type || (activityType ? activityTypeMapping[activityType] : "scan")

  return (
    <div
      data-slot="activity-icon"
      className={cn(activityIconVariants({ variant, type: typeVariant }), className)}
      {...props}
    >
      <IconComponent className="h-4 w-4" />
    </div>
  )
}

export { ActivityIcon, activityIconVariants }
export type { ActivityIconProps, ActivityType }
