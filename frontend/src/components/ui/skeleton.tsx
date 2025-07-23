import { cn } from "@/lib/utils"

interface SkeletonProps extends React.ComponentProps<"div"> {
  shimmer?: boolean
}

function Skeleton({ className, shimmer = true, ...props }: SkeletonProps) {
  return (
    <div
      data-slot="skeleton"
      className={cn(
        "bg-accent animate-pulse rounded-md",
        shimmer && "skeleton-shimmer",
        className
      )}
      {...props}
    />
  )
}

// Enhanced skeleton variants for common use cases
function SkeletonCard({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div className={cn("space-y-3", className)} {...props}>
      <div className="flex items-center space-x-4">
        <Skeleton className="h-12 w-12 rounded-full" />
        <div className="space-y-2">
          <Skeleton className="h-4 w-[200px]" />
          <Skeleton className="h-3 w-[150px]" />
        </div>
      </div>
      <div className="space-y-2">
        <Skeleton className="h-8 w-[100px]" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-[80%]" />
      </div>
    </div>
  )
}

function SkeletonTable({ rows = 5, className, ...props }: { rows?: number } & React.ComponentProps<"div">) {
  return (
    <div className={cn("space-y-3", className)} {...props}>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex items-center space-x-4">
          <Skeleton className="h-4 w-[200px]" />
          <Skeleton className="h-4 w-[100px]" />
          <Skeleton className="h-4 w-[80px]" />
          <Skeleton className="h-4 w-[120px]" />
          <Skeleton className="h-8 w-[80px]" />
        </div>
      ))}
    </div>
  )
}

function SkeletonStats({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div className={cn("grid gap-4 md:grid-cols-2 lg:grid-cols-4", className)} {...props}>
      {Array.from({ length: 4 }).map((_, i) => (
        <div key={i} className="space-y-3 rounded-lg border p-6">
          <div className="flex items-center justify-between">
            <Skeleton className="h-4 w-[120px]" />
            <Skeleton className="h-4 w-4 rounded" />
          </div>
          <Skeleton className="h-8 w-[80px]" />
          <Skeleton className="h-3 w-[100px]" />
        </div>
      ))}
    </div>
  )
}

export { Skeleton, SkeletonCard, SkeletonTable, SkeletonStats }
