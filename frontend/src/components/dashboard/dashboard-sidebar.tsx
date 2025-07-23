import { useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { 
  Home, 
  Shield, 
  Search, 
  FileText, 
  Settings, 
  BarChart3,
  ChevronLeft,
  ChevronRight,
  LogOut,
  User
} from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { useAuth } from '@/contexts/auth-context'
import { cn } from '@/lib/utils'

interface SidebarItem {
  title: string
  href: string
  icon: React.ComponentType<{ className?: string }>
  badge?: string
}

const sidebarItems: SidebarItem[] = [
  {
    title: 'Dashboard',
    href: '/dashboard',
    icon: Home,
  },
  {
    title: 'Scans',
    href: '/dashboard/scans',
    icon: Search,
  },
  {
    title: 'Vulnerabilities',
    href: '/dashboard/vulnerabilities',
    icon: Shield,
    badge: 'New'
  },
  {
    title: 'Reports',
    href: '/dashboard/reports',
    icon: FileText,
  },
  {
    title: 'Analytics',
    href: '/dashboard/analytics',
    icon: BarChart3,
  },
  {
    title: 'Settings',
    href: '/dashboard/settings',
    icon: Settings,
  },
]

interface DashboardSidebarProps {
  className?: string
}

export function DashboardSidebar({ className }: DashboardSidebarProps) {
  const [isCollapsed, setIsCollapsed] = useState(false)
  const location = useLocation()
  const { user, logout } = useAuth()

  const toggleSidebar = () => {
    setIsCollapsed(!isCollapsed)
  }

  return (
    <TooltipProvider>
      <div className={cn(
        "relative flex flex-col border-r bg-background transition-all duration-300",
        isCollapsed ? "w-16" : "w-64",
        className
      )}>
        {/* Header */}
        <div className="flex h-16 items-center border-b px-4">
          {!isCollapsed && (
            <div className="flex items-center space-x-2">
              <img src="/logo.svg" alt="Vulnity Logo" className="h-8 w-8" />
              <h2 className="text-lg font-semibold">Vulnity</h2>
            </div>
          )}
          {isCollapsed && (
            <img src="/logo.svg" alt="Vulnity Logo" className="h-8 w-8 mx-auto" />
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 space-y-1 p-2">
          {sidebarItems.map((item) => {
            const Icon = item.icon
            const isActive = location.pathname === item.href
            
            return (
              <Tooltip key={item.href} delayDuration={0}>
                <TooltipTrigger asChild>
                  <Link to={item.href}>
                    <Button
                      variant={isActive ? "secondary" : "ghost"}
                      className={cn(
                        "w-full justify-start",
                        isCollapsed && "justify-center px-2"
                      )}
                    >
                      <Icon className={cn("h-4 w-4", !isCollapsed && "mr-2")} />
                      {!isCollapsed && (
                        <>
                          <span>{item.title}</span>
                          {item.badge && (
                            <span className="ml-auto rounded-full bg-primary px-2 py-0.5 text-xs text-primary-foreground">
                              {item.badge}
                            </span>
                          )}
                        </>
                      )}
                    </Button>
                  </Link>
                </TooltipTrigger>
                {isCollapsed && (
                  <TooltipContent side="right">
                    <p>{item.title}</p>
                  </TooltipContent>
                )}
              </Tooltip>
            )
          })}
        </nav>

        <Separator />

        {/* User Section */}
        <div className="p-2">
          <Tooltip delayDuration={0}>
            <TooltipTrigger asChild>
              <div className={cn(
                "flex items-center space-x-2 rounded-lg p-2 hover:bg-accent",
                isCollapsed && "justify-center"
              )}>
                <div className="flex h-8 w-8 items-center justify-center rounded-full bg-primary text-primary-foreground">
                  <User className="h-4 w-4" />
                </div>
                {!isCollapsed && (
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">
                      {user?.full_name || user?.username}
                    </p>
                    <p className="text-xs text-muted-foreground truncate">
                      {user?.email}
                    </p>
                  </div>
                )}
              </div>
            </TooltipTrigger>
            {isCollapsed && (
              <TooltipContent side="right">
                <p>{user?.full_name || user?.username}</p>
                <p className="text-xs text-muted-foreground">{user?.email}</p>
              </TooltipContent>
            )}
          </Tooltip>

          <Tooltip delayDuration={0}>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                onClick={logout}
                className={cn(
                  "w-full mt-2",
                  isCollapsed ? "justify-center px-2" : "justify-start"
                )}
              >
                <LogOut className={cn("h-4 w-4", !isCollapsed && "mr-2")} />
                {!isCollapsed && "Logout"}
              </Button>
            </TooltipTrigger>
            {isCollapsed && (
              <TooltipContent side="right">
                <p>Logout</p>
              </TooltipContent>
            )}
          </Tooltip>
        </div>

        {/* Toggle Button */}
        <Button
          variant="ghost"
          size="sm"
          onClick={toggleSidebar}
          className="absolute -right-3 top-20 h-6 w-6 rounded-full border bg-background p-0 shadow-md"
        >
          {isCollapsed ? (
            <ChevronRight className="h-3 w-3" />
          ) : (
            <ChevronLeft className="h-3 w-3" />
          )}
        </Button>
      </div>
    </TooltipProvider>
  )
}
