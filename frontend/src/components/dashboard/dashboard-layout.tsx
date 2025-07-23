import React from 'react'
import { Outlet } from 'react-router-dom'
import { SidebarProvider, SidebarInset, SidebarTrigger } from "@/components/ui/sidebar"
import { AppSidebar } from "@/components/app-sidebar"
import { Separator } from "@/components/ui/separator"
import {
  Breadcrumb,
  BreadcrumbItem,
  BreadcrumbLink,
  BreadcrumbList,
  BreadcrumbPage,
  BreadcrumbSeparator
} from "@/components/ui/breadcrumb"
import { Toaster } from '@/components/ui/sonner'

interface DashboardLayoutProps {
  children?: React.ReactNode
}

export function DashboardLayout({ children }: DashboardLayoutProps) {
  return (
    <SidebarProvider>
      <AppSidebar />
      <SidebarInset>
        <div className="flex flex-1 flex-col">
          {children || <Outlet />}
        </div>
        {/* Toaster for notifications */}
        <Toaster position="bottom-right" />
      </SidebarInset>
    </SidebarProvider>
  )
}

// Header component for dashboard pages
interface DashboardHeaderProps {
  title?: string
  description?: string
  actions?: React.ReactNode
  breadcrumbs?: Array<{ title: string; href?: string }>
}

export function DashboardHeader({
  title,
  description,
  actions,
  breadcrumbs = [{ title: "Dashboard" }]
}: DashboardHeaderProps) {
  return (
    <header className="flex h-16 shrink-0 items-center gap-2 border-b px-4">
      <SidebarTrigger className="-ml-1" />
      <Separator orientation="vertical" className="mr-2 h-4" />
      <Breadcrumb>
        <BreadcrumbList>
          {breadcrumbs.map((crumb, index) => (
            <React.Fragment key={crumb.title}>
              <BreadcrumbItem className={index === 0 ? "hidden md:block" : ""}>
                {crumb.href && index < breadcrumbs.length - 1 ? (
                  <BreadcrumbLink href={crumb.href}>
                    {crumb.title}
                  </BreadcrumbLink>
                ) : (
                  <BreadcrumbPage>{crumb.title}</BreadcrumbPage>
                )}
              </BreadcrumbItem>
              {index < breadcrumbs.length - 1 && (
                <BreadcrumbSeparator className="hidden md:block" />
              )}
            </React.Fragment>
          ))}
        </BreadcrumbList>
      </Breadcrumb>

      {/* Page Title & Actions */}
      <div className="ml-auto flex items-center space-x-4">
        {(title || description) && (
          <div className="hidden lg:block">
            {title && <h1 className="text-lg font-semibold">{title}</h1>}
            {description && <p className="text-sm text-muted-foreground">{description}</p>}
          </div>
        )}
        {actions && <div className="flex items-center space-x-2">{actions}</div>}
      </div>
    </header>
  )
}

// Content wrapper for dashboard pages
interface DashboardContentProps {
  children: React.ReactNode
  className?: string
}

export function DashboardContent({ children, className = '' }: DashboardContentProps) {
  return (
    <div className={`flex flex-1 flex-col gap-4 p-4 ${className}`}>
      {children}
    </div>
  )
}
