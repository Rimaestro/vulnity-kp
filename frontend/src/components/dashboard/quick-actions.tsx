import { 
  Plus, 
  Search, 
  FileText, 
  Settings, 
  Upload,
  Download,
  RefreshCw,
  Zap
} from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'

interface QuickAction {
  title: string
  description: string
  icon: React.ComponentType<{ className?: string }>
  onClick: () => void
  variant?: 'default' | 'secondary' | 'outline' | 'destructive'
  disabled?: boolean
}

interface QuickActionsProps {
  onNewScan?: () => void
  onViewScans?: () => void
  onViewReports?: () => void
  onSettings?: () => void
  onImportData?: () => void
  onExportData?: () => void
  onRefreshData?: () => void
  isRefreshing?: boolean
}

export function QuickActions({
  onNewScan,
  onViewScans,
  onViewReports,
  onSettings,
  onImportData,
  onExportData,
  onRefreshData,
  isRefreshing = false
}: QuickActionsProps) {
  const primaryActions: QuickAction[] = [
    {
      title: 'New Scan',
      description: 'Mulai vulnerability scan baru',
      icon: Plus,
      onClick: () => onNewScan?.(),
      variant: 'default'
    },
    {
      title: 'View Scans',
      description: 'Lihat semua scan yang ada',
      icon: Search,
      onClick: () => onViewScans?.(),
      variant: 'outline'
    },
    {
      title: 'Reports',
      description: 'Akses laporan dan analytics',
      icon: FileText,
      onClick: () => onViewReports?.(),
      variant: 'outline'
    }
  ]

  const secondaryActions: QuickAction[] = [
    {
      title: 'Settings',
      description: 'Konfigurasi aplikasi',
      icon: Settings,
      onClick: () => onSettings?.(),
      variant: 'outline'
    },
    {
      title: 'Import Data',
      description: 'Import data dari file',
      icon: Upload,
      onClick: () => onImportData?.(),
      variant: 'outline'
    },
    {
      title: 'Export Data',
      description: 'Export data ke file',
      icon: Download,
      onClick: () => onExportData?.(),
      variant: 'outline'
    }
  ]

  return (
    <div className="space-y-6">
      {/* Primary Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Zap className="h-5 w-5 mr-2" />
            Quick Actions
          </CardTitle>
          <CardDescription>
            Aksi cepat untuk tugas-tugas umum
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-3">
            {primaryActions.map((action, index) => {
              const Icon = action.icon
              return (
                <Button
                  key={index}
                  variant={action.variant}
                  onClick={action.onClick}
                  disabled={action.disabled}
                  className="h-auto p-4 flex flex-col items-start space-y-2"
                >
                  <div className="flex items-center space-x-2">
                    <Icon className="h-5 w-5" />
                    <span className="font-medium">{action.title}</span>
                  </div>
                  <span className="text-xs text-left opacity-80">
                    {action.description}
                  </span>
                </Button>
              )
            })}
          </div>
        </CardContent>
      </Card>

      {/* Secondary Actions */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Additional Actions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {secondaryActions.map((action, index) => {
              const Icon = action.icon
              return (
                <Button
                  key={index}
                  variant="ghost"
                  onClick={action.onClick}
                  disabled={action.disabled}
                  className="w-full justify-start h-auto p-3"
                >
                  <Icon className="h-4 w-4 mr-3" />
                  <div className="flex flex-col items-start">
                    <span className="font-medium">{action.title}</span>
                    <span className="text-xs text-muted-foreground">
                      {action.description}
                    </span>
                  </div>
                </Button>
              )
            })}
            
            <Separator className="my-2" />
            
            {/* Refresh Action */}
            <Button
              variant="ghost"
              onClick={onRefreshData}
              disabled={isRefreshing}
              className="w-full justify-start h-auto p-3"
            >
              <RefreshCw className={`h-4 w-4 mr-3 ${isRefreshing ? 'animate-spin' : ''}`} />
              <div className="flex flex-col items-start">
                <span className="font-medium">
                  {isRefreshing ? 'Refreshing...' : 'Refresh Data'}
                </span>
                <span className="text-xs text-muted-foreground">
                  {isRefreshing ? 'Memperbarui data...' : 'Perbarui semua data dashboard'}
                </span>
              </div>
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

// Compact version for smaller spaces
interface CompactQuickActionsProps {
  onNewScan?: () => void
  onViewScans?: () => void
  onRefreshData?: () => void
  isRefreshing?: boolean
}

export function CompactQuickActions({
  onNewScan,
  onViewScans,
  onRefreshData,
  isRefreshing = false
}: CompactQuickActionsProps) {
  return (
    <div className="flex items-center space-x-2">
      <Button onClick={onNewScan} size="sm">
        <Plus className="h-4 w-4 mr-2" />
        New Scan
      </Button>
      <Button onClick={onViewScans} variant="outline" size="sm">
        <Search className="h-4 w-4 mr-2" />
        View All
      </Button>
      <Button 
        onClick={onRefreshData} 
        variant="ghost" 
        size="sm"
        disabled={isRefreshing}
      >
        <RefreshCw className={`h-4 w-4 ${isRefreshing ? 'animate-spin' : ''}`} />
      </Button>
    </div>
  )
}
