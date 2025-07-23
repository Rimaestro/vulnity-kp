import { useNavigate } from 'react-router-dom'
import { ArrowLeft, Shield } from 'lucide-react'
import { DashboardLayout, DashboardHeader, DashboardContent } from '@/components/dashboard/dashboard-layout'
import { ScanForm } from '@/components/scanner/scan-form'
import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { useToast } from '@/hooks/use-toast'

export function NewScanPage() {
  const navigate = useNavigate()
  const { toast } = useToast()

  const handleScanSuccess = (scanId: string) => {
    toast({
      title: "Scan Created Successfully",
      description: `Scan has been created and started. Scan ID: ${scanId}`,
    })
    // Navigate back to scans page
    navigate('/dashboard/scans')
  }

  const handleCancel = () => {
    navigate('/dashboard/scans')
  }

  return (
    <DashboardLayout>
      <DashboardHeader
        breadcrumbs={[
          { title: "Dashboard", href: "/dashboard" },
          { title: "Scans", href: "/dashboard/scans" },
          { title: "New Scan" }
        ]}
        actions={
          <Button variant="outline" onClick={handleCancel}>
            <ArrowLeft className="mr-2 h-4 w-4" />
            Back to Scans
          </Button>
        }
      />

      <DashboardContent className="max-w-none">
        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-center space-x-3 mb-2">
            <div className="p-2 bg-primary/10 rounded-lg">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Create New Vulnerability Scan</h1>
              <p className="text-muted-foreground">
                Configure and start a comprehensive security scan for your target application
              </p>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="max-w-7xl mx-auto">
          <Card className="border-0 shadow-lg">
            <CardContent className="p-8">
              <ScanForm
                onSuccess={handleScanSuccess}
                onCancel={handleCancel}
                isModal={false}
              />
            </CardContent>
          </Card>
        </div>
      </DashboardContent>
    </DashboardLayout>
  )
}
