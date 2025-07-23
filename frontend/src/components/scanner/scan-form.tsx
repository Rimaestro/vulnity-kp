import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { zodResolver } from '@hookform/resolvers/zod'
import * as z from 'zod'
import { Loader2, Globe, Settings, Shield, ChevronDown } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'

import { Textarea } from '@/components/ui/textarea'
import { Checkbox } from '@/components/ui/checkbox'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form'
import { Badge } from '@/components/ui/badge'
import { useToast } from '@/hooks/use-toast'

import { scanApi } from '@/lib/api'
import type { ScanRequest } from '@/types/api'
import type { ScanType } from '@/types/scanner'

// Form validation schema
const scanFormSchema = z.object({
  target_url: z.string().min(1, 'URL is required').refine((val) => {
    try {
      new URL(val)
      return true
    } catch {
      return false
    }
  }, { message: 'Please enter a valid URL' }),
  scan_name: z.string().min(1, 'Scan name is required').max(255, 'Scan name too long'),
  description: z.string().max(1000, 'Description too long').optional(),
  scan_types: z.array(z.string()).min(1, 'Select at least one scan type'),
  max_depth: z.number().min(1, 'Minimum depth is 1').max(10, 'Maximum depth is 10'),
  max_requests: z.number().min(1, 'Minimum requests is 1').max(10000, 'Maximum requests is 10000'),
  request_delay: z.number().min(0.1, 'Minimum delay is 0.1 seconds').max(10, 'Maximum delay is 10 seconds'),
})

type ScanFormValues = z.infer<typeof scanFormSchema>

// Available scan types
const availableScanTypes: ScanType[] = [
  {
    id: 'sql_injection',
    name: 'SQL Injection',
    description: 'Detect SQL injection vulnerabilities in forms and parameters',
    enabled: true,
    risk_level: 'high'
  },
  {
    id: 'xss',
    name: 'Cross-Site Scripting (XSS)',
    description: 'Detect reflected, stored, and DOM-based XSS vulnerabilities',
    enabled: true, // Now implemented!
    risk_level: 'high'
  },
  {
    id: 'csrf',
    name: 'Cross-Site Request Forgery',
    description: 'Test for CSRF protection mechanisms',
    enabled: false, // Not implemented yet
    risk_level: 'medium'
  }
]

interface ScanFormProps {
  onSuccess?: (scanId: string) => void
  onCancel?: () => void
  isModal?: boolean
}

export function ScanForm({ onSuccess, onCancel, isModal = false }: ScanFormProps) {
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [isAdvancedOpen, setIsAdvancedOpen] = useState(false)
  const { toast } = useToast()

  const form = useForm<ScanFormValues>({
    resolver: zodResolver(scanFormSchema),
    defaultValues: {
      target_url: '',
      scan_name: '',
      description: '',
      scan_types: ['sql_injection', 'xss'], // Default to SQL injection and XSS
      max_depth: 3,
      max_requests: 1000,
      request_delay: 1.0,
    },
  })

  const onSubmit = async (values: ScanFormValues) => {
    try {
      setIsSubmitting(true)

      const scanRequest: ScanRequest = {
        target_url: values.target_url,
        scan_name: values.scan_name,
        description: values.description,
        scan_types: values.scan_types,
        max_depth: values.max_depth,
        max_requests: values.max_requests,
      }

      const response = await scanApi.startScan(scanRequest)
      
      toast({
        title: "Scan Started",
        description: `Scan "${values.scan_name}" has been started successfully.`,
      })

      if (onSuccess && response.data?.scan_id) {
        onSuccess(response.data.scan_id)
      }

      // Reset form
      form.reset()
      
    } catch (error: any) {
      console.error('Failed to start scan:', error)
      toast({
        title: "Error",
        description: error.response?.data?.detail || "Failed to start scan. Please try again.",
        variant: "destructive",
      })
    } finally {
      setIsSubmitting(false)
    }
  }



  if (isModal) {
    return (
      <Card className="border-0 shadow-none">
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5" />
            <span>New Vulnerability Scan</span>
          </CardTitle>
          <CardDescription>
            Configure and start a new vulnerability scan for your target
          </CardDescription>
        </CardHeader>
        <CardContent>
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
            {/* Horizontal Layout Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-16">
              {/* Left Column */}
              <div className="space-y-6">
                {/* Target Information */}
                <div className="space-y-4">
                  <div className="flex items-center space-x-2">
                    <Globe className="h-5 w-5" />
                    <h3 className="text-lg font-semibold">Target Information</h3>
                  </div>

                  <FormField
                    control={form.control}
                    name="target_url"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Target URL</FormLabel>
                        <FormControl>
                          <Input placeholder="https://example.com" {...field} />
                        </FormControl>
                        <FormDescription>
                          The URL of the website or application to scan
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="scan_name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Scan Name</FormLabel>
                        <FormControl>
                          <Input placeholder="My Website Scan" {...field} />
                        </FormControl>
                        <FormDescription>
                          A descriptive name for this scan
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="description"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel>Description (Optional)</FormLabel>
                        <FormControl>
                          <Textarea
                            placeholder="Additional notes about this scan..."
                            className="resize-none"
                            {...field}
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                {/* Advanced Settings - Collapsible */}
                <div className="space-y-4">
                  <div
                    className="flex items-center justify-between cursor-pointer"
                    onClick={() => setIsAdvancedOpen(!isAdvancedOpen)}
                  >
                    <div className="flex items-center space-x-2">
                      <Settings className="h-5 w-5" />
                      <h3 className="text-lg font-semibold">Advanced Settings</h3>
                    </div>
                    <ChevronDown
                      className={`h-4 w-4 transition-transform duration-200 ${
                        isAdvancedOpen ? 'rotate-180' : ''
                      }`}
                    />
                  </div>

                  {isAdvancedOpen && (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
                      <FormField
                        control={form.control}
                        name="max_depth"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Max Depth</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={1}
                                max={10}
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value))}
                              />
                            </FormControl>
                            <FormDescription>
                              Maximum crawling depth
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="max_requests"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Max Requests</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={1}
                                max={10000}
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value))}
                              />
                            </FormControl>
                            <FormDescription>
                              Maximum number of requests
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="request_delay"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel>Request Delay (s)</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={0.1}
                                max={10}
                                step={0.1}
                                {...field}
                                onChange={(e) => field.onChange(parseFloat(e.target.value))}
                              />
                            </FormControl>
                            <FormDescription>
                              Delay between requests
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                  )}
                </div>
              </div>

              {/* Right Column */}
              <div>
                {/* Scan Types */}
                <div className="space-y-4">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-5 w-5" />
                    <h3 className="text-lg font-semibold">Scan Types</h3>
                  </div>

                  <FormField
                    control={form.control}
                    name="scan_types"
                    render={() => (
                      <FormItem>
                        <FormDescription>
                          Select the types of vulnerabilities to scan for
                        </FormDescription>
                        <div className="space-y-6">
                          {availableScanTypes.map((scanType) => (
                            <FormField
                              key={scanType.id}
                              control={form.control}
                              name="scan_types"
                              render={({ field }) => {
                                return (
                                  <div
                                    key={scanType.id}
                                    className={`p-6 bg-muted/50 border rounded-lg transition-colors ${
                                      !scanType.enabled ? 'opacity-60' : 'hover:bg-muted/80'
                                    }`}
                                  >
                                    <FormItem className="flex flex-row items-start space-x-3 space-y-0">
                                      <FormControl>
                                        <Checkbox
                                          checked={field.value?.includes(scanType.id)}
                                          disabled={!scanType.enabled}
                                          onCheckedChange={(checked) => {
                                            return checked
                                              ? field.onChange([...field.value, scanType.id])
                                              : field.onChange(
                                                  field.value?.filter(
                                                    (value) => value !== scanType.id
                                                  )
                                                )
                                          }}
                                        />
                                      </FormControl>
                                      <div className="flex-1 space-y-1 leading-none">
                                        <div className="flex items-center justify-between">
                                          <FormLabel className={!scanType.enabled ? 'text-muted-foreground' : ''}>
                                            {scanType.name}
                                          </FormLabel>
                                          <div className="flex items-center space-x-2">
                                            <Badge variant={
                                              scanType.risk_level === 'high' ? 'destructive' :
                                              scanType.risk_level === 'medium' ? 'default' : 'secondary'
                                            }>
                                              {scanType.risk_level}
                                            </Badge>
                                            {!scanType.enabled && (
                                              <Badge variant="outline">Coming Soon</Badge>
                                            )}
                                          </div>
                                        </div>
                                        <FormDescription className={!scanType.enabled ? 'text-muted-foreground' : ''}>
                                          {scanType.description}
                                        </FormDescription>
                                      </div>
                                    </FormItem>
                                  </div>
                                )
                              }}
                            />
                          ))}
                        </div>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>
              </div>
            </div>

            {/* Form Actions */}
            <div className="flex justify-end space-x-2 pt-6 border-t">
              {onCancel && (
                <Button type="button" variant="outline" onClick={onCancel}>
                  Cancel
                </Button>
              )}
              <Button type="submit" disabled={isSubmitting}>
                {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {isSubmitting ? 'Starting Scan...' : 'Start Scan'}
              </Button>
            </div>
          </form>
        </Form>
        </CardContent>
      </Card>
    )
  }

  // Full page mode
  return (
      <div className="w-full">
        <Form {...form}>
          <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-8">
            {/* Horizontal Layout Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-16">
              {/* Left Column */}
              <div className="space-y-8">
                {/* Target Information */}
                <div className="space-y-6">
                  <div className="flex items-center space-x-2">
                    <Globe className="h-6 w-6" />
                    <h3 className="text-xl font-semibold">Target Information</h3>
                  </div>

                  <FormField
                    control={form.control}
                    name="target_url"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-base">Target URL</FormLabel>
                        <FormControl>
                          <Input
                            placeholder="https://example.com"
                            {...field}
                            className="h-12 text-base"
                          />
                        </FormControl>
                        <FormDescription className="text-sm">
                          The URL of the website or application to scan
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="scan_name"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-base">Scan Name</FormLabel>
                        <FormControl>
                          <Input
                            placeholder="My Website Scan"
                            {...field}
                            className="h-12 text-base"
                          />
                        </FormControl>
                        <FormDescription className="text-sm">
                          A descriptive name for this scan
                        </FormDescription>
                        <FormMessage />
                      </FormItem>
                    )}
                  />

                  <FormField
                    control={form.control}
                    name="description"
                    render={({ field }) => (
                      <FormItem>
                        <FormLabel className="text-base">Description (Optional)</FormLabel>
                        <FormControl>
                          <Textarea
                            placeholder="Additional notes about this scan..."
                            {...field}
                            className="min-h-[100px] text-base"
                          />
                        </FormControl>
                        <FormMessage />
                      </FormItem>
                    )}
                  />
                </div>

                {/* Advanced Settings */}
                <div className="space-y-4">
                  <div
                    className="flex items-center justify-between cursor-pointer"
                    onClick={() => setIsAdvancedOpen(!isAdvancedOpen)}
                  >
                    <div className="flex items-center space-x-2">
                      <Settings className="h-6 w-6" />
                      <h3 className="text-xl font-semibold">Advanced Settings</h3>
                    </div>
                    <ChevronDown
                      className={`h-5 w-5 transition-transform ${isAdvancedOpen ? 'rotate-180' : ''}`}
                    />
                  </div>

                  {isAdvancedOpen && (
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-6 pt-4">
                      <FormField
                        control={form.control}
                        name="max_depth"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-base">Max Depth</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={1}
                                max={10}
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value))}
                                className="h-12 text-base"
                              />
                            </FormControl>
                            <FormDescription className="text-sm">
                              Maximum crawling depth
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="max_requests"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-base">Max Requests</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={1}
                                max={10000}
                                {...field}
                                onChange={(e) => field.onChange(parseInt(e.target.value))}
                                className="h-12 text-base"
                              />
                            </FormControl>
                            <FormDescription className="text-sm">
                              Maximum number of requests
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />

                      <FormField
                        control={form.control}
                        name="request_delay"
                        render={({ field }) => (
                          <FormItem>
                            <FormLabel className="text-base">Request Delay (s)</FormLabel>
                            <FormControl>
                              <Input
                                type="number"
                                min={0.1}
                                max={10}
                                step={0.1}
                                {...field}
                                onChange={(e) => field.onChange(parseFloat(e.target.value))}
                                className="h-12 text-base"
                              />
                            </FormControl>
                            <FormDescription className="text-sm">
                              Delay between requests
                            </FormDescription>
                            <FormMessage />
                          </FormItem>
                        )}
                      />
                    </div>
                  )}
                </div>
              </div>

              {/* Right Column */}
              <div className="space-y-6">
                {/* Scan Types */}
                <div className="space-y-6">
                  <div className="flex items-center space-x-2">
                    <Shield className="h-6 w-6" />
                    <h3 className="text-xl font-semibold">Scan Types</h3>
                  </div>

                  <div className="space-y-4">
                    <p className="text-muted-foreground">
                      Select the types of vulnerabilities to scan for
                    </p>

                    <FormField
                      control={form.control}
                      name="scan_types"
                      render={() => (
                        <FormItem>
                          <div className="space-y-6">
                            {availableScanTypes.map((scanType) => (
                              <FormField
                                key={scanType.id}
                                control={form.control}
                                name="scan_types"
                                render={({ field }) => {
                                  return (
                                    <FormItem
                                      key={scanType.id}
                                      className="flex flex-row items-start space-x-3 space-y-0"
                                    >
                                      <div
                                        key={scanType.id}
                                        className={`p-6 bg-muted/50 border rounded-lg transition-colors w-full ${
                                          !scanType.enabled ? 'opacity-60' : 'hover:bg-muted/80'
                                        }`}
                                      >
                                        <div className="flex items-start space-x-3">
                                          <FormControl>
                                            <Checkbox
                                              checked={field.value?.includes(scanType.id)}
                                              onCheckedChange={(checked) => {
                                                return checked
                                                  ? field.onChange([...field.value, scanType.id])
                                                  : field.onChange(
                                                      field.value?.filter(
                                                        (value) => value !== scanType.id
                                                      )
                                                    )
                                              }}
                                              disabled={!scanType.enabled}
                                            />
                                          </FormControl>
                                          <div className="flex-1 min-w-0">
                                            <div className="flex items-center justify-between mb-2">
                                              <FormLabel className="text-base font-medium cursor-pointer">
                                                {scanType.name}
                                              </FormLabel>
                                              <div className="flex items-center space-x-2">
                                                <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                                                  scanType.risk_level === 'high'
                                                    ? 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                                                    : 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200'
                                                }`}>
                                                  {scanType.risk_level}
                                                </span>
                                                {!scanType.enabled && (
                                                  <span className="px-2 py-1 text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-800 dark:text-gray-200 rounded-full">
                                                    Coming Soon
                                                  </span>
                                                )}
                                              </div>
                                            </div>
                                            <p className="text-sm text-muted-foreground">
                                              {scanType.description}
                                            </p>
                                          </div>
                                        </div>
                                      </div>
                                    </FormItem>
                                  )
                                }}
                              />
                            ))}
                          </div>
                          <FormMessage />
                        </FormItem>
                      )}
                    />
                  </div>
                </div>
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex justify-end space-x-4 pt-8 border-t">
              {onCancel && (
                <Button type="button" variant="outline" onClick={onCancel} size="lg">
                  Cancel
                </Button>
              )}
              <Button type="submit" disabled={isSubmitting} size="lg">
                {isSubmitting && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {isSubmitting ? 'Starting Scan...' : 'Start Scan'}
              </Button>
            </div>
          </form>
        </Form>
    </div>
  )
}
