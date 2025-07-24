

// Only import what is used
import { AreaChart, Area, BarChart, Bar, LineChart, Line, XAxis, YAxis, CartesianGrid } from "recharts";
import { motion } from "framer-motion";
import { TrendingUp, TrendingDown, Activity, Shield, AlertTriangle, Clock } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent } from "@/components/ui/chart";
import { useAnalyticsTrends } from "@/hooks/use-analytics-trends";

type AnalyticsDashboardProps = {
  className?: string;
};



const chartConfig = {
  critical: {
    label: "Critical",
    color: "hsl(var(--destructive))",
  },
  high: {
    label: "High", 
    color: "hsl(346 87% 43%)",
  },
  medium: {
    label: "Medium",
    color: "hsl(32 95% 44%)",
  },
  low: {
    label: "Low",
    color: "hsl(60 91% 45%)",
  },
  scans: {
    label: "Scans",
    color: "hsl(var(--primary))",
  },
  vulnerabilities: {
    label: "Vulnerabilities",
    color: "hsl(var(--destructive))",
  },
  fixed: {
    label: "Fixed",
    color: "hsl(142 76% 36%)",
  },
  total: {
    label: "Total",
    color: "hsl(var(--muted-foreground))",
  },
}


export function AnalyticsDashboard({ className }: AnalyticsDashboardProps) {
  const { vulnTrend, scanTrend, fixrateTrend, loading, error } = useAnalyticsTrends();

  // Calculate stats from trend data
  const lastVuln = vulnTrend?.length ? vulnTrend[vulnTrend.length - 1] : null;
  const prevVuln = vulnTrend && vulnTrend.length > 1 ? vulnTrend[vulnTrend.length - 2] : null;
  const totalVulnerabilities = lastVuln ? lastVuln.critical + lastVuln.high + lastVuln.medium + lastVuln.low : 0;
  const prevTotalVulnerabilities = prevVuln ? prevVuln.critical + prevVuln.high + prevVuln.medium + prevVuln.low : 0;
  const vulnerabilityTrend = prevTotalVulnerabilities > 0 ? ((totalVulnerabilities - prevTotalVulnerabilities) / prevTotalVulnerabilities) * 100 : 0;

  const lastScan = scanTrend?.length ? scanTrend[scanTrend.length - 1] : null;
  const prevScan = scanTrend && scanTrend.length > 1 ? scanTrend[scanTrend.length - 2] : null;
  const scanTrendValue = prevScan && lastScan && prevScan.scans > 0 ? ((lastScan.scans - prevScan.scans) / prevScan.scans) * 100 : 0;

  const lastFix = fixrateTrend?.length ? fixrateTrend[fixrateTrend.length - 1] : null;
  const fixRate = lastFix && lastFix.total > 0 ? Math.round((lastFix.fixed / lastFix.total) * 100) : 0;
  const fixedVulnerabilities = lastFix ? lastFix.fixed : 0;
  const totalFound = lastFix ? lastFix.total : 0;

  if (loading) return <div className={cn("space-y-6", className)}>Loading analytics...</div>;
  if (error) return <div className={cn("space-y-6", className)}>Error loading analytics: {error}</div>;

  return (
    <div className={cn("space-y-6", className)}>
      {/* Key Metrics Cards */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <Card className="hover-lift">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
              <Activity className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{lastScan?.scans ?? 0}</div>
              <div className="flex items-center space-x-1 text-xs text-muted-foreground">
                <TrendingUp className="h-3 w-3" />
                <span>{scanTrendValue >= 0 ? "+" : "-"}{Math.abs(scanTrendValue).toFixed(1)}% from previous</span>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
        >
          <Card className="hover-lift">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Active Scans</CardTitle>
              <Clock className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">-</div>
              <div className="text-xs text-muted-foreground">
                Currently running
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
        >
          <Card className="hover-lift">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Vulnerabilities</CardTitle>
              <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{totalVulnerabilities}</div>
              <div className="flex items-center space-x-1 text-xs text-muted-foreground">
                {vulnerabilityTrend < 0 ? (
                  <TrendingDown className="h-3 w-3 text-green-500" />
                ) : (
                  <TrendingUp className="h-3 w-3 text-red-500" />
                )}
                <span>{vulnerabilityTrend < 0 ? Math.abs(vulnerabilityTrend).toFixed(1) + "% decrease" : Math.abs(vulnerabilityTrend).toFixed(1) + "% increase"}</span>
              </div>
            </CardContent>
          </Card>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.4 }}
        >
          <Card className="hover-lift">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Fix Rate</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{fixRate}%</div>
              <div className="text-xs text-muted-foreground">
                {fixedVulnerabilities} of {totalFound} fixed
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Charts Grid */}
      <div className="grid gap-6 md:grid-cols-2">
        {/* Vulnerability Trend Chart */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.5 }}
        >
          <Card className="hover-lift">
            <CardHeader>
              <CardTitle>Vulnerability Trends</CardTitle>
              <CardDescription>
                Monthly vulnerability distribution by severity
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ChartContainer config={chartConfig} className="h-[300px] w-full">
                <AreaChart data={vulnTrend || []}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="month" />
                  <YAxis />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Area
                    type="monotone"
                    dataKey="critical"
                    stackId="1"
                    stroke={chartConfig.critical.color}
                    fill={chartConfig.critical.color}
                    fillOpacity={0.8}
                  />
                  <Area
                    type="monotone"
                    dataKey="high"
                    stackId="1"
                    stroke={chartConfig.high.color}
                    fill={chartConfig.high.color}
                    fillOpacity={0.8}
                  />
                  <Area
                    type="monotone"
                    dataKey="medium"
                    stackId="1"
                    stroke={chartConfig.medium.color}
                    fill={chartConfig.medium.color}
                    fillOpacity={0.8}
                  />
                  <Area
                    type="monotone"
                    dataKey="low"
                    stackId="1"
                    stroke={chartConfig.low.color}
                    fill={chartConfig.low.color}
                    fillOpacity={0.8}
                  />
                </AreaChart>
              </ChartContainer>
            </CardContent>
          </Card>
        </motion.div>

        {/* Scan Activity Chart */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.6 }}
        >
          <Card className="hover-lift">
            <CardHeader>
              <CardTitle>Weekly Scan Activity</CardTitle>
              <CardDescription>
                Daily scans and vulnerabilities found
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ChartContainer config={chartConfig} className="h-[300px] w-full">
                <BarChart data={scanTrend || []}>
                  <XAxis dataKey="week" />
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="day" />
                  <YAxis />
                  <ChartTooltip content={<ChartTooltipContent />} />
                  <Bar
                    dataKey="scans"
                    fill={chartConfig.scans.color}
                    radius={[4, 4, 0, 0]}
                  />
                  <Bar
                    dataKey="vulnerabilities"
                    fill={chartConfig.vulnerabilities.color}
                    radius={[4, 4, 0, 0]}
                  />
                </BarChart>
              </ChartContainer>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Fix Rate Trend */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3, delay: 0.7 }}
      >
        <Card className="hover-lift">
          <CardHeader>
            <CardTitle>Vulnerability Fix Rate Trend</CardTitle>
            <CardDescription>
              Monthly progress on fixing vulnerabilities
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ChartContainer config={chartConfig} className="h-[300px] w-full">
              <LineChart data={fixrateTrend || []}>
                <CartesianGrid strokeDasharray="3 3" />
                <XAxis dataKey="month" />
                <YAxis />
                <ChartTooltip content={<ChartTooltipContent />} />
                <Line
                  type="monotone"
                  dataKey="fixed"
                  stroke={chartConfig.fixed.color}
                  strokeWidth={2}
                  dot={{ fill: chartConfig.fixed.color, strokeWidth: 2, r: 4 }}
                />
                <Line
                  type="monotone"
                  dataKey="total"
                  stroke={chartConfig.total.color}
                  strokeWidth={2}
                  strokeDasharray="5 5"
                  dot={{ fill: chartConfig.total.color, strokeWidth: 2, r: 4 }}
                />
              </LineChart>
            </ChartContainer>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  )
}
