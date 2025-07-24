import { useCallback, useEffect, useState } from "react";
import { analyticsApi } from "@/lib/api";

export type VulnerabilityTrend = {
  month: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
};

export type ScanTrend = {
  week: string;
  scans: number;
  vulnerabilities: number;
};

export type FixrateTrend = {
  month: string;
  fixed: number;
  total: number;
};

export function useAnalyticsTrends() {
  const [vulnTrend, setVulnTrend] = useState<VulnerabilityTrend[] | null>(null);
  const [scanTrend, setScanTrend] = useState<ScanTrend[] | null>(null);
  const [fixrateTrend, setFixrateTrend] = useState<FixrateTrend[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchTrends = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [vulnRes, scanRes, fixrateRes] = await Promise.all([
        analyticsApi.getVulnerabilityTrend(6),
        analyticsApi.getScanTrend(8),
        analyticsApi.getFixrateTrend(6),
      ]);
      
      setVulnTrend(vulnRes.data.trend || []);
      setScanTrend(scanRes.data.trend || []);
      setFixrateTrend(fixrateRes.data.trend || []);
    } catch (e: any) {
      console.error('Analytics fetch error:', e);
      if (e.response?.data?.message) {
        setError(e.response.data.message);
      } else if (e.message) {
        setError(e.message);
      } else {
        setError("Failed to load analytics data");
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchTrends();
  }, [fetchTrends]);

  return { vulnTrend, scanTrend, fixrateTrend, loading, error, refetch: fetchTrends };
}
