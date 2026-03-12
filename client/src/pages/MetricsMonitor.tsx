import React, { useEffect, useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";

interface MetricsData {
  scan_count: number;
  malicious_count: number;
  scan_duration?: {
    avg: number;
    min: number;
    max: number;
  };
  intel_lookup_latency?: {
    avg: number;
    min: number;
    max: number;
  };
  cache_hits: number;
  cache_misses: number;
  cache_hit_rate?: number;
  signal_frequency?: Record<string, number>;
  error_count: number;
  uptime_seconds: number;
  timestamp: string;
}

export default function MetricsMonitor() {
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [lastUpdate, setLastUpdate] = useState<Date | null>(null);
  const [autoRefresh, setAutoRefresh] = useState(true);

  const fetchMetrics = async () => {
    try {
      const response = await fetch("/api/metrics");
      if (!response.ok) {
        throw new Error(`Failed to fetch metrics: ${response.status}`);
      }
      const data = await response.json();
      setMetrics(data);
      setLastUpdate(new Date());
      setError(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMetrics();
    if (!autoRefresh) return;

    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const formatDuration = (seconds: number) => {
    if (seconds < 0.001) return "<1ms";
    if (seconds < 1) return `${(seconds * 1000).toFixed(1)}ms`;
    return `${seconds.toFixed(2)}s`;
  };

  const formatUptime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${secs}s`;
    return `${secs}s`;
  };

  if (loading && !metrics) {
    return (
      <div className="min-h-screen bg-slate-950 text-slate-200 py-8 flex items-center justify-center">
        <div className="text-center">
          <p className="text-lg text-slate-400">Loading metrics...</p>
        </div>
      </div>
    );
  }

  const topSignals = metrics?.signal_frequency
    ? Object.entries(metrics.signal_frequency)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
    : [];

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200 py-8">
      <div className="max-w-6xl mx-auto px-4 space-y-6">
        {/* Header */}
        <div className="flex items-baseline justify-between">
          <div className="space-y-2">
            <h1 className="text-3xl font-bold">Metrics Monitor</h1>
            <p className="text-slate-400">
              Real-time system performance and analysis statistics
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`px-3 py-1 rounded text-sm transition ${
                autoRefresh
                  ? "bg-emerald-600 text-white hover:bg-emerald-700"
                  : "bg-slate-800 text-slate-300 hover:bg-slate-700"
              }`}
            >
              {autoRefresh ? "•" : "◦"} Auto-refresh (5s)
            </button>
            <button
              onClick={fetchMetrics}
              className="px-3 py-1 rounded text-sm bg-slate-800 text-slate-300 hover:bg-slate-700 transition"
            >
              Refresh
            </button>
          </div>
        </div>

        {lastUpdate && (
          <p className="text-xs text-slate-500">
            Last updated: {lastUpdate.toLocaleTimeString()}
          </p>
        )}

        {error && (
          <Alert className="bg-red-900 border-red-700 text-red-200">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {metrics && (
          <>
            {/* Main Metrics Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              {/* Scan Count */}
              <Card className="bg-slate-900 border-slate-700">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-slate-400">Analyses</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-3xl font-bold">{metrics.scan_count}</p>
                  <p className="text-xs text-slate-500 mt-1">Total scans performed</p>
                </CardContent>
              </Card>

              {/* Malicious Count */}
              <Card className="bg-slate-900 border-slate-700">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-slate-400">Malicious</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-3xl font-bold text-red-400">{metrics.malicious_count}</p>
                  <p className="text-xs text-slate-500 mt-1">
                    {metrics.scan_count > 0
                      ? `${((metrics.malicious_count / metrics.scan_count) * 100).toFixed(1)}% detection rate`
                      : "No data"}
                  </p>
                </CardContent>
              </Card>

              {/* Cache Hit Rate */}
              <Card className="bg-slate-900 border-slate-700">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-slate-400">Cache Hit Rate</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-3xl font-bold text-blue-400">
                    {(metrics.cache_hit_rate || 0).toFixed(1)}%
                  </p>
                  <p className="text-xs text-slate-500 mt-1">
                    {metrics.cache_hits} hits, {metrics.cache_misses} misses
                  </p>
                </CardContent>
              </Card>

              {/* Error Count */}
              <Card className="bg-slate-900 border-slate-700">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-slate-400">Errors</CardTitle>
                </CardHeader>
                <CardContent>
                  <p className={`text-3xl font-bold ${metrics.error_count > 0 ? "text-red-400" : "text-green-400"}`}>
                    {metrics.error_count}
                  </p>
                  <p className="text-xs text-slate-500 mt-1">
                    Uptime: {formatUptime(metrics.uptime_seconds)}
                  </p>
                </CardContent>
              </Card>
            </div>

            {/* Performance Metrics */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Scan Duration */}
              {metrics.scan_duration && (
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader>
                    <CardTitle className="text-base">Scan Duration</CardTitle>
                    <CardDescription>Analysis execution time</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-3 gap-2">
                      <div className="bg-slate-800 rounded p-2">
                        <p className="text-xs text-slate-400">Average</p>
                        <p className="text-sm font-bold text-emerald-400">
                          {formatDuration(metrics.scan_duration.avg)}
                        </p>
                      </div>
                      <div className="bg-slate-800 rounded p-2">
                        <p className="text-xs text-slate-400">Min</p>
                        <p className="text-sm font-bold text-blue-400">
                          {formatDuration(metrics.scan_duration.min)}
                        </p>
                      </div>
                      <div className="bg-slate-800 rounded p-2">
                        <p className="text-xs text-slate-400">Max</p>
                        <p className="text-sm font-bold text-red-400">
                          {formatDuration(metrics.scan_duration.max)}
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Intel Lookup Latency */}
              {metrics.intel_lookup_latency && (
                <Card className="bg-slate-900 border-slate-700">
                  <CardHeader>
                    <CardTitle className="text-base">Intel Lookup Latency</CardTitle>
                    <CardDescription>Threat intelligence retrieval time</CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid grid-cols-3 gap-2">
                      <div className="bg-slate-800 rounded p-2">
                        <p className="text-xs text-slate-400">Average</p>
                        <p className="text-sm font-bold text-emerald-400">
                          {formatDuration(metrics.intel_lookup_latency.avg)}
                        </p>
                      </div>
                      <div className="bg-slate-800 rounded p-2">
                        <p className="text-xs text-slate-400">Min</p>
                        <p className="text-sm font-bold text-blue-400">
                          {formatDuration(metrics.intel_lookup_latency.min)}
                        </p>
                      </div>
                      <div className="bg-slate-800 rounded p-2">
                        <p className="text-xs text-slate-400">Max</p>
                        <p className="text-sm font-bold text-red-400">
                          {formatDuration(metrics.intel_lookup_latency.max)}
                        </p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </div>

            {/* Top Signals */}
            {topSignals.length > 0 && (
              <Card className="bg-slate-900 border-slate-700">
                <CardHeader>
                  <CardTitle>Top 10 Most Triggered Signals</CardTitle>
                  <CardDescription>Signal frequency by detection count</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {topSignals.map(([signal, count], idx) => (
                      <div key={signal} className="flex items-center justify-between bg-slate-800 rounded-md p-2">
                        <div className="flex items-center gap-2">
                          <Badge variant="secondary" className="w-6 h-6 flex items-center justify-center p-0">
                            {idx + 1}
                          </Badge>
                          <span className="text-sm">{signal}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          <div className="w-24 h-2 bg-slate-700 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-yellow-500 to-red-500"
                              style={{
                                width: `${Math.min((count / (topSignals[0]?.[1] || 1)) * 100, 100)}%`,
                              }}
                            />
                          </div>
                          <span className="text-sm font-bold text-slate-300 w-12 text-right">{count}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* System Info */}
            <Card className="bg-slate-900 border-slate-700">
              <CardHeader>
                <CardTitle>System Status</CardTitle>
              </CardHeader>
              <CardContent className="grid grid-cols-2 md:grid-cols-4 gap-3">
                <div>
                  <p className="text-xs text-slate-400 uppercase">Uptime</p>
                  <p className="text-sm font-bold">{formatUptime(metrics.uptime_seconds)}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400 uppercase">Cache Hits</p>
                  <p className="text-sm font-bold text-emerald-400">{metrics.cache_hits}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400 uppercase">Cache Misses</p>
                  <p className="text-sm font-bold text-yellow-400">{metrics.cache_misses}</p>
                </div>
                <div>
                  <p className="text-xs text-slate-400 uppercase">Errors</p>
                  <p className={`text-sm font-bold ${metrics.error_count > 0 ? "text-red-400" : "text-green-400"}`}>
                    {metrics.error_count}
                  </p>
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}
