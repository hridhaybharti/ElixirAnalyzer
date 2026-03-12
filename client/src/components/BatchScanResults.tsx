import React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { RiskGauge } from "@/components/RiskGauge";

interface AnalysisResult {
  target: string;
  input: string;
  risk_score: number;
  verdict: string;
  confidence: number;
  error?: string;
}

interface BatchScanResultsProps {
  total: number;
  completed: number;
  maliciousCount: number;
  results: AnalysisResult[];
  latencyMs: number;
}

export const BatchScanResults: React.FC<BatchScanResultsProps> = ({
  total,
  completed,
  maliciousCount,
  results,
  latencyMs,
}) => {
  const progressPercent = total > 0 ? (completed / total) * 100 : 0;

  const getVerdictColor = (verdict: string) => {
    switch (verdict) {
      case "malicious":
        return "bg-red-950 text-red-400";
      case "suspicious":
        return "bg-yellow-950 text-yellow-400";
      case "benign":
        return "bg-green-950 text-green-400";
      case "error":
        return "bg-slate-800 text-slate-400";
      default:
        return "bg-slate-800 text-slate-400";
    }
  };

  const getVerdictBadgeVariant = (verdict: string) => {
    switch (verdict) {
      case "malicious":
        return "destructive";
      case "suspicious":
        return "secondary";
      case "benign":
        return "outline";
      default:
        return "default";
    }
  };

  return (
    <Card className="bg-slate-900 border-slate-700">
      <CardHeader>
        <CardTitle className="text-lg">Batch Scan Results</CardTitle>
        <CardDescription className="text-slate-400">
          Completed in {latencyMs}ms
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {/* Progress and Summary */}
        <div className="space-y-3">
          <div className="flex justify-between text-sm">
            <span className="text-slate-300">
              {completed} of {total} completed
            </span>
            <span className="text-slate-400">{progressPercent.toFixed(0)}%</span>
          </div>
          <Progress value={progressPercent} className="h-2 bg-slate-700" />

          {/* Stats */}
          <div className="grid grid-cols-3 gap-4 pt-2">
            <div className="bg-slate-800 rounded p-3 text-center">
              <div className="text-xs text-slate-400 uppercase">Malicious</div>
              <div className="text-lg font-bold text-red-400">{maliciousCount}</div>
            </div>
            <div className="bg-slate-800 rounded p-3 text-center">
              <div className="text-xs text-slate-400 uppercase">Clean</div>
              <div className="text-lg font-bold text-green-400">
                {completed - maliciousCount}
              </div>
            </div>
            <div className="bg-slate-800 rounded p-3 text-center">
              <div className="text-xs text-slate-400 uppercase">Detection Rate</div>
              <div className="text-lg font-bold text-yellow-400">
                {completed > 0 ? ((maliciousCount / completed) * 100).toFixed(0) : 0}%
              </div>
            </div>
          </div>
        </div>

        {/* Results Table */}
        <div className="space-y-2">
          <p className="text-sm font-semibold text-slate-300">Individual Results</p>
          <div className="space-y-2 max-h-96 overflow-y-auto">
            {results.map((result, idx) => (
              <div
                key={idx}
                className="bg-slate-800 rounded p-3 flex items-center justify-between hover:bg-slate-750 transition"
              >
                <div className="flex-1 min-w-0">
                  <p className="font-mono text-sm text-slate-200 truncate">
                    {result.target}
                  </p>
                  {result.error && (
                    <p className="text-xs text-red-400 mt-1">Error: {result.error}</p>
                  )}
                </div>

                {!result.error && (
                  <div className="flex items-center gap-3 ml-4">
                    <div className="text-center">
                      <div className="text-xs text-slate-400 mb-1">Risk</div>
                      <div className="w-12 h-12 flex items-center justify-center">
                        <RiskGauge score={result.risk_score} size="sm" />
                      </div>
                    </div>
                    <Badge variant={getVerdictBadgeVariant(result.verdict)}>
                      {result.verdict.toUpperCase()}
                    </Badge>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
