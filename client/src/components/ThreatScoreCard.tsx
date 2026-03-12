import React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { RiskGauge } from "@/components/RiskGauge";

interface ThreatScoreCardProps {
  riskScore: number;
  verdict: string;
  confidence: number;
  input: string;
}

export const ThreatScoreCard: React.FC<ThreatScoreCardProps> = ({
  riskScore,
  verdict,
  confidence,
  input,
}) => {
  const verdictColor = {
    malicious: "text-red-400",
    suspicious: "text-yellow-400",
    benign: "text-green-400",
    unknown: "text-slate-400",
  }[verdict] || "text-slate-400";

  const verdictBg = {
    malicious: "bg-red-950",
    suspicious: "bg-yellow-950",
    benign: "bg-green-950",
    unknown: "bg-slate-800",
  }[verdict] || "bg-slate-800";

  return (
    <Card className="bg-slate-900 border-slate-700">
      <CardHeader>
        <CardTitle className="text-lg">Threat Assessment</CardTitle>
        <CardDescription className="text-slate-400">
          Analysis for: <span className="font-mono text-slate-200">{input}</span>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="flex gap-8">
          {/* Risk Score Gauge */}
          <div className="flex-1 flex justify-center">
            <RiskGauge score={riskScore} size="lg" />
          </div>

          {/* Verdict & Confidence */}
          <div className="flex-1 space-y-4">
            <div>
              <p className="text-slate-400 text-sm uppercase tracking-wider mb-2">
                Verdict
              </p>
              <div className={`${verdictBg} ${verdictColor} px-4 py-2 rounded-md text-lg font-bold`}>
                {verdict.toUpperCase()}
              </div>
            </div>

            <div>
              <p className="text-slate-400 text-sm uppercase tracking-wider mb-2">
                Confidence
              </p>
              <div className="space-y-1">
                <div className="flex justify-between text-sm">
                  <span className="text-slate-300">{Math.round(confidence * 100)}%</span>
                  <span className="text-slate-500">Analysis Confidence</span>
                </div>
                <div className="w-full bg-slate-700 rounded-full h-2">
                  <div
                    className="bg-emerald-500 h-2 rounded-full transition-all"
                    style={{ width: `${confidence * 100}%` }}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
