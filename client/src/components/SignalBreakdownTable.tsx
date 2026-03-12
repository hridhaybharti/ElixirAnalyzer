import React from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";

interface Signal {
  name: string;
  weight?: number;
  impact?: number;
  reason?: string;
  description?: string;
  confidence?: number;
  bucket?: string;
}

interface SignalBreakdownTableProps {
  signals: Signal[];
}

export const SignalBreakdownTable: React.FC<SignalBreakdownTableProps> = ({ signals }) => {
  const riskSignals = signals.filter((s) => (s.impact || 0) > 0);
  const trustSignals = signals.filter((s) => (s.impact || 0) < 0);
  const neutralSignals = signals.filter((s) => (s.impact || 0) === 0);

  const getImpactColor = (impact?: number) => {
    if (!impact) return "bg-slate-700";
    if (impact > 20) return "bg-red-900";
    if (impact > 10) return "bg-orange-900";
    if (impact > 0) return "bg-yellow-900";
    return "bg-green-900";
  };

  const getBucketBadgeVariant = (bucket?: string) => {
    switch (bucket) {
      case "reputation":
        return "destructive";
      case "structure":
        return "secondary";
      case "network":
        return "default";
      default:
        return "outline";
    }
  };

  const renderSignalSection = (title: string, items: Signal[]) => (
    <>
      {items.length > 0 && (
        <div className="mb-4">
          <p className="text-sm font-semibold text-slate-300 mb-2">{title}</p>
          <Table>
            <TableBody>
              {items.map((signal, idx) => (
                <TableRow key={`${signal.name}-${idx}`} className="border-slate-700 hover:bg-slate-800">
                  <TableCell className="font-medium text-slate-200 text-sm">
                    {signal.name}
                  </TableCell>
                  <TableCell>
                    {signal.bucket && (
                      <Badge variant={getBucketBadgeVariant(signal.bucket)}>
                        {signal.bucket}
                      </Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className={`px-3 py-1 rounded text-sm font-bold text-center ${getImpactColor(signal.impact)}`}>
                      {signal.impact ? (signal.impact > 0 ? "+" : "") + signal.impact : "0"}
                    </div>
                  </TableCell>
                  <TableCell className="text-slate-400 text-xs">{signal.description || signal.reason}</TableCell>
                  <TableCell className="text-right">
                    {signal.confidence !== undefined && (
                      <span className="text-xs text-slate-400">
                        {Math.round((signal.confidence || 0) * 100)}%
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </>
  );

  return (
    <Card className="bg-slate-900 border-slate-700">
      <CardHeader>
        <CardTitle className="text-lg">Signal Breakdown</CardTitle>
        <CardDescription className="text-slate-400">
          {signals.length} signals analyzed across reputation, structure, and network
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {renderSignalSection("⚠️ Risk Signals", riskSignals)}
        {renderSignalSection("✓ Trust Signals", trustSignals)}
        {renderSignalSection("○ Neutral Signals", neutralSignals)}
      </CardContent>
    </Card>
  );
};
