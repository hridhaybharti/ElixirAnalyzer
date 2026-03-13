import React from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Brain, Database, Microscope, Zap, Clock, ShieldCheck } from "lucide-react";

interface SandboxSummaryProps {
  aiConfidence: number;
  heuristicScore: number;
  osintScore: number;
  anomalyFlags: string[];
}

export function SandboxSummary({
  aiConfidence,
  heuristicScore,
  osintScore,
  anomalyFlags
}: SandboxSummaryProps) {
  const pillars = [
    {
      name: "AI Inference",
      value: aiConfidence,
      icon: Brain,
      color: "text-purple-400",
      bg: "bg-purple-500/10",
      bar: "bg-purple-500"
    },
    {
      name: "Structural Heuristics",
      value: heuristicScore,
      icon: Microscope,
      color: "text-blue-400",
      bg: "bg-blue-500/10",
      bar: "bg-blue-500"
    },
    {
      name: "OSINT & DNS Intelligence",
      value: osintScore,
      icon: Database,
      color: "text-emerald-400",
      bg: "bg-emerald-500/10",
      bar: "bg-emerald-500"
    }
  ];

  const isStealth = anomalyFlags.includes("STEALTH_THREAT_DETECTED");

  return (
    <Card className="border-slate-800 bg-slate-950/50 backdrop-blur-xl overflow-hidden relative group">
      {isStealth && (
        <div className="absolute top-0 left-0 w-full h-1 bg-rose-500 animate-pulse shadow-[0_0_15px_rgba(244,63,94,0.8)]" />
      )}
      
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-mono uppercase tracking-tighter flex items-center justify-between text-slate-400">
          <div className="flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Hybrid Sandbox Intelligence
          </div>
          {isStealth && (
            <span className="text-[10px] text-rose-500 animate-pulse flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" /> ZERO-DAY DETECTED
            </span>
          )}
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-6">
        <div className="grid gap-4">
          {pillars.map((pillar) => (
            <div key={pillar.name} className="space-y-2">
              <div className="flex justify-between items-center text-xs">
                <div className="flex items-center gap-2">
                  <div className={`p-1 rounded ${pillar.bg}`}>
                    <pillar.icon className={`w-3 h-3 ${pillar.color}`} />
                  </div>
                  <span className="text-slate-300 font-medium">{pillar.name}</span>
                </div>
                <span className={`font-mono ${pillar.color}`}>{Math.round(pillar.value)}%</span>
              </div>
              <Progress value={pillar.value} className="h-1 bg-slate-800" indicatorClassName={pillar.bar} />
            </div>
          ))}
        </div>

        <div className="pt-2 border-t border-slate-800/50 flex flex-col gap-3">
          {anomalyFlags.length > 0 && (
            <div>
              <div className="text-[10px] uppercase text-slate-500 mb-2 font-bold tracking-widest">
                Security Anomalies
              </div>
              <div className="flex flex-wrap gap-2">
                {anomalyFlags.map((flag) => (
                  <Badge 
                    key={flag} 
                    variant="outline" 
                    className="bg-rose-500/10 text-rose-400 border-rose-500/20 text-[10px] animate-in fade-in zoom-in duration-500"
                  >
                    <ShieldAlert className="w-3 h-3 mr-1" />
                    {flag.replace(/_/g, ' ')}
                  </Badge>
                ))}
              </div>
            </div>
          )}
          
          <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono">
            <div className="flex items-center gap-1">
              <Clock className="w-3 h-3" /> SCAN_STAMP: {new Date().toLocaleTimeString()}
            </div>
            <div className="text-emerald-500/60 flex items-center gap-1">
              <ShieldCheck className="w-3 h-3" /> ENGINE_V3_ACTIVE
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}


function ShieldAlert(props: any) {
  return (
    <svg
      {...props}
      xmlns="http://www.w3.org/2000/svg"
      width="24"
      height="24"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10" />
      <path d="M12 8v4" />
      <path d="M12 16h.01" />
    </svg>
  );
}
