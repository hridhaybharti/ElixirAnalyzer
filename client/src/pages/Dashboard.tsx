import { useState, useEffect } from "react";
import { useLocation } from "wouter";
import { motion } from "framer-motion";
import { useCreateAnalysis, useReputationStatus } from "@/hooks/use-analysis";
import { detectInputType, type InputType } from "@/lib/detectInputType";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip";

import {
  Shield,
  Globe,
  Server,
  Link as LinkIcon,
  Search,
  Loader2,
  RotateCcw,
  CheckCircle,
  AlertCircle,
  Database,
} from "lucide-react";

export default function Dashboard() {
  const [, setLocation] = useLocation();

  const [input, setInput] = useState("");
  const [detectedType, setDetectedType] = useState<InputType>("domain");
  const [userOverride, setUserOverride] = useState(false);

  const { mutate, isPending } = useCreateAnalysis();
  const { data: status } = useReputationStatus();
  const reputation = status?.reputation;
  const secrets = status?.secrets;

  /* ---------------- Hybrid auto-detect ---------------- */
  useEffect(() => {
    if (userOverride) return;

    const value = input.trim();
    if (!value) return;

    const autoType = detectInputType(value);
    setDetectedType((prev) => (prev === autoType ? prev : autoType));
  }, [input, userOverride]);

  /* ---------------- Reset (NEW BUTTON) ---------------- */
  const handleNew = () => {
    setInput("");
    setDetectedType("domain");
    setUserOverride(false);
  };

  /* ---------------- Submit ---------------- */
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    const value = input.trim();
    if (!value) return;

    mutate(
      {
        value,
        inputType: detectedType,
      },
      {
        onSuccess: (data) => {
          setLocation(`/analysis/${data.id}`);
        },
      }
    );
  };

  /* ---------------- Helpers ---------------- */
  const getPlaceholder = (t: InputType) => {
    switch (t) {
      case "domain":
        return "example.com";
      case "ip":
        return "192.168.1.1";
      case "url":
        return "https://example.com/suspicious-path";
    }
  };

  const getIcon = (t: InputType) => {
    switch (t) {
      case "domain":
        return Globe;
      case "ip":
        return Server;
      case "url":
        return LinkIcon;
    }
  };

  const ActiveIcon = getIcon(detectedType);

  return (
    <div className="min-h-[calc(100vh-4rem)] flex flex-col items-center justify-center p-8 bg-grid-pattern relative overflow-hidden">
      {/* Background Cinematic Lighting */}
      <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-emerald-500/10 rounded-full blur-[120px] animate-pulse" />
      <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-blue-600/10 rounded-full blur-[120px] animate-pulse" />

      <div className="w-full max-w-6xl relative z-10">
        <div className="bento-grid">
          {/* Main Hero Card */}
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="bento-item bento-item-large flex flex-col justify-center items-center text-center space-y-6 satin-surface"
          >
            <motion.div 
              className="inline-flex items-center justify-center p-4 rounded-3xl bg-slate-900/80 border border-white/10 shadow-[0_0_40px_rgba(16,185,129,0.1)] animate-float"
            >
              <Shield className="w-14 h-14 text-emerald-500" />
            </motion.div>
            <div className="space-y-2">
              <h1 className="text-5xl md:text-6xl font-bold tracking-tighter premium-gradient-text">
                Elixir Analyzer
              </h1>
              <p className="text-slate-400 text-lg max-w-sm mx-auto font-medium">
                Next-generation neural threat intelligence.
              </p>
            </div>
          </motion.div>

          {/* Search Card */}
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="bento-item bento-item-wide satin-surface"
          >
            <Tabs
              value={detectedType}
              onValueChange={(val) => {
                setDetectedType(val as InputType);
                setUserOverride(true);
              }}
              className="w-full h-full flex flex-col justify-between"
            >
              <TabsList className="grid w-full grid-cols-3 bg-slate-950/40 p-1.5 rounded-xl border border-white/5 mb-4">
                <TabsTrigger value="domain" disabled={isPending} className="rounded-lg transition-all data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-400">
                  <Globe className="w-4 h-4 mr-2" /> Domain
                </TabsTrigger>
                <TabsTrigger value="ip" disabled={isPending} className="rounded-lg transition-all data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-400">
                  <Server className="w-4 h-4 mr-2" /> IP
                </TabsTrigger>
                <TabsTrigger value="url" disabled={isPending} className="rounded-lg transition-all data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-400">
                  <LinkIcon className="w-4 h-4 mr-2" /> URL
                </TabsTrigger>
              </TabsList>

              <form onSubmit={handleSubmit} className="relative mt-auto">
                <div className="relative group input-glow">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <ActiveIcon className="h-6 w-6 text-slate-500 group-focus-within:text-emerald-500 transition-colors duration-300" />
                  </div>

                  <Input
                    placeholder={getPlaceholder(detectedType)}
                    className="pl-14 h-16 bg-slate-950/40 border-slate-800 text-xl font-mono rounded-2xl placeholder:text-slate-600 transition-all focus:border-emerald-500/50"
                    value={input}
                    onChange={(e) => {
                      setInput(e.target.value);
                      setUserOverride(false);
                    }}
                    disabled={isPending}
                  />

                  <div className="absolute inset-y-1.5 right-1.5 flex gap-2">
                    <Button
                      type="submit"
                      size="lg"
                      disabled={isPending || !input.trim()}
                      className="h-13 px-6 rounded-xl bg-emerald-600 hover:bg-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.2)] transition-all active:scale-95"
                    >
                      {isPending ? (
                        <Loader2 className="w-6 h-6 animate-spin" />
                      ) : (
                        <Search className="w-5 h-5" />
                      )}
                    </Button>
                  </div>
                </div>
              </form>
            </Tabs>
          </motion.div>

          {/* Stats Card 1 */}
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
            className="bento-item satin-surface flex flex-col justify-between"
          >
            <div className="bg-emerald-500/10 p-2 rounded-lg w-fit">
              <Database className="w-5 h-5 text-emerald-500" />
            </div>
            <div>
              <div className="text-xs text-slate-500 uppercase font-bold tracking-widest mb-1">Global Intelligence</div>
              <div className="text-2xl font-bold text-white">{reputation?.loaded ? reputation.count.toLocaleString() : '---'}</div>
            </div>
          </motion.div>

          {/* Stats Card 2 */}
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.3 }}
            className="bento-item satin-surface flex flex-col justify-between"
          >
            <div className="bg-blue-500/10 p-2 rounded-lg w-fit">
              <Shield className="w-5 h-5 text-blue-500" />
            </div>
            <div>
              <div className="text-xs text-slate-500 uppercase font-bold tracking-widest mb-1">API Clusters</div>
              <div className="text-2xl font-bold text-white">{secrets?.virusTotal.active && secrets?.abuseIPDB.active ? 'Operational' : 'Partial'}</div>
            </div>
          </motion.div>

          {/* Bottom Row - Features */}
          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.4 }}
            className="bento-item bento-item-wide satin-surface flex items-center gap-6"
          >
            <div className="p-4 rounded-2xl bg-purple-500/10">
              <Zap className="w-8 h-8 text-purple-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Hybrid Risk Engine v3</h3>
              <p className="text-sm text-slate-400">Powered by Local Transformers & OSINT Synthesis.</p>
            </div>
          </motion.div>

          <motion.div 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.5 }}
            className="bento-item bento-item-wide satin-surface flex items-center gap-6"
          >
            <div className="p-4 rounded-2xl bg-amber-500/10">
              <RotateCcw className="w-8 h-8 text-amber-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">Forensic Sandbox</h3>
              <p className="text-sm text-slate-400">Recursive detonation with active behavioral monitoring.</p>
            </div>
          </motion.div>
        </div>
      </div>
    </div>
  );
}
}
