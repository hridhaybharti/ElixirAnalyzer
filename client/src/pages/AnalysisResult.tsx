import React, { useState } from "react";
import { useRoute, useLocation, Link } from "wouter";
import { useAnalysis } from "@/hooks/use-analysis";

import { RiskGauge } from "@/components/RiskGauge";
import { HeuristicList } from "@/components/HeuristicList";
import { SandboxSummary } from "@/components/SandboxSummary";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";

import {
  ArrowLeft,
  Globe,
  ShieldAlert,
	  CheckCircle,
	  ExternalLink,
	  FileDown,
	  Zap,
	} from "lucide-react";

import { format } from "date-fns";
import { motion } from "framer-motion";
import type { AnalysisDetails } from "@shared/schema";
import { useHistory } from "@/hooks/use-analysis";

/* =========================
   Main Page
========================= */

export default function AnalysisResult() {
  const [, params] = useRoute<{ id: string }>("/analysis/:id");
  const [, setLocation] = useLocation();

  if (!params?.id) return <AnalysisError />;

  const id = Number(params.id);
  const { data: analysis, isLoading, error } = useAnalysis(id);

  if (isLoading) return <AnalysisLoading />;
  if (error || !analysis) return <AnalysisError />;

  const details = (analysis.details || {}) as AnalysisDetails;
  const inputType = details.metadata?.inputType || analysis.type || "domain";
  const threatIntel = details.threatIntelligence;

  // Normalize backend risk labels
  const rawLevel = String(analysis.riskLevel || "");
  const upper = rawLevel.toUpperCase();
  let displayLevel = rawLevel || "Unknown";
  let statusColor = "text-emerald-500";

  if (upper.includes("MALIC")) {
    displayLevel = "Malicious";
    statusColor = "text-rose-500";
  } else if (upper.includes("SUSPIC")) {
    displayLevel = "Suspicious";
    statusColor = "text-amber-500";
  } else if (upper.includes("LOW") || upper.includes("RISK")) {
    displayLevel = "Low Risk";
    statusColor = "text-amber-400";
  } else if (upper.includes("BENIGN") || upper.includes("CLEAN")) {
    displayLevel = "Benign";
    statusColor = "text-emerald-500";
  }

  const [tab, setTab] = React.useState('heuristics');
  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <Button
        variant="ghost"
        onClick={() => setLocation("/")}
        className="mb-8 text-slate-400 hover:text-emerald-400"
      >
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Dashboard
      </Button>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* LEFT */}
        <motion.div
          initial={{ opacity: 0, x: -20 }}
          animate={{ opacity: 1, x: 0 }}
          className="space-y-6"
        >
          <Card className="border-slate-800">
            <CardHeader className="items-center">
              <RiskGauge
                score={analysis.riskScore}
                level={displayLevel}
                confidence={
                  typeof details.confidence === "number"
                    ? details.confidence / 100
                    : 0
                }
                size={220}
              />
              <div className={`text-2xl font-bold mt-4 ${statusColor}`}>
                {displayLevel}
              </div>
              <div className="text-xs text-slate-500 uppercase tracking-widest">
                Verdict
              </div>

              {/* Export Button */}
              <div className="pt-4 w-full">
                <Button 
                  onClick={() => window.open(`/api/analysis/${id}/export`, '_blank')}
                  className="w-full bg-slate-800 hover:bg-slate-700 text-white border border-white/5 gap-2"
                >
                  <FileDown className="w-4 h-4" />
                  Export Intelligence Report
                </Button>
              </div>
            </CardHeader>

            <CardContent className="space-y-4">
              <div>
                <div className="text-xs text-slate-500 uppercase mb-1">
                  Target
                </div>
                <div className="flex items-center gap-2 bg-slate-900 p-3 rounded border border-slate-800">
                  <Globe className="w-4 h-4 text-slate-400" />
                  <code className="text-sm text-slate-200 break-all">
                    {analysis.input}
                  </code>
                </div>
              </div>

              <div className="flex justify-between text-sm pt-4 border-t border-slate-800">
                <span className="text-slate-500">Scan Time</span>
                <span className="text-slate-300 font-mono">
                  {analysis.createdAt
                    ? format(
                        new Date(analysis.createdAt),
                        "HH:mm:ss dd/MM/yyyy"
                      )
                    : "N/A"}
                </span>
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-emerald-500" />
                Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="text-slate-400 text-sm">
              {analysis.summary}
            </CardContent>
          </Card>

          <SandboxSummary 
            aiConfidence={details.confidence || 0}
            heuristicScore={(details as any).heuristicScore || 0}
            osintScore={(details as any).osintScore || 0}
            anomalyFlags={(details as any).anomalyFlags || []}
          />

          <TrendWidget input={analysis.input} />
        </motion.div>

        {/* RIGHT */}
        <motion.div
          initial={{ opacity: 0, x: 20 }}
          animate={{ opacity: 1, x: 0 }}
          className="lg:col-span-2"
        >
          <CaseSummaryHeader analysis={analysis} details={details} setTab={setTab} />
          <IOCPanel analysis={analysis} details={details} />
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList className="mb-6">
              <TabsTrigger value="heuristics">
                Security Heuristics
              </TabsTrigger>
              <TabsTrigger value="engines">
                Engines
              </TabsTrigger>
              <TabsTrigger value="behavioral">
                Behavioral Sandbox
              </TabsTrigger>
              <TabsTrigger value="technical">
                Technical Data
              </TabsTrigger>
              <TabsTrigger value="graph">
                Graph
              </TabsTrigger>
            </TabsList>

            <TabsContent value="heuristics">
              <HeuristicsTab details={details} />
            </TabsContent>

            <TabsContent value="engines">
              <EnginesTab engines={threatIntel?.engines} />
            </TabsContent>

            <TabsContent value="behavioral">
              <BehavioralSandboxCard capture={details.threatIntelligence?.visualCapture} />
            </TabsContent>

            <TabsContent value="technical" className="space-y-6">
              {threatIntel ? (
                <>
                  <VirusTotalCard vt={threatIntel.virusTotal} />

                  {inputType === "ip" && threatIntel.ipReputation && (
                    <IPReputationCard ip={threatIntel.ipReputation} />
                  )}

                  {inputType === "ip" && (
                    <AbuseIPDBCard abuse={threatIntel.abuseIPDB} />
                  )}

                  {inputType === "ip" && (
                    <IPLocationCard loc={threatIntel.ipLocation} />
                  )}

                  {threatIntel.whoisData && (
                    <WhoisCard
                      whois={threatIntel.whoisData}
                      input={analysis.input}
                    />
                  )}

                  {threatIntel.detectionEngines?.length > 0 && (
                    <DetectionEnginesCard
                      engines={threatIntel.detectionEngines}
                    />
                  )}

                  {threatIntel.urlReputation?.length > 0 && (
                    <URLReputationCard
                      reports={threatIntel.urlReputation}
                    />
                  )}
                </>
              ) : (
                <div className="text-slate-400 text-sm p-4 rounded border border-slate-800">
                  Threat intelligence data not yet available.
                </div>
              )}
            </TabsContent>

            <TabsContent value="graph">
              <GraphPivotCard analysis={analysis} />
            </TabsContent>
          </Tabs>
        </motion.div>
      </div>
    </div>
  );
}

/* =========================
   Helper Components
========================= */

function IPReputationCard({ ip }: { ip: any }) {
  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
          IP Reputation
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-4">
          <InfoBlock label="IP Address" value={ip.ip} />
          <InfoBlock label="Status" value={ip.status} />
          <InfoBlock
            label="Abuse Score"
            value={
              typeof ip.abuseConfidenceScore === "number"
                ? `${Math.round(ip.abuseConfidenceScore)}%`
                : undefined
            }
          />
          <InfoBlock label="Reports" value={ip.totalReports?.toString()} />
          <InfoBlock label="ISP" value={ip.isp} />
          <InfoBlock label="Reverse DNS" value={ip.domain} />
        </div>

        {ip.threats?.length > 0 && (
          <div className="mt-4 p-3 bg-rose-500/10 rounded border border-rose-500/30">
            <div className="text-xs text-rose-400 font-semibold mb-2">
              Threat Categories
            </div>
            <div className="flex flex-wrap gap-2">
              {ip.threats.map((t: string, i: number) => (
                <span
                  key={i}
                  className="text-xs bg-rose-500/20 text-rose-300 px-2 py-1 rounded"
                >
                  {t}
                </span>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function VirusTotalCard({ vt }: { vt: any }) {
  if (!vt) {
    return (
      <Card className="border-slate-800">
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-widest">
            VirusTotal
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-slate-400">
          VirusTotal is not configured for this server. Set{" "}
          <code className="text-slate-300">VIRUSTOTAL_API_KEY</code> and re-run
          the server, then analyze again.
        </CardContent>
      </Card>
    );
  }

  const stats = vt?.stats || {};
  const items: Array<{ label: string; value: any; cls: string }> = [
    { label: "Malicious", value: stats.malicious, cls: "text-rose-400 bg-rose-500/10" },
    { label: "Suspicious", value: stats.suspicious, cls: "text-amber-400 bg-amber-500/10" },
    { label: "Harmless", value: stats.harmless, cls: "text-emerald-400 bg-emerald-500/10" },
    { label: "Undetected", value: stats.undetected, cls: "text-slate-300 bg-slate-800/60" },
  ].filter((x) => typeof x.value === "number");

  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
          VirusTotal
          {vt?.permalink && (
            <a
              href={vt.permalink}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1"
            >
              Open
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {vt?.ok === false && vt?.error ? (
          <div className="text-sm text-slate-400">{vt.error}</div>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-4">
              <InfoBlock label="Type" value={vt.type} />
              <InfoBlock label="Reputation" value={vt.reputation?.toString()} />
              <InfoBlock label="Last Analysis" value={vt.lastAnalysisDate} />
            </div>
            {items.length > 0 && (
              <div className="flex flex-wrap gap-2 pt-2">
                {items.map((it) => (
                  <span key={it.label} className={`px-2 py-1 rounded text-xs font-mono ${it.cls}`}>
                    {it.label}: {it.value}
                  </span>
                ))}
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}

function AbuseIPDBCard({ abuse }: { abuse: any }) {
  if (!abuse) {
    return (
      <Card className="border-slate-800">
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-widest">
            AbuseIPDB
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-slate-400">
          AbuseIPDB is not configured for this server (or no data is available).
          Set <code className="text-slate-300">ABUSEIPDB_API_KEY</code> and
          analyze an IP again.
        </CardContent>
      </Card>
    );
  }

  const ip = abuse?.ipAddress;
  const link = ip ? `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}` : null;

  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
          AbuseIPDB
          {link && (
            <a
              href={link}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1"
            >
              Open
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-4">
          <InfoBlock label="IP Address" value={ip} />
          <InfoBlock label="Country" value={abuse?.countryCode} />
          <InfoBlock
            label="Abuse Score"
            value={
              typeof abuse?.abuseConfidenceScore === "number"
                ? `${Math.round(abuse.abuseConfidenceScore)}%`
                : undefined
            }
          />
          <InfoBlock label="Reports" value={abuse?.totalReports?.toString()} />
          <InfoBlock label="Usage Type" value={abuse?.usageType} />
          <InfoBlock label="ISP" value={abuse?.isp} />
          <InfoBlock label="Domain" value={abuse?.domain} />
          <InfoBlock label="Whitelisted" value={typeof abuse?.isWhitelisted === "boolean" ? String(abuse.isWhitelisted) : undefined} />
          <InfoBlock label="Last Reported" value={abuse?.lastReportedAt || undefined} />
        </div>
      </CardContent>
    </Card>
  );
}

function IPLocationCard({ loc }: { loc: any }) {
  if (!loc) {
    return (
      <Card className="border-slate-800">
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-widest">
            IP Location
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-slate-400">
          Location is only available for IP analyses, and may be unavailable if
          the geolocation provider is blocked.
        </CardContent>
      </Card>
    );
  }

  const lat = typeof loc?.latitude === "number" ? loc.latitude : null;
  const lng = typeof loc?.longitude === "number" ? loc.longitude : null;
  const embedUrl =
    lat !== null && lng !== null
      ? `https://www.google.com/maps?q=${lat},${lng}&z=12&output=embed`
      : null;

  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
          IP Location
          {loc?.googleMapsUrl && (
            <a
              href={loc.googleMapsUrl}
              target="_blank"
              rel="noreferrer"
              className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1"
            >
              Open Map
              <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {loc?.error ? (
          <div className="text-sm text-slate-400">{loc.error}</div>
        ) : (
          <>
            {embedUrl && (
              <div className="aspect-video w-full overflow-hidden rounded border border-slate-800 bg-slate-950">
                <iframe
                  title="IP location map"
                  src={embedUrl}
                  className="w-full h-full"
                  loading="lazy"
                  referrerPolicy="no-referrer-when-downgrade"
                />
              </div>
            )}
            <div className="grid grid-cols-2 gap-4">
              <InfoBlock label="IP Address" value={loc?.ip} />
              <InfoBlock label="City" value={loc?.city} />
              <InfoBlock label="Region" value={loc?.region} />
              <InfoBlock label="Country" value={loc?.country} />
              <InfoBlock label="Latitude" value={loc?.latitude?.toString()} />
              <InfoBlock label="Longitude" value={loc?.longitude?.toString()} />
              <InfoBlock label="Accuracy" value={loc?.accuracy} />
            </div>
            <div className="text-xs text-slate-500">
              IP geolocation is approximate; it may not represent the exact physical location.
            </div>
          </>
        )}
      </CardContent>
    </Card>
  );
}

function WhoisCard({ whois, input }: { whois: any; input: string }) {
  const [showRaw, setShowRaw] = useState(false);
  const rawText =
    whois?.raw || whois?.raw_text || whois?.whois_raw || null;

  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
          WHOIS Information
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="grid grid-cols-2 gap-4">
          <InfoBlock label="Domain" value={whois.domain || input} />
          <InfoBlock label="Registrar" value={whois.registrar} />
          <InfoBlock label="Created" value={whois.creation_date} />
          <InfoBlock
            label="Age (Days)"
            value={whois.age_days?.toString()}
          />
        </div>

        {rawText && (
          <div>
            <button
              className="text-xs text-slate-400 hover:text-emerald-400"
              onClick={() => setShowRaw(!showRaw)}
            >
              {showRaw ? "Hide raw WHOIS" : "Show raw WHOIS"}
            </button>
            {showRaw && (
              <pre className="mt-2 p-3 bg-slate-900 rounded text-xs overflow-auto max-h-72 font-mono text-slate-300">
                {rawText}
              </pre>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function DetectionEnginesCard({ engines }: { engines: any[] }) {
  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
          Reputation Engines
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {engines.map((engine, i) => {
          const color =
            engine.result === "malicious"
              ? "text-rose-400 bg-rose-500/10"
              : engine.result === "suspicious"
              ? "text-amber-400 bg-amber-500/10"
              : "text-emerald-400 bg-emerald-500/10";

          return (
            <div
              key={i}
              className="flex items-center justify-between p-2 bg-slate-900 rounded text-sm"
            >
              <div className="text-slate-300">{engine.engine}</div>
              <div className={`px-2 py-1 rounded text-xs font-mono ${color}`}>
                {(engine.result || "unknown").toUpperCase()}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

function URLReputationCard({ reports }: { reports: any[] }) {
  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">
          URL Reputation
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {reports.map((r, i) => (
          <div
            key={i}
            className="p-3 rounded border border-slate-800 bg-slate-900"
          >
            <div className="flex justify-between mb-1">
              <span className="font-semibold">{r.source}</span>
              <span className="font-mono text-sm">{r.riskScore}/100</span>
            </div>
            <div className="text-sm text-slate-400">{r.details}</div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function BehavioralSandboxCard({ capture }: { capture: any }) {
  const signals = capture?.visualSignals;
  if (!signals || !signals.networkLog) {
    return (
      <Card className="border-slate-800 bg-slate-950/40">
        <CardContent className="py-12 text-center text-slate-500">
          <Globe className="w-12 h-12 mx-auto mb-4 opacity-20" />
          <p>No behavioral data captured for this target.</p>
          <p className="text-xs">Ensure VISUAL_CAPTURE_ENABLED is active.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {capture?.path && (
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
              Screenshot
              <a href={capture.path} target="_blank" rel="noreferrer" className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1">
                Open <ExternalLink className="w-3 h-3" />
              </a>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="rounded border border-slate-800 overflow-hidden bg-black/40">
              <img src={capture.path} alt="Sandbox Screenshot" className="w-full object-contain" />
            </div>
          </CardContent>
        </Card>
      )}

      <Card className="border-slate-800 bg-slate-950/40">
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-widest flex items-center gap-2">
            <Zap className="w-4 h-4 text-amber-400" />
            Execution Timeline (Network Connections)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
            {signals.networkLog.map((log: any, i: number) => (
              <div key={i} className="flex flex-col gap-1 p-2 rounded bg-slate-900/50 border border-slate-800/50 text-[11px] font-mono group hover:border-emerald-500/30 transition-colors">
                <div className="flex items-start gap-3">
                  <span className="text-slate-500">[{i.toString().padStart(2, '0')}]</span>
                  <span className="text-emerald-400 uppercase w-12">{log.method}</span>
                  <span className="text-slate-300 break-all flex-1">{log.url}</span>
                  <span className="text-slate-500 italic">{log.type}</span>
                </div>
                {log.countryCode && (
                  <div className="ml-8 flex items-center gap-2 text-[10px]">
                    <span className="text-slate-500 flex items-center gap-1">
                      <Globe className="w-2.5 h-2.5" /> {log.ip}
                    </span>
                    <span className="bg-emerald-500/10 text-emerald-400 px-1.5 py-0.5 rounded border border-emerald-500/20">
                      {log.countryCode} • {log.country}
                    </span>
                    {log.isp && <span className="text-slate-600 truncate max-w-[150px]">{log.isp}</span>}
                  </div>
                )}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <StatBox label="Hidden Iframes" value={signals.tinyIframeCount} color="text-rose-400" />
        <StatBox label="Tracking Scripts" value={signals.trackingScriptCount} color="text-amber-400" />
        <StatBox label="Password Fields" value={signals.hasPasswordField ? "DETECTED" : "NONE"} color={signals.hasPasswordField ? "text-rose-500" : "text-slate-500"} />
      </div>

      {capture?.dynamicSignals && (
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="text-sm uppercase tracking-widest">Dynamic Signals</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
              {renderDynStat('fetch', 'Fetch', capture.dynamicSignals)}
              {renderDynStat('xhr', 'XHR', capture.dynamicSignals)}
              {renderDynStat('beacon', 'Beacon', capture.dynamicSignals)}
              {renderDynStat('ws', 'WebSocket', capture.dynamicSignals)}
              {renderDynStat('eval', 'eval()', capture.dynamicSignals)}
              {renderDynStat('fn', 'Function()', capture.dynamicSignals)}
              {renderDynStat('atob', 'atob()', capture.dynamicSignals)}
            </div>
            {renderTopExfil(capture.dynamicSignals)}
          </CardContent>
        </Card>
      )}

      {(capture?.har?.path) && (
        <Card className="border-slate-800 bg-slate-950/40">
          <CardHeader>
            <CardTitle className="text-sm uppercase tracking-widest flex items-center justify-between">
              HAR
              <a href={capture.har.path} target="_blank" rel="noreferrer" className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1">
                Download <ExternalLink className="w-3 h-3" />
              </a>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-xs text-slate-400">HTTP Archive captured during detonation.</div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function StatBox({ label, value, color }: { label: string, value: any, color: string }) {
  return (
    <Card className="border-slate-800 bg-slate-900/30">
      <CardContent className="p-4 text-center">
        <div className="text-[10px] uppercase text-slate-500 font-bold mb-1">{label}</div>
        <div className={`text-lg font-mono font-bold ${color}`}>{value}</div>
      </CardContent>
    </Card>
  );
}

function renderDynStat(kind: string, label: string, dyn: any) {
  const c = Array.isArray(dyn?.events) ? dyn.events.filter((e: any) => e?.t === kind).length : 0;
  return <StatBox key={kind} label={label} value={c} color={c > 0 ? 'text-emerald-400' : 'text-slate-500'} />;
}

function renderTopExfil(dyn: any) {
  const events: any[] = Array.isArray(dyn?.events) ? dyn.events : [];
  const pageHost = String(dyn?.pageHost || '').toLowerCase();
  const exfil = events.filter(e => (e?.t === 'fetch' || e?.t === 'xhr' || e?.t === 'beacon') && e?.url)
    .map(e => ({ url: e.url, host: safeHost(e.url), t: e.t }))
    .filter(x => !!x.host && pageHost && x.host !== pageHost)
    .slice(0, 8);
  if (exfil.length === 0) return null;
  return (
    <div>
      <div className="text-xs text-slate-500 uppercase tracking-widest mb-2">Top Off-Origin Exfil</div>
      <div className="space-y-1 text-[11px] font-mono">
        {exfil.map((x, i) => (
          <div key={i} className="flex items-center gap-2 p-1.5 rounded bg-slate-900/40 border border-slate-800/40">
            <span className="text-emerald-400 uppercase w-12">{x.t}</span>
            <span className="text-slate-300 break-all">{x.url}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function safeHost(u: string) {
  try { return new URL(u).host.toLowerCase(); } catch { return ''; }
}

function EnginesTab({ engines }: { engines: any[] | undefined }) {
  if (!engines || engines.length === 0) {
    return (
      <Card className="border-slate-800">
        <CardContent className="py-8 text-center text-slate-500">
          No external engine verdicts. Configure keys to enable multi-engine checks.
        </CardContent>
      </Card>
    );
  }

  const colorFor = (v: string) =>
    v === 'malicious' ? 'text-rose-400 bg-rose-500/10' : v === 'suspicious' ? 'text-amber-400 bg-amber-500/10' : 'text-emerald-400 bg-emerald-500/10';

  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">External Engines</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {engines.map((e, idx) => (
          <div key={idx} className="flex items-center justify-between p-2 bg-slate-900 rounded text-sm">
            <div className="text-slate-300 flex items-center gap-2">
              <span>{e.engine}</span>
              {e.link && (
                <a href={e.link} target="_blank" rel="noreferrer" className="text-xs text-slate-400 hover:text-emerald-400 inline-flex items-center gap-1">
                  Open <ExternalLink className="w-3 h-3" />
                </a>
              )}
            </div>
            <div className={`px-2 py-1 rounded text-xs font-mono ${colorFor(e.verdict)}`}>
              {(e.verdict || 'unknown').toUpperCase()}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function InfoBlock({
  label,
  value,
}: {
  label: string;
  value?: React.ReactNode;
}) {
  if (value === undefined || value === null) return null;
  return (
    <div>
      <div className="text-xs text-slate-500">{label}</div>
      <div className="text-slate-200">{value}</div>
    </div>
  );
}

function GraphPivotCard({ analysis }: { analysis: any }) {
  const input = analysis?.input || '';
  const inputType = analysis?.type || 'domain';
  const node = inputType === 'url' ? `url:${input}` : inputType === 'domain' ? `domain:${input}` : `ip:${input}`;
  const [data, setData] = React.useState<any>(null);
  React.useEffect(() => {
    fetch(`/api/graph/pivot?node=${encodeURIComponent(node)}&depth=1`).then(r=>r.json()).then(setData).catch(()=>{});
  }, [node]);
  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">Graph Pivot</CardTitle>
      </CardHeader>
      <CardContent>
        {!data ? (
          <div className="text-slate-500 text-sm">No graph data.</div>
        ) : (
          <div className="space-y-2 text-sm">
            <div className="text-slate-400">Center: <span className="font-mono text-slate-200">{data.center}</span></div>
            <div className="text-slate-400">Nodes: {Array.isArray(data.nodes) ? data.nodes.length : 0}</div>
            <div className="space-y-1">
              {Array.isArray(data.edges) && data.edges.length > 0 ? data.edges.map((e: any, idx: number) => (
                <div key={idx} className="p-2 rounded bg-slate-900 border border-slate-800 font-mono text-[11px]">
                  {e.from}  --[{e.type}]--{'>'}  {e.to}
                </div>
              )) : <div className="text-slate-500 text-xs">No edges.</div>}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function HeuristicsTab({ details }: { details: AnalysisDetails }) {
  const all = details.heuristics || [];
  const [q, setQ] = React.useState('');
  const [sev, setSev] = React.useState<'all'|'fail'|'warn'|'pass'>('all');
  const cats = Array.from(new Set(all.map(h => h.category || 'General'))).sort();
  const [cat, setCat] = React.useState<string>('all');
  const filtered = all.filter(h => {
    const okSev = sev === 'all' ? true : h.status === sev;
    const okQ = !q ? true : (h.name + ' ' + h.description).toLowerCase().includes(q.toLowerCase());
    const okCat = cat === 'all' ? true : (h.category || 'General') === cat;
    return okSev && okQ && okCat;
  });

  const counts = all.reduce((acc, h) => { acc[h.status] = (acc[h.status]||0)+1; return acc; }, {} as any);

  const tagFor = (c?: string) => {
    const s = (c||'').toLowerCase();
    if (/(dns|tls|certificate|ct|protocol|port|network)/.test(s)) return 'Network';
    if (/(infra|asn|infrastructure)/.test(s)) return 'Infra';
    if (/(visual)/.test(s)) return 'Visual';
    if (/(histor)/.test(s)) return 'Historical';
    if (/(behavior|url|content|brand)/.test(s)) return 'Content';
    return 'General';
  };
  const order = ['Network','Content','Infra','Visual','Historical','General'];
  const grouped: Record<string, any[]> = {} as any;
  filtered.forEach(h => { const k = tagFor(h.category); (grouped[k] ||= []).push(h); });

  return (
    <div className="space-y-4">
      <TopSignals heuristics={all} />
      <Card className="border-slate-800">
        <CardHeader>
          <CardTitle className="flex items-center justify-between">
            <span>Security Heuristics</span>
            <div className="flex items-center gap-2 text-xs">
              <span className="px-2 py-1 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">fail: {counts['fail']||0}</span>
              <span className="px-2 py-1 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">warn: {counts['warn']||0}</span>
              <span className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">pass: {counts['pass']||0}</span>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col md:flex-row gap-3 mb-4">
            <input
              value={q}
              onChange={(e)=>setQ(e.target.value)}
              placeholder="Search heuristics..."
              className="flex-1 bg-slate-900 border border-slate-800 rounded px-3 py-2 text-sm text-slate-200 focus:outline-none focus:ring-1 focus:ring-emerald-500"
            />
            <div className="flex items-center gap-2">
              {(['all','fail','warn','pass'] as const).map(k => (
                <button key={k} onClick={()=>setSev(k)} className={`px-2 py-1 rounded text-xs border ${sev===k?'border-emerald-500/40 text-emerald-400':'border-slate-700 text-slate-400'} bg-slate-900 hover:border-emerald-500/40`}>
                  {k}
                </button>
              ))}
            </div>
          </div>
          <div className="flex flex-wrap gap-2 mb-4">
            <button onClick={()=>setCat('all')} className={`px-2 py-1 rounded text-xs border ${cat==='all'?'border-emerald-500/40 text-emerald-400':'border-slate-700 text-slate-400'} bg-slate-900 hover:border-emerald-500/40`}>all</button>
            {cats.map(c => (
              <button key={c} onClick={()=>setCat(c)} className={`px-2 py-1 rounded text-xs border ${cat===c?'border-emerald-500/40 text-emerald-400':'border-slate-700 text-slate-400'} bg-slate-900 hover:border-emerald-500/40`}>{c}</button>
            ))}
          </div>
          <HeuristicList
            heuristics={filtered}
            riskContribution={details.risk_contribution}
            trustContribution={details.trust_contribution}
          />
        </CardContent>
      </Card>
      {order.map(group => (
        (grouped[group]?.length > 0) ? (
          <Card key={group} className="border-slate-800 bg-slate-950/30">
            <CardHeader>
              <CardTitle className="text-sm uppercase tracking-widest">{group}</CardTitle>
            </CardHeader>
            <CardContent>
              <HeuristicList heuristics={grouped[group]} />
            </CardContent>
          </Card>
        ) : null
      ))}
    </div>
  );
}

function TopSignals({ heuristics }: { heuristics: any[] }) {
  if (!heuristics?.length) return null;
  const top = [...heuristics]
    .sort((a,b) => (b.status==='fail'?1:0)-(a.status==='fail'?1:0) || (b.scoreImpact||0)-(a.scoreImpact||0))
    .slice(0, 3);
  return (
    <Card className="border-slate-800 bg-slate-950/40">
      <CardContent className="p-4">
        <div className="text-xs uppercase text-slate-500 tracking-widest mb-2">Top Signals</div>
        <div className="grid md:grid-cols-3 gap-3">
          {top.map((t, i) => (
            <div key={i} className="p-3 rounded border border-slate-800 bg-slate-900/40">
              <div className="flex items-center justify-between mb-1">
                <div className="text-slate-200 text-sm font-medium truncate" title={t.name}>{t.name}</div>
                <span className={`text-xs font-mono ${t.status==='fail'?'text-rose-400':t.status==='warn'?'text-amber-400':'text-emerald-400'}`}>{t.status.toUpperCase()}</span>
              </div>
              <div className="text-[11px] text-slate-400 line-clamp-2" title={t.description}>{t.description}</div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

function CaseSummaryHeader({ analysis, details, setTab }: { analysis: any; details: AnalysisDetails; setTab: (t:string)=>void }) {
  const top = (details.heuristics || []).slice(0,3);
  return (
    <Card className="border-slate-800 bg-slate-950/60 backdrop-blur sticky top-0 z-10 mb-6">
      <CardContent className="p-4">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div>
            <div className="text-xs uppercase text-slate-500 tracking-widest">Case Summary</div>
            <div className="text-slate-200 text-lg font-semibold">{analysis.input}</div>
            <div className="flex gap-2 mt-2">
              {top.map((t:any,i:number)=> (
                <span key={i} className={`text-xs px-2 py-1 rounded border ${t.status==='fail'?'border-rose-500/30 text-rose-300 bg-rose-500/10':t.status==='warn'?'border-amber-500/30 text-amber-300 bg-amber-500/10':'border-emerald-500/30 text-emerald-300 bg-emerald-500/10'}`} title={t.description}>
                  {t.name}
                </span>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" className="border-slate-700" onClick={()=>setTab('graph')}>Pivot Graph</Button>
            <Button variant="outline" className="border-slate-700" onClick={()=>setTab('engines')}>Engines</Button>
            <Button onClick={()=>window.open(`/api/analysis/${analysis.id}/export`, '_blank')} className="bg-slate-800 hover:bg-slate-700 text-white border border-white/5">Export PDF</Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function IOCPanel({ analysis, details }: { analysis: any; details: AnalysisDetails }) {
  const items: Array<{ label: string; value?: string; copy?: string; link?: string }> = [];
  const type = details?.metadata?.inputType || analysis?.type;
  const input = analysis?.input;
  if (input) items.push({ label: type?.toUpperCase() || 'Input', value: input, copy: input });
  const vt = (details as any)?.threatIntelligence?.virusTotal;
  if (vt?.id) items.push({ label: 'VT ID', value: vt.id, copy: vt.id, link: vt.permalink });
  const whois = (details as any)?.threatIntelligence?.whoisData;
  if (whois?.domain) items.push({ label: 'Domain', value: whois.domain, copy: whois.domain });
  const ipRep = (details as any)?.threatIntelligence?.ipReputation;
  if (ipRep?.ip) items.push({ label: 'IP', value: ipRep.ip, copy: ipRep.ip });
  const vis = (details as any)?.threatIntelligence?.visualCapture;
  if (vis?.path) items.push({ label: 'Screenshot', value: vis.path, copy: vis.path, link: vis.path });
  const har = vis?.har?.path || (vis?.harPath);
  if (har) items.push({ label: 'HAR', value: har, copy: har, link: har });
  const ct = (details as any)?.threatIntelligence?.ctLogs || (details as any)?.threatIntelligence?.ctlog;
  const fps: string[] = Array.isArray(ct?.certFingerprints) ? ct.certFingerprints : [];
  if (fps.length > 0) fps.slice(0,3).forEach((fp: string, i: number) => items.push({ label: `Cert FP #${i+1}`, value: fp, copy: fp }));

  const onCopy = async (v?: string) => { if (!v) return; try { await navigator.clipboard.writeText(v); } catch {} };

  return (
    <Card className="border-slate-800 bg-slate-950/30 mb-6">
      <CardContent className="p-4">
        <div className="text-xs uppercase text-slate-500 tracking-widest mb-2">IOCs</div>
        {items.length === 0 ? (
          <div className="text-slate-500 text-sm">No indicators available.</div>
        ) : (
          <div className="grid md:grid-cols-2 gap-3">
            {items.map((it, idx) => (
              <div key={idx} className="p-3 rounded border border-slate-800 bg-slate-900/40 flex items-center justify-between gap-3">
                <div className="min-w-24 text-xs uppercase text-slate-500">{it.label}</div>
                <div className="flex-1 text-slate-200 truncate" title={it.value}>{it.value}</div>
                <div className="flex items-center gap-2">
                  {it.link && (
                    <a href={it.link} target="_blank" rel="noreferrer" className="text-xs text-slate-400 hover:text-emerald-400">Open</a>
                  )}
                  {it.copy && (
                    <button onClick={()=>onCopy(it.copy)} className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-300 hover:border-emerald-500/40">Copy</button>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function TrendWidget({ input }: { input: string }) {
  const { data } = useHistory();
  const items = Array.isArray(data) ? data.filter((x:any) => x.input === input).slice(-10) : [];
  if (items.length < 2) return null;
  const min = Math.min(...items.map((i:any)=>i.riskScore));
  const max = Math.max(...items.map((i:any)=>i.riskScore));
  const range = Math.max(1, max - min);
  return (
    <Card className="border-slate-800">
      <CardHeader>
        <CardTitle className="text-sm uppercase tracking-widest">Risk Trend (last {items.length})</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-16 flex items-end gap-1">
          {items.map((it:any, idx:number) => {
            const h = 12 + Math.round(((it.riskScore - min) / range) * 52);
            const cls = it.riskLevel?.toLowerCase().includes('critical') || it.riskScore>=90 ? 'bg-rose-500' : it.riskScore>=70 ? 'bg-rose-400' : it.riskScore>=30 ? 'bg-amber-400' : 'bg-emerald-400';
            return <div key={idx} title={`${it.riskScore} (${new Date(it.createdAt).toLocaleString()})`} className={`w-3 ${cls} rounded`} style={{height: `${h}px`}}/>;
          })}
        </div>
      </CardContent>
    </Card>
  );
}

function AnalysisLoading() {
  return (
    <div className="flex flex-col items-center py-24 space-y-6">
      <div className="w-16 h-16 border-4 border-emerald-500 border-t-transparent rounded-full animate-spin" />
      <Skeleton className="h-4 w-64 bg-slate-800" />
      <Skeleton className="h-4 w-48 bg-slate-800" />
    </div>
  );
}

function AnalysisError() {
  return (
    <div className="flex flex-col items-center py-24 text-center">
      <ShieldAlert className="w-16 h-16 text-rose-500 mb-4" />
      <h2 className="text-2xl font-bold text-white mb-2">
        Analysis Not Found
      </h2>
      <p className="text-slate-400 mb-6">
        The analysis does not exist or failed to load.
      </p>
      <Link href="/">
        <Button>Go Home</Button>
      </Link>
    </div>
  );
}
