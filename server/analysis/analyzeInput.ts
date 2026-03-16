import { HeuristicResult } from "@shared/schema";
import { HybridRiskEngine } from "./hybrid/risk-engine";
import { sanitizeInput } from "./sanitization";
import { webhookService } from "../utils/webhooks";
import { NarrativeEngine } from "./hybrid/narrative-engine";
import {
  checkAbuseIPDB,
  checkIPReputation,
  checkURLReputation,
  lookupIPLocation,
  lookupVirusTotalDomain,
  lookupVirusTotalIP,
  lookupVirusTotalUrl,
  lookupWhoisData,
  runDetectionEngines,
} from "./threat-intelligence";
import { getUrlEngineVerdicts } from "./engines/url-engines";

export type InputType = "ip" | "domain" | "url";

function getHostnameForType(type: InputType, input: string): string {
  if (type === "ip") return input;
  if (type === "domain") return input;

  try {
    const u = new URL(input.includes("://") ? input : `http://${input}`);
    return u.hostname;
  } catch {
    return input;
  }
}

async function buildThreatIntelligence(type: InputType, sanitizedInput: string, visualCapture: any) {
  const hostname = getHostnameForType(type, sanitizedInput);

  const vtPromise =
    type === "ip"
      ? lookupVirusTotalIP(sanitizedInput)
      : type === "domain"
        ? lookupVirusTotalDomain(hostname)
        : lookupVirusTotalUrl(sanitizedInput);

  const whoisPromise = type === "ip" ? Promise.resolve(null) : lookupWhoisData(hostname);
  const urlRepPromise = type === "ip" ? Promise.resolve([]) : checkURLReputation(sanitizedInput);
  const detectionEnginesPromise = runDetectionEngines(type === "url" ? hostname : sanitizedInput);

  const ipRepPromise = type === "ip" ? checkIPReputation(sanitizedInput) : Promise.resolve(null);
  const abusePromise = type === "ip" ? checkAbuseIPDB(sanitizedInput) : Promise.resolve(null);
  const ipLocPromise = type === "ip" ? lookupIPLocation(sanitizedInput) : Promise.resolve(null);

  const [virusTotal, whoisData, urlReputation, detectionEngines, ipReputation, abuseIPDB, ipLocation, engineVerdicts] =
    await Promise.all([
      vtPromise,
      whoisPromise,
      urlRepPromise,
      detectionEnginesPromise,
      ipRepPromise,
      abusePromise,
      ipLocPromise,
      getUrlEngineVerdicts(type, sanitizedInput).catch(() => []),
    ]);

  const stats = (virusTotal && virusTotal.ok ? virusTotal.stats : undefined) as any;
  const detectionSummary =
    stats && typeof stats === "object"
      ? {
          maliciousCount: Number(stats.malicious || 0),
          suspiciousCount: Number(stats.suspicious || 0),
          cleanCount: Number(stats.harmless || 0),
          totalEngines: Number(
            (stats.malicious || 0) +
              (stats.suspicious || 0) +
              (stats.harmless || 0) +
              (stats.undetected || 0) +
              (stats.timeout || 0),
          ),
        }
      : undefined;

  return {
    ipReputation,
    abuseIPDB,
    ipLocation,
    urlScan: null,
    archiveHistory: null,
    visualCapture: visualCapture || null,
    whoisData,
    detectionEngines: detectionEngines || [],
    urlReputation: urlReputation || [],
    virusTotal: virusTotal || null,
    engines: engineVerdicts || [],
    detectionSummary,
  };
}

/**
 * Main Analysis Pipeline - Re-engineered for Hybrid Intelligence v3
 */
export async function analyzeInput(type: InputType, input: string) {
  const startAt = Date.now();
  console.log(`[analyzeInput] Re-engineered Pipeline started for ${type}: ${input}`);

  // 1. Sanitization & Normalization
  const { sanitized } = sanitizeInput(input);

  // 2. Trigger the Hybrid Risk Engine (The Sandbox Brain)
  const report = await HybridRiskEngine.analyze(type, sanitized);
  function categorize(name: string, desc: string): string {
    const s = `${name} ${desc}`.toLowerCase();
    if (/brand|logo|vision/.test(s)) return 'Brand/Visual';
    if (/dns|nameserver|pdns|rdns/.test(s)) return 'DNS';
    if (/tls|certificate|ct-?log|x509/.test(s)) return 'TLS/Certificate';
    if (/asn|infrastructure|neighbor/.test(s)) return 'Infrastructure';
    if (/port|protocol/.test(s)) return 'Protocol/Port';
    if (/drift|historical|wayback/.test(s)) return 'Historical';
    if (/iframe|script|eval|function\(|atob\(|beacon|websocket|form|password/.test(s)) return 'Behavioral';
    if (/entropy|subdomain|url|path|obfuscation|length/.test(s)) return 'URL Structure';
    return 'General';
  }
  const heuristicsDetailed = Array.isArray((report as any).heuristicsList) ? (report as any).heuristicsList.map((h: any) => ({
    name: h.name,
    status: h.severity === 'critical' || h.severity === 'high' ? 'fail' : (h.severity === 'medium' ? 'warn' : 'pass'),
    description: h.description,
    scoreImpact: h.score,
    category: categorize(h.name, h.description)
  })) : [];
  const threatIntelligence =
    (await buildThreatIntelligence(type, sanitized, (report as any).visualCapture)) ??
    ({
      ipReputation: null,
      abuseIPDB: null,
      ipLocation: null,
      urlScan: null,
      archiveHistory: null,
      visualCapture: (report as any).visualCapture ?? null,
      whoisData: null,
      detectionEngines: [],
      urlReputation: [],
      virusTotal: null,
    } as any);

  // 3. Transform to Legacy Evidence Format for Frontend Compatibility
  const evidence: HeuristicResult[] = report.explanationSignals.map(sig => ({
    name: "Signal Insight",
    status: report.finalRiskScore >= 70 ? "fail" : report.finalRiskScore >= 30 ? "warn" : "pass",
    description: sig,
    scoreImpact: 0 // Already accounted for in finalRiskScore
  }));

  // 4. Construct the Intelligent Analysis Result
  const highImpactSignals = report.explanationSignals.slice(0, 3).join(". ");
  const intelligentSummary = NarrativeEngine.generate(report);

	  const resultObj = {
	    riskScore: report.finalRiskScore,
	    riskLevel: report.classification,
	    confidence: report.aiConfidence,
	    evidence,
	    details: {
	      engine: "Elixir Hybrid Sentinel",
	      engineVersion: "3.0.0-hybrid",
        confidence: report.aiConfidence,
        heuristicScore: report.heuristicScore,
	      osintScore: report.osintScore,
	      anomalyFlags: report.anomalyFlags,
        evidence,
        heuristics: heuristicsDetailed,
	      threatIntelligence,
	      metadata: {
	        inputType: type,
	        sanitizedInput: sanitized,
	        hasCorrelations: report.anomalyFlags.length > 0,
	        processingTimeMs: Date.now() - startAt,
	        isStealthThreat: report.anomalyFlags.includes("STEALTH_THREAT_DETECTED")
	      }
	    },
	    summary: intelligentSummary
	  };

  // 5. High-Risk Webhook Trigger
  if (report.finalRiskScore >= 70) {
    webhookService.notifyHighRisk({ 
      id: 0, 
      input, 
      type, 
      riskScore: report.finalRiskScore, 
      riskLevel: report.classification, 
      summary: resultObj.summary, 
      details: resultObj.details as any, 
      createdAt: new Date(), 
      isFavorite: false 
    }).catch(() => {});
  }

  return resultObj;
}

