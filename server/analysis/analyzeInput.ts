import { HeuristicResult } from "@shared/schema";
import { HybridRiskEngine } from "./hybrid/risk-engine";
import { sanitizeInput } from "./sanitization";
import { webhookService } from "../utils/webhooks";

export type InputType = "ip" | "domain" | "url";

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

  // 3. Transform to Legacy Evidence Format for Frontend Compatibility
  const evidence: HeuristicResult[] = report.explanationSignals.map(sig => ({
    name: "Signal Insight",
    status: report.finalRiskScore >= 70 ? "fail" : report.finalRiskScore >= 30 ? "warn" : "pass",
    description: sig,
    scoreImpact: 0 // Already accounted for in finalRiskScore
  }));

  // 4. Construct the Intelligent Analysis Result
  const highImpactSignals = report.explanationSignals.slice(0, 3).join(". ");
  const intelligentSummary = report.anomalyFlags.includes("STEALTH_THREAT_DETECTED") 
    ? `CRITICAL: AI detected a stealth zero-day threat. ${highImpactSignals}`
    : report.finalRiskScore >= 70
      ? `High-risk activity detected. Infrastructure signals: ${highImpactSignals}.`
      : report.finalRiskScore >= 30
        ? `Suspicious patterns identified. Minor anomalies found: ${highImpactSignals}.`
        : "Infrastructure appears consistent with reputable patterns. No immediate threats detected.";

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
      metadata: {
        inputType: type,
        sanitizedInput: input,
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

