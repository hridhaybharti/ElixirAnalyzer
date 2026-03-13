import { HeuristicSignal } from './heuristic-engine';
import { AISignal } from './ai-inference';
import { OSINTSignal } from './threat-intel';

export interface FinalAnalysisReport {
  finalRiskScore: number;
  classification: 'Safe' | 'Suspicious' | 'High Risk' | 'Critical';
  aiConfidence: number;
  heuristicScore: number;
  osintScore: number;
  anomalyFlags: string[];
  explanationSignals: string[];
}

export class SignalAggregator {
  static aggregate(
    heuristics: HeuristicSignal[],
    aiSignals: AISignal[],
    osintSignals: OSINTSignal[]
  ): FinalAnalysisReport {
    // 1. Calculate Component Scores (Normalized to 0-100)
    const heuristicScore = Math.min(100, heuristics.reduce((sum, s) => sum + s.score, 0));
    
    const aiScore = aiSignals.length > 0 
      ? (aiSignals.reduce((sum, s) => sum + s.maliciousProbability, 0) / aiSignals.length) * 100
      : 0;

    const osintScore = osintSignals.length > 0
      ? Math.min(100, osintSignals.reduce((sum, s) => sum + s.reputationScore, 0))
      : 0;

    // 2. Weighted Risk Calculation (The 0.4 / 0.3 / 0.3 Logic)
    let finalRiskScore = (0.4 * heuristicScore) + (0.3 * aiScore) + (0.3 * osintScore);

    // 3. Anomaly Detection: "Stealth Threat" Logic
    const anomalyFlags: string[] = [];
    const avgAiProb = aiSignals.length > 0 ? (aiSignals.reduce((sum, s) => sum + s.maliciousProbability, 0) / aiSignals.length) : 0;
    const totalVtDetections = osintSignals.find(s => s.source === "VirusTotal")?.maliciousCount || 0;

    if (avgAiProb > 0.85 && totalVtDetections === 0) {
      anomalyFlags.push("STEALTH_THREAT_DETECTED");
      // Boost score for stealth threats as they are highly dangerous zero-days
      finalRiskScore = Math.max(finalRiskScore, 85); 
    }

    // 4. Final Classification
    let classification: FinalAnalysisReport['classification'] = 'Safe';
    if (finalRiskScore >= 90) classification = 'Critical';
    else if (finalRiskScore >= 70) classification = 'High Risk';
    else if (finalRiskScore >= 30) classification = 'Suspicious';

    // 5. Generate Explanations
    const explanationSignals = [
      ...heuristics.map(h => h.description),
      ...anomalyFlags.map(f => `Anomaly: ${f} - AI detected malicious patterns while traditional scanners were silent.`)
    ];

    return {
      finalRiskScore: Math.round(finalRiskScore),
      classification,
      aiConfidence: Math.round(aiScore),
      heuristicScore: Math.round(heuristicScore),
      osintScore: Math.round(osintScore),
      anomalyFlags,
      explanationSignals
    };
  }
}
