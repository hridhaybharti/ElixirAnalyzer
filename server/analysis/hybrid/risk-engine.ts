import { FeatureExtractor } from './feature-extractor';
import { HeuristicEngine } from './heuristic-engine';
import { AIInferenceService } from './ai-inference';
import { ThreatIntelService } from './threat-intel';
import { SignalAggregator, FinalAnalysisReport } from './signal-aggregator';
import { DNSForensicService } from '../dns/dns-forensics';
import { IPNeighborService } from '../ip/neighbor-intel';
import { TLSService } from '../ssl/tls-fingerprint';

export class HybridRiskEngine {
  static async analyze(type: "ip" | "domain" | "url", input: string): Promise<FinalAnalysisReport> {
    console.log(`[HybridRiskEngine] Initiating full spectrum analysis for ${type}: ${input}`);
    
    // 1. Feature Extraction (DNA markers)
    const features = FeatureExtractor.extract(input);
    const hostname = type === "url" ? new URL(input.startsWith('http') ? input : `https://${input}`).hostname : input;

    // 2. Parallel Signal Gathering (The Blitz)
    const [heuristics, aiSignals, osintSignals, dnsSignal, ipNeighborSignal, tlsSignal] = await Promise.all([
      HeuristicEngine.generateSignals(features),
      AIInferenceService.getSignals(input),
      ThreatIntelService.getSignals(type, input),
      type !== "ip" ? DNSForensicService.analyze(hostname) : Promise.resolve(null),
      type === "ip" ? IPNeighborService.analyze(input) : Promise.resolve(null),
      type !== "ip" ? TLSService.analyze(hostname) : Promise.resolve(null)
    ]);

    // 3. Inject External Heuristics (DNS + IP Neighbor + TLS)
    if (dnsSignal) {
      dnsSignal.heuristics.forEach(h => heuristics.push({
        name: h.name,
        score: h.score,
        description: h.description,
        severity: h.score >= 25 ? 'high' : 'medium'
      }));
    }

    if (ipNeighborSignal) {
      ipNeighborSignal.heuristics.forEach(h => heuristics.push({
        name: h.name,
        score: h.score,
        description: h.description,
        severity: h.score >= 30 ? 'critical' : 'high'
      }));
    }

    if (tlsSignal) {
      tlsSignal.heuristics.forEach(h => heuristics.push({
        name: h.name,
        score: h.score,
        description: h.description,
        severity: h.score >= 30 ? 'critical' : 'high'
      }));
    }

    // 4. Signal Aggregation & Scoring
    const report = SignalAggregator.aggregate(heuristics, aiSignals, osintSignals);

    console.log(`[HybridRiskEngine] Analysis complete. Verdict: ${report.classification} (${report.finalRiskScore})`);
    
    return report;
  }
}
