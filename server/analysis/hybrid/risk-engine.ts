import { FeatureExtractor } from './feature-extractor';
import { HeuristicEngine } from './heuristic-engine';
import { AIInferenceService } from './ai-inference';
import { ThreatIntelService } from './threat-intel';
import { SignalAggregator, FinalAnalysisReport } from './signal-aggregator';
import { DNSForensicService } from '../dns/dns-forensics';
import { IPNeighborService } from '../ip/neighbor-intel';
import { TLSService } from '../ssl/tls-fingerprint';
import { ContentDriftService } from '../historical/content-drift';
import { CampaignDNAEngine } from '../dna/campaign-tracker';

export class HybridRiskEngine {
  static async analyze(type: "ip" | "domain" | "url", input: string): Promise<FinalAnalysisReport & { dnaMatch?: any }> {
    console.log(`[HybridRiskEngine] Initiating full spectrum analysis for ${type}: ${input}`);
    
    // 1. Feature Extraction (DNA markers)
    const features = FeatureExtractor.extract(input);
    const hostname = type === "url" ? new URL(input.startsWith('http') ? input : `https://${input}`).hostname : input;

    // 2. Parallel Signal Gathering (The Blitz)
    const [heuristics, aiSignals, osintSignals, dnsSignal, ipNeighborSignal, tlsSignal, driftSignal] = await Promise.all([
      HeuristicEngine.generateSignals(features),
      AIInferenceService.getSignals(input),
      ThreatIntelService.getSignals(type, input),
      type !== "ip" ? DNSForensicService.analyze(hostname) : Promise.resolve(null),
      type === "ip" ? IPNeighborService.analyze(input) : Promise.resolve(null),
      type !== "ip" ? TLSService.analyze(hostname) : Promise.resolve(null),
      type !== "ip" ? ContentDriftService.analyze(hostname) : Promise.resolve(null)
    ]);

    // 3. Inject External Heuristics (DNS + IP Neighbor + TLS + Drift)
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

    if (driftSignal) {
      driftSignal.heuristics.forEach(h => heuristics.push({
        name: h.name,
        score: h.score,
        description: h.description,
        severity: h.score >= 25 ? 'high' : 'medium'
      }));
    }

    // 4. Signal Aggregation & Scoring
    const report = SignalAggregator.aggregate(heuristics, aiSignals, osintSignals);

    // 🚀 Strike 3: Infrastructure DNA & Campaign Tracking
    const dnaVector = await CampaignDNAEngine.generateDNA(input, report.explanationSignals);
    const matches = CampaignDNAEngine.findMatches(dnaVector);
    
    if (matches.length > 0 && report.finalRiskScore >= 30) {
      report.anomalyFlags.push("RECURRING_CAMPAIGN_DETECTED");
      report.explanationSignals.push(`Campaign Link: This infrastructure matches a previously scanned threat (Similiarity: ${(matches[0].similarity * 100).toFixed(1)}%).`);
    }

    // Store for future comparisons
    CampaignDNAEngine.storeFingerprint(Date.now().toString(), dnaVector, {
      input,
      finalRiskScore: report.finalRiskScore,
      timestamp: Date.now()
    });

    console.log(`[HybridRiskEngine] Analysis complete. Verdict: ${report.classification} (${report.finalRiskScore})`);
    
    return report;
  }
}
