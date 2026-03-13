import { FeatureExtractor } from './feature-extractor';
import { HeuristicEngine } from './heuristic-engine';
import { AIInferenceService } from './ai-inference';
import { ThreatIntelService } from './threat-intel';
import { SignalAggregator, FinalAnalysisReport } from './signal-aggregator';

export class HybridRiskEngine {
  static async analyze(type: "ip" | "domain" | "url", input: string): Promise<FinalAnalysisReport> {
    console.log(`[HybridRiskEngine] Initiating full spectrum analysis for ${type}: ${input}`);
    
    // 1. Feature Extraction (DNA markers)
    const features = FeatureExtractor.extract(input);

    // 2. Parallel Signal Gathering (The Blitz)
    const [heuristics, aiSignals, osintSignals] = await Promise.all([
      HeuristicEngine.generateSignals(features),
      AIInferenceService.getSignals(input),
      ThreatIntelService.getSignals(type, input)
    ]);

    // 3. Signal Aggregation & Scoring
    const report = SignalAggregator.aggregate(heuristics, aiSignals, osintSignals);

    console.log(`[HybridRiskEngine] Analysis complete. Verdict: ${report.classification} (${report.finalRiskScore})`);
    
    return report;
  }
}
