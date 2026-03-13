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
import { ASNForensicService } from '../infrastructure/asn-lookup';
import { BrandVisionService } from '../vision/brand-scanner';
import { visualEngine } from '../visual-engine';
import { PortIntelligenceService } from '../protocols/port-intelligence';
import { PDNSHistoryService } from '../pdns/pdns-history';
import dns from 'dns/promises';

export class HybridRiskEngine {
  static async analyze(type: "ip" | "domain" | "url", input: string): Promise<FinalAnalysisReport & { dnaMatch?: any }> {
    console.log(`[HybridRiskEngine] Initiating full spectrum analysis for ${type}: ${input}`);
    
    // 1. Feature Extraction (DNA markers)
    const features = FeatureExtractor.extract(input);
    const hostname = type === "url" ? new URL(input.startsWith('http') ? input : `https://${input}`).hostname : input;

    // Resolve IP for port intelligence if needed
    let targetIp: string | null = type === "ip" ? input : null;
    if (!targetIp) {
      try {
        const addrs = await dns.resolve4(hostname);
        if (addrs.length > 0) targetIp = addrs[0];
      } catch { /* ignore resolution errors */ }
    }

    // 2. Parallel Signal Gathering (The Blitz)
    const [heuristics, aiSignals, osintSignals, dnsSignal, ipNeighborSignal, tlsSignal, driftSignal, asnSignal, portSignal, pdnsSignal] = await Promise.all([
      HeuristicEngine.generateSignals(features),
      AIInferenceService.getSignals(input),
      ThreatIntelService.getSignals(type, input),
      type !== "ip" ? DNSForensicService.analyze(hostname) : Promise.resolve(null),
      type === "ip" ? IPNeighborService.analyze(input) : Promise.resolve(null),
      type !== "ip" ? TLSService.analyze(hostname) : Promise.resolve(null),
      type !== "ip" ? ContentDriftService.analyze(hostname) : Promise.resolve(null),
      ASNForensicService.analyze(hostname),
      targetIp ? PortIntelligenceService.analyze(targetIp) : Promise.resolve(null),
      type !== "ip" ? PDNSHistoryService.analyze(hostname) : Promise.resolve(null)
    ]);

    // 🚀 Strike 2: Brand Vision AI (Visual Verification)
    const captureId = Buffer.from(input).toString('hex').substring(0, 12);
    const visualCapture = await visualEngine.captureSafeScreenshot(input, captureId);
    
    if (visualCapture.success && visualCapture.path) {
      const screenshotRelativePath = `server/data/screenshots/${captureId}.jpg`;
      const visionSignal = await BrandVisionService.analyze(screenshotRelativePath, hostname);
      
      if (visionSignal) {
        visionSignal.heuristics.forEach(h => heuristics.push({
          name: h.name,
          score: h.score,
          description: h.description,
          severity: 'critical'
        }));
      }

      const standardVisual = visualEngine.getVisualHeuristics(visualCapture);
      heuristics.push(...standardVisual.map(h => ({ ...h, severity: h.status as any })));
    }

    // 3. Inject External Heuristics (DNS + IP Neighbor + TLS + Drift + ASN + Port + PDNS)
    if (dnsSignal) {
      dnsSignal.heuristics.forEach(h => heuristics.push({
        name: h.name, score: h.score, description: h.description, severity: h.score >= 25 ? 'high' : 'medium'
      }));
    }

    if (ipNeighborSignal) {
      ipNeighborSignal.heuristics.forEach(h => heuristics.push({
        name: h.name, score: h.score, description: h.description, severity: h.score >= 30 ? 'critical' : 'high'
      }));
    }

    if (tlsSignal) {
      tlsSignal.heuristics.forEach(h => heuristics.push({
        name: h.name, score: h.score, description: h.description, severity: h.score >= 30 ? 'critical' : 'high'
      }));
    }

    if (driftSignal) {
      driftSignal.heuristics.forEach(h => heuristics.push({
        name: h.name, score: h.score, description: h.description, severity: h.score >= 25 ? 'high' : 'medium'
      }));
    }

    if (asnSignal) {
      asnSignal.heuristics.forEach(h => heuristics.push({
        name: h.name, score: h.score, description: h.description, severity: h.score >= 20 ? 'high' : 'medium'
      }));
    }

    if (portSignal) {
      portSignal.heuristics.forEach(h => heuristics.push({
        name: h.name, score: h.score, description: h.description, severity: h.score >= 20 ? 'high' : 'medium'
      }));
    }

    if (pdnsSignal) {
      pdnsSignal.heuristics.forEach(h => heuristics.push({
        name: h.name, score: h.score, description: h.description, severity: h.score >= 30 ? 'critical' : 'high'
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

    CampaignDNAEngine.storeFingerprint(Date.now().toString(), dnaVector, {
      input, finalRiskScore: report.finalRiskScore, timestamp: Date.now()
    });

    console.log(`[HybridRiskEngine] Analysis complete. Verdict: ${report.classification} (${report.finalRiskScore})`);
    
    return report;
  }
}
