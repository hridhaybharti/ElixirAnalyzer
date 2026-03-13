export class NarrativeEngine {
  /**
   * Generates a professional forensic narrative based on multi-pillar intelligence signals.
   */
  static generate(report: any): string {
    const findings: string[] = [];
    const { finalRiskScore, classification, anomalyFlags, explanationSignals, aiConfidence } = report;

    // 1. Core Verdict Intro
    if (finalRiskScore >= 90) {
      findings.push(`CRITICAL ALERT: This infrastructure exhibits definitive malicious characteristics associated with active cyber-attacks.`);
    } else if (finalRiskScore >= 70) {
      findings.push(`HIGH RISK: Strategic indicators suggest this target is part of a deceptive or malicious campaign.`);
    } else if (finalRiskScore >= 30) {
      findings.push(`SUSPICIOUS: Several anomalies were detected that deviate from standard reputable infrastructure patterns.`);
    } else {
      return "Technical analysis indicates this target is consistent with established reputable infrastructure. No tactical threats were identified during this session.";
    }

    // 2. Intelligence Pillar Highlights
    if (aiConfidence > 85) {
      findings.push(`Our neural engine is ${aiConfidence}% certain this target matches known phishing DNA.`);
    }

    if (anomalyFlags.includes("STEALTH_THREAT_DETECTED")) {
      findings.push(`A 'Stealth Zero-Day' was detected: the target bypassed traditional database blacklists but was exposed by deep behavioral analysis.`);
    }

    if (anomalyFlags.includes("RECURRING_CAMPAIGN_DETECTED")) {
      findings.push(`Forensic correlation links this infrastructure to a previously identified attack campaign.`);
    }

    // 3. Technical Specifics (Extracting from signals)
    const hasBrandSpoof = explanationSignals.some((s: string) => s.includes("Brand"));
    const hasOffshore = explanationSignals.some((s: string) => s.includes("offshore") || s.includes("jurisdiction"));
    const hasC2 = explanationSignals.some((s: string) => s.includes("C2") || s.includes("non-standard ports"));

    if (hasBrandSpoof) findings.push("Visual identity analysis confirms unauthorized brand impersonation.");
    if (hasOffshore) findings.push("The hosting environment is located in a high-risk offshore jurisdiction known for limited legal oversight.");
    if (hasC2) findings.push("Passive port-sniffing detected open control channels consistent with Command & Control (C2) behavior.");

    // 4. Final Executive Summary
    return findings.join(' ');
  }
}
