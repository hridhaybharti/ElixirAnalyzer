const { FeatureExtractor } = require('./server/analysis/hybrid/feature-extractor');
const { HeuristicEngine } = require('./server/analysis/hybrid/heuristic-engine');
const { SignalAggregator } = require('./server/analysis/hybrid/signal-aggregator');

async function testEngine() {
  console.log("--- 🧪 ELIXIR ENGINE V3: LOGIC VERIFICATION ---");
  
  const testInputs = [
    { name: "Safe Domain", value: "google.com" },
    { name: "Phishing Brand Mimic", value: "secure-paypal-login-update.info" },
    { name: "DGA/Botnet Randomness", value: "xhz-992-alert-881.xyz" }
  ];

  for (const input of testInputs) {
    console.log(`\n[Testing: ${input.name}] -> ${input.value}`);
    
    // 1. Feature Extraction
    const features = FeatureExtractor.extract(input.value);
    console.log(`  > DNA extracted: Entropy: ${features.entropyScore}, Brand Match: ${features.brandKeywords.join(', ') || 'None'}`);
    
    // 2. Heuristic Generation
    const heuristics = HeuristicEngine.generateSignals(features);
    console.log(`  > Signals detected: ${heuristics.map(h => h.name).join(', ') || 'None'}`);
    
    // 3. Mock Aggregation (Simulating AI 95% for malicious cases)
    const mockAi = input.name !== "Safe Domain" ? [{ modelName: "TestAI", maliciousProbability: 0.95, label: "phishing" }] : [];
    const mockOsint = input.name === "Phishing Brand Mimic" ? [{ source: "VirusTotal", maliciousCount: 1, reputationScore: 100 }] : [];
    
    const report = SignalAggregator.aggregate(heuristics, mockAi, mockOsint);
    console.log(`  > Verdict: ${report.classification} (Score: ${report.finalRiskScore})`);
    
    if (report.anomalyFlags.length > 0) {
      console.log(`  > ⚠️ Anomalies: ${report.anomalyFlags.join(', ')}`);
    }
  }
}

testEngine().catch(console.error);
