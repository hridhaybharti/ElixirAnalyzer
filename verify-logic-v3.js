// --- 🧪 ELIXIR ENGINE V3: LOGIC VERIFICATION ---

// Mocking the behavior of our TypeScript classes for logic testing
const FeatureExtractor = {
  extract: (input) => {
    const brands = ['paypal', 'google', 'microsoft'];
    const hostname = input.includes('://') ? input.split('/')[2] : input;
    return {
      entropy: (input.length / 5), // Simplified entropy
      brandMatch: brands.filter(b => input.toLowerCase().includes(b)),
      length: input.length,
      subdomains: hostname.split('.').length - 2
    };
  }
};

const HeuristicEngine = {
  generateSignals: (f) => {
    const signals = [];
    if (f.brandMatch.length > 0 && !f.brandMatch.includes('google')) signals.push({ name: 'BRAND_SPOOF', score: 45 });
    if (f.entropy > 4) signals.push({ name: 'HIGH_ENTROPY', score: 30 });
    if (f.subdomains > 3) signals.push({ name: 'EXCESSIVE_SUBDOMAINS', score: 20 });
    return signals;
  }
};

const SignalAggregator = {
  aggregate: (heuristics, aiProb, vtDetections) => {
    const hScore = Math.min(100, heuristics.reduce((sum, s) => sum + s.score, 0));
    const aiScore = aiProb * 100;
    const osintScore = vtDetections > 0 ? 100 : 0;
    
    let finalScore = (0.4 * hScore) + (0.3 * aiScore) + (0.3 * osintScore);
    let anomaly = (aiProb > 0.85 && vtDetections === 0) ? "STEALTH_THREAT_DETECTED" : "None";
    
    if (anomaly !== "None") finalScore = Math.max(finalScore, 85);
    
    return { score: Math.round(finalScore), anomaly };
  }
};

const testInputs = [
  { name: "Safe Domain", value: "google.com", ai: 0.05, vt: 0 },
  { name: "Phishing Mimic", value: "secure-paypal-verify.info", ai: 0.98, vt: 0 }, // Stealth Threat!
  { name: "Known Malicious", value: "malware-drop.com", ai: 0.95, vt: 5 }
];

console.log("--- 🧪 ELIXIR ENGINE V3: LOGIC VERIFICATION ---");
testInputs.forEach(input => {
  const f = FeatureExtractor.extract(input.value);
  const h = HeuristicEngine.generateSignals(f);
  const result = SignalAggregator.aggregate(h, input.ai, input.vt);
  
  console.log(`\n[Input]: ${input.value}`);
  console.log(`  > Heuristics: ${h.map(s => s.name).join(', ') || 'None'}`);
  console.log(`  > Final Score: ${result.score}`);
  console.log(`  > Anomaly: ${result.anomaly}`);
});
