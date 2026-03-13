import 'dotenv/config';
import { AIInferenceService } from './server/analysis/hybrid/ai-inference';

async function runTest() {
  console.log("--- STARTING AI SIGNAL TEST ---");
  
  const testInputs = [
    "google.com", // Safe
    "paypal-security-update-2026.com", // Likely Phishing
    "http://192.168.1.1/login.php" // Internal/Suspicious
  ];

  for (const input of testInputs) {
    console.log(`Testing Input: ${input}`);
    const signals = await AIInferenceService.getSignals(input);
    console.log(`Signals: `, JSON.stringify(signals, null, 2));
    console.log("----------------------------");
  }
}

runTest().catch(console.error);
