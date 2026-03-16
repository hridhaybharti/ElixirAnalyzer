import { analyzeInput } from "../../analysis/analyzeInput";
import { parseEmailSmart } from "../mailparse";

/**
 * Unified Pipeline: Phish-to-Sandbox
 * Automatically follows and detonates URLs found inside suspicious emails.
 */
export class PhishToSandboxBridge {
  static async processEmail(emailContent: string) {
    console.log("[Phish-to-Sandbox] Initiating unified forensic sequence...");
    
    // 1. Parse Email for URLs
    const parsed = await parseEmailSmart(emailContent);
    const urls = parsed.urls || [];

    const results = [];
    
    // 2. Detonate discovered URLs
    for (const url of urls.slice(0, 3)) { // Limit to top 3 for performance
      console.log(`[Phish-to-Sandbox] Following link to sandbox: ${url}`);
      const sandboxReport = await analyzeInput("url", url);
      results.push({
        url,
        verdict: sandboxReport.riskLevel,
        score: sandboxReport.riskScore,
        reportId: (sandboxReport as any).id
      });
    }

    return {
      emailId: parsed.messageId,
      discoveredThreats: results,
      chainVerdict: results.some(r => r.verdict === 'Malicious' || r.verdict === 'Critical') ? 'MALICIOUS_CHAIN' : 'CLEAN_CHAIN'
    };
  }
}
