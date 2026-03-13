import { osintService } from "../osint-engine";
import { lookupWhoisData, checkURLReputation, type WhoisData } from "../threat-intelligence";

export interface OSINTSignal {
  source: string;
  maliciousCount: number;
  totalEngines: number;
  reputationScore: number; // 0-100
  metadata: any;
}

export class ThreatIntelService {
  static async getSignals(type: "ip" | "domain" | "url", input: string): Promise<OSINTSignal[]> {
    const signals: OSINTSignal[] = [];
    const hostname = type === "url" ? new URL(input.startsWith('http') ? input : `https://${input}`).hostname : input;

    try {
      if (type === "ip") {
        const [abuseData, vtData] = await Promise.all([
          osintService.getAbuseIPDB(input),
          osintService.getVirusTotal(input, "ip")
        ]);

        if (abuseData) {
          signals.push({
            source: "AbuseIPDB",
            maliciousCount: abuseData.totalReports > 0 ? 1 : 0,
            totalEngines: 1,
            reputationScore: abuseData.abuseConfidenceScore,
            metadata: abuseData
          });
        }

        if (vtData?.ok && vtData.stats) {
          signals.push({
            source: "VirusTotal",
            maliciousCount: vtData.stats.malicious || 0,
            totalEngines: (vtData.stats.malicious || 0) + (vtData.stats.harmless || 0),
            reputationScore: (vtData.stats.malicious || 0) > 0 ? 100 : 0,
            metadata: vtData.stats
          });
        }
      } else {
        const [vtData, whoisData, urlRep] = await Promise.all([
          osintService.getVirusTotal(hostname, type === "url" ? "url" : "domain"),
          lookupWhoisData(hostname),
          checkURLReputation(hostname)
        ]);

        if (vtData?.ok && vtData.stats) {
          signals.push({
            source: "VirusTotal",
            maliciousCount: vtData.stats.malicious || 0,
            totalEngines: (vtData.stats.malicious || 0) + (vtData.stats.harmless || 0),
            reputationScore: (vtData.stats.malicious || 0) > 0 ? 100 : 0,
            metadata: vtData.stats
          });
        }

        if (whoisData) {
          // Domain age logic as a signal
          const isNew = whoisData.age < 30;
          signals.push({
            source: "WHOIS",
            maliciousCount: isNew ? 1 : 0,
            totalEngines: 1,
            reputationScore: isNew ? 70 : 0, // High score for brand new domains
            metadata: { ageDays: whoisData.age, registrar: whoisData.registrar }
          });
        }
      }
    } catch (error) {
      console.error("[ThreatIntel] OSINT gathering failed:", error);
    }

    return signals;
  }
}
