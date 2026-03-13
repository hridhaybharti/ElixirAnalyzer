import axios from 'axios';

export interface PDNSHistorySignal {
  ipChanges: number;
  lastIpChangeDays: number | null;
  firstSeenDays: number | null;
  historicalIps: string[];
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

/**
 * Passive DNS (pDNS) Replication History Service (Strike 2)
 * Analyzes how a domain's IP mapping has evolved over time.
 * Identifies "Infrastructure Flips" where a domain suddenly changes behavior.
 */
export class PDNSHistoryService {
  /**
   * Fetches historical IP mappings. 
   * Utilizes free OSINT lookups (via VirusTotal Domain API which provides historical resolutions).
   */
  static async analyze(hostname: string): Promise<PDNSHistorySignal | null> {
    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    if (!vtKey) return null;

    const signal: PDNSHistorySignal = {
      ipChanges: 0,
      lastIpChangeDays: null,
      firstSeenDays: null,
      historicalIps: [],
      heuristics: []
    };

    try {
      const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${hostname}/historical_resolutions`, {
        headers: { 'x-api-key': vtKey }
      });

      const data = response.data.data || [];
      signal.ipChanges = data.length;
      
      if (data.length > 0) {
        // Extract unique IPs and timestamps
        const ips = new Set<string>();
        const timestamps: number[] = [];
        
        data.forEach((res: any) => {
          if (res.attributes?.ip_address) ips.add(res.attributes.ip_address);
          if (res.attributes?.date) timestamps.push(res.attributes.date);
        });

        signal.historicalIps = Array.from(ips);
        
        const now = Math.floor(Date.now() / 1000);
        const latestChange = Math.max(...timestamps);
        const firstSeen = Math.min(...timestamps);

        signal.lastIpChangeDays = Math.floor((now - latestChange) / 86400);
        signal.firstSeenDays = Math.floor((now - firstSeen) / 86400);

        // --- HEURISTICS ---

        // 1. Rapid Infrastructure Flip (Volatile Domain)
        if (signal.lastIpChangeDays !== null && signal.lastIpChangeDays < 2 && signal.ipChanges > 1) {
          signal.heuristics.push({
            name: "RAPID_INFRASTRUCTURE_FLIP",
            score: 30,
            description: `Domain changed its IP resolution within the last 48 hours. High correlation with active campaign rotation.`
          });
        }

        // 2. High-Churn IP History
        if (signal.ipChanges > 5) {
          signal.heuristics.push({
            name: "HIGH_CHURN_IP_HISTORY",
            score: 20,
            description: `Domain has resolved to ${signal.ipChanges} different IPs. Unusual for stable reputable services.`
          });
        }
      }

      return signal;
    } catch (error) {
      console.error(`[PDNSHistory] Analysis failed for ${hostname}:`, error);
      return null;
    }
  }
}
