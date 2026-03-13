import axios from 'axios';

export interface ASNSignal {
  asn: string;
  name: string;
  country: string;
  reputation: 'trusted' | 'neutral' | 'high-risk';
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

export class ASNForensicService {
  /**
   * Fetches BGP/ASN metadata for an IP or Domain.
   * Identifies hosting providers known for "Bulletproof" activity or high abuse churn.
   */
  static async analyze(ipOrHostname: string): Promise<ASNSignal | null> {
    try {
      // Use ip-api.com (free for non-commercial use) for rapid ASN lookup
      // Note: In production, you'd use a local MaxMind DB or a specialized API like PeeringDB
      const response = await axios.get(`http://ip-api.com/json/${ipOrHostname}?fields=status,message,country,countryCode,isp,org,as,query`);
      
      if (response.data.status !== 'success') return null;

      const data = response.data;
      const asFull = data.as || ''; // e.g., "AS15169 Google LLC"
      const asn = asFull.split(' ')[0];
      const isp = data.isp.toLowerCase();

      const signal: ASNSignal = {
        asn,
        name: data.isp,
        country: data.countryCode,
        reputation: 'neutral',
        heuristics: []
      };

      // --- HEURISTICS: High-Risk Infrastructure Fingerprinting ---

      // 1. Known "Bulletproof" or High-Abuse Regions/Providers
      // We look for providers often used for disposable phishing infrastructure
      const highRiskKeywords = ['m247', 'digitalocean', 'ovh', 'linode', 'vultr', 'freenom', 'cloudns'];
      const isHighRiskProvider = highRiskKeywords.some(kw => isp.includes(kw));

      if (isHighRiskProvider) {
        signal.reputation = 'high-risk';
        signal.heuristics.push({
          name: "HIGH_CHURN_INFRASTRUCTURE",
          score: 15,
          description: `Target is hosted on ${data.isp} (ASN: ${asn}), a provider frequently utilized for disposable attack nodes.`
        });
      }

      // 2. Geographic Anomaly (e.g. US Brand hosted in High-Risk Jurisdiction)
      const highRiskCountries = ['RU', 'CN', 'KP', 'IR', 'RO', 'UA', 'NG'];
      if (highRiskCountries.includes(data.countryCode)) {
        signal.heuristics.push({
          name: "OFFSHORE_THREAT_HOSTING",
          score: 20,
          description: `Host is located in a high-risk jurisdiction (${data.countryCode}) with limited legal cooperation for takedowns.`
        });
      }

      return signal;
    } catch (error) {
      console.error(`[ASNForensics] Lookup failed for ${ipOrHostname}:`, error);
      return null;
    }
  }
}
