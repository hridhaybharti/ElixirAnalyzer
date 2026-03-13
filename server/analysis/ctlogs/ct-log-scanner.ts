import axios from 'axios';

export interface CTLogSignal {
  totalCertificates: number;
  recentCertificates: number; // last 7 days
  issuers: string[];
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

/**
 * SSL/TLS Certificate Transparency (CT) Log Scanner (Strike 3)
 * Analyzes the public ledger of certificates issued for a domain.
 * Identifies "Burner Certificate" patterns used to evade revocation.
 */
export class CTLogService {
  /**
   * Queries crt.sh (public CT log aggregator) for certificate history.
   */
  static async analyze(hostname: string): Promise<CTLogSignal | null> {
    const signal: CTLogSignal = {
      totalCertificates: 0,
      recentCertificates: 0,
      issuers: [],
      heuristics: []
    };

    try {
      // Query crt.sh API (JSON output)
      const response = await axios.get(`https://crt.sh/?q=${hostname}&output=json`, { timeout: 5000 });
      const data = response.data || [];

      if (data.length === 0) return signal;

      signal.totalCertificates = data.length;
      const issuers = new Set<string>();
      const now = new Date();
      const sevenDaysAgo = new Date(now.getTime() - (7 * 24 * 60 * 60 * 1000));

      data.forEach((cert: any) => {
        if (cert.issuer_name) issuers.add(cert.issuer_name);
        if (cert.not_before) {
          const issuedAt = new Date(cert.not_before);
          if (issuedAt > sevenDaysAgo) signal.recentCertificates++;
        }
      });

      signal.issuers = Array.from(issuers);

      // --- HEURISTICS ---

      // 1. Burner Certificate Pattern (High frequency issuance)
      if (signal.recentCertificates > 3) {
        signal.heuristics.push({
          name: "BURNER_CERTIFICATE_PATTERN",
          score: 30,
          description: `Detected ${signal.recentCertificates} certificates issued in the last 7 days. High correlation with disposable infrastructure used to evade SSL revocation.`
        });
      }

      // 2. High-Churn Issuance (Many different CAs)
      if (signal.issuers.length > 2 && signal.totalCertificates > 5) {
        signal.heuristics.push({
          name: "HIGH_CHURN_CA_HISTORY",
          score: 15,
          description: `Domain utilizes multiple different Certificate Authorities (${signal.issuers.length}). Unusual for consistent reputable brands.`
        });
      }

      return signal;
    } catch (error) {
      // Graceful fail for CT log service (often rate-limited)
      return null;
    }
  }
}
