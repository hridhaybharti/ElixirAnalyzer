import axios from 'axios';

export interface SSLFingerprintSignal {
  issuer: string;
  subject: string;
  validFrom: string;
  validTo: string;
  serialNumber: string;
  fingerprint: string;
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

export class TLSService {
  /**
   * Performs passive SSL/TLS fingerprinting and certificate analysis.
   * This identifies malicious server configurations often used by C2 or Phishing kits.
   */
  static async analyze(hostname: string): Promise<SSLFingerprintSignal | null> {
    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    if (!vtKey) return null;

    const signal: SSLFingerprintSignal = {
      issuer: '',
      subject: '',
      validFrom: '',
      validTo: '',
      serialNumber: '',
      fingerprint: '',
      heuristics: []
    };

    try {
      // Use VirusTotal IP/Domain API to get the last known SSL certificate
      const response = await axios.get(`https://www.virustotal.com/api/v3/domains/${hostname}`, {
        headers: { 'x-api-key': vtKey }
      });

      const cert = response.data.data?.attributes?.last_https_certificate;
      if (!cert) return null;

      signal.issuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown';
      signal.subject = cert.subject?.CN || 'Unknown';
      signal.validFrom = cert.validity?.not_before || '';
      signal.validTo = cert.validity?.not_after || '';
      signal.fingerprint = cert.thumbprint || '';

      // --- HEURISTICS ---

      // 1. Disposable CA Detection (Let's Encrypt + Brand Mimicry)
      const isFreeCert = signal.issuer.toLowerCase().includes("let's encrypt") || 
                         signal.issuer.toLowerCase().includes("zeroSSL");
      
      const brands = ['paypal', 'microsoft', 'google', 'apple', 'bank', 'secure'];
      const mimicsBrand = brands.some(b => hostname.toLowerCase().includes(b));

      if (isFreeCert && mimicsBrand) {
        signal.heuristics.push({
          name: "DISPOSABLE_CERT_BRAND_MIMIC",
          score: 30,
          description: "Domain mimics a major brand but uses a short-lived disposable SSL certificate."
        });
      }

      // 2. Self-Signed or High-Risk Issuer
      const highRiskIssuers = ['Snake Oil', 'Internal', 'Localhost', 'Default'];
      if (highRiskIssuers.some(i => signal.issuer.includes(i))) {
        signal.heuristics.push({
          name: "SELF_SIGNED_OR_UNTRUSTED_CA",
          score: 25,
          description: "Server uses a self-signed or default 'Snake Oil' certificate often seen in C2 nodes."
        });
      }

      // 3. Temporal Anomaly (Very recently issued)
      const issuedAt = new Date(signal.validFrom);
      const daysSinceIssued = (Date.now() - issuedAt.getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceIssued < 3) {
        signal.heuristics.push({
          name: "FRESH_SSL_CERTIFICATE",
          score: 15,
          description: "SSL certificate was issued within the last 72 hours. Typical for burner phishing sites."
        });
      }

    } catch (error) {
      console.error(`[TLSService] SSL analysis failed for ${hostname}:`, error);
    }

    return signal;
  }
}
