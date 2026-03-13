import { resolveMx, resolveTxt, resolveNs, resolveSoa } from 'dns/promises';

export interface DNSForensicSignal {
  mxRecords: string[];
  txtRecords: string[];
  nsRecords: string[];
  soaRecord: any | null;
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

export class DNSForensicService {
  static async analyze(hostname: string): Promise<DNSForensicSignal> {
    const signal: DNSForensicSignal = {
      mxRecords: [],
      txtRecords: [],
      nsRecords: [],
      soaRecord: null,
      heuristics: []
    };

    try {
      const [mx, txt, ns, soa] = await Promise.allSettled([
        resolveMx(hostname),
        resolveTxt(hostname),
        resolveNs(hostname),
        resolveSoa(hostname)
      ]);

      if (mx.status === 'fulfilled') signal.mxRecords = mx.value.map(r => r.exchange);
      if (txt.status === 'fulfilled') signal.txtRecords = txt.value.flat();
      if (ns.status === 'fulfilled') signal.nsRecords = ns.value;
      if (soa.status === 'fulfilled') signal.soaRecord = soa.value;

      // --- HEURISTICS ---

      // 1. SOA Forensic: Administrative Credibility Check
      if (signal.soaRecord && signal.soaRecord.hostmaster) {
        const hostmaster = signal.soaRecord.hostmaster.toLowerCase();
        const brands = ['paypal', 'microsoft', 'google', 'apple', 'bank', 'secure'];
        const isOfficialBrandMatch = brands.some(b => hostname.includes(b));
        
        // If it's a brand lookalike but hostmaster is generic or suspicious
        const isGenericEmail = hostmaster.includes('gmail') || 
                               hostmaster.includes('outlook') || 
                               hostmaster.includes('yandex') ||
                               hostmaster.includes('proton');

        if (isOfficialBrandMatch && isGenericEmail) {
          signal.heuristics.push({
            name: "SOA_ADMIN_CREDIBILITY_FAILURE",
            score: 35,
            description: `Domain mimics a major brand, but the SOA administrative contact (${hostmaster}) is a generic or suspicious address. High-fidelity Phishing indicator.`
          });
        }
      }

      // 2. Missing Mail Server (Suspicious for corporate domains)
      if (signal.mxRecords.length === 0) {
        signal.heuristics.push({
          name: "NO_MAIL_SERVER",
          score: 15,
          description: "No MX records found. Highly suspicious for domains mimicking corporate entities."
        });
      }

      // 3. SPF/DMARC Absence (Classic phishing indicator)
      const hasSPF = signal.txtRecords.some(r => r.includes("v=spf1"));
      if (!hasSPF && signal.mxRecords.length > 0) {
        signal.heuristics.push({
          name: "MISSING_SPF_POLICY",
          score: 20,
          description: "Domain has mail servers but no SPF security policy. Increased risk of spoofing."
        });
      }

      // 4. Bulletproof/High-Risk Nameservers
      const highRiskNS = ['cloudns.net', 'registrar-servers.com', 'dnspod.com', 'freenom.com'];
      const nsMatch = signal.nsRecords.some(ns => highRiskNS.some(risk => ns.toLowerCase().includes(risk)));
      if (nsMatch) {
        signal.heuristics.push({
          name: "HIGH_RISK_NAMESERVER",
          score: 25,
          description: "Domain uses nameservers frequently associated with bulletproof hosting or disposable infrastructure."
        });
      }

    } catch (error) {
      console.error(`[DNSForensics] Analysis failed for ${hostname}:`, error);
    }

    return signal;
  }
}
