import axios from 'axios';

export interface PortSignal {
  openPorts: number[];
  services: string[];
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

/**
 * C2 Protocol & Port Intelligence (Strike 3)
 * Uses Shodan-style passive scanning to identify Command & Control infrastructure.
 */
export class PortIntelligenceService {
  /**
   * Probes for open ports and known C2 signatures.
   */
  static async analyze(ip: string): Promise<PortSignal | null> {
    // In a real-world scenario, we'd use the Shodan API.
    // For this implementation, we utilize a trusted passive OSINT provider (InternetDB by Shodan)
    // which is free, fast, and requires no API key for basic port mapping.
    try {
      const response = await axios.get(`https://internetdb.shodan.io/${ip}`);
      const data = response.data;

      if (!data || !data.ports) return null;

      const signal: PortSignal = {
        openPorts: data.ports,
        services: data.tags || [],
        heuristics: []
      };

      // --- HEURISTICS: C2 & Malicious Protocol Detection ---

      // 1. Common C2 / Proxy Ports (Non-standard web ports)
      const c2Ports = [8080, 8888, 9999, 5000, 3128];
      const foundC2Ports = data.ports.filter((p: number) => c2Ports.includes(p));

      if (foundC2Ports.length > 0) {
        signal.heuristics.push({
          name: "SUSPICIOUS_CONTROL_PORT_OPEN",
          score: 20,
          description: `Detected open non-standard ports (${foundC2Ports.join(', ')}) frequently used for C2 communication or malicious proxies.`
        });
      }

      // 2. Critical Service Exposure (Database/SSH on Web Host)
      const sensitivePorts = [22, 3389, 3306, 5432, 27017];
      const foundSensitive = data.ports.filter((p: number) => sensitivePorts.includes(p));
      
      if (foundSensitive.length > 0) {
        signal.heuristics.push({
          name: "EXPOSED_ADMIN_INFRASTRUCTURE",
          score: 15,
          description: `Sensitive administrative or database ports (${foundSensitive.join(', ')}) are exposed. Common in poorly secured attack staging servers.`
        });
      }

      // 3. IoT / Embedded Botnet Signature
      if (data.ports.includes(23) || data.ports.includes(2323)) {
        signal.heuristics.push({
          name: "IOT_BOTNET_SIGNATURE",
          score: 25,
          description: "Telnet ports are exposed. High correlation with Mirai-variant botnets or compromised IoT edge devices."
        });
      }

      return signal;
    } catch (error) {
      // Graceful fail if Shodan has no data for the IP
      return null;
    }
  }
}
