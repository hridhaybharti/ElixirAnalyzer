import axios from 'axios';

export interface NeighborSignal {
  subnet: string;
  maliciousNeighborCount: number;
  neighborDensity: number; // Percentage
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

export class IPNeighborService {
  /**
   * Analyzes the /24 subnet of the target IP for a 'Bad Neighborhood' pattern.
   * This is a critical indicator of coordinated malicious infrastructure.
   */
  static async analyze(ip: string): Promise<NeighborSignal | null> {
    const vtKey = process.env.VIRUSTOTAL_API_KEY;
    if (!vtKey) return null;

    const parts = ip.split('.');
    if (parts.length !== 4) return null;
    
    // Define the /24 subnet (e.g., 1.2.3.0/24)
    const subnet = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    const signal: NeighborSignal = {
      subnet,
      maliciousNeighborCount: 0,
      neighborDensity: 0,
      heuristics: []
    };

    try {
      // Use VirusTotal API to find other malicious IPs in the same subnet
      // Note: This uses the /ip_addresses/{ip}/related_objects/communicating_files or similar
      // For this strike, we use the VT Search API to find malicious nodes in the network range.
      const response = await axios.get(`https://www.virustotal.com/api/v3/search?query=net:${subnet}`, {
        headers: { 'x-api-key': vtKey }
      });

      const data = response.data.data || [];
      signal.maliciousNeighborCount = data.length;
      signal.neighborDensity = (data.length / 254) * 100;

      // --- HEURISTICS ---

      // 1. Cluster Detection (Low Density)
      if (signal.maliciousNeighborCount >= 3) {
        signal.heuristics.push({
          name: "SUBNET_MALICIOUS_CLUSTER",
          score: 15,
          description: `Detected ${signal.maliciousNeighborCount} known malicious neighbors in the ${subnet} range.`
        });
      }

      // 2. High-Density Bad Neighborhood (Criminal Infrastructure)
      if (signal.neighborDensity > 2) {
        signal.heuristics.push({
          name: "CRIMINAL_INFRASTRUCTURE_DETECTED",
          score: 35,
          description: `Subnet density is critically high (${signal.neighborDensity.toFixed(2)}%). IP is likely part of a dedicated attack network.`
        });
      }

    } catch (error) {
      console.error(`[IPNeighbor] Subnet analysis failed for ${ip}:`, error);
    }

    return signal;
  }
}
