import axios from 'axios';

export interface GeoMappedConnection {
  url: string;
  method: string;
  type: string;
  ip?: string;
  country?: string;
  countryCode?: string;
  isp?: string;
}

/**
 * Sandbox Geo-Visualizer Service
 * Resolves network connections from the Sandbox detonation to their physical locations.
 */
export class SandboxGeoService {
  private static geoCache: Map<string, any> = new Map();

  static async mapConnections(networkLog: any[]): Promise<GeoMappedConnection[]> {
    const mapped: GeoMappedConnection[] = [];
    
    // Process only unique hostnames to save API calls
    const hostnames = Array.from(new Set(networkLog.map(log => {
      try {
        return new URL(log.url).hostname;
      } catch {
        return null;
      }
    }).filter(h => h !== null)));

    const geoMap: Record<string, any> = {};

    // Parallel lookup for hostnames
    await Promise.all(hostnames.slice(0, 10).map(async (host) => {
      if (this.geoCache.has(host!)) {
        geoMap[host!] = this.geoCache.get(host!);
        return;
      }

      try {
        const response = await axios.get(`http://ip-api.com/json/${host}?fields=status,country,countryCode,isp,query`);
        if (response.data.status === 'success') {
          const data = {
            ip: response.data.query,
            country: response.data.country,
            countryCode: response.data.countryCode,
            isp: response.data.isp
          };
          this.geoCache.set(host!, data);
          geoMap[host!] = data;
        }
      } catch (err) {
        // Silent fail for geo lookup
      }
    }));

    for (const log of networkLog) {
      try {
        const host = new URL(log.url).hostname;
        const geo = geoMap[host];
        mapped.push({
          ...log,
          ip: geo?.ip,
          country: geo?.country,
          countryCode: geo?.countryCode,
          isp: geo?.isp
        });
      } catch {
        mapped.push(log);
      }
    }

    return mapped;
  }
}
