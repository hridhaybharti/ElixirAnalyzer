import axios from "axios";
import { isIP as netIsIP } from "net";
import { secretsManager } from "../utils/secrets";
import { TTLCache } from "../utils/ttlCache";

/**
 * Enhanced OSINT Service - Seamless Multi-Source Intelligence
 * Handles real-time lookups for IPs, Domains, and URLs.
 */

export interface OSINTReport {
  virusTotal?: any;
  abuseIPDB?: any;
  ipLocation?: any;
  urlScan?: any;
  shodan?: any;
}

class OSINTService {
  private static instance: OSINTService;
  private cache = new TTLCache<any>({
    ttlMs: (Number(process.env.OSINT_CACHE_TTL_SECONDS) || 3600) * 1000,
    maxEntries: Number(process.env.OSINT_CACHE_MAX_ENTRIES) || 2000,
  });

  private constructor() {}

  public static getInstance(): OSINTService {
    if (!OSINTService.instance) {
      OSINTService.instance = new OSINTService();
    }
    return OSINTService.instance;
  }

  /**
   * Safe JSON fetch with timeout
   */
  private async fetchSafe(url: string, headers: Record<string, string>, timeout = 5000) {
    try {
      const response = await axios.get(url, { headers, timeout });
      return response.data;
    } catch (error: any) {
      console.error(`[OSINT] Request to ${url} failed:`, error.message);
      return null;
    }
  }

  private async cached<T>(
    key: string,
    fn: () => Promise<T>,
    ttlSeconds?: number,
  ): Promise<T> {
    if (process.env.OSINT_CACHE_ENABLED === "0") return await fn();

    const cached = this.cache.get(key);
    if (cached !== undefined) return cached as T;

    const value = await fn();
    this.cache.set(key, value, ttlSeconds ? ttlSeconds * 1000 : undefined);
    return value;
  }

  /**
   * VirusTotal lookup (v3 API)
   */
  public async getVirusTotal(target: string, type: "ip" | "domain" | "url") {
    const key = secretsManager.getSecret("VIRUSTOTAL_API_KEY");
    if (!key) return null;

    let endpoint = "";
    if (type === "ip") endpoint = `ip_addresses/${target}`;
    else if (type === "domain") endpoint = `domains/${target}`;
    else {
      const urlId = Buffer.from(target).toString("base64url").replace(/=/g, "");
      endpoint = `urls/${urlId}`;
    }

    const cacheKey = `vt:${type}:${target}`;
    const data = await this.cached(
      cacheKey,
      () =>
        this.fetchSafe(`https://www.virustotal.com/api/v3/${endpoint}`, {
          "x-apikey": key,
        }),
      3600,
    );
    if (!data?.data) return { ok: false, error: "No data returned" };

    const attrs = data.data.attributes;
    const lastAnalysisDate =
      typeof attrs.last_analysis_date === "number"
        ? new Date(attrs.last_analysis_date * 1000).toISOString()
        : undefined;
    const id =
      type === "url"
        ? Buffer.from(target).toString("base64url").replace(/=/g, "")
        : target;
    return {
      ok: true,
      type,
      id,
      stats: attrs.last_analysis_stats,
      reputation: attrs.reputation,
      permalink: `https://www.virustotal.com/gui/${type}/${type === "url" ? Buffer.from(target).toString("base64url") : target}`,
      lastAnalysisDate,
    };
  }

  /**
   * AbuseIPDB lookup (v2 API)
   */
  public async getAbuseIPDB(ip: string) {
    const key = secretsManager.getSecret("ABUSEIPDB_API_KEY");
    if (!key || !netIsIP(ip)) return null;

    const data = await this.cached(
      `abuseipdb:${ip}`,
      () =>
        this.fetchSafe(
          `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90&verbose=true`,
          {
            Key: key,
            Accept: "application/json",
          },
        ),
      3600,
    );
    
    return data?.data || null;
  }

  /**
   * urlscan.io lookup - NEW Source
   */
  public async getURLScan(url: string) {
    const key = secretsManager.getSecret("URLSCAN_API_KEY");
    if (!key) return null;

    // Search for existing scans first to be seamless
    const search = await this.cached(
      `urlscan:${url}`,
      () =>
        this.fetchSafe(`https://urlscan.io/api/v1/search/?q=url:"${url}"`, {
          "API-Key": key,
        }),
      3600,
    );
    return search?.results?.[0] || null;
  }

  /**
   * IP-API Geolocation (No key required)
   */
  public async getIPLocation(ip: string) {
    if (!netIsIP(ip)) return null;
    const j = await this.cached(
      `ipapi:${ip}`,
      () =>
        this.fetchSafe(
          `http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,mobile,proxy,hosting`,
          {},
          5000,
        ),
      86400,
    );

    if (!j || j.status !== "success") {
      return {
        ip,
        source: "ip-api.com",
        error: typeof j?.message === "string" ? j.message : "Lookup failed",
      };
    }

    return {
      ip,
      source: "ip-api.com",
      city: typeof j.city === "string" ? j.city : undefined,
      region: typeof j.regionName === "string" ? j.regionName : undefined,
      country: typeof j.country === "string" ? j.country : undefined,
      countryCode: typeof j.countryCode === "string" ? j.countryCode : undefined,
      latitude: typeof j.lat === "number" ? j.lat : undefined,
      longitude: typeof j.lon === "number" ? j.lon : undefined,
      accuracy: "approximate",
    };
  }
}

export const osintService = OSINTService.getInstance();
