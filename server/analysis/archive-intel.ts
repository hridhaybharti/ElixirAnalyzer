import axios from "axios";
import type { HeuristicResult } from "@shared/schema";
import { TTLCache } from "../utils/ttlCache";

/**
 * Archive Intelligence Service
 * Interacts with the Wayback Machine (Internet Archive) to detect 
 * sudden changes in domain behavior.
 */
class ArchiveService {
  private static instance: ArchiveService;
  private cache = new TTLCache<any>({
    ttlMs: (Number(process.env.ARCHIVE_CACHE_TTL_SECONDS) || 86400) * 1000,
    maxEntries: Number(process.env.ARCHIVE_CACHE_MAX_ENTRIES) || 2000,
  });

  private constructor() {}

  public static getInstance(): ArchiveService {
    if (!ArchiveService.instance) {
      ArchiveService.instance = new ArchiveService();
    }
    return ArchiveService.instance;
  }

  /**
   * Check if a domain has a history in the Wayback Machine.
   * A "Time-Travel" heuristic to identify aged domains vs newly repurposed ones.
   */
  public async getHistory(domain: string) {
    const cacheKey = `wayback:${domain.toLowerCase()}`;
    const cached = this.cache.get(cacheKey);
    if (cached !== undefined) return cached;

    const url = `http://archive.org/wayback/available?url=${domain}`;
    try {
      const response = await axios.get(url, { timeout: 5000 });
      const snapshots = response.data?.archived_snapshots;
      
      if (!snapshots || Object.keys(snapshots).length === 0) {
        const res = {
          hasHistory: false,
          firstSeen: null,
          message: "No historical record found. This domain might be extremely new or never crawled."
        };
        this.cache.set(cacheKey, res);
        return res;
      }

      const closest = snapshots.closest;
      const res = {
        hasHistory: true,
        firstSeen: closest.timestamp, // Format: YYYYMMDDhhmmss
        url: closest.url,
        message: `Domain first seen in global archives on ${closest.timestamp.substring(0, 4)}.`
      };
      this.cache.set(cacheKey, res);
      return res;
    } catch (error: any) {
      console.error(`[ArchiveService] Wayback lookup failed:`, error.message);
      return null;
    }
  }

  /**
   * Generate a signal based on domain maturity and archive presence.
   */
  public async getMaturitySignal(domain: string): Promise<HeuristicResult | null> {
    const history = await this.getHistory(domain);
    if (!history) return null;

    if (!history.hasHistory) {
      return {
        name: "Archive Blindspot",
        status: "warn",
        description: "This domain has no history in global web archives. High probability of being a recently registered disposable domain.",
        scoreImpact: 15,
      } satisfies HeuristicResult;
    }

    // Calculate age from archive timestamp
    const firstYear = parseInt(history.firstSeen.substring(0, 4));
    const currentYear = new Date().getFullYear();
    const archiveAge = currentYear - firstYear;

    if (archiveAge > 5) {
      return {
        name: "Domain Maturity (Archives)",
        status: "pass",
        description: `Domain has a stable presence in web archives dating back to ${firstYear} (${archiveAge} years).`,
        scoreImpact: -15, // Trust signal
      } satisfies HeuristicResult;
    }

    return {
      name: "Short Archive History",
      status: "warn",
      description: `Domain only appeared in archives recently (${firstYear}). Frequent pattern for short-lived phishing campaigns.`,
      scoreImpact: 5,
    } satisfies HeuristicResult;
  }
}

export const archiveService = ArchiveService.getInstance();
