import axios from "axios";

/**
 * Archive Intelligence Service
 * Interacts with the Wayback Machine (Internet Archive) to detect 
 * sudden changes in domain behavior.
 */
class ArchiveService {
  private static instance: ArchiveService;

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
    const url = `http://archive.org/wayback/available?url=${domain}`;
    try {
      const response = await axios.get(url, { timeout: 5000 });
      const snapshots = response.data?.archived_snapshots;
      
      if (!snapshots || Object.keys(snapshots).length === 0) {
        return {
          hasHistory: false,
          firstSeen: null,
          message: "No historical record found. This domain might be extremely new or never crawled."
        };
      }

      const closest = snapshots.closest;
      return {
        hasHistory: true,
        firstSeen: closest.timestamp, // Format: YYYYMMDDhhmmss
        url: closest.url,
        message: `Domain first seen in global archives on ${closest.timestamp.substring(0, 4)}.`
      };
    } catch (error: any) {
      console.error(`[ArchiveService] Wayback lookup failed:`, error.message);
      return null;
    }
  }

  /**
   * Generate a signal based on domain maturity and archive presence.
   */
  public async getMaturitySignal(domain: string) {
    const history = await this.getHistory(domain);
    if (!history) return null;

    if (!history.hasHistory) {
      return {
        name: "Archive Blindspot",
        status: "warn",
        description: "This domain has no history in global web archives. High probability of being a recently registered disposable domain.",
        scoreImpact: 15,
      };
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
      };
    }

    return {
      name: "Short Archive History",
      status: "warn",
      description: `Domain only appeared in archives recently (${firstYear}). Frequent pattern for short-lived phishing campaigns.`,
      scoreImpact: 5,
    };
  }
}

export const archiveService = ArchiveService.getInstance();
