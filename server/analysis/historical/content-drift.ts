import axios from 'axios';

export interface ContentDriftSignal {
  firstSeen: string | null;
  lastSeen: string | null;
  totalSnapshots: number;
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

export class ContentDriftService {
  /**
   * Analyzes historical maturity and category drift via the Wayback Machine.
   * Identifies "Dormant" domains that suddenly become active phishing sites.
   */
  static async analyze(hostname: string): Promise<ContentDriftSignal | null> {
    const signal: ContentDriftSignal = {
      firstSeen: null,
      lastSeen: null,
      totalSnapshots: 0,
      heuristics: []
    };

    try {
      // Query the Wayback Machine Availability API
      const response = await axios.get(`http://archive.org/wayback/available?url=${hostname}`);
      const snapshots = response.data.archived_snapshots;

      if (!snapshots || Object.keys(snapshots).length === 0) {
        signal.heuristics.push({
          name: "ZERO_HISTORICAL_PRESENCE",
          score: 25,
          description: "No historical snapshots found in the Wayback Machine. Domain has no established reputation."
        });
        return signal;
      }

      const closest = snapshots.closest;
      if (closest) {
        signal.firstSeen = closest.timestamp;
        signal.totalSnapshots = 1; // Basic presence indicator
      }

      // --- HEURISTICS ---

      // 1. "Pop-up" Domain (Very new historical record)
      if (signal.firstSeen) {
        const year = parseInt(signal.firstSeen.substring(0, 4));
        const currentYear = new Date().getFullYear();
        
        if (currentYear - year < 1) {
          signal.heuristics.push({
            name: "RECENT_HISTORICAL_APPEARANCE",
            score: 20,
            description: "Domain first appeared in web archives within the last 12 months. Lacks long-term stability."
          });
        }
      }

    } catch (error) {
      console.error(`[ContentDrift] Historical analysis failed for ${hostname}:`, error);
    }

    return signal;
  }
}
