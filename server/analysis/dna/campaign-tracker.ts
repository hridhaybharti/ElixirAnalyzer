import { pipeline } from '@xenova/transformers';

export interface ScanFingerprint {
  id: string;
  vector: number[];
  metadata: {
    input: string;
    finalRiskScore: number;
    timestamp: number;
  };
}

export class CampaignDNAEngine {
  private static embedder: any = null;
  private static fingerprintStore: ScanFingerprint[] = [];
  // Lightweight feature-extraction model
  private static MODEL_NAME = 'Xenova/all-MiniLM-L6-v2';

  private static async init() {
    if (!this.classifier) {
      console.log(`[CampaignDNA] Initializing DNA Embedder: ${this.MODEL_NAME}...`);
      this.embedder = await pipeline('feature-extraction', this.MODEL_NAME);
    }
  }

  /**
   * Generates a unique "Mathematical DNA" vector for a scan based on its structural findings.
   */
  static async generateDNA(input: string, signals: string[]): Promise<number[]> {
    await this.init();
    
    // Combine input name with all discovered signal descriptions to create a "Context String"
    const context = `${input} ${signals.join(' ')}`;
    const output = await this.embedder(context, { pooling: 'mean', normalize: true });
    
    return Array.from(output.data);
  }

  /**
   * Compares a new scan against the DNA of all previous scans to find campaign matches.
   */
  static findMatches(newVector: number[], threshold: number = 0.85) {
    return this.fingerprintStore
      .map(stored => ({
        ...stored,
        similarity: this.cosineSimilarity(newVector, stored.vector)
      }))
      .filter(match => match.similarity >= threshold)
      .sort((a, b) => b.similarity - a.similarity);
  }

  static storeFingerprint(id: string, vector: number[], metadata: any) {
    this.fingerprintStore.push({ id, vector, metadata });
    // Keep store manageable (last 500 scans)
    if (this.fingerprintStore.length > 500) this.fingerprintStore.shift();
  }

  private static cosineSimilarity(vecA: number[], vecB: number[]): number {
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < vecA.length; i++) {
      dotProduct += vecA[i] * vecB[i];
      normA += vecA[i] * vecA[i];
      normB += vecB[i] * vecB[i];
    }
    return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
  }
}
