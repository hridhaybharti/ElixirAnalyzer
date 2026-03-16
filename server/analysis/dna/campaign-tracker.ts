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
  private static pipelineFn: any = null;
  private static pipelineLoadError: unknown = null;

  private static async loadPipeline() {
    if (this.pipelineFn) return this.pipelineFn;
    if (this.pipelineLoadError) throw this.pipelineLoadError;

    try {
      const pkg = '@xenova/transformers';
      const mod = (await import(pkg as any)) as any;
      if (!mod?.pipeline) throw new Error(`Missing export 'pipeline' from ${pkg}`);
      this.pipelineFn = mod.pipeline;
      return this.pipelineFn;
    } catch (err) {
      this.pipelineLoadError = err;
      throw err;
    }
  }

  private static async init() {
    if (this.embedder) return;

    try {
      console.log(`[CampaignDNA] Initializing DNA Embedder: ${this.MODEL_NAME}...`);
      const pipeline = await this.loadPipeline();
      this.embedder = await pipeline('feature-extraction', this.MODEL_NAME);
    } catch (err) {
      // Optional dependency missing or model download unavailable; fall back to a lightweight deterministic vector.
      console.warn('[CampaignDNA] Embedder unavailable; using fallback vectors:', err);
      this.embedder = null;
    }
  }

  /**
   * Generates a unique "Mathematical DNA" vector for a scan based on its structural findings.
   */
  static async generateDNA(input: string, signals: string[]): Promise<number[]> {
    await this.init();
    
    // Combine input name with all discovered signal descriptions to create a "Context String"
    const context = `${input} ${signals.join(' ')}`;

    if (!this.embedder) {
      return this.fallbackVector(context);
    }

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
    if (vecA.length === 0 || vecB.length === 0) return 0;
    const len = Math.min(vecA.length, vecB.length);
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < len; i++) {
      const a = vecA[i];
      const b = vecB[i];
      dotProduct += a * b;
      normA += a * a;
      normB += b * b;
    }
    const denom = Math.sqrt(normA) * Math.sqrt(normB);
    return denom > 0 ? dotProduct / denom : 0;
  }

  private static fallbackVector(text: string, size: number = 64): number[] {
    const vec = new Array<number>(size).fill(0);
    const lowered = text.toLowerCase();

    for (let i = 0; i < lowered.length; i++) {
      const code = lowered.charCodeAt(i);
      const idx = code % size;
      vec[idx] += 1;
    }

    // Normalize (unit length) to keep cosine similarity stable
    let norm = 0;
    for (const x of vec) norm += x * x;
    norm = Math.sqrt(norm);
    if (norm > 0) {
      for (let i = 0; i < vec.length; i++) vec[i] = vec[i] / norm;
    }

    return vec;
  }
}
