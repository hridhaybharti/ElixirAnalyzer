export interface AISignal {
  modelName: string;
  maliciousProbability: number;
  label: "phishing" | "safe";
}

export class AIInferenceService {
  private static classifier: any = null;
  private static MODEL_NAME = 'Xenova/distilbert-base-uncased-finetuned-phishing';
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

  /**
   * Initializes the local AI model (Transformers.js)
   * Only loads once to conserve memory
   */
  private static async init() {
    if (!this.classifier) {
      console.log(`[AIInference] Loading local brain: ${this.MODEL_NAME}...`);
      const pipeline = await this.loadPipeline();
      this.classifier = await pipeline('text-classification', this.MODEL_NAME);
    }
  }

  static async getSignals(input: string): Promise<AISignal[]> {
    try {
      await this.init();
      
      const results = await this.classifier(input);
      const topResult = results[0];
      
      // The model labels are typically 'LABEL_1' (phish) and 'LABEL_0' (safe) 
      // or literally 'phishing' / 'safe' depending on the export
      const isMalicious = topResult.label.toLowerCase().includes('phish') || 
                          topResult.label === 'LABEL_1';

      return [{
        modelName: "LocalSentinel-V1",
        maliciousProbability: isMalicious ? topResult.score : (1 - topResult.score),
        label: isMalicious ? "phishing" : "safe"
      }];
    } catch (error) {
      console.error("[AIInference] Local inference failed:", error);
      return [];
    }
  }
}
