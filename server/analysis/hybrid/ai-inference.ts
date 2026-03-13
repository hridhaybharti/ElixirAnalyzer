import { pipeline } from '@xenova/transformers';

export interface AISignal {
  modelName: string;
  maliciousProbability: number;
  label: "phishing" | "safe";
}

export class AIInferenceService {
  private static classifier: any = null;
  private static MODEL_NAME = 'Xenova/distilbert-base-uncased-finetuned-phishing';

  /**
   * Initializes the local AI model (Transformers.js)
   * Only loads once to conserve memory
   */
  private static async init() {
    if (!this.classifier) {
      console.log(`[AIInference] Loading local brain: ${this.MODEL_NAME}...`);
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
