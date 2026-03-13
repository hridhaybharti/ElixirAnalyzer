import { HfInference } from "@huggingface/inference";

export interface AISignal {
  modelName: string;
  maliciousProbability: number;
  label: "phishing" | "safe";
}

export class AIInferenceService {
  private static hf = new HfInference(process.env.HUGGINGFACE_API_KEY);
  
  // High-fidelity phishing detector from Hugging Face
  private static LEXICAL_MODEL = "madhurjindal/autonlp-Phishing-Detector-20554160";
  // Structural URL classifier
  private static STRUCTURAL_MODEL = "elvis/distilbert-phishing-detector";

  static async getSignals(input: string): Promise<AISignal[]> {
    if (!process.env.HUGGINGFACE_API_KEY) {
      console.warn("[AIInference] HUGGINGFACE_API_KEY missing. Skipping AI layer.");
      return [];
    }

    try {
      const results = await Promise.all([
        this.hf.textClassification({ model: this.LEXICAL_MODEL, inputs: input }),
        this.hf.textClassification({ model: this.STRUCTURAL_MODEL, inputs: input })
      ]);

      return results.map((res, index) => {
        const topResult = res[0];
        const isMalicious = topResult.label.toLowerCase().includes("phish") || 
                           topResult.label.toLowerCase().includes("malicious") ||
                           topResult.label === "LABEL_1"; // Some models use LABEL_1 for positive

        return {
          modelName: index === 0 ? "LexicalPhishNet" : "StructuralClassifier",
          maliciousProbability: isMalicious ? topResult.score : (1 - topResult.score),
          label: isMalicious ? "phishing" : "safe"
        };
      });
    } catch (error) {
      console.error("[AIInference] Error during inference:", error);
      return [];
    }
  }
}
