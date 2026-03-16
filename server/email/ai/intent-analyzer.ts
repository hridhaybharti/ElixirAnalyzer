import { pipeline } from '@xenova/transformers';

export interface EmailIntentSignal {
  intent: string;
  confidence: number;
  isCoercive: boolean;
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

/**
 * Email Intent & Psychological Analysis Service
 * Uses local Transformers to detect coercive language and social engineering.
 */
export class EmailIntentAnalyzer {
  private static classifier: any = null;
  private static MODEL_NAME = 'Xenova/distilbert-base-uncased-finetuned-sst-2-english';

  private static async init() {
    if (!this.classifier) {
      console.log(`[EmailIntent] Loading NLP Brain: ${this.MODEL_NAME}...`);
      this.classifier = await pipeline('text-classification', this.MODEL_NAME);
    }
  }

  /**
   * Analyzes the email body for psychological triggers.
   */
  static async analyze(bodyText: string): Promise<EmailIntentSignal | null> {
    if (!bodyText || bodyText.length < 10) return null;

    try {
      await this.init();
      
      // Clean text for NLP
      const cleanText = bodyText.replace(/<[^>]*>?/gm, '').substring(0, 512);
      const result = await this.classifier(cleanText);
      const sentiment = result[0];

      const signal: EmailIntentSignal = {
        intent: sentiment.label === 'NEGATIVE' ? 'Hostile/Coercive' : 'Neutral/Informative',
        confidence: sentiment.score,
        isCoercive: false,
        heuristics: []
      };

      // --- HEURISTICS: Psychological Manipulation Patterns ---

      const triggers = [
        { re: /urgent|immediate|action required|suspended|blocked/i, name: "URGENCY_TRIGGER", score: 25, desc: "High-urgency language detected to bypass critical thinking." },
        { re: /unauthorized|security alert|login attempt|password reset/i, name: "SECURITY_FEAR_TRIGGER", score: 20, desc: "Security-related fear tactic detected." },
        { re: /invoice|payment|overdue|bank transfer|wire/i, name: "FINANCIAL_PRESSURE", score: 20, desc: "Financial pressure or unexpected billing context." },
        { re: /official|government|legal notice|police|irs/i, name: "AUTHORITY_MIMICRY", score: 30, desc: "Attempt to mimic official or legal authority." }
      ];

      for (const trigger of triggers) {
        if (trigger.re.test(cleanText)) {
          signal.isCoercive = true;
          signal.heuristics.push({
            name: trigger.name,
            score: trigger.score,
            description: trigger.desc
          });
        }
      }

      // If sentiment is negative and triggers exist, it's a high-confidence threat
      if (sentiment.label === 'NEGATIVE' && signal.isCoercive) {
        signal.heuristics.push({
          name: "COERCIVE_SOCIAL_ENGINEERING",
          score: 15,
          description: "NLP analysis confirms negative/coercive emotional tone combined with phishing triggers."
        });
      }

      return signal;
    } catch (error) {
      console.error(`[EmailIntent] NLP analysis failed:`, error);
      return null;
    }
  }
}
