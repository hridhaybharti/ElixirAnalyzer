import { ExtractedFeatures } from './feature-extractor';

export interface HeuristicSignal {
  name: string;
  score: number;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export class HeuristicEngine {
  static generateSignals(features: ExtractedFeatures): HeuristicSignal[] {
    const signals: HeuristicSignal[] = [];

    // 1. Lexical Entropy Signal
    if (features.entropyScore > 4.2) {
      signals.push({
        name: 'HIGH_ENTROPY_NAME',
        score: 30,
        description: `Name randomness (${features.entropyScore}) is consistent with automated DGA generation.`,
        severity: 'high'
      });
    }

    // 2. Brand Spoofing Signal
    if (features.brandKeywords.length > 0) {
      signals.push({
        name: 'BRAND_SPOOF_DETECTED',
        score: 45,
        description: `Potential impersonation of: ${features.brandKeywords.join(', ')}.`,
        severity: 'critical'
      });
    }

    // 3. Structural Complexity Signal
    if (features.subdomainCount > 3) {
      signals.push({
        name: 'EXCESSIVE_SUBDOMAINS',
        score: 20,
        description: `High subdomain count (${features.subdomainCount}) often used to hide target paths.`,
        severity: 'medium'
      });
    }

    // 4. Obfuscation Character Signal
    if (features.specialCharCount > 5) {
      signals.push({
        name: 'OBFUSCATION_CHARS_DETECTED',
        score: 15,
        description: `Excessive special characters (${features.specialCharCount}) found in URL structure.`,
        severity: 'medium'
      });
    }

    // 5. Long URL Signal (Phishing standard)
    if (features.urlLength > 75) {
      signals.push({
        name: 'LONG_URL_PHISH_PATTERN',
        score: 10,
        description: `URL length (${features.urlLength}) exceeds safe visual thresholds.`,
        severity: 'low'
      });
    }

    return signals;
  }
}
