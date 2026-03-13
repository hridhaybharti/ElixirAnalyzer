import tldextract from 'tldextract';

export interface ExtractedFeatures {
  urlLength: number;
  subdomainCount: number;
  pathDepth: number;
  tld: string;
  entropyScore: number;
  specialCharCount: number;
  brandKeywords: string[];
}

export class FeatureExtractor {
  private static brands = ['paypal', 'google', 'microsoft', 'apple', 'amazon', 'netflix', 'bankofamerica', 'chase', 'wellsfargo'];

  static extract(input: string): ExtractedFeatures {
    let url: URL;
    try {
      url = new URL(input.startsWith('http') ? input : `https://${input}`);
    } catch {
      // Fallback for raw domains
      return this.extractFromRaw(input);
    }

    const hostname = url.hostname;
    const path = url.pathname;
    const tldInfo = tldextract(hostname);

    return {
      urlLength: input.length,
      subdomainCount: hostname.split('.').length - 2,
      pathDepth: path.split('/').filter(p => p.length > 0).length,
      tld: tldInfo.tld,
      entropyScore: this.calculateEntropy(hostname),
      specialCharCount: (input.match(/[@%&=?#_]/g) || []).length,
      brandKeywords: this.detectBrands(hostname)
    };
  }

  private static extractFromRaw(domain: string): ExtractedFeatures {
    return {
      urlLength: domain.length,
      subdomainCount: domain.split('.').length - 2,
      pathDepth: 0,
      tld: domain.split('.').pop() || '',
      entropyScore: this.calculateEntropy(domain),
      specialCharCount: (domain.match(/[@%&=?#_]/g) || []).length,
      brandKeywords: this.detectBrands(domain)
    };
  }

  private static calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    return parseFloat(entropy.toFixed(3));
  }

  private static detectBrands(str: string): string[] {
    const lowerStr = str.toLowerCase();
    return this.brands.filter(brand => lowerStr.includes(brand));
  }
}
