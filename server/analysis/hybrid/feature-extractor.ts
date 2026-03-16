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
  private static COMMON_2PART_TLDS = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk',
    'com.au', 'net.au', 'org.au',
    'co.in',
    'com.br',
    'com.mx',
    'co.jp',
    'co.kr',
    'co.nz',
  ]);

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
    const tld = this.extractTld(hostname);
    const hostParts = hostname.split('.').filter(Boolean);
    const tldParts = tld ? tld.split('.').length : 1;
    const subdomainCount = Math.max(0, hostParts.length - (tldParts + 1));

    return {
      urlLength: input.length,
      subdomainCount,
      pathDepth: path.split('/').filter(p => p.length > 0).length,
      tld,
      entropyScore: this.calculateEntropy(hostname),
      specialCharCount: (input.match(/[@%&=?#_]/g) || []).length,
      brandKeywords: this.detectBrands(hostname)
    };
  }

  private static extractFromRaw(domain: string): ExtractedFeatures {
    const tld = this.extractTld(domain);
    const hostParts = domain.split('.').filter(Boolean);
    const tldParts = tld ? tld.split('.').length : 1;
    const subdomainCount = Math.max(0, hostParts.length - (tldParts + 1));
    return {
      urlLength: domain.length,
      subdomainCount,
      pathDepth: 0,
      tld,
      entropyScore: this.calculateEntropy(domain),
      specialCharCount: (domain.match(/[@%&=?#_]/g) || []).length,
      brandKeywords: this.detectBrands(domain)
    };
  }

  private static extractTld(hostname: string): string {
    const parts = hostname.split('.').map(p => p.trim()).filter(Boolean);
    if (parts.length < 2) return '';

    const lastTwo = parts.slice(-2).join('.').toLowerCase();
    if (this.COMMON_2PART_TLDS.has(lastTwo) && parts.length >= 3) return lastTwo;
    return parts[parts.length - 1].toLowerCase();
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
