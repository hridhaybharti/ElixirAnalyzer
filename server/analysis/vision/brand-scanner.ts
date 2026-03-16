import fs from 'fs';
import path from 'path';

export interface BrandVisionSignal {
  detectedBrands: string[];
  confidence: number;
  heuristics: {
    name: string;
    score: number;
    description: string;
  }[];
}

/**
 * Brand Vision Scanner (Strike 2)
 * Uses local Zero-Shot Image Classification to detect brand logos in screenshots.
 */
export class BrandVisionService {
  private static classifier: any = null;
  private static MODEL_NAME = 'Xenova/clip-vit-base-patch32';
  private static pipelineFn: any = null;
  private static pipelineLoadError: unknown = null;
  private static CANDIDATE_LABELS = [
    'a photo of a microsoft login page',
    'a photo of a paypal login page',
    'a photo of a google login page',
    'a photo of a bank login page',
    'a photo of a generic website'
  ];

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
    if (!this.classifier) {
      console.log(`[BrandVision] Loading Vision Brain: ${this.MODEL_NAME}...`);
      const pipeline = await this.loadPipeline();
      this.classifier = await pipeline('zero-shot-image-classification', this.MODEL_NAME);
    }
  }

  static async analyze(screenshotPath: string, hostname: string): Promise<BrandVisionSignal | null> {
    const absolutePath = path.isAbsolute(screenshotPath) 
      ? screenshotPath 
      : path.join(process.cwd(), screenshotPath.startsWith('/') ? screenshotPath.substring(1) : screenshotPath);

    if (!fs.existsSync(absolutePath)) {
      console.warn(`[BrandVision] Screenshot not found at: ${absolutePath}`);
      return null;
    }

    try {
      await this.init();
      
      const results = await this.classifier(absolutePath, this.CANDIDATE_LABELS);
      
      // Filter for high-confidence brand matches (excluding generic)
      const topMatch = results[0];
      const isBrandMatch = topMatch.score > 0.6 && !topMatch.label.includes('generic');

      const signal: BrandVisionSignal = {
        detectedBrands: isBrandMatch ? [topMatch.label] : [],
        confidence: topMatch.score,
        heuristics: []
      };

      if (isBrandMatch) {
        // --- HEURISTIC: Visual Identity Mismatch ---
        // Check if the visually detected brand matches the domain name
        const brandName = topMatch.label.split(' ')[4]; // extracts 'microsoft', 'paypal', etc.
        const domainMatchesBrand = hostname.toLowerCase().includes(brandName);

        if (!domainMatchesBrand) {
          signal.heuristics.push({
            name: "VISUAL_IDENTITY_MISMATCH",
            score: 40,
            description: `AI Vision detected a ${brandName.toUpperCase()} interface, but the domain (${hostname}) does not belong to that entity. High-fidelity Phishing indicator.`
          });
        }
      }

      return signal;
    } catch (error) {
      console.error(`[BrandVision] Visual analysis failed:`, error);
      return null;
    }
  }
}
