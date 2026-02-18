import { chromium } from 'playwright';
import path from 'path';
import fs from 'fs';
import { HeuristicResult } from '@shared/schema';

/**
 * Visual Intelligence Service (The 'Hazmat Suit')
 * Uses a headless browser to safely capture screenshots and 
 * extract visual heuristics from malicious sites.
 */
class VisualEngine {
  private static instance: VisualEngine;
  private screenshotDir = path.join(process.cwd(), 'server', 'data', 'screenshots');

  private constructor() {
    if (!fs.existsSync(this.screenshotDir)) {
      fs.mkdirSync(this.screenshotDir, { recursive: true });
    }
  }

  public static getInstance(): VisualEngine {
    if (!VisualEngine.instance) {
      VisualEngine.instance = new VisualEngine();
    }
    return VisualEngine.instance;
  }

  /**
   * Safely captures a screenshot of a URL.
   * Note: Requires playwright browsers to be installed on the host.
   */
  public async captureSafeScreenshot(url: string, id: string) {
    console.log(`[VisualEngine] Attempting capture for: ${url}`);
    
    // Check if browsers are available (graceful failure)
    try {
      const browser = await chromium.launch({ headless: true });
      const context = await browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36'
      });
      
      const page = await context.newPage();
      
      // Strict 15s timeout for safety
      await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
      
      const filename = `${id}.jpg`;
      const fullPath = path.join(this.screenshotDir, filename);
      
      await page.screenshot({ path: fullPath, type: 'jpeg', quality: 80 });
      
      // 🔥 Advanced Behavioral DOM Signals
      // 1. Hidden 1x1 iframes (often used for drive-by malware)
      const tinyIframes = await page.$$eval('iframe', iframes => 
        iframes.filter(i => {
          const style = window.getComputedStyle(i);
          return (parseInt(style.width) <= 1 && parseInt(style.height) <= 1) || style.display === 'none';
        }).length
      );

      // 2. High-volume tracking scripts (indicates laundry/tracking traffic)
      const trackingScripts = await page.$$eval('script[src]', scripts =>
        scripts.filter(s => {
          const src = s.getAttribute('src') || '';
          return /track|analytics|pixel|ads|collector|logger/i.test(src);
        }).length
      );

      // 3. Password field check
      const hasPassword = await page.$('input[type="password"]');
      const forms = await page.$$('form');
      
      await browser.close();
      
      return {
        success: true,
        path: `/api/screenshots/${filename}`,
        visualSignals: {
          hasPasswordField: !!hasPassword,
          formCount: forms.length,
          tinyIframeCount: tinyIframes,
          trackingScriptCount: trackingScripts
        }
      };
    } catch (error: any) {
      console.warn(`[VisualEngine] Capture failed (likely missing browser binaries):`, error.message);
      return { success: false, error: 'Headless browser not available or timeout' };
    }
  }

  /**
   * Generates a signal based on visual behavior (e.g. Credential Harvesters)
   */
  public getVisualHeuristics(captureResult: any): HeuristicResult[] {
    if (!captureResult?.success || !captureResult.visualSignals) return [];

    const signals: HeuristicResult[] = [];
    const { visualSignals } = captureResult;

    if (visualSignals.hasPasswordField) {
      signals.push({
        name: "Credential Harvester Pattern",
        status: "fail",
        description: "Headless inspection detected a password input field on a suspicious/non-reputable domain.",
        scoreImpact: 35
      });
    }

    if (visualSignals.tinyIframeCount > 0) {
      signals.push({
        name: "Zero-Day iframe detected",
        status: "fail",
        description: "Hidden or 1x1 iframes detected on the page. Frequent pattern for drive-by-download attacks.",
        scoreImpact: 25
      });
    }

    if (visualSignals.trackingScriptCount > 10) {
      signals.push({
        name: "Excessive Tracking Traffic",
        status: "warn",
        description: "Unusually high number of tracking/analytics scripts detected. Often used for traffic laundering.",
        scoreImpact: 10
      });
    }

    return signals;
  }
}

export const visualEngine = VisualEngine.getInstance();
