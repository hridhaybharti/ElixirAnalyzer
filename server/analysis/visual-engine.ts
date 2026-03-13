import path from "path";
import fs from "fs";
import { createRequire } from "module";
import { promises as dns } from "dns";
import net from "net";
import type { HeuristicResult } from "@shared/schema";

/**
 * Visual Intelligence Service (The 'Hazmat Suit')
 * Uses a headless browser to safely capture screenshots and 
 * extract visual heuristics from malicious sites.
 */
class VisualEngine {
  private static instance: VisualEngine;
  private screenshotDir = path.join(
    process.cwd(),
    "server",
    "data",
    "screenshots",
  );

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

    if (process.env.VISUAL_CAPTURE_ENABLED !== "1") {
      return { success: false, error: "Visual capture disabled" };
    }

    const validated = await this.validatePublicHttpUrl(url);
    if (!validated.ok) {
      return { success: false, error: validated.error };
    }
	    
    // Check if browsers are available (graceful failure)
    try {
      const require = createRequire(import.meta.url);
      const { chromium } = require("playwright") as any;
      const browser = await chromium.launch({ headless: true });
      const context = await browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
      });
      
      const page = await context.newPage();
      
      // Strict 15s timeout for safety
      await page.goto(validated.url.toString(), {
        waitUntil: "networkidle",
        timeout: 15000,
      });
      
      const filename = `${id}.jpg`;
      const fullPath = path.join(this.screenshotDir, filename);
      
      await page.screenshot({ path: fullPath, type: "jpeg", quality: 80 });
      
      // 🔥 Advanced Behavioral DOM Signals
      // 1. Hidden 1x1 iframes (often used for drive-by malware)
      const tinyIframes = await page.$$eval(
        "iframe",
        (iframes: HTMLIFrameElement[]) =>
          iframes.filter((i) => {
            const style = window.getComputedStyle(i);
            return (
              (parseInt(style.width) <= 1 && parseInt(style.height) <= 1) ||
              style.display === "none"
            );
          }).length,
      );

      // 2. High-volume tracking scripts (indicates laundry/tracking traffic)
      const trackingScripts = await page.$$eval(
        "script[src]",
        (scripts: HTMLScriptElement[]) =>
          scripts.filter((s) => {
            const src = s.getAttribute("src") || "";
            return /track|analytics|pixel|ads|collector|logger/i.test(src);
          }).length,
      );

      // 3. Password field check
      let hasPassword = await page.$('input[type="password"]');
      const forms = await page.$$('form');
      
      // 🚀 Strike 2: Recursive Detonation - Look for "Click to Login" traps
      let wasRedirectedByAI = false;
      if (!hasPassword) {
        console.log(`[VisualEngine] No password field found. Initiating AI-driven interaction scan...`);
        // Find buttons that look like "Login", "Sign In", "Access", "Verify"
        const loginButtons = await page.$$('button, a, input[type="button"], input[type="submit"]');
        for (const btn of loginButtons) {
          const text = await page.evaluate((el: any) => el.innerText || el.value, btn);
          if (/login|sign in|access|verify|proceed|account|secure/i.test(text)) {
            console.log(`[VisualEngine] Potential landing page trap detected. Clicking: ${text}`);
            await Promise.all([
              page.waitForNavigation({ waitUntil: 'networkidle', timeout: 5000 }).catch(() => {}),
              btn.click()
            ]);
            wasRedirectedByAI = true;
            // Check for password fields again after interaction
            hasPassword = await page.$('input[type="password"]');
            break;
          }
        }
      }
      
      // 🚀 Strike 2: Capture the Network Log during detonation
      const networkLog: any[] = [];
      page.on('request', (request: any) => {
        const url = request.url();
        if (url.startsWith('http')) {
          networkLog.push({
            url: url,
            method: request.method(),
            type: request.resourceType()
          });
        }
      });

      // Stay alive for a few more seconds to catch late-loading threats
      await page.waitForTimeout(3000);
      
      await browser.close();
      
      return {
        success: true,
        path: `/api/screenshots/${filename}`,
        visualSignals: {
          hasPasswordField: !!hasPassword,
          formCount: forms.length,
          tinyIframeCount: tinyIframes,
          trackingScriptCount: trackingScripts,
          networkLog: networkLog.slice(0, 50), // Capture first 50 requests
          wasRecursive: wasRedirectedByAI
        }
      };
    } catch (error: any) {
      console.warn(
        `[VisualEngine] Capture failed (likely missing browser binaries):`,
        error.message,
      );
      return { success: false, error: "Headless browser not available or timeout" };
    }
  }

  private async validatePublicHttpUrl(
    rawUrl: string,
  ): Promise<{ ok: true; url: URL } | { ok: false; error: string }> {
    let parsed: URL;
    try {
      parsed = new URL(rawUrl);
    } catch {
      return { ok: false, error: "Invalid URL" };
    }

    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return { ok: false, error: "Unsupported URL protocol" };
    }

    const host = parsed.hostname;

    const ipVersion = net.isIP(host);
    if (ipVersion) {
      if (!isPublicIp(host)) return { ok: false, error: "Blocked IP address" };
      return { ok: true, url: parsed };
    }

    try {
      const addrs = await dns.lookup(host, { all: true, verbatim: true });
      if (!addrs.length) return { ok: false, error: "DNS lookup failed" };

      for (const a of addrs) {
        if (!isPublicIp(a.address)) {
          return { ok: false, error: "Blocked hostname (non-public DNS)" };
        }
      }
    } catch {
      return { ok: false, error: "DNS lookup failed" };
    }

    return { ok: true, url: parsed };
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
        description: visualSignals.wasRecursive 
          ? "AI Recursive Detonation discovered a hidden login form behind a landing page trap." 
          : "Headless inspection detected a password input field on a suspicious/non-reputable domain.",
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

function isPublicIp(ip: string): boolean {
  const v = net.isIP(ip);
  if (!v) return false;

  if (v === 4) {
    const parts = ip.split(".").map((x) => Number(x));
    if (parts.length !== 4 || parts.some((n) => Number.isNaN(n))) return false;

    const [a, b] = parts;

    if (a === 0) return false;
    if (a === 10) return false;
    if (a === 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a >= 224) return false;
    if (ip === "255.255.255.255") return false;

    return true;
  }

  const lowered = ip.toLowerCase();
  if (lowered === "::1") return false;
  if (lowered.startsWith("fc") || lowered.startsWith("fd")) return false;
  if (
    lowered.startsWith("fe8") ||
    lowered.startsWith("fe9") ||
    lowered.startsWith("fea") ||
    lowered.startsWith("feb")
  ) {
    return false;
  }

  return true;
}
