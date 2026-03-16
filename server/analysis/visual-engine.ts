import path from "path";
import fs from "fs";
import { createRequire } from "module";
import { promises as dns } from "dns";
import net from "net";
import { SandboxGeoService } from "./hybrid/sandbox-geo";
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
  private harDir = path.join(process.cwd(), "server", "data", "har");

  private constructor() {
    if (!fs.existsSync(this.screenshotDir)) {
      fs.mkdirSync(this.screenshotDir, { recursive: true });
    }
    if (!fs.existsSync(this.harDir)) {
      fs.mkdirSync(this.harDir, { recursive: true });
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
      const harEnabled = process.env.DYN_CAPTURE_HAR === "1";
      const harFile = path.join(this.harDir, `${id}.har`);
      const context = await browser.newContext({
        viewport: { width: 1280, height: 720 },
        userAgent:
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        ...(harEnabled ? { recordHar: { path: harFile, content: 'embed' } } : {}),
      });
      
      const page = await context.newPage();

      // Optional dynamic JS instrumentation
      const dynEnabled = process.env.DYN_JS_INSTRUMENT === "1";
      if (dynEnabled) {
        await page.addInitScript(() => {
          try {
            (window as any).__ea_events = [] as any[];
            const push = (e: any) => {
              try {
                const arr = (window as any).__ea_events as any[];
                if (Array.isArray(arr) && arr.length < 200) arr.push(e);
              } catch {}
            };

            // fetch
            const _fetch = window.fetch;
            window.fetch = async function(input: any, init?: any) {
              const url = (typeof input === 'string') ? input : (input?.url || '');
              const method = (init?.method || 'GET').toUpperCase();
              const bodyLen = (init?.body && typeof init.body === 'string') ? (init.body as string).length : undefined;
              push({ t: 'fetch', url, method, bl: bodyLen });
              // @ts-ignore
              return (_fetch as any).apply(null, arguments as any);
            } as any;

            // XHR
            const _open = XMLHttpRequest.prototype.open;
            const _send = XMLHttpRequest.prototype.send;
            (XMLHttpRequest.prototype as any).open = function(method: string, url: string) {
              (this as any).__ea_url = url;
              (this as any).__ea_method = String(method || 'GET').toUpperCase();
              return _open.apply(this, arguments as any);
            };
            (XMLHttpRequest.prototype as any).send = function(body?: any) {
              try {
                const url = (this as any).__ea_url || '';
                const method = (this as any).__ea_method || 'GET';
                const bl = typeof body === 'string' ? body.length : undefined;
                push({ t: 'xhr', url, method, bl });
              } catch {}
              return _send.apply(this, arguments as any);
            };

            // Beacon
            const _beacon = navigator.sendBeacon?.bind(navigator);
            if (_beacon) {
              (navigator as any).sendBeacon = function(url: string, data?: any) {
                try { push({ t: 'beacon', url, method: 'BEACON', bl: (typeof data === 'string' ? data.length : undefined) }); } catch {}
                return _beacon(url, data);
              };
            }

            // WebSocket
            const _WS = window.WebSocket;
            (window as any).WebSocket = function(url: string, protocols?: string | string[]) {
              try { push({ t: 'ws', url }); } catch {}
              // @ts-ignore
              return new _WS(url, protocols as any);
            } as any;

            // Obfuscation indicators
            const _eval = window.eval;
            window.eval = function(code: string) {
              try { push({ t: 'eval' }); } catch {}
              // @ts-ignore
              return (_eval as any).call(null, code);
            } as any;

            const _Function = (window as any).Function;
            (window as any).Function = function(...args: any[]) {
              try { push({ t: 'fn' }); } catch {}
              // @ts-ignore
              return new _Function(...args);
            } as any;

            const _atob = window.atob;
            window.atob = function(data: string) {
              try { push({ t: 'atob' }); } catch {}
              return _atob.call(this, data);
            };

            // Minimal DOM locks detection
            try {
              const origAdd = EventTarget.prototype.addEventListener;
              (EventTarget.prototype as any).addEventListener = function(type: string, listener: any, options?: any) {
                if (type === 'contextmenu' || type === 'keydown') {
                  push({ t: 'domlock', evt: type });
                }
                return origAdd.call(this, type, listener, options);
              };
            } catch {}
          } catch {}
        });
      }
      
      // Strict 15s timeout for safety
      const navTimeout = Math.max(1000, Math.min(60000, Number(process.env.DYN_TIMEOUT_MS || 15000)));
      await page.goto(validated.url.toString(), {
        waitUntil: "networkidle",
        timeout: navTimeout,
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

      // Pull dynamic instrumentation data
      let dynamicSignals: any = null;
      if (dynEnabled) {
        try {
          dynamicSignals = await page.evaluate(() => {
            const events = Array.isArray((window as any).__ea_events) ? (window as any).__ea_events.slice(0, 200) : [];
            const pageUrl = location.href;
            const pageHost = location.host;
            const forms = Array.from(document.forms || []).map(f => {
              const hasPw = !!f.querySelector('input[type="password"]');
              const act = (f.getAttribute('action') || '').trim();
              return { action: act, hasPassword: hasPw };
            });
            const cmBlocked = !!(document as any).oncontextmenu;
            return { events, forms, pageUrl, pageHost, cmBlocked };
          });
        } catch {}
      }
      
      await browser.close();

      // 🚀 Betterify: Map connection geo-locations
      const mappedNetworkLog = await SandboxGeoService.mapConnections(networkLog.slice(0, 50));
      
      return {
        success: true,
        path: `/api/screenshots/${filename}`,
        visualSignals: {
          hasPasswordField: !!hasPassword,
          formCount: forms.length,
          tinyIframeCount: tinyIframes,
          trackingScriptCount: trackingScripts,
          networkLog: mappedNetworkLog,
          wasRecursive: wasRedirectedByAI
        },
        dynamicSignals
        , har: (process.env.DYN_CAPTURE_HAR === "1") ? { path: `/api/har/${id}.har` } : undefined
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
    const dyn = captureResult.dynamicSignals || null;

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

    // Dynamic JS signals (if available)
    if (dyn) {
      const pageHost = String(dyn.pageHost || '').toLowerCase();
      const urlHost = (u: string) => {
        try { return new URL(u).host.toLowerCase(); } catch { return ''; }
      };

      // Off-origin exfil events
      const exfil = (Array.isArray(dyn.events) ? dyn.events : []).filter((e: any) => {
        if (!e || !e.url) return false;
        const h = urlHost(e.url);
        return h && pageHost && h !== pageHost && (e.t === 'fetch' || e.t === 'xhr' || e.t === 'beacon');
      });

      if (exfil.length >= 3) {
        signals.push({
          name: "High-volume Off-Origin Exfiltration",
          status: "warn",
          description: `Detected ${exfil.length} network exfiltration events to off-origin hosts during detonation.`,
          scoreImpact: 25
        });
      } else if (exfil.length > 0) {
        signals.push({
          name: "Off-Origin Exfiltration",
          status: "warn",
          description: `Detected ${exfil.length} network exfiltration event(s) to off-origin hosts during detonation.`,
          scoreImpact: 12
        });
      }

      // Credential POSTs to off-origin
      const credsOffOrigin = (Array.isArray(dyn.forms) ? dyn.forms : []).some((f: any) => {
        if (!f?.hasPassword) return false;
        const act = String(f.action || '');
        if (!act) return false; // empty action defaults to same-origin
        const ah = urlHost(act);
        return ah && pageHost && ah !== pageHost;
      });
      if (credsOffOrigin) {
        signals.push({
          name: "Off-Origin Credential Post",
          status: "fail",
          description: "Password form action points to a different host than the page origin (common phishing pattern).",
          scoreImpact: 35
        });
      }

      // Obfuscation bursts
      const evalCount = (dyn.events || []).filter((e: any) => e?.t === 'eval').length;
      const fnCount = (dyn.events || []).filter((e: any) => e?.t === 'fn').length;
      const atobCount = (dyn.events || []).filter((e: any) => e?.t === 'atob').length;
      const obCount = evalCount + fnCount + atobCount;
      if (obCount >= 10) {
        signals.push({
          name: "Aggressive Script Obfuscation",
          status: "warn",
          description: `High frequency of dynamic code execution indicators (eval/Function/atob: ${obCount}).`,
          scoreImpact: 15
        });
      }

      // WebSocket beacon to off-origin
      const wsOff = (dyn.events || []).some((e: any) => e?.t === 'ws' && urlHost(e.url) && urlHost(e.url) !== pageHost);
      if (wsOff) {
        signals.push({
          name: "WebSocket Beacon",
          status: "warn",
          description: "Detected WebSocket connection to off-origin during detonation.",
          scoreImpact: 10
        });
      }

      // DOM locks
      if (dyn.cmBlocked || (dyn.events || []).some((e: any) => e?.t === 'domlock')) {
        signals.push({
          name: "UI Interaction Restrictions",
          status: "warn",
          description: "Detected right-click or keydown event interception (user interaction restrictions).",
          scoreImpact: 8
        });
      }
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
