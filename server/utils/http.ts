import { URL } from "url";
import { metrics } from "../observability/metrics";

export type SafeJsonResponse =
  | { ok: true; status: number; json: any }
  | { ok: false; status: number; error: string };

function isSandboxEnabled(): boolean {
  return String(process.env.SANDBOX || "").trim() === "1";
}

function getAllowHosts(): Set<string> {
  const raw = String(process.env.SANDBOX_ALLOW_HOSTS || "").trim();
  const parts = raw ? raw.split(",") : [];
  return new Set(parts.map((h) => h.trim().toLowerCase()).filter(Boolean));
}

function hostFromUrl(url: string): string | null {
  try {
    const u = new URL(url.includes("://") ? url : `http://${url}`);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Sandboxed fetch with optional host allowlist and timeout.
 * When SANDBOX=1 and the target host is not in SANDBOX_ALLOW_HOSTS, the call is blocked.
 * Example allowlist: SANDBOX_ALLOW_HOSTS=www.virustotal.com,api.abuseipdb.com,ipapi.co,ipwho.is,ip-api.com
 */
export async function safeFetchJson(
  url: string,
  init?: RequestInit,
  timeoutMs = Number(process.env.SANDBOX_REQUEST_TIMEOUT_MS || 8000),
): Promise<SafeJsonResponse> {
  // Enforce sandbox policy if enabled
  if (isSandboxEnabled()) {
    const host = hostFromUrl(url);
    const allowlist = getAllowHosts();
    if (!host || (allowlist.size > 0 && !allowlist.has(host))) {
      return { ok: false, status: 0, error: `Blocked by sandbox: ${host ?? "invalid-url"}` };
    }
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const t0 = Date.now();
    const res = await fetch(url, { ...init, signal: controller.signal });
    const status = res.status;
    const text = await res.text();
    try { const host = hostFromUrl(url) || ''; metrics.recordEgress(host, status, Date.now() - t0); } catch {}
    if (!res.ok) {
      return { ok: false, status, error: text || `HTTP ${status}` };
    }
    try {
      return { ok: true, status, json: text ? JSON.parse(text) : null };
    } catch (e: any) {
      return { ok: false, status, error: `Invalid JSON: ${String(e?.message || e)}` };
    }
  } catch (e: any) {
    return { ok: false, status: 0, error: String(e?.message || e) };
  } finally {
    clearTimeout(timer);
  }
}
