import { safeFetchJson as fetchJson } from "../utils/http";
import { secretsManager } from "../utils/secrets";

export type UrlEngineVerdict = "malicious" | "suspicious" | "clean" | "unknown";

export interface UrlEngineResult {
  engine: string;
  verdict: UrlEngineVerdict;
  confidence?: number;
  link?: string;
  details?: string;
}

function normalizeUrl(input: string): string {
  try {
    const u = new URL(input.includes("://") ? input : `http://${input}`);
    return u.toString();
  } catch {
    return input;
  }
}

function getHost(input: string): string | null {
  try {
    const u = new URL(input.includes("://") ? input : `http://${input}`);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export async function checkGoogleSafeBrowsing(url: string): Promise<UrlEngineResult | null> {
  const key = secretsManager.getSecret("GSB_API_KEY");
  if (!key) return null;
  const normalized = normalizeUrl(url);
  const body = {
    client: { clientId: "elixir-analyzer", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: [
        "MALWARE",
        "SOCIAL_ENGINEERING",
        "UNWANTED_SOFTWARE",
        "POTENTIALLY_HARMFUL_APPLICATION",
      ],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url: normalized }],
    },
  };

  const resp = await fetchJson(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
    { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
    8000
  );

  if (!resp.ok) {
    return { engine: "Google Safe Browsing", verdict: "unknown", details: resp.error };
  }
  const matches = Array.isArray(resp.json?.matches) ? resp.json.matches : [];
  const malicious = matches.length > 0;
  return {
    engine: "Google Safe Browsing",
    verdict: malicious ? "malicious" : "clean",
    confidence: malicious ? 0.95 : 0.9,
    details: malicious ? `Matches: ${matches.map((m: any)=>m.threatType).join(",")}` : undefined,
  };
}

export async function checkUrlscan(url: string): Promise<UrlEngineResult | null> {
  // urlscan.io search endpoint can be used without key but may be rate limited.
  const host = getHost(url);
  if (!host) return null;
  const query = `domain:${host}`;
  const resp = await fetchJson(`https://urlscan.io/api/v1/search/?q=${encodeURIComponent(query)}`, undefined, 8000);
  if (!resp.ok) {
    return { engine: "urlscan.io", verdict: "unknown", details: resp.error };
  }
  const total = Number(resp.json?.total || 0);
  const suspicious = total > 0;
  return { engine: "urlscan.io", verdict: suspicious ? "suspicious" : "clean", confidence: suspicious ? 0.7 : 0.6 };
}

export async function checkPhishTank(url: string): Promise<UrlEngineResult | null> {
  const key = secretsManager.getSecret("PHISHTANK_API_KEY");
  if (!key) return null;
  // PhishTank v2 requires an API key and uses a JSON API; here we assume a checker endpoint
  const resp = await fetchJson(
    `https://checkurl.phishtank.com/checkurl/`,
    {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", key },
      body: new URLSearchParams({ url: normalizeUrl(url), format: "json" }).toString(),
    },
    8000
  );
  if (!resp.ok) {
    return { engine: "PhishTank", verdict: "unknown", details: resp.error };
  }
  const valid = !!resp.json?.results?.valid;
  const inDatabase = !!resp.json?.results?.in_database;
  const verified = !!resp.json?.results?.verified;
  const malicious = inDatabase && verified && valid;
  return { engine: "PhishTank", verdict: malicious ? "malicious" : (inDatabase ? "suspicious" : "clean"), confidence: malicious ? 0.9 : (inDatabase ? 0.75 : 0.6) };
}

export async function runUrlEngines(urlOrDomain: string): Promise<UrlEngineResult[]> {
  const targets = [
    checkGoogleSafeBrowsing(urlOrDomain),
    checkUrlscan(urlOrDomain),
    checkPhishTank(urlOrDomain),
  ];
  const results = await Promise.all(targets);
  return results.filter((r): r is UrlEngineResult => !!r);
}
