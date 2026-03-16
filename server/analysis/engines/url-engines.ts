import { safeFetchJson as fetchJson } from "../../utils/http";
import { secretsManager } from "../../utils/secrets";

export type EngineVerdict = {
  engine: string;
  verdict: "malicious" | "suspicious" | "clean" | "unknown";
  category?: string;
  confidence?: number;
  details?: string;
  link?: string;
  raw?: any;
};

function normalizeUrl(input: string): string {
  try {
    const u = new URL(input.includes("://") ? input : `http://${input}`);
    return u.toString();
  } catch {
    return input.trim();
  }
}

function getHostname(input: string): string | null {
  try {
    const u = new URL(input.includes("://") ? input : `http://${input}`);
    return u.hostname.toLowerCase();
  } catch {
    return null;
  }
}

export async function checkGoogleSafeBrowsing(url: string): Promise<EngineVerdict | null> {
  const key = secretsManager.getSecret("GSB_API_KEY") || secretsManager.getSecret("GOOGLE_SAFE_BROWSING_KEY");
  if (!key) return null;

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
      threatEntries: [{ url }],
    },
  };

  const resp = await fetchJson(
    `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`,
    { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) },
    8000,
  );

  if (!resp.ok) {
    return {
      engine: "Google Safe Browsing",
      verdict: "unknown",
      details: resp.error,
    };
  }

  const matches = resp.json?.matches;
  if (Array.isArray(matches) && matches.length > 0) {
    const types = Array.from(new Set(matches.map((m: any) => String(m.threatType || "").toLowerCase()).filter(Boolean)));
    return {
      engine: "Google Safe Browsing",
      verdict: "malicious",
      category: types[0] || "unspecified",
      confidence: 0.98,
      details: `Matches: ${types.join(", ")}`,
      raw: resp.json,
    };
  }

  return { engine: "Google Safe Browsing", verdict: "clean", confidence: 0.9 };
}

export async function checkUrlscanSearch(input: string): Promise<EngineVerdict> {
  const host = getHostname(input) || input.trim();
  const resp = await fetchJson(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(host)}`, undefined, 8000);
  if (!resp.ok) {
    return { engine: "urlscan.io", verdict: "unknown", details: resp.error };
  }

  const total = Number(resp.json?.total || 0);
  const first = Array.isArray(resp.json?.results) ? resp.json.results[0] : undefined;
  const report = first?.task?.reportURL as string | undefined;
  const overall = first?.verdicts?.overall || {};
  const malicious = !!overall.malicious || (typeof overall.score === "number" && overall.score > 0);
  return {
    engine: "urlscan.io",
    verdict: malicious ? "suspicious" : (total > 0 ? "clean" : "unknown"),
    confidence: total > 0 ? 0.8 : 0.5,
    details: total > 0 ? `Found ${total} prior scans` : "No prior scans found",
    link: report,
    raw: first,
  };
}

export async function checkPhishTank(url: string): Promise<EngineVerdict | null> {
  const key = secretsManager.getSecret("PHISHTANK_APP_KEY");
  if (!key) return null;
  // PhishTank checkurl endpoint (legacy). May respond with JSON when format=json.
  const form = new URLSearchParams({ url, app_key: key, format: "json" }).toString();
  const resp = await fetchJson(
    "https://checkurl.phishtank.com/checkurl/",
    { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: form },
    10000,
  );
  if (!resp.ok) {
    return { engine: "PhishTank", verdict: "unknown", details: resp.error };
  }
  const j = resp.json || {};
  // Shape can vary; try to infer
  const inDb = !!(j?.results?.in_database || j?.in_database);
  const verified = !!(j?.results?.verified || j?.verified);
  const valid = !!(j?.results?.valid || j?.valid);
  if (inDb && verified && valid) {
    const url0 = j?.results?.url || url;
    return {
      engine: "PhishTank",
      verdict: "malicious",
      category: "phishing",
      confidence: 0.95,
      details: "URL present in PhishTank (verified)",
      link: typeof url0 === "string" ? url0 : undefined,
      raw: j,
    };
  }
  return { engine: "PhishTank", verdict: inDb ? "suspicious" : "clean", confidence: inDb ? 0.6 : 0.7, raw: j };
}

export async function getUrlEngineVerdicts(type: "ip" | "domain" | "url", input: string): Promise<EngineVerdict[]> {
  if (type === "ip") return [];
  const url = normalizeUrl(input);
  const tasks: Array<Promise<EngineVerdict | null>> = [];

  if (String(process.env.MULTI_ENGINE_ENABLED || "1").trim() === "1") {
    tasks.push(checkGoogleSafeBrowsing(url));
    tasks.push(checkPhishTank(url));
    tasks.push(checkUrlscanSearch(url));
  }

  const results = await Promise.all(tasks);
  return results.filter(Boolean) as EngineVerdict[];
}
