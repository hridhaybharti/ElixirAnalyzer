import fs from "fs";
import { samplePath } from "./samples";
import { spawn } from "child_process";

export interface Detection {
  engine: string;
  signature: string;
  severity: "low" | "medium" | "high";
  description?: string;
}

export interface ScanReport {
  sha256: string;
  size: number;
  startedAt: number;
  finishedAt: number;
  detections: Detection[];
  summary: string;
}

function toUtf8(buffer: Buffer): string {
  // Attempt UTF-8 decode; if fails, return empty for regex scanning
  try { return buffer.toString("utf8"); } catch { return ""; }
}

function entropy(buffer: Buffer): number {
  // Shannon entropy estimate over bytes
  const freq = new Array(256).fill(0);
  for (let i = 0; i < buffer.length; i++) freq[buffer[i]]++;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] === 0) continue;
    const p = freq[i] / buffer.length;
    e -= p * Math.log2(p);
  }
  return e;
}

function regexSignatures(text: string): Detection[] {
  const rules: Array<{ re: RegExp; signature: string; severity: Detection["severity"]; desc?: string }> = [
    { re: /atob\(|btoa\(/i, signature: "ENCODE_DECODE_JS", severity: "low", desc: "Base64 encode/decode usage" },
    { re: /document\.write\(/i, signature: "DOC_WRITE", severity: "low", desc: "document.write potentially injecting HTML" },
    { re: /eval\(/i, signature: "EVAL_CALL", severity: "medium", desc: "Dynamic evaluation detected" },
    { re: /powershell\s+-enc\s+/i, signature: "POWERSHELL_ENC", severity: "high", desc: "Encoded PowerShell invocation" },
    { re: /cmd\.exe|wscript\.shell|mshta/i, signature: "OS_SHELL_INVOKE", severity: "high", desc: "OS shell utilities referenced" },
    { re: /<script[^>]*>[^<]*eval\(/i, signature: "SCRIPT_EVAL_INLINE", severity: "medium", desc: "Inline eval inside script" },
  ];
  const hits: Detection[] = [];
  for (const r of rules) {
    if (r.re.test(text)) hits.push({ engine: "RegexSignatures", signature: r.signature, severity: r.severity, description: r.desc });
  }
  return hits;
}

function magicHeaders(buffer: Buffer): Detection[] {
  const hits: Detection[] = [];
  // PE executable (MZ)
  if (buffer.length >= 2 && buffer[0] === 0x4d && buffer[1] === 0x5a) {
    hits.push({ engine: "Magic", signature: "PE_MZ_HEADER", severity: "medium", description: "Windows Portable Executable" });
  }
  // ZIP
  if (buffer.length >= 4 && buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04) {
    hits.push({ engine: "Magic", signature: "ZIP", severity: "low", description: "ZIP archive" });
  }
  // PDF
  if (buffer.length >= 4 && buffer[0] === 0x25 && buffer[1] === 0x50 && buffer[2] === 0x44 && buffer[3] === 0x46) {
    hits.push({ engine: "Magic", signature: "PDF", severity: "low", description: "PDF document" });
  }
  return hits;
}

export function scanBuffer(sha256: string, buffer: Buffer): ScanReport {
  const startedAt = Date.now();
  const det: Detection[] = [];
  const text = toUtf8(buffer);
  det.push(...magicHeaders(buffer));
  det.push(...regexSignatures(text));
  const e = entropy(buffer);
  if (e > 7.5) det.push({ engine: "Entropy", signature: "HIGH_ENTROPY", severity: "medium", description: `Entropy=${e.toFixed(2)}` });
  // Optional ClamAV integration (CLI)
  if (process.env.CLAMAV_ENABLED === '1') {
    try {
      const tmpPath = samplePath(sha256);
      const clam = runClamScanSync(tmpPath, Number(process.env.CLAMAV_TIMEOUT_MS || 12000));
      for (const sig of clam) {
        det.push({ engine: 'ClamAV', signature: `CLAM:${sig}`, severity: 'high' });
      }
    } catch { /* ignore */ }
  }
  // Optional YARA integration
  // Requires: YARA_ENABLED=1 and YARA_RULES_DIR pointing to a directory of rules.
  // Attempts to execute 'yara' or 'yara64.exe' in PATH. Fails gracefully if not installed.
  if (process.env.YARA_ENABLED === '1') {
    const rulesDir = process.env.YARA_RULES_DIR;
    if (rulesDir && rulesDir.trim()) {
      const tmpPath = samplePath(sha256);
      try {
        const matches = runYaraSync(rulesDir.trim(), tmpPath, Number(process.env.YARA_TIMEOUT_MS || 8000));
        for (const rule of matches) {
          det.push({ engine: 'YARA', signature: `YARA:${rule}`, severity: 'high' });
        }
      } catch (e) {
        // Swallow YARA errors; scanning continues with basic detections
      }
    }
  }
  const finishedAt = Date.now();
  const sevScore = det.reduce((acc, d) => acc + (d.severity === "high" ? 3 : d.severity === "medium" ? 2 : 1), 0);
  const summary = det.length === 0 ? "No detections." : (sevScore >= 6 ? "Potentially malicious patterns detected." : "Suspicious patterns detected.");
  return { sha256, size: buffer.length, startedAt, finishedAt, detections: det, summary };
}

export function scanSampleBySha256(sha256: string): ScanReport | null {
  const p = samplePath(sha256);
  if (!fs.existsSync(p)) return null;
  const buf = fs.readFileSync(p);
  return scanBuffer(sha256, buf);
}

function runYaraSync(rulesDir: string, sampleFile: string, timeoutMs: number): string[] {
  const binCandidates = [process.env.YARA_BIN || 'yara', 'yara64.exe'];
  const results = new Set<string>();
  let lastErr: any = null;
  for (const bin of binCandidates) {
    try {
      const out = spawnSyncWithTimeout(bin, ['-r', rulesDir, sampleFile], timeoutMs);
      if (out && out.code === 0 && out.stdout) {
        const lines = out.stdout.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        for (const line of lines) {
          const rule = line.split(/\s+/)[0];
          if (rule) results.add(rule);
        }
        break;
      }
      lastErr = out?.stderr || out?.error;
    } catch (e) { lastErr = e; }
  }
  if (results.size === 0 && lastErr) {
    // no-op; optionally could log lastErr
  }
  return Array.from(results);
}

function spawnSyncWithTimeout(cmd: string, args: string[], timeoutMs: number): { code: number; stdout: string; stderr: string; error?: any } | null {
  return new Promise((resolve) => {
    try {
      const child = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '';
      let stderr = '';
      let exited = false;
      const timer = setTimeout(() => {
        if (!exited) {
          try { child.kill('SIGKILL'); } catch {}
        }
      }, Math.max(1000, timeoutMs));
      child.stdout?.on('data', d => { stdout += d.toString(); });
      child.stderr?.on('data', d => { stderr += d.toString(); });
      child.on('error', (err) => {
        clearTimeout(timer);
        exited = true;
        resolve({ code: 1, stdout, stderr, error: String(err?.message || err) });
      });
      child.on('exit', (code) => {
        clearTimeout(timer);
        exited = true;
        resolve({ code: code ?? 1, stdout, stderr });
      });
    } catch (e) {
      resolve({ code: 1, stdout: '', stderr: '', error: String((e as any)?.message || e) });
    }
  }) as unknown as { code: number; stdout: string; stderr: string; error?: any };
}

function runClamScanSync(sampleFile: string, timeoutMs: number): string[] {
  const candidates = [process.env.CLAMAV_BIN || 'clamscan', 'clamscan.exe', 'clamdscan', 'clamdscan.exe'];
  for (const bin of candidates) {
    try {
      const out = spawnSyncWithTimeout(bin, ['--no-summary', sampleFile], timeoutMs);
      if (!out) continue;
      // clamscan returns code 1 when a virus is found; 0 when clean.
      if (out.code === 1 && out.stdout) {
        const lines = out.stdout.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
        const sigs: string[] = [];
        for (const line of lines) {
          const m = line.match(/: (.+) FOUND$/);
          if (m && m[1]) sigs.push(m[1]);
        }
        if (sigs.length > 0) return sigs;
      }
      if (out.code === 0) return [];
    } catch { /* try next bin */ }
  }
  return [];
}
