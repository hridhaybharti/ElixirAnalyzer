import fs from "fs";
import path from "path";
import crypto from "crypto";

export interface SampleMeta {
  sha256: string;
  size: number;
  filename?: string;
  createdAt: number;
  analysis?: any;
}

const baseDir = path.resolve(process.cwd(), "server", "data", "samples");
const metaDir = path.join(baseDir, "meta");

function ensureDirs() {
  if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir, { recursive: true });
  if (!fs.existsSync(metaDir)) fs.mkdirSync(metaDir, { recursive: true });
}

export function sha256Of(buffer: Buffer): string {
  const h = crypto.createHash("sha256");
  h.update(buffer);
  return h.digest("hex");
}

export function samplePath(sha256: string): string {
  return path.join(baseDir, `${sha256}.bin`);
}

export function metaPath(sha256: string): string {
  return path.join(metaDir, `${sha256}.json`);
}

export function saveSample(buffer: Buffer, filename?: string): { meta: SampleMeta; existed: boolean } {
  ensureDirs();
  const sha256 = sha256Of(buffer);
  const filePath = samplePath(sha256);
  const existed = fs.existsSync(filePath);
  if (!existed) {
    fs.writeFileSync(filePath, buffer);
    const m: SampleMeta = { sha256, size: buffer.length, filename, createdAt: Date.now() };
    fs.writeFileSync(metaPath(sha256), JSON.stringify(m, null, 2), "utf-8");
    return { meta: m, existed: false };
  }
  // if metadata missing, reconstruct
  const mp = metaPath(sha256);
  let meta: SampleMeta | null = null;
  if (fs.existsSync(mp)) {
    try { meta = JSON.parse(fs.readFileSync(mp, "utf-8")); } catch { /* ignore */ }
  }
  if (!meta) {
    meta = { sha256, size: fs.statSync(filePath).size, filename, createdAt: Date.now() };
    try { fs.writeFileSync(mp, JSON.stringify(meta, null, 2), "utf-8"); } catch { /* ignore */ }
  }
  return { meta, existed: true };
}

export function getSampleMeta(sha256: string): SampleMeta | null {
  ensureDirs();
  const mp = metaPath(sha256);
  if (!fs.existsSync(mp)) return null;
  try {
    return JSON.parse(fs.readFileSync(mp, "utf-8"));
  } catch {
    return null;
  }
}

export function getSampleStream(sha256: string): fs.ReadStream | null {
  ensureDirs();
  const fp = samplePath(sha256);
  if (!fs.existsSync(fp)) return null;
  return fs.createReadStream(fp);
}

export function setSampleAnalysis(sha256: string, analysis: any): boolean {
  ensureDirs();
  const mp = metaPath(sha256);
  if (!fs.existsSync(mp)) return false;
  try {
    const meta = JSON.parse(fs.readFileSync(mp, 'utf-8')) as SampleMeta;
    (meta as any).analysis = analysis;
    fs.writeFileSync(mp, JSON.stringify(meta, null, 2), 'utf-8');
    return true;
  } catch {
    return false;
  }
}

export function getSampleAnalysis(sha256: string): any | null {
  const meta = getSampleMeta(sha256);
  return meta?.analysis ?? null;
}
