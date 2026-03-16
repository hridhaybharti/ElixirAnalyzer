import fs from 'fs';
import path from 'path';
import type { EmailCase } from './types';

const baseDir = path.resolve(process.cwd(), 'server', 'data', 'email');
const casesFile = path.join(baseDir, 'cases.json');

function ensure() {
  if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir, { recursive: true });
  if (!fs.existsSync(casesFile)) fs.writeFileSync(casesFile, JSON.stringify({ cases: [] }), 'utf-8');
}

function loadAll(): { cases: EmailCase[] } {
  ensure();
  try { return JSON.parse(fs.readFileSync(casesFile, 'utf-8')); } catch { return { cases: [] }; }
}

function saveAll(data: { cases: EmailCase[] }) {
  ensure();
  fs.writeFileSync(casesFile, JSON.stringify(data, null, 2), 'utf-8');
}

export const emailStore = {
  save(ec: EmailCase) {
    const all = loadAll();
    all.cases.unshift(ec);
    saveAll(all);
    return ec;
  },
  update(id: string, patch: Partial<EmailCase>) {
    const all = loadAll();
    const idx = all.cases.findIndex(c => c.id === id);
    if (idx === -1) return undefined;
    const updated = { ...all.cases[idx], ...patch } as EmailCase;
    all.cases[idx] = updated;
    saveAll(all);
    return updated;
  },
  get(id: string): EmailCase | undefined {
    const all = loadAll();
    return all.cases.find(c => c.id === id);
  },
  list(limit = 100) {
    const all = loadAll();
    return all.cases.slice(0, limit);
  }
};
