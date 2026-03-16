import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

(async () => {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const base = process.env.BASE || 'http://127.0.0.1:5000';
  async function analyze(emlPath) {
    const raw = fs.readFileSync(emlPath, 'utf8');
    const b64 = Buffer.from(raw, 'utf8').toString('base64');
    const res = await fetch(`${base}/api/email/analyze`, { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ source:'upload', contentBase64: b64 }) });
    if (!res.ok) throw new Error(`Analyze failed ${res.status}`);
    return res.json();
  }
  function assert(cond, msg) { if (!cond) { console.error('ASSERT:', msg); process.exit(1); } }
  try {
    const benign = await analyze(path.join(__dirname,'..','tests','eml','benign.eml'));
    const sus = await analyze(path.join(__dirname,'..','tests','eml','suspicious.eml'));
    console.log('Benign:', benign.id, benign.riskScore, benign.riskLevel);
    console.log('Suspicious:', sus.id, sus.riskScore, sus.riskLevel);
    assert(sus.riskScore >= benign.riskScore, 'suspicious should be >= benign');
    assert(sus.riskScore >= 30, 'suspicious should be at least Suspicious');
    console.log('E2E OK');
  } catch (e) {
    console.error('E2E failed:', e);
    process.exit(1);
  }
})();
