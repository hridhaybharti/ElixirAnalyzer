import crypto from 'crypto';
import { promises as dns } from 'dns';

function parseDKIMSignature(sig: string): Record<string,string> {
  const out: Record<string,string> = {};
  const parts = sig.split(';').map(p=>p.trim()).filter(Boolean);
  for (const p of parts) {
    const m = p.match(/^([a-zA-Z]+)\s*=\s*(.+)$/);
    if (m) out[m[1].toLowerCase()] = m[2];
  }
  return out;
}

function canonicalizeHeaderRelaxed(line: string): string {
  const idx = line.indexOf(':');
  if (idx === -1) return line.trim();
  const name = line.slice(0, idx).toLowerCase();
  let value = line.slice(idx+1);
  // Unfold and compress WSP
  value = value.replace(/\r?\n[\t ]+/g, ' ');
  value = value.replace(/[\t ]+/g, ' ').trim();
  return `${name}:${value}`;
}

function canonicalizeBodyRelaxed(rawBody: string): string {
  const lines = rawBody.replace(/\r?\n/g, '\r\n').split('\r\n');
  // Remove trailing empty lines
  while (lines.length>0 && lines[lines.length-1].trim()==='') lines.pop();
  const canon = lines.map(l => l.replace(/[\t ]+/g, ' ').replace(/[\t ]+$/,'')).join('\r\n') + '\r\n';
  return canon;
}

function selectHeadersForSignedString(rawHeaderLines: string[], signedNames: string[], dkimHeaderLine: string): string {
  // For each name in 'h=', pick the last matching occurrence from rawHeaderLines up to the DKIM-Signature header
  const lowerLines = rawHeaderLines.map(l => l);
  const dkimIndex = lowerLines.findIndex(l => /^dkim-signature\s*:/i.test(l));
  const upto = dkimIndex === -1 ? lowerLines.length : dkimIndex; // do not include DKIM header itself here
  const result: string[] = [];
  let cursor = upto - 1;
  for (const name of signedNames) {
    const nre = new RegExp('^'+name.replace(/[-]/g,'\\-')+'\s*:', 'i');
    for (let i=cursor; i>=0; i--) {
      if (nre.test(lowerLines[i])) {
        result.push(canonicalizeHeaderRelaxed(lowerLines[i]));
        cursor = i - 1; // next search goes above this
        break;
      }
    }
  }
  // Add the DKIM-Signature header up to b=
  const bIndex = dkimHeaderLine.indexOf(' b=');
  const dkimNoB = bIndex !== -1 ? dkimHeaderLine.slice(0, bIndex+3) : dkimHeaderLine;
  result.push(canonicalizeHeaderRelaxed(dkimNoB));
  return result.join('\r\n') + '\r\n';
}

async function fetchPublicKeyPEM(domain: string, selector: string): Promise<string> {
  const recs = await dns.resolveTxt(`${selector}._domainkey.${domain}`);
  const flat = recs.map(r=>r.join(''));
  const rec = flat.find(r => /\bp=/.test(r)) || '';
  const pMatch = rec.match(/\bp=([^;\s]+)/);
  if (!pMatch) throw new Error('No p= key');
  const p = pMatch[1].replace(/\s+/g,'');
  // Wrap to PEM SubjectPublicKeyInfo
  const lines = p.match(/.{1,64}/g) || [p];
  return `-----BEGIN PUBLIC KEY-----\n${lines.join('\n')}\n-----END PUBLIC KEY-----`;
}

export async function verifyDKIM(rawHeaderLines: string[], rawBody: string, dkimHeaderValue: string): Promise<{ verified: boolean; reason?: string; algorithm?: string }>{
  // Basic relaxed/relaxed, rsa-sha256 only
  try {
    const tags = parseDKIMSignature(dkimHeaderValue);
    const a = (tags['a']||'rsa-sha256').toLowerCase();
    if (a !== 'rsa-sha256') return { verified: false, reason: 'unsupported-alg' };
    const domain = tags['d']; const selector = tags['s']; const h = tags['h']; const bh = tags['bh']; const b = tags['b']; const c = (tags['c']||'relaxed/relaxed').toLowerCase();
    if (!domain || !selector || !h || !bh || !b) return { verified: false, reason: 'missing-tags' };
    // Body hash
    const bodyCanon = canonicalizeBodyRelaxed(rawBody);
    const bodyHash = crypto.createHash('sha256').update(bodyCanon, 'utf8').digest('base64');
    if (bodyHash !== bh) return { verified: false, reason: 'body-hash-mismatch' };
    // Signed header string
    const dkimHeaderLine = rawHeaderLines.find(l => /^dkim-signature\s*:/i.test(l)) || `DKIM-Signature: ${dkimHeaderValue}`;
    const signedNames = h.split(':').map(s => s.trim().toLowerCase());
    const signedString = selectHeadersForSignedString(rawHeaderLines, signedNames, dkimHeaderLine);
    // Public key
    const pub = await fetchPublicKeyPEM(domain, selector);
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(signedString, 'utf8');
    const sig = Buffer.from(b.replace(/\s+/g,''), 'base64');
    const ok = verifier.verify(pub, sig);
    return ok ? { verified: true, algorithm: a } : { verified: false, reason: 'signature-mismatch', algorithm: a };
  } catch (e:any) {
    return { verified: false, reason: String(e?.message || e) };
  }
}
