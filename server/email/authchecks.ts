import { promises as dns } from 'dns';
import net from 'net';

export async function checkSPF(envelopeFrom?: string): Promise<{ domain?: string; result: string; reason?: string }> {
  try {
    const dom = (envelopeFrom || '').split('@')[1] || '';
    if (!dom) return { result: 'none', reason: 'no-envelope-from' };
    const txt = await dns.resolveTxt(dom);
    const records = txt.map(arr => arr.join(''));
    const hasSpf = records.some(r => r.toLowerCase().startsWith('v=spf1'));
    return { domain: dom, result: hasSpf ? 'neutral' : 'none' };
  } catch {
    return { result: 'tempfail', reason: 'dns-error' };
  }
}

function ipInCidr(ip: string, cidr: string): boolean {
  // IPv4 only basic support
  if (net.isIP(ip) !== 4) return false;
  const [netIp, maskStr] = cidr.split('/');
  const mask = Number(maskStr||'32');
  const ipNum = ip.split('.').reduce((a,n)=> (a<<8) + Number(n), 0) >>> 0;
  const netNum = netIp.split('.').reduce((a,n)=> (a<<8) + Number(n), 0) >>> 0;
  const m = mask===0 ? 0 : (~0 << (32 - mask)) >>> 0;
  return (ipNum & m) === (netNum & m);
}

export async function evaluateSPF(ip: string, domain: string): Promise<{ result: string; reason?: string }> {
  try {
    const recs = await dns.resolveTxt(domain);
    const spf = recs.map(r=>r.join('')).find(r=>/^v=spf1\s/i.test(r));
    if (!spf) return { result: 'none', reason: 'no-spf' };
    const parts = spf.replace(/^v=spf1\s*/i,'').trim().split(/\s+/);
    let res: 'pass'|'fail'|'neutral'|'softfail' = 'neutral';
    for (const mech of parts) {
      const m = mech.toLowerCase();
      if (m==='all') { res = 'softfail'; break; }
      if (m.startsWith('ip4:')) {
        const cidr = m.substring(4);
        if (ipInCidr(ip, cidr)) { res = 'pass'; break; }
      }
      if (m.startsWith('include:')) {
        const incDom = m.substring(8);
        const inc = await evaluateSPF(ip, incDom);
        if (inc.result === 'pass') { res = 'pass'; break; }
      }
    }
    return { result: res };
  } catch (e:any) {
    return { result: 'tempfail', reason: 'dns-error' };
  }
}

export async function checkDKIM(_domain?: string, _selector?: string): Promise<{ domain?: string; selector?: string; result: string; reason?: string }> {
  // Placeholder (verification requires canonicalization and crypto signature check)
  return { domain: _domain, selector: _selector, result: 'neutral', reason: 'not-verified' };
}

export async function checkDKIMFromHeaders(headers: Record<string,string>): Promise<{ domain?: string; selector?: string; result: string; reason?: string }> {
  try {
    const raw = headers['dkim-signature'] || headers['dkim'] || '';
    if (!raw) return { result: 'none', reason: 'no-dkim-header' };
    const d = /\bd=([^;\s]+)/i.exec(raw)?.[1];
    const s = /\bs=([^;\s]+)/i.exec(raw)?.[1];
    if (!d || !s) return { result: 'none', reason: 'missing-s-or-d' };
    // Fetch public key
    const recs = await dns.resolveTxt(`${s}._domainkey.${d}`);
    const flat = recs.map(r=>r.join(''));
    const pub = flat.find(r => /\bp=/.test(r));
    if (!pub) return { domain: d, selector: s, result: 'neutral', reason: 'no-public-key' };
    // We found a key but did not verify signature; mark as neutral with reason
    return { domain: d, selector: s, result: 'neutral', reason: 'key-found-not-verified' };
  } catch {
    return { result: 'tempfail', reason: 'dns-error' };
  }
}

export async function checkDMARC(domain?: string): Promise<{ policy?: string; alignment?: string; result: string; reason?: string }> {
  try {
    if (!domain) return { result: 'none', reason: 'no-domain' };
    const recs = await dns.resolveTxt(`_dmarc.${domain}`);
    const flat = recs.map(r => r.join(''));
    const dmarc = flat.find(r => r.toLowerCase().startsWith('v=dmarc1')) || '';
    if (!dmarc) return { result: 'none' };
    const p = /;\s*p=([^;\s]+)/i.exec(dmarc)?.[1] || 'none';
    // Placeholder alignment reported as relaxed; real alignment computed in route using spf/dkim flags
    return { policy: p, alignment: 'relaxed', result: 'neutral' };
  } catch {
    return { result: 'tempfail', reason: 'dns-error' };
  }
}
