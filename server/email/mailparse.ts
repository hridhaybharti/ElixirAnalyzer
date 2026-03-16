import { createRequire } from 'module';
import { parseRfc822Minimal, extractAttachmentsMinimal } from './parser';

export interface SmartParsedEmail {
  headers: Record<string,string>;
  text?: string;
  html?: string;
  urls: string[];
  attachments: Array<{ filename?: string; mime?: string; contentBase64: string; size: number }>;
  from?: string; envelopeFrom?: string; returnPath?: string; subject?: string; date?: string; messageId?: string;
  receivedIps: string[];
  rawHeaderLines: string[];
  rawBody: string;
}

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;

function extractUrlsFromHtml(html: string): string[] {
  const urls: string[] = [];
  const attrs = ['href','src','data-href'];
  for (const attr of attrs) {
    const re = new RegExp(`${attr}\\s*=\\s*"([^"]+)"`, 'gi');
    let m: RegExpExecArray | null;
    while ((m = re.exec(html)) !== null) {
      const val = m[1];
      if (/^https?:\/\//i.test(val)) urls.push(val);
    }
  }
  const plain = (html.replace(/<[^>]+>/g,' ') || '').match(URL_RE) || [];
  urls.push(...plain);
  return Array.from(new Set(urls));
}

export async function parseEmailSmart(raw: string): Promise<SmartParsedEmail> {
  try {
    const require = createRequire(import.meta.url);
    const { simpleParser } = require('mailparser');
    const p = await simpleParser(raw);
    const headers: Record<string,string> = {};
    const rawHeaderLines: string[] = [];
    p.headerLines?.forEach((h: any) => { const k = String(h.key||'').toLowerCase(); const v = String(h.line||'').replace(/^([^:]+):\s*/,''); headers[k] = headers[k] ? `${headers[k]} ${v}` : v; rawHeaderLines.push(String(h.line||'')); });
    const from = p.from?.text; const subject = p.subject; const date = p.date?.toISOString?.() || String(p.date||''); const messageId = p.messageId || (p.headers?.get?.('message-id'));
    const text = p.text || ''; const html = p.html || '';
    const urls = Array.from(new Set([...(text.match(URL_RE)||[]), ...extractUrlsFromHtml(html||'')]));
    const attachments = (p.attachments||[]).map((a:any)=>({ filename: a.filename, mime: a.contentType, contentBase64: a.content?.toString?.('base64') || '', size: a.size||0 })).filter((a:any)=>a.contentBase64);
    // Received IPs and raw body via minimal fallback
    const min = parseRfc822Minimal(raw);
    const rawBody = (raw.split(/\r?\n\r?\n/).slice(1).join('\r\n\r\n')) || '';
    return { headers, text, html, urls, attachments, from, envelopeFrom: min.envelopeFrom, returnPath: min.returnPath, subject, date, messageId, receivedIps: min.receivedIps, rawHeaderLines, rawBody };
  } catch {
    // Fallback minimal
    const min = parseRfc822Minimal(raw);
    const atts = extractAttachmentsMinimal(raw);
    const rawHeaderLines = (raw.split(/\r?\n\r?\n/)[0] || '').split(/\r?\n/);
    const rawBody = (raw.split(/\r?\n\r?\n/).slice(1).join('\r\n\r\n')) || '';
    return { headers: min.headers, text: min.bodyText, html: undefined, urls: min.urls, attachments: atts, from: min.from, envelopeFrom: min.envelopeFrom, returnPath: min.returnPath, subject: min.subject, date: min.date, messageId: min.messageId, receivedIps: min.receivedIps, rawHeaderLines, rawBody };
  }
}
