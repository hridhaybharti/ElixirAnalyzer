export interface ParsedEmailMinimal {
  headers: Record<string, string>;
  bodyText?: string;
  urls: string[];
  from?: string;
  envelopeFrom?: string;
  returnPath?: string;
  subject?: string;
  date?: string;
  messageId?: string;
  receivedIps: string[];
}

const URL_RE = /https?:\/\/[^\s"'<>]+/gi;
const IP_RE = /\b(?:(?:2(?:5[0-5]|[0-4]\d))|(?:1?\d?\d))(?:\.(?:(?:2(?:5[0-5]|[0-4]\d))|(?:1?\d?\d))){3}\b/g;

export function parseRfc822Minimal(raw: string): ParsedEmailMinimal {
  const [rawHeaders, ...rest] = raw.split(/\r?\n\r?\n/);
  const headers: Record<string, string> = {};
  const receivedLines: string[] = [];
  (rawHeaders || '').split(/\r?\n/).forEach(line => {
    const m = line.match(/^([^:]+):\s*(.*)$/);
    if (m) {
      const key = m[1].trim().toLowerCase();
      const val = m[2].trim();
      if (key === 'received') {
        receivedLines.push(val);
      } else {
        headers[key] = headers[key] ? `${headers[key]} ${val}` : val;
      }
    }
  });
  const body = rest.join('\n\n') || '';
  const urls = Array.from(new Set((body.match(URL_RE) || []).map(u => u.trim())));

  const from = headers['from'];
  const envelopeFrom = headers['sender'] || headers['x-envelope-from'] || headers['return-path'];
  const returnPath = headers['return-path'];
  const subject = headers['subject'];
  const date = headers['date'];
  const messageId = headers['message-id'];

  const receivedIps: string[] = [];
  for (const line of receivedLines) {
    const ips = line.match(IP_RE) || [];
    for (const ip of ips) { if (!receivedIps.includes(ip)) receivedIps.push(ip); }
  }

  return { headers, bodyText: body, urls, from, envelopeFrom, returnPath, subject, date, messageId, receivedIps };
}

export interface MinimalAttachment {
  filename?: string;
  mime?: string;
  contentBase64: string;
  size: number;
}

export function extractAttachmentsMinimal(raw: string): MinimalAttachment[] {
  // Very basic multipart/mixed boundary parser for base64 attachments
  const ctMatch = raw.match(/Content-Type:\s*multipart\/(?:mixed|alternative);[^\n]*boundary="?([^"\r\n;]+)"?/i);
  const boundary = ctMatch?.[1];
  if (!boundary) return [];
  const splitter = new RegExp(`--${boundary}(?:--)?\r?\n`, 'g');
  const parts = raw.split(new RegExp(`--${boundary}`)).slice(1);
  const atts: MinimalAttachment[] = [];
  for (let p of parts) {
    // stop at end boundary
    p = p.replace(/^\r?\n/, '');
    const headerBodySplit = p.split(/\r?\n\r?\n/);
    if (headerBodySplit.length < 2) continue;
    const headerBlock = headerBodySplit[0];
    const bodyBlock = headerBodySplit.slice(1).join('\n\n');
    const disp = /Content-Disposition:\s*attachment;[^\n]*filename="?([^"\r\n;]+)"?/i.exec(headerBlock)?.[1];
    const enc = /Content-Transfer-Encoding:\s*base64/i.test(headerBlock);
    const mime = /Content-Type:\s*([^;\r\n]+)/i.exec(headerBlock)?.[1];
    if (!disp && !mime) continue;
    if (!enc) continue;
    // collect base64 lines until boundary marker appears
    const base64Text = bodyBlock.split(new RegExp(`\r?\n--${boundary}`))[0]
      .replace(/\r?\n/g, '')
      .trim();
    if (!base64Text) continue;
    try {
      const size = Buffer.from(base64Text, 'base64').length;
      atts.push({ filename: disp, mime, contentBase64: base64Text, size });
    } catch {}
  }
  return atts;
}
