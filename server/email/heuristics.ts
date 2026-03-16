const BRAND_PROFILES: Array<{ name: string; domains: string[] }> = [
  { name: 'microsoft', domains: ['microsoft.com', 'office.com', 'outlook.com', 'live.com'] },
  { name: 'google', domains: ['google.com', 'gmail.com', 'googlemail.com'] },
  { name: 'apple', domains: ['apple.com', 'icloud.com'] },
  { name: 'amazon', domains: ['amazon.com', 'amazonaws.com'] },
  { name: 'paypal', domains: ['paypal.com'] },
  { name: 'bank', domains: [] },
  { name: 'wells fargo', domains: ['wellsfargo.com'] },
  { name: 'chase', domains: ['chase.com'] },
  { name: 'citibank', domains: ['citi.com', 'citibank.com'] },
  { name: 'adobe', domains: ['adobe.com'] },
  { name: 'dropbox', domains: ['dropbox.com'] },
  { name: 'dhl', domains: ['dhl.com'] },
  { name: 'fedex', domains: ['fedex.com'] },
  { name: 'ups', domains: ['ups.com'] },
];

const BEC_PATTERNS: RegExp[] = [
  /wire\s+transfer/i,
  /bank\s+details/i,
  /change\s+bank/i,
  /payment\s+update/i,
  /urgent\s+payment/i,
  /invoice\s+attached/i,
  /purchase\s+order/i,
  /\bpo\b/i,
  /gift\s*card/i,
  /\bach\b/i,
  /direct\s+deposit/i,
  /payroll/i,
  /confidential/i,
  /please\s+review/i,
  /vendor\s+setup/i,
];

function normalizeDomain(domain: string) {
  return String(domain || '').trim().toLowerCase();
}

function isSubdomainOf(domain: string, base: string) {
  return domain === base || domain.endsWith(`.${base}`);
}

export function detectBrandImpersonation(fromDisplay: string, fromDomain: string, subject: string) {
  const signals: string[] = [];
  const text = `${fromDisplay} ${subject}`.toLowerCase();
  const dom = normalizeDomain(fromDomain);
  for (const brand of BRAND_PROFILES) {
    if (!text.includes(brand.name)) continue;
    if (brand.domains.length === 0) {
      signals.push(`Brand mention: ${brand.name}`);
      continue;
    }
    const ok = brand.domains.some(d => isSubdomainOf(dom, d));
    if (!ok) signals.push(`Brand impersonation: ${brand.name}`);
  }
  return signals;
}

export function detectBECIndicators(text: string) {
  const signals: string[] = [];
  for (const rx of BEC_PATTERNS) {
    if (rx.test(text)) {
      signals.push(`BEC: ${rx.source}`);
    }
  }
  return signals;
}

