export type EmailSource = 'upload' | 'gmail';

export interface EmailCase {
  id: string;
  createdAt: number;
  source: EmailSource;
  subject?: string;
  from?: string;
  envelopeFrom?: string;
  returnPath?: string;
  messageId?: string;
  date?: string;

  spf?: { domain?: string; result: string; reason?: string };
  dkim?: { domain?: string; selector?: string; result: string; reason?: string };
  dmarc?: { policy?: string; alignment?: string; result: string; reason?: string };
  alignmentMode?: 'relaxed' | 'strict';

  senderIp?: string;
  geo?: { city?: string; country?: string; countryCode?: string; lat?: number; lon?: number };
  receivedPath?: Array<{ ip: string; countryCode?: string; country?: string }>;

  indicators: {
    domains: string[];
    urls: string[];
    ips: string[];
    hashes: string[];
    attachments: Array<{ filename?: string; sha256?: string; mime?: string; size?: number; verdict?: string }>;
  };

  linkResults: Array<{ url: string; riskScore: number; riskLevel: string; summary?: string; id?: number }>; // tie-in to URL analyzer
  attachmentReports: Array<{ filename?: string; sha256?: string; summary?: string; detections?: string[] }>;
  bodySignals: string[];
  headerSignals?: string[];
  bodyHtml?: string;
  riskBreakdown?: {
    auth: number;
    headers: number;
    links: number;
    body: number;
    attachments: number;
    brand: number;
    bec: number;
  };
  feedback?: Array<{ label: 'false_positive' | 'false_negative' | 'confirm'; notes?: string; createdAt: number }>;

  riskScore: number;
  riskLevel: string;
  topSignals: string[];
  summary: string;

  artifacts?: { rawRef?: string; parsedRef?: string };
}
