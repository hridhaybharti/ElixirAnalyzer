import fs from 'fs';
import path from 'path';

export interface EmailRiskWeights {
  spfNone: number;
  spfFail: number;
  dmarcNone: number;
  dmarcFail: number;
  headerSignal: number;
  linkHigh: number;
  linkMedium: number;
  bodySignal: number;
  attachmentHit: number;
  brandImpersonation: number;
  becIndicator: number;
}

export interface EmailRiskFeedback {
  id: string;
  caseId: string;
  label: 'false_positive' | 'false_negative' | 'confirm';
  notes?: string;
  createdAt: number;
}

const baseDir = path.resolve(process.cwd(), 'server', 'data', 'email');
const weightsFile = path.join(baseDir, 'weights.json');
const feedbackFile = path.join(baseDir, 'feedback.json');

const defaultWeights: EmailRiskWeights = {
  spfNone: 15,
  spfFail: 20,
  dmarcNone: 15,
  dmarcFail: 20,
  headerSignal: 5,
  linkHigh: 20,
  linkMedium: 10,
  bodySignal: 5,
  attachmentHit: 15,
  brandImpersonation: 15,
  becIndicator: 10,
};

function ensure() {
  if (!fs.existsSync(baseDir)) fs.mkdirSync(baseDir, { recursive: true });
  if (!fs.existsSync(weightsFile)) fs.writeFileSync(weightsFile, JSON.stringify(defaultWeights, null, 2), 'utf-8');
  if (!fs.existsSync(feedbackFile)) fs.writeFileSync(feedbackFile, JSON.stringify({ feedback: [] }, null, 2), 'utf-8');
}

export function getEmailRiskWeights(): EmailRiskWeights {
  ensure();
  try {
    const raw = fs.readFileSync(weightsFile, 'utf-8');
    return { ...defaultWeights, ...(JSON.parse(raw) || {}) };
  } catch {
    return { ...defaultWeights };
  }
}

export function setEmailRiskWeights(next: Partial<EmailRiskWeights>): EmailRiskWeights {
  ensure();
  const updated = { ...getEmailRiskWeights(), ...next };
  fs.writeFileSync(weightsFile, JSON.stringify(updated, null, 2), 'utf-8');
  return updated;
}

export function recordEmailFeedback(caseId: string, label: EmailRiskFeedback['label'], notes?: string) {
  ensure();
  const entry: EmailRiskFeedback = {
    id: Date.now().toString(36),
    caseId,
    label,
    notes,
    createdAt: Date.now(),
  };
  try {
    const raw = JSON.parse(fs.readFileSync(feedbackFile, 'utf-8')) || { feedback: [] };
    raw.feedback = Array.isArray(raw.feedback) ? raw.feedback : [];
    raw.feedback.unshift(entry);
    fs.writeFileSync(feedbackFile, JSON.stringify(raw, null, 2), 'utf-8');
  } catch {
    fs.writeFileSync(feedbackFile, JSON.stringify({ feedback: [entry] }, null, 2), 'utf-8');
  }
  return entry;
}

