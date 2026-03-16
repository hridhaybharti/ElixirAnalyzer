import type { Express } from "express";
import type { Server } from "http";
import { z } from "zod";

import { storage } from "./storage";
import { api } from "@shared/routes";

// 🔥 Evidence-based risk engine
import { metrics } from './observability/metrics';
import { reputationService } from "./analysis/reputation";
import { secretsManager } from "./utils/secrets";
import { ThreatReportExporter } from "./utils/exporter";
import path from "path";
import fs from "fs";
import { analysisQueue } from "./jobs/index";
import { emailStore } from "./email/storage";
import { parseEmailSmart } from "./email/mailparse";
import { checkSPF, checkDKIMFromHeaders, checkDMARC, evaluateSPF } from "./email/authchecks";
import { verifyDKIM } from "./email/dkim";
import { lookupWhoisData } from './analysis/threat-intelligence';
import { lookupIPLocation } from "./analysis/threat-intelligence";
import { detectBECIndicators, detectBrandImpersonation } from "./email/heuristics";
import { getEmailRiskWeights, recordEmailFeedback, setEmailRiskWeights } from "./email/risk-tuning";
import { sha256Of } from "./files/samples";
import { scanBuffer } from "./files/scan";
import { analyzeInput } from "./analysis/analyzeInput";
import { getSampleMeta, getSampleStream, saveSample, setSampleAnalysis, getSampleAnalysis } from "./files/samples";
import { scanSampleBySha256 } from "./files/scan";

/* =========================
   ROUTES (ENGINE-DRIVEN, DB-SAFE)
========================= */

export async function registerRoutes(
  httpServer: Server,
  app: Express
): Promise<Server> {

  app.get("/api/health", (_req, res) => {
    const storageMode = (process.env.DATABASE_URL && process.env.USE_INMEMORY_STORAGE !== "1") ? "db" : "memory";
    const sandbox = String(process.env.SANDBOX || "").trim() === "1";
    res.json({
      ok: true,
      mode: process.env.USE_INMEMORY_STORAGE === "1" ? "in-memory" : (process.env.DATABASE_URL ? "database" : "in-memory"),
      storage: storageMode,
      sandbox,
      env: process.env.NODE_ENV || "development",
    });
  });

  /**
   * ENGINE STATUS & SECRETS (FOR DASHBOARD)
   */
  app.get(api.reputation.status.path, (_req, res) => {
    res.json(
      api.reputation.status.responses[200].parse({
        reputation: reputationService.getStatus(),
        secrets: secretsManager.getStatus(),
      }),
    );
  });

  /**
   * ANALYZE INPUT
   */
  app.post(api.analyze.create.path, async (req, res) => {
    try {
      const bodySchema = z.object({
        type: z.enum(["domain", "ip", "url"]),
        value: z.string().optional(),
        input: z.string().optional(),
      });

      const parsed = bodySchema.parse(req.body);
      const actualInput = parsed.value ?? parsed.input;

      if (!actualInput) {
        return res.status(400).json({ message: "Required" });
      }

      // 🔥 Run risk engine
      const assessment = await analyzeInput(
        parsed.type,
        actualInput
      );

      /**
       * ✅ INSERT USING CAMELCASE ONLY
       * Drizzle maps this to snake_case automatically
       */
      const stored = await storage.createAnalysis({
        type: parsed.type,
        input: actualInput,

        // Legacy DB-required fields
        riskScore: assessment.riskScore,
        riskLevel: assessment.riskLevel,
        summary: assessment.summary || `Analysis complete. Risk level: ${assessment.riskLevel}.`,

        // 🔥 All new intelligence safely inside JSONB
        details: assessment.details,
      });

      /**
       * ✅ API RESPONSE (frontend-friendly)
       */
      return res.status(201).json({
        id: stored.id,
        type: stored.type,
        input: stored.input,
        riskScore: stored.riskScore,
        riskLevel: stored.riskLevel,
        summary: stored.summary,
        details: stored.details,
        createdAt: stored.createdAt,
        isFavorite: stored.isFavorite,
      });

    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({
          message: err.errors[0].message,
        });
      }

      console.error(err);
      return res.status(500).json({
        message: "Internal server error",
      });
    }
  });

  /**
   * ASYNC SUBMIT (VT-style)
   */
  app.post("/api/submit", async (req, res) => {
    try {
      const bodySchema = z.object({
        type: z.enum(["domain", "ip", "url"]),
        input: z.string().min(1)
      });
      const { type, input } = bodySchema.parse(req.body);

      const job = await analysisQueue.submit(type, input);
      return res.status(202).json(job);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      console.error(err);
      return res.status(500).json({ message: "Internal server error" });
    }
  });

  /**
   * ASYNC RESULT POLLING
   */
  app.get("/api/result/:id", async (req, res) => {
    const id = String(req.params.id || "");
    const job = await analysisQueue.get(id);
    if (!job) return res.status(404).json({ message: "Job not found" });
    return res.json({ id: job.id, status: job.status, createdAt: job.createdAt, startedAt: job.startedAt, finishedAt: job.finishedAt, result: job.result, error: job.error });
  });

  /**
   * HISTORY
   */
  app.get(api.history.list.path, async (_req, res) => {
    res.json(await storage.getHistory());
  });

  app.delete(api.history.clear.path, async (_req, res) => {
    await storage.clearHistory();
    res.status(204).send();
  });

  /**
   * GET ANALYSIS BY ID
   */
  app.get(api.analysis.get.path, async (req, res) => {
    const id = Number(req.params.id);
    if (Number.isNaN(id)) {
      return res.status(404).json({ message: "Invalid ID" });
    }

    const analysis = await storage.getAnalysis(id);
    if (!analysis) {
      return res.status(404).json({ message: "Analysis not found" });
    }

    res.json(analysis);
  });

  /**
   * EXPORT PDF REPORT
   */
  app.get("/api/analysis/:id/export", async (req, res) => {
    const id = Number(req.params.id);
    const analysis = await storage.getAnalysis(id);
    if (!analysis) return res.status(404).json({ message: "Not found" });

    const pdfBuffer = ThreatReportExporter.generatePDF(analysis);
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", `attachment; filename=Elixir_Report_${id}.pdf`);
    res.send(pdfBuffer);
  });

  /**
   * SERVE SCREENSHOTS (read-only, safe path)
   */
  app.get("/api/screenshots/:file", (req, res) => {
    const fname = String(req.params.file || "");
    if (!/^[a-zA-Z0-9_-]+\.(?:png|jpg|jpeg)$/i.test(fname)) {
      return res.status(400).json({ message: "Invalid filename" });
    }
    const baseDir = path.resolve(process.cwd(), "server", "data", "screenshots");
    const full = path.join(baseDir, fname);
    if (!full.startsWith(baseDir)) return res.status(403).json({ message: "Forbidden" });
    if (!fs.existsSync(full)) return res.status(404).json({ message: "Not found" });
    res.setHeader("Cache-Control", "public, max-age=604800, immutable");
    res.sendFile(full);
  });

  /**
   * EMAIL ANALYSIS (MVP)
   */
  app.post('/api/email/analyze', async (req, res) => {
    try {
      const bodySchema = z.object({
        source: z.enum(['upload','gmail']).default('upload'),
        contentBase64: z.string().min(1),
        metadata: z.record(z.any()).optional(),
      });
      const { source, contentBase64 } = bodySchema.parse(req.body);
      const raw = Buffer.from(contentBase64, 'base64').toString('utf8');
      // Optional raw EML retention for audit
      let rawRef = '';
      if (process.env.EMAIL_RETAIN_RAW === '1') {
        try {
          const rawDir = path.resolve(process.cwd(), 'server', 'data', 'email', 'raw');
          if (!fs.existsSync(rawDir)) fs.mkdirSync(rawDir, { recursive: true });
          const tmpId = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2,8);
          const ref = path.join(rawDir, `${tmpId}.eml`);
          fs.writeFileSync(ref, raw, 'utf-8');
          rawRef = ref;
        } catch {}
      }
      const parsed = await parseEmailSmart(raw);

      const fromDomain = (parsed.from||'').split('@')[1] || '';
      const fromDisplay = (parsed.from || '').split('<')[0]?.replace(/"/g, '').trim();
      const envDomain = (parsed.envelopeFrom||'').split('@')[1] || '';
      const rpDomain = (parsed.returnPath||'').split('@')[1] || '';
      const senderIp = parsed.receivedIps[0];
      const spfBasic = await checkSPF(parsed.envelopeFrom || parsed.from);
      const spfEval = senderIp && (envDomain || fromDomain) ? await evaluateSPF(senderIp, envDomain || fromDomain) : { result: spfBasic.result || 'none' };
      const spf = { domain: spfBasic.domain || (envDomain || fromDomain), result: spfEval.result } as any;
      const dkim = await checkDKIMFromHeaders(parsed.headers || {});
      if (dkim.domain && dkim.selector && parsed.rawHeaderLines && parsed.rawBody !== undefined) {
        try {
          const dkimHeaderValue = parsed.headers['dkim-signature'] || parsed.headers['dkim'] || '';
          if (dkimHeaderValue) {
            const v = await verifyDKIM(parsed.rawHeaderLines, parsed.rawBody, dkimHeaderValue);
            if (v.verified) { dkim.result = 'pass'; dkim.reason = 'verified'; }
            else { dkim.result = 'neutral'; dkim.reason = v.reason || 'not-verified'; }
          }
        } catch {}
      }
      const dmarc = await checkDMARC(fromDomain);
      const alignmentMode = (String(process.env.EMAIL_DMARC_ALIGNMENT || '').toLowerCase() === 'strict') ? 'strict' : 'relaxed';

      // Sender IP heuristic: pick last Received IP (first in list), then geolocate
      const geo = senderIp ? await lookupIPLocation(senderIp) : null;
      const receivedPath = await (async () => {
        const out: Array<{ ip: string; countryCode?: string; country?: string }> = [];
        const ips = parsed.receivedIps.slice(0, 5);
        for (const ip of ips) {
          try {
            const g = await lookupIPLocation(ip);
            out.push({ ip, countryCode: g?.countryCode, country: g?.country });
          } catch { out.push({ ip }); }
        }
        return out;
      })();

      // Analyze URLs using existing URL analyzer (cap at 10)
      const urls = (parsed.urls || []).slice(0, 10);
      const linkResults: any[] = [];
      for (const url of urls) {
        try {
          const r = await analyzeInput('url', url);
          linkResults.push({ url, riskScore: r.riskScore, riskLevel: r.riskLevel, summary: r.summary });
        } catch { linkResults.push({ url, riskScore: 0, riskLevel: 'Unknown' }); }
      }

      // Body signals (very basic keywords)
      const subject = parsed.subject || '';
      const body = parsed.text || '';
      const kws = [/password/i, /gift\s*card/i, /crypto/i, /urgent/i, /reset/i];
      const bodySignals = kws.filter(rx => rx.test(body)).map(rx => `Keyword: ${rx.source}`);
      const becSignals = detectBECIndicators(`${subject} ${body}`);
      becSignals.forEach(s => bodySignals.push(s));

      // Attachments (MVP base64 extract + scan)
      const attachments = (parsed.attachments || []).slice(0, 5);
      const attachmentReports: any[] = [];
      const indicatorsAttachments: any[] = [];
      for (const a of attachments) {
        try {
          const buf = Buffer.from(a.contentBase64, 'base64');
          const sha = sha256Of(buf);
          const rep = scanBuffer(sha, buf);
          const sev = rep.detections?.some(d => d.severity === 'high') ? 'Malicious' : rep.detections?.length ? 'Suspicious' : 'Clean';
          attachmentReports.push({ filename: a.filename, sha256: sha, summary: rep.summary, detections: rep.detections?.map(d=>`${d.engine}:${d.signature}`) });
          indicatorsAttachments.push({ filename: a.filename, sha256: sha, mime: a.mime, size: a.size, verdict: sev });
        } catch {}
      }

      const strict = (a:string,b:string)=> !!a && !!b && (a===b);
      const relaxed = (a:string,b:string)=> !!a && !!b && (a===b || a.endsWith('.'+b) || b.endsWith('.'+a));

      // Header/domain heuristics
      const headerSignals: string[] = [];
      const suspiciousTlds = ['.zip','.mov','.click','.country','.gq','.work','.top','.link','.xyz'];
      const tld = fromDomain ? fromDomain.slice(fromDomain.lastIndexOf('.')) : '';
      if (tld && suspiciousTlds.includes(tld.toLowerCase())) headerSignals.push(`Suspicious TLD: ${tld}`);
      // Domain age
      try {
        if (fromDomain) {
          const whois = await lookupWhoisData(fromDomain);
          if (whois && whois.ageInDays !== undefined && whois.ageInDays < 7) headerSignals.push('Newly registered sender domain');
        }
      } catch {}
      // Alignment mismatch
      const spfStrict = strict(fromDomain, envDomain) || strict(fromDomain, rpDomain);
      if (!spfStrict && dkim.result!=='pass') headerSignals.push('Header alignment mismatch (SPF/DKIM)');
      if (dmarc.policy==='reject' && dmarc.result!=='pass') headerSignals.push('DMARC policy reject: not aligned');
      const brandSignals = detectBrandImpersonation(fromDisplay || '', fromDomain, subject);
      brandSignals.forEach(s => headerSignals.push(s));

      // Simple scoring (placeholder plus header heuristics)
      const weights = getEmailRiskWeights();
      let score = 0;
      const spfAlignedStrict = strict(fromDomain, envDomain) || strict(fromDomain, rpDomain);
      const spfAlignedRelaxed = relaxed(fromDomain, envDomain) || relaxed(fromDomain, rpDomain);
      const dkimAlignedStrict = dkim.domain ? strict(fromDomain, dkim.domain) : false;
      const dkimAlignedRelaxed = dkim.domain ? relaxed(fromDomain, dkim.domain) : false;
      const spfAligned = alignmentMode === 'strict' ? (spfAlignedStrict && spf.result === 'pass') : (spfAlignedRelaxed && spf.result === 'pass');
      const dkimAligned = alignmentMode === 'strict' ? (dkimAlignedStrict && dkim.result === 'pass') : (dkimAlignedRelaxed && dkim.result === 'pass');
      const dmarcPass = spfAligned || dkimAligned;
      // compute DMARC result from policy if available
      const effDmarcResult = dmarcPass ? 'pass' : (dmarc.policy ? (dmarc.policy==='reject'?'fail':'neutral') : 'none');
      dmarc.result = effDmarcResult;
      dmarc.alignment = alignmentMode;
      let authScore = 0;
      if (spf.result === 'none') authScore += weights.spfNone;
      if (spf.result === 'fail' || spf.result === 'softfail') authScore += weights.spfFail;
      if (effDmarcResult === 'none') authScore += weights.dmarcNone;
      if (effDmarcResult === 'fail') authScore += weights.dmarcFail;
      const headerScore = headerSignals.length * weights.headerSignal;
      const linkScore = linkResults.reduce((a, b) => a + (b.riskScore >= 70 ? weights.linkHigh : b.riskScore >= 30 ? weights.linkMedium : 0), 0);
      const bodyScore = bodySignals.length * weights.bodySignal;
      const attachmentScore = attachmentReports.reduce((a,b)=> a + ((b.detections?.length||0)>0 ? weights.attachmentHit : 0), 0);
      const brandScore = brandSignals.length * weights.brandImpersonation;
      const becScore = becSignals.length * weights.becIndicator;
      score = authScore + headerScore + linkScore + bodyScore + attachmentScore + brandScore + becScore;
      const riskScore = Math.min(100, score);
      const riskLevel = riskScore >= 90 ? 'Critical' : riskScore >= 70 ? 'High Risk' : riskScore >= 30 ? 'Suspicious' : 'Safe';

      const topSignals: string[] = [];
      if (spf.result === 'none') topSignals.push('SPF: none');
      if (dmarc.result === 'none') topSignals.push('DMARC: none');
      const hotLink = linkResults.find(l => l.riskScore >= 70);
      if (hotLink) topSignals.push(`Malicious Link: ${hotLink.url}`);
      if (attachmentReports.some(r => (r.detections?.length||0) > 0)) topSignals.push('Suspicious Attachment');
      headerSignals.slice(0,2).forEach(s => topSignals.push(s));

      const id = Date.now().toString(36);
      const emailCase = emailStore.save({
        id,
        createdAt: Date.now(),
        source,
        subject: parsed.subject,
        from: parsed.from,
        envelopeFrom: parsed.envelopeFrom,
        returnPath: parsed.returnPath,
        messageId: parsed.messageId,
        date: parsed.date,
        spf, dkim, dmarc,
        alignmentMode,
        senderIp,
        geo: geo ? { city: geo.city, country: geo.country, countryCode: geo.countryCode, lat: geo.latitude, lon: geo.longitude } : undefined,
        receivedPath,
        indicators: { domains: [], urls, ips: parsed.receivedIps, hashes: indicatorsAttachments.map((x:any)=>x.sha256).filter(Boolean), attachments: indicatorsAttachments },
        linkResults,
        attachmentReports,
        bodySignals,
        headerSignals,
        bodyHtml: process.env.EMAIL_STORE_BODY_HTML === '1' ? String(parsed.html || '') : undefined,
        riskBreakdown: { auth: authScore, headers: headerScore, links: linkScore, body: bodyScore, attachments: attachmentScore, brand: brandScore, bec: becScore },
        riskScore,
        riskLevel,
        topSignals,
        summary: `Email analyzed. Risk: ${riskLevel}. URLs=${urls.length}, SPF=${spf.result}, DKIM=${dkim.result}, DMARC=${dmarc.result}`,
        artifacts: { rawRef }
      });

      try {
        metrics.recordEmail({ spfResult: spf.result, dkimReason: dkim.reason, dmarcPolicy: dmarc.policy, attachmentCount: attachmentReports.length, linkCount: urls.length });
      } catch {}
      return res.status(201).json({ id: emailCase.id, riskScore, riskLevel, summary: emailCase.summary });
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      console.error(err);
      return res.status(500).json({ message: 'Internal server error' });
    }
  });

  app.get('/api/email/:id', (req, res) => {
    const id = String(req.params.id || '');
    const ec = emailStore.get(id);
    if (!ec) return res.status(404).json({ message: 'Not found' });
    if (String(req.query.redact || '') === '1') {
      const copy: any = { ...ec };
      if (copy.bodyHtml) delete copy.bodyHtml;
      if (copy.artifacts) delete copy.artifacts;
      return res.json(copy);
    }
    return res.json(ec);
  });

  app.post('/api/email/:id/feedback', (req, res) => {
    try {
      const id = String(req.params.id || '');
      const ec = emailStore.get(id);
      if (!ec) return res.status(404).json({ message: 'Not found' });
      const bodySchema = z.object({
        label: z.enum(['false_positive','false_negative','confirm']),
        notes: z.string().max(1000).optional(),
      });
      const { label, notes } = bodySchema.parse(req.body);
      const entry = recordEmailFeedback(id, label, notes);
      const feedback = Array.isArray(ec.feedback) ? ec.feedback.slice() : [];
      feedback.unshift({ label, notes, createdAt: entry.createdAt });
      const updated = emailStore.update(id, { feedback });
      return res.status(201).json(updated);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      return res.status(500).json({ message: 'Internal server error' });
    }
  });

  app.get('/api/email/risk/weights', (_req, res) => {
    return res.json(getEmailRiskWeights());
  });

  app.post('/api/email/risk/weights', (req, res) => {
    try {
      const bodySchema = z.object({
        spfNone: z.number().optional(),
        spfFail: z.number().optional(),
        dmarcNone: z.number().optional(),
        dmarcFail: z.number().optional(),
        headerSignal: z.number().optional(),
        linkHigh: z.number().optional(),
        linkMedium: z.number().optional(),
        bodySignal: z.number().optional(),
        attachmentHit: z.number().optional(),
        brandImpersonation: z.number().optional(),
        becIndicator: z.number().optional(),
      });
      const next = bodySchema.parse(req.body);
      const updated = setEmailRiskWeights(next);
      return res.json(updated);
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      return res.status(500).json({ message: 'Internal server error' });
    }
  });

  app.get('/api/email', (req, res) => {
    const limit = Math.max(1, Math.min(500, Number(req.query.limit || 100)));
    const list = emailStore.list(limit);
    return res.json(list);
  });

  /**
   * GRAPH: neighbors and pivot
   */
  app.get('/api/graph/neighbors', (req, res) => {
    const node = String(req.query.node || '').trim();
    if (!node) return res.status(400).json({ message: 'node required' });
    try {
      const { GraphService } = require('./graph/graph');
      return res.json(GraphService.neighbors(node));
    } catch (e: any) {
      return res.status(500).json({ message: String(e?.message || e) });
    }
  });
  app.get('/api/graph/pivot', (req, res) => {
    const node = String(req.query.node || '').trim();
    const depth = Number(req.query.depth || 1);
    if (!node) return res.status(400).json({ message: 'node required' });
    try {
      const { GraphService } = require('./graph/graph');
      return res.json(GraphService.subgraph(node, Math.max(1, Math.min(3, depth))));
    } catch (e: any) {
      return res.status(500).json({ message: String(e?.message || e) });
    }
  });

  /**
   * SAMPLE UPLOAD (base64 JSON) — returns sha256 + metadata
   */
  app.post("/api/samples/uploadBase64", async (req, res) => {
    try {
      const bodySchema = z.object({ filename: z.string().optional(), contentBase64: z.string().min(1) });
      const { filename, contentBase64 } = bodySchema.parse(req.body);
      let buffer: Buffer;
      try {
        buffer = Buffer.from(contentBase64, 'base64');
      } catch {
        return res.status(400).json({ message: "Invalid base64 content" });
      }
      const { meta, existed } = saveSample(buffer, filename);
      return res.status(existed ? 200 : 201).json({ ...meta, existed });
    } catch (err) {
      if (err instanceof z.ZodError) {
        return res.status(400).json({ message: err.errors[0].message });
      }
      console.error(err);
      return res.status(500).json({ message: "Internal server error" });
    }
  });

  /**
   * SAMPLE META
   */
  app.get("/api/samples/:sha256/meta", (req, res) => {
    const sha = String(req.params.sha256 || "").toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha)) return res.status(400).json({ message: "Invalid sha256" });
    const meta = getSampleMeta(sha);
    if (!meta) return res.status(404).json({ message: "Not found" });
    return res.json(meta);
  });

  /**
   * SAMPLE DOWNLOAD
   */
  app.get("/api/samples/:sha256/download", (req, res) => {
    const sha = String(req.params.sha256 || "").toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha)) return res.status(400).json({ message: "Invalid sha256" });
    const stream = getSampleStream(sha);
    if (!stream) return res.status(404).json({ message: "Not found" });
    res.setHeader("Content-Type", "application/octet-stream");
    res.setHeader("Content-Disposition", `attachment; filename=${sha}.bin`);
    stream.pipe(res);
  });

  /**
   * SAMPLE SCAN (basic regex/entropy)
   */
  app.post("/api/samples/:sha256/scan", (req, res) => {
    const sha = String(req.params.sha256 || "").toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha)) return res.status(400).json({ message: "Invalid sha256" });
    const report = scanSampleBySha256(sha);
    if (!report) return res.status(404).json({ message: "Sample not found" });
    setSampleAnalysis(sha, report);
    return res.status(201).json(report);
  });

  /**
   * SAMPLE REPORT
   */
  app.get("/api/samples/:sha256/report", (req, res) => {
    const sha = String(req.params.sha256 || "").toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(sha)) return res.status(400).json({ message: "Invalid sha256" });
    const report = getSampleAnalysis(sha);
    if (!report) return res.status(404).json({ message: "Not found" });
    return res.json(report);
  });

  app.get("/api/har/:file", (req, res) => {
    const fname = String(req.params.file || "");
    if (!/^[a-zA-Z0-9_-]+\.(?:har|har\.json|json)$/i.test(fname)) {
      return res.status(400).json({ message: "Invalid filename" });
    }
    const baseDir = path.resolve(process.cwd(), "server", "data", "har");
    const full = path.join(baseDir, fname);
    if (!full.startsWith(baseDir)) return res.status(403).json({ message: "Forbidden" });
    if (!fs.existsSync(full)) return res.status(404).json({ message: "Not found" });
    res.setHeader("Content-Type", "application/json");
    res.setHeader("Cache-Control", "public, max-age=604800, immutable");
    res.sendFile(full);
  });

  return httpServer;
}
