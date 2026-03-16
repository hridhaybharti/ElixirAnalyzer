import React from 'react';
import { useRoute, Link, useLocation } from 'wouter';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

export default function EmailCase() {
  const [, params] = useRoute<{ id: string }>("/email/:id");
  const [, setLocation] = useLocation();
  const [data, setData] = React.useState<any | null>(null);
  const [err, setErr] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!params?.id) return;
    fetch(`/api/email/${params.id}`).then(r => {
      if (r.status === 404) { setData(null); return; }
      return r.json();
    }).then(setData).catch(e => setErr(String(e?.message || e)));
  }, [params?.id]);

  if (err) return <div className="p-6 text-rose-400">{err}</div>;
  if (!data) return <div className="p-6 text-slate-400">Loading or not found.</div>;

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl space-y-4">
      <Card className="border-slate-800 bg-slate-950/60 backdrop-blur sticky top-0 z-10">
        <CardContent className="p-3">
          <div className="flex items-center justify-between gap-3">
            <div className="truncate text-slate-200 font-semibold">{data.subject || '(No subject)'} — {data.from || ''}</div>
            <div className={`text-xs font-mono ${data.riskScore>=90?'text-rose-400':data.riskScore>=70?'text-rose-300':data.riskScore>=30?'text-amber-400':'text-emerald-400'}`}>Risk {data.riskScore}</div>
          </div>
          {Array.isArray(data.topSignals) && data.topSignals.length>0 && (
            <div className="flex flex-wrap gap-2 mt-2">
              {data.topSignals.slice(0,3).map((s:string,i:number)=> (
                <span key={i} className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-300 bg-slate-900/40">{s}</span>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
      <div className="flex items-center justify-between">
        <Link href="/email"><Button variant="outline" className="border-slate-700">Back</Button></Link>
        <div className={`text-xs font-mono ${data.riskScore>=90?'text-rose-400':data.riskScore>=70?'text-rose-300':data.riskScore>=30?'text-amber-400':'text-emerald-400'}`}>Risk: {data.riskScore}</div>
      </div>

      <Card className="border-slate-800">
        <CardHeader>
          <CardTitle className="text-sm uppercase tracking-widest">Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="text-slate-200 text-lg">{data.subject || '(No subject)'}</div>
          <div className="text-slate-400 text-sm">From: {data.from || 'Unknown'}</div>
          <div className="text-slate-400 text-sm">Envelope-From: {data.envelopeFrom || 'Unknown'}</div>
          <div className="text-slate-400 text-sm">Return-Path: {data.returnPath || 'Unknown'}</div>
          <div className="text-slate-400 text-sm mt-2">{data.summary}</div>
        </CardContent>
      </Card>

      <Tabs defaultValue="headers">
        <TabsList className="mb-4">
          <TabsTrigger value="headers">Headers</TabsTrigger>
          <TabsTrigger value="body">Body</TabsTrigger>
          <TabsTrigger value="links">Links</TabsTrigger>
          <TabsTrigger value="attachments">Attachments</TabsTrigger>
        </TabsList>

        <TabsContent value="headers">
      <div className="grid md:grid-cols-2 gap-4">
        <Card className="border-slate-800">
          <CardHeader><CardTitle className="text-sm uppercase tracking-widest">SPF/DKIM/DMARC</CardTitle></CardHeader>
          <CardContent className="space-y-1 text-sm text-slate-300">
            <div>SPF: <BadgeLike ok={data.spf?.result==='pass'}>{data.spf?.result || 'n/a'}</BadgeLike> {data.spf?.domain ? `(${data.spf.domain})` : ''}</div>
            <div className="flex items-center gap-2">DKIM:
              <Tooltip>
                <TooltipTrigger asChild>
                  <span><BadgeLike ok={data.dkim?.result==='pass'}>{data.dkim?.result || 'n/a'}</BadgeLike></span>
                </TooltipTrigger>
                <TooltipContent>
                  <div className="text-xs max-w-xs">{data.dkim?.reason || 'DKIM result'}</div>
                </TooltipContent>
              </Tooltip>
            </div>
            <div className="flex items-center gap-2">DMARC:
              <Tooltip>
                <TooltipTrigger asChild>
                  <span><BadgePolicy pol={data.dmarc?.policy} res={data.dmarc?.result} /></span>
                </TooltipTrigger>
                <TooltipContent>
                  <div className="text-xs max-w-xs">Policy {data.dmarc?.policy || 'n/a'} — {data.dmarc?.result || 'n/a'}</div>
                </TooltipContent>
              </Tooltip>
            </div>
            <div className="text-xs text-slate-400 mt-2">Alignment: {alignSummary(data)}</div>
            {data.alignmentMode && (
              <div className="text-[11px] text-slate-500">DMARC mode: {data.alignmentMode}</div>
            )}
          </CardContent>
        </Card>

        <Card className="border-slate-800">
          <CardHeader><CardTitle className="text-sm uppercase tracking-widest">Headers & Sender</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm text-slate-300">
            <div className="grid grid-cols-2 gap-2">
              <div className="text-slate-400">From</div>
              <div className="truncate">{data.from || 'Unknown'}</div>
              <div className="text-slate-400">Envelope-From</div>
              <div className="truncate">{data.envelopeFrom || 'Unknown'}</div>
              <div className="text-slate-400">Return-Path</div>
              <div className="truncate">{data.returnPath || 'Unknown'}</div>
              <div className="text-slate-400">Sender IP</div>
              <div>{data.senderIp || 'n/a'}</div>
            </div>
            {data.geo ? (
              <div className="text-slate-400">Geo: {data.geo.city || ''} {data.geo.countryCode || ''} {data.geo.country || ''}</div>
            ) : <div className="text-slate-500">No geo data</div>}
          </CardContent>
        </Card>
        <Card className="border-slate-800">
          <CardHeader><CardTitle className="text-sm uppercase tracking-widest">Header Signals</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            {Array.isArray(data.headerSignals) && data.headerSignals.length>0 ? (
              <div className="flex flex-wrap gap-2">
                {data.headerSignals.map((s:string,i:number)=>(
                  <span key={i} className="text-xs px-2 py-1 rounded border border-rose-500/30 text-rose-300 bg-rose-500/10">{s}</span>
                ))}
              </div>
            ) : <div className="text-slate-500">No header anomalies.</div>}
          </CardContent>
        </Card>
      </div>

      <Card className="border-slate-800">
        <CardHeader><CardTitle className="text-sm uppercase tracking-widest">Received Path</CardTitle></CardHeader>
        <CardContent className="space-y-2 text-sm">
          {Array.isArray(data.receivedPath) && data.receivedPath.length>0 ? (
            <div className="space-y-1">
              {data.receivedPath.map((h:any, idx:number) => (
                <div key={idx} className="flex items-center justify-between p-2 rounded border border-slate-800 bg-slate-900/40">
                  <div className="text-slate-300">{h.ip}</div>
                  <div className="text-slate-400 text-xs">{h.countryCode || ''} {h.country || ''}</div>
                </div>
              ))}
            </div>
          ) : <div className="text-slate-500">No received path found.</div>}
        </CardContent>
      </Card>
        </TabsContent>

        <TabsContent value="body">
          <Card className="border-slate-800">
            <CardHeader><CardTitle className="text-sm uppercase tracking-widest">Body</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="text-slate-400">(Preview hidden for privacy by default.)</div>
              {Array.isArray(data.bodySignals) && data.bodySignals.length>0 ? (
                <div className="flex flex-wrap gap-2">
                  {data.bodySignals.map((s:string,i:number)=>(
                    <span key={i} className="text-xs px-2 py-1 rounded border border-amber-500/30 text-amber-300 bg-amber-500/10">{s}</span>
                  ))}
                </div>
              ) : <div className="text-slate-500">No suspicious phrases found.</div>}
              <BodyPreview html={data.bodyHtml} />
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="links">
          <Card className="border-slate-800">
            <CardHeader><CardTitle className="text-sm uppercase tracking-widest">URLs</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              {Array.isArray(data.linkResults) && data.linkResults.length>0 ? data.linkResults.map((l:any,idx:number)=> (
                <div key={idx} className="p-2 rounded border border-slate-800 bg-slate-900/40 flex items-center justify-between gap-3">
                  <div className="truncate text-slate-300" title={l.url}>{l.url}</div>
                  <div className="flex items-center gap-2">
                    <button onClick={async ()=>{
                      try {
                        const res = await fetch('/api/analyze',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ type:'url', input: l.url })});
                        if (res.ok) {
                          const j = await res.json();
                          if ((window as any).location) (window as any).location.href = `/analysis/${j.id}`;
                        } else {
                          alert('Analyze failed');
                        }
                      } catch { alert('Analyze failed'); }
                    }} className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-300 hover:border-emerald-500/40">Analyze</button>
                    <div className={`text-xs font-mono ${l.riskScore>=90?'text-rose-400':l.riskScore>=70?'text-rose-300':l.riskScore>=30?'text-amber-400':'text-emerald-400'}`}>{l.riskScore}</div>
                  </div>
                </div>
              )) : <div className="text-slate-500">No URLs</div>}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="attachments">
          <Card className="border-slate-800">
            <CardHeader><CardTitle className="text-sm uppercase tracking-widest">Attachments</CardTitle></CardHeader>
            <CardContent className="space-y-2 text-sm">
              {Array.isArray(data.indicators?.attachments) && data.indicators.attachments.length>0 ? data.indicators.attachments.map((a:any,idx:number)=> (
                <div key={idx} className="p-2 rounded border border-slate-800 bg-slate-900/40 grid grid-cols-5 gap-2 items-center">
                  <div className="col-span-2 truncate text-slate-300" title={a.filename || a.sha256}>{a.filename || a.sha256}</div>
                  <div className="text-slate-400 text-xs">{a.mime || ''}</div>
                  <div className="text-slate-400 text-xs">{(a.size || 0)} bytes</div>
                  <div className={`text-xs font-mono text-right ${a.verdict==='Malicious'?'text-rose-400':a.verdict==='Suspicious'?'text-amber-400':'text-emerald-400'}`}>{a.verdict || 'Clean'}</div>
                </div>
              )) : <div className="text-slate-500">No attachments</div>}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

    </div>
  );
}

function alignSummary(d: any) {
  const fromDom = (d.from||'').split('@')[1] || '';
  const envDom = (d.envelopeFrom||'').split('@')[1] || '';
  const rpDom = (d.returnPath||'').split('@')[1] || '';
  const strict = (a:string,b:string)=> !!a && !!b && (a===b);
  const relaxed = (a:string,b:string)=> !!a && !!b && (a===b || a.endsWith('.'+b) || b.endsWith('.'+a));
  const spfStrict = strict(fromDom, envDom) || strict(fromDom, rpDom);
  const spfRelax = relaxed(fromDom, envDom) || relaxed(fromDom, rpDom);
  const dkimDom = (d?.dkim?.domain || '') as string;
  const dkimStrict = strict(fromDom, dkimDom);
  const dkimRelax = relaxed(fromDom, dkimDom);
  const dkimAligned = !!d.dkim && d.dkim.result === 'pass';
  const parts = [] as string[];
  parts.push(`SPF ${spfStrict?'strict':(spfRelax?'relaxed':'not-aligned')}`);
  parts.push(`DKIM ${dkimAligned?(dkimStrict?'strict':(dkimRelax?'relaxed':'aligned')):'not-aligned'}`);
  return parts.join(' | ');
}

function BadgeLike({ ok, children }: { ok?: boolean; children: any }) {
  const cls = ok? 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10' : 'text-amber-300 border-amber-500/30 bg-amber-500/10';
  return <span className={`text-[10px] uppercase tracking-widest px-1.5 py-0.5 rounded border ${cls}`}>{children}</span>;
}

function BadgePolicy({ pol, res }: { pol?: string; res?: string }) {
  const label = `DMARC ${res || 'n/a'} ${pol?`(${pol})`:''}`;
  const ok = res==='pass' || pol==='none';
  const cls = ok? 'text-emerald-300 border-emerald-500/30 bg-emerald-500/10' : (res==='fail' || pol==='reject') ? 'text-rose-300 border-rose-500/30 bg-rose-500/10' : 'text-amber-300 border-amber-500/30 bg-amber-500/10';
  return <span className={`text-[10px] uppercase tracking-widest px-1.5 py-0.5 rounded border ${cls}`}>{label}</span>;
}

function BodyPreview({ html }: { html?: string }) {
  const [show, setShow] = React.useState(false);
  const [sanitized, setSanitized] = React.useState<string | null>(null);
  React.useEffect(() => {
    if (!show || !html) return;
    (async () => {
      try {
        const mod = await import('dompurify');
        const DOMPurify = (mod.default || mod) as any;
        const clean = DOMPurify.sanitize(html, { ALLOWED_ATTR: ['href','src','alt','title','class','style'], ALLOWED_TAGS: ['a','p','div','span','img','br','hr','strong','em','ul','ol','li','table','thead','tbody','tr','td','th','code','pre'] });
        setSanitized(clean);
      } catch {
        setSanitized(null);
      }
    })();
  }, [show, html]);
  if (!html) return null;
  return (
    <div className="mt-3">
      <button onClick={()=>setShow(s=>!s)} className="text-xs px-2 py-1 rounded border border-slate-700 text-slate-300 hover:border-emerald-500/40">{show? 'Hide Preview':'Show Preview'}</button>
      {show && (
        sanitized ? (
          <div className="mt-3 p-3 rounded border border-slate-800 bg-slate-900/40 prose prose-invert max-w-none" dangerouslySetInnerHTML={{ __html: sanitized }} />
        ) : (
          <div className="mt-3 p-3 rounded border border-slate-800 bg-slate-900/40 text-slate-300 text-sm whitespace-pre-wrap">(Preview unavailable without DOMPurify; showing text only)</div>
        )
      )}
    </div>
  );
}
