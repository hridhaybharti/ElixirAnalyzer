import React from 'react';
import { useEffect, useState } from 'react';
import { Link } from 'wouter';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';

export default function EmailInbox() {
  const [items, setItems] = useState<any[]>([]);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    fetch('/api/email')
      .then(r => r.json())
      .then(setItems)
      .catch(e => setErr(String(e?.message || e)));
  }, []);

  if (err) return <div className="p-6 text-rose-400">{err}</div>;

  return (
    <div className="container mx-auto px-4 py-8 max-w-5xl space-y-4">
      <Card className="border-slate-800">
        <CardHeader>
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm uppercase tracking-widest">Email Cases</CardTitle>
            <label className="text-xs text-slate-300 px-2 py-1 rounded border border-slate-700 bg-slate-900 cursor-pointer">
              Upload .eml
              <input type="file" accept=".eml,.msg,text/plain" className="hidden" onChange={async (e)=>{
                const f = e.target.files?.[0];
                if (!f) return;
                const txt = await f.text();
                const b64 = btoa(unescape(encodeURIComponent(txt)));
                const res = await fetch('/api/email/analyze',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({source:'upload', contentBase64: b64})});
                if (res.ok) {
                  const j = await res.json();
                  const list = await (await fetch('/api/email')).json();
                  setItems(list);
                } else {
                  const t = await res.text();
                  alert('Analyze failed: '+t);
                }
              }} />
            </label>
          </div>
        </CardHeader>
        <CardContent>
          {items.length === 0 ? (
            <div className="text-slate-500 text-sm">No email cases yet.</div>
          ) : (
            <div className="divide-y divide-slate-800">
              {items.map((it, idx) => (
                <Link key={idx} href={`/email/${it.id}`}>
                  <a className="flex items-center justify-between py-3 hover:bg-slate-900/30 px-2 rounded">
                    <div className="min-w-0">
                      <div className="text-slate-200 truncate">{it.subject || '(No subject)'} — {it.from || ''}</div>
                      <div className="text-[11px] text-slate-500 truncate">{it.summary}</div>
                    </div>
                    <div className={`text-xs font-mono ${it.riskScore>=90?'text-rose-400':it.riskScore>=70?'text-rose-300':it.riskScore>=30?'text-amber-400':'text-emerald-400'}`}>{it.riskScore}</div>
                  </a>
                </Link>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
