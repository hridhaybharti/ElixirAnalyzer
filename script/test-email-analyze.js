import fs from 'fs';

(async () => {
  const path = process.argv[2];
  const base = process.env.BASE || 'http://127.0.0.1:5000';
  if (!path || !fs.existsSync(path)) {
    console.error('Usage: node script/test-email-analyze.js <path-to.eml>');
    process.exit(1);
  }
  const raw = fs.readFileSync(path, 'utf8');
  const b64 = Buffer.from(raw, 'utf8').toString('base64');
  try {
    const res = await fetch(`${base}/api/email/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'upload', contentBase64: b64 })
    });
    const j = await res.json();
    console.log('status', res.status);
    console.log(j);
    if (res.ok) {
      const det = await (await fetch(`${base}/api/email/${j.id}`)).json();
      console.log('case.summary', det.summary);
      console.log('receivedPath', det.receivedPath);
      console.log('links', (det.linkResults||[]).length);
      console.log('attachments', (det.indicators?.attachments||[]).length);
    }
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
})();
