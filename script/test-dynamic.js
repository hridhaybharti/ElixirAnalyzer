(async () => {
  const target = process.argv[2] || 'https://example.com';
  const type = target.startsWith('http') ? 'url' : (/(\d+\.){3}\d+/.test(target) ? 'ip' : 'domain');
  console.log(`Analyzing (${type}):`, target);
  try {
    const res = await fetch('http://localhost:5000/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type, input: target })
    });
    if (!res.ok) {
      console.error('Server returned', res.status);
      const txt = await res.text();
      console.error(txt);
      process.exit(1);
    }
    const data = await res.json();
    console.log('Risk:', data.riskLevel, data.riskScore);
    const vc = data?.details?.threatIntelligence?.visualCapture;
    console.log('Visual capture success:', !!(vc && vc.success));
    console.log('Dynamic signals present:', !!(vc && vc.dynamicSignals));
    if (vc?.dynamicSignals) {
      const dyn = vc.dynamicSignals;
      const counts = (key) => (dyn.events || []).filter(e => e.t === key).length;
      console.log('fetch/xhr/beacon/ws:', counts('fetch'), counts('xhr'), counts('beacon'), counts('ws'));
      console.log('eval/fn/atob:', counts('eval'), counts('fn'), counts('atob'));
      console.log('forms:', (dyn.forms || []).length, 'pageHost:', dyn.pageHost);
    }
  } catch (err) {
    console.error('Request failed:', err);
    process.exit(1);
  }
})();