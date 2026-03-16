// Minimal MV3 service worker scaffold for Gmail RAW fetch + Elixir API post

chrome.action.onClicked.addListener(async (tab) => {
  if (!tab || !tab.url || !/mail.google.com/.test(tab.url)) {
    console.log('Open Gmail to analyze an email.');
    return;
  }
  try {
    // TODO: Use Gmail API to get the selected message raw via OAuth
    // Placeholder: prompt for raw EML copy-paste
    const raw = prompt('Paste raw email (RFC 822) for analysis:');
    if (!raw) return;
    const b64 = btoa(unescape(encodeURIComponent(raw)));

    const apiBase = (await chrome.storage.local.get(['apiBase'])).apiBase || 'http://127.0.0.1:5000';
    const res = await fetch(`${apiBase}/api/email/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ source: 'gmail', contentBase64: b64 })
    });
    const j = await res.json();
    if (!res.ok) throw new Error(j?.message || 'Analyze failed');
    chrome.notifications.create('', {
      type: 'basic',
      iconUrl: 'icon48.png',
      title: 'Elixir Analyzer',
      message: `Case ${j.id} — Risk ${j.riskScore} (${j.riskLevel})`
    });
  } catch (e) {
    console.error(e);
  }
});
