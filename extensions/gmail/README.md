# Elixir Email Analyzer (Gmail Extension)

Minimal MV3 scaffold to send Gmail emails to the Elixir Analyzer API.

## Setup

1. Create a Google OAuth2 client for a Chrome extension and set the `oauth2.client_id` in manifest.json.
2. (Dev) Load unpacked: Chrome → Extensions → Developer Mode → Load unpacked → select this folder.
3. Click the extension icon while on Gmail to trigger a prompt (temporary) to paste raw RFC 822.
4. Set API base (optional) in DevTools Console:
   ```js
   chrome.storage.local.set({ apiBase: 'http://127.0.0.1:5000' })
   ```

## Next

- Replace the prompt with Gmail API calls to fetch the selected message in `format=RAW`.
- Add a small UI for status/history.
