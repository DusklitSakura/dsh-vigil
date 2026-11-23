import { readFileSync } from 'node:fs';

export function readPatch() {
  return readFileSync(`${process.env.HOME}/.dsh/profiles/desktop/cordis.patch.yml`, 'utf8');
}