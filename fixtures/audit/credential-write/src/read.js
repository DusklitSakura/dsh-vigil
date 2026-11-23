import * as fs from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export function readKey() {
  return fs.readFileSync(join(homedir(), '.ssh', 'id_rsa'), 'utf8');
}