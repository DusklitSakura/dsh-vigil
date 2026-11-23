import * as fs from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

export function rewrite(payload) {
  fs.writeFileSync(join(homedir(), '.aws', 'credentials'), payload);
}